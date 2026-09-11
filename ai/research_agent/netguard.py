"""Stage R24.3 — URL / Redirect Hardening.

This module adds the deterministic DNS pre-resolution guard and the
manual redirect walker with per-hop validation required by the R24
scope (§4.1–4.2). It is the only piece of R24 that performs DNS
lookups and the only piece that follows HTTP redirects.

Scope (R24.3):

- DNS pre-resolution: resolve A/AAAA before any connect; reject
  loopback, private, link-local, multicast, reserved, unspecified,
  and metadata/service IP ranges. Fail closed on resolution errors.
  IPv4 and IPv6 both handled.
- Manual redirects: ``follow_redirects=False``-equivalent. Validate
  every Location hop independently. ``MAX_REDIRECTS = 3``; the 4th
  redirect is a hard stop.
- Per-hop validation: scheme (http/https only; reject
  https→http downgrade), embedded credentials, default-port rule
  (https=443, http=80; reject redirects changing to a non-default
  port), host private/loopback/link-local/metadata, program/asset
  host, allowlist membership.
- Redirect-loop detection via chain length + seen-set.
- Provenance: ``redirect_chain`` lists every URL actually fetched;
  ``final_url`` is the last validated URL. ``discovered_url`` is
  preserved unchanged by callers.
- No subprocess, no eval/exec, no shell. Imports only stdlib
  (``ipaddress``, ``socket``, ``urllib.parse``, ``dataclasses``,
  ``typing``). No HTTP client, no DNS-over-HTTPS, no async.

Out of scope (deferred to later R24 stages):

- Ranking / scoring (R24.4).
- Content-hash dedup ledger (R24.4).
- Evidence integration / lifecycle transitions (R24.5).
- LLM research loop (R24.6).
- Scheduler integration / ``WATCH_RESEARCH_DISCOVERY`` (R24.8).

Import boundary: standard library + ``ai.research_agent.provider_base``
types only (ProviderResponse, BoundedHTTPClient). Imports of
``ai.execution``, ``ai.verification``, ``ai.finding``, ``ai.resolver``,
``ai.authorizer``, ``ai.persistence``, ``nuclei_runner``, or any
browser automation package are explicitly forbidden and would be
caught by the import-boundary test in
``tests/test_research_agent_r24_3.py``.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Callable, Iterable
from urllib.parse import urljoin, urlparse

from ai.research_agent.provider_base import (
    BoundedHTTPClient,
    ProviderResponse,
)

__all__ = [
    "MAX_REDIRECTS",
    "DEFAULT_REDIRECT_TIMEOUT",
    "DEFAULT_REDIRECT_MAX_BYTES",
    "NetGuardError",
    "RedirectResult",
    "resolve_public_ips",
    "validate_url",
    "validate_hop",
    "safe_fetch_with_redirects",
]


# -- bounds (R24 scope §4.2, §7) -------------------------------------------
MAX_REDIRECTS = 3  # 4th redirect aborts
DEFAULT_REDIRECT_TIMEOUT = 10.0
DEFAULT_REDIRECT_MAX_BYTES = 1_000_000

# Default ports per scheme (R24 scope §4.2).
_DEFAULT_PORT = {"http": 80, "https": 443}

# Hostnames that are never valid research targets, regardless of
# resolution outcome. Belt-and-braces alongside the IP-literal guard.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "kubernetes.default",
        "kubernetes.default.svc",
        "0.0.0.0",
        "::",
    }
)
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost")
_METADATA_IPS = frozenset(
    {
        "169.254.169.254",
        "169.254.169.253",
        "169.254.170.2",
        "100.100.100.200",
    }
)


class NetGuardError(ValueError):
    """Raised when a URL fails the R24.3 SSRF/redirect guard.

    Callers (the HTTP seam in :class:`BoundedHTTPClient`) catch this
    and convert it to a fail-soft ``None`` return; ``RedirectResult``
    records the reason on ``error`` and ``reason``.
    """

    def __init__(self, message: str, *, reason: str = "guard") -> None:
        super().__init__(message)
        self.reason = str(reason or "guard")


# ---------------------------------------------------------------------------
# RedirectResult
# ---------------------------------------------------------------------------
@dataclass
class RedirectResult:
    """Outcome of one bounded, manual-redirect fetcher invocation.

    ``discovered_url`` is preserved unchanged by callers; ``url`` is
    the initial URL after the R24.3 URL guard (may equal
    ``discovered_url`` when the initial URL was already canonical).
    ``final_url`` is the last URL actually fetched (empty when no
    fetch completed). ``redirect_chain`` lists every URL fetched in
    order, including the initial one.
    """

    discovered_url: str
    url: str = ""
    status: int = 0
    body: str = ""
    content_type: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    final_url: str = ""
    hops: int = 0
    # When ``error`` is non-empty the fetcher stopped early;
    # ``reason`` is a short machine-readable tag (e.g. ``"private_ip"``,
    # ``"redirect_limit"``, ``"redirect_loop"``, ``"dns_failure"``).
    error: str = ""
    reason: str = ""

    @property
    def ok(self) -> bool:
        """True when a 2xx body was successfully retrieved."""
        if self.error:
            return False
        return 200 <= int(self.status or 0) < 300


# ---------------------------------------------------------------------------
# DNS pre-resolution
# ---------------------------------------------------------------------------
ResolverFn = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    """Default resolver using :mod:`socket`. Returns one IP per record.

    Filters ``getaddrinfo`` to A/AAAA only. Any non-A/AAAA record
    (e.g. CNAME hints) is ignored; the resolver returns the
    underlying A/AAAA addresses.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, socket.timeout, UnicodeError, ValueError):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for info in infos or []:
        try:
            sockaddr = info[4]
            address = str(sockaddr[0]) if sockaddr else ""
        except Exception:
            continue
        if not address:
            continue
        if address in seen:
            continue
        seen.add(address)
        out.append(address)
    return out


def _is_non_public_ip(address: str) -> bool:
    """Return True when ``address`` is an IP literal in a non-public range.

    For non-IP strings (hostnames) this returns ``False`` because
    hostnames are validated upstream by :func:`resolve_public_ips`,
    which performs the DNS resolution and rejects any host whose
    resolved-or-literal address is non-public. Conflating an
    unparseable string with "non-public" would over-reject valid
    public hostnames.

    Uses Python's :mod:`ipaddress` predicates so IPv6 is handled
    automatically; ``is_private`` covers RFC1918, ULA, and the
    IPv6 unique-local range (``fc00::/7``); ``is_link_local`` covers
    ``169.254.0.0/16`` (incl. cloud metadata) and ``fe80::/10``.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False  # hostname, not an IP literal
    if ip.is_unspecified:
        return True
    if ip.is_loopback:
        return True
    if ip.is_link_local:
        return True
    if ip.is_multicast:
        return True
    if ip.is_reserved:
        return True
    if ip.is_private:
        return True
    # Metadata IP literal
    if str(ip) in _METADATA_IPS:
        return True
    return False


def resolve_public_ips(
    host: str,
    *,
    resolver: ResolverFn | None = None,
) -> list[str]:
    """Resolve ``host`` and return its public IPs (or ``[]`` on failure).

    Fail-closed: any private/loopback/link-local/multicast/reserved/
    metadata address causes the entire host to be rejected. The
    resolver is injected; tests pass a fake mapping, default uses
    :func:`socket.getaddrinfo`.
    """
    name = (host or "").strip().lower().rstrip(".")
    if not name:
        return []
    if name in _BLOCKED_HOSTNAMES or name.endswith(_BLOCKED_SUFFIXES):
        return []
    # Already an IP literal: validate without DNS.
    try:
        ipaddress.ip_address(name)
        if _is_non_public_ip(name):
            return []
        return [name]
    except ValueError:
        pass
    fn = resolver or _default_resolver
    try:
        addresses = fn(name)
    except Exception:
        return []
    if not addresses:
        return []
    public: list[str] = []
    for address in addresses:
        if not address or _is_non_public_ip(address):
            return []  # fail closed on any non-public address
        public.append(address)
    return public


# ---------------------------------------------------------------------------
# URL guards
# ---------------------------------------------------------------------------
def _default_port_for(scheme: str) -> int | None:
    return _DEFAULT_PORT.get(str(scheme or "").lower())


def _host_in_program(host: str, program: str | None) -> bool:
    """Return True when any DNS label of ``host`` matches ``program``."""
    token = str(program or "").strip().lower()
    if not token:
        return False
    return token in [label for label in host.split(".") if label]


def _host_allowed(host: str, allowed_hosts: Iterable[str] | None) -> bool:
    """Return True when ``host`` is in the per-provider allowlist (if any)."""
    if not allowed_hosts:
        return True
    h = (host or "").lower().rstrip(".")
    for allowed in allowed_hosts:
        a = (allowed or "").strip().lower().rstrip(".")
        if not a:
            continue
        if h == a or h.endswith("." + a):
            return True
    return False


def validate_url(
    url: str,
    *,
    program: str | None = None,
    forbidden_hosts: Iterable[str] | None = None,
    allowed_hosts: Iterable[str] | None = None,
) -> str:
    """Full URL guard for an initial fetch (no scheme-downgrade check).

    Rejects (raises :class:`NetGuardError`):

    - non-http(s) schemes
    - embedded credentials (``user:pass@host``)
    - hosts whose resolved-or-literal IP is non-public (the caller is
      expected to have already pre-resolved; this guard is a backstop)
    - default-port rule: any explicit port other than the scheme
      default is rejected
    - ``localhost`` / ``*.local`` / ``*.internal`` hostnames
    - cloud metadata hostnames and IPs
    - the program/asset host and any caller-supplied forbidden host
    - hosts outside the per-provider allowlist (when configured)

    Returns the URL unchanged on success.
    """
    text = str(url or "").strip()
    if not text:
        raise NetGuardError("empty url", reason="invalid_url")
    try:
        parsed = urlparse(text)
    except Exception as exc:
        raise NetGuardError(
            f"invalid url: {type(exc).__name__}", reason="invalid_url"
        ) from exc
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise NetGuardError(
            f"unsupported scheme: {scheme!r}", reason="scheme"
        )
    if parsed.username or parsed.password:
        raise NetGuardError(
            "url contains embedded credentials", reason="embedded_credentials"
        )
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise NetGuardError("url has no host", reason="invalid_url")
    if host in _BLOCKED_HOSTNAMES:
        raise NetGuardError(f"blocked host: {host}", reason="host")
    if host.endswith(_BLOCKED_SUFFIXES):
        raise NetGuardError(f"blocked host suffix: {host}", reason="host")
    if host in _METADATA_IPS:
        raise NetGuardError(
            f"blocked metadata address: {host}", reason="private_ip"
        )
    if _is_non_public_ip(host):
        raise NetGuardError(f"non-public host: {host}", reason="private_ip")
    # Default-port rule: any explicit port other than the scheme
    # default is rejected. ``urlparse.port`` is ``None`` for implicit
    # default ports (e.g. ``https://example.com``).
    port = parsed.port
    expected = _default_port_for(scheme)
    if port is not None and expected is not None and port != expected:
        raise NetGuardError(
            f"non-default port: {port} for scheme {scheme!r}", reason="port"
        )
    if program and _host_in_program(host, program):
        raise NetGuardError(
            f"program/asset host: {host}", reason="program_host"
        )
    if forbidden_hosts:
        normalized = {
            (h or "").strip().lower().rstrip(".")
            for h in forbidden_hosts
            if h
        }
        if host in normalized:
            raise NetGuardError(
                f"forbidden host: {host}", reason="host"
            )
    if not _host_allowed(host, allowed_hosts):
        raise NetGuardError(
            f"host not in provider allowlist: {host}", reason="allowlist"
        )
    return text


def validate_hop(
    current: str,
    location: str,
    *,
    program: str | None = None,
    forbidden_hosts: Iterable[str] | None = None,
    allowed_hosts: Iterable[str] | None = None,
) -> str:
    """Validate one redirect hop and return the resolved target URL.

    Rejects everything :func:`validate_url` rejects, plus:

    - HTTPS→HTTP scheme downgrade
    - port change (other than the implicit default-port rule)
    - relative ``Location`` is resolved via :func:`urljoin` against
      ``current`` (RFC 3986)

    Raises :class:`NetGuardError` on every rejection.
    """
    if not location:
        raise NetGuardError(
            "empty Location header", reason="invalid_url"
        )
    try:
        cur_parsed = urlparse(current)
    except Exception as exc:
        raise NetGuardError(
            f"invalid current url: {type(exc).__name__}",
            reason="invalid_url",
        ) from exc
    try:
        resolved = urljoin(current, str(location))
    except Exception as exc:
        raise NetGuardError(
            f"invalid Location url: {type(exc).__name__}",
            reason="invalid_url",
        ) from exc
    if not resolved:
        raise NetGuardError(
            "empty resolved Location", reason="invalid_url"
        )
    try:
        parsed = urlparse(resolved)
    except Exception as exc:
        raise NetGuardError(
            f"invalid Location url: {type(exc).__name__}",
            reason="invalid_url",
        ) from exc
    cur_scheme = (cur_parsed.scheme or "").lower()
    new_scheme = (parsed.scheme or "").lower()
    if cur_scheme == "https" and new_scheme == "http":
        raise NetGuardError(
            "https→http scheme downgrade rejected", reason="scheme_downgrade"
        )
    # Port-change rule: any explicit port that differs from the
    # previous explicit port OR from the new scheme's default is
    # rejected.
    new_port = parsed.port
    expected = _default_port_for(new_scheme)
    if new_port is not None and expected is not None and new_port != expected:
        raise NetGuardError(
            f"non-default port: {new_port} for scheme {new_scheme!r}",
            reason="port",
        )
    if parsed.username or parsed.password:
        raise NetGuardError(
            "hop url contains embedded credentials", reason="embedded_credentials"
        )
    # Re-run the rest of the URL guard on the resolved URL.
    return validate_url(
        resolved,
        program=program,
        forbidden_hosts=forbidden_hosts,
        allowed_hosts=allowed_hosts,
    )


# ---------------------------------------------------------------------------
# Manual redirect walker
# ---------------------------------------------------------------------------
def _status_says_redirect(status: int) -> bool:
    """Return True when ``status`` is a 3xx redirect."""
    return 300 <= int(status or 0) < 400


def _extract_location(response: ProviderResponse | None) -> str:
    """Return the ``Location`` header from a response (or ``""``)."""
    if response is None:
        return ""
    # ProviderResponse does not currently carry headers; the transport
    # in :class:`BoundedHTTPClient` is expected to put the Location
    # value into the ``content_type`` slot as a backward-compatible
    # workaround (or expose ``final_url`` for the redirect target).
    # We accept any of: an explicit ``headers`` attribute, a non-empty
    # ``content_type`` prefixed by ``location:``, or a ``final_url``
    # that differs from ``url``.
    headers = getattr(response, "headers", None)
    if isinstance(headers, dict):
        loc = headers.get("Location") or headers.get("location") or ""
        if loc:
            return str(loc).strip()
    ct = response.content_type or ""
    if ct.lower().startswith("location:"):
        return ct.split(":", 1)[1].strip()
    # Fallback: a different ``final_url`` is itself a redirect target
    # hint supplied by the transport.
    if response.final_url and response.final_url != response.url:
        return response.final_url.strip()
    return ""


def safe_fetch_with_redirects(
    url: str,
    *,
    transport: Callable[..., ProviderResponse | None] | None = None,
    resolver: ResolverFn | None = None,
    timeout: float = DEFAULT_REDIRECT_TIMEOUT,
    max_bytes: int = DEFAULT_REDIRECT_MAX_BYTES,
    max_redirects: int = MAX_REDIRECTS,
    program: str | None = None,
    forbidden_hosts: Iterable[str] | None = None,
    allowed_hosts: Iterable[str] | None = None,
    method: str = "GET",
) -> RedirectResult:
    """One bounded, manual-redirect fetcher call.

    Behavior:

    1. Resolve the initial URL's host via :func:`resolve_public_ips`;
       fail closed on DNS errors / non-public addresses.
    2. :func:`validate_url` the initial URL (default-port rule,
       no-credentials, host guard, allowlist, program-host).
    3. Issue a single GET via ``transport``. On 3xx with a Location
       header, validate the hop via :func:`validate_hop` and repeat.
       The 4th redirect is a hard stop.
    4. Track every URL actually fetched in ``redirect_chain``;
       ``final_url`` is the last fetched URL (empty if no fetch
       completed).
    5. Any guard / transport failure yields a ``RedirectResult`` with
       ``error`` set and an empty body (fail-soft).
    """
    initial = str(url or "").strip()
    result = RedirectResult(discovered_url=initial, url=initial)

    # Step 1 — DNS pre-resolution on the initial host.
    try:
        parsed = urlparse(initial)
    except Exception as exc:
        result.error = f"invalid initial url: {type(exc).__name__}"
        result.reason = "invalid_url"
        return result
    initial_host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not initial_host:
        result.error = "no host"
        result.reason = "invalid_url"
        return result
    pub = resolve_public_ips(initial_host, resolver=resolver)
    if not pub:
        result.error = f"non-public host: {initial_host}"
        result.reason = "private_ip"
        return result

    # Step 2 — initial URL guard.
    try:
        current = validate_url(
            initial,
            program=program,
            forbidden_hosts=forbidden_hosts,
            allowed_hosts=allowed_hosts,
        )
    except NetGuardError as exc:
        result.error = str(exc)
        result.reason = getattr(exc, "reason", "guard")
        return result

    if transport is None:
        result.error = "no transport configured"
        result.reason = "transport"
        return result

    # Step 3 — initial GET.
    seen: set[str] = {current}
    chain: list[str] = [current]
    response = _call_transport(
        transport,
        method,
        current,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    if response is None:
        result.error = "transport returned None"
        result.reason = "transport"
        return result
    hops = 0
    # Track the last fetched URL (may differ from ``current`` if the
    # transport itself rewrites the URL during a single GET).
    last_fetched_url = response.url or current

    # Step 4 — redirect loop.
    while _status_says_redirect(response.status):
        if hops >= max(int(max_redirects or 0), 0):
            result.status = response.status
            result.body = response.body or ""
            result.content_type = response.content_type or ""
            result.redirect_chain = chain
            result.final_url = last_fetched_url
            result.hops = hops
            result.error = "redirect_limit"
            result.reason = "redirect_loop"
            return result
        location = _extract_location(response)
        if not location:
            # No Location; treat as a non-redirect final response.
            break
        try:
            next_url = validate_hop(
                current,
                location,
                program=program,
                forbidden_hosts=forbidden_hosts,
                allowed_hosts=allowed_hosts,
            )
        except NetGuardError as exc:
            result.status = response.status
            result.body = response.body or ""
            result.content_type = response.content_type or ""
            result.redirect_chain = chain
            result.final_url = last_fetched_url
            result.hops = hops
            result.error = str(exc)
            result.reason = getattr(exc, "reason", "guard")
            return result
        if next_url in seen:
            result.status = response.status
            result.body = response.body or ""
            result.content_type = response.content_type or ""
            result.redirect_chain = chain
            result.final_url = last_fetched_url
            result.hops = hops
            result.error = "redirect loop detected"
            result.reason = "redirect_loop"
            return result
        # DNS pre-resolution on the hop host.
        try:
            hop_parsed = urlparse(next_url)
            hop_host = (hop_parsed.hostname or "").strip().lower().rstrip(".")
            pub = resolve_public_ips(hop_host, resolver=resolver)
        except Exception:
            pub = []
        if not pub:
            result.status = response.status
            result.body = response.body or ""
            result.content_type = response.content_type or ""
            result.redirect_chain = chain
            result.final_url = last_fetched_url
            result.hops = hops
            result.error = f"non-public hop host: {hop_host}"
            result.reason = "private_ip"
            return result
        # Fetch the next hop.
        seen.add(next_url)
        chain.append(next_url)
        hops += 1
        current = next_url
        response = _call_transport(
            transport,
            method,
            current,
            timeout=timeout,
            max_bytes=max_bytes,
        )
        if response is None:
            result.status = 0
            result.body = ""
            result.content_type = ""
            result.redirect_chain = chain
            result.final_url = last_fetched_url
            result.hops = hops
            result.error = "transport returned None on hop"
            result.reason = "transport"
            return result
        last_fetched_url = response.url or current

    # Step 5 — finalize.
    body = response.body or ""
    if len(body) > int(max_bytes):
        body = body[: int(max_bytes)]
    result.status = response.status
    result.body = body
    result.content_type = response.content_type or ""
    result.redirect_chain = chain
    result.final_url = last_fetched_url or current
    result.hops = hops
    result.error = ""
    result.reason = ""
    return result


def _call_transport(
    transport: Callable[..., ProviderResponse | None],
    method: str,
    url: str,
    *,
    timeout: float,
    max_bytes: int,
) -> ProviderResponse | None:
    """Invoke the injected transport; convert any exception to ``None``."""
    try:
        return transport(
            str(method or "GET").upper(),
            url,
            params={},
            headers={},
            timeout=timeout,
            max_bytes=max_bytes,
        )
    except Exception:
        return None
