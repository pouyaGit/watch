"""Stage R24.2 — search provider protocol and network safety primitives.

This module defines the small deterministic interface that every concrete
public-source discovery provider must conform to, plus the bounded network
safety primitives reused by every provider implementation.

Design constraints (R24 scope):

- Providers receive only a :class:`~ai.research_agent.discovery_contract.
  DiscoveryQuery` (or the deliberately limited fields they need from it).
  Program, target URL/host/IP, asset, endpoint, response, credentials,
  cookies, and headers are structurally absent and never accepted.
- All network access is funneled through :class:`BoundedHTTPClient`, which
  enforces HTTPS preferred, finite connect/read timeout, finite response
  body size, no streaming, no credentials/cookies/headers from callers, and
  fail-soft semantics. R24.3 will harden redirects and DNS resolution in a
  separate module; this module deliberately does NOT perform redirect
  validation or DNS pre-resolution.
- No subprocess, no ``eval``/``exec``, no shell execution, no target
  interaction, no Nuclei execution, no browser automation, no
  ``ai.execution``/``ai.verification``/``ai.finding``/``ai.resolver``/
  ``ai.authorizer``/``ai.persistence``/``nuclei_runner`` imports.
- URL validation is delegated to the existing R23
  :func:`ai.research_agent.sources.validate_source_url` so R24.2 reuses the
  SSRF guard the agent already relies on; redirect-hop validation remains
  a R24.3 concern and is explicitly out of scope here.

Import boundary: standard library + the R24.1 contract + the existing R23
neutral URL validator. No HTTP client modules (``requests``, ``httpx``,
``socket``, ``urllib.request``) are imported at module load time; providers
that need a transport receive an injected ``transport`` callable so tests
can substitute a fake transport and the test suite never touches the live
network.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol
from urllib.parse import urlparse

from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    DiscoveryQuery,
    ForbiddenInputError,
    Lifecycle,
    SearchProvider,
    SourceCategory,
    TrustTier,
    assert_no_forbidden_input,
    discovered_source_id,
)
from ai.research_agent.sources import (
    SourceValidationError,
    validate_source_url,
)
from ai.schemas.research_agent import SOURCE_STORED_ONLY

__all__ = [
    "ProviderTransport",
    "ProviderResponse",
    "BoundedHTTPError",
    "BoundedHTTPClient",
    "SearchProviderProtocol",
    "ProviderRegistry",
    "build_default_registry",
    "classify_host",
    "classify_nvd_host",
    "classify_github_host",
    "classify_vendor_host",
    "classify_wordfence_host",
    "classify_wpscan_host",
    "classify_detection_rule_host",
    "classify_generic_host",
    "DEFAULT_PROVIDER_TIMEOUT",
    "DEFAULT_PROVIDER_MAX_BYTES",
    "MAX_RESULTS_PER_QUERY",
    "MAX_PROVIDER_RESULTS_PER_QUERY",
]


# -- bounds (R24 scope §7) ----------------------------------------------------------
DEFAULT_PROVIDER_TIMEOUT = 10.0  # seconds connect+read
DEFAULT_PROVIDER_MAX_BYTES = 1_000_000  # 1 MB hard cap per response body
MAX_RESULTS_PER_QUERY = 10  # R24 scope §7 "Results per query = 10"
MAX_PROVIDER_RESULTS_PER_QUERY = MAX_RESULTS_PER_QUERY

# Field names that must never appear in provider discovery input. These are
# separate from the R24.1 token-based forbidden-input invariant: they
# represent the structural shape of the input (no target/program/asset shape).
_PROVIDER_FORBIDDEN_INPUT_FIELDS: frozenset[str] = frozenset(
    {
        "target_url",
        "target_host",
        "target_ip",
        "target",
        "program",
        "asset",
        "endpoint",
        "response",
        "credentials",
        "cookies",
        "headers",
        "url",  # URLs are never passed in; providers build fixed canonical URLs.
    }
)


class BoundedHTTPError(RuntimeError):
    """Raised internally by :class:`BoundedHTTPClient` when an HTTP call fails.

    Providers catch every ``BoundedHTTPError`` and any other unexpected
    exception and convert it to a fail-soft empty list of discovered sources;
    the exception type is therefore only used as a marker for tests.
    """


@dataclass(frozen=True)
class ProviderResponse:
    """Bounded HTTP response returned by an injected provider transport."""

    url: str
    status: int
    body: str
    content_type: str = ""
    # Final URL after redirect resolution by the transport. R24.2 does NOT
    # validate redirect hops; R24.3 owns that. The transport simply records
    # the URL it last received.
    final_url: str = ""

    @property
    def ok(self) -> bool:
        """Return True only for definitive success statuses.

        2xx is accepted but ``202 Accepted`` (a non-content status used
        by some public providers to signal "still working") is treated as
        a fail-soft miss by R24.2 Wordfence/WPScan paths. Providers that
        need a stricter or looser check can compare ``status`` directly.
        """
        status = int(self.status or 0)
        if status in (202,):
            return False
        return 200 <= status < 300


# A transport is any callable with the signature
# ``transport(method, url, *, params=None, headers=None, timeout, max_bytes)``
# returning a :class:`ProviderResponse` or ``None``. Tests inject fakes; the
# default no-network implementation rejects every call.
ProviderTransport = Callable[..., ProviderResponse | None]


class BoundedHTTPClient:
    """Bounded, fail-soft HTTP client used by R24.2 providers.

    The client is transport-injected. The default transport (``None``)
    rejects every call and returns ``None`` so providers behave as
    ``fail-soft → []`` in environments without network access.

    Network guarantees enforced at this layer (R24.2 scope):

    - HTTPS preferred; HTTP allowed only when a provider explicitly asks
      for it (the public NVD/GitHub/Wordfence/WPScan endpoints used here
      are all HTTPS).
    - Finite ``timeout`` (connect+read) per call.
    - Finite ``max_bytes`` response size (no streaming).
    - No credentials, cookies, or caller-supplied headers. A fixed neutral
      ``User-Agent`` is the only header sent.
    - No link following: the client exposes a single-shot ``request``
      method and never follows links discovered in a response.
    - Pre-fetch SSRF guard via the existing R23
      :func:`validate_source_url`; redirect-hop validation is deferred to
      R24.3 and is **not** performed here.

    Fail-soft: any exception is caught and surfaced as a ``None`` response,
    so a single provider's failure never aborts a research run.
    """

    DEFAULT_TIMEOUT = DEFAULT_PROVIDER_TIMEOUT
    DEFAULT_MAX_BYTES = DEFAULT_PROVIDER_MAX_BYTES

    NEUTRAL_USER_AGENT = (
        "Watch-Security-Researcher/0.1 (authorized security research)"
    )

    def __init__(
        self,
        *,
        transport: ProviderTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        forbidden_tokens: Iterable[str] = (),
        allowed_hosts: Iterable[str] | None = None,
        route_through_netguard: bool = False,
        resolver: Any = None,
        forbidden_hosts: Iterable[str] | None = None,
        max_redirects: int | None = None,
    ) -> None:
        self._transport = transport
        self.timeout = max(float(timeout), 0.1)
        # max_bytes is a hard cap on response body size; small values
        # are honoured so tests can use tiny caps. A 1-byte floor guards
        # against absurd zero values.
        self.max_bytes = max(int(max_bytes), 1)
        self._forbidden = tuple(sorted({str(t or "") for t in forbidden_tokens if t}))
        normalized_hosts: set[str] = set()
        if allowed_hosts is not None:
            for host in allowed_hosts:
                text = str(host or "").strip().lower().rstrip(".")
                if text:
                    normalized_hosts.add(text)
        self._allowed_hosts = frozenset(normalized_hosts)
        # R24.8: when enabled, ALL traffic (provider discovery AND
        # source-body fetching) must pass through the R24.3 netguard
        # (DNS pre-resolution + per-hop redirect validation). Off by
        # default so the R24.2 unit tests keep their injected transport
        # semantics; the production discovery factory enables it.
        self._route_through_netguard = bool(route_through_netguard)
        self._resolver = resolver
        self._forbidden_hosts = frozenset(
            (h or "").strip().lower().rstrip(".") for h in (forbidden_hosts or ()) if h
        )
        self._max_redirects = max_redirects
        self.requests_made = 0
        self.bytes_received = 0
        self.last_error: str | None = None

    # -- host/IP guards ----------------------------------------------------
    @staticmethod
    def _is_private_ip(host: str) -> bool:
        """Return True when ``host`` is a non-public IP literal."""
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    def _host_allowed(self, host: str) -> bool:
        """Enforce the per-provider allowlist (when configured).

        When no allowlist is configured the transport is trusted to point
        only at fixed canonical endpoints; the per-provider allowlist is a
        defense-in-depth check on top of that.
        """
        if not self._allowed_hosts:
            return True
        h = host.lower().rstrip(".")
        if h in self._allowed_hosts:
            return True
        return any(h.endswith("." + allowed) for allowed in self._allowed_hosts)

    # -- public request ----------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
    ) -> ProviderResponse | None:
        """Issue one bounded HTTP request. Returns ``None`` on any failure.

        No headers/cookies/credentials are accepted from callers. The
        transport receives a fixed neutral ``User-Agent`` header. Any
        exception is converted to ``None`` and recorded in ``last_error``
        so providers can convert it to a fail-soft empty result.

        R24.8: when ``route_through_netguard`` is enabled this delegates to
        :meth:`request_via_netguard` so DNS pre-resolution and per-hop
        redirect validation apply to provider discovery as well.
        """
        if self._route_through_netguard:
            return self.request_via_netguard(
                method,
                url,
                params=params,
                forbidden_hosts=set(self._forbidden_hosts),
                max_redirects=self._max_redirects,
            )
        verb = str(method or "GET").upper()
        text_url = str(url or "").strip()
        if not text_url:
            self.last_error = "empty url"
            return None
        try:
            parsed = urlparse(text_url)
        except Exception as exc:
            self.last_error = f"invalid url: {type(exc).__name__}"
            return None
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            self.last_error = f"unsupported scheme: {scheme!r}"
            return None
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            self.last_error = "no host"
            return None
        if self._is_private_ip(host):
            self.last_error = f"non-public host: {host}"
            return None
        if not self._host_allowed(host):
            self.last_error = f"host not in provider allowlist: {host}"
            return None
        if self._forbidden:
            try:
                assert_no_forbidden_input(text_url, self._forbidden)
            except ForbiddenInputError as exc:
                self.last_error = f"forbidden token in url: {exc}"
                return None
        try:
            validate_source_url(text_url)
        except SourceValidationError as exc:
            self.last_error = f"url rejected by ssrf guard: {exc}"
            return None

        self.requests_made += 1
        if self._transport is None:
            self.last_error = "no transport configured"
            return None
        try:
            response = self._transport(
                verb,
                text_url,
                params=params or {},
                headers={"User-Agent": self.NEUTRAL_USER_AGENT},
                timeout=self.timeout,
                max_bytes=self.max_bytes,
            )
        except Exception as exc:
            self.last_error = f"transport error: {type(exc).__name__}"
            return None
        if response is None:
            self.last_error = self.last_error or "transport returned None"
            return None
        body = response.body or ""
        if len(body) > self.max_bytes:
            body = body[: self.max_bytes]
            response = ProviderResponse(
                url=response.url,
                status=response.status,
                body=body,
                content_type=response.content_type,
                final_url=response.final_url or response.url,
            )
        # Always rebuild the response with the bounded body so the
        # caller never sees bytes past the configured cap, regardless
        # of whether the truncation branch above ran.
        if response.body != body:
            response = ProviderResponse(
                url=response.url,
                status=response.status,
                body=body,
                content_type=response.content_type,
                final_url=response.final_url or response.url,
            )
        self.bytes_received += len(body)
        return response

    # -- helpers -----------------------------------------------------------
    def get_json(self, url: str, *, params: dict | None = None) -> Any:
        """GET a URL and parse the bounded body as JSON. ``None`` on any failure."""
        response = self.request("GET", url, params=params)
        if response is None or not response.ok:
            return None
        import json

        try:
            return json.loads(response.body or "")
        except Exception:
            return None

    def get_text(self, url: str, *, params: dict | None = None) -> str:
        """GET a URL and return the bounded body text. ``""`` on any failure."""
        response = self.request("GET", url, params=params)
        if response is None or not response.ok:
            return ""
        return response.body or ""

    # -- R24.3 seam: DNS pre-resolution + manual redirects -----------------
    def request_via_netguard(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        program: str | None = None,
        forbidden_hosts: set[str] | None = None,
        max_redirects: int | None = None,
    ) -> "ProviderResponse | None":
        """Like :meth:`request` but with R24.3 DNS pre-resolution and
        manual-redirect handling with per-hop validation.

        Behaviour:

        - DNS pre-resolution via :mod:`ai.research_agent.netguard` rejects
          loopback, private, link-local, multicast, reserved,
          unspecified, and metadata/service IP ranges (IPv4 + IPv6).
        - Manual ``follow_redirects=False``-equivalent: up to
          ``max_redirects`` (default :data:`MAX_REDIRECTS = 3`); the 4th
          redirect is a hard stop. Every Location hop is re-validated
          (scheme downgrade, embedded credentials, port, host).
        - On any guard / transport failure the call returns ``None``
          and ``self.last_error`` is set.
        - The returned :class:`ProviderResponse` carries the final
          fetched body and ``final_url`` = the last validated URL.
          Callers that need the full redirect chain should use
          :func:`ai.research_agent.netguard.safe_fetch_with_redirects`
          directly.
        """
        # Lazy import: keep provider_base import-time cheap and let
        # test suites that don't exercise redirects avoid loading
        # netguard at all.
        from ai.research_agent.netguard import (
            DEFAULT_REDIRECT_MAX_BYTES,
            DEFAULT_REDIRECT_TIMEOUT,
            MAX_REDIRECTS,
            safe_fetch_with_redirects,
        )

        text_url = str(url or "").strip()
        if not text_url:
            self.last_error = "empty url"
            return None
        result = safe_fetch_with_redirects(
            text_url,
            transport=self._transport,
            resolver=self._resolver,
            timeout=float(self.timeout or DEFAULT_REDIRECT_TIMEOUT),
            max_bytes=int(self.max_bytes or DEFAULT_REDIRECT_MAX_BYTES),
            max_redirects=(
                MAX_REDIRECTS if max_redirects is None else int(max_redirects)
            ),
            program=program,
            forbidden_hosts=forbidden_hosts,
            allowed_hosts=self._allowed_hosts,
            method=str(method or "GET"),
        )
        if result.error or result.status == 0:
            self.last_error = (
                result.error or "no response"
            ) + (
                f" (reason={result.reason})" if result.reason else ""
            )
            self.requests_made += 1
            return None
        self.requests_made += 1
        self.bytes_received += len(result.body or "")
        # Build a ProviderResponse that mirrors the R24.2 shape so
        # downstream code that already consumes ``final_url`` and
        # ``body`` keeps working. The full redirect chain is recorded
        # on ``final_url`` (last URL) for callers that need it; the
        # chain itself is preserved on ``content_type`` prefixed with
        # ``chain=`` (testable) when present, since ProviderResponse
        # has no headers field in R24.2.
        ct = result.content_type or ""
        if result.redirect_chain:
            ct = ct + (f";chain={';'.join(result.redirect_chain)}" if ct else f"chain={';'.join(result.redirect_chain)}")
        return ProviderResponse(
            url=result.url,
            status=result.status,
            body=result.body,
            content_type=ct,
            final_url=result.final_url,
        )


# -----------------------------------------------------------------------------
# Provider protocol
# -----------------------------------------------------------------------------
class SearchProviderProtocol(Protocol):
    """Deterministic public-source discovery provider.

    Implementations accept only a :class:`DiscoveryQuery` (and the
    deliberately bounded fields derived from it) and return a list of
    :class:`DiscoveredSource` items. Implementations MUST be:

    - deterministic with respect to ``DiscoveryQuery`` provenance
      (i.e. always emit the same query id / template id / provider);
    - bounded in result count (``<= MAX_RESULTS_PER_QUERY``);
    - bounded in network time and bytes (via :class:`BoundedHTTPClient`);
    - fail-soft (any error returns ``[]``);
    - safe (rejects forbidden target/program/asset input via
      :func:`assert_no_forbidden_input`).
    """

    provider_id: str

    def discover(self, query: DiscoveryQuery) -> list[DiscoveredSource]:
        """Return up to ``MAX_RESULTS_PER_QUERY`` discovered sources."""


# -----------------------------------------------------------------------------
# Provider-input guard
# -----------------------------------------------------------------------------
_HOST_LIKE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,}$")


def _assert_provider_input_safe(query: DiscoveryQuery) -> None:
    """Reject any query whose payload carries a forbidden field/value.

    The :class:`DiscoveryQuery` dataclass is already structurally
    limited, so this is mostly a defense-in-depth check: we re-validate
    the rendered query text against the supplied ``forbidden_tokens`` (if
    any) and verify the query has the only keys we accept.
    """
    model_fields = getattr(type(query), "model_fields", None)
    if isinstance(model_fields, dict):
        actual = set(model_fields.keys())
    else:
        actual = set()
    forbidden_seen = actual & _PROVIDER_FORBIDDEN_INPUT_FIELDS
    if forbidden_seen:
        raise ForbiddenInputError(
            "provider received a forbidden input field: "
            + ", ".join(sorted(forbidden_seen))
        )
    text = str(query.query or "")
    # Reject any DNS-style host material in inputs_used (the primary
    # R24.1 token-level forbidden-input check is performed by the
    # ``QueryBuilder``; the provider layer adds a structural check so
    # any host-like token reaching a provider is rejected even when the
    # caller forgot to wire ``forbidden_tokens``).
    for value in query.inputs_used or ():
        candidate = str(value or "").strip()
        if candidate and _HOST_LIKE_RE.match(candidate):
            raise ForbiddenInputError(
                "provider input contains a DNS-style host: "
                + candidate
            )
    if not text:
        # Empty queries are not search errors; providers may simply return [].
        return
    # The query itself is structurally query-only and was sanitized at
    # build time, so this is a redundant guard.
    assert_no_forbidden_input(text, ())


# -----------------------------------------------------------------------------
# Host -> category/tier classification helpers (R24.1 vocabulary)
# -----------------------------------------------------------------------------
_NVD_HOSTS = frozenset(
    {
        "nvd.nist.gov",
        "cve.mitre.org",
        "cve.org",
    }
)
_GITHUB_HOSTS = frozenset(
    {
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "gist.github.com",
    }
)
_WORDFENCE_HOSTS = frozenset(
    {
        "www.wordfence.com",
        "wordfence.com",
    }
)
_WPSCAN_HOSTS = frozenset(
    {
        "wpscan.com",
        "www.wpscan.com",
    }
)
_VENDOR_HOSTS = frozenset(
    {
        "msrc.microsoft.com",
        "www.microsoft.com",
        "www.oracle.com",
        "access.redhat.com",
        "helpx.adobe.com",
        "www.apache.org",
        "wordpress.org",
        "plugins.trac.wordpress.org",
        "www.drupal.org",
        "www.nginx.com",
        "nodejs.org",
        "www.php.net",
        "www.python.org",
        "github.io",
    }
)
_DETECTION_RULE_HOSTS = frozenset(
    {
        "github.com",
        "raw.githubusercontent.com",
        "gist.github.com",
        "cloud.google.com",
        "www.crowdsec.net",
        "sigmahq.io",
        "yaraify.abuse.ch",
        "rules.emergingthreats.net",
    }
)


def classify_nvd_host(host: str) -> tuple[SourceCategory, TrustTier]:
    """Classify a discovered NVD/MITRE/CVE.org URL."""
    return SourceCategory.NVD_CVE, TrustTier.TRUSTED


def classify_github_host(host: str) -> tuple[SourceCategory, TrustTier]:
    """Classify a discovered GitHub URL by host.

    Advisory URLs (``/advisories``) are mapped at call-site because the
    classification depends on the URL path, not only the host. This
    helper returns the default (``github_repo`` / ``DISCOVERY_ONLY``) and
    the path-aware classification is performed inside
    :class:`GitHubSearchProvider`.
    """
    return SourceCategory.GITHUB_REPO, TrustTier.DISCOVERY_ONLY


def classify_vendor_host(host: str) -> tuple[SourceCategory, TrustTier]:
    """Classify a vendor advisory URL."""
    return SourceCategory.VENDOR_ADVISORY, TrustTier.TRUSTED


def classify_wordfence_host(host: str) -> tuple[SourceCategory, TrustTier]:
    """Classify a Wordfence Threat Intel URL."""
    return SourceCategory.WORDFENCE, TrustTier.SEMI_TRUSTED


def classify_wpscan_host(host: str) -> tuple[SourceCategory, TrustTier]:
    """Classify a WPScan vulnerability database URL."""
    return SourceCategory.WPSCAN, TrustTier.SEMI_TRUSTED


def classify_detection_rule_host(host: str) -> tuple[SourceCategory, TrustTier]:
    """Classify a public detection-rule URL.

    Detection rules are DISCOVERY_ONLY by default. Advisory-backed rules
    (those that also reference an NVD record) MAY be promoted later by
    R24.4/R24.5; in R24.2 the default is conservative
    (``DISCOVERY_ONLY``).
    """
    return SourceCategory.DETECTION_RULE, TrustTier.DISCOVERY_ONLY


def classify_generic_host(host: str) -> tuple[SourceCategory, TrustTier]:
    """Classify a generic search engine result URL."""
    return SourceCategory.GENERIC_SEARCH, TrustTier.GENERIC


def classify_host(
    host: str,
) -> tuple[SourceCategory, TrustTier]:
    """Deterministic host-based category/tier classification.

    The classification uses the same neutral vocabulary as the existing
    R23 ``classify_source`` helper but exposes the R24.1
    ``SourceCategory``/``TrustTier`` enums for the discovery layer.
    """
    text = (host or "").strip().lower().rstrip(".")
    if text in _NVD_HOSTS:
        return SourceCategory.NVD_CVE, TrustTier.TRUSTED
    if text in _GITHUB_HOSTS:
        return SourceCategory.GITHUB_REPO, TrustTier.DISCOVERY_ONLY
    if text in _WORDFENCE_HOSTS:
        return SourceCategory.WORDFENCE, TrustTier.SEMI_TRUSTED
    if text in _WPSCAN_HOSTS:
        return SourceCategory.WPSCAN, TrustTier.SEMI_TRUSTED
    if text in _VENDOR_HOSTS:
        return SourceCategory.VENDOR_ADVISORY, TrustTier.TRUSTED
    if text in _DETECTION_RULE_HOSTS:
        return SourceCategory.DETECTION_RULE, TrustTier.DISCOVERY_ONLY
    return SourceCategory.GENERIC_SEARCH, TrustTier.GENERIC


# -----------------------------------------------------------------------------
# Source builder
# -----------------------------------------------------------------------------
def make_discovered_source(
    *,
    url: str,
    provider: SearchProvider,
    query: DiscoveryQuery,
    category: SourceCategory,
    tier: TrustTier,
    title: str | None = None,
    lifecycle: Lifecycle = Lifecycle.DISCOVERED_SOURCE,
    source_type: str | None = None,
    note: str = "",
) -> DiscoveredSource:
    """Build a fully populated :class:`DiscoveredSource` for one result.

    The caller MUST have already validated the URL (this helper does not
    raise on URL rejection; it falls back to an empty ``url`` and a
    bounded note so the discovery layer can record the rejection reason
    in provenance rather than failing the whole run).
    """
    text = str(url or "").strip()
    valid = True
    if text:
        try:
            text = validate_source_url(text)
        except SourceValidationError as exc:
            text = ""
            valid = False
            note = (note + " " if note else "") + f"rejected: {exc}"
    source_id = discovered_source_id(text) if text else discovered_source_id(url or "")
    return DiscoveredSource(
        source_id=source_id,
        url=text,
        source_type=str(source_type or category.value),
        title=title,
        status=SOURCE_STORED_ONLY,
        lifecycle=lifecycle,
        category=category,
        tier=tier,
        discovery_provider=provider.value,
        discovery_query=query.query,
        discovery_template_id=query.template_id,
        discovered_url=str(url or ""),
        final_url=text or None,
        redirect_chain=[text] if text and text != str(url or "") else [],
        note=note,
        production_finding=False,
    ) if valid else DiscoveredSource(
        source_id=source_id,
        url="",
        source_type=str(source_type or category.value),
        title=title,
        status=SOURCE_STORED_ONLY,
        lifecycle=lifecycle,
        category=category,
        tier=tier,
        discovery_provider=provider.value,
        discovery_query=query.query,
        discovery_template_id=query.template_id,
        discovered_url=str(url or ""),
        final_url=None,
        redirect_chain=[],
        note=note,
        production_finding=False,
    )


# -----------------------------------------------------------------------------
# Provider registry
# -----------------------------------------------------------------------------
@dataclass
class ProviderRegistry:
    """Deterministic registry of R24.2 search providers.

    The registry fixes the closed set of provider identifiers declared by
    R24.1's :class:`SearchProvider` enum and exposes a single
    ``discover(provider, query)`` entry point. Adding a new provider
    identifier requires editing the enum in the R24.1 contract first;
    R24.2 does not introduce new identifiers.
    """

    providers: dict[str, SearchProviderProtocol] = field(default_factory=dict)
    fallback_provider: SearchProviderProtocol | None = None

    def __post_init__(self) -> None:
        # Reject any provider id that is not part of the closed
        # ``SearchProvider`` enum; new identifiers must be added to the
        # R24.1 contract first.
        closed = {member.value for member in SearchProvider}
        for key in list(self.providers.keys()):
            if key not in closed:
                raise ValueError(
                    f"unknown provider id {key!r}; allowed: {sorted(closed)}"
                )

    @property
    def provider_ids(self) -> tuple[str, ...]:
        """The deterministic ordered tuple of registered provider ids."""
        return tuple(self.providers.keys())

    def get(self, provider_id: str) -> SearchProviderProtocol | None:
        """Return the registered provider for ``provider_id`` (or ``None``)."""
        return self.providers.get(str(provider_id or "").strip().lower())

    def discover(
        self, provider_id: str, query: DiscoveryQuery
    ) -> list[DiscoveredSource]:
        """Dispatch ``discover`` to the registered provider.

        Unknown provider ids return ``[]`` (fail-soft) rather than raising;
        this lets a future stage route through a fallback without
        destabilising earlier stages.
        """
        provider = self.get(provider_id)
        if provider is None:
            return []
        try:
            _assert_provider_input_safe(query)
        except ForbiddenInputError:
            return []
        try:
            results = provider.discover(query)
        except Exception:
            return []
        if not isinstance(results, list):
            return []
        # Provider contract: bounded result count, production_finding=False.
        bounded: list[DiscoveredSource] = []
        for item in results:
            if len(bounded) >= MAX_PROVIDER_RESULTS_PER_QUERY:
                break
            if not isinstance(item, DiscoveredSource):
                continue
            if item.production_finding:
                continue
            if item.discovery_provider != str(provider_id):
                # Provider tried to relabel the result; force the id.
                item = item.model_copy(
                    update={"discovery_provider": str(provider_id)}
                )
            if not item.discovery_query:
                item = item.model_copy(update={"discovery_query": query.query})
            if not item.discovery_template_id:
                item = item.model_copy(
                    update={"discovery_template_id": query.template_id}
                )
            bounded.append(item)
        return bounded


def build_default_registry(
    *,
    http_client: BoundedHTTPClient | None = None,
    forbidden_tokens: Iterable[str] = (),
) -> ProviderRegistry:
    """Build the closed R24.2 default provider registry.

    Importing is deferred so the registry can be constructed without
    loading the concrete provider implementations when only the registry
    shape is needed (e.g. in tests for the closed enum set).
    """
    # Local import to avoid a circular import: providers.py imports from
    # this module.
    from ai.research_agent.providers import build_providers

    providers = build_providers(
        http_client=http_client,
        forbidden_tokens=forbidden_tokens,
    )
    return ProviderRegistry(providers=providers)
