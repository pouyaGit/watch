"""EPIC15 §10/§11/§12 — isolation, network and redirect policy.

The policy a browser lane *would* have to satisfy, expressed
deterministically and enforced at every decision point this package
reaches.  Nothing here opens a socket, resolves a name or launches
anything: it is a pure decision function over a URL, the authorized scope
and the frozen ceilings.

Network policy (§11) — a browser verification must never become an SSRF
primitive:

* no loopback, no private/RFC1918 ranges, no link-local or cloud
  metadata addresses (169.254.0.0/16, ``metadata.google.internal``),
  no ``0.0.0.0/8``, no IPv6 loopback/ULA/link-local;
* no ``file://``, ``data:``, ``javascript:``, ``ftp:``, ``gopher:`` or any
  scheme other than ``http``/``https``;
* no port outside the authorized set;
* no destination outside the authorized host set (which is itself bound
  to the recorded scope) — a redirect that leaves it stops the attempt and
  is recorded as ``REDIRECT_OUT_OF_SCOPE``.

Cookie/request safety (§12): the browser context starts clean — no user
profile, no stored cookies, no credentials, no extensions, no host
filesystem, no downloads — and no credential header is ever attached by
this layer.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from ai.limits import ceilings as ce

ISOLATION_VERSION = "epic15-isolation-1"

#: decisions (closed vocabulary)
NAVIGATION_ALLOWED = "NAVIGATION_ALLOWED"
NAVIGATION_BLOCKED = "NAVIGATION_BLOCKED"
REDIRECT_OUT_OF_SCOPE = "REDIRECT_OUT_OF_SCOPE"
SCHEME_BLOCKED = "SCHEME_BLOCKED"
PORT_BLOCKED = "PORT_BLOCKED"
DESTINATION_BLOCKED = "DESTINATION_BLOCKED"
CREDENTIAL_BLOCKED = "CREDENTIAL_BLOCKED"

NAVIGATION_DECISIONS: tuple[str, ...] = (
    NAVIGATION_ALLOWED, NAVIGATION_BLOCKED, REDIRECT_OUT_OF_SCOPE,
    SCHEME_BLOCKED, PORT_BLOCKED, DESTINATION_BLOCKED, CREDENTIAL_BLOCKED)

ALLOWED_SCHEMES: tuple[str, ...] = ("http", "https")
ALLOWED_PORTS: tuple[int, ...] = (80, 443)

#: host names that always resolve to something local or sensitive
DENIED_HOSTS: frozenset[str] = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata", "metadata.google.internal", "metadata.goog",
    "instance-data", "instance-data.ec2.internal",
})

#: header names this layer must never attach on its own
FORBIDDEN_REQUEST_HEADERS: frozenset[str] = frozenset({
    "authorization", "cookie", "proxy-authorization", "x-api-key",
    "x-auth-token", "set-cookie",
})


@dataclass(frozen=True)
class IsolationPolicy:
    """The isolation contract of a would-be browser context (§10)."""

    non_persistent_context: bool = True
    user_profile: bool = False
    stored_cookies: bool = False
    credentials: bool = False
    extensions: bool = False
    host_filesystem: bool = False
    downloads: bool = False
    outbound_credentials: bool = False
    max_pages: int = ce.CEILINGS["browser_pages"]
    max_contexts: int = ce.CEILINGS["browser_contexts"]
    max_redirects: int = ce.CEILINGS["redirect_hops"]
    max_requests: int = ce.CEILINGS["requests_per_execution"]
    wall_seconds: int = ce.CEILINGS["browser_wall_seconds"]
    dom_observation_bytes: int = ce.CEILINGS["browser_dom_observation_bytes"]
    popup_events: int = ce.CEILINGS["browser_popup_events"]
    storage_keys: int = ce.CEILINGS["browser_storage_keys"]
    rule_version: str = ISOLATION_VERSION

    @property
    def isolated(self) -> bool:
        """True only when every isolation requirement holds."""
        return not any((
            self.user_profile, self.stored_cookies, self.credentials,
            self.extensions, self.host_filesystem, self.downloads,
            self.outbound_credentials))

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "non_persistent_context": self.non_persistent_context,
            "user_profile": self.user_profile,
            "stored_cookies": self.stored_cookies,
            "credentials": self.credentials,
            "extensions": self.extensions,
            "host_filesystem": self.host_filesystem,
            "downloads": self.downloads,
            "outbound_credentials": self.outbound_credentials,
            "max_pages": self.max_pages,
            "max_contexts": self.max_contexts,
            "max_redirects": self.max_redirects,
            "max_requests": self.max_requests,
            "wall_seconds": self.wall_seconds,
            "dom_observation_bytes": self.dom_observation_bytes,
            "popup_events": self.popup_events,
            "storage_keys": self.storage_keys,
            "isolated": self.isolated,
            "rule_version": self.rule_version,
        }
        return payload


def isolation_policy() -> IsolationPolicy:
    return IsolationPolicy()


@dataclass(frozen=True)
class NavigationDecision:
    """The deterministic verdict for one navigation or redirect hop."""

    allowed: bool
    decision: str
    reason: str = ""
    host: str = ""
    scheme: str = ""
    port: int = 0
    address_class: str = ""
    redirect: bool = False
    rule_version: str = ISOLATION_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "decision": self.decision,
            "reason": self.reason,
            "host": self.host,
            "scheme": self.scheme,
            "port": self.port,
            "address_class": self.address_class,
            "redirect": self.redirect,
            "rule_version": self.rule_version,
        }


def _address_class(host: str) -> str:
    """Classify a literal address (no resolution happens here)."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return ""
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved or address.is_unspecified:
        return "reserved"
    if address.version == 6:
        return "global_v6"
    return "global"


def _normalized_hosts(hosts: Iterable[str]) -> set[str]:
    return {str(h or "").strip().lower().lstrip(".")
            for h in hosts if str(h or "").strip()}


def check_navigation(url: str, *, scope_ref: str = "",
                     authorized_hosts: Iterable[str] = (),
                     allowed_ports: Iterable[int] = ALLOWED_PORTS,
                     redirect: bool = False) -> NavigationDecision:
    """Decide whether one navigation/redirect hop may proceed (§11)."""
    text = str(url or "").strip()
    if not text:
        return NavigationDecision(
            allowed=False, decision=NAVIGATION_BLOCKED,
            reason="empty_destination", redirect=redirect)
    parts = urlsplit(text)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    if scheme not in ALLOWED_SCHEMES:
        return NavigationDecision(
            allowed=False, decision=SCHEME_BLOCKED,
            reason=f"scheme_not_allowed:{scheme or 'none'}", host=host,
            scheme=scheme, port=port, redirect=redirect)
    if not host:
        return NavigationDecision(
            allowed=False, decision=NAVIGATION_BLOCKED,
            reason="missing_host", scheme=scheme, port=port,
            redirect=redirect)
    if host in DENIED_HOSTS:
        return NavigationDecision(
            allowed=False, decision=DESTINATION_BLOCKED,
            reason=f"denied_host:{host}", host=host, scheme=scheme,
            port=port, address_class="loopback", redirect=redirect)
    klass = _address_class(host)
    if klass and klass != "global" and klass != "global_v6":
        return NavigationDecision(
            allowed=False, decision=DESTINATION_BLOCKED,
            reason=f"denied_address_class:{klass}", host=host, scheme=scheme,
            port=port, address_class=klass, redirect=redirect)
    if int(port) not in {int(p) for p in allowed_ports}:
        return NavigationDecision(
            allowed=False, decision=PORT_BLOCKED,
            reason=f"port_not_allowed:{port}", host=host, scheme=scheme,
            port=port, address_class=klass, redirect=redirect)
    hosts = _normalized_hosts(authorized_hosts)
    if not hosts:
        return NavigationDecision(
            allowed=False, decision=DESTINATION_BLOCKED,
            reason="no_authorized_host_set", host=host, scheme=scheme,
            port=port, address_class=klass, redirect=redirect)
    if host not in hosts:
        return NavigationDecision(
            allowed=False,
            decision=REDIRECT_OUT_OF_SCOPE if redirect else DESTINATION_BLOCKED,
            reason=f"host_out_of_scope:{host}", host=host, scheme=scheme,
            port=port, address_class=klass, redirect=redirect)
    return NavigationDecision(
        allowed=True, decision=NAVIGATION_ALLOWED, reason="in_scope",
        host=host, scheme=scheme, port=port, address_class=klass or "name",
        redirect=redirect)


def check_redirect(from_url: str, location: str, *, scope_ref: str = "",
                   authorized_hosts: Iterable[str] = (),
                   allowed_ports: Iterable[int] = ALLOWED_PORTS
                   ) -> NavigationDecision:
    """A redirect hop: leaving the authorized host set stops the attempt."""
    decision = check_navigation(location, scope_ref=scope_ref,
                               authorized_hosts=authorized_hosts,
                               allowed_ports=allowed_ports, redirect=True)
    if decision.allowed:
        return decision
    if decision.decision == DESTINATION_BLOCKED:
        return NavigationDecision(
            allowed=False, decision=REDIRECT_OUT_OF_SCOPE,
            reason=decision.reason, host=decision.host,
            scheme=decision.scheme, port=decision.port,
            address_class=decision.address_class, redirect=True)
    return decision


def check_request_headers(headers: dict[str, Any] | None) -> NavigationDecision:
    """§12: this layer never attaches credentials of its own."""
    for name in (headers or {}):
        if str(name or "").strip().lower() in FORBIDDEN_REQUEST_HEADERS:
            return NavigationDecision(
                allowed=False, decision=CREDENTIAL_BLOCKED,
                reason=f"forbidden_header:{str(name).lower()}")
    return NavigationDecision(allowed=True, decision=NAVIGATION_ALLOWED,
                              reason="no_credential_headers")
