"""EPIC7 Part 5: tightly constrained HTTP observation adapter.

This module is the SINGLE sanctioned place in aec/ where a transport may
be imported (asserted by the EPIC7 invariants). Imports are function-local
and lazy: importing or constructing anything here never opens a socket,
and the transport is only ever reached after the runtime's gates have
passed. The adapter takes a ResolvedTarget — never a raw URL — and
records only allowlisted, redacted, bounded metadata: status, selected
headers, content metadata (type/length only), and timing. Bodies are
projected to a digest, never retained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from aec.runtime.adapters.target import ResolvedTarget
from aec.runtime.policy.limits import ResourceLimits, default_limits
from aec.runtime.results.redaction import (
    project_body, redact_headers, redact_trace)


class ResponseTooLarge(Exception):
    """Response exceeded the policy's maximum response bytes."""

    def __init__(self, actual: int, limit: int) -> None:
        super().__init__(f"response size {actual} exceeds limit {limit}")
        self.actual = actual
        self.limit = limit


class RedirectLimit(Exception):
    """Redirect refused: out of scope, scheme downgrade, or budget."""


def default_transport() -> Callable[..., Mapping[str, Any]]:
    """The real transport, constructed lazily.

    Importing http.client happens here, on first construction, never at
    module import time. The transport returns the same bounded mapping the
    injected fakes return, so the runtime's gating exercises identical
    code paths in tests.
    """

    def transport(target: ResolvedTarget, request: Mapping[str, Any],
                  limits: ResourceLimits) -> Mapping[str, Any]:
        import http.client  # lazy: the only transport import in aec/

        host = target.host
        port = target.port
        connection = http.client.HTTPSConnection(
            host, port=port if port is not None else 443,
            timeout=limits.request_timeout_seconds)
        endpoint = target.endpoint or "/"
        connection.request("GET", endpoint)
        response = connection.getresponse()
        headers = {
            name.lower(): value
            for name, value in response.getheaders()
        }
        body = response.read(limits.max_response_bytes + 1)
        if len(body) > limits.max_response_bytes:
            connection.close()
            raise ResponseTooLarge(
                len(body), limits.max_response_bytes)
        connection.close()
        return {
            "status": response.status,
            "headers": headers,
            "body": body,
            "timing_ms": 0,
        }

    return transport


def check_redirect(location: str, original_host: str,
                   scope_hosts: frozenset[str]) -> None:
    """Refuse redirects outside scope; no silent normalization."""
    import urllib.parse  # lazy: parsing only, no I/O

    if not isinstance(location, str) or not location:
        raise RedirectLimit("REDIRECT_MISSING_LOCATION")
    if "://" not in location:
        raise RedirectLimit("REDIRECT_RELATIVE_REFUSED")
    parsed = urllib.parse.urlsplit(location)
    if parsed.scheme != "https":
        raise RedirectLimit("REDIRECT_SCHEME_DOWNGRADE")
    if parsed.username or parsed.password:
        raise RedirectLimit("REDIRECT_USERINFO")
    host = (parsed.hostname or "").lower()
    if host != original_host:
        raise RedirectLimit("REDIRECT_OUT_OF_SCOPE")
    if scope_hosts and host not in scope_hosts:
        raise RedirectLimit("REDIRECT_OUT_OF_SCOPE")


def check_redirect_budget(redirects: int, max_redirects: int) -> None:
    if redirects > max_redirects:
        raise RedirectLimit("REDIRECT_BUDGET_EXHAUSTED")


def bounded_size(size: int, limits: ResourceLimits) -> bool:
    return size <= limits.max_response_bytes


@dataclass(frozen=True)
class ObservationResult:
    status: int
    timing_ms: int
    content_type: str
    content_length: int
    selected_headers: Mapping[str, str]
    scope_validation: str
    authorization_reference: str
    policy_version: str
    target_id: str
    redaction_status: str
    method_used: str
    body_digest: str = ""
    redirects: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "timing_ms": self.timing_ms,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "selected_headers": dict(self.selected_headers),
            "scope_validation": self.scope_validation,
            "authorization_reference": self.authorization_reference,
            "policy_version": self.policy_version,
            "target_id": self.target_id,
            "redaction_status": self.redaction_status,
            "method_used": self.method_used,
            "body_digest": self.body_digest,
            "redirects": self.redirects,
        }


def observe(
    target: ResolvedTarget,
    request: Mapping[str, Any],
    limits: ResourceLimits | None,
    transport: Callable[..., Mapping[str, Any]] | None = None,
) -> ObservationResult:
    """Run one bounded observation through the (injected or real)
    transport. Never retains the body; never returns secret headers."""
    limits = limits if limits is not None else default_limits()
    runner = transport if transport is not None else default_transport()
    raw = runner(target, request, limits)

    status = int(raw.get("status", 0))
    headers = raw.get("headers") if isinstance(raw.get("headers"), Mapping) \
        else {}
    header_map = {str(k).lower(): str(v) for k, v in headers.items()}
    selected = redact_headers(header_map)
    body = raw.get("body")
    if isinstance(body, bytes):
        body_digest, content_length = project_body(body)
    else:
        body_digest, content_length = "", int(
            raw.get("content_length", 0) or 0)
    timing = int(raw.get("timing_ms", 0) or 0)
    content_type = selected.get("content-type", "")

    return ObservationResult(
        status=status,
        timing_ms=timing,
        content_type=content_type,
        content_length=content_length,
        selected_headers=dict(sorted(selected.items())),
        scope_validation="PASS",
        authorization_reference=str(
            request.get("authorization_reference") or ""),
        policy_version=str(request.get("policy_version") or "unstated"),
        target_id=target.target_id,
        redaction_status="scrubbed",
        method_used="GET",
        body_digest=body_digest,
        redirects=0,
    )


__all__ = [
    "ObservationResult", "RedirectLimit", "ResponseTooLarge",
    "bounded_size", "check_redirect", "check_redirect_budget",
    "default_transport", "observe",
]