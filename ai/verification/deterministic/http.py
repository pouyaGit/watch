"""Sealed HTTP verification proof (Phase 5I, pure over HttpObservation).

NEVER performs another request. Positive evidence requires ALL
deterministic conditions (ported from the frozen World A
``_http_path_confirms`` semantics, adapted to sealed bytes):

- transport outcome ``responded`` with a 2xx-class sealed status;
- exact marker equality against a LOCALLY DERIVED expectation (the
  oracle seed recomputed from the sealed execution binding — the
  advisory ``matched``-shaped booleans are never consulted; a probe
  with no derivable marker can never be positive);
- meaningful reflection location (attribute / JS-string / script
  block / URL). Plain HTML-body reflection is explicitly weaker and
  does NOT count; the location is derived structurally from the
  sealed response sample, never from a caller label;
- artifact/request binding (method pair vs the authorized issuance);
- target binding (sealed request origin equals the canonical target);
- redirect safety (every sealed hop same-origin, no downgrade, no
  overflow, chain not truncated);
- no truncation ambiguity (no omitted sample, no truncated chain);
- no WAF/generic-error confounder (403/406 or generic-error body
  markers defeat the positive path).

HTTP reflection alone is POTENTIAL-ceiling evidence: it proves
reflection, never execution, and can NEVER produce CONFIRMED.
Transport success alone, generic errors, and reflection alone are
each insufficient. Truncated evidence is never guessed through.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai.schemas import evidence as ev

from ai.verification.deterministic.xss_oracle import (
    OracleIdentity,
    derive_oracle_identity,
)

__all__ = [
    "MEANINGFUL_REFLECTION_LOCATIONS",
    "HttpProof",
    "verify_http_observation",
    "classify_reflection_location",
]

MEANINGFUL_REFLECTION_LOCATIONS = frozenset(
    {"HTML_ATTRIBUTE", "JAVASCRIPT_STRING", "SCRIPT_BLOCK", "URL"}
)

_WAF_STATUSES = frozenset({403, 406})

_GENERIC_ERROR_MARKERS = (
    "not found",
    "internal server error",
    "bad gateway",
    "service unavailable",
    "gateway timeout",
    "forbidden",
    "unauthorized",
)

_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_ATTR_RE = re.compile(
    r"<[a-z][a-z0-9:-]*\b[^<>]*?=([\"'])(.*?)\1", re.IGNORECASE | re.DOTALL
)
_URL_ATTR_RE = re.compile(
    r"(?:href|src|action|data|ping|formaction)\s*=\s*([\"'])(.*?)\1",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class HttpProof:
    """Deterministic HTTP-path classification inputs."""

    positive: bool
    location: str | None
    reason: str


def classify_reflection_location(sample: str, marker: str) -> str:
    """Conservative structural reflection-location classification.

    Deterministic over the sealed sample only. Anything the classifier
    cannot prove meaningful is reported as ``HTML_BODY`` (insufficient
    for the positive path) — the verifier never upgrades ambiguity.
    """
    if not marker or marker not in sample:
        return "ABSENT"
    for block in _SCRIPT_BLOCK_RE.findall(sample):
        if marker in block:
            # Inside a script block: a JS string literal or raw code.
            for quote in ('"', "'"):
                if f"{quote}{marker}{quote}" in block:
                    return "JAVASCRIPT_STRING"
            return "SCRIPT_BLOCK"
    for match in _URL_ATTR_RE.finditer(sample):
        if marker in match.group(2):
            return "URL"
    for match in _ATTR_RE.finditer(sample):
        if marker in match.group(2):
            return "HTML_ATTRIBUTE"
    return "HTML_BODY"


def _origin_of(url: str) -> tuple[str, str, str] | None:
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url or "")
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in ("http", "https") or not host:
        return None
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme.lower(), host, str(port)


def verify_http_observation(
    record: ev.EvidenceRecord,
    *,
    authorization: object | None,
    identity: OracleIdentity | None,
) -> HttpProof:
    """Run the ordered HTTP positive-path gates over sealed bytes.

    Returns a positive proof only when every condition holds. Any
    single failure yields a non-positive result with a closed reason;
    the caller maps non-positive to UNKNOWN (never NOT_VULNERABLE).
    """
    http = record.http
    if http is None:
        return HttpProof(False, None, "http_observation_missing")
    if http.transport_outcome != "responded":
        return HttpProof(False, None, "transport_failure")
    status = http.response_status
    if status is None:
        return HttpProof(False, None, "response_status_missing")
    if status in _WAF_STATUSES:
        return HttpProof(False, None, "waf_confounder")
    if not 200 <= status < 300:
        return HttpProof(False, None, f"status_not_success_{status}")
    if http.sample_omitted:
        return HttpProof(False, None, "sample_truncated")
    if http.chain_truncated:
        return HttpProof(False, None, "chain_truncated")
    if len(http.redirect_chain) > 5:
        return HttpProof(False, None, "chain_over_cap")

    # Artifact/request binding: sealed method must equal the
    # authorized method pair (no lenient matching).
    if authorization is not None:
        plan_method = getattr(authorization, "plan_method", None)
        artifact_method = getattr(authorization, "artifact_method", None)
        if plan_method is not None and http.method != plan_method:
            return HttpProof(False, None, "request_method_mismatch")
        if (
            artifact_method is not None
            and plan_method is not None
            and artifact_method != plan_method
        ):
            return HttpProof(False, None, "authorized_method_pair_mismatch")

    # Target binding: sealed request origin equals the canonical target.
    target = record.target
    endpoint_origin = (target.scheme, target.host, str(target.effective_port))
    request_origin = _origin_of(http.request_url.redacted_url)
    if request_origin is None or request_origin != endpoint_origin:
        return HttpProof(False, None, "target_mismatch")
    for hop in http.redirect_chain:
        hop_origin = _origin_of(hop.redacted_url)
        if hop_origin is None:
            return HttpProof(False, None, "redirect_unparseable")
        if hop_origin != endpoint_origin:
            return HttpProof(False, None, "redirect_boundary_violation")
        if endpoint_origin[0] == "https" and hop_origin[0] != "https":
            return HttpProof(False, None, "redirect_downgrade")

    # Exact marker equality against a locally derived expectation.
    if identity is None:
        return HttpProof(False, None, "no_locally_derived_marker")
    sample = http.response_body_sample or ""
    lowered = sample.casefold()
    for marker in _GENERIC_ERROR_MARKERS:
        if marker in lowered and identity.seed not in sample:
            return HttpProof(False, None, "generic_error_confounder")
    if identity.seed not in sample:
        return HttpProof(False, None, "marker_not_reflected")

    location = classify_reflection_location(sample, identity.seed)
    if location not in MEANINGFUL_REFLECTION_LOCATIONS:
        return HttpProof(False, location, "reflection_location_insufficient")
    return HttpProof(True, location, "meaningful_http_reflection")
