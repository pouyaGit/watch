"""SSRF hypothesis schema (Stage R40.3).

An :class:`SSRFHypothesisPlan` is a deterministic research hypothesis about
possible SSRF-relevant behavior. It answers the research question:

    "Which SSRF review hypothesis follows from the observed context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability confirmation,
  no executable payload, no concrete exploitation instructions, no network
  request, no DNS resolution, no metadata access, no redirect following.
- Closed vocabularies: hypothesis type, supporting signals, confidence,
  priority and limitations are closed sets.
- Confidence and priority reuse the shared evidence-confidence vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no DNS, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

SSRF_HYPOTHESIS_RULE_VERSION = "r40-3"
RULE_VERSION = SSRF_HYPOTHESIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

TYPE_SERVER_SIDE_FETCH_ANALYSIS = "SERVER_SIDE_FETCH_ANALYSIS"
TYPE_URL_VALIDATION_REVIEW = "URL_VALIDATION_REVIEW"
TYPE_IP_VALIDATION_REVIEW = "IP_VALIDATION_REVIEW"
TYPE_REDIRECT_HANDLING_REVIEW = "REDIRECT_HANDLING_REVIEW"
TYPE_PROTOCOL_HANDLING_REVIEW = "PROTOCOL_HANDLING_REVIEW"
TYPE_DNS_REBINDING_REVIEW = "DNS_REBINDING_REVIEW"
TYPE_INTERNAL_ADDRESS_RESTRICTION_REVIEW = (
    "INTERNAL_ADDRESS_RESTRICTION_REVIEW"
)
TYPE_CLOUD_METADATA_BOUNDARY_REVIEW = "CLOUD_METADATA_BOUNDARY_REVIEW"
TYPE_WEBHOOK_FETCH_REVIEW = "WEBHOOK_FETCH_REVIEW"
TYPE_UNKNOWN = "UNKNOWN"

HYPOTHESIS_TYPES: tuple[str, ...] = (
    TYPE_SERVER_SIDE_FETCH_ANALYSIS,
    TYPE_URL_VALIDATION_REVIEW,
    TYPE_IP_VALIDATION_REVIEW,
    TYPE_REDIRECT_HANDLING_REVIEW,
    TYPE_PROTOCOL_HANDLING_REVIEW,
    TYPE_DNS_REBINDING_REVIEW,
    TYPE_INTERNAL_ADDRESS_RESTRICTION_REVIEW,
    TYPE_CLOUD_METADATA_BOUNDARY_REVIEW,
    TYPE_WEBHOOK_FETCH_REVIEW,
    TYPE_UNKNOWN,
)

SIGNAL_URL_HANDLING_OBSERVED = "URL_HANDLING_OBSERVED"
SIGNAL_URL_HANDLING_UNKNOWN = "URL_HANDLING_UNKNOWN"
SIGNAL_REDIRECT_TARGET = "REDIRECT_TARGET_OBSERVED"
SIGNAL_WEBHOOK_TARGET = "WEBHOOK_TARGET_OBSERVED"
SIGNAL_SERVER_FETCH_OBSERVED = "SERVER_FETCH_OBSERVED"
SIGNAL_SERVER_FETCH_NOT_OBSERVED = "SERVER_FETCH_NOT_OBSERVED"
SIGNAL_SERVER_FETCH_UNKNOWN = "SERVER_FETCH_UNKNOWN"
SIGNAL_PROTOCOL_HTTP = "PROTOCOL_HTTP"
SIGNAL_PROTOCOL_NON_HTTP = "PROTOCOL_NON_HTTP"
SIGNAL_PROTOCOL_UNKNOWN = "PROTOCOL_UNKNOWN"
SIGNAL_REDIRECT_FOLLOWED = "REDIRECT_FOLLOWED"
SIGNAL_REDIRECT_NOT_FOLLOWED = "REDIRECT_NOT_FOLLOWED"
SIGNAL_REDIRECT_UNKNOWN = "REDIRECT_UNKNOWN"
SIGNAL_HOSTNAME_VALIDATION_PRESENT = "HOSTNAME_VALIDATION_PRESENT"
SIGNAL_HOSTNAME_VALIDATION_ABSENT = "HOSTNAME_VALIDATION_ABSENT"
SIGNAL_IP_VALIDATION_PRESENT = "IP_VALIDATION_PRESENT"
SIGNAL_IP_VALIDATION_ABSENT = "IP_VALIDATION_ABSENT"
SIGNAL_ALLOWLIST_PRESENT = "ALLOWLIST_PRESENT"
SIGNAL_ALLOWLIST_ABSENT = "ALLOWLIST_ABSENT"
SIGNAL_ENCODING_NORMALIZED = "ENCODING_NORMALIZED"
SIGNAL_ENCODING_ENCODED = "ENCODING_ENCODED"
SIGNAL_ENCODING_PARTIAL = "ENCODING_PARTIAL"
SIGNAL_INPUT_QUERY = "INPUT_QUERY"
SIGNAL_INPUT_BODY = "INPUT_BODY"
SIGNAL_INPUT_HEADER = "INPUT_HEADER"
SIGNAL_INPUT_COOKIE = "INPUT_COOKIE"
SIGNAL_INPUT_PATH = "INPUT_PATH"
SIGNAL_CONTEXT_UNKNOWN = "CONTEXT_UNKNOWN"

SSRF_SIGNALS: tuple[str, ...] = (
    SIGNAL_URL_HANDLING_OBSERVED,
    SIGNAL_URL_HANDLING_UNKNOWN,
    SIGNAL_REDIRECT_TARGET,
    SIGNAL_WEBHOOK_TARGET,
    SIGNAL_SERVER_FETCH_OBSERVED,
    SIGNAL_SERVER_FETCH_NOT_OBSERVED,
    SIGNAL_SERVER_FETCH_UNKNOWN,
    SIGNAL_PROTOCOL_HTTP,
    SIGNAL_PROTOCOL_NON_HTTP,
    SIGNAL_PROTOCOL_UNKNOWN,
    SIGNAL_REDIRECT_FOLLOWED,
    SIGNAL_REDIRECT_NOT_FOLLOWED,
    SIGNAL_REDIRECT_UNKNOWN,
    SIGNAL_HOSTNAME_VALIDATION_PRESENT,
    SIGNAL_HOSTNAME_VALIDATION_ABSENT,
    SIGNAL_IP_VALIDATION_PRESENT,
    SIGNAL_IP_VALIDATION_ABSENT,
    SIGNAL_ALLOWLIST_PRESENT,
    SIGNAL_ALLOWLIST_ABSENT,
    SIGNAL_ENCODING_NORMALIZED,
    SIGNAL_ENCODING_ENCODED,
    SIGNAL_ENCODING_PARTIAL,
    SIGNAL_INPUT_QUERY,
    SIGNAL_INPUT_BODY,
    SIGNAL_INPUT_HEADER,
    SIGNAL_INPUT_COOKIE,
    SIGNAL_INPUT_PATH,
    SIGNAL_CONTEXT_UNKNOWN,
)

LIMITATION_NO_EXPLOIT_CLAIM = "NO_EXPLOIT_CLAIM"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

SSRF_HYPOTHESIS_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_SIGNALS = 8
MAX_LIMITATIONS = 5
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _require_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in allowed:
            raise ValueError(f"invalid closed code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_ssrf_hypothesis_plan(value: object) -> dict:
    """Project an R40.3 hypothesis onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "hypothesis_type": TYPE_UNKNOWN,
            "supporting_signals": [],
            "confidence": "UNKNOWN",
            "priority": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    hypothesis_type = _safe_text(
        value.get("hypothesis_type")
    ).strip().upper()
    if hypothesis_type not in HYPOTHESIS_TYPES:
        hypothesis_type = TYPE_UNKNOWN
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    priority = _safe_text(value.get("priority")).strip().upper()
    if priority not in CONFIDENCE_LEVELS:
        priority = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "hypothesis_type": hypothesis_type,
        "supporting_signals": [
            signal
            for signal in (
                _safe_text(item) for item in value.get("supporting_signals")
                or ()
            )
            if signal in SSRF_SIGNALS
        ][:MAX_SIGNALS],
        "confidence": confidence,
        "priority": priority,
        "limitations": [
            code
            for code in (
                _safe_text(item) for item in value.get("limitations") or ()
            )
            if code in SSRF_HYPOTHESIS_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SSRFHypothesisPlan(BaseModel):
    """Deterministic research-only SSRF hypothesis (R40.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SSRF_HYPOTHESIS_RULE_VERSION
    hypothesis_type: str
    supporting_signals: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    priority: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SSRF_HYPOTHESIS_RULE_VERSION

    @field_validator("hypothesis_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HYPOTHESIS_TYPES:
            raise ValueError(f"invalid hypothesis_type: {value!r}")
        return text

    @field_validator("supporting_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _require_codes(value, SSRF_SIGNALS, MAX_SIGNALS)

    @field_validator("confidence", "priority")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence/priority: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, SSRF_HYPOTHESIS_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("ssrf hypotheses are research-only")
        return True


def ssrf_hypothesis_plan_projection(value: SSRFHypothesisPlan) -> dict:
    """Serialize an SSRF hypothesis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SSRF_HYPOTHESIS_RULE_VERSION",
    "RULE_VERSION",
    "TYPE_SERVER_SIDE_FETCH_ANALYSIS",
    "TYPE_URL_VALIDATION_REVIEW",
    "TYPE_IP_VALIDATION_REVIEW",
    "TYPE_REDIRECT_HANDLING_REVIEW",
    "TYPE_PROTOCOL_HANDLING_REVIEW",
    "TYPE_DNS_REBINDING_REVIEW",
    "TYPE_INTERNAL_ADDRESS_RESTRICTION_REVIEW",
    "TYPE_CLOUD_METADATA_BOUNDARY_REVIEW",
    "TYPE_WEBHOOK_FETCH_REVIEW",
    "TYPE_UNKNOWN",
    "HYPOTHESIS_TYPES",
    "SIGNAL_URL_HANDLING_OBSERVED",
    "SIGNAL_URL_HANDLING_UNKNOWN",
    "SIGNAL_REDIRECT_TARGET",
    "SIGNAL_WEBHOOK_TARGET",
    "SIGNAL_SERVER_FETCH_OBSERVED",
    "SIGNAL_SERVER_FETCH_NOT_OBSERVED",
    "SIGNAL_SERVER_FETCH_UNKNOWN",
    "SIGNAL_PROTOCOL_HTTP",
    "SIGNAL_PROTOCOL_NON_HTTP",
    "SIGNAL_PROTOCOL_UNKNOWN",
    "SIGNAL_REDIRECT_FOLLOWED",
    "SIGNAL_REDIRECT_NOT_FOLLOWED",
    "SIGNAL_REDIRECT_UNKNOWN",
    "SIGNAL_HOSTNAME_VALIDATION_PRESENT",
    "SIGNAL_HOSTNAME_VALIDATION_ABSENT",
    "SIGNAL_IP_VALIDATION_PRESENT",
    "SIGNAL_IP_VALIDATION_ABSENT",
    "SIGNAL_ALLOWLIST_PRESENT",
    "SIGNAL_ALLOWLIST_ABSENT",
    "SIGNAL_ENCODING_NORMALIZED",
    "SIGNAL_ENCODING_ENCODED",
    "SIGNAL_ENCODING_PARTIAL",
    "SIGNAL_INPUT_QUERY",
    "SIGNAL_INPUT_BODY",
    "SIGNAL_INPUT_HEADER",
    "SIGNAL_INPUT_COOKIE",
    "SIGNAL_INPUT_PATH",
    "SIGNAL_CONTEXT_UNKNOWN",
    "SSRF_SIGNALS",
    "LIMITATION_NO_EXPLOIT_CLAIM",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_HYPOTHESIS_ONLY",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "SSRF_HYPOTHESIS_LIMITATIONS",
    "MAX_SIGNALS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_ssrf_hypothesis_plan",
    "SSRFHypothesisPlan",
    "ssrf_hypothesis_plan_projection",
]
