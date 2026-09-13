"""SSRF evidence plan schema (Stage R40.4).

An :class:`SSRFEvidencePlan` defines which research evidence would be required
to evaluate the SSRF hypotheses. It answers the research question:

    "Which bounded evidence categories would this research require?"

Hard boundaries encoded here:

- Evidence planning only: no evidence collection, no HTTP/network request,
  no DNS resolution, no localhost/private-IP connection, no port scan, no
  URL probing, no payload execution, no metadata access, no persistence.
- Closed vocabularies: evidence categories, evidence state and limitations
  are closed sets; confidence reuses the shared evidence-confidence
  vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no DNS, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

SSRF_EVIDENCE_PLAN_RULE_VERSION = "r40-4"
RULE_VERSION = SSRF_EVIDENCE_PLAN_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

EVIDENCE_SERVER_FETCH_BEHAVIOR = "SERVER_FETCH_BEHAVIOR"
EVIDENCE_URL_PARSING_CONTEXT = "URL_PARSING_CONTEXT"
EVIDENCE_HOST_VALIDATION = "HOST_VALIDATION"
EVIDENCE_IP_RANGE_VALIDATION = "IP_RANGE_VALIDATION"
EVIDENCE_REDIRECT_POLICY = "REDIRECT_POLICY"
EVIDENCE_PROTOCOL_RESTRICTION = "PROTOCOL_RESTRICTION"
EVIDENCE_DNS_RESOLUTION_BEHAVIOR = "DNS_RESOLUTION_BEHAVIOR"
EVIDENCE_DESTINATION_RESTRICTION = "DESTINATION_RESTRICTION"
EVIDENCE_APPLICATION_BEHAVIOR = "APPLICATION_BEHAVIOR"
EVIDENCE_CLOUD_BOUNDARY_CONTEXT = "CLOUD_BOUNDARY_CONTEXT"
EVIDENCE_UNKNOWN = "UNKNOWN"

SSRF_EVIDENCE_ITEMS: tuple[str, ...] = (
    EVIDENCE_SERVER_FETCH_BEHAVIOR,
    EVIDENCE_URL_PARSING_CONTEXT,
    EVIDENCE_HOST_VALIDATION,
    EVIDENCE_IP_RANGE_VALIDATION,
    EVIDENCE_REDIRECT_POLICY,
    EVIDENCE_PROTOCOL_RESTRICTION,
    EVIDENCE_DNS_RESOLUTION_BEHAVIOR,
    EVIDENCE_DESTINATION_RESTRICTION,
    EVIDENCE_APPLICATION_BEHAVIOR,
    EVIDENCE_CLOUD_BOUNDARY_CONTEXT,
    EVIDENCE_UNKNOWN,
)

STATE_COMPLETE = "COMPLETE"
STATE_PARTIAL = "PARTIAL"
STATE_UNKNOWN = "UNKNOWN"

EVIDENCE_STATES: tuple[str, ...] = (
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
)

LIMITATION_NO_COLLECTION_PERFORMED = "NO_COLLECTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_DNS_RESOLUTION = "NO_DNS_RESOLUTION"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

SSRF_EVIDENCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_DNS_RESOLUTION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_EVIDENCE_ITEMS = 11
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


def sanitize_ssrf_evidence_plan(value: object) -> dict:
    """Project an R40.4 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "evidence_items": [],
            "evidence_state": STATE_UNKNOWN,
            "confidence": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    evidence_state = _safe_text(value.get("evidence_state")).strip().upper()
    if evidence_state not in EVIDENCE_STATES:
        evidence_state = STATE_UNKNOWN
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "evidence_items": [
            item
            for item in (
                _safe_text(entry)
                for entry in value.get("evidence_items") or ()
            )
            if item in SSRF_EVIDENCE_ITEMS
        ][:MAX_EVIDENCE_ITEMS],
        "evidence_state": evidence_state,
        "confidence": confidence,
        "limitations": [
            code
            for code in (
                _safe_text(entry)
                for entry in value.get("limitations") or ()
            )
            if code in SSRF_EVIDENCE_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SSRFEvidencePlan(BaseModel):
    """Deterministic research-only SSRF evidence plan (R40.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SSRF_EVIDENCE_PLAN_RULE_VERSION
    evidence_items: list[str] = Field(default_factory=list)
    evidence_state: str = STATE_UNKNOWN
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SSRF_EVIDENCE_PLAN_RULE_VERSION

    @field_validator("evidence_items")
    @classmethod
    def _valid_items(cls, value: list) -> list[str]:
        return _require_codes(value, SSRF_EVIDENCE_ITEMS, MAX_EVIDENCE_ITEMS)

    @field_validator("evidence_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_STATES:
            raise ValueError(f"invalid evidence_state: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, SSRF_EVIDENCE_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("ssrf evidence plans are research-only")
        return True


def ssrf_evidence_plan_projection(value: SSRFEvidencePlan) -> dict:
    """Serialize an SSRF evidence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SSRF_EVIDENCE_PLAN_RULE_VERSION",
    "RULE_VERSION",
    "EVIDENCE_SERVER_FETCH_BEHAVIOR",
    "EVIDENCE_URL_PARSING_CONTEXT",
    "EVIDENCE_HOST_VALIDATION",
    "EVIDENCE_IP_RANGE_VALIDATION",
    "EVIDENCE_REDIRECT_POLICY",
    "EVIDENCE_PROTOCOL_RESTRICTION",
    "EVIDENCE_DNS_RESOLUTION_BEHAVIOR",
    "EVIDENCE_DESTINATION_RESTRICTION",
    "EVIDENCE_APPLICATION_BEHAVIOR",
    "EVIDENCE_CLOUD_BOUNDARY_CONTEXT",
    "EVIDENCE_UNKNOWN",
    "SSRF_EVIDENCE_ITEMS",
    "STATE_COMPLETE",
    "STATE_PARTIAL",
    "STATE_UNKNOWN",
    "EVIDENCE_STATES",
    "LIMITATION_NO_COLLECTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_DNS_RESOLUTION",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "SSRF_EVIDENCE_LIMITATIONS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_ssrf_evidence_plan",
    "SSRFEvidencePlan",
    "ssrf_evidence_plan_projection",
]
