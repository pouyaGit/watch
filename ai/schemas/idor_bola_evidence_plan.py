"""IDOR/BOLA evidence plan schema (Stage R46.4).

An :class:`IDORBOLAEvidencePlan` defines which research evidence would be
required to evaluate the IDOR/BOLA hypotheses. It answers the research
question:

    "Which bounded authorization evidence categories would this research
     require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP request, no DNS resolution,
  no socket, no browser, no database, no scanner, no payload, no
  authorization bypass, no execution, no persistence. Nothing is queried,
  sent, bypassed or executed.
- Evidence items describe what would be relevant; they are never collected
  here and never instruct an attack.
- Closed vocabularies: evidence items, evidence state and limitations are
  closed sets; confidence reuses the shared evidence-confidence vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

IDOR_BOLA_EVIDENCE_PLAN_RULE_VERSION = "r46-4"
RULE_VERSION = IDOR_BOLA_EVIDENCE_PLAN_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed evidence vocabulary
# ---------------------------------------------------------------------------

EVIDENCE_AUTHORIZATION_CONTROL = "AUTHORIZATION_CONTROL_EVIDENCE"
EVIDENCE_OWNERSHIP_RELATIONSHIP = "OWNERSHIP_RELATIONSHIP_EVIDENCE"
EVIDENCE_TENANT_BOUNDARY = "TENANT_BOUNDARY_EVIDENCE"
EVIDENCE_ROLE_DEFINITION = "ROLE_DEFINITION_EVIDENCE"
EVIDENCE_OBJECT_IDENTIFIER_CONTEXT = "OBJECT_IDENTIFIER_CONTEXT"
EVIDENCE_OBJECT_LOOKUP_CONTEXT = "OBJECT_LOOKUP_CONTEXT"
EVIDENCE_ROUTE_CONTROLLER_CONTEXT = "ROUTE_CONTROLLER_CONTEXT"
EVIDENCE_SERVER_SIDE_AUTHORIZATION = "SERVER_SIDE_AUTHORIZATION_EVIDENCE"
EVIDENCE_ACCESS_CONTROL_POLICY = "ACCESS_CONTROL_POLICY_EVIDENCE"
EVIDENCE_OBSERVED_AUTHORIZATION_BEHAVIOR = (
    "OBSERVED_AUTHORIZATION_BEHAVIOR"
)
EVIDENCE_CROSS_CONTEXT_ACCESS_BEHAVIOR = "CROSS_CONTEXT_ACCESS_BEHAVIOR"
EVIDENCE_UNKNOWN = "UNKNOWN"

IDOR_BOLA_EVIDENCE_ITEMS: tuple[str, ...] = (
    EVIDENCE_AUTHORIZATION_CONTROL,
    EVIDENCE_OWNERSHIP_RELATIONSHIP,
    EVIDENCE_TENANT_BOUNDARY,
    EVIDENCE_ROLE_DEFINITION,
    EVIDENCE_OBJECT_IDENTIFIER_CONTEXT,
    EVIDENCE_OBJECT_LOOKUP_CONTEXT,
    EVIDENCE_ROUTE_CONTROLLER_CONTEXT,
    EVIDENCE_SERVER_SIDE_AUTHORIZATION,
    EVIDENCE_ACCESS_CONTROL_POLICY,
    EVIDENCE_OBSERVED_AUTHORIZATION_BEHAVIOR,
    EVIDENCE_CROSS_CONTEXT_ACCESS_BEHAVIOR,
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

# ---------------------------------------------------------------------------
# Closed limitations
# ---------------------------------------------------------------------------

LIMITATION_NO_COLLECTION_PERFORMED = "NO_COLLECTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_NO_AUTHORIZATION_BYPASS = "NO_AUTHORIZATION_BYPASS"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

IDOR_BOLA_EVIDENCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_AUTHORIZATION_BYPASS,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_EVIDENCE_ITEMS = 12
MAX_LIMITATIONS = 6
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


def sanitize_idor_bola_evidence_plan(value: object) -> dict:
    """Project an R46.4 plan onto its fixed bounded key set."""

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
            if item in IDOR_BOLA_EVIDENCE_ITEMS
        ][:MAX_EVIDENCE_ITEMS],
        "evidence_state": evidence_state,
        "confidence": confidence,
        "limitations": [
            code
            for code in (
                _safe_text(entry)
                for entry in value.get("limitations") or ()
            )
            if code in IDOR_BOLA_EVIDENCE_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class IDORBOLAEvidencePlan(BaseModel):
    """Deterministic research-only IDOR/BOLA evidence plan (R46.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = IDOR_BOLA_EVIDENCE_PLAN_RULE_VERSION
    evidence_items: list[str] = Field(default_factory=list)
    evidence_state: str = STATE_UNKNOWN
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return IDOR_BOLA_EVIDENCE_PLAN_RULE_VERSION

    @field_validator("evidence_items")
    @classmethod
    def _valid_items(cls, value: list) -> list[str]:
        return _require_codes(
            value, IDOR_BOLA_EVIDENCE_ITEMS, MAX_EVIDENCE_ITEMS
        )

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
            value, IDOR_BOLA_EVIDENCE_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("idor/bola evidence plans are research-only")
        return True


def idor_bola_evidence_plan_projection(value: IDORBOLAEvidencePlan) -> dict:
    """Serialize an IDOR/BOLA evidence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "IDOR_BOLA_EVIDENCE_PLAN_RULE_VERSION",
    "RULE_VERSION",
    "EVIDENCE_AUTHORIZATION_CONTROL",
    "EVIDENCE_OWNERSHIP_RELATIONSHIP",
    "EVIDENCE_TENANT_BOUNDARY",
    "EVIDENCE_ROLE_DEFINITION",
    "EVIDENCE_OBJECT_IDENTIFIER_CONTEXT",
    "EVIDENCE_OBJECT_LOOKUP_CONTEXT",
    "EVIDENCE_ROUTE_CONTROLLER_CONTEXT",
    "EVIDENCE_SERVER_SIDE_AUTHORIZATION",
    "EVIDENCE_ACCESS_CONTROL_POLICY",
    "EVIDENCE_OBSERVED_AUTHORIZATION_BEHAVIOR",
    "EVIDENCE_CROSS_CONTEXT_ACCESS_BEHAVIOR",
    "EVIDENCE_UNKNOWN",
    "IDOR_BOLA_EVIDENCE_ITEMS",
    "STATE_COMPLETE",
    "STATE_PARTIAL",
    "STATE_UNKNOWN",
    "EVIDENCE_STATES",
    "LIMITATION_NO_COLLECTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_NO_AUTHORIZATION_BYPASS",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "IDOR_BOLA_EVIDENCE_LIMITATIONS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_idor_bola_evidence_plan",
    "IDORBOLAEvidencePlan",
    "idor_bola_evidence_plan_projection",
]
