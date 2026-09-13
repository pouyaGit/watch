"""SQLi evidence plan schema (Stage R41.4).

An :class:`SQLIEvidencePlan` defines which research evidence would be
required to evaluate the SQLi hypotheses. It answers the research question:

    "Which bounded evidence categories would this research require?"

Hard boundaries encoded here:

- Evidence planning only: no evidence collection, no SQL execution, no
  database connection, no HTTP/network request, no payload, no fuzzing, no
  parameter brute forcing, no sqlmap, no persistence.
- Closed vocabularies: evidence categories, evidence state and limitations
  are closed sets; confidence reuses the shared evidence-confidence
  vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no SQL, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

SQLI_EVIDENCE_PLAN_RULE_VERSION = "r41-4"
RULE_VERSION = SQLI_EVIDENCE_PLAN_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

EVIDENCE_QUERY_CONSTRUCTION = "QUERY_CONSTRUCTION"
EVIDENCE_PARAMETERIZATION = "PARAMETERIZATION"
EVIDENCE_INPUT_VALIDATION = "INPUT_VALIDATION"
EVIDENCE_TYPE_HANDLING = "TYPE_HANDLING"
EVIDENCE_ORM_QUERY_CONTEXT = "ORM_QUERY_CONTEXT"
EVIDENCE_RAW_QUERY_CONTEXT = "RAW_QUERY_CONTEXT"
EVIDENCE_ERROR_BEHAVIOR = "ERROR_BEHAVIOR"
EVIDENCE_BOOLEAN_BEHAVIOR = "BOOLEAN_BEHAVIOR"
EVIDENCE_TIMING_BEHAVIOR = "TIMING_BEHAVIOR"
EVIDENCE_ORDER_BY_CONTEXT = "ORDER_BY_CONTEXT"
EVIDENCE_IDENTIFIER_CONTEXT = "IDENTIFIER_CONTEXT"
EVIDENCE_STORED_PROCEDURE_CONTEXT = "STORED_PROCEDURE_CONTEXT"
EVIDENCE_DATABASE_CONTEXT = "DATABASE_CONTEXT"
EVIDENCE_APPLICATION_BEHAVIOR = "APPLICATION_BEHAVIOR"
EVIDENCE_UNKNOWN = "UNKNOWN"

SQLI_EVIDENCE_ITEMS: tuple[str, ...] = (
    EVIDENCE_QUERY_CONSTRUCTION,
    EVIDENCE_PARAMETERIZATION,
    EVIDENCE_INPUT_VALIDATION,
    EVIDENCE_TYPE_HANDLING,
    EVIDENCE_ORM_QUERY_CONTEXT,
    EVIDENCE_RAW_QUERY_CONTEXT,
    EVIDENCE_ERROR_BEHAVIOR,
    EVIDENCE_BOOLEAN_BEHAVIOR,
    EVIDENCE_TIMING_BEHAVIOR,
    EVIDENCE_ORDER_BY_CONTEXT,
    EVIDENCE_IDENTIFIER_CONTEXT,
    EVIDENCE_STORED_PROCEDURE_CONTEXT,
    EVIDENCE_DATABASE_CONTEXT,
    EVIDENCE_APPLICATION_BEHAVIOR,
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
LIMITATION_NO_SQL_EXECUTION = "NO_SQL_EXECUTION"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

SQLI_EVIDENCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_SQL_EXECUTION,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_EVIDENCE_ITEMS = 15
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


def sanitize_sqli_evidence_plan(value: object) -> dict:
    """Project an R41.4 plan onto its fixed bounded key set."""

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
            if item in SQLI_EVIDENCE_ITEMS
        ][:MAX_EVIDENCE_ITEMS],
        "evidence_state": evidence_state,
        "confidence": confidence,
        "limitations": [
            code
            for code in (
                _safe_text(entry)
                for entry in value.get("limitations") or ()
            )
            if code in SQLI_EVIDENCE_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SQLIEvidencePlan(BaseModel):
    """Deterministic research-only SQLi evidence plan (R41.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SQLI_EVIDENCE_PLAN_RULE_VERSION
    evidence_items: list[str] = Field(default_factory=list)
    evidence_state: str = STATE_UNKNOWN
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SQLI_EVIDENCE_PLAN_RULE_VERSION

    @field_validator("evidence_items")
    @classmethod
    def _valid_items(cls, value: list) -> list[str]:
        return _require_codes(value, SQLI_EVIDENCE_ITEMS, MAX_EVIDENCE_ITEMS)

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
            value, SQLI_EVIDENCE_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("sqli evidence plans are research-only")
        return True


def sqli_evidence_plan_projection(value: SQLIEvidencePlan) -> dict:
    """Serialize a SQLi evidence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SQLI_EVIDENCE_PLAN_RULE_VERSION",
    "RULE_VERSION",
    "EVIDENCE_QUERY_CONSTRUCTION",
    "EVIDENCE_PARAMETERIZATION",
    "EVIDENCE_INPUT_VALIDATION",
    "EVIDENCE_TYPE_HANDLING",
    "EVIDENCE_ORM_QUERY_CONTEXT",
    "EVIDENCE_RAW_QUERY_CONTEXT",
    "EVIDENCE_ERROR_BEHAVIOR",
    "EVIDENCE_BOOLEAN_BEHAVIOR",
    "EVIDENCE_TIMING_BEHAVIOR",
    "EVIDENCE_ORDER_BY_CONTEXT",
    "EVIDENCE_IDENTIFIER_CONTEXT",
    "EVIDENCE_STORED_PROCEDURE_CONTEXT",
    "EVIDENCE_DATABASE_CONTEXT",
    "EVIDENCE_APPLICATION_BEHAVIOR",
    "EVIDENCE_UNKNOWN",
    "SQLI_EVIDENCE_ITEMS",
    "STATE_COMPLETE",
    "STATE_PARTIAL",
    "STATE_UNKNOWN",
    "EVIDENCE_STATES",
    "LIMITATION_NO_COLLECTION_PERFORMED",
    "LIMITATION_NO_SQL_EXECUTION",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "SQLI_EVIDENCE_LIMITATIONS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_sqli_evidence_plan",
    "SQLIEvidencePlan",
    "sqli_evidence_plan_projection",
]
