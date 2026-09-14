"""Finding assessment schema (Stage R53.5).

A :class:`FindingAssessmentPlan` is the conservative, deterministic
assessment of a finding candidate: research state, confidence, severity
provenance, impact reasoning, remediation availability and the explicit
non-confirmation invariant. It answers:

    "How strong, how uncertain and how impactful is this research finding
     candidate?"

Hard boundaries encoded here:

- Research assessment only: confidence describes structured research
  confidence, never probability of exploitation, severity or likelihood of
  compromise.
- Severity is never computed: it can only mirror an upstream observed CVSS
  metadata value from the structured context (``CVSS_CONTEXT``); otherwise
  it stays ``UNKNOWN`` with ``NOT_ASSESSED``.
- Impact is potential at most: ``OBSERVED`` impact is never produced by R53;
  business impact is never asserted.
- Confirmation is impossible by construction: ``confirmation_state`` is
  forced to ``NOT_CONFIRMED``. R53 cannot confirm a vulnerability.
- Remediation is only mirrored from upstream structured remediation hints;
  otherwise it is explicitly ``UNAVAILABLE``.
- Closed vocabularies; bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_evaluation_score import (
    EVALUATION_RATINGS,
    HARD_GATE_STATES,
)
from ai.schemas.cve_research_context_analysis import (
    CVSS_UNKNOWN,
    CVSS_SEVERITIES,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.llm_advisory_input import (
    ADVISORY_SAFETY_STATES,
    SAFETY_UNKNOWN,
)

FINDING_ASSESSMENT_RULE_VERSION = "r53-5"
RULE_VERSION = FINDING_ASSESSMENT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATE_RESEARCH_CANDIDATE = "RESEARCH_CANDIDATE"
STATE_EVIDENCE_SUPPORTED = "EVIDENCE_SUPPORTED"
STATE_NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
STATE_CONFLICTED = "CONFLICTED"
STATE_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
STATE_CONFIRMED_OBSERVED = "CONFIRMED_OBSERVED"

FINDING_STATES: tuple[str, ...] = (
    STATE_RESEARCH_CANDIDATE,
    STATE_EVIDENCE_SUPPORTED,
    STATE_NEEDS_MORE_EVIDENCE,
    STATE_CONFLICTED,
    STATE_INSUFFICIENT_EVIDENCE,
    STATE_CONFIRMED_OBSERVED,
)

CONFIRMATION_NOT_CONFIRMED = "NOT_CONFIRMED"

CONFIRMATION_STATES: tuple[str, ...] = (CONFIRMATION_NOT_CONFIRMED,)

IMPACT_POTENTIAL = "POTENTIAL"
IMPACT_OBSERVED = "OBSERVED"
IMPACT_UNKNOWN = "UNKNOWN"

IMPACT_STATES: tuple[str, ...] = (
    IMPACT_POTENTIAL,
    IMPACT_OBSERVED,
    IMPACT_UNKNOWN,
)

REMEDIATION_AVAILABLE = "AVAILABLE"
REMEDIATION_UNAVAILABLE = "UNAVAILABLE"
REMEDIATION_UNKNOWN = "UNKNOWN"

REMEDIATION_STATES: tuple[str, ...] = (
    REMEDIATION_AVAILABLE,
    REMEDIATION_UNAVAILABLE,
    REMEDIATION_UNKNOWN,
)

REMEDIATION_RESEARCH_QUALITY = "RESEARCH_QUALITY"
REMEDIATION_VULNERABILITY = "VULNERABILITY"
REMEDIATION_TYPE_UNKNOWN = "UNKNOWN"

REMEDIATION_TYPES: tuple[str, ...] = (
    REMEDIATION_RESEARCH_QUALITY,
    REMEDIATION_VULNERABILITY,
    REMEDIATION_TYPE_UNKNOWN,
)

SEVERITY_SOURCE_CVSS_CONTEXT = "CVSS_CONTEXT"
SEVERITY_SOURCE_NOT_ASSESSED = "NOT_ASSESSED"

SEVERITY_SOURCES: tuple[str, ...] = (
    SEVERITY_SOURCE_CVSS_CONTEXT,
    SEVERITY_SOURCE_NOT_ASSESSED,
)

# Confidence derivation reason codes (closed). They document which upstream
# constraints actually capped the finding confidence.
REASON_UPSTREAM_SPECIALIST_CONFIDENCE = "UPSTREAM_SPECIALIST_CONFIDENCE"
REASON_UPSTREAM_EVIDENCE_CONFIDENCE = "UPSTREAM_EVIDENCE_CONFIDENCE"
REASON_UPSTREAM_CONTEXT_CONFIDENCE = "UPSTREAM_CONTEXT_CONFIDENCE"
REASON_UPSTREAM_EVIDENCE_STATE = "UPSTREAM_EVIDENCE_STATE"
REASON_UPSTREAM_STATUS = "UPSTREAM_STATUS"
REASON_EVALUATION_QUALITY_CAP = "EVALUATION_QUALITY_CAP"
REASON_EVALUATION_SAFETY_CAP = "EVALUATION_SAFETY_CAP"
REASON_EVALUATION_DIAGNOSTIC_CAP = "EVALUATION_DIAGNOSTIC_CAP"
REASON_EVALUATION_UNAVAILABLE_CAP = "EVALUATION_UNAVAILABLE_CAP"
REASON_CONFLICT_CAP = "CONFLICT_CAP"
REASON_INSUFFICIENT_EVIDENCE_CAP = "INSUFFICIENT_EVIDENCE_CAP"
REASON_EVIDENCE_PARTIAL_CAP = "EVIDENCE_PARTIAL_CAP"
REASON_NO_UPSTREAM_CONFIDENCE = "NO_UPSTREAM_CONFIDENCE"

CONFIDENCE_REASONS: tuple[str, ...] = (
    REASON_UPSTREAM_SPECIALIST_CONFIDENCE,
    REASON_UPSTREAM_EVIDENCE_CONFIDENCE,
    REASON_UPSTREAM_CONTEXT_CONFIDENCE,
    REASON_UPSTREAM_EVIDENCE_STATE,
    REASON_UPSTREAM_STATUS,
    REASON_EVALUATION_QUALITY_CAP,
    REASON_EVALUATION_SAFETY_CAP,
    REASON_EVALUATION_DIAGNOSTIC_CAP,
    REASON_EVALUATION_UNAVAILABLE_CAP,
    REASON_CONFLICT_CAP,
    REASON_INSUFFICIENT_EVIDENCE_CAP,
    REASON_EVIDENCE_PARTIAL_CAP,
    REASON_NO_UPSTREAM_CONFIDENCE,
)

MAX_CONFIDENCE_REASONS = 8
MAX_REMEDIATION_ITEMS = 8
MAX_DIAGNOSTIC_CODES = 16
MAX_IMPACT_DESCRIPTION_LEN = 400
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_tokens(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_free_tokens(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if not text or not _TOKEN_RE.match(text) or text in out:
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_remediation_item(value: object) -> dict:
    """Project one remediation item onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "remediation_type": REMEDIATION_TYPE_UNKNOWN,
            "guidance": "",
            "source": "",
        }
    return {
        "remediation_type": _closed(
            value.get("remediation_type"),
            REMEDIATION_TYPES,
            REMEDIATION_TYPE_UNKNOWN,
        ),
        "guidance": _safe_text(value.get("guidance"), 240),
        "source": _safe_text(value.get("source")),
    }


def sanitize_finding_assessment(value: object) -> dict:
    """Project a finding assessment onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "state": STATE_INSUFFICIENT_EVIDENCE,
            "confidence": "UNKNOWN",
            "confidence_reasons": [],
            "severity": CVSS_UNKNOWN,
            "severity_source": SEVERITY_SOURCE_NOT_ASSESSED,
            "impact_state": IMPACT_UNKNOWN,
            "impact_confidence": "UNKNOWN",
            "impact_description": "",
            "business_impact_asserted": False,
            "remediation_state": REMEDIATION_UNAVAILABLE,
            "remediation_items": [],
            "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
            "evaluation_present": False,
            "evaluation_rating": "",
            "hard_gate_state": "",
            "safety_state": SAFETY_UNKNOWN,
            "diagnostic_codes": [],
            "research_only": True,
        }
    items: list[dict] = []
    for item in value.get("remediation_items") or ():
        projected = sanitize_remediation_item(item)
        if projected["guidance"] and projected not in items:
            items.append(projected)
        if len(items) >= MAX_REMEDIATION_ITEMS:
            break
    evaluation_rating = value.get("evaluation_rating")
    if evaluation_rating not in EVALUATION_RATINGS:
        evaluation_rating = ""
    hard_gate = value.get("hard_gate_state")
    if hard_gate not in HARD_GATE_STATES:
        hard_gate = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "state": _closed(
            value.get("state"),
            FINDING_STATES,
            STATE_INSUFFICIENT_EVIDENCE,
        ),
        "confidence": _closed(
            value.get("confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "confidence_reasons": _bounded_tokens(
            value.get("confidence_reasons"),
            CONFIDENCE_REASONS,
            MAX_CONFIDENCE_REASONS,
        ),
        "severity": _closed(
            value.get("severity"), CVSS_SEVERITIES, CVSS_UNKNOWN
        ),
        "severity_source": _closed(
            value.get("severity_source"),
            SEVERITY_SOURCES,
            SEVERITY_SOURCE_NOT_ASSESSED,
        ),
        "impact_state": _closed(
            value.get("impact_state"), IMPACT_STATES, IMPACT_UNKNOWN
        ),
        "impact_confidence": _closed(
            value.get("impact_confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "impact_description": _safe_text(
            value.get("impact_description"), MAX_IMPACT_DESCRIPTION_LEN
        ),
        "business_impact_asserted": False,
        "remediation_state": _closed(
            value.get("remediation_state"),
            REMEDIATION_STATES,
            REMEDIATION_UNAVAILABLE,
        ),
        "remediation_items": items,
        "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
        "evaluation_present": bool(value.get("evaluation_present")) is True,
        "evaluation_rating": evaluation_rating,
        "hard_gate_state": hard_gate,
        "safety_state": _closed(
            value.get("safety_state"), ADVISORY_SAFETY_STATES, SAFETY_UNKNOWN
        ),
        "diagnostic_codes": _bounded_free_tokens(
            value.get("diagnostic_codes"), MAX_DIAGNOSTIC_CODES
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class FindingRemediationItemPlan(BaseModel):
    """One upstream-supported remediation hint (R53.5)."""

    model_config = ConfigDict(extra="forbid")

    remediation_type: str = REMEDIATION_TYPE_UNKNOWN
    guidance: str = ""
    source: str = ""

    @field_validator("remediation_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REMEDIATION_TYPES:
            raise ValueError(f"invalid remediation_type: {value!r}")
        return text

    @field_validator("guidance")
    @classmethod
    def _bounded_guidance(cls, value: object) -> str:
        return _safe_text(value, 240)

    @field_validator("source")
    @classmethod
    def _bounded_source(cls, value: object) -> str:
        return _safe_text(value)


class FindingAssessmentPlan(BaseModel):
    """Conservative deterministic finding assessment (R53.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_ASSESSMENT_RULE_VERSION
    state: str = STATE_INSUFFICIENT_EVIDENCE
    confidence: str = "UNKNOWN"
    confidence_reasons: list[str] = Field(default_factory=list)
    severity: str = CVSS_UNKNOWN
    severity_source: str = SEVERITY_SOURCE_NOT_ASSESSED
    impact_state: str = IMPACT_UNKNOWN
    impact_confidence: str = "UNKNOWN"
    impact_description: str = ""
    business_impact_asserted: bool = False
    remediation_state: str = REMEDIATION_UNAVAILABLE
    remediation_items: list[dict] = Field(default_factory=list)
    confirmation_state: str = CONFIRMATION_NOT_CONFIRMED
    evaluation_present: bool = False
    evaluation_rating: str = ""
    hard_gate_state: str = ""
    safety_state: str = SAFETY_UNKNOWN
    diagnostic_codes: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_ASSESSMENT_RULE_VERSION

    @field_validator("state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in FINDING_STATES:
            raise ValueError(f"invalid finding state: {value!r}")
        return text

    @field_validator("confidence", "impact_confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("confidence_reasons")
    @classmethod
    def _valid_reasons(cls, value: object) -> list[str]:
        return _bounded_tokens(value, CONFIDENCE_REASONS,
                               MAX_CONFIDENCE_REASONS)

    @field_validator("severity")
    @classmethod
    def _valid_severity(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CVSS_SEVERITIES:
            raise ValueError(f"invalid severity: {value!r}")
        return text

    @field_validator("severity_source")
    @classmethod
    def _valid_severity_source(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SEVERITY_SOURCES:
            raise ValueError(f"invalid severity_source: {value!r}")
        return text

    @field_validator("impact_state")
    @classmethod
    def _valid_impact(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in IMPACT_STATES:
            raise ValueError(f"invalid impact_state: {value!r}")
        return text

    @field_validator("impact_description")
    @classmethod
    def _bounded_impact(cls, value: object) -> str:
        return _safe_text(value, MAX_IMPACT_DESCRIPTION_LEN)

    @field_validator("business_impact_asserted")
    @classmethod
    def _no_business_impact(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("R53 never asserts business impact")
        return False

    @field_validator("remediation_state")
    @classmethod
    def _valid_remediation(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REMEDIATION_STATES:
            raise ValueError(f"invalid remediation_state: {value!r}")
        return text

    @field_validator("remediation_items")
    @classmethod
    def _bounded_remediation(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_remediation_item(item)
            if projected["guidance"] and projected not in out:
                out.append(projected)
            if len(out) >= MAX_REMEDIATION_ITEMS:
                break
        return out

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != CONFIRMATION_NOT_CONFIRMED:
            raise ValueError("R53 findings are never confirmed")
        return CONFIRMATION_NOT_CONFIRMED

    @field_validator("evaluation_rating")
    @classmethod
    def _valid_rating(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if not text:
            return ""
        if text not in EVALUATION_RATINGS:
            raise ValueError(f"invalid evaluation_rating: {value!r}")
        return text

    @field_validator("hard_gate_state")
    @classmethod
    def _valid_gate(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if not text:
            return ""
        if text not in HARD_GATE_STATES:
            raise ValueError(f"invalid hard_gate_state: {value!r}")
        return text

    @field_validator("safety_state")
    @classmethod
    def _valid_safety(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ADVISORY_SAFETY_STATES:
            raise ValueError(f"invalid safety_state: {value!r}")
        return text

    @field_validator("diagnostic_codes")
    @classmethod
    def _bounded_codes(cls, value: object) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item).strip().upper()
            if not text or not _TOKEN_RE.match(text) or text in out:
                continue
            out.append(text)
            if len(out) >= MAX_DIAGNOSTIC_CODES:
                break
        return out

    @field_validator("evaluation_present")
    @classmethod
    def _evaluation_bool(cls, value: object) -> bool:
        if not isinstance(value, bool):
            raise ValueError("evaluation_present must be a boolean")
        return value

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("finding assessments are research-only")
        return True


def finding_assessment_plan_projection(
    value: FindingAssessmentPlan,
) -> dict:
    """Serialize a finding assessment to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "FINDING_ASSESSMENT_RULE_VERSION",
    "RULE_VERSION",
    "FINDING_STATES",
    "CONFIRMATION_STATES",
    "IMPACT_STATES",
    "REMEDIATION_STATES",
    "REMEDIATION_TYPES",
    "SEVERITY_SOURCES",
    "CONFIDENCE_REASONS",
    "STATE_RESEARCH_CANDIDATE",
    "STATE_EVIDENCE_SUPPORTED",
    "STATE_NEEDS_MORE_EVIDENCE",
    "STATE_CONFLICTED",
    "STATE_INSUFFICIENT_EVIDENCE",
    "STATE_CONFIRMED_OBSERVED",
    "CONFIRMATION_NOT_CONFIRMED",
    "IMPACT_POTENTIAL",
    "IMPACT_OBSERVED",
    "IMPACT_UNKNOWN",
    "REMEDIATION_AVAILABLE",
    "REMEDIATION_UNAVAILABLE",
    "REMEDIATION_UNKNOWN",
    "REMEDIATION_RESEARCH_QUALITY",
    "REMEDIATION_VULNERABILITY",
    "REMEDIATION_TYPE_UNKNOWN",
    "SEVERITY_SOURCE_CVSS_CONTEXT",
    "SEVERITY_SOURCE_NOT_ASSESSED",
    "REASON_UPSTREAM_SPECIALIST_CONFIDENCE",
    "REASON_UPSTREAM_EVIDENCE_CONFIDENCE",
    "REASON_UPSTREAM_CONTEXT_CONFIDENCE",
    "REASON_UPSTREAM_EVIDENCE_STATE",
    "REASON_UPSTREAM_STATUS",
    "REASON_EVALUATION_QUALITY_CAP",
    "REASON_EVALUATION_SAFETY_CAP",
    "REASON_EVALUATION_DIAGNOSTIC_CAP",
    "REASON_EVALUATION_UNAVAILABLE_CAP",
    "REASON_CONFLICT_CAP",
    "REASON_INSUFFICIENT_EVIDENCE_CAP",
    "REASON_EVIDENCE_PARTIAL_CAP",
    "REASON_NO_UPSTREAM_CONFIDENCE",
    "MAX_CONFIDENCE_REASONS",
    "MAX_REMEDIATION_ITEMS",
    "MAX_DIAGNOSTIC_CODES",
    "MAX_IMPACT_DESCRIPTION_LEN",
    "MAX_VALUE_LEN",
    "sanitize_remediation_item",
    "sanitize_finding_assessment",
    "FindingRemediationItemPlan",
    "FindingAssessmentPlan",
    "finding_assessment_plan_projection",
]
