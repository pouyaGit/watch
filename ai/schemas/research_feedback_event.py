"""Research feedback event schema (Stage R44.1).

A :class:`ResearchFeedbackEventPlan` is a bounded, read-only projection of a
previous structured research outcome, used by the feedback learning layer. It
answers:

    "What did previous structured research produce that future research
     should consider?"

Hard boundaries encoded here:

- Learning only: the event is a structured observation over already-produced
  artifacts (R42 evaluation, R43 collaboration). No agent execution, no
  security testing, no network, no database, no browser, no LLM call, no
  payloads.
- No runtime identity: ``feedback_id`` is a deterministic content token or a
  caller-supplied validated token; no timestamps, random UUIDs or runtime
  identifiers.
- Feedback is based only on supplied structured outcomes; nothing is
  invented.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_evaluation_score import (
    EVALUATION_RATINGS,
    HARD_GATE_STATES,
    SAFETY_STATES,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

RESEARCH_FEEDBACK_EVENT_RULE_VERSION = "r44-1"
RULE_VERSION = RESEARCH_FEEDBACK_EVENT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

OUTCOME_QUALITY = "QUALITY_OBSERVATION"
OUTCOME_CONFIDENCE = "CONFIDENCE_OBSERVATION"
OUTCOME_EVIDENCE = "EVIDENCE_OBSERVATION"
OUTCOME_HYPOTHESIS = "HYPOTHESIS_OBSERVATION"
OUTCOME_DUPLICATION = "DUPLICATION_OBSERVATION"
OUTCOME_CONFLICT = "CONFLICT_OBSERVATION"
OUTCOME_GOVERNANCE = "GOVERNANCE_OBSERVATION"
OUTCOME_PROVENANCE = "PROVENANCE_OBSERVATION"
OUTCOME_SAFETY = "SAFETY_OBSERVATION"
OUTCOME_SUCCESS = "SUCCESS_OBSERVATION"
OUTCOME_UNKNOWN = "UNKNOWN"

OUTCOME_TYPES: tuple[str, ...] = (
    OUTCOME_QUALITY,
    OUTCOME_CONFIDENCE,
    OUTCOME_EVIDENCE,
    OUTCOME_HYPOTHESIS,
    OUTCOME_DUPLICATION,
    OUTCOME_CONFLICT,
    OUTCOME_GOVERNANCE,
    OUTCOME_PROVENANCE,
    OUTCOME_SAFETY,
    OUTCOME_SUCCESS,
    OUTCOME_UNKNOWN,
)

ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE = "ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE"
ISSUE_MISSING_EVIDENCE_REQUIREMENT = "ISSUE_MISSING_EVIDENCE_REQUIREMENT"
ISSUE_EVIDENCE_INCONSISTENT = "ISSUE_EVIDENCE_INCONSISTENT"
ISSUE_DUPLICATE_HYPOTHESES = "ISSUE_DUPLICATE_HYPOTHESES"
ISSUE_CONFLICTING_HYPOTHESES = "ISSUE_CONFLICTING_HYPOTHESES"
ISSUE_WEAK_HYPOTHESIS_SIGNALS = "ISSUE_WEAK_HYPOTHESIS_SIGNALS"
ISSUE_NO_HYPOTHESES = "ISSUE_NO_HYPOTHESES"
ISSUE_MISSING_PROVENANCE = "ISSUE_MISSING_PROVENANCE"
ISSUE_UNKNOWN_GOVERNANCE = "ISSUE_UNKNOWN_GOVERNANCE"
ISSUE_GOVERNANCE_INCONSISTENT = "ISSUE_GOVERNANCE_INCONSISTENT"
ISSUE_SAFETY_LIMITATION_MISSING = "ISSUE_SAFETY_LIMITATION_MISSING"
ISSUE_FORBIDDEN_CLAIM = "ISSUE_FORBIDDEN_CLAIM"
ISSUE_RESEARCH_ONLY_FALSE = "ISSUE_RESEARCH_ONLY_FALSE"
ISSUE_NONE_OBSERVED = "NONE_OBSERVED"
ISSUE_UNKNOWN = "UNKNOWN"

OBSERVED_ISSUES: tuple[str, ...] = (
    ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE,
    ISSUE_MISSING_EVIDENCE_REQUIREMENT,
    ISSUE_EVIDENCE_INCONSISTENT,
    ISSUE_DUPLICATE_HYPOTHESES,
    ISSUE_CONFLICTING_HYPOTHESES,
    ISSUE_WEAK_HYPOTHESIS_SIGNALS,
    ISSUE_NO_HYPOTHESES,
    ISSUE_MISSING_PROVENANCE,
    ISSUE_UNKNOWN_GOVERNANCE,
    ISSUE_GOVERNANCE_INCONSISTENT,
    ISSUE_SAFETY_LIMITATION_MISSING,
    ISSUE_FORBIDDEN_CLAIM,
    ISSUE_RESEARCH_ONLY_FALSE,
    ISSUE_NONE_OBSERVED,
    ISSUE_UNKNOWN,
)

SUCCESS_STRONG_EVALUATION = "SUCCESS_STRONG_EVALUATION"
SUCCESS_COMPLETE_EVIDENCE = "SUCCESS_COMPLETE_EVIDENCE"
SUCCESS_SAFE_RESEARCH = "SUCCESS_SAFE_RESEARCH"
SUCCESS_NONE_OBSERVED = "NONE_OBSERVED"
SUCCESS_UNKNOWN = "UNKNOWN"

OBSERVED_SUCCESSES: tuple[str, ...] = (
    SUCCESS_STRONG_EVALUATION,
    SUCCESS_COMPLETE_EVIDENCE,
    SUCCESS_SAFE_RESEARCH,
    SUCCESS_NONE_OBSERVED,
    SUCCESS_UNKNOWN,
)

FLAG_MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
FLAG_INVALID_ENUM_VALUE = "INVALID_ENUM_VALUE"
FLAG_UNKNOWN_SOURCE_CATEGORY = "UNKNOWN_SOURCE_CATEGORY"
FLAG_MALFORMED_EVALUATION_REFERENCE = "MALFORMED_EVALUATION_REFERENCE"
FLAG_MALFORMED_COLLABORATION_REFERENCE = (
    "MALFORMED_COLLABORATION_REFERENCE"
)
FLAG_MALFORMED_PROVENANCE = "MALFORMED_PROVENANCE"
FLAG_MALFORMED_GOVERNANCE = "MALFORMED_GOVERNANCE"
FLAG_NON_DETERMINISTIC_INPUT = "NON_DETERMINISTIC_INPUT"

FEEDBACK_STRUCTURAL_FLAGS: tuple[str, ...] = (
    FLAG_MISSING_REQUIRED_FIELD,
    FLAG_INVALID_ENUM_VALUE,
    FLAG_UNKNOWN_SOURCE_CATEGORY,
    FLAG_MALFORMED_EVALUATION_REFERENCE,
    FLAG_MALFORMED_COLLABORATION_REFERENCE,
    FLAG_MALFORMED_PROVENANCE,
    FLAG_MALFORMED_GOVERNANCE,
    FLAG_NON_DETERMINISTIC_INPUT,
)

GENERIC_PROVENANCE_LAYERS: tuple[str, ...] = (
    "REASONING",
    "MEMORY",
    "LEARNING",
    "STRATEGY",
    "ORCHESTRATION",
    "AUTHORIZATION",
    "GOVERNANCE",
)

GENERIC_PROVENANCE_STATES: tuple[str, ...] = (
    "COMPLETE",
    "PARTIAL",
    "UNKNOWN",
)

GENERIC_GOVERNANCE_STATES: tuple[str, ...] = (
    "REFERENCED",
    "UNKNOWN",
)

GENERIC_COMPONENT_STATES: tuple[str, ...] = (
    "COMPLETE",
    "PARTIAL",
    "VALID",
    "INVALID",
    "UNKNOWN",
)

GENERIC_EVIDENCE_STATES: tuple[str, ...] = (
    "COMPLETE",
    "PARTIAL",
    "UNKNOWN",
)

FEEDBACK_ID_PREFIX = "fb-"
FEEDBACK_ID_RE = re.compile(r"^fb-[0-9a-f]{16}$")

MAX_LIST = 16
MAX_FLAGS = 8
MAX_DIAGNOSTICS = 24
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_tokens(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if not text or not _TOKEN_RE.match(text) or text in out:
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_int(value: object, limit: int = 100) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, min(limit, value))


def sanitize_feedback_provenance(value: object) -> dict:
    """Project provenance onto a bounded generic shape.

    Missing or empty provenance stays ``{}`` so downstream classification can
    distinguish "no provenance record" from "provenance recorded as UNKNOWN".
    """

    if not isinstance(value, dict) or not value:
        return {}
    state = _safe_text(value.get("provenance_state")).strip().upper()
    if state not in GENERIC_PROVENANCE_STATES:
        state = "UNKNOWN"
    layers: list[str] = []
    for item in value.get("source_layers") or ():
        text = _safe_text(item).strip().upper()
        if text in GENERIC_PROVENANCE_LAYERS and text not in layers:
            layers.append(text)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "source_layers": layers,
        "provenance_state": state,
        "research_only": bool(value.get("research_only")) is True,
    }


def sanitize_feedback_governance(value: object) -> dict:
    """Project a governance reference onto a bounded generic shape.

    Missing or empty governance stays ``{}`` so downstream classification can
    distinguish "no governance record" from "governance recorded as UNKNOWN".
    """

    if not isinstance(value, dict) or not value:
        return {}
    reference_state = _safe_text(
        value.get("reference_state")
    ).strip().upper()
    if reference_state not in GENERIC_GOVERNANCE_STATES:
        reference_state = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "ready": bool(value.get("ready")) is True,
        "provenance_state": _closed_component(
            value.get("provenance_state")
        ),
        "trace_state": _closed_component(value.get("trace_state")),
        "audit_state": _closed_component(value.get("audit_state")),
        "explanation_state": _closed_component(
            value.get("explanation_state")
        ),
        "reference_state": reference_state,
    }


def _closed_component(value: object) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in GENERIC_COMPONENT_STATES else "UNKNOWN"


def sanitize_feedback_evaluation_reference(value: object) -> dict:
    """Project an R42 evaluation reference onto fixed bounded keys."""

    if not isinstance(value, dict) or not value.get("present"):
        return {
            "present": False,
            "overall_score": 0,
            "overall_rating": "CRITICAL",
            "hard_gate_state": "PASS",
            "safety_state": "FAILED",
            "structural_score": 0,
            "safety_score": 0,
            "evidence_score": 0,
            "confidence_score": 0,
            "dimension_scores_present": False,
            "diagnostic_codes": [],
            "deterministic": True,
            "research_only": True,
        }
    rating = _safe_text(value.get("overall_rating")).strip().upper()
    if rating not in EVALUATION_RATINGS:
        rating = "CRITICAL"
    hard_gate = _safe_text(value.get("hard_gate_state")).strip().upper()
    if hard_gate not in HARD_GATE_STATES:
        hard_gate = "PASS"
    safety = _safe_text(value.get("safety_state")).strip().upper()
    if safety not in SAFETY_STATES:
        safety = "FAILED"
    return {
        "present": True,
        "overall_score": _bounded_int(value.get("overall_score")),
        "overall_rating": rating,
        "hard_gate_state": hard_gate,
        "safety_state": safety,
        "structural_score": _bounded_int(value.get("structural_score")),
        "safety_score": _bounded_int(value.get("safety_score")),
        "evidence_score": _bounded_int(value.get("evidence_score")),
        "confidence_score": _bounded_int(value.get("confidence_score")),
        "dimension_scores_present": bool(
            value.get("dimension_scores_present", False)
        ) is True,
        "diagnostic_codes": _bounded_tokens(
            value.get("diagnostic_codes"), MAX_DIAGNOSTICS
        ),
        "deterministic": bool(value.get("deterministic", True)) is True,
        "research_only": bool(value.get("research_only", True)) is True,
    }


def sanitize_feedback_collaboration_reference(value: object) -> dict:
    """Project an R43 collaboration reference onto fixed bounded keys."""

    if not isinstance(value, dict) or not value.get("present"):
        return {
            "present": False,
            "participant_count": 0,
            "conflict_count": 0,
            "conflict_types": [],
            "duplicate_group_count": 0,
            "related_group_count": 0,
            "merged_evidence_state": "UNKNOWN",
            "ranking_count": 0,
            "deterministic": True,
            "research_only": True,
        }
    evidence_state = _safe_text(
        value.get("merged_evidence_state")
    ).strip().upper()
    if evidence_state not in GENERIC_EVIDENCE_STATES:
        evidence_state = "UNKNOWN"
    return {
        "present": True,
        "participant_count": _bounded_int(value.get("participant_count"), 16),
        "conflict_count": _bounded_int(value.get("conflict_count"), 32),
        "conflict_types": _bounded_tokens(
            value.get("conflict_types"), MAX_LIST
        ),
        "duplicate_group_count": _bounded_int(
            value.get("duplicate_group_count"), 32
        ),
        "related_group_count": _bounded_int(
            value.get("related_group_count"), 32
        ),
        "merged_evidence_state": evidence_state,
        "ranking_count": _bounded_int(value.get("ranking_count"), 16),
        "deterministic": bool(value.get("deterministic", True)) is True,
        "research_only": bool(value.get("research_only", True)) is True,
    }


def sanitize_research_feedback_event(value: object) -> dict:
    """Project a feedback event onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "feedback_id": "",
            "source_agent": "",
            "source_category": "UNKNOWN",
            "evaluation_reference": (
                sanitize_feedback_evaluation_reference(None)
            ),
            "collaboration_reference": (
                sanitize_feedback_collaboration_reference(None)
            ),
            "outcome_type": OUTCOME_UNKNOWN,
            "observed_issue": ISSUE_UNKNOWN,
            "observed_success": SUCCESS_UNKNOWN,
            "confidence": "UNKNOWN",
            "provenance": {},
            "governance_reference": {},
            "research_only": True,
            "structural_flags": [],
        }
    category = _safe_text(value.get("source_category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    flags: list[str] = []
    for item in value.get("structural_flags") or ():
        text = _safe_text(item).strip().upper()
        if text in FEEDBACK_STRUCTURAL_FLAGS and text not in flags:
            flags.append(text)
        if len(flags) >= MAX_FLAGS:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "feedback_id": _safe_text(value.get("feedback_id")),
        "source_agent": _safe_text(value.get("source_agent")),
        "source_category": category,
        "evaluation_reference": sanitize_feedback_evaluation_reference(
            value.get("evaluation_reference")
        ),
        "collaboration_reference": (
            sanitize_feedback_collaboration_reference(
                value.get("collaboration_reference")
            )
        ),
        "outcome_type": _closed(
            value.get("outcome_type"), OUTCOME_TYPES, OUTCOME_UNKNOWN
        ),
        "observed_issue": _closed(
            value.get("observed_issue"), OBSERVED_ISSUES, ISSUE_UNKNOWN
        ),
        "observed_success": _closed(
            value.get("observed_success"),
            OBSERVED_SUCCESSES,
            SUCCESS_UNKNOWN,
        ),
        "confidence": confidence,
        "provenance": sanitize_feedback_provenance(
            value.get("provenance")
        ),
        "governance_reference": sanitize_feedback_governance(
            value.get("governance_reference")
        ),
        "research_only": True,
        "structural_flags": flags,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchFeedbackEventPlan(BaseModel):
    """Bounded, read-only research feedback event (R44.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_FEEDBACK_EVENT_RULE_VERSION
    feedback_id: str = ""
    source_agent: str = ""
    source_category: str = "UNKNOWN"
    evaluation_reference: dict = Field(default_factory=dict)
    collaboration_reference: dict = Field(default_factory=dict)
    outcome_type: str = OUTCOME_UNKNOWN
    observed_issue: str = ISSUE_UNKNOWN
    observed_success: str = SUCCESS_UNKNOWN
    confidence: str = "UNKNOWN"
    provenance: dict = Field(default_factory=dict)
    governance_reference: dict = Field(default_factory=dict)
    research_only: bool = True
    structural_flags: list[str] = Field(default_factory=list)

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_FEEDBACK_EVENT_RULE_VERSION

    @field_validator("feedback_id", "source_agent")
    @classmethod
    def _bounded_text(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("source_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid source_category: {value!r}")
        return text

    @field_validator("evaluation_reference")
    @classmethod
    def _valid_evaluation(cls, value: object) -> dict:
        return sanitize_feedback_evaluation_reference(value)

    @field_validator("collaboration_reference")
    @classmethod
    def _valid_collaboration(cls, value: object) -> dict:
        return sanitize_feedback_collaboration_reference(value)

    @field_validator("outcome_type")
    @classmethod
    def _valid_outcome(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OUTCOME_TYPES:
            raise ValueError(f"invalid outcome_type: {value!r}")
        return text

    @field_validator("observed_issue")
    @classmethod
    def _valid_issue(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OBSERVED_ISSUES:
            raise ValueError(f"invalid observed_issue: {value!r}")
        return text

    @field_validator("observed_success")
    @classmethod
    def _valid_success(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OBSERVED_SUCCESSES:
            raise ValueError(f"invalid observed_success: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("provenance")
    @classmethod
    def _valid_provenance(cls, value: object) -> dict:
        return sanitize_feedback_provenance(value)

    @field_validator("governance_reference")
    @classmethod
    def _valid_governance(cls, value: object) -> dict:
        return sanitize_feedback_governance(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research feedback events are research-only")
        return True

    @field_validator("structural_flags")
    @classmethod
    def _valid_flags(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item).strip().upper()
            if text in FEEDBACK_STRUCTURAL_FLAGS and text not in out:
                out.append(text)
            if len(out) >= MAX_FLAGS:
                break
        return out


def research_feedback_event_plan_projection(
    value: ResearchFeedbackEventPlan,
) -> dict:
    """Serialize a feedback event to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_FEEDBACK_EVENT_RULE_VERSION",
    "RULE_VERSION",
    "OUTCOME_TYPES",
    "OUTCOME_QUALITY",
    "OUTCOME_CONFIDENCE",
    "OUTCOME_EVIDENCE",
    "OUTCOME_HYPOTHESIS",
    "OUTCOME_DUPLICATION",
    "OUTCOME_CONFLICT",
    "OUTCOME_GOVERNANCE",
    "OUTCOME_PROVENANCE",
    "OUTCOME_SAFETY",
    "OUTCOME_SUCCESS",
    "OUTCOME_UNKNOWN",
    "OBSERVED_ISSUES",
    "OBSERVED_SUCCESSES",
    "ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE",
    "ISSUE_MISSING_EVIDENCE_REQUIREMENT",
    "ISSUE_EVIDENCE_INCONSISTENT",
    "ISSUE_DUPLICATE_HYPOTHESES",
    "ISSUE_CONFLICTING_HYPOTHESES",
    "ISSUE_WEAK_HYPOTHESIS_SIGNALS",
    "ISSUE_NO_HYPOTHESES",
    "ISSUE_MISSING_PROVENANCE",
    "ISSUE_UNKNOWN_GOVERNANCE",
    "ISSUE_GOVERNANCE_INCONSISTENT",
    "ISSUE_SAFETY_LIMITATION_MISSING",
    "ISSUE_FORBIDDEN_CLAIM",
    "ISSUE_RESEARCH_ONLY_FALSE",
    "ISSUE_NONE_OBSERVED",
    "ISSUE_UNKNOWN",
    "SUCCESS_STRONG_EVALUATION",
    "SUCCESS_COMPLETE_EVIDENCE",
    "SUCCESS_SAFE_RESEARCH",
    "SUCCESS_NONE_OBSERVED",
    "SUCCESS_UNKNOWN",
    "FEEDBACK_STRUCTURAL_FLAGS",
    "FLAG_MISSING_REQUIRED_FIELD",
    "FLAG_INVALID_ENUM_VALUE",
    "FLAG_UNKNOWN_SOURCE_CATEGORY",
    "FLAG_MALFORMED_EVALUATION_REFERENCE",
    "FLAG_MALFORMED_COLLABORATION_REFERENCE",
    "FLAG_MALFORMED_PROVENANCE",
    "FLAG_MALFORMED_GOVERNANCE",
    "FLAG_NON_DETERMINISTIC_INPUT",
    "GENERIC_PROVENANCE_LAYERS",
    "GENERIC_PROVENANCE_STATES",
    "GENERIC_GOVERNANCE_STATES",
    "GENERIC_COMPONENT_STATES",
    "GENERIC_EVIDENCE_STATES",
    "FEEDBACK_ID_PREFIX",
    "FEEDBACK_ID_RE",
    "MAX_LIST",
    "MAX_FLAGS",
    "MAX_DIAGNOSTICS",
    "MAX_VALUE_LEN",
    "sanitize_feedback_provenance",
    "sanitize_feedback_governance",
    "sanitize_feedback_evaluation_reference",
    "sanitize_feedback_collaboration_reference",
    "sanitize_research_feedback_event",
    "ResearchFeedbackEventPlan",
    "research_feedback_event_plan_projection",
]
