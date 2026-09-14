"""Calibration recommendation schema (Stage R57.3).

Defines the bounded, deterministic advisory calibration recommendation
derived from one learning pattern. It answers:

    "What should future research calibrate or review, without changing
     behavior automatically?"

Hard boundaries encoded here:

- Advisory only: a recommendation never modifies agents, specialist logic,
  rules, scoring formulas, thresholds, prompts, models, orchestration
  policies or strategies. ``auto_applies``, ``modifies_agents``,
  ``modifies_rules``, ``modifies_thresholds`` and ``modifies_strategies``
  are forced ``False``.
- No execution: no execution authorization, no exploitation guidance, no
  payload generation, no attack planning and no vulnerability confirmation.
  ``execution_authorized`` is forced ``False`` and human authority and the
  safety boundary are declared preserved.
- Human decisions remain workflow feedback, never truth labels.
- Closed vocabularies; bounded, privacy-safe, JSON serializable; no
  timestamps, UUIDs, pids or randomness.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.continuous_learning import (
    CONFIDENCE_LEVELS,
    EVIDENCE_STRENGTHS,
    MAX_LIST,
    sanitize_learning_reference as _sanitize_learning_reference,
)
from ai.schemas.finding_result import sanitize_finding_governance
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

CALIBRATION_RECOMMENDATION_RULE_VERSION = "r57-3"
RULE_VERSION = CALIBRATION_RECOMMENDATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Recommendation vocabulary (closed)
# ---------------------------------------------------------------------------

CALIB_REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"
CALIB_INCREASE_CONTEXT_COLLECTION = "INCREASE_CONTEXT_COLLECTION"
CALIB_REDUCE_CONFIDENCE = "REDUCE_CONFIDENCE"
CALIB_REVIEW_CONFIDENCE_CALIBRATION = "REVIEW_CONFIDENCE_CALIBRATION"
CALIB_REVIEW_HYPOTHESIS = "REVIEW_HYPOTHESIS"
CALIB_REVIEW_DUPLICATION = "REVIEW_DUPLICATION"
CALIB_REVIEW_CONFLICT = "REVIEW_CONFLICT"
CALIB_REVIEW_GOVERNANCE = "REVIEW_GOVERNANCE"
CALIB_REVIEW_PROVENANCE = "REVIEW_PROVENANCE"
CALIB_REVIEW_SAFETY_BOUNDARY = "REVIEW_SAFETY_BOUNDARY"
CALIB_PRESERVE_SUCCESS_PATTERN = "PRESERVE_SUCCESS_PATTERN"
CALIB_REVIEW_HUMAN_FEEDBACK = "REVIEW_HUMAN_FEEDBACK"
CALIB_REVIEW_PRIORITY_ALIGNMENT = "REVIEW_PRIORITY_ALIGNMENT"
CALIB_REVIEW_RESEARCH_QUALITY = "REVIEW_RESEARCH_QUALITY"
CALIB_REVIEW_SPECIALIST_RELIABILITY = "REVIEW_SPECIALIST_RELIABILITY"

CALIBRATION_RECOMMENDATION_CODES: tuple[str, ...] = (
    CALIB_REQUEST_MORE_EVIDENCE,
    CALIB_INCREASE_CONTEXT_COLLECTION,
    CALIB_REDUCE_CONFIDENCE,
    CALIB_REVIEW_CONFIDENCE_CALIBRATION,
    CALIB_REVIEW_HYPOTHESIS,
    CALIB_REVIEW_DUPLICATION,
    CALIB_REVIEW_CONFLICT,
    CALIB_REVIEW_GOVERNANCE,
    CALIB_REVIEW_PROVENANCE,
    CALIB_REVIEW_SAFETY_BOUNDARY,
    CALIB_PRESERVE_SUCCESS_PATTERN,
    CALIB_REVIEW_HUMAN_FEEDBACK,
    CALIB_REVIEW_PRIORITY_ALIGNMENT,
    CALIB_REVIEW_RESEARCH_QUALITY,
    CALIB_REVIEW_SPECIALIST_RELIABILITY,
)

RECOMMENDATION_ORDER: dict[str, int] = {
    code: index
    for index, code in enumerate(CALIBRATION_RECOMMENDATION_CODES)
}

# ---------------------------------------------------------------------------
# Target-scope vocabulary (closed)
# ---------------------------------------------------------------------------

SCOPE_CATEGORY = "CATEGORY"
SCOPE_SPECIALIST = "SPECIALIST"
SCOPE_WORKFLOW = "WORKFLOW"
SCOPE_GOVERNANCE = "GOVERNANCE"
SCOPE_PROVENANCE = "PROVENANCE"
SCOPE_SAFETY = "SAFETY"
SCOPE_PRIORITY = "PRIORITY"
SCOPE_QUALITY = "QUALITY"

TARGET_SCOPES: tuple[str, ...] = (
    SCOPE_CATEGORY,
    SCOPE_SPECIALIST,
    SCOPE_WORKFLOW,
    SCOPE_GOVERNANCE,
    SCOPE_PROVENANCE,
    SCOPE_SAFETY,
    SCOPE_PRIORITY,
    SCOPE_QUALITY,
)

# ---------------------------------------------------------------------------
# Rationale vocabulary (closed)
# ---------------------------------------------------------------------------

RATIONALE_RECURRING_OBSERVATION = "RECURRING_OBSERVATION"
RATIONALE_CROSS_LAYER_CORROBORATION = "CROSS_LAYER_CORROBORATION"
RATIONALE_RECURRENCE_COUNT = "RECURRENCE_COUNT"
RATIONALE_HUMAN_WORKFLOW_FEEDBACK = "HUMAN_WORKFLOW_FEEDBACK"
RATIONALE_HUMAN_DECISION_NOT_TRUTH_LABEL = (
    "HUMAN_DECISION_NOT_TRUTH_LABEL"
)
RATIONALE_SAFETY_BOUNDARY = "SAFETY_BOUNDARY"
RATIONALE_SUCCESS_PATTERN = "SUCCESS_PATTERN"
RATIONALE_PRIORITY_ALIGNMENT = "PRIORITY_ALIGNMENT"
RATIONALE_SPECIALIST_RELIABILITY = "SPECIALIST_RELIABILITY"
RATIONALE_EVIDENCE_GAP = "EVIDENCE_GAP"
RATIONALE_GOVERNANCE_PRESERVED = "GOVERNANCE_PRESERVED"
RATIONALE_LIMITED_SUPPORT = "LIMITED_SUPPORT"

CALIBRATION_RATIONALES: tuple[str, ...] = (
    RATIONALE_RECURRING_OBSERVATION,
    RATIONALE_CROSS_LAYER_CORROBORATION,
    RATIONALE_RECURRENCE_COUNT,
    RATIONALE_HUMAN_WORKFLOW_FEEDBACK,
    RATIONALE_HUMAN_DECISION_NOT_TRUTH_LABEL,
    RATIONALE_SAFETY_BOUNDARY,
    RATIONALE_SUCCESS_PATTERN,
    RATIONALE_PRIORITY_ALIGNMENT,
    RATIONALE_SPECIALIST_RELIABILITY,
    RATIONALE_EVIDENCE_GAP,
    RATIONALE_GOVERNANCE_PRESERVED,
    RATIONALE_LIMITED_SUPPORT,
)

# ---------------------------------------------------------------------------
# Limitation vocabulary (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_NO_AGENT_MODIFICATION = "NO_AGENT_MODIFICATION"
LIMITATION_NO_RULE_MODIFICATION = "NO_RULE_MODIFICATION"
LIMITATION_NO_THRESHOLD_MODIFICATION = "NO_THRESHOLD_MODIFICATION"
LIMITATION_NO_STRATEGY_MODIFICATION = "NO_STRATEGY_MODIFICATION"
LIMITATION_NO_AUTOMATIC_BEHAVIOR_CHANGE = "NO_AUTOMATIC_BEHAVIOR_CHANGE"
LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL = (
    "HUMAN_DECISION_NOT_TRUTH_LABEL"
)
LIMITATION_NO_CAUSALITY_CLAIM = "NO_CAUSALITY_CLAIM"
LIMITATION_CORRELATION_NOT_CAUSALITY = "CORRELATION_NOT_CAUSALITY"
LIMITATION_FUTURE_STAGE_REQUIRED = "FUTURE_STAGE_REQUIRED"
LIMITATION_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
LIMITATION_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"

CALIBRATION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_NO_AGENT_MODIFICATION,
    LIMITATION_NO_RULE_MODIFICATION,
    LIMITATION_NO_THRESHOLD_MODIFICATION,
    LIMITATION_NO_STRATEGY_MODIFICATION,
    LIMITATION_NO_AUTOMATIC_BEHAVIOR_CHANGE,
    LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL,
    LIMITATION_NO_CAUSALITY_CLAIM,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
    LIMITATION_FUTURE_STAGE_REQUIRED,
    LIMITATION_HUMAN_REVIEW_REQUIRED,
    LIMITATION_INSUFFICIENT_DATA,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_PROVENANCE_INCOMPLETE,
)

RECOMMENDATION_ID_PREFIX = "clc-"
RECOMMENDATION_ID_RE = re.compile(r"^clc-[0-9a-f]{16}$")

MAX_RECOMMENDATIONS = 24
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_ids(value: object, limit: int, pattern: str) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if re.match(pattern, text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _ordered_codes(codes: object, allowed: tuple, limit: int) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in allowed:
            found.add(text)
    return [code for code in allowed if code in found][:limit]


def _ordered_limitations(codes: object) -> list[str]:
    return _ordered_codes(
        codes, CALIBRATION_LIMITATIONS, len(CALIBRATION_LIMITATIONS)
    )


def sanitize_calibration_recommendation(value: object) -> dict:
    """Project a calibration recommendation onto its fixed bounded keys."""

    if not isinstance(value, dict):
        return _default_recommendation()
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "recommendation_id": _safe_text(value.get("recommendation_id")),
        "recommendation_code": _closed(
            value.get("recommendation_code"),
            CALIBRATION_RECOMMENDATION_CODES,
            "",
        ),
        "target_scope": _closed(
            value.get("target_scope"), TARGET_SCOPES, SCOPE_CATEGORY
        ),
        "category": category,
        "specialist_name": _safe_text(value.get("specialist_name")),
        "pattern_id": _safe_text(value.get("pattern_id")),
        "supporting_pattern_ids": _bounded_ids(
            value.get("supporting_pattern_ids"), MAX_LIST,
            r"^clp-[0-9a-f]{16}$",
        ),
        "supporting_signal_ids": _bounded_ids(
            value.get("supporting_signal_ids"), MAX_LIST,
            r"^cls-[0-9a-f]{16}$",
        ),
        "recommendation_rank": _bounded_int(
            value.get("recommendation_rank"), 0, MAX_RECOMMENDATIONS
        ),
        "rationale_codes": _ordered_codes(
            value.get("rationale_codes"),
            CALIBRATION_RATIONALES,
            len(CALIBRATION_RATIONALES),
        ),
        "evidence_strength": _closed(
            value.get("evidence_strength"),
            EVIDENCE_STRENGTHS,
            "WEAK",
        ),
        "confidence": _closed(
            value.get("confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "human_feedback_basis": (
            bool(value.get("human_feedback_basis")) is True
        ),
        "advisory": True,
        "auto_applies": False,
        "modifies_agents": False,
        "modifies_rules": False,
        "modifies_thresholds": False,
        "modifies_strategies": False,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "safety_boundary_preserved": True,
        "human_authority_preserved": True,
        "provenance": _sanitize_learning_reference(value.get("provenance")),
        "governance": sanitize_finding_governance(value.get("governance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "research_only": True,
        "deterministic": True,
    }


def _default_recommendation() -> dict:
    return {
        "rule_version": "",
        "recommendation_id": "",
        "recommendation_code": "",
        "target_scope": SCOPE_CATEGORY,
        "category": "UNKNOWN",
        "specialist_name": "",
        "pattern_id": "",
        "supporting_pattern_ids": [],
        "supporting_signal_ids": [],
        "recommendation_rank": 0,
        "rationale_codes": [],
        "evidence_strength": "WEAK",
        "confidence": "UNKNOWN",
        "human_feedback_basis": False,
        "advisory": True,
        "auto_applies": False,
        "modifies_agents": False,
        "modifies_rules": False,
        "modifies_thresholds": False,
        "modifies_strategies": False,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "safety_boundary_preserved": True,
        "human_authority_preserved": True,
        "provenance": _sanitize_learning_reference(None),
        "governance": sanitize_finding_governance(None),
        "limitations": [],
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CalibrationRecommendationPlan(BaseModel):
    """Deterministic advisory calibration recommendation (R57.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = CALIBRATION_RECOMMENDATION_RULE_VERSION
    recommendation_id: str
    recommendation_code: str
    target_scope: str = SCOPE_CATEGORY
    category: str = "UNKNOWN"
    specialist_name: str = ""
    pattern_id: str = ""
    supporting_pattern_ids: list[str] = Field(default_factory=list)
    supporting_signal_ids: list[str] = Field(default_factory=list)
    recommendation_rank: int = 0
    rationale_codes: list[str] = Field(default_factory=list)
    evidence_strength: str = "WEAK"
    confidence: str = "UNKNOWN"
    human_feedback_basis: bool = False
    advisory: bool = True
    auto_applies: bool = False
    modifies_agents: bool = False
    modifies_rules: bool = False
    modifies_thresholds: bool = False
    modifies_strategies: bool = False
    execution_authorized: bool = False
    vulnerability_confirmed: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    safety_boundary_preserved: bool = True
    human_authority_preserved: bool = True
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return CALIBRATION_RECOMMENDATION_RULE_VERSION

    @field_validator("recommendation_id")
    @classmethod
    def _valid_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not RECOMMENDATION_ID_RE.match(text):
            raise ValueError(f"malformed recommendation_id: {value!r}")
        return text

    @field_validator("recommendation_code")
    @classmethod
    def _valid_code(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CALIBRATION_RECOMMENDATION_CODES:
            raise ValueError(f"invalid recommendation_code: {value!r}")
        return text

    @field_validator("target_scope")
    @classmethod
    def _valid_scope(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TARGET_SCOPES:
            raise ValueError(f"invalid target_scope: {value!r}")
        return text

    @field_validator("category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid category: {value!r}")
        return text

    @field_validator("rationale_codes")
    @classmethod
    def _valid_rationales(cls, value: object) -> list[str]:
        return _ordered_codes(
            value, CALIBRATION_RATIONALES, len(CALIBRATION_RATIONALES)
        )

    @field_validator("evidence_strength")
    @classmethod
    def _valid_strength(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_STRENGTHS:
            raise ValueError(f"invalid evidence_strength: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("advisory", "safety_boundary_preserved",
                     "human_authority_preserved", "research_only",
                     "deterministic")
    @classmethod
    def _true_flags(cls, value: object) -> bool:
        if value is not True:
            raise ValueError(
                "calibration recommendations are advisory research-only"
            )
        return True

    @field_validator(
        "auto_applies",
        "modifies_agents",
        "modifies_rules",
        "modifies_thresholds",
        "modifies_strategies",
        "execution_authorized",
        "vulnerability_confirmed",
    )
    @classmethod
    def _false_flags(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "calibration recommendations never change behavior or "
                "authorize execution"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError(
                "calibration recommendations never confirm a vulnerability"
            )
        return "NOT_CONFIRMED"

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return _sanitize_learning_reference(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_finding_governance(value)


def calibration_recommendation_plan_projection(
    value: CalibrationRecommendationPlan,
) -> dict:
    """Serialize a calibration recommendation to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "CALIBRATION_RECOMMENDATION_RULE_VERSION",
    "RULE_VERSION",
    "CALIBRATION_RECOMMENDATION_CODES",
    "RECOMMENDATION_ORDER",
    "TARGET_SCOPES",
    "CALIBRATION_RATIONALES",
    "CALIBRATION_LIMITATIONS",
    "RECOMMENDATION_ID_PREFIX",
    "RECOMMENDATION_ID_RE",
    "MAX_RECOMMENDATIONS",
    "MAX_VALUE_LEN",
    "CALIB_REQUEST_MORE_EVIDENCE",
    "CALIB_INCREASE_CONTEXT_COLLECTION",
    "CALIB_REDUCE_CONFIDENCE",
    "CALIB_REVIEW_CONFIDENCE_CALIBRATION",
    "CALIB_REVIEW_HYPOTHESIS",
    "CALIB_REVIEW_DUPLICATION",
    "CALIB_REVIEW_CONFLICT",
    "CALIB_REVIEW_GOVERNANCE",
    "CALIB_REVIEW_PROVENANCE",
    "CALIB_REVIEW_SAFETY_BOUNDARY",
    "CALIB_PRESERVE_SUCCESS_PATTERN",
    "CALIB_REVIEW_HUMAN_FEEDBACK",
    "CALIB_REVIEW_PRIORITY_ALIGNMENT",
    "CALIB_REVIEW_RESEARCH_QUALITY",
    "CALIB_REVIEW_SPECIALIST_RELIABILITY",
    "SCOPE_CATEGORY",
    "SCOPE_SPECIALIST",
    "SCOPE_WORKFLOW",
    "SCOPE_GOVERNANCE",
    "SCOPE_PROVENANCE",
    "SCOPE_SAFETY",
    "SCOPE_PRIORITY",
    "SCOPE_QUALITY",
    "RATIONALE_RECURRING_OBSERVATION",
    "RATIONALE_CROSS_LAYER_CORROBORATION",
    "RATIONALE_RECURRENCE_COUNT",
    "RATIONALE_HUMAN_WORKFLOW_FEEDBACK",
    "RATIONALE_HUMAN_DECISION_NOT_TRUTH_LABEL",
    "RATIONALE_SAFETY_BOUNDARY",
    "RATIONALE_SUCCESS_PATTERN",
    "RATIONALE_PRIORITY_ALIGNMENT",
    "RATIONALE_SPECIALIST_RELIABILITY",
    "RATIONALE_EVIDENCE_GAP",
    "RATIONALE_GOVERNANCE_PRESERVED",
    "RATIONALE_LIMITED_SUPPORT",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_ADVISORY_ONLY",
    "LIMITATION_NO_AGENT_MODIFICATION",
    "LIMITATION_NO_RULE_MODIFICATION",
    "LIMITATION_NO_THRESHOLD_MODIFICATION",
    "LIMITATION_NO_STRATEGY_MODIFICATION",
    "LIMITATION_NO_AUTOMATIC_BEHAVIOR_CHANGE",
    "LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL",
    "LIMITATION_NO_CAUSALITY_CLAIM",
    "LIMITATION_CORRELATION_NOT_CAUSALITY",
    "LIMITATION_FUTURE_STAGE_REQUIRED",
    "LIMITATION_HUMAN_REVIEW_REQUIRED",
    "LIMITATION_INSUFFICIENT_DATA",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_PROVENANCE_INCOMPLETE",
    "sanitize_calibration_recommendation",
    "CalibrationRecommendationPlan",
    "calibration_recommendation_plan_projection",
]
