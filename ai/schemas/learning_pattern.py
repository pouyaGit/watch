"""Learning pattern schema (Stage R57.2).

Defines the bounded, deterministic continuous-learning pattern: a
conservative aggregation of compatible continuous-learning signals. It
answers:

    "Which recurring structured observation can be explained from the
     accumulated research outcomes?"

Hard boundaries encoded here:

- Advisory only: a pattern is an explainable aggregation. It never claims
  causality, never modifies agents/rules/thresholds/strategies and never
  executes anything. ``auto_applies`` and the ``modifies_*`` flags are
  forced ``False``.
- Conservative: a pattern is only emitted when supported by structured
  evidence (recurrence or cross-layer corroboration); compatibility is a
  closed family mapping, not a semantic guess.
- Human decisions stay workflow feedback: patterns aggregating R56 decisions
  force ``feedback_kind`` context and preserve the human authority context;
  they are never truth labels.
- Provenance and governance are preserved references, never fabricated.
- Closed vocabularies; bounded, privacy-safe, JSON serializable; no
  timestamps, UUIDs, pids or randomness.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.calibration_recommendation import (
    CALIBRATION_RECOMMENDATION_CODES,
)
from ai.schemas.continuous_learning import (
    CONFIDENCE_LEVELS,
    EVIDENCE_STRENGTHS,
    MAX_LIST,
    _ordered_limitations,
)
from ai.schemas.continuous_learning import (
    sanitize_decision_context as _sanitize_decision_context,
)
from ai.schemas.finding_result import sanitize_finding_governance
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

LEARNING_PATTERN_RULE_VERSION = "r57-2"
RULE_VERSION = LEARNING_PATTERN_RULE_VERSION

# ---------------------------------------------------------------------------
# Pattern type vocabulary (closed families)
# ---------------------------------------------------------------------------

PATTERN_EVIDENCE_GAP = "EVIDENCE_GAP_PATTERN"
PATTERN_CONTEXT_GAP = "CONTEXT_GAP_PATTERN"
PATTERN_HYPOTHESIS_WEAKNESS = "HYPOTHESIS_WEAKNESS_PATTERN"
PATTERN_CONFIDENCE_CALIBRATION = "CONFIDENCE_CALIBRATION_PATTERN"
PATTERN_DUPLICATION = "DUPLICATION_PATTERN"
PATTERN_CONFLICT = "CONFLICT_PATTERN"
PATTERN_GOVERNANCE = "GOVERNANCE_PATTERN"
PATTERN_PROVENANCE = "PROVENANCE_PATTERN"
PATTERN_SAFETY = "SAFETY_PATTERN"
PATTERN_QUALITY = "QUALITY_PATTERN"
PATTERN_SUCCESS = "SUCCESS_PATTERN"
PATTERN_WORKFLOW_FEEDBACK = "WORKFLOW_FEEDBACK_PATTERN"
PATTERN_PRIORITY_ALIGNMENT = "PRIORITY_ALIGNMENT_PATTERN"
PATTERN_SPECIALIST_RELIABILITY = "SPECIALIST_RELIABILITY_PATTERN"

LEARNING_PATTERN_TYPES: tuple[str, ...] = (
    PATTERN_EVIDENCE_GAP,
    PATTERN_CONTEXT_GAP,
    PATTERN_HYPOTHESIS_WEAKNESS,
    PATTERN_CONFIDENCE_CALIBRATION,
    PATTERN_DUPLICATION,
    PATTERN_CONFLICT,
    PATTERN_GOVERNANCE,
    PATTERN_PROVENANCE,
    PATTERN_SAFETY,
    PATTERN_QUALITY,
    PATTERN_SUCCESS,
    PATTERN_WORKFLOW_FEEDBACK,
    PATTERN_PRIORITY_ALIGNMENT,
    PATTERN_SPECIALIST_RELIABILITY,
)

PATTERN_TYPE_ORDER: dict[str, int] = {
    pattern_type: index
    for index, pattern_type in enumerate(LEARNING_PATTERN_TYPES)
}

# ---------------------------------------------------------------------------
# Calibration indicator vocabulary (closed)
# ---------------------------------------------------------------------------

INDICATOR_EVIDENCE_GAP_RECURRING = "EVIDENCE_GAP_RECURRING"
INDICATOR_CONTEXT_GAP_RECURRING = "CONTEXT_GAP_RECURRING"
INDICATOR_HYPOTHESIS_WEAKNESS_RECURRING = "HYPOTHESIS_WEAKNESS_RECURRING"
INDICATOR_CONFIDENCE_OVERESTIMATION = "CONFIDENCE_OVERESTIMATION"
INDICATOR_CONFIDENCE_UNDERESTIMATION = "CONFIDENCE_UNDERESTIMATION"
INDICATOR_CONFIDENCE_MIXED = "CONFIDENCE_CALIBRATION_MIXED"
INDICATOR_DUPLICATION_OVERLAP = "DUPLICATION_OVERLAP"
INDICATOR_CONFLICT_RECURRENCE = "CONFLICT_RECURRENCE"
INDICATOR_GOVERNANCE_RECURRENCE = "GOVERNANCE_RECURRENCE"
INDICATOR_PROVENANCE_RECURRENCE = "PROVENANCE_RECURRENCE"
INDICATOR_SAFETY_RECURRENCE = "SAFETY_RECURRENCE"
INDICATOR_QUALITY_RECURRENCE = "QUALITY_RECURRENCE"
INDICATOR_SUCCESS_PATTERN = "SUCCESS_PATTERN"
INDICATOR_WORKFLOW_FEEDBACK_PATTERN = "WORKFLOW_FEEDBACK_PATTERN"
INDICATOR_PRIORITY_MISALIGNMENT = "PRIORITY_MISALIGNMENT"
INDICATOR_SPECIALIST_RELIABILITY = "SPECIALIST_RELIABILITY"
INDICATOR_UNKNOWN = "UNKNOWN"

CALIBRATION_INDICATORS: tuple[str, ...] = (
    INDICATOR_EVIDENCE_GAP_RECURRING,
    INDICATOR_CONTEXT_GAP_RECURRING,
    INDICATOR_HYPOTHESIS_WEAKNESS_RECURRING,
    INDICATOR_CONFIDENCE_OVERESTIMATION,
    INDICATOR_CONFIDENCE_UNDERESTIMATION,
    INDICATOR_CONFIDENCE_MIXED,
    INDICATOR_DUPLICATION_OVERLAP,
    INDICATOR_CONFLICT_RECURRENCE,
    INDICATOR_GOVERNANCE_RECURRENCE,
    INDICATOR_PROVENANCE_RECURRENCE,
    INDICATOR_SAFETY_RECURRENCE,
    INDICATOR_QUALITY_RECURRENCE,
    INDICATOR_SUCCESS_PATTERN,
    INDICATOR_WORKFLOW_FEEDBACK_PATTERN,
    INDICATOR_PRIORITY_MISALIGNMENT,
    INDICATOR_SPECIALIST_RELIABILITY,
    INDICATOR_UNKNOWN,
)

PATTERN_ID_PREFIX = "clp-"
PATTERN_ID_RE = re.compile(r"^clp-[0-9a-f]{16}$")

MAX_PATTERNS = 24
MAX_MEMBERS = 64
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


def _bounded_ids(value: object, limit: int, pattern: str) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if re.match(pattern, text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
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


def sanitize_pattern_provenance(value: object) -> dict:
    """Project aggregate pattern provenance onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "prioritization_ids": [],
            "correlation_ids": [],
            "orchestration_ids": [],
            "finding_rule_versions": [],
            "priority_rule_versions": [],
            "decision_rule_versions": [],
            "research_only": True,
        }
    return {
        "prioritization_ids": _bounded_strings(
            value.get("prioritization_ids"), MAX_LIST, 80
        ),
        "correlation_ids": _bounded_strings(
            value.get("correlation_ids"), MAX_LIST, 80
        ),
        "orchestration_ids": _bounded_strings(
            value.get("orchestration_ids"), MAX_LIST, 80
        ),
        "finding_rule_versions": _bounded_strings(
            value.get("finding_rule_versions"), MAX_LIST, 40
        ),
        "priority_rule_versions": _bounded_strings(
            value.get("priority_rule_versions"), MAX_LIST, 40
        ),
        "decision_rule_versions": _bounded_strings(
            value.get("decision_rule_versions"), MAX_LIST, 40
        ),
        "research_only": True,
    }


def sanitize_learning_pattern(value: object) -> dict:
    """Project a learning pattern onto its fixed bounded keys."""

    if not isinstance(value, dict):
        return _default_pattern()
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    decision_types = _bounded_strings(
        value.get("supporting_decision_types"), MAX_LIST, 60
    )
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "pattern_id": _safe_text(value.get("pattern_id")),
        "pattern_type": _closed(
            value.get("pattern_type"), LEARNING_PATTERN_TYPES, ""
        ),
        "source_layers": _bounded_strings(
            value.get("source_layers"), 7, 40
        ),
        "category": category,
        "specialist_name": _safe_text(value.get("specialist_name")),
        "agent_id": _safe_text(value.get("agent_id")),
        "frequency": _bounded_int(value.get("frequency"), 0, MAX_MEMBERS),
        "cross_layer_support": _bounded_int(
            value.get("cross_layer_support"), 0, 7
        ),
        "supporting_signal_ids": _bounded_ids(
            value.get("supporting_signal_ids"), MAX_MEMBERS, r"^cls-[0-9a-f]{16}$"
        ),
        "supporting_finding_ids": _bounded_ids(
            value.get("supporting_finding_ids"), MAX_LIST, r"^fnd-[0-9a-f]{16}$"
        ),
        "supporting_decision_ids": _bounded_ids(
            value.get("supporting_decision_ids"), MAX_LIST, r"^hdc-[0-9a-f]{16}$"
        ),
        "supporting_decision_types": decision_types,
        "calibration_indicator": _closed(
            value.get("calibration_indicator"),
            CALIBRATION_INDICATORS,
            INDICATOR_UNKNOWN,
        ),
        "calibration_recommendation_codes": _ordered_codes(
            value.get("calibration_recommendation_codes"),
            CALIBRATION_RECOMMENDATION_CODES,
            MAX_LIST,
        ),
        "evidence_strength": _closed(
            value.get("evidence_strength"),
            EVIDENCE_STRENGTHS,
            "WEAK",
        ),
        "confidence": _closed(
            value.get("confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "decision_context": _sanitize_decision_context(
            value.get("decision_context")
        ),
        "provenance": sanitize_pattern_provenance(value.get("provenance")),
        "governance": sanitize_finding_governance(value.get("governance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "advisory": True,
        "auto_applies": False,
        "modifies_agents": False,
        "modifies_rules": False,
        "research_only": True,
        "deterministic": True,
    }


def _default_pattern() -> dict:
    return {
        "rule_version": "",
        "pattern_id": "",
        "pattern_type": "",
        "source_layers": [],
        "category": "UNKNOWN",
        "specialist_name": "",
        "agent_id": "",
        "frequency": 0,
        "cross_layer_support": 0,
        "supporting_signal_ids": [],
        "supporting_finding_ids": [],
        "supporting_decision_ids": [],
        "supporting_decision_types": [],
        "calibration_indicator": INDICATOR_UNKNOWN,
        "calibration_recommendation_codes": [],
        "evidence_strength": "WEAK",
        "confidence": "UNKNOWN",
        "decision_context": _sanitize_decision_context(None),
        "provenance": sanitize_pattern_provenance(None),
        "governance": sanitize_finding_governance(None),
        "limitations": [],
        "advisory": True,
        "auto_applies": False,
        "modifies_agents": False,
        "modifies_rules": False,
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class LearningPatternPlan(BaseModel):
    """Deterministic conservative learning pattern (R57.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LEARNING_PATTERN_RULE_VERSION
    pattern_id: str
    pattern_type: str
    source_layers: list[str] = Field(default_factory=list)
    category: str = "UNKNOWN"
    specialist_name: str = ""
    agent_id: str = ""
    frequency: int = 0
    cross_layer_support: int = 0
    supporting_signal_ids: list[str] = Field(default_factory=list)
    supporting_finding_ids: list[str] = Field(default_factory=list)
    supporting_decision_ids: list[str] = Field(default_factory=list)
    supporting_decision_types: list[str] = Field(default_factory=list)
    calibration_indicator: str = INDICATOR_UNKNOWN
    calibration_recommendation_codes: list[str] = Field(
        default_factory=list
    )
    evidence_strength: str = "WEAK"
    confidence: str = "UNKNOWN"
    decision_context: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    advisory: bool = True
    auto_applies: bool = False
    modifies_agents: bool = False
    modifies_rules: bool = False
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LEARNING_PATTERN_RULE_VERSION

    @field_validator("pattern_id")
    @classmethod
    def _valid_pattern_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not PATTERN_ID_RE.match(text):
            raise ValueError(f"malformed pattern_id: {value!r}")
        return text

    @field_validator("pattern_type")
    @classmethod
    def _valid_pattern_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in LEARNING_PATTERN_TYPES:
            raise ValueError(f"invalid pattern_type: {value!r}")
        return text

    @field_validator("category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid category: {value!r}")
        return text

    @field_validator("calibration_indicator")
    @classmethod
    def _valid_indicator(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CALIBRATION_INDICATORS:
            raise ValueError(f"invalid calibration_indicator: {value!r}")
        return text

    @field_validator("calibration_recommendation_codes")
    @classmethod
    def _valid_recommendations(cls, value: object) -> list[str]:
        return _ordered_codes(
            value, CALIBRATION_RECOMMENDATION_CODES, MAX_LIST
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

    @field_validator("decision_context")
    @classmethod
    def _bounded_decision_context(cls, value: object) -> dict:
        return _sanitize_decision_context(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_pattern_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_finding_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("advisory", "research_only", "deterministic")
    @classmethod
    def _true_flags(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("patterns are advisory research-only records")
        return True

    @field_validator(
        "auto_applies", "modifies_agents", "modifies_rules"
    )
    @classmethod
    def _false_flags(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("learning patterns never modify behavior")
        return False


def learning_pattern_plan_projection(value: LearningPatternPlan) -> dict:
    """Serialize a learning pattern to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LEARNING_PATTERN_RULE_VERSION",
    "RULE_VERSION",
    "LEARNING_PATTERN_TYPES",
    "PATTERN_TYPE_ORDER",
    "CALIBRATION_INDICATORS",
    "PATTERN_ID_PREFIX",
    "PATTERN_ID_RE",
    "MAX_PATTERNS",
    "MAX_MEMBERS",
    "MAX_VALUE_LEN",
    "PATTERN_EVIDENCE_GAP",
    "PATTERN_CONTEXT_GAP",
    "PATTERN_HYPOTHESIS_WEAKNESS",
    "PATTERN_CONFIDENCE_CALIBRATION",
    "PATTERN_DUPLICATION",
    "PATTERN_CONFLICT",
    "PATTERN_GOVERNANCE",
    "PATTERN_PROVENANCE",
    "PATTERN_SAFETY",
    "PATTERN_QUALITY",
    "PATTERN_SUCCESS",
    "PATTERN_WORKFLOW_FEEDBACK",
    "PATTERN_PRIORITY_ALIGNMENT",
    "PATTERN_SPECIALIST_RELIABILITY",
    "INDICATOR_EVIDENCE_GAP_RECURRING",
    "INDICATOR_CONTEXT_GAP_RECURRING",
    "INDICATOR_HYPOTHESIS_WEAKNESS_RECURRING",
    "INDICATOR_CONFIDENCE_OVERESTIMATION",
    "INDICATOR_CONFIDENCE_UNDERESTIMATION",
    "INDICATOR_CONFIDENCE_MIXED",
    "INDICATOR_DUPLICATION_OVERLAP",
    "INDICATOR_CONFLICT_RECURRENCE",
    "INDICATOR_GOVERNANCE_RECURRENCE",
    "INDICATOR_PROVENANCE_RECURRENCE",
    "INDICATOR_SAFETY_RECURRENCE",
    "INDICATOR_QUALITY_RECURRENCE",
    "INDICATOR_SUCCESS_PATTERN",
    "INDICATOR_WORKFLOW_FEEDBACK_PATTERN",
    "INDICATOR_PRIORITY_MISALIGNMENT",
    "INDICATOR_SPECIALIST_RELIABILITY",
    "INDICATOR_UNKNOWN",
    "sanitize_pattern_provenance",
    "sanitize_learning_pattern",
    "LearningPatternPlan",
    "learning_pattern_plan_projection",
]
