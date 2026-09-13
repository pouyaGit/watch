"""Research feedback classification schema (Stage R44.2).

A :class:`ResearchFeedbackClassificationPlan` is the deterministic
classification of one feedback event. It answers:

    "What kind of learning does this structured research outcome suggest?"

Hard boundaries encoded here:

- Learning only: classification operates on structured signals only. No LLM,
  no semantic inference beyond structured indicators, no execution, no
  network, no database, no browser, no payloads.
- Closed classification, reason, signal and limitation vocabularies.
- Classification is advisory; it never modifies agents, rules or runtime
  behavior.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

RESEARCH_FEEDBACK_CLASSIFICATION_RULE_VERSION = "r44-2"
RULE_VERSION = RESEARCH_FEEDBACK_CLASSIFICATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed classification vocabulary
# ---------------------------------------------------------------------------

CLASSIFICATION_QUALITY_IMPROVEMENT = "QUALITY_IMPROVEMENT"
CLASSIFICATION_CONFIDENCE_CALIBRATION = "CONFIDENCE_CALIBRATION"
CLASSIFICATION_EVIDENCE_GAP = "EVIDENCE_GAP"
CLASSIFICATION_HYPOTHESIS_WEAKNESS = "HYPOTHESIS_WEAKNESS"
CLASSIFICATION_DUPLICATION_PATTERN = "DUPLICATION_PATTERN"
CLASSIFICATION_CONFLICT_PATTERN = "CONFLICT_PATTERN"
CLASSIFICATION_GOVERNANCE_ISSUE = "GOVERNANCE_ISSUE"
CLASSIFICATION_PROVENANCE_ISSUE = "PROVENANCE_ISSUE"
CLASSIFICATION_SAFETY_ISSUE = "SAFETY_ISSUE"
CLASSIFICATION_SUCCESS_PATTERN = "SUCCESS_PATTERN"
CLASSIFICATION_UNKNOWN = "UNKNOWN"

CLASSIFICATIONS: tuple[str, ...] = (
    CLASSIFICATION_QUALITY_IMPROVEMENT,
    CLASSIFICATION_CONFIDENCE_CALIBRATION,
    CLASSIFICATION_EVIDENCE_GAP,
    CLASSIFICATION_HYPOTHESIS_WEAKNESS,
    CLASSIFICATION_DUPLICATION_PATTERN,
    CLASSIFICATION_CONFLICT_PATTERN,
    CLASSIFICATION_GOVERNANCE_ISSUE,
    CLASSIFICATION_PROVENANCE_ISSUE,
    CLASSIFICATION_SAFETY_ISSUE,
    CLASSIFICATION_SUCCESS_PATTERN,
    CLASSIFICATION_UNKNOWN,
)

CLASSIFICATION_ORDER: dict[str, int] = {
    classification: index
    for index, classification in enumerate(CLASSIFICATIONS)
}

# ---------------------------------------------------------------------------
# Closed reason and supporting-signal vocabularies
# ---------------------------------------------------------------------------

REASON_SAFETY_STATE_FAILED = "SAFETY_STATE_FAILED"
REASON_HARD_GATE_FAIL_SAFETY = "HARD_GATE_FAIL_SAFETY"
REASON_FORBIDDEN_CLAIM = "FORBIDDEN_CLAIM"
REASON_RESEARCH_ONLY_FALSE = "RESEARCH_ONLY_FALSE"
REASON_SAFETY_LIMITATION_MISSING = "SAFETY_LIMITATION_MISSING"
REASON_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
REASON_GOVERNANCE_INCONSISTENT = "GOVERNANCE_INCONSISTENT"
REASON_PROVENANCE_MISSING = "PROVENANCE_MISSING"
REASON_CONFLICTS_PRESENT = "CONFLICTS_PRESENT"
REASON_DUPLICATE_GROUPS = "DUPLICATE_GROUPS"
REASON_CONFIDENCE_MISCALIBRATION = "CONFIDENCE_MISCALIBRATION"
REASON_EVIDENCE_GAP = "EVIDENCE_GAP"
REASON_HYPOTHESIS_WEAKNESS = "HYPOTHESIS_WEAKNESS"
REASON_LOW_QUALITY = "LOW_QUALITY"
REASON_STRONG_EVALUATION = "STRONG_EVALUATION"
REASON_OBSERVED_ISSUE = "OBSERVED_ISSUE"
REASON_OBSERVED_SUCCESS = "OBSERVED_SUCCESS"
REASON_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"

CLASSIFICATION_REASONS: tuple[str, ...] = (
    REASON_SAFETY_STATE_FAILED,
    REASON_HARD_GATE_FAIL_SAFETY,
    REASON_FORBIDDEN_CLAIM,
    REASON_RESEARCH_ONLY_FALSE,
    REASON_SAFETY_LIMITATION_MISSING,
    REASON_GOVERNANCE_UNKNOWN,
    REASON_GOVERNANCE_INCONSISTENT,
    REASON_PROVENANCE_MISSING,
    REASON_CONFLICTS_PRESENT,
    REASON_DUPLICATE_GROUPS,
    REASON_CONFIDENCE_MISCALIBRATION,
    REASON_EVIDENCE_GAP,
    REASON_HYPOTHESIS_WEAKNESS,
    REASON_LOW_QUALITY,
    REASON_STRONG_EVALUATION,
    REASON_OBSERVED_ISSUE,
    REASON_OBSERVED_SUCCESS,
    REASON_INSUFFICIENT_DATA,
)

SIGNAL_EVALUATION_PRESENT = "EVALUATION_PRESENT"
SIGNAL_EVALUATION_SAFETY_STATE = "EVALUATION_SAFETY_STATE"
SIGNAL_EVALUATION_HARD_GATE = "EVALUATION_HARD_GATE"
SIGNAL_EVALUATION_DIAGNOSTIC = "EVALUATION_DIAGNOSTIC"
SIGNAL_EVALUATION_OVERALL_RATING = "EVALUATION_OVERALL_RATING"
SIGNAL_EVALUATION_DIMENSION_SCORE = "EVALUATION_DIMENSION_SCORE"
SIGNAL_COLLABORATION_CONFLICTS = "COLLABORATION_CONFLICTS"
SIGNAL_COLLABORATION_DUPLICATE_GROUPS = "COLLABORATION_DUPLICATE_GROUPS"
SIGNAL_COLLABORATION_EVIDENCE_STATE = "COLLABORATION_EVIDENCE_STATE"
SIGNAL_OBSERVED_ISSUE = "OBSERVED_ISSUE"
SIGNAL_OBSERVED_SUCCESS = "OBSERVED_SUCCESS"
SIGNAL_GOVERNANCE_STATE = "GOVERNANCE_STATE"
SIGNAL_PROVENANCE_STATE = "PROVENANCE_STATE"

CLASSIFICATION_SIGNALS: tuple[str, ...] = (
    SIGNAL_EVALUATION_PRESENT,
    SIGNAL_EVALUATION_SAFETY_STATE,
    SIGNAL_EVALUATION_HARD_GATE,
    SIGNAL_EVALUATION_DIAGNOSTIC,
    SIGNAL_EVALUATION_OVERALL_RATING,
    SIGNAL_EVALUATION_DIMENSION_SCORE,
    SIGNAL_COLLABORATION_CONFLICTS,
    SIGNAL_COLLABORATION_DUPLICATE_GROUPS,
    SIGNAL_COLLABORATION_EVIDENCE_STATE,
    SIGNAL_OBSERVED_ISSUE,
    SIGNAL_OBSERVED_SUCCESS,
    SIGNAL_GOVERNANCE_STATE,
    SIGNAL_PROVENANCE_STATE,
)

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_AGENT_MODIFICATION = "NO_AGENT_MODIFICATION"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"

CLASSIFICATION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_AGENT_MODIFICATION,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_INSUFFICIENT_DATA,
)

MAX_REASONS = 8
MAX_SIGNALS = 8
MAX_LIMITATIONS = 5
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _require_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if not text:
            continue
        if text not in allowed:
            raise ValueError(f"invalid closed code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_research_feedback_classification(value: object) -> dict:
    """Project a classification onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "classification": CLASSIFICATION_UNKNOWN,
            "subject": "UNKNOWN",
            "source_agent": "",
            "feedback_id": "",
            "reasons": [],
            "supporting_signals": [],
            "confidence": "UNKNOWN",
            "limitations": list(CLASSIFICATION_LIMITATIONS),
        }
    category = _safe_text(value.get("subject")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    limitations = [
        code
        for code in _bounded_codes(
            value.get("limitations"), CLASSIFICATION_LIMITATIONS,
            MAX_LIMITATIONS,
        )
    ]
    if not limitations:
        limitations = list(CLASSIFICATION_LIMITATIONS)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "classification": _safe_text(
            value.get("classification")
        ).strip().upper()
        if _safe_text(value.get("classification")).strip().upper()
        in CLASSIFICATIONS
        else CLASSIFICATION_UNKNOWN,
        "subject": category,
        "source_agent": _safe_text(value.get("source_agent")),
        "feedback_id": _safe_text(value.get("feedback_id")),
        "reasons": _bounded_codes(
            value.get("reasons"), CLASSIFICATION_REASONS, MAX_REASONS
        ),
        "supporting_signals": _bounded_codes(
            value.get("supporting_signals"),
            CLASSIFICATION_SIGNALS,
            MAX_SIGNALS,
        ),
        "confidence": confidence,
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchFeedbackClassificationPlan(BaseModel):
    """Deterministic feedback classification (R44.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_FEEDBACK_CLASSIFICATION_RULE_VERSION
    classification: str = CLASSIFICATION_UNKNOWN
    subject: str = "UNKNOWN"
    source_agent: str = ""
    feedback_id: str = ""
    reasons: list[str] = Field(default_factory=list)
    supporting_signals: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_FEEDBACK_CLASSIFICATION_RULE_VERSION

    @field_validator("classification")
    @classmethod
    def _valid_classification(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CLASSIFICATIONS:
            raise ValueError(f"invalid classification: {value!r}")
        return text

    @field_validator("subject")
    @classmethod
    def _valid_subject(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid subject: {value!r}")
        return text

    @field_validator("source_agent", "feedback_id")
    @classmethod
    def _bounded_text(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("reasons")
    @classmethod
    def _valid_reasons(cls, value: list) -> list[str]:
        return _require_codes(value, CLASSIFICATION_REASONS, MAX_REASONS)

    @field_validator("supporting_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _require_codes(
            value, CLASSIFICATION_SIGNALS, MAX_SIGNALS
        )

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
            value, CLASSIFICATION_LIMITATIONS, MAX_LIMITATIONS
        )


def research_feedback_classification_plan_projection(
    value: ResearchFeedbackClassificationPlan,
) -> dict:
    """Serialize a classification to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_FEEDBACK_CLASSIFICATION_RULE_VERSION",
    "RULE_VERSION",
    "CLASSIFICATIONS",
    "CLASSIFICATION_ORDER",
    "CLASSIFICATION_QUALITY_IMPROVEMENT",
    "CLASSIFICATION_CONFIDENCE_CALIBRATION",
    "CLASSIFICATION_EVIDENCE_GAP",
    "CLASSIFICATION_HYPOTHESIS_WEAKNESS",
    "CLASSIFICATION_DUPLICATION_PATTERN",
    "CLASSIFICATION_CONFLICT_PATTERN",
    "CLASSIFICATION_GOVERNANCE_ISSUE",
    "CLASSIFICATION_PROVENANCE_ISSUE",
    "CLASSIFICATION_SAFETY_ISSUE",
    "CLASSIFICATION_SUCCESS_PATTERN",
    "CLASSIFICATION_UNKNOWN",
    "CLASSIFICATION_REASONS",
    "REASON_SAFETY_STATE_FAILED",
    "REASON_HARD_GATE_FAIL_SAFETY",
    "REASON_FORBIDDEN_CLAIM",
    "REASON_RESEARCH_ONLY_FALSE",
    "REASON_SAFETY_LIMITATION_MISSING",
    "REASON_GOVERNANCE_UNKNOWN",
    "REASON_GOVERNANCE_INCONSISTENT",
    "REASON_PROVENANCE_MISSING",
    "REASON_CONFLICTS_PRESENT",
    "REASON_DUPLICATE_GROUPS",
    "REASON_CONFIDENCE_MISCALIBRATION",
    "REASON_EVIDENCE_GAP",
    "REASON_HYPOTHESIS_WEAKNESS",
    "REASON_LOW_QUALITY",
    "REASON_STRONG_EVALUATION",
    "REASON_OBSERVED_ISSUE",
    "REASON_OBSERVED_SUCCESS",
    "REASON_INSUFFICIENT_DATA",
    "CLASSIFICATION_SIGNALS",
    "SIGNAL_EVALUATION_PRESENT",
    "SIGNAL_EVALUATION_SAFETY_STATE",
    "SIGNAL_EVALUATION_HARD_GATE",
    "SIGNAL_EVALUATION_DIAGNOSTIC",
    "SIGNAL_EVALUATION_OVERALL_RATING",
    "SIGNAL_EVALUATION_DIMENSION_SCORE",
    "SIGNAL_COLLABORATION_CONFLICTS",
    "SIGNAL_COLLABORATION_DUPLICATE_GROUPS",
    "SIGNAL_COLLABORATION_EVIDENCE_STATE",
    "SIGNAL_OBSERVED_ISSUE",
    "SIGNAL_OBSERVED_SUCCESS",
    "SIGNAL_GOVERNANCE_STATE",
    "SIGNAL_PROVENANCE_STATE",
    "CLASSIFICATION_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_AGENT_MODIFICATION",
    "LIMITATION_ADVISORY_ONLY",
    "LIMITATION_INSUFFICIENT_DATA",
    "MAX_REASONS",
    "MAX_SIGNALS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_research_feedback_classification",
    "ResearchFeedbackClassificationPlan",
    "research_feedback_classification_plan_projection",
]
