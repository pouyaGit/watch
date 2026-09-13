"""Learning recommendation schema (Stage R44.5).

A :class:`LearningRecommendationPlan` is a deterministic, advisory
recommendation derived from learning signals. It answers:

    "Which advisory recommendation follows from previous research outcomes?"

Hard boundaries encoded here:

- Learning only: recommendations are advisory. They never modify agents,
  rules, source code, security policies or runtime behavior; they do not
  modify R34 strategy or R35 orchestration.
- Closed recommendation-type and limitation vocabularies.
- No execution, no network, no database, no browser, no LLM, no payloads.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.research_feedback_classification import (
    CLASSIFICATION_SIGNALS,
    CLASSIFICATIONS,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

LEARNING_RECOMMENDATION_RULE_VERSION = "r44-5"
RULE_VERSION = LEARNING_RECOMMENDATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

REC_PRIORITIZE_EVIDENCE_PLANNING = "PRIORITIZE_EVIDENCE_PLANNING"
REC_CALIBRATE_CONFIDENCE = "CALIBRATE_CONFIDENCE"
REC_IMPROVE_CONTEXT_CAPTURE = "IMPROVE_CONTEXT_CAPTURE"
REC_PRESERVE_SUCCESSFUL_PATTERN = "PRESERVE_SUCCESSFUL_PATTERN"
REC_DEDUPLICATE_HYPOTHESES = "DEDUPLICATE_HYPOTHESES"
REC_REVIEW_GOVERNANCE_REFERENCES = "REVIEW_GOVERNANCE_REFERENCES"
REC_PRESERVE_PROVENANCE = "PRESERVE_PROVENANCE"
REC_STRENGTHEN_HYPOTHESES = "STRENGTHEN_HYPOTHESES"
REC_RESTORE_SAFETY_BOUNDARY = "RESTORE_SAFETY_BOUNDARY"
REC_UNKNOWN = "UNKNOWN"

LEARNING_RECOMMENDATION_TYPES: tuple[str, ...] = (
    REC_PRIORITIZE_EVIDENCE_PLANNING,
    REC_CALIBRATE_CONFIDENCE,
    REC_IMPROVE_CONTEXT_CAPTURE,
    REC_PRESERVE_SUCCESSFUL_PATTERN,
    REC_DEDUPLICATE_HYPOTHESES,
    REC_REVIEW_GOVERNANCE_REFERENCES,
    REC_PRESERVE_PROVENANCE,
    REC_STRENGTHEN_HYPOTHESES,
    REC_RESTORE_SAFETY_BOUNDARY,
    REC_UNKNOWN,
)

RECOMMENDATION_ORDER: dict[str, int] = {
    recommendation_type: index
    for index, recommendation_type in enumerate(
        LEARNING_RECOMMENDATION_TYPES
    )
}

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_AGENT_MODIFICATION = "NO_AGENT_MODIFICATION"
LIMITATION_NO_RULE_MODIFICATION = "NO_RULE_MODIFICATION"
LIMITATION_NO_AUTOMATIC_STRATEGY_CHANGE = "NO_AUTOMATIC_STRATEGY_CHANGE"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"

LEARNING_RECOMMENDATION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_AGENT_MODIFICATION,
    LIMITATION_NO_RULE_MODIFICATION,
    LIMITATION_NO_AUTOMATIC_STRATEGY_CHANGE,
    LIMITATION_ADVISORY_ONLY,
)

RECOMMENDATION_ID_PREFIX = "rec-"
RECOMMENDATION_ID_RE = re.compile(r"^rec-[0-9a-f]{16}$")

MAX_SIGNALS = 8
MAX_VALUE_LEN = 160
MAX_RECOMMENDATION_LEN = 240

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


def sanitize_learning_recommendation(value: object) -> dict:
    """Project a learning recommendation onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "recommendation_id": "",
            "recommendation_type": REC_UNKNOWN,
            "related_agent": "",
            "related_category": "UNKNOWN",
            "source_classification": "UNKNOWN",
            "supporting_signals": [],
            "recommendation": "",
            "confidence": "UNKNOWN",
            "limitations": list(LEARNING_RECOMMENDATION_LIMITATIONS),
        }
    category = _safe_text(value.get("related_category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    classification = _safe_text(
        value.get("source_classification")
    ).strip().upper()
    if classification not in CLASSIFICATIONS:
        classification = "UNKNOWN"
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    limitations = [
        code
        for code in _bounded_codes(
            value.get("limitations"),
            LEARNING_RECOMMENDATION_LIMITATIONS,
            MAX_SIGNALS,
        )
    ]
    if not limitations:
        limitations = list(LEARNING_RECOMMENDATION_LIMITATIONS)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "recommendation_id": _safe_text(value.get("recommendation_id")),
        "recommendation_type": _safe_text(
            value.get("recommendation_type")
        ).strip().upper()
        if _safe_text(value.get("recommendation_type")).strip().upper()
        in LEARNING_RECOMMENDATION_TYPES
        else REC_UNKNOWN,
        "related_agent": _safe_text(value.get("related_agent")),
        "related_category": category,
        "source_classification": classification,
        "supporting_signals": _bounded_codes(
            value.get("supporting_signals"),
            CLASSIFICATION_SIGNALS,
            MAX_SIGNALS,
        ),
        "recommendation": _safe_text(
            value.get("recommendation"), MAX_RECOMMENDATION_LEN
        ),
        "confidence": confidence,
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class LearningRecommendationPlan(BaseModel):
    """Deterministic advisory learning recommendation (R44.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LEARNING_RECOMMENDATION_RULE_VERSION
    recommendation_id: str = ""
    recommendation_type: str = REC_UNKNOWN
    related_agent: str = ""
    related_category: str = "UNKNOWN"
    source_classification: str = "UNKNOWN"
    supporting_signals: list[str] = Field(default_factory=list)
    recommendation: str = ""
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LEARNING_RECOMMENDATION_RULE_VERSION

    @field_validator("recommendation_id", "related_agent")
    @classmethod
    def _bounded_text(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("recommendation_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in LEARNING_RECOMMENDATION_TYPES:
            raise ValueError(f"invalid recommendation_type: {value!r}")
        return text

    @field_validator("related_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid related_category: {value!r}")
        return text

    @field_validator("source_classification")
    @classmethod
    def _valid_classification(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CLASSIFICATIONS:
            raise ValueError(f"invalid source_classification: {value!r}")
        return text

    @field_validator("supporting_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _bounded_codes(value, CLASSIFICATION_SIGNALS, MAX_SIGNALS)

    @field_validator("recommendation")
    @classmethod
    def _bounded_recommendation(cls, value: object) -> str:
        return _safe_text(value, MAX_RECOMMENDATION_LEN)

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
        return _bounded_codes(
            value, LEARNING_RECOMMENDATION_LIMITATIONS, MAX_SIGNALS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("learning recommendations are research-only")
        return True


def learning_recommendation_plan_projection(
    value: LearningRecommendationPlan,
) -> dict:
    """Serialize a learning recommendation to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LEARNING_RECOMMENDATION_RULE_VERSION",
    "RULE_VERSION",
    "LEARNING_RECOMMENDATION_TYPES",
    "RECOMMENDATION_ORDER",
    "REC_PRIORITIZE_EVIDENCE_PLANNING",
    "REC_CALIBRATE_CONFIDENCE",
    "REC_IMPROVE_CONTEXT_CAPTURE",
    "REC_PRESERVE_SUCCESSFUL_PATTERN",
    "REC_DEDUPLICATE_HYPOTHESES",
    "REC_REVIEW_GOVERNANCE_REFERENCES",
    "REC_PRESERVE_PROVENANCE",
    "REC_STRENGTHEN_HYPOTHESES",
    "REC_RESTORE_SAFETY_BOUNDARY",
    "REC_UNKNOWN",
    "LEARNING_RECOMMENDATION_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_AGENT_MODIFICATION",
    "LIMITATION_NO_RULE_MODIFICATION",
    "LIMITATION_NO_AUTOMATIC_STRATEGY_CHANGE",
    "LIMITATION_ADVISORY_ONLY",
    "RECOMMENDATION_ID_PREFIX",
    "RECOMMENDATION_ID_RE",
    "MAX_SIGNALS",
    "MAX_VALUE_LEN",
    "MAX_RECOMMENDATION_LEN",
    "sanitize_learning_recommendation",
    "LearningRecommendationPlan",
    "learning_recommendation_plan_projection",
]
