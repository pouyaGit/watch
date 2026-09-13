"""Learning signal schema (Stage R44.3).

A :class:`LearningSignalPlan` is a deterministic, advisory learning signal
derived from one feedback classification. It answers:

    "What should future research consider?"

Hard boundaries encoded here:

- Learning only: signals are recommendations, not actions. They never modify
  agents, rules, source code, security policies or runtime behavior, and
  they never execute anything.
- Closed signal, subject, confidence and limitation vocabularies.
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

LEARNING_SIGNAL_RULE_VERSION = "r44-3"
RULE_VERSION = LEARNING_SIGNAL_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

SIGNAL_REQUIRE_MORE_EVIDENCE = "REQUIRE_MORE_EVIDENCE"
SIGNAL_REDUCE_CONFIDENCE = "REDUCE_CONFIDENCE"
SIGNAL_IMPROVE_CONTEXT_COLLECTION = "IMPROVE_CONTEXT_COLLECTION"
SIGNAL_PRESERVE_SUCCESS_PATTERN = "PRESERVE_SUCCESS_PATTERN"
SIGNAL_AVOID_DUPLICATION = "AVOID_DUPLICATION"
SIGNAL_REVIEW_GOVERNANCE = "REVIEW_GOVERNANCE"
SIGNAL_REVIEW_PROVENANCE = "REVIEW_PROVENANCE"
SIGNAL_IMPROVE_HYPOTHESIS_QUALITY = "IMPROVE_HYPOTHESIS_QUALITY"
SIGNAL_IMPROVE_SAFETY_BOUNDARY = "IMPROVE_SAFETY_BOUNDARY"
SIGNAL_UNKNOWN = "UNKNOWN"

LEARNING_SIGNAL_TYPES: tuple[str, ...] = (
    SIGNAL_REQUIRE_MORE_EVIDENCE,
    SIGNAL_REDUCE_CONFIDENCE,
    SIGNAL_IMPROVE_CONTEXT_COLLECTION,
    SIGNAL_PRESERVE_SUCCESS_PATTERN,
    SIGNAL_AVOID_DUPLICATION,
    SIGNAL_REVIEW_GOVERNANCE,
    SIGNAL_REVIEW_PROVENANCE,
    SIGNAL_IMPROVE_HYPOTHESIS_QUALITY,
    SIGNAL_IMPROVE_SAFETY_BOUNDARY,
    SIGNAL_UNKNOWN,
)

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_AGENT_MODIFICATION = "NO_AGENT_MODIFICATION"
LIMITATION_NO_RULE_MODIFICATION = "NO_RULE_MODIFICATION"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"

LEARNING_SIGNAL_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_AGENT_MODIFICATION,
    LIMITATION_NO_RULE_MODIFICATION,
    LIMITATION_ADVISORY_ONLY,
)

MAX_SIGNALS = 8
MAX_VALUE_LEN = 160
MAX_RECOMMENDATION_LEN = 240

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


def sanitize_learning_signal(value: object) -> dict:
    """Project a learning signal onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "signal_type": SIGNAL_UNKNOWN,
            "subject": "UNKNOWN",
            "source_agent": "",
            "source_classification": "UNKNOWN",
            "recommendation": "",
            "supporting_signals": [],
            "confidence": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    category = _safe_text(value.get("subject")).strip().upper()
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
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "signal_type": _safe_text(
            value.get("signal_type")
        ).strip().upper()
        if _safe_text(value.get("signal_type")).strip().upper()
        in LEARNING_SIGNAL_TYPES
        else SIGNAL_UNKNOWN,
        "subject": category,
        "source_agent": _safe_text(value.get("source_agent")),
        "source_classification": classification,
        "recommendation": _safe_text(
            value.get("recommendation"), MAX_RECOMMENDATION_LEN
        ),
        "supporting_signals": _bounded_codes(
            value.get("supporting_signals"),
            CLASSIFICATION_SIGNALS,
            MAX_SIGNALS,
        ),
        "confidence": confidence,
        "limitations": [
            code
            for code in _bounded_codes(
                value.get("limitations"),
                LEARNING_SIGNAL_LIMITATIONS,
                MAX_SIGNALS,
            )
        ],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class LearningSignalPlan(BaseModel):
    """Deterministic advisory learning signal (R44.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LEARNING_SIGNAL_RULE_VERSION
    signal_type: str = SIGNAL_UNKNOWN
    subject: str = "UNKNOWN"
    source_agent: str = ""
    source_classification: str = "UNKNOWN"
    recommendation: str = ""
    supporting_signals: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LEARNING_SIGNAL_RULE_VERSION

    @field_validator("signal_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in LEARNING_SIGNAL_TYPES:
            raise ValueError(f"invalid signal_type: {value!r}")
        return text

    @field_validator("subject")
    @classmethod
    def _valid_subject(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid subject: {value!r}")
        return text

    @field_validator("source_agent")
    @classmethod
    def _bounded_agent(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("source_classification")
    @classmethod
    def _valid_classification(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CLASSIFICATIONS:
            raise ValueError(f"invalid source_classification: {value!r}")
        return text

    @field_validator("recommendation")
    @classmethod
    def _bounded_recommendation(cls, value: object) -> str:
        return _safe_text(value, MAX_RECOMMENDATION_LEN)

    @field_validator("supporting_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _bounded_codes(value, CLASSIFICATION_SIGNALS, MAX_SIGNALS)

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
        return _bounded_codes(value, LEARNING_SIGNAL_LIMITATIONS, MAX_SIGNALS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("learning signals are research-only")
        return True


def learning_signal_plan_projection(value: LearningSignalPlan) -> dict:
    """Serialize a learning signal to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LEARNING_SIGNAL_RULE_VERSION",
    "RULE_VERSION",
    "LEARNING_SIGNAL_TYPES",
    "SIGNAL_REQUIRE_MORE_EVIDENCE",
    "SIGNAL_REDUCE_CONFIDENCE",
    "SIGNAL_IMPROVE_CONTEXT_COLLECTION",
    "SIGNAL_PRESERVE_SUCCESS_PATTERN",
    "SIGNAL_AVOID_DUPLICATION",
    "SIGNAL_REVIEW_GOVERNANCE",
    "SIGNAL_REVIEW_PROVENANCE",
    "SIGNAL_IMPROVE_HYPOTHESIS_QUALITY",
    "SIGNAL_IMPROVE_SAFETY_BOUNDARY",
    "SIGNAL_UNKNOWN",
    "LEARNING_SIGNAL_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_AGENT_MODIFICATION",
    "LIMITATION_NO_RULE_MODIFICATION",
    "LIMITATION_ADVISORY_ONLY",
    "MAX_SIGNALS",
    "MAX_VALUE_LEN",
    "MAX_RECOMMENDATION_LEN",
    "sanitize_learning_signal",
    "LearningSignalPlan",
    "learning_signal_plan_projection",
]
