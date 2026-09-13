"""Research learning memory schema (Stage R44.4).

A :class:`ResearchLearningMemoryPlan` stores deterministic structured
patterns aggregated from feedback events. It answers:

    "Which recurring structured research patterns did previous outcomes
     reveal?"

Hard boundaries encoded here:

- Learning only: pattern memory is a structured, advisory record. There are
  no automatic rule changes, no automatic agent tuning and no execution.
- Closed pattern-type and limitation vocabularies.
- No timestamps, UUID generation, randomness or runtime identifiers.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.research_feedback_classification import CLASSIFICATIONS
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

RESEARCH_LEARNING_MEMORY_RULE_VERSION = "r44-4"
RULE_VERSION = RESEARCH_LEARNING_MEMORY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATE_COMPLETE = "COMPLETE"
STATE_PARTIAL = "PARTIAL"
STATE_UNKNOWN = "UNKNOWN"

MEMORY_STATES: tuple[str, ...] = (
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
)

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_RULE_MODIFICATION = "NO_RULE_MODIFICATION"
LIMITATION_NO_AUTOMATIC_AGENT_TUNING = "NO_AUTOMATIC_AGENT_TUNING"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"

MEMORY_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_RULE_MODIFICATION,
    LIMITATION_NO_AUTOMATIC_AGENT_TUNING,
    LIMITATION_ADVISORY_ONLY,
)

PATTERN_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_RULE_MODIFICATION,
    LIMITATION_NO_AUTOMATIC_AGENT_TUNING,
    LIMITATION_ADVISORY_ONLY,
)

PATTERN_ID_PREFIX = "pat-"
PATTERN_ID_RE = re.compile(r"^pat-[0-9a-f]{16}$")

MAX_PATTERNS = 32
MAX_EVENTS = 64
MAX_LIMITATIONS = 5
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_strings(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_learning_pattern(value: object) -> dict:
    """Project a learning pattern onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "pattern_id": "",
            "source_category": "UNKNOWN",
            "pattern_type": "UNKNOWN",
            "occurrence_count": 0,
            "confidence": "UNKNOWN",
            "supporting_events": [],
            "limitations": list(PATTERN_LIMITATIONS),
            "research_only": True,
        }
    category = _safe_text(value.get("source_category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    pattern_type = _safe_text(
        value.get("pattern_type")
    ).strip().upper()
    if pattern_type not in CLASSIFICATIONS:
        pattern_type = "UNKNOWN"
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    count = value.get("occurrence_count")
    if isinstance(count, bool) or not isinstance(count, int):
        count = 0
    count = max(0, min(MAX_EVENTS, count))
    limitations = [
        code
        for code in (
            _safe_text(item).strip().upper()
            for item in value.get("limitations") or ()
        )
        if code in PATTERN_LIMITATIONS
    ]
    if not limitations:
        limitations = list(PATTERN_LIMITATIONS)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "pattern_id": _safe_text(value.get("pattern_id")),
        "source_category": category,
        "pattern_type": pattern_type,
        "occurrence_count": count,
        "confidence": confidence,
        "supporting_events": _bounded_strings(
            value.get("supporting_events"), MAX_EVENTS
        ),
        "limitations": limitations,
        "research_only": True,
    }


def sanitize_research_learning_memory(value: object) -> dict:
    """Project a learning memory onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "patterns": [],
            "memory_state": STATE_UNKNOWN,
            "limitations": list(MEMORY_LIMITATIONS),
            "research_only": True,
        }
    patterns: list[dict] = []
    for item in value.get("patterns") or ():
        if isinstance(item, dict):
            patterns.append(sanitize_learning_pattern(item))
        if len(patterns) >= MAX_PATTERNS:
            break
    state = _safe_text(value.get("memory_state")).strip().upper()
    if state not in MEMORY_STATES:
        state = STATE_UNKNOWN
    limitations = [
        code
        for code in (
            _safe_text(item).strip().upper()
            for item in value.get("limitations") or ()
        )
        if code in MEMORY_LIMITATIONS
    ]
    if not limitations:
        limitations = list(MEMORY_LIMITATIONS)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "patterns": patterns,
        "memory_state": state,
        "limitations": limitations,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class LearningPatternPlan(BaseModel):
    """Deterministic aggregated learning pattern (R44.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_LEARNING_MEMORY_RULE_VERSION
    pattern_id: str = ""
    source_category: str = "UNKNOWN"
    pattern_type: str = "UNKNOWN"
    occurrence_count: int = 0
    confidence: str = "UNKNOWN"
    supporting_events: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_LEARNING_MEMORY_RULE_VERSION

    @field_validator("pattern_id")
    @classmethod
    def _bounded_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("source_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid source_category: {value!r}")
        return text

    @field_validator("pattern_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CLASSIFICATIONS:
            raise ValueError(f"invalid pattern_type: {value!r}")
        return text

    @field_validator("occurrence_count")
    @classmethod
    def _valid_count(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid occurrence_count: {value!r}")
        if value < 0 or value > MAX_EVENTS:
            raise ValueError(f"occurrence_count out of range: {value!r}")
        return value

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("supporting_events")
    @classmethod
    def _valid_events(cls, value: list) -> list[str]:
        return _bounded_strings(value, MAX_EVENTS)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return [
            code
            for code in (
                _safe_text(item).strip().upper() for item in value or ()
            )
            if code in PATTERN_LIMITATIONS
        ]

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("learning patterns are research-only")
        return True


class ResearchLearningMemoryPlan(BaseModel):
    """Bounded research learning memory (R44.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_LEARNING_MEMORY_RULE_VERSION
    patterns: list[dict] = Field(default_factory=list)
    memory_state: str = STATE_UNKNOWN
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_LEARNING_MEMORY_RULE_VERSION

    @field_validator("patterns")
    @classmethod
    def _valid_patterns(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                out.append(sanitize_learning_pattern(item))
            if len(out) >= MAX_PATTERNS:
                break
        return out

    @field_validator("memory_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in MEMORY_STATES:
            raise ValueError(f"invalid memory_state: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        out = [
            code
            for code in (
                _safe_text(item).strip().upper() for item in value or ()
            )
            if code in MEMORY_LIMITATIONS
        ]
        return out or list(MEMORY_LIMITATIONS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("learning memory is research-only")
        return True


def learning_pattern_plan_projection(value: LearningPatternPlan) -> dict:
    """Serialize a learning pattern to a deterministic dict."""

    return value.model_dump(mode="json")


def research_learning_memory_plan_projection(
    value: ResearchLearningMemoryPlan,
) -> dict:
    """Serialize learning memory to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_LEARNING_MEMORY_RULE_VERSION",
    "RULE_VERSION",
    "MEMORY_STATES",
    "STATE_COMPLETE",
    "STATE_PARTIAL",
    "STATE_UNKNOWN",
    "MEMORY_LIMITATIONS",
    "PATTERN_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_RULE_MODIFICATION",
    "LIMITATION_NO_AUTOMATIC_AGENT_TUNING",
    "LIMITATION_ADVISORY_ONLY",
    "PATTERN_ID_PREFIX",
    "PATTERN_ID_RE",
    "MAX_PATTERNS",
    "MAX_EVENTS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_learning_pattern",
    "sanitize_research_learning_memory",
    "LearningPatternPlan",
    "ResearchLearningMemoryPlan",
    "learning_pattern_plan_projection",
    "research_learning_memory_plan_projection",
]
