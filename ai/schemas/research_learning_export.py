"""Research learning export schema (Stage R33.4).

A :class:`ResearchLearningExportPlan` is the final deterministic, read-only
export over the R33.1 pattern intelligence, R33.2 candidate ranking and R33.3
efficiency plans. It answers the owner's personal-research question:

    "What learning intelligence is ready for downstream research attention?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: recommendation and limitation codes are closed sets;
  embedded plan vocabularies remain owned by R33.1-R33.3.
- Bounded, privacy-safe: embedded plans are projected onto fixed, closed key
  sets and sanitized.
- No Money Score, no execution authority, no persistence.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.historical_candidate_ranking import (
    sanitize_historical_candidate_ranking_plan,
)
from ai.schemas.research_efficiency import (
    sanitize_research_efficiency_plan,
)
from ai.schemas.research_pattern_intelligence import (
    sanitize_research_pattern_intelligence_plan,
)

RESEARCH_LEARNING_EXPORT_RULE_VERSION = "r33-4"
RULE_VERSION = RESEARCH_LEARNING_EXPORT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

RECOMMEND_PRIORITIZE = "PRIORITIZE_HISTORICAL_SUCCESS"
RECOMMEND_REDUCE_BLOCKERS = "REDUCE_RECURRING_BLOCKERS"
RECOMMEND_CLOSE_GAPS = "CLOSE_EVIDENCE_GAPS"
RECOMMEND_INCREASE_SUCCESS = "INCREASE_SUCCESSFUL_RESEARCH"
RECOMMEND_COLLECT_HISTORY = "COLLECT_MORE_HISTORY"
RECOMMEND_NO_ACTION = "NO_ACTION"

RECOMMENDATION_CODES: tuple[str, ...] = (
    RECOMMEND_PRIORITIZE,
    RECOMMEND_REDUCE_BLOCKERS,
    RECOMMEND_CLOSE_GAPS,
    RECOMMEND_INCREASE_SUCCESS,
    RECOMMEND_COLLECT_HISTORY,
    RECOMMEND_NO_ACTION,
)

LIMITATION_NO_HISTORY = "NO_HISTORY"
LIMITATION_LOW_PATTERN_CONFIDENCE = "LOW_PATTERN_CONFIDENCE"
LIMITATION_UNKNOWN_EFFICIENCY = "UNKNOWN_EFFICIENCY"
LIMITATION_NO_HISTORICAL_SUCCESS = "NO_HISTORICAL_SUCCESS"

LIMITATION_CODES: tuple[str, ...] = (
    LIMITATION_NO_HISTORY,
    LIMITATION_LOW_PATTERN_CONFIDENCE,
    LIMITATION_UNKNOWN_EFFICIENCY,
    LIMITATION_NO_HISTORICAL_SUCCESS,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_RECOMMENDATIONS = 8
MAX_LIMITATIONS = 8
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
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


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchLearningExportPlan(BaseModel):
    """Final deterministic research learning export object (R33.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_LEARNING_EXPORT_RULE_VERSION
    ready: bool
    ranking: dict = Field(default_factory=dict)
    patterns: dict = Field(default_factory=dict)
    efficiency: dict = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_LEARNING_EXPORT_RULE_VERSION

    @field_validator("ranking")
    @classmethod
    def _bounded_ranking(cls, value: object) -> dict:
        return sanitize_historical_candidate_ranking_plan(value)

    @field_validator("patterns")
    @classmethod
    def _bounded_patterns(cls, value: object) -> dict:
        return sanitize_research_pattern_intelligence_plan(value)

    @field_validator("efficiency")
    @classmethod
    def _bounded_efficiency(cls, value: object) -> dict:
        return sanitize_research_efficiency_plan(value)

    @field_validator("recommendations")
    @classmethod
    def _valid_recommendations(cls, value: list) -> list[str]:
        return _require_codes(value, RECOMMENDATION_CODES, MAX_RECOMMENDATIONS)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(value, LIMITATION_CODES, MAX_LIMITATIONS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research learning exports are research-only")
        return True


def research_learning_export_plan_projection(
    value: ResearchLearningExportPlan,
) -> dict:
    """Serialize a research learning export to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_LEARNING_EXPORT_RULE_VERSION",
    "RULE_VERSION",
    "RECOMMENDATION_CODES",
    "LIMITATION_CODES",
    "RECOMMEND_PRIORITIZE",
    "RECOMMEND_REDUCE_BLOCKERS",
    "RECOMMEND_CLOSE_GAPS",
    "RECOMMEND_INCREASE_SUCCESS",
    "RECOMMEND_COLLECT_HISTORY",
    "RECOMMEND_NO_ACTION",
    "LIMITATION_NO_HISTORY",
    "LIMITATION_LOW_PATTERN_CONFIDENCE",
    "LIMITATION_UNKNOWN_EFFICIENCY",
    "LIMITATION_NO_HISTORICAL_SUCCESS",
    "MAX_RECOMMENDATIONS",
    "MAX_LIMITATIONS",
    "ResearchLearningExportPlan",
    "research_learning_export_plan_projection",
]
