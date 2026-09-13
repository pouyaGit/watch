"""Research strategy export schema (Stage R34.4).

A :class:`ResearchStrategyExportPlan` is the final deterministic, read-only
export over the R34.1 strategy, R34.2 path and R34.3 budget plans. It answers
the owner's personal-research question:

    "What strategy intelligence is ready for the next research step?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``. The export is advisory and
  never an execution authorization.
- Closed vocabularies: limitation codes are a closed set; embedded plan
  vocabularies remain owned by R34.1-R34.3.
- Bounded, privacy-safe: embedded plans are projected onto fixed, closed key
  sets and sanitized.
- No Money Score, no R29 modification, no persistence.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.research_budget import sanitize_research_budget_plan
from ai.schemas.research_path import sanitize_research_path_plan
from ai.schemas.research_strategy import sanitize_research_strategy_plan

RESEARCH_STRATEGY_EXPORT_RULE_VERSION = "r34-4"
RULE_VERSION = RESEARCH_STRATEGY_EXPORT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LIMITATION_UNKNOWN_STRATEGY = "UNKNOWN_STRATEGY"
LIMITATION_LOW_CONFIDENCE = "LOW_CONFIDENCE"
LIMITATION_DEFERRED_STRATEGY = "DEFERRED_STRATEGY"
LIMITATION_REPEATED_BLOCKERS = "REPEATED_BLOCKERS"
LIMITATION_UNKNOWN_BUDGET = "UNKNOWN_BUDGET"

LIMITATION_CODES: tuple[str, ...] = (
    LIMITATION_UNKNOWN_STRATEGY,
    LIMITATION_LOW_CONFIDENCE,
    LIMITATION_DEFERRED_STRATEGY,
    LIMITATION_REPEATED_BLOCKERS,
    LIMITATION_UNKNOWN_BUDGET,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

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


class ResearchStrategyExportPlan(BaseModel):
    """Final deterministic research strategy export object (R34.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_STRATEGY_EXPORT_RULE_VERSION
    ready: bool
    strategy: dict = Field(default_factory=dict)
    path: dict = Field(default_factory=dict)
    budget: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_STRATEGY_EXPORT_RULE_VERSION

    @field_validator("strategy")
    @classmethod
    def _bounded_strategy(cls, value: object) -> dict:
        return sanitize_research_strategy_plan(value)

    @field_validator("path")
    @classmethod
    def _bounded_path(cls, value: object) -> dict:
        return sanitize_research_path_plan(value)

    @field_validator("budget")
    @classmethod
    def _bounded_budget(cls, value: object) -> dict:
        return sanitize_research_budget_plan(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(value, LIMITATION_CODES, MAX_LIMITATIONS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "research strategy exports are research-only"
            )
        return True


def research_strategy_export_plan_projection(
    value: ResearchStrategyExportPlan,
) -> dict:
    """Serialize a research strategy export to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_STRATEGY_EXPORT_RULE_VERSION",
    "RULE_VERSION",
    "LIMITATION_CODES",
    "LIMITATION_UNKNOWN_STRATEGY",
    "LIMITATION_LOW_CONFIDENCE",
    "LIMITATION_DEFERRED_STRATEGY",
    "LIMITATION_REPEATED_BLOCKERS",
    "LIMITATION_UNKNOWN_BUDGET",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "ResearchStrategyExportPlan",
    "research_strategy_export_plan_projection",
]
