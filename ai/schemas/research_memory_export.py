"""Research memory export schema (Stage R32.4).

A :class:`ResearchMemoryExportPlan` is the final deterministic, read-only
export object over the R32.2 research history and the R32.3 structural
pattern detection. It answers the owner's personal-research question:

    "What reusable historical intelligence is available for this layer?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: limitation codes are a closed set; history/pattern
  vocabularies remain owned by R32.2/R32.3 and are imported.
- Bounded, privacy-safe: the embedded history and pattern plans are projected
  onto fixed, closed key sets and sanitized.
- No persistence, no database migration, no vulnerability inference.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.research_history import (
    sanitize_research_history_plan,
)
from ai.schemas.research_pattern_plan import (
    sanitize_research_pattern_plan,
)

RESEARCH_MEMORY_EXPORT_RULE_VERSION = "r32-4"
RULE_VERSION = RESEARCH_MEMORY_EXPORT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LIMITATION_NO_HISTORY = "NO_HISTORY"
LIMITATION_SINGLE_RECORD = "SINGLE_RECORD_HISTORY"
LIMITATION_PATTERN_LOW_CONFIDENCE = "PATTERN_LOW_CONFIDENCE"
LIMITATION_RECURRING_BLOCKERS = "RECURRING_BLOCKERS_PRESENT"

LIMITATION_CODES: tuple[str, ...] = (
    LIMITATION_NO_HISTORY,
    LIMITATION_SINGLE_RECORD,
    LIMITATION_PATTERN_LOW_CONFIDENCE,
    LIMITATION_RECURRING_BLOCKERS,
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


def _bounded_limitations(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in LIMITATION_CODES:
            raise ValueError(f"invalid limitation code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= MAX_LIMITATIONS:
            break
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchMemoryExportPlan(BaseModel):
    """Final deterministic research memory export object (R32.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_MEMORY_EXPORT_RULE_VERSION
    ready: bool
    history: dict = Field(default_factory=dict)
    patterns: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_MEMORY_EXPORT_RULE_VERSION

    @field_validator("history")
    @classmethod
    def _bounded_history(cls, value: object) -> dict:
        return sanitize_research_history_plan(value)

    @field_validator("patterns")
    @classmethod
    def _bounded_patterns(cls, value: object) -> dict:
        return sanitize_research_pattern_plan(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _bounded_limitations(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research memory exports are research-only")
        return True


def research_memory_export_plan_projection(
    value: ResearchMemoryExportPlan,
) -> dict:
    """Serialize a research memory export to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_MEMORY_EXPORT_RULE_VERSION",
    "RULE_VERSION",
    "LIMITATION_CODES",
    "LIMITATION_NO_HISTORY",
    "LIMITATION_SINGLE_RECORD",
    "LIMITATION_PATTERN_LOW_CONFIDENCE",
    "LIMITATION_RECURRING_BLOCKERS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "ResearchMemoryExportPlan",
    "research_memory_export_plan_projection",
]
