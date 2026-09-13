"""Research budget schema (Stage R34.3).

A :class:`ResearchBudgetPlan` determines whether research should continue,
pause, or stop. It answers the owner's personal-research question:

    "How much further research budget should this candidate receive?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``. The budget state is an
  advisory planning label, never an execution authorization.
- Closed vocabularies: budget state, reason and allowed next step are closed
  deterministic sets.
- Bounded, privacy-safe: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

RESEARCH_BUDGET_RULE_VERSION = "r34-3"
RULE_VERSION = RESEARCH_BUDGET_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

BUDGET_CONTINUE = "CONTINUE"
BUDGET_LIMITED = "LIMITED"
BUDGET_PAUSE = "PAUSE"
BUDGET_STOP = "STOP"
BUDGET_UNKNOWN = "UNKNOWN"

BUDGET_STATES: tuple[str, ...] = (
    BUDGET_CONTINUE,
    BUDGET_LIMITED,
    BUDGET_PAUSE,
    BUDGET_STOP,
    BUDGET_UNKNOWN,
)

REASON_HIGH_CONFIDENCE_SUCCESS = "HIGH_CONFIDENCE_SUCCESS"
REASON_MEDIUM_CONFIDENCE = "MEDIUM_CONFIDENCE"
REASON_LOW_CONFIDENCE = "LOW_CONFIDENCE"
REASON_REPEATED_BLOCKERS = "REPEATED_BLOCKERS"
REASON_DEFERRED_STRATEGY = "DEFERRED_STRATEGY"
REASON_UNKNOWN_CONFIDENCE = "UNKNOWN_CONFIDENCE"

BUDGET_REASONS: tuple[str, ...] = (
    REASON_HIGH_CONFIDENCE_SUCCESS,
    REASON_MEDIUM_CONFIDENCE,
    REASON_LOW_CONFIDENCE,
    REASON_REPEATED_BLOCKERS,
    REASON_DEFERRED_STRATEGY,
    REASON_UNKNOWN_CONFIDENCE,
)

STEP_MORE_EVIDENCE = "MORE_EVIDENCE"
STEP_MORE_ANALYSIS = "MORE_ANALYSIS"
STEP_HUMAN_REVIEW = "HUMAN_REVIEW"
STEP_NONE = "NONE"
STEP_UNKNOWN = "UNKNOWN"

ALLOWED_NEXT_STEPS: tuple[str, ...] = (
    STEP_MORE_EVIDENCE,
    STEP_MORE_ANALYSIS,
    STEP_HUMAN_REVIEW,
    STEP_NONE,
    STEP_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def sanitize_research_budget_plan(value: object) -> dict:
    """Project an R34.3 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "budget_state": "",
            "reason": "",
            "allowed_next_step": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "budget_state": _safe_text(value.get("budget_state")),
        "reason": _safe_text(value.get("reason")),
        "allowed_next_step": _safe_text(value.get("allowed_next_step")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchBudgetPlan(BaseModel):
    """Deterministic research budget state (R34.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_BUDGET_RULE_VERSION
    budget_state: str
    reason: str
    allowed_next_step: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_BUDGET_RULE_VERSION

    @field_validator("budget_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in BUDGET_STATES:
            raise ValueError(f"invalid budget_state: {value!r}")
        return text

    @field_validator("reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in BUDGET_REASONS:
            raise ValueError(f"invalid reason: {value!r}")
        return text

    @field_validator("allowed_next_step")
    @classmethod
    def _valid_next_step(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ALLOWED_NEXT_STEPS:
            raise ValueError(f"invalid allowed_next_step: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research budget plans are research-only")
        return True


def research_budget_plan_projection(value: ResearchBudgetPlan) -> dict:
    """Serialize a research budget plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_BUDGET_RULE_VERSION",
    "RULE_VERSION",
    "BUDGET_STATES",
    "BUDGET_REASONS",
    "ALLOWED_NEXT_STEPS",
    "BUDGET_CONTINUE",
    "BUDGET_LIMITED",
    "BUDGET_PAUSE",
    "BUDGET_STOP",
    "BUDGET_UNKNOWN",
    "REASON_HIGH_CONFIDENCE_SUCCESS",
    "REASON_MEDIUM_CONFIDENCE",
    "REASON_LOW_CONFIDENCE",
    "REASON_REPEATED_BLOCKERS",
    "REASON_DEFERRED_STRATEGY",
    "REASON_UNKNOWN_CONFIDENCE",
    "STEP_MORE_EVIDENCE",
    "STEP_MORE_ANALYSIS",
    "STEP_HUMAN_REVIEW",
    "STEP_NONE",
    "STEP_UNKNOWN",
    "MAX_VALUE_LEN",
    "ResearchBudgetPlan",
    "sanitize_research_budget_plan",
    "research_budget_plan_projection",
]
