"""Research efficiency schema (Stage R33.3).

A :class:`ResearchEfficiencyPlan` measures research process efficiency from
historical counts. It answers the owner's personal-research question:

    "How efficiently is research progressing across recorded history?"

Hard boundaries encoded here:

- Deterministic ratios and closed state classification only: based solely on
  historical counts; no prediction, probability, ML, embeddings or LLM.
- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: efficiency state and improvement signal are closed
  sets.
- Bounded, privacy-safe: ratios are bounded to ``[0, 1]`` and only closed
  codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

RESEARCH_EFFICIENCY_RULE_VERSION = "r33-3"
RULE_VERSION = RESEARCH_EFFICIENCY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

EFFICIENCY_HIGH = "HIGH"
EFFICIENCY_MEDIUM = "MEDIUM"
EFFICIENCY_LOW = "LOW"
EFFICIENCY_UNKNOWN = "UNKNOWN"

EFFICIENCY_STATES: tuple[str, ...] = (
    EFFICIENCY_HIGH,
    EFFICIENCY_MEDIUM,
    EFFICIENCY_LOW,
    EFFICIENCY_UNKNOWN,
)

SIGNAL_NONE = "NONE"
SIGNAL_INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
SIGNAL_REDUCE_RECURRING_BLOCKERS = "REDUCE_RECURRING_BLOCKERS"
SIGNAL_CLOSE_EVIDENCE_GAPS = "CLOSE_EVIDENCE_GAPS"
SIGNAL_INCREASE_SUCCESSFUL_RESEARCH = "INCREASE_SUCCESSFUL_RESEARCH"

IMPROVEMENT_SIGNALS: tuple[str, ...] = (
    SIGNAL_NONE,
    SIGNAL_INSUFFICIENT_HISTORY,
    SIGNAL_REDUCE_RECURRING_BLOCKERS,
    SIGNAL_CLOSE_EVIDENCE_GAPS,
    SIGNAL_INCREASE_SUCCESSFUL_RESEARCH,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

RATIO_MIN = 0.0
RATIO_MAX = 1.0
RATIO_PRECISION = 4
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _coerce_ratio(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    if number != number:  # NaN guard
        number = 0.0
    return round(max(RATIO_MIN, min(RATIO_MAX, number)), RATIO_PRECISION)


def sanitize_research_efficiency_plan(value: object) -> dict:
    """Project an R33.3 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "efficiency_state": "",
            "successful_ratio": 0.0,
            "evidence_gap_ratio": 0.0,
            "recurring_blocker_ratio": 0.0,
            "improvement_signal": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "efficiency_state": _safe_text(value.get("efficiency_state")),
        "successful_ratio": _coerce_ratio(value.get("successful_ratio")),
        "evidence_gap_ratio": _coerce_ratio(value.get("evidence_gap_ratio")),
        "recurring_blocker_ratio": _coerce_ratio(
            value.get("recurring_blocker_ratio")
        ),
        "improvement_signal": _safe_text(value.get("improvement_signal")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchEfficiencyPlan(BaseModel):
    """Deterministic research efficiency measurement (R33.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_EFFICIENCY_RULE_VERSION
    efficiency_state: str
    successful_ratio: float = 0.0
    evidence_gap_ratio: float = 0.0
    recurring_blocker_ratio: float = 0.0
    improvement_signal: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_EFFICIENCY_RULE_VERSION

    @field_validator("efficiency_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EFFICIENCY_STATES:
            raise ValueError(f"invalid efficiency_state: {value!r}")
        return text

    @field_validator("improvement_signal")
    @classmethod
    def _valid_signal(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in IMPROVEMENT_SIGNALS:
            raise ValueError(f"invalid improvement_signal: {value!r}")
        return text

    @field_validator(
        "successful_ratio", "evidence_gap_ratio", "recurring_blocker_ratio",
    )
    @classmethod
    def _valid_ratio(cls, value: object) -> float:
        return _coerce_ratio(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "research efficiency plans are research-only"
            )
        return True


def research_efficiency_plan_projection(
    value: ResearchEfficiencyPlan,
) -> dict:
    """Serialize a research efficiency plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_EFFICIENCY_RULE_VERSION",
    "RULE_VERSION",
    "EFFICIENCY_STATES",
    "IMPROVEMENT_SIGNALS",
    "EFFICIENCY_HIGH",
    "EFFICIENCY_MEDIUM",
    "EFFICIENCY_LOW",
    "EFFICIENCY_UNKNOWN",
    "SIGNAL_NONE",
    "SIGNAL_INSUFFICIENT_HISTORY",
    "SIGNAL_REDUCE_RECURRING_BLOCKERS",
    "SIGNAL_CLOSE_EVIDENCE_GAPS",
    "SIGNAL_INCREASE_SUCCESSFUL_RESEARCH",
    "RATIO_MIN",
    "RATIO_MAX",
    "RATIO_PRECISION",
    "ResearchEfficiencyPlan",
    "sanitize_research_efficiency_plan",
    "research_efficiency_plan_projection",
]
