"""Stage R33.3 deterministic research efficiency intelligence (pure engine).

Measures research process efficiency from the read-only R32.2 history plan
(or the embedded history section of an R32.4 memory export):

    "How efficiently is research progressing across recorded history?"

This is an **efficiency signal only**. It never executes research, never
acquires evidence, never contacts a target, never calls an LLM and never
touches Mongo. It is based solely on historical counts: no prediction, no
probability, no ML, no embeddings.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic ratios (bounded ``[0, 1]``, fixed precision) and a closed
  state/improvement classification. Byte-identical repeated output.
- Read-only: inputs are never mutated; malformed counts degrade to zero.
- Privacy: only bounded ratios and closed codes are retained.
"""

from __future__ import annotations

from ai.schemas.research_efficiency import (
    EFFICIENCY_HIGH,
    EFFICIENCY_LOW,
    EFFICIENCY_MEDIUM,
    EFFICIENCY_UNKNOWN,
    RATIO_MAX,
    RATIO_PRECISION,
    RESEARCH_EFFICIENCY_RULE_VERSION,
    SIGNAL_CLOSE_EVIDENCE_GAPS,
    SIGNAL_INCREASE_SUCCESSFUL_RESEARCH,
    SIGNAL_INSUFFICIENT_HISTORY,
    SIGNAL_NONE,
    SIGNAL_REDUCE_RECURRING_BLOCKERS,
    ResearchEfficiencyPlan,
    research_efficiency_plan_projection,
)

RESEARCH_EFFICIENCY_PLANNER_RULE_VERSION = "r33-3"
RULE_VERSION = RESEARCH_EFFICIENCY_PLANNER_RULE_VERSION

HIGH_SUCCESS_RATIO = 0.5
LOW_SUCCESS_RATIO = 0.2
HIGH_BLOCKER_DENSITY = 0.25
HIGH_EVIDENCE_GAP_RATIO = 0.5


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _coerce_count(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(
        max(0.0, min(RATIO_MAX, numerator / denominator)), RATIO_PRECISION
    )


def _blocker_count(value: object) -> int:
    if isinstance(value, (list, tuple)):
        return len([item for item in value if str(item or "").strip()])
    return 0


def evaluate_research_efficiency(
    history_plan: object = None,
    *,
    memory_export: object = None,
) -> dict:
    """Measure efficiency from R32 history counts (read-only).

    ``history_plan`` is the R32.2 history plan; when absent, the embedded
    ``history`` section of the R32.4 ``memory_export`` is used. An empty or
    malformed history yields ``UNKNOWN`` / ``INSUFFICIENT_HISTORY``.
    """

    history = _block(history_plan) or _block(
        _block(memory_export).get("history")
    )

    total = _coerce_count(history.get("total_records"))
    successful = _coerce_count(history.get("successful_count"))
    waiting = _coerce_count(history.get("waiting_count"))
    recurring_blockers = _blocker_count(history.get("recurring_blockers"))

    successful_ratio = _ratio(successful, total)
    evidence_gap_ratio = _ratio(waiting, total)
    recurring_blocker_ratio = _ratio(recurring_blockers, total)

    if total == 0:
        state = EFFICIENCY_UNKNOWN
        improvement = SIGNAL_INSUFFICIENT_HISTORY
    else:
        if (
            successful_ratio >= HIGH_SUCCESS_RATIO
            and recurring_blocker_ratio == 0.0
            and evidence_gap_ratio < HIGH_EVIDENCE_GAP_RATIO
        ):
            state = EFFICIENCY_HIGH
        elif (
            successful_ratio < LOW_SUCCESS_RATIO
            or evidence_gap_ratio >= HIGH_EVIDENCE_GAP_RATIO
        ):
            state = EFFICIENCY_LOW
        else:
            state = EFFICIENCY_MEDIUM

        if recurring_blocker_ratio > 0:
            improvement = SIGNAL_REDUCE_RECURRING_BLOCKERS
        elif evidence_gap_ratio >= HIGH_EVIDENCE_GAP_RATIO:
            improvement = SIGNAL_CLOSE_EVIDENCE_GAPS
        elif successful_ratio < HIGH_SUCCESS_RATIO:
            improvement = SIGNAL_INCREASE_SUCCESSFUL_RESEARCH
        else:
            improvement = SIGNAL_NONE

    plan = ResearchEfficiencyPlan(
        rule_version=RESEARCH_EFFICIENCY_RULE_VERSION,
        efficiency_state=state,
        successful_ratio=successful_ratio,
        evidence_gap_ratio=evidence_gap_ratio,
        recurring_blocker_ratio=recurring_blocker_ratio,
        improvement_signal=improvement,
        research_only=True,
    )
    return research_efficiency_plan_projection(plan)


__all__ = [
    "RESEARCH_EFFICIENCY_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HIGH_SUCCESS_RATIO",
    "LOW_SUCCESS_RATIO",
    "HIGH_BLOCKER_DENSITY",
    "HIGH_EVIDENCE_GAP_RATIO",
    "evaluate_research_efficiency",
]
