"""Stage R34.3 deterministic research budget planner (pure engine).

Determines whether research should continue, pause, or stop from the
read-only R34.1 strategy plan, R34.2 path plan, R33.4 learning export and
R32.4 memory export:

    "How much further research budget should this candidate receive?"

This is a **budget state only**. It never executes research, never acquires
evidence, never contacts a target, never calls an LLM and never touches
Mongo. The state is an advisory planning label, never an execution
authorization, and never modifies the Money Score or R29 queue.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic precedence over closed vocabularies with byte-identical
  repeated output.
- Conservative: deferred strategies and repeated blockers downgrade the
  budget first; malformed input yields ``UNKNOWN``.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LEVELS,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.research_budget import (
    BUDGET_CONTINUE,
    BUDGET_LIMITED,
    BUDGET_PAUSE,
    BUDGET_STOP,
    BUDGET_UNKNOWN,
    REASON_DEFERRED_STRATEGY,
    REASON_HIGH_CONFIDENCE_SUCCESS,
    REASON_LOW_CONFIDENCE,
    REASON_MEDIUM_CONFIDENCE,
    REASON_REPEATED_BLOCKERS,
    REASON_UNKNOWN_CONFIDENCE,
    RESEARCH_BUDGET_RULE_VERSION,
    STEP_HUMAN_REVIEW,
    STEP_MORE_ANALYSIS,
    STEP_MORE_EVIDENCE,
    STEP_NONE,
    STEP_UNKNOWN,
    ResearchBudgetPlan,
    research_budget_plan_projection,
)
from ai.schemas.research_path import STEP_STOP
from ai.schemas.research_strategy import STRATEGY_DEFERRED

RESEARCH_BUDGET_PLANNER_RULE_VERSION = "r34-3"
RULE_VERSION = RESEARCH_BUDGET_PLANNER_RULE_VERSION

# budget state -> allowed next step
BUDGET_NEXT_STEP: dict[str, str] = {
    BUDGET_CONTINUE: STEP_MORE_EVIDENCE,
    BUDGET_LIMITED: STEP_MORE_ANALYSIS,
    BUDGET_PAUSE: STEP_HUMAN_REVIEW,
    BUDGET_STOP: STEP_NONE,
    BUDGET_UNKNOWN: STEP_UNKNOWN,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _closed(value: object, allowed: tuple) -> str:
    text = _upper(value)
    return text if text in allowed else ""


def _positive_ranking(ranking: dict) -> bool:
    scores = ranking.get("candidate_scores")
    if not isinstance(scores, (list, tuple)):
        return False
    for entry in scores:
        if isinstance(entry, dict):
            try:
                if int(entry.get("score")) > 0:
                    return True
            except (TypeError, ValueError):
                continue
    return False


def _result(state: str, reason: str) -> dict:
    plan = ResearchBudgetPlan(
        rule_version=RESEARCH_BUDGET_RULE_VERSION,
        budget_state=state,
        reason=reason,
        allowed_next_step=BUDGET_NEXT_STEP[state],
        research_only=True,
    )
    return research_budget_plan_projection(plan)


def plan_research_budget(
    strategy_plan: object = None,
    path_plan: object = None,
    learning_export: object = None,
    memory_export: object = None,
) -> dict:
    """Determine the deterministic research budget state (read-only).

    Precedence: deferred strategy/path -> STOP; recurring blockers -> PAUSE;
    high confidence with successful feedback -> CONTINUE; medium confidence ->
    LIMITED; low confidence -> LIMITED; unknown -> UNKNOWN.
    """

    strategy = _block(strategy_plan)
    path = _block(path_plan)
    learning = _block(learning_export)
    memory = _block(memory_export)

    strategy_type = _upper(strategy.get("strategy_type"))
    primary_step = _upper(path.get("primary_path"))
    confidence = _closed(
        strategy.get("confidence_level"), CONFIDENCE_LEVELS
    ) or CONFIDENCE_UNKNOWN

    efficiency = _block(learning.get("efficiency"))
    ranking = _block(learning.get("ranking"))
    history = _block(memory.get("history"))
    recurring = history.get("recurring_blockers")
    has_recurring_blockers = (
        isinstance(recurring, (list, tuple))
        and any(_text(code) for code in recurring)
    )
    successful_feedback = (
        _positive_ranking(ranking)
        or _upper(efficiency.get("efficiency_state")) == CONFIDENCE_HIGH
    )

    if strategy_type == STRATEGY_DEFERRED or primary_step == STEP_STOP:
        return _result(BUDGET_STOP, REASON_DEFERRED_STRATEGY)
    if has_recurring_blockers:
        return _result(BUDGET_PAUSE, REASON_REPEATED_BLOCKERS)
    if confidence == CONFIDENCE_HIGH and successful_feedback:
        return _result(BUDGET_CONTINUE, REASON_HIGH_CONFIDENCE_SUCCESS)
    if confidence == CONFIDENCE_MEDIUM:
        return _result(BUDGET_LIMITED, REASON_MEDIUM_CONFIDENCE)
    if confidence == CONFIDENCE_LOW:
        return _result(BUDGET_LIMITED, REASON_LOW_CONFIDENCE)
    return _result(BUDGET_UNKNOWN, REASON_UNKNOWN_CONFIDENCE)


__all__ = [
    "RESEARCH_BUDGET_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "BUDGET_NEXT_STEP",
    "plan_research_budget",
]
