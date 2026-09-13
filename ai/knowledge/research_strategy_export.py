"""Stage R34.4 deterministic research strategy exporter (pure engine).

Creates the final read-only export over the R34.1 strategy, R34.2 path and
R34.3 budget plans:

    "What strategy intelligence is ready for the next research step?"

This is an **export signal only**. It never executes research, never acquires
evidence, never contacts a target, never calls an LLM and never touches Mongo.
It never uses or modifies the Money Score and never modifies the R29 queue.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic readiness rule and fixed limitation order with byte-identical
  repeated output.
- Conservative: ``ready`` requires all three R34 plans to be present and
  valid; missing/malformed inputs are never silently upgraded.
- Read-only and privacy-safe: inputs are never mutated; embedded plans are
  bounded, sanitized snapshots.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_LEVELS,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.research_budget import (
    BUDGET_PAUSE,
    BUDGET_STATES,
    BUDGET_UNKNOWN,
    ALLOWED_NEXT_STEPS,
    sanitize_research_budget_plan,
)
from ai.schemas.research_path import (
    PATH_REASONS,
    PATH_STEPS,
    sanitize_research_path_plan,
)
from ai.schemas.research_strategy import (
    HISTORICAL_BASES,
    STRATEGY_DEFERRED,
    STRATEGY_REASONS,
    STRATEGY_TYPES,
    STRATEGY_UNKNOWN,
    sanitize_research_strategy_plan,
)
from ai.schemas.research_strategy_export import (
    LIMITATION_DEFERRED_STRATEGY,
    LIMITATION_LOW_CONFIDENCE,
    LIMITATION_REPEATED_BLOCKERS,
    LIMITATION_UNKNOWN_BUDGET,
    LIMITATION_UNKNOWN_STRATEGY,
    RESEARCH_STRATEGY_EXPORT_RULE_VERSION,
    ResearchStrategyExportPlan,
    research_strategy_export_plan_projection,
)

RESEARCH_STRATEGY_EXPORTER_RULE_VERSION = "r34-4"
RULE_VERSION = RESEARCH_STRATEGY_EXPORTER_RULE_VERSION


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def export_research_strategy(
    strategy_plan: object = None,
    path_plan: object = None,
    budget_plan: object = None,
) -> dict:
    """Package the three R34 plans into a deterministic strategy export.

    ``ready`` is ``True`` only when the strategy, path and budget plans are
    all present and carry valid closed vocabularies. Limitations are emitted
    in a fixed order.
    """

    strategy = sanitize_research_strategy_plan(strategy_plan)
    path = sanitize_research_path_plan(path_plan)
    budget = sanitize_research_budget_plan(budget_plan)

    strategy_valid = (
        isinstance(strategy_plan, dict)
        and bool(strategy_plan)
        and strategy.get("strategy_type") in STRATEGY_TYPES
        and strategy.get("strategy_reason") in STRATEGY_REASONS
        and strategy.get("historical_basis") in HISTORICAL_BASES
        and strategy.get("confidence_level") in CONFIDENCE_LEVELS
    )
    path_valid = (
        isinstance(path_plan, dict)
        and bool(path_plan)
        and path.get("primary_path") in PATH_STEPS
        and path.get("path_reason") in PATH_REASONS
        and isinstance(path.get("selected_path"), list)
        and bool(path.get("selected_path"))
        and path.get("confidence_level") in CONFIDENCE_LEVELS
    )
    budget_valid = (
        isinstance(budget_plan, dict)
        and bool(budget_plan)
        and budget.get("budget_state") in BUDGET_STATES
        and budget.get("allowed_next_step") in ALLOWED_NEXT_STEPS
    )
    ready = strategy_valid and path_valid and budget_valid

    limitations: list[str] = []
    if (
        strategy.get("strategy_type") not in STRATEGY_TYPES
        or strategy.get("strategy_type") == STRATEGY_UNKNOWN
    ):
        limitations.append(LIMITATION_UNKNOWN_STRATEGY)
    if (
        strategy.get("confidence_level") not in CONFIDENCE_LEVELS
        or strategy.get("confidence_level")
        in (CONFIDENCE_LOW, CONFIDENCE_UNKNOWN)
    ):
        limitations.append(LIMITATION_LOW_CONFIDENCE)
    if strategy.get("strategy_type") == STRATEGY_DEFERRED:
        limitations.append(LIMITATION_DEFERRED_STRATEGY)
    if budget.get("budget_state") == BUDGET_PAUSE:
        limitations.append(LIMITATION_REPEATED_BLOCKERS)
    if (
        budget.get("budget_state") not in BUDGET_STATES
        or budget.get("budget_state") == BUDGET_UNKNOWN
    ):
        limitations.append(LIMITATION_UNKNOWN_BUDGET)

    plan = ResearchStrategyExportPlan(
        rule_version=RESEARCH_STRATEGY_EXPORT_RULE_VERSION,
        ready=ready,
        strategy=strategy,
        path=path,
        budget=budget,
        limitations=limitations,
        research_only=True,
    )
    return research_strategy_export_plan_projection(plan)


__all__ = [
    "RESEARCH_STRATEGY_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "export_research_strategy",
]
