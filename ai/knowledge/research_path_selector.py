"""Stage R34.2 deterministic research path selector (pure engine).

Converts a read-only R34.1 research strategy plan into an ordered research
path:

    "In what order should the preferred strategy be approached?"

This is a **planning path only**. It never executes research, never acquires
evidence, never contacts a target, never calls an LLM and never touches
Mongo. Every step is a planning label; no operational action is represented.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic mapping from the closed strategy vocabulary with byte-
  identical repeated output.
- Read-only: the strategy input is never mutated; unknown/malformed strategies
  yield a conservative path and are never silently upgraded.
- Privacy: only closed step codes are retained.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_LEVELS,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.research_path import (
    REASON_DEFERRED,
    REASON_EVIDENCE,
    REASON_HUMAN,
    REASON_IDENTITY,
    REASON_SCOPE,
    REASON_TECHNOLOGY,
    REASON_UNKNOWN,
    REASON_VERSION,
    RESEARCH_PATH_RULE_VERSION,
    STEP_COLLECT_EVIDENCE,
    STEP_HUMAN_REVIEW,
    STEP_IDENTIFY_ASSET,
    STEP_REVIEW_HISTORY,
    STEP_STOP,
    STEP_VERIFY_SCOPE,
    STEP_VERIFY_TECHNOLOGY,
    STEP_VERIFY_VERSION,
    ResearchPathPlan,
    research_path_plan_projection,
)
from ai.schemas.research_strategy import (
    STRATEGY_DEFERRED,
    STRATEGY_EVIDENCE_FIRST,
    STRATEGY_HUMAN_REVIEW_FIRST,
    STRATEGY_IDENTITY_FIRST,
    STRATEGY_SCOPE_FIRST,
    STRATEGY_TECHNOLOGY_FIRST,
    STRATEGY_UNKNOWN,
    STRATEGY_VERSION_FIRST,
)

RESEARCH_PATH_SELECTOR_RULE_VERSION = "r34-2"
RULE_VERSION = RESEARCH_PATH_SELECTOR_RULE_VERSION

# strategy -> (steps, path_reason)
STRATEGY_PATH: dict[str, tuple] = {
    STRATEGY_EVIDENCE_FIRST: (
        (STEP_COLLECT_EVIDENCE, STEP_REVIEW_HISTORY),
        REASON_EVIDENCE,
    ),
    STRATEGY_IDENTITY_FIRST: (
        (STEP_IDENTIFY_ASSET, STEP_COLLECT_EVIDENCE),
        REASON_IDENTITY,
    ),
    STRATEGY_TECHNOLOGY_FIRST: (
        (STEP_VERIFY_TECHNOLOGY, STEP_COLLECT_EVIDENCE),
        REASON_TECHNOLOGY,
    ),
    STRATEGY_VERSION_FIRST: (
        (STEP_VERIFY_VERSION, STEP_COLLECT_EVIDENCE),
        REASON_VERSION,
    ),
    STRATEGY_SCOPE_FIRST: (
        (STEP_VERIFY_SCOPE, STEP_COLLECT_EVIDENCE),
        REASON_SCOPE,
    ),
    STRATEGY_HUMAN_REVIEW_FIRST: ((STEP_HUMAN_REVIEW,), REASON_HUMAN),
    STRATEGY_DEFERRED: ((STEP_STOP,), REASON_DEFERRED),
    STRATEGY_UNKNOWN: ((STEP_REVIEW_HISTORY,), REASON_UNKNOWN),
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def select_research_path(strategy_plan: object = None) -> dict:
    """Map a strategy to a deterministic ordered path (read-only).

    Missing/malformed strategy input yields the conservative
    ``UNKNOWN_STRATEGY`` path with confidence ``UNKNOWN``.
    """

    strategy = _block(strategy_plan)
    strategy_type = _upper(strategy.get("strategy_type"))
    confidence = _upper(strategy.get("confidence_level"))
    if confidence not in CONFIDENCE_LEVELS:
        confidence = CONFIDENCE_UNKNOWN

    steps, reason = STRATEGY_PATH.get(
        strategy_type, STRATEGY_PATH[STRATEGY_UNKNOWN]
    )

    plan = ResearchPathPlan(
        rule_version=RESEARCH_PATH_RULE_VERSION,
        selected_path=list(steps),
        primary_path=steps[0],
        path_reason=reason,
        confidence_level=confidence,
        research_only=True,
    )
    return research_path_plan_projection(plan)


__all__ = [
    "RESEARCH_PATH_SELECTOR_RULE_VERSION",
    "RULE_VERSION",
    "STRATEGY_PATH",
    "select_research_path",
]
