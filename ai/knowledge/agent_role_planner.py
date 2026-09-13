"""Stage R35.1 deterministic agent role planner (pure engine).

Consumes the read-only R34.1 research strategy plan (or its R34.4 export
context) and determines which conceptual research roles are needed:

    "Which conceptual research roles does this strategy require?"

This is an **orchestration planning signal only**. It creates no agent
runtime, no worker queue, no scheduler and no task dispatch. It never
executes research, never acquires evidence, never contacts a target, never
calls an LLM and never touches Mongo.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic closed strategy -> role mapping with byte-identical repeated
  output.
- Read-only: inputs are never mutated; unknown/malformed strategies map to
  the conservative history-analysis roles.
- Privacy: only closed role codes are retained.
"""

from __future__ import annotations

from ai.schemas.agent_role_plan import (
    AGENT_ROLE_PLAN_RULE_VERSION,
    AgentRolePlan,
    REASON_DEFERRED,
    REASON_EVIDENCE,
    REASON_HUMAN,
    REASON_IDENTITY,
    REASON_SCOPE,
    REASON_TECHNOLOGY,
    REASON_UNKNOWN,
    REASON_VERSION,
    ROLE_ASSET_ANALYSIS,
    ROLE_EVIDENCE_ANALYSIS,
    ROLE_HISTORY_ANALYSIS,
    ROLE_HUMAN_REVIEW,
    ROLE_IDENTITY_ANALYSIS,
    ROLE_TECHNOLOGY_ANALYSIS,
    ROLE_VERSION_ANALYSIS,
    agent_role_plan_projection,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_LEVELS,
    CONFIDENCE_UNKNOWN,
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

AGENT_ROLE_PLANNER_RULE_VERSION = "r35-1"
RULE_VERSION = AGENT_ROLE_PLANNER_RULE_VERSION

# strategy -> (ordered roles, role_reason)
STRATEGY_ROLES: dict[str, tuple] = {
    STRATEGY_IDENTITY_FIRST: (
        (ROLE_ASSET_ANALYSIS, ROLE_IDENTITY_ANALYSIS),
        REASON_IDENTITY,
    ),
    STRATEGY_VERSION_FIRST: (
        (ROLE_VERSION_ANALYSIS, ROLE_EVIDENCE_ANALYSIS),
        REASON_VERSION,
    ),
    STRATEGY_TECHNOLOGY_FIRST: (
        (ROLE_TECHNOLOGY_ANALYSIS, ROLE_EVIDENCE_ANALYSIS),
        REASON_TECHNOLOGY,
    ),
    STRATEGY_EVIDENCE_FIRST: (
        (ROLE_EVIDENCE_ANALYSIS, ROLE_HISTORY_ANALYSIS),
        REASON_EVIDENCE,
    ),
    STRATEGY_SCOPE_FIRST: (
        (ROLE_ASSET_ANALYSIS, ROLE_EVIDENCE_ANALYSIS),
        REASON_SCOPE,
    ),
    STRATEGY_HUMAN_REVIEW_FIRST: ((ROLE_HUMAN_REVIEW,), REASON_HUMAN),
    STRATEGY_DEFERRED: ((ROLE_HUMAN_REVIEW,), REASON_DEFERRED),
    STRATEGY_UNKNOWN: ((ROLE_HISTORY_ANALYSIS,), REASON_UNKNOWN),
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def plan_agent_roles(strategy_plan: object = None) -> dict:
    """Map a strategy to a deterministic conceptual role plan (read-only).

    Missing/malformed strategy input yields the conservative
    ``HISTORY_ANALYSIS`` role with confidence ``UNKNOWN``.
    """

    strategy = _block(strategy_plan)
    strategy_type = _upper(strategy.get("strategy_type"))
    confidence = _upper(strategy.get("confidence_level"))
    if confidence not in CONFIDENCE_LEVELS:
        confidence = CONFIDENCE_UNKNOWN

    roles, reason = STRATEGY_ROLES.get(
        strategy_type, STRATEGY_ROLES[STRATEGY_UNKNOWN]
    )

    plan = AgentRolePlan(
        rule_version=AGENT_ROLE_PLAN_RULE_VERSION,
        required_roles=list(roles),
        primary_role=roles[0],
        role_reason=reason,
        confidence_level=confidence,
        research_only=True,
    )
    return agent_role_plan_projection(plan)


__all__ = [
    "AGENT_ROLE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "STRATEGY_ROLES",
    "plan_agent_roles",
]
