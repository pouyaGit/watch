"""Stage R35.3 deterministic agent coordination planner (pure engine).

Consumes the read-only R34.1 strategy plan, R35.1 role plan and R34.3 budget
plan and describes conceptual coordination:

    "How would the conceptual research roles coordinate?"

This is a **conceptual coordination signal only**. It creates no agent
runtime, no real agent communication, no worker queue, no scheduler and no
task dispatch. It never executes research, never acquires evidence, never
contacts a target, never calls an LLM and never touches Mongo.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic closed mode selection with byte-identical repeated output.
- Conservative: unknown/invalid strategy or absent roles yield ``UNKNOWN``;
  deferred strategies yield a ``REVIEW_GATE``; an explicit halting budget
  without deferral yields ``STOPPED``.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.agent_coordination import (
    AGENT_COORDINATION_RULE_VERSION,
    AgentCoordinationPlan,
    MODE_REVIEW_GATE,
    MODE_SEQUENTIAL,
    MODE_STOPPED,
    MODE_UNKNOWN,
    agent_coordination_plan_projection,
)
from ai.schemas.agent_role_plan import AGENT_ROLES
from ai.schemas.research_budget import BUDGET_STOP
from ai.schemas.research_strategy import (
    STRATEGY_DEFERRED,
    STRATEGY_TYPES,
    STRATEGY_UNKNOWN,
)

AGENT_COORDINATION_PLANNER_RULE_VERSION = "r35-3"
RULE_VERSION = AGENT_COORDINATION_PLANNER_RULE_VERSION


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _role_sequence(role_plan: dict) -> list[str]:
    out: list[str] = []
    for item in role_plan.get("required_roles") or ():
        role = _upper(item)
        if role in AGENT_ROLES and role not in out:
            out.append(role)
    return out


def plan_agent_coordination(
    strategy_plan: object = None,
    role_plan: object = None,
    workflow_plan: object = None,
    budget_plan: object = None,
) -> dict:
    """Describe deterministic conceptual role coordination (read-only).

    ``strategy_plan`` and ``role_plan`` drive the mode: a missing/unknown
    strategy or an empty role sequence yields ``UNKNOWN``; a deferred strategy
    yields ``REVIEW_GATE``; an explicit ``STOP`` budget yields ``STOPPED``;
    otherwise ``SEQUENTIAL``. ``workflow_plan`` is accepted for pipeline
    parity and never changes the mode.
    """

    strategy = _block(strategy_plan)
    role_block = _block(role_plan)
    budget = _block(budget_plan)

    strategy_type = _upper(strategy.get("strategy_type"))
    budget_state = _upper(budget.get("budget_state"))
    roles = _role_sequence(role_block)

    if (
        strategy_type not in STRATEGY_TYPES
        or strategy_type == STRATEGY_UNKNOWN
        or not roles
    ):
        mode = MODE_UNKNOWN
    elif strategy_type == STRATEGY_DEFERRED:
        mode = MODE_REVIEW_GATE
    elif budget_state == BUDGET_STOP:
        mode = MODE_STOPPED
    else:
        mode = MODE_SEQUENTIAL

    dependencies = [
        {"role": roles[index + 1], "depends_on": roles[index]}
        for index in range(len(roles) - 1)
    ]
    handoff_points = [
        {"from": roles[index], "to": roles[index + 1]}
        for index in range(len(roles) - 1)
    ]

    plan = AgentCoordinationPlan(
        rule_version=AGENT_COORDINATION_RULE_VERSION,
        coordination_mode=mode,
        role_sequence=roles,
        dependencies=dependencies,
        handoff_points=handoff_points,
        research_only=True,
    )
    return agent_coordination_plan_projection(plan)


__all__ = [
    "AGENT_COORDINATION_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "plan_agent_coordination",
]
