"""Stage R35.2 deterministic research workflow graph builder (pure engine).

Consumes the read-only R34.1 research strategy plan (with the R35.1 role plan
as a fallback strategy hint) and builds an ordered, acyclic planning graph:

    "In what dependency order should the conceptual research nodes run?"

This is a **planning graph only**. It creates no agent runtime, no worker
queue, no scheduler and no dispatch. It never executes research, never
acquires evidence, never contacts a target, never calls an LLM and never
touches Mongo.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic, acyclic, ordered: a closed strategy -> node-chain mapping
  with edge generation from consecutive nodes and byte-identical repeated
  output.
- Read-only: inputs are never mutated; unknown/malformed strategies map to
  the conservative history-review chain.
- Privacy: only closed node codes are retained.
"""

from __future__ import annotations

from ai.knowledge.agent_role_planner import STRATEGY_ROLES
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
from ai.schemas.research_workflow_graph import (
    NODE_ANALYZE_ASSET,
    NODE_ANALYZE_IDENTITY,
    NODE_ANALYZE_TECHNOLOGY,
    NODE_ANALYZE_VERSION,
    NODE_COLLECT_EVIDENCE_PLAN,
    NODE_HUMAN_REVIEW,
    NODE_REVIEW_HISTORY,
    NODE_STOP,
    RESEARCH_WORKFLOW_GRAPH_RULE_VERSION,
    ResearchWorkflowGraphPlan,
    research_workflow_graph_plan_projection,
)

RESEARCH_WORKFLOW_GRAPH_BUILDER_RULE_VERSION = "r35-2"
RULE_VERSION = RESEARCH_WORKFLOW_GRAPH_BUILDER_RULE_VERSION

# strategy -> ordered workflow node chain
STRATEGY_WORKFLOW: dict[str, tuple] = {
    STRATEGY_IDENTITY_FIRST: (
        NODE_ANALYZE_ASSET,
        NODE_ANALYZE_IDENTITY,
        NODE_COLLECT_EVIDENCE_PLAN,
    ),
    STRATEGY_VERSION_FIRST: (
        NODE_ANALYZE_VERSION,
        NODE_COLLECT_EVIDENCE_PLAN,
        NODE_REVIEW_HISTORY,
    ),
    STRATEGY_TECHNOLOGY_FIRST: (
        NODE_ANALYZE_TECHNOLOGY,
        NODE_COLLECT_EVIDENCE_PLAN,
        NODE_REVIEW_HISTORY,
    ),
    STRATEGY_EVIDENCE_FIRST: (
        NODE_COLLECT_EVIDENCE_PLAN,
        NODE_REVIEW_HISTORY,
    ),
    STRATEGY_SCOPE_FIRST: (
        NODE_ANALYZE_ASSET,
        NODE_COLLECT_EVIDENCE_PLAN,
        NODE_REVIEW_HISTORY,
    ),
    STRATEGY_HUMAN_REVIEW_FIRST: (NODE_HUMAN_REVIEW,),
    STRATEGY_DEFERRED: (NODE_STOP,),
    STRATEGY_UNKNOWN: (NODE_REVIEW_HISTORY,),
}

# R35.1 role reason -> strategy (single source: R35.1 STRATEGY_ROLES).
REASON_TO_STRATEGY: dict[str, str] = {
    reason: strategy
    for strategy, (_roles, reason) in STRATEGY_ROLES.items()
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def build_research_workflow_graph(
    strategy_plan: object = None,
    role_plan: object = None,
) -> dict:
    """Build a deterministic workflow graph from a strategy (read-only).

    ``strategy_plan`` is authoritative; when absent, the R35.1 role plan's
    ``role_reason`` is decoded back to its strategy. Missing/malformed input
    yields the conservative ``REVIEW_HISTORY`` single-node graph.
    """

    strategy = _block(strategy_plan)
    strategy_type = _upper(strategy.get("strategy_type"))
    if strategy_type not in STRATEGY_WORKFLOW:
        reason = _upper(_block(role_plan).get("role_reason"))
        strategy_type = REASON_TO_STRATEGY.get(reason, STRATEGY_UNKNOWN)

    nodes = STRATEGY_WORKFLOW.get(
        strategy_type, STRATEGY_WORKFLOW[STRATEGY_UNKNOWN]
    )
    edges = [
        {"from": nodes[index], "to": nodes[index + 1]}
        for index in range(len(nodes) - 1)
    ]

    plan = ResearchWorkflowGraphPlan(
        rule_version=RESEARCH_WORKFLOW_GRAPH_RULE_VERSION,
        nodes=list(nodes),
        edges=edges,
        entry_nodes=[nodes[0]],
        terminal_nodes=[nodes[-1]],
        research_only=True,
    )
    return research_workflow_graph_plan_projection(plan)


__all__ = [
    "RESEARCH_WORKFLOW_GRAPH_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "STRATEGY_WORKFLOW",
    "REASON_TO_STRATEGY",
    "build_research_workflow_graph",
]
