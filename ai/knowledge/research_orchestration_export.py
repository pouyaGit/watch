"""Stage R35.4 deterministic research orchestration exporter (pure engine).

Creates the final read-only export over the R35.1 role plan, R35.2 workflow
graph and R35.3 coordination plan:

    "What conceptual orchestration intelligence is ready?"

This is an **export signal only**. It creates no agent runtime, no worker
queue, no scheduler and no dispatch. It never executes research, never
acquires evidence, never contacts a target, never calls an LLM and never
touches Mongo.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic readiness rule and fixed limitation order with byte-identical
  repeated output.
- Conservative: ``ready`` requires all three R35 plans to be present and
  valid; missing/malformed inputs are never silently upgraded.
- Read-only and privacy-safe: inputs are never mutated; embedded plans are
  bounded, sanitized snapshots.
"""

from __future__ import annotations

from ai.schemas.agent_coordination import (
    COORDINATION_MODES,
    MODE_REVIEW_GATE,
    MODE_UNKNOWN,
    sanitize_agent_coordination_plan,
)
from ai.schemas.agent_role_plan import (
    AGENT_ROLES,
    ROLE_REASONS,
    sanitize_agent_role_plan,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_LEVELS,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.research_orchestration_export import (
    LIMITATION_DEFERRED_STRATEGY,
    LIMITATION_EMPTY_WORKFLOW,
    LIMITATION_LOW_CONFIDENCE,
    LIMITATION_UNKNOWN_COORDINATION,
    LIMITATION_UNKNOWN_STRATEGY,
    RESEARCH_ORCHESTRATION_EXPORT_RULE_VERSION,
    ResearchOrchestrationExportPlan,
    research_orchestration_export_plan_projection,
)
from ai.schemas.research_workflow_graph import (
    sanitize_research_workflow_graph_plan,
)

RESEARCH_ORCHESTRATION_EXPORTER_RULE_VERSION = "r35-4"
RULE_VERSION = RESEARCH_ORCHESTRATION_EXPORTER_RULE_VERSION


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def export_research_orchestration(
    role_plan: object = None,
    workflow_plan: object = None,
    coordination_plan: object = None,
) -> dict:
    """Package the three R35 plans into a deterministic export.

    ``ready`` is ``True`` only when the role plan, workflow graph and
    coordination plan are all present and carry valid closed vocabularies.
    Limitations are emitted in a fixed order.
    """

    roles = sanitize_agent_role_plan(role_plan)
    workflow = sanitize_research_workflow_graph_plan(workflow_plan)
    coordination = sanitize_agent_coordination_plan(coordination_plan)

    roles_valid = (
        isinstance(role_plan, dict)
        and bool(role_plan)
        and bool(roles.get("required_roles"))
        and roles.get("primary_role") in AGENT_ROLES
        and roles.get("role_reason") in ROLE_REASONS
        and roles.get("confidence_level") in CONFIDENCE_LEVELS
    )
    workflow_valid = (
        isinstance(workflow_plan, dict)
        and bool(workflow_plan)
        and bool(workflow.get("nodes"))
        and isinstance(workflow.get("edges"), list)
        and bool(workflow.get("entry_nodes"))
        and bool(workflow.get("terminal_nodes"))
    )
    coordination_valid = (
        isinstance(coordination_plan, dict)
        and bool(coordination_plan)
        and coordination.get("coordination_mode") in COORDINATION_MODES
        and bool(coordination.get("role_sequence"))
    )
    ready = roles_valid and workflow_valid and coordination_valid

    limitations: list[str] = []
    if (
        roles.get("role_reason") not in ROLE_REASONS
        or roles.get("role_reason") == "UNKNOWN_STRATEGY"
    ):
        limitations.append(LIMITATION_UNKNOWN_STRATEGY)
    if (
        roles.get("confidence_level") not in CONFIDENCE_LEVELS
        or roles.get("confidence_level")
        in (CONFIDENCE_LOW, CONFIDENCE_UNKNOWN)
    ):
        limitations.append(LIMITATION_LOW_CONFIDENCE)
    if (
        roles.get("role_reason") == "DEFERRED_STRATEGY"
        or coordination.get("coordination_mode") == MODE_REVIEW_GATE
    ):
        limitations.append(LIMITATION_DEFERRED_STRATEGY)
    if (
        coordination.get("coordination_mode") not in COORDINATION_MODES
        or coordination.get("coordination_mode") == MODE_UNKNOWN
    ):
        limitations.append(LIMITATION_UNKNOWN_COORDINATION)
    if not workflow.get("nodes"):
        limitations.append(LIMITATION_EMPTY_WORKFLOW)

    plan = ResearchOrchestrationExportPlan(
        rule_version=RESEARCH_ORCHESTRATION_EXPORT_RULE_VERSION,
        ready=ready,
        roles=roles,
        workflow=workflow,
        coordination=coordination,
        limitations=limitations,
        research_only=True,
    )
    return research_orchestration_export_plan_projection(plan)


__all__ = [
    "RESEARCH_ORCHESTRATION_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "export_research_orchestration",
]
