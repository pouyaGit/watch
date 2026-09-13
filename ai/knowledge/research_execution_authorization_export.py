"""Stage R36.7 deterministic authorization export (pure engine).

Packages the complete R36 execution-safety boundary into the final bounded,
JSON-serializable export:

    "What authorization intelligence is ready for downstream consumers?"

Hard boundaries encoded here:

- Planning/authorization only: the export is advisory and never performs or
  schedules execution. No execution runtime, worker queue, scheduler,
  dispatch, subprocess, shell command, browser, network, Mongo persistence or
  LLM call is represented or created.
- ``ready`` is true only when the authorization, scope, risk, approval and
  boundary components are all present and non-UNKNOWN; any UNKNOWN critical
  state prevents readiness.
- Pure and offline: no I/O, no network, no LLM, no subprocess, no browser, no
  target interaction, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.execution_authorization_plan import (
    AUTHORIZATION_DECISIONS,
    DECISION_BLOCK,
    DECISION_UNKNOWN,
    sanitize_execution_authorization_plan,
    sanitize_source_orchestration_export,
    sanitize_source_strategy_export,
)
from ai.schemas.execution_boundary_plan import (
    BOUNDARY_STATES,
    BOUNDARY_UNKNOWN,
    BLOCKED_INVALID_WORKFLOW,
    sanitize_execution_boundary_plan,
)
from ai.schemas.execution_policy import (
    EXECUTION_POLICIES,
    sanitize_execution_policy_plan,
)
from ai.schemas.execution_risk import (
    RISK_LEVELS,
    RISK_UNKNOWN,
    sanitize_execution_risk_plan,
)
from ai.schemas.human_approval_gate import (
    APPROVAL_PENDING,
    APPROVAL_STATES,
    APPROVAL_UNKNOWN,
    sanitize_human_approval_gate_plan,
)
from ai.schemas.research_execution_authorization_export import (
    LIMITATION_BLOCKED,
    LIMITATION_HUMAN_APPROVAL_PENDING,
    LIMITATION_INVALID_WORKFLOW,
    LIMITATION_MISSING_SCOPE,
    LIMITATION_UNKNOWN_APPROVAL,
    LIMITATION_UNKNOWN_AUTHORIZATION,
    LIMITATION_UNKNOWN_BOUNDARY,
    LIMITATION_UNKNOWN_RISK,
    LIMITATION_UNKNOWN_SCOPE,
    RESEARCH_EXECUTION_AUTHORIZATION_EXPORT_RULE_VERSION,
    ResearchExecutionAuthorizationExportPlan,
    research_execution_authorization_export_plan_projection,
)
from ai.schemas.scope_capability_gate import (
    CAPABILITY_UNKNOWN,
    RESEARCH_CAPABILITIES,
    SCOPE_UNKNOWN,
    SCOPE_VALUES,
    sanitize_scope_capability_gate_plan,
)

RESEARCH_EXECUTION_AUTHORIZATION_EXPORTER_RULE_VERSION = "r36-7"
RULE_VERSION = RESEARCH_EXECUTION_AUTHORIZATION_EXPORTER_RULE_VERSION


def _safe_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = str(item if item is not None else "").strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def export_research_execution_authorization(
    policy_plan: object = None,
    authorization_plan: object = None,
    scope_plan: object = None,
    risk_plan: object = None,
    approval_plan: object = None,
    boundary_plan: object = None,
    strategy_export: object = None,
    orchestration_export: object = None,
) -> dict:
    """Package the complete R36 boundary into a deterministic export.

    ``ready`` is true only when every critical component is present and
    non-UNKNOWN. The export remains advisory/planning-only and never grants or
    performs execution.
    """

    policy = sanitize_execution_policy_plan(policy_plan)
    authorization = sanitize_execution_authorization_plan(
        authorization_plan
    )
    scope = sanitize_scope_capability_gate_plan(scope_plan)
    risk = sanitize_execution_risk_plan(risk_plan)
    approval = sanitize_human_approval_gate_plan(approval_plan)
    boundary = sanitize_execution_boundary_plan(boundary_plan)
    strategy_snapshot = sanitize_source_strategy_export(strategy_export)
    orchestration_snapshot = sanitize_source_orchestration_export(
        orchestration_export
    )

    policy_valid = policy.get("policy") in EXECUTION_POLICIES
    authorization_valid = (
        authorization.get("decision") in AUTHORIZATION_DECISIONS
        and authorization.get("decision") != DECISION_UNKNOWN
    )
    scope_valid = (
        scope.get("scope") in SCOPE_VALUES
        and scope.get("scope") != SCOPE_UNKNOWN
        and scope.get("capability") in RESEARCH_CAPABILITIES
    )
    risk_valid = (
        risk.get("risk_level") in RISK_LEVELS
        and risk.get("risk_level") != RISK_UNKNOWN
    )
    approval_valid = (
        approval.get("approval_state") in APPROVAL_STATES
        and approval.get("approval_state") != APPROVAL_UNKNOWN
    )
    boundary_valid = (
        boundary.get("boundary_state") in BOUNDARY_STATES
        and boundary.get("boundary_state") != BOUNDARY_UNKNOWN
    )
    ready = all((
        policy_valid,
        authorization_valid,
        scope_valid,
        risk_valid,
        approval_valid,
        boundary_valid,
    ))

    capabilities: list[str] = []
    if (
        scope.get("authorized")
        and scope.get("capability") in RESEARCH_CAPABILITIES
        and scope.get("capability") != CAPABILITY_UNKNOWN
    ):
        capabilities.append(scope["capability"])

    constraints: list[str] = []
    for source in (
        policy.get("constraints"),
        scope.get("constraints"),
        boundary.get("constraints"),
    ):
        for item in source or ():
            text = str(item if item is not None else "").strip().upper()
            if text and text not in constraints and len(constraints) < 8:
                constraints.append(text)

    limitations: list[str] = []
    if not authorization_valid:
        limitations.append(LIMITATION_UNKNOWN_AUTHORIZATION)
    if not risk_valid:
        limitations.append(LIMITATION_UNKNOWN_RISK)
    if not scope_valid:
        limitations.append(LIMITATION_UNKNOWN_SCOPE)
    if not approval_valid:
        limitations.append(LIMITATION_UNKNOWN_APPROVAL)
    if not boundary_valid:
        limitations.append(LIMITATION_UNKNOWN_BOUNDARY)
    if authorization.get("decision") == DECISION_BLOCK:
        limitations.append(LIMITATION_BLOCKED)
    if approval.get("approval_state") == APPROVAL_PENDING:
        limitations.append(LIMITATION_HUMAN_APPROVAL_PENDING)
    if scope.get("scope") == SCOPE_UNKNOWN:
        limitations.append(LIMITATION_MISSING_SCOPE)
    if BLOCKED_INVALID_WORKFLOW in (boundary.get("blocked_conditions") or ()):
        limitations.append(LIMITATION_INVALID_WORKFLOW)

    plan = ResearchExecutionAuthorizationExportPlan(
        rule_version=RESEARCH_EXECUTION_AUTHORIZATION_EXPORT_RULE_VERSION,
        ready=ready,
        authorization=authorization,
        policy=policy,
        risk=risk,
        scope=scope,
        capabilities=capabilities,
        human_approval=approval,
        constraints=constraints,
        source_strategy=strategy_snapshot,
        source_orchestration=orchestration_snapshot,
        execution_boundary=boundary,
        limitations=limitations,
        research_only=True,
    )
    return research_execution_authorization_export_plan_projection(plan)


__all__ = [
    "RESEARCH_EXECUTION_AUTHORIZATION_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "export_research_execution_authorization",
]
