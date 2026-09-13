"""Stage R36.6 deterministic execution boundary planner (pure engine).

Defines the explicit boundary between R35 research orchestration, R36
authorization and any future execution layer:

    "Where exactly is the execution boundary for this candidate?"

Hard boundaries encoded here:

- Planning/authorization only: the boundary is a closed planning label. No
  execution runtime, worker queue, scheduler, dispatch, subprocess, shell
  command, browser, network, Mongo persistence or LLM call is represented or
  created.
- R36 performs no execution: ``execution_performed`` is always ``False``.
  ``execution_permitted`` is a forward-looking eligibility flag only.
- Pure and offline: no I/O, no network, no LLM, no subprocess, no browser, no
  target interaction, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.execution_authorization_plan import (
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_LIMITS,
    DECISION_BLOCK,
    DECISION_REQUIRE_HUMAN_APPROVAL,
)
from ai.schemas.execution_boundary_plan import (
    BLOCKED_APPROVAL_EXPIRED,
    BLOCKED_APPROVAL_PENDING,
    BLOCKED_APPROVAL_REJECTED,
    BLOCKED_INVALID_WORKFLOW,
    BLOCKED_MISSING_SCOPE,
    BLOCKED_POLICY,
    BLOCKED_UNKNOWN_CONTEXT,
    BOUNDARY_AUTHORIZED,
    BOUNDARY_BLOCKED,
    BOUNDARY_HUMAN_REVIEW_REQUIRED,
    BOUNDARY_LIMITATION_AUTHORIZATION_ONLY,
    BOUNDARY_LIMITATION_BLOCKED,
    BOUNDARY_LIMITATION_HUMAN_APPROVAL,
    BOUNDARY_LIMITATION_PLAN_ONLY,
    BOUNDARY_LIMITATION_RESEARCH_ONLY,
    BOUNDARY_LIMITATION_UNKNOWN,
    BOUNDARY_RESEARCH_ONLY,
    BOUNDARY_UNKNOWN,
    EXECUTION_BOUNDARY_RULE_VERSION,
    ExecutionBoundaryPlan,
    execution_boundary_plan_projection,
)
from ai.schemas.execution_policy import POLICY_BLOCKED
from ai.schemas.execution_risk import RISK_UNKNOWN
from ai.schemas.human_approval_gate import (
    APPROVAL_APPROVED,
    APPROVAL_EXPIRED,
    APPROVAL_NOT_REQUIRED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
)
from ai.schemas.scope_capability_gate import (
    CAPABILITY_UNKNOWN,
    SCOPE_UNKNOWN,
)

EXECUTION_BOUNDARY_PLANNER_RULE_VERSION = "r36-6"
RULE_VERSION = EXECUTION_BOUNDARY_PLANNER_RULE_VERSION


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def plan_execution_boundary(
    authorization_plan: object = None,
    scope_plan: object = None,
    risk_plan: object = None,
    approval_plan: object = None,
    policy_plan: object = None,
    strategy_export: object = None,
    orchestration_export: object = None,
) -> dict:
    """Define the deterministic execution boundary (read-only).

    A BLOCK decision yields ``BLOCKED``; REQUIRE_HUMAN_APPROVAL (or an
    unresolved required approval) yields ``HUMAN_REVIEW_REQUIRED``; ALLOW with
    a satisfied approval yields ``AUTHORIZED``; ALLOW_WITH_LIMITS yields
    ``RESEARCH_ONLY``; unknown/missing context yields ``UNKNOWN``. R36 never
    performs execution.
    """

    authorization = _block(authorization_plan)
    scope = _block(scope_plan)
    risk = _block(risk_plan)
    approval = _block(approval_plan)
    policy = _block(policy_plan)

    decision = _upper(authorization.get("decision"))
    approval_state = _upper(approval.get("approval_state"))
    approval_required = bool(approval.get("required"))
    scope_value = _upper(scope.get("scope"))
    capability = _upper(scope.get("capability"))
    authorized = bool(scope.get("authorized"))
    risk_level = _upper(risk.get("risk_level"))

    if decision == DECISION_BLOCK:
        boundary = BOUNDARY_BLOCKED
    elif decision == DECISION_REQUIRE_HUMAN_APPROVAL:
        boundary = BOUNDARY_HUMAN_REVIEW_REQUIRED
    elif decision == DECISION_ALLOW_WITH_LIMITS:
        boundary = BOUNDARY_RESEARCH_ONLY
    elif decision == DECISION_ALLOW:
        if approval_required and approval_state not in (
            APPROVAL_APPROVED, APPROVAL_NOT_REQUIRED,
        ):
            boundary = BOUNDARY_HUMAN_REVIEW_REQUIRED
        else:
            boundary = BOUNDARY_AUTHORIZED
    else:
        boundary = BOUNDARY_UNKNOWN

    blocked_conditions: list[str] = []
    if _upper(policy.get("policy")) == POLICY_BLOCKED or (
        decision == DECISION_BLOCK
    ):
        blocked_conditions.append(BLOCKED_POLICY)
    if scope_value == SCOPE_UNKNOWN:
        blocked_conditions.append(BLOCKED_MISSING_SCOPE)
    if approval_state == APPROVAL_PENDING:
        blocked_conditions.append(BLOCKED_APPROVAL_PENDING)
    elif approval_state == APPROVAL_REJECTED:
        blocked_conditions.append(BLOCKED_APPROVAL_REJECTED)
    elif approval_state == APPROVAL_EXPIRED:
        blocked_conditions.append(BLOCKED_APPROVAL_EXPIRED)

    workflow = _block(_block(orchestration_export).get("workflow"))
    nodes = workflow.get("nodes")
    if not isinstance(nodes, (list, tuple)) or not list(nodes):
        blocked_conditions.append(BLOCKED_INVALID_WORKFLOW)
    if boundary == BOUNDARY_UNKNOWN:
        blocked_conditions.append(BLOCKED_UNKNOWN_CONTEXT)

    allowed_capabilities: list[str] = []
    if (
        boundary == BOUNDARY_AUTHORIZED
        and authorized
        and capability
        and capability != CAPABILITY_UNKNOWN
    ):
        allowed_capabilities.append(capability)

    constraints: list[str] = []
    for source in (
        policy.get("constraints"), scope.get("constraints"),
    ):
        for item in source or ():
            text = _upper(item)
            if text and text not in constraints and len(constraints) < 6:
                constraints.append(text)

    limitations = [
        BOUNDARY_LIMITATION_PLAN_ONLY,
        BOUNDARY_LIMITATION_AUTHORIZATION_ONLY,
    ]
    if boundary == BOUNDARY_RESEARCH_ONLY:
        limitations.append(BOUNDARY_LIMITATION_RESEARCH_ONLY)
    elif boundary == BOUNDARY_HUMAN_REVIEW_REQUIRED:
        limitations.append(BOUNDARY_LIMITATION_HUMAN_APPROVAL)
    elif boundary == BOUNDARY_BLOCKED:
        limitations.append(BOUNDARY_LIMITATION_BLOCKED)
    elif boundary == BOUNDARY_UNKNOWN:
        limitations.append(BOUNDARY_LIMITATION_UNKNOWN)

    execution_permitted = (
        boundary == BOUNDARY_AUTHORIZED
        and scope_value != SCOPE_UNKNOWN
        and risk_level != RISK_UNKNOWN
        and approval_state in (APPROVAL_NOT_REQUIRED, APPROVAL_APPROVED)
    )

    source_strategy = _text(
        _block(authorization.get("source_strategy")).get("strategy_type")
        or _block(_block(strategy_export).get("strategy")).get(
            "strategy_type"
        )
    )

    plan = ExecutionBoundaryPlan(
        rule_version=EXECUTION_BOUNDARY_RULE_VERSION,
        boundary_state=boundary,
        authorization_result=decision if decision else "UNKNOWN",
        allowed_capabilities=allowed_capabilities,
        scope=scope_value if scope_value else SCOPE_UNKNOWN,
        human_approval_required=approval_required,
        risk_level=risk_level if risk_level else RISK_UNKNOWN,
        constraints=constraints,
        blocked_conditions=blocked_conditions,
        source_strategy=source_strategy,
        source_orchestration=_block(orchestration_export),
        limitations=limitations,
        execution_permitted=execution_permitted,
        execution_performed=False,
        research_only=True,
    )
    return execution_boundary_plan_projection(plan)


__all__ = [
    "EXECUTION_BOUNDARY_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "plan_execution_boundary",
]
