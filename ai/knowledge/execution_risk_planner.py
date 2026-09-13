"""Stage R36.4 deterministic execution risk planner (pure engine).

Classifies the bounded execution-safety risk of the authorized (or blocked)
plan:

    "How risky would the authorized (or blocked) plan be?"

Hard boundaries encoded here:

- Planning only: risk is a closed classification label. No execution runtime,
  worker queue, scheduler, dispatch, subprocess, shell command, browser,
  network, Mongo persistence or LLM call is represented or created.
- Risk is NOT permission: authorization (R36.2) is authoritative and is never
  weakened or overridden by a low risk result. A BLOCK stays BLOCK.
- Pure and offline: no I/O, no network, no LLM, no subprocess, no browser, no
  target interaction, no Mongo, no wall-clock time, no randomness.
- Conservative escalation only: scope gaps, invalid workflows, low confidence
  and rejected/expired approvals can only raise the risk level, never lower
  it.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_LEVELS,
    CONFIDENCE_LOW,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.execution_authorization_plan import (
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_LIMITS,
    DECISION_BLOCK,
    DECISION_REQUIRE_HUMAN_APPROVAL,
    DECISION_UNKNOWN,
)
from ai.schemas.execution_risk import (
    EXECUTION_RISK_RULE_VERSION,
    FACTOR_ACTIVE_AUTHORIZED,
    FACTOR_APPROVAL_EXPIRED,
    FACTOR_APPROVAL_REJECTED,
    FACTOR_AUTHORIZATION_BLOCK,
    FACTOR_HUMAN_APPROVAL_REQUIRED,
    FACTOR_INVALID_WORKFLOW,
    FACTOR_LIMITED_AUTHORIZATION,
    FACTOR_LOW_CONFIDENCE,
    FACTOR_MISSING_SCOPE,
    FACTOR_UNKNOWN_CONTEXT,
    REASON_ACTIVE_AUTHORIZED,
    REASON_AUTHORIZATION_BLOCK,
    REASON_HUMAN_APPROVAL_REQUIRED,
    REASON_LIMITED_AUTHORIZATION,
    REASON_UNKNOWN_CONTEXT,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_UNKNOWN,
    ExecutionRiskPlan,
    execution_risk_plan_projection,
)
from ai.schemas.human_approval_gate import (
    APPROVAL_APPROVED,
    APPROVAL_EXPIRED,
    APPROVAL_REJECTED,
)
from ai.schemas.scope_capability_gate import (
    CERTAINTY_UNKNOWN,
    SCOPE_UNKNOWN,
)

EXECUTION_RISK_PLANNER_RULE_VERSION = "r36-4"
RULE_VERSION = EXECUTION_RISK_PLANNER_RULE_VERSION

# authorization decision -> (risk level, reason, base factor)
BASE_RISK: dict[str, tuple] = {
    DECISION_ALLOW: (
        RISK_LOW, REASON_ACTIVE_AUTHORIZED, FACTOR_ACTIVE_AUTHORIZED,
    ),
    DECISION_ALLOW_WITH_LIMITS: (
        RISK_MEDIUM, REASON_LIMITED_AUTHORIZATION,
        FACTOR_LIMITED_AUTHORIZATION,
    ),
    DECISION_REQUIRE_HUMAN_APPROVAL: (
        RISK_HIGH, REASON_HUMAN_APPROVAL_REQUIRED,
        FACTOR_HUMAN_APPROVAL_REQUIRED,
    ),
    DECISION_BLOCK: (
        RISK_CRITICAL, REASON_AUTHORIZATION_BLOCK,
        FACTOR_AUTHORIZATION_BLOCK,
    ),
    DECISION_UNKNOWN: (
        RISK_UNKNOWN, REASON_UNKNOWN_CONTEXT, FACTOR_UNKNOWN_CONTEXT,
    ),
}

ESCALATION: dict[str, str] = {
    RISK_LOW: RISK_MEDIUM,
    RISK_MEDIUM: RISK_HIGH,
    RISK_HIGH: RISK_CRITICAL,
    RISK_CRITICAL: RISK_CRITICAL,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def plan_execution_risk(
    authorization_plan: object = None,
    scope_plan: object = None,
    approval_plan: object = None,
    strategy_export: object = None,
    orchestration_export: object = None,
) -> dict:
    """Classify deterministic execution risk for one candidate (read-only).

    The authorization decision sets the base level (ALLOW=LOW,
    ALLOW_WITH_LIMITS=MEDIUM, REQUIRE_HUMAN_APPROVAL=HIGH, BLOCK=CRITICAL,
    UNKNOWN=UNKNOWN). Missing scope, invalid workflow, low confidence and
    rejected/expired approvals can only escalate, never lower, the level.
    """

    authorization = _block(authorization_plan)
    scope = _block(scope_plan)
    approval = _block(approval_plan)

    decision = _upper(authorization.get("decision"))
    level, reason, factor = BASE_RISK.get(
        decision, BASE_RISK[DECISION_UNKNOWN]
    )
    factors: list[str] = [factor]

    if level != RISK_UNKNOWN:
        scope_value = _upper(scope.get("scope"))
        certainty = _upper(scope.get("scope_certainty"))
        if scope_value == SCOPE_UNKNOWN or certainty == CERTAINTY_UNKNOWN:
            factors.append(FACTOR_MISSING_SCOPE)
            level = ESCALATION[level]

        workflow = _block(orchestration_export.get("workflow"))
        nodes = workflow.get("nodes")
        if not isinstance(nodes, (list, tuple)) or not list(nodes):
            factors.append(FACTOR_INVALID_WORKFLOW)
            level = ESCALATION[level]

        strategy = _block(_block(strategy_export).get("strategy"))
        confidence = _upper(
            strategy.get("confidence_level")
            or _block(strategy_export).get("confidence_level")
        )
        if confidence not in CONFIDENCE_LEVELS or confidence in (
            CONFIDENCE_LOW, CONFIDENCE_UNKNOWN,
        ):
            factors.append(FACTOR_LOW_CONFIDENCE)
            level = ESCALATION[level]

        approval_state = _upper(approval.get("approval_state"))
        if approval_state == APPROVAL_REJECTED:
            factors.append(FACTOR_APPROVAL_REJECTED)
            level = RISK_CRITICAL
        elif approval_state == APPROVAL_EXPIRED:
            factors.append(FACTOR_APPROVAL_EXPIRED)
            level = RISK_CRITICAL
        elif approval_state == APPROVAL_APPROVED:
            pass

    plan = ExecutionRiskPlan(
        rule_version=EXECUTION_RISK_RULE_VERSION,
        risk_level=level,
        risk_reason=reason,
        risk_factors=factors,
        authorization_authoritative=True,
        research_only=True,
    )
    return execution_risk_plan_projection(plan)


__all__ = [
    "EXECUTION_RISK_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "BASE_RISK",
    "ESCALATION",
    "plan_execution_risk",
]
