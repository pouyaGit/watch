"""Stage R37.4 deterministic explainability planner (pure engine).

Generates the bounded human-readable explanation for an authorization
decision:

    "Why was this decision made, in bounded governance terms?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  created. Nothing is executed.
- No hallucinated reasons: explanations are generated only from the strategy,
  orchestration, authorization, provenance and rule-trace inputs, using
  closed reason/limitation codes with static deterministic labels. No LLM,
  no free-form text, no invention.
- Pure and offline: no I/O, no network, no LLM, no subprocess, no browser, no
  target interaction, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.decision_provenance import (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
)
from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.execution_authorization_plan import (
    AUTHORIZATION_DECISIONS,
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_LIMITS,
    DECISION_BLOCK,
    DECISION_REQUIRE_HUMAN_APPROVAL,
    DECISION_UNKNOWN,
)
from ai.schemas.execution_policy import (
    POLICY_ACTIVE_ALLOWED,
    POLICY_BLOCKED,
    POLICY_HUMAN_APPROVAL_REQUIRED,
    POLICY_PASSIVE_ONLY,
    POLICY_RESEARCH_ONLY,
)
from ai.schemas.execution_risk import RISK_CRITICAL, RISK_HIGH
from ai.schemas.governance_rule_trace import (
    TRACE_COMPLETE,
    TRACE_UNKNOWN,
)
from ai.schemas.human_approval_gate import APPROVAL_PENDING
from ai.schemas.research_explanation import (
    EXPLANATION_COMPLETE,
    EXPLANATION_PARTIAL,
    EXPLANATION_UNKNOWN,
    EXPLANATION_REASONS,
    LIMITATION_PARTIAL_PROVENANCE,
    LIMITATION_SCOPE_UNKNOWN,
    LIMITATION_SOURCE_CONTEXT_MISSING,
    LIMITATION_UNKNOWN_EXPLANATION,
    REASON_APPROVAL_PENDING,
    REASON_BOUNDARY_BLOCKED,
    REASON_CONTEXT_INCOMPLETE,
    REASON_POLICY_ACTIVE_ALLOWED,
    REASON_POLICY_BLOCKED,
    REASON_POLICY_HUMAN_APPROVAL,
    REASON_POLICY_PASSIVE_ONLY,
    REASON_POLICY_RESEARCH_ONLY,
    REASON_RISK_ELEVATED,
    REASON_SCOPE_UNKNOWN,
    RESEARCH_EXPLANATION_RULE_VERSION,
    SUMMARY_AUTHORIZED,
    SUMMARY_BLOCKED,
    SUMMARY_HUMAN_APPROVAL,
    SUMMARY_LIMITED,
    SUMMARY_UNKNOWN,
    ResearchExplanationPlan,
    research_explanation_plan_projection,
)
from ai.schemas.scope_capability_gate import SCOPE_UNKNOWN

RESEARCH_EXPLANATION_PLANNER_RULE_VERSION = "r37-4"
RULE_VERSION = RESEARCH_EXPLANATION_PLANNER_RULE_VERSION

# decision -> (summary, base reason)
DECISION_EXPLANATION: dict[str, tuple] = {
    DECISION_BLOCK: (SUMMARY_BLOCKED, REASON_POLICY_BLOCKED),
    DECISION_REQUIRE_HUMAN_APPROVAL: (
        SUMMARY_HUMAN_APPROVAL, REASON_POLICY_HUMAN_APPROVAL,
    ),
    DECISION_ALLOW_WITH_LIMITS: (
        SUMMARY_LIMITED, REASON_POLICY_RESEARCH_ONLY,
    ),
    DECISION_ALLOW: (SUMMARY_AUTHORIZED, REASON_POLICY_ACTIVE_ALLOWED),
    DECISION_UNKNOWN: (SUMMARY_UNKNOWN, REASON_CONTEXT_INCOMPLETE),
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def plan_research_explanation(
    strategy_export: object = None,
    orchestration_export: object = None,
    authorization_plan: object = None,
    provenance_plan: object = None,
    trace_plan: object = None,
    scope_plan: object = None,
    risk_plan: object = None,
    approval_plan: object = None,
) -> dict:
    """Build the deterministic governance explanation (read-only).

    The summary/reasons derive from the authorization decision, policy,
    scope, risk and approval inputs; limitations derive from the provenance
    and rule-trace states. Only closed codes are emitted; no free-form text
    is generated.
    """

    strategy = _block(strategy_export)
    orchestration = _block(orchestration_export)
    authorization = _block(authorization_plan)
    provenance = _block(provenance_plan)
    trace = _block(trace_plan)
    scope = _block(scope_plan)
    risk = _block(risk_plan)
    approval = _block(approval_plan)

    policy = _upper(authorization.get("policy"))
    decision = _upper(authorization.get("decision"))
    if decision not in AUTHORIZATION_DECISIONS:
        decision = DECISION_UNKNOWN

    provenance_state = _upper(provenance.get("provenance_state"))
    trace_state = _upper(trace.get("trace_state"))

    summary, base_reason = DECISION_EXPLANATION[decision]

    reasons: list[str] = [base_reason]
    if decision == DECISION_ALLOW_WITH_LIMITS:
        if policy == POLICY_PASSIVE_ONLY:
            reasons[0] = REASON_POLICY_PASSIVE_ONLY
        elif policy == POLICY_RESEARCH_ONLY:
            reasons[0] = REASON_POLICY_RESEARCH_ONLY
    elif decision == DECISION_ALLOW and policy == POLICY_ACTIVE_ALLOWED:
        reasons[0] = REASON_POLICY_ACTIVE_ALLOWED
    elif decision == DECISION_BLOCK and policy == POLICY_BLOCKED:
        reasons[0] = REASON_POLICY_BLOCKED
        reasons.append(REASON_BOUNDARY_BLOCKED)
    elif decision == DECISION_REQUIRE_HUMAN_APPROVAL:
        reasons[0] = REASON_POLICY_HUMAN_APPROVAL
        if _upper(approval.get("approval_state")) == APPROVAL_PENDING:
            reasons.append(REASON_APPROVAL_PENDING)

    if _upper(scope.get("scope")) == SCOPE_UNKNOWN:
        reasons.append(REASON_SCOPE_UNKNOWN)
    if _upper(risk.get("risk_level")) in (RISK_HIGH, RISK_CRITICAL):
        reasons.append(REASON_RISK_ELEVATED)

    limitations: list[str] = []
    if provenance_state == PROVENANCE_COMPLETE and trace_state == TRACE_COMPLETE:
        explanation_state = (
            EXPLANATION_COMPLETE if decision != DECISION_UNKNOWN
            else EXPLANATION_PARTIAL
        )
    elif (
        provenance_state in (PROVENANCE_COMPLETE, PROVENANCE_PARTIAL)
        or trace_state not in ("", TRACE_UNKNOWN)
        or strategy or orchestration or authorization
    ):
        explanation_state = EXPLANATION_PARTIAL
    else:
        explanation_state = EXPLANATION_UNKNOWN

    if not strategy or not orchestration or not authorization:
        limitations.append(LIMITATION_SOURCE_CONTEXT_MISSING)
    if provenance_state == PROVENANCE_PARTIAL:
        limitations.append(LIMITATION_PARTIAL_PROVENANCE)
    if _upper(scope.get("scope")) == SCOPE_UNKNOWN:
        limitations.append(LIMITATION_SCOPE_UNKNOWN)
    if explanation_state == EXPLANATION_UNKNOWN:
        limitations.append(LIMITATION_UNKNOWN_EXPLANATION)

    if provenance_state == PROVENANCE_COMPLETE:
        confidence = (
            CONFIDENCE_HIGH if decision != DECISION_UNKNOWN
            else CONFIDENCE_MEDIUM
        )
    elif provenance_state == PROVENANCE_PARTIAL:
        confidence = CONFIDENCE_MEDIUM
    elif provenance_state == PROVENANCE_UNKNOWN or not provenance:
        confidence = (
            CONFIDENCE_LOW if (strategy or orchestration or authorization)
            else CONFIDENCE_UNKNOWN
        )
    else:
        confidence = CONFIDENCE_UNKNOWN

    plan = ResearchExplanationPlan(
        rule_version=RESEARCH_EXPLANATION_RULE_VERSION,
        summary=summary,
        reasons=[r for r in reasons if r in EXPLANATION_REASONS],
        limitations=limitations,
        confidence=confidence,
        explanation_state=explanation_state,
        research_only=True,
    )
    return research_explanation_plan_projection(plan)


__all__ = [
    "RESEARCH_EXPLANATION_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "DECISION_EXPLANATION",
    "plan_research_explanation",
]
