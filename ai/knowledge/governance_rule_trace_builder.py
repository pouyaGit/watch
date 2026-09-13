"""Stage R37.2 deterministic governance rule trace builder (pure engine).

Explains which explicit governance rules produced an authorization decision:

    "Which rules fired, which were rejected, and in what precedence?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  created. Nothing is executed.
- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no target interaction, no Mongo, no wall-clock time, no
  randomness, no environment or filesystem state.
- No hidden decision logic: only closed rule codes are emitted and the fixed
  precedence order is always recorded.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.execution_authorization_plan import (
    AUTHORIZATION_DECISIONS,
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_LIMITS,
    DECISION_BLOCK,
    DECISION_REQUIRE_HUMAN_APPROVAL,
    DECISION_UNKNOWN,
)
from ai.schemas.execution_policy import (
    EXECUTION_POLICIES,
    POLICY_PASSIVE_ONLY,
    POLICY_RESEARCH_ONLY,
)
from ai.schemas.governance_rule_trace import (
    GOVERNANCE_RULE_TRACE_RULE_VERSION,
    MAX_RULES,
    PRECEDENCE_ORDER,
    RULE_ACTIVE_ALLOWED,
    RULE_APPROVAL_GATE,
    RULE_BOUNDARY,
    RULE_CONTEXT_VALIDATION,
    RULE_HUMAN_APPROVAL,
    RULE_PASSIVE_ONLY,
    RULE_POLICY_BLOCK,
    RULE_RESEARCH_ONLY,
    RULE_RISK_NOT_PERMISSION,
    RULE_SCOPE_GATE,
    RULE_SCOPE_UNKNOWN,
    RULE_UNKNOWN,
    TRACE_COMPLETE,
    TRACE_PARTIAL,
    TRACE_UNKNOWN,
    GovernanceRuleTracePlan,
    governance_rule_trace_plan_projection,
)
from ai.schemas.scope_capability_gate import (
    SCOPE_UNKNOWN,
)

GOVERNANCE_RULE_TRACE_BUILDER_RULE_VERSION = "r37-2"
RULE_VERSION = GOVERNANCE_RULE_TRACE_BUILDER_RULE_VERSION

# decision -> (applied rules, rejected rules)
DECISION_RULES: dict[str, tuple] = {
    DECISION_BLOCK: (
        (RULE_POLICY_BLOCK, RULE_RISK_NOT_PERMISSION, RULE_BOUNDARY),
        (RULE_HUMAN_APPROVAL, RULE_RESEARCH_ONLY, RULE_PASSIVE_ONLY,
         RULE_ACTIVE_ALLOWED),
    ),
    DECISION_REQUIRE_HUMAN_APPROVAL: (
        (RULE_HUMAN_APPROVAL, RULE_APPROVAL_GATE, RULE_RISK_NOT_PERMISSION,
         RULE_BOUNDARY),
        (RULE_RESEARCH_ONLY, RULE_PASSIVE_ONLY, RULE_ACTIVE_ALLOWED),
    ),
    DECISION_ALLOW_WITH_LIMITS: (
        (RULE_RESEARCH_ONLY, RULE_SCOPE_GATE, RULE_RISK_NOT_PERMISSION,
         RULE_BOUNDARY),
        (RULE_HUMAN_APPROVAL, RULE_PASSIVE_ONLY, RULE_ACTIVE_ALLOWED),
    ),
    DECISION_ALLOW: (
        (RULE_ACTIVE_ALLOWED, RULE_SCOPE_GATE, RULE_APPROVAL_GATE,
         RULE_RISK_NOT_PERMISSION, RULE_BOUNDARY),
        (RULE_POLICY_BLOCK, RULE_HUMAN_APPROVAL, RULE_RESEARCH_ONLY,
         RULE_PASSIVE_ONLY),
    ),
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def build_governance_rule_trace(
    policy_plan: object = None,
    authorization_plan: object = None,
    scope_plan: object = None,
    approval_plan: object = None,
    risk_plan: object = None,
    boundary_plan: object = None,
) -> dict:
    """Build the deterministic rule trace for one decision (read-only).

    ``COMPLETE`` requires a valid policy and a valid non-UNKNOWN
    authorization decision; ``PARTIAL`` requires one of them; ``UNKNOWN``
    means neither is available. Applied/rejected rules come from the closed
    per-decision table; an unknown scope adds the conservative scope rule.
    """

    policy = _upper(_block(policy_plan).get("policy"))
    decision = _upper(_block(authorization_plan).get("decision"))
    scope = _upper(_block(scope_plan).get("scope"))

    policy_valid = policy in EXECUTION_POLICIES
    decision_valid = (
        decision in AUTHORIZATION_DECISIONS
        and decision != DECISION_UNKNOWN
    )

    if not policy_valid and not decision_valid:
        state = TRACE_UNKNOWN
    elif policy_valid and decision_valid:
        state = TRACE_COMPLETE
    else:
        state = TRACE_PARTIAL

    if not decision_valid:
        applied = [RULE_CONTEXT_VALIDATION]
        rejected = [
            rule for rule in PRECEDENCE_ORDER
            if rule != RULE_CONTEXT_VALIDATION
        ]
    else:
        applied, rejected = DECISION_RULES.get(
            decision, DECISION_RULES[DECISION_ALLOW_WITH_LIMITS]
        )
        applied = list(applied)
        rejected = list(rejected)
        if decision == DECISION_ALLOW_WITH_LIMITS:
            if policy == POLICY_RESEARCH_ONLY:
                applied[0] = RULE_RESEARCH_ONLY
            elif policy == POLICY_PASSIVE_ONLY:
                applied[0] = RULE_PASSIVE_ONLY

    if decision_valid and scope == SCOPE_UNKNOWN:
        if RULE_SCOPE_UNKNOWN not in applied:
            applied.insert(0, RULE_SCOPE_UNKNOWN)
    if not decision_valid and RULE_UNKNOWN not in applied:
        pass

    plan = GovernanceRuleTracePlan(
        rule_version=GOVERNANCE_RULE_TRACE_RULE_VERSION,
        applied_rules=applied[:MAX_RULES],
        rejected_rules=rejected[:MAX_RULES],
        precedence_order=list(PRECEDENCE_ORDER),
        trace_state=state,
        research_only=True,
    )
    return governance_rule_trace_plan_projection(plan)


__all__ = [
    "GOVERNANCE_RULE_TRACE_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "DECISION_RULES",
    "build_governance_rule_trace",
]
