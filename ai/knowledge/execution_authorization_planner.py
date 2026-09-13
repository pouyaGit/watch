"""Stage R36.1/R36.2 deterministic execution authorization planner (pure).

Consumes the read-only R34.4 strategy export, R35.4 orchestration export and
an explicit R36.1 execution policy, then resolves the policy plan and the
authorization decision:

    "Is this candidate authorized, limited, gated or blocked?"

Hard boundaries encoded here:

- Planning/authorization only: no execution runtime, worker queue, scheduler,
  dispatch, subprocess, shell command, browser, network, Mongo persistence or
  LLM call is created. Nothing is executed.
- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  wall-clock time, no randomness, no environment or filesystem state.
- Authorization is authoritative: risk is a separate dimension (R36.4) and can
  never convert a BLOCK into an ALLOW or bypass HUMAN_APPROVAL_REQUIRED.
- Conservative: malformed/empty context yields UNKNOWN and is never silently
  upgraded; a missing explicit policy defaults to RESEARCH_ONLY.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.agent_role_plan import AGENT_ROLES
from ai.schemas.execution_authorization_plan import (
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_LIMITS,
    DECISION_BLOCK,
    DECISION_REQUIRE_HUMAN_APPROVAL,
    DECISION_UNKNOWN,
    EXECUTION_AUTHORIZATION_RULE_VERSION,
    LIMITATION_BLOCKED,
    LIMITATION_HUMAN_APPROVAL,
    LIMITATION_PASSIVE_ONLY,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_UNKNOWN_CONTEXT,
    REASON_ACTIVE_VALID,
    REASON_MALFORMED,
    REASON_PASSIVE_LIMITS,
    REASON_POLICY_BLOCKED,
    REASON_RESEARCH_LIMITS,
    REASON_HUMAN_REQUIRED,
    REASON_UNKNOWN_POLICY,
    ExecutionAuthorizationPlan,
    execution_authorization_plan_projection,
)
from ai.schemas.execution_policy import (
    CONSTRAINT_AUTHORIZED_SCOPE_ONLY,
    CONSTRAINT_HUMAN_APPROVAL_MANDATORY,
    CONSTRAINT_NO_ACTION_PERMITTED,
    CONSTRAINT_NO_TARGET_INTERACTION,
    CONSTRAINT_PASSIVE_OBSERVATION,
    CONSTRAINT_UNKNOWN_NO_ACTION,
    EXECUTION_POLICIES,
    EXECUTION_POLICY_RULE_VERSION,
    POLICY_ACTIVE_ALLOWED,
    POLICY_BLOCKED,
    POLICY_HUMAN_APPROVAL_REQUIRED,
    POLICY_PASSIVE_ONLY,
    POLICY_RESEARCH_ONLY,
    POLICY_UNKNOWN,
    REASON_ACTIVE_EXPLICIT,
    REASON_BLOCKED_MANDATED,
    REASON_HUMAN_MANDATED,
    REASON_PASSIVE_RESEARCH,
    REASON_RESEARCH_DEFAULT,
    REASON_UNKNOWN,
    ExecutionPolicyPlan,
    execution_policy_plan_projection,
)
from ai.schemas.research_strategy import STRATEGY_TYPES

EXECUTION_AUTHORIZATION_PLANNER_RULE_VERSION = "r36-2"
RULE_VERSION = EXECUTION_AUTHORIZATION_PLANNER_RULE_VERSION

# policy -> (reason, constraints)
POLICY_RESOLUTION: dict[str, tuple] = {
    POLICY_RESEARCH_ONLY: (
        REASON_RESEARCH_DEFAULT,
        (CONSTRAINT_NO_TARGET_INTERACTION,),
    ),
    POLICY_PASSIVE_ONLY: (
        REASON_PASSIVE_RESEARCH,
        (CONSTRAINT_PASSIVE_OBSERVATION,),
    ),
    POLICY_ACTIVE_ALLOWED: (
        REASON_ACTIVE_EXPLICIT,
        (CONSTRAINT_AUTHORIZED_SCOPE_ONLY,),
    ),
    POLICY_HUMAN_APPROVAL_REQUIRED: (
        REASON_HUMAN_MANDATED,
        (CONSTRAINT_HUMAN_APPROVAL_MANDATORY,),
    ),
    POLICY_BLOCKED: (
        REASON_BLOCKED_MANDATED,
        (CONSTRAINT_NO_ACTION_PERMITTED,),
    ),
    POLICY_UNKNOWN: (
        REASON_UNKNOWN,
        (CONSTRAINT_UNKNOWN_NO_ACTION,),
    ),
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _strategy_type(strategy_export: object) -> str:
    export = _block(strategy_export)
    strategy = _block(export.get("strategy"))
    return _upper(
        strategy.get("strategy_type") or export.get("strategy_type")
    )


def _primary_role(orchestration_export: object) -> str:
    export = _block(orchestration_export)
    roles = _block(export.get("roles"))
    return _upper(roles.get("primary_role") or export.get("primary_role"))


def _workflow_nodes(orchestration_export: object) -> list:
    export = _block(orchestration_export)
    workflow = _block(export.get("workflow"))
    nodes = workflow.get("nodes")
    if isinstance(nodes, (list, tuple)):
        return list(nodes)
    return []


def authorization_context_valid(
    strategy_export: object = None,
    orchestration_export: object = None,
) -> bool:
    """True only when both bounded source contexts are structurally valid."""

    if not _block(strategy_export) or not _block(orchestration_export):
        return False
    if _strategy_type(strategy_export) not in STRATEGY_TYPES:
        return False
    if _primary_role(orchestration_export) not in AGENT_ROLES:
        return False
    return bool(_workflow_nodes(orchestration_export))


def plan_execution_policy(
    strategy_export: object = None,
    orchestration_export: object = None,
    explicit_policy: object = None,
) -> dict:
    """Resolve the explicit execution policy (R36.1).

    ``explicit_policy=None`` defaults to the bounded ``RESEARCH_ONLY``
    policy; a provided but malformed/unknown value resolves to ``UNKNOWN``
    (never permissive). The source exports are accepted for pipeline parity
    and never grant a policy.
    """

    if explicit_policy is None:
        policy = POLICY_RESEARCH_ONLY
    else:
        policy = _upper(explicit_policy)
        if policy not in EXECUTION_POLICIES:
            policy = POLICY_UNKNOWN

    reason, constraints = POLICY_RESOLUTION[policy]
    plan = ExecutionPolicyPlan(
        rule_version=EXECUTION_POLICY_RULE_VERSION,
        policy=policy,
        policy_reason=reason,
        constraints=list(constraints),
        research_only=True,
    )
    return execution_policy_plan_projection(plan)


def plan_execution_authorization(
    strategy_export: object = None,
    orchestration_export: object = None,
    policy_plan: object = None,
) -> dict:
    """Resolve the deterministic authorization decision (R36.2).

    Precedence (first match wins):

    1. malformed/unknown policy or malformed/empty critical context ->
       ``UNKNOWN``;
    2. ``BLOCKED`` policy -> ``BLOCK`` (terminal; risk can never override it);
    3. ``HUMAN_APPROVAL_REQUIRED`` policy -> ``REQUIRE_HUMAN_APPROVAL`` (low
       risk can never bypass it);
    4. ``RESEARCH_ONLY``/``PASSIVE_ONLY`` policy -> ``ALLOW_WITH_LIMITS``;
    5. ``ACTIVE_ALLOWED`` policy with valid context -> ``ALLOW``.
    """

    policy = _upper(_block(policy_plan).get("policy"))
    strategy = _block(strategy_export)
    orchestration = _block(orchestration_export)
    context_ok = authorization_context_valid(
        strategy_export, orchestration_export
    )

    def result(
        decision: str,
        reason: str,
        limitations: list[str],
    ) -> dict:
        plan = ExecutionAuthorizationPlan(
            rule_version=EXECUTION_AUTHORIZATION_RULE_VERSION,
            decision=decision,
            decision_reason=reason,
            policy=(
                policy if policy in EXECUTION_POLICIES else POLICY_UNKNOWN
            ),
            limitations=limitations,
            source_strategy=strategy,
            source_orchestration=orchestration,
            research_only=True,
        )
        return execution_authorization_plan_projection(plan)

    if policy not in EXECUTION_POLICIES:
        return result(
            DECISION_UNKNOWN,
            REASON_UNKNOWN_POLICY,
            [LIMITATION_UNKNOWN_CONTEXT],
        )
    if not context_ok:
        return result(
            DECISION_UNKNOWN,
            REASON_MALFORMED,
            [LIMITATION_UNKNOWN_CONTEXT],
        )
    if policy == POLICY_BLOCKED:
        return result(
            DECISION_BLOCK,
            REASON_POLICY_BLOCKED,
            [LIMITATION_BLOCKED],
        )
    if policy == POLICY_HUMAN_APPROVAL_REQUIRED:
        return result(
            DECISION_REQUIRE_HUMAN_APPROVAL,
            REASON_HUMAN_REQUIRED,
            [LIMITATION_HUMAN_APPROVAL],
        )
    if policy == POLICY_RESEARCH_ONLY:
        return result(
            DECISION_ALLOW_WITH_LIMITS,
            REASON_RESEARCH_LIMITS,
            [LIMITATION_RESEARCH_ONLY],
        )
    if policy == POLICY_PASSIVE_ONLY:
        return result(
            DECISION_ALLOW_WITH_LIMITS,
            REASON_PASSIVE_LIMITS,
            [LIMITATION_PASSIVE_ONLY],
        )
    if policy == POLICY_ACTIVE_ALLOWED:
        return result(DECISION_ALLOW, REASON_ACTIVE_VALID, [])
    return result(
        DECISION_UNKNOWN,
        REASON_UNKNOWN_POLICY,
        [LIMITATION_UNKNOWN_CONTEXT],
    )


__all__ = [
    "EXECUTION_AUTHORIZATION_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "POLICY_RESOLUTION",
    "authorization_context_valid",
    "plan_execution_policy",
    "plan_execution_authorization",
]
