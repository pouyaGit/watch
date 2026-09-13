"""Stage R36.5 deterministic human approval gate planner (pure engine).

Derives the bounded human-approval state for one research candidate:

    "Is human approval required, pending, approved, rejected or expired?"

Hard boundaries encoded here:

- State/planning model only: this is NOT an approval service, database, API,
  UI, notification system or persistence layer. Nothing is stored or sent.
- Pure and offline: no I/O, no network, no LLM, no subprocess, no browser, no
  target interaction, no Mongo, no wall-clock time, no randomness.
- Deterministic derivation from policy/authorization; a caller-supplied
  explicit state may only refine a required approval (PENDING/APPROVED/
  REJECTED/EXPIRED) and is never invented.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.execution_authorization_plan import (
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_LIMITS,
    DECISION_BLOCK,
    DECISION_REQUIRE_HUMAN_APPROVAL,
)
from ai.schemas.execution_policy import (
    POLICY_BLOCKED,
    POLICY_HUMAN_APPROVAL_REQUIRED,
)
from ai.schemas.human_approval_gate import (
    APPROVAL_APPROVED,
    APPROVAL_EXPIRED,
    APPROVAL_NOT_REQUIRED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    APPROVAL_UNKNOWN,
    DETERMINABLE_STATES,
    HUMAN_APPROVAL_GATE_RULE_VERSION,
    REASON_APPROVED,
    REASON_AUTHORIZED_NOT_REQUIRED,
    REASON_BLOCKED_NO_ACTION,
    REASON_EXPIRED,
    REASON_PENDING,
    REASON_RESEARCH_NOT_REQUIRED,
    REASON_REJECTED,
    REASON_UNKNOWN_CONTEXT,
    HumanApprovalGatePlan,
    human_approval_gate_plan_projection,
)

HUMAN_APPROVAL_GATE_PLANNER_RULE_VERSION = "r36-5"
RULE_VERSION = HUMAN_APPROVAL_GATE_PLANNER_RULE_VERSION

_STATE_REASON: dict[str, str] = {
    APPROVAL_PENDING: REASON_PENDING,
    APPROVAL_APPROVED: REASON_APPROVED,
    APPROVAL_REJECTED: REASON_REJECTED,
    APPROVAL_EXPIRED: REASON_EXPIRED,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _result(state: str, reason: str, required: bool) -> dict:
    plan = HumanApprovalGatePlan(
        rule_version=HUMAN_APPROVAL_GATE_RULE_VERSION,
        approval_state=state,
        approval_reason=reason,
        required=required,
        research_only=True,
    )
    return human_approval_gate_plan_projection(plan)


def plan_human_approval(
    policy_plan: object = None,
    authorization_plan: object = None,
    explicit_state: object = None,
) -> dict:
    """Derive the deterministic human-approval state (read-only).

    A BLOCKED policy/decision needs no approval (no action is permitted). A
    HUMAN_APPROVAL_REQUIRED policy or REQUIRE_HUMAN_APPROVAL decision requires
    approval: a valid caller-supplied ``explicit_state`` is preserved, else
    the state is ``PENDING``. Research/passive decisions are ``NOT_REQUIRED``;
    an unknown policy/decision is ``UNKNOWN``.
    """

    policy = _upper(_block(policy_plan).get("policy"))
    decision = _upper(_block(authorization_plan).get("decision"))

    if policy == POLICY_BLOCKED or decision == DECISION_BLOCK:
        return _result(
            APPROVAL_NOT_REQUIRED, REASON_BLOCKED_NO_ACTION, False
        )
    if (
        policy == POLICY_HUMAN_APPROVAL_REQUIRED
        or decision == DECISION_REQUIRE_HUMAN_APPROVAL
    ):
        state = _upper(explicit_state)
        if state not in DETERMINABLE_STATES:
            state = APPROVAL_PENDING
        return _result(state, _STATE_REASON[state], True)
    if decision == DECISION_ALLOW_WITH_LIMITS:
        return _result(
            APPROVAL_NOT_REQUIRED, REASON_RESEARCH_NOT_REQUIRED, False
        )
    if decision == DECISION_ALLOW:
        return _result(
            APPROVAL_NOT_REQUIRED, REASON_AUTHORIZED_NOT_REQUIRED, False
        )
    return _result(APPROVAL_UNKNOWN, REASON_UNKNOWN_CONTEXT, False)


__all__ = [
    "HUMAN_APPROVAL_GATE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "plan_human_approval",
]
