"""EPIC12 — deterministic selection of the next verification action (§15).

The planner turns a chain state into **at most one** next action, using only
deterministic policy: the stage that still needs evidence, the actions that stage
allows, the action's declared capability, the authorization reference and the
remaining budget.  Safety-first ordering is fixed (read-only derivations before
probes before active payloads), so the same state always yields the same plan.

An advisory (LLM) hint may only *reorder among actions the chain already
allows*; it can never introduce a new action, widen the scope, or authorize
anything.  If the hint names an action that is not allowed for the stage it is
recorded as ignored — the deterministic choice stands.

When nothing can be planned the planner returns a terminal decision with an
explicit reason (``capability_unavailable``, ``authorization_unavailable``,
``budget_exhausted:<resource>``, ``chain_not_implemented`` …).  It never returns
a plan it cannot justify.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.research_agents.verification import actions as ac
from backend.research_agents.verification import chains as ch
from backend.research_agents.verification.engine import ChainState

PLANNER_RULE_VERSION = "epic12-verification-planner-1"

#: Fixed safety-first ordering (never data-dependent).
SAFETY_ORDER: dict[str, int] = {
    ac.SAFETY_READ_ONLY: 0,
    ac.SAFETY_PROBE: 1,
    ac.SAFETY_ACTIVE: 2,
    ac.SAFETY_UNAVAILABLE: 3,
}

#: Deterministic terminal reasons.
REASON_CONFIRMED = "confirmed"
REASON_CHAIN_NOT_IMPLEMENTED = "chain_not_implemented"
REASON_CAPABILITY_CONTRACT_ONLY = "capability_contract_only"
REASON_NO_REQUIRED_STAGE = "no_required_stage"
REASON_NO_AVAILABLE_ACTION = "no_available_action"
REASON_AUTHORIZATION_UNAVAILABLE = "authorization_unavailable"
REASON_ACTION_NOT_IMPLEMENTED = "action_not_implemented"
REASON_BUDGET_PREFIX = "budget_exhausted"
REASON_RETRIES_EXHAUSTED = "action_retries_exhausted"
REASON_CHAIN_TERMINATED = "chain_terminated"


@dataclass(frozen=True)
class ActionPlan:
    """One planned action — or one explicit refusal."""

    action_type: str
    stage_key: str
    candidate_id: str
    objective_id: str
    scope_ref: str
    target: str = ""
    stage_label: str = ""
    inputs: dict[str, Any] = field(default_factory=dict)
    authorization_id: str = ""
    safety: str = ""
    requires_authorization: bool = False
    requires_network: bool = False
    implemented: bool = False
    rationale: str = ""
    plan_reason: str = ""
    blocked_reason: str = ""
    advisor_hint: str = ""
    advisor_honored: bool = False
    attempt: int = 1
    rule_version: str = PLANNER_RULE_VERSION

    @property
    def executable(self) -> bool:
        return not self.blocked_reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "stage_key": self.stage_key,
            "stage_label": self.stage_label,
            "candidate_id": self.candidate_id,
            "objective_id": self.objective_id,
            "scope_ref": self.scope_ref,
            "target": self.target,
            "inputs": dict(self.inputs),
            "authorization_id": self.authorization_id,
            "safety": self.safety,
            "requires_authorization": self.requires_authorization,
            "requires_network": self.requires_network,
            "implemented": self.implemented,
            "rationale": self.rationale,
            "plan_reason": self.plan_reason,
            "blocked_reason": self.blocked_reason,
            "advisor_hint": self.advisor_hint,
            "advisor_honored": self.advisor_honored,
            "attempt": self.attempt,
            "executable": self.executable,
            "rule_version": self.rule_version,
        }


@dataclass(frozen=True)
class PlanDecision:
    """The planner's outcome: a plan, or a terminal stop with a reason."""

    plan: ActionPlan | None = None
    terminal: bool = False
    termination_reason: str = ""
    considered: tuple[str, ...] = ()
    rejected: tuple[dict[str, Any], ...] = ()
    rule_version: str = PLANNER_RULE_VERSION

    @property
    def has_plan(self) -> bool:
        return self.plan is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan.to_dict() if self.plan else None,
            "terminal": self.terminal,
            "termination_reason": self.termination_reason,
            "considered": list(self.considered),
            "rejected": [dict(r) for r in self.rejected],
            "rule_version": self.rule_version,
        }


def _resources_for(spec: ac.ActionSpec) -> tuple[str, ...]:
    """The budget resources one execution of this action consumes."""
    out = ["max_actions"]
    if spec.requires_network:
        out.append("max_requests")
    if spec.safety == ac.SAFETY_ACTIVE:
        out.append("max_payload_attempts")
    return tuple(out)


def _attempts_for(attempted: Iterable[str], action_type: str) -> int:
    return sum(1 for a in attempted if a == action_type)


#: Refusal priority: the reason an analyst must act on comes first.
#: Most actionable refusal first: a refusal the operator can actually act on
#: (grant authorization, raise a budget, wait for a retry window) outranks one
#: that simply says "this lane does not exist yet".
_REJECTION_PRIORITY: tuple[str, ...] = (
    REASON_AUTHORIZATION_UNAVAILABLE, REASON_BUDGET_PREFIX,
    REASON_RETRIES_EXHAUSTED, REASON_ACTION_NOT_IMPLEMENTED,
    "unknown_action_type")


def _best_rejection(rejected: list[dict[str, Any]]) -> str:
    """Deterministically pick the most actionable refusal reason."""
    for prefix in _REJECTION_PRIORITY:
        for row in rejected:
            if str(row.get("reason") or "").startswith(prefix):
                return str(row["reason"])
    return str(rejected[0].get("reason") or REASON_NO_AVAILABLE_ACTION)


def plan_next_action(
    state: ChainState,
    *,
    candidate_id: str,
    objective_id: str,
    scope_ref: str,
    target: str = "",
    authorization_id: str = "",
    inputs: dict[str, Any] | None = None,
    attempt: int = 1,
    budget: Any = None,
    attempted: Iterable[str] = (),
    advisor_hint: str = "",
    requested_action: str = "",
) -> PlanDecision:
    """Deterministically select the next verification action (or stop)."""
    attempted_list = [str(a) for a in attempted]

    # ---- terminal states -------------------------------------------------
    if state.verdict == "VERIFIED" or state.confirmed:
        return PlanDecision(terminal=True, termination_reason=REASON_CONFIRMED)
    if state.chain_terminated:
        return PlanDecision(
            terminal=True,
            termination_reason=state.termination_reason or REASON_CHAIN_TERMINATED)
    if state.capability == ch.CAPABILITY_NOT_IMPLEMENTED:
        return PlanDecision(terminal=True,
                            termination_reason=REASON_CHAIN_NOT_IMPLEMENTED)
    if state.capability != ch.CAPABILITY_FULL:
        return PlanDecision(terminal=True,
                            termination_reason=REASON_CAPABILITY_CONTRACT_ONLY)
    if not state.next_stage:
        return PlanDecision(terminal=True,
                            termination_reason=REASON_NO_REQUIRED_STAGE)

    stage = state.stage(state.next_stage)
    allowed = tuple(stage.allowed_actions if stage else ())
    hint = str(advisor_hint or "").strip().upper()
    requested = str(requested_action or "").strip().upper()

    considered: list[str] = []
    rejected: list[dict[str, Any]] = []
    viable: list[ac.ActionSpec] = []

    for action_type in allowed:
        considered.append(action_type)
        spec = ac.ACTION_SPECS.get(action_type)
        if spec is None:
            rejected.append({"action_type": action_type,
                             "reason": "unknown_action_type"})
            continue
        max_retries = 1
        if budget is not None:
            try:
                max_retries = int(budget.limits.get("max_retries", 1))
            except Exception:  # noqa: BLE001
                max_retries = 1
        if _attempts_for(attempted_list, action_type) > max_retries:
            rejected.append({"action_type": action_type,
                             "reason": REASON_RETRIES_EXHAUSTED})
            continue
        if not spec.implemented:
            rejected.append({"action_type": action_type,
                             "reason": f"{REASON_ACTION_NOT_IMPLEMENTED}:"
                                       f"{spec.safety.lower()}"})
            continue
        if spec.requires_authorization and not str(authorization_id).strip():
            rejected.append({"action_type": action_type,
                             "reason": REASON_AUTHORIZATION_UNAVAILABLE})
            continue
        if budget is not None:
            missing = [r for r in _resources_for(spec)
                       if not budget.allow(r, 1)]
            if missing:
                rejected.append({"action_type": action_type,
                                 "reason": f"{REASON_BUDGET_PREFIX}:"
                                           f"{missing[0]}"})
                continue
        viable.append(spec)

    if not viable:
        reason = (_best_rejection(rejected) if rejected
                  else REASON_NO_AVAILABLE_ACTION)
        return PlanDecision(
            plan=None, terminal=True, termination_reason=reason,
            considered=tuple(considered), rejected=tuple(rejected))

    # ---- deterministic ordering (advisor may only reorder) --------------
    order_index = {t: i for i, t in enumerate(allowed)}
    viable.sort(key=lambda s: (SAFETY_ORDER.get(s.safety, 9),
                               order_index.get(s.action_type, 99),
                               s.action_type))
    chosen = viable[0]
    honored = False
    preferred = requested or hint
    if preferred:
        for spec in viable:
            if spec.action_type == preferred:
                chosen = spec
                honored = True
                break

    plan_reason = ("stage_missing_evidence"
                   if stage and stage.status == ch.STAGE_MISSING
                   else "stage_not_tested")
    if preferred and not honored:
        plan_reason += ":advisor_hint_not_allowed"

    return PlanDecision(
        plan=ActionPlan(
            action_type=chosen.action_type,
            stage_key=state.next_stage,
            stage_label=state.next_stage_label,
            candidate_id=candidate_id,
            objective_id=objective_id,
            scope_ref=scope_ref,
            target=target,
            inputs=dict(inputs or {}),
            authorization_id=str(authorization_id or ""),
            safety=chosen.safety,
            requires_authorization=chosen.requires_authorization,
            requires_network=chosen.requires_network,
            implemented=chosen.implemented,
            rationale=(f"stage {state.next_stage} requires "
                       f"{'/'.join(state.next_stage_missing_types) or 'evidence'}; "
                       f"{chosen.label} is the highest-safety allowed action"),
            plan_reason=plan_reason,
            blocked_reason="",
            advisor_hint=hint,
            advisor_honored=honored,
            attempt=int(attempt)),
        terminal=False,
        considered=tuple(considered),
        rejected=tuple(rejected))


__all__ = [
    "ActionPlan", "PLANNER_RULE_VERSION", "PlanDecision", "REASON_ACTION_NOT_IMPLEMENTED",
    "REASON_AUTHORIZATION_UNAVAILABLE", "REASON_BUDGET_PREFIX",
    "REASON_CAPABILITY_CONTRACT_ONLY", "REASON_CHAIN_NOT_IMPLEMENTED",
    "REASON_CHAIN_TERMINATED", "REASON_CONFIRMED", "REASON_NO_AVAILABLE_ACTION",
    "REASON_NO_REQUIRED_STAGE", "REASON_RETRIES_EXHAUSTED", "SAFETY_ORDER",
    "plan_next_action",
]
