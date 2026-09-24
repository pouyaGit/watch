"""EPIC12 — the bounded autonomous verification loop (§15).

    candidate -> chain state -> missing evidence -> authorized action
              -> structured observation -> EPIC11 classification
              -> claim evaluation -> next required evidence -> terminal verdict

The loop is deliberately boring: it runs at most ``max_steps`` actions, refuses
to spend a budget it does not have, requires progress (a step that produces no
new observation ends the loop), and terminates in a **deterministic** state:

``CONFIRMED``
    the EPIC11 gate returned ``VERIFIED``.
``NOT_CONFIRMED``
    the evidence contradicted a required stage (e.g. a safe/encoded context, a
    marker that is not reflected) — a first-class negative result (§9).
``BLOCKED``
    authorization, capability or scope prevented verification.  Never a finding.
``VERIFICATION_PENDING``
    the loop stopped with evidence still missing (steps exhausted, no executor
    wired, retries exhausted).
``BUDGET_EXHAUSTED``
    a declared limit stopped the loop before the chain completed.
``ERROR``
    an unexpected internal failure — reported, never converted into a finding.

The verdict always comes from the EPIC11 gate; the loop never computes it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from backend.research_agents.verification import actions as ac
from backend.research_agents.verification import budget as vb
from backend.research_agents.verification import chains as ch
from backend.research_agents.verification import engine as en
from backend.research_agents.verification import executors as ex
from backend.research_agents.verification import planner as pl
from backend.research_agents.verification.engine import ChainState

LOOP_RULE_VERSION = "epic12-verification-loop-1"

LOOP_CONFIRMED = "CONFIRMED"
LOOP_NOT_CONFIRMED = "NOT_CONFIRMED"
LOOP_BLOCKED = "BLOCKED"
LOOP_PENDING = "VERIFICATION_PENDING"
LOOP_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
LOOP_ERROR = "ERROR"

LOOP_TERMINATIONS: tuple[str, ...] = (
    LOOP_CONFIRMED, LOOP_NOT_CONFIRMED, LOOP_BLOCKED, LOOP_PENDING,
    LOOP_BUDGET_EXHAUSTED, LOOP_ERROR)

DEFAULT_MAX_STEPS = 4


@dataclass
class LoopOutcome:
    """The persisted outcome of one bounded verification loop."""

    objective_id: str
    candidate_id: str
    vulnerability_class: str
    scope_ref: str
    chain_state: dict[str, Any] = field(default_factory=dict)
    termination: str = LOOP_PENDING
    termination_reason: str = ""
    steps: int = 0
    actions: tuple[dict[str, Any], ...] = ()
    observations: tuple[dict[str, Any], ...] = ()
    verdict: str = ""
    verdict_reason: str = ""
    verdict_source: str = en.VERDICT_SOURCE
    why_not_confirmed: tuple[str, ...] = ()
    blocked_reason: str = ""
    budget: dict[str, Any] = field(default_factory=dict)
    llm_calls: int = 0
    llm_failures: int = 0
    evidence_gained: tuple[str, ...] = ()
    evidence_missing: tuple[str, ...] = ()
    runtime_seconds: float = 0.0
    started_at: str = ""
    finished_at: str = ""
    errors: tuple[str, ...] = ()
    rule_version: str = LOOP_RULE_VERSION

    @property
    def confirmed(self) -> bool:
        return self.termination == LOOP_CONFIRMED

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "candidate_id": self.candidate_id,
            "vulnerability_class": self.vulnerability_class,
            "scope_ref": self.scope_ref,
            "chain_state": dict(self.chain_state),
            "termination": self.termination,
            "termination_reason": self.termination_reason,
            "steps": self.steps,
            "actions": [dict(a) for a in self.actions],
            "observations": [dict(o) for o in self.observations],
            "verdict": self.verdict,
            "verdict_reason": self.verdict_reason,
            "verdict_source": self.verdict_source,
            "why_not_confirmed": list(self.why_not_confirmed),
            "blocked_reason": self.blocked_reason,
            "budget": dict(self.budget),
            "llm_calls": self.llm_calls,
            "llm_failures": self.llm_failures,
            "evidence_gained": list(self.evidence_gained),
            "evidence_missing": list(self.evidence_missing),
            "runtime_seconds": round(float(self.runtime_seconds), 3),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "errors": list(self.errors),
            "rule_version": self.rule_version,
        }


def _utcnow() -> str:
    from backend.research_agents.finding.models import utcnow
    return utcnow()


def _llm_budget_owner(budget: Any) -> bool:
    """True when a budget owns the ``max_llm_calls`` resource for this layer."""
    if budget is None:
        return False
    if "max_llm_calls" in getattr(budget, "limits", {}) or {}:
        return True
    try:
        return bool(budget.delegated("max_llm_calls"))
    except Exception:  # noqa: BLE001 - an opaque budget owns nothing here
        return False


def _llm_exhausted(budget: Any) -> bool:
    """Only a budget that OWNS ``max_llm_calls`` may refuse advisory calls.

    Without such a budget the advisory lane is bounded by ``max_steps`` alone
    (at most one call per step), so no advisory budget is invented and no
    second ledger is created.
    """
    if not _llm_budget_owner(budget):
        return False
    try:
        return not budget.allow("max_llm_calls", 1)
    except Exception:  # noqa: BLE001 - an unreadable budget refuses, fail closed
        return True


def _consume_llm(budget: Any) -> None:
    if not _llm_budget_owner(budget):
        return
    try:
        budget.ensure("max_llm_calls", 1, reason="chain_advisor")
    except Exception:  # noqa: BLE001 - a refusal must not become an outcome
        pass


def termination_for(state: ChainState, *, budget: Any = None) -> tuple[str, str]:
    """Map an EPIC11 verdict + budget state to a loop termination."""
    if state.confirmed:
        return LOOP_CONFIRMED, state.verdict_reason or "claim_supported"
    if state.rejected:
        return LOOP_NOT_CONFIRMED, state.termination_reason or "evidence_contradicted"
    if state.blocked:
        return LOOP_BLOCKED, (state.blockers[0] if state.blockers
                              else state.verdict_reason or "blocked")
    if budget is not None:
        try:
            # A limit of 0 means the lane is unavailable in this runtime, which
            # is a capability fact, not a spent budget: only a resource that was
            # actually spendable AND is used up counts as exhaustion.
            used = budget.used()
            limits = dict(getattr(budget, "limits", {}))
            exhausted = sorted(
                k for k, limit in limits.items()
                if int(limit) > 0 and int(used.get(k, 0)) >= int(limit))
        except Exception:  # noqa: BLE001
            exhausted = []
        if exhausted:
            return LOOP_BUDGET_EXHAUSTED, f"budget_exhausted:{exhausted[0]}"
    return LOOP_PENDING, state.verdict_reason or "evidence_missing"


def run_verification_loop(
    *,
    candidate_id: str,
    objective_id: str,
    vulnerability_class: str,
    scope_ref: str,
    store: Any,
    target: str = "",
    rows: Iterable[dict[str, Any]] = (),
    authorization: Any = None,
    authorization_id: str = "",
    context: dict[str, Any] | None = None,
    budget: Any = None,
    limits: dict[str, int] | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    advisor: Callable[..., Any] | None = None,
    advisor_hint: str = "",
    now_fn: Callable[[], float] = time.monotonic,
    evidence_confirmed_authorization: bool = False,
    runtime_gate_reason: str = "",
    runtime_gate_claimed_case: bool = False,
    persist: bool = True,
) -> LoopOutcome:
    """Run one bounded verification loop for a candidate/objective."""
    started = now_fn()
    started_at = _utcnow()
    cls = ch.normalize_class(vulnerability_class)
    chain = ch.chain_for(cls)
    ctx = dict(context or {})
    ctx.setdefault("job_id", "")
    evidence_rows: list[dict[str, Any]] = [dict(r) for r in (rows or [])]
    if store is not None:
        try:
            evidence_rows.extend(store.evidence_rows_for_candidate(candidate_id))
        except Exception:  # noqa: BLE001 - an unreadable store must not fabricate
            pass

    budget = budget or (vb.VerificationBudget(
        store, {**vb.DEFAULT_VERIFICATION_LIMITS, **dict(limits or {})},
        objective_id=objective_id) if store is not None else None)
    runtime_limit = float(getattr(budget, "limits", {}).get(
        "max_runtime_seconds", vb.DEFAULT_VERIFICATION_LIMITS[
            "max_runtime_seconds"]))

    outcome = LoopOutcome(
        objective_id=objective_id, candidate_id=candidate_id,
        vulnerability_class=cls, scope_ref=scope_ref, started_at=started_at)
    executed_actions: list[dict[str, Any]] = []
    produced_observations: list[dict[str, Any]] = []
    attempted: list[str] = []
    llm_calls = 0
    llm_failures = 0

    def evaluate() -> ChainState:
        return en.evaluate_chain(
            cls, evidence_rows, authorization=authorization, chain=chain,
            runtime_gate_reason=runtime_gate_reason,
            runtime_gate_claimed_case=runtime_gate_claimed_case,
            evidence_confirmed_authorization=evidence_confirmed_authorization)

    try:
        state = evaluate()
        step = 0
        hint = advisor_hint
        while step < max(0, int(max_steps)):
            if state.confirmed or state.chain_terminated or state.blocked:
                break
            if (now_fn() - started) >= runtime_limit:
                outcome.errors = tuple(outcome.errors) + (
                    "runtime_budget_exhausted",)
                break

            # ---- advisory (never authoritative, at most one call per step,
            # and bounded by the llm allowance of whichever layer owns it)
            if advisor is not None and not hint and not _llm_exhausted(budget):
                _consume_llm(budget)
                llm_calls += 1
                try:
                    hint_value, _meta = advisor(
                        candidate_id=candidate_id, chain_state=state.to_dict(),
                        missing_evidence=list(state.next_stage_missing_types),
                        allowed_actions=(list(state.stage(state.next_stage)
                                              .allowed_actions)
                                         if state.stage(state.next_stage) else []),
                        budget=budget.report() if budget is not None else {})
                    hint = str(hint_value or "").strip().upper()
                    # an advisory that failed inside the advisor wrapper is
                    # still an advisory failure (recorded, never a result)
                    if isinstance(_meta, Mapping) and _meta.get("error"):
                        llm_failures += 1
                except Exception:  # noqa: BLE001 - an advisor failure is not a
                    # verification result: continue deterministically
                    llm_failures += 1
                    hint = ""

            decision = pl.plan_next_action(
                state, candidate_id=candidate_id, objective_id=objective_id,
                scope_ref=scope_ref, target=target,
                authorization_id=authorization_id, inputs=dict(ctx),
                attempt=1 + attempted.count(""), budget=budget,
                attempted=attempted, advisor_hint=hint)
            if decision.terminal or decision.plan is None:
                outcome.termination_reason = decision.termination_reason
                outcome.blocked_reason = (
                    decision.termination_reason
                    if decision.termination_reason.startswith(
                        (pl.REASON_AUTHORIZATION_UNAVAILABLE,
                         pl.REASON_CAPABILITY_CONTRACT_ONLY,
                         pl.REASON_CHAIN_NOT_IMPLEMENTED,
                         pl.REASON_ACTION_NOT_IMPLEMENTED,
                         pl.REASON_BUDGET_PREFIX)) else "")
                break

            plan = decision.plan
            # ---- budget: refuse before the work starts (fail closed)
            if budget is not None:
                try:
                    budget.ensure("max_actions", 1,
                                  reason=f"action:{plan.action_type}")
                    if plan.requires_network:
                        budget.ensure("max_requests", 1,
                                      reason=f"request:{plan.action_type}")
                    if plan.safety == ac.SAFETY_ACTIVE:
                        budget.ensure("max_payload_attempts", 1,
                                      reason=f"payload:{plan.action_type}")
                except vb.VerificationBudgetExhausted as exc:
                    outcome.termination_reason = f"budget_exhausted:{exc}"
                    outcome.blocked_reason = str(exc)
                    break

            action = ac.VerificationAction(
                action_type=plan.action_type, candidate_id=candidate_id,
                objective_id=objective_id, scope_ref=scope_ref, target=target,
                authorization_id=authorization_id, inputs=plan.inputs,
                attempt=1 + attempted.count(plan.action_type),
                provenance={"stage": plan.stage_key, "plan_reason":
                            plan.plan_reason,
                            "advisor_honored": plan.advisor_honored})
            attempted.append(plan.action_type)
            step += 1
            if store is not None and persist:
                store.record_action(action)

            if action.spec.requires_authorization and authorization_id:
                action.transition(ac.ACTION_AUTHORIZED, reason="authorized")
                if store is not None and persist:
                    store.record_action(action)
            action.transition(ac.ACTION_EXECUTING, reason="executing")
            result = ex.execute_action(action, context=ctx)

            if result.blocked or not result.ok:
                reason = result.blocked_reason or "execution_failed"
                action.transition(ac.ACTION_BLOCKED, reason=reason,
                                  detail=result.error)
                if store is not None and persist:
                    store.record_action(action)
                executed_actions.append(action.to_dict())
                outcome.blocked_reason = reason
                outcome.termination_reason = reason
                break

            action.transition(ac.ACTION_SUCCEEDED, reason="executed")
            action.result = dict(result.result)
            action.executor = result.executor
            new_rows: list[dict[str, Any]] = []
            for observation in result.observations:
                if budget is not None:
                    try:
                        budget.ensure("max_observations", 1,
                                      reason=f"observation:{observation.signal}")
                    except vb.VerificationBudgetExhausted as exc:
                        outcome.termination_reason = f"budget_exhausted:{exc}"
                        break
                row = observation.to_dict()
                produced_observations.append(row)
                action.observation_ids.append(observation.observation_id)
                action.evidence_refs.append(str(row.get("id") or ""))
                if store is not None and persist:
                    store.record_observation(observation)
                new_rows.append(observation.to_evidence_row())
            if store is not None and persist:
                store.record_action(action)
            executed_actions.append(action.to_dict())

            if not new_rows:
                # no progress: terminate deterministically instead of looping
                outcome.termination_reason = (
                    outcome.termination_reason or "no_new_evidence")
                break
            evidence_rows.extend(new_rows)
            state = evaluate()

        # ---- terminal mapping (the EPIC11 gate remains authoritative)
        outcome.chain_state = state.to_dict()
        outcome.verdict = state.verdict
        outcome.verdict_reason = state.verdict_reason
        outcome.why_not_confirmed = state.why_not_confirmed
        # the COMPLETE outstanding requirement (every required stage that is
        # not satisfied and not n/a), not only the next one — an operator must
        # be able to read everything that stands between this and a verdict
        missing: list[str] = []
        for stage in state.stages:
            if stage.status in (ch.STAGE_SATISFIED, ch.STAGE_NOT_APPLICABLE):
                continue
            if not stage.required_for_confirmation:
                continue
            for evidence_type in stage.missing_types:
                if evidence_type not in missing:
                    missing.append(evidence_type)
        outcome.evidence_missing = tuple(missing)
        termination, reason = termination_for(state, budget=budget)
        if (not state.confirmed and not state.rejected and not state.blocked
                and outcome.termination_reason):
            # an explicit planner/executor stop keeps its own reason
            if outcome.termination_reason.startswith(
                    (pl.REASON_AUTHORIZATION_UNAVAILABLE,
                     pl.REASON_CAPABILITY_CONTRACT_ONLY,
                     pl.REASON_CHAIN_NOT_IMPLEMENTED,
                     pl.REASON_ACTION_NOT_IMPLEMENTED,
                     "budget_exhausted", ex.REASON_TRANSPORT_UNAVAILABLE,
                     ex.REASON_CAPABILITY_UNAVAILABLE,
                     "target_out_of_scope", "runtime_budget_exhausted",
                     "no_new_evidence")):
                if outcome.termination_reason.startswith("budget_exhausted"):
                    termination = LOOP_BUDGET_EXHAUSTED
                elif outcome.termination_reason.startswith(
                        ("target_out_of_scope", pl.REASON_AUTHORIZATION_UNAVAILABLE,
                         pl.REASON_CAPABILITY_CONTRACT_ONLY,
                         pl.REASON_CHAIN_NOT_IMPLEMENTED)):
                    termination = LOOP_BLOCKED
                else:
                    termination = LOOP_PENDING
                reason = outcome.termination_reason
        outcome.termination = termination
        outcome.termination_reason = reason
        outcome.steps = step
        outcome.actions = tuple(executed_actions)
        outcome.observations = tuple(produced_observations)
        outcome.llm_calls = llm_calls
        outcome.llm_failures = llm_failures
        outcome.evidence_gained = tuple(
            sorted({str(o.get("evidence_type") or o.get("evidence_class") or "")
                    for o in produced_observations
                    if o.get("evidence_type")}))
        outcome.budget = budget.report() if budget is not None else {}
    except Exception as exc:  # noqa: BLE001 - never a finding, always reported
        outcome.termination = LOOP_ERROR
        outcome.termination_reason = f"loop_error:{type(exc).__name__}"
        outcome.errors = tuple(outcome.errors) + (str(exc)[:200],)
    finally:
        outcome.runtime_seconds = float(now_fn() - started)
        outcome.finished_at = _utcnow()
        if store is not None and persist:
            try:
                store.record_loop(outcome.to_dict())
            except Exception as exc:  # noqa: BLE001
                outcome.errors = tuple(outcome.errors) + (
                    f"loop_persist:{type(exc).__name__}",)
    return outcome


__all__ = [
    "DEFAULT_MAX_STEPS", "LOOP_BLOCKED", "LOOP_BUDGET_EXHAUSTED",
    "LOOP_CONFIRMED", "LOOP_ERROR", "LOOP_NOT_CONFIRMED", "LOOP_PENDING",
    "LOOP_RULE_VERSION", "LOOP_TERMINATIONS", "LoopOutcome",
    "run_verification_loop", "termination_for",
]
