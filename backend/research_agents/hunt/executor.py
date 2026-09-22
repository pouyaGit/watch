"""Bounded autonomous execution loop (Phases 9, 11, 12, 18).

One objective, hard budgets, explicit termination:

  objective -> research state -> missing evidence -> Hunt Plan
  -> validate -> authorization gate -> observation runtime
  -> persisted observation -> interim authoritative evidence gate
  -> learning -> re-plan or terminate.

Everything dangerous lives outside this loop: observations execute only
through the injected ObservationProvider (the existing runtime boundary),
authorization only through the injected AuthorizationChecker gate, the
evidence gate is called READ-ONLY (this module never records evidence or
cases), and the LLM advisor only ever returns suggestions that trusted
code re-validates.

Hard limits (fail-closed): max plans, max observations, max planning
iterations, max LLM planning calls, max wall seconds, max context is
enforced by the caller's allowlist. No infinite loop is constructible.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from backend.research_agents.hunt.authorization import (
    authorization_gate,
    build_authorization_request,
    reverify_before_observation,
)
from backend.research_agents.hunt.missing_evidence import (
    any_satisfiable,
    compute_missing_evidence,
)
from backend.research_agents.hunt.models import (
    HuntObjective,
    ObservationRecord,
    PlanTransition,
    new_id,
)
from backend.research_agents.hunt.planner import (
    AdvisorOutcome,
    advisor_request,
    build_candidates,
    build_plan,
    map_advisor_response,
    validate_final_plan,
)
from backend.research_agents.hunt.registry import REGISTRY
from backend.research_agents.hunt.store import HuntStore, utcnow
from backend.research_agents.hunt.uncertainty import ResearchUncertainty

HUNT_RULE_VERSION = "autonomous-hunt-planner-v1"

# Explicit termination reasons (Phase 12) — never "completed" when the
# real state is unknown.
TERM_SUFFICIENT = "sufficient_evidence"
TERM_REJECTED_NO_SIGNAL = "hypothesis_rejected_no_signal"
TERM_NO_AUTHORIZED_REDUCTION = "no_authorized_observation_can_reduce_uncertainty"
TERM_AUTHORIZATION_DENIED = "authorization_denied"
TERM_SCOPE_INVALID = "scope_invalid"
TERM_CAPABILITY_UNAVAILABLE = "required_capability_unavailable"
TERM_MAX_PLANS = "max_plans_per_objective_reached"
TERM_MAX_OBSERVATIONS = "max_observations_reached"
TERM_MAX_ITERATIONS = "max_planning_iterations_reached"
TERM_BUDGET = "runtime_budget_exhausted"
TERM_OBSERVATION_UNAVAILABLE = "observation_runtime_unavailable"
TERM_PLAN_VALIDATION = "plan_validation_failed"
TERM_STALE_AUTHORIZATION = "stale_authorization"


@dataclass(frozen=True)
class HuntLimits:
    max_plans_per_objective: int = 3
    max_observations: int = 6
    max_planning_iterations: int = 4
    max_llm_planning_calls: int = 2
    max_seconds: int = 60
    per_type_limit: int = 25
    max_consecutive_observation_failures: int = 2


@dataclass
class HuntOutcome:
    enabled: bool = True
    objective_id: str = ""
    state: str = ""
    termination_reason: str = ""
    termination_detail: str = ""
    iterations: int = 0
    plan_ids: list[str] = None            # type: ignore[assignment]
    plans: list[dict[str, Any]] = None    # type: ignore[assignment]
    authorization_ids: list[str] = None   # type: ignore[assignment]
    observation_ids: list[str] = None     # type: ignore[assignment]
    missing_remaining: list[str] = None   # type: ignore[assignment]
    rows_added: int = 0
    knowledge_added: int = 0
    rows: list[dict[str, Any]] = None      # type: ignore[assignment]
    knowledge: list[dict[str, Any]] = None  # type: ignore[assignment]
    memory_learned: list[str] = None      # type: ignore[assignment]
    llm_advisory: dict[str, Any] = None   # type: ignore[assignment]
    errors: list[str] = None              # type: ignore[assignment]
    rule_version: str = HUNT_RULE_VERSION

    def __post_init__(self) -> None:
        for name in ("plan_ids", "plans", "authorization_ids",
                     "observation_ids", "missing_remaining",
                     "memory_learned", "errors", "rows", "knowledge"):
            if getattr(self, name) is None:
                setattr(self, name, [])
        if self.llm_advisory is None:
            self.llm_advisory = {"used": False, "calls": 0,
                                 "rejected": [], "errors": []}

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_version": self.rule_version,
            "enabled": self.enabled,
            "objective_id": self.objective_id,
            "state": self.state,
            "termination_reason": self.termination_reason,
            "termination_detail": self.termination_detail,
            "iterations": self.iterations,
            "plan_ids": list(self.plan_ids),
            "plans": list(self.plans),
            "authorization_ids": list(self.authorization_ids),
            "observation_ids": list(self.observation_ids),
            "missing_remaining": list(self.missing_remaining)[:12],
            "rows_added": int(self.rows_added),
            "knowledge_added": int(self.knowledge_added),
            "memory_learned": list(self.memory_learned),
            "llm_advisory": dict(self.llm_advisory),
            "errors": list(self.errors)[:8],
        }


def _row_key(row: dict[str, Any]) -> str:
    ref = row.get("ref") or row.get("_id") or row.get("url") or ""
    return f"{row.get('source', '?')}:{ref}"


def _observe_typed(provider: Any, job: Any, otype: str,
                   limit: int) -> list[dict[str, Any]]:
    """One type-scoped read through the existing observation boundary."""
    try:
        return list(provider.observe(job, types=(otype,), limit=limit)
                    or [])
    except TypeError:
        # provider without type support: fall back to its own contract
        return list(provider.observe(job) or [])


def _gate_evidence_rows(job: Any,
                        analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """In-memory evidence rows for the READ-ONLY interim gate decision.

    Never persisted: ids are obviously synthetic and this module has no
    access to the evidence store (AST-verifiable).
    """
    rows: list[dict[str, Any]] = []
    for idx, cand in enumerate(
            (analysis.get("evidence_candidates") or [])[:20]):
        rows.append({
            "id": f"interim-hunt-{idx}",
            "type": cand.get("type"),
            "observation_ref": cand.get("observation_ref", ""),
            "job_id": job.id,
        })
    return rows


def run_hunt(
    *,
    job: Any,
    capability: Any,
    store: Any,                      # RuntimeStore (activity/audit only)
    hunt_store: HuntStore,
    observations: Any,               # ObservationProvider (execution boundary)
    auth_checker: Any,               # AuthorizationChecker (scope boundary)
    determin_fn: Callable[..., dict[str, Any]],
    gate_fn: Callable[..., Any],     # evaluate_case_creation (read-only)
    limits: HuntLimits,
    initial_rows: Iterable[dict[str, Any]] = (),
    initial_knowledge: Iterable[dict[str, Any]] = (),
    advisor_fn: Callable[[dict], tuple[Any, dict]] | None = None,
    knowledge_fn: Callable[[list[str]], list[dict]] | None = None,
    memory_store: Any | None = None,
    deadline_fn: Callable[[], bool] | None = None,   # True => expired
    emit_activity: Callable[[str, str], None] | None = None,
    emit_audit: Callable[[str, dict[str, Any]], None] | None = None,
    now_fn: Callable[[], str] = utcnow,
) -> HuntOutcome:
    """Run the bounded autonomous hunt loop for one job."""
    outcome = HuntOutcome()
    start = time.monotonic()

    def activity(action: str, detail: str) -> None:
        if emit_activity:
            try:
                emit_activity(action, detail)
            except Exception:  # noqa: BLE001 - activity is best-effort
                pass

    def audit(stage: str, payload: dict[str, Any]) -> None:
        if emit_audit:
            try:
                emit_audit(stage, payload)
            except Exception as exc:  # noqa: BLE001 - visible, never silent
                outcome.errors.append(
                    f"audit:{stage}:{type(exc).__name__}")

    def expired() -> bool:
        if deadline_fn is not None:
            try:
                return bool(deadline_fn())
            except Exception:  # noqa: BLE001
                return True
        return (time.monotonic() - start) > limits.max_seconds

    allowed = tuple(str(t) for t in
                    (getattr(capability, "allowed_observation_types", ()) or ()))
    if not allowed:
        outcome.state = "BLOCKED"
        outcome.termination_reason = TERM_CAPABILITY_UNAVAILABLE
        outcome.termination_detail = (
            "capability declares no allowed observation types")
        activity("hunt_terminated",
                 f"reason={TERM_CAPABILITY_UNAVAILABLE} "
                 f"(no allowed observation types)")
        outcome.rows = list(initial_rows)
        outcome.knowledge = list(initial_knowledge)
        return outcome

    scope_ref = str(getattr(job, "authorization_ref", "") or "")
    target_context = {
        "program": str(getattr(job, "program", "") or ""),
        "subdomain": str(getattr(job, "subdomain", "") or ""),
        "job_mode": str(getattr(job, "execution_mode", "") or ""),
        "allowed_observation_types": list(allowed),
    }
    if not scope_ref:
        # no authoritative scope => no objective can exist (fail closed)
        outcome.state = "BLOCKED"
        outcome.termination_reason = TERM_AUTHORIZATION_DENIED
        outcome.termination_detail = (
            "job has no authorization scope reference; hunt never starts")
        outcome.rows = list(initial_rows)
        outcome.knowledge = list(initial_knowledge)
        activity("hunt_terminated",
                 f"reason={TERM_AUTHORIZATION_DENIED} "
                 f"(job missing authorization_ref; no objective created)")
        return outcome
    rows_ref: dict[str, Any] = {
        "rows": list(initial_rows),
        "kb": list(initial_knowledge),
    }
    return execute_hunt(
        outcome=outcome, job=job, capability=capability, store=store,
        hunt_store=hunt_store, observations=observations,
        auth_checker=auth_checker, determin_fn=determin_fn,
        gate_fn=gate_fn, limits=limits, advisor_fn=advisor_fn,
        knowledge_fn=knowledge_fn, memory_store=memory_store,
        expired=expired, activity=activity, audit=audit, allowed=allowed,
        scope_ref=scope_ref, target_context=target_context,
        hypothesis="", rows_ref=rows_ref, start=start, now_fn=now_fn)


def execute_hunt(  # noqa: C901, PLR0915 - bounded by HuntLimits
    *,
    outcome: HuntOutcome,
    job: Any,
    capability: Any,
    store: Any,
    hunt_store: HuntStore,
    observations: Any,
    auth_checker: Any,
    determin_fn: Callable[..., dict[str, Any]],
    gate_fn: Callable[..., Any],
    limits: HuntLimits,
    advisor_fn: Any,
    knowledge_fn: Any,
    memory_store: Any,
    expired: Callable[[], bool],
    activity: Callable[[str, str], None],
    audit: Callable[[str, dict[str, Any]], None],
    allowed: tuple[str, ...],
    scope_ref: str,
    target_context: dict[str, Any],
    hypothesis: str,
    rows_ref: dict[str, Any],
    start: float,
    now_fn: Callable[[], str],
) -> HuntOutcome:  # noqa: C901 - one explicit orchestration path
    rows_acc: list[dict[str, Any]] = rows_ref["rows"]
    kb_acc: list[dict[str, Any]] = rows_ref["kb"]
    seen_refs: set[str] = {_row_key(r) for r in rows_acc}
    seen_kb: set[str] = {str(d.get("id") or "") for d in kb_acc}
    initial_kb_count = len(seen_kb)
    observed_types: set[str] = set()
    objective_id = new_id("obj")

    research_objective = (
        "Determine whether the authorized observation set for this scope "
        f"contains sufficient evidence, across all observation types "
        f"allowed to {getattr(capability, 'agent_name', capability.category)},"
        " to support or reject the hypothesis."
    )
    determin0 = determin_fn(capability, job, rows_acc, kb_acc)
    if not hypothesis:
        for h in (determin0.get("hypotheses") or []):
            text = str((h or {}).get("hypothesis") or "").strip()
            if text:
                hypothesis = text[:300]
                break
        if not hypothesis:
            hypothesis = (f"{capability.category} hypothesis over "
                          f"{target_context.get('subdomain') or scope_ref}")

    objective = HuntObjective(
        objective_id=objective_id,
        job_id=str(getattr(job, "id", "") or ""),
        specialist=str(getattr(capability, "agent_name", "") or ""),
        category=str(capability.category),
        scope_ref=scope_ref,
        target_context=target_context,
        hypothesis=hypothesis,
        research_objective=research_objective,
        evidence_requirements={
            "min_evidence_refs": int(
                getattr(capability.evidence_requirements,
                        "min_evidence_refs", 2) or 2),
            "required_types": list(
                getattr(capability.evidence_requirements,
                        "required_types", ()) or ()),
            "require_high_confidence": bool(
                getattr(capability.evidence_requirements,
                        "require_high_confidence", True)),
        },
        state="OPEN",
        priority=int(getattr(job, "priority_score", 50) or 50),
        provenance={"source": "autonomous_hunt_planner_v1",
                    "job_id": str(getattr(job, "id", "") or ""),
                    "created_by": "runtime_hunt_loop"},
        created_at=now_fn(),
        updated_at=now_fn(),
    )
    objective = hunt_store.create_objective(objective)
    outcome.objective_id = objective.objective_id
    activity("hunt_objective_created",
             f"{objective.objective_id} state=OPEN scope={scope_ref} "
             f"specialist={objective.specialist} "
             f"allowed={','.join(allowed)}")

    state = objective.state
    plans_count = 0
    obs_executed = 0
    llm_calls = 0
    iterations = 0
    consecutive_obs_failures = 0
    parent_plan_id = ""
    termination = ""
    termination_detail = ""
    final_state = ""

    def set_state(new_state: str, reason: str) -> None:
        nonlocal state
        if new_state == state:
            return
        try:
            revised = hunt_store.revise_objective(
                objective.objective_id, state=new_state,
                reason=reason, iteration=iterations,
                plans_created=plans_count, observations_run=obs_executed,
                llm_plans_used=llm_calls, now=now_fn())
            state = revised.state
            activity("research_state_updated",
                     f"{objective.objective_id} -> {state} "
                     f"({reason[:120]})")
        except Exception as exc:  # noqa: BLE001
            outcome.errors.append(
                f"state_update:{type(exc).__name__}")

    def finish(reason: str, detail: str, state_name: str) -> HuntOutcome:
        nonlocal termination, termination_detail, final_state
        termination = reason
        termination_detail = detail[:300]
        final_state = state_name
        try:
            hunt_store.revise_objective(
                objective.objective_id, state=state_name,
                reason=termination, iteration=iterations,
                plans_created=plans_count, observations_run=obs_executed,
                llm_plans_used=llm_calls,
                termination_reason=termination,
                termination_detail=termination_detail, now=now_fn())
            state_final = state_name
        except Exception as exc:  # noqa: BLE001
            outcome.errors.append(f"final_state:{type(exc).__name__}")
            state_final = state
        outcome.state = state_final
        outcome.termination_reason = termination
        outcome.termination_detail = termination_detail
        outcome.iterations = iterations
        activity("hunt_terminated",
                 f"{objective.objective_id} reason={termination} "
                 f"state={state_final} plans={plans_count} "
                 f"observations={obs_executed} iterations={iterations}")
        outcome.rows = list(rows_ref["rows"])
        outcome.knowledge = list(rows_ref["kb"])
        audit("hunt_lineage_final", {
            "objective_id": objective.objective_id,
            "state": state_final,
            "termination_reason": termination,
            "plans": outcome.plan_ids,
            "observations": outcome.observation_ids,
            "missing_remaining": outcome.missing_remaining,
            "llm_calls": llm_calls,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
            "rule_version": HUNT_RULE_VERSION,
        })
        rows_ref["rows"] = rows_acc
        rows_ref["kb"] = kb_acc
        return outcome

    def no_reduction_termination(missing_blockers: list[str]) -> HuntOutcome:
        no_signal = "no_category_signal_in_authorized_observations" in \
            missing_blockers
        if no_signal:
            return finish(TERM_REJECTED_NO_SIGNAL,
                          "all allowed observation types were observed and "
                          "no category signal exists in authorized rows",
                          "REJECTED")
        return finish(TERM_NO_AUTHORIZED_REDUCTION,
                      "remaining missing evidence has no allowed "
                      "observation type that can still be read",
                      "BLOCKED")

    while True:
        iterations += 1
        if iterations > limits.max_planning_iterations:
            iterations = limits.max_planning_iterations
            return finish(TERM_MAX_ITERATIONS,
                          f"planning iteration budget "
                          f"{limits.max_planning_iterations} exhausted",
                          "NEEDS_EVIDENCE"
                          if state not in {"RESOLVED", "REJECTED",
                                           "BLOCKED"} else state)
        if expired():
            return finish(TERM_BUDGET,
                          f"runtime budget {limits.max_seconds}s exhausted",
                          state if state in {"RESOLVED", "REJECTED",
                                             "BLOCKED"}
                          else "NEEDS_EVIDENCE")

        # ---------------- 1-2. research state + missing evidence
        determin = determin_fn(capability, job, rows_acc, kb_acc)
        gate_decision = gate_fn(capability, job, determin,
                                _gate_evidence_rows(job, determin))
        missing = compute_missing_evidence(
            capability=capability, scope_ref=scope_ref, analysis=determin,
            observed_types=observed_types,
            knowledge_ids=[str(d.get("id")) for d in kb_acc],
            hypothesis=objective.hypothesis,
        )
        satisfiable = [m for m in missing if m.satisfiable]
        outcome.missing_remaining = [m.item_code for m in missing]

        uncertainty = ResearchUncertainty(
            objective_id=objective.objective_id,
            hypothesis=objective.hypothesis,
            state=("RESOLVED"
                   if (gate_decision.create and not satisfiable)
                   else "NEEDS_EVIDENCE"),
            supporting_observations=sorted({
                str(c.get("observation_ref") or "")
                for c in (determin.get("evidence_candidates") or [])
                if str(c.get("type")) == "observation"})[:20],
            evidence_collected=sorted(seen_refs)[:40],
            evidence_requested=[r["observation_id"]
                                for r in _obs_rows(hunt_store,
                                                   objective.objective_id)],
            missing_evidence=[m.to_dict() for m in missing[:12]],
            confidence=str(determin.get("confidence") or "insufficient"),
            blockers=[str(b) for b in (determin.get("blockers") or [])][:8],
            research_objective=objective.research_objective,
            scope_ref=scope_ref, specialist=objective.specialist,
            iteration=iterations,
            provenance={"job_id": job.id, "source": "hunt_loop",
                        "created_at": now_fn()},
        )

        # -------- sufficiency (authoritative gate, coverage complete)
        if gate_decision.create and not satisfiable:
            return finish(TERM_SUFFICIENT,
                          f"evidence gate: {gate_decision.reason}; no "
                          f"satisfiable missing evidence remains",
                          "RESOLVED")
        if not satisfiable:
            audit("hunt_lineage", _iter_payload(
                objective, iterations, missing, determin, None,
                gate_decision, uncertainty, termination_hint="no_reduction"))
            return no_reduction_termination(
                [str(b) for b in (determin.get("blockers") or [])])

        if state in {"OPEN"}:
            set_state("NEEDS_EVIDENCE",
                      f"{len(missing)} missing evidence item(s), "
                      f"gate={gate_decision.reason}")
        elif state == "OBSERVATION_COMPLETE":
            set_state("NEEDS_EVIDENCE",
                      f"post-observation gate={gate_decision.reason}; "
                      f"{len(missing)} item(s) remain")

        activity("missing_evidence_detected",
                 f"{objective.objective_id} iter={iterations} items="
                 + ",".join(m.item_code for m in missing[:8]))

        # ---------------- budgets checked BEFORE planning
        if plans_count >= limits.max_plans_per_objective:
            return finish(TERM_MAX_PLANS,
                          f"plan budget {limits.max_plans_per_objective} "
                          f"exhausted with {len(satisfiable)} item(s) left",
                          "NEEDS_EVIDENCE")
        if obs_executed >= limits.max_observations:
            return finish(TERM_MAX_OBSERVATIONS,
                          f"observation budget {limits.max_observations} "
                          f"exhausted", "NEEDS_EVIDENCE")

        # ---------------- 3-5. plan + validate (trusted code)
        if state == "NEEDS_EVIDENCE":
            set_state("READY_FOR_PLANNING",
                      "missing evidence is satisfiable by an allowed type")
        candidates = build_candidates(
            missing_items=missing, capability=capability,
            observed_types=observed_types, scope_ready=bool(scope_ref))
        if not candidates:
            return no_reduction_termination(
                [str(b) for b in (determin.get("blockers") or [])])

        advisor: AdvisorOutcome | None = None
        if advisor_fn is not None and llm_calls < limits.max_llm_planning_calls:
            llm_calls += 1
            try:
                request = advisor_request(
                    objective=objective, missing_items=missing,
                    candidates=candidates, capability=capability,
                    allowed_types=allowed, observed_types=observed_types,
                    job=job)
                response, meta = advisor_fn(request)
                advisor = map_advisor_response(
                    response, capability=capability, allowed_types=allowed)
                advisor.model_requested = str(
                    meta.get("model_requested") or "openrouter/free")
                advisor.model_resolved = str(
                    meta.get("model_resolved") or "")
                advisor.latency_ms = int(meta.get("latency_ms") or 0)
                if advisor.error:
                    outcome.llm_advisory["errors"].append(advisor.error)
                if advisor.rejected_suggestions:
                    outcome.llm_advisory["rejected"].extend(
                        list(advisor.rejected_suggestions))
                if advisor.used:
                    outcome.llm_advisory["used"] = True
                outcome.llm_advisory["calls"] = llm_calls
            except Exception as exc:  # noqa: BLE001 - advisor degrades
                advisor = AdvisorOutcome(
                    used=False, accepted_types=(),
                    rejected_suggestions=(), forbidden_hits=(),
                    objective_interpretation="", rationale="",
                    blockers=(), confidence="advisory",
                    recommended_priority=50,
                    model_requested="openrouter/free", model_resolved="",
                    prompt_version="hunt-planner-advisor-v1", latency_ms=0,
                    error=(f"advisor_unavailable:{type(exc).__name__}: "
                           f"{str(exc)[:160]}"))
                outcome.llm_advisory["errors"].append(advisor.error)
                outcome.llm_advisory["calls"] = llm_calls
                activity("research_state_updated",
                         f"LLM planning advisor unavailable "
                         f"({type(exc).__name__}); deterministic planning "
                         f"continues")

        version = plans_count + 1
        plan, notes = build_plan(
            objective=objective, job=job, capability=capability,
            candidates=candidates, missing_items=missing,
            advisor=advisor, version=version, parent_plan_id=parent_plan_id,
            now=now_fn())
        if plan is None:
            return no_reduction_termination(
                [str(b) for b in (determin.get("blockers") or [])])
        try:  # advisory rejections stay reconstructable (Phase 14)
            plan.provenance["notes"] = [str(n)[:200] for n in notes][:8]
        except Exception:  # noqa: BLE001
            pass

        reject_reasons = validate_final_plan(
            plan, capability=capability, job=job, scope_ref=scope_ref)
        hunt_store.append_plan(plan)
        outcome.plan_ids.append(plan.plan_id)
        plans_count += 1
        activity("hunt_plan_created",
                 f"{plan.plan_id} v{plan.version} objective="
                 f"{objective.objective_id} types="
                 f"{','.join(plan.observation_types)} "
                 f"score_reason={plan.reason[:160]}")
        if plan.version > 1:
            activity("hunt_replanned",
                     f"{plan.plan_id} v{plan.version} after "
                     f"{objective.objective_id} re-evaluation; parent="
                     f"{parent_plan_id}")
        if reject_reasons:
            hunt_store.record_transition(PlanTransition(
                plan_id=plan.plan_id, from_state="DRAFT",
                to_state="REJECTED",
                reason="; ".join(reject_reasons)[:200], at=now_fn()))
            return finish(TERM_PLAN_VALIDATION,
                          "; ".join(reject_reasons)[:300], "BLOCKED")
        hunt_store.record_transition(PlanTransition(
            plan_id=plan.plan_id, from_state="DRAFT", to_state="VALIDATED",
            reason="trusted_code_validation_ok", at=now_fn()))
        activity("plan_validated",
                 f"{plan.plan_id} validation ok; "
                 f"{len(plan.observations_requested)} observation request(s)")

        if state == "READY_FOR_PLANNING":
            set_state("PLANNED", f"plan {plan.plan_id} validated")

        # ---------------- 6-7. authorization bridge (fail closed)
        request = build_authorization_request(plan, job=job,
                                              capability=capability)
        activity("authorization_requested",
                 f"{request['authorization_id']} plan={plan.plan_id} "
                 f"types={','.join(request['observation_types'])} "
                 f"scope={scope_ref}")
        hunt_store.record_transition(PlanTransition(
            plan_id=plan.plan_id, from_state="VALIDATED",
            to_state="AUTHORIZATION_REQUIRED",
            reason="authorization requested", at=now_fn()))
        record = authorization_gate(request, job=job, capability=capability,
                                    auth_checker=auth_checker)
        hunt_store.append_authorization(record)
        outcome.authorization_ids.append(record.auth_id)
        audit("hunt_authorization", {
            "objective_id": objective.objective_id,
            "plan_id": plan.plan_id, "auth_id": record.auth_id,
            "status": record.status,
            "reasons": list(record.reasons),
            "observation_types": list(record.observation_types),
        })
        if record.status != "GRANTED":
            hunt_store.record_transition(PlanTransition(
                plan_id=plan.plan_id, from_state="AUTHORIZATION_REQUIRED",
                to_state="BLOCKED",
                reason="; ".join(record.reasons)[:200], at=now_fn()))
            activity("authorization_rejected",
                     f"{record.auth_id} plan={plan.plan_id} reasons="
                     + ";".join(record.reasons)[:180])
            reason_text = " ".join(record.reasons)
            if "scope" in reason_text:
                term = TERM_SCOPE_INVALID
            else:
                term = TERM_AUTHORIZATION_DENIED
            return finish(term,
                          "; ".join(record.reasons)[:300], "BLOCKED")
        hunt_store.record_transition(PlanTransition(
            plan_id=plan.plan_id, from_state="AUTHORIZATION_REQUIRED",
            to_state="AUTHORIZED", reason="gate granted", at=now_fn()))
        activity("authorization_granted",
                 f"{record.auth_id} plan={plan.plan_id} gate=granted")
        if state == "PLANNED":
            set_state("OBSERVATION_PENDING",
                      f"authorization {record.auth_id} granted")

        # ---------------- 8. execute through the observation boundary
        definition_hash = plan.definition_hash()
        hunt_store.record_transition(PlanTransition(
            plan_id=plan.plan_id, from_state="AUTHORIZED",
            to_state="EXECUTING", reason="execution start",
            at=now_fn(), definition_hash=definition_hash))
        started_at = now_fn()
        outcomes: list[str] = []
        errors: list[str] = []
        new_refs_all: list[str] = []
        source_counts: dict[str, int] = {}
        rows_new_total = 0

        for req in plan.observations_requested:
            otype = str(req.get("observation_type") or "")
            if obs_executed >= limits.max_observations:
                errors.append("observation_budget_exhausted")
                break
            allowed_now, stale_reason = reverify_before_observation(
                record, plan=plan, job=job, capability=capability,
                auth_checker=auth_checker, observation_types=(otype,))
            if not allowed_now:
                errors.append(stale_reason)
                hunt_store.append_authorization(
                    _denied_followup(record, stale_reason, now_fn()))
                activity("authorization_rejected",
                         f"pre-observation reverification failed: "
                         f"{stale_reason}")
                break
            obs_id = new_id("obs")
            activity("observation_started",
                     f"{obs_id} plan={plan.plan_id} type={otype} "
                     f"auth={record.auth_id}")
            rows_new: list[dict[str, Any]] = []
            kb_new: list[dict[str, Any]] = []
            obs_error = ""
            try:
                if otype == "kb-rows":
                    if knowledge_fn is None:
                        raise RuntimeError("knowledge_runtime_unavailable")
                    hints = [str(h) for h in
                             (req.get("inputs", {}).get("query_hints")
                              or [])][:6]
                    kb_new = [d for d in (knowledge_fn(hints) or [])
                              if str(d.get("id") or "") not in seen_kb]
                else:
                    typed = _observe_typed(observations, job, otype,
                                           limits.per_type_limit)
                    for row in typed:
                        key = _row_key(row)
                        if key not in seen_refs:
                            rows_new.append(row)
            except Exception as exc:  # noqa: BLE001 - honest failure
                obs_error = f"{type(exc).__name__}: " \
                            f"{str(exc)[:120]}"

            fresh_rows = 0
            fresh_kb = 0
            if not obs_error:
                for row in rows_new:
                    key = _row_key(row)
                    seen_refs.add(key)
                    rows_acc.append(row)
                    new_refs_all.append(key)
                    src = str(row.get("source") or "?")
                    source_counts[src] = source_counts.get(src, 0) + 1
                fresh_rows = len(rows_new)
                for doc in kb_new:
                    seen_kb.add(str(doc.get("id") or ""))
                    kb_acc.append(doc)
                    fresh_kb = len(kb_new)
                rows_new_total += fresh_rows
                observed_types.add(otype)
                if fresh_rows or fresh_kb or otype == "kb-rows":
                    outcomes.append(otype)
                else:
                    # ran fine but nothing new: still an honest observation
                    outcomes.append(otype)
                consecutive_obs_failures = 0
            else:
                errors.append(f"{otype}:{obs_error}")
                outcome.errors.append(f"observation:{otype}:{obs_error}")
                consecutive_obs_failures += 1

            outcome_row = ("ok" if not obs_error
                           else ("unavailable" if not rows_new
                                 else "partial"))
            hunt_store.append_observation(ObservationRecord(
                observation_id=obs_id, plan_id=plan.plan_id,
                auth_id=record.auth_id,
                objective_id=objective.objective_id, job_id=job.id,
                observation_types=(otype,),
                rows_total=len(rows_new) + (len(kb_new)
                                            if otype == "kb-rows" else 0),
                new_rows=fresh_rows or fresh_kb,
                new_refs=tuple(new_refs_all[-10:]),
                source_counts=dict(source_counts),
                outcome=outcome_row, error=obs_error,
                started_at=started_at, completed_at=now_fn()))
            outcome.observation_ids.append(obs_id)
            obs_executed += 1
            activity("observation_completed",
                     f"{obs_id} type={otype} outcome={outcome_row} "
                     f"new_rows={fresh_rows} new_kb={fresh_kb}")
            if not obs_error:
                _learn_observation(
                    memory_store, job, capability, otype,
                    fresh_rows=fresh_rows, fresh_kb=fresh_kb,
                    refs=new_refs_all[-10:], objective=objective,
                    outcome=outcome, activity=activity)

        rows_ref["rows"] = rows_acc
        rows_ref["kb"] = kb_acc
        outcome.rows_added = rows_new_total
        outcome.knowledge_added = max(0, len(seen_kb) - initial_kb_count)
        if errors and not outcomes:
            plan_terminal, plan_reason = "FAILED", "; ".join(errors)[:200]
        elif errors:
            plan_terminal, plan_reason = "PARTIAL", "; ".join(errors)[:200]
        else:
            plan_terminal, plan_reason = "COMPLETED", "all types observed"
        hunt_store.record_transition(PlanTransition(
            plan_id=plan.plan_id, from_state="EXECUTING",
            to_state=plan_terminal, reason=plan_reason, at=now_fn()))
        parent_plan_id = plan.plan_id
        outcome.plans.append({
            "plan_id": plan.plan_id, "version": plan.version,
            "state": plan_terminal,
            "observation_types": list(plan.observation_types),
            "reason": plan.reason[:300],
            "expected_information_gain":
                plan.expected_information_gain,
            "gain_label": plan.gain_label,
            "priority": plan.priority,
        })
        audit("hunt_lineage", _iter_payload(
            objective, iterations, missing, determin, plan,
            gate_decision, uncertainty, advisor=advisor,
            auth=record, obs_added=fresh_rows + fresh_kb))

        if consecutive_obs_failures >= limits.max_consecutive_observation_failures:
            set_state("BLOCKED", "observation runtime failing")
            return finish(TERM_OBSERVATION_UNAVAILABLE,
                          f"{consecutive_obs_failures} consecutive "
                          f"observation failures", "BLOCKED")
        if errors and any("stale_authorization" in e for e in errors):
            set_state("BLOCKED", "stale authorization during observation")
            return finish(TERM_STALE_AUTHORIZATION,
                          "; ".join(errors)[:300], "BLOCKED")

        # ---------------- 9-12. update + next iteration decision
        if state == "OBSERVATION_PENDING":
            set_state("OBSERVATION_COMPLETE",
                      f"{len(outcomes)} observation type(s) executed; "
                      f"gate re-evaluation next")
        # learn: RESEARCHED digest of remaining missing evidence
        _learn_missing(memory_store, job, capability, missing,
                       objective=objective, outcome=outcome,
                       activity=activity)
        if expired():
            return finish(TERM_BUDGET,
                          f"runtime budget {limits.max_seconds}s exhausted "
                          f"after {iterations} iteration(s)",
                          "NEEDS_EVIDENCE")


def _obs_rows(hunt_store: HuntStore, objective_id: str) -> list[dict]:
    try:
        return [o.to_dict() for o in
                hunt_store.observations_for_objective(objective_id)]
    except Exception:  # noqa: BLE001
        return []


def _iter_payload(objective: HuntObjective, iterations: int,
                   missing: Iterable[Any], determin: dict[str, Any],
                   plan: Any, gate_decision: Any,
                   uncertainty: ResearchUncertainty,
                   advisor: Any = None, auth: Any = None,
                   obs_added: int = 0,
                   termination_hint: str = "") -> dict[str, Any]:
    payload = {
        "objective_id": objective.objective_id,
        "iteration": iterations,
        "state_uncertainty": uncertainty.state,
        "uncertainty_digest": uncertainty.digest(),
        "missing_codes": [getattr(m, "item_code", str(m))
                          for m in list(missing)[:12]],
        "gate_reason": getattr(gate_decision, "reason", ""),
        "gate_create": bool(getattr(gate_decision, "create", False)),
        "confidence": str(determin.get("confidence") or ""),
        "rule_version": HUNT_RULE_VERSION,
    }
    if plan is not None:
        payload.update({
            "plan_id": plan.plan_id,
            "plan_version": plan.version,
            "definition_hash": plan.definition_hash(),
            "observation_types": list(plan.observation_types),
            "scoring_method": plan.provenance.get("scoring_method", ""),
            "planner": plan.provenance.get("planner", ""),
            "planner_version": plan.provenance.get("planner_version", ""),
        })
    if advisor is not None:
        payload.update({
            "model_requested": advisor.model_requested,
            "model_resolved": advisor.model_resolved,
            "prompt_version": advisor.prompt_version,
            "advisor_used": advisor.used,
            "advisor_rejected": list(advisor.rejected_suggestions),
            "advisor_error": advisor.error,
            "advisor_latency_ms": advisor.latency_ms,
        })
    if auth is not None:
        payload.update({
            "authorization_id": auth.auth_id,
            "authorization_status": auth.status,
        })
    if obs_added:
        payload["observation_rows_added"] = obs_added
    if termination_hint:
        payload["termination_hint"] = termination_hint
    return payload


def _denied_followup(record: Any, reason: str, now: str) -> Any:
    from backend.research_agents.hunt.models import AuthorizationRecord
    return AuthorizationRecord(
        auth_id=new_id("authz"), plan_id=record.plan_id,
        objective_id=record.objective_id, job_id=record.job_id,
        scope_ref=record.scope_ref, target=record.target,
        observation_types=record.observation_types,
        capability=record.capability, specialist=record.specialist,
        purpose=record.purpose, allowed_data=record.allowed_data,
        safety_class="READ_ONLY", status="DENIED",
        reasons=(f"pre_observation_reverification:{reason}",),
        gate=record.gate, requested_at=record.requested_at,
        decided_at=now)


def _learn_observation(memory_store: Any, job: Any, capability: Any,
                       otype: str, *, fresh_rows: int, fresh_kb: int,
                       refs: list[str], objective: HuntObjective,
                       outcome: HuntOutcome,
                       activity: Callable[[str, str], None]) -> None:
    if memory_store is None:
        return
    try:
        from backend.research_agents.intelligence.memory import make_item
        item = make_item(
            kind="observed_behavior",
            state="OBSERVED",
            subject_key=f"hunt_observed:{otype}:{objective.objective_id}",
            text=(f"authorized {otype} observation executed under hunt "
                  f"objective {objective.objective_id}: "
                  f"{fresh_rows} new row(s), {fresh_kb} new knowledge "
                  f"document(s)"),
            category=capability.category,
            agent=getattr(capability, "agent_name", ""),
            target=str(getattr(job, "subdomain", "") or ""),
            program=str(getattr(job, "program", "") or ""),
            confidence="not_evaluated",
            provenance_job=job.id,
            provenance_source="hunt_observation_runtime",
            provenance_refs=(objective.objective_id, otype, *refs),
        )
        memory_store.append([item])
        outcome.memory_learned.append(item.id)
    except Exception as exc:  # noqa: BLE001 - learning must not kill hunt
        outcome.errors.append(f"learn_observation:{type(exc).__name__}")
        activity("research_state_updated",
                 f"observation memory unavailable: {type(exc).__name__}")


def _learn_missing(memory_store: Any, job: Any, capability: Any,
                   missing: list, *, objective: HuntObjective,
                   outcome: HuntOutcome,
                   activity: Callable[[str, str], None]) -> None:
    if memory_store is None or not missing:
        return
    try:
        from backend.research_agents.intelligence.memory import make_item
        codes = ",".join(m.item_code for m in missing[:6])[:160]
        item = make_item(
            kind="evidence_requirement",
            state="RESEARCHED",
            subject_key=f"hunt_missing:{objective.objective_id}",
            text=(f"missing evidence after hunt iteration: {codes} "
                  f"(deterministic derivation, heuristic gains)"),
            category=capability.category,
            agent=getattr(capability, "agent_name", ""),
            target=str(getattr(job, "subdomain", "") or ""),
            program=str(getattr(job, "program", "") or ""),
            confidence="not_evaluated",
            provenance_job=job.id,
            provenance_source="hunt_missing_evidence_engine",
            provenance_refs=(objective.objective_id,
                             *(m.item_id for m in missing[:6])),
        )
        memory_store.append([item])
        outcome.memory_learned.append(item.id)
    except Exception as exc:  # noqa: BLE001
        outcome.errors.append(f"learn_missing:{type(exc).__name__}")


__all__ = [
    "HUNT_RULE_VERSION",
    "HuntLimits",
    "HuntOutcome",
    "TERM_AUTHORIZATION_DENIED",
    "TERM_BUDGET",
    "TERM_CAPABILITY_UNAVAILABLE",
    "TERM_MAX_ITERATIONS",
    "TERM_MAX_OBSERVATIONS",
    "TERM_MAX_PLANS",
    "TERM_NO_AUTHORIZED_REDUCTION",
    "TERM_OBSERVATION_UNAVAILABLE",
    "TERM_PLAN_VALIDATION",
    "TERM_REJECTED_NO_SIGNAL",
    "TERM_SCOPE_INVALID",
    "TERM_STALE_AUTHORIZATION",
    "TERM_SUFFICIENT",
    "execute_hunt",
    "run_hunt",
]
