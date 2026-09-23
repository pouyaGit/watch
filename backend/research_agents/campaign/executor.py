"""Phase 8/11/12/13: the bounded campaign execution loop.

Delegates EVERY objective to the existing system: one RuntimeStore job per
objective, executed by the existing AgentWorker (knowledge -> observations
-> Hunt Planner -> Authorization -> Observation Runtime -> Evidence Gate ->
Research Memory).  The coordinator itself never executes observations,
never writes evidence or cases, never talks to any network endpoint.

Loop (Phase 8, bounded by budgets + --max-objectives + lifetime):
  load campaign -> lease -> verify scope -> load objectives ->
  resolve dependencies -> update states -> remaining budget ->
  executable set -> prioritize (deterministic) -> optional validated LLM
  reorder -> validate selection -> select specialist -> enqueue job ->
  run ONE existing worker job -> read back real result/gate/hunt ->
  update objective -> record cross-objective context -> campaign memory ->
  budget ledger -> audit lineage -> next objective -> termination.

Honest termination only (Phase 11): COMPLETED only when every objective
is terminal with no failures; budget/runtime/lifetime stops transition to
BUDGET_EXHAUSTED/EXPIRED with full termination records; nothing executable
left -> BLOCKED (never COMPLETED).  Pause/resume revalidates scope,
dependencies and budget (Phase 12); one coordinator lease at a time
(Phase 13).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from backend.research_agents.campaign.advisor import (
    AdvisorOutcome, ADVISOR_PROMPT_VERSION, advisor_request,
    apply_advisory, map_advisor_response,
)
from backend.research_agents.campaign.audit import campaign_event, lineage_row
from backend.research_agents.campaign.budget import (
    BudgetExhausted, CampaignBudget, DEFAULT_LIMITS,
)
from backend.research_agents.campaign.context import (
    collect_context, extract_context_items, record_context,
)
from backend.research_agents.campaign.dependencies import (
    DependencyCycleError, resolve_all,
)
from backend.research_agents.campaign.models import (
    Campaign, CampaignObjective, CampaignStateError, OBJECTIVE_TERMINAL,
    utcnow,
)
from backend.research_agents.campaign.prioritizer import (
    PRIORITIZER_VERSION, prioritize,
)
from backend.research_agents.campaign.selector import select_specialist
from backend.research_agents.campaign.store import CampaignStore, CampaignStoreError

# Bounded passes per objective: the queue may hold unrelated same-category
# jobs ahead of ours; each pass runs exactly ONE authorized job.
_MAX_WORKER_PASSES = 4
LEASE_TTL_SECONDS = 120

CAMPAIGN_RULE_VERSION = "campaign-orchestrator-v1"


def _bounded(value: Any, limit: int) -> str:
    return str(value or "")[:max(0, int(limit))]


@dataclass
class CampaignRunSummary:
    campaign_id: str
    ok: bool = True
    state: str = ""
    termination_reason: str = ""
    lease: str = ""
    executed_this_run: int = 0
    objective_states: dict[str, str] = field(default_factory=dict)
    selected: list[dict[str, Any]] = field(default_factory=list)
    advisor_outcomes: list[dict[str, Any]] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "ok": self.ok,
            "state": self.state,
            "termination_reason": self.termination_reason,
            "lease": self.lease,
            "executed_this_run": self.executed_this_run,
            "objective_states": dict(self.objective_states),
            "selected": list(self.selected),
            "advisor_outcomes": list(self.advisor_outcomes),
            "budget": dict(self.budget),
            "errors": list(self.errors),
            "reason": self.reason,
        }


def _default_worker_factory(config: Any, store: Any) -> Any:
    from backend.research_agents.runtime import AgentWorker
    return AgentWorker(config=config, store=store)


def build_objective_job(
    *,
    campaign: Campaign,
    objective: CampaignObjective,
    agent_name: str,
    config: Any,
    context_digest: str = "",
) -> Any:
    """Construct the RuntimeStore job that executes one objective.

    Scope chain: job.authorization_ref = objective.scope_ref, which the
    store validated to EQUAL campaign.scope_ref at add/save time — the
    campaign can never widen scope (rule 15/16).
    """

    from backend.research_agents.models import JobStatus, ResearchJob

    target = campaign.target_context or {}
    category = objective.category.upper()
    mission = (f"[campaign {campaign.campaign_id} objective "
               f"{objective.objective_id}] "
               f"{_bounded(objective.research_question, 240)}")
    reasons = [
        f"campaign:{campaign.campaign_id}",
        f"objective:{objective.objective_id}",
        "campaign-executed:coordinated-objective",
    ]
    if context_digest:
        reasons.append(f"campaign-context:{_bounded(context_digest, 300)}")
    return ResearchJob(
        id=f"job-{category.lower()}-{uuid.uuid4().hex[:10]}",
        candidate_id=f"campaign:{campaign.campaign_id}",
        category=category,
        endpoint=str(target.get("url") or objective.scope_ref),
        parameter="",
        priority_score=int(campaign.priority),
        status=JobStatus.QUEUED.value,
        assigned_agent=agent_name,
        created_at=utcnow(),
        updated_at=utcnow(),
        agent_category=category,
        reasons=tuple(reasons),
        program=str(target.get("program") or campaign.program),
        subdomain=str(target.get("subdomain") or ""),
        url=str(target.get("url") or ""),
        mission=mission,
        authorization_ref=objective.scope_ref,
        timeout_seconds=int(getattr(config, "job_timeout", 300)),
        execution_mode=str(target.get("execution_mode")
                           or getattr(config, "execution_mode", "production")),
    )


def _extract_gate(structured: dict[str, Any]) -> tuple[str, bool, str]:
    """Authoritative gate fields from a persisted result (production shape).

    The runtime persists the Evidence Gate decision at
    ``structured["evidence_gate"]`` (authoritative/reason/created_case/
    confidence).  Legacy + fixture results may instead carry gate fields
    inside ``structured["research_lineage"]`` — both shapes are honoured;
    the authoritative record always wins when present.
    """

    gate = structured.get("evidence_gate") or {}
    lineage = structured.get("research_lineage") or {}
    if gate.get("authoritative") is True:
        return (str(gate.get("reason") or ""),
                bool(gate.get("created_case")),
                str(lineage.get("case_id") or ""))
    reason = str(lineage.get("gate_reason") or "")
    return reason, reason == "evidence_rules_met", str(lineage.get("case_id") or "")


def _map_objective_outcome(
    job: Any,
    result: Any,
    hunt: dict[str, Any],
    gate_reason: str,
    case_id: str,
) -> tuple[str, str, str]:
    """job+result+gate -> (objective_state, reason, detail).

    The Evidence Gate is authoritative: RESOLVED only when the gate
    claimed evidence rules met (case created).  Hunt BLOCKED maps to
    BLOCKED; failed jobs to FAILED; completed-but-unclaimed gates to
    REJECTED (honest negative/inconclusive outcome); still-running jobs
    are NOT terminal (caller moves them to WAITING).
    """

    status = str(getattr(job, "status", "") or "")
    detail = _bounded(
        f"job={job.id} status={status} gate={gate_reason or 'n/a'} "
        f"case={case_id or 'none'} hunt={hunt.get('state', 'n/a')}", 400)
    if status == "TERMINAL_FAILED":
        return ("FAILED",
                _bounded(getattr(job, "error", "") or "job_failed", 120),
                detail)
    if status == "EXPIRED":
        return "EXPIRED", "job_lease_expired_attempts_exhausted", detail
    if status == "CANCELLED":
        return "CANCELLED", "job_cancelled", detail
    if status != "COMPLETED":
        return "", "", detail   # not terminal: caller -> WAITING
    if str(hunt.get("state") or "") == "BLOCKED":
        return ("BLOCKED",
                _bounded(hunt.get("termination_reason")
                         or "hunt_blocked", 120),
                detail)
    if case_id or gate_reason == "evidence_rules_met":
        return "RESOLVED", _bounded(gate_reason or "evidence_rules_met",
                                    120), detail
    if str(hunt.get("state") or "") == "RESOLVED":
        # hunt resolved but the authoritative gate did not claim a case
        return ("REJECTED",
                _bounded(gate_reason or "gate_not_claimed", 120),
                detail)
    return ("REJECTED",
            _bounded(gate_reason or "gate_not_claimed", 120), detail)


def _campaign_memory_items(
    *,
    campaign: Campaign,
    objective: CampaignObjective,
    job_id: str,
    case_id: str,
    gate_reason: str,
    confidence: str,
) -> list[Any]:
    """Phase 10: campaign-level learning (provenance-preserving).

    Rules: VERIFIED only when the authoritative gate created a case;
    REJECTED hypotheses preserved for REJECTED objectives; blocked
    objectives preserved as negative evidence; FAILED objectives produce
    no memory (failure is not knowledge).  Subject keys are
    objective-scoped so campaign items NEVER overwrite specialist memory.
    """

    from backend.research_agents.intelligence.memory import make_item

    base = dict(
        category=objective.category,
        agent=f"campaign:{campaign.campaign_id}",
        target=str((campaign.target_context or {}).get("subdomain")
                   or campaign.program),
        program=campaign.program,
        confidence=confidence or "not_evaluated",
        provenance_job=job_id,
        provenance_source=f"campaign:{campaign.campaign_id}",
        provenance_refs=(objective.objective_id, case_id or "no-case"),
        limitations="campaign coordination context; evidence gate remains "
                    "authoritative for findings",
    )
    items: list[Any] = []
    if objective.state == "RESOLVED":
        items.append(make_item(
            kind="confirmed_historical_result",
            state="VERIFIED" if case_id else "RESEARCHED",
            subject_key=f"campaign:{objective.objective_id}",
            text=_bounded(
                f"campaign {campaign.campaign_id}: objective "
                f"{objective.objective_id} ({objective.category}) resolved; "
                f"gate={gate_reason or 'evidence_rules_met'} "
                f"case={case_id or 'none'}; "
                f"question={objective.research_question[:160]}", 400),
            **base))
    elif objective.state == "REJECTED":
        items.append(make_item(
            kind="rejected_hypothesis",
            state="REJECTED",
            subject_key=f"campaign:{objective.objective_id}",
            text=_bounded(
                f"campaign {campaign.campaign_id}: objective "
                f"{objective.objective_id} ({objective.category}) "
                f"rejected by evidence gate ({gate_reason or 'no_case'}); "
                f"hypothesis={objective.hypothesis[:160]}", 400),
            **base))
    elif objective.state == "BLOCKED":
        items.append(make_item(
            kind="negative_evidence",
            state="OBSERVED",
            subject_key=f"campaign:{objective.objective_id}",
            text=_bounded(
                f"campaign {campaign.campaign_id}: objective "
                f"{objective.objective_id} blocked; "
                f"reason={objective.termination_reason[:160]}", 400),
            **base))
    return items


def execute_campaign(
    campaign_id: str,
    *,
    config: Any = None,
    advisor_fn: Callable[[dict], tuple[Any, dict]] | None = None,
    store: Any = None,
    campaign_store: CampaignStore | None = None,
    memory_store: Any = None,
    worker_factory: Callable[[Any, Any], Any] | None = None,
    max_objectives: int | None = None,
    now_fn: Callable[[], str] = utcnow,
) -> CampaignRunSummary:
    """Run the bounded orchestration loop for ONE campaign.

    Returns a summary; NEVER raises for expected business failures
    (unknown campaign, lease refusal, budget exhaustion) — they are
    reported honestly in the summary and persisted state.
    """

    from backend.research_agents.models import JobStatus
    from backend.research_agents.runtime import RuntimeConfig
    from backend.research_agents.runtime_store import default_store

    config = config or RuntimeConfig()
    store = store or default_store()
    cs = campaign_store or CampaignStore(store.base)
    wf = worker_factory or _default_worker_factory
    run_limit = int(max_objectives if max_objectives is not None
                    else max(1, DEFAULT_LIMITS["max_objectives"]))
    summary = CampaignRunSummary(campaign_id=campaign_id)
    coordinator = f"coordinator-{uuid.uuid4().hex[:8]}"
    started = time.monotonic()

    def audit(stage: str, payload: dict[str, Any]) -> None:
        try:
            store.record_audit_event(campaign_event(stage, payload))
        except Exception as exc:  # noqa: BLE001 - visible, never fatal
            summary.errors.append(
                f"audit_{stage}:{_bounded(type(exc).__name__, 40)}")

    def activity(action: str, detail: str, *,
                 objective_id: str = "", job_id: str = "") -> None:
        try:
            store.record_activity({
                "campaign_id": campaign_id,
                "objective_id": objective_id,
                "job_id": job_id,
                "agent": "campaign-orchestrator",
                "category": "CAMPAIGN",
                "action": action,
                "detail": _bounded(detail, 300),
                "mode": str((config.execution_mode
                             if hasattr(config, "execution_mode")
                             else "production")),
            })
        except Exception:  # noqa: BLE001 - activity is best effort
            pass

    # ---- 1/2/3: load + scope + state ------------------------------------
    campaign = cs.get_campaign(campaign_id)
    if campaign is None:
        summary.ok = False
        summary.reason = f"unknown campaign: {campaign_id}"
        return summary
    if campaign.is_terminal:
        summary.ok = False
        summary.state = campaign.state
        summary.termination_reason = campaign.termination_reason
        summary.reason = f"campaign already terminal ({campaign.state})"
        return summary
    if campaign.state == "PAUSED":
        summary.ok = False
        summary.state = campaign.state
        summary.reason = "campaign paused; resume before running"
        return summary

    # ---- 13: coordinator lease ------------------------------------------
    ok, lease_reason = cs.claim_lease(campaign_id, coordinator,
                                      ttl_seconds=LEASE_TTL_SECONDS,
                                      now=now_fn())
    if not ok:
        summary.ok = False
        summary.reason = f"lease_refused: {lease_reason}"
        audit("lease_refused", {"campaign_id": campaign_id,
                                "coordinator": coordinator,
                                "reason": lease_reason})
        return summary
    summary.lease = coordinator

    budget: CampaignBudget | None = None
    try:
        # ---- campaign state entry ---------------------------------------
        # DRAFT -> READY -> RUNNING; READY/WAITING -> RUNNING; an already
        # RUNNING campaign means a crashed coordinator (the lease check
        # above already reclaimed the expired lease) -> continue as-is.
        entry_state = campaign.state   # PAUSED refused pre-lease (above)
        came_from_draft = entry_state == "DRAFT"
        if came_from_draft:
            campaign = cs.transition_campaign(campaign_id, "READY",
                                              reason="validated_for_run")
            entry_state = campaign.state
        if entry_state in ("READY", "WAITING"):
            campaign = cs.transition_campaign(
                campaign_id, "RUNNING",
                reason=("coordinator_started"
                        if came_from_draft else "resumed_run"))
        if came_from_draft:
            activity("campaign_started",
                     f"campaign {campaign_id} state=RUNNING "
                     f"lease={coordinator}")
            audit("started", {"campaign_id": campaign_id,
                              "coordinator": coordinator,
                              "scope_ref": campaign.scope_ref,
                              "state": "RUNNING"})
        else:
            activity("campaign_resumed",
                     f"campaign {campaign_id} entry={entry_state} "
                     f"state=RUNNING lease={coordinator}")
            audit("resumed", {"campaign_id": campaign_id,
                              "coordinator": coordinator,
                              "entry_state": entry_state,
                              "state": "RUNNING"})

        budget = CampaignBudget(cs, campaign)
        executed = 0
        last_completed = ""
        last_evidence_state = ""

        def terminate(state: str, reason: str, *,
                      detail: str = "",
                      last_obj: str | None = None) -> None:
            objectives = cs.objectives_for_campaign(campaign_id)
            record = {
                "detail": detail or reason,
                "remaining_objectives": [
                    {"objective_id": o.objective_id, "state": o.state}
                    for o in objectives if not o.is_terminal],
                "budget_state": budget.report().to_dict()
                if budget else {},
                "last_completed_objective": (last_obj if last_obj is not None
                                             else last_completed),
                "last_evidence_state": (last_evidence_state or "none"),
            }
            try:
                cs.record_termination(campaign_id, record, state=state,
                                      reason=reason)
            except CampaignStoreError as exc:
                summary.errors.append(
                    f"termination_persist:{_bounded(exc, 120)}")
                summary.ok = False
            summary.state = state
            summary.termination_reason = reason
            if state == "FAILED":
                # fail-closed honesty: a safety/persistence/cycle
                # termination means the RUN did not succeed.
                summary.ok = False
            action = ("campaign_completed" if state == "COMPLETED"
                      else "campaign_terminated")
            activity(action, f"{state}: {reason}")
            audit("terminated", {"campaign_id": campaign_id,
                                 "state": state, "reason": reason,
                                 "detail": _bounded(detail, 400),
                                 "budget": budget.report().to_dict()
                                 if budget else {},
                                 "last_completed_objective":
                                     last_completed,
                                 "last_evidence_state":
                                     last_evidence_state})

        def assess_termination() -> bool:
            """Phase 11 conditions; returns True when campaign terminal."""

            objectives = cs.objectives_for_campaign(campaign_id)
            # lifetime + runtime budgets
            try:
                from datetime import datetime
                age = (datetime.fromisoformat(now_fn())
                       - datetime.fromisoformat(campaign.created_at)
                       ).total_seconds()
            except (TypeError, ValueError):
                age = 0.0
            # measured wall lifetime shows in every budget report
            budget.used["campaign_lifetime_seconds"] = int(age)
            campaign.budget["campaign_lifetime_seconds"] = int(age)
            life_limit = int(budget.limits.get(
                "max_campaign_lifetime_seconds", 0) or 0)
            if life_limit and age > life_limit:
                terminate("EXPIRED", "campaign_lifetime_exceeded",
                          detail=f"age={int(age)}s limit={life_limit}s")
                return True
            if budget.is_exhausted("runtime_seconds"):
                terminate("BUDGET_EXHAUSTED", "max_runtime_seconds",
                          detail="cumulative runtime budget exhausted")
                return True

            non_terminal = [o for o in objectives if not o.is_terminal]
            if not non_terminal:
                failed = [o.objective_id for o in objectives
                          if o.state == "FAILED"]
                expired = [o.objective_id for o in objectives
                           if o.state == "EXPIRED"]
                if failed:
                    terminate("FAILED",
                              f"objective_failures:{','.join(failed[:4])}",
                              detail="one or more objectives failed; "
                                     "campaign is NOT completed")
                    return True
                if expired:
                    terminate("EXPIRED", "objectives_expired",
                              detail=f"expired: {','.join(expired[:4])}")
                    return True
                resolved = sum(1 for o in objectives
                               if o.state == "RESOLVED")
                rejected = sum(1 for o in objectives
                               if o.state == "REJECTED")
                cancelled = sum(1 for o in objectives
                                if o.state == "CANCELLED")
                terminate("COMPLETED",
                          f"all_objectives_terminal resolved={resolved} "
                          f"rejected={rejected} cancelled={cancelled}",
                          detail="every objective reached a terminal state "
                                 "with no failures")
                return True
            return False

        def refresh_states() -> list[CampaignObjective]:
            """Resolve dependencies + push objective state transitions."""

            objectives = cs.objectives_for_campaign(campaign_id)
            # Phase 17 fail-closed: an objective whose scope no longer
            # matches the campaign scope (tampering / corruption) must
            # never reach selection or execution.
            mismatched = [o.objective_id for o in objectives
                          if str(o.scope_ref) != str(campaign.scope_ref)]
            if mismatched:
                summary.errors.append(
                    "scope_mismatch:" + ",".join(sorted(mismatched)))
                terminate("FAILED", "scope_mismatch_detected",
                          detail="objectives outside campaign scope: "
                                 + ",".join(sorted(mismatched)))
                return objectives
            try:
                dep_results = resolve_all(objectives)
            except DependencyCycleError as exc:
                terminate("FAILED", "dependency_cycle_detected",
                          detail=str(exc))
                return objectives
            for obj in objectives:
                if obj.is_terminal:
                    continue
                res = dep_results.get(obj.objective_id) or {}
                effect = res.get("effect")
                reason = "; ".join(res.get("reasons") or [])[:300]
                try:
                    # crash recovery: a RUNNING objective always has a
                    # job; demote to WAITING so the selection path
                    # RESUMES the existing job instead of enqueuing a
                    # duplicate (single execution per objective).
                    if obj.state == "RUNNING":
                        obj = cs.transition_objective(
                            obj.objective_id, "WAITING",
                            reason="coordinator_resume",
                            detail=(f"job {obj.job_id or 'unknown'} "
                                    "will be resumed, not re-enqueued"))
                    if effect == "permanently_blocked" \
                            and obj.state != "BLOCKED":
                        obj = cs.transition_objective(
                            obj.objective_id, "BLOCKED",
                            reason="dependencies_permanently_blocked",
                            detail=reason)
                    elif effect == "waiting" and obj.state in (
                            "QUEUED", "READY"):
                        obj = cs.transition_objective(
                            obj.objective_id, "WAITING",
                            reason="waiting_for_dependencies",
                            detail=reason)
                    elif res.get("ready") and obj.state in (
                            "QUEUED", "WAITING"):
                        obj = cs.transition_objective(
                            obj.objective_id, "READY",
                            reason="dependencies_satisfied",
                            detail=reason)
                    elif res.get("ready") and obj.state == "BLOCKED" \
                            and int(obj.attempts or 0) == 0:
                        # NEVER re-promote an executed objective: a job
                        # outcome of BLOCKED is conclusive for this
                        # campaign (pre-execution blocks may retry once
                        # the cause clears, attempts==0 only).
                        obj = cs.transition_objective(
                            obj.objective_id, "READY",
                            reason="pre_execution_block_cleared",
                            detail=reason)
                except (CampaignStateError, CampaignStoreError) as exc:
                    summary.errors.append(
                        f"state_refresh:{_bounded(exc, 120)}")
            return cs.objectives_for_campaign(campaign_id)

        # ---- main bounded loop ------------------------------------------
        while executed < run_limit:
            if not cs.renew_lease(campaign_id, coordinator,
                                  ttl_seconds=LEASE_TTL_SECONDS):
                summary.ok = False
                summary.reason = "lease_lost_aborting"
                audit("lease_refused", {"campaign_id": campaign_id,
                                        "coordinator": coordinator,
                                        "reason": "lease lost mid-run"})
                break

            # 4/5/6: load objectives + resolve dependencies + update states
            objectives = refresh_states()
            if summary.termination_reason:
                break    # cycle termination inside refresh_states

            # lifetime-expire stale objectives (honest staleness)
            # (handled via assess_termination lifetime check above)

            # 7: remaining budget (fail closed BEFORE selecting)
            budget.sync_from_objectives(objectives)
            try:
                budget.ensure("objectives", "runtime_seconds",
                              "observations", "hunt_plans")
            except BudgetExhausted as exc:
                terminate("BUDGET_EXHAUSTED", f"max_{exc.resource}",
                          detail=(f"{exc.resource} {exc.used}/{exc.limit} "
                                  "cumulative across campaign"))
                break

            # terminal assessment before selection
            if assess_termination():
                break

            # 8: executable set
            candidates = [o for o in objectives
                          if o.state == "READY" and not o.is_terminal]

            # scope safety: any objective whose scope drifted from the
            # campaign scope is a safety violation -> FAILED (never runs)
            drifted = [o.objective_id for o in objectives
                       if not campaign.scope_matches(o.scope_ref)]
            if drifted:
                summary.ok = False
                terminate("FAILED", "scope_invalidated",
                          detail="objective scope mismatch: "
                                 + ",".join(drifted[:4]))
                break

            if not candidates:
                # no executable objectives: BLOCKED (never COMPLETED)
                pending = [o for o in objectives if not o.is_terminal]
                if pending:
                    # are any merely waiting on non-terminal deps that
                    # themselves cannot run? resolve_all already blocked
                    # permanent cases; remaining waits mean the dependency
                    # chain head is missing -> nothing executable remains.
                    terminate(
                        "BLOCKED", "no_executable_objectives",
                        detail="pending: " + "; ".join(
                            f"{o.objective_id}={o.state}"
                            for o in pending[:6]))
                break

            # 9: deterministic prioritization (real missing-evidence read)
            missing_by_obj: dict[str, list[Any]] = {}
            prev_research: dict[str, dict[str, Any]] = {}
            specialist_avail: dict[str, bool] = {}
            specialists_map: dict[str, str] = {}
            for obj in candidates:
                cap_sel = select_specialist(obj)
                specialist_avail[obj.category] = cap_sel.selected
                if cap_sel.selected:
                    specialists_map[obj.objective_id] = cap_sel.agent_name
                missing_by_obj[obj.objective_id] = []   # filled per-job
                prev_research[obj.objective_id] = {
                    "count": int(obj.provenance.get("prior_research", 0)
                                 or 0),
                    "confidence": str(obj.provenance.get(
                        "prior_confidence", "") or ""),
                }
            dep_results = resolve_all(objectives)
            order = prioritize(
                candidates,
                dep_results=dep_results,
                missing_by_objective=missing_by_obj,
                previous_research=prev_research,
                specialist_available=specialist_avail,
                attempts={o.objective_id: o.attempts for o in candidates},
                now_iso=now_fn(),
                budget_remaining=budget.report().remaining,
                risk_class={o.objective_id: str(
                    (o.provenance or {}).get("risk_class", "medium"))
                    for o in candidates},
                scope_relevance={o.objective_id: 1.0
                                 for o in candidates},
            )
            deterministic = order.order
            audit("objective_selected", {
                "campaign_id": campaign_id,
                "prioritizer_version": order.version,
                "scoring_method": order.scoring_method,
                "order": ",".join(deterministic[:8]),
                "excluded": ",".join(
                    f"{e['objective_id']}:{e['reason']}"
                    for e in order.excluded[:8]),
                "reasons_head": "; ".join(
                    order.ordered[0].reasons) if order.ordered else "",
            })
            if executed >= 1:
                activity("campaign_replanned",
                         f"reprioritized after "
                         f"{executed} objective(s): "
                         f"{','.join(deterministic[:6])}")

            executable_ids = set(deterministic)

            # 10: optional validated LLM advisory reorder
            final_order = list(deterministic)
            if advisor_fn is not None:
                try:
                    budget.ensure("llm_calls")
                except BudgetExhausted:
                    # advisory budget is exhausted: disable the advisor
                    # AUDIBLY (outcome + audit), deterministic order
                    # stands — never a silent skip, never a fake stop.
                    advisor_fn = None
                    summary.advisor_outcomes.append({
                        "used": False,
                        "error": "advisor_disabled:max_llm_calls",
                        "rejected": [],
                        "reordered": [],
                    })
                    audit("advisor_outcome", {
                        "campaign_id": campaign_id,
                        "used": False,
                        "error": "advisor_disabled:max_llm_calls",
                    })
                if advisor_fn is not None:
                    try:
                        by_id = {o.objective_id: o for o in objectives}
                        req = advisor_request(
                            campaign=campaign,
                            ordered=[by_id[oid] for oid in deterministic
                                     if oid in by_id],
                            dep_results=dep_results,
                            budget_report=budget.report().to_dict(),
                            executable_ids=executable_ids,
                            specialists=specialists_map,
                        )
                        response, meta = advisor_fn(req)
                        outcome = map_advisor_response(
                            response,
                            campaign_id=campaign_id,
                            scope_ref=campaign.scope_ref,
                            objectives_by_id=by_id,
                            executable_ids=executable_ids,
                            deterministic_order=deterministic,
                            specialists=specialists_map,
                            budget_ok=not budget.is_exhausted("objectives"),
                        )
                        outcome.model_requested = str(
                            meta.get("model_requested")
                            or "openrouter/free")
                        outcome.model_resolved = str(
                            meta.get("model_resolved") or "")
                        outcome.latency_ms = int(
                            meta.get("latency_ms") or 0)
                        final_order = apply_advisory(deterministic, outcome)
                        budget.consume(
                            "llm_calls", 1,
                            reason="campaign advisor call",
                            objective_id=outcome.recommended_objective)
                        summary.advisor_outcomes.append(
                            outcome.to_dict())
                        audit("advisor_outcome", {
                            "campaign_id": campaign_id,
                            "objective_id": outcome.recommended_objective,
                            "used": outcome.used,
                            "error": outcome.error,
                            "rejected": ",".join(outcome.rejected[:4]),
                            "requested_model": outcome.model_requested,
                            "resolved_model": outcome.model_resolved,
                            "latency_ms": outcome.latency_ms,
                            "prompt_version": ADVISOR_PROMPT_VERSION,
                            "final_order": ",".join(final_order[:8]),
                        })
                    except Exception as exc:  # noqa: BLE001 - degrade
                        summary.advisor_outcomes.append(
                            AdvisorOutcome(
                                error=f"advisor_unavailable:"
                                      f"{type(exc).__name__}:"
                                      f"{_bounded(exc, 160)}",
                            ).to_dict())
                        audit("advisor_outcome", {
                            "campaign_id": campaign_id,
                            "used": False,
                            "error": _bounded(
                                f"{type(exc).__name__}: {exc}", 200),
                        })
                        activity(
                            "objective_selected",
                            "LLM campaign advisor unavailable "
                            f"({type(exc).__name__}); deterministic order "
                            "continues")

            if not final_order:
                # Phase 6/14: candidates excluded for an unavailable
                # specialist become explicitly BLOCKED with the reason
                # (never left READY under a BLOCKED campaign).
                excluded_by_id = {e["objective_id"]: e["reason"]
                                  for e in order.excluded}
                for obj in candidates:
                    reason = excluded_by_id.get(
                        obj.objective_id, "no executable objective")
                    try:
                        cs.transition_objective(
                            obj.objective_id, "BLOCKED",
                            reason="objective_blocked",
                            detail=_bounded(reason, 200))
                    except (CampaignStateError, CampaignStoreError):
                        pass   # already moved; keep the run fail-closed
                terminate("BLOCKED", "no_executable_objectives",
                          detail="prioritizer returned an empty order")
                break

            # 11: validate selected objective (Phase 5 checks, head-first)
            from backend.research_agents.campaign.advisor import (
                validate_recommendation,
            )
            by_id = {o.objective_id: o for o in objectives}
            selected_obj: CampaignObjective | None = None
            selection_error = ""
            for candidate_id in final_order:
                ok_sel, why = validate_recommendation(
                    candidate_id,
                    campaign_id=campaign_id,
                    scope_ref=campaign.scope_ref,
                    objectives_by_id=by_id,
                    executable_ids=executable_ids,
                    specialists=specialists_map,
                    budget_ok=True,
                    running_ids=set(),
                )
                if not ok_sel:
                    selection_error = f"{candidate_id}: {why}"
                    audit("objective_selected", {
                        "campaign_id": campaign_id,
                        "objective_id": candidate_id,
                        "rejected": why,
                    })
                    continue
                selected_obj = by_id[candidate_id]
                activity(
                    "objective_selected",
                    f"{candidate_id} at rank "
                    f"{final_order.index(candidate_id) + 1}"
                    f"/{len(final_order)} of the deterministic order "
                    "(heuristic_transparent_v1)",
                    objective_id=candidate_id)
                break
            if selected_obj is None:
                summary.ok = False
                terminate("BLOCKED", "no_valid_objective",
                          detail=selection_error or "no candidate validated")
                break

            # 12: specialist selection (capability-aware, recorded)
            sel = select_specialist(selected_obj)
            audit("specialist_selected", {
                "campaign_id": campaign_id,
                "objective_id": selected_obj.objective_id,
                "category": selected_obj.category,
                "agent_name": sel.agent_name,
                "selected": sel.selected,
                "reason": sel.reason,
            })
            if not sel.selected:
                activity("objective_blocked",
                         f"{selected_obj.objective_id}: {sel.reason}",
                         objective_id=selected_obj.objective_id)
                try:
                    selected_obj = cs.transition_objective(
                        selected_obj.objective_id, "BLOCKED",
                        reason="specialist_unavailable",
                        detail=sel.reason)
                except (CampaignStateError, CampaignStoreError) as exc:
                    summary.errors.append(
                        f"specialist_block:{_bounded(exc, 120)}")
                executed += 1    # bounded: an attempted selection counts
                continue
            activity("specialist_selected",
                     f"{selected_obj.objective_id} -> {sel.agent_name}: "
                     f"{sel.reason}",
                     objective_id=selected_obj.objective_id)

            # Phase 9: bounded, scope-safe cross-objective context
            bundle = collect_context(
                cs,
                campaign_id=campaign_id,
                scope_ref=campaign.scope_ref,
                exclude_objective=selected_obj.objective_id,
            )
            digest = bundle.digest(max_chars=300)

            # 13: enqueue ONE job through the EXISTING queue — unless the
            # objective already has a job (resume after interruption:
            # continue the persisted job, never a duplicate execution).
            try:
                existing = (store.get(selected_obj.job_id)
                            if selected_obj.job_id else None)
                if existing is not None:
                    job = existing    # resume path (Phase 12/16)
                    fresh_enqueue = False
                else:
                    fresh_enqueue = True
                    if selected_obj.job_id:
                        summary.errors.append(
                            "job_missing:"
                            f"{selected_obj.job_id}: re-enqueueing")
                        selected_obj.job_id = ""
                    job = build_objective_job(
                        campaign=campaign, objective=selected_obj,
                        agent_name=sel.agent_name, config=config,
                        context_digest=digest)
                    # persist the link FIRST: if the process dies
                    # between these two writes, the objective already
                    # points at job id X and the resume path never
                    # enqueues a duplicate (store.get(X) is None ->
                    # single re-enqueue, recorded as job_missing).
                    selected_obj.job_id = job.id
                    selected_obj.attempts += 1
                    selected_obj = cs.save_objective(selected_obj)
                    store.enqueue(job)
            except Exception as exc:  # noqa: BLE001 - honest failure
                summary.ok = False
                summary.errors.append(
                    f"enqueue:{_bounded(type(exc).__name__, 40)}")
                try:
                    selected_obj = cs.transition_objective(
                        selected_obj.objective_id, "FAILED",
                        reason="enqueue_failed", detail=_bounded(exc, 200))
                except (CampaignStateError, CampaignStoreError):
                    pass
                audit("objective_terminal", {
                    "campaign_id": campaign_id,
                    "objective_id": selected_obj.objective_id,
                    "state": "FAILED", "reason": "enqueue_failed",
                })
                executed += 1
                continue

            budget_before = budget.report().to_dict()
            # job link + attempts already persisted above (fresh) or
            # already existed (resume) — only the state transition
            # remains; the store copy is authoritative.
            if selected_obj.state != "RUNNING":
                try:
                    selected_obj = cs.transition_objective(
                        selected_obj.objective_id, "RUNNING",
                        reason=("job_enqueued" if fresh_enqueue
                                else "job_resumed"),
                        detail=f"job={job.id}")
                except (CampaignStateError, CampaignStoreError) as exc:
                    summary.errors.append(
                        f"objective_start:{_bounded(exc, 120)}")
            activity("objective_started",
                     f"{selected_obj.objective_id} job={job.id} "
                     f"agent={sel.agent_name}",
                     objective_id=selected_obj.objective_id,
                     job_id=job.id)
            activity("hunt_started",
                     f"hunt enabled for job={job.id} objective="
                     f"{selected_obj.objective_id}",
                     objective_id=selected_obj.objective_id,
                     job_id=job.id)
            audit("objective_started", {
                "campaign_id": campaign_id,
                "objective_id": selected_obj.objective_id,
                "job_id": job.id,
                "specialist": sel.agent_name,
                "scope_ref": selected_obj.scope_ref,
                "budget_before": budget_before,
                "context_items": len(bundle.items),
                "context_chars": bundle.total_chars,
            })

            # 13-18: run ONE existing worker job (bounded passes)
            activity("observation_started",
                     f"observations via Observation Runtime for job="
                     f"{job.id} (objective {selected_obj.objective_id})",
                     objective_id=selected_obj.objective_id,
                     job_id=job.id)
            obj_started = time.monotonic()
            try:
                worker = wf(config, store)
                try:
                    worker.categories = (selected_obj.category,)
                except Exception:  # noqa: BLE001 - keep default categories
                    pass
                passes = 0
                job_now = store.get(job.id)
                terminal_states = {
                    JobStatus.COMPLETED.value,
                    JobStatus.TERMINAL_FAILED.value,
                    JobStatus.EXPIRED.value,
                    JobStatus.CANCELLED.value,
                }
                while passes < _MAX_WORKER_PASSES:
                    job_now = store.get(job.id)
                    if job_now is None:
                        break
                    if str(job_now.status) in terminal_states:
                        break
                    store.sweep()
                    worker.run(max_jobs=1)
                    passes += 1
                    job_now = store.get(job.id)
                    if job_now is not None and \
                            str(job_now.status) in terminal_states:
                        break
            except Exception as exc:  # noqa: BLE001 - persistence failure
                summary.ok = False
                summary.errors.append(
                    f"worker:{_bounded(type(exc).__name__, 60)}")
                try:
                    terminate("FAILED", "persistence_failure",
                              detail=f"worker error: "
                                     f"{_bounded(exc, 200)}",
                              last_obj=selected_obj.objective_id)
                except Exception:  # noqa: BLE001 - store itself broken
                    summary.reason = (
                        f"unrecoverable persistence failure: "
                        f"{_bounded(exc, 160)}")
                break

            job_now = store.get(job.id) or job
            result = store.get_result(job.id)
            structured = (getattr(result, "structured", None)
                          if result else None) or {}
            hunt = structured.get("hunt") or {}
            gate_reason, case_claimed, case_id = _extract_gate(structured)
            if not case_id and case_claimed:
                # authoritative gate created a case; resolve its real id
                # for audit + learning references (lineage may omit it)
                try:
                    case_id = str(next(
                        (str(c.get("id") or "")
                         for c in store.list_cases()
                         if str(c.get("job_id") or "") == str(job.id)), ""))
                except Exception:  # noqa: BLE001 - lookup is best effort
                    case_id = ""
            confidence = str(getattr(result, "confidence", "")
                             if result else "") or "insufficient"
            evidence_rows = store.list_evidence(job_id=job.id)

            activity("evidence_updated",
                     f"job={job.id} evidence={len(evidence_rows)} "
                     f"gate={gate_reason or 'n/a'} "
                     f"case={case_id or 'none'}",
                     objective_id=selected_obj.objective_id,
                     job_id=job.id)
            activity("observation_completed",
                     f"observations={len(hunt.get('observation_ids') or [])}"
                     f" plans={len(hunt.get('plan_ids') or [])} "
                     f"rows_added={int(hunt.get('rows_added') or 0)} "
                     f"job={job.id}",
                     objective_id=selected_obj.objective_id,
                     job_id=job.id)

            # 18: map outcome -> objective state (gate authoritative)
            new_state, why, detail = _map_objective_outcome(
                job_now, result, hunt, gate_reason, case_id)
            if not new_state:
                # job did not finish within bounds: honest WAITING, not a
                # fake completion; the next run resumes from persisted state
                try:
                    selected_obj = cs.transition_objective(
                        selected_obj.objective_id, "WAITING",
                        reason="job_not_terminal_within_run_bound",
                        detail=detail)
                except (CampaignStateError, CampaignStoreError) as exc:
                    summary.errors.append(
                        f"waiting_transition:{_bounded(exc, 120)}")
                activity("objective_blocked",
                         f"{selected_obj.objective_id}: job still "
                         f"{getattr(job_now, 'status', '?')} within run "
                         "bound; campaign WAITING for resume",
                         objective_id=selected_obj.objective_id,
                         job_id=job.id)
                summary.objective_states[selected_obj.objective_id] = \
                    selected_obj.state
                summary.selected.append({
                    "objective_id": selected_obj.objective_id,
                    "job_id": job.id,
                    "specialist": sel.agent_name,
                    "state": selected_obj.state,
                    "reason": "job_not_terminal_within_run_bound",
                    "case_id": "",
                    "gate_reason": "",
                })
                summary.budget = budget.report().to_dict()
                try:
                    cs.transition_campaign(
                        campaign_id, "WAITING",
                        reason="job_pending_on_resume",
                        detail=f"job {job.id} still "
                               f"{getattr(job_now, 'status', '?')} within "
                               "run bound; resume re-runs it")
                    summary.state = "WAITING"
                    summary.termination_reason = (
                        "run_bound_reached_objectives_pending")
                    activity("campaign_paused",
                             f"job {job.id} pending; campaign WAITING "
                             "for resume")
                except (CampaignStateError, CampaignStoreError) as exc:
                    summary.errors.append(
                        f"waiting_campaign:{_bounded(exc, 120)}")
                    summary.state = campaign.state
                audit("paused", {"campaign_id": campaign_id,
                                 "reason": "job_pending_on_resume",
                                 "job_id": job.id,
                                 "objective_id":
                                     selected_obj.objective_id})
                break
            try:
                selected_obj = cs.transition_objective(
                    selected_obj.objective_id, new_state,
                    reason=why, detail=detail)
            except (CampaignStateError, CampaignStoreError) as exc:
                summary.errors.append(
                    f"objective_terminal:{_bounded(exc, 120)}")

            # 19: Research Memory (provenance-aware, non-overwriting)
            try:
                if memory_store is None:
                    from backend.research_agents.intelligence.memory \
                        import MemoryStore
                    memory_store = MemoryStore(store.base)
                items = _campaign_memory_items(
                    campaign=campaign, objective=selected_obj,
                    job_id=job.id, case_id=case_id,
                    gate_reason=gate_reason, confidence=confidence)
                if items:
                    from backend.research_agents.intelligence.memory \
                        import should_append
                    heads = {h.id: h for h in memory_store.heads()}
                    fresh = [i for i in items
                             if should_append(heads.get(i.id), i)]
                    if fresh:
                        memory_store.append(fresh)
            except Exception as exc:  # noqa: BLE001 - visible, non-fatal
                summary.errors.append(
                    f"memory:{_bounded(type(exc).__name__, 60)}")
                audit("memory_failed", {
                    "campaign_id": campaign_id,
                    "objective_id": selected_obj.objective_id,
                    "job_id": job.id,
                    "error": _bounded(exc, 200),
                })
                activity("memory_learned",
                         f"campaign memory record FAILED for "
                         f"{selected_obj.objective_id}: "
                         f"{_bounded(exc, 120)}",
                         objective_id=selected_obj.objective_id,
                         job_id=job.id)

            # Phase 9: persist cross-objective context from REAL state
            try:
                ctx_items = extract_context_items(
                    campaign_id=campaign_id, objective=selected_obj,
                    job_id=job.id, result={**(structured or {}),
                                           "technology":
                                               list(getattr(job_now,
                                                            "technology",
                                                            ()) or ())},
                    hunt=hunt, gate_reason=gate_reason,
                    confidence=confidence)
                stored_ctx = record_context(cs, ctx_items)
                audit("context_recorded", {
                    "campaign_id": campaign_id,
                    "objective_id": selected_obj.objective_id,
                    "job_id": job.id,
                    "items": stored_ctx,
                    "chars": bundle.total_chars,
                })
            except Exception as exc:  # noqa: BLE001 - visible
                summary.errors.append(
                    f"context:{_bounded(type(exc).__name__, 60)}")

            # 7: budget consumption read-back from REAL stores
            runtime_s = int(time.monotonic() - obj_started)
            try:
                budget.consume("observations",
                               len(hunt.get("observation_ids") or []),
                               reason="hunt observations executed",
                               objective_id=selected_obj.objective_id)
                budget.consume("hunt_plans",
                               len(hunt.get("plan_ids") or []),
                               reason="hunt plans created",
                               objective_id=selected_obj.objective_id)
                analysis_calls = 1 if getattr(result, "model",
                                              "") else 0
                budget.consume("llm_calls",
                               int((hunt.get("llm_advisory") or {}
                                    ).get("calls") or 0) + analysis_calls,
                               reason="hunt advisor + analysis LLM calls",
                               objective_id=selected_obj.objective_id)
                budget.consume("knowledge_documents",
                               int(hunt.get("knowledge_added") or 0),
                               reason="knowledge documents read",
                               objective_id=selected_obj.objective_id)
                budget.consume("runtime_seconds", runtime_s,
                               reason="objective wall time",
                               objective_id=selected_obj.objective_id)
                budget.consume("context_chars", bundle.total_chars,
                               reason="cross-objective context attached",
                               objective_id=selected_obj.objective_id)
                budget.consume("completed_objectives", 1,
                               reason="objective reached terminal state",
                               objective_id=selected_obj.objective_id)
            except Exception as exc:  # noqa: BLE001 - visible
                summary.errors.append(
                    f"budget:{_bounded(type(exc).__name__, 60)}")
            budget.sync_from_objectives(
                cs.objectives_for_campaign(campaign_id))

            # 15: full audit lineage for this objective
            audit_row = lineage_row(
                campaign_id=campaign_id,
                objective_id=selected_obj.objective_id,
                job_id=job.id,
                specialist=sel.agent_name,
                requested_model=str(
                    (hunt.get("llm_advisory") or {}
                     ).get("model_requested") or "openrouter/free"),
                resolved_model=str(
                    (hunt.get("llm_advisory") or {}
                     ).get("model_resolved") or ""),
                prompt_version=str(
                    (hunt.get("llm_advisory") or {}
                     ).get("prompt_version") or "deterministic"),
                prioritizer_version=PRIORITIZER_VERSION,
                planner_version=str(hunt.get("rule_version") or ""),
                budget_before=budget_before,
                budget_after=budget.report().to_dict(),
                authorization_result="GRANTED" if hunt.get(
                    "authorization_ids") else "none",
                evidence_result=f"{len(evidence_rows)} rows "
                                f"gate={gate_reason or 'n/a'}",
                termination_reason=why,
                plan_ids=hunt.get("plan_ids"),
                auth_ids=hunt.get("authorization_ids"),
                observation_ids=hunt.get("observation_ids"),
                case_id=case_id,
                stage="objective_terminal",
                extra={"objective_state": selected_obj.state,
                       "confidence": confidence,
                       "executed": executed + 1},
            )
            audit("objective_terminal", audit_row)

            # Phase 14 activity (real, store-derived)
            act_map = {"RESOLVED": "objective_resolved",
                       "BLOCKED": "objective_blocked",
                       "REJECTED": "objective_rejected",
                       "FAILED": "objective_failed",
                       "EXPIRED": "objective_expired",
                       "CANCELLED": "objective_cancelled"}
            activity(act_map.get(new_state, "objective_failed"),
                     f"{selected_obj.objective_id} -> {new_state} "
                     f"({why}) gate={gate_reason or 'n/a'} "
                     f"case={case_id or 'none'}",
                     objective_id=selected_obj.objective_id,
                     job_id=job.id)

            summary.objective_states[selected_obj.objective_id] = \
                selected_obj.state
            summary.selected.append({
                "objective_id": selected_obj.objective_id,
                "job_id": job.id,
                "specialist": sel.agent_name,
                "state": selected_obj.state,
                "reason": why,
                "case_id": case_id,
                "gate_reason": gate_reason,
            })
            if selected_obj.state in ("RESOLVED", "REJECTED"):
                last_completed = selected_obj.objective_id
                last_evidence_state = (
                    f"{selected_obj.state}:{gate_reason or 'n/a'}")
            executed += 1
            summary.executed_this_run = executed

            # 20/21: campaign state + next objective (loop continues)
            if executed >= run_limit:
                remaining = [o for o in
                             cs.objectives_for_campaign(campaign_id)
                             if not o.is_terminal]
                if remaining and not assess_termination():
                    try:
                        cs.transition_campaign(
                            campaign_id, "WAITING",
                            reason="per_run_objective_limit",
                            detail=f"executed {executed} objective(s) "
                                   "this run; {n} remain"
                                   .format(n=len(remaining)))
                        summary.state = "WAITING"
                        summary.termination_reason = (
                            "per_run_objective_limit")
                        activity("campaign_paused",
                                 f"run bound reached "
                                 f"({executed} objectives); "
                                 f"{len(remaining)} remain (WAITING)")
                        audit("paused", {
                            "campaign_id": campaign_id,
                            "reason": "per_run_objective_limit",
                            "executed": executed,
                            "remaining": len(remaining),
                        })
                    except (CampaignStateError, CampaignStoreError) as exc:
                        summary.errors.append(
                            f"run_bound:{_bounded(exc, 120)}")
                break
            continue

        # loop exit: ensure terminal assessment ran when not waiting
        if not summary.state:
            if not assess_termination():
                # run limit not hit and nothing terminal? then the loop
                # exited via break paths already recorded; as a last
                # resort reflect current campaign state honestly.
                current = cs.get_campaign(campaign_id)
                summary.state = current.state if current else ""
                summary.termination_reason = (
                    current.termination_reason if current else "")
                summary.ok = summary.state in (
                    "COMPLETED", "WAITING", "RUNNING")

        current = cs.get_campaign(campaign_id)
        if current is not None:
            summary.state = summary.state or current.state
        summary.budget = budget.report().to_dict()
        summary.objective_states = {
            o.objective_id: o.state
            for o in cs.objectives_for_campaign(campaign_id)}
        return summary
    finally:
        try:
            cs.release_lease(campaign_id, coordinator)
        except Exception:  # noqa: BLE001 - lease expiry covers crashes
            pass
        _ = started    # wall clock measured via budget runtime_seconds


__all__ = ["execute_campaign", "build_objective_job",
           "CampaignRunSummary", "LEASE_TTL_SECONDS",
           "CAMPAIGN_RULE_VERSION"]
