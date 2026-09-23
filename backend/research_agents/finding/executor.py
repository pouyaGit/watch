"""Bounded finding-verification executor (Phases 2-8, 15-16, 21).

Pipeline (one run):

  source job(s)
    -> deterministic extraction          (candidate_detected)
    -> structured correlation             (candidate_correlated)
    -> deterministic dedup                (candidate_deduplicated)
    -> deterministic triage               (candidate_triaged)
    -> verification objective + case      (verification_created, case_created)
    -> AuthorizationChecker pre-check     (verification_authorized)
    -> EXISTING queue + worker + Hunt Planner + Authorization +
       Observation Runtime + Evidence Gate (verification_started,
       verification_observation_completed)
    -> verification gate decision         (verification_gate_decided,
                                           case_verified/case_rejected)
    -> analyst case package               (case_handoff_ready)

Nothing here re-implements Runtime, Hunt Planner, Authorization,
Observation Runtime, the Evidence Gate or the Campaign Orchestrator —
jobs flow through the same enqueue/worker path those systems own, and the
verification gate (finding.gate) reads only the authoritative
``structured["evidence_gate"]`` record.  The advisor (if configured) is
called for ANNOTATION ONLY: its outcome is persisted into provenance and
never read by triage, the gate, or any transition (rule 6-9).

Bounds (rules 26-29 / Phase 21): cumulative FindingBudget limits, wall
clock, bounded worker passes, bounded candidate history.  Honest states
throughout: unfinished jobs park verification in WAITING (resumable, no
second job ever enqueued for an EXECUTING/WAITING verification).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from backend.research_agents.finding.advisor import (
    VerificationAdvisorOutcome,
    advisor_request,
    map_advisor_response,
)
from backend.research_agents.finding.audit import finding_event, lineage_row
from backend.research_agents.finding.case_package import build_package, ensure_case
from backend.research_agents.finding.correlate import correlate_pair
from backend.research_agents.finding.dedupe import deduplicate
from backend.research_agents.finding.extract import extract_candidates
from backend.research_agents.finding.gate import decide as gate_decide
from backend.research_agents.finding.limits import (
    DEFAULT_LIMITS,
    BudgetExhausted,
    FindingBudget,
)
from backend.research_agents.finding.models import (
    CandidateFinding,
    FindingStateError,
    FindingStoreError,
)
from backend.research_agents.finding.quality import classify_batch
from backend.research_agents.finding.store import FindingStore
from backend.research_agents.finding.triage import (
    RECOMMEND_VERIFY,
    triage_candidate,
)
from backend.research_agents.finding.verification import (
    allowed_types_for,
    build_verification_job,
    create_verification,
    precheck_authorization,
)

_MAX_WORKER_PASSES = 8
_TERMINAL_JOB_STATES = ("COMPLETED", "TERMINAL_FAILED", "EXPIRED",
                        "CANCELLED")


def _bounded(value: Any, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _default_worker_factory(config: Any, store: Any) -> Any:
    from backend.research_agents.runtime import AgentWorker
    return AgentWorker(config=config, store=store)


def _capability_for(category: str) -> Any:
    try:
        from backend.research_agents.capabilities import capability_for
        return capability_for(category)
    except Exception:  # noqa: BLE001 - registry fallback
        try:
            from backend.research_agents.capabilities import CAPABILITIES
            for cap in CAPABILITIES:
                if str(getattr(cap, "category", "")).upper() == \
                        str(category).upper():
                    return cap
        except Exception:  # noqa: BLE001
            return None
    return None


@dataclass
class FindingRunSummary:
    ok: bool = True
    reason: str = ""
    source_jobs: list[str] = field(default_factory=list)
    extracted: int = 0
    triaged: int = 0
    correlated: int = 0
    deduplicated: int = 0
    verifications_created: int = 0
    verifications_executed: int = 0
    verifications_waiting: int = 0
    cases_created: int = 0
    decisions: dict[str, str] = field(default_factory=dict)
    candidate_states: dict[str, str] = field(default_factory=dict)
    verification_states: dict[str, str] = field(default_factory=dict)
    advisor_outcomes: list[dict[str, Any]] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "source_jobs": list(self.source_jobs),
            "extracted": self.extracted,
            "triaged": self.triaged,
            "correlated": self.correlated,
            "deduplicated": self.deduplicated,
            "verifications_created": self.verifications_created,
            "verifications_executed": self.verifications_executed,
            "verifications_waiting": self.verifications_waiting,
            "cases_created": self.cases_created,
            "decisions": dict(self.decisions),
            "candidate_states": dict(self.candidate_states),
            "verification_states": dict(self.verification_states),
            "advisor_outcomes": list(self.advisor_outcomes),
            "budget": dict(self.budget),
            "errors": list(self.errors),
            "skipped": list(self.skipped),
        }


def run_findings(
    *,
    source_jobs: list[str],
    config: Any = None,
    store: Any = None,
    finding_store: Any = None,
    target: dict[str, Any] | None = None,
    campaign_id: str = "",
    objective_id: str = "",
    limits: dict[str, int] | None = None,
    advisor_fn: Callable[[dict], tuple[Any, dict]] | None = None,
    worker_factory: Callable[[Any, Any], Any] | None = None,
    max_verifications: int | None = None,
    wall_seconds: float | None = None,
    extract_only: bool = False,
    now_fn: Callable[[], float] = time.monotonic,
) -> FindingRunSummary:
    """Run the bounded CANDIDATE -> ... -> GATE pipeline (Phase 24 flow)."""
    from backend.research_agents.runtime import RuntimeConfig
    from backend.research_agents.runtime_store import default_store

    config = config or RuntimeConfig()
    store = store or default_store()
    fs = finding_store or FindingStore(store.base)
    wf = worker_factory or _default_worker_factory
    limits = dict(DEFAULT_LIMITS | (limits or {}))
    budget = FindingBudget(fs, limits)
    summary = FindingRunSummary()
    started = now_fn()
    wall_limit = float(wall_seconds if wall_seconds is not None
                       else limits["max_verification_runtime_seconds"])
    summary.source_jobs = list(source_jobs)

    def expired() -> bool:
        return (now_fn() - started) >= wall_limit

    def activity(action: str, detail: str, *, candidate_id: str = "",
                 job_id: str = "", verification_id: str = "") -> None:
        try:
            store.record_activity({
                "action": f"finding_{action}",
                "detail": _bounded(detail, 300),
                "candidate_id": candidate_id,
                "verification_id": verification_id,
                "job_id": job_id,
                "campaign_id": campaign_id,
                "mode": "production",
            })
        except Exception as exc:  # noqa: BLE001 - never fatal
            summary.errors.append(
                f"activity_{action}:{type(exc).__name__}")

    def audit(stage: str, payload: dict[str, Any]) -> None:
        try:
            store.record_audit_event(finding_event(stage, payload))
        except Exception as exc:  # noqa: BLE001 - never fatal
            summary.errors.append(
                f"audit_{stage}:{type(exc).__name__}")

    # ================================================================
    # PHASE A: extraction -> correlation -> dedup -> triage -> plan
    # ================================================================
    for jid in source_jobs:
        if expired():
            summary.skipped.append("wall_time_exhausted_during_extraction")
            break
        job = store.get(jid)
        if job is None:
            summary.skipped.append(f"job_not_found:{jid}")
            continue
        result = store.get_result(jid)
        if result is None:
            summary.skipped.append(f"no_result:{jid}")
            continue
        try:
            evidence_rows = store.list_evidence(job_id=jid)
        except Exception as exc:  # noqa: BLE001 - honest, never a crash
            summary.errors.append(
                f"evidence_unreadable:{jid}:{type(exc).__name__}")
            continue
        category = str(getattr(job, "agent_category", "")
                       or getattr(job, "category", ""))
        capability = _capability_for(category)
        if capability is None:
            summary.skipped.append(f"no_capability:{category}")
            continue

        scope_ref = str(getattr(job, "authorization_ref", "") or "")
        try:
            extraction = extract_candidates(
                job=job, result=result, evidence_rows=evidence_rows,
                capability=capability, scope_ref=scope_ref,
                target=target or {},
                source_campaign=campaign_id,
                source_objective=objective_id,
                max_candidates=int(limits["max_candidates_per_job"]),
            )
        except Exception as exc:  # noqa: BLE001 - fail closed, keep going
            summary.skipped.append(
                f"extraction_failed:{jid}:{type(exc).__name__}")
            continue
        summary.skipped.extend(extraction.skipped)

        # candidates already persisted (for correlation + dedup)
        existing = fs.list_candidates()

        for candidate in extraction.candidates:
            # budget: cumulative total candidates (fail closed)
            try:
                budget.ensure("max_candidates_total", 1,
                              reason="candidate_extracted")
            except BudgetExhausted as exc:
                summary.skipped.append(f"budget:{exc}")
                break
            try:
                fs.add_candidate(candidate)
            except FindingStoreError as exc:
                summary.skipped.append(
                    f"add_candidate:{_bounded(exc, 120)}")
                continue
            summary.extracted += 1
            existing.append(candidate)   # same-job candidates correlate too
            activity("candidate_detected",
                     f"{candidate.candidate_id} from {jid} "
                     f"class={candidate.vulnerability_class}",
                     candidate_id=candidate.candidate_id, job_id=jid)
            audit("candidate_detected", {
                "candidate_id": candidate.candidate_id,
                "source_job": jid, "campaign_id": campaign_id,
                "objective_id": objective_id,
                "specialist": candidate.specialist,
                "scope_ref": candidate.scope_ref,
                "confidence": candidate.confidence,
                "evidence_refs": candidate.evidence_refs[:10],
            })

            # ---- Phase 4: structured correlation --------------------
            others = [c for c in existing
                      if c.candidate_id != candidate.candidate_id]
            others = others[-int(limits["max_historical_candidates"]):]
            dup_hits: list[str] = []
            results = []
            for other in others:
                pair = correlate_pair(candidate, other)
                results.append(pair)
                if pair.relation == "INDEPENDENT":
                    continue
                summary.correlated += 1
                fs.record_correlation({
                    "left_id": pair.left_id, "right_id": pair.right_id,
                    "canonical_id": "",
                    "relation": pair.relation,
                    "reasons": pair.reasons,
                    "provenance": pair.provenance,
                })
                activity("candidate_correlated",
                         f"{pair.left_id}~{pair.right_id} "
                         f"{pair.relation} reasons={','.join(pair.reasons[:4])}",
                         candidate_id=candidate.candidate_id)
                if pair.relation in ("SAME_CANDIDATE",
                                     "POSSIBLE_DUPLICATE"):
                    dup_hits.append(pair.right_id if pair.left_id
                                    == candidate.candidate_id
                                    else pair.left_id)

            # ---- Phase 5: deterministic dedup ------------------------
            candidate = fs.get_candidate(candidate.candidate_id) or candidate
            if dup_hits and candidate.lifecycle_state != "DUPLICATE":
                ded = deduplicate(fs, candidate, others, results)
                if ded.action == "linked_duplicate":
                    summary.deduplicated += 1
                    activity("candidate_deduplicated",
                             f"{ded.duplicate_id} -> {ded.canonical_id} "
                             f"({ded.relation})",
                             candidate_id=candidate.candidate_id)
                    audit("candidate_deduplicated", {
                        "canonical_id": ded.canonical_id,
                        "duplicate_id": ded.duplicate_id,
                        "relation": ded.relation,
                        "reasons": ded.reasons[:8],
                        "preserved_evidence": ded.preserved_evidence[:10],
                        "campaign_id": campaign_id,
                    })
                # re-read: dedupe may have just marked THIS candidate
                candidate = (fs.get_candidate(candidate.candidate_id)
                             or candidate)

            if candidate.lifecycle_state == "DUPLICATE":
                summary.candidate_states[candidate.candidate_id] = \
                    "DUPLICATE"
                continue    # never triaged, never verified (Phase 5)

            # ---- Phase 3: deterministic triage -----------------------
            existing_cases: list[str] = []
            try:
                existing_cases = [c.id for c in store.list_cases()
                                  if str(c.get("job_id") or "") == jid]
            except Exception:  # noqa: BLE001 - empty is honest
                existing_cases = []
            prior_vers = fs.list_verifications(
                candidate_id=candidate.candidate_id)
            duplicates = list(dict.fromkeys(
                dup_hits + [str(x) for x in
                            (candidate.correlation or {}).get(
                                "linked_duplicates") or []]))
            try:
                decision_triage = triage_candidate(
                    candidate=candidate, evidence_rows=evidence_rows,
                    capability=capability,
                    existing_case_ids=existing_cases,
                    duplicate_candidates=duplicates,
                    previous_attempts=len(prior_vers),
                    verification_exists=bool(prior_vers),
                )
            except Exception as exc:  # noqa: BLE001 - honest state
                summary.errors.append(
                    f"triage:{candidate.candidate_id}:"
                    f"{type(exc).__name__}")
                continue

            # DETECTED -> TRIAGED -> decision state (audited; the
            # machine has no DETECTED->NEEDS_EVIDENCE edge by design)
            try:
                candidate = fs.transition_candidate(
                    candidate.candidate_id, "TRIAGED",
                    reason="triage:" + decision_triage.recommended_path,
                    detail=",".join(
                        decision_triage.reason_codes[:8]))
                if candidate.lifecycle_state != decision_triage.state:
                    candidate = fs.transition_candidate(
                        candidate.candidate_id, decision_triage.state,
                        reason="triage:" + decision_triage.recommended_path,
                        detail=",".join(
                            decision_triage.reason_codes[:8]))
            except (FindingStateError, FindingStoreError) as exc:
                summary.errors.append(
                    f"triage_transition:{_bounded(exc, 120)}")
                continue
            summary.triaged += 1
            activity("candidate_triaged",
                     f"{candidate.candidate_id} state="
                     f"{decision_triage.state} prio="
                     f"{decision_triage.priority} "
                     f"reasons={','.join(decision_triage.reason_codes[:5])}",
                     candidate_id=candidate.candidate_id)
            audit("candidate_triaged", {
                "candidate_id": candidate.candidate_id,
                "state": decision_triage.state,
                "priority": decision_triage.priority,
                "heuristic_priority": True,
                "recommended_path": decision_triage.recommended_path,
                "missing_evidence": decision_triage.missing_evidence[:6],
                "reason_codes": decision_triage.reason_codes[:10],
                "freshness": decision_triage.freshness,
            })

            # triage-terminal candidates stop here
            if candidate.lifecycle_state in (
                    "REJECTED", "BLOCKED", "DUPLICATE", "EXPIRED",
                    "INCONCLUSIVE"):
                summary.candidate_states[candidate.candidate_id] = \
                    candidate.lifecycle_state
                continue

            # ---- Phase 6: verification objective (when needed) -------
            wants_verify = (
                decision_triage.recommended_path == RECOMMEND_VERIFY
                or decision_triage.state in ("NEEDS_EVIDENCE",
                                             "TRIAGED"))
            if not wants_verify:
                summary.candidate_states[candidate.candidate_id] = \
                    candidate.lifecycle_state
                continue
            if expired():
                summary.skipped.append(
                    f"wall_time_before_verification:{candidate.candidate_id}")
                summary.candidate_states[candidate.candidate_id] = \
                    candidate.lifecycle_state
                continue
            if fs.list_verifications(candidate_id=candidate.candidate_id):
                summary.skipped.append(
                    f"verification_exists:{candidate.candidate_id}")
                summary.candidate_states[candidate.candidate_id] = \
                    candidate.lifecycle_state
                continue

            try:
                budget.ensure("max_verification_objectives", 1,
                              reason="verification_created")
            except BudgetExhausted as exc:
                summary.skipped.append(f"budget:{exc}")
                summary.candidate_states[candidate.candidate_id] = \
                    candidate.lifecycle_state
                continue

            # case package exists ONLY for verification-bound candidates
            try:
                case = ensure_case(fs, candidate,
                                   reason="verification_bound")
                summary.cases_created += 1
                activity("case_created",
                         f"{case.case_id} for {candidate.candidate_id}",
                         candidate_id=candidate.candidate_id)
                audit("case_created", {
                    "case_id": case.case_id,
                    "candidate_id": candidate.candidate_id,
                    "scope_ref": case.scope_ref,
                    "campaign_id": campaign_id,
                })
            except FindingStoreError as exc:
                summary.errors.append(
                    f"case_create:{_bounded(exc, 120)}")
                case = None

            # candidate -> VERIFICATION_PLANNED
            target_state = "VERIFICATION_PLANNED"
            if candidate.lifecycle_state != target_state:
                try:
                    candidate = fs.transition_candidate(
                        candidate.candidate_id, target_state,
                        reason="triage_recommends_verification",
                        detail=",".join(
                            decision_triage.reason_codes[:6]))
                except (FindingStateError, FindingStoreError) as exc:
                    summary.errors.append(
                        f"plan_transition:{_bounded(exc, 120)}")
                    continue

            try:
                ver = create_verification(
                    store=fs, candidate=candidate, capability=capability,
                    missing_evidence=decision_triage.missing_evidence,
                    budget={"max_observations":
                            int(limits["max_verification_observations"])},
                    provenance={
                        "campaign_id": campaign_id,
                        "objective_id": objective_id,
                        "triage_priority": decision_triage.priority,
                        "triage_reasons": decision_triage.reason_codes[:8],
                    })
            except (FindingStoreError, FindingStateError) as exc:
                summary.errors.append(
                    f"verification_create:{_bounded(exc, 120)}")
                continue
            summary.verifications_created += 1
            activity("verification_created",
                     f"{ver.verification_id} for {candidate.candidate_id}",
                     candidate_id=candidate.candidate_id,
                     verification_id=ver.verification_id)
            audit("verification_created", {
                "verification_id": ver.verification_id,
                "candidate_id": candidate.candidate_id,
                "scope_ref": ver.scope_ref,
                "required_evidence": ver.required_evidence[:6],
                "missing_evidence": ver.missing_evidence[:6],
                "allowed_observation_types":
                    ver.allowed_observation_types[:8],
            })

        existing = fs.list_candidates()   # refresh for next source job

    summary.budget = budget.report()
    if extract_only:
        summary.reason = "extract_only"
        summary.candidate_states = {
            c.candidate_id: c.lifecycle_state
            for c in fs.list_candidates()}
        summary.budget = budget.report()
        return summary

    # ================================================================
    # PHASE B: authorization -> (advisory) -> execution -> gate
    # ================================================================
    executable = fs.list_verifications(state="AUTHORIZATION_REQUIRED") \
        + fs.list_verifications(state="AUTHORIZED") \
        + fs.list_verifications(state="EXECUTING") \
        + fs.list_verifications(state="WAITING")
    executed_here = 0
    for ver in executable:
        if max_verifications is not None and \
                executed_here >= int(max_verifications):
            summary.skipped.append("max_verifications_reached")
            break
        if expired():
            summary.skipped.append("wall_time_exhausted")
            break
        candidate = fs.get_candidate(ver.candidate_id)
        if candidate is None:
            summary.errors.append(
                f"verification_orphan:{ver.verification_id}")
            continue
        if candidate.is_terminal or candidate.lifecycle_state == "DUPLICATE":
            summary.skipped.append(
                f"candidate_terminal:{ver.verification_id}")
            continue

        # ---- resume vs fresh job ------------------------------------
        job = None
        fresh = False
        if ver.job_id:
            job = store.get(ver.job_id)
            if job is None:
                # recorded job vanished: honest single re-enqueue
                job = None
                fresh = True
        else:
            fresh = True

        if fresh:
            capability = _capability_for(candidate.vulnerability_class)
            if capability is None:
                summary.errors.append(
                    f"capability_missing:{ver.verification_id}")
                continue
            try:
                job = build_verification_job(
                    candidate=candidate, verification=ver,
                    agent_name=str(getattr(capability, "agent_name", "")
                                   or candidate.specialist
                                   or "xss-agent"),
                    config=config)
            except Exception as exc:  # noqa: BLE001
                summary.errors.append(
                    f"job_build:{ver.verification_id}:"
                    f"{type(exc).__name__}")
                continue

            # ---- Phase 7 precondition: EXISTING authorization boundary
            authorized, auth_reason = precheck_authorization(job)
            if not authorized:
                ver = fs.transition_verification(
                    ver.verification_id, "BLOCKED",
                    reason=f"authorization_denied:{auth_reason}"[:120],
                    detail="pre-enqueue AuthorizationChecker denial")
                try:
                    candidate = fs.transition_candidate(
                        candidate.candidate_id, "BLOCKED",
                        reason=f"authorization_denied:{auth_reason}"[:120],
                        detail=ver.verification_id)
                except (FindingStateError, FindingStoreError) as exc:
                    summary.errors.append(
                        f"candidate_block:{_bounded(exc, 100)}")
                activity("verification_blocked",
                         f"{ver.verification_id} denied: {auth_reason}",
                         candidate_id=candidate.candidate_id,
                         verification_id=ver.verification_id)
                audit("authorization_denied", {
                    "verification_id": ver.verification_id,
                    "candidate_id": candidate.candidate_id,
                    "reason": str(auth_reason)[:120],
                })
                summary.verification_states[ver.verification_id] = "BLOCKED"
                continue

            needs_auth = ver.state == "AUTHORIZATION_REQUIRED"
            if needs_auth:
                ver = fs.transition_verification(
                    ver.verification_id, "AUTHORIZED",
                    reason=f"authorized:{auth_reason}"[:120])
                activity("verification_authorized",
                         f"{ver.verification_id} scope={ver.scope_ref}",
                         candidate_id=candidate.candidate_id,
                         verification_id=ver.verification_id)
                audit("verification_authorized", {
                    "verification_id": ver.verification_id,
                    "candidate_id": candidate.candidate_id,
                    "scope_ref": ver.scope_ref,
                })

                # candidate -> VERIFICATION_PENDING (authorization granted)
                if candidate.lifecycle_state == "VERIFICATION_PLANNED":
                    try:
                        candidate = fs.transition_candidate(
                            candidate.candidate_id, "VERIFICATION_PENDING",
                            reason="authorization_granted",
                            detail=ver.verification_id)
                    except (FindingStateError, FindingStoreError) as exc:
                        summary.errors.append(
                            f"candidate_pending:{_bounded(exc, 100)}")

                # ---- Phase 10: ADVISORY ONLY (never read by the gate)
                if advisor_fn is not None:
                    _run_advisor(
                        fs=fs, store=store, candidate=candidate, ver=ver,
                        capability=capability, budget=budget,
                        limits=limits, summary=summary,
                        campaign_id=campaign_id,
                        advisor_fn=advisor_fn)
            else:
                # crash recovery: recorded job vanished while already
                # AUTHORIZED/EXECUTING/WAITING — single re-enqueue of a
                # NEW job id, recorded honestly, never a duplicate run
                activity("verification_job_recovered",
                         f"{ver.verification_id} state={ver.state} "
                         "job_missing_single_reenqueue",
                         candidate_id=candidate.candidate_id,
                         verification_id=ver.verification_id)

            # enqueue through the EXISTING queue (duplicate-proof:
            # EXECUTING/WAITING verifications never reach this branch
            # unless their recorded job vanished)
            try:
                store.enqueue(job)
                ver.job_id = job.id
                ver = fs.save_verification(ver)
            except Exception as exc:  # noqa: BLE001
                summary.errors.append(
                    f"enqueue:{ver.verification_id}:{type(exc).__name__}")
                try:
                    ver = fs.transition_verification(
                        ver.verification_id, "FAILED",
                        reason="enqueue_failed",
                        detail=_bounded(exc, 200))
                except (FindingStateError, FindingStoreError):
                    pass
                continue

        if job is None:
            summary.skipped.append(
                f"job_missing_for:{ver.verification_id}")
            continue

        # ---- EXECUTING ------------------------------------------------
        if ver.state in ("AUTHORIZED",):
            ver = fs.transition_verification(
                ver.verification_id, "EXECUTING",
                reason="verification_started", detail=f"job={job.id}")
        if candidate.lifecycle_state == "VERIFICATION_PENDING":
            try:
                candidate = fs.transition_candidate(
                    candidate.candidate_id, "VERIFYING",
                    reason="verification_started", detail=job.id)
            except (FindingStateError, FindingStoreError) as exc:
                summary.errors.append(
                    f"candidate_verifying:{_bounded(exc, 100)}")
            # case lifecycle: TRIAGED -> VERIFYING
            case_row = fs.cases_for_candidate(candidate.candidate_id)
            if case_row is not None and case_row.state == "TRIAGED":
                try:
                    fs.transition_case(case_row.case_id, "VERIFYING",
                                       reason="verification_started")
                except (FindingStateError, FindingStoreError) as exc:
                    summary.errors.append(
                        f"case_verifying:{_bounded(exc, 100)}")
        activity("verification_started",
                 f"{ver.verification_id} job={job.id}",
                 candidate_id=candidate.candidate_id,
                 job_id=job.id, verification_id=ver.verification_id)
        audit("verification_started", {
            "verification_id": ver.verification_id,
            "candidate_id": candidate.candidate_id,
            "job_id": job.id,
            "scope_ref": ver.scope_ref,
            "specialist": candidate.specialist,
        })

        # ---- run ONE existing worker job (bounded passes) -----------
        job_now = store.get(job.id)
        passes = 0
        try:
            worker = wf(config, store)
            try:
                worker.categories = (candidate.vulnerability_class,)
            except Exception:  # noqa: BLE001 - keep default categories
                pass
            while passes < _MAX_WORKER_PASSES and not expired():
                job_now = store.get(job.id)
                if job_now is None:
                    break
                if str(job_now.status) in _TERMINAL_JOB_STATES:
                    break
                store.sweep()
                worker.run(max_jobs=1)
                passes += 1
                job_now = store.get(job.id)
                if job_now is not None and \
                        str(job_now.status) in _TERMINAL_JOB_STATES:
                    break
        except Exception as exc:  # noqa: BLE001 - honest failure
            summary.errors.append(
                f"worker:{ver.verification_id}:{type(exc).__name__}")
            try:
                ver = fs.transition_verification(
                    ver.verification_id, "FAILED",
                    reason="worker_failure", detail=_bounded(exc, 200))
                if not candidate.is_terminal:
                    candidate = fs.transition_candidate(
                        candidate.candidate_id, "BLOCKED",
                        reason="verification_worker_failure",
                        detail=_bounded(exc, 200))
                summary.verification_states[ver.verification_id] = "FAILED"
            except (FindingStateError, FindingStoreError):
                pass
            continue

        job_now = store.get(job.id) or job_now
        job_status = str(getattr(job_now, "status", "") or "")

        # ---- unfinished: honest WAITING (never a second job) ---------
        if job_status not in _TERMINAL_JOB_STATES:
            if ver.state == "EXECUTING":
                try:
                    ver = fs.transition_verification(
                        ver.verification_id, "WAITING",
                        reason="verification_job_not_finished",
                        detail=f"status={job_status or 'unknown'}")
                except (FindingStateError, FindingStoreError) as exc:
                    summary.errors.append(
                        f"waiting:{_bounded(exc, 100)}")
            summary.verifications_waiting += 1
            summary.verification_states[ver.verification_id] = \
                ver.state
            summary.candidate_states[candidate.candidate_id] = \
                candidate.lifecycle_state
            continue

        # ---- finished: observation completed + gate decision ---------
        result = store.get_result(job.id)
        structured = (getattr(result, "structured", None)
                      if result else None) or {}
        if not isinstance(structured, dict):
            structured = {}
        hunt = structured.get("hunt") or {}
        if isinstance(hunt, dict):
            if hunt.get("plan_ids"):
                ver.plan_ids = list(hunt.get("plan_ids") or [])
            if hunt.get("authorization_ids"):
                ver.authorization_ids = list(
                    hunt.get("authorization_ids") or [])
            if hunt.get("observation_ids"):
                ver.observation_ids = list(
                    hunt.get("observation_ids") or [])
            ver = fs.save_verification(ver)

        # Round-2 production fix: hunt's structured block carries no
        # authorization ids — the authoritative GRANTED authz ids live in
        # hunt_authorization audit events (Phase 16 provenance).  Harvest
        # them for this verification's job; never invent them.
        if not ver.authorization_ids:
            try:
                auth_ids = [str(row.get("auth_id") or "")
                            for row in store.audit_events(limit=5000)
                            if row.get("event") == "hunt_authorization"
                            and str(row.get("job_id") or "") == job.id
                            and row.get("auth_id")]
                auth_ids = [x for x in dict.fromkeys(auth_ids) if x]
            except Exception:  # noqa: BLE001 - honest empty on unread
                auth_ids = []
            if auth_ids:
                ver.authorization_ids = auth_ids
                ver = fs.save_verification(ver)

        # Phase 21 accounting: real observations from this verification
        obs_count = len(ver.observation_ids or [])
        if obs_count:
            try:
                budget.ensure("max_verification_observations", obs_count,
                              reason="verification_observations",
                              verification_id=ver.verification_id)
            except BudgetExhausted as exc:
                summary.skipped.append(f"budget:{exc}")

        activity("verification_observation_completed",
                 f"{ver.verification_id} job={job.id} "
                 f"observations={obs_count} "
                 f"plans={len(ver.plan_ids or [])} "
                 f"auths={len(ver.authorization_ids or [])}",
                 candidate_id=candidate.candidate_id,
                 job_id=job.id, verification_id=ver.verification_id)

        # quality metadata (Phase 9): prior + verification evidence.
        # evidence persistence failure = honest FAILED verification +
        # BLOCKED candidate (never a crash, never a fake decision)
        try:
            prior_rows = store.list_evidence(job_id=candidate.source_job)
            ver_rows = store.list_evidence(job_id=job.id)
            qualities = classify_batch(
                prior_rows + ver_rows,
                vulnerability_class=candidate.vulnerability_class,
                verification_job_ids=[job.id])
            quality_dicts = [q.to_dict() for q in qualities]
        except Exception as exc:  # noqa: BLE001 - honest failure
            summary.errors.append(
                f"evidence_unreadable:{ver.verification_id}:"
                f"{type(exc).__name__}")
            try:
                ver = fs.transition_verification(
                    ver.verification_id, "FAILED",
                    reason="evidence_persistence_failure",
                    detail=_bounded(exc, 200))
                if not candidate.is_terminal:
                    candidate = fs.transition_candidate(
                        candidate.candidate_id, "BLOCKED",
                        reason="evidence_persistence_failure",
                        detail=ver.verification_id)
            except (FindingStateError, FindingStoreError):
                pass
            summary.verification_states[ver.verification_id] = "FAILED"
            summary.candidate_states[candidate.candidate_id] = \
                candidate.lifecycle_state
            continue

        # runtime case id (job-level gate may have created one)
        runtime_case_id = ""
        try:
            for row in store.list_cases():
                if str(row.get("job_id") or "") == job.id:
                    runtime_case_id = str(row.get("id") or "")
                    break
        except Exception:  # noqa: BLE001 - lookup is best effort
            runtime_case_id = ""

        # ---- Phase 8: THE verification gate (no advisor input) -------
        decision = gate_decide(
            candidate=candidate, verification=ver,
            job_status=job_status,
            job_error=str(getattr(job_now, "error", "") or ""),
            structured=structured, quality_rows=quality_dicts,
            hunt=hunt if isinstance(hunt, dict) else {},
            runtime_case_id=runtime_case_id,
        )

        # verification objective terminal transition.  Persist the
        # AUTHORITATIVE gate reason when present; otherwise persist the
        # decision's own reason (e.g. gate_record_absent) so every
        # terminal outcome is auditable — never a blank reason.
        ver.gate_reason = (decision.gate_reason
                           or decision.reason
                           or ver.gate_reason)
        ver.decision = decision.verification_state
        try:
            ver = fs.save_verification(ver)
            ver = fs.transition_verification(
                ver.verification_id, decision.verification_state,
                reason=decision.reason, detail=decision.detail)
        except (FindingStateError, FindingStoreError) as exc:
            summary.errors.append(
                f"verification_decide:{_bounded(exc, 120)}")

        # candidate terminal transition (store re-checks the gate result)
        if not candidate.is_terminal:
            try:
                candidate = fs.transition_candidate(
                    candidate.candidate_id, decision.candidate_state,
                    reason=decision.reason, detail=decision.detail,
                    gate_result=decision.gate_reason)
            except (FindingStateError, FindingStoreError) as exc:
                summary.errors.append(
                    f"candidate_decide:{_bounded(exc, 120)}")
        summary.decisions[candidate.candidate_id] = \
            decision.verification_state

        activity("verification_gate_decided",
                 f"{ver.verification_id} -> "
                 f"{decision.verification_state} "
                 f"reason={decision.reason}",
                 candidate_id=candidate.candidate_id,
                 job_id=job.id, verification_id=ver.verification_id)
        audit("verification_gate_decided", {
            "verification_id": ver.verification_id,
            "candidate_id": candidate.candidate_id,
            "job_id": job.id,
            "case_id": decision.case_id or runtime_case_id,
            "gate_reason": decision.gate_reason,
            "gate_confidence": decision.gate_confidence,
            "decision": decision.verification_state,
            "reason": decision.reason,
            "plan_ids": list(ver.plan_ids or []),
            "authorization_ids": list(ver.authorization_ids or []),
            "observation_ids": list(ver.observation_ids or []),
            "campaign_id": campaign_id,
            "objective_id": objective_id,
        })

        # ---- Phase 12/13: case lifecycle + analyst package -----------
        case_row = fs.cases_for_candidate(candidate.candidate_id)
        if case_row is not None:
            new_case_state = {
                "VERIFIED": "VERIFIED", "REJECTED": "REJECTED",
                "INCONCLUSIVE": "INCONCLUSIVE", "BLOCKED": "BLOCKED",
                "FAILED": "BLOCKED",
            }.get(decision.verification_state, "")
            if new_case_state and case_row.state != new_case_state:
                try:
                    fs.transition_case(
                        case_row.case_id, new_case_state,
                        reason=decision.reason,
                        gate_result=decision.gate_reason)
                    if new_case_state == "VERIFIED":
                        activity("case_verified",
                                 f"{case_row.case_id} gate="
                                 f"{decision.gate_reason}",
                                 candidate_id=candidate.candidate_id)
                    elif new_case_state == "REJECTED":
                        activity("case_rejected",
                                 f"{case_row.case_id} "
                                 f"reason={decision.reason}",
                                 candidate_id=candidate.candidate_id)
                    audit("case_state", {
                        "case_id": case_row.case_id,
                        "candidate_id": candidate.candidate_id,
                        "state": new_case_state,
                        "reason": decision.reason,
                    })
                except (FindingStateError, FindingStoreError) as exc:
                    summary.errors.append(
                        f"case_state:{_bounded(exc, 120)}")

            # analyst package ONLY for gate-verified cases
            if new_case_state == "VERIFIED":
                knowledge_ids: list[str] = []
                try:
                    knowledge_ids = [
                        str(k.get("id") or "")
                        for k in (structured.get("knowledge_considered")
                                  or [])
                        if isinstance(k, dict)][:10]
                except Exception:  # noqa: BLE001
                    knowledge_ids = []
                try:
                    package = build_package(
                        store=fs, runtime_store=store,
                        candidate=candidate, verification=ver,
                        decision=decision, qualities=qualities,
                        knowledge_ids=knowledge_ids,
                        research_jobs=[candidate.source_job, job.id])
                    # re-read: case_row was fetched BEFORE the terminal
                    # transition; saving the stale copy would roll the
                    # state back to VERIFYING
                    case_row = (fs.cases_for_candidate(
                        candidate.candidate_id) or case_row)
                    case_row.package = package
                    case_row.severity = candidate.severity
                    case_row.severity_provenance = \
                        candidate.severity_provenance
                    case_row.recommended_next_step = str(
                        package.get("recommended_analyst_next_step") or "")
                    case_row.limitations = list(
                        package.get("limitations") or [])
                    fs.save_case(case_row)
                    fs.transition_case(case_row.case_id,
                                       "READY_FOR_REVIEW",
                                       reason="package_ready")
                    activity("case_handoff_ready",
                             f"{case_row.case_id} package_ready "
                             f"evidence={len(package.get('evidence_ids') or [])}",
                             candidate_id=candidate.candidate_id)
                    audit("case_handoff_ready", {
                        "case_id": case_row.case_id,
                        "candidate_id": candidate.candidate_id,
                        "verification_id": ver.verification_id,
                        "evidence_count": len(
                            package.get("evidence_ids") or []),
                    })
                except Exception as exc:  # noqa: BLE001 - honest failure
                    summary.errors.append(
                        f"package:{_bounded(exc, 120)}")

        # ---- lineage row (Phase 16) ---------------------------------
        audit("lineage", lineage_row(
            candidate_id=candidate.candidate_id,
            verification_id=ver.verification_id,
            case_id=case_row.case_id if case_row else "",
            job_id=job.id,
            plan_id=(ver.plan_ids or [""])[0],
            authorization_ids=list(ver.authorization_ids or []),
            observation_ids=list(ver.observation_ids or []),
            evidence_refs=list(candidate.evidence_refs or []),
            campaign_id=campaign_id,
            objective_id=objective_id,
            specialist=candidate.specialist,
            model_requested=str(structured.get("requested_model") or ""),
            model_resolved=str(structured.get("resolved_model") or ""),
            prompt_version=str(structured.get("prompt_version") or ""),
            gate_result=decision.gate_reason,
            lifecycle_transition=f"VERIFYING->{decision.candidate_state}",
            reason_codes=[decision.reason],
        ))

        summary.verifications_executed += 1
        summary.verification_states[ver.verification_id] = ver.state
        summary.candidate_states[candidate.candidate_id] = \
            candidate.lifecycle_state
        executed_here += 1

    summary.budget = budget.report()
    if summary.errors and not summary.verifications_executed \
            and not summary.extracted:
        summary.ok = False
        summary.reason = "no_progress:" + summary.errors[0][:120]
    elif not summary.reason:
        summary.reason = "completed"
    return summary


def _run_advisor(*, fs: Any, store: Any, candidate: Any, ver: Any,
                 capability: Any, budget: FindingBudget,
                 limits: dict[str, int], summary: FindingRunSummary,
                 campaign_id: str,
                 advisor_fn: Callable[[dict], tuple[Any, dict]]
                 | None = None) -> VerificationAdvisorOutcome:
    """Advisory call — outcome persisted to provenance only.

    The gate, triage and every transition above never read this value
    (rule 6-9: advisory only, cannot confirm anything).
    """
    outcome = VerificationAdvisorOutcome()
    if not budget.ok("max_llm_calls"):
        outcome.error = "advisor_disabled:max_llm_calls"
        summary.advisor_outcomes.append(outcome.to_dict())
        _record_advisor(fs, ver, outcome, summary, campaign_id)
        return outcome
    try:
        budget.ensure("max_llm_calls", 1, reason="advisor_attempt",
                      verification_id=ver.verification_id)
    except BudgetExhausted as exc:
        outcome.error = f"advisor_disabled:{exc}"
        summary.advisor_outcomes.append(outcome.to_dict())
        _record_advisor(fs, ver, outcome, summary, campaign_id)
        return outcome

    prior_rows = store.list_evidence(job_id=candidate.source_job)
    qualities = classify_batch(
        prior_rows,
        vulnerability_class=candidate.vulnerability_class,
        verification_job_ids=[ver.job_id] if ver.job_id else [])
    evidence_summary = [q.to_dict() for q in qualities[:6]]
    try:
        request = advisor_request(
            candidate=candidate, verification=ver,
            evidence_summary=evidence_summary,
            related_research=fs.list_correlations(
                candidate_id=candidate.candidate_id)[:6],
            knowledge_count=len(
                (candidate.provenance or {}).get("knowledge_ids") or []),
            allowed_observation_types=ver.allowed_observation_types,
            budget_remaining=budget.remaining(),
        )
    except Exception as exc:  # noqa: BLE001 - honest degrade
        outcome.error = f"advisor_request_failed:{type(exc).__name__}"
        summary.advisor_outcomes.append(outcome.to_dict())
        _record_advisor(fs, ver, outcome, summary, campaign_id)
        return outcome

    import json as _json
    canonical = len(_json.dumps(request, sort_keys=True))
    if canonical > int(limits.get("max_context_chars", 4000)):
        outcome.error = (f"context_too_large:{canonical}>"
                         f"{limits.get('max_context_chars', 4000)}")
        summary.advisor_outcomes.append(outcome.to_dict())
        _record_advisor(fs, ver, outcome, summary, campaign_id)
        return outcome

    try:
        response, meta = advisor_fn(request)
    except Exception as exc:  # noqa: BLE001 - honest failure, no fallback
        outcome.error = f"advisor_provider_error:{_bounded(exc, 160)}"
        summary.advisor_outcomes.append(outcome.to_dict())
        _record_advisor(fs, ver, outcome, summary, campaign_id)
        return outcome

    outcome = map_advisor_response(
        response,
        candidate_id=candidate.candidate_id,
        verification_id=ver.verification_id,
        scope_ref=candidate.scope_ref,
        expected_scope=ver.scope_ref,
        allowed_types=set(str(t).lower()
                          for t in allowed_types_for(capability))
        | set(str(t).lower()
              for t in (ver.allowed_observation_types or [])),
    )
    outcome.model_requested = str(
        (meta or {}).get("model_requested") or "openrouter/free")
    outcome.model_resolved = str((meta or {}).get("model_resolved") or "")
    outcome.latency_ms = int((meta or {}).get("latency_ms") or 0)
    summary.advisor_outcomes.append(outcome.to_dict())
    _record_advisor(fs, ver, outcome, summary, campaign_id)
    return outcome


def _record_advisor(fs: Any, ver: Any, outcome: VerificationAdvisorOutcome,
                    summary: FindingRunSummary, campaign_id: str) -> None:
    """Persist the advisory outcome into provenance (annotation only)."""
    try:
        ver.provenance = {**(ver.provenance or {}),
                          "advisor": outcome.to_dict()}
        fs.save_verification(ver)
    except Exception as exc:  # noqa: BLE001
        summary.errors.append(f"advisor_persist:{type(exc).__name__}")


__all__ = ["run_findings", "FindingRunSummary", "FindingBudget",
           "BudgetExhausted"]
