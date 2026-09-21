"""Read-only AEC views for the command center (EPIC 3 Part 4, EPIC 4 Part 5).

Five GET endpoints over explicitly supplied view data — case records,
queue snapshot, aggregate status, research candidates, research status.
Handlers are pure allowlist projections: they select a fixed field set
and drop everything else, so unmounted or mis-shaped input can neither
leak nor mutate. There is no database, no session, and no write path
anywhere in this module.

Mounting (operator decision, Track B)::

    from backend.routers import aec as aec_router
    app.include_router(aec_router.router)

The router is inert until mounted: importing it serves nothing.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from aec.orchestrator.models import STATES as LIFECYCLE_STATES

router = APIRouter()

LAYER_VERSION = "aec-1/epic-3"

#: EPIC8: server-rendered AEC pages share the dashboard template directory
#: (fresh instance on purpose — aec.py stays free of backend.* imports).
_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "web" / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

OBSERVATION_LIFECYCLE_STATES = frozenset({
    "RECEIVED", "VALIDATING", "AUTHORIZED", "DISPATCHED", "OBSERVING",
    "COLLECTING", "COMPLETED", "REFUSED", "BLOCKED", "TIMED_OUT", "FAILED",
})

AUDIT_ACTIONS = frozenset({
    "case.created", "assignment.created", "authorization.requested",
    "authorization.approved", "observation.executed", "evidence.stored",
    "review.requested",
})

BADGE_OK = "ok"
BADGE_WARN = "warn"
BADGE_ERR = "err"
BADGE_MUTED = "muted"

CASE_VIEW_KEYS = ("case_id", "state", "evidence_state", "selection_order")

CANDIDATE_VIEW_KEYS = (
    "candidate_id", "asset", "endpoint", "research_category",
    "band", "score", "role",
)

RESEARCH_BANDS = frozenset({"LOW", "MEDIUM", "HIGH"})

ASSIGNMENT_ROLES = frozenset({
    "authorization-researcher",
    "input-researcher",
    "server-researcher",
    "technology-researcher",
    "general-researcher",
})

STATUS_COUNT_STATES = frozenset(LIFECYCLE_STATES) | frozenset(
    {"WAITING_EVIDENCE", "EVIDENCE_PARTIAL", "EVIDENCE_READY"}
)


def _text(value: object) -> str:
    return str(value or "").strip()


def build_cases_view(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project case records to the public field set, in input order."""
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise ValueError("records must be a sequence of mappings")
    cases: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        case_id = _text(record.get("case_id"))
        state = _text(record.get("state"))
        if not case_id or not state:
            continue
        order = record.get("selection_order", 0)
        cases.append(
            {
                "case_id": case_id,
                "state": state,
                "evidence_state": _text(record.get("evidence_state"))
                or "WAITING_EVIDENCE",
                "selection_order": order if isinstance(order, int) else 0,
            }
        )
    return {"cases": cases}


def build_queue_view(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Project a queue snapshot, verifying its internal totals."""
    if not isinstance(snapshot, Mapping):
        raise ValueError("snapshot must be a mapping")
    entries = snapshot.get("entries")
    if not isinstance(entries, (list, tuple)):
        raise ValueError("snapshot entries must be a sequence")
    total = snapshot.get("total")
    if not isinstance(total, int) or total != len(entries):
        raise ValueError("snapshot total must match its entries")
    return {
        "snapshot_id": _text(snapshot.get("snapshot_id")),
        "entries": [dict(e) for e in entries],
        "total": total,
    }


def build_status_view(counts: Mapping[str, int]) -> dict[str, Any]:
    """Aggregate lifecycle counts with the layer version stamp."""
    if not isinstance(counts, Mapping):
        raise ValueError("counts must be a mapping")
    clean: dict[str, int] = {}
    for state, count in counts.items():
        if state not in STATUS_COUNT_STATES:
            raise ValueError(f"unknown lifecycle state: {state!r}")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"count for {state!r} must be a non-negative int")
        clean[state] = count
    return {"counts": clean, "versions": {"aec": LAYER_VERSION}}


@router.get("/api/aec/cases")
def get_cases() -> dict[str, Any]:
    """Case explorer rows over the fixture simulation (EPIC8 Part 3)."""
    return build_case_explorer_view(_simulation_run().get("cases", []))


@router.get("/api/aec/queue")
def get_queue() -> dict[str, Any]:
    """Current queue snapshot (empty until wired)."""
    return build_queue_view({"snapshot_id": "", "entries": [], "total": 0})


@router.get("/api/aec/status")
def get_status() -> dict[str, Any]:
    """Aggregate lifecycle counts (empty until wired)."""
    return build_status_view({})


def build_candidates_view(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project research candidates with priority band, score, and role."""
    if isinstance(items, (str, bytes)) or not isinstance(items, Sequence):
        raise ValueError("items must be a sequence of mappings")
    candidates: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        candidate_id = _text(item.get("candidate_id"))
        band = _text(item.get("band"))
        if not candidate_id or band not in RESEARCH_BANDS:
            continue
        score = item.get("score", 0)
        role = _text(item.get("role"))
        candidates.append(
            {
                "candidate_id": candidate_id,
                "asset": _text(item.get("asset")),
                "endpoint": _text(item.get("endpoint")),
                "research_category": _text(item.get("research_category")),
                "band": band,
                "score": score if isinstance(score, int) else 0,
                "role": role if role in ASSIGNMENT_ROLES else "general-researcher",
            }
        )
    return {"candidates": candidates}


def build_research_status_view(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Aggregate band counts, role counts, and the layer version stamp."""
    if not isinstance(summary, Mapping):
        raise ValueError("summary must be a mapping")
    bands = summary.get("bands", {})
    roles = summary.get("roles", {})
    if not isinstance(bands, Mapping) or not isinstance(roles, Mapping):
        raise ValueError("bands and roles must be mappings")
    clean_bands: dict[str, int] = {}
    for band, count in bands.items():
        if band not in RESEARCH_BANDS:
            raise ValueError(f"unknown research band: {band!r}")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"count for {band!r} must be a non-negative int")
        clean_bands[band] = count
    clean_roles: dict[str, int] = {}
    for role, count in roles.items():
        if role not in ASSIGNMENT_ROLES:
            raise ValueError(f"unknown research role: {role!r}")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"count for {role!r} must be a non-negative int")
        clean_roles[role] = count
    return {
        "bands": clean_bands,
        "roles": clean_roles,
        "versions": {"aec": LAYER_VERSION},
    }


@router.get("/api/aec/candidates")
def get_candidates() -> dict[str, Any]:
    """Research candidates with priority (empty until wired)."""
    return build_candidates_view([])


@router.get("/api/aec/research-status")
def get_research_status() -> dict[str, Any]:
    """Aggregate band/role counts (empty until wired)."""
    return build_research_status_view({"bands": {}, "roles": {}})


RESEARCH_RUN_KEYS = (
    "run_id", "candidates_processed", "cases_created", "cases_skipped",
    "plans_generated", "review_items", "failures", "completion_summary",
)


def _simulation_run() -> dict[str, Any]:
    """Run the committed fixture through the coordinator (pure, no I/O).

    The fixture lives in-module, so handlers serve real
    simulation-derived data on demand: deterministic, read-only, no
    storage reads or writes. Imported lazily so importing this router
    never pays for a simulation.
    """
    from aec.coordinator import fixtures, pipeline

    return pipeline.run_research(list(fixtures.CANDIDATES)).to_dict()


def build_research_runs_view(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project research runs to the public field set, in input order."""
    if isinstance(runs, (str, bytes)) or not isinstance(runs, Sequence):
        raise ValueError("runs must be a sequence of mappings")
    projected: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        run_id = _text(run.get("run_id"))
        if not run_id:
            continue
        projected.append(
            {
                "run_id": run_id,
                "candidates_processed": run.get("candidates_processed", 0),
                "cases_created": list(run.get("cases_created", [])),
                "cases_skipped": list(run.get("cases_skipped", [])),
                "plans_generated": list(run.get("plans_generated", [])),
                "review_items": list(run.get("review_items", [])),
                "failures": list(run.get("failures", [])),
                "completion_summary": dict(run.get("completion_summary", {})),
            }
        )
    return {"runs": projected}


def build_research_queue_view(snapshot: Mapping[str, Any] | None) -> dict[str, Any]:
    """Project a coordinator queue snapshot (empty view for None)."""
    if snapshot is None:
        return {"snapshot_id": "", "entries": [], "total": 0}
    return build_queue_view(snapshot)


def build_review_view(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project review items, dropping malformed entries."""
    if isinstance(items, (str, bytes)) or not isinstance(items, Sequence):
        raise ValueError("items must be a sequence of mappings")
    from aec.review import queue as review_queue

    projected: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        try:
            projected.append(review_queue.build_review_item(item).to_dict())
        except ValueError:
            continue
    return {"items": projected}


def build_research_summary_view(run: Mapping[str, Any]) -> dict[str, Any]:
    """Aggregate a run into band, specialist, authorization, and evidence counts."""
    if not isinstance(run, Mapping):
        raise ValueError("run must be a mapping")
    cases = run.get("cases", [])
    if not isinstance(cases, (list, tuple)):
        raise ValueError("run cases must be a sequence")
    bands: dict[str, int] = {}
    by_specialist: dict[str, int] = {}
    for case in cases:
        if not isinstance(case, Mapping):
            continue
        band = _text(case.get("band"))
        if band in RESEARCH_BANDS:
            bands[band] = bands.get(band, 0) + 1
        specialist = _text(case.get("specialist"))
        if specialist in ASSIGNMENT_ROLES:
            by_specialist[specialist] = by_specialist.get(specialist, 0) + 1
    authorizations = run.get("authorization_states", {})
    evidence = run.get("evidence_states", {})
    if not isinstance(authorizations, Mapping) or not isinstance(evidence, Mapping):
        raise ValueError("run states must be mappings")
    failures = run.get("failures", [])
    return {
        "run_id": _text(run.get("run_id")),
        "candidates_processed": run.get("candidates_processed", 0),
        "cases_created": len(run.get("cases_created", []) or []),
        "bands": bands,
        "assignments_by_specialist": by_specialist,
        "authorizations": dict(authorizations),
        "evidence_states": dict(evidence),
        "failures": len(failures) if isinstance(failures, (list, tuple)) else 0,
        "versions": {"aec": LAYER_VERSION},
    }


@router.get("/api/aec/research-runs")
def get_research_runs() -> dict[str, Any]:
    """Latest research run over the committed fixture (simulated)."""
    return build_research_runs_view([_simulation_run()])


@router.get("/api/aec/research-queue")
def get_research_queue() -> dict[str, Any]:
    """Research queue from the fixture simulation."""
    return build_research_queue_view(_simulation_run().get("queue_snapshot"))


@router.get("/api/aec/review")
def get_review() -> dict[str, Any]:
    """Human review queue from the fixture simulation."""
    return build_review_view(_simulation_run().get("review_items", []))


@router.get("/api/aec/research-summary")
def get_research_summary() -> dict[str, Any]:
    """Aggregate counts from the fixture simulation."""
    return build_research_summary_view(_simulation_run())


EXECUTION_KEYS = (
    "run_id", "source_mode", "candidate_count", "case_count", "job_count",
    "queued_count", "blocked_count", "waiting_authorization_count",
    "observation_count", "evidence_count", "review_required_count",
    "completed_count", "failed_count", "duration", "replay_identity",
    "policy_version",
)


def _execution_run() -> dict[str, Any]:
    """Run the committed fixture through the execution loop (pure, no I/O)."""
    from aec.runtime import loop

    records = list(_EXECUTION_FIXTURE)
    authz = {record["id"]: {"status": "GRANTED", "expires_tick": 100}
             for record in records}
    return loop.run_execution(records, "fixture", authz=authz).to_dict()


_EXECUTION_FIXTURE = (
    {
        "subdomain": "shop.example.com",
        "url": "/orders?order_id=",
        "endpoint": "/orders",
        "parameter": "order_id",
        "method": "GET",
        "location": "query",
        "technology": ["flask"],
        "source": "watch",
        "id": "srv-1",
        "category": "IDOR_CANDIDATE",
    },
    {
        "subdomain": "cdn.example.com",
        "url": "/reflect?q=",
        "endpoint": "/reflect",
        "parameter": "q",
        "method": "GET",
        "location": "query",
        "technology": ["nginx"],
        "source": "watch",
        "id": "srv-2",
        "category": "XSS_CANDIDATE",
    },
)


def build_execution_runs_view(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project execution runs to the public field set."""
    if isinstance(runs, (str, bytes)) or not isinstance(runs, Sequence):
        raise ValueError("runs must be a sequence of mappings")
    projected: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        run_id = _text(run.get("run_id"))
        if not run_id:
            continue
        projected.append({
            key: run.get(key) for key in EXECUTION_KEYS
        })
    return {"runs": projected, "total": len(projected)}


def build_research_jobs_view(run: Mapping[str, Any]) -> dict[str, Any]:
    """Project research jobs from one execution run."""
    if not isinstance(run, Mapping):
        raise ValueError("run must be a mapping")
    jobs = run.get("jobs", [])
    if not isinstance(jobs, (list, tuple)):
        raise ValueError("jobs must be a sequence")
    return {"jobs": [dict(job) for job in jobs], "total": len(jobs)}


def build_specialists_view() -> dict[str, Any]:
    """List declared specialist contracts (registry, not findings)."""
    from aec.specialists import registry

    profiles = registry.default_registry()
    return {
        "specialists": [profile.to_dict() for profile in profiles],
        "total": len(profiles),
    }


def build_evidence_view(run: Mapping[str, Any]) -> dict[str, Any]:
    """Project ingested evidence records from one execution run."""
    if not isinstance(run, Mapping):
        raise ValueError("run must be a mapping")
    evidence = run.get("evidence", [])
    if not isinstance(evidence, (list, tuple)):
        raise ValueError("evidence must be a sequence")
    return {"evidence": [dict(record) for record in evidence],
            "total": len(evidence)}


def build_execution_summary_view(run: Mapping[str, Any]) -> dict[str, Any]:
    """Operational counters for one execution run (no conclusions)."""
    if not isinstance(run, Mapping):
        raise ValueError("run must be a mapping")
    return {
        "run_id": _text(run.get("run_id")),
        "source_mode": _text(run.get("source_mode")),
        "job_count": run.get("job_count", 0),
        "blocked_count": run.get("blocked_count", 0),
        "waiting_authorization_count": run.get(
            "waiting_authorization_count", 0),
        "observation_count": run.get("observation_count", 0),
        "evidence_count": run.get("evidence_count", 0),
        "review_required_count": run.get("review_required_count", 0),
        "completed_count": run.get("completed_count", 0),
        "failed_count": run.get("failed_count", 0),
        "duration": run.get("duration", 0),
        "replay_identity": _text(run.get("replay_identity")),
        "versions": {"aec": LAYER_VERSION},
    }


@router.get("/api/aec/execution-runs")
def get_execution_runs() -> dict[str, Any]:
    """Latest execution run over the committed fixture (simulated)."""
    return build_execution_runs_view([_execution_run()])


@router.get("/api/aec/research-jobs")
def get_research_jobs() -> dict[str, Any]:
    """Research jobs from the execution simulation."""
    return build_research_jobs_view(_execution_run())


@router.get("/api/aec/specialists")
def get_specialists() -> dict[str, Any]:
    """Declared specialist contracts."""
    return build_specialists_view()


@router.get("/api/aec/evidence")
def get_evidence() -> dict[str, Any]:
    """Ingested evidence records from the execution simulation."""
    return build_evidence_view(_execution_run())


@router.get("/api/aec/execution-summary")
def get_execution_summary() -> dict[str, Any]:
    """Operational counters from the execution simulation."""
    return build_execution_summary_view(_execution_run())


# ---------------------------------------------------------------------------
# EPIC8: Command Center Intelligence UI (read-only views, GET only).
# Every builder below is a pure projection of the committed simulations:
# no storage, no network, no mutation, no execution trigger.
# ---------------------------------------------------------------------------

TERMINAL_CASE_STATES = frozenset({"COMPLETED", "REFUSED", "BLOCKED",
                                  "FAILED"})


def _activity_entries() -> list[dict[str, Any]]:
    """Deterministic recent-activity feed derived from the simulations."""
    sim = _simulation_run()
    run = _execution_run()
    entries: list[dict[str, Any]] = []
    entries.append({
        "timestamp": 10, "actor": "pipeline",
        "action": "started research run", "result": sim.get("run_id", "")})
    for case in sim.get("cases", []):
        if isinstance(case, Mapping):
            entries.append({
                "timestamp": 9, "actor": "pipeline",
                "action": "created case",
                "result": _text(case.get("case_id"))})
    for assignment in sim.get("assignments", []):
        if isinstance(assignment, Mapping):
            entries.append({
                "timestamp": 8, "actor": "pipeline",
                "action": "assigned specialist",
                "result": _text(assignment.get("specialist"))})
    for case in sim.get("cases", []):
        if isinstance(case, Mapping) and sim.get(
                "authorization_states", {}).get(case.get("candidate_id")):
            entries.append({
                "timestamp": 7, "actor": "gate",
                "action": "authorized research",
                "result": "ALLOW"})
    for record in run.get("evidence", []):
        if isinstance(record, Mapping):
            entries.append({
                "timestamp": 6, "actor": "runtime",
                "action": "stored evidence",
                "result": _text(record.get("evidence_id"))})
    for record in run.get("review_records", []):
        if isinstance(record, Mapping):
            entries.append({
                "timestamp": 5, "actor": "pipeline",
                "action": "requested review",
                "result": _text(record.get("outcome"))})
    for reason in run.get("blocked_reasons", []) or []:
        entries.append({
            "timestamp": 4, "actor": "runtime",
            "action": "blocked observation",
            "result": str(reason)})
    return entries[:40]


def build_dashboard_view(empty: bool = False) -> dict[str, Any]:
    """System overview: KPI counts plus a bounded recent-activity feed."""
    sim = _simulation_run()
    run = _execution_run()
    if empty:
        return {
            "candidates": 0, "active_cases": 0, "research_jobs": 0,
            "waiting_evidence": 0, "observations": 0, "review_pending": 0,
            "recent_activity": [], "generated_at": 0,
        }
    cases = sim.get("cases", [])
    active = sum(
        1 for case in cases
        if case.get("state", "") not in TERMINAL_CASE_STATES)
    waiting = sum(
        1 for case in cases
        if case.get("evidence_state") == "WAITING_EVIDENCE")
    return {
        "candidates": sim.get("candidates_processed", 0),
        "active_cases": active,
        "research_jobs": run.get("job_count", 0),
        "waiting_evidence": waiting,
        "observations": run.get("observation_count", 0),
        "review_pending": run.get("review_required_count", 0),
        "recent_activity": _activity_entries(),
        # deterministic logical generation stamp (fixture-derived, stable)
        "generated_at": max(
            [entry["timestamp"] for entry in _activity_entries()] or [0]),
    }


def _explorer_row(case: Mapping[str, Any],
                  jobs_by_case: Mapping[str, Any]) -> dict[str, Any]:
    case_id = _text(case.get("case_id"))
    job = jobs_by_case.get(case_id) if jobs_by_case else None
    transitions = job.get("transitions", []) if job else []
    last_tick = max(
        [t.get("tick", 0) for t in transitions if isinstance(t, Mapping)]
        or [0]) if transitions else 0
    evidence_state = _text(case.get("evidence_state"))
    if not evidence_state and job:
        # Execution-run cases carry research state instead of a dedicated
        # evidence column; derive the display value from the job state.
        state = _text(job.get("state"))
        evidence_state = (
            "REVIEW_REQUIRED" if state == "REVIEW_REQUIRED"
            else "WAITING_EVIDENCE" if state == "READY_FOR_OBSERVATION"
            else state or "")
    if not evidence_state:
        # A case that was selected but never processed has no evidence yet.
        evidence_state = "NOT_STARTED"
    state = _text(case.get("state"))
    if evidence_state == "WAITING_EVIDENCE" or state == "WAITING_EVIDENCE":
        next_action = "collect evidence"
        badge = BADGE_WARN
    elif state == "WAITING_AUTHORIZATION":
        next_action = "await authorization"
        badge = BADGE_WARN
    elif state in TERMINAL_CASE_STATES:
        next_action = "none (terminal)"
        badge = BADGE_MUTED
    else:
        next_action = "monitor"
        badge = BADGE_OK
    return {
        "case_id": case_id,
        "target": _text(case.get("asset")) or _text(case.get("endpoint")),
        "category": _text(case.get("category")),
        "research_state": state,
        "evidence_state": evidence_state,
        "specialist": _text(case.get("specialist")),
        "last_activity": f"tick {last_tick}" if last_tick else "",
        "next_action": next_action,
        "badge": badge,
    }


def build_case_explorer_view(
        records: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Case list projection with operator columns (EPIC8 Part 3)."""
    if records is None:
        records = _simulation_run().get("cases", [])
    if isinstance(records, (str, bytes)) or not isinstance(records,
                                                           Sequence):
        raise ValueError("records must be a sequence of mappings")
    run = _execution_run()
    jobs_by_case = {
        job.get("case_id"): job for job in run.get("jobs", [])
        if isinstance(job, Mapping) and job.get("case_id")
    }
    rows = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        case_id = _text(record.get("case_id"))
        if not case_id:
            continue
        rows.append(_explorer_row(record, jobs_by_case))
    rows.sort(key=lambda row: row["case_id"])
    return {"cases": rows, "total": len(rows)}


def build_case_detail_view(case_id: str) -> dict[str, Any]:
    """One case: timeline, history, evidence, authorization, audit."""
    if not isinstance(case_id, str) or not case_id:
        return {"not_found": True, "case": {}}
    sim = _simulation_run()
    run = _execution_run()
    case = next(
        (c for c in sim.get("cases", [])
         if isinstance(c, Mapping) and c.get("case_id") == case_id),
        None)
    if case is None:
        # Execution-run cases (jobs) are also valid detail targets.
        job_match = next(
            (j for j in run.get("jobs", [])
             if isinstance(j, Mapping) and j.get("case_id") == case_id),
            None)
        if job_match is not None:
            case = job_match
    if case is None:
        return {"not_found": True, "case": {}}
    jobs_by_case = {
        job.get("case_id"): job for job in run.get("jobs", [])
        if isinstance(job, Mapping) and job.get("case_id")
    }
    job = jobs_by_case.get(case_id)
    transitions = job.get("transitions", []) if job else []
    timeline = [
        {"tick": t.get("tick", 0), "actor": _text(t.get("actor")),
         "event": _text(t.get("next_state"))}
        for t in transitions if isinstance(t, Mapping)
    ]
    timeline.sort(key=lambda entry: entry["tick"])
    research_history = []
    steps = case.get("steps", [])
    if isinstance(steps, (list, tuple)):
        research_history.append({
            "plan_id": _text(case.get("plan_id")),
            "step_count": len(
                [s for s in steps if isinstance(s, Mapping)]),
        })
    evidence_artifacts = [
        dict(record) for record in run.get("evidence", [])
        if isinstance(record, Mapping) and record.get("case_id") == case_id
    ]
    authz_state = sim.get("authorization_states", {}).get(
        case.get("candidate_id"), "")
    audit_events = [
        event for event in build_audit_view()["events"]
        if event.get("reference") == case_id
    ]
    observations = [
        row for row in build_observations_view()["observations"]
        if row["case_id"] == case_id
    ]
    return {
        "case": _explorer_row(case, jobs_by_case),
        "timeline": timeline,
        "research_history": research_history,
        "evidence_artifacts": evidence_artifacts,
        "authorization_status": {
            "state": authz_state or "UNKNOWN",
            "reference": "authz-" + case_id[5:] if len(case_id) > 5
            else "",
        },
        "observation_history": observations,
        "audit_events": audit_events,
    }


def build_pipeline_view(empty: bool = False) -> dict[str, Any]:
    """Research pipeline: candidate -> … -> review, with blockers."""
    sim = _simulation_run()
    run = _execution_run()
    if empty:
        stages = [{"stage": name, "state": "", "blocks": [],
                   "badge": BADGE_MUTED}
                  for name in ("candidate", "case", "assignment",
                               "research_job", "authorization",
                               "observation", "evidence", "review")]
        return {"stages": stages}
    review_items = sim.get("review_items", []) or []
    waiting_evidence = sum(
        1 for case in sim.get("cases", [])
        if isinstance(case, Mapping)
        and case.get("evidence_state") == "WAITING_EVIDENCE")
    stages = [
        {"stage": "candidate", "state": "SELECTED"
            if sim.get("candidates_processed", 0) > 0 else "",
         "blocks": [], "badge": BADGE_OK},
        {"stage": "case", "state": "OPEN"
            if sim.get("cases") else "",
         "blocks": [], "badge": BADGE_OK},
        {"stage": "assignment", "state": "ASSIGNED"
            if sim.get("assignments") else "",
         "blocks": [], "badge": BADGE_OK},
        {"stage": "research_job", "state": "RUNNING"
            if run.get("job_count", 0) > 0 else "",
         "blocks": [], "badge": BADGE_OK},
        {"stage": "authorization", "state": "ALLOW"
            if sim.get("authorization_states") else "",
         "blocks": [], "badge": BADGE_OK},
        {"stage": "observation", "state": "COMPLETED"
            if run.get("observation_count", 0) > 0 else "",
         "blocks": [], "badge": BADGE_OK},
        {"stage": "evidence", "state": "WAITING_EVIDENCE"
            if waiting_evidence > 0 else "EVIDENCE_READY",
         "blocks": ["Missing comparison artifact"]
            if waiting_evidence > 0 else [],
         "badge": BADGE_WARN if waiting_evidence > 0 else BADGE_OK},
        {"stage": "review", "state": "REQUIRED"
            if len(review_items) > 0 else "",
         "blocks": ["Human review required"] if review_items else [],
         "badge": BADGE_WARN if review_items else BADGE_MUTED},
    ]
    for stage in stages:
        if not stage["state"]:
            stage["badge"] = BADGE_MUTED
    return {"stages": stages}


def build_observations_view(
        records: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Read-only observation center rows (EPIC8 Part 5)."""
    if records is None:
        records = _execution_run().get("evidence", [])
    if isinstance(records, (str, bytes)):
        raise ValueError("records must be a sequence of mappings")
    rows = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        artifact = _text(record.get("artifact_reference"))
        evidence_id = _text(record.get("evidence_id"))
        if not artifact or not evidence_id:
            continue
        tick = record.get("tick", 0)
        obs_id = "obs-" + (artifact.split(":", 1)[0]
                           .split("-", 1)[-1])
        suffix = artifact.split(":", 1)[-1] if ":" in artifact else ""
        if suffix:
            obs_id = f"{obs_id}-{suffix}"
        rows.append({
            "request_id": obs_id,
            "case_id": _text(record.get("case_id")),
            "target": "/".join(str(p) for p in
                               (record.get("observation") or [])),
            "observation_type": "HTTP_METADATA",
            "state": "COMPLETED",
            "created_time": tick if isinstance(tick, int) else 0,
            "completed_time": tick if isinstance(tick, int) else 0,
            "evidence_id": evidence_id,
            "badge": BADGE_OK,
        })
    return {"observations": rows, "total": len(rows)}


def _viewer_artifact(record: Mapping[str, Any]) -> dict[str, Any]:
    evidence_id = _text(record.get("evidence_id"))
    integrity = _text(record.get("integrity")) or "0" * 64
    return {
        "evidence_id": evidence_id,
        "case_id": _text(record.get("case_id")),
        "observation_type": "HTTP_METADATA",
        "authorization_reference": "authz-" + _text(record.get("case_id"))[5:],
        "scope_validation": "n/a",
        "provenance": {
            "source": _text(record.get("source")),
            "source_mode": _text(record.get("source_mode")),
            "tick": record.get("tick", 0),
        },
        "integrity": "sha256:" + integrity,
        "integrity_badge": BADGE_OK,
        "redaction_status": _text(record.get("redaction_status"))
        or "clean",
        "redaction_badge": BADGE_MUTED,
        "quality_score": "partial",
    }


def build_evidence_viewer_view(
        records: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Evidence artifacts with integrity/redaction display fields."""
    if records is None:
        records = _execution_run().get("evidence", [])
    if isinstance(records, (str, bytes)):
        raise ValueError("records must be a sequence of mappings")
    artifacts = [_viewer_artifact(r) for r in records
                 if isinstance(r, Mapping) and r.get("evidence_id")]
    artifacts.sort(key=lambda row: row["evidence_id"])
    return {"artifacts": artifacts}


def build_audit_view(empty: bool = False) -> dict[str, Any]:
    """Unified audit timeline: case created -> … -> review requested."""
    if empty:
        return {"events": []}
    sim = _simulation_run()
    run = _execution_run()
    events: list[dict[str, Any]] = []
    for case in sim.get("cases", []):
        if isinstance(case, Mapping):
            events.append({
                "timestamp": 1, "actor": "pipeline",
                "action": "case.created",
                "result": "created",
                "reference": _text(case.get("case_id")),
                "badge": BADGE_MUTED,
            })
    for assignment in sim.get("assignments", []):
        if isinstance(assignment, Mapping):
            events.append({
                "timestamp": 2, "actor": "pipeline",
                "action": "assignment.created",
                "result": _text(assignment.get("specialist")),
                "reference": _text(assignment.get("candidate_id")),
                "badge": BADGE_MUTED,
            })
    authz = sim.get("authorization_states", {})
    for candidate_id, state in authz.items():
        if isinstance(state, str) and state:
            events.append({
                "timestamp": 3, "actor": "gate",
                "action": "authorization.requested",
                "result": state,
                "reference": candidate_id,
                "badge": BADGE_WARN,
            })
            events.append({
                "timestamp": 4, "actor": "authorizer",
                "action": "authorization.approved",
                "result": "granted",
                "reference": candidate_id,
                "badge": BADGE_OK,
            })
    for record in run.get("evidence", []):
        if isinstance(record, Mapping):
            events.append({
                "timestamp": 5, "actor": "runtime",
                "action": "observation.executed",
                "result": "COMPLETED",
                "reference": _text(record.get("case_id")),
                "badge": BADGE_OK,
            })
            events.append({
                "timestamp": 6, "actor": "runtime",
                "action": "evidence.stored",
                "result": "stored",
                "reference": _text(record.get("evidence_id")),
                "badge": BADGE_MUTED,
            })
    for record in run.get("review_records", []):
        if isinstance(record, Mapping):
            events.append({
                "timestamp": 7, "actor": "pipeline",
                "action": "review.requested",
                "result": _text(record.get("outcome")),
                "reference": _text(record.get("case_id")),
                "badge": BADGE_WARN,
            })
    events.sort(key=lambda event: (event["timestamp"],
                                   event["reference"]))
    return {"events": events}


# --- EPIC8 API handlers -------------------------------------------------

@router.get("/api/aec/dashboard")
def get_dashboard() -> dict[str, Any]:
    """Command Center dashboard overview (simulated, read-only)."""
    return build_dashboard_view()


@router.get("/api/aec/cases/{id}")
def get_case_detail(case_id: str) -> dict[str, Any]:
    """One case with timeline, evidence, and audit sections."""
    return build_case_detail_view(case_id)


@router.get("/api/aec/research/jobs")
def get_research_pipeline() -> dict[str, Any]:
    """Research pipeline visualization (stages + blockers)."""
    return build_pipeline_view()


@router.get("/api/aec/observations")
def get_observations() -> dict[str, Any]:
    """Read-only observation center rows."""
    return build_observations_view()


@router.get("/api/aec/audit")
def get_audit() -> dict[str, Any]:
    """Unified audit timeline."""
    return build_audit_view()


# --- EPIC8 page payloads (server-rendered UI) ---------------------------

def dashboard_page_payload() -> dict[str, Any]:
    return {
        "view": build_dashboard_view(),
        "active": "aec-dashboard",
        "page_title": "AEC Command Center",
    }


def cases_page_payload(empty: bool = False) -> dict[str, Any]:
    view = ({"cases": [], "total": 0} if empty
            else build_case_explorer_view(_simulation_run().get(
                "cases", [])))
    return {**view, "active": "aec-cases", "page_title": "AEC Cases"}


def case_detail_page_payload(case_id: str) -> dict[str, Any]:
    detail = build_case_detail_view(case_id)
    if detail.get("not_found"):
        return {**detail, "page_title": "Case not found",
                "active": "aec-cases"}
    return {**detail, "page_title": "AEC Case Detail",
            "active": "aec-cases"}


def pipeline_page_payload() -> dict[str, Any]:
    return {**build_pipeline_view(),
            "page_title": "AEC Research Pipeline",
            "active": "aec-pipeline"}


def observations_page_payload() -> dict[str, Any]:
    return {**build_observations_view(),
            "page_title": "AEC Observations",
            "active": "aec-observations"}


def evidence_page_payload(
        records: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    return {**build_evidence_viewer_view(records),
            "page_title": "AEC Evidence", "active": "aec-evidence"}


def audit_page_payload() -> dict[str, Any]:
    return {**build_audit_view(), "page_title": "AEC Audit",
            "active": "aec-audit"}


# --- EPIC8 page routes (GET only, server-rendered) ----------------------

@router.get("/ui/aec/dashboard", response_class=HTMLResponse)
def ui_aec_dashboard(request: Request):
    return _templates.TemplateResponse(
        request, "aec/dashboard.html", dashboard_page_payload())


@router.get("/ui/aec/cases", response_class=HTMLResponse)
def ui_aec_cases(request: Request):
    return _templates.TemplateResponse(
        request, "aec/cases.html", cases_page_payload())


@router.get("/ui/aec/cases/{id}", response_class=HTMLResponse)
def ui_aec_case_detail(request: Request, case_id: str):
    return _templates.TemplateResponse(
        request, "aec/case_detail.html", case_detail_page_payload(case_id))


@router.get("/ui/aec/pipeline", response_class=HTMLResponse)
def ui_aec_pipeline(request: Request):
    return _templates.TemplateResponse(
        request, "aec/pipeline.html", pipeline_page_payload())


@router.get("/ui/aec/observations", response_class=HTMLResponse)
def ui_aec_observations(request: Request):
    return _templates.TemplateResponse(
        request, "aec/observations.html", observations_page_payload())


@router.get("/ui/aec/evidence", response_class=HTMLResponse)
def ui_aec_evidence(request: Request):
    return _templates.TemplateResponse(
        request, "aec/evidence.html", evidence_page_payload())


@router.get("/ui/aec/audit", response_class=HTMLResponse)
def ui_aec_audit(request: Request):
    return _templates.TemplateResponse(
        request, "aec/audit.html", audit_page_payload())


# ---------------------------------------------------------------------------
# EPIC7 Part 18: Authorized Observation Runtime API (additive GET only).
# The runtime is exposed as operational state over the committed fixture
# simulation — DRY_RUN mode, zero network. Live observation stays behind
# the authorization boundary and is never triggered by these endpoints.
# ---------------------------------------------------------------------------

def _runtime_request() -> dict[str, Any]:
    """One deterministic fixture runtime request (DRY_RUN, no network)."""
    return {
        "request_id": "obsreq-f0f0f0f0f0f0",
        "research_job_id": "job-deadbeef0001",
        "case_id": "case-feedface0001",
        "target_id": "tgt-000000000001",
        "observation_type": "HTTP_METADATA",
        "method": "GET",
        "required_evidence_level": "PARTIAL",
        "authorization_reference": "authz-fixture-001",
        "policy_version": "v1",
        "mode": "DRY_RUN",
        "state": "AUTHORIZED",
        "dry_run": True,
        "executed": False,
        "reason": "",
    }


def build_runtime_view() -> dict[str, Any]:
    """Runtime overview: supported modes, current state, gating posture."""
    return {
        "modes": ["DRY_RUN", "LIVE_OBSERVATION"],
        "mode": "DRY_RUN",
        "state": "READY",
        "observation_types": [
            "HTTP_METADATA", "HTTP_HEADERS", "HTTP_STATUS",
            "HTTP_BODY_METADATA"],
        "authorization_gated": True,
        "scope_enforced": True,
        "versions": {"runtime": LAYER_VERSION},
    }


def build_runtime_requests_view() -> dict[str, Any]:
    """Recent runtime requests from the fixture simulation (DRY_RUN)."""
    return {
        "total": 1,
        "requests": [_runtime_request()],
    }


def build_runtime_audit_view() -> dict[str, Any]:
    """Append-only audit trail snapshot for the simulated request."""
    return {
        "verified": True,
        "entries": [{
            "seq": 1,
            "request_id": "obsreq-f0f0f0f0f0f0",
            "decision": "AUTHORIZED",
            "execution_state": "AUTHORIZED",
            "mode": "DRY_RUN",
        }],
    }


def build_runtime_limits_view() -> dict[str, int]:
    """The policy's resource limits (EPIC7 Part 7)."""
    limits = _runtime_limits()
    return dict(limits.to_dict())


def build_runtime_health_view() -> dict[str, Any]:
    """Operational health: runtime ready and authorization-gated."""
    return {
        "status": "ready",
        "mode": "DRY_RUN",
        "authorization_boundary": "enforced",
        "network": "disabled",
    }


def _runtime_limits():
    from aec.runtime.policy.limits import default_limits
    return default_limits()


@router.get("/api/aec/runtime")
def get_runtime() -> dict[str, Any]:
    """Authorized Observation Runtime overview (simulated, DRY_RUN)."""
    return build_runtime_view()


@router.get("/api/aec/runtime/requests")
def get_runtime_requests() -> dict[str, Any]:
    """Runtime observation requests from the fixture simulation."""
    return build_runtime_requests_view()


@router.get("/api/aec/runtime/audit")
def get_runtime_audit() -> dict[str, Any]:
    """Audit trail snapshot (append-only, hash-chained in the runtime)."""
    return build_runtime_audit_view()


@router.get("/api/aec/runtime/limits")
def get_runtime_limits() -> dict[str, Any]:
    """Policy-driven resource limits."""
    return build_runtime_limits_view()


@router.get("/api/aec/runtime/health")
def get_runtime_health() -> dict[str, Any]:
    """Runtime health and gating posture."""
    return build_runtime_health_view()


__all__ = [
    "build_candidates_view",
    "build_cases_view",
    "build_evidence_view",
    "build_execution_runs_view",
    "build_execution_summary_view",
    "build_queue_view",
    "build_research_jobs_view",
    "build_research_queue_view",
    "build_research_runs_view",
    "build_research_status_view",
    "build_research_summary_view",
    "build_review_view",
    "build_runtime_audit_view",
    "build_runtime_health_view",
    "build_runtime_limits_view",
    "build_runtime_requests_view",
    "build_runtime_view",
    "build_specialists_view",
    "build_status_view",
    "build_evidence_viewer_view",
    "build_dashboard_view",
    "build_case_explorer_view",
    "build_case_detail_view",
    "build_pipeline_view",
    "build_observations_view",
    "build_audit_view",
    "dashboard_page_payload",
    "cases_page_payload",
    "case_detail_page_payload",
    "pipeline_page_payload",
    "observations_page_payload",
    "evidence_page_payload",
    "audit_page_payload",
    "get_dashboard",
    "get_case_detail",
    "get_research_pipeline",
    "get_observations",
    "get_audit",
    "get_candidates",
    "get_cases",
    "get_evidence",
    "get_execution_runs",
    "get_execution_summary",
    "get_queue",
    "get_research_jobs",
    "get_research_queue",
    "get_research_runs",
    "get_research_summary",
    "get_review",
    "get_research_status",
    "get_runtime",
    "get_runtime_audit",
    "get_runtime_health",
    "get_runtime_limits",
    "get_runtime_requests",
    "get_specialists",
    "get_status",
    "router",
]
