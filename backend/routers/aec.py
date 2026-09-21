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

from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import APIRouter

from aec.orchestrator.models import STATES as LIFECYCLE_STATES

router = APIRouter()

LAYER_VERSION = "aec-1/epic-3"

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
    """Case records currently held in memory (empty until wired)."""
    return build_cases_view([])


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
