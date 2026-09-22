"""backend/research_agents/service.py — orchestration facade + UI payloads.

Wires the registry, repository and orchestrator into the shapes consumed by the
API and the Command Center:

- :func:`bootstrap_pipeline` -- idempotently turn the Attack Surface priority
  queue into research jobs (candidate -> job -> agent -> evidence plan).
- :func:`create_jobs` -- explicit job creation from candidates or the surface.
- :func:`agents_payload` -- agent status + queue counters.
- :func:`command_center_payload` -- the ``RESEARCH AGENTS`` section payload.
- :func:`list_jobs` / :func:`get_job` -- queue / investigation state.

The default store is in-memory and process-local; nothing is written to the
production database. Bootstrap is bounded and idempotent.
"""

from __future__ import annotations

import threading

from backend.research_agents.models import (
    ACTIVE_JOB_STATUSES,
    CATEGORY_TO_AGENT,
)
from backend.research_agents.orchestrator import AgentOrchestrator
from backend.research_agents.registry import (
    AgentRegistry,
    build_default_registry,
)
from backend.research_agents.repository import (
    DEFAULT_CANDIDATE_LIMIT,
    ResearchJobStore,
    candidates_from_payload,
    load_priority_candidates,
)

DEFAULT_PIPELINE_LIMIT = 20

#: Agent category -> attack-surface category (for candidate counters).
AGENT_TO_CANDIDATE_CATEGORY: dict[str, str] = {
    agent: candidate for candidate, agent in CATEGORY_TO_AGENT.items()
}

_REGISTRY: AgentRegistry = build_default_registry()
_STORE: ResearchJobStore = ResearchJobStore()
_ORCHESTRATOR: AgentOrchestrator = AgentOrchestrator(_REGISTRY, _STORE)
_PIPELINE_LOCK = threading.Lock()


def registry() -> AgentRegistry:
    return _REGISTRY


def store() -> ResearchJobStore:
    return _STORE


def orchestrator() -> AgentOrchestrator:
    return _ORCHESTRATOR


# ---------------------------------------------------------------------------
# Candidate counters
# ---------------------------------------------------------------------------


def _surface_payload(
    program: str | None,
    *,
    payload: dict | None = None,
    records: dict | None = None,
) -> dict:
    if isinstance(payload, dict):
        return payload
    try:
        from backend.attack_surface import service as asurface

        return asurface.attack_surface_payload(program, records=records)
    except Exception:
        return {"available": False, "summary": {}, "priority_queue": []}


def _candidate_counts(payload: dict) -> dict:
    summary = payload.get("summary") if isinstance(payload, dict) else {}
    by_category = (summary or {}).get("by_category") or {}
    return {
        str(key): int(value)
        for key, value in by_category.items()
        if isinstance(value, (int, float))
    }


# ---------------------------------------------------------------------------
# Agent payload
# ---------------------------------------------------------------------------


def agents_payload(
    program: str | None = None,
    *,
    payload: dict | None = None,
    records: dict | None = None,
) -> dict:
    """Agent status + candidate/job queue counters (deterministic)."""

    surface = _surface_payload(program, payload=payload, records=records)
    counts = _candidate_counts(surface)
    agents: list[dict] = []
    for agent in _REGISTRY.list_agents():
        candidate_category = AGENT_TO_CANDIDATE_CATEGORY.get(agent.category, "")
        candidate_count = counts.get(candidate_category, 0)
        jobs = _STORE.jobs_for_agent(agent.name)
        active = sum(1 for job in jobs if job.status in ACTIVE_JOB_STATUSES)
        entry = agent.to_dict()
        entry.update({
            "queue": candidate_count,
            "job_count": len(jobs),
            "active_jobs": active,
            "available": agent.status == "ready",
        })
        agents.append(entry)
    return {
        "available": bool(surface.get("available")),
        "count": len(agents),
        "agents": agents,
    }


# ---------------------------------------------------------------------------
# Job creation / pipeline
# ---------------------------------------------------------------------------


def bootstrap_pipeline(
    program: str | None = None,
    *,
    payload: dict | None = None,
    records: dict | None = None,
    limit: int = DEFAULT_PIPELINE_LIMIT,
    now: str | None = None,
) -> dict:
    """Idempotently materialize the priority queue into research jobs."""

    if payload is None:
        candidates = load_priority_candidates(
            program, records=records, limit=limit, now=now
        )
    else:
        candidates = candidates_from_payload(payload, limit=limit)

    with _PIPELINE_LOCK:
        before = {job.id for job in _STORE.all_jobs()}
        outcomes = _ORCHESTRATOR.dispatch_many(candidates, now=now)
        created = [
            outcome.job.to_dict()
            for outcome in outcomes
            if outcome.job.id not in before
        ]
    return {
        "available": bool(candidates),
        "created": len(created),
        "jobs": [outcome.job.to_dict() for outcome in outcomes],
        "created_jobs": created,
    }


def create_jobs(
    candidates=None,
    *,
    program: str | None = None,
    payload: dict | None = None,
    records: dict | None = None,
    limit: int = DEFAULT_CANDIDATE_LIMIT,
    now: str | None = None,
) -> dict:
    """Create jobs from explicit candidates, a payload, or the live surface."""

    if candidates:
        items = list(candidates)
        with _PIPELINE_LOCK:
            before = {job.id for job in _STORE.all_jobs()}
            outcomes = _ORCHESTRATOR.dispatch_many(items, now=now)
            created = [
                outcome.job.to_dict()
                for outcome in outcomes
                if outcome.job.id not in before
            ]
        return {
            "available": True,
            "created": len(created),
            "jobs": [outcome.job.to_dict() for outcome in outcomes],
            "created_jobs": created,
        }
    return bootstrap_pipeline(
        program,
        payload=payload,
        records=records,
        limit=limit,
        now=now,
    )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def list_jobs() -> dict:
    jobs = [job.to_dict() for job in _STORE.all_jobs()]
    return {
        "available": bool(jobs),
        "counts": _STORE.counts(),
        "jobs": jobs,
    }


def list_results() -> dict:
    results = [res.to_dict() for res in _STORE.all_results()]
    return {"count": len(results), "results": results}


def get_job(job_id: object) -> dict | None:
    job = _STORE.get_job(job_id)
    if job is None:
        return None
    result = _STORE.get_result(job.id)
    return {
        "job": job.to_dict(),
        "result": result.to_dict() if result else None,
    }


# ---------------------------------------------------------------------------
# Command Center payload
# ---------------------------------------------------------------------------


def command_center_payload(
    program: str | None = None,
    *,
    payload: dict | None = None,
    records: dict | None = None,
    limit: int = DEFAULT_PIPELINE_LIMIT,
    now: str | None = None,
) -> dict:
    """The ``RESEARCH AGENTS`` section payload.

    Materializes a bounded, idempotent set of research jobs from the Attack
    Surface priority queue so the orchestration flow is visible, then returns
    the agent status and the current job queue.
    """

    surface = _surface_payload(program, payload=payload, records=records)
    bootstrap_pipeline(
        program, payload=surface, limit=limit, now=now
    )
    agents = agents_payload(program, payload=surface)
    jobs = [job.to_dict() for job in _STORE.all_jobs()]
    counts = _STORE.counts()
    return {
        "available": bool(surface.get("available")) or bool(jobs),
        "agents": agents["agents"],
        "agent_count": agents["count"],
        "queue": jobs[:50],
        "queue_count": len(jobs),
        "counts": counts,
        "rule_version": "research-agents-1",
    }


def reset_pipeline() -> None:
    """Test helper: clear the in-memory job/result store (no persistence)."""

    _STORE.clear()


__all__ = [
    "DEFAULT_PIPELINE_LIMIT",
    "AGENT_TO_CANDIDATE_CATEGORY",
    "registry",
    "store",
    "orchestrator",
    "agents_payload",
    "bootstrap_pipeline",
    "create_jobs",
    "list_jobs",
    "list_results",
    "get_job",
    "command_center_payload",
    "reset_pipeline",
]
