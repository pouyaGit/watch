"""backend/routers/research_agents.py — Research Agent Orchestration API (v1).

    GET  /api/research-agents          -- available specialist agents + queue
    GET  /api/research/jobs            -- research job queue
    POST /api/research/jobs/create     -- create jobs from attack-surface candidates
    GET  /api/research/jobs/{id}       -- investigation state (job + evidence plan)

Read-only in spirit: jobs are investigation plans held in an in-memory store.
No exploitation, no target interaction, no production database writes.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.deps import verify_api_key
from backend.research_agents import service as ra

router = APIRouter()

_AUTH = [Depends(verify_api_key)]


class JobCreateRequest(BaseModel):
    """Optional POST body for job creation."""

    program: Optional[str] = None
    limit: int = 20
    candidates: Optional[List[dict]] = None


@router.get("/api/research-agents", dependencies=_AUTH)
def api_research_agents(program: Optional[str] = None):
    """Available specialist agents, their status and candidate queue."""

    return ra.agents_payload(program)


@router.get("/api/research/jobs", dependencies=_AUTH)
def api_research_jobs():
    """The current research job queue (in-memory investigation plans)."""

    return ra.list_jobs()


@router.post("/api/research/jobs/create", dependencies=_AUTH)
def api_research_jobs_create(body: JobCreateRequest | None = None):
    """Create research jobs from attack-surface candidates.

    With no body, a bounded, idempotent set of the highest-priority candidates
    is materialized. An explicit ``candidates`` list may be supplied instead.
    """

    program = body.program if body is not None else None
    limit = body.limit if body is not None else 20
    candidates = body.candidates if body is not None else None
    return ra.create_jobs(candidates, program=program, limit=limit)


@router.get("/api/research/jobs/{job_id}", dependencies=_AUTH)
def api_research_job(job_id: str):
    """Investigation state for one job (job + agent evidence plan)."""

    data = ra.get_job(job_id)
    if data is None:
        raise HTTPException(status_code=404, detail="unknown research job")
    return data
