"""
backend/routers/research.py — Stage D2 read-only research API.

Exposes already-persisted research/KB/XSS/report artifacts as compact,
key-gated JSON. READ-ONLY by construction:

- no writes (no KB mutation, no Mongo writes)
- no subprocess, no network, no LLM, no Nuclei execution
- no production verifier / live validation
- Markdown is returned raw (never rendered to HTML, never |safe)

All routes are behind ``verify_api_key`` (same dependency as the
existing routers) and the global APIKeyMiddleware in api.py.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ai.knowledge.task_store import (
    StaleTaskError,
    TaskNotFound,
    TaskStoreError,
    TaskValidationError,
)
from backend import research_tasks
from backend.deps import verify_api_key
from backend.research_data import (
    NotFoundError,
    ResearchDataError,
    cve_relevance,
    get_kb,
    get_overview,
    get_report,
    get_research,
    get_xss,
    get_xss_llm_research,
    list_kb,
    list_reports,
    list_research,
    list_research_queue,
    list_xss,
)

router = APIRouter()

_AUTH = [Depends(verify_api_key)]


def _bad(exc: ResearchDataError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _task_error(exc: TaskStoreError) -> HTTPException:
    """Map research-workflow store errors onto HTTP status codes."""

    if isinstance(exc, StaleTaskError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, TaskNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, TaskValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class ResearchTaskCreate(BaseModel):
    """Validated task-create payload (bounded; no arbitrary paths)."""

    cve: str
    program: str
    queue_id: str
    title: str | None = None
    notes: str | None = None
    references: list[str] | None = None


class ResearchTaskPatch(BaseModel):
    """Validated task-update payload with optimistic-concurrency token."""

    expected_version: int
    status: str | None = None
    notes: str | None = None
    blocker: str | None = None
    result_summary: str | None = None
    references: list[str] | None = None


# ---------------------------------------------------------------------------
# Research
# ---------------------------------------------------------------------------


@router.get("/api/research", dependencies=_AUTH)
def api_research_list(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    q: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    try:
        return list_research(limit=limit, offset=offset, q=q, cve=cve, severity=severity, status=status)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/overview", dependencies=_AUTH)
def api_research_overview():
    try:
        return get_overview()
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Research workflow tasks (Stage R20) — read/write, key-gated, local JSON only.
# Declared before /api/research/{cve} so "tasks" is not captured as a CVE.
# ---------------------------------------------------------------------------


@router.get("/api/research/tasks", dependencies=_AUTH)
def api_research_tasks(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    status: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
):
    try:
        return research_tasks.list_tasks(
            limit=limit, offset=offset, status=status, cve=cve
        )
    except TaskStoreError as exc:
        raise _task_error(exc)


@router.post("/api/research/tasks", dependencies=_AUTH, status_code=201)
def api_research_task_create(body: ResearchTaskCreate):
    try:
        task, created = research_tasks.create_task(
            cve=body.cve,
            program=body.program,
            queue_id=body.queue_id,
            title=body.title,
            notes=body.notes,
            references=body.references,
        )
    except TaskStoreError as exc:
        raise _task_error(exc)
    return {"created": created, "task": task.model_dump(mode="json")}


@router.get("/api/research/tasks/{task_id}", dependencies=_AUTH)
def api_research_task_detail(task_id: str):
    try:
        task = research_tasks.get_task(task_id)
    except TaskStoreError as exc:
        raise _task_error(exc)
    return task.model_dump(mode="json")


@router.patch("/api/research/tasks/{task_id}", dependencies=_AUTH)
def api_research_task_update(task_id: str, body: ResearchTaskPatch):
    try:
        task = research_tasks.update_task(
            task_id,
            expected_version=body.expected_version,
            status=body.status,
            notes=body.notes,
            blocker=body.blocker,
            result_summary=body.result_summary,
            references=body.references,
        )
    except TaskStoreError as exc:
        raise _task_error(exc)
    return task.model_dump(mode="json")


@router.get("/api/research/queue", dependencies=_AUTH)
def api_research_queue(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    cve: Optional[str] = Query(default=None),
):
    """Ranked R18 research queue (research planning only). Read-only."""

    try:
        return list_research_queue(limit=limit, offset=offset, cve=cve)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/queue/{cve}", dependencies=_AUTH)
def api_research_queue_cve(cve: str):
    """Ranked queue items for one CVE. Read-only."""

    try:
        return list_research_queue(limit=100, offset=0, cve=cve)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/{cve}", dependencies=_AUTH)
def api_research_detail(cve: str):
    try:
        return get_research(cve)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="research artifact not found")
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/{cve}/relevance", dependencies=_AUTH)
def api_research_relevance(cve: str):
    """R17 asset/program relevance for one CVE (research relevance only)."""

    try:
        return cve_relevance(cve)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="research artifact not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Knowledge base (read-only KnowledgeStore)
# ---------------------------------------------------------------------------


@router.get("/api/kb", dependencies=_AUTH)
def api_kb_list(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    q: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
):
    try:
        return list_kb(limit=limit, offset=offset, q=q, cve=cve, tag=tag)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/kb/{kid}", dependencies=_AUTH)
def api_kb_detail(kid: str):
    try:
        return get_kb(kid)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="knowledge document not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# XSS candidates (research candidates, NOT findings)
# ---------------------------------------------------------------------------


@router.get("/api/xss/candidates", dependencies=_AUTH)
def api_xss_list(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    status: Optional[str] = Query(default=None),
    type: Optional[str] = Query(default=None, alias="type"),
    context: Optional[str] = Query(default=None),
):
    try:
        return list_xss(limit=limit, offset=offset, status=status, xss_type=type, context=context)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/xss/candidates/{candidate_id}", dependencies=_AUTH)
def api_xss_detail(candidate_id: str):
    try:
        return get_xss(candidate_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="xss candidate not found")
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/xss/candidates/{candidate_id}/llm-research", dependencies=_AUTH)
def api_xss_llm_research(candidate_id: str):
    """Read-only R7 LLM research record (research commentary, not verified).

    Never invokes a provider; serves only the persisted JSON under
    ``ai_data/research/xss/llm/``. 404 when no research was generated.
    """
    try:
        return get_xss_llm_research(candidate_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="llm research not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Reports (raw Markdown)
# ---------------------------------------------------------------------------


@router.get("/api/reports", dependencies=_AUTH)
def api_reports_list(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    q: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
):
    try:
        return list_reports(limit=limit, offset=offset, q=q, cve=cve)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/reports/{cve}", dependencies=_AUTH)
def api_report_detail(cve: str):
    try:
        return get_report(cve)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="report not found")
    except ResearchDataError as exc:
        raise _bad(exc)
