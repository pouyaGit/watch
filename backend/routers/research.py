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

from backend.deps import verify_api_key
from backend.research_data import (
    NotFoundError,
    ResearchDataError,
    get_kb,
    get_overview,
    get_report,
    get_research,
    get_xss,
    get_xss_llm_research,
    list_kb,
    list_reports,
    list_research,
    list_xss,
)

router = APIRouter()

_AUTH = [Depends(verify_api_key)]


def _bad(exc: ResearchDataError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


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


@router.get("/api/research/{cve}", dependencies=_AUTH)
def api_research_detail(cve: str):
    try:
        return get_research(cve)
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
