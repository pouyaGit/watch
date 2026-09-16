"""backend/routers/research_cases.py — Stage R81 researcher API contract.

Researcher-facing interface over the existing research workflow. Interface
layer only: it delegates to the R81 service module, which in turn composes the
unchanged authorities.

    GET  /api/research/cases
        Bounded case summaries (no raw model output, no sensitive data).

    GET  /api/research/cases/{case_id}
        R77 workbench for one case (R77 remains the workbench authority).

    POST /api/research/cases/{case_id}/evidence
        R80 submission envelope; the URL case_id must match ``case_ref``.
        Delegates to R80 -> R74 -> R75 -> R76 -> R77. Fully in-memory: no
        Mongo writes and no persistence layer.

All routes are behind ``verify_api_key`` like the existing routers. R81 does
not invent authentication: it reuses the existing API-key gate.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from backend import research_cases
from backend.deps import verify_api_key

router = APIRouter()

_AUTH = [Depends(verify_api_key)]


class EvidenceSubmissionRequest(BaseModel):
    """R80 submission envelope (bounded; the item shape is R80's)."""

    model_config = ConfigDict(extra="allow")

    submission_version: str
    case_ref: str
    submitted_by: str = ""
    items: list[dict[str, Any]]


def _rejection(exc: research_cases.CaseServiceError) -> HTTPException:
    return HTTPException(
        status_code=exc.http_status,
        detail=f"{exc.code}: {exc.message}",
    )


@router.get("/api/research/cases", dependencies=_AUTH)
def list_research_cases():
    """Bounded list of research cases."""

    return research_cases.list_cases()


@router.get("/api/research/cases/{case_id}", dependencies=_AUTH)
def get_research_case(case_id: str):
    """R77 workbench for one research case."""

    detail = research_cases.get_case_workbench(case_id)
    if detail is None:
        raise HTTPException(
            status_code=404, detail="UNKNOWN_CASE: unknown case"
        )
    return detail


@router.post("/api/research/cases/{case_id}/evidence", dependencies=_AUTH)
def submit_research_case_evidence(
    case_id: str, body: EvidenceSubmissionRequest
):
    """Submit researcher evidence through the R80 boundary."""

    try:
        return research_cases.submit_case_evidence(
            case_id, body.model_dump()
        )
    except research_cases.CaseServiceError as exc:
        raise _rejection(exc) from None
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="INTERNAL_PROCESSING_FAILURE: internal processing failure",
        ) from None
