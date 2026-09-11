"""backend/routers/product_api.py — Stage R28.1 product API contract.

Dedicated read-only v1 router exposing Watch research intelligence as
consumer-oriented ``ResearchOpportunityResponse`` records. READ-ONLY by
construction: GET only, key-gated, bounded, deterministic.

- No writes, no Mongo writes, no subprocess, no network, no LLM, no Nuclei
  execution, no target interaction, no findings, no alerts, no payouts.
- Errors use the deterministic v1 envelope
  ``{"api_version", "error": {"code", "message"}, "research_only"}`` with
  pre-sanitized static messages only — never stack traces, file paths,
  credentials, environment values, Mongo URIs or provider keys.
- Auth reuses the existing API-key dependency (same as all other routers);
  no second mechanism, no accounts, no OAuth.
- No rate-limit service; application-level bounds only (limit/offset/
  filters capped, no unbounded responses, no recursive or external calls).
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from ai.schemas.product_api import PRODUCT_API_VERSION, product_error
from backend.deps import verify_api_key
from backend.research_data import (
    NotFoundError,
    ResearchDataError,
)

router = APIRouter()

_AUTH = [Depends(verify_api_key)]

_NOT_FOUND_MESSAGE = "research opportunity not found"
_BAD_MESSAGE = "invalid request parameters"


@router.get(
    "/api/v1/opportunities",
    dependencies=_AUTH,
    summary="API v1 opportunities",
    description="Read-only research intelligence. Does not perform "
                "security testing.",
)
def api_v1_opportunities(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
    opportunity_class: Optional[str] = Query(default=None, alias="class"),
    action: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    min_money_score: int = Query(default=0),
):
    """Ranked v1 research opportunities (read-only, R26.2 ordering)."""
    from backend import product_api

    try:
        return product_api.list_product_opportunities(
            limit=limit,
            offset=offset,
            cve=cve,
            program=program,
            opportunity_class=opportunity_class,
            action=action,
            status=status,
            min_money_score=min_money_score,
        )
    except ResearchDataError:
        return JSONResponse(
            status_code=400,
            content=product_error("INVALID_REQUEST", _BAD_MESSAGE),
        )


@router.get(
    "/api/v1/opportunities/summary",
    dependencies=_AUTH,
    summary="API v1 opportunities summary",
    description="Read-only research intelligence. Does not perform "
                "security testing.",
)
def api_v1_opportunities_summary():
    """Compact v1 counts + top items (read-only)."""
    from backend import product_api

    return product_api.product_opportunity_summary()


@router.get(
    "/api/v1/opportunities/{lead_id}",
    dependencies=_AUTH,
    summary="API v1 opportunity detail",
    description="Read-only research intelligence. Does not perform "
                "security testing.",
)
def api_v1_opportunity_detail(lead_id: str):
    """One v1 research opportunity by deterministic lead id (read-only)."""
    from backend import product_api

    try:
        return product_api.get_product_opportunity(lead_id)
    except NotFoundError:
        return JSONResponse(
            status_code=404,
            content=product_error("NOT_FOUND", _NOT_FOUND_MESSAGE),
        )
    except ResearchDataError:
        return JSONResponse(
            status_code=400,
            content=product_error("INVALID_REQUEST", _BAD_MESSAGE),
        )


@router.get(
    "/api/v1/research/status",
    dependencies=_AUTH,
    summary="API v1 research status",
    description="Read-only research intelligence. Does not perform "
                "security testing.",
)
def api_v1_research_status():
    """High-level v1 system state (no secrets, no target data)."""
    from backend import product_api

    return product_api.product_research_status()
