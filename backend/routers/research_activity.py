"""backend/routers/research_activity.py — Stage R83 AI activity status API.

Read-only bounded AI runtime status for the researcher dashboard:

    GET /api/research/activity

Facts come from the existing persisted agent run records, research case
artifacts, the scheduler lock liveness probe and the scheduler window policy
(``backend.research_activity``). Nothing is started, stopped, mutated or
executed; the endpoint never returns prompts, model output, URLs, credentials
or stack traces. It is fail-soft: an unexpected collector failure returns a
bounded ``UNKNOWN`` contract instead of a 500 with internals.

Registered before the generic ``/api/research/{cve}`` route so the path is
matched by this specific router.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ai.knowledge.ai_activity_status import (
    LOCK_UNAVAILABLE,
    build_activity_status,
)
from backend import research_activity
from backend.deps import verify_api_key

router = APIRouter()

_AUTH = [Depends(verify_api_key)]


@router.get("/api/research/activity", dependencies=_AUTH)
def get_research_activity():
    """Bounded, real AI activity / runtime status."""

    try:
        return research_activity.collect_activity()
    except Exception as exc:
        return build_activity_status(
            lock_state=LOCK_UNAVAILABLE,
            source_errors=[f"collector_{type(exc).__name__}"],
        )
