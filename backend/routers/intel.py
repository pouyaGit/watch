"""backend/routers/intel.py — Production Intelligence read API.

Stable JSON endpoints for the Epic8 intelligence layer. Authentication
is the existing global API-key middleware (same as every other Watch
route — nothing here exempts itself); documentation flows through the
app's OpenAPI schema.

Mounted WITHOUT touching ``api.py`` (which carries an uncommitted
operator edit in production): ``backend/routers/soc.py`` includes this
router into the already-mounted SOC router.

One authoritative projection (``backend.prod_intel.*``) feeds these
endpoints AND the AI SOC UI templates — no duplicated business logic.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()


def _window(hours: float | None) -> float | None:
    return hours


@router.get("/api/intel/overview")
def intel_overview(
    hours: float | None = Query(
        default=168.0, ge=0.0, le=2160.0,
        description="rolling window hours (max 90 days); "
                    "omit for all history")) -> dict[str, Any]:
    """Production intelligence overview (agents/campaigns/hunts/findings/
    cases by family/handoff/activity/blockers/current state)."""
    from backend.prod_intel.overview import overview
    return overview(hours=hours)


@router.get("/api/intel/targets")
def intel_targets(
    hours: float | None = Query(default=168.0, ge=0.0, le=2160.0)
) -> dict[str, Any]:
    """Every target discovered from persisted records, with lineage."""
    from backend.prod_intel.targets import target_intelligence
    return target_intelligence(hours=hours)


@router.get("/api/intel/targets/{target}")
def intel_target(
    target: str,
    hours: float | None = Query(default=168.0, ge=0.0, le=2160.0),
) -> dict[str, Any]:
    """One target's full intelligence bundle. 404 when the target is not
    present in any persisted record (never an invented empty profile)."""
    from backend.prod_intel.targets import (
        discover_targets, target_detail)
    disc = discover_targets()
    known = any(s["target"] == target.lower() for s in disc["targets"])
    if not known:
        raise HTTPException(
            status_code=404,
            detail=f"target {target!r} not present in any persisted "
                   f"record")
    return target_detail(target.lower(), disc=disc)


@router.get("/api/intel/agents")
def intel_agents(
    hours: float | None = Query(default=168.0, ge=0.0, le=2160.0)
) -> dict[str, Any]:
    """Per-specialist intelligence over every registered capability."""
    from backend.prod_intel.agents_intel import agent_intelligence
    return agent_intelligence(hours=hours)


@router.get("/api/intel/agents/{category}")
def intel_agent(
    category: str,
    hours: float | None = Query(default=168.0, ge=0.0, le=2160.0),
) -> dict[str, Any]:
    """One specialist (category, slug or agent name). 404 when unknown."""
    from backend.prod_intel.agents_intel import agent_detail
    from backend.prod_intel.agents_intel import registered_agents
    reg = registered_agents()
    if reg["state"] != "ok":
        raise HTTPException(status_code=503,
                            detail="capability registry unavailable")
    needle = category.lower().replace("-", "_")
    match = next((a for a in reg["agents"]
                  if a["category"].lower() == needle
                  or a["slug"].lower() == category.lower()
                  or a["agent"].lower() == category.lower()), None)
    if match is None:
        raise HTTPException(
            status_code=404, detail=f"specialist {category!r} is not "
                                    f"registered")
    return agent_detail(match["category"])


@router.get("/api/intel/activity")
def intel_activity(
    hours: float | None = Query(default=168.0, ge=0.0, le=2160.0),
    limit: int = Query(default=60, ge=1, le=200),
) -> dict[str, Any]:
    """Meaningful-activity feed (documented taxonomy, newest first)."""
    from backend.prod_intel.activity import build_feed
    return build_feed(hours=hours, limit=limit)


@router.get("/api/intel/now")
def intel_now() -> dict[str, Any]:
    """What the system is doing right now (UNKNOWN preferred to fake)."""
    from backend.prod_intel.activity import current_activity
    return current_activity()


@router.get("/api/intel/hunt-effectiveness")
def intel_hunt_effectiveness(
    hours: float | None = Query(default=168.0, ge=0.0, le=2160.0)
) -> dict[str, Any]:
    """Descriptive funnels with explicit denominators — never rankings."""
    from backend.prod_intel.effectiveness import effectiveness
    return effectiveness(hours=hours)


@router.get("/api/intel/learning")
def intel_learning(
    hours: float | None = Query(default=168.0, ge=0.0, le=2160.0)
) -> dict[str, Any]:
    """Recurring research learning signals (derived, capped at INFERRED)."""
    from backend.prod_intel.learning_signals import learning_signals
    return learning_signals(hours=hours)


@router.get("/api/intel/cases/{case_id}")
def intel_case(case_id: str) -> dict[str, Any]:
    """Complete analyst case package (fcase-* or runtime case-*).
    404 when the id matches no persisted case."""
    from backend.prod_intel.case_intel import case_intelligence
    pkg = case_intelligence(case_id)
    if not pkg.get("found"):
        if pkg.get("state") == "unavailable":
            return pkg                      # source outage: honest envelope
        raise HTTPException(
            status_code=404,
            detail=str(pkg.get("reason") or "case not found"))
    return pkg


@router.get("/api/intel/knowledge-usage")
def intel_knowledge_usage(
    hours: float | None = Query(default=None, ge=0.0, le=2160.0),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Actual knowledge usage (paginated) + availability rollups."""
    from backend.prod_intel.knowledge_usage import knowledge_usage
    return knowledge_usage(hours=hours, limit=limit, offset=offset)


@router.get("/api/intel/handoff")
def intel_handoff() -> dict[str, Any]:
    """Handoff intelligence — the SAME projection the Handoff UI renders
    (backend.soc.handoff), returned as JSON for external consumers."""
    try:
        from backend.soc import handoff as soc_handoff
        idx = soc_handoff.handoff_index()
        rows = idx.get("reports") or []
        return {
            "count": len(rows),
            "reports": rows,
            "semantics": "read-only handoff rows across families; status "
                         "is the persisted case/report state",
            "state": "ok",
        }
    except Exception as exc:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=503,
            detail=f"handoff source unavailable: {type(exc).__name__}"
        ) from None


@router.get("/api/intel/ai-ops")
def intel_ai_ops() -> dict[str, Any]:
    """EPIC9: AI Operations window / operations state / process liveness
    as three separate read-only facts. Global API-key auth (shared app
    gate) — nothing here exempts itself. Worker PROCESS state and AI
    OPERATIONS state are deliberately distinct: an idle operations state
    with no live worker process is the normal healthy condition between
    bounded ticks, not an error."""
    try:
        from backend.ai_ops.state import panel
        return panel()
    except Exception as exc:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=503,
            detail=f"ai-ops source unavailable: {type(exc).__name__}"
        ) from None
