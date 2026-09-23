"""
backend/routers/soc.py — AI Security Operations Center UI routes (SOC-1..5).

GET-only server-rendered pages under /ui/soc/.  Every handler is a thin
projection over ``backend.soc`` adapters — no business logic lives here,
nothing mutates, and authentication stays on the global API-key gate
(same as the rest of the Watch UI; no auth changes in this module).

Mounting is the operator's step (identical to the AEC router): this
router is inert until ``app.include_router(soc_router.router)`` is added
to api.py.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

# Epic8: mount the Production Intelligence JSON API inside the already-
# mounted SOC router so api.py (which carries an uncommitted operator
# edit in production) never has to change. Auth stays on the global
# API-key gate (handled by the shared app layer); routes appear in the
# app OpenAPI schema.
from backend.routers.intel import router as _intel_router  # noqa: E402

router.include_router(_intel_router)

_templates = Jinja2Templates(directory=str(
    __import__("pathlib").Path(__file__).resolve().parents[2] / "web" / "templates"  # noqa: E501
))


def _ctx(request: Request, **extra) -> dict:
    """Common context: api_key propagation + nav markers (base.html)."""
    from backend.soc._util import _text

    base = {
        "request": request,
        "api_key_qs": _text(request.query_params.get("api_key")),
        "active": "",
        "title": "AI SOC",
    }
    base.update(extra)
    return base


@router.get("/ui/soc/", response_class=HTMLResponse)
def ui_soc_overview(request: Request):
    from backend.soc import overview as soc_overview

    payload = soc_overview.overview_payload()
    # Epic8: same authoritative projection as /api/intel/overview
    try:
        from backend.prod_intel.overview import overview as pi_overview
        payload["intel"] = pi_overview()
    except Exception as exc:                     # honest degrade, no crash
        payload["intel"] = {"state": "unavailable",
                            "reason": f"{type(exc).__name__}"}
    return _templates.TemplateResponse(
        request, "soc/home.html", _ctx(
            request, **payload, active="soc-overview"))


@router.get("/ui/soc/agents", response_class=HTMLResponse)
def ui_soc_agents(request: Request):
    from backend.soc import agents as soc_agents

    payload = soc_agents.agents_index()
    return _templates.TemplateResponse(
        request, "soc/agents.html", _ctx(
            request, **payload, active="soc-agents"))


@router.get("/ui/soc/agents/{slug}", response_class=HTMLResponse)
def ui_soc_agent_detail(request: Request, slug: str):
    from backend.soc import agents as soc_agents

    detail = soc_agents.agent_detail(slug)
    if detail is None:
        from fastapi.responses import HTMLResponse as HR

        return HR(
            "<h1>Agent not found</h1><p>No agent matches "
            f"{slug!r}.</p>", status_code=404)
    # Epic8: same authoritative projection as /api/intel/agents/{slug}
    try:
        from backend.prod_intel.agents_intel import (
            agent_detail as pi_agent_detail)
        detail["intel"] = pi_agent_detail(slug)
    except Exception as exc:
        detail["intel"] = {"state": "unavailable",
                           "reason": f"{type(exc).__name__}"}
    return _templates.TemplateResponse(
        request, "soc/agent_detail.html", _ctx(
            request, **detail, active="soc-agents"))


@router.get("/ui/soc/cases", response_class=HTMLResponse)
def ui_soc_cases(request: Request):
    from backend.soc import cases as soc_cases

    payload = soc_cases.cases_index()
    return _templates.TemplateResponse(
        request, "soc/cases.html", _ctx(
            request, **payload, active="soc-cases"))


@router.get("/ui/soc/cases/{case_id}", response_class=HTMLResponse)
def ui_soc_case_detail(request: Request, case_id: str):
    from backend.soc import cases as soc_cases

    detail = soc_cases.case_detail(case_id)
    if detail is None:
        from fastapi.responses import HTMLResponse as HR

        return HR(
            "<h1>Case not found</h1><p>No case matches "
            f"{case_id!r}.</p>", status_code=404)
    # Epic8: complete analyst package (same projection as
    # /api/intel/cases/{id}); absent package renders the honest reason
    try:
        from backend.prod_intel.case_intel import case_intelligence
        detail["case_intel"] = case_intelligence(case_id)
    except Exception as exc:
        detail["case_intel"] = {"found": False, "state": "unavailable",
                                "reason": f"{type(exc).__name__}"}
    return _templates.TemplateResponse(
        request, "soc/case_detail.html", _ctx(
            request, **detail, active="soc-cases"))


@router.get("/ui/soc/activity", response_class=HTMLResponse)
def ui_soc_activity(request: Request):
    from backend.soc import activity as soc_activity

    payload = soc_activity.activity_payload()
    # Epic8: same authoritative projections as /api/intel/activity|now
    try:
        from backend.prod_intel.activity import (
            build_feed, current_activity)
        payload["intel_feed"] = build_feed(hours=168.0, limit=40)
        payload["intel_now"] = current_activity()
    except Exception as exc:
        payload["intel_feed"] = {"state": "unavailable",
                                 "reason": f"{type(exc).__name__}",
                                 "value": [], "categories": []}
        payload["intel_now"] = {"state": "UNKNOWN",
                                "basis": f"{type(exc).__name__}",
                                "running_jobs": [], "worker": {}}
    return _templates.TemplateResponse(
        request, "soc/activity.html", _ctx(
            request, **payload, active="soc-activity"))


@router.get("/ui/soc/campaigns", response_class=HTMLResponse)
def ui_soc_campaigns(request: Request):
    from backend.soc import campaigns as soc_campaigns

    payload = soc_campaigns.campaigns_index()
    return _templates.TemplateResponse(
        request, "soc/campaigns.html", _ctx(
            request, **payload, active="soc-campaigns"))


@router.get("/ui/soc/campaigns/{campaign_id}", response_class=HTMLResponse)
def ui_soc_campaign_detail(request: Request, campaign_id: str):
    from backend.soc import campaigns as soc_campaigns

    detail = soc_campaigns.campaign_detail(campaign_id)
    if detail is None:
        from fastapi.responses import HTMLResponse as HR
        return HR(
            "<h1>Campaign not found</h1><p>No campaign matches "
            f"{campaign_id!r}.</p>", status_code=404)
    return _templates.TemplateResponse(
        request, "soc/campaign_detail.html", _ctx(
            request, **detail, active="soc-campaigns"))


@router.get("/ui/soc/campaigns/{campaign_id}/objectives/{objective_id}",
            response_class=HTMLResponse)
def ui_soc_campaign_objective(request: Request, campaign_id: str,
                              objective_id: str):
    from backend.soc import campaigns as soc_campaigns

    detail = soc_campaigns.objective_detail(campaign_id, objective_id)
    if detail is None:
        from fastapi.responses import HTMLResponse as HR
        return HR(
            "<h1>Objective not found</h1><p>No objective matches "
            f"{objective_id!r}.</p>", status_code=404)
    return _templates.TemplateResponse(
        request, "soc/campaign_objective.html", _ctx(
            request, **detail, active="soc-campaigns"))


@router.get("/ui/soc/findings", response_class=HTMLResponse)
def ui_soc_findings(request: Request):
    from backend.soc import findings as soc_findings

    payload = soc_findings.findings_index()
    return _templates.TemplateResponse(
        request, "soc/findings.html", _ctx(
            request, **payload, active="soc-findings"))


@router.get("/ui/soc/findings/{candidate_id}", response_class=HTMLResponse)
def ui_soc_finding_detail(request: Request, candidate_id: str):
    from backend.soc import findings as soc_findings

    detail = soc_findings.finding_detail(candidate_id)
    if detail is None:
        from fastapi.responses import HTMLResponse as HR

        return HR(
            "<h1>Candidate not found</h1><p>No candidate matches "
            f"{candidate_id!r}.</p>", status_code=404)
    # Epic8: full analyst package for the finding-family case
    try:
        fcid = str(detail.get("finding_case_id")
                   or (detail.get("gate") or {}).get("finding_case_id")
                   or (detail.get("case") or {}).get("case_id")
                   or "")
        if fcid:
            from backend.prod_intel.case_intel import case_intelligence
            detail["case_intel"] = case_intelligence(fcid)
    except Exception as exc:
        detail["case_intel"] = {"found": False, "state": "unavailable",
                                "reason": f"{type(exc).__name__}"}
    return _templates.TemplateResponse(
        request, "soc/finding_detail.html", _ctx(
            request, **detail, active="soc-findings"))


@router.get("/ui/soc/targets", response_class=HTMLResponse)
def ui_soc_targets(request: Request):
    # Epic8: same authoritative projection as /api/intel/targets
    hours_raw = request.query_params.get("hours")
    try:
        hours = float(hours_raw) if hours_raw not in (None, "") else 168.0
    except (TypeError, ValueError):
        hours = 168.0
    from backend.prod_intel.targets import target_intelligence
    payload = target_intelligence(hours=hours)
    payload["hours"] = hours
    return _templates.TemplateResponse(
        request, "soc/targets.html", _ctx(
            request, **payload, active="soc-targets"))


@router.get("/ui/soc/handoff", response_class=HTMLResponse)
def ui_soc_handoff(request: Request):
    from backend.soc import handoff as soc_handoff

    payload = soc_handoff.handoff_index()
    return _templates.TemplateResponse(
        request, "soc/handoff.html", _ctx(
            request, **payload, active="soc-handoff"))


@router.get("/ui/soc/handoff/{job_id}", response_class=HTMLResponse)
def ui_soc_handoff_detail(request: Request, job_id: str):
    from backend.soc import handoff as soc_handoff

    detail = soc_handoff.handoff_detail(job_id)
    if detail is None:
        from fastapi.responses import HTMLResponse as HR

        return HR(
            "<h1>Handoff not found</h1><p>No report matches "
            f"{job_id!r}.</p>", status_code=404)
    return _templates.TemplateResponse(
        request, "soc/handoff_detail.html", _ctx(
            request, **detail, active="soc-handoff"))