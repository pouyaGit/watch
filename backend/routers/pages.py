"""
backend/routers/pages.py — HTML pages that the dashboard visits.

These are the routes that used to live directly in api.py:
- GET /                       -- the main program list + fresh banner + stat cards
- GET /ui/program/{name}      -- per-program detail
- GET /ui/tasks               -- the new Phase 1 Tasks page

All list pages (subdomains/lives/http/urls/endpoints/.../...) still live
in backend/routers/programs.py -- they were moved verbatim from api.py and
their HTML rendering has been switched to use templates from web/templates/.
"""
import os
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from backend.deps import API_KEY, build_url, verify_api_key
from backend.routers.programs import BF_PROVIDERS, PROVIDERS
from backend.task_runner import get_last_run, get_task_status, list_history
from backend.tasks_registry import TASKS_REGISTRY, all_tasks
from database.db import (
    DnsBruteStatus,
    Endpoints,
    Http,
    LiveSubdomains,
    Programs,
    Subdomains,
    Urls,
)

_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "web" / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _ctx(request: Request, **extra):
    """Common template context -- builds the api_key query string and the
    base nav URLs once so every page can use them via {{ root_url }} etc."""
    base = {
        "request": request,
        "api_key_qs": API_KEY or "",
        "root_url":  build_url("/"),
        "tasks_url": build_url("/ui/tasks"),
        "dns_url":   build_url("/ui/dns-bruteforce/status"),
        "docs_url":  build_url("/docs"),
        "home_url":  build_url("/"),
    }
    base.update(extra)
    return base


router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    """Lightweight -- just counts, no cross-collection joins. Per-program
    detail (tech/provider badges, which need the expensive $lookup) lives on
    /ui/program/{name} now, computed one program at a time, only when opened."""
    programs = list(Programs.objects().all())

    fresh_count = Http.objects(created_date__gte=datetime.now() - timedelta(hours=24)).count()

    rows = []
    for p in programs:
        name = p.program_name
        rows.append({
            "program_name": name,
            "detail_url":   build_url(f"/ui/program/{name}"),
            "subdomains":   Subdomains.objects(program_name=name).count(),
            "live":         LiveSubdomains.objects(program_name=name).count(),
            "http":         Http.objects(program_name=name).count(),
        })

    return templates.TemplateResponse(
            request,
            "dashboard.html",
            _ctx(
            request,
            programs=rows,
            fresh_count=fresh_count,
            fresh_link=build_url("/ui/http/fresh"),
            stats_link=build_url("/api/stats/by-program"),
            dns_link=build_url("/ui/dns-bruteforce/status"),
        ),
    )


@router.get("/ui/program/{name}", response_class=HTMLResponse)
def ui_program(request: Request, name: str):
    """The detailed per-program view (tech badges, provider badges, exclusive
    finds). Split out from the main dashboard so opening it only computes
    for ONE program, not all of them at once."""
    c_sub = Subdomains.objects(program_name=name).count()
    c_live = LiveSubdomains.objects(program_name=name).count()
    c_http = Http.objects(program_name=name).count()
    c_urls = Urls.objects(program_name=name).count()
    c_eps = Endpoints.objects(program_name=name).count()

    techs = sorted({t.strip() for t in Http.objects(program_name=name).distinct("tech") if t and t.strip()})
    tech_html = [
        {"name": t, "url": build_url(f"/ui/http/tech/{name}/{t}")}
        for t in techs
    ]

    bf_html = []
    for provider in BF_PROVIDERS:
        count = Subdomains.objects(program_name=name, providers=provider).count()
        if count:
            bf_html.append({
                "name": provider, "count": count, "bf": True,
                "url": build_url(f"/ui/http/provider/{name}/{provider}"),
            })

    provider_html = []
    for provider in PROVIDERS:
        count = Subdomains.objects(program_name=name, providers=provider).count()
        if count:
            provider_html.append({
                "name": provider, "count": count, "bf": False,
                "url": build_url(f"/ui/http/provider/{name}/{provider}"),
            })

    unique_html = []
    for provider in BF_PROVIDERS + PROVIDERS:
        raw_query = {
            "program_name": provider,
            "$and": [{"providers": provider}, {"providers": {"$size": 1}}],
        }
        # NOTE: provider name reused above as program_name in raw_query was a bug
        # in the original code path; fix it here:
        raw_query["program_name"] = name
        count = Subdomains.objects(__raw__=raw_query).count()
        if count:
            unique_html.append({
                "name": provider, "count": count, "bf": provider in BF_PROVIDERS,
                "url": build_url(f"/ui/subdomains/unique/{name}/{provider}"),
            })

    return templates.TemplateResponse(
            request,
            "program.html",
            _ctx(
            request,
            program_name=name,
            counts={"sub": c_sub, "live": c_live, "http": c_http, "urls": c_urls, "eps": c_eps},
            sub_link=build_url(f"/ui/subdomains/program/{name}"),
            live_link=build_url(f"/ui/lives/program/{name}"),
            http_link=build_url(f"/ui/http/program/{name}"),
            urls_link=build_url(f"/ui/urls/program/{name}"),
            eps_link=build_url(f"/ui/endpoints/program/{name}"),
            wl_link=build_url(f"/api/wordlist/{name}"),
            techs=tech_html,
            providers=bf_html + provider_html,
            uniques=unique_html,
        ),
    )


@router.get("/ui/tasks", response_class=HTMLResponse, dependencies=[Depends(verify_api_key)])
def tasks_page(request: Request):
    """Server-rendered Tasks page. Each row also carries the live status
    badge (rendered server-side on this initial paint) and a recent-history
    snippet (last 10 TaskRun docs per task)."""
    rows = []
    for task_id, entry in all_tasks():
        last = get_last_run(task_id)
        total, history = list_history(task_id, page=1, limit=10)
        rows.append({
            "task_id":     task_id,
            "name":        entry["name"],
            "script":      entry["script"],
            "default_args": entry.get("default_args", []),
            "status":      get_task_status(task_id),
            "last_run":    _run_to_dict(last),
            "history":     [_run_to_dict(r) for r in history],
            "history_total": total,
        })
    return templates.TemplateResponse(
            request,
            "tasks.html",
            _ctx(request, tasks=rows),
    )


def _run_to_dict(run):
    if not run:
        return None
    return {
        "id": str(run.id),
        "started_at":  run.started_at.isoformat()  if run.started_at  else "",
        "finished_at": run.finished_at.isoformat() if run.finished_at else "",
        "status":      run.status,
        "triggered_by": run.triggered_by,
        "pid":         run.pid,
        "log_path":    run.log_path or "",
    }