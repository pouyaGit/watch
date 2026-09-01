"""
backend/routers/pages.py — HTML pages for the dashboard.

Routes (all pre-existing paths preserved):
- GET /                      -- dashboard: stats, latest runs, recent changes, programs
- GET /ui/programs           -- sortable/filterable/searchable programs table
- GET /ui/program/{name}     -- per-program recon overview
- GET /ui/tasks              -- task runner page (status badges + history)
- GET /ui/changes            -- recent change events (title/cdn/status/ip/tech)
- GET /ui/search             -- global search across programs/domains/endpoints/urls

Data-heavy per-program aggregation moved into backend/dashboard.py so the
dashboard runs a handful of MongoDB aggregations instead of per-program
.count() loops.
"""
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from backend import dashboard as dash
from backend.deps import API_KEY, build_url, verify_api_key
from backend.templating import templates
from backend.tz import fmt_ago, fmt_duration, fmt_tehran
from backend.routers.programs import BF_PROVIDERS, PROVIDERS
from backend.task_runner import get_last_run, get_task_status, list_history
from backend.tasks_registry import all_tasks
from database.change_events import ChangeEvent
from database.db import Endpoints, Http, LiveSubdomains, Subdomains, Urls

router = APIRouter()


def _ctx(request: Request, **extra):
    """Common template context -- sidebar/topbar nav links, api key
    propagation and the active-nav marker for base.html."""
    base = {
        "request": request,
        "api_key_qs": API_KEY or "",
        "root_url":    build_url("/"),
        "home_url":    build_url("/"),
        "tasks_url":   build_url("/ui/tasks"),
        "runs_url":    build_url("/ui/runs"),
        "changes_url": build_url("/ui/changes"),
        "domains_url": build_url("/ui/domains"),
        "http_url":    build_url("/ui/http"),
        "urls_url":    build_url("/ui/urls"),
        "endpoints_url": build_url("/ui/endpoints"),
        "parameters_url": build_url("/ui/parameters"),
        "search_url":  build_url("/ui/search"),
        "programs_url": build_url("/ui/programs"),
        "dns_url":     build_url("/ui/dns-bruteforce/status"),
        "docs_url":    build_url("/docs"),
        "stats_link":  build_url("/api/stats/by-program"),
        "fresh_link":  build_url("/ui/http/fresh"),
    }
    base.update(extra)
    return base


def _program_link(name: str) -> str:
    return build_url(f"/ui/program/{name}")


# ----------------------------- dashboard -----------------------------
@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    stats = dash.global_counts()
    rows = dash.program_rows(sort="updated", direction="desc")[:12]
    for r in rows:
        r["detail_url"] = build_url(f"/ui/program/{r['program_name']}")
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        _ctx(
            request,
            active="dashboard",
            page_title="Dashboard",
            stats=stats,
            latest_runs=dash.latest_runs(),
            changes=dash.recent_changes(limit=12),
            activity_summary=dash.activity_summary(),
            programs=rows,
            fresh_count=stats.get("fresh_http_24h", 0),
        ),
    )


# ----------------------------- programs table -----------------------------
@router.get("/ui/programs", response_class=HTMLResponse)
def programs_table(request: Request, sort: str = "name", direction: str = "asc",
                   mode: str = "all", q: Optional[str] = None,
                   page: int = 1, limit: int = 50):
    limit = min(max(limit, 10), 200)
    page = max(page, 1)
    rows = dash.program_rows(sort=sort, direction=direction, mode=mode)
    rows = dash.search_program_rows(rows, q)
    total = len(rows)
    total_pages = max(1, (total + limit - 1) // limit)
    page = min(page, total_pages)
    rows = rows[(page - 1) * limit: page * limit]
    for r in rows:
        r["detail_url"] = build_url(f"/ui/program/{r['program_name']}")
    return templates.TemplateResponse(
        request,
        "programs.html",
        _ctx(
            request,
            active="programs",
            page_title="Programs",
            programs=rows,
            sort=sort,
            direction=direction,
            mode=mode,
            q=q or "",
            page=page,
            limit=limit,
            total=total,
            total_pages=total_pages,
            prev_url=build_url("/ui/programs", q=q, sort=sort, direction=direction,
                               mode=mode, page=page - 1, limit=limit) if page > 1 else None,
            next_url=build_url("/ui/programs", q=q, sort=sort, direction=direction,
                               mode=mode, page=page + 1, limit=limit) if page < total_pages else None,
        ),
    )


# ----------------------------- global search -----------------------------
@router.get("/ui/search", response_class=HTMLResponse)
def ui_search(request: Request, q: Optional[str] = None):
    """Global recon search: programs, live domains, endpoints, URLs.

    Every result set is capped server-side (no unbounded collections). Each
    section links to the full, filterable listing for that asset type."""
    q = (q or "").strip()
    results = {"programs": [], "domains": [], "endpoints": [], "urls": []}
    if q:
        ql = q.lower()
        for r in dash.search_program_rows(dash.program_rows(sort="name"), ql)[:12]:
            r["detail_url"] = build_url(f"/ui/program/{r['program_name']}")
            results["programs"].append(r)
        for s in LiveSubdomains.objects(subdomain__icontains=q).order_by("-last_update").only(
                "subdomain", "program_name")[:15]:
            results["domains"].append({
                "subdomain": s.subdomain,
                "program_name": s.program_name,
                "url": f"https://{s.subdomain}",
            })
        for e in Endpoints.objects(path__icontains=q).order_by("-hit_count").only(
                "path", "program_name", "subdomain", "hit_count")[:15]:
            results["endpoints"].append({
                "path": e.path,
                "program_name": e.program_name,
                "subdomain": e.subdomain,
                "hit_count": e.hit_count,
            })
        for u in Urls.objects(url__icontains=q).only("url", "program_name")[:15]:
            results["urls"].append({"url": u.url, "program_name": u.program_name})
    return templates.TemplateResponse(
        request,
        "search.html",
        _ctx(
            request,
            active="search",
            page_title="Search",
            q=q,
            results=results,
            full_domains=build_url("/ui/domains", q=q) if q else None,
            full_urls=build_url("/ui/urls", q=q) if q else None,
            full_endpoints=build_url("/ui/endpoints", q=q) if q else None,
            full_programs=build_url("/ui/programs", q=q) if q else None,
        ),
    )


# ----------------------------- program detail -----------------------------
@router.get("/ui/program/{name}", response_class=HTMLResponse)
def ui_program(request: Request, name: str):
    """Per-program recon overview: stats, live-domain preview, HTTP
    intelligence, recent changes and recon activity."""
    summary = dash.program_summary(name)

    # Live domains preview (10 newest, joined with Http for status/title/tech)
    live_rows = list(
        LiveSubdomains.objects(program_name=name)
        .order_by("-last_update")
        .only("subdomain", "cdn", "ips", "last_update")[:10]
    )
    names = [s.subdomain for s in live_rows]
    http_map = {}
    if names:
        for h in Http.objects(program_name=name, subdomain__in=names).only(
                "subdomain", "status_code", "title", "tech", "url", "last_update"):
            if h.subdomain not in http_map:
                http_map[h.subdomain] = h

    domains = []
    for s in live_rows:
        h = http_map.get(s.subdomain)
        domains.append({
            "subdomain": s.subdomain,
            "url": (h.url if h and h.url else f"https://{s.subdomain}"),
            "status_code": h.status_code if h else None,
            "title": (h.title or "") if h else "",
            "tech": ", ".join((h.tech or [])[:4]) if h else "",
            "cdn": s.cdn or "Normal",
            "ips": ", ".join((s.ips or [])[:2]) if s.ips else "",
            "last_update": s.last_update,
            "ago": fmt_ago(s.last_update),
        })

    techs = sorted({
        t.strip() for t in Http.objects(program_name=name).distinct("tech")
        if t and t.strip()
    })
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

    return templates.TemplateResponse(
        request,
        "program.html",
        _ctx(
            request,
            active="programs",
            page_title=name,
            program_name=name,
            summary=summary,
            domains=domains,
            changes=dash.recent_changes(limit=15, program_name=name),
            sub_link=build_url(f"/ui/subdomains/program/{name}"),
            live_link=build_url(f"/ui/lives/program/{name}"),
            http_link=build_url(f"/ui/http/program/{name}"),
            urls_link=build_url(f"/ui/urls/program/{name}"),
            eps_link=build_url(f"/ui/endpoints/program/{name}"),
            all_live_link=build_url(f"/ui/domains", program=name),
            wl_link=build_url(f"/api/wordlist/{name}"),
            techs=tech_html,
            providers=bf_html + provider_html,
        ),
    )


# ----------------------------- recent changes -----------------------------
@router.get("/ui/changes", response_class=HTMLResponse)
def ui_changes(request: Request, page: int = 1, limit: int = 50):
    limit = min(max(limit, 10), 200)
    page = max(page, 1)
    qs = ChangeEvent.objects().order_by("-created_date")
    total = qs.count()
    events = [e.as_dict() for e in qs.skip((page - 1) * limit).limit(limit)]
    for e in events:
        e["program_url"] = build_url(f"/ui/program/{e['program_name']}")
    total_pages = max(1, (total + limit - 1) // limit)
    return templates.TemplateResponse(
        request,
        "changes.html",
        _ctx(
            request,
            active="changes",
            page_title="Recent Changes",
            changes=events,
            page=page,
            limit=limit,
            total=total,
            total_pages=total_pages,
            prev_url=build_url("/ui/changes", page=page - 1, limit=limit) if page > 1 else None,
            next_url=build_url("/ui/changes", page=page + 1, limit=limit) if page < total_pages else None,
        ),
    )


# ----------------------------- tasks -----------------------------
@router.get("/ui/tasks", response_class=HTMLResponse, dependencies=[Depends(verify_api_key)])
def tasks_page(request: Request):
    """Server-rendered Tasks page with live status badges and recent
    history (duration computed here, Tehran timestamps via filters)."""
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
            "last_run":    _run_row(last),
            "history":     [_run_row(r) for r in history],
            "history_total": total,
        })
    return templates.TemplateResponse(
            request,
            "tasks.html",
            _ctx(request, active="tasks", page_title="Tasks", tasks=rows),
    )


def _run_row(run):
    """Display-ready TaskRun row: Tehran timestamps + duration string."""
    if not run:
        return None
    return {
        "id": str(run.id),
        "status": run.status,
        "triggered_by": run.triggered_by,
        "pid": run.pid,
        "log_path": run.log_path or "",
        "log_name": Path(run.log_path).name if run.log_path else "",
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "started_tehran": fmt_tehran(run.started_at),
        "finished_tehran": fmt_tehran(run.finished_at),
        "ago": fmt_ago(run.started_at),
        "duration": fmt_duration(run.started_at, run.finished_at),
    }
