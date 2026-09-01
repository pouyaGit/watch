"""
backend/routers/runs.py — Recon Runs view (aggregated across all task types).

Routes:
- GET /ui/runs          — HTML page: recent runs across all tasks + DNS runs
- GET /api/runs/recent  — JSON: same data, for any JS consumer
"""
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse

from backend.deps import build_url, verify_api_key
from backend.templating import templates
from backend.tz import fmt_ago, fmt_duration, fmt_tehran
from backend.task_runner import get_last_run, get_task_status
from backend.tasks_registry import all_tasks
from backend.models import TaskRun
from database.db import DnsBruteStatus

router = APIRouter()


def _ctx(request: Request, **extra):
    from backend.deps import API_KEY
    base = {
        "request": request,
        "api_key_qs": API_KEY or "",
        "root_url": build_url("/"),
        "home_url": build_url("/"),
        "tasks_url": build_url("/ui/tasks"),
        "runs_url": build_url("/ui/runs"),
        "changes_url": build_url("/ui/changes"),
        "domains_url": build_url("/ui/domains"),
        "http_url": build_url("/ui/http"),
        "urls_url": build_url("/ui/urls"),
        "endpoints_url": build_url("/ui/endpoints"),
        "parameters_url": build_url("/ui/parameters"),
        "search_url": build_url("/ui/search"),
        "programs_url": build_url("/ui/programs"),
        "dns_url": build_url("/ui/dns-bruteforce/status"),
        "docs_url": build_url("/docs"),
        "stats_link": build_url("/api/stats/by-program"),
        "fresh_link": build_url("/ui/http/fresh"),
    }
    base.update(extra)
    return base


def _run_row(run):
    if not run:
        return None
    return {
        "task_id": run.task_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "status": run.status,
        "exit_code": run.exit_code,
        "triggered_by": run.triggered_by,
        "log_path": run.log_path or "",
        "log_name": Path(run.log_path).name if run.log_path else "",
        "started_tehran": fmt_tehran(run.started_at),
        "finished_tehran": fmt_tehran(run.finished_at),
        "ago": fmt_ago(run.started_at),
        "duration": fmt_duration(run.started_at, run.finished_at),
    }


@router.get("/ui/runs", response_class=HTMLResponse)
def runs_page(request: Request):
    """Aggregated recon runs across all task types + DNS brute runs."""
    tasks = []
    for task_id, entry in all_tasks():
        status = get_task_status(task_id)
        last = get_last_run(task_id)
        total = TaskRun.objects(task_id=task_id).count()
        tasks.append({
            "task_id": task_id,
            "name": entry["name"],
            "status": status,
            "last_run": _run_row(last),
            "total_runs": total,
            "history": [],
        })

    # DNS brute-force statuses as "runs"
    dns_runs = []
    for s in DnsBruteStatus.objects().order_by("-last_static_run", "-last_dynamic_run").limit(50):
        dns_runs.append({
            "program_name": s.program_name,
            "domain": s.domain,
            "feasible": s.feasible,
            "last_static": fmt_tehran(s.last_static_run),
            "last_static_ago": fmt_ago(s.last_static_run),
            "last_dynamic": fmt_tehran(s.last_dynamic_run),
            "last_dynamic_ago": fmt_ago(s.last_dynamic_run),
        })

    return templates.TemplateResponse(
        request,
        "runs.html",
        _ctx(
            request,
            active="runs",
            page_title="Recon Runs",
            tasks=tasks,
            dns_runs=dns_runs[:20],
        ),
    )


@router.get("/api/runs/recent", dependencies=[Depends(verify_api_key)])
def api_runs_recent():
    """JSON: recent runs across all tasks (last 3 per task) + DNS runs."""
    tasks = []
    for task_id, entry in all_tasks():
        qs = TaskRun.objects(task_id=task_id).order_by("-started_at").limit(3)
        tasks.append({
            "task_id": task_id,
            "name": entry["name"],
            "status": get_task_status(task_id),
            "recent": [_run_row(r) for r in qs if r],
        })
    return {"tasks": tasks}