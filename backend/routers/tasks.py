"""
backend/routers/tasks.py — Manual task runner + history endpoints (Phase 1).

Per the architecture doc, scheduling endpoints land in Phase 2 once APScheduler
is wired in. For now this module only exposes:
  GET    /api/tasks                       -- list + status + last_run summary
  POST   /api/tasks/{task_id}/run         -- launch detached subprocess
  GET    /api/tasks/{task_id}/history     -- paginated TaskRun docs
  GET    /api/tasks/{task_id}/status      -- live liveness (for htmx polling)

Every route is behind verify_api_key, same as the existing endpoints.
"""
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from backend.deps import verify_api_key
from backend.models import TaskRun
from backend.task_runner import (
    get_last_run,
    get_task_status,
    list_history,
    run_task,
)
from backend.tasks_registry import TASKS_REGISTRY, get_task

router = APIRouter()

_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "web" / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _serialize_run(run: Optional[TaskRun]):
    if not run:
        return None
    return {
        "id": str(run.id),
        "task_id": run.task_id,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "status": run.status,
        "exit_code": run.exit_code,
        "triggered_by": run.triggered_by,
        "pid": run.pid,
        "log_path": run.log_path,
    }


@router.get("/api/tasks", dependencies=[Depends(verify_api_key)])
def list_tasks():
    """Return every registered task with its current status + last run summary.

    Current status is reconciled against PID liveness on every call, so the
    UI doesn't need its own polling/cleanup logic.
    """
    out = []
    for task_id, entry in TASKS_REGISTRY.items():
        last = get_last_run(task_id)
        out.append({
            "task_id": task_id,
            "name": entry["name"],
            "script": entry["script"],
            "default_args": entry.get("default_args", []),
            "status": get_task_status(task_id),
            "last_run": _serialize_run(last),
        })
    return out


@router.post("/api/tasks/{task_id}/run", dependencies=[Depends(verify_api_key)])
def trigger_task(task_id: str):
    if not get_task(task_id):
        raise HTTPException(status_code=404, detail=f"Unknown task_id: {task_id!r}")
    try:
        run = run_task(task_id, triggered_by="manual")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {
        "task_run_id": str(run.id),
        "status": run.status,
        "pid": run.pid,
        "log_path": run.log_path,
    }


@router.get("/api/tasks/{task_id}/history", dependencies=[Depends(verify_api_key)])
def task_history(task_id: str, page: int = 1, limit: int = 10):
    if not get_task(task_id):
        raise HTTPException(status_code=404, detail=f"Unknown task_id: {task_id!r}")
    total, items = list_history(task_id, page=page, limit=limit)
    return {
        "task_id": task_id,
        "total": total,
        "page": page,
        "items": [_serialize_run(r) for r in items],
    }


@router.get("/api/tasks/{task_id}/status", dependencies=[Depends(verify_api_key)],
            response_class=HTMLResponse)
def task_status_badge(request: Request, task_id: str):
    """Lightweight HTML fragment for htmx polling -- returns just the badge."""
    if not get_task(task_id):
        raise HTTPException(status_code=404, detail=f"Unknown task_id: {task_id!r}")
    return templates.TemplateResponse(
        request,
        "_status_badge.html",
        {"status": get_task_status(task_id)},
    )


@router.get("/api/tasks/{task_id}/status.json", dependencies=[Depends(verify_api_key)])
def task_status(task_id: str):
    """JSON variant of /status, kept for any future non-htmx caller."""
    if not get_task(task_id):
        raise HTTPException(status_code=404, detail=f"Unknown task_id: {task_id!r}")
    last = get_last_run(task_id)
    return {
        "task_id": task_id,
        "status": get_task_status(task_id),
        "last_run": _serialize_run(last),
    }