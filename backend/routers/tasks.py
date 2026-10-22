"""Run, control and inspect allowlisted recon stages. Tool ids come only from the registry."""
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from backend.helpers import read_params
from backend.models import TaskRun
from backend.task_runner import (
    RunConflict, RunError, control_system_unit, group_next, group_stop, latest_run, launch,
    list_runs, live_snapshot, pause_task, read_log_tail, reconcile, rerun_task, resume_task,
    run_task, send_heavy_command, serialize_run, stop_task, LIVE_STATUSES,
)
from backend.tasks_registry import TASKS_REGISTRY, get_task

router = APIRouter()


def _error(message, status):
    return JSONResponse({"detail": message}, status_code=status)


def _find_run(run_id):
    try:
        return TaskRun.objects(id=ObjectId(run_id)).first()
    except (InvalidId, TypeError):
        return None


def _run_error(exc):
    if isinstance(exc, RunConflict):
        return _error(str(exc), 409)
    return _error(str(exc), 400)


async def _body(request: Request):
    try:
        return await read_params(request), None
    except ValueError as exc:
        return None, _error(str(exc), 400)


@router.get("/api/tasks")
def list_tasks():
    out = []
    for task_id, entry in TASKS_REGISTRY.items():
        last = latest_run(task_id)
        out.append({
            "task_id": task_id,
            "tool": entry["tool"],
            "name": entry["name"],
            "arg_style": entry["arg_style"],
            "supports_all": entry["supports_all"],
            "heavy": entry["heavy"],
            "filter": entry["arg_style"] == "filter_flag",
            "default_args": entry["default_args"],
            "latest": serialize_run(reconcile(last)) if last else None,
        })
    return out


@router.get("/api/tasks/live")
def tasks_live():
    return live_snapshot()


@router.post("/api/runs")
async def create_runs(request: Request):
    data, err = await _body(request)
    if err:
        return err
    max_minutes = data.get("max_minutes")
    try:
        result = launch(
            tools=data.get("tools"),
            scope_kind=data.get("scope_kind"),
            scope=data.get("scope") or [],
            max_minutes=max_minutes,
        )
    except RunError as exc:
        return _run_error(exc)
    return JSONResponse(result, status_code=201)


@router.get("/api/tasks/runs")
def runs_index(page: int = 1, limit: int = 25, task_id: str = None, status: str = None):
    total, items = list_runs(page=page, limit=limit, task_id=task_id, status=status)
    return {"total": total, "page": page, "items": [serialize_run(r) for r in items]}


@router.get("/api/tasks/runs/{run_id}/log", response_class=PlainTextResponse)
def run_log(run_id: str, tail: int = 200):
    run = _find_run(run_id)
    if run is None:
        return PlainTextResponse("run not found", status_code=404)
    return PlainTextResponse("".join(read_log_tail(run, lines=tail)))


@router.post("/api/tasks/runs/{run_id}/stop")
def run_stop(run_id: str):
    run = _find_run(run_id)
    if run is None:
        return _error("run not found", 404)
    return {"run": serialize_run(stop_task(str(run.id)))}


@router.post("/api/tasks/runs/{run_id}/pause")
def run_pause(run_id: str):
    run = _find_run(run_id)
    if run is None:
        return _error("run not found", 404)
    try:
        return {"run": serialize_run(pause_task(str(run.id)))}
    except RunError as exc:
        return _run_error(exc)


@router.post("/api/tasks/runs/{run_id}/resume")
def run_resume(run_id: str):
    run = _find_run(run_id)
    if run is None:
        return _error("run not found", 404)
    try:
        return {"run": serialize_run(resume_task(str(run.id)))}
    except RunError as exc:
        return _run_error(exc)


@router.post("/api/tasks/runs/{run_id}/rerun")
def run_rerun(run_id: str):
    run = _find_run(run_id)
    if run is None:
        return _error("run not found", 404)
    try:
        new_run = rerun_task(str(run.id))
    except RunError as exc:
        return _run_error(exc)
    return JSONResponse({"run": serialize_run(new_run)}, status_code=201)


@router.post("/api/groups/{group_id}/next")
def group_next_endpoint(group_id: str):
    try:
        stopped = group_next(group_id)
    except LookupError:
        return _error("group not found", 404)
    except RunError as exc:
        return _run_error(exc)
    return {"group_id": group_id, "stopped": stopped}


@router.post("/api/groups/{group_id}/stop")
def group_stop_endpoint(group_id: str):
    try:
        stopped = group_stop(group_id)
    except LookupError:
        return _error("group not found", 404)
    return {"group_id": group_id, "stopped": stopped}


@router.post("/api/system/{unit}/{action}")
def system_control(unit: str, action: str):
    try:
        return control_system_unit(unit, action)
    except RunError as exc:
        return _run_error(exc)


@router.post("/api/heavy/control/{command}")
def heavy_control(command: str):
    try:
        return {"ok": True, **send_heavy_command(command)}
    except RunError as exc:
        return _run_error(exc)


@router.post("/api/tasks/{task_id}/run")
async def run_stage(task_id: str, request: Request):
    if get_task(task_id) is None:
        return _error("unknown task", 404)
    data, err = await _body(request)
    if err:
        return err
    target = (data.get("target") or "").strip() or None
    try:
        run, created = run_task(task_id, target=target, triggered_by="dashboard")
    except RunError as exc:
        return _run_error(exc)
    return JSONResponse({"created": created, "run": serialize_run(run)}, status_code=201 if created else 200)


@router.post("/api/tasks/{task_id}/stop")
async def stop_stage(task_id: str, request: Request, run_id: str = None):
    if get_task(task_id) is None:
        return _error("unknown task", 404)
    if run_id:
        run = _find_run(run_id)
        if run is None or run.task_id != task_id:
            return _error("run not found", 404)
    else:
        data, err = await _body(request)
        if err:
            return err
        target = (data.get("target") or "").strip() or None
        run = None
        for candidate in TaskRun.objects(task_id=task_id, target=target, status__in=list(LIVE_STATUSES)).order_by("-started_at"):
            if reconcile(candidate).status in LIVE_STATUSES:
                run = candidate
                break
        if run is None:
            return _error("no running run", 404)
    return {"run": serialize_run(stop_task(str(run.id)))}


@router.get("/api/tasks/{task_id}/status.json")
def stage_status(task_id: str, target: str = None):
    if get_task(task_id) is None:
        return _error("unknown task", 404)
    run = latest_run(task_id, target or None)
    if run is None:
        return {"status": None}
    run = reconcile(run)
    return {"status": run.status, "pid": run.pid, "started_at": run.started_at.isoformat() if run.started_at else None,
            "exit_code": run.exit_code}
