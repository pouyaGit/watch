"""Add, edit and remove targets (Programs). Form posts redirect back to the Targets page."""
import json
import os
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from backend.helpers import read_params
from backend.targets import ValidationError, normalize_apex_list, validate_program_name
from backend.task_runner import stop_task
from backend.models import TaskRun
from config import get_path
from database.db import Programs, delete_program_and_related, upsert_program

router = APIRouter()


# A target lives in two places: the DB (what the UI reads) and a
# programs/<name>.json file (the source of truth for the pipeline's Sync
# Programs stage, watch_sync_programs.py). That stage DELETES any DB program
# with no matching file, so a UI-only add is wiped on the next run. Keep the
# file in lockstep with every create/update/delete here so UI-added targets
# persist.
def _program_json_path(name):
    return os.path.join(get_path("programs"), f"{name}.json")


def _write_program_file(name, scopes, ooscopes):
    path = _program_json_path(name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as fh:
        json.dump(
            {"program_name": name, "scopes": scopes, "ooscopes": ooscopes or []},
            fh, indent=2,
        )
    os.replace(tmp, path)  # atomic: never leave a half-written file for sync


def _remove_program_file(name):
    try:
        os.remove(_program_json_path(name))
    except FileNotFoundError:
        pass


def _view(p):
    return {
        "program_name": p.program_name,
        "scopes": p.scopes,
        "ooscopes": p.ooscopes,
        "created_date": p.created_date.isoformat() if p.created_date else None,
    }


def _is_form(request):
    return "application/json" not in request.headers.get("content-type", "")


def _ok(request, message, location, status=200, payload=None):
    if _is_form(request):
        return RedirectResponse(f"{location}?ok={quote(message)}", status_code=303)
    return JSONResponse(payload or {"detail": message}, status_code=status)


def _fail(request, message, status=400):
    if _is_form(request):
        return RedirectResponse(f"/ui/targets?err={quote(message)}", status_code=303)
    return JSONResponse({"detail": message}, status_code=status)


def _scopes(data):
    scopes = normalize_apex_list(data.get("scopes"), "scope")
    if not scopes:
        raise ValidationError("at least one scope is required")
    return scopes, normalize_apex_list(data.get("ooscopes"), "ooscope")


@router.get("/api/targets")
def list_targets():
    return [_view(p) for p in Programs.objects().order_by("program_name")]


@router.post("/api/targets")
async def create_target(request: Request):
    try:
        data = await read_params(request)
        name = validate_program_name(data.get("program_name"))
        scopes, ooscopes = _scopes(data)
    except ValueError as exc:
        return _fail(request, str(exc))
    if Programs.objects(program_name=name).first():
        return _fail(request, f"target {name!r} already exists", status=409)
    upsert_program(name, scopes, ooscopes, {})
    _write_program_file(name, scopes, ooscopes)
    return _ok(request, f"created {name}", "/ui/targets", status=201,
               payload=_view(Programs.objects(program_name=name).first()))


@router.post("/api/targets/{name}")
async def update_target(name: str, request: Request):
    program = Programs.objects(program_name=name).first()
    if program is None:
        return _fail(request, "target not found", status=404)
    try:
        data = await read_params(request)
        scopes, ooscopes = _scopes(data)
    except ValueError as exc:
        return _fail(request, str(exc))
    upsert_program(name, scopes, ooscopes, program.config or {})
    _write_program_file(name, scopes, ooscopes)
    return _ok(request, f"updated {name}", "/ui/targets",
               payload=_view(Programs.objects(program_name=name).first()))


@router.post("/api/targets/{name}/delete")
async def delete_target(name: str, request: Request):
    if Programs.objects(program_name=name).first() is None:
        return _fail(request, "target not found", status=404)
    try:
        data = await read_params(request)
    except ValueError as exc:
        return _fail(request, str(exc))
    if (data.get("confirm") or "") != name:
        return _fail(request, "confirmation does not match the target name")
    for run in TaskRun.objects(target=name, status="running"):
        stop_task(str(run.id))
    delete_program_and_related(name)
    _remove_program_file(name)
    return _ok(request, f"deleted {name}", "/ui/targets", payload={"deleted": name})
