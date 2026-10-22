"""Launch allowlisted recon scripts as detached process groups and track them.

Every launch becomes one TaskRun row per invocation. Invocations run one at a
time on a single queue thread, so ad-hoc work never overwhelms the small VPS.
Each running child is owned by that thread, which records its exit code and a
result summary. A run whose exit cannot be observed (e.g. after a dashboard
restart) is recorded as "unknown", never as "success".
"""
import glob
import json
import os
import queue
import re
import signal
import subprocess
import threading
import time
import traceback
import uuid
from collections import deque
from datetime import datetime

from mongoengine import Q

from backend.models import TaskRun
from backend.tasks_registry import (
    HEAVY_UNIT, PROJECT_ROOT, SYSTEM_UNITS, TASKS_REGISTRY, TOOL_TO_TASK, VENV_PYTHON, get_task,
)
from backend.targets import APEX_RE
from database.db import Http, LiveSubdomains, Programs, Subdomains

LOG_DIR = os.path.join(PROJECT_ROOT, "logs", "tasks")
STATE_DIR = os.path.join(PROJECT_ROOT, "logs")
HEAVY_STATE_PATH = os.path.join(STATE_DIR, "heavy_state.json")
HEAVY_CONTROL_PATH = os.path.join(STATE_DIR, "heavy_control.json")
HEAVY_COMMANDS = ("skip", "pause", "resume", "stop-after-lane")
PIPELINE_LOG_GLOB = os.path.join(STATE_DIR, "pipeline_*.log")
STOP_GRACE_SECONDS = 10
KILL_WAIT_SECONDS = 3
MAX_MINUTES_CAP = 1440
MAX_INVOCATIONS = 500
SCOPE_KINDS = ("all", "programs", "domains")
ACTIVE_STATUSES = ("running", "paused")
LIVE_STATUSES = ("queued", "running", "paused")
SYSTEM_NAMES = {
    "watch.service": "Pipeline",
    "watch-heavy.service": "Heavy worker",
    "watch-ct-stream.service": "CT stream",
}
_STAGE_RE = re.compile(r"^===== (.+?) =====\s*$", re.M)

_procs = {}
_procs_lock = threading.Lock()
_pending = {}
_pending_lock = threading.Lock()
_queue = queue.Queue()
_worker = None
_worker_lock = threading.Lock()


class RunError(ValueError):
    pass


class RunConflict(RunError):
    pass


def _assert_script_confined(script_path: str, task_id: str) -> None:
    normalized = os.path.normpath(script_path)
    if normalized != script_path or not os.path.isabs(normalized):
        raise RunError(f"unsafe script for task {task_id!r}")
    if os.path.commonpath([normalized, PROJECT_ROOT]) != PROJECT_ROOT:
        raise RunError(f"unsafe script for task {task_id!r}")
    if os.path.dirname(os.path.relpath(normalized, PROJECT_ROOT)) not in ("enum", "ns", "http", "crawl"):
        raise RunError(f"unsafe script for task {task_id!r}")


def _entry(task_id):
    entry = get_task(task_id)
    if entry is None:
        raise RunError(f"unknown task_id: {task_id!r}")
    return entry


def _proc_state(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    return data.rsplit(b")", 1)[-1].split()[0].decode()


def _cmdline_has(pid, needle: str) -> bool:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return needle.encode() in fh.read()
    except OSError:
        return False


def _run_pid_alive(run) -> bool:
    entry = get_task(run.task_id)
    if not run.pid or not entry:
        return False
    if _proc_state(run.pid) in (None, "Z", "X"):
        return False
    return _cmdline_has(run.pid, entry["script"])


def _group_alive(pgid) -> bool:
    if not pgid:
        return False
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_group(pgid, sig) -> bool:
    try:
        os.killpg(pgid, sig)
    except OSError:
        return False
    return True


def reconcile(run):
    """Return run with a corrected status when nothing owns or backs it any more."""
    if run.status == "queued":
        with _pending_lock:
            if str(run.id) in _pending:
                return run
    elif run.status in ACTIVE_STATUSES:
        with _procs_lock:
            owned = str(run.id) in _procs
        if owned or _run_pid_alive(run) or _group_alive(run.pid):
            return run
    else:
        return run
    TaskRun.objects(id=run.id, status__in=list(LIVE_STATUSES)).update_one(
        set__status="unknown", set__finished_at=datetime.now(),
    )
    return TaskRun.objects(id=run.id).first()


def _clamp_minutes(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise RunError("max_minutes must be a number or null")
    try:
        minutes = int(float(value))
    except (TypeError, ValueError, OverflowError):
        raise RunError("max_minutes must be a number or null")
    return min(max(minutes, 1), MAX_MINUTES_CAP)


def _valid_domain(raw) -> str:
    domain = str(raw).strip().lower()
    if not APEX_RE.match(domain) or domain.startswith("-"):
        raise RunError(f"invalid domain: {raw!r}")
    return domain


def _scope_pairs(scope_kind, scope):
    """Return unique (program_name, domain) pairs, each validated against Programs."""
    pairs = []
    if scope_kind == "all":
        for program in Programs.objects():
            pairs.extend((program.program_name, _valid_domain(raw)) for raw in program.scopes or [])
    else:
        if not isinstance(scope, list) or not scope:
            raise RunError("scope must be a non-empty list")
        if scope_kind == "programs":
            for name in scope:
                program = Programs.objects(program_name=name).first()
                if program is None:
                    raise RunError(f"unknown program: {name!r}")
                pairs.extend((program.program_name, _valid_domain(raw)) for raw in program.scopes or [])
        else:
            for raw in scope:
                domain = _valid_domain(raw)
                program = Programs.objects(scopes=domain).first()
                if program is None:
                    raise RunError(f"domain is not in any program scope: {domain!r}")
                pairs.append((program.program_name, domain))
    unique = list(dict.fromkeys(pairs))
    if not unique:
        raise RunError("no in-scope domains for this selection")
    return unique


def _default_budget(entry):
    args = entry["default_args"]
    if "--max-minutes" in args:
        return int(args[args.index("--max-minutes") + 1])
    return None


def _budget_args(entry, budget):
    args = list(entry["default_args"])
    if "--max-minutes" in args:
        i = args.index("--max-minutes")
        del args[i:i + 2]
    if budget is not None and entry["max_minutes_flag"]:
        args += ["--max-minutes", str(budget)]
    return args


def expand_invocations(task_id, scope_kind, scope, max_minutes):
    """Expand one tool + scope + budget into one invocation dict per child run.

    Each dict carries the argv list, the program/domain it targets, and a
    watchdog in seconds (None when the script enforces its own budget or the
    run is until-stopped).
    """
    entry = _entry(task_id)
    if scope_kind not in SCOPE_KINDS:
        raise RunError("scope_kind must be all, programs or domains")
    budget = _clamp_minutes(max_minutes)
    if entry["arg_style"] == "none":
        if scope_kind != "all":
            raise RunError(f"{entry['tool']} runs whole-DB only; use scope 'all'")
        pairs = [(None, None)]
    elif scope_kind == "all" and entry["arg_style"] == "filter_flag" and entry["supports_all"]:
        pairs = [(None, None)]
    else:
        pairs = _scope_pairs(scope_kind, scope)
    if len(pairs) > MAX_INVOCATIONS:
        raise RunError(f"too many invocations ({len(pairs)}); narrow the scope")

    invocations = []
    for program, domain in pairs:
        argv = [VENV_PYTHON, entry["script"], *_budget_args(entry, budget)]
        if domain and entry["arg_style"] == "filter_flag":
            argv += ["--filter", domain]
        elif domain and entry["arg_style"] == "positional_domain":
            argv.append(domain)
        invocations.append({
            "task_id": task_id,
            "tool": entry["tool"],
            "argv": argv,
            "program": program,
            "domain": domain,
            "scope_kind": scope_kind,
            "max_minutes": budget,
            "watchdog": budget * 60 if budget and not entry["max_minutes_flag"] else None,
        })
    return invocations


def _ensure_worker():
    global _worker
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_queue_loop, name="task-queue", daemon=True)
            _worker.start()


def _submit(run_id, argv, watchdog):
    with _pending_lock:
        _pending[run_id] = {"argv": argv, "watchdog": watchdog}
    _queue.put(run_id)
    _ensure_worker()


def _enqueue_invocation(inv, group_id, source, triggered_by):
    """Return (run, created). An identical live invocation is reused, not duplicated."""
    scope = [inv["domain"]] if inv["domain"] else []
    for candidate in TaskRun.objects(task_id=inv["task_id"], status__in=list(LIVE_STATUSES), scope=scope):
        candidate = reconcile(candidate)
        if candidate.status in LIVE_STATUSES:
            return candidate, False
    run = TaskRun(
        task_id=inv["task_id"],
        target=inv["program"],
        tool=inv["tool"],
        scope_kind=inv["scope_kind"],
        scope=scope,
        max_minutes=inv["max_minutes"],
        status="queued",
        source=source,
        group_id=group_id,
        triggered_by=triggered_by,
        started_at=datetime.now(),
    )
    run.save()
    _submit(str(run.id), inv["argv"], inv["watchdog"])
    return run, True


def _check_heavy(invocations):
    if any(get_task(inv["task_id"])["heavy"] for inv in invocations) and heavy_active():
        raise RunConflict(
            "watch-heavy.service is active and already runs these lanes. "
            "Stop it from the Live panel before launching heavy tools."
        )


def launch(tools, scope_kind, scope, max_minutes, source="dashboard", triggered_by="dashboard"):
    """Queue one child run per invocation. Returns group_id and the created runs."""
    if not isinstance(tools, list) or not tools or len(tools) > len(TASKS_REGISTRY):
        raise RunError("tools must be a non-empty list")
    task_ids = []
    for tool in tools:
        task_id = TOOL_TO_TASK.get(tool) if isinstance(tool, str) else None
        if task_id is None:
            raise RunError(f"unknown tool: {tool!r}")
        if task_id not in task_ids:
            task_ids.append(task_id)
    invocations = []
    for task_id in task_ids:
        invocations.extend(expand_invocations(task_id, scope_kind, scope, max_minutes))
    if len(invocations) > MAX_INVOCATIONS:
        raise RunError(f"too many invocations ({len(invocations)}); narrow the scope")
    _check_heavy(invocations)

    group_id = uuid.uuid4().hex
    created, skipped = [], 0
    for inv in invocations:
        run, is_new = _enqueue_invocation(inv, group_id, source, triggered_by)
        if is_new:
            created.append(run)
        else:
            skipped += 1
    return {
        "group_id": group_id,
        "created": len(created),
        "skipped": skipped,
        "runs": [serialize_run(r) for r in created],
    }


def run_task(task_id: str, target=None, triggered_by: str = "manual"):
    """Legacy single-stage launch. Returns (run, created)."""
    entry = _entry(task_id)
    if entry["arg_style"] == "none" or target is None:
        scope_kind, scope = "all", []
    else:
        scope_kind, scope = "programs", [target]
    invocations = expand_invocations(task_id, scope_kind, scope, _default_budget(entry))
    _check_heavy(invocations)
    results = [_enqueue_invocation(inv, None, "dashboard", triggered_by) for inv in invocations]
    run, _ = results[0]
    return run, any(is_new for _, is_new in results)


def _queue_loop():
    while True:
        run_id = _queue.get()
        try:
            _execute(run_id)
        except Exception:
            traceback.print_exc()
        finally:
            _queue.task_done()


def _execute(run_id):
    with _pending_lock:
        job = _pending.get(run_id)
    if job is None:
        return
    try:
        run = TaskRun.objects(id=run_id).first()
        if run is None or run.status != "queued":
            return
        if get_task(run.task_id)["heavy"] and heavy_active():
            TaskRun.objects(id=run_id, status="queued").update_one(
                set__status="stopped", set__finished_at=datetime.now(),
                set__summary={"note": "skipped: watch-heavy.service is active"},
            )
            return
        try:
            proc, log_path = _spawn(run, job["argv"])
        except Exception as exc:
            TaskRun.objects(id=run_id, status="queued").update_one(
                set__status="failed", set__finished_at=datetime.now(),
                set__summary={"note": f"spawn failed: {exc}"},
            )
            return
        claimed = TaskRun.objects(id=run_id, status="queued").update_one(
            set__status="running", set__pid=proc.pid,
            set__started_at=datetime.now(), set__log_path=log_path,
        )
        if not claimed:
            _kill_group(proc.pid)
            proc.wait()
            return
        with _procs_lock:
            _procs[run_id] = proc
        try:
            _supervise(run_id, proc, job["watchdog"])
            _finalize(run_id, proc.returncode)
        finally:
            with _procs_lock:
                _procs.pop(run_id, None)
    finally:
        with _pending_lock:
            _pending.pop(run_id, None)


def _spawn(run, argv):
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, f"{run.task_id}-{run.id}.log")
    budget = f"{run.max_minutes}m" if run.max_minutes else "until stopped"
    with open(log_path, "ab", buffering=0) as log_fp:
        log_fp.write(
            f"# task={run.task_id} tool={run.tool} target={run.target or 'all'} "
            f"scope={','.join(run.scope) or 'all'} budget={budget} argv={' '.join(argv)}\n".encode()
        )
        proc = subprocess.Popen(
            argv,
            stdout=log_fp,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            cwd=PROJECT_ROOT,
            env={**os.environ, "TASK_RUN_ID": str(run.id), "PYTHONUNBUFFERED": "1"},
            close_fds=True,
        )
    return proc, log_path


def _supervise(run_id, proc, watchdog):
    deadline = time.monotonic() + watchdog if watchdog else None
    while True:
        try:
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            if deadline is not None and time.monotonic() >= deadline:
                deadline = None
                TaskRun.objects(id=run_id, status__in=list(ACTIVE_STATUSES)).update_one(
                    set__status="stopped", set__finished_at=datetime.now(),
                    set__summary={"note": "time budget reached"},
                )
                _kill_group(proc.pid)


def _finalize(run_id, rc):
    TaskRun.objects(id=run_id).update_one(set__exit_code=rc)
    TaskRun.objects(id=run_id, status__in=list(ACTIVE_STATUSES)).update_one(
        set__status="success" if rc == 0 else "failed", set__finished_at=datetime.now(),
    )
    try:
        _summarize(run_id)
    except Exception:
        traceback.print_exc()


def _summarize(run_id):
    run = TaskRun.objects(id=run_id).first()
    if run is None or run.started_at is None:
        return
    since = run.started_at
    domain = run.scope[0] if run.scope else None

    def count(model):
        qs = model.objects(created_date__gte=since)
        if run.target:
            qs = qs.filter(program_name=run.target)
        if domain:
            qs = qs.filter(Q(subdomain=domain) | Q(subdomain__endswith="." + domain))
        return qs.count()

    summary = {**(run.summary or {})}
    summary.update({
        "program": run.target,
        "domain": domain,
        "new_subs": count(Subdomains),
        "new_live": count(LiveSubdomains),
        "new_http": count(Http),
    })
    TaskRun.objects(id=run_id).update_one(set__summary=summary)


def _kill_group(pgid: int):
    _signal_group(pgid, signal.SIGCONT)
    for sig, wait_seconds in ((signal.SIGTERM, STOP_GRACE_SECONDS), (signal.SIGKILL, KILL_WAIT_SECONDS)):
        if not _group_alive(pgid):
            return
        if not _signal_group(pgid, sig):
            return
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if not _group_alive(pgid):
                return
            time.sleep(0.2)


def _get_run(run_id: str):
    run = TaskRun.objects(id=run_id).first()
    if run is None:
        raise LookupError(f"no run {run_id}")
    return run


def stop_task(run_id: str):
    run = reconcile(_get_run(run_id))
    if run.status == "queued":
        TaskRun.objects(id=run.id, status="queued").update_one(
            set__status="stopped", set__finished_at=datetime.now(),
        )
    elif run.status in ACTIVE_STATUSES:
        TaskRun.objects(id=run.id, status__in=list(ACTIVE_STATUSES)).update_one(
            set__status="stopped", set__finished_at=datetime.now(),
        )
        if run.pid:
            _kill_group(run.pid)
    return TaskRun.objects(id=run.id).first()


def pause_task(run_id: str):
    run = reconcile(_get_run(run_id))
    if run.status != "running":
        raise RunConflict(f"run is {run.status}, not running")
    if not run.pid or not _signal_group(run.pid, signal.SIGSTOP):
        raise RunConflict("process is not running")
    TaskRun.objects(id=run.id, status="running").update_one(set__status="paused")
    return TaskRun.objects(id=run.id).first()


def resume_task(run_id: str):
    run = reconcile(_get_run(run_id))
    if run.status != "paused":
        raise RunConflict(f"run is {run.status}, not paused")
    if not run.pid or not _signal_group(run.pid, signal.SIGCONT):
        raise RunConflict("process is not running")
    TaskRun.objects(id=run.id, status="paused").update_one(set__status="running")
    return TaskRun.objects(id=run.id).first()


def rerun_task(run_id: str):
    """Queue a new standalone run with the same tool, scope and budget."""
    run = reconcile(_get_run(run_id))
    if run.scope:
        scope_kind, scope = "domains", list(run.scope)
    else:
        scope_kind, scope = "all", []
    invocations = expand_invocations(run.task_id, scope_kind, scope, run.max_minutes)
    _check_heavy(invocations)
    new_run, _ = _enqueue_invocation(invocations[0], None, "dashboard", "rerun")
    return new_run


def _group_runs(group_id: str):
    runs = list(TaskRun.objects(group_id=group_id).order_by("started_at"))
    if not runs:
        raise LookupError(f"no group {group_id}")
    return runs


def group_next(group_id: str):
    """Stop the child that is running now; the queue starts the next one."""
    current = None
    for run in _group_runs(group_id):
        run = reconcile(run)
        if run.status in ACTIVE_STATUSES:
            current = run
            break
    if current is None:
        raise RunConflict("no running child in this group")
    stop_task(str(current.id))
    return str(current.id)


def group_stop(group_id: str):
    runs = _group_runs(group_id)
    for run in runs:
        if run.status == "queued":
            stop_task(str(run.id))
    for run in runs:
        run = reconcile(run)
        if run.status in ACTIVE_STATUSES:
            stop_task(str(run.id))
    return sum(1 for r in _group_runs(group_id) if r.status == "stopped")


def latest_run(task_id: str, target=None):
    qs = TaskRun.objects(task_id=task_id)
    if target is not None:
        qs = qs.filter(target=target)
    return qs.order_by("-started_at").first()


def list_runs(page: int = 1, limit: int = 25, task_id=None, status=None):
    limit = min(max(limit, 1), 100)
    page = max(page, 1)
    qs = TaskRun.objects()
    if task_id:
        qs = qs.filter(task_id=task_id)
    if status:
        qs = qs.filter(status=status)
    qs = qs.order_by("-started_at")
    total = qs.count()
    items = [reconcile(r) for r in qs.skip((page - 1) * limit).limit(limit)]
    return total, items


def _log_path_ok(path):
    if not path:
        return None
    real = os.path.realpath(path)
    if not real.startswith(os.path.realpath(LOG_DIR) + os.sep) or not os.path.isfile(real):
        return None
    return real


def read_log_tail(run, lines: int = 200):
    real = _log_path_ok(run.log_path)
    if real is None:
        return []
    with open(real, "r", encoding="utf-8", errors="replace") as fh:
        return list(deque(fh, maxlen=min(max(lines, 1), 2000)))


def _read_tail(path, nbytes=65536):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - nbytes))
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _last_log_line(run):
    real = _log_path_ok(run.log_path)
    if real is None:
        return None
    lines = [line for line in _read_tail(real, 4096).splitlines() if line.strip()]
    return lines[-1][:200] if lines else None


def serialize_run(run) -> dict:
    end = run.finished_at or datetime.now()
    duration = int((end - run.started_at).total_seconds()) if run.started_at else None
    return {
        "id": str(run.id),
        "task_id": run.task_id,
        "tool": run.tool or run.task_id,
        "target": run.target,
        "scope_kind": run.scope_kind,
        "scope": list(run.scope or []),
        "max_minutes": run.max_minutes,
        "source": run.source,
        "group_id": run.group_id,
        "summary": dict(run.summary or {}),
        "status": run.status,
        "pid": run.pid,
        "exit_code": run.exit_code,
        "triggered_by": run.triggered_by,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "duration_seconds": duration,
    }


def _unit_props(unit):
    try:
        out = subprocess.run(
            ["systemctl", "show", unit, "--property=ActiveState,SubState,ExecMainStartTimestamp,MainPID"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    props = {}
    for line in out.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            props[key] = value
    return props


def heavy_active() -> bool:
    return _unit_props(HEAVY_UNIT).get("ActiveState") == "active"


def _parse_systemd_time(text):
    parts = (text or "").split()
    if len(parts) < 3:
        return None
    try:
        return datetime.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def read_heavy_state():
    try:
        with open(HEAVY_STATE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _heavy_activity(state):
    if not state:
        return None
    parts = []
    if state.get("lane"):
        target = state.get("target")
        parts.append(f"{state['lane']} → {target}" if target else f"{state['lane']} (starting)")
    if state.get("hold_after_lane"):
        parts.append("holding after lane")
    return " · ".join(parts) or None


def _pipeline_activity():
    paths = sorted(glob.glob(PIPELINE_LOG_GLOB))
    if not paths:
        return None
    markers = _STAGE_RE.findall(_read_tail(paths[-1]))
    if not markers:
        return f"log {os.path.basename(paths[-1])}"
    last = markers[-1]
    if " Finished in " in last:
        return f"after {last.split(' Finished in ')[0]}"
    return f"stage {last}"


def _system_row(unit):
    props = _unit_props(unit)
    active = props.get("ActiveState", "unknown")
    status = {"active": "running", "activating": "starting", "inactive": "idle",
              "failed": "failed"}.get(active, active)
    started = _parse_systemd_time(props.get("ExecMainStartTimestamp")) if active in ("active", "activating") else None
    elapsed = int((datetime.now() - started).total_seconds()) if started else None
    activity = None
    if unit == "watch.service":
        activity = _pipeline_activity()
    elif unit == HEAVY_UNIT:
        state = read_heavy_state()
        activity = _heavy_activity(state)
        if state and state.get("paused") and active == "active":
            status = "paused"
    return {
        "source": "systemd",
        "unit": unit,
        "run_id": None,
        "name": SYSTEM_NAMES[unit],
        "tool": None,
        "scope_kind": None,
        "scope": [],
        "target": None,
        "group_id": None,
        "max_minutes": None,
        "status": status,
        "started_at": started.isoformat() if started else None,
        "elapsed_seconds": elapsed,
        "activity": activity,
    }


def _run_live_row(run):
    row = serialize_run(run)
    if run.status == "queued":
        activity = "waiting in queue"
    else:
        activity = _last_log_line(run)
    row.update({
        "source": "dashboard",
        "unit": None,
        "run_id": row["id"],
        "name": row["tool"],
        "elapsed_seconds": row["duration_seconds"],
        "activity": activity,
    })
    return row


def live_snapshot(limit: int = 100):
    rows = [_system_row(unit) for unit in SYSTEM_UNITS]
    runs = TaskRun.objects(status__in=list(LIVE_STATUSES)).order_by("-started_at").limit(limit)
    for run in runs:
        run = reconcile(run)
        if run.status in LIVE_STATUSES:
            rows.append(_run_live_row(run))
    return rows


def send_heavy_command(command: str):
    if command not in HEAVY_COMMANDS:
        raise RunError(f"unknown heavy command: {command!r}")
    if not heavy_active():
        raise RunConflict("watch-heavy.service is not active")
    payload = {"command": command, "at": datetime.now().isoformat()}
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = HEAVY_CONTROL_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    os.replace(tmp, HEAVY_CONTROL_PATH)
    return payload


def control_system_unit(unit: str, action: str):
    if unit not in SYSTEM_UNITS:
        raise RunError(f"unit not allowed: {unit!r}")
    if action not in ("stop", "restart"):
        raise RunError(f"action not allowed: {action!r}")
    result = subprocess.run(["systemctl", action, unit], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:300]
        raise RunError(f"systemctl {action} {unit} failed: {detail}")
    return {"unit": unit, "action": action, "ok": True}
