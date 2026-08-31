"""
backend/task_runner.py — Launch registered tasks as detached subprocesses.

Two responsibilities:

1. run_task(task_id, triggered_by="manual") -> Spawn `python3 {script} {args}`
   via subprocess.Popen with start_new_session=True so the child becomes its
   own process group leader (a Ctrl-C or SIGHUP against the FastAPI process
   will not cascade into the running crawl). stdout/stderr are tee'd into a
   per-run log file under /opt/watch/logs/tasks/. A TaskRun document is
   created up front; the live status badge / history endpoint reads from it.

2. get_task_status(task_id) -> Best-effort liveness check based on the PID
   stored in the most recent TaskRun for that task. If the PID is no longer
   alive (os.kill(pid, 0) raises ProcessLookupError/ESRCH) AND the TaskRun
   is still marked "running", flip it to "success" (best-effort: we don't
   have a real exit code this way; that limitation is noted here).

This module does NOT poll or wait. It fires-and-records. The polling
behavior the UI needs is implemented by re-calling get_task_status() from
the Tasks page (htmx polls it every few seconds).
"""
import errno
import os
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional

from backend.models import TaskRun
from backend.tasks_registry import get_task, VENV_PYTHON

LOG_DIR = "/opt/watch/logs/tasks"


def _pid_alive(pid: Optional[int]) -> bool:
    """True if a process with this PID is currently running."""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, OSError) as exc:
        # ESRCH = no such process; EPERM = exists but not ours (still alive).
        if exc.errno == errno.EPERM:
            return True
        return False
    return True


def _resolve_final_status(task_id: str) -> str:
    """Reconcile the latest TaskRun for task_id.

    If mark_finished() already recorded a terminal status ("success"/"failed"
    with a real exit code), trust it. Only fall back to PID-liveness guessing
    when the run is still "running" and no terminal status was ever reported
    (covers runs launched before task_report.py existed, or runs started
    manually outside the dashboard where TASK_RUN_ID was never exported).
    Returns the resulting status string."""
    latest = (
        TaskRun.objects(task_id=task_id)
        .order_by("-started_at")
        .first()
    )
    if not latest:
        return "idle"
    if latest.status in ("success", "failed"):
        # Reported by the process itself via mark_finished() -- authoritative.
        return latest.status
    if latest.status != "running":
        return latest.status
    if _pid_alive(latest.pid):
        return "running"
    # PID gone -- we never observed a real exit code, so record "success"
    # as a best-effort marker (the process exited without us capturing why).
    latest.status = "success"
    latest.finished_at = latest.finished_at or datetime.now()
    latest.save()
    return "success"


def get_task_status(task_id: str) -> str:
    """Return one of: 'idle', 'running', 'success', 'failed'.

    'idle' means no TaskRun exists for this task_id. Anything else mirrors
    the TaskRun document's status field, with the liveness reconciliation
    above applied first.
    """
    if TaskRun.objects(task_id=task_id).count() == 0:
        return "idle"
    return _resolve_final_status(task_id)


def get_last_run(task_id: str) -> Optional[TaskRun]:
    """Most recent TaskRun for task_id, or None if none exists."""
    return (
        TaskRun.objects(task_id=task_id)
        .order_by("-started_at")
        .first()
    )


def list_history(task_id: str, page: int = 1, limit: int = 10):
    """Return TaskRun docs for task_id, newest first, paginated."""
    limit = min(max(limit, 1), 100)
    page = max(page, 1)
    qs = TaskRun.objects(task_id=task_id).order_by("-started_at")
    total = qs.count()
    items = list(qs.skip((page - 1) * limit).limit(limit))
    return total, items


def run_task(task_id: str, triggered_by: str = "manual") -> TaskRun:
    """Launch the registered script as a detached subprocess.

    Raises ValueError if task_id is not in the registry. Returns the TaskRun
    document (already saved, with status='running' and the new pid/log_path).
    """
    entry = get_task(task_id)
    if not entry:
        raise ValueError(f"Unknown task_id: {task_id!r}")

    script_path = entry["script"]
    if not os.path.isfile(script_path):
        raise FileNotFoundError(f"Script not found: {script_path}")

    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOG_DIR, f"{task_id}_{timestamp}.log")

    # Create the TaskRun document FIRST so the UI gets a run_id to poll
    # against even if the subprocess fails to spawn.
    run = TaskRun(
        task_id=task_id,
        started_at=datetime.now(),
        status="running",
        triggered_by=triggered_by,
        log_path=log_path,
    )
    run.save()

    # Open the log file (line-buffered so tail -f works during the run),
    # then spawn the subprocess in its own session.
    log_fp = open(log_path, "ab", buffering=0)
    try:
        proc = subprocess.Popen(
            [VENV_PYTHON, script_path, *entry.get("default_args", [])],
            stdout=log_fp,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            cwd="/opt/watch",
            env={**os.environ, "TASK_RUN_ID": str(run.id)},
            close_fds=True,
        )
        run.pid = proc.pid
        run.save()
    except Exception:
        # If Popen itself blew up, flip the run to "failed" with no exit code.
        run.status = "failed"
        run.finished_at = datetime.now()
        run.save()
        log_fp.close()
        raise

    # NOTE: we deliberately do NOT proc.wait() here -- these jobs run for
    # hours. The caller (POST /api/tasks/{task_id}/run) returns immediately
    # with the run.id; liveness is reconciled on demand by get_task_status().
    return run