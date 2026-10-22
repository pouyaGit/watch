"""Terminal status reporting for scripts launched by backend/task_runner.py.

Scripts call mark_finished() from their __main__ block. Outside the dashboard
TASK_RUN_ID is unset and this is a no-op. Failures are written to stderr, which
lands in the run's log file, so a broken report is visible instead of silent.
"""
import os
import sys
from datetime import datetime


def mark_finished(status: str, exit_code: int = None):
    run_id = os.environ.get("TASK_RUN_ID")
    if not run_id:
        return
    try:
        from backend.models import TaskRun

        TaskRun.objects(id=run_id, status="running").update_one(
            set__status=status,
            set__exit_code=exit_code,
            set__finished_at=datetime.now(),
        )
    except Exception as exc:
        print(f"[task_report] could not record status for run {run_id}: {exc}", file=sys.stderr, flush=True)
