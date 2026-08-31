"""
backend/task_report.py — Real exit-code reporting from spawned task processes.

task_runner.run_task() exports TASK_RUN_ID into the environment of every
subprocess it launches. Scripts opt into accurate status reporting by calling
mark_finished() from their __main__ block (on success and on uncaught
failure). Manual/CLI usage without TASK_RUN_ID set is completely unaffected:
mark_finished() is a silent no-op in that case.

This module must never raise, never print, and never require a live Mongo
connection merely to be imported -- it is imported by every registered task
script at module load time.
"""
import os
from datetime import datetime


def mark_finished(status: str, exit_code: int = None):
    """Mark the TaskRun identified by $TASK_RUN_ID as finished.

    - status: "success" or "failed"
    - exit_code: process exit code (0 on success, 1 on failure typically)

    Silent no-op when TASK_RUN_ID is unset (manual CLI runs), when Mongo is
    unreachable, or when anything at all goes wrong -- status reporting must
    never break the actual task.
    """
    run_id = os.environ.get("TASK_RUN_ID")
    if not run_id:
        return
    try:
        # Imported lazily so importing this module never requires Mongo.
        from backend.models import TaskRun

        run = TaskRun.objects(id=run_id).first()
        if run is None:
            return
        run.status = status
        run.exit_code = exit_code
        run.finished_at = datetime.now()
        run.save()
    except Exception:
        # Never let telemetry break the task itself.
        pass