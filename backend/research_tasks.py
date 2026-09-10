"""backend/research_tasks.py — thin adapter for the R20 research workflow store.

Exposes the default local task directory (``ai_data/research/tasks``) and a
fresh :class:`ResearchTaskStore` per call so tests can redirect the directory.
Read and write helpers stay here so the API/UI routers contain no storage or
state-machine logic.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TASKS_DIR = PROJECT_ROOT / "ai_data" / "research" / "tasks"


def task_store():
    from ai.knowledge.task_store import ResearchTaskStore

    return ResearchTaskStore(TASKS_DIR)


def list_tasks(limit: int = 50, offset: int = 0, status=None, cve=None) -> dict:
    return task_store().list(limit=limit, offset=offset, status=status, cve=cve)


def get_task(task_id: str):
    return task_store().get(task_id)


def task_by_queue() -> dict:
    """Bounded {queue_id: task_id} map for queue-page task indicators."""

    data = task_store().list(limit=100)
    return {item["queue_id"]: item["task_id"] for item in data["items"]}


def create_task(cve, program, queue_id, title=None, notes=None, references=None):
    return task_store().create(
        cve=cve,
        program=program,
        queue_id=queue_id,
        title=title,
        notes=notes,
        references=references,
    )


def update_task(
    task_id,
    expected_version,
    status=None,
    notes=None,
    blocker=None,
    result_summary=None,
    references=None,
):
    return task_store().update(
        task_id,
        expected_version=expected_version,
        status=status,
        notes=notes,
        blocker=blocker,
        result_summary=result_summary,
        references=references,
    )
