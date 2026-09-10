"""Deterministic research-workflow task store (Stage R20).

Local JSON persistence under ``ai_data/research/tasks/`` with:

- deterministic task ids (``rt-`` + SHA-256 over rule version + CVE + program +
  queue id) — no randomness, no timestamps in identity;
- atomic writes (temp file + ``os.replace``) so a crash never leaves a
  half-written task;
- optimistic concurrency: every task carries a monotonically increasing
  ``version``; updates must pass the ``expected_version`` or fail with
  :class:`StaleTaskError` (compare-and-swap), serialized by an advisory lock so
  two simultaneous writers cannot both win;
- a bounded audit history (previous/new status + version, no request bodies);
- bounded strings and reference lists.

RESEARCH MANAGEMENT ONLY. No network, no subprocess, no Mongo, no LLM, no
execution. The researcher manually writes notes/results.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

try:  # POSIX advisory locking (Linux); degrades to version-only CAS if absent
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

from ai.schemas.research_task import (
    MAX_BLOCKER_CHARS,
    MAX_HISTORY,
    MAX_NOTES_CHARS,
    MAX_REFERENCE_CHARS,
    MAX_REFERENCES,
    MAX_RESULT_CHARS,
    MAX_TITLE_CHARS,
    RESEARCH_TASK_RULE_VERSION,
    ResearchTask,
    ResearchTaskAuditEntry,
    TASK_STATUSES,
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
QUEUE_ID_RE = re.compile(r"^rq-[0-9a-f]{16}$")
TASK_ID_RE = re.compile(r"^rt-[0-9a-f]{16}$")
PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

# State machine: only these directed transitions are allowed.
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "TODO": frozenset({"IN_PROGRESS"}),
    "IN_PROGRESS": frozenset({"BLOCKED", "DONE"}),
    "BLOCKED": frozenset({"IN_PROGRESS"}),
    "DONE": frozenset(),
}

DEFAULT_TASKS_DIR = "ai_data/research/tasks"


class TaskStoreError(ValueError):
    """Base class for research-workflow store failures."""


class TaskNotFound(TaskStoreError):
    """No persisted task for the given id."""


class TaskValidationError(TaskStoreError):
    """Invalid input, transition, or missing required field."""


class StaleTaskError(TaskStoreError):
    """expected_version did not match the current task version."""


def task_id_for(cve: str, program: str, queue_id: str) -> str:
    """Deterministic research-task id (no randomness, no time)."""

    basis = (
        f"{RESEARCH_TASK_RULE_VERSION}\n{cve}\n{program}\n{queue_id}"
    )
    return "rt-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded(value: object, limit: int, field: str, *, strip: bool = True) -> str:
    text = str(value if value is not None else "")
    if strip:
        text = text.strip()
    if len(text) > limit:
        raise TaskValidationError(
            f"{field} exceeds {limit} characters"
        )
    return text


def _validate_cve(value: object) -> str:
    text = str(value or "").strip()
    if not CVE_RE.match(text):
        raise TaskValidationError(f"malformed CVE id: {value!r}")
    return text


def _validate_program(value: object) -> str:
    text = str(value or "").strip()
    if not PROGRAM_RE.match(text):
        raise TaskValidationError(f"malformed program name: {value!r}")
    return text


def _validate_queue_id(value: object) -> str:
    text = str(value or "").strip()
    if not QUEUE_ID_RE.match(text):
        raise TaskValidationError(f"malformed queue id: {value!r}")
    return text


def _validate_task_id(value: object) -> str:
    text = str(value or "").strip()
    if not TASK_ID_RE.match(text):
        raise TaskValidationError(f"malformed task id: {value!r}")
    return text


def _validate_references(values: object) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise TaskValidationError("references must be a list")
    if len(values) > MAX_REFERENCES:
        raise TaskValidationError(
            f"references exceed {MAX_REFERENCES} entries"
        )
    bounded: list[str] = []
    for item in values:
        text = _bounded(item, MAX_REFERENCE_CHARS, "reference")
        if text:
            bounded.append(text)
    return bounded


class ResearchTaskStore:
    """Atomic, idempotent, corruption-resistant local task store."""

    def __init__(self, root_dir: str | Path = DEFAULT_TASKS_DIR):
        self.root_dir = Path(root_dir)

    # -- helpers ------------------------------------------------------------
    def _path(self, task_id: str) -> Path:
        safe_id = _validate_task_id(task_id)
        return self.root_dir / f"{safe_id}.json"

    @contextmanager
    def _locked(self):
        """Exclusive advisory lock serializing read-check-write mutations."""

        self.root_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.root_dir / ".tasks.lock"
        handle = open(lock_path, "a+")
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            handle.close()

    def _read(self, task_id: str) -> ResearchTask:
        path = self._path(task_id)
        if not path.exists():
            raise TaskNotFound(f"unknown task id: {task_id}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise TaskNotFound(f"unknown task id: {task_id}") from None
        except (OSError, ValueError) as exc:
            raise TaskStoreError(
                f"unreadable task artifact {path.name}"
            ) from exc
        try:
            return ResearchTask.model_validate(payload)
        except ValueError as exc:
            raise TaskStoreError(
                f"invalid task artifact {path.name}"
            ) from exc

    def _write(self, task: ResearchTask) -> None:
        """Atomic write: temp file in the same dir, then os.replace."""

        self.root_dir.mkdir(parents=True, exist_ok=True)
        path = self._path(task.task_id)
        payload = json.dumps(
            task.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{task.task_id}.", suffix=".tmp", dir=str(self.root_dir)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass

    # -- operations ---------------------------------------------------------
    def create(
        self,
        cve: str,
        program: str,
        queue_id: str,
        title: str | None = None,
        notes: str | None = None,
        references: object = None,
    ) -> tuple[ResearchTask, bool]:
        """Create (or idempotently return) a research task.

        Returns ``(task, created)``. Calling twice with the same
        CVE/program/queue_id returns the existing task (``created=False``) and
        never duplicates or overwrites it.
        """

        cve = _validate_cve(cve)
        program = _validate_program(program)
        queue_id = _validate_queue_id(queue_id)
        title_text = _bounded(title or "", MAX_TITLE_CHARS, "title")
        notes_text = _bounded(notes or "", MAX_NOTES_CHARS, "notes")
        references_list = _validate_references(references)
        task_id = task_id_for(cve, program, queue_id)

        with self._locked():
            path = self._path(task_id)
            if path.exists():
                return self._read(task_id), False

            now = _utcnow()
            task = ResearchTask(
                task_id=task_id,
                cve=cve,
                program=program,
                queue_id=queue_id,
                status="TODO",
                title=title_text or f"{cve} -> {program}",
                notes=notes_text,
                created_at=now,
                updated_at=now,
                references=references_list,
                rule_version=RESEARCH_TASK_RULE_VERSION,
                version=1,
                history=[
                    ResearchTaskAuditEntry(
                        at=now,
                        previous_status="",
                        new_status="TODO",
                        version=1,
                    )
                ],
            )
            self._write(task)
            return task, True

    def get(self, task_id: str) -> ResearchTask:
        return self._read(task_id)

    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
        cve: str | None = None,
    ) -> dict:
        """Capped deterministic task list (task_id ascending)."""

        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 50
        limit = min(max(limit, 1), 100)
        try:
            offset = max(int(offset or 0), 0)
        except (TypeError, ValueError):
            offset = 0
        status_filter = str(status or "").strip().upper()
        cve_filter = str(cve or "").strip().upper()

        tasks: list[ResearchTask] = []
        if self.root_dir.exists():
            for path in sorted(self.root_dir.glob("*.json")):
                stem = path.stem
                if not TASK_ID_RE.match(stem):
                    continue
                try:
                    tasks.append(self._read(stem))
                except TaskStoreError:
                    # Corruption-resistant: a bad file never breaks the list.
                    continue
        if status_filter:
            tasks = [t for t in tasks if t.status == status_filter]
        if cve_filter:
            tasks = [t for t in tasks if t.cve == cve_filter]
        tasks.sort(key=lambda task: task.task_id)
        total = len(tasks)
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "items": [
                task.model_dump(mode="json")
                for task in tasks[offset : offset + limit]
            ],
        }

    def update(
        self,
        task_id: str,
        expected_version: int,
        status: str | None = None,
        notes: str | None = None,
        blocker: str | None = None,
        result_summary: str | None = None,
        references: object = None,
    ) -> ResearchTask:
        """Apply a validated, version-checked task mutation."""

        safe_id = _validate_task_id(task_id)
        try:
            expected = int(expected_version)
        except (TypeError, ValueError):
            raise TaskValidationError(
                "expected_version must be an integer"
            ) from None

        with self._locked():
            task = self._read(safe_id)
            if task.version != expected:
                raise StaleTaskError(
                    f"stale task version: expected {expected}, "
                    f"current {task.version}"
                )
            previous_status = task.status

            updates: dict = {}
            if notes is not None:
                updates["notes"] = _bounded(
                    notes, MAX_NOTES_CHARS, "notes"
                )
            if blocker is not None:
                updates["blocker"] = _bounded(
                    blocker, MAX_BLOCKER_CHARS, "blocker"
                )
            if result_summary is not None:
                updates["result_summary"] = _bounded(
                    result_summary, MAX_RESULT_CHARS, "result_summary"
                )
            if references is not None:
                updates["references"] = _validate_references(references)

            new_status = task.status
            if status is not None:
                candidate = str(status).strip().upper()
                if candidate not in TASK_STATUSES:
                    raise TaskValidationError(
                        f"invalid status: {status!r}"
                    )
                if candidate != task.status:
                    if candidate not in ALLOWED_TRANSITIONS.get(
                        task.status, frozenset()
                    ):
                        raise TaskValidationError(
                            f"invalid transition {task.status} -> {candidate}"
                        )
                    new_status = candidate

            updated = task.model_copy(update={**updates, "status": new_status})

            # Required-field gates apply to the resulting state.
            if new_status == "BLOCKED" and not updated.blocker.strip():
                raise TaskValidationError(
                    "BLOCKED requires a non-empty blocker"
                )
            if new_status == "DONE" and not updated.result_summary.strip():
                raise TaskValidationError(
                    "DONE requires a non-empty result_summary"
                )

            now = _utcnow()
            updated.updated_at = now
            if new_status == "DONE" and previous_status != "DONE":
                updated.completed_at = now
            updated.version = task.version + 1
            updated.history = (
                list(task.history)
                + [
                    ResearchTaskAuditEntry(
                        at=now,
                        previous_status=previous_status,
                        new_status=new_status,
                        version=updated.version,
                    )
                ]
            )[-MAX_HISTORY:]

            self._write(updated)
            return updated
