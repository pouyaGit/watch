"""backend/research_activity.py — Stage R83 read-only AI activity collector.

Gathers the real runtime facts the R83 core (``ai.knowledge.ai_activity_status``)
projects into the bounded activity contract:

- agent run records persisted by the existing R23 scheduler
  (``ai_data/research/agent/runs/<run_id>.json`` via
  ``ai.research_agent.storage``);
- bounded research case artifact summaries (R64-R77 envelopes) and their real
  modification times;
- a real liveness probe on the scheduler lock file(s) the running service
  holds while a research run executes;
- the scheduler window policy (``SchedulerConfig.from_env``; the code
  defaults are 12:00-00:00 Asia/Tehran, the same window the systemd service
  enforces).

Read-only by construction: no Mongo, no network, no process spawning, no
LLM, no writes. The lock probe opens the lock file read-only and takes a shared
non-blocking lock that is released immediately; it never creates or modifies
a file. Missing observability is reported, never invented.
"""

from __future__ import annotations

import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from ai.knowledge.ai_activity_status import (
    DEFAULT_WINDOW_END,
    DEFAULT_WINDOW_START,
    LOCK_FREE,
    LOCK_HELD,
    LOCK_UNAVAILABLE,
    build_activity_status,
    to_tehran,
)

RULE_VERSION = "r83-1"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AGENT_DIR = PROJECT_ROOT / "ai_data" / "research" / "agent"
DEFAULT_RESEARCH_DIR = PROJECT_ROOT / "ai_data" / "research"

#: The running systemd service holds the app lock under its RuntimeDirectory;
#: the plain default path is also probed for manual/CLI runs.
SERVICE_LOCK_CANDIDATES: tuple[str, ...] = (
    "/run/watch-research/research.lock",
    "/run/watch-research.lock",
)

MAX_RUNS = 50
MAX_CASES = 32

SOURCE_NOTES: tuple[str, ...] = (
    "run records are written by the scheduler when a run finishes; an "
    "in-flight run has no record yet",
    "the in-flight case and research stage are not persisted by the agent, "
    "so they are reported as unknown while RUNNING",
    "the execution lock probe is a shared, non-blocking, immediately-released "
    "read-only check",
    "window policy comes from WATCH_RESEARCH_* environment values with the "
    "code defaults 12:00-00:00 Asia/Tehran",
)


def _text(value: object, limit: int = 320) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _project_path(value: object, default: Path) -> Path:
    text = _text(value, 512)
    if not text:
        return default
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate


def agent_dir() -> Path:
    return _project_path(os.environ.get("WATCH_RESEARCH_AGENT_DIR"), DEFAULT_AGENT_DIR)


def research_dir() -> Path:
    return _project_path(
        os.environ.get("WATCH_RESEARCH_RESEARCH_DIR"), DEFAULT_RESEARCH_DIR
    )


def lock_paths() -> list[str]:
    paths: list[str] = []
    configured = _text(os.environ.get("WATCH_RESEARCH_LOCK"), 512)
    if configured:
        paths.append(configured)
    for candidate in SERVICE_LOCK_CANDIDATES:
        if candidate not in paths:
            paths.append(candidate)
    return paths


def probe_lock(paths: object = None) -> tuple[str, list[str]]:
    """Return ``(lock_state, notes)`` using a read-only shared flock probe."""

    notes: list[str] = []
    candidates = [str(path) for path in (paths or lock_paths())]
    permission_denied = False
    for candidate in candidates:
        try:
            fd = os.open(candidate, os.O_RDONLY)
        except FileNotFoundError:
            continue
        except PermissionError:
            permission_denied = True
            continue
        except OSError:
            permission_denied = True
            continue
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError:
                return LOCK_HELD, [f"lock held: {Path(candidate).name}"]
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            return LOCK_FREE, notes
        finally:
            os.close(fd)
    if permission_denied:
        notes.append("lock path not readable")
        return LOCK_UNAVAILABLE, notes
    return LOCK_FREE, notes


def read_run_records(base: object = None, limit: int = MAX_RUNS) -> list[dict]:
    """Bounded newest-first agent run records (read-only)."""

    from ai.research_agent import storage

    directory = Path(base) if base is not None else agent_dir()
    records = storage.list_runs(base=directory)
    newest = list(reversed(records))[:limit]
    return [dict(record) for record in newest]


def _block(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _case_record(payload: Mapping, modified_iso: str) -> dict:
    workspace = payload.get("research_case_workspace")
    cases = []
    if isinstance(workspace, Mapping):
        raw_cases = workspace.get("cases")
        if isinstance(raw_cases, (list, tuple)):
            cases = [case for case in raw_cases if isinstance(case, Mapping)]
    if not cases:
        return {}
    case = cases[0]
    validation = payload.get("validation")
    validation = validation if isinstance(validation, Mapping) else {}
    acquisition = payload.get("acquisition_plan")
    acquisition = acquisition if isinstance(acquisition, Mapping) else {}
    action_plan = payload.get("action_plan")
    action_plan = action_plan if isinstance(action_plan, Mapping) else {}
    readiness = case.get("readiness")
    readiness = readiness if isinstance(readiness, Mapping) else {}
    return {
        "case_id": _text(case.get("case_id"), 96),
        "program": _text(payload.get("program") or case.get("program"), 64),
        "category": _text(case.get("category"), 64),
        "case_status": _text(case.get("status"), 40),
        "sufficiency_state": _text(readiness.get("sufficiency_state"), 40),
        "decision_state": _text(readiness.get("decision_state"), 40),
        "available_count": _text(
            _block(case.get("evidence")).get("available_count"), 8
        ),
        "missing_count": _text(
            _block(case.get("evidence")).get("missing_count"), 8
        ),
        "actions_count": _text(
            _block(action_plan.get("summary")).get("action_count"), 8
        ),
        "validation_accepted": _text(validation.get("accepted_count"), 8),
        "validation_rejected": _text(validation.get("rejected_count"), 8),
        "modified_at": modified_iso,
    }


def read_case_records(
    root: object = None, limit: int = MAX_CASES
) -> list[dict]:
    """Bounded newest-first research case summaries (read-only)."""

    directory = Path(root) if root is not None else research_dir()
    if not directory.is_dir():
        return []
    records: list[dict] = []
    for path in sorted(directory.glob("*/*.json")):
        if path.name.endswith(".tmp"):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            modified = path.stat().st_mtime
        except (OSError, ValueError):
            continue
        if not isinstance(payload, Mapping):
            continue
        record = _case_record(payload, "")
        if not record or not record.get("case_id"):
            continue
        record["modified_at"] = _text(
            (
                to_tehran(datetime.fromtimestamp(modified, tz=timezone.utc))
                or datetime.now(timezone.utc)
            ).isoformat(),
            64,
        )
        records.append(record)
    records.sort(key=lambda record: record.get("modified_at") or "", reverse=True)
    return records[:limit]


def _scheduler_policy() -> dict:
    from ai.research_agent.scheduler import SchedulerConfig

    config = SchedulerConfig.from_env()
    return {
        "window_start": config.window_start or DEFAULT_WINDOW_START,
        "window_end": config.window_end or DEFAULT_WINDOW_END,
        "timezone": config.timezone or "Asia/Tehran",
        "enabled": bool(config.enabled),
    }


def collect_activity(
    *,
    now: object = None,
    agent_base: object = None,
    research_base: object = None,
    lock_candidates: object = None,
) -> dict:
    """Collect the real facts and project the bounded activity contract."""

    notes = list(SOURCE_NOTES)
    errors: list[str] = []
    try:
        policy = _scheduler_policy()
    except Exception as exc:
        policy = {
            "window_start": DEFAULT_WINDOW_START,
            "window_end": DEFAULT_WINDOW_END,
            "timezone": "Asia/Tehran",
            "enabled": None,
        }
        errors.append(f"scheduler_policy:{type(exc).__name__}")

    try:
        lock_state, lock_notes = probe_lock(lock_candidates)
        notes.extend(lock_notes)
    except Exception as exc:
        lock_state = LOCK_UNAVAILABLE
        errors.append(f"lock_probe:{type(exc).__name__}")

    try:
        runs = read_run_records(agent_base)
    except Exception as exc:
        runs = []
        errors.append(f"run_records:{type(exc).__name__}")

    try:
        cases = read_case_records(research_base)
    except Exception as exc:
        cases = []
        errors.append(f"case_records:{type(exc).__name__}")

    return build_activity_status(
        run_records=runs,
        case_records=cases,
        lock_state=lock_state,
        window_start=policy["window_start"],
        window_end=policy["window_end"],
        timezone_name=policy["timezone"],
        scheduler_enabled=policy["enabled"],
        now=now,
        source_notes=notes,
        source_errors=errors,
    )


__all__ = [
    "RULE_VERSION",
    "DEFAULT_AGENT_DIR",
    "DEFAULT_RESEARCH_DIR",
    "SERVICE_LOCK_CANDIDATES",
    "SOURCE_NOTES",
    "agent_dir",
    "research_dir",
    "lock_paths",
    "probe_lock",
    "read_run_records",
    "read_case_records",
    "collect_activity",
]
