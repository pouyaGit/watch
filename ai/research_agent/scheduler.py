"""Deterministic, bounded research scheduler (Stage R23).

The scheduler does NOT pick arbitrary targets. Its only input is the existing
R22 Research Execution Plan projection. It enforces:

- disabled by default
- a configured time window in an explicit timezone (never the system clock)
- max wall-clock runtime and max plans per run
- one plan at a time, deterministic ordering, fail-soft per plan
- a single-worker file lock (no overlapping research)
- it runs once and exits (never continuously)
"""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator
from zoneinfo import ZoneInfo

__all__ = [
    "SchedulerConfig",
    "ResearchScheduler",
    "RUN_STATUS_COMPLETED",
    "RUN_STATUS_PARTIAL",
    "RUN_STATUS_BLOCKED",
    "RUN_STATUS_FAILED",
    "parse_hhmm",
    "in_window",
    "next_window_start",
    "priority_rank",
    "select_plans",
    "acquire_lock",
]

RUN_STATUS_COMPLETED = "RESEARCH_COMPLETED"
RUN_STATUS_PARTIAL = "RESEARCH_PARTIAL"
RUN_STATUS_BLOCKED = "RESEARCH_BLOCKED"
RUN_STATUS_FAILED = "RESEARCH_FAILED"

_PRIORITY_RANK = {
    "CRITICAL_RESEARCH": 0,
    "HIGH_RESEARCH": 1,
    "MEDIUM_RESEARCH": 2,
    "LOW_RESEARCH": 3,
    "INSUFFICIENT_DATA": 4,
}

PLAN_COMPLETED = "RESEARCH_PLAN_COMPLETED"


def _parse_int(value: str | None, default: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return parsed


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def parse_hhmm(value: str) -> int:
    """Parse ``"HH:MM"`` -> minutes since midnight. Raises on malformed input."""
    text = str(value or "").strip()
    parts = text.split(":")
    if len(parts) != 2:
        raise ValueError(f"expected HH:MM, got {value!r}")
    hour, minute = int(parts[0]), int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"invalid time of day: {value!r}")
    return hour * 60 + minute


def in_window(
    now: datetime, window_start: str, window_end: str
) -> bool:
    """True when ``now`` (already in the configured tz) is inside the window.

    Supports windows crossing midnight (e.g. 18:00 -> 00:00 or 22:00 -> 06:00).
    A zero-length window (start == end) is always closed.
    """
    start = parse_hhmm(window_start)
    end = parse_hhmm(window_end)
    if start == end:
        return False
    current = now.hour * 60 + now.minute
    if start < end:
        return start <= current < end
    return current >= start or current < end


def next_window_start(
    now: datetime, window_start: str, window_end: str
) -> datetime:
    """Next occurrence of the window start at/after ``now`` (same tz)."""
    start = parse_hhmm(window_start)
    hh, mm = divmod(start, 60)
    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if candidate <= now:
        candidate = candidate + timedelta(days=1)
    return candidate


def priority_rank(priority_level: str | None) -> int:
    return _PRIORITY_RANK.get(str(priority_level or ""), 5)


def select_plans(plans: list[dict], max_plans: int) -> list[dict]:
    """Deterministic bounded plan selection (never arbitrary).

    Priority classes first (CRITICAL > HIGH > MEDIUM > LOW > other), then
    within a class: R22 recommended_start, relevance score (desc),
    priority score (desc), CVE, program. Completed plans are excluded.
    """
    if not plans:
        return []
    eligible = [
        plan
        for plan in plans
        if isinstance(plan, dict) and plan.get("status") != PLAN_COMPLETED
    ]

    def _key(plan: dict):
        meta = plan.get("metadata") or {}
        return (
            priority_rank(meta.get("priority_level")),
            str(plan.get("recommended_start") or ""),
            -_parse_int(plan.get("relevance_score"), 0),
            -_parse_int(plan.get("priority_score"), 0),
            str(plan.get("cve_id") or ""),
            str(plan.get("program") or ""),
            str(plan.get("plan_id") or ""),
        )

    eligible.sort(key=_key)
    return eligible[: max(int(max_plans), 0)]


@contextmanager
def acquire_lock(path: str | Path) -> Iterator[bool]:
    """Non-blocking exclusive file lock. Yields False when unavailable."""
    lock_path = Path(path)
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        yield False
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(fd)


@dataclass
class SchedulerConfig:
    enabled: bool = False
    window_start: str = "18:00"
    window_end: str = "00:00"
    max_minutes: int = 300
    max_plans: int = 5
    timezone: str = "Asia/Tehran"
    # Bounded public research fetching is on by default (the agent's purpose);
    # disable with WATCH_RESEARCH_NETWORK=false or --no-network. Dry-run is
    # always zero-network regardless.
    network: bool = True
    llm: bool = False
    max_sources: int = 12
    kb_ingest: bool = False
    lock_path: str = "/run/watch-research.lock"
    agent_dir: str = "ai_data/research/agent"
    research_dir: str = "ai_data/research"

    @classmethod
    def from_env(cls, env: dict | None = None) -> "SchedulerConfig":
        source = os.environ if env is None else env

        def get(name: str, default: str | None = None):
            return source.get(name, default)

        return cls(
            enabled=_parse_bool(get("WATCH_RESEARCH_ENABLED"), False),
            window_start=str(get("WATCH_RESEARCH_WINDOW_START", "18:00")),
            window_end=str(get("WATCH_RESEARCH_WINDOW_END", "00:00")),
            max_minutes=_parse_int(get("WATCH_RESEARCH_MAX_MINUTES"), 300),
            max_plans=_parse_int(get("WATCH_RESEARCH_MAX_PLANS"), 5),
            timezone=str(get("WATCH_RESEARCH_TIMEZONE", "Asia/Tehran")),
            network=_parse_bool(get("WATCH_RESEARCH_NETWORK"), True),
            llm=_parse_bool(get("WATCH_RESEARCH_LLM"), False),
            max_sources=_parse_int(get("WATCH_RESEARCH_MAX_SOURCES"), 12),
            kb_ingest=_parse_bool(get("WATCH_RESEARCH_KB_INGEST"), False),
            lock_path=str(get("WATCH_RESEARCH_LOCK", "/run/watch-research.lock")),
            agent_dir=str(
                get("WATCH_RESEARCH_AGENT_DIR", "ai_data/research/agent")
            ),
            research_dir=str(
                get("WATCH_RESEARCH_RESEARCH_DIR", "ai_data/research")
            ),
        )

    @property
    def tzinfo(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    def window_label(self) -> str:
        return f"{self.window_start}-{self.window_end} {self.timezone}"


def _default_plan_loader() -> list[dict]:
    try:
        from backend import research_execution

        return research_execution.build_plans()
    except Exception:
        return []


def _run_id_for(now: datetime) -> str:
    return "run-" + now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class ResearchScheduler:
    """One-shot, bounded, deterministic scheduler over R22 plans."""

    def __init__(
        self,
        config: SchedulerConfig | None = None,
        *,
        agent: object | None = None,
        plan_loader: Callable[[], list[dict]] | None = None,
        now_fn: Callable[[], datetime] | None = None,
        monotonic_fn: Callable[[], float] | None = None,
    ) -> None:
        self.config = config or SchedulerConfig.from_env()
        self.agent = agent
        self.plan_loader = plan_loader or _default_plan_loader
        self._now_fn = now_fn
        self._monotonic = monotonic_fn or (lambda: __import__("time").monotonic())

    # -- time -------------------------------------------------------------
    def _now(self) -> datetime:
        if self._now_fn is not None:
            now = self._now_fn()
            if now.tzinfo is None:
                now = now.replace(tzinfo=self.config.tzinfo)
            return now.astimezone(self.config.tzinfo)
        return datetime.now(self.config.tzinfo)

    def in_window(self, now: datetime | None = None) -> bool:
        moment = now or self._now()
        return in_window(moment, self.config.window_start, self.config.window_end)

    def next_run(self, now: datetime | None = None) -> str:
        moment = now or self._now()
        return next_window_start(
            moment, self.config.window_start, self.config.window_end
        ).isoformat()

    # -- read-only preview ------------------------------------------------
    def status(self, now: datetime | None = None) -> dict:
        moment = now or self._now()
        plans = self.plan_loader() or []
        eligible = select_plans(plans, self.config.max_plans)
        return {
            "enabled": self.config.enabled,
            "window": self.config.window_label(),
            "window_start": self.config.window_start,
            "window_end": self.config.window_end,
            "timezone": self.config.timezone,
            "in_window": in_window(
                moment, self.config.window_start, self.config.window_end
            ),
            "max_minutes": self.config.max_minutes,
            "max_plans": self.config.max_plans,
            "network": self.config.network,
            "llm": self.config.llm,
            "eligible_plans": eligible,
            "eligible_count": len(eligible),
            "total_plans": len(plans),
            "next_run": self.next_run(moment),
            "now": moment.isoformat(),
        }

    def preview(
        self,
        *,
        now: datetime | None = None,
        plan_id: str | None = None,
        limit: int | None = None,
    ) -> dict:
        moment = now or self._now()
        plans = self.plan_loader() or []
        if plan_id:
            plans = [p for p in plans if p.get("plan_id") == plan_id]
        cap = self.config.max_plans if limit is None else max(int(limit), 0)
        selected = select_plans(plans, cap)
        return {
            "enabled": self.config.enabled,
            "in_window": in_window(
                moment, self.config.window_start, self.config.window_end
            ),
            "window": self.config.window_label(),
            "network": self.config.network,
            "llm": self.config.llm,
            "plans": selected,
        }

    # -- execution --------------------------------------------------------
    def run_once(
        self,
        *,
        now: datetime | None = None,
        plan_id: str | None = None,
        limit: int | None = None,
        force: bool = False,
        dry_run: bool = False,
        network: bool | None = None,
    ) -> dict:
        moment = now or self._now()
        started_at = moment.isoformat()
        run_id = _run_id_for(moment)
        record: dict = {
            "run_id": run_id,
            "started_at": started_at,
            "completed_at": started_at,
            "dry_run": bool(dry_run),
            "forced": bool(force),
            "enabled": self.config.enabled,
            "in_window": in_window(
                moment, self.config.window_start, self.config.window_end
            ),
            "window": self.config.window_label(),
            "network": self.config.network if network is None else bool(network),
            "llm": self.config.llm,
            "plans_selected": 0,
            "plans_processed": 0,
            "result_ids": [],
            "results": [],
            "failures": [],
            "status": RUN_STATUS_BLOCKED,
            "skipped": None,
        }

        if not force:
            if not self.config.enabled:
                record["skipped"] = "disabled"
                record["completed_at"] = (now or self._now()).isoformat()
                return record
            if not in_window(moment, self.config.window_start, self.config.window_end):
                record["skipped"] = "outside_window"
                record["completed_at"] = (now or self._now()).isoformat()
                return record

        with acquire_lock(self.config.lock_path) as locked:
            if not locked:
                record["skipped"] = "locked"
                record["completed_at"] = (now or self._now()).isoformat()
                return record

            plans = self.plan_loader() or []
            if plan_id:
                plans = [p for p in plans if p.get("plan_id") == plan_id]
            cap = self.config.max_plans if limit is None else max(int(limit), 0)
            selected = select_plans(plans, cap)
            record["plans_selected"] = len(selected)

            if dry_run:
                record["status"] = (
                    RUN_STATUS_BLOCKED if not selected else RUN_STATUS_COMPLETED
                )
                record["skipped"] = "dry_run"
                record["results"] = [
                    {
                        "plan_id": p.get("plan_id"),
                        "cve_id": p.get("cve_id"),
                        "program": p.get("program"),
                    }
                    for p in selected
                ]
                record["completed_at"] = (now or self._now()).isoformat()
                # dry-run never writes (no results, no run record)
                return record

            if not selected:
                record["status"] = RUN_STATUS_BLOCKED
                record["completed_at"] = (now or self._now()).isoformat()
                from ai.research_agent import storage
                storage.store_run(record, base=self.config.agent_dir)
                return record

            if self.agent is None:
                record["status"] = RUN_STATUS_FAILED
                record["failures"].append({"error": "no agent configured"})
                record["completed_at"] = (now or self._now()).isoformat()
                from ai.research_agent import storage
                storage.store_run(record, base=self.config.agent_dir)
                return record

            deadline = self._monotonic() + max(self.config.max_minutes, 0) * 60

            def _expired() -> bool:
                return self._monotonic() >= deadline

            try:
                results, failures = self.agent.run_plans(
                    selected,
                    run_id=run_id,
                    deadline=deadline,
                    dry_run=False,
                    network=network,
                    persist=True,
                    per_plan_timeout=_expired,
                )
            except Exception as exc:  # never propagate; a run is fail-soft
                record["status"] = RUN_STATUS_FAILED
                record["failures"].append({"error": type(exc).__name__})
                record["completed_at"] = (now or self._now()).isoformat()
                from ai.research_agent import storage
                storage.store_run(record, base=self.config.agent_dir)
                return record

            record["failures"] = failures
            record["plans_processed"] = len(results)
            record["results"] = [
                {
                    "plan_id": r.plan_id,
                    "result_id": r.result_id,
                    "cve_id": r.cve_id,
                    "program": r.program,
                    "status": r.status,
                    "evidence": len(r.evidence),
                    "sources": len(r.sources),
                }
                for r in results
            ]
            record["result_ids"] = [r.result_id for r in results]
            if failures and results:
                record["status"] = RUN_STATUS_PARTIAL
            elif failures and not results:
                record["status"] = RUN_STATUS_FAILED
            else:
                record["status"] = RUN_STATUS_COMPLETED
            record["completed_at"] = (now or self._now()).isoformat()
            from ai.research_agent import storage
            storage.store_run(record, base=self.config.agent_dir)
            return record
