"""EPIC9 §3: the bounded AI Operations Dispatcher — one tick, then exit.

Tick model (no persistent worker, no daemon, no 24/7 loop):

    acquire tick lock (existing flock mechanism)
      -> window gate (12:00-00:00 Asia/Tehran, start inclusive /
         end exclusive; outside => OFF_WINDOW, nothing starts)
      -> recover interrupted tick state (lock proves no live peer)
      -> RuntimeStore.sweep()   (existing stale-lease recovery)
      -> discover work          (existing stores only, fail-soft)
      -> prioritize + bounded fairness selection
      -> execute <= max_work units, each through the EXISTING
         executors (AgentWorker / execute_campaign / run_findings)
      -> persist truthful activity + operations state
      -> release lock, exit

Hard boundaries:

* The window check cannot be disabled by any environment variable.
* NEEDS_EVIDENCE items are classified WAITING_FOR_EVIDENCE and are never
  executed, reclassified or faked (§6); other executable work continues.
* Authorization, scope, evidence sufficiency, leases and verification
  remain with the existing executors/gates — this module adds an
  eligibility pre-filter, it never grants anything.
* Budgets stop scheduling NEW units (STOP_GRACEFULLY between items,
  never mid-transition); the tick records reason, completed work and
  remaining work.
* Zero LLM usage: runners are invoked without advisor/provider options,
  so the deterministic paths are used (existing architecture decides
  if a provider is permitted; nothing here can introduce one).
* Execution runners are injectable for tests; production defaults are
  the real executors.
"""

from __future__ import annotations

import fcntl
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend.ai_ops import activity as act
from backend.ai_ops import state as ops_state
from backend.ai_ops.config import DispatcherConfig
from backend.ai_ops.discovery import (
    BUDGET_DEFERRED,
    CLASS_CAMPAIGN,
    CLASS_FINDING,
    CLASS_JOB,
    EXECUTABLE_CLASSES,
    WAITING_FOR_EVIDENCE,
    WorkItem,
    discover,
)
from backend.ai_ops.priority import select_bounded
from backend.ai_ops.window import DEFAULT_WINDOW

RUNNER = Callable[[WorkItem, "TickBudget"], dict[str, Any]]


class TickBudget:
    """Shared wall-clock + item budget for one tick (§9)."""

    def __init__(self, max_seconds: float, max_work: int) -> None:
        self.started = time.monotonic()
        self.max_seconds = float(max_seconds)
        self.max_work = int(max_work)

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def wall_exhausted(self) -> bool:
        return self.elapsed() >= self.max_seconds

    def remaining_seconds(self) -> float:
        return max(0.0, self.max_seconds - self.elapsed())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _tick_id() -> str:
    return f"tick-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-" \
           f"{uuid.uuid4().hex[:8]}"


def _bounded(value: Any, limit: int = 300) -> str:
    try:
        text = value if isinstance(value, str) else json.dumps(
            value, ensure_ascii=True, default=str, sort_keys=True)
    except (TypeError, ValueError):
        text = str(value)
    return text[:limit]


# --------------------------------------------------------- real runners

def run_jobs_runner(store: Any, item: WorkItem, budget: TickBudget,
                    ) -> dict[str, Any]:
    """Existing bounded worker drain (claims via existing flock lease
    path). Configured like ``cli run`` defaults; deterministic provider
    (no LLM options passed)."""
    from backend.research_agents.models import JobStatus
    from backend.research_agents.runtime import AgentWorker, RuntimeConfig

    queued = [j for j in store.list_jobs()
              if j.status in (JobStatus.QUEUED.value, JobStatus.NEW.value)]
    max_jobs = max(1, min(len(queued), budget.max_work))
    config = RuntimeConfig(max_jobs_per_run=max_jobs,
                           lease_seconds=30, job_timeout=120,
                           execution_mode="production")
    worker = AgentWorker(config=config, store=store)
    stats = worker.run(max_jobs=max_jobs)
    return {"runner": "agent_worker", **stats}


def run_campaign_runner(store: Any, item: WorkItem, budget: TickBudget,
                        ) -> dict[str, Any]:
    """Existing campaign orchestrator for exactly one objective bound
    (max_objectives=1; cumulative campaign budgets still apply)."""
    from backend.research_agents.campaign.executor import execute_campaign
    from backend.research_agents.runtime import RuntimeConfig

    config = RuntimeConfig(max_jobs_per_run=1, lease_seconds=30,
                           job_timeout=120, execution_mode="production")
    summary = execute_campaign(item.campaign_id, config=config,
                               store=store, max_objectives=1)
    out = {"runner": "execute_campaign"}
    for attr in ("objectives_executed", "executed", "jobs_claimed",
                 "errors", "skipped", "state"):
        if hasattr(summary, attr):
            out[attr] = getattr(summary, attr)
    if hasattr(summary, "to_dict"):
        out["summary"] = summary.to_dict()
    else:
        out["summary"] = _bounded(summary)
    return out


def run_finding_runner(store: Any, item: WorkItem, budget: TickBudget,
                       ) -> dict[str, Any]:
    """Existing bounded finding pipeline for one completed source job
    (deterministic verification path — no advisor/provider options)."""
    from backend.research_agents.finding.executor import run_findings

    source_job = str(item.meta.get("source_job") or item.source_id)
    wall = max(1.0, budget.remaining_seconds())
    summary = run_findings(source_jobs=[source_job], store=store,
                           max_verifications=1, wall_seconds=wall)
    out = {"runner": "run_findings"}
    if hasattr(summary, "to_dict"):
        out["summary"] = summary.to_dict()
    else:
        out["summary"] = _bounded(summary)
    return out


DEFAULT_RUNNERS: dict[str, RUNNER] = {
    CLASS_JOB: run_jobs_runner,
    CLASS_FINDING: run_finding_runner,
    CLASS_CAMPAIGN: run_campaign_runner,
}


# ------------------------------------------------------------ the tick

def run_tick(*,
             config: DispatcherConfig | None = None,
             store: Any = None,
             now_fn: Callable[[], datetime] | None = None,
             runners: dict[str, RUNNER] | None = None,
             base: Path | str | None = None,
             persist: bool = True,
             ) -> dict[str, Any]:
    """Execute ONE bounded AI operations tick; returns the tick record.

    ``now_fn`` exists for deterministic tests; production uses the real
    clock and the real window check (the window gate always runs).
    """
    cfg = config or DispatcherConfig.from_env()
    now_fn = now_fn or _now

    from backend.research_agents.runtime_store import default_store
    rt = store or default_store()

    # DEFAULT_RUNNERS take (store, item, budget); the tick calls
    # runner(item, budget). Bind the store HERE so the real executors
    # receive it, while injected test runners stay (item, budget).
    def _bind(fn: RUNNER) -> RUNNER:
        def bound(item: WorkItem, budget: "TickBudget",
                  ) -> dict[str, Any]:
            return fn(rt, item, budget)
        return bound

    runner_map: dict[str, RUNNER] = {
        cls: _bind(fn) for cls, fn in DEFAULT_RUNNERS.items()
    }
    if runners:
        runner_map.update(runners)
    base_dir = base if base is not None else getattr(rt, "base", None)

    lock = ops_state.lock_path(base_dir)
    lock.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock, "a+", encoding="utf-8")
    record: dict[str, Any] = {
        "tick_id": _tick_id(), "outcome": "", "window_open": False,
        "discovered": {}, "selected": [], "executed": [],
        "remaining": [], "deferred": [], "errors": [],
        "recovered_interrupted": False, "audit_failures": 0,
        "started_at": now_fn().isoformat(timespec="seconds"),
        "completed_at": "", "tick_seconds": 0.0,
    }
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Another tick owns the lock: report contention truthfully
            # WITHOUT writing state (the live tick is the only writer).
            record["outcome"] = "CONTENDED"
            record["completed_at"] = now_fn().isoformat(
                timespec="seconds")
            return record
        return _tick_locked(cfg, rt, base_dir, now_fn, runner_map,
                            record, persist)
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()


def _tick_locked(cfg: DispatcherConfig, rt: Any, base_dir: Any,
                 now_fn: Callable[[], datetime],
                 runner_map: dict[str, RUNNER],
                 record: dict[str, Any], persist: bool) -> dict[str, Any]:
    started_monotonic = time.monotonic()
    now = now_fn()
    open_now = DEFAULT_WINDOW.is_open(now)
    record["window_open"] = open_now
    doc = ops_state.load_state(base_dir)
    prev_state = doc.get("state", "IDLE")
    prev_open = doc.get("window_open")

    def emit(event: str, **fields: Any) -> None:
        if act.emit(rt, event, record["tick_id"], **fields) is None:
            record["audit_failures"] += 1

    def finish(outcome: str, ops_state_name: str,
               **extra: Any) -> dict[str, Any]:
        record["outcome"] = outcome
        record["operations_state"] = ops_state_name
        record["completed_at"] = now_fn().isoformat(timespec="seconds")
        record["tick_seconds"] = round(time.monotonic()
                                       - started_monotonic, 3)
        record.update(extra)
        if persist:
            doc = ops_state.load_state(base_dir)
            doc["window_open"] = open_now
            doc["current_tick"] = None
            if outcome not in ("CONTENDED",):
                doc["last_tick"] = record
            ops_state.transition(doc, ops_state_name, now=now_fn())
            ops_state.save_state(doc, base_dir)
        return record

    # ---- window gate (§11): outside the window nothing starts -------
    if not open_now:
        if prev_open:
            emit("ai_window_closed", window=DEFAULT_WINDOW.label)
        if prev_state in ("DISCOVERING", "EXECUTING"):
            record["recovered_interrupted"] = True
        record["discovered"] = {"discovered": 0, "executable": 0,
                                "waiting": 0, "blocked": 0,
                                "by_reason": {}, "by_class": {},
                                "source_errors": 0}
        record["remaining"] = []
        return finish("SKIPPED_OUT_OF_WINDOW", "OFF_WINDOW")

    # ---- in window ---------------------------------------------------
    if prev_open is False or prev_open is None:
        emit("ai_window_opened", window=DEFAULT_WINDOW.label)
    if prev_state in ("DISCOVERING", "EXECUTING"):
        record["recovered_interrupted"] = True

    emit("ai_tick_started", window=DEFAULT_WINDOW.label)
    if persist:
        doc = ops_state.load_state(base_dir)
        doc["window_open"] = True
        doc["current_tick"] = {"tick_id": record["tick_id"],
                               "started_at": record["started_at"]}
        ops_state.transition(doc, "DISCOVERING", now=now_fn())
        ops_state.save_state(doc, base_dir)

    # existing stale-lease recovery before discovery (§17)
    try:
        record["sweep"] = rt.sweep()
    except Exception as exc:  # noqa: BLE001 - recorded, never fatal
        record["errors"].append(f"sweep:{type(exc).__name__}")

    try:
        report = discover(
            runtime_store=rt,
            now=now_fn(),
            max_attempts=cfg.max_attempts,
            backoff_seconds=cfg.backoff_seconds,
        )
    except Exception as exc:  # noqa: BLE001 - discovery failure is FAILED
        record["errors"].append(f"discovery:{type(exc).__name__}: "
                                f"{str(exc)[:120]}")
        emit("ai_tick_completed", outcome="FAILED")
        return finish("FAILED", "FAILED")

    record["discovered"] = report.counts()
    record["errors"].extend(f"{e['source']}:{e['error']}"
                            for e in report.errors)
    emit("work_discovered", **report.counts())
    if report.waiting:
        # §13: waiting-for-evidence is meaningful in EVERY tick shape
        # (all-waiting, or mixed with executable work).
        emit("waiting_for_evidence",
             count=len(report.waiting),
             work_ids=[i.work_id for i in report.waiting[:10]])

    executable = report.executable
    if not executable:
        if report.blocked:
            emit("work_blocked", count=len(report.blocked),
                 reasons=report.counts()["by_reason"])
        record["remaining"] = [
            {"work_id": i.work_id, "reason": i.reason,
             "detail": i.detail[:160]}
            for i in report.items if not i.executable
        ]
        non_terminal_blocked = report.counts()["non_terminal_blocked"]
        if report.waiting and not non_terminal_blocked:
            target_state = "WAITING_FOR_EVIDENCE"
        elif non_terminal_blocked:
            target_state = "BLOCKED"
        else:
            # Terminal-only (or nothing at all) discovered is a healthy
            # IDLE — terminal work is not a blocker.
            target_state = "IDLE"
        emit("ai_tick_completed", outcome="COMPLETED_TICK",
             executable=0, waiting=len(report.waiting),
             blocked=len(report.blocked))
        return finish("COMPLETED_TICK", target_state)

    selected, deferred = select_bounded(executable, cfg)
    record["selected"] = [i.work_id for i in selected]
    record["deferred"] = [{"work_id": i.work_id,
                           "reason": BUDGET_DEFERRED,
                           "detail": i.meta.get("deferred_by", "")}
                          for i in deferred]
    emit("work_selected", count=len(selected),
         work_ids=[i.work_id for i in selected[:20]])
    if deferred:
        emit("tick_budget_exhausted", reason="fairness_caps",
             deferred=[i.work_id for i in deferred[:20]])

    if persist:
        doc = ops_state.load_state(base_dir)
        doc["window_open"] = True
        doc["current_tick"] = {"tick_id": record["tick_id"],
                               "started_at": record["started_at"],
                               "selected": record["selected"]}
        ops_state.transition(doc, "EXECUTING", now=now_fn())
        ops_state.save_state(doc, base_dir)

    budget = TickBudget(cfg.max_seconds, cfg.max_work)
    stop_reason = ""
    for item in selected:
        # budgets checked BETWEEN units: never kill mid-transition (§9/§11)
        if budget.wall_exhausted():
            stop_reason = "WALL_BUDGET"
            break
        if len(record["executed"]) >= cfg.max_work:
            stop_reason = "WORK_BUDGET"
            break
        if not DEFAULT_WINDOW.is_open(now_fn()):
            stop_reason = "WINDOW_CLOSED"
            break
        runner = runner_map.get(item.work_class)
        emit("work_started", work_id=item.work_id,
             work_class=item.work_class, target=item.target or
             item.scope_ref, source_id=item.source_id,
             state=item.state)
        if runner is None:
            emit("work_blocked", work_id=item.work_id,
                 work_class=item.work_class, reason="NO_RUNNER",
                 detail="no executor for class")
            record["executed"].append({"work_id": item.work_id,
                                       "outcome": "blocked",
                                       "reason": "NO_RUNNER"})
            continue
        try:
            result = runner(item, budget)
            outcome = _outcome_of(result)
        except Exception as exc:  # noqa: BLE001 - bounded, honest
            outcome = "failed"
            result = {"error": type(exc).__name__,
                      "detail": str(exc)[:200]}
        entry = {"work_id": item.work_id, "work_class": item.work_class,
                 "target": item.target or item.scope_ref,
                 "outcome": outcome, "result": _bounded(result)}
        record["executed"].append(entry)
        if outcome in ("completed", "executed"):
            emit("work_completed", work_id=item.work_id,
                 work_class=item.work_class, target=item.target or
                 item.scope_ref, source_id=item.source_id,
                 state="done")
        else:
            emit("work_blocked", work_id=item.work_id,
                 work_class=item.work_class,
                 target=item.target or item.scope_ref,
                 source_id=item.source_id, reason=outcome.upper(),
                 detail=_bounded(result, 160))

    done_ids = {e["work_id"] for e in record["executed"]}
    record["remaining"] = [
        {"work_id": i.work_id, "reason":
            BUDGET_DEFERRED if i.work_id not in done_ids else "executed",
         "detail": i.meta.get("deferred_by", "")}
        for i in deferred
    ] + [{"work_id": i.work_id, "reason": i.reason,
          "detail": i.detail[:160]}
         for i in report.items
         if not i.executable]
    if stop_reason:
        record["stop_reason"] = stop_reason
        emit("tick_budget_exhausted", reason=stop_reason,
             completed=len(record["executed"]),
             remaining=len(record["remaining"]))
        outcome = "BUDGET_EXHAUSTED"
    else:
        outcome = "COMPLETED_TICK"
    emit("ai_tick_completed", outcome=outcome,
         executable=len(executable), executed=len(record["executed"]),
         remaining=len(record["remaining"]))
    return finish(outcome, "COMPLETED_TICK")


def _outcome_of(result: dict[str, Any]) -> str:
    """Derive an honest outcome from a runner result — never assume
    success: explicit error keys fail, explicit counters decide."""
    if not isinstance(result, dict):
        return "completed" if result else "failed"
    if result.get("error"):
        return "failed"
    summary = result.get("summary")
    if isinstance(summary, dict) and summary.get("errors"):
        errors = summary["errors"]
        if errors and not any(k in result for k in
                              ("claimed", "processed", "objectives")):
            return "blocked"
    for key in ("claimed", "processed", "objectives_executed",
                "executed"):
        value = result.get(key)
        if isinstance(value, int) and value > 0:
            return "completed"
    if "summary" in result or "runner" in result:
        # runner finished its bounded pass without an error marker
        if isinstance(summary, dict) and summary.get("errors"):
            return "blocked"
        return "completed"
    return "completed" if result.get("ok") else "failed"


# ---------------------------------------------- scheduler integration §10

def maybe_run_from_scheduler(
    *, config: DispatcherConfig | None = None,
) -> dict[str, Any] | None:
    """Called by ``ai.research_cli agent run`` after the research pass.

    Disabled unless ``WATCH_AI_OPS_ENABLED=true`` (the scheduling
    service opts in explicitly; a manual run never dispatches by
    accident). Failures are contained here: the research scheduler's
    exit semantics are never changed by dispatcher errors — the caller
    prints the honest error.
    """
    cfg = config or DispatcherConfig.from_env()
    if not cfg.enabled:
        return None
    return run_tick(config=cfg)


def status_payload(*, at: datetime | None = None,
                   config: DispatcherConfig | None = None,
                   base: Path | str | None = None,
                   ) -> dict[str, Any]:
    """Read-only what-if status for any timestamp (``cli status --at``):
    never executes, never writes — used to demonstrate outside-window
    behavior deterministically without waiting for midnight."""
    cfg = config or DispatcherConfig.from_env()
    at = at or _now()
    panel = ops_state.panel(base, config=cfg, now=at)
    panel["what_if_at"] = at.isoformat(timespec="seconds")
    panel["would_dispatch"] = bool(DEFAULT_WINDOW.is_open(at))
    if not panel["would_dispatch"]:
        panel["dispatch_skipped_because"] = "OUT_OF_WINDOW"
    return panel
