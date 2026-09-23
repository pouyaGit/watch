"""EPIC9 §12: AI Operations state — SEPARATE from process liveness.

``worker.json`` (RuntimeStore, TTL heartbeat) answers:
    "is a bounded worker PROCESS alive right now?"
``ai_ops_state.json`` (this module) answers:
    "is AI OPERATIONS supposed to be working, and if not — why not?"

A bounded worker exiting while the scheduler is healthy is NORMAL: the
operations state stays IDLE / WAITING_FOR_EVIDENCE / BLOCKED and the SOC
must never conflate that with "PLANNED / heartbeat stale".

Persisted states (closed vocabulary, EPIC9 §12):

    OFF_WINDOW             last tick observed the window closed
    DISCOVERING            transient: discovery in progress
    EXECUTING              transient: bounded execution in progress
    IDLE                   no tick yet / nothing discovered
    COMPLETED_TICK         last tick finished; operations idle (the UI
                           displays this as IDLE + last-tick detail)
    WAITING_FOR_EVIDENCE   last tick: no executable work, all of it
                           waiting on the legitimate evidence workflow
    BLOCKED                last tick: no executable work, at least one
                           item blocked for a non-evidence reason
    FAILED                 the tick itself failed (recorded, honest)

Crash recovery: DISCOVERING/EXECUTING left behind by a dead tick are
detected at the next tick (the tick lock proves no other tick is live)
and recorded as ``recovered_interrupted`` — no state is lost, no work is
duplicated (leases/claims of the existing stores remain authoritative).

This module writes ONLY its own state file. It never touches objective,
campaign, hunt, finding or job state.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from backend.ai_ops.config import DispatcherConfig
from backend.ai_ops.window import DEFAULT_WINDOW

RULE_VERSION = "ai-ops-state-v1"

STATES = (
    "OFF_WINDOW", "DISCOVERING", "EXECUTING", "IDLE",
    "COMPLETED_TICK", "WAITING_FOR_EVIDENCE", "BLOCKED", "FAILED",
)

#: UI mapping: a completed tick IS operational idleness (§12/§14).
DISPLAY = {
    "OFF_WINDOW": "OFF WINDOW",
    "DISCOVERING": "DISCOVERING",
    "EXECUTING": "EXECUTING",
    "IDLE": "IDLE",
    "COMPLETED_TICK": "IDLE",
    "WAITING_FOR_EVIDENCE": "WAITING FOR EVIDENCE",
    "BLOCKED": "BLOCKED",
    "FAILED": "FAILED",
    "UNAVAILABLE": "UNAVAILABLE",
}

STATE_FILENAME = "ai_ops_state.json"
LOCK_FILENAME = ".ai_ops.lock"


def state_path(base: Path | str | None = None) -> Path:
    from backend.research_agents.runtime_store import runtime_base_dir
    root = Path(base) if base is not None else runtime_base_dir()
    return root / STATE_FILENAME


def lock_path(base: Path | str | None = None) -> Path:
    from backend.research_agents.runtime_store import runtime_base_dir
    root = Path(base) if base is not None else runtime_base_dir()
    return root / LOCK_FILENAME


def initial_state() -> dict[str, Any]:
    return {
        "rule_version": RULE_VERSION,
        "state": "IDLE",
        "window": {
            "start": DEFAULT_WINDOW.start,
            "end": DEFAULT_WINDOW.end,
            "timezone": DEFAULT_WINDOW.timezone,
            "label": DEFAULT_WINDOW.label,
        },
        "window_open": None,       # None = never observed yet
        "current_tick": None,
        "last_tick": None,
        "transitioned_at": "",
        "updated_at": "",
    }


def load_state(base: Path | str | None = None) -> dict[str, Any]:
    """Tolerant read: missing/corrupt file yields the honest initial
    state (never a fabricated tick history)."""
    path = state_path(base)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "state" not in raw:
            return initial_state()
        merged = initial_state()
        merged.update(raw)
        if merged["state"] not in STATES:
            merged["state"] = "FAILED"
        return merged
    except FileNotFoundError:
        return initial_state()
    except (OSError, ValueError):
        state = initial_state()
        state["state"] = "FAILED"
        state["load_error"] = "state file unreadable"
        return state


def save_state(doc: dict[str, Any],
               base: Path | str | None = None) -> Path:
    """Atomic write (tmp + replace) — a tick crash never leaves a
    half-written state file."""
    path = state_path(base)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = dict(doc)
    doc["rule_version"] = RULE_VERSION
    doc["updated_at"] = datetime.now(timezone.utc).isoformat(
        timespec="seconds")
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=True, sort_keys=True),
                   encoding="utf-8")
    os.replace(tmp, path)
    return path


def transition(doc: dict[str, Any], new_state: str,
               *, now: datetime | None = None) -> dict[str, Any]:
    if new_state not in STATES:
        raise ValueError(f"unknown ai-ops state: {new_state!r}")
    if doc.get("state") != new_state:
        doc["transitioned_at"] = (now or datetime.now(timezone.utc)) \
            .isoformat(timespec="seconds")
    doc["state"] = new_state
    return doc


def display_state(state: str) -> str:
    return DISPLAY.get(str(state or ""), "UNAVAILABLE")


def next_tick_at(config: DispatcherConfig,
                 now: datetime | None = None,
                 ) -> datetime | None:
    """Next in-window scheduler tick (hourly at :config.tick_minute in
    the window timezone — aligned with watch-research.timer, which fires
    hourly at :00 UTC = :30 Asia/Tehran by default).

    Returns None when no in-window tick is found within 48h (only
    possible with a misconfigured window; surfaced honestly).
    """
    tz = ZoneInfo(DEFAULT_WINDOW.timezone)
    now = now or datetime.now(timezone.utc)
    local = now.astimezone(tz).replace(tzinfo=None)
    probe = local.replace(minute=config.tick_minute, second=0,
                          microsecond=0)
    if probe <= local:
        probe += timedelta(hours=1)
    for _ in range(48):
        aware = probe.replace(tzinfo=tz)
        if DEFAULT_WINDOW.is_open(aware):
            return aware
        probe += timedelta(hours=1)
    return None


def panel(base: Path | str | None = None, *,
          config: DispatcherConfig | None = None,
          now: datetime | None = None,
          worker_alive: dict[str, Any] | None = None,
          ) -> dict[str, Any]:
    """SOC projection: window + operations state + process liveness as
    three SEPARATE facts (§14). Read-only."""
    cfg = config or DispatcherConfig.from_env()
    now = now or datetime.now(timezone.utc)
    doc = load_state(base)
    window_open = DEFAULT_WINDOW.is_open(now)
    if worker_alive is None:
        try:
            from backend.research_agents.runtime_store import default_store
            worker_alive = default_store().worker_alive()
        except Exception as exc:  # noqa: BLE001 - honest unavailability
            worker_alive = {"alive": False,
                            "reason": f"worker source unavailable: "
                                      f"{type(exc).__name__}"}
    last = doc.get("last_tick") or None
    nxt = next_tick_at(cfg, now)
    return {
        "rule_version": RULE_VERSION,
        "window": {
            "start": DEFAULT_WINDOW.start,
            "end": DEFAULT_WINDOW.end,
            "timezone": DEFAULT_WINDOW.timezone,
            "label": DEFAULT_WINDOW.label,
            "open": window_open,
        },
        "operations_state": doc.get("state", "IDLE"),
        "operations_display": display_state(doc.get("state", "IDLE")),
        "window_observed_open": doc.get("window_open"),
        "current_tick": doc.get("current_tick"),
        "last_tick": last,
        "next_tick_at": nxt.isoformat(timespec="seconds") if nxt else None,
        "work": {
            "discovered": (last or {}).get("discovered", {}).get(
                "discovered"),
            "executable": (last or {}).get("discovered", {}).get(
                "executable"),
            "waiting": (last or {}).get("discovered", {}).get("waiting"),
            "blocked": (last or {}).get("discovered", {}).get("blocked"),
            "reasons": (last or {}).get("discovered", {}).get("by_reason"),
        },
        "process": {
            "alive": bool(worker_alive.get("alive")),
            "worker_id": worker_alive.get("worker_id", ""),
            "last_heartbeat": worker_alive.get("last_heartbeat", ""),
            "reason": worker_alive.get("reason", ""),
        },
        "updated_at": doc.get("updated_at", ""),
    }
