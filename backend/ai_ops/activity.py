"""EPIC9 §13: truthful AI Operations activity events.

Events go through the EXISTING audit stream
(``RuntimeStore.record_audit_event``) so the SOC activity feed and the
EPIC8 intelligence taxonomy see them with full provenance — no parallel
activity system.

Vocabulary (closed):

    ai_window_opened        window transitioned closed -> open (tick-seen)
    ai_window_closed        window transitioned open -> closed (tick-seen)
    ai_tick_started         a bounded tick began (in window)
    work_discovered         discovery finished (counts + source errors)
    work_selected           items selected under budgets
    work_started            one bounded unit started
    work_completed          one bounded unit completed (real outcome)
    work_blocked            one bounded unit / summary blocked (reason)
    waiting_for_evidence    no executable work; all of it evidence-waiting
    tick_budget_exhausted   a documented budget stopped/deferred work
    ai_tick_completed       the tick finished (outcome recorded)

Every event carries: timestamp (``at``), ``tick_id``, and — where a work
item is involved — work type (``work_class``), ``target``/scope,
``source`` object id, ``state`` and ``reason`` where applicable.

Forbidden (enforced by tests): fake heartbeats, fake ACTIVE states,
"progress" without a real outcome, events not in this vocabulary.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

AI_EVENTS: tuple[str, ...] = (
    "ai_window_opened",
    "ai_window_closed",
    "ai_tick_started",
    "work_discovered",
    "work_selected",
    "work_started",
    "work_completed",
    "work_blocked",
    "waiting_for_evidence",
    "tick_budget_exhausted",
    "ai_tick_completed",
)

_MAX_TEXT = 200


def _bounded(value: Any, limit: int = _MAX_TEXT) -> str:
    return str(value if value is not None else "")[:limit]


def emit(store: Any, event: str, tick_id: str, **fields: Any
         ) -> dict[str, Any] | None:
    """Append one AI-ops event to the existing audit stream.

    Never raises: an audit failure is returned as None so a tick can
    finish its bounded work; the caller records audit errors in the tick
    record (mirroring campaign/finding executor practice).
    """
    if event not in AI_EVENTS:
        raise ValueError(f"unknown ai-ops event: {event!r}")
    row: dict[str, Any] = {
        "event": event,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tick_id": _bounded(tick_id, 80),
    }
    for key, value in fields.items():
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            row[key] = value if not isinstance(value, str) \
                else _bounded(value)
        elif isinstance(value, (list, tuple)):
            row[key] = [_bounded(v, 80) for v in list(value)[:20]]
        elif isinstance(value, dict):
            row[key] = {str(k)[:60]: _bounded(v, 120)
                        for k, v in list(value.items())[:20]}
        else:
            row[key] = _bounded(value)
    try:
        store.record_audit_event(row)
        return row
    except Exception:  # noqa: BLE001 - visible via return, never fatal
        return None
