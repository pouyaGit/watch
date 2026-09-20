"""backend/operations_status.py — read-only live operations status provider.

Backs the Command Center "Live Operations" layer. It answers "what is Watch
doing right now?" from safe, local, read-only sources:

- **systemd unit state** for the primary Watch units, queried with a bounded
  ``systemctl show`` (``shell=False``). For services it reports the active /
  sub state, unit-file (enabled) state, last execution start/finish times,
  exit status, ``Result`` and duration. For timers it reports the last trigger
  and next elapse.
- **host resources** — CPU / RAM / disk / load via the existing
  ``backend.system_stats.collect`` collector, plus uptime via
  ``psutil.boot_time``.

READ-ONLY by construction. The only subprocess is a read-only ``systemctl
show`` query; nothing is started, stopped, restarted, enabled, disabled,
masked or written. No shell, no network, no Mongo, no LLM, no background
process. Missing units and an unavailable systemd are reported as honest
unavailable empty states, never invented.

The systemctl invocation is injectable (``runner``) so tests never touch the
real system, and the resource collector is injectable (``collector``).
"""

from __future__ import annotations

import subprocess
import time
from datetime import datetime, timezone
from typing import Callable

#: Primary Watch units surfaced by the live operations layer. ``kind`` selects
#: the systemd property set and the projection.
PRIMARY_UNITS: tuple[tuple[str, str], ...] = (
    ("watch-api.service", "service"),
    ("watch-dell-watchlist.service", "service"),
    ("watch-dell-watchlist.timer", "timer"),
)

SERVICE_PROPS: tuple[str, ...] = (
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "Result",
    "ExecMainStatus",
    "ExecMainStartTimestamp",
    "ExecMainExitTimestamp",
    "ExecMainStartTimestampMonotonic",
    "ExecMainExitTimestampMonotonic",
)

TIMER_PROPS: tuple[str, ...] = (
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "LastTriggerUSec",
    "NextElapseUSecRealtime",
    "LastTriggerUSecMonotonic",
)

DEFAULT_TIMEOUT = 5.0
MAX_TEXT = 160

Runner = Callable[[list, float], tuple]


def _text(value: object, limit: int = MAX_TEXT) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _int_or_none(value: object):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# systemctl invocation (read-only, injectable)
# ---------------------------------------------------------------------------


def _default_runner(args: list, timeout: float = DEFAULT_TIMEOUT) -> tuple:
    """Run a bounded, read-only ``systemctl`` query (no shell, no writes)."""

    proc = subprocess.run(
        ["systemctl", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _systemd_reachable(runner: Runner) -> tuple[bool, str]:
    """Cheap read-only probe: is systemd answering ``systemctl show``?"""

    try:
        code, out, err = runner(["show", "--property=Version", "--value"], 5.0)
    except FileNotFoundError:
        return False, "systemctl is not installed"
    except Exception as exc:  # timeout, permission, ...
        return False, f"systemctl probe failed ({type(exc).__name__})"
    if code == 0:
        return True, ""
    text = f"{out}\n{err}".lower()
    if "not been booted" in text or "failed to connect" in text:
        return False, "systemd is not available on this host"
    return False, "systemctl query failed"


def _parse_show(text: object) -> dict:
    """Parse ``systemctl show`` ``Key=Value`` output deterministically."""

    out: dict[str, str] = {}
    for line in str(text or "").splitlines():
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


_SYSDATE_FORMATS: tuple[str, ...] = (
    "%a %Y-%m-%d %H:%M:%S %Z",
    "%a %Y-%m-%d %H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S %Z",
    "%Y-%m-%d %H:%M:%S %z",
)


def _parse_when(text: object) -> datetime | None:
    """Parse a systemd timestamp to aware UTC (None when unparseable).

    systemd renders timestamps in the host timezone (often with a ``UTC``
    suffix). A timezone-naive result is treated as UTC so it is never
    misread as Tehran wall-clock downstream.
    """

    value = _text(text, 64)
    if not value or value.lower() in {"n/a", "none", "-", ""}:
        return None
    for fmt in _SYSDATE_FORMATS:
        try:
            moment = datetime.strptime(value, fmt)
        except ValueError:
            continue
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)
    return None


def _monotonic_us(text: object):
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return None


def _duration_seconds(start_us, end_us):
    if start_us is None or end_us is None or end_us < start_us:
        return None
    return round((end_us - start_us) / 1_000_000, 3)


def _format_duration(seconds) -> str:
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return ""
    if total < 0:
        return ""
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s" if secs else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"


def _format_uptime(seconds) -> str:
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return ""
    if total <= 0:
        return ""
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Unit projections
# ---------------------------------------------------------------------------


def _service_status(show: dict) -> str:
    load = show.get("LoadState", "")
    if load == "not-found":
        return "NOT INSTALLED"
    if load == "masked":
        return "MASKED"
    active = show.get("ActiveState", "")
    sub = show.get("SubState", "")
    result = show.get("Result", "")
    if active == "active":
        return "RUNNING" if sub == "running" else "ACTIVE"
    if active == "activating":
        return "STARTING"
    if active == "deactivating":
        return "STOPPING"
    if active == "failed":
        return "FAILED"
    if result == "success":
        return "LAST RUN SUCCESS"
    if result:
        return f"LAST RUN {result.upper()}"
    return "INACTIVE"


def _timer_status(show: dict) -> str:
    load = show.get("LoadState", "")
    if load == "not-found":
        return "NOT INSTALLED"
    if load == "masked":
        return "MASKED"
    active = show.get("ActiveState", "")
    sub = show.get("SubState", "")
    if active == "active":
        return "SCHEDULED" if sub == "waiting" else "ACTIVE"
    if active == "failed":
        return "FAILED"
    return "INACTIVE"


def _empty_unit(unit: str, kind: str, status: str, detail: str = "") -> dict:
    return {
        "unit": unit,
        "kind": kind,
        "available": False,
        "installed": None,
        "load_state": "",
        "active_state": "",
        "sub_state": "",
        "unit_file_state": "",
        "enabled": None,
        "status": status,
        "result": "",
        "note": _text(detail),
        "last_run": None,
        "last_trigger": None,
        "next_elapse": None,
    }


def _service_view(unit: str, show: dict) -> dict:
    load = _text(show.get("LoadState"), 32)
    installed = load not in ("", "not-found", "masked")
    unit_file_state = _text(show.get("UnitFileState"), 32)
    started = _parse_when(show.get("ExecMainStartTimestamp"))
    finished = _parse_when(show.get("ExecMainExitTimestamp"))
    duration = _duration_seconds(
        _monotonic_us(show.get("ExecMainStartTimestampMonotonic")),
        _monotonic_us(show.get("ExecMainExitTimestampMonotonic")),
    )
    exit_status = _int_or_none(show.get("ExecMainStatus"))
    result = _text(show.get("Result"), 32)
    last_run = None
    if (started is not None or finished is not None
            or exit_status is not None or result):
        last_run = {
            "started_at": started,
            "finished_at": finished,
            "duration_seconds": duration,
            "duration_label": _format_duration(duration),
            "exit_status": exit_status,
            "result": result,
        }
    return {
        "unit": unit,
        "kind": "service",
        "available": True,
        "installed": installed,
        "load_state": load,
        "active_state": _text(show.get("ActiveState"), 32),
        "sub_state": _text(show.get("SubState"), 32),
        "unit_file_state": unit_file_state,
        "enabled": (unit_file_state == "enabled") if unit_file_state else None,
        "status": _service_status(show),
        "result": result,
        "note": "",
        "last_run": last_run,
        "last_trigger": None,
        "next_elapse": None,
    }


def _timer_view(unit: str, show: dict) -> dict:
    load = _text(show.get("LoadState"), 32)
    installed = load not in ("", "not-found", "masked")
    unit_file_state = _text(show.get("UnitFileState"), 32)
    return {
        "unit": unit,
        "kind": "timer",
        "available": True,
        "installed": installed,
        "load_state": load,
        "active_state": _text(show.get("ActiveState"), 32),
        "sub_state": _text(show.get("SubState"), 32),
        "unit_file_state": unit_file_state,
        "enabled": (unit_file_state == "enabled") if unit_file_state else None,
        "status": _timer_status(show),
        "result": "",
        "note": "",
        "last_run": None,
        "last_trigger": _parse_when(show.get("LastTriggerUSec")),
        "next_elapse": _parse_when(show.get("NextElapseUSecRealtime")),
    }


def _query_unit(unit: str, kind: str, runner: Runner,
                timeout: float = DEFAULT_TIMEOUT) -> dict:
    props = TIMER_PROPS if kind == "timer" else SERVICE_PROPS
    args = ["show", unit, "--property=" + ",".join(props)]
    try:
        code, out, err = runner(args, timeout)
    except Exception as exc:
        return _empty_unit(unit, kind, "UNAVAILABLE", type(exc).__name__)
    if code != 0:
        return _empty_unit(unit, kind, "UNAVAILABLE", err)
    show = _parse_show(out)
    if kind == "timer":
        return _timer_view(unit, show)
    return _service_view(unit, show)


def collect_operations(
    units: Iterable | None = None,
    *,
    runner: Runner | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """Read-only systemd status for the primary Watch units.

    Returns ``available: False`` with honest ``UNAVAILABLE`` unit rows when
    systemd cannot be reached, and a ``NOT INSTALLED`` status for units that
    are not present. Never raises.
    """

    specs = list(units or PRIMARY_UNITS)
    runner = runner or _default_runner
    reachable, note = _systemd_reachable(runner)
    if not reachable:
        return {
            "available": False,
            "note": note,
            "unit_count": len(specs),
            "units": [
                _empty_unit(unit, kind, "UNAVAILABLE", note)
                for unit, kind in specs
            ],
        }
    views = [_query_unit(unit, kind, runner, timeout) for unit, kind in specs]
    return {
        "available": True,
        "note": "",
        "unit_count": len(views),
        "units": views,
    }


def operation_events(operations: dict) -> list:
    """Normalize service/timer last executions into the activity timeline shape."""

    events: list[dict] = []
    if not isinstance(operations, dict):
        return events
    for unit in operations.get("units") or []:
        if not isinstance(unit, dict):
            continue
        name = _text(unit.get("unit"), 96)
        if unit.get("kind") == "service":
            last = unit.get("last_run") or {}
            started = last.get("started_at")
            if not name or started is None:
                continue
            running = (unit.get("active_state") == "active"
                       and unit.get("sub_state") == "running")
            if running:
                # A long-lived service: report that it is running now; do not
                # reuse a previous run's exit/result values for this start.
                events.append({
                    "kind": "SERVICE_START",
                    "source": "System service",
                    "title": name,
                    "program": "",
                    "ref": name,
                    "status": "RUNNING",
                    "at": started,
                    "detail": "running now",
                })
                continue
            parts = []
            if last.get("result"):
                parts.append(f"result={last['result']}")
            if last.get("exit_status") is not None:
                parts.append(f"exit={last['exit_status']}")
            if last.get("duration_label"):
                parts.append(last["duration_label"])
            events.append({
                "kind": "SERVICE_RUN",
                "source": "System service",
                "title": name,
                "program": "",
                "ref": name,
                "status": _text(unit.get("status"), 32),
                "at": started,
                "detail": " · ".join(parts) or "service execution observed",
            })
        elif unit.get("kind") == "timer":
            triggered = unit.get("last_trigger")
            if not name or triggered is None:
                continue
            detail = "timer trigger"
            if unit.get("next_elapse") is not None:
                detail = f"next {unit['next_elapse'].isoformat(timespec='minutes')}"
            events.append({
                "kind": "TIMER_TRIGGER",
                "source": "System timer",
                "title": name,
                "program": "",
                "ref": name,
                "status": _text(unit.get("status"), 32),
                "at": triggered,
                "detail": detail,
            })
    return events


# ---------------------------------------------------------------------------
# Host resources (reuses the existing system_stats collector)
# ---------------------------------------------------------------------------


def uptime_status(now: float | None = None) -> dict:
    """Host uptime from ``psutil.boot_time`` (fail-soft)."""

    try:
        import psutil

        boot = float(psutil.boot_time())
    except Exception:
        return {"uptime_seconds": None, "boot_time": None, "uptime_label": ""}
    reference = float(now) if now is not None else time.time()
    seconds = max(int(reference - boot), 0)
    return {
        "uptime_seconds": seconds,
        "boot_time": datetime.fromtimestamp(boot, tz=timezone.utc),
        "uptime_label": _format_uptime(seconds),
    }


def collect_resources(collector=None, *, now: float | None = None) -> dict:
    """CPU/RAM/disk/load (existing collector) plus uptime."""

    if collector is None:
        from backend import system_stats

        collector = system_stats.collect
    try:
        stats = dict(collector() or {})
    except Exception:
        stats = {}
    stats.update(uptime_status(now))
    stats["available"] = any(
        stats.get(key) is not None
        for key in ("cpu_percent", "ram_percent", "disk_percent",
                    "load_avg", "uptime_seconds")
    )
    return stats


def snapshot(
    *,
    units: Iterable | None = None,
    runner: Runner | None = None,
    collector=None,
) -> dict:
    """Compose the live operations projection (systemd + resources + events)."""

    operations = collect_operations(units, runner=runner)
    resources = collect_resources(collector)
    return {
        "operations": operations,
        "resources": resources,
        "events": operation_events(operations),
    }


__all__ = [
    "PRIMARY_UNITS",
    "SERVICE_PROPS",
    "TIMER_PROPS",
    "collect_operations",
    "operation_events",
    "uptime_status",
    "collect_resources",
    "snapshot",
]
