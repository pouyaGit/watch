"""
backend/tz.py — One place for every timezone conversion in the dashboard.

Storage convention (verified against the production VPS: /etc/timezone is
Asia/Tehran and every writer uses naive ``datetime.now()``):

    ALL naive datetimes in the Watch database are Tehran WALL-CLOCK time.

Conversion is therefore explicit and does NOT depend on the locale of the
process rendering the page -- a dashboard served from a UTC box still shows
the same Tehran timestamps. Stored values are never rewritten.

Rules applied here:
  * naive datetime  -> interpreted as ``STORAGE_TZ`` (Asia/Tehran).
  * aware datetime  -> converted to Asia/Tehran directly.
  * None            -> None (templates render an em-dash).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

TEHRAN = ZoneInfo("Asia/Tehran")

# The timezone in which naive DB timestamps were written. datetime.now() on
# the production VPS returns Tehran wall-clock (system tz = Asia/Tehran), so
# naive values are interpreted as Tehran -- deterministically, regardless of
# the web process's own locale. If the storage convention ever changes (e.g.
# crawlers migrate to UTC), change ONLY this constant.
STORAGE_TZ = TEHRAN

# "31 Aug 2026 15:42"
_FMT_ABS = "%d %b %Y %H:%M"
# "15:42"
_FMT_TIME = "%H:%M"
# "31 Aug 14:20" (change-event timeline)
_FMT_SHORT = "%d %b %H:%M"


def to_tehran(dt):
    """Convert a stored (naive-Tehran or aware) datetime to Tehran time.

    Returns ``None`` for falsy input so templates can call it blindly.
    """
    if not dt:
        return None
    try:
        if dt.tzinfo is None:
            # Deterministic: naive DB values are Tehran wall-clock (see
            # STORAGE_TZ). NOT the process locale.
            dt = dt.replace(tzinfo=STORAGE_TZ)
        return dt.astimezone(TEHRAN)
    except (ValueError, OSError, OverflowError):
        # Non-convertible (e.g. pre-epoch on some platforms): show as-is.
        return dt


def tehran_now() -> datetime:
    """Current time as an AWARE Tehran datetime (for relative math)."""
    return datetime.now(TEHRAN)


def _reference(now=None):
    """Normalise the reference clock for relative-time helpers.

    ``None`` -> current Tehran time. A naive ``now`` is interpreted with the
    same STORAGE_TZ rule as stored data (never implicitly UTC).
    """
    if now is None:
        return tehran_now()
    t = to_tehran(now)
    return t or tehran_now()


def fmt_tehran(dt, fmt: str = _FMT_ABS) -> str:
    """Absolute Tehran timestamp, e.g. ``31 Aug 2026 15:42``."""
    t = to_tehran(dt)
    return t.strftime(fmt) if t else "—"


def fmt_time(dt) -> str:
    """Clock time only in Tehran, e.g. ``15:42``."""
    t = to_tehran(dt)
    return t.strftime(_FMT_TIME) if t else "—"


def fmt_short(dt) -> str:
    """Compact timeline stamp, e.g. ``31 Aug 14:20``."""
    t = to_tehran(dt)
    return t.strftime(_FMT_SHORT) if t else "—"


def fmt_ago(dt, now=None) -> str:
    """Relative age in Tehran terms: ``just now`` / ``5m ago`` / ``3h ago``
    / ``2d ago``; falls back to a short absolute date past ~30 days."""
    t = to_tehran(dt)
    if not t:
        return "never"
    ref = _reference(now)
    delta = ref - t
    secs = delta.total_seconds()
    if secs < 0:
        # Clock skew / future timestamp: treat as just now.
        return "just now"
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    days = int(secs // 86400)
    if days <= 30:
        return f"{days}d ago"
    return t.strftime(_FMT_SHORT)


def fmt_duration(start, end=None) -> str:
    """Human duration between two datetimes: ``32m`` / ``2h 14m`` / ``45s``."""
    if not start:
        return "—"
    a = to_tehran(start)
    b = to_tehran(end) if end else tehran_now()
    if not a or not b:
        return "—"
    secs = int((b - a).total_seconds())
    if secs < 0:
        return "—"
    if secs < 60:
        return f"{secs}s"
    mins, s = divmod(secs, 60)
    if mins < 60:
        return f"{mins}m" if not s else f"{mins}m {s}s"
    hours, m = divmod(mins, 60)
    if hours < 24:
        return f"{hours}h {m}m" if m else f"{hours}h"
    days, h = divmod(hours, 24)
    return f"{days}d {h}h" if h else f"{days}d"


def age_days(dt, now=None):
    """Integer days since ``dt`` (Tehran-normalized), or ``None`` if never."""
    t = to_tehran(dt)
    if not t:
        return None
    ref = _reference(now)
    return max(0, (ref - t).days)


def is_stale(dt, threshold_days: int, now=None) -> bool:
    """True when ``dt`` is missing or older than ``threshold_days``."""
    d = age_days(dt, now=now)
    return d is None or d > threshold_days


__all__ = [
    "TEHRAN",
    "STORAGE_TZ",
    "to_tehran",
    "tehran_now",
    "fmt_tehran",
    "fmt_time",
    "fmt_short",
    "fmt_ago",
    "fmt_duration",
    "age_days",
    "is_stale",
]
