"""The single authoritative AI Operations Window (EPIC9 §2).

    timezone = Asia/Tehran
    start    = 12:00   (inclusive)
    end      = 00:00   (exclusive)

Every module that needs the AI window (the research scheduler, the AI
operations dispatcher, the SOC projection) consumes THIS module. No other
module may restate the window values or the open/closed semantics.

Semantics (tested around midnight and at exact boundaries):

* ``11:59`` -> CLOSED, ``12:00`` -> OPEN, ``18:00`` -> OPEN,
  ``23:59`` -> OPEN, ``00:00`` -> CLOSED.
* start inclusive, end exclusive; a window crossing midnight is OPEN from
  start through 23:59 and from 00:00 up to (not including) end.
* ``start == end`` is always CLOSED (zero-length window fails closed).
* All comparisons happen in the window's own timezone; ``ZoneInfo``
  conversion makes the decision DST-safe for any configured zone
  (Asia/Tehran currently has no DST; a zone that does is covered by
  tests so a future tz change cannot silently break boundaries).

Pure module: no I/O, no Watch imports, no clock of its own beyond the
``now`` values callers pass in.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

TIMEZONE = "Asia/Tehran"
START = "12:00"
END = "00:00"

__all__ = [
    "AIWindow",
    "DEFAULT_WINDOW",
    "END",
    "START",
    "TIMEZONE",
    "is_open_local",
    "next_close_local",
    "next_open_local",
    "parse_hhmm",
]


def parse_hhmm(value: str) -> int:
    """Parse ``HH:MM`` into minutes-of-day; malformed values fail closed."""
    text = str(value or "").strip()
    parts = text.split(":")
    if len(parts) != 2:
        raise ValueError(f"invalid time of day: {value!r}")
    try:
        hour, minute = int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise ValueError(f"invalid time of day: {value!r}") from exc
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"invalid time of day: {value!r}")
    return hour * 60 + minute


def is_open_local(now: datetime, start: str, end: str) -> bool:
    """True when naive-local ``now`` is inside [start, end).

    start inclusive, end exclusive; midnight-crossing supported;
    start == end always closed (fail closed).
    """
    s = parse_hhmm(start)
    e = parse_hhmm(end)
    if s == e:
        return False
    current = now.hour * 60 + now.minute
    if s < e:
        return s <= current < e
    return current >= s or current < e


def next_open_local(now: datetime, start: str, end: str) -> datetime:
    """Next occurrence of window start at/after ``now`` (same local tz)."""
    hh, mm = divmod(parse_hhmm(start), 60)
    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if candidate <= now:
        candidate = candidate + timedelta(days=1)
    return candidate


def next_close_local(now: datetime, start: str, end: str) -> datetime:
    """Next occurrence of window end strictly after ``now`` (same tz).

    Only meaningful while the window is open; callers outside the window
    should use :meth:`AIWindow.next_open`.
    """
    hh, mm = divmod(parse_hhmm(end), 60)
    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if candidate <= now:
        candidate = candidate + timedelta(days=1)
    return candidate


@dataclass(frozen=True)
class AIWindow:
    """Immutable window configuration (values validated at construction)."""

    start: str = START
    end: str = END
    timezone: str = TIMEZONE

    def __post_init__(self) -> None:
        parse_hhmm(self.start)          # raises on malformed values
        parse_hhmm(self.end)
        ZoneInfo(self.timezone)         # raises on unknown timezone

    @property
    def label(self) -> str:
        return f"{self.start}-{self.end} {self.timezone}"

    def local(self, now: datetime) -> datetime:
        """Convert an aware ``now`` (any tz) to the window timezone."""
        tz = ZoneInfo(self.timezone)
        if now.tzinfo is None:
            # Naive input is interpreted as UTC (the system clock domain),
            # never as local time — a fail-closed choice.
            now = now.replace(tzinfo=timezone.utc)
        return now.astimezone(tz)

    def is_open(self, now: datetime) -> bool:
        return is_open_local(self.local(now), self.start, self.end)

    def next_open(self, now: datetime) -> datetime:
        local = self.local(now)
        if self.is_open(local):
            # already open: the next *new* opening is the next day's start
            local_naive = local.replace(tzinfo=None)
            nxt = next_open_local(
                local_naive.replace(hour=0, minute=0, second=0,
                                    microsecond=0)
                + timedelta(days=1),
                self.start, self.end,
            )
            return nxt.replace(tzinfo=ZoneInfo(self.timezone))
        nxt = next_open_local(local.replace(tzinfo=None), self.start,
                              self.end)
        return nxt.replace(tzinfo=ZoneInfo(self.timezone))

    def next_close(self, now: datetime) -> datetime | None:
        """Next end-boundary after ``now``, or None when currently closed."""
        if not self.is_open(now):
            return None
        local = self.local(now).replace(tzinfo=None)
        close = next_close_local(local, self.start, self.end)
        return close.replace(tzinfo=ZoneInfo(self.timezone))


DEFAULT_WINDOW = AIWindow()
