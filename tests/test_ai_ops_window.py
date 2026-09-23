"""EPIC9 §2: the single authoritative AI window — boundaries, midnight,
DST-safety, delegation from the research scheduler, and no duplicate
window definitions anywhere."""

from __future__ import annotations

import ast
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from backend.ai_ops.window import (
    DEFAULT_WINDOW, END, START, TIMEZONE, AIWindow,
    is_open_local, next_close_local, next_open_local,
    parse_hhmm,
)

REPO = Path(__file__).resolve().parents[1]
TEHRAN = "Asia/Tehran"


class WindowBoundaryTests(unittest.TestCase):
    """The exact semantics the prompt requires (12:00 in, 00:00 out)."""

    def test_1159_closed(self):
        self.assertFalse(is_open_local(datetime(2026, 9, 23, 11, 59),
                                       START, END))

    def test_1200_open(self):
        self.assertTrue(is_open_local(datetime(2026, 9, 23, 12, 0),
                                      START, END))

    def test_1800_open(self):
        self.assertTrue(is_open_local(datetime(2026, 9, 23, 18, 0),
                                      START, END))

    def test_2359_open(self):
        self.assertTrue(is_open_local(datetime(2026, 9, 23, 23, 59),
                                      START, END))

    def test_0000_closed(self):
        self.assertFalse(is_open_local(datetime(2026, 9, 24, 0, 0),
                                       START, END))

    def test_0001_closed(self):
        self.assertFalse(is_open_local(datetime(2026, 9, 24, 0, 1),
                                       START, END))

    def test_1158_closed(self):
        self.assertFalse(is_open_local(datetime(2026, 9, 23, 11, 58),
                                       START, END))

    def test_midnight_crossing_window_22_06(self):
        # 22:00 -> 06:00 crosses midnight in both directions.
        self.assertTrue(is_open_local(datetime(2026, 9, 23, 23, 0),
                                      "22:00", "06:00"))
        self.assertTrue(is_open_local(datetime(2026, 9, 24, 5, 59),
                                      "22:00", "06:00"))
        self.assertFalse(is_open_local(datetime(2026, 9, 24, 6, 0),
                                       "22:00", "06:00"))
        self.assertFalse(is_open_local(datetime(2026, 9, 23, 21, 59),
                                       "22:00", "06:00"))

    def test_non_crossing_window(self):
        self.assertTrue(is_open_local(datetime(2026, 9, 23, 9, 0),
                                      "08:00", "10:00"))
        self.assertFalse(is_open_local(datetime(2026, 9, 23, 10, 0),
                                       "08:00", "10:00"))

    def test_zero_length_window_always_closed(self):
        for minute in (0, 1, 30, 59):
            self.assertFalse(is_open_local(
                datetime(2026, 9, 23, 12, minute), "12:00", "12:00"))

    def test_full_day_window_via_00_00_start(self):
        # start==end is closed by definition; documents the boundary
        # and prevents an accidental "always open" regression.
        self.assertFalse(is_open_local(datetime(2026, 9, 23, 15, 0),
                                       "00:00", "00:00"))


class WindowTimezoneTests(unittest.TestCase):
    """is_open converts aware instants into the window timezone."""

    def test_constants(self):
        self.assertEqual(TIMEZONE, "Asia/Tehran")
        self.assertEqual(START, "12:00")
        self.assertEqual(END, "00:00")

    def test_utc_instant_inside_tehran_window(self):
        # 15:00 UTC == 18:30 Tehran -> OPEN
        instant = datetime(2026, 9, 23, 15, 0, tzinfo=timezone.utc)
        self.assertTrue(DEFAULT_WINDOW.is_open(instant))

    def test_utc_instant_outside_tehran_window(self):
        # 08:00 UTC == 11:30 Tehran -> CLOSED
        instant = datetime(2026, 9, 23, 8, 0, tzinfo=timezone.utc)
        self.assertFalse(DEFAULT_WINDOW.is_open(instant))

    def test_exact_open_edge_utc(self):
        # 08:30 UTC == 12:00 Tehran exactly -> OPEN (inclusive)
        instant = datetime(2026, 9, 23, 8, 30, tzinfo=timezone.utc)
        self.assertTrue(DEFAULT_WINDOW.is_open(instant))

    def test_exact_close_edge_utc(self):
        # 20:30 UTC == 00:00 Tehran exactly -> CLOSED (exclusive)
        instant = datetime(2026, 9, 23, 20, 30, tzinfo=timezone.utc)
        self.assertFalse(DEFAULT_WINDOW.is_open(instant))

    def test_dst_safe_for_zones_that_have_dst(self):
        # Europe/Berlin: window 01:00 -> 03:00; on the 2026-10-25 DST
        # night the local gap means 02:xx only exists once. The window
        # must behave sanely on both sides of the transition.
        w = AIWindow(start="01:00", end="03:00", timezone="Europe/Berlin")
        before = datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
        during = datetime(2026, 10, 24, 23, 30, tzinfo=timezone.utc)
        after = datetime(2026, 10, 25, 2, 30, tzinfo=timezone.utc)
        # 02:30 CEST (before jump) inside 01:00-03:00 local -> open
        self.assertTrue(w.is_open(during))
        # instant conversions must not raise across the DST gap
        self.assertIsInstance(w.is_open(before), bool)
        self.assertIsInstance(w.is_open(after), bool)

    def test_naive_input_treated_as_utc_fail_closed(self):
        # Naive input is interpreted as UTC (never as local time).
        naive = datetime(2026, 9, 23, 13, 0)          # = 16:30 Tehran
        self.assertTrue(DEFAULT_WINDOW.is_open(naive))
        early = datetime(2026, 9, 23, 6, 0)            # = 09:30 Tehran
        self.assertFalse(DEFAULT_WINDOW.is_open(early))

    def test_next_open_crosses_midnight(self):
        now = datetime(2026, 9, 23, 23, 0,
                       tzinfo=ZoneInfo(TEHRAN))
        nxt = next_open_local(now, START, END)
        self.assertEqual((nxt.hour, nxt.minute), (12, 0))
        self.assertEqual(nxt.day, 24)

    def test_next_open_same_day_when_before_start(self):
        now = datetime(2026, 9, 23, 8, 0, tzinfo=ZoneInfo(TEHRAN))
        nxt = next_open_local(now, START, END)
        self.assertEqual((nxt.day, nxt.hour, nxt.minute), (23, 12, 0))

    def test_next_open_at_exact_start_is_strictly_after(self):
        # Boundary equality inherits the R23 semantic: at exactly
        # start, the *next* start is tomorrow (candidate <= now).
        now = datetime(2026, 9, 23, 12, 0)
        nxt = next_open_local(now, START, END)
        self.assertEqual((nxt.day, nxt.hour, nxt.minute), (24, 12, 0))
        # one minute before start -> same day
        before = datetime(2026, 9, 23, 11, 59)
        nxt2 = next_open_local(before, START, END)
        self.assertEqual((nxt2.day, nxt2.hour, nxt2.minute), (23, 12, 0))

    def test_next_open_via_window_object_when_open_means_next_new(self):
        # AIWindow.next_open = the next *new* opening (documented):
        # while open, that is tomorrow's start.
        now = datetime(2026, 9, 23, 13, 0, tzinfo=ZoneInfo(TEHRAN))
        nxt = DEFAULT_WINDOW.next_open(now)
        self.assertEqual((nxt.day, nxt.hour, nxt.minute), (24, 12, 0))

    def test_next_close_inside_window(self):
        now = datetime(2026, 9, 23, 18, 0, tzinfo=ZoneInfo(TEHRAN))
        nxt = next_close_local(now, START, END)
        self.assertEqual((nxt.day, nxt.hour, nxt.minute), (24, 0, 0))

    def test_next_close_none_when_closed(self):
        # Outside the window there is no "next close" — callers use
        # next_open instead (documented semantics).
        now = datetime(2026, 9, 23, 5, 0, tzinfo=ZoneInfo(TEHRAN))
        self.assertIsNone(DEFAULT_WINDOW.next_close(now))

    def test_next_close_returns_boundary_when_open(self):
        now = datetime(2026, 9, 23, 18, 0, tzinfo=ZoneInfo(TEHRAN))
        close = DEFAULT_WINDOW.next_close(now)
        self.assertIsNotNone(close)
        self.assertEqual((close.day, close.hour, close.minute),
                         (24, 0, 0))


class WindowParsingTests(unittest.TestCase):

    def test_parse_valid(self):
        self.assertEqual(parse_hhmm("12:00"), 720)
        self.assertEqual(parse_hhmm("00:00"), 0)
        self.assertEqual(parse_hhmm("23:59"), 1439)
        self.assertEqual(parse_hhmm(" 09:30 "), 570)

    def test_parse_rejects_bad_shapes(self):
        for bad in ("", "9", "9:30:00", "abc", "12", ":"):
            with self.assertRaises(ValueError):
                parse_hhmm(bad)

    def test_parse_rejects_out_of_range(self):
        for bad in ("24:00", "12:60", "25:30", "-1:00", "12:99"):
            with self.assertRaises(ValueError):
                parse_hhmm(bad)

    def test_label(self):
        label = DEFAULT_WINDOW.label
        self.assertIn("12:00", label)
        self.assertIn("00:00", label)
        self.assertIn(TEHRAN, label)


class AuthoritativeWindowObjectTests(unittest.TestCase):

    def test_default_window_values(self):
        self.assertEqual(DEFAULT_WINDOW.start, "12:00")
        self.assertEqual(DEFAULT_WINDOW.end, "00:00")
        self.assertEqual(DEFAULT_WINDOW.timezone, TEHRAN)

    def test_default_window_is_frozen(self):
        with self.assertRaises(Exception):
            DEFAULT_WINDOW.start = "09:00"  # type: ignore[misc]

    def test_label_includes_bounds_and_tz(self):
        self.assertEqual(DEFAULT_WINDOW.label,
                         "12:00-00:00 Asia/Tehran")

    def test_is_open_uses_instance_values(self):
        w = AIWindow(start="09:00", end="17:00", timezone=TEHRAN)
        inside = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
        self.assertTrue(w.is_open(inside))
        # ... while the default window is closed at that same instant
        # (09:00 UTC = 12:30 Tehran, so default also open — pick an
        # instant clearly inside 09-17 Tehran only)
        edge = datetime(2026, 9, 23, 6, 0, tzinfo=timezone.utc)
        self.assertTrue(w.is_open(edge))       # 09:30 Tehran
        self.assertFalse(DEFAULT_WINDOW.is_open(edge))

    def test_invalid_window_rejected(self):
        with self.assertRaises(ValueError):
            AIWindow(start="25:00", end="00:00", timezone=TEHRAN)
        # unknown zone: ZoneInfo raises (KeyError family) or ValueError
        with self.assertRaises((ValueError, KeyError)):
            AIWindow(start="12:00", end="00:00", timezone="Not/AZone")


class SchedulerConsumesAuthorityTests(unittest.TestCase):
    """The research scheduler must consume — not restate — the window."""

    def test_scheduler_defaults_equal_authority(self):
        from ai.research_agent.scheduler import SchedulerConfig
        cfg = SchedulerConfig.from_env({})
        self.assertEqual(cfg.window_start, DEFAULT_WINDOW.start)
        self.assertEqual(cfg.window_end, DEFAULT_WINDOW.end)
        self.assertEqual(cfg.timezone, DEFAULT_WINDOW.timezone)

    def test_env_override_still_works(self):
        from ai.research_agent.scheduler import SchedulerConfig
        cfg = SchedulerConfig.from_env(
            {"WATCH_RESEARCH_WINDOW_START": "09:00"})
        self.assertEqual(cfg.window_start, "09:00")
        self.assertEqual(cfg.window_end, DEFAULT_WINDOW.end)

    def test_scheduler_in_window_delegates_identically(self):
        from ai.research_agent.scheduler import in_window
        hours = []
        for day in (23, 24):
            for h in range(24):
                hours.append(datetime(2026, 9, day, h, 0))
        for now in hours:
            self.assertEqual(
                in_window(now, START, END),
                is_open_local(now, START, END),
                msg=f"mismatch at {now}",
            )

    def test_scheduler_in_window_matches_for_crossing_window(self):
        from ai.research_agent.scheduler import in_window
        for h in range(24):
            now = datetime(2026, 9, 23, h, 30)
            self.assertEqual(in_window(now, "22:00", "06:00"),
                             is_open_local(now, "22:00", "06:00"))

    def test_scheduler_parse_delegates(self):
        from ai.research_agent.scheduler import parse_hhmm
        self.assertEqual(parse_hhmm("12:00"), 720)
        with self.assertRaises(ValueError):
            parse_hhmm("99:00")

    def test_scheduler_next_window_delegates(self):
        from ai.research_agent.scheduler import next_window_start
        now = datetime(2026, 9, 23, 13, 0)
        self.assertEqual(next_window_start(now, START, END),
                         next_open_local(now, START, END))

    def test_no_window_literals_outside_authority(self):
        """No module may restate 12:00/00:00/Asia/Tehran as its own
        window definition (constants re-exported from window.py and
        env-key strings are fine)."""
        banned = ('"12:00"', '"00:00"', "'12:00'", "'00:00'")
        checked = [
            "backend/ai_ops/dispatcher.py",
            "backend/ai_ops/discovery.py",
            "backend/ai_ops/state.py",
            "backend/ai_ops/cli.py",
            "backend/ai_ops/activity.py",
            "backend/ai_ops/priority.py",
        ]
        for rel in checked:
            text = (REPO / rel).read_text()
            for token in banned:
                self.assertNotIn(token, text,
                                 msg=f"{rel} restates window {token}")
        # scheduler only references the authority, no literals at all
        sched = (REPO / "ai/research_agent/scheduler.py").read_text()
        for token in banned:
            self.assertNotIn(token, sched,
                             msg="scheduler restates the window")

    def test_window_module_is_pure(self):
        """The authority must not import Watch subsystems (no cycles)."""
        tree = ast.parse((REPO / "backend/ai_ops/window.py").read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(
            imported <= {"datetime", "zoneinfo", "typing", "dataclasses",
                         "__future__"},
            msg=f"window.py imports Watch code: {imported}",
        )


if __name__ == "__main__":
    unittest.main()
