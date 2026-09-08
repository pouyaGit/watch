"""
tests/test_tz.py — Unit tests for backend/tz.py (Tehran timezone helpers).
"""
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from zoneinfo import ZoneInfo

from backend.tz import (
    TEHRAN,
    age_days,
    fmt_ago,
    fmt_duration,
    fmt_tehran,
    fmt_time,
    is_stale,
    tehran_now,
    to_tehran,
)


class TestStorageTimeZone(unittest.TestCase):
    """VERIFIED production assumption: every writer uses naive
    ``datetime.now()`` on a box whose /etc/timezone is Asia/Tehran, so the
    DB stores Tehran WALL-CLOCK time. Conversion must be driven by the
    STORAGE_TZ constant -- never the process locale."""

    def test_naive_is_interpreted_as_tehran_not_utc(self):
        # A naive 15:42 must come out as Tehran 15:42 (NOT 19:12 if it were
        # misinterpreted as UTC, and NOT shifted by the process locale).
        naive = datetime(2026, 8, 31, 15, 42)
        out = to_tehran(naive)
        self.assertEqual(out.tzinfo, TEHRAN)
        self.assertEqual(out.hour, 15)
        self.assertEqual(out.minute, 42)

    def test_interpretation_is_driven_by_storage_tz(self):
        # Prove the conversion follows STORAGE_TZ: if the storage convention
        # were UTC, the same naive value would shift +3:30.
        with mock.patch(
            "backend.tz.STORAGE_TZ", ZoneInfo("UTC")
        ):
            out = to_tehran(datetime(2026, 8, 31, 15, 42))
        self.assertEqual(out.tzinfo, TEHRAN)
        self.assertEqual(out.hour, 19)  # 15:42 UTC -> 19:12 Tehran

    def test_correct_even_if_server_is_utc(self):
        # Simulate the web process running under TZ=UTC: conversion relies
        # only on STORAGE_TZ, so naive values stay Tehran regardless.
        naive = datetime(2026, 8, 31, 15, 42)
        with mock.patch("backend.tz.STORAGE_TZ", TEHRAN):
            out = to_tehran(naive)
        self.assertEqual(out.hour, 15)
        self.assertEqual(out.tzinfo, TEHRAN)

    def test_fmt_ago_uses_tehran_interpretation_for_naive_now(self):
        # A naive reference clock must be read as Tehran, not UTC (this used
        # to hardcode UTC and skew all relative times by 3h30m).
        with mock.patch("backend.tz.STORAGE_TZ", TEHRAN):
            delta = timedelta(hours=2)
            out = fmt_ago(datetime.now() - delta, now=datetime.now())
        self.assertEqual(out, "2h ago")


class TestToTehran(unittest.TestCase):
    def test_none_returns_none(self):
        self.assertIsNone(to_tehran(None))

    def test_naive_datetime_converted(self):
        # A naive datetime is assumed server-local; astimezone() attaches
        # the system tz then converts to Tehran.
        naive = datetime(2026, 8, 31, 12, 0, 0)
        result = to_tehran(naive)
        self.assertIsNotNone(result)
        self.assertEqual(result.tzinfo, TEHRAN)

    def test_aware_utc_converted(self):
        utc = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
        tehran = to_tehran(utc)
        # Tehran is UTC+3:30
        self.assertEqual(tehran.hour, 15)
        self.assertEqual(tehran.minute, 30)

    def test_aware_tehran_passthrough(self):
        t = datetime(2026, 8, 31, 15, 42, tzinfo=TEHRAN)
        self.assertEqual(to_tehran(t), t)


class TestFmtTehran(unittest.TestCase):
    def test_none_shows_emdash(self):
        self.assertEqual(fmt_tehran(None), "—")

    def test_format(self):
        t = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
        result = fmt_tehran(t)
        self.assertIn("2026", result)
        self.assertIn("Aug", result)

    def test_fmt_time(self):
        t = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
        result = fmt_time(t)
        self.assertEqual(result, "15:30")  # UTC+3:30


class TestFmtAgo(unittest.TestCase):
    def test_none_shows_never(self):
        self.assertEqual(fmt_ago(None), "never")

    def test_just_now(self):
        now = tehran_now()
        self.assertEqual(fmt_ago(now), "just now")

    def test_minutes(self):
        now = tehran_now()
        t = now - timedelta(minutes=5)
        self.assertEqual(fmt_ago(t), "5m ago")

    def test_hours(self):
        now = tehran_now()
        t = now - timedelta(hours=3)
        self.assertEqual(fmt_ago(t), "3h ago")

    def test_days(self):
        now = tehran_now()
        t = now - timedelta(days=2)
        self.assertEqual(fmt_ago(t), "2d ago")

    def test_future_treated_as_just_now(self):
        now = tehran_now()
        t = now + timedelta(hours=1)
        self.assertEqual(fmt_ago(t), "just now")


class TestFmtDuration(unittest.TestCase):
    def test_none_start(self):
        self.assertEqual(fmt_duration(None), "—")

    def test_seconds(self):
        a = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
        b = datetime(2026, 8, 31, 12, 0, 45, tzinfo=timezone.utc)
        self.assertEqual(fmt_duration(a, b), "45s")

    def test_minutes(self):
        a = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
        b = datetime(2026, 8, 31, 12, 32, 0, tzinfo=timezone.utc)
        self.assertEqual(fmt_duration(a, b), "32m")

    def test_hours_minutes(self):
        a = datetime(2026, 8, 31, 10, 0, 0, tzinfo=timezone.utc)
        b = datetime(2026, 8, 31, 12, 14, 0, tzinfo=timezone.utc)
        self.assertEqual(fmt_duration(a, b), "2h 14m")

    def test_days(self):
        a = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
        b = datetime(2026, 8, 31, 10, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(fmt_duration(a, b), "3d")

    def test_running_duration_until_now(self):
        # A running task has no finished_at: duration is start -> now.
        fixed_now = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
        start = fixed_now - timedelta(minutes=90)
        with mock.patch("backend.tz.tehran_now", return_value=fixed_now):
            self.assertEqual(fmt_duration(start), "1h 30m")


class TestAgeDays(unittest.TestCase):
    def test_none_returns_none(self):
        self.assertIsNone(age_days(None))

    def test_today_zero(self):
        self.assertEqual(age_days(tehran_now()), 0)

    def test_three_days(self):
        t = tehran_now() - timedelta(days=3)
        self.assertEqual(age_days(t), 3)


class TestIsStale(unittest.TestCase):
    def test_none_is_stale(self):
        self.assertTrue(is_stale(None, 7))

    def test_recent_not_stale(self):
        t = tehran_now() - timedelta(days=3)
        self.assertFalse(is_stale(t, 7))

    def test_old_is_stale(self):
        t = tehran_now() - timedelta(days=10)
        self.assertTrue(is_stale(t, 7))


if __name__ == "__main__":
    unittest.main()
