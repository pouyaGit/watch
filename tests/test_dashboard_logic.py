"""
tests/test_dashboard_logic.py — Unit tests for the pure merge/sort/filter
logic in backend/dashboard.py (no database required).
"""
import unittest
from datetime import datetime, timedelta, timezone

from backend.dashboard import (
    SORT_KEYS,
    STALE_DAYS,
    _latest,
    compute_program_rows,
    filter_program_rows,
    sort_program_rows,
)


def _hours_ago(h):
    return datetime.now() - timedelta(hours=h)


def _metrics():
    """Two programs + one with no data at all."""
    return {
        "subs":       {"dell": 2481, "indeed": 900},
        "live":       {"dell": 1932, "indeed": 400},
        "http":       {"dell": 1821, "indeed": 380},
        "urls":       {"dell": 12431, "indeed": 5000},
        "endpoints":  {"dell": 4892, "indeed": 1500},
        "params":     {"dell": 1204, "indeed": 300},
        "changes":    {"dell": 3},
        "urls_last":  {"dell": _hours_ago(2)},
        "http_last":  {"dell": _hours_ago(1)},
        "live_last":  {"dell": _hours_ago(3)},
        "x8_last":    {"dell": _hours_ago(6)},
        "dns_static_last": {"dell": _hours_ago(4)},
        "dns_dynamic_last": {},
    }


class TestComputeProgramRows(unittest.TestCase):
    def test_merges_metrics(self):
        rows = compute_program_rows(["dell", "indeed"], _metrics())
        self.assertEqual(len(rows), 2)
        by = {r["program_name"]: r for r in rows}
        self.assertEqual(by["dell"]["subdomains"], 2481)
        self.assertEqual(by["dell"]["live"], 1932)
        self.assertEqual(by["dell"]["urls"], 12431)
        self.assertEqual(by["dell"]["endpoints"], 4892)
        self.assertEqual(by["dell"]["params"], 1204)
        self.assertEqual(by["dell"]["changes_24h"], 3)
        self.assertEqual(by["indeed"]["params"], 300)

    def test_missing_program_yields_zeros(self):
        rows = compute_program_rows(["ghost"], _metrics())
        r = rows[0]
        self.assertEqual(r["subdomains"], 0)
        self.assertEqual(r["live"], 0)
        self.assertIsNone(r["last_activity"])
        self.assertTrue(r["stale"])

    def test_dell_not_stale(self):
        rows = compute_program_rows(["dell"], _metrics())
        self.assertFalse(rows[0]["stale"])

    def test_last_activity_is_max(self):
        rows = compute_program_rows(["dell"], _metrics())
        self.assertIsNotNone(rows[0]["last_activity"])


class TestSortProgramRows(unittest.TestCase):
    def _rows(self):
        return compute_program_rows(["dell", "indeed", "ghost"], _metrics())

    def test_sort_by_name_asc(self):
        rows = sort_program_rows(self._rows(), "name", "asc")
        names = [r["program_name"] for r in rows]
        self.assertEqual(names, sorted(names))

    def test_sort_by_name_desc(self):
        rows = sort_program_rows(self._rows(), "name", "desc")
        names = [r["program_name"] for r in rows]
        self.assertEqual(names, sorted(names, reverse=True))

    def test_sort_by_live_desc(self):
        rows = sort_program_rows(self._rows(), "live", "desc")
        lives = [r["live"] for r in rows]
        self.assertEqual(lives, sorted(lives, reverse=True))

    def test_sort_numeric_with_zero_value(self):
        # Regression: a 0 count must not be coerced to datetime.min and
        # crash the comparison (int vs datetime).
        rows = self._rows()
        rows[0]["live"] = 0
        out = sort_program_rows(rows, "live", "asc")
        self.assertEqual(out[0]["live"], 0)

    def test_sort_by_updated_puts_none_last(self):
        rows = sort_program_rows(self._rows(), "updated", "desc")
        # ghost (no activity) must be last even in desc order
        self.assertEqual(rows[-1]["program_name"], "ghost")

    def test_unknown_sort_falls_back_to_name(self):
        rows = sort_program_rows(self._rows(), "bogus-key", "asc")
        names = [r["program_name"] for r in rows]
        self.assertEqual(names, sorted(names))

    def test_whitelist_covers_ui_columns(self):
        for key in ("name", "subdomains", "live", "http", "urls",
                    "endpoints", "params", "updated", "crawl", "dns", "param"):
            self.assertIn(key, SORT_KEYS)


class TestFilterProgramRows(unittest.TestCase):
    def _rows(self):
        return compute_program_rows(["dell", "indeed", "ghost"], _metrics())

    def test_all_returns_everything(self):
        self.assertEqual(len(filter_program_rows(self._rows(), "all")), 3)

    def test_active_excludes_stale(self):
        rows = filter_program_rows(self._rows(), "active")
        names = {r["program_name"] for r in rows}
        self.assertIn("dell", names)
        self.assertNotIn("ghost", names)

    def test_stale_only_stale(self):
        rows = filter_program_rows(self._rows(), "stale")
        self.assertEqual({r["program_name"] for r in rows}, {"ghost", "indeed"})

    def test_changes_only_rows_with_events(self):
        rows = filter_program_rows(self._rows(), "changes")
        self.assertEqual({r["program_name"] for r in rows}, {"dell"})

    def test_unknown_mode_returns_all(self):
        self.assertEqual(len(filter_program_rows(self._rows(), "bogus")), 3)


class TestLatest(unittest.TestCase):
    def test_ignores_none(self):
        a = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
        b = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(_latest(None, a, b), a)

    def test_all_none(self):
        self.assertIsNone(_latest(None, None))


class TestStaleConstant(unittest.TestCase):
    def test_threshold_is_seven_days(self):
        self.assertEqual(STALE_DAYS, 7)


if __name__ == "__main__":
    unittest.main()
