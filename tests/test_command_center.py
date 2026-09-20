"""tests/test_command_center.py — WATCH Command Center v1 focused tests.

Covers exactly the new behavior:

- ``backend.watchlist_data`` read-only projections over synthetic local
  watchlist artifacts (snapshots / deltas / evidence): program discovery,
  candidate/evidence-gap merge, delta + match-state counts, bounded recent
  activity, honest empty states, malformed-artifact tolerance.
- ``/ui/command`` server-rendered page through the real app: real data is
  surfaced, forbidden confirmation words are absent, empty state is honest.
- ``/api/command/overview`` bounded JSON projection.
- sidebar navigation to the Command Center from the existing pages.

Fully offline: Mongo-backed dashboard queries are mocked and the watchlist
root points at a temp directory. No network, no writes, no LLM.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


def _snapshot_payload(program="dell", snapshot_id="watch-20260919T203013Z",
                      created="2026-09-19T20:30:13Z", delta="NEW",
                      previous=""):
    return {
        "watchlist_version": "watchlist-1",
        "rule_version": "watchlist-1",
        "snapshot_id": snapshot_id,
        "created_utc": created,
        "program": program,
        "cve_count": 1,
        "match_state_counts": {"WEAK": 1},
        "delta_counts": {"NEW": 1, "CHANGED": 0, "UNCHANGED": 0},
        "previous_snapshot_id": previous,
        "entries": [{
            "cve_id": "CVE-2020-11022",
            "program": program,
            "match_state": "WEAK",
            "confidence": "LOW",
            "strongest_match_type": "VERSION",
            "strongest_confidence": "LOW",
            "matched_component": "",
            "matched_version": "1.12.4",
            "matched_parameter": "",
            "match_summary": (
                "Observed version satisfies the affected range; "
                "component not confirmed."
            ),
            "research_status": "NOT YET SUFFICIENT",
            "version_state": "MATCH",
            "version_association_state": "VERSION_MATCH_WITHIN_SAME_FAMILY",
            "version_association_reason": "same family",
            "resolved_blockers": ["version_unknown"],
            "remaining_blockers": ["plugin_not_observed"],
            "missing": ["PRODUCT"],
            "match_row_count": 1,
            "match_rows": [{
                "match_id": "am-67dd1daa94629032",
                "match_type": "VERSION",
                "matched_value": "1.12.4",
                "confidence": "LOW",
            }],
            "delta": delta,
            "queue": {
                "present": True,
                "relevance": "MEDIUM",
                "priority_class": "MEDIUM_RESEARCH",
                "queue_score": 45,
            },
        }],
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


class _WatchlistFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._env = mock.patch.dict(
            os.environ, {"WATCH_RESEARCH_WATCHLIST_DIR": str(self.root)}
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def write_snapshot(self, payload, program=None):
        program = program or payload.get("program") or "dell"
        directory = self.root / program
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{payload['snapshot_id']}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path


# --------------------------------------------------------------------------
# Data layer
# --------------------------------------------------------------------------


class TestWatchlistData(_WatchlistFixture):
    def test_parse_utc_valid_and_invalid(self):
        from backend import watchlist_data as wd

        parsed = wd.parse_utc("2026-09-19T20:30:13Z")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.isoformat(), "2026-09-19T20:30:13+00:00")
        self.assertIsNone(wd.parse_utc("not-a-time"))
        self.assertIsNone(wd.parse_utc(None))

    def test_missing_root_is_honest_empty(self):
        from backend import watchlist_data as wd

        empty = self.root / "nope"
        payload = wd.overview(empty)
        self.assertFalse(payload["available"])
        self.assertFalse(payload["root_available"])
        self.assertEqual(payload["programs"], [])
        self.assertEqual(payload["totals"]["cves"], 0)

    def test_list_programs_ignores_non_snapshot_dirs(self):
        from backend import watchlist_data as wd

        self.write_snapshot(_snapshot_payload())
        (self.root / "evidence" / "dell").mkdir(parents=True)
        (self.root / "emptyprog").mkdir()
        self.assertEqual(wd.list_programs(self.root), ["dell"])

    def test_overview_candidate_uses_existing_evidence_gaps(self):
        from backend import watchlist_data as wd

        self.write_snapshot(_snapshot_payload())
        payload = wd.overview(self.root)
        self.assertTrue(payload["available"])
        view = payload["programs"][0]
        self.assertEqual(view["cve_count"], 1)
        self.assertEqual(view["delta_counts"]["NEW"], 1)
        self.assertEqual(view["match_state_counts"], {"WEAK": 1})
        candidate = view["candidates"][0]
        # the conservative vocabulary is surfaced verbatim
        self.assertEqual(candidate["match_state"], "WEAK")
        self.assertEqual(candidate["finding_readiness"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("COMPONENT_IDENTITY", candidate["gap_missing"])
        self.assertIn("VERSION_IDENTITY", candidate["gap_present"])
        self.assertEqual(candidate["matched_version"], "1.12.4")
        self.assertEqual(candidate["strongest_match_type"], "VERSION")
        self.assertEqual(candidate["strongest_match_value"], "1.12.4")
        # readiness aggregates for the program
        self.assertEqual(
            view["readiness_counts"].get("INSUFFICIENT_EVIDENCE"), 1
        )

    def test_overview_delta_counts_fallback_from_entries(self):
        from backend import watchlist_data as wd

        payload = _snapshot_payload()
        payload.pop("delta_counts")
        payload.pop("match_state_counts")
        self.write_snapshot(payload)
        view = wd.overview(self.root)["programs"][0]
        self.assertEqual(view["delta_counts"], {"NEW": 1, "CHANGED": 0,
                                                "UNCHANGED": 0})
        self.assertEqual(view["match_state_counts"], {"WEAK": 1})

    def test_malformed_artifact_is_skipped_not_fatal(self):
        from backend import watchlist_data as wd

        self.write_snapshot(_snapshot_payload())
        bad = self.root / "dell" / "watch-20260918T000000Z.json"
        bad.write_text("{not json", encoding="utf-8")
        payload = wd.overview(self.root)
        self.assertTrue(payload["available"])
        self.assertEqual(payload["programs"][0]["cve_count"], 1)

    def test_recent_activity_real_artifacts_only(self):
        from backend import watchlist_data as wd

        self.write_snapshot(_snapshot_payload(previous="watch-20260918T000000Z"))
        (self.root / "dell" / "delta-abc_to_def-0123abcd.json").write_text(
            json.dumps({
                "delta_id": "delta-abc_to_def-0123abcd",
                "program": "dell",
                "created_utc": "2026-09-19T21:00:00Z",
                "summary": {"NEW_CVE": 1, "UNCHANGED": 4},
            }),
            encoding="utf-8",
        )
        evdir = self.root / "evidence" / "dell"
        evdir.mkdir(parents=True)
        (evdir / "wev-0123456789abcdef.json").write_text(
            json.dumps({
                "program": "dell",
                "state": "ACQUIRED",
                "evidence_type": "APPLICATION_RESPONSE",
                "method": "HTTP_GET",
                "collected_at": "2026-09-19T22:00:00Z",
            }),
            encoding="utf-8",
        )
        items = wd.recent_activity(self.root)
        kinds = [item["kind"] for item in items]
        self.assertEqual(
            kinds,
            ["EVIDENCE_ACQUISITION", "WATCHLIST_DELTA", "WATCHLIST_RUN"],
        )
        # newest first, real timestamps
        self.assertEqual(items[0]["at"].isoformat(), "2026-09-19T22:00:00+00:00")
        self.assertIn("1 CVE(s)", items[-1]["detail"])


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------


class TestCommandCenterRoutes(_WatchlistFixture):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    def _fake_runs(self):
        return [{
            "task_id": "crawl_all",
            "name": "Crawl All (full corpus)",
            "status": "success",
            "last_run": {
                "id": "1",
                "started_at": None,
                "finished_at": None,
                "duration": "2h 14m",
                "triggered_by": "timer",
            },
        }]

    def test_page_renders_real_data_and_never_confirms(self):
        self.write_snapshot(_snapshot_payload())
        with mock.patch("backend.dashboard.latest_runs",
                        return_value=self._fake_runs()):
            r = self._get("/ui/command")
        self.assertEqual(r.status_code, 200)
        text = r.text
        self.assertIn("Command Center", text)
        self.assertIn("WATCHLIST RESEARCH ONLY", text)
        self.assertIn("CVE-2020-11022", text)
        self.assertIn("WEAK", text)
        self.assertIn("INSUFFICIENT_EVIDENCE", text)
        self.assertIn("missing: COMPONENT_IDENTITY", text)
        self.assertIn("Watchlist sweep", text)
        # never assert a vulnerability
        self.assertNotIn("Vulnerable", text)
        self.assertNotIn("Exploitable", text)

    def test_page_empty_state_is_honest(self):
        with mock.patch("backend.dashboard.latest_runs", return_value=[]):
            r = self._get("/ui/command")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No watchlist snapshots available", r.text)
        # no fabricated numbers for the watchlist section
        self.assertIn("No candidates to show", r.text)

    def test_json_projection_is_bounded_and_link_free(self):
        self.write_snapshot(_snapshot_payload())
        with mock.patch("backend.dashboard.latest_runs",
                        return_value=self._fake_runs()):
            r = self._get("/api/command/overview")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        for key in ("watchlist", "activity", "runs", "last_successful_run",
                    "timeline"):
            self.assertIn(key, body)
        self.assertEqual(body["watchlist"]["totals"]["cves"], 1)
        candidate = body["watchlist"]["programs"][0]["candidates"][0]
        # JSON projection carries no credential-bearing URL
        self.assertNotIn("research_url", candidate)

    def test_sidebar_links_to_command_center(self):
        for path, patch_target in (
            ("/", "backend.dashboard"),
            ("/ui/command", "backend.dashboard"),
        ):
            with self.subTest(path=path):
                counts = {"programs": 0, "subdomains": 0, "live": 0,
                          "http": 0, "urls": 0, "endpoints": 0,
                          "params": 0, "fresh_http_24h": 0}
                with mock.patch("backend.dashboard.global_counts",
                                return_value=counts), \
                     mock.patch("backend.dashboard.program_rows",
                                return_value=[]), \
                     mock.patch("backend.dashboard.latest_runs",
                                return_value=[]), \
                     mock.patch("backend.dashboard.recent_changes",
                                return_value=[]), \
                     mock.patch("backend.dashboard.activity_summary",
                                return_value={"total": 0}):
                    r = self._get(path)
                self.assertEqual(r.status_code, 200)
                link = re.search(
                    r'<a class="side-link[^"]*" href="([^"]*)"[^>]*>\s*'
                    r'<span class="side-ico">[^<]*</span>Command Center</a>',
                    r.text,
                )
                self.assertIsNotNone(link, f"{path}: missing Command Center link")
                self.assertEqual(link.group(1).split("?")[0], "/ui/command")

    def test_command_route_resolves(self):
        with mock.patch("backend.dashboard.latest_runs", return_value=[]):
            r = self._get("/ui/command")
        self.assertEqual(r.status_code, 200)

    def test_page_is_fail_soft_when_activity_collector_unavailable(self):
        self.write_snapshot(_snapshot_payload())
        with mock.patch("backend.routers.command_center._collect_activity",
                        return_value=None), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]):
            r = self._get("/ui/command")
        self.assertEqual(r.status_code, 200)
        self.assertIn("activity collector unavailable", r.text)
        # watchlist data is unaffected by the runtime collector failure
        self.assertIn("CVE-2020-11022", r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
