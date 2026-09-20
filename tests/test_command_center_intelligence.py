"""tests/test_command_center_intelligence.py — Command Center Intelligence v1.

Focused tests for the new intelligence layer:

- ``backend.agent_operations`` — workspace/mode/branch resolution from Git
  metadata, agent report discovery + field parsing, normalized report
  activity and the read-only tmux socket probe.
- ``backend.command_intelligence`` — research-operations aggregation and the
  Discovery -> Metadata -> Evidence -> Verification -> Review lifecycle
  mapping.
- ``/ui/command`` and ``/api/command/overview`` — the new panels and payload
  keys render, and the page never emits a confirmation word.

Fully offline: agent workspace points at a temp directory, the watchlist root
points at a temp directory, Mongo-backed dashboard queries are mocked. No
network, no subprocess, no writes, no LLM.
"""
from __future__ import annotations

import json
import os
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


def _candidate(
    cve="CVE-2020-11022",
    *,
    match_state="WEAK",
    readiness="INSUFFICIENT_EVIDENCE",
    dimensions=None,
    missing=None,
    partial=None,
    blockers=None,
):
    """A candidate view shaped like ``backend.watchlist_data._candidate_view``."""

    return {
        "cve_id": cve,
        "program": "dell",
        "match_state": match_state,
        "confidence": "LOW",
        "research_status": "NOT YET SUFFICIENT",
        "finding_readiness": readiness,
        "evidence_state": "PARTIAL",
        "gap_dimensions": dimensions or [],
        "gap_missing": missing or [],
        "gap_partial": partial or [],
        "remaining_blockers": blockers or [],
    }


def _dim(name, state):
    return {"name": name, "state": state, "reason": "", "strategy": ""}


def _overview(candidates, *, available=True, program="dell"):
    return {
        "available": available,
        "root_available": available,
        "programs": [{
            "program": program,
            "snapshot_id": "watch-20260919T203013Z",
            "created_utc": None,
            "previous_snapshot_id": "",
            "cve_count": len(candidates),
            "snapshot_count": 2,
            "delta_counts": {"NEW": 1, "CHANGED": 0, "UNCHANGED": 0},
            "match_state_counts": {"WEAK": 1},
            "readiness_counts": {"INSUFFICIENT_EVIDENCE": 1},
            "latest_changes": [],
            "candidates": candidates,
        }],
        "totals": {"programs": 1, "cves": len(candidates), "delta": {},
                   "match_state": {}, "readiness": {}},
    }


class _AgentFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".git").mkdir()
        (self.root / ".git" / "HEAD").write_text(
            "ref: refs/heads/agent/daily-development\n", encoding="utf-8"
        )
        reports = self.root / "agent-reports"
        reports.mkdir()
        older = reports / "older-report.md"
        older.write_text("# Older\n\n## TASK\n\nold work\n", encoding="utf-8")
        latest = reports / "command-center-intelligence-layer-v1.md"
        latest.write_text(
            "# Command Center Intelligence Layer v1 — Report\n\n"
            "## TASK\n\nBuild the operational intelligence layer.\n\n"
            "## COMMIT STATUS\n\n"
            "COMMIT STATUS: committed on `agent/daily-development`.\n\n"
            "## PUSH STATUS\n\n"
            "PUSH STATUS: not pushed. Push is always manual.\n\n"
            "## READY TO PUSH\n\nREADY TO PUSH: YES\n",
            encoding="utf-8",
        )
        os.utime(older, (1, 1))
        os.utime(latest, (2, 2))
        self._env = mock.patch.dict(
            os.environ,
            {
                "WATCH_AGENT_DIR": str(self.root),
                "WATCH_AGENT_TMUX_SESSION": "watch-agent",
            },
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()


class TestAgentOperations(_AgentFixture):
    def test_workspace_mode_and_branch(self):
        from backend import agent_operations as ao

        facts = ao.workspace()
        self.assertEqual(facts["mode"], "AGENT")
        self.assertEqual(facts["branch"], "agent/daily-development")
        self.assertTrue(facts["git"])
        self.assertTrue(facts["branch_ok"])

    def test_production_mode_when_workspace_is_project_root(self):
        from backend import agent_operations as ao

        # The live worktree is on the agent branch, so pin a non-agent branch
        # to exercise the production fallback deterministically.
        with mock.patch.dict(os.environ, {"WATCH_AGENT_DIR": str(ao.PROJECT_ROOT)}), \
             mock.patch.object(ao, "current_branch", return_value="main"):
            facts = ao.workspace()
        self.assertEqual(facts["mode"], "PRODUCTION")

    def test_latest_report_fields_parsed(self):
        from backend import agent_operations as ao

        report = ao.latest_report()
        self.assertIsNotNone(report)
        self.assertEqual(report["name"], "command-center-intelligence-layer-v1.md")
        self.assertEqual(report["ready_to_push"], "YES")
        self.assertIn("committed", report["commit_status"])
        self.assertIn("operational intelligence", report["task"])

    def test_recent_report_activity_is_newest_first_and_normalized(self):
        from backend import agent_operations as ao

        items = ao.recent_report_activity()
        self.assertEqual(items[0]["kind"], "AGENT_REPORT")
        self.assertEqual(items[0]["ref"], "command-center-intelligence-layer-v1.md")
        self.assertIsNotNone(items[0]["at"])
        self.assertEqual(items[-1]["ref"], "older-report.md")

    def test_agent_operations_projection_keys(self):
        from backend import agent_operations as ao

        view = ao.agent_operations()
        for key in ("available", "mode", "workspace", "branch", "report_count",
                    "latest_report", "recent_reports", "tmux"):
            self.assertIn(key, view)
        self.assertEqual(view["mode"], "AGENT")
        self.assertEqual(view["report_count"], 2)

    def test_tmux_state_is_honest(self):
        from backend import agent_operations as ao

        state = ao.tmux_state()
        self.assertIn(state["state"],
                      {"SERVER_PRESENT", "SERVER_ABSENT", "UNKNOWN"})
        self.assertFalse(state["verified"])
        self.assertEqual(state["session"], "watch-agent")


class TestCommandIntelligence(unittest.TestCase):
    def test_research_operations_counts(self):
        from backend import command_intelligence as ci

        dims = [_dim("COMPONENT_IDENTITY", "MISSING"),
                _dim("VERSION_IDENTITY", "PRESENT")]
        candidates = [
            _candidate("CVE-2020-11022", dimensions=dims,
                       missing=["COMPONENT_IDENTITY"],
                       blockers=["plugin_not_observed"]),
            _candidate("CVE-2021-1234", dimensions=dims,
                       missing=["COMPONENT_IDENTITY", "TECHNOLOGY_IDENTITY"],
                       partial=["MATCH_STATE"]),
        ]
        ops = ci.research_operations(_overview(candidates))
        self.assertTrue(ops["available"])
        self.assertEqual(ops["candidate_count"], 2)
        self.assertEqual(ops["readiness"]["INSUFFICIENT_EVIDENCE"], 2)
        self.assertEqual(ops["match_states"]["WEAK"], 2)
        self.assertEqual(ops["confidence"]["LOW"], 2)
        missing = {item["dimension"]: item["count"]
                   for item in ops["missing_dimensions"]}
        self.assertEqual(missing["COMPONENT_IDENTITY"], 2)
        self.assertEqual(ops["snapshots"][0]["program"], "dell")

    def test_research_operations_unavailable_is_honest(self):
        from backend import command_intelligence as ci

        ops = ci.research_operations({"available": False})
        self.assertFalse(ops["available"])
        self.assertEqual(ops["candidate_count"], 0)
        self.assertEqual(ops["missing_dimensions"], [])

    def test_lifecycle_ready_candidate(self):
        from backend import command_intelligence as ci

        candidate = _candidate(
            readiness="EVIDENCE_READY",
            dimensions=[_dim("TECHNOLOGY_IDENTITY", "PRESENT"),
                        _dim("COMPONENT_IDENTITY", "PRESENT"),
                        _dim("VERSION_IDENTITY", "PRESENT")],
        )
        life = ci.candidate_lifecycle(candidate, has_report=True)
        states = {stage["stage"]: stage["state"] for stage in life["stages"]}
        self.assertEqual(states["Discovery"], ci.COMPLETE)
        self.assertEqual(states["Metadata"], ci.COMPLETE)
        self.assertEqual(states["Evidence"], ci.COMPLETE)
        self.assertEqual(states["Verification"], ci.PENDING)
        self.assertEqual(states["Review"], ci.COMPLETE)

    def test_lifecycle_blocked_candidate(self):
        from backend import command_intelligence as ci

        candidate = _candidate(
            dimensions=[_dim("TECHNOLOGY_IDENTITY", "MISSING"),
                        _dim("COMPONENT_IDENTITY", "MISSING"),
                        _dim("VERSION_IDENTITY", "MISSING")],
            missing=["COMPONENT_IDENTITY"],
        )
        life = ci.candidate_lifecycle(candidate)
        states = {stage["stage"]: stage["state"] for stage in life["stages"]}
        self.assertEqual(states["Metadata"], ci.BLOCKED)
        self.assertEqual(states["Evidence"], ci.BLOCKED)
        self.assertEqual(states["Verification"], ci.BLOCKED)
        self.assertEqual(states["Review"], ci.BLOCKED)

    def test_lifecycle_partial_candidate(self):
        from backend import command_intelligence as ci

        candidate = _candidate(
            readiness="EVIDENCE_PARTIAL",
            dimensions=[_dim("COMPONENT_IDENTITY", "PRESENT"),
                        _dim("VERSION_IDENTITY", "MISSING")],
            partial=["VERSION_IDENTITY"],
        )
        life = ci.candidate_lifecycle(candidate)
        states = {stage["stage"]: stage["state"] for stage in life["stages"]}
        self.assertEqual(states["Metadata"], ci.IN_PROGRESS)
        self.assertEqual(states["Evidence"], ci.IN_PROGRESS)
        self.assertEqual(states["Review"], ci.BLOCKED)

    def test_lifecycle_view_summary_and_probe(self):
        from backend import command_intelligence as ci

        candidates = [_candidate("CVE-2020-11022"),
                      _candidate("CVE-2021-1234")]
        overview = _overview(candidates)
        self.assertEqual(ci.report_cves_for(overview, probe=lambda cve: True),
                         {"CVE-2020-11022", "CVE-2021-1234"})
        view = ci.lifecycle_view(overview, report_cves={"CVE-2020-11022"})
        self.assertTrue(view["available"])
        self.assertEqual(view["candidate_count"], 2)
        self.assertEqual(len(view["summary"]), 5)
        review = [s for s in view["summary"] if s["stage"] == "Review"][0]
        self.assertEqual(review["complete"], 1)
        self.assertEqual(review["blocked"], 1)
        by_cve = {c["cve_id"]: c for c in view["candidates"]}
        self.assertTrue(by_cve["CVE-2020-11022"]["has_report"])
        self.assertFalse(by_cve["CVE-2021-1234"]["has_report"])

    def test_lifecycle_view_unavailable(self):
        from backend import command_intelligence as ci

        view = ci.lifecycle_view({"available": False})
        self.assertFalse(view["available"])
        self.assertEqual(view["candidates"], [])
        self.assertEqual(view["stages"], list(ci.STAGES))


class TestCommandCenterIntelligenceRoutes(_AgentFixture):
    def setUp(self):
        super().setUp()
        self._watch = tempfile.TemporaryDirectory()
        self.watch_root = Path(self._watch.name)
        self._watch_env = mock.patch.dict(
            os.environ, {"WATCH_RESEARCH_WATCHLIST_DIR": str(self.watch_root)}
        )
        self._watch_env.start()

    def tearDown(self):
        self._watch_env.stop()
        self._watch.cleanup()
        super().tearDown()

    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    def _write_snapshot(self):
        payload = {
            "watchlist_version": "watchlist-1",
            "snapshot_id": "watch-20260919T203013Z",
            "created_utc": "2026-09-19T20:30:13Z",
            "program": "dell",
            "cve_count": 1,
            "match_state_counts": {"WEAK": 1},
            "delta_counts": {"NEW": 1, "CHANGED": 0, "UNCHANGED": 0},
            "previous_snapshot_id": "",
            "entries": [{
                "cve_id": "CVE-2020-11022",
                "program": "dell",
                "match_state": "WEAK",
                "confidence": "LOW",
                "strongest_match_type": "VERSION",
                "matched_component": "",
                "matched_version": "1.12.4",
                "research_status": "NOT YET SUFFICIENT",
                "version_association_state": "VERSION_MATCH_WITHIN_SAME_FAMILY",
                "remaining_blockers": ["plugin_not_observed"],
                "missing": ["PRODUCT"],
                "match_rows": [{"match_id": "am-1", "match_type": "VERSION",
                                "matched_value": "1.12.4", "confidence": "LOW"}],
                "delta": "NEW",
                "queue": {"present": True, "relevance": "MEDIUM",
                          "priority_class": "MEDIUM_RESEARCH", "queue_score": 45},
            }],
        }
        directory = self.watch_root / "dell"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{payload['snapshot_id']}.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )

    def test_page_renders_intelligence_panels(self):
        self._write_snapshot()
        with mock.patch("backend.dashboard.latest_runs", return_value=[]), \
             mock.patch("backend.research_data.has_report", return_value=False):
            r = self._get("/ui/command")
        self.assertEqual(r.status_code, 200)
        text = r.text
        self.assertIn("Agent Operations", text)
        self.assertIn("Research Operations", text)
        self.assertIn("Findings Lifecycle", text)
        self.assertIn("Discovery", text)
        self.assertIn("CVE-2020-11022", text)
        self.assertIn("command-center-intelligence-layer-v1.md", text)
        self.assertNotIn("Vulnerable", text)
        self.assertNotIn("Exploitable", text)

    def test_json_projection_includes_intelligence_keys(self):
        self._write_snapshot()
        with mock.patch("backend.dashboard.latest_runs", return_value=[]), \
             mock.patch("backend.research_data.has_report", return_value=True):
            r = self._get("/api/command/overview")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        for key in ("agent", "research_ops", "lifecycle"):
            self.assertIn(key, body)
        self.assertEqual(body["agent"]["mode"], "AGENT")
        self.assertTrue(body["research_ops"]["available"])
        # JSON projection carries no credential-bearing URLs anywhere new
        self.assertNotIn("research_url", body["lifecycle"]["candidates"][0])
        review = [s for s in body["lifecycle"]["summary"]
                  if s["stage"] == "Review"][0]
        self.assertEqual(review["complete"], 1)

    def test_page_empty_watchlist_still_renders_agent_panel(self):
        with mock.patch("backend.dashboard.latest_runs", return_value=[]), \
             mock.patch("backend.research_data.has_report", return_value=False):
            r = self._get("/ui/command")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No research operations to show", r.text)
        self.assertIn("Agent Operations", r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
