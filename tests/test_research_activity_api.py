"""Focused tests for the R83 AI activity status API and collector.

Hermetic tests use temporary directories and injected fixtures; API tests use
the real FastAPI app (existing convention). No Mongo, no network and no
OpenRouter dependency; nothing in the research data directories is modified.
"""

from __future__ import annotations

import fcntl
import inspect
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

from config import config
from fastapi.testclient import TestClient

from ai.knowledge.ai_activity_status import STATUSES
from ai.research_agent import storage as agent_storage
from backend import research_activity as activity

API_KEY = config().get("API_KEY", "")
TEHRAN = ZoneInfo("Asia/Tehran")
RUNS_DIR = Path("ai_data/research/agent/runs")

FORBIDDEN_PRIMITIVES = (
    "subprocess",
    "socket",
    "requests",
    "httpx",
    "urllib",
    "pymongo",
    "MongoClient",
    "openai",
    "write_text",
    "persist_result",
    "insert_one",
    "update_one",
    "delete_one",
    "store_run",
)


def _params(**extra):
    params = {"api_key": API_KEY} if API_KEY else {}
    params.update(extra)
    return params


def _fixture_run(now: datetime) -> dict:
    started = now - timedelta(minutes=5)
    return {
        "run_id": "run-20990101T000000Z",
        "started_at": started.isoformat(),
        "completed_at": now.isoformat(),
        "dry_run": False,
        "forced": False,
        "enabled": True,
        "in_window": True,
        "window": "12:00-00:00 Asia/Tehran",
        "network": True,
        "llm": False,
        "plans_selected": 1,
        "plans_processed": 1,
        "result_ids": ["loop-abc"],
        "results": [
            {
                "plan_id": "r22-38d26f10681e9a0f",
                "result_id": "loop-abc",
                "cve_id": "CVE-2026-1557",
                "program": "dell",
                "status": "RESEARCH_COMPLETED",
                "evidence": 2,
                "sources": 3,
            }
        ],
        "failures": [],
        "status": "RESEARCH_COMPLETED",
        "skipped": None,
    }


def _fixture_case() -> dict:
    return {
        "program": "indeed",
        "validation": {"accepted_count": 1, "rejected_count": 2},
        "acquisition_plan": {"summary": {"requirements_available": 2}},
        "action_plan": {"summary": {"action_count": 1}},
        "research_case_workspace": {
            "cases": [
                {
                    "case_id": "case-indeed-a1-endpoint-behavior",
                    "program": "indeed",
                    "category": "RECON",
                    "status": "WAITING_FOR_EVIDENCE",
                    "evidence": {"available_count": 2, "missing_count": 2},
                    "readiness": {
                        "sufficiency_state": "INSUFFICIENT",
                        "decision_state": "NEEDS_EVIDENCE",
                    },
                }
            ]
        },
        # raw source URLs must never be projected into activity output
        "provider": {"url": "http://target.example/secret"},
    }


class TestLockProbe(unittest.TestCase):
    def test_free_then_held(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "research.lock"
            lock.touch()
            state, _ = activity.probe_lock([str(lock)])
            self.assertEqual(state, "free")
            fd = os.open(str(lock), os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                state, notes = activity.probe_lock([str(lock)])
                self.assertEqual(state, "held")
                self.assertTrue(notes)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            state, _ = activity.probe_lock([str(lock)])
            self.assertEqual(state, "free")

    def test_missing_paths_are_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, _ = activity.probe_lock([str(Path(tmp) / "nope.lock")])
            self.assertEqual(state, "free")

    def test_unreadable_path_is_unavailable(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses file permissions")
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "locked.lock"
            lock.touch()
            lock.chmod(0o000)
            try:
                state, _ = activity.probe_lock([str(lock)])
                self.assertEqual(state, "unavailable")
            finally:
                lock.chmod(0o600)


class TestCollector(unittest.TestCase):
    def test_read_run_records_bounded_and_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for index in range(3):
                agent_storage.store_run(
                    {
                        "run_id": f"run-2099010{index + 1}T000000Z",
                        "started_at": f"2099-01-0{index + 1}T13:00:00+03:30",
                        "completed_at": f"2099-01-0{index + 1}T13:01:00+03:30",
                        "status": "RESEARCH_COMPLETED",
                    },
                    base=base,
                )
            before = {
                path.name: path.read_bytes()
                for path in (base / "runs").glob("*.json")
            }
            records = activity.read_run_records(base, limit=2)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["run_id"], "run-20990103T000000Z")
            after = {
                path.name: path.read_bytes()
                for path in (base / "runs").glob("*.json")
            }
            self.assertEqual(before, after)

    def test_read_case_records_projection_hides_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "r83").mkdir()
            (root / "r83" / "case.json").write_text(
                json.dumps(_fixture_case()), encoding="utf-8"
            )
            records = activity.read_case_records(root)
            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertEqual(record["case_id"], "case-indeed-a1-endpoint-behavior")
            self.assertEqual(record["case_status"], "WAITING_FOR_EVIDENCE")
            self.assertEqual(record["validation_accepted"], "1")
            self.assertEqual(record["missing_count"], "2")
            self.assertTrue(record["modified_at"])
            text = json.dumps(record)
            self.assertNotIn("://", text)
            self.assertNotIn("secret", text)

    def test_collect_activity_hermetic(self):
        now = datetime(2099, 1, 2, 13, 0, tzinfo=TEHRAN)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            agent_storage.store_run(
                _fixture_run(now), base=base / "agent"
            )
            policy = {
                "window_start": "12:00",
                "window_end": "00:00",
                "timezone": "Asia/Tehran",
                "enabled": True,
            }
            with mock.patch.object(
                activity, "_scheduler_policy", return_value=policy
            ):
                result = activity.collect_activity(
                    now=now,
                    agent_base=base / "agent",
                    research_base=base / "research",
                    lock_candidates=[str(base / "missing.lock")],
                )
        self.assertEqual(result["rule_version"], "r83-1")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["daily"]["runs"], 1)
        self.assertEqual(result["daily"]["plans_processed"], 1)
        self.assertIsNone(result["current_case"])
        self.assertEqual(result["last_run"]["duration_seconds"], 300.0)

    def test_collect_activity_unknown_when_unobservable(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses file permissions")
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "locked.lock"
            lock.touch()
            lock.chmod(0o000)
            try:
                result = activity.collect_activity(
                    now=datetime(2099, 1, 2, 13, 0, tzinfo=TEHRAN),
                    agent_base=Path(tmp) / "no-agent",
                    research_base=Path(tmp) / "no-research",
                    lock_candidates=[str(lock)],
                )
            finally:
                lock.chmod(0o600)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn(
            "execution_lock_state",
            result["observability"]["unavailable_fields"],
        )

    def test_collector_is_fail_soft_per_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                agent_storage, "list_runs", side_effect=OSError("boom")
            ):
                result = activity.collect_activity(
                    lock_candidates=[],
                    agent_base=Path(tmp) / "agent",
                    research_base=Path(tmp) / "research",
                )
        self.assertIn(
            "run_records",
            " ".join(result["observability"]["source_errors"]),
        )

    def test_no_forbidden_primitives_in_new_modules(self):
        import ai.knowledge.ai_activity_status as core
        import backend.routers.research_activity as router

        for module in (core, activity, router):
            source = inspect.getsource(module)
            for primitive in FORBIDDEN_PRIMITIVES:
                self.assertNotIn(primitive, source, f"{module.__name__}: {primitive}")


class TestActivityApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def test_auth_gate(self):
        if not API_KEY:
            self.skipTest("API key not configured")
        response = self.client.get("/api/research/activity")
        self.assertEqual(response.status_code, 401)

    def test_activity_contract_bounded(self):
        response = self.client.get(
            "/api/research/activity", params=_params()
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["rule_version"], "r83-1")
        self.assertIn(body["status"], STATUSES)
        self.assertEqual(body["window"]["timezone"], "Asia/Tehran")
        self.assertIn(
            body["window"]["start"], ("12:00", body["window"]["start"])
        )
        self.assertTrue(body["observability"]["unknown_is_not_failure"])
        self.assertTrue(body["research_only"])
        self.assertEqual(body["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(body["safety"]["execution_performed"])
        self.assertFalse(body["safety"]["vulnerability_confirmed"])
        self.assertFalse(body["safety"]["exploit_authorized"])
        self.assertTrue(body["safety"]["human_authority_required"])
        text = json.dumps(body)
        for forbidden in ("://", "sk-", "Bearer", '"_id"', "Traceback"):
            self.assertNotIn(forbidden, text)

    def test_activity_is_read_only(self):
        before = {
            path.name: path.read_bytes()
            for path in RUNS_DIR.glob("*.json")
        }
        self.client.get("/api/research/activity", params=_params())
        after = {
            path.name: path.read_bytes()
            for path in RUNS_DIR.glob("*.json")
        }
        self.assertEqual(before, after)

    def test_fail_soft_route(self):
        with mock.patch.object(
            activity, "collect_activity", side_effect=RuntimeError("boom")
        ):
            response = self.client.get(
                "/api/research/activity", params=_params()
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "UNKNOWN")
        self.assertIn(
            "collector_RuntimeError",
            body["observability"]["source_errors"],
        )
        self.assertNotIn("Traceback", response.text)

    def test_r81_and_r82_still_work(self):
        cases = self.client.get("/api/research/cases", params=_params())
        self.assertEqual(cases.status_code, 200)
        self.assertGreaterEqual(cases.json()["total"], 1)
        detail = self.client.get(
            "/api/research/cases/case-indeed-a1-endpoint-behavior",
            params=_params(),
        )
        self.assertEqual(detail.status_code, 200)
        page = self.client.get("/static/research/index.html")
        self.assertEqual(page.status_code, 200)
        self.assertIn("AI Runtime Activity", page.text)
        script = self.client.get("/static/js/research_dashboard.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn("/api/research/activity", script.text)


if __name__ == "__main__":
    unittest.main()
