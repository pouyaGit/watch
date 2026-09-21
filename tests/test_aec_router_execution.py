"""EPIC6 Part 13: additive command-center endpoints for the execution layer."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from backend.routers import aec

WATCH_RECORD = {
    "subdomain": "shop.example.com",
    "url": "/orders?order_id=",
    "endpoint": "/orders",
    "parameter": "order_id",
    "method": "GET",
    "location": "query",
    "technology": ["flask"],
    "source": "watch",
    "id": "srv-1",
    "category": "IDOR_CANDIDATE",
}

FIXTURE_GRANTED = {WATCH_RECORD["id"]: {"status": "GRANTED",
                                        "expires_tick": 100}}


def sample_run():
    try:
        from aec.runtime import loop

        return loop.run_execution(
            [WATCH_RECORD], "fixture", authz=FIXTURE_GRANTED).to_dict()
    except ImportError:  # RED phase: loop not implemented yet
        return {
            "run_id": "run-x", "source_mode": "OFFLINE_FIXTURE",
            "candidate_count": 0, "case_count": 0, "job_count": 0,
            "queued_count": 0, "blocked_count": 0,
            "waiting_authorization_count": 0, "observation_count": 0,
            "evidence_count": 0, "review_required_count": 0,
            "completed_count": 0, "failed_count": 0, "duration": 0,
            "replay_identity": "x" * 64, "jobs": (), "evidence": (),
            "failures": (), "review_records": (), "blocked_reasons": (),
        }


class TestBuilders(unittest.TestCase):
    def test_execution_runs_view(self):
        view = aec.build_execution_runs_view([sample_run()])
        self.assertEqual(view["total"], 1)
        self.assertEqual(view["runs"][0]["source_mode"], "OFFLINE_FIXTURE")

    def test_research_jobs_view(self):
        view = aec.build_research_jobs_view(sample_run())
        self.assertEqual(sorted(view), ["jobs", "total"])

    def test_specialists_view(self):
        view = aec.build_specialists_view()
        self.assertEqual(view["total"], 5)
        roles = {item["role"] for item in view["specialists"]}
        self.assertIn("input-researcher", roles)
        self.assertIn("general-researcher", roles)

    def test_evidence_view(self):
        view = aec.build_evidence_view(sample_run())
        self.assertEqual(sorted(view), ["evidence", "total"])

    def test_execution_summary_view(self):
        view = aec.build_execution_summary_view(sample_run())
        self.assertEqual(view["source_mode"], "OFFLINE_FIXTURE")
        self.assertIn("run_id", view)
        self.assertIn("replay_identity", view)

    def test_summary_source_mode_present(self):
        view = aec.build_execution_summary_view(sample_run())
        self.assertIn("source_mode", view)


class TestRoutes(unittest.TestCase):
    def test_five_new_routes_exist(self):
        paths = [route.path for route in aec.router.routes]
        for expected in (
            "/api/aec/execution-runs",
            "/api/aec/research-jobs",
            "/api/aec/specialists",
            "/api/aec/evidence",
            "/api/aec/execution-summary",
        ):
            self.assertIn(expected, paths)

    def test_new_routes_are_get_only(self):
        for route in aec.router.routes:
            if route.path in (
                "/api/aec/execution-runs",
                "/api/aec/research-jobs",
                "/api/aec/specialists",
                "/api/aec/evidence",
                "/api/aec/execution-summary",
            ):
                self.assertEqual(sorted(route.methods), ["GET"])

    def test_execution_runs_handler(self):
        with patch.object(aec, "_execution_run", return_value=sample_run()):
            response = aec.get_execution_runs()
        self.assertIn("runs", response)
        self.assertEqual(response["runs"][0]["source_mode"], "OFFLINE_FIXTURE")

    def test_research_jobs_handler(self):
        with patch.object(aec, "_execution_run", return_value=sample_run()):
            response = aec.get_research_jobs()
        self.assertIn("jobs", response)
        self.assertIn("total", response)

    def test_specialists_handler(self):
        response = aec.get_specialists()
        self.assertEqual(response["total"], 5)

    def test_evidence_handler(self):
        with patch.object(aec, "_execution_run", return_value=sample_run()):
            response = aec.get_evidence()
        self.assertIn("evidence", response)

    def test_execution_summary_handler(self):
        with patch.object(aec, "_execution_run", return_value=sample_run()):
            response = aec.get_execution_summary()
        self.assertEqual(response["source_mode"], "OFFLINE_FIXTURE")

    def test_handlers_state_not_findings(self):
        with patch.object(aec, "_execution_run", return_value=sample_run()):
            response = aec.get_execution_summary()
        blob = str(response).lower()
        for marker in ("confirmed", "finding", "verdict"):
            self.assertNotIn(marker, blob)

    def test_routes_total_now_fourteen(self):
        paths = sorted(route.path for route in aec.router.routes)
        self.assertEqual(len(paths), 14)

    def test_no_mutation_endpoints(self):
        for route in aec.router.routes:
            self.assertEqual(sorted(route.methods), ["GET"])

    def test_legacy_routes_intact(self):
        for route in aec.router.routes:
            if route.path == "/api/aec/research-runs":
                self.assertEqual(sorted(route.methods), ["GET"])


if __name__ == "__main__":
    unittest.main()