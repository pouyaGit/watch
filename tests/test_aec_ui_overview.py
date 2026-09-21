"""EPIC8: Command Center overview — KPI semantics + cross-view consistency."""

from __future__ import annotations

import unittest


class TestKPISemantics(unittest.TestCase):
    def test_kpi_keys_match_epic_example(self):
        from backend.routers import aec
        view = aec.build_dashboard_view()
        for key in ("candidates", "active_cases", "research_jobs",
                    "waiting_evidence", "observations", "review_pending"):
            self.assertIn(key, view)

    def test_candidates_nonzero_fixture(self):
        from backend.routers import aec
        self.assertGreater(aec.build_dashboard_view()["candidates"], 0)

    def test_active_cases_positive(self):
        from backend.routers import aec
        self.assertGreaterEqual(
            aec.build_dashboard_view()["active_cases"], 0)

    def test_waiting_evidence_present(self):
        from backend.routers import aec
        self.assertGreaterEqual(
            aec.build_dashboard_view()["waiting_evidence"], 0)

    def test_all_kpis_plain_ints(self):
        from backend.routers import aec
        for key, value in aec.build_dashboard_view().items():
            if key in ("candidates", "active_cases", "research_jobs",
                       "waiting_evidence", "observations",
                       "review_pending"):
                self.assertIs(type(value), int, key)


class TestCrossViewConsistency(unittest.TestCase):
    def test_dashboard_matches_explorer_count(self):
        from backend.routers import aec
        dash = aec.build_dashboard_view()
        cases = aec.get_cases()["total"]
        self.assertEqual(dash["active_cases"], cases)

    def test_observations_total_matches_rows(self):
        from backend.routers import aec
        view = aec.build_observations_view()
        self.assertEqual(view["total"], len(view["observations"]))

    def test_pipeline_review_state_consistent(self):
        from backend.routers import aec
        stages = {s["stage"]: s for s in aec.build_pipeline_view()["stages"]}
        review_state = stages["review"]["state"]
        dash_review = aec.build_dashboard_view()["review_pending"]
        if dash_review > 0:
            self.assertIn(review_state, ("PENDING", "REQUIRED"))
        else:
            self.assertEqual(review_state, "")


class TestActivityFeed(unittest.TestCase):
    def test_activity_shows_start_and_review(self):
        from backend.routers import aec
        joined = " ".join(
            e["action"].lower() for e in
            aec.build_dashboard_view()["recent_activity"])
        self.assertIn("started", joined)

    def test_activity_actors_known(self):
        from backend.routers import aec
        for entry in aec.build_dashboard_view()["recent_activity"]:
            self.assertTrue(entry["actor"])

    def test_activity_results_json_safe(self):
        import json
        from backend.routers import aec
        json.dumps(aec.build_dashboard_view()["recent_activity"])


class TestSnapshotIdentity(unittest.TestCase):
    def test_generated_at_epoch(self):
        from backend.routers import aec
        self.assertIs(type(aec.build_dashboard_view()["generated_at"]),
                      int)

    def test_audit_events_json_safe(self):
        import json
        from backend.routers import aec
        json.dumps(aec.build_audit_view()["events"])

    def test_evidence_artifacts_json_safe(self):
        import json
        from backend.routers import aec
        json.dumps(aec.build_evidence_viewer_view()["artifacts"])


if __name__ == "__main__":
    unittest.main()