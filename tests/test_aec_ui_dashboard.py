"""EPIC8 Part 2: dashboard internals — counts and recent activity."""

from __future__ import annotations

import unittest


def view():
    from backend.routers import aec
    return aec.build_dashboard_view()


class TestCountDerivation(unittest.TestCase):
    def test_candidates_match_simulation(self):
        from backend.routers import aec
        sim = aec._simulation_run()
        self.assertEqual(view()["candidates"],
                         sim.get("candidates_processed"))

    def test_active_cases_match_simulation(self):
        from backend.routers import aec
        sim = aec._simulation_run()
        active = sum(
            1 for case in sim.get("cases", [])
            if case.get("state") not in ("COMPLETED", "REFUSED",
                                         "BLOCKED", "FAILED"))
        self.assertEqual(view()["active_cases"], active)

    def test_research_jobs_match_execution(self):
        from backend.routers import aec
        run = aec._execution_run()
        self.assertEqual(view()["research_jobs"],
                         run.get("job_count"))

    def test_observations_match_execution(self):
        from backend.routers import aec
        run = aec._execution_run()
        self.assertEqual(view()["observations"],
                         run.get("observation_count"))

    def test_review_pending_match_execution(self):
        from backend.routers import aec
        run = aec._execution_run()
        self.assertEqual(view()["review_pending"],
                         run.get("review_required_count"))

    def test_waiting_evidence_derived(self):
        from backend.routers import aec
        sim = aec._simulation_run()
        waiting = sum(
            1 for case in sim.get("cases", [])
            if case.get("evidence_state") == "WAITING_EVIDENCE")
        self.assertEqual(view()["waiting_evidence"], waiting)


class TestRecentActivity(unittest.TestCase):
    def test_entries_have_shape(self):
        for entry in view()["recent_activity"]:
            self.assertIn("timestamp", entry)
            self.assertIn("actor", entry)
            self.assertIn("action", entry)
            self.assertIn("result", entry)

    def test_actions_recognized(self):
        known = {"started", "created", "assigned", "authorized",
                 "observed", "evidence", "review", "blocked", "updated"}
        for entry in view()["recent_activity"]:
            action = entry["action"].lower()
            self.assertTrue(
                any(word in action for word in known), action)

    def test_bounded_length(self):
        self.assertLessEqual(len(view()["recent_activity"]), 40)

    def test_descending_order(self):
        stamps = [entry["timestamp"] for entry in
                  view()["recent_activity"]]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_no_secrets_in_activity(self):
        blob = str(view()["recent_activity"]).lower()
        for secret in ("cookie", "authorization:", "bearer",
                       "password"):
            self.assertNotIn(secret, blob)

    def test_no_urls_in_activity(self):
        blob = str(view()["recent_activity"])
        self.assertNotIn("https://", blob)


class TestDashboardEmpty(unittest.TestCase):
    def test_empty(self):
        from backend.routers import aec
        view = aec.build_dashboard_view(empty=True)
        self.assertEqual(view["candidates"], 0)
        self.assertEqual(view["active_cases"], 0)
        self.assertEqual(view["research_jobs"], 0)
        self.assertEqual(view["waiting_evidence"], 0)
        self.assertEqual(view["observations"], 0)
        self.assertEqual(view["review_pending"], 0)
        self.assertEqual(view["recent_activity"], [])


class TestDashboardStability(unittest.TestCase):
    def test_deterministic(self):
        from backend.routers import aec
        self.assertEqual(aec.build_dashboard_view(),
                         aec.build_dashboard_view())

    def test_no_side_effects(self):
        from backend.routers import aec
        before = aec._execution_run()
        aec.build_dashboard_view()
        aec.build_dashboard_view()
        after = aec._execution_run()
        self.assertEqual(before, after)

    def test_handler_get_only(self):
        from backend.routers import aec
        by_path = {r.path: r.methods for r in aec.router.routes
                   if hasattr(r, "methods")}
        self.assertEqual(by_path["/api/aec/dashboard"], {"GET"})

    def test_generated_at_monotonic(self):
        from backend.routers import aec
        first = aec.build_dashboard_view()["generated_at"]
        second = aec.build_dashboard_view()["generated_at"]
        self.assertGreaterEqual(second, first)


class TestCaseExplorerInternals(unittest.TestCase):
    def test_explorer_dedupes_fixture(self):
        from backend.routers import aec
        view = aec.get_cases()
        ids = [row["case_id"] for row in view["cases"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_next_action_derived_from_state(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            if row["evidence_state"] == "WAITING_EVIDENCE":
                self.assertIn("evidence", row["next_action"].lower())
            elif row["research_state"] == "WAITING_AUTHORIZATION":
                self.assertIn("auth", row["next_action"].lower())

    def test_last_activity_from_transitions(self):
        from backend.routers import aec
        run = aec._execution_run()
        jobs = {job["job_id"]: job for job in run.get("jobs", [])}
        for row in aec.get_cases()["cases"]:
            job = jobs.get("job-" + row["case_id"][5:])
            if job:
                self.assertTrue(row["last_activity"])


if __name__ == "__main__":
    unittest.main()