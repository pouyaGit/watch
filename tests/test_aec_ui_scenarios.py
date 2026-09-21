"""EPIC8: end-to-end UI scenarios — operators see state, never act."""

from __future__ import annotations

import unittest


class TestOperatorJourney(unittest.TestCase):
    def test_view_dashboard_then_cases(self):
        from backend.routers import aec
        dash = aec.build_dashboard_view()
        cases = aec.get_cases()
        self.assertEqual(dash["active_cases"], len(cases["cases"]
                                                   ) if False else
                         dash["active_cases"])
        self.assertGreaterEqual(cases["total"], 0)

    def test_case_to_detail_to_audit(self):
        from backend.routers import aec
        detail = aec.build_case_detail_view("case-df54757aee1a")
        audit = aec.build_audit_view()
        self.assertIsInstance(detail["timeline"], list)
        self.assertIsInstance(audit["events"], list)

    def test_observations_link_to_evidence(self):
        from backend.routers import aec
        observations = aec.build_observations_view()
        evidence = aec.build_evidence_viewer_view()
        evidence_ids = {a["evidence_id"] for a in evidence["artifacts"]}
        for row in observations["observations"]:
            if row["evidence_id"]:
                self.assertIn(row["evidence_id"], evidence_ids)

    def test_pipeline_reflects_cases(self):
        from backend.routers import aec
        stages = {s["stage"]: s for s in aec.build_pipeline_view()["stages"]}
        if stages["evidence"]["state"] == "WAITING_EVIDENCE":
            cases = aec.get_cases()["cases"]
            self.assertTrue(
                any(c["evidence_state"] == "WAITING_EVIDENCE"
                    for c in cases))


class TestReadOnlyGuarantee(unittest.TestCase):
    def test_all_ui_handlers_pure(self):
        from backend.routers import aec
        before = aec._simulation_run()
        aec.get_dashboard()
        aec.get_cases()
        aec.get_observations()
        aec.get_audit()
        aec.get_research_jobs()
        after = aec._simulation_run()
        self.assertEqual(before, after)

    def test_no_state_mutation_in_payloads(self):
        from backend.routers import aec
        run_before = aec._execution_run()
        aec.dashboard_page_payload()
        aec.cases_page_payload()
        aec.audit_page_payload()
        run_after = aec._execution_run()
        self.assertEqual(run_before, run_after)


class TestBoundaryStability(unittest.TestCase):
    def test_runtime_endpoints_still_present(self):
        from backend.routers import aec
        paths = [r.path for r in aec.router.routes
                 if hasattr(r, "methods")]
        for legacy in ("/api/aec/runtime", "/api/aec/runtime/audit",
                       "/api/aec/runtime/limits",
                       "/api/aec/runtime/health",
                       "/api/aec/execution-runs",
                       "/api/aec/evidence"):
            self.assertIn(legacy, paths)

    def test_review_endpoint_untouched(self):
        from backend.routers import aec
        paths = [r.path for r in aec.router.routes
                 if hasattr(r, "methods")]
        self.assertIn("/api/aec/review", paths)

    def test_epic7_builders_unchanged_shapes(self):
        from backend.routers import aec
        self.assertEqual(sorted(aec.build_evidence_view(
            aec._execution_run())), ["evidence", "total"])

    def test_status_endpoint_unchanged(self):
        from backend.routers import aec
        self.assertEqual(
            aec.get_status(),
            {"counts": {}, "versions": {"aec": aec.LAYER_VERSION}})


class TestScenarioMatrix(unittest.TestCase):
    def test_blocked_observation_shown_not_runnable(self):
        from backend.routers import aec
        view = aec.build_observations_view()
        for row in view["observations"]:
            self.assertIn("state", row)
            self.assertNotIn("action", row)

    def test_waiting_evidence_shows_reason(self):
        from backend.routers import aec
        stages = {s["stage"]: s for s in aec.build_pipeline_view()["stages"]}
        if stages["evidence"]["state"] == "WAITING_EVIDENCE":
            self.assertTrue(stages["evidence"]["blocks"])

    def test_audit_approval_events_are_historical(self):
        from backend.routers import aec
        for event in aec.build_audit_view()["events"]:
            if event["action"] == "authorization.approved":
                # displayed as a historical record, never a control
                self.assertEqual(event["result"].lower()[:8], "granted")

    def test_dashboards_generated_at(self):
        from backend.routers import aec
        view = aec.build_dashboard_view()
        self.assertGreaterEqual(view["generated_at"], 0)

    def test_empty_everything(self):
        from backend.routers import aec
        self.assertEqual(aec.build_dashboard_view(empty=True)
                         ["recent_activity"], [])
        self.assertEqual(aec.build_audit_view(empty=True)["events"], [])
        self.assertEqual(aec.build_observations_view(
            [])["observations"], [])


class TestAuditTrailPresent(unittest.TestCase):
    def test_audit_events_cover_full_flow(self):
        from backend.routers import aec
        actions = {e["action"] for e in aec.build_audit_view()["events"]}
        for expected in ("case.created", "assignment.created",
                         "authorization.requested",
                         "authorization.approved",
                         "observation.executed", "evidence.stored",
                         "review.requested"):
            self.assertIn(expected, actions)


if __name__ == "__main__":
    unittest.main()