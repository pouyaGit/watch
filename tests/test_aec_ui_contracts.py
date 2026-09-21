"""EPIC8 Part 8+10: read-only Command Center API contract tests."""

from __future__ import annotations

import unittest

EXPECTED_DASHBOARD_KEYS = (
    "candidates", "active_cases", "research_jobs", "waiting_evidence",
    "observations", "review_pending", "recent_activity", "generated_at",
)

OBSERVATION_STATES = frozenset({
    "RECEIVED", "VALIDATING", "AUTHORIZED", "DISPATCHED", "OBSERVING",
    "COLLECTING", "COMPLETED", "REFUSED", "BLOCKED", "TIMED_OUT", "FAILED",
})


def dashboard():
    from backend.routers import aec
    return aec.build_dashboard_view()


class TestDashboardContract(unittest.TestCase):
    def test_top_level_keys(self):
        view = dashboard()
        self.assertEqual(sorted(view), sorted(list(EXPECTED_DASHBOARD_KEYS)))

    def test_counts_are_ints(self):
        for key in ("candidates", "active_cases", "research_jobs",
                    "waiting_evidence", "observations", "review_pending"):
            value = dashboard()[key]
            self.assertIsInstance(value, int, key)
            self.assertGreaterEqual(value, 0, key)

    def test_recent_activity_is_list(self):
        self.assertIsInstance(dashboard()["recent_activity"], list)

    def test_recent_activity_deterministic(self):
        first = dashboard()
        second = dashboard()
        self.assertEqual(first["recent_activity"],
                         second["recent_activity"])

    def test_generated_at_bumped_epoch(self):
        view = dashboard()
        self.assertGreaterEqual(view["generated_at"], 0)


class TestCaseListContract(unittest.TestCase):
    def test_cases_view_shape(self):
        from backend.routers import aec
        view = aec.get_cases()
        self.assertIn("cases", view)
        self.assertIn("total", view)
        self.assertEqual(view["total"], len(view["cases"]))

    def test_case_row_columns(self):
        from backend.routers import aec
        view = aec.get_cases()
        for row in view["cases"]:
            for column in ("case_id", "target", "category",
                           "research_state", "evidence_state",
                           "specialist", "last_activity",
                           "next_action"):
                self.assertIn(column, row, column)

    def test_empty_state(self):
        from backend.routers import aec
        view = aec.build_case_explorer_view([])
        self.assertEqual(view["cases"], [])
        self.assertEqual(view["total"], 0)


class TestCaseDetailContract(unittest.TestCase):
    def test_detail_sections(self):
        from backend.routers import aec
        detail = aec.build_case_detail_view("case-df54757aee1a")
        for section in ("case", "timeline", "research_history",
                        "evidence_artifacts", "authorization_status",
                        "observation_history", "audit_events"):
            self.assertIn(section, detail, section)

    def test_unknown_case_not_found(self):
        from backend.routers import aec
        detail = aec.build_case_detail_view("case-missing")
        self.assertIn("not_found", detail)
        self.assertTrue(detail["not_found"])

    def test_detail_has_no_raw_candidate_payload(self):
        from backend.routers import aec
        blob = str(aec.build_case_detail_view("case-df54757aee1a"))
        self.assertNotIn("authorization:", blob.lower().replace(" ", ""))


class TestPipelineContract(unittest.TestCase):
    def test_pipeline_stages_present(self):
        from backend.routers import aec
        view = aec.build_pipeline_view()
        stages = [stage["stage"] for stage in view["stages"]]
        self.assertEqual(
            stages,
            ["candidate", "case", "assignment", "research_job",
             "authorization", "observation", "evidence", "review"])

    def test_stage_current_state(self):
        from backend.routers import aec
        for stage in aec.build_pipeline_view()["stages"]:
            self.assertIn("state", stage)
            self.assertIn("blocks", stage)

    def test_blocked_reasons_are_lists(self):
        from backend.routers import aec
        for stage in aec.build_pipeline_view()["stages"]:
            self.assertIsInstance(stage["blocks"], list)


class TestObservationsContract(unittest.TestCase):
    def test_observation_fields(self):
        from backend.routers import aec
        view = aec.build_observations_view()
        self.assertIn("observations", view)
        self.assertIn("total", view)
        for row in view["observations"]:
            for field in ("request_id", "case_id", "target",
                          "observation_type", "state", "created_time",
                          "completed_time", "evidence_id"):
                self.assertIn(field, row, field)

    def test_observation_states_closed(self):
        from backend.routers import aec
        for row in aec.build_observations_view()["observations"]:
            self.assertIn(row["state"], OBSERVATION_STATES)

    def test_no_execution_controls(self):
        from backend.routers import aec
        blob = str(aec.build_observations_view())
        for control in ("execute", "run_observation", "approve",
                        "authorize"):
            self.assertNotIn(control + "(", blob)

    def test_empty_state(self):
        from backend.routers import aec
        view = aec.build_observations_view([])
        self.assertEqual(view["observations"], [])
        self.assertEqual(view["total"], 0)


class TestEvidenceContract(unittest.TestCase):
    def test_evidence_viewer_fields(self):
        from backend.routers import aec
        view = aec.build_evidence_viewer_view()
        self.assertIn("artifacts", view)
        for artifact in view["artifacts"]:
            for field in ("evidence_id", "case_id", "observation_type",
                          "authorization_reference", "scope_validation",
                          "provenance", "integrity", "redaction_status",
                          "quality_score"):
                self.assertIn(field, artifact, field)

    def test_no_secrets_in_evidence(self):
        from backend.routers import aec
        blob = str(aec.build_evidence_viewer_view()).lower()
        for secret in ("cookie", "authorization:", "set-cookie",
                       "password", "bearer"):
            self.assertNotIn(secret, blob)

    def test_empty_state(self):
        from backend.routers import aec
        view = aec.build_evidence_viewer_view([])
        self.assertEqual(view["artifacts"], [])


class TestAuditContract(unittest.TestCase):
    def test_audit_event_fields(self):
        from backend.routers import aec
        view = aec.build_audit_view()
        self.assertIn("events", view)
        for event in view["events"]:
            for field in ("timestamp", "actor", "action", "result"):
                self.assertIn(field, event, field)

    def test_audit_actions_closed(self):
        from backend.routers import aec
        allowed = {"case.created", "assignment.created",
                   "authorization.requested", "authorization.approved",
                   "observation.executed", "evidence.stored",
                   "review.requested"}
        for event in aec.build_audit_view()["events"]:
            self.assertIn(event["action"], allowed)

    def test_audit_deterministic(self):
        from backend.routers import aec
        first = aec.build_audit_view()
        second = aec.build_audit_view()
        self.assertEqual(first["events"], second["events"])

    def test_audit_no_secrets(self):
        from backend.routers import aec
        blob = str(aec.build_audit_view()).lower()
        for secret in ("cookie", "authorization:", "bearer"):
            self.assertNotIn(secret, blob)


class TestMutationAndDeterminism(unittest.TestCase):
    def test_get_only_no_writes(self):
        from backend.routers import aec
        for route in aec.router.routes:
            if hasattr(route, "methods"):
                self.assertEqual(route.methods, {"GET"})

    def test_handlers_do_not_import_execution(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertFalse(
                    node.module.startswith(
                        ("aec.runtime.execution", "aec.execution")),
                    node.module)

    def test_dashboard_deterministic_across_calls(self):
        first = dashboard()
        second = dashboard()
        self.assertEqual(first["candidates"], second["candidates"])
        self.assertEqual(first["recent_activity"],
                         second["recent_activity"])


if __name__ == "__main__":
    unittest.main()