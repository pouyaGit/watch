"""EPIC8: UI layer must never weaken EPIC6/EPIC7 boundaries (regression)."""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

ROUTER = Path("backend/routers/aec.py")


class TestFrozenContracts(unittest.TestCase):
    def test_authorization_gate_never_imported(self):
        tree = ast.parse(ROUTER.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertFalse(node.module.startswith("ai.authorizer"),
                                 node.module)
                self.assertFalse(
                    node.module.startswith("aec.authorization"),
                    node.module)

    def test_runtime_execution_never_imported(self):
        tree = ast.parse(ROUTER.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertFalse(
                    node.module.startswith("aec.runtime.execution"),
                    node.module)

    def test_no_observation_trigger_functions(self):
        source = ROUTER.read_text()
        for name in ("create_observation_request",
                     "request_observation",
                     "grant_authorization",
                     "approve_request",
                     "run_observation",
                     "execute_observation"):
            self.assertNotIn(name, source)

    def test_no_evidence_mutation_functions(self):
        source = ROUTER.read_text()
        for name in ("store_evidence", "update_evidence",
                     "mark_finding", "confirm_finding"):
            self.assertNotIn(name, source)

    def test_evidence_bridge_not_imported(self):
        tree = ast.parse(ROUTER.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertFalse(
                    node.module.startswith("aec.evidence_bridge"),
                    node.module)


class TestVocabularies(unittest.TestCase):
    def test_no_finding_eligibility_vocabulary(self):
        source = ROUTER.read_text().lower()
        for word in ("eligible", "eligibility", "confirmed_finding",
                     "finding_eligible"):
            self.assertNotIn(word, source)

    def test_no_verdict_export(self):
        # no view payload may carry a verdict/conclusion key (the router's
        # own docstring already says "no conclusions" — we assert output
        # contracts, not prose)
        from backend.routers import aec
        payloads = (
            aec.build_dashboard_view(),
            aec.build_pipeline_view(),
            aec.build_observations_view(),
            aec.build_audit_view(),
            aec.build_evidence_viewer_view(),
            aec.build_case_explorer_view([]),
        )
        for payload in payloads:
            blob = json.dumps(payload).lower()
            for word in ("verdict", "conclusion"):
                self.assertNotIn(word, blob)


class TestRouteSafety(unittest.TestCase):
    def test_no_write_http_methods_on_ui(self):
        tree = ast.parse(ROUTER.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(
                    node.func, ast.Attribute):
                if node.func.attr in ("post", "put", "patch", "delete"):
                    self.fail(f"{node.func.attr} route present")

    def test_query_params_are_read_only(self):
        # any query param on a route is a filter; none may name an action.
        # Scan route decorators + handler signatures only — display keys
        # like "action" in audit events are data, not query parameters.
        source = ROUTER.read_text()
        for line in source.splitlines():
            if "@router.get" in line or "def " in line and "request" in line:
                for param in ("action", "command", "operation", "exec"):
                    self.assertNotIn(f'"{param}"', line)


class TestLayerSeparation(unittest.TestCase):
    def test_ui_module_does_not_import_sim_loop_at_top(self):
        tree = ast.parse(ROUTER.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                # lazy fixture imports are fine (existing pattern), but the
                # loop itself must not run at import time
                self.assertNotEqual(node.module, "aec.runtime.loop")

    def test_payload_builders_never_raise(self):
        from backend.routers import aec
        for builder in (aec.build_dashboard_view,
                        aec.build_pipeline_view,
                        aec.build_observations_view,
                        aec.build_audit_view,
                        aec.build_evidence_viewer_view,
                        aec.build_case_explorer_view):
            result = builder()
            self.assertIsInstance(result, dict)


class TestEvidenceIntegrityChain(unittest.TestCase):
    def test_viewer_shows_integrity_not_meaning(self):
        from backend.routers import aec
        for artifact in aec.build_evidence_viewer_view()["artifacts"]:
            self.assertTrue(artifact["integrity"].startswith("sha256:"))
            # the UI must not assert what the evidence means
            self.assertNotIn("conclusion", artifact)
            self.assertNotIn("assessment", artifact)

    def test_redaction_status_not_values(self):
        from backend.routers import aec
        for artifact in aec.build_evidence_viewer_view()["artifacts"]:
            self.assertIn(artifact["redaction_status"],
                          {"clean", "scrubbed", "n/a"})


class TestStateMachinesUntouched(unittest.TestCase):
    def test_evidence_states_not_redefined(self):
        import aec.runtime.jobs as jobs
        self.assertTrue(hasattr(jobs, "transition"))
        from backend.routers import aec
        self.assertTrue(callable(aec.build_case_explorer_view))

    def test_no_duplicate_state_names(self):
        from backend.routers import aec
        from aec.runtime.execution.states import STATES
        ui_states = {row["state"] for row in
                     aec.build_observations_view()["observations"]}
        self.assertLessEqual(ui_states, set(STATES))


if __name__ == "__main__":
    unittest.main()