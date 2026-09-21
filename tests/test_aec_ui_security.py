"""EPIC8 Part 10: permission boundaries, secret filtering, rendering."""

from __future__ import annotations

import unittest


class TestDisplayOnlyBoundary(unittest.TestCase):
    def test_no_execution_imports_in_ui_builders(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertFalse(
                    node.module.startswith("aec.runtime.execution"),
                    node.module)

    def test_no_authorizer_imports(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertFalse(
                    node.module.startswith("ai.authorizer"), node.module)

    def test_no_evidence_mutation_imports(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertFalse(node.module.endswith("evidence_bridge"),
                                 node.module)

    def test_no_approve_endpoint(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self.assertNotIn("approve", node.name.lower())
                self.assertNotIn("execute", node.name.lower())
                self.assertNotIn("mutate", node.name.lower())

    def test_keyword_vocabulary_clean(self):
        from backend.routers import aec
        blob = str(aec.build_dashboard_view()).lower()
        for word in ("confirmed", "vulnerable", "finding", "exploit"):
            self.assertNotIn(word, blob)


class TestSecretFiltering(unittest.TestCase):
    def test_dashboard_no_secrets(self):
        from backend.routers import aec
        blob = str(aec.build_dashboard_view()).lower()
        for secret in ("cookie", "authorization:", "set-cookie",
                       "password", "bearer", "token="):
            self.assertNotIn(secret, blob)

    def test_observations_no_secrets(self):
        from backend.routers import aec
        blob = str(aec.build_observations_view()).lower()
        for secret in ("cookie", "set-cookie", "authorization:",
                       "password", "bearer"):
            self.assertNotIn(secret, blob)

    def test_case_detail_no_secrets(self):
        from backend.routers import aec
        blob = str(aec.build_case_detail_view("case-df54757aee1a")).lower()
        for secret in ("cookie", "authorization:", "set-cookie",
                       "password", "bearer"):
            self.assertNotIn(secret, blob)

    def test_evidence_viewer_no_raw_bodies(self):
        from backend.routers import aec
        blob = str(aec.build_evidence_viewer_view()).lower()
        for marker in ("<html", "response_body", "raw_body"):
            self.assertNotIn(marker, blob)

    def test_audit_no_secrets(self):
        from backend.routers import aec
        blob = str(aec.build_audit_view()).lower()
        for secret in ("cookie", "authorization:", "bearer"):
            self.assertNotIn(secret, blob)

    def test_pipeline_no_secrets(self):
        from backend.routers import aec
        blob = str(aec.build_pipeline_view()).lower()
        for secret in ("cookie", "authorization:", "bearer"):
            self.assertNotIn(secret, blob)


class TestEvidenceRendering(unittest.TestCase):
    def test_viewer_fields_no_verdict(self):
        from backend.routers import aec
        view = aec.build_evidence_viewer_view()
        for artifact in view["artifacts"]:
            self.assertNotIn("severity", artifact)
            self.assertNotIn("confidence", artifact)

    def test_integrity_is_hex(self):
        from backend.routers import aec
        for artifact in aec.build_evidence_viewer_view()["artifacts"]:
            value = artifact["integrity"]
            self.assertTrue(value.startswith("sha256:"))
            int(value.split(":", 1)[1], 16)

    def test_redaction_status_closed(self):
        from backend.routers import aec
        allowed = {"clean", "scrubbed", "n/a"}
        for artifact in aec.build_evidence_viewer_view()["artifacts"]:
            self.assertIn(artifact["redaction_status"], allowed)

    def test_provenance_shape(self):
        from backend.routers import aec
        for artifact in aec.build_evidence_viewer_view()["artifacts"]:
            provenance = artifact["provenance"]
            self.assertIn("source", provenance)
            self.assertIn("source_mode", provenance)
            self.assertIn("tick", provenance)


class TestAuditRendering(unittest.TestCase):
    def test_event_order_by_timestamp(self):
        from backend.routers import aec
        events = aec.build_audit_view()["events"]
        timestamps = [event["timestamp"] for event in events]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_actors_present(self):
        from backend.routers import aec
        for event in aec.build_audit_view()["events"]:
            self.assertTrue(event["actor"])

    def test_results_present(self):
        from backend.routers import aec
        for event in aec.build_audit_view()["events"]:
            self.assertTrue(event["result"])


class TestEmptyStates(unittest.TestCase):
    def test_empty_dashboard(self):
        from backend.routers import aec
        view = aec.build_dashboard_view(empty=True)
        self.assertEqual(view["candidates"], 0)
        self.assertEqual(view["active_cases"], 0)
        self.assertEqual(view["research_jobs"], 0)
        self.assertEqual(view["recent_activity"], [])

    def test_empty_pipeline(self):
        from backend.routers import aec
        view = aec.build_pipeline_view(empty=True)
        for stage in view["stages"]:
            self.assertEqual(stage["state"], "")

    def test_empty_audit(self):
        from backend.routers import aec
        view = aec.build_audit_view(empty=True)
        self.assertEqual(view["events"], [])

    def test_empty_case_detail(self):
        from backend.routers import aec
        view = aec.build_case_detail_view("")
        self.assertTrue(view["not_found"])


class TestDeterministicOutput(unittest.TestCase):
    def test_all_builders_deterministic(self):
        from backend.routers import aec
        builders = (
            aec.build_dashboard_view, aec.build_pipeline_view,
            aec.build_observations_view, aec.build_evidence_viewer_view,
            aec.build_audit_view,
        )
        for builder in builders:
            first = builder()
            second = builder()
            self.assertEqual(first, second, builder.__name__)

    def test_case_list_deterministic(self):
        from backend.routers import aec
        self.assertEqual(aec.get_cases(), aec.get_cases())


class TestNoHiddenExecutionPaths(unittest.TestCase):
    def test_no_http_client_in_ui_module(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertFalse(
                    node.module.startswith(("http", "urllib", "socket")),
                    node.module)

    def test_no_subprocess(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotIn("subprocess", node.module)

    def test_no_observation_trigger(self):
        from backend.routers import aec
        names = [r.name for r in aec.router.routes
                 if hasattr(r, "methods")]
        for name in names:
            self.assertNotIn("trigger", name.lower())
            self.assertNotIn("start", name.lower())

    def test_no_authorization_grant(self):
        from backend.routers import aec
        names = [r.name for r in aec.router.routes
                 if hasattr(r, "methods")]
        for name in names:
            self.assertNotIn("grant", name.lower())
            self.assertNotIn("approve", name.lower())


if __name__ == "__main__":
    unittest.main()