"""EPIC7 Part 18: additive Command Center API — runtime GET endpoints."""

from __future__ import annotations

import unittest

EXPECTED_NEW_ROUTES = (
    ("/api/aec/runtime", "GET"),
    ("/api/aec/runtime/requests", "GET"),
    ("/api/aec/runtime/audit", "GET"),
    ("/api/aec/runtime/limits", "GET"),
    ("/api/aec/runtime/health", "GET"),
)


class TestNewRoutesExist(unittest.TestCase):
    def test_five_new_routes(self):
        from backend.routers import aec

        paths = {
            (r.path, next(iter(r.methods)))
            for r in aec.router.routes
            if hasattr(r, "methods") and r.path.startswith(
                "/api/aec/runtime")
        }
        for route, method in EXPECTED_NEW_ROUTES:
            self.assertIn((route, method), paths)

    def test_new_routes_are_get_only(self):
        from backend.routers import aec

        for r in aec.router.routes:
            if hasattr(r, "methods") and r.path.startswith(
                    "/api/aec/runtime"):
                self.assertEqual(r.methods, {"GET"})

    def test_existing_routes_untouched(self):
        from backend.routers import aec

        paths = [
            r.path for r in aec.router.routes if hasattr(r, "methods")
        ]
        for existing in ("/api/aec/cases", "/api/aec/queue",
                         "/api/aec/status", "/api/aec/candidates",
                         "/api/aec/research-status",
                         "/api/aec/research-runs",
                         "/api/aec/research-queue",
                         "/api/aec/review",
                         "/api/aec/research-summary",
                         "/api/aec/execution-runs",
                         "/api/aec/research-jobs",
                         "/api/aec/specialists",
                         "/api/aec/evidence",
                         "/api/aec/execution-summary"):
            self.assertIn(existing, paths)

    def test_exactly_nineteen_get_routes(self):
        from backend.routers import aec

        routes = [
            r.path for r in aec.router.routes
            if hasattr(r, "methods") and "GET" in r.methods
        ]
        self.assertEqual(len(routes), 19)


class TestRuntimeOverviewView(unittest.TestCase):
    def test_overview_operational_state(self):
        from backend.routers import aec

        view = aec.build_runtime_view()
        self.assertIn("mode", view)
        self.assertIn("state", view)

    def test_overview_no_secrets(self):
        from backend.routers import aec

        joined = str(aec.build_runtime_view())
        for secret in ("Bearer ", "password=", "cookie="):
            self.assertNotIn(secret, joined)


class TestRuntimeRequestsView(unittest.TestCase):
    def test_requests_view_shape(self):
        from backend.routers import aec

        view = aec.build_runtime_requests_view()
        self.assertIn("total", view)
        self.assertIn("requests", view)

    def test_requests_never_expose_urls(self):
        from backend.routers import aec

        joined = str(aec.build_runtime_requests_view())
        self.assertNotIn("https://", joined)


class TestRuntimeAuditView(unittest.TestCase):
    def test_audit_view_shape(self):
        from backend.routers import aec

        view = aec.build_runtime_audit_view()
        self.assertIn("verified", view)
        self.assertIn("entries", view)

    def test_audit_view_no_secrets(self):
        from backend.routers import aec

        joined = str(aec.build_runtime_audit_view())
        for secret in ("Bearer ", "password="):
            self.assertNotIn(secret, joined)


class TestRuntimeLimitsView(unittest.TestCase):
    def test_limits_view(self):
        from backend.routers import aec

        view = aec.build_runtime_limits_view()
        self.assertIn("request_timeout_seconds", view)
        self.assertIn("max_response_bytes", view)
        self.assertIn("max_redirects", view)
        self.assertIn("max_concurrent_observations", view)
        self.assertIn("max_observations_per_host", view)
        self.assertIn("max_total_runtime_seconds", view)
        self.assertIn("retry_limit", view)

    def test_limits_positive(self):
        from backend.routers import aec

        view = aec.build_runtime_limits_view()
        for value in view.values():
            self.assertGreater(value, 0)


class TestRuntimeHealthView(unittest.TestCase):
    def test_health_view(self):
        from backend.routers import aec

        view = aec.build_runtime_health_view()
        self.assertIn("status", view)
        self.assertEqual(view["status"], "ready")

    def test_health_mentions_gating(self):
        from backend.routers import aec

        joined = str(aec.build_runtime_health_view())
        self.assertIn("authorization", joined.lower())


class TestRouterDeterminism(unittest.TestCase):
    def test_handlers_deterministic(self):
        import copy
        from backend.routers import aec

        first = aec.build_runtime_view()
        second = aec.build_runtime_view()
        self.assertEqual(first, second)

    def test_builders_do_not_mutate_inputs(self):
        import copy

        from backend.routers import aec

        sample = {"runs": [{"request_id": "x"}]}
        snapshot = copy.deepcopy(sample)
        aec.build_runtime_requests_view()
        self.assertEqual(sample, snapshot)

    def test_routes_are_additive_no_writes(self):
        import ast
        from pathlib import Path

        path = Path("backend/routers/aec.py")
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(
                            child.func, ast.Attribute) and \
                            child.func.attr in ("write_text", "open",
                                                "mkdir"):
                        self.fail(f"write call in {node.name}")


if __name__ == "__main__":
    unittest.main()