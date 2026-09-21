"""EPIC8 Part 8+10: Command Center router surface — additive GET only."""

from __future__ import annotations

import unittest

NEW_ROUTES = {
    ("/api/aec/dashboard", "GET"),
    ("/api/aec/cases/{id}", "GET"),
    ("/api/aec/research/jobs", "GET"),
    ("/api/aec/observations", "GET"),
    ("/api/aec/audit", "GET"),
}


class TestNewRoutes(unittest.TestCase):
    def test_five_new_routes_registered(self):
        from backend.routers import aec
        actual = {
            (r.path, next(iter(r.methods)))
            for r in aec.router.routes if hasattr(r, "methods")
        }
        for route in NEW_ROUTES:
            self.assertIn(route, actual)

    def test_total_routes_now_thirty_one(self):
        from backend.routers import aec
        paths = [r.path for r in aec.router.routes
                 if hasattr(r, "methods")]
        self.assertEqual(len(paths), 31)

    def test_get_only_still(self):
        from backend.routers import aec
        for route in aec.router.routes:
            if hasattr(route, "methods"):
                self.assertEqual(route.methods, {"GET"})

    def test_no_mutation_decorators_in_source(self):
        from pathlib import Path
        source = Path("backend/routers/aec.py").read_text()
        for decorator in ("@router.post", "@router.put", "@router.patch",
                          "@router.delete", "@router.options",
                          "@router.head"):
            self.assertNotIn(decorator, source)

    def test_handlers_return_dict_shapes(self):
        from backend.routers import aec
        self.assertIsInstance(aec.get_dashboard(), dict)
        self.assertIsInstance(aec.get_observations(), dict)
        self.assertIsInstance(aec.get_audit(), dict)
        self.assertIsInstance(aec.get_research_jobs(), dict)

    def test_dashboard_handler_deterministic(self):
        from backend.routers import aec
        self.assertEqual(aec.get_dashboard(), aec.get_dashboard())


class TestNoSideEffects(unittest.TestCase):
    def test_builders_never_write_disk(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        name = ""
                        if isinstance(child.func, ast.Attribute):
                            name = child.func.attr
                        elif isinstance(child.func, ast.Name):
                            name = child.func.id
                        self.assertNotIn(
                            name, {"open", "write_text", "mkdir",
                                   "unlink", "remove", "connect"},
                            f"{node.name} calls {name}")

    def test_views_are_json_serializable(self):
        import json as json_lib
        from backend.routers import aec
        for view in (aec.get_dashboard(), aec.get_observations(),
                     aec.get_audit(), aec.get_research_jobs(),
                     aec.get_cases()):
            json_lib.dumps(view)

    def test_no_dynamic_imports(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = ""
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                self.assertNotIn(name, {"__import__", "import_module"})

    def test_router_has_no_secret_literals(self):
        from backend.routers import aec
        blob = str(aec.router.routes)
        for secret in ("Bearer ", "api_key=", "password="):
            self.assertNotIn(secret, blob)


class TestRouteIndexes(unittest.TestCase):
    def test_case_detail_subpath_does_not_shadow_list(self):
        from backend.routers import aec
        paths = [r.path for r in aec.router.routes
                 if hasattr(r, "methods")]
        self.assertIn("/api/aec/cases", paths)
        self.assertIn("/api/aec/cases/{id}", paths)

    def test_research_jobs_slash_alias(self):
        from backend.routers import aec
        paths = [r.path for r in aec.router.routes
                 if hasattr(r, "methods")]
        # both the legacy hyphen form and the slash form exist additively
        self.assertIn("/api/aec/research-jobs", paths)
        self.assertIn("/api/aec/research/jobs", paths)


if __name__ == "__main__":
    unittest.main()