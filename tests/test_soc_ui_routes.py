"""SOC UI — route surface and read-only contract (RED phase).

SOC-1..SOC-5: the SOC router exposes GET-only UI pages under /ui/soc/.
Every handler is a projection over existing read APIs:
  - backend.research_agents  (registry + service payloads)
  - backend.research_data    (knowledge base + research overview)
  - backend.investigation_engine (memory, evidence store, reports)
  - backend.routers.aec      (AEC view builders, reused read-only)
  - ai.knowledge.ai_activity_status (real runtime activity status)
No route mutates anything; no schema change; no AEC core modification.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOC_ROUTER = ROOT / "backend" / "routers" / "soc.py"
SOC_PKG = ROOT / "backend" / "soc"


def expected_routes() -> list[tuple[list[str], str]]:
    return sorted([
        (["GET"], "/ui/soc/"),
        (["GET"], "/ui/soc/agents"),
        (["GET"], "/ui/soc/agents/{slug}"),
        (["GET"], "/ui/soc/cases"),
        (["GET"], "/ui/soc/cases/{case_id}"),
        (["GET"], "/ui/soc/activity"),
        (["GET"], "/ui/soc/handoff"),
        (["GET"], "/ui/soc/handoff/{job_id}"),
    ])


class TestSocRoutes(unittest.TestCase):
    def test_router_module_exists(self):
        self.assertTrue(SOC_ROUTER.exists(), "backend/routers/soc.py missing")

    def test_router_exposes_soc_routes(self):
        from backend.routers import soc

        routes = [
            (sorted(r.methods), r.path)
            for r in soc.router.routes
            if hasattr(r, "methods")
        ]
        self.assertEqual(sorted(routes), expected_routes())

    def test_soc_package_exists(self):
        self.assertTrue(SOC_PKG.is_dir(), "backend/soc/ package missing")
        self.assertTrue((SOC_PKG / "__init__.py").exists())

    def test_no_mutation_decorators_in_router(self):
        source = SOC_ROUTER.read_text()
        for decorator in ("@router.post", "@router.put", "@router.patch",
                          "@router.delete", "@router.options",
                          "@router.head"):
            self.assertNotIn(decorator, source)


class TestSocReadOnlyContract(unittest.TestCase):
    """The SOC surface must be projections only: no writes, no network,
    no new storage, no AEC core mutation."""

    PY_SOURCES = [
        SOC_ROUTER,
        *sorted(SOC_PKG.glob("*.py")),
    ]

    def _modules_present(self):
        missing = [p for p in self.PY_SOURCES if not p.exists()]
        if missing:
            raise AssertionError(f"missing: {missing}")

    def test_adapters_import_no_network_or_writer_stacks(self):
        self._modules_present()
        for path in self.PY_SOURCES:
            tree = ast.parse(path.read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
            banned = imported & {"socket", "pymongo", "subprocess"}
            self.assertEqual(banned, set(), f"banned imports in {path.name}")

    def test_no_write_calls_in_adapters(self):
        self._modules_present()
        banned_calls = {
            "open", "write_text", "write_bytes", "mkdir", "unlink",
            "save_artifact", "save_plan", "save_report", "remember_report",
            "mark_false_positive", "create_task", "enqueue",
            "insert_one", "update_one", "delete_one",
        }
        for path in self.PY_SOURCES:
            tree = ast.parse(path.read_text())
            calls: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name):
                        calls.add(func.id)
                    elif isinstance(func, ast.Attribute):
                        calls.add(func.attr)
            hit = calls & banned_calls
            self.assertEqual(hit, set(), f"write calls in {path.name}: {hit}")

    def test_adapters_never_import_aec_fixture_writers(self):
        self._modules_present()
        # consume only aec's *public* view builders; private fixture
        # writers must never be reached (AST-level: attribute call on
        # the aec module whose name starts with '_').
        for path in self.PY_SOURCES:
            tree = ast.parse(path.read_text())
            private: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and \
                        isinstance(node.value, ast.Name) and \
                        node.value.id == "aec":
                    private.add(node.attr)
            hit = {a for a in private if a.startswith("_")}
            self.assertEqual(hit, set(), f"private aec access in {path.name}")

    def test_router_uses_shared_templates_and_api_key_qs(self):
        self.assertTrue(SOC_ROUTER.exists())
        source = SOC_ROUTER.read_text()
        self.assertIn("api_key_qs", source)
        # SOC pages stay behind the same global API-key middleware: the
        # router must NOT register its own auth bypass or middleware.
        self.assertNotIn("middleware", source.lower())

    def test_router_does_not_touch_auth_modules(self):
        self.assertTrue(SOC_ROUTER.exists())
        source = SOC_ROUTER.read_text()
        for token in ("APIKeyMiddleware", "verify_api_key(", "deps.API_KEY"):
            # verify_api_key import is fine; overriding the handler is not.
            self.assertNotIn(f"def {token}", source)


if __name__ == "__main__":
    unittest.main()