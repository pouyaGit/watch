"""SOC router production mounting — api.py integration regression.

The AI SOC UI (SOC-1..SOC-5) was promoted with ``backend/routers/soc.py``
complete but *inert*: ``api.py`` never registered it, so the eight GET-only
``/ui/soc/*`` routes were unreachable through the production entrypoint.
This module pins the missing integration without redesigning anything:

  1. ``api.py`` imports the router in the existing style and includes it once
  2. the SOC UI route (``/ui/soc/``) is reachable on the mounted app
  3. the rest of the SOC surface — including the parameterised routes and the
     AEC-style sibling pages — is reachable too
  4. the API key is required: no key is rejected (401) before routing
  5. a valid ``X-API-Key``/``?api_key=`` succeeds (200)
  6. missing / invalid keys are rejected on every SOC route
  7. pre-existing routes still work, unchanged (auth + status), and
     ``/static`` + the docs exemptions are untouched
  8. no security boundary moved: the single ``APIKeyMiddleware`` is still the
     only middleware, ``EXEMPT_PATHS`` is unchanged, no AEC route is mounted,
     no mutation endpoint was added, SOC stays GET-only

The API key is patched on the imported module (the middleware reads the
module global at request time) so the suite is deterministic regardless of
the ambient ``API_KEY`` environment. The literal is fragmented so the repo
carries no secret-shaped test fixture.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_PY = ROOT / "api.py"
SOC_ROUTER = ROOT / "backend" / "routers" / "soc.py"

KEY = "soc-" + "mount-regression-" + "key-1a2b3c4d"
BAD_KEY = "soc-" + "mount-regression-" + "key-9z8y7x6w"

#: The SOC surface as promoted (SOC-1..SOC-5): GET-only UI pages.
SOC_ROUTES: list[tuple[str, tuple[str, ...]]] = sorted([
    ("/ui/soc/", ("GET",)),
    ("/ui/soc/agents", ("GET",)),
    ("/ui/soc/agents/{slug}", ("GET",)),
    ("/ui/soc/cases", ("GET",)),
    ("/ui/soc/cases/{case_id}", ("GET",)),
    ("/ui/soc/activity", ("GET",)),
    ("/ui/soc/handoff", ("GET",)),
    ("/ui/soc/handoff/{job_id}", ("GET",)),
])

#: Pre-existing routes that must survive the SOC mount byte-for-byte
#: (path + exact method set), sampled across every router api.py already
#: included — read-only API routes, HTML UI routes and the pre-existing
#: POST endpoints (which must stay exactly as they were: this change adds
#: no mutation surface).
PINNED_EXISTING: dict[str, tuple[str, ...]] = {
    "/": ("GET",),
    "/api/system/stats": ("GET",),
    "/api/tasks": ("GET",),
    "/api/tasks/{task_id}/run": ("POST",),
    "/api/research": ("GET",),
    "/api/research/cases": ("GET",),
    "/api/research/cases/{case_id}/evidence": ("POST",),
    "/api/command/overview": ("GET",),
    "/api/kb": ("GET",),
    "/api/runs/recent": ("GET",),
    "/ui/tasks": ("GET",),
    "/ui/research": ("GET",),
    "/ui/command": ("GET",),
    "/ui/kb": ("GET",),
}

#: Auth exemptions as promoted — must not grow (that would be a bypass).
EXEMPT_PATHS = {"/docs", "/redoc", "/openapi.json"}

#: app.<attribute> calls api.py is allowed to make on its FastAPI instance.
ALLOWED_APP_CALLS = {"add_middleware", "mount", "include_router"}


def routes_of(app) -> dict[str, tuple[str, ...]]:
    """path -> sorted method tuple for every route mounted on ``app``.

    Walks the route tree (FastAPI 0.141 nests included routers) instead of
    the OpenAPI schema, so ``include_in_schema=False`` routes are covered.
    """

    found: dict[str, tuple[str, ...]] = {}

    def _walk(entries):
        for entry in entries:
            path = getattr(entry, "path", None)
            methods = getattr(entry, "methods", None)
            if path is not None and methods:
                found[path] = tuple(sorted(methods))
            for attr in ("routes", "original_router"):
                sub = getattr(entry, attr, None)
                if sub is None:
                    continue
                sub_routes = getattr(sub, "routes", None)
                if sub_routes:
                    _walk(sub_routes)

    _walk(app.routes)
    return found


def mounts_of(app) -> dict[str, str]:
    """mount path -> directory, for StaticFiles mounts on ``app``."""
    out: dict[str, str] = {}
    for entry in app.routes:
        if type(entry).__name__ != "Mount":
            continue
        app_obj = getattr(entry, "app", None)
        directory = getattr(app_obj, "directory", None)
        out[getattr(entry, "path", "<mount>")] = (
            str(directory) if directory is not None else ""
        )
    return out


def api_module():
    import api

    return api


class _SocTestBase(unittest.TestCase):
    """Imports the production app once and pins the API key for the class."""

    client = None
    saved_key = None
    api = None

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        cls.api = api_module()
        cls.saved_key = cls.api.API_KEY
        cls.api.API_KEY = KEY
        cls.client = TestClient(cls.api.app)

    @classmethod
    def tearDownClass(cls):
        cls.api.API_KEY = cls.saved_key


# --------------------------------------------------------------------------
# 1. api.py mount contract (source level)
# --------------------------------------------------------------------------
class TestApiPyMountContract(unittest.TestCase):
    def _tree(self) -> ast.Module:
        api_py = API_PY.read_text()
        self.assertIn("soc", api_py, "api.py does not mention the SOC router")
        return ast.parse(api_py)

    def test_api_py_imports_soc_as_soc_router(self):
        imported = set()
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.ImportFrom) and node.module == "backend.routers":
                for alias in node.names:
                    imported.add((alias.name, alias.asname))
        self.assertIn(
            ("soc", "soc_router"), imported,
            "api.py must import the router as 'soc_router' "
            "(existing style: backend.routers.X as Y_router)")

    def test_api_py_includes_soc_router_exactly_once(self):
        calls = []
        for node in ast.walk(self._tree()):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute)
                    and func.attr == "include_router"):
                continue
            args = node.args
            arg = args[0] if args else None
            if isinstance(arg, ast.Attribute) and arg.attr == "router":
                value = arg.value
                if isinstance(value, ast.Name):
                    calls.append(value.id)
        self.assertEqual(
            calls.count("soc_router"), 1,
            f"SOC router must be included exactly once, saw {calls}")

    def test_api_py_only_uses_existing_app_operations(self):
        used = set()
        for node in ast.walk(self._tree()):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "app":
                    used.add(func.attr)
        self.assertEqual(
            used - ALLOWED_APP_CALLS, set(),
            "api.py gained a new app operation "
            f"(no route decorators, no new mounts): {sorted(used)}")

    def test_api_key_comes_from_config_and_middleware_is_unchanged(self):
        source = API_PY.read_text()
        self.assertIn('API_KEY = config().get("API_KEY", "")', source)
        for forbidden in ("@app.post", "@app.put", "@app.patch", "@app.delete"):
            self.assertNotIn(forbidden, source)

    def test_only_one_auth_middleware_is_registered(self):
        api = api_module()
        names = [entry.cls.__name__ for entry in api.app.user_middleware]
        self.assertEqual(names, ["APIKeyMiddleware"])
        self.assertEqual(api.EXEMPT_PATHS, EXEMPT_PATHS)


# --------------------------------------------------------------------------
# 2. mounted route surface
# --------------------------------------------------------------------------
class TestMountedRouteSurface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = api_module()
        cls.routes = routes_of(cls.api.app)

    def test_soc_routes_are_mounted_get_only(self):
        for path, methods in SOC_ROUTES:
            self.assertIn(path, self.routes, f"SOC route not mounted: {path}")
            self.assertEqual(
                self.routes[path], methods,
                f"{path} must stay GET-only, got {self.routes[path]}")

    def test_no_soc_route_accepts_a_mutating_method(self):
        soc_paths = {
            path for path in self.routes if path.rstrip("/") == "/ui/soc"
            or path.startswith("/ui/soc/")
        }
        self.assertTrue(soc_paths, "no /ui/soc/ route on the mounted app")
        for path in sorted(soc_paths):
            self.assertEqual(
                self.routes[path], ("GET",), f"{path} is not GET-only")

    def test_no_api_soc_surface_was_invented(self):
        # SOC-1..SOC-5 shipped 8 UI routes and no JSON API. Mounting must
        # not invent an /api/soc surface.
        self.assertEqual(
            [p for p in self.routes if p.startswith("/api/soc")], [])

    def test_pinned_existing_routes_are_unchanged(self):
        for path, methods in sorted(PINNED_EXISTING.items()):
            self.assertIn(path, self.routes, f"existing route lost: {path}")
            self.assertEqual(
                self.routes[path], methods,
                f"{path} changed methods: {self.routes[path]} != {methods}")

    def test_soc_routes_do_not_shadow_existing_paths(self):
        overlap = set(PINNED_EXISTING) & {path for path, _ in SOC_ROUTES}
        self.assertEqual(overlap, set())

    def test_no_aec_route_is_mounted(self):
        # AEC stays inert exactly as it was before this change.
        aec = [p for p in self.routes
               if p.startswith("/api/aec") or p.startswith("/ui/aec")]
        self.assertEqual(aec, [])

    def test_static_and_log_mounts_are_unchanged(self):
        mounts = mounts_of(self.api.app)
        self.assertIn("/static", mounts)
        self.assertTrue(
            mounts["/static"].endswith("/web/static"),
            f"/static target changed: {mounts['/static']}")
        self.assertIn("/logs/tasks", mounts)


# --------------------------------------------------------------------------
# 3. API key enforcement on the mounted SOC routes
# --------------------------------------------------------------------------
class TestSocRoutesBehindApiKey(_SocTestBase):
    def test_soc_ui_route_is_reachable_with_header_key(self):
        response = self.client.get("/ui/soc/", headers={"X-API-Key": KEY})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertGreater(len(response.text), 200)

    def test_soc_ui_route_is_reachable_with_query_key(self):
        response = self.client.get("/ui/soc/", params={"api_key": KEY})
        self.assertEqual(response.status_code, 200)

    def test_soc_ui_route_requires_api_key(self):
        response = self.client.get("/ui/soc/")
        self.assertEqual(response.status_code, 401)

    def test_soc_ui_route_rejects_invalid_api_key(self):
        for attempt in (
            self.client.get("/ui/soc/", headers={"X-API-Key": BAD_KEY}),
            self.client.get("/ui/soc/", params={"api_key": BAD_KEY}),
        ):
            self.assertEqual(attempt.status_code, 401)

    def test_every_soc_route_is_gated(self):
        for path, _ in SOC_ROUTES:
            probe = path.replace("{slug}", "probe").replace(
                "{case_id}", "probe").replace("{job_id}", "probe")
            unauth = self.client.get(probe)
            self.assertEqual(
                unauth.status_code, 401, f"{probe} reachable without a key")
            self.assertNotEqual(
                self.client.get(probe, headers={"X-API-Key": BAD_KEY}).status_code,
                200, f"{probe} accepted an invalid key")

    def test_soc_listing_pages_render_when_authorised(self):
        for path in ("/ui/soc/", "/ui/soc/agents", "/ui/soc/cases",
                     "/ui/soc/activity", "/ui/soc/handoff"):
            response = self.client.get(path, params={"api_key": KEY})
            self.assertEqual(response.status_code, 200, path)
            self.assertGreater(len(response.text), 200, path)

    def test_soc_detail_routes_are_reachable(self):
        from backend.soc import agents as soc_agents
        from backend.soc import cases as soc_cases
        from backend.soc import handoff as soc_handoff

        def _first(payload: dict, key: str, field: str):
            items = payload.get(key) or []
            return (items[0] or {}).get(field) if items else None

        slug = _first(soc_agents.agents_index(), "agents", "slug")
        case_id = _first(soc_cases.cases_index(), "cases", "case_id")
        job_id = _first(soc_handoff.handoff_index(), "reports", "job_id")

        for prefix, real in (("/ui/soc/agents/", slug),
                             ("/ui/soc/cases/", case_id),
                             ("/ui/soc/handoff/", job_id)):
            if real:
                ok = self.client.get(prefix + str(real),
                                     params={"api_key": KEY})
                self.assertEqual(ok.status_code, 200, f"{prefix}{real}")
            else:
                # No live record: the route must still be mounted — an
                # unknown id is a 404 from the handler, never a 401/405.
                missing = self.client.get(prefix + "no-such-record",
                                          params={"api_key": KEY})
                self.assertEqual(missing.status_code, 404, prefix)

    def test_api_key_propagates_through_soc_navigation(self):
        html = self.client.get("/ui/soc/", params={"api_key": KEY}).text
        self.assertIn(f"api_key={KEY}", html)

    def test_unknown_path_is_still_gated_before_routing(self):
        # The middleware runs ahead of routing, so the gate covers every
        # newly mounted route as well as unknown paths.
        self.assertEqual(self.client.get("/ui/soc/definitely-not-a-route").status_code, 401)


# --------------------------------------------------------------------------
# 4. pre-existing surface still functional (no AEC/security boundary move)
# --------------------------------------------------------------------------
class TestExistingSurfaceUnaffected(_SocTestBase):
    def test_existing_routes_work_with_a_valid_key(self):
        for path in ("/", "/ui/tasks", "/api/system/stats", "/api/tasks",
                     "/ui/command"):
            response = self.client.get(path, params={"api_key": KEY})
            self.assertEqual(response.status_code, 200, path)

    def test_existing_routes_still_reject_anonymous_access(self):
        for path in ("/", "/ui/tasks", "/api/system/stats", "/api/tasks",
                     "/ui/command", "/api/research"):
            self.assertEqual(self.client.get(path).status_code, 401, path)

    def test_static_assets_stay_unauthenticated(self):
        served = self.client.get("/static/css/custom.css")
        self.assertEqual(served.status_code, 200)
        missing = self.client.get("/static/css/soc-mount-probe-missing.css")
        # 404 (not 401) proves /static is still mounted outside the gate.
        self.assertEqual(missing.status_code, 404)

    def test_docs_exemptions_are_unchanged(self):
        for path in ("/docs", "/openapi.json", "/redoc"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        # The exemption set itself must not grow (that would be a bypass).
        self.assertEqual(api_module().EXEMPT_PATHS, EXEMPT_PATHS)


class TestSocAdapterBoundariesUntouched(unittest.TestCase):
    """This task mounts a router; it must not touch SOC adapters or AEC."""

    def test_soc_router_has_no_mutating_decorators(self):
        source = SOC_ROUTER.read_text()
        for decorator in ("@router.post", "@router.put", "@router.patch",
                          "@router.delete", "@router.options", "@router.head"):
            self.assertNotIn(decorator, source)

    def test_soc_package_modules_are_the_promoted_set(self):
        pkg = ROOT / "backend" / "soc"
        names = sorted(p.name for p in pkg.glob("*.py"))
        self.assertEqual(names, [
            "__init__.py", "_util.py", "activity.py", "agents.py",
            "cases.py", "handoff.py", "overview.py",
        ])

    def test_aec_router_is_not_imported_by_api_py(self):
        imported = set()
        for node in ast.walk(ast.parse(API_PY.read_text())):
            if isinstance(node, ast.ImportFrom) and node.module == "backend.routers":
                imported.update(alias.name for alias in node.names)
        self.assertNotIn("aec", imported)


if __name__ == "__main__":
    unittest.main()
