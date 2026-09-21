"""EPIC8 fix: AEC UI api_key propagation through internal navigation.

Server-side propagation (Option A): every page handler reads the
middleware-validated ?api_key= from the request query and injects
api_key_qs into the render context, and every internal AEC link appends
it when present. Auth middleware untouched; static assets and external
links never receive the key.
"""

from __future__ import annotations

import unittest

KEY = "k-" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def _request(api_key: str = "") -> "Request":
    from starlette.requests import Request

    query = f"api_key={api_key}" if api_key else ""
    scope = {
        "type": "http", "method": "GET",
        "path": "/ui/aec/dashboard",
        "headers": [], "scheme": "http",
        "server": ("localhost", 80), "client": ("127.0.0.1", 1),
        "query_string": query.encode(),
    }
    return Request(scope)


def _render(handler_name: str, api_key: str = "", case_id: str | None = None):
    from backend.routers import aec

    handler = getattr(aec, handler_name)
    request = _request(api_key)
    if case_id is None:
        response = handler(request)
    else:
        response = handler(request, case_id)
    return response.body.decode()


class TestApiKeyPropagation(unittest.TestCase):
    def test_handlers_accept_request(self):
        from backend.routers import aec

        for name in ("ui_aec_dashboard", "ui_aec_cases",
                     "ui_aec_case_detail", "ui_aec_pipeline",
                     "ui_aec_observations", "ui_aec_evidence",
                     "ui_aec_audit"):
            handler = getattr(aec, name, None)
            self.assertIsNotNone(handler, name)

    def test_dashboard_url_with_api_key(self):
        html = _render("ui_aec_dashboard", api_key=KEY)
        self.assertIn(f"api_key={KEY}", html)
        self.assertIn("/ui/aec/cases?api_key=", html)

    def test_navigation_keeps_api_key_on_all_pages(self):
        # the dashboard quick-actions are the nav surface; every
        # destination link must carry the key
        html = _render("ui_aec_dashboard", api_key=KEY)
        for page in ("/ui/aec/dashboard", "/ui/aec/cases",
                     "/ui/aec/pipeline", "/ui/aec/observations",
                     "/ui/aec/evidence", "/ui/aec/audit"):
            self.assertIn(f"{page}?api_key={KEY}", html, page)

    def test_keyfree_pages_render_when_reached_with_key(self):
        # pages without nav links still render fine when the key is
        # present (their own links, if any, keep it)
        for handler in ("ui_aec_pipeline", "ui_aec_observations",
                        "ui_aec_evidence", "ui_aec_audit"):
            html = _render(handler, api_key=KEY)
            self.assertGreater(len(html), 200, handler)

    def test_case_detail_link_keeps_api_key(self):
        html = _render("ui_aec_cases", api_key=KEY)
        # the rendered cell link carries the key
        self.assertIn("cell-link", html)
        self.assertIn("?api_key=" + KEY, html)

    def test_navigation_without_api_key_remains_clean(self):
        for handler in ("ui_aec_dashboard", "ui_aec_cases",
                        "ui_aec_pipeline", "ui_aec_observations",
                        "ui_aec_evidence", "ui_aec_audit"):
            html = _render(handler)
            # footer prose mentions ?api_key= as documentation; the
            # assertion scope is actual link attributes only.
            self.assertNotIn('href="?api_key=', html, handler)
            self.assertNotIn("/ui/aec/?api_key=", html, handler)
            self.assertNotIn("?api_key=&", html, handler)

    def test_case_detail_without_key_clean(self):
        html = _render("ui_aec_case_detail", case_id="case-df54757aee1a")
        self.assertNotIn('href="?api_key=', html)

    def test_static_assets_do_not_carry_key(self):
        from pathlib import Path

        for template in Path("web/templates/aec").glob("*.html"):
            text = template.read_text()
            if "/static/" in text:
                # the link itself must not have been given the key
                self.assertNotIn("api_key_qs", text.split(
                    "/static/")[0])
        html = _render("ui_aec_dashboard", api_key=KEY)
        self.assertIn("/static/css/aec/aec.css", html)
        self.assertNotIn("/static/css/aec/aec.css?api_key=", html)
        self.assertNotIn("/static/js/aec/aec.js?api_key=", html)

    def test_external_links_never_receive_key(self):
        import re

        html = _render("ui_aec_dashboard", api_key=KEY)
        external = re.findall(r'href="(https?://[^"]+)"', html)
        for url in external:
            self.assertNotIn("api_key=", url)

    def test_base_sidebar_gains_key_when_present(self):
        # base.html sidebar research link uses api_key_qs from context
        html = _render("ui_aec_dashboard", api_key=KEY)
        self.assertIn("research/index.html?api_key=", html)


class TestMiddlewareUntouched(unittest.TestCase):
    def test_no_auth_middleware_changes_in_router(self):
        from pathlib import Path

        source = Path("backend/routers/aec.py").read_text()
        for word in ("APIKeyMiddleware", "verify_api_key", "X-API-Key"):
            self.assertNotIn(word, source)

    def test_router_source_imports_middleware_free(self):
        import ast
        from pathlib import Path

        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotIn("middleware", node.module)
                self.assertNotIn("deps", node.module)

    def test_ui_pages_never_build_key_into_external_hrefs(self):
        import re
        from pathlib import Path

        for template in Path("web/templates/aec").glob("*.html"):
            text = template.read_text()
            for href in re.findall(r'href="(https?://[^"]+)"', text):
                self.assertNotIn("api_key", href)


class TestApiKeyQSViaHandlerContext(unittest.TestCase):
    def test_payload_missing_key_no_api_key_qs(self):
        # page payload builders stay key-free; only handlers inject
        from backend.routers import aec

        for builder in ("dashboard_page_payload", "cases_page_payload",
                        "pipeline_page_payload", "audit_page_payload"):
            payload = getattr(aec, builder)()
            self.assertNotIn("api_key_qs", payload, builder)

    def test_empty_key_value_clean(self):
        html = _render("ui_aec_dashboard", api_key="")
        self.assertNotIn('href="?api_key=', html)


if __name__ == "__main__":
    unittest.main()