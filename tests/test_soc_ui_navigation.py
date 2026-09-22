"""SOC UI — page render + navigation regression (RED phase).

The side navigation gains a SOC group at the top and the legacy pages
move under a "Legacy / Engineering" group.  No existing item may be
removed; the base template keeps every pre-existing href.  SOC pages
render through the shared Jinja2Templates instance and propagate
api_key_qs exactly like the AEC pages (EPIC8 fix contract).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LEGACY_VARS = [
    "command_url", "programs_url",
    "domains_url", "http_url", "urls_url", "endpoints_url",
    "parameters_url", "runs_url", "dns_url", "changes_url",
    "research_url", "queue_url", "research_tasks_url", "leads_url",
    "plans_url", "agent_url", "xss_url", "kb_url", "reports_url",
]

SOC_HREFS = [
    "/ui/soc/", "/ui/soc/agents",
    "/ui/soc/cases", "/ui/soc/activity", "/ui/soc/handoff",
]


class TestSideNavigation(unittest.TestCase):
    def _base(self) -> str:
        return (ROOT / "web" / "templates" / "base.html").read_text()

    def test_legacy_nav_entries_are_not_rendered(self):
        text = self._base()
        # UX correction: the legacy pages keep their routes for backward
        # compatibility but their links must not be rendered in the sidebar
        for var in LEGACY_VARS:
            self.assertNotIn(f"{{{{ {var} }}}}", text,
                             f"legacy sidebar link still rendered: {var}")

    def test_soc_group_present(self):
        text = self._base()
        self.assertIn("SOC", text)
        for href in SOC_HREFS:
            self.assertIn(href, text, f"SOC link {href} missing")

    def test_legacy_engineering_label_absent(self):
        text = self._base()
        self.assertNotIn("Legacy / Engineering", text)
        self.assertNotIn("nav-legacy", text)
        # SOC-first sidebar: exactly the AI SOC group plus the system group
        groups = re.findall(r'<p class="nav-group">([^<]+)</p>', text)
        self.assertEqual(groups, ["AI SOC", "System"], groups)


class TestSocPageRender(unittest.TestCase):
    """Render each SOC page through its handler with a plain starlette
    Request scope (the router is inert-until-mounted, same as AEC)."""

    def _html(self, handler_name, **kw):
        import starlette.requests as sr
        from backend.routers import soc

        handler = getattr(soc, handler_name)
        scope = {
            "type": "http", "method": "GET",
            "path": "/ui/soc/", "headers": [],
            "scheme": "http", "server": ("localhost", 80),
            "client": ("127.0.0.1", 1), "query_string": b"",
            "path_params": {k: v for k, v in kw.items()},
        }
        req = sr.Request(scope)
        resp = handler(req, **kw) if kw else handler(req)
        body = resp.body.decode()
        self.assertGreater(len(body), 200)
        return body

    def test_overview_renders(self):
        html = self._html("ui_soc_overview")
        self.assertIn("AI Security Operations Center", html) \
            or self.assertIn("Security Operations", html)

    def test_agents_renders(self):
        self._html("ui_soc_agents")

    def test_agent_detail_renders(self):
        html = self._html("ui_soc_agent_detail", slug="xss-agent")
        self.assertIn("XSS", html)

    def test_cases_renders(self):
        self._html("ui_soc_cases")

    def test_case_detail_renders(self):
        self._html("ui_soc_case_detail", case_id="rc-1430e0f21394")

    def test_activity_renders(self):
        self._html("ui_soc_activity")

    def test_handoff_renders(self):
        self._html("ui_soc_handoff")


class TestApiKeyPropagation(unittest.TestCase):
    def _html(self, handler_name, api_key="", **kw):
        import starlette.requests as sr
        from backend.routers import soc

        handler = getattr(soc, handler_name)
        qs = f"api_key={api_key}" if api_key else ""
        scope = {
            "type": "http", "method": "GET",
            "path": "/ui/soc/", "headers": [],
            "scheme": "http", "server": ("localhost", 80),
            "client": ("127.0.0.1", 1), "query_string": qs.encode(),
            "path_params": {k: v for k, v in kw.items()},
        }
        req = sr.Request(scope)
        resp = handler(req, **kw) if kw else handler(req)
        return resp.body.decode()

    def test_internal_soc_links_carry_key(self):
        KEY = "k-soc-test-0123456789abcdef"
        html = self._html("ui_soc_overview", api_key=KEY)
        # internal SOC nav must keep the key
        self.assertIn(f"/ui/soc/agents?api_key={KEY}", html)
        self.assertIn(f"/ui/soc/cases?api_key={KEY}", html)

    def test_no_key_renders_clean_links(self):
        html = self._html("ui_soc_overview")
        self.assertNotIn('href="?api_key=', html)
        self.assertNotIn("?api_key=&", html)


if __name__ == "__main__":
    unittest.main()