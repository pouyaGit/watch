"""EPIC8 Part 1+9: Command Center UI pages — templates, styling, states."""

from __future__ import annotations

import unittest
from pathlib import Path

WEB = Path("web")

PAGES = (
    ("templates/aec/dashboard.html", "/ui/aec/dashboard"),
    ("templates/aec/cases.html", "/ui/aec/cases"),
    ("templates/aec/case_detail.html", "/ui/aec/cases/{id}"),
    ("templates/aec/pipeline.html", "/ui/aec/pipeline"),
    ("templates/aec/observations.html", "/ui/aec/observations"),
    ("templates/aec/evidence.html", "/ui/aec/evidence"),
    ("templates/aec/audit.html", "/ui/aec/audit"),
)

REQUIRED_STATES = ("empty", "loading", "error")


class TestTemplateFiles(unittest.TestCase):
    def test_all_pages_exist(self):
        for template, _route in PAGES:
            self.assertTrue(
                (WEB / template).exists(), f"missing {template}")

    def test_pages_extend_base(self):
        for template, _route in PAGES:
            text = (WEB / template).read_text()
            self.assertIn('{% extends "base.html" %}', text,
                          template)

    def test_no_heavy_frontend_dependencies(self):
        for template, _route in PAGES:
            text = (WEB / template).read_text()
            for framework in ("react", "vue", "svelte", "jquery",
                              "chart.js", "d3"):
                self.assertNotIn(framework, text.lower(), template)

    def test_templates_contain_no_secret_literals(self):
        for template, _route in PAGES:
            text = (WEB / template).read_text().lower()
            for secret in ("bearer ", "authorization:", "set-cookie",
                           "password="):
                self.assertNotIn(secret, text, template)
            # api_key= appears only as a query-param placeholder bound to
            # the api_key_qs variable (never a hardcoded secret value)
            if "api_key=" in text:
                self.assertIn("api_key={{ api_key_qs }}", text, template)
                self.assertNotIn("api_key=secret", text, template)

    def test_empty_state_present(self):
        for template, _route in PAGES:
            text = (WEB / template).read_text().lower()
            self.assertIn("empty", text, template)

    def test_loading_state_present(self):
        for template, _route in PAGES:
            text = (WEB / template).read_text().lower()
            self.assertIn("loading", text, template)

    def test_error_state_present(self):
        for template, _route in PAGES:
            text = (WEB / template).read_text().lower()
            self.assertIn("error", text, template)


class TestStaticAssets(unittest.TestCase):
    def test_aec_css_exists(self):
        self.assertTrue((WEB / "static/css/aec/aec.css").exists())

    def test_aec_js_exists(self):
        self.assertTrue((WEB / "static/js/aec/aec.js").exists())

    def test_css_uses_existing_palette(self):
        text = (WEB / "static/css/aec/aec.css").read_text()
        self.assertIn("--bg", text)
        self.assertIn("--panel", text)

    def test_js_has_no_network_calls(self):
        text = (WEB / "static/js/aec/aec.js").read_text()
        for call in ("fetch(", "XMLHttpRequest", "WebSocket"):
            self.assertNotIn(call, text)


class TestPageRoutes(unittest.TestCase):
    def test_page_routes_registered(self):
        from backend.routers import aec
        paths = {r.path for r in aec.router.routes
                 if hasattr(r, "methods")}
        for _template, route in PAGES:
            self.assertIn(route, paths)

    def test_page_routes_are_get(self):
        from backend.routers import aec
        by_path = {r.path: r.methods for r in aec.router.routes
                   if hasattr(r, "methods")}
        for _template, route in PAGES:
            self.assertEqual(by_path[route], {"GET"})

    def test_no_ui_post_routes(self):
        from backend.routers import aec
        for route in aec.router.routes:
            if hasattr(route, "methods") and route.path.startswith(
                    "/ui/aec"):
                self.assertEqual(route.methods, {"GET"})


class TestOverviewPageData(unittest.TestCase):
    def test_dashboard_page_has_kpi_labels(self):
        text = (WEB / "templates/aec/dashboard.html").read_text()
        for label in ("Candidates", "Active Cases", "Research Jobs",
                      "Waiting Evidence", "Observations",
                      "Review Pending"):
            self.assertIn(label, text, label)

    def test_pipeline_page_lists_eight_stages(self):
        text = (WEB / "templates/aec/pipeline.html").read_text()
        for stage in ("Candidate", "Case", "Assignment", "Research Job",
                      "Authorization", "Observation", "Evidence",
                      "Review"):
            self.assertIn(stage, text, stage)


if __name__ == "__main__":
    unittest.main()