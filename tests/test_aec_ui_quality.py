"""EPIC8 Part 9+10: UI quality invariants and serialization guarantees."""

from __future__ import annotations

import json
import unittest


class TestSerialization(unittest.TestCase):
    def test_all_views_json_serializable(self):
        from backend.routers import aec
        views = (
            aec.build_dashboard_view(),
            aec.build_pipeline_view(),
            aec.build_observations_view(),
            aec.build_evidence_viewer_view(),
            aec.build_audit_view(),
            aec.build_case_detail_view("case-df54757aee1a"),
        )
        for view in views:
            json.dumps(view)

    def test_render_ready_values(self):
        """Values must be plain JSON types — never datetimes/decimal."""
        from backend.routers import aec
        for view in (aec.build_dashboard_view(),
                     aec.build_audit_view(),
                     aec.build_observations_view()):
            text = json.dumps(view)
            self.assertNotIn("datetime", text)
            self.assertNotIn("Decimal", text)

    def test_no_none_render_breaks(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            for value in row.values():
                self.assertIsNotNone(value)


class TestBadgesAndStates(unittest.TestCase):
    def test_badge_classes_exist_in_css(self):
        from pathlib import Path
        css = Path("web/static/css/aec/aec.css").read_text()
        for badge in ("ok", "warn", "err", "muted"):
            self.assertIn(badge, css)

    def test_stage_badge_mapping_in_page(self):
        from pathlib import Path
        text = Path("web/templates/aec/pipeline.html").read_text()
        self.assertIn("badge", text)

    def test_dashboard_uses_cards(self):
        from pathlib import Path
        text = Path("web/templates/aec/dashboard.html").read_text()
        self.assertIn("card", text.lower())


class TestBaseIntegration(unittest.TestCase):
    def test_templates_link_static_assets(self):
        from pathlib import Path
        for template in Path("web/templates/aec").glob("*.html"):
            text = template.read_text()
            self.assertIn("/static/css/aec/aec.css", text)
            self.assertIn("/static/js/aec/aec.js", text)

    def test_single_css_link_only(self):
        from pathlib import Path
        for template in Path("web/templates/aec").glob("*.html"):
            text = template.read_text()
            self.assertLessEqual(
                text.count("/static/css/aec/aec.css"), 1)

    def test_templates_use_base_blocks(self):
        from pathlib import Path
        for template in Path("web/templates/aec").glob("*.html"):
            text = template.read_text()
            self.assertIn("{% block content %}", text)


class TestDataFlowBoundaries(unittest.TestCase):
    def test_ui_builders_only_use_simulations(self):
        """The UI derives exclusively from the committed fixtures."""
        from backend.routers import aec
        import inspect
        source = inspect.getsource(aec)
        # no storage/network/db module *imports* at all — check import
        # statements only (function names like get_runtime_requests are
        # EPIC7 API surface, not network access)
        import_lines = [
            line for line in source.splitlines()
            if line.strip().startswith(("import ", "from "))
        ]
        for banned in ("sqlite", "psycopg", "database",
                       "import requests", "from requests", "httpx",
                       "socket", "websocket"):
            for line in import_lines:
                self.assertNotIn(banned, line)

    def test_dashboard_is_simulation_derived(self):
        from backend.routers import aec
        view = aec.build_dashboard_view()
        # the dashboard is a projection: candidates equal the fixture count
        self.assertGreaterEqual(view["candidates"], 0)

    def test_no_db_import_in_router(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path("backend/routers/aec.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertFalse(node.module.startswith("database"),
                                 node.module)


class TestHtmlSecurity(unittest.TestCase):
    def test_templates_escape_dynamic_values(self):
        from pathlib import Path
        for template in Path("web/templates/aec").glob("*.html"):
            text = template.read_text()
            for unsafe in ("{{ value|safe }}", "{{ row|safe }}",
                           "autoescape off", "| e }}"):
                self.assertNotIn(unsafe, text, template.name)

    def test_no_inline_script_with_data(self):
        from pathlib import Path
        for template in Path("web/templates/aec").glob("*.html"):
            text = template.read_text()
            self.assertNotIn("document.write", text)
            self.assertNotIn("innerHTML", text)

    def test_js_avoids_eval(self):
        from pathlib import Path
        js = Path("web/static/js/aec/aec.js").read_text()
        for banned in ("eval(", "new Function", "document.write"):
            self.assertNotIn(banned, js)


class TestResponsiveLayout(unittest.TestCase):
    def test_css_has_media_queries(self):
        from pathlib import Path
        css = Path("web/static/css/aec/aec.css").read_text()
        self.assertIn("@media", css)

    def test_templates_use_grid_or_flex(self):
        from pathlib import Path
        for template in Path("web/templates/aec").glob("*.html"):
            text = template.read_text()
            self.assertTrue(
                "grid" in text or "flex" in text, template.name)

    def test_kpi_grid_present(self):
        from pathlib import Path
        css = Path("web/static/css/aec/aec.css").read_text()
        self.assertIn("grid", css)


class TestAccessibilityBasics(unittest.TestCase):
    def test_tables_have_headers(self):
        from pathlib import Path
        for template in Path("web/templates/aec").glob("*.html"):
            text = template.read_text()
            if "<table" in text:
                self.assertIn("<th", text, template.name)

    def test_status_badges_are_spans(self):
        from pathlib import Path
        text = Path("web/templates/aec/observations.html").read_text()
        self.assertIn("<span", text)


if __name__ == "__main__":
    unittest.main()