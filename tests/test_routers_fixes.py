"""
tests/test_routers_fixes.py — Regression tests for the second-pass fixes.
"""
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from backend.routers.programs import (
    _apply_search,
    _apply_sort,
    _paginated_list_ctx,
)


class FakeQS:
    def __init__(self):
        self.filters = {}
        self.order = []

    def filter(self, **kw):
        self.filters.update(kw)
        return self

    def order_by(self, *fields):
        self.order = list(fields)
        return self

    def only(self, *fields):
        return self

    def __iter__(self):
        return iter(())


class TestSearchHelpers(unittest.TestCase):
    def test_apply_search_uses_icontains(self):
        qs = FakeQS()
        out = _apply_search(qs, "api", "subdomain")
        self.assertEqual(out.filters, {"subdomain__icontains": "api"})

    def test_apply_search_ignores_empty(self):
        qs = FakeQS()
        out = _apply_search(qs, None, "subdomain")
        self.assertEqual(out.filters, {})

    def test_apply_sort_whitelisted(self):
        qs = FakeQS()
        out = _apply_sort(qs, "updated", "desc",
                          {"updated": "last_update"}, "subdomain")
        self.assertEqual(out.order, ["-last_update"])

    def test_apply_sort_unknown_key_falls_back(self):
        qs = FakeQS()
        out = _apply_sort(qs, "bogus", "asc",
                          {"updated": "last_update"}, "subdomain")
        self.assertEqual(out.order, ["subdomain"])

    def test_apply_sort_ascending(self):
        qs = FakeQS()
        out = _apply_sort(qs, "subdomain", "asc",
                          {"subdomain": "subdomain"}, "subdomain")
        self.assertEqual(out.order, ["subdomain"])


class TestPaginationParams(unittest.TestCase):
    def test_pagination_preserves_search_and_sort(self):
        ctx = _paginated_list_ctx(
            base_path="/ui/subdomains/program/dell",
            page=2, limit=100, total=350,
            extra={"q": "api", "sort": "updated", "direction": "desc"},
        )
        self.assertIn("q=api", ctx["prev_url"])
        self.assertIn("q=api", ctx["next_url"])
        self.assertIn("sort=updated", ctx["next_url"])
        self.assertIn("direction=desc", ctx["next_url"])
        self.assertEqual(ctx["page"], 2)
        self.assertEqual(ctx["total_pages"], 4)

    def test_pagination_first_page_has_no_prev(self):
        ctx = _paginated_list_ctx(base_path="/x", page=1, limit=100, total=350)
        self.assertIsNone(ctx["prev_url"])
        self.assertIsNotNone(ctx["next_url"])

    def test_pagination_last_page_has_no_next(self):
        ctx = _paginated_list_ctx(base_path="/x", page=4, limit=100, total=350)
        self.assertIsNone(ctx["next_url"])


class TestDomainsProgramIsolation(unittest.TestCase):
    def test_lookup_matches_program_name(self):
        captured = {}

        class FakeColl:
            name = "http"

        http_coll = FakeColl()
        fake = mock.MagicMock()
        fake.aggregate.return_value = iter([{"total": [{"count": 0}], "items": []}])
        fake.distinct.return_value = []

        with mock.patch("backend.routers.programs.LiveSubdomains._get_collection",
                        return_value=fake), \
             mock.patch("backend.routers.programs.Http._get_collection",
                        return_value=http_coll):
            from backend.routers.programs import ui_domains
            ui_domains(mock.Mock(), limit=10)

        pipeline = fake.aggregate.call_args[0][0]
        lookup = next(s for s in pipeline if "$lookup" in s)["$lookup"]
        self.assertIn("prog", lookup["let"])


class TestStatsByProgramNoN1(unittest.TestCase):
    def test_no_per_program_count_queries(self):
        rows = [
            {
                "program_name": "dell", "subdomains": 1, "live": 1, "http": 1,
                "urls": 1, "endpoints": 1, "endpoints_with_params": 0,
                "endpoints_x8_checked": 0, "params": 0, "changes_24h": 0,
                "last_crawl": None, "last_param": None, "last_dns": None,
                "last_activity": None, "stale": True,
            }
        ]
        with mock.patch("backend.dashboard._program_names",
                        return_value=["dell"]), \
             mock.patch("backend.dashboard._metrics", return_value={}), \
             mock.patch("backend.dashboard.compute_program_rows",
                        return_value=rows):
            from backend.routers.programs import stats_by_program
            # Ensure no program-level .objects().count() calls happen
            with mock.patch("database.db.Programs.objects") as p:
                p.return_value.count.side_effect = AssertionError("N+1")
                out = stats_by_program()
        self.assertIn("dell", out)
        self.assertEqual(out["dell"]["endpoints_with_params"], 0)


class TestEmptyDataRender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)
        cls.api_key = __import__("config").config().get("API_KEY", "")

    def _get(self, path):
        return self.client.get(f"{path}?api_key={self.api_key}")

    @mock.patch("backend.dashboard.global_counts")
    @mock.patch("backend.dashboard.program_rows")
    @mock.patch("backend.dashboard.latest_runs")
    @mock.patch("backend.dashboard.recent_changes")
    def test_dashboard_empty(self, recent, latest, rows, counts):
        counts.return_value = {"programs": 0, "subdomains": 0, "live": 0,
                               "http": 0, "urls": 0, "endpoints": 0,
                               "params": 0, "fresh_http_24h": 0}
        rows.return_value = []
        latest.return_value = []
        recent.return_value = []
        r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No programs yet.", r.text)

    @mock.patch("backend.dashboard.program_rows")
    def test_programs_empty(self, rows):
        rows.return_value = []
        r = self._get("/ui/programs")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No programs match this filter.", r.text)


class TestXssSafeRendering(unittest.TestCase):
    def _render(self, template_name, **ctx):
        from backend.templating import templates
        tmpl = templates.env.get_template(template_name)
        return tmpl.render(**ctx)

    def test_change_values_are_escaped(self):
        ctx = {
            "api_key_qs": "", "root_url": "/", "home_url": "/",
            "tasks_url": "/ui/tasks", "runs_url": "/ui/runs",
            "changes_url": "/ui/changes", "domains_url": "/ui/domains",
            "programs_url": "/ui/programs", "dns_url": "/ui/dns-bruteforce/status",
            "docs_url": "/docs", "fresh_link": "/ui/http/fresh",
            "request": mock.Mock(), "page": 1, "total_pages": 1, "total": 1,
            "prev_url": None, "next_url": None,
            "changes": [{
                "program_name": "<img src=x onerror=alert(1)>",
                "program_url": "/ui/program/x",
                "subdomain": "x' onmouseover=alert(1)",
                "event_type": "title_changed",
                "event_class": "title_changed",
                "label": "Title",
                "old_value": "<script>alert('old')</script>",
                "new_value": "<script>alert('new')</script>",
                "created_date": None,
            }],
        }
        html = self._render("changes.html", **ctx)
        self.assertNotIn("<script>alert('old')", html)
        self.assertNotIn("<script>alert('new')", html)
        self.assertNotIn("<img src=x onerror=", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()