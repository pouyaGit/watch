"""
tests/test_ui_redesign.py — Focused tests for the professional UI/UX
redesign: sidebar shell, dashboard operations table, programs search +
pagination, global discovery pages (HTTP / URLs / Endpoints / Parameters),
global search, CDN badge safety and shared badge macros.

No live MongoDB / network: every data access is monkeypatched.
"""
import unittest
from datetime import datetime, timedelta
from unittest import mock

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")


def _api(path, **params):
    from urllib.parse import urlencode
    qs = {"api_key": API_KEY} if API_KEY else {}
    qs.update(params)
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}{urlencode(qs)}" if qs else path


def _chain(qs_cls, rows=None, total=0):
    """Mock a mongoengine-style objects().filter().order_by().only() chain
    that paginates to `rows` and counts `total`."""
    qs = mock.MagicMock()
    qs.count.return_value = total
    qs.order_by.return_value = qs
    qs.only.return_value = qs
    qs.filter.return_value = qs
    qs.skip.return_value = qs
    qs.limit.return_value = rows or []
    qs.__iter__ = lambda self: iter(rows or [])
    return qs


class TestShell(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        return self.client.get(_api(path, **params))

    @mock.patch("backend.dashboard.global_counts")
    @mock.patch("backend.dashboard.program_rows")
    @mock.patch("backend.dashboard.latest_runs")
    @mock.patch("backend.dashboard.recent_changes")
    def test_sidebar_and_topbar_render(self, recent, latest, rows, counts):
        counts.return_value = {"programs": 1, "subdomains": 2, "live": 1,
                               "http": 1, "urls": 1, "endpoints": 1,
                               "params": 1, "fresh_http_24h": 0}
        rows.return_value = []
        latest.return_value = []
        recent.return_value = []
        r = self._get("/")
        self.assertEqual(r.status_code, 200, r.text[:300])
        # sidebar groups + destinations
        for token in ("Overview", "Discovery", "Operations", "System",
                      "/ui/parameters", "/ui/endpoints", "/ui/http", "/ui/urls"):
            self.assertIn(token, r.text)
        # timezone indicator (mandatory)
        self.assertIn("Asia/Tehran", r.text)
        # global search entry point
        self.assertIn("/ui/search", r.text)

    @mock.patch("backend.dashboard.global_counts")
    @mock.patch("backend.dashboard.program_rows")
    @mock.patch("backend.dashboard.latest_runs")
    @mock.patch("backend.dashboard.recent_changes")
    def test_dashboard_operations_table(self, recent, latest, rows, counts):
        now = datetime.now()
        counts.return_value = {"programs": 1, "subdomains": 2, "live": 1,
                               "http": 1, "urls": 1, "endpoints": 1,
                               "params": 1, "fresh_http_24h": 0}
        rows.return_value = []
        latest.return_value = [
            {"task_id": "crawl_all", "name": "Crawl All (full corpus)",
             "status": "running",
             "last_run": {"started_tehran": "31 Aug 2026 15:10",
                          "finished_tehran": "—", "ago": "32m ago",
                          "duration": "32m", "log_name": "crawl_all_x.log"}},
            {"task_id": "dns_static", "name": "DNS Bruteforce (static wordlist)",
             "status": "failed",
             "last_run": {"started_tehran": "31 Aug 2026 10:00",
                          "finished_tehran": "31 Aug 2026 12:14", "ago": "5h ago",
                          "duration": "2h 14m", "log_name": "dns_static_y.log"}},
            {"task_id": "param_discovery", "name": "Parameter Discovery (x8)",
             "status": "idle", "last_run": None},
        ]
        recent.return_value = []
        r = self._get("/")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("RUNNING", r.text)
        self.assertIn("FAILED", r.text)
        self.assertIn("2h 14m", r.text)
        self.assertIn("31 Aug 2026 15:10", r.text)
        self.assertIn("NEVER", r.text)

    @mock.patch("backend.dashboard.global_counts")
    @mock.patch("backend.dashboard.program_rows")
    @mock.patch("backend.dashboard.latest_runs")
    @mock.patch("backend.dashboard.recent_changes")
    def test_dashboard_change_events_use_whitelisted_class(self, recent, latest, rows, counts):
        counts.return_value = {"programs": 0, "subdomains": 0, "live": 0,
                               "http": 0, "urls": 0, "endpoints": 0,
                               "params": 0, "fresh_http_24h": 0}
        rows.return_value = []
        latest.return_value = []
        recent.return_value = [{
            "program_name": "p", "subdomain": "s",
            "event_type": '"><script>alert(1)</script>',
            "event_class": "other",  # server-side whitelist already applied
            "label": "• Change", "old_value": "a", "new_value": "b",
            "created_date": datetime.now(),
        }]
        r = self._get("/")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("change-other", r.text)
        self.assertNotIn("<script>alert(1)</script>", r.text)


class TestProgramsSearchPagination(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _rows(self, n):
        return [
            {"program_name": f"prog{i}", "subdomains": i, "live": i,
             "http": i, "urls": i, "endpoints": i, "params": i,
             "changes_24h": 0, "last_crawl": None, "last_dns": None,
             "last_activity": datetime.now(), "stale": False}
            for i in range(n)
        ]

    def test_search_filters_programs(self):
        with mock.patch("backend.dashboard.program_rows", return_value=self._rows(5)), \
             mock.patch("backend.dashboard.search_program_rows",
                        side_effect=lambda rows, q: [r for r in rows if q and q in r["program_name"]]):
            r = self.client.get(_api("/ui/programs", q="prog1"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("prog1", r.text)
        self.assertNotIn("prog2", r.text)

    def test_pagination_preserves_search_sort_mode(self):
        with mock.patch("backend.dashboard.program_rows", return_value=self._rows(30)), \
             mock.patch("backend.dashboard.search_program_rows", return_value=self._rows(30)):
            r = self.client.get(_api("/ui/programs", q="prog", sort="live",
                                     direction="desc", mode="active", page=2, limit=10))
        self.assertEqual(r.status_code, 200, r.text[:300])
        # prev/next links must carry every active param
        self.assertIn("q=prog", r.text)
        self.assertIn("sort=live", r.text)
        self.assertIn("direction=desc", r.text)
        self.assertIn("mode=active", r.text)
        self.assertIn("page=1", r.text)
        self.assertIn("page=3", r.text)

    def test_empty_search_state(self):
        with mock.patch("backend.dashboard.program_rows", return_value=self._rows(3)), \
             mock.patch("backend.dashboard.search_program_rows", return_value=[]):
            r = self.client.get(_api("/ui/programs", q="zzz"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("No programs match", r.text)


class TestGlobalDiscoveryPages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def test_http_page_200(self):
        with mock.patch("backend.routers.programs.Http") as http, \
             mock.patch("backend.dashboard._program_names", return_value=["dell"]):
            http.objects.return_value = _chain(http, rows=[], total=0)
            r = self.client.get(_api("/ui/http"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("HTTP records", r.text)

    def test_urls_page_200(self):
        with mock.patch("backend.routers.programs.Urls") as urls:
            urls.objects.return_value = _chain(urls, rows=[], total=0)
            r = self.client.get(_api("/ui/urls"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("No URLs recorded yet.", r.text)

    def test_endpoints_page_200(self):
        with mock.patch("backend.routers.programs.Endpoints") as eps:
            eps.objects.return_value = _chain(eps, rows=[], total=0)
            r = self.client.get(_api("/ui/endpoints"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("unique paths", r.text)

    def test_parameters_page_200(self):
        fake = mock.MagicMock()
        fake.aggregate.return_value = iter([{"total": [{"count": 0}], "items": []}])
        with mock.patch("backend.routers.programs.Endpoints._get_collection",
                        return_value=fake):
            r = self.client.get(_api("/ui/parameters"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("distinct parameter names", r.text)

    def test_parameters_page_with_rows(self):
        fake = mock.MagicMock()
        fake.aggregate.return_value = iter([{
            "total": [{"count": 1}],
            "items": [{"_id": "token", "count": 42, "programs": ["dell"]}],
        }])
        with mock.patch("backend.routers.programs.Endpoints._get_collection",
                        return_value=fake):
            r = self.client.get(_api("/ui/parameters"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("token", r.text)
        self.assertIn("dell", r.text)

    def test_search_page_no_query(self):
        r = self.client.get(_api("/ui/search"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("Type a query", r.text)

    def test_search_page_no_results(self):
        with mock.patch("backend.dashboard.program_rows", return_value=[]), \
             mock.patch("backend.dashboard.search_program_rows", return_value=[]), \
             mock.patch("backend.routers.pages.LiveSubdomains") as lives, \
             mock.patch("backend.routers.pages.Endpoints") as eps, \
             mock.patch("backend.routers.pages.Urls") as urls:
            for m in (lives, eps, urls):
                m.objects.return_value = _chain(m, rows=[], total=0)
            r = self.client.get(_api("/ui/search", q="nothing"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("No results", r.text)


class TestCdnBadgeSafety(unittest.TestCase):
    def test_cdn_slug_filter(self):
        from backend.templating import _cdn_slug
        self.assertEqual(_cdn_slug("Cloudflare"), "cloudflare")
        self.assertEqual(_cdn_slug("AWS CloudFront"), "aws-cloudfront")
        self.assertEqual(_cdn_slug("Normal"), "normal")
        self.assertEqual(_cdn_slug(None), "unknown")
        self.assertEqual(_cdn_slug("—"), "unknown")
        # hostile input cannot escape the class attribute
        self.assertEqual(_cdn_slug('"><script>alert(1)</script>'), "script-alert-1-script")
        self.assertNotIn('"', _cdn_slug('a"b'))
        self.assertNotIn("<", _cdn_slug('a<b'))

    def test_cdn_badge_escapes_display(self):
        from backend.templating import templates
        tmpl = templates.env.get_template("macros.html")
        out = tmpl.module.cdn_badge('"><img src=x onerror=alert(1)>')
        self.assertNotIn("<img", out)
        self.assertIn("&#34;", out)  # escaped quote (numeric entity)


class TestStatusBadgeMacro(unittest.TestCase):
    def _badge(self, status):
        from backend.templating import templates
        tmpl = templates.env.get_template("macros.html")
        return tmpl.module.status_badge(status)

    def test_running(self):
        out = self._badge("running")
        self.assertIn("RUNNING", out)
        self.assertIn("badge-running", out)

    def test_success_failed_idle(self):
        self.assertIn("SUCCESS", self._badge("success"))
        self.assertIn("FAILED", self._badge("failed"))
        self.assertIn("NEVER", self._badge(None))
        self.assertIn("NEVER", self._badge("idle"))


class TestDomainsProgramFilter(unittest.TestCase):
    def test_program_dropdown_present(self):
        fake = mock.MagicMock()
        fake.aggregate.return_value = iter([{"total": [{"count": 0}], "items": []}])
        fake.distinct.return_value = ["Cloudflare"]
        with mock.patch("backend.routers.programs.LiveSubdomains._get_collection",
                        return_value=fake), \
             mock.patch("backend.routers.programs.Http._get_collection",
                        return_value=mock.MagicMock()), \
             mock.patch("backend.dashboard._program_names", return_value=["dell", "indeed"]):
            from api import app
            client = TestClient(app)
            r = client.get(_api("/ui/domains"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("All programs", r.text)
        self.assertIn("dell", r.text)


class TestPaginationFilterPreservation(unittest.TestCase):
    """Domains pagination must preserve q / sort / direction / filters."""

    def test_next_url_keeps_all_params(self):
        fake = mock.MagicMock()
        fake.aggregate.return_value = iter([{
            "total": [{"count": 250}],
            "items": [],
        }])
        fake.distinct.return_value = []
        with mock.patch("backend.routers.programs.LiveSubdomains._get_collection",
                        return_value=fake), \
             mock.patch("backend.routers.programs.Http._get_collection",
                        return_value=mock.MagicMock()), \
             mock.patch("backend.dashboard._program_names", return_value=[]):
            from api import app
            client = TestClient(app)
            r = client.get(_api("/ui/domains", q="api", cdn="Cloudflare",
                                status="2xx", sort="domain", direction="asc",
                                page=2, limit=100))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIn("q=api", r.text)
        self.assertIn("cdn=Cloudflare", r.text)
        self.assertIn("status=2xx", r.text)
        self.assertIn("sort=domain", r.text)
        self.assertIn("direction=asc", r.text)


if __name__ == "__main__":
    unittest.main()
