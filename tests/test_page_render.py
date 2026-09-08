"""
tests/test_page_render.py — Smoke tests for all dashboard routes using
TestClient with monkeypatched data access (no live MongoDB/network).
"""
import json
import sys
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")


def _api_qs(path):
    """Append api_key query param if set in config."""
    return f"{path}?api_key={API_KEY}" if API_KEY else path


class TestDashboardRender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **kwargs):
        url = _api_qs(path)
        if kwargs:
            import urllib.parse
            from urllib.parse import urlencode, urlparse, urlunparse
            parsed = list(urlparse(url))
            existing = dict(urllib.parse.parse_qsl(parsed[4]))
            existing.update(kwargs)
            parsed[4] = urlencode(existing)
            url = urlunparse(parsed)
        return self.client.get(url)

    @mock.patch("backend.dashboard.global_counts")
    @mock.patch("backend.dashboard.program_rows")
    @mock.patch("backend.dashboard.latest_runs")
    @mock.patch("backend.dashboard.recent_changes")
    def test_dashboard_200(self, recent, latest, prog_rows, glob):
        glob.return_value = {
            "programs": 5, "subdomains": 10000, "live": 5000,
            "http": 4000, "urls": 30000, "endpoints": 8000,
            "params": 2000, "fresh_http_24h": 200,
        }
        prog_rows.return_value = [
            {"program_name": "test", "subdomains": 100, "live": 50,
             "http": 40, "urls": 300, "endpoints": 80, "params": 20,
             "changes_24h": 3, "last_activity": datetime.now()}
        ]
        latest.return_value = [
            {"task_id": "crawl_all", "name": "Crawl", "status": "success",
             "last_run": {"started_at": datetime.now(), "finished_at": datetime.now(),
                          "duration": "2h 14m", "log_name": "crawl.log", "ago": "1h ago",
                          "started_tehran": "31 Aug 2026 12:00", "finished_tehran": "31 Aug 2026 14:14"}}
        ]
        recent.return_value = [
            {"program_name": "test", "subdomain": "api.test.com",
             "event_type": "title_changed", "event_class": "title_changed",
             "label": "🔄 Title", "old_value": "Old", "new_value": "New",
             "created_date": datetime.now()}
        ]
        r = self._get("/")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertIn("Crawl", r.text)
        self.assertIn("test", r.text)
        self.assertIn("Title", r.text)

    @mock.patch("backend.dashboard.program_rows")
    def test_programs_page_200(self, prog_rows):
        prog_rows.return_value = [
            {"program_name": "dell", "subdomains": 100, "live": 50,
             "http": 40, "urls": 300, "endpoints": 80, "params": 20,
             "changes_24h": 0, "last_activity": datetime.now(),
             "last_crawl": datetime.now(), "last_dns": None, "stale": False}
        ]
        r = self._get("/ui/programs")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertIn("dell", r.text)

    @mock.patch("backend.dashboard.recent_changes")
    @mock.patch("database.change_events.ChangeEvent.objects")
    def test_changes_page_200(self, mock_objects, recent_changes):
        # Mock the ChangeEvent query chain
        qs = mock.MagicMock()
        qs.count.return_value = 1
        qs.order_by.return_value = qs
        qs.skip.return_value = qs
        qs.limit.return_value = [
            mock.MagicMock(
                as_dict=lambda: {"program_name": "p", "subdomain": "s",
                                 "event_type": "title_changed",
                                 "old_value": "old", "new_value": "new",
                                 "created_date": datetime.now()}
            )
        ]
        mock_objects.return_value = qs
        recent_changes.return_value = []
        r = self._get("/ui/changes")
        self.assertEqual(r.status_code, 200, r.text[:200])

    @mock.patch("backend.routers.pages.get_task_status")
    @mock.patch("backend.routers.pages.get_last_run")
    @mock.patch("backend.routers.pages.list_history")
    def test_tasks_page_200(self, history, last_run, status):
        status.return_value = "idle"
        last_run.return_value = None
        history.return_value = (0, [])
        r = self._get("/ui/tasks")
        self.assertEqual(r.status_code, 200, r.text[:200])
        # Verify basename filter is working (no template error)
        self.assertNotIn("No filter named", r.text)
        self.assertIn("Crawl All (full corpus)", r.text)

    @mock.patch("backend.routers.pages.dash.program_summary")
    @mock.patch("backend.routers.pages.LiveSubdomains")
    @mock.patch("backend.routers.pages.Http")
    @mock.patch("backend.routers.pages.Subdomains")
    def test_program_detail_200(self, subs, http, lives, summary):
        summary.return_value = {
            "program_name": "dell", "subdomains": 100, "live": 50,
            "http": 40, "urls": 300, "endpoints": 80, "params": 20,
            "endpoints_with_params": 12, "endpoints_x8_checked": 5,
            "last_crawl": datetime.now(), "last_http": datetime.now(),
            "last_param": datetime.now(), "last_dns_static": None,
            "last_dns_dynamic": None, "last_dns": None,
            "last_activity": datetime.now(),
        }
        lives.objects.return_value.order_by.return_value.only.return_value.__getitem__.return_value = []
        http.objects.return_value.distinct.return_value = []
        http.objects.return_value.only.return_value = []
        subs.objects.return_value.count.return_value = 0
        r = self._get("/ui/program/dell")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertIn("dell", r.text.lower())

    @mock.patch("backend.routers.programs.LiveSubdomains._get_collection")
    @mock.patch("backend.routers.programs.Http._get_collection")
    def test_domains_page_200(self, http_coll, lives_coll):
        # Fake aggregate pipeline
        fake_coll = mock.MagicMock()
        fake_coll.aggregate.return_value = [
            {
                "total": [{"count": 0}],
                "items": []
            }
        ]
        fake_coll.distinct.return_value = ["Cloudflare", "Normal"]
        lives_coll.return_value = fake_coll
        http_coll.return_value = mock.MagicMock()
        r = self._get("/ui/domains")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertIn("Live Domains", r.text)

    @mock.patch("backend.routers.runs.TaskRun")
    @mock.patch("backend.routers.runs.DnsBruteStatus")
    @mock.patch("backend.routers.runs.get_task_status")
    @mock.patch("backend.routers.runs.get_last_run")
    @mock.patch("backend.routers.runs.all_tasks")
    def test_runs_page_200(self, tasks, last_run, status, dns, taskrun):
        tasks.return_value = [
            ("crawl", {"name": "Crawl", "script": "crawl.py", "default_args": []})
        ]
        status.return_value = "success"
        last_run.return_value = None
        taskrun.objects.return_value.count.return_value = 0
        dns.objects.return_value.order_by.return_value.limit.return_value = []
        r = self._get("/ui/runs")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertIn("Crawl", r.text)


if __name__ == "__main__":
    unittest.main()