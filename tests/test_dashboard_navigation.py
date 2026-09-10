"""
tests/test_dashboard_navigation.py — Stage D8 dashboard navigation &
Recent Operations regression tests.

Covers:
- every Research sidebar destination (href, route response, precedence)
- dashboard <-> leads <-> plans <-> CVE cross navigation
- Recent Operations rendering + per-operation fail-soft (no fabrication)
- the "All runs" link points at the real UI Runs route
- security: api_key scope, escaping, no open redirect / path generation

Fully offline: Mongo-backed dashboard queries are mocked; no network, no
writes, no LLM. The focused-on-UI nature keeps it independent of the real
recon DB.
"""
import re
import sys
import unittest
from contextlib import contextmanager
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")

CVE = "CVE-2026-1557"                    # persisted research, program dell
LEAD_ID = "rl-af7ecfba1a86fc83"          # R21 lead for CVE-2026-1557 -> dell
PLAN_ID = "r22-38d26f10681e9a0f"         # R22 plan for that lead

SIDE_LINK_RE = re.compile(
    r'<a class="side-link[^"]*" href="([^"]*)"[^>]*>\s*'
    r'<span class="side-ico">[^<]*</span>([^<]+)</a>'
)

# The eight Research sidebar destinations required by D8.
RESEARCH_SIDEBAR = {
    "Research / CVEs": "/ui/research",
    "Research Queue": "/ui/research/queue",
    "Research Tasks": "/ui/research/tasks",
    "Research Leads": "/ui/research/leads",
    "Research Plans": "/ui/research/plans",
    "XSS": "/ui/xss",
    "Knowledge Base": "/ui/kb",
    "Reports": "/ui/reports",
}


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


@contextmanager
def dashboard_data(latest_runs=None, counts=None):
    """Patch the Mongo-backed recon dashboard queries (offline render)."""
    if counts is None:
        counts = {"programs": 1, "subdomains": 1, "live": 1, "http": 1,
                  "urls": 1, "endpoints": 1, "params": 1, "fresh_http_24h": 0}
    if latest_runs is None:
        latest_runs = []
    with mock.patch("backend.dashboard.global_counts", return_value=counts), \
         mock.patch("backend.dashboard.program_rows", return_value=[]), \
         mock.patch("backend.dashboard.latest_runs", return_value=latest_runs), \
         mock.patch("backend.dashboard.recent_changes", return_value=[]), \
         mock.patch("backend.dashboard.activity_summary",
                    return_value={"total": 0}):
        yield


@contextmanager
def runs_data():
    """Patch the Runs page task/DNS queries (offline render)."""
    with mock.patch("backend.routers.runs.TaskRun") as taskrun, \
         mock.patch("backend.routers.runs.DnsBruteStatus") as dns, \
         mock.patch("backend.routers.runs.get_task_status", return_value="idle"), \
         mock.patch("backend.routers.runs.get_last_run", return_value=None):
        taskrun.objects.return_value.count.return_value = 0
        dns.objects.return_value.order_by.return_value.limit.return_value = []
        yield


@contextmanager
def domains_data():
    """Patch the Live Domains aggregation (offline render)."""
    fake = mock.MagicMock()
    fake.aggregate.return_value = [{"total": [], "items": []}]
    fake.distinct.return_value = []
    with mock.patch("backend.routers.programs.LiveSubdomains._get_collection",
                    return_value=fake), \
         mock.patch("backend.routers.programs.Http._get_collection",
                    return_value=mock.MagicMock()), \
         mock.patch("backend.routers.programs.dash._program_names",
                    return_value=[]):
        yield


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    @staticmethod
    def _sidebar(html):
        return {name.strip(): href for href, name in SIDE_LINK_RE.findall(html)}


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------


class TestResearchSidebar(_Base):
    def _render(self, page):
        if page == "/":
            with dashboard_data():
                return self._get(page)
        if page == "/ui/runs":
            with runs_data():
                return self._get(page)
        if page == "/ui/domains":
            with domains_data():
                return self._get(page)
        return self._get(page)

    def test_every_research_destination_present_and_nonempty(self):
        for page in ("/", "/ui/runs", "/ui/domains", "/ui/research"):
            with self.subTest(page=page):
                r = self._render(page)
                self.assertEqual(r.status_code, 200)
                links = self._sidebar(r.text)
                for name, path in RESEARCH_SIDEBAR.items():
                    self.assertIn(name, links, f"{page}: missing sidebar {name!r}")
                    href = links[name]
                    self.assertTrue(href, f"{page}: empty href for {name!r}")
                    self.assertEqual(href.split("?")[0], path,
                                     f"{page}: {name!r} -> {href!r}")
                # regression: plans was the link left undefined on
                # programs.py / runs.py pages (rendered href="").
                self.assertTrue(links["Research Plans"])

    def test_every_research_destination_route_resolves(self):
        for name, path in RESEARCH_SIDEBAR.items():
            with self.subTest(name=name):
                r = self._get(path)
                self.assertEqual(r.status_code, 200, path)

    def test_specific_routes_not_swallowed_by_generic_cve(self):
        cases = {
            "/ui/research/queue": "Research Queue",
            "/ui/research/tasks": "Research Tasks",
            "/ui/research/leads": "Research Leads",
            "/ui/research/plans": "Research Plans",
        }
        for path, marker in cases.items():
            with self.subTest(path=path):
                r = self._get(path)
                self.assertEqual(r.status_code, 200)
                self.assertIn(marker, r.text)
                self.assertNotIn("Invalid CVE identifier", r.text)

    def test_api_specific_routes_not_swallowed_by_generic_cve(self):
        for path in ("/api/research/queue", "/api/research/leads",
                     "/api/research/plans"):
            with self.subTest(path=path):
                r = self._get(path)
                self.assertEqual(r.status_code, 200, path)


# --------------------------------------------------------------------------
# Cross navigation
# --------------------------------------------------------------------------


class TestCrossNavigation(_Base):
    def test_dashboard_links_to_leads_and_plans(self):
        with dashboard_data():
            r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("/ui/research/leads", r.text)
        self.assertIn("/ui/research/plans", r.text)

    def test_lead_detail_links_to_plan_and_cve(self):
        r = self._get(f"/ui/research/leads/{LEAD_ID}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"/ui/research/plans/{PLAN_ID}", r.text)
        self.assertIn(f"/ui/research/{CVE}", r.text)
        self.assertIn(CVE, r.text)

    def test_plan_detail_links_to_cve_and_lead(self):
        r = self._get(f"/ui/research/plans/{PLAN_ID}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"/ui/research/{CVE}", r.text)
        self.assertIn(f"/ui/research/leads/{LEAD_ID}", r.text)
        self.assertIn("REVIEW_PUBLIC_POC", r.text)
        # remains research planning, not a vulnerability claim
        self.assertIn("NOT VERIFIED", r.text)

    def test_cve_detail_links_to_queue_task_lead_plan_kb(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertEqual(r.status_code, 200)
        for frag in ("/ui/research/queue", "/ui/research/tasks", "/ui/kb"):
            self.assertIn(frag, r.text)
        self.assertIn(f"/ui/research/leads/{LEAD_ID}", r.text)
        self.assertIn(f"/ui/research/plans/{PLAN_ID}", r.text)

    def test_cve_xss_link_only_when_applicable(self):
        # non-XSS CVE -> no XSS candidate link (existing safe rule preserved)
        r = self._get(f"/ui/research/{CVE}")
        self.assertNotIn("XSS candidates", r.text)
        # XSS CVE -> link present
        r = self._get("/ui/research/CVE-2024-5376")
        self.assertIn("XSS candidates", r.text)


# --------------------------------------------------------------------------
# Recent Operations
# --------------------------------------------------------------------------


class TestRecentOperations(_Base):
    @staticmethod
    def _ops(html):
        return html.split("Recent Operations", 1)[1].split("Recent Activity", 1)[0]

    def test_lists_all_registered_operations(self):
        import backend.dashboard as dash
        from backend.tasks_registry import task_ids

        with mock.patch.object(dash, "get_task_status", return_value="idle"), \
             mock.patch.object(dash, "get_last_run", return_value=None):
            runs = dash.latest_runs()
        self.assertEqual([r["task_id"] for r in runs], task_ids())
        self.assertEqual(len(runs), 6)
        for r in runs:
            self.assertEqual(r["status"], "idle")
            self.assertIsNone(r["last_run"])

    def test_fail_soft_when_one_data_source_raises(self):
        import backend.dashboard as dash

        with mock.patch.object(dash, "get_task_status",
                               side_effect=RuntimeError("db down")), \
             mock.patch.object(dash, "get_last_run",
                               side_effect=RuntimeError("db down")):
            runs = dash.latest_runs()
        # still one row per operation; none invented
        self.assertEqual(len(runs), 6)
        for r in runs:
            self.assertEqual(r["status"], "idle")
            self.assertIsNone(r["last_run"])

    def test_renders_success_failed_never_and_duration(self):
        rows = [
            {"task_id": "crawl_all", "name": "Crawl All (full corpus)",
             "status": "success",
             "last_run": {"started_tehran": "31 Aug 2026 15:10",
                          "finished_tehran": "31 Aug 2026 17:24",
                          "duration": "2h 14m", "ago": "5h ago"}},
            {"task_id": "dns_static", "name": "DNS Bruteforce (static wordlist)",
             "status": "failed",
             "last_run": {"started_tehran": "31 Aug 2026 10:00",
                          "finished_tehran": "31 Aug 2026 10:05",
                          "duration": "5m", "ago": "10h ago"}},
            {"task_id": "param_discovery", "name": "Parameter Discovery (x8)",
             "status": "idle", "last_run": None},
        ]
        with dashboard_data(latest_runs=rows):
            r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("SUCCESS", r.text)
        self.assertIn("FAILED", r.text)
        self.assertIn("NEVER", r.text)
        self.assertIn("2h 14m", r.text)
        self.assertIn("5m", r.text)
        self.assertIn("31 Aug 2026 15:10", r.text)

    def test_malformed_run_data_is_fail_soft(self):
        # a row claiming a run but carrying no run payload must not 500
        rows = [
            {"task_id": "crawl_all", "name": "Crawl All", "status": "success",
             "last_run": None},
            {"task_id": "dns_static", "name": "DNS", "status": "idle",
             "last_run": None},
        ]
        with dashboard_data(latest_runs=rows):
            r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("SUCCESS", r.text)
        self.assertIn("NEVER", r.text)

    def test_never_run_has_no_fabricated_timestamp(self):
        rows = [{"task_id": "crawl_all", "name": "Crawl All NoRun",
                 "status": "idle", "last_run": None}]
        with dashboard_data(latest_runs=rows):
            r = self._get("/")
        self.assertEqual(r.status_code, 200)
        ops = self._ops(r.text)
        row = ops.split("Crawl All NoRun", 1)[1].split("</tr>", 1)[0]
        self.assertIn("NEVER", row)
        self.assertNotRegex(row, r"\b20\d\d\b")
        self.assertIn("—", row)


# --------------------------------------------------------------------------
# All runs link
# --------------------------------------------------------------------------


class TestAllRunsLink(_Base):
    def test_all_runs_points_to_ui_runs_page(self):
        with dashboard_data():
            r = self._get("/")
        self.assertEqual(r.status_code, 200)
        m = re.search(r'<a class="badge-link" href="([^"]+)"[^>]*>All runs',
                      r.text)
        self.assertIsNotNone(m, "All runs link not found")
        href = m.group(1)
        self.assertTrue(href.startswith("/ui/runs"), href)
        self.assertNotIn("/api/", href)

    def test_runs_page_resolves(self):
        with runs_data():
            r = self._get("/ui/runs")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Recon Runs", r.text)


# --------------------------------------------------------------------------
# Security
# --------------------------------------------------------------------------


class TestNavigationSecurity(_Base):
    def test_api_key_not_leaked_to_external_urls(self):
        with dashboard_data():
            r = self._get("/")
        for href in re.findall(r'href="([^"]+)"', r.text):
            if href.startswith(("http://", "https://", "//")):
                self.assertNotIn("api_key=", href, href)

    def test_hostile_operation_name_is_escaped(self):
        payload = "<script>alert('xss')</script>"
        rows = [{"task_id": "crawl_all", "name": payload,
                 "status": "failed", "last_run": None}]
        with dashboard_data(latest_runs=rows):
            r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(payload, r.text)
        self.assertIn("&lt;script&gt;", r.text)

    def test_no_open_redirect_on_research_pages(self):
        for path in ("/ui/research", "/ui/research/queue",
                     "/ui/research/tasks", "/ui/research/leads",
                     "/ui/research/plans"):
            with self.subTest(path=path):
                r = self._get(path, next="https://evil.example/",
                              redirect="https://evil.example/")
                self.assertEqual(r.status_code, 200)
                self.assertNotIn("location", {k.lower() for k in r.headers})

    def test_invalid_plan_id_rejected(self):
        for bad in ("not-a-plan", "r22-zzzz", "r22-0123", "r22-../../etc"):
            with self.subTest(bad=bad):
                r = self._get(f"/ui/research/plans/{bad}")
                self.assertIn(r.status_code, (400, 404), bad)
                self.assertNotIn("root:", r.text)

    def test_invalid_lead_id_rejected(self):
        for bad in ("not-a-lead", "rl-zzzz", "rl-0123"):
            with self.subTest(bad=bad):
                r = self._get(f"/ui/research/leads/{bad}")
                self.assertIn(r.status_code, (400, 404), bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
