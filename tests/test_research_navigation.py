"""
tests/test_research_navigation.py — Stage D6 research navigation UX tests.

Dashboard research-intelligence section, sidebar active state, and
cross-navigation between Research / Queue / Tasks / XSS / KB / Reports.
Read-only: no network, no Mongo writes.
"""
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
XSS_ID = "xss-66d4b40bc1570361"          # candidate whose evidence names a CVE
KB_ID = "kb-609f38e9c57c0592"            # CVE-2026-1557 synthesis document


_LEGACY_SIDEBAR_LABELS = {
    # the OLD research navigation stays out of the primary sidebar.
    # Core recon destinations (Programs, HTTP, URLs, Endpoints, …) were
    # restored as the Recon Ops group — see tests.test_recon_soc_navigation.
    "Research Cases", "Research / CVEs", "Research Queue", "Research Tasks",
    "Research Leads", "Research Plans", "Research Agent", "XSS",
    "Knowledge Base", "Reports", "Command Center", "Dashboard",
}


def _shipped_sidebar_labels() -> set:
    """Labels rendered by the sidebar this worktree ships (source of truth)."""

    base = Path(__file__).resolve().parents[1] / "web" / "templates" / "base.html"
    nav = re.search(r'<nav class="sidebar-nav">(.*?)</nav>', base.read_text(),
                    re.S).group(1)
    return {m.strip() for m in
            re.findall(r'<span class="side-ico">[^<]*</span>([^<]+)</a>', nav)}


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    def _post(self, path, data, **params):
        p, q = _qs(path, **params)
        return self.client.post(p, data=data, params=q, follow_redirects=False)

    def _active(self, html):
        return re.findall(r'<a class="side-link active" href="([^"]+)"', html)


class TestDashboardResearchSection(_Base):
    def setUp(self):
        # The recon half of the dashboard queries Mongo; mock it so these
        # tests stay offline and fast (same convention as test_research_ui).
        starts = []
        for name in ("global_counts", "program_rows", "latest_runs",
                     "recent_changes", "activity_summary"):
            patcher = mock.patch(f"backend.dashboard.{name}")
            m = patcher.start()
            if name == "global_counts":
                m.return_value = {
                    "programs": 1, "subdomains": 1, "live": 1, "http": 1,
                    "urls": 1, "endpoints": 1, "params": 1, "fresh_http_24h": 0,
                }
            else:
                m.return_value = [] if name != "activity_summary" else None
            starts.append(patcher)
        self.addCleanup(lambda: [p.stop() for p in starts])

    def test_section_and_cards(self):
        r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research Intelligence", r.text)
        for label in ("Research CVEs", "Research Queue", "Research Tasks",
                      "Knowledge Patterns", "Target Research Candidates",
                      "KB Documents", "Reports"):
            self.assertIn(label, r.text)

    def test_cards_link_to_pages(self):
        r = self._get("/")
        for path in ("/ui/research", "/ui/research/queue",
                     "/ui/research/tasks", "/ui/xss", "/ui/kb", "/ui/reports"):
            self.assertIn(path, r.text)

    def test_empty_state_when_overview_unavailable(self):
        from backend import research_data
        with mock.patch.object(
            research_data, "get_overview", side_effect=RuntimeError("boom")
        ):
            r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research intelligence unavailable", r.text)
        # recon KPI grid still renders (dashboard never fails on research)
        self.assertIn("Recon Overview", r.text)


class TestSidebarActiveState(_Base):
    def test_legacy_pages_render_but_are_not_sidebar_destinations(self):
        # UX correction: the sidebar carries Recon Ops + AI SOC + System, so
        # legacy research pages no longer get a sidebar entry (hence no
        # sidebar active highlight).  Routes and page content are unchanged;
        # asserted against the shipped template because this module drives
        # the deployed app.
        cases = [
            "/ui/research", "/ui/research/queue", "/ui/research/tasks",
            "/ui/xss", "/ui/kb", "/ui/reports",
        ]
        labels = _shipped_sidebar_labels()
        leaked = labels & _LEGACY_SIDEBAR_LABELS
        self.assertEqual(leaked, set(), f"legacy sidebar items: {leaked}")
        for path in cases:
            with self.subTest(path=path):
                r = self._get(path)
                self.assertEqual(r.status_code, 200)

    def test_research_group_links_present(self):
        # in-page cross navigation the research page itself renders (the
        # sidebar no longer contributes these hrefs)
        r = self._get("/ui/research")
        for path in ("/ui/research", "/ui/research/queue", "/ui/xss",
                     "/ui/reports"):
            self.assertIn(path, r.text)


class TestCveCrossNavigation(_Base):
    def test_cve_links_to_queue_tasks_report(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("/ui/research/queue", r.text)
        self.assertIn("/ui/research/tasks", r.text)
        self.assertIn(f"/ui/reports/{CVE}", r.text)
        self.assertIn("Queue candidates", r.text)
        self.assertIn("Research tasks", r.text)
        self.assertIn("Knowledge base", r.text)

    def test_cve_xss_link_only_when_applicable(self):
        # XSS CVE -> link present; path-traversal CVE -> absent
        r = self._get("/ui/research/CVE-2024-5376")
        self.assertIn("XSS candidates", r.text)
        r = self._get(f"/ui/research/{CVE}")
        self.assertNotIn("XSS candidates", r.text)


class TestQueueCrossNavigation(_Base):
    def test_queue_back_link_and_start(self):
        r = self._get("/ui/research/queue")
        self.assertEqual(r.status_code, 200)
        self.assertIn("← Research / CVEs", r.text)
        self.assertIn("Start Research", r.text)

    def test_queue_links_open_task_after_create(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch("backend.research_tasks.TASKS_DIR", Path(td)):
                self._post("/ui/research/tasks", {
                    "cve": CVE, "program": "dell",
                    "queue_id": "rq-075e9ef25c8f94a7",
                })
                r = self._get("/ui/research/queue")
        self.assertIn("Open task", r.text)


class TestTaskCrossNavigation(_Base):
    def test_task_links_back_to_cve_and_queue(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch("backend.research_tasks.TASKS_DIR", Path(td)):
                self._post("/ui/research/tasks", {
                    "cve": CVE, "program": "dell",
                    "queue_id": "rq-075e9ef25c8f94a7",
                })
                listing = self._get("/ui/research/tasks")
                tid = re.search(
                    r"/ui/research/tasks/(rt-[0-9a-f]{16})", listing.text
                ).group(1)
                r = self._get(f"/ui/research/tasks/{tid}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"/ui/research/{CVE}", r.text)
        self.assertIn("/ui/research/queue", r.text)
        self.assertIn("CVE research", r.text)
        self.assertIn("Queue view", r.text)
        # DONE wording stays research-completed
        self.assertIn("research completed", r.text.lower())


class TestXssCrossNavigation(_Base):
    def test_xss_links_back_to_related_research(self):
        r = self._get(f"/ui/xss/{XSS_ID}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Related research", r.text)
        self.assertIn("/ui/research/CVE-", r.text)
        # deterministic candidate stays authoritative / not target validated
        # (D9: generic KB pattern, no target association in this corpus)
        self.assertIn("KNOWLEDGE PATTERN — NOT TARGET VALIDATED", r.text)
        self.assertIn("No target associated", r.text)

    def test_xss_without_cve_has_no_research_link(self):
        r = self._get("/ui/xss/xss-0df931af429249e4")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("Related research", r.text)


class TestKbAndReportCrossNavigation(_Base):
    def test_kb_links_to_research_queue_tasks(self):
        r = self._get(f"/ui/kb/{KB_ID}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"/ui/research/{CVE}", r.text)
        self.assertIn("/ui/research/queue", r.text)
        self.assertIn("/ui/research/tasks", r.text)

    def test_report_links_to_research(self):
        r = self._get(f"/ui/reports/{CVE}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"/ui/research/{CVE}", r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
