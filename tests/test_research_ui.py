"""
tests/test_research_ui.py — Stage D3 Research Dashboard UI tests.

Server-rendered pages are exercised through the real app with
TestClient. Hostile-payload escaping tests point the read-only data
layer at a temp directory (module-level dir constants are patched,
never the real ai_data/). No network, no Mongo writes.
"""
import json
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
XSS_ID = "xss-60edf609e21c6b41"
KB_ID = "kb-609f38e9c57c0592"


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


class TestResearchUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    # -- auth ---------------------------------------------------------------
    def test_pages_require_auth(self):
        paths = [
            "/ui/research", f"/ui/research/{CVE}", "/ui/xss",
            f"/ui/xss/{XSS_ID}", "/ui/kb", f"/ui/kb/{KB_ID}",
            "/ui/reports", f"/ui/reports/{CVE}",
            f"/ui/reports/{CVE}/download",
        ]
        for path in paths:
            with self.subTest(path=path):
                r = self.client.get(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)
                else:
                    self.assertIn(r.status_code, (200, 404))

    # -- research list -------------------------------------------------------
    def test_research_page(self):
        r = self._get("/ui/research")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research / CVEs", r.text)
        self.assertIn("RESEARCH ONLY", r.text)
        self.assertIn("NOT A PRODUCTION FINDING", r.text)
        self.assertIn(CVE, r.text)
        # persisted CVE detail link
        self.assertIn(f"/ui/research/{CVE}", r.text)

    def test_research_page_empty_state(self):
        r = self._get("/ui/research", q="zzz-no-such-cve-zzz")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No research artifacts match this filter", r.text)
        self.assertIn("clear the search/filters", r.text)

    def test_research_page_filters(self):
        r = self._get("/ui/research", severity="critical")
        self.assertEqual(r.status_code, 200)
        self.assertIn("CVE-2026-78207", r.text)  # the Critical one
        r = self._get("/ui/research", severity="critical")
        self.assertNotIn(CVE, r.text)  # 7.5 High must not match critical

    def test_research_detail(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(CVE, r.text)
        self.assertIn("RESEARCH ONLY", r.text)
        self.assertIn("Summary", r.text)
        self.assertIn("Vulnerability", r.text)
        self.assertIn("Evidence", r.text)
        self.assertIn("References", r.text)
        self.assertIn("Nuclei", r.text)
        self.assertIn("Report", r.text)
        # references are plain text, not fetched links
        self.assertIn("plugins.trac.wordpress.org", r.text)

    def test_research_detail_missing_404(self):
        r = self._get("/ui/research/CVE-2026-99999")
        self.assertEqual(r.status_code, 404)
        self.assertIn("not found", r.text.lower())

    def test_research_detail_malformed_400(self):
        r = self._get("/ui/research/not-a-cve")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Invalid CVE identifier", r.text)
        self.assertNotIn("ai_data", r.text)
        self.assertNotIn("/opt/watch", r.text)

    def test_research_sort_toggle_inverts_order(self):
        import re
        def cvtes(**params):
            r = self._get("/ui/research", limit=100, **params)
            self.assertEqual(r.status_code, 200)
            return re.findall(r"CVE-\d{4}-\d+</a>", r.text)
        asc = cvtes(sort="title", direction="asc")
        desc = cvtes(sort="title", direction="desc")
        self.assertGreaterEqual(len(asc), 2)
        self.assertEqual(set(asc), set(desc))
        # direction must actually invert the primary ordering
        self.assertEqual(desc, list(reversed(asc)))

    def test_research_sort_updated_is_chronological(self):
        import re
        from backend import research_data as rdata
        dates = {
            it["cve"]: str(it.get("generated_at") or "")
            for it in rdata.list_research(limit=100)["items"]
        }
        r = self._get("/ui/research", sort="updated", direction="asc", limit=100)
        cvcs = re.findall(r"CVE-\d{4}-\d+</a>", r.text)
        self.assertEqual(cvcs, sorted(cvcs, key=lambda c: (dates.get(c[:-4], ""), c)))

    # -- xss -----------------------------------------------------------------
    def test_xss_page(self):
        r = self._get("/ui/xss")
        self.assertEqual(r.status_code, 200)
        self.assertIn("RESEARCH CANDIDATES", r.text)
        self.assertIn("NOT PRODUCTION FINDINGS", r.text)
        self.assertIn(XSS_ID, r.text)

    def test_xss_page_filters(self):
        r = self._get("/ui/xss", status="REJECTED")
        self.assertIn("xss-0df931af429249e4", r.text)
        self.assertNotIn(XSS_ID, r.text)

    def test_xss_detail(self):
        r = self._get(f"/ui/xss/{XSS_ID}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("UNTESTED RESEARCH IDEA", r.text)
        self.assertIn("NEVER EXECUTED", r.text)
        self.assertIn("NOT A PRODUCTION FINDING", r.text)
        self.assertIn("Preconditions", r.text)
        self.assertIn("Unknowns", r.text)

    def test_xss_detail_malformed_and_missing(self):
        self.assertEqual(self._get("/ui/xss/bad-id").status_code, 400)
        self.assertEqual(
            self._get("/ui/xss/xss-0000000000000000").status_code, 404
        )

    # -- kb -------------------------------------------------------------------
    def test_kb_page(self):
        r = self._get("/ui/kb")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Knowledge Base", r.text)
        self.assertIn(KB_ID, r.text)

    def test_kb_page_search(self):
        r = self._get("/ui/kb", q="responsive")
        self.assertIn(KB_ID, r.text)
        r = self._get("/ui/kb", q="zzz-none-zzz")
        self.assertIn("No knowledge documents match", r.text)

    def test_kb_detail(self):
        r = self._get(f"/ui/kb/{KB_ID}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Provenance", r.text)
        self.assertIn("plain text", r.text)
        self.assertIn("md-report", r.text)  # content in escaped <pre>

    def test_kb_detail_malformed_and_missing(self):
        self.assertEqual(self._get("/ui/kb/nope").status_code, 400)
        self.assertEqual(
            self._get("/ui/kb/kb-0000000000000000").status_code, 404
        )

    # -- reports -----------------------------------------------------------------
    def test_reports_page(self):
        r = self._get("/ui/reports")
        self.assertEqual(r.status_code, 200)
        self.assertIn(CVE, r.text)
        self.assertIn("download", r.text)

    def test_report_detail_shows_escaped_markdown(self):
        r = self._get(f"/ui/reports/{CVE}")
        self.assertEqual(r.status_code, 200)
        body = r.text
        pre = body.split('<pre class="md-report">')[1].split("</pre>")[0]
        self.assertIn("# Research Report", pre)
        # headings from the markdown must NOT become page HTML
        self.assertNotIn("<h1>Research Report", body)
        self.assertIn("Download .md", body)

    def test_report_missing_404(self):
        r = self._get("/ui/reports/CVE-2026-99999")
        self.assertEqual(r.status_code, 404)
        self.assertIn("Report not found", r.text)

    def test_report_download(self):
        r = self._get(f"/ui/reports/{CVE}/download")
        self.assertEqual(r.status_code, 200)
        self.assertIn("attachment", r.headers.get("content-disposition", ""))
        self.assertIn("# Research Report", r.text)

    def test_report_traversal_rejected(self):
        for bad in ("../../etc/passwd", "..", "not-a-cve", "CVE-99-1"):
            r = self._get(f"/ui/reports/{bad}")
            self.assertIn(r.status_code, (400, 404), bad)
        # no filesystem content leaked
        r = self._get("/ui/reports/CVE-2026-0000")
        self.assertNotIn("root:", r.text)

    # -- sidebar / overview ---------------------------------------------------------
    def test_sidebar_has_research_nav(self):
        r = self._get("/ui/research")
        for frag in ("/ui/research", "/ui/xss", "/ui/kb", "/ui/reports"):
            self.assertIn(frag, r.text)

    @mock.patch("backend.dashboard.global_counts")
    @mock.patch("backend.dashboard.program_rows")
    @mock.patch("backend.dashboard.latest_runs")
    @mock.patch("backend.dashboard.recent_changes")
    def test_dashboard_research_section(self, recent, latest, rows, counts):
        counts.return_value = {"programs": 1, "subdomains": 1, "live": 1,
                               "http": 1, "urls": 1, "endpoints": 1,
                               "params": 1, "fresh_http_24h": 0}
        rows.return_value = []
        latest.return_value = []
        recent.return_value = []
        r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research CVEs", r.text)
        self.assertIn("XSS Candidates", r.text)
        self.assertIn("KB Documents", r.text)
        self.assertIn("offline artifacts", r.text)

    # -- D5 polish ---------------------------------------------------------------
    @mock.patch("backend.dashboard.global_counts")
    @mock.patch("backend.dashboard.program_rows")
    @mock.patch("backend.dashboard.latest_runs")
    @mock.patch("backend.dashboard.recent_changes")
    def test_dashboard_strip_real_counts(self, recent, latest, rows, counts):
        from backend import research_data as rd
        counts.return_value = {"programs": 1, "subdomains": 1, "live": 1,
                               "http": 1, "urls": 1, "endpoints": 1,
                               "params": 1, "fresh_http_24h": 0}
        rows.return_value = []
        latest.return_value = []
        recent.return_value = []
        expected = rd.get_overview()
        r = self._get("/")
        seg = r.text.split("kpi-research")[1].split("System Health")[0]
        self.assertIn("Nuclei Candidates", seg)
        self.assertIn("Public Exploits", seg)
        self.assertIn(f">{expected['research_cves']}<", seg)
        self.assertIn(f">{expected['nuclei_candidates']}<", seg)
        self.assertIn(f">{expected['xss_candidates']}<", seg)
        self.assertIn(f">{expected['kb_documents']}<", seg)
        self.assertIn(f">{expected['reports']}<", seg)

    def test_research_list_timestamp_and_exploit_columns(self):
        r = self._get("/ui/research")
        self.assertIn("Researched", r.text)
        self.assertIn("Exploit", r.text)
        # real persisted generated_at date for CVE-2026-1557
        self.assertIn("2026-09-06", r.text)

    def test_research_list_active_filter_chips(self):
        r = self._get("/ui/research", q="responsive", severity="high")
        self.assertIn("Active:", r.text)
        self.assertIn("filter-chip", r.text)
        import re
        hrefs = [h.replace("&amp;", "&") for h in
                 re.findall(r'<a class="filter-chip" href="([^"]+)"', r.text)]
        # one chip removes q (keeps severity), the other removes severity
        self.assertTrue(any("severity=high" in h and "q=responsive" not in h for h in hrefs))
        self.assertTrue(any("q=responsive" in h and "severity=high" not in h for h in hrefs))
        # following a removal link still works and keeps the other filter
        keep_sev = next(h for h in hrefs if "severity=high" in h)
        r2 = self.client.get(keep_sev)
        self.assertEqual(r2.status_code, 200)
        self.assertIn("Active:", r2.text)
        self.assertIn("2026-78203", r2.text)  # the High Ghostwriter CVE survives

    def test_no_chips_when_no_filters(self):
        r = self._get("/ui/research")
        self.assertNotIn("Active:", r.text)

    def test_research_detail_new_panels(self):
        r = self._get("/ui/research/CVE-2026-1557")
        for frag in ("Watch Relevance", "Detection Ideas",
                     "Scope &amp; Limitations", "NOT AUTHORITATIVE",
                     "cli-1", "Bounty relevance"):
            self.assertIn(frag, r.text)
        # persisted correlation metadata shown verbatim
        self.assertIn("dell", r.text)
        self.assertIn("WordPress", r.text)

    def test_xss_detail_evidence_cards_and_kb_links(self):
        r = self._get(f"/ui/xss/{XSS_ID}")
        self.assertIn("ev-card", r.text)
        # KB ids matching the valid pattern get real (validated) links
        self.assertIn("/ui/kb/kb-0958da2bb9935000", r.text)
        self.assertIn("UNTESTED RESEARCH IDEA", r.text)

    def test_kb_list_polish(self):
        r = self._get("/ui/kb")
        self.assertIn("Indexed", r.text)
        self.assertIn("cve:CVE-2026-1557", r.text)  # tag chip content

    def test_reports_download_prominence_and_size(self):
        r = self._get("/ui/reports")
        self.assertIn("download .md", r.text.lower())
        self.assertIn(" KB)", r.text)  # human size next to bytes

    # -- escaping with hostile payloads ------------------------------------------------
    def test_hostile_payloads_are_escaped(self):
        payload = "<script>alert('xss')</script>"
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            research = td / "research"
            xss = research / "xss"
            reports = td / "reports"
            kb = td / "knowledge"
            xss.mkdir(parents=True)
            reports.mkdir()
            cli = {
                "cve": {"id": CVE, "cvss_score": 9.9},
                "research": {
                    "title": payload,
                    "severity": "Critical",
                    "vulnerability_type": payload,
                    "summary": payload,
                    "evidence": [payload],
                    "references": [f"https://example.com/{payload}"],
                },
                "authoritative": False,
            }
            (research / f"{CVE}.cli.json").write_text(json.dumps(cli))
            (xss / f"{XSS_ID}.json").write_text(json.dumps({
                "candidate_id": XSS_ID, "status": "RESEARCH_CANDIDATE",
                "query": payload, "test_idea": payload,
                "vulnerability_pattern": payload,
                "disclaimer": payload,
            }))
            (reports / f"{CVE}.md").write_text(f"# t\n<script>alert(1)</script>\n")
            from backend import research_data as rd
            with mock.patch.object(rd, "RESEARCH_DIR", research), \
                 mock.patch.object(rd, "XSS_DIR", xss), \
                 mock.patch.object(rd, "REPORTS_DIR", reports):
                r = self._get(f"/ui/research/{CVE}")
                self.assertEqual(r.status_code, 200)
                self.assertNotIn("<script>alert('xss')</script>", r.text)
                self.assertIn("&lt;script&gt;", r.text)

                r = self._get(f"/ui/xss/{XSS_ID}")
                self.assertNotIn("<script>alert('xss')</script>", r.text)
                self.assertIn("&lt;script&gt;", r.text)
                self.assertIn("quarantine", r.text)

                r = self._get(f"/ui/reports/{CVE}")
                self.assertNotIn("<script>alert(1)</script>", r.text)
                self.assertIn("&lt;script&gt;", r.text)

    def test_no_secrets_in_pages(self):
        from backend import research_data as rd
        env_path = str(rd.PROJECT_ROOT / ".env")
        for path in ("/ui/research", f"/ui/research/{CVE}", "/ui/xss",
                     "/ui/kb", "/ui/reports"):
            r = self._get(path)
            self.assertEqual(r.status_code, 200, path)
            t = r.text.lower()
            # NOTE: the dashboard-wide convention embeds ?api_key= in links
            # (pre-existing build_url behaviour); beyond that, no credential
            # material may appear.
            for banned in ("openrouter", "sk-or-", "OPENROUTER_API_KEY",
                           "traceback", env_path.lower()):
                self.assertNotIn(banned.lower(), t, f"{path} leaks {banned!r}")

    def test_error_pages_are_generic(self):
        r = self._get("/ui/research/not-a-cve")
        self.assertEqual(r.status_code, 400)
        self.assertIn("error-panel", r.text)
        self.assertNotIn("Traceback", r.text)
        self.assertNotIn("/opt/watch", r.text)

    def test_pagination_preserves_filters(self):
        r = self._get("/ui/research", q="responsive", page=1, limit=10)
        self.assertEqual(r.status_code, 200)
        # the active filter survives re-render (form value + count line)
        self.assertIn('name="q" value="responsive"', r.text)
        self.assertIn(CVE, r.text)


class TestResearchUiPolish(unittest.TestCase):
    """Stage D5 polish: real-data presentation details (no data-contract change)."""

    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    def test_dashboard_xss_status_breakdown_humanized(self):
        r = self._get("/")
        self.assertEqual(r.status_code, 200)
        # raw snake_case status tokens must not leak into the research strip
        self.assertNotIn("research_candidate:", r.text)
        self.assertNotIn("insufficient_evidence:", r.text)
        # human-readable breakdown of the 3 real persisted candidates
        self.assertIn("research candidate:", r.text)
        self.assertIn("insufficient evidence:", r.text)
        # real persisted counts on the strip (4 CVEs / 3 XSS / 1 KB / 1 report)
        for needle in (">4<", ">3<", ">1<"):
            self.assertIn(needle, r.text)

    def test_research_detail_nuclei_scannable(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertEqual(r.status_code, 200)
        # persisted decision rendered as a chip (existing badge-sm class)
        self.assertIn('<span class="badge-sm">GOOD_CANDIDATE</span>', r.text)
        # persisted booleans rendered as yes/no, never Python True/False
        self.assertIn("semantic=yes", r.text)
        self.assertIn("template=yes", r.text)
        self.assertNotIn("semantic=True", r.text)
        self.assertNotIn("template=True", r.text)

    def test_report_detail_download_prominent(self):
        r = self._get(f"/ui/reports/{CVE}")
        self.assertEqual(r.status_code, 200)
        # primary download action kept as escaped-text view (no HTML rendering)
        self.assertIn("Download .md", r.text)
        self.assertIn('class="btn-primary"', r.text)
        self.assertIn("<pre", r.text)
        self.assertNotIn("|safe", r.text)


if __name__ == "__main__":
    unittest.main()
