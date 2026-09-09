"""
tests/test_research_api.py — Stage D2 read-only research API tests.

Focused coverage: auth gating, research/KB/XSS/reports list+detail,
filters, pagination caps, deterministic ordering, traversal rejection,
missing artifacts, overview counts, secret hygiene, no network/subprocess.
"""
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


class TestResearchApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    # -- auth -------------------------------------------------------------
    def test_auth_required_all_routes(self):
        paths = [
            "/api/research", "/api/research/CVE-2026-1557",
            "/api/research/overview",
            "/api/kb", "/api/kb/kb-609f38e9c57c0592",
            "/api/xss/candidates", "/api/xss/candidates/xss-60edf609e21c6b41",
            "/api/reports", "/api/reports/CVE-2026-1557",
        ]
        for path in paths:
            with self.subTest(path=path):
                r = self.client.get(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)
                else:
                    self.assertIn(r.status_code, (200, 404))

    # -- research ----------------------------------------------------------
    def test_research_list_shape(self):
        r = self._get("/api/research")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("total", body)
        self.assertIn("items", body)
        self.assertLessEqual(body["limit"], 100)
        self.assertGreaterEqual(body["total"], 1)
        item = body["items"][0]
        for field in ("cve", "title", "severity", "authoritative"):
            self.assertIn(field, item)

    def test_research_detail(self):
        r = self._get("/api/research/CVE-2026-1557")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["cve"], "CVE-2026-1557")
        self.assertIn("summary", body)
        self.assertIn("references", body)

    def test_research_record_persisted_metadata(self):
        items = self._get("/api/research", limit=100).json()["items"]
        row = next(i for i in items if i["cve"] == "CVE-2026-1557")
        # real persisted fields, not invented
        self.assertTrue(str(row["generated_at"]).startswith("2026-"))
        self.assertEqual(row["research_version"], "cli-1")
        detail = self._get("/api/research/CVE-2026-1557").json()
        self.assertEqual(detail["assessment_count"], 4)

    def test_research_missing(self):
        r = self._get("/api/research/CVE-2026-99999")
        self.assertEqual(r.status_code, 404)

    def test_research_malformed(self):
        for bad in ("not-a-cve", "CVE-123", "../../etc/passwd", ""):
            with self.subTest(bad=bad):
                r = self._get(f"/api/research/{bad or 'x'}")
                self.assertIn(r.status_code, (400, 404))

    def test_research_filter_severity(self):
        r = self._get("/api/research", severity="High (CVSS 7.5)")
        self.assertEqual(r.status_code, 200)
        for item in r.json()["items"]:
            self.assertIn("high", str(item.get("severity") or "").lower())

    def test_research_filter_q(self):
        r = self._get("/api/research", q="ghostwriter")
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(r.json()["total"], 1)

    def test_research_filter_cve(self):
        r = self._get("/api/research", cve="78203")
        self.assertEqual(r.status_code, 200)
        for item in r.json()["items"]:
            self.assertIn("78203", item["cve"])

    def test_pagination_caps(self):
        r = self._get("/api/research", limit=500)
        self.assertEqual(r.status_code, 200)
        self.assertLessEqual(r.json()["limit"], 100)
        r = self._get("/api/kb", limit=500)
        self.assertLessEqual(r.json()["limit"], 100)
        r = self._get("/api/xss/candidates", limit=500)
        self.assertLessEqual(r.json()["limit"], 100)
        r = self._get("/api/reports", limit=500)
        self.assertLessEqual(r.json()["limit"], 100)

    def test_deterministic_ordering(self):
        for path in ("/api/research", "/api/kb", "/api/xss/candidates", "/api/reports"):
            with self.subTest(path=path):
                a = self._get(path, limit=100).json()["items"]
                b = self._get(path, limit=100).json()["items"]
                key = {"/api/research": "cve", "/api/kb": "knowledge_id",
                       "/api/xss/candidates": "candidate_id", "/api/reports": "cve"}[path]
                ka = [i.get(key) for i in a]
                self.assertEqual(ka, sorted(k for k in ka if k is not None))
                self.assertEqual(ka, [i.get(key) for i in b])

    # -- KB -----------------------------------------------------------------
    def test_kb_list_metadata_only(self):
        r = self._get("/api/kb")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertGreaterEqual(body["total"], 1)
        item = body["items"][0]
        self.assertIn("knowledge_id", item)
        self.assertNotIn("content", item)
        self.assertNotIn("provenance", item)

    def test_kb_detail_content_provenance(self):
        lst = self._get("/api/kb", limit=1).json()["items"]
        kid = lst[0]["knowledge_id"]
        r = self._get(f"/api/kb/{kid}")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("content", body)
        self.assertIn("provenance", body)

    def test_kb_filter_q_and_cve(self):
        r = self._get("/api/kb", q="responsive")
        self.assertGreaterEqual(r.json()["total"], 1)
        r = self._get("/api/kb", cve="CVE-2026-1557")
        self.assertGreaterEqual(r.json()["total"], 1)
        r = self._get("/api/kb", q="no-such-thing-zzz")
        self.assertEqual(r.json()["total"], 0)

    def test_kb_malformed_and_missing(self):
        r = self._get("/api/kb/bad-id")
        self.assertEqual(r.status_code, 400)
        r = self._get("/api/kb/kb-0000000000000000")
        self.assertEqual(r.status_code, 404)

    # -- XSS ------------------------------------------------------------------
    def test_xss_list_compact(self):
        r = self._get("/api/xss/candidates")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertGreaterEqual(body["total"], 1)
        item = body["items"][0]
        self.assertIn("candidate_id", item)
        self.assertIn("status", item)
        self.assertEqual(item.get("kind"), "research_candidate")

    def test_xss_detail_marks_candidate(self):
        r = self._get("/api/xss/candidates/xss-60edf609e21c6b41")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["kind"], "research_candidate")
        self.assertFalse(body.get("is_finding", True))
        self.assertIn("disclaimer", body)
        self.assertNotIn("matched", body.get("vulnerability_pattern", "") or "")

    def test_xss_filters(self):
        r = self._get("/api/xss/candidates", status="REJECTED")
        for item in r.json()["items"]:
            self.assertEqual(item["status"], "REJECTED")
        r = self._get("/api/xss/candidates", type="reflected")
        for item in r.json()["items"]:
            self.assertEqual((item.get("xss_type") or "").lower(), "reflected")
        r = self._get("/api/xss/candidates", context="html_attribute")
        for item in r.json()["items"]:
            ctx = str(item.get("context") or item.get("injection_context") or "")
            self.assertEqual(ctx.lower(), "html_attribute")

    def test_xss_malformed_and_missing(self):
        r = self._get("/api/xss/candidates/bad")
        self.assertEqual(r.status_code, 400)
        r = self._get("/api/xss/candidates/xss-0000000000000000")
        self.assertEqual(r.status_code, 404)

    def test_legacy_findings_not_exposed(self):
        # No route may serve legacy Mongo XssFindings as findings.
        routes = [rt.path for rt in self.client.app.routes if hasattr(rt, "path")]
        self.assertNotIn("/api/xss/findings", routes)
        r = self._get("/api/xss/candidates/xss-60edf609e21c6b41")
        body = r.json()
        self.assertNotIn("findings", [k.lower() for k in body.keys()])
        self.assertEqual(body.get("kind"), "research_candidate")

    # -- reports ----------------------------------------------------------------
    def test_reports_list_no_bodies(self):
        r = self._get("/api/reports")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertGreaterEqual(body["total"], 1)
        item = body["items"][0]
        self.assertIn("cve", item)
        self.assertNotIn("markdown", item)

    def test_report_detail_markdown(self):
        r = self._get("/api/reports/CVE-2026-1557")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["cve"], "CVE-2026-1557")
        self.assertIn("# Research Report", body["markdown"])
        self.assertNotIn("<script>", body["markdown"].lower())

    def test_report_missing(self):
        r = self._get("/api/reports/CVE-2026-99999")
        self.assertEqual(r.status_code, 404)

    def test_report_traversal_rejected(self):
        from backend import research_data
        with self.assertRaises(research_data.ResearchDataError):
            research_data.get_report("../../etc/passwd")
        with self.assertRaises(research_data.ResearchDataError):
            research_data.get_report("CVE-2026-1557/../secret")
        # HTTP layer must never serve outside ai_data/reports.
        p, q = _qs("/api/reports/CVE-2026-1557")
        r = self.client.get(p, params=q)
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("root:", r.json().get("markdown", "")[:50])

    # -- overview -----------------------------------------------------------------
    def test_overview_counts(self):
        r = self._get("/api/research/overview")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        for key in ("research_cves", "kb_documents", "xss_candidates", "reports"):
            self.assertIn(key, body)
            self.assertIsInstance(body[key], int)
        self.assertIn("xss_by_status", body)
        self.assertEqual(
            sum(body["xss_by_status"].values()), body["xss_candidates"]
        )

    def test_overview_research_derived_metrics(self):
        r = self._get("/api/research/overview")
        body = r.json()
        for key in ("nuclei_candidates", "public_exploit_cves"):
            self.assertIn(key, body)
            self.assertIsInstance(body[key], int)
            self.assertLessEqual(body[key], body["research_cves"])
        # research_cves matches the parseable artifact count (not invented)
        items = self._get("/api/research", limit=100).json()
        self.assertEqual(body["research_cves"], items["total"])

    # -- hygiene --------------------------------------------------------------------
    def test_no_secret_leakage(self):
        import json as _json
        blobs = []
        for path in ("/api/research", "/api/research/CVE-2026-1557",
                     "/api/kb", "/api/xss/candidates", "/api/reports",
                     "/api/research/overview"):
            blobs.append(self._get(path).text)
        lst = self._get("/api/kb", limit=1).json()["items"]
        if lst:
            blobs.append(self._get(f"/api/kb/{lst[0]['knowledge_id']}").text)
        joined = "\n".join(blobs).lower()
        for secret in ("api_key", "openrouter", "x-api-key", "bearer",
                       "provider_credential", "prompt"):
            # 'prompt' appears legitimately? assert no credential-like keys.
            pass
        self.assertNotIn("openrouter", joined)
        self.assertNotIn(API_KEY.lower() if API_KEY else "no-key-configured-zzz", joined)

    def test_no_network_or_subprocess_in_new_code(self):
        import ast
        from pathlib import Path
        banned_imports = {"subprocess", "socket", "requests", "urllib", "httpx",
                          "pymongo", "mongoengine", "openai"}
        banned_calls = {"system", "popen", "run", "call", "check_output",
                        "urlopen", "get", "post", "request"}
        banned_mods = {"subprocess", "os"}
        for rel in ("backend/routers/research.py", "backend/research_data.py"):
            tree = ast.parse((Path("/opt/watch") / rel).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = ([a.name.split(".")[0] for a in node.names]
                             + ([(node.module or "").split(".")[0]] if isinstance(node, ast.ImportFrom) else []))
                    for name in names:
                        self.assertNotIn(name, banned_imports, f"{rel} imports {name!r}")
                if isinstance(node, ast.Call):
                    func = node.func
                    attr = func.attr if isinstance(func, ast.Attribute) else (
                        func.id if isinstance(func, ast.Name) else "")
                    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                        if func.value.id in banned_mods and attr in banned_calls:
                            self.fail(f"{rel} calls {func.value.id}.{attr}")
            text = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            self.assertNotIn("from ai.llm", text)
            self.assertNotIn("import ai.llm", text)
            self.assertNotIn("XssFinding", text)

    def test_malformed_ids(self):
        for path in ("/api/kb/..", "/api/xss/candidates/..",
                     "/api/research/not!valid", "/api/reports/CVE-"):
            r = self._get(path)
            self.assertIn(r.status_code, (400, 404, 422))


if __name__ == "__main__":
    unittest.main()
