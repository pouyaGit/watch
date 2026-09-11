"""
tests/test_xss_presentation.py — Stage D9 XSS candidate semantics tests.

Semantics + presentation only. No matching/scoring changes, no R15-R22
changes, no network, no LLM, no Nuclei, no active validation, no browser,
no findings/alerts, no verifier behaviour changes.
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

XSS_ID = "xss-60edf609e21c6b41"

FORBIDDEN_UPPER = (
    "VULNERABLE",
    "VERIFIED",
    "EXPLOITED",
    "FINDING",
)


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


class TestClassifyKnowledgePattern(unittest.TestCase):
    def test_real_corpus_candidate_is_knowledge_pattern(self):
        from backend.xss_presentation import classify_xss_presentation
        payload = json.loads(
            Path(f"/opt/watch/ai_data/research/xss/{XSS_ID}.json").read_text(
                encoding="utf-8"
            )
        )
        # Real artifact carries no explicit target association.
        for key in ("program", "target", "asset", "program_id", "target_id",
                    "asset_id", "target_program", "target_asset",
                    "monitored_program"):
            self.assertNotIn(key, payload)
        result = classify_xss_presentation(payload)
        self.assertEqual(result["presentation_type"], "KNOWLEDGE_PATTERN")
        self.assertEqual(result["label"], "KNOWLEDGE PATTERN — NOT TARGET VALIDATED")
        self.assertEqual(result["scope"], "Generic XSS knowledge pattern")
        self.assertEqual(result["target"], "No target associated")
        self.assertFalse(result["target_association"])
        self.assertEqual(result["validation_state"], "NOT_TESTED")

    def test_cve_and_kb_text_never_imply_target(self):
        from backend.xss_presentation import classify_xss_presentation
        payload = {
            "candidate_id": "xss-aaaaaaaaaaaaaaaa",
            "query": "CVE-2024-1234 reflected XSS",
            "references": ["kb-0958da2bb9935000"],
            "source_evidence": [{"knowledge_id": "kb-0958da2bb9935000"}],
            "vulnerability_pattern": "CVE-2024-1234 pattern per kb-0958da2bb9935000",
        }
        result = classify_xss_presentation(payload)
        self.assertEqual(result["presentation_type"], "KNOWLEDGE_PATTERN")
        self.assertFalse(result["target_association"])

    def test_no_program_fabricated(self):
        from backend.xss_presentation import classify_xss_presentation
        result = classify_xss_presentation({"candidate_id": "xss-bbbbbbbbbbbbbbbb"})
        self.assertEqual(result["target"], "No target associated")

    def test_target_candidate_only_with_explicit_association(self):
        from backend.xss_presentation import classify_xss_presentation
        result = classify_xss_presentation(
            {"candidate_id": "xss-cccccccccccccccc", "program": "example-prog"}
        )
        self.assertEqual(result["presentation_type"], "TARGET_RESEARCH_CANDIDATE")
        self.assertEqual(result["label"], "TARGET RESEARCH CANDIDATE — NOT VERIFIED")
        self.assertEqual(result["scope"], "Target-specific research candidate")
        self.assertTrue(result["target_association"])
        self.assertEqual(result["target"], "example-prog")
        self.assertEqual(result["validation_state"], "NOT_VERIFIED")
        # Empty strings do not count as association.
        empty = classify_xss_presentation(
            {"candidate_id": "xss-dddddddddddddddd", "program": "   "}
        )
        self.assertEqual(empty["presentation_type"], "KNOWLEDGE_PATTERN")


class TestPresentationUiApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    def test_detail_page_knowledge_pattern_labels(self):
        r = self._get(f"/ui/xss/{XSS_ID}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("KNOWLEDGE PATTERN", r.text)
        self.assertIn("KNOWLEDGE PATTERN — NOT TARGET VALIDATED", r.text)
        self.assertNotIn("TARGET RESEARCH CANDIDATE", r.text)
        self.assertIn("Generic XSS knowledge pattern", r.text)
        self.assertIn("No target associated", r.text)
        self.assertIn("Not target-specific", r.text)
        self.assertIn("Not tested", r.text)
        self.assertIn("NOT TESTED", r.text)
        self.assertIn(
            "This record describes reusable security knowledge. "
            "It does NOT indicate an XSS finding on any monitored program.",
            r.text,
        )

    def test_detail_page_makes_no_finding_claims(self):
        import re
        r = self._get(f"/ui/xss/{XSS_ID}")
        self.assertEqual(r.status_code, 200)
        # Negations ("NOT VERIFIED", "NOT TESTED", "NOT ... FINDING") are
        # scope disclaimers, not claims — strip them before asserting.
        cleaned = r.text
        for negation in ("NOT VERIFIED", "NOT_VERIFIED", "NOT TESTED",
                         "NOT_TESTED", "NOT TARGET VALIDATED",
                         "NOT A PRODUCTION FINDING", "NOT PRODUCTION FINDINGS",
                         "NOT indicate an XSS finding"):
            cleaned = cleaned.replace(negation, "")
        for token in FORBIDDEN_UPPER:
            self.assertNotIn(token, cleaned)

    def test_list_page_cards(self):
        r = self._get("/ui/xss")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Knowledge Patterns", r.text)
        self.assertIn("Target Research Candidates", r.text)
        self.assertIn("KNOWLEDGE PATTERN", r.text)
        self.assertIn("NOT TARGET VALIDATED", r.text)

    @mock.patch("backend.dashboard.global_counts")
    @mock.patch("backend.dashboard.program_rows")
    @mock.patch("backend.dashboard.latest_runs")
    @mock.patch("backend.dashboard.recent_changes")
    def test_dashboard_counts_generic_separately(
        self, recent, latest, rows, counts
    ):
        counts.return_value = {"programs": 1, "subdomains": 1, "live": 1,
                               "http": 1, "urls": 1, "endpoints": 1,
                               "params": 1, "fresh_http_24h": 0}
        rows.return_value = []
        latest.return_value = []
        recent.return_value = []
        r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Knowledge Patterns", r.text)
        self.assertIn("Target Research Candidates", r.text)

    def test_api_exposes_presentation_metadata(self):
        r = self._get("/api/xss/candidates/xss-60edf609e21c6b41")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        # Existing fields preserved (compatibility).
        for key in ("candidate_id", "status", "query", "confidence", "disclaimer"):
            self.assertIn(key, body)
        self.assertEqual(body["presentation_type"], "KNOWLEDGE_PATTERN")
        self.assertEqual(body["scope"], "Generic XSS knowledge pattern")
        self.assertFalse(body["target_association"])
        self.assertEqual(body["validation_state"], "NOT_TESTED")
        self.assertIn("presentation", body)
        self.assertEqual(body["presentation"]["label"],
                         "KNOWLEDGE PATTERN — NOT TARGET VALIDATED")

    def test_api_list_presentation_counts(self):
        r = self._get("/api/xss/candidates", limit=500)
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("presentation_counts", body)
        counts = body["presentation_counts"]
        self.assertIn("KNOWLEDGE_PATTERN", counts)
        self.assertIn("TARGET_RESEARCH_CANDIDATE", counts)
        self.assertEqual(counts["TARGET_RESEARCH_CANDIDATE"], 0)
        self.assertGreaterEqual(counts["KNOWLEDGE_PATTERN"], 1)

    def test_hostile_text_still_escaped(self):
        hostile = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            xss = td / "xss"
            xss.mkdir(parents=True)
            (xss / f"{XSS_ID}.json").write_text(json.dumps({
                "candidate_id": XSS_ID, "status": "RESEARCH_CANDIDATE",
                "query": hostile, "test_idea": hostile,
                "vulnerability_pattern": hostile,
                "program": hostile,
                "disclaimer": hostile,
            }))
            from backend import research_data as rd
            with mock.patch.object(rd, "XSS_DIR", xss):
                r = self._get(f"/ui/xss/{XSS_ID}")
                self.assertEqual(r.status_code, 200)
                self.assertNotIn(hostile, r.text)
                self.assertIn("&lt;script&gt;", r.text)
                # Explicit program value is shown but escaped.
                self.assertIn("Target-specific research candidate", r.text)
                self.assertIn("TARGET RESEARCH CANDIDATE — NOT VERIFIED", r.text)

    def test_no_forbidden_subsystems_imported(self):
        import ast
        # Strict for the new D9 module: stdlib-only, no network/LLM/Nuclei.
        text = (Path("/opt/watch") / "backend/xss_presentation.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(text)
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    modules.add(node.module.split(".")[0])
        self.assertLessEqual(modules, {"typing", "__future__"},
                             f"xss_presentation imports: {sorted(modules)}")
        # Touched read/UI layers: no execution or provider calls.
        # (Pre-existing urllib/fastapi imports for URL building are not
        # live network activity; what matters is no calls are made.)
        for rel in ("backend/xss_presentation.py",
                    "backend/research_data.py",
                    "backend/routers/research.py",
                    "backend/routers/research_pages.py"):
            lowered = (Path("/opt/watch") / rel).read_text(
                encoding="utf-8"
            ).lower()
            for banned in ("nuclei.execute", "openrouter.ai", "playwright",
                           "selenium", "llm_provider", "verify_target",
                           "urlopen(", "requests.get(", "httpx.get(",
                           "socket.create_connection", "subprocess.",
                           "webdriver"):
                self.assertNotIn(banned, lowered, f"{rel} mentions {banned}")


if __name__ == "__main__":
    unittest.main()
