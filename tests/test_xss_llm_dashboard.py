"""
tests/test_xss_llm_dashboard.py — Stage R8 read-only LLM XSS research surface.

Covers: data-layer lookup, API success/missing/malformed/invalid/auth/
traversal, UI rendering incl. neutral absence + hostile escaping +
EVIDENCE/INFERENCE/UNKNOWN display + candidate authority, no provider
invocation, report renderer unchanged.
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
HOSTILE = "<script>alert('llm-xss')</script>"


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


def _llm_doc(candidate_id=XSS_ID, **over):
    doc = {
        "candidate_id": candidate_id,
        "status": "RESEARCH_CANDIDATE",
        "confidence": 0.9,
        "content_hash": "abc123",
        "explanation": "Supplied evidence indicates attribute breakout.",
        "likely_attack_surface": "search parameter reflected in attribute",
        "relevant_context": "quoted html attribute",
        "supporting_reasoning": ["score 11 exact type+context match"],
        "missing_evidence": ["live reflection not observed"],
        "suggested_test_idea": "Untested idea only — never executed.",
        "references_used": ["kb-0958da2bb9935000"],
        "evidence": [
            {"kind": "EVIDENCE", "text": "Reflected attribute pattern present.",
             "knowledge_ids": ["kb-0958da2bb9935000"]},
            {"kind": "INFERENCE", "text": "Likely breakable with event handler.",
             "knowledge_ids": []},
            {"kind": "UNKNOWN", "text": "Cookie theft not established.",
             "knowledge_ids": []},
        ],
        "model": "mock-model",
    }
    doc.update(over)
    return doc


class TestXssLlmDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    def _llm_dir_with(self, tmpdir, payload=None, name=None):
        from backend import research_data as rd
        llm_dir = Path(tmpdir) / "llm"
        llm_dir.mkdir(parents=True, exist_ok=True)
        if payload is not None:
            (llm_dir / f"{name or XSS_ID}.json").write_text(json.dumps(payload))
        return mock.patch.object(rd, "XSS_LLM_DIR", llm_dir)

    # -- data layer ---------------------------------------------------------
    def test_data_lookup_missing_returns_notfound(self):
        from backend import research_data as rd
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(rd, "XSS_LLM_DIR", Path(td)):
                with self.assertRaises(rd.NotFoundError):
                    rd.get_xss_llm_research(XSS_ID)
                self.assertFalse(rd.has_xss_llm_research(XSS_ID))

    def test_data_lookup_malformed_fails_safely(self):
        from backend import research_data as rd
        with tempfile.TemporaryDirectory() as td:
            llm = Path(td)
            (llm / f"{XSS_ID}.json").write_text("{not json")
            with mock.patch.object(rd, "XSS_LLM_DIR", llm):
                with self.assertRaises(rd.ResearchDataError):
                    rd.get_xss_llm_research(XSS_ID)

    def test_data_lookup_rejects_mismatch(self):
        from backend import research_data as rd
        with tempfile.TemporaryDirectory() as td:
            with self._llm_dir_with(td, _llm_doc(candidate_id="xss-aaaaaaaaaaaaaaaa")) as p:
                with p:
                    with self.assertRaises(rd.ResearchDataError):
                        rd.get_xss_llm_research(XSS_ID)

    def test_data_lookup_rejects_path_traversal(self):
        from backend import research_data as rd
        with self.assertRaises(rd.ResearchDataError):
            rd.get_xss_llm_research("../../etc/passwd")
        with self.assertRaises(rd.ResearchDataError):
            rd.get_xss_llm_research("xss-60edf609e21c6b41/../secret")

    # -- API -----------------------------------------------------------------
    def test_api_missing_result_404(self):
        from backend import research_data as rd
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(rd, "XSS_LLM_DIR", Path(td)):
                r = self._get(f"/api/xss/candidates/{XSS_ID}/llm-research")
                self.assertEqual(r.status_code, 404)

    def test_api_success_deterministic(self):
        from backend import research_data as rd
        doc = _llm_doc()
        with tempfile.TemporaryDirectory() as td:
            with self._llm_dir_with(td, doc):
                a = self._get(f"/api/xss/candidates/{XSS_ID}/llm-research")
                b = self._get(f"/api/xss/candidates/{XSS_ID}/llm-research")
                self.assertEqual(a.status_code, 200)
                self.assertEqual(a.json(), b.json())
                body = a.json()
                self.assertEqual(body["candidate_id"], XSS_ID)
                self.assertEqual(body["kind"], "llm_research")
                self.assertFalse(body["verified"])
                self.assertFalse(body.get("is_finding", True))

    def test_api_malformed_400_and_invalid_id_400(self):
        from backend import research_data as rd
        with tempfile.TemporaryDirectory() as td:
            llm = Path(td)
            (llm / f"{XSS_ID}.json").write_text("{bad")
            with mock.patch.object(rd, "XSS_LLM_DIR", llm):
                r = self._get(f"/api/xss/candidates/{XSS_ID}/llm-research")
                self.assertEqual(r.status_code, 400)
        r = self._get("/api/xss/candidates/bad-id/llm-research")
        self.assertEqual(r.status_code, 400)

    def test_api_auth_required(self):
        r = self.client.get(f"/api/xss/candidates/{XSS_ID}/llm-research")
        if API_KEY:
            self.assertEqual(r.status_code, 401)
        else:
            self.assertIn(r.status_code, (200, 404))

    # -- UI -------------------------------------------------------------------
    def test_ui_absent_state_neutral(self):
        from backend import research_data as rd
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(rd, "XSS_LLM_DIR", Path(td)):
                r = self._get(f"/ui/xss/{XSS_ID}")
                self.assertEqual(r.status_code, 200)
                self.assertIn("LLM RESEARCH", r.text)
                self.assertIn("LLM research not generated.", r.text)
                # deterministic authority banners stay prominent
                # (D9: generic pattern wording, never a target finding)
                self.assertIn("KNOWLEDGE PATTERN", r.text)
                self.assertIn("UNTESTED RESEARCH IDEA", r.text)

    def test_ui_renders_llm_panel_with_kinds(self):
        from backend import research_data as rd
        with tempfile.TemporaryDirectory() as td:
            with self._llm_dir_with(td, _llm_doc()):
                r = self._get(f"/ui/xss/{XSS_ID}")
                self.assertEqual(r.status_code, 200)
                for frag in ("LLM RESEARCH", "NOT VERIFIED", "mock-model",
                             "Supplied evidence indicates",
                             "EVIDENCE", "INFERENCE", "UNKNOWN",
                             "DETERMINISTIC CANDIDATE"):
                    self.assertIn(frag, r.text)
                # deterministic status/confidence still from candidate
                # (badge renders CANDIDATE; banner carries D9 wording)
                self.assertIn("CANDIDATE", r.text)
                self.assertIn("KNOWLEDGE PATTERN", r.text)
                self.assertIn("0.90", r.text)
                self.assertNotIn("|safe", r.text)

    def test_ui_escapes_hostile_llm_content(self):
        from backend import research_data as rd
        doc = _llm_doc(explanation=HOSTILE, suggested_test_idea=HOSTILE,
                       supporting_reasoning=[HOSTILE],
                       evidence=[{"kind": "EVIDENCE", "text": HOSTILE,
                                  "knowledge_ids": ["kb-0958da2bb9935000"]}])
        with tempfile.TemporaryDirectory() as td:
            with self._llm_dir_with(td, doc):
                r = self._get(f"/ui/xss/{XSS_ID}")
                self.assertEqual(r.status_code, 200)
                self.assertNotIn(HOSTILE, r.text)
                self.assertIn("&lt;script&gt;", r.text)

    def test_ui_malformed_llm_fails_safe(self):
        from backend import research_data as rd
        with tempfile.TemporaryDirectory() as td:
            llm = Path(td)
            (llm / f"{XSS_ID}.json").write_text("{bad")
            with mock.patch.object(rd, "XSS_LLM_DIR", llm):
                r = self._get(f"/ui/xss/{XSS_ID}")
                self.assertEqual(r.status_code, 200)
                # deterministic candidate still renders (badge text CANDIDATE)
                self.assertIn("CANDIDATE", r.text)
                self.assertIn("KNOWLEDGE PATTERN", r.text)

    # -- safety ------------------------------------------------------------------
    def test_no_provider_or_execution_imports(self):
        import ast
        for rel in ("backend/research_data.py",
                    "backend/routers/research.py",
                    "backend/routers/research_pages.py"):
            text = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mods = [a.name.split(".")[0] for a in node.names]
                    if isinstance(node, ast.ImportFrom) and node.module:
                        mods.append(node.module.split(".")[0])
                    for banned in ("subprocess", "socket", "requests",
                                   "httpx", "pymongo", "openai"):
                        self.assertNotIn(banned, mods, f"{rel} imports {banned}")
            self.assertNotIn("ai.llm", text, rel)
            self.assertNotIn("XssFinding", text, rel)
            self.assertNotIn("LLMProvider", text, rel)
            self.assertNotIn("OpenRouter", text, rel)

    def test_report_renderer_has_no_llm_section(self):
        text = (Path("/opt/watch") / "ai/reports/renderer.py").read_text(
            encoding="utf-8")
        # Renderer is CVE-scoped (R2); it must not gain an XSS LLM section.
        self.assertNotIn("LLM Research", text)
        self.assertNotIn("llm-research", text)
        self.assertNotIn("XSSLLM", text)
        self.assertNotIn("xss/llm", text)


if __name__ == "__main__":
    unittest.main()
