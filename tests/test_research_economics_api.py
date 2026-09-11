"""tests/test_research_economics_api.py — Stage R25.4 API + UI tests.

Deterministic, offline tests for the Money Score presentation layer:
key-gated API list/detail, filters, pagination caps, ordering, 404s,
research-only invariants, and the minimal leads-list/detail UI.

No network, no DNS, no LLM, no subprocess, no target interaction, no
Nuclei, no PoC execution, no 5B-5J, no findings, no alerts, no Mongo
writes, no persistence. Rendering tests use only the research leads
pages (never the dashboard root).
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
FORBIDDEN = ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING")


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


class TestEconomicsApiAuth(_Base):
    def test_auth_required(self):
        for path in ("/api/research/economics",
                     "/api/research/economics/rl-0123456789abcdef"):
            with self.subTest(path=path):
                r = self.client.get(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)
                else:
                    self.assertIn(r.status_code, (200, 404))


class TestEconomicsApiList(_Base):
    def test_list_shape(self):
        body = self._get("/api/research/economics").json()
        self.assertEqual(self._get("/api/research/economics").status_code, 200)
        for field in ("total", "offset", "limit", "items", "skipped",
                      "rule_version", "research_only"):
            self.assertIn(field, body)
        self.assertEqual(body["rule_version"], "r25-1")
        self.assertTrue(body["research_only"])
        self.assertLessEqual(body["limit"], 100)

    def test_real_corpus_values(self):
        body = self._get("/api/research/economics").json()
        self.assertEqual(body["total"], 2)
        rows = {(i["cve_id"], i["program"]): i for i in body["items"]}
        for key in ((CVE, "dell"), (CVE, "indeed")):
            item = rows[key]
            self.assertEqual(item["money_score"], 53)
            self.assertEqual(item["priority"], "P3_MEDIUM")
            self.assertEqual(item["confidence"], "HIGH")
            self.assertEqual(item["effort_estimate"], "1–2 h")
            self.assertEqual(item["recommended_action"],
                             "VERIFY_ASSET_MATCH_FIRST")
            self.assertTrue(item["research_only"])

    def test_deterministic_ordering(self):
        items = self._get("/api/research/economics", limit=100).json()["items"]
        keys = [(-i["money_score"], i["cve_id"], i["program"]) for i in items]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual([i["program"] for i in items], ["dell", "indeed"])

    def test_filters(self):
        body = self._get("/api/research/economics", cve=CVE).json()
        self.assertEqual(body["total"], 2)
        body = self._get("/api/research/economics", program="dell").json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["program"], "dell")
        body = self._get("/api/research/economics",
                         cve=CVE, program="indeed").json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["program"], "indeed")

    def test_limit_offset(self):
        body = self._get("/api/research/economics", limit=1).json()
        self.assertEqual(body["total"], 2)
        self.assertEqual(len(body["items"]), 1)
        body = self._get("/api/research/economics", limit=100,
                         offset=1).json()
        self.assertEqual(len(body["items"]), 1)
        self.assertEqual(body["items"][0]["program"], "indeed")

    def test_limit_bounded(self):
        body = self._get("/api/research/economics", limit=10000).json()
        self.assertLessEqual(body["limit"], 100)

    def test_malformed_cve(self):
        r = self._get("/api/research/economics", cve="not-a-cve")
        self.assertEqual(r.status_code, 400)

    def test_no_match(self):
        body = self._get("/api/research/economics",
                         cve="CVE-2024-0001").json()
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["items"], [])

    def test_no_payout_prediction(self):
        body = self._get("/api/research/economics", limit=100).json()
        blob = str(body).upper()
        for word in FORBIDDEN + ("PAYOUT", "$", "USD"):
            self.assertNotIn(word, blob)


class TestEconomicsApiDetail(_Base):
    def _lead_id(self):
        items = self._get("/api/research/economics").json()["items"]
        return items[0]["lead_id"]

    def test_detail_shape(self):
        item = self._get(
            f"/api/research/economics/{self._lead_id()}").json()
        for field in ("money_score", "priority", "confidence",
                      "confidence_basis", "effort", "effort_estimate",
                      "asset_match", "why_valuable", "main_blockers",
                      "recommended_action", "subscores", "evidence_summary",
                      "caps_applied", "rule_version", "research_only"):
            self.assertIn(field, item)
        self.assertEqual(item["money_score"], 53)
        self.assertTrue(item["research_only"])
        self.assertEqual(item["rule_version"], "r25-1")

    def test_detail_404(self):
        r = self._get("/api/research/economics/rl-ffffffffffffffff")
        self.assertEqual(r.status_code, 404)

    def test_detail_malformed(self):
        r = self._get("/api/research/economics/not-a-lead")
        self.assertEqual(r.status_code, 404)


class TestEconomicsUi(_Base):
    def test_leads_list_money_column(self):
        r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertIn("RESEARCH LEAD", r.text)
        self.assertIn(">Money<", r.text)
        # compact money cells for both corpus leads, money order preserved
        self.assertEqual(r.text.count("53 · P3"), 2)
        dell_pos = r.text.find(">dell<")
        indeed_pos = r.text.find(">indeed<")
        self.assertTrue(0 <= dell_pos < indeed_pos)

    def test_priority_indicator_classes(self):
        r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertIn("prio-p3", r.text)

    def test_lead_detail_economic_block(self):
        lead_id = self._get("/api/research/economics").json()["items"][0][
            "lead_id"]
        r = self._get(f"/ui/research/leads/{lead_id}")
        self.assertEqual(r.status_code, 200)
        for text in ("Economic research", "Money Score", "P3 — MEDIUM",
                     "HIGH", "1–2 h", "TECHNOLOGY ONLY", "Why valuable",
                     "Main blockers", "VERIFY_ASSET_MATCH_FIRST",
                     "Subscores", "Value 59"):
            self.assertIn(text, r.text)

    def test_lead_detail_missing_projection(self):
        hostile_lead = {
            "lead_id": "rl-0123456789abcdef",
            "cve_id": CVE, "program": "dell",
            "queue_id": "rq-0123456789abcdef", "task_id": None,
            "priority_score": 80, "priority_level": "CRITICAL_RESEARCH",
            "relevance_score": 20, "relevance_level": "LOW",
            "exploitability_summary": "Public PoC available",
            "asset_match_summary": "none",
            "reasons": [], "blockers": [],
            "recommended_next_step": "START_RESEARCH",
            "status": "RESEARCH_LEAD", "rule_version": "r21-1",
        }
        with mock.patch("backend.research_leads.get_lead",
                        return_value=dict(hostile_lead)), \
             mock.patch("backend.research_economics.get_research_economic_value",
                        side_effect=Exception("projection failed")):
            r = self._get("/ui/research/leads/rl-0123456789abcdef")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No economic projection", r.text)

    def test_empty_state(self):
        with mock.patch("backend.research_leads.list_leads",
                        return_value={"total": 0, "offset": 0, "limit": 50,
                                      "items": []}), \
             mock.patch("backend.research_leads.leads_summary",
                        return_value={"total": 0, "actionable": 0,
                                      "blocked": 0, "completed": 0,
                                      "top": []}):
            r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertIn("MONEY QUEUE: no research candidates", r.text)

    def test_ui_research_only_wording(self):
        import re
        lead_id = self._get("/api/research/economics").json()["items"][0][
            "lead_id"]
        list_html = self._get("/ui/research/leads").text
        detail_html = self._get(f"/ui/research/leads/{lead_id}").text
        # sanctioned research-only framing is present on both pages
        self.assertIn("NOT VERIFIED", list_html.upper())
        self.assertIn("NOT VERIFIED", detail_html.upper())
        # the R25.4 blocks themselves carry no verdict vocabulary: the
        # Money cells and the ECONOMIC RESEARCH panel only
        money_cells = re.findall(r"53 · P3", list_html)
        self.assertEqual(len(money_cells), 2)
        panel = detail_html.split("Economic research", 1)[1].split(
            "Why investigate", 1)[0]
        blob = " ".join([panel]).upper()
        for word in FORBIDDEN:
            self.assertNotIn(word, blob)


class TestApiSafetyScan(unittest.TestCase):
    def test_no_execution_side_effects_in_router(self):
        # scoped to the two new R25 handlers (the module docstring itself
        # documents the read-only "no subprocess/network/LLM" contract).
        import inspect
        from backend.routers import research as router_mod
        source = inspect.getsource(
            router_mod.api_research_economics)
        source += inspect.getsource(
            router_mod.api_research_economic_detail)
        for token in ("subprocess", "Popen", "requests.get", "urlopen",
                      "openai", "anthropic", "nuclei_runner", "verify_target",
                      "background_task", "store_result", "report_path"):
            self.assertNotIn(token, source)

    def test_api_reads_projection_directly(self):
        import inspect
        from backend.routers import research as router_mod
        src = inspect.getsource(router_mod.api_research_economics)
        self.assertIn("list_research_economics", src)
        self.assertNotIn("assess_economic_value", src)
        src = inspect.getsource(router_mod.api_research_economic_detail)
        self.assertIn("get_research_economic_value", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
