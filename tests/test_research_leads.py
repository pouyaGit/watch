"""tests/test_research_leads.py — Stage R21 actionable research leads tests.

Deterministic, offline, read-only tests for the research-lead projection:
lead ids, R15-R18 composition, positive/UNKNOWN reason behaviour, R18
blocker propagation, next-step selection, the strong CVE-2026-1557
candidate, task association, API auth/pagination, HTML escaping,
research-only wording, a no-network/no-subprocess/no-LLM source scan and
idempotent output. No LLM, no Nuclei, no network, no Mongo writes.
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
ALLOWED_STATUSES = {"RESEARCH_LEAD", "RESEARCH_BLOCKED", "RESEARCH_COMPLETED"}
ALLOWED_NEXT = {
    "START_RESEARCH", "REVIEW_ASSET_MATCH", "WAIT_FOR_MORE_EVIDENCE",
    "RESEARCH_COMPLETED",
}
FORBIDDEN = ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING")


def _weak_item():
    return {
        "cve": "CVE-2024-5376", "program": "dell",
        "queue_id": "rq-aaaaaaaaaaaaaaaa", "priority_class": "LOW_RESEARCH",
        "priority_score": 10, "relevance": "LOW", "relevance_score": 5,
        "blockers": ["affected plugin not observed"], "unknown_factors": [],
    }


def _weak_intel():
    return {
        "exploitability": {
            "public_poc": "unknown", "exploit_available": "unknown",
            "authentication_required": "unknown",
            "user_interaction_required": "unknown",
            "exploit_complexity": "unknown",
        },
        "relevance": [
            {"program": "dell", "reasons": ["technology match: dell"],
             "matched_assets": []}
        ],
    }


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)


class TestLeadId(unittest.TestCase):
    def test_deterministic(self):
        from backend.research_leads import lead_id_for, LEAD_ID_RE
        first = lead_id_for(CVE, "dell")
        self.assertTrue(LEAD_ID_RE.match(first))
        self.assertEqual(first, lead_id_for(CVE, "dell"))

    def test_distinct_per_program_and_cve(self):
        from backend.research_leads import lead_id_for
        self.assertNotEqual(lead_id_for(CVE, "dell"), lead_id_for(CVE, "indeed"))
        self.assertNotEqual(
            lead_id_for(CVE, "dell"), lead_id_for("CVE-2024-5376", "dell"))


class TestDeterministicOrdering(unittest.TestCase):
    def test_rank_order_matches_r18(self):
        from backend import research_data, research_leads
        queue = research_data.list_research_queue(limit=100)["items"]
        leads = research_leads.list_leads(limit=100)["items"]
        self.assertEqual(
            [(i["cve"], i["program"]) for i in queue],
            [(i["cve_id"], i["program"]) for i in leads])


class TestComposition(unittest.TestCase):
    def test_strong_candidate_fields(self):
        from backend.research_leads import list_leads
        leads = [l for l in list_leads(cve=CVE)["items"] if l["program"] == "dell"]
        self.assertEqual(len(leads), 1)
        lead = leads[0]
        self.assertEqual(lead["queue_id"], "rq-075e9ef25c8f94a7")
        self.assertEqual(lead["priority_score"], 80)
        self.assertEqual(lead["priority_level"], "CRITICAL_RESEARCH")
        self.assertEqual(lead["relevance_score"], 20)
        self.assertEqual(lead["relevance_level"], "LOW")
        self.assertEqual(lead["rule_version"], "r21-1")
        self.assertIsNone(lead["task_id"])

    def test_positive_r15_reasons(self):
        from backend.research_leads import list_leads
        lead = [l for l in list_leads(cve=CVE)["items"]
                if l["program"] == "dell"][0]
        by_code = {r["code"]: r for r in lead["reasons"]}
        for code, source in (
            ("PUBLIC_POC", "exploitability"),
            ("EXPLOIT_AVAILABLE", "exploitability"),
            ("UNAUTHENTICATED", "exploitability"),
            ("NO_USER_INTERACTION", "exploitability"),
            ("LOW_ATTACK_COMPLEXITY", "exploitability"),
            ("TECHNOLOGY_OBSERVED", "relevance"),
            ("PRODUCT_MATCHED", "relevance"),
            ("CRITICAL_PRIORITY", "priority"),
        ):
            with self.subTest(code=code):
                self.assertIn(code, by_code)
                self.assertEqual(by_code[code]["source"], source)
    def test_unknown_produces_no_positive_reason(self):
        from backend.research_leads import _exploitability_reasons
        self.assertEqual(_exploitability_reasons({
            "public_poc": "unknown", "exploit_available": "unknown",
            "authentication_required": "unknown",
            "user_interaction_required": "unknown",
            "exploit_complexity": "unknown"}), [])
        self.assertEqual(_exploitability_reasons({}), [])
        self.assertEqual(_exploitability_reasons(None), [])

    def test_unknown_relevance_gives_no_reason(self):
        from backend.research_leads import _relevance_reasons
        self.assertEqual(
            _relevance_reasons({"reasons": ["keyword overlap: x"]}, []), [])

    def test_blocker_propagation(self):
        from backend.research_leads import list_leads
        lead = [l for l in list_leads(cve=CVE)["items"]
                if l["program"] == "dell"][0]
        self.assertIn("asset version unknown", lead["blockers"])
        self.assertIn("affected plugin not observed", lead["blockers"])

    def test_strong_candidate_next_step(self):
        from backend.research_leads import list_leads
        lead = [l for l in list_leads(cve=CVE)["items"]
                if l["program"] == "dell"][0]
        self.assertEqual(lead["recommended_next_step"], "START_RESEARCH")
        self.assertEqual(lead["status"], "RESEARCH_LEAD")

    def test_weak_blocked_candidate(self):
        from backend.research_leads import _build_lead
        lead = _build_lead(_weak_item(), _weak_intel(), None, None)
        self.assertEqual(lead["status"], "RESEARCH_BLOCKED")
        self.assertEqual(lead["recommended_next_step"], "REVIEW_ASSET_MATCH")

    def test_ineligible_priority_waits(self):
        from backend.research_leads import recommended_next_step
        self.assertEqual(
            recommended_next_step("INSUFFICIENT_DATA", "UNKNOWN", [], None),
            "WAIT_FOR_MORE_EVIDENCE")


class TestTaskAssociation(unittest.TestCase):
    def test_done_task_completes_lead(self):
        from backend.research_leads import _build_lead
        lead = _build_lead(_weak_item(), _weak_intel(), "rt-0123456789abcdef",
                           "DONE")
        self.assertEqual(lead["task_id"], "rt-0123456789abcdef")
        self.assertEqual(lead["status"], "RESEARCH_COMPLETED")
        self.assertEqual(lead["recommended_next_step"], "RESEARCH_COMPLETED")

    def test_blocked_task_waits(self):
        from backend.research_leads import recommended_next_step
        self.assertEqual(
            recommended_next_step("CRITICAL_RESEARCH", "LOW", [], "BLOCKED"),
            "WAIT_FOR_MORE_EVIDENCE")

class TestLeadsApi(_Base):
    def test_auth_required(self):
        self.assertEqual(
            self.client.get("/api/research/leads").status_code, 401)

    def test_list_and_detail(self):
        r = self._get("/api/research/leads")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["total"], len(body["items"]))
        lead = body["items"][0]
        self.assertIn(lead["status"], ALLOWED_STATUSES)
        self.assertIn(lead["recommended_next_step"], ALLOWED_NEXT)
        detail = self._get(f"/api/research/leads/{lead['lead_id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["lead_id"], lead["lead_id"])

    def test_detail_404(self):
        self.assertEqual(
            self._get("/api/research/leads/rl-0000000000000000").status_code,
            404)
        self.assertEqual(
            self._get("/api/research/leads/not-an-id").status_code, 404)

    def test_pagination_and_filters(self):
        total = self._get("/api/research/leads").json()["total"]
        one = self._get("/api/research/leads", limit=1).json()
        self.assertEqual(len(one["items"]), 1)
        self.assertEqual(one["total"], total)
        scoped = self._get(
            "/api/research/leads", cve=CVE, program="dell").json()
        self.assertEqual(scoped["total"], 1)
        self.assertEqual(scoped["items"][0]["program"], "dell")


class TestLeadsUi(_Base):
    def test_list_banner_and_links(self):
        r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertIn("RESEARCH LEAD", r.text)
        self.assertIn("Actionable", r.text)
        self.assertIn("Blocked", r.text)
        self.assertIn("View Research Leads", self._get("/").text)

    def test_detail_banner_and_lead(self):
        r = self._get("/api/research/leads")
        lead_id = r.json()["items"][0]["lead_id"]
        detail = self._get(f"/ui/research/leads/{lead_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("RESEARCH LEAD", detail.text)
        self.assertIn(f"/ui/research/{CVE}", detail.text)

    def test_cve_detail_exposes_lead(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research lead", r.text)
        self.assertIn("/ui/research/leads/rl-", r.text)

    def test_escaping(self):
        hostile = {
            "lead_id": "rl-0123456789abcdef",
            "cve_id": CVE, "program": "<script>alert(1)</script>",
            "queue_id": "rq-0123456789abcdef", "task_id": None,
            "priority_score": 80, "priority_level": "CRITICAL_RESEARCH",
            "relevance_score": 20, "relevance_level": "LOW",
            "exploitability_summary": "Public PoC available",
            "asset_match_summary": "<b>owned</b>",
            "reasons": [{"code": "PUBLIC_POC", "text": "Public PoC available",
                         "source": "exploitability"}],
            "blockers": [],
            "recommended_next_step": "START_RESEARCH",
            "status": "RESEARCH_LEAD", "rule_version": "r21-1",
        }
        with mock.patch("backend.research_leads.list_leads",
                         return_value={"total": 1, "offset": 0, "limit": 50,
                                       "items": [dict(hostile)]}), \
             mock.patch("backend.research_leads.leads_summary",
                         return_value={"total": 1, "actionable": 1,
                                       "blocked": 0, "completed": 0,
                                       "top": []}):
            r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("<script>alert(1)</script>", r.text)
        self.assertIn("&lt;script&gt;", r.text)

    def test_research_only_wording(self):
        data = self._get("/api/research/leads").json()
        for lead in data["items"]:
            blob = " ".join([
                lead["status"], lead["recommended_next_step"],
                *[r["code"] for r in lead["reasons"]],
                lead["exploitability_summary"], lead["asset_match_summary"],
            ]).upper()
            for word in FORBIDDEN:
                self.assertNotIn(word, blob)
        # Page framing must stay research planning, never a verdict:
        r = self._get("/ui/research/leads")
        self.assertIn("NOT VERIFIED", r.text.upper())


class TestSafetyScan(unittest.TestCase):
    def test_no_network_subprocess_llm_sources(self):
        source = (Path(__file__).resolve().parent / ".." / "backend"
                  / "research_leads.py").read_text(encoding="utf-8")
        for token in ("import socket", "import subprocess", "import urllib",
                      "import requests", "import httpx", "import llm",
                      "import openai", "import anthropic", "nuclei",
                      "requests.", "urlopen", "browser"):
            self.assertNotIn(token, source)

    def test_idempotent_output(self):
        from backend.research_leads import list_leads, leads_summary
        first, second = list_leads(), list_leads()
        self.assertEqual(
            [l["lead_id"] for l in first["items"]],
            [l["lead_id"] for l in second["items"]])
        self.assertEqual(leads_summary(), leads_summary())


if __name__ == "__main__":
    unittest.main(verbosity=2)
