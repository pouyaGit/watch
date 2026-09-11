"""tests/test_product_api.py — Stage R28.1 product API tests.

Focused coverage: v1 response schema, explicit internal→public mapping,
auth gating, list/detail/summary/status endpoints, filters, pagination,
deterministic ordering, v1 error contract, secret hygiene, OpenAPI surface,
CLI projection, UI link section, and compatibility of every R25.2–R26.3
rule set (no formula changes by this stage).
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.schemas.product_api import (
    PRODUCT_API_VERSION,
    ResearchOpportunityResponse,
    opportunity_response,
    product_error,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
DELL_LEAD = "rl-af7ecfba1a86fc83"

REQUIRED_FIELDS = {
    "opportunity_id", "lead_id", "cve_id", "program",
    "opportunity_class", "money_score", "money_priority", "confidence",
    "evidence_quality", "estimated_minutes", "current_status",
    "recommended_action", "why_now", "why_valuable", "blockers",
    "next_step", "research_status", "outcome_status", "session_status",
    "research_only", "api_version",
}

FORBIDDEN_TOKENS = (
    "payout", "bounty", "reward", "target_url",
    "production_finding", "OPENROUTER", "MONGO", "mongodb://",
    "mongodb+srv://",
)

FORBIDDEN_FIELDS = {
    "payout", "bounty", "reward", "target_url", "ip", "domain",
    "credentials", "http_response", "exploit_command",
    "execution_command", "production_finding",
}


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


class TestSchema(unittest.TestCase):
    def test_required_fields_present(self):
        from backend import product_api
        item = product_api.build_product_opportunities()[0]
        self.assertTrue(REQUIRED_FIELDS.issubset(set(item.keys())),
                        f"missing: {REQUIRED_FIELDS - set(item.keys())}")

    def test_api_version_and_research_only(self):
        from backend import product_api
        for item in product_api.build_product_opportunities():
            self.assertEqual(item["api_version"], PRODUCT_API_VERSION)
            self.assertTrue(item["research_only"])

    def test_extra_fields_rejected(self):
        from backend import product_api
        item = dict(product_api.build_product_opportunities()[0])
        item["anything_new"] = 1
        with self.assertRaises(ValueError):
            ResearchOpportunityResponse(**item)

    def test_forbidden_fields_rejected(self):
        from backend import product_api
        item = dict(product_api.build_product_opportunities()[0])
        for field in FORBIDDEN_FIELDS:
            with self.subTest(field=field):
                payload = dict(item)
                payload[field] = "x"
                with self.assertRaises(ValueError):
                    ResearchOpportunityResponse(**payload)

    def test_no_forbidden_fields_in_contract(self):
        fields = set(ResearchOpportunityResponse.model_fields)
        lowered = {f.lower() for f in fields}
        for token in ("payout", "bounty", "reward", "target_url", "ip",
                      "domain", "credential", "response", "command",
                      "finding"):
            self.assertFalse([f for f in lowered if token in f],
                             f"forbidden token in schema: {fields}")

    def test_error_contract_shape(self):
        body = product_error("NOT_FOUND", "research opportunity not found")
        self.assertEqual(
            set(body.keys()), {"api_version", "error", "research_only"})
        self.assertEqual(body["error"]["code"], "NOT_FOUND")
        self.assertTrue(body["research_only"])
        for code in ("INVALID_REQUEST", "NOT_FOUND", "UNAUTHORIZED",
                     "INTERNAL_READ_ERROR"):
            self.assertEqual(product_error(code, "m")["error"]["code"], code)

    def test_error_rejects_unknown_code(self):
        with self.assertRaises(ValueError):
            product_error("TEAPOT", "m")

    def test_explicit_mapping_drops_internal_fields(self):
        from backend import research_opportunities
        internal = research_opportunities.build_opportunities()[0]
        public = ResearchOpportunityResponse(
            **{k: v for k, v in internal.items()
               if k in REQUIRED_FIELDS}).model_dump(mode="json")
        for dropped in ("confidence_score", "value_score", "effort_score",
                        "risk_score", "subscores", "acceptance_rate",
                        "wasted_rate", "efficiency_ratio", "rule_version",
                        "task_id", "queue_id"):
            self.assertNotIn(dropped, public)


class TestMapping(unittest.TestCase):
    def test_opportunity_response_passthrough(self):
        from backend import research_action_queue
        from backend import research_opportunities
        opportunity = research_opportunities.build_opportunities()[0]
        action = research_action_queue.build_action_queue()[0]
        public = opportunity_response(opportunity, action)
        ResearchOpportunityResponse(**public)
        self.assertEqual(public["lead_id"], opportunity["lead_id"])
        self.assertEqual(public["money_score"], 53)
        self.assertEqual(public["opportunity_class"], "BLOCKED")
        self.assertEqual(public["recommended_action"], "VERIFY_ASSET_MATCH")
        self.assertEqual(public["api_version"], "v1")
        self.assertTrue(public["research_only"])


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    # -- auth ---------------------------------------------------------
    def test_auth_required(self):
        for path in ("/api/v1/opportunities",
                     "/api/v1/opportunities/summary",
                     "/api/v1/research/status",
                     f"/api/v1/opportunities/{DELL_LEAD}"):
            with self.subTest(path=path):
                r = self.client.get(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)
                else:
                    self.assertIn(r.status_code, (200, 404))

    # -- list ---------------------------------------------------------
    def test_list_shape(self):
        body = self._get("/api/v1/opportunities").json()
        self.assertEqual(self._get("/api/v1/opportunities").status_code, 200)
        for field in ("api_version", "research_only", "total", "offset",
                      "limit", "items"):
            self.assertIn(field, body)
        self.assertEqual(body["api_version"], "v1")
        self.assertTrue(body["research_only"])
        self.assertEqual(body["total"], 2)
        self.assertLessEqual(body["limit"], 100)

    def test_list_real_corpus(self):
        items = self._get("/api/v1/opportunities").json()["items"]
        rows = {(i["cve_id"], i["program"]): i for i in items}
        for key in ((CVE, "dell"), (CVE, "indeed")):
            item = rows[key]
            self.assertEqual(item["money_score"], 53)
            self.assertEqual(item["money_priority"], "P3_MEDIUM")
            self.assertEqual(item["opportunity_class"], "BLOCKED")
            self.assertEqual(item["recommended_action"], "VERIFY_ASSET_MATCH")
            self.assertEqual(item["confidence"], "HIGH")
            self.assertTrue(item["research_only"])
            self.assertEqual(item["api_version"], "v1")

    def test_deterministic_ordering(self):
        first = self._get("/api/v1/opportunities").json()["items"]
        second = self._get("/api/v1/opportunities").json()["items"]
        self.assertEqual(first, second)
        self.assertEqual([i["program"] for i in first], ["dell", "indeed"])

    def test_filters(self):
        body = self._get("/api/v1/opportunities", cve=CVE).json()
        self.assertEqual(body["total"], 2)
        body = self._get("/api/v1/opportunities", program="dell").json()
        self.assertEqual(body["total"], 1)
        body = self._get("/api/v1/opportunities",
                         **{"class": "BLOCKED"}).json()
        self.assertEqual(body["total"], 2)
        body = self._get("/api/v1/opportunities",
                         **{"class": "HIGH_VALUE"}).json()
        self.assertEqual(body["total"], 0)
        body = self._get("/api/v1/opportunities",
                         action="VERIFY_ASSET_MATCH").json()
        self.assertEqual(body["total"], 2)
        body = self._get("/api/v1/opportunities", status="BLOCKED").json()
        self.assertEqual(body["total"], 2)

    def test_pagination(self):
        body = self._get("/api/v1/opportunities", limit=1).json()
        self.assertEqual(body["total"], 2)
        self.assertEqual(len(body["items"]), 1)
        body = self._get("/api/v1/opportunities", limit=100,
                         offset=1).json()
        self.assertEqual(len(body["items"]), 1)
        self.assertEqual(body["items"][0]["program"], "indeed")

    def test_min_money_score(self):
        body = self._get("/api/v1/opportunities",
                         min_money_score=53).json()
        self.assertEqual(body["total"], 2)
        body = self._get("/api/v1/opportunities",
                         min_money_score=54).json()
        self.assertEqual(body["total"], 0)
        body = self._get("/api/v1/opportunities",
                         min_money_score=101).json()
        self.assertEqual(body["total"], 0)

    def test_malformed_cve(self):
        r = self._get("/api/v1/opportunities", cve="not-a-cve")
        self.assertEqual(r.status_code, 400)
        body = r.json()
        self.assertEqual(body["api_version"], "v1")
        self.assertEqual(body["error"]["code"], "INVALID_REQUEST")
        self.assertTrue(body["research_only"])

    # -- detail -------------------------------------------------------
    def test_detail(self):
        r = self._get(f"/api/v1/opportunities/{DELL_LEAD}")
        self.assertEqual(r.status_code, 200)
        item = r.json()
        self.assertEqual(item["lead_id"], DELL_LEAD)
        self.assertEqual(item["money_score"], 53)
        self.assertTrue(REQUIRED_FIELDS.issubset(set(item.keys())))

    def test_detail_malformed(self):
        r = self._get("/api/v1/opportunities/not-a-lead")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["error"]["code"], "NOT_FOUND")

    def test_detail_unknown(self):
        r = self._get("/api/v1/opportunities/rl-ffffffffffffffff")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["error"]["code"], "NOT_FOUND")

    # -- summary / status ---------------------------------------------
    def test_summary(self):
        body = self._get("/api/v1/opportunities/summary").json()
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["by_class"], {"BLOCKED": 2})
        self.assertEqual(body["by_action"], {"VERIFY_ASSET_MATCH": 2})
        self.assertEqual(body["by_status"], {"BLOCKED": 2})
        self.assertEqual(len(body["top_opportunities"]), 2)
        self.assertEqual(body["api_version"], "v1")
        self.assertTrue(body["research_only"])

    def test_research_status(self):
        body = self._get("/api/v1/research/status").json()
        self.assertEqual(body["product_api_version"], "v1")
        self.assertTrue(body["research_only"])
        self.assertEqual(body["opportunity_count"], 2)
        self.assertEqual(body["blocked_count"], 2)
        self.assertEqual(body["ready_count"], 0)
        self.assertEqual(body["in_progress_count"], 0)
        self.assertEqual(body["completed_count"], 0)
        self.assertTrue(body["evidence_available"])
        self.assertFalse(body["outcomes_available"])
        self.assertFalse(body["sessions_available"])
        blob = json.dumps(body)
        lowered = blob.lower()
        for token in ("openrouter", "mongo", "model", "key", "uri",
                      "dellnetworking", "dellservervr", "hiringlab"):
            self.assertNotIn(token, lowered)

    # -- safety -------------------------------------------------------
    def test_no_write_endpoints(self):
        params = {"api_key": API_KEY} if API_KEY else {}
        for method in ("post", "put", "patch", "delete"):
            with self.subTest(method=method):
                r = getattr(self.client, method)(
                    "/api/v1/opportunities", params=params)
                self.assertIn(r.status_code, (401, 404, 405))
        r = self.client.post("/api/v1/research/status", params=params)
        self.assertIn(r.status_code, (401, 404, 405))

    def test_no_payout_or_target_vocabulary(self):
        blob = json.dumps(
            self._get("/api/v1/opportunities").json()).lower()
        for token in FORBIDDEN_TOKENS:
            self.assertNotIn(token, blob)
        # exploit *commands* are forbidden; the bare R15/R21 signal words
        # ("public proof-of-concept available", "exploit available") are
        # legitimate existing research vocabulary, not execution language.
        for token in ("curl ", "nuclei ", "msfconsole", "nmap ",
                      "http://", "https://", "bash ", "sh -c"):
            self.assertNotIn(token, blob)
        self.assertNotIn("vulnerable", blob)
        self.assertNotIn("confirmed", blob)

    def test_openapi_exposes_v1(self):
        spec = self.client.get("/openapi.json").json()
        paths = spec.get("paths", {})
        for path in ("/api/v1/opportunities",
                     "/api/v1/opportunities/{lead_id}",
                     "/api/v1/opportunities/summary",
                     "/api/v1/research/status"):
            self.assertIn(path, paths)
        detail = paths["/api/v1/opportunities"]["get"]
        blob = json.dumps(detail).lower()
        self.assertIn("read-only research intelligence", blob)
        self.assertIn("does not perform security testing", blob)


class TestCli(unittest.TestCase):
    def _run(self, argv):
        from ai.research_cli import main
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_human_output(self):
        code, out, _ = self._run(["product", "opportunities"])
        self.assertEqual(code, 0)
        self.assertIn("PRODUCT OPPORTUNITIES", out)
        self.assertIn("#1 BLOCKED", out)
        self.assertIn("CVE-2026-1557 → dell", out)
        self.assertIn("Money: 53 / P3", out)
        self.assertIn("Confidence: HIGH", out)
        self.assertIn("Action: VERIFY_ASSET_MATCH", out)
        self.assertIn("Next:", out)
        self.assertIn("Confirm affected component/plugin presence.", out)
        self.assertIn("PRODUCT OPPORTUNITIES: 2", out)
        lowered = out.lower()
        for token in ("vulnerab", "exploit", "payout", "bounty"):
            self.assertNotIn(token, lowered)

    def test_json_and_filters(self):
        code, out, _ = self._run(["product", "opportunities", "--json"])
        self.assertEqual(code, 0)
        items = json.loads(out)
        self.assertEqual(len(items), 2)
        self.assertTrue(REQUIRED_FIELDS.issubset(set(items[0].keys())))
        self.assertEqual(items[0]["api_version"], "v1")
        code, out, _ = self._run([
            "product", "opportunities", "--program", "dell", "--json"])
        self.assertEqual(len(json.loads(out)), 1)
        code, out, _ = self._run([
            "product", "opportunities", "--cve", "CVE-2024-0001"])
        self.assertEqual(code, 0)
        self.assertIn("none", out)

    def test_validation_still_works(self):
        code, out, _ = self._run(["product", "validation", "--json"])
        self.assertEqual(code, 0)
        self.assertIn("product_decision", json.loads(out))


class TestUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_product_api_panel(self):
        r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertIn("PRODUCT API", r.text)
        self.assertIn("API v1", r.text)
        self.assertIn("Read-only", r.text)
        self.assertIn("Research Intelligence", r.text)
        self.assertIn("/docs", r.text)
        self.assertIn("/openapi.json", r.text)


class TestCompatibility(unittest.TestCase):
    def test_money_and_upstream_rules_unchanged(self):
        from ai.knowledge import daily_research
        from ai.knowledge import economics
        from ai.knowledge import opportunity
        from ai.knowledge import opportunity_action
        self.assertEqual(economics.MONEY_W_VALUE, 0.55)
        self.assertEqual(economics.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(economics.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(economics.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(economics.RULE_VERSION, "r25-1")
        self.assertEqual(opportunity.OPPORTUNITY_RULE_VERSION, "r26-1")
        self.assertEqual(opportunity_action.ACTION_RULE_VERSION, "r26-2")
        self.assertEqual(daily_research.WORKFLOW_VERSION, "r26-3")

    def test_corpus_values_unchanged(self):
        from backend import research_action_queue
        from backend import research_calibration
        from backend import research_economics
        economics = research_economics.build_economics()
        self.assertEqual([e["money_score"] for e in economics], [53, 53])
        actions = research_action_queue.build_action_queue()
        self.assertTrue(all(a["recommended_action"] == "VERIFY_ASSET_MATCH"
                            for a in actions))
        report = research_calibration.build_report()
        self.assertEqual(report["recommendation"], "INSUFFICIENT_DATA")
        self.assertTrue(report["weights_unchanged"])

    def test_no_execution_tokens(self):
        for rel in ("ai/schemas/product_api.py",
                    "backend/product_api.py",
                    "backend/routers/product_api.py"):
            source = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            for token in ("import subprocess", "subprocess.",
                          "import socket", "socket.",
                          "import requests", "requests.",
                          "import httpx", "httpx.",
                          "import openai", "import anthropic",
                          "from ai.llm", "nuclei.", "Popen(",
                          "selenium", "playwright", "os.system(",
                          "urlopen"):
                self.assertNotIn(token, source,
                                 f"{token} found in {rel}")

    def test_product_api_version_independent(self):
        from ai.schemas.product_api import PRODUCT_API_VERSION
        self.assertEqual(PRODUCT_API_VERSION, "v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
