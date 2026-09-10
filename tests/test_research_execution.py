"""tests/test_research_execution.py — Stage R22 Research Execution Plan tests.

Deterministic, offline, read-only. Covers plan_id, ordering, step/evidence/
unknown rules, CLI `research plan`, API auth/pagination/bounds, UI escaping,
research-only wording, no-network/no-subprocess/no-LLM scan, idempotent
projection, no-finding vocabulary, and real corpus behaviour for
CVE-2026-1557 -> dell/indeed. No network, no Nuclei, no Mongo writes.
"""
import hashlib
import io
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
PLAN_RE = re.compile(r"^r22-[0-9a-f]{16}$")
ALLOWED_STATUSES = {"RESEARCH_PLAN_READY", "RESEARCH_PLAN_BLOCKED", "RESEARCH_PLAN_COMPLETED"}
ALLOWED_STEPS = {
    "REVIEW_CVE_SUMMARY", "REVIEW_EXPLOITABILITY", "REVIEW_PUBLIC_POC",
    "REVIEW_REFERENCES", "REVIEW_TECHNOLOGY_MATCH", "REVIEW_COMPONENT_MATCH",
    "REVIEW_PARAMETER_MATCH", "REVIEW_VERSION", "REVIEW_ASSET_EVIDENCE",
    "REVIEW_RESEARCH_TASK",
}
ALLOWED_EVIDENCE = {
    "CVE_REFERENCE", "VENDOR_ADVISORY", "PUBLIC_POC", "EXPLOIT_REFERENCE",
    "AFFECTED_COMPONENT", "AFFECTED_PARAMETER", "AFFECTED_VERSION",
    "ASSET_TECHNOLOGY", "ASSET_COMPONENT", "ASSET_VERSION", "RESEARCH_TASK_CONTEXT",
}
FORBIDDEN = ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING")
FORBIDDEN_PLAN_STATUSES = {"VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING", "CONFIRMED"}
STEP_ORDER = [
    "REVIEW_CVE_SUMMARY", "REVIEW_EXPLOITABILITY", "REVIEW_PUBLIC_POC",
    "REVIEW_REFERENCES", "REVIEW_TECHNOLOGY_MATCH", "REVIEW_COMPONENT_MATCH",
    "REVIEW_PARAMETER_MATCH", "REVIEW_VERSION", "REVIEW_ASSET_EVIDENCE",
    "REVIEW_RESEARCH_TASK",
]
STEP_ORDER_INDEX = {c: i for i, c in enumerate(STEP_ORDER)}
EVIDENCE_ORDER = [
    "CVE_REFERENCE", "VENDOR_ADVISORY", "PUBLIC_POC", "EXPLOIT_REFERENCE",
    "AFFECTED_COMPONENT", "AFFECTED_PARAMETER", "AFFECTED_VERSION",
    "ASSET_TECHNOLOGY", "ASSET_COMPONENT", "ASSET_VERSION", "RESEARCH_TASK_CONTEXT",
]
EVIDENCE_ORDER_INDEX = {c: i for i, c in enumerate(EVIDENCE_ORDER)}


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)


# ---- plan_id -------------------------------------------------------------

class TestPlanId(unittest.TestCase):
    def test_deterministic(self):
        from backend.research_execution import plan_id_for, PLAN_ID_RE
        first = plan_id_for(CVE, "dell")
        self.assertTrue(PLAN_ID_RE.match(first))
        self.assertEqual(first, plan_id_for(CVE, "dell"))
        # matches r22-1 rule version
        basis = f"r22-1\n{CVE}\ndell"
        expected = "r22-" + hashlib.sha256(basis.encode()).hexdigest()[:16]
        self.assertEqual(first, expected)

    def test_distinct_per_program_and_cve(self):
        from backend.research_execution import plan_id_for
        self.assertNotEqual(plan_id_for(CVE, "dell"), plan_id_for(CVE, "indeed"))
        self.assertNotEqual(plan_id_for(CVE, "dell"), plan_id_for("CVE-2024-5376", "dell"))

    def test_deterministic_across_imports(self):
        from backend.research_execution import plan_id_for
        a = plan_id_for(CVE, "dell")
        # reload semantics: second import
        import importlib, backend.research_execution as mod
        importlib.reload(mod)
        b = mod.plan_id_for(CVE, "dell")
        self.assertEqual(a, b)

    def test_no_path_traversal_in_plan_id(self):
        from backend.research_execution import get_plan
        from backend.research_data import NotFoundError, ResearchDataError
        for bad in ("../etc/passwd", "r22-../escape", "r22-0000000000000000/../x", ""):
            with self.subTest(bad=bad):
                with self.assertRaises((NotFoundError, ResearchDataError)):
                    get_plan(bad)


# ---- deterministic ordering ----------------------------------------------

class TestDeterministicOrdering(unittest.TestCase):
    def test_rank_order_matches_r21(self):
        from backend import research_execution, research_leads
        leads = research_leads.list_leads(limit=100)["items"]
        plans = research_execution.list_plans(limit=100)["items"]
        self.assertEqual(
            [(l["cve_id"], l["program"]) for l in leads],
            [(p["cve_id"], p["program"]) for p in plans])

    def test_step_order_precedence(self):
        from backend.research_execution import list_plans
        plans = list_plans(limit=100)["items"]
        for plan in plans:
            codes = [s["code"] for s in plan["steps"]]
            indices = [STEP_ORDER_INDEX[c] for c in codes]
            self.assertEqual(indices, sorted(indices), f"steps out of order for {plan['plan_id']}")

    def test_evidence_order_precedence(self):
        from backend.research_execution import list_plans
        plans = list_plans(limit=100)["items"]
        for plan in plans:
            codes = [t["code"] for t in plan["evidence_targets"]]
            indices = [EVIDENCE_ORDER_INDEX[c] for c in codes]
            self.assertEqual(indices, sorted(indices), f"evidence out of order for {plan['plan_id']}")

    def test_build_plans_idempotent_bytes(self):
        from backend.research_execution import build_plans
        a = json.dumps(build_plans(), sort_keys=True, ensure_ascii=False)
        b = json.dumps(build_plans(), sort_keys=True, ensure_ascii=False)
        self.assertEqual(a, b)


# ---- composition: real corpus CVE-2026-1557 -> dell / indeed --------------

class TestCorpusComposition(unittest.TestCase):
    def test_strong_candidate_fields(self):
        from backend.research_execution import list_plans
        plans = [p for p in list_plans(cve=CVE)["items"] if p["program"] == "dell"]
        self.assertEqual(len(plans), 1)
        plan = plans[0]
        self.assertTrue(PLAN_RE.match(plan["plan_id"]))
        self.assertEqual(plan["cve_id"], CVE)
        self.assertEqual(plan["program"], "dell")
        self.assertEqual(plan["queue_id"], "rq-075e9ef25c8f94a7")
        self.assertEqual(plan["rule_version"], "r22-1")
        self.assertIn(plan["status"], ALLOWED_STATUSES)
        self.assertEqual(plan["status"], "RESEARCH_PLAN_READY")

    def test_indeed_also_has_plan(self):
        from backend.research_execution import list_plans
        plans = [p for p in list_plans(cve=CVE)["items"] if p["program"] == "indeed"]
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0]["status"], "RESEARCH_PLAN_READY")

    def test_public_poc_step_when_supported(self):
        from backend.research_execution import list_plans
        plan = [p for p in list_plans(cve=CVE)["items"] if p["program"] == "dell"][0]
        codes = {s["code"] for s in plan["steps"]}
        # public_poc == true for this CVE -> step must be present
        self.assertIn("REVIEW_PUBLIC_POC", codes)
        self.assertIn("REVIEW_EXPLOITABILITY", codes)
        self.assertIn("REVIEW_CVE_SUMMARY", codes)
        # evidence target too
        ev = {t["code"] for t in plan["evidence_targets"]}
        self.assertIn("PUBLIC_POC", ev)

    def test_technology_evidence_and_no_false_component_claim(self):
        from backend.research_execution import list_plans
        plan = [p for p in list_plans(cve=CVE)["items"] if p["program"] == "dell"][0]
        ev = {t["code"] for t in plan["evidence_targets"]}
        self.assertIn("ASSET_TECHNOLOGY", ev)
        # No positive component match in relevance for this corpus,
        # so component steps/targets must not be falsely claimed
        codes = {s["code"] for s in plan["steps"]}
        self.assertNotIn("REVIEW_COMPONENT_MATCH", codes)
        self.assertNotIn("ASSET_COMPONENT", ev)
        self.assertNotIn("ASSET_VERSION", ev)

    def test_unknowns_remain_explicit(self):
        from backend.research_execution import list_plans
        plan = [p for p in list_plans(cve=CVE)["items"] if p["program"] == "dell"][0]
        unknowns = plan["unknowns"]
        # version/component unknowns must be preserved, never converted to positive
        self.assertIn("asset version unknown", unknowns)
        self.assertIn("affected plugin not observed", unknowns)
        # blockers mirror queue blockers
        self.assertIn("asset version unknown", plan["blockers"])

    def test_no_vulnerable_claim_in_plan(self):
        from backend.research_execution import list_plans
        for plan in list_plans(limit=100)["items"]:
            blob = " ".join([
                plan["status"],
                plan.get("recommended_start") or "",
                *[s["code"] for s in plan["steps"]],
                *[t["code"] for t in plan["evidence_targets"]],
                *plan["unknowns"],
                *plan["blockers"],
            ]).upper()
            for word in FORBIDDEN:
                with self.subTest(word=word, plan=plan["plan_id"]):
                    self.assertNotIn(word, blob)
            self.assertNotIn(plan["status"], FORBIDDEN_PLAN_STATUSES)

    def test_recommended_start_references_emitted_step(self):
        from backend.research_execution import list_plans
        for plan in list_plans(limit=100)["items"]:
            if plan["steps"]:
                codes = {s["code"] for s in plan["steps"]}
                self.assertIn(plan["recommended_start"], codes)
            else:
                self.assertIsNone(plan["recommended_start"])

    def test_corpus_recommended_start_is_public_poc(self):
        from backend.research_execution import list_plans
        for program in ("dell", "indeed"):
            plan = [p for p in list_plans(cve=CVE)["items"] if p["program"] == program][0]
            self.assertEqual(plan["recommended_start"], "REVIEW_PUBLIC_POC")
            # steps[] display order is unchanged (CVE summary still first)
            self.assertEqual(plan["steps"][0]["code"], "REVIEW_CVE_SUMMARY")

    def test_step_codes_whitelisted(self):
        from backend.research_execution import list_plans
        for plan in list_plans(limit=100)["items"]:
            for step in plan["steps"]:
                self.assertIn(step["code"], ALLOWED_STEPS)
                self.assertIn(step["status"], {"READY", "BLOCKED", "INFORMATIONAL"})

    def test_evidence_codes_whitelisted(self):
        from backend.research_execution import list_plans
        for plan in list_plans(limit=100)["items"]:
            for target in plan["evidence_targets"]:
                self.assertIn(target["code"], ALLOWED_EVIDENCE)
                self.assertIn("description", target)
                self.assertIn("source", target)

    def test_unknown_never_becomes_positive_step(self):
        from backend.research_execution import _steps_for
        # public_poc unknown must not produce a POC step
        lead = {"lead_id": "rl-0000000000000001", "blockers": [], "task_id": None, "status": "RESEARCH_LEAD"}
        intel = {"available": True, "exploitability": {"public_poc": "unknown", "exploit_available": "unknown"}, "relevance": []}
        steps = _steps_for(lead, intel, {}, None, None)
        codes = {s["code"] for s in steps}
        self.assertNotIn("REVIEW_PUBLIC_POC", codes)

    def test_weaker_cve_does_not_create_spurious_plan(self):
        from backend.research_execution import list_plans
        # A CVE with no R18 candidate cannot yield a plan
        plans = list_plans(cve="CVE-2024-0001")["items"]
        self.assertEqual(plans, [])


# ---- recommended_start selection -------------------------------------------

class TestRecommendedStart(unittest.TestCase):
    def _plan(self, steps):
        from backend.research_execution import _recommended_start_for
        return _recommended_start_for(
            [{"code": c, "order": i + 1} for i, c in enumerate(steps)]
        )

    def test_poc_first_when_present(self):
        self.assertEqual(
            self._plan(["REVIEW_CVE_SUMMARY", "REVIEW_EXPLOITABILITY",
                        "REVIEW_PUBLIC_POC", "REVIEW_REFERENCES"]),
            "REVIEW_PUBLIC_POC")

    def test_unknown_poc_does_not_select_poc(self):
        from backend.research_execution import _steps_for, _recommended_start_for
        lead = {"lead_id": "rl-0000000000000001", "blockers": [], "task_id": None, "status": "RESEARCH_LEAD"}
        intel = {"available": True, "exploitability": {"public_poc": "unknown", "exploit_available": "unknown"}, "relevance": []}
        steps = _steps_for(lead, intel, {}, None, None)
        codes = {s["code"] for s in steps}
        self.assertNotIn("REVIEW_PUBLIC_POC", codes)
        self.assertNotEqual(_recommended_start_for(steps), "REVIEW_PUBLIC_POC")

    def test_no_poc_but_known_exploitability(self):
        from backend.research_execution import _steps_for, _recommended_start_for
        lead = {"lead_id": "rl-0000000000000002", "blockers": [], "task_id": None, "status": "RESEARCH_LEAD"}
        intel = {"available": True,
                 "exploitability": {"public_poc": "false", "authentication_required": "false",
                                    "exploit_available": "unknown"},
                 "relevance": []}
        steps = _steps_for(lead, intel, {}, None, None)
        self.assertIn("REVIEW_EXPLOITABILITY", {s["code"] for s in steps})
        self.assertNotIn("REVIEW_PUBLIC_POC", {s["code"] for s in steps})
        self.assertEqual(_recommended_start_for(steps), "REVIEW_EXPLOITABILITY")

    def test_technology_only_case(self):
        self.assertEqual(
            self._plan(["REVIEW_CVE_SUMMARY", "REVIEW_TECHNOLOGY_MATCH",
                        "REVIEW_ASSET_EVIDENCE"]),
            "REVIEW_TECHNOLOGY_MATCH")

    def test_fallback_to_cve_summary(self):
        self.assertEqual(self._plan(["REVIEW_CVE_SUMMARY"]), "REVIEW_CVE_SUMMARY")

    def test_none_when_no_steps(self):
        from backend.research_execution import _recommended_start_for
        self.assertIsNone(_recommended_start_for([]))

    def test_always_references_emitted_step_and_deterministic(self):
        from backend.research_execution import _recommended_start_for, build_plans
        import json
        for plan in build_plans():
            start = _recommended_start_for(plan["steps"])
            if plan["steps"]:
                self.assertIn(start, {s["code"] for s in plan["steps"]})
                self.assertEqual(start, plan["recommended_start"])
            else:
                self.assertIsNone(start)
        a = json.dumps(build_plans(), sort_keys=True, ensure_ascii=False)
        b = json.dumps(build_plans(), sort_keys=True, ensure_ascii=False)
        self.assertEqual(a, b)


# ---- status semantics ----------------------------------------------------

class TestStatusSemantics(unittest.TestCase):
    def test_status_derives_from_lead(self):
        from backend.research_execution import _build_plan
        base_item = {"cve": CVE, "program": "dell", "queue_id": "rq-test", "priority_score": 80, "relevance_score": 20}
        intel = {"available": True, "exploitability": {"public_poc": "true"}, "relevance": [{"program": "dell", "reasons": ["technology match: wp"], "matched_assets": ["a"], "unknown_factors": []}]}
        payload = {"research": {"references": ["https://example.com"], "affected_versions": ["1.0"]}}
        class Doc:
            components = ["ghostwriter"]
            parameters = ["page"]
        # READY lead -> READY plan
        lead = {"lead_id": "rl-aaaaaaaaaaaaaaaa", "queue_id": "rq-test", "blockers": [], "task_id": None, "status": "RESEARCH_LEAD", "priority_level": "CRITICAL_RESEARCH", "relevance_level": "LOW", "recommended_next_step": "START_RESEARCH"}
        plan = _build_plan(base_item, intel, payload, Doc(), lead)
        self.assertEqual(plan["status"], "RESEARCH_PLAN_READY")
        # BLOCKED lead -> BLOCKED plan
        lead2 = dict(lead, status="RESEARCH_BLOCKED")
        plan2 = _build_plan(base_item, intel, payload, Doc(), lead2)
        self.assertEqual(plan2["status"], "RESEARCH_PLAN_BLOCKED")
        # COMPLETED lead -> COMPLETED plan
        lead3 = dict(lead, status="RESEARCH_COMPLETED")
        plan3 = _build_plan(base_item, intel, payload, Doc(), lead3)
        self.assertEqual(plan3["status"], "RESEARCH_PLAN_COMPLETED")

    def test_no_finding_vocabulary_in_status(self):
        from backend.research_execution import PLAN_READY, PLAN_BLOCKED, PLAN_COMPLETED
        for status in (PLAN_READY, PLAN_BLOCKED, PLAN_COMPLETED):
            for word in FORBIDDEN:
                self.assertNotIn(word, status)


# ---- API -----------------------------------------------------------------

class TestPlansApi(_Base):
    def test_auth_required(self):
        self.assertEqual(self.client.get("/api/research/plans").status_code, 401)
        self.assertEqual(self.client.get("/api/research/plans/r22-0000000000000000").status_code, 401)

    def test_list_and_detail(self):
        r = self._get("/api/research/plans")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["total"], len(body["items"]))
        self.assertLessEqual(body["limit"], 100)
        plan = body["items"][0]
        self.assertIn(plan["status"], ALLOWED_STATUSES)
        self.assertTrue(PLAN_RE.match(plan["plan_id"]))
        detail = self._get(f"/api/research/plans/{plan['plan_id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["plan_id"], plan["plan_id"])

    def test_detail_404(self):
        self.assertEqual(self._get("/api/research/plans/r22-0000000000000000").status_code, 404)
        self.assertIn(self._get("/api/research/plans/not-an-id").status_code, (400, 404))

    def test_pagination_bounds(self):
        total = self._get("/api/research/plans").json()["total"]
        one = self._get("/api/research/plans", limit=1).json()
        self.assertEqual(len(one["items"]), 1)
        self.assertEqual(one["total"], total)
        capped = self._get("/api/research/plans", limit=500).json()
        self.assertLessEqual(capped["limit"], 100)
        # offset beyond total returns empty but 200
        beyond = self._get("/api/research/plans", offset=9999).json()
        self.assertEqual(beyond["items"], [])

    def test_filters(self):
        scoped = self._get("/api/research/plans", cve=CVE, program="dell").json()
        self.assertEqual(scoped["total"], 1)
        self.assertEqual(scoped["items"][0]["program"], "dell")
        # filter by lead id also works
        lead_id = self._get("/api/research/plans", cve=CVE, program="dell").json()["items"][0]["lead_id"]
        by_lead = self._get("/api/research/plans", lead=lead_id).json()
        self.assertEqual(by_lead["total"], 1)

    def test_plans_before_cve_route(self):
        # /api/research/plans must not be captured as /api/research/{cve}
        r = self._get("/api/research/plans")
        self.assertEqual(r.status_code, 200)
        self.assertIn("total", r.json())

    def test_no_traversal_via_plan_id(self):
        for bad in ("r22-../../etc/passwd", "r22-0000000000000000/../secret"):
            r = self._get(f"/api/research/plans/{bad}")
            self.assertIn(r.status_code, (400, 404))


# ---- CLI -----------------------------------------------------------------

class TestResearchPlanCli(unittest.TestCase):
    def _run(self, argv):
        from ai.research_cli import main
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_plan_help(self):
        from ai.research_cli import build_parser
        parser = build_parser()
        # --help exits via SystemExit(0); capture
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(buf):
                parser.parse_args(["research", "plan", "--help"])
        self.assertEqual(cm.exception.code, 0)
        # also verify main path renders plan help via direct invoke
        import subprocess, sys
        result = subprocess.run([sys.executable, "-m", "ai.research_cli", "research", "plan", "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("plan", (result.stdout + result.stderr).lower())

    def test_plan_lists(self):
        code, out, _ = self._run(["research", "plan"])
        self.assertEqual(code, 0)
        self.assertIn("Research Execution Plan", out)
        self.assertIn("RESEARCH_PLAN_READY", out)

    def test_plan_filters(self):
        code, out, _ = self._run(["research", "plan", "--cve", CVE, "--program", "dell"])
        self.assertEqual(code, 0)
        self.assertIn(CVE, out)
        self.assertIn("dell", out)
        self.assertEqual(out.count(CVE), out.count("->") if "->" in out else out.count(CVE))

    def test_plan_json(self):
        code, out, _ = self._run(["research", "plan", "--cve", CVE, "--program", "dell", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["cve_id"], CVE)
        self.assertEqual(data[0]["program"], "dell")
        self.assertIn(data[0]["status"], ALLOWED_STATUSES)

    def test_plan_limit(self):
        code, out, _ = self._run(["research", "plan", "--limit", "1", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data), 1)

    def test_plan_lead_filter(self):
        from backend.research_execution import list_plans
        lead_id = list_plans(cve=CVE, program="dell")["items"][0]["lead_id"]
        code, out, _ = self._run(["research", "plan", "--lead", lead_id, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["lead_id"], lead_id)

    def test_legacy_research_still_requires_cve(self):
        code, out, err = self._run(["research"])
        self.assertEqual(code, 2)


# ---- UI ------------------------------------------------------------------

class TestPlansUi(_Base):
    def test_list_banner_and_links(self):
        r = self._get("/ui/research/plans")
        self.assertEqual(r.status_code, 200)
        self.assertIn("RESEARCH PLAN", r.text)
        self.assertIn("NOT VERIFIED", r.text)
        self.assertIn("Research Plans", self._get("/").text)

    def test_detail_banner_and_plan(self):
        r = self._get("/api/research/plans")
        plan_id = r.json()["items"][0]["plan_id"]
        detail = self._get(f"/ui/research/plans/{plan_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("RESEARCH PLAN", detail.text)
        self.assertIn("NOT VERIFIED", detail.text)
        self.assertIn(f"/ui/research/{CVE}", detail.text)

    def test_lead_detail_has_plan_cta(self):
        r = self._get("/api/research/leads")
        lead_id = r.json()["items"][0]["lead_id"]
        detail = self._get(f"/ui/research/leads/{lead_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("Research Execution Plan", detail.text)
        self.assertIn("/ui/research/plans/r22-", detail.text)

    def test_cve_detail_exposes_plan(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research Execution Plan", r.text)
        self.assertIn("/ui/research/plans/r22-", r.text)

    def test_escaping(self):
        hostile = {
            "plan_id": "r22-0123456789abcdef",
            "lead_id": "rl-0123456789abcdef",
            "cve_id": CVE, "program": "<script>alert(1)</script>",
            "queue_id": "rq-0123456789abcdef", "task_id": None,
            "priority_score": 80, "relevance_score": 20,
            "status": "RESEARCH_PLAN_READY",
            "steps": [{"order": 1, "code": "REVIEW_CVE_SUMMARY", "title": "Review CVE summary", "purpose": "x", "source": "research/cve", "status": "READY"}],
            "evidence_targets": [],
            "unknowns": ["<b>owned</b>"],
            "blockers": [],
            "recommended_start": "REVIEW_CVE_SUMMARY",
            "rule_version": "r22-1",
            "metadata": {"priority_level": "CRITICAL_RESEARCH", "relevance_level": "LOW", "recommended_next_step": "START_RESEARCH", "lead_status": "RESEARCH_LEAD"},
        }
        with mock.patch("backend.research_execution.list_plans",
                         return_value={"total": 1, "offset": 0, "limit": 50, "items": [dict(hostile)]}), \
             mock.patch("backend.research_execution.plans_summary",
                         return_value={"total": 1, "ready": 1, "blocked": 0, "completed": 0, "top": []}):
            r = self._get("/ui/research/plans")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("<script>alert(1)</script>", r.text)
        self.assertIn("&lt;script&gt;", r.text)

    def test_research_only_wording(self):
        data = self._get("/api/research/plans").json()
        for plan in data["items"]:
            blob = " ".join([plan["status"], plan.get("recommended_start") or "", *[s["code"] for s in plan["steps"]]]).upper()
            for word in FORBIDDEN:
                self.assertNotIn(word, blob)
        r = self._get("/ui/research/plans")
        self.assertIn("NOT VERIFIED", r.text.upper())
        r2 = self._get("/ui/research/plans/" + data["items"][0]["plan_id"])
        self.assertIn("NOT VERIFIED", r2.text.upper())

    def test_dashboard_has_plans_kpi(self):
        r = self._get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research Plans", r.text)
        self.assertIn("/ui/research/plans", r.text)


# ---- safety: no network / subprocess / LLM / Nuclei ----------------------

class TestSafetyScan(unittest.TestCase):
    def test_no_network_subprocess_llm_sources(self):
        source = (Path(__file__).resolve().parent / ".." / "backend" / "research_execution.py").read_text(encoding="utf-8")
        for token in ("import socket", "import subprocess", "import urllib",
                      "import requests", "import httpx", "import llm",
                      "import openai", "import anthropic", "nuclei",
                      "requests.", "urlopen", "browser", "subprocess.",
                      "socket.", "NucleiRunner", "BrowserExecutor"):
            self.assertNotIn(token, source)

    def test_no_finding_vocabulary_in_source(self):
        source = (Path(__file__).resolve().parent / ".." / "backend" / "research_execution.py").read_text(encoding="utf-8")
        # The file may mention these only in comments about what NOT to use
        # Check that no plan status uses them
        self.assertNotIn('"VULNERABLE"', source)
        self.assertNotIn('"VERIFIED"', source)
        self.assertNotIn('"EXPLOITED"', source)
        self.assertIn("RESEARCH_PLAN_READY", source)

    def test_idempotent_byte_identical(self):
        from backend.research_execution import build_plans
        a = json.dumps(build_plans(), sort_keys=True, ensure_ascii=False).encode()
        b = json.dumps(build_plans(), sort_keys=True, ensure_ascii=False).encode()
        self.assertEqual(a, b)
        self.assertEqual(hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
