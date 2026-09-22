"""tests/test_research_agents.py — Research Agent Orchestration v1 tests.

Offline and deterministic: candidates and attack-surface payloads are injected
directly, so no Mongo, no network, no LLM and no target interaction are
required for the core and API tests. Covers the registry, job creation, agent
assignment, lifecycle states, evidence plans, the in-memory store, API
responses and the Command Center payload.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from config import config
from fastapi.testclient import TestClient

from backend.research_agents import service as ra
from backend.research_agents.models import (
    AGENT_STATUSES,
    JOB_STATUSES,
    RESEARCH_JOB_RULE_VERSION,
    AgentInfo,
    CandidateRef,
    JobStatus,
    ResearchResult,
    agent_category_for,
    job_id_for,
)
from backend.research_agents.orchestrator import (
    AgentOrchestrator,
    OrchestratorError,
)
from backend.research_agents.registry import (
    AgentRegistry,
    build_default_registry,
)
from backend.research_agents.repository import (
    ResearchJobStore,
    candidates_from_payload,
)

API_KEY = config().get("API_KEY", "")


def candidate(cid="asc-1", category="XSS_CANDIDATE", endpoint="/search",
              parameter="q", *, score=70, confidence="MEDIUM", method="GET",
              technology=(), program="dell", subdomain="a.dell.com"):
    return {
        "id": cid,
        "category": category,
        "endpoint": endpoint,
        "parameter": parameter,
        "method": method,
        "score": score,
        "confidence": confidence,
        "technology": list(technology),
        "reasons": ["test"],
        "program": program,
        "subdomain": subdomain,
        "url": f"{endpoint}?{parameter}=",
        "location": "query",
        "source": "watch",
    }


def surface_payload():
    by_category = {
        "XSS_CANDIDATE": 3,
        "IDOR_CANDIDATE": 5,
        "SSRF_CANDIDATE": 2,
        "FILE_UPLOAD_CANDIDATE": 1,
    }
    summary = {
        "available": True,
        "total": 3,
        "by_category": by_category,
        "by_confidence": {"LOW": 1, "MEDIUM": 2, "HIGH": 0},
        "short": {"XSS": 3, "IDOR": 5, "SSRF": 2, "UPLOAD": 1},
        "rule_version": "attack-surface-1",
    }
    return {
        "available": True,
        "rule_version": "attack-surface-1",
        "summary": summary,
        "candidates": summary,
        "discovery": {
            "domains": 1,
            "urls": 1,
            "endpoints": 3,
            "parameters": 3,
            "programs": ["dell"],
            "domain_sample": ["a.dell.com"],
        },
        "priority_queue": [
            candidate("asc-xss", "XSS_CANDIDATE", "/search", "q", score=70),
            candidate("asc-idor", "IDOR_CANDIDATE", "/api/user", "id",
                      score=100, confidence="HIGH"),
            candidate("asc-ssrf", "SSRF_CANDIDATE", "/proxy", "url",
                      score=65, confidence="MEDIUM"),
        ],
    }


class TestRegistry(unittest.TestCase):
    def test_default_registry(self):
        registry = build_default_registry()
        keys = [agent.key for agent in registry.list_agents()]
        self.assertEqual(
            keys, ["authz", "file_upload", "idor", "ssrf", "xss"]
        )
        self.assertEqual(registry.get("xss").status, "ready")
        self.assertEqual(registry.get("idor").status, "ready")
        self.assertEqual(registry.get("ssrf").status, "ready")
        self.assertEqual(registry.get("file_upload").status, "ready")
        self.assertEqual(registry.get("authz").status, "ready")

    def test_get_by_category_accepts_surface_category(self):
        registry = build_default_registry()
        self.assertEqual(registry.get_by_category("XSS_CANDIDATE").key, "xss")
        self.assertEqual(registry.get_by_category("IDOR_CANDIDATE").key, "idor")
        self.assertEqual(registry.get_by_category("ssrf").key, "ssrf")
        self.assertEqual(registry.get_by_category("xss").key, "xss")

    def test_ready_for(self):
        registry = build_default_registry()
        self.assertIsNotNone(registry.ready_for("xss"))
        self.assertIsNotNone(registry.ready_for("ssrf"))
        self.assertIsNone(registry.ready_for("unknown_category"))

    def test_analyzer_for(self):
        registry = build_default_registry()
        self.assertTrue(callable(registry.analyzer_for("xss")))
        self.assertTrue(callable(registry.analyzer_for("idor")))
        self.assertTrue(callable(registry.analyzer_for("ssrf")))
        self.assertIsNone(registry.analyzer_for("unknown_category"))

    def test_register_and_list(self):
        registry = AgentRegistry()
        registry.register(
            AgentInfo(key="custom", name="Custom Agent", category="custom",
                      status="ready"),
            analyzer=lambda ref: {},
        )
        self.assertEqual(registry.get("custom").name, "Custom Agent")
        self.assertEqual(registry.categories(), ["custom"])

    def test_register_rejects_bad_status(self):
        registry = AgentRegistry()
        with self.assertRaises(ValueError):
            registry.register(AgentInfo(key="x", name="X", category="x",
                                        status="bogus"))

    def test_agent_statuses_closed(self):
        self.assertEqual(set(AGENT_STATUSES), {"ready", "planned", "disabled"})


class TestCandidateAdapter(unittest.TestCase):
    def test_from_attack_surface_candidate_object(self):
        class Fake:
            id = "asc-obj"
            category = "XSS_CANDIDATE"
            endpoint = "/x"
            parameter = "q"
            method = "POST"
            score = 90
            confidence = "HIGH"
            technology = ("nginx",)
            reasons = ("r",)
            program = "dell"
            subdomain = "a.dell.com"
            url = "/x?q="
            location = "body"

        ref = CandidateRef.from_any(Fake())
        self.assertEqual(ref.agent_category, "xss")
        self.assertEqual(ref.priority_score, 90)
        self.assertEqual(ref.method, "POST")

    def test_from_dict(self):
        ref = CandidateRef.from_any(candidate())
        self.assertEqual(ref.id, "asc-1")
        self.assertEqual(ref.agent_category, "xss")

    def test_candidates_from_payload_limit(self):
        refs = candidates_from_payload(surface_payload(), limit=2)
        self.assertEqual([ref.id for ref in refs], ["asc-xss", "asc-idor"])

    def test_category_mapping(self):
        self.assertEqual(agent_category_for("SSRF_CANDIDATE"), "ssrf")
        self.assertEqual(agent_category_for("FILE_UPLOAD_CANDIDATE"),
                         "file_upload")


class TestJobCreation(unittest.TestCase):
    def setUp(self):
        self.orchestrator = AgentOrchestrator()

    def test_create_job_fields(self):
        job = self.orchestrator.create_job(candidate(), now="2026-09-20T00:00:00Z")
        self.assertEqual(job.status, JobStatus.NEW.value)
        self.assertEqual(job.candidate_id, "asc-1")
        self.assertEqual(job.endpoint, "/search")
        self.assertEqual(job.parameter, "q")
        self.assertEqual(job.priority_score, 70)
        self.assertEqual(job.agent_category, "xss")
        self.assertEqual(job.created_at, "2026-09-20T00:00:00Z")
        self.assertEqual(job.rule_version, RESEARCH_JOB_RULE_VERSION)

    def test_job_id_deterministic(self):
        self.assertEqual(job_id_for("asc-1", "xss"), job_id_for("asc-1", "xss"))
        self.assertNotEqual(job_id_for("asc-1", "xss"),
                            job_id_for("asc-1", "idor"))

    def test_create_job_idempotent(self):
        first = self.orchestrator.create_job(candidate())
        second = self.orchestrator.create_job(candidate())
        self.assertEqual(first.id, second.id)
        self.assertEqual(self.orchestrator.store.counts()["total"], 1)


class TestAgentAssignment(unittest.TestCase):
    def setUp(self):
        self.orchestrator = AgentOrchestrator()

    def test_xss_assignment(self):
        outcome = self.orchestrator.dispatch(candidate())
        self.assertEqual(outcome.job.assigned_agent, "XSS Research Agent")
        self.assertEqual(outcome.job.agent_category, "xss")

    def test_idor_assignment(self):
        outcome = self.orchestrator.dispatch(
            candidate("asc-2", "IDOR_CANDIDATE", "/api/user", "id")
        )
        self.assertEqual(outcome.job.assigned_agent, "IDOR Research Agent")

    def test_ssrf_assignment(self):
        outcome = self.orchestrator.dispatch(
            candidate("asc-3", "SSRF_CANDIDATE", "/proxy", "url")
        )
        self.assertEqual(outcome.job.assigned_agent, "SSRF Research Agent")
        self.assertEqual(outcome.job.agent_category, "ssrf")

    def test_unknown_category_prepared_but_unassigned(self):
        outcome = self.orchestrator.dispatch(
            candidate("asc-x", "OPEN_REDIRECT_CANDIDATE", "/go", "next")
        )
        self.assertEqual(outcome.job.assigned_agent, "")
        self.assertEqual(outcome.job.status, JobStatus.QUEUED.value)
        self.assertIn("no ready specialist agent", outcome.result.blockers[0])

    def test_evidence_plan_generated(self):
        xss = self.orchestrator.dispatch(candidate())
        self.assertEqual(
            xss.result.evidence_required,
            ("reflection confirmation", "encoding context", "execution context"),
        )
        self.assertIn("reflected parameter", xss.result.signals)
        self.assertEqual(xss.result.findings, ())
        idor = self.orchestrator.dispatch(
            candidate("asc-2", "IDOR_CANDIDATE", "/api/user", "id")
        )
        self.assertEqual(
            idor.result.evidence_required,
            ("authorization comparison", "object ownership context",
             "response difference"),
        )
        self.assertIn("numeric identifier", idor.result.signals)
        self.assertIn("API endpoint", idor.result.signals)


class TestLifecycle(unittest.TestCase):
    def setUp(self):
        self.orchestrator = AgentOrchestrator()

    def test_dispatch_reaches_waiting_evidence(self):
        outcome = self.orchestrator.dispatch(candidate())
        self.assertEqual(outcome.job.status,
                         JobStatus.WAITING_EVIDENCE.value)

    def test_transition_path(self):
        job = self.orchestrator.create_job(candidate())
        for status in (JobStatus.QUEUED.value, JobStatus.ASSIGNED.value,
                       JobStatus.RUNNING.value,
                       JobStatus.WAITING_EVIDENCE.value,
                       JobStatus.COMPLETED.value):
            job = self.orchestrator.transition(job.id, status)
            self.assertEqual(job.status, status)

    def test_illegal_transition_rejected(self):
        job = self.orchestrator.create_job(candidate())
        with self.assertRaises(OrchestratorError):
            self.orchestrator.transition(job.id, JobStatus.RUNNING.value)

    def test_unknown_job_rejected(self):
        with self.assertRaises(OrchestratorError):
            self.orchestrator.transition("rj-missing", JobStatus.QUEUED.value)

    def test_job_statuses_closed(self):
        # Agent Runtime v1 extended the vocabulary (CLAIMED lease, CANCELLED,
        # EXPIRED lease, TIMEOUT, TERMINAL_FAILED) — it stays closed.
        self.assertEqual(
            set(JOB_STATUSES),
            {"NEW", "QUEUED", "ASSIGNED", "CLAIMED", "RUNNING",
             "WAITING_EVIDENCE", "COMPLETED", "FAILED", "TIMEOUT",
             "EXPIRED", "CANCELLED", "TERMINAL_FAILED"},
        )

    def test_dispatch_idempotent(self):
        first = self.orchestrator.dispatch(candidate())
        second = self.orchestrator.dispatch(candidate())
        self.assertEqual(first.job.id, second.job.id)
        self.assertEqual(second.job.status, JobStatus.WAITING_EVIDENCE.value)
        self.assertEqual(self.orchestrator.store.counts()["total"], 1)


class TestStore(unittest.TestCase):
    def test_counts(self):
        orchestrator = AgentOrchestrator()
        orchestrator.dispatch(candidate("asc-1", "XSS_CANDIDATE"))
        orchestrator.dispatch(candidate("asc-2", "IDOR_CANDIDATE",
                                        "/api/user", "id"))
        counts = orchestrator.store.counts()
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["active"], 2)
        self.assertEqual(counts["by_status"]["WAITING_EVIDENCE"], 2)

    def test_json_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "jobs.json"
            store = ResearchJobStore(path=path)
            orchestrator = AgentOrchestrator(store=store)
            outcome = orchestrator.dispatch(candidate())
            store.save()
            self.assertTrue(path.is_file())
            reloaded = ResearchJobStore(path=path)
            self.assertEqual(reloaded.get_job(outcome.job.id).status,
                             JobStatus.WAITING_EVIDENCE.value)

    def test_in_memory_store_writes_nothing(self):
        base = Path(__file__).resolve().parents[1] / "ai_data"
        before = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        store = ResearchJobStore()
        AgentOrchestrator(store=store).dispatch(candidate())
        after = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        self.assertEqual(before, after)


class TestService(unittest.TestCase):
    def setUp(self):
        ra.reset_pipeline()

    def tearDown(self):
        ra.reset_pipeline()

    def test_bootstrap_pipeline(self):
        result = ra.bootstrap_pipeline(payload=surface_payload(),
                                       now="2026-09-20T00:00:00Z")
        self.assertTrue(result["available"])
        self.assertEqual(result["created"], 3)
        jobs = ra.list_jobs()
        self.assertEqual(jobs["counts"]["total"], 3)

    def test_bootstrap_idempotent(self):
        ra.bootstrap_pipeline(payload=surface_payload())
        second = ra.bootstrap_pipeline(payload=surface_payload())
        self.assertEqual(second["created"], 0)
        self.assertEqual(ra.list_jobs()["counts"]["total"], 3)

    def test_create_jobs_from_explicit_candidates(self):
        result = ra.create_jobs([candidate()])
        self.assertEqual(result["created"], 1)
        self.assertEqual(len(result["jobs"]), 1)

    def test_agents_payload_counts(self):
        payload = ra.agents_payload(payload=surface_payload())
        by_key = {agent["key"]: agent for agent in payload["agents"]}
        self.assertEqual(by_key["xss"]["queue"], 3)
        self.assertEqual(by_key["idor"]["queue"], 5)
        self.assertEqual(by_key["ssrf"]["queue"], 2)
        self.assertTrue(by_key["xss"]["available"])
        self.assertTrue(by_key["ssrf"]["available"])

    def test_get_job_includes_result(self):
        ra.bootstrap_pipeline(payload=surface_payload())
        job_id = ra.list_jobs()["jobs"][0]["id"]
        detail = ra.get_job(job_id)
        self.assertIn("job", detail)
        self.assertIn("result", detail)
        self.assertIsNotNone(detail["result"])

    def test_get_unknown_job_none(self):
        self.assertIsNone(ra.get_job("rj-missing"))

    def test_command_center_payload(self):
        payload = ra.command_center_payload(payload=surface_payload())
        self.assertTrue(payload["available"])
        self.assertEqual(payload["agent_count"], 5)
        self.assertGreaterEqual(payload["queue_count"], 1)
        self.assertEqual(payload["rule_version"], "research-agents-1")

    def test_empty_surface_is_honest(self):
        payload = ra.command_center_payload(
            payload={"available": False, "summary": {}, "priority_queue": []}
        )
        self.assertFalse(payload["available"])
        self.assertEqual(payload["queue"], [])
        self.assertEqual(payload["queue_count"], 0)


class TestSafety(unittest.TestCase):
    NEW_FILES = (
        "backend/research_agents/models.py",
        "backend/research_agents/repository.py",
        "backend/research_agents/registry.py",
        "backend/research_agents/orchestrator.py",
        "backend/research_agents/service.py",
        "backend/research_agents/agents/xss_agent.py",
        "backend/research_agents/agents/idor_agent.py",
        "backend/research_agents/agents/ssrf_agent.py",
        "backend/research_agents/agents/upload_agent.py",
        "backend/research_agents/agents/authz_agent.py",
        "backend/research_agents/agents/common.py",
    )

    def test_no_execution_tokens(self):
        for rel in self.NEW_FILES:
            source = (Path(__file__).resolve().parents[1] / rel).read_text(
                encoding="utf-8"
            )
            for token in ("import requests", "import httpx", "import socket",
                          "subprocess", "openai", "anthropic", "from ai.llm",
                          "urlopen", "Popen(", "selenium", "playwright",
                          "os.system(", "nuclei"):
                self.assertNotIn(token, source, f"{token} in {rel}")

    def test_no_confirm_words_in_agent_plans(self):
        orchestrator = AgentOrchestrator()
        for cat, param, endpoint in (("XSS_CANDIDATE", "q", "/search"),
                                     ("IDOR_CANDIDATE", "id", "/api/user"),
                                     ("SSRF_CANDIDATE", "url", "/proxy"),
                                     ("FILE_UPLOAD_CANDIDATE", "file",
                                      "/upload"),
                                     ("AUTHZ_CANDIDATE", "role",
                                      "/admin/users")):
            outcome = orchestrator.dispatch(
                candidate(category=cat, parameter=param, endpoint=endpoint)
            )
            blob = " ".join(outcome.result.evidence_required
                            + outcome.result.signals).lower()
            self.assertNotIn("vulnerable", blob)
            self.assertNotIn("exploitable", blob)


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def setUp(self):
        ra.reset_pipeline()

    def tearDown(self):
        ra.reset_pipeline()

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def _post(self, path, json=None, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.post(path, params=params, json=json)

    def test_auth_required(self):
        if not API_KEY:
            self.skipTest("API key not configured")
        for path in ("/api/research-agents", "/api/research/jobs"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)

    def test_agents_endpoint(self):
        with mock.patch(
            "backend.attack_surface.service.attack_surface_payload",
            return_value=surface_payload(),
        ):
            response = self._get("/api/research-agents")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["count"], 5)
        by_key = {agent["key"]: agent for agent in body["agents"]}
        self.assertEqual(by_key["idor"]["queue"], 5)

    def test_create_and_list_jobs(self):
        response = self._post("/api/research/jobs/create",
                              json={"candidates": [candidate()]})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["created"], 1)
        job_id = body["jobs"][0]["id"]

        listing = self._get("/api/research/jobs").json()
        self.assertEqual(listing["counts"]["total"], 1)
        self.assertEqual(listing["jobs"][0]["id"], job_id)

    def test_job_detail(self):
        created = self._post("/api/research/jobs/create",
                             json={"candidates": [candidate()]}).json()
        job_id = created["jobs"][0]["id"]
        detail = self._get(f"/api/research/jobs/{job_id}").json()
        self.assertEqual(detail["job"]["assigned_agent"],
                         "XSS Research Agent")
        self.assertIn("reflection confirmation",
                      detail["result"]["evidence_required"])

    def test_unknown_job_404(self):
        self.assertEqual(
            self._get("/api/research/jobs/rj-nope").status_code, 404
        )

    def test_no_write_on_get(self):
        params = {"api_key": API_KEY} if API_KEY else {}
        self.assertIn(
            self.client.post("/api/research-agents", params=params).status_code,
            (405, 401),
        )


class TestCommandCenterUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def setUp(self):
        ra.reset_pipeline()

    def tearDown(self):
        ra.reset_pipeline()

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_command_center_renders_research_agents(self):
        with mock.patch(
            "backend.routers.command_center._attack_surface_state",
            return_value=surface_payload(),
        ), mock.patch("backend.dashboard.latest_runs", return_value=[]):
            response = self._get("/ui/command")
        self.assertEqual(response.status_code, 200)
        text = response.text
        self.assertIn("Research Agents", text)
        self.assertIn("Agent status", text)
        self.assertIn("XSS Research Agent", text)
        self.assertIn("IDOR Research Agent", text)
        self.assertIn("Research queue", text)
        self.assertIn('id="research-agents"', text)
        self.assertIn("WAITING_EVIDENCE", text)
        self.assertNotIn("Vulnerable", text)
        self.assertNotIn("Exploitable", text)

    def test_command_center_empty_state(self):
        empty = {"available": False, "summary": {}, "priority_queue": []}
        with mock.patch(
            "backend.routers.command_center._attack_surface_state",
            return_value=empty,
        ), mock.patch("backend.dashboard.latest_runs", return_value=[]):
            response = self._get("/ui/command")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Research agents unavailable", response.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
