"""AUTONOMOUS RESEARCH INTELLIGENCE v1 — Phase 9 SOC intelligence UI.

Proves the SOC actually EXPOSES the intelligence layer from persisted
state: agent page (memory/hypotheses/rejected/knowledge/activity),
case page (structured-research-v2 block + gate), knowledge page usage
records, and intelligence activity rows — with no secrets in payloads
and no fabricated rows.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    AgentWorker, FixtureObservations, RuntimeConfig,
)
from backend.research_agents.runtime_store import RuntimeStore, utcnow

TEMPLATES = (Path(__file__).resolve().parents[1] / "web" / "templates")
KEY = "sk-or-...ARI-SOC"


def _job(tag: str = "", **over) -> ResearchJob:
    base = dict(
        id="job-soc" + (f"-{tag}" if tag else ""),
        candidate_id="c", category="XSS",
        endpoint="https://t.example/x", parameter="q", priority_score=10,
        status=JobStatus.RUNNING.value, assigned_agent="xss-agent",
        created_at=utcnow(), updated_at=utcnow(), agent_category="XSS",
        program="p1", subdomain="t.example", url="https://t.example/x",
        mission="reflected-input-review",
        authorization_ref="watch:scope:p1/t.example",
        execution_mode="production",
    )
    base.update(over)
    return ResearchJob(**base)


def _rows(n: int = 5) -> list[dict]:
    return [{"source": "http", "ref": str(i),
             "url": f"https://t.example/x?p={i}", "params": ["p"],
             "status": 200, "title": "x"} for i in range(n)]


def _kb():
    return {"items": [{"knowledge_id": "kb-1",
                       "title": "Reflected XSS in query widgets",
                       "summary": "xss patterns", "topic": "XSS",
                       "tags": ["xss"], "source_url": ""}],
            "total": 1, "page": 1, "page_size": 100, "pages": 1}


class TestSOCIntelligenceExposure(unittest.TestCase):
    """One deterministic case-producing run feeds every SOC surface."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ari-soc-",
                                   dir=os.environ.get("TMPDIR", "/tmp"))
        cls._old_runtime_dir = os.environ.get("WATCH_AGENT_RUNTIME_DIR")
        cls._old_key = os.environ.get("OPENROUTER_API_KEY")
        os.environ["WATCH_AGENT_RUNTIME_DIR"] = cls.dir
        os.environ["OPENROUTER_API_KEY"] = KEY
        os.environ.pop("WATCH_AGENT_LLM_MODE", None)
        os.environ.pop("OPENROUTER_MODEL", None)
        os.environ.pop("OPENROUTER_BASE_URL", None)

        cls.store = RuntimeStore(cls.dir)
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        cls.store.enqueue(job)
        cls.job = job
        with mock.patch("backend.research_data.list_kb",
                        side_effect=lambda q="", limit=100: _kb()):
            worker = AgentWorker(
                config=RuntimeConfig(execution_mode="fixture",
                                     worker_id="w-soc"),
                store=cls.store,
                observations=FixtureObservations({job.id: _rows(5)}),
                llm_enabled=False,
            )
            worker.run(max_jobs=1)
        cls.status = cls.store.get(job.id)
        cls.result = cls.store.get_result(job.id)
        cls.cases = cls.store.list_cases()
        cls.case = next((c for c in cls.cases
                         if c.get("job_id") == job.id), None)

    @classmethod
    def tearDownClass(cls):
        for name, old in (("WATCH_AGENT_RUNTIME_DIR", cls._old_runtime_dir),
                          ("OPENROUTER_API_KEY", cls._old_key)):
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old

    def test_run_produced_a_real_case_and_result(self):
        self.assertEqual(self.status.status, JobStatus.COMPLETED.value)
        self.assertIsNotNone(self.result)
        self.assertIsNotNone(self.case)

    def test_agent_page_intelligence_payload(self):
        from backend.soc.agents import _agent_intelligence
        intel = _agent_intelligence(self.store, "XSS", "xss-agent")
        self.assertTrue(intel["available"])
        self.assertGreater(intel["memory_by_state"]["total"], 0)
        self.assertTrue(intel["hypotheses"] or intel["memory_recent"])
        self.assertTrue(intel["knowledge_recent"])
        self.assertTrue(intel["recommendations"])
        actions = {a["action"]
                   for a in intel["recent_research_activity"]}
        self.assertTrue(actions & {"memory_retrieved",
                                   "knowledge_selected",
                                   "prior_research_matched",
                                   "memory_learned",
                                   "recommendation_generated"})
        self.assertEqual(intel["intelligence_errors"], [])
        blob = json.dumps(intel, default=str)
        self.assertNotIn(KEY, blob)

    def test_agent_detail_template_exposes_intelligence(self):
        source = (TEMPLATES / "soc" / "agent_detail.html").read_text(
            encoding="utf-8")
        self.assertIn("Research intelligence", source)
        self.assertIn("memory_by_state", source)
        self.assertIn("rejected_hypotheses", source)
        self.assertIn("recent_research_activity", source)

    def test_case_page_research_intel_block(self):
        from backend.soc import cases as soc_cases
        self.assertIsNotNone(self.case)
        detail = soc_cases.case_detail(self.case["id"])
        self.assertIsNotNone(detail)
        intel = detail["research_intel"]
        self.assertEqual(intel["contract"], "structured-research-v2")
        self.assertTrue(intel["evidence_gate"]["authoritative"])
        self.assertTrue(intel["lineage_digest"])
        self.assertTrue(intel["knowledge_considered"])
        self.assertIsInstance(intel["research_recommendations"], list)
        self.assertIsInstance(intel["negative_evidence"], list)
        self.assertIsInstance(intel["evidence_missing"], list)
        blob = json.dumps(detail, default=str)
        self.assertNotIn(KEY, blob)

    def test_case_detail_template_exposes_intel(self):
        source = (TEMPLATES / "soc" / "case_detail.html").read_text(
            encoding="utf-8")
        self.assertIn("Research intelligence", source)
        self.assertIn("research_intel.evidence_gate", source)
        self.assertIn("research_intel.knowledge_considered", source)
        self.assertIn("research_intel.research_recommendations", source)

    def test_knowledge_page_usage_contract(self):
        # payload side: usage index over real knowledge_use rows
        from backend.research_agents.intelligence.knowledge_intel import (
            usage_index,
        )
        rows = self.store.list_knowledge_use()
        self.assertTrue(rows)
        idx = usage_index(rows)
        self.assertIn("kb-1", idx)
        self.assertGreaterEqual(idx["kb-1"]["uses"], 1)
        self.assertIn(self.job.id, idx["kb-1"]["jobs"])
        # template side: usage columns/sections exist
        kb_source = (TEMPLATES / "kb.html").read_text(encoding="utf-8")
        self.assertIn("Agent uses", kb_source)
        kbd_source = (TEMPLATES / "kb_detail.html").read_text(encoding="utf-8")
        self.assertIn("Agent research usage", kbd_source)
        self.assertIn("Research contexts", kbd_source)

    def test_intelligence_activity_visible_in_soc_activity(self):
        from backend.soc.activity import activity_payload
        # isolate from live attack-surface/Mongo aggregates; the runtime
        # activity slice under test comes from the runtime store directly
        with mock.patch(
                "backend.research_agents.service.agents_payload",
                return_value={"agents": [], "records": []}):
            payload = activity_payload()
        blob = json.dumps(payload, default=str)
        for action in ("memory_retrieved", "knowledge_selected",
                       "prior_research_matched", "memory_learned",
                       "recommendation_generated"):
            self.assertIn(action, blob, action)
        self.assertNotIn(KEY, blob)

    def test_runtime_audit_lineage_is_reconstructable(self):
        events = self.store.audit_events(limit=500)
        intel_events = [e for e in events
                        if str(e.get("event", "")).startswith(
                            "intelligence_")]
        stages = {e["event"] for e in intel_events}
        for stage in ("intelligence_memory_retrieved",
                      "intelligence_knowledge_selected",
                      "intelligence_prior_research_matched",
                      "intelligence_context_assembled",
                      "intelligence_memory_learned",
                      "intelligence_recommendation_generated",
                      "intelligence_lineage_recorded"):
            self.assertIn(stage, stages, stage)
        # every intelligence event carries the job id (lineage join key)
        for event in intel_events:
            self.assertEqual(event.get("job_id"), self.job.id)
        blob = json.dumps(intel_events, default=str)
        self.assertNotIn(KEY, blob)
        self.assertNotIn("sk-or-", blob)


if __name__ == "__main__":
    unittest.main()
