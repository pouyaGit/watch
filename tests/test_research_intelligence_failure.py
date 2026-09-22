"""AUTONOMOUS RESEARCH INTELLIGENCE v1 — Phase 12 failure / recovery.

Every failure condition must fail HONESTLY: classified error, no fake
research result, no fake memory, no fake recommendation, no silent paid
downgrade — and where safe, deterministic degradation with the
degradation itself recorded.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from backend.research_agents.capabilities import capability_for
from backend.research_agents.intelligence.learning import extract
from backend.research_agents.intelligence.memory import (
    MemoryStore, MemoryUnavailable,
)
from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    AnalysisUnavailable, AgentWorker, FixtureObservations, RuntimeConfig,
    llm_analysis,
)
from backend.research_agents.runtime_store import RuntimeStore, utcnow

KEY = "sk-or-...ARI-FAIL"


def _job(tag: str = "", **over) -> ResearchJob:
    base = dict(
        id="job-fail" + (f"-{tag}" if tag else ""),
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


def _envelope(response=None, error=None):
    return {"response": response, "error": error,
            "telemetry": {"attempts": 1}, "_exception": None}


def _response():
    return {"summary": "parameter inventory",
            "insights": [{"insight_code": "PARAM_INVENTORY",
                          "text": "parameter p present"}],
            "recommendations": [{"recommendation_code": "NEXT_OBSERVATION",
                                 "text": "observe rendering for p"}]}


class _EnvBase(unittest.TestCase):
    def setUp(self):
        self._old_key = os.environ.get("OPENROUTER_API_KEY")
        os.environ["OPENROUTER_API_KEY"] = KEY
        self._old_mode = os.environ.pop("WATCH_AGENT_LLM_MODE", None)
        self._old_model = os.environ.pop("OPENROUTER_MODEL", None)
        self._old_base = os.environ.pop("OPENROUTER_BASE_URL", None)
        self.dir = tempfile.mkdtemp(prefix="ari-fail-",
                                    dir=os.environ.get("TMPDIR", "/tmp"))
        self.store = RuntimeStore(self.dir)
        self.memory = MemoryStore(self.store.base)

    def tearDown(self):
        for name, old in (("OPENROUTER_API_KEY", self._old_key),
                          ("WATCH_AGENT_LLM_MODE", self._old_mode),
                          ("OPENROUTER_MODEL", self._old_model),
                          ("OPENROUTER_BASE_URL", self._old_base)):
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old

    def _llm_failure(self, side_effect=None, envelope=None, config_extra=None):
        """llm_analysis under a failing fake provider -> AnalysisUnavailable."""
        cap = capability_for("XSS")
        cfg = RuntimeConfig(execution_mode="fixture",
                            llm_provider_kind="OPENROUTER",
                            worker_id="w-fail", **(config_extra or {}))
        provider = mock.Mock()
        if side_effect is not None:
            provider.complete_with_status.side_effect = side_effect
        else:
            provider.complete_with_status.return_value = envelope
        with mock.patch("ai.providers.provider_registry.select_provider",
                        return_value=provider):
            with self.assertRaises(AnalysisUnavailable) as ctx:
                llm_analysis(cfg, cap, _job(), _rows(), [], None)
        return str(ctx.exception)

    def _run(self, job, *, list_kb=None, patches=(), config_extra=None):
        self.store.enqueue(job)
        all_patches = list(patches)
        if list_kb is not None:
            all_patches.append(mock.patch("backend.research_data.list_kb",
                                          side_effect=list_kb))
        started = []
        try:
            for p in all_patches:
                p.start()
                started.append(p)
            worker = AgentWorker(
                config=RuntimeConfig(execution_mode="fixture",
                                     worker_id="w-fail",
                                     **(config_extra or {})),
                store=self.store,
                observations=FixtureObservations({job.id: _rows(5)}),
                llm_enabled=False,
            )
            worker.run(max_jobs=1)
        finally:
            for p in started:
                p.stop()
        return self.store.get(job.id)


class TestProviderFailures(_EnvBase):
    """12.1–12.7: OpenRouter/transport/schema conditions, classified."""

    def test_openrouter_unavailable_is_classified(self):
        msg = self._llm_failure(
            side_effect=RuntimeError("connection refused: network down"))
        self.assertTrue(msg.startswith("llm_"), msg)
        self.assertIn("provider_unavailable", msg)

    def test_timeout_is_classified(self):
        msg = self._llm_failure(
            side_effect=RuntimeError("request timed out after 120s"))
        self.assertIn("llm_timeout", msg)

    def test_rate_limit_is_classified(self):
        msg = self._llm_failure(
            side_effect=RuntimeError("HTTP 429 rate limited by router"))
        self.assertIn("llm_rate_limit", msg)

    def test_malformed_response_is_classified(self):
        msg = self._llm_failure(
            envelope=_envelope(response={"insights": "not-a-list"},
                               error={"error": "invalid provider response",
                                      "kind": "malformed"}))
        self.assertIn("llm_", msg)

    def test_schema_failure_is_classified(self):
        msg = self._llm_failure(
            envelope=_envelope(
                response=None,
                error={"error": "schema failure: provider content failed "
                                "the advisory validator",
                       "kind": "schema"}))
        self.assertIn("llm_schema_failure", msg)

    def test_empty_response_is_classified(self):
        msg = self._llm_failure(
            envelope=_envelope(response=None,
                               error={"error": "empty response from provider",
                                      "kind": "empty"}))
        self.assertIn("llm_empty_response", msg)

    def test_context_limit_fails_before_any_provider_call(self):
        cap = capability_for("XSS")
        cfg = RuntimeConfig(execution_mode="fixture",
                            llm_provider_kind="OPENROUTER",
                            worker_id="w1", context_max_chars=40)
        factory = mock.Mock()
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=factory):
            with self.assertRaises(AnalysisUnavailable) as ctx:
                llm_analysis(cfg, cap, _job(), _rows(), [], None)
        self.assertIn("context_too_large", str(ctx.exception))
        factory.assert_not_called()

    def test_provider_failure_writes_no_result(self):
        """Failed LLM analysis never yields a persisted result/fake memory."""
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        provider = mock.Mock()
        provider.complete_with_status.side_effect = RuntimeError(
            "rate limited 429")
        patches = [
            mock.patch("ai.providers.provider_registry.select_provider",
                       return_value=provider),
            mock.patch("backend.research_data.list_kb",
                       side_effect=lambda q="", limit=100: _kb()),
        ]
        started = []
        try:
            self.store.enqueue(job)
            for p in patches:
                p.start()
                started.append(p)
            worker = AgentWorker(
                config=RuntimeConfig(execution_mode="fixture",
                                     worker_id="w-fail",
                                     llm_provider_kind="OPENROUTER"),
                store=self.store,
                observations=FixtureObservations({job.id: _rows(5)}),
                llm_enabled=True,
            )
            worker.run(max_jobs=1)
        finally:
            for p in started:
                p.stop()
        after = self.store.get(job.id)
        self.assertNotEqual(after.status, JobStatus.COMPLETED.value)
        self.assertIsNone(self.store.get_result(job.id))
        # activity honestly records the failure attempts
        actions = {a["action"] for a in self.store.list_activity(limit=200)}
        self.assertIn("job_failed", actions)


class TestIntelligenceDegradation(_EnvBase):
    """12.8–12.11: intelligence stores fail -> honest, bounded degrade."""

    def test_knowledge_store_unavailable_degrades_honestly(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")

        def broken(q="", limit=100):
            raise RuntimeError("ResearchDataError: disk gone")

        status = self._run(job, list_kb=broken)
        self.assertEqual(status.status, JobStatus.COMPLETED.value)
        rows = self.store.list_activity(limit=200)
        ks = [a for a in rows if a["action"] == "knowledge_selected"]
        self.assertTrue(ks)
        self.assertIn("unavailable", ks[-1]["detail"])
        result = self.store.get_result(job.id)
        self.assertEqual(result.structured.get("knowledge_considered"), [])

    def test_research_memory_unavailable_degrades_honestly(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        patcher = mock.patch.object(
            MemoryStore, "query",
            side_effect=MemoryUnavailable("memory store unavailable: "
                                          "OSError"))
        status = self._run(job, list_kb=lambda q="", limit=100: _kb(),
                           patches=[patcher])
        self.assertEqual(status.status, JobStatus.COMPLETED.value)
        rows = self.store.list_activity(limit=200)
        mr = [a for a in rows if a["action"] == "memory_retrieved"]
        self.assertTrue(mr)
        self.assertIn("unavailable", mr[-1]["detail"])
        result = self.store.get_result(job.id)
        self.assertTrue(any("memory_retrieved" in e
                            for e in result.structured["intelligence_errors"]))

    def test_prior_research_retrieval_failure_degrades_honestly(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        patcher = mock.patch(
            "backend.research_agents.runtime.find_related_research",
            side_effect=OSError("similarity index unreadable"))
        status = self._run(job, list_kb=lambda q="", limit=100: _kb(),
                           patches=[patcher])
        self.assertEqual(status.status, JobStatus.COMPLETED.value)
        rows = self.store.list_activity(limit=200)
        pr = [a for a in rows if a["action"] == "prior_research_matched"]
        self.assertTrue(pr)
        self.assertIn("unavailable", pr[-1]["detail"])
        result = self.store.get_result(job.id)
        self.assertTrue(any("prior_research" in e
                            for e in result.structured["intelligence_errors"]))

    def test_persistence_failure_after_gate_is_honest_and_partial(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        patcher = mock.patch.object(
            MemoryStore, "append",
            side_effect=MemoryUnavailable("memory store unavailable: ENOSPC"))
        status = self._run(job, list_kb=lambda q="", limit=100: _kb(),
                           patches=[patcher])
        self.assertEqual(status.status, JobStatus.COMPLETED.value)
        result = self.store.get_result(job.id)
        # recommendations themselves persisted with the result (not faked
        # away), while the memory write failure is recorded honestly
        self.assertTrue(result.structured["research_recommendations"])
        self.assertTrue(any("recommendation_memory" in e
                            for e in result.structured["intelligence_errors"]))
        rows = self.store.list_activity(limit=200)
        ml = [a for a in rows if a["action"] == "memory_learned"]
        self.assertTrue(ml)
        self.assertIn("failed", " ".join(a["detail"] for a in ml))
        # nothing was written to the memory store (no fake memory)
        self.assertEqual(self.memory.heads(), [])


class TestPartialLearning(_EnvBase):
    """12.12: partial/broken learning input -> no fabricated memory."""

    def test_extract_with_empty_analysis_fabricates_nothing(self):
        job = _job()
        cap = capability_for("XSS")
        from backend.research_agents.runtime import CaseDecision
        items = extract(
            job=job, capability=cap,
            decision=CaseDecision(False, "evidence_threshold_not_met", None),
            analysis={}, observations=[], knowledge=[], case_id="")
        self.assertTrue(all(i.state != "VERIFIED" for i in items))
        # no hypothesis was provided -> no rejected hypothesis invented
        self.assertFalse(any(i.kind == "rejected_hypothesis"
                             for i in items))
        # every produced item still has provenance
        for item in items:
            self.assertTrue(item.provenance.get("job_id"))
            self.assertTrue(item.provenance.get("source"))

    def test_learning_crash_leaves_job_completed_and_recorded(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        patcher = mock.patch(
            "backend.research_agents.runtime.learn_from_job",
            side_effect=RuntimeError("learning exploded"))
        status = self._run(job, list_kb=lambda q="", limit=100: _kb(),
                           patches=[patcher])
        self.assertEqual(status.status, JobStatus.COMPLETED.value)
        result = self.store.get_result(job.id)
        # result exists (job work was real) and the learning failure is
        # visible in honest errors — no fake memory, no fake learning
        self.assertIsNotNone(result)
        self.assertTrue(any("memory_learned" in e
                            for e in result.structured["intelligence_errors"]))
        # no LEARNED memory was fabricated — only independently generated
        # recommendation memory (a separate honest stage) may exist
        for item in self.memory.heads():
            self.assertEqual(item.provenance.get("source"),
                             "recommendation_engine")
        self.assertFalse(any(i.kind in ("hypothesis", "rejected_hypothesis",
                                        "confirmed_historical_result",
                                        "negative_evidence")
                             for i in self.memory.heads()))
        rows = self.store.list_activity(limit=200)
        ml = [a for a in rows if a["action"] == "memory_learned"]
        self.assertTrue(ml)
        self.assertIn("failed", ml[-1]["detail"])


if __name__ == "__main__":
    unittest.main()
