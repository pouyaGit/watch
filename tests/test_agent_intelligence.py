"""AI AGENT INTELLIGENCE v1 — free-only cost guard, advisory contract,
structured analysis chain, SOC exposure (Phases 1–5, 7, 9, 11–12).

Every test here is deterministic: provider calls are faked at the
``select_provider`` boundary only; the allowlist test runs the REAL
``ai.providers.context_allowlist.sanitize_provider_context``.  No test
touches the network, and no test can pass with a paid model configured.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from backend.research_agents.capabilities import capability_for
from backend.research_agents.llm_guard import (
    FREE_MODEL,
    FreeOnlyViolation,
    llm_indicator,
    llm_mode,
    resolve_free_config,
)
from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    AnalysisUnavailable,
    AgentWorker,
    FixtureObservations,
    RuntimeConfig,
    _advisory_request,
    deterministic_analysis,
    llm_analysis,
    prompt_version_for,
)
from backend.research_agents.runtime_store import RuntimeStore, utcnow

KEY = "sk-or-test-INTELLIGENCE-SENTINEL"


def _job(tag: str = "", **over) -> ResearchJob:
    base = dict(
        id="job-intel" + (f"-{tag}" if tag else ""),
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


def _rows(n: int = 3) -> list[dict]:
    return [{"source": "http", "ref": str(i),
             "url": f"https://t.example/x?p={i}", "params": ["p"],
             "status": 200, "title": "x"} for i in range(n)]


def _envelope(response=None, error=None, telemetry=None):
    return {"response": response, "error": error,
            "telemetry": telemetry or {"attempts": 1}, "_exception": None}


def _good_response():
    return {
        "summary": "parameter inventory from authorized observations",
        "insights": [{"insight_code": "PARAM_INVENTORY",
                      "text": "parameter p present on observed url"}],
        "recommendations": [{"recommendation_code": "NEXT_OBSERVATION",
                             "text": "observe response rendering for p"}],
    }


class _CapturingProvider:
    """Fake provider capturing the outbound request (no network)."""

    last_request = None

    def __init__(self, outcome=None, error=None):
        self.outcome = outcome
        self.error = error

    def complete(self, request):
        _CapturingProvider.last_request = request
        if self.error is not None:
            raise self.error
        return self.outcome


class _EnvBase(unittest.TestCase):
    def setUp(self):
        self._old_key = os.environ.get("OPENROUTER_API_KEY")
        os.environ["OPENROUTER_API_KEY"] = KEY
        self._old_mode = os.environ.pop("WATCH_AGENT_LLM_MODE", None)
        # isolate every guard-relevant env key (host .env may define them)
        self._old_env_model = os.environ.pop("OPENROUTER_MODEL", None)
        self._old_env_base = os.environ.pop("OPENROUTER_BASE_URL", None)
        self.dir = tempfile.mkdtemp(prefix="intel-",
                                    dir=os.environ.get("TMPDIR", "/tmp"))
        self.store = RuntimeStore(self.dir)
        _CapturingProvider.last_request = None

    def tearDown(self):
        if self._old_key is None:
            os.environ.pop("OPENROUTER_API_KEY", None)
        else:
            os.environ["OPENROUTER_API_KEY"] = self._old_key
        os.environ.pop("WATCH_AGENT_LLM_MODE", None)
        if self._old_mode is not None:
            os.environ["WATCH_AGENT_LLM_MODE"] = self._old_mode
        os.environ.pop("OPENROUTER_MODEL", None)
        if self._old_env_model is not None:
            os.environ["OPENROUTER_MODEL"] = self._old_env_model
        os.environ.pop("OPENROUTER_BASE_URL", None)
        if self._old_env_base is not None:
            os.environ["OPENROUTER_BASE_URL"] = self._old_env_base


class TestFreeOnlyGuard(_EnvBase):
    """Phase 1/9: the only accepted path is OpenRouter -> openrouter/free."""

    def test_free_router_accepted_exactly(self):
        cfg = resolve_free_config("OPENROUTER", "", 30)
        self.assertEqual(cfg["requested_model"], FREE_MODEL)
        self.assertEqual(FREE_MODEL, "openrouter/free")
        self.assertEqual(cfg["provider_kind"], "OPENROUTER")
        self.assertEqual(cfg["provider_label"], "OpenRouter Free")
        self.assertNotIn("api_key", cfg)
        self.assertNotIn(KEY, json.dumps(cfg))

    def test_paid_models_are_rejected(self):
        for model in ("openai/gpt-4o", "gpt-4o", "gpt-4.1",
                      "deepseek/deepseek-chat", "anthropic/claude-3.5",
                      "openai/gpt-4o-mini:free"):
            with self.assertRaises(FreeOnlyViolation, msg=model):
                resolve_free_config("OPENROUTER", model, 30)

    def test_wrong_provider_is_rejected(self):
        for kind in ("OPENAI", "MOCK", "", "openrouter/free",
                     "ROUTER"):
            with self.assertRaises(FreeOnlyViolation, msg=repr(kind)):
                resolve_free_config(kind, "", 30)

    def test_missing_key_is_rejected(self):
        os.environ.pop("OPENROUTER_API_KEY", None)
        with self.assertRaises(FreeOnlyViolation) as ctx:
            resolve_free_config("OPENROUTER", "", 30)
        self.assertEqual(ctx.exception.reason, "missing_openrouter_api_key")

    def test_modes_fail_closed(self):
        os.environ["WATCH_AGENT_LLM_MODE"] = "off"
        with self.assertRaises(FreeOnlyViolation):
            resolve_free_config("OPENROUTER", "", 30)
        os.environ["WATCH_AGENT_LLM_MODE"] = "auto-paid"
        with self.assertRaises(FreeOnlyViolation):
            llm_mode()
        os.environ["WATCH_AGENT_LLM_MODE"] = "free"
        self.assertEqual(llm_mode(), "free")
        os.environ.pop("WATCH_AGENT_LLM_MODE", None)
        self.assertEqual(llm_mode(), "free")  # default is free-only

    def test_env_paid_model_cannot_bypass(self):
        os.environ["OPENROUTER_MODEL"] = "openai/gpt-4o"
        with self.assertRaises(FreeOnlyViolation) as ctx:
            resolve_free_config("OPENROUTER", "", 30)
        self.assertIn("env_model_not_free", ctx.exception.reason)

    def test_env_base_url_must_be_openrouter(self):
        os.environ["OPENROUTER_BASE_URL"] = "https://evil.example/v1"
        with self.assertRaises(FreeOnlyViolation) as ctx:
            resolve_free_config("OPENROUTER", "", 30)
        self.assertIn("base_url_not_openrouter", ctx.exception.reason)

    def test_fallback_is_structurally_impossible(self):
        # every accepted configuration resolves to exactly the free router
        for model in ("", None, "  openrouter/free  "):
            cfg = resolve_free_config("OPENROUTER", model, 15)
            self.assertEqual(cfg["requested_model"], "openrouter/free")

    def test_indicator_never_contains_the_key(self):
        blob = json.dumps(llm_indicator())
        self.assertNotIn(KEY, blob)
        self.assertIn("openrouter/free", blob)
        self.assertTrue(llm_indicator()["enabled"])
        os.environ.pop("OPENROUTER_API_KEY", None)
        ind = llm_indicator()
        self.assertFalse(ind["enabled"])
        self.assertIn("missing_openrouter_api_key", ind.get("reason", ""))


class TestAdvisoryContract(_EnvBase):
    """Phase 4: outbound context passes the REAL R51 allowlist."""

    def test_request_passes_real_context_allowlist(self):
        from ai.providers.context_allowlist import sanitize_provider_context
        cap = capability_for("XSS")
        req = _advisory_request(cap, _job(), _rows(4),
                                [{"id": "kb1", "title": "Reflected XSS",
                                  "topic": "xss",
                                  "summary": "bounded excerpt"}],
                                deterministic_analysis(cap, _job(),
                                                       _rows(4), []),
                                prompt_version_for(cap))
        self.assertLessEqual(len(req["instruction"]), 400)
        blob = json.dumps(req, sort_keys=True, default=str)
        self.assertNotIn(KEY, blob)
        self.assertNotIn("https://", blob)   # R45: URLs never leave
        self.assertNotIn("t.example", blob)  # no hostname either
        self.assertIn("reflected-input-review", blob)  # mission present
        self.assertIn("params=[p]", blob)    # structural facts present
        bundle = sanitize_provider_context(req)   # raises on violations
        self.assertIsInstance(bundle, dict)
        self.assertIn("context", bundle)
        payload = json.dumps(req["sections"], sort_keys=True, default=str)
        self.assertLessEqual(len(payload), 4000 + 200)

    def test_context_budget_fails_closed_before_provider(self):
        cfg = RuntimeConfig(execution_mode="fixture",
                            llm_provider_kind="OPENROUTER",
                            worker_id="w1", context_max_chars=40)
        cap = capability_for("XSS")
        called = []

        def factory(kind, **opts):
            called.append(kind)
            return _CapturingProvider(_envelope(_good_response()))
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=factory):
            with self.assertRaises(AnalysisUnavailable) as ctx:
                llm_analysis(cfg, cap, _job(), _rows(), [], None)
        self.assertIn("context_too_large", str(ctx.exception))
        self.assertEqual(called, [])

    def test_request_carries_only_authorized_context(self):
        cap = capability_for("XSS")
        req = _advisory_request(cap, _job(), _rows(2), [],
                                deterministic_analysis(cap, _job(),
                                                       _rows(2), []),
                                prompt_version_for(cap))
        blob = json.dumps(req, sort_keys=True, default=str)
        self.assertIn("reflected-input-review", blob)   # mission
        self.assertIn("AUTHORIZED_OBSERVATION", blob)
        # no credentials, keys or env-var names ride along
        self.assertNotIn(KEY, blob)
        self.assertNotIn("OPENROUTER_API_KEY", blob)
        self.assertNotIn("WATCH_AGENT_LLM_MODE", blob)


class TestXSSChainWithLLM(_EnvBase):
    """Phase 6/11/12: XSS agent end-to-end through the fake-free-router."""

    def _config(self):
        return RuntimeConfig(execution_mode="fixture",
                             llm_provider_kind="OPENROUTER",
                             worker_id="w-intel")

    def test_full_chain_records_structured_analysis_and_activity(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        self.store.enqueue(job)
        provider = _CapturingProvider(_envelope(_good_response(),
                                                telemetry={"attempts": 1,
                                                           "usage": None}))
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=lambda kind, **opts: provider):
            worker = AgentWorker(
                config=self._config(), store=self.store,
                observations=FixtureObservations({job.id: _rows(5)}),
                llm_enabled=True,
            )
            worker.run(max_jobs=1)
        after = self.store.get(job.id)
        self.assertEqual(after.status, JobStatus.COMPLETED.value)
        result = self.store.get_result(job.id)
        self.assertIsNotNone(result)
        self.assertEqual(result.provider, "OPENROUTER")
        self.assertEqual(result.model, "openrouter/free")
        self.assertEqual(result.prompt_version, "xss-agent-analysis-v1")
        st = result.structured
        self.assertIn(st["verdict"],
                      ("evidence_sufficient_for_review",
                       "needs_more_observation", "insufficient_evidence"))
        self.assertEqual(st["requested_model"], "openrouter/free")
        self.assertEqual(st["reasoning_summary"],
                         "parameter inventory from authorized observations")
        actions = {a.get("action") for a in self.store.list_activity()}
        for expected in ("observations_loaded", "llm_analysis_started",
                         "llm_analysis_completed", "evidence_gate_evaluated",
                         "analysis_completed"):
            self.assertIn(expected, actions)
        # outbound request captured at the provider boundary: no secret,
        # no env, authorized context only
        req_blob = json.dumps(_CapturingProvider.last_request,
                              sort_keys=True, default=str)
        self.assertNotIn(KEY, req_blob)
        self.assertNotIn("WATCH_AGENT", req_blob)

    def test_knowledge_docs_really_read_reach_the_llm_context(self):
        """Phase 5: only actually-read knowledge may ride to the LLM, and
        the knowledge_used row must match what was sent."""
        kb = [{"id": "kb-001", "title": "Reflected XSS parameter patterns",
               "summary": "bounded excerpt about parameter reflection",
               "topic": "xss"}]
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        self.store.enqueue(job)
        provider = _CapturingProvider(_envelope(_good_response()))
        with mock.patch("backend.research_data.list_kb",
                        return_value={"items": kb, "total": 1}):
            with mock.patch("ai.providers.provider_registry.select_provider",
                            side_effect=lambda kind, **opts: provider):
                worker = AgentWorker(
                    config=self._config(), store=self.store,
                    observations=FixtureObservations({job.id: _rows(3)}),
                    llm_enabled=True,
                )
                worker.run(max_jobs=1)
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.COMPLETED.value)
        req_blob = json.dumps(_CapturingProvider.last_request,
                              sort_keys=True, default=str)
        # the excerpt and title were really sent
        self.assertIn("Reflected XSS parameter patterns", req_blob)
        self.assertIn("bounded excerpt about parameter reflection", req_blob)
        self.assertIn("KNOWLEDGE_REFERENCE", req_blob)
        # and the store records exactly those reads for this job
        used = self.store.list_knowledge_use(job_id=job.id)
        self.assertEqual(len(used), 1)
        self.assertEqual(used[0]["title"], "Reflected XSS parameter patterns")
        self.assertEqual(used[0]["document_id"], "kb-001")

    def test_llm_failure_keeps_retry_state_and_no_result(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        self.store.enqueue(job)
        provider = _CapturingProvider(error=TimeoutError("timed out"))
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=lambda kind, **opts: provider):
            worker = AgentWorker(
                config=self._config(), store=self.store,
                observations=FixtureObservations({job.id: _rows(3)}),
                llm_enabled=True,
            )
            worker.run(max_jobs=1)
        after = self.store.get(job.id)
        self.assertIn(after.status,
                      (JobStatus.QUEUED.value,
                       JobStatus.TERMINAL_FAILED.value))
        self.assertIsNone(self.store.get_result(job.id))
        actions = {a.get("action") for a in self.store.list_activity()}
        self.assertIn("llm_analysis_failed", actions)
        self.assertIn("job_failed", actions)

    def test_llm_off_still_runs_deterministic_with_no_llm_events(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        self.store.enqueue(job)
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture", worker_id="w2"),
            store=self.store,
            observations=FixtureObservations({job.id: _rows(5)}),
            llm_enabled=False,
        )
        worker.run(max_jobs=1)
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.COMPLETED.value)
        actions = {a.get("action") for a in self.store.list_activity()}
        self.assertNotIn("llm_analysis_started", actions)
        result = self.store.get_result(job.id)
        self.assertEqual(result.structured, {})
        self.assertEqual(result.prompt_version, "")


class TestSOCExposure(_EnvBase):
    """Phase 11: SOC shows truthful LLM state, never secrets."""

    def test_runtime_block_carries_llm_indicator(self):
        from backend.soc.agents import _runtime_block
        block = _runtime_block(True)
        self.assertIn("llm", block)
        self.assertEqual(block["llm"]["requested_model"], "openrouter/free")
        self.assertTrue(block["llm"]["key_configured"])
        self.assertNotIn(KEY, json.dumps(block))
        absent = _runtime_block(False)
        self.assertEqual(absent["llm"], {})

    def test_agent_records_expose_llm_last_after_job(self):
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        self.store.enqueue(job)
        provider = _CapturingProvider(_envelope(_good_response()))
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=lambda kind, **opts: provider):
            worker = AgentWorker(
                config=RuntimeConfig(execution_mode="fixture",
                                     llm_provider_kind="OPENROUTER",
                                     worker_id="w3"),
                store=self.store,
                observations=FixtureObservations({job.id: _rows(5)}),
                llm_enabled=True,
            )
            worker.run(max_jobs=1)
        # point the default store at this temp store for the SOC reader
        from backend.research_agents import runtime_store as rs
        from backend.soc.agents import _runtime_agent_records
        old = rs.default_store
        rs.default_store = lambda: self.store
        try:
            records = _runtime_agent_records("xss", "xss-agent")
        finally:
            rs.default_store = old
        self.assertTrue(records["source_available"])
        last = records["llm_last"]
        self.assertEqual(last["requested_model"], "openrouter/free")
        self.assertEqual(last["prompt_version"], "xss-agent-analysis-v1")
        self.assertEqual(last["job_status"], JobStatus.COMPLETED.value)
        self.assertTrue(last["hypothesis"])
        self.assertIn("verdict", last)
        self.assertNotIn(KEY, json.dumps(records))


if __name__ == "__main__":
    unittest.main()
