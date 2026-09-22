"""Agent Runtime v1 — security, authorization and LLM tests (Phases 6/14).

Covers: fail-closed authorization before every observation, the
observation boundary (no network/shell/code execution reachable from the
runtime), LLM provider failure semantics (fail/retry, never pretend),
structured-output validation, job timeout → TIMEOUT lifecycle, secret
non-persistence, and resource bounds.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from backend.research_agents.capabilities import CAPABILITIES, capability_for
from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    AgentWorker,
    AnalysisUnavailable,
    AuthorizationChecker,
    AuthorizationDenied,
    FixtureObservations,
    RuntimeConfig,
    deterministic_analysis,
    llm_analysis,
)
from backend.research_agents.runtime_store import RuntimeStore, utcnow

REPO = pathlib.Path(__file__).resolve().parents[1]
RUNTIME_PKG = REPO / "backend" / "research_agents"

BANNED_IMPORTS = {"socket", "requests", "http", "urllib", "subprocess",
                  "telnetlib", "ftplib", "smtplib"}
BANNED_CALLS = {"system", "popen", "Popen", "urlopen",
                "create_connection", "check_output", "eval", "exec",
                "__import__"}
# WATCH_AGENT_RUNTIME_DIR: store location.
# OPENROUTER_* / WATCH_AGENT_LLM_MODE: the Phase 1/9 free-only cost guard
# (presence/shape checks only — values are never persisted anywhere).
ENV_KEYS_ALLOWED = {"WATCH_AGENT_RUNTIME_DIR", "OPENROUTER_API_KEY",
                    "OPENROUTER_MODEL", "OPENROUTER_BASE_URL",
                    "WATCH_AGENT_LLM_MODE"}


def _job(tag: str = "", **over) -> ResearchJob:
    base = dict(
        id="job-authz" + (f"-{tag}" if tag else ""),
        candidate_id="c", category="XSS",
        endpoint="https://t.example/x", parameter="q", priority_score=10,
        status=JobStatus.RUNNING.value, assigned_agent="xss-agent",
        created_at=utcnow(), updated_at=utcnow(), agent_category="XSS",
        program="p1", subdomain="t.example", url="https://t.example/x",
        mission="m", authorization_ref="watch:scope:p1/t.example",
        execution_mode="production",
    )
    base.update(over)
    return ResearchJob(**base)


class TestAuthorizationFailClosed(unittest.TestCase):
    def setUp(self):
        self.checker = AuthorizationChecker()

    def test_missing_authorization_ref_is_denied(self):
        with self.assertRaises(AuthorizationDenied) as ctx:
            self.checker.verify(_job(authorization_ref=""))
        self.assertEqual(ctx.exception.reason, "missing_authorization_ref")

    def test_non_watch_scope_is_denied_in_production(self):
        with self.assertRaises(AuthorizationDenied) as ctx:
            self.checker.verify(_job(authorization_ref="free:everything"))
        self.assertEqual(ctx.exception.reason,
                         "authorization_ref_not_watch_scope")

    def test_target_outside_scope_subdomain_is_denied(self):
        with self.assertRaises(AuthorizationDenied) as ctx:
            self.checker.verify(_job(url="https://evil.example/x"))
        self.assertEqual(ctx.exception.reason, "target_out_of_scope")

    def test_missing_scope_fields_are_denied(self):
        with self.assertRaises(AuthorizationDenied) as ctx:
            self.checker.verify(_job(program="", subdomain=""))
        self.assertEqual(ctx.exception.reason, "missing_scope")

    def test_valid_watch_scope_passes(self):
        ref = self.checker.verify(_job())
        self.assertEqual(ref, "watch:scope:p1/t.example")

    def test_fixture_job_must_carry_fixture_scope(self):
        with self.assertRaises(AuthorizationDenied) as ctx:
            self.checker.verify(_job(execution_mode="fixture",
                                     authorization_ref="watch:scope:p1/t"))
        self.assertEqual(ctx.exception.reason,
                         "fixture_job_without_fixture_scope")

    def test_unauthorized_job_is_terminal_failed_and_audited(self):
        store_dir = tempfile.mkdtemp(prefix="rt-authz-",
                                     dir=os.environ.get("TMPDIR", "/tmp"))
        store = RuntimeStore(store_dir)
        job = _job(status=JobStatus.QUEUED.value, authorization_ref="",
                   execution_mode="fixture")
        store.enqueue(job)
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture", worker_id="w1"),
            store=store,
            observations=FixtureObservations({}),
            llm_enabled=False,
        )
        worker.run(max_jobs=1)
        after = store.get(job.id)
        self.assertEqual(after.status, JobStatus.TERMINAL_FAILED.value)
        self.assertIn("authorization_denied", after.error)
        events = [e["event"] for e in store.audit_events()]
        self.assertIn("job_rejected", events)
        # an unauthorized job must never produce a result
        self.assertIsNone(store.get_result(job.id))


class TestObservationBoundary(unittest.TestCase):
    """No network/shell/code path exists inside the runtime package."""

    def test_runtime_package_imports_no_network_or_shell_modules(self):
        offenders = []
        for path in sorted(RUNTIME_PKG.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        if root in BANNED_IMPORTS:
                            offenders.append(f"{path.name}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    if root in BANNED_IMPORTS:
                        offenders.append(f"{path.name}: from {node.module}")
        self.assertEqual(offenders, [],
                         f"observation boundary violation: {offenders}")

    def test_runtime_package_never_calls_shell_or_eval(self):
        offenders = []
        for path in sorted(RUNTIME_PKG.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    name = (fn.attr if isinstance(fn, ast.Attribute)
                            else fn.id if isinstance(fn, ast.Name) else "")
                    if name in BANNED_CALLS:
                        offenders.append(f"{path.name}:{node.lineno} {name}()")
        self.assertEqual(offenders, [],
                         f"forbidden call in runtime: {offenders}")

    def test_only_env_key_read_by_runtime_is_the_store_dir(self):
        used = set()
        for path in sorted(RUNTIME_PKG.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                on_env = (isinstance(fn, ast.Attribute)
                          and fn.attr == "get"
                          and isinstance(fn.value, ast.Attribute)
                          and fn.value.attr == "environ")
                if on_env and node.args and isinstance(node.args[0],
                                                       ast.Constant):
                    used.add(node.args[0].value)
                if isinstance(fn, ast.Attribute) and fn.attr == "environ":
                    used.add("<environ attribute access>")
                if isinstance(fn, ast.Name) and fn.id == "environ":
                    used.add("<environ>")
        self.assertLessEqual(used, ENV_KEYS_ALLOWED,
                             f"unexpected env access: {used}")

    def test_read_store_provider_reads_only_database_models(self):
        from backend.research_agents.runtime import ReadStoreObservations

        src = pathlib.Path(
            REPO / "backend" / "research_agents" / "runtime.py"
        ).read_text(encoding="utf-8")
        self.assertIn("from database import db", src)
        # the provider exists, but the boundary test above proves it cannot
        # reach a network module from this package
        self.assertTrue(callable(ReadStoreObservations.observe))


class TestLLMFailureSemantics(unittest.TestCase):
    """Phase 6: unavailable provider fails/retries — never pretends."""

    """Agent Intelligence v1: free-only guard, structured validation,
    fail/retry-never-pretend, and secret hygiene (Phases 1/3/8/9/14)."""

    KEY = "sk-or-test-SENTINEL-not-a-real-key"

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rt-llm-",
                                    dir=os.environ.get("TMPDIR", "/tmp"))
        self.store = RuntimeStore(self.dir)
        self._old_key = os.environ.get("OPENROUTER_API_KEY")
        os.environ["OPENROUTER_API_KEY"] = self.KEY
        self._old_mode = os.environ.pop("WATCH_AGENT_LLM_MODE", None)
        self._old_env_model = os.environ.pop("OPENROUTER_MODEL", None)
        self._old_env_base = os.environ.pop("OPENROUTER_BASE_URL", None)
        self.config = RuntimeConfig(execution_mode="fixture",
                                    llm_provider_kind="OPENROUTER",
                                    worker_id="w1")

    def tearDown(self):
        if self._old_key is None:
            os.environ.pop("OPENROUTER_API_KEY", None)
        else:
            os.environ["OPENROUTER_API_KEY"] = self._old_key
        os.environ.pop("WATCH_AGENT_LLM_MODE", None)
        if self._old_mode is not None:
            os.environ["WATCH_AGENT_LLM_MODE"] = self._old_mode
        os.environ.pop("OPENROUTER_MODEL", None)
        if getattr(self, "_old_env_model", None) is not None:
            os.environ["OPENROUTER_MODEL"] = self._old_env_model
        os.environ.pop("OPENROUTER_BASE_URL", None)
        if getattr(self, "_old_env_base", None) is not None:
            os.environ["OPENROUTER_BASE_URL"] = self._old_env_base

    @staticmethod
    def _envelope(response=None, error=None, telemetry=None):
        return {"response": response, "error": error,
                "telemetry": telemetry or {"attempts": 1},
                "_exception": None}

    @staticmethod
    def _good_response():
        return {
            "summary": "reflected parameter context observed",
            "insights": [{"insight_code": "PARAM_INVENTORY",
                          "text": "parameter q observed"}],
            "recommendations": [{"recommendation_code": "NEXT_OBSERVATION",
                                 "text": "observe response rendering"}],
        }

    def _factory(self, outcome):
        class Provider:
            def __init__(self, inner):
                self.inner = inner
                self.calls = 0

            def complete(self, request):
                self.calls += 1
                if isinstance(self.inner, Exception):
                    raise self.inner
                return self.inner
        holder = Provider(outcome)

        def factory(kind, **opts):
            holder.opts = opts
            return holder
        factory.holder = holder
        return factory

    def _analyze(self, provider_factory, rows=None, knowledge=None):
        cap = capability_for("XSS")
        rows = rows if rows is not None else [
            {"source": "http", "ref": "1", "url": "https://t/x?q=1",
             "params": ["q"], "status": 200, "title": "x"}]
        with mock.patch(
                "ai.providers.provider_registry.select_provider",
                side_effect=provider_factory):
            return llm_analysis(self.config, cap, _job(), rows,
                                knowledge or [])

    # -- success + structured output -------------------------------------
    def test_success_path_returns_structured_analysis_and_meta(self):
        f = self._factory(self._envelope(self._good_response()))
        analysis, meta = self._analyze(f)
        cap = capability_for("XSS")
        determin = deterministic_analysis(
            cap, _job(),
            [{"source": "http", "ref": "1", "url": "https://t/x?q=1",
              "params": ["q"], "status": 200, "title": "x"}], [])
        # guard metadata: free router only, key never present
        self.assertEqual(meta["provider"], "OPENROUTER")
        self.assertEqual(meta["requested_model"], "openrouter/free")
        self.assertEqual(meta["prompt_version"], "xss-agent-analysis-v1")
        self.assertGreaterEqual(meta["analysis_ms"], 0)
        self.assertIsNone(meta["usage"])
        # provider is always built with the free model explicitly
        self.assertEqual(f.holder.opts.get("model"), "openrouter/free")
        # structured schema (Phase 3) persisted on the analysis
        st = analysis["structured"]
        for key in ("hypothesis", "vulnerability_class",
                    "observations_considered", "evidence_required",
                    "evidence_present", "confidence", "blockers",
                    "reasoning_summary", "recommended_next_observation",
                    "verdict"):
            self.assertIn(key, st)
        self.assertEqual(st["reasoning_summary"],
                         "reflected parameter context observed")
        self.assertEqual(analysis["summary"], st["reasoning_summary"])
        self.assertEqual(analysis["prompt_version"],
                         "xss-agent-analysis-v1")
        # the gate value stays deterministic — LLM is input only
        self.assertEqual(analysis["confidence"], determin["confidence"])
        self.assertEqual(st["confidence"], determin["confidence"])

    def test_llm_hypothesis_cannot_create_a_case(self):
        from backend.research_agents.runtime import evaluate_case_creation
        f = self._factory(self._envelope(self._good_response()))
        analysis, _ = self._analyze(f, rows=[])
        self.assertTrue(analysis["structured"]["hypothesis"])
        decision = evaluate_case_creation(capability_for("XSS"), _job(),
                                          analysis, [])
        self.assertFalse(decision.create)
        self.assertEqual(analysis["confidence"], "insufficient")

    # -- free-only cost guard --------------------------------------------
    def test_paid_model_rejected_without_provider_call(self):
        bad = RuntimeConfig(execution_mode="fixture",
                            llm_provider_kind="OPENROUTER",
                            llm_model="openai/gpt-4o", worker_id="w1")
        cap = capability_for("XSS")
        f = self._factory(self._envelope(self._good_response()))
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=f):
            with self.assertRaises(AnalysisUnavailable) as ctx:
                llm_analysis(bad, cap, _job(), [{"url": "https://t/x",
                                                 "params": ["q"]}], [])
        self.assertIn("free_only", str(ctx.exception))
        self.assertIn("model_not_free", str(ctx.exception))
        self.assertEqual(getattr(f.holder, "calls", 0), 0)

    def test_other_free_model_ids_are_rejected(self):
        # only the openrouter/free router id is allowed — no substitutions
        other = RuntimeConfig(execution_mode="fixture",
                              llm_provider_kind="OPENROUTER",
                              llm_model="deepseek/deepseek-chat:free",
                              worker_id="w1")
        f = self._factory(self._envelope(self._good_response()))
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=f):
            with self.assertRaises(AnalysisUnavailable) as ctx:
                llm_analysis(other, capability_for("XSS"), _job(),
                             [{"url": "https://t/x", "params": ["q"]}], [])
        self.assertIn("model_not_free", str(ctx.exception))
        self.assertEqual(getattr(f.holder, "calls", 0), 0)

    def test_missing_api_key_fails_closed(self):
        os.environ.pop("OPENROUTER_API_KEY", None)
        f = self._factory(self._envelope(self._good_response()))
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=f):
            with self.assertRaises(AnalysisUnavailable) as ctx:
                self._analyze(f)
        self.assertIn("missing_openrouter_api_key", str(ctx.exception))
        self.assertEqual(f.holder.calls, 0)

    def test_env_paid_model_cannot_leak_in(self):
        os.environ["OPENROUTER_MODEL"] = "gpt-4o"
        try:
            f = self._factory(self._envelope(self._good_response()))
            with mock.patch(
                    "ai.providers.provider_registry.select_provider",
                    side_effect=f):
                with self.assertRaises(AnalysisUnavailable) as ctx:
                    self._analyze(f)
            self.assertIn("env_model_not_free", str(ctx.exception))
            self.assertEqual(f.holder.calls, 0)
        finally:
            del os.environ["OPENROUTER_MODEL"]

    def test_llm_mode_off_rejects_llm_runs(self):
        os.environ["WATCH_AGENT_LLM_MODE"] = "off"
        f = self._factory(self._envelope(self._good_response()))
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=f):
            with self.assertRaises(AnalysisUnavailable) as ctx:
                self._analyze(f)
        self.assertIn("llm_mode_off", str(ctx.exception))
        self.assertEqual(f.holder.calls, 0)

    # -- structured-output validation ------------------------------------
    def test_schema_failure_on_bad_item_shape(self):
        bad = self._good_response()
        bad["insights"] = [{"insight_code": "A", "text": "x", "extra": 1}]
        f = self._factory(self._envelope(bad))
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(f)
        self.assertIn("schema_failure", str(ctx.exception))

    def test_empty_summary_is_rejected(self):
        bad = self._good_response()
        bad["summary"] = "   "
        f = self._factory(self._envelope(bad))
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(f)
        self.assertIn("schema_failure", str(ctx.exception))

    def test_non_envelope_outcome_is_rejected(self):
        f = self._factory("raw text, not an envelope")
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(f)
        self.assertIn("llm_provider_error", str(ctx.exception))

    # -- failure classification ------------------------------------------
    def test_timeout_classified(self):
        f = self._factory(TimeoutError("request timed out after 30s"))
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(f)
        self.assertIn("llm_timeout", str(ctx.exception))

    def test_rate_limit_classified(self):
        f = self._factory(self._envelope(
            error={"error": "RATE_LIMIT", "safe_message": "429"}))
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(f)
        self.assertIn("llm_rate_limit", str(ctx.exception))

    def test_invalid_key_classified_as_auth(self):
        f = self._factory(self._envelope(
            error={"error": "AUTHENTICATION_ERROR",
                   "safe_message": "401 unauthorized"}))
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(f)
        self.assertIn("llm_auth", str(ctx.exception))

    def test_provider_config_error_is_clean(self):
        def factory(kind, **opts):
            raise RuntimeError("provider construction exploded")
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(factory)
        self.assertIn("provider_configuration", str(ctx.exception))

    # -- job-level fail/retry --------------------------------------------
    def test_llm_failure_fails_the_job_without_a_result(self):
        store = self.store
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        store.enqueue(job)
        f = self._factory(RuntimeError("provider construction exploded"))
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=f):
            worker = AgentWorker(
                config=self.config, store=store,
                observations=FixtureObservations({
                    job.id: [{"source": "http", "ref": "1",
                              "url": "https://t.example/x?q=1",
                              "params": ["q"], "status": 200}]}),
                llm_enabled=True,
            )
            worker.run(max_jobs=1)
        after = store.get(job.id)
        self.assertIn(after.status,
                      (JobStatus.QUEUED.value,
                       JobStatus.TERMINAL_FAILED.value))
        self.assertIsNone(store.get_result(job.id),
                          "a failed LLM must never produce a result")
        failed_rows = [a for a in store.list_activity()
                       if a.get("action") == "job_failed"]
        self.assertTrue(failed_rows, "the failure must be auditable")
        self.assertIn("llm_provider_error", failed_rows[-1]["detail"])

    def test_persistent_failure_reaches_terminal_failed(self):
        store = self.store
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        store.enqueue(job)
        f = self._factory(TimeoutError("timed out"))
        statuses = []
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=f):
            for _ in range(6):
                worker = AgentWorker(
                    config=self.config, store=store,
                    observations=FixtureObservations({
                        job.id: [{"source": "http", "ref": "1",
                                  "url": "https://t.example/x?q=1",
                                  "params": ["q"], "status": 200}]}),
                    llm_enabled=True,
                )
                worker.run(max_jobs=1)
                statuses.append(store.get(job.id).status)
                if statuses[-1] == JobStatus.TERMINAL_FAILED.value:
                    break
        self.assertEqual(store.get(job.id).status,
                         JobStatus.TERMINAL_FAILED.value,
                         f"retry policy must exhaust: {statuses}")
        self.assertIsNone(store.get_result(job.id))

    # -- secret hygiene ----------------------------------------------------
    def test_error_text_and_state_never_carry_the_key(self):
        f = self._factory(RuntimeError(f"boom for key {self.KEY}"))
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(f)
        self.assertNotIn(self.KEY, str(ctx.exception))
        for path in (self.store.state_path, self.store.audit_path):
            if path.exists():
                self.assertNotIn(self.KEY, path.read_text(encoding="utf-8"))



class TestTimeoutAndBounds(unittest.TestCase):
    def test_zero_timeout_routes_through_timeout_state(self):
        store_dir = tempfile.mkdtemp(prefix="rt-to-",
                                     dir=os.environ.get("TMPDIR", "/tmp"))
        store = RuntimeStore(store_dir)
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example", max_attempts=1)
        store.enqueue(job)
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture", worker_id="w1",
                                 job_timeout=0),
            store=store,
            observations=FixtureObservations({}),
            llm_enabled=False,
        )
        worker.run(max_jobs=1)
        self.assertEqual(store.get(job.id).status,
                         JobStatus.TERMINAL_FAILED.value)

    def test_single_worker_holds_a_single_lease(self):
        store_dir = tempfile.mkdtemp(prefix="rt-lease-",
                                     dir=os.environ.get("TMPDIR", "/tmp"))
        store = RuntimeStore(store_dir)
        for i in range(3):
            store.enqueue(_job(tag=f"bnd{i}",
                               status=JobStatus.QUEUED.value))
        store.heartbeat_worker("w1", ttl_seconds=120)
        store.claim_next("w1", ("XSS",), lease_seconds=30)
        from backend.research_agents.runtime import runtime_snapshot
        snap = runtime_snapshot(store)
        self.assertEqual(len(snap["leases"]), 1,
                         "worker holds more than one lease")

    def test_deterministic_analysis_reports_insufficient_without_rows(self):
        cap = capability_for("XSS")
        analysis = deterministic_analysis(cap, _job(), [], [])
        self.assertTrue(analysis["insufficient_evidence"])
        self.assertEqual(analysis["confidence"], "insufficient")
        self.assertIn("no_authorized_observations", analysis["blockers"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
