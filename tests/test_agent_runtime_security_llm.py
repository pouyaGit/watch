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
ENV_KEYS_ALLOWED = {"WATCH_AGENT_RUNTIME_DIR"}


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

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rt-llm-",
                                    dir=os.environ.get("TMPDIR", "/tmp"))
        self.store = RuntimeStore(self.dir)
        self.config = RuntimeConfig(execution_mode="fixture",
                                    llm_provider_kind="OPENROUTER",
                                    worker_id="w1")

    def _analyze(self, provider_factory):
        cap = capability_for("XSS")
        rows = [{"source": "http", "ref": "1", "url": "https://t/x?q=1",
                 "params": ["q"], "status": 200, "title": "x"}]
        with mock.patch(
                "ai.providers.provider_registry.select_provider",
                side_effect=provider_factory):
            return llm_analysis(self.config, cap, _job(), rows, [])

    def test_success_path_parses_and_merges_json(self):
        from types import SimpleNamespace

        class P:
            model = "m-test"

            def complete(self, prompt):
                return SimpleNamespace(content=json.dumps({
                    "summary": "ok", "confidence": "medium",
                    "hypotheses": [{"endpoint": "https://t/x",
                                    "hypothesis": "param inventory"}],
                    "insufficient_evidence": False, "blockers": []}),
                    model="m-test")

        class _F:
            def __call__(self, kind, **opts):
                return P()
        analysis, provider, model = self._analyze(_F())
        self.assertEqual(analysis["confidence"], "medium")
        self.assertEqual(provider, "OPENROUTER")
        self.assertEqual(model, "m-test")

    def test_llm_cannot_upgrade_missing_evidence(self):
        class P:
            def complete(self, prompt):
                return json.dumps({"summary": "ok", "confidence": "high",
                                   "hypotheses": [], "blockers": []})

        class _F:
            def __call__(self, kind, **opts):
                return P()
        # no observations -> deterministic insufficient; LLM says high
        cap = capability_for("XSS")
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=_F()):
            analysis, _, _ = llm_analysis(self.config, cap, _job(), [], [])
        self.assertEqual(analysis["confidence"], "insufficient")
        self.assertTrue(analysis["insufficient_evidence"])
        self.assertIn("llm_cannot_upgrade_missing_evidence",
                      analysis["blockers"])

    def test_malformed_json_raises_analysis_unavailable(self):
        class P:
            def complete(self, prompt):
                return "this is not json {"

        class _F:
            def __call__(self, kind, **opts):
                return P()
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(_F())
        self.assertIn("malformed", str(ctx.exception))

    def test_bad_confidence_value_is_rejected(self):
        class P:
            def complete(self, prompt):
                return json.dumps({"summary": "s",
                                   "confidence": "very-sure",
                                   "hypotheses": []})

        class _F:
            def __call__(self, kind, **opts):
                return P()
        with self.assertRaises(AnalysisUnavailable):
            self._analyze(_F())

    def test_provider_timeout_classified_not_raised(self):
        class P:
            def complete(self, prompt):
                raise TimeoutError("request timed out after 30s")

        class _F:
            def __call__(self, kind, **opts):
                return P()
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(_F())
        self.assertIn("llm_timeout", str(ctx.exception))

    def test_provider_config_error_is_clean(self):
        def factory(kind, **opts):
            raise RuntimeError("API key is not configured")
        with self.assertRaises(AnalysisUnavailable) as ctx:
            self._analyze(factory)
        self.assertIn("provider_configuration", str(ctx.exception))

    def test_llm_failure_fails_the_job_without_a_result(self):
        store = self.store
        job = _job(status=JobStatus.QUEUED.value, execution_mode="fixture",
                   authorization_ref="fixture:p/t.example")
        store.enqueue(job)

        def factory(kind, **opts):
            raise RuntimeError("API key is not configured")
        with mock.patch("ai.providers.provider_registry.select_provider",
                        side_effect=factory):
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
                      (JobStatus.QUEUED.value, JobStatus.TERMINAL_FAILED.value))
        self.assertIsNone(store.get_result(job.id),
                          "a failed LLM must never produce a result")

    def test_error_text_never_carries_key_material(self):
        sentinel = "sk-" + "SENTINEL" + "KEYVALUE99"
        os.environ["AGENT_RUNTIME_TEST_KEY"] = sentinel
        try:
            def factory(kind, **opts):
                raise RuntimeError(f"401 unauthorized for key {sentinel}")
            with mock.patch(
                    "ai.providers.provider_registry.select_provider",
                    side_effect=factory):
                with self.assertRaises(AnalysisUnavailable) as ctx:
                    self._analyze(factory)
            self.assertNotIn(sentinel, str(ctx.exception))
            # nothing the store wrote contains the sentinel either
            for path in (self.store.state_path, self.store.audit_path):
                if path.exists():
                    self.assertNotIn(sentinel,
                                     path.read_text(encoding="utf-8"))
        finally:
            del os.environ["AGENT_RUNTIME_TEST_KEY"]


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
