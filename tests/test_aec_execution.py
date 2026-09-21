"""Tests for aec/execution (EPIC 6 Part 4: execution bridge).

ResearchExecutor never performs network I/O. It verifies the gate
decision and an explicit authorization state, then mints a data-only
AUTHORIZED_OBSERVATION_REQUEST. Missing/denied/expired authorization
and missing capability each map to their documented terminal state.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

EXECUTION_DIR = Path(__file__).resolve().parents[1] / "aec" / "execution"
MODULES = ("models.py", "executor.py", "results.py")

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp",
    "subprocess", "asyncio", "ai", "watch_xss_verify", "backend",
})

FORBIDDEN = (
    "SEVERITY", "CVSS", "CRITICAL", "VULNERABLE", "EXPLOITABLE", "EXPLOIT",
    "PAYLOAD", "CONFIRMED", "FINDING", "VERDICT",
)


def plan(**overrides):
    entry = {
        "plan_id": "plan-001",
        "case_id": "case-001",
        "steps": [
            {"step_id": "s1", "endpoint": "/orders", "purpose": "BASELINE"},
        ],
    }
    entry.update(overrides)
    return entry


def granted(**overrides):
    entry = {"status": "GRANTED", "scope": "observation",
             "expires_tick": 100}
    entry.update(overrides)
    return entry


class TestSubmitPlan(unittest.TestCase):
    def submit(self, **overrides):
        from aec.execution import executor

        fields = {
            "job_id": "job-001",
            "plan": plan(),
            "gate": "ALLOW",
            "authz": granted(),
            "capabilities": ("baseline-observe",),
            "tick": 5,
        }
        fields.update(overrides)
        return executor.submit_plan(**fields)

    def test_granted_creates_request(self):
        outcome = self.submit()
        self.assertEqual(outcome.disposition, "OBSERVATION_REQUESTED")
        self.assertEqual(outcome.job_transition, "OBSERVATION_RUNNING")

    def test_request_schema(self):
        outcome = self.submit()
        self.assertEqual(
            sorted(outcome.request),
            ["authorized_by", "capability", "case_id", "job_id", "plan_id",
             "request_id", "steps", "tick"],
        )

    def test_request_id_deterministic(self):
        first = self.submit()
        second = self.submit()
        self.assertEqual(first.request["request_id"],
                         second.request["request_id"])

    def test_request_steps_descriptive_only(self):
        outcome = self.submit()
        for step in outcome.request["steps"]:
            self.assertEqual(sorted(step), ["endpoint", "purpose", "step_id"])

    def test_missing_authz_waits(self):
        outcome = self.submit(authz={"status": "MISSING"})
        self.assertEqual(outcome.disposition, "WAITING_AUTHORIZATION")
        self.assertEqual(outcome.job_transition, "WAITING_AUTHORIZATION")
        self.assertEqual(outcome.request, {})

    def test_denied_blocks(self):
        outcome = self.submit(authz={"status": "DENIED"})
        self.assertEqual(outcome.disposition, "BLOCKED")
        self.assertEqual(outcome.job_transition, "BLOCKED")

    def test_expired_expires(self):
        outcome = self.submit(authz={"status": "EXPIRED"})
        self.assertEqual(outcome.disposition, "EXPIRED")
        self.assertEqual(outcome.job_transition, "EXPIRED")

    def test_granted_but_expired_tick_expires(self):
        outcome = self.submit(
            authz=granted(expires_tick=3), tick=5)
        self.assertEqual(outcome.disposition, "EXPIRED")

    def test_gate_refuse_blocks(self):
        outcome = self.submit(gate="REFUSE")
        self.assertEqual(outcome.disposition, "BLOCKED")
        self.assertIn("GATE", outcome.reason)

    def test_gate_unknown_blocks(self):
        outcome = self.submit(gate="MAYBE")
        self.assertEqual(outcome.disposition, "BLOCKED")

    def test_missing_capability_blocks(self):
        outcome = self.submit(capabilities=())
        self.assertEqual(outcome.disposition, "BLOCKED")
        self.assertTrue(outcome.requires_observation)

    def test_unknown_authz_status_blocks(self):
        outcome = self.submit(authz={"status": "SIGNED"})
        self.assertEqual(outcome.disposition, "BLOCKED")

    def test_empty_plan_refused(self):
        from aec.execution import executor

        with self.assertRaises(executor.SubmissionRefusal):
            self.submit(plan={"plan_id": "", "case_id": "c", "steps": []})

    def test_plan_without_steps_refused(self):
        from aec.execution import executor

        with self.assertRaises(executor.SubmissionRefusal):
            self.submit(plan=plan(steps=[]))

    def test_refusal_codes_closed(self):
        from aec.execution import executor

        self.assertLessEqual(
            set(executor.REFUSAL_CODES),
            {"EMPTY_PLAN", "EMPTY_STEPS", "BAD_TICK", "EMPTY_JOB"},
        )

    def test_outcome_fields(self):
        outcome = self.submit()
        self.assertEqual(
            sorted(outcome.to_dict()),
            ["disposition", "job_transition", "reason", "request",
             "requires_observation"],
        )


class TestIngestResult(unittest.TestCase):
    def request(self):
        from aec.execution import executor

        outcome = executor.submit_plan(
            job_id="job-001", plan=plan(), gate="ALLOW",
            authz=granted(), capabilities=("baseline-observe",), tick=5,
        )
        return outcome.request

    def result(self, **overrides):
        entry = {
            "observation_id": "obs-001",
            "request_id": "REQ",
            "observed_fields": ["initial-observation"],
            "missing_fields": [],
            "tick": 6,
            "source": "fixture-observer",
        }
        entry.update(overrides)
        return entry

    def test_valid_result_pending(self):
        from aec.execution import executor

        request = self.request()
        outcome = executor.ingest_result(
            request, self.result(request_id=request["request_id"]))
        self.assertEqual(outcome.disposition, "EVIDENCE_PENDING")
        self.assertEqual(outcome.job_transition, "EVIDENCE_PENDING")

    def test_request_mismatch_refused(self):
        from aec.execution import executor

        with self.assertRaises(executor.IngestionRefusal):
            executor.ingest_result(
                self.request(), self.result(request_id="other"))

    def test_duplicate_observation_recorded(self):
        from aec.execution import executor

        request = self.request()
        seen = {"obs-001"}
        outcome = executor.ingest_result(
            request, self.result(request_id=request["request_id"]),
            seen_observation_ids=seen,
        )
        self.assertEqual(outcome.disposition, "DUPLICATE_OBSERVATION")
        self.assertEqual(outcome.job_transition, "")

    def test_malformed_result_refused(self):
        from aec.execution import executor

        with self.assertRaises(executor.IngestionRefusal):
            executor.ingest_result(
                self.request(), {"observation_id": "x"})

    def test_empty_observed_fields_refused(self):
        from aec.execution import executor

        request = self.request()
        with self.assertRaises(executor.IngestionRefusal):
            executor.ingest_result(
                request,
                self.result(request_id=request["request_id"],
                            observed_fields=[]),
            )


class TestRetryClassification(unittest.TestCase):
    def test_timeout_retryable(self):
        from aec.execution import executor

        self.assertEqual(executor.classify_failure("TIMEOUT"), "RETRYABLE")

    def test_ingestion_error_retryable(self):
        from aec.execution import executor

        self.assertEqual(
            executor.classify_failure("INGESTION_ERROR"), "RETRYABLE")

    def test_refused_terminal(self):
        from aec.execution import executor

        self.assertEqual(
            executor.classify_failure("EXECUTION_REFUSED"), "TERMINAL")

    def test_denied_terminal(self):
        from aec.execution import executor

        self.assertEqual(
            executor.classify_failure("AUTHORIZATION_DENIED"), "TERMINAL")

    def test_malformed_terminal(self):
        from aec.execution import executor

        self.assertEqual(
            executor.classify_failure("MALFORMED_RESULT"), "TERMINAL")

    def test_unknown_kind_terminal(self):
        from aec.execution import executor

        self.assertEqual(executor.classify_failure("WEIRD"), "TERMINAL")

    def test_timeout_detection(self):
        from aec.execution import executor

        self.assertTrue(executor.is_timed_out(start_tick=1, now_tick=10,
                                             timeout_ticks=5))
        self.assertFalse(executor.is_timed_out(start_tick=8, now_tick=10,
                                              timeout_ticks=5))


class TestSafetyGuards(unittest.TestCase):
    def test_no_forbidden_vocabulary_in_source(self):
        for name in MODULES:
            source = (EXECUTION_DIR / name).read_text()
            for word in FORBIDDEN:
                self.assertNotIn(word, source, f"{name}:{word}")

    def test_no_network_imports(self):
        for name in MODULES:
            tree = ast.parse((EXECUTION_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)

    def test_no_request_sending_calls(self):
        for name in MODULES:
            tree = ast.parse((EXECUTION_DIR / name).read_text())
            calls = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    target = node.func
                    if isinstance(target, ast.Name):
                        calls.add(target.id)
                    while isinstance(target, ast.Attribute):
                        calls.add(target.attr)
                        target = target.value
            banned = {"post", "request", "urlopen", "send",
                      "connect", "fetch", "execute"}
            self.assertLessEqual(calls & banned, set(), name)


if __name__ == "__main__":
    unittest.main()
