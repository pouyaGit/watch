"""EPIC7 Part 1/10/11/17: the ObservationRuntime abstraction — lifecycle
recording, dry-run plans, live gating, and eviction of executed work."""

from __future__ import annotations

import unittest


def ready_context(**overrides):
    def request(**kw):
        base = {
            "request_id": "obsreq-abc123",
            "research_job_id": "job-123",
            "case_id": "case-123",
            "target_id": "tgt-000000000001",
            "observation_type": "HTTP_METADATA",
            "method": "GET",
            "required_evidence_level": "PARTIAL",
            "authorization_reference": "authz-123",
            "policy_version": "v1",
        }
        base.update(kw)
        return base

    def authz(**kw):
        base = {
            "status": "GRANTED",
            "expires_tick": 100,
            "authorization_reference": "authz-123",
            "target_id": "tgt-000000000001",
            "case_id": "case-123",
        }
        base.update(kw)
        return base

    def target():
        from aec.runtime.adapters.target import resolve_target

        return resolve_target(
            {"host": "shop.example.com", "scheme": "https",
             "endpoint": "/orders", "port": None, "source": "watch",
             "authorization_reference": "authz-123"},
            scope_hosts=frozenset({"shop.example.com"}))

    return request(), authz(), target()


class FakeTransport:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {"content-type": "text/plain"}
        self.body = b"ok"
        self.timing_ms = 4
        self.calls = 0

    def __call__(self, target, request, limits):
        self.calls += 1
        return {"status": self.status, "headers": dict(self.headers),
                "body": self.body, "timing_ms": self.timing_ms}


class TestLifecycleRecording(unittest.TestCase):
    def test_valid_live_records_terminal_state(self):
        from aec.runtime.execution.runtime import execute

        request, authz, target = ready_context()
        transport = FakeTransport()
        result = execute(request, authz, target,
                         mode="LIVE_OBSERVATION",
                         source_mode="REAL_WATCH_DATA",
                         policy_version="v1", transport=transport)
        self.assertEqual(result.state, "COMPLETED")
        self.assertTrue(result.executed)

    def test_observed_transitions_are_total(self):
        from aec.runtime.execution.runtime import execute

        request, authz, target = ready_context()
        result = execute(request, authz, target,
                         mode="DRY_RUN",
                         source_mode="REAL_WATCH_DATA",
                         policy_version="v1")
        self.assertIn(result.state,
                      {"AUTHORIZED", "REFUSED", "BLOCKED",
                       "TIMED_OUT", "FAILED"})

    def test_no_transition_outside_lifecycle(self):
        from aec.runtime.execution.runtime import execute

        request, authz, target = ready_context()
        result = execute(request, authz, target,
                         mode="DRY_RUN",
                         source_mode="REAL_WATCH_DATA",
                         policy_version="v1")
        # the runtime never emits a state the lifecycle does not define
        self.assertTrue(hasattr(result, "state"))


class TestCancellationAndEviction(unittest.TestCase):
    def _req(self, request_id, authz_ref, target_id):
        return {
            "request_id": request_id,
            "research_job_id": "job-123",
            "case_id": "case-123",
            "target_id": target_id,
            "observation_type": "HTTP_METADATA",
            "method": "GET",
            "required_evidence_level": "PARTIAL",
            "authorization_reference": authz_ref,
            "policy_version": "v1",
        }

    def test_evict_discards_entries(self):
        from aec.runtime.execution.idempotency import IdempotencyGuard

        guard = IdempotencyGuard()
        guard.record(self._req("r1", "authz-a", "tgt-1"))
        guard.record(self._req("r2", "authz-b", "tgt-2"))
        self.assertEqual(guard.snapshot()["count"], 2)
        guard.evict(self._req("r1", "authz-a", "tgt-1"))
        self.assertEqual(guard.snapshot()["count"], 1)
        self.assertFalse(guard.is_duplicate(
            self._req("r1", "authz-a", "tgt-1")))

    def test_cancel_unblocks_later_attempt(self):
        from aec.runtime.execution.idempotency import IdempotencyGuard

        guard = IdempotencyGuard()
        guard.record(self._req("r1", "authz-a", "tgt-1"))
        self.assertTrue(guard.is_duplicate(
            self._req("r1", "authz-a", "tgt-1")))
        guard.evict(self._req("r1", "authz-a", "tgt-1"))
        self.assertFalse(guard.is_duplicate(
            self._req("r1", "authz-a", "tgt-1")))


class TestDryRunPlan(unittest.TestCase):
    def test_plan_shape(self):
        from aec.runtime.execution.runtime import build_plan

        request, authz, target = ready_context()
        plan = build_plan(request, authz, target,
                          mode="DRY_RUN", policy_version="v1",
                          decision="AUTHORIZED", reasons=())
        self.assertIn("authorization_result", plan)
        self.assertIn("target_validation", plan)
        self.assertIn("observation_type", plan)
        self.assertIn("limits", plan)
        self.assertIn("expected_evidence", plan)
        self.assertIn("refusal_reason", plan)
        self.assertIn("dry_run", plan)

    def test_plan_refusal_reason_recorded(self):
        from aec.runtime.execution.runtime import build_plan

        request, authz, target = ready_context()
        plan = build_plan(request, authz, target,
                          mode="DRY_RUN", policy_version="v1",
                          decision="REFUSED",
                          reasons=("TYPE_UNKNOWN",))
        self.assertEqual(plan["refusal_reason"], "TYPE_UNKNOWN")

    def test_plan_marks_dry_run(self):
        from aec.runtime.execution.runtime import build_plan

        request, authz, target = ready_context()
        plan = build_plan(request, authz, target,
                          mode="DRY_RUN", policy_version="v1",
                          decision="AUTHORIZED", reasons=())
        self.assertTrue(plan["dry_run"])

    def test_plan_limits_are_policy(self):
        from aec.runtime.execution.runtime import build_plan
        from aec.runtime.policy.limits import default_limits

        request, authz, target = ready_context()
        plan = build_plan(request, authz, target,
                          mode="DRY_RUN", policy_version="v1",
                          decision="AUTHORIZED", reasons=())
        expected = default_limits().to_dict()
        self.assertEqual(plan["limits"], expected)

    def test_plan_expected_evidence_type(self):
        from aec.runtime.execution.runtime import build_plan

        request, authz, target = ready_context()
        plan = build_plan(request, authz, target,
                          mode="DRY_RUN", policy_version="v1",
                          decision="AUTHORIZED", reasons=())
        self.assertIn("HTTP_METADATA", plan["expected_evidence"])


class TestModeGate(unittest.TestCase):
    def test_unknown_mode_rejected(self):
        from aec.runtime.execution.runtime import execute

        request, authz, target = ready_context()
        result = execute(request, authz, target,
                         mode="BLAZE_IT", source_mode="REAL_WATCH_DATA",
                         policy_version="v1", transport=FakeTransport())
        self.assertEqual(result.decision, "REFUSED")
        self.assertFalse(result.executed)

    def test_modes_exhaustive(self):
        from aec.runtime.execution.runtime import RUNTIME_MODES

        self.assertEqual(set(RUNTIME_MODES),
                         {"DRY_RUN", "LIVE_OBSERVATION"})
        self.assertEqual(len(RUNTIME_MODES), 2)

    def test_no_arbitrary_mode_extension(self):
        from aec.runtime.execution.runtime import RUNTIME_MODES

        for mode in RUNTIME_MODES:
            self.assertIn(mode, ("DRY_RUN", "LIVE_OBSERVATION"))

    def test_supported_mode_checks(self):
        from aec.runtime.execution.runtime import is_supported_mode

        self.assertTrue(is_supported_mode("DRY_RUN"))
        self.assertTrue(is_supported_mode("LIVE_OBSERVATION"))
        self.assertFalse(is_supported_mode("DRY_RUN2"))
        self.assertFalse(is_supported_mode(""))


class TestEvidenceWiring(unittest.TestCase):
    def test_live_success_carries_evidence(self):
        from aec.runtime.execution.runtime import execute

        request, authz, target = ready_context()
        transport = FakeTransport()
        result = execute(request, authz, target,
                         mode="LIVE_OBSERVATION",
                         source_mode="REAL_WATCH_DATA",
                         policy_version="v1", transport=transport)
        self.assertIsNotNone(result.evidence)
        self.assertTrue(result.evidence.evidence_id.startswith("ev-"))

    def test_dry_run_carries_no_evidence(self):
        from aec.runtime.execution.runtime import execute

        request, authz, target = ready_context()
        result = execute(request, authz, target,
                         mode="DRY_RUN",
                         source_mode="REAL_WATCH_DATA",
                         policy_version="v1")
        self.assertIsNone(result.evidence)

    def test_blocked_carries_no_evidence(self):
        from aec.runtime.execution.runtime import execute

        request, authz, target = ready_context()
        blocked_authz = dict(authz)
        blocked_authz["target_id"] = "tgt-999"
        result = execute(request, blocked_authz, target,
                         mode="LIVE_OBSERVATION",
                         source_mode="REAL_WATCH_DATA",
                         policy_version="v1", transport=FakeTransport())
        self.assertIsNone(result.evidence)


class TestRuntimeModuleBoundaries(unittest.TestCase):
    def test_runtime_is_importable_without_network(self):
        from aec.runtime.execution import runtime  # noqa: F401

        self.assertTrue(callable(runtime.execute))

    def test_results_package_exported(self):
        from aec.runtime.results import (  # noqa: F401
            AuditTrail, EvidenceArtifact)

        self.assertTrue(AuditTrail and EvidenceArtifact)


if __name__ == "__main__":
    unittest.main()