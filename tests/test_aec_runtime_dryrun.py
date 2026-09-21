"""EPIC7 Part 10+17: DRY_RUN mode and source-mode isolation."""

from __future__ import annotations

import unittest


class _NoNetwork(Exception):
    pass


class ExplodingTransport:
    def __call__(self, *args, **kwargs):
        raise _NoNetwork("transport invoked in dry-run/fixture mode")


def valid_request(**overrides):
    request = {
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
    request.update(overrides)
    return request


def valid_authz(**overrides):
    authz = {
        "status": "GRANTED",
        "expires_tick": 100,
        "authorization_reference": "authz-123",
        "target_id": "tgt-000000000001",
        "case_id": "case-123",
    }
    authz.update(overrides)
    return authz


def valid_target():
    from aec.runtime.adapters.target import resolve_target

    return resolve_target(
        {"host": "shop.example.com", "scheme": "https",
         "endpoint": "/orders", "port": None, "source": "watch",
         "authorization_reference": "authz-123"},
        scope_hosts=frozenset({"shop.example.com"}))


class TestDryRunModes(unittest.TestCase):
    def test_dry_run_is_recognized(self):
        from aec.runtime.execution.runtime import RUNTIME_MODES

        self.assertIn("DRY_RUN", RUNTIME_MODES)
        self.assertIn("LIVE_OBSERVATION", RUNTIME_MODES)

    def test_unknown_mode_refused(self):
        from aec.runtime.execution.runtime import is_supported_mode

        self.assertFalse(is_supported_mode("FULL_SCAN"))

    def test_supported_modes(self):
        from aec.runtime.execution.runtime import is_supported_mode

        self.assertTrue(is_supported_mode("DRY_RUN"))
        self.assertTrue(is_supported_mode("LIVE_OBSERVATION"))


class TestDryRunExecution(unittest.TestCase):
    def test_dry_run_produces_plan(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=ExplodingTransport())
        self.assertEqual(result.decision, "AUTHORIZED")
        self.assertTrue(result.dry_run)

    def test_dry_run_zero_transport(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=ExplodingTransport())
        self.assertFalse(result.executed)

    def test_dry_run_distinguishable(self):
        from aec.runtime.execution.runtime import execute

        dry = execute(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=ExplodingTransport())
        self.assertTrue(dry.dry_run)
        self.assertNotEqual(dry.state, "COMPLETED")

    def test_dry_run_blocked_authz(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            valid_request(), valid_authz(status="DENIED"), valid_target(),
            mode="DRY_RUN", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=ExplodingTransport())
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("AUTHORIZATION_DENIED", result.reasons)

    def test_dry_run_refuses_bad_type(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            valid_request(observation_type="HTTP_POST"), valid_authz(),
            valid_target(), mode="DRY_RUN",
            source_mode="REAL_WATCH_DATA", policy_version="v1",
            transport=ExplodingTransport())
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("TYPE_UNKNOWN", result.reasons)


class TestFixtureIsolation(unittest.TestCase):
    def test_fixture_never_executes(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            valid_request(), valid_authz(), valid_target(),
            mode="LIVE_OBSERVATION", source_mode="OFFLINE_FIXTURE",
            policy_version="v1", transport=ExplodingTransport())
        self.assertEqual(result.decision, "REFUSED")
        self.assertFalse(result.executed)
        self.assertIn("FIXTURE_CANNOT_EXECUTE", result.reasons)

    def test_fixture_dry_run_never_executes(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", source_mode="OFFLINE_FIXTURE",
            policy_version="v1", transport=ExplodingTransport())
        self.assertFalse(result.executed)

    def test_live_mode_requires_real_source(self):
        from aec.runtime.execution.runtime import (
            live_requires_real_source)

        self.assertFalse(live_requires_real_source("OFFLINE_FIXTURE"))
        self.assertTrue(live_requires_real_source("REAL_WATCH_DATA"))


class TestLiveGating(unittest.TestCase):
    def test_live_execution_authz_gated(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            valid_request(), valid_authz(status="EXPIRED"), valid_target(),
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=ExplodingTransport())
        self.assertEqual(result.decision, "BLOCKED")
        self.assertFalse(result.executed)

    def test_live_execution_scope_gated(self):
        from aec.runtime.execution.runtime import execute
        from aec.runtime.adapters.target import resolve_target

        evil = resolve_target(
            {"host": "evil.example.com", "scheme": "https",
             "endpoint": "/x", "port": None, "source": "watch",
             "authorization_reference": "authz-123"},
            scope_hosts=frozenset({"evil.example.com"}))
        result = execute(
            valid_request(target_id=evil.target_id),
            valid_authz(target_id=evil.target_id), evil,
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=ExplodingTransport(),
            scope_hosts=frozenset({"shop.example.com"}))
        self.assertEqual(result.decision, "REFUSED")
        self.assertFalse(result.executed)

    def test_live_execution_requires_transport_gate(self):
        from aec.runtime.execution.runtime import execute

        # Without an explicit transport, LIVE_OBSERVATION must refuse
        # (no implicit default transport in tests).
        result = execute(
            valid_request(), valid_authz(), valid_target(),
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=None)
        self.assertIn(result.decision, ("REFUSED", "BLOCKED"))
        self.assertFalse(result.executed)


class TestExecutionPlan(unittest.TestCase):
    def test_plan_lists_authorization_result(self):
        from aec.runtime.execution.runtime import build_plan

        plan = build_plan(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", policy_version="v1",
            decision="AUTHORIZED", reasons=())
        self.assertEqual(plan["authorization_result"], "AUTHORIZED")

    def test_plan_lists_target_validation(self):
        from aec.runtime.execution.runtime import build_plan

        plan = build_plan(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", policy_version="v1",
            decision="AUTHORIZED", reasons=())
        self.assertEqual(plan["target_validation"], "PASS")

    def test_plan_lists_observation_type(self):
        from aec.runtime.execution.runtime import build_plan

        plan = build_plan(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", policy_version="v1",
            decision="AUTHORIZED", reasons=())
        self.assertEqual(plan["observation_type"], "HTTP_METADATA")

    def test_plan_lists_limits(self):
        from aec.runtime.execution.runtime import build_plan

        plan = build_plan(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", policy_version="v1",
            decision="AUTHORIZED", reasons=())
        self.assertIn("limits", plan)
        self.assertIn("request_timeout_seconds", plan["limits"])

    def test_plan_lists_expected_evidence(self):
        from aec.runtime.execution.runtime import build_plan

        plan = build_plan(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", policy_version="v1",
            decision="AUTHORIZED", reasons=())
        self.assertIn("expected_evidence", plan)
        self.assertIn("HTTP_METADATA", plan["expected_evidence"])

    def test_plan_lists_refusal_reason(self):
        from aec.runtime.execution.runtime import build_plan

        plan = build_plan(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", policy_version="v1",
            decision="REFUSED", reasons=("TYPE_UNKNOWN",))
        self.assertEqual(plan["refusal_reason"], "TYPE_UNKNOWN")

    def test_plan_dry_run_flag(self):
        from aec.runtime.execution.runtime import build_plan

        plan = build_plan(
            valid_request(), valid_authz(), valid_target(),
            mode="DRY_RUN", policy_version="v1",
            decision="AUTHORIZED", reasons=())
        self.assertTrue(plan["dry_run"])


if __name__ == "__main__":
    unittest.main()