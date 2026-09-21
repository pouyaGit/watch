"""EPIC7 Part 20: end-to-end deterministic acceptance scenarios A–N."""

from __future__ import annotations

import unittest


class _NoNetwork(Exception):
    pass


class ExplodingTransport:
    def __call__(self, *args, **kwargs):
        raise _NoNetwork("transport invoked in fixture/dry-run mode")


class FakeTransport:
    def __init__(self, status=200, headers=None, body=b"ok",
                 timing_ms=5):
        self.status = status
        self.headers = headers or {"content-type": "text/plain"}
        self.body = body
        self.timing_ms = timing_ms
        self.calls = 0

    def __call__(self, target, request, limits):
        self.calls += 1
        return {"status": self.status, "headers": dict(self.headers),
                "body": self.body, "timing_ms": self.timing_ms}


def request(**overrides):
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
    base.update(overrides)
    return base


def authz(**overrides):
    base = {
        "status": "GRANTED",
        "expires_tick": 100,
        "authorization_reference": "authz-123",
        "target_id": "tgt-000000000001",
        "case_id": "case-123",
    }
    base.update(overrides)
    return base


def target():
    from aec.runtime.adapters.target import resolve_target

    return resolve_target(
        {"host": "shop.example.com", "scheme": "https",
         "endpoint": "/orders", "port": None, "source": "watch",
         "authorization_reference": "authz-123"},
        scope_hosts=frozenset({"shop.example.com"}))


class TestScenarioA(unittest.TestCase):
    def test_valid_authz_in_scope_http_metadata(self):
        from aec.runtime.execution.runtime import execute

        transport = FakeTransport()
        result = execute(
            request(), authz(), target(),
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=transport)
        self.assertTrue(result.executed)
        self.assertEqual(result.state, "COMPLETED")
        self.assertIsNotNone(result.evidence)


class TestScenarioB(unittest.TestCase):
    def test_missing_authz_refused(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            request(), None, target(),
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=FakeTransport())
        self.assertEqual(result.decision, "BLOCKED")
        self.assertFalse(result.executed)


class TestScenarioC(unittest.TestCase):
    def test_expired_authz_blocked(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            request(), authz(status="EXPIRED"), target(),
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=FakeTransport())
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("AUTHORIZATION_EXPIRED", result.reasons)
        self.assertFalse(result.executed)


class TestScenarioD(unittest.TestCase):
    def test_out_of_scope_host_refused(self):
        from aec.runtime.adapters.target import resolve_target
        from aec.runtime.execution.runtime import execute

        evil = resolve_target(
            {"host": "evil.example.com", "scheme": "https",
             "endpoint": "/x", "port": None, "source": "watch",
             "authorization_reference": "authz-999"},
            scope_hosts=frozenset({"evil.example.com"}))
        result = execute(
            request(target_id=evil.target_id,
                    authorization_reference="authz-999"),
            authz(authorization_reference="authz-999",
                  target_id=evil.target_id), evil,
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=FakeTransport(),
            scope_hosts=frozenset({"shop.example.com"}))
        self.assertEqual(result.decision, "REFUSED")
        self.assertFalse(result.executed)


class TestScenarioE(unittest.TestCase):
    def test_redirect_out_of_scope_refused(self):
        from aec.runtime.adapters.http_observation import (
            RedirectLimit, check_redirect)

        with self.assertRaises(RedirectLimit):
            check_redirect("https://attacker.example.com/x",
                           "shop.example.com",
                           frozenset({"shop.example.com"}))


class TestScenarioF(unittest.TestCase):
    def test_unsupported_observation_refused(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            request(observation_type="HTTP_EXPLOIT"), authz(), target(),
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=FakeTransport())
        self.assertEqual(result.decision, "REFUSED")
        self.assertFalse(result.executed)


class TestScenarioG(unittest.TestCase):
    def test_duplicate_no_second_execution(self):
        from aec.runtime.execution.idempotency import IdempotencyGuard
        from aec.runtime.execution.runtime import execute

        guard = IdempotencyGuard()
        transport = FakeTransport()
        first = execute(
            request(), authz(), target(),
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=transport, guard=guard)
        self.assertTrue(first.executed)
        second = execute(
            request(), authz(), target(),
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=transport, guard=guard)
        self.assertFalse(second.executed)
        self.assertEqual(second.decision, "BLOCKED")
        self.assertEqual(transport.calls, 1)


class TestScenarioH(unittest.TestCase):
    def test_dry_run_zero_network(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            request(), authz(), target(),
            mode="DRY_RUN", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=ExplodingTransport())
        self.assertFalse(result.executed)
        self.assertIsNotNone(result.plan)


class TestScenarioI(unittest.TestCase):
    def test_fixture_zero_network(self):
        from aec.runtime.execution.runtime import execute

        result = execute(
            request(), authz(), target(),
            mode="LIVE_OBSERVATION", source_mode="OFFLINE_FIXTURE",
            policy_version="v1", transport=ExplodingTransport())
        self.assertFalse(result.executed)
        self.assertIn("FIXTURE_CANNOT_EXECUTE", result.reasons)


class TestScenarioJ(unittest.TestCase):
    def test_sensitive_headers_redacted(self):
        from aec.runtime.execution.runtime import execute

        transport = FakeTransport(
            headers={"content-type": "text/plain",
                     "authorization": "Bearer abc123secret"})
        result = execute(
            request(), authz(), target(),
            mode="LIVE_OBSERVATION", source_mode="REAL_WATCH_DATA",
            policy_version="v1", transport=transport)
        joined = str(result.to_dict())
        self.assertNotIn("abc123secret", joined)


class TestScenarioK(unittest.TestCase):
    def test_timeout_timed_out(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("HTTP_TIMEOUT"), "TIMED_OUT")


class TestScenarioL(unittest.TestCase):
    def test_response_exceeds_limit_blocked(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("RESPONSE_TOO_LARGE"), "BLOCKED")


class TestScenarioM(unittest.TestCase):
    def test_valid_observation_to_analysis_pending(self):
        from aec.runtime.integrate import (
            advance_analysis_pending, advance_evidence_pending,
            advance_to_observation_running)
        from aec.runtime.jobs import create_job, transition

        job = create_job(job_id="job-123", case_id="case-123",
                         candidate_id="srv-1",
                         source_mode="REAL_WATCH_DATA")
        job = transition(job, "QUEUED", "q", "pipeline", 1)
        job = transition(job, "ASSIGNED", "a", "pipeline", 2)
        job = transition(job, "WAITING_AUTHORIZATION", "w", "gate", 3)
        job = transition(job, "READY_FOR_OBSERVATION", "r", "gate", 4)
        job = advance_to_observation_running(job, 5)
        job = advance_evidence_pending(job, 6)
        job = advance_analysis_pending(job, 7)
        self.assertEqual(job.state, "ANALYSIS_PENDING")


class TestScenarioN(unittest.TestCase):
    def test_replay_deterministic_output(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append({"request_id": "r1", "decision": "AUTHORIZED",
                      "execution_state": "DISPATCHED"})
        trail.append({"request_id": "r2", "decision": "REFUSED",
                      "execution_state": "REFUSED"})
        self.assertEqual(trail.replay(), ("AUTHORIZED", "REFUSED"))
        self.assertTrue(trail.verify())


if __name__ == "__main__":
    unittest.main()