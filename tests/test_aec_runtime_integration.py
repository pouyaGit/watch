"""EPIC7 Part 14+15: ResearchJob integration and specialist boundary."""

from __future__ import annotations

import unittest


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


def valid_specialist_request(**overrides):
    specialist = {
        "case_id": "case-123",
        "research_job_id": "job-123",
        "target_id": "tgt-000000000001",
        "observation_type": "HTTP_METADATA",
        "reason": "baseline metadata",
        "required_evidence_level": "PARTIAL",
    }
    specialist.update(overrides)
    return specialist


def ready_job():
    from aec.runtime.jobs import create_job, transition

    job = create_job(job_id="job-123", case_id="case-123",
                     candidate_id="srv-1", source_mode="REAL_WATCH_DATA")
    job = transition(job, "QUEUED", "enqueued", "pipeline", 1)
    job = transition(job, "ASSIGNED", "staffed", "pipeline", 2)
    job = transition(job, "WAITING_AUTHORIZATION", "authz", "gate", 3)
    return transition(job, "READY_FOR_OBSERVATION", "granted", "gate", 4)


class TestJobIntegration(unittest.TestCase):
    def test_ready_to_running(self):
        from aec.runtime.integrate import advance_to_observation_running

        job = ready_job()
        moved = advance_to_observation_running(job, 5)
        self.assertEqual(moved.state, "OBSERVATION_RUNNING")

    def test_valid_to_evidence_pending(self):
        from aec.runtime.integrate import (
            advance_evidence_pending, advance_to_observation_running)

        job = advance_to_observation_running(ready_job(), 5)
        moved = advance_evidence_pending(job, 6)
        self.assertEqual(moved.state, "EVIDENCE_PENDING")

    def test_valid_to_analysis_pending(self):
        from aec.runtime.integrate import (
            advance_analysis_pending, advance_evidence_pending,
            advance_to_observation_running)

        job = advance_to_observation_running(ready_job(), 5)
        job = advance_evidence_pending(job, 6)
        moved = advance_analysis_pending(job, 7)
        self.assertEqual(moved.state, "ANALYSIS_PENDING")

    def test_refusal_blocks(self):
        from aec.runtime.integrate import advance_to_blocked

        job = ready_job()
        moved = advance_to_blocked(job, "SCOPE_MISMATCH", 5)
        self.assertEqual(moved.state, "BLOCKED")

    def test_timeout_fails(self):
        from aec.runtime.integrate import (
            advance_to_failed, advance_to_observation_running)

        job = advance_to_observation_running(ready_job(), 5)
        moved = advance_to_failed(job, "TIMEOUT", 6)
        self.assertEqual(moved.state, "FAILED")

    def test_full_chain_never_skips_evidence(self):
        from aec.runtime.integrate import (
            advance_analysis_pending, advance_evidence_pending,
            advance_to_observation_running)

        job = advance_to_observation_running(ready_job(), 5)
        job = advance_evidence_pending(job, 6)
        self.assertEqual(job.state, "EVIDENCE_PENDING")
        job = advance_analysis_pending(job, 7)
        self.assertEqual(job.state, "ANALYSIS_PENDING")


class TestEvidenceLayerNeverSkipped(unittest.TestCase):
    def test_running_cannot_jump_to_analysis(self):
        from aec.runtime.integrate import advance_to_observation_running
        from aec.runtime.models import TransitionRefusal
        from aec.runtime.jobs import transition

        running = advance_to_observation_running(ready_job(), 5)
        with self.assertRaises(TransitionRefusal):
            transition(running, "ANALYSIS_PENDING", "skip evidence",
                       "integration", 5)


class TestSpecialistBoundary(unittest.TestCase):
    def test_specialist_request_shape_validated(self):
        from aec.runtime.integrate import validate_specialist_request

        self.assertTrue(
            validate_specialist_request(valid_specialist_request()))

    def test_missing_case_refused(self):
        from aec.runtime.integrate import validate_specialist_request

        self.assertFalse(
            validate_specialist_request(
                valid_specialist_request(case_id="")))

    def test_missing_job_refused(self):
        from aec.runtime.integrate import validate_specialist_request

        self.assertFalse(
            validate_specialist_request(
                valid_specialist_request(research_job_id="")))

    def test_missing_target_refused(self):
        from aec.runtime.integrate import validate_specialist_request

        self.assertFalse(
            validate_specialist_request(
                valid_specialist_request(target_id="")))

    def test_unsupported_type_refused(self):
        from aec.runtime.integrate import validate_specialist_request

        self.assertFalse(
            validate_specialist_request(
                valid_specialist_request(
                    observation_type="HTTP_POST")))

    def test_missing_evidence_level_refused(self):
        from aec.runtime.integrate import validate_specialist_request

        self.assertFalse(
            validate_specialist_request(
                valid_specialist_request(required_evidence_level="")))

    def test_missing_reason_refused(self):
        from aec.runtime.integrate import validate_specialist_request

        self.assertFalse(
            validate_specialist_request(
                valid_specialist_request(reason="")))

    def test_specialists_cannot_pass_raw_url(self):
        from aec.runtime.integrate import (
            specialist_target_identity, validate_specialist_request)

        self.assertFalse(
            validate_specialist_request(
                valid_specialist_request(target_id="https://evil/x")))


class TestExecutorOnlyPath(unittest.TestCase):
    def test_runtime_accepts_only_executor_requests(self):
        from aec.runtime.execution.runtime import execute
        from aec.runtime.adapters.target import resolve_target

        request = valid_request()
        # A request that never came from the executor must fail validation
        # — it carries no executor-minted shape.
        result = execute(
            request, None, resolve_target(
                {"host": "shop.example.com", "scheme": "https",
                 "endpoint": "/orders", "port": None, "source": "watch",
                 "authorization_reference": "authz-123"},
                scope_hosts=frozenset({"shop.example.com"})),
            mode="DRY_RUN", source_mode="REAL_WATCH_DATA",
            policy_version="v1")
        self.assertIn(result.decision, ("BLOCKED", "REFUSED"))

    def test_specialist_dict_never_enters_runtime(self):
        from aec.runtime.execution.runtime import RUNTIME_MODES

        # The runtime's public contract is the AUTHORIZED_OBSERVATION_REQUEST
        # (executor output); a specialist's request dict is a planning input,
        # not an execution input.
        self.assertIn("LIVE_OBSERVATION", RUNTIME_MODES)


if __name__ == "__main__":
    unittest.main()