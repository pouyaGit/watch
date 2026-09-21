"""EPIC6 Part 4: execution bridge — authorization boundary, request minting."""

from __future__ import annotations

import unittest

from aec.execution.executor import (
    REFUSAL_CODES, RETRYABLE, classify_failure, ingest_result, is_timed_out,
    submit_plan)
from aec.execution.models import (
    IngestionRefusal, SubmissionRefusal)

GRANTED_AUTHZ = {"status": "GRANTED", "expires_tick": 100}

PLAN = {
    "plan_id": "plan-1",
    "case_id": "case-1",
    "steps": [{"step_id": "s1", "endpoint": "/orders",
               "method": "GET", "purpose": "BASELINE"}],
}

RESULT = {
    "observation_id": "obs-1",
    "request_id": "obsreq-abc",
    "observed_fields": ["status_code", "content_type"],
    "missing_fields": [],
    "tick": 5,
    "source": "fixture-observer",
}


class TestSubmissionRefusals(unittest.TestCase):
    def test_refusal_codes_closed(self):
        self.assertEqual(
            REFUSAL_CODES, ("EMPTY_PLAN", "EMPTY_STEPS", "BAD_TICK",
                            "EMPTY_JOB"))

    def test_empty_job_refused(self):
        with self.assertRaises(SubmissionRefusal):
            submit_plan("", PLAN, "ALLOW", GRANTED_AUTHZ, ["baseline-observe"], 0)

    def test_non_mapping_plan_refused(self):
        with self.assertRaises(SubmissionRefusal):
            submit_plan("job-1", "not-a-plan", "ALLOW", GRANTED_AUTHZ,
                        ["baseline-observe"], 0)

    def test_missing_plan_id_refused(self):
        bad = dict(PLAN)
        del bad["plan_id"]
        with self.assertRaises(SubmissionRefusal):
            submit_plan("job-1", bad, "ALLOW", GRANTED_AUTHZ,
                        ["baseline-observe"], 0)

    def test_empty_steps_refused(self):
        bad = dict(PLAN, steps=[])
        with self.assertRaises(SubmissionRefusal):
            submit_plan("job-1", bad, "ALLOW", GRANTED_AUTHZ,
                        ["baseline-observe"], 0)

    def test_bad_tick_refused(self):
        with self.assertRaises(SubmissionRefusal):
            submit_plan("job-1", PLAN, "ALLOW", GRANTED_AUTHZ,
                        ["baseline-observe"], -1)


class TestAuthorizationBoundary(unittest.TestCase):
    def outcome(self, gate="ALLOW", authz=None, capabilities=None, tick=0):
        return submit_plan(
            "job-1", PLAN, gate,
            authz if authz is not None else GRANTED_AUTHZ,
            capabilities if capabilities is not None
            else ["baseline-observe"], tick)

    def test_gate_not_allowed_blocks(self):
        result = self.outcome(gate="REFUSE")
        self.assertEqual(result.disposition, "BLOCKED")
        self.assertEqual(result.job_transition, "BLOCKED")
        self.assertIn("GATE_NOT_ALLOWED", result.reason)

    def test_missing_authz_waits(self):
        result = self.outcome(authz={"status": "MISSING"})
        self.assertEqual(result.disposition, "WAITING_AUTHORIZATION")
        self.assertEqual(result.job_transition, "WAITING_AUTHORIZATION")

    def test_denied_authz_blocks(self):
        result = self.outcome(authz={"status": "DENIED"})
        self.assertEqual(result.disposition, "BLOCKED")
        self.assertEqual(result.reason, "AUTHORIZATION_DENIED")

    def test_expired_status_expires(self):
        result = self.outcome(authz={"status": "EXPIRED"})
        self.assertEqual(result.disposition, "EXPIRED")

    def test_expired_by_tick(self):
        result = self.outcome(authz={"status": "GRANTED", "expires_tick": 4},
                              tick=6)
        self.assertEqual(result.disposition, "EXPIRED")
        self.assertEqual(result.job_transition, "EXPIRED")

    def test_granted_within_window_ok(self):
        result = self.outcome(authz={"status": "GRANTED", "expires_tick": 10},
                              tick=5)
        self.assertEqual(result.disposition, "OBSERVATION_REQUESTED")

    def test_unknown_authz_status_blocks(self):
        result = self.outcome(authz={"status": "MAYBE"})
        self.assertEqual(result.disposition, "BLOCKED")
        self.assertIn("unknown authorization status", result.reason)

    def test_missing_capability_blocks_requires_observation(self):
        result = self.outcome(capabilities=[])
        self.assertEqual(result.disposition, "BLOCKED")
        self.assertTrue(result.requires_observation)

    def test_no_bypass_without_grant(self):
        for authz in ({"status": "MISSING"}, {"status": "DENIED"},
                      {"status": "EXPIRED"}):
            result = self.outcome(authz=authz)
            self.assertNotEqual(result.disposition, "OBSERVATION_REQUESTED")


class TestObservationRequest(unittest.TestCase):
    def test_request_id_minted(self):
        result = self.request()
        self.assertTrue(result.request["request_id"].startswith("obsreq-"))
        self.assertEqual(len(result.request["request_id"]), 19)

    def request(self, tick=0):
        return submit_plan("job-1", PLAN, "ALLOW", GRANTED_AUTHZ,
                           ["baseline-observe"], tick)

    def test_request_fields(self):
        result = self.request(tick=3)
        request = result.request
        self.assertEqual(request["job_id"], "job-1")
        self.assertEqual(request["plan_id"], "plan-1")
        self.assertEqual(request["tick"], 3)
        self.assertIn("steps", request)

    def test_request_actions_are_descriptions_only(self):
        result = self.request()
        for action in result.request["steps"]:
            self.assertEqual(sorted(action), ["endpoint", "purpose",
                                              "step_id"])

    def test_no_url_ever_minted(self):
        result = self.request()
        blob = str(result.request)
        self.assertNotIn("://", blob)

    def test_transition_running(self):
        result = self.request()
        self.assertEqual(result.job_transition, "OBSERVATION_RUNNING")

    def test_request_deterministic(self):
        first = self.request(tick=2).to_dict()
        second = self.request(tick=2).to_dict()
        self.assertEqual(first, second)

    def test_disposition_label(self):
        self.assertEqual(self.request().disposition, "OBSERVATION_REQUESTED")


class TestResultIngestion(unittest.TestCase):
    def request(self):
        return submit_plan("job-1", PLAN, "ALLOW", GRANTED_AUTHZ,
                           ["baseline-observe"], 0).request

    def test_accepted_result_pending(self):
        request = self.request()
        result = dict(RESULT, request_id=request["request_id"])
        outcome = ingest_result(request, result)
        self.assertEqual(outcome.disposition, "EVIDENCE_PENDING")
        self.assertEqual(outcome.job_transition, "EVIDENCE_PENDING")

    def test_duplicate_observation_refused(self):
        request = self.request()
        result = dict(RESULT, request_id=request["request_id"])
        outcome = ingest_result(
            request, result, seen_observation_ids={"obs-1"})
        self.assertEqual(outcome.disposition, "DUPLICATE_OBSERVATION")
        self.assertEqual(outcome.job_transition, "")

    def test_duplicate_observed_twice(self):
        request = self.request()
        result = dict(RESULT, request_id=request["request_id"])
        outcome = ingest_result(request, result)
        outcome = ingest_result(request, result,
                                seen_observation_ids={result["observation_id"]})
        self.assertEqual(outcome.disposition, "DUPLICATE_OBSERVATION")

    def test_wrong_request_refused(self):
        bad = dict(RESULT, request_id="obsreq-other")
        with self.assertRaises(IngestionRefusal):
            ingest_result(self.request(), bad)

    def test_missing_request_id_in_request(self):
        with self.assertRaises(IngestionRefusal):
            ingest_result({"plan_id": "plan-1"}, RESULT)

    def test_non_mapping_result_refused(self):
        with self.assertRaises(IngestionRefusal):
            ingest_result(self.request(), "result")

    def test_missing_observation_id_refused(self):
        bad = dict(RESULT)
        del bad["observation_id"]
        with self.assertRaises(IngestionRefusal):
            ingest_result(self.request(), bad)

    def test_empty_observed_fields_refused(self):
        bad = dict(RESULT, observed_fields=[])
        with self.assertRaises(IngestionRefusal):
            ingest_result(self.request(), bad)


class TestTimeoutAndRetry(unittest.TestCase):
    def test_timeout_detection(self):
        self.assertTrue(is_timed_out(start_tick=0, now_tick=11, timeout_ticks=10))
        self.assertFalse(is_timed_out(start_tick=0, now_tick=10, timeout_ticks=10))

    def test_retryable_set(self):
        self.assertEqual(RETRYABLE,
                         frozenset({"TIMEOUT", "INGESTION_ERROR",
                                    "OBSERVATION_ERROR"}))

    def test_classify_retryable(self):
        for kind in ("TIMEOUT", "INGESTION_ERROR", "OBSERVATION_ERROR"):
            self.assertEqual(classify_failure(kind), "RETRYABLE")

    def test_classify_terminal(self):
        for kind in ("EXECUTION_REFUSAL", "AUTHORIZATION_DENIED", "FAILED"):
            self.assertEqual(classify_failure(kind), "TERMINAL")


class TestOutcomeModel(unittest.TestCase):
    def test_outcome_to_dict(self):
        result = submit_plan("job-1", PLAN, "ALLOW", GRANTED_AUTHZ,
                             ["baseline-observe"], 0)
        document = result.to_dict()
        self.assertEqual(sorted(document), [
            "disposition", "job_transition", "reason", "request",
            "requires_observation"])

    def test_outcome_frozen(self):
        result = submit_plan("job-1", PLAN, "ALLOW", GRANTED_AUTHZ,
                             ["baseline-observe"], 0)
        with self.assertRaises(Exception):
            result.disposition = "X"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()