"""EPIC6 Part 11+15: failure handling, recovery, acceptance scenarios."""

from __future__ import annotations

import unittest

GRANTED = {"status": "GRANTED", "expires_tick": 100}

WATCH_RECORD = {
    "subdomain": "shop.example.com",
    "url": "/orders?order_id=",
    "endpoint": "/orders",
    "parameter": "order_id",
    "method": "GET",
    "location": "query",
    "technology": ["flask"],
    "source": "watch",
    "id": "srv-1",
    "category": "IDOR_CANDIDATE",
}


def realize(record, **overrides):
    copy = dict(record)
    copy.update(overrides)
    return copy


class TestFailureKinds(unittest.TestCase):
    def test_malformed_candidate_recorded(self):
        from aec.runtime import loop

        run = loop.run_execution([{"endpoint": ""}], "fixture", {})
        kinds = {failure["kind"] for failure in run.failures}
        self.assertIn("MALFORMED_CANDIDATE", kinds)

    def test_missing_case_recorded(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={}, drop_case=True)
        self.assertTrue(run.failures)
        self.assertIn("MISSING_CASE", {f["kind"] for f in run.failures})

    def test_missing_authorization_is_wait_not_failure(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "MISSING"}})
        self.assertEqual(run.waiting_authorization_count, 1)
        self.assertNotIn(
            "AUTHORIZATION", {f["kind"] for f in run.failures})

    def test_unsupported_specialist_recorded(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED},
            registry_override="none")
        self.assertTrue(run.failures)
        self.assertIn("UNSUPPORTED_SPECIALIST",
                      {f["kind"] for f in run.failures})

    def test_evidence_ingestion_failure_recorded(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED},
            corrupt_observation=True)
        self.assertTrue(run.failures)
        self.assertIn("EVIDENCE_INGESTION",
                      {f["kind"] for f in run.failures})

    def test_execution_refusal_recorded(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "DENIED"}})
        self.assertGreaterEqual(run.blocked_count, 1)
        self.assertIn("AUTHORIZATION_DENIED",
                      {r["reason"] for r in run.blocked_reasons})


class TestRecovery(unittest.TestCase):
    def test_retry_classification_of_jobs(self):
        from aec.runtime import recovery

        kind = recovery.classify("TIMEOUT")
        self.assertEqual(kind, "RETRYABLE")

    def test_terminal_classification(self):
        from aec.runtime import recovery

        kind = recovery.classify("AUTHORIZATION_DENIED")
        self.assertEqual(kind, "TERMINAL")

    def test_recovery_plan_for_partial_run(self):
        from aec.runtime import loop, recovery

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "DENIED"}})
        plan = recovery.recovery_plan(run)
        self.assertIsInstance(plan, list)
        for entry in plan:
            self.assertIn("job_id", entry)
            self.assertIn("action", entry)

    def test_recovery_never_invents_authorization(self):
        from aec.runtime import loop, recovery

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "DENIED"}})
        plan = recovery.recovery_plan(run)
        for entry in plan:
            self.assertNotEqual(entry["action"], "BYPASS_AUTHORIZATION")

    def test_retryable_budget_respected(self):
        from aec.runtime import recovery

        self.assertTrue(recovery.retryable("TIMEOUT", attempts=1))
        self.assertFalse(recovery.retryable("TIMEOUT", attempts=3))


class TestAcceptanceScenarios(unittest.TestCase):
    """EPIC6 Part 15 scenarios A-J, deterministic."""

    def test_A_waiting_authorization(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "MISSING"}})
        self.assertEqual(run.jobs[0].state, "WAITING_AUTHORIZATION")

    def test_B_authorization_denied_blocked(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "DENIED"}})
        self.assertEqual(run.jobs[0].state, "BLOCKED")

    def test_C_authorization_expired(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "GRANTED",
                                        "expires_tick": 0}})
        self.assertEqual(run.jobs[0].state, "EXPIRED")

    def test_D_observation_to_review(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        self.assertGreaterEqual(run.observation_count, 1)
        self.assertGreaterEqual(run.evidence_count, 1)
        self.assertGreaterEqual(run.review_required_count, 1)

    def test_E_insufficient_evidence_outcome(self):
        from aec.specialists import analysis
        from aec.specialists.registry import default_registry, lookup

        profile = lookup(default_registry(), "input-researcher")
        opinion = analysis.analyze(profile, {
            "job_id": "job-1", "category": "XSS_CANDIDATE",
            "evidence_level": "NONE",
        }, [{"coverage": "PARTIAL"}])
        self.assertEqual(opinion.outcome, "INSUFFICIENT_EVIDENCE")

    def test_F_duplicate_candidate_deduplicated(self):
        from aec.runtime import loop

        first = realize(WATCH_RECORD, id="srv-1")
        duplicate = realize(WATCH_RECORD, id="srv-1")
        run = loop.run_execution(
            [first, duplicate], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED})
        self.assertEqual(run.job_count, 1)
        self.assertGreaterEqual(run.deduplicated_count, 1)

    def test_G_partial_failure_others_continue(self):
        from aec.runtime import loop

        good = realize(WATCH_RECORD, id="srv-good")
        bad = {"subdomain": "x.example", "endpoint": ""}
        run = loop.run_execution(
            [good, bad], "fixture",
            authz={good["id"]: GRANTED})
        self.assertGreaterEqual(run.failed_count, 1)
        self.assertGreaterEqual(run.completed_count +
                                run.review_required_count, 1)

    def test_H_byte_identical_replay(self):
        from aec.replay import kernel
        from aec.runtime import loop

        original = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED})
        replayed = kernel.replay(original, run_research=loop.run_execution)
        self.assertEqual(
            kernel.serialize_run(original), kernel.serialize_run(replayed))

    def test_I_fixture_never_production_finding(self):
        from aec.research.guard import promotable_to_production

        run_document = {
            "source_mode": "OFFLINE_FIXTURE",
            "outcome": "POTENTIAL",
        }
        self.assertFalse(promotable_to_production(run_document))

    def test_J_conflicting_outputs_review(self):
        from aec.specialists import analysis

        comparison = analysis.detect_disagreement([
            analysis.Opinion("job-1", "a", "POTENTIAL", "low", "x"),
            analysis.Opinion("job-1", "b", "REVIEW_REQUIRED", "high", "y"),
        ])
        self.assertTrue(comparison.review_required)


if __name__ == "__main__":
    unittest.main()