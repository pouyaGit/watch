"""EPIC6 Part 6+8: deterministic research loop + ExecutionRun model."""

from __future__ import annotations

import unittest

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

GRANTED = {"status": "GRANTED", "expires_tick": 100}


def authz_by_candidate(*candidates):
    return {candidate["id"]: GRANTED for candidate in candidates}


class TestRunBasics(unittest.TestCase):
    def test_run_id_minted(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        self.assertTrue(run.run_id.startswith("run-"))
        self.assertEqual(len(run.run_id), 16)

    def test_source_mode_recorded(self):
        from aec.runtime import loop

        watch = loop.run_execution([WATCH_RECORD], origin="watch",
                                   authz=authz_by_candidate(WATCH_RECORD))
        fixture = loop.run_execution([WATCH_RECORD], origin="fixture",
                                     authz=authz_by_candidate(WATCH_RECORD))
        self.assertEqual(watch.source_mode, "REAL_WATCH_DATA")
        self.assertEqual(fixture.source_mode, "OFFLINE_FIXTURE")

    def test_unknown_origin_refused(self):
        from aec.runtime import loop

        with self.assertRaises(ValueError):
            loop.run_execution([WATCH_RECORD], origin="live",
                               authz={})

    def test_candidate_count_matches(self):
        from aec.runtime import loop

        records = [dict(WATCH_RECORD, id=f"srv-{index}")
                   for index in range(3)]
        run = loop.run_execution(records, origin="fixture",
                                 authz=authz_by_candidate(*records))
        self.assertEqual(run.candidate_count, 3)

    def test_every_candidate_has_job(self):
        from aec.runtime import loop

        records = [dict(WATCH_RECORD, id=f"srv-{index}")
                   for index in range(2)]
        run = loop.run_execution(records, origin="fixture",
                                 authz=authz_by_candidate(*records))
        self.assertEqual(run.job_count, 2)
        self.assertEqual(len(run.jobs), 2)

    def test_job_source_mode_matches_run(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="watch",
                                 authz=authz_by_candidate(WATCH_RECORD))
        for job in run.jobs:
            self.assertEqual(job.source_mode, "REAL_WATCH_DATA")

    def test_ticks_advance(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        self.assertGreaterEqual(run.completed_at, run.started_at)
        self.assertEqual(run.duration, run.completed_at - run.started_at)

    def test_duration_nonnegative(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        self.assertGreaterEqual(run.duration, 0)

    def test_deterministic_replay_identity(self):
        from aec.runtime import loop

        first = loop.run_execution([WATCH_RECORD], origin="fixture",
                                   authz=authz_by_candidate(WATCH_RECORD))
        second = loop.run_execution([WATCH_RECORD], origin="fixture",
                                    authz=authz_by_candidate(WATCH_RECORD))
        self.assertEqual(first.replay_identity, second.replay_identity)
        self.assertTrue(first.replay_identity)

    def test_identity_changes_with_origin(self):
        from aec.runtime import loop

        watch = loop.run_execution([WATCH_RECORD], origin="watch",
                                   authz=authz_by_candidate(WATCH_RECORD))
        fixture = loop.run_execution([WATCH_RECORD], origin="fixture",
                                     authz=authz_by_candidate(WATCH_RECORD))
        self.assertNotEqual(watch.replay_identity, fixture.replay_identity)


class TestAuthorizationStates(unittest.TestCase):
    def test_missing_authz_waits(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], origin="fixture",
            authz={WATCH_RECORD["id"]: {"status": "MISSING"}})
        job = run.jobs[0]
        self.assertEqual(job.state, "WAITING_AUTHORIZATION")
        self.assertEqual(run.waiting_authorization_count, 1)

    def test_denied_authz_blocks(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], origin="fixture",
            authz={WATCH_RECORD["id"]: {"status": "DENIED"}})
        job = run.jobs[0]
        self.assertEqual(job.state, "BLOCKED")
        self.assertEqual(run.blocked_count, 1)

    def test_expired_authz_expires(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], origin="fixture",
            authz={WATCH_RECORD["id"]: {"status": "GRANTED", "expires_tick": 1}})
        job = run.jobs[0]
        self.assertEqual(job.state, "EXPIRED")

    def test_granted_reaches_observation(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        job = run.jobs[0]
        self.assertIn(job.state, ("OBSERVATION_RUNNING", "EVIDENCE_PENDING",
                                  "ANALYSIS_PENDING", "REVIEW_REQUIRED",
                                  "COMPLETED"))
        self.assertGreaterEqual(run.observation_count, 1)

    def test_missing_capability_blocks(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], origin="fixture",
            authz=authz_by_candidate(WATCH_RECORD),
            capabilities=())
        job = run.jobs[0]
        self.assertEqual(job.state, "BLOCKED")

    def test_blocking_reason_recorded(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], origin="fixture",
            authz={WATCH_RECORD["id"]: {"status": "DENIED"}})
        self.assertTrue(run.blocked_reasons)
        reason = run.blocked_reasons[0]
        self.assertIn("case_id", reason)
        self.assertIn("reason", reason)
        self.assertIn("AUTHORIZATION_DENIED", reason["reason"])

    def test_no_silent_drop_of_blocked(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], origin="fixture",
            authz={WATCH_RECORD["id"]: {"status": "DENIED"}})
        self.assertEqual(run.blocked_count + run.failed_count, 1)


class TestEvidenceFlow(unittest.TestCase):
    def test_evidence_ingested(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        self.assertGreaterEqual(run.evidence_count, 1)
        self.assertTrue(run.evidence)

    def test_evidence_records_carry_mode(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        for record in run.evidence:
            self.assertEqual(record.source_mode, "OFFLINE_FIXTURE")

    def test_evidence_tied_to_job_and_case(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        job = run.jobs[0]
        for record in run.evidence:
            self.assertEqual(record.job_id, job.job_id)
            self.assertEqual(record.case_id, job.case_id)

    def test_timeout_fails_job(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], origin="fixture",
            authz=authz_by_candidate(WATCH_RECORD),
            timeout_ticks=0)
        self.assertGreaterEqual(run.failed_count, 1)
        self.assertIn("TIMEOUT", run.failures[0]["kind"])


class TestReviewBoundary(unittest.TestCase):
    def test_complete_evidence_forces_review(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        self.assertGreaterEqual(run.review_required_count, 1)

    def test_review_records_have_reasons(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        for record in run.review_records:
            self.assertTrue(record["reason"])

    def test_policy_review_flag(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], origin="fixture",
            authz=authz_by_candidate(WATCH_RECORD),
            policy_review=True)
        self.assertGreaterEqual(run.review_required_count, 1)

    def test_review_never_skipped_for_review_required_job(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], origin="fixture",
                                 authz=authz_by_candidate(WATCH_RECORD))
        review_jobs = {record["job_id"] for record in run.review_records}
        for job in run.jobs:
            if job.state == "REVIEW_REQUIRED":
                self.assertIn(job.job_id, review_jobs)


class TestPartialFailure(unittest.TestCase):
    def test_one_bad_candidate_others_continue(self):
        from aec.runtime import loop

        good = dict(WATCH_RECORD, id="srv-good")
        bad = {"subdomain": "broken.example", "endpoint": ""}
        run = loop.run_execution([good, bad], origin="fixture",
                                 authz=authz_by_candidate(good))
        self.assertGreaterEqual(run.failed_count, 1)
        self.assertGreaterEqual(run.job_count, 1)
        self.assertEqual(run.candidate_count, 2)

    def test_seen_observation_deduplicated(self):
        from aec.runtime import loop

        records = [dict(WATCH_RECORD, id=f"srv-{index}")
                   for index in range(2)]
        run = loop.run_execution(records, origin="fixture",
                                 authz=authz_by_candidate(*records))
        observation_ids = [record.evidence_id for record in run.evidence]
        self.assertEqual(len(observation_ids), len(set(observation_ids)))


class TestSummaries(unittest.TestCase):
    def build_run(self):
        from aec.runtime import loop

        return loop.run_execution([WATCH_RECORD], origin="fixture",
                                  authz=authz_by_candidate(WATCH_RECORD))

    def test_machine_summary_counts(self):
        run = self.build_run()
        summary = run.machine_summary()
        self.assertEqual(summary["run_id"], run.run_id)
        self.assertEqual(summary["source_mode"], "OFFLINE_FIXTURE")
        self.assertEqual(summary["candidate_count"], 1)
        self.assertEqual(summary["case_count"], run.case_count)
        self.assertEqual(summary["job_count"], run.job_count)

    def test_machine_summary_is_json_serializable(self):
        import json

        run = self.build_run()
        json.dumps(run.machine_summary())

    def test_human_summary_is_text(self):
        run = self.build_run()
        text = run.human_summary()
        self.assertIsInstance(text, str)
        self.assertIn("OFFLINE_FIXTURE", text)
        self.assertIn(run.run_id, text)

    def test_run_to_dict(self):
        run = self.build_run()
        document = run.to_dict()
        self.assertEqual(document["source_mode"], "OFFLINE_FIXTURE")
        self.assertEqual(len(document["jobs"]), run.job_count)

    def test_no_production_claims_in_summary(self):
        run = self.build_run()
        text = run.human_summary().lower()
        for marker in ("confirmed", "finding", "verdict"):
            self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main()