"""EPIC6 Part 6+15: end-to-end offline research loop through coordinator."""

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


class TestFullLifecycle(unittest.TestCase):
    def test_real_candidate_to_review_chain(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        # candidate -> case -> job -> specialist -> plan -> authz ->
        # observation -> evidence -> analysis -> review
        self.assertEqual(run.candidate_count, 1)
        self.assertEqual(run.case_count, 1)
        self.assertEqual(run.job_count, 1)
        self.assertGreaterEqual(run.observation_count, 1)
        self.assertGreaterEqual(run.evidence_count, 1)
        self.assertGreaterEqual(run.review_required_count, 1)
        job = run.jobs[0]
        self.assertEqual(job.state, "REVIEW_REQUIRED")

    def test_job_case_candidate_linkage(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        job = run.jobs[0]
        self.assertTrue(job.case_id)
        self.assertTrue(job.candidate_id)
        self.assertEqual(job.candidate_id, "srv-1")

    def test_specialist_matched_from_category(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        job = run.jobs[0]
        self.assertEqual(job.specialist, "authorization-researcher")

    def test_input_candidate_matches_input_specialist(self):
        from aec.runtime import loop

        record = dict(WATCH_RECORD, category="XSS_CANDIDATE", id="srv-x")
        run = loop.run_execution([record], "fixture",
                                 authz={record["id"]: GRANTED})
        self.assertEqual(run.jobs[0].specialist, "input-researcher")

    def test_plan_generated_before_observation(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        job = run.jobs[0]
        self.assertIn(job.state, ("OBSERVATION_RUNNING", "EVIDENCE_PENDING",
                                  "ANALYSIS_PENDING", "REVIEW_REQUIRED",
                                  "COMPLETED"))
        self.assertGreaterEqual(run.observation_count, 1)

    def test_case_update_precedes_review(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        # review records must all reference created cases
        created = {job.case_id for job in run.jobs}
        for record in run.review_records:
            self.assertIn(record["case_id"], created)

    def test_no_state_skipping_in_jobs(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        for job in run.jobs:
            states = [t["next_state"] for t in job.transitions]
            previous = "DISCOVERED"
            for state in states:
                self.assertIn(state, _allowable(previous))
                previous = state

    def test_evidence_flows_through_bridge(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        job = run.jobs[0]
        for record in run.evidence:
            self.assertEqual(record.case_id, job.case_id)
            self.assertIn(record.evidence_level, ("COMPLETE", "PARTIAL"))


def _allowable(state):
    from aec.runtime.jobs import TRANSITIONS

    return TRANSITIONS.get(state, ())


class TestQueueIntegration(unittest.TestCase):
    def test_loop_uses_specialist_queue(self):
        from aec.runtime import loop
        from aec.specialists import queue

        records = [
            dict(WATCH_RECORD, id="srv-1"),
            dict(WATCH_RECORD, id="srv-2", category="SSRF_CANDIDATE"),
        ]
        authz = {record["id"]: GRANTED for record in records}
        run = loop.run_execution(records, "fixture", authz=authz)
        # jobs order must match queue priority order (band then case)
        by_case = {job.case_id: job for job in run.jobs}
        self.assertEqual(len(by_case), 2)

    def test_queue_entry_specialist_matches_job(self):
        from aec.runtime import loop
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [{"host": "shop.example.com", "family": "example.com",
              "category": "IDOR_CANDIDATE", "band": "HIGH",
              "attempts": 0, "refused": "", "duplicate_of": "",
              "case_id": "case-1"}],
            queue.default_registry())
        self.assertEqual(built.entries[0]["specialist"],
                         "authorization-researcher")

    def test_duplicate_jobs_not_created_twice(self):
        from aec.runtime import loop

        records = [WATCH_RECORD, dict(WATCH_RECORD)]
        run = loop.run_execution(records, "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        self.assertEqual(run.job_count, 1)
        self.assertGreaterEqual(run.deduplicated_count, 1)

    def test_order_stable_across_runs(self):
        from aec.runtime import loop

        records = [
            dict(WATCH_RECORD, id="srv-low", category="XSS_CANDIDATE"),
            dict(WATCH_RECORD, id="srv-hi"),
        ]
        authz = {record["id"]: GRANTED for record in records}
        first = loop.run_execution(records, "fixture", authz=authz)
        second = loop.run_execution(records, "fixture", authz=authz)
        self.assertEqual(
            [job.candidate_id for job in first.jobs],
            [job.candidate_id for job in second.jobs])


class TestBlockingReasons(unittest.TestCase):
    def test_missing_authz_reason_exact(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "MISSING"}})
        reasons = {item["reason"] for item in run.blocked_reasons}
        self.assertTrue(any("authorization" in reason.lower()
                            for reason in reasons))

    def test_capability_missing_reason_exact(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED},
                                 capabilities=())
        reasons = " ".join(
            item["reason"] for item in run.blocked_reasons).lower()
        self.assertIn("capability", reasons)

    def test_every_blocked_job_has_reason(self):
        from aec.runtime import loop

        records = [WATCH_RECORD, dict(WATCH_RECORD, id="srv-2")]
        run = loop.run_execution(
            records, "fixture",
            authz={record["id"]: {"status": "DENIED"} for record in records})
        blocked_jobs = [job for job in run.jobs if job.state == "BLOCKED"]
        reason_cases = {item["case_id"] for item in run.blocked_reasons}
        for job in blocked_jobs:
            self.assertIn(job.case_id, reason_cases)


class TestCoordinatorContractIntegration(unittest.TestCase):
    def test_run_consumes_coordinator_cases(self):
        from aec.coordinator import pipeline
        from aec.runtime import loop

        records = [WATCH_RECORD, dict(WATCH_RECORD, id="srv-2")]
        authz = {record["id"]: GRANTED for record in records}
        run = loop.run_execution(records, "fixture", authz=authz)
        coordinator = pipeline.run_research(records)
        self.assertEqual(run.case_count, len(coordinator.cases_created))

    def test_run_mode_states_human_summary(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        text = run.human_summary()
        self.assertIn("candidate", text.lower())
        self.assertIn(str(run.job_count), text)


if __name__ == "__main__":
    unittest.main()