"""EPIC6 supplementary pins: run stats, replay depth, queue edges, isolation."""

from __future__ import annotations

import json
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


def make_run(records=None, origin="fixture", **kwargs):
    from aec.runtime import loop

    records = records or [WATCH_RECORD]
    authz = kwargs.pop("authz", None) or {
        record["id"]: GRANTED for record in records}
    return loop.run_execution(records, origin, authz=authz, **kwargs)


class TestRunModelStats(unittest.TestCase):
    def test_machine_summary_exact_keys(self):
        run = make_run()
        self.assertEqual(sorted(run.machine_summary()), [
            "blocked_count", "candidate_count", "case_count", "completed_at",
            "completed_count", "deduplicated_count", "duration",
            "evidence_count", "failed_count", "job_count",
            "observation_count", "policy_version", "queued_count",
            "replay_identity", "review_required_count", "run_id",
            "source_mode", "started_at", "waiting_authorization_count"])

    def test_summary_run_id_matches(self):
        run = make_run()
        self.assertEqual(run.machine_summary()["run_id"], run.run_id)

    def test_human_summary_lines(self):
        run = make_run()
        lines = run.human_summary().splitlines()
        self.assertEqual(len(lines), 16)

    def test_zero_run_counts(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "MISSING"}})
        summary = run.machine_summary()
        self.assertEqual(summary["observation_count"], 0)
        self.assertEqual(summary["evidence_count"], 0)
        self.assertEqual(summary["waiting_authorization_count"], 1)

    def test_case_dedup_job_per_record(self):
        records = [dict(WATCH_RECORD, id=f"srv-{i}") for i in range(3)]
        run = make_run(records)
        # Coordinator dedupes by content hash (all three share the URL),
        # while jobs are one per distinct record id.
        self.assertEqual(run.case_count, 1)
        self.assertEqual(run.job_count, 3)

    def test_case_count_unique_content(self):
        records = [
            dict(WATCH_RECORD, id="srv-1"),
            dict(WATCH_RECORD, id="srv-2", endpoint="/other",
                 url="/other?x=", category="XSS_CANDIDATE"),
        ]
        run = make_run(records)
        self.assertEqual(run.case_count, 2)
        self.assertEqual(run.job_count, 2)


class TestReplayDepth(unittest.TestCase):
    def test_replay_identity_len_64(self):
        run = make_run()
        self.assertEqual(len(run.replay_identity), 64)

    def test_replay_identity_hex(self):
        run = make_run()
        int(run.replay_identity, 16)

    def test_serialize_stable_json(self):
        from aec.replay import kernel

        run = make_run()
        text = kernel.serialize_run(run)
        self.assertEqual(
            json.dumps(json.loads(text), sort_keys=True,
                       separators=(",", ":")), text)

    def test_serialize_changes_with_policy(self):
        from aec.replay import kernel

        first = kernel.serialize_run(make_run(policy_version="v1"))
        second = kernel.serialize_run(make_run(policy_version="v2"))
        self.assertNotEqual(first, second)

    def test_validate_refuses_missing_jobs(self):
        from aec.replay import kernel

        document = make_run().to_dict()
        del document["jobs"]
        with self.assertRaises(ValueError):
            kernel.validate(document)

    def test_validate_refuses_missing_context(self):
        from aec.replay import kernel

        document = make_run().to_dict()
        del document["context"]
        with self.assertRaises(ValueError):
            kernel.validate(document)

    def test_validate_refuses_bad_origin(self):
        from aec.replay import kernel

        document = make_run().to_dict()
        document["context"]["origin"] = "live"
        with self.assertRaises(ValueError):
            kernel.validate(document)

    def test_context_replay_preserves_inputs(self):
        from aec.replay import kernel

        run = make_run()
        document = run.to_dict()
        self.assertEqual(document["context"]["origin"], "fixture")
        self.assertEqual(document["context"]["records"][0]["id"], "srv-1")


class TestQueueEdges(unittest.TestCase):
    def test_empty_queue_metrics_zero(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue([], queue.default_registry())
        self.assertEqual(built.metrics["total"], 0)

    def test_band_unknown_defaults(self):
        from aec.specialists import queue

        self.assertEqual(queue.band_priority("UNKNOWN"), 3)

    def test_non_mapping_jobs_ignored(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            ["junk", {"case_id": "case-1", "category": "XSS_CANDIDATE",
                      "band": "HIGH", "attempts": 0, "refused": "",
                      "duplicate_of": "", "host": "h", "family": "f"}],
            queue.default_registry())
        self.assertEqual(built.total, 1)

    def test_queue_id_stable_for_same_input(self):
        from aec.specialists import queue

        jobs = [{"case_id": "case-1", "category": "XSS_CANDIDATE",
                 "band": "HIGH", "attempts": 0, "refused": "",
                 "duplicate_of": "", "host": "h", "family": "f"}]
        first = queue.build_specialist_queue(jobs, queue.default_registry())
        second = queue.build_specialist_queue(jobs, queue.default_registry())
        self.assertEqual(first.queue_id, second.queue_id)

    def test_family_budget_respected(self):
        from aec.specialists import queue

        jobs = [
            {"case_id": f"case-{i}", "category": "XSS_CANDIDATE",
             "band": "LOW", "attempts": 0, "refused": "",
             "duplicate_of": "", "host": f"a{i}.x.example",
             "family": "x.example"}
            for i in range(4)
        ]
        built = queue.build_specialist_queue(
            jobs, queue.default_registry(), family_budget=2)
        over = [item for item in built.entries if item["budget"] == "OVER"]
        self.assertEqual(len(over), 2)


class TestIsolation(unittest.TestCase):
    def test_fixture_run_never_real(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        self.assertEqual(run.source_mode, "OFFLINE_FIXTURE")
        for record in run.evidence:
            self.assertEqual(record.source_mode, "OFFLINE_FIXTURE")
        for job in run.jobs:
            self.assertEqual(job.source_mode, "OFFLINE_FIXTURE")

    def test_real_run_never_fixture(self):
        from aec.runtime import loop

        run = loop.run_execution([WATCH_RECORD], "watch",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        self.assertEqual(run.source_mode, "REAL_WATCH_DATA")

    def test_identity_document_mode(self):
        from aec.replay import identity

        watch = identity.document([WATCH_RECORD], "watch",
                                  {WATCH_RECORD["id"]: GRANTED}, "v1")
        fixture = identity.document([WATCH_RECORD], "fixture",
                                    {WATCH_RECORD["id"]: GRANTED}, "v1")
        self.assertEqual(watch["source_mode"], "REAL_WATCH_DATA")
        self.assertEqual(fixture["source_mode"], "OFFLINE_FIXTURE")
        self.assertNotEqual(watch["replay_identity"],
                            fixture["replay_identity"])

    def test_fixture_cannot_be_promoted(self):
        from aec.research.guard import promotable_to_production

        self.assertFalse(promotable_to_production({
            "source_mode": "OFFLINE_FIXTURE",
            "outcome": "POTENTIAL"}))


class TestGuardVocab(unittest.TestCase):
    def test_guard_marks_case_insensitive(self):
        from aec.research.guard import is_production_claim

        for word in ("CoNfIrMeD", "VULNERABLE", "Exploitable"):
            self.assertTrue(is_production_claim({"outcome": word}))

    def test_guard_ignores_unrelated_values(self):
        from aec.research.guard import is_production_claim

        self.assertFalse(is_production_claim({
            "note": "the finding queue is empty today"}))

    def test_ensure_uses_verbatim_context(self):
        from aec.research.guard import ensure_no_production_claim

        with self.assertRaises(ValueError) as ctx:
            ensure_no_production_claim({"outcome": "verdict"}, "job-1")
        self.assertIn("job-1", str(ctx.exception))

    def test_same_source_mode_symmetric(self):
        from aec.research.guard import same_source_mode

        self.assertTrue(
            same_source_mode("OFFLINE_FIXTURE", "OFFLINE_FIXTURE"))
        self.assertFalse(
            same_source_mode("OFFLINE_FIXTURE", "REAL_WATCH_DATA"))


class TestEvidenceBridgeEdges(unittest.TestCase):
    def test_empty_result_raises(self):
        from aec.evidence_bridge.bridge import IngestionFailure, ingest

        with self.assertRaises(IngestionFailure):
            ingest("case-1", "job-1", {}, "OFFLINE_FIXTURE", 1)

    def test_scrubbed_sensitive(self):
        from aec.evidence_bridge.bridge import ingest

        result = {
            "observation_id": "obs-1",
            "request_id": "obsreq-abc",
            "observed_fields": ["set-cookie"],
            "missing_fields": [],
            "tick": 1,
            "source": "observer",
        }
        record = ingest("case-1", "job-1", result, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.redaction_status, "scrubbed")

    def test_tick_clamped(self):
        from aec.evidence_bridge.bridge import ingest

        result = {
            "observation_id": "obs-1",
            "request_id": "obsreq-abc",
            "observed_fields": ["status_code"],
            "missing_fields": [],
            "tick": -5,
        }
        record = ingest("case-1", "job-1", result, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.tick, 1)


class TestRouterLoopIntegration(unittest.TestCase):
    def test_execution_runs_view_real_data(self):
        from backend.routers import aec

        run = make_run().to_dict()
        view = aec.build_execution_runs_view([run])
        self.assertEqual(view["total"], 1)
        self.assertIn("source_mode", view["runs"][0])
        self.assertEqual(view["runs"][0]["source_mode"], "OFFLINE_FIXTURE")

    def test_research_jobs_view_counts(self):
        from backend.routers import aec

        run = make_run().to_dict()
        view = aec.build_research_jobs_view(run)
        self.assertEqual(view["total"], 1)
        self.assertEqual(view["jobs"][0]["state"], "REVIEW_REQUIRED")

    def test_evidence_view_has_records(self):
        from backend.routers import aec

        run = make_run().to_dict()
        view = aec.build_evidence_view(run)
        self.assertGreaterEqual(view["total"], 1)

    def test_execution_summary_specialists_count(self):
        from backend.routers import aec

        view = aec.build_specialists_view()
        self.assertEqual(view["total"], 5)


class TestAuthzUnchangedBoundary(unittest.TestCase):
    def test_gate_not_called_for_observation_decision(self):
        from aec.runtime import loop

        # The loop consults the authorization map, never the frozen
        # verification chain: a MISSING authz must wait, not default-open.
        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: {"status": "MISSING"}})
        self.assertEqual(run.jobs[0].state, "WAITING_AUTHORIZATION")
        self.assertEqual(run.observation_count, 0)

    def test_no_capability_no_observation(self):
        from aec.runtime import loop

        run = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED},
            capabilities=())
        self.assertEqual(run.jobs[0].state, "BLOCKED")
        self.assertEqual(run.observation_count, 0)

    def test_authorization_boundary_is_the_only_gate(self):
        from aec.execution import executor

        self.assertNotIn(
            "verifier", dir(executor))


if __name__ == "__main__":
    unittest.main()