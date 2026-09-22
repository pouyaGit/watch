"""Agent Runtime v1 — core tests (Phases 1/2/3/4 + Phase 10 CLI).

Covers: capability definitions for all 8 specialists, persistent queue
lifecycle (QUEUED→CLAIMED→RUNNING→COMPLETED + failure paths), atomic
claims, leases/heartbeat/sweep, retry policy, cancellation, restart
persistence, audit events, worker snapshot/heartbeat observability, and
the bounded worker CLI.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from backend.research_agents.capabilities import (
    CAPABILITIES,
    capability_for,
    validate_capabilities,
)
from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    AgentWorker,
    FixtureObservations,
    RuntimeConfig,
    agent_runtime_states,
    runtime_snapshot,
)
from backend.research_agents.runtime_store import (
    RuntimeStore,
    TransitionError,
    utcnow,
)


def _job(store_dir_tag: str, *, category: str = "XSS", job_id: str = "",
         priority: int = 50, status: str = "QUEUED",
         auth: str = "", mode: str = "fixture",
         max_attempts: int = 3) -> ResearchJob:
    return ResearchJob(
        id=job_id or f"job-{category.lower()}-{store_dir_tag}",
        candidate_id="cand",
        category=category,
        endpoint="https://t.example/x",
        parameter="q",
        priority_score=priority,
        status=status,
        assigned_agent=f"{category.lower()}-agent",
        created_at=utcnow(),
        updated_at=utcnow(),
        agent_category=category,
        reasons=("test",),
        program="p1" if mode != "fixture" else "fixture:p",
        subdomain="t.example",
        url="https://t.example/x",
        mission="test mission",
        authorization_ref=auth or (f"watch:scope:p1/t.example"
                                   if mode != "fixture"
                                   else "fixture:p/t.example"),
        execution_mode=mode,
        max_attempts=max_attempts,
        timeout_seconds=30,
    )


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rt-core-",
                                    dir=os.environ.get("TMPDIR", "/tmp"))
        self.store = RuntimeStore(self.dir)

    # -- Phase 4: capabilities -------------------------------------------

    def test_all_eight_capabilities_validate(self):
        self.assertEqual(validate_capabilities(), [])
        self.assertEqual(len(CAPABILITIES), 8)

    def test_capability_lookup_is_case_insensitive(self):
        cap = capability_for("xss")
        self.assertIsNotNone(cap)
        self.assertEqual(cap.category, "XSS")
        self.assertIsNone(capability_for("NOPE"))

    def test_universal_bans_present_for_every_specialist(self):
        for cat, cap in CAPABILITIES.items():
            for banned in ("exploit execution", "arbitrary shell execution",
                           "credential attacks"):
                self.assertIn(banned, cap.unsupported_operations, cat)

    def test_case_threshold_cannot_be_zero(self):
        for cat, cap in CAPABILITIES.items():
            self.assertGreaterEqual(
                cap.evidence_requirements.min_evidence_refs, 1, cat)

    # -- Phase 2: queue lifecycle ----------------------------------------

    def test_enqueue_is_idempotent_by_job_id(self):
        job = _job("a")
        self.store.enqueue(job)
        self.store.enqueue(job)
        self.assertEqual(len(self.store.list_jobs()), 1)

    def test_claim_marks_claimed_with_lease_and_attempt(self):
        self.store.enqueue(_job("b"))
        claimed = self.store.claim_next("w1", ("XSS",), lease_seconds=30)
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed.status, JobStatus.CLAIMED.value)
        self.assertEqual(claimed.lease_owner, "w1")
        self.assertEqual(claimed.attempt_count, 1)
        self.assertTrue(claimed.lease_expires_at)

    def test_second_worker_cannot_double_claim(self):
        self.store.enqueue(_job("c"))
        first = self.store.claim_next("w1", ("XSS",))
        second = self.store.claim_next("w2", ("XSS",))
        self.assertIsNotNone(first)
        self.assertIsNone(second, "the same job was claimed twice")

    def test_claim_respects_priority_order(self):
        self.store.enqueue(_job("low", priority=10))
        self.store.enqueue(_job("high", priority=90))
        claimed = self.store.claim_next("w1", ("XSS",))
        self.assertEqual(claimed.priority_score, 90)

    def test_claim_only_takes_matching_category(self):
        self.store.enqueue(_job("d", category="JWT"))
        claimed = self.store.claim_next("w1", ("XSS",))
        self.assertIsNone(claimed)

    def test_illegal_transition_is_rejected(self):
        self.store.enqueue(_job("e"))
        with self.assertRaises(TransitionError):
            self.store.transition(_job("e").id, JobStatus.RUNNING.value)

    def test_full_happy_path_transition_chain(self):
        job = _job("f")
        self.store.enqueue(job)
        self.store.claim_next("w1", ("XSS",))
        self.store.transition(job.id, JobStatus.RUNNING.value, worker="w1")
        done = self.store.transition(job.id, JobStatus.COMPLETED.value,
                                     worker="w1")
        self.assertEqual(done.status, JobStatus.COMPLETED.value)

    def test_heartbeat_renews_only_for_the_owner(self):
        job = _job("g")
        self.store.enqueue(job)
        self.store.claim_next("w1", ("XSS",))
        renewed = self.store.heartbeat(job.id, "w1", lease_seconds=60)
        self.assertTrue(renewed)
        self.assertIsNone(self.store.heartbeat(job.id, "w2"))

    def test_release_requires_ownership(self):
        job = _job("h")
        self.store.enqueue(job)
        self.store.claim_next("w1", ("XSS",))
        self.assertFalse(self.store.release(job.id, "w2"))
        self.assertTrue(self.store.release(job.id, "w1"))
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.QUEUED.value)

    def test_cancel_queued_and_refuse_terminal(self):
        job = _job("i")
        self.store.enqueue(job)
        self.assertTrue(self.store.cancel(job.id))
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.CANCELLED.value)
        self.assertFalse(self.store.cancel(job.id), "terminal was cancellable")

    def test_expired_claim_is_swept_back_to_queue(self):
        job = _job("j")
        self.store.enqueue(job)
        self.store.claim_next("w1", ("XSS",), lease_seconds=0)
        swept = self.store.sweep(now_ts=__import__("time").time() + 5)
        self.assertEqual(swept["expired"], 1)
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.QUEUED.value)
        self.assertEqual(swept["requeued"], 1)

    def test_running_lease_loss_fails_then_requeues(self):
        job = _job("k")
        self.store.enqueue(job)
        self.store.claim_next("w1", ("XSS",), lease_seconds=0)
        self.store.transition(job.id, JobStatus.RUNNING.value, worker="w1")
        swept = self.store.sweep(now_ts=__import__("time").time() + 5)
        self.assertEqual(swept["lease_lost"], 1)
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.QUEUED.value)

    def test_attempts_exhausted_goes_terminal(self):
        job = _job("l", max_attempts=1)
        self.store.enqueue(job)
        self.store.claim_next("w1", ("XSS",), lease_seconds=0)
        self.store.sweep(now_ts=__import__("time").time() + 5)
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.TERMINAL_FAILED.value)

    def test_retry_policy_requeues_then_terminates(self):
        job = _job("m", max_attempts=2)
        self.store.enqueue(job)
        self.store.claim_next("w1", ("XSS",))
        self.store.transition(job.id, JobStatus.RUNNING.value, worker="w1")
        self.store.transition(job.id, JobStatus.FAILED.value, worker="w1",
                              error="boom")
        self.assertEqual(self.store.retry_or_terminal(job.id, error="boom"),
                         JobStatus.QUEUED.value)
        # burn the second attempt
        self.store.claim_next("w1", ("XSS",))
        self.store.transition(job.id, JobStatus.RUNNING.value, worker="w1")
        self.store.transition(job.id, JobStatus.FAILED.value, worker="w1",
                              error="boom")
        self.assertEqual(self.store.retry_or_terminal(job.id, error="boom"),
                         JobStatus.TERMINAL_FAILED.value)

    def test_audit_trail_records_the_chain(self):
        job = _job("n")
        self.store.enqueue(job)
        self.store.claim_next("w1", ("XSS",))
        events = [e["event"] for e in self.store.audit_events()]
        for expected in ("job_enqueued", "job_claimed"):
            self.assertIn(expected, events)

    # -- restart survival (Phase 3 requirement) --------------------------

    def test_jobs_results_and_cases_survive_restart(self):
        job = _job("o")
        self.store.enqueue(job)
        from backend.research_agents.models import ResearchResult
        self.store.put_result(ResearchResult(
            job_id=job.id, agent_name="xss-agent", confidence="high",
            created_at=utcnow(), status=JobStatus.COMPLETED.value))
        self.store.record_case({"job_id": job.id, "confidence": "high",
                                "specialist": "xss-agent"})
        self.store.record_evidence({"job_id": job.id, "type": "observation",
                                    "signal": "s", "execution_mode": "fixture"})
        self.store.record_knowledge_use({"job_id": job.id,
                                         "agent": "xss-agent",
                                         "document_id": "kb-1", "title": "t"})
        reborn = RuntimeStore(self.dir)          # fresh process == new store
        self.assertEqual(reborn.get(job.id).status, JobStatus.QUEUED.value)
        self.assertIsNotNone(reborn.get_result(job.id))
        self.assertEqual(len(reborn.list_cases()), 1)
        self.assertEqual(len(reborn.list_evidence(job_id=job.id)), 1)
        self.assertEqual(len(reborn.list_knowledge_use(job_id=job.id)), 1)

    def test_state_file_is_valid_json_after_every_op(self):
        self.store.enqueue(_job("p"))
        payload = json.loads(
            (self.store.state_path).read_text(encoding="utf-8"))
        self.assertIn("jobs", payload)

    # -- Phase 11: observability -----------------------------------------

    def test_snapshot_exposes_worker_queue_and_leases(self):
        job = _job("q")
        self.store.enqueue(job)
        self.store.heartbeat_worker("w1", mode="fixture", ttl_seconds=120)
        self.store.claim_next("w1", ("XSS",))
        snap = runtime_snapshot(self.store)
        self.assertTrue(snap["deployed"])
        self.assertTrue(snap["worker"]["alive"])
        self.assertEqual(snap["queue"], 0)
        self.assertEqual(len(snap["leases"]), 1)
        self.assertEqual(snap["total"], 1)

    def test_worker_stale_heartbeat_reports_dead(self):
        self.store.heartbeat_worker("w1", ttl_seconds=0)
        import time as _t
        info = self.store.worker_alive(now_ts=_t.time() + 10)
        self.assertFalse(info["alive"])
        self.assertIn("stale", info["reason"])

    def test_absent_runtime_state_reports_not_deployed(self):
        snap = runtime_snapshot(self.store)
        self.assertFalse(snap["deployed"])
        self.assertFalse(snap["worker"]["alive"])

    def test_agent_states_without_worker_are_planned(self):
        self.store.enqueue(_job("r"))
        states = agent_runtime_states(self.store)
        self.assertEqual(states["xss"]["status"], "PLANNED")
        self.assertFalse(states["xss"]["available"])

    def test_agent_states_ready_idle_active_failed_with_worker(self):
        from backend.research_agents.runtime_store import rebind_store
        rebind_store(self.store)
        try:
            self.store.heartbeat_worker("w1", mode="fixture",
                                        ttl_seconds=120)
            # READY: worker alive, no jobs
            self.assertEqual(agent_runtime_states(self.store)["xss"]
                             ["status"], "READY")
            # queued job -> operational with pending work, none executing
            job = _job("s")
            self.store.enqueue(job)
            st = agent_runtime_states(self.store)["xss"]
            self.assertEqual(st["status"], "IDLE")
            self.assertEqual(st["queue"], 1)
            # claimed -> ACTIVE
            self.store.claim_next("w1", ("XSS",))
            self.assertEqual(agent_runtime_states(self.store)["xss"]
                             ["status"], "ACTIVE")
            # completed -> IDLE
            self.store.transition(job.id, JobStatus.RUNNING.value)
            self.store.transition(job.id, JobStatus.COMPLETED.value)
            self.assertEqual(agent_runtime_states(self.store)["xss"]
                             ["status"], "IDLE")
        finally:
            rebind_store(None)

    # -- worker: bounded execution (Phase 3) ------------------------------

    def test_worker_executes_claimed_job_to_completion(self):
        job = _job("t")
        self.store.enqueue(job)
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture", worker_id="w1"),
            store=self.store,
            observations=FixtureObservations({
                job.id: [{"source": "http", "ref": "1",
                          "url": "https://t.example/x?q=1", "params": ["q"],
                          "status": 200, "title": "x"}]}),
            llm_enabled=False,
        )
        processed = worker.run(max_jobs=2)
        self.assertEqual(processed["processed"], 1)
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.COMPLETED.value)

    def test_worker_run_respects_max_jobs(self):
        for i in range(3):
            self.store.enqueue(_job(f"u{i}"))
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture", worker_id="w1",
                                 max_jobs_per_run=2),
            store=self.store,
            observations=FixtureObservations({}),
            llm_enabled=False,
        )
        stats = worker.run()
        self.assertEqual(stats["processed"], 2)
        remaining = self.store.list_jobs(status=JobStatus.QUEUED.value)
        self.assertEqual(len(remaining), 1, "queue budget not enforced")

    def test_worker_stop_flag_halts_between_jobs(self):
        for i in range(3):
            self.store.enqueue(_job(f"v{i}"))
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture", worker_id="w1"),
            store=self.store,
            observations=FixtureObservations({}),
            llm_enabled=False,
        )
        calls = {"n": 0}

        def stop() -> bool:
            calls["n"] += 1
            return calls["n"] > 1
        stats = worker.run(max_jobs=3, stop=stop)
        self.assertLess(stats["processed"], 3)
        self.assertEqual(len(self.store.list_jobs(
            status=JobStatus.QUEUED.value)), 3 - stats["processed"])

    def test_activity_log_is_bounded(self):
        job = _job("w")
        self.store.enqueue(job)
        for i in range(520):
            self.store.record_activity({"job_id": job.id, "action": "x",
                                        "i": i})
        self.assertLessEqual(len(self.store.list_activity(limit=1000)), 500)


class TestWorkerCLI(unittest.TestCase):
    """Phase 10: bounded CLI (enqueue/status/run/cancel)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rt-cli-",
                                    dir=os.environ.get("TMPDIR", "/tmp"))
        self.env = mock.patch.dict(os.environ,
                                   {"WATCH_AGENT_RUNTIME_DIR": self.dir})
        self.env.start()
        from backend.research_agents import runtime_store
        runtime_store.rebind_store(None)   # re-resolve env-bound store

    def tearDown(self):
        from backend.research_agents import runtime_store
        runtime_store.rebind_store(None)
        self.env.stop()

    def test_enqueue_status_run_cancel_roundtrip(self):
        from backend.research_agents import cli

        rc = cli.main(["enqueue", "--category", "XSS",
                       "--subdomain", "t.example", "--program", "p",
                       "--mode", "fixture"])
        self.assertEqual(rc, 0)
        rc = cli.main(["status"])
        self.assertEqual(rc, 0)
        rc = cli.main(["run", "--max-jobs", "1", "--mode", "fixture"])
        self.assertEqual(rc, 0)
        rc = cli.main(["cancel", "job-xss-nonexistent"])
        self.assertEqual(rc, 2, "cancel of unknown job must not report ok")

    def test_cli_run_is_bounded_by_max_jobs(self):
        from backend.research_agents import cli
        from backend.research_agents.runtime_store import default_store

        store = default_store()
        for i in range(4):
            store.enqueue(_job(f"cli{i}"))
        rc = cli.main(["run", "--max-jobs", "2", "--mode", "fixture"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(store.list_jobs(
            status=JobStatus.QUEUED.value)), 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
