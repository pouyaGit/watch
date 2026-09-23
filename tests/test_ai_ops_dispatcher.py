"""EPIC9 §3/§5/§6/§9/§11/§17/§18: the bounded dispatcher tick."""

from __future__ import annotations

import fcntl
import os
import unittest
from datetime import datetime, timezone

from backend.ai_ops import dispatcher as D
from backend.ai_ops import state as S
from backend.ai_ops.activity import AI_EVENTS
from backend.ai_ops.discovery import (
    CLASS_CAMPAIGN, CLASS_JOB, WAITING_FOR_EVIDENCE,
)
from backend.ai_ops.dispatcher import maybe_run_from_scheduler, run_tick
from backend.ai_ops.window import DEFAULT_WINDOW
from tests.ai_ops_fixtures import (
    AiOpsEnvMixin, SCOPE, make_campaign, make_hunt, make_job,
    make_objective,
)

# Instants (UTC): 14:30 = 18:00 Tehran (OPEN), 04:30 = 08:00 (CLOSED)
OPEN = datetime(2026, 9, 23, 14, 30, tzinfo=timezone.utc)
CLOSED = datetime(2026, 9, 23, 4, 30, tzinfo=timezone.utc)


def fake_ok(item, budget):
    return {"runner": "fake", "claimed": 1, "processed": 1}


def fake_fail(item, budget):
    raise RuntimeError("runner exploded")


class TickTestCase(AiOpsEnvMixin):
    def tick(self, now=OPEN, runners=None, **cfg_kw):
        cfg = self.config(**{"enabled": True, **cfg_kw})
        calls: list[str] = []
        if runners is None:
            runners = {CLASS_JOB: lambda item, budget:
                       (calls.append(item.work_id),
                        {"runner": "fake", "claimed": 1})[1],
                       CLASS_CAMPAIGN: lambda item, budget:
                       (calls.append(item.work_id),
                        {"runner": "fake", "executed": 1})[1]}
        rec = run_tick(config=cfg, now_fn=lambda: now, runners=runners)
        return rec, calls

    def events(self):
        from backend.research_agents.runtime import RuntimeStore
        return [e for e in RuntimeStore().audit_events(limit=500)
                if isinstance(e, dict) and e.get("event")]

    def event_names(self):
        return [e["event"] for e in self.events()]


class WindowGateTests(TickTestCase):

    def test_outside_window_skips_everything(self):
        rec, calls = self.tick(now=CLOSED)
        self.assertEqual(rec["outcome"], "SKIPPED_OUT_OF_WINDOW")
        self.assertFalse(rec["window_open"])
        self.assertEqual(calls, [])                 # runner never called
        self.assertNotIn("ai_tick_started", self.event_names())
        doc = S.load_state()
        self.assertEqual(doc.get("state"), "OFF_WINDOW")

    def test_outside_window_after_open_emits_window_closed(self):
        doc = S.initial_state()
        doc["window_open"] = True
        S.save_state(doc)
        self.tick(now=CLOSED)
        self.assertIn("ai_window_closed", self.event_names())

    def test_first_open_tick_emits_window_opened(self):
        self.tick(now=OPEN)
        self.assertIn("ai_window_opened", self.event_names())

    def test_second_open_tick_does_not_reemit_window_opened(self):
        self.tick(now=OPEN)
        self.tick(now=OPEN)
        names = self.event_names()
        self.assertEqual(names.count("ai_window_opened"), 1)
        self.assertEqual(names.count("ai_tick_started"), 2)

    def test_window_check_cannot_be_disabled_by_env(self):
        os.environ["WATCH_AI_OPS_ENABLED"] = "true"
        rec = run_tick(config=self.config(enabled=True),
                       now_fn=lambda: CLOSED, runners={})
        self.assertEqual(rec["outcome"], "SKIPPED_OUT_OF_WINDOW")


class EmptyAndClassificationTests(TickTestCase):

    def test_empty_tick_is_honest_idle(self):
        rec, _ = self.tick()
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")
        self.assertEqual(rec["discovered"]["discovered"], 0)
        doc = S.load_state()
        # Nothing discovered -> the operation state is IDLE (not
        # COMPLETED_TICK — that one marks ticks that RAN work).
        self.assertEqual(doc.get("state"), "IDLE")
        self.assertEqual(S.display_state(doc.get("state", "")), "IDLE")

    def test_needs_evidence_does_not_block_other_work(self):
        # Section 6: A waiting, B executed — same tick.
        from backend.research_agents.hunt.store import HuntStore
        from backend.research_agents.runtime import RuntimeStore
        HuntStore().create_objective(
            make_hunt(objective_id="hobj-A", state="NEEDS_EVIDENCE"))
        RuntimeStore().enqueue(make_job("job-B", "QUEUED"))
        rec, calls = self.tick()
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")
        self.assertEqual(len(rec["executed"]), 1)
        self.assertIn("job-B", rec["executed"][0]["work_id"])
        # the NEEDS_EVIDENCE item stayed non-executable + reported
        waiting = [r for r in rec["remaining"]
                   if r["reason"] == WAITING_FOR_EVIDENCE]
        self.assertEqual(len(waiting), 1)
        self.assertIn("waiting_for_evidence", self.event_names())

    def test_only_waiting_items_yield_waiting_state(self):
        from backend.research_agents.hunt.store import HuntStore
        HuntStore().create_objective(
            make_hunt(state="NEEDS_EVIDENCE"))
        rec, _ = self.tick()
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")
        doc = S.load_state()
        self.assertEqual(doc.get("state"), "WAITING_FOR_EVIDENCE")

    def test_non_terminal_blocked_yields_blocked_state(self):
        from backend.research_agents.campaign.store import CampaignStore
        cs = CampaignStore()
        cs.create_campaign(make_campaign(state="DRAFT"))
        cs.add_objective(make_objective(state="QUEUED"))
        rec, _ = self.tick()
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")
        doc = S.load_state()
        self.assertEqual(doc.get("state"), "BLOCKED")
        self.assertIn("work_blocked", self.event_names())

    def test_terminal_only_items_yield_idle_not_blocked(self):
        from backend.research_agents.runtime import RuntimeStore
        RuntimeStore().enqueue(make_job("job-done", "COMPLETED"))
        rec, _ = self.tick()
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")
        self.assertEqual(rec["discovered"]["terminal"], 1)
        doc = S.load_state()
        self.assertEqual(doc.get("state"), "IDLE")


class ExecutionTests(TickTestCase):

    def test_executes_queued_job_through_injected_runner(self):
        from backend.research_agents.runtime import RuntimeStore
        RuntimeStore().enqueue(make_job("job-x", "QUEUED"))
        rec, calls = self.tick()
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")
        self.assertEqual(len(rec["executed"]), 1)
        self.assertEqual(calls, ["job:job-x"])
        self.assertEqual(rec["executed"][0]["outcome"], "completed")
        self.assertIn("work_started", self.event_names())
        self.assertIn("work_completed", self.event_names())

    def test_default_runners_receive_the_bound_store(self):
        """Regression: DEFAULT_RUNNERS are (store, item, budget) and
        must be store-bound by the tick (previously a TypeError)."""
        from backend.research_agents.runtime import RuntimeStore
        from backend.ai_ops.dispatcher import DEFAULT_RUNNERS
        RuntimeStore().enqueue(make_job("job-bind", "QUEUED"))
        seen: dict = {}

        def three_arg(store, item, budget):
            seen["store"] = store
            seen["item"] = item.work_id
            return {"runner": "x", "claimed": 1}

        orig = dict(DEFAULT_RUNNERS)
        DEFAULT_RUNNERS[CLASS_JOB] = three_arg
        try:
            rec, _ = self.tick(runners={})   # use DEFAULT map only
        finally:
            DEFAULT_RUNNERS.clear()
            DEFAULT_RUNNERS.update(orig)
        self.assertIsNotNone(seen.get("store"))
        self.assertTrue(hasattr(seen["store"], "base"))
        self.assertEqual(rec["executed"][0]["outcome"], "completed")

    def test_runner_exception_is_honest_failure(self):
        from backend.research_agents.runtime import RuntimeStore
        RuntimeStore().enqueue(make_job("job-boom", "QUEUED"))
        rec, _ = self.tick(runners={CLASS_JOB: fake_fail})
        self.assertEqual(rec["executed"][0]["outcome"], "failed")
        self.assertIn("RuntimeError", rec["executed"][0]["result"])
        self.assertIn("work_blocked", self.event_names())
        # tick itself still completes truthfully
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")

    def test_runner_error_key_marks_failed_outcome(self):
        from backend.research_agents.runtime import RuntimeStore
        RuntimeStore().enqueue(make_job("job-e", "QUEUED"))
        rec, _ = self.tick(runners={CLASS_JOB:
                                    lambda i, b: {"error": "nope"}})
        self.assertEqual(rec["executed"][0]["outcome"], "failed")

    def test_missing_runner_records_no_runner_block(self):
        from backend.research_agents.campaign.store import CampaignStore
        cs = CampaignStore()
        cs.create_campaign(make_campaign())
        cs.add_objective(make_objective())
        orig = dict(D.DEFAULT_RUNNERS)
        D.DEFAULT_RUNNERS.pop(CLASS_CAMPAIGN, None)
        try:
            rec, _ = self.tick(runners={})   # campaign runner removed
        finally:
            D.DEFAULT_RUNNERS.clear()
            D.DEFAULT_RUNNERS.update(orig)
        self.assertEqual(rec["executed"][0]["outcome"], "blocked")
        self.assertEqual(rec["executed"][0]["reason"], "NO_RUNNER")


class BudgetTests(TickTestCase):

    def test_work_budget_defers_extra_items(self):
        from backend.research_agents.runtime import RuntimeStore
        for i in range(3):
            RuntimeStore().enqueue(
                make_job(f"job-{i}", "QUEUED",
                         subdomain=f"t{i}.example.com"))
        rec, calls = self.tick(max_work=1, max_per_target=5)
        self.assertEqual(len(rec["executed"]), 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")
        self.assertTrue(any(d["reason"] == "BUDGET_DEFERRED"
                            for d in rec["deferred"]))
        self.assertIn("tick_budget_exhausted", self.event_names())

    def test_wall_budget_stops_gracefully(self):
        import time
        from backend.research_agents.runtime import RuntimeStore
        RuntimeStore().enqueue(make_job("job-w1", "QUEUED",
                                        subdomain="slow.example.com"))
        RuntimeStore().enqueue(make_job("job-w2", "QUEUED",
                                        subdomain="fast.example.com"))
        calls: list[str] = []

        def slow_runner(item, budget):
            calls.append(item.work_id)
            time.sleep(1.2)                # blows the 1s wall budget
            return {"runner": "slow", "claimed": 1}

        rec, _ = self.tick(max_seconds=1,
                           runners={CLASS_JOB: slow_runner})
        # The FIRST unit was already running when the budget expired —
        # it finishes (never killed mid-transition); the SECOND never
        # starts. STOP_GRACEFULLY between units, per §9.
        self.assertEqual(rec.get("stop_reason"), "WALL_BUDGET")
        self.assertEqual(len(calls), 1)
        self.assertEqual(rec["outcome"], "BUDGET_EXHAUSTED")
        self.assertIn("tick_budget_exhausted", self.event_names())

    def test_window_closing_mid_tick_stops_new_units(self):
        from backend.research_agents.runtime import RuntimeStore
        RuntimeStore().enqueue(make_job("job-c", "QUEUED"))
        seq = [OPEN, OPEN, OPEN, OPEN] + [CLOSED] * 10
        state = {"i": 0}

        def clock():
            idx = min(state["i"], len(seq) - 1)
            state["i"] += 1
            return seq[idx]

        cfg = self.config(enabled=True, max_work=2)
        rec = run_tick(config=cfg, now_fn=clock,
                       runners={CLASS_JOB: fake_ok})
        self.assertEqual(rec.get("stop_reason"), "WINDOW_CLOSED")
        self.assertEqual(rec["executed"], [])
        self.assertEqual(rec["outcome"], "BUDGET_EXHAUSTED")

    def test_fairness_cap_defers_other_target(self):
        from backend.research_agents.runtime import RuntimeStore
        RuntimeStore().enqueue(make_job("job-t1", "QUEUED",
                                        subdomain="aaa.example.com"))
        RuntimeStore().enqueue(make_job("job-t2", "QUEUED",
                                        subdomain="bbb.example.com"))
        rec, calls = self.tick(max_work=1, max_per_target=1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(rec["deferred"]), 1)
        self.assertEqual(rec["deferred"][0]["reason"], "BUDGET_DEFERRED")


class RecoveryConcurrencyTests(TickTestCase):

    def test_duplicate_tick_reports_contention_without_writing(self):
        import backend.ai_ops.state as st
        lock = st.lock_path(None)
        lock.parent.mkdir(parents=True, exist_ok=True)
        handle = open(lock, "a+", encoding="utf-8")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            rec = run_tick(config=self.config(enabled=True),
                           now_fn=lambda: OPEN, runners={})
            self.assertEqual(rec["outcome"], "CONTENDED")
            self.assertFalse(os.path.exists(st.state_path(None)))
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()

    def test_lock_released_after_normal_tick(self):
        self.tick()
        import backend.ai_ops.state as st
        handle = open(st.lock_path(None), "a+", encoding="utf-8")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()

    def test_interrupted_tick_is_recovered_and_recorded(self):
        doc = S.initial_state()
        doc["state"] = "EXECUTING"       # crashed mid-tick previously
        doc["window_open"] = True
        S.save_state(doc)
        rec, _ = self.tick()
        self.assertTrue(rec.get("recovered_interrupted"))
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")

    def test_stale_lease_sweep_runs_every_in_window_tick(self):
        rec, _ = self.tick()
        self.assertIn("sweep", rec)
        self.assertFalse(rec["errors"])

    def test_second_consecutive_tick_succeeds_after_release(self):
        first, _ = self.tick()
        second, _ = self.tick()
        self.assertEqual(first["outcome"], "COMPLETED_TICK")
        self.assertEqual(second["outcome"], "COMPLETED_TICK")
        self.assertNotEqual(first["tick_id"], second["tick_id"])


class PersistenceActivityTests(TickTestCase):

    def test_state_file_persists_last_tick(self):
        rec, _ = self.tick()
        doc = S.load_state()
        self.assertEqual(doc.get("rule_version"), S.RULE_VERSION)
        self.assertEqual(doc["last_tick"]["tick_id"], rec["tick_id"])
        self.assertEqual(doc["last_tick"]["outcome"], "COMPLETED_TICK")
        self.assertIsNone(doc.get("current_tick"))

    def test_events_carry_matching_tick_id(self):
        rec, _ = self.tick()
        ids = {e.get("tick_id") for e in self.events()}
        self.assertIn(rec["tick_id"], ids)

    def test_no_audit_failures_with_healthy_store(self):
        rec, _ = self.tick()
        self.assertEqual(rec["audit_failures"], 0)

    def test_emitted_events_are_taxonomy_registered(self):
        from backend.prod_intel.activity import EVENT_CATEGORY
        self.tick()
        for name in self.event_names():
            self.assertIn(name, AI_EVENTS, msg=name)
            self.assertIn(name, EVENT_CATEGORY, msg=name)

    def test_all_event_names_have_taxonomy_entries(self):
        from backend.prod_intel.activity import EVENT_CATEGORY
        for name in AI_EVENTS:
            self.assertIn(name, EVENT_CATEGORY, msg=name)

    def test_out_of_window_state_has_no_current_tick(self):
        self.tick(now=CLOSED)
        doc = S.load_state()
        self.assertIsNone(doc.get("current_tick"))
        self.assertEqual(doc.get("state"), "OFF_WINDOW")


class SchedulerIntegrationGateTests(TickTestCase):

    def test_disabled_by_default_returns_none(self):
        result = maybe_run_from_scheduler(
            config=self.config(enabled=False))
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(S.state_path(None)))

    def test_enabled_returns_tick_record(self):
        result = maybe_run_from_scheduler(
            config=self.config(enabled=True))
        self.assertIsInstance(result, dict)
        self.assertIn("outcome", result)
        # real clock — either IN or OUT of window is a valid truth
        self.assertIn(result["outcome"],
                      ("COMPLETED_TICK", "SKIPPED_OUT_OF_WINDOW",
                       "BUDGET_EXHAUSTED", "FAILED"))

    def test_env_gate_default_is_false(self):
        cfg = D.DispatcherConfig.from_env({})
        self.assertFalse(cfg.enabled)


class StatusPayloadTests(TickTestCase):

    def test_status_outside_window_is_what_if_no_write(self):
        payload = D.status_payload(at=CLOSED)
        self.assertFalse(payload["would_dispatch"])
        self.assertEqual(payload["dispatch_skipped_because"],
                         "OUT_OF_WINDOW")
        self.assertIn("what_if_at", payload)
        self.assertFalse(os.path.exists(S.state_path(None)))

    def test_status_inside_window_would_dispatch(self):
        payload = D.status_payload(at=OPEN)
        self.assertTrue(payload["would_dispatch"])
        self.assertEqual(payload["window"]["label"],
                         "12:00-00:00 Asia/Tehran")

    def test_status_never_executes(self):
        from backend.research_agents.runtime import RuntimeStore
        RuntimeStore().enqueue(make_job("job-s", "QUEUED"))
        payload = D.status_payload(at=OPEN)
        self.assertTrue(payload["would_dispatch"])
        # still queued: a read-only status cannot have drained it
        job = RuntimeStore().get("job-s")
        self.assertEqual(job.status, "QUEUED")


if __name__ == "__main__":
    unittest.main()
