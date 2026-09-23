"""EPIC9 §12/§13: operations state vs process liveness, heartbeat
truthfulness, panel projection, activity events, config parsing."""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.ai_ops import state as S
from backend.ai_ops.activity import AI_EVENTS, emit
from backend.ai_ops.config import DispatcherConfig
from tests.ai_ops_fixtures import AiOpsEnvMixin

# OPEN/CLOSED instants (UTC): 18:00 Tehran open, 08:00 closed.
OPEN = datetime(2026, 9, 23, 14, 30, tzinfo=timezone.utc)
CLOSED = datetime(2026, 9, 23, 4, 30, tzinfo=timezone.utc)

REQUIRED_STATES = {
    "OFF_WINDOW", "IDLE", "DISCOVERING", "EXECUTING",
    "WAITING_FOR_EVIDENCE", "BLOCKED", "COMPLETED_TICK", "FAILED",
}


class StateSchemaTests(AiOpsEnvMixin):

    def test_states_vocabulary_is_complete(self):
        self.assertTrue(REQUIRED_STATES <= set(S.STATES),
                        msg=f"missing: {REQUIRED_STATES - set(S.STATES)}")

    def test_initial_state_shape(self):
        doc = S.initial_state()
        self.assertEqual(doc["rule_version"], S.RULE_VERSION)
        self.assertEqual(doc["state"], "IDLE")
        self.assertIsNone(doc.get("last_tick"))
        self.assertIsNone(doc.get("current_tick"))

    def test_transition_validates_state_names(self):
        doc = S.initial_state()
        with self.assertRaises((ValueError, KeyError)):
            S.transition(doc, "TELEPORTED")

    def test_transition_records_timestamp(self):
        doc = S.initial_state()
        out = S.transition(doc, "EXECUTING", now=OPEN)
        self.assertEqual(out["state"], "EXECUTING")
        self.assertTrue(out.get("transitioned_at"))

    def test_save_load_roundtrip(self):
        doc = S.initial_state()
        doc["window_open"] = True
        S.save_state(doc)
        loaded = S.load_state()
        self.assertEqual(loaded["rule_version"], S.RULE_VERSION)
        self.assertTrue(loaded["window_open"])

    def test_load_missing_file_returns_initial(self):
        loaded = S.load_state()
        self.assertEqual(loaded["state"], "IDLE")

    def test_paths_live_under_runtime_dir(self):
        self.assertEqual(S.state_path(None).name, S.STATE_FILENAME)
        self.assertEqual(S.lock_path(None).name, S.LOCK_FILENAME)
        self.assertIn("runtime", str(S.state_path(None)))

    def test_rule_version_is_stable(self):
        self.assertEqual(S.RULE_VERSION, "ai-ops-state-v1")


class ProcessVsOperationTests(AiOpsEnvMixin):
    """§12: the process may be dead while operations are healthy."""

    def test_display_completed_tick_reads_as_idle(self):
        self.assertEqual(S.display_state("COMPLETED_TICK"), "IDLE")

    def test_display_label_mapping(self):
        # UI labels use spaces; COMPLETED_TICK reads as IDLE.
        self.assertEqual(S.display_state("OFF_WINDOW"), "OFF WINDOW")
        self.assertEqual(S.display_state("WAITING_FOR_EVIDENCE"),
                         "WAITING FOR EVIDENCE")
        for name in ("IDLE", "EXECUTING", "DISCOVERING", "BLOCKED",
                     "FAILED"):
            self.assertEqual(S.display_state(name), name)

    def test_display_unparseable_state_is_unavailable_not_a_guess(self):
        self.assertEqual(S.display_state("???"), "UNAVAILABLE")

    def test_panel_separates_process_from_operations(self):
        doc = S.initial_state()          # operations IDLE
        doc["state"] = "COMPLETED_TICK"
        S.save_state(doc)
        panel = S.panel(worker_alive={"alive": False,
                                      "reason": "bounded worker exited"})
        self.assertEqual(panel["operations_display"], "IDLE")
        self.assertFalse(panel["process"]["alive"])
        self.assertIn("bounded worker exited", panel["process"]["reason"])

    def test_panel_reports_live_process_when_heartbeat_fresh(self):
        panel = S.panel(worker_alive={"alive": True,
                                      "worker_id": "agent-worker-1",
                                      "last_heartbeat": "T"})
        self.assertTrue(panel["process"]["alive"])
        self.assertEqual(panel["process"]["worker_id"],
                         "agent-worker-1")

    def test_panel_process_default_is_not_alive(self):
        # Never claim a live process without evidence.
        panel = S.panel()
        self.assertFalse(panel["process"]["alive"])

    def test_panel_window_open_follows_the_instant(self):
        self.assertTrue(S.panel(now=OPEN)["window"]["open"])
        self.assertFalse(S.panel(now=CLOSED)["window"]["open"])

    def test_panel_window_label_is_authoritative(self):
        panel = S.panel(now=OPEN)
        self.assertEqual(panel["window"]["label"],
                         S.DEFAULT_WINDOW.label)

    def test_panel_contains_all_ui_fields(self):
        panel = S.panel(now=OPEN)
        for key in ("window", "operations_state", "operations_display",
                    "current_tick", "last_tick", "next_tick_at",
                    "work", "process", "rule_version", "updated_at"):
            self.assertIn(key, panel)

    def test_panel_work_counts_come_from_last_tick(self):
        doc = S.initial_state()
        doc["last_tick"] = {"outcome": "COMPLETED_TICK",
                            "discovered": {"discovered": 6,
                                           "executable": 0,
                                           "waiting": 1,
                                           "blocked": 5,
                                           "terminal": 2}}
        S.save_state(doc)
        work = S.panel()["work"]
        self.assertEqual(work["discovered"], 6)
        self.assertEqual(work["waiting"], 1)
        self.assertEqual(work["blocked"], 5)

    def test_next_tick_is_on_the_configured_minute(self):
        cfg = DispatcherConfig.from_env({})
        nxt = S.next_tick_at(cfg, now=OPEN)
        self.assertIsNotNone(nxt)
        self.assertEqual(nxt.minute, cfg.tick_minute)
        self.assertGreater(nxt, OPEN)

    def test_next_tick_after_close_points_into_next_window(self):
        cfg = DispatcherConfig.from_env({})
        nxt = S.next_tick_at(cfg, now=CLOSED)
        self.assertIsNotNone(nxt)
        self.assertTrue(S.DEFAULT_WINDOW.is_open(nxt))


class HeartbeatTruthfulnessTests(AiOpsEnvMixin):

    def test_tick_does_not_fake_a_heartbeat(self):
        from backend.ai_ops.dispatcher import run_tick
        from backend.research_agents.runtime import RuntimeStore
        rt = RuntimeStore()
        self.assertFalse(rt.worker_alive().get("alive", False))
        run_tick(config=self.config(enabled=True),
                 now_fn=lambda: OPEN, runners={})
        # A dispatcher tick is NOT a worker process: no heartbeat row
        # may appear out of nowhere.
        self.assertFalse(rt.worker_alive().get("alive", False))


class ActivityTests(AiOpsEnvMixin):

    def test_ai_events_vocabulary_is_exact(self):
        expected = {
            "ai_window_opened", "ai_window_closed", "ai_tick_started",
            "work_discovered", "work_selected", "work_started",
            "work_completed", "work_blocked", "waiting_for_evidence",
            "tick_budget_exhausted", "ai_tick_completed",
        }
        self.assertEqual(set(AI_EVENTS), expected)

    def test_emit_writes_event_and_tick_id(self):
        from backend.research_agents.runtime import RuntimeStore
        row = emit(RuntimeStore(), "ai_tick_started", "tick-1",
                   window="w")
        self.assertEqual(row["event"], "ai_tick_started")
        self.assertEqual(row["tick_id"], "tick-1")
        stored = RuntimeStore().audit_events(limit=10)
        self.assertTrue(any(r.get("event") == "ai_tick_started"
                            for r in stored))

    def test_emit_rejects_unregistered_event_names(self):
        # Strict taxonomy: unknown names raise instead of leaking into
        # the activity feed — and nothing is written.
        from backend.research_agents.runtime import RuntimeStore
        before = len(RuntimeStore().audit_events(limit=500))
        with self.assertRaises(ValueError):
            emit(RuntimeStore(), "totally_made_up", "tick-1")
        after = len(RuntimeStore().audit_events(limit=500))
        self.assertEqual(before, after)   # nothing fabricated

    def test_emit_is_bounded_not_screaming(self):
        from backend.research_agents.runtime import RuntimeStore
        row = emit(RuntimeStore(), "work_blocked", "tick-1",
                   detail="x" * 5000)
        self.assertIsNotNone(row)
        if row is not None and "detail" in row:
            self.assertLessEqual(len(str(row["detail"])), 600)

    def test_event_carries_target_and_reason_fields(self):
        from backend.research_agents.runtime import RuntimeStore
        row = emit(RuntimeStore(), "work_blocked", "tick-1",
                   work_id="w1", target="t1",
                   reason="DEPENDENCY_BLOCKED", source_id="s1")
        self.assertEqual(row["reason"], "DEPENDENCY_BLOCKED")
        self.assertEqual(row["target"], "t1")


class ConfigParsingTests(AiOpsEnvMixin):

    def test_defaults(self):
        cfg = DispatcherConfig.from_env({})
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.max_seconds, 600)
        self.assertEqual(cfg.max_work, 4)
        self.assertEqual(cfg.max_per_target, 2)
        self.assertEqual(cfg.max_per_campaign, 1)
        self.assertEqual(cfg.tick_minute, 30)

    def test_enabled_truthy_variants(self):
        for val in ("true", "TRUE", "1", "yes", "on"):
            self.assertTrue(
                DispatcherConfig.from_env(
                    {"WATCH_AI_OPS_ENABLED": val}).enabled, msg=val)

    def test_enabled_false_variants(self):
        for val in ("", "false", "0", "no", "off"):
            self.assertFalse(
                DispatcherConfig.from_env(
                    {"WATCH_AI_OPS_ENABLED": val}).enabled, msg=val)

    def test_budgets_are_clamped_to_safe_bounds(self):
        cfg = DispatcherConfig.from_env({
            "WATCH_AI_OPS_MAX_SECONDS": "999999",
            "WATCH_AI_OPS_MAX_WORK": "0",
            "WATCH_AI_OPS_MAX_PER_TARGET": "abc",
        })
        self.assertLessEqual(cfg.max_seconds, 3600)
        self.assertGreaterEqual(cfg.max_work, 1)
        self.assertEqual(cfg.max_per_target, 2)   # unparsable -> default

    def test_zero_wall_budget_clamps_to_one_second(self):
        cfg = DispatcherConfig.from_env(
            {"WATCH_AI_OPS_MAX_SECONDS": "0"})
        self.assertEqual(cfg.max_seconds, 1)

    def test_from_env_reads_process_environment(self):
        os.environ["WATCH_AI_OPS_MAX_WORK"] = "7"
        try:
            self.assertEqual(DispatcherConfig.from_env().max_work, 7)
        finally:
            del os.environ["WATCH_AI_OPS_MAX_WORK"]


if __name__ == "__main__":
    unittest.main()
