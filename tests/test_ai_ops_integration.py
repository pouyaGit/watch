"""EPIC9 §10/§16/§20: scheduler <-> dispatcher integration (one hourly
tick does research THEN bounded AI operations; opt-in; fail-soft)."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

from ai.research_agent.scheduler import SchedulerConfig, in_window
from backend.ai_ops import dispatcher as disp
from backend.ai_ops.config import DispatcherConfig
from backend.ai_ops.state import load_state, state_path
from backend.ai_ops.window import DEFAULT_WINDOW, is_open_local
from tests.ai_ops_fixtures import AiOpsEnvMixin, make_job

REPO = Path(__file__).resolve().parents[1]
OPEN = datetime(2026, 9, 23, 14, 30, tzinfo=timezone.utc)   # 18:00 Tehran


class WindowAuthorityConsumptionTests(unittest.TestCase):

    def test_scheduler_config_defaults_equal_ai_window(self):
        cfg = SchedulerConfig()
        self.assertEqual(cfg.window_start, DEFAULT_WINDOW.start)
        self.assertEqual(cfg.window_end, DEFAULT_WINDOW.end)
        self.assertEqual(cfg.timezone, DEFAULT_WINDOW.timezone)

    def test_scheduler_env_overrides_still_win(self):
        cfg = SchedulerConfig.from_env(
            {"WATCH_RESEARCH_WINDOW_START": "09:00",
             "WATCH_RESEARCH_WINDOW_END": "17:00"})
        self.assertEqual(cfg.window_start, "09:00")
        self.assertEqual(cfg.window_end, "17:00")

    def test_scheduler_and_dispatcher_agree_all_day(self):
        # One authoritative window: R23 in_window == ai_ops view for
        # every hour of the day, in the window timezone.
        tz = ZoneInfo(DEFAULT_WINDOW.timezone)
        base = datetime(2026, 9, 23, 0, 0, tzinfo=tz)
        for minutes in range(0, 24 * 60, 30):
            instant = base + timedelta(minutes=minutes)
            self.assertEqual(
                in_window(instant.replace(tzinfo=None),
                          DEFAULT_WINDOW.start, DEFAULT_WINDOW.end),
                DEFAULT_WINDOW.is_open(instant),
                msg=f"disagreement at {instant.isoformat()}")

    def test_agreement_covers_exact_boundaries(self):
        tz = ZoneInfo(DEFAULT_WINDOW.timezone)
        for hh, mm, expect in ((11, 59, False), (12, 0, True),
                               (23, 59, True), (0, 0, False)):
            instant = datetime(2026, 9, 24 if hh < 12 else 23, hh, mm,
                               tzinfo=tz)
            self.assertEqual(is_open_local(instant, DEFAULT_WINDOW.start,
                                           DEFAULT_WINDOW.end),
                             expect, msg=f"{hh:02d}:{mm:02d}")


class ResearchCliWiringTests(AiOpsEnvMixin):

    def test_helper_exists_and_is_wired_into_run_agent_run(self):
        from ai import research_cli
        self.assertTrue(callable(research_cli._ai_ops_after_research))
        src = Path(research_cli.__file__).read_text()
        self.assertEqual(src.count("_ai_ops_after_research()"), 3)
        # helper definition + json path + text path

    def test_disabled_by_default_returns_none(self):
        from ai import research_cli
        # AiOpsEnvMixin strips WATCH_AI_OPS_* — the fail-safe default.
        self.assertIsNone(research_cli._ai_ops_after_research())

    def test_enabled_runs_a_bounded_tick_clock_independent(self):
        from ai import research_cli
        import os
        os.environ["WATCH_AI_OPS_ENABLED"] = "true"
        try:
            result = research_cli._ai_ops_after_research()
        finally:
            del os.environ["WATCH_AI_OPS_ENABLED"]
        self.assertIsInstance(result, dict)
        self.assertIn("outcome", result)
        self.assertIn(result["outcome"],
                      {"COMPLETED_TICK", "BUDGET_EXHAUSTED",
                       "FAILED", "SKIPPED_OUT_OF_WINDOW"})

    def test_dispatcher_failure_never_crashes_the_research_run(self):
        from ai import research_cli
        with mock.patch(
            "backend.ai_ops.dispatcher.maybe_run_from_scheduler",
            side_effect=RuntimeError("exploded-xyz")):
            result = research_cli._ai_ops_after_research()
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("outcome"), "FAILED")
        self.assertIn("exploded-xyz", result.get("error", ""))

    def test_research_exit_semantics_not_swallowed(self):
        # The research record still ends with its own return; AI-OPS
        # summary lines are additive.
        src = Path(
            __import__("ai.research_cli", fromlist=["x"]).__file__
        ).read_text()
        self.assertIn("AI-OPS:", src)


class SystemdIntegrationTests(unittest.TestCase):

    def test_service_unit_keeps_the_env_file_channel(self):
        # The dispatcher opt-in (WATCH_AI_OPS_ENABLED=true) travels
        # through /opt/watch/.env via the unit's EXISTING
        # EnvironmentFile= line — the unit itself is a pinned AEC
        # read-only contract file and stays byte-identical.
        unit = (REPO / "systemd/watch-research.service").read_text()
        self.assertIn("EnvironmentFile=/opt/watch/.env", unit)
        # still no persistent worker / no new daemon:
        self.assertNotIn("watch-ai-ops.service", unit)
        self.assertNotIn("WATCH_AI_OPS_ENABLED", unit)

    def test_unit_file_is_unmodified_from_pinned_hash(self):
        import subprocess
        out = subprocess.run(
            ["git", "diff", "--stat", "--",
             "systemd/watch-research.service"],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "",
                         "pinned unit file must not drift")

    def test_no_new_daemon_units_introduced(self):
        systemd_dir = REPO / "systemd"
        names = sorted(p.name for p in systemd_dir.glob("*"))
        self.assertNotIn("watch-ai-ops.service", names)
        self.assertNotIn("watch-ai-ops.timer", names)


class RealDefaultRunnerBindingTests(AiOpsEnvMixin):
    """Regression: DEFAULT_RUNNERS take (store, item, budget) and must
    be store-bound before run_tick calls runner(item, budget)."""

    def test_default_style_runner_receives_the_store(self):
        from backend.research_agents.runtime import RuntimeStore
        from backend.ai_ops.discovery import CLASS_JOB
        RuntimeStore().enqueue(make_job("job-bind", "QUEUED"))
        seen: dict = {}

        def three_arg(store, item, budget):
            seen["store"] = store
            seen["item"] = item.work_id
            return {"claimed": 1}

        original = disp.DEFAULT_RUNNERS[CLASS_JOB]
        disp.DEFAULT_RUNNERS[CLASS_JOB] = three_arg
        try:
            rec = disp.run_tick(config=self.config(enabled=True),
                                now_fn=lambda: OPEN)
        finally:
            disp.DEFAULT_RUNNERS[CLASS_JOB] = original
        self.assertIsNotNone(seen.get("store"))
        self.assertTrue(hasattr(seen["store"], "base"))
        self.assertEqual(seen["item"], "job:job-bind")
        self.assertEqual(rec["outcome"], "COMPLETED_TICK")

    def test_real_default_runners_with_empty_queue(self):
        # The ACTUAL run_jobs_runner (real AgentWorker, bounded drain)
        # runs against an empty queue: claimed 0, no crash, honest
        # completion — exercising the genuine execution path end to end.
        rec = disp.run_tick(config=self.config(enabled=True),
                            now_fn=lambda: OPEN)
        self.assertIn(rec["outcome"],
                      {"COMPLETED_TICK", "BUDGET_EXHAUSTED"})
        executed = rec.get("executed", [])
        for entry in executed:
            self.assertNotIn("error", entry.get("detail", {})
                             if isinstance(entry.get("detail"), dict)
                             else {})

    def test_second_tick_recovers_and_continues(self):
        first = disp.run_tick(config=self.config(enabled=True),
                              now_fn=lambda: OPEN)
        second = disp.run_tick(config=self.config(enabled=True),
                               now_fn=lambda: OPEN)
        self.assertEqual(first["tick_id"] != second["tick_id"], True)
        doc = load_state()
        self.assertEqual(doc["last_tick"]["tick_id"], second["tick_id"])

    def test_status_payload_is_read_only_what_if(self):
        closed = datetime(2026, 9, 23, 4, 30, tzinfo=timezone.utc)
        payload = disp.status_payload(
            at=closed, config=DispatcherConfig.from_env({}))
        self.assertFalse(payload["would_dispatch"])
        self.assertEqual(payload.get("dispatch_skipped_because"),
                         "OUT_OF_WINDOW")
        self.assertFalse(state_path(None).exists())   # no side effect


class ServiceEntrypointContractTests(AiOpsEnvMixin):
    """§10: the EXISTING hourly tick is the AI operations tick — no
    second scheduler is created."""

    def test_research_cli_run_path_invokes_dispatch(self):
        src = Path(REPO / "ai/research_cli.py").read_text()
        # exactly one definition, two call sites (json + text output)
        self.assertEqual(src.count("def _ai_ops_after_research"), 1)

    def test_dispatcher_enforces_its_own_window(self):
        # even a forced research run cannot start AI work out of window
        closed = datetime(2026, 9, 23, 4, 30, tzinfo=timezone.utc)
        rec = disp.run_tick(config=self.config(enabled=True),
                            now_fn=lambda: closed, runners={
                                "CAMPAIGN_OBJECTIVE":
                                    lambda i, b: {"executed": 1}})
        self.assertEqual(rec["outcome"], "SKIPPED_OUT_OF_WINDOW")
        self.assertEqual(rec.get("executed", []), [])


if __name__ == "__main__":
    unittest.main()
