"""Focused tests for the R84 Telegram AI activity reporting orchestration.

Everything is hermetic: the R83 collector is injected/patched, the Telegram
transport is a fake (no real Telegram message is ever sent), and the
deduplication state lives in a temporary directory. No Mongo, no network and
nothing under ai_data/research is modified.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

from ai.knowledge.ai_activity_status import (
    LOCK_FREE,
    LOCK_HELD,
    STATUSES,
    build_activity_status,
)
from backend import telegram_reporting as reporting

TEHRAN = ZoneInfo("Asia/Tehran")

# 14:00 Tehran is inside 12:00-00:00; 01:00 the next day is the first hour
# after the window closed, so the daily summary covers 2026-09-16 12:00-00:00.
NOW_IN_WINDOW = datetime(2026, 9, 16, 14, 0, tzinfo=TEHRAN)
NOW_OUTSIDE_WINDOW = datetime(2026, 9, 17, 1, 0, tzinfo=TEHRAN)

CONFIGURED = {
    "TELEGRAM_BOT_TOKEN": "123456:FAKE-TOKEN-NOT-REAL",
    "TELEGRAM_CHAT_ID": "-1001234567890",
}
UNCONFIGURED = {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""}

FORBIDDEN_PRIMITIVES = (
    "pymongo",
    "MongoClient",
    "requests",
    "httpx",
    "urllib",
    "subprocess",
    "socket",
    "openai",
    "insert_one",
    "update_one",
    "delete_one",
    "store_run",
)

R84_MODULES = (
    "ai/knowledge/ai_activity_report.py",
    "backend/telegram_reporting.py",
)


def run_record(*, run_id="run-20260916T093000Z", status="RESEARCH_COMPLETED"):
    return {
        "run_id": run_id,
        "status": status,
        "started_at": "2026-09-16T13:00:00+03:30",
        "completed_at": "2026-09-16T13:02:00+03:30",
        "plans_selected": 1,
        "plans_processed": 1,
        "results": [
            {
                "plan_id": "r22-38d26f10681e9a0f",
                "cve_id": "CVE-2026-1557",
                "program": "dell",
                "status": "RESEARCH_COMPLETED",
                "evidence": 2,
                "sources": 3,
            }
        ],
        "failures": [],
        "skipped": None,
    }


def case_record(*, case_id="case-indeed-a1-endpoint-behavior"):
    return {
        "case_id": case_id,
        "program": "https://target.example/path",
        "category": "RECON",
        "case_status": "WAITING_FOR_EVIDENCE",
        "sufficiency_state": "INSUFFICIENT",
        "decision_state": "NEEDS_EVIDENCE",
        "available_count": "2",
        "missing_count": "2",
        "actions_count": "1",
        "validation_accepted": "1",
        "validation_rejected": "2",
        "modified_at": "2026-09-16T13:05:00+03:30",
    }


def activity_at(now, *, lock=LOCK_FREE, runs=(), cases=()):
    return build_activity_status(
        now=now,
        lock_state=lock,
        run_records=list(runs),
        case_records=list(cases),
    )


class FakeSender:
    """Mocked Telegram transport: records messages, never sends anything."""

    def __init__(self, result=True, error=None):
        self.messages: list[str] = []
        self.result = result
        self.error = error

    def __call__(self, message: str) -> bool:
        self.messages.append(message)
        if self.error is not None:
            raise self.error
        return self.result


class ReportingTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_path = Path(self._tmp.name) / "nested" / "telegram_state.json"

    def patched_config(self, values=None):
        return mock.patch("config.config", return_value=dict(values or CONFIGURED))

    def call(self, **overrides):
        params = {
            "activity": activity_at(NOW_OUTSIDE_WINDOW),
            "mode": "daily",
            "sender": FakeSender(),
            "state_path_override": self.state_path,
        }
        params.update(overrides)
        return reporting.send_activity_reports(**params)

    def load_state(self):
        return reporting.load_state(self.state_path)


class TestConfigurationSafety(ReportingTestCase):
    def test_missing_config_fails_safe_without_send(self):
        sender = FakeSender()
        with self.patched_config(UNCONFIGURED):
            result = self.call(sender=sender)
        self.assertFalse(result["configured"])
        self.assertFalse(result["token_configured"])
        self.assertFalse(result["chat_configured"])
        self.assertEqual(result["sent"], 0)
        self.assertEqual(sender.messages, [])
        self.assertIn("telegram_not_configured", result["reasons"])
        self.assertFalse(self.state_path.exists())

    def test_partial_config_fails_safe(self):
        sender = FakeSender()
        with self.patched_config({"TELEGRAM_BOT_TOKEN": "x", "TELEGRAM_CHAT_ID": ""}):
            result = self.call(sender=sender)
        self.assertFalse(result["configured"])
        self.assertEqual(sender.messages, [])
        self.assertIn("telegram_not_configured", result["reasons"])

    def test_config_status_reports_booleans_only(self):
        with self.patched_config():
            status = reporting.telegram_config_status()
        self.assertEqual(
            set(status), {"token_configured", "chat_configured", "configured"}
        )
        self.assertTrue(status["configured"])
        self.assertNotIn(CONFIGURED["TELEGRAM_BOT_TOKEN"], json.dumps(status))

    def test_default_sender_delegates_to_existing_transport(self):
        with mock.patch("database.telegram.send_message", return_value=True) as send:
            self.assertTrue(reporting._default_sender("hello"))
            send.assert_called_once_with("hello")
        with mock.patch("database.telegram.send_message", return_value=False):
            self.assertFalse(reporting._default_sender("hello"))

    def test_totality_wrapper_never_raises(self):
        with mock.patch.object(
            reporting, "_send_activity_reports", side_effect=ValueError("boom")
        ):
            result = reporting.send_activity_reports(mode="daily")
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["reasons"], ["unexpected_ValueError"])


class TestDeduplication(ReportingTestCase):
    def test_daily_send_then_deduplicated(self):
        sender = FakeSender()
        with self.patched_config():
            first = self.call(sender=sender)
            second = self.call(sender=sender)
        self.assertEqual(first["sent"], 1)
        self.assertEqual(first["skipped"], 0)
        self.assertEqual(second["sent"], 0)
        self.assertEqual(second["skipped"], 1)
        self.assertEqual(len(sender.messages), 1)
        # The transport must receive the multi-line report unchanged.
        self.assertIn("🤖 WATCH AI DAILY REPORT\n", sender.messages[0])
        self.assertIn("\n━━━━", sender.messages[0])
        state = self.load_state()
        self.assertEqual(
            state["keys"],
            ["daily:2026-09-16T12:00:00+03:30"],
        )

    def test_events_baseline_then_transition_then_dedup(self):
        baseline = activity_at(NOW_IN_WINDOW)
        completed = activity_at(NOW_IN_WINDOW, runs=[run_record()])
        sender = FakeSender()
        with self.patched_config():
            first = self.call(activity=baseline, mode="events", sender=sender)
            second = self.call(activity=completed, mode="events", sender=sender)
            third = self.call(activity=completed, mode="events", sender=sender)
        self.assertEqual(first["sent"], 0)
        self.assertEqual(second["sent"], 1)
        self.assertEqual(third["sent"], 0)
        self.assertEqual(len(sender.messages), 1)
        self.assertIn("WATCH AI RUN COMPLETED", sender.messages[0])
        state = self.load_state()
        self.assertEqual(state["keys"], ["event:RUN_COMPLETED:run-20260916T093000Z"])
        self.assertTrue(state["snapshot"]["status"])

    def test_case_event_dedup_key_is_deterministic(self):
        baseline = activity_at(NOW_IN_WINDOW)
        with_case = activity_at(
            NOW_IN_WINDOW, runs=[run_record()], cases=[case_record()]
        )
        sender = FakeSender()
        with self.patched_config():
            self.call(activity=baseline, mode="events", sender=sender)
            self.call(activity=with_case, mode="events", sender=sender)
        keys = self.load_state()["keys"]
        self.assertIn(
            "event:CASE_WAITING_FOR_EVIDENCE:case-indeed-a1-endpoint-behavior:"
            "2026-09-16T13:05:00+03:30",
            keys,
        )

    def test_state_is_bounded(self):
        reporting.save_state(
            {"keys": [f"key-{index}" for index in range(40)], "snapshot": {}},
            self.state_path,
        )
        keys = reporting.load_state(self.state_path)["keys"]
        self.assertEqual(len(keys), reporting.MAX_KEYS)
        self.assertEqual(keys[0], "key-16")
        self.assertEqual(keys[-1], "key-39")

    def test_state_write_failure_is_bounded(self):
        blocker = Path(self._tmp.name) / "blocker"
        blocker.write_text("", encoding="utf-8")
        sender = FakeSender()
        with self.patched_config():
            result = self.call(
                sender=sender, state_path_override=blocker / "state.json"
            )
        self.assertEqual(result["sent"], 1)
        self.assertIn("state_write_failed", result["reasons"])


class TestTransportFailure(ReportingTestCase):
    def test_transport_exception_is_bounded_and_retried(self):
        failing = FakeSender(error=RuntimeError("socket exploded"))
        with self.patched_config():
            first = self.call(sender=failing)
            self.assertFalse(self.state_path.exists())
            second = self.call(sender=FakeSender())
        self.assertEqual(first["sent"], 0)
        self.assertEqual(first["failed"], 1)
        self.assertIn("transport_error_RuntimeError", first["reasons"])
        self.assertEqual(second["sent"], 1)

    def test_transport_false_is_bounded(self):
        sender = FakeSender(result=False)
        with self.patched_config():
            result = self.call(sender=sender)
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["failed"], 1)
        self.assertIn("send_failed", result["reasons"])
        self.assertFalse(self.state_path.exists())

    def test_activity_unavailable_is_unknown_not_error(self):
        sender = FakeSender()
        with self.patched_config(), mock.patch.object(
            reporting.research_activity,
            "collect_activity",
            side_effect=RuntimeError("collector down"),
        ):
            result = reporting.send_activity_reports(
                mode="daily",
                sender=sender,
                state_path_override=self.state_path,
            )
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["failed"], 0)
        self.assertIn("activity_unavailable_RuntimeError", result["reasons"])
        self.assertEqual(sender.messages, [])

    def test_injected_activity_skips_collector(self):
        sender = FakeSender()
        with self.patched_config(), mock.patch.object(
            reporting.research_activity,
            "collect_activity",
            side_effect=AssertionError("collector must not be called"),
        ):
            result = self.call(sender=sender)
        self.assertEqual(result["sent"], 1)


class TestModeSelection(ReportingTestCase):
    def test_auto_mode_outside_window_sends_daily(self):
        sender = FakeSender()
        with self.patched_config():
            result = self.call(
                activity=activity_at(NOW_OUTSIDE_WINDOW), mode="auto", sender=sender
            )
        self.assertEqual(result["sent"], 1)
        self.assertEqual(len(sender.messages), 1)
        self.assertIn("WATCH AI DAILY REPORT", sender.messages[0])

    def test_auto_mode_inside_window_does_not_send_daily(self):
        sender = FakeSender()
        with self.patched_config():
            result = self.call(
                activity=activity_at(NOW_IN_WINDOW), mode="auto", sender=sender
            )
        self.assertEqual(result["sent"], 0)
        self.assertEqual(sender.messages, [])
        state = self.load_state()
        self.assertEqual(state["keys"], [])
        self.assertTrue(state["snapshot"]["status"])

    def test_dry_run_sends_nothing_and_writes_nothing(self):
        sender = FakeSender()
        with self.patched_config(), mock.patch.object(
            reporting, "save_state"
        ) as save:
            result = self.call(sender=sender, dry_run=True)
        self.assertEqual(result["sent"], 0)
        self.assertEqual(sender.messages, [])
        save.assert_not_called()
        self.assertIn("dry_run:DAILY_ACTIVITY", result["reasons"])


class TestMessageSafety(ReportingTestCase):
    def test_no_secret_in_result_messages_or_state(self):
        sender = FakeSender()
        activity = activity_at(
            NOW_OUTSIDE_WINDOW,
            runs=[run_record()],
            cases=[case_record()],
        )
        activity["last_error"] = "token=123456:FAKE-TOKEN-NOT-REAL"
        with self.patched_config():
            result = self.call(activity=activity, mode="both", sender=sender)
        blob = json.dumps(result)
        message = "\n".join(sender.messages)
        self.assertNotIn(CONFIGURED["TELEGRAM_BOT_TOKEN"], blob)
        self.assertNotIn("FAKE-TOKEN", blob)
        self.assertNotIn(CONFIGURED["TELEGRAM_BOT_TOKEN"], message)
        self.assertNotIn("FAKE-TOKEN", message)
        self.assertNotIn("http", message)
        self.assertNotIn("target.example", message)
        if self.state_path.exists():
            state_text = self.state_path.read_text(encoding="utf-8")
            self.assertNotIn("FAKE-TOKEN", state_text)
            self.assertNotIn("http", state_text)

    def test_state_file_never_contains_target_or_secrets(self):
        with self.patched_config():
            self.call(
                activity=activity_at(
                    NOW_OUTSIDE_WINDOW, runs=[run_record()], cases=[case_record()]
                )
            )
        text = self.state_path.read_text(encoding="utf-8")
        self.assertNotIn("://", text)
        self.assertNotIn("target.example", text)
        self.assertNotIn("FAKE-TOKEN", text)


class TestCli(ReportingTestCase):
    def test_cli_dry_run_json_sends_nothing(self):
        buffer = io.StringIO()
        with self.patched_config(), mock.patch.object(
            reporting.research_activity,
            "collect_activity",
            return_value=activity_at(NOW_OUTSIDE_WINDOW),
        ), mock.patch.object(
            reporting, "_default_sender", side_effect=AssertionError("must not send")
        ), mock.patch.object(reporting, "save_state") as save:
            with redirect_stdout(buffer):
                code = reporting.main(["--mode", "daily", "--dry-run", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["sent"], 0)
        save.assert_not_called()

    def test_cli_failure_returns_zero(self):
        buffer = io.StringIO()
        with mock.patch.object(
            reporting.research_activity,
            "collect_activity",
            side_effect=RuntimeError("collector down"),
        ):
            with redirect_stdout(buffer):
                code = reporting.main(["--mode", "daily"])
        self.assertEqual(code, 0)
        self.assertIn("sent=0", buffer.getvalue())


class TestSourceHygiene(unittest.TestCase):
    def test_no_forbidden_primitives_in_r84_modules(self):
        for path in R84_MODULES:
            text = Path(path).read_text(encoding="utf-8")
            for token in FORBIDDEN_PRIMITIVES:
                self.assertNotIn(token, text, f"{path} contains {token}")

    def test_real_collector_dry_run_contract(self):
        result = reporting.send_activity_reports(mode="daily", dry_run=True)
        self.assertIn(result["activity_status"], STATUSES)
        self.assertEqual(result["sent"], 0)

    def test_events_never_emit_without_prior_snapshot(self):
        sender = FakeSender()
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "config.config", return_value=dict(CONFIGURED)
        ):
            result = reporting.send_activity_reports(
                activity=activity_at(NOW_IN_WINDOW, lock=LOCK_HELD),
                mode="events",
                sender=sender,
                state_path_override=Path(tmp) / "state.json",
            )
        self.assertEqual(result["sent"], 0)
        self.assertEqual(sender.messages, [])


if __name__ == "__main__":
    unittest.main()
