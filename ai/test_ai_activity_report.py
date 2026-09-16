"""Focused tests for the R84 deterministic Telegram AI activity formatter.

Pure engine tests: no I/O, no network, no Telegram, no Mongo. The activity
contract used as input is built by the real R83 core
(``ai.knowledge.ai_activity_status.build_activity_status``) so the formatter is
exercised against the exact shape the R83 collector produces.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from ai.knowledge.ai_activity_report import (
    EVENT_CASE_WAITING_FOR_EVIDENCE,
    EVENT_HUMAN_REVIEW_REQUIRED,
    EVENT_RUN_COMPLETED,
    EVENT_RUN_COMPLETED_WITH_REJECTIONS,
    EVENT_RUN_FAILED,
    EVENT_RUN_STARTED,
    FOOTER,
    MAX_MESSAGE_CHARS,
    REPORT_DAILY,
    REPORT_EVENT,
    RULE_VERSION,
    _bounded_message,
    build_daily_report,
    daily_dedup_key,
    event_reports,
    snapshot_of,
)
from ai.knowledge.ai_activity_status import (
    LOCK_FREE,
    LOCK_HELD,
    LOCK_UNAVAILABLE,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_REJECTIONS,
    STATUS_ERROR,
    STATUS_IDLE,
    STATUS_RUNNING,
    STATUS_UNKNOWN,
    STATUS_WAITING_FOR_EVIDENCE,
    build_activity_status,
)

TEHRAN = ZoneInfo("Asia/Tehran")


def run_record(
    *,
    run_id="run-20260916T093000Z",
    status="RESEARCH_COMPLETED",
    started="2026-09-16T13:00:00+03:30",
    completed="2026-09-16T13:02:00+03:30",
    plans_processed=1,
    evidence=2,
    sources=3,
    failures=None,
):
    return {
        "run_id": run_id,
        "status": status,
        "started_at": started,
        "completed_at": completed,
        "plans_selected": 1,
        "plans_processed": plans_processed,
        "results": [
            {
                "plan_id": "r22-38d26f10681e9a0f",
                "cve_id": "CVE-2026-1557",
                "program": "dell",
                "status": "RESEARCH_COMPLETED",
                "evidence": evidence,
                "sources": sources,
            }
        ],
        "failures": failures or [],
        "skipped": None,
    }


def case_record(
    *,
    case_id="case-indeed-a1-endpoint-behavior",
    program="indeed",
    category="RECON",
    case_status="WAITING_FOR_EVIDENCE",
    sufficiency_state="INSUFFICIENT",
    decision_state="NEEDS_EVIDENCE",
    available="2",
    missing="2",
    actions="1",
    accepted="1",
    rejected="2",
    modified="2026-09-16T13:05:00+03:30",
):
    return {
        "case_id": case_id,
        "program": program,
        "category": category,
        "case_status": case_status,
        "sufficiency_state": sufficiency_state,
        "decision_state": decision_state,
        "available_count": available,
        "missing_count": missing,
        "actions_count": actions,
        "validation_accepted": accepted,
        "validation_rejected": rejected,
        "modified_at": modified,
    }


def activity_at(now, *, lock=LOCK_FREE, runs=(), cases=()):
    return build_activity_status(
        now=now,
        lock_state=lock,
        run_records=list(runs),
        case_records=list(cases),
    )


NOW = datetime(2026, 9, 16, 14, 0, tzinfo=TEHRAN)


def utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


class TestDailyReport(unittest.TestCase):
    def test_zero_activity_is_reported_honestly(self):
        report = build_daily_report(activity_at(NOW))
        message = report["message"]
        self.assertEqual(report["report_type"], REPORT_DAILY)
        self.assertEqual(report["rule_version"], RULE_VERSION)
        self.assertTrue(report["research_only"])
        self.assertTrue(report["window_in_progress"])  # 14:00 is in the window
        self.assertIn("Runs: 0", message)
        self.assertIn("Cases processed: 0", message)
        self.assertIn("Hypotheses accepted: 0", message)
        self.assertIn("Evidence acquired: 0", message)
        self.assertIn("No AI run was recorded", message)
        self.assertIn("2026-09-16", message)
        self.assertIn("12:00 → 00:00 Asia/Tehran", message)
        self.assertIn(FOOTER, message)
        self.assertNotIn("AI is RUNNING", message)

    def test_completed_activity_counts_are_real(self):
        activity = activity_at(
            NOW,
            runs=[run_record()],
            cases=[
                case_record(
                    case_status="READY_FOR_HUMAN_REVIEW",
                    decision_state="READY_FOR_HUMAN_REVIEW",
                )
            ],
        )
        message = build_daily_report(activity)["message"]
        self.assertIn("✅ Status", message)
        self.assertIn(STATUS_COMPLETED, message)
        self.assertIn("Runs: 1", message)
        self.assertIn("Plans processed: 1", message)
        self.assertIn("Results: 1", message)
        self.assertIn("Cases processed: 1", message)
        self.assertIn("Hypotheses accepted: 1", message)
        self.assertIn("Hypotheses rejected: 2", message)
        self.assertIn("Evidence acquired: 2", message)
        self.assertIn("Actions generated: 1", message)
        self.assertIn("last run: COMPLETED run-20260916T093000Z", message)
        self.assertNotIn("No AI run was recorded", message)

    def test_completed_with_rejections(self):
        activity = activity_at(
            NOW,
            runs=[run_record(status="RESEARCH_PARTIAL")],
            cases=[case_record(case_status="READY_FOR_HUMAN_REVIEW")],
        )
        message = build_daily_report(activity)["message"]
        self.assertIn(STATUS_COMPLETED_WITH_REJECTIONS, message)
        self.assertIn("rejected hypotheses in window: 2", message)

    def test_error_status_and_bounded_error(self):
        activity = activity_at(
            NOW,
            runs=[run_record(status="RESEARCH_FAILED", failures=[{"error": "TimeoutError"}])],
        )
        report = build_daily_report(activity)
        message = report["message"]
        self.assertIn(STATUS_ERROR, message)
        self.assertIn("last error: TimeoutError", message)

    def test_waiting_for_evidence_status_and_pending(self):
        activity = activity_at(
            NOW,
            runs=[run_record()],
            cases=[case_record()],
        )
        message = build_daily_report(activity)["message"]
        self.assertIn(STATUS_WAITING_FOR_EVIDENCE, message)
        self.assertIn("case is WAITING_FOR_EVIDENCE (human-supplied evidence)", message)
        self.assertIn("missing decision-critical evidence", message)

    def test_running_claim_only_when_running(self):
        running = activity_at(NOW, lock=LOCK_HELD)
        self.assertIn("AI is RUNNING", build_daily_report(running)["message"])
        for activity in (
            activity_at(NOW),
            activity_at(NOW, lock=LOCK_UNAVAILABLE),
            activity_at(NOW, runs=[run_record()], cases=[case_record()]),
        ):
            self.assertNotIn("AI is RUNNING", build_daily_report(activity)["message"])

    def test_unknown_is_not_error(self):
        activity = activity_at(NOW, lock=LOCK_UNAVAILABLE)
        report = build_daily_report(activity)
        self.assertEqual(activity["status"], STATUS_UNKNOWN)
        self.assertIn("❔ Status", report["message"])
        self.assertIn("UNKNOWN is not failure", report["message"])
        self.assertNotIn("🔴", report["message"])

    def test_idle_status_when_nothing_ever_ran(self):
        report = build_daily_report(activity_at(NOW))
        self.assertIn(STATUS_IDLE, report["message"])
        self.assertIn("last run: none recorded", report["message"])
        self.assertIn("nothing pending observed", report["message"])

    def test_twelve_hour_boundary_is_inclusive(self):
        boundary = datetime(2026, 9, 16, 12, 0, tzinfo=TEHRAN)
        activity = activity_at(boundary)
        self.assertTrue(activity["window"]["in_window"])
        report = build_daily_report(activity)
        self.assertTrue(report["window_in_progress"])
        self.assertIn("📅 2026-09-16", report["message"])
        self.assertEqual(
            report["dedup_key"], "daily:2026-09-16T12:00:00+03:30"
        )

    def test_midnight_boundary_belongs_to_previous_window(self):
        boundary = datetime(2026, 9, 17, 0, 0, tzinfo=TEHRAN)
        activity = activity_at(boundary)
        self.assertFalse(activity["window"]["in_window"])
        report = build_daily_report(activity)
        self.assertFalse(report["window_in_progress"])
        self.assertIn("📅 2026-09-16", report["message"])
        self.assertEqual(
            report["dedup_key"], "daily:2026-09-16T12:00:00+03:30"
        )

    def test_tehran_timezone_applied_to_server_time(self):
        activity = activity_at(datetime(2026, 9, 16, 9, 30, tzinfo=timezone.utc))
        self.assertTrue(activity["window"]["in_window"])
        self.assertEqual(activity["server_time_tehran"][:16], "2026-09-16T13:00")
        report = build_daily_report(activity)
        self.assertIn("2026-09-16", report["message"])
        self.assertIn("Asia/Tehran", report["message"])

    def test_daily_dedup_key_is_deterministic(self):
        activity = activity_at(NOW)
        self.assertEqual(daily_dedup_key(activity), daily_dedup_key(activity))
        self.assertEqual(daily_dedup_key({}), "daily:unknown-window")

    def test_message_is_bounded(self):
        activity = activity_at(NOW)
        activity["status"] = "X" * 5000
        activity["current_case"] = {
            "case_id": "C" * 5000,
            "program": "P" * 5000,
            "category": "K" * 5000,
        }
        message = build_daily_report(activity)["message"]
        self.assertLessEqual(utf16_len(message), MAX_MESSAGE_CHARS)
        self.assertTrue(message.endswith(FOOTER))

        for huge in ("Z" * 20000, "🎯" * 5000):
            bounded = _bounded_message([huge])
            self.assertLessEqual(utf16_len(bounded), MAX_MESSAGE_CHARS)
            self.assertTrue(bounded.endswith(FOOTER))


class TestMessageSafety(unittest.TestCase):
    def _message_with(self, **case_overrides):
        activity = activity_at(NOW, cases=[case_record(**case_overrides)])
        return build_daily_report(activity)["message"]

    def test_no_url_leak(self):
        message = self._message_with(program="https://target.example/path")
        self.assertNotIn("http://", message)
        self.assertNotIn("https://", message)
        self.assertNotIn("target.example", message)
        self.assertIn("[withheld]", message)

    def test_no_ip_leak(self):
        message = self._message_with(case_id="10.11.12.13")
        self.assertNotIn("10.11.12.13", message)
        self.assertIn("[withheld]", message)

    def test_no_object_id_leak(self):
        message = self._message_with(case_id="507f1f77bcf86cd799439011")
        self.assertNotIn("507f1f77bcf86cd799439011", message)
        self.assertIn("[redacted]", message)

    def test_no_path_or_stack_trace_leak(self):
        activity = activity_at(
            NOW,
            runs=[
                run_record(
                    status="RESEARCH_FAILED",
                    failures=[
                        {
                            "error": 'ValueError: boom\n  File "/srv/app/x.py", '
                            "line 42, in run"
                        }
                    ],
                )
            ],
        )
        message = build_daily_report(activity)["message"]
        self.assertNotIn("/srv", message)
        self.assertNotIn(".py", message)
        self.assertNotIn("line 42", message)
        self.assertIn("last error: ValueError", message)

    def test_secret_pairs_are_redacted(self):
        activity = activity_at(NOW)
        activity["last_error"] = "token=abc123secret"
        activity["status_basis"] = "Authorization: Bearer sk-live-abcdef"
        message = build_daily_report(activity)["message"]
        self.assertNotIn("abc123secret", message)
        self.assertNotIn("sk-live-abcdef", message)
        self.assertNotIn("Bearer sk", message)
        self.assertIn("[redacted]", message)

    def test_prompts_and_model_responses_are_never_rendered(self):
        activity = activity_at(NOW, runs=[run_record()], cases=[case_record()])
        activity["prompt"] = "RAW PROMPT TEXT"
        activity["model_response"] = "RAW MODEL RESPONSE"
        activity["last_run"]["raw_response"] = "RAW RUN RESPONSE"
        message = build_daily_report(activity)["message"]
        self.assertNotIn("RAW PROMPT TEXT", message)
        self.assertNotIn("RAW MODEL RESPONSE", message)
        self.assertNotIn("RAW RUN RESPONSE", message)

    def test_html_markup_is_escaped(self):
        message = self._message_with(case_id="a<b>&pwn")
        self.assertNotIn("<b>", message)
        self.assertIn("a&lt;b&gt;&amp;pwn", message)

    def test_closing_html_tag_value_is_withheld(self):
        message = self._message_with(case_id="</b>pwn")
        self.assertNotIn("</b>", message)
        self.assertIn("[withheld]", message)

    def test_snapshot_is_sanitized_and_bounded(self):
        activity = activity_at(NOW, runs=[run_record()], cases=[case_record()])
        activity["last_error"] = "https://secret.example/x"
        activity["current_case"]["case_id"] = "a" * 400
        snapshot = snapshot_of(activity)
        self.assertEqual(snapshot["last_error"], "[withheld]")
        self.assertLessEqual(len(snapshot["case_id"]), 96)
        self.assertNotIn("secret.example", str(snapshot))


class TestEventReports(unittest.TestCase):
    def test_first_observation_is_a_silent_baseline(self):
        activity = activity_at(NOW, runs=[run_record()], cases=[case_record()])
        self.assertEqual(event_reports(activity, {}), [])
        self.assertEqual(event_reports(activity, None), [])

    def test_run_started_transition(self):
        running = activity_at(NOW, lock=LOCK_HELD)
        previous = snapshot_of(activity_at(NOW))
        reports = event_reports(running, previous)
        self.assertEqual([r["event_type"] for r in reports], [EVENT_RUN_STARTED])
        self.assertEqual(
            reports[0]["dedup_key"],
            f"event:{EVENT_RUN_STARTED}:2026-09-16T12:00:00+03:30",
        )
        self.assertEqual(reports[0]["report_type"], REPORT_EVENT)

    def test_run_completed_transition_and_deterministic_id(self):
        completed = activity_at(NOW, runs=[run_record(run_id="run-abc")])
        previous = snapshot_of(activity_at(NOW))
        reports = event_reports(completed, previous)
        self.assertEqual([r["event_type"] for r in reports], [EVENT_RUN_COMPLETED])
        self.assertEqual(reports[0]["dedup_key"], f"event:{EVENT_RUN_COMPLETED}:run-abc")
        again = event_reports(completed, snapshot_of(completed))
        self.assertEqual(again, [])

    def test_run_completed_with_rejections_event(self):
        completed = activity_at(
            NOW, runs=[run_record(run_id="run-partial", status="RESEARCH_PARTIAL")]
        )
        reports = event_reports(completed, snapshot_of(activity_at(NOW)))
        self.assertEqual(
            [r["event_type"] for r in reports],
            [EVENT_RUN_COMPLETED_WITH_REJECTIONS],
        )

    def test_run_failed_event(self):
        failed = activity_at(
            NOW,
            runs=[
                run_record(
                    run_id="run-failed",
                    status="RESEARCH_FAILED",
                    failures=[{"error": "TimeoutError"}],
                )
            ],
        )
        reports = event_reports(failed, snapshot_of(activity_at(NOW)))
        self.assertEqual([r["event_type"] for r in reports], [EVENT_RUN_FAILED])
        self.assertEqual(reports[0]["dedup_key"], f"event:{EVENT_RUN_FAILED}:run-failed")
        self.assertIn("TimeoutError", reports[0]["message"])

    def test_case_waiting_for_evidence_event(self):
        previous = snapshot_of(
            activity_at(
                NOW,
                runs=[run_record(run_id="run-1")],
                cases=[case_record(case_status="COLLECTING_EVIDENCE", missing="0")],
            )
        )
        current = activity_at(
            NOW,
            runs=[run_record(run_id="run-1")],
            cases=[case_record(case_status="WAITING_FOR_EVIDENCE")],
        )
        reports = event_reports(current, previous)
        case_events = [
            r for r in reports if r["event_type"] == EVENT_CASE_WAITING_FOR_EVIDENCE
        ]
        self.assertEqual(len(case_events), 1)
        self.assertEqual(
            case_events[0]["dedup_key"],
            f"event:{EVENT_CASE_WAITING_FOR_EVIDENCE}:"
            "case-indeed-a1-endpoint-behavior:2026-09-16T13:05:00+03:30",
        )

    def test_human_review_event(self):
        previous = snapshot_of(
            activity_at(
                NOW,
                runs=[run_record(run_id="run-1")],
                cases=[
                    case_record(
                        case_status="COLLECTING_EVIDENCE",
                        decision_state="NEEDS_EVIDENCE",
                    )
                ],
            )
        )
        current = activity_at(
            NOW,
            runs=[run_record(run_id="run-1")],
            cases=[
                case_record(
                    case_status="READY_FOR_HUMAN_REVIEW",
                    decision_state="READY_FOR_HUMAN_REVIEW",
                )
            ],
        )
        reports = event_reports(current, previous)
        human = [r for r in reports if r["event_type"] == EVENT_HUMAN_REVIEW_REQUIRED]
        self.assertEqual(len(human), 1)
        self.assertIn("human review", human[0]["message"])

    def test_same_snapshot_never_repeats_events(self):
        activity = activity_at(NOW, runs=[run_record()], cases=[case_record()])
        previous = snapshot_of(activity_at(NOW))
        reports = event_reports(activity, previous)
        self.assertTrue(reports)
        self.assertEqual(event_reports(activity, snapshot_of(activity)), [])

    def test_event_count_is_bounded(self):
        previous = snapshot_of(activity_at(NOW))
        current = activity_at(
            NOW,
            lock=LOCK_HELD,
            runs=[run_record(run_id="run-new")],
            cases=[case_record()],
        )
        reports = event_reports(current, previous, limit=1)
        self.assertEqual(len(reports), 1)


if __name__ == "__main__":
    unittest.main()
