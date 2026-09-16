"""Focused tests for the R83 AI activity/runtime status core (pure engine).

No I/O, no Mongo, no network: every fact is injected. Real-environment
collection is covered separately by tests/test_research_activity_api.py.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from ai.knowledge.ai_activity_status import (
    LOCK_FREE,
    LOCK_HELD,
    LOCK_UNAVAILABLE,
    RULE_VERSION,
    RUN_STATUS_TO_ACTIVITY,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_REJECTIONS,
    STATUS_ERROR,
    STATUS_IDLE,
    STATUS_RUNNING,
    STATUS_UNKNOWN,
    STATUS_WAITING_FOR_EVIDENCE,
    STATUSES,
    build_activity_status,
    in_window,
    to_tehran,
    window_bounds,
)

TEHRAN = ZoneInfo("Asia/Tehran")


def run_record(
    *,
    run_id="run-20260916T100000Z",
    status="RESEARCH_COMPLETED",
    started="2026-09-16T09:30:00+00:00",
    completed="2026-09-16T09:32:00+00:00",
    results=None,
    failures=None,
):
    return {
        "run_id": run_id,
        "status": status,
        "started_at": started,
        "completed_at": completed,
        "plans_selected": 1,
        "plans_processed": 1,
        "results": results
        if results is not None
        else [
            {
                "plan_id": "r22-38d26f10681e9a0f",
                "cve_id": "CVE-2026-1557",
                "program": "dell",
                "status": "RESEARCH_COMPLETED",
                "evidence": 2,
                "sources": 3,
            }
        ],
        "failures": failures or [],
        "skipped": None,
    }


def case_record(
    *,
    case_id="case-indeed-a1-endpoint-behavior",
    case_status="WAITING_FOR_EVIDENCE",
    modified="2026-09-16T10:33:33+03:30",
    available="2",
    missing="2",
    actions="1",
    accepted="1",
    rejected="2",
):
    return {
        "case_id": case_id,
        "program": "indeed",
        "category": "RECON",
        "case_status": case_status,
        "sufficiency_state": "INSUFFICIENT",
        "decision_state": "NEEDS_EVIDENCE",
        "available_count": available,
        "missing_count": missing,
        "actions_count": actions,
        "validation_accepted": accepted,
        "validation_rejected": rejected,
        "modified_at": modified,
    }


NOW = datetime(2026, 9, 16, 13, 0, tzinfo=TEHRAN)


class TestStatusResolution(unittest.TestCase):
    def test_status_vocabulary_is_closed(self):
        for status in STATUSES:
            self.assertTrue(status)
        for agent_status, activity in RUN_STATUS_TO_ACTIVITY.items():
            self.assertIn(activity, STATUSES, agent_status)

    def test_unknown_when_state_not_observable(self):
        result = build_activity_status(now=NOW, lock_state=LOCK_UNAVAILABLE)
        self.assertEqual(result["status"], STATUS_UNKNOWN)
        self.assertEqual(result["status_basis"], "runtime_state_not_observable")
        self.assertIn("execution_lock_state", result["observability"]["unavailable_fields"])
        self.assertTrue(result["observability"]["unknown_is_not_failure"])

    def test_idle_with_no_runs_or_cases(self):
        result = build_activity_status(now=NOW, lock_state=LOCK_FREE)
        self.assertEqual(result["status"], STATUS_IDLE)
        self.assertEqual(result["status_basis"], "no_runs_no_cases")
        self.assertIsNone(result["last_run"])
        self.assertIsNone(result["current_case"])

    def test_running_when_lock_held(self):
        result = build_activity_status(
            now=NOW,
            lock_state=LOCK_HELD,
            run_records=[run_record()],
            case_records=[case_record()],
        )
        self.assertEqual(result["status"], STATUS_RUNNING)
        self.assertEqual(result["status_basis"], "execution_lock_held")
        self.assertIsNone(result["current_run"])
        self.assertIsNone(result["current_stage"])
        self.assertIn(
            "in_flight_case_and_stage",
            result["observability"]["unavailable_fields"],
        )

    def test_completed(self):
        result = build_activity_status(
            now=NOW, lock_state=LOCK_FREE, run_records=[run_record()]
        )
        self.assertEqual(result["status"], STATUS_COMPLETED)
        self.assertEqual(result["status_basis"], "latest_run_completed")

    def test_completed_with_rejections(self):
        result = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            run_records=[run_record(status="RESEARCH_PARTIAL", failures=[{"error": "TimeoutError"}])],
        )
        self.assertEqual(result["status"], STATUS_COMPLETED_WITH_REJECTIONS)
        self.assertEqual(result["status_basis"], "latest_run_partial")

    def test_error_and_bounded_last_error(self):
        result = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            run_records=[
                run_record(
                    status="RESEARCH_FAILED",
                    failures=[
                        {"error": "C:/secret/path.py:boom Authorization: Bearer abc123"}
                    ],
                )
            ],
        )
        self.assertEqual(result["status"], STATUS_ERROR)
        self.assertEqual(result["last_error"], "C")
        text = json.dumps(result)
        self.assertNotIn("Bearer", text)
        self.assertNotIn("C:/", text)
        self.assertNotIn("abc123", text)

    def test_waiting_case_precedes_completed_run(self):
        result = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            run_records=[run_record()],
            case_records=[case_record()],
        )
        self.assertEqual(result["status"], STATUS_WAITING_FOR_EVIDENCE)
        self.assertEqual(
            result["status_basis"], "latest_case_waiting_for_evidence"
        )
        self.assertEqual(
            result["current_case"]["case_id"],
            "case-indeed-a1-endpoint-behavior",
        )

    def test_case_present_without_runs_is_idle(self):
        result = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            case_records=[case_record(case_status="READY_FOR_HUMAN_REVIEW")],
        )
        self.assertEqual(result["status"], STATUS_IDLE)
        self.assertEqual(result["status_basis"], "case_present_no_runs")
        self.assertEqual(
            result["current_case"]["case_status"], "READY_FOR_HUMAN_REVIEW"
        )


class TestTehranTime(unittest.TestCase):
    def test_window_bounds_inside_window(self):
        start, end = window_bounds(NOW)
        self.assertEqual(start.isoformat(), "2026-09-16T12:00:00+03:30")
        self.assertEqual(end.isoformat(), "2026-09-17T00:00:00+03:30")

    def test_window_bounds_before_noon_uses_previous_day(self):
        morning = datetime(2026, 9, 16, 8, 0, tzinfo=TEHRAN)
        start, end = window_bounds(morning)
        self.assertEqual(start.isoformat(), "2026-09-15T12:00:00+03:30")
        self.assertEqual(end.isoformat(), "2026-09-16T00:00:00+03:30")

    def test_window_boundaries(self):
        noon = datetime(2026, 9, 16, 12, 0, tzinfo=TEHRAN)
        self.assertTrue(in_window(noon))
        just_before = datetime(2026, 9, 16, 11, 59, tzinfo=TEHRAN)
        self.assertFalse(in_window(just_before))
        midnight = datetime(2026, 9, 17, 0, 0, tzinfo=TEHRAN)
        self.assertFalse(in_window(midnight))

    def test_utc_timestamp_converted_to_tehran(self):
        converted = to_tehran("2026-09-16T09:00:00+00:00")
        self.assertEqual(converted.isoformat(), "2026-09-16T12:30:00+03:30")
        self.assertTrue(in_window(converted))

    def test_naive_timestamp_is_treated_as_tehran(self):
        converted = to_tehran("2026-09-16T13:00:00")
        self.assertEqual(converted.isoformat(), "2026-09-16T13:00:00+03:30")

    def test_daily_window_uses_tehran_not_utc(self):
        # 09:00 UTC = 12:30 Tehran -> inside the window.
        inside = run_record(
            started="2026-09-16T09:00:00+00:00",
            completed="2026-09-16T09:05:00+00:00",
        )
        # 07:00 UTC = 10:30 Tehran -> outside the window.
        outside = run_record(
            run_id="run-outside",
            started="2026-09-16T07:00:00+00:00",
            completed="2026-09-16T07:05:00+00:00",
        )
        result = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            run_records=[inside, outside],
        )
        self.assertEqual(result["daily"]["runs"], 1)
        self.assertEqual(result["daily"]["plans_processed"], 1)

    def test_daily_counts_aggregate(self):
        first = run_record()
        second = run_record(
            run_id="run-2",
            results=[
                {
                    "plan_id": "r22-fda96966ea7af4ae",
                    "cve_id": "CVE-2026-78203",
                    "program": "indeed",
                    "status": "RESEARCH_COMPLETED",
                    "evidence": 3,
                    "sources": 4,
                }
            ],
        )
        result = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            run_records=[first, second],
            case_records=[case_record(modified="2026-09-16T12:30:00+03:30")],
        )
        daily = result["daily"]
        self.assertEqual(daily["runs"], 2)
        self.assertEqual(daily["results"], 2)
        self.assertEqual(daily["evidence_acquired"], 5)
        self.assertEqual(daily["cases_processed"], 1)
        self.assertEqual(daily["accepted_hypotheses"], 1)
        self.assertEqual(daily["rejected_hypotheses"], 2)
        self.assertEqual(daily["evidence_available"], 2)
        self.assertEqual(daily["evidence_missing"], 2)
        self.assertEqual(daily["actions_generated"], 1)

    def test_duration_and_unparseable_timestamp(self):
        good = build_activity_status(
            now=NOW, lock_state=LOCK_FREE, run_records=[run_record()]
        )
        self.assertEqual(good["last_run"]["duration_seconds"], 120.0)
        broken = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            run_records=[run_record(started="not-a-time", completed="also-bad")],
        )
        self.assertEqual(broken["last_run"]["started_at"], "")
        self.assertIsNone(broken["last_run"]["duration_seconds"])
        self.assertFalse(broken["last_run"]["in_window"])


class TestBoundsAndSafety(unittest.TestCase):
    def test_output_is_bounded_and_deterministic(self):
        result = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            run_records=[run_record(run_id="x" * 200)],
            case_records=[case_record()],
        )
        self.assertLessEqual(len(result["last_run"]["run_id"]), 64)
        again = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            run_records=[run_record(run_id="x" * 200)],
            case_records=[case_record()],
        )
        self.assertEqual(json.dumps(result), json.dumps(again))

    def test_safety_flags(self):
        result = build_activity_status(now=NOW, lock_state=LOCK_FREE)
        self.assertEqual(result["rule_version"], RULE_VERSION)
        self.assertTrue(result["advisory"])
        self.assertTrue(result["research_only"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(result["safety"]["advisory"])
        self.assertTrue(result["safety"]["research_only"])
        self.assertFalse(result["safety"]["execution_performed"])
        self.assertFalse(result["safety"]["vulnerability_confirmed"])
        self.assertFalse(result["safety"]["exploit_authorized"])
        self.assertTrue(result["safety"]["human_authority_required"])

    def test_no_sensitive_content_in_output(self):
        result = build_activity_status(
            now=NOW,
            lock_state=LOCK_FREE,
            run_records=[run_record()],
            case_records=[case_record()],
            source_notes=["note with http://target.example/path"],
            source_errors=["Error: /etc/passwd token=abc123"],
        )
        text = json.dumps(result)
        self.assertNotIn("://", text)
        self.assertNotIn("token=abc123", text)
        self.assertNotIn("/etc/passwd", text)


if __name__ == "__main__":
    unittest.main()
