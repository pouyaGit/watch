"""tests/test_research_sessions.py — Stage R25.7 session tests.

Deterministic, offline tests for the research session time-accounting layer:
schema validation, append-only event storage, lifecycle transitions, time
accounting, outcome linking, the composed economic performance view, CLI, API
and UI, plus safety invariants (no execution, no targets, no payouts, no
automatic outcomes, Money Score unchanged).

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no browser, no PoC execution, no 5B-5J, no findings, no alerts, no Mongo
writes. Every write test uses temporary session/outcome directories.
"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge.research_sessions import (
    SessionNotFound,
    SessionStore,
    SessionValidationError,
)
from ai.schemas.research_session import (
    MAX_NOTES_CHARS,
    SESSION_RULE_VERSION,
    SESSION_STATUSES,
    ResearchSession,
    ResearchSessionEvent,
    event_id_for,
    session_id_for,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
DELL = "rl-af7ecfba1a86fc83"
INDEED = "rl-d1d66e2ee9d8467c"
TS1 = "2026-09-11T10:00:00+00:00"
TS2 = "2026-09-11T10:05:00+00:00"
TS3 = "2026-09-11T11:35:00+00:00"


def _event(**over):
    payload = {
        "event_id": "re-0123456789abcdef",
        "session_id": "rs-0123456789abcdef",
        "lead_id": DELL,
        "cve_id": CVE,
        "program": "dell",
        "event_type": "CREATED",
        "timestamp": TS1,
        "planned_minutes": 60,
        "actual_minutes": 0,
        "outcome_id": "",
        "note": "",
        "rule_version": SESSION_RULE_VERSION,
        "research_only": True,
    }
    payload.update(over)
    return ResearchSessionEvent(**payload)


class _Dirs(unittest.TestCase):
    def setUp(self):
        self.s_tmp = tempfile.TemporaryDirectory()
        self.o_tmp = tempfile.TemporaryDirectory()
        self.sessions_dir = Path(self.s_tmp.name)
        self.outcomes_dir = Path(self.o_tmp.name)
        self._p1 = mock.patch(
            "backend.research_sessions.SESSIONS_DIR", self.sessions_dir)
        self._p2 = mock.patch(
            "backend.research_outcomes.OUTCOMES_DIR", self.outcomes_dir)
        self._p1.start()
        self._p2.start()

    def tearDown(self):
        self._p1.stop()
        self._p2.stop()
        self.s_tmp.cleanup()
        self.o_tmp.cleanup()


class TestSessionSchema(unittest.TestCase):
    def test_statuses(self):
        self.assertEqual(SESSION_STATUSES,
                         ("PLANNED", "IN_PROGRESS", "COMPLETED",
                          "ABANDONED"))
        for status in SESSION_STATUSES:
            session = ResearchSession(
                session_id="rs-0123456789abcdef", lead_id=DELL, cve_id=CVE,
                program="dell", status=status, created_at=TS1)
            self.assertEqual(session.status, status)

    def test_invalid_status_rejected(self):
        for bad in ("VULNERABLE", "VERIFIED", "RUNNING", "BOGUS"):
            with self.subTest(status=bad):
                with self.assertRaises(ValueError):
                    ResearchSession(
                        session_id="rs-0123456789abcdef", lead_id=DELL,
                        cve_id=CVE, program="dell", status=bad,
                        created_at=TS1)

    def test_event_types(self):
        for event_type in ("CREATED", "STARTED", "COMPLETED", "ABANDONED"):
            self.assertEqual(_event(event_type=event_type).event_type,
                             event_type)
        with self.assertRaises(ValueError):
            _event(event_type="EXECUTED")

    def test_malformed_ids(self):
        with self.assertRaises(ValueError):
            _event(lead_id="not-a-lead")
        with self.assertRaises(ValueError):
            _event(cve_id="not-a-cve")
        with self.assertRaises(ValueError):
            _event(program="bad program!")
        with self.assertRaises(ValueError):
            _event(session_id="rs-xyz")
        with self.assertRaises(ValueError):
            _event(event_id="not-an-event")
        with self.assertRaises(ValueError):
            _event(outcome_id="not-an-outcome")

    def test_minutes(self):
        with self.assertRaises(ValueError):
            _event(planned_minutes=-1)
        with self.assertRaises(ValueError):
            _event(actual_minutes=-5)
        with self.assertRaises(ValueError):
            _event(actual_minutes=10 ** 9)
        with self.assertRaises(ValueError):
            _event(planned_minutes="many")

    def test_note_bounds_and_normalization(self):
        event = _event(note="  line one  \r\n\r\n\r\n line two ")
        self.assertEqual(event.note, "line one\n\nline two")
        with self.assertRaises(ValueError):
            _event(note="a" * (MAX_NOTES_CHARS + 1))

    def test_timestamp_validation(self):
        with self.assertRaises(ValueError):
            _event(timestamp="")
        with self.assertRaises(ValueError):
            _event(timestamp="not-a-time")
        session = ResearchSession(
            session_id="rs-0123456789abcdef", lead_id=DELL, cve_id=CVE,
            program="dell", created_at=TS1, started_at="",
            ended_at="2026-09-11T11:00:00+00:00")
        self.assertEqual(session.ended_at, "2026-09-11T11:00:00+00:00")
        with self.assertRaises(ValueError):
            ResearchSession(
                session_id="rs-0123456789abcdef", lead_id=DELL, cve_id=CVE,
                program="dell", created_at=TS1, ended_at="bad")

    def test_unknown_fields_rejected(self):
        for field in ("target_url", "target", "ip", "domain", "credential",
                      "executed", "command", "payout_amount", "bounty",
                      "verified", "production_finding"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    _event(**{field: "x"})
                with self.assertRaises(ValueError):
                    ResearchSession(
                        session_id="rs-0123456789abcdef", lead_id=DELL,
                        cve_id=CVE, program="dell", created_at=TS1,
                        **{field: "x"})

    def test_no_forbidden_model_fields(self):
        for model in (ResearchSessionEvent, ResearchSession):
            fields = set(model.model_fields)
            for token in ("target", "url", "ip", "domain", "credential",
                          "executed", "command", "payout", "bounty",
                          "reward", "amount", "vulnerable", "verified",
                          "exploited", "finding"):
                self.assertFalse(
                    [f for f in fields if token in f.lower()],
                    f"forbidden field token {token} in {model.__name__}: "
                    f"{fields}")

    def test_rule_version_fixed_and_research_only(self):
        event = _event(rule_version="r99-9", research_only=True)
        self.assertEqual(event.rule_version, SESSION_RULE_VERSION)
        with self.assertRaises(ValueError):
            _event(research_only=False)

    def test_derived_time_accounting(self):
        session = ResearchSession(
            session_id="rs-0123456789abcdef", lead_id=DELL, cve_id=CVE,
            program="dell", status="COMPLETED", created_at=TS1,
            started_at=TS2, ended_at=TS3, planned_minutes=60,
            actual_minutes=90)
        self.assertEqual(session.variance_minutes, 30)
        self.assertEqual(session.efficiency_ratio, 0.6667)
        zero = ResearchSession(
            session_id="rs-0123456789abcdef", lead_id=DELL, cve_id=CVE,
            program="dell", created_at=TS1, planned_minutes=60,
            actual_minutes=0)
        self.assertEqual(zero.variance_minutes, -60)
        self.assertIsNone(zero.efficiency_ratio)


class TestSessionIds(unittest.TestCase):
    def test_deterministic(self):
        first = session_id_for(DELL, 60, "note")
        self.assertEqual(first, session_id_for(DELL, 60, "note"))
        self.assertTrue(first.startswith("rs-"))

    def test_distinct(self):
        base = session_id_for(DELL, 60, "note")
        self.assertNotEqual(base, session_id_for(INDEED, 60, "note"))
        self.assertNotEqual(base, session_id_for(DELL, 90, "note"))
        self.assertNotEqual(base, session_id_for(DELL, 60, "other"))

    def test_event_id_deterministic(self):
        first = event_id_for("rs-0123456789abcdef", "CREATED", TS1)
        self.assertEqual(
            first, event_id_for("rs-0123456789abcdef", "CREATED", TS1))
        self.assertNotEqual(
            first, event_id_for("rs-0123456789abcdef", "STARTED", TS1))


class TestSessionStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SessionStore(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def _append(self, **over):
        return self.store.append_event(_event(**over))

    def test_append_and_fold(self):
        event, created = self._append()
        self.assertTrue(created)
        session = self.store.fold(event.session_id)
        self.assertEqual(session.status, "PLANNED")
        self.assertEqual(session.planned_minutes, 60)
        self.assertEqual(session.notes, "")

    def test_lifecycle_fold(self):
        self._append()
        self._append(event_id="re-0000000000000002", event_type="STARTED",
                     timestamp=TS2, planned_minutes=60)
        self._append(event_id="re-0000000000000003", event_type="COMPLETED",
                     timestamp=TS3, actual_minutes=45, note="done")
        session = self.store.fold("rs-0123456789abcdef")
        self.assertEqual(session.status, "COMPLETED")
        self.assertEqual(session.started_at, TS2)
        self.assertEqual(session.ended_at, TS3)
        self.assertEqual(session.actual_minutes, 45)
        self.assertEqual(session.variance_minutes, -15)
        self.assertEqual(session.notes, "done")

    def test_duplicate_event_idempotent(self):
        first, created_first = self._append()
        second, created_second = self._append()
        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(first.event_id, second.event_id)
        lines = [l for l in self.store.path.read_text().splitlines()
                 if l.strip()]
        self.assertEqual(len(lines), 1)

    def test_append_only(self):
        self._append()
        self._append(event_id="re-0000000000000002", event_type="STARTED",
                     timestamp=TS2)
        lines = [l for l in self.store.path.read_text().splitlines()
                 if l.strip()]
        self.assertEqual(len(lines), 2)

    def test_fold_ignores_out_of_order_duplicates(self):
        self._append()
        self._append(event_id="re-0000000000000002", event_type="COMPLETED",
                     timestamp=TS3, actual_minutes=10)
        self._append(event_id="re-0000000000000003", event_type="STARTED",
                     timestamp=TS2)
        self._append(event_id="re-0000000000000004", event_type="COMPLETED",
                     timestamp=TS3, actual_minutes=99)
        session = self.store.fold("rs-0123456789abcdef")
        self.assertEqual(session.status, "COMPLETED")
        self.assertEqual(session.actual_minutes, 10)

    def test_malformed_line_skipped(self):
        self._append()
        with open(self.store.path, "a", encoding="utf-8") as handle:
            handle.write("{not json}\n")
        data = self.store.list()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["malformed"], 1)
        self.assertTrue(data["research_only"])

    def test_unknown_and_malformed_get(self):
        with self.assertRaises(SessionNotFound):
            self.store.get("rs-ffffffffffffffff")
        with self.assertRaises(SessionValidationError):
            self.store.get("nope")

    def test_list_filters_and_order(self):
        self._append()
        self._append(
            session_id="rs-0000000000000002", event_id="re-0000000000000002",
            lead_id=INDEED, program="indeed", timestamp="2026-09-11T09:00:00+00:00")
        self._append(
            session_id="rs-0000000000000003", event_id="re-0000000000000003",
            timestamp="2026-09-11T12:00:00+00:00", planned_minutes=10)
        self.assertEqual(self.store.list()["total"], 3)
        self.assertEqual(self.store.list(lead_id=DELL)["total"], 2)
        self.assertEqual(self.store.list(program="indeed")["total"], 1)
        items = self.store.list(limit=1)["items"]
        self.assertEqual(items[0]["session_id"], "rs-0000000000000003")
        self.assertEqual(self.store.list(limit=10000)["limit"], 100)

    def test_no_writes_on_reads(self):
        before = self.tmp.name and list(Path(self.tmp.name).rglob("*"))
        self.store.list()
        try:
            self.store.get("rs-ffffffffffffffff")
        except SessionNotFound:
            pass
        self.assertEqual(list(Path(self.tmp.name).rglob("*")), before)


class TestSessionLifecycle(_Dirs):
    def test_create_is_planned_and_not_auto_started(self):
        from backend import research_sessions as rs
        result = rs.create_session(DELL, planned_minutes=60)
        self.assertTrue(result["created"])
        self.assertEqual(result["session"]["status"], "PLANNED")
        self.assertEqual(result["session"]["started_at"], "")

    def test_create_idempotent(self):
        from backend import research_sessions as rs
        first = rs.create_session(DELL, planned_minutes=60)
        second = rs.create_session(DELL, planned_minutes=60)
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["session"]["session_id"],
                         second["session"]["session_id"])

    def test_start_and_complete(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        started = rs.start_session(session_id)
        self.assertEqual(started["session"]["status"], "IN_PROGRESS")
        self.assertTrue(started["session"]["started_at"])
        completed = rs.complete_session(session_id, actual_minutes=45)
        self.assertEqual(completed["session"]["status"], "COMPLETED")
        self.assertEqual(completed["session"]["actual_minutes"], 45)
        self.assertEqual(completed["session"]["variance_minutes"], -15)

    def test_complete_requires_in_progress(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        with self.assertRaises(SessionValidationError):
            rs.complete_session(session_id, actual_minutes=10)

    def test_complete_after_abandon_rejected(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.abandon_session(session_id)
        with self.assertRaises(SessionValidationError):
            rs.complete_session(session_id, actual_minutes=10)

    def test_complete_idempotent(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        first = rs.complete_session(session_id, actual_minutes=10)
        second = rs.complete_session(session_id, actual_minutes=99)
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(second["session"]["actual_minutes"], 10)

    def test_abandon_from_planned_and_in_progress(self):
        from backend import research_sessions as rs
        first = rs.create_session(DELL, 60)["session"]["session_id"]
        abandoned = rs.abandon_session(first)
        self.assertEqual(abandoned["session"]["status"], "ABANDONED")
        second = rs.create_session(DELL, 90, note="second")["session"][
            "session_id"]
        rs.start_session(second)
        self.assertEqual(
            rs.abandon_session(second)["session"]["status"], "ABANDONED")
        self.assertFalse(rs.abandon_session(second)["created"])

    def test_start_idempotent_when_in_progress(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        again = rs.start_session(session_id)
        self.assertFalse(again["created"])

    def test_begin_session_creates_and_starts(self):
        from backend import research_sessions as rs
        result = rs.begin_session(DELL, 60)
        self.assertEqual(result["session"]["status"], "IN_PROGRESS")

    def test_unknown_lead_rejected(self):
        from backend import research_sessions as rs
        with self.assertRaises(SessionValidationError):
            rs.create_session("rl-ffffffffffffffff")

    def test_negative_minutes_rejected(self):
        from backend import research_sessions as rs
        with self.assertRaises(SessionValidationError):
            rs.create_session(DELL, planned_minutes=-1)
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        with self.assertRaises(SessionValidationError):
            rs.complete_session(session_id, actual_minutes=-5)


class TestTimeAccounting(_Dirs):
    def test_derived_actual_minutes(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(
            DELL, 60, timestamp=TS1)["session"]["session_id"]
        rs.start_session(session_id, timestamp=TS2)
        result = rs.complete_session(session_id, ended_at=TS3)
        session = result["session"]
        self.assertEqual(session["actual_minutes"], 90)
        self.assertEqual(session["variance_minutes"], 30)
        self.assertEqual(session["efficiency_ratio"], 0.6667)

    def test_zero_duration(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        session = rs.complete_session(session_id,
                                      actual_minutes=0)["session"]
        self.assertEqual(session["actual_minutes"], 0)
        self.assertEqual(session["variance_minutes"], -60)
        self.assertIsNone(session["efficiency_ratio"])

    def test_negative_derived_duration_rejected(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(
            DELL, 60, timestamp=TS2)["session"]["session_id"]
        rs.start_session(session_id, timestamp=TS3)
        with self.assertRaises(SessionValidationError):
            rs.complete_session(session_id, ended_at=TS1)

    def test_summary_time_fields(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        rs.complete_session(session_id, actual_minutes=45)
        abandoned = rs.create_session(DELL, 30, note="ab")["session"][
            "session_id"]
        rs.abandon_session(abandoned, actual_minutes=10)
        summary = rs.summarize_session(DELL)
        self.assertEqual(summary["total_sessions"], 2)
        self.assertEqual(summary["completed_sessions"], 1)
        self.assertEqual(summary["abandoned_sessions"], 1)
        self.assertEqual(summary["planned_time"], 90)
        self.assertEqual(summary["actual_time"], 55)
        self.assertEqual(summary["estimated_vs_actual_delta"], -35)
        self.assertEqual(summary["average_actual_minutes"], 27)
        self.assertTrue(summary["research_only"])


class TestOutcomeLinking(_Dirs):
    def _record_outcome(self, lead_id=DELL, status="ACCEPTED",
                        timestamp="2026-09-11T12:00:00+00:00"):
        from backend import research_outcomes
        return research_outcomes.record_outcome(
            lead_id=lead_id, status=status, time_spent_minutes=10,
            note=f"{status}-{lead_id}", timestamp=timestamp,
        )["outcome"]["outcome_id"]

    def test_link_outcome_and_time_to_outcome(self):
        from backend import research_sessions as rs
        outcome_id = self._record_outcome()
        session_id = rs.create_session(
            DELL, 60, timestamp=TS1)["session"]["session_id"]
        rs.start_session(session_id, timestamp=TS2)
        result = rs.complete_session(
            session_id, ended_at=TS3, outcome_id=outcome_id)
        self.assertEqual(result["session"]["outcome_id"], outcome_id)
        summary = rs.summarize_session(DELL)
        # outcome at 12:00, session ended 11:35 -> 25 minutes
        self.assertEqual(summary["time_to_outcome"], 25)
        self.assertEqual(summary["time_to_outcome_samples"], 1)

    def test_wrong_lead_outcome_rejected(self):
        from backend import research_sessions as rs
        outcome_id = self._record_outcome(lead_id=INDEED)
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        with self.assertRaises(SessionValidationError):
            rs.complete_session(session_id, actual_minutes=10,
                                outcome_id=outcome_id)

    def test_unknown_outcome_rejected(self):
        from backend import research_sessions as rs
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        with self.assertRaises(SessionValidationError):
            rs.complete_session(session_id, actual_minutes=10,
                                outcome_id="ro-ffffffffffffffff")

    def test_no_automatic_outcome_creation(self):
        from backend import research_outcomes
        from backend import research_sessions as rs
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        rs.complete_session(session_id, actual_minutes=10)
        self.assertEqual(
            research_outcomes.summarize_lead_outcomes(DELL)["attempts"], 0)

    def test_non_terminal_outcome_has_no_time_to_outcome(self):
        from backend import research_sessions as rs
        outcome_id = self._record_outcome(status="IN_PROGRESS")
        session_id = rs.create_session(
            DELL, 60, timestamp=TS1)["session"]["session_id"]
        rs.start_session(session_id, timestamp=TS2)
        rs.complete_session(session_id, ended_at=TS3, outcome_id=outcome_id)
        summary = rs.summarize_session(DELL)
        self.assertIsNone(summary["time_to_outcome"])
        self.assertEqual(summary["time_to_outcome_samples"], 0)


class TestEconomicPerformance(_Dirs):
    def test_performance_view_fields_and_composition(self):
        from backend import research_outcomes
        from backend import research_sessions as rs
        research_outcomes.record_outcome(
            DELL, "ACCEPTED", 20, "ok", timestamp=TS3)
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        rs.complete_session(session_id, actual_minutes=90)
        perf = rs.lead_execution_performance(DELL)
        for key in ("lead_id", "cve_id", "program", "money_score",
                    "priority", "confidence", "planned_time", "actual_time",
                    "total_sessions", "completed_sessions",
                    "abandoned_sessions", "accepted", "duplicate",
                    "rejected", "wasted_time", "acceptance_rate",
                    "wasted_rate", "average_actual_minutes",
                    "estimated_vs_actual_delta"):
            self.assertIn(key, perf)
        self.assertEqual(perf["money_score"], 53)
        self.assertEqual(perf["priority"], "P3_MEDIUM")
        self.assertEqual(perf["planned_time"], 60)
        self.assertEqual(perf["actual_time"], 90)
        self.assertEqual(perf["estimated_vs_actual_delta"], 30)
        self.assertEqual(perf["accepted"], 1)
        self.assertEqual(perf["acceptance_rate"], 1.0)
        self.assertEqual(perf["wasted_rate"], 0.0)
        self.assertTrue(perf["research_only"])
        self.assertEqual(perf["rule_version"], "r25-1")

    def test_money_score_unchanged_by_sessions(self):
        from backend import research_economics
        from backend import research_sessions as rs
        before = research_economics.build_economics()
        session_id = rs.create_session(DELL, 60)["session"]["session_id"]
        rs.start_session(session_id)
        rs.complete_session(session_id, actual_minutes=30)
        rs.lead_execution_performance(DELL)
        after = research_economics.build_economics()
        self.assertEqual(before, after)
        self.assertEqual([e["money_score"] for e in after], [53, 53])

    def test_unknown_lead_performance(self):
        from backend import research_sessions as rs
        with self.assertRaises(ValueError):
            rs.lead_execution_performance("rl-ffffffffffffffff")


class TestSessionApi(_Dirs):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def _post(self, path, body=None):
        params = {"api_key": API_KEY} if API_KEY else {}
        return self.client.post(path, json=body or {}, params=params)

    def test_auth_required(self):
        for method, path in (("get", "/api/research/economics/sessions"),
                             ("post", "/api/research/economics/sessions")):
            with self.subTest(path=path):
                r = getattr(self.client, method)(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)

    def test_lifecycle_and_reads(self):
        created = self._post("/api/research/economics/sessions",
                             {"lead_id": DELL, "planned_minutes": 60})
        self.assertEqual(created.status_code, 201)
        session = created.json()["session"]
        self.assertEqual(session["status"], "PLANNED")
        session_id = session["session_id"]

        started = self._post(
            f"/api/research/economics/sessions/{session_id}/start")
        self.assertEqual(started.status_code, 200)
        self.assertEqual(started.json()["session"]["status"], "IN_PROGRESS")

        completed = self._post(
            f"/api/research/economics/sessions/{session_id}/complete",
            {"actual_minutes": 45})
        self.assertEqual(completed.status_code, 200)
        body = completed.json()["session"]
        self.assertEqual(body["status"], "COMPLETED")
        self.assertEqual(body["actual_minutes"], 45)
        self.assertEqual(body["variance_minutes"], -15)

        listing = self._get("/api/research/economics/sessions")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["total"], 1)
        self.assertTrue(listing.json()["research_only"])

        detail = self._get(
            f"/api/research/economics/sessions/{session_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["session_id"], session_id)

        summary = self._get("/api/research/economics/sessions/summary",
                            lead_id=DELL)
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.json()["total_sessions"], 1)
        self.assertEqual(summary.json()["money_score"], 53)

    def test_abandon_route(self):
        session_id = self._post(
            "/api/research/economics/sessions",
            {"lead_id": DELL, "planned_minutes": 30,
             "note": "abandon me"}).json()["session"]["session_id"]
        r = self._post(
            f"/api/research/economics/sessions/{session_id}/abandon",
            {"note": "no time"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["session"]["status"], "ABANDONED")

    def test_validation_and_errors(self):
        bad_extra = self._post("/api/research/economics/sessions",
                               {"lead_id": DELL, "target_url": "https://x"})
        self.assertEqual(bad_extra.status_code, 422)
        bad_payout = self._post("/api/research/economics/sessions",
                                {"lead_id": DELL, "payout": 5})
        self.assertEqual(bad_payout.status_code, 422)
        unknown = self._post("/api/research/economics/sessions",
                             {"lead_id": "rl-ffffffffffffffff"})
        self.assertEqual(unknown.status_code, 400)
        missing = self._get(
            "/api/research/economics/sessions/rs-ffffffffffffffff")
        self.assertEqual(missing.status_code, 404)
        bad_transition = self._post(
            "/api/research/economics/sessions/rs-ffffffffffffffff/start")
        self.assertEqual(bad_transition.status_code, 404)
        # complete a PLANNED session -> invalid transition
        session_id = self._post(
            "/api/research/economics/sessions",
            {"lead_id": DELL, "planned_minutes": 10,
             "note": "planned only"}).json()["session"]["session_id"]
        r = self._post(
            f"/api/research/economics/sessions/{session_id}/complete",
            {"actual_minutes": 5})
        self.assertEqual(r.status_code, 400)

    def test_filters(self):
        self._post("/api/research/economics/sessions",
                   {"lead_id": DELL, "planned_minutes": 10, "note": "a"})
        self._post("/api/research/economics/sessions",
                   {"lead_id": INDEED, "planned_minutes": 10, "note": "b"})
        self.assertEqual(
            self._get("/api/research/economics/sessions",
                      lead_id=DELL).json()["total"], 1)
        self.assertEqual(
            self._get("/api/research/economics/sessions",
                      program="indeed").json()["total"], 1)
        self.assertEqual(
            self._get("/api/research/economics/sessions",
                      status="PLANNED").json()["total"], 2)

    def test_no_money_score_change(self):
        from backend import research_economics
        before = research_economics.build_economics()
        session_id = self._post(
            "/api/research/economics/sessions",
            {"lead_id": DELL, "planned_minutes": 10, "note": "money"}).json()[
                "session"]["session_id"]
        self._post(f"/api/research/economics/sessions/{session_id}/start")
        self._post(
            f"/api/research/economics/sessions/{session_id}/complete",
            {"actual_minutes": 10})
        after = research_economics.build_economics()
        self.assertEqual(before, after)


class TestSessionCli(_Dirs):
    def _run(self, argv):
        from ai.research_cli import main
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_start_complete_show_list_summary(self):
        code, out, _ = self._run([
            "economics", "session", "start", "--lead-id", DELL,
            "--planned-minutes", "60", "--json"])
        self.assertEqual(code, 0)
        session_id = json.loads(out)["session"]["session_id"]
        code, out, _ = self._run([
            "economics", "session", "complete", "--session-id", session_id,
            "--actual-minutes", "45", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["session"]["status"], "COMPLETED")
        code, out, _ = self._run(["economics", "session", "list", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["total"], 1)
        code, out, _ = self._run([
            "economics", "session", "show", "--session-id", session_id,
            "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["session_id"], session_id)
        code, out, _ = self._run([
            "economics", "session", "summary", "--lead-id", DELL, "--json"])
        self.assertEqual(code, 0)
        summary = json.loads(out)
        self.assertEqual(summary["actual_time"], 45)
        self.assertEqual(summary["money_score"], 53)

    def test_human_output(self):
        code, out, _ = self._run([
            "economics", "session", "list"])
        self.assertEqual(code, 0)
        self.assertIn("none recorded", out)
        code, out, _ = self._run([
            "economics", "session", "start", "--lead-id", DELL,
            "--planned-minutes", "30"])
        self.assertEqual(code, 0)
        self.assertIn("Research session started", out)
        self.assertIn("Planned:  30 min", out)

    def test_abandon(self):
        self._run(["economics", "session", "start", "--lead-id", DELL,
                   "--planned-minutes", "10", "--json"])
        session_id = json.loads(self._run([
            "economics", "session", "list", "--json"])[1])["items"][0][
                "session_id"]
        code, out, _ = self._run([
            "economics", "session", "abandon", "--session-id", session_id,
            "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["session"]["status"], "ABANDONED")

    def test_errors(self):
        code, _, err = self._run([
            "economics", "session", "start", "--lead-id",
            "rl-ffffffffffffffff"])
        self.assertEqual(code, 1)
        self.assertIn("unknown lead_id", err)
        code, _, err = self._run([
            "economics", "session", "show", "--session-id",
            "rs-ffffffffffffffff"])
        self.assertEqual(code, 1)

    def test_cli_rejects_payout_and_target_flags(self):
        for flag in ("--payout", "--target", "--execute", "--nuclei"):
            with self.subTest(flag=flag):
                with self.assertRaises(SystemExit) as ctx:
                    with redirect_stderr(io.StringIO()):
                        self._run([
                            "economics", "session", "start",
                            "--lead-id", DELL, flag, "x"])
                self.assertEqual(ctx.exception.code, 2)


class TestSessionUi(_Dirs):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def _post(self, path, **data):
        params = {"api_key": API_KEY} if API_KEY else {}
        return self.client.post(path, data=data, params=params,
                                follow_redirects=False)

    def test_zero_session_state(self):
        r = self._get(f"/ui/research/leads/{DELL}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research session", r.text)
        self.assertIn("Start research session", r.text)
        self.assertIn("Sessions", r.text)
        # the session panel itself carries no execution vocabulary
        panel = r.text.split("Research session", 1)[1].split(
            "Why investigate", 1)[0]
        for token in ("scan", "run nuclei", "target url"):
            self.assertNotIn(token, panel.lower())

    def test_active_session_and_completion(self):
        started = self._post(f"/ui/research/leads/{DELL}/session/start",
                             planned_minutes="60", note="ui")
        self.assertEqual(started.status_code, 303)
        self.assertIn("session_saved=started", started.headers["location"])
        active = self._get(f"/ui/research/leads/{DELL}")
        self.assertIn("Complete session", active.text)
        self.assertIn("Abandon session", active.text)
        self.assertIn("outcome_id", active.text)
        session_id = json.loads(self._get(
            "/api/research/economics/sessions", lead_id=DELL).text)[
                "items"][0]["session_id"]
        done = self._post(
            f"/ui/research/leads/{DELL}/session/{session_id}/complete",
            actual_minutes="45", outcome_id="", note="done")
        self.assertEqual(done.status_code, 303)
        after = self._get(f"/ui/research/leads/{DELL}",
                          session_saved="completed")
        self.assertIn("Session completed", after.text)
        self.assertIn("45 min", after.text)
        self.assertIn("Start research session", after.text)

    def test_abandon_from_ui(self):
        self._post(f"/ui/research/leads/{DELL}/session/start",
                   planned_minutes="10", note="abandon-ui")
        session_id = json.loads(self._get(
            "/api/research/economics/sessions", lead_id=DELL).text)[
                "items"][0]["session_id"]
        r = self._post(
            f"/ui/research/leads/{DELL}/session/{session_id}/abandon",
            note="stop")
        self.assertEqual(r.status_code, 303)
        after = self._get(f"/ui/research/leads/{DELL}",
                          session_saved="abandoned")
        self.assertIn("Session abandoned", after.text)
        self.assertIn("0 / 1", after.text)

    def test_invalid_completion_renders_error(self):
        self._post(f"/ui/research/leads/{DELL}/session/start",
                   planned_minutes="10", note="bad-complete")
        session_id = json.loads(self._get(
            "/api/research/economics/sessions", lead_id=DELL).text)[
                "items"][0]["session_id"]
        r = self._post(
            f"/ui/research/leads/{DELL}/session/{session_id}/complete",
            actual_minutes="-5")
        self.assertEqual(r.status_code, 400)


class TestRealCorpus(_Dirs):
    def test_zero_sessions_outcomes_and_unchanged_money(self):
        from backend import research_economics
        from backend import research_calibration
        from backend import research_sessions as rs
        for lead in (DELL, INDEED):
            summary = rs.summarize_session(lead)
            self.assertEqual(summary["total_sessions"], 0)
            self.assertEqual(summary["actual_time"], 0)
        economics = research_economics.build_economics()
        self.assertEqual([e["money_score"] for e in economics], [53, 53])
        report = research_calibration.build_report()
        self.assertEqual(report["recommendation"], "INSUFFICIENT_DATA")
        self.assertEqual(report["total_terminal_outcomes"], 0)
        self.assertTrue(report["weights_unchanged"])
        self.assertFalse(any(self.sessions_dir.rglob("*")))
        self.assertFalse(any(self.outcomes_dir.rglob("*")))


class TestSafety(unittest.TestCase):
    def test_no_execution_tokens(self):
        for rel in ("ai/schemas/research_session.py",
                    "ai/knowledge/research_sessions.py",
                    "backend/research_sessions.py"):
            source = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            for token in ("import subprocess", "subprocess.",
                          "import socket", "socket.",
                          "import requests", "requests.",
                          "import httpx", "httpx.",
                          "import openai", "import anthropic",
                          "from ai.llm", "nuclei.", "Popen(",
                          "selenium", "playwright", "os.system(",
                          "urlopen"):
                self.assertNotIn(token, source,
                                 f"{token} found in {rel}")

    def test_no_auto_start_in_source(self):
        source = (Path("/opt/watch")
                  / "backend/research_sessions.py").read_text(encoding="utf-8")
        # create_session must never append a STARTED event
        create_body = source.split("def create_session", 1)[1].split(
            "def start_session", 1)[0]
        self.assertNotIn("STARTED", create_body)

    def test_money_score_constants_unchanged(self):
        from ai.knowledge import economics
        self.assertEqual(economics.MONEY_W_VALUE, 0.55)
        self.assertEqual(economics.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(economics.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(economics.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(economics.RULE_VERSION, "r25-1")

    def test_session_no_forbidden_fields(self):
        for model in (ResearchSessionEvent, ResearchSession):
            blob = json.dumps(list(model.model_fields)).lower()
            for token in ("target", "url", "ip", "domain", "credential",
                          "executed", "command", "payout", "bounty",
                          "reward", "amount", "vulnerable", "verified",
                          "exploited", "finding"):
                self.assertNotIn(token, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
