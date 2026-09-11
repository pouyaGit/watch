"""tests/test_research_outcomes.py — Stage R25.5 outcome-capture tests.

Deterministic, offline tests for the append-only economic outcome layer:
schema validation, deterministic ids, idempotent/append-only storage,
fail-closed reads, projections/summaries, API/CLI/UI, and safety invariants
(no payout fields, no execution, no Money Score formula changes).

No network, no DNS, no LLM, no subprocess, no target interaction, no
Nuclei, no PoC execution, no 5B-5J, no findings, no alerts, no Mongo
writes. Every write test uses a temporary outcomes directory.
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

from ai.knowledge.research_outcomes import (
    OutcomeNotFound,
    OutcomeStore,
    OutcomeValidationError,
)
from ai.schemas.research_outcome import (
    MAX_NOTE_CHARS,
    OUTCOME_RULE_VERSION,
    OUTCOME_SOURCES,
    OUTCOME_STATUSES,
    ResearchOutcome,
    normalize_note,
    outcome_id_for,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"


def _lead_id(program="dell"):
    from backend.research_leads import lead_id_for
    return lead_id_for(CVE, program)


def _base_payload(**over):
    payload = {
        "outcome_id": "ro-0123456789abcdef",
        "lead_id": _lead_id(),
        "cve_id": CVE,
        "program": "dell",
        "status": "ACCEPTED",
        "timestamp": "2026-09-11T12:00:00+00:00",
        "researcher_note": "",
        "time_spent_minutes": 0,
        "source": "MANUAL",
        "rule_version": OUTCOME_RULE_VERSION,
    }
    payload.update(over)
    return payload


class TestOutcomeSchema(unittest.TestCase):
    def test_all_status_values_valid(self):
        for status in OUTCOME_STATUSES:
            record = ResearchOutcome(**_base_payload(status=status))
            self.assertEqual(record.status, status)

    def test_all_source_values_valid(self):
        for source in OUTCOME_SOURCES:
            record = ResearchOutcome(**_base_payload(source=source))
            self.assertEqual(record.source, source)

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(status="BOGUS"))
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(status="VULNERABLE"))
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(status="VERIFIED"))

    def test_malformed_lead_id_rejected(self):
        for bad in ("", "dell", "rl-xyz", "rq-0123456789abcdef"):
            with self.subTest(lead_id=bad):
                with self.assertRaises(ValueError):
                    ResearchOutcome(**_base_payload(lead_id=bad))

    def test_malformed_cve_rejected(self):
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(cve_id="not-a-cve"))

    def test_negative_time_rejected(self):
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(time_spent_minutes=-1))
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(time_spent_minutes=-75))

    def test_absurd_time_rejected(self):
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(time_spent_minutes=10**9))

    def test_non_integer_time_rejected(self):
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(time_spent_minutes="many"))

    def test_note_bounds(self):
        short = ResearchOutcome(**_base_payload(
            researcher_note="ok"))
        self.assertEqual(short.researcher_note, "ok")
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(
                researcher_note="a" * (MAX_NOTE_CHARS + 1)))

    def test_note_whitespace_normalization(self):
        first = ResearchOutcome(**_base_payload(
            researcher_note="  line one  \r\n\r\n\r\n  line two\t\r\n  "))
        second = ResearchOutcome(**_base_payload(
            researcher_note="line one\n\nline two"))
        self.assertEqual(first.researcher_note, second.researcher_note)
        self.assertEqual(first.researcher_note, "line one\n\nline two")
        self.assertEqual(normalize_note(" \t \n  "), "")

    def test_unknown_fields_rejected(self):
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(payout_amount=500))
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(bounty=500))
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(verified=True))
        with self.assertRaises(ValueError):
            ResearchOutcome(**_base_payload(production_finding=True))

    def test_no_payout_or_verdict_model_fields(self):
        fields = set(ResearchOutcome.model_fields)
        for token in ("payout", "bounty", "reward", "amount", "price",
                      "usd", "vulnerable", "verified", "exploited",
                      "finding", "production_finding"):
            self.assertFalse([f for f in fields if token in f.lower()],
                             f"forbidden field token {token} in {fields}")

    def test_rule_version_fixed(self):
        record = ResearchOutcome(**_base_payload(rule_version="r99-9"))
        self.assertEqual(record.rule_version, OUTCOME_RULE_VERSION)

    def test_status_normalized_case(self):
        record = ResearchOutcome(**_base_payload(status=" accepted "))
        self.assertEqual(record.status, "ACCEPTED")


class TestOutcomeId(unittest.TestCase):
    def test_deterministic(self):
        first = outcome_id_for(_lead_id(), "ACCEPTED", 75, "note")
        second = outcome_id_for(_lead_id(), "ACCEPTED", 75, "note")
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("ro-"))
        self.assertEqual(len(first), 19)

    def test_distinct_for_content(self):
        base = outcome_id_for(_lead_id(), "ACCEPTED", 75, "note")
        self.assertNotEqual(
            base, outcome_id_for(_lead_id(), "DUPLICATE", 75, "note"))
        self.assertNotEqual(
            base, outcome_id_for(_lead_id(), "ACCEPTED", 76, "note"))
        self.assertNotEqual(
            base, outcome_id_for(_lead_id(), "ACCEPTED", 75, "other"))
        self.assertNotEqual(
            base, outcome_id_for(_lead_id("indeed"), "ACCEPTED", 75, "note"))

    def test_note_normalization_in_id(self):
        first = outcome_id_for(_lead_id(), "ACCEPTED", 1, "  a  \r\n b ")
        second = outcome_id_for(_lead_id(), "ACCEPTED", 1, "a\nb")
        self.assertEqual(first, second)

    def test_timestamp_not_in_id(self):
        # idempotency relies on content only; timestamp is metadata
        self.assertEqual(
            outcome_id_for(_lead_id(), "ACCEPTED", 1, "n", "MANUAL"),
            outcome_id_for(_lead_id(), "ACCEPTED", 1, "n", "MANUAL"))


class TestOutcomeStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = OutcomeStore(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _append(self, **over):
        payload = dict(
            lead_id=_lead_id(),
            cve_id=CVE,
            program="dell",
            status="ACCEPTED",
            timestamp="2026-09-11T12:00:00+00:00",
            researcher_note="",
            time_spent_minutes=0,
            source="MANUAL",
        )
        payload.update(over)
        return self.store.append(**payload)

    def test_append_and_get(self):
        record, created = self._append(time_spent_minutes=75)
        self.assertTrue(created)
        loaded = self.store.get(record.outcome_id)
        self.assertEqual(loaded.time_spent_minutes, 75)

    def test_idempotent_duplicate_submission(self):
        first, created_first = self._append(time_spent_minutes=30)
        second, created_second = self._append(time_spent_minutes=30)
        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(first.outcome_id, second.outcome_id)
        lines = [l for l in self.store.path.read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)

    def test_append_only_never_overwrites(self):
        first, _ = self._append(time_spent_minutes=10)
        second, _ = self._append(time_spent_minutes=20)
        third, _ = self._append(status="DUPLICATE", time_spent_minutes=20)
        lines = [l for l in self.store.path.read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 3)
        ids = {json.loads(l)["outcome_id"] for l in lines}
        self.assertEqual(ids, {first.outcome_id, second.outcome_id,
                               third.outcome_id})

    def test_fail_closed_on_bad_status(self):
        with self.assertRaises(OutcomeValidationError):
            self._append(status="NOPE")
        self.assertFalse(self.store.path.exists())

    def test_malformed_line_skipped(self):
        self._append(time_spent_minutes=5)
        with open(self.store.path, "a", encoding="utf-8") as handle:
            handle.write("{not json}\n")
        data = self.store.list()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["malformed"], 1)
        self.assertTrue(data["research_only"])

    def test_unknown_get(self):
        with self.assertRaises(OutcomeNotFound):
            self.store.get("ro-ffffffffffffffff")
        with self.assertRaises(OutcomeValidationError):
            self.store.get("not-an-id")

    def test_list_filters(self):
        self._append(time_spent_minutes=1)
        self._append(status="DUPLICATE", time_spent_minutes=2,
                     researcher_note="dup")
        self._append(status="WASTED_TIME", lead_id=_lead_id("indeed"),
                     cve_id=CVE, program="indeed", time_spent_minutes=3)
        self.assertEqual(self.store.list()["total"], 3)
        self.assertEqual(
            self.store.list(status="DUPLICATE")["total"], 1)
        self.assertEqual(
            self.store.list(lead_id=_lead_id())["total"], 2)
        self.assertEqual(
            self.store.list(program="indeed")["total"], 1)
        self.assertEqual(self.store.list(cve=CVE)["total"], 3)

    def test_list_limit_offset_and_order(self):
        self._append(time_spent_minutes=1,
                     timestamp="2026-09-11T01:00:00+00:00")
        self._append(status="DUPLICATE", time_spent_minutes=2,
                     timestamp="2026-09-11T02:00:00+00:00",
                     researcher_note="newer")
        items = self.store.list(limit=1)["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["timestamp"], "2026-09-11T02:00:00+00:00")
        page = self.store.list(limit=10, offset=1)["items"]
        self.assertEqual(len(page), 1)
        self.assertEqual(
            page[0]["timestamp"], "2026-09-11T01:00:00+00:00")
        self.assertEqual(self.store.list(limit=10000)["limit"], 100)

    def test_repeated_reads_deterministic(self):
        self._append(time_spent_minutes=1)
        self._append(status="DUPLICATE", researcher_note="x")
        self.assertEqual(self.store.list(), self.store.list())

    def test_no_writes_on_reads(self):
        before = self.root.exists()
        self.store.list()
        try:
            self.store.get("ro-ffffffffffffffff")
        except OutcomeNotFound:
            pass
        self.assertEqual(self.root.exists(), before)


class TestBackendProjection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patcher = mock.patch(
            "backend.research_outcomes.OUTCOMES_DIR", self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def test_record_resolves_lead_attribution(self):
        from backend import research_outcomes
        result = research_outcomes.record_outcome(
            lead_id=_lead_id(), status="ACCEPTED",
            time_spent_minutes=75, note="Validated and submitted",
            timestamp="2026-09-11T12:00:00+00:00")
        self.assertTrue(result["created"])
        outcome = result["outcome"]
        self.assertEqual(outcome["cve_id"], CVE)
        self.assertEqual(outcome["program"], "dell")
        self.assertEqual(outcome["lead_id"], _lead_id())
        self.assertEqual(outcome["time_spent_minutes"], 75)
        self.assertEqual(outcome["rule_version"], "r25-1")
        self.assertNotIn("production_finding", outcome)

    def test_record_unknown_lead_rejected(self):
        from backend import research_outcomes
        with self.assertRaises(OutcomeValidationError):
            research_outcomes.record_outcome(
                lead_id="rl-ffffffffffffffff", status="ACCEPTED")

    def test_record_invalid_status_rejected(self):
        from backend import research_outcomes
        with self.assertRaises(OutcomeValidationError):
            research_outcomes.record_outcome(
                lead_id=_lead_id(), status="NOPE")

    def test_record_negative_time_rejected(self):
        from backend import research_outcomes
        with self.assertRaises(OutcomeValidationError):
            research_outcomes.record_outcome(
                lead_id=_lead_id(), status="ACCEPTED", time_spent_minutes=-5)

    def test_summary_counts_time_and_confidence(self):
        from backend import research_outcomes as ro
        ro.record_outcome(_lead_id(), "ACCEPTED", 60, "a",
                          timestamp="2026-09-11T01:00:00+00:00")
        ro.record_outcome(_lead_id(), "DUPLICATE", 30, "b",
                          timestamp="2026-09-11T02:00:00+00:00")
        ro.record_outcome(_lead_id(), "WASTED_TIME", 15, "c",
                          timestamp="2026-09-11T03:00:00+00:00")
        summary = ro.summarize_lead_outcomes(_lead_id())
        self.assertEqual(summary["attempts"], 3)
        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(summary["duplicate"], 1)
        self.assertEqual(summary["wasted_time"], 1)
        self.assertEqual(summary["total_time_spent_minutes"], 105)
        self.assertEqual(summary["average_time_spent_minutes"], 35)
        self.assertEqual(summary["terminal_attempts"], 3)
        self.assertEqual(summary["outcome_confidence"], "MEDIUM")
        self.assertEqual(summary["latest_outcome"]["status"], "WASTED_TIME")
        self.assertTrue(summary["research_only"])

    def test_summary_zero_for_fresh_store(self):
        from backend import research_outcomes as ro
        for program in ("dell", "indeed"):
            summary = ro.summarize_lead_outcomes(_lead_id(program))
            self.assertEqual(summary["attempts"], 0)
            self.assertEqual(summary["accepted"], 0)
            self.assertEqual(summary["total_time_spent_minutes"], 0)
            self.assertEqual(summary["outcome_confidence"], "NONE")
            self.assertIsNone(summary["latest_outcome"])

    def test_summary_in_progress_excluded_from_average(self):
        from backend import research_outcomes as ro
        ro.record_outcome(_lead_id(), "ACCEPTED", 40, "",
                          timestamp="2026-09-11T01:00:00+00:00")
        ro.record_outcome(_lead_id(), "IN_PROGRESS", 500, "",
                          timestamp="2026-09-11T02:00:00+00:00")
        summary = ro.summarize_lead_outcomes(_lead_id())
        self.assertEqual(summary["attempts"], 2)
        self.assertEqual(summary["terminal_attempts"], 1)
        self.assertEqual(summary["in_progress"], 1)
        self.assertEqual(summary["total_time_spent_minutes"], 540)
        self.assertEqual(summary["average_time_spent_minutes"], 40)

    def test_lead_performance_feedback_readiness(self):
        from backend import research_outcomes as ro
        # distinct content (note differs) so each is a distinct outcome;
        # identical content is idempotent by design
        ro.record_outcome(_lead_id(), "ACCEPTED", 60, "attempt one",
                          timestamp="2026-09-11T01:00:00+00:00")
        ro.record_outcome(_lead_id(), "ACCEPTED", 60, "attempt two",
                          timestamp="2026-09-11T01:01:00+00:00")
        ro.record_outcome(_lead_id(), "DUPLICATE", 30, "dup",
                          timestamp="2026-09-11T01:02:00+00:00")
        ro.record_outcome(_lead_id(), "WASTED_TIME", 15, "wasted",
                          timestamp="2026-09-11T01:03:00+00:00")
        perf = ro.lead_performance(_lead_id())
        self.assertEqual(perf["terminal_attempts"], 4)
        self.assertEqual(perf["acceptance_rate"], 0.5)
        self.assertEqual(perf["duplicate_rate"], 0.25)
        self.assertEqual(perf["wasted_rate"], 0.25)
        self.assertEqual(perf["data_quality"], "MEDIUM")
        self.assertTrue(perf["research_only"])
        self.assertEqual(perf["rule_version"], "r25-1")

    def test_global_summary(self):
        from backend import research_outcomes as ro
        ro.record_outcome(_lead_id(), "ACCEPTED", 10, "",
                          timestamp="2026-09-11T01:00:00+00:00")
        ro.record_outcome(_lead_id("indeed"), "DUPLICATE", 20, "",
                          timestamp="2026-09-11T02:00:00+00:00")
        s = ro.summarize_economic_outcomes()
        self.assertEqual(s["total_outcomes"], 2)
        self.assertEqual(s["accepted"], 1)
        self.assertEqual(s["duplicate"], 1)
        self.assertEqual(s["total_time_spent_minutes"], 30)
        self.assertEqual(s["leads_with_outcomes"], 2)
        self.assertEqual(len(s["leads"]), 2)
        self.assertTrue(s["research_only"])

    def test_idempotent_duplicate(self):
        from backend import research_outcomes as ro
        first = ro.record_outcome(_lead_id(), "ACCEPTED", 10, "note",
                                  timestamp="2026-09-11T01:00:00+00:00")
        second = ro.record_outcome(_lead_id(), "ACCEPTED", 10, "note",
                                   timestamp="2026-09-11T09:00:00+00:00")
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["outcome"]["outcome_id"],
                         second["outcome"]["outcome_id"])
        self.assertEqual(first["outcome"]["timestamp"],
                         second["outcome"]["timestamp"])

    def test_list_filter_invalid_status(self):
        from backend import research_outcomes as ro
        with self.assertRaises(ValueError):
            ro.list_outcomes(status="BOGUS")

    def test_no_payout_fields_anywhere(self):
        from backend import research_outcomes as ro
        result = ro.record_outcome(_lead_id(), "ACCEPTED", 5, "n",
                                   timestamp="2026-09-11T01:00:00+00:00")
        blob = json.dumps(result).lower()
        for token in ("payout", "bounty", "reward", "amount", "usd"):
            self.assertNotIn(token, blob)


class TestOutcomeApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patcher = mock.patch(
            "backend.research_outcomes.OUTCOMES_DIR", self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def _post(self, path, body):
        params = {"api_key": API_KEY} if API_KEY else {}
        return self.client.post(path, json=body, params=params)

    def test_auth_required(self):
        for method, path in (
            ("get", "/api/research/economics/outcomes"),
            ("get", "/api/research/economics/outcomes/ro-ffffffffffffffff"),
            ("post", "/api/research/economics/outcomes"),
        ):
            with self.subTest(path=path):
                r = getattr(self.client, method)(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)

    def test_create_list_detail(self):
        r = self._post("/api/research/economics/outcomes", {
            "lead_id": _lead_id(), "status": "ACCEPTED",
            "time_spent_minutes": 75, "researcher_note": "Validated",
        })
        self.assertEqual(r.status_code, 201)
        body = r.json()
        self.assertTrue(body["created"])
        outcome = body["outcome"]
        self.assertEqual(outcome["cve_id"], CVE)
        self.assertEqual(outcome["program"], "dell")
        self.assertEqual(outcome["rule_version"], "r25-1")

        listing = self._get("/api/research/economics/outcomes")
        self.assertEqual(listing.status_code, 200)
        data = listing.json()
        self.assertEqual(data["total"], 1)
        self.assertTrue(data["research_only"])
        self.assertEqual(data["rule_version"], "r25-1")

        detail = self._get(
            f"/api/research/economics/outcomes/{outcome['outcome_id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["outcome_id"], outcome["outcome_id"])

    def test_post_idempotent(self):
        body = {"lead_id": _lead_id(), "status": "ACCEPTED",
                "time_spent_minutes": 10, "researcher_note": "same"}
        first = self._post("/api/research/economics/outcomes", body).json()
        second = self._post("/api/research/economics/outcomes", body).json()
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["outcome"]["outcome_id"],
                         second["outcome"]["outcome_id"])
        self.assertEqual(
            self._get("/api/research/economics/outcomes").json()["total"], 1)

    def test_post_validation(self):
        bad_status = self._post("/api/research/economics/outcomes", {
            "lead_id": _lead_id(), "status": "NOPE"})
        self.assertEqual(bad_status.status_code, 400)
        unknown_lead = self._post("/api/research/economics/outcomes", {
            "lead_id": "rl-ffffffffffffffff", "status": "ACCEPTED"})
        self.assertEqual(unknown_lead.status_code, 400)
        negative = self._post("/api/research/economics/outcomes", {
            "lead_id": _lead_id(), "status": "ACCEPTED",
            "time_spent_minutes": -1})
        self.assertEqual(negative.status_code, 400)
        malformed = self._post("/api/research/economics/outcomes", {
            "lead_id": "not-a-lead", "status": "ACCEPTED"})
        self.assertEqual(malformed.status_code, 400)

    def test_post_rejects_payout_fields(self):
        r = self._post("/api/research/economics/outcomes", {
            "lead_id": _lead_id(), "status": "ACCEPTED",
            "payout_amount": 500})
        self.assertEqual(r.status_code, 422)
        r = self._post("/api/research/economics/outcomes", {
            "lead_id": _lead_id(), "status": "ACCEPTED",
            "verified": True})
        self.assertEqual(r.status_code, 422)

    def test_filters(self):
        self._post("/api/research/economics/outcomes", {
            "lead_id": _lead_id(), "status": "ACCEPTED"})
        self._post("/api/research/economics/outcomes", {
            "lead_id": _lead_id("indeed"), "status": "DUPLICATE"})
        self.assertEqual(
            self._get("/api/research/economics/outcomes",
                      lead_id=_lead_id()).json()["total"], 1)
        self.assertEqual(
            self._get("/api/research/economics/outcomes",
                      program="indeed").json()["total"], 1)
        self.assertEqual(
            self._get("/api/research/economics/outcomes",
                      status="DUPLICATE").json()["total"], 1)
        self.assertEqual(
            self._get("/api/research/economics/outcomes",
                      status="WASTED_TIME").json()["total"], 0)
        invalid = self._get("/api/research/economics/outcomes",
                            status="BOGUS")
        self.assertEqual(invalid.status_code, 400)

    def test_detail_404(self):
        r = self._get(
            "/api/research/economics/outcomes/ro-ffffffffffffffff")
        self.assertEqual(r.status_code, 404)
        # malformed id follows the existing 400 convention for bad input
        r = self._get("/api/research/economics/outcomes/not-an-id")
        self.assertEqual(r.status_code, 400)

    def test_outcomes_route_precedes_lead_detail(self):
        # "outcomes" must not be captured by /economics/{lead_id}
        r = self._get("/api/research/economics/outcomes")
        self.assertEqual(r.status_code, 200)
        self.assertIn("items", r.json())

    def test_no_money_score_change_via_api(self):
        from backend import research_economics
        before = research_economics.build_economics()
        self._post("/api/research/economics/outcomes", {
            "lead_id": _lead_id(), "status": "ACCEPTED",
            "time_spent_minutes": 5})
        after = research_economics.build_economics()
        self.assertEqual(before, after)
        self.assertEqual([e["money_score"] for e in after], [53, 53])


class TestOutcomeCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patcher = mock.patch(
            "backend.research_outcomes.OUTCOMES_DIR", self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def _run(self, argv):
        from ai.research_cli import main
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_add_json_and_idempotent(self):
        code, out, _ = self._run([
            "economics", "outcome", "add",
            "--lead-id", _lead_id(), "--status", "ACCEPTED",
            "--time-minutes", "75", "--note", "Validated and submitted",
            "--json"])
        self.assertEqual(code, 0)
        body = json.loads(out)
        self.assertTrue(body["created"])
        self.assertEqual(body["outcome"]["cve_id"], CVE)
        code2, out2, _ = self._run([
            "economics", "outcome", "add",
            "--lead-id", _lead_id(), "--status", "ACCEPTED",
            "--time-minutes", "75", "--note", "Validated and submitted",
            "--json"])
        self.assertEqual(code2, 0)
        self.assertFalse(json.loads(out2)["created"])

    def test_add_human_output(self):
        code, out, _ = self._run([
            "economics", "outcome", "add",
            "--lead-id", _lead_id(), "--status", "WASTED_TIME",
            "--time-minutes", "20"])
        self.assertEqual(code, 0)
        self.assertIn("Outcome recorded", out)
        self.assertIn("WASTED_TIME", out)

    def test_list_and_show_and_summary(self):
        self._run(["economics", "outcome", "add",
                   "--lead-id", _lead_id(), "--status", "ACCEPTED",
                   "--time-minutes", "30", "--json"])
        code, out, _ = self._run(["economics", "outcome", "list", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["total"], 1)
        outcome_id = data["items"][0]["outcome_id"]
        code, out, _ = self._run([
            "economics", "outcome", "show",
            "--outcome-id", outcome_id, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["outcome_id"], outcome_id)
        code, out, _ = self._run([
            "economics", "outcome", "summary",
            "--lead-id", _lead_id(), "--json"])
        self.assertEqual(code, 0)
        summary = json.loads(out)
        self.assertEqual(summary["attempts"], 1)
        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(summary["total_time_spent_minutes"], 30)

    def test_cli_empty(self):
        code, out, _ = self._run(["economics", "outcome", "list"])
        self.assertEqual(code, 0)
        self.assertIn("none recorded", out)

    def test_unknown_lead_and_outcome(self):
        code, _, err = self._run([
            "economics", "outcome", "add",
            "--lead-id", "rl-ffffffffffffffff", "--status", "ACCEPTED"])
        self.assertEqual(code, 1)
        self.assertIn("unknown lead_id", err)
        code, _, err = self._run([
            "economics", "outcome", "show",
            "--outcome-id", "ro-ffffffffffffffff"])
        self.assertEqual(code, 1)

    def test_cli_rejects_payout_flag(self):
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stderr(io.StringIO()):
                self._run([
                    "economics", "outcome", "add",
                    "--lead-id", _lead_id(), "--status", "ACCEPTED",
                    "--payout", "500"])
        self.assertEqual(ctx.exception.code, 2)

    def test_money_queue_still_works(self):
        code, out, _ = self._run(["economics", "--limit", "5"])
        self.assertEqual(code, 0)
        self.assertIn("MONEY QUEUE", out)
        self.assertIn("53  P3_MEDIUM", out)


class TestOutcomeUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patcher = mock.patch(
            "backend.research_outcomes.OUTCOMES_DIR", self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_lead_detail_renders_outcome_section_and_form(self):
        r = self._get(f"/ui/research/leads/{_lead_id()}")
        self.assertEqual(r.status_code, 200)
        for text in ("Research outcomes", "Attempts", "Accepted",
                     "Duplicate", "Rejected", "Wasted time", "Total time",
                     "Record outcome", "Add outcome"):
            self.assertIn(text, r.text)
        self.assertIn('name="status"', r.text)
        self.assertIn('name="time_minutes"', r.text)
        self.assertIn('name="note"', r.text)
        for token in ("payout", "bounty", "reward", "amount"):
            self.assertNotIn(token, r.text.lower())

    def test_lead_detail_zero_outcomes(self):
        r = self._get(f"/ui/research/leads/{_lead_id()}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("NONE", r.text)  # data quality when no outcomes

    def test_form_post_records_outcome(self):
        r = self.client.post(
            f"/ui/research/leads/{_lead_id()}/outcome",
            data={"status": "ACCEPTED", "time_minutes": "75",
                  "note": "Validated"},
            params={"api_key": API_KEY} if API_KEY else {},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertIn("outcome_saved=1", r.headers["location"])
        saved = self._get(f"/ui/research/leads/{_lead_id()}",
                          outcome_saved="1")
        self.assertIn("Outcome recorded", saved.text)
        self.assertIn("75 min", saved.text)
        # money score untouched by outcome capture
        api = self._get("/api/research/economics").json()
        self.assertEqual([e["money_score"] for e in api["items"]], [53, 53])

    def test_form_invalid_status_rejected(self):
        r = self.client.post(
            f"/ui/research/leads/{_lead_id()}/outcome",
            data={"status": "BOGUS", "time_minutes": "5", "note": ""},
            params={"api_key": API_KEY} if API_KEY else {},
        )
        self.assertEqual(r.status_code, 400)


class TestSafety(unittest.TestCase):
    def test_no_execution_tokens(self):
        # Scan executable tokens, not prose ("no subprocess" appears in the
        # module safety docstrings by design).
        for rel in ("ai/schemas/research_outcome.py",
                    "ai/knowledge/research_outcomes.py",
                    "backend/research_outcomes.py"):
            source = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            for token in ("import subprocess", "subprocess.",
                          "import socket", "socket.",
                          "import requests", "requests.",
                          "import httpx", "httpx.",
                          "import openai", "import anthropic",
                          "from ai.llm", "nuclei.", "Popen(",
                          "selenium", "playwright", "os.system("):
                self.assertNotIn(token, source,
                                 f"{token} found in {rel}")

    def test_money_score_formula_constants_unchanged(self):
        from ai.knowledge import economics as econ
        self.assertEqual(econ.MONEY_W_VALUE, 0.55)
        self.assertEqual(econ.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(econ.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(econ.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(econ.RULE_VERSION, "r25-1")

    def test_router_has_no_execution_paths(self):
        import inspect
        from backend.routers import research as router_mod
        source = inspect.getsource(router_mod.api_research_outcome_create)
        for token in ("subprocess", "requests", "httpx", "nuclei", "Popen",
                      "assess_economic_value", "run_agent", "executor"):
            self.assertNotIn(token, source)

    def test_outcome_paths_store_no_payout_keys(self):
        fields = set(ResearchOutcome.model_fields)
        self.assertNotIn("payout_amount", fields)
        self.assertNotIn("bounty_amount", fields)
        self.assertNotIn("production_finding", fields)


if __name__ == "__main__":
    unittest.main(verbosity=2)
