"""tests/test_product_validation.py — Stage R27.1 product validation tests.

Deterministic, offline tests for the read-only product validation audit:
dataset joins, metric denominators, missing data, actionability,
follow-through, conversion, time efficiency, blocker resolution, hypothesis
states and thresholds, product decision, backend composition, CLI, API, UI
and safety invariants.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no browser, no PoC execution, no findings, no alerts, no Mongo writes, no
persistence. Money Score is never modified.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge import product_validation as pv

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
DELL = "rl-af7ecfba1a86fc83"
INDEED = "rl-d1d66e2ee9d8467c"


def make_row(**over):
    row = {
        "lead_id": DELL,
        "cve_id": CVE,
        "program": "dell",
        "money_score": 53,
        "opportunity_class": "BLOCKED",
        "action_status": "BLOCKED",
        "recommended_action": "VERIFY_ASSET_MATCH",
        "confidence": "HIGH",
        "evidence_quality": "HIGH",
        "estimated_minutes": 90,
        "sessions": [],
        "outcomes": [],
        "session_data": "NONE",
        "outcome_data": "NONE",
        "opportunity_data": "PRESENT",
    }
    row.update(over)
    return row


def session(status="COMPLETED", planned=60, actual=45):
    return {"session_id": "rs-1", "status": status,
            "planned_minutes": planned, "actual_minutes": actual}


def outcome(status="ACCEPTED", minutes=30):
    return {"outcome_id": "ro-1", "status": status,
            "time_spent_minutes": minutes}


class TestDataset(unittest.TestCase):
    def test_join_by_lead_id_only(self):
        opportunities = [
            {"lead_id": DELL, "cve_id": CVE, "program": "dell",
             "money_score": 53, "current_status": "BLOCKED",
             "opportunity_class": "BLOCKED"},
            {"lead_id": INDEED, "cve_id": CVE, "program": "indeed",
             "money_score": 53, "current_status": "BLOCKED",
             "opportunity_class": "BLOCKED"},
        ]
        sessions = {DELL: [session()]}
        outcomes = {INDEED: [outcome()]}
        rows = pv.build_validation_dataset(opportunities, sessions, outcomes)
        by_lead = {r["lead_id"]: r for r in rows}
        self.assertEqual(len(by_lead[DELL]["sessions"]), 1)
        self.assertEqual(len(by_lead[DELL]["outcomes"]), 0)
        self.assertEqual(len(by_lead[INDEED]["sessions"]), 0)
        self.assertEqual(len(by_lead[INDEED]["outcomes"]), 1)

    def test_malformed_items_skipped(self):
        rows = pv.build_validation_dataset(
            ["bad", {"no_lead": 1}, None, {"lead_id": DELL}])
        self.assertEqual(len(rows), 1)

    def test_missing_data_explicit(self):
        opportunities = [{"lead_id": DELL, "cve_id": CVE, "program": "dell",
                          "current_status": "BLOCKED"}]
        rows = pv.build_validation_dataset(
            opportunities, {}, {},
            {DELL: {"session_data": "UNAVAILABLE",
                    "outcome_data": "NONE"}})
        self.assertEqual(rows[0]["session_data"], "UNAVAILABLE")
        self.assertEqual(rows[0]["outcome_data"], "NONE")
        follow = pv.calculate_follow_through(rows)
        self.assertEqual(follow["session_data"]["unavailable"], 1)
        self.assertEqual(follow["outcome_data"]["none"], 1)

    def test_deterministic_order(self):
        opportunities = [{"lead_id": INDEED}, {"lead_id": DELL}]
        rows = pv.build_validation_dataset(opportunities)
        self.assertEqual([r["lead_id"] for r in rows], [DELL, INDEED])


class TestActionability(unittest.TestCase):
    def test_counts_and_denominators(self):
        rows = [make_row(action_status="READY"),
                make_row(lead_id=INDEED, action_status="IN_PROGRESS"),
                make_row(lead_id="rl-0000000000000003",
                         action_status="BLOCKED"),
                make_row(lead_id="rl-0000000000000004",
                         action_status="DEFERRED")]
        result = pv.calculate_actionability(rows)
        self.assertEqual(result["opportunities_surfaced"]["value"], 4)
        self.assertEqual(result["opportunities_surfaced"]["denominator"], 4)
        self.assertEqual(result["ready"]["value"], 1)
        self.assertEqual(result["in_progress"]["value"], 1)
        self.assertEqual(result["blocked"]["value"], 1)
        self.assertEqual(result["actionable"]["value"], 2)

    def test_empty(self):
        result = pv.calculate_actionability([])
        self.assertEqual(result["opportunities_surfaced"]["value"], 0)
        self.assertEqual(result["ready"]["value"], 0)


class TestFollowThrough(unittest.TestCase):
    def test_counts(self):
        rows = [
            make_row(sessions=[session("COMPLETED"),
                               session("ABANDONED")],
                     outcomes=[outcome(), outcome("WASTED_TIME")]),
            make_row(lead_id=INDEED, sessions=[session("IN_PROGRESS")]),
        ]
        result = pv.calculate_follow_through(rows)
        self.assertEqual(result["sessions_total"]["value"], 3)
        self.assertEqual(result["sessions_started"]["value"], 3)
        self.assertEqual(result["sessions_completed"]["value"], 1)
        self.assertEqual(result["sessions_completed"]["denominator"], 3)
        self.assertEqual(result["sessions_abandoned"]["value"], 1)
        self.assertEqual(result["sessions_in_progress"]["value"], 1)
        self.assertEqual(result["outcome_records_created"]["value"], 2)
        self.assertEqual(
            result["outcome_records_created"]["denominator"], 2)

    def test_planned_sessions_not_started(self):
        rows = [make_row(sessions=[session("PLANNED")])]
        result = pv.calculate_follow_through(rows)
        self.assertEqual(result["sessions_total"]["value"], 1)
        self.assertEqual(result["sessions_started"]["value"], 0)


class TestConversion(unittest.TestCase):
    def test_rates_with_denominators(self):
        ready = make_row(action_status="READY",
                         sessions=[session("COMPLETED")],
                         outcomes=[outcome("ACCEPTED")])
        blocked = make_row(lead_id=INDEED, action_status="BLOCKED",
                           outcomes=[outcome("WASTED_TIME")])
        result = pv.calculate_conversion([ready, blocked])
        self.assertEqual(result["ready_to_session"]["numerator"], 1)
        self.assertEqual(result["ready_to_session"]["denominator"], 1)
        self.assertEqual(result["ready_to_session"]["rate"], 1.0)
        self.assertEqual(result["session_to_completed"]["rate"], 1.0)
        self.assertEqual(
            result["completed_to_terminal_outcome"]["rate"], 1.0)
        self.assertEqual(result["terminal_to_accepted"]["numerator"], 1)
        self.assertEqual(result["terminal_to_accepted"]["denominator"], 2)
        self.assertEqual(result["terminal_to_accepted"]["rate"], 0.5)

    def test_zero_denominators_are_none(self):
        result = pv.calculate_conversion([make_row()])
        for key in ("ready_to_session", "session_to_completed",
                    "completed_to_terminal_outcome", "terminal_to_accepted"):
            self.assertIsNone(result[key]["rate"])
        self.assertEqual(result["ready_to_session"]["denominator"], 0)


class TestTimeEfficiency(unittest.TestCase):
    def test_totals_and_averages(self):
        rows = [
            make_row(sessions=[session("COMPLETED", 60, 45),
                               session("COMPLETED", 30, 30)],
                     outcomes=[outcome("ACCEPTED", 40)]),
        ]
        result = pv.calculate_time_efficiency(rows)
        self.assertEqual(result["planned_minutes"]["value"], 90)
        self.assertEqual(result["actual_minutes"]["value"], 75)
        self.assertEqual(result["variance_minutes"]["value"], -15)
        self.assertEqual(result["average_actual_minutes"]["value"], 37.5)
        self.assertEqual(result["average_actual_minutes"]["denominator"], 2)
        self.assertEqual(result["accepted_outcome_time"]["value"], 40)
        self.assertEqual(result["accepted_outcome_time"]["denominator"], 1)

    def test_no_data_is_none(self):
        result = pv.calculate_time_efficiency([make_row()])
        self.assertIsNone(result["average_actual_minutes"]["value"])
        self.assertIsNone(result["accepted_outcome_time"]["value"])


class TestBlockerResolution(unittest.TestCase):
    def test_counts(self):
        rows = [
            make_row(action_status="BLOCKED",
                     sessions=[session("COMPLETED")],
                     outcomes=[outcome("REJECTED")]),
            make_row(lead_id=INDEED, action_status="BLOCKED"),
        ]
        result = pv.calculate_blocker_resolution(rows)
        self.assertEqual(result["blocked_leads"]["value"], 2)
        self.assertEqual(result["blocked_to_session"]["numerator"], 1)
        self.assertEqual(result["blocked_to_session"]["denominator"], 2)
        self.assertEqual(result["blocked_to_outcome"]["rate"], 0.5)

    def test_blocked_to_ready_requires_previous(self):
        rows = [make_row(action_status="READY")]
        without = pv.calculate_blocker_resolution(rows)
        self.assertIsNone(without["blocked_became_ready"]["rate"])
        self.assertEqual(without["blocked_became_ready"]["denominator"], 0)
        with_previous = pv.calculate_blocker_resolution(
            rows, {DELL: "BLOCKED"})
        self.assertEqual(with_previous["blocked_became_ready"]["rate"], 1.0)
        self.assertEqual(
            with_previous["blocked_became_ready"]["denominator"], 1)


class TestHypotheses(unittest.TestCase):
    def _statuses(self, rows, **kwargs):
        return {h["hypothesis_id"]: h["status"]
                for h in pv.evaluate_hypotheses(rows, **kwargs)}

    def test_empty_is_untestable(self):
        statuses = self._statuses([])
        self.assertEqual(set(statuses.values()), {pv.UNTESTABLE})

    def test_zero_data_corpus_is_insufficient(self):
        rows = [make_row(), make_row(lead_id=INDEED, program="indeed")]
        statuses = self._statuses(rows)
        self.assertEqual(set(statuses.values()), {pv.INSUFFICIENT_DATA})

    def test_supported_fixture(self):
        high = [
            make_row(lead_id=f"rl-{i:016x}", action_status="READY",
                     opportunity_class="HIGH_VALUE", confidence="HIGH",
                     evidence_quality="HIGH", money_score=80,
                     sessions=[session("COMPLETED")],
                     outcomes=[outcome("ACCEPTED")])
            for i in range(1, 4)
        ]
        weak = [
            make_row(lead_id=f"rl-{i:016x}", action_status="BLOCKED",
                     opportunity_class="BLOCKED", confidence="LOW",
                     evidence_quality="LOW", money_score=30,
                     outcomes=[outcome("WASTED_TIME")])
            for i in range(4, 7)
        ]
        statuses = self._statuses(high + weak, min_sessions=3,
                                  min_terminal_outcomes=6, min_leads=6)
        for hypothesis_id in ("H1", "H2", "H3", "H4", "H5"):
            self.assertEqual(statuses[hypothesis_id], pv.SUPPORTED,
                             f"{hypothesis_id} status {statuses}")

    def test_directional_when_groups_small(self):
        high = [
            make_row(lead_id="rl-0000000000000001", action_status="READY",
                     opportunity_class="HIGH_VALUE", confidence="HIGH",
                     money_score=80, sessions=[session("COMPLETED")],
                     outcomes=[outcome("ACCEPTED")]),
        ]
        weak = [
            make_row(lead_id=f"rl-{i:016x}", action_status="BLOCKED",
                     confidence="LOW", evidence_quality="LOW",
                     money_score=30, outcomes=[outcome("WASTED_TIME")])
            for i in range(2, 4)
        ]
        statuses = self._statuses(high + weak, min_sessions=1,
                                  min_terminal_outcomes=1, min_leads=1)
        self.assertEqual(statuses["H1"], pv.DIRECTIONAL_SIGNAL)
        self.assertEqual(statuses["H2"], pv.DIRECTIONAL_SIGNAL)
        self.assertEqual(statuses["H3"], pv.DIRECTIONAL_SIGNAL)
        self.assertEqual(statuses["H5"], pv.DIRECTIONAL_SIGNAL)

    def test_threshold_raises_to_insufficient(self):
        high = [
            make_row(lead_id=f"rl-{i:016x}", action_status="READY",
                     opportunity_class="HIGH_VALUE", confidence="HIGH",
                     money_score=80, sessions=[session("COMPLETED")],
                     outcomes=[outcome("ACCEPTED")])
            for i in range(1, 4)
        ]
        weak = [
            make_row(lead_id=f"rl-{i:016x}", confidence="LOW",
                     money_score=30, outcomes=[outcome("WASTED_TIME")])
            for i in range(4, 7)
        ]
        statuses = self._statuses(high + weak, min_sessions=100,
                                  min_terminal_outcomes=100, min_leads=100)
        self.assertNotIn(pv.SUPPORTED, statuses.values())
        self.assertIn(pv.INSUFFICIENT_DATA, statuses.values())

    def test_result_shape(self):
        results = pv.evaluate_hypotheses([make_row()])
        self.assertEqual([h["hypothesis_id"] for h in results],
                         ["H1", "H2", "H3", "H4", "H5"])
        for result in results:
            for key in ("hypothesis_id", "status", "sample_size",
                        "required_sample", "metric", "observed_value",
                        "comparison", "reason", "limitations"):
                self.assertIn(key, result)
            self.assertIn(result["status"], pv.HYPOTHESIS_STATUSES)
            self.assertNotIn(result["status"], ("PROVEN", "CONFIRMED"))


class TestReport(unittest.TestCase):
    def test_empty_report_is_no_data(self):
        report = pv.build_product_validation_report([])
        self.assertEqual(report["product_decision"], pv.RETHINK_WORKFLOW)
        self.assertEqual(report["totals"]["leads"], 0)
        self.assertTrue(report["research_only"])

    def test_real_corpus_shape(self):
        rows = [
            make_row(),
            make_row(lead_id=INDEED, program="indeed"),
        ]
        report = pv.build_product_validation_report(
            rows, generated_at="2026-09-11T12:00:00+00:00")
        self.assertEqual(report["validation_version"], "r27-1")
        self.assertEqual(report["totals"]["leads"], 2)
        self.assertEqual(report["totals"]["sessions"], 0)
        self.assertEqual(report["totals"]["terminal_outcomes"], 0)
        self.assertEqual(report["product_decision"], pv.COLLECT_MORE_DATA)
        self.assertEqual(report["supported_hypotheses"], [])
        self.assertEqual(
            report["thresholds"],
            {"min_sessions": 20, "min_terminal_outcomes": 20,
             "min_leads": 10})
        for key in ("actionability", "follow_through", "conversion",
                    "time_efficiency", "blocker_resolution", "hypotheses",
                    "data_coverage", "limitations"):
            self.assertIn(key, report)
        self.assertTrue(report["research_only"])

    def test_decision_rules(self):
        rows = [make_row()]
        self.assertEqual(
            pv.build_product_validation_report(rows)["product_decision"],
            pv.COLLECT_MORE_DATA)
        # degenerate zero thresholds cannot bypass the hard floor
        self.assertEqual(
            pv.build_product_validation_report(
                rows, min_sessions=0, min_terminal_outcomes=0,
                min_leads=0)["product_decision"],
            pv.COLLECT_MORE_DATA)

    def test_deterministic(self):
        rows = [make_row(), make_row(lead_id=INDEED, program="indeed")]
        first = pv.build_product_validation_report(rows, generated_at="T")
        second = pv.build_product_validation_report(rows, generated_at="T")
        self.assertEqual(first, second)

    def _keys(self, value):
        keys: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                keys.append(str(key).lower())
                keys.extend(self._keys(item))
        elif isinstance(value, list):
            for item in value:
                keys.extend(self._keys(item))
        return keys

    def test_no_new_score_fields(self):
        report = pv.build_product_validation_report([make_row()])
        keys = " ".join(self._keys(report))
        for token in ("product_score", "value_score", "validation_score",
                      "confidence_score", "payout", "bounty", "reward",
                      "amount", "usd"):
            self.assertNotIn(token, keys)


class TestBackend(unittest.TestCase):
    def test_real_corpus(self):
        from backend import product_validation
        report = product_validation.build_product_validation_report()
        self.assertEqual(report["totals"]["leads"], 2)
        self.assertEqual(report["totals"]["sessions"], 0)
        self.assertEqual(report["totals"]["terminal_outcomes"], 0)
        self.assertEqual(report["actionability"]["blocked"]["value"], 2)
        self.assertEqual(report["product_decision"], pv.COLLECT_MORE_DATA)
        statuses = [h["status"] for h in report["hypotheses"]]
        self.assertEqual(set(statuses), {pv.INSUFFICIENT_DATA})
        self.assertEqual(report["supported_hypotheses"], [])
        self.assertTrue(report["research_only"])

    def test_filters(self):
        from backend import product_validation
        self.assertEqual(product_validation.build_product_validation_report(
            program="dell")["totals"]["leads"], 1)
        self.assertEqual(product_validation.build_product_validation_report(
            cve=CVE)["totals"]["leads"], 2)
        self.assertEqual(product_validation.build_product_validation_report(
            cve="CVE-2024-0001")["totals"]["leads"], 0)

    def test_summary(self):
        from backend import product_validation
        summary = product_validation.product_validation_summary()
        self.assertEqual(summary["data_status"], "INSUFFICIENT")
        self.assertEqual(summary["product_decision"], pv.COLLECT_MORE_DATA)
        self.assertEqual(summary["leads"], 2)
        self.assertTrue(summary["research_only"])

    def test_deterministic(self):
        from backend import product_validation
        first = product_validation.build_product_validation_report(
            generated_at="T")
        second = product_validation.build_product_validation_report(
            generated_at="T")
        self.assertEqual(first, second)

    def test_no_persistence(self):
        from backend import product_validation
        base = Path("/opt/watch/ai_data/research")
        before = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        product_validation.build_product_validation_report()
        product_validation.product_validation_summary()
        after = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        self.assertEqual(before, after)
        self.assertFalse((base / "snapshots").exists())

    def test_money_score_unchanged(self):
        from backend import product_validation
        from backend import research_economics
        before = research_economics.build_economics()
        product_validation.build_product_validation_report()
        after = research_economics.build_economics()
        self.assertEqual(before, after)


class TestCli(unittest.TestCase):
    def _run(self, argv):
        from ai.research_cli import main
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_human_output(self):
        code, out, _ = self._run(["product", "validation"])
        self.assertEqual(code, 0)
        self.assertIn("WATCH PRODUCT VALIDATION", out)
        self.assertIn("Leads: 2", out)
        self.assertIn("Sessions: 0", out)
        self.assertIn("Terminal outcomes: 0", out)
        self.assertIn("ACTIONABILITY", out)
        self.assertIn("Blocked: 2", out)
        self.assertIn("FOLLOW-THROUGH", out)
        self.assertIn("Sessions started: 0", out)
        self.assertIn("HYPOTHESES", out)
        for hid in ("H1", "H2", "H3", "H4", "H5"):
            self.assertIn(f"{hid}  INSUFFICIENT_DATA", out)
        self.assertIn("No product hypothesis is currently supported.", out)
        self.assertIn("PRODUCT DECISION: COLLECT_MORE_DATA", out)

    def test_json_output(self):
        code, out, _ = self._run(["product", "validation", "--json"])
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(report["validation_version"], "r27-1")
        self.assertEqual(report["product_decision"], "COLLECT_MORE_DATA")
        self.assertTrue(report["research_only"])

    def test_filters_and_thresholds(self):
        code, out, _ = self._run([
            "product", "validation", "--program", "dell", "--json"])
        self.assertEqual(json.loads(out)["totals"]["leads"], 1)
        code, out, _ = self._run([
            "product", "validation", "--min-sessions", "1",
            "--min-outcomes", "1", "--min-leads", "1", "--json"])
        report = json.loads(out)
        self.assertEqual(report["thresholds"]["min_sessions"], 1)
        self.assertEqual(report["product_decision"], "COLLECT_MORE_DATA")

    def test_no_payout_or_execution_flags(self):
        for flag in ("--payout", "--bounty", "--target", "--execute"):
            with self.subTest(flag=flag):
                with self.assertRaises(SystemExit) as ctx:
                    with redirect_stderr(io.StringIO()):
                        self._run(["product", "validation", flag, "x"])
                self.assertEqual(ctx.exception.code, 2)


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_auth_required(self):
        r = self.client.get("/api/research/product-validation")
        if API_KEY:
            self.assertEqual(r.status_code, 401)

    def test_shape(self):
        r = self._get("/api/research/product-validation")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["validation_version"], "r27-1")
        self.assertEqual(body["product_decision"], "COLLECT_MORE_DATA")
        self.assertEqual(body["totals"]["leads"], 2)
        self.assertTrue(body["research_only"])
        for key in ("actionability", "follow_through", "conversion",
                    "time_efficiency", "blocker_resolution", "hypotheses"):
            self.assertIn(key, body)

    def test_filters_and_thresholds(self):
        body = self._get("/api/research/product-validation",
                         program="dell").json()
        self.assertEqual(body["totals"]["leads"], 1)
        body = self._get("/api/research/product-validation",
                         min_sessions=1, min_outcomes=1,
                         min_leads=1).json()
        self.assertEqual(body["thresholds"]["min_sessions"], 1)
        bad = self._get("/api/research/product-validation", min_sessions=-1)
        self.assertEqual(bad.status_code, 422)

    def test_no_write_endpoint(self):
        params = {"api_key": API_KEY} if API_KEY else {}
        r = self.client.post("/api/research/product-validation",
                             params=params)
        self.assertIn(r.status_code, (405, 401))

    def test_no_payout_vocabulary(self):
        blob = json.dumps(
            self._get("/api/research/product-validation").json()).lower()
        # limitations prose may mention that payouts are not used; assert the
        # structured keys never carry payout fields
        keys = set()
        for match in __import__("re").findall(r'"([^"]+)":', blob):
            keys.add(match)
        for token in ("payout", "bounty", "reward", "amount", "usd"):
            self.assertFalse([k for k in keys if token in k],
                             f"{token} key present: {keys}")


class TestUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_compact_indicator(self):
        r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertIn("PRODUCT VALIDATION", r.text)
        self.assertIn("Data: INSUFFICIENT", r.text)
        self.assertIn("COLLECT_MORE_DATA", r.text)

    def test_indicator_is_research_only(self):
        r = self._get("/ui/research/leads")
        panel = r.text.split("PRODUCT VALIDATION", 1)[1].split(
            'action="/ui/research/leads"', 1)[0]
        for token in ("payout", "bounty", "target url", "run nuclei"):
            self.assertNotIn(token, panel.lower())


class TestSafety(unittest.TestCase):
    def test_no_execution_tokens(self):
        for rel in ("ai/knowledge/product_validation.py",
                    "backend/product_validation.py"):
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

    def test_no_persistence_tokens(self):
        source = (Path("/opt/watch") / "backend"
                  / "product_validation.py").read_text(encoding="utf-8")
        for token in ("O_APPEND", "fsync", "open(", "os.replace",
                      "insert_one", "update_one", "pymongo", "mongoengine",
                      "write_text", "snapshot"):
            self.assertNotIn(token, source)

    def test_engine_is_pure(self):
        rows = [make_row()]
        first = pv.build_product_validation_report(rows, generated_at="T")
        second = pv.build_product_validation_report(rows, generated_at="T")
        self.assertEqual(first, second)

    def test_upstream_rules_unchanged(self):
        from ai.knowledge import daily_research
        from ai.knowledge import economics
        from ai.knowledge import opportunity
        from ai.knowledge import opportunity_action
        self.assertEqual(economics.MONEY_W_VALUE, 0.55)
        self.assertEqual(economics.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(economics.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(economics.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(economics.RULE_VERSION, "r25-1")
        self.assertEqual(opportunity.OPPORTUNITY_RULE_VERSION, "r26-1")
        self.assertEqual(opportunity_action.ACTION_RULE_VERSION, "r26-2")
        self.assertEqual(daily_research.WORKFLOW_VERSION, "r26-3")

    def test_report_has_no_new_score(self):
        report = pv.build_product_validation_report([make_row()])
        self.assertNotIn("score", json.dumps(
            report["product_decision"]).lower())
        self.assertIn("product_decision", report)
        self.assertNotIn("product_value_score", report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
