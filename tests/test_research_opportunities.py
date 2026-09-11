"""tests/test_research_opportunities.py — Stage R26.1 opportunity tests.

Deterministic, offline tests for the read-only opportunity intelligence layer:
schema, deterministic ids, classification precedence, why-now mapping,
economic/time/evidence composition, ranking, backend composition, CLI, API,
UI and safety invariants (no new score, no execution, Money Score unchanged).

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no browser, no PoC execution, no 5B-5J, no findings, no alerts, no Mongo
writes. Nothing is executed by this layer.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge import opportunity as opp
from ai.schemas.research_opportunity import (
    OPPORTUNITY_CLASSES,
    OPPORTUNITY_RULE_VERSION,
    ResearchOpportunity,
    opportunity_id_for,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
DELL = "rl-af7ecfba1a86fc83"
INDEED = "rl-d1d66e2ee9d8467c"


def make_lead(**over):
    lead = {
        "lead_id": DELL,
        "cve_id": CVE,
        "program": "dell",
        "priority_score": 80,
        "priority_level": "CRITICAL_RESEARCH",
        "relevance_score": 20,
        "relevance_level": "LOW",
        "reasons": [
            {"code": "PUBLIC_POC", "text": "Public PoC available",
             "source": "exploitability"},
            {"code": "EXPLOIT_AVAILABLE", "text": "Exploit available",
             "source": "exploitability"},
            {"code": "TECHNOLOGY_OBSERVED", "text": "Affected technology",
             "source": "relevance"},
            {"code": "PRODUCT_MATCHED", "text": "Matching product",
             "source": "relevance"},
            {"code": "CRITICAL_PRIORITY", "text": "Critical priority",
             "source": "priority"},
        ],
        "blockers": [],
        "status": "RESEARCH_LEAD",
        "recommended_next_step": "START_RESEARCH",
        "rule_version": "r21-1",
    }
    lead.update(over)
    return lead


def make_economic(**over):
    economic = {
        "lead_id": DELL,
        "cve_id": CVE,
        "program": "dell",
        "money_score": 53,
        "priority": "P3_MEDIUM",
        "confidence": "HIGH",
        "effort": 47,
        "effort_estimate": "1–2 h",
        "asset_match": "TECHNOLOGY_ONLY",
        "why_valuable": ["research priority score 80",
                         "public proof-of-concept available"],
        "main_blockers": ["only generic technology match",
                          "affected plugin not observed",
                          "asset component not observed",
                          "asset version unknown"],
        "subscores": {"value": 59, "confidence": 71, "effort": 47,
                      "risk": 85},
        "rule_version": "r25-1",
        "research_only": True,
    }
    economic.update(over)
    return economic


def make_outcomes(**over):
    outcomes = {
        "lead_id": DELL,
        "terminal_attempts": 0,
        "accepted": 0,
        "duplicate": 0,
        "rejected": 0,
        "wasted_time": 0,
        "acceptance_rate": 0.0,
        "wasted_rate": 0.0,
        "outcome_status": "NONE",
    }
    outcomes.update(over)
    return outcomes


def make_sessions(**over):
    sessions = {
        "lead_id": DELL,
        "total_sessions": 0,
        "planned_sessions": 0,
        "in_progress_sessions": 0,
        "completed_sessions": 0,
        "abandoned_sessions": 0,
        "planned_time": 0,
        "actual_time": 0,
        "session_status": "NONE",
        "historical_time_status": "NONE",
        "efficiency_ratio": None,
    }
    sessions.update(over)
    return sessions


def make_evidence(**over):
    evidence = {
        "source_count": 12,
        "evidence_count": 7,
        "strongest_source_tier": "TRUSTED",
        "evidence_confidence": "HIGH",
        "latest_research_status": "RESEARCH_COMPLETED",
    }
    evidence.update(over)
    return evidence


def build(**over):
    kwargs = {
        "lead": over.pop("lead", make_lead()),
        "economic": over.pop("economic", make_economic()),
        "outcomes": over.pop("outcomes", make_outcomes()),
        "sessions": over.pop("sessions", make_sessions()),
        "evidence": over.pop("evidence", make_evidence()),
    }
    kwargs.update(over)
    return opp.build_opportunity(**kwargs)


class TestSchema(unittest.TestCase):
    def test_deterministic_id(self):
        first = opportunity_id_for(DELL)
        self.assertEqual(first, opportunity_id_for(DELL))
        self.assertTrue(first.startswith("op-"))
        self.assertNotEqual(first, opportunity_id_for(INDEED))

    def test_model_validates_projection(self):
        model = build()
        self.assertIsInstance(model, ResearchOpportunity)
        self.assertEqual(model.opportunity_id, opportunity_id_for(DELL))
        self.assertEqual(model.rule_version, OPPORTUNITY_RULE_VERSION)
        self.assertTrue(model.research_only)
        self.assertIn(model.opportunity_class, OPPORTUNITY_CLASSES)

    def test_malformed_fields_rejected(self):
        base = build().model_dump(mode="json")
        for field, value in (
            ("opportunity_id", "nope"),
            ("lead_id", "nope"),
            ("cve_id", "nope"),
            ("program", "bad program!"),
            ("opportunity_class", "NOPE"),
            ("recommended_action", "EXECUTE"),
            ("confidence", "SURE"),
            ("evidence_quality", "MAYBE"),
            ("session_status", "RUNNING"),
            ("historical_time_status", "RUNNING"),
        ):
            with self.subTest(field=field):
                payload = dict(base)
                payload[field] = value
                with self.assertRaises(ValueError):
                    ResearchOpportunity(**payload)

    def test_rule_and_research_only_forced(self):
        base = build().model_dump(mode="json")
        base["rule_version"] = "r99-9"
        self.assertEqual(ResearchOpportunity(**base).rule_version,
                         OPPORTUNITY_RULE_VERSION)
        base["research_only"] = False
        with self.assertRaises(ValueError):
            ResearchOpportunity(**base)

    def test_forbidden_fields_rejected(self):
        base = build().model_dump(mode="json")
        for field in ("payout", "bounty", "reward", "target_url", "ip",
                      "domain", "credentials", "exploit_command",
                      "execution_command", "production_finding"):
            with self.subTest(field=field):
                payload = dict(base)
                payload[field] = "x"
                with self.assertRaises(ValueError):
                    ResearchOpportunity(**payload)

    def test_no_forbidden_model_fields(self):
        fields = set(ResearchOpportunity.model_fields)
        for token in ("payout", "bounty", "reward", "target_url", "ip",
                      "domain", "credential", "command", "finding"):
            self.assertFalse([f for f in fields if token in f.lower()],
                             f"{token} in {fields}")


class TestEstimatedMinutes(unittest.TestCase):
    def test_midpoint_bands(self):
        cases = {0: 20, 25: 20, 26: 45, 45: 45, 46: 90, 65: 90, 66: 240,
                 85: 240, 86: 480, 100: 480, "bad": 0}
        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertEqual(opp.estimated_minutes_for(score), expected)


class TestClassification(unittest.TestCase):
    def test_blocked_beats_high_value(self):
        blockers = ["only generic technology match",
                    "affected plugin not observed"]
        self.assertEqual(
            opp.classify_opportunity(90, "HIGH", blockers, True), "BLOCKED")

    def test_blocked_requires_unverified_asset_combo(self):
        # a generic technology match alone is not declared blocked
        self.assertEqual(
            opp.classify_opportunity(90, "HIGH",
                                     ["only generic technology match"], True),
            "HIGH_VALUE")
        self.assertEqual(
            opp.classify_opportunity(70, "HIGH",
                                     ["affected plugin not observed"], True),
            "HIGH_VALUE")

    def test_high_value(self):
        self.assertEqual(
            opp.classify_opportunity(65, "HIGH", [], True), "HIGH_VALUE")
        self.assertEqual(
            opp.classify_opportunity(100, "HIGH", [], True), "HIGH_VALUE")

    def test_good_opportunity(self):
        self.assertEqual(
            opp.classify_opportunity(65, "MEDIUM", [], True),
            "GOOD_OPPORTUNITY")
        self.assertEqual(
            opp.classify_opportunity(45, "MEDIUM", [], True),
            "GOOD_OPPORTUNITY")

    def test_research_first(self):
        self.assertEqual(
            opp.classify_opportunity(30, "MEDIUM", [], True),
            "RESEARCH_FIRST")

    def test_low_confidence(self):
        # money >= 30 but no evidence -> not RESEARCH_FIRST -> LOW_CONFIDENCE
        self.assertEqual(
            opp.classify_opportunity(50, "LOW", [], False),
            "LOW_CONFIDENCE")

    def test_defer(self):
        self.assertEqual(
            opp.classify_opportunity(10, "MEDIUM", [], False), "DEFER")
        self.assertEqual(
            opp.classify_opportunity(0, "LOW", [], False),
            "LOW_CONFIDENCE")

    def test_class_order_covers_all(self):
        self.assertEqual(set(opp.CLASS_ORDER), set(OPPORTUNITY_CLASSES))


class TestWhyNow(unittest.TestCase):
    def test_lead_reasons_mapped(self):
        reasons = opp.build_why_now(make_lead(), make_economic(),
                                    make_outcomes(), make_sessions(),
                                    make_evidence())
        for code in ("PUBLIC_POC", "EXPLOIT_AVAILABLE", "CRITICAL_PRIORITY",
                     "TECHNOLOGY_OBSERVED", "PRODUCT_MATCHED",
                     "HIGH_CONFIDENCE", "NO_TERMINAL_OUTCOME",
                     "NO_SESSION_HISTORY"):
            self.assertIn(code, reasons)

    def test_order_is_fixed(self):
        reasons = opp.build_why_now(make_lead(), make_economic(),
                                    make_outcomes(), make_sessions(),
                                    make_evidence())
        self.assertEqual(reasons,
                         [c for c in opp.WHY_NOW_ORDER if c in reasons])

    def test_no_invented_reasons(self):
        empty_lead = make_lead(reasons=[], priority_level="LOW_RESEARCH")
        economic = make_economic(confidence="MEDIUM", effort=10,
                                 priority="P4_LOW")
        reasons = opp.build_why_now(empty_lead, economic, make_outcomes(),
                                    make_sessions(total_sessions=2), {})
        self.assertNotIn("PUBLIC_POC", reasons)
        self.assertNotIn("CRITICAL_PRIORITY", reasons)
        self.assertNotIn("HIGH_CONFIDENCE", reasons)
        self.assertIn("LOW_RESEARCH_EFFORT", reasons)
        self.assertIn("NO_TERMINAL_OUTCOME", reasons)
        self.assertNotIn("NO_SESSION_HISTORY", reasons)

    def test_outcome_reasons(self):
        outcomes = make_outcomes(terminal_attempts=4, accepted=1,
                                 duplicate=1, wasted_rate=0.5)
        reasons = opp.build_why_now(make_lead(), make_economic(), outcomes,
                                    make_sessions(total_sessions=3), {})
        self.assertIn("PREVIOUSLY_ACCEPTED", reasons)
        self.assertIn("PREVIOUSLY_DUPLICATED", reasons)
        self.assertIn("HIGH_WASTE_RATE", reasons)
        self.assertNotIn("NO_TERMINAL_OUTCOME", reasons)

    def test_active_session_reason(self):
        sessions = make_sessions(total_sessions=1, in_progress_sessions=1,
                                 session_status="ACTIVE")
        reasons = opp.build_why_now(make_lead(), make_economic(),
                                    make_outcomes(), sessions, {})
        self.assertIn("ACTIVE_SESSION", reasons)
        self.assertNotIn("NO_SESSION_HISTORY", reasons)


class TestOpportunityComposition(unittest.TestCase):
    def test_no_history_not_penalized(self):
        model = build()
        self.assertEqual(model.actual_minutes, 0)
        self.assertIsNone(model.efficiency_ratio)
        self.assertEqual(model.historical_time_status, "NONE")
        self.assertEqual(model.time_delta_minutes, 0)
        self.assertEqual(model.session_status, "NONE")
        self.assertEqual(model.outcome_status, "NONE")
        self.assertEqual(model.evidence_quality, "HIGH")
        self.assertEqual(model.research_status, "RESEARCH_COMPLETED")

    def test_history_composition(self):
        outcomes = make_outcomes(terminal_attempts=4, accepted=2,
                                 duplicate=1, rejected=1, wasted_time=0,
                                 acceptance_rate=0.5, wasted_rate=0.0,
                                 outcome_status="REJECTED")
        sessions = make_sessions(total_sessions=2, completed_sessions=1,
                                 planned_time=120, actual_time=90,
                                 session_status="COMPLETED",
                                 historical_time_status="COMPLETED",
                                 efficiency_ratio=1.3333)
        model = build(outcomes=outcomes, sessions=sessions)
        self.assertEqual(model.accepted, 2)
        self.assertEqual(model.duplicate, 1)
        self.assertEqual(model.rejected, 1)
        self.assertEqual(model.acceptance_rate, 0.5)
        self.assertEqual(model.actual_minutes, 90)
        self.assertEqual(model.time_delta_minutes, 90 - 90)
        self.assertEqual(model.efficiency_ratio, 1.3333)
        self.assertEqual(model.outcome_status, "REJECTED")

    def test_history_does_not_change_money_or_class(self):
        no_history = build()
        with_history = build(
            outcomes=make_outcomes(terminal_attempts=3, accepted=3,
                                   acceptance_rate=1.0),
            sessions=make_sessions(total_sessions=1, completed_sessions=1,
                                   planned_time=60, actual_time=30,
                                   session_status="COMPLETED",
                                   historical_time_status="COMPLETED",
                                   efficiency_ratio=2.0))
        self.assertEqual(no_history.money_score, with_history.money_score)
        self.assertEqual(no_history.opportunity_class,
                         with_history.opportunity_class)

    def test_blockers_propagated(self):
        model = build()
        self.assertIn("only generic technology match", model.blockers)
        self.assertEqual(model.opportunity_class, "BLOCKED")
        self.assertEqual(model.recommended_action, "VERIFY_ASSET_MATCH")

    def test_active_session_action(self):
        model = build(sessions=make_sessions(
            total_sessions=1, in_progress_sessions=1,
            session_status="ACTIVE", historical_time_status="IN_PROGRESS"))
        self.assertEqual(model.recommended_action, "CONTINUE_SESSION")

    def test_why_valuable_copied(self):
        model = build()
        self.assertEqual(model.why_valuable,
                         make_economic()["why_valuable"])

    def test_all_fields_present(self):
        model = build().model_dump(mode="json")
        for field in ("opportunity_id", "lead_id", "cve_id", "program",
                      "money_score", "money_priority", "confidence",
                      "confidence_score", "value_score", "effort_score",
                      "risk_score", "asset_match", "evidence_quality",
                      "research_status", "outcome_status", "session_status",
                      "estimated_minutes", "actual_minutes",
                      "acceptance_rate", "wasted_rate", "opportunity_class",
                      "recommended_action", "why_now", "why_valuable",
                      "blockers", "evidence_summary", "rule_version",
                      "research_only"):
            self.assertIn(field, model)


class TestRanking(unittest.TestCase):
    def test_class_order(self):
        # build with explicit classes by blocking or high value
        high = build(economic=make_economic(money_score=90,
                                            main_blockers=[]),
                     lead=make_lead(blockers=[]))
        blocked = build()
        ranked = opp.rank_opportunities([blocked, high])
        self.assertEqual(ranked[0].opportunity_class, "HIGH_VALUE")
        self.assertEqual(ranked[1].opportunity_class, "BLOCKED")

    def test_money_then_confidence_then_effort(self):
        same = "GOOD_OPPORTUNITY"
        first = build(economic=make_economic(money_score=70, confidence="HIGH",
                                             effort=20),
                      lead=make_lead(blockers=[]))
        second = build(economic=make_economic(money_score=60, confidence="HIGH",
                                              effort=20),
                       lead=make_lead(lead_id=INDEED, program="indeed",
                                      blockers=[]))
        third = build(economic=make_economic(money_score=70, confidence="MEDIUM",
                                             effort=20),
                      lead=make_lead(cve_id="CVE-2024-0001", blockers=[]))
        ranked = opp.rank_opportunities([third, second, first])
        self.assertEqual([m.money_score for m in ranked], [70, 70, 60])
        self.assertEqual(ranked[0].confidence, "HIGH")
        self.assertEqual(ranked[1].confidence, "MEDIUM")

    def test_cve_program_lead_tiebreaks(self):
        # build three equal-ranked items explicitly
        items = []
        for lead_id, cve, program in ((DELL, "CVE-2024-0001", "b"),
                                      (INDEED, "CVE-2024-0001", "a"),
                                      ("rl-0000000000000003", "CVE-2024-0001",
                                       "a")):
            items.append(build(
                lead=make_lead(lead_id=lead_id, cve_id=cve, program=program,
                               blockers=[]),
                economic=make_economic(money_score=50, confidence="MEDIUM")))
        ranked = opp.rank_opportunities(items)
        self.assertEqual([m.program for m in ranked], ["a", "a", "b"])
        # lead_id ascending breaks the final tie
        self.assertEqual([m.lead_id for m in ranked][:2],
                         ["rl-0000000000000003", INDEED])

    def test_summary(self):
        summary = opp.build_opportunity_summary([build(), build()])
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_class"]["BLOCKED"], 2)
        self.assertEqual(len(summary["top"]), 2)
        self.assertTrue(summary["research_only"])


class TestBackendComposition(unittest.TestCase):
    def test_real_corpus(self):
        from backend import research_opportunities
        items = research_opportunities.build_opportunities()
        self.assertEqual(len(items), 2)
        for item in items:
            self.assertEqual(item["cve_id"], CVE)
            self.assertEqual(item["money_score"], 53)
            self.assertEqual(item["money_priority"], "P3_MEDIUM")
            self.assertEqual(item["confidence"], "HIGH")
            self.assertEqual(item["evidence_quality"], "HIGH")
            self.assertEqual(item["opportunity_class"], "BLOCKED")
            self.assertEqual(item["recommended_action"],
                             "VERIFY_ASSET_MATCH")
            self.assertEqual(item["outcome_status"], "NONE")
            self.assertEqual(item["session_status"], "NONE")
            self.assertEqual(item["historical_time_status"], "NONE")
            self.assertIsNone(item["efficiency_ratio"])
            self.assertEqual(item["rule_version"], "r26-1")
            self.assertTrue(item["research_only"])

    def test_missing_history_is_explicit(self):
        from backend import research_opportunities
        data = research_opportunities.list_opportunities(limit=10)
        self.assertEqual(data["items"][0]["outcome_status"], "NONE")
        self.assertIn("NO_TERMINAL_OUTCOME", data["items"][0]["why_now"])
        self.assertIn("NO_SESSION_HISTORY", data["items"][0]["why_now"])
        self.assertTrue(data["research_only"])
        self.assertEqual(data["rule_version"], "r26-1")

    def test_filters_and_limit(self):
        from backend import research_opportunities
        self.assertEqual(research_opportunities.list_opportunities(
            program="dell")["total"], 1)
        self.assertEqual(research_opportunities.list_opportunities(
            cve=CVE)["total"], 2)
        self.assertEqual(research_opportunities.list_opportunities(
            cve="CVE-2024-0001")["total"], 0)
        data = research_opportunities.list_opportunities(limit=1)
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["items"]), 1)
        data = research_opportunities.list_opportunities(limit=10, offset=1)
        self.assertEqual(len(data["items"]), 1)

    def test_malformed_candidates_skipped(self):
        from backend import research_opportunities
        with mock.patch("backend.research_leads.build_leads",
                        return_value=[{"bogus": 1}, "not-a-dict",
                                      {"lead_id": DELL}]):
            items = research_opportunities.build_opportunities()
        self.assertEqual(items, [])

    def test_missing_economic_projection_skipped(self):
        from backend import research_opportunities
        with mock.patch("backend.research_opportunities._economics_by_lead",
                        return_value={}):
            self.assertEqual(
                research_opportunities.build_opportunities(), [])

    def test_missing_evidence_sessions_outcomes(self):
        from backend import research_opportunities
        with mock.patch(
            "backend.research_opportunities._evidence_for",
            return_value={"source_count": 0, "evidence_count": 0,
                          "strongest_source_tier": "NONE",
                          "evidence_confidence": "NONE",
                          "latest_research_status": "NONE"}), \
             mock.patch("backend.research_opportunities._outcomes_for",
                        return_value={"accepted": 0, "duplicate": 0,
                                      "rejected": 0, "wasted_time": 0,
                                      "terminal_attempts": 0,
                                      "acceptance_rate": 0.0,
                                      "wasted_rate": 0.0,
                                      "outcome_status": "NONE"}), \
             mock.patch("backend.research_opportunities._sessions_for",
                        return_value={"total_sessions": 0, "actual_time": 0,
                                      "planned_time": 0,
                                      "session_status": "NONE",
                                      "historical_time_status": "NONE",
                                      "efficiency_ratio": None}):
            items = research_opportunities.build_opportunities()
        self.assertEqual(len(items), 2)
        for item in items:
            self.assertEqual(item["evidence_quality"], "NONE")
            self.assertEqual(item["session_status"], "NONE")
            self.assertEqual(item["outcome_status"], "NONE")

    def test_detail_and_summary(self):
        from backend import research_opportunities
        item = research_opportunities.get_opportunity(DELL)
        self.assertEqual(item["lead_id"], DELL)
        summary = research_opportunities.opportunity_summary()
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_class"]["BLOCKED"], 2)

    def test_detail_errors(self):
        from backend import research_opportunities
        with self.assertRaises(ValueError):
            research_opportunities.get_opportunity("not-a-lead")
        with self.assertRaises(ValueError):
            research_opportunities.get_opportunity("rl-ffffffffffffffff")

    def test_deterministic_output(self):
        from backend import research_opportunities
        self.assertEqual(research_opportunities.build_opportunities(),
                         research_opportunities.build_opportunities())
        self.assertEqual(research_opportunities.list_opportunities(),
                         research_opportunities.list_opportunities())

    def test_money_score_unchanged(self):
        from backend import research_economics
        from backend import research_opportunities
        before = research_economics.build_economics()
        research_opportunities.build_opportunities()
        research_opportunities.opportunity_summary()
        after = research_economics.build_economics()
        self.assertEqual(before, after)
        self.assertEqual([e["money_score"] for e in after], [53, 53])

    def test_no_duplicate_score_fields(self):
        from backend import research_opportunities
        item = research_opportunities.build_opportunities()[0]
        for key in item:
            if "score" in key.lower():
                self.assertIn(key, {"money_score", "confidence_score",
                                    "value_score", "effort_score",
                                    "risk_score"})
        self.assertNotIn("opportunity_score", item)
        self.assertNotIn("priority_score", item)


class TestOpportunityApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_auth_required(self):
        for path in ("/api/research/opportunities",
                     "/api/research/opportunities/summary",
                     f"/api/research/opportunities/{DELL}"):
            with self.subTest(path=path):
                r = self.client.get(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)

    def test_list_shape(self):
        r = self._get("/api/research/opportunities")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["rule_version"], "r26-1")
        self.assertTrue(body["research_only"])
        item = body["items"][0]
        self.assertEqual(item["opportunity_class"], "BLOCKED")
        self.assertEqual(item["money_score"], 53)
        self.assertIn("why_now", item)
        self.assertIn("evidence_summary", item)

    def test_detail_and_summary(self):
        item = self._get(f"/api/research/opportunities/{DELL}").json()
        self.assertEqual(item["lead_id"], DELL)
        summary = self._get("/api/research/opportunities/summary").json()
        self.assertEqual(summary["by_class"]["BLOCKED"], 2)
        self.assertTrue(summary["research_only"])

    def test_filters(self):
        body = self._get("/api/research/opportunities", program="dell").json()
        self.assertEqual(body["total"], 1)
        body = self._get("/api/research/opportunities", cve=CVE).json()
        self.assertEqual(body["total"], 2)
        body = self._get("/api/research/opportunities", limit=1).json()
        self.assertEqual(len(body["items"]), 1)

    def test_errors_and_no_write(self):
        r = self._get("/api/research/opportunities/rl-ffffffffffffffff")
        self.assertEqual(r.status_code, 404)
        r = self._get("/api/research/opportunities/not-a-lead")
        self.assertEqual(r.status_code, 404)
        params = {"api_key": API_KEY} if API_KEY else {}
        r = self.client.post("/api/research/opportunities", params=params)
        self.assertIn(r.status_code, (405, 401))

    def test_no_payout_vocabulary(self):
        blob = json.dumps(
            self._get("/api/research/opportunities").json()).lower()
        for token in ("payout", "bounty", "reward", "amount", "usd"):
            self.assertNotIn(token, blob)


class TestOpportunityCli(unittest.TestCase):
    def _run(self, argv):
        from ai.research_cli import main
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_list_human(self):
        code, out, _ = self._run(["opportunity", "list"])
        self.assertEqual(code, 0)
        self.assertIn("OPPORTUNITY QUEUE", out)
        self.assertIn("#1 BLOCKED", out)
        self.assertIn("CVE-2026-1557 → dell", out)
        self.assertIn("Money: 53 / P3_MEDIUM", out)
        self.assertIn("Action: VERIFY_ASSET_MATCH", out)
        self.assertIn("Why now:", out)
        self.assertIn("NO_SESSION_HISTORY", out)
        self.assertIn("OPPORTUNITIES: 2", out)

    def test_list_json_and_filters(self):
        code, out, _ = self._run(["opportunity", "list", "--json"])
        self.assertEqual(code, 0)
        items = json.loads(out)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["rule_version"], "r26-1")
        code, out, _ = self._run([
            "opportunity", "list", "--program", "dell", "--json"])
        self.assertEqual(len(json.loads(out)), 1)
        code, out, _ = self._run([
            "opportunity", "list", "--cve", "CVE-2024-0001"])
        self.assertEqual(code, 0)
        self.assertIn("none", out)

    def test_show(self):
        code, out, _ = self._run([
            "opportunity", "show", "--lead-id", DELL, "--json"])
        self.assertEqual(code, 0)
        item = json.loads(out)
        self.assertEqual(item["lead_id"], DELL)
        self.assertEqual(item["opportunity_class"], "BLOCKED")
        code, out, _ = self._run([
            "opportunity", "show", "--lead-id", DELL])
        self.assertIn("Opportunity Intelligence", out)

    def test_show_errors(self):
        code, _, err = self._run([
            "opportunity", "show", "--lead-id", "rl-ffffffffffffffff"])
        self.assertEqual(code, 1)
        code, _, err = self._run([
            "opportunity", "show", "--lead-id", "not-a-lead"])
        self.assertEqual(code, 1)

    def test_summary(self):
        code, out, _ = self._run(["opportunity", "summary", "--json"])
        self.assertEqual(code, 0)
        summary = json.loads(out)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_class"]["BLOCKED"], 2)
        code, out, _ = self._run(["opportunity", "summary"])
        self.assertIn("Opportunity Summary", out)


class TestOpportunityUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_leads_list_column(self):
        r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertIn(">Opportunity<", r.text)
        self.assertEqual(r.text.count("opp-blocked"), 2)

    def test_lead_detail_panel(self):
        r = self._get(f"/ui/research/leads/{DELL}")
        self.assertEqual(r.status_code, 200)
        for text in ("Opportunity intelligence", "BLOCKED",
                     "VERIFY_ASSET_MATCH", "Why now",
                     "NO_SESSION_HISTORY", "missing historical data"):
            self.assertIn(text, r.text)

    def test_panel_is_research_only(self):
        r = self._get(f"/ui/research/leads/{DELL}")
        panel = r.text.split("Opportunity intelligence", 1)[1].split(
            "Why investigate", 1)[0]
        for token in ("payout", "bounty", "target url", "run nuclei"):
            self.assertNotIn(token, panel.lower())
        self.assertIn("not a vulnerability confirmation", panel.lower())


class TestSafety(unittest.TestCase):
    def test_no_execution_tokens(self):
        for rel in ("ai/schemas/research_opportunity.py",
                    "ai/knowledge/opportunity.py",
                    "backend/research_opportunities.py"):
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

    def test_engine_is_pure(self):
        first = build().model_dump(mode="json")
        second = build().model_dump(mode="json")
        self.assertEqual(first, second)

    def test_money_score_constants_unchanged(self):
        from ai.knowledge import economics
        self.assertEqual(economics.MONEY_W_VALUE, 0.55)
        self.assertEqual(economics.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(economics.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(economics.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(economics.RULE_VERSION, "r25-1")
        self.assertEqual(OPPORTUNITY_RULE_VERSION, "r26-1")

    def test_calibration_unchanged(self):
        from backend import research_calibration
        report = research_calibration.build_report()
        self.assertEqual(report["recommendation"], "INSUFFICIENT_DATA")
        self.assertTrue(report["weights_unchanged"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
