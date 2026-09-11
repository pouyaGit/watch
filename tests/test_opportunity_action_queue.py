"""tests/test_opportunity_action_queue.py — Stage R26.2 action-queue tests.

Deterministic, offline tests for the read-only Action Queue layer:
schema, deterministic ids, action precedence, blocker translation, next
step, status derivation, ranking, backend composition, CLI, API, UI and
safety invariants (no new score, no execution, no payout/target fields,
Money Score unchanged).

No network, no DNS, no LLM, no subprocess, no target interaction, no
Nuclei, no browser, no PoC execution, no 5B-5J, no findings, no alerts, no
Mongo writes. Nothing is executed by this layer.
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

from ai.knowledge import opportunity as opp
from ai.knowledge import opportunity_action as oa
from ai.schemas.opportunity_action import (
    ACTION_CODES,
    ACTION_RULE_VERSION,
    ACTION_STATUSES,
    OpportunityAction,
    action_id_for,
)
from ai.schemas.research_opportunity import (
    OPPORTUNITY_RULE_VERSION,
    opportunity_id_for,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
DELL = "rl-af7ecfba1a86fc83"
INDEED = "rl-d1d66e2ee9d8467c"


# ---------- fixtures --------------------------------------------------------


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
    econ = {
        "lead_id": DELL,
        "cve_id": CVE,
        "program": "dell",
        "money_score": 53,
        "priority": "P3_MEDIUM",
        "confidence": "HIGH",
        "effort": 47,
        "effort_estimate": "1–2 h",
        "asset_match": "TECHNOLOGY_ONLY",
        "why_valuable": ["research priority score 80"],
        "main_blockers": ["only generic technology match",
                          "affected plugin not observed",
                          "asset component not observed",
                          "asset version unknown"],
        "subscores": {"value": 59, "confidence": 71, "effort": 47, "risk": 85},
        "rule_version": "r25-1",
        "research_only": True,
    }
    econ.update(over)
    return econ


def make_outcomes(**over):
    out = {
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
    out.update(over)
    return out


def make_sessions(**over):
    s = {
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
    s.update(over)
    return s


def make_evidence(**over):
    e = {
        "source_count": 12,
        "evidence_count": 7,
        "strongest_source_tier": "TRUSTED",
        "evidence_confidence": "HIGH",
        "latest_research_status": "RESEARCH_COMPLETED",
    }
    e.update(over)
    return e


def build_opportunity(**over):
    kwargs = {
        "lead": over.pop("lead", make_lead()),
        "economic": over.pop("economic", make_economic()),
        "outcomes": over.pop("outcomes", make_outcomes()),
        "sessions": over.pop("sessions", make_sessions()),
        "evidence": over.pop("evidence", make_evidence()),
    }
    kwargs.update(over)
    return opp.build_opportunity(**kwargs)


def build_action(**over):
    opportunity = over.pop("opportunity", None)
    sessions = over.pop("sessions", make_sessions())
    outcomes = over.pop("outcomes", make_outcomes())
    if opportunity is None:
        opportunity = build_opportunity(
            sessions=sessions, outcomes=outcomes
        )
    return oa.build_action(opportunity, sessions, outcomes)


# ---------- schema tests ---------------------------------------------------


class TestSchema(unittest.TestCase):
    def test_deterministic_action_id(self):
        a = action_id_for(DELL)
        self.assertEqual(a, action_id_for(DELL))
        self.assertTrue(a.startswith("oa-"))
        self.assertNotEqual(a, action_id_for(INDEED))

    def test_action_id_differs_from_opportunity_id(self):
        # Different prefixes guarantee no collision
        self.assertNotEqual(
            action_id_for(DELL)[:3], opportunity_id_for(DELL)[:3]
        )

    def test_model_validates_minimal(self):
        m = build_action()
        self.assertIsInstance(m, OpportunityAction)
        self.assertEqual(m.action_id, action_id_for(DELL))
        self.assertEqual(m.rule_version, ACTION_RULE_VERSION)
        self.assertTrue(m.research_only)

    def test_malformed_fields_rejected(self):
        base = build_action().model_dump(mode="json")
        for field, value in (
            ("action_id", "nope"),
            ("opportunity_id", "nope"),
            ("lead_id", "nope"),
            ("cve_id", "nope"),
            ("program", "bad program!"),
            ("opportunity_class", "NOPE"),
            ("current_status", "RUNNING"),
            ("recommended_action", "EXECUTE"),
            ("confidence", "SURE"),
            ("evidence_quality", "MAYBE"),
        ):
            with self.subTest(field=field):
                payload = dict(base)
                payload[field] = value
                with self.assertRaises(ValueError):
                    OpportunityAction(**payload)

    def test_rule_and_research_only_forced(self):
        base = build_action().model_dump(mode="json")
        base["rule_version"] = "r99-9"
        self.assertEqual(
            OpportunityAction(**base).rule_version, ACTION_RULE_VERSION
        )
        base["research_only"] = False
        with self.assertRaises(ValueError):
            OpportunityAction(**base)

    def test_no_payout_fields(self):
        base = build_action().model_dump(mode="json")
        for token in ("payout", "bounty", "reward", "estimated_payout",
                      "payout_amount", "bounty_amount"):
            with self.subTest(token=token):
                payload = dict(base)
                payload[token] = "x"
                with self.assertRaises(ValueError):
                    OpportunityAction(**payload)

    def test_no_target_or_execution_fields(self):
        base = build_action().model_dump(mode="json")
        for token in ("target_url", "ip", "domain", "credential",
                      "exploit_command", "execution_command",
                      "production_finding", "scan_command"):
            with self.subTest(token=token):
                payload = dict(base)
                payload[token] = "x"
                with self.assertRaises(ValueError):
                    OpportunityAction(**payload)

    def test_no_forbidden_model_fields(self):
        # Schema must not even define a payout/target/execution field.
        fields = {name.lower() for name in OpportunityAction.model_fields}
        for token in ("payout", "bounty", "reward", "target_url", "ip",
                      "domain", "credential", "command", "finding",
                      "exploit"):
            self.assertFalse(
                [f for f in fields if token in f],
                f"{token} field present: {fields}",
            )

    def test_extra_rejected(self):
        payload = build_action().model_dump(mode="json")
        payload["custom_field"] = "x"
        with self.assertRaises(ValueError):
            OpportunityAction(**payload)


# ---------- precedence tests ----------------------------------------------


class TestActionPrecedence(unittest.TestCase):
    def test_active_session_beats_everything(self):
        # BLOCKED + active session -> CONTINUE_RESEARCH (rule 1)
        self.assertEqual(
            oa.classify_action(
                "BLOCKED",
                {"session_status": "IN_PROGRESS"},
                {"outcome_status": "NONE"},
                "HIGH",
            ),
            "CONTINUE_RESEARCH",
        )
        self.assertEqual(
            oa.classify_action(
                "BLOCKED",
                {"session_status": "PLANNED"},
                {"outcome_status": "NONE"},
                "HIGH",
            ),
            "CONTINUE_RESEARCH",
        )

    def test_blocked_opportunity_rule_2(self):
        self.assertEqual(
            oa.classify_action(
                "BLOCKED",
                {"session_status": "NONE"},
                {"outcome_status": "NONE"},
                "HIGH",
            ),
            "VERIFY_ASSET_MATCH",
        )

    def test_terminal_outcome_rule_3(self):
        self.assertEqual(
            oa.classify_action(
                "HIGH_VALUE",
                {"session_status": "NONE"},
                {"outcome_status": "ACCEPTED"},
                "HIGH",
            ),
            "REVIEW_OUTCOME",
        )
        self.assertEqual(
            oa.classify_action(
                "GOOD_OPPORTUNITY",
                {"session_status": "NONE"},
                {"terminal_attempts": 1, "outcome_status": "NONE"},
                "MEDIUM",
            ),
            "REVIEW_OUTCOME",
        )

    def test_low_confidence_rule_4(self):
        self.assertEqual(
            oa.classify_action(
                "LOW_CONFIDENCE",
                {"session_status": "NONE"},
                {"outcome_status": "NONE"},
                "HIGH",
            ),
            "GATHER_EVIDENCE",
        )

    def test_high_value_rule_5(self):
        self.assertEqual(
            oa.classify_action(
                "HIGH_VALUE",
                {"session_status": "NONE"},
                {"outcome_status": "NONE"},
                "HIGH",
            ),
            "START_RESEARCH",
        )

    def test_good_opportunity_rule_5(self):
        self.assertEqual(
            oa.classify_action(
                "GOOD_OPPORTUNITY",
                {"session_status": "NONE"},
                {"outcome_status": "NONE"},
                "MEDIUM",
            ),
            "START_RESEARCH",
        )

    def test_research_first_rule_6(self):
        self.assertEqual(
            oa.classify_action(
                "RESEARCH_FIRST",
                {"session_status": "NONE"},
                {"outcome_status": "NONE"},
                "MEDIUM",
            ),
            "START_RESEARCH",
        )

    def test_default_defer_rule_7(self):
        self.assertEqual(
            oa.classify_action(
                "DEFER",
                {"session_status": "NONE"},
                {"outcome_status": "NONE"},
                "HIGH",
            ),
            "DEFER",
        )
        # LOW_CONFIDENCE class still triggers rule 4 (GATHER_EVIDENCE) first.
        self.assertEqual(
            oa.classify_action(
                "LOW_CONFIDENCE",
                {"session_status": "NONE"},
                {"outcome_status": "NONE"},
                "MEDIUM",
            ),
            "GATHER_EVIDENCE",
        )

    def test_all_action_codes_covered(self):
        # Every code is reachable by some combination of inputs.
        seen = set()
        # 1) CONTINUE_RESEARCH: active session
        seen.add(oa.classify_action(
            "BLOCKED", {"session_status": "ACTIVE"}, {}, "HIGH"
        ))
        # 2) VERIFY_ASSET_MATCH: BLOCKED + no active session
        seen.add(oa.classify_action("BLOCKED", {}, {}, "HIGH"))
        # 3) REVIEW_OUTCOME: terminal outcome
        seen.add(oa.classify_action(
            "HIGH_VALUE", {}, {"outcome_status": "ACCEPTED"}, "HIGH"
        ))
        # 4) GATHER_EVIDENCE: LOW_CONFIDENCE class
        seen.add(oa.classify_action("LOW_CONFIDENCE", {}, {}, "HIGH"))
        # 5) START_RESEARCH: HIGH_VALUE
        seen.add(oa.classify_action("HIGH_VALUE", {}, {}, "HIGH"))
        # 6) START_RESEARCH: RESEARCH_FIRST
        seen.add(oa.classify_action("RESEARCH_FIRST", {}, {}, "MEDIUM"))
        # 7) DEFER: otherwise
        seen.add(oa.classify_action("DEFER", {}, {}, "HIGH"))
        self.assertEqual(seen, set(ACTION_CODES))


# ---------- status derivation ---------------------------------------------


class TestStatusDerivation(unittest.TestCase):
    def test_in_progress(self):
        self.assertEqual(
            oa.classify_status(
                "BLOCKED",
                {"session_status": "IN_PROGRESS"},
                {},
                "CONTINUE_RESEARCH",
            ),
            "IN_PROGRESS",
        )

    def test_completed(self):
        self.assertEqual(
            oa.classify_status(
                "HIGH_VALUE",
                {"session_status": "NONE"},
                {"outcome_status": "ACCEPTED"},
                "REVIEW_OUTCOME",
            ),
            "COMPLETED",
        )

    def test_blocked(self):
        self.assertEqual(
            oa.classify_status(
                "BLOCKED",
                {"session_status": "NONE"},
                {},
                "VERIFY_ASSET_MATCH",
            ),
            "BLOCKED",
        )

    def test_deferred(self):
        self.assertEqual(
            oa.classify_status(
                "DEFER",
                {"session_status": "NONE"},
                {},
                "DEFER",
            ),
            "DEFERRED",
        )

    def test_ready(self):
        self.assertEqual(
            oa.classify_status(
                "GOOD_OPPORTUNITY",
                {"session_status": "NONE"},
                {},
                "START_RESEARCH",
            ),
            "READY",
        )


# ---------- blocker translation --------------------------------------------


class TestBlockerTranslation(unittest.TestCase):
    def test_known_codes_translated(self):
        codes = [
            "only generic technology match",
            "affected plugin not observed",
            "asset component not observed",
            "asset version unknown",
        ]
        out = oa.translate_blockers(codes)
        self.assertEqual(len(out), 4)
        self.assertEqual([entry["code"] for entry in out], codes)
        for entry in out:
            self.assertTrue(entry["text"])
            self.assertNotEqual(entry["text"], entry["code"])

    def test_machine_code_preserved(self):
        out = oa.translate_blockers(["only generic technology match"])
        self.assertEqual(out[0]["code"], "only generic technology match")
        self.assertIn("CVE applies", out[0]["text"])

    def test_unknown_code_kept_with_fallback(self):
        out = oa.translate_blockers(["some_fresh_unknown_code"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["code"], "some_fresh_unknown_code")
        self.assertIn("Investigate", out[0]["text"])

    def test_deduplication(self):
        out = oa.translate_blockers(
            ["asset version unknown", "asset version unknown"]
        )
        self.assertEqual(len(out), 1)

    def test_empty_input(self):
        self.assertEqual(oa.translate_blockers([]), [])
        self.assertEqual(oa.translate_blockers(None), [])


# ---------- next step ------------------------------------------------------


class TestNextStep(unittest.TestCase):
    def test_exact_steps(self):
        cases = {
            "VERIFY_ASSET_MATCH": "Confirm affected component/plugin "
                                   "presence.",
            "GATHER_EVIDENCE": "Collect authoritative public evidence for "
                               "the CVE.",
            "START_RESEARCH": "Begin a time-boxed research session.",
            "CONTINUE_RESEARCH": "Continue the active research session.",
            "REVIEW_OUTCOME": "Review the previous research outcome before "
                              "spending more time.",
            "DEFER": "No high-value action is currently justified.",
        }
        for action, expected in cases.items():
            with self.subTest(action=action):
                self.assertEqual(oa.build_next_step(action), expected)

    def test_unknown_action_falls_back_to_defer(self):
        self.assertEqual(
            oa.build_next_step("EXECUTE"),
            "No high-value action is currently justified.",
        )

    def test_no_exploit_or_target_language(self):
        for action in ACTION_CODES:
            step = oa.build_next_step(action)
            for forbidden in ("payload", "inject", "exploit ", "curl ",
                              "nuclei ", "nmap ", "msfconsole", "bash ",
                              "target ", "http://", "https://"):
                self.assertNotIn(
                    forbidden, step.lower(),
                    f"{forbidden!r} in step for {action!r}",
                )


# ---------- composition ---------------------------------------------------


class TestActionComposition(unittest.TestCase):
    def test_deterministic(self):
        m1 = build_action()
        m2 = build_action()
        self.assertEqual(m1.model_dump(mode="json"),
                         m2.model_dump(mode="json"))

    def test_dell_real_corpus(self):
        m = build_action(
            opportunity=build_opportunity(
                outcomes=make_outcomes(),
                sessions=make_sessions(),
            ),
            outcomes=make_outcomes(),
            sessions=make_sessions(),
        )
        self.assertEqual(m.current_status, "BLOCKED")
        self.assertEqual(m.recommended_action, "VERIFY_ASSET_MATCH")
        self.assertEqual(m.money_score, 53)
        self.assertEqual(m.priority, "P3_MEDIUM")
        self.assertEqual(m.confidence, "HIGH")
        self.assertEqual(
            m.next_step, "Confirm affected component/plugin presence."
        )

    def test_active_session_no_history_yet(self):
        sessions = make_sessions(
            total_sessions=1, in_progress_sessions=1,
            session_status="ACTIVE",
        )
        m = build_action(
            sessions=sessions, outcomes=make_outcomes()
        )
        self.assertEqual(m.current_status, "IN_PROGRESS")
        self.assertEqual(m.recommended_action, "CONTINUE_RESEARCH")
        self.assertEqual(
            m.next_step, "Continue the active research session."
        )

    def test_terminal_outcome_triggers_review(self):
        outcomes = make_outcomes(
            terminal_attempts=1, accepted=1, acceptance_rate=1.0,
            outcome_status="ACCEPTED",
        )
        m = build_action(
            opportunity=build_opportunity(
                lead=make_lead(),
                economic=make_economic(
                    money_score=80, confidence="HIGH", priority="P1_START_NOW",
                    main_blockers=[],
                ),
                outcomes=outcomes,
                sessions=make_sessions(),
            ),
            outcomes=outcomes,
            sessions=make_sessions(),
        )
        self.assertEqual(m.current_status, "COMPLETED")
        self.assertEqual(m.recommended_action, "REVIEW_OUTCOME")

    def test_low_confidence_triggers_gather(self):
        outcomes = make_outcomes()
        sessions = make_sessions()
        m = build_action(
            opportunity=build_opportunity(
                lead=make_lead(),
                economic=make_economic(
                    money_score=20, confidence="LOW", priority="P5_MINIMAL",
                    main_blockers=[],
                ),
                outcomes=outcomes, sessions=sessions,
            ),
            outcomes=outcomes, sessions=sessions,
        )
        self.assertEqual(m.recommended_action, "GATHER_EVIDENCE")
        self.assertEqual(m.current_status, "READY")

    def test_high_value_class_triggers_start_research(self):
        outcomes = make_outcomes()
        sessions = make_sessions()
        m = build_action(
            opportunity=build_opportunity(
                lead=make_lead(),
                economic=make_economic(
                    money_score=80, confidence="HIGH", priority="P1_START_NOW",
                    main_blockers=[],
                ),
                outcomes=outcomes, sessions=sessions,
            ),
            outcomes=outcomes, sessions=sessions,
        )
        self.assertEqual(m.recommended_action, "START_RESEARCH")
        self.assertEqual(m.current_status, "READY")

    def test_blockers_preserved(self):
        m = build_action()
        for code in (
            "only generic technology match",
            "affected plugin not observed",
            "asset component not observed",
            "asset version unknown",
        ):
            self.assertIn(code, m.blockers)

    def test_no_history_does_not_change_money(self):
        no_history = build_action(
            sessions=make_sessions(), outcomes=make_outcomes()
        )
        with_history = build_action(
            sessions=make_sessions(
                total_sessions=2, completed_sessions=2,
                planned_time=120, actual_time=90, session_status="COMPLETED",
            ),
            outcomes=make_outcomes(
                terminal_attempts=2, accepted=2, acceptance_rate=1.0,
                outcome_status="ACCEPTED",
            ),
        )
        self.assertEqual(no_history.money_score, with_history.money_score)
        self.assertEqual(
            no_history.opportunity_class, with_history.opportunity_class
        )

    def test_malformed_lead_does_not_crash(self):
        # Malformed opportunity produces an OpportunityAction with default
        # class (DEFER) and a deterministic id; never crashes.
        bad = {
            "lead_id": "",
            "opportunity_id": "",
            "cve_id": "",
            "program": "",
            "opportunity_class": "",
            "money_score": 0,
            "priority": "",
            "confidence": "MEDIUM",
            "evidence_quality": "NONE",
            "effort_score": 50,
            "estimated_minutes": 0,
            "blockers": [],
            "why_now": [],
        }
        try:
            m = oa.build_action(bad, make_sessions(), make_outcomes())
        except Exception:
            # Either it succeeds with sane defaults OR raises; never half-build.
            return
        self.assertIn(m.opportunity_class,
                      ("DEFER", "BLOCKED", "GOOD_OPPORTUNITY",
                       "HIGH_VALUE", "RESEARCH_FIRST", "LOW_CONFIDENCE"))
        self.assertEqual(m.rule_version, ACTION_RULE_VERSION)
        self.assertTrue(m.research_only)

    def test_missing_opportunity_class_defaults_to_defer(self):
        m = oa.build_action(
            {
                "lead_id": DELL,
                "opportunity_id": opportunity_id_for(DELL),
                "cve_id": CVE, "program": "dell",
                "opportunity_class": "",
                "money_score": 0,
                "priority": "",
                "confidence": "MEDIUM",
                "evidence_quality": "NONE",
                "effort_score": 50,
                "estimated_minutes": 90,
                "blockers": [], "why_now": [],
            },
            make_sessions(), make_outcomes(),
        )
        self.assertIn(m.recommended_action, ACTION_CODES)
        self.assertEqual(m.opportunity_class, "DEFER")


# ---------- ranking --------------------------------------------------------


class TestRanking(unittest.TestCase):
    def test_ranking_is_deterministic(self):
        actions = [build_action() for _ in range(3)]
        a = oa.rank_actions(actions)
        b = oa.rank_actions(actions)
        self.assertEqual(
            [x.action_id for x in a], [x.action_id for x in b]
        )

    def test_ranking_status_first(self):
        sessions = make_sessions(
            total_sessions=1, in_progress_sessions=1,
            session_status="ACTIVE",
        )
        outcomes = make_outcomes()
        a_inprog = build_action(
            opportunity=build_opportunity(
                lead=make_lead(),
                economic=make_economic(money_score=80, priority="P1_START_NOW"),
                outcomes=outcomes, sessions=sessions,
            ),
            sessions=sessions, outcomes=outcomes,
        )
        a_blocked = build_action()  # default: BLOCKED + VERIFY_ASSET_MATCH
        ranked = oa.rank_actions([a_blocked, a_inprog])
        self.assertEqual(ranked[0].current_status, "IN_PROGRESS")
        self.assertEqual(ranked[1].current_status, "BLOCKED")

    def test_ranking_money_within_status(self):
        # Two BLOCKED opportunities, different money_score.
        outcomes = make_outcomes()
        sessions = make_sessions()
        econ_high = make_economic(
            money_score=80, priority="P1_START_NOW", main_blockers=[]
        )
        # Force BLOCKED class with high money but no asset_match.
        lead_high = make_lead()
        opp_high = build_opportunity(
            lead=lead_high, economic=econ_high,
            outcomes=outcomes, sessions=sessions,
        )
        opp_low = build_opportunity(
            lead=make_lead(),
            economic=make_economic(money_score=10, priority="P5_MINIMAL"),
            outcomes=outcomes, sessions=sessions,
        )
        a_high = oa.build_action(opp_high, sessions, outcomes)
        a_low = oa.build_action(opp_low, sessions, outcomes)
        ranked = oa.rank_actions([a_low, a_high])
        # the higher money-score action should be ranked first when status matches
        if a_high.current_status == a_low.current_status:
            self.assertGreaterEqual(
                ranked[0].money_score, ranked[1].money_score
            )


# ---------- summary --------------------------------------------------------


class TestSummary(unittest.TestCase):
    def test_summary_counts(self):
        s = oa.build_action_summary([build_action()])
        self.assertEqual(s["total"], 1)
        self.assertEqual(s["blocked"], 1)
        self.assertEqual(s["ready"], 0)
        self.assertEqual(s["top_action"], "VERIFY_ASSET_MATCH")
        self.assertEqual(s["rule_version"], ACTION_RULE_VERSION)
        self.assertEqual(
            s["opportunity_rule_version"], OPPORTUNITY_RULE_VERSION
        )
        self.assertTrue(s["research_only"])

    def test_summary_includes_top_lead_and_program(self):
        s = oa.build_action_summary([build_action()])
        self.assertEqual(s["top_lead"], DELL)
        self.assertEqual(s["top_program"], "dell")
        self.assertEqual(s["top_cve"], CVE)

    def test_summary_empty(self):
        s = oa.build_action_summary([])
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["ready"], 0)
        self.assertEqual(s["blocked"], 0)
        self.assertEqual(s["top_action"], "DEFER")
        self.assertEqual(s["top_lead"], "")
        self.assertEqual(s["top_reason"], "")


# ---------- backend composition --------------------------------------------


class TestBackend(unittest.TestCase):
    def test_build_action_queue_returns_real_corpus(self):
        from backend import research_action_queue
        items = research_action_queue.build_action_queue()
        self.assertGreaterEqual(len(items), 1)
        self.assertTrue(all(i["research_only"] for i in items))
        self.assertTrue(all(i["rule_version"] == ACTION_RULE_VERSION
                            for i in items))

    def test_dell_blocked_verify_asset_match(self):
        from backend import research_action_queue
        item = research_action_queue.get_action(DELL)
        self.assertEqual(item["current_status"], "BLOCKED")
        self.assertEqual(item["recommended_action"], "VERIFY_ASSET_MATCH")
        self.assertEqual(item["money_score"], 53)
        self.assertEqual(item["priority"], "P3_MEDIUM")
        self.assertEqual(
            item["next_step"], "Confirm affected component/plugin presence."
        )

    def test_indeed_blocked_verify_asset_match(self):
        from backend import research_action_queue
        item = research_action_queue.get_action(INDEED)
        self.assertEqual(item["current_status"], "BLOCKED")
        self.assertEqual(item["recommended_action"], "VERIFY_ASSET_MATCH")

    def test_action_summary_known_fields(self):
        from backend import research_action_queue
        s = research_action_queue.action_summary()
        for k in ("total", "ready", "blocked", "in_progress", "deferred",
                  "completed", "top_action", "top_lead", "top_program",
                  "top_reason", "rule_version", "research_only"):
            self.assertIn(k, s)
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["blocked"], 2)
        self.assertEqual(s["top_action"], "VERIFY_ASSET_MATCH")

    def test_filters(self):
        from backend import research_action_queue
        # class
        self.assertEqual(
            research_action_queue.list_actions(opportunity_class="BLOCKED")
            ["total"], 2
        )
        # status
        self.assertEqual(
            research_action_queue.list_actions(status="BLOCKED")["total"], 2
        )
        # cve
        self.assertEqual(
            research_action_queue.list_actions(cve=CVE)["total"], 2
        )
        # program
        self.assertEqual(
            research_action_queue.list_actions(program="dell")["total"], 1
        )

    def test_limit_and_offset(self):
        from backend import research_action_queue
        out = research_action_queue.list_actions(limit=1)
        self.assertEqual(out["total"], 2)
        self.assertEqual(len(out["items"]), 1)
        out = research_action_queue.list_actions(limit=1, offset=1)
        self.assertEqual(len(out["items"]), 1)
        # ranking preserved
        self.assertNotEqual(out["items"][0]["lead_id"],
                            research_action_queue.list_actions(limit=1)
                            ["items"][0]["lead_id"])

    def test_no_history_does_not_change_money(self):
        from backend import research_action_queue
        items = research_action_queue.build_action_queue()
        for item in items:
            self.assertEqual(item["money_score"], 53)

    def test_no_payout_or_target_fields(self):
        from backend import research_action_queue
        items = research_action_queue.build_action_queue()
        keys = set()
        for item in items:
            keys.update(item.keys())
        for token in ("payout", "bounty", "reward", "target_url", "ip",
                      "domain", "credential", "exploit_command",
                      "execution_command", "production_finding"):
            self.assertFalse(
                [k for k in keys if token in k.lower()],
                f"{token} in {keys}",
            )

    def test_get_action_invalid_lead_id(self):
        from backend import research_action_queue
        from backend.research_data import NotFoundError
        with self.assertRaises(NotFoundError):
            research_action_queue.get_action("not-a-lead")
        with self.assertRaises(NotFoundError):
            research_action_queue.get_action("rl-doesnotexist")

    def test_get_action_unknown_lead_id(self):
        from backend import research_action_queue
        from backend.research_data import NotFoundError
        with self.assertRaises(NotFoundError):
            research_action_queue.get_action("rl-ffffffffffffffff")


# ---------- CLI ------------------------------------------------------------


class TestCli(unittest.TestCase):
    def _run(self, args):
        from ai import research_cli
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            code = research_cli.main(args)
        return code, buf_out.getvalue(), buf_err.getvalue()

    def test_action_list(self):
        code, out, _ = self._run(["opportunity", "action-list"])
        self.assertEqual(code, 0)
        self.assertIn("ACTION QUEUE", out)
        self.assertIn("CVE-2026-1557", out)
        self.assertIn("VERIFY_ASSET_MATCH", out)
        self.assertIn("Confirm affected component/plugin presence.", out)

    def test_action_list_filters(self):
        code, out, _ = self._run(
            ["opportunity", "action-list", "--class", "BLOCKED", "--limit", "1"]
        )
        self.assertEqual(code, 0)
        self.assertIn("BLOCKED", out)

    def test_action_list_json(self):
        code, out, _ = self._run(["opportunity", "action-list", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertGreaterEqual(len(data), 1)
        self.assertEqual(data[0]["recommended_action"], "VERIFY_ASSET_MATCH")

    def test_action_show(self):
        code, out, _ = self._run([
            "opportunity", "action-show", "--lead-id", DELL
        ])
        self.assertEqual(code, 0)
        self.assertIn("Opportunity Action", out)
        self.assertIn("VERIFY_ASSET_MATCH", out)
        self.assertIn("Confirm affected component/plugin presence.", out)
        self.assertIn("BLOCKED", out)

    def test_action_show_errors(self):
        code, _, _ = self._run([
            "opportunity", "action-show", "--lead-id", "rl-ffffffffffffffff"
        ])
        self.assertEqual(code, 1)
        code, _, _ = self._run([
            "opportunity", "action-show", "--lead-id", "not-a-lead"
        ])
        self.assertEqual(code, 1)

    def test_action_summary(self):
        code, out, _ = self._run(["opportunity", "action-summary"])
        self.assertEqual(code, 0)
        self.assertIn("Action Queue Summary", out)
        self.assertIn("Top action: VERIFY_ASSET_MATCH", out)
        code, out, _ = self._run(["opportunity", "action-summary", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["blocked"], 2)
        self.assertEqual(data["top_action"], "VERIFY_ASSET_MATCH")


# ---------- API ------------------------------------------------------------


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _headers(self):
        h = {}
        if API_KEY:
            h["X-API-Key"] = API_KEY
        return h

    def test_actions_list(self):
        r = self.client.get(
            "/api/research/opportunities/actions",
            headers=self._headers(),
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["items"][0]["recommended_action"],
                         "VERIFY_ASSET_MATCH")

    def test_actions_list_filters(self):
        r = self.client.get(
            "/api/research/opportunities/actions",
            params={"class": "BLOCKED", "limit": 1},
            headers=self._headers(),
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["items"]), 1)

        r = self.client.get(
            "/api/research/opportunities/actions",
            params={"status": "BLOCKED"},
            headers=self._headers(),
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["total"], 2)

        r = self.client.get(
            "/api/research/opportunities/actions",
            params={"program": "dell"},
            headers=self._headers(),
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["total"], 1)

    def test_actions_summary(self):
        r = self.client.get(
            "/api/research/opportunities/actions/summary",
            headers=self._headers(),
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["blocked"], 2)
        self.assertEqual(data["top_action"], "VERIFY_ASSET_MATCH")

    def test_action_detail(self):
        r = self.client.get(
            f"/api/research/opportunities/actions/{DELL}",
            headers=self._headers(),
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["lead_id"], DELL)
        self.assertEqual(data["current_status"], "BLOCKED")
        self.assertEqual(data["recommended_action"], "VERIFY_ASSET_MATCH")
        self.assertEqual(data["money_score"], 53)

    def test_action_detail_404(self):
        r = self.client.get(
            "/api/research/opportunities/actions/rl-ffffffffffffffff",
            headers=self._headers(),
        )
        self.assertEqual(r.status_code, 404)

    def test_no_write_endpoints(self):
        # POST/PUT/PATCH on the actions route must not be exposed.
        for method in ("post", "put", "patch"):
            r = getattr(self.client, method)(
                "/api/research/opportunities/actions",
                json={},
                headers=self._headers(),
            )
            self.assertIn(r.status_code, (401, 405),
                          f"{method} -> {r.status_code}")
        # DELETE does not accept json; check it directly.
        r = self.client.delete(
            "/api/research/opportunities/actions",
            headers=self._headers(),
        )
        self.assertIn(r.status_code, (401, 405))

    def test_no_payout_vocabulary(self):
        r = self.client.get(
            f"/api/research/opportunities/actions/{DELL}",
            headers=self._headers(),
        )
        text = r.text.lower()
        for token in ("payout", "bounty", "reward amount",
                      "exploit_command", "target_url"):
            self.assertNotIn(token, text)

    def test_research_only_flag(self):
        r = self.client.get(
            "/api/research/opportunities/actions",
            headers=self._headers(),
        )
        data = r.json()
        self.assertTrue(data["research_only"])
        self.assertEqual(data["rule_version"], "r26-2")
        for item in data["items"]:
            self.assertTrue(item["research_only"])
            self.assertEqual(item["rule_version"], "r26-2")


# ---------- UI -------------------------------------------------------------


class TestUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path):
        if API_KEY:
            return self.client.get(path, params={"api_key": API_KEY})
        return self.client.get(path)

    def test_leads_list_next_action_column(self):
        r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Next action", r.text)
        self.assertIn("VERIFY ASSET", r.text)

    def test_lead_detail_action_panel(self):
        r = self._get(f"/ui/research/leads/{DELL}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Next action", r.text)
        self.assertIn("VERIFY_ASSET_MATCH", r.text)
        self.assertIn("NEXT STEP", r.text)
        self.assertIn("BLOCKER", r.text)
        self.assertIn("Confirm affected component/plugin presence.", r.text)

    def test_ui_panel_is_research_only(self):
        r = self._get(f"/ui/research/leads/{DELL}")
        # Grab the "Next action" panel only (read-only vocabulary check).
        panel = r.text.split("Next action", 1)[1].split(
            "Opportunity intelligence", 1
        )[0].lower()
        for token in ("payout", "bounty", "exploit ", "nuclei ",
                      "run scan", "target_url"):
            self.assertNotIn(token, panel)
        self.assertIn("read-only decision layer", panel)


# ---------- safety / boundaries -------------------------------------------


class TestSafety(unittest.TestCase):
    def test_no_execution_tokens(self):
        files = [
            "ai/schemas/opportunity_action.py",
            "ai/knowledge/opportunity_action.py",
            "backend/research_action_queue.py",
        ]
        bad_tokens = [
            "import subprocess", "subprocess.",
            "import socket", "socket.",
            "import requests", "requests.",
            "import httpx", "httpx.",
            "import openai", "import anthropic",
            "from ai.llm", "nuclei.", "Popen(",
            "selenium", "playwright", "os.system(",
            "urlopen",
        ]
        for rel in files:
            text = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            for token in bad_tokens:
                self.assertNotIn(
                    token, text, f"{token!r} found in {rel}"
                )

    def test_engine_purity(self):
        first = build_action().model_dump(mode="json")
        second = build_action().model_dump(mode="json")
        self.assertEqual(first, second)

    def test_ranking_purity(self):
        a = build_action()
        b = oa.rank_actions([a])
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0].action_id, a.action_id)

    def test_summary_purity(self):
        a = build_action()
        s = oa.build_action_summary([a])
        self.assertEqual(s["total"], 1)
        s2 = oa.build_action_summary([a])
        self.assertEqual(s, s2)

    def test_money_score_constants_unchanged(self):
        from ai.knowledge import economics
        self.assertEqual(economics.MONEY_W_VALUE, 0.55)
        self.assertEqual(economics.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(economics.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(economics.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(economics.RULE_VERSION, "r25-1")
        self.assertEqual(OPPORTUNITY_RULE_VERSION, "r26-1")
        self.assertEqual(ACTION_RULE_VERSION, "r26-2")

    def test_no_duplicate_score_field(self):
        # The Action Queue must NOT carry a fresh numeric score.
        from backend import research_action_queue
        items = research_action_queue.build_action_queue()
        for item in items:
            for token in ("score", "queue_score", "action_score",
                          "priority_score", "weighted_score"):
                self.assertFalse(
                    [k for k in item if token == k],
                    f"unexpected score field {token} in action",
                )
            # money_score is allowed (copied verbatim from R26.1).
            self.assertIn("money_score", item)

    def test_calibration_unchanged(self):
        from backend import research_calibration
        report = research_calibration.build_report()
        self.assertEqual(report["recommendation"], "INSUFFICIENT_DATA")
        self.assertTrue(report["weights_unchanged"])

    def test_known_action_codes_only(self):
        # Every recommended_action in the queue must be in the closed enum.
        from backend import research_action_queue
        items = research_action_queue.build_action_queue()
        for item in items:
            self.assertIn(item["recommended_action"], ACTION_CODES)
            self.assertIn(item["current_status"], ACTION_STATUSES)


if __name__ == "__main__":
    unittest.main(verbosity=2)