"""Focused offline tests for the R70 research outcome and action planner."""

from __future__ import annotations

import json
import re
import unittest

from ai.knowledge.research_outcome_planner import (
    CATEGORY_GAPS,
    CATEGORY_ORDER,
    SAFETY_BLOCK,
    ResearchOutcomeError,
    build_research_actions,
    build_research_outcomes,
    evidence_state_of,
    gap_id_for,
    plan_research_actions,
    rank_research_actions,
    summarize_research_actions,
)

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MONGO_ID_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{24}(?![0-9a-fA-F])")

FORBIDDEN_TEXT = (
    "payload",
    "execute",
    "exploit",
    "attack",
    "send a request",
    "curl ",
    "nmap",
    "sqlmap",
    "brute force",
)


def hypothesis(**overrides) -> dict:
    item = {
        "title": "Sample structural hypothesis",
        "category": "IDOR",
        "priority": "MEDIUM",
        "confidence": "MEDIUM",
        "evidence": {
            "observations": [
                {
                    "ref": "path:/api/items/{id}",
                    "fact": "observed path /api/items/{id}",
                    "source": "context",
                }
            ],
            "derived_signals": [
                {
                    "signal": "IDOR",
                    "detail": "object_reference=PATH_PARAMETER",
                    "source": "watch_derived",
                }
            ],
        },
        "selected_evidence_refs": ["E1"],
        "inference": "The reference may be object-scoped.",
        "why_interesting": "Structural lead only.",
        "missing_evidence": ["authorization behavior"],
        "next_safe_action": "Review stored records.",
    }
    item.update(overrides)
    return item


class TestResearchOutcomes(unittest.TestCase):
    def test_accepted_hypothesis_to_outcome(self):
        outcomes = build_research_outcomes([hypothesis()])
        self.assertEqual(len(outcomes), 1)
        outcome = outcomes[0]
        for field in (
            "hypothesis_ref",
            "title",
            "category",
            "priority",
            "confidence",
            "evidence_state",
            "current_evidence",
            "hypothesis_missing_evidence",
            "gap_id",
            "evidence_gap",
            "research_objective",
            "recommended_next_action",
            "expected_evidence",
            "reason_for_action",
            "safe_stopping_condition",
        ):
            self.assertIn(field, outcome, field)
        self.assertEqual(outcome["hypothesis_ref"], "H1")
        self.assertEqual(outcome["gap_id"], "OBJECT_AUTHORIZATION")
        self.assertEqual(outcome["evidence_state"], "STRUCTURE_AND_SIGNAL")
        self.assertEqual(
            outcome["hypothesis_missing_evidence"], ["authorization behavior"]
        )

    def test_category_gap_mapping(self):
        expected = {
            "IDOR": "OBJECT_AUTHORIZATION",
            "SSRF": "SERVER_SIDE_FETCH",
            "XSS": "REFLECTION_CONTEXT",
            "SQLI": "QUERY_BEHAVIOR",
            "JWT": "TOKEN_VALIDATION",
            "OAUTH": "OAUTH_FLOW_ARTIFACTS",
            "CVE_RESEARCH": "COMPONENT_MAPPING",
            "RECON": "ENDPOINT_BEHAVIOR",
            "MAGIC": "ADDITIONAL_EVIDENCE",
        }
        for category, gap in expected.items():
            with self.subTest(category=category):
                self.assertEqual(gap_id_for(category), gap)
        self.assertEqual(CATEGORY_GAPS["IDOR"], "OBJECT_AUTHORIZATION")

    def test_evidence_state_vocabulary(self):
        corroborated = hypothesis()
        corroborated["evidence"]["observations"] = [
            {"ref": "response:r1", "fact": "x", "source": "context"}
        ]
        self.assertEqual(evidence_state_of(corroborated), "CORROBORATED")

        structural = hypothesis()
        structural["evidence"]["derived_signals"] = []
        self.assertEqual(evidence_state_of(structural), "STRUCTURAL_ONLY")

        derived_only = hypothesis()
        derived_only["evidence"]["observations"] = []
        self.assertEqual(evidence_state_of(derived_only), "DERIVED_ONLY")

        none = hypothesis()
        none["evidence"] = {}
        self.assertEqual(evidence_state_of(none), "NONE")


class TestResearchActions(unittest.TestCase):
    def test_duplicate_gap_correlation(self):
        outcomes = build_research_outcomes(
            [hypothesis(title="First"), hypothesis(title="Second")]
        )
        actions = build_research_actions(outcomes)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["hypothesis_count"], 2)
        self.assertEqual(actions[0]["hypothesis_refs"], ["H1", "H2"])
        self.assertEqual(
            actions[0]["hypothesis_titles"], ["First", "Second"]
        )

    def test_distinct_gaps_produce_distinct_actions(self):
        outcomes = build_research_outcomes(
            [hypothesis(category="IDOR"), hypothesis(category="XSS")]
        )
        actions = build_research_actions(outcomes)
        self.assertEqual(len(actions), 2)
        self.assertEqual(
            {action["gap_id"] for action in actions},
            {"OBJECT_AUTHORIZATION", "REFLECTION_CONTEXT"},
        )

    def test_category_aware_actions(self):
        for category, gap in CATEGORY_GAPS.items():
            with self.subTest(category=category):
                plan = plan_research_actions([hypothesis(category=category)])
                self.assertEqual(plan["actions"][0]["gap_id"], gap)
                self.assertTrue(plan["actions"][0]["objective"])
                self.assertTrue(plan["actions"][0]["recommended_action"])
                self.assertTrue(plan["actions"][0]["expected_evidence"])
                self.assertTrue(plan["actions"][0]["stopping_condition"])

    def test_action_safety_flags(self):
        action = build_research_actions(
            build_research_outcomes([hypothesis()])
        )[0]
        self.assertEqual(action["safety"], SAFETY_BLOCK)
        self.assertTrue(action["safety"]["advisory"])
        self.assertTrue(action["safety"]["research_only"])
        self.assertFalse(action["safety"]["execution_performed"])
        self.assertFalse(action["safety"]["vulnerability_confirmed"])
        self.assertFalse(action["safety"]["exploit_authorized"])
        self.assertTrue(action["safety"]["human_authority_required"])
        self.assertEqual(
            action["safety"]["confirmation_state"], "NOT_CONFIRMED"
        )

    def test_ranking_is_deterministic_and_ordered(self):
        outcomes = build_research_outcomes(
            [
                hypothesis(category="XSS", priority="LOW", confidence="LOW"),
                hypothesis(
                    category="IDOR", priority="HIGH", confidence="MEDIUM"
                ),
            ]
        )
        first = rank_research_actions(build_research_actions(outcomes))
        second = rank_research_actions(build_research_actions(outcomes))
        self.assertEqual(first, second)
        self.assertEqual([action["category"] for action in first], ["IDOR", "XSS"])
        self.assertGreater(
            first[0]["score"]["total"], first[1]["score"]["total"]
        )
        for action in first:
            self.assertEqual(
                action["score"]["total"],
                sum(action["score"]["factors"].values()),
            )

    def test_ranking_tie_breaks_by_category_order(self):
        outcomes = build_research_outcomes(
            [hypothesis(category="RECON"), hypothesis(category="XSS")]
        )
        ranked = rank_research_actions(build_research_actions(outcomes))
        self.assertEqual(
            [action["category"] for action in ranked], ["XSS", "RECON"]
        )

    def test_plan_bounds_and_summary(self):
        hypotheses = [hypothesis(category=c) for c in CATEGORY_ORDER]
        plan = plan_research_actions(hypotheses, limit=3)
        self.assertEqual(len(plan["actions"]), 3)
        self.assertEqual(plan["summary"]["action_count"], 3)
        self.assertEqual(plan["summary"]["top_action_id"], "A1")
        self.assertEqual(
            plan["summary"]["priority_bands"],
            {"HIGH": 0, "MEDIUM": 3, "LOW": 0},
        )
        self.assertTrue(plan["summary"]["top_action_objective"])
        with self.assertRaises(ResearchOutcomeError):
            plan_research_actions(hypotheses, limit=True)
        with self.assertRaises(ResearchOutcomeError):
            plan_research_actions(hypotheses, limit=-1)

    def test_empty_and_invalid_hypothesis_handling(self):
        for value in (None, [], "not-a-list", [None, 3, "x"]):
            with self.subTest(value=value):
                plan = plan_research_actions(value)
                self.assertEqual(plan["actions"], [])
                self.assertEqual(plan["outcomes"], [])
                self.assertEqual(plan["summary"]["action_count"], 0)
        plan = plan_research_actions([{"title": "no category"}])
        self.assertEqual(plan["actions"][0]["gap_id"], "ADDITIONAL_EVIDENCE")

    def test_bounded_text(self):
        item = hypothesis(
            title="t" * 1000, missing_evidence=["m" * 1000]
        )
        plan = plan_research_actions([item])
        outcome = plan["outcomes"][0]
        self.assertLessEqual(len(outcome["title"]), 160)
        self.assertLessEqual(
            len(outcome["hypothesis_missing_evidence"][0]), 160
        )
        self.assertLessEqual(len(outcome["hypothesis_ref"]), 16)


class TestPlannerSafety(unittest.TestCase):
    def test_unconfirmed_state_preserved(self):
        plan = plan_research_actions([hypothesis()])
        self.assertEqual(plan["safety"], SAFETY_BLOCK)
        self.assertEqual(
            plan["safety"]["confirmation_state"], "NOT_CONFIRMED"
        )
        self.assertFalse(plan["safety"]["vulnerability_confirmed"])
        self.assertFalse(plan["safety"]["execution_performed"])
        for action in plan["actions"]:
            self.assertEqual(
                action["safety"]["confirmation_state"], "NOT_CONFIRMED"
            )
        for outcome in plan["outcomes"]:
            self.assertEqual(outcome["confirmation_state"], "NOT_CONFIRMED")

    def test_no_execution_semantics(self):
        plan = plan_research_actions(
            [hypothesis(category=c) for c in CATEGORY_ORDER]
        )
        content = []
        for outcome in plan["outcomes"]:
            content.extend(
                [
                    outcome["research_objective"],
                    outcome["recommended_next_action"],
                    outcome["expected_evidence"],
                    outcome["reason_for_action"],
                    outcome["safe_stopping_condition"],
                ]
            )
        for action in plan["actions"]:
            content.extend(
                [
                    action["objective"],
                    action["recommended_action"],
                    action["expected_evidence"],
                    action["reason"],
                    action["stopping_condition"],
                ]
            )
        text = " ".join(content).lower()
        for forbidden in FORBIDDEN_TEXT:
            self.assertIsNone(
                re.search(rf"\b{re.escape(forbidden)}\b", text), forbidden
            )

    def test_no_sensitive_data_leakage(self):
        plan = plan_research_actions([hypothesis()])
        text = json.dumps(plan)
        self.assertNotIn("://", text)
        self.assertIsNone(IPV4_RE.search(text))
        self.assertIsNone(MONGO_ID_RE.search(text))
        self.assertNotIn("sk-", text)
        self.assertNotIn('"_id"', text)

    def test_summary_is_bounded_and_safe(self):
        summary = summarize_research_actions(
            build_research_actions(build_research_outcomes([hypothesis()]))
        )
        self.assertEqual(summary["action_count"], 1)
        self.assertEqual(summary["covered_hypotheses"], 1)
        self.assertEqual(summary["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(summary["advisory"])


if __name__ == "__main__":
    unittest.main()
