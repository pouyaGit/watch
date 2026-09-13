"""tests/test_research_learning_export.py — Stage R33.4 tests.

Deterministic, offline tests for the research learning exporter:

- deterministic output
- ready requires all three R33 plans to be valid
- recommendation and limitation mappings
- malformed input handling
- no mutation, JSON serialization, closed vocabulary validation
- research_only always true, no operational attack content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import research_learning_export as rle
from ai.schemas import research_learning_export as schema


def patterns(signal="NO_PATTERN", confidence="UNKNOWN", scores=()):
    return {
        "rule_version": "r33-1",
        "dominant_patterns": [s["pattern"] for s in scores],
        "pattern_scores": list(scores),
        "strongest_signal": signal,
        "confidence": confidence,
        "research_only": True,
    }


def ranking(reason="SINGLE_CANDIDATE", candidates=(),
            signals=()):
    return {
        "rule_version": "r33-2",
        "candidate_scores": list(candidates),
        "ranking_reason": reason,
        "historical_signals": list(signals),
        "research_only": True,
    }


def efficiency(state="MEDIUM", improvement="NONE"):
    return {
        "rule_version": "r33-3",
        "efficiency_state": state,
        "successful_ratio": 0.5,
        "evidence_gap_ratio": 0.0,
        "recurring_blocker_ratio": 0.0,
        "improvement_signal": improvement,
        "research_only": True,
    }


def candidate(score=4, identity="rc-a"):
    return {
        "candidate_identity": identity,
        "score": score,
        "records": 1,
        "signals": ["HISTORICAL_SUCCESS"],
    }


class TestLearningExport(unittest.TestCase):
    def test_ready_when_all_valid(self):
        export = rle.export_research_learning(
            patterns("VERSION_LIMITED", "HIGH"),
            ranking(),
            efficiency(),
        )
        self.assertTrue(export["ready"])
        self.assertEqual(export["rule_version"], "r33-4")
        self.assertEqual(export["patterns"]["strongest_signal"],
                         "VERSION_LIMITED")
        self.assertEqual(export["ranking"]["ranking_reason"],
                         "SINGLE_CANDIDATE")
        self.assertEqual(export["efficiency"]["efficiency_state"],
                         "MEDIUM")

    def test_not_ready_when_any_plan_missing(self):
        valid_patterns = patterns("VERSION_LIMITED", "HIGH")
        valid_ranking = ranking()
        valid_efficiency = efficiency()
        for combo in (
            (None, valid_ranking, valid_efficiency),
            (valid_patterns, None, valid_efficiency),
            (valid_patterns, valid_ranking, None),
            (None, None, None),
        ):
            export = rle.export_research_learning(*combo)
            self.assertFalse(export["ready"], repr(combo))

    def test_not_ready_when_plan_malformed(self):
        export = rle.export_research_learning(
            {"strongest_signal": "NOPE"},
            {"ranking_reason": "NOPE"},
            {"efficiency_state": "NOPE", "improvement_signal": "NOPE"},
        )
        self.assertFalse(export["ready"])

    def test_prioritize_recommendation(self):
        export = rle.export_research_learning(
            patterns("VERSION_LIMITED", "HIGH"),
            ranking(candidates=[candidate(5)]),
            efficiency(),
        )
        self.assertIn("PRIORITIZE_HISTORICAL_SUCCESS",
                      export["recommendations"])

    def test_efficiency_recommendations(self):
        expectations = (
            ("REDUCE_RECURRING_BLOCKERS", "REDUCE_RECURRING_BLOCKERS"),
            ("CLOSE_EVIDENCE_GAPS", "CLOSE_EVIDENCE_GAPS"),
            ("INCREASE_SUCCESSFUL_RESEARCH",
             "INCREASE_SUCCESSFUL_RESEARCH"),
        )
        for improvement, expected in expectations:
            export = rle.export_research_learning(
                patterns("VERSION_LIMITED", "HIGH"),
                ranking(),
                efficiency(improvement=improvement),
            )
            self.assertIn(expected, export["recommendations"])

    def test_collect_more_history_recommendation(self):
        export = rle.export_research_learning(
            patterns("NO_PATTERN", "UNKNOWN"),
            ranking(reason="NO_HISTORY"),
            efficiency(state="UNKNOWN", improvement="INSUFFICIENT_HISTORY"),
        )
        self.assertIn("COLLECT_MORE_HISTORY", export["recommendations"])
        self.assertIn(schema.LIMITATION_NO_HISTORY,
                      export["limitations"])
        self.assertIn(schema.LIMITATION_LOW_PATTERN_CONFIDENCE,
                      export["limitations"])
        self.assertIn(schema.LIMITATION_UNKNOWN_EFFICIENCY,
                      export["limitations"])

    def test_no_action_recommendation(self):
        export = rle.export_research_learning(
            patterns("VERSION_LIMITED", "HIGH"),
            ranking(),
            efficiency(),
        )
        self.assertEqual(export["recommendations"], ["NO_ACTION"])
        self.assertEqual(export["limitations"], [])

    def test_no_historical_success_limitation(self):
        export = rle.export_research_learning(
            patterns("VERSION_LIMITED", "HIGH"),
            ranking(candidates=[candidate(0)]),
            efficiency(),
        )
        self.assertIn(schema.LIMITATION_NO_HISTORICAL_SUCCESS,
                      export["limitations"])

    def test_malformed_inputs_are_not_ready(self):
        for args in ((None, None, None), ({}, {}, {}), ("x", 0, [])):
            export = rle.export_research_learning(*args)
            self.assertFalse(export["ready"], repr(args))
            self.assertIn("COLLECT_MORE_HISTORY",
                          export["recommendations"])
            self.assertIn(schema.LIMITATION_NO_HISTORY,
                          export["limitations"])

    def test_deterministic_output(self):
        args = (
            patterns("VERSION_LIMITED", "HIGH"),
            ranking(candidates=[candidate(4)]),
            efficiency(),
        )
        first = rle.export_research_learning(*args)
        second = rle.export_research_learning(*args)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        pattern_plan = patterns("VERSION_LIMITED", "HIGH")
        ranking_plan = ranking(candidates=[candidate(4)])
        efficiency_plan = efficiency()
        snapshots = (
            copy.deepcopy(pattern_plan),
            copy.deepcopy(ranking_plan),
            copy.deepcopy(efficiency_plan),
        )
        rle.export_research_learning(
            pattern_plan, ranking_plan, efficiency_plan
        )
        self.assertEqual(pattern_plan, snapshots[0])
        self.assertEqual(ranking_plan, snapshots[1])
        self.assertEqual(efficiency_plan, snapshots[2])

    def test_embedded_snapshots_do_not_alias_inputs(self):
        pattern_plan = patterns("VERSION_LIMITED", "HIGH")
        ranking_plan = ranking(candidates=[candidate(4)])
        efficiency_plan = efficiency()
        export = rle.export_research_learning(
            pattern_plan, ranking_plan, efficiency_plan
        )
        export["patterns"]["confidence"] = "UNKNOWN"
        export["ranking"]["candidate_scores"].clear()
        export["efficiency"]["efficiency_state"] = "UNKNOWN"
        self.assertEqual(pattern_plan["confidence"], "HIGH")
        self.assertEqual(len(ranking_plan["candidate_scores"]), 1)
        self.assertEqual(efficiency_plan["efficiency_state"], "MEDIUM")

    def test_json_serializable(self):
        export = rle.export_research_learning(
            patterns("VERSION_LIMITED", "HIGH"),
            ranking(),
            efficiency(),
        )
        self.assertIsInstance(json.loads(json.dumps(export)), dict)

    def test_research_only_always_true(self):
        export = rle.export_research_learning()
        self.assertIs(export["research_only"], True)
        export = rle.export_research_learning(
            patterns("VERSION_LIMITED", "HIGH"),
            ranking(),
            efficiency(),
        )
        self.assertIs(export["research_only"], True)

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            rle.export_research_learning(
                patterns("VERSION_LIMITED", "HIGH"),
                ranking(candidates=[candidate(4)]),
                efficiency(),
            )
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchLearningExportPlan(
                ready=True,
                recommendations=["WIN"],
                limitations=[],
            )
        with self.assertRaises(ValidationError):
            schema.ResearchLearningExportPlan(
                ready=True,
                recommendations=[],
                limitations=["DEPLOY_EXPLOIT"],
            )
        with self.assertRaises(ValidationError):
            schema.ResearchLearningExportPlan(
                ready=True,
                recommendations=[],
                limitations=[],
                severity="HIGH",
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchLearningExportPlan(
            rule_version="r99-9",
            ready=False,
            recommendations=["NO_ACTION"],
            limitations=[],
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r33-4")
        with self.assertRaises(ValidationError):
            schema.ResearchLearningExportPlan(
                ready=False,
                recommendations=[],
                limitations=[],
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rle.RESEARCH_LEARNING_EXPORTER_RULE_VERSION, "r33-4"
        )
        export = rle.export_research_learning()
        self.assertEqual(export["rule_version"], "r33-4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
