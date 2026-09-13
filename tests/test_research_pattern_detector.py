"""tests/test_research_pattern_detector.py — Stage R32.3 tests.

Deterministic, offline tests for the research pattern detector:

- deterministic output
- empty history -> NO_PATTERN / UNKNOWN
- low / medium / high frequency confidence
- dominant pattern tie-break
- evidence distribution
- malformed input handling
- no mutation, JSON serialization, schema validation
- research_only always true, no operational content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import research_pattern_detector as rpd
from ai.schemas import research_pattern_plan as schema


def snapshot(improvement_area="VERSION", **over):
    record = {
        "rule_version": "r32-1",
        "candidate_identity": "rc-test",
        "research_status": "ACTIVE",
        "outcome": "IN_PROGRESS",
        "confidence_level": "MEDIUM",
        "feedback_signal": "CONTINUE_SIGNAL",
        "improvement_area": improvement_area,
        "blockers": [],
        "timestamp_reference": "ref",
        "source_export": {},
        "research_only": True,
    }
    record.update(over)
    return record


class TestPatternDetection(unittest.TestCase):
    def test_empty_history(self):
        for value in (None, [], (), {}, [None, "x", 0], [{}]):
            plan = rpd.detect_research_patterns(value)
            self.assertEqual(plan["dominant_pattern"], schema.PATTERN_NONE)
            self.assertEqual(plan["frequency"], 0)
            self.assertEqual(plan["confidence"], "UNKNOWN")
            self.assertEqual(plan["evidence"], [])

    def test_single_record_low_confidence(self):
        plan = rpd.detect_research_patterns([snapshot("VERSION")])
        self.assertEqual(plan["dominant_pattern"],
                         schema.PATTERN_VERSION_LIMITED)
        self.assertEqual(plan["frequency"], 1)
        self.assertEqual(plan["confidence"], "LOW")

    def test_two_records_medium_confidence(self):
        plan = rpd.detect_research_patterns(
            [snapshot("PATH"), snapshot("PATH")]
        )
        self.assertEqual(plan["dominant_pattern"],
                         schema.PATTERN_PATH_LIMITED)
        self.assertEqual(plan["frequency"], 2)
        self.assertEqual(plan["confidence"], "MEDIUM")

    def test_three_records_high_confidence(self):
        plan = rpd.detect_research_patterns(
            [snapshot("TECHNOLOGY")] * 3
        )
        self.assertEqual(plan["dominant_pattern"],
                         schema.PATTERN_TECHNOLOGY_LIMITED)
        self.assertEqual(plan["frequency"], 3)
        self.assertEqual(plan["confidence"], "HIGH")

    def test_dominant_tie_break_is_alphabetical(self):
        plan = rpd.detect_research_patterns(
            [snapshot("VERSION"), snapshot("PATH")]
        )
        self.assertEqual(plan["dominant_pattern"],
                         schema.PATTERN_PATH_LIMITED)
        self.assertEqual(plan["frequency"], 1)

    def test_evidence_distribution_sorted(self):
        plan = rpd.detect_research_patterns(
            [
                snapshot("VERSION"), snapshot("VERSION"),
                snapshot("HUMAN_RESEARCH"), snapshot("HUMAN_RESEARCH"),
                snapshot("PATH"),
            ]
        )
        self.assertEqual(
            plan["evidence"],
            [
                {"pattern": "HUMAN_RESEARCH", "count": 2},
                {"pattern": "VERSION_LIMITED", "count": 2},
                {"pattern": "PATH_LIMITED", "count": 1},
            ],
        )
        self.assertEqual(plan["dominant_pattern"],
                         schema.PATTERN_HUMAN_RESEARCH)

    def test_none_area_produces_no_pattern(self):
        plan = rpd.detect_research_patterns(
            [snapshot("NONE"), snapshot("NONE")]
        )
        self.assertEqual(plan["dominant_pattern"], schema.PATTERN_NONE)
        self.assertEqual(plan["confidence"], "UNKNOWN")

    def test_malformed_entries_are_skipped(self):
        plan = rpd.detect_research_patterns(
            [None, "x", {}, [1], snapshot("SCOPE")]
        )
        self.assertEqual(plan["dominant_pattern"],
                         schema.PATTERN_SCOPE_LIMITED)
        self.assertEqual(plan["frequency"], 1)

    def test_malformed_improvement_areas_ignored(self):
        plan = rpd.detect_research_patterns(
            [snapshot("MONEY"), snapshot(None), snapshot("VERSION")]
        )
        self.assertEqual(plan["dominant_pattern"],
                         schema.PATTERN_VERSION_LIMITED)
        self.assertEqual(len(plan["evidence"]), 1)

    def test_confidence_for_helper(self):
        self.assertEqual(rpd.confidence_for(0), "UNKNOWN")
        self.assertEqual(rpd.confidence_for(1), "LOW")
        self.assertEqual(rpd.confidence_for(2), "MEDIUM")
        self.assertEqual(rpd.confidence_for(5), "HIGH")

    def test_deterministic_output(self):
        records = [snapshot("VERSION"), snapshot("PATH")]
        first = rpd.detect_research_patterns(records)
        second = rpd.detect_research_patterns(records)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        records = [snapshot("VERSION"), snapshot("PATH")]
        before = copy.deepcopy(records)
        rpd.detect_research_patterns(records)
        self.assertEqual(records, before)

    def test_json_serializable(self):
        plan = rpd.detect_research_patterns([snapshot()])
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        for value in (None, [snapshot()]):
            plan = rpd.detect_research_patterns(value)
            self.assertIs(plan["research_only"], True)

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            rpd.detect_research_patterns(
                [snapshot("VERSION"), snapshot("PATH")]
            )
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_pattern_vocabulary_is_closed(self):
        self.assertIn(schema.PATTERN_NONE, schema.PATTERN_CODES)
        self.assertIn(schema.PATTERN_VERSION_LIMITED,
                      schema.PATTERN_CODES)
        self.assertIn(schema.PATTERN_HUMAN_RESEARCH,
                      schema.PATTERN_CODES)
        self.assertEqual(
            set(schema.PATTERN_BY_AREA.values()) - {schema.PATTERN_UNKNOWN},
            set(schema.PATTERN_CODES) - {
                schema.PATTERN_NONE, schema.PATTERN_UNKNOWN,
            },
        )

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchPatternPlan(
                dominant_pattern="WINNER", frequency=1,
                confidence="HIGH",
            )
        with self.assertRaises(ValidationError):
            schema.ResearchPatternPlan(
                dominant_pattern=schema.PATTERN_NONE, frequency=-1,
                confidence="UNKNOWN",
            )
        with self.assertRaises(ValidationError):
            schema.ResearchPatternPlan(
                dominant_pattern=schema.PATTERN_NONE, frequency=0,
                confidence="CERTAIN",
            )
        with self.assertRaises(ValidationError):
            schema.ResearchPatternPlan(
                dominant_pattern=schema.PATTERN_NONE, frequency=0,
                confidence="UNKNOWN", severity="HIGH",
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchPatternPlan(
            rule_version="r99-9",
            dominant_pattern=schema.PATTERN_NONE,
            frequency=0,
            confidence="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r32-3")
        with self.assertRaises(ValidationError):
            schema.ResearchPatternPlan(
                dominant_pattern=schema.PATTERN_NONE,
                frequency=0,
                confidence="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rpd.RESEARCH_PATTERN_DETECTOR_RULE_VERSION, "r32-3"
        )
        plan = rpd.detect_research_patterns()
        self.assertEqual(plan["rule_version"], "r32-3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
