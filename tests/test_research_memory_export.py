"""tests/test_research_memory_export.py — Stage R32.4 tests.

Deterministic, offline tests for the research memory exporter:

- deterministic output
- ready / not-ready rules
- limitations (no history, single record, low-confidence pattern,
  recurring blockers)
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

from ai.knowledge import research_history_aggregator as rha
from ai.knowledge import research_memory_exporter as rme
from ai.knowledge import research_pattern_detector as rpd
from ai.schemas import research_memory_export as schema


def snapshot(outcome="IN_PROGRESS", improvement_area="VERSION",
             blockers=(), **over):
    record = {
        "rule_version": "r32-1",
        "candidate_identity": "rc-test",
        "research_status": "ACTIVE",
        "outcome": outcome,
        "confidence_level": "MEDIUM",
        "feedback_signal": "CONTINUE_SIGNAL",
        "improvement_area": improvement_area,
        "blockers": list(blockers),
        "timestamp_reference": "ref",
        "source_export": {},
        "research_only": True,
    }
    record.update(over)
    return record


def plans(records):
    history = rha.aggregate_research_history(records)
    patterns = rpd.detect_research_patterns(records)
    return history, patterns


class TestMemoryExport(unittest.TestCase):
    def test_ready_with_history_and_patterns(self):
        history, patterns = plans([snapshot("IN_PROGRESS", "VERSION")])
        export = rme.export_research_memory(history, patterns)
        self.assertTrue(export["ready"])
        self.assertEqual(export["rule_version"], "r32-4")
        self.assertEqual(export["limitations"],
                         ["SINGLE_RECORD_HISTORY",
                          "PATTERN_LOW_CONFIDENCE"])
        self.assertEqual(export["history"]["total_records"], 1)
        self.assertEqual(export["patterns"]["dominant_pattern"],
                         "VERSION_LIMITED")

    def test_no_history_not_ready(self):
        export = rme.export_research_memory()
        self.assertFalse(export["ready"])
        self.assertIn(schema.LIMITATION_NO_HISTORY,
                      export["limitations"])

    def test_empty_history_plan_not_ready(self):
        history, patterns = plans([])
        export = rme.export_research_memory(history, patterns)
        self.assertFalse(export["ready"])
        self.assertIn(schema.LIMITATION_NO_HISTORY,
                      export["limitations"])
        self.assertIn(schema.LIMITATION_PATTERN_LOW_CONFIDENCE,
                      export["limitations"])

    def test_single_record_limitation(self):
        history, patterns = plans([snapshot("COMPLETED", "NONE")])
        export = rme.export_research_memory(history, patterns)
        self.assertTrue(export["ready"])
        self.assertIn(schema.LIMITATION_SINGLE_RECORD,
                      export["limitations"])

    def test_recurring_blockers_limitation(self):
        records = [
            snapshot(blockers=["VERSION_EVIDENCE_MISSING"]),
            snapshot(blockers=["VERSION_EVIDENCE_MISSING"]),
        ]
        history, patterns = plans(records)
        export = rme.export_research_memory(history, patterns)
        self.assertTrue(export["ready"])
        self.assertIn(schema.LIMITATION_RECURRING_BLOCKERS,
                      export["limitations"])
        self.assertNotIn(schema.LIMITATION_SINGLE_RECORD,
                         export["limitations"])

    def test_high_confidence_pattern_no_low_confidence_limitation(self):
        records = [snapshot(improvement_area="VERSION")] * 3
        history, patterns = plans(records)
        export = rme.export_research_memory(history, patterns)
        self.assertEqual(patterns["confidence"], "HIGH")
        self.assertNotIn(schema.LIMITATION_PATTERN_LOW_CONFIDENCE,
                         export["limitations"])

    def test_missing_inputs_not_ready(self):
        for history, patterns in (
            (None, None), ({}, {}), ("x", 0), ([], "y"),
        ):
            export = rme.export_research_memory(history, patterns)
            self.assertFalse(export["ready"],
                             repr((history, patterns)))
            self.assertEqual(export["limitations"][0],
                             schema.LIMITATION_NO_HISTORY)
            self.assertIn(schema.LIMITATION_PATTERN_LOW_CONFIDENCE,
                          export["limitations"])

    def test_history_without_pattern_plan_not_ready(self):
        history, _ = plans([snapshot()])
        export = rme.export_research_memory(history)
        self.assertFalse(export["ready"])

    def test_deterministic_output(self):
        history, patterns = plans(
            [snapshot(), snapshot(improvement_area="PATH")]
        )
        first = rme.export_research_memory(history, patterns)
        second = rme.export_research_memory(history, patterns)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        history, patterns = plans([snapshot()])
        history_before = copy.deepcopy(history)
        patterns_before = copy.deepcopy(patterns)
        rme.export_research_memory(history, patterns)
        self.assertEqual(history, history_before)
        self.assertEqual(patterns, patterns_before)

    def test_embedded_snapshots_do_not_alias_inputs(self):
        history, patterns = plans([snapshot()])
        export = rme.export_research_memory(history, patterns)
        export["history"]["total_records"] = 99
        export["patterns"]["dominant_pattern"] = "NO_PATTERN"
        self.assertEqual(history["total_records"], 1)
        self.assertEqual(patterns["dominant_pattern"], "VERSION_LIMITED")

    def test_json_serializable(self):
        history, patterns = plans([snapshot()])
        export = rme.export_research_memory(history, patterns)
        self.assertIsInstance(json.loads(json.dumps(export)), dict)

    def test_research_only_always_true(self):
        history, patterns = plans([snapshot()])
        for export in (
            rme.export_research_memory(history, patterns),
            rme.export_research_memory(),
        ):
            self.assertIs(export["research_only"], True)

    def test_no_operational_attack_content(self):
        history, patterns = plans([snapshot()])
        blob = json.dumps(
            rme.export_research_memory(history, patterns)
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_limitation_vocabulary_is_closed(self):
        self.assertEqual(
            set(schema.LIMITATION_CODES),
            {
                "NO_HISTORY", "SINGLE_RECORD_HISTORY",
                "PATTERN_LOW_CONFIDENCE", "RECURRING_BLOCKERS_PRESENT",
            },
        )

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchMemoryExportPlan(
                ready=True, limitations=["DEPLOY_EXPLOIT"]
            )
        with self.assertRaises(ValidationError):
            schema.ResearchMemoryExportPlan(
                ready=True, severity="CRITICAL"
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchMemoryExportPlan(
            rule_version="r99-9", ready=False, research_only=True
        )
        self.assertEqual(plan.rule_version, "r32-4")
        with self.assertRaises(ValidationError):
            schema.ResearchMemoryExportPlan(
                ready=False, research_only=False
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rme.RESEARCH_MEMORY_EXPORTER_RULE_VERSION, "r32-4"
        )
        export = rme.export_research_memory()
        self.assertEqual(export["rule_version"], "r32-4")

    def test_limitations_are_bounded_and_deduplicated(self):
        plan = schema.ResearchMemoryExportPlan(
            ready=False,
            limitations=[schema.LIMITATION_NO_HISTORY] * 64,
        )
        self.assertEqual(plan.limitations,
                         [schema.LIMITATION_NO_HISTORY])


if __name__ == "__main__":
    unittest.main(verbosity=2)
