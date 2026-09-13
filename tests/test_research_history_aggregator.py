"""tests/test_research_history_aggregator.py — Stage R32.2 tests.

Deterministic, offline tests for the research history aggregator:

- deterministic output
- empty history and multiple records
- recurring blockers / improvement areas
- structural pattern distribution
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
from ai.schemas import research_history as schema

STATUS_BY_OUTCOME = {
    "COMPLETED": "COMPLETE",
    "IN_PROGRESS": "ACTIVE",
    "WAITING_FOR_EVIDENCE": "WAITING",
    "DEFERRED": "DEFERRED",
    "UNKNOWN": "UNKNOWN",
}


def snapshot(outcome="IN_PROGRESS", improvement_area="VERSION",
             blockers=(), **over):
    record = {
        "rule_version": "r32-1",
        "candidate_identity": "rc-test",
        "research_status": STATUS_BY_OUTCOME.get(outcome, "UNKNOWN"),
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


# ---------------------------------------------------------------------------
# aggregation
# ---------------------------------------------------------------------------


class TestHistoryAggregation(unittest.TestCase):
    def test_empty_history(self):
        for value in (None, [], (), {}, [None, "", 0], [{}]):
            history = rha.aggregate_research_history(value)
            self.assertEqual(history["total_records"], 0, repr(value))
            self.assertEqual(history["successful_count"], 0)
            self.assertEqual(history["deferred_count"], 0)
            self.assertEqual(history["waiting_count"], 0)
            self.assertEqual(history["recurring_blockers"], [])
            self.assertEqual(history["recurring_improvement_areas"], [])
            self.assertEqual(history["research_patterns"], [])

    def test_multiple_records_counts(self):
        records = [
            snapshot("COMPLETED", "NONE"),
            snapshot("COMPLETED", "NONE"),
            snapshot("DEFERRED", "UNKNOWN"),
            snapshot("WAITING_FOR_EVIDENCE", "VERSION"),
            snapshot("IN_PROGRESS", "VERSION"),
        ]
        history = rha.aggregate_research_history(records)
        self.assertEqual(history["total_records"], 5)
        self.assertEqual(history["successful_count"], 2)
        self.assertEqual(history["deferred_count"], 1)
        self.assertEqual(history["waiting_count"], 1)

    def test_recurring_blockers(self):
        records = [
            snapshot(blockers=["VERSION_EVIDENCE_MISSING", "SCOPE_EVIDENCE_MISSING"]),
            snapshot(blockers=["VERSION_EVIDENCE_MISSING"]),
            snapshot(blockers=["VERSION_EVIDENCE_MISSING"]),
            snapshot(blockers=["PATH_EVIDENCE_MISSING"]),
        ]
        history = rha.aggregate_research_history(records)
        self.assertEqual(history["recurring_blockers"],
                         ["VERSION_EVIDENCE_MISSING"])

    def test_recurring_improvement_areas(self):
        records = [
            snapshot(improvement_area="VERSION"),
            snapshot(improvement_area="VERSION"),
            snapshot(improvement_area="PATH"),
            snapshot(improvement_area="NONE"),
        ]
        history = rha.aggregate_research_history(records)
        self.assertEqual(history["recurring_improvement_areas"],
                         ["VERSION"])

    def test_pattern_distribution_sorted(self):
        records = [
            snapshot(improvement_area="VERSION"),
            snapshot(improvement_area="VERSION"),
            snapshot(improvement_area="PATH"),
            snapshot(improvement_area="PATH"),
            snapshot(improvement_area="TECHNOLOGY"),
        ]
        history = rha.aggregate_research_history(records)
        self.assertEqual(
            history["research_patterns"],
            [
                {"pattern": "PATH_LIMITED", "count": 2},
                {"pattern": "VERSION_LIMITED", "count": 2},
                {"pattern": "TECHNOLOGY_LIMITED", "count": 1},
            ],
        )

    def test_count_patterns_helper(self):
        records = [
            snapshot(improvement_area="HUMAN_RESEARCH"),
            snapshot(improvement_area="HUMAN_RESEARCH"),
            snapshot(improvement_area="NONE"),
        ]
        self.assertEqual(
            rha.count_patterns(records),
            [("HUMAN_RESEARCH", 2)],
        )

    def test_single_dict_is_accepted(self):
        history = rha.aggregate_research_history(
            snapshot("COMPLETED", "NONE")
        )
        self.assertEqual(history["total_records"], 1)
        self.assertEqual(history["successful_count"], 1)

    def test_malformed_entries_are_skipped(self):
        records = [
            None, "not-a-snapshot", 0, [],
            snapshot("COMPLETED", "NONE"),
        ]
        history = rha.aggregate_research_history(records)
        self.assertEqual(history["total_records"], 1)
        self.assertEqual(history["successful_count"], 1)

    def test_malformed_fields_do_not_crash(self):
        records = [
            {"outcome": "NOPE", "improvement_area": "MONEY",
             "blockers": "not-a-list"},
            {"outcome": "IN_PROGRESS", "improvement_area": None,
             "blockers": [1, 2]},
        ]
        history = rha.aggregate_research_history(records)
        self.assertEqual(history["total_records"], 2)
        self.assertEqual(history["research_patterns"], [])

    def test_deterministic_output(self):
        records = [snapshot("COMPLETED", "NONE"), snapshot("IN_PROGRESS")]
        first = rha.aggregate_research_history(records)
        second = rha.aggregate_research_history(records)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        records = [
            snapshot(blockers=["VERSION_EVIDENCE_MISSING"]),
            snapshot(improvement_area="PATH"),
        ]
        before = copy.deepcopy(records)
        rha.aggregate_research_history(records)
        self.assertEqual(records, before)

    def test_results_do_not_alias_inputs(self):
        records = [snapshot(blockers=["VERSION_EVIDENCE_MISSING"])]
        history = rha.aggregate_research_history(records)
        history["recurring_blockers"].append("PATH_EVIDENCE_MISSING")
        self.assertEqual(records[0]["blockers"],
                         ["VERSION_EVIDENCE_MISSING"])

    def test_max_records_bound(self):
        records = [snapshot() for _ in range(schema.MAX_RECORDS + 50)]
        history = rha.aggregate_research_history(records)
        self.assertEqual(history["total_records"], schema.MAX_RECORDS)


# ---------------------------------------------------------------------------
# output shape and schema
# ---------------------------------------------------------------------------


class TestOutputShape(unittest.TestCase):
    def test_json_serializable(self):
        history = rha.aggregate_research_history([snapshot()])
        self.assertIsInstance(json.loads(json.dumps(history)), dict)

    def test_research_only_always_true(self):
        for value in (None, [snapshot()]):
            history = rha.aggregate_research_history(value)
            self.assertIs(history["research_only"], True)

    def test_no_operational_attack_content(self):
        history = rha.aggregate_research_history(
            [snapshot(), snapshot("DEFERRED", "UNKNOWN")]
        )
        blob = json.dumps(history).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchHistoryPlan(total_records=-1)
        with self.assertRaises(ValidationError):
            schema.ResearchHistoryPlan(recurring_blockers=["DEPLOY_EXPLOIT"])
        with self.assertRaises(ValidationError):
            schema.ResearchHistoryPlan(
                research_patterns=[{"pattern": "WINNER", "count": 1}]
            )
        with self.assertRaises(ValidationError):
            schema.ResearchHistoryPlan(severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchHistoryPlan(
            rule_version="r99-9", research_only=True
        )
        self.assertEqual(plan.rule_version, "r32-2")
        with self.assertRaises(ValidationError):
            schema.ResearchHistoryPlan(research_only=False)

    def test_exact_rule_version(self):
        self.assertEqual(
            rha.RESEARCH_HISTORY_AGGREGATOR_RULE_VERSION, "r32-2"
        )
        history = rha.aggregate_research_history()
        self.assertEqual(history["rule_version"], "r32-2")

    def test_bounds(self):
        blockers = [
            "VERSION_EVIDENCE_MISSING", "SCOPE_EVIDENCE_MISSING",
            "PATH_EVIDENCE_MISSING", "PARAMETER_EVIDENCE_MISSING",
            "IDENTITY_EVIDENCE_MISSING",
            "HTTP_BEHAVIOR_EVIDENCE_MISSING",
            "TECHNOLOGY_EVIDENCE_MISSING", "HUMAN_RESEARCH_REQUIRED",
            "NO_ACQUISITION_PLANNED",
        ]
        plan = schema.ResearchHistoryPlan(recurring_blockers=blockers)
        self.assertLessEqual(
            len(plan.recurring_blockers), schema.MAX_RECURRING
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
