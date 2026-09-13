"""tests/test_research_efficiency.py — Stage R33.3 tests.

Deterministic, offline tests for the research efficiency planner:

- deterministic output
- empty history -> UNKNOWN / INSUFFICIENT_HISTORY
- HIGH / MEDIUM / LOW efficiency states
- improvement signals
- ratios bounded and rounded
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

from ai.knowledge import research_efficiency as reff
from ai.schemas import research_efficiency as schema


def history(total=0, successful=0, deferred=0, waiting=0,
            recurring_blockers=(), **over):
    plan = {
        "rule_version": "r32-2",
        "total_records": total,
        "successful_count": successful,
        "deferred_count": deferred,
        "waiting_count": waiting,
        "recurring_blockers": list(recurring_blockers),
        "recurring_improvement_areas": [],
        "research_patterns": [],
        "research_only": True,
    }
    plan.update(over)
    return plan


class TestResearchEfficiency(unittest.TestCase):
    def test_empty_history(self):
        for value in (None, {}, [], "x"):
            result = reff.evaluate_research_efficiency(value)
            self.assertEqual(result["efficiency_state"], "UNKNOWN")
            self.assertEqual(result["improvement_signal"],
                             "INSUFFICIENT_HISTORY")
            self.assertEqual(result["successful_ratio"], 0.0)
            self.assertEqual(result["evidence_gap_ratio"], 0.0)
            self.assertEqual(result["recurring_blocker_ratio"], 0.0)

    def test_high_efficiency(self):
        result = reff.evaluate_research_efficiency(
            history(total=4, successful=3, waiting=1)
        )
        self.assertEqual(result["efficiency_state"], "HIGH")
        self.assertEqual(result["successful_ratio"], 0.75)
        self.assertEqual(result["evidence_gap_ratio"], 0.25)
        self.assertEqual(result["improvement_signal"], "NONE")

    def test_medium_efficiency(self):
        result = reff.evaluate_research_efficiency(
            history(total=4, successful=1, deferred=3)
        )
        self.assertEqual(result["efficiency_state"], "MEDIUM")
        self.assertEqual(result["successful_ratio"], 0.25)

    def test_low_efficiency_success_ratio(self):
        result = reff.evaluate_research_efficiency(
            history(total=10, successful=1, deferred=9)
        )
        self.assertEqual(result["efficiency_state"], "LOW")
        self.assertEqual(result["improvement_signal"],
                         "INCREASE_SUCCESSFUL_RESEARCH")

    def test_low_efficiency_evidence_gap(self):
        result = reff.evaluate_research_efficiency(
            history(total=4, successful=2, waiting=2)
        )
        self.assertEqual(result["efficiency_state"], "LOW")
        self.assertEqual(result["improvement_signal"],
                         "CLOSE_EVIDENCE_GAPS")

    def test_recurring_blocker_signal(self):
        result = reff.evaluate_research_efficiency(
            history(total=4, successful=2, waiting=2,
                    recurring_blockers=["VERSION_EVIDENCE_MISSING"])
        )
        self.assertEqual(result["recurring_blocker_ratio"], 0.25)
        self.assertEqual(result["improvement_signal"],
                         "REDUCE_RECURRING_BLOCKERS")

    def test_recurring_blocker_density_blocks_high(self):
        result = reff.evaluate_research_efficiency(
            history(total=4, successful=3,
                    recurring_blockers=["VERSION_EVIDENCE_MISSING"])
        )
        self.assertNotEqual(result["efficiency_state"], "HIGH")

    def test_ratios_are_bounded_and_rounded(self):
        result = reff.evaluate_research_efficiency(
            history(total=3, successful=1, waiting=1,
                    recurring_blockers=["A", "B"])
        )
        self.assertEqual(result["successful_ratio"], 0.3333)
        self.assertEqual(result["recurring_blocker_ratio"], 0.6667)
        for key in (
            "successful_ratio", "evidence_gap_ratio",
            "recurring_blocker_ratio",
        ):
            self.assertGreaterEqual(result[key], 0.0)
            self.assertLessEqual(result[key], 1.0)

    def test_memory_export_fallback(self):
        export = {"history": history(total=2, successful=2)}
        result = reff.evaluate_research_efficiency(
            None, memory_export=export
        )
        self.assertEqual(result["efficiency_state"], "HIGH")

    def test_malformed_counts_degrade_to_zero(self):
        result = reff.evaluate_research_efficiency(
            {"total_records": "bad", "successful_count": None,
             "waiting_count": [], "recurring_blockers": "nope"}
        )
        self.assertEqual(result["efficiency_state"], "UNKNOWN")

    def test_deterministic_output(self):
        plan = history(total=4, successful=1, deferred=3)
        first = reff.evaluate_research_efficiency(plan)
        second = reff.evaluate_research_efficiency(plan)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        plan = history(total=2, successful=1)
        before = copy.deepcopy(plan)
        reff.evaluate_research_efficiency(plan)
        self.assertEqual(plan, before)

    def test_json_serializable(self):
        result = reff.evaluate_research_efficiency(history(total=1))
        self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_research_only_always_true(self):
        for value in (None, history(total=1, successful=1)):
            result = reff.evaluate_research_efficiency(value)
            self.assertIs(result["research_only"], True)

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            reff.evaluate_research_efficiency(
                history(total=4, successful=2)
            )
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchEfficiencyPlan(
                efficiency_state="GREAT", improvement_signal="NONE"
            )
        with self.assertRaises(ValidationError):
            schema.ResearchEfficiencyPlan(
                efficiency_state="HIGH", improvement_signal="WIN"
            )
        with self.assertRaises(ValidationError):
            schema.ResearchEfficiencyPlan(
                efficiency_state="HIGH", improvement_signal="NONE",
                severity="HIGH",
            )

    def test_schema_clamps_ratios(self):
        plan = schema.ResearchEfficiencyPlan(
            efficiency_state="HIGH",
            improvement_signal="NONE",
            successful_ratio=5.0,
            evidence_gap_ratio=-2.0,
        )
        self.assertEqual(plan.successful_ratio, 1.0)
        self.assertEqual(plan.evidence_gap_ratio, 0.0)

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchEfficiencyPlan(
            rule_version="r99-9",
            efficiency_state="UNKNOWN",
            improvement_signal="INSUFFICIENT_HISTORY",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r33-3")
        with self.assertRaises(ValidationError):
            schema.ResearchEfficiencyPlan(
                efficiency_state="UNKNOWN",
                improvement_signal="INSUFFICIENT_HISTORY",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            reff.RESEARCH_EFFICIENCY_PLANNER_RULE_VERSION, "r33-3"
        )
        result = reff.evaluate_research_efficiency()
        self.assertEqual(result["rule_version"], "r33-3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
