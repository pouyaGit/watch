"""tests/test_research_strategy_export.py — Stage R34.4 tests.

Deterministic, offline tests for the research strategy exporter:

- deterministic output
- ready requires all three R34 plans to be valid
- limitation mappings
- malformed input handling
- no input mutation, JSON serialization, vocabulary validation
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

from ai.knowledge import research_strategy_export as rse
from ai.schemas import research_strategy_export as schema


def strategy(strategy_type="VERSION_FIRST", confidence="HIGH",
             reason="VERSION_LIMITATION_DOMINANT",
             basis="VERSION_LIMITATION"):
    return {
        "rule_version": "r34-1",
        "strategy_type": strategy_type,
        "strategy_reason": reason,
        "historical_basis": basis,
        "confidence_level": confidence,
        "blockers": [],
        "research_only": True,
    }


def path(primary="VERIFY_VERSION", reason="VERSION_STRATEGY",
         confidence="HIGH"):
    return {
        "rule_version": "r34-2",
        "selected_path": [primary, "COLLECT_EVIDENCE"],
        "primary_path": primary,
        "path_reason": reason,
        "confidence_level": confidence,
        "research_only": True,
    }


def budget(state="CONTINUE", reason="HIGH_CONFIDENCE_SUCCESS",
           step="MORE_EVIDENCE"):
    return {
        "rule_version": "r34-3",
        "budget_state": state,
        "reason": reason,
        "allowed_next_step": step,
        "research_only": True,
    }


class TestStrategyExport(unittest.TestCase):
    def test_ready_when_all_valid(self):
        export = rse.export_research_strategy(
            strategy(), path(), budget()
        )
        self.assertTrue(export["ready"])
        self.assertEqual(export["rule_version"], "r34-4")
        self.assertEqual(export["strategy"]["strategy_type"],
                         "VERSION_FIRST")
        self.assertEqual(export["path"]["primary_path"],
                         "VERIFY_VERSION")
        self.assertEqual(export["budget"]["budget_state"], "CONTINUE")
        self.assertEqual(export["limitations"], [])

    def test_not_ready_when_any_plan_missing(self):
        valid_strategy = strategy()
        valid_path = path()
        valid_budget = budget()
        for combo in (
            (None, valid_path, valid_budget),
            (valid_strategy, None, valid_budget),
            (valid_strategy, valid_path, None),
            (None, None, None),
        ):
            export = rse.export_research_strategy(*combo)
            self.assertFalse(export["ready"], repr(combo))

    def test_not_ready_when_plan_malformed(self):
        export = rse.export_research_strategy(
            {"strategy_type": "NOPE"},
            {"primary_path": "RUN"},
            {"budget_state": "SPEND"},
        )
        self.assertFalse(export["ready"])

    def test_unknown_strategy_limitation(self):
        export = rse.export_research_strategy(
            strategy("UNKNOWN", "UNKNOWN", "UNMAPPED_PATTERN",
                     "UNKNOWN_PATTERN"),
            path("REVIEW_HISTORY", "UNKNOWN_STRATEGY", "UNKNOWN"),
            budget("UNKNOWN", "UNKNOWN_CONFIDENCE", "UNKNOWN"),
        )
        self.assertIn(schema.LIMITATION_UNKNOWN_STRATEGY,
                      export["limitations"])
        self.assertIn(schema.LIMITATION_LOW_CONFIDENCE,
                      export["limitations"])
        self.assertIn(schema.LIMITATION_UNKNOWN_BUDGET,
                      export["limitations"])

    def test_deferred_limitation(self):
        export = rse.export_research_strategy(
            strategy("DEFERRED", "LOW", "DEFERRED_OUTCOME_DOMINANT",
                     "DEFERRED_OUTCOME"),
            path("STOP", "DEFERRED_STRATEGY", "LOW"),
            budget("STOP", "DEFERRED_STRATEGY", "NONE"),
        )
        self.assertIn(schema.LIMITATION_DEFERRED_STRATEGY,
                      export["limitations"])
        self.assertIn(schema.LIMITATION_LOW_CONFIDENCE,
                      export["limitations"])

    def test_repeated_blockers_limitation(self):
        export = rse.export_research_strategy(
            strategy("VERSION_FIRST", "HIGH"),
            path(),
            budget("PAUSE", "REPEATED_BLOCKERS", "HUMAN_REVIEW"),
        )
        self.assertIn(schema.LIMITATION_REPEATED_BLOCKERS,
                      export["limitations"])
        self.assertNotIn(schema.LIMITATION_LOW_CONFIDENCE,
                         export["limitations"])

    def test_limitations_are_ordered_and_deduplicated(self):
        export = rse.export_research_strategy(
            strategy("UNKNOWN", "LOW", "UNMAPPED_PATTERN",
                     "UNKNOWN_PATTERN"),
            path("REVIEW_HISTORY", "UNKNOWN_STRATEGY", "LOW"),
            budget("UNKNOWN", "UNKNOWN_CONFIDENCE", "UNKNOWN"),
        )
        self.assertEqual(
            export["limitations"],
            [
                schema.LIMITATION_UNKNOWN_STRATEGY,
                schema.LIMITATION_LOW_CONFIDENCE,
                schema.LIMITATION_UNKNOWN_BUDGET,
            ],
        )

    def test_malformed_inputs(self):
        for args in ((None, None, None), ({}, {}, {}), ("x", 0, [])):
            export = rse.export_research_strategy(*args)
            self.assertFalse(export["ready"], repr(args))
            self.assertEqual(export["limitations"],
                             [schema.LIMITATION_UNKNOWN_STRATEGY,
                              schema.LIMITATION_LOW_CONFIDENCE,
                              schema.LIMITATION_UNKNOWN_BUDGET])

    def test_deterministic_output(self):
        args = (strategy(), path(), budget())
        first = rse.export_research_strategy(*args)
        second = rse.export_research_strategy(*args)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        strategy_plan = strategy()
        path_plan = path()
        budget_plan = budget()
        snapshots = (
            copy.deepcopy(strategy_plan),
            copy.deepcopy(path_plan),
            copy.deepcopy(budget_plan),
        )
        rse.export_research_strategy(strategy_plan, path_plan, budget_plan)
        self.assertEqual(strategy_plan, snapshots[0])
        self.assertEqual(path_plan, snapshots[1])
        self.assertEqual(budget_plan, snapshots[2])

    def test_embedded_snapshots_do_not_alias_inputs(self):
        strategy_plan = strategy()
        path_plan = path()
        budget_plan = budget()
        export = rse.export_research_strategy(
            strategy_plan, path_plan, budget_plan
        )
        export["strategy"]["confidence_level"] = "UNKNOWN"
        export["path"]["selected_path"].clear()
        export["budget"]["budget_state"] = "UNKNOWN"
        self.assertEqual(strategy_plan["confidence_level"], "HIGH")
        self.assertEqual(len(path_plan["selected_path"]), 2)
        self.assertEqual(budget_plan["budget_state"], "CONTINUE")

    def test_json_serializable(self):
        export = rse.export_research_strategy(
            strategy(), path(), budget()
        )
        self.assertIsInstance(json.loads(json.dumps(export)), dict)

    def test_research_only_always_true(self):
        for export in (
            rse.export_research_strategy(),
            rse.export_research_strategy(strategy(), path(), budget()),
        ):
            self.assertIs(export["research_only"], True)

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            rse.export_research_strategy(strategy(), path(), budget())
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
                "UNKNOWN_STRATEGY", "LOW_CONFIDENCE",
                "DEFERRED_STRATEGY", "REPEATED_BLOCKERS",
                "UNKNOWN_BUDGET",
            },
        )

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchStrategyExportPlan(
                ready=True, limitations=["WIN"]
            )
        with self.assertRaises(ValidationError):
            schema.ResearchStrategyExportPlan(
                ready=True, limitations=[], severity="HIGH"
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchStrategyExportPlan(
            rule_version="r99-9",
            ready=False,
            limitations=[],
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r34-4")
        with self.assertRaises(ValidationError):
            schema.ResearchStrategyExportPlan(
                ready=False, limitations=[], research_only=False
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rse.RESEARCH_STRATEGY_EXPORTER_RULE_VERSION, "r34-4"
        )
        export = rse.export_research_strategy()
        self.assertEqual(export["rule_version"], "r34-4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
