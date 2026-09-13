"""tests/test_research_path_selector.py — Stage R34.2 tests.

Deterministic, offline tests for the research path selector:

- deterministic output
- every strategy -> path branch
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

from ai.knowledge import research_path_selector as rps
from ai.schemas import research_path as schema


def strategy(strategy_type="UNKNOWN", confidence="UNKNOWN"):
    return {
        "rule_version": "r34-1",
        "strategy_type": strategy_type,
        "strategy_reason": "MALFORMED_INPUT",
        "historical_basis": "MALFORMED_INPUT",
        "confidence_level": confidence,
        "blockers": [],
        "research_only": True,
    }


class TestPathBranches(unittest.TestCase):
    def test_every_strategy_maps(self):
        expectations = (
            ("EVIDENCE_FIRST",
             ["COLLECT_EVIDENCE", "REVIEW_HISTORY"],
             "COLLECT_EVIDENCE", "EVIDENCE_STRATEGY"),
            ("IDENTITY_FIRST",
             ["IDENTIFY_ASSET", "COLLECT_EVIDENCE"],
             "IDENTIFY_ASSET", "IDENTITY_STRATEGY"),
            ("TECHNOLOGY_FIRST",
             ["VERIFY_TECHNOLOGY", "COLLECT_EVIDENCE"],
             "VERIFY_TECHNOLOGY", "TECHNOLOGY_STRATEGY"),
            ("VERSION_FIRST",
             ["VERIFY_VERSION", "COLLECT_EVIDENCE"],
             "VERIFY_VERSION", "VERSION_STRATEGY"),
            ("SCOPE_FIRST",
             ["VERIFY_SCOPE", "COLLECT_EVIDENCE"],
             "VERIFY_SCOPE", "SCOPE_STRATEGY"),
            ("HUMAN_REVIEW_FIRST",
             ["HUMAN_REVIEW"], "HUMAN_REVIEW",
             "HUMAN_REVIEW_STRATEGY"),
            ("DEFERRED", ["STOP"], "STOP", "DEFERRED_STRATEGY"),
            ("UNKNOWN",
             ["REVIEW_HISTORY"], "REVIEW_HISTORY", "UNKNOWN_STRATEGY"),
        )
        for strategy_type, steps, primary, reason in expectations:
            path = rps.select_research_path(
                strategy(strategy_type, "HIGH")
            )
            self.assertEqual(path["selected_path"], steps, strategy_type)
            self.assertEqual(path["primary_path"], primary, strategy_type)
            self.assertEqual(path["path_reason"], reason, strategy_type)
            self.assertEqual(path["confidence_level"], "HIGH")

    def test_deferred_path_is_stop_only(self):
        path = rps.select_research_path(strategy("DEFERRED", "MEDIUM"))
        self.assertEqual(path["selected_path"], ["STOP"])
        self.assertEqual(path["primary_path"], "STOP")

    def test_confidence_passthrough(self):
        for confidence in ("HIGH", "MEDIUM", "LOW"):
            path = rps.select_research_path(
                strategy("VERSION_FIRST", confidence)
            )
            self.assertEqual(path["confidence_level"], confidence)

    def test_invalid_confidence_defaults_unknown(self):
        path = rps.select_research_path(
            strategy("VERSION_FIRST", "CERTAIN")
        )
        self.assertEqual(path["confidence_level"], "UNKNOWN")

    def test_malformed_input(self):
        for value in (None, {}, [], "x", 0):
            path = rps.select_research_path(value)
            self.assertEqual(path["selected_path"], ["REVIEW_HISTORY"],
                             repr(value))
            self.assertEqual(path["primary_path"], "REVIEW_HISTORY")
            self.assertEqual(path["path_reason"], "UNKNOWN_STRATEGY")
            self.assertEqual(path["confidence_level"], "UNKNOWN")

    def test_unrecognized_strategy_type(self):
        path = rps.select_research_path(
            {"strategy_type": "WIN_FIRST", "confidence_level": "HIGH"}
        )
        self.assertEqual(path["path_reason"], "UNKNOWN_STRATEGY")
        self.assertEqual(path["selected_path"], ["REVIEW_HISTORY"])

    def test_deterministic_output(self):
        plan = strategy("IDENTITY_FIRST", "HIGH")
        first = rps.select_research_path(plan)
        second = rps.select_research_path(plan)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        plan = strategy("TECHNOLOGY_FIRST", "MEDIUM")
        before = copy.deepcopy(plan)
        rps.select_research_path(plan)
        self.assertEqual(plan, before)

    def test_json_serializable(self):
        path = rps.select_research_path(strategy("DEFERRED", "LOW"))
        self.assertIsInstance(json.loads(json.dumps(path)), dict)

    def test_research_only_always_true(self):
        for value in (None, strategy("EVIDENCE_FIRST", "HIGH")):
            path = rps.select_research_path(value)
            self.assertIs(path["research_only"], True)

    def test_path_steps_are_closed_and_ordered(self):
        path = rps.select_research_path(strategy("EVIDENCE_FIRST", "HIGH"))
        self.assertEqual(path["primary_path"], path["selected_path"][0])
        for step in path["selected_path"]:
            self.assertIn(step, schema.PATH_STEPS)

    def test_no_operational_attack_content(self):
        blob = json.dumps(
            [
                rps.select_research_path(strategy(name, "HIGH"))
                for name in (
                    "EVIDENCE_FIRST", "IDENTITY_FIRST",
                    "TECHNOLOGY_FIRST", "VERSION_FIRST", "SCOPE_FIRST",
                    "HUMAN_REVIEW_FIRST", "DEFERRED", "UNKNOWN",
                )
            ]
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        base = {
            "selected_path": ["COLLECT_EVIDENCE"],
            "primary_path": "COLLECT_EVIDENCE",
            "path_reason": "EVIDENCE_STRATEGY",
            "confidence_level": "HIGH",
        }
        for key, value in (
            ("selected_path", ["EXECUTE_SCAN"]),
            ("primary_path", "RUN_NUCLEI"),
            ("path_reason", "BECAUSE"),
            ("confidence_level", "CERTAIN"),
        ):
            with self.assertRaises(ValidationError):
                schema.ResearchPathPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.ResearchPathPlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchPathPlan(
            rule_version="r99-9",
            selected_path=["STOP"],
            primary_path="STOP",
            path_reason="UNKNOWN_STRATEGY",
            confidence_level="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r34-2")
        with self.assertRaises(ValidationError):
            schema.ResearchPathPlan(
                selected_path=["STOP"],
                primary_path="STOP",
                path_reason="UNKNOWN_STRATEGY",
                confidence_level="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rps.RESEARCH_PATH_SELECTOR_RULE_VERSION, "r34-2"
        )
        path = rps.select_research_path()
        self.assertEqual(path["rule_version"], "r34-2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
