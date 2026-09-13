"""tests/test_agent_coordination_planner.py — Stage R35.3 tests.

Deterministic, offline tests for the agent coordination planner:

- deterministic output
- every coordination mode (SEQUENTIAL / REVIEW_GATE / STOPPED / UNKNOWN)
- mode precedence
- role sequence, dependencies and handoff points
- invalid input and empty strategy
- no mutation, JSON serialization, vocabulary validation
- research_only always true, no operational execution content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import agent_coordination_planner as acp
from ai.schemas import agent_coordination as schema


def strategy(strategy_type="VERSION_FIRST"):
    return {
        "rule_version": "r34-1",
        "strategy_type": strategy_type,
        "strategy_reason": "VERSION_LIMITATION_DOMINANT",
        "historical_basis": "VERSION_LIMITATION",
        "confidence_level": "HIGH",
        "blockers": [],
        "research_only": True,
    }


def role_plan(roles=("VERSION_ANALYSIS", "EVIDENCE_ANALYSIS")):
    return {
        "rule_version": "r35-1",
        "required_roles": list(roles),
        "primary_role": roles[0],
        "role_reason": "VERSION_STRATEGY",
        "confidence_level": "HIGH",
        "research_only": True,
    }


def budget(state="CONTINUE"):
    return {
        "rule_version": "r34-3",
        "budget_state": state,
        "reason": "HIGH_CONFIDENCE_SUCCESS",
        "allowed_next_step": "MORE_EVIDENCE",
        "research_only": True,
    }


class TestCoordinationModes(unittest.TestCase):
    def test_sequential_mode(self):
        coordination = acp.plan_agent_coordination(
            strategy("VERSION_FIRST"), role_plan(), {}, budget("CONTINUE")
        )
        self.assertEqual(coordination["coordination_mode"], "SEQUENTIAL")
        self.assertEqual(
            coordination["role_sequence"],
            ["VERSION_ANALYSIS", "EVIDENCE_ANALYSIS"],
        )
        self.assertEqual(
            coordination["dependencies"],
            [
                {"role": "EVIDENCE_ANALYSIS",
                 "depends_on": "VERSION_ANALYSIS"},
            ],
        )
        self.assertEqual(
            coordination["handoff_points"],
            [{"from": "VERSION_ANALYSIS", "to": "EVIDENCE_ANALYSIS"}],
        )

    def test_review_gate_mode(self):
        coordination = acp.plan_agent_coordination(
            strategy("DEFERRED"),
            role_plan(("HUMAN_REVIEW",)),
            {},
            budget("STOP"),
        )
        self.assertEqual(coordination["coordination_mode"],
                         "REVIEW_GATE")
        self.assertEqual(coordination["role_sequence"], ["HUMAN_REVIEW"])

    def test_stopped_mode(self):
        coordination = acp.plan_agent_coordination(
            strategy("VERSION_FIRST"), role_plan(), {}, budget("STOP")
        )
        self.assertEqual(coordination["coordination_mode"], "STOPPED")

    def test_unknown_mode_for_unknown_strategy(self):
        coordination = acp.plan_agent_coordination(
            strategy("UNKNOWN"),
            role_plan(("HISTORY_ANALYSIS",)),
            {},
            budget("UNKNOWN"),
        )
        self.assertEqual(coordination["coordination_mode"], "UNKNOWN")

    def test_unknown_mode_for_missing_strategy(self):
        coordination = acp.plan_agent_coordination()
        self.assertEqual(coordination["coordination_mode"], "UNKNOWN")
        self.assertEqual(coordination["role_sequence"], [])
        self.assertEqual(coordination["dependencies"], [])
        self.assertEqual(coordination["handoff_points"], [])

    def test_unknown_mode_for_missing_roles(self):
        coordination = acp.plan_agent_coordination(
            strategy("VERSION_FIRST"), {}, {}, budget("CONTINUE")
        )
        self.assertEqual(coordination["coordination_mode"], "UNKNOWN")

    def test_review_gate_beats_stopped_budget(self):
        coordination = acp.plan_agent_coordination(
            strategy("DEFERRED"),
            role_plan(("HUMAN_REVIEW",)),
            {},
            budget("STOP"),
        )
        self.assertNotEqual(coordination["coordination_mode"], "STOPPED")

    def test_dependencies_chain_for_three_roles(self):
        coordination = acp.plan_agent_coordination(
            strategy("IDENTITY_FIRST"),
            role_plan(("ASSET_ANALYSIS", "IDENTITY_ANALYSIS",
                       "EVIDENCE_ANALYSIS")),
            {},
            budget("LIMITED"),
        )
        self.assertEqual(len(coordination["dependencies"]), 2)
        self.assertEqual(len(coordination["handoff_points"]), 2)
        self.assertEqual(
            coordination["dependencies"][1],
            {"role": "EVIDENCE_ANALYSIS",
             "depends_on": "IDENTITY_ANALYSIS"},
        )

    def test_malformed_roles_are_filtered(self):
        coordination = acp.plan_agent_coordination(
            strategy("VERSION_FIRST"),
            {"required_roles": ["NOPE", "VERSION_ANALYSIS", None]},
            {},
            budget("CONTINUE"),
        )
        self.assertEqual(coordination["role_sequence"],
                         ["VERSION_ANALYSIS"])
        self.assertEqual(coordination["coordination_mode"], "SEQUENTIAL")

    def test_deterministic_output(self):
        args = (
            strategy("VERSION_FIRST"), role_plan(), {}, budget("CONTINUE"),
        )
        first = acp.plan_agent_coordination(*args)
        second = acp.plan_agent_coordination(*args)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        inputs = (
            strategy("VERSION_FIRST"), role_plan(), {}, budget("CONTINUE"),
        )
        snapshots = tuple(copy.deepcopy(value) for value in inputs)
        acp.plan_agent_coordination(*inputs)
        for before, after in zip(snapshots, inputs):
            self.assertEqual(before, after)

    def test_json_serializable(self):
        coordination = acp.plan_agent_coordination()
        self.assertIsInstance(json.loads(json.dumps(coordination)), dict)

    def test_research_only_always_true(self):
        for args in (
            (None, None, None, None),
            (strategy("VERSION_FIRST"), role_plan(), {}, budget()),
        ):
            coordination = acp.plan_agent_coordination(*args)
            self.assertIs(coordination["research_only"], True)

    def test_no_operational_execution_content(self):
        blob = json.dumps(
            acp.plan_agent_coordination(
                strategy("VERSION_FIRST"), role_plan(), {},
                budget("CONTINUE"),
            )
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body", "dispatch",
            "worker", "scheduler", "execute",
        ):
            self.assertNotIn(marker, blob)

    def test_mode_vocabulary_is_closed(self):
        self.assertEqual(
            set(schema.COORDINATION_MODES),
            {"SEQUENTIAL", "REVIEW_GATE", "STOPPED", "UNKNOWN"},
        )

    def test_schema_rejects_bad_values(self):
        base = {
            "coordination_mode": "SEQUENTIAL",
            "role_sequence": ["VERSION_ANALYSIS"],
            "dependencies": [],
            "handoff_points": [],
        }
        for key, value in (
            ("coordination_mode", "ORCHESTRATE"),
            ("role_sequence", ["RUN_SCAN"]),
            ("dependencies", [{"role": "NOPE",
                               "depends_on": "VERSION_ANALYSIS"}]),
            ("handoff_points", [{"from": "VERSION_ANALYSIS",
                                 "to": "NOPE"}]),
        ):
            with self.assertRaises(ValidationError):
                schema.AgentCoordinationPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.AgentCoordinationPlan(**base, severity="HIGH")

    def test_schema_rejects_self_dependency(self):
        with self.assertRaises(ValidationError):
            schema.AgentCoordinationPlan(
                coordination_mode="SEQUENTIAL",
                role_sequence=["VERSION_ANALYSIS"],
                dependencies=[{"role": "VERSION_ANALYSIS",
                               "depends_on": "VERSION_ANALYSIS"}],
                handoff_points=[],
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.AgentCoordinationPlan(
            rule_version="r99-9",
            coordination_mode="UNKNOWN",
            role_sequence=[],
            dependencies=[],
            handoff_points=[],
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r35-3")
        with self.assertRaises(ValidationError):
            schema.AgentCoordinationPlan(
                coordination_mode="UNKNOWN",
                role_sequence=[],
                dependencies=[],
                handoff_points=[],
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            acp.AGENT_COORDINATION_PLANNER_RULE_VERSION, "r35-3"
        )
        coordination = acp.plan_agent_coordination()
        self.assertEqual(coordination["rule_version"], "r35-3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
