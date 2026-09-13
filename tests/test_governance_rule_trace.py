"""tests/test_governance_rule_trace.py — Stage R37.2 tests.

Deterministic, offline tests for the governance rule trace builder:

- rule mapping per authorization decision
- explicit precedence order
- trace states (COMPLETE / PARTIAL / UNKNOWN)
- conservative scope rule
- malformed and empty input handling
- no mutation, JSON serialization, closed vocabulary validation
- research_only always true, no execution content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.governance_rule_trace_builder import (
    build_governance_rule_trace,
)
from ai.schemas import governance_rule_trace as schema


def policy(value="RESEARCH_ONLY"):
    return {
        "rule_version": "r36-1",
        "policy": value,
        "policy_reason": "X",
        "constraints": [],
        "research_only": True,
    }


def authorization(decision="ALLOW_WITH_LIMITS"):
    return {
        "rule_version": "r36-2",
        "decision": decision,
        "decision_reason": "X",
        "policy": "RESEARCH_ONLY",
        "limitations": [],
        "source_strategy": {},
        "source_orchestration": {},
        "research_only": True,
    }


def scope(value="COMPONENT_SCOPED"):
    return {
        "rule_version": "r36-3",
        "capability": "VERSION_ANALYSIS",
        "agent_role": "VERSION_ANALYSIS",
        "scope": value,
        "scope_certainty": "HIGH",
        "authorized": True,
        "source_strategy": "VERSION_FIRST",
        "constraints": [],
        "research_only": True,
    }


def trace(decision="ALLOW_WITH_LIMITS", policy_value="RESEARCH_ONLY",
          scope_value="COMPONENT_SCOPED"):
    return build_governance_rule_trace(
        policy(policy_value),
        authorization(decision),
        scope(scope_value),
        {},
        {},
        {},
    )


class TestGovernanceRuleTrace(unittest.TestCase):
    def test_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.GOVERNANCE_RULES),
            {
                "CONTEXT_VALIDATION_FIRST", "POLICY_BLOCK_TERMINAL",
                "HUMAN_APPROVAL_MANDATORY", "RESEARCH_ONLY_LIMIT",
                "PASSIVE_ONLY_LIMIT", "ACTIVE_ALLOWED_VALID",
                "SCOPE_GATE", "SCOPE_UNKNOWN_CONSERVATIVE",
                "APPROVAL_GATE", "RISK_NOT_PERMISSION",
                "BOUNDARY_PRECEDENCE", "UNKNOWN_CONTEXT",
            },
        )

    def test_every_decision_trace(self):
        expectations = (
            ("ALLOW", "ACTIVE_ALLOWED_VALID"),
            ("ALLOW_WITH_LIMITS", "RESEARCH_ONLY_LIMIT"),
            ("REQUIRE_HUMAN_APPROVAL", "HUMAN_APPROVAL_MANDATORY"),
            ("BLOCK", "POLICY_BLOCK_TERMINAL"),
        )
        for decision, first_rule in expectations:
            plan = trace(decision)
            self.assertEqual(plan["trace_state"], "COMPLETE", decision)
            self.assertIn(first_rule, plan["applied_rules"], decision)

    def test_research_only_maps_to_research_rule(self):
        plan = trace("ALLOW_WITH_LIMITS", "RESEARCH_ONLY")
        self.assertIn("RESEARCH_ONLY_LIMIT", plan["applied_rules"])
        self.assertNotIn("RESEARCH_ONLY_LIMIT", plan["rejected_rules"])

    def test_passive_only_maps_to_passive_rule(self):
        plan = trace("ALLOW_WITH_LIMITS", "PASSIVE_ONLY")
        self.assertIn("PASSIVE_ONLY_LIMIT", plan["applied_rules"])

    def test_rejected_rules_are_explicit(self):
        plan = trace("BLOCK")
        self.assertIn("POLICY_BLOCK_TERMINAL", plan["applied_rules"])
        for rule in (
            "HUMAN_APPROVAL_MANDATORY", "RESEARCH_ONLY_LIMIT",
            "PASSIVE_ONLY_LIMIT", "ACTIVE_ALLOWED_VALID",
        ):
            self.assertIn(rule, plan["rejected_rules"], rule)

    def test_precedence_order_is_fixed(self):
        plan = trace("ALLOW")
        self.assertEqual(
            plan["precedence_order"], list(schema.PRECEDENCE_ORDER)
        )
        self.assertEqual(
            plan["precedence_order"][0], "CONTEXT_VALIDATION_FIRST"
        )

    def test_scope_unknown_conservative_rule(self):
        plan = trace(scope_value="UNKNOWN")
        self.assertEqual(
            plan["applied_rules"][0], "SCOPE_UNKNOWN_CONSERVATIVE"
        )

    def test_partial_trace_state(self):
        plan = build_governance_rule_trace(
            policy("RESEARCH_ONLY"), None, scope(), {}, {}, {}
        )
        self.assertEqual(plan["trace_state"], "PARTIAL")

    def test_unknown_trace_state(self):
        plan = build_governance_rule_trace()
        self.assertEqual(plan["trace_state"], "UNKNOWN")
        self.assertEqual(plan["applied_rules"], ["CONTEXT_VALIDATION_FIRST"])

    def test_malformed_inputs(self):
        for value in (None, {}, [], "x"):
            plan = build_governance_rule_trace(
                value, value, value, value, value, value
            )
            self.assertEqual(plan["trace_state"], "UNKNOWN", repr(value))

    def test_deterministic_output(self):
        first = trace()
        second = trace()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        inputs = (
            policy(), authorization(), scope(), {}, {}, {},
        )
        snapshots = tuple(copy.deepcopy(value) for value in inputs)
        build_governance_rule_trace(*inputs)
        for before, after in zip(snapshots, inputs):
            self.assertEqual(before, after)

    def test_json_serializable(self):
        self.assertIsInstance(json.loads(json.dumps(trace())), dict)

    def test_research_only_always_true(self):
        self.assertIs(trace()["research_only"], True)
        self.assertIs(
            build_governance_rule_trace()["research_only"], True
        )

    def test_schema_rejects_bad_values(self):
        base = {
            "applied_rules": ["RESEARCH_ONLY_LIMIT"],
            "rejected_rules": ["ACTIVE_ALLOWED_VALID"],
            "precedence_order": list(schema.PRECEDENCE_ORDER),
            "trace_state": "COMPLETE",
        }
        for key, value in (
            ("applied_rules", ["RUN_SCAN"]),
            ("rejected_rules", ["RUN_NUCLEI"]),
            ("precedence_order", ["EXECUTE"]),
            ("trace_state", "MAYBE"),
        ):
            with self.assertRaises(ValidationError):
                schema.GovernanceRuleTracePlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.GovernanceRuleTracePlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.GovernanceRuleTracePlan(
            rule_version="r99-9",
            trace_state="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r37-2")
        with self.assertRaises(ValidationError):
            schema.GovernanceRuleTracePlan(
                trace_state="UNKNOWN", research_only=False
            )

    def test_exact_rule_version(self):
        self.assertEqual(schema.GOVERNANCE_RULE_TRACE_RULE_VERSION,
                         "r37-2")
        self.assertEqual(trace()["rule_version"], "r37-2")

    def test_no_execution_content(self):
        blob = json.dumps(
            [trace(decision) for decision in (
                "ALLOW", "ALLOW_WITH_LIMITS", "REQUIRE_HUMAN_APPROVAL",
                "BLOCK", "UNKNOWN",
            )]
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
        ):
            self.assertNotIn(marker, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
