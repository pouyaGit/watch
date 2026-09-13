"""tests/test_scope_capability_gate.py — Stage R36.3 tests.

Deterministic, offline tests for the scope/capability gate:

- capability mapping from the R35.1 role plan
- conservative scope resolution (no unrestricted inference)
- authorized flag rules
- malformed input handling
- deterministic output, no mutation, JSON serialization
- schema validation, research_only, no execution vocabulary

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.scope_capability_gate import plan_scope_capability_gate
from ai.schemas import scope_capability_gate as schema


def authorization(decision="ALLOW_WITH_LIMITS"):
    return {
        "rule_version": "r36-2",
        "decision": decision,
        "decision_reason": "RESEARCH_ONLY_LIMITS",
        "policy": "RESEARCH_ONLY",
        "limitations": [],
        "source_strategy": {"strategy_type": "VERSION_FIRST"},
        "source_orchestration": {},
        "research_only": True,
    }


def role_plan(primary="VERSION_ANALYSIS"):
    return {
        "rule_version": "r35-1",
        "required_roles": [primary],
        "primary_role": primary,
        "role_reason": "VERSION_STRATEGY",
        "confidence_level": "HIGH",
        "research_only": True,
    }


class TestScopeCapabilityGate(unittest.TestCase):
    def test_capability_from_role_plan(self):
        gate = plan_scope_capability_gate(
            authorization("ALLOW"), role_plan("VERSION_ANALYSIS"),
            "COMPONENT_SCOPED",
        )
        self.assertEqual(gate["capability"], "VERSION_ANALYSIS")
        self.assertEqual(gate["agent_role"], "VERSION_ANALYSIS")

    def test_every_research_capability_is_closed(self):
        self.assertEqual(
            set(schema.RESEARCH_CAPABILITIES),
            {
                "ASSET_ANALYSIS", "IDENTITY_ANALYSIS",
                "TECHNOLOGY_ANALYSIS", "VERSION_ANALYSIS",
                "EVIDENCE_ANALYSIS", "HISTORY_ANALYSIS",
                "HUMAN_REVIEW", "UNKNOWN",
            },
        )

    def test_scope_resolution(self):
        expectations = (
            ("COMPONENT_SCOPED", "COMPONENT_SCOPED", "HIGH"),
            ("AUTHORIZED_RESEARCH_SCOPE", "AUTHORIZED_RESEARCH_SCOPE",
             "MEDIUM"),
            ("PROGRAM_SCOPED", "PROGRAM_SCOPED", "MEDIUM"),
        )
        for value, scope, certainty in expectations:
            gate = plan_scope_capability_gate(
                authorization("ALLOW"), role_plan(), value
            )
            self.assertEqual(gate["scope"], scope, value)
            self.assertEqual(gate["scope_certainty"], certainty, value)

    def test_missing_scope_is_conservative(self):
        for value in (None, "", "GLOBAL", "NONE", "UNRESTRICTED",
                      "everything"):
            gate = plan_scope_capability_gate(
                authorization("ALLOW"), role_plan(), value
            )
            self.assertEqual(gate["scope"], "UNKNOWN", repr(value))
            self.assertEqual(gate["scope_certainty"], "UNKNOWN")
            self.assertFalse(gate["authorized"], repr(value))

    def test_no_unrestricted_scope_value_exists(self):
        self.assertNotIn("UNRESTRICTED", schema.SCOPE_VALUES)
        self.assertNotIn("GLOBAL", schema.SCOPE_VALUES)

    def test_authorized_requires_allow_and_known_scope(self):
        allow = plan_scope_capability_gate(
            authorization("ALLOW"), role_plan(), "COMPONENT_SCOPED"
        )
        self.assertTrue(allow["authorized"])
        limited = plan_scope_capability_gate(
            authorization("ALLOW_WITH_LIMITS"), role_plan(),
            "COMPONENT_SCOPED",
        )
        self.assertTrue(limited["authorized"])
        for decision in ("BLOCK", "REQUIRE_HUMAN_APPROVAL", "UNKNOWN"):
            gate = plan_scope_capability_gate(
                authorization(decision), role_plan(), "COMPONENT_SCOPED"
            )
            self.assertFalse(gate["authorized"], decision)

    def test_unknown_capability_is_not_authorized(self):
        gate = plan_scope_capability_gate(
            authorization("ALLOW"), role_plan("NOPE"),
            "COMPONENT_SCOPED",
        )
        self.assertEqual(gate["capability"], "UNKNOWN")
        self.assertFalse(gate["authorized"])

    def test_malformed_inputs(self):
        gate = plan_scope_capability_gate()
        self.assertEqual(gate["capability"], "UNKNOWN")
        self.assertEqual(gate["scope"], "UNKNOWN")
        self.assertFalse(gate["authorized"])
        self.assertEqual(gate["constraints"], ["UNKNOWN_CONTEXT"])

    def test_constraints_by_decision(self):
        expectations = (
            ("BLOCK", ["BLOCKED"]),
            ("REQUIRE_HUMAN_APPROVAL", ["HUMAN_APPROVAL_REQUIRED"]),
            ("UNKNOWN", ["UNKNOWN_CONTEXT"]),
            ("ALLOW_WITH_LIMITS",
             ["RESEARCH_ONLY_BOUNDARY", "COMPONENT_SCOPED_ONLY"]),
        )
        for decision, constraints in expectations:
            gate = plan_scope_capability_gate(
                authorization(decision), role_plan(), "COMPONENT_SCOPED"
            )
            self.assertEqual(gate["constraints"], constraints, decision)

    def test_deterministic_output(self):
        args = (
            authorization("ALLOW"), role_plan(), "COMPONENT_SCOPED",
        )
        first = plan_scope_capability_gate(*args)
        second = plan_scope_capability_gate(*args)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        auth = authorization("ALLOW")
        roles = role_plan()
        snapshots = (copy.deepcopy(auth), copy.deepcopy(roles))
        plan_scope_capability_gate(auth, roles, "COMPONENT_SCOPED")
        self.assertEqual(auth, snapshots[0])
        self.assertEqual(roles, snapshots[1])

    def test_json_serializable(self):
        gate = plan_scope_capability_gate()
        self.assertIsInstance(json.loads(json.dumps(gate)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            plan_scope_capability_gate()["research_only"], True
        )

    def test_schema_rejects_bad_values(self):
        base = {
            "capability": "VERSION_ANALYSIS",
            "agent_role": "VERSION_ANALYSIS",
            "scope": "COMPONENT_SCOPED",
            "scope_certainty": "HIGH",
            "authorized": True,
            "source_strategy": "VERSION_FIRST",
        }
        for key, value in (
            ("capability", "RUN_SCAN"),
            ("agent_role", "OPERATOR"),
            ("scope", "UNRESTRICTED"),
            ("scope_certainty", "CERTAIN"),
            ("constraints", ["RUN_NUCLEI"]),
        ):
            with self.assertRaises(ValidationError):
                schema.ScopeCapabilityGatePlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.ScopeCapabilityGatePlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ScopeCapabilityGatePlan(
            rule_version="r99-9",
            capability="UNKNOWN",
            agent_role="UNKNOWN",
            scope="UNKNOWN",
            scope_certainty="UNKNOWN",
            authorized=False,
            source_strategy="",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r36-3")
        with self.assertRaises(ValidationError):
            schema.ScopeCapabilityGatePlan(
                capability="UNKNOWN",
                agent_role="UNKNOWN",
                scope="UNKNOWN",
                scope_certainty="UNKNOWN",
                authorized=False,
                source_strategy="",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(schema.SCOPE_CAPABILITY_GATE_RULE_VERSION,
                         "r36-3")
        gate = plan_scope_capability_gate()
        self.assertEqual(gate["rule_version"], "r36-3")

    def test_no_operational_execution_vocabulary(self):
        blob = json.dumps(
            [
                plan_scope_capability_gate(
                    authorization(decision), role_plan(), value
                )
                for decision in (
                    "ALLOW", "ALLOW_WITH_LIMITS", "BLOCK",
                    "REQUIRE_HUMAN_APPROVAL", "UNKNOWN",
                )
                for value in ("COMPONENT_SCOPED", None)
            ]
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
        ):
            self.assertNotIn(marker, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
