"""tests/test_execution_policy.py — Stage R36.1 tests.

Deterministic, offline tests for the execution policy model:

- exact closed vocabulary
- default policy resolution
- explicit policy resolution and malformed policy handling
- deterministic output, JSON serialization
- schema validation, forced research_only
- no operational execution vocabulary

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.execution_authorization_planner import (
    plan_execution_policy,
)
from ai.schemas import execution_policy as schema

STRATEGY = {
    "rule_version": "r34-4",
    "ready": True,
    "strategy": {"strategy_type": "VERSION_FIRST",
                 "confidence_level": "HIGH"},
    "path": {"primary_path": "VERIFY_VERSION"},
    "budget": {"budget_state": "CONTINUE"},
    "research_only": True,
}
ORCHESTRATION = {
    "rule_version": "r35-4",
    "ready": True,
    "roles": {"primary_role": "VERSION_ANALYSIS"},
    "workflow": {"nodes": ["ANALYZE_VERSION", "COLLECT_EVIDENCE_PLAN"]},
    "coordination": {"coordination_mode": "SEQUENTIAL"},
    "research_only": True,
}


class TestExecutionPolicy(unittest.TestCase):
    def test_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.EXECUTION_POLICIES),
            {
                "RESEARCH_ONLY", "PASSIVE_ONLY", "ACTIVE_ALLOWED",
                "HUMAN_APPROVAL_REQUIRED", "BLOCKED", "UNKNOWN",
            },
        )
        self.assertEqual(
            set(schema.EXECUTION_POLICY_REASONS),
            {
                "RESEARCH_DEFAULT", "PASSIVE_RESEARCH",
                "ACTIVE_EXPLICIT_AUTHORIZATION",
                "HUMAN_APPROVAL_MANDATED", "BLOCKED_MANDATED",
                "UNKNOWN_POLICY",
            },
        )

    def test_missing_policy_defaults_research_only(self):
        plan = plan_execution_policy(STRATEGY, ORCHESTRATION)
        self.assertEqual(plan["policy"], "RESEARCH_ONLY")
        self.assertEqual(plan["policy_reason"], "RESEARCH_DEFAULT")
        self.assertEqual(plan["constraints"], ["NO_TARGET_INTERACTION"])

    def test_every_explicit_policy_maps(self):
        expectations = (
            ("RESEARCH_ONLY", "RESEARCH_DEFAULT",
             ["NO_TARGET_INTERACTION"]),
            ("PASSIVE_ONLY", "PASSIVE_RESEARCH",
             ["PASSIVE_OBSERVATION_ONLY"]),
            ("ACTIVE_ALLOWED", "ACTIVE_EXPLICIT_AUTHORIZATION",
             ["AUTHORIZED_SCOPE_ONLY"]),
            ("HUMAN_APPROVAL_REQUIRED", "HUMAN_APPROVAL_MANDATED",
             ["HUMAN_APPROVAL_MANDATORY"]),
            ("BLOCKED", "BLOCKED_MANDATED", ["NO_ACTION_PERMITTED"]),
            ("UNKNOWN", "UNKNOWN_POLICY", ["UNKNOWN_NO_ACTION"]),
        )
        for policy, reason, constraints in expectations:
            plan = plan_execution_policy(STRATEGY, ORCHESTRATION, policy)
            self.assertEqual(plan["policy"], policy)
            self.assertEqual(plan["policy_reason"], reason)
            self.assertEqual(plan["constraints"], constraints)

    def test_malformed_policy_is_unknown_never_permissive(self):
        for value in ("NONSENSE", "execute_everything", "", "  ", 0):
            plan = plan_execution_policy(
                STRATEGY, ORCHESTRATION, value
            )
            self.assertEqual(plan["policy"], "UNKNOWN", repr(value))
            self.assertEqual(plan["policy_reason"], "UNKNOWN_POLICY")

    def test_explicit_none_is_research_only_not_unknown(self):
        plan = plan_execution_policy(STRATEGY, ORCHESTRATION, None)
        self.assertEqual(plan["policy"], "RESEARCH_ONLY")

    def test_lowercase_policy_is_normalized(self):
        plan = plan_execution_policy(
            STRATEGY, ORCHESTRATION, "blocked"
        )
        self.assertEqual(plan["policy"], "BLOCKED")

    def test_deterministic_output(self):
        first = plan_execution_policy(STRATEGY, ORCHESTRATION, "BLOCKED")
        second = plan_execution_policy(STRATEGY, ORCHESTRATION, "BLOCKED")
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        import copy

        strategy = copy.deepcopy(STRATEGY)
        orchestration = copy.deepcopy(ORCHESTRATION)
        plan_execution_policy(strategy, orchestration, "BLOCKED")
        self.assertEqual(strategy, STRATEGY)
        self.assertEqual(orchestration, ORCHESTRATION)

    def test_json_serializable(self):
        plan = plan_execution_policy()
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        self.assertIs(plan_execution_policy()["research_only"], True)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ExecutionPolicyPlan(
                policy="EXECUTE", policy_reason="RESEARCH_DEFAULT"
            )
        with self.assertRaises(ValidationError):
            schema.ExecutionPolicyPlan(
                policy="BLOCKED", policy_reason="BECAUSE"
            )
        with self.assertRaises(ValidationError):
            schema.ExecutionPolicyPlan(
                policy="BLOCKED",
                policy_reason="BLOCKED_MANDATED",
                constraints=["RUN_SCAN"],
            )
        with self.assertRaises(ValidationError):
            schema.ExecutionPolicyPlan(
                policy="BLOCKED", policy_reason="BLOCKED_MANDATED",
                severity="HIGH",
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ExecutionPolicyPlan(
            rule_version="r99-9",
            policy="BLOCKED",
            policy_reason="BLOCKED_MANDATED",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r36-1")
        with self.assertRaises(ValidationError):
            schema.ExecutionPolicyPlan(
                policy="BLOCKED",
                policy_reason="BLOCKED_MANDATED",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(schema.EXECUTION_POLICY_RULE_VERSION, "r36-1")
        plan = plan_execution_policy()
        self.assertEqual(plan["rule_version"], "r36-1")

    def test_no_operational_execution_vocabulary(self):
        blob = json.dumps(
            [
                plan_execution_policy(STRATEGY, ORCHESTRATION, value)
                for value in schema.EXECUTION_POLICIES
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
