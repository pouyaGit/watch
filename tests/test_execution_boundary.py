"""tests/test_execution_boundary.py — Stage R36.6 tests.

Deterministic, offline tests for the execution boundary planner:

- boundary state per authorization decision
- approved/limited/human-review/blocked/unknown handling
- blocked conditions and limitations
- execution_performed is always False (schema-enforced)
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

from ai.knowledge.execution_boundary_planner import (
    plan_execution_boundary,
)
from ai.schemas import execution_boundary_plan as schema

STRATEGY = {
    "rule_version": "r34-4",
    "ready": True,
    "strategy": {"strategy_type": "VERSION_FIRST",
                 "confidence_level": "HIGH"},
    "research_only": True,
}
ORCHESTRATION = {
    "rule_version": "r35-4",
    "ready": True,
    "workflow": {"nodes": ["ANALYZE_VERSION", "COLLECT_EVIDENCE_PLAN"]},
    "research_only": True,
}


def authorization(decision):
    return {
        "rule_version": "r36-2",
        "decision": decision,
        "decision_reason": "X",
        "policy": "RESEARCH_ONLY",
        "limitations": [],
        "source_strategy": {"strategy_type": "VERSION_FIRST"},
        "source_orchestration": {},
        "research_only": True,
    }


def scope(scope_value="COMPONENT_SCOPED", capability="VERSION_ANALYSIS",
          authorized=True):
    return {
        "rule_version": "r36-3",
        "capability": capability,
        "agent_role": capability,
        "scope": scope_value,
        "scope_certainty": "HIGH",
        "authorized": authorized,
        "source_strategy": "VERSION_FIRST",
        "constraints": [],
        "research_only": True,
    }


def boundary(decision="ALLOW_WITH_LIMITS", **over):
    kwargs = dict(
        authorization_plan=authorization(decision),
        scope_plan=scope(),
        risk_plan={"risk_level": "MEDIUM"},
        approval_plan={"approval_state": "NOT_REQUIRED", "required": False},
        policy_plan={"policy": "RESEARCH_ONLY", "constraints": []},
        strategy_export=STRATEGY,
        orchestration_export=ORCHESTRATION,
    )
    kwargs.update(over)
    return plan_execution_boundary(**kwargs)


class TestExecutionBoundary(unittest.TestCase):
    def test_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.BOUNDARY_STATES),
            {"RESEARCH_ONLY", "AUTHORIZED", "HUMAN_REVIEW_REQUIRED",
             "BLOCKED", "UNKNOWN"},
        )

    def test_boundary_per_decision(self):
        expectations = (
            ("ALLOW", "AUTHORIZED"),
            ("ALLOW_WITH_LIMITS", "RESEARCH_ONLY"),
            ("REQUIRE_HUMAN_APPROVAL", "HUMAN_REVIEW_REQUIRED"),
            ("BLOCK", "BLOCKED"),
            ("UNKNOWN", "UNKNOWN"),
        )
        for decision, state in expectations:
            plan = boundary(decision)
            self.assertEqual(plan["boundary_state"], state, decision)
            self.assertEqual(plan["authorization_result"], decision)

    def test_allow_with_pending_required_approval_is_human_review(self):
        plan = boundary(
            "ALLOW",
            approval_plan={"approval_state": "PENDING", "required": True},
        )
        self.assertEqual(plan["boundary_state"],
                         "HUMAN_REVIEW_REQUIRED")

    def test_allow_with_approved_approval_is_authorized(self):
        plan = boundary(
            "ALLOW",
            approval_plan={"approval_state": "APPROVED", "required": True},
        )
        self.assertEqual(plan["boundary_state"], "AUTHORIZED")

    def test_execution_performed_is_always_false(self):
        for decision in (
            "ALLOW", "ALLOW_WITH_LIMITS", "REQUIRE_HUMAN_APPROVAL",
            "BLOCK", "UNKNOWN",
        ):
            plan = boundary(decision)
            self.assertFalse(plan["execution_performed"], decision)

    def test_execution_permitted_only_for_authorized_complete_context(self):
        permitted = boundary("ALLOW")
        self.assertTrue(permitted["execution_permitted"])
        limited = boundary("ALLOW_WITH_LIMITS")
        self.assertFalse(limited["execution_permitted"])
        blocked = boundary("BLOCK")
        self.assertFalse(blocked["execution_permitted"])
        missing_scope = boundary(
            "ALLOW",
            scope_plan=scope("UNKNOWN", "UNKNOWN", False),
        )
        self.assertFalse(missing_scope["execution_permitted"])
        unknown_risk = boundary(
            "ALLOW", risk_plan={"risk_level": "UNKNOWN"}
        )
        self.assertFalse(unknown_risk["execution_permitted"])

    def test_allowed_capabilities_only_when_authorized(self):
        permitted = boundary("ALLOW")
        self.assertEqual(permitted["allowed_capabilities"],
                         ["VERSION_ANALYSIS"])
        limited = boundary("ALLOW_WITH_LIMITS")
        self.assertEqual(limited["allowed_capabilities"], [])
        blocked = boundary("BLOCK")
        self.assertEqual(blocked["allowed_capabilities"], [])

    def test_blocked_conditions(self):
        plan = boundary(
            "BLOCK",
            scope_plan=scope("UNKNOWN", "UNKNOWN", False),
            approval_plan={"approval_state": "REJECTED", "required": True},
            orchestration_export={"workflow": {"nodes": []}},
        )
        for condition in (
            "POLICY_BLOCKED", "MISSING_SCOPE", "HUMAN_APPROVAL_REJECTED",
            "INVALID_WORKFLOW",
        ):
            self.assertIn(condition, plan["blocked_conditions"])

    def test_unknown_boundary_has_unknown_context_condition(self):
        plan = plan_execution_boundary()
        self.assertEqual(plan["boundary_state"], "UNKNOWN")
        self.assertIn("UNKNOWN_CONTEXT", plan["blocked_conditions"])

    def test_limitations_include_plan_only_marker(self):
        plan = boundary("ALLOW")
        self.assertIn("PLAN_ONLY_NO_EXECUTION", plan["limitations"])
        self.assertIn("AUTHORIZATION_ONLY", plan["limitations"])

    def test_deterministic_output(self):
        first = boundary("ALLOW")
        second = boundary("ALLOW")
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        args = (
            authorization("ALLOW"), scope(), {"risk_level": "LOW"},
            {"approval_state": "NOT_REQUIRED", "required": False},
            {"policy": "ACTIVE_ALLOWED", "constraints": []},
            STRATEGY, ORCHESTRATION,
        )
        snapshots = tuple(copy.deepcopy(value) for value in args)
        plan_execution_boundary(*args)
        for before, after in zip(snapshots, args):
            self.assertEqual(before, after)

    def test_json_serializable(self):
        plan = boundary("BLOCK")
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        self.assertIs(boundary("ALLOW")["research_only"], True)

    def test_schema_rejects_bad_values(self):
        base = {
            "boundary_state": "BLOCKED",
            "authorization_result": "BLOCK",
            "scope": "UNKNOWN",
            "risk_level": "CRITICAL",
        }
        for key, value in (
            ("boundary_state", "EXECUTING"),
            ("authorization_result", "RUN"),
            ("scope", "UNRESTRICTED"),
            ("risk_level", "SEVERE"),
            ("allowed_capabilities", ["RUN_SCAN"]),
            ("blocked_conditions", ["RUN_NUCLEI"]),
        ):
            with self.assertRaises(ValidationError):
                schema.ExecutionBoundaryPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.ExecutionBoundaryPlan(**base, severity="HIGH")

    def test_schema_refuses_execution_performed_true(self):
        with self.assertRaises(ValidationError):
            schema.ExecutionBoundaryPlan(
                boundary_state="AUTHORIZED",
                authorization_result="ALLOW",
                scope="COMPONENT_SCOPED",
                risk_level="LOW",
                execution_performed=True,
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ExecutionBoundaryPlan(
            rule_version="r99-9",
            boundary_state="UNKNOWN",
            authorization_result="UNKNOWN",
            scope="UNKNOWN",
            risk_level="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r36-6")
        self.assertFalse(plan.execution_performed)
        with self.assertRaises(ValidationError):
            schema.ExecutionBoundaryPlan(
                boundary_state="UNKNOWN",
                authorization_result="UNKNOWN",
                scope="UNKNOWN",
                risk_level="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(schema.EXECUTION_BOUNDARY_RULE_VERSION, "r36-6")
        self.assertEqual(boundary("ALLOW")["rule_version"], "r36-6")

    def test_no_operational_execution_vocabulary(self):
        blob = json.dumps(
            [boundary(decision) for decision in (
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
