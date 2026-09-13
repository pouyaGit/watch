"""tests/test_execution_risk.py — Stage R36.4 tests.

Deterministic, offline tests for the execution risk planner:

- base risk level per authorization decision
- conservative escalation (scope, workflow, confidence, approval)
- risk is not permission: authorization remains authoritative
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

from ai.knowledge.execution_risk_planner import plan_execution_risk
from ai.schemas import execution_risk as schema

STRATEGY = {
    "rule_version": "r34-4",
    "ready": True,
    "strategy": {"strategy_type": "VERSION_FIRST",
                 "confidence_level": "HIGH"},
    "budget": {"budget_state": "CONTINUE"},
    "research_only": True,
}
ORCHESTRATION = {
    "rule_version": "r35-4",
    "ready": True,
    "roles": {"primary_role": "VERSION_ANALYSIS"},
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
        "source_strategy": {},
        "source_orchestration": {},
        "research_only": True,
    }


def scope(scope_value="COMPONENT_SCOPED", certainty="HIGH",
          authorized=True):
    return {
        "rule_version": "r36-3",
        "capability": "VERSION_ANALYSIS",
        "agent_role": "VERSION_ANALYSIS",
        "scope": scope_value,
        "scope_certainty": certainty,
        "authorized": authorized,
        "source_strategy": "VERSION_FIRST",
        "constraints": [],
        "research_only": True,
    }


def approval(state, required=False):
    return {
        "rule_version": "r36-5",
        "approval_state": state,
        "approval_reason": "X",
        "required": required,
        "research_only": True,
    }


def risk(decision="ALLOW", **over):
    kwargs = dict(
        authorization_plan=authorization(decision),
        scope_plan=scope(),
        approval_plan=approval("NOT_REQUIRED"),
        strategy_export=STRATEGY,
        orchestration_export=ORCHESTRATION,
    )
    kwargs.update(over)
    return plan_execution_risk(**kwargs)


class TestExecutionRisk(unittest.TestCase):
    def test_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.RISK_LEVELS),
            {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"},
        )

    def test_base_levels(self):
        expectations = (
            ("ALLOW", "LOW", "ACTIVE_AUTHORIZED"),
            ("ALLOW_WITH_LIMITS", "MEDIUM", "LIMITED_AUTHORIZATION"),
            ("REQUIRE_HUMAN_APPROVAL", "HIGH",
             "HUMAN_APPROVAL_REQUIRED"),
            ("BLOCK", "CRITICAL", "AUTHORIZATION_BLOCK"),
            ("UNKNOWN", "UNKNOWN", "UNKNOWN_CONTEXT"),
        )
        for decision, level, reason in expectations:
            plan = risk(decision)
            self.assertEqual(plan["risk_level"], level, decision)
            self.assertEqual(plan["risk_reason"], reason, decision)

    def test_missing_scope_escalates(self):
        plan = risk("ALLOW_WITH_LIMITS",
                    scope_plan=scope("UNKNOWN", "UNKNOWN", False))
        self.assertEqual(plan["risk_level"], "HIGH")
        self.assertIn("MISSING_SCOPE", plan["risk_factors"])

    def test_invalid_workflow_escalates(self):
        plan = risk("ALLOW_WITH_LIMITS",
                    orchestration_export={"workflow": {"nodes": []}})
        self.assertEqual(plan["risk_level"], "HIGH")
        self.assertIn("INVALID_WORKFLOW", plan["risk_factors"])

    def test_low_confidence_escalates(self):
        strategy = copy.deepcopy(STRATEGY)
        strategy["strategy"]["confidence_level"] = "LOW"
        plan = risk("ALLOW_WITH_LIMITS", strategy_export=strategy)
        self.assertEqual(plan["risk_level"], "HIGH")
        self.assertIn("LOW_CONFIDENCE", plan["risk_factors"])

    def test_escalations_compound(self):
        plan = risk(
            "ALLOW_WITH_LIMITS",
            scope_plan=scope("UNKNOWN", "UNKNOWN", False),
            orchestration_export={"workflow": {"nodes": []}},
            strategy_export={"strategy": {"confidence_level": "UNKNOWN"}},
        )
        self.assertEqual(plan["risk_level"], "CRITICAL")
        for factor in (
            "LIMITED_AUTHORIZATION", "MISSING_SCOPE",
            "INVALID_WORKFLOW", "LOW_CONFIDENCE",
        ):
            self.assertIn(factor, plan["risk_factors"])

    def test_rejected_approval_is_critical(self):
        plan = risk("REQUIRE_HUMAN_APPROVAL",
                    approval_plan=approval("REJECTED", True))
        self.assertEqual(plan["risk_level"], "CRITICAL")
        self.assertIn("APPROVAL_REJECTED", plan["risk_factors"])

    def test_expired_approval_is_critical(self):
        plan = risk("REQUIRE_HUMAN_APPROVAL",
                    approval_plan=approval("EXPIRED", True))
        self.assertEqual(plan["risk_level"], "CRITICAL")
        self.assertIn("APPROVAL_EXPIRED", plan["risk_factors"])

    def test_risk_is_not_permission(self):
        # A BLOCK stays CRITICAL and the authorization decision is untouched.
        auth = authorization("BLOCK")
        plan = risk("BLOCK")
        self.assertEqual(plan["risk_level"], "CRITICAL")
        self.assertIs(plan["authorization_authoritative"], True)
        self.assertEqual(auth["decision"], "BLOCK")
        # No low-risk result can exist for a BLOCK.
        self.assertNotEqual(plan["risk_level"], "LOW")

    def test_malformed_inputs_are_unknown(self):
        plan = plan_execution_risk()
        self.assertEqual(plan["risk_level"], "UNKNOWN")
        self.assertEqual(plan["risk_reason"], "UNKNOWN_CONTEXT")
        self.assertEqual(plan["research_only"], True)

    def test_deterministic_output(self):
        first = risk("ALLOW_WITH_LIMITS")
        second = risk("ALLOW_WITH_LIMITS")
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        args = (
            authorization("BLOCK"), scope(), approval("NOT_REQUIRED"),
            STRATEGY, ORCHESTRATION,
        )
        snapshots = tuple(copy.deepcopy(value) for value in args)
        plan_execution_risk(*args)
        for before, after in zip(snapshots, args):
            self.assertEqual(before, after)

    def test_json_serializable(self):
        plan = risk("ALLOW")
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        for decision in ("ALLOW", "BLOCK", "UNKNOWN"):
            self.assertIs(risk(decision)["research_only"], True)

    def test_schema_rejects_bad_values(self):
        base = {
            "risk_level": "LOW",
            "risk_reason": "ACTIVE_AUTHORIZED",
        }
        for key, value in (
            ("risk_level", "SEVERE"),
            ("risk_reason", "BECAUSE"),
            ("risk_factors", ["RUN_SCAN"]),
        ):
            with self.assertRaises(ValidationError):
                schema.ExecutionRiskPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.ExecutionRiskPlan(**base, severity="HIGH")
        with self.assertRaises(ValidationError):
            schema.ExecutionRiskPlan(
                **base, authorization_authoritative=False
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ExecutionRiskPlan(
            rule_version="r99-9",
            risk_level="UNKNOWN",
            risk_reason="UNKNOWN_CONTEXT",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r36-4")
        with self.assertRaises(ValidationError):
            schema.ExecutionRiskPlan(
                risk_level="UNKNOWN",
                risk_reason="UNKNOWN_CONTEXT",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(schema.EXECUTION_RISK_RULE_VERSION, "r36-4")
        self.assertEqual(risk("ALLOW")["rule_version"], "r36-4")

    def test_no_operational_execution_vocabulary(self):
        blob = json.dumps(
            [risk(decision) for decision in (
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
