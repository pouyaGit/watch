"""tests/test_research_execution_authorization_export.py — Stage R36.7 tests.

Deterministic, offline tests for the R36 authorization export:

- readiness gating (any UNKNOWN critical state prevents ready)
- every critical component validation
- limitation mappings
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

from ai.knowledge.research_execution_authorization_export import (
    export_research_execution_authorization,
)
from ai.schemas import research_execution_authorization_export as schema

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


def policy(value="RESEARCH_ONLY"):
    return {
        "rule_version": "r36-1",
        "policy": value,
        "policy_reason": "RESEARCH_DEFAULT",
        "constraints": ["NO_TARGET_INTERACTION"],
        "research_only": True,
    }


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


def scope(scope_value="COMPONENT_SCOPED", capability="VERSION_ANALYSIS",
          authorized=True):
    return {
        "rule_version": "r36-3",
        "capability": capability,
        "agent_role": capability,
        "scope": scope_value,
        "scope_certainty": "HIGH" if scope_value != "UNKNOWN" else "UNKNOWN",
        "authorized": authorized,
        "source_strategy": "VERSION_FIRST",
        "constraints": ["RESEARCH_ONLY_BOUNDARY"],
        "research_only": True,
    }


def risk(level="MEDIUM"):
    return {
        "rule_version": "r36-4",
        "risk_level": level,
        "risk_reason": "LIMITED_AUTHORIZATION",
        "risk_factors": ["LIMITED_AUTHORIZATION"],
        "authorization_authoritative": True,
        "research_only": True,
    }


def approval(state="NOT_REQUIRED", required=False):
    return {
        "rule_version": "r36-5",
        "approval_state": state,
        "approval_reason": "RESEARCH_ONLY_NOT_REQUIRED",
        "required": required,
        "research_only": True,
    }


def boundary(state="RESEARCH_ONLY"):
    return {
        "rule_version": "r36-6",
        "boundary_state": state,
        "authorization_result": "ALLOW_WITH_LIMITS",
        "allowed_capabilities": [],
        "scope": "COMPONENT_SCOPED",
        "human_approval_required": False,
        "risk_level": "MEDIUM",
        "constraints": ["NO_TARGET_INTERACTION",
                        "RESEARCH_ONLY_BOUNDARY"],
        "blocked_conditions": [],
        "source_strategy": "VERSION_FIRST",
        "source_orchestration": {},
        "limitations": ["PLAN_ONLY_NO_EXECUTION",
                        "AUTHORIZATION_ONLY",
                        "RESEARCH_ONLY_BOUNDARY"],
        "execution_permitted": False,
        "execution_performed": False,
        "research_only": True,
    }


def export(**over):
    kwargs = dict(
        policy_plan=policy(),
        authorization_plan=authorization(),
        scope_plan=scope(),
        risk_plan=risk(),
        approval_plan=approval(),
        boundary_plan=boundary(),
        strategy_export=STRATEGY,
        orchestration_export=ORCHESTRATION,
    )
    kwargs.update(over)
    return export_research_execution_authorization(**kwargs)


class TestAuthorizationExport(unittest.TestCase):
    def test_ready_when_all_valid(self):
        plan = export()
        self.assertTrue(plan["ready"])
        self.assertEqual(plan["rule_version"], "r36-7")
        self.assertEqual(plan["policy"]["policy"], "RESEARCH_ONLY")
        self.assertEqual(plan["authorization"]["decision"],
                         "ALLOW_WITH_LIMITS")
        self.assertEqual(plan["risk"]["risk_level"], "MEDIUM")
        self.assertEqual(plan["limitations"], [])

    def test_unknown_authorization_prevents_ready(self):
        plan = export(authorization_plan=authorization("UNKNOWN"))
        self.assertFalse(plan["ready"])
        self.assertIn("UNKNOWN_AUTHORIZATION", plan["limitations"])

    def test_unknown_risk_prevents_ready(self):
        plan = export(risk_plan=risk("UNKNOWN"))
        self.assertFalse(plan["ready"])
        self.assertIn("UNKNOWN_RISK", plan["limitations"])

    def test_unknown_scope_prevents_ready(self):
        plan = export(
            scope_plan=scope("UNKNOWN", "UNKNOWN", False)
        )
        self.assertFalse(plan["ready"])
        self.assertIn("UNKNOWN_SCOPE", plan["limitations"])
        self.assertIn("MISSING_SCOPE", plan["limitations"])

    def test_unknown_approval_prevents_ready(self):
        plan = export(approval_plan=approval("UNKNOWN"))
        self.assertFalse(plan["ready"])
        self.assertIn("UNKNOWN_APPROVAL", plan["limitations"])

    def test_unknown_boundary_prevents_ready(self):
        plan = export(boundary_plan=boundary("UNKNOWN"))
        self.assertFalse(plan["ready"])
        self.assertIn("UNKNOWN_BOUNDARY", plan["limitations"])

    def test_block_is_ready_with_blocked_limitation(self):
        plan = export(
            authorization_plan=authorization("BLOCK"),
            risk_plan=risk("CRITICAL"),
            boundary_plan=boundary("BLOCKED"),
        )
        self.assertTrue(plan["ready"])
        self.assertIn("BLOCKED", plan["limitations"])

    def test_unknown_scope_prevents_ready_even_when_blocked(self):
        plan = export(
            authorization_plan=authorization("BLOCK"),
            scope_plan=scope("UNKNOWN", "UNKNOWN", False),
            risk_plan=risk("CRITICAL"),
            boundary_plan=boundary("BLOCKED"),
        )
        self.assertFalse(plan["ready"])
        self.assertIn("UNKNOWN_SCOPE", plan["limitations"])

    def test_pending_approval_limitation(self):
        plan = export(
            authorization_plan=authorization("REQUIRE_HUMAN_APPROVAL"),
            approval_plan=approval("PENDING", True),
            boundary_plan=boundary("HUMAN_REVIEW_REQUIRED"),
        )
        self.assertTrue(plan["ready"])
        self.assertIn("HUMAN_APPROVAL_PENDING", plan["limitations"])

    def test_invalid_workflow_limitation(self):
        plan = export(
            boundary_plan={
                **boundary(),
                "blocked_conditions": ["INVALID_WORKFLOW"],
            }
        )
        self.assertIn("INVALID_WORKFLOW", plan["limitations"])

    def test_capabilities_from_authorized_scope(self):
        # The default scope gate is authorized for a known component scope.
        plan = export()
        self.assertEqual(plan["capabilities"], ["VERSION_ANALYSIS"])
        plan = export(
            scope_plan=scope("UNKNOWN", "UNKNOWN", False),
            risk_plan=risk("LOW"),
        )
        self.assertEqual(plan["capabilities"], [])

    def test_constraints_are_merged_and_deduplicated(self):
        plan = export()
        self.assertEqual(
            plan["constraints"],
            ["NO_TARGET_INTERACTION", "RESEARCH_ONLY_BOUNDARY"],
        )

    def test_malformed_inputs_not_ready(self):
        plan = export_research_execution_authorization()
        self.assertFalse(plan["ready"])
        for limitation in (
            "UNKNOWN_AUTHORIZATION", "UNKNOWN_RISK", "UNKNOWN_SCOPE",
            "UNKNOWN_APPROVAL", "UNKNOWN_BOUNDARY",
        ):
            self.assertIn(limitation, plan["limitations"])

    def test_deterministic_output(self):
        first = export()
        second = export()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        args = (
            policy(), authorization(), scope(), risk(), approval(),
            boundary(), STRATEGY, ORCHESTRATION,
        )
        snapshots = tuple(copy.deepcopy(value) for value in args)
        export_research_execution_authorization(*args)
        for before, after in zip(snapshots, args):
            self.assertEqual(before, after)

    def test_embedded_snapshots_do_not_alias_inputs(self):
        plan = export()
        plan["authorization"]["decision"] = "ALLOW"
        plan["scope"]["scope"] = "UNKNOWN"
        self.assertEqual(
            authorization()["decision"], "ALLOW_WITH_LIMITS"
        )
        self.assertEqual(scope()["scope"], "COMPONENT_SCOPED")

    def test_json_serializable(self):
        plan = export()
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        for plan in (
            export(),
            export_research_execution_authorization(),
        ):
            self.assertIs(plan["research_only"], True)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchExecutionAuthorizationExportPlan(
                ready=True, limitations=["RUN"]
            )
        with self.assertRaises(ValidationError):
            schema.ResearchExecutionAuthorizationExportPlan(
                ready=True, capabilities=["RUN_SCAN"]
            )
        with self.assertRaises(ValidationError):
            schema.ResearchExecutionAuthorizationExportPlan(
                ready=True, severity="HIGH"
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchExecutionAuthorizationExportPlan(
            rule_version="r99-9",
            ready=False,
            limitations=[],
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r36-7")
        with self.assertRaises(ValidationError):
            schema.ResearchExecutionAuthorizationExportPlan(
                ready=False, limitations=[], research_only=False
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            schema.RESEARCH_EXECUTION_AUTHORIZATION_EXPORT_RULE_VERSION,
            "r36-7",
        )
        self.assertEqual(export()["rule_version"], "r36-7")

    def test_no_operational_execution_vocabulary(self):
        blob = json.dumps(
            [export(), export_research_execution_authorization()]
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
        ):
            self.assertNotIn(marker, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
