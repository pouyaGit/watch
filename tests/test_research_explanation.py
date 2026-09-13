"""tests/test_research_explanation.py — Stage R37.4 tests.

Deterministic, offline tests for the research explanation planner:

- summaries per authorization decision
- closed reasons only (no hallucinated reasons)
- scope/risk/approval reason derivation
- limitations and confidence mapping
- explanation states (COMPLETE / PARTIAL / UNKNOWN)
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

from ai.knowledge.research_explanation_planner import (
    plan_research_explanation,
)
from ai.schemas import research_explanation as schema

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
    "roles": {"primary_role": "VERSION_ANALYSIS"},
    "workflow": {"nodes": ["ANALYZE_VERSION"]},
    "research_only": True,
}


def authorization(decision="ALLOW_WITH_LIMITS", policy="RESEARCH_ONLY"):
    return {
        "rule_version": "r36-2",
        "decision": decision,
        "decision_reason": "X",
        "policy": policy,
        "limitations": [],
        "source_strategy": {},
        "source_orchestration": {},
        "research_only": True,
    }


def provenance(state="COMPLETE"):
    return {
        "rule_version": "r37-1",
        "decision_id": "dp-" + "a" * 16,
        "source_strategy": {"strategy_type": "VERSION_FIRST"},
        "source_orchestration": {},
        "source_authorization": {},
        "contributing_signals": ["STRATEGY", "ORCHESTRATION",
                                 "AUTHORIZATION"],
        "provenance_state": state,
        "research_only": True,
    }


def trace(state="COMPLETE"):
    return {
        "rule_version": "r37-2",
        "applied_rules": [],
        "rejected_rules": [],
        "precedence_order": [],
        "trace_state": state,
        "research_only": True,
    }


def scope(value="COMPONENT_SCOPED"):
    return {"scope": value, "scope_certainty": "HIGH"}


def risk(level="MEDIUM"):
    return {"risk_level": level}


def approval(state="NOT_REQUIRED"):
    return {"approval_state": state, "required": False}


def explain(decision="ALLOW_WITH_LIMITS", policy="RESEARCH_ONLY", **over):
    kwargs = dict(
        strategy_export=STRATEGY,
        orchestration_export=ORCHESTRATION,
        authorization_plan=authorization(decision, policy),
        provenance_plan=provenance(),
        trace_plan=trace(),
        scope_plan=scope(),
        risk_plan=risk(),
        approval_plan=approval(),
    )
    kwargs.update(over)
    return plan_research_explanation(**kwargs)


class TestResearchExplanation(unittest.TestCase):
    def test_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.EXPLANATION_SUMMARIES),
            {
                "EXPLANATION_AUTHORIZED", "EXPLANATION_LIMITED",
                "EXPLANATION_HUMAN_APPROVAL", "EXPLANATION_BLOCKED",
                "EXPLANATION_UNKNOWN",
            },
        )

    def test_summary_per_decision(self):
        expectations = (
            ("ALLOW", "RESEARCH_ONLY", "EXPLANATION_AUTHORIZED",
             "POLICY_ACTIVE_ALLOWED"),
            ("ALLOW_WITH_LIMITS", "RESEARCH_ONLY", "EXPLANATION_LIMITED",
             "POLICY_RESEARCH_ONLY"),
            ("ALLOW_WITH_LIMITS", "PASSIVE_ONLY", "EXPLANATION_LIMITED",
             "POLICY_PASSIVE_ONLY"),
            ("REQUIRE_HUMAN_APPROVAL", "HUMAN_APPROVAL_REQUIRED",
             "EXPLANATION_HUMAN_APPROVAL", "POLICY_HUMAN_APPROVAL_REQUIRED"),
            ("BLOCK", "BLOCKED", "EXPLANATION_BLOCKED", "POLICY_BLOCKED"),
        )
        for decision, policy, summary, reason in expectations:
            plan = explain(decision, policy)
            self.assertEqual(plan["summary"], summary, decision)
            self.assertIn(reason, plan["reasons"], decision)

    def test_no_hallucinated_reasons(self):
        for decision, policy in (
            ("ALLOW", "ACTIVE_ALLOWED"),
            ("ALLOW_WITH_LIMITS", "RESEARCH_ONLY"),
            ("REQUIRE_HUMAN_APPROVAL", "HUMAN_APPROVAL_REQUIRED"),
            ("BLOCK", "BLOCKED"),
            ("UNKNOWN", "UNKNOWN"),
        ):
            plan = explain(decision, policy)
            for reason in plan["reasons"]:
                self.assertIn(reason, schema.EXPLANATION_REASONS)
            for limitation in plan["limitations"]:
                self.assertIn(limitation,
                              schema.EXPLANATION_LIMITATIONS)

    def test_scope_unknown_reason(self):
        plan = explain(scope_plan=scope("UNKNOWN"))
        self.assertIn("SCOPE_UNKNOWN", plan["reasons"])
        self.assertIn(schema.LIMITATION_SCOPE_UNKNOWN,
                      plan["limitations"])

    def test_risk_elevated_reason(self):
        plan = explain(risk_plan=risk("CRITICAL"))
        self.assertIn("RISK_ELEVATED", plan["reasons"])

    def test_approval_pending_reason(self):
        plan = explain(
            "REQUIRE_HUMAN_APPROVAL", "HUMAN_APPROVAL_REQUIRED",
            approval_plan=approval("PENDING"),
        )
        self.assertIn("APPROVAL_PENDING", plan["reasons"])

    def test_blocked_includes_boundary_reason(self):
        plan = explain("BLOCK", "BLOCKED")
        self.assertIn("BOUNDARY_BLOCKED", plan["reasons"])

    def test_limitations_for_missing_sources(self):
        plan = plan_research_explanation(
            authorization_plan=authorization("ALLOW_WITH_LIMITS"),
            provenance_plan=provenance("PARTIAL"),
            trace_plan=trace("PARTIAL"),
        )
        self.assertIn(schema.LIMITATION_SOURCE_CONTEXT_MISSING,
                      plan["limitations"])
        self.assertIn(schema.LIMITATION_PARTIAL_PROVENANCE,
                      plan["limitations"])
        self.assertEqual(plan["explanation_state"], "PARTIAL")

    def test_unknown_explanation_for_empty_input(self):
        plan = plan_research_explanation()
        self.assertEqual(plan["summary"], "EXPLANATION_UNKNOWN")
        self.assertEqual(plan["explanation_state"], "UNKNOWN")
        self.assertEqual(plan["confidence"], "UNKNOWN")
        self.assertIn(schema.LIMITATION_UNKNOWN_EXPLANATION,
                      plan["limitations"])
        self.assertEqual(plan["reasons"], ["CONTEXT_INCOMPLETE"])

    def test_confidence_mapping(self):
        complete = explain()
        self.assertEqual(complete["confidence"], "HIGH")
        partial = explain(provenance_plan=provenance("PARTIAL"))
        self.assertEqual(partial["confidence"], "MEDIUM")
        low = explain(
            provenance_plan=provenance("UNKNOWN"),
            authorization_plan=authorization(),
        )
        self.assertEqual(low["confidence"], "LOW")

    def test_deterministic_output(self):
        first = explain()
        second = explain()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        inputs = (
            STRATEGY, ORCHESTRATION, authorization(), provenance(),
            trace(), scope(), risk(), approval(),
        )
        snapshots = tuple(copy.deepcopy(value) for value in inputs)
        plan_research_explanation(*inputs)
        for before, after in zip(snapshots, inputs):
            self.assertEqual(before, after)

    def test_no_free_text_leakage(self):
        plan = explain()
        blob = json.dumps(plan)
        for token in ("http://", "https://", "CVE-"):
            self.assertNotIn(token, blob)

    def test_json_serializable(self):
        self.assertIsInstance(json.loads(json.dumps(explain())), dict)

    def test_research_only_always_true(self):
        self.assertIs(explain()["research_only"], True)
        self.assertIs(
            plan_research_explanation()["research_only"], True
        )

    def test_schema_rejects_bad_values(self):
        base = {
            "summary": "EXPLANATION_LIMITED",
            "reasons": ["POLICY_RESEARCH_ONLY"],
            "limitations": [],
            "confidence": "HIGH",
            "explanation_state": "COMPLETE",
        }
        for key, value in (
            ("summary", "EXPLANATION_ELITE"),
            ("reasons", ["RUN_SCAN"]),
            ("limitations", ["DEPLOY"]),
            ("confidence", "CERTAIN"),
            ("explanation_state", "MAYBE"),
        ):
            with self.assertRaises(ValidationError):
                schema.ResearchExplanationPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.ResearchExplanationPlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchExplanationPlan(
            rule_version="r99-9",
            summary="EXPLANATION_UNKNOWN",
            reasons=["CONTEXT_INCOMPLETE"],
            limitations=["UNKNOWN_EXPLANATION"],
            confidence="UNKNOWN",
            explanation_state="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r37-4")
        with self.assertRaises(ValidationError):
            schema.ResearchExplanationPlan(
                summary="EXPLANATION_UNKNOWN",
                reasons=[],
                limitations=[],
                confidence="UNKNOWN",
                explanation_state="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(schema.RESEARCH_EXPLANATION_RULE_VERSION,
                         "r37-4")
        self.assertEqual(explain()["rule_version"], "r37-4")

    def test_no_execution_content(self):
        blob = json.dumps(explain()).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
        ):
            self.assertNotIn(marker, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
