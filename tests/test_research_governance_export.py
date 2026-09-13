"""tests/test_research_governance_export.py — Stage R37.5 tests.

Deterministic, offline tests for the research governance exporter:

- readiness gating (any UNKNOWN critical state prevents ready)
- INVALID audit event prevents readiness
- limitation mappings
- malformed input handling
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

from ai.knowledge.research_governance_export import (
    export_research_governance,
)
from ai.schemas import research_governance_export as schema


def provenance(state="COMPLETE"):
    return {
        "rule_version": "r37-1",
        "decision_id": "dp-" + "a" * 16,
        "source_strategy": {},
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


def audit(state="VALID", event="AUTHORIZATION_DECIDED"):
    return {
        "rule_version": "r37-3",
        "event_type": event,
        "event_source": "AUTHORIZATION",
        "event_summary": "AUTHORIZATION_RECORDED",
        "related_strategy": "VERSION_FIRST",
        "related_authorization": "ALLOW_WITH_LIMITS",
        "audit_state": state,
        "research_only": True,
    }


def explanation(state="COMPLETE"):
    return {
        "rule_version": "r37-4",
        "summary": "EXPLANATION_LIMITED",
        "reasons": ["POLICY_RESEARCH_ONLY"],
        "limitations": [],
        "confidence": "HIGH",
        "explanation_state": state,
        "research_only": True,
    }


def export(**over):
    kwargs = dict(
        provenance_plan=provenance(),
        rule_trace_plan=trace(),
        audit_event_plan=audit(),
        explanation_plan=explanation(),
    )
    kwargs.update(over)
    return export_research_governance(**kwargs)


class TestGovernanceExport(unittest.TestCase):
    def test_ready_when_all_valid(self):
        plan = export()
        self.assertTrue(plan["ready"])
        self.assertEqual(plan["rule_version"], "r37-5")
        self.assertEqual(plan["provenance"]["provenance_state"],
                         "COMPLETE")
        self.assertEqual(plan["rule_trace"]["trace_state"], "COMPLETE")
        self.assertEqual(plan["audit_event"]["audit_state"], "VALID")
        self.assertEqual(plan["explanation"]["explanation_state"],
                         "COMPLETE")
        self.assertEqual(plan["limitations"], [])

    def test_unknown_provenance_prevents_ready(self):
        plan = export(provenance_plan=provenance("UNKNOWN"))
        self.assertFalse(plan["ready"])
        self.assertIn(schema.LIMITATION_UNKNOWN_PROVENANCE,
                      plan["limitations"])

    def test_unknown_rule_trace_prevents_ready(self):
        plan = export(rule_trace_plan=trace("UNKNOWN"))
        self.assertFalse(plan["ready"])
        self.assertIn(schema.LIMITATION_UNKNOWN_RULE_TRACE,
                      plan["limitations"])

    def test_invalid_audit_event_prevents_ready(self):
        plan = export(audit_event_plan=audit("INVALID"))
        self.assertFalse(plan["ready"])
        self.assertIn(schema.LIMITATION_INVALID_AUDIT_EVENT,
                      plan["limitations"])

    def test_unknown_audit_event_prevents_ready(self):
        plan = export(audit_event_plan=audit("UNKNOWN"))
        self.assertFalse(plan["ready"])
        self.assertIn(schema.LIMITATION_UNKNOWN_AUDIT_EVENT,
                      plan["limitations"])

    def test_unknown_explanation_prevents_ready(self):
        plan = export(explanation_plan=explanation("UNKNOWN"))
        self.assertFalse(plan["ready"])
        self.assertIn(schema.LIMITATION_UNKNOWN_EXPLANATION,
                      plan["limitations"])

    def test_partial_provenance_is_ready_with_missing_sources(self):
        plan = export(provenance_plan=provenance("PARTIAL"))
        self.assertTrue(plan["ready"])
        self.assertIn(schema.LIMITATION_MISSING_SOURCES,
                      plan["limitations"])

    def test_malformed_inputs_not_ready(self):
        plan = export_research_governance()
        self.assertFalse(plan["ready"])
        for limitation in (
            schema.LIMITATION_UNKNOWN_PROVENANCE,
            schema.LIMITATION_UNKNOWN_RULE_TRACE,
            schema.LIMITATION_UNKNOWN_AUDIT_EVENT,
            schema.LIMITATION_UNKNOWN_EXPLANATION,
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
            provenance(), trace(), audit(), explanation(),
        )
        snapshots = tuple(copy.deepcopy(value) for value in args)
        export_research_governance(*args)
        for before, after in zip(snapshots, args):
            self.assertEqual(before, after)

    def test_embedded_snapshots_do_not_alias_inputs(self):
        plan = export()
        plan["provenance"]["provenance_state"] = "UNKNOWN"
        plan["audit_event"]["event_type"] = "UNKNOWN"
        self.assertEqual(provenance()["provenance_state"], "COMPLETE")
        self.assertEqual(audit()["event_type"], "AUTHORIZATION_DECIDED")

    def test_json_serializable(self):
        plan = export()
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        for plan in (
            export(),
            export_research_governance(),
        ):
            self.assertIs(plan["research_only"], True)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchGovernanceExportPlan(
                ready=True, limitations=["RUN"]
            )
        with self.assertRaises(ValidationError):
            schema.ResearchGovernanceExportPlan(
                ready=True, severity="HIGH"
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchGovernanceExportPlan(
            rule_version="r99-9",
            ready=False,
            limitations=[],
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r37-5")
        with self.assertRaises(ValidationError):
            schema.ResearchGovernanceExportPlan(
                ready=False, limitations=[], research_only=False
            )

    def test_exact_rule_version(self):
        self.assertEqual(schema.RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION,
                         "r37-5")
        self.assertEqual(export()["rule_version"], "r37-5")

    def test_no_execution_content(self):
        blob = json.dumps(
            [export(), export_research_governance()]
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
        ):
            self.assertNotIn(marker, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
