"""tests/test_collaboration_conflict_analyzer.py — Stage R43.4 tests.

Deterministic, offline tests for collaboration conflict analysis:

- confidence, context, evidence, governance, provenance, hypothesis and
  safety conflict detection
- deterministic resolution states and conflict ids
- both sides preserved and ordered deterministically
- schema validation and serialization

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.collaboration_conflict_analyzer import (
    analyze_collaboration_conflicts,
)
from ai.knowledge.multi_agent_collaboration_input import (
    build_multi_agent_collaboration_input,
)
from ai.schemas import collaboration_conflict as schema


AGENT_A = "sa-" + "a" * 16
AGENT_B = "sa-" + "b" * 16


def hypothesis(hypothesis_type, signals, confidence):
    return {
        "rule_version": "r99-3",
        "hypothesis_type": hypothesis_type,
        "supporting_signals": list(signals),
        "confidence": confidence,
        "priority": confidence,
        "limitations": [
            "NO_EXPLOIT_CLAIM",
            "NO_VULNERABILITY_CONFIRMATION",
            "HYPOTHESIS_ONLY",
            "EVIDENCE_REQUIRED",
        ],
        "research_only": True,
    }


def result(agent_id="", category="XSS", **over):
    base = {
        "rule_version": "r99-5",
        "agent_identity": {
            "rule_version": "r99-1",
            "agent_id": agent_id,
            "agent_name": "a",
            "category": category,
            "version": "1.0",
            "maturity": "RESEARCH",
            "supported_contexts": [],
            "supported_capabilities": [],
            "lifecycle_state": "PLANNED",
            "limitations": [],
            "research_only": True,
        },
        "status": "COMPLETED",
        "confidence": "HIGH",
        "context_analysis": {
            "input_location": "QUERY",
            "output_context": "HTML",
            "reflection_state": "REFLECTED",
            "encoding_state": "NONE_OBSERVED",
            "framework_context": "GENERIC",
        },
        "hypotheses": [hypothesis("TYPE_A", ["S1"], "HIGH")],
        "evidence_plan": {
            "rule_version": "r99-4",
            "evidence_items": ["REFLECTION_CONTEXT"],
            "evidence_state": "COMPLETE",
            "confidence": "HIGH",
            "limitations": ["NO_COLLECTION_PERFORMED", "EVIDENCE_REQUIRED"],
            "research_only": True,
        },
        "limitations": [
            "NO_EXECUTION_PERFORMED",
            "NO_VULNERABILITY_CONFIRMATION",
        ],
        "provenance": {
            "rule_version": "r99-5",
            "source_layers": ["REASONING"],
            "provenance_state": "COMPLETE",
            "research_only": True,
        },
        "governance_reference": {
            "rule_version": "r37-5",
            "ready": True,
            "provenance_state": "COMPLETE",
            "trace_state": "COMPLETE",
            "audit_state": "VALID",
            "explanation_state": "COMPLETE",
            "reference_state": "REFERENCED",
        },
        "research_only": True,
    }
    base.update(over)
    return base


def conflicts_for(results):
    collaboration = build_multi_agent_collaboration_input(results)
    return analyze_collaboration_conflicts(collaboration)


def types(conflicts):
    return [entry["conflict_type"] for entry in conflicts]


class TestCollaborationConflictAnalyzer(unittest.TestCase):
    def test_no_conflicts_for_aligned_inputs(self):
        conflicts = conflicts_for(
            [
                result(AGENT_A, "XSS"),
                result(AGENT_B, "XSS"),
            ]
        )
        self.assertEqual(conflicts, [])

    def test_confidence_conflict_unresolved(self):
        results = [
            result(AGENT_A, "XSS"),
            result(AGENT_B, "SSRF", confidence="LOW"),
        ]
        conflicts = conflicts_for(results)
        confidence = [
            entry for entry in conflicts
            if entry["conflict_type"] == "CONFIDENCE_CONFLICT"
        ]
        self.assertEqual(len(confidence), 1)
        self.assertEqual(confidence[0]["resolution_state"], "UNRESOLVED")
        self.assertEqual(
            confidence[0]["subjects"], [AGENT_A, AGENT_B]
        )
        self.assertEqual(
            confidence[0]["conflicting_fields"], ["result_confidence"]
        )
        self.assertTrue(schema.CONFLICT_ID_RE.match(
            confidence[0]["conflict_id"]
        ))

    def test_confidence_conflict_reconcilable(self):
        sparse = {
            "input_location": "QUERY",
        }
        results = [
            result(AGENT_A, "XSS"),
            result(AGENT_B, "SSRF", confidence="LOW",
                   context_analysis=sparse),
        ]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "CONFIDENCE_CONFLICT"
        ][0]
        self.assertEqual(entry["resolution_state"], "RECONCILABLE")

    def test_confidence_conflict_unknown(self):
        sparse = {"input_location": "QUERY"}
        results = [
            result(AGENT_A, "XSS", confidence="UNKNOWN",
                   context_analysis=sparse),
            result(AGENT_B, "SSRF", confidence="HIGH",
                   context_analysis=sparse),
        ]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "CONFIDENCE_CONFLICT"
        ][0]
        self.assertEqual(entry["resolution_state"], "UNKNOWN")

    def test_context_conflict(self):
        results = [
            result(AGENT_A, "XSS"),
            result(
                AGENT_B, "XSS",
                context_analysis={
                    "input_location": "BODY",
                    "output_context": "HTML",
                },
            ),
        ]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "CONTEXT_CONFLICT"
        ]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["resolution_state"], "UNRESOLVED")
        self.assertIn("input_location", entry[0]["conflicting_fields"])

    def test_context_conflict_reconcilable(self):
        results = [
            result(AGENT_A, "XSS"),
            result(
                AGENT_B, "XSS",
                context_analysis={"extra_a": "1", "extra_b": "2"},
            ),
        ]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "CONTEXT_CONFLICT"
        ][0]
        self.assertEqual(entry["resolution_state"], "RECONCILABLE")

    def test_evidence_state_conflict(self):
        results = [
            result(AGENT_A, "XSS"),
            result(
                AGENT_B, "XSS",
                evidence_plan={
                    "evidence_items": ["REFLECTION_CONTEXT"],
                    "evidence_state": "UNKNOWN",
                    "confidence": "UNKNOWN",
                    "limitations": ["NO_COLLECTION_PERFORMED"],
                },
            ),
        ]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "EVIDENCE_STATE_CONFLICT"
        ]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["resolution_state"], "RECONCILABLE")

    def test_governance_conflict(self):
        results = [
            result(AGENT_A, "XSS"),
            result(
                AGENT_B, "SSRF",
                governance_reference={
                    "rule_version": "",
                    "ready": False,
                    "provenance_state": "UNKNOWN",
                    "trace_state": "UNKNOWN",
                    "audit_state": "UNKNOWN",
                    "explanation_state": "UNKNOWN",
                    "reference_state": "UNKNOWN",
                },
            ),
        ]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "GOVERNANCE_CONFLICT"
        ]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["resolution_state"], "RECONCILABLE")

    def test_provenance_conflict(self):
        results = [
            result(AGENT_A, "XSS"),
            result(
                AGENT_B, "SSRF",
                provenance={
                    "rule_version": "r99-5",
                    "source_layers": [],
                    "provenance_state": "UNKNOWN",
                    "research_only": True,
                },
            ),
        ]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "PROVENANCE_CONFLICT"
        ]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["resolution_state"], "RECONCILABLE")

    def test_safety_conflict_research_only_false(self):
        results = [
            result(AGENT_A, "XSS"),
            result(AGENT_B, "SSRF", research_only=False),
        ]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "SAFETY_CONFLICT"
            and "research_only" in item["conflicting_fields"]
        ]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["resolution_state"], "UNRESOLVED")
        self.assertIn(AGENT_B, entry[0]["subjects"])

    def test_safety_conflict_forbidden_claim(self):
        claimed = result(AGENT_A, "XSS")
        claimed["limitations"] = list(claimed["limitations"]) + [
            "VULNERABILITY_CONFIRMED"
        ]
        results = [claimed, result(AGENT_B, "SSRF")]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "SAFETY_CONFLICT"
        ]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["resolution_state"], "UNRESOLVED")
        self.assertIn(AGENT_A, entry[0]["subjects"])

    def test_hypothesis_conflict(self):
        results = [
            result(AGENT_A, "XSS", hypotheses=[
                hypothesis("TYPE_A", ["S1", "S2"], "HIGH")
            ]),
            result(AGENT_B, "XSS", hypotheses=[
                hypothesis("TYPE_A", ["S2", "S3"], "LOW")
            ]),
        ]
        conflicts = conflicts_for(results)
        entry = [
            item for item in conflicts
            if item["conflict_type"] == "HYPOTHESIS_CONFLICT"
        ]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["resolution_state"], "UNRESOLVED")

    def test_conflicts_ordered_and_deduplicated(self):
        results = [
            result(AGENT_A, "XSS"),
            result(AGENT_B, "XSS", confidence="LOW",
                   research_only=False),
        ]
        conflicts = conflicts_for(results)
        self.assertEqual(len(conflicts), len(set(
            (entry["conflict_type"], tuple(entry["subjects"]))
            for entry in conflicts
        )))
        order = [
            schema.CONFLICT_TYPES.index(entry["conflict_type"])
            for entry in conflicts
        ]
        self.assertEqual(order, sorted(order))

    def test_deterministic_output(self):
        results = [
            result(AGENT_A, "XSS"),
            result(AGENT_B, "SSRF", confidence="LOW"),
        ]
        first = conflicts_for(results)
        second = conflicts_for(results)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        conflicts = conflicts_for(
            [result(AGENT_A, "XSS"), result(AGENT_B, "SSRF",
                                            confidence="LOW")]
        )
        self.assertIsInstance(json.loads(json.dumps(conflicts)), list)

    def test_schema_rejects_bad_values_and_extra(self):
        with self.assertRaises(ValidationError):
            schema.CollaborationConflictRecordPlan(unexpected="x")
        with self.assertRaises(ValidationError):
            schema.CollaborationConflictRecordPlan(
                conflict_type="NOT_A_TYPE"
            )
        with self.assertRaises(ValidationError):
            schema.CollaborationConflictRecordPlan(
                resolution_state="MAYBE"
            )

    def test_schema_forces_rule_version(self):
        plan = schema.CollaborationConflictRecordPlan(
            rule_version="r99-9",
            conflict_type="SAFETY_CONFLICT",
        )
        self.assertEqual(plan.rule_version, "r43-5")

    def test_exact_rule_version(self):
        conflicts = conflicts_for(
            [result(AGENT_A, "XSS"), result(AGENT_B, "SSRF",
                                            confidence="LOW")]
        )
        self.assertEqual(conflicts[0]["rule_version"], "r43-5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
