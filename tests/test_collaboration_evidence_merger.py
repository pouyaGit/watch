"""tests/test_collaboration_evidence_merger.py — Stage R43.4 tests.

Deterministic, offline tests for evidence requirement merging:

- merge across agents with equivalence-based deduplication
- source-agent and hypothesis attribution preservation
- complete / partial / unknown merged states
- no-collection limitations preserved
- schema validation, deterministic ordering and serialization

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.collaboration_evidence_merger import (
    merge_collaboration_evidence,
)
from ai.knowledge.multi_agent_collaboration_input import (
    build_multi_agent_collaboration_input,
)
from ai.schemas import collaboration_evidence as schema


def result(agent_id, category, evidence_state, items, hypotheses=None):
    return {
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
        "context_analysis": {"input_location": "QUERY"},
        "hypotheses": hypotheses or [],
        "evidence_plan": {
            "rule_version": "r99-4",
            "evidence_items": list(items),
            "evidence_state": evidence_state,
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
            "provenance_state": "PARTIAL",
            "research_only": True,
        },
        "governance_reference": {
            "rule_version": "r37-5",
            "ready": False,
            "provenance_state": "UNKNOWN",
            "trace_state": "UNKNOWN",
            "audit_state": "UNKNOWN",
            "explanation_state": "UNKNOWN",
            "reference_state": "UNKNOWN",
        },
        "research_only": True,
    }


AGENT_A = "sa-" + "a" * 16
AGENT_B = "sa-" + "b" * 16


def merge(results):
    collaboration = build_multi_agent_collaboration_input(results)
    return merge_collaboration_evidence(collaboration)


class TestCollaborationEvidenceMerger(unittest.TestCase):
    def test_merge_equivalent_categories(self):
        plan = merge(
            [
                result(AGENT_A, "XSS", "COMPLETE", ["REFLECTION_CONTEXT"]),
                result(AGENT_B, "SSRF", "COMPLETE", [
                    "REFLECTION_CONTEXT", "SERVER_FETCH_BEHAVIOR"
                ]),
            ]
        )
        items = {
            item["evidence_category"]: item
            for item in plan["evidence_items"]
        }
        self.assertEqual(len(items), 2)
        reflection = items["REFLECTION_CONTEXT"]
        self.assertEqual(
            reflection["source_agents"], [AGENT_A, AGENT_B]
        )
        self.assertEqual(reflection["source_count"], 2)
        self.assertEqual(
            plan["evidence_state"], "COMPLETE"
        )
        self.assertEqual(plan["confidence"], "HIGH")

    def test_distinct_categories_kept_separate(self):
        plan = merge(
            [
                result(AGENT_A, "XSS", "COMPLETE", ["CONTEXT_A"]),
                result(AGENT_B, "SSRF", "COMPLETE", ["CONTEXT_B"]),
            ]
        )
        self.assertEqual(
            [item["evidence_category"]
             for item in plan["evidence_items"]],
            ["CONTEXT_A", "CONTEXT_B"],
        )

    def test_unknown_item_ignored(self):
        plan = merge(
            [result(AGENT_A, "XSS", "UNKNOWN", ["UNKNOWN"])]
        )
        self.assertEqual(plan["evidence_items"], [])
        self.assertEqual(plan["evidence_state"], "UNKNOWN")
        self.assertEqual(plan["confidence"], "UNKNOWN")
        self.assertIn(
            "INSUFFICIENT_CONTEXT", plan["limitations"]
        )

    def test_partial_state(self):
        plan = merge(
            [
                result(AGENT_A, "XSS", "COMPLETE", ["CONTEXT_A"]),
                result(AGENT_B, "SSRF", "PARTIAL", ["CONTEXT_B"]),
            ]
        )
        self.assertEqual(plan["evidence_state"], "PARTIAL")
        self.assertEqual(plan["confidence"], "LOW")

    def test_requirement_state_upgrades(self):
        plan = merge(
            [
                result(AGENT_A, "XSS", "UNKNOWN", ["CONTEXT_A"]),
                result(AGENT_B, "SSRF", "COMPLETE", ["CONTEXT_A"]),
            ]
        )
        self.assertEqual(
            plan["evidence_items"][0]["requirement_state"], "REQUIRED"
        )

    def test_hypothesis_attribution(self):
        hypotheses = [
            {
                "rule_version": "r99-3",
                "hypothesis_type": "TYPE_A",
                "supporting_signals": ["S1"],
                "confidence": "HIGH",
                "priority": "HIGH",
                "limitations": ["EVIDENCE_REQUIRED"],
                "research_only": True,
            }
        ]
        plan = merge(
            [
                result(
                    AGENT_A, "XSS", "COMPLETE", ["CONTEXT_A"],
                    hypotheses=hypotheses,
                )
            ]
        )
        references = plan["evidence_items"][0][
            "hypothesis_references"
        ]
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["agent_id"], AGENT_A)
        self.assertEqual(references[0]["hypothesis_index"], 0)
        self.assertEqual(references[0]["hypothesis_type"], "TYPE_A")

    def test_limitations_always_present(self):
        plan = merge(
            [result(AGENT_A, "XSS", "COMPLETE", ["CONTEXT_A"])]
        )
        for limitation in (
            "NO_COLLECTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_DATABASE_ACCESS",
            "EVIDENCE_REQUIRED",
        ):
            self.assertIn(limitation, plan["limitations"])

    def test_empty_input(self):
        plan = merge([])
        self.assertEqual(plan["evidence_state"], "UNKNOWN")
        self.assertEqual(plan["evidence_items"], [])
        self.assertIn(
            "INSUFFICIENT_CONTEXT", plan["limitations"]
        )

    def test_deterministic_output(self):
        results = [
            result(AGENT_A, "XSS", "COMPLETE", ["CONTEXT_A"]),
            result(AGENT_B, "SSRF", "COMPLETE", ["CONTEXT_A"]),
        ]
        first = merge(results)
        second = merge(results)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = merge(
            [result(AGENT_A, "XSS", "COMPLETE", ["CONTEXT_A"])]
        )
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_schema_rejects_bad_values_and_extra(self):
        with self.assertRaises(ValidationError):
            schema.CollaborationEvidencePlan(unexpected="x")
        with self.assertRaises(ValidationError):
            schema.CollaborationEvidencePlan(research_only=False)
        with self.assertRaises(ValidationError):
            schema.CollaborationEvidencePlan(evidence_state="DONE")
        with self.assertRaises(ValidationError):
            schema.CollaborationEvidenceItemPlan(
                evidence_category="bad lower"
            )

    def test_schema_forces_rule_version(self):
        plan = schema.CollaborationEvidencePlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r43-4")
        self.assertEqual(
            merge([])["rule_version"], "r43-4"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
