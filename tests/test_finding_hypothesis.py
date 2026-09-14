"""tests/test_finding_hypothesis.py — Stage R53.3 tests.

Deterministic, offline tests for finding hypothesis linkage:

- hypothesis type/signals/confidence/priority/limitations preservation
- subject reference, rationale and fingerprint preservation
- hypotheses are never invented, merged or promoted
- bounded schemas and deterministic confidence summaries

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.schemas.finding_hypothesis import (
    MAX_HYPOTHESES,
    FindingHypothesisReferencePlan,
    sanitize_finding_hypothesis_linkage,
    sanitize_finding_hypothesis_reference,
)

AGENT_ID = "sa-" + "a" * 16

HYPOTHESIS = {
    "rule_version": "r39-3",
    "hypothesis_type": "REFLECTION_ANALYSIS",
    "supporting_signals": ["REFLECTION_OBSERVED", "OUTPUT_HTML"],
    "confidence": "MEDIUM",
    "priority": "HIGH",
    "limitations": [
        "NO_EXPLOIT_CLAIM",
        "NO_VULNERABILITY_CONFIRMATION",
        "HYPOTHESIS_ONLY",
        "EVIDENCE_REQUIRED",
    ],
    "subject_reference": "query-param:q",
    "rationale": "Reflected input observed in the HTML output context.",
    "fingerprint": "fp-1234",
    "research_only": True,
}


def reference(**over):
    payload = {"agent_id": AGENT_ID, "agent_category": "XSS", **HYPOTHESIS}
    payload.update(over)
    return sanitize_finding_hypothesis_reference(payload)


class TestHypothesisPreservation(unittest.TestCase):
    def test_reference_preserves_all_structured_fields(self):
        projected = reference()
        self.assertEqual(projected["hypothesis_type"], "REFLECTION_ANALYSIS")
        self.assertEqual(
            projected["supporting_signals"],
            ["REFLECTION_OBSERVED", "OUTPUT_HTML"],
        )
        self.assertEqual(projected["confidence"], "MEDIUM")
        self.assertEqual(projected["priority"], "HIGH")
        self.assertIn("HYPOTHESIS_ONLY", projected["limitations"])
        self.assertEqual(projected["subject_reference"], "query-param:q")
        self.assertIn("Reflected input", projected["rationale"])
        self.assertEqual(projected["fingerprint"], "fp-1234")
        self.assertEqual(projected["agent_id"], AGENT_ID)
        self.assertEqual(projected["agent_category"], "XSS")
        self.assertTrue(projected["research_only"])

    def test_linkage_preserves_order_and_count(self):
        linkage = sanitize_finding_hypothesis_linkage(
            {
                "references": [
                    reference(hypothesis_type="TYPE_A"),
                    reference(hypothesis_type="TYPE_B"),
                    reference(hypothesis_type="TYPE_C"),
                ]
            }
        )
        self.assertEqual(linkage["hypothesis_count"], 3)
        self.assertEqual(
            linkage["hypothesis_types"],
            ["TYPE_A", "TYPE_B", "TYPE_C"],
        )
        self.assertEqual(
            [
                item["hypothesis_type"]
                for item in linkage["references"]
            ],
            ["TYPE_A", "TYPE_B", "TYPE_C"],
        )

    def test_empty_linkage_invents_nothing(self):
        linkage = sanitize_finding_hypothesis_linkage({})
        self.assertEqual(linkage["references"], [])
        self.assertEqual(linkage["hypothesis_count"], 0)
        self.assertEqual(linkage["hypothesis_types"], [])
        self.assertEqual(
            linkage["confidence_summary"]["confidence_state"], "UNKNOWN"
        )

    def test_malformed_hypotheses_degrade_to_unknown_not_invented(self):
        projected = sanitize_finding_hypothesis_reference(
            {"hypothesis_type": "lower case!", "confidence": "bogus"}
        )
        self.assertEqual(projected["hypothesis_type"], "UNKNOWN")
        self.assertEqual(projected["confidence"], "UNKNOWN")
        self.assertEqual(projected["priority"], "UNKNOWN")
        self.assertEqual(projected["agent_category"], "UNKNOWN")

    def test_non_dict_reference_is_bounded(self):
        projected = sanitize_finding_hypothesis_reference("nope")
        self.assertEqual(projected["hypothesis_type"], "UNKNOWN")
        self.assertEqual(projected["supporting_signals"], [])

    def test_linkage_is_bounded(self):
        linkage = sanitize_finding_hypothesis_linkage(
            {
                "references": [
                    reference(hypothesis_type=f"TYPE_{index}")
                    for index in range(MAX_HYPOTHESES + 10)
                ]
            }
        )
        self.assertEqual(len(linkage["references"]), MAX_HYPOTHESES)
        self.assertEqual(linkage["hypothesis_count"], MAX_HYPOTHESES)

    def test_confidence_summary_is_deterministic(self):
        consistent = sanitize_finding_hypothesis_linkage(
            {
                "references": [
                    reference(confidence="HIGH"),
                    reference(confidence="HIGH"),
                ],
                "confidence_summary": {
                    "highest_confidence": "HIGH",
                    "lowest_confidence": "HIGH",
                    "confidence_state": "AGREE",
                },
            }
        )["confidence_summary"]
        self.assertEqual(consistent["highest_confidence"], "HIGH")
        self.assertEqual(consistent["lowest_confidence"], "HIGH")
        self.assertEqual(consistent["confidence_state"], "AGREE")
        divergent = sanitize_finding_hypothesis_linkage(
            {
                "references": [
                    reference(confidence="HIGH"),
                    reference(confidence="LOW"),
                ],
                "confidence_summary": {
                    "highest_confidence": "HIGH",
                    "lowest_confidence": "LOW",
                    "confidence_state": "DIVERGENT",
                },
            }
        )["confidence_summary"]
        self.assertEqual(divergent["highest_confidence"], "HIGH")
        self.assertEqual(divergent["lowest_confidence"], "LOW")
        self.assertEqual(divergent["confidence_state"], "DIVERGENT")

    def test_reference_schema_rejects_invalid_values(self):
        with self.assertRaises(ValidationError):
            FindingHypothesisReferencePlan(
                hypothesis_type="bad type", confidence="HIGH"
            )
        with self.assertRaises(ValidationError):
            FindingHypothesisReferencePlan(
                hypothesis_type="TYPE", confidence="BOGUS"
            )
        with self.assertRaises(ValidationError):
            FindingHypothesisReferencePlan(
                hypothesis_type="TYPE", agent_category="BOGUS"
            )
        with self.assertRaises(ValidationError):
            FindingHypothesisReferencePlan(
                hypothesis_type="TYPE", research_only=False
            )

    def test_linkage_projection_is_json_safe(self):
        linkage = sanitize_finding_hypothesis_linkage(
            {"references": [reference()]}
        )
        self.assertIsInstance(json.loads(json.dumps(linkage)), dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
