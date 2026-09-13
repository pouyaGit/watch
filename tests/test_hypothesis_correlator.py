"""tests/test_hypothesis_correlator.py — Stage R43.3 tests.

Deterministic, offline tests for hypothesis correlation:

- deterministic fingerprints over normalized structured data
- DUPLICATE / RELATED / INDEPENDENT / CONFLICTING grouping
- confidence summaries and shared signals
- duplicate grouping without deletion and full attribution
- deterministic ordering, ids and serialization

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.hypothesis_correlator import (
    correlate_hypotheses,
    hypothesis_fingerprint,
)
from ai.knowledge.multi_agent_collaboration_input import (
    build_multi_agent_collaboration_input,
)
from ai.schemas.hypothesis_correlation import (
    CORRELATION_ID_RE,
    CORRELATION_CONFLICTING,
    CORRELATION_DUPLICATE,
    CORRELATION_INDEPENDENT,
    CORRELATION_RELATED,
)


def hypothesis(
    hypothesis_type,
    signals,
    confidence="HIGH",
    priority=None,
    subject="",
):
    return {
        "rule_version": "r99-3",
        "hypothesis_type": hypothesis_type,
        "supporting_signals": list(signals),
        "confidence": confidence,
        "priority": priority or confidence,
        "limitations": [
            "NO_EXPLOIT_CLAIM",
            "NO_VULNERABILITY_CONFIRMATION",
            "HYPOTHESIS_ONLY",
            "EVIDENCE_REQUIRED",
        ],
        "research_only": True,
        "subject_reference": subject,
    }


def result(agent_id, category, hypotheses):
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
        "hypotheses": hypotheses,
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
            "provenance_state": "PARTIAL",
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


def groups_for(results):
    collaboration = build_multi_agent_collaboration_input(results)
    return correlate_hypotheses(collaboration)


def group_types(groups):
    return [group["correlation_type"] for group in groups]


AGENT_A = "sa-" + "a" * 16
AGENT_B = "sa-" + "b" * 16
AGENT_C = "sa-" + "c" * 16


class TestHypothesisCorrelator(unittest.TestCase):
    def test_fingerprint_is_deterministic(self):
        first = hypothesis_fingerprint(
            "XSS", "REFLECTION_ANALYSIS", ["B", "A"], "sub"
        )
        second = hypothesis_fingerprint(
            "XSS", "REFLECTION_ANALYSIS", ["A", "B"], "sub"
        )
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("fp-"))

    def test_fingerprint_changes_with_structure(self):
        base = hypothesis_fingerprint("XSS", "TYPE_A", ["SIG"], "")
        self.assertNotEqual(
            base, hypothesis_fingerprint("SSRF", "TYPE_A", ["SIG"], "")
        )
        self.assertNotEqual(
            base, hypothesis_fingerprint("XSS", "TYPE_B", ["SIG"], "")
        )
        self.assertNotEqual(
            base, hypothesis_fingerprint("XSS", "TYPE_A", ["OTHER"], "")
        )
        self.assertNotEqual(
            base, hypothesis_fingerprint("XSS", "TYPE_A", ["SIG"], "x")
        )

    def test_duplicate_detection(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["S1", "S2"])
                ]),
                result(AGENT_B, "XSS", [
                    hypothesis("TYPE_A", ["S2", "S1"])
                ]),
            ]
        )
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(group["correlation_type"], CORRELATION_DUPLICATE)
        self.assertEqual(group["member_count"], 2)
        self.assertEqual(
            group["participating_agents"], [AGENT_A, AGENT_B]
        )
        self.assertEqual(group["shared_signals"], ["S1", "S2"])
        self.assertTrue(CORRELATION_ID_RE.match(group["correlation_id"]))

    def test_duplicates_preserve_attribution(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["S1"]),
                    hypothesis("TYPE_A", ["S1"]),
                ]),
            ]
        )
        self.assertEqual(len(groups), 1)
        references = groups[0]["hypothesis_references"]
        self.assertEqual(len(references), 2)
        self.assertEqual(
            [reference["hypothesis_index"] for reference in references],
            [0, 1],
        )
        for reference in references:
            self.assertEqual(reference["agent_id"], AGENT_A)
            self.assertEqual(reference["agent_category"], "XSS")
            self.assertTrue(reference["fingerprint"].startswith("fp-"))

    def test_related_cross_category(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["SHARED_SIGNAL"])
                ]),
                result(AGENT_B, "SSRF", [
                    hypothesis("TYPE_B", ["SHARED_SIGNAL"])
                ]),
            ]
        )
        self.assertEqual(group_types(groups), [CORRELATION_RELATED])
        self.assertEqual(groups[0]["member_count"], 2)
        self.assertEqual(
            groups[0]["shared_signals"], ["SHARED_SIGNAL"]
        )

    def test_related_same_type_different_category(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["S1"])
                ]),
                result(AGENT_B, "SQLI", [
                    hypothesis("TYPE_A", ["S2"])
                ]),
            ]
        )
        self.assertEqual(group_types(groups), [CORRELATION_RELATED])

    def test_independent_detection(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["S1"])
                ]),
                result(AGENT_B, "SSRF", [
                    hypothesis("TYPE_B", ["S2"])
                ]),
            ]
        )
        self.assertEqual(
            group_types(groups),
            [CORRELATION_INDEPENDENT, CORRELATION_INDEPENDENT],
        )
        self.assertTrue(
            all(group["member_count"] == 1 for group in groups)
        )

    def test_conflicting_detection(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["S1", "S2"], "HIGH")
                ]),
                result(AGENT_B, "XSS", [
                    hypothesis("TYPE_A", ["S2", "S3"], "LOW")
                ]),
            ]
        )
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(
            group["correlation_type"], CORRELATION_CONFLICTING
        )
        self.assertEqual(
            group["confidence_summary"]["confidence_state"], "CONFLICT"
        )
        self.assertEqual(
            group["confidence_summary"]["highest_confidence"], "HIGH"
        )
        self.assertEqual(
            group["confidence_summary"]["lowest_confidence"], "LOW"
        )

    def test_confidence_summary_agree(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["S1"], "MEDIUM")
                ]),
                result(AGENT_B, "XSS", [
                    hypothesis("TYPE_A", ["S1"], "MEDIUM")
                ]),
            ]
        )
        self.assertEqual(
            groups[0]["confidence_summary"]["confidence_state"], "AGREE"
        )

    def test_subject_reference_participates(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["S1"], subject="param")
                ]),
                result(AGENT_B, "XSS", [
                    hypothesis("TYPE_A", ["S1"], subject="other")
                ]),
            ]
        )
        self.assertEqual(
            groups[0]["correlation_type"], CORRELATION_RELATED
        )

    def test_every_hypothesis_preserved(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["S1"]),
                    hypothesis("TYPE_B", ["S2"]),
                ]),
                result(AGENT_B, "SSRF", [
                    hypothesis("TYPE_C", ["S3"]),
                ]),
            ]
        )
        total = sum(group["member_count"] for group in groups)
        self.assertEqual(total, 3)
        indexes = [
            (
                reference["agent_id"],
                reference["hypothesis_index"],
            )
            for group in groups
            for reference in group["hypothesis_references"]
        ]
        self.assertEqual(len(indexes), 3)
        self.assertEqual(len(set(indexes)), 3)

    def test_group_ordering_is_canonical(self):
        groups = groups_for(
            [
                result(AGENT_A, "XSS", [
                    hypothesis("TYPE_A", ["S1"]),
                    hypothesis("TYPE_B", ["S2"]),
                ]),
            ]
        )
        self.assertEqual(
            [
                group["hypothesis_references"][0]["hypothesis_index"]
                for group in groups
            ],
            [0, 1],
        )

    def test_deterministic_output(self):
        results = [
            result(AGENT_A, "XSS", [hypothesis("TYPE_A", ["S1"])]),
            result(AGENT_B, "SSRF", [hypothesis("TYPE_B", ["S1"])]),
            result(AGENT_C, "SQLI", [hypothesis("TYPE_C", ["S3"])]),
        ]
        first = groups_for(results)
        second = groups_for(results)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_hypotheses(self):
        groups = groups_for([result(AGENT_A, "XSS", [])])
        self.assertEqual(groups, [])

    def test_json_serializable(self):
        groups = groups_for(
            [result(AGENT_A, "XSS", [hypothesis("TYPE_A", ["S1"])])]
        )
        self.assertIsInstance(json.loads(json.dumps(groups)), list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
