"""tests/test_finding_evidence.py — Stage R53.4 tests.

Deterministic, offline tests for finding evidence linkage:

- evidence state/confidence preservation
- conservative completeness and origin derivation
- observed facts separated from planned requirements and merged evidence
- merged collaboration requirements attributed to their source agents
- assumptions are never recorded and evidence is never manufactured

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.schemas.finding_evidence import (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_MISSING,
    COMPLETENESS_PARTIAL,
    COMPLETENESS_UNKNOWN,
    ORIGIN_COLLABORATION_MERGED,
    ORIGIN_NONE,
    ORIGIN_SPECIALIST_PLAN,
    FindingEvidencePlan,
    derive_evidence_completeness,
    derive_evidence_origin,
    sanitize_finding_evidence,
)

AGENT_ID = "sa-" + "a" * 16


def merged_item(category="REFLECTION_EVIDENCE", agents=(AGENT_ID,)):
    return {
        "rule_version": "r43-4",
        "evidence_category": category,
        "requirement_state": "REQUIRED",
        "source_agents": list(agents),
        "hypothesis_references": [],
        "source_count": len(agents),
    }


class TestEvidenceCompleteness(unittest.TestCase):
    def test_complete_plan_with_items_is_complete(self):
        self.assertEqual(
            derive_evidence_completeness("COMPLETE", ["A"], []),
            COMPLETENESS_COMPLETE,
        )

    def test_partial_state_is_partial(self):
        self.assertEqual(
            derive_evidence_completeness("PARTIAL", ["A"], []),
            COMPLETENESS_PARTIAL,
        )
        self.assertEqual(
            derive_evidence_completeness("PARTIAL", [], []),
            COMPLETENESS_PARTIAL,
        )

    def test_missing_when_nothing_planned(self):
        self.assertEqual(
            derive_evidence_completeness("UNKNOWN", [], []),
            COMPLETENESS_MISSING,
        )

    def test_complete_without_items_is_unknown_not_complete(self):
        self.assertEqual(
            derive_evidence_completeness("COMPLETE", [], []),
            COMPLETENESS_UNKNOWN,
        )

    def test_origin_derivation(self):
        self.assertEqual(derive_evidence_origin([], []), ORIGIN_NONE)
        self.assertEqual(
            derive_evidence_origin(["A"], []), ORIGIN_SPECIALIST_PLAN
        )
        self.assertEqual(
            derive_evidence_origin([], [merged_item()]),
            ORIGIN_COLLABORATION_MERGED,
        )
        self.assertEqual(
            derive_evidence_origin(["A"], [merged_item()]),
            ORIGIN_COLLABORATION_MERGED,
        )


class TestEvidenceLinkage(unittest.TestCase):
    def test_state_and_confidence_are_preserved(self):
        projected = sanitize_finding_evidence(
            {
                "rule_version": "r40-4",
                "evidence_state": "PARTIAL",
                "planned_requirements": ["HOST_VALIDATION"],
                "observed_context": [
                    {"key": "server_side_fetch", "value": "OBSERVED"}
                ],
            }
        )
        self.assertEqual(projected["rule_version"], "r40-4")
        self.assertEqual(projected["evidence_state"], "PARTIAL")
        self.assertEqual(projected["planned_requirements"], [
            "HOST_VALIDATION"
        ])
        self.assertEqual(
            projected["observed_context"],
            [{"key": "server_side_fetch", "value": "OBSERVED"}],
        )

    def test_observed_planned_and_missing_are_separated(self):
        projected = sanitize_finding_evidence(
            {
                "evidence_state": "COMPLETE",
                "planned_requirements": ["REFLECTION_EVIDENCE"],
                "observed_context": [
                    {"key": "reflection_state", "value": "REFLECTED"}
                ],
                "merged_requirements": [merged_item()],
            }
        )
        self.assertEqual(len(projected["observed_context"]), 1)
        self.assertEqual(
            projected["planned_requirements"], ["REFLECTION_EVIDENCE"]
        )
        self.assertEqual(len(projected["merged_requirements"]), 1)
        self.assertFalse(projected["evidence_missing"])
        self.assertEqual(
            projected["evidence_completeness"], COMPLETENESS_COMPLETE
        )

    def test_evidence_missing_when_nothing_supplied(self):
        projected = sanitize_finding_evidence({})
        self.assertTrue(projected["evidence_missing"])
        self.assertEqual(
            projected["evidence_completeness"], COMPLETENESS_MISSING
        )
        self.assertEqual(projected["evidence_origin"], ORIGIN_NONE)

    def test_merged_requirements_are_bounded_and_attributed(self):
        projected = sanitize_finding_evidence(
            {
                "evidence_state": "PARTIAL",
                "merged_requirements": [
                    merged_item("CATEGORY_A"),
                    merged_item("CATEGORY_B", agents=("sa-" + "b" * 16,)),
                    {"evidence_category": ""},
                ],
            }
        )
        self.assertEqual(len(projected["merged_requirements"]), 2)
        self.assertEqual(
            projected["merged_requirements"][0]["source_agents"], [AGENT_ID]
        )
        self.assertEqual(
            projected["merged_requirements"][0]["evidence_category"],
            "CATEGORY_A",
        )

    def test_references_are_bounded(self):
        projected = sanitize_finding_evidence(
            {
                "evidence_references": [f"ref-{index}" for index in range(50)]
            }
        )
        self.assertEqual(len(projected["evidence_references"]), 16)

    def test_assumptions_are_never_recorded(self):
        projected = sanitize_finding_evidence(
            {"assumptions_recorded": True}
        )
        self.assertFalse(projected["assumptions_recorded"])
        with self.assertRaises(ValidationError):
            FindingEvidencePlan(assumptions_recorded=True)

    def test_schema_rejects_inconsistent_values(self):
        with self.assertRaises(ValidationError):
            FindingEvidencePlan(evidence_state="BOGUS")
        with self.assertRaises(ValidationError):
            FindingEvidencePlan(evidence_completeness="BOGUS")
        with self.assertRaises(ValidationError):
            FindingEvidencePlan(evidence_origin="BOGUS")
        with self.assertRaises(ValidationError):
            FindingEvidencePlan(research_only=False)

    def test_non_dict_is_bounded(self):
        projected = sanitize_finding_evidence("nope")
        self.assertEqual(projected["evidence_state"], "UNKNOWN")
        self.assertTrue(projected["evidence_missing"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
