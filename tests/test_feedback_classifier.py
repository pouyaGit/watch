"""tests/test_feedback_classifier.py — Stage R44.2 tests.

Deterministic, offline tests for the feedback classifier:

- closed classification vocabulary
- safety, governance, provenance, conflict, duplication, confidence,
  evidence, hypothesis, success and unknown classification
- deterministic classification, reasons and signals
- R42/R43 structured integration

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback,
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import (
    build_research_feedback_event,
)
from ai.schemas.agent_evaluation_rule import EVALUATION_DIMENSIONS
from ai.schemas import research_feedback_classification as schema


def evaluation(**over):
    dimensions = [
        {
            "dimension": dimension,
            "score": 90,
            "status": "EXCELLENT",
            "weight": 10,
            "reasons": [],
            "passed_rules": [],
            "failed_rules": [],
        }
        for dimension in EVALUATION_DIMENSIONS
    ]
    base = {
        "rule_version": "r42-5",
        "evaluation_rule_version": "r42-5",
        "evaluated_agent_id": "sa-" + "a" * 16,
        "evaluated_agent_category": "XSS",
        "evaluated_agent_rule_version": "r39-1",
        "evaluated_result_rule_version": "r39-5",
        "overall_score": 90,
        "overall_rating": "EXCELLENT",
        "dimension_scores": dimensions,
        "diagnostics": [],
        "hard_gate_state": "PASS",
        "safety_state": "PASS",
        "applied_caps": [],
        "deterministic": True,
        "research_only": True,
        "limitations": [],
    }
    base.update(over)
    return base


def collaboration(conflict_types=(), duplicate_groups=0,
                  evidence_state="COMPLETE"):
    groups = []
    for index in range(duplicate_groups):
        groups.append(
            {
                "correlation_id": "hg-" + f"{index:016x}",
                "correlation_type": "DUPLICATE",
                "hypothesis_references": [],
                "participating_agents": ["sa-" + "a" * 16],
                "shared_signals": ["S1"],
                "confidence_summary": {
                    "highest_confidence": "HIGH",
                    "lowest_confidence": "HIGH",
                    "confidence_state": "AGREE",
                },
                "member_count": 2,
            }
        )
    conflicts = []
    for index, conflict_type in enumerate(conflict_types):
        conflicts.append(
            {
                "rule_version": "r43-5",
                "conflict_id": "cf-" + f"{index:016x}",
                "conflict_type": conflict_type,
                "subjects": ["sa-" + "a" * 16],
                "conflicting_fields": ["result_confidence"],
                "resolution_state": "UNRESOLVED",
                "message": "conflict",
                "evidence_references": [],
            }
        )
    return {
        "rule_version": "r43-6",
        "collaboration_rule_version": "r43-6",
        "collaboration_id": "collab-" + "a" * 16,
        "participating_agents": [
            {
                "agent_id": "sa-" + "a" * 16,
                "agent_category": "XSS",
                "agent_rule_version": "r39-1",
                "result_rule_version": "r39-5",
                "research_only": True,
                "provenance": {},
            }
        ],
        "hypothesis_groups": groups,
        "merged_evidence": {
            "rule_version": "r43-4",
            "evidence_items": [],
            "evidence_state": evidence_state,
            "confidence": "LOW",
            "limitations": ["NO_COLLECTION_PERFORMED", "EVIDENCE_REQUIRED"],
            "research_only": True,
        },
        "conflicts": conflicts,
        "collaboration_rankings": [],
        "shared_context_summary": {},
        "governance_summary": {},
        "provenance_summary": {},
        "collaboration_diagnostics": [],
        "deterministic": True,
        "research_only": True,
        "limitations": [],
    }


def event(**over):
    kwargs = {
        "source_category": "XSS",
        "outcome_type": "QUALITY_OBSERVATION",
    }
    kwargs.update(over)
    return build_research_feedback_event(**kwargs)


class TestFeedbackClassifier(unittest.TestCase):
    def test_classification_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.CLASSIFICATIONS),
            {"QUALITY_IMPROVEMENT", "CONFIDENCE_CALIBRATION",
             "EVIDENCE_GAP", "HYPOTHESIS_WEAKNESS",
             "DUPLICATION_PATTERN", "CONFLICT_PATTERN",
             "GOVERNANCE_ISSUE", "PROVENANCE_ISSUE", "SAFETY_ISSUE",
             "SUCCESS_PATTERN", "UNKNOWN"},
        )

    def test_safety_issue_from_evaluation(self):
        result = classify_research_feedback(
            event(
                evaluation_result=evaluation(safety_state="FAILED"),
                outcome_type="SAFETY_OBSERVATION",
            )
        )
        self.assertEqual(result["classification"], "SAFETY_ISSUE")
        self.assertIn("SAFETY_STATE_FAILED", result["reasons"])

    def test_safety_issue_from_observed_claim(self):
        result = classify_research_feedback(
            event(
                outcome_type="SAFETY_OBSERVATION",
                observed_issue="ISSUE_FORBIDDEN_CLAIM",
                confidence="HIGH",
            )
        )
        self.assertEqual(result["classification"], "SAFETY_ISSUE")
        self.assertIn("FORBIDDEN_CLAIM", result["reasons"])
        self.assertEqual(result["confidence"], "MEDIUM")

    def test_governance_issue(self):
        result = classify_research_feedback(
            event(
                outcome_type="GOVERNANCE_OBSERVATION",
                observed_issue="ISSUE_UNKNOWN_GOVERNANCE",
                governance_reference={
                    "rule_version": "",
                    "ready": False,
                    "provenance_state": "UNKNOWN",
                    "trace_state": "UNKNOWN",
                    "audit_state": "UNKNOWN",
                    "explanation_state": "UNKNOWN",
                    "reference_state": "UNKNOWN",
                },
            )
        )
        self.assertEqual(result["classification"], "GOVERNANCE_ISSUE")
        self.assertIn("GOVERNANCE_UNKNOWN", result["reasons"])

    def test_provenance_issue(self):
        result = classify_research_feedback(
            event(
                outcome_type="PROVENANCE_OBSERVATION",
                observed_issue="ISSUE_MISSING_PROVENANCE",
            )
        )
        self.assertEqual(result["classification"], "PROVENANCE_ISSUE")
        self.assertIn("PROVENANCE_MISSING", result["reasons"])

    def test_conflict_pattern(self):
        result = classify_research_feedback(
            event(
                collaboration_result=collaboration(
                    conflict_types=("CONFIDENCE_CONFLICT",)
                ),
                outcome_type="CONFLICT_OBSERVATION",
            )
        )
        self.assertEqual(result["classification"], "CONFLICT_PATTERN")
        self.assertIn("CONFLICTS_PRESENT", result["reasons"])

    def test_duplication_pattern(self):
        result = classify_research_feedback(
            event(
                collaboration_result=collaboration(duplicate_groups=2),
                outcome_type="DUPLICATION_OBSERVATION",
            )
        )
        self.assertEqual(result["classification"], "DUPLICATION_PATTERN")
        self.assertIn("DUPLICATE_GROUPS", result["reasons"])

    def test_confidence_calibration(self):
        result = classify_research_feedback(
            event(
                evaluation_result=evaluation(
                    diagnostics=[
                        {
                            "rule_version": "r42-4",
                            "diagnostic_code": "CONFIDENCE_OVERSTATED",
                            "dimension": "CONFIDENCE_CALIBRATION",
                            "severity": "MEDIUM",
                            "message": "m",
                            "evidence_reference": "result_confidence",
                            "remediation_hint": "h",
                        }
                    ]
                ),
                outcome_type="CONFIDENCE_OBSERVATION",
            )
        )
        self.assertEqual(
            result["classification"], "CONFIDENCE_CALIBRATION"
        )
        self.assertIn("CONFIDENCE_MISCALIBRATION", result["reasons"])

    def test_confidence_calibration_from_observed(self):
        result = classify_research_feedback(
            event(
                outcome_type="CONFIDENCE_OBSERVATION",
                observed_issue="ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE",
            )
        )
        self.assertEqual(
            result["classification"], "CONFIDENCE_CALIBRATION"
        )

    def test_evidence_gap(self):
        result = classify_research_feedback(
            event(
                evaluation_result=evaluation(
                    diagnostics=[
                        {
                            "rule_version": "r42-4",
                            "diagnostic_code": (
                                "MISSING_EVIDENCE_REQUIREMENT"
                            ),
                            "dimension": "EVIDENCE_COMPLETENESS",
                            "severity": "MEDIUM",
                            "message": "m",
                            "evidence_reference": "evidence_plan",
                            "remediation_hint": "h",
                        }
                    ]
                ),
                outcome_type="EVIDENCE_OBSERVATION",
            )
        )
        self.assertEqual(result["classification"], "EVIDENCE_GAP")
        self.assertIn("EVIDENCE_GAP", result["reasons"])

    def test_hypothesis_weakness(self):
        result = classify_research_feedback(
            event(
                evaluation_result=evaluation(
                    diagnostics=[
                        {
                            "rule_version": "r42-4",
                            "diagnostic_code": "NO_HYPOTHESES_REPORTED",
                            "dimension": "HYPOTHESIS_SUPPORT",
                            "severity": "MEDIUM",
                            "message": "m",
                            "evidence_reference": "hypotheses",
                            "remediation_hint": "h",
                        }
                    ]
                ),
                outcome_type="HYPOTHESIS_OBSERVATION",
            )
        )
        self.assertEqual(
            result["classification"], "HYPOTHESIS_WEAKNESS"
        )

    def test_success_pattern(self):
        result = classify_research_feedback(
            event(
                evaluation_result=evaluation(),
                outcome_type="SUCCESS_OBSERVATION",
                observed_success="SUCCESS_STRONG_EVALUATION",
                confidence="HIGH",
            )
        )
        self.assertEqual(result["classification"], "SUCCESS_PATTERN")
        self.assertIn("OBSERVED_SUCCESS", result["reasons"])

    def test_success_requires_clean_evaluation(self):
        result = classify_research_feedback(
            event(
                evaluation_result=evaluation(
                    diagnostics=[
                        {
                            "rule_version": "r42-4",
                            "diagnostic_code": "CONTEXT_TOO_SPARSE",
                            "dimension": "CONTEXT_COMPLETENESS",
                            "severity": "LOW",
                            "message": "m",
                            "evidence_reference": "context_analysis",
                            "remediation_hint": "h",
                        }
                    ]
                ),
                outcome_type="SUCCESS_OBSERVATION",
            )
        )
        self.assertNotEqual(
            result["classification"], "SUCCESS_PATTERN"
        )

    def test_quality_improvement(self):
        result = classify_research_feedback(
            event(
                evaluation_result=evaluation(
                    overall_score=40, overall_rating="WEAK"
                ),
                outcome_type="QUALITY_OBSERVATION",
            )
        )
        self.assertEqual(
            result["classification"], "QUALITY_IMPROVEMENT"
        )
        self.assertIn("LOW_QUALITY", result["reasons"])

    def test_unknown_classification(self):
        result = classify_research_feedback(
            event(outcome_type="UNKNOWN")
        )
        self.assertEqual(result["classification"], "UNKNOWN")
        self.assertIn("INSUFFICIENT_DATA", result["reasons"])
        self.assertIn("INSUFFICIENT_DATA", result["limitations"])

    def test_malformed_input(self):
        for bad in (None, "", 42, [], "NOPE"):
            result = classify_research_feedback(bad)
            self.assertEqual(result["classification"], "UNKNOWN")
            self.assertEqual(result["subject"], "UNKNOWN")

    def test_batch_classification_order(self):
        events = [
            event(observed_issue="ISSUE_FORBIDDEN_CLAIM",
                  outcome_type="SAFETY_OBSERVATION"),
            event(observed_issue="ISSUE_MISSING_PROVENANCE",
                  outcome_type="PROVENANCE_OBSERVATION"),
        ]
        results = classify_research_feedback_events(events)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["classification"], "SAFETY_ISSUE")
        self.assertEqual(
            results[1]["classification"], "PROVENANCE_ISSUE"
        )

    def test_deterministic_output(self):
        kwargs = {
            "source_category": "SQLI",
            "outcome_type": "CONFIDENCE_OBSERVATION",
            "observed_issue": "ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE",
        }
        first = classify_research_feedback(event(**kwargs))
        second = classify_research_feedback(event(**kwargs))
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        result = classify_research_feedback(event())
        self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchFeedbackClassificationPlan(
                classification="NOT_A_CLASS"
            )
        with self.assertRaises(ValidationError):
            schema.ResearchFeedbackClassificationPlan(
                reasons=["NOT_A_REASON"]
            )
        with self.assertRaises(ValidationError):
            schema.ResearchFeedbackClassificationPlan(
                classification="SAFETY_ISSUE", unexpected="x"
            )

    def test_exact_rule_version(self):
        result = classify_research_feedback(event())
        self.assertEqual(result["rule_version"], "r44-2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
