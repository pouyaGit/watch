"""tests/test_continuous_learning.py — Stage R57 builder and integration tests.

Deterministic, offline tests for continuous-learning building:

- human decision integration (every decision type) and workflow-feedback
  semantics (never truth labels)
- evidence-gap, duplication, conflict, confidence, hypothesis and priority
  learning families
- cross-layer corroboration (R42/R43/R44/R53/R54/R55/R56)
- specialist/category aggregation and successful-pattern preservation
- deterministic output, stable ids, shuffled-input equivalence
- empty/minimal/malformed/unsupported input handling
- safety rejection of forbidden autonomous/execution requests
- advisory-only invariants and input immutability
- R42 -> R57 and full R42-R56 integration

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_orchestrator import orchestrate_research
from ai.knowledge.continuous_learning import (
    aggregate_learning_patterns,
    build_calibration_recommendations,
    build_continuous_learning_result,
    build_learning_signals,
    export_continuous_learning,
)
from ai.knowledge.finding_builder import build_finding_intelligence
from ai.knowledge.finding_correlation import correlate_findings
from ai.knowledge.human_review import create_human_review
from ai.knowledge.research_prioritization import prioritize_findings
from ai.schemas.agent_evaluation_diagnostic import (
    CONFIDENCE_OVERSTATED,
    MISSING_EVIDENCE_REQUIREMENT,
)
from ai.schemas.continuous_learning import (
    SIGNAL_HUMAN_APPROVED_RESEARCH,
    SIGNAL_HUMAN_DEFERRED_RESEARCH,
    SIGNAL_HUMAN_ESCALATED_RESEARCH,
    SIGNAL_HUMAN_REJECTED_WORKFLOW,
    SIGNAL_HUMAN_REQUESTED_EVIDENCE,
    SIGNAL_HUMAN_REVIEW_REQUIRED,
    SIGNAL_REPEATED_EVIDENCE_GAP,
    SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    SOURCE_LAYER_R42,
    SOURCE_LAYER_R53,
    SOURCE_LAYER_R54,
    SOURCE_LAYER_R55,
    SOURCE_LAYER_R56,
)
from ai.schemas.continuous_learning_result import (
    CONTINUOUS_LEARNING_STATUSES,
    ERROR_SAFETY_BLOCKED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_SIGNALS,
    STATUS_PARTIAL,
)
from ai.schemas.learning_pattern import (
    INDICATOR_CONFIDENCE_OVERESTIMATION,
    INDICATOR_SUCCESS_PATTERN,
    PATTERN_CONFLICT,
    PATTERN_DUPLICATION,
    PATTERN_EVIDENCE_GAP,
    PATTERN_PRIORITY_ALIGNMENT,
    PATTERN_SPECIALIST_RELIABILITY,
    PATTERN_SUCCESS,
    PATTERN_WORKFLOW_FEEDBACK,
)
from tests.test_research_priority import (
    conflicting_findings,
    critical_finding,
    duplicate_findings,
)
from tests.test_research_priority_rules import finding

FINDING_ONE = "fnd-" + "1" * 16
FINDING_TWO = "fnd-" + "2" * 16
AGENT_A = "sa-" + "a" * 16
AGENT_B = "sa-" + "b" * 16


def evaluation(
    *,
    agent_id=AGENT_A,
    category="XSS",
    overall_rating="ACCEPTABLE",
    safety="PASS",
    gate="PASS",
    diagnostics=None,
):
    return {
        "rule_version": "r42-5",
        "evaluated_agent_id": agent_id,
        "evaluated_agent_category": category,
        "overall_rating": overall_rating,
        "safety_state": safety,
        "hard_gate_state": gate,
        "diagnostics": list(diagnostics or ()),
    }


def diagnostic(code, severity="MEDIUM"):
    return {
        "rule_version": "r42-4",
        "diagnostic_code": code,
        "dimension": "EVIDENCE_COMPLETENESS",
        "severity": severity,
        "message": "",
    }


def finding_intelligence(findings):
    return {"rule_version": "r53-6", "findings": list(findings)}


def pipeline(findings, decisions=None, correlation_result=None):
    correlation = correlation_result or correlate_findings(findings)
    prioritization = prioritize_findings(
        findings, correlation_result=correlation
    )
    review = create_human_review(
        prioritization_result=prioritization,
        correlation_result=correlation,
        decisions=decisions,
    )
    return correlation, prioritization, review


def signal_types(result):
    return [signal["signal_type"] for signal in result["signals"]]


def pattern_types(result):
    return [pattern["pattern_type"] for pattern in result["patterns"]]


def recommendations_for(result, code):
    return [
        recommendation
        for recommendation in result["calibration_recommendations"]
        if recommendation["recommendation_code"] == code
    ]


class TestEmptyAndMalformed(unittest.TestCase):
    def test_empty_input_is_no_signals(self):
        result = build_continuous_learning_result()
        self.assertEqual(result["status"], STATUS_NO_SIGNALS)
        self.assertEqual(result["signals"], [])
        self.assertEqual(result["patterns"], [])
        self.assertEqual(result["calibration_recommendations"], [])
        self.assertTrue(result["advisory"])
        self.assertTrue(result["human_authority"])
        self.assertFalse(result["auto_applies"])
        self.assertFalse(result["execution_authorized"])
        self.assertIn("INSUFFICIENT_DATA", result["limitations"])

    def test_wrong_orchestration_type_fails_closed(self):
        result = build_continuous_learning_result(orchestration_result=42)
        self.assertEqual(result["status"], STATUS_FAILED)

    def test_wrong_orchestration_version_fails_closed(self):
        result = build_continuous_learning_result(
            orchestration_result={"rule_version": "r99-9"}
        )
        self.assertEqual(result["status"], STATUS_FAILED)

    def test_wrong_evaluation_container_fails_closed(self):
        result = build_continuous_learning_result(evaluation_results="x")
        self.assertEqual(result["status"], STATUS_FAILED)

    def test_orchestration_plus_standalone_fails_closed(self):
        orchestration = orchestrate_research(
            research_context={"output_context": "HTML"}
        )
        result = build_continuous_learning_result(
            orchestration_result=orchestration,
            evaluation_results=[evaluation()],
        )
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_INPUT"
        )

    def test_mis_versioned_layer_input_is_skipped(self):
        result = build_continuous_learning_result(
            finding_intelligence={"rule_version": "r99-9", "findings": []}
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertEqual(
            result["skipped_inputs"][0]["reason"], "RULE_VERSION_MISMATCH"
        )

    def test_malformed_layer_input_is_skipped(self):
        result = build_continuous_learning_result(
            human_review_result="not-a-mapping"
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertEqual(
            result["skipped_inputs"][0]["reason"], "MALFORMED_INPUT"
        )

    def test_malformed_evaluation_entries_are_skipped(self):
        result = build_continuous_learning_result(
            evaluation_results=[None, "x", evaluation()]
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        skipped = {
            item["reason"] for item in result["skipped_inputs"]
        }
        self.assertIn("MALFORMED_INPUT", skipped)

    def test_status_vocabulary_is_closed(self):
        result = build_continuous_learning_result()
        self.assertIn(result["status"], CONTINUOUS_LEARNING_STATUSES)
        self.assertEqual(result["rule_version"], "r57-4")


class TestHumanDecisionIntegration(unittest.TestCase):
    def decision_result(self, decision_type, rationale_codes=None):
        raw = finding("XSS", AGENT_A, finding_id_value=FINDING_ONE)
        correlation, prioritization, _ = pipeline([raw])
        decision = {
            "finding_id": FINDING_ONE,
            "decision_type": decision_type,
        }
        if rationale_codes:
            decision["rationale_codes"] = list(rationale_codes)
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[decision],
        )
        return build_continuous_learning_result(
            prioritization_result=prioritization,
            correlation_result=correlation,
            human_review_result=review,
        )

    def assert_workflow_signal(self, result, signal_type):
        matches = [
            signal
            for signal in result["signals"]
            if signal["signal_type"] == signal_type
        ]
        self.assertEqual(len(matches), 1)
        signal = matches[0]
        self.assertEqual(signal["source_layer"], SOURCE_LAYER_R56)
        self.assertEqual(signal["feedback_kind"], "WORKFLOW_FEEDBACK")
        self.assertTrue(signal["workflow_feedback"])
        self.assertFalse(signal["truth_label"])
        self.assertEqual(signal["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(signal["execution_authorized"])
        self.assertTrue(signal["decision_context"]["present"])
        self.assertEqual(
            signal["decision_context"]["decision_source"], "HUMAN"
        )
        self.assertEqual(
            signal["decision_context"]["decision_authority"], "HUMAN"
        )
        self.assertTrue(signal["decision_context"]["human_authority"])
        self.assertFalse(
            signal["decision_context"]["vulnerability_confirmed"]
        )
        return signal

    def test_approve_research_is_positive_workflow_feedback(self):
        result = self.decision_result("APPROVE_RESEARCH")
        signal = self.assert_workflow_signal(
            result, SIGNAL_HUMAN_APPROVED_RESEARCH
        )
        self.assertEqual(signal["observation"], "SUCCESS")
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(result["vulnerability_confirmed"])

    def test_request_more_evidence_is_evidence_gap_feedback(self):
        result = self.decision_result(
            "REQUEST_MORE_EVIDENCE", ["EVIDENCE_INCOMPLETE"]
        )
        self.assert_workflow_signal(result, SIGNAL_HUMAN_REQUESTED_EVIDENCE)
        self.assert_workflow_signal(result, SIGNAL_REPEATED_EVIDENCE_GAP)

    def test_defer_is_workflow_deferral(self):
        result = self.decision_result("DEFER")
        self.assert_workflow_signal(result, SIGNAL_HUMAN_DEFERRED_RESEARCH)

    def test_reject_is_rejected_direction(self):
        result = self.decision_result("REJECT")
        self.assert_workflow_signal(result, SIGNAL_HUMAN_REJECTED_WORKFLOW)

    def test_escalate_is_escalation_feedback(self):
        result = self.decision_result("ESCALATE")
        self.assert_workflow_signal(result, SIGNAL_HUMAN_ESCALATED_RESEARCH)

    def test_needs_review_is_review_requirement(self):
        result = self.decision_result("NEEDS_REVIEW")
        self.assert_workflow_signal(result, SIGNAL_HUMAN_REVIEW_REQUIRED)

    def test_approval_does_not_make_a_finding_true(self):
        raw = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_ONE,
            confidence="LOW",
            state="EVIDENCE_SUPPORTED",
        )
        correlation, prioritization, _ = pipeline([raw])
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "APPROVE_RESEARCH",
                    "rationale_codes": ["EVIDENCE_SUFFICIENT"],
                }
            ],
        )
        result = build_continuous_learning_result(
            prioritization_result=prioritization,
            correlation_result=correlation,
            human_review_result=review,
        )
        for signal in result["signals"]:
            self.assertFalse(signal["truth_label"])
            self.assertEqual(signal["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertIn(
            "HUMAN_DECISION_NOT_TRUTH_LABEL", result["limitations"]
        )

    def test_single_human_signal_is_conservative(self):
        result = self.decision_result("DEFER")
        workflow = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == PATTERN_WORKFLOW_FEEDBACK
        ]
        self.assertEqual(workflow, [])

    def test_two_human_decisions_form_workflow_pattern(self):
        first = finding("XSS", AGENT_A, finding_id_value=FINDING_ONE)
        second = finding("XSS", AGENT_B, finding_id_value=FINDING_TWO)
        correlation = correlate_findings([first, second])
        prioritization = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "DEFER",
                    "rationale_codes": ["CONFLICT_REQUIRES_RESOLUTION"],
                },
                {
                    "finding_id": FINDING_TWO,
                    "decision_type": "DEFER",
                    "rationale_codes": ["CONFLICT_REQUIRES_RESOLUTION"],
                },
            ],
        )
        result = build_continuous_learning_result(
            prioritization_result=prioritization,
            correlation_result=correlation,
            human_review_result=review,
        )
        workflow = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == PATTERN_WORKFLOW_FEEDBACK
        ]
        self.assertEqual(len(workflow), 1)
        self.assertEqual(
            workflow[0]["calibration_recommendation_codes"],
            ["REVIEW_HUMAN_FEEDBACK"],
        )
        self.assertTrue(
            recommendations_for(result, "REVIEW_HUMAN_FEEDBACK")
        )
        self.assertEqual(result["summary"]["human_decision_count"], 2)


class TestLearningFamilies(unittest.TestCase):
    def test_evidence_gap_cross_layer_pattern(self):
        r42 = [evaluation(diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)])]
        raw = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_ONE,
            evidence_state="UNKNOWN",
            evidence_completeness="MISSING",
            evidence_requirements=None,
            state="NEEDS_MORE_EVIDENCE",
        )
        correlation, prioritization, _ = pipeline([raw])
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "REQUEST_MORE_EVIDENCE",
                    "rationale_codes": ["EVIDENCE_INCOMPLETE"],
                }
            ],
        )
        result = build_continuous_learning_result(
            evaluation_results=r42,
            finding_intelligence=finding_intelligence([raw]),
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )
        patterns = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == PATTERN_EVIDENCE_GAP
        ]
        self.assertEqual(len(patterns), 1)
        self.assertGreaterEqual(patterns[0]["cross_layer_support"], 3)
        self.assertEqual(patterns[0]["evidence_strength"], "STRONG")
        self.assertTrue(
            recommendations_for(result, "REQUEST_MORE_EVIDENCE")
        )

    def test_duplication_pattern_across_layers(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "DEFER",
                    "rationale_codes": ["DUPLICATE_RESEARCH_OVERLAP"],
                }
            ],
        )
        result = build_continuous_learning_result(
            finding_intelligence=finding_intelligence([first, second]),
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )
        patterns = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == PATTERN_DUPLICATION
        ]
        self.assertEqual(len(patterns), 1)
        self.assertGreaterEqual(patterns[0]["cross_layer_support"], 3)
        self.assertIn(
            SOURCE_LAYER_R54, patterns[0]["source_layers"]
        )
        self.assertIn(SOURCE_LAYER_R56, patterns[0]["source_layers"])
        self.assertTrue(
            recommendations_for(result, "REVIEW_DUPLICATION")
        )

    def test_conflict_pattern(self):
        first, second = conflicting_findings()
        correlation = correlate_findings([first, second])
        prioritization = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        result = build_continuous_learning_result(
            correlation_result=correlation,
            prioritization_result=prioritization,
        )
        patterns = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == PATTERN_CONFLICT
        ]
        self.assertEqual(len(patterns), 1)
        self.assertIn(
            SOURCE_LAYER_R54, patterns[0]["source_layers"]
        )
        self.assertIn(
            SOURCE_LAYER_R55, patterns[0]["source_layers"]
        )
        self.assertTrue(recommendations_for(result, "REVIEW_CONFLICT"))

    def test_confidence_overestimation_pattern(self):
        first = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_ONE,
            confidence="HIGH",
            evidence_completeness="PARTIAL",
            evidence_state="PARTIAL",
        )
        second = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_TWO,
            confidence="HIGH",
            evidence_completeness="PARTIAL",
            evidence_state="PARTIAL",
        )
        result = build_continuous_learning_result(
            finding_intelligence=finding_intelligence([first, second])
        )
        patterns = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == "CONFIDENCE_CALIBRATION_PATTERN"
        ]
        self.assertEqual(len(patterns), 1)
        self.assertEqual(
            patterns[0]["calibration_indicator"],
            INDICATOR_CONFIDENCE_OVERESTIMATION,
        )
        self.assertTrue(
            recommendations_for(result, "REDUCE_CONFIDENCE")
        )

    def test_hypothesis_weakness_pattern(self):
        first = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_ONE,
            state="INSUFFICIENT_EVIDENCE",
            confidence="UNKNOWN",
            evidence_requirements=None,
            evidence_state="UNKNOWN",
            evidence_completeness="MISSING",
        )
        second = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_TWO,
            state="INSUFFICIENT_EVIDENCE",
            confidence="UNKNOWN",
            evidence_requirements=None,
            evidence_state="UNKNOWN",
            evidence_completeness="MISSING",
        )
        result = build_continuous_learning_result(
            finding_intelligence=finding_intelligence([first, second])
        )
        self.assertIn(
            SIGNAL_REPEATED_WEAK_HYPOTHESIS, signal_types(result)
        )
        self.assertTrue(
            recommendations_for(result, "REVIEW_HYPOTHESIS")
        )

    def test_prioritization_alignment_pattern(self):
        first = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_ONE,
            evidence_completeness="COMPLETE",
            state="EVIDENCE_SUPPORTED",
            confidence="UNKNOWN",
            impact_state="UNKNOWN",
            orchestration_id="",
        )
        second = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_TWO,
            evidence_completeness="COMPLETE",
            state="EVIDENCE_SUPPORTED",
            confidence="UNKNOWN",
            impact_state="UNKNOWN",
            orchestration_id="",
        )
        prioritization = prioritize_findings([first, second])
        result = build_continuous_learning_result(
            prioritization_result=prioritization
        )
        patterns = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == PATTERN_PRIORITY_ALIGNMENT
        ]
        self.assertEqual(len(patterns), 1)
        self.assertTrue(
            recommendations_for(result, "REVIEW_PRIORITY_ALIGNMENT")
        )

    def test_success_pattern_preservation(self):
        raw = critical_finding(FINDING_ONE)
        correlation, prioritization, _ = pipeline([raw])
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "APPROVE_RESEARCH",
                    "rationale_codes": ["EVIDENCE_SUFFICIENT"],
                }
            ],
        )
        success_feedback = {
            "rule_version": "r52-5",
            "classifications": [
                {
                    "rule_version": "r44-2",
                    "classification": "SUCCESS_PATTERN",
                    "subject": "XSS",
                    "source_agent": AGENT_A,
                    "feedback_id": "",
                    "reasons": [],
                    "supporting_signals": [],
                    "confidence": "UNKNOWN",
                    "limitations": [],
                }
            ],
            "learning_signals": [],
            "recommendations": [],
            "events": [],
        }
        result = build_continuous_learning_result(
            feedback_result=success_feedback,
            prioritization_result=prioritization,
            correlation_result=correlation,
            human_review_result=review,
        )
        patterns = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == PATTERN_SUCCESS
        ]
        self.assertEqual(len(patterns), 1)
        self.assertEqual(
            patterns[0]["calibration_indicator"],
            INDICATOR_SUCCESS_PATTERN,
        )
        self.assertTrue(
            recommendations_for(result, "PRESERVE_SUCCESS_PATTERN")
        )

    def test_specialist_reliability_pattern(self):
        result = build_continuous_learning_result(
            evaluation_results=[
                evaluation(
                    agent_id=AGENT_A,
                    overall_rating="GOOD",
                    safety="PASS",
                ),
                evaluation(
                    agent_id=AGENT_B,
                    overall_rating="EXCELLENT",
                    safety="PASS",
                ),
            ]
        )
        patterns = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == PATTERN_SPECIALIST_RELIABILITY
        ]
        self.assertEqual(len(patterns), 1)
        self.assertEqual(
            patterns[0]["pattern_type"], PATTERN_SPECIALIST_RELIABILITY
        )
        self.assertTrue(
            recommendations_for(
                result, "REVIEW_SPECIALIST_RELIABILITY"
            )
        )

    def test_category_aggregation_is_separate(self):
        result = build_continuous_learning_result(
            evaluation_results=[
                evaluation(
                    agent_id=AGENT_A,
                    category="XSS",
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                ),
                evaluation(
                    agent_id="sa-" + "c" * 16,
                    category="XSS",
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                ),
                evaluation(
                    agent_id=AGENT_B,
                    category="SSRF",
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                ),
                evaluation(
                    agent_id="sa-" + "d" * 16,
                    category="SSRF",
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                ),
            ]
        )
        patterns = [
            pattern
            for pattern in result["patterns"]
            if pattern["pattern_type"] == PATTERN_EVIDENCE_GAP
        ]
        self.assertEqual(
            sorted(pattern["category"] for pattern in patterns),
            ["SSRF", "XSS"],
        )


class TestSafetyRejection(unittest.TestCase):
    def test_execution_authorized_evaluation_is_skipped(self):
        unsafe = evaluation()
        unsafe["execution_authorized"] = True
        result = build_continuous_learning_result(
            evaluation_results=[unsafe, evaluation(agent_id=AGENT_B)]
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertTrue(
            any(
                error["error_category"] == ERROR_SAFETY_BLOCKED
                for error in result["errors"]
            )
        )
        self.assertEqual(
            result["skipped_inputs"][0]["reason"], "SAFETY_BLOCKED"
        )

    def test_payload_text_is_skipped(self):
        result = build_continuous_learning_result(
            collaboration_result={
                "rule_version": "r43-6",
                "note": "GENERATE_PAYLOAD then BYPASS_HUMAN",
            }
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertEqual(
            result["skipped_inputs"][0]["reason"], "SAFETY_BLOCKED"
        )

    def test_safe_negative_codes_are_not_rejected(self):
        result = build_continuous_learning_result(
            collaboration_result={
                "rule_version": "r43-6",
                "limitations": [
                    "NO_EXECUTION_PERFORMED",
                    "NO_PAYLOAD_GENERATION",
                    "ATTACK_PLANNING_NOT_AUTHORIZED",
                ],
                "conflicts": [],
                "hypothesis_groups": [],
            }
        )
        self.assertEqual(result["skipped_inputs"], [])
        self.assertEqual(result["status"], STATUS_NO_SIGNALS)

    def test_unsafe_input_never_becomes_a_recommendation(self):
        unsafe = evaluation()
        unsafe["modifies_thresholds"] = True
        result = build_continuous_learning_result(
            evaluation_results=[unsafe]
        )
        self.assertEqual(result["signals"], [])
        self.assertEqual(result["calibration_recommendations"], [])
        self.assertTrue(result["advisory"])
        self.assertFalse(result["auto_applies"])


class TestDeterminismAndImmutability(unittest.TestCase):
    def full_inputs(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "REQUEST_MORE_EVIDENCE",
                    "rationale_codes": ["EVIDENCE_INCOMPLETE"],
                }
            ],
        )
        return {
            "evaluation_results": [
                evaluation(
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)]
                )
            ],
            "finding_intelligence": finding_intelligence([first, second]),
            "correlation_result": correlation,
            "prioritization_result": prioritization,
            "human_review_result": review,
        }

    def test_byte_identical_output(self):
        inputs = self.full_inputs()
        first = build_continuous_learning_result(**inputs)
        second = build_continuous_learning_result(**inputs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertEqual(first["learning_id"], second["learning_id"])

    def test_shuffled_evaluation_order_is_stable(self):
        first_inputs = self.full_inputs()
        evaluations = first_inputs["evaluation_results"] + [
            evaluation(
                agent_id=AGENT_B,
                diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
            )
        ]
        forward = build_continuous_learning_result(
            **{**first_inputs, "evaluation_results": evaluations}
        )
        backward = build_continuous_learning_result(
            **{
                **first_inputs,
                "evaluation_results": list(reversed(evaluations)),
            }
        )
        self.assertEqual(
            json.dumps(forward, sort_keys=True),
            json.dumps(backward, sort_keys=True),
        )

    def test_ids_are_stable_across_calls(self):
        inputs = self.full_inputs()
        first = build_continuous_learning_result(**inputs)
        second = build_continuous_learning_result(**inputs)
        self.assertEqual(
            [signal["signal_id"] for signal in first["signals"]],
            [signal["signal_id"] for signal in second["signals"]],
        )
        self.assertEqual(
            [pattern["pattern_id"] for pattern in first["patterns"]],
            [pattern["pattern_id"] for pattern in second["patterns"]],
        )

    def test_inputs_are_not_mutated(self):
        inputs = self.full_inputs()
        snapshot = {
            key: json.dumps(value, sort_keys=True)
            for key, value in inputs.items()
        }
        build_continuous_learning_result(**inputs)
        for key, value in inputs.items():
            self.assertEqual(
                json.dumps(value, sort_keys=True), snapshot[key], key
            )

    def test_signals_are_canonically_sorted(self):
        inputs = self.full_inputs()
        result = build_continuous_learning_result(**inputs)
        signal_ids = [
            signal["signal_id"] for signal in result["signals"]
        ]
        self.assertEqual(signal_ids, sorted(signal_ids))


class TestAdvisoryOnly(unittest.TestCase):
    def test_result_flags_are_advisory(self):
        inputs = TestDeterminismAndImmutability().full_inputs()
        result = build_continuous_learning_result(**inputs)
        self.assertTrue(result["advisory"])
        self.assertTrue(result["human_authority"])
        self.assertFalse(result["auto_applies"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(result["research_only"])
        self.assertTrue(result["deterministic"])

    def test_recommendations_never_modify_behavior(self):
        inputs = TestDeterminismAndImmutability().full_inputs()
        result = build_continuous_learning_result(**inputs)
        for recommendation in result["calibration_recommendations"]:
            self.assertTrue(recommendation["advisory"])
            self.assertFalse(recommendation["auto_applies"])
            self.assertFalse(recommendation["modifies_agents"])
            self.assertFalse(recommendation["modifies_rules"])
            self.assertFalse(recommendation["modifies_thresholds"])
            self.assertFalse(recommendation["modifies_strategies"])
            self.assertFalse(recommendation["execution_authorized"])
            self.assertTrue(recommendation["safety_boundary_preserved"])
            self.assertTrue(recommendation["human_authority_preserved"])
            self.assertIn(
                "FUTURE_STAGE_REQUIRED", recommendation["limitations"]
            )

    def test_patterns_never_modify_behavior(self):
        inputs = TestDeterminismAndImmutability().full_inputs()
        result = build_continuous_learning_result(**inputs)
        for pattern in result["patterns"]:
            self.assertTrue(pattern["advisory"])
            self.assertFalse(pattern["auto_applies"])
            self.assertFalse(pattern["modifies_agents"])
            self.assertFalse(pattern["modifies_rules"])


class TestProvenanceAndGovernance(unittest.TestCase):
    def test_provenance_preserves_upstream_ids(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"}
            ],
        )
        result = build_continuous_learning_result(
            finding_intelligence=finding_intelligence([first, second]),
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )
        provenance = result["provenance"]
        self.assertIn(
            prioritization["prioritization_id"],
            provenance["prioritization_ids"],
        )
        self.assertIn(
            correlation["correlation_id"], provenance["correlation_ids"]
        )
        self.assertTrue(provenance["finding_rule_versions"])
        self.assertTrue(provenance["decision_ids"])
        self.assertTrue(provenance["deterministic"])

    def test_signal_provenance_is_preserved(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        result = build_continuous_learning_result(
            correlation_result=correlation,
            prioritization_result=prioritization,
        )
        r54_signals = [
            signal
            for signal in result["signals"]
            if signal["source_layer"] == SOURCE_LAYER_R54
        ]
        self.assertTrue(r54_signals)
        for signal in r54_signals:
            self.assertEqual(
                signal["provenance"]["correlation_id"],
                correlation["correlation_id"],
            )
            self.assertEqual(
                signal["provenance"]["correlation_rule_version"], "r54-1"
            )

    def test_governance_is_preserved_from_findings(self):
        first, second = duplicate_findings()
        result = build_continuous_learning_result(
            finding_intelligence=finding_intelligence([first, second])
        )
        governance = result["governance"]
        self.assertIn(
            governance["governance_state"],
            ("UNKNOWN", "MIXED", "CONSISTENT_REFERENCED"),
        )
        referenced = [
            signal
            for signal in result["signals"]
            if signal["finding_id"] and signal["governance"]
        ]
        self.assertTrue(referenced)
        for signal in referenced:
            self.assertIn(
                "reference_state", signal["governance"]
            )


class TestIntegration(unittest.TestCase):
    def test_full_pipeline_integration(self):
        orchestration = orchestrate_research(
            research_context={
                "output_context": "HTML",
                "reflection_state": "REFLECTED",
            }
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        correlation = correlate_findings(intelligence["findings"])
        prioritization = prioritize_findings(
            intelligence["findings"], correlation_result=correlation
        )
        finding_id = prioritization["ranked_findings"][0]["finding_id"]
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": finding_id,
                    "decision_type": "REQUEST_MORE_EVIDENCE",
                    "rationale_codes": ["EVIDENCE_INCOMPLETE"],
                }
            ],
        )
        result = build_continuous_learning_result(
            orchestration_result=orchestration,
            finding_intelligence=intelligence,
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )
        self.assertEqual(result["status"], STATUS_COMPLETED)
        self.assertGreaterEqual(len(result["signals"]), 1)
        layers = result["provenance"]["source_layers"]
        self.assertIn(SOURCE_LAYER_R42, layers)
        self.assertIn(SOURCE_LAYER_R53, layers)
        self.assertIn(SOURCE_LAYER_R55, layers)
        self.assertIn(SOURCE_LAYER_R56, layers)
        self.assertEqual(result["summary"]["human_decision_count"], 1)
        self.assertTrue(
            recommendations_for(result, "REQUEST_MORE_EVIDENCE")
        )

    def test_stage_apis_are_equivalent_to_full_result(self):
        inputs = {
            "evaluation_results": [
                evaluation(
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)]
                ),
                evaluation(
                    agent_id=AGENT_B,
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                ),
            ]
        }
        full = build_continuous_learning_result(**inputs)
        staged = build_calibration_recommendations(**inputs)
        self.assertEqual(
            json.dumps(full, sort_keys=True),
            json.dumps(staged, sort_keys=True),
        )
        patterns_only = aggregate_learning_patterns(**inputs)
        self.assertEqual(
            patterns_only["calibration_recommendations"], []
        )
        signals_only = build_learning_signals(**inputs)
        self.assertEqual(signals_only["patterns"], [])

    def test_export_alias(self):
        inputs = {
            "evaluation_results": [
                evaluation(
                    diagnostics=[diagnostic(CONFIDENCE_OVERSTATED)]
                )
            ]
        }
        self.assertEqual(
            json.dumps(
                export_continuous_learning(**inputs), sort_keys=True
            ),
            json.dumps(
                build_continuous_learning_result(**inputs), sort_keys=True
            ),
        )

    def test_minimal_standalone_layer_input(self):
        raw = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_ONE,
            evidence_completeness="PARTIAL",
            evidence_state="PARTIAL",
        )
        result = build_continuous_learning_result(
            finding_intelligence=finding_intelligence([raw])
        )
        self.assertEqual(result["status"], STATUS_COMPLETED)
        self.assertEqual(
            signal_types(result).count(SIGNAL_REPEATED_EVIDENCE_GAP), 1
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
