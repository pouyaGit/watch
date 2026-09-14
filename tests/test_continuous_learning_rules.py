"""tests/test_continuous_learning_rules.py — Stage R57.1–R57.5 tests.

Deterministic, offline tests for continuous-learning schemas and rules:

- learning signal, pattern and calibration recommendation contracts
- closed vocabularies and forced advisory invariants
- deterministic signal generation and pattern aggregation
- content-derived deterministic ids and canonical ordering
- R42 diagnostic / R44 classification / R56 decision mappings
- cross-layer corroboration and conservative pattern emission
- safety gate (forbidden autonomous/execution requests are rejected)
- summary, provenance, governance and limitations

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.continuous_learning_rules import (
    DECISION_SIGNAL,
    FORBIDDEN_LEARNING_MARKERS,
    INDICATOR_RECOMMENDATION,
    PATTERN_SCOPE,
    R42_DIAGNOSTIC_SIGNAL,
    R44_CLASSIFICATION_SIGNAL,
    R44_SIGNAL_MAP,
    RATIONALE_SIGNAL,
    SIGNAL_TO_PATTERN,
    aggregate_governance,
    aggregate_patterns,
    build_calibration_recommendations,
    build_result_provenance,
    build_summary,
    dedupe_signals,
    learning_id,
    make_signal,
    pattern_id,
    recommendation_id,
    result_limitations,
    signal_id,
    signals_from_collaboration,
    signals_from_evaluations,
    signals_from_feedback,
    signals_from_findings,
    signals_from_human_review,
    signals_from_prioritization,
    unsafe_input_reason,
)
from ai.knowledge.continuous_learning import (
    build_calibration_recommendations as build_calibration_recommendations_api,
    build_continuous_learning_result,
    build_learning_signals,
    aggregate_learning_patterns,
)
from ai.knowledge.human_review import create_human_review
from ai.knowledge.research_prioritization import prioritize_findings
from ai.schemas.agent_evaluation_diagnostic import (
    CONFIDENCE_OVERSTATED,
    CONFIDENCE_UNDERSPECIFIED,
    MISSING_EVIDENCE_REQUIREMENT,
    PROVENANCE_INCOMPLETE,
)
from ai.schemas.calibration_recommendation import (
    CALIBRATION_LIMITATIONS,
    CALIBRATION_RECOMMENDATION_CODES,
    CalibrationRecommendationPlan,
    sanitize_calibration_recommendation,
)
from ai.schemas.continuous_learning import (
    CONTINUOUS_LEARNING_SIGNAL_TYPES,
    EVIDENCE_STRENGTHS,
    FEEDBACK_KINDS,
    FEEDBACK_KIND_WORKFLOW,
    OBSERVATIONS,
    SIGNAL_HUMAN_APPROVED_RESEARCH,
    SIGNAL_PRIORITIZATION_MISMATCH,
    SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION,
    SIGNAL_RECURRING_CONFLICT,
    SIGNAL_REPEATED_DUPLICATION,
    SIGNAL_REPEATED_EVIDENCE_GAP,
    SIGNAL_SPECIALIST_RELIABILITY,
    SOURCE_LAYERS,
    SOURCE_LAYER_R42,
    SOURCE_LAYER_R44,
    SOURCE_LAYER_R53,
    SOURCE_LAYER_R56,
    ContinuousLearningSignalPlan,
    sanitize_continuous_learning_signal,
)
from ai.schemas.learning_pattern import (
    CALIBRATION_INDICATORS,
    INDICATOR_CONFIDENCE_MIXED,
    INDICATOR_CONFIDENCE_OVERESTIMATION,
    INDICATOR_CONFIDENCE_UNDERESTIMATION,
    LEARNING_PATTERN_TYPES,
    LearningPatternPlan,
)
from tests.test_research_priority import (
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
    rating="PASS",
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


def feedback(classifications=None, learning_signals=None):
    return {
        "rule_version": "r52-5",
        "classifications": list(classifications or ()),
        "learning_signals": list(learning_signals or ()),
        "recommendations": [],
        "events": [],
        "research_only": True,
    }


def classification(kind, subject="XSS", agent=AGENT_A):
    return {
        "rule_version": "r44-2",
        "classification": kind,
        "subject": subject,
        "source_agent": agent,
        "feedback_id": "",
        "reasons": [],
        "supporting_signals": [],
        "confidence": "UNKNOWN",
        "limitations": [],
    }


def feedback_signal(kind, subject="XSS", agent=AGENT_A):
    return {
        "rule_version": "r44-3",
        "signal_type": kind,
        "subject": subject,
        "source_agent": agent,
        "source_classification": "UNKNOWN",
        "recommendation": "",
        "supporting_signals": [],
        "confidence": "UNKNOWN",
        "limitations": [],
    }


class TestSignalSchema(unittest.TestCase):
    def signal(self, **overrides):
        payload = {
            "rule_version": "r57-1",
            "signal_id": "cls-" + "a" * 16,
            "signal_type": SIGNAL_REPEATED_EVIDENCE_GAP,
            "source_layer": SOURCE_LAYER_R42,
            "category": "XSS",
            "finding_id": FINDING_ONE,
            "observation": "ISSUE",
            "feedback_kind": "QUALITY_OBSERVATION",
            "evidence_strength": "MODERATE",
            "confidence": "MEDIUM",
            "provenance": {"orchestration_id": "orch-" + "1" * 16},
        }
        payload.update(overrides)
        return payload

    def test_valid_signal(self):
        signal = ContinuousLearningSignalPlan(**self.signal())
        self.assertFalse(signal.truth_label)
        self.assertEqual(signal.confirmation_state, "NOT_CONFIRMED")
        self.assertFalse(signal.execution_authorized)
        self.assertTrue(signal.research_only)
        self.assertTrue(signal.deterministic)

    def test_closed_vocabularies(self):
        self.assertEqual(
            len(CONTINUOUS_LEARNING_SIGNAL_TYPES),
            len(set(CONTINUOUS_LEARNING_SIGNAL_TYPES)),
        )
        self.assertEqual(len(SOURCE_LAYERS), len(set(SOURCE_LAYERS)))
        self.assertEqual(len(OBSERVATIONS), len(set(OBSERVATIONS)))
        self.assertEqual(len(FEEDBACK_KINDS), len(set(FEEDBACK_KINDS)))
        self.assertEqual(len(EVIDENCE_STRENGTHS), len(set(EVIDENCE_STRENGTHS)))

    def test_unknown_signal_type_is_rejected(self):
        with self.assertRaises(ValidationError):
            ContinuousLearningSignalPlan(
                **self.signal(signal_type="LEARN_EXPLOIT")
            )

    def test_truth_label_is_forced_false(self):
        with self.assertRaises(ValidationError):
            ContinuousLearningSignalPlan(**self.signal(truth_label=True))

    def test_confirmation_is_forced(self):
        with self.assertRaises(ValidationError):
            ContinuousLearningSignalPlan(
                **self.signal(confirmation_state="CONFIRMED")
            )

    def test_execution_authorization_is_rejected(self):
        with self.assertRaises(ValidationError):
            ContinuousLearningSignalPlan(
                **self.signal(execution_authorized=True)
            )

    def test_malformed_signal_id_is_rejected(self):
        with self.assertRaises(ValidationError):
            ContinuousLearningSignalPlan(**self.signal(signal_id="bad"))

    def test_sanitizer_forces_invariants(self):
        projected = sanitize_continuous_learning_signal(
            {
                "signal_type": SIGNAL_REPEATED_EVIDENCE_GAP,
                "source_layer": SOURCE_LAYER_R42,
                "truth_label": True,
                "confirmation_state": "CONFIRMED",
                "execution_authorized": True,
                "research_only": False,
                "deterministic": False,
            }
        )
        self.assertFalse(projected["truth_label"])
        self.assertEqual(projected["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(projected["execution_authorized"])
        self.assertTrue(projected["research_only"])
        self.assertTrue(projected["deterministic"])

    def test_decision_context_preserves_authority_and_never_truth(self):
        projected = sanitize_continuous_learning_signal(
            {
                "signal_type": SIGNAL_HUMAN_APPROVED_RESEARCH,
                "source_layer": SOURCE_LAYER_R56,
                "feedback_kind": FEEDBACK_KIND_WORKFLOW,
                "decision_context": {
                    "present": True,
                    "decision_source": "HUMAN",
                    "decision_authority": "HUMAN",
                    "human_authority": True,
                    "execution_authorized": True,
                    "vulnerability_confirmed": True,
                    "confirmation_state": "CONFIRMED",
                },
            }
        )
        context = projected["decision_context"]
        self.assertEqual(context["decision_source"], "HUMAN")
        self.assertEqual(context["decision_authority"], "HUMAN")
        self.assertTrue(context["human_authority"])
        self.assertFalse(context["execution_authorized"])
        self.assertFalse(context["vulnerability_confirmed"])
        self.assertFalse(context["truth_label"])
        self.assertEqual(context["confirmation_state"], "NOT_CONFIRMED")


class TestPatternSchema(unittest.TestCase):
    def payload(self, **overrides):
        payload = {
            "rule_version": "r57-2",
            "pattern_id": "clp-" + "a" * 16,
            "pattern_type": "EVIDENCE_GAP_PATTERN",
            "source_layers": [SOURCE_LAYER_R42, SOURCE_LAYER_R53],
            "category": "XSS",
            "frequency": 2,
            "cross_layer_support": 2,
            "supporting_signal_ids": ["cls-" + "b" * 16],
            "calibration_indicator": "EVIDENCE_GAP_RECURRING",
            "calibration_recommendation_codes": [
                "REQUEST_MORE_EVIDENCE"
            ],
            "evidence_strength": "MODERATE",
            "confidence": "MEDIUM",
        }
        payload.update(overrides)
        return payload

    def test_valid_pattern(self):
        pattern = LearningPatternPlan(**self.payload())
        self.assertTrue(pattern.advisory)
        self.assertFalse(pattern.auto_applies)
        self.assertFalse(pattern.modifies_agents)
        self.assertFalse(pattern.modifies_rules)
        self.assertTrue(pattern.research_only)

    def test_unknown_pattern_type_is_rejected(self):
        with self.assertRaises(ValidationError):
            LearningPatternPlan(**self.payload(pattern_type="EXPLOIT_PATTERN"))

    def test_autonomous_modification_flags_are_rejected(self):
        for flag in (
            "auto_applies",
            "modifies_agents",
            "modifies_rules",
        ):
            with self.assertRaises(ValidationError):
                LearningPatternPlan(**self.payload(**{flag: True}))

    def test_unknown_indicator_is_rejected(self):
        with self.assertRaises(ValidationError):
            LearningPatternPlan(
                **self.payload(calibration_indicator="UNSUPPORTED")
            )

    def test_unknown_recommendation_code_is_dropped(self):
        pattern = LearningPatternPlan(
            **self.payload(
                calibration_recommendation_codes=[
                    "REQUEST_MORE_EVIDENCE",
                    "NOT_A_CODE",
                ]
            )
        )
        self.assertEqual(
            pattern.calibration_recommendation_codes,
            ["REQUEST_MORE_EVIDENCE"],
        )

    def test_pattern_type_order_is_closed(self):
        self.assertEqual(
            len(LEARNING_PATTERN_TYPES), len(set(LEARNING_PATTERN_TYPES))
        )
        self.assertEqual(
            len(CALIBRATION_INDICATORS), len(set(CALIBRATION_INDICATORS))
        )


class TestRecommendationSchema(unittest.TestCase):
    def payload(self, **overrides):
        payload = {
            "rule_version": "r57-3",
            "recommendation_id": "clc-" + "a" * 16,
            "recommendation_code": "REQUEST_MORE_EVIDENCE",
            "target_scope": "CATEGORY",
            "category": "XSS",
            "pattern_id": "clp-" + "b" * 16,
            "rationale_codes": ["RECURRING_OBSERVATION"],
            "evidence_strength": "MODERATE",
            "confidence": "MEDIUM",
        }
        payload.update(overrides)
        return payload

    def test_valid_recommendation(self):
        recommendation = CalibrationRecommendationPlan(**self.payload())
        self.assertTrue(recommendation.advisory)
        self.assertFalse(recommendation.auto_applies)
        self.assertFalse(recommendation.modifies_agents)
        self.assertFalse(recommendation.modifies_rules)
        self.assertFalse(recommendation.modifies_thresholds)
        self.assertFalse(recommendation.modifies_strategies)
        self.assertFalse(recommendation.execution_authorized)
        self.assertFalse(recommendation.vulnerability_confirmed)
        self.assertEqual(recommendation.confirmation_state, "NOT_CONFIRMED")
        self.assertTrue(recommendation.safety_boundary_preserved)
        self.assertTrue(recommendation.human_authority_preserved)

    def test_closed_vocabularies(self):
        self.assertEqual(
            len(CALIBRATION_RECOMMENDATION_CODES),
            len(set(CALIBRATION_RECOMMENDATION_CODES)),
        )
        self.assertEqual(
            len(CALIBRATION_LIMITATIONS), len(set(CALIBRATION_LIMITATIONS))
        )

    def test_automatic_behavior_change_is_rejected(self):
        for flag in (
            "auto_applies",
            "modifies_agents",
            "modifies_rules",
            "modifies_thresholds",
            "modifies_strategies",
        ):
            with self.assertRaises(ValidationError):
                CalibrationRecommendationPlan(
                    **self.payload(**{flag: True})
                )

    def test_execution_authorization_is_rejected(self):
        with self.assertRaises(ValidationError):
            CalibrationRecommendationPlan(
                **self.payload(execution_authorized=True)
            )
        with self.assertRaises(ValidationError):
            CalibrationRecommendationPlan(
                **self.payload(vulnerability_confirmed=True)
            )

    def test_sanitizer_forces_advisory_flags(self):
        projected = sanitize_calibration_recommendation(
            {
                "recommendation_code": "REQUEST_MORE_EVIDENCE",
                "auto_applies": True,
                "modifies_agents": True,
                "execution_authorized": True,
                "safety_boundary_preserved": False,
                "human_authority_preserved": False,
                "research_only": False,
            }
        )
        self.assertTrue(projected["advisory"])
        self.assertFalse(projected["auto_applies"])
        self.assertFalse(projected["modifies_agents"])
        self.assertFalse(projected["execution_authorized"])
        self.assertTrue(projected["safety_boundary_preserved"])
        self.assertTrue(projected["human_authority_preserved"])
        self.assertTrue(projected["research_only"])


class TestDeterministicIds(unittest.TestCase):
    def test_signal_id_is_deterministic_and_content_sensitive(self):
        first = signal_id(
            SIGNAL_REPEATED_EVIDENCE_GAP,
            SOURCE_LAYER_R42,
            "XSS",
            AGENT_A,
            "",
            "",
            MISSING_EVIDENCE_REQUIREMENT,
            "ISSUE",
            "QUALITY_OBSERVATION",
        )
        second = signal_id(
            SIGNAL_REPEATED_EVIDENCE_GAP,
            SOURCE_LAYER_R42,
            "XSS",
            AGENT_A,
            "",
            "",
            MISSING_EVIDENCE_REQUIREMENT,
            "ISSUE",
            "QUALITY_OBSERVATION",
        )
        third = signal_id(
            SIGNAL_REPEATED_EVIDENCE_GAP,
            SOURCE_LAYER_R42,
            "SSRF",
            AGENT_A,
            "",
            "",
            MISSING_EVIDENCE_REQUIREMENT,
            "ISSUE",
            "QUALITY_OBSERVATION",
        )
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)
        self.assertTrue(first.startswith("cls-"))

    def test_pattern_and_recommendation_ids_are_deterministic(self):
        first = pattern_id(
            "EVIDENCE_GAP_PATTERN", "XSS", ["cls-" + "a" * 16]
        )
        second = pattern_id(
            "EVIDENCE_GAP_PATTERN", "XSS", ["cls-" + "a" * 16]
        )
        third = pattern_id(
            "EVIDENCE_GAP_PATTERN", "XSS", ["cls-" + "b" * 16]
        )
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)
        self.assertEqual(
            recommendation_id("REQUEST_MORE_EVIDENCE", first, "CATEGORY"),
            recommendation_id("REQUEST_MORE_EVIDENCE", first, "CATEGORY"),
        )

    def test_learning_id_is_deterministic(self):
        self.assertEqual(
            learning_id(["cls-" + "a" * 16], [], []),
            learning_id(["cls-" + "a" * 16], [], []),
        )
        self.assertNotEqual(
            learning_id(["cls-" + "a" * 16], [], []),
            learning_id(["cls-" + "b" * 16], [], []),
        )


class TestMappings(unittest.TestCase):
    def test_signal_families_are_closed(self):
        for signal_type, family in SIGNAL_TO_PATTERN.items():
            self.assertIn(signal_type, CONTINUOUS_LEARNING_SIGNAL_TYPES)
            self.assertIn(family, LEARNING_PATTERN_TYPES)

    def test_r42_diagnostics_map_to_closed_signals(self):
        for code, signal_type in R42_DIAGNOSTIC_SIGNAL.items():
            self.assertIn(signal_type, CONTINUOUS_LEARNING_SIGNAL_TYPES)

    def test_r44_mappings_are_closed(self):
        for kind, signal_type in R44_CLASSIFICATION_SIGNAL.items():
            self.assertIn(signal_type, CONTINUOUS_LEARNING_SIGNAL_TYPES)
        for kind, signal_type in R44_SIGNAL_MAP.items():
            self.assertIn(signal_type, CONTINUOUS_LEARNING_SIGNAL_TYPES)

    def test_decision_mapping_covers_every_decision_type(self):
        self.assertEqual(
            set(DECISION_SIGNAL),
            {
                "APPROVE_RESEARCH",
                "REQUEST_MORE_EVIDENCE",
                "DEFER",
                "REJECT",
                "ESCALATE",
                "NEEDS_REVIEW",
            },
        )
        for signal_type in DECISION_SIGNAL.values():
            self.assertIn(signal_type, CONTINUOUS_LEARNING_SIGNAL_TYPES)
        for signal_type in RATIONALE_SIGNAL.values():
            self.assertIn(signal_type, CONTINUOUS_LEARNING_SIGNAL_TYPES)

    def test_indicators_and_scopes_are_closed(self):
        for indicator, codes in INDICATOR_RECOMMENDATION.items():
            self.assertIn(indicator, CALIBRATION_INDICATORS)
            for code in codes:
                self.assertIn(code, CALIBRATION_RECOMMENDATION_CODES)
        for pattern_type, scope in PATTERN_SCOPE.items():
            self.assertIn(pattern_type, LEARNING_PATTERN_TYPES)


class TestSignalGeneration(unittest.TestCase):
    def test_make_signal_is_deterministic(self):
        first = make_signal(
            signal_type=SIGNAL_REPEATED_EVIDENCE_GAP,
            source_layer=SOURCE_LAYER_R42,
            observation="ISSUE",
            category="XSS",
            agent_id=AGENT_A,
            subject_reference=MISSING_EVIDENCE_REQUIREMENT,
            evidence_strength="MODERATE",
        )
        second = make_signal(
            signal_type=SIGNAL_REPEATED_EVIDENCE_GAP,
            source_layer=SOURCE_LAYER_R42,
            observation="ISSUE",
            category="XSS",
            agent_id=AGENT_A,
            subject_reference=MISSING_EVIDENCE_REQUIREMENT,
            evidence_strength="MODERATE",
        )
        self.assertEqual(first, second)
        self.assertEqual(first["limitations"][0], "NO_EXECUTION_PERFORMED")

    def test_evaluation_diagnostics_generate_signals(self):
        signals = signals_from_evaluations(
            [
                evaluation(
                    overall_rating="GOOD",
                    diagnostics=[
                        diagnostic(CONFIDENCE_OVERSTATED),
                        diagnostic(MISSING_EVIDENCE_REQUIREMENT),
                    ],
                )
            ]
        )
        types = {signal["signal_type"] for signal in signals}
        self.assertIn(SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION, types)
        self.assertIn(SIGNAL_REPEATED_EVIDENCE_GAP, types)
        self.assertIn(SIGNAL_SPECIALIST_RELIABILITY, types)

    def test_evaluation_underestimation_generates_signal(self):
        signals = signals_from_evaluations(
            [
                evaluation(
                    diagnostics=[diagnostic(CONFIDENCE_UNDERSPECIFIED)]
                )
            ]
        )
        types = {signal["signal_type"] for signal in signals}
        self.assertIn(
            "RECURRING_CONFIDENCE_UNDERESTIMATION", types
        )

    def test_evaluation_safety_failure_is_strong(self):
        signals = signals_from_evaluations(
            [evaluation(safety="FAILED", gate="FAIL_SAFETY")]
        )
        safety = [
            signal
            for signal in signals
            if signal["signal_type"] == "REPEATED_SAFETY_ISSUE"
        ]
        self.assertEqual(len(safety), 1)
        self.assertEqual(safety[0]["evidence_strength"], "STRONG")

    def test_malformed_evaluation_entries_are_ignored(self):
        self.assertEqual(signals_from_evaluations(None), [])
        self.assertEqual(signals_from_evaluations(["x", None, 3]), [])

    def test_collaboration_conflicts_and_duplicates(self):
        signals = signals_from_collaboration(
            {
                "rule_version": "r43-6",
                "conflicts": [
                    {
                        "conflict_type": "CONTEXT_CONFLICT",
                        "resolution_state": "UNRESOLVED",
                        "subjects": [AGENT_A],
                    }
                ],
                "hypothesis_groups": [
                    {
                        "correlation_type": "DUPLICATE",
                        "participating_agents": [AGENT_A, AGENT_B],
                    }
                ],
            }
        )
        types = {signal["signal_type"] for signal in signals}
        self.assertEqual(
            types, {SIGNAL_RECURRING_CONFLICT, SIGNAL_REPEATED_DUPLICATION}
        )

    def test_feedback_classifications_are_preferred(self):
        signals = signals_from_feedback(
            feedback(
                classifications=[classification("EVIDENCE_GAP")],
                learning_signals=[
                    feedback_signal("REQUIRE_MORE_EVIDENCE"),
                    feedback_signal("REDUCE_CONFIDENCE"),
                ],
            )
        )
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["signal_type"], SIGNAL_REPEATED_EVIDENCE_GAP)
        self.assertEqual(signals[0]["subject_reference"], "EVIDENCE_GAP")

    def test_feedback_signals_are_used_when_no_classifications(self):
        signals = signals_from_feedback(
            feedback(
                classifications=[],
                learning_signals=[
                    feedback_signal("REQUIRE_MORE_EVIDENCE")
                ],
            )
        )
        self.assertEqual(len(signals), 1)
        self.assertEqual(
            signals[0]["source_layer"], SOURCE_LAYER_R44
        )

    def test_human_decision_generates_workflow_feedback(self):
        first, second = duplicate_findings()
        prioritization = prioritize_findings([first, second])
        review = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"}
            ],
        )
        signals = signals_from_human_review(review)
        workflow = [
            signal
            for signal in signals
            if signal["signal_type"] == "HUMAN_DEFERRED_RESEARCH"
        ]
        self.assertEqual(len(workflow), 1)
        self.assertEqual(workflow[0]["feedback_kind"], FEEDBACK_KIND_WORKFLOW)
        self.assertFalse(workflow[0]["truth_label"])
        self.assertTrue(workflow[0]["workflow_feedback"])
        self.assertTrue(
            workflow[0]["decision_context"]["human_authority"]
        )
        self.assertFalse(
            workflow[0]["decision_context"]["execution_authorized"]
        )

    def test_rationale_codes_add_corroborating_signals(self):
        first, second = duplicate_findings()
        prioritization = prioritize_findings([first, second])
        review = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "DEFER",
                    "rationale_codes": ["DUPLICATE_RESEARCH_OVERLAP"],
                }
            ],
        )
        signals = signals_from_human_review(review)
        types = {signal["signal_type"] for signal in signals}
        self.assertIn(SIGNAL_REPEATED_DUPLICATION, types)
        for signal in signals:
            self.assertEqual(signal["feedback_kind"], FEEDBACK_KIND_WORKFLOW)

    def test_priority_mismatch_generates_signal(self):
        raw = finding(
            "XSS",
            AGENT_A,
            finding_id_value=FINDING_ONE,
            evidence_completeness="COMPLETE",
            state="EVIDENCE_SUPPORTED",
            confidence="UNKNOWN",
            impact_state="UNKNOWN",
            orchestration_id="",
        )
        prioritization = prioritize_findings([raw])
        plan = prioritization["ranked_findings"][0]
        self.assertEqual(plan["priority_band"], "LOW")
        signals = signals_from_prioritization(prioritization)
        mismatch = [
            signal
            for signal in signals
            if signal["signal_type"] == SIGNAL_PRIORITIZATION_MISMATCH
        ]
        self.assertEqual(len(mismatch), 1)

    def test_dedupe_is_sorted_and_order_independent(self):
        signals = signals_from_evaluations(
            [
                evaluation(
                    agent_id=AGENT_A,
                    diagnostics=[diagnostic(PROVENANCE_INCOMPLETE)],
                ),
                evaluation(
                    agent_id=AGENT_B,
                    diagnostics=[diagnostic(PROVENANCE_INCOMPLETE)],
                ),
            ]
        )
        forward = dedupe_signals(signals)
        backward = dedupe_signals(list(reversed(signals)))
        self.assertEqual(
            [signal["signal_id"] for signal in forward],
            [signal["signal_id"] for signal in backward],
        )
        self.assertEqual(
            [signal["signal_id"] for signal in forward],
            sorted(signal["signal_id"] for signal in forward),
        )


class TestPatternAggregation(unittest.TestCase):
    def test_single_signal_does_not_form_a_pattern(self):
        signals = dedupe_signals(
            signals_from_evaluations(
                [
                    evaluation(
                        diagnostics=[
                            diagnostic(MISSING_EVIDENCE_REQUIREMENT)
                        ]
                    )
                ]
            )
        )
        self.assertEqual(len(signals), 1)
        self.assertEqual(aggregate_patterns(signals), [])

    def test_cross_layer_corroboration_forms_pattern(self):
        r42 = signals_from_evaluations(
            [
                evaluation(
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)]
                )
            ]
        )
        r53 = signals_from_findings(
            {
                "rule_version": "r53-6",
                "findings": [
                    finding(
                        "XSS",
                        AGENT_A,
                        finding_id_value=FINDING_ONE,
                        evidence_state="UNKNOWN",
                        evidence_completeness="MISSING",
                        evidence_requirements=None,
                        state="NEEDS_MORE_EVIDENCE",
                    )
                ],
            }
        )
        patterns = aggregate_patterns(dedupe_signals(r42 + r53))
        evidence = [
            pattern
            for pattern in patterns
            if pattern["pattern_type"] == "EVIDENCE_GAP_PATTERN"
        ]
        self.assertEqual(len(evidence), 1)
        self.assertGreaterEqual(evidence[0]["cross_layer_support"], 2)
        self.assertEqual(
            evidence[0]["calibration_recommendation_codes"],
            ["REQUEST_MORE_EVIDENCE"],
        )

    def test_recurrence_forms_pattern(self):
        r53 = signals_from_findings(
            {
                "rule_version": "r53-6",
                "findings": [
                    finding(
                        "XSS",
                        AGENT_A,
                        finding_id_value=FINDING_ONE,
                        evidence_state="UNKNOWN",
                        evidence_completeness="MISSING",
                        evidence_requirements=None,
                        state="NEEDS_MORE_EVIDENCE",
                    ),
                    finding(
                        "XSS",
                        AGENT_A,
                        finding_id_value=FINDING_TWO,
                        evidence_state="UNKNOWN",
                        evidence_completeness="MISSING",
                        evidence_requirements=None,
                        state="NEEDS_MORE_EVIDENCE",
                    ),
                ],
            }
        )
        patterns = aggregate_patterns(dedupe_signals(r53))
        evidence = [
            pattern
            for pattern in patterns
            if pattern["pattern_type"] == "EVIDENCE_GAP_PATTERN"
        ]
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["frequency"], 2)

    def test_confidence_direction_is_derived(self):
        over = signals_from_findings(
            {
                "rule_version": "r53-6",
                "findings": [
                    finding(
                        "XSS",
                        AGENT_A,
                        finding_id_value=FINDING_ONE,
                        confidence="HIGH",
                        evidence_completeness="PARTIAL",
                        evidence_state="PARTIAL",
                    ),
                    finding(
                        "XSS",
                        AGENT_A,
                        finding_id_value=FINDING_TWO,
                        confidence="HIGH",
                        evidence_completeness="PARTIAL",
                        evidence_state="PARTIAL",
                    ),
                ],
            }
        )
        patterns = aggregate_patterns(dedupe_signals(over))
        confidence = [
            pattern
            for pattern in patterns
            if pattern["pattern_type"] == "CONFIDENCE_CALIBRATION_PATTERN"
        ]
        self.assertEqual(len(confidence), 1)
        self.assertEqual(
            confidence[0]["calibration_indicator"],
            INDICATOR_CONFIDENCE_OVERESTIMATION,
        )

    def test_confidence_underestimation_direction(self):
        under = signals_from_findings(
            {
                "rule_version": "r53-6",
                "findings": [
                    finding(
                        "XSS",
                        AGENT_A,
                        finding_id_value=FINDING_ONE,
                        confidence="LOW",
                        evidence_completeness="COMPLETE",
                        state="EVIDENCE_SUPPORTED",
                    ),
                    finding(
                        "XSS",
                        AGENT_A,
                        finding_id_value=FINDING_TWO,
                        confidence="LOW",
                        evidence_completeness="COMPLETE",
                        state="EVIDENCE_SUPPORTED",
                    ),
                ],
            }
        )
        patterns = aggregate_patterns(dedupe_signals(under))
        confidence = [
            pattern
            for pattern in patterns
            if pattern["pattern_type"] == "CONFIDENCE_CALIBRATION_PATTERN"
        ]
        self.assertEqual(
            confidence[0]["calibration_indicator"],
            INDICATOR_CONFIDENCE_UNDERESTIMATION,
        )

    def test_mixed_confidence_direction_is_explicit(self):
        mixed = signals_from_findings(
            {
                "rule_version": "r53-6",
                "findings": [
                    finding(
                        "XSS",
                        AGENT_A,
                        finding_id_value=FINDING_ONE,
                        confidence="HIGH",
                        evidence_completeness="PARTIAL",
                        evidence_state="PARTIAL",
                    ),
                    finding(
                        "XSS",
                        AGENT_A,
                        finding_id_value=FINDING_TWO,
                        confidence="LOW",
                        evidence_completeness="COMPLETE",
                        state="EVIDENCE_SUPPORTED",
                    ),
                ],
            }
        )
        patterns = aggregate_patterns(dedupe_signals(mixed))
        confidence = [
            pattern
            for pattern in patterns
            if pattern["pattern_type"] == "CONFIDENCE_CALIBRATION_PATTERN"
        ]
        self.assertEqual(
            confidence[0]["calibration_indicator"],
            INDICATOR_CONFIDENCE_MIXED,
        )

    def test_pattern_aggregation_is_deterministic(self):
        signals = dedupe_signals(
            signals_from_evaluations(
                [
                    evaluation(
                        diagnostics=[
                            diagnostic(MISSING_EVIDENCE_REQUIREMENT)
                        ]
                    ),
                    evaluation(
                        agent_id=AGENT_B,
                        diagnostics=[diagnostic(CONFIDENCE_OVERSTATED)],
                    ),
                ]
            )
        )
        first = aggregate_patterns(signals)
        second = aggregate_patterns(list(reversed(signals)))
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )


class TestRecommendations(unittest.TestCase):
    def patterns(self):
        signals = dedupe_signals(
            signals_from_findings(
                {
                    "rule_version": "r53-6",
                    "findings": [
                        finding(
                            "XSS",
                            AGENT_A,
                            finding_id_value=FINDING_ONE,
                            evidence_state="UNKNOWN",
                            evidence_completeness="MISSING",
                            evidence_requirements=None,
                            state="NEEDS_MORE_EVIDENCE",
                        ),
                        finding(
                            "XSS",
                            AGENT_A,
                            finding_id_value=FINDING_TWO,
                            evidence_state="UNKNOWN",
                            evidence_completeness="MISSING",
                            evidence_requirements=None,
                            state="NEEDS_MORE_EVIDENCE",
                        ),
                    ],
                }
            )
        )
        return aggregate_patterns(signals)

    def test_recommendations_are_ranked_and_advisory(self):
        recommendations = build_calibration_recommendations(self.patterns())
        self.assertGreaterEqual(len(recommendations), 1)
        recommendation = recommendations[0]
        self.assertEqual(recommendation["recommendation_code"],
                         "REQUEST_MORE_EVIDENCE")
        self.assertEqual(recommendation["recommendation_rank"], 1)
        self.assertTrue(recommendation["advisory"])
        self.assertFalse(recommendation["auto_applies"])
        self.assertIn(
            "NO_AUTOMATIC_BEHAVIOR_CHANGE", recommendation["limitations"]
        )

    def test_recommendation_is_deterministic(self):
        first = build_calibration_recommendations(self.patterns())
        second = build_calibration_recommendations(self.patterns())
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_safety_recommendation_ranks_first(self):
        members = dedupe_signals(
            signals_from_evaluations(
                [
                    evaluation(safety="FAILED", gate="FAIL_SAFETY"),
                    evaluation(agent_id=AGENT_B, safety="FAILED"),
                ]
            )
            + signals_from_findings(
                {
                    "rule_version": "r53-6",
                    "findings": [
                        finding(
                            "XSS",
                            AGENT_A,
                            finding_id_value=FINDING_ONE,
                            evidence_state="UNKNOWN",
                            evidence_completeness="MISSING",
                            evidence_requirements=None,
                            state="NEEDS_MORE_EVIDENCE",
                        ),
                        finding(
                            "XSS",
                            AGENT_A,
                            finding_id_value=FINDING_TWO,
                            evidence_state="UNKNOWN",
                            evidence_completeness="MISSING",
                            evidence_requirements=None,
                            state="NEEDS_MORE_EVIDENCE",
                        ),
                    ],
                }
            )
        )
        recommendations = build_calibration_recommendations(
            aggregate_patterns(members)
        )
        self.assertEqual(
            recommendations[0]["recommendation_code"],
            "REVIEW_SAFETY_BOUNDARY",
        )


class TestSummaryProvenanceGovernance(unittest.TestCase):
    def build(self):
        signals = dedupe_signals(
            signals_from_evaluations(
                [
                    evaluation(
                        agent_id=AGENT_A,
                        diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                    ),
                    evaluation(
                        agent_id=AGENT_B,
                        diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                    ),
                ]
            )
        )
        patterns = aggregate_patterns(signals)
        recommendations = build_calibration_recommendations(patterns)
        return signals, patterns, recommendations

    def test_summary_counts_are_deterministic(self):
        signals, patterns, recommendations = self.build()
        summary = build_summary(signals, patterns, recommendations)
        self.assertEqual(summary["signal_count"], len(signals))
        self.assertEqual(summary["pattern_count"], len(patterns))
        self.assertEqual(
            summary["source_layer_counts"][SOURCE_LAYER_R42], len(signals)
        )
        self.assertEqual(
            summary["recommendation_code_counts"]["REQUEST_MORE_EVIDENCE"],
            1,
        )

    def test_provenance_aggregates_layers(self):
        signals, _, _ = self.build()
        provenance = build_result_provenance(signals)
        self.assertIn(SOURCE_LAYER_R42, provenance["source_layers"])
        self.assertTrue(provenance["deterministic"])

    def test_governance_aggregation_defaults_to_unknown(self):
        signals, _, _ = self.build()
        governance = aggregate_governance(signals)
        self.assertEqual(governance["governance_state"], "UNKNOWN")

    def test_limitations_are_closed_and_ordered(self):
        signals, patterns, recommendations = self.build()
        limitations = result_limitations(
            signals, patterns, recommendations, []
        )
        self.assertEqual(
            limitations,
            [code for code in CALIBRATION_LIMITATIONS if code in limitations],
        )


class TestSafetyGate(unittest.TestCase):
    def test_negative_codes_are_not_flagged(self):
        safe = {
            "limitations": [
                "NO_EXECUTION_PERFORMED",
                "NO_PAYLOAD_GENERATION",
                "NO_VULNERABILITY_CONFIRMATION",
                "ATTACK_PLANNING_NOT_AUTHORIZED",
                "EXECUTION_NOT_AUTHORIZED",
            ],
            "execution_authorized": False,
            "vulnerability_confirmed": False,
        }
        self.assertEqual(unsafe_input_reason(safe), "")

    def test_execution_flags_are_rejected(self):
        for key in (
            "execution_authorized",
            "vulnerability_confirmed",
            "exploit_authorized",
            "auto_applies",
            "modifies_agents",
            "modifies_rules",
            "modifies_thresholds",
            "modifies_strategies",
        ):
            self.assertTrue(
                unsafe_input_reason({key: True}),
                key,
            )

    def test_forbidden_claims_are_rejected(self):
        for text in (
            "PAYLOAD_EXECUTED",
            "VULNERABILITY_CONFIRMED",
            "GENERATE_PAYLOAD",
            "BYPASS_HUMAN",
            "DISABLE_SAFETY",
            "AUTONOMOUS_EXECUTION",
        ):
            self.assertTrue(
                unsafe_input_reason({"note": text}), text
            )

    def test_forbidden_markers_are_non_empty(self):
        self.assertTrue(FORBIDDEN_LEARNING_MARKERS)


class TestPublicStages(unittest.TestCase):
    def test_build_learning_signals_stage(self):
        result = build_learning_signals(
            evaluation_results=[
                evaluation(
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)]
                ),
                evaluation(
                    agent_id=AGENT_B,
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                ),
            ]
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(len(result["signals"]), 2)
        self.assertEqual(result["patterns"], [])
        self.assertEqual(result["calibration_recommendations"], [])

    def test_aggregate_learning_patterns_stage(self):
        result = aggregate_learning_patterns(
            evaluation_results=[
                evaluation(
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)]
                ),
                evaluation(
                    agent_id=AGENT_B,
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                ),
            ]
        )
        self.assertEqual(len(result["patterns"]), 1)
        self.assertEqual(result["calibration_recommendations"], [])

    def test_build_calibration_recommendations_stage(self):
        result = build_calibration_recommendations_api(
            evaluation_results=[
                evaluation(
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)]
                ),
                evaluation(
                    agent_id=AGENT_B,
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                ),
            ]
        )
        self.assertEqual(len(result["calibration_recommendations"]), 1)

    def test_full_result_stage(self):
        result = build_continuous_learning_result(
            evaluation_results=[
                evaluation(
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)]
                ),
                evaluation(
                    agent_id=AGENT_B,
                    diagnostics=[diagnostic(MISSING_EVIDENCE_REQUIREMENT)],
                ),
            ]
        )
        self.assertEqual(result["rule_version"], "r57-4")
        self.assertEqual(result["pattern_rule_version"], "r57-2")
        self.assertEqual(result["recommendation_rule_version"], "r57-3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
