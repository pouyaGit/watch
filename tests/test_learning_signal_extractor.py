"""tests/test_learning_signal_extractor.py — Stage R44.3 tests.

Deterministic, offline tests for learning signal extraction:

- closed signal vocabulary and deterministic classification mapping
- one advisory signal per classification with fixed recommendation text
- subject, agent and supporting-signal preservation
- advisory-only limitations, schema validation and determinism

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.learning_signal_extractor import (
    CLASSIFICATION_TO_SIGNAL,
    SIGNAL_RECOMMENDATIONS,
    extract_learning_signals,
)
from ai.schemas import learning_signal as schema


AGENT = "sa-" + "a" * 16


def classification(classification_type, subject="XSS", **over):
    base = {
        "rule_version": "r44-2",
        "classification": classification_type,
        "subject": subject,
        "source_agent": AGENT,
        "feedback_id": "fb-" + "a" * 16,
        "reasons": [],
        "supporting_signals": ["EVALUATION_PRESENT"],
        "confidence": "MEDIUM",
        "limitations": [],
    }
    base.update(over)
    return base


class TestLearningSignalExtractor(unittest.TestCase):
    def test_signal_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.LEARNING_SIGNAL_TYPES),
            {"REQUIRE_MORE_EVIDENCE", "REDUCE_CONFIDENCE",
             "IMPROVE_CONTEXT_COLLECTION", "PRESERVE_SUCCESS_PATTERN",
             "AVOID_DUPLICATION", "REVIEW_GOVERNANCE",
             "REVIEW_PROVENANCE", "IMPROVE_HYPOTHESIS_QUALITY",
             "IMPROVE_SAFETY_BOUNDARY", "UNKNOWN"},
        )

    def test_classification_mapping_is_exact(self):
        self.assertEqual(
            CLASSIFICATION_TO_SIGNAL,
            {
                "SAFETY_ISSUE": "IMPROVE_SAFETY_BOUNDARY",
                "GOVERNANCE_ISSUE": "REVIEW_GOVERNANCE",
                "PROVENANCE_ISSUE": "REVIEW_PROVENANCE",
                "CONFLICT_PATTERN": "IMPROVE_HYPOTHESIS_QUALITY",
                "DUPLICATION_PATTERN": "AVOID_DUPLICATION",
                "CONFIDENCE_CALIBRATION": "REDUCE_CONFIDENCE",
                "EVIDENCE_GAP": "REQUIRE_MORE_EVIDENCE",
                "HYPOTHESIS_WEAKNESS": "IMPROVE_HYPOTHESIS_QUALITY",
                "QUALITY_IMPROVEMENT": "IMPROVE_CONTEXT_COLLECTION",
                "SUCCESS_PATTERN": "PRESERVE_SUCCESS_PATTERN",
                "UNKNOWN": "UNKNOWN",
            },
        )

    def test_every_classification_produces_signal(self):
        for classification_type in CLASSIFICATION_TO_SIGNAL:
            signals = extract_learning_signals(
                [classification(classification_type)]
            )
            self.assertEqual(len(signals), 1)
            signal = signals[0]
            expected = CLASSIFICATION_TO_SIGNAL[classification_type]
            self.assertEqual(signal["signal_type"], expected)
            self.assertTrue(signal["recommendation"])
            self.assertEqual(
                signal["recommendation"],
                SIGNAL_RECOMMENDATIONS[expected],
            )

    def test_signal_preserves_attribution(self):
        signals = extract_learning_signals(
            [
                classification(
                    "CONFIDENCE_CALIBRATION",
                    subject="SQLI",
                    supporting_signals=["OBSERVED_ISSUE"],
                    confidence="HIGH",
                )
            ]
        )
        signal = signals[0]
        self.assertEqual(signal["subject"], "SQLI")
        self.assertEqual(signal["source_agent"], AGENT)
        self.assertEqual(
            signal["source_classification"], "CONFIDENCE_CALIBRATION"
        )
        self.assertEqual(
            signal["supporting_signals"], ["OBSERVED_ISSUE"]
        )
        self.assertEqual(signal["confidence"], "HIGH")

    def test_unknown_classification_signal(self):
        signals = extract_learning_signals([classification("UNKNOWN")])
        self.assertEqual(signals[0]["signal_type"], "UNKNOWN")

    def test_advisory_limitations(self):
        signals = extract_learning_signals([classification("EVIDENCE_GAP")])
        limitations = signals[0]["limitations"]
        for code in (
            "NO_EXECUTION_PERFORMED",
            "NO_AGENT_MODIFICATION",
            "NO_RULE_MODIFICATION",
            "ADVISORY_ONLY",
        ):
            self.assertIn(code, limitations)

    def test_batch_and_order(self):
        signals = extract_learning_signals(
            [
                classification("SAFETY_ISSUE"),
                classification("EVIDENCE_GAP"),
            ]
        )
        self.assertEqual(
            [signal["signal_type"] for signal in signals],
            ["IMPROVE_SAFETY_BOUNDARY", "REQUIRE_MORE_EVIDENCE"],
        )

    def test_single_dict_accepted(self):
        signals = extract_learning_signals(
            classification("SUCCESS_PATTERN")
        )
        self.assertEqual(len(signals), 1)

    def test_malformed_input(self):
        for bad in (None, "", 42, "NOPE"):
            self.assertEqual(extract_learning_signals(bad), [])

    def test_deterministic_output(self):
        items = [
            classification("CONFIDENCE_CALIBRATION"),
            classification("SUCCESS_PATTERN", subject="SSRF"),
        ]
        first = extract_learning_signals(items)
        second = extract_learning_signals(items)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        signals = extract_learning_signals([classification("EVIDENCE_GAP")])
        self.assertIsInstance(json.loads(json.dumps(signals)), list)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.LearningSignalPlan(signal_type="NOT_A_SIGNAL")
        with self.assertRaises(ValidationError):
            schema.LearningSignalPlan(subject="NOPE")
        with self.assertRaises(ValidationError):
            schema.LearningSignalPlan(research_only=False)
        with self.assertRaises(ValidationError):
            schema.LearningSignalPlan(unexpected="x")

    def test_schema_forces_rule_version(self):
        plan = schema.LearningSignalPlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r44-3")

    def test_exact_rule_version(self):
        signals = extract_learning_signals([classification("EVIDENCE_GAP")])
        self.assertEqual(signals[0]["rule_version"], "r44-3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
