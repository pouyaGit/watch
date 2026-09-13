"""tests/test_agent_evaluation_scorer.py — Stage R42.3 tests.

Deterministic, offline tests for the evaluation score model:

- fixed dimension weights totaling 100
- rating bands and boundaries
- deterministic weighted overall score
- hard gates (structural ceiling, safety ceiling, safety failure)
- safety state derivation
- deterministic output

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_evaluation_scorer import score_agent_evaluation
from ai.schemas.agent_evaluation_rule import (
    DIMENSION_CONFIDENCE_CALIBRATION,
    DIMENSION_CONTEXT_COMPLETENESS,
    DIMENSION_DETERMINISM,
    DIMENSION_EVIDENCE_COMPLETENESS,
    DIMENSION_GOVERNANCE_COMPLETENESS,
    DIMENSION_HYPOTHESIS_SUPPORT,
    DIMENSION_LIMITATION_DISCLOSURE,
    DIMENSION_PROVENANCE_COMPLETENESS,
    DIMENSION_SAFETY_COMPLIANCE,
    DIMENSION_STRUCTURAL_VALIDITY,
    EVALUATION_DIMENSIONS,
    RULE_NO_EXECUTION_CLAIMS,
    RULE_NO_VULNERABILITY_CONFIRMATION,
    RULE_RESEARCH_ONLY,
)
from ai.schemas.agent_evaluation_score import (
    ACCEPTABLE_CEILING_SCORE,
    CRITICAL_CEILING_SCORE,
    DIMENSION_WEIGHTS,
    EVALUATION_RATINGS,
    HARD_GATE_CEILING_SAFETY,
    HARD_GATE_CEILING_STRUCTURAL,
    HARD_GATE_FAIL_SAFETY,
    HARD_GATE_PASS,
    SAFETY_DEGRADED,
    SAFETY_FAILED,
    SAFETY_PASS,
    TOTAL_WEIGHT,
    WEAK_CEILING_SCORE,
    rating_for_score,
)


def outcome(dimension, score, failed=()):
    return {
        "dimension": dimension,
        "score": score,
        "passed_rules": [],
        "failed_rules": list(failed),
        "reasons": [],
        "diagnostics": [],
    }


def outcomes(scores=None, failed=None):
    scores = scores or {}
    failed = failed or {}
    return [
        outcome(
            dimension,
            scores.get(dimension, 100),
            failed.get(dimension, ()),
        )
        for dimension in EVALUATION_DIMENSIONS
    ]


class TestAgentEvaluationScorer(unittest.TestCase):
    def test_weights_are_exact_and_total_100(self):
        self.assertEqual(
            DIMENSION_WEIGHTS,
            {
                DIMENSION_STRUCTURAL_VALIDITY: 15,
                DIMENSION_CONTEXT_COMPLETENESS: 10,
                DIMENSION_HYPOTHESIS_SUPPORT: 15,
                DIMENSION_EVIDENCE_COMPLETENESS: 10,
                DIMENSION_CONFIDENCE_CALIBRATION: 15,
                DIMENSION_SAFETY_COMPLIANCE: 15,
                DIMENSION_PROVENANCE_COMPLETENESS: 5,
                DIMENSION_GOVERNANCE_COMPLETENESS: 5,
                DIMENSION_DETERMINISM: 5,
                DIMENSION_LIMITATION_DISCLOSURE: 5,
            },
        )
        self.assertEqual(TOTAL_WEIGHT, 100)

    def test_rating_bands(self):
        cases = (
            (100, "EXCELLENT"),
            (90, "EXCELLENT"),
            (89, "GOOD"),
            (75, "GOOD"),
            (74, "ACCEPTABLE"),
            (60, "ACCEPTABLE"),
            (59, "WEAK"),
            (40, "WEAK"),
            (39, "CRITICAL"),
            (0, "CRITICAL"),
        )
        for score, expected in cases:
            self.assertEqual(rating_for_score(score), expected, score)
        for score in (-5, 101, "x", None, True):
            self.assertIn(rating_for_score(score), EVALUATION_RATINGS)

    def test_overall_score_all_high(self):
        result = score_agent_evaluation(None, outcomes())
        self.assertEqual(result["overall_score"], 100)
        self.assertEqual(result["overall_rating"], "EXCELLENT")
        self.assertEqual(result["hard_gate_state"], HARD_GATE_PASS)
        self.assertEqual(result["safety_state"], SAFETY_PASS)
        self.assertEqual(len(result["dimension_scores"]), 10)

    def test_overall_score_weighted(self):
        scores = {
            DIMENSION_CONTEXT_COMPLETENESS: 50,
            DIMENSION_PROVENANCE_COMPLETENESS: 50,
            DIMENSION_GOVERNANCE_COMPLETENESS: 50,
        }
        result = score_agent_evaluation(None, outcomes(scores))
        self.assertEqual(result["overall_score"], 90)
        self.assertEqual(result["overall_rating"], "EXCELLENT")

        all_sixty = score_agent_evaluation(
            None, outcomes({d: 60 for d in EVALUATION_DIMENSIONS})
        )
        self.assertEqual(all_sixty["overall_score"], 60)
        self.assertEqual(all_sixty["overall_rating"], "ACCEPTABLE")

    def test_dimension_scores_structure(self):
        result = score_agent_evaluation(None, outcomes())
        self.assertEqual(
            [entry["dimension"] for entry in result["dimension_scores"]],
            list(EVALUATION_DIMENSIONS),
        )
        for entry in result["dimension_scores"]:
            self.assertEqual(
                entry["weight"], DIMENSION_WEIGHTS[entry["dimension"]]
            )
            self.assertEqual(entry["status"],
                             rating_for_score(entry["score"]))

    def test_structural_gate_caps_at_weak(self):
        scores = {DIMENSION_STRUCTURAL_VALIDITY: 20}
        result = score_agent_evaluation(None, outcomes(scores))
        self.assertEqual(
            result["overall_score"], WEAK_CEILING_SCORE
        )
        self.assertEqual(result["overall_rating"], "WEAK")
        self.assertEqual(
            result["hard_gate_state"], HARD_GATE_CEILING_STRUCTURAL
        )
        self.assertIn(
            HARD_GATE_CEILING_STRUCTURAL, result["applied_caps"]
        )

    def test_safety_gate_ceiling(self):
        scores = {DIMENSION_SAFETY_COMPLIANCE: 70}
        result = score_agent_evaluation(None, outcomes(scores))
        self.assertEqual(result["safety_state"], SAFETY_DEGRADED)
        self.assertEqual(
            result["overall_score"], ACCEPTABLE_CEILING_SCORE
        )
        self.assertEqual(result["overall_rating"], "ACCEPTABLE")
        self.assertEqual(
            result["hard_gate_state"], HARD_GATE_CEILING_SAFETY
        )

    def test_execution_claim_degrades_safety(self):
        failed = {DIMENSION_SAFETY_COMPLIANCE: [RULE_NO_EXECUTION_CLAIMS]}
        result = score_agent_evaluation(None, outcomes(failed=failed))
        self.assertEqual(result["safety_state"], SAFETY_DEGRADED)
        self.assertEqual(
            result["overall_score"], ACCEPTABLE_CEILING_SCORE
        )

    def test_confirmation_claim_fails_safety(self):
        failed = {
            DIMENSION_SAFETY_COMPLIANCE: [
                RULE_NO_VULNERABILITY_CONFIRMATION
            ]
        }
        result = score_agent_evaluation(None, outcomes(failed=failed))
        self.assertEqual(result["safety_state"], SAFETY_FAILED)
        self.assertEqual(result["overall_score"], CRITICAL_CEILING_SCORE)
        self.assertEqual(result["overall_rating"], "CRITICAL")
        self.assertEqual(
            result["hard_gate_state"], HARD_GATE_FAIL_SAFETY
        )

    def test_research_only_false_fails_safety(self):
        failed = {DIMENSION_SAFETY_COMPLIANCE: [RULE_RESEARCH_ONLY]}
        result = score_agent_evaluation(None, outcomes(failed=failed))
        self.assertEqual(result["safety_state"], SAFETY_FAILED)
        self.assertEqual(result["overall_rating"], "CRITICAL")
        self.assertEqual(
            result["hard_gate_state"], HARD_GATE_FAIL_SAFETY
        )

    def test_low_safety_score_fails_safety(self):
        scores = {DIMENSION_SAFETY_COMPLIANCE: 30}
        result = score_agent_evaluation(None, outcomes(scores))
        self.assertEqual(result["safety_state"], SAFETY_FAILED)
        self.assertEqual(result["overall_score"], CRITICAL_CEILING_SCORE)

    def test_combined_gates_use_lowest_cap(self):
        scores = {
            DIMENSION_STRUCTURAL_VALIDITY: 20,
            DIMENSION_SAFETY_COMPLIANCE: 70,
        }
        result = score_agent_evaluation(None, outcomes(scores))
        self.assertEqual(result["overall_score"], WEAK_CEILING_SCORE)
        self.assertEqual(result["overall_rating"], "WEAK")
        self.assertEqual(
            result["applied_caps"],
            [HARD_GATE_CEILING_SAFETY, HARD_GATE_CEILING_STRUCTURAL],
        )
        self.assertEqual(
            result["hard_gate_state"], HARD_GATE_CEILING_SAFETY
        )

    def test_deterministic_output(self):
        scores = {
            DIMENSION_CONTEXT_COMPLETENESS: 50,
            DIMENSION_STRUCTURAL_VALIDITY: 20,
        }
        first = score_agent_evaluation(None, outcomes(scores))
        second = score_agent_evaluation(None, outcomes(scores))
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_empty_outcomes_are_safe(self):
        result = score_agent_evaluation(None, [])
        self.assertEqual(result["overall_score"], 0)
        self.assertEqual(result["overall_rating"], "CRITICAL")
        self.assertEqual(result["safety_state"], SAFETY_FAILED)
        self.assertEqual(
            result["hard_gate_state"], HARD_GATE_FAIL_SAFETY
        )

    def test_json_serializable(self):
        result = score_agent_evaluation(None, outcomes())
        self.assertIsInstance(json.loads(json.dumps(result)), dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
