"""tests/test_finding_state.py — Stage R53.5 tests.

Deterministic, offline tests for finding state and confidence reasoning:

- every closed finding state is reachable and derived deterministically
- state precedence is conservative
- confidence is a meet of upstream constraints plus explicit caps
- agreement between agents is never a boost
- confidence reason codes are closed and ordered

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import inspect
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.finding_state import (
    confidence_rank,
    derive_finding_confidence,
    derive_finding_state,
    min_confidence,
)
from ai.schemas.finding_assessment import (
    CONFIDENCE_REASONS,
    FINDING_STATES,
    STATE_CONFIRMED_OBSERVED,
    STATE_CONFLICTED,
    STATE_EVIDENCE_SUPPORTED,
    STATE_INSUFFICIENT_EVIDENCE,
    STATE_NEEDS_MORE_EVIDENCE,
    STATE_RESEARCH_CANDIDATE,
)


def state_inputs(**over):
    payload = {
        "status": "COMPLETED",
        "has_hypotheses": True,
        "context_fact_count": 5,
        "evidence_state": "COMPLETE",
        "evidence_completeness": "COMPLETE",
        "evidence_missing": False,
        "conflict_count": 0,
        "evaluation_present": True,
        "evaluation_rating": "GOOD",
        "safety_state": "PASS",
        "hard_gate_state": "PASS",
        "diagnostic_codes": [],
    }
    payload.update(over)
    return payload


def confidence_inputs(**over):
    payload = {
        "state": STATE_EVIDENCE_SUPPORTED,
        "status": "COMPLETED",
        "result_confidence": "HIGH",
        "evidence_confidence": "HIGH",
        "context_confidence": "HIGH",
        "evidence_state": "COMPLETE",
        "evidence_completeness": "COMPLETE",
        "evaluation_present": True,
        "evaluation_rating": "GOOD",
        "safety_state": "PASS",
        "hard_gate_state": "PASS",
        "diagnostic_codes": [],
        "conflict_count": 0,
    }
    payload.update(over)
    return payload


class TestFindingStates(unittest.TestCase):
    def test_every_state_is_closed(self):
        self.assertEqual(
            set(FINDING_STATES),
            {
                STATE_RESEARCH_CANDIDATE,
                STATE_EVIDENCE_SUPPORTED,
                STATE_NEEDS_MORE_EVIDENCE,
                STATE_CONFLICTED,
                STATE_INSUFFICIENT_EVIDENCE,
                STATE_CONFIRMED_OBSERVED,
            },
        )

    def test_insufficient_when_no_hypotheses(self):
        self.assertEqual(
            derive_finding_state(**state_inputs(has_hypotheses=False)),
            STATE_INSUFFICIENT_EVIDENCE,
        )

    def test_insufficient_when_status_created_or_unknown(self):
        for status in ("CREATED", "UNKNOWN"):
            self.assertEqual(
                derive_finding_state(**state_inputs(status=status)),
                STATE_INSUFFICIENT_EVIDENCE,
                status,
            )

    def test_insufficient_when_nothing_observed_or_planned(self):
        self.assertEqual(
            derive_finding_state(
                **state_inputs(
                    context_fact_count=0,
                    evidence_missing=True,
                    evidence_state="UNKNOWN",
                    evidence_completeness="MISSING",
                )
            ),
            STATE_INSUFFICIENT_EVIDENCE,
        )

    def test_insufficient_precedence_over_conflicts(self):
        self.assertEqual(
            derive_finding_state(
                **state_inputs(has_hypotheses=False, conflict_count=2)
            ),
            STATE_INSUFFICIENT_EVIDENCE,
        )

    def test_conflicted_precedence_over_partial_evidence(self):
        self.assertEqual(
            derive_finding_state(
                **state_inputs(
                    conflict_count=1,
                    evidence_state="PARTIAL",
                    evidence_completeness="PARTIAL",
                )
            ),
            STATE_CONFLICTED,
        )

    def test_needs_more_evidence_for_partial_or_unknown(self):
        self.assertEqual(
            derive_finding_state(
                **state_inputs(
                    evidence_state="PARTIAL",
                    evidence_completeness="PARTIAL",
                )
            ),
            STATE_NEEDS_MORE_EVIDENCE,
        )
        self.assertEqual(
            derive_finding_state(
                **state_inputs(
                    evidence_state="UNKNOWN",
                    evidence_completeness="UNKNOWN",
                )
            ),
            STATE_NEEDS_MORE_EVIDENCE,
        )

    def test_research_candidate_when_complete_but_unverified(self):
        cases = (
            {"status": "ANALYZING"},
            {"evaluation_present": False, "evaluation_rating": "",
             "safety_state": "UNKNOWN", "hard_gate_state": ""},
            {"safety_state": "DEGRADED"},
            {"hard_gate_state": "CEILING_SAFETY"},
        )
        for case in cases:
            self.assertEqual(
                derive_finding_state(**state_inputs(**case)),
                STATE_RESEARCH_CANDIDATE,
                case,
            )

    def test_evidence_supported_requires_completed_safe_evaluation(self):
        state = derive_finding_state(
            **state_inputs(evaluation_rating="ACCEPTABLE")
        )
        self.assertEqual(state, STATE_EVIDENCE_SUPPORTED)
        state = derive_finding_state(
            **state_inputs(diagnostic_codes=["PROVENANCE_INCOMPLETE"])
        )
        self.assertEqual(state, STATE_EVIDENCE_SUPPORTED)

    def test_confirmed_observed_requires_complete_clean_observation(self):
        self.assertEqual(
            derive_finding_state(**state_inputs()),
            STATE_CONFIRMED_OBSERVED,
        )

    def test_confirmed_observed_requires_enough_observed_context(self):
        self.assertEqual(
            derive_finding_state(**state_inputs(context_fact_count=4)),
            STATE_EVIDENCE_SUPPORTED,
        )

    def test_confirmed_observed_requires_strong_rating(self):
        self.assertEqual(
            derive_finding_state(**state_inputs(evaluation_rating="ACCEPTABLE")),
            STATE_EVIDENCE_SUPPORTED,
        )
        self.assertEqual(
            derive_finding_state(**state_inputs(evaluation_rating="WEAK")),
            STATE_EVIDENCE_SUPPORTED,
        )

    def test_state_is_deterministic(self):
        first = derive_finding_state(**state_inputs())
        second = derive_finding_state(**state_inputs())
        self.assertEqual(first, second)
        self.assertIn(first, FINDING_STATES)


class TestFindingConfidence(unittest.TestCase):
    def test_confidence_helpers(self):
        self.assertEqual(confidence_rank("HIGH"), 3)
        self.assertEqual(confidence_rank("BOGUS"), 0)
        self.assertEqual(min_confidence("HIGH", "LOW", "MEDIUM"), "LOW")
        self.assertEqual(min_confidence("HIGH", "HIGH"), "HIGH")
        self.assertEqual(min_confidence(), "UNKNOWN")

    def test_confidence_is_the_meet_of_upstream_levels(self):
        derived = derive_finding_confidence(
            **confidence_inputs(
                result_confidence="HIGH",
                evidence_confidence="LOW",
                context_confidence="MEDIUM",
            )
        )
        self.assertEqual(derived["confidence"], "LOW")
        self.assertIn(
            "UPSTREAM_EVIDENCE_CONFIDENCE", derived["confidence_reasons"]
        )

    def test_confidence_never_exceeds_unknown_upstream(self):
        derived = derive_finding_confidence(
            **confidence_inputs(
                result_confidence="UNKNOWN",
                evidence_confidence="UNKNOWN",
                context_confidence="UNKNOWN",
            )
        )
        self.assertEqual(derived["confidence"], "UNKNOWN")
        self.assertIn(
            "NO_UPSTREAM_CONFIDENCE", derived["confidence_reasons"]
        )

    def test_missing_evaluation_caps_at_medium(self):
        derived = derive_finding_confidence(
            **confidence_inputs(evaluation_present=False)
        )
        self.assertEqual(derived["confidence"], "MEDIUM")
        self.assertIn(
            "EVALUATION_UNAVAILABLE_CAP", derived["confidence_reasons"]
        )

    def test_safety_degradation_caps_at_low(self):
        derived = derive_finding_confidence(
            **confidence_inputs(safety_state="DEGRADED")
        )
        self.assertEqual(derived["confidence"], "LOW")
        self.assertIn(
            "EVALUATION_SAFETY_CAP", derived["confidence_reasons"]
        )

    def test_weak_rating_caps_at_low_and_acceptable_at_medium(self):
        weak = derive_finding_confidence(
            **confidence_inputs(evaluation_rating="WEAK")
        )
        self.assertEqual(weak["confidence"], "LOW")
        acceptable = derive_finding_confidence(
            **confidence_inputs(evaluation_rating="ACCEPTABLE")
        )
        self.assertEqual(acceptable["confidence"], "MEDIUM")

    def test_confidence_overstated_diagnostic_caps_at_low(self):
        derived = derive_finding_confidence(
            **confidence_inputs(
                diagnostic_codes=["CONFIDENCE_OVERSTATED"]
            )
        )
        self.assertEqual(derived["confidence"], "LOW")
        self.assertIn(
            "EVALUATION_DIAGNOSTIC_CAP", derived["confidence_reasons"]
        )

    def test_quality_diagnostic_caps_at_medium(self):
        derived = derive_finding_confidence(
            **confidence_inputs(diagnostic_codes=["PROVENANCE_INCOMPLETE"])
        )
        self.assertEqual(derived["confidence"], "MEDIUM")

    def test_conflicts_cap_at_medium(self):
        derived = derive_finding_confidence(
            **confidence_inputs(conflict_count=1)
        )
        self.assertEqual(derived["confidence"], "MEDIUM")
        self.assertIn("CONFLICT_CAP", derived["confidence_reasons"])

    def test_insufficient_and_partial_states_cap_at_low(self):
        insufficient = derive_finding_confidence(
            **confidence_inputs(state=STATE_INSUFFICIENT_EVIDENCE)
        )
        self.assertEqual(insufficient["confidence"], "LOW")
        partial = derive_finding_confidence(
            **confidence_inputs(
                state=STATE_NEEDS_MORE_EVIDENCE,
                evidence_state="PARTIAL",
                evidence_completeness="PARTIAL",
            )
        )
        self.assertEqual(partial["confidence"], "LOW")

    def test_agreement_is_never_a_boost(self):
        # Correlation/agreement is not an input to the derivation: the
        # signature has no agreement parameter, and identical signals with
        # more conflicts never score higher.
        parameters = set(
            inspect.signature(derive_finding_confidence).parameters
        )
        for forbidden in (
            "agreement",
            "agreement_count",
            "correlated_agents",
            "correlation",
            "other_agents",
        ):
            self.assertNotIn(forbidden, parameters)
        clean = derive_finding_confidence(**confidence_inputs())
        conflicted = derive_finding_confidence(
            **confidence_inputs(conflict_count=3)
        )
        self.assertEqual(clean["confidence"], "HIGH")
        self.assertEqual(conflicted["confidence"], "MEDIUM")
        self.assertLess(
            confidence_rank(conflicted["confidence"]),
            confidence_rank(clean["confidence"]),
        )

    def test_reasons_are_closed_and_ordered(self):
        derived = derive_finding_confidence(
            **confidence_inputs(
                safety_state="DEGRADED",
                conflict_count=1,
                diagnostic_codes=["CONFIDENCE_OVERSTATED"],
            )
        )
        reasons = derived["confidence_reasons"]
        for reason in reasons:
            self.assertIn(reason, CONFIDENCE_REASONS)
        self.assertEqual(len(reasons), len(set(reasons)))
        self.assertEqual(
            reasons,
            [reason for reason in CONFIDENCE_REASONS if reason in reasons],
        )

    def test_confidence_is_deterministic(self):
        first = derive_finding_confidence(**confidence_inputs())
        second = derive_finding_confidence(**confidence_inputs())
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main(verbosity=2)
