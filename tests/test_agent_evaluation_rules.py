"""tests/test_agent_evaluation_rules.py — Stage R42.2 tests.

Deterministic, offline tests for the evaluation rule engine:

- all ten dimensions evaluated in canonical order
- structural validity, context completeness, hypothesis support
- evidence completeness, confidence calibration, safety compliance
- provenance completeness, governance completeness
- determinism and limitation disclosure
- score bounds, closed rule codes, deterministic outcomes

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_evaluation_input import (
    build_agent_evaluation_input,
)
from ai.knowledge.agent_evaluation_rules import (
    CONFIRMATION_CLAIM_TOKENS,
    EXECUTION_CLAIM_TOKENS,
    evaluate_evaluation_dimensions,
)
from ai.schemas.agent_evaluation_rule import (
    EVALUATION_DIMENSIONS,
    EVALUATION_RULES,
)


def clean_result(**over):
    result = {
        "rule_version": "r99-5",
        "agent_identity": {
            "rule_version": "r99-1",
            "agent_id": "sa-" + "a" * 16,
            "agent_name": "test-agent",
            "category": "XSS",
            "version": "1.0",
            "maturity": "RESEARCH",
            "supported_contexts": ["REFLECTED"],
            "supported_capabilities": ["ANALYZE_CONTEXT"],
            "lifecycle_state": "PLANNED",
            "limitations": ["NO_EXECUTION_CAPABILITY"],
            "research_only": True,
        },
        "status": "COMPLETED",
        "confidence": "HIGH",
        "context_analysis": {
            "input_location": "QUERY",
            "output_context": "HTML",
            "reflection_state": "REFLECTED",
            "encoding_state": "NONE_OBSERVED",
            "framework_context": "GENERIC",
            "url_handling": "FULL_URL",
            "server_side_fetch": "OBSERVED",
            "protocol_context": "HTTPS",
            "redirect_behavior": "FOLLOWED",
        },
        "hypotheses": [
            {
                "rule_version": "r99-3",
                "hypothesis_type": "REFLECTION_ANALYSIS",
                "supporting_signals": ["REFLECTION_OBSERVED"],
                "confidence": "HIGH",
                "priority": "HIGH",
                "limitations": [
                    "NO_EXPLOIT_CLAIM",
                    "NO_VULNERABILITY_CONFIRMATION",
                    "HYPOTHESIS_ONLY",
                    "EVIDENCE_REQUIRED",
                ],
                "research_only": True,
            }
        ],
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
            "NO_PAYLOAD_GENERATION",
            "NO_VULNERABILITY_CONFIRMATION",
            "HYPOTHESIS_ONLY",
            "EVIDENCE_REQUIRED",
        ],
        "provenance": {
            "rule_version": "r99-5",
            "source_layers": ["REASONING", "MEMORY", "STRATEGY",
                              "ORCHESTRATION", "AUTHORIZATION",
                              "GOVERNANCE"],
            "provenance_state": "COMPLETE",
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
    result.update(over)
    return result


def outcomes_for(result):
    evaluation_input = build_agent_evaluation_input(result)
    outcomes = evaluate_evaluation_dimensions(evaluation_input)
    return {outcome["dimension"]: outcome for outcome in outcomes}


def score_of(result, dimension):
    return outcomes_for(result)[dimension]["score"]


class TestAgentEvaluationRules(unittest.TestCase):
    def test_dimensions_are_complete_and_ordered(self):
        outcomes = evaluate_evaluation_dimensions(
            build_agent_evaluation_input(clean_result())
        )
        self.assertEqual(
            [outcome["dimension"] for outcome in outcomes],
            list(EVALUATION_DIMENSIONS),
        )
        self.assertEqual(len(outcomes), 10)

    def test_rule_vocabulary_is_closed(self):
        outcomes = evaluate_evaluation_dimensions(
            build_agent_evaluation_input(clean_result())
        )
        for outcome in outcomes:
            for rule in (
                outcome["passed_rules"] + outcome["failed_rules"]
            ):
                self.assertIn(rule, EVALUATION_RULES)

    def test_clean_result_scores_high(self):
        outcomes = evaluate_evaluation_dimensions(
            build_agent_evaluation_input(clean_result())
        )
        for outcome in outcomes:
            self.assertEqual(outcome["score"], 100, outcome["dimension"])
            self.assertEqual(outcome["failed_rules"], [])

    def test_structural_validity(self):
        self.assertEqual(score_of(clean_result(), "STRUCTURAL_VALIDITY"),
                         100)
        broken = clean_result()
        del broken["rule_version"]
        self.assertLess(
            score_of(broken, "STRUCTURAL_VALIDITY"), 100
        )
        unknown = clean_result()
        del unknown["agent_identity"]["category"]
        outcomes = outcomes_for(unknown)
        self.assertLess(
            outcomes["STRUCTURAL_VALIDITY"]["score"], 100
        )
        codes = [
            item["diagnostic_code"]
            for item in outcomes["STRUCTURAL_VALIDITY"]["diagnostics"]
        ]
        self.assertIn("UNKNOWN_AGENT_CATEGORY", codes)

    def test_context_completeness(self):
        rich = clean_result()
        sparse = clean_result(context_analysis={})
        self.assertEqual(
            score_of(rich, "CONTEXT_COMPLETENESS"), 100
        )
        self.assertLess(
            score_of(sparse, "CONTEXT_COMPLETENESS"), 40
        )
        outcomes = outcomes_for(sparse)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["CONTEXT_COMPLETENESS"]["diagnostics"]
        ]
        self.assertIn("CONTEXT_TOO_SPARSE", codes)

    def test_hypothesis_support(self):
        self.assertEqual(
            score_of(clean_result(), "HYPOTHESIS_SUPPORT"), 100
        )
        unsupported = clean_result()
        unsupported["hypotheses"][0]["supporting_signals"] = []
        self.assertLess(
            score_of(unsupported, "HYPOTHESIS_SUPPORT"), 100
        )
        missing_flags = clean_result()
        missing_flags["hypotheses"][0]["limitations"] = []
        outcomes = outcomes_for(missing_flags)
        self.assertLess(
            outcomes["HYPOTHESIS_SUPPORT"]["score"], 100
        )
        codes = [
            item["diagnostic_code"]
            for item in outcomes["HYPOTHESIS_SUPPORT"]["diagnostics"]
        ]
        self.assertIn("HYPOTHESIS_SAFETY_FLAGS_MISSING", codes)

    def test_no_hypotheses(self):
        outcomes = outcomes_for(clean_result(hypotheses=[]))
        self.assertEqual(
            outcomes["HYPOTHESIS_SUPPORT"]["score"], 40
        )
        codes = [
            item["diagnostic_code"]
            for item in outcomes["HYPOTHESIS_SUPPORT"]["diagnostics"]
        ]
        self.assertIn("NO_HYPOTHESES_REPORTED", codes)

    def test_evidence_completeness(self):
        self.assertEqual(
            score_of(clean_result(), "EVIDENCE_COMPLETENESS"), 100
        )
        no_items = clean_result()
        no_items["evidence_plan"]["evidence_items"] = []
        outcomes = outcomes_for(no_items)
        self.assertLess(
            outcomes["EVIDENCE_COMPLETENESS"]["score"], 40
        )
        codes = [
            item["diagnostic_code"]
            for item in outcomes["EVIDENCE_COMPLETENESS"]["diagnostics"]
        ]
        self.assertIn("MISSING_EVIDENCE_REQUIREMENT", codes)

        no_required = clean_result()
        no_required["evidence_plan"]["limitations"] = []
        no_required["hypotheses"][0]["limitations"] = [
            "NO_EXPLOIT_CLAIM",
            "NO_VULNERABILITY_CONFIRMATION",
            "HYPOTHESIS_ONLY",
        ]
        no_required["limitations"] = [
            "NO_EXECUTION_PERFORMED", "NO_VULNERABILITY_CONFIRMATION",
            "HYPOTHESIS_ONLY",
        ]
        outcomes = outcomes_for(no_required)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["EVIDENCE_COMPLETENESS"]["diagnostics"]
        ]
        self.assertIn(
            "EVIDENCE_REQUIRED_LIMITATION_MISSING", codes
        )

        inconsistent = clean_result()
        inconsistent["confidence"] = "LOW"
        outcomes = outcomes_for(inconsistent)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["EVIDENCE_COMPLETENESS"]["diagnostics"]
        ]
        self.assertIn("EVIDENCE_INCONSISTENT", codes)

    def test_confidence_calibration(self):
        self.assertEqual(
            score_of(clean_result(), "CONFIDENCE_CALIBRATION"), 100
        )
        overstated = clean_result(
            confidence="HIGH",
            context_analysis={"input_location": "QUERY"},
        )
        outcomes = outcomes_for(overstated)
        self.assertLess(
            outcomes["CONFIDENCE_CALIBRATION"]["score"], 100
        )
        codes = [
            item["diagnostic_code"]
            for item in outcomes["CONFIDENCE_CALIBRATION"]["diagnostics"]
        ]
        self.assertIn("CONFIDENCE_OVERSTATED", codes)

        underspecified = clean_result(confidence="UNKNOWN")
        outcomes = outcomes_for(underspecified)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["CONFIDENCE_CALIBRATION"]["diagnostics"]
        ]
        self.assertIn("CONFIDENCE_UNDERSPECIFIED", codes)

    def test_safety_compliance(self):
        self.assertEqual(
            score_of(clean_result(), "SAFETY_COMPLIANCE"), 100
        )
        not_research = clean_result(research_only=False)
        outcomes = outcomes_for(not_research)
        self.assertEqual(
            outcomes["SAFETY_COMPLIANCE"]["score"], 0
        )
        codes = [
            item["diagnostic_code"]
            for item in outcomes["SAFETY_COMPLIANCE"]["diagnostics"]
        ]
        self.assertIn("RESEARCH_ONLY_FALSE", codes)

    def test_safety_claims_detected(self):
        execution = clean_result()
        execution["hypotheses"][0]["limitations"].append(
            "PAYLOAD_SENT"
        )
        outcomes = outcomes_for(execution)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["SAFETY_COMPLIANCE"]["diagnostics"]
        ]
        self.assertIn("EXECUTION_CLAIM_DETECTED", codes)

        confirmation = clean_result()
        confirmation["hypotheses"][0]["limitations"].append(
            "VULNERABILITY_CONFIRMED"
        )
        outcomes = outcomes_for(confirmation)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["SAFETY_COMPLIANCE"]["diagnostics"]
        ]
        self.assertIn("VULNERABILITY_CONFIRMATION_CLAIM", codes)

    def test_safety_limitations_missing(self):
        missing = clean_result()
        missing["limitations"] = []
        missing["evidence_plan"]["limitations"] = []
        missing["hypotheses"][0]["limitations"] = []
        outcomes = outcomes_for(missing)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["SAFETY_COMPLIANCE"]["diagnostics"]
        ]
        self.assertIn("SAFETY_LIMITATION_MISSING", codes)

    def test_provenance_completeness(self):
        self.assertEqual(
            score_of(clean_result(), "PROVENANCE_COMPLETENESS"), 100
        )
        partial = clean_result()
        partial["provenance"] = {
            "rule_version": "r99-5",
            "source_layers": ["REASONING"],
            "provenance_state": "PARTIAL",
            "research_only": True,
        }
        self.assertLess(
            score_of(partial, "PROVENANCE_COMPLETENESS"), 100
        )
        unknown = clean_result()
        unknown["provenance"] = {
            "rule_version": "r99-5",
            "source_layers": [],
            "provenance_state": "UNKNOWN",
            "research_only": True,
        }
        outcomes = outcomes_for(unknown)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["PROVENANCE_COMPLETENESS"]["diagnostics"]
        ]
        self.assertIn("PROVENANCE_INCOMPLETE", codes)

        inconsistent = clean_result()
        inconsistent["provenance"] = {
            "rule_version": "r99-5",
            "source_layers": ["REASONING"],
            "provenance_state": "COMPLETE",
            "research_only": True,
        }
        self.assertLess(
            score_of(inconsistent, "PROVENANCE_COMPLETENESS"), 100
        )

    def test_governance_completeness(self):
        self.assertEqual(
            score_of(clean_result(), "GOVERNANCE_COMPLETENESS"), 100
        )
        unknown = clean_result()
        unknown["governance_reference"] = {
            "rule_version": "",
            "ready": False,
            "provenance_state": "UNKNOWN",
            "trace_state": "UNKNOWN",
            "audit_state": "UNKNOWN",
            "explanation_state": "UNKNOWN",
            "reference_state": "UNKNOWN",
        }
        outcomes = outcomes_for(unknown)
        self.assertLess(
            outcomes["GOVERNANCE_COMPLETENESS"]["score"], 100
        )
        codes = [
            item["diagnostic_code"]
            for item in outcomes["GOVERNANCE_COMPLETENESS"]["diagnostics"]
        ]
        self.assertIn("GOVERNANCE_UNKNOWN", codes)

        inconsistent = clean_result()
        inconsistent["governance_reference"]["ready"] = True
        inconsistent["governance_reference"][
            "provenance_state"
        ] = "UNKNOWN"
        outcomes = outcomes_for(inconsistent)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["GOVERNANCE_COMPLETENESS"]["diagnostics"]
        ]
        self.assertIn("GOVERNANCE_INCONSISTENT", codes)

    def test_determinism_dimension(self):
        self.assertEqual(
            score_of(clean_result(), "DETERMINISM"), 100
        )
        flagged = clean_result()
        flagged["created_at"] = "now"
        outcomes = outcomes_for(flagged)
        self.assertEqual(outcomes["DETERMINISM"]["score"], 0)
        codes = [
            item["diagnostic_code"]
            for item in outcomes["DETERMINISM"]["diagnostics"]
        ]
        self.assertIn("NON_DETERMINISTIC_OUTPUT", codes)

    def test_limitation_disclosure(self):
        self.assertEqual(
            score_of(clean_result(), "LIMITATION_DISCLOSURE"), 100
        )
        empty = clean_result(limitations=[])
        outcomes = outcomes_for(empty)
        self.assertLess(
            outcomes["LIMITATION_DISCLOSURE"]["score"], 40
        )
        codes = [
            item["diagnostic_code"]
            for item in outcomes["LIMITATION_DISCLOSURE"]["diagnostics"]
        ]
        self.assertIn("LIMITATION_DISCLOSURE_INCOMPLETE", codes)

        no_execution = clean_result()
        no_execution["limitations"] = [
            "NO_VULNERABILITY_CONFIRMATION", "HYPOTHESIS_ONLY"
        ]
        self.assertLess(
            score_of(no_execution, "LIMITATION_DISCLOSURE"), 100
        )

    def test_scores_are_bounded(self):
        results = (
            clean_result(),
            clean_result(confidence="UNKNOWN", context_analysis={}),
            clean_result(research_only=False),
            clean_result(hypotheses=[]),
        )
        for result in results:
            for outcome in evaluate_evaluation_dimensions(
                build_agent_evaluation_input(result)
            ):
                self.assertGreaterEqual(outcome["score"], 0)
                self.assertLessEqual(outcome["score"], 100)

    def test_outcomes_are_deterministic(self):
        evaluation_input = build_agent_evaluation_input(clean_result())
        first = evaluate_evaluation_dimensions(evaluation_input)
        second = evaluate_evaluation_dimensions(evaluation_input)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_claim_token_vocabularies(self):
        self.assertIn("EXECUTED", EXECUTION_CLAIM_TOKENS)
        self.assertIn(
            "VULNERABILITY_CONFIRMED", CONFIRMATION_CLAIM_TOKENS
        )

    def test_json_serializable(self):
        outcomes = evaluate_evaluation_dimensions(
            build_agent_evaluation_input(clean_result())
        )
        self.assertIsInstance(json.loads(json.dumps(outcomes)), list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
