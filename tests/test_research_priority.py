"""tests/test_research_priority.py — Stage R55 builder and integration tests.

Deterministic, offline tests for research prioritization:

- every priority band and bounded scores
- deterministic ranking, stable tie-breaking and shuffled input
- priority is not confidence (no confidence inflation, NOT_CONFIRMED)
- evidence, impact, severity, correlation, duplicate and conflict handling
- R44 learning signals and explicit learning unavailability
- governance constraints, provenance preservation and safety deferral
- malformed / empty / minimal / unsupported inputs and fail-closed behavior
- R53 -> R55 and R54 -> R55 integration and input immutability
- byte-identical deterministic output

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_orchestrator import orchestrate_research
from ai.knowledge.finding_builder import build_finding_intelligence
from ai.knowledge.finding_correlation import (
    correlate,
    correlate_findings,
)
from ai.knowledge.research_prioritization import (
    export_research_priorities,
    prioritize,
    prioritize_correlated_findings,
    prioritize_finding_intelligence,
    prioritize_findings,
)
from ai.schemas.learning_recommendation import (
    REC_DEDUPLICATE_HYPOTHESES,
    REC_PRIORITIZE_EVIDENCE_PLANNING,
    REC_RESTORE_SAFETY_BOUNDARY,
    REC_REVIEW_GOVERNANCE_REFERENCES,
    REC_STRENGTHEN_HYPOTHESES,
)
from ai.schemas.research_priority import (
    PRIORITY_BANDS,
    RESEARCH_PRIORITY_RULE_VERSION,
)
from ai.schemas.research_priority_result import (
    PRIORITIZATION_ID_RE,
    RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
)

from tests.test_research_priority_rules import (
    DEFAULT_AGENT,
    finding,
    recommend,
)

COMPONENT_ONE = {
    "availability": "PRESENT",
    "component_name": "SHARED_COMPONENT",
    "component_version": "1.0",
    "endpoint_reference": "/api/x",
}
COMPONENT_A = {
    "availability": "PRESENT",
    "component_name": "COMPONENT_A",
    "component_version": "",
    "endpoint_reference": "",
}
COMPONENT_B = {
    "availability": "PRESENT",
    "component_name": "COMPONENT_B",
    "component_version": "",
    "endpoint_reference": "",
}


def critical_finding(finding_id_value="fnd-" + "c" * 16, agent=DEFAULT_AGENT):
    return finding(
        "XSS",
        agent,
        finding_id_value=finding_id_value,
        context={
            "endpoint_path": "/search",
            "reflection_state": "REFLECTED",
            "parameter_name": "q",
            "output_context": "HTML",
            "input_location": "query",
        },
        state="CONFIRMED_OBSERVED",
        confidence="HIGH",
        severity="CRITICAL_OBSERVED",
        severity_source="CVSS_CONTEXT",
        impact_state="OBSERVED",
        governance_state="REFERENCED",
        governance_ready=True,
    )


def duplicate_findings():
    first = finding(
        "XSS",
        "sa-" + "1" * 16,
        finding_id_value="fnd-" + "1" * 16,
        context={"endpoint_path": "/a"},
        evidence_completeness="COMPLETE",
    )
    second = finding(
        "XSS",
        "sa-" + "1" * 16,
        finding_id_value="fnd-" + "2" * 16,
        context={"endpoint_path": "/a"},
        evidence_completeness="PARTIAL",
        evidence_state="PARTIAL",
    )
    return first, second


def conflicting_findings():
    first = finding(
        "XSS",
        "sa-" + "1" * 16,
        finding_id_value="fnd-" + "1" * 16,
        hypothesis_types=("REFLECTION_CONTEXT",),
        context={"endpoint_path": "/a"},
    )
    second = finding(
        "XSS",
        "sa-" + "2" * 16,
        finding_id_value="fnd-" + "2" * 16,
        hypothesis_types=("STORED_CONTEXT",),
        context={"endpoint_path": "/b"},
    )
    return first, second


def related_findings():
    first = finding(
        "XSS",
        "sa-" + "1" * 16,
        finding_id_value="fnd-" + "1" * 16,
        endpoint_component=COMPONENT_ONE,
    )
    second = finding(
        "SSRF",
        "sa-" + "2" * 16,
        finding_id_value="fnd-" + "2" * 16,
        hypothesis_types=("SERVER_SIDE_REQUEST",),
        evidence_requirements=("EVIDENCE_SSRF",),
        endpoint_component=COMPONENT_ONE,
    )
    return first, second


def independent_findings():
    first = finding(
        "XSS",
        "sa-" + "1" * 16,
        finding_id_value="fnd-" + "1" * 16,
        endpoint_component=COMPONENT_A,
    )
    second = finding(
        "SSRF",
        "sa-" + "2" * 16,
        finding_id_value="fnd-" + "2" * 16,
        hypothesis_types=("SERVER_SIDE_REQUEST",),
        evidence_requirements=("EVIDENCE_SSRF",),
        endpoint_component=COMPONENT_B,
    )
    return first, second


def plan_by_id(result, finding_id_value):
    for plan in result["ranked_findings"] + result["deferred_findings"]:
        if plan["finding_id"] == finding_id_value:
            return plan
    raise AssertionError(f"plan not found: {finding_id_value}")


def reason_has(result, finding_id_value, reason):
    return reason in plan_by_id(result, finding_id_value)["priority_reasons"]


def factor_of(plan, factor_code):
    for item in plan["priority_factors"]:
        if item["factor"] == factor_code:
            return item
    return {}


class TestBands(unittest.TestCase):
    def test_critical_band(self):
        result = prioritize_findings([critical_finding()])
        plan = result["ranked_findings"][0]
        self.assertEqual(plan["priority_band"], "CRITICAL")
        self.assertGreaterEqual(plan["priority_score"], 80)
        self.assertLessEqual(plan["priority_score"], 100)

    def test_high_band(self):
        raw = critical_finding()
        raw["assessment"]["impact_state"] = "POTENTIAL"
        raw["assessment"]["severity_source"] = "NOT_ASSESSED"
        raw["assessment"]["severity"] = "UNKNOWN"
        result = prioritize_findings([raw])
        plan = result["ranked_findings"][0]
        self.assertEqual(plan["priority_band"], "HIGH")
        self.assertGreaterEqual(plan["priority_score"], 65)

    def test_medium_band(self):
        result = prioritize_findings([finding("XSS", DEFAULT_AGENT)])
        plan = result["ranked_findings"][0]
        self.assertEqual(plan["priority_band"], "MEDIUM")
        self.assertGreaterEqual(plan["priority_score"], 45)

    def test_low_band(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            evidence_state="UNKNOWN",
            evidence_completeness="MISSING",
            evidence_requirements=None,
            context={},
            state="INSUFFICIENT_EVIDENCE",
            confidence="UNKNOWN",
            impact_state="UNKNOWN",
            orchestration_id="",
        )
        result = prioritize_findings([raw])
        plan = result["ranked_findings"][0]
        self.assertEqual(plan["priority_band"], "LOW")
        self.assertLess(plan["priority_score"], 45)

    def test_deferred_band(self):
        raw = finding("XSS", DEFAULT_AGENT, confirmation_state="CONFIRMED")
        result = prioritize_findings([raw])
        self.assertEqual(result["ranked_findings"], [])
        plan = result["deferred_findings"][0]
        self.assertEqual(plan["priority_band"], "DEFERRED")
        self.assertEqual(plan["priority_score"], 0)
        self.assertEqual(plan["ranking_position"], 0)

    def test_every_result_band_is_closed(self):
        for plan in prioritize_findings([critical_finding()])[
            "ranked_findings"
        ]:
            self.assertIn(plan["priority_band"], PRIORITY_BANDS)


class TestRanking(unittest.TestCase):
    def test_positions_are_sequential_from_one(self):
        findings = [
            critical_finding("fnd-" + "1" * 16),
            critical_finding("fnd-" + "2" * 16),
            critical_finding("fnd-" + "3" * 16),
        ]
        result = prioritize_findings(findings)
        positions = [
            plan["ranking_position"] for plan in result["ranked_findings"]
        ]
        self.assertEqual(positions, [1, 2, 3])

    def test_scores_are_non_increasing(self):
        findings = [
            critical_finding("fnd-" + "1" * 16),
            finding("XSS", DEFAULT_AGENT, finding_id_value="fnd-" + "2" * 16),
            finding(
                "SSRF",
                DEFAULT_AGENT,
                finding_id_value="fnd-" + "3" * 16,
                evidence_completeness="MISSING",
                evidence_state="UNKNOWN",
                evidence_requirements=None,
                state="INSUFFICIENT_EVIDENCE",
                confidence="UNKNOWN",
                impact_state="UNKNOWN",
            ),
        ]
        result = prioritize_findings(findings)
        scores = [
            plan["priority_score"] for plan in result["ranked_findings"]
        ]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_stable_tie_breaking_by_finding_id(self):
        first = finding(
            "XSS",
            DEFAULT_AGENT,
            finding_id_value="fnd-" + "1" * 16,
        )
        second = finding(
            "XSS",
            DEFAULT_AGENT,
            finding_id_value="fnd-" + "2" * 16,
        )
        forward = prioritize_findings([first, second])
        self.assertEqual(
            [plan["finding_id"] for plan in forward["ranked_findings"]],
            ["fnd-" + "1" * 16, "fnd-" + "2" * 16],
        )
        reversed_result = prioritize_findings([second, first])
        self.assertEqual(
            [
                plan["finding_id"]
                for plan in reversed_result["ranked_findings"]
            ],
            ["fnd-" + "1" * 16, "fnd-" + "2" * 16],
        )

    def test_shuffled_input_produces_identical_ranking(self):
        findings = [
            critical_finding("fnd-" + "1" * 16),
            finding("XSS", DEFAULT_AGENT, finding_id_value="fnd-" + "2" * 16),
            finding(
                "SSRF",
                "sa-" + "3" * 16,
                finding_id_value="fnd-" + "3" * 16,
            ),
            finding(
                "IDOR",
                "sa-" + "4" * 16,
                finding_id_value="fnd-" + "4" * 16,
            ),
        ]
        baseline = prioritize_findings(findings)
        rotations = (
            list(reversed(findings)),
            findings[1:] + findings[:1],
            findings[2:] + findings[:2],
            [findings[0], findings[2], findings[1], findings[3]],
        )
        baseline_order = [
            plan["finding_id"] for plan in baseline["ranked_findings"]
        ]
        for rotated in rotations:
            result = prioritize_findings(rotated)
            self.assertEqual(
                [
                    plan["finding_id"]
                    for plan in result["ranked_findings"]
                ],
                baseline_order,
            )

    def test_deterministic_byte_identical_output(self):
        findings = [
            critical_finding("fnd-" + "1" * 16),
            finding("XSS", DEFAULT_AGENT, finding_id_value="fnd-" + "2" * 16),
        ]
        first = prioritize_findings(findings)
        second = prioritize_findings(findings)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertEqual(first["prioritization_id"], second["prioritization_id"])


class TestPriorityIsNotConfidence(unittest.TestCase):
    def test_high_confidence_low_priority(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            confidence="HIGH",
            evidence_state="UNKNOWN",
            evidence_completeness="MISSING",
            evidence_requirements=None,
            context={},
            state="INSUFFICIENT_EVIDENCE",
            impact_state="UNKNOWN",
            orchestration_id="",
        )
        result = prioritize_findings([raw])
        plan = result["ranked_findings"][0]
        self.assertEqual(plan["confidence"], "HIGH")
        self.assertEqual(plan["priority_band"], "LOW")
        self.assertLess(plan["priority_score"], 45)

    def test_low_confidence_high_priority(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            confidence="LOW",
            state="EVIDENCE_SUPPORTED",
            impact_state="POTENTIAL",
            severity="CRITICAL_OBSERVED",
            severity_source="CVSS_CONTEXT",
            governance_state="REFERENCED",
            governance_ready=True,
            context={
                "endpoint_path": "/a",
                "b": "1",
                "c": "1",
                "d": "1",
                "e": "1",
            },
        )
        result = prioritize_findings([raw])
        plan = result["ranked_findings"][0]
        self.assertEqual(plan["confidence"], "LOW")
        self.assertEqual(plan["priority_band"], "HIGH")
        self.assertGreaterEqual(plan["priority_score"], 65)

    def test_confidence_effect_is_always_none(self):
        first, second = related_findings()
        result = prioritize_findings([first, second])
        self.assertEqual(result["confidence_effect"], "NONE")
        self.assertIn("CONFIDENCE_NOT_UPGRADED", result["limitations"])
        for plan in result["ranked_findings"]:
            self.assertEqual(plan["confidence_effect"], "NONE")
            self.assertIn("CONFIDENCE_NOT_UPGRADED", plan["limitations"])

    def test_confirmation_state_is_never_confirmed(self):
        unsafe = finding(
            "XSS", DEFAULT_AGENT, confirmation_state="CONFIRMED"
        )
        result = prioritize_findings(
            [critical_finding(), unsafe]
        )
        for plan in (
            result["ranked_findings"] + result["deferred_findings"]
        ):
            self.assertEqual(plan["confirmation_state"], "NOT_CONFIRMED")
            self.assertIn("NOT_CONFIRMED", plan["limitations"])
        self.assertIn("NOT_CONFIRMED", result["limitations"])

    def test_priority_never_modifies_upstream_confidence(self):
        first, second = duplicate_findings()
        snapshot = json.dumps([first, second], sort_keys=True)
        result = prioritize_findings([first, second])
        self.assertEqual(
            json.dumps([first, second], sort_keys=True), snapshot
        )
        self.assertEqual(
            plan_by_id(result, "fnd-" + "1" * 16)["confidence"],
            first["assessment"]["confidence"],
        )

    def test_agreement_does_not_inflate_confidence(self):
        first, second = related_findings()
        result = prioritize_findings([first, second])
        self.assertEqual(
            result["ranked_findings"][0]["confidence"], "MEDIUM"
        )
        self.assertEqual(
            result["ranked_findings"][1]["confidence"], "MEDIUM"
        )
        self.assertIn(
            "PRIORITY_NOT_CONFIDENCE", result["limitations"]
        )


class TestEvidenceHandling(unittest.TestCase):
    def test_complete_evidence_reason_and_factor(self):
        result = prioritize_findings([critical_finding()])
        plan = result["ranked_findings"][0]
        self.assertIn("COMPLETE_EVIDENCE", plan["priority_reasons"])
        self.assertEqual(
            factor_of(plan, "EVIDENCE_COMPLETENESS")["contribution"], 25
        )

    def test_partial_evidence_reason_and_factor(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            evidence_completeness="PARTIAL",
            evidence_state="PARTIAL",
        )
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertIn("PARTIAL_EVIDENCE", plan["priority_reasons"])
        self.assertEqual(
            factor_of(plan, "EVIDENCE_COMPLETENESS")["contribution"], 12
        )

    def test_missing_evidence_reason_and_factor(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            evidence_completeness="MISSING",
            evidence_state="UNKNOWN",
            evidence_requirements=None,
        )
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertIn("MISSING_EVIDENCE", plan["priority_reasons"])
        self.assertEqual(
            factor_of(plan, "EVIDENCE_COMPLETENESS")["contribution"], 0
        )
        self.assertIn("EVIDENCE_INCOMPLETE", plan["limitations"])

    def test_evidence_gap_finding_gets_meaningful_priority(self):
        gap = finding(
            "XSS",
            DEFAULT_AGENT,
            finding_id_value="fnd-" + "1" * 16,
            evidence_state="UNKNOWN",
            evidence_completeness="MISSING",
            evidence_requirements=None,
            context={"endpoint_path": "/a", "b": "1"},
            state="NEEDS_MORE_EVIDENCE",
            confidence="LOW",
            impact_state="POTENTIAL",
        )
        empty = finding(
            "XSS",
            DEFAULT_AGENT,
            finding_id_value="fnd-" + "2" * 16,
            evidence_state="UNKNOWN",
            evidence_completeness="MISSING",
            evidence_requirements=None,
            context={},
            state="INSUFFICIENT_EVIDENCE",
            confidence="UNKNOWN",
            impact_state="UNKNOWN",
            orchestration_id="",
        )
        result = prioritize_findings([empty, gap])
        gap_plan = plan_by_id(result, "fnd-" + "1" * 16)
        empty_plan = plan_by_id(result, "fnd-" + "2" * 16)
        self.assertIn("NEEDS_MORE_EVIDENCE", gap_plan["priority_reasons"])
        self.assertGreater(
            gap_plan["priority_score"], empty_plan["priority_score"]
        )
        self.assertLess(gap_plan["ranking_position"], 2)

    def test_context_missing_is_explicit(self):
        raw = finding("XSS", DEFAULT_AGENT, context={})
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertIn("INSUFFICIENT_CONTEXT", plan["priority_reasons"])
        self.assertIn("INSUFFICIENT_CONTEXT", plan["limitations"])


class TestImpactAndSeverity(unittest.TestCase):
    def test_potential_vs_observed_impact(self):
        potential = finding(
            "XSS",
            DEFAULT_AGENT,
            finding_id_value="fnd-" + "1" * 16,
            impact_state="POTENTIAL",
        )
        observed = finding(
            "XSS",
            DEFAULT_AGENT,
            finding_id_value="fnd-" + "2" * 16,
            impact_state="OBSERVED",
        )
        potential_plan = prioritize_findings([potential])["ranked_findings"][0]
        observed_plan = prioritize_findings([observed])["ranked_findings"][0]
        self.assertEqual(potential_plan["impact_state"], "POTENTIAL")
        self.assertEqual(
            factor_of(potential_plan, "IMPACT_SIGNAL")["contribution"], 6
        )
        self.assertIn("POTENTIAL_IMPACT", potential_plan["priority_reasons"])
        self.assertEqual(observed_plan["impact_state"], "OBSERVED")
        self.assertEqual(
            factor_of(observed_plan, "IMPACT_SIGNAL")["contribution"], 10
        )
        self.assertIn("OBSERVED_IMPACT", observed_plan["priority_reasons"])

    def test_impact_unknown_is_explicit_and_not_observed(self):
        raw = finding("XSS", DEFAULT_AGENT, impact_state="UNKNOWN")
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertEqual(plan["impact_state"], "UNKNOWN")
        self.assertIn("IMPACT_UNKNOWN", plan["priority_reasons"])
        self.assertIn("IMPACT_NOT_OBSERVED", plan["limitations"])

    def test_severity_never_computed_from_category(self):
        xss = finding("XSS", DEFAULT_AGENT, finding_id_value="fnd-" + "1" * 16)
        cve = finding(
            "CVE_RESEARCH",
            DEFAULT_AGENT,
            finding_id_value="fnd-" + "2" * 16,
        )
        for raw in (xss, cve):
            plan = prioritize_findings([raw])["ranked_findings"][0]
            self.assertEqual(plan["severity"], "UNKNOWN")
            self.assertEqual(plan["severity_source"], "NOT_ASSESSED")
            self.assertEqual(
                factor_of(plan, "SEVERITY_SIGNAL")["contribution"], 0
            )
            self.assertIn("SEVERITY_NOT_ASSESSED", plan["priority_reasons"])
            self.assertIn("SEVERITY_NOT_ASSESSED", plan["limitations"])

    def test_structured_cvss_context_is_consumed(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            severity="HIGH_OBSERVED",
            severity_source="CVSS_CONTEXT",
        )
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertEqual(plan["severity"], "HIGH_OBSERVED")
        self.assertEqual(plan["severity_source"], "CVSS_CONTEXT")
        self.assertEqual(
            factor_of(plan, "SEVERITY_SIGNAL")["contribution"], 6
        )
        self.assertIn("CVSS_CONTEXT_AVAILABLE", plan["priority_reasons"])


class TestCorrelationHandling(unittest.TestCase):
    def test_duplicate_research_reduction(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        self.assertEqual(
            correlation["relationships"][0]["relationship_type"],
            "DUPLICATE",
        )
        result = prioritize_findings(
            [second, first], correlation_result=correlation
        )
        self.assertEqual(len(result["ranked_findings"]), 2)
        representative = plan_by_id(result, "fnd-" + "1" * 16)
        redundant = plan_by_id(result, "fnd-" + "2" * 16)
        self.assertIn(
            "DUPLICATE_REPRESENTATIVE", representative["priority_reasons"]
        )
        self.assertIn(
            "DUPLICATE_RESEARCH_REDUCTION",
            redundant["priority_reasons"],
        )
        self.assertEqual(
            factor_of(redundant, "CORRELATION_CONTEXT")["contribution"], -6
        )
        self.assertLess(
            redundant["priority_score"], representative["priority_score"]
        )
        self.assertIn("DUPLICATE_RELATIONSHIP", result["limitations"])

    def test_first_duplicate_is_not_automatically_superior(self):
        strong = finding(
            "XSS",
            "sa-" + "1" * 16,
            finding_id_value="fnd-" + "2" * 16,
            evidence_completeness="COMPLETE",
        )
        weak = finding(
            "XSS",
            "sa-" + "1" * 16,
            finding_id_value="fnd-" + "1" * 16,
            evidence_completeness="PARTIAL",
            evidence_state="PARTIAL",
        )
        correlation = correlate_findings([weak, strong])
        result = prioritize_findings(
            [weak, strong], correlation_result=correlation
        )
        self.assertIn(
            "DUPLICATE_REPRESENTATIVE",
            plan_by_id(result, "fnd-" + "2" * 16)["priority_reasons"],
        )
        self.assertIn(
            "DUPLICATE_RESEARCH_REDUCTION",
            plan_by_id(result, "fnd-" + "1" * 16)["priority_reasons"],
        )

    def test_related_relationship_is_context_not_boost(self):
        first, second = related_findings()
        correlation = correlate_findings([first, second])
        self.assertEqual(
            correlation["relationships"][0]["relationship_type"], "RELATED"
        )
        result = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        for plan in result["ranked_findings"]:
            self.assertIn(
                "RELATED_FINDINGS_CONTEXT", plan["priority_reasons"]
            )
            self.assertEqual(
                factor_of(plan, "CORRELATION_CONTEXT")["contribution"], 0
            )
        self.assertIn("CONFIDENCE_NOT_UPGRADED", result["limitations"])

    def test_conflicting_findings_both_preserved_and_capped(self):
        first, second = conflicting_findings()
        first["assessment"]["impact_state"] = "OBSERVED"
        first["assessment"]["severity"] = "CRITICAL_OBSERVED"
        first["assessment"]["severity_source"] = "CVSS_CONTEXT"
        first["assessment"]["confidence"] = "HIGH"
        first["evidence"]["evidence_completeness"] = "COMPLETE"
        first["context"]["affected_context"] = [
            {"key": "endpoint_path", "value": "/a"},
            {"key": "b", "value": "1"},
            {"key": "c", "value": "1"},
            {"key": "d", "value": "1"},
            {"key": "e", "value": "1"},
        ]
        first["context"]["context_fact_count"] = 5
        correlation = correlate_findings([first, second])
        self.assertEqual(
            correlation["relationships"][0]["relationship_type"],
            "CONFLICTING",
        )
        result = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        self.assertEqual(len(result["ranked_findings"]), 2)
        first_id = first["identity"]["finding_id"]
        second_id = second["identity"]["finding_id"]
        first_plan = plan_by_id(result, first_id)
        second_plan = plan_by_id(result, second_id)
        self.assertEqual(first_plan["conflict_state"], "CONFLICT_PRESENT")
        self.assertEqual(second_plan["conflict_state"], "CONFLICT_PRESENT")
        self.assertIn(
            "CONFLICT_REQUIRES_REVIEW", first_plan["priority_reasons"]
        )
        self.assertLessEqual(first_plan["priority_score"], 64)
        self.assertEqual(first_plan["priority_band"], "MEDIUM")
        self.assertIn(second_id, first_plan["correlation_summary"][
            "conflict_sources"
        ])
        self.assertIn(first_id, second_plan["correlation_summary"][
            "conflict_sources"
        ])
        self.assertIn("CONFLICT_PRESENT", result["limitations"])
        self.assertIn("CONFLICT_PRESENT", first_plan["limitations"])

    def test_independent_findings_are_reported(self):
        first, second = independent_findings()
        correlation = correlate_findings([first, second])
        self.assertEqual(
            correlation["relationships"][0]["relationship_type"],
            "INDEPENDENT",
        )
        result = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        for plan in result["ranked_findings"]:
            self.assertIn("INDEPENDENT_FINDINGS", plan["priority_reasons"])
            self.assertEqual(
                factor_of(plan, "CORRELATION_CONTEXT")["contribution"], 0
            )

    def test_unknown_correlation_is_explicit(self):
        raw = finding("XSS", DEFAULT_AGENT)
        correlation = correlate_findings([raw])
        result = prioritize_findings(
            [raw], correlation_result=correlation
        )
        plan = result["ranked_findings"][0]
        self.assertIn("UNKNOWN_CORRELATION", plan["priority_reasons"])
        self.assertEqual(
            factor_of(plan, "CORRELATION_CONTEXT")["contribution"], 0
        )

    def test_unmatched_correlation_is_structured_mismatch(self):
        first, second = related_findings()
        correlation = correlate_findings([first, second])
        result = prioritize_findings(
            [first], correlation_result=correlation
        )
        categories = {
            error["error_category"] for error in result["errors"]
        }
        self.assertIn("CORRELATION_MISMATCH", categories)
        self.assertIn("CORRELATION_INCOMPLETE", result["limitations"])
        self.assertEqual(result["status"], "PARTIAL")


class TestLearningHandling(unittest.TestCase):
    def test_learning_signal_from_finding(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            learning_recommendations=[
                recommend(REC_PRIORITIZE_EVIDENCE_PLANNING)
            ],
        )
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertEqual(
            factor_of(plan, "LEARNING_SIGNAL")["value"],
            "LEARNING_REQUIRE_MORE_EVIDENCE",
        )
        self.assertEqual(
            factor_of(plan, "LEARNING_SIGNAL")["contribution"], 4
        )
        self.assertTrue(plan["learning_summary"]["available"])

    def test_learning_signal_from_container(self):
        raw = finding("XSS", DEFAULT_AGENT)
        learning = {
            "rule_version": "r52-5",
            "recommendations": [
                recommend(REC_STRENGTHEN_HYPOTHESES),
                recommend(REC_DEDUPLICATE_HYPOTHESES, agent_id="other"),
            ],
            "research_only": True,
        }
        result = prioritize(
            findings=[raw], learning_result=learning
        )
        plan = result["ranked_findings"][0]
        self.assertEqual(
            factor_of(plan, "LEARNING_SIGNAL")["value"],
            "LEARNING_STRENGTHEN_HYPOTHESES",
        )
        self.assertIn(
            "LEARNING_SIGNAL_STRENGTHEN_HYPOTHESIS",
            plan["priority_reasons"],
        )
        self.assertTrue(plan["learning_summary"]["available"])

    def test_learning_unavailable_is_explicit(self):
        raw = finding("XSS", DEFAULT_AGENT)
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertFalse(plan["learning_summary"]["available"])
        self.assertEqual(
            factor_of(plan, "LEARNING_SIGNAL")["value"],
            "LEARNING_UNAVAILABLE",
        )
        self.assertIn("LEARNING_UNAVAILABLE", plan["priority_reasons"])
        self.assertIn("LEARNING_UNAVAILABLE", plan["limitations"])

    def test_safety_boundary_learning_signal_defers(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            learning_recommendations=[
                recommend(REC_RESTORE_SAFETY_BOUNDARY)
            ],
        )
        result = prioritize_findings([raw])
        self.assertEqual(result["ranked_findings"], [])
        plan = result["deferred_findings"][0]
        self.assertIn(
            "LEARNING_SIGNAL_SAFETY_BOUNDARY", plan["priority_reasons"]
        )
        self.assertIn("SAFETY_DEFERRED", plan["priority_reasons"])

    def test_governance_review_learning_signal_caps(self):
        raw = critical_finding()
        raw["learning_recommendations"] = [
            recommend(REC_REVIEW_GOVERNANCE_REFERENCES)
        ]
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertLessEqual(plan["priority_score"], 64)
        self.assertEqual(plan["priority_band"], "MEDIUM")
        self.assertIn(
            "LEARNING_SIGNAL_REVIEW_GOVERNANCE",
            plan["priority_reasons"],
        )

    def test_learning_memory_is_not_modified(self):
        raw = finding("XSS", DEFAULT_AGENT)
        learning = {
            "rule_version": "r52-5",
            "recommendations": [recommend(REC_STRENGTHEN_HYPOTHESES)],
            "research_only": True,
        }
        snapshot = json.dumps(learning, sort_keys=True)
        prioritize(findings=[raw], learning_result=learning)
        self.assertEqual(json.dumps(learning, sort_keys=True), snapshot)


class TestGovernanceHandling(unittest.TestCase):
    def test_governance_unknown_caps_medium(self):
        raw = critical_finding()
        raw["governance"]["reference_state"] = "UNKNOWN"
        raw["governance"]["ready"] = False
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertEqual(plan["priority_band"], "MEDIUM")
        self.assertLessEqual(plan["priority_score"], 64)
        self.assertIn("GOVERNANCE_LIMITATION", plan["priority_reasons"])
        self.assertIn("GOVERNANCE_UNKNOWN", plan["limitations"])

    def test_governance_not_ready_caps_low(self):
        raw = critical_finding()
        raw["governance"]["ready"] = False
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertEqual(plan["priority_band"], "LOW")
        self.assertLessEqual(plan["priority_score"], 44)
        self.assertIn("GOVERNANCE_NOT_READY", plan["limitations"])

    def test_governance_ready_does_not_constrain(self):
        raw = critical_finding()
        plan = prioritize_findings([raw])["ranked_findings"][0]
        self.assertEqual(plan["priority_band"], "CRITICAL")
        self.assertEqual(
            plan["governance"]["reference_state"], "REFERENCED"
        )
        self.assertEqual(plan["governance"]["ready_state"], "READY")
        self.assertNotIn("GOVERNANCE_UNKNOWN", plan["limitations"])

    def test_governance_summary_is_aggregated(self):
        referenced = critical_finding("fnd-" + "1" * 16)
        unknown = finding(
            "XSS",
            DEFAULT_AGENT,
            finding_id_value="fnd-" + "2" * 16,
            governance_state="UNKNOWN",
        )
        result = prioritize_findings([referenced, unknown])
        self.assertEqual(
            result["governance"]["governance_state"], "MIXED"
        )
        self.assertEqual(
            result["governance"]["referenced_finding_ids"],
            ["fnd-" + "1" * 16],
        )
        self.assertEqual(
            result["governance"]["unknown_finding_ids"],
            ["fnd-" + "2" * 16],
        )

    def test_governance_never_claims_governed_execution(self):
        result = prioritize_findings([critical_finding()])
        serialized = json.dumps(result, sort_keys=True).upper()
        self.assertNotIn("GOVERNED_EXECUTION", serialized)
        self.assertNotIn("EXECUTION_AUTHORIZED", serialized)


class TestSafetyDeferral(unittest.TestCase):
    def assert_deferred(self, raw, reason):
        result = prioritize_findings([raw])
        self.assertEqual(result["ranked_findings"], [])
        self.assertEqual(len(result["deferred_findings"]), 1)
        plan = result["deferred_findings"][0]
        self.assertIn(reason, plan["priority_reasons"])
        self.assertIn("SAFETY_DEFERRED", plan["priority_reasons"])
        self.assertIn("SAFETY_DEFERRED", plan["limitations"])
        self.assertEqual(plan["priority_score"], 0)
        self.assertEqual(plan["priority_band"], "DEFERRED")
        return plan

    def test_non_research_only_is_deferred(self):
        raw = finding("XSS", DEFAULT_AGENT, research_only=False)
        self.assert_deferred(raw, "NON_RESEARCH_ONLY")

    def test_unsafe_confirmation_is_deferred(self):
        raw = finding(
            "XSS", DEFAULT_AGENT, confirmation_state="CONFIRMED"
        )
        self.assert_deferred(raw, "UNSAFE_CONFIRMATION")

    def test_safety_failure_is_deferred(self):
        raw = finding("XSS", DEFAULT_AGENT, safety_state="FAILED")
        self.assert_deferred(raw, "SAFETY_FAILURE")

    def test_hard_gate_failure_is_deferred(self):
        raw = finding("XSS", DEFAULT_AGENT, hard_gate_state="FAIL_SAFETY")
        self.assert_deferred(raw, "SAFETY_FAILURE")

    def test_forbidden_claim_is_deferred(self):
        raw = finding("XSS", DEFAULT_AGENT)
        raw["context"]["title"] = "VULNERABILITY_CONFIRMED on /search"
        self.assert_deferred(raw, "FORBIDDEN_CLAIM")

    def test_invalid_provenance_diagnostic_is_deferred(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            diagnostic_codes=["PROVENANCE_INVENTED_LAYER"],
        )
        self.assert_deferred(raw, "INVALID_PROVENANCE")

    def test_invalid_governance_diagnostic_is_deferred(self):
        raw = finding(
            "XSS",
            DEFAULT_AGENT,
            diagnostic_codes=["MALFORMED_GOVERNANCE"],
        )
        self.assert_deferred(raw, "INVALID_GOVERNANCE")

    def test_unsafe_findings_are_never_deleted(self):
        unsafe = finding(
            "XSS", DEFAULT_AGENT, confirmation_state="CONFIRMED"
        )
        safe = critical_finding("fnd-" + "1" * 16)
        result = prioritize_findings([unsafe, safe])
        self.assertEqual(len(result["ranked_findings"]), 1)
        self.assertEqual(len(result["deferred_findings"]), 1)
        self.assertEqual(result["deferred_findings"][0]["finding_id"],
                         unsafe["identity"]["finding_id"])
        self.assertEqual(result["status"], "PARTIAL")

    def test_unsafe_findings_are_not_boosted(self):
        plan = self.assert_deferred(
            finding("XSS", DEFAULT_AGENT, research_only=False),
            "NON_RESEARCH_ONLY",
        )
        self.assertEqual(plan["priority_factors"], [
            {
                "factor": "SAFETY_ELIGIBILITY",
                "value": "SAFETY_DEFERRED",
                "contribution": 0,
            }
        ])


class TestInputHandling(unittest.TestCase):
    def test_invalid_finding_intelligence_type_fails_closed(self):
        result = prioritize(finding_intelligence=42)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_INPUT"
        )

    def test_invalid_findings_type_fails_closed(self):
        result = prioritize(findings="nope")
        self.assertEqual(result["status"], "FAILED")

    def test_both_sources_fail_closed(self):
        raw = finding("XSS", DEFAULT_AGENT)
        result = prioritize(finding_intelligence={}, findings=[raw])
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_INPUT"
        )

    def test_wrong_finding_intelligence_rule_version_fails_closed(self):
        result = prioritize(
            finding_intelligence={"rule_version": "r99-9", "findings": []}
        )
        self.assertEqual(result["status"], "FAILED")

    def test_wrong_correlation_rule_version_fails_closed(self):
        result = prioritize(
            findings=[],
            correlation_result={
                "rule_version": "r99-9",
                "relationships": [],
            },
        )
        self.assertEqual(result["status"], "FAILED")

    def test_malformed_correlation_shape_fails_closed(self):
        result = prioritize(
            findings=[],
            correlation_result={
                "rule_version": "r54-2",
                "relationships": "nope",
            },
        )
        self.assertEqual(result["status"], "FAILED")

    def test_malformed_learning_shape_fails_closed(self):
        result = prioritize(
            findings=[],
            learning_result={"recommendations": "nope"},
        )
        self.assertEqual(result["status"], "FAILED")

    def test_malformed_finding_entry_is_skipped(self):
        valid = critical_finding()
        result = prioritize_findings([None, "x", valid])
        self.assertEqual(result["status"], "PARTIAL")
        reasons = {
            item["reason"] for item in result["skipped_findings"]
        }
        self.assertIn("MALFORMED_FINDING", reasons)
        self.assertEqual(len(result["ranked_findings"]), 1)

    def test_unsupported_category_is_skipped(self):
        raw = finding("BOGUS", DEFAULT_AGENT)
        result = prioritize_findings([raw])
        reasons = {
            item["reason"] for item in result["skipped_findings"]
        }
        self.assertIn("UNSUPPORTED_CATEGORY", reasons)
        self.assertEqual(result["ranked_findings"], [])
        self.assertEqual(result["status"], "PARTIAL")

    def test_duplicate_identity_is_skipped(self):
        raw = finding("XSS", DEFAULT_AGENT)
        result = prioritize_findings([raw, raw])
        reasons = {
            item["reason"] for item in result["skipped_findings"]
        }
        self.assertIn("DUPLICATE_IDENTITY", reasons)
        self.assertEqual(len(result["ranked_findings"]), 1)
        self.assertEqual(result["status"], "PARTIAL")

    def test_limit_exceeded_is_skipped(self):
        findings = [
            finding(
                "XSS",
                DEFAULT_AGENT,
                finding_id_value="fnd-" + format(index, "016x"),
            )
            for index in range(10)
        ]
        result = prioritize_findings(findings)
        self.assertEqual(len(result["ranked_findings"]), 8)
        reasons = {
            item["reason"] for item in result["skipped_findings"]
        }
        self.assertIn("LIMIT_EXCEEDED", reasons)

    def test_empty_input_is_no_findings(self):
        result = prioritize_findings([])
        self.assertEqual(result["status"], "NO_FINDINGS")
        self.assertEqual(result["ranked_findings"], [])
        self.assertIn("CORRELATION_UNAVAILABLE", result["limitations"])

    def test_no_input_is_no_findings(self):
        result = prioritize()
        self.assertEqual(result["status"], "NO_FINDINGS")
        self.assertTrue(result["research_only"])
        self.assertTrue(result["deterministic"])

    def test_minimal_input_is_prioritized_conservatively(self):
        raw = {
            "rule_version": "r53-6",
            "research_only": True,
            "identity": {
                "finding_id": "fnd-" + "1" * 16,
                "category": "XSS",
                "agent_id": DEFAULT_AGENT,
            },
        }
        result = prioritize_findings([raw])
        self.assertEqual(result["status"], "COMPLETED")
        plan = result["ranked_findings"][0]
        self.assertEqual(plan["priority_band"], "LOW")
        self.assertEqual(plan["severity"], "UNKNOWN")
        self.assertEqual(plan["severity_source"], "NOT_ASSESSED")
        self.assertEqual(plan["impact_state"], "UNKNOWN")

    def test_malformed_rule_version_entry_is_skipped(self):
        raw = finding("XSS", DEFAULT_AGENT, rule_version="r99-9")
        result = prioritize_findings([raw])
        reasons = {
            item["reason"] for item in result["skipped_findings"]
        }
        self.assertIn("MALFORMED_FINDING", reasons)


class TestImmutability(unittest.TestCase):
    def test_r53_intelligence_is_not_mutated(self):
        orchestration = orchestrate_research(
            research_context={
                "output_context": "HTML",
                "reflection_state": "REFLECTED",
            }
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        snapshot = json.dumps(intelligence, sort_keys=True)
        prioritize_finding_intelligence(intelligence)
        self.assertEqual(
            json.dumps(intelligence, sort_keys=True), snapshot
        )

    def test_r54_correlation_is_not_mutated(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        snapshot = json.dumps(correlation, sort_keys=True)
        prioritize_findings(
            [first, second], correlation_result=correlation
        )
        self.assertEqual(
            json.dumps(correlation, sort_keys=True), snapshot
        )

    def test_upstream_findings_are_not_mutated(self):
        first, second = conflicting_findings()
        snapshot = json.dumps([first, second], sort_keys=True)
        prioritize_findings([first, second])
        self.assertEqual(
            json.dumps([first, second], sort_keys=True), snapshot
        )

    def test_output_does_not_inject_fields_into_upstream(self):
        raw = critical_finding()
        result = prioritize_findings([raw])
        for key in (
            "priority_score",
            "priority_band",
            "priority_factors",
            "ranking_position",
            "confidence_effect",
        ):
            self.assertNotIn(key, raw)
            self.assertNotIn(key, raw["assessment"])
        self.assertIn("priority_score", result["ranked_findings"][0])


class TestIntegration(unittest.TestCase):
    def orchestrated_intelligence(self):
        orchestration = orchestrate_research(
            research_context={
                "output_context": "HTML",
                "reflection_state": "REFLECTED",
            }
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        return intelligence

    def test_r53_to_r55_integration(self):
        intelligence = self.orchestrated_intelligence()
        result = prioritize_finding_intelligence(intelligence)
        self.assertEqual(
            result["rule_version"],
            RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
        )
        self.assertEqual(result["finding_rule_version"], "r53-6")
        self.assertGreaterEqual(len(result["ranked_findings"]), 1)
        for plan in result["ranked_findings"]:
            self.assertEqual(plan["rule_version"],
                             RESEARCH_PRIORITY_RULE_VERSION)
            self.assertEqual(plan["confirmation_state"], "NOT_CONFIRMED")
            self.assertEqual(plan["confidence_effect"], "NONE")
            self.assertTrue(plan["provenance"]["finding_rule_version"])

    def test_r53_to_r54_to_r55_integration(self):
        intelligence = self.orchestrated_intelligence()
        correlation = correlate(finding_intelligence=intelligence)
        result = prioritize(
            finding_intelligence=intelligence,
            correlation_result=correlation,
        )
        self.assertEqual(result["correlation_rule_version"], "r54-1")
        for plan in result["ranked_findings"]:
            self.assertEqual(
                plan["provenance"]["correlation_rule_version"], "r54-1"
            )

    def test_r54_to_r55_integration(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        result = prioritize_correlated_findings(correlation)
        self.assertEqual(
            result["status"], "COMPLETED"
        )
        references = {
            plan["finding_id"] for plan in result["ranked_findings"]
        }
        self.assertEqual(
            references, {"fnd-" + "1" * 16, "fnd-" + "2" * 16}
        )
        for plan in result["ranked_findings"]:
            self.assertEqual(plan["provenance"]["source_kind"],
                             "R54_REFERENCE")
            self.assertEqual(plan["severity_source"], "NOT_ASSESSED")
            self.assertEqual(plan["impact_state"], "UNKNOWN")

    def test_alias_export_research_priorities(self):
        raw = finding("XSS", DEFAULT_AGENT)
        direct = prioritize(findings=[raw])
        alias = export_research_priorities(findings=[raw])
        self.assertEqual(direct, alias)

    def test_alias_prioritize_finding_intelligence(self):
        intelligence = self.orchestrated_intelligence()
        direct = prioritize(finding_intelligence=intelligence)
        alias = prioritize_finding_intelligence(intelligence)
        self.assertEqual(direct, alias)


class TestContainer(unittest.TestCase):
    def test_status_completed(self):
        result = prioritize_findings([critical_finding()])
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["confidence_effect"], "NONE")

    def test_status_partial_with_skipped(self):
        result = prioritize_findings([critical_finding(), None])
        self.assertEqual(result["status"], "PARTIAL")

    def test_prioritization_id_has_stable_format(self):
        result = prioritize_findings([critical_finding()])
        self.assertTrue(
            PRIORITIZATION_ID_RE.match(result["prioritization_id"])
        )

    def test_summary_counts(self):
        unsafe = finding(
            "XSS", DEFAULT_AGENT, confirmation_state="CONFIRMED"
        )
        result = prioritize_findings(
            [critical_finding("fnd-" + "1" * 16), unsafe]
        )
        summary = result["summary"]
        self.assertEqual(summary["finding_count"], 2)
        self.assertEqual(summary["ranked_count"], 1)
        self.assertEqual(summary["deferred_count"], 1)
        self.assertEqual(summary["evidence_complete_count"], 2)
        self.assertEqual(summary["severity_assessed_count"], 1)
        self.assertEqual(summary["impact_observed_count"], 1)
        self.assertEqual(summary["band_counts"]["CRITICAL"], 1)
        self.assertEqual(summary["band_counts"]["DEFERRED"], 1)

    def test_provenance_is_preserved(self):
        raw = critical_finding()
        result = prioritize_findings([raw])
        provenance = result["provenance"]
        self.assertEqual(provenance["finding_rule_version"], "r53-6")
        self.assertIn("R53_FINDING", provenance["source_kinds"])
        self.assertIn(
            raw["provenance"]["orchestration_id"],
            provenance["orchestration_ids"],
        )
        self.assertIn("XSS", provenance["source_categories"])
        plan_provenance = result["ranked_findings"][0]["provenance"]
        self.assertEqual(plan_provenance["source_kind"], "R53_FINDING")
        self.assertEqual(plan_provenance["finding_rule_version"], "r53-6")
        self.assertEqual(plan_provenance["orchestration_id"],
                         raw["provenance"]["orchestration_id"])
        self.assertEqual(plan_provenance["evaluation_rating"], "GOOD")
        self.assertEqual(plan_provenance["hard_gate_state"], "PASS")
        self.assertEqual(plan_provenance["safety_state"], "PASS")
        self.assertEqual(result["priority_rule_version"], "r55-3")

    def test_limitations_are_closed_and_ordered(self):
        result = prioritize_findings([critical_finding()])
        from ai.schemas.research_priority import PRIORITY_LIMITATIONS

        self.assertEqual(
            result["limitations"],
            [
                code
                for code in PRIORITY_LIMITATIONS
                if code in result["limitations"]
            ],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
