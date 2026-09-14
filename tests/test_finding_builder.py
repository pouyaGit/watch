"""tests/test_finding_builder.py — Stage R53.6 tests.

Deterministic, offline tests for the finding builder and R52 integration:

- R52 orchestration result -> R53 finding intelligence
- standalone structured specialist inputs
- correlation awareness (duplicate/related/conflicting) without isolation loss
- provenance, governance, references and learning preservation
- conservative limitations disclosure
- empty/minimal and malformed/unsupported inputs
- deterministic output and stable content ids

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_orchestrator import orchestrate_research
from ai.knowledge.finding_builder import (
    build_finding_intelligence,
    export_finding_intelligence,
    findings_from_orchestration,
)
from ai.knowledge.llm_provider import MockLLMProvider
from ai.knowledge.research_governance_export import (
    export_research_governance,
)
from ai.schemas.finding_result import (
    FINDING_SKIP_REASONS,
    INTELLIGENCE_STATUSES,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_PARTIAL,
)

AGENT_XSS = "sa-" + "a" * 16
AGENT_SSRF = "sa-" + "b" * 16
AGENT_SQLI = "sa-" + "c" * 16

MULTI_CONTEXT = {
    "input_location": "QUERY",
    "output_context": "HTML",
    "reflection_state": "REFLECTED",
    "encoding_state": "NONE_OBSERVED",
    "framework_context": "GENERIC",
    "parameter_type": "QUERY_PARAM",
    "query_context": "DATABASE_QUERY",
    "data_flow": "RAW_QUERY",
}


def xss_result(over=None):
    result = {
        "rule_version": "r39-5",
        "agent_name": "xss-agent",
        "status": "COMPLETED",
        "context_analysis": {
            "rule_version": "r39-2",
            "input_location": "QUERY",
            "output_context": "HTML",
            "reflection_state": "REFLECTED",
            "encoding_state": "NONE_OBSERVED",
            "framework_context": "GENERIC",
            "context_confidence": "HIGH",
            "research_only": True,
        },
        "hypotheses": [
            {
                "rule_version": "r39-3",
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
            "rule_version": "r39-4",
            "evidence_items": ["REFLECTION_EVIDENCE"],
            "evidence_state": "COMPLETE",
            "confidence": "HIGH",
            "limitations": ["EVIDENCE_REQUIRED"],
            "research_only": True,
        },
        "confidence": "HIGH",
        "limitations": [
            "NO_EXECUTION_PERFORMED",
            "NO_VULNERABILITY_CONFIRMATION",
        ],
        "governance_reference": {
            "rule_version": "",
            "ready": False,
            "reference_state": "UNKNOWN",
        },
        "research_only": True,
    }
    if over:
        result.update(over)
    return result


def xss_entry(result=None, agent_id=AGENT_XSS):
    return {
        "category": "XSS",
        "specialist_name": "xss-agent",
        "agent_id": agent_id,
        "stage": "INVOCATION",
        "result": result if result is not None else xss_result(),
        "evaluation_reference": {"reference_state": "UNKNOWN"},
        "collaboration_reference": {"reference_state": "UNKNOWN"},
        "feedback_reference": {"reference_state": "UNKNOWN"},
        "advisory_reference": {"reference_state": "UNKNOWN"},
    }


def evaluation(agent_id=AGENT_XSS, category="XSS", over=None):
    payload = {
        "rule_version": "r42-5",
        "evaluation_rule_version": "r42-5",
        "evaluated_agent_id": agent_id,
        "evaluated_agent_category": category,
        "evaluated_agent_rule_version": "r39-1",
        "evaluated_result_rule_version": "r39-5",
        "overall_score": 90,
        "overall_rating": "GOOD",
        "dimension_scores": [],
        "diagnostics": [],
        "hard_gate_state": "PASS",
        "safety_state": "PASS",
        "applied_caps": [],
        "deterministic": True,
        "research_only": True,
        "limitations": [],
    }
    if over:
        payload.update(over)
    return payload


def collaboration(over=None):
    payload = {
        "rule_version": "r43-6",
        "collaboration_rule_version": "r43-6",
        "collaboration_id": "collab-" + "d" * 16,
        "participating_agents": [
            {"agent_id": AGENT_XSS, "agent_category": "XSS"},
            {"agent_id": AGENT_SQLI, "agent_category": "SQLI"},
        ],
        "hypothesis_groups": [
            {
                "rule_version": "r43-3",
                "correlation_id": "hg-" + "1" * 16,
                "correlation_type": "DUPLICATE",
                "hypothesis_references": [],
                "participating_agents": [AGENT_XSS, AGENT_SQLI],
                "shared_signals": ["REFLECTION_OBSERVED"],
                "confidence_summary": {
                    "highest_confidence": "HIGH",
                    "lowest_confidence": "LOW",
                    "confidence_state": "DIVERGENT",
                },
                "member_count": 2,
            },
            {
                "rule_version": "r43-3",
                "correlation_id": "hg-" + "2" * 16,
                "correlation_type": "CONFLICTING",
                "hypothesis_references": [],
                "participating_agents": [AGENT_XSS, AGENT_SQLI],
                "shared_signals": [],
                "confidence_summary": {
                    "highest_confidence": "HIGH",
                    "lowest_confidence": "LOW",
                    "confidence_state": "CONFLICTING",
                },
                "member_count": 2,
            },
            {
                "rule_version": "r43-3",
                "correlation_id": "hg-" + "4" * 16,
                "correlation_type": "RELATED",
                "hypothesis_references": [],
                "participating_agents": [AGENT_SSRF],
                "shared_signals": [],
                "confidence_summary": {
                    "highest_confidence": "LOW",
                    "lowest_confidence": "LOW",
                    "confidence_state": "AGREE",
                },
                "member_count": 1,
            },
        ],
        "merged_evidence": {
            "rule_version": "r43-4",
            "evidence_items": [
                {
                    "rule_version": "r43-4",
                    "evidence_category": "SHARED_EVIDENCE",
                    "requirement_state": "REQUIRED",
                    "source_agents": [AGENT_XSS],
                    "hypothesis_references": [],
                    "source_count": 1,
                }
            ],
            "evidence_state": "PARTIAL",
            "confidence": "MEDIUM",
            "limitations": ["EVIDENCE_REQUIRED"],
            "research_only": True,
        },
        "conflicts": [
            {
                "rule_version": "r43-5",
                "conflict_id": "cf-" + "3" * 16,
                "conflict_type": "HYPOTHESIS_CONFLICT",
                "subjects": [AGENT_XSS, AGENT_SQLI],
                "conflicting_fields": ["confidence"],
                "resolution_state": "UNRESOLVED",
                "message": "conflicting confidence",
                "evidence_references": ["r43-5"],
            }
        ],
        "collaboration_rankings": [],
        "shared_context_summary": {},
        "governance_summary": {},
        "provenance_summary": {},
        "collaboration_diagnostics": [],
        "deterministic": True,
        "research_only": True,
        "limitations": [],
    }
    if over:
        payload.update(over)
    return payload


def feedback(over=None):
    payload = {
        "rule_version": "r52-5",
        "events": [
            {
                "rule_version": "r44-1",
                "feedback_id": "fb-" + "e" * 16,
                "source_agent": AGENT_XSS,
                "source_category": "XSS",
                "evaluation_reference": {},
                "collaboration_reference": {},
                "outcome_type": "QUALITY_OBSERVATION",
                "observed_issue": "NONE_OBSERVED",
                "observed_success": "NONE_OBSERVED",
                "confidence": "MEDIUM",
                "provenance": {},
                "governance_reference": {},
                "research_only": True,
                "structural_flags": [],
            }
        ],
        "classifications": [],
        "learning_signals": [],
        "recommendations": [
            {
                "rule_version": "r44-5",
                "recommendation_id": "rec-" + "f" * 16,
                "recommendation_type": "REVIEW_GOVERNANCE_REFERENCES",
                "related_agent": AGENT_XSS,
                "related_category": "XSS",
                "source_classification": "GOVERNANCE_ISSUE",
                "supporting_signals": [],
                "recommendation": "Review governance references",
                "confidence": "MEDIUM",
                "limitations": [],
            }
        ],
        "research_only": True,
    }
    if over:
        payload.update(over)
    return payload


class TestR52Integration(unittest.TestCase):
    def test_findings_from_orchestration_result(self):
        orchestration = orchestrate_research(
            research_context=MULTI_CONTEXT,
            governance_plan=export_research_governance(),
        )
        result = build_finding_intelligence(
            orchestration_result=orchestration
        )
        self.assertIn(result["status"], INTELLIGENCE_STATUSES)
        self.assertEqual(result["orchestration_id"],
                         orchestration["orchestration_id"])
        categories = [
            finding["identity"]["category"]
            for finding in result["findings"]
        ]
        self.assertEqual(
            categories,
            [entry["category"]
             for entry in orchestration["specialist_results"]],
        )
        for finding in result["findings"]:
            self.assertTrue(finding["research_only"])
            self.assertTrue(finding["deterministic"])
            self.assertEqual(
                finding["provenance"]["orchestration_id"],
                orchestration["orchestration_id"],
            )
            self.assertIn(
                "FINDING_INTELLIGENCE",
                finding["provenance"]["source_stages"],
            )
            self.assertEqual(
                finding["references"]["evaluation"]["reference_state"],
                "REFERENCED",
            )

    def test_findings_from_orchestration_alias(self):
        orchestration = orchestrate_research(
            research_context=MULTI_CONTEXT
        )
        first = findings_from_orchestration(orchestration)
        second = export_finding_intelligence(orchestration_result=orchestration)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_builder_does_not_mutate_orchestration_result(self):
        orchestration = orchestrate_research(
            research_context=MULTI_CONTEXT,
            governance_plan=export_research_governance(),
        )
        snapshot = json.dumps(orchestration, sort_keys=True)
        build_finding_intelligence(orchestration_result=orchestration)
        self.assertEqual(
            json.dumps(orchestration, sort_keys=True), snapshot
        )

    def test_r52_advisory_reference_is_preserved(self):
        orchestration = orchestrate_research(
            research_context={
                "output_context": "HTML",
                "reflection_state": "REFLECTED",
                "encoding_state": "NONE_OBSERVED",
            },
            policy={"advisory_enabled": True},
            advisory_provider=MockLLMProvider(),
        )
        result = build_finding_intelligence(
            orchestration_result=orchestration
        )
        self.assertTrue(result["advisory_reference"]["present"])
        self.assertEqual(
            result["advisory_reference"]["provider_state"], "OK"
        )
        for finding in result["findings"]:
            self.assertEqual(
                finding["references"]["advisory"]["reference_state"],
                "REFERENCED",
            )

    def test_r52_governance_reference_is_preserved(self):
        orchestration = orchestrate_research(
            research_context={"output_context": "HTML"},
            governance_plan=export_research_governance(),
        )
        result = build_finding_intelligence(
            orchestration_result=orchestration
        )
        self.assertEqual(
            result["governance"]["reference_state"], "REFERENCED"
        )
        self.assertNotIn("GOVERNANCE_UNKNOWN", result["limitations"])
        for finding in result["findings"]:
            self.assertEqual(
                finding["governance"]["reference_state"], "REFERENCED"
            )


class TestStandaloneInputs(unittest.TestCase):
    def test_standalone_specialist_result(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
            collaboration_result=collaboration(),
            feedback_result=feedback(),
        )
        self.assertEqual(result["status"], STATUS_COMPLETED)
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["identity"]["category"], "XSS")
        self.assertEqual(finding["identity"]["agent_id"], AGENT_XSS)
        self.assertEqual(
            finding["references"]["collaboration"]["collaboration_id"],
            "collab-" + "d" * 16,
        )
        self.assertEqual(
            finding["references"]["feedback"]["feedback_id"],
            "fb-" + "e" * 16,
        )
        self.assertEqual(len(finding["learning_recommendations"]), 1)

    def test_standalone_governance_plan(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            governance_plan=export_research_governance(),
        )
        self.assertEqual(
            result["governance"]["reference_state"], "REFERENCED"
        )

    def test_governance_unavailable_is_disclosed(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()]
        )
        self.assertEqual(result["governance"]["reference_state"], "UNKNOWN")
        self.assertIn("GOVERNANCE_UNKNOWN", result["limitations"])
        self.assertIn(
            "GOVERNANCE_UNKNOWN", result["findings"][0]["limitations"]
        )

    def test_mixed_specialists_produce_one_finding_each(self):
        result = build_finding_intelligence(
            specialist_results=[
                xss_entry(),
                {
                    "category": "SSRF",
                    "specialist_name": "ssrf-agent",
                    "agent_id": AGENT_SSRF,
                    "result": xss_result({"rule_version": "r40-5"}),
                },
            ]
        )
        categories = [
            finding["identity"]["category"]
            for finding in result["findings"]
        ]
        self.assertEqual(categories, ["XSS", "SSRF"])

    def test_both_inputs_is_invalid(self):
        result = build_finding_intelligence(
            orchestration_result={"specialist_results": []},
            specialist_results=[xss_entry()],
        )
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_INPUT"
        )
        self.assertEqual(result["findings"], [])

    def test_empty_input_is_no_findings(self):
        result = build_finding_intelligence()
        self.assertEqual(result["status"], STATUS_NO_FINDINGS)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["errors"], [])
        self.assertIn("NO_EXECUTION_PERFORMED", result["limitations"])

    def test_invalid_argument_types_fail_closed(self):
        cases = (
            {"orchestration_result": "nope"},
            {"specialist_results": "nope"},
            {"evaluation_results": "nope"},
            {"collaboration_result": "nope"},
            {"feedback_result": "nope"},
            {"governance_plan": "nope"},
        )
        for case in cases:
            result = build_finding_intelligence(**case)
            self.assertEqual(result["status"], STATUS_FAILED, case)
            self.assertEqual(
                result["errors"][0]["error_category"],
                "INVALID_INPUT",
                case,
            )


class TestSafetyFiltering(unittest.TestCase):
    def test_research_only_false_is_skipped(self):
        result = build_finding_intelligence(
            specialist_results=[
                xss_entry(xss_result({"research_only": False}))
            ]
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(
            result["skipped_candidates"][0]["reason"], "SAFETY_FAILURE"
        )
        self.assertEqual(
            result["errors"][0]["error_category"], "SAFETY_BLOCKED"
        )

    def test_forbidden_claim_is_skipped(self):
        unsafe = xss_result(
            {
                "hypotheses": [
                    {
                        "rule_version": "r39-3",
                        "hypothesis_type": "VULNERABILITY_CONFIRMED",
                        "supporting_signals": ["IS_VULNERABLE"],
                        "confidence": "HIGH",
                        "priority": "HIGH",
                        "limitations": [],
                    }
                ]
            }
        )
        result = build_finding_intelligence(
            specialist_results=[xss_entry(unsafe)]
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(
            result["skipped_candidates"][0]["reason"], "FORBIDDEN_CLAIM"
        )

    def test_safety_failed_evaluation_is_skipped(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[
                evaluation(over={"safety_state": "FAILED"})
            ],
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(
            result["skipped_candidates"][0]["reason"], "SAFETY_FAILURE"
        )

    def test_malformed_entry_is_skipped(self):
        result = build_finding_intelligence(
            specialist_results=[
                "not-a-result",
                {
                    "category": "XSS",
                    "agent_id": AGENT_XSS,
                    "result": "nope",
                },
            ]
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(len(result["skipped_candidates"]), 2)
        for skipped in result["skipped_candidates"]:
            self.assertEqual(skipped["reason"], "MALFORMED_RESULT")
        self.assertEqual(
            result["skipped_candidates"][1]["category"], "XSS"
        )

    def test_unsupported_category_is_skipped(self):
        result = build_finding_intelligence(
            specialist_results=[
                {
                    "category": "NOT_A_CATEGORY",
                    "agent_id": AGENT_XSS,
                    "result": xss_result(),
                }
            ]
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(
            result["skipped_candidates"][0]["reason"],
            "UNSUPPORTED_CATEGORY",
        )

    def test_skip_reasons_are_closed(self):
        result = build_finding_intelligence(
            specialist_results=[
                "bad",
                {"category": "BOGUS", "result": {}},
                xss_entry(xss_result({"research_only": False})),
            ]
        )
        for skipped in result["skipped_candidates"]:
            self.assertIn(skipped["reason"], FINDING_SKIP_REASONS)


class TestCorrelationAndProvenance(unittest.TestCase):
    def test_correlation_is_preserved_without_isolation_loss(self):
        result = build_finding_intelligence(
            specialist_results=[
                xss_entry(),
                {
                    "category": "SQLI",
                    "specialist_name": "sqli-agent",
                    "agent_id": AGENT_SQLI,
                    "result": xss_result({"rule_version": "r41-5"}),
                },
            ],
            collaboration_result=collaboration(),
        )
        for finding in result["findings"]:
            correlation = finding["correlation"]
            self.assertEqual(len(correlation["groups"]), 2)
            self.assertEqual(len(correlation["conflicts"]), 1)
            self.assertEqual(correlation["duplicate_group_count"], 1)
            self.assertEqual(correlation["conflicting_group_count"], 1)
            self.assertEqual(correlation["conflict_count"], 1)
            self.assertIn(
                "CONFLICT_PRESENT", finding["limitations"]
            )
            self.assertIn(
                "DUPLICATE_CORRELATION_PRESENT", finding["limitations"]
            )
        self.assertEqual(result["collaboration_reference"]["present"], True)
        self.assertEqual(
            result["collaboration_reference"]["duplicate_group_count"], 1
        )
        self.assertEqual(
            result["collaboration_reference"]["related_group_count"], 1
        )
        self.assertEqual(
            result["collaboration_reference"]["conflict_count"], 1
        )

    def test_other_agent_correlation_is_not_attached_but_is_counted(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            collaboration_result=collaboration(),
        )
        finding = result["findings"][0]
        participating = {
            agent
            for group in finding["correlation"]["groups"]
            for agent in group["participating_agents"]
        }
        self.assertNotIn(AGENT_SSRF, participating)
        self.assertEqual(len(finding["correlation"]["groups"]), 2)
        self.assertEqual(
            result["collaboration_reference"]["related_group_count"], 1
        )

    def test_findings_are_not_deduplicated(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry(), xss_entry(agent_id=AGENT_SSRF)],
            collaboration_result=collaboration(),
        )
        self.assertEqual(len(result["findings"]), 2)

    def test_correlation_unavailable_is_disclosed(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()]
        )
        finding = result["findings"][0]
        self.assertEqual(finding["correlation"]["groups"], [])
        self.assertIn(
            "COLLABORATION_UNAVAILABLE", finding["limitations"]
        )
        self.assertIn(
            "CORRELATION_UNAVAILABLE", finding["limitations"]
        )

    def test_provenance_preserves_origin(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
        )
        finding = result["findings"][0]
        self.assertEqual(finding["provenance"]["category"], "XSS")
        self.assertEqual(finding["provenance"]["agent_id"], AGENT_XSS)
        self.assertEqual(
            finding["provenance"]["specialist_name"], "xss-agent"
        )
        self.assertEqual(finding["provenance"]["source_stages"],
                         ["FINDING_INTELLIGENCE"])
        self.assertEqual(
            finding["provenance"]["rule_version"], "r53-6"
        )
        self.assertEqual(result["provenance"]["finding_count"], 1)

    def test_hypothesis_confidence_summary_is_computed(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()]
        )
        summary = result["findings"][0]["hypotheses"]["confidence_summary"]
        self.assertEqual(summary["highest_confidence"], "HIGH")
        self.assertEqual(summary["lowest_confidence"], "HIGH")
        self.assertEqual(summary["confidence_state"], "AGREE")

    def test_evaluation_reference_carries_diagnostics(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[
                evaluation(
                    over={
                        "overall_rating": "WEAK",
                        "diagnostics": [
                            {
                                "rule_version": "r42-4",
                                "diagnostic_code": "MISSING_REQUIRED_FIELD",
                                "severity": "HIGH",
                                "evidence_reference": "result",
                                "remediation_hint": "emit required fields",
                            }
                        ],
                    }
                )
            ],
        )
        finding = result["findings"][0]
        reference = finding["references"]["evaluation"]
        self.assertEqual(
            reference["diagnostic_codes"], ["MISSING_REQUIRED_FIELD"]
        )
        assessment = finding["assessment"]
        self.assertEqual(
            assessment["diagnostic_codes"], ["MISSING_REQUIRED_FIELD"]
        )
        self.assertEqual(assessment["remediation_state"], "AVAILABLE")
        self.assertEqual(
            assessment["remediation_items"][0]["source"],
            "MISSING_REQUIRED_FIELD",
        )

    def test_learning_recommendations_are_preserved(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            feedback_result=feedback(),
        )
        finding = result["findings"][0]
        self.assertEqual(len(finding["learning_recommendations"]), 1)
        self.assertEqual(
            finding["learning_recommendations"][0]["related_agent"],
            AGENT_XSS,
        )
        self.assertEqual(result["learning_reference"]["present"], True)
        self.assertEqual(
            result["learning_reference"]["recommendation_count"], 1
        )


class TestDeterminismAndLimitations(unittest.TestCase):
    def test_output_is_byte_identical(self):
        first = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
            collaboration_result=collaboration(),
            feedback_result=feedback(),
            governance_plan=export_research_governance(),
        )
        second = build_finding_intelligence(
            specialist_results=[copy.deepcopy(xss_entry())],
            evaluation_results=[copy.deepcopy(evaluation())],
            collaboration_result=copy.deepcopy(collaboration()),
            feedback_result=copy.deepcopy(feedback()),
            governance_plan=copy.deepcopy(export_research_governance()),
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertEqual(
            first["intelligence_id"], second["intelligence_id"]
        )
        self.assertTrue(first["intelligence_id"].startswith("fni-"))
        self.assertTrue(first["findings"][0]["finding_id"].startswith("fnd-"))

    def test_no_runtime_identifiers(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
        )
        serialized = json.dumps(result, sort_keys=True).lower()
        for token in ("timestamp", "created_at", "updated_at", "uuid",
                      "process_id", "runtime_id", "nonce"):
            self.assertNotIn(token, serialized)

    def test_limitations_are_disclosed(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
        )
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_VULNERABILITY_CONFIRMATION",
            "NO_EXPLOIT_GENERATION",
            "NO_EVIDENCE_COLLECTED",
            "HYPOTHESIS_ONLY",
        ):
            self.assertIn(limitation, result["limitations"])
            self.assertIn(limitation, result["findings"][0]["limitations"])
        finding = result["findings"][0]
        for limitation in (
            "IMPACT_NOT_OBSERVED",
            "REMEDIATION_UNAVAILABLE",
            "SEVERITY_NOT_ASSESSED",
            "ADVISORY_UNAVAILABLE",
        ):
            self.assertIn(limitation, finding["limitations"])

    def test_evaluation_summary_is_bounded(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
        )
        summary = result["evaluation_summary"]
        self.assertTrue(summary["present"])
        self.assertEqual(summary["evaluated_count"], 1)
        self.assertEqual(summary["safety_states"], ["PASS"])

    def test_severity_mirrored_from_structured_context(self):
        result = build_finding_intelligence(
            specialist_results=[
                {
                    "category": "CVE_RESEARCH",
                    "specialist_name": "cve-research-specialist",
                    "agent_id": AGENT_XSS,
                    "result": xss_result(
                        {
                            "rule_version": "r50-5",
                            "context_analysis": {
                                "rule_version": "r50-2",
                                "cvss_severity": "HIGH_OBSERVED",
                                "observed_component": "LOG4J",
                                "observed_version": "2.14.1",
                            },
                        }
                    ),
                }
            ]
        )
        finding = result["findings"][0]
        self.assertEqual(
            finding["assessment"]["severity"], "HIGH_OBSERVED"
        )
        self.assertEqual(
            finding["assessment"]["severity_source"], "CVSS_CONTEXT"
        )
        self.assertNotIn(
            "SEVERITY_NOT_ASSESSED", finding["limitations"]
        )
        self.assertEqual(
            finding["context"]["endpoint_component"]["component_name"],
            "LOG4J",
        )

    def test_intelligence_id_changes_with_content(self):
        first = build_finding_intelligence(
            specialist_results=[xss_entry()]
        )
        second = build_finding_intelligence(
            specialist_results=[
                xss_entry(
                    xss_result(
                        {
                            "evidence_plan": {
                                "rule_version": "r39-4",
                                "evidence_items": ["REFLECTION_EVIDENCE"],
                                "evidence_state": "PARTIAL",
                                "confidence": "MEDIUM",
                                "limitations": ["EVIDENCE_REQUIRED"],
                            }
                        }
                    )
                )
            ]
        )
        self.assertNotEqual(
            first["intelligence_id"], second["intelligence_id"]
        )
        # Finding identity is stable across research-state updates: only the
        # state (and the container id) changes, not the finding identity.
        self.assertEqual(
            first["findings"][0]["finding_id"],
            second["findings"][0]["finding_id"],
        )
        self.assertNotEqual(
            first["findings"][0]["state"],
            second["findings"][0]["state"],
        )

    def test_status_variants(self):
        completed = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
        )
        self.assertEqual(completed["status"], STATUS_COMPLETED)
        partial = build_finding_intelligence(
            specialist_results=[xss_entry(), "malformed"]
        )
        self.assertEqual(partial["status"], STATUS_PARTIAL)
        empty = build_finding_intelligence()
        self.assertEqual(empty["status"], STATUS_NO_FINDINGS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
