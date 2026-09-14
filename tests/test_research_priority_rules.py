"""tests/test_research_priority_rules.py — Stage R55.1–R55.3 tests.

Deterministic, offline tests for research-priority rules and schemas:

- closed priority bands, factor codes, factor values, reasons, limitations
- documented contribution tables and bounded scores
- priority is not confidence; NOT_CONFIRMED and confidence_effect invariants
- deterministic factor calculation, caps and reason generation
- correlation contexts (duplicate/related/conflicting/independent/unknown)
- deterministic duplicate-representative selection
- R44 learning signal interpretation as advisory context
- governance constraints and safety-first deferral markers
- schema validation and preservation contracts

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import hashlib
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.finding_correlation import correlate_findings
from ai.knowledge.research_priority_rules import (
    CAP_LOW_SCORE,
    CAP_MEDIUM_SCORE,
    CONFIDENCE_CONTRIBUTIONS,
    CONTEXT_COMPLETE,
    CONTEXT_COMPLETE_MIN_FACTS,
    CONTEXT_CONTRIBUTIONS,
    CONTEXT_MISSING,
    CONTEXT_PARTIAL,
    CORRELATION_CONTRIBUTIONS,
    EVIDENCE_CONTRIBUTIONS,
    IMPACT_CONTRIBUTIONS,
    LEARNING_CONTRIBUTIONS,
    LEARNING_SIGNAL_MAP,
    LEARNING_SIGNAL_PRECEDENCE,
    PROVENANCE_CONTRIBUTIONS,
    SEVERITY_CONTRIBUTIONS,
    STATE_CONTRIBUTIONS,
    build_correlation_contexts,
    context_class,
    duplicate_preference,
    duplicate_representative,
    empty_correlation_context,
    evaluate_candidate,
    finding_candidate,
    governance_class,
    learning_deferral,
    learning_recommendations_for,
    priority_limitations,
    provenance_class,
    reference_candidate,
)
from ai.schemas.finding_correlation import (
    RELATIONSHIP_CONFLICTING,
    RELATIONSHIP_DUPLICATE,
    RELATIONSHIP_INDEPENDENT,
    RELATIONSHIP_RELATED,
)
from ai.schemas.finding_result import sanitize_finding
from ai.schemas.learning_recommendation import (
    REC_DEDUPLICATE_HYPOTHESES,
    REC_PRESERVE_SUCCESSFUL_PATTERN,
    REC_PRIORITIZE_EVIDENCE_PLANNING,
    REC_RESTORE_SAFETY_BOUNDARY,
    REC_REVIEW_GOVERNANCE_REFERENCES,
    REC_STRENGTHEN_HYPOTHESES,
)
from ai.schemas.research_priority import (
    BAND_CAP_LOW,
    BAND_CAP_MEDIUM,
    BAND_CRITICAL,
    BAND_DEFERRED,
    BAND_HIGH,
    BAND_LOW,
    BAND_MEDIUM,
    FACTOR_CORRELATION_CONTEXT,
    FACTOR_EVIDENCE_COMPLETENESS,
    FACTOR_GOVERNANCE_CONSTRAINT,
    FACTOR_LEARNING_SIGNAL,
    FACTOR_SEVERITY_SIGNAL,
    MAX_FACTOR_CONTRIBUTION,
    MAX_PRIORITY_SCORE,
    MIN_FACTOR_CONTRIBUTION,
    PRIORITY_BAND_RANK,
    PRIORITY_BANDS,
    PRIORITY_FACTOR_CODES,
    PRIORITY_LIMITATIONS,
    PRIORITY_REASONS,
    RESEARCH_PRIORITY_RULE_VERSION,
    ResearchPriorityPlan,
    band_for_score,
    sanitize_priority_factor,
    sanitize_research_priority,
)

DEFAULT_AGENT = "sa-" + "a" * 16


def finding_id(category, agent_id, suffix=""):
    digest = hashlib.sha256(
        f"{category}:{agent_id}:{suffix}".encode("utf-8")
    ).hexdigest()
    return "fnd-" + digest[:16]


def finding(
    category="XSS",
    agent_id=None,
    *,
    suffix="",
    finding_id_value=None,
    context=None,
    endpoint_component=None,
    hypothesis_types=("REFLECTION_CONTEXT",),
    evidence_state="COMPLETE",
    evidence_completeness="COMPLETE",
    evidence_requirements=("EVIDENCE_REFLECTION",),
    confidence="MEDIUM",
    state="EVIDENCE_SUPPORTED",
    severity="UNKNOWN",
    severity_source="NOT_ASSESSED",
    impact_state="POTENTIAL",
    impact_confidence="UNKNOWN",
    impact_description="",
    governance_state="UNKNOWN",
    governance_ready=False,
    orchestration_id="orch-" + "1" * 16,
    confirmation_state="NOT_CONFIRMED",
    research_only=True,
    learning_recommendations=None,
    conflicts=None,
    evaluation_present=True,
    evaluation_rating="GOOD",
    safety_state="PASS",
    hard_gate_state="PASS",
    diagnostic_codes=None,
    rule_version="r53-6",
):
    agent = agent_id or (
        "sa-" + hashlib.sha256(category.encode("utf-8")).hexdigest()[:16]
    )
    fid = finding_id_value or finding_id(category, agent, suffix)
    facts = [
        {"key": key, "value": value}
        for key, value in (context or {}).items()
    ]
    hypotheses = []
    for index, hypothesis_type in enumerate(hypothesis_types or ()):
        hypotheses.append(
            {
                "rule_version": "r99-3",
                "agent_id": agent,
                "agent_category": category,
                "hypothesis_index": index,
                "hypothesis_type": hypothesis_type,
                "supporting_signals": [],
                "confidence": confidence,
                "priority": confidence,
                "limitations": [],
                "subject_reference": "",
                "rationale": "",
                "fingerprint": "",
                "research_only": True,
            }
        )
    component = endpoint_component or {
        "availability": "UNAVAILABLE",
        "component_name": "",
        "component_version": "",
        "endpoint_reference": "",
    }
    limitations = ["NO_EXECUTION_PERFORMED"]
    for code in diagnostic_codes or ():
        if code not in limitations:
            limitations.append(code)
    return {
        "rule_version": rule_version,
        "finding_id": fid,
        "state": state,
        "identity": {
            "rule_version": "r53-1",
            "finding_id": fid,
            "category": category,
            "specialist_name": f"{category.lower()}-agent",
            "agent_id": agent,
            "category_label": "",
            "descriptive_label": "",
            "research_only": True,
        },
        "context": {
            "rule_version": "r53-2",
            "title": "",
            "summary": "",
            "technical_description": "",
            "affected_context": facts,
            "endpoint_component": component,
            "context_fact_count": len(facts),
            "research_only": True,
        },
        "hypotheses": {
            "rule_version": "r53-3",
            "references": hypotheses,
            "hypothesis_count": len(hypotheses),
            "hypothesis_types": list(hypothesis_types or ()),
            "confidence_summary": {},
            "research_only": True,
        },
        "evidence": {
            "rule_version": "r53-4",
            "evidence_state": evidence_state,
            "evidence_completeness": evidence_completeness,
            "evidence_origin": "SPECIALIST_PLAN",
            "observed_context": facts,
            "planned_requirements": list(evidence_requirements or ()),
            "merged_requirements": [],
            "evidence_references": [],
            "evidence_missing": not evidence_requirements,
            "assumptions_recorded": False,
            "research_only": True,
        },
        "assessment": {
            "rule_version": "r53-5",
            "state": state,
            "confidence": confidence,
            "confidence_reasons": [],
            "severity": severity,
            "severity_source": severity_source,
            "impact_state": impact_state,
            "impact_confidence": impact_confidence,
            "impact_description": impact_description,
            "business_impact_asserted": False,
            "remediation_state": "UNAVAILABLE",
            "remediation_items": [],
            "confirmation_state": confirmation_state,
            "evaluation_present": evaluation_present,
            "evaluation_rating": evaluation_rating,
            "hard_gate_state": hard_gate_state,
            "safety_state": safety_state,
            "diagnostic_codes": list(diagnostic_codes or ()),
            "research_only": True,
        },
        "correlation": {
            "rule_version": "",
            "groups": [],
            "conflicts": list(conflicts or ()),
            "research_only": True,
        },
        "references": {},
        "learning_recommendations": list(learning_recommendations or ()),
        "provenance": {
            "rule_version": "r53-6",
            "category": category,
            "specialist_name": f"{category.lower()}-agent",
            "agent_id": agent,
            "orchestration_id": orchestration_id,
            "source_stages": ["FINDING_INTELLIGENCE"],
            "deterministic": True,
            "research_only": True,
        },
        "governance": {
            "rule_version": "" if governance_state == "UNKNOWN" else "r37-4",
            "ready": governance_ready,
            "provenance_state": "UNKNOWN",
            "trace_state": "UNKNOWN",
            "audit_state": "UNKNOWN",
            "explanation_state": "UNKNOWN",
            "reference_state": governance_state,
        },
        "limitations": limitations,
        "research_only": research_only,
        "deterministic": True,
    }


def candidate(raw_finding):
    return finding_candidate(sanitize_finding(raw_finding))


def recommend(recommendation_type, agent_id=DEFAULT_AGENT, category="XSS"):
    return {
        "rule_version": "r44-5",
        "recommendation_id": "rec-" + "a" * 16,
        "recommendation_type": recommendation_type,
        "related_agent": agent_id,
        "related_category": category,
        "source_classification": "UNKNOWN",
        "supporting_signals": [],
        "recommendation": "",
        "confidence": "UNKNOWN",
        "limitations": [],
    }


def factor_map(evaluated):
    return {
        item["factor"]: item for item in evaluated["priority_factors"]
    }


class TestVocabulary(unittest.TestCase):
    def test_bands_are_closed(self):
        self.assertEqual(
            set(PRIORITY_BANDS),
            {BAND_CRITICAL, BAND_HIGH, BAND_MEDIUM, BAND_LOW, BAND_DEFERRED},
        )

    def test_factor_codes_are_closed(self):
        self.assertEqual(
            len(PRIORITY_FACTOR_CODES), len(set(PRIORITY_FACTOR_CODES))
        )
        projected = sanitize_priority_factor(
            {
                "factor": FACTOR_EVIDENCE_COMPLETENESS,
                "value": "COMPLETE",
                "contribution": 25,
            }
        )
        self.assertEqual(projected["contribution"], 25)
        self.assertEqual(
            sanitize_priority_factor(
                {"factor": "NOT_A_FACTOR", "value": "X", "contribution": 1}
            ),
            {},
        )
        self.assertEqual(
            sanitize_priority_factor(
                {
                    "factor": FACTOR_EVIDENCE_COMPLETENESS,
                    "value": "NOT_A_VALUE",
                    "contribution": 1,
                }
            ),
            {},
        )

    def test_reasons_are_closed(self):
        self.assertEqual(len(PRIORITY_REASONS), len(set(PRIORITY_REASONS)))
        self.assertIn("SAFETY_DEFERRED", PRIORITY_REASONS)
        self.assertIn("NEEDS_MORE_EVIDENCE", PRIORITY_REASONS)

    def test_limitations_are_closed(self):
        self.assertEqual(
            len(PRIORITY_LIMITATIONS), len(set(PRIORITY_LIMITATIONS))
        )
        self.assertIn("PRIORITY_NOT_CONFIDENCE", PRIORITY_LIMITATIONS)
        self.assertIn("NOT_CONFIRMED", PRIORITY_LIMITATIONS)

    def test_contribution_tables_are_documented_and_bounded(self):
        tables = (
            EVIDENCE_CONTRIBUTIONS,
            CONTEXT_CONTRIBUTIONS,
            STATE_CONTRIBUTIONS,
            CONFIDENCE_CONTRIBUTIONS,
            IMPACT_CONTRIBUTIONS,
            SEVERITY_CONTRIBUTIONS,
            CORRELATION_CONTRIBUTIONS,
            LEARNING_CONTRIBUTIONS,
            PROVENANCE_CONTRIBUTIONS,
        )
        for table in tables:
            self.assertTrue(table)
            for contribution in table.values():
                self.assertGreaterEqual(
                    contribution, MIN_FACTOR_CONTRIBUTION
                )
                self.assertLessEqual(
                    contribution, MAX_FACTOR_CONTRIBUTION
                )

    def test_correlation_never_boosts(self):
        from ai.schemas.research_priority import (
            CORRELATION_CONFLICTING,
            CORRELATION_INDEPENDENT,
            CORRELATION_RELATED,
        )

        self.assertEqual(CORRELATION_CONTRIBUTIONS[CORRELATION_RELATED], 0)
        self.assertEqual(
            CORRELATION_CONTRIBUTIONS[CORRELATION_INDEPENDENT], 0
        )
        self.assertLess(
            CORRELATION_CONTRIBUTIONS[CORRELATION_CONFLICTING], 0
        )

    def test_band_rank_is_closed(self):
        self.assertEqual(set(PRIORITY_BAND_RANK), set(PRIORITY_BANDS))
        self.assertGreater(
            PRIORITY_BAND_RANK[BAND_CRITICAL],
            PRIORITY_BAND_RANK[BAND_HIGH],
        )
        self.assertGreater(
            PRIORITY_BAND_RANK[BAND_HIGH], PRIORITY_BAND_RANK[BAND_MEDIUM]
        )
        self.assertGreater(
            PRIORITY_BAND_RANK[BAND_MEDIUM], PRIORITY_BAND_RANK[BAND_LOW]
        )
        self.assertGreater(
            PRIORITY_BAND_RANK[BAND_LOW], PRIORITY_BAND_RANK[BAND_DEFERRED]
        )


class TestBands(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(band_for_score(100), BAND_CRITICAL)
        self.assertEqual(band_for_score(80), BAND_CRITICAL)
        self.assertEqual(band_for_score(79), BAND_HIGH)
        self.assertEqual(band_for_score(65), BAND_HIGH)
        self.assertEqual(band_for_score(64), BAND_MEDIUM)
        self.assertEqual(band_for_score(45), BAND_MEDIUM)
        self.assertEqual(band_for_score(44), BAND_LOW)
        self.assertEqual(band_for_score(0), BAND_LOW)

    def test_invalid_scores_are_conservative(self):
        self.assertEqual(band_for_score(None), BAND_LOW)
        self.assertEqual(band_for_score("70"), BAND_LOW)
        self.assertEqual(band_for_score(True), BAND_LOW)

    def test_band_for_score_never_returns_deferred(self):
        for score in range(0, 101):
            self.assertNotEqual(band_for_score(score), BAND_DEFERRED)


class TestCandidateNormalization(unittest.TestCase):
    def test_finding_candidate_preserves_fields(self):
        raw = finding(
            context={"endpoint_path": "/a", "reflection_state": "REFLECTED"},
            confidence="HIGH",
            governance_state="REFERENCED",
            governance_ready=True,
        )
        item = candidate(raw)
        self.assertEqual(item["category"], "XSS")
        self.assertEqual(item["confidence"], "HIGH")
        self.assertEqual(item["state"], "EVIDENCE_SUPPORTED")
        self.assertEqual(item["context_fact_count"], 2)
        self.assertEqual(item["source_kind"], "R53_FINDING")
        self.assertEqual(item["governance_reference_state"], "REFERENCED")
        self.assertEqual(item["governance_ready_state"], "READY")
        self.assertEqual(item["finding_rule_version"], "r53-6")

    def test_reference_candidate_keeps_impact_and_severity_unknown(self):
        first = finding("XSS", "sa-" + "1" * 16)
        correlation = correlate_findings([first])
        reference = correlation["finding_references"][0]
        item = reference_candidate(reference)
        self.assertEqual(item["source_kind"], "R54_REFERENCE")
        self.assertEqual(item["impact_state"], "UNKNOWN")
        self.assertEqual(item["severity"], "UNKNOWN")
        self.assertEqual(item["severity_source"], "NOT_ASSESSED")
        self.assertEqual(item["learning_recommendations"], [])

    def test_invalid_reference_fields_are_clamped(self):
        item = reference_candidate(
            {
                "finding_id": "fnd-" + "1" * 16,
                "category": "XSS",
                "state": "NOT_A_STATE",
                "confidence": "CERTAIN",
                "evidence_completeness": "SOMETIMES",
                "severity": "CRITICAL_OBSERVED",
                "severity_source": "CVSS_CONTEXT",
            }
        )
        self.assertEqual(item["state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(item["confidence"], "UNKNOWN")
        self.assertEqual(item["evidence_completeness"], "UNKNOWN")
        self.assertEqual(item["severity"], "UNKNOWN")
        self.assertEqual(item["severity_source"], "NOT_ASSESSED")


class TestClassifications(unittest.TestCase):
    def test_context_class(self):
        self.assertEqual(
            context_class({"context_fact_count": CONTEXT_COMPLETE_MIN_FACTS}),
            CONTEXT_COMPLETE,
        )
        self.assertEqual(
            context_class({"context_fact_count": CONTEXT_COMPLETE_MIN_FACTS - 1}),
            CONTEXT_PARTIAL,
        )
        self.assertEqual(context_class({"context_fact_count": 1}), CONTEXT_PARTIAL)
        self.assertEqual(context_class({"context_fact_count": 0}), CONTEXT_MISSING)

    def test_provenance_class(self):
        complete = candidate(finding())
        self.assertEqual(provenance_class(complete), "PROVENANCE_COMPLETE")
        partial = dict(complete)
        partial["orchestration_id"] = ""
        self.assertEqual(provenance_class(partial), "PROVENANCE_PARTIAL")
        empty = dict(complete)
        empty.update(
            {
                "orchestration_id": "",
                "agent_id": "",
                "category": "",
                "finding_rule_version": "",
            }
        )
        self.assertEqual(provenance_class(empty), "PROVENANCE_INCOMPLETE")

    def test_governance_class(self):
        unknown = candidate(finding(governance_state="UNKNOWN"))
        self.assertEqual(governance_class(unknown), "GOVERNANCE_UNKNOWN")
        not_ready = candidate(
            finding(governance_state="REFERENCED", governance_ready=False)
        )
        self.assertEqual(governance_class(not_ready), "GOVERNANCE_NOT_READY")
        ready = candidate(
            finding(governance_state="REFERENCED", governance_ready=True)
        )
        self.assertEqual(governance_class(ready), "GOVERNANCE_READY")


class TestFactors(unittest.TestCase):
    def evaluate(self, raw_finding, correlation=None, recommendations=None):
        return evaluate_candidate(
            candidate(raw_finding),
            correlation or empty_correlation_context(),
            recommendations or [],
        )

    def test_evidence_factor_contributions(self):
        for completeness, contribution in EVIDENCE_CONTRIBUTIONS.items():
            evaluated = self.evaluate(
                finding(evidence_completeness=completeness)
            )
            factor = factor_map(evaluated)[FACTOR_EVIDENCE_COMPLETENESS]
            self.assertEqual(factor["value"], completeness)
            self.assertEqual(factor["contribution"], contribution)

    def test_context_factor_contributions(self):
        cases = (
            ({}, CONTEXT_MISSING),
            ({"a": "1"}, CONTEXT_PARTIAL),
            (
                {"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
                CONTEXT_COMPLETE,
            ),
        )
        for context, expected in cases:
            evaluated = self.evaluate(finding(context=context))
            factor = factor_map(evaluated)["CONTEXT_COMPLETENESS"]
            self.assertEqual(factor["value"], expected)

    def test_state_factor_contributions(self):
        for state, contribution in STATE_CONTRIBUTIONS.items():
            evaluated = self.evaluate(finding(state=state))
            factor = factor_map(evaluated)["FINDING_STATE"]
            self.assertEqual(factor["value"], state)
            self.assertEqual(factor["contribution"], contribution)

    def test_confidence_factor_is_small_and_bounded(self):
        for confidence, contribution in CONFIDENCE_CONTRIBUTIONS.items():
            evaluated = self.evaluate(finding(confidence=confidence))
            factor = factor_map(evaluated)["UPSTREAM_CONFIDENCE"]
            self.assertEqual(factor["contribution"], contribution)
            self.assertLessEqual(contribution, 12)

    def test_impact_factor(self):
        for impact, contribution in IMPACT_CONTRIBUTIONS.items():
            evaluated = self.evaluate(finding(impact_state=impact))
            factor = factor_map(evaluated)["IMPACT_SIGNAL"]
            self.assertEqual(factor["value"], impact)
            self.assertEqual(factor["contribution"], contribution)

    def test_severity_requires_structured_cvss_context(self):
        without_source = self.evaluate(
            finding(severity="CRITICAL_OBSERVED", severity_source="NOT_ASSESSED")
        )
        factor = factor_map(without_source)[FACTOR_SEVERITY_SIGNAL]
        self.assertEqual(factor["value"], "UNKNOWN")
        self.assertEqual(factor["contribution"], 0)
        self.assertIn("SEVERITY_NOT_ASSESSED", without_source["priority_reasons"])
        with_source = self.evaluate(
            finding(
                severity="CRITICAL_OBSERVED",
                severity_source="CVSS_CONTEXT",
            )
        )
        factor = factor_map(with_source)[FACTOR_SEVERITY_SIGNAL]
        self.assertEqual(factor["value"], "CRITICAL_OBSERVED")
        self.assertEqual(factor["contribution"], 8)
        self.assertIn("CVSS_CONTEXT_AVAILABLE", with_source["priority_reasons"])

    def test_provenance_factor(self):
        complete = self.evaluate(finding())
        factor = factor_map(complete)["PROVENANCE_COMPLETENESS"]
        self.assertEqual(factor["value"], "PROVENANCE_COMPLETE")
        self.assertEqual(factor["contribution"], 4)
        partial = self.evaluate(finding(orchestration_id=""))
        factor = factor_map(partial)["PROVENANCE_COMPLETENESS"]
        self.assertEqual(factor["value"], "PROVENANCE_PARTIAL")
        self.assertEqual(factor["contribution"], 2)

    def test_score_is_the_bounded_sum_of_contributions(self):
        fixtures = (
            finding(),
            finding(evidence_completeness="MISSING", evidence_state="UNKNOWN"),
            finding(
                state="CONFIRMED_OBSERVED",
                confidence="HIGH",
                impact_state="OBSERVED",
                severity="CRITICAL_OBSERVED",
                severity_source="CVSS_CONTEXT",
                context={"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
            ),
        )
        for raw_finding in fixtures:
            evaluated = self.evaluate(raw_finding)
            total = sum(
                item["contribution"]
                for item in evaluated["priority_factors"]
            )
            self.assertEqual(
                evaluated["priority_score"],
                max(0, min(MAX_PRIORITY_SCORE, total)),
            )
            self.assertGreaterEqual(evaluated["priority_score"], 0)
            self.assertLessEqual(evaluated["priority_score"], 100)
            self.assertEqual(
                evaluated["priority_band"],
                band_for_score(evaluated["priority_score"]),
            )

    def test_governance_unknown_caps_at_medium(self):
        evaluated = self.evaluate(
            finding(
                state="CONFIRMED_OBSERVED",
                confidence="HIGH",
                evidence_state="COMPLETE",
                evidence_completeness="COMPLETE",
                severity="CRITICAL_OBSERVED",
                severity_source="CVSS_CONTEXT",
                impact_state="OBSERVED",
                context={"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
                governance_state="UNKNOWN",
            )
        )
        self.assertLessEqual(evaluated["priority_score"], CAP_MEDIUM_SCORE)
        self.assertEqual(evaluated["priority_band"], BAND_MEDIUM)
        factor = factor_map(evaluated)[FACTOR_GOVERNANCE_CONSTRAINT]
        self.assertEqual(factor["value"], BAND_CAP_MEDIUM)
        self.assertLess(factor["contribution"], 0)
        self.assertIn(
            "GOVERNANCE_LIMITATION", evaluated["priority_reasons"]
        )

    def test_governance_not_ready_caps_at_low(self):
        evaluated = self.evaluate(
            finding(
                state="CONFIRMED_OBSERVED",
                confidence="HIGH",
                severity="CRITICAL_OBSERVED",
                severity_source="CVSS_CONTEXT",
                impact_state="OBSERVED",
                context={"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
                governance_state="REFERENCED",
                governance_ready=False,
            )
        )
        self.assertLessEqual(evaluated["priority_score"], CAP_LOW_SCORE)
        self.assertEqual(evaluated["priority_band"], BAND_LOW)
        factor = factor_map(evaluated)[FACTOR_GOVERNANCE_CONSTRAINT]
        self.assertEqual(factor["value"], BAND_CAP_LOW)

    def test_embedded_conflict_caps_and_reduces(self):
        conflicts = [
            {
                "conflict_type": "CONTEXT_CONFLICT",
                "resolution_state": "UNRESOLVED",
                "subjects": ["sa-other"],
                "conflicting_fields": ["endpoint_path"],
            }
        ]
        evaluated = self.evaluate(
            finding(
                state="CONFIRMED_OBSERVED",
                confidence="HIGH",
                severity="CRITICAL_OBSERVED",
                severity_source="CVSS_CONTEXT",
                impact_state="OBSERVED",
                context={"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
                governance_state="REFERENCED",
                governance_ready=True,
                conflicts=conflicts,
            )
        )
        self.assertLessEqual(evaluated["priority_score"], CAP_MEDIUM_SCORE)
        self.assertEqual(evaluated["priority_band"], BAND_MEDIUM)
        correlation_factor = factor_map(evaluated)[FACTOR_CORRELATION_CONTEXT]
        self.assertEqual(
            correlation_factor["value"], "CORRELATION_CONFLICTING"
        )
        self.assertEqual(correlation_factor["contribution"], -10)
        self.assertIn(
            "CONFLICT_REQUIRES_REVIEW", evaluated["priority_reasons"]
        )


class TestCorrelationContexts(unittest.TestCase):
    def test_duplicate_relationship_and_cluster(self):
        first = finding(
            "XSS",
            "sa-" + "1" * 16,
            finding_id_value="fnd-" + "1" * 16,
            evidence_completeness="COMPLETE",
        )
        second = finding(
            "XSS",
            "sa-" + "1" * 16,
            finding_id_value="fnd-" + "2" * 16,
            evidence_completeness="PARTIAL",
            evidence_state="PARTIAL",
        )
        correlation = correlate_findings([first, second])
        contexts, unmatched = build_correlation_contexts(
            [candidate(first), candidate(second)],
            correlation["relationships"],
            correlation["clusters"],
            True,
        )
        self.assertEqual(unmatched, [])
        self.assertIn(
            RELATIONSHIP_DUPLICATE,
            contexts["fnd-" + "1" * 16]["relationship_types"],
        )
        self.assertEqual(
            contexts["fnd-" + "1" * 16]["duplicate_cluster_size"], 2
        )
        self.assertFalse(contexts["fnd-" + "1" * 16]["duplicate_redundant"])
        self.assertTrue(contexts["fnd-" + "2" * 16]["duplicate_redundant"])

    def test_conflict_sources_are_preserved(self):
        first = finding(
            "XSS",
            "sa-" + "1" * 16,
            finding_id_value="fnd-" + "1" * 16,
            context={"endpoint_path": "/a"},
        )
        second = finding(
            "XSS",
            "sa-" + "2" * 16,
            finding_id_value="fnd-" + "2" * 16,
            context={"endpoint_path": "/b"},
        )
        correlation = correlate_findings([first, second])
        self.assertEqual(
            correlation["relationships"][0]["relationship_type"],
            RELATIONSHIP_CONFLICTING,
        )
        contexts, _ = build_correlation_contexts(
            [candidate(first), candidate(second)],
            correlation["relationships"],
            correlation["clusters"],
            True,
        )
        self.assertEqual(
            contexts["fnd-" + "1" * 16]["conflict_sources"],
            ["fnd-" + "2" * 16],
        )
        self.assertEqual(
            contexts["fnd-" + "1" * 16]["conflict_count"], 1
        )

    def test_related_and_independent_never_boost(self):
        first = finding(
            "XSS",
            "sa-" + "1" * 16,
            finding_id_value="fnd-" + "1" * 16,
            endpoint_component={
                "availability": "PRESENT",
                "component_name": "SHARED",
                "component_version": "",
                "endpoint_reference": "",
            },
        )
        second = finding(
            "SSRF",
            "sa-" + "2" * 16,
            finding_id_value="fnd-" + "2" * 16,
            endpoint_component={
                "availability": "PRESENT",
                "component_name": "SHARED",
                "component_version": "",
                "endpoint_reference": "",
            },
        )
        correlation = correlate_findings([first, second])
        self.assertEqual(
            correlation["relationships"][0]["relationship_type"],
            RELATIONSHIP_RELATED,
        )
        contexts, _ = build_correlation_contexts(
            [candidate(first), candidate(second)],
            correlation["relationships"],
            correlation["clusters"],
            True,
        )
        evaluated = evaluate_candidate(
            candidate(first),
            contexts["fnd-" + "1" * 16],
            [],
        )
        factor = factor_map(evaluated)[FACTOR_CORRELATION_CONTEXT]
        self.assertEqual(factor["value"], "CORRELATION_RELATED")
        self.assertEqual(factor["contribution"], 0)

    def test_independent_context(self):
        first = finding(
            "XSS",
            "sa-" + "1" * 16,
            finding_id_value="fnd-" + "1" * 16,
            endpoint_component={
                "availability": "PRESENT",
                "component_name": "ONE",
                "component_version": "",
                "endpoint_reference": "",
            },
        )
        second = finding(
            "SSRF",
            "sa-" + "2" * 16,
            finding_id_value="fnd-" + "2" * 16,
            hypothesis_types=("SERVER_SIDE_REQUEST",),
            evidence_requirements=("EVIDENCE_SSRF",),
            endpoint_component={
                "availability": "PRESENT",
                "component_name": "TWO",
                "component_version": "",
                "endpoint_reference": "",
            },
        )
        correlation = correlate_findings([first, second])
        self.assertEqual(
            correlation["relationships"][0]["relationship_type"],
            RELATIONSHIP_INDEPENDENT,
        )
        contexts, _ = build_correlation_contexts(
            [candidate(first), candidate(second)],
            correlation["relationships"],
            correlation["clusters"],
            True,
        )
        evaluated = evaluate_candidate(
            candidate(first), contexts["fnd-" + "1" * 16], []
        )
        factor = factor_map(evaluated)[FACTOR_CORRELATION_CONTEXT]
        self.assertEqual(factor["value"], "CORRELATION_INDEPENDENT")
        self.assertEqual(factor["contribution"], 0)

    def test_unmatched_endpoints_are_reported_not_guessed(self):
        known = candidate(finding("XSS", "sa-" + "1" * 16))
        relationships = [
            {
                "relationship_type": "RELATED",
                "source_finding_id": known["finding_id"],
                "target_finding_id": "fnd-" + "9" * 16,
                "relationship_id": "fcr-" + "9" * 16,
            }
        ]
        contexts, unmatched = build_correlation_contexts(
            [known], relationships, [], True
        )
        self.assertEqual(unmatched, ["fnd-" + "9" * 16])

    def test_no_correlation_is_explicitly_unavailable(self):
        context = empty_correlation_context()
        self.assertFalse(context["present"])
        evaluated = evaluate_candidate(
            candidate(finding()), context, []
        )
        factor = factor_map(evaluated)[FACTOR_CORRELATION_CONTEXT]
        self.assertEqual(factor["value"], "CORRELATION_UNAVAILABLE")
        self.assertEqual(factor["contribution"], 0)


class TestDuplicatePreference(unittest.TestCase):
    def test_strongest_evidence_wins(self):
        strong = candidate(
            finding(
                "XSS",
                "sa-" + "1" * 16,
                finding_id_value="fnd-" + "1" * 16,
                evidence_completeness="COMPLETE",
            )
        )
        weak = candidate(
            finding(
                "XSS",
                "sa-" + "1" * 16,
                finding_id_value="fnd-" + "2" * 16,
                evidence_completeness="PARTIAL",
                evidence_state="PARTIAL",
            )
        )
        self.assertGreater(
            duplicate_preference(strong), duplicate_preference(weak)
        )

    def test_most_complete_context_breaks_the_tie(self):
        first = candidate(
            finding(
                "XSS",
                "sa-" + "1" * 16,
                finding_id_value="fnd-" + "1" * 16,
                context={"a": "1", "b": "2"},
            )
        )
        second = candidate(
            finding(
                "XSS",
                "sa-" + "1" * 16,
                finding_id_value="fnd-" + "2" * 16,
                context={"a": "1"},
            )
        )
        self.assertGreater(
            duplicate_preference(first), duplicate_preference(second)
        )

    def test_finding_id_breaks_the_full_tie(self):
        first = candidate(
            finding(
                "XSS",
                "sa-" + "1" * 16,
                finding_id_value="fnd-" + "1" * 16,
            )
        )
        second = candidate(
            finding(
                "XSS",
                "sa-" + "1" * 16,
                finding_id_value="fnd-" + "2" * 16,
            )
        )
        self.assertEqual(
            duplicate_preference(first), duplicate_preference(second)
        )
        self.assertTrue(duplicate_representative(first, second))
        self.assertFalse(duplicate_representative(second, first))


class TestLearningSignals(unittest.TestCase):
    def test_every_closed_recommendation_maps_to_a_closed_factor(self):
        for recommendation_type, (
            value,
            contribution,
            _,
        ) in LEARNING_SIGNAL_MAP.items():
            self.assertIn(value, LEARNING_CONTRIBUTIONS)
            self.assertEqual(
                contribution, LEARNING_CONTRIBUTIONS[value]
            )
        self.assertEqual(
            set(LEARNING_SIGNAL_MAP), set(LEARNING_SIGNAL_PRECEDENCE)
        )

    def test_learning_signals_are_advisory_context(self):
        evaluated = evaluate_candidate(
            candidate(finding()),
            empty_correlation_context(),
            [recommend(REC_PRIORITIZE_EVIDENCE_PLANNING)],
        )
        factor = factor_map(evaluated)[FACTOR_LEARNING_SIGNAL]
        self.assertEqual(factor["value"], "LEARNING_REQUIRE_MORE_EVIDENCE")
        self.assertEqual(factor["contribution"], 4)
        self.assertIn(
            "LEARNING_SIGNAL_REQUIRES_EVIDENCE",
            evaluated["priority_reasons"],
        )

    def test_safety_boundary_signal_defers(self):
        recommendations = [
            recommend(REC_RESTORE_SAFETY_BOUNDARY),
        ]
        self.assertTrue(learning_deferral(recommendations))

    def test_governance_review_signal_caps_at_medium(self):
        evaluated = evaluate_candidate(
            candidate(
                finding(
                    state="CONFIRMED_OBSERVED",
                    confidence="HIGH",
                    severity="CRITICAL_OBSERVED",
                    severity_source="CVSS_CONTEXT",
                    impact_state="OBSERVED",
                    context={"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
                    governance_state="REFERENCED",
                    governance_ready=True,
                )
            ),
            empty_correlation_context(),
            [recommend(REC_REVIEW_GOVERNANCE_REFERENCES)],
        )
        self.assertLessEqual(evaluated["priority_score"], CAP_MEDIUM_SCORE)
        self.assertIn(
            "LEARNING_SIGNAL_REVIEW_GOVERNANCE",
            evaluated["priority_reasons"],
        )

    def test_learning_unavailable_without_recommendations(self):
        evaluated = evaluate_candidate(
            candidate(finding()), empty_correlation_context(), []
        )
        factor = factor_map(evaluated)[FACTOR_LEARNING_SIGNAL]
        self.assertEqual(factor["value"], "LEARNING_UNAVAILABLE")
        self.assertIn("LEARNING_UNAVAILABLE", evaluated["priority_reasons"])

    def test_container_learning_is_matched_by_agent_only(self):
        item = candidate(finding("XSS", DEFAULT_AGENT))
        matched = learning_recommendations_for(
            item,
            {
                "recommendations": [
                    recommend(REC_STRENGTHEN_HYPOTHESES),
                    recommend(REC_DEDUPLICATE_HYPOTHESES, agent_id="other"),
                ]
            },
        )
        types = {rec["recommendation_type"] for rec in matched}
        self.assertIn(REC_STRENGTHEN_HYPOTHESES, types)
        self.assertNotIn(REC_DEDUPLICATE_HYPOTHESES, types)

    def test_candidate_recommendations_are_preserved(self):
        item = candidate(
            finding(
                learning_recommendations=[
                    recommend(REC_PRESERVE_SUCCESSFUL_PATTERN)
                ]
            )
        )
        matched = learning_recommendations_for(item, None)
        self.assertEqual(
            matched[0]["recommendation_type"], REC_PRESERVE_SUCCESSFUL_PATTERN
        )


class TestReasonsAndLimitations(unittest.TestCase):
    def test_missing_evidence_reasons_are_explicit(self):
        evaluated = evaluate_candidate(
            candidate(
                finding(
                    evidence_state="UNKNOWN",
                    evidence_completeness="MISSING",
                    context={},
                    confidence="LOW",
                    state="NEEDS_MORE_EVIDENCE",
                )
            ),
            empty_correlation_context(),
            [],
        )
        self.assertIn("MISSING_EVIDENCE", evaluated["priority_reasons"])
        self.assertIn("NEEDS_MORE_EVIDENCE", evaluated["priority_reasons"])
        self.assertIn("INSUFFICIENT_CONTEXT", evaluated["priority_reasons"])

    def test_limitations_are_ordered_and_closed(self):
        raw_finding = finding()
        item = candidate(raw_finding)
        limitations = priority_limitations(
            item,
            empty_correlation_context(),
            [],
            correlation_present=False,
            correlation_incomplete=False,
        )
        self.assertEqual(
            limitations,
            [code for code in PRIORITY_LIMITATIONS if code in limitations],
        )
        self.assertIn("CORRELATION_UNAVAILABLE", limitations)
        self.assertIn("LEARNING_UNAVAILABLE", limitations)
        self.assertIn("PRIORITY_NOT_CONFIDENCE", limitations)

    def test_deferred_limitation_is_explicit(self):
        limitations = priority_limitations(
            candidate(finding()),
            empty_correlation_context(),
            [],
            correlation_present=False,
            correlation_incomplete=False,
            deferred=True,
        )
        self.assertIn("SAFETY_DEFERRED", limitations)


class TestDeterminism(unittest.TestCase):
    def test_evaluation_is_deterministic(self):
        raw_finding = finding(context={"endpoint_path": "/a"})
        first = evaluate_candidate(
            candidate(raw_finding), empty_correlation_context(), []
        )
        second = evaluate_candidate(
            candidate(raw_finding), empty_correlation_context(), []
        )
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )


class TestPrioritySchema(unittest.TestCase):
    def plan_payload(self):
        evaluated = evaluate_candidate(
            candidate(finding()), empty_correlation_context(), []
        )
        return {
            "rule_version": RESEARCH_PRIORITY_RULE_VERSION,
            "finding_id": "fnd-" + "1" * 16,
            "category": "XSS",
            "state": "EVIDENCE_SUPPORTED",
            "confidence": "MEDIUM",
            "priority_score": evaluated["priority_score"],
            "priority_band": evaluated["priority_band"],
            "priority_factors": evaluated["priority_factors"],
            "priority_reasons": evaluated["priority_reasons"],
        }

    def test_plan_is_valid(self):
        plan = ResearchPriorityPlan(**self.plan_payload())
        self.assertEqual(plan.confirmation_state, "NOT_CONFIRMED")
        self.assertEqual(plan.confidence_effect, "NONE")
        self.assertTrue(plan.research_only)
        self.assertTrue(plan.deterministic)

    def test_plan_rejects_confidence_effect_change(self):
        payload = self.plan_payload()
        payload["confidence_effect"] = "UPGRADED"
        with self.assertRaises(ValidationError):
            ResearchPriorityPlan(**payload)

    def test_plan_rejects_confirmed_state(self):
        payload = self.plan_payload()
        payload["confirmation_state"] = "CONFIRMED"
        with self.assertRaises(ValidationError):
            ResearchPriorityPlan(**payload)

    def test_plan_rejects_out_of_range_score(self):
        payload = self.plan_payload()
        payload["priority_score"] = 101
        with self.assertRaises(ValidationError):
            ResearchPriorityPlan(**payload)

    def test_sanitize_research_priority_forces_invariants(self):
        projected = sanitize_research_priority(
            {
                "finding_id": "fnd-" + "1" * 16,
                "category": "XSS",
                "state": "EVIDENCE_SUPPORTED",
                "confirmation_state": "CONFIRMED",
                "confidence_effect": "UPGRADED",
                "research_only": False,
                "deterministic": False,
            }
        )
        self.assertEqual(projected["confirmation_state"], "NOT_CONFIRMED")
        self.assertEqual(projected["confidence_effect"], "NONE")
        self.assertTrue(projected["research_only"])
        self.assertTrue(projected["deterministic"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
