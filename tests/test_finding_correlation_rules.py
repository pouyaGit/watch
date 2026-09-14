"""tests/test_finding_correlation_rules.py — Stage R54.1–R54.3 tests.

Deterministic, offline tests for finding-correlation rules and schemas:

- relationship vocabulary reused from R43
- deterministic finding fact normalization
- DUPLICATE / RELATED / INDEPENDENT / CONFLICTING / UNKNOWN classification
- conservative conflict semantics (no confidence-only conflicts)
- generic signal filtering (input location, unknown markers, technology)
- bounded interpretable scores
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

from ai.knowledge.finding_correlation_rules import (
    AUTHORIZATION_FAMILY,
    GENERIC_CONTEXT_KEYS,
    GENERIC_HYPOTHESIS_SIGNAL_PREFIXES,
    MATERIAL_CONFLICT_TYPES,
    analyze_pair,
    finding_facts,
    relational_score,
)
from ai.schemas.finding_correlation import (
    CORRELATION_LIMITATIONS,
    CORRELATION_SIGNALS,
    FindingReferencePlan,
    FindingRelationshipPlan,
    MAX_RELATIONSHIP_SCORE,
    RELATIONSHIP_CONFLICTING,
    RELATIONSHIP_DUPLICATE,
    RELATIONSHIP_INDEPENDENT,
    RELATIONSHIP_PRECEDENCE,
    RELATIONSHIP_RELATED,
    RELATIONSHIP_TYPES,
    RELATIONSHIP_UNKNOWN,
    SIGNAL_CATEGORY_FAMILY,
    SIGNAL_CONFIDENCE_DIVERGENCE,
    SIGNAL_CONTEXT_CONFLICT,
    SIGNAL_EVIDENCE_STATE_DIVERGENCE,
    SIGNAL_IDENTICAL_FINDING_ID,
    SIGNAL_INSUFFICIENT_STRUCTURE,
    SIGNAL_NO_SHARED_SIGNAL,
    SIGNAL_R43_MATERIAL_CONFLICT,
    SIGNAL_R43_RELATED_GROUP,
    SIGNAL_SAME_AGENT,
    SIGNAL_SAME_CATEGORY,
    SIGNAL_SAME_ORCHESTRATION,
    SIGNAL_SHARED_COMPONENT,
    SIGNAL_SHARED_CONTEXT_VALUE,
    SIGNAL_SHARED_ENDPOINT,
    SIGNAL_SHARED_EVIDENCE_REQUIREMENT,
    SIGNAL_SHARED_HYPOTHESIS_FINGERPRINT,
    SIGNAL_SHARED_HYPOTHESIS_SIGNAL,
    SIGNAL_SHARED_HYPOTHESIS_TYPE,
    SIGNAL_WEIGHTS,
    sanitize_finding_reference,
    sanitize_finding_relationship,
)
from ai.schemas.hypothesis_correlation import CORRELATION_TYPES


def finding_id(category, agent_id):
    digest = hashlib.sha256(
        f"{category}:{agent_id}".encode("utf-8")
    ).hexdigest()
    return "fnd-" + digest[:16]


def finding(
    category,
    agent_id=None,
    *,
    finding_id_value=None,
    context=None,
    endpoint_component=None,
    hypothesis_types=None,
    hypothesis_signals=None,
    fingerprints=None,
    evidence_requirements=None,
    evidence_state="COMPLETE",
    evidence_completeness="COMPLETE",
    confidence="MEDIUM",
    state="RESEARCH_CANDIDATE",
    conflicts=None,
    groups=None,
    governance_state="UNKNOWN",
    orchestration_id="orch-" + "1" * 16,
    research_only=True,
    confirmation_state="NOT_CONFIRMED",
):
    agent = agent_id or ("sa-" + category.lower().ljust(16, "0")[:16])
    fid = finding_id_value or finding_id(category, agent)
    facts = [
        {"key": key, "value": value}
        for key, value in (context or {}).items()
    ]
    hypotheses = []
    for index, hypothesis_type in enumerate(hypothesis_types or []):
        hypotheses.append(
            {
                "rule_version": "r99-3",
                "agent_id": agent,
                "agent_category": category,
                "hypothesis_index": index,
                "hypothesis_type": hypothesis_type,
                "supporting_signals": list(hypothesis_signals or []),
                "confidence": confidence,
                "priority": confidence,
                "limitations": [],
                "subject_reference": "",
                "rationale": "",
                "fingerprint": (
                    fingerprints[0]
                    if fingerprints and index == 0
                    else ""
                ),
                "research_only": True,
            }
        )
    component = endpoint_component or {
        "availability": "UNAVAILABLE",
        "component_name": "",
        "component_version": "",
        "endpoint_reference": "",
    }
    return {
        "rule_version": "r53-6",
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
            "hypothesis_types": list(hypothesis_types or []),
            "confidence_summary": {},
            "research_only": True,
        },
        "evidence": {
            "rule_version": "r53-4",
            "evidence_state": evidence_state,
            "evidence_completeness": evidence_completeness,
            "evidence_origin": "SPECIALIST_PLAN",
            "observed_context": facts,
            "planned_requirements": list(evidence_requirements or []),
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
            "severity": "UNKNOWN",
            "severity_source": "NOT_ASSESSED",
            "impact_state": "POTENTIAL",
            "impact_confidence": "UNKNOWN",
            "impact_description": "",
            "business_impact_asserted": False,
            "remediation_state": "UNAVAILABLE",
            "remediation_items": [],
            "confirmation_state": confirmation_state,
            "evaluation_present": False,
            "evaluation_rating": "",
            "hard_gate_state": "",
            "safety_state": "UNKNOWN",
            "diagnostic_codes": [],
            "research_only": True,
        },
        "correlation": {
            "rule_version": "",
            "groups": list(groups or []),
            "conflicts": list(conflicts or []),
            "research_only": True,
        },
        "references": {},
        "learning_recommendations": [],
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
            "rule_version": "",
            "ready": False,
            "provenance_state": "UNKNOWN",
            "trace_state": "UNKNOWN",
            "audit_state": "UNKNOWN",
            "explanation_state": "UNKNOWN",
            "reference_state": governance_state,
        },
        "limitations": ["NO_EXECUTION_PERFORMED"],
        "research_only": research_only,
        "deterministic": True,
    }


def facts_of(raw):
    return finding_facts(raw)


class TestVocabulary(unittest.TestCase):
    def test_relationship_types_reuse_r43(self):
        self.assertEqual(RELATIONSHIP_TYPES, CORRELATION_TYPES)
        self.assertEqual(
            set(RELATIONSHIP_TYPES),
            {"DUPLICATE", "RELATED", "INDEPENDENT", "CONFLICTING", "UNKNOWN"},
        )

    def test_precedence_is_closed(self):
        self.assertEqual(
            set(RELATIONSHIP_PRECEDENCE), set(RELATIONSHIP_TYPES)
        )
        self.assertGreater(
            RELATIONSHIP_PRECEDENCE[RELATIONSHIP_CONFLICTING],
            RELATIONSHIP_PRECEDENCE[RELATIONSHIP_RELATED],
        )

    def test_signal_weights_are_bounded(self):
        for signal, weight in SIGNAL_WEIGHTS.items():
            self.assertIn(signal, CORRELATION_SIGNALS)
            self.assertGreaterEqual(weight, 0)
            self.assertLessEqual(weight, MAX_RELATIONSHIP_SCORE)

    def test_generic_context_keys(self):
        self.assertIn("context_confidence", GENERIC_CONTEXT_KEYS)
        self.assertIn("input_location", GENERIC_CONTEXT_KEYS)
        self.assertIn("INPUT_", GENERIC_HYPOTHESIS_SIGNAL_PREFIXES)

    def test_authorization_family(self):
        self.assertEqual(
            AUTHORIZATION_FAMILY, frozenset({"IDOR", "JWT", "OAUTH", "RECON"})
        )

    def test_material_conflict_types(self):
        self.assertIn("CONTEXT_CONFLICT", MATERIAL_CONFLICT_TYPES)
        self.assertIn("HYPOTHESIS_CONFLICT", MATERIAL_CONFLICT_TYPES)
        self.assertIn("CONFIDENCE_CONFLICT", MATERIAL_CONFLICT_TYPES)


class TestFindingFacts(unittest.TestCase):
    def test_facts_are_normalized(self):
        raw = finding(
            "XSS",
            context={"output_context": "HTML", "input_location": "QUERY"},
            hypothesis_types=["REFLECTION_ANALYSIS"],
            hypothesis_signals=["REFLECTION_OBSERVED", "INPUT_QUERY"],
            evidence_requirements=["REFLECTION_EVIDENCE"],
            confidence="HIGH",
        )
        facts = facts_of(raw)
        self.assertEqual(facts["category"], "XSS")
        self.assertEqual(
            facts["context_values"], {"output_context": "HTML"}
        )
        self.assertEqual(
            facts["hypothesis_types"], ["REFLECTION_ANALYSIS"]
        )
        # Generic input signal and unknown markers are filtered.
        self.assertEqual(
            facts["hypothesis_signals"], ["REFLECTION_OBSERVED"]
        )
        self.assertTrue(facts["has_structure"])

    def test_generic_only_finding_has_no_structure(self):
        raw = finding(
            "XSS",
            context={"input_location": "QUERY", "context_confidence": "LOW"},
            hypothesis_signals=["CONTEXT_UNKNOWN", "INPUT_QUERY"],
        )
        facts = facts_of(raw)
        self.assertEqual(facts["context_values"], {})
        self.assertEqual(facts["hypothesis_signals"], [])
        self.assertFalse(facts["has_structure"])

    def test_facts_are_read_only(self):
        raw = finding("XSS", context={"output_context": "HTML"})
        snapshot = json.dumps(raw, sort_keys=True)
        facts_of(raw)
        self.assertEqual(json.dumps(raw, sort_keys=True), snapshot)

    def test_related_agents_are_extracted_from_r43_groups(self):
        raw = finding(
            "XSS",
            groups=[
                {
                    "correlation_type": "RELATED",
                    "participating_agents": ["sa-" + "b" * 16],
                },
                {
                    "correlation_type": "DUPLICATE",
                    "participating_agents": ["sa-" + "c" * 16],
                },
            ],
        )
        facts = facts_of(raw)
        self.assertEqual(facts["related_agents"], ["sa-" + "b" * 16])
        self.assertEqual(facts["duplicate_agents"], ["sa-" + "c" * 16])


class TestDuplicateClassification(unittest.TestCase):
    def test_identical_finding_id_is_duplicate(self):
        first = finding("XSS", "sa-" + "a" * 16)
        second = dict(
            json.loads(json.dumps(first)),
            **{"finding_id": first["finding_id"]},
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_DUPLICATE
        )
        self.assertIn(SIGNAL_IDENTICAL_FINDING_ID, analysis["signals"])

    def test_same_category_same_agent_is_duplicate(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            finding_id_value="fnd-" + "1" * 16,
        )
        second = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"framework_context": "GENERIC"},
            finding_id_value="fnd-" + "2" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_DUPLICATE
        )
        self.assertIn(SIGNAL_SAME_AGENT, analysis["signals"])

    def test_matching_fingerprints_and_signature_are_duplicate(self):
        first = finding(
            "SSRF",
            "sa-" + "a" * 16,
            context={"server_side_fetch": "OBSERVED"},
            hypothesis_types=["SERVER_SIDE_FETCH_ANALYSIS"],
            fingerprints=["fp-shared"],
            evidence_requirements=["SERVER_FETCH_BEHAVIOR"],
            finding_id_value="fnd-" + "3" * 16,
        )
        second = finding(
            "SSRF",
            "sa-" + "b" * 16,
            context={"server_side_fetch": "OBSERVED"},
            hypothesis_types=["SERVER_SIDE_FETCH_ANALYSIS"],
            fingerprints=["fp-shared"],
            evidence_requirements=["SERVER_FETCH_BEHAVIOR"],
            finding_id_value="fnd-" + "4" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_DUPLICATE
        )
        self.assertIn(
            SIGNAL_SHARED_HYPOTHESIS_FINGERPRINT, analysis["signals"]
        )

    def test_r43_duplicate_group_is_duplicate(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            groups=[
                {
                    "correlation_type": "DUPLICATE",
                    "participating_agents": ["sa-" + "b" * 16],
                }
            ],
            finding_id_value="fnd-" + "5" * 16,
        )
        second = finding(
            "XSS",
            "sa-" + "b" * 16,
            context={"output_context": "HTML"},
            hypothesis_types=["REFLECTION_ANALYSIS"],
            finding_id_value="fnd-" + "6" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_DUPLICATE
        )

    def test_different_context_same_types_is_related_not_duplicate(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            hypothesis_types=["REFLECTION_ANALYSIS"],
            evidence_requirements=["REFLECTION_EVIDENCE"],
            finding_id_value="fnd-" + "7" * 16,
        )
        second = finding(
            "XSS",
            "sa-" + "b" * 16,
            context={"framework_context": "GENERIC"},
            hypothesis_types=["REFLECTION_ANALYSIS"],
            evidence_requirements=["REFLECTION_EVIDENCE"],
            finding_id_value="fnd-" + "8" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_RELATED
        )


class TestRelatedClassification(unittest.TestCase):
    def test_shared_context_value_is_related(self):
        first = finding(
            "JWT",
            "sa-" + "a" * 16,
            context={"issuer_validation": "NOT_PROVIDED"},
            finding_id_value="fnd-" + "1" * 16,
        )
        second = finding(
            "OAUTH",
            "sa-" + "b" * 16,
            context={"issuer_validation": "NOT_PROVIDED"},
            finding_id_value="fnd-" + "2" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_RELATED
        )
        self.assertIn(SIGNAL_SHARED_CONTEXT_VALUE, analysis["signals"])
        self.assertIn(SIGNAL_CATEGORY_FAMILY, analysis["signals"])

    def test_shared_component_is_related(self):
        first = finding(
            "CVE_RESEARCH",
            "sa-" + "a" * 16,
            endpoint_component={
                "availability": "PRESENT",
                "component_name": "LOG4J",
                "component_version": "2.14.1",
                "endpoint_reference": "",
            },
            finding_id_value="fnd-" + "3" * 16,
        )
        second = finding(
            "RECON",
            "sa-" + "b" * 16,
            endpoint_component={
                "availability": "PRESENT",
                "component_name": "LOG4J",
                "component_version": "2.14.1",
                "endpoint_reference": "",
            },
            finding_id_value="fnd-" + "4" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_RELATED
        )
        self.assertIn(SIGNAL_SHARED_COMPONENT, analysis["signals"])

    def test_shared_endpoint_is_related(self):
        first = finding(
            "RECON",
            "sa-" + "a" * 16,
            endpoint_component={
                "availability": "PRESENT",
                "component_name": "",
                "component_version": "",
                "endpoint_reference": "/api/v1/users",
            },
            finding_id_value="fnd-" + "5" * 16,
        )
        second = finding(
            "IDOR",
            "sa-" + "b" * 16,
            endpoint_component={
                "availability": "PRESENT",
                "component_name": "",
                "component_version": "",
                "endpoint_reference": "/api/v1/users",
            },
            finding_id_value="fnd-" + "6" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_RELATED
        )
        self.assertIn(SIGNAL_SHARED_ENDPOINT, analysis["signals"])

    def test_shared_evidence_requirement_is_related(self):
        first = finding(
            "JWT",
            "sa-" + "a" * 16,
            evidence_requirements=["VALIDATION_IMPLEMENTATION_EVIDENCE"],
            finding_id_value="fnd-" + "7" * 16,
        )
        second = finding(
            "OAUTH",
            "sa-" + "b" * 16,
            evidence_requirements=["VALIDATION_IMPLEMENTATION_EVIDENCE"],
            finding_id_value="fnd-" + "8" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_RELATED
        )
        self.assertIn(
            SIGNAL_SHARED_EVIDENCE_REQUIREMENT, analysis["signals"]
        )

    def test_shared_hypothesis_type_is_related(self):
        first = finding(
            "JWT",
            "sa-" + "a" * 16,
            hypothesis_types=["ISSUER_VALIDATION_GAP"],
            finding_id_value="fnd-" + "9" * 16,
        )
        second = finding(
            "OAUTH",
            "sa-" + "b" * 16,
            hypothesis_types=["ISSUER_VALIDATION_GAP"],
            finding_id_value="fnd-" + "a" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_RELATED
        )
        self.assertIn(SIGNAL_SHARED_HYPOTHESIS_TYPE, analysis["signals"])

    def test_r43_related_group_is_related(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            groups=[
                {
                    "correlation_type": "RELATED",
                    "participating_agents": ["sa-" + "b" * 16],
                }
            ],
            finding_id_value="fnd-" + "b" * 16,
        )
        second = finding(
            "SQLI",
            "sa-" + "b" * 16,
            context={"query_context": "DATABASE_QUERY"},
            finding_id_value="fnd-" + "c" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_RELATED
        )
        self.assertIn(SIGNAL_R43_RELATED_GROUP, analysis["signals"])

    def test_family_alone_does_not_force_relationship(self):
        first = finding(
            "JWT",
            "sa-" + "a" * 16,
            hypothesis_types=["ISSUER_VALIDATION_GAP"],
            finding_id_value="fnd-" + "d" * 16,
        )
        second = finding(
            "RECON",
            "sa-" + "b" * 16,
            hypothesis_types=["API_AUTHORIZATION_GAP"],
            finding_id_value="fnd-" + "e" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_INDEPENDENT
        )
        self.assertIn(SIGNAL_CATEGORY_FAMILY, analysis["signals"])
        self.assertIn(SIGNAL_NO_SHARED_SIGNAL, analysis["signals"])

    def test_same_orchestration_alone_does_not_force_relationship(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            orchestration_id="orch-" + "9" * 16,
            finding_id_value="fnd-" + "f" * 16,
        )
        second = finding(
            "SQLI",
            "sa-" + "b" * 16,
            context={"query_context": "DATABASE_QUERY"},
            orchestration_id="orch-" + "9" * 16,
            finding_id_value="fnd-" + "0" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_INDEPENDENT
        )
        self.assertIn(SIGNAL_SAME_ORCHESTRATION, analysis["signals"])
        self.assertIn(SIGNAL_NO_SHARED_SIGNAL, analysis["signals"])

    def test_generic_technology_name_alone_does_not_force_relationship(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"framework_context": "GENERIC"},
            hypothesis_signals=["CONTEXT_UNKNOWN", "INPUT_QUERY"],
            finding_id_value="fnd-" + "1" * 16,
        )
        second = finding(
            "SQLI",
            "sa-" + "b" * 16,
            context={"framework_context": "GENERIC"},
            hypothesis_signals=["CONTEXT_UNKNOWN", "INPUT_QUERY"],
            finding_id_value="fnd-" + "2" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        # framework_context shared value actually relates them; remove it and
        # the generic-only pair must not relate.
        self.assertIn(SIGNAL_SHARED_CONTEXT_VALUE, analysis["signals"])
        stripped_first = finding(
            "XSS",
            "sa-" + "a" * 16,
            hypothesis_signals=["CONTEXT_UNKNOWN"],
            finding_id_value="fnd-" + "3" * 16,
        )
        stripped_second = finding(
            "SQLI",
            "sa-" + "b" * 16,
            hypothesis_signals=["CONTEXT_UNKNOWN"],
            finding_id_value="fnd-" + "4" * 16,
        )
        stripped = analyze_pair(
            facts_of(stripped_first), facts_of(stripped_second)
        )
        self.assertNotEqual(
            stripped["relationship_type"], RELATIONSHIP_RELATED
        )


class TestConflictClassification(unittest.TestCase):
    def test_contradictory_context_value_is_conflicting(self):
        first = finding(
            "JWT",
            "sa-" + "a" * 16,
            context={"issuer_validation": "PRESENT"},
            finding_id_value="fnd-" + "1" * 16,
        )
        second = finding(
            "OAUTH",
            "sa-" + "b" * 16,
            context={"issuer_validation": "ABSENT"},
            finding_id_value="fnd-" + "2" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_CONFLICTING
        )
        self.assertIn(SIGNAL_CONTEXT_CONFLICT, analysis["signals"])
        self.assertTrue(analysis["conflict_details"])

    def test_r43_unresolved_material_conflict_is_conflicting(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            conflicts=[
                {
                    "conflict_type": "HYPOTHESIS_CONFLICT",
                    "resolution_state": "UNRESOLVED",
                    "subjects": ["sa-" + "b" * 16],
                    "conflicting_fields": ["confidence"],
                }
            ],
            finding_id_value="fnd-" + "3" * 16,
        )
        second = finding(
            "SQLI",
            "sa-" + "b" * 16,
            context={"query_context": "DATABASE_QUERY"},
            finding_id_value="fnd-" + "4" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_CONFLICTING
        )
        self.assertIn(SIGNAL_R43_MATERIAL_CONFLICT, analysis["signals"])

    def test_r43_reconcilable_confidence_conflict_is_not_material(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            conflicts=[
                {
                    "conflict_type": "CONFIDENCE_CONFLICT",
                    "resolution_state": "RECONCILABLE",
                    "subjects": ["sa-" + "b" * 16],
                    "conflicting_fields": ["result_confidence"],
                }
            ],
            confidence="HIGH",
            finding_id_value="fnd-" + "5" * 16,
        )
        second = finding(
            "SQLI",
            "sa-" + "b" * 16,
            context={"query_context": "DATABASE_QUERY"},
            confidence="LOW",
            finding_id_value="fnd-" + "6" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertNotEqual(
            analysis["relationship_type"], RELATIONSHIP_CONFLICTING
        )
        self.assertIn(SIGNAL_CONFIDENCE_DIVERGENCE, analysis["signals"])

    def test_confidence_disagreement_alone_is_not_a_conflict(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            confidence="HIGH",
            finding_id_value="fnd-" + "7" * 16,
        )
        second = finding(
            "SQLI",
            "sa-" + "b" * 16,
            context={"query_context": "DATABASE_QUERY"},
            confidence="LOW",
            finding_id_value="fnd-" + "8" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_INDEPENDENT
        )
        self.assertIn(SIGNAL_CONFIDENCE_DIVERGENCE, analysis["signals"])

    def test_evidence_state_conflict_requires_scope_overlap(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            evidence_state="COMPLETE",
            finding_id_value="fnd-" + "9" * 16,
        )
        second = finding(
            "CVE_RESEARCH",
            "sa-" + "b" * 16,
            context={"cve_metadata": "CVE-2021-44228"},
            evidence_state="UNKNOWN",
            finding_id_value="fnd-" + "a" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertNotEqual(
            analysis["relationship_type"], RELATIONSHIP_CONFLICTING
        )
        self.assertIn(
            SIGNAL_EVIDENCE_STATE_DIVERGENCE, analysis["signals"]
        )

    def test_r43_provenance_conflict_is_not_material(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            conflicts=[
                {
                    "conflict_type": "PROVENANCE_CONFLICT",
                    "resolution_state": "UNKNOWN",
                    "subjects": ["sa-" + "b" * 16],
                    "conflicting_fields": ["provenance_state"],
                }
            ],
            finding_id_value="fnd-" + "b" * 16,
        )
        second = finding(
            "SQLI",
            "sa-" + "b" * 16,
            context={"query_context": "DATABASE_QUERY"},
            finding_id_value="fnd-" + "c" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertNotEqual(
            analysis["relationship_type"], RELATIONSHIP_CONFLICTING
        )


class TestIndependentAndUnknown(unittest.TestCase):
    def test_unrelated_findings_are_independent(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            hypothesis_types=["REFLECTION_ANALYSIS"],
            finding_id_value="fnd-" + "1" * 16,
        )
        second = finding(
            "SQLI",
            "sa-" + "b" * 16,
            context={"query_context": "DATABASE_QUERY"},
            hypothesis_types=["RAW_QUERY_REVIEW"],
            finding_id_value="fnd-" + "2" * 16,
        )
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_INDEPENDENT
        )
        self.assertIn(SIGNAL_NO_SHARED_SIGNAL, analysis["signals"])

    def test_insufficient_structure_is_unknown(self):
        first = finding("IDOR", "sa-" + "a" * 16)
        second = finding("CVE_RESEARCH", "sa-" + "b" * 16)
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_UNKNOWN
        )
        self.assertIn(SIGNAL_INSUFFICIENT_STRUCTURE, analysis["signals"])

    def test_one_sided_insufficient_structure_is_unknown(self):
        first = finding(
            "XSS",
            "sa-" + "a" * 16,
            context={"output_context": "HTML"},
            finding_id_value="fnd-" + "3" * 16,
        )
        second = finding("CVE_RESEARCH", "sa-" + "b" * 16)
        analysis = analyze_pair(facts_of(first), facts_of(second))
        self.assertEqual(
            analysis["relationship_type"], RELATIONSHIP_UNKNOWN
        )


class TestScoresAndSchema(unittest.TestCase):
    def test_score_is_bounded_and_weight_derived(self):
        self.assertEqual(relational_score([]), 0)
        self.assertEqual(
            relational_score([SIGNAL_SAME_ORCHESTRATION]), 0
        )
        self.assertEqual(
            relational_score(
                [SIGNAL_SHARED_COMPONENT, SIGNAL_SHARED_CONTEXT_VALUE]
            ),
            SIGNAL_WEIGHTS[SIGNAL_SHARED_COMPONENT]
            + SIGNAL_WEIGHTS[SIGNAL_SHARED_CONTEXT_VALUE],
        )
        self.assertEqual(
            relational_score(
                [SIGNAL_IDENTICAL_FINDING_ID, SIGNAL_R43_MATERIAL_CONFLICT]
            ),
            MAX_RELATIONSHIP_SCORE,
        )

    def test_score_never_exceeds_maximum(self):
        for signals in (
            list(CORRELATION_SIGNALS),
            [SIGNAL_IDENTICAL_FINDING_ID] * 3,
        ):
            self.assertLessEqual(
                relational_score(signals), MAX_RELATIONSHIP_SCORE
            )

    def test_sanitize_relationship_bounds_and_enforces_none(self):
        payload = sanitize_finding_relationship(
            {
                "relationship_id": "fcr-" + "a" * 16,
                "relationship_type": "RELATED",
                "source_finding_id": "fnd-" + "b" * 16,
                "target_finding_id": "fnd-" + "c" * 16,
                "signals": ["SHARED_CONTEXT_VALUE", "BOGUS"],
                "score": 999,
                "confidence_effect": "HIGHER",
                "limitations": ["NOT_CONFIRMED", "BOGUS"],
            }
        )
        self.assertEqual(payload["signals"], ["SHARED_CONTEXT_VALUE"])
        self.assertEqual(payload["score"], MAX_RELATIONSHIP_SCORE)
        self.assertEqual(payload["confidence_effect"], "NONE")
        self.assertEqual(payload["limitations"], ["NOT_CONFIRMED"])

    def test_relationship_model_rejects_invalid_values(self):
        base = {
            "relationship_id": "fcr-" + "a" * 16,
            "relationship_type": "RELATED",
            "source_finding_id": "fnd-" + "b" * 16,
            "target_finding_id": "fnd-" + "c" * 16,
        }
        with self.assertRaises(ValidationError):
            FindingRelationshipPlan(
                **{**base, "relationship_type": "BOGUS"}
            )
        with self.assertRaises(ValidationError):
            FindingRelationshipPlan(
                **{**base, "relationship_id": "nope"}
            )
        with self.assertRaises(ValidationError):
            FindingRelationshipPlan(
                **{**base, "source_finding_id": "not-a-finding"}
            )
        with self.assertRaises(ValidationError):
            FindingRelationshipPlan(
                **{**base, "confidence_effect": "HIGHER"}
            )
        with self.assertRaises(ValidationError):
            FindingRelationshipPlan(
                **{**base, "research_only": False}
            )

    def test_finding_reference_enforces_not_confirmed(self):
        with self.assertRaises(ValidationError):
            FindingReferencePlan(
                finding_id="fnd-" + "a" * 16,
                category="XSS",
                confirmation_state="CONFIRMED",
            )
        with self.assertRaises(ValidationError):
            FindingReferencePlan(
                finding_id="fnd-" + "a" * 16, category="BOGUS"
            )
        with self.assertRaises(ValidationError):
            FindingReferencePlan(
                finding_id="not-a-finding", category="XSS"
            )

    def test_sanitize_reference_is_bounded(self):
        projected = sanitize_finding_reference(
            {
                "finding_id": "fnd-" + "a" * 16,
                "category": "xss",
                "confidence": "BOGUS",
                "evidence_completeness": "BOGUS",
                "confirmation_state": "CONFIRMED",
            }
        )
        self.assertEqual(projected["category"], "XSS")
        self.assertEqual(projected["confidence"], "UNKNOWN")
        self.assertEqual(projected["evidence_completeness"], "UNKNOWN")
        self.assertEqual(
            projected["confirmation_state"], "NOT_CONFIRMED"
        )

    def test_limitation_vocabulary_is_closed(self):
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_VULNERABILITY_CONFIRMATION",
            "NOT_CONFIRMED",
            "RESEARCH_ONLY",
            "CONFIDENCE_NOT_UPGRADED",
            "INSUFFICIENT_CONTEXT",
            "CORRELATION_UNAVAILABLE",
            "CONFLICT_PRESENT",
            "DUPLICATE_RELATIONSHIP",
            "SHARED_CONTEXT",
            "EVIDENCE_INCOMPLETE",
            "PROVENANCE_UNAVAILABLE",
            "GOVERNANCE_UNKNOWN",
        ):
            self.assertIn(limitation, CORRELATION_LIMITATIONS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
