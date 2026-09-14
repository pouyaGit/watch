"""tests/test_finding_context.py — Stage R53.2 tests.

Deterministic, offline tests for finding context, impact, severity and
remediation reasoning:

- descriptive context assembled only from structured values
- deterministic titles/summaries/technical descriptions
- observed structured facts and endpoint/component extraction
- potential impact only; no business impact; no observed impact
- severity mirrored from observed CVSS context only
- remediation mirrored from upstream hints only

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.finding_reasoning import (
    CATEGORY_IMPACT_TEXT,
    build_finding_context,
    build_impact,
    build_remediation,
    build_severity,
    extract_endpoint_component,
    known_context_facts,
)
from ai.schemas.finding_context import (
    ENDPOINT_PRESENT,
    ENDPOINT_UNAVAILABLE,
    MAX_CONTEXT_FACTS,
    FindingContextPlan,
    sanitize_context_facts,
    sanitize_endpoint_component,
    sanitize_finding_context,
)

CONTEXT = {
    "rule_version": "r39-2",
    "input_location": "QUERY",
    "output_context": "HTML",
    "reflection_state": "REFLECTED",
    "encoding_state": "NONE_OBSERVED",
    "framework_context": "GENERIC",
    "context_confidence": "HIGH",
    "unknown_key": "UNKNOWN",
    "research_only": True,
}

HYPOTHESES = [
    {
        "hypothesis_type": "REFLECTION_ANALYSIS",
        "supporting_signals": ["REFLECTION_OBSERVED"],
        "confidence": "HIGH",
    }
]

EVIDENCE = {"planned_requirements": ["REFLECTION_EVIDENCE"]}


class TestFindingContext(unittest.TestCase):
    def test_known_context_facts_exclude_unknown_and_metadata(self):
        facts = known_context_facts(CONTEXT)
        keys = [fact["key"] for fact in facts]
        self.assertIn("output_context", keys)
        self.assertIn("reflection_state", keys)
        self.assertNotIn("rule_version", keys)
        self.assertNotIn("research_only", keys)
        self.assertNotIn("unknown_key", keys)

    def test_known_context_facts_are_ordered_and_bounded(self):
        facts = known_context_facts(CONTEXT)
        self.assertEqual(facts, sorted(facts, key=lambda item: item["key"]))
        self.assertLessEqual(len(facts), MAX_CONTEXT_FACTS)
        big = {f"key_{index:03d}": "VALUE" for index in range(40)}
        self.assertEqual(len(known_context_facts(big)), MAX_CONTEXT_FACTS)

    def test_context_fact_sanitizer_drops_invalid_keys(self):
        facts = sanitize_context_facts(
            [
                {"key": "output_context", "value": "HTML"},
                {"key": "Bad Key", "value": "x"},
                {"key": "", "value": "x"},
                {"key": "output_context", "value": "HTML"},
            ]
        )
        self.assertEqual(facts, [{"key": "output_context", "value": "HTML"}])

    def test_endpoint_component_unavailable_when_absent(self):
        component = extract_endpoint_component(CONTEXT)
        self.assertEqual(component["availability"], ENDPOINT_UNAVAILABLE)
        self.assertEqual(component["component_name"], "")

    def test_endpoint_component_present_when_structured(self):
        component = extract_endpoint_component(
            {
                "observed_component": "LOG4J",
                "observed_version": "2.14.1",
                "cvss_severity": "HIGH_OBSERVED",
            }
        )
        self.assertEqual(component["availability"], ENDPOINT_PRESENT)
        self.assertEqual(component["component_name"], "LOG4J")
        self.assertEqual(component["component_version"], "2.14.1")
        self.assertEqual(component["endpoint_reference"], "")

    def test_endpoint_component_sanitizer_defaults(self):
        self.assertEqual(
            sanitize_endpoint_component(None)["availability"],
            ENDPOINT_UNAVAILABLE,
        )

    def test_context_plan_builds_deterministic_description(self):
        first = build_finding_context(
            "XSS", "xss-agent", CONTEXT, HYPOTHESES, EVIDENCE
        )
        second = build_finding_context(
            "XSS", "xss-agent", CONTEXT, HYPOTHESES, EVIDENCE
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertIn("Cross-Site Scripting", first["title"])
        self.assertIn("REFLECTION_ANALYSIS", first["technical_description"])
        self.assertIn("REFLECTION_EVIDENCE", first["technical_description"])
        self.assertIn("output_context=HTML", first["technical_description"])
        self.assertIn(
            "not a confirmed vulnerability", first["technical_description"]
        )
        self.assertEqual(first["context_fact_count"], len(
            first["affected_context"]
        ))

    def test_context_description_never_invents_values(self):
        context = build_finding_context(
            "XSS", "xss-agent", {}, [], {"planned_requirements": []}
        )
        self.assertIn("UNKNOWN", context["technical_description"])
        self.assertIn("NONE_PLANNED", context["technical_description"])
        self.assertIn("NONE", context["technical_description"])
        self.assertEqual(context["affected_context"], [])
        self.assertEqual(
            context["endpoint_component"]["availability"],
            ENDPOINT_UNAVAILABLE,
        )

    def test_context_plan_schema_bounds(self):
        plan = FindingContextPlan(
            title="t" * 500,
            summary="s" * 900,
            technical_description="d" * 2000,
            affected_context=[{"key": "output_context", "value": "HTML"}],
            endpoint_component=sanitize_endpoint_component(None),
            context_fact_count=1,
        )
        projection = plan.model_dump(mode="json")
        self.assertEqual(len(projection["title"]), 200)
        self.assertEqual(len(projection["summary"]), 600)
        self.assertEqual(len(projection["technical_description"]), 1200)
        with self.assertRaises(ValidationError):
            FindingContextPlan(context_fact_count=1, research_only=False)
        dropped = FindingContextPlan(
            affected_context=[{"key": "BAD KEY", "value": "x"}]
        )
        self.assertEqual(dropped.affected_context, [])

    def test_context_sanitizer_handles_non_dict(self):
        projected = sanitize_finding_context("nope")
        self.assertEqual(projected["affected_context"], [])
        self.assertEqual(projected["context_fact_count"], 0)


class TestImpactSeverityRemediation(unittest.TestCase):
    def test_impact_is_potential_only(self):
        impact = build_impact("XSS", True, "HIGH")
        self.assertEqual(impact["impact_state"], "POTENTIAL")
        self.assertEqual(impact["impact_confidence"], "MEDIUM")
        self.assertIn("Potential impact", impact["impact_description"])
        self.assertIn("no impact is confirmed", impact["impact_description"])
        for category, text in CATEGORY_IMPACT_TEXT.items():
            self.assertIn(
                "no impact is confirmed", text, category
            )

    def test_impact_unknown_without_hypotheses(self):
        impact = build_impact("XSS", False, "HIGH")
        self.assertEqual(impact["impact_state"], "UNKNOWN")
        self.assertEqual(impact["impact_confidence"], "UNKNOWN")
        self.assertEqual(impact["impact_description"], "")

    def test_impact_confidence_never_exceeds_medium(self):
        for confidence in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            impact = build_impact("XSS", True, confidence)
            self.assertIn(
                impact["impact_confidence"],
                ("MEDIUM", "LOW", "UNKNOWN"),
            )

    def test_observed_impact_is_never_produced(self):
        for category in CATEGORY_IMPACT_TEXT:
            for confidence in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
                impact = build_impact(category, True, confidence)
                self.assertNotEqual(impact["impact_state"], "OBSERVED")

    def test_severity_mirrors_observed_cvss_context_only(self):
        mirrored = build_severity(
            "CVE_RESEARCH", {"cvss_severity": "HIGH_OBSERVED"}
        )
        self.assertEqual(mirrored["severity"], "HIGH_OBSERVED")
        self.assertEqual(mirrored["severity_source"], "CVSS_CONTEXT")
        unknown = build_severity("CVE_RESEARCH", {"cvss_severity": "UNKNOWN"})
        self.assertEqual(unknown["severity"], "UNKNOWN")
        self.assertEqual(unknown["severity_source"], "NOT_ASSESSED")

    def test_severity_never_computed_for_other_categories(self):
        severity = build_severity(
            "XSS", {"cvss_severity": "HIGH_OBSERVED"}
        )
        self.assertEqual(severity["severity"], "UNKNOWN")
        self.assertEqual(severity["severity_source"], "NOT_ASSESSED")

    def test_remediation_mirrors_upstream_hints_only(self):
        evaluation = {
            "diagnostics": [
                {
                    "diagnostic_code": "MISSING_REQUIRED_FIELD",
                    "remediation_hint": "emit every required field",
                },
                {"diagnostic_code": "NO_HINT", "remediation_hint": ""},
            ]
        }
        remediation = build_remediation(evaluation)
        self.assertEqual(remediation["remediation_state"], "AVAILABLE")
        self.assertEqual(len(remediation["remediation_items"]), 1)
        item = remediation["remediation_items"][0]
        self.assertEqual(item["remediation_type"], "RESEARCH_QUALITY")
        self.assertEqual(item["source"], "MISSING_REQUIRED_FIELD")
        self.assertIn("required field", item["guidance"])

    def test_remediation_unavailable_without_hints(self):
        remediation = build_remediation(None)
        self.assertEqual(remediation["remediation_state"], "UNAVAILABLE")
        self.assertEqual(remediation["remediation_items"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
