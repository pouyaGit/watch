"""tests/test_cve_research_hypothesis_planner.py — Stage R50.3 tests.

Deterministic, offline tests for the CVE research hypothesis planner:

- affected-version, component, advisory and CWE match reasoning
- CVSS risk-signal and exploit-maturity reasoning
- fixed-version, version-constraint, patch-availability and reference
  corroboration gap reasoning
- description match, exposure relevance and context-present reasoning
- needs-evidence semantics and no speculation from metadata presence
- deterministic ordering, priority, state and rationale
- schema validation and extra-field rejection
- R50 AST safety scan and standalone backend decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no CVE lookup, no payloads, no Mongo writes, no persistence, no
execution of any kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.cve_research_context_analyzer import (
    analyze_cve_research_context,
)
from ai.knowledge.cve_research_hypothesis_planner import (
    plan_cve_research_hypotheses,
)
from ai.schemas import cve_research_hypothesis as schema
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.cve_research_hypothesis import (
    HYPOTHESIS_STATES,
    SIGNAL_AFFECTED_VERSIONS_OBSERVED,
    SIGNAL_VERSION_MATCH_OBSERVED,
)


ROOT = Path(__file__).resolve().parents[1]

R50_MODULES = (
    "ai/schemas/cve_research_agent_identity.py",
    "ai/schemas/cve_research_context_analysis.py",
    "ai/schemas/cve_research_hypothesis.py",
    "ai/schemas/cve_research_evidence_plan.py",
    "ai/schemas/cve_research_agent_result.py",
    "ai/schemas/cve_research_agent.py",
    "ai/knowledge/cve_research_agent_identity.py",
    "ai/knowledge/cve_research_context_analyzer.py",
    "ai/knowledge/cve_research_hypothesis_planner.py",
    "ai/knowledge/cve_research_evidence_planner.py",
    "ai/knowledge/cve_research_agent_result_export.py",
    "ai/knowledge/cve_research_agent.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "urllib3", "requests",
    "httpx", "aiohttp", "asyncio", "threading", "multiprocessing",
    "concurrent", "importlib", "ctypes", "shutil", "ssl", "os", "dns",
    "selenium", "playwright", "pyppeteer", "paramiko", "sqlite3",
    "sqlalchemy", "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap",
    "nuclei", "ffuf", "curl", "pycurl", "openai", "ollama", "litellm",
    "anthropic", "openrouter", "nvdlib", "cvss", "vulners",
    "exploitdb", "metasploit", "shodan", "censys", "osv", "pyyaml",
}

FORBIDDEN_CALLS = {"__import__", "eval", "exec", "compile", "open"}

FORBIDDEN_CALL_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "importlib.",
    "socket.",
    "urllib.",
    "requests.",
    "httpx.",
    "sqlite3.",
    "sqlalchemy.",
    "psycopg2.",
    "pymysql.",
    "openai.",
    "nvdlib.",
    "shodan.",
    "censys.",
    "urllib3.",
)


def dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def scan_module(relative_path):
    tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
    imports = set()
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                name = dotted_name(node.func)
                if name.startswith(FORBIDDEN_CALL_PREFIXES):
                    calls.add(name)
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)
    return imports, calls


def hypotheses_for(**context):
    return plan_cve_research_hypotheses(
        analyze_cve_research_context(**context)
    )


def types_of(hypotheses):
    return [entry["hypothesis_type"] for entry in hypotheses]


def by_type(hypotheses, hypothesis_type):
    return [
        entry
        for entry in hypotheses
        if entry["hypothesis_type"] == hypothesis_type
    ]


class TestCVEResearchHypothesisPlanner(unittest.TestCase):
    def test_affected_version_match_reasoning(self):
        matched = hypotheses_for(
            cve_metadata="OBSERVED",
            affected_versions="OBSERVED",
            observed_version="OBSERVED",
            version_match="MATCH_OBSERVED",
        )
        gap = by_type(matched, "AFFECTED_VERSION_MATCH")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertIn(
            SIGNAL_VERSION_MATCH_OBSERVED, gap["supporting_signals"]
        )
        confirmed = hypotheses_for(
            cve_metadata="OBSERVED",
            version_match="MATCH_OBSERVED",
            applicability_evidence="CONFIRMED_OBSERVED",
        )
        gap = by_type(confirmed, "AFFECTED_VERSION_MATCH")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        partial = hypotheses_for(version_match="PARTIAL_MATCH_OBSERVED")
        gap = by_type(partial, "AFFECTED_VERSION_MATCH")[0]
        self.assertEqual(gap["priority"], "LOW")
        no_match = hypotheses_for(version_match="NO_MATCH_OBSERVED")
        gap = by_type(no_match, "AFFECTED_VERSION_MATCH")[0]
        self.assertEqual(gap["hypothesis_state"], "NOT_OBSERVED")
        needs = hypotheses_for(
            observed_version="OBSERVED", affected_versions="OBSERVED"
        )
        gap = by_type(needs, "AFFECTED_VERSION_MATCH")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertEqual(gap["priority"], "LOW")
        self.assertIn(
            SIGNAL_AFFECTED_VERSIONS_OBSERVED, gap["supporting_signals"]
        )

    def test_component_match_reasoning(self):
        matched = hypotheses_for(
            affected_product="OBSERVED",
            observed_component="OBSERVED",
            component_match="MATCH_OBSERVED",
        )
        gap = by_type(matched, "COMPONENT_MATCH")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        no_match = hypotheses_for(component_match="NO_MATCH_OBSERVED")
        gap = by_type(no_match, "COMPONENT_MATCH")[0]
        self.assertEqual(gap["hypothesis_state"], "NOT_OBSERVED")
        needs = hypotheses_for(
            affected_product="OBSERVED", observed_component="OBSERVED"
        )
        gap = by_type(needs, "COMPONENT_MATCH")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_vendor_advisory_match_reasoning(self):
        matched = hypotheses_for(
            vendor_advisory="OBSERVED", advisory_match="MATCH_OBSERVED"
        )
        gap = by_type(matched, "VENDOR_ADVISORY_MATCH")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        no_match = hypotheses_for(advisory_match="NO_MATCH_OBSERVED")
        gap = by_type(no_match, "VENDOR_ADVISORY_MATCH")[0]
        self.assertEqual(gap["hypothesis_state"], "NOT_OBSERVED")
        needs = hypotheses_for(vendor_advisory="OBSERVED")
        gap = by_type(needs, "VENDOR_ADVISORY_MATCH")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_cwe_match_reasoning(self):
        matched = hypotheses_for(
            cwe_metadata="OBSERVED", cwe_match="MATCH_OBSERVED"
        )
        gap = by_type(matched, "CWE_MATCH")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        no_match = hypotheses_for(cwe_match="NO_MATCH_OBSERVED")
        gap = by_type(no_match, "CWE_MATCH")[0]
        self.assertEqual(gap["hypothesis_state"], "NOT_OBSERVED")
        needs = hypotheses_for(cwe_metadata="OBSERVED")
        gap = by_type(needs, "CWE_MATCH")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_cvss_risk_signal_reasoning(self):
        critical = hypotheses_for(
            cvss_metadata="OBSERVED",
            cvss_severity="CRITICAL_OBSERVED",
            attack_vector="NETWORK_OBSERVED",
        )
        gap = by_type(critical, "CVSS_RISK_SIGNAL")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertNotEqual(gap["priority"], "HIGH")
        high = hypotheses_for(cvss_severity="HIGH_OBSERVED")
        self.assertEqual(
            by_type(high, "CVSS_RISK_SIGNAL")[0]["hypothesis_state"],
            "WEAKNESS_OBSERVED",
        )
        medium = hypotheses_for(cvss_severity="MEDIUM_OBSERVED")
        self.assertEqual(
            by_type(medium, "CVSS_RISK_SIGNAL")[0]["hypothesis_state"],
            "WEAKNESS_OBSERVED",
        )
        benign = hypotheses_for(cvss_severity="LOW_OBSERVED")
        self.assertEqual(
            by_type(benign, "CVSS_RISK_SIGNAL")[0]["hypothesis_state"],
            "NOT_OBSERVED",
        )
        needs = hypotheses_for(cvss_metadata="OBSERVED")
        self.assertEqual(
            by_type(needs, "CVSS_RISK_SIGNAL")[0]["hypothesis_state"],
            "NEEDS_EVIDENCE",
        )

    def test_exploit_maturity_reasoning(self):
        functional = hypotheses_for(exploit_maturity="FUNCTIONAL_OBSERVED")
        gap = by_type(functional, "EXPLOIT_MATURITY_SIGNAL")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        weaponized = hypotheses_for(
            exploit_maturity="WEAPONIZED_OBSERVED"
        )
        gap = by_type(weaponized, "EXPLOIT_MATURITY_SIGNAL")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        poc = hypotheses_for(exploit_maturity="PROOF_OF_CONCEPT_OBSERVED")
        gap = by_type(poc, "EXPLOIT_MATURITY_SIGNAL")[0]
        self.assertEqual(gap["priority"], "LOW")
        none = hypotheses_for(exploit_maturity="NONE_OBSERVED")
        gap = by_type(none, "EXPLOIT_MATURITY_SIGNAL")[0]
        self.assertEqual(gap["hypothesis_state"], "NOT_OBSERVED")
        needs = hypotheses_for(cve_metadata="OBSERVED")
        gap = by_type(needs, "EXPLOIT_MATURITY_SIGNAL")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_fixed_version_gap_reasoning(self):
        no_fix = hypotheses_for(
            affected_versions="OBSERVED",
            fixed_version_state="FIXED_VERSION_NOT_AVAILABLE_OBSERVED",
        )
        gap = by_type(no_fix, "FIXED_VERSION_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        fixed = hypotheses_for(
            fixed_version_state="FIXED_VERSION_AVAILABLE_OBSERVED"
        )
        gap = by_type(fixed, "FIXED_VERSION_GAP")[0]
        self.assertEqual(
            gap["hypothesis_state"], "CONTROL_PRESENT_OBSERVED"
        )
        applied = hypotheses_for(
            fixed_version_state="FIX_APPLIED_OBSERVED"
        )
        gap = by_type(applied, "FIXED_VERSION_GAP")[0]
        self.assertEqual(
            gap["hypothesis_state"], "CONTROL_PRESENT_OBSERVED"
        )
        needs = hypotheses_for(affected_versions="OBSERVED")
        gap = by_type(needs, "FIXED_VERSION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_version_constraint_gap_reasoning(self):
        version_without_constraints = hypotheses_for(
            observed_version="OBSERVED"
        )
        gap = by_type(
            version_without_constraints, "VERSION_CONSTRAINT_GAP"
        )[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertEqual(gap["priority"], "LOW")
        constraints_without_version = hypotheses_for(
            affected_versions="OBSERVED"
        )
        self.assertTrue(
            by_type(constraints_without_version, "VERSION_CONSTRAINT_GAP")
        )
        both = hypotheses_for(
            observed_version="OBSERVED",
            affected_versions="OBSERVED",
            version_match="MATCH_OBSERVED",
        )
        self.assertEqual(
            by_type(both, "VERSION_CONSTRAINT_GAP"), []
        )

    def test_vulnerability_description_reasoning(self):
        described = hypotheses_for(
            cve_metadata="OBSERVED",
            vulnerability_description="OBSERVED",
        )
        gap = by_type(
            described, "VULNERABILITY_DESCRIPTION_MATCH"
        )[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        needs = hypotheses_for(cve_metadata="OBSERVED")
        gap = by_type(needs, "VULNERABILITY_DESCRIPTION_MATCH")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_reference_corroboration_reasoning(self):
        corroborated = hypotheses_for(
            references="OBSERVED",
            reference_corroboration="CORROBORATED_OBSERVED",
        )
        gap = by_type(
            corroborated, "REFERENCE_CORROBORATION_GAP"
        )[0]
        self.assertEqual(
            gap["hypothesis_state"], "CONTROL_PRESENT_OBSERVED"
        )
        single = hypotheses_for(
            reference_corroboration="SINGLE_SOURCE_OBSERVED"
        )
        gap = by_type(single, "REFERENCE_CORROBORATION_GAP")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        none = hypotheses_for(
            reference_corroboration="NONE_OBSERVED"
        )
        gap = by_type(none, "REFERENCE_CORROBORATION_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        needs = hypotheses_for(references="OBSERVED")
        gap = by_type(needs, "REFERENCE_CORROBORATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_patch_availability_reasoning(self):
        no_patch = hypotheses_for(
            patch_state="PATCH_NOT_AVAILABLE_OBSERVED"
        )
        gap = by_type(no_patch, "PATCH_AVAILABILITY_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        available = hypotheses_for(
            patch_state="PATCH_AVAILABLE_OBSERVED"
        )
        gap = by_type(available, "PATCH_AVAILABILITY_GAP")[0]
        self.assertEqual(
            gap["hypothesis_state"], "CONTROL_PRESENT_OBSERVED"
        )
        needs = hypotheses_for(patch_information="OBSERVED")
        gap = by_type(needs, "PATCH_AVAILABILITY_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_exposure_relevance_reasoning(self):
        exposed = hypotheses_for(
            target_exposure="EXPOSED_OBSERVED",
            cvss_severity="HIGH_OBSERVED",
        )
        gap = by_type(exposed, "EXPOSURE_RELEVANCE")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        not_exposed = hypotheses_for(
            target_exposure="NOT_EXPOSED_OBSERVED"
        )
        gap = by_type(not_exposed, "EXPOSURE_RELEVANCE")[0]
        self.assertEqual(gap["hypothesis_state"], "NOT_OBSERVED")

    def test_cve_context_present_reasoning(self):
        controlled = hypotheses_for(
            cve_metadata="OBSERVED",
            version_match="MATCH_OBSERVED",
            applicability_evidence="MATCH_OBSERVED",
            fixed_version_state="FIX_APPLIED_OBSERVED",
        )
        control = by_type(controlled, "CVE_CONTEXT_PRESENT")
        self.assertEqual(len(control), 1)
        self.assertEqual(
            control[0]["hypothesis_state"], "CONTROL_PRESENT_OBSERVED"
        )
        self.assertEqual(control[0]["priority"], "LOW")

    def test_negative_signals_reduce_priority(self):
        weak = hypotheses_for(version_match="NO_MATCH_OBSERVED")
        controlled = hypotheses_for(
            version_match="MATCH_OBSERVED",
            applicability_evidence="MATCH_OBSERVED",
            reference_corroboration="CORROBORATED_OBSERVED",
        )
        self.assertEqual(
            by_type(weak, "AFFECTED_VERSION_MATCH")[0][
                "hypothesis_state"
            ],
            "NOT_OBSERVED",
        )
        control = by_type(controlled, "CVE_CONTEXT_PRESENT")
        self.assertEqual(len(control), 1)

    def test_no_speculation_from_metadata_presence(self):
        metadata_only = hypotheses_for(
            cve_metadata="OBSERVED",
            vulnerability_description="OBSERVED",
            affected_product="OBSERVED",
            affected_versions="OBSERVED",
            vendor_advisory="OBSERVED",
            cwe_metadata="OBSERVED",
            cvss_metadata="OBSERVED",
            references="OBSERVED",
            patch_information="OBSERVED",
            observed_component="OBSERVED",
            observed_version="OBSERVED",
        )
        for entry in metadata_only:
            self.assertNotEqual(entry["priority"], "HIGH")
        self.assertNotIn(
            "WEAKNESS_OBSERVED",
            [
                entry["hypothesis_state"]
                for entry in by_type(
                    metadata_only, "AFFECTED_VERSION_MATCH"
                )
            ],
        )

    def test_missing_context_handling(self):
        unknown = hypotheses_for()
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["hypothesis_type"], "UNKNOWN")
        self.assertEqual(unknown[0]["hypothesis_state"], "UNKNOWN")
        self.assertIn(
            "INSUFFICIENT_CONTEXT", unknown[0]["limitations"]
        )
        missing = hypotheses_for(technology_mapping="OBSERVED")
        self.assertEqual(
            types_of(missing), ["MISSING_CVE_CONTEXT"]
        )
        self.assertEqual(
            missing[0]["hypothesis_state"], "NEEDS_EVIDENCE"
        )

    def test_hypotheses_are_canonical_ordered_and_closed(self):
        hypotheses = hypotheses_for(
            cve_metadata="OBSERVED",
            version_match="MATCH_OBSERVED",
            applicability_evidence="CONFIRMED_OBSERVED",
            cvss_severity="CRITICAL_OBSERVED",
            exploit_maturity="FUNCTIONAL_OBSERVED",
            fixed_version_state="FIXED_VERSION_NOT_AVAILABLE_OBSERVED",
        )
        types = types_of(hypotheses)
        expected_order = [
            hypothesis_type
            for hypothesis_type in schema.HYPOTHESIS_TYPES
            if hypothesis_type in types
        ]
        self.assertEqual(types, expected_order)
        self.assertEqual(len(types), len(set(types)))
        for entry in hypotheses:
            self.assertIn(entry["hypothesis_type"], schema.HYPOTHESIS_TYPES)
            self.assertIn(entry["hypothesis_state"], HYPOTHESIS_STATES)
            self.assertIn(entry["priority"], CONFIDENCE_LEVELS)
            self.assertIn(entry["confidence"], CONFIDENCE_LEVELS)
            self.assertTrue(entry["supporting_signals"])
            for signal in entry["supporting_signals"]:
                self.assertIn(signal, schema.CVE_RESEARCH_SIGNALS)
            self.assertNotEqual(entry["rationale"], "")

    def test_hypothesis_limitations(self):
        hypotheses = hypotheses_for(
            cve_metadata="OBSERVED",
            applicability_evidence="CONFIRMED_OBSERVED",
        )
        for entry in hypotheses:
            for limitation in (
                "NO_EXPLOIT_CLAIM",
                "NO_VULNERABILITY_CONFIRMATION",
                "NO_CVE_LOOKUP_CLAIM",
                "NO_EXPLOIT_RETRIEVAL_CLAIM",
                "NO_REPRODUCTION_CLAIM",
                "NO_PAYLOAD_GENERATION_CLAIM",
                "HYPOTHESIS_ONLY",
                "EVIDENCE_REQUIRED",
            ):
                self.assertIn(limitation, entry["limitations"])
        unknown = hypotheses_for()
        self.assertIn(
            "INSUFFICIENT_CONTEXT", unknown[0]["limitations"]
        )

    def test_schema_rejects_bad_values_and_extra(self):
        base = hypotheses_for(
            cve_metadata="OBSERVED",
            version_match="MATCH_OBSERVED",
        )[0]
        with self.assertRaises(ValidationError):
            schema.CVEResearchHypothesisPlan(
                **{**base, "hypothesis_type": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchHypothesisPlan(
                **{**base, "hypothesis_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchHypothesisPlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchHypothesisPlan(
                **{**base, "priority": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchHypothesisPlan(
                **{**base, "supporting_signals": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchHypothesisPlan(
                **{**base, "limitations": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchHypothesisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchHypothesisPlan(
                **{**base, "exploit": "x"}
            )

    def test_schema_forces_rule_version(self):
        plan = schema.CVEResearchHypothesisPlan(
            hypothesis_type="CVSS_RISK_SIGNAL",
            rule_version="r99-9",
        )
        self.assertEqual(plan.rule_version, "r50-3")

    def test_deterministic_serialization(self):
        first = json.dumps(
            hypotheses_for(
                cve_metadata="OBSERVED",
                version_match="MATCH_OBSERVED",
            ),
            sort_keys=True,
        )
        second = json.dumps(
            hypotheses_for(
                cve_metadata="OBSERVED",
                version_match="MATCH_OBSERVED",
            ),
            sort_keys=True,
        )
        self.assertEqual(first, second)

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R50_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("cve_research_agent", backend_source)
        self.assertNotIn("CVE_RESEARCH_AGENT", backend_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
