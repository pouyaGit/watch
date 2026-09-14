"""tests/test_cve_research_evidence_planner.py — Stage R50.4 tests.

Deterministic, offline tests for the CVE research evidence planner:

- closed evidence vocabulary and per-hypothesis evidence mapping
- evidence requirements are planning only, never collection
- deterministic planning state and confidence calibration
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
from ai.knowledge.cve_research_evidence_planner import (
    HYPOTHESIS_EVIDENCE,
    plan_cve_research_evidence,
)
from ai.knowledge.cve_research_hypothesis_planner import (
    plan_cve_research_hypotheses,
)
from ai.schemas import cve_research_evidence_plan as schema
from ai.schemas.cve_research_evidence_plan import (
    EVIDENCE_AFFECTED_PRODUCT_IDENTIFICATION,
    EVIDENCE_AFFECTED_VERSION_CONSTRAINTS,
    EVIDENCE_APPLICABILITY_EVIDENCE,
    EVIDENCE_ATTACK_VECTOR_CONTEXT,
    EVIDENCE_COMPONENT_MATCH_EVIDENCE,
    EVIDENCE_CVE_IDENTITY_REFERENCE,
    EVIDENCE_CVE_RESEARCH_CONTEXT,
    EVIDENCE_CVSS_METADATA,
    EVIDENCE_CWE_REFERENCE,
    EVIDENCE_EXPLOIT_MATURITY_SOURCE,
    EVIDENCE_FIXED_VERSION_INFORMATION,
    EVIDENCE_OBSERVED_COMPONENT_IDENTIFICATION,
    EVIDENCE_OBSERVED_VERSION_IDENTIFICATION,
    EVIDENCE_PATCH_APPLICATION_STATE,
    EVIDENCE_PATCH_AVAILABILITY,
    EVIDENCE_PREREQUISITE_CONTEXT,
    EVIDENCE_REFERENCE_CORROBORATION,
    EVIDENCE_REFERENCE_PROVENANCE,
    EVIDENCE_TARGET_EXPOSURE_CONTEXT,
    EVIDENCE_TECHNOLOGY_MAPPING,
    EVIDENCE_UNKNOWN,
    EVIDENCE_VENDOR_ADVISORY,
    EVIDENCE_VERSION_CONSTRAINT_COMPARISON,
    EVIDENCE_VULNERABILITY_DESCRIPTION,
)
from ai.schemas.cve_research_hypothesis import (
    HYPOTHESIS_TYPES,
    TYPE_AFFECTED_VERSION_MATCH,
    TYPE_COMPONENT_MATCH,
    TYPE_CVE_CONTEXT_PRESENT,
    TYPE_CVSS_RISK_SIGNAL,
    TYPE_CWE_MATCH,
    TYPE_EXPLOIT_MATURITY_SIGNAL,
    TYPE_FIXED_VERSION_GAP,
    TYPE_MISSING_CVE_CONTEXT,
    TYPE_PATCH_AVAILABILITY_GAP,
    TYPE_REFERENCE_CORROBORATION_GAP,
    TYPE_UNKNOWN,
    TYPE_VENDOR_ADVISORY_MATCH,
    TYPE_VERSION_CONSTRAINT_GAP,
    TYPE_VULNERABILITY_DESCRIPTION_MATCH,
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


def rich_context():
    return analyze_cve_research_context(
        cve_metadata="OBSERVED",
        vulnerability_description="OBSERVED",
        affected_product="OBSERVED",
        affected_versions="OBSERVED",
        observed_component="OBSERVED",
        observed_version="OBSERVED",
        technology_mapping="OBSERVED",
        version_match="MATCH_OBSERVED",
        component_match="MATCH_OBSERVED",
        applicability_evidence="MATCH_OBSERVED",
        cvss_metadata="OBSERVED",
        cvss_severity="HIGH_OBSERVED",
        attack_vector="NETWORK_OBSERVED",
    )


class TestCVEResearchEvidencePlanner(unittest.TestCase):
    def test_evidence_vocabulary_is_closed(self):
        self.assertEqual(len(schema.CVE_RESEARCH_EVIDENCE_ITEMS), 25)
        self.assertEqual(
            len(set(schema.CVE_RESEARCH_EVIDENCE_ITEMS)), 25
        )
        self.assertEqual(
            schema.CVE_RESEARCH_EVIDENCE_ITEMS[-1], EVIDENCE_UNKNOWN
        )
        for limitation in (
            "NO_COLLECTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_CVE_LOOKUP",
            "NO_REFERENCE_RETRIEVAL",
            "NO_EXPLOIT_RETRIEVAL",
            "NO_VULNERABILITY_REPRODUCTION",
            "NO_PAYLOAD_GENERATION",
            "EVIDENCE_REQUIRED",
            "INSUFFICIENT_CONTEXT",
        ):
            self.assertIn(
                limitation, schema.CVE_RESEARCH_EVIDENCE_LIMITATIONS
            )

    def test_mapping_covers_every_hypothesis(self):
        for hypothesis_type in HYPOTHESIS_TYPES:
            self.assertIn(hypothesis_type, HYPOTHESIS_EVIDENCE)
            for item in HYPOTHESIS_EVIDENCE[hypothesis_type]:
                self.assertIn(item, schema.CVE_RESEARCH_EVIDENCE_ITEMS)

    def test_version_match_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_AFFECTED_VERSION_MATCH]
        self.assertIn(EVIDENCE_AFFECTED_VERSION_CONSTRAINTS, evidence)
        self.assertIn(EVIDENCE_OBSERVED_VERSION_IDENTIFICATION, evidence)
        self.assertIn(EVIDENCE_VERSION_CONSTRAINT_COMPARISON, evidence)
        self.assertIn(EVIDENCE_APPLICABILITY_EVIDENCE, evidence)

    def test_component_match_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_COMPONENT_MATCH]
        self.assertIn(EVIDENCE_AFFECTED_PRODUCT_IDENTIFICATION, evidence)
        self.assertIn(EVIDENCE_OBSERVED_COMPONENT_IDENTIFICATION, evidence)
        self.assertIn(EVIDENCE_COMPONENT_MATCH_EVIDENCE, evidence)
        self.assertIn(EVIDENCE_TECHNOLOGY_MAPPING, evidence)

    def test_advisory_and_cwe_evidence(self):
        advisory = HYPOTHESIS_EVIDENCE[TYPE_VENDOR_ADVISORY_MATCH]
        self.assertIn(EVIDENCE_VENDOR_ADVISORY, advisory)
        self.assertIn(EVIDENCE_REFERENCE_PROVENANCE, advisory)
        cwe = HYPOTHESIS_EVIDENCE[TYPE_CWE_MATCH]
        self.assertIn(EVIDENCE_CWE_REFERENCE, cwe)

    def test_risk_signal_evidence(self):
        cvss = HYPOTHESIS_EVIDENCE[TYPE_CVSS_RISK_SIGNAL]
        self.assertIn(EVIDENCE_CVSS_METADATA, cvss)
        self.assertIn(EVIDENCE_ATTACK_VECTOR_CONTEXT, cvss)
        self.assertIn(EVIDENCE_PREREQUISITE_CONTEXT, cvss)
        maturity = HYPOTHESIS_EVIDENCE[TYPE_EXPLOIT_MATURITY_SIGNAL]
        self.assertIn(EVIDENCE_EXPLOIT_MATURITY_SOURCE, maturity)
        self.assertIn(EVIDENCE_REFERENCE_CORROBORATION, maturity)

    def test_gap_evidence(self):
        fixed = HYPOTHESIS_EVIDENCE[TYPE_FIXED_VERSION_GAP]
        self.assertIn(EVIDENCE_FIXED_VERSION_INFORMATION, fixed)
        self.assertIn(EVIDENCE_PATCH_APPLICATION_STATE, fixed)
        constraints = HYPOTHESIS_EVIDENCE[TYPE_VERSION_CONSTRAINT_GAP]
        self.assertIn(EVIDENCE_AFFECTED_VERSION_CONSTRAINTS, constraints)
        patch = HYPOTHESIS_EVIDENCE[TYPE_PATCH_AVAILABILITY_GAP]
        self.assertIn(EVIDENCE_PATCH_AVAILABILITY, patch)
        corroboration = HYPOTHESIS_EVIDENCE[
            TYPE_REFERENCE_CORROBORATION_GAP
        ]
        self.assertIn(EVIDENCE_REFERENCE_CORROBORATION, corroboration)

    def test_description_and_exposure_evidence(self):
        description = HYPOTHESIS_EVIDENCE[
            TYPE_VULNERABILITY_DESCRIPTION_MATCH
        ]
        self.assertIn(EVIDENCE_VULNERABILITY_DESCRIPTION, description)
        self.assertIn(EVIDENCE_CVE_IDENTITY_REFERENCE, description)
        exposure = HYPOTHESIS_EVIDENCE["EXPOSURE_RELEVANCE"]
        self.assertIn(EVIDENCE_TARGET_EXPOSURE_CONTEXT, exposure)
        self.assertIn(EVIDENCE_TECHNOLOGY_MAPPING, exposure)

    def test_context_present_and_missing_evidence(self):
        control = HYPOTHESIS_EVIDENCE[TYPE_CVE_CONTEXT_PRESENT]
        self.assertIn(EVIDENCE_CVE_RESEARCH_CONTEXT, control)
        missing = HYPOTHESIS_EVIDENCE[TYPE_MISSING_CVE_CONTEXT]
        self.assertIn(EVIDENCE_CVE_IDENTITY_REFERENCE, missing)
        self.assertIn(EVIDENCE_AFFECTED_PRODUCT_IDENTIFICATION, missing)

    def test_unknown_context_plan(self):
        evidence = plan_cve_research_evidence(
            analyze_cve_research_context()
        )
        self.assertEqual(evidence["evidence_items"], [EVIDENCE_UNKNOWN])
        self.assertEqual(evidence["evidence_state"], "UNKNOWN")
        self.assertEqual(evidence["confidence"], "UNKNOWN")
        self.assertIn("INSUFFICIENT_CONTEXT", evidence["limitations"])

    def test_partial_plan_for_metadata_only(self):
        context = analyze_cve_research_context(cve_metadata="OBSERVED")
        evidence = plan_cve_research_evidence(context)
        self.assertEqual(context["context_confidence"], "LOW")
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        self.assertFalse(
            any(
                item == EVIDENCE_UNKNOWN
                for item in evidence["evidence_items"]
            )
        )

    def test_isolated_version_match_is_not_complete(self):
        context = analyze_cve_research_context(
            version_match="MATCH_OBSERVED"
        )
        self.assertEqual(context["context_confidence"], "MEDIUM")
        evidence = plan_cve_research_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")

    def test_complete_plan_for_confirmed_applicability(self):
        context = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            version_match="MATCH_OBSERVED",
            applicability_evidence="CONFIRMED_OBSERVED",
        )
        self.assertEqual(context["context_confidence"], "HIGH")
        evidence = plan_cve_research_evidence(context)
        self.assertEqual(evidence["evidence_state"], "COMPLETE")
        self.assertEqual(evidence["confidence"], "HIGH")

    def test_missing_context_hypothesis_is_never_complete(self):
        context = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            applicability_evidence="CONFIRMED_OBSERVED",
        )
        self.assertEqual(context["context_confidence"], "HIGH")
        evidence = plan_cve_research_evidence(
            context,
            [
                {
                    "hypothesis_type": TYPE_MISSING_CVE_CONTEXT,
                    "hypothesis_state": "NEEDS_EVIDENCE",
                    "confidence": "LOW",
                    "priority": "LOW",
                }
            ],
        )
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        unknown_only = plan_cve_research_evidence(
            context,
            [
                {
                    "hypothesis_type": TYPE_UNKNOWN,
                    "hypothesis_state": "UNKNOWN",
                    "confidence": "UNKNOWN",
                    "priority": "UNKNOWN",
                }
            ],
        )
        self.assertNotEqual(unknown_only["evidence_state"], "COMPLETE")

    def test_explicit_hypotheses_are_respected(self):
        context = rich_context()
        manual = plan_cve_research_evidence(
            context,
            [
                {
                    "hypothesis_type": TYPE_CVSS_RISK_SIGNAL,
                    "hypothesis_state": "WEAKNESS_OBSERVED",
                    "confidence": "LOW",
                    "priority": "LOW",
                }
            ],
        )
        self.assertEqual(
            manual["evidence_items"],
            list(HYPOTHESIS_EVIDENCE[TYPE_CVSS_RISK_SIGNAL]),
        )

    def test_evidence_limitations(self):
        evidence = plan_cve_research_evidence(
            analyze_cve_research_context()
        )
        for limitation in (
            "NO_COLLECTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_CVE_LOOKUP",
            "NO_REFERENCE_RETRIEVAL",
            "NO_EXPLOIT_RETRIEVAL",
            "NO_VULNERABILITY_REPRODUCTION",
            "NO_PAYLOAD_GENERATION",
            "EVIDENCE_REQUIRED",
        ):
            self.assertIn(limitation, evidence["limitations"])
        complete = plan_cve_research_evidence(
            analyze_cve_research_context(
                cve_metadata="OBSERVED",
                applicability_evidence="CONFIRMED_OBSERVED",
            )
        )
        self.assertNotIn(
            "INSUFFICIENT_CONTEXT", complete["limitations"]
        )

    def test_generated_evidence_plan_matches_hypotheses(self):
        context = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            version_match="MATCH_OBSERVED",
            cvss_severity="CRITICAL_OBSERVED",
        )
        hypotheses = plan_cve_research_hypotheses(context)
        evidence = plan_cve_research_evidence(context, hypotheses)
        expected: list[str] = []
        for hypothesis in hypotheses:
            for item in HYPOTHESIS_EVIDENCE[hypothesis["hypothesis_type"]]:
                if item not in expected:
                    expected.append(item)
        self.assertEqual(evidence["evidence_items"], expected)

    def test_schema_rejects_bad_values_and_extra(self):
        base = plan_cve_research_evidence(
            analyze_cve_research_context(cve_metadata="OBSERVED")
        )
        with self.assertRaises(ValidationError):
            schema.CVEResearchEvidencePlan(
                **{**base, "evidence_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchEvidencePlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchEvidencePlan(
                **{**base, "evidence_items": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchEvidencePlan(
                **{**base, "limitations": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchEvidencePlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchEvidencePlan(**{**base, "lookup": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.CVEResearchEvidencePlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r50-4")

    def test_deterministic_serialization(self):
        first = json.dumps(
            plan_cve_research_evidence(
                analyze_cve_research_context(
                    cve_metadata="OBSERVED",
                    version_match="MATCH_OBSERVED",
                )
            ),
            sort_keys=True,
        )
        second = json.dumps(
            plan_cve_research_evidence(
                analyze_cve_research_context(
                    cve_metadata="OBSERVED",
                    version_match="MATCH_OBSERVED",
                )
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
