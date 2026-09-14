"""tests/test_cve_research_context_analyzer.py — Stage R50.2 tests.

Deterministic, offline tests for the CVE research context analyzer:

- CVE metadata / description / product / version / advisory / CWE / CVSS /
  reference / patch presence detection
- version/component/advisory/CWE match states
- CVSS severity, attack vector, prerequisites and exploit-maturity signals
- fixed-version, patch, corroboration, applicability, history and exposure
  handling
- deterministic normalization and malformed-input degradation
- confidence calibration (metadata alone is never HIGH)
- schema validation and extra-field rejection
- R50 AST safety scan and standalone backend decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no CVE lookup, no payloads, no Mongo writes, no persistence, no
execution of any kind.
"""
import ast
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.cve_research_context_analyzer import (
    analyze_cve_research_context,
    applicability_confirmed,
    control_observed,
    cve_research_context_confidence_of,
    cve_research_context_fact_count,
    cve_research_context_present,
    match_state_of,
    remediation_present,
    version_match_observed,
    weakness_observed,
)
from ai.schemas import cve_research_context_analysis as schema


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


class TestCVEResearchContextAnalyzer(unittest.TestCase):
    def test_presence_observation_detection(self):
        analysis = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            vulnerability_description="observed",
            affected_product="observed",
            affected_versions="observed",
            fixed_version="observed",
            vendor_advisory="observed",
            cwe_metadata="observed",
            cvss_metadata="observed",
            references="observed",
            patch_information="observed",
            observed_component="observed",
            observed_version="observed",
            technology_mapping="observed",
        )
        for field in schema.PRESENCE_OBSERVATION_FIELDS:
            self.assertEqual(analysis[field], "OBSERVED", field)

    def test_presence_none_and_unknown(self):
        analysis = analyze_cve_research_context(
            cve_metadata="NONE_OBSERVED",
            cvss_metadata="UNKNOWN",
        )
        self.assertEqual(analysis["cve_metadata"], "NONE_OBSERVED")
        self.assertEqual(analysis["cvss_metadata"], "UNKNOWN")
        self.assertEqual(analysis["references"], "UNKNOWN")

    def test_match_state_detection(self):
        analysis = analyze_cve_research_context(
            version_match="MATCH_OBSERVED",
            component_match="PARTIAL_MATCH_OBSERVED",
            advisory_match="NO_MATCH_OBSERVED",
            cwe_match="MATCH_OBSERVED",
        )
        self.assertEqual(analysis["version_match"], "MATCH_OBSERVED")
        self.assertEqual(
            analysis["component_match"], "PARTIAL_MATCH_OBSERVED"
        )
        self.assertEqual(analysis["advisory_match"], "NO_MATCH_OBSERVED")
        self.assertEqual(analysis["cwe_match"], "MATCH_OBSERVED")

    def test_cvss_and_context_detection(self):
        analysis = analyze_cve_research_context(
            cvss_severity="critical_observed",
            attack_vector="network_observed",
            prerequisites="authentication_required_observed",
            exploit_maturity="functional_observed",
            historical_context="recurring_pattern_observed",
            target_exposure="exposed_observed",
        )
        self.assertEqual(analysis["cvss_severity"], "CRITICAL_OBSERVED")
        self.assertEqual(
            analysis["attack_vector"], "NETWORK_OBSERVED"
        )
        self.assertEqual(
            analysis["prerequisites"],
            "AUTHENTICATION_REQUIRED_OBSERVED",
        )
        self.assertEqual(
            analysis["exploit_maturity"], "FUNCTIONAL_OBSERVED"
        )
        self.assertEqual(
            analysis["historical_context"], "RECURRING_PATTERN_OBSERVED"
        )
        self.assertEqual(
            analysis["target_exposure"], "EXPOSED_OBSERVED"
        )

    def test_fixed_and_patch_detection(self):
        analysis = analyze_cve_research_context(
            fixed_version_state="FIXED_VERSION_AVAILABLE_OBSERVED",
            patch_state="PATCH_APPLIED_OBSERVED",
            reference_corroboration="CORROBORATED_OBSERVED",
            applicability_evidence="MATCH_OBSERVED",
        )
        self.assertEqual(
            analysis["fixed_version_state"],
            "FIXED_VERSION_AVAILABLE_OBSERVED",
        )
        self.assertEqual(analysis["patch_state"], "PATCH_APPLIED_OBSERVED")
        self.assertEqual(
            analysis["reference_corroboration"], "CORROBORATED_OBSERVED"
        )
        self.assertEqual(
            analysis["applicability_evidence"], "MATCH_OBSERVED"
        )

    def test_malformed_input_degrades(self):
        analysis = analyze_cve_research_context(
            cve_metadata="NOPE",
            version_match="similar",
            cvss_severity="9.8",
            attack_vector=42,
            exploit_maturity=["FUNCTIONAL_OBSERVED"],
            fixed_version_state="eternal",
            target_exposure=object(),
        )
        self.assertEqual(analysis["cve_metadata"], "UNKNOWN")
        self.assertEqual(analysis["version_match"], "UNKNOWN")
        self.assertEqual(analysis["cvss_severity"], "UNKNOWN")
        self.assertEqual(analysis["attack_vector"], "UNKNOWN")
        self.assertEqual(analysis["exploit_maturity"], "UNKNOWN")
        self.assertEqual(analysis["fixed_version_state"], "UNKNOWN")
        self.assertEqual(analysis["target_exposure"], "UNKNOWN")

    def test_deterministic_normalization(self):
        first = analyze_cve_research_context(
            cve_metadata=" observed ",
            version_match="match_observed",
            cvss_severity="high_observed",
        )
        second = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            version_match="MATCH_OBSERVED",
            cvss_severity="HIGH_OBSERVED",
        )
        self.assertEqual(first, second)

    def test_confidence_calibration_metadata_only_is_low(self):
        analysis = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            vulnerability_description="OBSERVED",
            affected_product="OBSERVED",
            affected_versions="OBSERVED",
            cwe_metadata="OBSERVED",
            cvss_metadata="OBSERVED",
            references="OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))
        self.assertFalse(control_observed(analysis))

    def test_confidence_cvss_and_exploit_alone_is_not_high(self):
        analysis = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            cvss_metadata="OBSERVED",
            cvss_severity="CRITICAL_OBSERVED",
            exploit_maturity="WEAPONIZED_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))

    def test_confidence_product_match_alone_is_not_high(self):
        analysis = analyze_cve_research_context(
            affected_product="OBSERVED",
            observed_component="OBSERVED",
            component_match="MATCH_OBSERVED",
            technology_mapping="OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))

    def test_confidence_version_match_is_medium(self):
        analysis = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            affected_versions="OBSERVED",
            observed_version="OBSERVED",
            version_match="MATCH_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "MEDIUM")
        self.assertFalse(weakness_observed(analysis))
        self.assertTrue(control_observed(analysis))
        self.assertTrue(version_match_observed(analysis))

    def test_confidence_applicability_match_is_medium(self):
        analysis = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            applicability_evidence="MATCH_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "MEDIUM")
        self.assertFalse(weakness_observed(analysis))

    def test_confidence_applicability_confirmed_is_high(self):
        analysis = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            applicability_evidence="CONFIRMED_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "HIGH")
        self.assertTrue(weakness_observed(analysis))
        self.assertTrue(applicability_confirmed(analysis))

    def test_confidence_remediation_and_corroboration_is_medium(self):
        for context in (
            {"fixed_version_state": "FIX_APPLIED_OBSERVED"},
            {"patch_state": "PATCH_APPLIED_OBSERVED"},
            {"reference_corroboration": "CORROBORATED_OBSERVED"},
        ):
            analysis = analyze_cve_research_context(
                cve_metadata="OBSERVED", **context
            )
            self.assertEqual(
                analysis["context_confidence"], "MEDIUM", context
            )
            self.assertTrue(control_observed(analysis), context)
        self.assertTrue(
            remediation_present(
                analyze_cve_research_context(
                    fixed_version_state="FIX_APPLIED_OBSERVED"
                )
            )
        )
        self.assertTrue(
            remediation_present(
                analyze_cve_research_context(
                    patch_state="PATCH_APPLIED_OBSERVED"
                )
            )
        )

    def test_no_match_is_not_weakness(self):
        analysis = analyze_cve_research_context(
            version_match="NO_MATCH_OBSERVED",
            component_match="NO_MATCH_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))

    def test_isolated_exposure_is_not_high(self):
        for context in (
            {"target_exposure": "EXPOSED_OBSERVED"},
            {"exploit_maturity": "FUNCTIONAL_OBSERVED"},
            {"cvss_severity": "CRITICAL_OBSERVED"},
            {"reference_corroboration": "NONE_OBSERVED"},
        ):
            analysis = analyze_cve_research_context(**context)
            self.assertNotEqual(
                analysis["context_confidence"], "HIGH", context
            )
            self.assertFalse(weakness_observed(analysis), context)

    def test_missing_context_handling(self):
        analysis = analyze_cve_research_context()
        self.assertFalse(cve_research_context_present(analysis))
        self.assertEqual(analysis["context_confidence"], "UNKNOWN")
        self.assertEqual(cve_research_context_fact_count(analysis), 0)
        partial = analyze_cve_research_context(cve_metadata="OBSERVED")
        self.assertTrue(cve_research_context_present(partial))
        self.assertEqual(cve_research_context_fact_count(partial), 1)

    def test_match_state_helper(self):
        analysis = analyze_cve_research_context(
            version_match="MATCH_OBSERVED"
        )
        self.assertEqual(
            match_state_of(analysis, "version_match"), "MATCH_OBSERVED"
        )
        self.assertEqual(
            match_state_of(analysis, "cwe_match"), "UNKNOWN"
        )
        self.assertEqual(
            match_state_of(analysis, "nope"), "UNKNOWN"
        )

    def test_confidence_recompute_ignores_stored_value(self):
        analysis = analyze_cve_research_context(
            cve_metadata="OBSERVED",
            applicability_evidence="CONFIRMED_OBSERVED",
        )
        forged = copy.deepcopy(analysis)
        forged["context_confidence"] = "UNKNOWN"
        self.assertEqual(
            cve_research_context_confidence_of(forged), "HIGH"
        )
        downgraded = copy.deepcopy(analysis)
        downgraded["context_confidence"] = "LOW"
        self.assertEqual(
            cve_research_context_confidence_of(downgraded), "HIGH"
        )

    def test_schema_rejects_bad_values_and_extra(self):
        base = analyze_cve_research_context(cve_metadata="OBSERVED")
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "cve_metadata": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "version_match": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "cvss_severity": "9.8"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "attack_vector": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "prerequisites": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "exploit_maturity": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "fixed_version_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "patch_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "reference_corroboration": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "applicability_evidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "historical_context": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "target_exposure": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchContextAnalysisPlan(
                **{**base, "cve_id": "CVE-2026-0001"}
            )

    def test_schema_forces_rule_version(self):
        plan = schema.CVEResearchContextAnalysisPlan(
            **{
                **analyze_cve_research_context(),
                "rule_version": "r99-9",
            }
        )
        self.assertEqual(plan.rule_version, "r50-2")

    def test_deterministic_serialization(self):
        first = json.dumps(
            analyze_cve_research_context(
                cve_metadata="OBSERVED",
                version_match="MATCH_OBSERVED",
                applicability_evidence="MATCH_OBSERVED",
            ),
            sort_keys=True,
        )
        second = json.dumps(
            analyze_cve_research_context(
                cve_metadata="OBSERVED",
                version_match="MATCH_OBSERVED",
                applicability_evidence="MATCH_OBSERVED",
            ),
            sort_keys=True,
        )
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())

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
