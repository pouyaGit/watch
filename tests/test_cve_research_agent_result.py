"""tests/test_cve_research_agent_result.py — Stage R50.5 tests.

Deterministic, offline tests for the CVE research agent result:

- exact result contract and status/confidence derivation
- provenance and governance preservation without invention
- observed evidence preservation and no fabrication
- R42 / R43 / R44 / R45 compatibility through generic contracts
- R46 / R47 / R48 / R49 interoperability
- forbidden payload/attack/secret output scan
- deterministic serialization and repeated execution equality
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

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.api_security_agent_result_export import (
    export_api_security_agent_result,
)
from ai.knowledge.cve_research_agent_result_export import (
    build_governance_reference,
    cve_research_agent_result_to_r38,
    export_cve_research_agent_result,
)
from ai.knowledge.idor_bola_agent_result_export import (
    export_idor_bola_agent_result,
)
from ai.knowledge.jwt_authentication_agent_result_export import (
    export_jwt_authentication_agent_result,
)
from ai.knowledge.learning_signal_extractor import extract_learning_signals
from ai.knowledge.llm_advisory_export import export_llm_advisory
from ai.knowledge.multi_agent_collaboration_export import (
    export_multi_agent_collaboration,
)
from ai.knowledge.oauth_agent_result_export import (
    export_oauth_agent_result,
)
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import build_research_feedback_event
from ai.knowledge.research_governance_export import export_research_governance
from ai.knowledge.security_agent_input_validator import (
    validate_security_agent_input,
)
from ai.knowledge.sqli_agent_result_export import export_sqli_agent_result
from ai.knowledge.ssrf_agent_result_export import export_ssrf_agent_result
from ai.knowledge.xss_agent_identity import plan_xss_agent_identity
from ai.knowledge.xss_agent_result_export import export_xss_agent_result
from ai.schemas import cve_research_agent_result as schema
from ai.schemas.agent_evaluation_score import (
    EVALUATION_RATINGS,
    HARD_GATE_STATES,
    SAFETY_STATES,
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

FORBIDDEN_OUTPUT_TOKENS = (
    "nvd.nist.gov",
    "nvd api",
    "exploit-db",
    "metasploit",
    "shodan",
    "censys",
    "download exploit",
    "exploit payload",
    "reproduce the vulnerability",
    "curl http",
    "wget http",
    "payload:",
    "<script",
    "union select",
    "execute this",
    "run this command",
    "steal token",
    "forge token",
    "secret key is",
    "api key is",
    "authorization: bearer",
    "brute force password",
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


def weakness_result():
    return export_cve_research_agent_result(
        cve_metadata="OBSERVED",
        affected_versions="OBSERVED",
        observed_version="OBSERVED",
        version_match="MATCH_OBSERVED",
        applicability_evidence="CONFIRMED_OBSERVED",
    )


def needs_evidence_result():
    return export_cve_research_agent_result(cve_metadata="OBSERVED")


def sparse_weakness_result():
    return export_cve_research_agent_result(
        cvss_severity="CRITICAL_OBSERVED"
    )


def control_result():
    return export_cve_research_agent_result(
        cve_metadata="OBSERVED",
        applicability_evidence="MATCH_OBSERVED",
        fixed_version_state="FIX_APPLIED_OBSERVED",
        patch_state="PATCH_APPLIED_OBSERVED",
        reference_corroboration="CORROBORATED_OBSERVED",
    )


class TestCVEResearchAgentResult(unittest.TestCase):
    def test_key_set_is_exact(self):
        result = export_cve_research_agent_result()
        self.assertEqual(
            set(result.keys()),
            {"rule_version", "agent_name", "agent_identity", "status",
             "context_analysis", "hypotheses", "evidence_plan",
             "confidence", "limitations", "governance_reference",
             "provenance", "research_only"},
        )
        self.assertEqual(result["rule_version"], "r50-5")
        self.assertIs(result["research_only"], True)

    def test_identity_embedded(self):
        result = export_cve_research_agent_result()
        identity = result["agent_identity"]
        self.assertEqual(identity["category"], "CVE_RESEARCH")
        self.assertEqual(identity["agent_name"], "cve-research-specialist")
        self.assertEqual(identity["rule_version"], "r50-1")
        self.assertEqual(result["agent_name"], "cve-research-specialist")

    def test_status_derivation(self):
        self.assertEqual(
            export_cve_research_agent_result()["status"], "CREATED"
        )
        self.assertEqual(
            needs_evidence_result()["status"], "ANALYZING"
        )
        self.assertEqual(weakness_result()["status"], "COMPLETED")
        self.assertEqual(control_result()["status"], "ANALYZING")

    def test_confidence_calibration_through_result(self):
        self.assertEqual(
            export_cve_research_agent_result()["confidence"], "UNKNOWN"
        )
        self.assertEqual(needs_evidence_result()["confidence"], "LOW")
        self.assertEqual(weakness_result()["confidence"], "HIGH")
        self.assertEqual(control_result()["confidence"], "LOW")

    def test_hypotheses_bounded(self):
        result = weakness_result()
        self.assertLessEqual(
            len(result["hypotheses"]), schema.MAX_HYPOTHESES
        )
        self.assertTrue(result["hypotheses"])

    def test_observed_weakness_preserved(self):
        result = weakness_result()
        version = [
            hypothesis
            for hypothesis in result["hypotheses"]
            if hypothesis["hypothesis_type"] == "AFFECTED_VERSION_MATCH"
        ][0]
        self.assertEqual(
            version["hypothesis_state"], "WEAKNESS_OBSERVED"
        )
        self.assertEqual(version["priority"], "HIGH")
        self.assertIn(
            "VERSION_MATCH_OBSERVED", version["supporting_signals"]
        )
        self.assertIn(
            "APPLICABILITY_CONFIRMED_OBSERVED",
            version["supporting_signals"],
        )
        self.assertEqual(
            result["context_analysis"]["applicability_evidence"],
            "CONFIRMED_OBSERVED",
        )

    def test_no_fabricated_weakness(self):
        result = needs_evidence_result()
        serialized = json.dumps(result, sort_keys=True)
        for hypothesis in result["hypotheses"]:
            self.assertNotEqual(hypothesis["priority"], "HIGH")
        self.assertNotIn("VULNERABILITY_CONFIRMED", serialized)
        self.assertNotIn("EXPLOITED", serialized)
        self.assertNotIn("exploit code", serialized.lower())

    def test_provenance_unknown_by_default(self):
        provenance = export_cve_research_agent_result()["provenance"]
        self.assertEqual(provenance["provenance_state"], "UNKNOWN")
        self.assertEqual(provenance["source_layers"], [])

    def test_provenance_preserved_from_r38_input(self):
        bounded = validate_security_agent_input(
            research_context={"topic": "r31"},
            memory_context={"prior": "r32"},
            authorization_context={"scope": "research"},
        )
        result = export_cve_research_agent_result(
            security_agent_input=bounded,
            cve_metadata="OBSERVED",
        )
        self.assertEqual(
            result["provenance"]["source_layers"],
            ["REASONING", "MEMORY", "AUTHORIZATION"],
        )
        self.assertEqual(
            result["provenance"]["provenance_state"], "PARTIAL"
        )

    def test_provenance_complete_for_all_layers(self):
        bounded = validate_security_agent_input(
            research_context={"a": 1},
            memory_context={"b": 2},
            strategy_context={"c": 3},
            orchestration_context={"d": 4},
            authorization_context={"e": 5},
            governance_context={"f": 6},
        )
        result = export_cve_research_agent_result(
            security_agent_input=bounded
        )
        self.assertEqual(
            result["provenance"]["source_layers"],
            ["REASONING", "MEMORY", "STRATEGY", "ORCHESTRATION",
             "AUTHORIZATION", "GOVERNANCE"],
        )
        self.assertEqual(
            result["provenance"]["provenance_state"], "COMPLETE"
        )

    def test_provenance_records_governance_reference(self):
        result = export_cve_research_agent_result(
            governance_plan=export_research_governance()
        )
        self.assertEqual(
            result["provenance"]["source_layers"], ["GOVERNANCE"]
        )

    def test_governance_unknown_by_default(self):
        result = export_cve_research_agent_result()
        reference = result["governance_reference"]
        self.assertEqual(reference["reference_state"], "UNKNOWN")
        self.assertIs(reference["ready"], False)
        self.assertIn("GOVERNANCE_UNKNOWN", result["limitations"])

    def test_governance_reference_integration(self):
        result = export_cve_research_agent_result(
            governance_plan=export_research_governance()
        )
        reference = result["governance_reference"]
        self.assertEqual(reference["rule_version"], "r37-5")
        self.assertEqual(reference["reference_state"], "REFERENCED")
        self.assertNotIn("GOVERNANCE_UNKNOWN", result["limitations"])

    def test_governance_rejects_foreign_or_malformed(self):
        for bad in (
            None,
            "",
            42,
            [],
            {"rule_version": "r40-5", "ready": True},
            {"rule_version": "r37-5"},
            {"rule_version": "r37-5", "reference_state": "REFERENCED",
             "ready": True},
        ):
            reference = build_governance_reference(bad)
            self.assertEqual(
                reference["reference_state"], "UNKNOWN", repr(bad)
            )
            self.assertIs(reference["ready"], False, repr(bad))

    def test_r42_compatibility(self):
        result = weakness_result()
        evaluation = evaluate_agent_result(result)
        self.assertEqual(
            evaluation["evaluated_agent_category"], "CVE_RESEARCH"
        )
        self.assertEqual(
            evaluation["evaluated_result_rule_version"], "r50-5"
        )
        self.assertIn(evaluation["overall_rating"], EVALUATION_RATINGS)
        self.assertIn(evaluation["hard_gate_state"], HARD_GATE_STATES)
        self.assertIn(evaluation["safety_state"], SAFETY_STATES)
        self.assertGreaterEqual(evaluation["overall_score"], 0)
        self.assertLessEqual(evaluation["overall_score"], 100)
        self.assertIs(evaluation["deterministic"], True)
        self.assertIs(evaluation["research_only"], True)

    def test_r42_structural_and_calibration_fields(self):
        evaluation = evaluate_agent_result(control_result())
        dimensions = {
            entry["dimension"]: entry
            for entry in evaluation["dimension_scores"]
        }
        self.assertIn("STRUCTURAL_VALIDITY", dimensions)
        self.assertIn("EVIDENCE_COMPLETENESS", dimensions)
        self.assertIn("CONFIDENCE_CALIBRATION", dimensions)
        self.assertIn("SAFETY_COMPLIANCE", dimensions)
        self.assertIn("PROVENANCE_COMPLETENESS", dimensions)
        self.assertIn("GOVERNANCE_COMPLETENESS", dimensions)
        codes = [
            entry["diagnostic_code"]
            for entry in evaluation["diagnostics"]
        ]
        self.assertNotIn("RESEARCH_ONLY_FALSE", codes)
        self.assertNotIn("EXECUTION_CLAIM_DETECTED", codes)

    def test_sparse_weakness_context_is_conservative(self):
        result = sparse_weakness_result()
        self.assertEqual(result["status"], "ANALYZING")
        self.assertEqual(result["confidence"], "LOW")
        self.assertNotEqual(result["status"], "COMPLETED")
        self.assertNotEqual(result["confidence"], "HIGH")
        cvss = [
            hypothesis
            for hypothesis in result["hypotheses"]
            if hypothesis["hypothesis_type"] == "CVSS_RISK_SIGNAL"
        ][0]
        self.assertEqual(cvss["priority"], "LOW")
        self.assertEqual(cvss["hypothesis_state"], "WEAKNESS_OBSERVED")

    def test_r42_sparse_context_is_not_overstated(self):
        for result in (
            sparse_weakness_result(),
            export_cve_research_agent_result(
                target_exposure="EXPOSED_OBSERVED"
            ),
            export_cve_research_agent_result(
                exploit_maturity="FUNCTIONAL_OBSERVED"
            ),
            export_cve_research_agent_result(
                version_match="MATCH_OBSERVED"
            ),
        ):
            evaluation = evaluate_agent_result(result)
            codes = [
                entry["diagnostic_code"]
                for entry in evaluation["diagnostics"]
            ]
            self.assertNotIn("CONFIDENCE_OVERSTATED", codes)
            self.assertEqual(evaluation["overall_rating"], "GOOD")

    def test_observed_weakness_is_research_finding_only(self):
        result = weakness_result()
        gaps = [
            hypothesis
            for hypothesis in result["hypotheses"]
            if hypothesis["hypothesis_state"] == "WEAKNESS_OBSERVED"
        ]
        self.assertTrue(gaps)
        for gap in gaps:
            self.assertIn("NO_EXPLOIT_CLAIM", gap["limitations"])
            self.assertIn(
                "NO_VULNERABILITY_CONFIRMATION", gap["limitations"]
            )
            self.assertIn("NO_REPRODUCTION_CLAIM", gap["limitations"])
            self.assertIn("EVIDENCE_REQUIRED", gap["limitations"])

    def _collaboration(self, other):
        result = export_cve_research_agent_result(
            cve_metadata="OBSERVED",
            version_match="MATCH_OBSERVED",
        )
        return export_multi_agent_collaboration([other, result])

    def _xss_wrapped(self):
        xss_identity = plan_xss_agent_identity(maturity="RESEARCH")
        return {
            "specialist_result": export_xss_agent_result(),
            "agent_id": xss_identity["agent_id"],
            "agent_category": "XSS",
        }

    def test_r43_collaboration_with_r39(self):
        collaboration = self._collaboration(self._xss_wrapped())
        categories = {
            agent["agent_category"]
            for agent in collaboration["participating_agents"]
        }
        self.assertEqual(categories, {"XSS", "CVE_RESEARCH"})
        self.assertEqual(len(collaboration["collaboration_rankings"]), 2)

    def test_r43_collaboration_with_r40(self):
        collaboration = self._collaboration(export_ssrf_agent_result())
        categories = {
            agent["agent_category"]
            for agent in collaboration["participating_agents"]
        }
        self.assertEqual(categories, {"SSRF", "CVE_RESEARCH"})
        self.assertEqual(len(collaboration["collaboration_rankings"]), 2)
        self.assertTrue(collaboration["hypothesis_groups"])
        self.assertIn("merged_evidence", collaboration)
        for agent in collaboration["participating_agents"]:
            self.assertIn("provenance", agent)

    def test_r43_collaboration_with_r41(self):
        collaboration = self._collaboration(export_sqli_agent_result())
        categories = {
            agent["agent_category"]
            for agent in collaboration["participating_agents"]
        }
        self.assertEqual(categories, {"SQLI", "CVE_RESEARCH"})
        self.assertEqual(len(collaboration["collaboration_rankings"]), 2)

    def test_r43_collaboration_with_r46(self):
        idor = export_idor_bola_agent_result(
            object_reference="PATH_PARAMETER",
            ownership_relationship="OWNER_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
            authorization_control="AUTHORIZATION_ABSENT",
        )
        collaboration = self._collaboration(idor)
        categories = {
            agent["agent_category"]
            for agent in collaboration["participating_agents"]
        }
        self.assertEqual(categories, {"IDOR", "CVE_RESEARCH"})
        first = json.dumps(collaboration, sort_keys=True)
        second = json.dumps(self._collaboration(idor), sort_keys=True)
        self.assertEqual(first, second)

    def test_r43_collaboration_with_r47(self):
        jwt = export_jwt_authentication_agent_result(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
        )
        collaboration = self._collaboration(jwt)
        categories = {
            agent["agent_category"]
            for agent in collaboration["participating_agents"]
        }
        self.assertEqual(categories, {"JWT", "CVE_RESEARCH"})
        first = json.dumps(collaboration, sort_keys=True)
        second = json.dumps(self._collaboration(jwt), sort_keys=True)
        self.assertEqual(first, second)

    def test_r43_collaboration_with_r48(self):
        oauth = export_oauth_agent_result(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            state_validation="ABSENT_OBSERVED",
        )
        collaboration = self._collaboration(oauth)
        categories = {
            agent["agent_category"]
            for agent in collaboration["participating_agents"]
        }
        self.assertEqual(categories, {"OAUTH", "CVE_RESEARCH"})
        first = json.dumps(collaboration, sort_keys=True)
        second = json.dumps(self._collaboration(oauth), sort_keys=True)
        self.assertEqual(first, second)

    def test_r43_collaboration_with_r49(self):
        api = export_api_security_agent_result(
            api_type="REST",
            api_authentication="ABSENT_OBSERVED",
        )
        collaboration = self._collaboration(api)
        categories = {
            agent["agent_category"]
            for agent in collaboration["participating_agents"]
        }
        self.assertEqual(categories, {"RECON", "CVE_RESEARCH"})
        first = json.dumps(collaboration, sort_keys=True)
        second = json.dumps(self._collaboration(api), sort_keys=True)
        self.assertEqual(first, second)

    def test_r44_feedback_compatibility(self):
        evaluation = evaluate_agent_result(weakness_result())
        event = build_research_feedback_event(
            evaluation_result=evaluation
        )
        self.assertEqual(event["source_category"], "CVE_RESEARCH")
        classifications = classify_research_feedback_events([event])
        self.assertEqual(len(classifications), 1)
        self.assertEqual(classifications[0]["subject"], "CVE_RESEARCH")
        signals = extract_learning_signals(classifications)
        self.assertEqual(len(signals), 1)

    def test_r44_missing_provenance_example(self):
        event = build_research_feedback_event(
            source_agent="sa-" + "a" * 16,
            source_category="CVE_RESEARCH",
            outcome_type="QUALITY_OBSERVATION",
            observed_issue="ISSUE_MISSING_PROVENANCE",
        )
        classifications = classify_research_feedback_events([event])
        self.assertEqual(
            classifications[0]["classification"], "PROVENANCE_ISSUE"
        )

    def test_r44_weak_evidence_example(self):
        event = build_research_feedback_event(
            source_agent="sa-" + "a" * 16,
            source_category="CVE_RESEARCH",
            outcome_type="EVIDENCE_OBSERVATION",
            observed_issue="ISSUE_MISSING_EVIDENCE_REQUIREMENT",
        )
        classifications = classify_research_feedback_events([event])
        signals = extract_learning_signals(classifications)
        self.assertEqual(
            signals[0]["signal_type"], "REQUIRE_MORE_EVIDENCE"
        )

    def test_r45_advisory_compatibility(self):
        evaluation = evaluate_agent_result(weakness_result())
        event = build_research_feedback_event(
            evaluation_result=evaluation
        )
        signals = extract_learning_signals(
            classify_research_feedback_events([event])
        )
        advisory = export_llm_advisory(
            evaluation_result=evaluation,
            learning_signals=signals,
        )
        self.assertEqual(advisory["validation_state"], "PASS")
        self.assertIs(advisory["research_only"], True)
        self.assertIn(
            {"layer": "R42", "reference": "r42-5"},
            advisory["source_refs"],
        )
        self.assertNotEqual(advisory["summary"], "")
        self.assertEqual(advisory["safety_state"], "PASS")

    def test_forbidden_payload_secret_or_attack_output(self):
        serialized = json.dumps(
            {**weakness_result(), **control_result()},
            sort_keys=True,
        ).lower()
        for token in FORBIDDEN_OUTPUT_TOKENS:
            self.assertNotIn(token.lower(), serialized)
        self.assertNotIn("cve-2026-", serialized)
        self.assertNotIn("https://", serialized)

    def test_result_limitations(self):
        result = export_cve_research_agent_result()
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_CVE_LOOKUP",
            "NO_REFERENCE_RETRIEVAL",
            "NO_EXPLOIT_RETRIEVAL",
            "NO_VULNERABILITY_REPRODUCTION",
            "NO_PAYLOAD_GENERATION",
            "NO_SCANNER_EXECUTION",
            "NO_SECRET_EXTRACTION",
            "NO_VULNERABILITY_CONFIRMATION",
            "HYPOTHESIS_ONLY",
            "EVIDENCE_REQUIRED",
        ):
            self.assertIn(limitation, result["limitations"])

    def test_r38_result_projection(self):
        projection = cve_research_agent_result_to_r38(weakness_result())
        self.assertEqual(projection["status"], "COMPLETED")
        self.assertEqual(
            projection["findings_summary"], "HYPOTHESES_RECORDED"
        )
        self.assertEqual(
            projection["evidence_summary"], "EVIDENCE_SUFFICIENT"
        )
        self.assertEqual(projection["confidence"], "HIGH")
        self.assertIs(projection["research_only"], True)

    def test_deterministic_serialization(self):
        first = json.dumps(weakness_result(), sort_keys=True)
        second = json.dumps(weakness_result(), sort_keys=True)
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())
        self.assertNotIn("runtime_id", first.lower())

    def test_repeated_execution_equality(self):
        runs = [needs_evidence_result() for _ in range(3)]
        first = json.dumps(runs[0], sort_keys=True)
        for run in runs[1:]:
            self.assertEqual(json.dumps(run, sort_keys=True), first)

    def test_json_serializable(self):
        self.assertIsInstance(
            json.loads(json.dumps(weakness_result())), dict
        )

    def test_result_model_rejects_bad_values_and_extra(self):
        base = weakness_result()
        with self.assertRaises(ValidationError):
            schema.CVEResearchAgentResultPlan(
                **{**base, "status": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchAgentResultPlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchAgentResultPlan(
                **{**base, "limitations": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchAgentResultPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.CVEResearchAgentResultPlan(
                **{**base, "exploit": "x"}
            )

    def test_result_model_forces_rule_version(self):
        plan = schema.CVEResearchAgentResultPlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r50-5")

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
