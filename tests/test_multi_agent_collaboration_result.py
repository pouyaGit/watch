"""tests/test_multi_agent_collaboration_result.py — Stage R43.5 tests.

Deterministic, offline tests for the unified collaboration result:

- full result contract, participation (R39/R40/R41), attribution
- fixed ranking weights, factor model and safety boundary
- evaluation-aware ranking (present, missing, invalid)
- governance/provenance/shared-context summaries
- unsafe input preservation and forbidden-claim surfacing
- determinism (identical JSON, no timestamp/uuid)
- R43 AST safety scan and backend integration decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.multi_agent_collaboration_export import (
    export_multi_agent_collaboration,
)
from ai.knowledge.research_governance_export import (
    export_research_governance,
)
from ai.knowledge.sqli_agent_result_export import (
    export_sqli_agent_result,
)
from ai.knowledge.ssrf_agent_result_export import (
    export_ssrf_agent_result,
)
from ai.knowledge.xss_agent_identity import plan_xss_agent_identity
from ai.knowledge.xss_agent_result_export import export_xss_agent_result
from ai.schemas import multi_agent_collaboration_result as schema
from ai.schemas.multi_agent_collaboration_result import (
    RANKING_WEIGHTS,
    TOTAL_RANKING_WEIGHT,
)


ROOT = Path(__file__).resolve().parents[1]

R43_MODULES = (
    "ai/schemas/multi_agent_collaboration_input.py",
    "ai/schemas/shared_research_context.py",
    "ai/schemas/hypothesis_correlation.py",
    "ai/schemas/collaboration_evidence.py",
    "ai/schemas/collaboration_conflict.py",
    "ai/schemas/multi_agent_collaboration_result.py",
    "ai/knowledge/multi_agent_collaboration_input.py",
    "ai/knowledge/shared_research_context.py",
    "ai/knowledge/hypothesis_correlator.py",
    "ai/knowledge/collaboration_evidence_merger.py",
    "ai/knowledge/collaboration_conflict_analyzer.py",
    "ai/knowledge/multi_agent_collaboration_export.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "asyncio", "threading", "multiprocessing", "concurrent",
    "importlib", "ctypes", "shutil", "ssl", "os", "dns", "selenium",
    "playwright", "pyppeteer", "paramiko", "sqlite3", "sqlalchemy",
    "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap", "nuclei",
    "curl", "pycurl",
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


def xss_participant():
    identity = plan_xss_agent_identity(maturity="RESEARCH")
    wrapped = {
        "specialist_result": export_xss_agent_result(
            input_location="QUERY",
            output_context="HTML",
            reflection_state="REFLECTED",
            encoding_state="NONE_OBSERVED",
            framework_context="GENERIC",
            governance_plan=export_research_governance(),
        ),
        "agent_id": identity["agent_id"],
        "agent_category": "XSS",
    }
    return wrapped, identity


def ssrf_participant():
    return export_ssrf_agent_result(
        input_location="QUERY",
        url_handling="FULL_URL",
        server_side_fetch="OBSERVED",
        protocol_context="HTTPS",
        redirect_behavior="FOLLOWED",
        hostname_validation="ABSENT",
        ip_validation="ABSENT",
        allowlist_behavior="ABSENT",
        encoding_behavior="NORMALIZED",
        governance_plan=export_research_governance(),
    )


def sqli_participant():
    return export_sqli_agent_result(
        input_location="QUERY",
        parameter_type="IDENTIFIER",
        data_flow="RAW_QUERY",
        query_context="ORDER_BY",
        database_context="MYSQL",
        input_handling="CONCATENATED",
        type_handling="NONE_OBSERVED",
        error_behavior="DATABASE_ERROR_OBSERVED",
        behavioral_signal="TIMING_RELEVANT",
        governance_plan=export_research_governance(),
    )


def mixed_collaboration():
    wrapped, identity = xss_participant()
    ssrf = ssrf_participant()
    sqli = sqli_participant()
    evaluations = [
        evaluate_agent_result(
            wrapped["specialist_result"],
            agent_id=identity["agent_id"],
            agent_category="XSS",
        ),
        evaluate_agent_result(ssrf),
        evaluate_agent_result(sqli),
    ]
    return export_multi_agent_collaboration(
        [wrapped, ssrf, sqli], evaluation_results=evaluations
    )


class TestMultiAgentCollaborationResult(unittest.TestCase):
    def test_key_set_is_exact(self):
        result = export_multi_agent_collaboration([ssrf_participant()])
        self.assertEqual(
            set(result.keys()),
            {"rule_version", "collaboration_rule_version",
             "collaboration_id", "participating_agents",
             "hypothesis_groups", "merged_evidence", "conflicts",
             "collaboration_rankings", "shared_context_summary",
             "governance_summary", "provenance_summary",
             "collaboration_diagnostics", "deterministic",
             "research_only", "limitations"},
        )

    def test_fixed_weights(self):
        self.assertEqual(
            RANKING_WEIGHTS,
            {
                "SPECIALIST_CONFIDENCE": 20,
                "HYPOTHESIS_PRIORITY": 20,
                "EVALUATION_QUALITY": 25,
                "EVIDENCE_COMPLETENESS": 10,
                "PROVENANCE_COMPLETENESS": 5,
                "GOVERNANCE_STATE": 5,
                "SAFETY_STATE": 15,
            },
        )
        self.assertEqual(TOTAL_RANKING_WEIGHT, 100)

    def test_mixed_specialist_participation(self):
        result = mixed_collaboration()
        categories = [
            agent["agent_category"]
            for agent in result["participating_agents"]
        ]
        self.assertEqual(categories, ["XSS", "SSRF", "SQLI"])
        self.assertEqual(len(result["collaboration_rankings"]), 3)
        self.assertTrue(result["hypothesis_groups"])
        self.assertTrue(result["merged_evidence"]["evidence_items"])
        self.assertTrue(
            all(item["source_agents"]
                for item in result["merged_evidence"]["evidence_items"])
        )

    def test_ranking_attribution(self):
        result = mixed_collaboration()
        for ranking in result["collaboration_rankings"]:
            self.assertTrue(ranking["agent_id"])
            self.assertIn(
                ranking["agent_category"], ("XSS", "SSRF", "SQLI")
            )
            self.assertGreaterEqual(ranking["rank"], 1)

    def test_ranking_score_matches_fixed_weights(self):
        result = mixed_collaboration()
        for ranking in result["collaboration_rankings"]:
            if ranking["safety_state"] != "PASS":
                continue
            weighted = sum(
                ranking["factors"][factor] * RANKING_WEIGHTS[factor]
                for factor in RANKING_WEIGHTS
            )
            expected = (
                weighted + (TOTAL_RANKING_WEIGHT // 2)
            ) // TOTAL_RANKING_WEIGHT
            self.assertEqual(ranking["priority_score"], expected)

    def test_evaluation_aware_ranking(self):
        wrapped, identity = xss_participant()
        ssrf = ssrf_participant()
        evaluation = evaluate_agent_result(ssrf)
        result = export_multi_agent_collaboration(
            [wrapped, ssrf], evaluation_results=[evaluation]
        )
        rankings = {
            ranking["agent_category"]: ranking
            for ranking in result["collaboration_rankings"]
        }
        self.assertIs(
            rankings["SSRF"]["evaluation_present"], True
        )
        self.assertEqual(
            rankings["SSRF"]["factors"]["EVALUATION_QUALITY"],
            evaluation["overall_score"],
        )
        self.assertIs(
            rankings["XSS"]["evaluation_present"], False
        )
        self.assertEqual(
            rankings["XSS"]["factors"]["EVALUATION_QUALITY"], 40
        )

    def test_missing_evaluation_visible(self):
        result = export_multi_agent_collaboration([ssrf_participant()])
        ranking = result["collaboration_rankings"][0]
        self.assertIs(ranking["evaluation_present"], False)
        self.assertEqual(
            ranking["factors"]["EVALUATION_QUALITY"], 40
        )

    def test_invalid_evaluation_diagnostic(self):
        result = export_multi_agent_collaboration(
            [ssrf_participant()], evaluation_results=["nope"]
        )
        codes = [
            entry["diagnostic_code"]
            for entry in result["collaboration_diagnostics"]
        ]
        self.assertIn("INVALID_EVALUATION_RESULT", codes)

    def test_safety_boundary_ranking(self):
        unsafe = sqli_participant()
        unsafe["research_only"] = False
        safe = ssrf_participant()
        result = export_multi_agent_collaboration([unsafe, safe])
        rankings = result["collaboration_rankings"]
        unsafe_entry = [
            entry for entry in rankings
            if entry["agent_category"] == "SQLI"
        ][0]
        safe_entry = [
            entry for entry in rankings
            if entry["agent_category"] == "SSRF"
        ][0]
        self.assertEqual(unsafe_entry["safety_state"], "FAILED")
        self.assertEqual(unsafe_entry["safety_bucket"], 2)
        self.assertLessEqual(unsafe_entry["priority_score"], 39)
        self.assertGreater(
            safe_entry["rank"], 0
        )
        self.assertLess(safe_entry["rank"], unsafe_entry["rank"])

    def test_safety_conflict_surfaced(self):
        unsafe = sqli_participant()
        unsafe["research_only"] = False
        safe = ssrf_participant()
        result = export_multi_agent_collaboration([unsafe, safe])
        safety = [
            entry for entry in result["conflicts"]
            if entry["conflict_type"] == "SAFETY_CONFLICT"
        ]
        self.assertTrue(safety)
        self.assertEqual(safety[0]["resolution_state"], "UNRESOLVED")

    def test_forbidden_confirmation_claim_surfaced(self):
        claimed = sqli_participant()
        claimed["hypotheses"][0]["limitations"] = list(
            claimed["hypotheses"][0]["limitations"]
        ) + ["VULNERABILITY_CONFIRMED"]
        result = export_multi_agent_collaboration([claimed])
        codes = [
            (
                entry["conflict_type"],
                entry["resolution_state"],
            )
            for entry in result["conflicts"]
        ]
        self.assertIn(("SAFETY_CONFLICT", "UNRESOLVED"), codes)
        ranking = result["collaboration_rankings"][0]
        self.assertEqual(ranking["safety_state"], "FAILED")
        blob = json.dumps(result).lower()
        # The unsafe input claim is preserved with attribution, never
        # normalized into a safe claim; the result must not assert success.
        for marker in (
            "exploit_success", "target_compromised", "attack_executed"
        ):
            self.assertNotIn(marker, blob)

    def test_governance_summary(self):
        result = mixed_collaboration()
        summary = result["governance_summary"]
        self.assertIn(
            summary["governance_state"],
            ("CONSISTENT_REFERENCED", "MIXED", "UNKNOWN"),
        )
        self.assertTrue(summary["referenced_agents"])

    def test_governance_never_upgraded(self):
        ssrf = ssrf_participant()
        ssrf["governance_reference"] = {
            "rule_version": "",
            "ready": False,
            "provenance_state": "UNKNOWN",
            "trace_state": "UNKNOWN",
            "audit_state": "UNKNOWN",
            "explanation_state": "UNKNOWN",
            "reference_state": "UNKNOWN",
        }
        result = export_multi_agent_collaboration([ssrf])
        summary = result["governance_summary"]
        self.assertEqual(summary["governance_state"], "UNKNOWN")
        self.assertEqual(summary["referenced_agents"], [])
        self.assertTrue(summary["unknown_agents"])

    def test_provenance_summary(self):
        from ai.knowledge.security_agent_input_validator import (
            validate_security_agent_input,
        )

        bounded = validate_security_agent_input(
            research_context={"a": 1},
            memory_context={"b": 2},
        )
        ssrf = export_ssrf_agent_result(security_agent_input=bounded)
        result = export_multi_agent_collaboration([ssrf])
        summary = result["provenance_summary"]
        self.assertEqual(
            summary["source_layers"], ["REASONING", "MEMORY"]
        )
        self.assertEqual(summary["provenance_state"], "PARTIAL")
        self.assertTrue(summary["partial_agents"])

    def test_shared_context_summary(self):
        result = export_multi_agent_collaboration(
            [ssrf_participant()],
            shared_context={
                "asset_reference": "asset-1",
                "application_context": {"framework": "django"},
                "source_layers": ["REASONING"],
            },
        )
        summary = result["shared_context_summary"]
        self.assertIs(summary["asset_reference_present"], True)
        self.assertEqual(summary["blocks_present"],
                         ["application_context"])
        self.assertEqual(summary["source_layers"], ["REASONING"])

    def test_unknown_category_participant(self):
        result = export_multi_agent_collaboration([{}])
        self.assertEqual(
            result["participating_agents"][0]["agent_category"],
            "UNKNOWN",
        )
        codes = [
            entry["diagnostic_code"]
            for entry in result["collaboration_diagnostics"]
        ]
        self.assertIn("UNKNOWN_AGENT_CATEGORY", codes)

    def test_result_limitations(self):
        result = export_multi_agent_collaboration([ssrf_participant()])
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_EVIDENCE_COLLECTED",
            "NO_VULNERABILITY_CONFIRMATION",
            "NO_AGENTS_EXECUTED",
            "COLLABORATION_QUALITY_ONLY",
        ):
            self.assertIn(limitation, result["limitations"])
        self.assertIs(result["deterministic"], True)
        self.assertIs(result["research_only"], True)

    def test_determinism(self):
        first = mixed_collaboration()
        runs = [mixed_collaboration() for _ in range(3)]
        reference = json.dumps(first, sort_keys=True)
        for run in runs:
            self.assertEqual(
                json.dumps(run, sort_keys=True), reference
            )
        blob = reference.lower()
        self.assertNotIn("timestamp", blob)
        self.assertNotIn("uuid", blob)
        self.assertNotIn("runtime_id", blob)

    def test_json_serializable(self):
        result = mixed_collaboration()
        self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R43_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("multi_agent_collaboration", backend_source)
        self.assertNotIn("export_multi_agent_collaboration", backend_source)

    def test_schema_rejects_bad_values_and_extra(self):
        with self.assertRaises(ValidationError):
            schema.MultiAgentCollaborationResultPlan(unexpected="x")
        with self.assertRaises(ValidationError):
            schema.MultiAgentCollaborationResultPlan(
                deterministic=False
            )
        with self.assertRaises(ValidationError):
            schema.MultiAgentCollaborationResultPlan(research_only=False)
        with self.assertRaises(ValidationError):
            schema.CollaborationRankingPlan(priority_rating="PERFECT")
        with self.assertRaises(ValidationError):
            schema.CollaborationRankingPlan(priority_score=101)

    def test_schema_forces_rule_versions(self):
        plan = schema.MultiAgentCollaborationResultPlan(
            rule_version="r99-9", collaboration_rule_version="r99-9"
        )
        self.assertEqual(plan.rule_version, "r43-6")
        self.assertEqual(plan.collaboration_rule_version, "r43-6")

    def test_exact_rule_version(self):
        result = export_multi_agent_collaboration([ssrf_participant()])
        self.assertEqual(result["rule_version"], "r43-6")
        self.assertEqual(result["collaboration_rule_version"], "r43-6")


if __name__ == "__main__":
    unittest.main(verbosity=2)
