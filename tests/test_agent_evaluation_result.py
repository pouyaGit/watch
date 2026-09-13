"""tests/test_agent_evaluation_result.py — Stage R42.5 tests.

Deterministic, offline tests for the agent evaluation result export:

- R38-compatible / specialist result evaluation (R39, R40, R41)
- result contract, dimension score consistency, ratings
- hard gates through the full pipeline
- determinism (identical JSON, scores, diagnostics, rating, rule version)
- R42 AST safety scan (no execution/network/database/LLM capability)
- backend integration decision (standalone evaluation layer)

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

from ai.knowledge.agent_evaluation_export import (
    evaluate_agent_result,
    export_agent_evaluation,
)
from ai.knowledge.sqli_agent_result_export import (
    export_sqli_agent_result,
)
from ai.knowledge.ssrf_agent_result_export import (
    export_ssrf_agent_result,
)
from ai.knowledge.xss_agent_identity import plan_xss_agent_identity
from ai.knowledge.xss_agent_result_export import export_xss_agent_result
from ai.schemas import agent_evaluation_result as schema
from ai.schemas.agent_evaluation_rule import EVALUATION_DIMENSIONS
from ai.schemas.agent_evaluation_score import (
    DIMENSION_WEIGHTS,
    EVALUATION_RATINGS,
    TOTAL_WEIGHT,
)


ROOT = Path(__file__).resolve().parents[1]

R42_MODULES = (
    "ai/schemas/agent_evaluation_input.py",
    "ai/schemas/agent_evaluation_rule.py",
    "ai/schemas/agent_evaluation_score.py",
    "ai/schemas/agent_evaluation_diagnostic.py",
    "ai/schemas/agent_evaluation_result.py",
    "ai/knowledge/agent_evaluation_input.py",
    "ai/knowledge/agent_evaluation_rules.py",
    "ai/knowledge/agent_evaluation_diagnostics.py",
    "ai/knowledge/agent_evaluation_scorer.py",
    "ai/knowledge/agent_evaluation_export.py",
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


def rich_ssrf_result():
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
    )


def rich_sqli_result():
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
    )


def rich_xss_result():
    return export_xss_agent_result(
        input_location="QUERY",
        output_context="HTML",
        reflection_state="REFLECTED",
        encoding_state="NONE_OBSERVED",
        framework_context="GENERIC",
    )


class TestAgentEvaluationResult(unittest.TestCase):
    def test_key_set_is_exact(self):
        result = evaluate_agent_result(rich_sqli_result())
        self.assertEqual(
            set(result.keys()),
            {"rule_version", "evaluation_rule_version",
             "evaluated_agent_id", "evaluated_agent_category",
             "evaluated_agent_rule_version",
             "evaluated_result_rule_version", "overall_score",
             "overall_rating", "dimension_scores", "diagnostics",
             "hard_gate_state", "safety_state", "applied_caps",
             "deterministic", "research_only", "limitations"},
        )

    def test_evaluates_r41_sqli_result(self):
        result = evaluate_agent_result(rich_sqli_result())
        self.assertEqual(result["evaluated_agent_category"], "SQLI")
        self.assertEqual(result["evaluated_result_rule_version"], "r41-5")
        self.assertEqual(result["overall_score"], 95)
        self.assertEqual(result["overall_rating"], "EXCELLENT")
        self.assertEqual(result["safety_state"], "PASS")
        self.assertEqual(result["hard_gate_state"], "PASS")
        self.assertIs(result["deterministic"], True)
        self.assertIs(result["research_only"], True)

    def test_evaluates_r40_ssrf_result(self):
        result = evaluate_agent_result(rich_ssrf_result())
        self.assertEqual(result["evaluated_agent_category"], "SSRF")
        self.assertEqual(result["evaluated_result_rule_version"], "r40-5")
        self.assertEqual(result["overall_score"], 95)
        self.assertEqual(result["overall_rating"], "EXCELLENT")

    def test_evaluates_r39_xss_result(self):
        identity = plan_xss_agent_identity(maturity="RESEARCH")
        rich = rich_xss_result()
        result = evaluate_agent_result(
            rich,
            agent_id=identity["agent_id"],
            agent_category="XSS",
        )
        self.assertEqual(result["evaluated_agent_category"], "XSS")
        self.assertEqual(result["evaluated_agent_id"],
                         identity["agent_id"])
        self.assertEqual(result["evaluated_result_rule_version"], "r39-5")
        self.assertIn(result["overall_rating"], ("GOOD", "EXCELLENT"))
        self.assertGreaterEqual(result["overall_score"], 80)

    def test_evaluates_default_specialist_results(self):
        for exporter, category in (
            (export_xss_agent_result, "UNKNOWN"),
            (export_ssrf_agent_result, "SSRF"),
            (export_sqli_agent_result, "SQLI"),
        ):
            result = evaluate_agent_result(exporter())
            self.assertEqual(
                result["evaluated_agent_category"], category
            )
            self.assertIn(result["overall_rating"], EVALUATION_RATINGS)
            self.assertGreaterEqual(result["overall_score"], 0)

    def test_evaluates_plain_r38_result(self):
        plain = {
            "rule_version": "r38-5",
            "agent_name": "agent",
            "status": "COMPLETED",
            "confidence": "HIGH",
            "findings_summary": "NO_FINDINGS",
            "evidence_summary": "EVIDENCE_NONE",
            "limitations": ["NO_EXECUTION_PERFORMED"],
            "research_only": True,
        }
        result = evaluate_agent_result(plain)
        self.assertEqual(result["evaluated_agent_category"], "UNKNOWN")
        self.assertEqual(result["evaluated_result_rule_version"], "r38-5")
        self.assertLessEqual(result["overall_score"], 59)

    def test_dimension_scores_are_complete_and_ordered(self):
        result = evaluate_agent_result(rich_sqli_result())
        self.assertEqual(
            [entry["dimension"] for entry in result["dimension_scores"]],
            list(EVALUATION_DIMENSIONS),
        )
        for entry in result["dimension_scores"]:
            self.assertGreaterEqual(entry["score"], 0)
            self.assertLessEqual(entry["score"], 100)
            self.assertEqual(
                entry["weight"], DIMENSION_WEIGHTS[entry["dimension"]]
            )
            self.assertIn(entry["status"], EVALUATION_RATINGS)

    def test_overall_score_matches_fixed_weights(self):
        result = evaluate_agent_result(rich_sqli_result())
        total = sum(
            entry["score"] * entry["weight"]
            for entry in result["dimension_scores"]
        )
        expected = (total + (TOTAL_WEIGHT // 2)) // TOTAL_WEIGHT
        self.assertEqual(result["overall_score"], min(expected, 100))

    def test_diagnostics_are_ordered_and_structured(self):
        result = evaluate_agent_result(export_xss_agent_result())
        positions = [
            EVALUATION_DIMENSIONS.index(entry["dimension"])
            for entry in result["diagnostics"]
        ]
        self.assertEqual(positions, sorted(positions))
        for entry in result["diagnostics"]:
            self.assertEqual(entry["rule_version"], "r42-4")
            self.assertTrue(entry["message"])
            self.assertTrue(entry["remediation_hint"])

    def test_determinism_of_full_evaluation(self):
        rich = rich_sqli_result()
        runs = [
            evaluate_agent_result(rich)
            for _ in range(3)
        ]
        first = json.dumps(runs[0], sort_keys=True)
        for run in runs[1:]:
            self.assertEqual(
                json.dumps(run, sort_keys=True), first
            )
        self.assertNotIn("timestamp", first.lower())
        self.assertEqual(runs[0]["rule_version"], "r42-5")
        self.assertEqual(
            runs[0]["evaluation_rule_version"], "r42-5"
        )

    def test_unknown_category(self):
        result = evaluate_agent_result(
            rich_ssrf_result(), agent_category="NOPE"
        )
        self.assertEqual(result["evaluated_agent_category"], "UNKNOWN")
        codes = [
            entry["diagnostic_code"] for entry in result["diagnostics"]
        ]
        self.assertIn("UNKNOWN_AGENT_CATEGORY", codes)
        structural = [
            entry for entry in result["dimension_scores"]
            if entry["dimension"] == "STRUCTURAL_VALIDITY"
        ][0]
        self.assertLess(structural["score"], 100)
        self.assertLessEqual(result["overall_score"], 90)

    def test_research_only_false_fails_safety(self):
        bad = rich_sqli_result()
        bad["research_only"] = False
        result = evaluate_agent_result(bad)
        self.assertEqual(result["safety_state"], "FAILED")
        self.assertEqual(result["hard_gate_state"], "FAIL_SAFETY")
        self.assertEqual(result["overall_rating"], "CRITICAL")
        self.assertIn("FAIL_SAFETY", result["applied_caps"])
        codes = [
            entry["diagnostic_code"] for entry in result["diagnostics"]
        ]
        self.assertIn("RESEARCH_ONLY_FALSE", codes)

    def test_execution_claim_degrades_safety(self):
        bad = rich_sqli_result()
        bad["hypotheses"][0]["limitations"].append("PAYLOAD_SENT")
        result = evaluate_agent_result(bad)
        self.assertEqual(result["safety_state"], "DEGRADED")
        self.assertEqual(result["hard_gate_state"], "CEILING_SAFETY")
        self.assertLessEqual(result["overall_score"], 74)
        codes = [
            entry["diagnostic_code"] for entry in result["diagnostics"]
        ]
        self.assertIn("EXECUTION_CLAIM_DETECTED", codes)

    def test_confirmation_claim_fails_safety(self):
        bad = rich_sqli_result()
        bad["hypotheses"][0]["limitations"].append(
            "VULNERABILITY_CONFIRMED"
        )
        result = evaluate_agent_result(bad)
        self.assertEqual(result["safety_state"], "FAILED")
        self.assertEqual(result["hard_gate_state"], "FAIL_SAFETY")
        self.assertEqual(result["overall_rating"], "CRITICAL")
        codes = [
            entry["diagnostic_code"] for entry in result["diagnostics"]
        ]
        self.assertIn("VULNERABILITY_CONFIRMATION_CLAIM", codes)

    def test_result_limitations(self):
        result = evaluate_agent_result(rich_sqli_result())
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_EVIDENCE_COLLECTED",
            "NO_VULNERABILITY_CONFIRMATION",
            "QUALITY_EVALUATION_ONLY",
        ):
            self.assertIn(limitation, result["limitations"])

    def test_export_alias(self):
        rich = rich_ssrf_result()
        self.assertEqual(
            json.dumps(evaluate_agent_result(rich), sort_keys=True),
            json.dumps(export_agent_evaluation(rich), sort_keys=True),
        )

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R42_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("agent_evaluation", backend_source)
        self.assertNotIn("evaluate_agent_result", backend_source)

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "evaluated_agent_category": "SQLI",
            "overall_score": 80,
            "overall_rating": "GOOD",
            "hard_gate_state": "PASS",
            "safety_state": "PASS",
        }
        for key, value in (
            ("evaluated_agent_category", "NOPE"),
            ("overall_score", 101),
            ("overall_rating", "PERFECT"),
            ("hard_gate_state", "MAYBE"),
            ("safety_state", "MAYBE"),
        ):
            with self.assertRaises(ValidationError):
                schema.AgentEvaluationResultPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.AgentEvaluationResultPlan(**base, payload="x")

    def test_schema_forces_rule_versions_and_flags(self):
        plan = schema.AgentEvaluationResultPlan(
            rule_version="r99-9",
            evaluation_rule_version="r99-9",
            deterministic=True,
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r42-5")
        self.assertEqual(plan.evaluation_rule_version, "r42-5")
        with self.assertRaises(ValidationError):
            schema.AgentEvaluationResultPlan(
                deterministic=False
            )
        with self.assertRaises(ValidationError):
            schema.AgentEvaluationResultPlan(research_only=False)

    def test_exact_rule_version(self):
        result = evaluate_agent_result(rich_sqli_result())
        self.assertEqual(result["rule_version"], "r42-5")
        self.assertEqual(result["evaluation_rule_version"], "r42-5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
