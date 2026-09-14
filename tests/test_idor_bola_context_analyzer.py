"""tests/test_idor_bola_context_analyzer.py — Stage R46.2 tests.

Deterministic, offline tests for the IDOR/BOLA context analyzer:

- valid structured context and deterministic normalization
- malformed input degradation to UNKNOWN
- identifier exposure is not authorization evidence
- deterministic context confidence calibration and safety caps
- observed behavior preservation and no fabricated behavior
- schema validation and extra-field rejection
- R46 AST safety scan and standalone backend decision

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

from ai.knowledge.idor_bola_context_analyzer import (
    analyze_idor_bola_context,
    idor_bola_authorization_control_absent,
    idor_bola_authorization_control_present,
    idor_bola_authorization_control_unknown,
    idor_bola_boundary_context_count,
    idor_bola_context_confidence_of,
    idor_bola_cross_context_behavior_observed,
    idor_bola_object_reference_present,
)
from ai.schemas import idor_bola_context_analysis as schema


ROOT = Path(__file__).resolve().parents[1]

R46_MODULES = (
    "ai/schemas/idor_bola_agent_identity.py",
    "ai/schemas/idor_bola_context_analysis.py",
    "ai/schemas/idor_bola_hypothesis.py",
    "ai/schemas/idor_bola_evidence_plan.py",
    "ai/schemas/idor_bola_agent_result.py",
    "ai/schemas/idor_bola_agent.py",
    "ai/knowledge/idor_bola_agent_identity.py",
    "ai/knowledge/idor_bola_context_analyzer.py",
    "ai/knowledge/idor_bola_hypothesis_planner.py",
    "ai/knowledge/idor_bola_evidence_planner.py",
    "ai/knowledge/idor_bola_agent_result_export.py",
    "ai/knowledge/idor_bola_agent.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "asyncio", "threading", "multiprocessing", "concurrent",
    "importlib", "ctypes", "shutil", "ssl", "os", "dns", "selenium",
    "playwright", "pyppeteer", "paramiko", "sqlite3", "sqlalchemy",
    "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap", "nuclei",
    "curl", "pycurl", "openai", "ollama", "litellm", "anthropic",
    "openrouter",
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


def rich_context(**over):
    base = {
        "object_reference": "PATH_PARAMETER",
        "resource_type": "ORDER",
        "identifier_type": "SEQUENTIAL_INTEGER",
        "ownership_relationship": "OWNER_RECORDED",
        "tenant_boundary": "TENANT_RECORDED",
        "role_boundary": "ROLE_RECORDED",
        "authorization_control": "POLICY_ENFORCEMENT_PRESENT",
        "authorization_location": "SERVER_SIDE",
        "object_lookup": "LOOKUP_BY_IDENTIFIER",
        "authorization_behavior": "OWN_OBJECT_ONLY_OBSERVED",
        "route_context": "RESOURCE_ROUTE",
    }
    base.update(over)
    return base


class TestIDORBOLAContextAnalyzer(unittest.TestCase):
    def test_valid_context_analysis(self):
        analysis = analyze_idor_bola_context(**rich_context())
        self.assertEqual(analysis["rule_version"], "r46-2")
        self.assertEqual(analysis["object_reference"], "PATH_PARAMETER")
        self.assertEqual(analysis["resource_type"], "ORDER")
        self.assertEqual(
            analysis["identifier_type"], "SEQUENTIAL_INTEGER"
        )
        self.assertEqual(
            analysis["ownership_relationship"], "OWNER_RECORDED"
        )
        self.assertEqual(analysis["authorization_control"],
                         "POLICY_ENFORCEMENT_PRESENT")
        self.assertEqual(analysis["context_confidence"], "HIGH")
        self.assertIs(analysis["research_only"], True)

    def test_malformed_input_degrades_to_unknown(self):
        analysis = analyze_idor_bola_context(
            object_reference=42,
            resource_type=[],
            identifier_type={"x": 1},
            ownership_relationship="NOPE",
            authorization_control="EXPLOIT",
        )
        self.assertEqual(analysis["object_reference"], "UNKNOWN")
        self.assertEqual(analysis["resource_type"], "UNKNOWN")
        self.assertEqual(analysis["identifier_type"], "UNKNOWN")
        self.assertEqual(analysis["ownership_relationship"], "UNKNOWN")
        self.assertEqual(analysis["authorization_control"], "UNKNOWN")
        self.assertEqual(analysis["context_confidence"], "UNKNOWN")

    def test_deterministic_normalization(self):
        analysis = analyze_idor_bola_context(
            object_reference="path_parameter",
            authorization_control="ownership_check_present",
            object_lookup="lookup_by_identifier",
        )
        self.assertEqual(analysis["object_reference"], "PATH_PARAMETER")
        self.assertEqual(
            analysis["authorization_control"], "OWNERSHIP_CHECK_PRESENT"
        )
        self.assertEqual(
            analysis["object_lookup"], "LOOKUP_BY_IDENTIFIER"
        )

    def test_identifier_alone_is_not_authorization_evidence(self):
        analysis = analyze_idor_bola_context(
            object_reference="QUERY_PARAMETER",
            identifier_type="SEQUENTIAL_INTEGER",
        )
        self.assertNotEqual(analysis["context_confidence"], "HIGH")
        self.assertEqual(analysis["context_confidence"], "LOW")

    def test_lookup_alone_is_not_broken_authorization(self):
        analysis = analyze_idor_bola_context(
            object_reference="PATH_PARAMETER",
            object_lookup="LOOKUP_BY_IDENTIFIER",
        )
        self.assertNotEqual(analysis["context_confidence"], "HIGH")
        self.assertIn(
            analysis["context_confidence"], ("LOW", "MEDIUM")
        )

    def test_context_confidence_calibration(self):
        self.assertEqual(
            analyze_idor_bola_context()["context_confidence"], "UNKNOWN"
        )
        self.assertEqual(
            analyze_idor_bola_context(
                object_reference="PATH_PARAMETER"
            )["context_confidence"],
            "LOW",
        )
        self.assertEqual(
            analyze_idor_bola_context(
                object_reference="PATH_PARAMETER",
                identifier_type="SEQUENTIAL_INTEGER",
                object_lookup="LOOKUP_BY_IDENTIFIER",
                ownership_relationship="OWNER_RECORDED",
            )["context_confidence"],
            "LOW",
        )
        self.assertEqual(
            analyze_idor_bola_context(
                object_reference="PATH_PARAMETER",
                identifier_type="SEQUENTIAL_INTEGER",
                object_lookup="LOOKUP_BY_IDENTIFIER",
                ownership_relationship="OWNER_RECORDED",
                authorization_control="AUTHORIZATION_ABSENT",
            )["context_confidence"],
            "MEDIUM",
        )

    def test_safety_cap_without_server_side_evidence(self):
        client_side = rich_context(
            authorization_location="CLIENT_SIDE_ONLY"
        )
        self.assertEqual(
            analyze_idor_bola_context(**client_side)[
                "context_confidence"
            ],
            "MEDIUM",
        )
        absent = rich_context(authorization_control="AUTHORIZATION_ABSENT")
        self.assertEqual(
            analyze_idor_bola_context(**absent)["context_confidence"],
            "MEDIUM",
        )
        unknown = rich_context(authorization_control="UNKNOWN")
        self.assertEqual(
            analyze_idor_bola_context(**unknown)["context_confidence"],
            "MEDIUM",
        )

    def test_confidence_recompute_ignores_stored_value(self):
        analysis = analyze_idor_bola_context(**rich_context())
        tampered = dict(analysis, context_confidence="HIGH")
        tampered["authorization_control"] = "AUTHORIZATION_ABSENT"
        self.assertEqual(
            idor_bola_context_confidence_of(tampered), "MEDIUM"
        )

    def test_helpers(self):
        analysis = analyze_idor_bola_context(
            object_reference="PATH_PARAMETER",
            authorization_control="OWNERSHIP_CHECK_PRESENT",
            ownership_relationship="OWNER_RECORDED",
            tenant_boundary="TENANT_NOT_RECORDED",
        )
        self.assertTrue(idor_bola_object_reference_present(analysis))
        self.assertTrue(
            idor_bola_authorization_control_present(analysis)
        )
        self.assertFalse(
            idor_bola_authorization_control_absent(analysis)
        )
        self.assertFalse(
            idor_bola_authorization_control_unknown(analysis)
        )
        self.assertEqual(idor_bola_boundary_context_count(analysis), 2)
        self.assertFalse(
            idor_bola_cross_context_behavior_observed(analysis)
        )

    def test_observed_behavior_preserved_as_supplied(self):
        analysis = analyze_idor_bola_context(
            object_reference="PATH_PARAMETER",
            authorization_behavior="CROSS_USER_ACCESS_OBSERVED",
        )
        self.assertEqual(
            analysis["authorization_behavior"], "CROSS_USER_ACCESS_OBSERVED"
        )
        self.assertTrue(
            idor_bola_cross_context_behavior_observed(analysis)
        )

    def test_no_fabricated_observed_behavior(self):
        analysis = analyze_idor_bola_context(**rich_context())
        self.assertEqual(analysis["authorization_behavior"],
                         "OWN_OBJECT_ONLY_OBSERVED")
        default = analyze_idor_bola_context(object_reference="PATH_PARAMETER")
        self.assertEqual(default["authorization_behavior"], "UNKNOWN")
        self.assertNotIn(
            "CROSS_USER_ACCESS_OBSERVED",
            json.dumps(default, sort_keys=True),
        )
        self.assertNotIn(
            "CROSS_TENANT_ACCESS_OBSERVED",
            json.dumps(default, sort_keys=True),
        )

    def test_schema_rejects_bad_values_and_extra(self):
        base = analyze_idor_bola_context(**rich_context())
        for key, value in (
            ("object_reference", "NOPE"),
            ("resource_type", "NOPE"),
            ("identifier_type", "NOPE"),
            ("ownership_relationship", "NOPE"),
            ("tenant_boundary", "NOPE"),
            ("role_boundary", "NOPE"),
            ("authorization_control", "NOPE"),
            ("authorization_location", "NOPE"),
            ("object_lookup", "NOPE"),
            ("authorization_behavior", "NOPE"),
            ("route_context", "NOPE"),
            ("context_confidence", "NOPE"),
        ):
            with self.assertRaises(ValidationError):
                schema.IDORBOLAContextAnalysisPlan(
                    **{**base, key: value}
                )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAContextAnalysisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAContextAnalysisPlan(**{**base, "payload": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.IDORBOLAContextAnalysisPlan(
            **{**analyze_idor_bola_context(), "rule_version": "r99-9"}
        )
        self.assertEqual(plan.rule_version, "r46-2")

    def test_deterministic_serialization(self):
        first = json.dumps(
            analyze_idor_bola_context(**rich_context()), sort_keys=True
        )
        second = json.dumps(
            analyze_idor_bola_context(**rich_context()), sort_keys=True
        )
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R46_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("idor_bola", backend_source)
        self.assertNotIn("IDOR_BOLA", backend_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
