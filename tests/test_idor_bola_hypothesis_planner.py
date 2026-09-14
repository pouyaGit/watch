"""tests/test_idor_bola_hypothesis_planner.py — Stage R46.3 tests.

Deterministic, offline tests for the IDOR/BOLA hypothesis planner:

- direct object reference and missing authorization context hypotheses
- ownership, tenant and role boundary hypotheses
- authorization-control-present negative signal handling
- deterministic priority and calibration bounds
- observed behavior influence without fabrication
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

from ai.knowledge.idor_bola_context_analyzer import analyze_idor_bola_context
from ai.knowledge.idor_bola_hypothesis_planner import (
    plan_idor_bola_hypotheses,
)
from ai.schemas import idor_bola_hypothesis as schema
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.idor_bola_hypothesis import (
    SIGNAL_AUTHORIZATION_CONTROL_ABSENT,
    SIGNAL_AUTHORIZATION_CONTROL_UNKNOWN,
    SIGNAL_CONTEXT_UNKNOWN,
    SIGNAL_CROSS_TENANT_ACCESS_OBSERVED,
    SIGNAL_LOOKUP_BY_IDENTIFIER,
    SIGNAL_OWNER_RECORDED,
    SIGNAL_OWNERSHIP_CHECK_PRESENT,
    SIGNAL_ROLE_RECORDED,
    SIGNAL_ROUTE_RESOURCE,
    SIGNAL_TENANT_RECORDED,
)


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


def hypotheses_for(**context):
    return plan_idor_bola_hypotheses(
        analyze_idor_bola_context(**context)
    )


def types_of(hypotheses):
    return [entry["hypothesis_type"] for entry in hypotheses]


def by_type(hypotheses, hypothesis_type):
    return [
        entry
        for entry in hypotheses
        if entry["hypothesis_type"] == hypothesis_type
    ]


PRIORITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


class TestIDORBOLAHypothesisPlanner(unittest.TestCase):
    def test_direct_object_reference_detection(self):
        hypotheses = hypotheses_for(
            object_reference="QUERY_PARAMETER",
            object_lookup="LOOKUP_BY_IDENTIFIER",
        )
        types = types_of(hypotheses)
        self.assertIn("OBJECT_LEVEL_AUTHORIZATION_GAP", types)
        self.assertIn("DIRECT_OBJECT_REFERENCE", types)
        self.assertIn("MISSING_AUTHORIZATION_CONTEXT", types)
        direct = by_type(hypotheses, "DIRECT_OBJECT_REFERENCE")[0]
        self.assertIn(SIGNAL_LOOKUP_BY_IDENTIFIER,
                      direct["supporting_signals"])
        self.assertIn(SIGNAL_AUTHORIZATION_CONTROL_UNKNOWN,
                      direct["supporting_signals"])

    def test_missing_authorization_evidence(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            authorization_control="AUTHORIZATION_ABSENT",
        )
        types = types_of(hypotheses)
        self.assertIn("MISSING_AUTHORIZATION_CONTEXT", types)
        missing = by_type(
            hypotheses, "MISSING_AUTHORIZATION_CONTEXT"
        )[0]
        self.assertIn(
            SIGNAL_AUTHORIZATION_CONTROL_ABSENT,
            missing["supporting_signals"],
        )

    def test_ownership_boundary_hypothesis(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            ownership_relationship="OWNER_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
        )
        ownership = by_type(hypotheses, "OWNERSHIP_BOUNDARY_GAP")
        self.assertEqual(len(ownership), 1)
        self.assertIn(
            SIGNAL_OWNER_RECORDED, ownership[0]["supporting_signals"]
        )

    def test_tenant_isolation_hypothesis(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            tenant_boundary="TENANT_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
        )
        tenant = by_type(hypotheses, "TENANT_ISOLATION_GAP")
        self.assertEqual(len(tenant), 1)
        self.assertIn(
            SIGNAL_TENANT_RECORDED, tenant[0]["supporting_signals"]
        )

    def test_role_boundary_hypothesis(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            role_boundary="ROLE_RECORDED",
            route_context="RESOURCE_ROUTE",
        )
        role = by_type(hypotheses, "ROLE_BOUNDARY_GAP")
        self.assertEqual(len(role), 1)
        self.assertIn(
            SIGNAL_ROLE_RECORDED, role[0]["supporting_signals"]
        )
        self.assertIn(
            SIGNAL_ROUTE_RESOURCE, role[0]["supporting_signals"]
        )

    def test_authorization_control_present(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            ownership_relationship="OWNER_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
            authorization_control="OWNERSHIP_CHECK_PRESENT",
            authorization_location="SERVER_SIDE",
        )
        control = by_type(hypotheses, "AUTHORIZATION_CONTROL_PRESENT")
        self.assertEqual(len(control), 1)
        self.assertIn(
            SIGNAL_OWNERSHIP_CHECK_PRESENT,
            control[0]["supporting_signals"],
        )
        self.assertEqual(control[0]["priority"], "LOW")

    def test_negative_signal_reduces_priority_without_erasing(self):
        without_control = hypotheses_for(
            object_reference="PATH_PARAMETER",
            resource_type="ORDER",
            identifier_type="SEQUENTIAL_INTEGER",
            tenant_boundary="TENANT_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
            authorization_control="AUTHORIZATION_ABSENT",
        )
        with_control = hypotheses_for(
            object_reference="PATH_PARAMETER",
            resource_type="ORDER",
            identifier_type="SEQUENTIAL_INTEGER",
            tenant_boundary="TENANT_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
            authorization_control="TENANT_AUTHORIZATION_PRESENT",
            authorization_location="SERVER_SIDE",
        )
        gap_without = by_type(
            without_control, "TENANT_ISOLATION_GAP"
        )[0]
        gap_with = by_type(with_control, "TENANT_ISOLATION_GAP")
        self.assertEqual(len(gap_with), 1)
        self.assertEqual(gap_with[0]["priority"], "LOW")
        self.assertGreater(
            PRIORITY_ORDER[gap_without["priority"]],
            PRIORITY_ORDER[gap_with[0]["priority"]],
        )
        self.assertTrue(
            by_type(with_control, "AUTHORIZATION_CONTROL_PRESENT")
        )

    def test_insufficient_context(self):
        hypotheses = plan_idor_bola_hypotheses(analyze_idor_bola_context())
        self.assertEqual(len(hypotheses), 1)
        self.assertEqual(hypotheses[0]["hypothesis_type"], "UNKNOWN")
        self.assertEqual(hypotheses[0]["priority"], "UNKNOWN")
        self.assertIn(
            SIGNAL_CONTEXT_UNKNOWN,
            hypotheses[0]["supporting_signals"],
        )
        self.assertIn(
            "INSUFFICIENT_CONTEXT", hypotheses[0]["limitations"]
        )

    def test_priority_is_closed_and_deterministic(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            ownership_relationship="OWNER_RECORDED",
            tenant_boundary="TENANT_RECORDED",
            role_boundary="ROLE_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
            authorization_control="AUTHORIZATION_ABSENT",
            route_context="RESOURCE_ROUTE",
        )
        for entry in hypotheses:
            self.assertIn(entry["priority"], CONFIDENCE_LEVELS)
            self.assertEqual(entry["confidence"], entry["priority"])
            self.assertIn(entry["hypothesis_type"], schema.HYPOTHESIS_TYPES)

    def test_observed_behavior_increases_gap_priority(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            tenant_boundary="TENANT_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
            authorization_control="POLICY_ENFORCEMENT_PRESENT",
            authorization_location="SERVER_SIDE",
            authorization_behavior="CROSS_TENANT_ACCESS_OBSERVED",
        )
        tenant = by_type(hypotheses, "TENANT_ISOLATION_GAP")[0]
        self.assertEqual(tenant["priority"], "MEDIUM")
        self.assertIn(
            SIGNAL_CROSS_TENANT_ACCESS_OBSERVED,
            tenant["supporting_signals"],
        )

    def test_observed_behavior_not_fabricated(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            authorization_control="AUTHORIZATION_ABSENT",
        )
        serialized = json.dumps(hypotheses, sort_keys=True)
        self.assertNotIn("CROSS_USER_ACCESS_OBSERVED", serialized)
        self.assertNotIn("CROSS_TENANT_ACCESS_OBSERVED", serialized)

    def test_hypotheses_are_canonical_ordered(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            ownership_relationship="OWNER_RECORDED",
            tenant_boundary="TENANT_RECORDED",
            role_boundary="ROLE_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
            authorization_control="AUTHORIZATION_ABSENT",
            route_context="RESOURCE_ROUTE",
        )
        positions = [
            schema.HYPOTHESIS_TYPES.index(entry["hypothesis_type"])
            for entry in hypotheses
        ]
        self.assertEqual(positions, sorted(positions))

    def test_hypothesis_limitations(self):
        hypotheses = hypotheses_for(
            object_reference="PATH_PARAMETER",
            authorization_control="AUTHORIZATION_ABSENT",
        )
        for entry in hypotheses:
            for limitation in (
                "NO_EXPLOIT_CLAIM",
                "NO_VULNERABILITY_CONFIRMATION",
                "NO_AUTHORIZATION_BYPASS_CLAIM",
                "HYPOTHESIS_ONLY",
                "EVIDENCE_REQUIRED",
            ):
                self.assertIn(limitation, entry["limitations"])

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "hypothesis_type": "DIRECT_OBJECT_REFERENCE",
            "supporting_signals": [SIGNAL_LOOKUP_BY_IDENTIFIER],
            "confidence": "LOW",
            "priority": "LOW",
            "limitations": ["NO_EXPLOIT_CLAIM"],
        }
        with self.assertRaises(ValidationError):
            schema.IDORBOLAHypothesisPlan(
                **{**base, "hypothesis_type": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAHypothesisPlan(
                **{**base, "supporting_signals": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAHypothesisPlan(
                **{**base, "priority": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAHypothesisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAHypothesisPlan(**{**base, "payload": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.IDORBOLAHypothesisPlan(
            hypothesis_type="UNKNOWN", rule_version="r99-9"
        )
        self.assertEqual(plan.rule_version, "r46-3")

    def test_deterministic_serialization(self):
        context = analyze_idor_bola_context(
            object_reference="PATH_PARAMETER",
            ownership_relationship="OWNER_RECORDED",
            authorization_control="AUTHORIZATION_ABSENT",
        )
        first = json.dumps(
            plan_idor_bola_hypotheses(context), sort_keys=True
        )
        second = json.dumps(
            plan_idor_bola_hypotheses(context), sort_keys=True
        )
        self.assertEqual(first, second)

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
