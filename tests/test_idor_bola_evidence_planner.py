"""tests/test_idor_bola_evidence_planner.py — Stage R46.4 tests.

Deterministic, offline tests for the IDOR/BOLA evidence planner:

- closed evidence vocabulary and per-hypothesis evidence mapping
- authorization evidence requirements are planning only, never collection
- deterministic planning state and confidence calibration
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
from ai.knowledge.idor_bola_evidence_planner import (
    HYPOTHESIS_EVIDENCE,
    plan_idor_bola_evidence,
)
from ai.knowledge.idor_bola_hypothesis_planner import (
    plan_idor_bola_hypotheses,
)
from ai.schemas import idor_bola_evidence_plan as schema
from ai.schemas.idor_bola_evidence_plan import (
    EVIDENCE_ACCESS_CONTROL_POLICY,
    EVIDENCE_AUTHORIZATION_CONTROL,
    EVIDENCE_CROSS_CONTEXT_ACCESS_BEHAVIOR,
    EVIDENCE_OBJECT_IDENTIFIER_CONTEXT,
    EVIDENCE_OBJECT_LOOKUP_CONTEXT,
    EVIDENCE_OBSERVED_AUTHORIZATION_BEHAVIOR,
    EVIDENCE_OWNERSHIP_RELATIONSHIP,
    EVIDENCE_ROLE_DEFINITION,
    EVIDENCE_ROUTE_CONTROLLER_CONTEXT,
    EVIDENCE_SERVER_SIDE_AUTHORIZATION,
    EVIDENCE_TENANT_BOUNDARY,
    EVIDENCE_UNKNOWN,
)
from ai.schemas.idor_bola_hypothesis import (
    HYPOTHESIS_TYPES,
    TYPE_AUTHORIZATION_CONTROL_PRESENT,
    TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP,
    TYPE_ROLE_BOUNDARY_GAP,
    TYPE_TENANT_ISOLATION_GAP,
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


class TestIDORBOLAEvidencePlanner(unittest.TestCase):
    def test_evidence_vocabulary_is_closed(self):
        self.assertEqual(len(schema.IDOR_BOLA_EVIDENCE_ITEMS), 12)
        self.assertEqual(
            schema.IDOR_BOLA_EVIDENCE_ITEMS[-1], EVIDENCE_UNKNOWN
        )

    def test_mapping_covers_every_hypothesis(self):
        self.assertEqual(
            set(HYPOTHESIS_EVIDENCE.keys()), set(HYPOTHESIS_TYPES)
        )

    def test_object_level_gap_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[
            TYPE_OBJECT_LEVEL_AUTHORIZATION_GAP
        ]
        for item in (
            EVIDENCE_AUTHORIZATION_CONTROL,
            EVIDENCE_OWNERSHIP_RELATIONSHIP,
            EVIDENCE_OBJECT_LOOKUP_CONTEXT,
            EVIDENCE_CROSS_CONTEXT_ACCESS_BEHAVIOR,
        ):
            self.assertIn(item, evidence)

    def test_tenant_isolation_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_TENANT_ISOLATION_GAP]
        for item in (
            EVIDENCE_TENANT_BOUNDARY,
            EVIDENCE_OBJECT_IDENTIFIER_CONTEXT,
            EVIDENCE_SERVER_SIDE_AUTHORIZATION,
            EVIDENCE_CROSS_CONTEXT_ACCESS_BEHAVIOR,
        ):
            self.assertIn(item, evidence)

    def test_role_boundary_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_ROLE_BOUNDARY_GAP]
        for item in (
            EVIDENCE_ROLE_DEFINITION,
            EVIDENCE_ROUTE_CONTROLLER_CONTEXT,
            EVIDENCE_SERVER_SIDE_AUTHORIZATION,
            EVIDENCE_OBSERVED_AUTHORIZATION_BEHAVIOR,
        ):
            self.assertIn(item, evidence)

    def test_authorization_control_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[
            TYPE_AUTHORIZATION_CONTROL_PRESENT
        ]
        for item in (
            EVIDENCE_AUTHORIZATION_CONTROL,
            EVIDENCE_ACCESS_CONTROL_POLICY,
            EVIDENCE_OWNERSHIP_RELATIONSHIP,
        ):
            self.assertIn(item, evidence)

    def test_unknown_context_plan(self):
        evidence = plan_idor_bola_evidence(analyze_idor_bola_context())
        self.assertEqual(evidence["evidence_items"], [EVIDENCE_UNKNOWN])
        self.assertEqual(evidence["evidence_state"], "UNKNOWN")
        self.assertEqual(evidence["confidence"], "UNKNOWN")
        self.assertIn(
            "INSUFFICIENT_CONTEXT", evidence["limitations"]
        )

    def test_partial_plan_for_typical_context(self):
        context = analyze_idor_bola_context(
            object_reference="PATH_PARAMETER",
            identifier_type="SEQUENTIAL_INTEGER",
            ownership_relationship="OWNER_RECORDED",
            object_lookup="LOOKUP_BY_IDENTIFIER",
            authorization_control="AUTHORIZATION_ABSENT",
        )
        evidence = plan_idor_bola_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        self.assertIn(
            EVIDENCE_AUTHORIZATION_CONTROL, evidence["evidence_items"]
        )
        self.assertIn(
            EVIDENCE_OWNERSHIP_RELATIONSHIP,
            evidence["evidence_items"],
        )

    def test_complete_plan_for_strong_context(self):
        context = analyze_idor_bola_context(**rich_context())
        self.assertEqual(context["context_confidence"], "HIGH")
        evidence = plan_idor_bola_evidence(context)
        self.assertEqual(evidence["evidence_state"], "COMPLETE")
        self.assertEqual(evidence["confidence"], "HIGH")
        self.assertNotIn(
            EVIDENCE_UNKNOWN, evidence["evidence_items"]
        )

    def test_explicit_hypotheses_are_respected(self):
        hypotheses = plan_idor_bola_hypotheses(
            analyze_idor_bola_context(**rich_context())
        )
        evidence = plan_idor_bola_evidence(
            analyze_idor_bola_context(**rich_context()), hypotheses
        )
        manual = plan_idor_bola_evidence(
            analyze_idor_bola_context(**rich_context()),
            [
                {
                    "hypothesis_type": TYPE_TENANT_ISOLATION_GAP,
                    "confidence": "LOW",
                    "priority": "LOW",
                }
            ],
        )
        self.assertEqual(
            manual["evidence_items"],
            list(HYPOTHESIS_EVIDENCE[TYPE_TENANT_ISOLATION_GAP]),
        )
        self.assertNotEqual(manual, evidence)

    def test_evidence_limitations(self):
        evidence = plan_idor_bola_evidence(analyze_idor_bola_context())
        for limitation in (
            "NO_COLLECTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_PAYLOAD_GENERATION",
            "NO_AUTHORIZATION_BYPASS",
            "EVIDENCE_REQUIRED",
        ):
            self.assertIn(limitation, evidence["limitations"])

    def test_schema_rejects_bad_values_and_extra(self):
        base = plan_idor_bola_evidence(analyze_idor_bola_context())
        with self.assertRaises(ValidationError):
            schema.IDORBOLAEvidencePlan(
                **{**base, "evidence_items": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAEvidencePlan(
                **{**base, "evidence_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAEvidencePlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAEvidencePlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAEvidencePlan(**{**base, "payload": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.IDORBOLAEvidencePlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r46-4")

    def test_deterministic_serialization(self):
        context = analyze_idor_bola_context(**rich_context())
        first = json.dumps(
            plan_idor_bola_evidence(context), sort_keys=True
        )
        second = json.dumps(
            plan_idor_bola_evidence(context), sort_keys=True
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
