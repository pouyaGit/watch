"""tests/test_security_agent_framework_export.py — Stage R38.7 tests.

Deterministic, offline tests for the security agent framework exporter:

- readiness gating (any UNKNOWN critical state prevents ready)
- end-to-end combination of identity, capability, input, lifecycle, result
  and registry contracts
- malformed and empty input handling
- static source scan: no execution-capable imports or calls
- JSON serialization, schema validation
- research_only always true, no attack automation behaviour

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import security_agent_framework_export as exporter
from ai.knowledge.security_agent_registry import STATIC_CATEGORIES
from ai.schemas import security_agent_capability as capability_schema
from ai.schemas import security_agent_framework_export as schema


ROOT = Path(__file__).resolve().parents[1]

R38_MODULES = (
    "ai/schemas/security_agent_identity.py",
    "ai/schemas/security_agent_capability.py",
    "ai/schemas/security_agent_input.py",
    "ai/schemas/security_agent_lifecycle.py",
    "ai/schemas/security_agent_result.py",
    "ai/schemas/security_agent_registry.py",
    "ai/schemas/security_agent_framework_export.py",
    "ai/knowledge/security_agent_identity.py",
    "ai/knowledge/security_agent_capability.py",
    "ai/knowledge/security_agent_input_validator.py",
    "ai/knowledge/security_agent_lifecycle.py",
    "ai/knowledge/security_agent_result_validator.py",
    "ai/knowledge/security_agent_registry.py",
    "ai/knowledge/security_agent_framework_export.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "asyncio", "threading", "multiprocessing", "concurrent",
    "importlib", "ctypes", "shutil", "ssl", "ftplib", "smtplib",
    "telnetlib", "os",
}

FORBIDDEN_CALLS = {"__import__", "eval", "exec", "compile", "open"}

FORBIDDEN_CALL_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "importlib.",
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


class TestSecurityAgentFrameworkExport(unittest.TestCase):
    def test_key_set_is_exact(self):
        plan = exporter.export_security_agent_framework()
        self.assertEqual(
            set(plan.keys()),
            {"rule_version", "ready", "identities", "capabilities",
             "input_contract", "lifecycle", "result_contract", "registry",
             "limitations", "research_only"},
        )

    def test_default_export_is_ready(self):
        plan = exporter.export_security_agent_framework()
        self.assertIs(plan["ready"], True)
        self.assertEqual(plan["lifecycle"]["lifecycle_state"], "VALID")
        self.assertEqual(plan["registry"]["registry_state"], "VALID")

    def test_default_components_cover_all_static_categories(self):
        plan = exporter.export_security_agent_framework()
        self.assertEqual(len(plan["identities"]), len(STATIC_CATEGORIES))
        self.assertEqual(len(plan["capabilities"]),
                         len(STATIC_CATEGORIES))
        self.assertEqual(
            [item["category"] for item in plan["identities"]],
            list(STATIC_CATEGORIES),
        )
        self.assertEqual(
            [item["agent_category"] for item in plan["capabilities"]],
            list(STATIC_CATEGORIES),
        )
        self.assertEqual(
            len(plan["registry"]["registered_agents"]),
            len(STATIC_CATEGORIES),
        )

    def test_placeholder_limitation_is_always_recorded(self):
        plan = exporter.export_security_agent_framework()
        self.assertIn("PLACEHOLDER_TEMPLATES", plan["limitations"])

    def test_ready_requires_identity(self):
        plan = exporter.export_security_agent_framework(
            identity_plans=[None, "not-a-plan"]
        )
        self.assertIs(plan["ready"], False)
        self.assertIn("UNKNOWN_IDENTITY", plan["limitations"])

    def test_ready_requires_capability(self):
        plan = exporter.export_security_agent_framework(
            capability_plans=[{"agent_category": "NOPE"}]
        )
        self.assertIs(plan["ready"], False)
        self.assertIn("UNKNOWN_CAPABILITY", plan["limitations"])

    def test_ready_requires_lifecycle(self):
        plan = exporter.export_security_agent_framework(
            lifecycle_plan={"current_state": "PLANNED",
                            "previous_state": "COMPLETED"}
        )
        self.assertIs(plan["ready"], False)
        self.assertIn("UNKNOWN_LIFECYCLE", plan["limitations"])

    def test_ready_requires_registry(self):
        plan = exporter.export_security_agent_framework(
            registry_plan={"registered_agents": []}
        )
        self.assertIs(plan["ready"], False)
        self.assertIn("UNKNOWN_REGISTRY", plan["limitations"])
        self.assertIn("NO_REGISTERED_AGENTS", plan["limitations"])

    def test_malformed_inputs_never_raise_and_are_not_ready(self):
        malformed = (
            {"identity_plans": [1, 2]},
            {"capability_plans": ["nope"]},
            {"lifecycle_plan": 42},
            {"lifecycle_plan": {}},
            {"registry_plan": 42},
            {"registry_plan": {}},
        )
        for kwargs in malformed:
            plan = exporter.export_security_agent_framework(**kwargs)
            self.assertIs(plan["ready"], False, repr(kwargs))
            self.assertIs(plan["research_only"], True)

    def test_empty_optional_plans_do_not_crash(self):
        plan = exporter.export_security_agent_framework(
            input_plan={}, result_plan={}
        )
        self.assertEqual(plan["input_contract"]["authorization_context"],
                         {})
        self.assertEqual(plan["result_contract"]["status"], "UNKNOWN")
        self.assertIs(plan["ready"], True)

    def test_prohibited_capabilities_always_explicit(self):
        plan = exporter.export_security_agent_framework()
        for item in plan["capabilities"]:
            allowed = set(item["allowed_capabilities"])
            prohibited = set(item["prohibited_capabilities"])
            self.assertEqual(allowed & prohibited, set())
            self.assertEqual(
                prohibited,
                set(capability_schema.PROHIBITED_CAPABILITIES),
            )

    def test_no_execution_content(self):
        plan = exporter.export_security_agent_framework()
        blob = json.dumps(plan).lower()
        for marker in (
            "http://", "https://", "fuzz", "nuclei", "sqlmap",
            "subprocess", "shell", "browser", "worker", "scheduler",
            "docker", "systemd", "timestamp", "plugin",
        ):
            self.assertNotIn(marker, blob)

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R38_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_deterministic_output(self):
        first = exporter.export_security_agent_framework()
        second = exporter.export_security_agent_framework()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = exporter.export_security_agent_framework()
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_everywhere(self):
        plan = exporter.export_security_agent_framework()
        self.assertIs(plan["research_only"], True)
        self.assertIs(plan["input_contract"]["research_only"], True)
        self.assertIs(plan["lifecycle"]["research_only"], True)
        self.assertIs(plan["result_contract"]["research_only"], True)
        self.assertIs(plan["registry"]["research_only"], True)
        for item in plan["identities"]:
            self.assertIs(item["research_only"], True)
        for item in plan["capabilities"]:
            self.assertIs(item["research_only"], True)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.SecurityAgentFrameworkExportPlan(
                ready=True,
                limitations=["NOT_A_CODE"],
            )
        with self.assertRaises(ValidationError):
            schema.SecurityAgentFrameworkExportPlan(
                ready=True, unexpected="x"
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.SecurityAgentFrameworkExportPlan(
            rule_version="r99-9", ready=False, research_only=True
        )
        self.assertEqual(plan.rule_version, "r38-7")
        with self.assertRaises(ValidationError):
            schema.SecurityAgentFrameworkExportPlan(
                ready=False, research_only=False
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            exporter.SECURITY_AGENT_FRAMEWORK_EXPORTER_RULE_VERSION,
            "r38-7",
        )
        self.assertEqual(
            exporter.export_security_agent_framework()["rule_version"],
            "r38-7",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
