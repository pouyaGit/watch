"""tests/test_xss_agent_result.py — Stage R39.5 tests.

Deterministic, offline tests for the XSS agent result export:

- R38 compatibility (status/confidence vocabularies, R38 result projection)
- R37 governance reference integration
- conservative status derivation
- serialization and input immutability
- malformed/empty input handling
- research_only always true, no payload or execution fields
- static source scan: no execution-capable imports or calls

No network, no DNS, no LLM, no subprocess, no browser, no payloads, no
target interaction, no Mongo writes, no persistence, no execution of any
kind.
"""
import ast
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import xss_agent_result_export as exporter
from ai.knowledge.research_governance_export import export_research_governance
from ai.knowledge.security_agent_input_validator import (
    validate_security_agent_input,
)
from ai.knowledge.xss_agent_identity import compute_xss_agent_id
from ai.schemas import security_agent_result as r38_result_schema
from ai.schemas import xss_agent_result as schema


ROOT = Path(__file__).resolve().parents[1]

R39_MODULES = (
    "ai/schemas/xss_agent_identity.py",
    "ai/schemas/xss_context_analysis.py",
    "ai/schemas/xss_hypothesis.py",
    "ai/schemas/xss_evidence_plan.py",
    "ai/schemas/xss_agent_result.py",
    "ai/knowledge/xss_agent_identity.py",
    "ai/knowledge/xss_context_analyzer.py",
    "ai/knowledge/xss_hypothesis_planner.py",
    "ai/knowledge/xss_evidence_planner.py",
    "ai/knowledge/xss_agent_result_export.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "asyncio", "threading", "multiprocessing", "concurrent",
    "importlib", "ctypes", "shutil", "ssl", "ftplib", "smtplib",
    "telnetlib", "os", "selenium", "playwright", "pyppeteer",
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


def rich_result(**over):
    kwargs = {
        "input_location": "QUERY",
        "output_context": "HTML",
        "reflection_state": "REFLECTED",
        "encoding_state": "NONE_OBSERVED",
        "framework_context": "GENERIC",
    }
    kwargs.update(over)
    return exporter.export_xss_agent_result(**kwargs)


class TestXSSAgentResult(unittest.TestCase):
    def test_key_set_is_exact(self):
        plan = exporter.export_xss_agent_result()
        self.assertEqual(
            set(plan.keys()),
            {"rule_version", "agent_name", "status", "context_analysis",
             "hypotheses", "evidence_plan", "confidence", "limitations",
             "governance_reference", "research_only"},
        )

    def test_r38_status_vocabulary_matches(self):
        self.assertEqual(
            tuple(schema.XSS_AGENT_STATUSES),
            tuple(r38_result_schema.AGENT_RESULT_STATUSES),
        )
        self.assertEqual(
            set(schema.XSS_AGENT_STATUSES),
            {"CREATED", "ANALYZING", "COMPLETED", "FAILED", "UNKNOWN"},
        )

    def test_r38_compatibility_projection(self):
        projection = exporter.xss_agent_result_to_r38(rich_result())
        validated = r38_result_schema.SecurityAgentResultPlan(**projection)
        self.assertEqual(validated.rule_version, "r38-5")
        self.assertEqual(validated.status, "COMPLETED")
        self.assertEqual(validated.confidence, "HIGH")
        self.assertEqual(
            validated.findings_summary, "HYPOTHESES_RECORDED"
        )
        self.assertEqual(
            validated.evidence_summary, "EVIDENCE_SUFFICIENT"
        )
        self.assertIn(
            "NO_EXECUTION_PERFORMED", validated.limitations
        )
        self.assertIs(validated.research_only, True)

    def test_r38_projection_of_default_result(self):
        projection = exporter.xss_agent_result_to_r38(
            exporter.export_xss_agent_result()
        )
        validated = r38_result_schema.SecurityAgentResultPlan(**projection)
        self.assertEqual(validated.status, "CREATED")
        self.assertEqual(validated.findings_summary, "NO_FINDINGS")

    def test_r37_governance_reference_unknown_by_default(self):
        plan = exporter.export_xss_agent_result()
        reference = plan["governance_reference"]
        self.assertEqual(reference["reference_state"], "UNKNOWN")
        self.assertIs(reference["ready"], False)
        self.assertIn("GOVERNANCE_UNKNOWN", plan["limitations"])

    def test_r37_governance_reference_integration(self):
        governance = export_research_governance()
        plan = exporter.export_xss_agent_result(governance_plan=governance)
        reference = plan["governance_reference"]
        self.assertEqual(reference["rule_version"], "r37-5")
        self.assertEqual(reference["reference_state"], "REFERENCED")
        self.assertNotIn("GOVERNANCE_UNKNOWN", plan["limitations"])

    def test_r37_governance_reference_ready_states(self):
        reference = exporter.build_governance_reference(
            {
                "rule_version": "r37-5",
                "ready": True,
                "provenance": {"provenance_state": "COMPLETE"},
                "rule_trace": {"trace_state": "COMPLETE"},
                "audit_event": {"audit_state": "VALID"},
                "explanation": {"explanation_state": "COMPLETE"},
            }
        )
        self.assertIs(reference["ready"], True)
        self.assertEqual(reference["provenance_state"], "COMPLETE")
        self.assertEqual(reference["trace_state"], "COMPLETE")
        self.assertEqual(reference["audit_state"], "VALID")
        self.assertEqual(reference["explanation_state"], "COMPLETE")
        self.assertEqual(reference["reference_state"], "REFERENCED")

    def test_r37_governance_reference_rejects_foreign_or_malformed(self):
        for bad in (
            None, "", 42, [],
            {"rule_version": "r38-7", "ready": True},
            {"rule_version": "r37-5"},
            {"rule_version": "r37-5", "reference_state": "REFERENCED",
             "ready": True},
        ):
            reference = exporter.build_governance_reference(bad)
            self.assertEqual(
                reference["reference_state"], "UNKNOWN", repr(bad)
            )
            self.assertIs(reference["ready"], False, repr(bad))

    def test_status_derivation(self):
        self.assertEqual(
            exporter.export_xss_agent_result()["status"], "CREATED"
        )
        self.assertEqual(rich_result()["status"], "COMPLETED")
        mid = exporter.export_xss_agent_result(
            input_location="QUERY",
            output_context="HTML",
            reflection_state="REFLECTED",
            encoding_state="UNKNOWN",
            framework_context="UNKNOWN",
        )
        self.assertEqual(mid["status"], "ANALYZING")

    def test_limitations_are_conservative(self):
        plan = rich_result()
        self.assertIn("NO_EXECUTION_PERFORMED", plan["limitations"])
        self.assertIn("NO_PAYLOAD_GENERATION", plan["limitations"])
        self.assertIn(
            "NO_VULNERABILITY_CONFIRMATION", plan["limitations"]
        )
        self.assertIn("HYPOTHESIS_ONLY", plan["limitations"])
        self.assertNotIn("INSUFFICIENT_CONTEXT", plan["limitations"])

    def test_governance_limitation_cleared_when_referenced(self):
        plan = exporter.export_xss_agent_result(
            governance_plan=export_research_governance()
        )
        self.assertNotIn("GOVERNANCE_UNKNOWN", plan["limitations"])

    def test_malformed_inputs_do_not_crash(self):
        for bad in (None, "", 42, [], {}, "NOPE"):
            plan = exporter.export_xss_agent_result(
                agent_identity=bad,
                security_agent_input=bad,
                input_location=bad,
                output_context=bad,
                reflection_state=bad,
                encoding_state=bad,
                framework_context=bad,
                governance_plan=bad,
            )
            self.assertEqual(plan["status"], "CREATED")
            self.assertIs(plan["research_only"], True)

    def test_r38_input_contract_integration(self):
        agent_name = "xss-research-agent"
        agent_id = compute_xss_agent_id(agent_name, "3.1")
        r38_input = validate_security_agent_input(
            agent_identity={
                "rule_version": "r38-1",
                "agent_id": agent_id,
                "agent_name": agent_name,
                "category": "XSS",
                "version": "3.1",
                "maturity": "RESEARCH",
            }
        )
        plan = exporter.export_xss_agent_result(
            security_agent_input=r38_input,
            input_location="QUERY",
            output_context="HTML",
            reflection_state="REFLECTED",
        )
        self.assertEqual(plan["agent_name"], agent_name)

    def test_explicit_agent_identity(self):
        plan = exporter.export_xss_agent_result(
            agent_identity={
                "category": "XSS",
                "agent_id": compute_xss_agent_id("custom", "2.0"),
                "agent_name": "custom",
                "version": "2.0",
            }
        )
        self.assertEqual(plan["agent_name"], "custom")

    def test_input_immutability(self):
        governance = export_research_governance()
        r38_input = validate_security_agent_input(
            agent_identity={
                "agent_id": compute_xss_agent_id("xss-agent", "2.0"),
                "agent_name": "xss-agent",
                "category": "XSS",
            }
        )
        governance_before = copy.deepcopy(governance)
        input_before = copy.deepcopy(r38_input)
        exporter.export_xss_agent_result(
            security_agent_input=r38_input,
            governance_plan=governance,
        )
        self.assertEqual(governance, governance_before)
        self.assertEqual(r38_input, input_before)

    def test_deterministic_output(self):
        first = rich_result()
        second = rich_result()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = exporter.export_xss_agent_result()
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_everywhere(self):
        plan = rich_result()
        self.assertIs(plan["research_only"], True)
        self.assertIs(plan["context_analysis"]["research_only"], True)
        self.assertIs(plan["evidence_plan"]["research_only"], True)
        for hypothesis in plan["hypotheses"]:
            self.assertIs(hypothesis["research_only"], True)

    def test_no_payload_or_execution_fields(self):
        plan = exporter.export_xss_agent_result()
        for key in ("payload", "exploit", "request", "response",
                    "execution_log", "timestamp", "findings"):
            self.assertNotIn(key, plan)

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R39_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_schema_rejects_bad_values(self):
        base = {
            "agent_name": "xss-agent",
            "status": "ANALYZING",
            "confidence": "LOW",
            "limitations": ["HYPOTHESIS_ONLY"],
        }
        for key, value in (
            ("status", "SCANNING"),
            ("confidence", "CERTAIN"),
            ("limitations", ["CONFIRMED_VULNERABILITY"]),
        ):
            with self.assertRaises(ValidationError):
                schema.XSSAgentResultPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.XSSAgentResultPlan(**base, payload="x")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.XSSAgentResultPlan(
            rule_version="r99-9",
            status="UNKNOWN",
            confidence="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r39-5")
        with self.assertRaises(ValidationError):
            schema.XSSAgentResultPlan(research_only=False)

    def test_exact_rule_version(self):
        self.assertEqual(
            exporter.XSS_AGENT_RESULT_EXPORTER_RULE_VERSION, "r39-5"
        )
        self.assertEqual(
            exporter.export_xss_agent_result()["rule_version"], "r39-5"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
