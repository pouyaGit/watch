"""tests/test_sqli_agent_result.py — Stage R41.5 tests.

Deterministic, offline tests for the SQLi agent result export:

- R38 compatibility (status/confidence vocabularies, R38 result projection)
- R37 governance reference integration
- R31-R37 provenance preservation
- identity exposure and limitation preservation
- conservative status derivation
- serialization and input immutability
- backend additive integration
- safety scans: no SQL/database/network/subprocess/socket/sqlmap imports or
  calls

No SQL, no database, no network, no LLM, no subprocess, no sqlmap, no
sockets, no browser, no payloads, no Mongo writes, no persistence, no
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

from ai.knowledge import sqli_agent_result_export as exporter
from ai.knowledge.research_governance_export import (
    export_research_governance,
)
from ai.knowledge.security_agent_input_validator import (
    validate_security_agent_input,
)
from ai.knowledge.sqli_agent_identity import compute_sqli_agent_id
from ai.schemas import security_agent_capability as r38_capability_schema
from ai.schemas import security_agent_result as r38_result_schema
from ai.schemas import sqli_agent_result as schema


ROOT = Path(__file__).resolve().parents[1]

R41_MODULES = (
    "ai/schemas/sqli_agent_identity.py",
    "ai/schemas/sqli_context_analysis.py",
    "ai/schemas/sqli_hypothesis.py",
    "ai/schemas/sqli_evidence_plan.py",
    "ai/schemas/sqli_agent_result.py",
    "ai/knowledge/sqli_agent_identity.py",
    "ai/knowledge/sqli_context_analyzer.py",
    "ai/knowledge/sqli_hypothesis_planner.py",
    "ai/knowledge/sqli_evidence_planner.py",
    "ai/knowledge/sqli_agent_result_export.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "asyncio", "threading", "multiprocessing", "concurrent",
    "importlib", "ctypes", "shutil", "ssl", "ftplib", "smtplib",
    "telnetlib", "os", "dns", "selenium", "playwright", "pyppeteer",
    "paramiko", "urllib3", "curl", "pycurl", "sqlite3", "sqlalchemy",
    "psycopg", "psycopg2", "pymysql", "MySQLdb", "cx_Oracle",
    "pyodbc", "asyncpg", "aiosqlite", "mariadb", "sqlmap",
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
    "dns.",
    "sqlite3.",
    "sqlalchemy.",
    "psycopg2.",
    "pymysql.",
    "sqlmap.",
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


FULL_CONTEXT = {
    "input_location": "QUERY",
    "parameter_type": "IDENTIFIER",
    "data_flow": "RAW_QUERY",
    "query_context": "ORDER_BY",
    "database_context": "MYSQL",
    "input_handling": "CONCATENATED",
    "type_handling": "NONE_OBSERVED",
    "error_behavior": "DATABASE_ERROR_OBSERVED",
    "behavioral_signal": "TIMING_RELEVANT",
}


def rich_result(**over):
    kwargs = dict(FULL_CONTEXT)
    kwargs.update(over)
    return exporter.export_sqli_agent_result(**kwargs)


class TestSQLIAgentResult(unittest.TestCase):
    def test_key_set_is_exact(self):
        plan = exporter.export_sqli_agent_result()
        self.assertEqual(
            set(plan.keys()),
            {"rule_version", "agent_name", "agent_identity", "status",
             "context_analysis", "hypotheses", "evidence_plan",
             "confidence", "limitations", "governance_reference",
             "provenance", "research_only"},
        )

    def test_r38_status_vocabulary_matches(self):
        self.assertEqual(
            tuple(schema.SQLI_AGENT_STATUSES),
            tuple(r38_result_schema.AGENT_RESULT_STATUSES),
        )
        self.assertEqual(
            set(schema.SQLI_AGENT_STATUSES),
            {"CREATED", "ANALYZING", "COMPLETED", "FAILED", "UNKNOWN"},
        )

    def test_r38_compatibility_projection(self):
        projection = exporter.sqli_agent_result_to_r38(rich_result())
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
        projection = exporter.sqli_agent_result_to_r38(
            exporter.export_sqli_agent_result()
        )
        validated = r38_result_schema.SecurityAgentResultPlan(**projection)
        self.assertEqual(validated.status, "CREATED")
        self.assertEqual(validated.findings_summary, "NO_FINDINGS")

    def test_identity_exposed(self):
        plan = rich_result()
        identity = plan["agent_identity"]
        self.assertEqual(identity["category"], "SQLI")
        self.assertEqual(identity["agent_name"], "sqli-agent")
        self.assertTrue(identity["agent_id"].startswith("sa-"))
        for capability in identity["supported_capabilities"]:
            self.assertIn(
                capability, r38_capability_schema.ALLOWED_CAPABILITIES
            )
            self.assertNotIn(
                capability,
                r38_capability_schema.PROHIBITED_CAPABILITIES,
            )
        self.assertIs(identity["research_only"], True)

    def test_required_limitations_preserved(self):
        plan = exporter.export_sqli_agent_result()
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_SQL_EXECUTION",
            "NO_NETWORK_REQUESTS",
            "NO_PAYLOAD_GENERATION",
            "NO_VULNERABILITY_CONFIRMATION",
            "HYPOTHESIS_ONLY",
            "EVIDENCE_REQUIRED",
        ):
            self.assertIn(limitation, plan["limitations"])

    def test_r37_governance_reference_unknown_by_default(self):
        plan = exporter.export_sqli_agent_result()
        reference = plan["governance_reference"]
        self.assertEqual(reference["reference_state"], "UNKNOWN")
        self.assertIs(reference["ready"], False)
        self.assertIn("GOVERNANCE_UNKNOWN", plan["limitations"])

    def test_r37_governance_reference_integration(self):
        governance = export_research_governance()
        plan = exporter.export_sqli_agent_result(
            governance_plan=governance
        )
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
        self.assertEqual(reference["audit_state"], "VALID")
        self.assertEqual(reference["reference_state"], "REFERENCED")

    def test_r37_governance_reference_rejects_foreign_or_malformed(self):
        for bad in (
            None, "", 42, [],
            {"rule_version": "r40-5", "ready": True},
            {"rule_version": "r37-5"},
            {"rule_version": "r37-5", "reference_state": "REFERENCED",
             "ready": True},
        ):
            reference = exporter.build_governance_reference(bad)
            self.assertEqual(
                reference["reference_state"], "UNKNOWN", repr(bad)
            )
            self.assertIs(reference["ready"], False, repr(bad))

    def test_provenance_unknown_by_default(self):
        plan = exporter.export_sqli_agent_result()
        provenance = plan["provenance"]
        self.assertEqual(provenance["provenance_state"], "UNKNOWN")
        self.assertEqual(provenance["source_layers"], [])

    def test_provenance_preserved_from_r38_input(self):
        bounded = validate_security_agent_input(
            research_context={"topic": "r31"},
            memory_context={"prior": "r32"},
            authorization_context={"scope": "research"},
        )
        plan = exporter.export_sqli_agent_result(
            security_agent_input=bounded,
            input_location="QUERY",
            input_handling="CONCATENATED",
        )
        provenance = plan["provenance"]
        self.assertEqual(
            provenance["source_layers"],
            ["REASONING", "MEMORY", "AUTHORIZATION"],
        )
        self.assertEqual(provenance["provenance_state"], "PARTIAL")

    def test_provenance_complete_for_all_layers(self):
        bounded = validate_security_agent_input(
            research_context={"a": 1},
            memory_context={"b": 2},
            strategy_context={"c": 3},
            orchestration_context={"d": 4},
            authorization_context={"e": 5},
            governance_context={"f": 6},
        )
        plan = exporter.export_sqli_agent_result(
            security_agent_input=bounded
        )
        self.assertEqual(
            plan["provenance"]["source_layers"],
            ["REASONING", "MEMORY", "STRATEGY", "ORCHESTRATION",
             "AUTHORIZATION", "GOVERNANCE"],
        )
        self.assertEqual(
            plan["provenance"]["provenance_state"], "COMPLETE"
        )

    def test_provenance_records_governance_reference(self):
        plan = exporter.export_sqli_agent_result(
            governance_plan=export_research_governance()
        )
        self.assertEqual(
            plan["provenance"]["source_layers"], ["GOVERNANCE"]
        )
        self.assertEqual(
            plan["provenance"]["provenance_state"], "PARTIAL"
        )

    def test_status_derivation(self):
        self.assertEqual(
            exporter.export_sqli_agent_result()["status"], "CREATED"
        )
        self.assertEqual(rich_result()["status"], "COMPLETED")
        mid = exporter.export_sqli_agent_result(
            input_location="QUERY",
            data_flow="RAW_QUERY",
        )
        self.assertEqual(mid["status"], "ANALYZING")

    def test_parameterized_context_never_completes(self):
        plan = exporter.export_sqli_agent_result(
            input_location="QUERY",
            parameter_type="STRING",
            data_flow="QUERY_BUILDER",
            query_context="WHERE",
            database_context="POSTGRESQL",
            input_handling="PARAMETERIZED",
            type_handling="STRONG",
            error_behavior="NO_ERROR_OBSERVED",
            behavioral_signal="NONE_OBSERVED",
        )
        self.assertNotEqual(plan["status"], "COMPLETED")
        self.assertNotEqual(plan["context_analysis"]
                            ["context_confidence"], "HIGH")

    def test_malformed_inputs_do_not_crash(self):
        for bad in (None, "", 42, [], {}, "NOPE"):
            plan = exporter.export_sqli_agent_result(
                agent_identity=bad,
                security_agent_input=bad,
                input_location=bad,
                parameter_type=bad,
                data_flow=bad,
                query_context=bad,
                database_context=bad,
                input_handling=bad,
                type_handling=bad,
                error_behavior=bad,
                behavioral_signal=bad,
                governance_plan=bad,
            )
            self.assertEqual(plan["status"], "CREATED")
            self.assertIs(plan["research_only"], True)

    def test_r38_input_contract_integration(self):
        agent_name = "sqli-research-agent"
        agent_id = compute_sqli_agent_id(agent_name, "1.4")
        r38_input = validate_security_agent_input(
            agent_identity={
                "rule_version": "r38-1",
                "agent_id": agent_id,
                "agent_name": agent_name,
                "category": "SQLI",
                "version": "1.4",
                "maturity": "RESEARCH",
            }
        )
        plan = exporter.export_sqli_agent_result(
            security_agent_input=r38_input,
            input_location="QUERY",
        )
        self.assertEqual(plan["agent_name"], agent_name)
        self.assertEqual(plan["agent_identity"]["category"], "SQLI")

    def test_explicit_agent_identity(self):
        plan = exporter.export_sqli_agent_result(
            agent_identity={
                "category": "SQLI",
                "agent_id": compute_sqli_agent_id("custom", "9.9"),
                "agent_name": "custom",
                "version": "9.9",
            }
        )
        self.assertEqual(plan["agent_name"], "custom")

    def test_input_immutability(self):
        governance = export_research_governance()
        r38_input = validate_security_agent_input(
            agent_identity={
                "agent_id": compute_sqli_agent_id("sqli-agent", "1.0"),
                "agent_name": "sqli-agent",
                "category": "SQLI",
            }
        )
        governance_before = copy.deepcopy(governance)
        input_before = copy.deepcopy(r38_input)
        exporter.export_sqli_agent_result(
            security_agent_input=r38_input,
            governance_plan=governance,
        )
        self.assertEqual(governance, governance_before)
        self.assertEqual(r38_input, input_before)

    def test_deterministic_output_and_json(self):
        first = rich_result()
        second = rich_result()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertIsInstance(json.loads(json.dumps(first)), dict)

    def test_research_only_everywhere(self):
        plan = rich_result()
        self.assertIs(plan["research_only"], True)
        self.assertIs(plan["context_analysis"]["research_only"], True)
        self.assertIs(plan["evidence_plan"]["research_only"], True)
        self.assertIs(plan["provenance"]["research_only"], True)
        for hypothesis in plan["hypotheses"]:
            self.assertIs(hypothesis["research_only"], True)

    def test_no_sql_or_connection_fields(self):
        plan = exporter.export_sqli_agent_result()
        for key in ("payload", "exploit", "query", "sql", "connection",
                    "dsn", "request", "response", "execution_log",
                    "timestamp"):
            self.assertNotIn(key, plan)

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R41_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_no_sql_payload_content(self):
        blob = json.dumps(exporter.export_sqli_agent_result()).lower()
        for marker in (
            "select ", "union ", "drop table", "insert into", " or 1=1",
            "sleep(", "waitfor delay", "sqlmap", "sqlite3",
            "psycopg", "pymysql", "sqlalchemy", "connection string",
        ):
            self.assertNotIn(marker, blob)

    def test_backend_additive_integration(self):
        sys.path.insert(0, "/opt/watch")
        import backend.asset_cve_matching as backend

        data = backend.build_matches(cve="CVE-2026-1557")
        self.assertTrue(data.get("items"))
        for summary in data["items"]:
            plan = summary["sqli_agent_plan"]
            self.assertEqual(plan["rule_version"], "r41-5")
            self.assertEqual(
                summary["sqli_agent_plan_rule_version"], "r41-5"
            )
            self.assertIs(plan["research_only"], True)
            self.assertIn("NO_SQL_EXECUTION", plan["limitations"])
            self.assertIn("NO_NETWORK_REQUESTS", plan["limitations"])
            self.assertEqual(
                plan["governance_reference"]["reference_state"],
                "UNKNOWN",
            )
            self.assertIn("ssrf_agent_plan", summary)
            self.assertIn("xss_agent_plan", summary)
            self.assertIn("security_agent_framework_plan", summary)
            self.assertIn("research_governance_export_plan", summary)

    def test_schema_rejects_bad_values(self):
        base = {
            "agent_name": "sqli-agent",
            "status": "ANALYZING",
            "confidence": "LOW",
            "limitations": ["HYPOTHESIS_ONLY"],
        }
        for key, value in (
            ("status", "QUERYING"),
            ("confidence", "CERTAIN"),
            ("limitations", ["CONFIRMED_VULNERABILITY"]),
        ):
            with self.assertRaises(ValidationError):
                schema.SQLIAgentResultPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SQLIAgentResultPlan(**base, payload="' OR 1=1")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.SQLIAgentResultPlan(
            rule_version="r99-9",
            status="UNKNOWN",
            confidence="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r41-5")
        with self.assertRaises(ValidationError):
            schema.SQLIAgentResultPlan(research_only=False)

    def test_exact_rule_version(self):
        self.assertEqual(
            exporter.SQLI_AGENT_RESULT_EXPORTER_RULE_VERSION, "r41-5"
        )
        self.assertEqual(
            exporter.export_sqli_agent_result()["rule_version"], "r41-5"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
