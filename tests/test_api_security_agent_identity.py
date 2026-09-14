"""tests/test_api_security_agent_identity.py — Stage R49.1 tests.

Deterministic, offline tests for the API security specialist identity:

- existing canonical R38 category and deterministic content-token id
- maturity, API-type context, capability and lifecycle resolution
- R38 identity projection conformance
- schema validation and extra-field rejection
- R49 AST safety scan and standalone backend decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no API calls, no endpoint probing, no payloads, no Mongo
writes, no persistence, no execution of any kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.api_security_agent import (
    API_SECURITY_AGENT_KNOWLEDGE_MODULES,
    run_api_security_agent,
)
from ai.knowledge.api_security_agent_identity import (
    DEFAULT_AGENT_NAME,
    api_security_agent_identity_to_r38,
    compute_api_security_agent_id,
    plan_api_security_agent_identity,
    resolve_supported_capabilities,
    resolve_supported_contexts,
)
from ai.schemas import api_security_agent_identity as schema
from ai.schemas.api_security_agent import (
    API_SECURITY_AGENT_SCHEMA_MODULES,
    APISecurityAgentIdentityPlan,
)
from ai.schemas.security_agent_capability import (
    ALLOWED_CAPABILITIES,
    PROHIBITED_CAPABILITIES,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES, AGENT_ID_RE


ROOT = Path(__file__).resolve().parents[1]

R49_MODULES = (
    "ai/schemas/api_security_agent_identity.py",
    "ai/schemas/api_security_context_analysis.py",
    "ai/schemas/api_security_hypothesis.py",
    "ai/schemas/api_security_evidence_plan.py",
    "ai/schemas/api_security_agent_result.py",
    "ai/schemas/api_security_agent.py",
    "ai/knowledge/api_security_agent_identity.py",
    "ai/knowledge/api_security_context_analyzer.py",
    "ai/knowledge/api_security_hypothesis_planner.py",
    "ai/knowledge/api_security_evidence_planner.py",
    "ai/knowledge/api_security_agent_result_export.py",
    "ai/knowledge/api_security_agent.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "urllib3", "requests",
    "httpx", "aiohttp", "asyncio", "threading", "multiprocessing",
    "concurrent", "importlib", "ctypes", "shutil", "ssl", "os", "dns",
    "selenium", "playwright", "pyppeteer", "paramiko", "sqlite3",
    "sqlalchemy", "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap",
    "nuclei", "ffuf", "curl", "pycurl", "openai", "ollama", "litellm",
    "anthropic", "openrouter", "jwt", "pyjwt", "jose", "oauthlib",
    "authlib", "oauth2", "oauth2client", "requests_oauthlib", "msal",
    "google", "gql", "graphql", "openapi", "swagger", "grpc",
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
    "oauthlib.",
    "authlib.",
    "msal.",
    "urllib3.",
    "grpc.",
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


class TestAPISecurityAgentIdentity(unittest.TestCase):
    def test_identity_defaults(self):
        identity = plan_api_security_agent_identity()
        self.assertEqual(identity["rule_version"], "r49-1")
        self.assertEqual(identity["agent_name"], DEFAULT_AGENT_NAME)
        self.assertEqual(identity["agent_name"], "api-security-specialist")
        self.assertEqual(identity["category"], "RECON")
        self.assertIn(identity["category"], AGENT_CATEGORIES)
        self.assertTrue(AGENT_ID_RE.match(identity["agent_id"]))
        self.assertIs(identity["research_only"], True)

    def test_category_is_existing_r38_category(self):
        identity = plan_api_security_agent_identity()
        self.assertEqual(schema.API_SECURITY_CATEGORY, "RECON")
        self.assertEqual(schema.API_SECURITY_RESEARCH_LABEL, "API_SECURITY")
        self.assertIn(schema.API_SECURITY_CATEGORY, AGENT_CATEGORIES)
        self.assertNotIn(
            schema.API_SECURITY_RESEARCH_LABEL, AGENT_CATEGORIES
        )
        self.assertEqual(identity["category"], schema.API_SECURITY_CATEGORY)

    def test_agent_id_is_deterministic_content_token(self):
        first = plan_api_security_agent_identity()
        second = plan_api_security_agent_identity()
        self.assertEqual(first["agent_id"], second["agent_id"])
        self.assertEqual(
            first["agent_id"],
            compute_api_security_agent_id(DEFAULT_AGENT_NAME, "1.0"),
        )
        renamed = plan_api_security_agent_identity(agent_name="other-agent")
        self.assertNotEqual(first["agent_id"], renamed["agent_id"])

    def test_no_runtime_identity(self):
        serialized = json.dumps(
            plan_api_security_agent_identity(), sort_keys=True
        ).lower()
        for token in ("timestamp", "uuid", "runtime_id", "random"):
            self.assertNotIn(token, serialized)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("api_key_value", serialized)
        self.assertNotIn("endpoint_url", serialized)

    def test_maturity_resolution(self):
        for maturity in ("EXPERIMENTAL", "RESEARCH", "STABLE"):
            identity = plan_api_security_agent_identity(maturity=maturity)
            self.assertEqual(identity["maturity"], maturity)
        self.assertEqual(
            plan_api_security_agent_identity(maturity="NOPE")["maturity"],
            "UNKNOWN",
        )
        self.assertEqual(
            plan_api_security_agent_identity()["maturity"], "UNKNOWN"
        )

    def test_supported_contexts_bounded(self):
        identity = plan_api_security_agent_identity(
            supported_contexts=["REST", "NOPE", "GRAPHQL"]
        )
        self.assertEqual(
            identity["supported_contexts"], ["REST", "GRAPHQL"]
        )
        empty = plan_api_security_agent_identity(supported_contexts=[])
        self.assertEqual(empty["supported_contexts"], ["UNKNOWN"])
        self.assertIn("SCOPE_UNKNOWN", empty["limitations"])
        self.assertEqual(
            resolve_supported_contexts(["rpc", "bogus"]), ["RPC"]
        )

    def test_supported_capabilities_analysis_only(self):
        identity = plan_api_security_agent_identity()
        self.assertEqual(
            identity["supported_capabilities"],
            list(ALLOWED_CAPABILITIES),
        )
        for prohibited in PROHIBITED_CAPABILITIES:
            self.assertNotIn(prohibited, identity["supported_capabilities"])
        bounded = resolve_supported_capabilities(
            list(PROHIBITED_CAPABILITIES) + ["ANALYZE_CONTEXT"]
        )
        self.assertEqual(bounded, ["ANALYZE_CONTEXT"])
        self.assertEqual(resolve_supported_capabilities([]), [])

    def test_lifecycle_resolution(self):
        self.assertEqual(
            plan_api_security_agent_identity()["lifecycle_state"], "PLANNED"
        )
        self.assertEqual(
            plan_api_security_agent_identity(
                lifecycle_state="CREATED"
            )["lifecycle_state"],
            "CREATED",
        )
        self.assertEqual(
            plan_api_security_agent_identity(
                lifecycle_state="RUNNING"
            )["lifecycle_state"],
            "PLANNED",
        )

    def test_identity_limitations(self):
        identity = plan_api_security_agent_identity()
        for limitation in (
            "NO_EXECUTION_CAPABILITY",
            "NO_API_CALLS",
            "NO_ENDPOINT_PROBING",
            "NO_PAYLOAD_GENERATION",
            "NO_CREDENTIAL_TESTING",
            "NO_NETWORK_REQUESTS",
            "NO_BYPASS_ATTEMPT",
            "NO_SCANNER_EXECUTION",
            "NO_VULNERABILITY_CONFIRMATION",
        ):
            self.assertIn(limitation, identity["limitations"])

    def test_r38_identity_projection(self):
        projection = api_security_agent_identity_to_r38(
            plan_api_security_agent_identity(maturity="RESEARCH")
        )
        self.assertEqual(projection["category"], "RECON")
        self.assertTrue(AGENT_ID_RE.match(projection["agent_id"]))
        self.assertIs(projection["research_only"], True)

    def test_schema_rejects_bad_values_and_extra(self):
        base = plan_api_security_agent_identity()
        with self.assertRaises(ValidationError):
            schema.APISecurityAgentIdentityPlan(
                **{**base, "category": "API_SECURITY"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityAgentIdentityPlan(**{**base, "maturity": "NOPE"})
        with self.assertRaises(ValidationError):
            schema.APISecurityAgentIdentityPlan(
                **{**base, "agent_id": "api-security-specialist"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityAgentIdentityPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityAgentIdentityPlan(
                **{**base, "supported_capabilities": ["BYPASS_AUTH"]}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityAgentIdentityPlan(**{**base, "token": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.APISecurityAgentIdentityPlan(
            **{
                **plan_api_security_agent_identity(),
                "rule_version": "r99-9",
            }
        )
        self.assertEqual(plan.rule_version, "r49-1")

    def test_facades_expose_components(self):
        self.assertEqual(len(API_SECURITY_AGENT_SCHEMA_MODULES), 5)
        self.assertEqual(len(API_SECURITY_AGENT_KNOWLEDGE_MODULES), 5)
        self.assertIs(
            APISecurityAgentIdentityPlan,
            schema.APISecurityAgentIdentityPlan,
        )
        self.assertEqual(run_api_security_agent()["rule_version"], "r49-5")

    def test_deterministic_serialization(self):
        first = json.dumps(
            plan_api_security_agent_identity(maturity="RESEARCH"),
            sort_keys=True,
        )
        second = json.dumps(
            plan_api_security_agent_identity(maturity="RESEARCH"),
            sort_keys=True,
        )
        self.assertEqual(first, second)

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R49_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("api_security", backend_source)
        self.assertNotIn("API_SECURITY", backend_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
