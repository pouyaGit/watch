"""tests/test_oauth_agent_identity.py — Stage R48.1 tests.

Deterministic, offline tests for the OAuth specialist identity:

- canonical R38 category and deterministic content-token agent id
- maturity, OAuth flow context, capability and lifecycle resolution
- R38 identity projection conformance
- schema validation and extra-field rejection
- R48 AST safety scan and standalone backend decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no OAuth flow, no redirect following, no token exchange, no
payloads, no Mongo writes, no persistence, no execution of any kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.oauth_agent import (
    OAUTH_AGENT_KNOWLEDGE_MODULES,
    run_oauth_agent,
)
from ai.knowledge.oauth_agent_identity import (
    DEFAULT_AGENT_NAME,
    compute_oauth_agent_id,
    oauth_agent_identity_to_r38,
    plan_oauth_agent_identity,
    resolve_supported_capabilities,
    resolve_supported_contexts,
)
from ai.schemas import oauth_agent_identity as schema
from ai.schemas.oauth_agent import (
    OAUTH_AGENT_SCHEMA_MODULES,
    OAuthAgentIdentityPlan,
)
from ai.schemas.security_agent_capability import (
    ALLOWED_CAPABILITIES,
    PROHIBITED_CAPABILITIES,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES, AGENT_ID_RE


ROOT = Path(__file__).resolve().parents[1]

R48_MODULES = (
    "ai/schemas/oauth_agent_identity.py",
    "ai/schemas/oauth_context_analysis.py",
    "ai/schemas/oauth_hypothesis.py",
    "ai/schemas/oauth_evidence_plan.py",
    "ai/schemas/oauth_agent_result.py",
    "ai/schemas/oauth_agent.py",
    "ai/knowledge/oauth_agent_identity.py",
    "ai/knowledge/oauth_context_analyzer.py",
    "ai/knowledge/oauth_hypothesis_planner.py",
    "ai/knowledge/oauth_evidence_planner.py",
    "ai/knowledge/oauth_agent_result_export.py",
    "ai/knowledge/oauth_agent.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "asyncio", "threading", "multiprocessing", "concurrent",
    "importlib", "ctypes", "shutil", "ssl", "os", "dns", "selenium",
    "playwright", "pyppeteer", "paramiko", "sqlite3", "sqlalchemy",
    "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap", "nuclei",
    "curl", "pycurl", "openai", "ollama", "litellm", "anthropic",
    "openrouter", "jwt", "pyjwt", "jose", "oauthlib", "authlib",
    "oauth2", "oauth2client", "requests_oauthlib", "msal", "google",
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


class TestOAuthAgentIdentity(unittest.TestCase):
    def test_identity_defaults(self):
        identity = plan_oauth_agent_identity()
        self.assertEqual(identity["rule_version"], "r48-1")
        self.assertEqual(identity["agent_name"], DEFAULT_AGENT_NAME)
        self.assertEqual(identity["agent_name"], "oauth-specialist")
        self.assertEqual(identity["category"], "OAUTH")
        self.assertIn(identity["category"], AGENT_CATEGORIES)
        self.assertTrue(AGENT_ID_RE.match(identity["agent_id"]))
        self.assertIs(identity["research_only"], True)

    def test_category_is_canonical_r38_oauth(self):
        identity = plan_oauth_agent_identity()
        self.assertEqual(schema.OAUTH_CATEGORY, "OAUTH")
        self.assertEqual(schema.OAUTH_RESEARCH_LABEL, "OAUTH_FLOW")
        self.assertIn(schema.OAUTH_CATEGORY, AGENT_CATEGORIES)
        self.assertNotIn(schema.OAUTH_RESEARCH_LABEL, AGENT_CATEGORIES)
        self.assertIn(
            "OAUTH",
            {entry["category"] for entry in [identity]},
        )

    def test_agent_id_is_deterministic_content_token(self):
        first = plan_oauth_agent_identity()
        second = plan_oauth_agent_identity()
        self.assertEqual(first["agent_id"], second["agent_id"])
        self.assertEqual(
            first["agent_id"],
            compute_oauth_agent_id(DEFAULT_AGENT_NAME, "1.0"),
        )
        renamed = plan_oauth_agent_identity(agent_name="other-agent")
        self.assertNotEqual(first["agent_id"], renamed["agent_id"])

    def test_no_runtime_identity(self):
        serialized = json.dumps(
            plan_oauth_agent_identity(), sort_keys=True
        ).lower()
        for token in (
            "timestamp",
            "uuid",
            "runtime_id",
            "random",
        ):
            self.assertNotIn(token, serialized)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("token_value", serialized)
        self.assertNotIn("client_secret", serialized)

    def test_maturity_resolution(self):
        for maturity in ("EXPERIMENTAL", "RESEARCH", "STABLE"):
            identity = plan_oauth_agent_identity(maturity=maturity)
            self.assertEqual(identity["maturity"], maturity)
        self.assertEqual(
            plan_oauth_agent_identity(maturity="NOPE")["maturity"],
            "UNKNOWN",
        )
        self.assertEqual(
            plan_oauth_agent_identity()["maturity"], "UNKNOWN"
        )

    def test_supported_contexts_bounded(self):
        identity = plan_oauth_agent_identity(
            supported_contexts=[
                "AUTHORIZATION_CODE",
                "NOPE",
                "AUTHORIZATION_CODE_PKCE",
            ]
        )
        self.assertEqual(
            identity["supported_contexts"],
            ["AUTHORIZATION_CODE", "AUTHORIZATION_CODE_PKCE"],
        )
        empty = plan_oauth_agent_identity(supported_contexts=[])
        self.assertEqual(empty["supported_contexts"], ["UNKNOWN"])
        self.assertIn("SCOPE_UNKNOWN", empty["limitations"])
        self.assertEqual(
            resolve_supported_contexts(["implicit", "bogus"]),
            ["IMPLICIT"],
        )

    def test_supported_capabilities_analysis_only(self):
        identity = plan_oauth_agent_identity()
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
            plan_oauth_agent_identity()["lifecycle_state"], "PLANNED"
        )
        self.assertEqual(
            plan_oauth_agent_identity(
                lifecycle_state="CREATED"
            )["lifecycle_state"],
            "CREATED",
        )
        self.assertEqual(
            plan_oauth_agent_identity(
                lifecycle_state="RUNNING"
            )["lifecycle_state"],
            "PLANNED",
        )

    def test_identity_limitations(self):
        identity = plan_oauth_agent_identity()
        for limitation in (
            "NO_EXECUTION_CAPABILITY",
            "NO_OAUTH_FLOW_EXECUTION",
            "NO_TOKEN_EXCHANGE",
            "NO_REDIRECT_FOLLOWING",
            "NO_AUTHENTICATION_BYPASS",
            "NO_CREDENTIAL_TESTING",
            "NO_NETWORK_REQUESTS",
            "NO_PAYLOAD_GENERATION",
            "NO_VULNERABILITY_CONFIRMATION",
        ):
            self.assertIn(limitation, identity["limitations"])

    def test_r38_identity_projection(self):
        projection = oauth_agent_identity_to_r38(
            plan_oauth_agent_identity(maturity="RESEARCH")
        )
        self.assertEqual(projection["category"], "OAUTH")
        self.assertTrue(AGENT_ID_RE.match(projection["agent_id"]))
        self.assertIs(projection["research_only"], True)

    def test_schema_rejects_bad_values_and_extra(self):
        base = plan_oauth_agent_identity()
        with self.assertRaises(ValidationError):
            schema.OAuthAgentIdentityPlan(
                **{**base, "category": "OAUTH_FLOW"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthAgentIdentityPlan(**{**base, "maturity": "NOPE"})
        with self.assertRaises(ValidationError):
            schema.OAuthAgentIdentityPlan(
                **{**base, "agent_id": "oauth-specialist"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthAgentIdentityPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthAgentIdentityPlan(
                **{**base, "supported_capabilities": ["BYPASS_AUTH"]}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthAgentIdentityPlan(**{**base, "token": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.OAuthAgentIdentityPlan(
            **{
                **plan_oauth_agent_identity(),
                "rule_version": "r99-9",
            }
        )
        self.assertEqual(plan.rule_version, "r48-1")

    def test_facades_expose_components(self):
        self.assertEqual(len(OAUTH_AGENT_SCHEMA_MODULES), 5)
        self.assertEqual(len(OAUTH_AGENT_KNOWLEDGE_MODULES), 5)
        self.assertIs(
            OAuthAgentIdentityPlan,
            schema.OAuthAgentIdentityPlan,
        )
        self.assertEqual(run_oauth_agent()["rule_version"], "r48-5")

    def test_deterministic_serialization(self):
        first = json.dumps(
            plan_oauth_agent_identity(maturity="RESEARCH"),
            sort_keys=True,
        )
        second = json.dumps(
            plan_oauth_agent_identity(maturity="RESEARCH"),
            sort_keys=True,
        )
        self.assertEqual(first, second)

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R48_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("oauth_agent", backend_source)
        self.assertNotIn("OAUTH_AGENT", backend_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
