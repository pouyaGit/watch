"""tests/test_oauth_hypothesis_planner.py — Stage R48.3 tests.

Deterministic, offline tests for the OAuth hypothesis planner:

- redirect URI, state, nonce, PKCE, authorization-code, client
  authentication, scope, resource/audience, issuer, token validation,
  refresh-token, consent and CSRF reasoning
- implicit-flow risk, redirect handling, token exposure and authorization
  flow gap reasoning
- present-control vs gap distinction and negative signals
- needs-evidence semantics and no speculation from technology presence
- deterministic ordering, priority, state and rationale
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

from ai.knowledge.oauth_context_analyzer import analyze_oauth_context
from ai.knowledge.oauth_hypothesis_planner import (
    plan_oauth_hypotheses,
)
from ai.schemas import oauth_hypothesis as schema
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.oauth_hypothesis import (
    HYPOTHESIS_STATES,
    SIGNAL_REDIRECT_URI_VALIDATION_ABSENT,
    SIGNAL_STATE_VALIDATION_ABSENT,
)


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


def hypotheses_for(**context):
    return plan_oauth_hypotheses(analyze_oauth_context(**context))


def types_of(hypotheses):
    return [entry["hypothesis_type"] for entry in hypotheses]


def by_type(hypotheses, hypothesis_type):
    return [
        entry
        for entry in hypotheses
        if entry["hypothesis_type"] == hypothesis_type
    ]


class TestOAuthHypothesisPlanner(unittest.TestCase):
    def test_redirect_uri_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            redirect_uri_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "REDIRECT_URI_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertIn(
            SIGNAL_REDIRECT_URI_VALIDATION_ABSENT,
            gap["supporting_signals"],
        )
        not_provided = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            redirect_uri_validation="NOT_PROVIDED",
        )
        gap = by_type(not_provided, "REDIRECT_URI_VALIDATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertEqual(gap["priority"], "LOW")

    def test_state_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            state_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "STATE_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertIn(
            SIGNAL_STATE_VALIDATION_ABSENT, gap["supporting_signals"]
        )
        enforced = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            state_validation="ENFORCED_OBSERVED",
        )
        self.assertEqual(by_type(enforced, "STATE_VALIDATION_GAP"), [])

    def test_nonce_reasoning(self):
        relevance = hypotheses_for(
            oauth_version="OAUTH2",
            flow="IMPLICIT",
            response_type="TOKEN",
        )
        gap = by_type(relevance, "NONCE_VALIDATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="IMPLICIT",
            response_type="TOKEN",
            nonce_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "NONCE_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        nonce_presence = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            nonce_parameter="OBSERVED",
        )
        self.assertTrue(
            by_type(nonce_presence, "NONCE_VALIDATION_GAP")
        )
        plain_code = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
        )
        self.assertEqual(by_type(plain_code, "NONCE_VALIDATION_GAP"), [])

    def test_pkce_enforcement_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            pkce_enforcement="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "PKCE_ENFORCEMENT_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            pkce_enforcement="ENFORCED_OBSERVED",
        )
        self.assertEqual(by_type(enforced, "PKCE_ENFORCEMENT_GAP"), [])
        confidential = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            client_type="CONFIDENTIAL_CLIENT",
        )
        self.assertEqual(by_type(confidential, "PKCE_ENFORCEMENT_GAP"), [])

    def test_pkce_verifier_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            pkce_challenge="OBSERVED",
            pkce_enforcement="ENFORCED_OBSERVED",
            pkce_verifier_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "PKCE_VERIFIER_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            pkce_challenge="OBSERVED",
            pkce_enforcement="ENFORCED_OBSERVED",
            pkce_verifier_validation="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            by_type(enforced, "PKCE_VERIFIER_VALIDATION_GAP"), []
        )

    def test_authorization_code_reasoning(self):
        binding = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            authorization_code_binding="ABSENT_OBSERVED",
        )
        gap = by_type(
            binding, "AUTHORIZATION_CODE_VALIDATION_GAP"
        )[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        reuse = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            code_reuse_control="ABSENT_OBSERVED",
        )
        gap = by_type(reuse, "AUTHORIZATION_CODE_REUSE_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")

    def test_authorization_code_lifetime_reasoning(self):
        long_lifetime = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            authorization_code_lifetime="LONG_OBSERVED",
        )
        gap = by_type(
            long_lifetime, "AUTHORIZATION_CODE_LIFETIME_RISK"
        )[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        unbounded = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            authorization_code_lifetime="UNBOUNDED_OBSERVED",
        )
        gap = by_type(
            unbounded, "AUTHORIZATION_CODE_LIFETIME_RISK"
        )[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        short = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            authorization_code_lifetime="SHORT_OBSERVED",
        )
        self.assertEqual(
            by_type(short, "AUTHORIZATION_CODE_LIFETIME_RISK"), []
        )

    def test_client_authentication_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            client_type="CONFIDENTIAL_CLIENT",
            client_authentication="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "CLIENT_AUTHENTICATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        public = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            client_authentication="NOT_PROVIDED",
        )
        self.assertEqual(by_type(public, "CLIENT_AUTHENTICATION_GAP"), [])
        inconsistent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            client_type="CONFIDENTIAL_CLIENT",
            token_endpoint_auth_method="NONE_OBSERVED",
        )
        gap = by_type(inconsistent, "CLIENT_AUTHENTICATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertEqual(gap["priority"], "HIGH")

    def test_client_configuration_reasoning(self):
        wildcard = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            redirect_uri_registration="WILDCARD_REGISTERED",
        )
        gap = by_type(wildcard, "CLIENT_CONFIGURATION_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        exact = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            redirect_uri_registration="EXACT_REGISTERED",
        )
        self.assertEqual(
            by_type(exact, "CLIENT_CONFIGURATION_GAP"), []
        )
        not_required = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            client_type="CONFIDENTIAL_CLIENT",
            client_secret_usage="NOT_REQUIRED_OBSERVED",
        )
        gap = by_type(not_required, "CLIENT_CONFIGURATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")

    def test_scope_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            scope_context="OBSERVED",
            scope_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "SCOPE_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        presence_only = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            scope_context="OBSERVED",
        )
        gap = by_type(presence_only, "SCOPE_VALIDATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_resource_audience_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="CLIENT_CREDENTIALS",
            resource_server_context="OBSERVED",
            resource_audience_validation="ABSENT_OBSERVED",
        )
        gap = by_type(
            absent, "RESOURCE_AUDIENCE_VALIDATION_GAP"
        )[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            oauth_version="OAUTH2",
            flow="CLIENT_CREDENTIALS",
            resource_server_context="OBSERVED",
            resource_audience_validation="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            by_type(enforced, "RESOURCE_AUDIENCE_VALIDATION_GAP"), []
        )

    def test_issuer_and_token_validation_reasoning(self):
        issuer = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            authorization_server_context="OBSERVED",
            issuer_validation="ABSENT_OBSERVED",
        )
        gap = by_type(issuer, "ISSUER_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        token = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            token_validation="ABSENT_OBSERVED",
        )
        gap = by_type(token, "TOKEN_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")

    def test_refresh_token_reasoning(self):
        absent_rotation = hypotheses_for(
            oauth_version="OAUTH2",
            flow="REFRESH_TOKEN",
            refresh_token_present="OBSERVED",
            refresh_token_rotation="ABSENT_OBSERVED",
        )
        gap = by_type(
            absent_rotation, "REFRESH_TOKEN_ROTATION_GAP"
        )[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        absent_revocation = hypotheses_for(
            oauth_version="OAUTH2",
            flow="REFRESH_TOKEN",
            refresh_token_present="OBSERVED",
            refresh_token_revocation="ABSENT_OBSERVED",
        )
        gap = by_type(
            absent_revocation, "REFRESH_TOKEN_REVOCATION_GAP"
        )[0]
        self.assertEqual(gap["priority"], "HIGH")
        not_provided = hypotheses_for(
            oauth_version="OAUTH2",
            flow="REFRESH_TOKEN",
            refresh_token_present="OBSERVED",
        )
        gap = by_type(
            not_provided, "REFRESH_TOKEN_ROTATION_GAP"
        )[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        controlled = hypotheses_for(
            oauth_version="OAUTH2",
            flow="REFRESH_TOKEN",
            refresh_token_present="OBSERVED",
            refresh_token_rotation="ENFORCED_OBSERVED",
            refresh_token_revocation="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            by_type(controlled, "REFRESH_TOKEN_ROTATION_GAP"), []
        )
        self.assertEqual(
            by_type(controlled, "REFRESH_TOKEN_REVOCATION_GAP"), []
        )

    def test_consent_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            consent_control="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "CONSENT_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            consent_control="ENFORCED_OBSERVED",
        )
        self.assertEqual(by_type(enforced, "CONSENT_CONTROL_GAP"), [])

    def test_csrf_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            csrf_protection="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "CSRF_PROTECTION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            csrf_protection="ENFORCED_OBSERVED",
        )
        self.assertEqual(by_type(enforced, "CSRF_PROTECTION_GAP"), [])

    def test_login_csrf_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            login_csrf_protection="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "LOGIN_CSRF_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        not_provided = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
        )
        gap = by_type(not_provided, "LOGIN_CSRF_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        non_interactive = hypotheses_for(
            oauth_version="OAUTH2",
            flow="CLIENT_CREDENTIALS",
        )
        self.assertEqual(by_type(non_interactive, "LOGIN_CSRF_GAP"), [])

    def test_redirect_handling_reasoning(self):
        absent = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            redirect_handling="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "REDIRECT_HANDLING_RISK")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            redirect_handling="ENFORCED_OBSERVED",
        )
        self.assertEqual(by_type(enforced, "REDIRECT_HANDLING_RISK"), [])

    def test_implicit_flow_reasoning(self):
        implicit = hypotheses_for(
            oauth_version="OAUTH2",
            flow="IMPLICIT",
            response_type="TOKEN",
        )
        gap = by_type(implicit, "IMPLICIT_FLOW_RISK")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertIn(
            "NO_EXPLOIT_CLAIM", gap["limitations"]
        )
        code_flow = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
        )
        self.assertEqual(by_type(code_flow, "IMPLICIT_FLOW_RISK"), [])

    def test_token_exposure_reasoning(self):
        exposed = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            token_exposure="URL_EXPOSURE_OBSERVED",
        )
        gap = by_type(exposed, "TOKEN_EXPOSURE_RISK")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        none = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            token_exposure="NONE_OBSERVED",
        )
        self.assertEqual(by_type(none, "TOKEN_EXPOSURE_RISK"), [])

    def test_authorization_flow_gap_reasoning(self):
        client_side = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            authorization_boundary="CLIENT_SIDE_ONLY_OBSERVED",
        )
        gap = by_type(client_side, "AUTHORIZATION_FLOW_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        mixed = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            authorization_boundary="MIXED_OBSERVED",
        )
        gap = by_type(mixed, "AUTHORIZATION_FLOW_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        server_side = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            authorization_boundary="SERVER_SIDE_ENFORCED_OBSERVED",
        )
        self.assertEqual(
            by_type(server_side, "AUTHORIZATION_FLOW_GAP"), []
        )

    def test_control_present_reasoning(self):
        controlled = hypotheses_for(
            oauth_version="OAUTH2_1",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            redirect_uri_validation="ENFORCED_OBSERVED",
            exact_redirect_matching="ENFORCED_OBSERVED",
            state_validation="ENFORCED_OBSERVED",
            pkce_enforcement="ENFORCED_OBSERVED",
            pkce_verifier_validation="ENFORCED_OBSERVED",
            csrf_protection="ENFORCED_OBSERVED",
            consent_control="ENFORCED_OBSERVED",
        )
        control = by_type(
            controlled, "AUTHENTICATION_CONTROL_PRESENT"
        )
        self.assertEqual(len(control), 1)
        self.assertEqual(
            control[0]["hypothesis_state"], "CONTROL_PRESENT_OBSERVED"
        )

    def test_negative_signals_reduce_priority(self):
        weak = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            state_validation="ABSENT_OBSERVED",
        )
        controlled = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            state_validation="ENFORCED_OBSERVED",
            csrf_protection="ENFORCED_OBSERVED",
            login_csrf_protection="ENFORCED_OBSERVED",
        )
        self.assertTrue(by_type(weak, "STATE_VALIDATION_GAP"))
        self.assertEqual(by_type(controlled, "STATE_VALIDATION_GAP"), [])
        control = by_type(
            controlled, "AUTHENTICATION_CONTROL_PRESENT"
        )
        self.assertEqual(len(control), 1)
        self.assertEqual(control[0]["priority"], "LOW")

    def test_no_speculation_from_technology_presence(self):
        oauth_only = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            redirect_uri="OBSERVED",
            client_id="OBSERVED",
            state_parameter="OBSERVED",
            scope_context="OBSERVED",
        )
        for entry in oauth_only:
            self.assertNotEqual(entry["priority"], "HIGH")
            self.assertEqual(entry["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertNotIn(
            "WEAKNESS_OBSERVED",
            [entry["hypothesis_state"] for entry in oauth_only],
        )

    def test_missing_context_handling(self):
        unknown = hypotheses_for()
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["hypothesis_type"], "UNKNOWN")
        self.assertEqual(unknown[0]["hypothesis_state"], "UNKNOWN")
        self.assertIn(
            "INSUFFICIENT_CONTEXT", unknown[0]["limitations"]
        )
        missing = hypotheses_for(oauth_version="OAUTH2")
        self.assertEqual(
            [entry["hypothesis_type"] for entry in missing],
            ["MISSING_OAUTH_CONTEXT"],
        )
        self.assertEqual(missing[0]["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_isolated_risk_metadata_is_not_an_oauth_hypothesis(self):
        for context in (
            {"token_exposure": "URL_EXPOSURE_OBSERVED"},
            {"session_integration": "CLIENT_SIDE_SESSION_OBSERVED"},
            {"authorization_boundary": "CLIENT_SIDE_ONLY_OBSERVED"},
            {"redirect_uri_validation": "ABSENT_OBSERVED"},
            {"state_validation": "ABSENT_OBSERVED"},
        ):
            hypotheses = hypotheses_for(**context)
            self.assertEqual(
                types_of(hypotheses),
                ["MISSING_OAUTH_CONTEXT"],
                context,
            )
            self.assertNotEqual(hypotheses[0]["priority"], "HIGH")
        public_client = hypotheses_for(client_type="PUBLIC_CLIENT")
        self.assertEqual(
            types_of(public_client), ["PKCE_ENFORCEMENT_GAP"]
        )
        self.assertEqual(
            public_client[0]["hypothesis_state"], "NEEDS_EVIDENCE"
        )
        self.assertEqual(public_client[0]["priority"], "LOW")

    def test_hypotheses_are_canonical_ordered_and_closed(self):
        hypotheses = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            state_validation="ABSENT_OBSERVED",
            pkce_enforcement="ABSENT_OBSERVED",
        )
        types = types_of(hypotheses)
        expected_order = [
            hypothesis_type
            for hypothesis_type in schema.HYPOTHESIS_TYPES
            if hypothesis_type in types
        ]
        self.assertEqual(types, expected_order)
        self.assertEqual(len(types), len(set(types)))
        for entry in hypotheses:
            self.assertIn(entry["hypothesis_type"], schema.HYPOTHESIS_TYPES)
            self.assertIn(entry["hypothesis_state"], HYPOTHESIS_STATES)
            self.assertIn(entry["priority"], CONFIDENCE_LEVELS)
            self.assertIn(entry["confidence"], CONFIDENCE_LEVELS)
            self.assertTrue(entry["supporting_signals"])
            for signal in entry["supporting_signals"]:
                self.assertIn(signal, schema.OAUTH_SIGNALS)
            self.assertNotEqual(entry["rationale"], "")

    def test_hypothesis_limitations(self):
        hypotheses = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            state_validation="ABSENT_OBSERVED",
        )
        for entry in hypotheses:
            for limitation in (
                "NO_EXPLOIT_CLAIM",
                "NO_VULNERABILITY_CONFIRMATION",
                "NO_OAUTH_BYPASS_CLAIM",
                "NO_REDIRECT_URI_EXPLOIT_CLAIM",
                "NO_TOKEN_EXCHANGE_CLAIM",
                "NO_CSRF_EXPLOIT_CLAIM",
                "HYPOTHESIS_ONLY",
                "EVIDENCE_REQUIRED",
            ):
                self.assertIn(limitation, entry["limitations"])
        unknown = hypotheses_for()
        self.assertIn(
            "INSUFFICIENT_CONTEXT", unknown[0]["limitations"]
        )

    def test_schema_rejects_bad_values_and_extra(self):
        base = hypotheses_for(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            state_validation="ABSENT_OBSERVED",
        )[0]
        with self.assertRaises(ValidationError):
            schema.OAuthHypothesisPlan(
                **{**base, "hypothesis_type": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthHypothesisPlan(
                **{**base, "hypothesis_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthHypothesisPlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthHypothesisPlan(
                **{**base, "priority": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthHypothesisPlan(
                **{**base, "supporting_signals": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthHypothesisPlan(
                **{**base, "limitations": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthHypothesisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthHypothesisPlan(**{**base, "token": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.OAuthHypothesisPlan(
            hypothesis_type="STATE_VALIDATION_GAP",
            rule_version="r99-9",
        )
        self.assertEqual(plan.rule_version, "r48-3")

    def test_deterministic_serialization(self):
        first = json.dumps(
            hypotheses_for(
                oauth_version="OAUTH2",
                flow="AUTHORIZATION_CODE",
                state_validation="ABSENT_OBSERVED",
            ),
            sort_keys=True,
        )
        second = json.dumps(
            hypotheses_for(
                oauth_version="OAUTH2",
                flow="AUTHORIZATION_CODE",
                state_validation="ABSENT_OBSERVED",
            ),
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
