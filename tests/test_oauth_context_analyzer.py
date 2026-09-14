"""tests/test_oauth_context_analyzer.py — Stage R48.2 tests.

Deterministic, offline tests for the OAuth context analyzer:

- OAuth version, flow, client type and actor/parameter detection
- redirect URI, state, nonce, PKCE, authorization-code, client
  authentication, scope, resource/audience, issuer, token validation,
  refresh-token, consent and CSRF reasoning
- implicit-flow handling and token-exposure handling
- deterministic normalization and malformed-input degradation
- confidence calibration (technology presence is never HIGH)
- observed vs inferred vs not-provided distinction
- schema validation and extra-field rejection
- R48 AST safety scan and standalone backend decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no OAuth flow, no redirect following, no token exchange, no
payloads, no Mongo writes, no persistence, no execution of any kind.
"""
import ast
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.oauth_context_analyzer import (
    analyze_oauth_context,
    authorization_code_flow_present,
    control_observed,
    interactive_flow_present,
    oauth_context_confidence_of,
    oauth_context_present,
    pkce_context_present,
    token_flow_present,
    validation_state_of,
    weakness_observed,
)
from ai.schemas import oauth_context_analysis as schema


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


class TestOAuthContextAnalyzer(unittest.TestCase):
    def test_oauth_version_detection(self):
        for version in ("OAUTH2", "OAUTH2_1"):
            analysis = analyze_oauth_context(oauth_version=version)
            self.assertEqual(analysis["oauth_version"], version)
        self.assertEqual(
            analyze_oauth_context(
                oauth_version="oauth2"
            )["oauth_version"],
            "OAUTH2",
        )
        self.assertEqual(
            analyze_oauth_context()["oauth_version"], "UNKNOWN"
        )

    def test_flow_detection(self):
        for flow in schema.KNOWN_OAUTH_FLOWS:
            analysis = analyze_oauth_context(flow=flow)
            self.assertEqual(analysis["flow"], flow)
        self.assertEqual(analyze_oauth_context()["flow"], "UNKNOWN")
        self.assertTrue(
            interactive_flow_present(
                analyze_oauth_context(flow="AUTHORIZATION_CODE_PKCE")
            )
        )
        self.assertFalse(
            interactive_flow_present(
                analyze_oauth_context(flow="CLIENT_CREDENTIALS")
            )
        )
        self.assertTrue(
            authorization_code_flow_present(
                analyze_oauth_context(flow="AUTHORIZATION_CODE")
            )
        )
        self.assertTrue(
            token_flow_present(
                analyze_oauth_context(flow="CLIENT_CREDENTIALS")
            )
        )
        self.assertTrue(
            pkce_context_present(
                analyze_oauth_context(client_type="PUBLIC_CLIENT")
            )
        )

    def test_client_type_detection(self):
        self.assertEqual(
            analyze_oauth_context(
                client_type="PUBLIC_CLIENT"
            )["client_type"],
            "PUBLIC_CLIENT",
        )
        self.assertEqual(
            analyze_oauth_context(
                client_type="CONFIDENTIAL_CLIENT"
            )["client_type"],
            "CONFIDENTIAL_CLIENT",
        )
        self.assertEqual(
            analyze_oauth_context()["client_type"], "UNKNOWN"
        )

    def test_valid_context_analysis(self):
        analysis = analyze_oauth_context(
            oauth_version="OAUTH2_1",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            authorization_server_context="OBSERVED",
            resource_server_context="OBSERVED",
            authorization_endpoint="OBSERVED",
            token_endpoint="OBSERVED",
            redirect_uri="OBSERVED",
            client_id="OBSERVED",
            response_type="CODE",
            grant_type="AUTHORIZATION_CODE",
            scope_context="OBSERVED",
            state_parameter="OBSERVED",
            nonce_parameter="OBSERVED",
            pkce_challenge="OBSERVED",
            redirect_uri_registration="EXACT_REGISTERED",
            authorization_boundary="SERVER_SIDE_ENFORCED_OBSERVED",
            session_integration="SERVER_SIDE_SESSION_OBSERVED",
        )
        self.assertEqual(analysis["oauth_version"], "OAUTH2_1")
        self.assertEqual(analysis["flow"], "AUTHORIZATION_CODE_PKCE")
        self.assertEqual(analysis["client_type"], "PUBLIC_CLIENT")
        self.assertEqual(
            analysis["response_type"], "CODE"
        )
        self.assertEqual(
            analysis["grant_type"], "AUTHORIZATION_CODE"
        )
        self.assertEqual(
            analysis["redirect_uri_registration"], "EXACT_REGISTERED"
        )
        self.assertTrue(oauth_context_present(analysis))

    def test_malformed_input_degrades(self):
        analysis = analyze_oauth_context(
            oauth_version="NOPE",
            flow=42,
            client_type=["PUBLIC_CLIENT"],
            redirect_uri_validation="nope",
            authorization_code_lifetime="eternal",
            token_exposure=object(),
        )
        self.assertEqual(analysis["oauth_version"], "UNKNOWN")
        self.assertEqual(analysis["flow"], "UNKNOWN")
        self.assertEqual(analysis["client_type"], "UNKNOWN")
        self.assertEqual(
            analysis["redirect_uri_validation"], "NOT_PROVIDED"
        )
        self.assertEqual(
            analysis["authorization_code_lifetime"], "UNKNOWN"
        )
        self.assertEqual(analysis["token_exposure"], "UNKNOWN")

    def test_deterministic_normalization(self):
        first = analyze_oauth_context(
            oauth_version=" oauth2 ",
            flow="authorization_code_pkce",
            redirect_uri_validation="enforced_observed",
        )
        second = analyze_oauth_context(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            redirect_uri_validation="ENFORCED_OBSERVED",
        )
        self.assertEqual(first, second)

    def test_confidence_calibration(self):
        self.assertEqual(
            analyze_oauth_context()["context_confidence"], "UNKNOWN"
        )
        oauth_only = analyze_oauth_context(oauth_version="OAUTH2")
        self.assertEqual(oauth_only["context_confidence"], "LOW")
        flow_only = analyze_oauth_context(flow="AUTHORIZATION_CODE")
        self.assertEqual(flow_only["context_confidence"], "LOW")
        self.assertNotEqual(
            flow_only["context_confidence"], "HIGH"
        )
        self.assertNotEqual(
            analyze_oauth_context(
                redirect_uri="OBSERVED"
            )["context_confidence"],
            "HIGH",
        )
        self.assertNotEqual(
            analyze_oauth_context(
                state_parameter="OBSERVED"
            )["context_confidence"],
            "HIGH",
        )
        self.assertNotEqual(
            analyze_oauth_context(
                pkce_challenge="OBSERVED"
            )["context_confidence"],
            "HIGH",
        )

    def test_technology_presence_is_not_weakness(self):
        analysis = analyze_oauth_context(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            redirect_uri="OBSERVED",
            client_id="OBSERVED",
            state_parameter="OBSERVED",
            pkce_challenge="OBSERVED",
            scope_context="OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))
        self.assertFalse(control_observed(analysis))

    def test_observed_control_is_medium(self):
        analysis = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            state_validation="ENFORCED_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "MEDIUM")
        self.assertTrue(control_observed(analysis))
        self.assertFalse(weakness_observed(analysis))

    def test_observed_weakness_is_high(self):
        analysis = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            redirect_uri_validation="ABSENT_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "HIGH")
        self.assertTrue(weakness_observed(analysis))

    def test_not_provided_is_not_weakness(self):
        analysis = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            state_validation="NOT_PROVIDED",
            csrf_protection="NOT_PROVIDED",
            login_csrf_protection="NOT_PROVIDED",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))

    def test_redirect_uri_reasoning(self):
        absent = analyze_oauth_context(
            redirect_uri="OBSERVED",
            redirect_uri_validation="ABSENT_OBSERVED",
        )
        enforced = analyze_oauth_context(
            redirect_uri="OBSERVED",
            redirect_uri_validation="ENFORCED_OBSERVED",
        )
        wildcard = analyze_oauth_context(
            redirect_uri="OBSERVED",
            redirect_uri_registration="WILDCARD_REGISTERED",
        )
        self.assertTrue(weakness_observed(absent))
        self.assertFalse(weakness_observed(enforced))
        self.assertTrue(weakness_observed(wildcard))
        self.assertTrue(control_observed(enforced))

    def test_state_reasoning(self):
        absent = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            state_parameter="OBSERVED",
            state_validation="ABSENT_OBSERVED",
        )
        enforced = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            state_parameter="OBSERVED",
            state_validation="ENFORCED_OBSERVED",
        )
        presence_only = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            state_parameter="OBSERVED",
        )
        self.assertTrue(weakness_observed(absent))
        self.assertFalse(weakness_observed(enforced))
        self.assertFalse(weakness_observed(presence_only))

    def test_nonce_reasoning(self):
        absent = analyze_oauth_context(
            flow="IMPLICIT",
            nonce_parameter="OBSERVED",
            nonce_validation="ABSENT_OBSERVED",
        )
        enforced = analyze_oauth_context(
            flow="IMPLICIT",
            nonce_parameter="OBSERVED",
            nonce_validation="ENFORCED_OBSERVED",
        )
        self.assertTrue(weakness_observed(absent))
        self.assertFalse(weakness_observed(enforced))

    def test_pkce_reasoning(self):
        not_enforced = analyze_oauth_context(
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            pkce_challenge="OBSERVED",
            pkce_enforcement="ABSENT_OBSERVED",
        )
        enforced = analyze_oauth_context(
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            pkce_challenge="OBSERVED",
            pkce_enforcement="ENFORCED_OBSERVED",
            pkce_verifier_validation="ENFORCED_OBSERVED",
        )
        self.assertTrue(weakness_observed(not_enforced))
        self.assertFalse(weakness_observed(enforced))
        self.assertTrue(control_observed(enforced))

    def test_authorization_code_reasoning(self):
        reuse_absent = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            code_reuse_control="ABSENT_OBSERVED",
        )
        binding_absent = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            authorization_code_binding="ABSENT_OBSERVED",
        )
        unbounded = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            authorization_code_lifetime="UNBOUNDED_OBSERVED",
        )
        short = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            authorization_code_lifetime="SHORT_OBSERVED",
        )
        self.assertTrue(weakness_observed(reuse_absent))
        self.assertTrue(weakness_observed(binding_absent))
        self.assertTrue(weakness_observed(unbounded))
        self.assertFalse(weakness_observed(short))

    def test_client_authentication_reasoning(self):
        absent = analyze_oauth_context(
            client_type="CONFIDENTIAL_CLIENT",
            client_authentication="ABSENT_OBSERVED",
        )
        enforced = analyze_oauth_context(
            client_type="CONFIDENTIAL_CLIENT",
            client_authentication="ENFORCED_OBSERVED",
        )
        public = analyze_oauth_context(
            client_type="PUBLIC_CLIENT",
            client_authentication="NOT_PROVIDED",
        )
        self.assertTrue(weakness_observed(absent))
        self.assertTrue(control_observed(enforced))
        self.assertFalse(weakness_observed(public))

    def test_scope_reasoning(self):
        absent = analyze_oauth_context(
            scope_context="OBSERVED",
            scope_validation="ABSENT_OBSERVED",
        )
        enforced = analyze_oauth_context(
            scope_context="OBSERVED",
            scope_validation="ENFORCED_OBSERVED",
        )
        presence_only = analyze_oauth_context(scope_context="OBSERVED")
        self.assertTrue(weakness_observed(absent))
        self.assertFalse(weakness_observed(enforced))
        self.assertFalse(weakness_observed(presence_only))

    def test_resource_audience_reasoning(self):
        absent = analyze_oauth_context(
            resource_server_context="OBSERVED",
            resource_audience_validation="ABSENT_OBSERVED",
        )
        enforced = analyze_oauth_context(
            resource_server_context="OBSERVED",
            resource_audience_validation="ENFORCED_OBSERVED",
        )
        self.assertTrue(weakness_observed(absent))
        self.assertTrue(control_observed(enforced))

    def test_issuer_and_token_validation_reasoning(self):
        issuer = analyze_oauth_context(
            authorization_server_context="OBSERVED",
            issuer_validation="ABSENT_OBSERVED",
        )
        token = analyze_oauth_context(
            token_endpoint="OBSERVED",
            token_validation="ABSENT_OBSERVED",
        )
        self.assertTrue(weakness_observed(issuer))
        self.assertTrue(weakness_observed(token))

    def test_refresh_token_reasoning(self):
        rotation = analyze_oauth_context(
            refresh_token_present="OBSERVED",
            refresh_token_rotation="ABSENT_OBSERVED",
        )
        revocation = analyze_oauth_context(
            refresh_token_present="OBSERVED",
            refresh_token_revocation="ABSENT_OBSERVED",
        )
        controlled = analyze_oauth_context(
            refresh_token_present="OBSERVED",
            refresh_token_rotation="ENFORCED_OBSERVED",
            refresh_token_revocation="ENFORCED_OBSERVED",
        )
        presence_only = analyze_oauth_context(
            refresh_token_present="OBSERVED"
        )
        self.assertTrue(weakness_observed(rotation))
        self.assertTrue(weakness_observed(revocation))
        self.assertFalse(weakness_observed(controlled))
        self.assertFalse(weakness_observed(presence_only))

    def test_consent_reasoning(self):
        absent = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            consent_control="ABSENT_OBSERVED",
        )
        enforced = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            consent_control="ENFORCED_OBSERVED",
        )
        self.assertTrue(weakness_observed(absent))
        self.assertTrue(control_observed(enforced))

    def test_csrf_reasoning(self):
        absent = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            csrf_protection="ABSENT_OBSERVED",
        )
        enforced = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            csrf_protection="ENFORCED_OBSERVED",
        )
        login_absent = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            login_csrf_protection="ABSENT_OBSERVED",
        )
        self.assertTrue(weakness_observed(absent))
        self.assertFalse(weakness_observed(enforced))
        self.assertTrue(weakness_observed(login_absent))

    def test_implicit_flow_context(self):
        implicit = analyze_oauth_context(
            flow="IMPLICIT", response_type="TOKEN"
        )
        self.assertEqual(implicit["flow"], "IMPLICIT")
        self.assertEqual(implicit["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(implicit))

    def test_token_exposure_reasoning(self):
        exposed = analyze_oauth_context(
            flow="AUTHORIZATION_CODE_PKCE",
            token_exposure="URL_EXPOSURE_OBSERVED",
        )
        none = analyze_oauth_context(
            flow="AUTHORIZATION_CODE_PKCE",
            token_exposure="NONE_OBSERVED",
        )
        self.assertTrue(weakness_observed(exposed))
        self.assertFalse(weakness_observed(none))

    def test_isolated_risk_without_oauth_context_is_not_high(self):
        for analysis in (
            analyze_oauth_context(
                token_exposure="URL_EXPOSURE_OBSERVED"
            ),
            analyze_oauth_context(
                session_integration="CLIENT_SIDE_SESSION_OBSERVED"
            ),
            analyze_oauth_context(
                authorization_boundary="CLIENT_SIDE_ONLY_OBSERVED"
            ),
            analyze_oauth_context(
                redirect_uri_validation="ABSENT_OBSERVED"
            ),
            analyze_oauth_context(
                state_validation="ABSENT_OBSERVED"
            ),
        ):
            self.assertNotEqual(
                analysis["context_confidence"], "HIGH"
            )
            self.assertFalse(weakness_observed(analysis))

    def test_missing_context_handling(self):
        analysis = analyze_oauth_context()
        self.assertFalse(oauth_context_present(analysis))
        self.assertEqual(analysis["context_confidence"], "UNKNOWN")
        partial = analyze_oauth_context(flow="AUTHORIZATION_CODE")
        self.assertTrue(oauth_context_present(partial))

    def test_validation_state_helper(self):
        analysis = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            state_validation="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            validation_state_of(analysis, "state_validation"),
            "ENFORCED_OBSERVED",
        )
        self.assertEqual(
            validation_state_of(analysis, "csrf_protection"),
            "NOT_PROVIDED",
        )
        self.assertEqual(
            validation_state_of(analysis, "nope"), "UNKNOWN"
        )

    def test_confidence_recompute_ignores_stored_value(self):
        analysis = analyze_oauth_context(
            flow="AUTHORIZATION_CODE",
            state_validation="ABSENT_OBSERVED",
        )
        forged = copy.deepcopy(analysis)
        forged["context_confidence"] = "UNKNOWN"
        self.assertEqual(
            oauth_context_confidence_of(forged), "HIGH"
        )
        downgraded = copy.deepcopy(analysis)
        downgraded["context_confidence"] = "LOW"
        self.assertEqual(
            oauth_context_confidence_of(downgraded), "HIGH"
        )

    def test_schema_rejects_bad_values_and_extra(self):
        base = analyze_oauth_context(flow="AUTHORIZATION_CODE")
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "flow": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "oauth_version": "OAUTH1"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "state_validation": "MAYBE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "client_type": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "authorization_code_lifetime": "ETERNAL"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "token_exposure": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "authorization_boundary": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "session_integration": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthContextAnalysisPlan(
                **{**base, "redirect": "https://example"}
            )

    def test_schema_forces_rule_version(self):
        plan = schema.OAuthContextAnalysisPlan(
            **{
                **analyze_oauth_context(),
                "rule_version": "r99-9",
            }
        )
        self.assertEqual(plan.rule_version, "r48-2")

    def test_deterministic_serialization(self):
        first = json.dumps(
            analyze_oauth_context(
                oauth_version="OAUTH2_1",
                flow="AUTHORIZATION_CODE_PKCE",
                client_type="PUBLIC_CLIENT",
                state_validation="ABSENT_OBSERVED",
            ),
            sort_keys=True,
        )
        second = json.dumps(
            analyze_oauth_context(
                oauth_version="OAUTH2_1",
                flow="AUTHORIZATION_CODE_PKCE",
                client_type="PUBLIC_CLIENT",
                state_validation="ABSENT_OBSERVED",
            ),
            sort_keys=True,
        )
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())

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
