"""tests/test_oauth_evidence_planner.py — Stage R48.4 tests.

Deterministic, offline tests for the OAuth evidence planner:

- closed evidence vocabulary and per-hypothesis evidence mapping
- evidence requirements are planning only, never collection
- deterministic planning state and confidence calibration
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
from ai.knowledge.oauth_evidence_planner import (
    HYPOTHESIS_EVIDENCE,
    plan_oauth_evidence,
)
from ai.knowledge.oauth_hypothesis_planner import plan_oauth_hypotheses
from ai.schemas import oauth_evidence_plan as schema
from ai.schemas.oauth_evidence_plan import (
    EVIDENCE_AUTHORIZATION_CODE_BINDING,
    EVIDENCE_AUTHORIZATION_CODE_LIFETIME,
    EVIDENCE_AUTHORIZATION_CODE_ONE_TIME_USE,
    EVIDENCE_AUTHORIZATION_CODE_REPLAY_CONTROLS,
    EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION,
    EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION,
    EVIDENCE_CLIENT_AUTHENTICATION_METHOD,
    EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION,
    EVIDENCE_CLIENT_TYPE,
    EVIDENCE_CONSENT_CONFIGURATION,
    EVIDENCE_CSRF_REQUEST_BINDING,
    EVIDENCE_GRANTED_SCOPES,
    EVIDENCE_ISSUER_CONFIGURATION,
    EVIDENCE_LOGIN_CSRF_SESSION_BINDING,
    EVIDENCE_NONCE_VALIDATION_BEHAVIOR,
    EVIDENCE_PKCE_CHALLENGE_METHOD,
    EVIDENCE_PKCE_ENFORCEMENT_POLICY,
    EVIDENCE_PKCE_VERIFIER_VALIDATION,
    EVIDENCE_REDIRECT_HANDLING_CONFIGURATION,
    EVIDENCE_REDIRECT_URI_MATCHING_POLICY,
    EVIDENCE_REDIRECT_URI_REGISTRATION,
    EVIDENCE_REDIRECT_URI_VALIDATION_BEHAVIOR,
    EVIDENCE_REFRESH_TOKEN_REUSE_DETECTION,
    EVIDENCE_REFRESH_TOKEN_REVOCATION_POLICY,
    EVIDENCE_REFRESH_TOKEN_ROTATION_POLICY,
    EVIDENCE_REQUESTED_SCOPES,
    EVIDENCE_RESOURCE_INDICATOR_CONFIGURATION,
    EVIDENCE_SCOPE_VALIDATION_POLICY,
    EVIDENCE_STATE_GENERATION,
    EVIDENCE_STATE_SESSION_BINDING,
    EVIDENCE_STATE_VALIDATION_BEHAVIOR,
    EVIDENCE_TOKEN_EXPOSURE_CONTEXT,
    EVIDENCE_TOKEN_STORAGE_MECHANISM,
    EVIDENCE_TOKEN_VALIDATION_CONFIGURATION,
    EVIDENCE_UNKNOWN,
)
from ai.schemas.oauth_hypothesis import (
    HYPOTHESIS_TYPES,
    TYPE_AUTHORIZATION_CODE_LIFETIME_RISK,
    TYPE_AUTHORIZATION_CODE_REUSE_GAP,
    TYPE_AUTHORIZATION_CODE_VALIDATION_GAP,
    TYPE_AUTHORIZATION_FLOW_GAP,
    TYPE_CLIENT_AUTHENTICATION_GAP,
    TYPE_CLIENT_CONFIGURATION_GAP,
    TYPE_CONSENT_CONTROL_GAP,
    TYPE_CSRF_PROTECTION_GAP,
    TYPE_IMPLICIT_FLOW_RISK,
    TYPE_ISSUER_VALIDATION_GAP,
    TYPE_LOGIN_CSRF_GAP,
    TYPE_MISSING_OAUTH_CONTEXT,
    TYPE_NONCE_VALIDATION_GAP,
    TYPE_PKCE_ENFORCEMENT_GAP,
    TYPE_PKCE_VERIFIER_VALIDATION_GAP,
    TYPE_REDIRECT_HANDLING_RISK,
    TYPE_REDIRECT_URI_VALIDATION_GAP,
    TYPE_REFRESH_TOKEN_REVOCATION_GAP,
    TYPE_REFRESH_TOKEN_ROTATION_GAP,
    TYPE_RESOURCE_AUDIENCE_VALIDATION_GAP,
    TYPE_SCOPE_VALIDATION_GAP,
    TYPE_STATE_VALIDATION_GAP,
    TYPE_TOKEN_EXPOSURE_RISK,
    TYPE_TOKEN_VALIDATION_GAP,
    TYPE_UNKNOWN,
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


def rich_context():
    return analyze_oauth_context(
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
        redirect_uri_validation="ENFORCED_OBSERVED",
        exact_redirect_matching="ENFORCED_OBSERVED",
        state_validation="ENFORCED_OBSERVED",
        pkce_enforcement="ENFORCED_OBSERVED",
        pkce_verifier_validation="ENFORCED_OBSERVED",
        csrf_protection="ENFORCED_OBSERVED",
        consent_control="ENFORCED_OBSERVED",
        authorization_boundary="SERVER_SIDE_ENFORCED_OBSERVED",
    )


class TestOAuthEvidencePlanner(unittest.TestCase):
    def test_evidence_vocabulary_is_closed(self):
        self.assertEqual(len(schema.OAUTH_EVIDENCE_ITEMS), 36)
        self.assertEqual(
            len(set(schema.OAUTH_EVIDENCE_ITEMS)), 36
        )
        self.assertEqual(schema.OAUTH_EVIDENCE_ITEMS[-1], EVIDENCE_UNKNOWN)
        for limitation in (
            "NO_COLLECTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_OAUTH_FLOW_EXECUTION",
            "NO_TOKEN_EXCHANGE",
            "NO_REDIRECT_FOLLOWING",
            "NO_CREDENTIAL_TESTING",
            "NO_PAYLOAD_GENERATION",
            "EVIDENCE_REQUIRED",
            "INSUFFICIENT_CONTEXT",
        ):
            self.assertIn(
                limitation, schema.OAUTH_EVIDENCE_LIMITATIONS
            )

    def test_mapping_covers_every_hypothesis(self):
        for hypothesis_type in HYPOTHESIS_TYPES:
            self.assertIn(hypothesis_type, HYPOTHESIS_EVIDENCE)
            for item in HYPOTHESIS_EVIDENCE[hypothesis_type]:
                self.assertIn(item, schema.OAUTH_EVIDENCE_ITEMS)

    def test_redirect_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_REDIRECT_URI_VALIDATION_GAP]
        self.assertIn(EVIDENCE_REDIRECT_URI_REGISTRATION, evidence)
        self.assertIn(EVIDENCE_REDIRECT_URI_MATCHING_POLICY, evidence)
        self.assertIn(EVIDENCE_REDIRECT_URI_VALIDATION_BEHAVIOR, evidence)

    def test_state_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_STATE_VALIDATION_GAP]
        self.assertIn(EVIDENCE_STATE_GENERATION, evidence)
        self.assertIn(EVIDENCE_STATE_SESSION_BINDING, evidence)
        self.assertIn(EVIDENCE_STATE_VALIDATION_BEHAVIOR, evidence)

    def test_nonce_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_NONCE_VALIDATION_GAP]
        self.assertIn(EVIDENCE_NONCE_VALIDATION_BEHAVIOR, evidence)
        self.assertIn(EVIDENCE_STATE_SESSION_BINDING, evidence)

    def test_pkce_evidence(self):
        enforcement = HYPOTHESIS_EVIDENCE[TYPE_PKCE_ENFORCEMENT_GAP]
        self.assertIn(EVIDENCE_PKCE_ENFORCEMENT_POLICY, enforcement)
        self.assertIn(EVIDENCE_PKCE_CHALLENGE_METHOD, enforcement)
        verifier = HYPOTHESIS_EVIDENCE[
            TYPE_PKCE_VERIFIER_VALIDATION_GAP
        ]
        self.assertIn(EVIDENCE_PKCE_VERIFIER_VALIDATION, verifier)

    def test_authorization_code_evidence(self):
        binding = HYPOTHESIS_EVIDENCE[
            TYPE_AUTHORIZATION_CODE_VALIDATION_GAP
        ]
        self.assertIn(EVIDENCE_AUTHORIZATION_CODE_BINDING, binding)
        self.assertIn(EVIDENCE_AUTHORIZATION_CODE_LIFETIME, binding)
        self.assertIn(EVIDENCE_AUTHORIZATION_CODE_ONE_TIME_USE, binding)
        reuse = HYPOTHESIS_EVIDENCE[TYPE_AUTHORIZATION_CODE_REUSE_GAP]
        self.assertIn(EVIDENCE_AUTHORIZATION_CODE_REPLAY_CONTROLS, reuse)
        lifetime = HYPOTHESIS_EVIDENCE[
            TYPE_AUTHORIZATION_CODE_LIFETIME_RISK
        ]
        self.assertIn(EVIDENCE_AUTHORIZATION_CODE_LIFETIME, lifetime)

    def test_client_authentication_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_CLIENT_AUTHENTICATION_GAP]
        self.assertIn(EVIDENCE_CLIENT_TYPE, evidence)
        self.assertIn(EVIDENCE_CLIENT_AUTHENTICATION_METHOD, evidence)
        self.assertIn(EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION, evidence)

    def test_client_configuration_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_CLIENT_CONFIGURATION_GAP]
        self.assertIn(EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION, evidence)
        self.assertIn(EVIDENCE_REDIRECT_URI_REGISTRATION, evidence)

    def test_scope_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_SCOPE_VALIDATION_GAP]
        self.assertIn(EVIDENCE_REQUESTED_SCOPES, evidence)
        self.assertIn(EVIDENCE_GRANTED_SCOPES, evidence)
        self.assertIn(EVIDENCE_SCOPE_VALIDATION_POLICY, evidence)

    def test_resource_and_issuer_evidence(self):
        resource = HYPOTHESIS_EVIDENCE[
            TYPE_RESOURCE_AUDIENCE_VALIDATION_GAP
        ]
        self.assertIn(EVIDENCE_RESOURCE_INDICATOR_CONFIGURATION, resource)
        issuer = HYPOTHESIS_EVIDENCE[TYPE_ISSUER_VALIDATION_GAP]
        self.assertIn(EVIDENCE_ISSUER_CONFIGURATION, issuer)
        self.assertIn(
            EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION, issuer
        )
        token = HYPOTHESIS_EVIDENCE[TYPE_TOKEN_VALIDATION_GAP]
        self.assertIn(EVIDENCE_TOKEN_VALIDATION_CONFIGURATION, token)

    def test_refresh_evidence(self):
        rotation = HYPOTHESIS_EVIDENCE[
            TYPE_REFRESH_TOKEN_ROTATION_GAP
        ]
        self.assertIn(EVIDENCE_REFRESH_TOKEN_ROTATION_POLICY, rotation)
        self.assertIn(EVIDENCE_REFRESH_TOKEN_REUSE_DETECTION, rotation)
        revocation = HYPOTHESIS_EVIDENCE[
            TYPE_REFRESH_TOKEN_REVOCATION_GAP
        ]
        self.assertIn(EVIDENCE_REFRESH_TOKEN_REVOCATION_POLICY, revocation)

    def test_consent_and_csrf_evidence(self):
        consent = HYPOTHESIS_EVIDENCE[TYPE_CONSENT_CONTROL_GAP]
        self.assertIn(EVIDENCE_CONSENT_CONFIGURATION, consent)
        csrf = HYPOTHESIS_EVIDENCE[TYPE_CSRF_PROTECTION_GAP]
        self.assertIn(EVIDENCE_CSRF_REQUEST_BINDING, csrf)
        login_csrf = HYPOTHESIS_EVIDENCE[TYPE_LOGIN_CSRF_GAP]
        self.assertIn(EVIDENCE_LOGIN_CSRF_SESSION_BINDING, login_csrf)

    def test_implicit_and_exposure_evidence(self):
        implicit = HYPOTHESIS_EVIDENCE[TYPE_IMPLICIT_FLOW_RISK]
        self.assertIn(EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION, implicit)
        self.assertIn(EVIDENCE_TOKEN_STORAGE_MECHANISM, implicit)
        exposure = HYPOTHESIS_EVIDENCE[TYPE_TOKEN_EXPOSURE_RISK]
        self.assertIn(EVIDENCE_TOKEN_STORAGE_MECHANISM, exposure)
        self.assertIn(EVIDENCE_TOKEN_EXPOSURE_CONTEXT, exposure)

    def test_redirect_handling_and_flow_evidence(self):
        handling = HYPOTHESIS_EVIDENCE[TYPE_REDIRECT_HANDLING_RISK]
        self.assertIn(EVIDENCE_REDIRECT_HANDLING_CONFIGURATION, handling)
        flow_gap = HYPOTHESIS_EVIDENCE[TYPE_AUTHORIZATION_FLOW_GAP]
        self.assertIn(EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION, flow_gap)

    def test_control_present_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[
            "AUTHENTICATION_CONTROL_PRESENT"
        ]
        self.assertIn(
            EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION, evidence
        )
        self.assertIn(EVIDENCE_STATE_VALIDATION_BEHAVIOR, evidence)

    def test_unknown_context_plan(self):
        evidence = plan_oauth_evidence(analyze_oauth_context())
        self.assertEqual(evidence["evidence_items"], [EVIDENCE_UNKNOWN])
        self.assertEqual(evidence["evidence_state"], "UNKNOWN")
        self.assertEqual(evidence["confidence"], "UNKNOWN")
        self.assertIn("INSUFFICIENT_CONTEXT", evidence["limitations"])

    def test_partial_plan_for_needs_evidence(self):
        context = analyze_oauth_context(
            oauth_version="OAUTH2", flow="AUTHORIZATION_CODE"
        )
        evidence = plan_oauth_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        self.assertIn(
            EVIDENCE_REDIRECT_URI_REGISTRATION,
            evidence["evidence_items"],
        )
        self.assertFalse(
            any(
                item == EVIDENCE_UNKNOWN
                for item in evidence["evidence_items"]
            )
        )

    def test_complete_plan_for_observed_weakness(self):
        context = analyze_oauth_context(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE_PKCE",
            client_type="PUBLIC_CLIENT",
            redirect_uri_validation="ABSENT_OBSERVED",
            state_validation="ABSENT_OBSERVED",
            pkce_enforcement="ABSENT_OBSERVED",
        )
        self.assertEqual(context["context_confidence"], "HIGH")
        evidence = plan_oauth_evidence(context)
        self.assertEqual(evidence["evidence_state"], "COMPLETE")
        self.assertEqual(evidence["confidence"], "HIGH")

    def test_isolated_weakness_signal_is_not_complete(self):
        context = analyze_oauth_context(
            redirect_uri_validation="ABSENT_OBSERVED"
        )
        self.assertNotEqual(context["context_confidence"], "HIGH")
        evidence = plan_oauth_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")

    def test_missing_context_hypothesis_is_never_complete(self):
        context = analyze_oauth_context(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            state_validation="ABSENT_OBSERVED",
        )
        self.assertEqual(context["context_confidence"], "HIGH")
        evidence = plan_oauth_evidence(
            context,
            [
                {
                    "hypothesis_type": TYPE_MISSING_OAUTH_CONTEXT,
                    "hypothesis_state": "NEEDS_EVIDENCE",
                    "confidence": "LOW",
                    "priority": "LOW",
                }
            ],
        )
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        unknown_only = plan_oauth_evidence(
            context,
            [
                {
                    "hypothesis_type": TYPE_UNKNOWN,
                    "hypothesis_state": "UNKNOWN",
                    "confidence": "UNKNOWN",
                    "priority": "UNKNOWN",
                }
            ],
        )
        self.assertNotEqual(unknown_only["evidence_state"], "COMPLETE")

    def test_control_context_is_partial_conservatively(self):
        context = rich_context()
        self.assertEqual(context["context_confidence"], "MEDIUM")
        evidence = plan_oauth_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        self.assertIn(
            EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION,
            evidence["evidence_items"],
        )

    def test_explicit_hypotheses_are_respected(self):
        context = rich_context()
        manual = plan_oauth_evidence(
            context,
            [
                {
                    "hypothesis_type": TYPE_ISSUER_VALIDATION_GAP,
                    "hypothesis_state": "NEEDS_EVIDENCE",
                    "confidence": "LOW",
                    "priority": "LOW",
                }
            ],
        )
        self.assertEqual(
            manual["evidence_items"],
            list(HYPOTHESIS_EVIDENCE[TYPE_ISSUER_VALIDATION_GAP]),
        )

    def test_evidence_limitations(self):
        evidence = plan_oauth_evidence(analyze_oauth_context())
        for limitation in (
            "NO_COLLECTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_OAUTH_FLOW_EXECUTION",
            "NO_TOKEN_EXCHANGE",
            "NO_REDIRECT_FOLLOWING",
            "NO_CREDENTIAL_TESTING",
            "NO_PAYLOAD_GENERATION",
            "EVIDENCE_REQUIRED",
        ):
            self.assertIn(limitation, evidence["limitations"])
        complete = plan_oauth_evidence(
            analyze_oauth_context(
                oauth_version="OAUTH2",
                flow="AUTHORIZATION_CODE",
                state_validation="ABSENT_OBSERVED",
            )
        )
        self.assertNotIn(
            "INSUFFICIENT_CONTEXT", complete["limitations"]
        )

    def test_generated_evidence_plan_matches_hypotheses(self):
        context = analyze_oauth_context(
            oauth_version="OAUTH2",
            flow="AUTHORIZATION_CODE",
            state_validation="ABSENT_OBSERVED",
            csrf_protection="ABSENT_OBSERVED",
        )
        hypotheses = plan_oauth_hypotheses(context)
        evidence = plan_oauth_evidence(context, hypotheses)
        expected: list[str] = []
        for hypothesis in hypotheses:
            for item in HYPOTHESIS_EVIDENCE[hypothesis["hypothesis_type"]]:
                if item not in expected:
                    expected.append(item)
        self.assertEqual(evidence["evidence_items"], expected)

    def test_schema_rejects_bad_values_and_extra(self):
        base = plan_oauth_evidence(
            analyze_oauth_context(
                oauth_version="OAUTH2", flow="AUTHORIZATION_CODE"
            )
        )
        with self.assertRaises(ValidationError):
            schema.OAuthEvidencePlan(
                **{**base, "evidence_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthEvidencePlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthEvidencePlan(
                **{**base, "evidence_items": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthEvidencePlan(
                **{**base, "limitations": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthEvidencePlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.OAuthEvidencePlan(**{**base, "token": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.OAuthEvidencePlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r48-4")

    def test_deterministic_serialization(self):
        first = json.dumps(
            plan_oauth_evidence(
                analyze_oauth_context(
                    oauth_version="OAUTH2",
                    flow="AUTHORIZATION_CODE",
                    state_validation="ABSENT_OBSERVED",
                )
            ),
            sort_keys=True,
        )
        second = json.dumps(
            plan_oauth_evidence(
                analyze_oauth_context(
                    oauth_version="OAUTH2",
                    flow="AUTHORIZATION_CODE",
                    state_validation="ABSENT_OBSERVED",
                )
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
