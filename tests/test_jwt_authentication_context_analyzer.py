"""tests/test_jwt_authentication_context_analyzer.py — Stage R47.2 tests.

Deterministic, offline tests for the JWT/authentication context analyzer:

- JWT and authentication mechanism detection
- validation, key, storage, refresh, revocation and session reasoning
- deterministic normalization and malformed-input degradation
- confidence calibration (technology presence is never HIGH)
- observed vs inferred vs not-provided distinction
- schema validation and extra-field rejection
- R47 AST safety scan and standalone backend decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
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

from ai.knowledge.jwt_authentication_context_analyzer import (
    analyze_jwt_authentication_context,
    authentication_context_present,
    control_observed,
    cookie_security_incomplete,
    jwt_authentication_context_confidence_of,
    jwt_present,
    token_present,
    validation_state_of,
    weakness_observed,
)
from ai.schemas import jwt_authentication_context_analysis as schema


ROOT = Path(__file__).resolve().parents[1]

R47_MODULES = (
    "ai/schemas/jwt_authentication_agent_identity.py",
    "ai/schemas/jwt_authentication_context_analysis.py",
    "ai/schemas/jwt_authentication_hypothesis.py",
    "ai/schemas/jwt_authentication_evidence_plan.py",
    "ai/schemas/jwt_authentication_agent_result.py",
    "ai/schemas/jwt_authentication_agent.py",
    "ai/knowledge/jwt_authentication_agent_identity.py",
    "ai/knowledge/jwt_authentication_context_analyzer.py",
    "ai/knowledge/jwt_authentication_hypothesis_planner.py",
    "ai/knowledge/jwt_authentication_evidence_planner.py",
    "ai/knowledge/jwt_authentication_agent_result_export.py",
    "ai/knowledge/jwt_authentication_agent.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "asyncio", "threading", "multiprocessing", "concurrent",
    "importlib", "ctypes", "shutil", "ssl", "os", "dns", "selenium",
    "playwright", "pyppeteer", "paramiko", "sqlite3", "sqlalchemy",
    "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap", "nuclei",
    "curl", "pycurl", "openai", "ollama", "litellm", "anthropic",
    "openrouter", "jwt", "pyjwt", "jose",
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


class TestJWTAuthenticationContextAnalyzer(unittest.TestCase):
    def test_jwt_detection(self):
        self.assertTrue(
            jwt_present(
                analyze_jwt_authentication_context(
                    token_mechanism="JWT"
                )
            )
        )
        self.assertTrue(
            jwt_present(
                analyze_jwt_authentication_context(
                    token_format="COMPACT_JWS"
                )
            )
        )
        self.assertTrue(
            jwt_present(
                analyze_jwt_authentication_context(
                    signing_algorithm="RS256"
                )
            )
        )
        self.assertTrue(
            jwt_present(
                analyze_jwt_authentication_context(
                    signing_method="ASYMMETRIC"
                )
            )
        )
        self.assertFalse(
            jwt_present(
                analyze_jwt_authentication_context(
                    authentication_mechanism="COOKIE_SESSION"
                )
            )
        )
        self.assertFalse(jwt_present(analyze_jwt_authentication_context()))

    def test_authentication_mechanism_detection(self):
        analysis = analyze_jwt_authentication_context(
            authentication_mechanism="bearer_token"
        )
        self.assertEqual(analysis["authentication_mechanism"],
                         "BEARER_TOKEN")
        self.assertTrue(token_present(analysis))
        self.assertTrue(authentication_context_present(analysis))
        for mechanism in schema.KNOWN_AUTHENTICATION_MECHANISMS:
            resolved = analyze_jwt_authentication_context(
                authentication_mechanism=mechanism
            )
            self.assertEqual(
                resolved["authentication_mechanism"], mechanism
            )

    def test_valid_context_analysis(self):
        analysis = analyze_jwt_authentication_context(
            authentication_mechanism="JWT_BEARER",
            token_mechanism="JWT",
            token_format="COMPACT_JWS",
            signing_algorithm="RS256",
            signing_method="ASYMMETRIC",
            signature_verification="ENFORCED_OBSERVED",
            issuer_validation="ENFORCED_OBSERVED",
            audience_validation="ENFORCED_OBSERVED",
            expiration_validation="ENFORCED_OBSERVED",
            key_management="MANAGED_OBSERVED",
            token_lifetime="SHORT_OBSERVED",
            token_storage="MEMORY_ONLY_OBSERVED",
            authorization_boundary="SERVER_SIDE_ENFORCED_OBSERVED",
        )
        self.assertEqual(analysis["rule_version"], "r47-2")
        self.assertEqual(analysis["token_mechanism"], "JWT")
        self.assertEqual(analysis["signing_algorithm"], "RS256")
        self.assertEqual(analysis["context_confidence"], "MEDIUM")
        self.assertIs(analysis["research_only"], True)

    def test_malformed_input_degrades(self):
        analysis = analyze_jwt_authentication_context(
            authentication_mechanism=42,
            token_mechanism=[],
            token_format={"x": 1},
            signature_verification="NOPE",
            key_management="NOPE",
            token_storage="NOPE",
            cookie_attributes="not-a-list",
        )
        self.assertEqual(analysis["authentication_mechanism"], "UNKNOWN")
        self.assertEqual(analysis["token_mechanism"], "UNKNOWN")
        self.assertEqual(analysis["token_format"], "UNKNOWN")
        self.assertEqual(
            analysis["signature_verification"], "NOT_PROVIDED"
        )
        self.assertEqual(analysis["key_management"], "UNKNOWN")
        self.assertEqual(analysis["token_storage"], "UNKNOWN")
        self.assertEqual(analysis["cookie_attributes"], [])
        self.assertEqual(analysis["context_confidence"], "UNKNOWN")

    def test_deterministic_normalization(self):
        analysis = analyze_jwt_authentication_context(
            token_mechanism="jwt",
            signing_algorithm="rs256",
            signature_verification="absent_observed",
            token_storage="local_storage_observed",
            cookie_attributes=["secure", "http_only"],
        )
        self.assertEqual(analysis["token_mechanism"], "JWT")
        self.assertEqual(analysis["signing_algorithm"], "RS256")
        self.assertEqual(
            analysis["signature_verification"], "ABSENT_OBSERVED"
        )
        self.assertEqual(
            analysis["token_storage"], "LOCAL_STORAGE_OBSERVED"
        )
        self.assertEqual(
            analysis["cookie_attributes"], ["SECURE", "HTTP_ONLY"]
        )

    def test_confidence_calibration(self):
        self.assertEqual(
            analyze_jwt_authentication_context()["context_confidence"],
            "UNKNOWN",
        )
        jwt_only = analyze_jwt_authentication_context(
            token_mechanism="JWT"
        )
        self.assertEqual(jwt_only["context_confidence"], "LOW")
        bearer_only = analyze_jwt_authentication_context(
            authentication_mechanism="BEARER_TOKEN"
        )
        self.assertEqual(bearer_only["context_confidence"], "LOW")
        self.assertNotEqual(bearer_only["context_confidence"], "HIGH")
        cookie_only = analyze_jwt_authentication_context(
            authentication_mechanism="COOKIE_SESSION"
        )
        self.assertEqual(cookie_only["context_confidence"], "LOW")
        self.assertNotEqual(cookie_only["context_confidence"], "HIGH")

    def test_technology_presence_is_not_weakness(self):
        analysis = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signing_algorithm="HS256",
            signing_method="SYMMETRIC",
            token_format="COMPACT_JWS",
            authentication_mechanism="JWT_BEARER",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))

    def test_observed_control_is_medium(self):
        analysis = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signature_verification="ENFORCED_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "MEDIUM")
        self.assertTrue(control_observed(analysis))
        self.assertFalse(weakness_observed(analysis))

    def test_observed_weakness_is_high(self):
        analysis = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "HIGH")
        self.assertTrue(weakness_observed(analysis))

    def test_not_provided_is_not_weakness(self):
        analysis = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signature_verification="NOT_PROVIDED",
            issuer_validation="NOT_PROVIDED",
            audience_validation="NOT_PROVIDED",
            expiration_validation="NOT_PROVIDED",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))

    def test_algorithm_reasoning(self):
        alg_none_metadata = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signing_algorithm="NONE",
        )
        self.assertEqual(
            alg_none_metadata["context_confidence"], "LOW"
        )
        alg_none_absent_validation = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signing_algorithm="NONE",
            algorithm_validation="ABSENT_OBSERVED",
        )
        self.assertEqual(
            alg_none_absent_validation["context_confidence"], "HIGH"
        )

    def test_issuer_audience_expiration_reasoning(self):
        issuer = analyze_jwt_authentication_context(
            token_mechanism="JWT", issuer_validation="ABSENT_OBSERVED"
        )
        audience = analyze_jwt_authentication_context(
            token_mechanism="JWT", audience_validation="ABSENT_OBSERVED"
        )
        expiration = analyze_jwt_authentication_context(
            token_mechanism="JWT", expiration_validation="ABSENT_OBSERVED"
        )
        for analysis in (issuer, audience, expiration):
            self.assertEqual(analysis["context_confidence"], "HIGH")
            self.assertTrue(weakness_observed(analysis))

    def test_not_before_and_claim_reasoning(self):
        not_before = analyze_jwt_authentication_context(
            token_mechanism="JWT", not_before_validation="ABSENT_OBSERVED"
        )
        claim = analyze_jwt_authentication_context(
            token_mechanism="JWT", claim_validation="ABSENT_OBSERVED"
        )
        for analysis in (not_before, claim):
            self.assertEqual(analysis["context_confidence"], "HIGH")

    def test_key_management_reasoning(self):
        static = analyze_jwt_authentication_context(
            token_mechanism="JWT", key_management="STATIC_KEY_OBSERVED"
        )
        embedded = analyze_jwt_authentication_context(
            token_mechanism="JWT", key_management="EMBEDDED_KEY_OBSERVED"
        )
        absent = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            key_management="KEY_MANAGEMENT_ABSENT_OBSERVED",
        )
        managed = analyze_jwt_authentication_context(
            token_mechanism="JWT", key_management="MANAGED_OBSERVED"
        )
        for analysis in (static, embedded, absent):
            self.assertTrue(weakness_observed(analysis))
        self.assertTrue(control_observed(managed))
        self.assertEqual(managed["context_confidence"], "MEDIUM")

    def test_token_lifetime_reasoning(self):
        long_lifetime = analyze_jwt_authentication_context(
            token_mechanism="JWT", token_lifetime="LONG_OBSERVED"
        )
        unbounded = analyze_jwt_authentication_context(
            token_mechanism="JWT", token_lifetime="UNBOUNDED_OBSERVED"
        )
        short = analyze_jwt_authentication_context(
            token_mechanism="JWT", token_lifetime="SHORT_OBSERVED"
        )
        self.assertTrue(weakness_observed(long_lifetime))
        self.assertTrue(weakness_observed(unbounded))
        self.assertFalse(weakness_observed(short))

    def test_token_storage_reasoning(self):
        local = analyze_jwt_authentication_context(
            token_mechanism="JWT", token_storage="LOCAL_STORAGE_OBSERVED"
        )
        session = analyze_jwt_authentication_context(
            token_mechanism="JWT", token_storage="SESSION_STORAGE_OBSERVED"
        )
        memory = analyze_jwt_authentication_context(
            token_mechanism="JWT", token_storage="MEMORY_ONLY_OBSERVED"
        )
        self.assertTrue(weakness_observed(local))
        self.assertTrue(weakness_observed(session))
        self.assertTrue(control_observed(memory))
        self.assertFalse(weakness_observed(memory))

    def test_cookie_security_reasoning(self):
        incomplete = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            token_storage="COOKIE_OBSERVED",
            cookie_attributes=["SAME_SITE_STRICT"],
        )
        complete = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            token_storage="COOKIE_OBSERVED",
            cookie_attributes=["SECURE", "HTTP_ONLY", "SAME_SITE_STRICT"],
        )
        self.assertTrue(cookie_security_incomplete(incomplete))
        self.assertTrue(weakness_observed(incomplete))
        self.assertFalse(cookie_security_incomplete(complete))
        self.assertTrue(control_observed(complete))
        self.assertFalse(weakness_observed(complete))

    def test_token_exposure_reasoning(self):
        url = analyze_jwt_authentication_context(
            token_mechanism="JWT", token_exposure="URL_EXPOSURE_OBSERVED"
        )
        none = analyze_jwt_authentication_context(
            token_mechanism="JWT", token_exposure="NONE_OBSERVED"
        )
        self.assertTrue(weakness_observed(url))
        self.assertFalse(weakness_observed(none))

    def test_refresh_and_revocation_reasoning(self):
        refresh_absent_control = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            refresh_token="PRESENT",
            refresh_control="ABSENT_OBSERVED",
        )
        refresh_controlled = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            refresh_token="PRESENT",
            refresh_control="ENFORCED_OBSERVED",
        )
        revocation_absent = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            revocation_control="ABSENT_OBSERVED",
        )
        self.assertTrue(weakness_observed(refresh_absent_control))
        self.assertFalse(weakness_observed(refresh_controlled))
        self.assertTrue(weakness_observed(revocation_absent))

    def test_session_reasoning(self):
        client_side = analyze_jwt_authentication_context(
            authentication_mechanism="COOKIE_SESSION",
            session_lifecycle="CLIENT_SIDE_SESSION_OBSERVED",
        )
        server_side = analyze_jwt_authentication_context(
            authentication_mechanism="COOKIE_SESSION",
            session_lifecycle="SERVER_SIDE_SESSION_OBSERVED",
        )
        stateless_no_revocation = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            session_lifecycle="STATELESS_TOKEN_OBSERVED",
            revocation_control="ABSENT_OBSERVED",
        )
        self.assertTrue(weakness_observed(client_side))
        self.assertTrue(control_observed(server_side))
        self.assertTrue(weakness_observed(stateless_no_revocation))

    def test_stateless_token_alone_is_not_weakness(self):
        stateless_only = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            session_lifecycle="STATELESS_TOKEN_OBSERVED",
        )
        self.assertFalse(weakness_observed(stateless_only))
        self.assertEqual(stateless_only["context_confidence"], "LOW")
        self.assertNotEqual(
            stateless_only["context_confidence"], "HIGH"
        )
        no_context = analyze_jwt_authentication_context(
            session_lifecycle="STATELESS_TOKEN_OBSERVED"
        )
        self.assertFalse(weakness_observed(no_context))
        self.assertEqual(no_context["context_confidence"], "LOW")

    def test_isolated_risk_signal_without_auth_context_is_not_high(self):
        for analysis in (
            analyze_jwt_authentication_context(
                token_lifetime="LONG_OBSERVED"
            ),
            analyze_jwt_authentication_context(
                token_storage="LOCAL_STORAGE_OBSERVED"
            ),
            analyze_jwt_authentication_context(
                token_exposure="URL_EXPOSURE_OBSERVED"
            ),
            analyze_jwt_authentication_context(
                key_management="STATIC_KEY_OBSERVED"
            ),
        ):
            self.assertNotEqual(
                analysis["context_confidence"], "HIGH"
            )
            self.assertFalse(weakness_observed(analysis))

    def test_missing_context_handling(self):
        analysis = analyze_jwt_authentication_context()
        self.assertFalse(authentication_context_present(analysis))
        self.assertEqual(analysis["context_confidence"], "UNKNOWN")
        partial = analyze_jwt_authentication_context(
            authentication_mechanism="BEARER_TOKEN"
        )
        self.assertTrue(authentication_context_present(partial))

    def test_validation_state_helper(self):
        analysis = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            issuer_validation="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            validation_state_of(analysis, "issuer_validation"),
            "ENFORCED_OBSERVED",
        )
        self.assertEqual(
            validation_state_of(analysis, "audience_validation"),
            "NOT_PROVIDED",
        )
        self.assertEqual(
            validation_state_of(analysis, "nope"), "UNKNOWN"
        )

    def test_confidence_recompute_ignores_stored_value(self):
        analysis = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
        )
        tampered = copy.deepcopy(analysis)
        tampered["context_confidence"] = "LOW"
        tampered["signature_verification"] = "ENFORCED_OBSERVED"
        self.assertEqual(
            jwt_authentication_context_confidence_of(tampered), "MEDIUM"
        )

    def test_schema_rejects_bad_values_and_extra(self):
        base = analyze_jwt_authentication_context(token_mechanism="JWT")
        for key, value in (
            ("authentication_mechanism", "NOPE"),
            ("token_mechanism", "NOPE"),
            ("token_format", "NOPE"),
            ("signing_algorithm", "NOPE"),
            ("signing_method", "NOPE"),
            ("signature_verification", "NOPE"),
            ("key_management", "NOPE"),
            ("key_rotation", "NOPE"),
            ("token_lifetime", "NOPE"),
            ("refresh_token", "NOPE"),
            ("session_lifecycle", "NOPE"),
            ("token_storage", "NOPE"),
            ("token_exposure", "NOPE"),
            ("authorization_boundary", "NOPE"),
            ("authentication_flow", "NOPE"),
            ("context_confidence", "NOPE"),
        ):
            with self.assertRaises(ValidationError):
                schema.JWTAuthenticationContextAnalysisPlan(
                    **{**base, key: value}
                )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationContextAnalysisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationContextAnalysisPlan(
                **{**base, "token_value": "x"}
            )

    def test_schema_forces_rule_version(self):
        plan = schema.JWTAuthenticationContextAnalysisPlan(
            **{
                **analyze_jwt_authentication_context(),
                "rule_version": "r99-9",
            }
        )
        self.assertEqual(plan.rule_version, "r47-2")

    def test_deterministic_serialization(self):
        context = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
            token_storage="COOKIE_OBSERVED",
            cookie_attributes=["SAME_SITE_LAX"],
        )
        first = json.dumps(context, sort_keys=True)
        second = json.dumps(context, sort_keys=True)
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R47_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("jwt_authentication", backend_source)
        self.assertNotIn("JWT_AUTHENTICATION", backend_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
