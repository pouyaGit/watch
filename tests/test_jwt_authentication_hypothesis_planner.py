"""tests/test_jwt_authentication_hypothesis_planner.py — Stage R47.3 tests.

Deterministic, offline tests for the JWT/authentication hypothesis planner:

- signature, algorithm, issuer, audience, expiration and not-before reasoning
- key management, lifetime, storage, refresh, revocation and session reasoning
- present-control vs gap distinction and negative signals
- needs-evidence semantics and no speculation from technology presence
- deterministic ordering, priority, state and rationale
- schema validation and extra-field rejection
- R47 AST safety scan and standalone backend decision

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

from ai.knowledge.jwt_authentication_context_analyzer import (
    analyze_jwt_authentication_context,
)
from ai.knowledge.jwt_authentication_hypothesis_planner import (
    plan_jwt_authentication_hypotheses,
)
from ai.schemas import jwt_authentication_hypothesis as schema
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.jwt_authentication_hypothesis import (
    HYPOTHESIS_STATES,
    SIGNAL_ISSUER_VALIDATION_ABSENT,
    SIGNAL_SIGNATURE_VERIFICATION_ABSENT,
)


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


def hypotheses_for(**context):
    return plan_jwt_authentication_hypotheses(
        analyze_jwt_authentication_context(**context)
    )


def types_of(hypotheses):
    return [entry["hypothesis_type"] for entry in hypotheses]


def by_type(hypotheses, hypothesis_type):
    return [
        entry
        for entry in hypotheses
        if entry["hypothesis_type"] == hypothesis_type
    ]


class TestJWTAuthenticationHypothesisPlanner(unittest.TestCase):
    def test_signature_verification_reasoning(self):
        absent = hypotheses_for(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "SIGNATURE_VERIFICATION_GAP")
        self.assertEqual(len(gap), 1)
        self.assertEqual(gap[0]["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertEqual(gap[0]["priority"], "HIGH")
        self.assertEqual(gap[0]["confidence"], "HIGH")
        self.assertIn(
            SIGNAL_SIGNATURE_VERIFICATION_ABSENT,
            gap[0]["supporting_signals"],
        )
        not_provided = hypotheses_for(
            token_mechanism="JWT",
            signature_verification="NOT_PROVIDED",
        )
        gap = by_type(not_provided, "SIGNATURE_VERIFICATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertEqual(gap["priority"], "LOW")
        enforced = hypotheses_for(
            token_mechanism="JWT",
            signature_verification="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            by_type(enforced, "SIGNATURE_VERIFICATION_GAP"), []
        )

    def test_algorithm_validation_reasoning(self):
        absent = hypotheses_for(
            token_mechanism="JWT",
            signing_algorithm="NONE",
            algorithm_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "ALGORITHM_VALIDATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertEqual(gap["priority"], "HIGH")
        self.assertIn(
            "SIGNING_ALGORITHM_NONE_OBSERVED",
            gap["supporting_signals"],
        )
        metadata_only = hypotheses_for(
            token_mechanism="JWT",
            signing_algorithm="NONE",
        )
        gap = by_type(metadata_only, "ALGORITHM_VALIDATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertNotEqual(gap["priority"], "HIGH")

    def test_issuer_validation_reasoning(self):
        absent = hypotheses_for(
            token_mechanism="JWT",
            issuer_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "ISSUER_VALIDATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertEqual(gap["priority"], "HIGH")
        self.assertIn(
            SIGNAL_ISSUER_VALIDATION_ABSENT, gap["supporting_signals"]
        )
        not_provided = hypotheses_for(
            token_mechanism="JWT", issuer_validation="NOT_PROVIDED"
        )
        gap = by_type(not_provided, "ISSUER_VALIDATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertEqual(gap["priority"], "LOW")
        self.assertTrue(gap["rationale"])

    def test_audience_validation_reasoning(self):
        absent = hypotheses_for(
            token_mechanism="JWT",
            audience_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "AUDIENCE_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            token_mechanism="JWT",
            audience_validation="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            by_type(enforced, "AUDIENCE_VALIDATION_GAP"), []
        )

    def test_expiration_validation_reasoning(self):
        absent = hypotheses_for(
            token_mechanism="JWT",
            expiration_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "EXPIRATION_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        not_provided = hypotheses_for(token_mechanism="JWT")
        gap = by_type(not_provided, "EXPIRATION_VALIDATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_not_before_validation_reasoning(self):
        absent = hypotheses_for(
            token_mechanism="JWT",
            not_before_validation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "NOT_BEFORE_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")

    def test_claim_validation_reasoning(self):
        absent = hypotheses_for(
            token_mechanism="JWT", claim_validation="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "CLAIM_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")

    def test_key_management_reasoning(self):
        static = hypotheses_for(
            token_mechanism="JWT", key_management="STATIC_KEY_OBSERVED"
        )
        self.assertEqual(
            by_type(static, "KEY_MANAGEMENT_GAP")[0]["priority"],
            "MEDIUM",
        )
        absent = hypotheses_for(
            token_mechanism="JWT",
            key_management="KEY_MANAGEMENT_ABSENT_OBSERVED",
        )
        self.assertEqual(
            by_type(absent, "KEY_MANAGEMENT_GAP")[0]["priority"],
            "HIGH",
        )
        no_rotation = hypotheses_for(
            token_mechanism="JWT",
            key_rotation="NO_ROTATION_OBSERVED",
        )
        self.assertEqual(
            by_type(no_rotation, "KEY_MANAGEMENT_GAP")[0]["priority"],
            "MEDIUM",
        )
        managed = hypotheses_for(
            token_mechanism="JWT",
            key_management="MANAGED_OBSERVED",
            key_rotation="ROTATION_CONFIGURED_OBSERVED",
        )
        self.assertEqual(by_type(managed, "KEY_MANAGEMENT_GAP"), [])
        self.assertTrue(
            by_type(managed, "AUTHENTICATION_CONTROL_PRESENT")
        )

    def test_token_lifetime_reasoning(self):
        long_lifetime = hypotheses_for(
            token_mechanism="JWT", token_lifetime="LONG_OBSERVED"
        )
        gap = by_type(long_lifetime, "TOKEN_LIFETIME_RISK")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        unbounded = hypotheses_for(
            token_mechanism="JWT", token_lifetime="UNBOUNDED_OBSERVED"
        )
        self.assertEqual(
            by_type(unbounded, "TOKEN_LIFETIME_RISK")[0]["priority"],
            "MEDIUM",
        )
        short = hypotheses_for(
            token_mechanism="JWT", token_lifetime="SHORT_OBSERVED"
        )
        self.assertEqual(by_type(short, "TOKEN_LIFETIME_RISK"), [])

    def test_token_storage_reasoning(self):
        local = hypotheses_for(
            token_mechanism="JWT", token_storage="LOCAL_STORAGE_OBSERVED"
        )
        gap = by_type(local, "TOKEN_STORAGE_RISK")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        cookie_incomplete = hypotheses_for(
            token_mechanism="JWT",
            token_storage="COOKIE_OBSERVED",
            cookie_attributes=["SAME_SITE_LAX"],
        )
        gap = by_type(cookie_incomplete, "TOKEN_STORAGE_RISK")[0]
        self.assertIn(
            "COOKIE_SECURITY_ATTRIBUTES_MISSING",
            gap["supporting_signals"],
        )
        cookie_complete = hypotheses_for(
            token_mechanism="JWT",
            token_storage="COOKIE_OBSERVED",
            cookie_attributes=["SECURE", "HTTP_ONLY"],
        )
        self.assertEqual(
            by_type(cookie_complete, "TOKEN_STORAGE_RISK"), []
        )

    def test_refresh_token_reasoning(self):
        absent_control = hypotheses_for(
            token_mechanism="JWT",
            refresh_token="PRESENT",
            refresh_control="ABSENT_OBSERVED",
        )
        gap = by_type(absent_control, "REFRESH_TOKEN_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        not_provided = hypotheses_for(
            token_mechanism="JWT", refresh_token="PRESENT"
        )
        gap = by_type(not_provided, "REFRESH_TOKEN_CONTROL_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        controlled = hypotheses_for(
            token_mechanism="JWT",
            refresh_token="PRESENT",
            refresh_control="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            by_type(controlled, "REFRESH_TOKEN_CONTROL_GAP"), []
        )

    def test_revocation_and_session_reasoning(self):
        revocation = hypotheses_for(
            token_mechanism="JWT",
            revocation_control="ABSENT_OBSERVED",
        )
        gap = by_type(revocation, "TOKEN_REVOCATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        client_session = hypotheses_for(
            authentication_mechanism="COOKIE_SESSION",
            session_lifecycle="CLIENT_SIDE_SESSION_OBSERVED",
        )
        gap = by_type(client_session, "SESSION_MANAGEMENT_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        stateless = hypotheses_for(
            token_mechanism="JWT",
            session_lifecycle="STATELESS_TOKEN_OBSERVED",
            revocation_control="ABSENT_OBSERVED",
        )
        gap = by_type(stateless, "SESSION_MANAGEMENT_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")

    def test_session_server_side_is_control(self):
        server = hypotheses_for(
            authentication_mechanism="COOKIE_SESSION",
            session_lifecycle="SERVER_SIDE_SESSION_OBSERVED",
        )
        self.assertEqual(by_type(server, "SESSION_MANAGEMENT_GAP"), [])
        self.assertTrue(
            by_type(server, "AUTHENTICATION_CONTROL_PRESENT")
        )

    def test_control_observation_without_mechanism_is_planned(self):
        absent = hypotheses_for(
            authentication_control="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "AUTHENTICATION_FLOW_GAP")
        self.assertEqual(len(gap), 1)
        self.assertEqual(gap[0]["priority"], "HIGH")
        self.assertEqual(gap[0]["hypothesis_state"], "WEAKNESS_OBSERVED")
        flow = hypotheses_for(authentication_flow="LOGIN_FLOW_OBSERVED")
        gap = by_type(flow, "AUTHENTICATION_FLOW_GAP")
        self.assertEqual(len(gap), 1)
        self.assertEqual(gap[0]["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertNotEqual(gap[0]["priority"], "HIGH")

    def test_isolated_session_observation_is_planned(self):
        client = hypotheses_for(
            session_lifecycle="CLIENT_SIDE_SESSION_OBSERVED"
        )
        gap = by_type(client, "SESSION_MANAGEMENT_GAP")
        self.assertEqual(len(gap), 1)
        self.assertEqual(gap[0]["priority"], "MEDIUM")
        self.assertEqual(gap[0]["hypothesis_state"], "WEAKNESS_OBSERVED")
        stateless = hypotheses_for(
            session_lifecycle="STATELESS_TOKEN_OBSERVED"
        )
        gap = by_type(stateless, "SESSION_MANAGEMENT_GAP")
        self.assertEqual(len(gap), 1)
        self.assertEqual(gap[0]["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_isolated_risk_metadata_is_not_a_token_hypothesis(self):
        for context in (
            {"token_lifetime": "UNBOUNDED_OBSERVED"},
            {"token_storage": "LOCAL_STORAGE_OBSERVED"},
            {"token_exposure": "URL_EXPOSURE_OBSERVED"},
            {"key_management": "KEY_MANAGEMENT_ABSENT_OBSERVED"},
            {"revocation_control": "ABSENT_OBSERVED"},
            {"authorization_boundary": "CLIENT_SIDE_ONLY_OBSERVED"},
        ):
            hypotheses = hypotheses_for(**context)
            self.assertEqual(
                types_of(hypotheses),
                ["MISSING_AUTHENTICATION_CONTEXT"],
                context,
            )
            self.assertNotEqual(hypotheses[0]["priority"], "HIGH")

    def test_authentication_control_reasoning(self):
        absent = hypotheses_for(
            authentication_mechanism="BEARER_TOKEN",
            authentication_control="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "AUTHENTICATION_FLOW_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        enforced = hypotheses_for(
            authentication_mechanism="BEARER_TOKEN",
            authentication_control="ENFORCED_OBSERVED",
        )
        self.assertEqual(by_type(enforced, "AUTHENTICATION_FLOW_GAP"), [])
        control = by_type(enforced, "AUTHENTICATION_CONTROL_PRESENT")
        self.assertEqual(len(control), 1)
        self.assertEqual(
            control[0]["hypothesis_state"], "CONTROL_PRESENT_OBSERVED"
        )

    def test_negative_signals_reduce_priority(self):
        weak = hypotheses_for(
            token_mechanism="JWT",
            issuer_validation="ABSENT_OBSERVED",
        )
        controlled = hypotheses_for(
            token_mechanism="JWT",
            issuer_validation="ENFORCED_OBSERVED",
            audience_validation="ENFORCED_OBSERVED",
            expiration_validation="ENFORCED_OBSERVED",
            signature_verification="ENFORCED_OBSERVED",
        )
        self.assertTrue(by_type(weak, "ISSUER_VALIDATION_GAP"))
        self.assertEqual(by_type(controlled, "ISSUER_VALIDATION_GAP"), [])
        control = by_type(controlled, "AUTHENTICATION_CONTROL_PRESENT")
        self.assertEqual(len(control), 1)
        self.assertEqual(control[0]["priority"], "LOW")

    def test_jwt_validation_gap_umbrella(self):
        partial = hypotheses_for(
            token_mechanism="JWT",
            signature_verification="ENFORCED_OBSERVED",
        )
        umbrella = by_type(partial, "JWT_VALIDATION_GAP")
        self.assertEqual(len(umbrella), 1)
        self.assertEqual(umbrella[0]["hypothesis_state"], "NEEDS_EVIDENCE")
        observed = hypotheses_for(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
        )
        self.assertEqual(by_type(observed, "JWT_VALIDATION_GAP"), [])

    def test_no_speculation_from_technology_presence(self):
        jwt_only = hypotheses_for(
            token_mechanism="JWT",
            signing_algorithm="RS256",
            signing_method="ASYMMETRIC",
        )
        for entry in jwt_only:
            self.assertNotEqual(entry["priority"], "HIGH")
            self.assertEqual(entry["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertNotIn(
            "SIGNATURE_VERIFICATION_GAP",
            [
                entry["hypothesis_type"]
                for entry in jwt_only
                if entry["hypothesis_state"] == "WEAKNESS_OBSERVED"
            ],
        )

    def test_missing_context_handling(self):
        unknown = hypotheses_for()
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["hypothesis_type"], "UNKNOWN")
        self.assertEqual(unknown[0]["hypothesis_state"], "UNKNOWN")
        self.assertIn(
            "INSUFFICIENT_CONTEXT", unknown[0]["limitations"]
        )
        missing = hypotheses_for(cookie_attributes=["SECURE"])
        self.assertEqual(
            [entry["hypothesis_type"] for entry in missing],
            ["MISSING_AUTHENTICATION_CONTEXT"],
        )
        self.assertEqual(missing[0]["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_hypotheses_are_canonical_ordered_and_closed(self):
        hypotheses = hypotheses_for(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
            issuer_validation="ABSENT_OBSERVED",
            token_storage="LOCAL_STORAGE_OBSERVED",
            refresh_token="PRESENT",
            refresh_control="ABSENT_OBSERVED",
            revocation_control="ABSENT_OBSERVED",
        )
        positions = [
            schema.HYPOTHESIS_TYPES.index(entry["hypothesis_type"])
            for entry in hypotheses
        ]
        self.assertEqual(positions, sorted(positions))
        for entry in hypotheses:
            self.assertIn(entry["priority"], CONFIDENCE_LEVELS)
            self.assertIn(entry["hypothesis_state"], HYPOTHESIS_STATES)
            self.assertEqual(entry["confidence"], entry["priority"])
            self.assertEqual(
                entry["hypothesis_type"], entry["hypothesis_type"].upper()
            )
            self.assertTrue(entry["rationale"])

    def test_hypothesis_limitations(self):
        hypotheses = hypotheses_for(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
        )
        for entry in hypotheses:
            for limitation in (
                "NO_EXPLOIT_CLAIM",
                "NO_VULNERABILITY_CONFIRMATION",
                "NO_SIGNATURE_BYPASS_CLAIM",
                "NO_AUTHENTICATION_BYPASS_CLAIM",
                "HYPOTHESIS_ONLY",
                "EVIDENCE_REQUIRED",
            ):
                self.assertIn(limitation, entry["limitations"])

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "hypothesis_type": "ISSUER_VALIDATION_GAP",
            "hypothesis_state": "NEEDS_EVIDENCE",
            "supporting_signals": ["ISSUER_VALIDATION_NOT_PROVIDED"],
            "confidence": "LOW",
            "priority": "LOW",
            "rationale": "text",
            "limitations": ["NO_EXPLOIT_CLAIM"],
        }
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationHypothesisPlan(
                **{**base, "hypothesis_type": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationHypothesisPlan(
                **{**base, "hypothesis_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationHypothesisPlan(
                **{**base, "supporting_signals": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationHypothesisPlan(
                **{**base, "priority": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationHypothesisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationHypothesisPlan(
                **{**base, "token": "x"}
            )

    def test_schema_forces_rule_version(self):
        plan = schema.JWTAuthenticationHypothesisPlan(
            hypothesis_type="UNKNOWN", rule_version="r99-9"
        )
        self.assertEqual(plan.rule_version, "r47-3")

    def test_deterministic_serialization(self):
        context = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
            issuer_validation="NOT_PROVIDED",
        )
        first = json.dumps(
            plan_jwt_authentication_hypotheses(context), sort_keys=True
        )
        second = json.dumps(
            plan_jwt_authentication_hypotheses(context), sort_keys=True
        )
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
