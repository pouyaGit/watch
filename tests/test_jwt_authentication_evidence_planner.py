"""tests/test_jwt_authentication_evidence_planner.py — Stage R47.4 tests.

Deterministic, offline tests for the JWT/authentication evidence planner:

- closed evidence vocabulary and per-hypothesis evidence mapping
- evidence requirements are planning only, never collection
- deterministic planning state and confidence calibration
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
from ai.knowledge.jwt_authentication_evidence_planner import (
    HYPOTHESIS_EVIDENCE,
    plan_jwt_authentication_evidence,
)
from ai.knowledge.jwt_authentication_hypothesis_planner import (
    plan_jwt_authentication_hypotheses,
)
from ai.schemas import jwt_authentication_evidence_plan as schema
from ai.schemas.jwt_authentication_evidence_plan import (
    EVIDENCE_ALGORITHM_ACCEPTANCE_RULES,
    EVIDENCE_ALGORITHM_VALIDATION_BEHAVIOR,
    EVIDENCE_AUDIENCE_CONFIGURATION,
    EVIDENCE_AUDIENCE_VALIDATION_RULES,
    EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE,
    EVIDENCE_AUTHENTICATION_FLOW_CONFIGURATION,
    EVIDENCE_COOKIE_SECURITY_ATTRIBUTES,
    EVIDENCE_EXPIRATION_POLICY,
    EVIDENCE_EXPIRATION_VALIDATION_BEHAVIOR,
    EVIDENCE_ISSUER_CONFIGURATION,
    EVIDENCE_ISSUER_VALIDATION_RULES,
    EVIDENCE_REFRESH_CONTROL_CONFIGURATION,
    EVIDENCE_REVOCATION_CONFIGURATION,
    EVIDENCE_SESSION_LIFECYCLE_CONFIGURATION,
    EVIDENCE_SIGNATURE_VERIFICATION_BEHAVIOR,
    EVIDENCE_SIGNATURE_VERIFICATION_CONFIGURATION,
    EVIDENCE_TOKEN_LIFETIME_POLICY,
    EVIDENCE_TOKEN_STORAGE_MECHANISM,
    EVIDENCE_UNKNOWN,
    EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
)
from ai.schemas.jwt_authentication_hypothesis import (
    HYPOTHESIS_TYPES,
    TYPE_ALGORITHM_VALIDATION_GAP,
    TYPE_AUDIENCE_VALIDATION_GAP,
    TYPE_AUTHENTICATION_CONTROL_PRESENT,
    TYPE_AUTHENTICATION_FLOW_GAP,
    TYPE_EXPIRATION_VALIDATION_GAP,
    TYPE_ISSUER_VALIDATION_GAP,
    TYPE_MISSING_AUTHENTICATION_CONTEXT,
    TYPE_REFRESH_TOKEN_CONTROL_GAP,
    TYPE_SESSION_MANAGEMENT_GAP,
    TYPE_SIGNATURE_VERIFICATION_GAP,
    TYPE_TOKEN_LIFETIME_RISK,
    TYPE_TOKEN_STORAGE_RISK,
    TYPE_UNKNOWN,
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


def rich_context(**over):
    base = {
        "authentication_mechanism": "JWT_BEARER",
        "token_mechanism": "JWT",
        "token_format": "COMPACT_JWS",
        "signing_algorithm": "RS256",
        "signing_method": "ASYMMETRIC",
        "signature_verification": "ENFORCED_OBSERVED",
        "algorithm_validation": "ENFORCED_OBSERVED",
        "issuer_validation": "ENFORCED_OBSERVED",
        "audience_validation": "ENFORCED_OBSERVED",
        "expiration_validation": "ENFORCED_OBSERVED",
        "not_before_validation": "ENFORCED_OBSERVED",
        "claim_validation": "ENFORCED_OBSERVED",
        "key_management": "MANAGED_OBSERVED",
        "key_rotation": "ROTATION_CONFIGURED_OBSERVED",
        "token_lifetime": "SHORT_OBSERVED",
        "refresh_token": "PRESENT",
        "refresh_control": "ENFORCED_OBSERVED",
        "revocation_control": "ENFORCED_OBSERVED",
        "session_lifecycle": "SERVER_SIDE_SESSION_OBSERVED",
        "token_storage": "MEMORY_ONLY_OBSERVED",
        "authorization_boundary": "SERVER_SIDE_ENFORCED_OBSERVED",
        "authentication_control": "ENFORCED_OBSERVED",
    }
    base.update(over)
    return base


class TestJWTAuthenticationEvidencePlanner(unittest.TestCase):
    def test_evidence_vocabulary_is_closed(self):
        self.assertEqual(len(schema.JWT_AUTHENTICATION_EVIDENCE_ITEMS), 25)
        self.assertEqual(
            schema.JWT_AUTHENTICATION_EVIDENCE_ITEMS[-1], EVIDENCE_UNKNOWN
        )

    def test_mapping_covers_every_hypothesis(self):
        self.assertEqual(
            set(HYPOTHESIS_EVIDENCE.keys()), set(HYPOTHESIS_TYPES)
        )

    def test_signature_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_SIGNATURE_VERIFICATION_GAP]
        for item in (
            EVIDENCE_SIGNATURE_VERIFICATION_CONFIGURATION,
            EVIDENCE_SIGNATURE_VERIFICATION_BEHAVIOR,
            EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
        ):
            self.assertIn(item, evidence)

    def test_algorithm_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_ALGORITHM_VALIDATION_GAP]
        for item in (
            EVIDENCE_ALGORITHM_ACCEPTANCE_RULES,
            EVIDENCE_ALGORITHM_VALIDATION_BEHAVIOR,
            EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
        ):
            self.assertIn(item, evidence)

    def test_issuer_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_ISSUER_VALIDATION_GAP]
        for item in (
            EVIDENCE_ISSUER_CONFIGURATION,
            EVIDENCE_ISSUER_VALIDATION_RULES,
            EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
        ):
            self.assertIn(item, evidence)

    def test_audience_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_AUDIENCE_VALIDATION_GAP]
        for item in (
            EVIDENCE_AUDIENCE_CONFIGURATION,
            EVIDENCE_AUDIENCE_VALIDATION_RULES,
            EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
        ):
            self.assertIn(item, evidence)

    def test_expiration_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_EXPIRATION_VALIDATION_GAP]
        for item in (
            EVIDENCE_EXPIRATION_POLICY,
            EVIDENCE_EXPIRATION_VALIDATION_BEHAVIOR,
            EVIDENCE_TOKEN_LIFETIME_POLICY,
        ):
            self.assertIn(item, evidence)

    def test_storage_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_TOKEN_STORAGE_RISK]
        self.assertIn(EVIDENCE_TOKEN_STORAGE_MECHANISM, evidence)
        self.assertIn(EVIDENCE_COOKIE_SECURITY_ATTRIBUTES, evidence)

    def test_refresh_and_session_evidence(self):
        refresh = HYPOTHESIS_EVIDENCE[TYPE_REFRESH_TOKEN_CONTROL_GAP]
        self.assertIn(EVIDENCE_REFRESH_CONTROL_CONFIGURATION, refresh)
        self.assertIn(EVIDENCE_REVOCATION_CONFIGURATION, refresh)
        session = HYPOTHESIS_EVIDENCE[TYPE_SESSION_MANAGEMENT_GAP]
        self.assertIn(
            EVIDENCE_SESSION_LIFECYCLE_CONFIGURATION, session
        )
        self.assertIn(EVIDENCE_TOKEN_STORAGE_MECHANISM, session)

    def test_lifetime_and_flow_evidence(self):
        lifetime = HYPOTHESIS_EVIDENCE[TYPE_TOKEN_LIFETIME_RISK]
        self.assertIn(EVIDENCE_TOKEN_LIFETIME_POLICY, lifetime)
        flow = HYPOTHESIS_EVIDENCE[TYPE_AUTHENTICATION_FLOW_GAP]
        self.assertIn(EVIDENCE_AUTHENTICATION_FLOW_CONFIGURATION, flow)
        self.assertIn(EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE, flow)

    def test_control_present_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_AUTHENTICATION_CONTROL_PRESENT]
        self.assertIn(EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE, evidence)
        self.assertIn(
            EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE, evidence
        )

    def test_unknown_context_plan(self):
        evidence = plan_jwt_authentication_evidence(
            analyze_jwt_authentication_context()
        )
        self.assertEqual(evidence["evidence_items"], [EVIDENCE_UNKNOWN])
        self.assertEqual(evidence["evidence_state"], "UNKNOWN")
        self.assertEqual(evidence["confidence"], "UNKNOWN")
        self.assertIn("INSUFFICIENT_CONTEXT", evidence["limitations"])

    def test_partial_plan_for_needs_evidence(self):
        context = analyze_jwt_authentication_context(
            token_mechanism="JWT"
        )
        evidence = plan_jwt_authentication_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        self.assertIn(
            EVIDENCE_SIGNATURE_VERIFICATION_CONFIGURATION,
            evidence["evidence_items"],
        )
        self.assertFalse(
            any(item == EVIDENCE_UNKNOWN for item in evidence["evidence_items"])
        )

    def test_complete_plan_for_observed_weakness(self):
        context = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
            issuer_validation="ABSENT_OBSERVED",
            audience_validation="ABSENT_OBSERVED",
            expiration_validation="ABSENT_OBSERVED",
        )
        self.assertEqual(context["context_confidence"], "HIGH")
        evidence = plan_jwt_authentication_evidence(context)
        self.assertEqual(evidence["evidence_state"], "COMPLETE")
        self.assertEqual(evidence["confidence"], "HIGH")

    def test_isolated_weakness_signal_is_not_complete(self):
        context = analyze_jwt_authentication_context(
            token_lifetime="UNBOUNDED_OBSERVED"
        )
        self.assertNotEqual(context["context_confidence"], "HIGH")
        evidence = plan_jwt_authentication_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        self.assertFalse(
            any(
                item == EVIDENCE_UNKNOWN
                for item in evidence["evidence_items"]
            )
        )

    def test_missing_context_hypothesis_is_never_complete(self):
        context = analyze_jwt_authentication_context(
            authentication_mechanism="BEARER_TOKEN",
            signature_verification="ABSENT_OBSERVED",
        )
        self.assertEqual(context["context_confidence"], "HIGH")
        evidence = plan_jwt_authentication_evidence(
            context,
            [
                {
                    "hypothesis_type": TYPE_MISSING_AUTHENTICATION_CONTEXT,
                    "hypothesis_state": "NEEDS_EVIDENCE",
                    "confidence": "LOW",
                    "priority": "LOW",
                }
            ],
        )
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        unknown_only = plan_jwt_authentication_evidence(
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
        context = analyze_jwt_authentication_context(**rich_context())
        self.assertEqual(context["context_confidence"], "MEDIUM")
        evidence = plan_jwt_authentication_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        self.assertIn(
            EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE,
            evidence["evidence_items"],
        )

    def test_explicit_hypotheses_are_respected(self):
        context = analyze_jwt_authentication_context(**rich_context())
        manual = plan_jwt_authentication_evidence(
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
        evidence = plan_jwt_authentication_evidence(
            analyze_jwt_authentication_context()
        )
        for limitation in (
            "NO_COLLECTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_TOKEN_MANIPULATION",
            "NO_SIGNATURE_BYPASS",
            "NO_AUTHENTICATION_BYPASS",
            "NO_CREDENTIAL_TESTING",
            "NO_PAYLOAD_GENERATION",
            "EVIDENCE_REQUIRED",
        ):
            self.assertIn(limitation, evidence["limitations"])

    def test_generated_evidence_plan_matches_hypotheses(self):
        context = analyze_jwt_authentication_context(
            token_mechanism="JWT",
            signature_verification="ABSENT_OBSERVED",
            token_storage="LOCAL_STORAGE_OBSERVED",
        )
        hypotheses = plan_jwt_authentication_hypotheses(context)
        evidence = plan_jwt_authentication_evidence(context)
        expected: list[str] = []
        for hypothesis in hypotheses:
            for item in HYPOTHESIS_EVIDENCE.get(
                hypothesis["hypothesis_type"], (EVIDENCE_UNKNOWN,)
            ):
                if item not in expected:
                    expected.append(item)
        self.assertEqual(evidence["evidence_items"], expected)

    def test_schema_rejects_bad_values_and_extra(self):
        base = plan_jwt_authentication_evidence(
            analyze_jwt_authentication_context(token_mechanism="JWT")
        )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationEvidencePlan(
                **{**base, "evidence_items": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationEvidencePlan(
                **{**base, "evidence_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationEvidencePlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationEvidencePlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.JWTAuthenticationEvidencePlan(
                **{**base, "token": "x"}
            )

    def test_schema_forces_rule_version(self):
        plan = schema.JWTAuthenticationEvidencePlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r47-4")

    def test_deterministic_serialization(self):
        context = analyze_jwt_authentication_context(**rich_context())
        first = json.dumps(
            plan_jwt_authentication_evidence(context), sort_keys=True
        )
        second = json.dumps(
            plan_jwt_authentication_evidence(context), sort_keys=True
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
