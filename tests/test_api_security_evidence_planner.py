"""tests/test_api_security_evidence_planner.py — Stage R49.4 tests.

Deterministic, offline tests for the API security evidence planner:

- closed evidence vocabulary and per-hypothesis evidence mapping
- evidence requirements are planning only, never collection
- deterministic planning state and confidence calibration
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

from ai.knowledge.api_security_context_analyzer import (
    analyze_api_security_context,
)
from ai.knowledge.api_security_evidence_planner import (
    HYPOTHESIS_EVIDENCE,
    plan_api_security_evidence,
)
from ai.knowledge.api_security_hypothesis_planner import (
    plan_api_security_hypotheses,
)
from ai.schemas import api_security_evidence_plan as schema
from ai.schemas.api_security_evidence_plan import (
    EVIDENCE_API_AUTHENTICATION_CONFIGURATION,
    EVIDENCE_API_AUTHENTICATION_ENFORCEMENT,
    EVIDENCE_API_KEY_REVOCATION_POLICY,
    EVIDENCE_API_KEY_ROTATION_POLICY,
    EVIDENCE_API_KEY_SCOPE_POLICY,
    EVIDENCE_API_SECURITY_CONFIGURATION,
    EVIDENCE_AUTHORIZATION_ENFORCEMENT_BEHAVIOR,
    EVIDENCE_BATCH_LIMIT_POLICY,
    EVIDENCE_CONTENT_TYPE_VALIDATION_POLICY,
    EVIDENCE_CORS_CREDENTIAL_POLICY,
    EVIDENCE_CORS_ORIGIN_POLICY,
    EVIDENCE_DEBUG_CONFIGURATION,
    EVIDENCE_DOWNLOAD_CONTROL_POLICY,
    EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY,
    EVIDENCE_ERROR_HANDLING_CONFIGURATION,
    EVIDENCE_FUNCTION_ROLE_AUTHORIZATION_POLICY,
    EVIDENCE_GRAPHQL_COMPLEXITY_LIMIT_POLICY,
    EVIDENCE_GRAPHQL_DEPTH_LIMIT_POLICY,
    EVIDENCE_GRAPHQL_FIELD_AUTHORIZATION_POLICY,
    EVIDENCE_GRAPHQL_INTROSPECTION_POLICY,
    EVIDENCE_GRAPHQL_MUTATION_AUTHORIZATION_POLICY,
    EVIDENCE_HTTP_METHOD_CONFIGURATION,
    EVIDENCE_INPUT_VALIDATION_IMPLEMENTATION,
    EVIDENCE_METHOD_OVERRIDE_CONFIGURATION,
    EVIDENCE_PAGINATION_LIMIT_POLICY,
    EVIDENCE_QUERY_COMPLEXITY_POLICY,
    EVIDENCE_RATE_LIMIT_POLICY,
    EVIDENCE_REQUEST_SCHEMA_DEFINITION,
    EVIDENCE_REQUEST_SIZE_LIMIT_POLICY,
    EVIDENCE_RESPONSE_FIELD_POLICY,
    EVIDENCE_SENSITIVE_FIELD_POLICY,
    EVIDENCE_TENANT_ISOLATION_POLICY,
    EVIDENCE_UNKNOWN,
    EVIDENCE_UNKNOWN_FIELD_HANDLING_POLICY,
    EVIDENCE_UPLOAD_LIMIT_POLICY,
    EVIDENCE_WEBHOOK_REPLAY_PROTECTION,
    EVIDENCE_WEBHOOK_SIGNATURE_VALIDATION,
    EVIDENCE_WEBHOOK_SOURCE_VALIDATION,
    EVIDENCE_WRITABLE_FIELD_POLICY,
)
from ai.schemas.api_security_hypothesis import (
    HYPOTHESIS_TYPES,
    TYPE_API_AUTHENTICATION_GAP,
    TYPE_API_AUTHORIZATION_GAP,
    TYPE_API_SECURITY_CONTROL_PRESENT,
    TYPE_CORS_CONTROL_GAP,
    TYPE_GRAPHQL_AUTHORIZATION_GAP,
    TYPE_GRAPHQL_QUERY_COMPLEXITY_GAP,
    TYPE_HTTP_METHOD_CONTROL_GAP,
    TYPE_INPUT_VALIDATION_GAP,
    TYPE_MASS_ASSIGNMENT_RISK,
    TYPE_MISSING_API_CONTEXT,
    TYPE_PAGINATION_CONTROL_GAP,
    TYPE_RATE_LIMIT_CONTROL_GAP,
    TYPE_SCHEMA_VALIDATION_GAP,
    TYPE_TENANT_ISOLATION_GAP,
    TYPE_UNKNOWN,
    TYPE_WEBHOOK_SIGNATURE_CONTROL_GAP,
)


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


def rich_context():
    return analyze_api_security_context(
        api_type="REST",
        content_type="JSON_OBSERVED",
        authentication_mechanism="BEARER_TOKEN",
        endpoint_metadata="OBSERVED",
        request_schema="OBSERVED",
        response_schema="OBSERVED",
        api_authentication="ENFORCED_OBSERVED",
        endpoint_authorization="ENFORCED_OBSERVED",
        function_role_authorization="ENFORCED_OBSERVED",
        tenant_isolation="ENFORCED_OBSERVED",
        schema_validation="ENFORCED_OBSERVED",
        parameter_validation="ENFORCED_OBSERVED",
        rate_limit_control="ENFORCED_OBSERVED",
        request_size_limit="ENFORCED_OBSERVED",
    )


class TestAPISecurityEvidencePlanner(unittest.TestCase):
    def test_evidence_vocabulary_is_closed(self):
        self.assertEqual(len(schema.API_SECURITY_EVIDENCE_ITEMS), 40)
        self.assertEqual(
            len(set(schema.API_SECURITY_EVIDENCE_ITEMS)), 40
        )
        self.assertEqual(
            schema.API_SECURITY_EVIDENCE_ITEMS[-1], EVIDENCE_UNKNOWN
        )
        for limitation in (
            "NO_COLLECTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_API_CALLS",
            "NO_ENDPOINT_PROBING",
            "NO_SCANNER_EXECUTION",
            "NO_PAYLOAD_GENERATION",
            "NO_CREDENTIAL_TESTING",
            "EVIDENCE_REQUIRED",
            "INSUFFICIENT_CONTEXT",
        ):
            self.assertIn(
                limitation, schema.API_SECURITY_EVIDENCE_LIMITATIONS
            )

    def test_mapping_covers_every_hypothesis(self):
        for hypothesis_type in HYPOTHESIS_TYPES:
            self.assertIn(hypothesis_type, HYPOTHESIS_EVIDENCE)
            for item in HYPOTHESIS_EVIDENCE[hypothesis_type]:
                self.assertIn(item, schema.API_SECURITY_EVIDENCE_ITEMS)

    def test_authentication_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_API_AUTHENTICATION_GAP]
        self.assertIn(EVIDENCE_API_AUTHENTICATION_CONFIGURATION, evidence)
        self.assertIn(EVIDENCE_API_AUTHENTICATION_ENFORCEMENT, evidence)

    def test_authorization_evidence(self):
        endpoint = HYPOTHESIS_EVIDENCE[TYPE_API_AUTHORIZATION_GAP]
        self.assertIn(EVIDENCE_ENDPOINT_AUTHORIZATION_POLICY, endpoint)
        self.assertIn(
            EVIDENCE_AUTHORIZATION_ENFORCEMENT_BEHAVIOR, endpoint
        )
        role = HYPOTHESIS_EVIDENCE[
            "FUNCTION_LEVEL_AUTHORIZATION_GAP"
        ]
        self.assertIn(EVIDENCE_FUNCTION_ROLE_AUTHORIZATION_POLICY, role)
        tenant = HYPOTHESIS_EVIDENCE[TYPE_TENANT_ISOLATION_GAP]
        self.assertIn(EVIDENCE_TENANT_ISOLATION_POLICY, tenant)

    def test_input_and_schema_evidence(self):
        parameter = HYPOTHESIS_EVIDENCE[TYPE_INPUT_VALIDATION_GAP]
        self.assertIn(EVIDENCE_INPUT_VALIDATION_IMPLEMENTATION, parameter)
        self.assertIn(EVIDENCE_REQUEST_SCHEMA_DEFINITION, parameter)
        schema_state = HYPOTHESIS_EVIDENCE[TYPE_SCHEMA_VALIDATION_GAP]
        self.assertIn(EVIDENCE_REQUEST_SCHEMA_DEFINITION, schema_state)

    def test_mass_assignment_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_MASS_ASSIGNMENT_RISK]
        self.assertIn(EVIDENCE_UNKNOWN_FIELD_HANDLING_POLICY, evidence)
        self.assertIn(EVIDENCE_WRITABLE_FIELD_POLICY, evidence)
        self.assertIn(EVIDENCE_SENSITIVE_FIELD_POLICY, evidence)

    def test_method_evidence(self):
        method = HYPOTHESIS_EVIDENCE[TYPE_HTTP_METHOD_CONTROL_GAP]
        self.assertIn(EVIDENCE_HTTP_METHOD_CONFIGURATION, method)
        override = HYPOTHESIS_EVIDENCE["METHOD_OVERRIDE_RISK"]
        self.assertIn(EVIDENCE_METHOD_OVERRIDE_CONFIGURATION, override)

    def test_exposure_and_error_evidence(self):
        resource = HYPOTHESIS_EVIDENCE["RESOURCE_EXPOSURE_RISK"]
        self.assertIn(EVIDENCE_RESPONSE_FIELD_POLICY, resource)
        sensitive = HYPOTHESIS_EVIDENCE[
            "SENSITIVE_FIELD_EXPOSURE_RISK"
        ]
        self.assertIn(EVIDENCE_SENSITIVE_FIELD_POLICY, sensitive)
        error = HYPOTHESIS_EVIDENCE["ERROR_INFORMATION_DISCLOSURE"]
        self.assertIn(EVIDENCE_ERROR_HANDLING_CONFIGURATION, error)
        debug = HYPOTHESIS_EVIDENCE["DEBUG_INFORMATION_EXPOSURE"]
        self.assertIn(EVIDENCE_DEBUG_CONFIGURATION, debug)

    def test_resource_control_evidence(self):
        rate = HYPOTHESIS_EVIDENCE[TYPE_RATE_LIMIT_CONTROL_GAP]
        self.assertIn(EVIDENCE_RATE_LIMIT_POLICY, rate)
        size = HYPOTHESIS_EVIDENCE["RESOURCE_LIMIT_CONTROL_GAP"]
        self.assertIn(EVIDENCE_REQUEST_SIZE_LIMIT_POLICY, size)
        pagination = HYPOTHESIS_EVIDENCE[TYPE_PAGINATION_CONTROL_GAP]
        self.assertIn(EVIDENCE_PAGINATION_LIMIT_POLICY, pagination)
        complexity = HYPOTHESIS_EVIDENCE[
            "QUERY_COMPLEXITY_CONTROL_GAP"
        ]
        self.assertIn(EVIDENCE_QUERY_COMPLEXITY_POLICY, complexity)

    def test_batch_and_file_evidence(self):
        batch = HYPOTHESIS_EVIDENCE["BATCH_OPERATION_CONTROL_GAP"]
        self.assertIn(EVIDENCE_BATCH_LIMIT_POLICY, batch)
        upload = HYPOTHESIS_EVIDENCE["FILE_UPLOAD_CONTROL_GAP"]
        self.assertIn(EVIDENCE_UPLOAD_LIMIT_POLICY, upload)
        download = HYPOTHESIS_EVIDENCE["FILE_DOWNLOAD_CONTROL_GAP"]
        self.assertIn(EVIDENCE_DOWNLOAD_CONTROL_POLICY, download)

    def test_graphql_evidence(self):
        introspection = HYPOTHESIS_EVIDENCE[
            "GRAPHQL_INTROSPECTION_RISK"
        ]
        self.assertIn(EVIDENCE_GRAPHQL_INTROSPECTION_POLICY, introspection)
        authz = HYPOTHESIS_EVIDENCE[TYPE_GRAPHQL_AUTHORIZATION_GAP]
        self.assertIn(EVIDENCE_GRAPHQL_FIELD_AUTHORIZATION_POLICY, authz)
        self.assertIn(
            EVIDENCE_GRAPHQL_MUTATION_AUTHORIZATION_POLICY, authz
        )
        complexity = HYPOTHESIS_EVIDENCE[
            TYPE_GRAPHQL_QUERY_COMPLEXITY_GAP
        ]
        self.assertIn(
            EVIDENCE_GRAPHQL_COMPLEXITY_LIMIT_POLICY, complexity
        )
        self.assertIn(EVIDENCE_GRAPHQL_DEPTH_LIMIT_POLICY, complexity)

    def test_cors_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE[TYPE_CORS_CONTROL_GAP]
        self.assertIn(EVIDENCE_CORS_ORIGIN_POLICY, evidence)
        self.assertIn(EVIDENCE_CORS_CREDENTIAL_POLICY, evidence)

    def test_api_key_evidence(self):
        evidence = HYPOTHESIS_EVIDENCE["API_KEY_CONTROL_GAP"]
        self.assertIn(EVIDENCE_API_KEY_ROTATION_POLICY, evidence)
        self.assertIn(EVIDENCE_API_KEY_REVOCATION_POLICY, evidence)
        self.assertIn(EVIDENCE_API_KEY_SCOPE_POLICY, evidence)

    def test_webhook_evidence(self):
        signature = HYPOTHESIS_EVIDENCE[
            TYPE_WEBHOOK_SIGNATURE_CONTROL_GAP
        ]
        self.assertIn(EVIDENCE_WEBHOOK_SIGNATURE_VALIDATION, signature)
        self.assertIn(EVIDENCE_WEBHOOK_SOURCE_VALIDATION, signature)
        replay = HYPOTHESIS_EVIDENCE["WEBHOOK_REPLAY_CONTROL_GAP"]
        self.assertIn(EVIDENCE_WEBHOOK_REPLAY_PROTECTION, replay)

    def test_content_type_and_control_evidence(self):
        content = HYPOTHESIS_EVIDENCE["CONTENT_TYPE_CONTROL_GAP"]
        self.assertIn(EVIDENCE_CONTENT_TYPE_VALIDATION_POLICY, content)
        control = HYPOTHESIS_EVIDENCE[TYPE_API_SECURITY_CONTROL_PRESENT]
        self.assertIn(EVIDENCE_API_SECURITY_CONFIGURATION, control)

    def test_unknown_context_plan(self):
        evidence = plan_api_security_evidence(analyze_api_security_context())
        self.assertEqual(evidence["evidence_items"], [EVIDENCE_UNKNOWN])
        self.assertEqual(evidence["evidence_state"], "UNKNOWN")
        self.assertEqual(evidence["confidence"], "UNKNOWN")
        self.assertIn("INSUFFICIENT_CONTEXT", evidence["limitations"])

    def test_partial_plan_for_needs_evidence(self):
        context = analyze_api_security_context(api_type="REST")
        evidence = plan_api_security_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        self.assertIn(
            EVIDENCE_API_AUTHENTICATION_CONFIGURATION,
            evidence["evidence_items"],
        )
        self.assertFalse(
            any(
                item == EVIDENCE_UNKNOWN
                for item in evidence["evidence_items"]
            )
        )

    def test_complete_plan_for_observed_weakness(self):
        context = analyze_api_security_context(
            api_type="REST",
            api_authentication="ABSENT_OBSERVED",
            endpoint_authorization="ABSENT_OBSERVED",
            rate_limit_control="ABSENT_OBSERVED",
        )
        self.assertEqual(context["context_confidence"], "HIGH")
        evidence = plan_api_security_evidence(context)
        self.assertEqual(evidence["evidence_state"], "COMPLETE")
        self.assertEqual(evidence["confidence"], "HIGH")

    def test_isolated_weakness_signal_is_not_complete(self):
        context = analyze_api_security_context(
            api_authentication="ABSENT_OBSERVED"
        )
        self.assertNotEqual(context["context_confidence"], "HIGH")
        evidence = plan_api_security_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")

    def test_missing_context_hypothesis_is_never_complete(self):
        context = analyze_api_security_context(
            api_type="REST",
            api_authentication="ABSENT_OBSERVED",
        )
        self.assertEqual(context["context_confidence"], "HIGH")
        evidence = plan_api_security_evidence(
            context,
            [
                {
                    "hypothesis_type": TYPE_MISSING_API_CONTEXT,
                    "hypothesis_state": "NEEDS_EVIDENCE",
                    "confidence": "LOW",
                    "priority": "LOW",
                }
            ],
        )
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        unknown_only = plan_api_security_evidence(
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
        evidence = plan_api_security_evidence(context)
        self.assertEqual(evidence["evidence_state"], "PARTIAL")
        self.assertEqual(evidence["confidence"], "LOW")
        self.assertIn(
            EVIDENCE_API_AUTHENTICATION_CONFIGURATION,
            evidence["evidence_items"],
        )

    def test_explicit_hypotheses_are_respected(self):
        context = rich_context()
        manual = plan_api_security_evidence(
            context,
            [
                {
                    "hypothesis_type": "API_AUTHENTICATION_GAP",
                    "hypothesis_state": "NEEDS_EVIDENCE",
                    "confidence": "LOW",
                    "priority": "LOW",
                }
            ],
        )
        self.assertEqual(
            manual["evidence_items"],
            list(HYPOTHESIS_EVIDENCE[TYPE_API_AUTHENTICATION_GAP]),
        )

    def test_evidence_limitations(self):
        evidence = plan_api_security_evidence(
            analyze_api_security_context()
        )
        for limitation in (
            "NO_COLLECTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_API_CALLS",
            "NO_ENDPOINT_PROBING",
            "NO_SCANNER_EXECUTION",
            "NO_PAYLOAD_GENERATION",
            "NO_CREDENTIAL_TESTING",
            "EVIDENCE_REQUIRED",
        ):
            self.assertIn(limitation, evidence["limitations"])
        complete = plan_api_security_evidence(
            analyze_api_security_context(
                api_type="REST", api_authentication="ABSENT_OBSERVED"
            )
        )
        self.assertNotIn(
            "INSUFFICIENT_CONTEXT", complete["limitations"]
        )

    def test_generated_evidence_plan_matches_hypotheses(self):
        context = analyze_api_security_context(
            api_type="REST",
            api_authentication="ABSENT_OBSERVED",
            rate_limit_control="ABSENT_OBSERVED",
        )
        hypotheses = plan_api_security_hypotheses(context)
        evidence = plan_api_security_evidence(context, hypotheses)
        expected: list[str] = []
        for hypothesis in hypotheses:
            for item in HYPOTHESIS_EVIDENCE[hypothesis["hypothesis_type"]]:
                if item not in expected:
                    expected.append(item)
        self.assertEqual(evidence["evidence_items"], expected)

    def test_schema_rejects_bad_values_and_extra(self):
        base = plan_api_security_evidence(
            analyze_api_security_context(api_type="REST")
        )
        with self.assertRaises(ValidationError):
            schema.APISecurityEvidencePlan(
                **{**base, "evidence_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityEvidencePlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityEvidencePlan(
                **{**base, "evidence_items": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityEvidencePlan(
                **{**base, "limitations": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityEvidencePlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityEvidencePlan(**{**base, "token": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.APISecurityEvidencePlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r49-4")

    def test_deterministic_serialization(self):
        first = json.dumps(
            plan_api_security_evidence(
                analyze_api_security_context(
                    api_type="REST",
                    api_authentication="ABSENT_OBSERVED",
                )
            ),
            sort_keys=True,
        )
        second = json.dumps(
            plan_api_security_evidence(
                analyze_api_security_context(
                    api_type="REST",
                    api_authentication="ABSENT_OBSERVED",
                )
            ),
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
