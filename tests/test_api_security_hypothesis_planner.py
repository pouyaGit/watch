"""tests/test_api_security_hypothesis_planner.py — Stage R49.3 tests.

Deterministic, offline tests for the API security hypothesis planner:

- authentication, authorization, function/tenant, input/schema, mass
  assignment, method, versioning, exposure, error/debug, rate/resource
  limit, pagination/batch, upload/download, GraphQL, CORS, API key and
  webhook reasoning
- present-control vs gap distinction and negative signals
- needs-evidence semantics and no speculation from technology presence
- R46/R47/R48 responsibility-boundary checks
- deterministic ordering, priority, state and rationale
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
from ai.knowledge.api_security_hypothesis_planner import (
    plan_api_security_hypotheses,
)
from ai.schemas import api_security_hypothesis as schema
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.api_security_hypothesis import (
    HYPOTHESIS_STATES,
    SIGNAL_API_AUTHENTICATION_ABSENT,
    SIGNAL_GRAPHQL_FIELD_AUTHORIZATION_ABSENT,
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


def hypotheses_for(**context):
    return plan_api_security_hypotheses(analyze_api_security_context(**context))


def types_of(hypotheses):
    return [entry["hypothesis_type"] for entry in hypotheses]


def by_type(hypotheses, hypothesis_type):
    return [
        entry
        for entry in hypotheses
        if entry["hypothesis_type"] == hypothesis_type
    ]


class TestAPISecurityHypothesisPlanner(unittest.TestCase):
    def test_authentication_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", api_authentication="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "API_AUTHENTICATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertIn(
            SIGNAL_API_AUTHENTICATION_ABSENT, gap["supporting_signals"]
        )
        not_provided = hypotheses_for(api_type="REST")
        gap = by_type(not_provided, "API_AUTHENTICATION_GAP")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertEqual(gap["priority"], "LOW")

    def test_authorization_reasoning(self):
        endpoint = hypotheses_for(
            api_type="REST", endpoint_authorization="ABSENT_OBSERVED"
        )
        gap = by_type(endpoint, "API_AUTHORIZATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            api_type="REST", endpoint_authorization="ENFORCED_OBSERVED"
        )
        self.assertEqual(by_type(enforced, "API_AUTHORIZATION_GAP"), [])
        self.assertTrue(
            by_type(enforced, "API_SECURITY_CONTROL_PRESENT")
        )

    def test_function_level_authorization_reasoning(self):
        absent = hypotheses_for(
            api_type="REST",
            function_role_authorization="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "FUNCTION_LEVEL_AUTHORIZATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            api_type="REST",
            function_role_authorization="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            by_type(enforced, "FUNCTION_LEVEL_AUTHORIZATION_GAP"), []
        )

    def test_tenant_isolation_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", tenant_isolation="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "TENANT_ISOLATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            api_type="REST", tenant_isolation="ENFORCED_OBSERVED"
        )
        self.assertEqual(by_type(enforced, "TENANT_ISOLATION_GAP"), [])

    def test_input_and_schema_validation_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", parameter_validation="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "INPUT_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        schema_absent = hypotheses_for(
            api_type="REST", schema_validation="ABSENT_OBSERVED"
        )
        gap = by_type(schema_absent, "SCHEMA_VALIDATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")

    def test_mass_assignment_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", unknown_field_handling="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "MASS_ASSIGNMENT_RISK")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        rejected = hypotheses_for(
            api_type="REST", unknown_field_handling="ENFORCED_OBSERVED"
        )
        self.assertEqual(by_type(rejected, "MASS_ASSIGNMENT_RISK"), [])
        not_provided = hypotheses_for(api_type="REST")
        gap = by_type(not_provided, "MASS_ASSIGNMENT_RISK")[0]
        self.assertEqual(gap["hypothesis_state"], "NEEDS_EVIDENCE")

    def test_http_method_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", http_method_restrictions="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "HTTP_METHOD_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            api_type="REST", http_method_restrictions="ENFORCED_OBSERVED"
        )
        self.assertEqual(
            by_type(enforced, "HTTP_METHOD_CONTROL_GAP"), []
        )

    def test_method_override_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", method_override_control="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "METHOD_OVERRIDE_RISK")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        controlled = hypotheses_for(
            api_type="REST", method_override_control="ENFORCED_OBSERVED"
        )
        self.assertEqual(by_type(controlled, "METHOD_OVERRIDE_RISK"), [])

    def test_api_versioning_reasoning(self):
        deprecated = hypotheses_for(
            api_type="REST",
            api_versioning="DEPRECATED_VERSION_OBSERVED",
        )
        gap = by_type(deprecated, "API_VERSIONING_RISK")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        versioned = hypotheses_for(
            api_type="REST", api_versioning="VERSIONED_OBSERVED"
        )
        self.assertEqual(by_type(versioned, "API_VERSIONING_RISK"), [])

    def test_resource_and_sensitive_exposure_reasoning(self):
        excessive = hypotheses_for(
            api_type="REST",
            resource_exposure="EXCESSIVE_DATA_OBSERVED",
        )
        gap = by_type(excessive, "RESOURCE_EXPOSURE_RISK")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        sensitive = hypotheses_for(
            api_type="REST",
            sensitive_field_exposure="SENSITIVE_FIELDS_OBSERVED",
        )
        gap = by_type(sensitive, "SENSITIVE_FIELD_EXPOSURE_RISK")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")

    def test_error_and_debug_reasoning(self):
        stack_trace = hypotheses_for(
            api_type="REST", error_detail="STACK_TRACE_OBSERVED"
        )
        gap = by_type(stack_trace, "ERROR_INFORMATION_DISCLOSURE")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        debug = hypotheses_for(
            api_type="REST", debug_information="OBSERVED"
        )
        gap = by_type(debug, "DEBUG_INFORMATION_EXPOSURE")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        generic = hypotheses_for(
            api_type="REST", error_detail="GENERIC_MESSAGE_OBSERVED"
        )
        self.assertEqual(
            by_type(generic, "ERROR_INFORMATION_DISCLOSURE"), []
        )

    def test_rate_limit_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", rate_limit_control="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "RATE_LIMIT_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            api_type="REST", rate_limit_control="ENFORCED_OBSERVED"
        )
        self.assertEqual(by_type(enforced, "RATE_LIMIT_CONTROL_GAP"), [])

    def test_resource_limit_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", request_size_limit="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "RESOURCE_LIMIT_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")

    def test_pagination_reasoning(self):
        absent = hypotheses_for(
            api_type="REST",
            pagination_context="OBSERVED",
            pagination_limit="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "PAGINATION_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        bounded = hypotheses_for(
            api_type="REST",
            pagination_context="OBSERVED",
            pagination_limit="ENFORCED_OBSERVED",
        )
        self.assertEqual(by_type(bounded, "PAGINATION_CONTROL_GAP"), [])

    def test_batch_reasoning(self):
        absent = hypotheses_for(
            api_type="REST",
            batch_context="OBSERVED",
            batch_limit="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "BATCH_OPERATION_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        no_batch = hypotheses_for(api_type="REST")
        self.assertEqual(
            by_type(no_batch, "BATCH_OPERATION_CONTROL_GAP"), []
        )

    def test_file_upload_download_reasoning(self):
        upload = hypotheses_for(
            api_type="REST",
            file_upload_context="OBSERVED",
            upload_limit="ABSENT_OBSERVED",
        )
        gap = by_type(upload, "FILE_UPLOAD_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        download = hypotheses_for(
            api_type="REST",
            file_download_context="OBSERVED",
            download_control="ABSENT_OBSERVED",
        )
        gap = by_type(download, "FILE_DOWNLOAD_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")

    def test_graphql_introspection_reasoning(self):
        enabled = hypotheses_for(
            api_type="GRAPHQL",
            graphql_introspection="INTROSPECTION_ENABLED_OBSERVED",
        )
        gap = by_type(enabled, "GRAPHQL_INTROSPECTION_RISK")[0]
        self.assertEqual(gap["priority"], "LOW")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        disabled = hypotheses_for(
            api_type="GRAPHQL",
            graphql_introspection="INTROSPECTION_DISABLED_OBSERVED",
        )
        self.assertEqual(
            by_type(disabled, "GRAPHQL_INTROSPECTION_RISK"), []
        )

    def test_graphql_authorization_reasoning(self):
        absent = hypotheses_for(
            api_type="GRAPHQL",
            graphql_field_authorization="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "GRAPHQL_AUTHORIZATION_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        self.assertIn(
            SIGNAL_GRAPHQL_FIELD_AUTHORIZATION_ABSENT,
            gap["supporting_signals"],
        )
        enforced = hypotheses_for(
            api_type="GRAPHQL",
            graphql_field_authorization="ENFORCED_OBSERVED",
            graphql_mutation_authorization="ENFORCED_OBSERVED",
        )
        self.assertEqual(
            by_type(enforced, "GRAPHQL_AUTHORIZATION_GAP"), []
        )

    def test_graphql_query_complexity_reasoning(self):
        absent = hypotheses_for(
            api_type="GRAPHQL",
            graphql_complexity_limit="ABSENT_OBSERVED",
            graphql_depth_limit="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "GRAPHQL_QUERY_COMPLEXITY_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        generic = hypotheses_for(api_type="REST")
        self.assertEqual(
            by_type(generic, "GRAPHQL_QUERY_COMPLEXITY_GAP"), []
        )
        self.assertTrue(
            by_type(generic, "QUERY_COMPLEXITY_CONTROL_GAP")
        )

    def test_cors_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", cors_origin_policy="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "CORS_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "HIGH")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        strict = hypotheses_for(
            api_type="REST",
            cors_origin_policy="ENFORCED_OBSERVED",
            cors_credentials_policy="ENFORCED_OBSERVED",
        )
        self.assertEqual(by_type(strict, "CORS_CONTROL_GAP"), [])

    def test_api_key_reasoning(self):
        absent = hypotheses_for(
            api_type="REST",
            authentication_mechanism="API_KEY",
            api_key_rotation="ABSENT_OBSERVED",
            api_key_revocation="ABSENT_OBSERVED",
        )
        gap = by_type(absent, "API_KEY_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        non_key = hypotheses_for(api_type="REST")
        self.assertEqual(by_type(non_key, "API_KEY_CONTROL_GAP"), [])

    def test_webhook_reasoning(self):
        absent = hypotheses_for(
            api_type="WEBHOOK",
            webhook_signature_validation="ABSENT_OBSERVED",
            webhook_replay_protection="ABSENT_OBSERVED",
        )
        signature = by_type(
            absent, "WEBHOOK_SIGNATURE_CONTROL_GAP"
        )[0]
        self.assertEqual(signature["priority"], "HIGH")
        self.assertEqual(
            signature["hypothesis_state"], "WEAKNESS_OBSERVED"
        )
        replay = by_type(absent, "WEBHOOK_REPLAY_CONTROL_GAP")[0]
        self.assertEqual(replay["priority"], "HIGH")
        self.assertEqual(replay["hypothesis_state"], "WEAKNESS_OBSERVED")
        non_webhook = hypotheses_for(api_type="REST")
        self.assertEqual(
            by_type(non_webhook, "WEBHOOK_SIGNATURE_CONTROL_GAP"), []
        )

    def test_content_type_control_reasoning(self):
        absent = hypotheses_for(
            api_type="REST", content_type_validation="ABSENT_OBSERVED"
        )
        gap = by_type(absent, "CONTENT_TYPE_CONTROL_GAP")[0]
        self.assertEqual(gap["priority"], "MEDIUM")
        self.assertEqual(gap["hypothesis_state"], "WEAKNESS_OBSERVED")
        enforced = hypotheses_for(
            api_type="REST", content_type_validation="ENFORCED_OBSERVED"
        )
        self.assertEqual(
            by_type(enforced, "CONTENT_TYPE_CONTROL_GAP"), []
        )

    def test_control_present_reasoning(self):
        controlled = hypotheses_for(
            api_type="REST",
            api_authentication="ENFORCED_OBSERVED",
            endpoint_authorization="ENFORCED_OBSERVED",
            rate_limit_control="ENFORCED_OBSERVED",
        )
        control = by_type(controlled, "API_SECURITY_CONTROL_PRESENT")
        self.assertEqual(len(control), 1)
        self.assertEqual(
            control[0]["hypothesis_state"], "CONTROL_PRESENT_OBSERVED"
        )
        self.assertEqual(control[0]["priority"], "LOW")

    def test_negative_signals_reduce_priority(self):
        weak = hypotheses_for(
            api_type="REST", api_authentication="ABSENT_OBSERVED"
        )
        controlled = hypotheses_for(
            api_type="REST",
            api_authentication="ENFORCED_OBSERVED",
            endpoint_authorization="ENFORCED_OBSERVED",
        )
        self.assertTrue(by_type(weak, "API_AUTHENTICATION_GAP"))
        self.assertEqual(
            by_type(controlled, "API_AUTHENTICATION_GAP"), []
        )

    def test_no_speculation_from_technology_presence(self):
        api_only = hypotheses_for(
            api_type="REST",
            content_type="JSON_OBSERVED",
            endpoint_metadata="OBSERVED",
            request_schema="OBSERVED",
            response_schema="OBSERVED",
            pagination_context="OBSERVED",
            authentication_mechanism="BEARER_TOKEN",
        )
        for entry in api_only:
            self.assertNotEqual(entry["priority"], "HIGH")
            self.assertEqual(entry["hypothesis_state"], "NEEDS_EVIDENCE")
        self.assertNotIn(
            "WEAKNESS_OBSERVED",
            [entry["hypothesis_state"] for entry in api_only],
        )

    def test_missing_context_handling(self):
        unknown = hypotheses_for()
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["hypothesis_type"], "UNKNOWN")
        self.assertEqual(unknown[0]["hypothesis_state"], "UNKNOWN")
        self.assertIn(
            "INSUFFICIENT_CONTEXT", unknown[0]["limitations"]
        )
        missing = hypotheses_for(
            sensitive_field_exposure="SENSITIVE_FIELDS_OBSERVED"
        )
        self.assertEqual(
            types_of(missing), ["MISSING_API_CONTEXT"]
        )
        self.assertEqual(
            missing[0]["hypothesis_state"], "NEEDS_EVIDENCE"
        )

    def test_responsibility_boundaries_with_r46_r47_r48(self):
        hypotheses = hypotheses_for(
            api_type="REST",
            object_authorization_context="OBSERVED",
            authentication_mechanism="JWT_BEARER",
            api_authentication="NOT_PROVIDED",
        )
        types = types_of(hypotheses)
        for forbidden in (
            "BOLA",
            "IDOR",
            "OBJECT_LEVEL_AUTHORIZATION_GAP",
            "JWT_VALIDATION_GAP",
            "SIGNATURE_VERIFICATION_GAP",
            "REDIRECT_URI_VALIDATION_GAP",
            "PKCE_ENFORCEMENT_GAP",
        ):
            self.assertNotIn(forbidden, types)
        self.assertNotIn(
            "OBJECT_AUTHORIZATION_CONTEXT_OBSERVED", types
        )

    def test_hypotheses_are_canonical_ordered_and_closed(self):
        hypotheses = hypotheses_for(
            api_type="GRAPHQL",
            api_authentication="ABSENT_OBSERVED",
            rate_limit_control="ABSENT_OBSERVED",
            graphql_field_authorization="ABSENT_OBSERVED",
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
                self.assertIn(signal, schema.API_SECURITY_SIGNALS)
            self.assertNotEqual(entry["rationale"], "")

    def test_hypothesis_limitations(self):
        hypotheses = hypotheses_for(
            api_type="REST", api_authentication="ABSENT_OBSERVED"
        )
        for entry in hypotheses:
            for limitation in (
                "NO_EXPLOIT_CLAIM",
                "NO_VULNERABILITY_CONFIRMATION",
                "NO_API_ATTACK_CLAIM",
                "NO_AUTH_BYPASS_CLAIM",
                "NO_IDOR_EXPLOIT_CLAIM",
                "NO_INJECTION_EXPLOIT_CLAIM",
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
            api_type="REST", api_authentication="ABSENT_OBSERVED"
        )[0]
        with self.assertRaises(ValidationError):
            schema.APISecurityHypothesisPlan(
                **{**base, "hypothesis_type": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityHypothesisPlan(
                **{**base, "hypothesis_state": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityHypothesisPlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityHypothesisPlan(
                **{**base, "priority": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityHypothesisPlan(
                **{**base, "supporting_signals": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityHypothesisPlan(
                **{**base, "limitations": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityHypothesisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityHypothesisPlan(**{**base, "token": "x"})

    def test_schema_forces_rule_version(self):
        plan = schema.APISecurityHypothesisPlan(
            hypothesis_type="API_AUTHENTICATION_GAP",
            rule_version="r99-9",
        )
        self.assertEqual(plan.rule_version, "r49-3")

    def test_deterministic_serialization(self):
        first = json.dumps(
            hypotheses_for(
                api_type="REST", api_authentication="ABSENT_OBSERVED"
            ),
            sort_keys=True,
        )
        second = json.dumps(
            hypotheses_for(
                api_type="REST", api_authentication="ABSENT_OBSERVED"
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
