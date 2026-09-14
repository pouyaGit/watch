"""tests/test_api_security_context_analyzer.py — Stage R49.2 tests.

Deterministic, offline tests for the API security context analyzer:

- API type, versioning, content type and authentication detection
- authentication, authorization, function/tenant, input/schema, mass
  assignment, method, versioning, exposure, error/debug, rate/resource
  limit, pagination/batch, upload/download, GraphQL, CORS, API key and
  webhook reasoning
- deterministic normalization and malformed-input degradation
- confidence calibration (technology presence is never HIGH)
- observed vs inferred vs not-provided distinction
- schema validation and extra-field rejection
- R49 AST safety scan and standalone backend decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no API calls, no endpoint probing, no payloads, no Mongo
writes, no persistence, no execution of any kind.
"""
import ast
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.api_security_context_analyzer import (
    analyze_api_security_context,
    api_key_context_present,
    api_security_context_confidence_of,
    api_security_context_present,
    batch_context_present,
    control_observed,
    file_download_context_present,
    file_upload_context_present,
    graphql_context_present,
    pagination_context_present,
    validation_state_of,
    weakness_observed,
    webhook_context_present,
)
from ai.schemas import api_security_context_analysis as schema


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


class TestAPISecurityContextAnalyzer(unittest.TestCase):
    def test_api_type_detection(self):
        for api_type in ("REST", "GRAPHQL", "RPC", "JSON_API", "XML_API",
                         "WEBHOOK"):
            analysis = analyze_api_security_context(api_type=api_type)
            self.assertEqual(analysis["api_type"], api_type)
        self.assertEqual(
            analyze_api_security_context(
                api_type="rest"
            )["api_type"],
            "REST",
        )
        self.assertEqual(
            analyze_api_security_context()["api_type"], "UNKNOWN"
        )

    def test_api_versioning_detection(self):
        for state in (
            "VERSIONED_OBSERVED",
            "UNVERSIONED_OBSERVED",
            "DEPRECATED_VERSION_OBSERVED",
        ):
            analysis = analyze_api_security_context(api_versioning=state)
            self.assertEqual(analysis["api_versioning"], state)

    def test_content_type_detection(self):
        for state in (
            "JSON_OBSERVED",
            "FORM_OBSERVED",
            "XML_OBSERVED",
            "MULTIPART_OBSERVED",
        ):
            analysis = analyze_api_security_context(content_type=state)
            self.assertEqual(analysis["content_type"], state)

    def test_authentication_mechanism_detection(self):
        for mechanism in schema.KNOWN_AUTHENTICATION_MECHANISMS:
            analysis = analyze_api_security_context(
                authentication_mechanism=mechanism
            )
            self.assertEqual(
                analysis["authentication_mechanism"], mechanism
            )
        self.assertEqual(
            analyze_api_security_context(
                authentication_mechanism="bearer_token"
            )["authentication_mechanism"],
            "BEARER_TOKEN",
        )

    def test_valid_context_analysis(self):
        analysis = analyze_api_security_context(
            api_type="REST",
            api_versioning="VERSIONED_OBSERVED",
            content_type="JSON_OBSERVED",
            authentication_mechanism="BEARER_TOKEN",
            endpoint_metadata="OBSERVED",
            request_schema="OBSERVED",
            response_schema="OBSERVED",
            pagination_context="OBSERVED",
            object_authorization_context="OBSERVED",
        )
        self.assertEqual(analysis["api_type"], "REST")
        self.assertEqual(analysis["content_type"], "JSON_OBSERVED")
        self.assertTrue(api_security_context_present(analysis))
        self.assertFalse(graphql_context_present(analysis))
        self.assertFalse(webhook_context_present(analysis))

    def test_malformed_input_degrades(self):
        analysis = analyze_api_security_context(
            api_type="NOPE",
            api_versioning=42,
            content_type=["JSON_OBSERVED"],
            api_authentication="maybe",
            error_detail="nope",
            cors_origin_policy=object(),
        )
        self.assertEqual(analysis["api_type"], "UNKNOWN")
        self.assertEqual(analysis["api_versioning"], "UNKNOWN")
        self.assertEqual(analysis["content_type"], "UNKNOWN")
        self.assertEqual(analysis["api_authentication"], "NOT_PROVIDED")
        self.assertEqual(analysis["error_detail"], "UNKNOWN")
        self.assertEqual(analysis["cors_origin_policy"], "NOT_PROVIDED")

    def test_deterministic_normalization(self):
        first = analyze_api_security_context(
            api_type=" graphql ",
            graphql_field_authorization="absent_observed",
            content_type="json_observed",
        )
        second = analyze_api_security_context(
            api_type="GRAPHQL",
            graphql_field_authorization="ABSENT_OBSERVED",
            content_type="JSON_OBSERVED",
        )
        self.assertEqual(first, second)

    def test_confidence_calibration(self):
        self.assertEqual(
            analyze_api_security_context()["context_confidence"], "UNKNOWN"
        )
        rest_only = analyze_api_security_context(api_type="REST")
        self.assertEqual(rest_only["context_confidence"], "LOW")
        graphql_only = analyze_api_security_context(api_type="GRAPHQL")
        self.assertEqual(graphql_only["context_confidence"], "LOW")
        self.assertNotEqual(
            analyze_api_security_context(
                pagination_context="OBSERVED"
            )["context_confidence"],
            "HIGH",
        )
        self.assertNotEqual(
            analyze_api_security_context(
                api_versioning="DEPRECATED_VERSION_OBSERVED"
            )["context_confidence"],
            "HIGH",
        )
        self.assertNotEqual(
            analyze_api_security_context(
                graphql_introspection="INTROSPECTION_ENABLED_OBSERVED"
            )["context_confidence"],
            "HIGH",
        )

    def test_technology_presence_is_not_weakness(self):
        analysis = analyze_api_security_context(
            api_type="REST",
            content_type="JSON_OBSERVED",
            authentication_mechanism="BEARER_TOKEN",
            endpoint_metadata="OBSERVED",
            request_schema="OBSERVED",
            response_schema="OBSERVED",
            pagination_context="OBSERVED",
            rate_limit_control="NOT_PROVIDED",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))
        self.assertFalse(control_observed(analysis))

    def test_observed_control_is_medium(self):
        analysis = analyze_api_security_context(
            api_type="REST",
            api_authentication="ENFORCED_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "MEDIUM")
        self.assertTrue(control_observed(analysis))
        self.assertFalse(weakness_observed(analysis))

    def test_observed_weakness_is_high(self):
        analysis = analyze_api_security_context(
            api_type="REST",
            api_authentication="ABSENT_OBSERVED",
        )
        self.assertEqual(analysis["context_confidence"], "HIGH")
        self.assertTrue(weakness_observed(analysis))

    def test_not_provided_is_not_weakness(self):
        analysis = analyze_api_security_context(
            api_type="REST",
            api_authentication="NOT_PROVIDED",
            endpoint_authorization="NOT_PROVIDED",
            rate_limit_control="NOT_PROVIDED",
        )
        self.assertEqual(analysis["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(analysis))

    def test_authentication_reasoning(self):
        absent = analyze_api_security_context(
            api_type="REST", api_authentication="ABSENT_OBSERVED"
        )
        enforced = analyze_api_security_context(
            api_type="REST", api_authentication="ENFORCED_OBSERVED"
        )
        self.assertTrue(weakness_observed(absent))
        self.assertTrue(control_observed(enforced))
        self.assertFalse(weakness_observed(enforced))

    def test_authorization_reasoning(self):
        endpoint = analyze_api_security_context(
            api_type="REST", endpoint_authorization="ABSENT_OBSERVED"
        )
        function = analyze_api_security_context(
            api_type="REST",
            function_role_authorization="ABSENT_OBSERVED",
        )
        tenant = analyze_api_security_context(
            api_type="REST", tenant_isolation="ABSENT_OBSERVED"
        )
        controlled = analyze_api_security_context(
            api_type="REST",
            endpoint_authorization="ENFORCED_OBSERVED",
            function_role_authorization="ENFORCED_OBSERVED",
            tenant_isolation="ENFORCED_OBSERVED",
        )
        for analysis in (endpoint, function, tenant):
            self.assertTrue(weakness_observed(analysis))
        self.assertTrue(control_observed(controlled))
        self.assertFalse(weakness_observed(controlled))

    def test_input_and_schema_validation_reasoning(self):
        parameter = analyze_api_security_context(
            api_type="REST", parameter_validation="ABSENT_OBSERVED"
        )
        schema_state = analyze_api_security_context(
            api_type="REST", schema_validation="ABSENT_OBSERVED"
        )
        enforced = analyze_api_security_context(
            api_type="REST",
            parameter_validation="ENFORCED_OBSERVED",
            schema_validation="ENFORCED_OBSERVED",
        )
        self.assertTrue(weakness_observed(parameter))
        self.assertTrue(weakness_observed(schema_state))
        self.assertTrue(control_observed(enforced))

    def test_mass_assignment_reasoning(self):
        absent = analyze_api_security_context(
            api_type="REST", unknown_field_handling="ABSENT_OBSERVED"
        )
        rejected = analyze_api_security_context(
            api_type="REST", unknown_field_handling="ENFORCED_OBSERVED"
        )
        self.assertTrue(weakness_observed(absent))
        self.assertFalse(weakness_observed(rejected))

    def test_http_method_and_override_reasoning(self):
        method = analyze_api_security_context(
            api_type="REST", http_method_restrictions="ABSENT_OBSERVED"
        )
        override = analyze_api_security_context(
            api_type="REST", method_override_control="ABSENT_OBSERVED"
        )
        restricted = analyze_api_security_context(
            api_type="REST",
            http_method_restrictions="ENFORCED_OBSERVED",
            method_override_control="ENFORCED_OBSERVED",
        )
        self.assertTrue(weakness_observed(method))
        self.assertTrue(weakness_observed(override))
        self.assertTrue(control_observed(restricted))

    def test_versioning_reasoning(self):
        deprecated = analyze_api_security_context(
            api_type="REST",
            api_versioning="DEPRECATED_VERSION_OBSERVED",
        )
        versioned = analyze_api_security_context(
            api_type="REST", api_versioning="VERSIONED_OBSERVED"
        )
        self.assertEqual(deprecated["context_confidence"], "LOW")
        self.assertFalse(weakness_observed(deprecated))
        self.assertFalse(weakness_observed(versioned))

    def test_resource_and_sensitive_exposure_reasoning(self):
        excessive = analyze_api_security_context(
            api_type="REST",
            resource_exposure="EXCESSIVE_DATA_OBSERVED",
        )
        sensitive = analyze_api_security_context(
            api_type="REST",
            sensitive_field_exposure="SENSITIVE_FIELDS_OBSERVED",
        )
        internal = analyze_api_security_context(
            api_type="REST",
            sensitive_field_exposure="INTERNAL_IDENTIFIERS_OBSERVED",
        )
        none = analyze_api_security_context(
            api_type="REST",
            resource_exposure="NONE_OBSERVED",
            sensitive_field_exposure="NONE_OBSERVED",
        )
        for analysis in (excessive, sensitive, internal):
            self.assertTrue(weakness_observed(analysis))
        self.assertFalse(weakness_observed(none))

    def test_error_and_debug_reasoning(self):
        detailed = analyze_api_security_context(
            api_type="REST", error_detail="DETAILED_ERROR_OBSERVED"
        )
        stack_trace = analyze_api_security_context(
            api_type="REST", error_detail="STACK_TRACE_OBSERVED"
        )
        generic = analyze_api_security_context(
            api_type="REST", error_detail="GENERIC_MESSAGE_OBSERVED"
        )
        debug = analyze_api_security_context(
            api_type="REST", debug_information="OBSERVED"
        )
        self.assertTrue(weakness_observed(detailed))
        self.assertTrue(weakness_observed(stack_trace))
        self.assertFalse(weakness_observed(generic))
        self.assertTrue(weakness_observed(debug))

    def test_rate_limit_and_resource_limit_reasoning(self):
        rate = analyze_api_security_context(
            api_type="REST", rate_limit_control="ABSENT_OBSERVED"
        )
        size = analyze_api_security_context(
            api_type="REST", request_size_limit="ABSENT_OBSERVED"
        )
        controlled = analyze_api_security_context(
            api_type="REST",
            rate_limit_control="ENFORCED_OBSERVED",
            request_size_limit="ENFORCED_OBSERVED",
        )
        self.assertTrue(weakness_observed(rate))
        self.assertTrue(weakness_observed(size))
        self.assertTrue(control_observed(controlled))

    def test_pagination_and_batch_reasoning(self):
        pagination = analyze_api_security_context(
            api_type="REST", pagination_limit="ABSENT_OBSERVED"
        )
        batch = analyze_api_security_context(
            api_type="REST", batch_limit="ABSENT_OBSERVED"
        )
        self.assertTrue(weakness_observed(pagination))
        self.assertTrue(weakness_observed(batch))
        self.assertTrue(
            pagination_context_present(
                analyze_api_security_context(
                    pagination_context="OBSERVED"
                )
            )
        )
        self.assertTrue(
            batch_context_present(
                analyze_api_security_context(batch_context="OBSERVED")
            )
        )

    def test_file_upload_download_reasoning(self):
        upload = analyze_api_security_context(
            api_type="REST", upload_limit="ABSENT_OBSERVED"
        )
        download = analyze_api_security_context(
            api_type="REST", download_control="ABSENT_OBSERVED"
        )
        self.assertTrue(weakness_observed(upload))
        self.assertTrue(weakness_observed(download))
        self.assertTrue(
            file_upload_context_present(
                analyze_api_security_context(
                    file_upload_context="OBSERVED"
                )
            )
        )
        self.assertTrue(
            file_download_context_present(
                analyze_api_security_context(
                    file_download_context="OBSERVED"
                )
            )
        )

    def test_graphql_reasoning(self):
        analysis = analyze_api_security_context(
            api_type="GRAPHQL",
            graphql_introspection="INTROSPECTION_ENABLED_OBSERVED",
            graphql_field_authorization="ABSENT_OBSERVED",
            graphql_complexity_limit="ABSENT_OBSERVED",
        )
        self.assertTrue(graphql_context_present(analysis))
        self.assertTrue(weakness_observed(analysis))
        introspection_only = analyze_api_security_context(
            api_type="GRAPHQL",
            graphql_introspection="INTROSPECTION_ENABLED_OBSERVED",
        )
        self.assertEqual(
            introspection_only["context_confidence"], "LOW"
        )
        self.assertFalse(weakness_observed(introspection_only))

    def test_cors_reasoning(self):
        absent = analyze_api_security_context(
            api_type="REST", cors_origin_policy="ABSENT_OBSERVED"
        )
        strict = analyze_api_security_context(
            api_type="REST",
            cors_origin_policy="ENFORCED_OBSERVED",
            cors_credentials_policy="ENFORCED_OBSERVED",
        )
        self.assertTrue(weakness_observed(absent))
        self.assertTrue(control_observed(strict))

    def test_api_key_reasoning(self):
        analysis = analyze_api_security_context(
            api_type="REST",
            authentication_mechanism="API_KEY",
            api_key_rotation="ABSENT_OBSERVED",
        )
        self.assertTrue(api_key_context_present(analysis))
        self.assertTrue(weakness_observed(analysis))
        controlled = analyze_api_security_context(
            api_type="REST",
            authentication_mechanism="API_KEY",
            api_key_rotation="ENFORCED_OBSERVED",
            api_key_revocation="ENFORCED_OBSERVED",
        )
        self.assertTrue(control_observed(controlled))

    def test_webhook_reasoning(self):
        analysis = analyze_api_security_context(
            api_type="WEBHOOK",
            webhook_signature_validation="ABSENT_OBSERVED",
            webhook_replay_protection="ABSENT_OBSERVED",
        )
        self.assertTrue(webhook_context_present(analysis))
        self.assertTrue(weakness_observed(analysis))
        controlled = analyze_api_security_context(
            api_type="WEBHOOK",
            webhook_signature_validation="ENFORCED_OBSERVED",
        )
        self.assertTrue(control_observed(controlled))

    def test_content_type_control_reasoning(self):
        absent = analyze_api_security_context(
            api_type="REST", content_type_validation="ABSENT_OBSERVED"
        )
        enforced = analyze_api_security_context(
            api_type="REST", content_type_validation="ENFORCED_OBSERVED"
        )
        self.assertTrue(weakness_observed(absent))
        self.assertTrue(control_observed(enforced))

    def test_isolated_risk_without_api_context_is_not_high(self):
        for analysis in (
            analyze_api_security_context(
                sensitive_field_exposure="SENSITIVE_FIELDS_OBSERVED"
            ),
            analyze_api_security_context(
                error_detail="STACK_TRACE_OBSERVED"
            ),
            analyze_api_security_context(
                debug_information="OBSERVED"
            ),
            analyze_api_security_context(
                resource_exposure="EXCESSIVE_DATA_OBSERVED"
            ),
            analyze_api_security_context(
                api_authentication="ABSENT_OBSERVED"
            ),
            analyze_api_security_context(
                rate_limit_control="ABSENT_OBSERVED"
            ),
        ):
            self.assertNotEqual(
                analysis["context_confidence"], "HIGH"
            )
            self.assertFalse(weakness_observed(analysis))

    def test_missing_context_handling(self):
        analysis = analyze_api_security_context()
        self.assertFalse(api_security_context_present(analysis))
        self.assertEqual(analysis["context_confidence"], "UNKNOWN")
        partial = analyze_api_security_context(api_type="REST")
        self.assertTrue(api_security_context_present(partial))

    def test_validation_state_helper(self):
        analysis = analyze_api_security_context(
            api_type="REST", api_authentication="ENFORCED_OBSERVED"
        )
        self.assertEqual(
            validation_state_of(analysis, "api_authentication"),
            "ENFORCED_OBSERVED",
        )
        self.assertEqual(
            validation_state_of(analysis, "rate_limit_control"),
            "NOT_PROVIDED",
        )
        self.assertEqual(
            validation_state_of(analysis, "nope"), "UNKNOWN"
        )

    def test_confidence_recompute_ignores_stored_value(self):
        analysis = analyze_api_security_context(
            api_type="REST", api_authentication="ABSENT_OBSERVED"
        )
        forged = copy.deepcopy(analysis)
        forged["context_confidence"] = "UNKNOWN"
        self.assertEqual(
            api_security_context_confidence_of(forged), "HIGH"
        )
        downgraded = copy.deepcopy(analysis)
        downgraded["context_confidence"] = "LOW"
        self.assertEqual(
            api_security_context_confidence_of(downgraded), "HIGH"
        )

    def test_schema_rejects_bad_values_and_extra(self):
        base = analyze_api_security_context(api_type="REST")
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "api_type": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "api_versioning": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "content_type": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "authentication_mechanism": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "error_detail": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "graphql_introspection": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "endpoint_metadata": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "rate_limit_control": "MAYBE"}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.APISecurityContextAnalysisPlan(
                **{**base, "endpoint": "https://example"}
            )

    def test_schema_forces_rule_version(self):
        plan = schema.APISecurityContextAnalysisPlan(
            **{
                **analyze_api_security_context(),
                "rule_version": "r99-9",
            }
        )
        self.assertEqual(plan.rule_version, "r49-2")

    def test_deterministic_serialization(self):
        first = json.dumps(
            analyze_api_security_context(
                api_type="REST",
                api_authentication="ABSENT_OBSERVED",
                rate_limit_control="NOT_PROVIDED",
            ),
            sort_keys=True,
        )
        second = json.dumps(
            analyze_api_security_context(
                api_type="REST",
                api_authentication="ABSENT_OBSERVED",
                rate_limit_control="NOT_PROVIDED",
            ),
            sort_keys=True,
        )
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())

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
