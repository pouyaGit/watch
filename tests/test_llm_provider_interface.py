"""tests/test_llm_provider_interface.py — Stage R51 interface tests.

Deterministic, offline tests for the R51 real provider interface:

- provider interface and boundary description
- explicit provider selection (fail closed, no fallback)
- provider configuration contract and bounds
- provider error contract and secret-free messages
- provider telemetry contract
- deterministic prompt construction and strict response parsing
- outbound context allowlist and data minimization
- network isolation and AST safety for the provider layer

No real API calls, no network, no LLM, no subprocess, no sockets, no
browser, no SQL, no database, no payloads, no Mongo writes, no
persistence, no execution of any kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from ai.knowledge.llm_provider import AdvisoryProvider, MockLLMProvider
from ai.providers import (
    HttpRequestSpec,
    HttpResponseSpec,
    HttpTransport,
    OpenAIProvider,
    OpenRouterProvider,
    ProviderCallError,
    ProviderContextRejected,
    RealAdvisoryProvider,
    available_provider_kinds,
    available_real_provider_kinds,
    build_provider_prompt,
    detect_sensitive_content,
    parse_advisory_content,
    sanitize_provider_context,
    select_provider,
    serialize_provider_call_error,
)
from ai.providers.provider_registry import R51_REGISTRY_KINDS
from ai.schemas.llm_provider_config import (
    MAX_MAX_TOKENS,
    MAX_RETRIES_LIMIT,
    MAX_TIMEOUT_SECONDS,
    LLMRealProviderConfigPlan,
    sanitize_llm_real_provider_config,
)
from ai.schemas.llm_provider_error import (
    ERROR_CONFIGURATION,
    ERROR_UNKNOWN,
    PROVIDER_ERROR_CATEGORIES,
    safe_error_message,
    sanitize_provider_error,
)
from ai.schemas.llm_provider_telemetry import (
    TELEMETRY_KEYS,
    sanitize_provider_telemetry,
)


ROOT = Path(__file__).resolve().parents[1]

R51_PROVIDER_MODULES = (
    "ai/providers/__init__.py",
    "ai/providers/provider_errors.py",
    "ai/providers/http_transport.py",
    "ai/providers/context_allowlist.py",
    "ai/providers/prompt_builder.py",
    "ai/providers/real_provider.py",
    "ai/providers/openrouter_provider.py",
    "ai/providers/openai_provider.py",
    "ai/providers/provider_registry.py",
    "ai/providers/advisory_bridge.py",
)

NETWORK_MODULES = {
    "urllib", "http", "socket", "ssl", "requests", "httpx", "aiohttp",
    "openai", "openrouter", "anthropic", "ollama", "litellm",
}

FORBIDDEN_CALLS = {"__import__", "eval", "exec", "compile", "open"}

FORBIDDEN_CALL_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "socket.",
    "requests.",
    "httpx.",
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


class FakeTransport(HttpTransport):
    transport_kind = "FAKE"

    def __init__(self, status=200, payload=None):
        self.status = status
        self.payload = payload if payload is not None else {}
        self.requests = []

    def send(self, spec):
        self.requests.append(spec)
        return HttpResponseSpec(
            status_code=self.status,
            body_text=json.dumps(self.payload),
        )


def advisory_content():
    return {
        "summary": "Structured research state is summarized.",
        "insights": [
            {
                "insight_code": "ADVISORY_SCOPE",
                "text": "Advisory explanation only.",
            }
        ],
        "recommendations": [],
    }


def provider_environ(
    kind="OPENROUTER",
) -> dict:
    return {
        "OPENROUTER_API_KEY": "not-a-real-key",
        "OPENROUTER_MODEL": "vendor/model",
        "OPENAI_API_KEY": "not-a-real-key",
        "OPENAI_MODEL": "vendor/model",
    }


def sample_request(**over):
    request = {
        "rule_version": "r45-3",
        "advisory_id": "adv-0123456789abcdef",
        "advisory_mode": "SUMMARY",
        "provider_kind": "OPENROUTER",
        "source_layer": "R42",
        "instruction": "Summarize the supplied state.",
        "sections": {
            "research_context": {
                "research_question": "How strong is the evidence?",
                "research_focus": "",
                "context_fact_count": 3,
                "source_layers": ["R42"],
                "research_only": True,
            },
            "evaluation_summary": {
                "present": True,
                "reference_rule_version": "r42-5",
                "evaluated_agent_category": "SSRF",
                "overall_score": 80,
                "overall_rating": "GOOD",
                "hard_gate_state": "PASS",
                "safety_state": "PASS",
                "diagnostic_count": 0,
                "diagnostic_codes": [],
            },
            "collaboration_summary": {
                "present": False,
                "reference_rule_version": "",
                "participant_count": 0,
                "hypothesis_group_count": 0,
                "conflict_count": 0,
                "conflict_types": [],
                "merged_evidence_state": "UNKNOWN",
                "governance_state": "UNKNOWN",
                "provenance_state": "UNKNOWN",
            },
            "learning_signals": [],
            "governance_state": "UNKNOWN",
            "safety_state": "PASS",
        },
        "source_refs": [{"layer": "R42", "reference": "r42-5"}],
        "limitations": ["NO_EXECUTION_PERFORMED"],
        "research_only": True,
        "deterministic": True,
    }
    request.update(over)
    return request


class TestProviderInterface(unittest.TestCase):
    def test_provider_kinds_are_explicit(self):
        self.assertEqual(
            available_provider_kinds(), ["MOCK", "OPENROUTER", "OPENAI"]
        )
        self.assertEqual(
            available_real_provider_kinds(), ["OPENROUTER", "OPENAI"]
        )
        self.assertEqual(list(R51_REGISTRY_KINDS), available_provider_kinds())

    def test_select_mock_provider(self):
        provider = select_provider("MOCK")
        self.assertIsInstance(provider, MockLLMProvider)
        self.assertIsInstance(provider, AdvisoryProvider)
        self.assertEqual(provider.provider_kind, "MOCK")

    def test_select_real_providers_explicitly(self):
        transport = FakeTransport()
        openrouter = select_provider(
            "OPENROUTER", transport=transport, environ=provider_environ()
        )
        self.assertIsInstance(openrouter, OpenRouterProvider)
        self.assertIsInstance(openrouter, RealAdvisoryProvider)
        openai = select_provider(
            "OPENAI", transport=transport, environ=provider_environ()
        )
        self.assertIsInstance(openai, OpenAIProvider)

    def test_selection_never_silently_falls_back(self):
        for kind in ("", None, "OLLAMA", "LOCAL", "NOPE"):
            with self.assertRaises(ProviderCallError) as caught:
                select_provider(kind)
            self.assertEqual(
                caught.exception.error_category, ERROR_CONFIGURATION
            )
            self.assertEqual(
                caught.exception.error_code, "CONFIG_UNSUPPORTED_KIND"
            )

    def test_provider_describe_never_exposes_credentials(self):
        provider = OpenRouterProvider(
            transport=FakeTransport(), environ=provider_environ()
        )
        described = provider.describe()
        self.assertIs(described["network_access"], True)
        self.assertIs(described["external_provider"], True)
        self.assertIs(described["credentials_configured"], True)
        self.assertIs(described["content_deterministic"], False)
        serialized = json.dumps(described).lower()
        self.assertNotIn("not-a-real-key", serialized)
        self.assertNotIn("authorization", serialized)

    def test_config_sanitizer_and_bounds(self):
        config = sanitize_llm_real_provider_config(
            {
                "provider_kind": "openai",
                "model": "vendor/model",
                "base_url": "https://api.example.test/v1",
                "api_key_env": "OPENAI_API_KEY",
                "timeout_seconds": 10_000,
                "max_retries": 10_000,
                "max_tokens": 10_000_000,
                "max_response_bytes": 10_000_000,
            }
        )
        self.assertEqual(config["provider_kind"], "OPENAI")
        self.assertEqual(config["timeout_seconds"], MAX_TIMEOUT_SECONDS)
        self.assertEqual(config["max_retries"], MAX_RETRIES_LIMIT)
        self.assertEqual(config["max_tokens"], MAX_MAX_TOKENS)
        self.assertIs(config["research_only"], True)
        self.assertNotIn("api_key", config)
        self.assertNotIn("secret", config)

    def test_config_model_rejects_credentials(self):
        config = sanitize_llm_real_provider_config(
            {
                "provider_kind": "OPENROUTER",
                "model": "sk-not-a-real-credential",
                "base_url": "http://insecure.example.test",
            }
        )
        self.assertEqual(config["model"], "")
        self.assertEqual(config["base_url"], "")

    def test_config_plan_rejects_bad_values(self):
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            LLMRealProviderConfigPlan(provider_kind="OLLAMA")
        with self.assertRaises(ValidationError):
            LLMRealProviderConfigPlan(timeout_seconds=0)
        with self.assertRaises(ValidationError):
            LLMRealProviderConfigPlan(max_retries=99)
        with self.assertRaises(ValidationError):
            LLMRealProviderConfigPlan(base_url="http://insecure")
        with self.assertRaises(ValidationError):
            LLMRealProviderConfigPlan(unexpected="x")

    def test_error_contract_is_closed_and_secret_free(self):
        self.assertIn(ERROR_CONFIGURATION, PROVIDER_ERROR_CATEGORIES)
        self.assertEqual(len(PROVIDER_ERROR_CATEGORIES), 11)
        plan = sanitize_provider_error(
            {
                "provider_kind": "OPENROUTER",
                "error_category": "NOPE",
                "error_code": "NOPE",
                "safe_message": "Authorization: Bearer not-a-real-key",
            }
        )
        self.assertEqual(plan["error_category"], ERROR_UNKNOWN)
        self.assertNotIn("not-a-real-key", json.dumps(plan))
        self.assertNotIn("bearer", plan["safe_message"].lower())

    def test_error_messages_blank_credentials(self):
        for message in (
            "Authorization: Bearer abcdefgh",
            "api_key=abcdef",
            "Cookie: session=abcdef",
            "sk-abcdef123456",
            "password=hunter2",
        ):
            sanitized = safe_error_message(message)
            self.assertNotIn("abcdef", sanitized)
            self.assertNotIn("hunter2", sanitized)

    def test_serialize_arbitrary_exception(self):
        plan = serialize_provider_call_error(RuntimeError("boom"))
        self.assertEqual(plan["error_category"], ERROR_UNKNOWN)
        self.assertIs(plan["research_only"], True)

    def test_telemetry_contract_keys_and_safety(self):
        telemetry = sanitize_provider_telemetry(
            {
                "provider_kind": "openrouter",
                "model": "vendor/model",
                "advisory_id": "adv-0123456789abcdef",
                "advisory_mode": "SUMMARY",
                "attempt_count": 2,
                "retry_count": 1,
                "success": True,
                "validation_state": "PASS",
                "response_chars": 120,
                "external_provider": True,
                "network_access": True,
                "credentials_used": True,
                "content_deterministic": False,
            }
        )
        self.assertEqual(set(telemetry.keys()), set(TELEMETRY_KEYS))
        self.assertEqual(telemetry["provider_kind"], "OPENROUTER")
        serialized = json.dumps(telemetry).lower()
        for token in ("prompt", "response\"", "authorization", "secret"):
            self.assertNotIn(token, serialized)

    def test_context_allowlist_rejects_unknown_keys(self):
        request = sample_request()
        request["sections"]["research_context"]["credentials"] = "x"
        with self.assertRaises(ProviderCallError) as caught:
            sanitize_provider_context(request)
        self.assertEqual(
            caught.exception.error_code, "CONFIG_INVALID_PARAMETER"
        )
        request = sample_request()
        request["unexpected"] = "x"
        with self.assertRaises(ProviderCallError):
            sanitize_provider_context(request)

    def test_context_allowlist_crossing_fields(self):
        bundle = sanitize_provider_context(sample_request())
        self.assertIn("advisory_id", bundle["crossing_fields"])
        self.assertIn("sections.research_context", bundle["crossing_fields"])
        self.assertIn("source_refs", bundle["crossing_fields"])
        self.assertGreater(bundle["context_chars"], 0)
        self.assertLess(bundle["context_chars"], 4000)

    def test_context_rejects_sensitive_content(self):
        payloads = (
            {"research_question": "Authorization: Bearer abcdefgh"},
            {"research_question": "Cookie: session=abcdef"},
            {"research_question": "api_key=abcdef"},
            {"research_question": "sk-abcdef123456"},
            {"research_question": "visit https://internal.example.test"},
            {"research_question": "<script>alert(1)</script>"},
        )
        for payload in payloads:
            request = sample_request()
            request["sections"]["research_context"].update(payload)
            with self.assertRaises(ProviderContextRejected) as caught:
                sanitize_provider_context(request)
            self.assertEqual(
                caught.exception.error_category, "SAFETY_VALIDATION_ERROR"
            )
            self.assertEqual(
                caught.exception.error_code, "UNSAFE_CONTEXT_REJECTED"
            )

    def test_detect_sensitive_content_reason_codes(self):
        reasons = detect_sensitive_content(
            "authorization: bearer abcdefghij; sk-abcdef123456"
        )
        self.assertIn("AUTHORIZATION_PATTERN", reasons)
        self.assertIn("CREDENTIAL_PATTERN", reasons)

    def test_prompt_builder_is_deterministic_and_bounded(self):
        bundle = sanitize_provider_context(sample_request())
        first = build_provider_prompt(bundle)
        second = build_provider_prompt(bundle)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertLessEqual(first["prompt_chars"], 8000)
        self.assertEqual(len(first["messages"]), 2)
        self.assertEqual(first["messages"][0]["role"], "system")
        self.assertEqual(first["messages"][1]["role"], "user")
        self.assertTrue(first["prompt_fingerprint"].startswith("prompt-"))

    def test_parse_advisory_content_rejects_malformed(self):
        request = sample_request()
        for content in (
            "not json",
            "[]",
            '{"summary": "x"}',
            '{"summary":"x","insights":[],"recommendations":[],"extra":1}',
            '{"summary":"","insights":[],"recommendations":[]}',
            '{"summary":"x","insights":[{"insight_code":"lower","text":"t"}],'
            '"recommendations":[]}',
            '{"summary":"x","insights":[{"insight_code":"OK","text":""}],'
            '"recommendations":[]}',
        ):
            with self.assertRaises(ProviderCallError):
                parse_advisory_content(content, request, "OPENROUTER")

    def test_parse_advisory_content_empty(self):
        with self.assertRaises(ProviderCallError) as caught:
            parse_advisory_content("   ", sample_request(), "OPENROUTER")
        self.assertEqual(caught.exception.error_category, "EMPTY_RESPONSE")

    def test_parse_advisory_content_valid_maps_to_r45(self):
        response = parse_advisory_content(
            json.dumps(advisory_content()), sample_request(), "OPENROUTER"
        )
        self.assertEqual(response["provider_kind"], "OPENROUTER")
        self.assertEqual(
            response["advisory_mode"], "SUMMARY"
        )
        self.assertEqual(
            response["source_refs"],
            [{"layer": "R42", "reference": "r42-5"}],
        )
        self.assertIs(response["research_only"], True)
        self.assertIs(response["deterministic"], True)
        self.assertIn("NETWORK_PROVIDER_USED", response["limitations"])

    def test_network_imports_are_isolated_to_transport(self):
        allowed = {"ai/providers/http_transport.py"}
        for relative_path in R51_PROVIDER_MODULES:
            imports, _calls = scan_module(relative_path)
            network = imports & NETWORK_MODULES
            if relative_path in allowed:
                continue
            self.assertEqual(network, set(), relative_path)

    def test_no_forbidden_calls_in_provider_layer(self):
        for relative_path in R51_PROVIDER_MODULES:
            _imports, calls = scan_module(relative_path)
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_transport_spec_is_bounded(self):
        transport = FakeTransport(
            payload={"choices": [{"message": {"content": "{}"}}]}
        )
        provider = OpenRouterProvider(
            transport=transport,
            environ=provider_environ(),
            timeout_seconds=7,
            max_response_bytes=4096,
            max_tokens=128,
        )
        provider.complete_with_status(sample_request())
        spec = transport.requests[0]
        self.assertIsInstance(spec, HttpRequestSpec)
        self.assertEqual(spec.method, "POST")
        self.assertEqual(spec.url, "https://openrouter.ai/api/v1/chat/completions")
        self.assertEqual(spec.timeout_seconds, 7.0)
        self.assertEqual(spec.max_response_bytes, 4096)
        body = json.loads(spec.body.decode("utf-8"))
        self.assertEqual(body["temperature"], 0)
        self.assertEqual(body["max_tokens"], 128)
        self.assertEqual(body["model"], "vendor/model")
        headers = dict(spec.headers)
        self.assertIn("Authorization", headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
