"""tests/test_llm_provider.py — Stage R45.3 tests.

Deterministic, offline tests for the advisory provider abstraction:

- closed provider kind vocabulary (mock only in version 1)
- deterministic mock provider responses per advisory mode
- response contract shape and safety validation
- unsupported and future provider kinds rejected
- no credentials, no network capability, no SDK imports
- R45 AST safety scan

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

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.llm_advisory_input import build_llm_advisory_input
from ai.knowledge.llm_advisory_request_builder import (
    build_llm_advisory_request,
)
from ai.knowledge.llm_provider import (
    AdvisoryProvider,
    MockLLMProvider,
    UnsupportedProviderError,
    get_advisory_provider,
    provider_descriptor,
    MOCK_MODE_SUMMARIES,
)
from ai.knowledge.llm_advisory_validator import (
    detect_forbidden_claims,
    validate_advisory_response,
)
from ai.schemas.llm_advisory_policy import ADVISORY_MODES
from ai.schemas import llm_provider as schema


ROOT = Path(__file__).resolve().parents[1]

R45_MODULES = (
    "ai/schemas/llm_advisory_input.py",
    "ai/schemas/llm_advisory_policy.py",
    "ai/schemas/llm_provider.py",
    "ai/schemas/llm_advisory_result.py",
    "ai/knowledge/llm_advisory_input.py",
    "ai/knowledge/llm_advisory_policy.py",
    "ai/knowledge/llm_provider.py",
    "ai/knowledge/llm_advisory_request_builder.py",
    "ai/knowledge/llm_advisory_validator.py",
    "ai/knowledge/llm_advisory_export.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "selenium", "playwright", "pyppeteer", "sqlite3",
    "sqlalchemy", "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap",
    "nuclei", "openai", "ollama", "litellm", "anthropic", "openrouter",
    "curl", "pycurl",
}

FORBIDDEN_CALLS = {"__import__", "eval", "exec", "compile", "open"}

FORBIDDEN_CALL_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "socket.",
    "urllib.",
    "requests.",
    "httpx.",
    "aiohttp.",
    "selenium.",
    "playwright.",
    "sqlite3.",
    "sqlalchemy.",
    "sqlmap.",
    "nuclei.",
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


def sample_request(mode=None):
    advisory_input = build_llm_advisory_input(
        evaluation_result=evaluate_agent_result(r38_result()),
        research_context={"research_question": "How strong is it?"},
    )
    return build_llm_advisory_request(
        advisory_input, requested_mode=mode
    )


def r38_result(**over):
    base = {
        "rule_version": "r38-5",
        "agent_id": "sa-" + "a" * 16,
        "agent_category": "SSRF",
        "status": "COMPLETED",
        "confidence": "HIGH",
        "findings_summary": "NO_FINDINGS",
        "evidence_summary": "EVIDENCE_NONE",
        "limitations": ["NO_EXECUTION_PERFORMED"],
        "research_only": True,
    }
    base.update(over)
    return base


class TestLLMProvider(unittest.TestCase):
    def test_provider_kinds_are_closed(self):
        # R51 additively extends the supported vocabulary with the real
        # remote provider kinds; ollama/local remain unsupported future
        # kinds and the two sets stay disjoint.
        self.assertEqual(
            schema.SUPPORTED_PROVIDER_KINDS,
            ("MOCK", "OPENROUTER", "OPENAI"),
        )
        self.assertEqual(
            schema.FUTURE_PROVIDER_KINDS,
            ("OLLAMA", "LOCAL"),
        )
        self.assertEqual(
            set(schema.SUPPORTED_PROVIDER_KINDS)
            & set(schema.FUTURE_PROVIDER_KINDS),
            set(),
        )

    def test_mock_provider_completes_without_network(self):
        provider = MockLLMProvider()
        self.assertIsInstance(provider, AdvisoryProvider)
        self.assertEqual(provider.provider_kind, "MOCK")
        response = provider.complete(sample_request())
        self.assertEqual(response["provider_kind"], "MOCK")
        self.assertEqual(response["rule_version"], "r45-3")

    def test_mock_response_is_deterministic(self):
        provider = MockLLMProvider()
        request = sample_request()
        first = json.dumps(provider.complete(request), sort_keys=True)
        second = json.dumps(provider.complete(request), sort_keys=True)
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())

    def test_mock_response_contract(self):
        response = MockLLMProvider().complete(sample_request())
        self.assertEqual(
            set(response.keys()),
            {"rule_version", "provider_kind", "advisory_id",
             "advisory_mode", "summary", "insights", "recommendations",
             "source_refs", "limitations", "research_only",
             "deterministic"},
        )
        self.assertIs(response["research_only"], True)
        self.assertIs(response["deterministic"], True)
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_CREDENTIALS_USED",
            "DETERMINISTIC_MOCK_RESPONSE",
            "ADVISORY_ONLY",
        ):
            self.assertIn(limitation, response["limitations"])

    def test_mode_specific_summaries(self):
        provider = MockLLMProvider()
        for mode in ADVISORY_MODES:
            response = provider.complete(sample_request(mode))
            self.assertEqual(response["advisory_mode"], mode)
            self.assertEqual(
                response["summary"], MOCK_MODE_SUMMARIES[mode]
            )

    def test_mock_responses_pass_safety_validation(self):
        provider = MockLLMProvider()
        request = sample_request()
        validation = validate_advisory_response(
            provider.complete(request), request
        )
        self.assertEqual(validation["validation_state"], "PASS")
        self.assertEqual(validation["violations"], [])

    def test_mock_output_contains_no_forbidden_claims(self):
        provider = MockLLMProvider()
        response = provider.complete(sample_request())
        texts = [response["summary"]]
        texts += [item["text"] for item in response["insights"]]
        texts += [item["text"] for item in response["recommendations"]]
        for text in texts:
            self.assertEqual(detect_forbidden_claims(text), [])

    def test_insights_and_recommendations_preserve_source_refs(self):
        provider = MockLLMProvider()
        request = sample_request()
        response = provider.complete(request)
        evaluation_insights = [
            item for item in response["insights"]
            if item["insight_code"] == "EVALUATION_STATE"
        ]
        self.assertEqual(len(evaluation_insights), 1)
        self.assertEqual(
            evaluation_insights[0]["source_refs"],
            [{"layer": "R42", "reference": "r42-5"}],
        )
        self.assertTrue(
            any(
                item["recommendation_code"]
                == "REQUIRE_ADDITIONAL_EVIDENCE"
                for item in response["recommendations"]
            )
        )
        for item in response["recommendations"]:
            for ref in item["source_refs"]:
                self.assertIn(ref["layer"], ("R42", "R43", "R44"))

    def test_get_advisory_provider_mock(self):
        self.assertIsInstance(
            get_advisory_provider("MOCK"), MockLLMProvider
        )
        self.assertIsInstance(
            get_advisory_provider("mock"), MockLLMProvider
        )
        self.assertIsInstance(
            get_advisory_provider(), MockLLMProvider
        )

    def test_future_provider_kinds_rejected(self):
        for kind in schema.FUTURE_PROVIDER_KINDS:
            with self.assertRaises(UnsupportedProviderError) as caught:
                get_advisory_provider(kind)
            diagnostic = caught.exception.diagnostic
            self.assertEqual(diagnostic["provider_kind"], kind)
            self.assertIs(diagnostic["network_access"], False)
            self.assertIs(diagnostic["credentials_used"], False)

    def test_unknown_provider_kind_rejected(self):
        with self.assertRaises(UnsupportedProviderError):
            get_advisory_provider("NOPE")

    def test_provider_descriptor(self):
        descriptor = provider_descriptor()
        self.assertEqual(descriptor["provider_kind"], "MOCK")
        self.assertIs(descriptor["supported"], True)
        self.assertIs(descriptor["network_access"], False)
        self.assertIs(descriptor["credentials_used"], False)
        self.assertIs(descriptor["deterministic"], True)
        self.assertIs(descriptor["research_only"], True)

    def test_no_credentials_or_sdks_in_provider_sources(self):
        for relative_path in (
            "ai/knowledge/llm_provider.py",
            "ai/schemas/llm_provider.py",
        ):
            source = (ROOT / relative_path).read_text(encoding="utf-8")
            lowered = source.lower()
            for token in (
                "api_key",
                "apikey",
                "authorization",
                "bearer ",
                "secret",
                "password",
                "sk-",
            ):
                self.assertNotIn(token, lowered, relative_path)

    def test_schema_request_rejects_unsupported_kind(self):
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            schema.LLMProviderRequestPlan(provider_kind="OLLAMA")
        with self.assertRaises(ValidationError):
            schema.LLMProviderResponsePlan(provider_kind="OLLAMA")

    def test_schema_response_forces_flags(self):
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            schema.LLMProviderResponsePlan(research_only=False)
        with self.assertRaises(ValidationError):
            schema.LLMProviderResponsePlan(deterministic=False)
        with self.assertRaises(ValidationError):
            schema.LLMProviderResponsePlan(advisory_mode="EXPLOITATION")
        with self.assertRaises(ValidationError):
            schema.LLMProviderResponsePlan(unexpected="x")

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R45_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("llm_advisory", backend_source)
        self.assertNotIn("llm_provider", backend_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
