"""tests/test_llm_openai_provider.py — Stage R51 OpenAI tests.

Deterministic, offline tests for the OpenAI provider adapter using a fake
bounded transport (no real API calls):

- OpenAI-specific environment/base-URL/model configuration
- fail-closed missing credentials and no cross-provider fallback
- the shared R51 response contract, error mapping and retry model
- secret hygiene in specs, errors and telemetry

No real API calls, no network, no LLM, no subprocess, no sockets, no
browser, no SQL, no database, no payloads, no Mongo writes, no
persistence, no execution of any kind.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from ai.knowledge.llm_provider import AdvisoryProvider
from ai.providers.http_transport import (
    HttpTransport,
    HttpResponseSpec,
    TransportFailure,
)
from ai.providers.openai_provider import (
    DEFAULT_OPENAI_BASE_URL,
    OPENAI_API_KEY_ENV,
    OPENAI_BASE_URL_ENV,
    OPENAI_MODEL_ENV,
    OpenAIProvider,
)
from ai.providers.openrouter_provider import OpenRouterProvider
from ai.providers.provider_errors import ProviderCallError


ROOT = Path(__file__).resolve().parents[1]

SECRET = "not-a-real-openai-credential"


def environ(model="vendor/model"):
    data = {"OPENAI_API_KEY": SECRET}
    if model:
        data["OPENAI_MODEL"] = model
    return data


def request():
    return {
        "rule_version": "r45-3",
        "advisory_id": "adv-0123456789abcdef",
        "advisory_mode": "EXPLANATION",
        "provider_kind": "OPENAI",
        "source_layer": "R42",
        "instruction": "Explain.",
        "sections": {
            "research_context": {},
            "evaluation_summary": {},
            "collaboration_summary": {},
            "learning_signals": [],
            "governance_state": "UNKNOWN",
            "safety_state": "PASS",
        },
        "source_refs": [],
        "limitations": ["NO_EXECUTION_PERFORMED"],
        "research_only": True,
        "deterministic": True,
    }


def success_body():
    content = {
        "summary": "Bounded advisory summary.",
        "insights": [],
        "recommendations": [
            {
                "recommendation_code": "REQUIRE_ADDITIONAL_EVIDENCE",
                "text": "Require more structured evidence.",
            }
        ],
    }
    return json.dumps(
        {"choices": [{"message": {"content": json.dumps(content)}}]}
    )


class SequenceTransport(HttpTransport):
    transport_kind = "SEQUENCE"

    def __init__(self, steps):
        self.steps = list(steps)
        self.requests = []

    def send(self, spec):
        self.requests.append(spec)
        if self.steps:
            step = self.steps.pop(0)
        else:
            step = HttpResponseSpec(status_code=200, body_text=success_body())
        if isinstance(step, TransportFailure):
            raise step
        return step


class TestOpenAIProvider(unittest.TestCase):
    def test_default_configuration(self):
        self.assertEqual(
            DEFAULT_OPENAI_BASE_URL, "https://api.openai.com/v1"
        )
        self.assertEqual(OpenAIProvider.default_api_key_env, OPENAI_API_KEY_ENV)
        self.assertEqual(OpenAIProvider.default_model_env, OPENAI_MODEL_ENV)
        self.assertEqual(
            OpenAIProvider.default_base_url_env, OPENAI_BASE_URL_ENV
        )
        provider = OpenAIProvider(environ=environ())
        self.assertEqual(provider.provider_kind, "OPENAI")
        self.assertEqual(provider.model, "vendor/model")

    def test_does_not_use_other_provider_credentials(self):
        transport = SequenceTransport([])
        provider = OpenAIProvider(
            transport=transport,
            environ={
                "OPENROUTER_API_KEY": SECRET,
                "OPENROUTER_MODEL": "vendor/model",
            },
        )
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(
            caught.exception.error_code, "CONFIG_MISSING_CREDENTIAL"
        )
        self.assertEqual(transport.requests, [])

    def test_success_mapping(self):
        transport = SequenceTransport(
            [HttpResponseSpec(200, success_body())]
        )
        provider = OpenAIProvider(transport=transport, environ=environ())
        response = provider.complete(request())
        self.assertEqual(response["provider_kind"], "OPENAI")
        self.assertEqual(response["advisory_mode"], "EXPLANATION")
        self.assertEqual(response["summary"], "Bounded advisory summary.")
        self.assertEqual(
            transport.requests[0].url,
            "https://api.openai.com/v1/chat/completions",
        )

    def test_same_contract_as_openrouter(self):
        openai_transport = SequenceTransport(
            [HttpResponseSpec(200, success_body())]
        )
        router_transport = SequenceTransport(
            [HttpResponseSpec(200, success_body())]
        )
        openai = OpenAIProvider(
            transport=openai_transport, environ=environ()
        ).complete(request())
        router_request = request()
        router_request["provider_kind"] = "OPENROUTER"
        router = OpenRouterProvider(
            transport=router_transport,
            environ={
                "OPENROUTER_API_KEY": SECRET,
                "OPENROUTER_MODEL": "vendor/model",
            },
        ).complete(router_request)
        self.assertEqual(set(openai.keys()), set(router.keys()))
        self.assertEqual(openai["limitations"], router["limitations"])

    def test_shared_error_mapping(self):
        for status, category in (
            (401, "AUTHENTICATION_ERROR"),
            (403, "AUTHORIZATION_ERROR"),
            (429, "RATE_LIMIT_ERROR"),
            (400, "PROVIDER_ERROR"),
        ):
            transport = SequenceTransport(
                [HttpResponseSpec(status, json.dumps({"error": "x"}))]
            )
            provider = OpenAIProvider(
                transport=transport, environ=environ(), max_retries=0
            )
            with self.assertRaises(ProviderCallError) as caught:
                provider.complete(request())
            self.assertEqual(
                caught.exception.error_category, category, status
            )

    def test_retry_is_bounded(self):
        transport = SequenceTransport(
            [HttpResponseSpec(429, json.dumps({"error": "x"}))] * 6
        )
        provider = OpenAIProvider(
            transport=transport, environ=environ(), max_retries=1
        )
        with self.assertRaises(ProviderCallError):
            provider.complete(request())
        self.assertEqual(len(transport.requests), 2)

    def test_timeout_mapping(self):
        transport = SequenceTransport(
            [TransportFailure("TIMEOUT", "timed out")]
        )
        provider = OpenAIProvider(
            transport=transport, environ=environ(), max_retries=0
        )
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(caught.exception.error_category, "TIMEOUT_ERROR")

    def test_no_fallback_to_other_provider(self):
        transport = SequenceTransport(
            [HttpResponseSpec(500, json.dumps({"error": "x"}))]
        )
        provider = OpenAIProvider(
            transport=transport, environ=environ(), max_retries=0
        )
        with self.assertRaises(ProviderCallError):
            provider.complete(request())
        urls = {spec.url for spec in transport.requests}
        self.assertEqual(urls, {
            "https://api.openai.com/v1/chat/completions"
        })

    def test_secret_never_in_error_or_telemetry(self):
        transport = SequenceTransport(
            [HttpResponseSpec(401, json.dumps({"error": SECRET}))]
        )
        provider = OpenAIProvider(transport=transport, environ=environ())
        outcome = provider.complete_with_status(request())
        serialized = json.dumps(outcome["error"]) + json.dumps(
            outcome["telemetry"]
        )
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn("Authorization", serialized)
        headers = dict(transport.requests[0].headers)
        self.assertEqual(headers["Authorization"], "Bearer " + SECRET)

    def test_provider_describe_is_safe(self):
        provider = OpenAIProvider(
            transport=SequenceTransport([]), environ=environ()
        )
        described = json.dumps(provider.describe())
        self.assertNotIn(SECRET, described)
        self.assertNotIn("Authorization", described)
        self.assertIn("OPENAI", described)

    def test_is_advisory_provider(self):
        provider = OpenAIProvider(
            transport=SequenceTransport([]), environ=environ()
        )
        self.assertIsInstance(provider, AdvisoryProvider)

    def test_deterministic_request_body(self):
        first = SequenceTransport(
            [HttpResponseSpec(200, success_body())]
        )
        second = SequenceTransport(
            [HttpResponseSpec(200, success_body())]
        )
        OpenAIProvider(transport=first, environ=environ()).complete(request())
        OpenAIProvider(transport=second, environ=environ()).complete(request())
        self.assertEqual(
            first.requests[0].body, second.requests[0].body
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
