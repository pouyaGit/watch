"""tests/test_llm_openrouter_provider.py — Stage R51 OpenRouter tests.

Deterministic, offline tests for the OpenRouter provider adapter using a
fake bounded transport (no real API calls):

- environment/configuration resolution and fail-closed behavior
- successful response mapping into the R45 response contract
- malformed/empty/unexpected provider responses
- authentication, authorization, rate-limit, timeout and network mapping
- transient retry, bounded retries and deterministic attempt counts
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

from ai.knowledge.llm_provider import AdvisoryProvider, AdvisoryProviderError
from ai.providers.http_transport import (
    FAILURE_RESPONSE_TOO_LARGE,
    FAILURE_TIMEOUT,
    HttpTransport,
    HttpResponseSpec,
    TransportFailure,
)
from ai.providers.openrouter_provider import OpenRouterProvider
from ai.providers.provider_errors import ProviderCallError


ROOT = Path(__file__).resolve().parents[1]

SECRET = "not-a-real-openrouter-credential"


def environ(model="vendor/model"):
    data = {"OPENROUTER_API_KEY": SECRET}
    if model:
        data["OPENROUTER_MODEL"] = model
    return data


def request(provider_kind="OPENROUTER"):
    return {
        "rule_version": "r45-3",
        "advisory_id": "adv-0123456789abcdef",
        "advisory_mode": "SUMMARY",
        "provider_kind": provider_kind,
        "source_layer": "R42",
        "instruction": "Summarize.",
        "sections": {
            "research_context": {
                "research_question": "How strong is the evidence?",
                "research_focus": "",
                "context_fact_count": 1,
                "source_layers": [],
                "research_only": True,
            },
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


def advisory_content():
    return {
        "summary": "Bounded advisory summary.",
        "insights": [
            {"insight_code": "ADVISORY_SCOPE", "text": "Advisory only."}
        ],
        "recommendations": [],
    }


def body(payload):
    return json.dumps(payload)


def success_body(content=None):
    return body(
        {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            content if content is not None else advisory_content()
                        )
                    }
                }
            ]
        }
    )


class SequenceTransport(HttpTransport):
    transport_kind = "SEQUENCE"

    def __init__(self, steps):
        self.steps = list(steps)
        self.requests = []

    def send(self, spec):
        self.requests.append(spec)
        step = self.steps.pop(0) if self.steps else self.steps_result()
        if isinstance(step, TransportFailure):
            raise step
        return step

    def steps_result(self):
        return HttpResponseSpec(status_code=200, body_text=success_body())


class TestOpenRouterProvider(unittest.TestCase):
    def test_defaults_and_environment_configuration(self):
        provider = OpenRouterProvider(transport=SequenceTransport([]))
        provider._environ = environ()
        self.assertEqual(provider.provider_kind, "OPENROUTER")
        self.assertEqual(
            provider.base_url, "https://openrouter.ai/api/v1"
        )
        from ai.providers.openrouter_provider import (
            OPENROUTER_API_KEY_ENV,
            OPENROUTER_BASE_URL_ENV,
            OPENROUTER_MODEL_ENV,
        )
        self.assertEqual(provider.api_key_env, OPENROUTER_API_KEY_ENV)
        self.assertEqual(
            OpenRouterProvider.default_model_env, OPENROUTER_MODEL_ENV
        )
        self.assertEqual(
            OpenRouterProvider.default_base_url_env, OPENROUTER_BASE_URL_ENV
        )

    def test_explicit_overrides(self):
        transport = SequenceTransport([HttpResponseSpec(200, success_body())])
        provider = OpenRouterProvider(
            model="custom/model",
            base_url="https://gateway.example.test/v1",
            transport=transport,
            environ=environ(),
        )
        self.assertEqual(provider.model, "custom/model")
        outcome = provider.complete_with_status(request())
        self.assertEqual(outcome["response"]["provider_kind"], "OPENROUTER")
        self.assertEqual(
            transport.requests[0].url,
            "https://gateway.example.test/v1/chat/completions",
        )

    def test_missing_api_key_fails_closed_without_call(self):
        transport = SequenceTransport([HttpResponseSpec(200, success_body())])
        provider = OpenRouterProvider(
            transport=transport, environ={"OPENROUTER_MODEL": "vendor/model"}
        )
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(
            caught.exception.error_code, "CONFIG_MISSING_CREDENTIAL"
        )
        self.assertEqual(transport.requests, [])

    def test_missing_model_fails_closed_without_call(self):
        transport = SequenceTransport([HttpResponseSpec(200, success_body())])
        provider = OpenRouterProvider(
            transport=transport, environ={"OPENROUTER_API_KEY": SECRET}
        )
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(
            caught.exception.error_code, "CONFIG_MISSING_MODEL"
        )
        self.assertEqual(transport.requests, [])

    def test_invalid_configuration_fails_closed(self):
        for bad in (
            {"timeout_seconds": 0},
            {"max_retries": 99},
            {"max_tokens": 0},
            {"base_url": "http://insecure.example.test"},
        ):
            with self.assertRaises(ProviderCallError) as caught:
                OpenRouterProvider(environ=environ(), **bad)
            self.assertEqual(
                caught.exception.error_code, "CONFIG_INVALID_PARAMETER"
            )

    def test_success_response_mapping(self):
        transport = SequenceTransport([HttpResponseSpec(200, success_body())])
        provider = OpenRouterProvider(transport=transport, environ=environ())
        response = provider.complete(request())
        self.assertEqual(
            set(response.keys()),
            {"rule_version", "provider_kind", "advisory_id",
             "advisory_mode", "summary", "insights", "recommendations",
             "source_refs", "limitations", "research_only",
             "deterministic"},
        )
        self.assertEqual(response["rule_version"], "r45-3")
        self.assertEqual(response["advisory_id"], "adv-0123456789abcdef")
        self.assertEqual(response["advisory_mode"], "SUMMARY")
        self.assertEqual(response["summary"], "Bounded advisory summary.")
        self.assertIs(response["research_only"], True)
        self.assertIs(response["deterministic"], True)

    def test_request_construction_is_deterministic(self):
        first = SequenceTransport([HttpResponseSpec(200, success_body())])
        second = SequenceTransport([HttpResponseSpec(200, success_body())])
        OpenRouterProvider(
            transport=first, environ=environ()
        ).complete(request())
        OpenRouterProvider(
            transport=second, environ=environ()
        ).complete(request())
        self.assertEqual(
            first.requests[0].body, second.requests[0].body
        )
        self.assertEqual(
            first.requests[0].url, second.requests[0].url
        )
        body_value = json.loads(first.requests[0].body.decode("utf-8"))
        self.assertEqual(
            sorted(body_value.keys()),
            ["max_tokens", "messages", "model", "temperature"],
        )
        self.assertEqual(body_value["temperature"], 0)

    def test_authorization_header_only_in_transport_spec(self):
        transport = SequenceTransport([HttpResponseSpec(200, success_body())])
        provider = OpenRouterProvider(transport=transport, environ=environ())
        outcome = provider.complete_with_status(request())
        headers = dict(transport.requests[0].headers)
        self.assertEqual(headers["Authorization"], "Bearer " + SECRET)
        serialized = json.dumps(outcome["response"]) + json.dumps(
            outcome["telemetry"]
        )
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn("Authorization", serialized)

    def test_malformed_json_body(self):
        transport = SequenceTransport([HttpResponseSpec(200, "not json")])
        provider = OpenRouterProvider(transport=transport, environ=environ())
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(caught.exception.error_code,
                         "INVALID_PROVIDER_RESPONSE")
        self.assertEqual(len(transport.requests), 1)

    def test_missing_choices_and_empty_content(self):
        for payload in (
            {"choices": []},
            {"choices": [{"message": {}}]},
            {"choices": [{"message": {"content": ""}}]},
        ):
            transport = SequenceTransport(
                [HttpResponseSpec(200, body(payload))]
            )
            provider = OpenRouterProvider(
                transport=transport, environ=environ()
            )
            with self.assertRaises(ProviderCallError) as caught:
                provider.complete(request())
            self.assertIn(
                caught.exception.error_code,
                ("INVALID_PROVIDER_RESPONSE", "EMPTY_PROVIDER_RESPONSE"),
            )

    def test_non_string_content(self):
        payload = {"choices": [{"message": {"content": ["part"]}}]}
        transport = SequenceTransport([HttpResponseSpec(200, body(payload))])
        provider = OpenRouterProvider(transport=transport, environ=environ())
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(
            caught.exception.error_code, "INVALID_PROVIDER_RESPONSE"
        )

    def test_authentication_failure_not_retried(self):
        transport = SequenceTransport(
            [HttpResponseSpec(401, body({"error": "invalid"}))]
        )
        provider = OpenRouterProvider(transport=transport, environ=environ())
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(
            caught.exception.error_category, "AUTHENTICATION_ERROR"
        )
        self.assertEqual(caught.exception.error_code,
                         "AUTH_INVALID_CREDENTIALS")
        self.assertIs(caught.exception.retryable, False)
        self.assertEqual(len(transport.requests), 1)

    def test_authorization_failure_not_retried(self):
        transport = SequenceTransport(
            [HttpResponseSpec(403, body({"error": "forbidden"}))]
        )
        provider = OpenRouterProvider(transport=transport, environ=environ())
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(
            caught.exception.error_category, "AUTHORIZATION_ERROR"
        )
        self.assertEqual(len(transport.requests), 1)

    def test_rate_limit_retry_then_success(self):
        transport = SequenceTransport(
            [
                HttpResponseSpec(429, body({"error": "rate limited"})),
                HttpResponseSpec(200, success_body()),
            ]
        )
        provider = OpenRouterProvider(
            transport=transport, environ=environ(), max_retries=2
        )
        outcome = provider.complete_with_status(request())
        self.assertIsNone(outcome["error"])
        self.assertEqual(outcome["telemetry"]["attempt_count"], 2)
        self.assertEqual(outcome["telemetry"]["retry_count"], 1)

    def test_rate_limit_exhaustion_is_bounded(self):
        transport = SequenceTransport(
            [HttpResponseSpec(429, body({"error": "rate limited"}))]
            * 5
        )
        provider = OpenRouterProvider(
            transport=transport, environ=environ(), max_retries=2
        )
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(
            caught.exception.error_category, "RATE_LIMIT_ERROR"
        )
        self.assertEqual(caught.exception.attempts, 3)
        self.assertEqual(len(transport.requests), 3)

    def test_transient_server_error_retry(self):
        transport = SequenceTransport(
            [
                HttpResponseSpec(503, body({"error": "unavailable"})),
                HttpResponseSpec(200, success_body()),
            ]
        )
        provider = OpenRouterProvider(
            transport=transport, environ=environ(), max_retries=1
        )
        outcome = provider.complete_with_status(request())
        self.assertIsNone(outcome["error"])
        self.assertEqual(outcome["telemetry"]["attempt_count"], 2)

    def test_non_retryable_client_error(self):
        transport = SequenceTransport(
            [HttpResponseSpec(400, body({"error": "bad request"}))]
        )
        provider = OpenRouterProvider(transport=transport, environ=environ())
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(caught.exception.error_category, "PROVIDER_ERROR")
        self.assertIs(caught.exception.retryable, False)
        self.assertEqual(len(transport.requests), 1)

    def test_timeout_retry_and_exhaustion(self):
        transport = SequenceTransport(
            [
                TransportFailure(FAILURE_TIMEOUT, "request timed out"),
                TransportFailure(FAILURE_TIMEOUT, "request timed out"),
            ]
        )
        provider = OpenRouterProvider(
            transport=transport, environ=environ(), max_retries=1
        )
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(caught.exception.error_category, "TIMEOUT_ERROR")
        self.assertEqual(caught.exception.attempts, 2)
        self.assertEqual(len(transport.requests), 2)

    def test_network_failure_retry_then_success(self):
        transport = SequenceTransport(
            [
                TransportFailure("NETWORK", "connection failed"),
                HttpResponseSpec(200, success_body()),
            ]
        )
        provider = OpenRouterProvider(
            transport=transport, environ=environ(), max_retries=1
        )
        outcome = provider.complete_with_status(request())
        self.assertIsNone(outcome["error"])
        self.assertEqual(outcome["telemetry"]["attempt_count"], 2)

    def test_response_too_large_is_not_retried(self):
        transport = SequenceTransport(
            [
                TransportFailure(
                    FAILURE_RESPONSE_TOO_LARGE, "too large"
                )
            ]
        )
        provider = OpenRouterProvider(
            transport=transport, environ=environ(), max_retries=2
        )
        with self.assertRaises(ProviderCallError) as caught:
            provider.complete(request())
        self.assertEqual(
            caught.exception.error_category, "INVALID_RESPONSE"
        )
        self.assertEqual(len(transport.requests), 1)

    def test_parse_failure_is_not_retried(self):
        bad_content = body(
            {"choices": [{"message": {"content": "not json"}}]}
        )
        transport = SequenceTransport(
            [HttpResponseSpec(200, bad_content)] * 3
        )
        provider = OpenRouterProvider(
            transport=transport, environ=environ(), max_retries=2
        )
        with self.assertRaises(ProviderCallError):
            provider.complete(request())
        self.assertEqual(len(transport.requests), 1)

    def test_safe_error_never_contains_credentials(self):
        transport = SequenceTransport(
            [HttpResponseSpec(401, body({"error": SECRET}))]
        )
        provider = OpenRouterProvider(transport=transport, environ=environ())
        try:
            provider.complete(request())
        except ProviderCallError as exc:
            serialized = json.dumps(exc.as_error_plan())
            self.assertNotIn(SECRET, serialized)
        else:  # pragma: no cover
            self.fail("expected ProviderCallError")

    def test_each_attempt_carries_explicit_timeout(self):
        transport = SequenceTransport(
            [
                TransportFailure(FAILURE_TIMEOUT, "timeout"),
                HttpResponseSpec(200, success_body()),
            ]
        )
        provider = OpenRouterProvider(
            transport=transport,
            environ=environ(),
            timeout_seconds=9,
            max_retries=1,
        )
        provider.complete(request())
        for spec in transport.requests:
            self.assertEqual(spec.timeout_seconds, 9.0)

    def test_provider_is_an_advisory_provider(self):
        provider = OpenRouterProvider(
            transport=SequenceTransport([]), environ=environ()
        )
        self.assertIsInstance(provider, AdvisoryProvider)
        outcome = provider.complete_with_status(request())
        self.assertIn("telemetry", outcome)
        self.assertEqual(outcome["telemetry"]["provider_kind"], "OPENROUTER")
        self.assertIs(outcome["telemetry"]["external_provider"], True)
        self.assertIs(outcome["telemetry"]["credentials_used"], True)
        self.assertIs(outcome["telemetry"]["content_deterministic"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
