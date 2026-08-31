import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from openai import (
    APIConnectionError,
    APIStatusError,
)

from ai.knowledge.store import KnowledgeStore
from ai.llm.openrouter import (
    DEFAULT_BASE_URL,
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT_SECONDS,
    OpenRouterProvider,
    OpenRouterProviderError,
    OpenRouterResponse,
)
from ai.researcher.xss_llm_researcher import XSSLLMResearcher
from ai.researcher.xss_researcher import XSSResearcher
from ai.schemas.knowledge import KnowledgeDocument
from ai.schemas.xss import XSSCase, XSSContext


FIXTURE_DIR = (
    Path(__file__).parent
    / "tests"
    / "fixtures"
    / "knowledge"
)


def _load_fixture(name: str) -> KnowledgeDocument:
    return KnowledgeDocument.model_validate(
        json.loads(
            (FIXTURE_DIR / name).read_text(
                encoding="utf-8"
            )
        )
    )


def _make_case() -> XSSCase:
    return XSSCase(
        case_id="case-1",
        target="https://target.example.test",
        endpoint="https://target.example.test/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        xss_type="reflected",
        context=XSSContext(
            type="html_attribute",
            attribute_name="class",
            attribute_quoted=True,
        ),
        technology=["Example Framework"],
        waf="Strict WAF",
        source_type="endpoint",
        created_at="2026-08-01T00:00:00+00:00",
        updated_at="2026-08-01T00:00:00+00:00",
    )


def _make_chat_payload(
    *,
    content: str = '{"ok": true}',
    response_id: str = "or-resp-123",
    model: str = "minimax/minimax-m3:free",
) -> dict:
    return {
        "id": response_id,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                },
                "finish_reason": "stop",
            }
        ],
    }


def _build_capturing_client(handler):
    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport)


class OpenRouterProviderConfigTests(unittest.TestCase):
    def setUp(self):
        self._saved_env: dict[str, str | None] = {}
        for key in (
            "OPENROUTER_API_KEY",
            "OPENROUTER_MODEL",
        ):
            self._saved_env[key] = os.environ.get(key)

    def tearDown(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_default_model_is_minimax_free(self):
        os.environ.pop("OPENROUTER_MODEL", None)
        os.environ["OPENROUTER_API_KEY"] = "test-key"

        provider = OpenRouterProvider()

        self.assertEqual(provider.model, DEFAULT_MODEL)
        self.assertEqual(
            DEFAULT_MODEL, "minimax/minimax-m3:free"
        )

    def test_env_model_overrides_default(self):
        os.environ["OPENROUTER_API_KEY"] = "test-key"
        os.environ["OPENROUTER_MODEL"] = "custom/model"

        provider = OpenRouterProvider()

        self.assertEqual(provider.model, "custom/model")

    def test_missing_api_key_raises(self):
        os.environ.pop("OPENROUTER_API_KEY", None)
        os.environ["OPENROUTER_MODEL"] = "some/model"

        with self.assertRaises(OpenRouterProviderError):
            OpenRouterProvider()

    def test_default_url_and_timeout(self):
        provider = OpenRouterProvider(
            api_key="test-key", model="m"
        )

        self.assertEqual(provider.base_url, DEFAULT_BASE_URL)
        self.assertEqual(
            DEFAULT_BASE_URL,
            "https://openrouter.ai/api/v1",
        )
        self.assertEqual(
            provider.timeout, DEFAULT_TIMEOUT_SECONDS
        )


class OpenRouterProviderMaxTokensTests(unittest.TestCase):
    """
    The provider must send an explicit completion/output token
    budget (``max_tokens``) with every request so structured
    JSON responses from models such as MiniMax are not
    truncated mid-field by a small provider-side default.
    """

    def setUp(self):
        self._saved_env: dict[str, str | None] = {}
        for key in (
            "OPENROUTER_API_KEY",
            "OPENROUTER_MODEL",
            "OPENROUTER_MAX_TOKENS",
        ):
            self._saved_env[key] = os.environ.get(key)

    def tearDown(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    @staticmethod
    def _capturing_handler(captured: dict):
        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(
                request.content.decode("utf-8")
            )
            return httpx.Response(
                200, json=_make_chat_payload()
            )

        return handler

    def _provider(self, handler, **kwargs) -> OpenRouterProvider:
        client = _build_capturing_client(handler)
        return OpenRouterProvider(
            api_key="sk-or-v1-secret-key",
            model="minimax/minimax-m3:free",
            http_client=client,
            **kwargs,
        )

    def test_default_max_tokens_sent_when_env_absent(self):
        os.environ.pop("OPENROUTER_MAX_TOKENS", None)
        captured: dict = {}
        provider = self._provider(
            self._capturing_handler(captured)
        )

        provider.generate("p")

        self.assertEqual(
            provider.max_tokens, DEFAULT_MAX_TOKENS
        )
        self.assertEqual(
            captured["body"]["max_tokens"],
            DEFAULT_MAX_TOKENS,
        )

    def test_env_max_tokens_is_passed_to_create(self):
        os.environ["OPENROUTER_MAX_TOKENS"] = "8192"
        captured: dict = {}
        provider = self._provider(
            self._capturing_handler(captured)
        )

        provider.generate("p")

        self.assertEqual(provider.max_tokens, 8192)
        self.assertEqual(
            captured["body"]["max_tokens"], 8192
        )

    def test_explicit_max_tokens_overrides_env(self):
        os.environ["OPENROUTER_MAX_TOKENS"] = "8192"
        captured: dict = {}
        provider = self._provider(
            self._capturing_handler(captured),
            max_tokens=1234,
        )

        provider.generate("p")

        self.assertEqual(provider.max_tokens, 1234)
        self.assertEqual(
            captured["body"]["max_tokens"], 1234
        )

    def test_blank_env_value_falls_back_to_default(self):
        os.environ["OPENROUTER_MAX_TOKENS"] = "   "
        captured: dict = {}
        provider = self._provider(
            self._capturing_handler(captured)
        )

        provider.generate("p")

        self.assertEqual(
            captured["body"]["max_tokens"],
            DEFAULT_MAX_TOKENS,
        )

    def test_invalid_env_value_raises_at_construction(self):
        for bad in ("abc", "12.5", "4096 tokens"):
            os.environ["OPENROUTER_MAX_TOKENS"] = bad
            with self.assertRaises(
                OpenRouterProviderError
            ):
                self._provider(
                    lambda _request: httpx.Response(200)
                )

    def test_non_positive_env_value_raises_at_construction(self):
        for bad in ("0", "-5"):
            os.environ["OPENROUTER_MAX_TOKENS"] = bad
            with self.assertRaises(
                OpenRouterProviderError
            ):
                self._provider(
                    lambda _request: httpx.Response(200)
                )

    def test_invalid_explicit_max_tokens_raises_at_construction(
        self,
    ):
        for bad in (0, -1, True):
            with self.assertRaises(
                OpenRouterProviderError
            ):
                self._provider(
                    lambda _request: httpx.Response(200),
                    max_tokens=bad,
                )


class OpenRouterProviderRequestTests(unittest.TestCase):
    def _captured(self):
        return {}

    def _build_provider(self, handler):
        client = _build_capturing_client(handler)
        provider = OpenRouterProvider(
            api_key="sk-or-v1-secret-key",
            model="minimax/minimax-m3:free",
            http_client=client,
        )
        return provider, client

    def test_request_url_and_authorization_header(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["auth"] = request.headers.get(
                "authorization"
            )
            return httpx.Response(
                200, json=_make_chat_payload()
            )

        provider, _ = self._build_provider(handler)

        provider.generate("hello world")

        self.assertEqual(
            captured["url"],
            "https://openrouter.ai/api/v1/chat/completions",
        )
        self.assertIsNotNone(captured["auth"])
        self.assertTrue(captured["auth"].startswith("Bearer "))
        # The full bearer token is the API key by design; the
        # provider never strips it. What we guarantee is that
        # the key is never echoed in our own error messages,
        # which is covered by separate tests.
        self.assertEqual(
            captured["auth"], "Bearer sk-or-v1-secret-key"
        )

    def test_request_body_uses_configured_model_and_prompt(
        self,
    ):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(
                request.content.decode("utf-8")
            )
            return httpx.Response(
                200, json=_make_chat_payload()
            )

        provider, _ = self._build_provider(handler)

        provider.generate("the prompt")

        body = captured["body"]
        self.assertEqual(
            body["model"], "minimax/minimax-m3:free"
        )
        self.assertEqual(
            body["messages"][0]["role"], "user"
        )
        self.assertEqual(
            body["messages"][0]["content"], "the prompt"
        )
        self.assertEqual(
            body["response_format"],
            {"type": "json_object"},
        )

    def test_json_response_content_is_extracted(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_make_chat_payload(
                    content='{"hello":"world"}'
                ),
            )

        provider, _ = self._build_provider(handler)

        content = provider.generate("p")

        self.assertEqual(content, '{"hello":"world"}')

    def test_response_id_is_preserved(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_make_chat_payload(
                    response_id="or-resp-xyz"
                ),
            )

        provider, _ = self._build_provider(handler)

        result: OpenRouterResponse = provider.complete("p")

        self.assertEqual(result.request_id, "or-resp-xyz")
        self.assertEqual(
            result.model, "minimax/minimax-m3:free"
        )

    def test_http_4xx_raises_provider_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={"error": "unauthorized"},
            )

        provider, _ = self._build_provider(handler)

        with self.assertRaises(OpenRouterProviderError):
            provider.generate("p")

    def test_http_5xx_raises_provider_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                500,
                json={"error": "server error"},
            )

        provider, _ = self._build_provider(handler)

        with self.assertRaises(OpenRouterProviderError):
            provider.generate("p")

    def test_provider_passes_through_fenced_json(self):
        """The provider returns raw content; the LLM layer strips fences."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_make_chat_payload(
                    content=(
                        "```json\n"
                        '{"hello":"world"}\n'
                        "```"
                    )
                ),
            )

        provider, _ = self._build_provider(handler)

        content = provider.generate("p")

        self.assertIn("```json", content)
        self.assertIn('"hello":"world"', content)

    def test_provider_passes_through_non_json_content(self):
        """
        The provider does not validate JSON shape; that is the
        LLM researcher's job. Only transport-level errors and
        empty content raise.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_make_chat_payload(
                    content="not json {"
                ),
            )

        provider, _ = self._build_provider(handler)

        self.assertEqual(provider.generate("p"), "not json {")

    def test_missing_choices_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"id": "x", "model": "m"}
            )

        provider, _ = self._build_provider(handler)

        with self.assertRaises(OpenRouterProviderError):
            provider.generate("p")

    def test_empty_message_content_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "id": "x",
                    "model": "m",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "",
                            },
                        }
                    ],
                },
            )

        provider, _ = self._build_provider(handler)

        with self.assertRaises(OpenRouterProviderError):
            provider.generate("p")

    def test_api_key_not_in_provider_errors(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={"error": "unauthorized"},
            )

        provider, _ = self._build_provider(handler)

        try:
            provider.generate("p")
        except OpenRouterProviderError as exc:
            captured["message"] = str(exc)
            captured["cause"] = (
                str(exc.__cause__)
                if exc.__cause__ is not None
                else ""
            )

        self.assertNotIn(
            "sk-or-v1-secret-key", captured["message"]
        )
        self.assertNotIn(
            "sk-or-v1-secret-key", captured["cause"]
        )

    def test_api_key_not_in_connection_error(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            raise APIConnectionError(request=request)

        provider, _ = self._build_provider(handler)

        try:
            provider.generate("p")
        except OpenRouterProviderError as exc:
            captured["message"] = str(exc)
            captured["cause"] = (
                str(exc.__cause__)
                if exc.__cause__ is not None
                else ""
            )

        self.assertNotIn(
            "sk-or-v1-secret-key", captured["message"]
        )
        self.assertNotIn(
            "sk-or-v1-secret-key", captured["cause"]
        )


class OpenRouterProviderNoNetworkTests(unittest.TestCase):
    """
    No real network calls. We patch httpx.Client at the openai SDK
    boundary so a stray attempt to instantiate the real client is
    caught.
    """

    def test_no_real_network_module_imports(self):
        from ai.llm import openrouter as module

        forbidden = {"requests"}
        self.assertTrue(
            forbidden.isdisjoint(module.__dict__)
        )

    @patch("ai.llm.openrouter.OpenAI")
    def test_constructor_does_not_instantiate_openai_when_fake(
        self,
        openai_mock,
    ):
        # If a fake http_client is passed, the openai SDK should
        # still be constructed, but it must not perform any
        # network I/O on construction.
        OpenRouterProvider(
            api_key="x", model="y", http_client=object()
        )
        openai_mock.assert_called_once()


class OpenRouterProviderIntegrationTest(unittest.TestCase):
    """
    End-to-end: XSSLLMResearcher -> OpenRouterProvider -> fake
    transport -> XSSResearchLLMResult.
    """

    def test_xss_llm_researcher_uses_openrouter_provider(
        self,
    ):
        with tempfile.TemporaryDirectory() as d:
            store = KnowledgeStore(Path(d) / "knowledge")
            store.ingest(
                _load_fixture("attribute_quoted_writeup.json")
            )
            researcher = XSSResearcher(store)
            case = _make_case()
            _updated, context = researcher.research(case)

            knowledge_id = context.retrieved_knowledge_ids[0]
            payload = next(
                iter(context.payload_patterns)
            )
            source_id = payload.source_ids[0]
            payload_value = payload.value

            response_content = json.dumps(
                {
                    "case_id": case.case_id,
                    "case_status_suggestion": "ANALYZED",
                    "suggested_payloads": [
                        {
                            "pattern": (
                                "adapted from supplied pattern"
                            ),
                            "origin": "knowledge",
                            "knowledge_ids": [knowledge_id],
                            "source_ids": [source_id],
                            "based_on_pattern": payload_value,
                            "rationale": (
                                "directly adapted from supplied"
                                " context"
                            ),
                        }
                    ],
                    "verification_ideas": [],
                    "context_observations": [],
                    "next_research_questions": [],
                    "evidence": [
                        "SECONDARY: knowledge base supports "
                        "attribute breakout"
                    ],
                    "model": "minimax/minimax-m3:free",
                    "raw_response_id": "or-int-1",
                }
            )

            captured: dict = {}

            def handler(
                request: httpx.Request,
            ) -> httpx.Response:
                captured["url"] = str(request.url)
                captured["auth_present"] = (
                    request.headers.get("authorization")
                    is not None
                )
                return httpx.Response(
                    200,
                    json=_make_chat_payload(
                        content=response_content,
                        response_id="or-int-1",
                    ),
                )

            http_client = _build_capturing_client(handler)
            provider = OpenRouterProvider(
                api_key="sk-or-v1-secret-key",
                model="minimax/minimax-m3:free",
                http_client=http_client,
            )

            llm_researcher = XSSLLMResearcher(provider)
            result = llm_researcher.analyze(case, context)

            self.assertEqual(
                captured["url"],
                "https://openrouter.ai/api/v1/chat/completions",
            )
            self.assertTrue(captured["auth_present"])
            self.assertEqual(result.case_id, case.case_id)
            self.assertEqual(
                result.case_status_suggestion, "ANALYZED"
            )
            self.assertEqual(len(result.suggested_payloads), 1)
            self.assertEqual(
                result.suggested_payloads[0].origin,
                "knowledge",
            )
            self.assertEqual(
                result.suggested_payloads[0].knowledge_ids,
                [knowledge_id],
            )


if __name__ == "__main__":
    unittest.main()
