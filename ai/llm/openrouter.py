from __future__ import annotations

import os
from typing import Any

from openai import OpenAI
from openai import (
    APIConnectionError,
    APIStatusError,
)

from ai.llm.base import LLMProvider, LLMResult


DEFAULT_MODEL = "minimax/minimax-m3:free"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_TIMEOUT_SECONDS = 60.0


class OpenRouterProviderError(RuntimeError):
    """Raised when the OpenRouter provider cannot fulfill a request."""


OpenRouterResponse = LLMResult


def _resolve_default_model(env_value: str) -> str:
    if env_value:
        return env_value
    return DEFAULT_MODEL


class OpenRouterProvider(LLMProvider):
    """
    Real OpenRouter provider for the XSS LLM layer.

    The provider is the only place that talks to OpenRouter. The
    XSS layer above it only ever calls :meth:`generate`. The
    provider never logs or echoes the API key, never performs
    retries, and never reaches out to anything other than the
    configured OpenRouter chat completions endpoint.

    Configuration:

    - ``OPENROUTER_API_KEY`` (required at construction time)
    - ``OPENROUTER_MODEL``   (optional; falls back to
      ``minimax/minimax-m3:free``)

    The HTTP transport is injectable via ``http_client`` so tests
    can drive a fake without making a real network call.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        base_url: str = DEFAULT_BASE_URL,
        http_client: Any = None,
        api_key_env: str = "OPENROUTER_API_KEY",
        model_env: str = "OPENROUTER_MODEL",
    ) -> None:
        resolved_api_key = (
            api_key
            if api_key is not None
            else os.getenv(api_key_env, "")
        )
        if not resolved_api_key:
            raise OpenRouterProviderError(
                f"{api_key_env} is not configured"
            )

        resolved_model = (
            model
            if model is not None
            else _resolve_default_model(
                os.getenv(model_env, "")
            )
        )
        if not resolved_model:
            raise OpenRouterProviderError(
                f"{model_env} is not configured"
            )

        self._api_key = resolved_api_key
        self.model = resolved_model
        self.base_url = base_url
        self.timeout = timeout

        client_kwargs: dict[str, Any] = {
            "api_key": resolved_api_key,
            "base_url": base_url,
            "timeout": timeout,
        }
        if http_client is not None:
            client_kwargs["http_client"] = http_client

        self._client = OpenAI(**client_kwargs)

    def generate(self, prompt: str) -> str:
        return self.complete(prompt).content

    def _extract_content(self, response: Any) -> str:
        choices = getattr(response, "choices", None)
        if not choices:
            raise OpenRouterProviderError(
                "OpenRouter response has no choices"
            )

        first = choices[0]
        message = getattr(first, "message", None)
        content = getattr(message, "content", None)

        if not content:
            raise OpenRouterProviderError(
                "OpenRouter response has no message content"
            )

        return content

    def complete(self, prompt: str) -> OpenRouterResponse:
        """
        Send a single chat completion request and return the
        assistant content together with the provider's request id
        and model identifier.

        The provider never retries and never exposes the API key
        in any error path.
        """

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                response_format={"type": "json_object"},
            )
        except APIStatusError as exc:
            raise OpenRouterProviderError(
                f"OpenRouter returned HTTP "
                f"{exc.status_code}: {type(exc).__name__}"
            ) from exc
        except APIConnectionError as exc:
            raise OpenRouterProviderError(
                f"OpenRouter connection error: "
                f"{type(exc).__name__}"
            ) from exc
        except Exception as exc:
            raise OpenRouterProviderError(
                f"OpenRouter request failed: "
                f"{type(exc).__name__}"
            ) from exc

        content = self._extract_content(response)

        return OpenRouterResponse(
            content=content,
            request_id=getattr(response, "id", None),
            model=getattr(response, "model", None),
        )
