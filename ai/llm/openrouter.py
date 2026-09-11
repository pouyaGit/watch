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
# Completion/output token budget sent with every request.
# Without an explicit budget, some OpenRouter models (e.g.
# MiniMax) apply a small provider-side default and truncate
# structured JSON responses mid-field.
DEFAULT_MAX_TOKENS = 4096


class OpenRouterProviderError(RuntimeError):
    """Raised when the OpenRouter provider cannot fulfill a request."""


OpenRouterResponse = LLMResult


def _resolve_default_model(env_value: str) -> str:
    if env_value:
        return env_value
    return DEFAULT_MODEL


def _resolve_max_tokens(
    explicit: int | None,
    env_name: str,
    env_value: str | None,
) -> int:
    """
    Resolve the completion/output token budget.

    Precedence: explicit constructor argument, then the env
    variable (``OPENROUTER_MAX_TOKENS`` by default), then
    ``DEFAULT_MAX_TOKENS``. An empty or whitespace-only env
    value counts as unset. Any other value that is not a
    positive integer raises ``OpenRouterProviderError``:
    invalid configuration fails loudly instead of being
    silently clamped or dropped, because a missing or
    too-small budget is exactly what produces truncated
    JSON responses.
    """

    if explicit is not None:
        if (
            isinstance(explicit, bool)
            or not isinstance(explicit, int)
            or explicit <= 0
        ):
            raise OpenRouterProviderError(
                "max_tokens must be a positive integer, "
                f"got {explicit!r}"
            )
        return explicit

    text = (env_value or "").strip()
    if not text:
        return DEFAULT_MAX_TOKENS
    try:
        value = int(text)
    except ValueError:
        raise OpenRouterProviderError(
            f"{env_name} must be a positive integer, "
            f"got {env_value!r}"
        ) from None
    if value <= 0:
        raise OpenRouterProviderError(
            f"{env_name} must be a positive integer, "
            f"got {env_value!r}"
        )
    return value


class OpenRouterProvider(LLMProvider):
    """
    Real OpenRouter provider for the XSS LLM layer.

    The provider is the only place that talks to OpenRouter. The
    XSS layer above it only ever calls :meth:`generate`. The
    provider never logs or echoes the API key, never performs
    retries (the openai SDK's built-in retry-on-429/5xx behavior is
    disabled via ``max_retries=0``, so ONE invocation is exactly
    ONE provider HTTP call), and never reaches out to anything
    other than the configured OpenRouter chat completions endpoint.

    Configuration:

    - ``OPENROUTER_API_KEY`` (required at construction time)
    - ``OPENROUTER_MODEL``   (optional; falls back to
      ``minimax/minimax-m3:free``)
    - ``OPENROUTER_MAX_TOKENS`` (optional completion/output
      token budget, passed to the API as ``max_tokens``;
      falls back to ``DEFAULT_MAX_TOKENS``). An explicit
      budget keeps structured JSON responses from being
      truncated mid-field by a small provider-side default.

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
        max_tokens: int | None = None,
        max_tokens_env: str = "OPENROUTER_MAX_TOKENS",
        response_format_json: bool = True,
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
        # R24.11: some free models reject ``response_format={"type":"json_object"}``.
        # Default True preserves the existing R23/R24 behavior exactly; callers
        # may explicitly opt out for compatibility (the response is still parsed
        # and validated by the caller).
        self.response_format_json = bool(response_format_json)
        self.max_tokens = _resolve_max_tokens(
            max_tokens,
            max_tokens_env,
            os.getenv(max_tokens_env, ""),
        )

        client_kwargs: dict[str, Any] = {
            "api_key": resolved_api_key,
            "base_url": base_url,
            "timeout": timeout,
            # One invocation = exactly one provider HTTP call. The
            # openai SDK retries 408/409/429/5xx by default
            # (max_retries=2), which would burn rate-limit budget
            # (e.g. free-tier 429s) behind the caller's back.
            # Automatic retries / fallback-model routing belong to a
            # future orchestration layer, not to this provider.
            "max_retries": 0,
        }
        if http_client is not None:
            client_kwargs["http_client"] = http_client

        self._client = OpenAI(**client_kwargs)

    def generate(self, prompt: str) -> str:
        return self.complete(prompt).content

    def _extract_content(self, response: Any) -> str:
        choices = getattr(response, "choices", None)
        if not isinstance(choices, (list, tuple)) or not choices:
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
        if not isinstance(content, str):
            # Malformed provider response: some providers/models
            # return ``message.content`` as a non-string (e.g. an
            # array of content parts). It must never leak past the
            # provider boundary as a non-str ``LLMResult.content``.
            raise OpenRouterProviderError(
                "OpenRouter response content is not a string: "
                f"{type(content).__name__}"
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

        request_kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "max_tokens": self.max_tokens,
        }
        if self.response_format_json:
            request_kwargs["response_format"] = {"type": "json_object"}

        try:
            response = self._client.chat.completions.create(**request_kwargs)
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
