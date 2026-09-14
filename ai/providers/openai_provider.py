"""Stage R51 OpenAI provider adapter.

Real OpenAI provider behind the R45 advisory provider interface using the
OpenAI chat completions HTTP API.

Configuration (environment-based, no hardcoded credentials):

- ``OPENAI_API_KEY``  (required at call time; fail closed if missing)
- ``OPENAI_MODEL``    (required; the model is never hardcoded)
- ``OPENAI_BASE_URL`` (optional; defaults to the public API base URL)

The adapter shares the R51 provider interface, request/response contract,
error mapping, retry policy and safety pipeline with the OpenRouter
adapter. The credential is only ever placed in the transport
authorization header and never appears in results, errors, telemetry or
logs.

No vulnerability confirmation, no execution, no payloads, no attack
planning is represented here.
"""

from __future__ import annotations

from ai.schemas.llm_provider import PROVIDER_KIND_OPENAI

from ai.providers.real_provider import RealAdvisoryProvider

OPENAI_PROVIDER_RULE_VERSION = "r51-openai"
RULE_VERSION = OPENAI_PROVIDER_RULE_VERSION

DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENAI_API_KEY_ENV = "OPENAI_API_KEY"
OPENAI_MODEL_ENV = "OPENAI_MODEL"
OPENAI_BASE_URL_ENV = "OPENAI_BASE_URL"


class OpenAIProvider(RealAdvisoryProvider):
    """Bounded OpenAI advisory provider (R51)."""

    provider_kind = PROVIDER_KIND_OPENAI
    default_base_url = DEFAULT_OPENAI_BASE_URL
    default_api_key_env = OPENAI_API_KEY_ENV
    default_model_env = OPENAI_MODEL_ENV
    default_base_url_env = OPENAI_BASE_URL_ENV


__all__ = [
    "OPENAI_PROVIDER_RULE_VERSION",
    "RULE_VERSION",
    "DEFAULT_OPENAI_BASE_URL",
    "OPENAI_API_KEY_ENV",
    "OPENAI_MODEL_ENV",
    "OPENAI_BASE_URL_ENV",
    "OpenAIProvider",
]
