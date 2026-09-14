"""Stage R51 OpenRouter provider adapter.

Real OpenRouter provider behind the R45 advisory provider interface using
the OpenRouter OpenAI-compatible chat completions HTTP API.

Configuration (environment-based, no hardcoded credentials):

- ``OPENROUTER_API_KEY``  (required at call time; fail closed if missing)
- ``OPENROUTER_MODEL``    (required; the model is never hardcoded)
- ``OPENROUTER_BASE_URL`` (optional; defaults to the public API base URL)

The adapter performs one bounded HTTP exchange per attempt with an
explicit timeout, bounded retries for transient failures only, a bounded
token budget and a bounded response size. The credential is only ever
placed in the transport authorization header and never appears in
results, errors, telemetry or logs.

No vulnerability confirmation, no execution, no payloads, no attack
planning is represented here.
"""

from __future__ import annotations

from ai.schemas.llm_provider import PROVIDER_KIND_OPENROUTER

from ai.providers.real_provider import RealAdvisoryProvider

OPENROUTER_PROVIDER_RULE_VERSION = "r51-openrouter"
RULE_VERSION = OPENROUTER_PROVIDER_RULE_VERSION

DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_API_KEY_ENV = "OPENROUTER_API_KEY"
OPENROUTER_MODEL_ENV = "OPENROUTER_MODEL"
OPENROUTER_BASE_URL_ENV = "OPENROUTER_BASE_URL"


class OpenRouterProvider(RealAdvisoryProvider):
    """Bounded OpenRouter advisory provider (R51)."""

    provider_kind = PROVIDER_KIND_OPENROUTER
    default_base_url = DEFAULT_OPENROUTER_BASE_URL
    default_api_key_env = OPENROUTER_API_KEY_ENV
    default_model_env = OPENROUTER_MODEL_ENV
    default_base_url_env = OPENROUTER_BASE_URL_ENV


__all__ = [
    "OPENROUTER_PROVIDER_RULE_VERSION",
    "RULE_VERSION",
    "DEFAULT_OPENROUTER_BASE_URL",
    "OPENROUTER_API_KEY_ENV",
    "OPENROUTER_MODEL_ENV",
    "OPENROUTER_BASE_URL_ENV",
    "OpenRouterProvider",
]
