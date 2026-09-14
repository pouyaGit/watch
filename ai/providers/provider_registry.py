"""Stage R51 explicit provider registry (fail-closed selection).

Selects the advisory provider for an explicitly requested provider kind:

    "Which provider will serve this advisory request?"

Hard boundaries encoded here:

- Explicit selection only: the caller names the provider kind. There is no
  default provider in the registry, no silent fallback to another provider
  and no silent fallback to the mock.
- Fail closed: a missing, unknown or future (Ollama/local) kind raises a
  structured CONFIGURATION_ERROR; invalid configuration is surfaced the
  same way.
- The R45-native pure factory (``get_advisory_provider``) remains
  mock-only; this registry is the R51 selection point for real providers.
- Injectable transport: tests and hosts may inject a bounded transport;
  the default is the stdlib transport.
- No I/O, no network call at selection time, no LLM, no Mongo, no
  execution.
"""

from __future__ import annotations

from ai.knowledge.llm_provider import AdvisoryProvider, MockLLMProvider
from ai.schemas.llm_provider import (
    PROVIDER_KIND_MOCK,
    PROVIDER_KIND_OPENAI,
    PROVIDER_KIND_OPENROUTER,
)

from ai.providers.openai_provider import OpenAIProvider
from ai.providers.openrouter_provider import OpenRouterProvider
from ai.providers.provider_errors import unsupported_kind_error

R51_PROVIDER_REGISTRY_RULE_VERSION = "r51-registry"
RULE_VERSION = R51_PROVIDER_REGISTRY_RULE_VERSION

R51_REGISTRY_KINDS: tuple[str, ...] = (
    PROVIDER_KIND_MOCK,
    PROVIDER_KIND_OPENROUTER,
    PROVIDER_KIND_OPENAI,
)

R51_REAL_PROVIDER_KINDS: tuple[str, ...] = (
    PROVIDER_KIND_OPENROUTER,
    PROVIDER_KIND_OPENAI,
)

REAL_PROVIDER_CLASSES: dict[str, type] = {
    PROVIDER_KIND_OPENROUTER: OpenRouterProvider,
    PROVIDER_KIND_OPENAI: OpenAIProvider,
}


def available_provider_kinds() -> list[str]:
    """Return the closed R51 selectable provider kinds."""

    return list(R51_REGISTRY_KINDS)


def available_real_provider_kinds() -> list[str]:
    """Return the closed R51 real (network) provider kinds."""

    return list(R51_REAL_PROVIDER_KINDS)


def select_provider(
    provider_kind: object = None, **options
) -> AdvisoryProvider:
    """Return the explicitly requested provider (fail closed).

    ``options`` are forwarded to the real provider constructor; the caller
    remains responsible for supplying model/transport/environment
    overrides. Missing or unsupported kinds raise a structured
    CONFIGURATION_ERROR and never fall back to another provider.
    """

    text = str(provider_kind if provider_kind is not None else "").strip()
    text = text.upper()
    if not text:
        raise unsupported_kind_error("")
    if text == PROVIDER_KIND_MOCK:
        return MockLLMProvider()
    provider_class = REAL_PROVIDER_CLASSES.get(text)
    if provider_class is None:
        raise unsupported_kind_error(text)
    return provider_class(**options)


__all__ = [
    "R51_PROVIDER_REGISTRY_RULE_VERSION",
    "RULE_VERSION",
    "R51_REGISTRY_KINDS",
    "R51_REAL_PROVIDER_KINDS",
    "REAL_PROVIDER_CLASSES",
    "available_provider_kinds",
    "available_real_provider_kinds",
    "select_provider",
]
