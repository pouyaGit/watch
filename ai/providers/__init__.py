"""R51 real LLM provider layer.

Network-capable provider adapters implemented behind the existing R45 LLM
advisory provider interface:

- explicit selection: :func:`ai.providers.provider_registry.select_provider`
- OpenRouter / OpenAI adapters (bounded HTTP, timeout, retries)
- strict outbound context allowlist and data minimization
- deterministic bounded prompt construction and strict response parsing
- structured, secret-free provider error and telemetry contracts
- advisory bridge that runs provider output through the unmodified R45
  advisory validator and result assembly

The layer is advisory-only. Nothing here confirms vulnerabilities,
executes anything, generates payloads or plans attacks, and no specialist
agent gains network access as a side effect.
"""

from ai.providers.advisory_bridge import (
    BRIDGE_KEYS,
    BRIDGE_STATE_ERROR,
    BRIDGE_STATE_OK,
    BRIDGE_STATE_REJECTED,
    BRIDGE_STATES,
    R51_ADVISORY_BRIDGE_RULE_VERSION,
    SingleResponseProvider,
    export_real_llm_advisory,
)
from ai.providers.context_allowlist import (
    SENSITIVE_REASON_CODES,
    detect_sensitive_content,
    sanitize_provider_context,
)
from ai.providers.http_transport import (
    HttpRequestSpec,
    HttpResponseSpec,
    HttpTransport,
    TransportFailure,
    UrllibHttpTransport,
)
from ai.providers.openai_provider import OpenAIProvider
from ai.providers.openrouter_provider import OpenRouterProvider
from ai.providers.prompt_builder import (
    build_provider_prompt,
    parse_advisory_content,
)
from ai.providers.provider_errors import (
    ProviderCallError,
    ProviderContextRejected,
    serialize_provider_call_error,
)
from ai.providers.provider_registry import (
    R51_REGISTRY_KINDS,
    available_provider_kinds,
    available_real_provider_kinds,
    select_provider,
)
from ai.providers.real_provider import RealAdvisoryProvider

__all__ = [
    "R51_ADVISORY_BRIDGE_RULE_VERSION",
    "BRIDGE_STATES",
    "BRIDGE_KEYS",
    "BRIDGE_STATE_OK",
    "BRIDGE_STATE_REJECTED",
    "BRIDGE_STATE_ERROR",
    "SingleResponseProvider",
    "export_real_llm_advisory",
    "SENSITIVE_REASON_CODES",
    "detect_sensitive_content",
    "sanitize_provider_context",
    "HttpRequestSpec",
    "HttpResponseSpec",
    "HttpTransport",
    "TransportFailure",
    "UrllibHttpTransport",
    "OpenAIProvider",
    "OpenRouterProvider",
    "build_provider_prompt",
    "parse_advisory_content",
    "ProviderCallError",
    "ProviderContextRejected",
    "serialize_provider_call_error",
    "R51_REGISTRY_KINDS",
    "available_provider_kinds",
    "available_real_provider_kinds",
    "select_provider",
    "RealAdvisoryProvider",
]
