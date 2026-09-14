"""Real LLM provider configuration schema (Stage R51.1).

A :class:`LLMRealProviderConfigPlan` is the bounded, secret-free provider
configuration used by the R51 real provider layer:

    "Which provider, model, endpoint and bounded transport limits apply?"

Hard boundaries encoded here:

- Configuration only: no credential value is ever accepted, stored,
  returned or serialized. The configuration carries only the *name* of the
  environment variable that holds the credential and a boolean
  ``credentials_configured`` flag computed at resolution time.
- Provider selection is explicit: the provider kind is a closed value from
  the R45-extended vocabulary; Ollama/local are declared future kinds and
  are not selectable here.
- Fail closed: invalid or missing required configuration raises through
  the R51 registry as a structured CONFIGURATION_ERROR; it is never
  silently defaulted into a working provider and never falls back to a
  different provider.
- Bounded: endpoint, model, timeout, retry count, token budget and
  response size are all bounded.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.llm_provider import (
    PROVIDER_KIND_MOCK,
    PROVIDER_KIND_OPENAI,
    PROVIDER_KIND_OPENROUTER,
    REAL_PROVIDER_KINDS,
    SUPPORTED_PROVIDER_KINDS,
)

LLM_PROVIDER_CONFIG_RULE_VERSION = "r51-1"
RULE_VERSION = LLM_PROVIDER_CONFIG_RULE_VERSION

DEFAULT_TIMEOUT_SECONDS = 30.0
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 120.0

DEFAULT_MAX_RETRIES = 2
MAX_RETRIES_LIMIT = 3

DEFAULT_RETRY_BACKOFF_SECONDS = 0.0
MAX_RETRY_BACKOFF_SECONDS = 10.0

DEFAULT_MAX_TOKENS = 2048
MIN_MAX_TOKENS = 1
MAX_MAX_TOKENS = 8192

DEFAULT_MAX_RESPONSE_BYTES = 65536
MIN_MAX_RESPONSE_BYTES = 1024
MAX_RESPONSE_BYTES_LIMIT = 262144

MAX_MODEL_LEN = 160
MAX_URL_LEN = 200
MAX_ENV_NAME_LEN = 80
MAX_VALUE_LEN = 200

_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,159}$")
_CREDENTIAL_LIKE_RE = re.compile(
    r"(?i)(sk-[A-Za-z0-9]|bearer|authorization|api[_-]?key|apikey|"
    r"password|secret)"
)
_HTTPS_URL_RE = re.compile(
    r"^https://[A-Za-z0-9.\-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~\-/%]*)?$"
)
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

_CONFIG_KEYS: tuple[str, ...] = (
    "rule_version",
    "provider_kind",
    "model",
    "base_url",
    "api_key_env",
    "timeout_seconds",
    "max_retries",
    "retry_backoff_seconds",
    "max_tokens",
    "max_response_bytes",
    "credentials_configured",
    "research_only",
)


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_float(
    value: object, minimum: float, maximum: float, fallback: float
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return fallback
    return max(minimum, min(maximum, float(value)))


def _bounded_int(
    value: object, minimum: int, maximum: int, fallback: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return fallback
    return max(minimum, min(maximum, value))


def sanitize_llm_real_provider_config(value: object) -> dict:
    """Project a provider configuration onto its fixed bounded key set."""

    if not isinstance(value, dict):
        value = {}
    kind = _safe_text(value.get("provider_kind")).strip().upper()
    if kind not in SUPPORTED_PROVIDER_KINDS:
        kind = PROVIDER_KIND_MOCK
    model = _safe_text(value.get("model"), MAX_MODEL_LEN)
    if model and (
        not _MODEL_RE.match(model) or _CREDENTIAL_LIKE_RE.search(model)
    ):
        model = ""
    base_url = _safe_text(value.get("base_url"), MAX_URL_LEN)
    if base_url and not _HTTPS_URL_RE.match(base_url):
        base_url = ""
    api_key_env = _safe_text(value.get("api_key_env"), MAX_ENV_NAME_LEN)
    if api_key_env and not _ENV_NAME_RE.match(api_key_env):
        api_key_env = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "provider_kind": kind,
        "model": model,
        "base_url": base_url,
        "api_key_env": api_key_env,
        "timeout_seconds": _bounded_float(
            value.get("timeout_seconds"),
            MIN_TIMEOUT_SECONDS,
            MAX_TIMEOUT_SECONDS,
            DEFAULT_TIMEOUT_SECONDS,
        ),
        "max_retries": _bounded_int(
            value.get("max_retries"),
            0,
            MAX_RETRIES_LIMIT,
            DEFAULT_MAX_RETRIES,
        ),
        "retry_backoff_seconds": _bounded_float(
            value.get("retry_backoff_seconds"),
            0.0,
            MAX_RETRY_BACKOFF_SECONDS,
            DEFAULT_RETRY_BACKOFF_SECONDS,
        ),
        "max_tokens": _bounded_int(
            value.get("max_tokens"),
            MIN_MAX_TOKENS,
            MAX_MAX_TOKENS,
            DEFAULT_MAX_TOKENS,
        ),
        "max_response_bytes": _bounded_int(
            value.get("max_response_bytes"),
            MIN_MAX_RESPONSE_BYTES,
            MAX_RESPONSE_BYTES_LIMIT,
            DEFAULT_MAX_RESPONSE_BYTES,
        ),
        "credentials_configured": (
            bool(value.get("credentials_configured")) is True
        ),
        "research_only": True,
    }


class LLMRealProviderConfigPlan(BaseModel):
    """Deterministic, secret-free real provider configuration (R51.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LLM_PROVIDER_CONFIG_RULE_VERSION
    provider_kind: str = PROVIDER_KIND_MOCK
    model: str = ""
    base_url: str = ""
    api_key_env: str = ""
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES
    retry_backoff_seconds: float = DEFAULT_RETRY_BACKOFF_SECONDS
    max_tokens: int = DEFAULT_MAX_TOKENS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    credentials_configured: bool = False
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LLM_PROVIDER_CONFIG_RULE_VERSION

    @field_validator("provider_kind")
    @classmethod
    def _valid_kind(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SUPPORTED_PROVIDER_KINDS:
            raise ValueError(f"unsupported provider_kind: {value!r}")
        return text

    @field_validator("model")
    @classmethod
    def _valid_model(cls, value: object) -> str:
        text = _safe_text(value, MAX_MODEL_LEN)
        if text and not _MODEL_RE.match(text):
            raise ValueError(f"invalid model identifier: {value!r}")
        if text and _CREDENTIAL_LIKE_RE.search(text):
            raise ValueError("model identifier must not contain credentials")
        return text

    @field_validator("base_url")
    @classmethod
    def _valid_base_url(cls, value: object) -> str:
        text = _safe_text(value, MAX_URL_LEN)
        if text and not _HTTPS_URL_RE.match(text):
            raise ValueError(f"invalid provider base_url: {value!r}")
        return text

    @field_validator("api_key_env")
    @classmethod
    def _valid_env_name(cls, value: object) -> str:
        text = _safe_text(value, MAX_ENV_NAME_LEN)
        if text and not _ENV_NAME_RE.match(text):
            raise ValueError(f"invalid api_key_env name: {value!r}")
        return text

    @field_validator("timeout_seconds")
    @classmethod
    def _valid_timeout(cls, value: object) -> float:
        number = float(value)
        if not (MIN_TIMEOUT_SECONDS <= number <= MAX_TIMEOUT_SECONDS):
            raise ValueError(f"timeout_seconds out of bounds: {value!r}")
        return number

    @field_validator("max_retries")
    @classmethod
    def _valid_retries(cls, value: object) -> int:
        number = int(value)
        if not (0 <= number <= MAX_RETRIES_LIMIT):
            raise ValueError(f"max_retries out of bounds: {value!r}")
        return number

    @field_validator("retry_backoff_seconds")
    @classmethod
    def _valid_backoff(cls, value: object) -> float:
        number = float(value)
        if not (0.0 <= number <= MAX_RETRY_BACKOFF_SECONDS):
            raise ValueError(
                f"retry_backoff_seconds out of bounds: {value!r}"
            )
        return number

    @field_validator("max_tokens")
    @classmethod
    def _valid_tokens(cls, value: object) -> int:
        number = int(value)
        if not (MIN_MAX_TOKENS <= number <= MAX_MAX_TOKENS):
            raise ValueError(f"max_tokens out of bounds: {value!r}")
        return number

    @field_validator("max_response_bytes")
    @classmethod
    def _valid_bytes(cls, value: object) -> int:
        number = int(value)
        if not (
            MIN_MAX_RESPONSE_BYTES <= number <= MAX_RESPONSE_BYTES_LIMIT
        ):
            raise ValueError(f"max_response_bytes out of bounds: {value!r}")
        return number

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("provider configurations are research-only")
        return True


def llm_real_provider_config_plan_projection(
    value: LLMRealProviderConfigPlan,
) -> dict:
    """Serialize a provider configuration to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LLM_PROVIDER_CONFIG_RULE_VERSION",
    "RULE_VERSION",
    "DEFAULT_TIMEOUT_SECONDS",
    "MIN_TIMEOUT_SECONDS",
    "MAX_TIMEOUT_SECONDS",
    "DEFAULT_MAX_RETRIES",
    "MAX_RETRIES_LIMIT",
    "DEFAULT_RETRY_BACKOFF_SECONDS",
    "MAX_RETRY_BACKOFF_SECONDS",
    "DEFAULT_MAX_TOKENS",
    "MIN_MAX_TOKENS",
    "MAX_MAX_TOKENS",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "MIN_MAX_RESPONSE_BYTES",
    "MAX_RESPONSE_BYTES_LIMIT",
    "MAX_MODEL_LEN",
    "MAX_URL_LEN",
    "MAX_ENV_NAME_LEN",
    "REAL_PROVIDER_KINDS",
    "PROVIDER_KIND_OPENROUTER",
    "PROVIDER_KIND_OPENAI",
    "sanitize_llm_real_provider_config",
    "LLMRealProviderConfigPlan",
    "llm_real_provider_config_plan_projection",
]
