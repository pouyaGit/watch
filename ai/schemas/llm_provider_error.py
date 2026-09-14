"""Real LLM provider error contract schema (Stage R51.2).

Defines the structured, secret-free error contract for the R51 real
provider layer:

    "What went wrong at the provider boundary, and is a retry appropriate?"

Hard boundaries encoded here:

- Error metadata only: a provider error is a structured research-infrastructure
  condition. It is never a vulnerability finding, never a security
  conclusion and never an execution trigger.
- No provider internals: the error carries a bounded safe message and a
  closed error code/category. Raw exception text, request headers, prompts
  and raw provider bodies are never part of the contract.
- No credential material: the sanitizer rejects/blanks any message that
  appears to contain credential or authorization material.
- Retry classification is explicit and deterministic per category, with
  5xx provider errors retryable and 4xx provider errors not retryable.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

LLM_PROVIDER_ERROR_RULE_VERSION = "r51-2"
RULE_VERSION = LLM_PROVIDER_ERROR_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed error categories
# ---------------------------------------------------------------------------

ERROR_CONFIGURATION = "CONFIGURATION_ERROR"
ERROR_AUTHENTICATION = "AUTHENTICATION_ERROR"
ERROR_AUTHORIZATION = "AUTHORIZATION_ERROR"
ERROR_RATE_LIMIT = "RATE_LIMIT_ERROR"
ERROR_TIMEOUT = "TIMEOUT_ERROR"
ERROR_NETWORK = "NETWORK_ERROR"
ERROR_PROVIDER = "PROVIDER_ERROR"
ERROR_INVALID_RESPONSE = "INVALID_RESPONSE"
ERROR_EMPTY_RESPONSE = "EMPTY_RESPONSE"
ERROR_SAFETY_VALIDATION = "SAFETY_VALIDATION_ERROR"
ERROR_UNKNOWN = "UNKNOWN_ERROR"

PROVIDER_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_CONFIGURATION,
    ERROR_AUTHENTICATION,
    ERROR_AUTHORIZATION,
    ERROR_RATE_LIMIT,
    ERROR_TIMEOUT,
    ERROR_NETWORK,
    ERROR_PROVIDER,
    ERROR_INVALID_RESPONSE,
    ERROR_EMPTY_RESPONSE,
    ERROR_SAFETY_VALIDATION,
    ERROR_UNKNOWN,
)

RETRYABLE_PROVIDER_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_RATE_LIMIT,
    ERROR_TIMEOUT,
    ERROR_NETWORK,
)

# ---------------------------------------------------------------------------
# Closed error codes
# ---------------------------------------------------------------------------

CODE_CONFIG_MISSING_CREDENTIAL = "CONFIG_MISSING_CREDENTIAL"
CODE_CONFIG_MISSING_MODEL = "CONFIG_MISSING_MODEL"
CODE_CONFIG_INVALID_BASE_URL = "CONFIG_INVALID_BASE_URL"
CODE_CONFIG_INVALID_PARAMETER = "CONFIG_INVALID_PARAMETER"
CODE_CONFIG_UNSUPPORTED_KIND = "CONFIG_UNSUPPORTED_KIND"
CODE_CONFIG_CONTEXT_UNSAFE = "CONFIG_CONTEXT_UNSAFE"
CODE_AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
CODE_AUTHZ_FORBIDDEN = "AUTHORIZATION_FORBIDDEN"
CODE_RATE_LIMITED = "RATE_LIMITED"
CODE_REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
CODE_CONNECTION_FAILED = "CONNECTION_FAILED"
CODE_TRANSPORT_ERROR = "TRANSPORT_ERROR"
CODE_PROVIDER_HTTP_ERROR = "PROVIDER_HTTP_ERROR"
CODE_PROVIDER_TRANSIENT_ERROR = "PROVIDER_TRANSIENT_ERROR"
CODE_INVALID_PROVIDER_RESPONSE = "INVALID_PROVIDER_RESPONSE"
CODE_EMPTY_PROVIDER_RESPONSE = "EMPTY_PROVIDER_RESPONSE"
CODE_UNSAFE_CONTEXT_REJECTED = "UNSAFE_CONTEXT_REJECTED"
CODE_UNSAFE_OUTPUT_REJECTED = "UNSAFE_OUTPUT_REJECTED"
CODE_UNKNOWN = "UNKNOWN"

PROVIDER_ERROR_CODES: tuple[str, ...] = (
    CODE_CONFIG_MISSING_CREDENTIAL,
    CODE_CONFIG_MISSING_MODEL,
    CODE_CONFIG_INVALID_BASE_URL,
    CODE_CONFIG_INVALID_PARAMETER,
    CODE_CONFIG_UNSUPPORTED_KIND,
    CODE_CONFIG_CONTEXT_UNSAFE,
    CODE_AUTH_INVALID_CREDENTIALS,
    CODE_AUTHZ_FORBIDDEN,
    CODE_RATE_LIMITED,
    CODE_REQUEST_TIMEOUT,
    CODE_CONNECTION_FAILED,
    CODE_TRANSPORT_ERROR,
    CODE_PROVIDER_HTTP_ERROR,
    CODE_PROVIDER_TRANSIENT_ERROR,
    CODE_INVALID_PROVIDER_RESPONSE,
    CODE_EMPTY_PROVIDER_RESPONSE,
    CODE_UNSAFE_CONTEXT_REJECTED,
    CODE_UNSAFE_OUTPUT_REJECTED,
    CODE_UNKNOWN,
)

TRANSIENT_HTTP_STATUSES: tuple[int, ...] = (500, 502, 503, 504)

MAX_SAFE_MESSAGE_LEN = 200
MAX_MODEL_LEN = 160
MAX_STATUS_CODE = 599

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_FORBIDDEN_ERROR_TOKENS: tuple[re.Pattern, ...] = (
    re.compile(r"\bsk-[A-Za-z0-9._\-]{6,}"),
    re.compile(r"(?i)\bauthorization\b"),
    re.compile(r"(?i)\bbearer\b"),
    re.compile(r"(?i)\bcookie\b"),
    re.compile(r"(?i)\b(api[_-]?key|apikey)\b"),
    re.compile(r"(?i)\b(password|passwd|secret)\b"),
    re.compile(r"(?i)\b(session|access|refresh)[_-]?token\b"),
)

ERROR_KEYS: tuple[str, ...] = (
    "rule_version",
    "provider_kind",
    "error_category",
    "error_code",
    "status_code",
    "retryable",
    "attempts",
    "model",
    "safe_message",
    "research_only",
    "deterministic",
)


def _safe_text(value: object, limit: int = MAX_SAFE_MESSAGE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def safe_error_message(value: object) -> str:
    """Return a bounded message with credential-like material blanked.

    Defense in depth only: provider adapters already construct bounded
    messages. This helper guarantees the error contract itself can never
    carry credential material.
    """

    text = _safe_text(value)
    for pattern in _FORBIDDEN_ERROR_TOKENS:
        if pattern.search(text):
            return "provider error (details withheld)"
    return text


def default_retryable(error_category: object) -> bool:
    """Return the deterministic retry classification for a category."""

    text = _safe_text(error_category).strip().upper()
    return text in RETRYABLE_PROVIDER_ERROR_CATEGORIES


def sanitize_provider_error(value: object) -> dict:
    """Project a provider error onto its fixed bounded key set."""

    if not isinstance(value, dict):
        value = {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in PROVIDER_ERROR_CATEGORIES:
        category = ERROR_UNKNOWN
    code = _safe_text(value.get("error_code")).strip().upper()
    if code not in PROVIDER_ERROR_CODES:
        code = CODE_UNKNOWN
    status = value.get("status_code")
    if isinstance(status, bool) or not isinstance(status, int):
        status = None
    else:
        status = max(0, min(MAX_STATUS_CODE, status))
    attempts = value.get("attempts")
    if isinstance(attempts, bool) or not isinstance(attempts, int):
        attempts = 0
    attempts = max(0, min(10, attempts))
    retryable = value.get("retryable")
    if not isinstance(retryable, bool):
        retryable = default_retryable(category)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "provider_kind": _safe_text(value.get("provider_kind"), 40)
        .strip()
        .upper(),
        "error_category": category,
        "error_code": code,
        "status_code": status,
        "retryable": retryable,
        "attempts": attempts,
        "model": _safe_text(value.get("model"), MAX_MODEL_LEN),
        "safe_message": safe_error_message(value.get("safe_message")),
        "research_only": True,
        "deterministic": True,
    }


class LLMProviderErrorPlan(BaseModel):
    """Deterministic, secret-free provider error contract (R51.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LLM_PROVIDER_ERROR_RULE_VERSION
    provider_kind: str = ""
    error_category: str = ERROR_UNKNOWN
    error_code: str = CODE_UNKNOWN
    status_code: int | None = None
    retryable: bool = False
    attempts: int = 0
    model: str = ""
    safe_message: str = ""
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LLM_PROVIDER_ERROR_RULE_VERSION

    @field_validator("provider_kind")
    @classmethod
    def _bounded_kind(cls, value: object) -> str:
        return _safe_text(value, 40).strip().upper()

    @field_validator("error_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PROVIDER_ERROR_CATEGORIES:
            raise ValueError(f"invalid error_category: {value!r}")
        return text

    @field_validator("error_code")
    @classmethod
    def _valid_code(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PROVIDER_ERROR_CODES:
            raise ValueError(f"invalid error_code: {value!r}")
        return text

    @field_validator("status_code")
    @classmethod
    def _valid_status(cls, value: object) -> object:
        if value is None:
            return None
        number = int(value)
        if not (0 <= number <= MAX_STATUS_CODE):
            raise ValueError(f"status_code out of bounds: {value!r}")
        return number

    @field_validator("attempts")
    @classmethod
    def _valid_attempts(cls, value: object) -> int:
        number = int(value)
        if not (0 <= number <= 10):
            raise ValueError(f"attempts out of bounds: {value!r}")
        return number

    @field_validator("safe_message")
    @classmethod
    def _bounded_message(cls, value: object) -> str:
        return safe_error_message(value)

    @field_validator("research_only", "deterministic")
    @classmethod
    def _forced_true(cls, value: object) -> bool:
        if not value:
            raise ValueError("provider errors are deterministic and "
                             "research-only")
        return True


def llm_provider_error_plan_projection(
    value: LLMProviderErrorPlan,
) -> dict:
    """Serialize a provider error to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LLM_PROVIDER_ERROR_RULE_VERSION",
    "RULE_VERSION",
    "ERROR_CONFIGURATION",
    "ERROR_AUTHENTICATION",
    "ERROR_AUTHORIZATION",
    "ERROR_RATE_LIMIT",
    "ERROR_TIMEOUT",
    "ERROR_NETWORK",
    "ERROR_PROVIDER",
    "ERROR_INVALID_RESPONSE",
    "ERROR_EMPTY_RESPONSE",
    "ERROR_SAFETY_VALIDATION",
    "ERROR_UNKNOWN",
    "PROVIDER_ERROR_CATEGORIES",
    "RETRYABLE_PROVIDER_ERROR_CATEGORIES",
    "CODE_CONFIG_MISSING_CREDENTIAL",
    "CODE_CONFIG_MISSING_MODEL",
    "CODE_CONFIG_INVALID_BASE_URL",
    "CODE_CONFIG_INVALID_PARAMETER",
    "CODE_CONFIG_UNSUPPORTED_KIND",
    "CODE_CONFIG_CONTEXT_UNSAFE",
    "CODE_AUTH_INVALID_CREDENTIALS",
    "CODE_AUTHZ_FORBIDDEN",
    "CODE_RATE_LIMITED",
    "CODE_REQUEST_TIMEOUT",
    "CODE_CONNECTION_FAILED",
    "CODE_TRANSPORT_ERROR",
    "CODE_PROVIDER_HTTP_ERROR",
    "CODE_PROVIDER_TRANSIENT_ERROR",
    "CODE_INVALID_PROVIDER_RESPONSE",
    "CODE_EMPTY_PROVIDER_RESPONSE",
    "CODE_UNSAFE_CONTEXT_REJECTED",
    "CODE_UNSAFE_OUTPUT_REJECTED",
    "CODE_UNKNOWN",
    "PROVIDER_ERROR_CODES",
    "TRANSIENT_HTTP_STATUSES",
    "MAX_SAFE_MESSAGE_LEN",
    "MAX_MODEL_LEN",
    "MAX_STATUS_CODE",
    "ERROR_KEYS",
    "safe_error_message",
    "default_retryable",
    "sanitize_provider_error",
    "LLMProviderErrorPlan",
    "llm_provider_error_plan_projection",
]
