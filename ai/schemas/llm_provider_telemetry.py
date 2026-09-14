"""Real LLM provider telemetry schema (Stage R51.3).

Defines bounded, safe provider telemetry for the R51 real provider layer:

    "What happened at the provider boundary, without leaking anything?"

Hard boundaries encoded here:

- Safe metadata only: provider kind, model, advisory mode/id, attempt and
  retry counts, success/failure, error category, validation state and
  response size. Credential material, authorization headers, cookies,
  session tokens, prompts and raw provider bodies are never recorded.
- Advisory-only: telemetry describes infrastructure state. It is never a
  vulnerability finding and never an execution trigger.
- Deterministic projection: the telemetry structure is a pure function of
  the call outcome; external provider content may vary, which is recorded
  explicitly via ``content_deterministic=False`` for external providers.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.llm_provider_error import (
    ERROR_UNKNOWN,
    PROVIDER_ERROR_CATEGORIES,
)

LLM_PROVIDER_TELEMETRY_RULE_VERSION = "r51-3"
RULE_VERSION = LLM_PROVIDER_TELEMETRY_RULE_VERSION

VALIDATION_NOT_RUN = "NOT_RUN"
VALIDATION_PASS = "PASS"
VALIDATION_REJECTED = "REJECTED"

TELEMETRY_VALIDATION_STATES: tuple[str, ...] = (
    VALIDATION_NOT_RUN,
    VALIDATION_PASS,
    VALIDATION_REJECTED,
)

MAX_MODEL_LEN = 160
MAX_ID_LEN = 80
MAX_VALUE_LEN = 160
MAX_RESPONSE_CHARS = 10_000_000

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

TELEMETRY_KEYS: tuple[str, ...] = (
    "rule_version",
    "provider_kind",
    "model",
    "advisory_id",
    "advisory_mode",
    "attempt_count",
    "retry_count",
    "success",
    "error_category",
    "validation_state",
    "response_chars",
    "external_provider",
    "network_access",
    "credentials_used",
    "content_deterministic",
    "research_only",
    "deterministic",
)


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def sanitize_provider_telemetry(value: object) -> dict:
    """Project provider telemetry onto its fixed bounded key set."""

    if not isinstance(value, dict):
        value = {}
    error_category = _safe_text(value.get("error_category")).strip().upper()
    if error_category not in PROVIDER_ERROR_CATEGORIES:
        error_category = ""
    validation_state = _safe_text(
        value.get("validation_state")
    ).strip().upper()
    if validation_state not in TELEMETRY_VALIDATION_STATES:
        validation_state = VALIDATION_NOT_RUN
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "provider_kind": _safe_text(value.get("provider_kind"), 40)
        .strip()
        .upper(),
        "model": _safe_text(value.get("model"), MAX_MODEL_LEN),
        "advisory_id": _safe_text(value.get("advisory_id"), MAX_ID_LEN),
        "advisory_mode": _safe_text(value.get("advisory_mode"), 40)
        .strip()
        .upper(),
        "attempt_count": _bounded_int(value.get("attempt_count"), 0, 10),
        "retry_count": _bounded_int(value.get("retry_count"), 0, 9),
        "success": bool(value.get("success")) is True,
        "error_category": error_category,
        "validation_state": validation_state,
        "response_chars": _bounded_int(
            value.get("response_chars"), 0, MAX_RESPONSE_CHARS
        ),
        "external_provider": bool(value.get("external_provider")) is True,
        "network_access": bool(value.get("network_access")) is True,
        "credentials_used": bool(value.get("credentials_used")) is True,
        "content_deterministic": (
            bool(value.get("content_deterministic", True)) is True
        ),
        "research_only": True,
        "deterministic": True,
    }


class LLMProviderTelemetryPlan(BaseModel):
    """Deterministic, safe provider telemetry contract (R51.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LLM_PROVIDER_TELEMETRY_RULE_VERSION
    provider_kind: str = ""
    model: str = ""
    advisory_id: str = ""
    advisory_mode: str = ""
    attempt_count: int = 0
    retry_count: int = 0
    success: bool = False
    error_category: str = ""
    validation_state: str = VALIDATION_NOT_RUN
    response_chars: int = 0
    external_provider: bool = False
    network_access: bool = False
    credentials_used: bool = False
    content_deterministic: bool = True
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LLM_PROVIDER_TELEMETRY_RULE_VERSION

    @field_validator("provider_kind", "advisory_mode")
    @classmethod
    def _bounded_upper(cls, value: object) -> str:
        return _safe_text(value, 40).strip().upper()

    @field_validator("model")
    @classmethod
    def _bounded_model(cls, value: object) -> str:
        return _safe_text(value, MAX_MODEL_LEN)

    @field_validator("advisory_id")
    @classmethod
    def _bounded_id(cls, value: object) -> str:
        return _safe_text(value, MAX_ID_LEN)

    @field_validator("attempt_count")
    @classmethod
    def _valid_attempts(cls, value: object) -> int:
        number = int(value)
        if not (0 <= number <= 10):
            raise ValueError(f"attempt_count out of bounds: {value!r}")
        return number

    @field_validator("retry_count")
    @classmethod
    def _valid_retries(cls, value: object) -> int:
        number = int(value)
        if not (0 <= number <= 9):
            raise ValueError(f"retry_count out of bounds: {value!r}")
        return number

    @field_validator("error_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text and text not in PROVIDER_ERROR_CATEGORIES:
            raise ValueError(f"invalid error_category: {value!r}")
        return text

    @field_validator("validation_state")
    @classmethod
    def _valid_validation(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TELEMETRY_VALIDATION_STATES:
            raise ValueError(f"invalid validation_state: {value!r}")
        return text

    @field_validator("response_chars")
    @classmethod
    def _valid_chars(cls, value: object) -> int:
        number = int(value)
        if not (0 <= number <= MAX_RESPONSE_CHARS):
            raise ValueError(f"response_chars out of bounds: {value!r}")
        return number

    @field_validator("research_only", "deterministic")
    @classmethod
    def _forced_true(cls, value: object) -> bool:
        if not value:
            raise ValueError("provider telemetry is deterministic and "
                             "research-only")
        return True


def llm_provider_telemetry_plan_projection(
    value: LLMProviderTelemetryPlan,
) -> dict:
    """Serialize provider telemetry to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LLM_PROVIDER_TELEMETRY_RULE_VERSION",
    "RULE_VERSION",
    "VALIDATION_NOT_RUN",
    "VALIDATION_PASS",
    "VALIDATION_REJECTED",
    "TELEMETRY_VALIDATION_STATES",
    "MAX_MODEL_LEN",
    "MAX_ID_LEN",
    "MAX_VALUE_LEN",
    "MAX_RESPONSE_CHARS",
    "TELEMETRY_KEYS",
    "ERROR_UNKNOWN",
    "sanitize_provider_telemetry",
    "LLMProviderTelemetryPlan",
    "llm_provider_telemetry_plan_projection",
]
