"""Stage R51 provider errors (structured, secret-free exceptions).

Defines the R51 provider exception hierarchy used by the real provider
adapters:

- :class:`ProviderCallError` carries a closed R51 error category/code,
  bounded attempts/retry metadata and a safe message that never contains
  credential or authorization material.
- :class:`ProviderContextRejected` is raised before any provider call when
  the outbound advisory context fails the R51 allowlist/sensitive-content
  gate.

Hard boundaries encoded here:

- Errors are infrastructure state only: they are never vulnerability
  findings and never execution triggers.
- No credential material is accepted into or emitted from an error.
- The error projects onto the R51 error schema
  (``ai.schemas.llm_provider_error``).

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

from ai.knowledge.llm_provider import AdvisoryProviderError
from ai.schemas.llm_provider_error import (
    CODE_CONFIG_MISSING_CREDENTIAL,
    CODE_CONFIG_MISSING_MODEL,
    CODE_CONFIG_UNSUPPORTED_KIND,
    CODE_UNKNOWN,
    CODE_UNSAFE_CONTEXT_REJECTED,
    ERROR_CONFIGURATION,
    ERROR_SAFETY_VALIDATION,
    ERROR_UNKNOWN,
    PROVIDER_ERROR_CATEGORIES,
    PROVIDER_ERROR_CODES,
    LLMProviderErrorPlan,
    default_retryable,
    llm_provider_error_plan_projection,
    safe_error_message,
)

PROVIDER_ERRORS_RULE_VERSION = "r51-2"
RULE_VERSION = PROVIDER_ERRORS_RULE_VERSION


class ProviderCallError(AdvisoryProviderError):
    """Bounded provider failure with a structured, secret-free contract."""

    def __init__(
        self,
        error_category: str = ERROR_UNKNOWN,
        error_code: str = CODE_UNKNOWN,
        *,
        status_code: int | None = None,
        retryable: bool | None = None,
        attempts: int = 0,
        provider_kind: str = "",
        model: str = "",
        safe_message: str = "",
    ):
        category = str(error_category or ERROR_UNKNOWN).strip().upper()
        if category not in PROVIDER_ERROR_CATEGORIES:
            category = ERROR_UNKNOWN
        code = str(error_code or CODE_UNKNOWN).strip().upper()
        if code not in PROVIDER_ERROR_CODES:
            code = CODE_UNKNOWN
        self.error_category = category
        self.error_code = code
        self.status_code = status_code
        self.attempts = max(0, int(attempts))
        self.provider_kind = str(provider_kind or "").strip().upper()
        self.model = str(model or "")
        self.safe_message = safe_error_message(safe_message)
        self.retryable = (
            default_retryable(category)
            if retryable is None
            else bool(retryable)
        )
        super().__init__(
            self.safe_message or self.error_code,
            self.as_error_plan(),
        )

    def as_error_plan(self) -> dict:
        """Return the bounded error contract projection."""

        return serialize_provider_call_error(self)


def serialize_provider_call_error(error: object) -> dict:
    """Project any provider exception onto the bounded error contract."""

    if isinstance(error, ProviderCallError):
        values = {
            "provider_kind": error.provider_kind,
            "error_category": error.error_category,
            "error_code": error.error_code,
            "status_code": error.status_code,
            "retryable": error.retryable,
            "attempts": error.attempts,
            "model": error.model,
            "safe_message": error.safe_message,
        }
    else:
        values = {
            "error_category": ERROR_UNKNOWN,
            "error_code": CODE_UNKNOWN,
            "safe_message": safe_error_message(
                type(error).__name__ if error is not None else "unknown"
            ),
        }
    plan = LLMProviderErrorPlan(**values)
    return llm_provider_error_plan_projection(plan)


class ProviderContextRejected(ProviderCallError):
    """Raised before a provider call when outbound context is unsafe."""

    def __init__(
        self,
        reason_codes: object = (),
        *,
        provider_kind: str = "",
        model: str = "",
    ):
        codes = [str(code) for code in reason_codes or () if str(code)]
        self.reason_codes = tuple(codes[:8])
        message = "outbound advisory context rejected"
        if codes:
            message += ": " + ",".join(self.reason_codes)
        super().__init__(
            ERROR_SAFETY_VALIDATION,
            CODE_UNSAFE_CONTEXT_REJECTED,
            retryable=False,
            attempts=0,
            provider_kind=provider_kind,
            model=model,
            safe_message=message,
        )


def missing_credentials_error(
    provider_kind: str = "", api_key_env: str = ""
) -> ProviderCallError:
    """Return the deterministic fail-closed configuration error."""

    name = str(api_key_env or "").strip()
    message = "provider credentials are not configured"
    if name:
        message = f"provider credentials are not configured ({name})"
    return ProviderCallError(
        ERROR_CONFIGURATION,
        CODE_CONFIG_MISSING_CREDENTIAL,
        retryable=False,
        attempts=0,
        provider_kind=provider_kind,
        safe_message=message,
    )


def missing_model_error(provider_kind: str = "") -> ProviderCallError:
    """Return the deterministic missing-model configuration error."""

    return ProviderCallError(
        ERROR_CONFIGURATION,
        CODE_CONFIG_MISSING_MODEL,
        retryable=False,
        attempts=0,
        provider_kind=provider_kind,
        safe_message="provider model is not configured",
    )


def unsupported_kind_error(provider_kind: str = "") -> ProviderCallError:
    """Return the deterministic unsupported-kind configuration error."""

    return ProviderCallError(
        ERROR_CONFIGURATION,
        CODE_CONFIG_UNSUPPORTED_KIND,
        retryable=False,
        attempts=0,
        provider_kind=provider_kind,
        safe_message=f"unsupported provider kind: {provider_kind}",
    )


__all__ = [
    "PROVIDER_ERRORS_RULE_VERSION",
    "RULE_VERSION",
    "ProviderCallError",
    "ProviderContextRejected",
    "serialize_provider_call_error",
    "missing_credentials_error",
    "missing_model_error",
    "unsupported_kind_error",
]
