"""Stage R51 advisory bridge (real provider into the R45 contract).

Connects the real provider layer to the existing R45 advisory pipeline
without weakening it:

    R45 advisory input / request
      -> explicit R51 provider selection (fail closed)
      -> ONE real provider call (bounded, retried, validated)
      -> R45 advisory validator + result assembly (export_llm_advisory)
      -> structured R51 envelope

Hard boundaries encoded here:

- The provider output is passed through the existing R45 advisory export
  and validator. Unsafe output is rejected with preserved diagnostics and
  never rewritten into acceptable content.
- One provider call per bridge invocation: the already-obtained response
  is replayed to the R45 assembler through a single-response adapter, so
  the R45 path is exercised exactly once without a second network call.
- Provider errors become structured infrastructure errors; they never
  become vulnerability findings and never trigger execution.
- No prompt, raw provider body, credential or authorization material is
  part of the returned envelope.
- The mock provider keeps working unchanged (inject it or select MOCK).
- No orchestrator: the bridge serves one advisory request and never
  dispatches specialists.
"""

from __future__ import annotations

import copy

from ai.knowledge.llm_advisory_export import export_llm_advisory
from ai.knowledge.llm_advisory_input import build_llm_advisory_input
from ai.knowledge.llm_advisory_request_builder import (
    build_llm_advisory_request,
)
from ai.knowledge.llm_advisory_validator import (
    VALIDATION_PASS,
    VALIDATION_REJECTED,
)
from ai.knowledge.llm_provider import AdvisoryProvider, AdvisoryProviderError
from ai.schemas.llm_provider import REAL_PROVIDER_KINDS
from ai.schemas.llm_provider_error import (
    CODE_UNSAFE_OUTPUT_REJECTED,
    ERROR_SAFETY_VALIDATION,
)
from ai.schemas.llm_provider_telemetry import (
    VALIDATION_NOT_RUN,
    VALIDATION_PASS as TELEMETRY_VALIDATION_PASS,
    VALIDATION_REJECTED as TELEMETRY_VALIDATION_REJECTED,
    sanitize_provider_telemetry,
)

from ai.providers.provider_errors import (
    ProviderCallError,
    serialize_provider_call_error,
)
from ai.providers.provider_registry import select_provider

R51_ADVISORY_BRIDGE_RULE_VERSION = "r51-bridge"
RULE_VERSION = R51_ADVISORY_BRIDGE_RULE_VERSION

BRIDGE_STATE_OK = "OK"
BRIDGE_STATE_REJECTED = "REJECTED"
BRIDGE_STATE_ERROR = "ERROR"

BRIDGE_STATES: tuple[str, ...] = (
    BRIDGE_STATE_OK,
    BRIDGE_STATE_REJECTED,
    BRIDGE_STATE_ERROR,
)

BRIDGE_KEYS: tuple[str, ...] = (
    "rule_version",
    "provider_kind",
    "provider_state",
    "advisory_result",
    "provider_error",
    "provider_telemetry",
    "content_deterministic",
    "research_only",
    "deterministic",
)

MAX_SAFE_MESSAGE_LEN = 200


class SingleResponseProvider(AdvisoryProvider):
    """Replays one already-obtained bounded response to the R45 assembler.

    This adapter performs no I/O of any kind; it exists so the single real
    provider response passes through the existing R45 validation and
    assembly path exactly once.
    """

    def __init__(self, provider_kind: str, response: object):
        self.provider_kind = str(provider_kind or "").strip().upper()
        self._response = response if isinstance(response, dict) else {}

    def complete(self, request: object = None) -> dict:
        if isinstance(request, dict):
            request_id = str(request.get("advisory_id") or "")
            response_id = str(self._response.get("advisory_id") or "")
            if request_id and response_id != request_id:
                raise AdvisoryProviderError(
                    "advisory identity mismatch on replay",
                    {"rule_version": R51_ADVISORY_BRIDGE_RULE_VERSION},
                )
            request_mode = str(request.get("advisory_mode") or "")
            response_mode = str(self._response.get("advisory_mode") or "")
            if request_mode and response_mode != request_mode:
                raise AdvisoryProviderError(
                    "advisory mode mismatch on replay",
                    {"rule_version": R51_ADVISORY_BRIDGE_RULE_VERSION},
                )
        return copy.deepcopy(self._response)


def _error_telemetry(
    provider_kind: str,
    model: str,
    error_category: str,
    *,
    external: bool,
    network_access: bool,
    credentials_used: bool,
    validation_state: str = VALIDATION_NOT_RUN,
) -> dict:
    return sanitize_provider_telemetry(
        {
            "provider_kind": provider_kind,
            "model": model,
            "success": False,
            "error_category": error_category,
            "attempt_count": 0,
            "retry_count": 0,
            "validation_state": validation_state,
            "external_provider": external,
            "network_access": network_access,
            "credentials_used": credentials_used,
            "content_deterministic": not external,
        }
    )


def export_real_llm_advisory(
    evaluation_result: object = None,
    collaboration_result: object = None,
    learning_signals: object = None,
    research_context: object = None,
    governance_state: object = None,
    safety_state: object = None,
    requested_mode: object = None,
    advisory_id: object = None,
    provider_kind: object = None,
    provider: object = None,
    transport: object = None,
    environ: object = None,
    model: object = None,
    base_url: object = None,
    api_key: object = None,
    timeout_seconds: object = None,
    max_retries: object = None,
    retry_backoff_seconds: object = None,
    max_tokens: object = None,
    max_response_bytes: object = None,
    sleep: object = None,
) -> dict:
    """Run one advisory request through an explicitly selected provider.

    Returns the structured R51 envelope. The R45 advisory result inside it
    is produced by the unmodified R45 export and validator.
    """

    explicit_kind = str(
        provider_kind if provider_kind is not None else ""
    ).strip().upper()
    if not explicit_kind and provider is not None:
        explicit_kind = str(
            getattr(provider, "provider_kind", "") or ""
        ).strip().upper()

    advisory_input = build_llm_advisory_input(
        evaluation_result=evaluation_result,
        collaboration_result=collaboration_result,
        learning_signals=learning_signals,
        research_context=research_context,
        governance_state=governance_state,
        safety_state=safety_state,
        advisory_id=advisory_id,
    )

    if provider is None:
        try:
            provider = select_provider(
                explicit_kind,
                model=model,
                base_url=base_url,
                api_key=api_key,
                transport=transport,
                environ=environ,
                sleep=sleep,
                timeout_seconds=timeout_seconds,
                max_retries=max_retries,
                retry_backoff_seconds=retry_backoff_seconds,
                max_tokens=max_tokens,
                max_response_bytes=max_response_bytes,
            )
        except ProviderCallError as exc:
            return {
                "rule_version": R51_ADVISORY_BRIDGE_RULE_VERSION,
                "provider_kind": explicit_kind,
                "provider_state": BRIDGE_STATE_ERROR,
                "advisory_result": None,
                "provider_error": exc.as_error_plan(),
                "provider_telemetry": _error_telemetry(
                    explicit_kind,
                    str(model or ""),
                    exc.error_category,
                    external=explicit_kind in REAL_PROVIDER_KINDS,
                    network_access=False,
                    credentials_used=False,
                ),
                "content_deterministic": False,
                "research_only": True,
                "deterministic": True,
            }

    resolved_kind = str(
        getattr(provider, "provider_kind", "") or explicit_kind
    ).strip().upper()

    request = build_llm_advisory_request(
        advisory_input,
        requested_mode=requested_mode,
        provider_kind=resolved_kind,
    )

    outcome = _call_provider(provider, request)
    if outcome["error"] is not None:
        telemetry = outcome["telemetry"]
        telemetry = sanitize_provider_telemetry(
            {**telemetry, "validation_state": VALIDATION_NOT_RUN}
        )
        return {
            "rule_version": R51_ADVISORY_BRIDGE_RULE_VERSION,
            "provider_kind": resolved_kind,
            "provider_state": BRIDGE_STATE_ERROR,
            "advisory_result": None,
            "provider_error": outcome["error"],
            "provider_telemetry": telemetry,
            "content_deterministic": telemetry["content_deterministic"],
            "research_only": True,
            "deterministic": True,
        }

    replay = SingleResponseProvider(resolved_kind, outcome["response"])
    advisory_result = export_llm_advisory(
        evaluation_result=evaluation_result,
        collaboration_result=collaboration_result,
        learning_signals=learning_signals,
        research_context=research_context,
        governance_state=governance_state,
        safety_state=safety_state,
        requested_mode=requested_mode,
        advisory_id=advisory_id,
        provider=replay,
        provider_kind=resolved_kind,
    )

    validation_state = str(
        advisory_result.get("validation_state") or ""
    ).strip().upper()
    if validation_state == VALIDATION_PASS:
        state = BRIDGE_STATE_OK
        error_plan = None
        telemetry_state = TELEMETRY_VALIDATION_PASS
    else:
        state = BRIDGE_STATE_REJECTED
        rejection = ProviderCallError(
            ERROR_SAFETY_VALIDATION,
            CODE_UNSAFE_OUTPUT_REJECTED,
            retryable=False,
            attempts=int(outcome["telemetry"].get("attempt_count") or 0),
            provider_kind=resolved_kind,
            model=str(outcome["telemetry"].get("model") or ""),
            safe_message=(
                "provider output was rejected by the R45 advisory validator"
            ),
        )
        error_plan = rejection.as_error_plan()
        telemetry_state = TELEMETRY_VALIDATION_REJECTED

    telemetry = sanitize_provider_telemetry(
        {
            **outcome["telemetry"],
            "provider_kind": resolved_kind,
            "advisory_id": request.get("advisory_id") or "",
            "advisory_mode": request.get("advisory_mode") or "",
            "validation_state": telemetry_state,
        }
    )
    return {
        "rule_version": R51_ADVISORY_BRIDGE_RULE_VERSION,
        "provider_kind": resolved_kind,
        "provider_state": state,
        "advisory_result": advisory_result,
        "provider_error": error_plan,
        "provider_telemetry": telemetry,
        "content_deterministic": telemetry["content_deterministic"],
        "research_only": True,
        "deterministic": True,
    }


def _call_provider(provider: object, request: object) -> dict:
    """Call the provider once, normalizing mock/real providers alike."""

    if hasattr(provider, "complete_with_status"):
        return provider.complete_with_status(request)  # type: ignore[attr-defined]

    try:
        response = provider.complete(request)  # type: ignore[attr-defined]
    except AdvisoryProviderError as exc:
        return {
            "response": None,
            "error": serialize_provider_call_error(exc),
            "telemetry": _error_telemetry(
                str(getattr(provider, "provider_kind", "") or ""),
                "",
                str(getattr(exc, "error_category", "") or "") or "UNKNOWN_ERROR",
                external=False,
                network_access=False,
                credentials_used=False,
            ),
        }
    except Exception as exc:  # defensive: never leak raw exceptions
        return {
            "response": None,
            "error": serialize_provider_call_error(exc),
            "telemetry": _error_telemetry(
                str(getattr(provider, "provider_kind", "") or ""),
                "",
                "UNKNOWN_ERROR",
                external=False,
                network_access=False,
                credentials_used=False,
            ),
        }
    return {
        "response": response,
        "error": None,
        "telemetry": sanitize_provider_telemetry(
            {
                "provider_kind": str(
                    getattr(provider, "provider_kind", "") or ""
                ),
                "success": True,
                "attempt_count": 1,
                "retry_count": 0,
                "external_provider": False,
                "network_access": False,
                "credentials_used": False,
                "content_deterministic": True,
            }
        ),
    }


__all__ = [
    "R51_ADVISORY_BRIDGE_RULE_VERSION",
    "RULE_VERSION",
    "BRIDGE_STATE_OK",
    "BRIDGE_STATE_REJECTED",
    "BRIDGE_STATE_ERROR",
    "BRIDGE_STATES",
    "BRIDGE_KEYS",
    "MAX_SAFE_MESSAGE_LEN",
    "SingleResponseProvider",
    "export_real_llm_advisory",
]
