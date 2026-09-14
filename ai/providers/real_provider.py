"""Stage R51 real advisory provider base adapter.

Implements the real provider flow behind the existing R45 advisory
provider interface:

    R45 advisory request
      -> R51 context allowlist (reject unsafe context)
      -> deterministic bounded prompt
      -> bounded HTTP transport (timeout, bounded retries, bounded size)
      -> strict JSON parse into the R45 response contract
      -> R45 advisory validator (outside this module)
      -> structured R51 result

Hard boundaries encoded here:

- Advisory only: the adapter produces bounded advisory response
  structures. It never confirms vulnerabilities, never executes anything,
  never generates payloads and never plans attacks.
- Fail closed: missing credentials, missing model or invalid
  configuration return a structured CONFIGURATION_ERROR without any
  provider call and without any fabricated response.
- Explicit provider selection: the adapter never falls back to another
  provider or to the mock.
- Bounded behavior: explicit timeout, bounded deterministic retries for
  transient failures only, bounded token budget and bounded response
  size.
- Secret hygiene: the credential is read from the environment (or an
  explicit in-memory argument), used only in the transport authorization
  header, and never returned, logged, serialized or included in errors
  and telemetry.
- Provider-specific objects never leak: only the R45 response contract
  and the R51 telemetry/error contracts cross the boundary.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from pydantic import ValidationError

from ai.knowledge.llm_provider import AdvisoryProvider
from ai.schemas.llm_provider import REAL_PROVIDER_LIMITATIONS
from ai.schemas.llm_provider_config import (
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_RETRIES,
    DEFAULT_MAX_TOKENS,
    DEFAULT_RETRY_BACKOFF_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    LLMRealProviderConfigPlan,
    llm_real_provider_config_plan_projection,
)
from ai.schemas.llm_provider_error import (
    CODE_CONFIG_INVALID_PARAMETER,
    CODE_CONNECTION_FAILED,
    CODE_INVALID_PROVIDER_RESPONSE,
    CODE_EMPTY_PROVIDER_RESPONSE,
    CODE_PROVIDER_HTTP_ERROR,
    CODE_PROVIDER_TRANSIENT_ERROR,
    CODE_RATE_LIMITED,
    CODE_REQUEST_TIMEOUT,
    CODE_TRANSPORT_ERROR,
    CODE_AUTH_INVALID_CREDENTIALS,
    CODE_AUTHZ_FORBIDDEN,
    ERROR_AUTHENTICATION,
    ERROR_AUTHORIZATION,
    ERROR_CONFIGURATION,
    ERROR_EMPTY_RESPONSE,
    ERROR_INVALID_RESPONSE,
    ERROR_NETWORK,
    ERROR_PROVIDER,
    ERROR_RATE_LIMIT,
    ERROR_TIMEOUT,
    TRANSIENT_HTTP_STATUSES,
)
from ai.schemas.llm_provider_telemetry import (
    LLMProviderTelemetryPlan,
    llm_provider_telemetry_plan_projection,
)

from ai.providers.context_allowlist import sanitize_provider_context
from ai.providers.http_transport import (
    DEFAULT_USER_AGENT,
    FAILURE_RESPONSE_TOO_LARGE,
    FAILURE_TIMEOUT,
    HttpRequestSpec,
    HttpTransport,
    TransportFailure,
    UrllibHttpTransport,
)
from ai.providers.prompt_builder import (
    build_provider_prompt,
    parse_advisory_content,
)
from ai.providers.provider_errors import (
    ProviderCallError,
    missing_credentials_error,
    missing_model_error,
)

REAL_PROVIDER_RULE_VERSION = "r51-provider"
RULE_VERSION = REAL_PROVIDER_RULE_VERSION

MAX_SAFE_MESSAGE_LEN = 200


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


class RealAdvisoryProvider(AdvisoryProvider):
    """Base class for real remote advisory providers (R51)."""

    provider_kind: str = ""
    default_base_url: str = ""
    default_api_key_env: str = ""
    default_model_env: str = ""
    default_base_url_env: str = ""

    def __init__(
        self,
        *,
        model: object = None,
        base_url: object = None,
        api_key: object = None,
        api_key_env: object = None,
        timeout_seconds: object = None,
        max_retries: object = None,
        retry_backoff_seconds: object = None,
        max_tokens: object = None,
        max_response_bytes: object = None,
        transport: HttpTransport | None = None,
        environ: object = None,
        sleep: object = None,
        config: object = None,
    ):
        environ_map = environ if environ is not None else os.environ
        self._environ = environ_map
        self._transport = transport
        self._sleep = sleep if sleep is not None else time.sleep

        provided = config if isinstance(config, dict) else {}

        def _pick(argument: object, config_key: str, env_key: str) -> object:
            if argument is not None:
                return argument
            if config_key in provided:
                return provided.get(config_key)
            if env_key:
                return environ_map.get(env_key)
            return None

        resolved_api_env = (
            str(
                api_key_env
                if api_key_env is not None
                else provided.get("api_key_env")
                or self.default_api_key_env
            ).strip()
        )
        resolved_base_url = _pick(
            base_url, "base_url", self.default_base_url_env
        ) or self.default_base_url
        resolved_model = _pick(model, "model", self.default_model_env)

        try:
            plan = LLMRealProviderConfigPlan(
                provider_kind=self.provider_kind,
                model=str(resolved_model or ""),
                base_url=str(resolved_base_url or ""),
                api_key_env=resolved_api_env,
                timeout_seconds=_pick(
                    timeout_seconds,
                    "timeout_seconds",
                    None,
                )
                if _pick(timeout_seconds, "timeout_seconds", None)
                is not None
                else DEFAULT_TIMEOUT_SECONDS,
                max_retries=_pick(max_retries, "max_retries", None)
                if _pick(max_retries, "max_retries", None) is not None
                else DEFAULT_MAX_RETRIES,
                retry_backoff_seconds=_pick(
                    retry_backoff_seconds, "retry_backoff_seconds", None
                )
                if _pick(
                    retry_backoff_seconds, "retry_backoff_seconds", None
                )
                is not None
                else DEFAULT_RETRY_BACKOFF_SECONDS,
                max_tokens=_pick(max_tokens, "max_tokens", None)
                if _pick(max_tokens, "max_tokens", None) is not None
                else DEFAULT_MAX_TOKENS,
                max_response_bytes=_pick(
                    max_response_bytes, "max_response_bytes", None
                )
                if _pick(max_response_bytes, "max_response_bytes", None)
                is not None
                else DEFAULT_MAX_RESPONSE_BYTES,
            )
        except (ValidationError, TypeError, ValueError) as exc:
            raise ProviderCallError(
                ERROR_CONFIGURATION,
                CODE_CONFIG_INVALID_PARAMETER,
                retryable=False,
                attempts=0,
                provider_kind=self.provider_kind,
                safe_message=(
                    "invalid provider configuration: "
                    f"{type(exc).__name__}"
                ),
            ) from None

        self.config = llm_real_provider_config_plan_projection(plan)
        self.model = plan.model
        self.base_url = plan.base_url.rstrip("/")
        self.api_key_env = plan.api_key_env
        self.timeout_seconds = plan.timeout_seconds
        self.max_retries = plan.max_retries
        self.retry_backoff_seconds = plan.retry_backoff_seconds
        self.max_tokens = plan.max_tokens
        self.max_response_bytes = plan.max_response_bytes

        resolved_key = (
            api_key
            if api_key is not None
            else environ_map.get(self.api_key_env, "")
        )
        self._api_key = str(resolved_key or "")
        self._credentials_configured = bool(self._api_key)

    # ------------------------------------------------------------------
    # Boundary description
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return (
            f"<{type(self).__name__} kind={self.provider_kind!r} "
            f"model={self.model!r} credentials_configured="
            f"{self._credentials_configured}>"
        )

    def describe(self) -> dict:
        """Return the deterministic provider boundary description."""

        return {
            "rule_version": REAL_PROVIDER_RULE_VERSION,
            "provider_kind": self.provider_kind,
            "supported": True,
            "network_access": True,
            "credentials_used": self._credentials_configured,
            "credentials_configured": self._credentials_configured,
            "external_provider": True,
            "content_deterministic": False,
            "deterministic": True,
            "research_only": True,
            "model_configured": bool(self.model),
            "base_url": self.base_url,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "max_tokens": self.max_tokens,
            "max_response_bytes": self.max_response_bytes,
            "limitations": list(REAL_PROVIDER_LIMITATIONS),
        }

    # ------------------------------------------------------------------
    # Safety validation remains authoritative
    # ------------------------------------------------------------------

    def validate_response(self, response: object, request: object) -> dict:
        """Run the R45 advisory validator over a normalized response."""

        from ai.knowledge.llm_advisory_validator import (
            validate_advisory_response,
        )

        return validate_advisory_response(response, request)

    # ------------------------------------------------------------------
    # Provider call
    # ------------------------------------------------------------------

    def complete(self, request: object = None) -> dict:
        outcome = self.complete_with_status(request)
        if outcome["error"] is not None:
            raise outcome["_exception"]
        return outcome["response"]

    def complete_with_status(self, request: object = None) -> dict:
        """Perform one bounded provider exchange with deterministic retries.

        Returns ``{"response": dict|None, "error": dict|None,
        "telemetry": dict, "_exception": ProviderCallError|None}``.
        The ``_exception`` entry is an internal carrier used by
        :meth:`complete`; consumers use the bounded ``error`` plan.
        """

        if not self._credentials_configured:
            error = missing_credentials_error(
                self.provider_kind, self.api_key_env
            )
            return self._outcome(error, attempts=0)
        if not self.model:
            error = missing_model_error(self.provider_kind)
            return self._outcome(error, attempts=0)

        try:
            context_bundle = sanitize_provider_context(request)
            prompt = build_provider_prompt(context_bundle)
        except ProviderCallError as exc:
            return self._outcome(exc, attempts=0)

        messages = prompt["messages"]
        last_error: ProviderCallError | None = None
        attempts = 0

        for attempt in range(1, self.max_retries + 2):
            attempts = attempt
            try:
                spec = self._request_spec(messages)
                response = self._transport_impl().send(spec)
            except TransportFailure as failure:
                last_error = self._map_transport_failure(failure, attempt)
            except Exception as exc:  # defensive: transport must fail bounded
                last_error = ProviderCallError(
                    ERROR_NETWORK,
                    CODE_TRANSPORT_ERROR,
                    retryable=False,
                    attempts=attempt,
                    provider_kind=self.provider_kind,
                    model=self.model,
                    safe_message=(
                        "provider transport failure: "
                        f"{type(exc).__name__}"
                    ),
                )
            else:
                if response.status_code != 200:
                    last_error = self._map_status(
                        response.status_code, attempt
                    )
                else:
                    try:
                        content = self._extract_raw_content(
                            response.body_text
                        )
                        normalized = parse_advisory_content(
                            content, request, self.provider_kind
                        )
                    except ProviderCallError as exc:
                        last_error = self._attach_attempts(exc, attempt)
                    else:
                        telemetry = self._telemetry(
                            attempts=attempt,
                            success=True,
                            response_chars=len(content),
                        )
                        return {
                            "response": normalized,
                            "error": None,
                            "telemetry": telemetry,
                            "_exception": None,
                        }

            if last_error is None or not last_error.retryable:
                break
            if attempt > self.max_retries:
                break
            if self.retry_backoff_seconds:
                self._sleep(self.retry_backoff_seconds)

        assert last_error is not None
        error = self._attach_attempts(last_error, attempts)
        return self._outcome(error, attempts=attempts)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _transport_impl(self) -> HttpTransport:
        if self._transport is not None:
            return self._transport
        self._transport = UrllibHttpTransport()
        return self._transport

    def _endpoint_url(self) -> str:
        return self.base_url + "/chat/completions"

    def _request_spec(self, messages: object) -> HttpRequestSpec:
        body = _canonical_json(
            {
                "model": self.model,
                "messages": messages,
                "max_tokens": self.max_tokens,
                "temperature": 0,
            }
        )
        headers = (
            ("Content-Type", "application/json"),
            ("Accept", "application/json"),
            ("User-Agent", DEFAULT_USER_AGENT),
            ("Authorization", "Bearer " + self._api_key),
        )
        return HttpRequestSpec(
            method="POST",
            url=self._endpoint_url(),
            headers=headers,
            body=body.encode("utf-8"),
            timeout_seconds=float(self.timeout_seconds),
            max_response_bytes=int(self.max_response_bytes),
        )

    def _extract_raw_content(self, body_text: object) -> str:
        if not isinstance(body_text, str) or not body_text.strip():
            raise ProviderCallError(
                ERROR_EMPTY_RESPONSE,
                CODE_EMPTY_PROVIDER_RESPONSE,
                retryable=False,
                attempts=0,
                provider_kind=self.provider_kind,
                model=self.model,
                safe_message="provider returned an empty body",
            )
        try:
            payload = json.loads(body_text)
        except (ValueError, TypeError):
            raise ProviderCallError(
                ERROR_INVALID_RESPONSE,
                CODE_INVALID_PROVIDER_RESPONSE,
                retryable=False,
                attempts=0,
                provider_kind=self.provider_kind,
                model=self.model,
                safe_message="provider body is not valid JSON",
            )
        if not isinstance(payload, dict):
            raise ProviderCallError(
                ERROR_INVALID_RESPONSE,
                CODE_INVALID_PROVIDER_RESPONSE,
                retryable=False,
                attempts=0,
                provider_kind=self.provider_kind,
                model=self.model,
                safe_message="provider payload is not an object",
            )
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderCallError(
                ERROR_INVALID_RESPONSE,
                CODE_INVALID_PROVIDER_RESPONSE,
                retryable=False,
                attempts=0,
                provider_kind=self.provider_kind,
                model=self.model,
                safe_message="provider payload has no choices",
            )
        first = choices[0]
        message = first.get("message") if isinstance(first, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if content is None or content == "":
            raise ProviderCallError(
                ERROR_EMPTY_RESPONSE,
                CODE_EMPTY_PROVIDER_RESPONSE,
                retryable=False,
                attempts=0,
                provider_kind=self.provider_kind,
                model=self.model,
                safe_message="provider message content is empty",
            )
        if not isinstance(content, str):
            raise ProviderCallError(
                ERROR_INVALID_RESPONSE,
                CODE_INVALID_PROVIDER_RESPONSE,
                retryable=False,
                attempts=0,
                provider_kind=self.provider_kind,
                model=self.model,
                safe_message="provider message content is not text",
            )
        return content

    def _map_status(self, status: int, attempts: int) -> ProviderCallError:
        common: dict[str, Any] = {
            "status_code": status,
            "attempts": attempts,
            "provider_kind": self.provider_kind,
            "model": self.model,
        }
        if status == 401:
            return ProviderCallError(
                ERROR_AUTHENTICATION,
                CODE_AUTH_INVALID_CREDENTIALS,
                retryable=False,
                safe_message="provider rejected the credentials",
                **common,
            )
        if status == 403:
            return ProviderCallError(
                ERROR_AUTHORIZATION,
                CODE_AUTHZ_FORBIDDEN,
                retryable=False,
                safe_message="provider refused the request",
                **common,
            )
        if status == 408:
            return ProviderCallError(
                ERROR_TIMEOUT,
                CODE_REQUEST_TIMEOUT,
                retryable=True,
                safe_message="provider request timed out",
                **common,
            )
        if status == 429:
            return ProviderCallError(
                ERROR_RATE_LIMIT,
                CODE_RATE_LIMITED,
                retryable=True,
                safe_message="provider rate limit reached",
                **common,
            )
        if 500 <= status <= 599:
            if status in TRANSIENT_HTTP_STATUSES:
                return ProviderCallError(
                    ERROR_PROVIDER,
                    CODE_PROVIDER_TRANSIENT_ERROR,
                    retryable=True,
                    safe_message="provider transient server error",
                    **common,
                )
            return ProviderCallError(
                ERROR_PROVIDER,
                CODE_PROVIDER_HTTP_ERROR,
                retryable=False,
                safe_message="provider server error",
                **common,
            )
        return ProviderCallError(
            ERROR_PROVIDER,
            CODE_PROVIDER_HTTP_ERROR,
            retryable=False,
            safe_message="provider rejected the request",
            **common,
        )

    def _map_transport_failure(
        self, failure: TransportFailure, attempts: int
    ) -> ProviderCallError:
        common: dict[str, Any] = {
            "attempts": attempts,
            "provider_kind": self.provider_kind,
            "model": self.model,
        }
        if failure.kind == FAILURE_TIMEOUT:
            return ProviderCallError(
                ERROR_TIMEOUT,
                CODE_REQUEST_TIMEOUT,
                retryable=True,
                safe_message="provider request timed out",
                **common,
            )
        if failure.kind == FAILURE_RESPONSE_TOO_LARGE:
            return ProviderCallError(
                ERROR_INVALID_RESPONSE,
                CODE_INVALID_PROVIDER_RESPONSE,
                retryable=False,
                safe_message="provider response exceeds the bounded size",
                **common,
            )
        return ProviderCallError(
            ERROR_NETWORK,
            CODE_CONNECTION_FAILED,
            retryable=True,
            safe_message="provider connection failed",
            **common,
        )

    def _attach_attempts(
        self, error: ProviderCallError, attempts: int
    ) -> ProviderCallError:
        return ProviderCallError(
            error.error_category,
            error.error_code,
            status_code=error.status_code,
            retryable=error.retryable,
            attempts=attempts,
            provider_kind=self.provider_kind,
            model=self.model,
            safe_message=error.safe_message,
        )

    def _telemetry(
        self,
        *,
        attempts: int,
        success: bool,
        response_chars: int,
        error_category: str = "",
        advisory_id: str = "",
        advisory_mode: str = "",
    ) -> dict:
        plan = LLMProviderTelemetryPlan(
            provider_kind=self.provider_kind,
            model=self.model,
            advisory_id=str(advisory_id or "")[:80],
            advisory_mode=str(advisory_mode or "")[:40],
            attempt_count=attempts,
            retry_count=max(0, attempts - 1),
            success=success,
            error_category=error_category,
            response_chars=response_chars,
            external_provider=True,
            network_access=True,
            credentials_used=self._credentials_configured,
            content_deterministic=False,
        )
        return llm_provider_telemetry_plan_projection(plan)

    def _outcome(
        self, error: ProviderCallError, *, attempts: int
    ) -> dict:
        enriched = self._attach_attempts(error, attempts)
        return {
            "response": None,
            "error": enriched.as_error_plan(),
            "telemetry": self._telemetry(
                attempts=attempts,
                success=False,
                response_chars=0,
                error_category=enriched.error_category,
            ),
            "_exception": enriched,
        }


__all__ = [
    "REAL_PROVIDER_RULE_VERSION",
    "RULE_VERSION",
    "MAX_SAFE_MESSAGE_LEN",
    "RealAdvisoryProvider",
]
