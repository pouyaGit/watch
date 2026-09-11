"""Stage R24.11 — deterministic LLM failure classification + safe failover.

This module hardens the R24 research LLM path against intermittent free-model
failures (e.g. ``OpenRouter response has no choices``) **without** weakening any
R24.6 safety rule or the shared call budget.

It provides:

- a closed, deterministic failure vocabulary
  (:data:`LLM_SUCCESS` … :data:`LLM_AUTH_CONFIG_ERROR`);
- :func:`classify_llm_error` — maps a provider exception to a kind from the
  message shape only (no network, no key access);
- :func:`sanitize_llm_error` — bounded, key-free error text;
- :func:`call_llm` — one fail-soft provider attempt returning an
  :class:`LLMOutcome` (never raises);
- fallback/retry eligibility predicates.

The module performs no network calls and never logs secrets, Authorization
headers or API keys. Call-budget enforcement (primary + fallback + retries all
consume the same budget) lives in :mod:`ai.research_agent.llm_loop`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "LLM_SUCCESS",
    "LLM_EMPTY_CHOICES",
    "LLM_MALFORMED_RESPONSE",
    "LLM_TIMEOUT",
    "LLM_HTTP_ERROR",
    "LLM_RATE_LIMIT",
    "LLM_AUTH_CONFIG_ERROR",
    "LLM_UNKNOWN_ERROR",
    "LLM_FAILURE_KINDS",
    "LLMOutcome",
    "sanitize_llm_error",
    "classify_llm_error",
    "classify_llm_exception",
    "is_fallback_eligible",
    "is_retry_eligible",
    "call_llm",
]

LLM_SUCCESS = "SUCCESS"
LLM_EMPTY_CHOICES = "EMPTY_CHOICES"
LLM_MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
LLM_TIMEOUT = "TIMEOUT"
LLM_HTTP_ERROR = "HTTP_ERROR"
LLM_RATE_LIMIT = "RATE_LIMIT"
LLM_AUTH_CONFIG_ERROR = "AUTH_CONFIG_ERROR"
LLM_UNKNOWN_ERROR = "UNKNOWN_ERROR"

LLM_FAILURE_KINDS = (
    LLM_EMPTY_CHOICES,
    LLM_MALFORMED_RESPONSE,
    LLM_TIMEOUT,
    LLM_HTTP_ERROR,
    LLM_RATE_LIMIT,
    LLM_AUTH_CONFIG_ERROR,
    LLM_UNKNOWN_ERROR,
)

_SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_\-]{6,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(authorization|x-api-key|api[_-]?key)\s*[:=]\s*\S+"),
)


@dataclass(frozen=True)
class LLMOutcome:
    """Result of a single LLM provider attempt (never raises)."""

    kind: str
    content: str = ""
    error: str = ""
    model: str | None = None


def sanitize_llm_error(exc: BaseException | str) -> str:
    """Bounded, single-line, key-free error text."""
    text = str(exc or "")
    if not text:
        return ""
    text = text.replace("\n", " ").replace("\r", " ")
    text = " ".join(text.split())
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text[:200]


def classify_llm_error(exc: BaseException | str) -> str:
    """Deterministically classify a provider failure from its message shape."""
    message = str(exc or "")
    if not message:
        return LLM_UNKNOWN_ERROR
    lowered = message.lower()

    if (
        "is not configured" in lowered
        or "no api key" in lowered
        or ("api key" in lowered and "not" in lowered)
        or "unauthorized" in lowered
    ):
        return LLM_AUTH_CONFIG_ERROR
    if "http 401" in lowered or "http 403" in lowered:
        return LLM_AUTH_CONFIG_ERROR
    if "http 429" in lowered or "rate limit" in lowered or "too many requests" in lowered:
        return LLM_RATE_LIMIT
    if "timeout" in lowered or "timed out" in lowered:
        return LLM_TIMEOUT
    if "no choices" in lowered or "no message content" in lowered:
        return LLM_EMPTY_CHOICES
    if "content is not a string" in lowered or "invalid json" in lowered or "not json" in lowered:
        return LLM_MALFORMED_RESPONSE
    if "http 4" in lowered or "http 5" in lowered or "http " in lowered:
        return LLM_HTTP_ERROR
    if "json" in lowered and ("decode" in lowered or "parse" in lowered):
        return LLM_MALFORMED_RESPONSE
    return LLM_UNKNOWN_ERROR


# Backwards-friendly alias.
def classify_llm_exception(exc: BaseException | str) -> str:
    return classify_llm_error(exc)


def is_fallback_eligible(kind: str) -> bool:
    """Fallback may run for transient/model failures, never for auth/config."""
    return kind in (
        LLM_EMPTY_CHOICES,
        LLM_MALFORMED_RESPONSE,
        LLM_TIMEOUT,
        LLM_HTTP_ERROR,
        LLM_RATE_LIMIT,
        LLM_UNKNOWN_ERROR,
    )


def is_retry_eligible(kind: str) -> bool:
    """Retry eligibility (the caller still enforces budget/deadline)."""
    return is_fallback_eligible(kind)


def call_llm(provider: Any, prompt: str) -> LLMOutcome:
    """One fail-soft provider attempt; returns an :class:`LLMOutcome`.

    Uses ``complete()`` when available (to capture the provider's model id),
    otherwise ``generate()``. Never raises and never leaks a secret.
    """
    if provider is None:
        return LLMOutcome(kind=LLM_AUTH_CONFIG_ERROR, error="no LLM provider configured")

    model = getattr(provider, "model", None)
    complete = getattr(provider, "complete", None)
    try:
        if callable(complete):
            result = complete(prompt)
            content = getattr(result, "content", result)
            model = getattr(result, "model", None) or model
        else:
            content = provider.generate(prompt)
    except Exception as exc:  # fail-soft: never propagate
        return LLMOutcome(
            kind=classify_llm_error(exc),
            error=sanitize_llm_error(exc),
            model=model,
        )

    if not isinstance(content, str):
        return LLMOutcome(
            kind=LLM_MALFORMED_RESPONSE,
            error=f"provider returned non-string content: {type(content).__name__}",
            model=model,
        )
    if not content.strip():
        return LLMOutcome(kind=LLM_EMPTY_CHOICES, error="empty model response", model=model)
    return LLMOutcome(kind=LLM_SUCCESS, content=content, model=model)
