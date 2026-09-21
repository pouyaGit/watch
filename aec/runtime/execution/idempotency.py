"""EPIC7 Part 12: idempotency and explicit retry classification.

Observation execution is idempotent: the same request_id +
authorization_reference + target_id + observation_type never executes
twice. Retries are never automatic — they are explicit, classified acts
that respect the policy retry budget.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from aec.runtime.execution.failures import failure_state

RETRYABLE_KINDS = frozenset({
    "TIMEOUT", "CONNECTION_TIMEOUT", "DNS_FAILURE", "HTTP_TIMEOUT",
})

_TERMINAL_KINDS = frozenset({
    "SCOPE_MISMATCH", "POLICY_MISMATCH", "REDIRECT_OUT_OF_SCOPE",
    "AUTHORIZATION_DENIED", "REDACTION_FAILURE", "AUTHORIZATION_EXPIRY",
    "DUPLICATE_REQUEST",
})


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      default=str)


def execution_key(request: Mapping[str, Any]) -> str:
    """Idempotency key: request + authorization + target + type."""
    basis = _canonical({
        "request_id": request.get("request_id"),
        "authorization_reference": request.get("authorization_reference"),
        "target_id": request.get("target_id"),
        "observation_type": request.get("observation_type"),
    })
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return "exec-" + digest[:20]


def classify_retry(kind: str) -> str:
    """RETRYABLE or TERMINAL. Unknown kinds are TERMINAL (fail closed)."""
    if kind in RETRYABLE_KINDS:
        return "RETRYABLE"
    return "TERMINAL"


def retry_allowed(guard: "IdempotencyGuard", kind: str,
                  attempts: int, retry_limit: int) -> bool:
    """An explicit retry is allowed only when classified RETRYABLE and
    the budget has room. Never automatic; never for unsafe kinds."""
    if classify_retry(kind) != "RETRYABLE":
        return False
    if attempts >= retry_limit:
        return False
    return True


class IdempotencyGuard:
    """Remembers executed observation keys; refuses duplicates."""

    def __init__(self) -> None:
        self._executed: set[str] = set()

    def is_duplicate(self, request: Mapping[str, Any]) -> bool:
        return execution_key(request) in self._executed

    def record(self, request: Mapping[str, Any]) -> str:
        key = execution_key(request)
        self._executed.add(key)
        return key

    def snapshot(self) -> dict[str, int]:
        return {"count": len(self._executed)}

    def executed_keys(self) -> set[str]:
        return set(self._executed)

    def evict(self, request: Mapping[str, Any]) -> bool:
        """Remove one executed observation key (cancellation/cleanup).

        Explicit and audit-visible, never implicit: a caller must name the
        request whose dedup slot is released."""
        key = execution_key(request)
        if key not in self._executed:
            return False
        self._executed.discard(key)
        return True


__all__ = [
    "IdempotencyGuard", "RETRYABLE_KINDS", "classify_retry",
    "execution_key", "retry_allowed",
]