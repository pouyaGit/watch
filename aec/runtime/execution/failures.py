"""EPIC7 Part 13: failure handling — every failure becomes an explicit
runtime state. No silent failures."""

from __future__ import annotations

#: Exactly 14 documented failure kinds (EPIC7 §13), each mapped to a state.
FAILURE_KIND_TO_STATE = {
    "DNS_FAILURE": "FAILED",
    "CONNECTION_TIMEOUT": "TIMED_OUT",
    "TLS_FAILURE": "FAILED",
    "HTTP_TIMEOUT": "TIMED_OUT",
    "RESPONSE_TOO_LARGE": "BLOCKED",
    "REDIRECT_OUT_OF_SCOPE": "REFUSED",
    "AUTHORIZATION_EXPIRY": "BLOCKED",
    "SCOPE_MISMATCH": "REFUSED",
    "POLICY_MISMATCH": "REFUSED",
    "DUPLICATE_REQUEST": "BLOCKED",
    "RUNTIME_SHUTDOWN": "FAILED",
    "PARTIAL_EVIDENCE": "FAILED",
    "REDACTION_FAILURE": "FAILED",
    "INVALID_TRANSITION": "FAILED",
}

FAILURE_STATES = frozenset({"REFUSED", "BLOCKED", "TIMED_OUT", "FAILED"})


def failure_state(kind: str) -> str:
    """Map a failure kind to its explicit runtime state; unknown kinds
    fail closed to FAILED rather than being silently ignored."""
    return FAILURE_KIND_TO_STATE.get(kind, "FAILED")


__all__ = ["FAILURE_KIND_TO_STATE", "FAILURE_STATES", "failure_state"]