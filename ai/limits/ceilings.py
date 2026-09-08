"""Immutable resource-ceiling contract (Phase 5H-core).

Global ceilings are frozen here. Operator configuration may ONLY
tighten: any configured value above the ceiling raises
``LIMIT_EXCEEDED``; any unknown, unbounded (``None``), or
non-numeric value raises ``LIMIT_UNKNOWN``. Both fail closed at
boot — no executor starts.

This module provides deterministic enforcement helpers and tests
only. It is NOT integrated into live executors (5E–5G work).
"""

from __future__ import annotations

from ai.schemas import evidence as ev

__all__ = [
    "CEILINGS",
    "check_limit",
    "validate_config",
]

_KIB = 1024
_MIB = 1024 * 1024

# Dimensions whose frozen ceiling is legitimately zero (deny by
# default). Zero is a valid configured value for these dimensions
# only; negatives remain rejected and any positive value raises
# LIMIT_EXCEEDED against the zero ceiling.
_ZERO_ALLOWED_DIMENSIONS = frozenset(
    {"nuclei_retries", "browser_popup_events"}
)

#: Frozen immutable ceilings: dimension -> maximum permitted value.
#: Units are documented per dimension; all values are integers.
CEILINGS: dict[str, int] = {
    # wall times (seconds)
    "http_wall_seconds": 60,
    "nuclei_wall_seconds": 120,
    "browser_wall_seconds": 15,
    "connect_timeout_seconds": 10,
    "read_timeout_seconds": 10,
    "chunk_stall_timeout_seconds": 10,
    # body sizes (bytes)
    "request_body_bytes": 16 * _KIB,
    "response_transport_bytes": 512 * _KIB,
    "response_evidence_sample_bytes": 8 * _KIB,
    "decompressed_bytes": 2 * _MIB,
    # ratio (integer multiplier)
    "compression_ratio": 10,
    # counts
    "redirect_hops": 5,
    "requests_per_execution": 7,
    "dns_answers": 8,
    "browser_pages": 1,
    "browser_contexts": 1,
    "nuclei_concurrency": 1,
    "nuclei_rate_per_second": 5,
    "nuclei_retries": 0,
    # capture / storage (bytes, seconds)
    "nuclei_output_bytes": 1 * _MIB,
    "temp_storage_bytes": 16 * _MIB,
    "subprocess_memory_bytes": 512 * _MIB,
    "subprocess_cpu_seconds": 60,
    "pending_authorizations": 1000,
    # browser/XSS observation bounds (5H-centralized 5G dimensions;
    # single source of truth — 5G BROWSER_EVENT_BOUNDS is a
    # read-through alias of these keys, never authoritative).
    # Ceilings are policy, not evidence-hash content.
    "browser_dialog_events": 8,
    "browser_frame_events": 4,
    "browser_popup_events": 0,
    "browser_console_entries": 32,
    "browser_oracle_events": 16,
    "browser_dom_observation_bytes": 8 * _KIB,
    "browser_storage_keys": 16,
}


def check_limit(dimension: str, value: object) -> int:
    """Validate one configured value against its immutable ceiling.

    Returns the (tightened) value. Raises ``LIMIT_UNKNOWN`` for
    unknown dimensions or unknown/unbounded/non-numeric values;
    raises ``LIMIT_EXCEEDED`` for values above the ceiling.
    """
    ceiling = CEILINGS.get(dimension)
    if ceiling is None:
        raise ev.EvidenceError(
            "LIMIT_UNKNOWN", f"unknown ceiling dimension: {dimension!r}"
        )
    if value is None or isinstance(value, bool) or not isinstance(
        value, int
    ):
        raise ev.EvidenceError(
            "LIMIT_UNKNOWN", f"unbounded dimension: {dimension!r}"
        )
    if value <= 0 and dimension not in _ZERO_ALLOWED_DIMENSIONS:
        raise ev.EvidenceError(
            "LIMIT_UNKNOWN", f"non-positive dimension: {dimension!r}"
        )
    if value < 0:
        raise ev.EvidenceError(
            "LIMIT_UNKNOWN", f"negative dimension: {dimension!r}"
        )
    if value > ceiling:
        raise ev.EvidenceError(
            "LIMIT_EXCEEDED",
            f"configured {dimension} above immutable ceiling",
        )
    return value


def validate_config(config: dict[str, int]) -> dict[str, int]:
    """Boot assertion: every configured value must tighten, never loosen.

    Unknown keys raise ``LIMIT_UNKNOWN`` (fail closed — an unbounded
    dimension refuses to start). Returns the validated mapping.
    """
    if not isinstance(config, dict):
        raise TypeError(
            "validate_config accepts only a mapping, "
            f"not {type(config).__name__}"
        )
    validated: dict[str, int] = {}
    for dimension, value in config.items():
        validated[dimension] = check_limit(dimension, value)
    return validated
