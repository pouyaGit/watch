"""EPIC13 §10 — acquisition bounds.

Every bound here is a read-through of the platform's frozen ceilings
(``ai.limits.ceilings.CEILINGS``) or strictly tighter than them.  The
acquisition layer never invents a budget larger than the platform already
allows, and a bound it cannot justify against a ceiling is declared as an
acquisition-local policy value with the reason recorded.

Fail-closed: an unknown dimension, a non-numeric value or a value above the
platform ceiling is refused rather than clamped silently.
"""
from __future__ import annotations

from typing import Any, Mapping

ACQUISITION_RULE_VERSION = "epic13-acquisition-limits-1"

try:  # the platform's immutable ceilings (policy, not evidence)
    from ai.limits import ceilings as _ceilings

    _CEILINGS: dict[str, int] = dict(getattr(_ceilings, "CEILINGS", {}) or {})
except Exception:  # noqa: BLE001 - absent ceilings must not become unbounded
    _CEILINGS = {}

#: acquisition dimension -> the platform ceiling dimension it may not exceed.
CEILING_FOR: dict[str, str] = {
    "max_response_bytes": "response_evidence_sample_bytes",
    "max_transport_bytes": "response_transport_bytes",
    "max_redirects": "redirect_hops",
    "max_requests": "requests_per_execution",
    "connect_timeout_seconds": "connect_timeout_seconds",
    "read_timeout_seconds": "read_timeout_seconds",
    "max_wall_seconds": "http_wall_seconds",
}

#: dimension -> default.  Deliberately tight: acquisition is evidence
#: gathering, not enumeration (§27).
DEFAULT_LIMITS: dict[str, int] = {
    "max_actions": 3,
    "max_requests": 3,
    "max_requests_per_parameter": 1,
    "max_response_bytes": 8 * 1024,
    "max_transport_bytes": 64 * 1024,
    "max_redirects": 0,
    "max_retries": 0,
    "connect_timeout_seconds": 10,
    "read_timeout_seconds": 10,
    "max_wall_seconds": 60,
    "max_parameters": 8,
    "max_occurrences_recorded": 8,
    "max_context_sample_bytes": 400,
    "max_marker_length": 64,
}

#: dimensions whose limit of 0 means "not available in this runtime".
CAPABILITY_DIMENSIONS: frozenset[str] = frozenset(
    {"max_redirects", "max_retries"})


class LimitError(ValueError):
    """A bound was unknown, malformed, or above the platform ceiling."""


def ceiling_for(dimension: str) -> int | None:
    """The platform ceiling this dimension must respect, if one is declared."""
    name = CEILING_FOR.get(str(dimension))
    if not name:
        return None
    value = _CEILINGS.get(name)
    return int(value) if isinstance(value, int) else None


def check(dimension: str, value: Any) -> int:
    """Validate one bound.  Returns the integer value; never clamps silently."""
    key = str(dimension or "")
    if key not in DEFAULT_LIMITS:
        raise LimitError(f"unknown acquisition limit: {key!r}")
    if isinstance(value, bool) or not isinstance(value, int):
        raise LimitError(f"acquisition limit {key} must be an integer")
    if value < 0:
        raise LimitError(f"acquisition limit {key} must not be negative")
    ceiling = ceiling_for(key)
    if ceiling is not None and value > ceiling:
        raise LimitError(
            f"acquisition limit {key}={value} exceeds the platform ceiling "
            f"({CEILING_FOR[key]}={ceiling})")
    return value


def limits_for(overrides: Mapping[str, Any] | None = None) -> dict[str, int]:
    """The effective acquisition limits (defaults tightened by overrides)."""
    out = dict(DEFAULT_LIMITS)
    for key, value in dict(overrides or {}).items():
        if key not in DEFAULT_LIMITS:
            raise LimitError(f"unknown acquisition limit: {key!r}")
        checked = check(key, value)
        # tightening only: an override may never widen a default either.
        if checked > DEFAULT_LIMITS[key]:
            raise LimitError(
                f"acquisition limit {key}={checked} widens the default "
                f"({DEFAULT_LIMITS[key]})")
        out[key] = checked
    return out


def limits_document() -> dict[str, Any]:
    """The bound set with its provenance, for the report and the docs."""
    return {
        "rule_version": ACQUISITION_RULE_VERSION,
        "defaults": dict(DEFAULT_LIMITS),
        "ceilings": {k: ceiling_for(k) for k in DEFAULT_LIMITS},
        "ceiling_dimensions": dict(CEILING_FOR),
        "platform_ceilings_available": bool(_CEILINGS),
    }


def is_capability_dimension(dimension: str) -> bool:
    """True when a limit of 0 means 'not available', not 'exhausted'."""
    return str(dimension) in CAPABILITY_DIMENSIONS


__all__ = [
    "ACQUISITION_RULE_VERSION", "CAPABILITY_DIMENSIONS", "CEILING_FOR",
    "DEFAULT_LIMITS", "LimitError", "ceiling_for", "check",
    "is_capability_dimension", "limits_document", "limits_for",
]
