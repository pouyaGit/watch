"""Deterministic observation-result helpers (EPIC 6 Part 4)."""

from __future__ import annotations

from typing import Any, Mapping


def build_result(request_id: str, observation_id: str,
                 observed_fields: list[str],
                 missing_fields: list[str] | None = None,
                 tick: int = 0,
                 source: str = "fixture-observer") -> dict[str, Any]:
    """Build a well-formed observation result mapping for tests/fixtures."""
    return {
        "observation_id": observation_id,
        "request_id": request_id,
        "observed_fields": list(observed_fields),
        "missing_fields": list(missing_fields or []),
        "tick": tick,
        "source": source,
    }


def is_wellformed(result: Mapping[str, Any]) -> bool:
    """Structural check shared by callers before ingestion."""
    observed = result.get("observed_fields")
    return (
        isinstance(result.get("observation_id"), str)
        and bool(result.get("observation_id"))
        and isinstance(result.get("request_id"), str)
        and isinstance(observed, list) and bool(observed)
    )


__all__ = ["build_result", "is_wellformed"]
