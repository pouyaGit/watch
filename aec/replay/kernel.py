"""Replay kernel: serialize/validate/re-run deterministically."""

from __future__ import annotations

import json
from typing import Any, Callable

from aec.replay.identity import ORIGIN_MODES, SOURCE_MODES

_REQUIRED_RUN_KEYS = frozenset({
    "run_id", "source_mode", "jobs", "evidence", "failures",
    "review_records", "context"})


def serialize_run(run: Any) -> str:
    """Stable JSON for a run (sorted keys, compact separators)."""
    return json.dumps(run.to_dict(), sort_keys=True, separators=(",", ":"),
                      default=str)


def validate(document: Any) -> None:
    """Refuse corrupted or mode-swapped run documents."""
    if not isinstance(document, dict):
        raise ValueError("replay input must be a mapping")
    missing = _REQUIRED_RUN_KEYS - set(document)
    if missing:
        raise ValueError(f"corrupted replay input: missing {sorted(missing)}")
    mode = document.get("source_mode")
    if mode not in SOURCE_MODES:
        raise ValueError(f"corrupted replay input: source_mode {mode!r}")
    context = document.get("context")
    if not isinstance(context, dict):
        raise ValueError("corrupted replay input: context missing")
    origin = context.get("origin")
    derived = ORIGIN_MODES.get(origin)
    if derived is None:
        raise ValueError(f"corrupted replay input: origin {origin!r}")
    if mode != derived:
        raise ValueError(
            f"source-mode mismatch: document {mode!r} vs origin {derived!r}")
    if not isinstance(document.get("jobs"), (list, tuple)):
        raise ValueError("corrupted replay input: jobs must be a sequence")
    if not isinstance(document.get("failures"), (list, tuple)):
        raise ValueError("corrupted replay input: failures must be a sequence")


def replay(original: Any, run_research: Callable[..., Any]) -> Any:
    """Re-run a captured run from its context; require byte-identical output."""
    if run_research is None or not callable(run_research):
        raise ValueError("replay requires the run function")
    document = original.to_dict() if hasattr(original, "to_dict") \
        else original
    validate(document)
    context = document["context"]
    rebuilt = run_research(
        list(context.get("records", [])),
        origin=context.get("origin", "fixture"),
        authz=dict(context.get("authz") or {}),
        policy_version=context.get("policy_version", "v1"),
    )
    if serialize_run(rebuilt) != serialize_run(original):
        raise ValueError("replay diverged from original run")
    return rebuilt


__all__ = ["replay", "serialize_run", "validate"]