"""Replay identity: content hash over the full deterministic input set."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

SOURCE_MODES = frozenset({"REAL_WATCH_DATA", "OFFLINE_FIXTURE"})

ORIGIN_MODES = {
    "watch": "REAL_WATCH_DATA",
    "fixture": "OFFLINE_FIXTURE",
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      default=str)


def identity_for(records: Sequence[Any], origin: str,
                 authz: Mapping[str, Any], policy_version: str) -> str:
    """Deterministic 64-hex identity for a replayable input set."""
    if origin not in ORIGIN_MODES:
        raise ValueError(f"unknown origin: {origin!r}")
    basis = _canonical({
        "records": list(records),
        "origin": origin,
        "authz": dict(authz),
        "policy_version": policy_version,
    })
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def document(records: Sequence[Any], origin: str,
             authz: Mapping[str, Any], policy_version: str) -> dict[str, str]:
    """Identity plus source-mode label, for run records and reports."""
    if origin not in ORIGIN_MODES:
        raise ValueError(f"unknown origin: {origin!r}")
    return {
        "source_mode": ORIGIN_MODES[origin],
        "replay_identity": identity_for(
            records, origin, authz, policy_version),
    }


__all__ = ["ORIGIN_MODES", "SOURCE_MODES", "document", "identity_for"]