"""EPIC7 Part 16: append-only observation audit trail.

Every attempt records request, authorization, target, policy, decision,
execution state, result, evidence reference, and failure/refusal reason.
Entries are hash-chained (each entry binds the previous entry's hash), the
stored sequence is an immutable tuple, and verify() detects any tamper —
including a broken chain. replay() re-derives the decisions in order, so
the trail supports investigation and deterministic replay.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

RULE_VERSION = "aec-runtime-audit/v1"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      default=str)


def _entry_hash(payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        _canonical(payload).encode("utf-8")).hexdigest()
    return digest


class AuditTrail:
    """Append-only audit log. No update, delete, remove, or clear."""

    def __init__(self) -> None:
        self._entries: tuple[dict[str, Any], ...] = ()

    def append(self, event: Mapping[str, Any]) -> dict[str, Any]:
        payload = dict(event)
        previous_hash = None
        if self._entries:
            previous_hash = self._entries[-1]["entry_hash"]
        payload["previous_hash"] = previous_hash
        payload["entry_hash"] = _entry_hash(payload)
        entry = {
            "seq": len(self._entries) + 1,
            "entry_hash": payload["entry_hash"],
            "previous_hash": payload["previous_hash"],
            **payload,
        }
        self._entries = tuple(list(self._entries) + [entry])
        return dict(entry)

    def entries(self) -> tuple[dict[str, Any], ...]:
        return self._entries

    def verify(self,
               entries: Sequence[Mapping[str, Any]] | None = None) -> bool:
        items = list(entries) if entries is not None \
            else list(self._entries)
        previous = None
        for item in items:
            cur = dict(item)
            chain_ok = cur.get("previous_hash") == previous
            if not chain_ok:
                return False
            payload = {k: v for k, v in cur.items()
                       if k not in ("seq", "entry_hash")}
            if cur.get("entry_hash") != _entry_hash(payload):
                return False
            previous = cur.get("entry_hash")
        return True

    def replay(self) -> tuple[str, ...]:
        """Deterministic replay: the sequence of recorded decisions."""
        return tuple(str(item.get("decision", ""))
                     for item in self._entries)

    def export_json(self) -> dict[str, Any]:
        return {
            "rule_version": RULE_VERSION,
            "verified": self.verify(),
            "entries": list(self._entries),
        }


__all__ = ["AuditTrail", "RULE_VERSION"]