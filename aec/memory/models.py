"""Frozen models for case memory (EPIC 3 Part 3). Pure data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Closed entry vocabulary.
ENTRY_KINDS = ("OBSERVATION", "FAILED_APPROACH", "GAP_NOTE", "PATTERN")

#: Closed refusal vocabulary for the store.
REFUSAL_CODES = frozenset({"INVALID_KIND", "EMPTY_DETAIL", "INVALID_RELATION"})


@dataclass(frozen=True)
class MemoryEntry:
    """One recalled item. Detail is always the scrubbed text."""

    entry_id: str
    case_id: str
    kind: str
    detail: str
    relates_to: tuple[str, ...] = ()
    was_redacted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "case_id": self.case_id,
            "kind": self.kind,
            "detail": self.detail,
            "relates_to": list(self.relates_to),
            "was_redacted": self.was_redacted,
        }


@dataclass(frozen=True)
class CaseMemory:
    """Append-only recall for one case: entries only ever grow."""

    case_id: str
    entries: tuple[MemoryEntry, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass(frozen=True)
class RememberOutcome:
    """Outcome of a store attempt: new memory plus entry, or a refusal."""

    ok: bool
    memory: CaseMemory
    entry: MemoryEntry | None
    refusal_code: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "memory": self.memory.to_dict(),
            "entry": self.entry.to_dict() if self.entry is not None else None,
            "refusal_code": self.refusal_code,
        }


__all__ = ["ENTRY_KINDS", "REFUSAL_CODES", "CaseMemory", "MemoryEntry", "RememberOutcome"]
