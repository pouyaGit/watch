"""Memory store (EPIC 3 Part 3): append-only recall with scrub-on-write.

``remember`` validates the kind, scrubs the detail through
:func:`aec.redaction.scrub_text`, assigns the next sequential id, and
returns the extended memory. Nothing stored can carry secret-shaped
text, and the entry records whether scrubbing fired.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from typing import Any

from aec.memory.models import (
    ENTRY_KINDS,
    REFUSAL_CODES,
    CaseMemory,
    MemoryEntry,
    RememberOutcome,
)
from aec.redaction import scrub_text


def fresh_memory(case_id: str) -> CaseMemory:
    """Empty recall for one case."""
    return CaseMemory(case_id=case_id)


def _relations(value: object) -> tuple[str, ...] | None:
    if value is None:
        return ()
    if isinstance(value, str):
        return None
    if isinstance(value, Sequence):
        items = list(value)
        if all(isinstance(item, str) and item.strip() for item in items):
            return tuple(items)
        return None
    return None


def remember(
    memory: CaseMemory,
    kind: object,
    detail: object,
    relates_to: object = (),
) -> RememberOutcome:
    """Append one entry to a case memory. Pure: the input is never mutated."""
    if kind not in ENTRY_KINDS:
        assert "INVALID_KIND" in REFUSAL_CODES
        return RememberOutcome(
            ok=False, memory=memory, entry=None, refusal_code="INVALID_KIND"
        )
    text = detail if isinstance(detail, str) else ""
    if not text.strip():
        return RememberOutcome(
            ok=False, memory=memory, entry=None, refusal_code="EMPTY_DETAIL"
        )
    relations = _relations(relates_to)
    if relations is None:
        return RememberOutcome(
            ok=False, memory=memory, entry=None, refusal_code="INVALID_RELATION"
        )
    safe, records = scrub_text(text, field="memory-detail")
    seq = len(memory.entries) + 1
    entry = MemoryEntry(
        entry_id=f"{memory.case_id}:{str(kind).lower()}:{seq:03d}",
        case_id=memory.case_id,
        kind=str(kind),
        detail=safe,
        relates_to=relations,
        was_redacted=bool(records),
    )
    return RememberOutcome(
        ok=True,
        memory=replace(memory, entries=tuple(list(memory.entries) + [entry])),
        entry=entry,
        refusal_code=None,
    )


def recall(memory: CaseMemory, kind: object = None) -> tuple[MemoryEntry, ...]:
    """Read entries back, optionally filtered by kind, oldest first."""
    if kind is None:
        return memory.entries
    return tuple(entry for entry in memory.entries if entry.kind == kind)


def patterns(memory: CaseMemory) -> tuple[MemoryEntry, ...]:
    """Reusable patterns only — the cross-case learning surface."""
    return recall(memory, "PATTERN")


def serialize_memory(memory: CaseMemory) -> str:
    """Stable bytes for one case memory."""
    return json.dumps(memory.to_dict(), sort_keys=True)


__all__ = [
    "fresh_memory",
    "patterns",
    "recall",
    "remember",
    "serialize_memory",
]
