"""Memory connector (EPIC 4 Part 4): cross-case recall for candidates.

Pure reads over supplied case memories. A candidate duplicates prior
research when another case's memory holds an OBSERVATION entry relating
to the same endpoint key (``asset + endpoint + ? + first parameter``);
PATTERN entries on matching keys surface as reusable context. The store
is never mutated here — use ``store.remember`` to record.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RelatedContext:
    """What prior research says about a candidate."""

    candidate_id: str
    duplicates: tuple[str, ...]
    related_patterns: tuple[str, ...]
    researched: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "duplicates": list(self.duplicates),
            "related_patterns": list(self.related_patterns),
            "researched": bool(self.researched),
        }


def endpoint_key(candidate: Mapping) -> str:
    """Deterministic identity of the studied surface point."""
    asset = str(candidate.get("asset", ""))
    endpoint = str(candidate.get("endpoint", ""))
    parameters = candidate.get("parameters", ())
    first = ""
    if isinstance(parameters, (list, tuple)) and parameters:
        first = str(parameters[0])
    key = asset + endpoint
    if first:
        key += "?" + first
    return key


def _entries(memory: Any) -> tuple:
    entries = getattr(memory, "entries", ())
    return tuple(entries) if isinstance(entries, tuple) else tuple(entries or ())


def find_related(memories: Mapping[str, Any], candidate: Mapping) -> RelatedContext:
    """Scan supplied memories for duplicates and reusable patterns."""
    key = endpoint_key(candidate)
    candidate_id = str(candidate.get("candidate_id", ""))
    duplicates: list[str] = []
    patterns: list[str] = []
    for case_id in sorted(memories):
        memory = memories[case_id]
        if getattr(memory, "case_id", case_id) != case_id:
            continue
        for entry in _entries(memory):
            relates = getattr(entry, "relates_to", ())
            if key not in tuple(relates or ()):
                continue
            kind = getattr(entry, "kind", "")
            if kind == "OBSERVATION" and case_id != candidate_id:
                # Case ids and candidate ids share a namespace by design
                # (candidates become cases); the same id is the same case.
                if case_id not in duplicates:
                    duplicates.append(case_id)
            elif kind == "PATTERN":
                detail = str(getattr(entry, "detail", ""))
                if detail and detail not in patterns:
                    patterns.append(detail)
    duplicates_tuple = tuple(sorted(duplicates))
    return RelatedContext(
        candidate_id=candidate_id,
        duplicates=duplicates_tuple,
        related_patterns=tuple(sorted(patterns)),
        researched=bool(duplicates_tuple),
    )


def history_summary(context: RelatedContext) -> dict[str, Any]:
    """Project a context onto the history summary the scorer consumes."""
    return {
        "researched": bool(context.researched),
        "related_patterns": len(context.related_patterns),
    }
