"""Frozen models for the research queue (EPIC 3 Part 2). Pure data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ScoredEntry:
    """One queued case with its score and rank (1-based, dense)."""

    case_id: str
    score: int
    rank: int

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "score": self.score, "rank": self.rank}


@dataclass(frozen=True)
class QueueSnapshot:
    """A frozen queue ordering with a content-hash id."""

    snapshot_id: str
    entries: tuple[ScoredEntry, ...]
    generated_from: tuple[str, ...]
    total: int = 0

    def __post_init__(self) -> None:
        if self.total == 0:
            object.__setattr__(self, "total", len(self.entries))

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "entries": [e.to_dict() for e in self.entries],
            "generated_from": list(self.generated_from),
            "total": self.total,
        }


@dataclass(frozen=True)
class RetryCase:
    """Retry ledger for one case: attempts spent and the last reason."""

    case_id: str
    attempts: int
    last_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "attempts": self.attempts,
            "last_reason": self.last_reason,
        }


@dataclass(frozen=True)
class RetryTracker:
    """Bounded retry state for queued cases. Append-only per case."""

    cases: tuple[RetryCase, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"cases": [c.to_dict() for c in self.cases]}


__all__ = ["QueueSnapshot", "RetryCase", "RetryTracker", "ScoredEntry"]
