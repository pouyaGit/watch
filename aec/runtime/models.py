"""ResearchJob model (EPIC 6 Part 2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ResearchJob:
    """Durable deterministic research job."""

    job_id: str
    case_id: str
    candidate_id: str
    source_mode: str
    state: str = "DISCOVERED"
    specialist: str = ""
    attempts: int = 0
    max_attempts: int = 3
    transitions: tuple[dict[str, Any], ...] = ()
    actor_history: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "case_id": self.case_id,
            "candidate_id": self.candidate_id,
            "source_mode": self.source_mode,
            "state": self.state,
            "specialist": self.specialist,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "transitions": [dict(item) for item in self.transitions],
            "actor_history": list(self.actor_history),
        }


class TransitionRefusal(Exception):
    """Raised when a job transition is refused (fail closed)."""

    def __init__(self, code: str, previous: str, proposed: str,
                 detail: str = "") -> None:
        super().__init__(f"{code}: {previous} -> {proposed} {detail}".strip())
        self.code = code
        self.previous = previous
        self.proposed = proposed
        self.detail = detail


__all__ = ["ResearchJob", "TransitionRefusal"]
