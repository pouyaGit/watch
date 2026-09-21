"""Execution bridge models (EPIC 6 Part 4)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ExecutionOutcome:
    """Result of submitting a plan or ingesting an observation result."""

    disposition: str
    job_transition: str
    reason: str
    request: dict[str, Any]
    requires_observation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition,
            "job_transition": self.job_transition,
            "reason": self.reason,
            "request": dict(self.request),
            "requires_observation": self.requires_observation,
        }


class SubmissionRefusal(Exception):
    """Refused plan submission (malformed plan, not an authz decision)."""


class IngestionRefusal(Exception):
    """Refused observation result (mismatch or malformed)."""


__all__ = ["ExecutionOutcome", "IngestionRefusal", "SubmissionRefusal"]
