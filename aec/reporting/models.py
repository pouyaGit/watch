"""Frozen models for research reporting (EPIC 5 Part 8). Pure data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ResearchReport:
    """One deterministic report over a research run."""

    report_id: str
    run_id: str
    observed_facts: tuple[dict[str, Any], ...]
    planned_observations: tuple[dict[str, Any], ...]
    missing_evidence: tuple[str, ...]
    context: dict[str, Any]
    blocked_actions: tuple[dict[str, str], ...]
    next_steps: tuple[dict[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "run_id": self.run_id,
            "observed_facts": [dict(item) for item in self.observed_facts],
            "planned_observations": [
                dict(item) for item in self.planned_observations
            ],
            "missing_evidence": list(self.missing_evidence),
            "context": dict(self.context),
            "blocked_actions": [dict(item) for item in self.blocked_actions],
            "next_steps": [dict(item) for item in self.next_steps],
        }
