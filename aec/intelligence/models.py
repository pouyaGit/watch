"""Frozen models for the intelligence engine (EPIC 4 Part 2). Pure data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Research priority bands (effort ordering, not severity).
BANDS = ("LOW", "MEDIUM", "HIGH")

#: Score dimensions; each contributes 0–20, total 0–100.
DIMENSIONS = (
    "endpoint_importance",
    "parameter_relevance",
    "technology_context",
    "research_history",
    "evidence_gap",
)


@dataclass(frozen=True)
class ResearchPriority:
    """Scored research priority for one candidate."""

    candidate_id: str
    band: str
    score: int
    dimensions: dict[str, int]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "band": self.band,
            "score": int(self.score),
            "dimensions": {key: int(self.dimensions[key]) for key in DIMENSIONS},
            "reasons": list(self.reasons),
        }
