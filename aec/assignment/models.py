"""Frozen models for research assignment (EPIC 4 Part 3). Pure data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Closed research-role vocabulary.
ROLES = (
    "authorization-researcher",
    "input-researcher",
    "server-researcher",
    "general-researcher",
)

#: Closed surface vocabulary.
SURFACES = (
    "authorization_surface",
    "input_surface",
    "server_side_surface",
    "general_surface",
)


@dataclass(frozen=True)
class Assignment:
    """Role assignment for one candidate."""

    candidate_id: str
    surface: str
    role: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "surface": self.surface,
            "role": self.role,
            "rationale": self.rationale,
        }
