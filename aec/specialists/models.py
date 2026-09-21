"""Specialist profile model (EPIC 6 Part 3)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SpecialistProfile:
    """Contract declared by one research role."""

    role: str
    capabilities: tuple[str, ...]
    accepted_inputs: tuple[str, ...]
    required_evidence: str
    output_schema: tuple[str, ...]
    confidence_levels: tuple[str, ...]
    refusals: tuple[str, ...]
    fallback: str

    def can_handle(self, category: str) -> bool:
        """True for accepted categories (ANY matches everything)."""
        return "ANY" in self.accepted_inputs or category in self.accepted_inputs

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "capabilities": list(self.capabilities),
            "accepted_inputs": list(self.accepted_inputs),
            "required_evidence": self.required_evidence,
            "output_schema": list(self.output_schema),
            "confidence_levels": list(self.confidence_levels),
            "refusals": list(self.refusals),
            "fallback": self.fallback,
        }


__all__ = ["SpecialistProfile"]
