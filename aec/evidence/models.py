"""Frozen models for the evidence intelligence layer (EPIC 2).

Pure data. An :class:`EvidenceArtifactDraft` describes the *shape* of one
planned observation's record — which dimensions are known, which record
types are still outstanding — never observed values. Quality and state are
computed elsewhere from these structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Case evidence lifecycle, in order. Transitions move one step forward only.
STATES = ("WAITING_EVIDENCE", "EVIDENCE_PARTIAL", "EVIDENCE_READY")

#: Artifact kinds, mirroring the observation plan purposes one-to-one.
ARTIFACT_KINDS = ("baseline", "comparison", "context")


@dataclass(frozen=True)
class EvidenceArtifactDraft:
    """Planned record shape for one observation step. No observed values."""

    artifact_id: str
    plan_id: str
    case_id: str
    observation_ref: str
    artifact_kind: str
    artifact_type: str
    collected_fields: tuple[str, ...]
    missing_fields: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "plan_id": self.plan_id,
            "case_id": self.case_id,
            "observation_ref": self.observation_ref,
            "artifact_kind": self.artifact_kind,
            "artifact_type": self.artifact_type,
            "collected_fields": list(self.collected_fields),
            "missing_fields": list(self.missing_fields),
            "provenance": [list(pair) for pair in self.provenance],
        }


@dataclass(frozen=True)
class EvidenceQualityAssessment:
    """Completeness assessment of one artifact draft. Numeric only.

    This measures record completeness — how much of the planned shape is
    described as known — and nothing about any target.
    """

    artifact_id: str
    completeness: float
    consistency: float
    reproducibility: float
    provenance: float
    overall: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "completeness": self.completeness,
            "consistency": self.consistency,
            "reproducibility": self.reproducibility,
            "provenance": self.provenance,
            "overall": self.overall,
        }


@dataclass(frozen=True)
class EvidenceGapState:
    """Where one case stands on the WAITING → PARTIAL → READY lifecycle."""

    case_id: str
    state: str
    known_fields: tuple[str, ...]
    missing_fields: tuple[str, ...]
    history: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "state": self.state,
            "known_fields": list(self.known_fields),
            "missing_fields": list(self.missing_fields),
            "history": list(self.history),
        }


__all__ = [
    "ARTIFACT_KINDS",
    "STATES",
    "EvidenceArtifactDraft",
    "EvidenceGapState",
    "EvidenceQualityAssessment",
]
