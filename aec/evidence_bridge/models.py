"""Evidence record model (EPIC 6 Part 5)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvidenceRecord:
    """One ingested observation, provenance intact, claim-free."""

    evidence_id: str
    case_id: str
    job_id: str
    evidence_level: str
    source: str
    source_mode: str
    artifact_reference: str
    observation: tuple[str, ...]
    missing_fields: tuple[str, ...]
    tick: int
    integrity: str
    confidence: str
    redaction_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "job_id": self.job_id,
            "evidence_level": self.evidence_level,
            "source": self.source,
            "source_mode": self.source_mode,
            "artifact_reference": self.artifact_reference,
            "observation": list(self.observation),
            "missing_fields": list(self.missing_fields),
            "tick": self.tick,
            "integrity": self.integrity,
            "confidence": self.confidence,
            "redaction_status": self.redaction_status,
        }


__all__ = ["EvidenceRecord"]
