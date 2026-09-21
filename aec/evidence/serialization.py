"""Stable serialization for the evidence layer (EPIC 2).

Every serializer emits canonical JSON (sorted keys, stable separators):
identical structures always produce identical bytes. Loaders return plain
data, never live objects.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from aec.evidence.models import (
    EvidenceArtifactDraft,
    EvidenceGapState,
    EvidenceQualityAssessment,
)


def canonical_dumps(document: Mapping[str, Any]) -> str:
    """Canonical JSON bytes for a plain-data mapping (sorted keys)."""
    return json.dumps(document, sort_keys=True)


def serialize_artifact(artifact: EvidenceArtifactDraft) -> str:
    """Stable bytes for one artifact draft."""
    return canonical_dumps(artifact.to_dict())


def serialize_assessment(assessment: EvidenceQualityAssessment) -> str:
    """Stable bytes for one quality assessment."""
    return canonical_dumps(assessment.to_dict())


def serialize_state(state: EvidenceGapState) -> str:
    """Stable bytes for one gap state."""
    return canonical_dumps(state.to_dict())


def serialize_bundle(
    artifacts: Sequence[EvidenceArtifactDraft],
    assessments: Sequence[EvidenceQualityAssessment],
    state: EvidenceGapState,
) -> str:
    """Stable bytes for a full evidence bundle of one case."""
    return canonical_dumps(
        {
            "artifacts": [a.to_dict() for a in artifacts],
            "assessments": [a.to_dict() for a in assessments],
            "state": state.to_dict(),
        }
    )


def parse_canonical(text: str) -> dict[str, Any]:
    """Parse canonical JSON back into plain data."""
    document = json.loads(text)
    if not isinstance(document, dict):
        raise ValueError("canonical evidence JSON must decode to an object")
    return document


__all__ = [
    "canonical_dumps",
    "parse_canonical",
    "serialize_artifact",
    "serialize_assessment",
    "serialize_bundle",
    "serialize_state",
]
