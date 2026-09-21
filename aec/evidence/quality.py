"""Completeness assessment (EPIC 2): artifact draft → quality numbers.

Only record completeness is measured — the share of the planned shape
described as known, the internal coherence of the draft, and whether its
references allow the record to be reproduced and traced. Nothing here
characterizes any target; all outputs are plain numbers in [0, 1].
"""

from __future__ import annotations

from aec.evidence.models import EvidenceArtifactDraft, EvidenceQualityAssessment


def _completeness(artifact: EvidenceArtifactDraft) -> float:
    union = set(artifact.collected_fields) | set(artifact.missing_fields)
    if not union:
        return 0.0
    return len(set(artifact.collected_fields)) / len(union)


def _refs_present(artifact: EvidenceArtifactDraft) -> bool:
    return bool(
        artifact.artifact_id.strip()
        and artifact.plan_id.strip()
        and artifact.case_id.strip()
        and artifact.observation_ref.strip()
    )


def _consistency(artifact: EvidenceArtifactDraft) -> float:
    if not _refs_present(artifact):
        return 0.0
    names = list(artifact.collected_fields) + list(artifact.missing_fields)
    if len(names) != len(set(names)):
        return 0.5
    return 1.0


def _reproducibility(artifact: EvidenceArtifactDraft) -> float:
    return 1.0 if _refs_present(artifact) else 0.0


def _provenance(artifact: EvidenceArtifactDraft) -> float:
    chain = dict(artifact.provenance)
    if chain.get("plan_id", "").strip() and chain.get("case_id", "").strip():
        return 1.0
    return 0.0


def assess(artifact: EvidenceArtifactDraft) -> EvidenceQualityAssessment:
    """Assess one artifact draft. Pure and deterministic."""
    completeness = _completeness(artifact)
    consistency = _consistency(artifact)
    reproducibility = _reproducibility(artifact)
    provenance = _provenance(artifact)
    overall = round((completeness + consistency + reproducibility + provenance) / 4, 3)
    return EvidenceQualityAssessment(
        artifact_id=artifact.artifact_id,
        completeness=completeness,
        consistency=consistency,
        reproducibility=reproducibility,
        provenance=provenance,
        overall=overall,
    )


__all__ = ["assess"]
