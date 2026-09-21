"""Frozen models for the surface adapter (EPIC 4 Part 1). Pure data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Categories this layer accepts (normalized, lowercase, no suffix).
KNOWN_CATEGORIES = ("idor", "xss", "ssrf", "file_upload", "authz")

#: A fresh candidate always needs its first observation.
INITIAL_OBSERVATION = "initial-observation"

#: Closed adapter refusal vocabulary.
REFUSAL_CODES = (
    "INVALID_INPUT",
    "MISSING_ENDPOINT",
    "MISSING_ASSET",
    "MISSING_CATEGORY",
    "UNKNOWN_CATEGORY",
)


@dataclass(frozen=True)
class ResearchCandidateDraft:
    """Normalized research candidate: a question about a surface, not a claim."""

    candidate_id: str
    asset: str
    endpoint: str
    parameters: tuple[str, ...]
    technology: tuple[str, ...]
    method: str
    research_category: str
    evidence_gap: dict[str, list[str]]
    source_reference: str
    classification_notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "asset": self.asset,
            "endpoint": self.endpoint,
            "parameters": list(self.parameters),
            "technology": list(self.technology),
            "method": self.method,
            "research_category": self.research_category,
            "evidence_gap": {
                "required": list(self.evidence_gap.get("required", [])),
                "missing": list(self.evidence_gap.get("missing", [])),
            },
            "source_reference": self.source_reference,
            "classification_notes": list(self.classification_notes),
        }


@dataclass(frozen=True)
class AdaptOutcome:
    """Either a draft (ok) or a closed-vocabulary refusal."""

    ok: bool
    draft: ResearchCandidateDraft | None
    refusal_code: str | None
