"""Deterministic specialist analysis (EPIC 6 Part 3).

analyze() maps (profile contract, job evidence) to one closed-vocabulary
opinion. Nothing here can produce a confirmed result: the strongest
positive output is REVIEW_REQUIRED, which routes to human review.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from aec.specialists.models import SpecialistProfile
from aec.specialists.registry import EVIDENCE_LEVELS

OPINION_OUTCOMES = (
    "NO_SIGNAL",
    "INSUFFICIENT_EVIDENCE",
    "REQUIRES_OBSERVATION",
    "POTENTIAL",
    "REVIEW_REQUIRED",
)


class AnalysisRefusal(Exception):
    """Refused analysis: unsupported input or malformed job."""


@dataclass(frozen=True)
class Opinion:
    """One specialist's deterministic read of a job's evidence."""

    job_id: str
    role: str
    outcome: str
    confidence: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "role": self.role,
            "outcome": self.outcome,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class Disagreement:
    """Result of comparing opinions on one job."""

    job_id: str
    outcomes: tuple[str, ...]
    disagree: bool
    review_required: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "outcomes": list(self.outcomes),
            "disagree": self.disagree,
            "review_required": self.review_required,
        }


def _level_rank(level: str) -> int:
    try:
        return EVIDENCE_LEVELS.index(level)
    except ValueError:
        return -1


def analyze(profile: SpecialistProfile, job: Mapping[str, Any],
            evidence: Sequence[Mapping[str, Any]]) -> Opinion:
    """Produce an opinion. Refuses unsupported or malformed input."""
    if not isinstance(job, Mapping):
        raise AnalysisRefusal("job must be a mapping")
    job_id = job.get("job_id")
    category = job.get("category")
    level = job.get("evidence_level", "NONE")
    if not isinstance(job_id, str) or not job_id:
        raise AnalysisRefusal("job missing job_id")
    if not isinstance(category, str) or not category:
        raise AnalysisRefusal("job missing category")
    if not profile.can_handle(category):
        raise AnalysisRefusal(f"{profile.role} refuses {category}")
    items = list(evidence) if isinstance(evidence, Sequence) \
        and not isinstance(evidence, (str, bytes)) else []
    if _level_rank(str(level)) < _level_rank(profile.required_evidence):
        return Opinion(job_id, profile.role, "INSUFFICIENT_EVIDENCE",
                       "high",
                       "evidence below required level "
                       f"{profile.required_evidence}")
    if not items:
        return Opinion(job_id, profile.role, profile.fallback, "medium",
                       "no evidence records supplied")
    coverage = {str(item.get("coverage", "")) for item in items
                if isinstance(item, Mapping)}
    if "COMPLETE" in coverage:
        return Opinion(job_id, profile.role, "REVIEW_REQUIRED", "medium",
                       "complete coverage needs human review")
    if "PARTIAL" in coverage:
        return Opinion(job_id, profile.role, "POTENTIAL", "low",
                       "partial coverage is a research lead only")
    return Opinion(job_id, profile.role, "NO_SIGNAL", "low",
                   "evidence carries no research signal")


def detect_disagreement(opinions: Sequence[Opinion]) -> Disagreement:
    """Compare opinions. Any outcome split forces human review."""
    items = list(opinions)
    if not items:
        raise AnalysisRefusal("no opinions to compare")
    outcomes = tuple(opinion.outcome for opinion in items)
    disagree = len(set(outcomes)) > 1
    return Disagreement(
        job_id=items[0].job_id,
        outcomes=outcomes,
        disagree=disagree,
        review_required=disagree,
    )


__all__ = ["OPINION_OUTCOMES", "AnalysisRefusal", "Disagreement", "Opinion",
           "analyze", "detect_disagreement"]
