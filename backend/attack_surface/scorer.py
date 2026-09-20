"""backend/attack_surface/scorer.py — deterministic, explainable scoring.

Every candidate score is a plain sum of named, inspectable contributions. There
is no black box: :func:`score` returns both the integer score and the exact
reasons that produced it, and the same input always yields the same output.

Contributions (v1)
------------------

==============================  ======  ====================================
Component                       Points  Trigger
==============================  ======  ====================================
base                            30      any classification match
parameter signal (exact)        30      exact known input name
parameter signal (heuristic)    18      token/prefix/suffix name match
endpoint signal                 30      endpoint references a resource set
state-changing method           8       POST / PUT / PATCH / DELETE
identifier parameter            12      id / uid / *_id shaped parameter
technology context              5       observed technology on the host
reflection signal (XSS only)    5       GET-observable text parameter
==============================  ======  ====================================

Confidence buckets: ``HIGH`` >= 80, ``MEDIUM`` >= 55, otherwise ``LOW``. The
score is capped at 100.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.attack_surface.classifier import Classification
from backend.attack_surface.models import (
    CandidateCategory,
    Confidence,
    canonical_category,
)

BASE_SCORE = 30
PARAM_EXACT_POINTS = 30
PARAM_HEURISTIC_POINTS = 18
ENDPOINT_POINTS = 30
METHOD_POINTS = 8
IDENTIFIER_POINTS = 12
TECHNOLOGY_POINTS = 5
REFLECTION_POINTS = 5

HIGH_THRESHOLD = 80
MEDIUM_THRESHOLD = 55
MAX_SCORE = 100

_STATEFUL_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_REFLECTION_CATEGORIES = frozenset({CandidateCategory.XSS.value})


@dataclass(frozen=True)
class ScoredCandidate:
    """A classification plus its explainable score."""

    category: str
    score: int
    confidence: str
    reasons: tuple[str, ...]
    contributions: tuple[tuple[str, int], ...] = ()

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "score": int(self.score),
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "contributions": [
                {"component": name, "points": points}
                for name, points in self.contributions
            ],
        }


def confidence_for(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return Confidence.HIGH.value
    if score >= MEDIUM_THRESHOLD:
        return Confidence.MEDIUM.value
    return Confidence.LOW.value


def score(record, classification: Classification) -> ScoredCandidate:
    """Score one classified record deterministically and explainably."""

    category = canonical_category(classification.category)
    points = 0
    contributions: list[tuple[str, int]] = [("base", BASE_SCORE)]
    points += BASE_SCORE

    reasons: list[str] = list(classification.reasons)

    if classification.param_signal:
        if classification.param_match == "exact":
            points += PARAM_EXACT_POINTS
            contributions.append(("parameter_signal_exact", PARAM_EXACT_POINTS))
            reasons.append(
                "exact known input name: "
                f"{classification.param_signal}"
            )
        else:
            points += PARAM_HEURISTIC_POINTS
            contributions.append(
                ("parameter_signal_heuristic", PARAM_HEURISTIC_POINTS)
            )
            reasons.append(
                "parameter name resembles a known input: "
                f"{classification.param_signal}"
            )

    if classification.endpoint_signal:
        points += ENDPOINT_POINTS
        contributions.append(("endpoint_signal", ENDPOINT_POINTS))
        reasons.append(
            "endpoint matches a resource collection: "
            f"{classification.endpoint_signal}"
        )

    method = str(getattr(record, "method", "") or "GET").upper()
    if method in _STATEFUL_METHODS:
        points += METHOD_POINTS
        contributions.append(("state_changing_method", METHOD_POINTS))
        reasons.append(f"state-changing HTTP method ({method})")

    if classification.identifier:
        points += IDENTIFIER_POINTS
        contributions.append(("identifier_parameter", IDENTIFIER_POINTS))

    technology = tuple(getattr(record, "technology", ()) or ())
    if technology:
        points += TECHNOLOGY_POINTS
        contributions.append(("technology_context", TECHNOLOGY_POINTS))
        reasons.append(
            f"technology context observed ({len(technology)} technology/ies)"
        )

    if (
        category in _REFLECTION_CATEGORIES
        and method == "GET"
        and classification.param_signal
    ):
        points += REFLECTION_POINTS
        contributions.append(("reflection_signal", REFLECTION_POINTS))
        reasons.append("GET parameter is commonly reflected")

    capped = min(points, MAX_SCORE)
    return ScoredCandidate(
        category=category,
        score=capped,
        confidence=confidence_for(capped),
        reasons=tuple(_dedupe(reasons)),
        contributions=tuple(contributions),
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = " ".join(str(value or "").split())
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def score_record(record, classification: Classification) -> dict:
    """JSON-friendly scored candidate."""

    return score(record, classification).to_dict()


__all__ = [
    "BASE_SCORE",
    "PARAM_EXACT_POINTS",
    "PARAM_HEURISTIC_POINTS",
    "ENDPOINT_POINTS",
    "METHOD_POINTS",
    "IDENTIFIER_POINTS",
    "TECHNOLOGY_POINTS",
    "REFLECTION_POINTS",
    "HIGH_THRESHOLD",
    "MEDIUM_THRESHOLD",
    "MAX_SCORE",
    "ScoredCandidate",
    "confidence_for",
    "score",
    "score_record",
]
