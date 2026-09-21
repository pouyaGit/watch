"""Priority rubric (EPIC 4 Part 2): explicit, deterministic, capped.

Five dimensions, each 0–20, summed to 0–100. Every weight below is a
pinned constant with a one-line rationale; changing a weight changes
scores, so the rubric table is part of the tested contract.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from aec.intelligence.models import BANDS, DIMENSIONS, ResearchPriority

#: Path tokens that suggest an endpoint is worth studying first.
#: Rationale: administrative and account paths concentrate access logic.
ENDPOINT_TOKENS = (
    "admin", "login", "account", "api", "billing", "payment",
    "user", "profile", "dashboard", "settings",
)

#: Parameter names that suggest a reference worth studying.
#: Rationale: identity/address parameters shape request routing.
PARAMETER_TOKENS = (
    "id", "user", "account", "role", "redirect", "url",
    "callback", "file", "path", "email",
)

#: Technology labels that add study context.
#: Rationale: a known stack tells the researcher which manuals apply.
RECOGNIZED_STACKS = frozenset({
    "php", "wordpress", "laravel", "symfony", "django", "flask",
    "rails", "node", "express", "asp", "java", "spring",
})

_MAX_DIMENSION = 20
_HIGH_AT = 60
_MEDIUM_AT = 30


def endpoint_importance(endpoint: Any) -> int:
    if not isinstance(endpoint, str):
        return 0
    lowered = endpoint.lower()
    hits = sum(1 for token in ENDPOINT_TOKENS if token in lowered)
    return min(_MAX_DIMENSION, hits * 4)


def parameter_relevance(parameters: Any) -> int:
    if not isinstance(parameters, (list, tuple)) or not parameters:
        return 0
    best = 0
    for parameter in parameters:
        if not isinstance(parameter, str):
            continue
        lowered = parameter.lower()
        score = 0
        for token in PARAMETER_TOKENS:
            if token and token in lowered:
                score = max(score, 12 if token == lowered else 8)
        best = max(best, score)
    return min(_MAX_DIMENSION, best)


def technology_context(technology: Any) -> int:
    if not isinstance(technology, (list, tuple)):
        return 0
    recognized = sum(
        1 for item in technology
        if isinstance(item, str) and item.strip().lower() in RECOGNIZED_STACKS
    )
    return min(_MAX_DIMENSION, recognized * 7)


def research_history(summary: Any) -> int:
    """Novel surfaces score highest; already-studied ones score zero."""
    if not isinstance(summary, Mapping):
        return 0
    if summary.get("researched"):
        return 0
    related = summary.get("related_patterns", 0)
    if isinstance(related, int) and related > 0:
        return 10
    return _MAX_DIMENSION


def evidence_gap_weight(gap: Any) -> int:
    if not isinstance(gap, Mapping):
        return 0
    missing = gap.get("missing", [])
    if not isinstance(missing, (list, tuple)):
        return 0
    count = len(missing)
    if count >= 3:
        return _MAX_DIMENSION
    if count == 2:
        return 13
    if count == 1:
        return 7
    return 0


def band_for(score: int) -> ResearchPriority:
    band = "LOW"
    if score >= _HIGH_AT:
        band = "HIGH"
    elif score >= _MEDIUM_AT:
        band = "MEDIUM"
    return ResearchPriority(
        candidate_id="", band=band, score=int(score),
        dimensions={dim: 0 for dim in DIMENSIONS}, reasons=(),
    )


def _fields(draft: Any) -> Mapping:
    if isinstance(draft, Mapping):
        return draft
    to_dict = getattr(draft, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    raise ValueError("candidate must be a mapping or draft")


def prioritize(draft: Any, history_summary: Any) -> ResearchPriority:
    fields = _fields(draft)
    dimensions = {
        "endpoint_importance": endpoint_importance(fields.get("endpoint", "")),
        "parameter_relevance": parameter_relevance(fields.get("parameters", ())),
        "technology_context": technology_context(fields.get("technology", ())),
        "research_history": research_history(history_summary),
        "evidence_gap": evidence_gap_weight(fields.get("evidence_gap", {})),
    }
    total = sum(dimensions.values())
    band = band_for(total).band
    reasons = tuple(
        f"{name}:{dimensions[name]}"
        for name in DIMENSIONS
        if dimensions[name] > 0
    )
    candidate_id = fields.get("candidate_id", "")
    return ResearchPriority(
        candidate_id=str(candidate_id) if candidate_id else "",
        band=band,
        score=total,
        dimensions=dimensions,
        reasons=reasons,
    )


def order_priorities(priorities: list[ResearchPriority]) -> list[ResearchPriority]:
    """Highest score first; ties break on candidate id (deterministic)."""
    return sorted(priorities, key=lambda item: (-item.score, item.candidate_id))


def serialize_priority(priority: ResearchPriority) -> str:
    """Stable JSON for a priority (sorted keys, compact separators)."""
    return json.dumps(priority.to_dict(), sort_keys=True, separators=(",", ":"))
