"""Assignment rules (EPIC 4 Part 3): category → surface → role.

The table below is the whole policy. Reference-shaped categories
(idor, authz) study access logic; injection-shaped categories (xss,
file_upload) study input handling; request-shaping categories (ssrf)
study server behavior. Anything else gets a generalist — dropping a
candidate for novelty would lose coverage silently.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aec.assignment.models import Assignment

#: Category → (surface, role). Closed; unknown categories fall through.
_RULES: tuple[tuple[str, str, str], ...] = (
    ("idor", "authorization_surface", "authorization-researcher"),
    ("authz", "authorization_surface", "authorization-researcher"),
    ("xss", "input_surface", "input-researcher"),
    ("file_upload", "input_surface", "input-researcher"),
    ("ssrf", "server_side_surface", "server-researcher"),
)

_FALLBACK = ("general_surface", "general-researcher")


def assign(candidate: Any) -> Assignment:
    """Assign a research role to a candidate mapping or draft."""
    if isinstance(candidate, Mapping):
        fields: Mapping = candidate
    else:
        to_dict = getattr(candidate, "to_dict", None)
        fields = to_dict() if callable(to_dict) else {}
    category = fields.get("research_category", "")
    category = str(category).strip().lower() if isinstance(category, str) else ""
    candidate_id = fields.get("candidate_id", "")
    candidate_id = str(candidate_id) if candidate_id else ""
    for known, surface, role in _RULES:
        if category == known:
            return Assignment(
                candidate_id=candidate_id,
                surface=surface,
                role=role,
                rationale=f"category {known} studies {surface} via {role}",
            )
    surface, role = _FALLBACK
    return Assignment(
        candidate_id=candidate_id,
        surface=surface,
        role=role,
        rationale=f"category {category or 'unspecified'} has no specialist; generalist review via {role}",
    )
