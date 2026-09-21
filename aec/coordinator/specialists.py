"""Specialist staffing policy (EPIC 5 Part 4).

Staffs each assigned candidate with one of five research specialists.
The base role comes from the assignment contract; a candidate carrying
recognized stack context is staffed with a technology researcher
instead, because stack-specific study dominates the plan. Staffing
names who studies a surface — it starts no work and reaches no
conclusions.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

#: Closed specialist vocabulary.
SPECIALISTS = (
    "authorization-researcher",
    "input-researcher",
    "server-researcher",
    "technology-researcher",
    "general-researcher",
)


@dataclass(frozen=True)
class SpecialistAssignment:
    """One candidate staffed with a specialist plus its context."""

    candidate_id: str
    specialist: str
    reason: str
    evidence_gap: dict[str, list[str]]
    prior_context: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        gap = self.evidence_gap if isinstance(self.evidence_gap, Mapping) else {}
        return {
            "candidate_id": self.candidate_id,
            "specialist": self.specialist,
            "reason": self.reason,
            "evidence_gap": {
                "required": list(gap.get("required", [])),
                "missing": list(gap.get("missing", [])),
            },
            "prior_context": dict(self.prior_context),
        }


def _fields(value: Any) -> Mapping:
    if isinstance(value, Mapping):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        return result if isinstance(result, Mapping) else {}
    return {}


def specialize(assignment: Any, draft: Any,
               prior: Any = None) -> SpecialistAssignment:
    """Staff a candidate: stack context routes to technology research."""
    assignment_fields = _fields(assignment)
    draft_fields = _fields(draft)
    candidate_id = assignment_fields.get("candidate_id") or draft_fields.get(
        "candidate_id", ""
    )
    base_role = str(assignment_fields.get("role", "") or "general-researcher")
    technology = draft_fields.get("technology", ())
    stack = ""
    if isinstance(technology, (list, tuple)):
        for item in technology:
            if isinstance(item, str) and item.strip():
                stack = item.strip()
                break
    gap = draft_fields.get("evidence_gap", {})
    if not isinstance(gap, Mapping):
        gap = {}
    prior_context = dict(prior) if isinstance(prior, Mapping) else {
        "researched": False, "related_patterns": 0,
    }
    if stack:
        return SpecialistAssignment(
            candidate_id=str(candidate_id),
            specialist="technology-researcher",
            reason=(
                f"stack {stack} calls for stack-focused study "
                f"(base role {base_role})"
            ),
            evidence_gap={
                "required": list(gap.get("required", [])),
                "missing": list(gap.get("missing", [])),
            },
            prior_context=prior_context,
        )
    specialist = base_role if base_role in SPECIALISTS else "general-researcher"
    return SpecialistAssignment(
        candidate_id=str(candidate_id),
        specialist=specialist,
        reason=f"staffed per assignment role {specialist}",
        evidence_gap={
            "required": list(gap.get("required", [])),
            "missing": list(gap.get("missing", [])),
        },
        prior_context=prior_context,
    )
