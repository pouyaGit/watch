"""Read-only AEC views for the command center (EPIC 3 Part 4, EPIC 4 Part 5).

Five GET endpoints over explicitly supplied view data — case records,
queue snapshot, aggregate status, research candidates, research status.
Handlers are pure allowlist projections: they select a fixed field set
and drop everything else, so unmounted or mis-shaped input can neither
leak nor mutate. There is no database, no session, and no write path
anywhere in this module.

Mounting (operator decision, Track B)::

    from backend.routers import aec as aec_router
    app.include_router(aec_router.router)

The router is inert until mounted: importing it serves nothing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import APIRouter

from aec.orchestrator.models import STATES as LIFECYCLE_STATES

router = APIRouter()

LAYER_VERSION = "aec-1/epic-3"

CASE_VIEW_KEYS = ("case_id", "state", "evidence_state", "selection_order")

CANDIDATE_VIEW_KEYS = (
    "candidate_id", "asset", "endpoint", "research_category",
    "band", "score", "role",
)

RESEARCH_BANDS = frozenset({"LOW", "MEDIUM", "HIGH"})

ASSIGNMENT_ROLES = frozenset({
    "authorization-researcher",
    "input-researcher",
    "server-researcher",
    "general-researcher",
})

STATUS_COUNT_STATES = frozenset(LIFECYCLE_STATES) | frozenset(
    {"WAITING_EVIDENCE", "EVIDENCE_PARTIAL", "EVIDENCE_READY"}
)


def _text(value: object) -> str:
    return str(value or "").strip()


def build_cases_view(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project case records to the public field set, in input order."""
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise ValueError("records must be a sequence of mappings")
    cases: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        case_id = _text(record.get("case_id"))
        state = _text(record.get("state"))
        if not case_id or not state:
            continue
        order = record.get("selection_order", 0)
        cases.append(
            {
                "case_id": case_id,
                "state": state,
                "evidence_state": _text(record.get("evidence_state"))
                or "WAITING_EVIDENCE",
                "selection_order": order if isinstance(order, int) else 0,
            }
        )
    return {"cases": cases}


def build_queue_view(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Project a queue snapshot, verifying its internal totals."""
    if not isinstance(snapshot, Mapping):
        raise ValueError("snapshot must be a mapping")
    entries = snapshot.get("entries")
    if not isinstance(entries, (list, tuple)):
        raise ValueError("snapshot entries must be a sequence")
    total = snapshot.get("total")
    if not isinstance(total, int) or total != len(entries):
        raise ValueError("snapshot total must match its entries")
    return {
        "snapshot_id": _text(snapshot.get("snapshot_id")),
        "entries": [dict(e) for e in entries],
        "total": total,
    }


def build_status_view(counts: Mapping[str, int]) -> dict[str, Any]:
    """Aggregate lifecycle counts with the layer version stamp."""
    if not isinstance(counts, Mapping):
        raise ValueError("counts must be a mapping")
    clean: dict[str, int] = {}
    for state, count in counts.items():
        if state not in STATUS_COUNT_STATES:
            raise ValueError(f"unknown lifecycle state: {state!r}")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"count for {state!r} must be a non-negative int")
        clean[state] = count
    return {"counts": clean, "versions": {"aec": LAYER_VERSION}}


@router.get("/api/aec/cases")
def get_cases() -> dict[str, Any]:
    """Case records currently held in memory (empty until wired)."""
    return build_cases_view([])


@router.get("/api/aec/queue")
def get_queue() -> dict[str, Any]:
    """Current queue snapshot (empty until wired)."""
    return build_queue_view({"snapshot_id": "", "entries": [], "total": 0})


@router.get("/api/aec/status")
def get_status() -> dict[str, Any]:
    """Aggregate lifecycle counts (empty until wired)."""
    return build_status_view({})


def build_candidates_view(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project research candidates with priority band, score, and role."""
    if isinstance(items, (str, bytes)) or not isinstance(items, Sequence):
        raise ValueError("items must be a sequence of mappings")
    candidates: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        candidate_id = _text(item.get("candidate_id"))
        band = _text(item.get("band"))
        if not candidate_id or band not in RESEARCH_BANDS:
            continue
        score = item.get("score", 0)
        role = _text(item.get("role"))
        candidates.append(
            {
                "candidate_id": candidate_id,
                "asset": _text(item.get("asset")),
                "endpoint": _text(item.get("endpoint")),
                "research_category": _text(item.get("research_category")),
                "band": band,
                "score": score if isinstance(score, int) else 0,
                "role": role if role in ASSIGNMENT_ROLES else "general-researcher",
            }
        )
    return {"candidates": candidates}


def build_research_status_view(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Aggregate band counts, role counts, and the layer version stamp."""
    if not isinstance(summary, Mapping):
        raise ValueError("summary must be a mapping")
    bands = summary.get("bands", {})
    roles = summary.get("roles", {})
    if not isinstance(bands, Mapping) or not isinstance(roles, Mapping):
        raise ValueError("bands and roles must be mappings")
    clean_bands: dict[str, int] = {}
    for band, count in bands.items():
        if band not in RESEARCH_BANDS:
            raise ValueError(f"unknown research band: {band!r}")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"count for {band!r} must be a non-negative int")
        clean_bands[band] = count
    clean_roles: dict[str, int] = {}
    for role, count in roles.items():
        if role not in ASSIGNMENT_ROLES:
            raise ValueError(f"unknown research role: {role!r}")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"count for {role!r} must be a non-negative int")
        clean_roles[role] = count
    return {
        "bands": clean_bands,
        "roles": clean_roles,
        "versions": {"aec": LAYER_VERSION},
    }


@router.get("/api/aec/candidates")
def get_candidates() -> dict[str, Any]:
    """Research candidates with priority (empty until wired)."""
    return build_candidates_view([])


@router.get("/api/aec/research-status")
def get_research_status() -> dict[str, Any]:
    """Aggregate band/role counts (empty until wired)."""
    return build_research_status_view({"bands": {}, "roles": {}})


__all__ = [
    "build_candidates_view",
    "build_cases_view",
    "build_queue_view",
    "build_research_status_view",
    "build_status_view",
    "get_candidates",
    "get_cases",
    "get_queue",
    "get_research_status",
    "get_status",
    "router",
]
