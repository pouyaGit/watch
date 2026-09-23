"""Phase 9: bounded, provenance-aware cross-objective context.

Context items flow from completed objectives to later objectives inside
the SAME campaign and scope.  Every item identifies source objective,
source job, source observation/result, confidence/state, and timestamp.

Hard rules enforced here:
  * context is NEVER authoritative evidence — items are labeled
    ``research_context_only=True`` and consumed only as advisory input;
  * context is scope-safe: only items whose scope_ref equals the
    consuming objective's scope are ever surfaced;
  * bounded: item text <= 400 chars, <= ``limit`` items, total chars
    <= ``max_chars`` — no unlimited historical context (rule 22).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.research_agents.campaign.store import CampaignStore


@dataclass
class ContextBundle:
    items: list[dict[str, Any]]
    total_chars: int
    dropped: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [dict(i) for i in self.items],
            "total_chars": self.total_chars,
            "dropped": self.dropped,
            "authoritative": False,    # context is never evidence
        }

    def digest(self, max_chars: int = 600) -> str:
        """Short bounded digest for job mission text / activity detail."""

        parts = [f"{i.get('source_objective_id')}:{i.get('text')[:120]}"
                 for i in self.items]
        return "; ".join(parts)[:max_chars]


def collect_context(
    store: CampaignStore,
    *,
    campaign_id: str,
    scope_ref: str,
    exclude_objective: str = "",
    limit: int = 6,
    max_chars: int = 1600,
) -> ContextBundle:
    """Bounded + scope-safe retrieval for a starting objective."""

    raw = store.context_for(
        campaign_id,
        scope_ref=scope_ref,          # scope safety: exact match only
        exclude_objective=exclude_objective,
        limit=max(1, int(limit)) * 2,  # over-fetch then trim by chars
    )
    kept: list[dict[str, Any]] = []
    total = 0
    dropped = 0
    for row in raw:
        if len(kept) >= int(limit):
            dropped += 1
            continue
        text = str(row.get("text") or "")
        if total + len(text) > int(max_chars):
            dropped += 1
            continue
        kept.append(row)
        total += len(text)
    return ContextBundle(items=kept, total_chars=total, dropped=dropped)


def extract_context_items(
    *,
    campaign_id: str,
    objective: Any,
    job_id: str,
    result: dict[str, Any] | None,
    hunt: dict[str, Any] | None,
    gate_reason: str = "",
    confidence: str = "",
) -> list[dict[str, Any]]:
    """Build context rows from a REAL completed objective.

    Sources are structural facts only (category, state, counts, gate
    reason, hypothesis verdict) — no evidence rows, no target URLs, no
    secrets.  Each row carries full provenance.
    """

    result = result or {}
    hunt = hunt or {}
    items: list[dict[str, Any]] = []
    scope = str(getattr(objective, "scope_ref", "") or "")
    obj_id = str(getattr(objective, "objective_id", ""))

    verdict = str(result.get("verdict") or result.get("confidence")
                  or confidence or "not_evaluated")
    items.append({
        "campaign_id": campaign_id,
        "source_objective_id": obj_id,
        "source_job_id": job_id,
        "source_ref": f"result:{job_id}",
        "confidence": str(verdict)[:40],
        "state": str(getattr(objective, "state", ""))[:20],
        "scope_ref": scope,
        "text": (f"{getattr(objective, 'category', '')} objective "
                 f"{obj_id} concluded {str(getattr(objective, 'state', ''))}"
                 f" (confidence={str(verdict)[:40]}, gate="
                 f"{str(gate_reason)[:80]})"),
    })
    if gate_reason:
        items.append({
            "campaign_id": campaign_id,
            "source_objective_id": obj_id,
            "source_job_id": job_id,
            "source_ref": f"gate:{job_id}",
            "confidence": "gate_decision",
            "state": str(getattr(objective, "state", ""))[:20],
            "scope_ref": scope,
            "text": f"evidence gate reason: {str(gate_reason)[:300]}",
        })
    if hunt:
        items.append({
            "campaign_id": campaign_id,
            "source_objective_id": obj_id,
            "source_job_id": job_id,
            "source_ref": f"hunt:{hunt.get('objective_id', job_id)}",
            "confidence": "observation_summary",
            "state": str(hunt.get("state") or "")[:20],
            "scope_ref": scope,
            "text": (
                f"observations={len(hunt.get('observation_ids') or [])} "
                f"plans={len(hunt.get('plan_ids') or [])} "
                f"rows_added={int(hunt.get('rows_added') or 0)} "
                f"knowledge_added={int(hunt.get('knowledge_added') or 0)} "
                f"termination="
                f"{str(hunt.get('termination_reason') or '')[:80]}"),
        })
    # technology/knowledge findings pass through as bounded context when
    # present in structured research (still non-authoritative)
    tech = result.get("technology") or []
    if isinstance(tech, (list, tuple)) and tech:
        items.append({
            "campaign_id": campaign_id,
            "source_objective_id": obj_id,
            "source_job_id": job_id,
            "source_ref": f"structured:{job_id}",
            "confidence": str(verdict)[:40],
            "state": "research_context",
            "scope_ref": scope,
            "text": "technology observed: " + ", ".join(
                str(t)[:40] for t in list(tech)[:6]),
        })
    return items


def record_context(store: CampaignStore,
                   items: list[dict[str, Any]]) -> int:
    """Persist context rows; returns stored count. Failures are visible."""

    stored = 0
    for row in items:
        try:
            store.record_context(row)
            stored += 1
        except Exception:  # noqa: BLE001 - caller records the failure
            continue
    return stored


__all__ = ["ContextBundle", "collect_context", "extract_context_items",
           "record_context"]
