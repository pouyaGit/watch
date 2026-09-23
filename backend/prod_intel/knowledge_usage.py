"""backend/prod_intel/knowledge_usage.py — knowledge usage, not inventory.

Projects which KB documents agents ACTUALLY used (persisted
``knowledge_use`` rows) beside the available inventory — with lineage
(agent -> job -> document) exactly as persisted, no inferred causality.
"""

from __future__ import annotations

from typing import Any

from backend.prod_intel import sources
from backend.prod_intel.semantics import (
    DEFAULT_WINDOW_HOURS,
    NOT_OBSERVED,
    OK,
    UNAVAILABLE,
    in_window,
    metric,
    window_bounds,
)


def knowledge_usage(*, hours: float | int | None = DEFAULT_WINDOW_HOURS,
                    limit: int = 100, offset: int = 0
                    ) -> dict[str, Any]:
    """Paginated usage projection + per-document/per-agent rollups."""
    iso_lower, window = window_bounds(hours)
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))

    ku_env = sources.knowledge_use()
    kb_env = sources.kb_total()
    if ku_env["state"] != "ok":
        return {"rule_version": "production-intelligence-v1",
                "window": window, "state": UNAVAILABLE,
                "reason": ku_env["reason"],
                "items": [], "count": 0, "total": 0}

    rows = [k for k in ku_env["data"]
            if in_window(str(k.get("created_at") or ""), iso_lower)]
    rows.sort(key=lambda k: str(k.get("created_at") or ""), reverse=True)
    total = len(rows)
    page = rows[offset:offset + limit]

    by_doc: dict[str, int] = {}
    by_agent: dict[str, int] = {}
    for k in rows:
        doc = str(k.get("document_id") or "")
        ag = str(k.get("agent") or "")
        if doc:
            by_doc[doc] = by_doc.get(doc, 0) + 1
        if ag:
            by_agent[ag] = by_agent.get(ag, 0) + 1

    items = [{"document_id": str(k.get("document_id") or ""),
              "title": str(k.get("title") or "")[:200],
              "agent": str(k.get("agent") or ""),
              "category": str(k.get("category") or ""),
              "job_id": str(k.get("job_id") or ""),
              "topic": str(k.get("topic") or ""),
              "at": str(k.get("created_at") or ""),
              "link": (f"/ui/kb/{k.get('document_id')}"
                       if k.get("document_id") else None)}
             for k in page]

    top_docs = sorted(by_doc.items(), key=lambda kv: (-kv[1], kv[0]))[:20]
    return {
        "rule_version": "production-intelligence-v1",
        "window": window,
        "state": OK if rows else NOT_OBSERVED,
        "count": len(items),
        "total": total,
        "pagination": {"limit": limit, "offset": offset,
                       "has_more": offset + limit < total},
        "items": items,
        "documents_available": (
            metric(kb_env["data"], source="research_data.list_kb",
                   population="KB inventory total",
                   aggregation="inventory count",
                   time_range={"kind": "current_snapshot"}, state=OK)
            if kb_env["state"] == "ok"
            else metric(None, source="research_data.list_kb",
                        population="KB inventory", aggregation="count",
                        time_range={"kind": "snapshot"},
                        state=UNAVAILABLE, reason=kb_env["reason"])),
        "documents_used_distinct": len(by_doc),
        "usage_by_document": [{"document_id": d, "uses": n}
                              for d, n in top_docs],
        "usage_by_agent": [{"agent": a, "uses": n}
                           for a, n in sorted(by_agent.items())],
        "semantics": "usage counts are persisted knowledge_use rows in "
                     "window; availability is the KB inventory snapshot; "
                     "lineage rows are stored facts, not inferred causes",
    }
