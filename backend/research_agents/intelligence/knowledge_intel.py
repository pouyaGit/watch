"""backend/research_agents/intelligence/knowledge_intel.py — Phase 4.

Relevance-aware, bounded knowledge selection over the EXISTING knowledge
base API (``backend.research_data.list_kb``) — no new store, no content
fabrication: documents are metadata records the real KB returns, and a
document counts as consulted only when the runtime records the read.

Selection is deterministic: candidate queries come from the specialist's
declared knowledge requirements plus declared intelligence hints, scoring
uses only structural signals (specialist topic, class token, observation
signal tokens, prior-memory references), results are sorted and capped,
and every selected document carries its reasons (``why``) plus which
research outputs it informed (``informed`` — term-overlap linked, or
honestly ``prompt_context``).

A failing knowledge store raises ``KnowledgeUnavailable`` so the runtime
can degrade honestly (activity row + empty selection), never fabricate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from backend.research_agents.intelligence.memory import scrub_text

MAX_CANDIDATES = 40
_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
_STOP = {"the", "and", "for", "with", "via", "before", "after", "from",
         "that", "this", "using", "up", "and", "all", "including",
         "cross", "site", "scripting"}


class KnowledgeUnavailable(Exception):
    """The knowledge base cannot be read right now."""


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOP}


@dataclass
class KnowledgeSelection:
    docs: list[dict[str, Any]] = field(default_factory=list)
    considered: int = 0
    queries: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def ids(self) -> list[str]:
        return [str(d.get("id") or "") for d in self.docs]


def _candidate_docs(
    queries: list[str],
    list_kb: Callable[..., dict],
    per_query: int,
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    failures: list[str] = []
    for q in queries:
        if len(out) >= MAX_CANDIDATES:
            break
        try:
            payload = list_kb(q=q, limit=per_query)
        except Exception as exc:  # noqa: BLE001 - classified by caller
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            # A failing store is fatal for honest selection; a query that
            # merely returns nothing is not.
            if exc.__class__.__name__ in ("ResearchDataError",
                                          "KnowledgeUnavailable"):
                raise KnowledgeUnavailable(
                    f"knowledge store unavailable: {exc.__class__.__name__}"
                ) from exc
            failures.append(exc.__class__.__name__)
            continue
        for item in (payload or {}).get("items", []) or []:
            doc_id = scrub_text(item.get("knowledge_id") or item.get("id")
                                or item.get("title"), 80)
            if not doc_id or doc_id in seen:
                continue
            seen.add(doc_id)
            out.append(dict(item))
            if len(out) >= MAX_CANDIDATES:
                break
    if not out and failures:
        raise KnowledgeUnavailable(
            "knowledge store unavailable: all queries failed ("
            + ",".join(sorted(set(failures))[:4]) + ")")
    return out


def _score(
    item: dict[str, Any],
    *,
    topics: tuple[str, ...],
    hints: tuple[str, ...],
    category: str,
    signal_tokens: set[str],
    memory_refs: set[str],
) -> tuple[int, list[str]]:
    title = str(item.get("title") or "").lower()
    summary = str(item.get("summary") or "").lower()
    tags = " ".join(str(t) for t in (item.get("tags") or [])).lower()
    hay = f"{title} {summary} {tags}"
    doc_id = scrub_text(item.get("knowledge_id") or item.get("id"), 80)
    score = 0
    reasons: list[str] = []
    for topic in topics:
        t = topic.lower().strip()
        if t and t in hay:
            score += 3
            reasons.append(f"specialist_topic:{topic}")
    cat = category.lower().strip()
    if cat and (cat in _tokens(hay) or (cat == "cve" and "cve" in hay)):
        score += 2
        reasons.append(f"class_match:{category}")
    for hint in hints:
        h = hint.lower().strip()
        if h and len(h) > 2 and h in hay:
            score += 2
            reasons.append(f"hint_match:{hint}")
    overlap = sorted(signal_tokens & _tokens(hay))
    if overlap:
        score += min(3, len(overlap))
        reasons.append("signal_token:" + ",".join(overlap[:3]))
    if doc_id and doc_id in memory_refs:
        score += 2
        reasons.append("prior_memory_reference")
    return score, reasons


def select_knowledge(
    *,
    capability: Any,
    job: Any,
    observations: list[dict[str, Any]],
    memory_hits: list[Any],
    list_kb: Callable[..., dict],
    limit: int = 5,
    extra_queries: Any = (),
) -> KnowledgeSelection:
    """Deterministic bounded relevance selection. Raises
    ``KnowledgeUnavailable`` when the KB itself fails."""
    limit = max(0, int(limit))
    topics = tuple(str(t) for t in
                   (getattr(capability, "knowledge_requirements", ()) or ()))
    hints = tuple(str(h) for h in
                  (getattr(capability, "intelligence_hints", ()) or ()))
    category = str(getattr(capability, "category", "") or "")
    extra = [str(q).strip() for q in (extra_queries or ())
             if str(q).strip()]
    queries = list(dict.fromkeys(
        q for q in (extra + list(topics) + list(hints)) if q))[:6]

    signal_tokens: set[str] = set()
    for row in observations[:20]:
        tech = str(row.get("tech") or "")
        if tech:
            signal_tokens.update(_tokens(tech))
        if row.get("db_error_style"):
            signal_tokens.update({"database", "error"})
        for p in (row.get("params") or [])[:8]:
            signal_tokens.update(_tokens(str(p)))
    memory_refs: set[str] = set()
    for item in memory_hits:
        for ref in (getattr(item, "provenance", {}).get("refs") or []):
            if str(ref).startswith("kb-"):
                memory_refs.add(str(ref))

    selection = KnowledgeSelection(queries=queries)
    candidates = _candidate_docs(queries, list_kb,
                                 per_query=max(limit * 2, 6))
    selection.considered = len(candidates)
    scored: list[tuple[int, int, str, dict[str, Any], list[str]]] = []
    for idx, item in enumerate(candidates):
        score, reasons = _score(item, topics=topics, hints=hints,
                                category=category,
                                signal_tokens=signal_tokens,
                                memory_refs=memory_refs)
        if score <= 0:
            continue
        doc_id = scrub_text(item.get("knowledge_id") or item.get("id"), 80)
        scored.append((score, idx, doc_id, item, reasons))
    scored.sort(key=lambda r: (-r[0], r[2]))
    for score, _idx, doc_id, item, reasons in scored[:limit]:
        selection.docs.append({
            "id": doc_id,
            "title": scrub_text(item.get("title"), 160),
            "topic": (reasons[0].split(":", 1)[1]
                      if reasons and ":" in reasons[0] else category),
            "summary": scrub_text(item.get("summary"), 400),
            "relevance": {
                "score": int(score),
                "reasons": reasons[:6],
                "why": "; ".join(reasons[:4]),
            },
        })
    if not selection.docs:
        selection.notes.append("no_knowledge_documents_matched")
    if selection.considered > len(selection.docs):
        selection.notes.append(
            f"bounded_selection:{len(selection.docs)}/{selection.considered}")
    return selection


def link_informed(
    docs: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    recommendations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Honest association: which outputs cite the doc (term overlap) vs
    merely having it in the prompt context."""
    for doc in docs:
        doc_tokens = _tokens(str(doc.get("title") or ""))
        informed: list[str] = []
        for group, key in ((insights, "insight_code"),
                           (recommendations, "recommendation_code")):
            for entry in group[:8]:
                code = str(entry.get(key) or "")
                text = str(entry.get("text") or "")
                if code and len(doc_tokens & _tokens(text)) >= 2:
                    informed.append(code)
        doc["informed"] = informed or ["prompt_context"]
    return docs


def usage_index(knowledge_use_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Aggregate runtime knowledge-use records per document for the
    existing knowledge pages (usage count, last used, agents, jobs)."""
    out: dict[str, dict[str, Any]] = {}
    for row in knowledge_use_rows:
        doc_id = scrub_text(row.get("document_id"), 80)
        if not doc_id:
            continue
        entry = out.setdefault(doc_id, {
            "document_id": doc_id, "uses": 0, "last_used": "",
            "agents": [], "jobs": [], "specialist_topics": [],
        })
        entry["uses"] += 1
        at = str(row.get("at") or row.get("created_at") or "")
        if at > entry["last_used"]:
            entry["last_used"] = at
        for field_name, key in (("agent", "agents"), ("job_id", "jobs"),
                                ("topic", "specialist_topics")):
            value = str(row.get(field_name) or "").strip()
            if value and value not in entry[key]:
                entry[key].append(value)
    return out


__all__ = [
    "KnowledgeSelection",
    "KnowledgeUnavailable",
    "link_informed",
    "select_knowledge",
    "usage_index",
]
