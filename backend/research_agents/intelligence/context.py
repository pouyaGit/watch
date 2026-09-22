"""backend/research_agents/intelligence/context.py — Phase 6.

Bounded cross-job research context assembly.  A new job receives a
compact, deterministic digest of prior research — related cases, memory
heads, prior recommendations and recent historical jobs — hard-limited
by configuration (items AND characters).  The LLM never receives
unrestricted database history: callers pass pre-bounded slices and this
assembler enforces the configured caps on top.

Priority order (first wins budget): related prior research > gate-
relevant memory (VERIFIED/REJECTED) > other memory > prior
recommendations > historical job summaries.  Overflow is dropped
(honestly counted in ``stats``) instead of truncated mid-item.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.research_agents.intelligence.memory import scrub_text


@dataclass(frozen=True)
class ContextLimits:
    max_items: int = 24
    max_chars: int = 1600
    max_history_jobs: int = 4
    max_related_cases: int = 3
    max_knowledge: int = 5
    max_memory_items: int = 12
    max_recommendations: int = 6


def _prior_field(obj: Any, key: str, default: str = "") -> str:
    """Prior records may be ResearchJob objects or plain dicts."""
    if isinstance(obj, dict):
        return str(obj.get(key, default) or default)
    return str(getattr(obj, key, default) or default)


def _section(signal_type: str, subject: str, classification: str) -> dict[str, Any]:
    return {
        "signal_type": signal_type,
        "subject": subject,
        "source_agent": "research-intelligence",
        "source_classification": classification,
        "confidence": "not_evaluated",
        "research_only": True,
    }


def assemble(
    *,
    job: Any,
    related: list[Any],
    memory_hits: list[Any],
    knowledge: list[dict[str, Any]],
    prior_recommendations: list[str],
    history_jobs: list[Any],
    limits: ContextLimits,
) -> dict[str, Any]:
    """Build allowlist-shaped context signals within the hard limits."""
    max_items = max(0, int(limits.max_items))
    max_chars = max(0, int(limits.max_chars))
    candidates: list[tuple[int, dict[str, Any]]] = []

    for rel in list(related)[: max(0, int(limits.max_related_cases))]:
        d = rel.to_dict() if hasattr(rel, "to_dict") else dict(rel)
        reasons = ",".join(list(d.get("reasons") or [])[:3])
        candidates.append((10, _section(
            "PRIOR_RESEARCH",
            f"{d.get('kind', 'prior')} {d.get('category', '')} "
            f"ref={d.get('ref', '')} score={d.get('score', 0)} "
            f"reasons={reasons}",
            "prior_research",
        )))

    for item in list(memory_hits)[: max(0, int(limits.max_memory_items))]:
        priority = 8 if item.state in ("VERIFIED", "REJECTED") else 5
        candidates.append((priority, _section(
            "MEMORY_REFERENCE",
            f"{item.state} {item.kind}: {scrub_text(item.text, 160)}",
            "research_memory",
        )))

    for text in list(prior_recommendations)[: max(
            0, int(limits.max_recommendations))]:
        candidates.append((6, _section(
            "RECOMMENDATION_REFERENCE",
            scrub_text(text, 160), "prior_recommendation",
        )))

    for doc in list(knowledge)[: max(0, int(limits.max_knowledge))]:
        rel = doc.get("relevance") or {}
        why = str(rel.get("why") or doc.get("title") or "")[:46]
        # keep title + the bounded excerpt actually read + why it matched
        # (bounded to the allowlist's 240-char small-text limit)
        excerpt = str(doc.get("summary") or "")[:110]
        candidates.append((7, _section(
            "KNOWLEDGE_REFERENCE",
            f"{str(doc.get('title') or '')[:70]}: {excerpt} (why: {why})",
            "knowledge",
        )))

    history_built = 0
    for prior in list(history_jobs)[: max(0, int(limits.max_history_jobs))]:
        candidates.append((3, _section(
            "HISTORICAL_JOB",
            f"{_prior_field(prior, 'id')} "
            f"{_prior_field(prior, 'agent_category')} "
            f"status={_prior_field(prior, 'status')}",
            "prior_job",
        )))
        history_built += 1

    # stable order: priority desc, then insertion order
    ordered = [sec for _idx, (_prio, sec) in sorted(
        enumerate(candidates), key=lambda t: (-t[1][0], t[0]))]

    kept: list[dict[str, Any]] = []
    chars = 0
    dropped = 0
    for cand in ordered:
        size = len(cand.get("subject", "")) + 60
        if len(kept) >= max_items or chars + size > max_chars:
            dropped += 1
            continue
        kept.append(cand)
        chars += size

    return {
        "sections": kept,
        "stats": {
            "items": len(kept),
            "chars": chars,
            "dropped": dropped,
            "limits": {
                "max_items": max_items,
                "max_chars": max_chars,
                "max_history_jobs": limits.max_history_jobs,
                "max_related_cases": limits.max_related_cases,
                "max_knowledge": limits.max_knowledge,
                "max_memory_items": limits.max_memory_items,
                "max_recommendations": limits.max_recommendations,
            },
            "counts": {
                "related": len(related),
                "memory": len(memory_hits),
                "knowledge": len(knowledge),
                "prior_recommendations": len(prior_recommendations),
                "history_jobs": history_built,
            },
        },
    }


__all__ = ["ContextLimits", "assemble"]
