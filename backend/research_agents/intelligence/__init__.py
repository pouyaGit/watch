"""backend/research_agents/intelligence/__init__.py — shared intelligence layer.

One capability-driven layer used by every specialist edge (Phase 8):
research memory, learning, relevance-aware knowledge selection, prior
research similarity, bounded cross-job context, recommendations and the
research-lineage audit helpers.

Nothing in this package contacts targets, executes code, calls the LLM
directly (the runtime owns the single provider path), or creates cases —
the evidence gate remains the only authority for outcomes.
"""

from backend.research_agents.intelligence.memory import (  # noqa: F401
    MEMORY_KINDS,
    MEMORY_STATES,
    MemoryItem,
    MemoryStore,
    MemoryUnavailable,
    make_item,
    memory_id,
)

INTELLIGENCE_RULE_VERSION = "research-intelligence-v1"

__all__ = [
    "INTELLIGENCE_RULE_VERSION",
    "MEMORY_KINDS",
    "MEMORY_STATES",
    "MemoryItem",
    "MemoryStore",
    "MemoryUnavailable",
    "make_item",
    "memory_id",
]
