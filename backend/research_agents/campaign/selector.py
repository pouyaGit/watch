"""Phase 6: capability-aware specialist selection (no invented specialists).

Selection is a pure function over the EXISTING capability registry: an
objective requiring XSS capability can only be served by the capability
whose category is XSS (agent xss-agent).  Every selection records a
reason.  Unmatched categories fail closed (no specialist -> objective
cannot run).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SELECTOR_VERSION = "campaign-agent-selector-v1"


@dataclass
class Selection:
    selected: bool
    category: str
    agent_name: str
    agent_id: str
    reason: str
    knowledge_coverage: int = 0
    observation_support: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": SELECTOR_VERSION,
            "selected": self.selected,
            "category": self.category,
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "reason": self.reason,
            "knowledge_coverage": self.knowledge_coverage,
            "observation_support": list(self.observation_support),
        }


def select_specialist(
    objective: Any,
    *,
    capability_lookup: Any = None,
    knowledge_docs_for_category: dict[str, int] | None = None,
    state_available: dict[str, bool] | None = None,
) -> Selection:
    """Pick the specialist for an objective from real capabilities.

    Rules:
      * category must resolve to an existing capability (else fail closed)
      * if the objective declares a specialist it must EQUAL the
        capability's agent_name for that category (no cross-wiring)
      * availability (state_available) is recorded and respected
    """

    from backend.research_agents.capabilities import capability_for

    lookup = capability_lookup or capability_for
    knowledge_docs_for_category = knowledge_docs_for_category or {}
    state_available = state_available or {}

    category = str(getattr(objective, "category", "") or "").strip()
    declared = str(getattr(objective, "specialist", "") or "").strip()

    cap = lookup(category)
    if cap is None:
        return Selection(
            selected=False, category=category, agent_name="",
            agent_id="",
            reason=f"no capability registered for category {category!r}",
        )

    if declared and declared != cap.agent_name:
        return Selection(
            selected=False, category=category, agent_name=cap.agent_name,
            agent_id=getattr(cap, "agent_id", ""),
            reason=(f"declared specialist {declared!r} does not match "
                    f"capability agent {cap.agent_name!r} for {category}; "
                    "cross-category selection refused"),
        )

    available = state_available.get(cap.agent_name, True)
    if not available:
        return Selection(
            selected=False, category=category, agent_name=cap.agent_name,
            agent_id=getattr(cap, "agent_id", ""),
            reason=f"specialist {cap.agent_name} currently unavailable",
        )

    coverage = int(knowledge_docs_for_category.get(category, 0))
    reason = (f"capability match: category {category} -> "
              f"{cap.agent_name} (agent_id={getattr(cap, 'agent_id', '')}); "
              f"allowed observations="
              f"{','.join(cap.allowed_observation_types)}")
    if declared:
        reason += "; objective-declared specialist matches capability"
    if coverage:
        reason += f"; knowledge_docs={coverage}"

    return Selection(
        selected=True,
        category=category,
        agent_name=cap.agent_name,
        agent_id=getattr(cap, "agent_id", ""),
        reason=reason,
        knowledge_coverage=coverage,
        observation_support=tuple(cap.allowed_observation_types),
    )


__all__ = ["select_specialist", "Selection", "SELECTOR_VERSION"]
