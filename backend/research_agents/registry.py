"""backend/research_agents/registry.py — specialist agent registry (Part 2).

A small in-process registry that allows registering, listing and looking up
specialist agents by category. Registration is deterministic; the default
registry ships the XSS and IDOR agents as ``ready`` and reserves ``ssrf`` as a
``planned`` slot so the orchestrator can prepare (but not assign) future work.
"""

from __future__ import annotations

from backend.research_agents.models import (
    AGENT_STATUSES,
    AgentInfo,
    agent_category_for,
)


class AgentRegistry:
    """Register / list / lookup specialist research agents."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentInfo] = {}
        self._analyzers: dict[str, object] = {}
        self._evidence_analyzers: dict[str, object] = {}

    # -- registration ------------------------------------------------------
    def register(self, agent: AgentInfo, analyzer=None,
                 evidence_analyzer=None) -> AgentInfo:
        if not isinstance(agent, AgentInfo):
            raise TypeError("register requires an AgentInfo")
        if agent.status not in AGENT_STATUSES:
            raise ValueError(f"unknown agent status {agent.status!r}")
        key = agent.key.strip().lower()
        if not key:
            raise ValueError("agent key must be non-empty")
        self._agents[key] = agent
        if analyzer is not None:
            self._analyzers[key] = analyzer
        if evidence_analyzer is not None:
            self._evidence_analyzers[key] = evidence_analyzer
        return agent

    def unregister(self, key: str) -> None:
        self._agents.pop(str(key).strip().lower(), None)
        self._analyzers.pop(str(key).strip().lower(), None)
        self._evidence_analyzers.pop(str(key).strip().lower(), None)

    # -- lookup ------------------------------------------------------------
    def get(self, key: object) -> AgentInfo | None:
        return self._agents.get(str(key or "").strip().lower())

    def get_by_category(self, category: object) -> AgentInfo | None:
        """Look up an agent by agent category or attack-surface category."""

        wanted = agent_category_for(category)
        for agent in self._agents.values():
            if agent.category.lower() == wanted:
                return agent
        return None

    def analyzer_for(self, category: object):
        """Return the planning analyzer callable for a category (or ``None``)."""

        agent = self.get_by_category(category)
        if agent is None:
            return None
        return self._analyzers.get(agent.key)

    def evidence_analyzer_for(self, category: object):
        """Return the evidence analyzer callable for a category (or ``None``)."""

        agent = self.get_by_category(category)
        if agent is None:
            return None
        return self._evidence_analyzers.get(agent.key)

    def ready_for(self, category: object) -> AgentInfo | None:
        agent = self.get_by_category(category)
        if agent is not None and agent.status == "ready":
            return agent
        return None

    # -- listing -----------------------------------------------------------
    def list_agents(self) -> list[AgentInfo]:
        return [self._agents[key] for key in sorted(self._agents)]

    def categories(self) -> list[str]:
        return sorted({agent.category for agent in self._agents.values()})

    def to_dict(self) -> dict:
        return {
            "count": len(self._agents),
            "agents": [agent.to_dict() for agent in self.list_agents()],
        }


def build_default_registry() -> AgentRegistry:
    """Build the v2 registry: XSS, IDOR, SSRF, file-upload and AuthZ ready."""

    from backend.research_agents.agents import (
        authz_agent,
        idor_agent,
        ssrf_agent,
        upload_agent,
        xss_agent,
    )

    registry = AgentRegistry()
    for module in (
        xss_agent,
        idor_agent,
        ssrf_agent,
        upload_agent,
        authz_agent,
    ):
        registry.register(
            AgentInfo(
                key=module.KEY,
                name=module.NAME,
                category=module.CATEGORY,
                status="ready",
                description=module.DESCRIPTION,
                evidence_types=module.EVIDENCE_TYPES,
                strategy=getattr(module, "STRATEGY", ()),
                report_sections=getattr(module, "REPORT_SECTIONS", ()),
                confidence_model=getattr(module, "CONFIDENCE_MODEL", ""),
            ),
            analyzer=module.analyze,
            evidence_analyzer=module.analyze_evidence,
        )
    return registry


__all__ = ["AgentRegistry", "build_default_registry"]
