"""backend/soc/overview.py — SOC-1 overview/home (read-only).

Aggregates real existing state so an operator understands system state
in under 30 seconds: agent count, case count, evidence count, report
count, knowledge-document count and live runtime status.
"""

from __future__ import annotations

from typing import Any


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def overview_payload() -> dict[str, Any]:
    """SOC home: high-level state totals + runtime status.

    The agent number comes from the *same* projection ``/ui/soc/agents``
    renders (``backend.soc.agents.agents_index``) so the Overview and the
    Agents page can never disagree, and the ready/active/planned split is
    exposed beside it so the metric cannot be misread as "operational
    agents".  (It used to count ``backend.research_agents.registry`` — a
    module that is not part of the deployed tree — and reported 0 while
    the Agents page showed the declared registry.)
    """
    agents = 0
    agent_counts = {"registered": 0, "ready": 0, "idle": 0, "active": 0,
                    "failed": 0, "planned": 0}
    cases = 0
    evidence = 0
    reports = 0
    knowledge = 0

    try:
        from backend.soc import agents as soc_agents

        index = soc_agents.agents_index()
        listed = index.get("agents") or []
        agents = int(index.get("count") or len(listed))
        agent_counts["registered"] = agents
        for agent in listed:
            status = str(agent.get("status") or "").upper()
            if status in ("READY", "IDLE", "ACTIVE", "FAILED", "PLANNED"):
                agent_counts[status.lower()] += 1
    except Exception:
        pass

    try:
        from backend.routers import aec

        cases = _safe_int(aec.build_case_explorer_view().get("count"))
        evidence = _safe_int(aec.get_evidence().get("total"))
    except Exception:
        pass

    try:
        from backend.investigation_engine import service as inv

        reports = _safe_int(inv.report_documents().get("count"))
    except Exception:
        pass

    try:
        from backend import research_data as rd

        knowledge = _safe_int(rd.list_kb(limit=1).get("total"))
    except Exception:
        pass

    from backend.soc.activity import _runtime_status

    # EPIC9 §14: AI operations panel — window / operations state /
    # process liveness as three separate, read-only facts.
    try:
        from backend.ai_ops.state import panel as ai_ops_panel
        ai_ops = ai_ops_panel()
    except Exception as exc:  # noqa: BLE001 - honest unavailability
        ai_ops = {"rule_version": "ai-ops-state-v1",
                  "operations_state": "UNAVAILABLE",
                  "operations_display": "UNAVAILABLE",
                  "window": {"label": "12:00-00:00 Asia/Tehran",
                             "open": None},
                  "source_error": type(exc).__name__,
                  "last_tick": None, "current_tick": None,
                  "next_tick_at": None, "work": {},
                  "process": {"alive": False,
                              "reason": "ai-ops source unavailable"}}

    return {
        "agents": agents,
        "agent_counts": agent_counts,
        "cases": cases,
        "evidence": evidence,
        "reports": reports,
        "knowledge": knowledge,
        "runtime": _runtime_status(),
        "ai_ops": ai_ops,
    }