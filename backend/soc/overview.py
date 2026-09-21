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
    """SOC home: high-level state totals + runtime status."""
    agents = 0
    cases = 0
    evidence = 0
    reports = 0
    knowledge = 0

    try:
        from backend.research_agents.registry import build_default_registry

        agents = len(build_default_registry().list_agents())
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

    return {
        "agents": agents,
        "cases": cases,
        "evidence": evidence,
        "reports": reports,
        "knowledge": knowledge,
        "runtime": _runtime_status(),
    }