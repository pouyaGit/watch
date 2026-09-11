"""
backend/research_agent.py — Stage R23 read-only view layer for the autonomous
research agent.

Thin, fail-soft readback over ``ai.research_agent.storage`` + the scheduler
policy. Nothing here runs research, fetches, calls an LLM, or writes.

Used by:
- the dashboard "Research Agent" card
- ``/ui/research/agent`` and ``/ui/research/agent/{run_id}``
- ``/api/research/agent/status`` and ``/api/research/agent/runs``
"""

from __future__ import annotations

from typing import Optional

from ai.research_agent import storage
from ai.research_agent.scheduler import SchedulerConfig


def _config() -> SchedulerConfig:
    try:
        return SchedulerConfig.from_env()
    except Exception:
        return SchedulerConfig()


def _scheduler():
    from ai.research_agent.scheduler import ResearchScheduler

    return ResearchScheduler(_config())


def agent_status() -> dict:
    """Read-only scheduler + result summary (never raises)."""
    config = _config()
    try:
        info = _scheduler().status()
    except Exception:
        info = {
            "enabled": config.enabled,
            "window": config.window_label(),
            "in_window": False,
            "max_minutes": config.max_minutes,
            "max_plans": config.max_plans,
            "timezone": config.timezone,
            "network": config.network,
            "llm": config.llm,
            "next_run": "",
            "eligible_count": 0,
            "total_plans": 0,
        }
    try:
        results = storage.results_summary(base=config.agent_dir)
    except Exception:
        results = {"total": 0, "by_status": {}}
    try:
        last_run = storage.latest_run(base=config.agent_dir)
    except Exception:
        last_run = None
    return {
        "enabled": info.get("enabled", False),
        "window": info.get("window"),
        "in_window": info.get("in_window", False),
        "timezone": info.get("timezone"),
        "max_minutes": info.get("max_minutes"),
        "max_plans": info.get("max_plans"),
        "network": info.get("network", False),
        "llm": info.get("llm", False),
        # R24.8: public-source discovery state + conservative budget (read-only).
        "discovery": info.get("discovery", getattr(config, "discovery", False)),
        "discovery_budget": info.get("discovery_budget", {}),
        "next_run": info.get("next_run"),
        "eligible_count": info.get("eligible_count", 0),
        "total_plans": info.get("total_plans", 0),
        "results": results,
        "last_run": last_run,
        "recent_results": list_results()[:5],
    }


def list_runs(limit: int = 50) -> list[dict]:
    try:
        runs = storage.list_runs(base=_config().agent_dir)
    except Exception:
        return []
    runs = sorted(runs, key=lambda r: str(r.get("started_at") or ""), reverse=True)
    return runs[: max(int(limit), 0)]


def get_run(run_id: str) -> Optional[dict]:
    for run in list_runs(limit=1000):
        if run.get("run_id") == run_id:
            return run
    return None


def list_results(limit: int = 100) -> list[dict]:
    try:
        results = storage.list_results(base=_config().agent_dir)
    except Exception:
        return []
    results = sorted(
        results, key=lambda r: str(r.get("completed_at") or ""), reverse=True
    )
    return results[: max(int(limit), 0)]


def get_result(plan_id: str) -> Optional[dict]:
    try:
        return storage.load_result(plan_id, "r23-1", base=_config().agent_dir)
    except Exception:
        return None
