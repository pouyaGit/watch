"""backend/soc/activity.py — SOC-4 AI activity / mission control (read-only).

Answers "what is AI doing right now" from real existing sources:
the real ai-knowledge activity status, the research-agent service
counters, the AEC execution-run view, investigation reports, and
research loop records.  No invented events, bounded timeline.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from backend.soc._util import _bounded, _text

_TIMELINE_LIMIT = 60


def _runtime_status() -> dict[str, Any]:
    """Real runtime observability (ai-knowledge activity status)."""
    try:
        from ai.knowledge.ai_activity_status import build_activity_status

        status = build_activity_status()
        if not isinstance(status, Mapping):
            return {"status": "UNKNOWN", "current_stage": "",
                    "current_run": None}
        return {
            "status": _text(status.get("status")) or "UNKNOWN",
            "current_stage": _text(status.get("current_stage")) or "",
            "current_run": (
                _text(status["current_run"])
                if status.get("current_run") else None
            ),
            "status_basis": _text(status.get("status_basis")) or "",
            "rule_version": _text(status.get("rule_version")) or "",
        }
    except Exception:
        return {"status": "UNKNOWN", "current_stage": "",
                "current_run": None, "status_basis": "unavailable"}


def _counts() -> dict[str, int]:
    """Aggregate counters from real sources (never fabricated)."""
    out = {
        "running_agents": 0,
        "queued_jobs": 0,
        "completed_jobs": 0,
        "blocked_jobs": 0,
        "waiting_review": 0,
    }
    try:
        from backend.research_agents import service as ra

        payload = ra.agents_payload()
        for agent in payload.get("agents", []):
            if int(agent.get("active_jobs") or 0) > 0:
                out["running_agents"] += 1
    except Exception:
        pass
    try:
        from backend.routers import aec
        from backend.investigation_engine import service as inv

        runs = aec.get_execution_runs().get("runs", [])
        run = runs[0] if runs else {}
        out["queued_jobs"] += int(run.get("queued_count") or 0)
        out["completed_jobs"] += int(run.get("completed_count") or 0)
        out["blocked_jobs"] += int(run.get("blocked_count") or 0)
        out["waiting_review"] += int(run.get("review_required_count") or 0)
        reports = inv.report_documents()
        out["completed_jobs"] += int(reports.get("count") or 0)
    except Exception:
        pass
    return out


def _cve_events() -> list[dict[str, Any]]:
    """Research loop records: CVEs studied (real, bounded)."""
    import glob
    import json
    from pathlib import Path

    events: list[dict[str, Any]] = []
    for path in sorted(glob.glob("ai_data/research/agent/*.loop.json")):
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        cve = _text(payload.get("cve_id"))
        if not cve:
            continue
        events.append({
            "time": _text(payload.get("completed_at")) or None,
            "agent": "Research Agent",
            "action": "analyzing/" + _text(payload.get("status"))
            or "researching CVE",
            "detail": cve,
            "source": "research-loop",
        })
        if len(events) >= 10:
            break
    return events


def _investigation_events() -> list[dict[str, Any]]:
    """Investigation reports: completed evidence runs (real)."""
    events: list[dict[str, Any]] = []
    try:
        from backend.investigation_engine import service as inv

        reports = inv.report_documents()
    except Exception:
        return events
    for report in (reports.get("reports") or []) if isinstance(reports, Mapping) else []:  # noqa: E501
        if not isinstance(report, Mapping):
            continue
        events.append({
            "time": _text(report.get("generated_at")),
            "agent": _text(report.get("agent")) or "Evidence Agent",
            "action": "evidence report generated",
            "detail": f"{_text(report.get('target'))} "
                      f"{_text(report.get('endpoint'))}".strip(),
            "source": "investigation-report",
        })
    return events


def _aec_events() -> list[dict[str, Any]]:
    """AEC execution-run transitions: pipeline activity (real view)."""
    events: list[dict[str, Any]] = []
    try:
        from backend.routers import aec

        jobs = aec.get_research_jobs().get("jobs", []) or []
    except Exception:
        return events
    for job in jobs:
        if not isinstance(job, Mapping):
            continue
        for transition in job.get("transitions", []) or []:
            if not isinstance(transition, Mapping):
                continue
            events.append({
                "time": transition.get("tick") if "tick" in transition else None,
                "agent": _text(transition.get("actor")) or "pipeline",
                "action": (
                    f"{_text(transition.get('previous_state'))} -> "
                    f"{_text(transition.get('next_state'))}"
                ),
                "detail": _text(transition.get("reason")),
                "source": "aec-run",
            })
    return events


def activity_payload(limit: int = _TIMELINE_LIMIT) -> dict[str, Any]:
    """Mission-control payload: counts + bounded real timeline."""
    timeline = _cve_events() + _investigation_events() + _aec_events()
    # aec events use tick numbers; sort numeric/ISO mixed by str, bounded
    timeline.sort(key=lambda e: str(e.get("time") or ""))
    return {
        "counts": _counts(),
        "timeline": _bounded(timeline, limit),
        "runtime": _runtime_status(),
    }