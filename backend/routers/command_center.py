"""backend/routers/command_center.py — WATCH Command Center (v1).

A single operational overview page composed read-only from the existing
authorities. Nothing new is computed as a security conclusion: the page
surfaces the real persisted watchlist stages (sweep / delta / evidence) and
the real runtime facts the rest of the dashboard already exposes.

    GET /ui/command              -- server-rendered Command Center
    GET /api/command/overview    -- bounded JSON projection of the same data
    GET /api/command/operations  -- bounded JSON system-operations projection
    GET /api/command/repository  -- bounded JSON repository-state projection

Data sources (all read-only, all fail-soft):

- ``backend.watchlist_data``       -- local watchlist snapshots + existing
  deterministic evidence-gap projection (the R30.1/R30.2/R31 evidence
  vocabulary is surfaced verbatim, never upgraded).
- ``backend.command_intelligence`` -- read-only aggregations over the
  existing candidate views: research operations counters and the
  Discovery -> Metadata -> Evidence -> Verification -> Review research
  pipeline (progress only; never a vulnerability verdict).
- ``backend.agent_operations``     -- the autonomous development workspace
  facts (mode, workspace, branch, agent reports, tmux socket probe), read
  from filesystem + Git metadata only.
- ``backend.repository_intelligence`` -- categorizes the running checkout's
  uncommitted state (source/knowledge/reports/runtime/ignored/deleted/unknown)
  from a read-only Git index parse plus a bounded working-tree scan. No git
  command is executed.
- ``backend.operations_status``    -- live operations: read-only ``systemctl
  show`` unit state + last execution for the primary Watch units, and host
  resources (CPU/RAM/disk/load/uptime) via the existing ``system_stats``.
- ``backend.research_activity``    -- the existing R83 bounded AI runtime
  status contract (agent runs, scheduler lock, window policy).
- ``backend.dashboard.latest_runs`` -- the existing recon operation status.
- ``backend.system_stats``         -- host CPU/RAM/disk/load (the page reuses
  the existing htmx ``/api/system/stats`` fragment for live polling).

No Mongo writes, no network, no LLM, no matcher invocation, no target
interaction and no git invocation. The only subprocess is the bounded,
read-only ``systemctl show`` status query in ``backend.operations_status``.
Missing observability is rendered as an honest empty/unavailable state, never
invented.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from backend import agent_operations as adata
from backend import command_intelligence as cintel
from backend import operations_status as ostatus
from backend import repository_intelligence as rintel
from backend import watchlist_data as wdata
from backend.deps import API_KEY, build_url, verify_api_key
from backend.templating import templates
from backend.tz import to_tehran

router = APIRouter()

_UI_AUTH = [Depends(verify_api_key)]

ACTIVITY_LIMIT = 40

#: Recon task statuses are the pre-existing vocabulary; a "successful run"
#: is exactly the run the existing task runner reports as success.
_SUCCESS_STATUSES = frozenset({"success"})


def _ctx(request: Request, **extra):
    """Common template context (same nav contract as the other routers)."""

    base = {
        "request": request,
        "api_key_qs": API_KEY or "",
        "root_url": build_url("/"),
        "home_url": build_url("/"),
        "command_url": build_url("/ui/command"),
        "tasks_url": build_url("/ui/tasks"),
        "runs_url": build_url("/ui/runs"),
        "changes_url": build_url("/ui/changes"),
        "domains_url": build_url("/ui/domains"),
        "http_url": build_url("/ui/http"),
        "urls_url": build_url("/ui/urls"),
        "endpoints_url": build_url("/ui/endpoints"),
        "parameters_url": build_url("/ui/parameters"),
        "search_url": build_url("/ui/search"),
        "programs_url": build_url("/ui/programs"),
        "dns_url": build_url("/ui/dns-bruteforce/status"),
        "docs_url": build_url("/docs"),
        "research_url": build_url("/ui/research"),
        "queue_url": build_url("/ui/research/queue"),
        "research_tasks_url": build_url("/ui/research/tasks"),
        "leads_url": build_url("/ui/research/leads"),
        "plans_url": build_url("/ui/research/plans"),
        "agent_url": build_url("/ui/research/agent"),
        "xss_url": build_url("/ui/xss"),
        "kb_url": build_url("/ui/kb"),
        "reports_url": build_url("/ui/reports"),
    }
    base.update(extra)
    return base


def _safe(callable_, default):
    try:
        return callable_()
    except Exception:
        return default


def _collect_activity() -> dict | None:
    """Existing R83 bounded AI runtime status (never raises)."""

    def _run():
        from backend import research_activity

        return research_activity.collect_activity()

    return _safe(_run, None)


def _operation_runs() -> list:
    def _run():
        from backend import dashboard

        return dashboard.latest_runs()

    return _safe(_run, []) or []


def _system_operations() -> dict:
    """Read-only live operations projection (systemd + resources + events)."""

    empty = {
        "operations": {"available": False, "note": "unavailable",
                       "unit_count": 0, "units": []},
        "resources": {"available": False},
        "events": [],
    }
    return _safe(ostatus.snapshot, empty)


def _repository_state() -> dict:
    """Read-only repository-state intelligence for the running checkout."""

    return _safe(rintel.analyze, rintel.empty_payload(str(rintel.PROJECT_ROOT)))


def _last_successful_run(runs: list) -> dict | None:
    """Newest recon operation whose last run succeeded (never invented)."""

    best = None
    for run in runs:
        last = run.get("last_run") if isinstance(run, dict) else None
        if run.get("status") not in _SUCCESS_STATUSES or not last:
            continue
        started = last.get("started_at")
        if started is None:
            continue
        if best is None or started > best[0]:
            best = (started, run)
    return best[1] if best else None


def _activity_from_watchlist(items: list) -> list:
    out = []
    for item in items:
        at = to_tehran(item.get("at"))
        out.append({
            "kind": item.get("kind"),
            "source": item.get("source") or "Watchlist",
            "title": item.get("source") or "Watchlist",
            "program": item.get("program") or "",
            "ref": item.get("ref") or "",
            "status": item.get("status") or "",
            "at": at,
            "detail": item.get("detail") or "",
        })
    return out


def _activity_from_runs(runs: list) -> list:
    out = []
    for run in runs:
        last = run.get("last_run") if isinstance(run, dict) else None
        if not last:
            continue
        out.append({
            "kind": "OPERATION",
            "source": "Recon operation",
            "title": run.get("name") or run.get("task_id") or "Operation",
            "program": "",
            "ref": run.get("task_id") or "",
            "status": (run.get("status") or "idle").upper(),
            "at": to_tehran(last.get("started_at")),
            "detail": " · ".join(
                part for part in (
                    last.get("duration"),
                    last.get("triggered_by"),
                ) if part
            ),
        })
    return out


def _activity_from_research(activity: dict | None) -> list:
    last = (activity or {}).get("last_run") if isinstance(activity, dict) else None
    if not last:
        return []
    from ai.knowledge.ai_activity_status import to_tehran as _iso_tehran

    at = _iso_tehran(last.get("finished_at") or last.get("started_at"))
    detail = " · ".join(
        part for part in (
            str(last.get("status") or "").upper() or None,
            f"{last.get('plans_processed', 0)} plan(s)",
            f"{last.get('result_count', 0)} result(s)",
        ) if part
    )
    return [{
        "kind": "RESEARCH_RUN",
        "source": "Research runtime",
        "title": "Research agent run",
        "program": last.get("program") or "",
        "ref": last.get("run_id") or "",
        "status": str(last.get("status") or "").upper(),
        "at": at,
        "detail": detail,
    }]


def _timeline(activity: dict | None, runs: list, watchlist_items: list,
              report_items: list, operation_items: list | None = None,
              limit: int = ACTIVITY_LIMIT) -> list:
    items = (
        _activity_from_watchlist(watchlist_items)
        + _activity_from_runs(runs)
        + _activity_from_research(activity)
        + list(report_items or [])
        + list(operation_items or [])
    )
    items = [item for item in items if item.get("at") is not None]
    items.sort(key=lambda item: item["at"], reverse=True)
    return items[:limit]


def _attach_research_links(watchlist: dict) -> None:
    """Add api-key-propagating research links to every candidate (in place).

    Only the HTML route attaches links: the JSON projection deliberately
    carries no credential-bearing URLs.
    """

    for view in watchlist.get("programs") or []:
        for candidate in view.get("candidates") or []:
            cve = candidate.get("cve_id")
            if cve:
                candidate["research_url"] = build_url(f"/ui/research/{cve}")


def _attach_lifecycle_links(lifecycle: dict) -> None:
    """Add api-key-propagating research links to lifecycle candidates (in place)."""

    for candidate in lifecycle.get("candidates") or []:
        cve = candidate.get("cve_id")
        if cve:
            candidate["research_url"] = build_url(f"/ui/research/{cve}")


def _command_payload(program: Optional[str] = None,
                     *, with_links: bool = False) -> dict:
    """Compose the bounded Command Center projection.

    No secrets and no credential-bearing URLs. The Agent Operations panel
    intentionally carries the local agent workspace path (operational context,
    not a secret); report entries carry names only, never filesystem paths.
    """

    watchlist = wdata.overview(program=program)
    activity = _collect_activity()
    runs = _operation_runs()
    watchlist_items = wdata.recent_activity(limit=ACTIVITY_LIMIT)
    report_items = adata.recent_report_activity()
    system_ops = _system_operations()
    repository = _repository_state()
    research_ops = cintel.research_operations(watchlist)
    lifecycle = cintel.lifecycle_view(
        watchlist, report_cves=cintel.report_cves_for(watchlist)
    )
    if with_links:
        _attach_research_links(watchlist)
        _attach_lifecycle_links(lifecycle)
    return {
        "watchlist": watchlist,
        "activity": activity,
        "agent": adata.agent_operations(),
        "repository": repository,
        "research_ops": research_ops,
        "lifecycle": lifecycle,
        "operations": system_ops["operations"],
        "resources": system_ops["resources"],
        "runs": [
            {
                "task_id": run.get("task_id"),
                "name": run.get("name"),
                "status": run.get("status"),
                "last_run": run.get("last_run"),
            }
            for run in runs
        ],
        "last_successful_run": _last_successful_run(runs),
        "timeline": _timeline(
            activity, runs, watchlist_items, report_items, system_ops["events"]
        ),
    }


@router.get("/ui/command", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_command(request: Request, program: Optional[str] = None):
    """Server-rendered Watch Command Center (read-only operational overview)."""

    payload = _command_payload(program, with_links=True)
    return templates.TemplateResponse(
        request,
        "command_center.html",
        _ctx(
            request,
            active="command",
            page_title="Command Center",
            **payload,
        ),
    )


@router.get("/api/command/overview", dependencies=_UI_AUTH)
def api_command_overview(program: Optional[str] = None):
    """Bounded JSON projection of the Command Center (same data, read-only)."""

    return _command_payload(program)


@router.get("/api/command/operations", dependencies=_UI_AUTH)
def api_command_operations():
    """Bounded JSON system-operations projection (systemd + resources + events).

    Deterministic shape; read-only. Separate from ``/api/command/overview`` so
    operators (and tests) can poll just the live operations slice.
    """

    system_ops = _system_operations()
    return {
        "operations": system_ops["operations"],
        "resources": system_ops["resources"],
        "events": system_ops["events"],
    }


@router.get("/api/command/repository", dependencies=_UI_AUTH)
def api_command_repository():
    """Bounded JSON repository-state projection (deterministic, read-only).

    Categorizes the running checkout's uncommitted state without invoking git.
    """

    return _repository_state()
