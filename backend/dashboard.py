"""
backend/dashboard.py — Aggregation-based dashboard statistics.

Design goals (the Watch DB holds hundreds of thousands of rows):
  * Every count comes from a small number of MongoDB ``$group`` aggregations
    (one per collection), NOT a per-program ``.count()`` loop -- so the cost
    is independent of how many programs exist.
  * The merge / sort / filter logic is pure Python over tiny per-program
    dicts and is unit-testable without a database.
  * A short TTL cache absorbs dashboard refreshes / htmx polls without
    re-running the aggregations on every request.

Timestamps returned here are the raw (naive, server-local) DB values; the
presentation layer (backend.tz / Jinja filters) converts them to Tehran.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from pathlib import Path

from backend import tz
from backend.models import TaskRun
from backend.task_runner import get_last_run, get_task_status
from backend.tasks_registry import all_tasks
from database.change_events import ChangeEvent
from database.db import (
    DnsBruteStatus,
    Endpoints,
    Http,
    LiveSubdomains,
    Programs,
    Subdomains,
    Urls,
)

# A program is considered "stale" when its newest recon activity is older
# than this many days (used by the Stale filter / badge).
STALE_DAYS = 7

# TTL for the aggregate dashboard payload (seconds). Cheap to tune.
_CACHE_TTL = 10.0
_CACHE: dict = {}


def _group_count_by_program(coll, extra_match=None) -> dict:
    """{program_name: doc_count} via a single $group aggregation.

    ``extra_match`` (optional dict) restricts which docs are counted first
    (e.g. ``{"params__0": {"$exists": True}}`` or ``{"x8_checked": True}``),
    still with one aggregation for ALL programs.
    """
    out = {}
    pipeline = []
    if extra_match:
        pipeline.append({"$match": extra_match})
    pipeline.append({"$group": {"_id": "$program_name", "n": {"$sum": 1}}})
    for doc in coll.aggregate(pipeline, allowDiskUse=True):
        if doc.get("_id"):
            out[doc["_id"]] = doc.get("n", 0)
    return out


def _group_max_by_program(coll, field: str) -> dict:
    """{program_name: max(<field>)} via a single $group aggregation."""
    out = {}
    pipeline = [{"$group": {"_id": "$program_name", "m": {"$max": f"${field}"}}}]
    for doc in coll.aggregate(pipeline, allowDiskUse=True):
        if doc.get("_id") and doc.get("m"):
            out[doc["_id"]] = doc["m"]
    return out


def _distinct_params_by_program() -> dict:
    """{program_name: distinct parameter-name count} from Endpoints.params."""
    out = {}
    pipeline = [
        {"$unwind": "$params"},
        # Empty / null param names carry no signal.
        {"$match": {"params": {"$nin": ["", None]}}},
        {"$group": {"_id": {"p": "$program_name", "n": "$params"}}},
        {"$group": {"_id": "$_id.p", "c": {"$sum": 1}}},
    ]
    for doc in Endpoints._get_collection().aggregate(pipeline, allowDiskUse=True):
        if doc.get("_id"):
            out[doc["_id"]] = doc.get("c", 0)
    return out


def _distinct_params_for_program(name: str) -> int:
    """Distinct parameter-name count for ONE program (targeted $match first,
    so it never scans other programs' endpoints)."""
    pipeline = [
        {"$match": {"program_name": name}},
        {"$unwind": "$params"},
        {"$match": {"params": {"$nin": ["", None]}}},
        {"$group": {"_id": "$params"}},
        {"$count": "c"},
    ]
    docs = list(Endpoints._get_collection().aggregate(pipeline, allowDiskUse=True))
    return docs[0]["c"] if docs else 0


def _changes_by_program(since: datetime) -> dict:
    """{program_name: change-event count since <since>}."""
    out = {}
    pipeline = [
        {"$match": {"created_date": {"$gte": since}}},
        {"$group": {"_id": "$program_name", "c": {"$sum": 1}}},
    ]
    for doc in ChangeEvent._get_collection().aggregate(pipeline, allowDiskUse=True):
        if doc.get("_id"):
            out[doc["_id"]] = doc.get("c", 0)
    return out


def _latest(*values):
    """Max of a list of optional datetimes (ignores None)."""
    present = [v for v in values if v]
    return max(present) if present else None


def compute_program_rows(program_names, metrics: dict) -> list:
    """Merge per-program metric dicts into dashboard rows (pure).

    ``metrics`` maps metric-key -> {program: value}. Each row carries the
    counts, the last-activity timestamps and a derived ``last_activity``.
    """
    def g(key, name):
        return metrics.get(key, {}).get(name, 0)

    def gt(key, name):
        return metrics.get(key, {}).get(name)

    rows = []
    for name in program_names:
        last_crawl = gt("urls_last", name)
        last_http = gt("http_last", name)
        last_live = gt("live_last", name)
        last_param = gt("x8_last", name)
        last_static = gt("dns_static_last", name)
        last_dynamic = gt("dns_dynamic_last", name)
        last_dns = _latest(last_static, last_dynamic)
        last_activity = _latest(
            last_crawl, last_http, last_live, last_param, last_dns
        )
        rows.append({
            "program_name": name,
            "subdomains": g("subs", name),
            "live": g("live", name),
            "http": g("http", name),
            "urls": g("urls", name),
            "endpoints": g("endpoints", name),
            "endpoints_with_params": g("endpoints_with_params", name),
            "endpoints_x8_checked": g("endpoints_x8_checked", name),
            "params": g("params", name),
            "changes_24h": g("changes", name),
            "last_crawl": last_crawl,
            "last_http": last_http,
            "last_param": last_param,
            "last_dns": last_dns,
            "last_activity": last_activity,
            "stale": _is_stale(last_activity),
        })
    return rows


# Whitelisted sortable columns -> row key (never user input straight to sort).
SORT_KEYS = {
    "name": "program_name",
    "subdomains": "subdomains",
    "live": "live",
    "http": "http",
    "urls": "urls",
    "endpoints": "endpoints",
    "params": "params",
    "updated": "last_activity",
    "crawl": "last_crawl",
    "dns": "last_dns",
    "param": "last_param",
}


def sort_program_rows(rows, sort: str = "name", direction: str = "asc") -> list:
    key = SORT_KEYS.get(sort, "program_name")
    reverse = str(direction).lower() in ("desc", "descending", "-1")
    if key == "program_name":
        return sorted(rows, key=lambda r: (r["program_name"] or "").lower(),
                      reverse=reverse)
    # Rows missing the sort value always land last, regardless of direction.
    present = [r for r in rows if r.get(key) is not None]
    missing = [r for r in rows if r.get(key) is None]
    present.sort(key=lambda r: r[key], reverse=reverse)
    return present + missing


def filter_program_rows(rows, mode: str = "all", now=None) -> list:
    """mode: all | active | stale | changes."""
    mode = (mode or "all").lower()
    if mode == "all":
        return rows
    if mode == "changes":
        return [r for r in rows if r.get("changes_24h")]
    if mode == "active":
        return [r for r in rows if not _is_stale(r.get("last_activity"), now)]
    if mode == "stale":
        return [r for r in rows if _is_stale(r.get("last_activity"), now)]
    return rows


def search_program_rows(rows, q: str = None) -> list:
    """Case-insensitive substring filter over program names (pure, cheap --
    program rows are small in-memory dicts, never loaded into the browser)."""
    if not q:
        return rows
    needle = str(q).strip().lower()
    if not needle:
        return rows
    return [r for r in rows if needle in (r.get("program_name") or "").lower()]


def _is_stale(last_activity, now=None) -> bool:
    if not last_activity:
        return True
    ref = now or datetime.now()
    return (ref - last_activity) > timedelta(days=STALE_DAYS)


def gather_program_metrics() -> dict:
    """Run the (few) aggregations and return the metrics map for
    compute_program_rows()."""
    since = datetime.now() - timedelta(hours=24)
    return {
        "subs": _group_count_by_program(Subdomains._get_collection()),
        "live": _group_count_by_program(LiveSubdomains._get_collection()),
        "http": _group_count_by_program(Http._get_collection()),
        "urls": _group_count_by_program(Urls._get_collection()),
        "endpoints": _group_count_by_program(Endpoints._get_collection()),
        "endpoints_with_params": _group_count_by_program(
            # Legacy semantic of "has params": params != [] (includes params
            # missing the field, matching the old params__ne=[] count).
            Endpoints._get_collection(),
            {"params": {"$ne": []}},
        ),
        "endpoints_x8_checked": _group_count_by_program(
            Endpoints._get_collection(), {"x8_checked": True}
        ),
        "params": _distinct_params_by_program(),
        "changes": _changes_by_program(since),
        "urls_last": _group_max_by_program(Urls._get_collection(), "last_update"),
        "http_last": _group_max_by_program(Http._get_collection(), "last_update"),
        "live_last": _group_max_by_program(LiveSubdomains._get_collection(), "last_update"),
        "x8_last": _group_max_by_program(Endpoints._get_collection(), "x8_last_checked"),
        "dns_static_last": _group_max_by_program(DnsBruteStatus._get_collection(), "last_static_run"),
        "dns_dynamic_last": _group_max_by_program(DnsBruteStatus._get_collection(), "last_dynamic_run"),
    }


def _cached(key, producer):
    now = time.monotonic()
    hit = _CACHE.get(key)
    if hit and (now - hit[0]) < _CACHE_TTL:
        return hit[1]
    value = producer()
    _CACHE[key] = (now, value)
    return value


def _program_names():
    def produce():
        return [p.program_name for p in Programs.objects().only("program_name")]
    return _cached("program_names", produce)


def _metrics():
    # Both global_counts() and program_rows() share this single cached set
    # of aggregations so a dashboard page runs the expensive queries once.
    return _cached("metrics", gather_program_metrics)


def program_rows(sort="name", direction="asc", mode="all"):
    """Full per-program rows for the dashboard / programs table."""
    names = _program_names()
    rows = compute_program_rows(names, _metrics())
    rows = filter_program_rows(rows, mode)
    return sort_program_rows(rows, sort, direction)


def global_counts() -> dict:
    """Top-level stat-card totals (program-count-independent)."""
    def produce():
        metrics = _metrics()
        fresh_http = Http.objects(
            created_date__gte=datetime.now() - timedelta(hours=24)
        ).count()
        return {
            "programs": len(metrics["subs"]) or Programs.objects().count(),
            "subdomains": sum(metrics["subs"].values()),
            "live": sum(metrics["live"].values()),
            "http": sum(metrics["http"].values()),
            "urls": sum(metrics["urls"].values()),
            "endpoints": sum(metrics["endpoints"].values()),
            "params": sum(metrics["params"].values()),
            "fresh_http_24h": fresh_http,
        }

    return _cached("global_counts", produce)


def _run_to_dict(run) -> dict:
    """Presentation-ready TaskRun summary for the dashboard operations panel.

    The templates render Tehran timestamps / durations directly, so they are
    computed here (single source of truth: backend.tz) instead of silently
    rendering Undefined as blank.
    """
    log_name = Path(run.log_path).name if run.log_path else ""
    return {
        "id": str(run.id),
        "task_id": run.task_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "status": run.status,
        "exit_code": run.exit_code,
        "triggered_by": run.triggered_by,
        "pid": run.pid,
        "log_path": run.log_path or "",
        "log_name": log_name,
        "started_tehran": tz.fmt_tehran(run.started_at),
        "finished_tehran": tz.fmt_tehran(run.finished_at),
        "ago": tz.fmt_ago(run.started_at),
        "duration": tz.fmt_duration(run.started_at, run.finished_at),
    }


def latest_runs() -> list:
    """One summary per registered task: status + last run (for the
    'Latest Recon Activity' panel)."""
    out = []
    for task_id, entry in all_tasks():
        status = get_task_status(task_id)
        last = get_last_run(task_id)
        out.append({
            "task_id": task_id,
            "name": entry["name"],
            "status": status,
            "last_run": _run_to_dict(last) if last else None,
        })
    return out


def recent_changes(limit=25, program_name=None):
    """Newest change events as plain dicts (Tehran conversion in UI)."""
    q = ChangeEvent.objects()
    if program_name:
        q = q(program_name=program_name)
    return [e.as_dict() for e in q.order_by("-created_date").limit(limit)]


# Event types that count as "new asset discoveries" (vs config drift).
_NEW_HOST_TYPES    = {"new_live", "new_http", "new_domain"}
_NEW_ENDPOINT_TYPES = {"new_endpoint"}
_NEW_PARAM_TYPES   = {"new_parameter"}
_CDN_CHANGE_TYPES  = {"cdn_changed"}
_TITLE_CHANGE_TYPES = {"title_changed"}
_STATUS_CHANGE_TYPES = {"status_changed"}
_IP_CHANGE_TYPES   = {"ip_changed"}
_TECH_CHANGE_TYPES = {"technology_changed"}


def activity_summary(hours: int = 24) -> dict:
    """Cheap 24h activity rollup from ChangeEvent (ONE $group aggregation).

    The dashboard renders a single header line ("12 changes / 4 new hosts /
    5 new endpoints / 2 new parameters / 1 CDN change"), so this lives
    inside the dashboard code path that already touches ChangeEvent and
    shares its existing ``-created_date`` index.

    Bounded: at most a few thousand grouped buckets (one per event_type).
    NEVER a per-event scan, and NEVER an N+1 program loop.
    """
    out = {
        "total": 0,
        "new_hosts": 0,
        "new_endpoints": 0,
        "new_parameters": 0,
        "cdn_changes": 0,
        "title_changes": 0,
        "status_changes": 0,
        "ip_changes": 0,
        "tech_changes": 0,
    }
    try:
        since = datetime.now() - timedelta(hours=hours)
        pipeline = [
            {"$match": {"created_date": {"$gte": since}}},
            {"$group": {"_id": "$event_type", "c": {"$sum": 1}}},
        ]
        counts = {}
        for doc in ChangeEvent._get_collection().aggregate(pipeline, allowDiskUse=True):
            counts[doc.get("_id")] = doc.get("c", 0)
    except Exception:
        return out
    out["total"] = sum(counts.values())
    out["new_hosts"]      = sum(counts.get(t, 0) for t in _NEW_HOST_TYPES)
    out["new_endpoints"]  = sum(counts.get(t, 0) for t in _NEW_ENDPOINT_TYPES)
    out["new_parameters"] = sum(counts.get(t, 0) for t in _NEW_PARAM_TYPES)
    out["cdn_changes"]    = sum(counts.get(t, 0) for t in _CDN_CHANGE_TYPES)
    out["title_changes"]  = sum(counts.get(t, 0) for t in _TITLE_CHANGE_TYPES)
    out["status_changes"] = sum(counts.get(t, 0) for t in _STATUS_CHANGE_TYPES)
    out["ip_changes"]     = sum(counts.get(t, 0) for t in _IP_CHANGE_TYPES)
    out["tech_changes"]   = sum(counts.get(t, 0) for t in _TECH_CHANGE_TYPES)
    return out


def program_summary(name: str) -> dict:
    """Per-program detail-page stats (single program, cheap).

    Uses per-program indexed queries (the detail page is opened one program
    at a time), NOT whole-collection aggregations -- for a single program
    those would scan every document across all programs.
    """
    subs = Subdomains.objects(program_name=name).count()
    live = LiveSubdomains.objects(program_name=name).count()
    http = Http.objects(program_name=name).count()
    urls = Urls.objects(program_name=name).count()
    eps = Endpoints.objects(program_name=name).count()
    eps_with_params = Endpoints.objects(program_name=name, params__ne=[]).count()
    eps_x8_checked = Endpoints.objects(program_name=name, x8_checked=True).count()
    params = _distinct_params_for_program(name)

    def _last(model, field):
        """Most recent value of ``field`` for this program (indexed query)."""
        doc = model.objects(program_name=name).order_by(f"-{field}").only(field).first()
        return getattr(doc, field, None) if doc else None

    last_crawl = _last(Urls, "last_update")
    last_http = _last(Http, "last_update")
    last_live = _last(LiveSubdomains, "last_update")
    last_param = _last(Endpoints, "x8_last_checked")
    dns_static = _last(DnsBruteStatus, "last_static_run")
    dns_dynamic = _last(DnsBruteStatus, "last_dynamic_run")
    return {
        "program_name": name,
        "subdomains": subs,
        "live": live,
        "http": http,
        "urls": urls,
        "endpoints": eps,
        "endpoints_with_params": eps_with_params,
        "endpoints_x8_checked": eps_x8_checked,
        "params": params,
        "last_crawl": last_crawl,
        "last_http": last_http,
        "last_live": last_live,
        "last_param": last_param,
        "last_dns_static": dns_static,
        "last_dns_dynamic": dns_dynamic,
        "last_dns": _latest(dns_static, dns_dynamic),
        "last_activity": _latest(last_crawl, last_http, last_live, last_param,
                                 dns_static, dns_dynamic),
    }
