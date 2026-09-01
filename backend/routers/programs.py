"""
backend/routers/programs.py — All the existing Programs/Subdomains/LiveSubdomains
/Http/Urls/Endpoints/wordlists/dns-bruteforce-status routes, lifted from
api.py with the URL paths unchanged so nothing currently pointing at this
API breaks.

HTML routes render via Jinja2 templates from web/templates (shared instance
from backend/templating.py). List pages also support server-side search
(``q``) and sorting (``sort`` / ``direction``) with a whitelisted field map.
"""
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from backend import dashboard as dash
from backend.deps import API_KEY, build_url, paginate
from backend.templating import templates
from backend.tz import fmt_ago, is_stale
from database.db import (
    DnsBruteStatus,
    Endpoints,
    Http,
    LiveSubdomains,
    Programs,
    Subdomains,
    Urls,
)

router = APIRouter()


def _ctx(request: Request, **extra):
    base = {
        "request": request,
        "api_key_qs": API_KEY or "",
        "root_url": build_url("/"),
        "home_url": build_url("/"),
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
        "stats_link": build_url("/api/stats/by-program"),
        "fresh_link": build_url("/ui/http/fresh"),
    }
    base.update(extra)
    return base


PROVIDERS = ["subfinder", "crtsh", "findomain", "assetfinder", "abuseipdb", "waybackurls"]
BF_PROVIDERS = ["staticBF", "dynamicBF"]  # shown first, styled distinctly -- highest-value finds


def provider_counts(program_name, provider):
    """(found, live_http) -- computed with a single server-side aggregation
    (Mongo $lookup + $facet) instead of pulling thousands of subdomain names
    into Python and building a giant $in query."""
    sub_coll = Subdomains._get_collection()
    http_coll_name = Http._get_collection().name

    pipeline = [
        {"$match": {"program_name": program_name, "providers": provider}},
        {"$lookup": {
            "from": http_coll_name,
            "let": {"sub": "$subdomain", "prog": "$program_name"},
            "pipeline": [
                {"$match": {"$expr": {"$and": [
                    {"$eq": ["$subdomain", "$$sub"]},
                    {"$eq": ["$program_name", "$$prog"]},
                ]}}},
                {"$limit": 1},
                {"$project": {"_id": 1}},
            ],
            "as": "http_match",
        }},
        {"$facet": {
            "found": [{"$count": "count"}],
            "live_http": [
                {"$match": {"http_match.0": {"$exists": True}}},
                {"$count": "count"},
            ],
        }},
    ]
    result = list(sub_coll.aggregate(pipeline))
    if not result:
        return 0, 0
    doc = result[0]
    found = doc["found"][0]["count"] if doc["found"] else 0
    live_http = doc["live_http"][0]["count"] if doc["live_http"] else 0
    return found, live_http


def unique_provider_count(program_name, provider):
    """Subdomains found by this provider AND NO OTHER provider."""
    raw_query = {
        "program_name": program_name,
        "$and": [
            {"providers": provider},
            {"providers": {"$size": 1}},
        ],
    }
    return Subdomains.objects(__raw__=raw_query).count()


def get_unique_provider_subdomains(program_name, provider, page, limit):
    raw_query = {
        "program_name": program_name,
        "$and": [
            {"providers": provider},
            {"providers": {"$size": 1}},
        ],
    }
    qs = Subdomains.objects(__raw__=raw_query).only("subdomain", "providers")
    total = qs.count()
    rows = [(s.subdomain, s.providers) for s in paginate(qs, page, limit)]
    return rows, total


# ----- shared helpers for list-page rendering -----
def _paginated_list_ctx(*, base_path, page, limit, total, extra=None):
    total_pages = max(1, (total + limit - 1) // limit)
    prev_url = build_url(base_path, page=page - 1, limit=limit, **(extra or {})) if page > 1 else None
    next_url = build_url(base_path, page=page + 1, limit=limit, **(extra or {})) if page < total_pages else None
    return {
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "prev_url": prev_url,
        "next_url": next_url,
    }


def _http_or_subdomain_items(records):
    """records: list of (name_or_h, providers_or_None).
    Returns the items[] payload for list_with_badges.html."""
    items = []
    for rec in records:
        name, providers = rec
        href = name if str(name).startswith("http") else f"https://{name}"
        items.append({
            "label": name,
            "url": href,
            "badges": [
                {"label": p, "bf": p in BF_PROVIDERS}
                for p in sorted(providers or [])
            ],
        })
    return items


# ----- shared search/sort helpers for list pages -----
def _apply_search(qs, q, field):
    """Case-insensitive substring search on ``field`` (escaped -- the value
    is user input and must never be interpreted as a regex)."""
    if q:
        return qs.filter(**{f"{field}__icontains": q})
    return qs


def _apply_sort(qs, sort, direction, sort_map, default):
    """Whitelisted server-side sort. ``sort_map`` maps a public sort key to a
    mongoengine order_by token; unknown keys fall back to ``default``."""
    token = sort_map.get(sort, default)
    if str(direction).lower() in ("desc", "descending", "-1") and not token.startswith("-"):
        token = "-" + token
    return qs.order_by(token)


# ====================== Live domains table ======================
# One $lookup aggregation over LiveSubdomains joined with Http: server-side
# search / CDN + HTTP-status filters / sorting / pagination. Never pulls the
# whole collection into Python.
_DOMAIN_SORTS = {
    "domain": "subdomain",
    "updated": "last_update",
    "cdn": "cdn",
    "status": "status_sort",
}


@router.get("/ui/domains", response_class=HTMLResponse)
def ui_domains(request: Request, program: Optional[str] = None,
               q: Optional[str] = None, cdn: Optional[str] = None,
               status: Optional[str] = None, sort: str = "updated",
               direction: str = "desc", page: int = 1, limit: int = 100):
    limit = min(max(limit, 10), 200)
    page = max(page, 1)
    skip = (page - 1) * limit

    match = {}
    if program:
        match["program_name"] = program
    if q:
        match["subdomain"] = {"$regex": re.escape(q), "$options": "i"}
    if cdn:
        match["cdn"] = cdn

    status_match = {
        "2xx": {"h.status_code": {"$gte": 200, "$lt": 300}},
        "3xx": {"h.status_code": {"$gte": 300, "$lt": 400}},
        "4xx": {"h.status_code": {"$gte": 400, "$lt": 500}},
        "5xx": {"h.status_code": {"$gte": 500, "$lt": 600}},
        "nohttp": {"h": {"$eq": {}}},
    }.get(status or "")

    http_coll = Http._get_collection().name
    sort_field = _DOMAIN_SORTS.get(sort, "last_update")
    sort_dir = -1 if str(direction).lower() in ("desc", "descending", "-1") else 1
    sort_spec = (
        {"status_sort": sort_dir} if sort_field == "status_sort"
        else {sort_field: sort_dir}
    )

    pipeline = [
        {"$match": match},
        {"$lookup": {
            "from": http_coll,
            "let": {"sub": "$subdomain", "prog": "$program_name"},
            "pipeline": [
                {"$match": {"$expr": {"$and": [
                    {"$eq": ["$subdomain", "$$sub"]},
                    {"$eq": ["$program_name", "$$prog"]},
                ]}}},
                {"$limit": 1},
                {"$project": {"_id": 0, "status_code": 1, "title": 1,
                              "tech": 1, "url": 1}},
            ],
            "as": "h",
        }},
        {"$unwind": {"path": "$h", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"h": {"$ifNull": ["$h", {}]},
                        "status_sort": {"$ifNull": ["$h.status_code", -1]}}},
    ]
    if status_match:
        pipeline.append({"$match": status_match})
    pipeline.append({"$facet": {
        "total": [{"$count": "count"}],
        "items": [{"$sort": sort_spec}, {"$skip": skip}, {"$limit": limit}],
    }})

    doc = next(iter(LiveSubdomains._get_collection().aggregate(pipeline, allowDiskUse=True)), None)
    total = doc["total"][0]["count"] if doc and doc.get("total") else 0
    items = []
    for row in (doc["items"] if doc else []):
        h = row.get("h") or {}
        items.append({
            "subdomain": row.get("subdomain"),
            "program_name": row.get("program_name"),
            "url": h.get("url") or f"https://{row.get('subdomain')}",
            "status_code": h.get("status_code"),
            "title": h.get("title") or "",
            "tech": ", ".join((h.get("tech") or [])[:4]),
            "cdn": row.get("cdn") or "Normal",
            "ips": ", ".join((row.get("ips") or [])[:2]),
            "last_update": row.get("last_update"),
            "ago": fmt_ago(row.get("last_update")),
            "stale": is_stale(row.get("last_update"), 7),
        })

    cdn_options = sorted({c for c in LiveSubdomains._get_collection().distinct("cdn") if c})
    program_options = sorted(dash._program_names())
    base_path = "/ui/domains"
    total_pages = max(1, (total + limit - 1) // limit)
    return templates.TemplateResponse(
        request,
        "domains.html",
        _ctx(
            request,
            active="domains",
            page_title="Live Domains",
            title="Live Domains",
            program=program or "",
            q=q or "",
            cdn=cdn or "",
            status=status or "",
            sort=sort,
            direction=direction,
            cdn_options=cdn_options,
            program_options=program_options,
            items=items,
            page=page,
            limit=limit,
            total=total,
            total_pages=total_pages,
            prev_url=build_url(base_path, program=program, q=q, cdn=cdn, status=status,
                               sort=sort, direction=direction, page=page - 1, limit=limit) if page > 1 else None,
            next_url=build_url(base_path, program=program, q=q, cdn=cdn, status=status,
                               sort=sort, direction=direction, page=page + 1, limit=limit) if page < total_pages else None,
        ),
    )


# ====================== Global HTTP table ======================
# Sidebar "HTTP" destination: every Http record across all programs, with
# server-side search / program filter / sorting / pagination. Same shape as
# the domains page but keyed on the HTTP record (so it also covers hosts the
# live-checker may not have re-confirmed).
_HTTP_SORTS = {
    "url": "url",
    "subdomain": "subdomain",
    "updated": "last_update",
    "status": "status_code",
}


@router.get("/ui/http", response_class=HTMLResponse)
def ui_http_all(request: Request, program: Optional[str] = None,
                q: Optional[str] = None, sort: str = "updated",
                direction: str = "desc", page: int = 1, limit: int = 100):
    limit = min(max(limit, 10), 200)
    page = max(page, 1)
    qs = Http.objects()
    if program:
        qs = qs(program_name=program)
    if q:
        qs = qs(__raw__={"$or": [
            {"subdomain": {"$regex": re.escape(q), "$options": "i"}},
            {"url": {"$regex": re.escape(q), "$options": "i"}},
            {"title": {"$regex": re.escape(q), "$options": "i"}},
        ]})
    qs = _apply_sort(qs, sort, direction, _HTTP_SORTS, "last_update")
    total = qs.count()
    items = []
    for h in paginate(qs, page, limit):
        items.append({
            "subdomain": h.subdomain,
            "program_name": h.program_name,
            "url": h.url or f"https://{h.subdomain}",
            "status_code": h.status_code,
            "title": h.title or "",
            "tech": ", ".join((h.tech or [])[:4]),
            "last_update": h.last_update,
            "ago": fmt_ago(h.last_update),
        })
    total_pages = max(1, (total + limit - 1) // limit)
    base = "/ui/http"
    return templates.TemplateResponse(
        request,
        "http_list.html",
        _ctx(
            request,
            active="http",
            page_title="HTTP",
            title="HTTP",
            program=program or "",
            q=q or "",
            sort=sort,
            direction=direction,
            program_options=sorted(dash._program_names()),
            items=items,
            page=page,
            limit=limit,
            total=total,
            total_pages=total_pages,
            prev_url=build_url(base, program=program, q=q, sort=sort,
                               direction=direction, page=page - 1, limit=limit) if page > 1 else None,
            next_url=build_url(base, program=program, q=q, sort=sort,
                               direction=direction, page=page + 1, limit=limit) if page < total_pages else None,
        ),
    )


# ====================== Global URLs list ======================
@router.get("/ui/urls", response_class=HTMLResponse)
def ui_urls_all(request: Request, program: Optional[str] = None,
                q: Optional[str] = None, page: int = 1, limit: int = 200):
    qs = Urls.objects()
    if program:
        qs = qs(program_name=program)
    qs = _apply_search(qs.only("url", "program_name"), q, "url")
    total = qs.count()
    items = [
        {"label": u.url, "url": u.url, "program_name": u.program_name}
        for u in paginate(qs, page, limit) if u.url
    ]
    return templates.TemplateResponse(
        request,
        "list_simple.html",
        _ctx(
            request,
            active="urls",
            page_title="URLs",
            title="URLs",
            items=items,
            q=q or "",
            **_paginated_list_ctx(
                base_path="/ui/urls", page=page, limit=limit, total=total,
                extra={"q": q, "program": program},
            ),
        ),
    )


# ====================== Global endpoints table ======================
_ENDPOINT_SORTS = {
    "path": "path",
    "hits": "hit_count",
    "updated": "last_update",
    "params": "params",
}


@router.get("/ui/endpoints", response_class=HTMLResponse)
def ui_endpoints_all(request: Request, program: Optional[str] = None,
                     q: Optional[str] = None, sort: str = "hits",
                     direction: str = "desc", page: int = 1, limit: int = 100):
    qs = Endpoints.objects()
    if program:
        qs = qs(program_name=program)
    if q:
        qs = qs(__raw__={"$or": [
            {"path": {"$regex": re.escape(q), "$options": "i"}},
            {"subdomain": {"$regex": re.escape(q), "$options": "i"}},
        ]})
    qs = _apply_sort(qs, sort, direction, _ENDPOINT_SORTS, "hit_count")
    total = qs.count()
    items = []
    for e in paginate(qs, page, limit):
        items.append({
            "path": e.path,
            "subdomain": e.subdomain,
            "program_name": e.program_name,
            "url": e.example_url or f"https://{e.subdomain}{e.path}",
            "hit_count": e.hit_count,
            "params": e.params or [],
            "params_str": ", ".join(e.params or []),
            "x8_checked": e.x8_checked,
        })
    total_pages = max(1, (total + limit - 1) // limit)
    base = "/ui/endpoints"
    return templates.TemplateResponse(
        request,
        "endpoints_list.html",
        _ctx(
            request,
            active="endpoints",
            page_title="Endpoints",
            title="Endpoints",
            program_name=program or "",
            program=program or "",
            sort_base=build_url("/ui/endpoints"),
            q=q or "",
            sort=sort,
            direction=direction,
            items=items,
            page=page,
            limit=limit,
            total=total,
            total_pages=total_pages,
            prev_url=build_url(base, program=program, q=q, sort=sort,
                               direction=direction, page=page - 1, limit=limit) if page > 1 else None,
            next_url=build_url(base, program=program, q=q, sort=sort,
                               direction=direction, page=page + 1, limit=limit) if page < total_pages else None,
        ),
    )


# ====================== Global parameters table ======================
# Distinct parameter names across all Endpoints, with how many endpoints /
# programs expose each. One $unwind+$group aggregation (capped by pagination),
# never a full collection pull.
_PARAM_SORTS = {"name": "_id", "count": "count", "programs": "programs"}


@router.get("/ui/parameters", response_class=HTMLResponse)
def ui_parameters(request: Request, q: Optional[str] = None,
                  sort: str = "count", direction: str = "desc",
                  page: int = 1, limit: int = 100):
    limit = min(max(limit, 10), 200)
    page = max(page, 1)
    skip = (page - 1) * limit

    match = {"params": {"$nin": ["", None]}}
    if q:
        match["params"] = {"$regex": re.escape(q), "$options": "i"}

    sort_field = _PARAM_SORTS.get(sort, "count")
    sort_dir = -1 if str(direction).lower() in ("desc", "descending", "-1") else 1
    pipeline = [
        {"$unwind": "$params"},
        {"$match": match},
        {"$group": {
            "_id": "$params",
            "count": {"$sum": 1},
            "programs": {"$addToSet": "$program_name"},
        }},
        {"$facet": {
            "total": [{"$count": "count"}],
            "items": [{"$sort": {sort_field: sort_dir}},
                      {"$skip": skip}, {"$limit": limit}],
        }},
    ]
    doc = next(iter(Endpoints._get_collection().aggregate(pipeline, allowDiskUse=True)), None)
    total = doc["total"][0]["count"] if doc and doc.get("total") else 0
    items = []
    for row in (doc["items"] if doc else []):
        progs = sorted(row.get("programs") or [])
        items.append({
            "name": row.get("_id"),
            "count": row.get("count", 0),
            "programs": progs,
            "program_count": len(progs),
        })
    total_pages = max(1, (total + limit - 1) // limit)
    base = "/ui/parameters"
    return templates.TemplateResponse(
        request,
        "parameters.html",
        _ctx(
            request,
            active="parameters",
            page_title="Parameters",
            title="Parameters",
            q=q or "",
            sort=sort,
            direction=direction,
            items=items,
            page=page,
            limit=limit,
            total=total,
            total_pages=total_pages,
            prev_url=build_url(base, q=q, sort=sort, direction=direction,
                               page=page - 1, limit=limit) if page > 1 else None,
            next_url=build_url(base, q=q, sort=sort, direction=direction,
                               page=page + 1, limit=limit) if page < total_pages else None,
        ),
    )


# ====================== Subdomain uniqueness page ======================
@router.get("/ui/subdomains/unique/{program_name}/{provider}", response_class=HTMLResponse)
def ui_subdomains_unique(request: Request, program_name: str, provider: str,
                          page: int = 1, limit: int = 100):
    rows, total = get_unique_provider_subdomains(program_name, provider, page, limit)
    title = f"{program_name} — Exclusive to: {provider}"
    return templates.TemplateResponse(
            request,
            "list_with_badges.html",
            _ctx(
            request,
            title=title,
            items=_http_or_subdomain_items(rows),
            **_paginated_list_ctx(
                base_path=f"/ui/subdomains/unique/{program_name}/{provider}",
                page=page, limit=limit, total=total,
            ),
        ),
    )


# ====================== HTML list pages ======================
@router.get("/ui/subdomains/program/{p_name}", response_class=HTMLResponse)
def ui_subdomains(request: Request, p_name: str, page: int = 1, limit: int = 100,
                  q: Optional[str] = None, sort: str = "subdomain",
                  direction: str = "asc"):
    qs = _apply_sort(
        _apply_search(Subdomains.objects(program_name=p_name).only("subdomain", "providers"), q, "subdomain"),
        sort, direction,
        {"subdomain": "subdomain", "updated": "last_update", "created": "created_date"},
        "subdomain",
    )
    total = qs.count()
    rows = [(s.subdomain, s.providers) for s in paginate(qs, page, limit)]
    return templates.TemplateResponse(
            request,
            "list_with_badges.html",
            _ctx(
            request,
            title=f"Subdomains — {p_name}",
            items=_http_or_subdomain_items(rows),
            q=q or "",
            sort=sort,
            direction=direction,
            **_paginated_list_ctx(
                base_path=f"/ui/subdomains/program/{p_name}",
                page=page, limit=limit, total=total,
                extra={"q": q, "sort": sort, "direction": direction},
            ),
        ),
    )


@router.get("/ui/lives/program/{p_name}", response_class=HTMLResponse)
def ui_lives(request: Request, p_name: str, page: int = 1, limit: int = 100,
             q: Optional[str] = None, sort: str = "subdomain", direction: str = "asc"):
    qs = _apply_sort(
        _apply_search(LiveSubdomains.objects(program_name=p_name).only("subdomain"), q, "subdomain"),
        sort, direction,
        {"subdomain": "subdomain", "updated": "last_update", "cdn": "cdn"},
        "subdomain",
    )
    total = qs.count()
    page_items = list(paginate(qs, page, limit))
    names = [s.subdomain for s in page_items]
    provider_map = {
        s.subdomain: s.providers
        for s in Subdomains.objects(program_name=p_name, subdomain__in=names).only("subdomain", "providers")
    }
    rows = [(n, provider_map.get(n, [])) for n in names]
    return templates.TemplateResponse(
            request,
            "list_with_badges.html",
            _ctx(
            request,
            title=f"Live Subdomains — {p_name}",
            items=_http_or_subdomain_items(rows),
            q=q or "",
            sort=sort,
            direction=direction,
            **_paginated_list_ctx(
                base_path=f"/ui/lives/program/{p_name}",
                page=page, limit=limit, total=total,
                extra={"q": q, "sort": sort, "direction": direction},
            ),
        ),
    )


@router.get("/ui/http/program/{p_name}", response_class=HTMLResponse)
def ui_http(request: Request, p_name: str, page: int = 1, limit: int = 100,
            q: Optional[str] = None):
    qs = _apply_search(Http.objects(program_name=p_name).only("url", "subdomain"), q, "subdomain")
    total = qs.count()
    names = [h.subdomain for h in qs if h.subdomain]
    provider_map = {
        s.subdomain: s.providers
        for s in Subdomains.objects(program_name=p_name, subdomain__in=names).only("subdomain", "providers")
    }
    items = []
    for h in paginate(qs, page, limit):
        if not h.url:
            continue
        items.append({
            "label": h.url,
            "url": h.url,
            "badges": [
                {"label": p, "bf": p in BF_PROVIDERS}
                for p in sorted(provider_map.get(h.subdomain, []))
            ],
        })
    return templates.TemplateResponse(
            request,
            "list_with_badges.html",
            _ctx(
            request,
            title=f"HTTP — {p_name}",
            items=items,
            q=q or "",
            **_paginated_list_ctx(
                base_path=f"/ui/http/program/{p_name}",
                page=page, limit=limit, total=total,
                extra={"q": q},
            ),
        ),
    )


@router.get("/ui/http/fresh", response_class=HTMLResponse)
def ui_http_fresh(request: Request, hours: int = 24, page: int = 1, limit: int = 100):
    cutoff = datetime.now() - timedelta(hours=hours)
    qs = Http.objects(created_date__gte=cutoff).only("url", "subdomain")
    total = qs.count()
    items = []
    names = [h.subdomain for h in qs if h.subdomain]
    provider_map = {
        s.subdomain: s.providers
        for s in Subdomains.objects(subdomain__in=names).only("subdomain", "providers")
    }
    for h in paginate(qs, page, limit):
        if not h.url:
            continue
        items.append({
            "label": h.url,
            "url": h.url,
            "badges": [
                {"label": p, "bf": p in BF_PROVIDERS}
                for p in sorted(provider_map.get(h.subdomain, []))
            ],
        })
    return templates.TemplateResponse(
            request,
            "list_with_badges.html",
            _ctx(
            request,
            title=f"Fresh HTTP ({hours}h)",
            items=items,
            **_paginated_list_ctx(
                base_path=f"/ui/http/fresh?hours={hours}",
                page=page, limit=limit, total=total,
            ),
        ),
    )


@router.get("/ui/http/provider/{program_name}/{provider}", response_class=HTMLResponse)
def ui_http_provider(request: Request, program_name: str, provider: str,
                      page: int = 1, limit: int = 100):
    """Same $lookup+$facet approach as provider_counts() -- avoids pulling
    thousands of subdomain names into Python before querying Http."""
    sub_coll = Subdomains._get_collection()
    http_coll_name = Http._get_collection().name
    page = max(page, 1)
    skip = (page - 1) * limit

    pipeline = [
        {"$match": {"program_name": program_name, "providers": provider}},
        {"$lookup": {
            "from": http_coll_name,
            "let": {"sub": "$subdomain", "prog": "$program_name"},
            "pipeline": [
                {"$match": {"$expr": {"$and": [
                    {"$eq": ["$subdomain", "$$sub"]},
                    {"$eq": ["$program_name", "$$prog"]},
                ]}}},
                {"$project": {"_id": 0, "url": 1, "subdomain": 1}},
            ],
            "as": "http_match",
        }},
        {"$unwind": "$http_match"},
        {"$facet": {
            "total": [{"$count": "count"}],
            "items": [{"$skip": skip}, {"$limit": limit}],
        }},
    ]
    result = list(sub_coll.aggregate(pipeline))
    total, items = 0, []
    if result:
        doc = result[0]
        total = doc["total"][0]["count"] if doc["total"] else 0
        items = [i["http_match"] for i in doc["items"]]

    items_html = []
    for i in items:
        url = i.get("url")
        if not url:
            continue
        items_html.append({
            "label": url, "url": url,
            "badges": [{"label": provider, "bf": provider in BF_PROVIDERS}],
        })

    return templates.TemplateResponse(
            request,
            "list_with_badges.html",
            _ctx(
            request,
            title=f"{program_name} — Provider: {provider}",
            items=items_html,
            **_paginated_list_ctx(
                base_path=f"/ui/http/provider/{program_name}/{provider}",
                page=page, limit=limit, total=total,
            ),
        ),
    )


@router.get("/ui/http/tech/{program_name}/{tech}", response_class=HTMLResponse)
def ui_http_tech(request: Request, program_name: str, tech: str,
                  page: int = 1, limit: int = 100):
    qs = Http.objects(program_name=program_name, tech=tech).only("url", "subdomain")
    total = qs.count()
    items = [
        {"label": h.url, "url": h.url, "badges": []}
        for h in paginate(qs, page, limit) if h.url
    ]
    return templates.TemplateResponse(
            request,
            "list_with_badges.html",
            _ctx(
            request,
            title=f"{program_name} — Tech: {tech}",
            items=items,
            **_paginated_list_ctx(
                base_path=f"/ui/http/tech/{program_name}/{tech}",
                page=page, limit=limit, total=total,
            ),
        ),
    )


@router.get("/ui/urls/program/{p_name}", response_class=HTMLResponse)
def ui_urls(request: Request, p_name: str, page: int = 1, limit: int = 200,
            q: Optional[str] = None):
    qs = _apply_search(Urls.objects(program_name=p_name).only("url"), q, "url")
    total = qs.count()
    items = [{"label": u.url, "url": u.url} for u in paginate(qs, page, limit) if u.url]
    return templates.TemplateResponse(
            request,
            "list_simple.html",
            _ctx(
            request,
            active="urls",
            page_title=f"URLs — {p_name}",
            title=f"URLs — {p_name}",
            items=items,
            q=q or "",
            **_paginated_list_ctx(
                base_path=f"/ui/urls/program/{p_name}",
                page=page, limit=limit, total=total,
                extra={"q": q},
            ),
        ),
    )


@router.get("/ui/endpoints/program/{p_name}", response_class=HTMLResponse)
def ui_endpoints(request: Request, p_name: str, page: int = 1, limit: int = 100,
                 q: Optional[str] = None, sort: str = "hits",
                 direction: str = "desc"):
    qs = _apply_sort(
        _apply_search(Endpoints.objects(program_name=p_name), q, "path"),
        sort, direction, _ENDPOINT_SORTS, "hit_count",
    )
    total = qs.count()
    items = []
    for e in paginate(qs, page, limit):
        link = e.example_url or f"https://{e.subdomain}{e.path}"
        params_str = ", ".join(e.params) if e.params else ""
        items.append({
            "path": e.path,
            "subdomain": e.subdomain,
            "program_name": p_name,
            "url": link,
            "hit_count": e.hit_count,
            "params_str": params_str,
            "params": e.params or [],
            "x8_checked": e.x8_checked,
        })
    return templates.TemplateResponse(
            request,
            "endpoints_list.html",
            _ctx(
            request,
            active="endpoints",
            page_title=f"Endpoints — {p_name}",
            title=f"Endpoints — {p_name}",
            program_name=p_name,
            program="",
            sort_base=build_url(f"/ui/endpoints/program/{p_name}"),
            q=q or "",
            sort=sort,
            direction=direction,
            items=items,
            **_paginated_list_ctx(
                base_path=f"/ui/endpoints/program/{p_name}",
                page=page, limit=limit, total=total,
                extra={"q": q, "sort": sort, "direction": direction},
            ),
        ),
    )


@router.get("/ui/dns-bruteforce/status", response_class=HTMLResponse)
def ui_dns_bruteforce_status(request: Request, q: Optional[str] = None):
    from backend.tz import age_days, fmt_tehran
    statuses_raw = list(DnsBruteStatus.objects().order_by("program_name", "domain"))
    if q:
        ql = q.lower()
        statuses_raw = [s for s in statuses_raw
                        if ql in (s.program_name or "").lower() or ql in (s.domain or "").lower()]
    rendered = []
    for s in statuses_raw:
        static_days = age_days(s.last_static_run)
        dynamic_days = age_days(s.last_dynamic_run)
        rendered.append({
            "program_name": s.program_name,
            "domain": s.domain,
            "feasible": s.feasible,
            "last_static": fmt_tehran(s.last_static_run),
            "last_static_days": static_days,
            "last_static_stale": static_days is None or static_days > 8,
            "last_dynamic": fmt_tehran(s.last_dynamic_run),
            "last_dynamic_days": dynamic_days,
            "last_dynamic_stale": dynamic_days is None or dynamic_days > 8,
        })
    return templates.TemplateResponse(
            request,
            "dns_status.html",
            _ctx(request, active="dns", page_title="DNS Bruteforce", statuses=rendered, q=q or ""),
    )


# ====================== JSON API ======================
@router.get("/api/dns-bruteforce/status")
def api_dns_bruteforce_status():
    return [
        {
            "program_name": s.program_name,
            "domain": s.domain,
            "feasible": s.feasible,
            "last_static_run": s.last_static_run.isoformat() if s.last_static_run else None,
            "last_dynamic_run": s.last_dynamic_run.isoformat() if s.last_dynamic_run else None,
        }
        for s in DnsBruteStatus.objects().order_by("program_name", "domain")
    ]


@router.get("/api/stats/by-program")
def stats_by_program():
    """Per-program stats. Existing keys preserved; new keys (urls, endpoints,
    params, last-activity) added additively so current consumers are unaffected.
    Computed from the shared aggregation/cache layer: NO per-program .count()
    loops (constant number of whole-collection $group aggregations)."""
    from backend import dashboard as dash
    out = {}
    for row in dash.compute_program_rows(dash._program_names(), dash._metrics()):
        out[row["program_name"]] = {
            # --- legacy keys (unchanged) ---
            "subdomains": row["subdomains"],
            "live_subdomains": row["live"],
            "http": row["http"],
            "urls": row["urls"],
            "endpoints": row["endpoints"],
            # --- new keys ---
            "endpoints_with_params": row["endpoints_with_params"],
            "endpoints_x8_checked": row["endpoints_x8_checked"],
            "params": row["params"],
            "changes_24h": row["changes_24h"],
            "last_crawl": row["last_crawl"].isoformat() if row["last_crawl"] else None,
            "last_param_discovery": row["last_param"].isoformat() if row["last_param"] else None,
            "last_dns": row["last_dns"].isoformat() if row["last_dns"] else None,
            "last_activity": row["last_activity"].isoformat() if row["last_activity"] else None,
        }
    return out


@router.get("/api/stats")
def stats_total():
    return {
        "programs": Programs.objects().count(),
        "subdomains": Subdomains.objects().count(),
        "live_subdomains": LiveSubdomains.objects().count(),
        "http": Http.objects().count(),
        "urls": Urls.objects().count(),
        "endpoints": Endpoints.objects().count(),
    }


@router.get("/api/programs/all")
def all_programs():
    return {
        p.program_name: {"scopes": p.scopes, "ooscopes": p.ooscopes, "created_date": p.created_date}
        for p in Programs.objects().all()
    }


@router.get("/api/subdomains/all")
def all_subdomains(raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = Subdomains.objects().only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@router.get("/api/subdomains/program/{p_name}")
def subdomains_of_program(p_name: str, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = Subdomains.objects(program_name=p_name).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@router.get("/api/subdomains/domain/{domain}")
def subdomains_of_domain(domain: str, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = Subdomains.objects(scope=domain).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@router.get("/api/lives/all")
def all_lives(raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = LiveSubdomains.objects().only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@router.get("/api/lives/fresh")
def lives_fresh(hours: int = 24, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    cutoff = datetime.now() - timedelta(hours=hours)
    qs = LiveSubdomains.objects(created_date__gte=cutoff).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@router.get("/api/lives/program/{p_name}")
def lives_by_program(p_name: str, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = LiveSubdomains.objects(program_name=p_name).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@router.get("/api/lives/domain/{domain}")
def lives_by_domain(domain: str, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = LiveSubdomains.objects(scope=domain).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@router.get("/api/http/all")
def all_http(raw: Optional[int] = None, page: int = 1, limit: int = 200):
    qs = Http.objects().only("url")
    if raw == 1:
        return PlainTextResponse("\n".join(h.url for h in qs if h.url))
    return {"total": qs.count(), "page": page, "items": [h.url for h in paginate(qs, page, limit) if h.url]}


@router.get("/api/http/fresh")
def all_http_fresh(hours: int = 24, raw: Optional[int] = None, page: int = 1, limit: int = 200):
    cutoff = datetime.now() - timedelta(hours=hours)
    qs = Http.objects(created_date__gte=cutoff).only("url")
    if raw == 1:
        return PlainTextResponse("\n".join(h.url for h in qs if h.url))
    return {"total": qs.count(), "page": page, "items": [h.url for h in paginate(qs, page, limit) if h.url]}


@router.get("/api/http/tech/{program_name}/{tech}")
def http_by_tech(program_name: str, tech: str, raw: Optional[int] = None):
    qs = Http.objects(program_name=program_name, tech=tech).only("url")
    items = [h.url for h in qs if h.url]
    if raw == 1:
        return PlainTextResponse("\n".join(items))
    return {"total": len(items), "items": items}


@router.get("/api/urls")
def list_urls(
    program: Optional[str] = None,
    subdomain: Optional[str] = None,
    has_params: Optional[bool] = None,
    raw: Optional[int] = None,
    page: int = 1,
    limit: int = 200,
):
    q = {}
    if program:
        q["program_name"] = program
    if subdomain:
        q["subdomain"] = subdomain
    if has_params:
        q["params__ne"] = []
    qs = Urls.objects(**q).only("url")
    if raw == 1:
        return PlainTextResponse("\n".join(u.url for u in qs))
    return {"total": qs.count(), "page": page, "items": [u.url for u in paginate(qs, page, limit)]}


@router.get("/api/endpoints")
def list_endpoints(
    program: Optional[str] = None,
    subdomain: Optional[str] = None,
    checked: Optional[bool] = None,
    min_hits: Optional[int] = None,
    page: int = 1,
    limit: int = 200,
):
    q = {}
    if program:
        q["program_name"] = program
    if subdomain:
        q["subdomain"] = subdomain
    if checked is not None:
        q["x8_checked"] = checked
    if min_hits:
        q["hit_count__gte"] = min_hits
    qs = Endpoints.objects(**q).order_by("-hit_count")
    items = paginate(qs, page, limit)
    return {
        "total": qs.count(),
        "page": page,
        "items": [
            {
                "program_name": e.program_name, "subdomain": e.subdomain, "path": e.path,
                "example_url": e.example_url, "params": e.params,
                "hit_count": e.hit_count, "x8_checked": e.x8_checked,
            }
            for e in items
        ],
    }


@router.get("/api/wordlist/{program_name}", response_class=PlainTextResponse)
def wordlist_for_program(program_name: str):
    params = set()
    for e in Endpoints.objects(program_name=program_name).only("params"):
        params.update(e.params or [])
    return "\n".join(sorted(params))