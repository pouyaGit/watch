"""
backend/routers/programs.py — All the existing Programs/Subdomains/LiveSubdomains
/Http/Urls/Endpoints/wordlists/dns-bruteforce-status routes, lifted from
api.py with the URL paths unchanged so nothing currently pointing at this
API breaks.

HTML routes now render via Jinja2 templates from web/templates/ instead of
string concatenation. The visual output is the same dark-theme look; the
classes/colors live in web/static/css/custom.css.

Phase 1 keeps the helper functions (paginate, build_url, provider_counts,
etc.) here -- they were local to api.py before.
"""
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from backend.deps import API_KEY, build_url, paginate
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

_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "web" / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _ctx(request: Request, **extra):
    base = {
        "request": request,
        "api_key_qs": API_KEY or "",
        "root_url": build_url("/"),
        "home_url": build_url("/"),
        "tasks_url": build_url("/ui/tasks"),
        "dns_url": build_url("/ui/dns-bruteforce/status"),
        "docs_url": build_url("/docs"),
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
def _paginated_list_ctx(*, base_path, page, limit, total):
    total_pages = max(1, (total + limit - 1) // limit)
    prev_url = build_url(base_path, page=page - 1, limit=limit) if page > 1 else None
    next_url = build_url(base_path, page=page + 1, limit=limit) if page < total_pages else None
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
def ui_subdomains(request: Request, p_name: str, page: int = 1, limit: int = 100):
    qs = Subdomains.objects(program_name=p_name).only("subdomain", "providers")
    total = qs.count()
    rows = [(s.subdomain, s.providers) for s in paginate(qs, page, limit)]
    return templates.TemplateResponse(
            request,
            "list_with_badges.html",
            _ctx(
            request,
            title=f"Subdomains — {p_name}",
            items=_http_or_subdomain_items(rows),
            **_paginated_list_ctx(
                base_path=f"/ui/subdomains/program/{p_name}",
                page=page, limit=limit, total=total,
            ),
        ),
    )


@router.get("/ui/lives/program/{p_name}", response_class=HTMLResponse)
def ui_lives(request: Request, p_name: str, page: int = 1, limit: int = 100):
    qs = LiveSubdomains.objects(program_name=p_name).only("subdomain")
    total = qs.count()
    page_items = list(paginate(qs, page, limit))
    names = [s.subdomain for s in page_items]
    provider_map = {
        s.subdomain: s.providers
        for s in Subdomains.objects(subdomain__in=names).only("subdomain", "providers")
    }
    rows = [(n, provider_map.get(n, [])) for n in names]
    return templates.TemplateResponse(
            request,
            "list_with_badges.html",
            _ctx(
            request,
            title=f"Live Subdomains — {p_name}",
            items=_http_or_subdomain_items(rows),
            **_paginated_list_ctx(
                base_path=f"/ui/lives/program/{p_name}",
                page=page, limit=limit, total=total,
            ),
        ),
    )


@router.get("/ui/http/program/{p_name}", response_class=HTMLResponse)
def ui_http(request: Request, p_name: str, page: int = 1, limit: int = 100):
    qs = Http.objects(program_name=p_name).only("url", "subdomain")
    total = qs.count()
    names = [h.subdomain for h in qs if h.subdomain]
    provider_map = {
        s.subdomain: s.providers
        for s in Subdomains.objects(subdomain__in=names).only("subdomain", "providers")
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
            **_paginated_list_ctx(
                base_path=f"/ui/http/program/{p_name}",
                page=page, limit=limit, total=total,
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
def ui_urls(request: Request, p_name: str, page: int = 1, limit: int = 200):
    qs = Urls.objects(program_name=p_name).only("url")
    total = qs.count()
    items = [{"label": u.url, "url": u.url} for u in paginate(qs, page, limit) if u.url]
    return templates.TemplateResponse(
            request,
            "list_simple.html",
            _ctx(
            request,
            title=f"URLs — {p_name}",
            items=items,
            **_paginated_list_ctx(
                base_path=f"/ui/urls/program/{p_name}",
                page=page, limit=limit, total=total,
            ),
        ),
    )


@router.get("/ui/endpoints/program/{p_name}", response_class=HTMLResponse)
def ui_endpoints(request: Request, p_name: str, page: int = 1, limit: int = 100):
    qs = Endpoints.objects(program_name=p_name).order_by("-hit_count")
    total = qs.count()
    items = []
    for e in paginate(qs, page, limit):
        link = e.example_url or f"https://{e.subdomain}{e.path}"
        params_str = ", ".join(e.params) if e.params else ""
        items.append({
            "path": e.path,
            "url": link,
            "hit_count": e.hit_count,
            "params_str": params_str,
        })
    return templates.TemplateResponse(
            request,
            "endpoints_list.html",
            _ctx(
            request,
            title=f"Endpoints — {p_name}",
            program_name=p_name,
            items=items,
            **_paginated_list_ctx(
                base_path=f"/ui/endpoints/program/{p_name}",
                page=page, limit=limit, total=total,
            ),
        ),
    )


@router.get("/ui/dns-bruteforce/status", response_class=HTMLResponse)
def ui_dns_bruteforce_status(request: Request):
    statuses = list(DnsBruteStatus.objects().order_by("program_name", "domain"))
    rendered = []
    for s in statuses:
        def fmt(dt):
            if not dt:
                return ("never", False)
            days_ago = (datetime.now() - dt).days
            return (f'{dt.strftime("%Y-%m-%d %H:%M")} ({days_ago}d ago)', days_ago > 8)
        last_static,    static_stale    = fmt(s.last_static_run)
        last_dynamic,   dynamic_stale   = fmt(s.last_dynamic_run)
        rendered.append({
            "program_name": s.program_name,
            "domain": s.domain,
            "feasible": s.feasible,
            "last_static": last_static,
            "last_static_stale": static_stale,
            "last_dynamic": last_dynamic,
            "last_dynamic_stale": dynamic_stale,
        })
    return templates.TemplateResponse(
            request,
            "dns_status.html",
            _ctx(request, statuses=rendered),
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
    out = {}
    for p in Programs.objects().only("program_name"):
        name = p.program_name
        out[name] = {
            "subdomains": Subdomains.objects(program_name=name).count(),
            "live_subdomains": LiveSubdomains.objects(program_name=name).count(),
            "http": Http.objects(program_name=name).count(),
            "urls": Urls.objects(program_name=name).count(),
            "endpoints": Endpoints.objects(program_name=name).count(),
            "endpoints_with_params": Endpoints.objects(program_name=name, params__ne=[]).count(),
            "endpoints_x8_checked": Endpoints.objects(program_name=name, x8_checked=True).count(),
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