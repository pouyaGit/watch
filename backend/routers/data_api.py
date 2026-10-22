"""JSON endpoints under /api (unchanged paths and behavior)."""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from backend.helpers import paginate
from database.db import Programs, Subdomains, LiveSubdomains, Http, Urls, Endpoints, DnsBruteStatus

router = APIRouter()


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


# ====================== JSON API (بدون تغییر نسبت به قبل) ======================
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


# HTTP: مسیرهای قدیمی -- crawl scripts بهشون وابسته‌ن، عوضشون نکن
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
