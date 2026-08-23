#!/usr/bin/env python3
"""
api.py — API + داشبورد سبک برای پروژه‌ی Watch (جایگزین app.py قدیمی Flask)

اضافه شده نسبت به نسخه‌ی قبلی:
- داشبورد HTML رو "/" (شبیه صفحه‌ی اصلی app.py قدیمی: لیست برنامه‌ها، تکنولوژی‌ها، لینک‌ها)
- صفحات HTML قابل مرور برای subdomains/lives/http/urls/endpoints (با pagination)
- auth با API key، هم از هدر X-API-Key هم از ?api_key= تو URL (برای مرور راحت با کلیک)
- /docs و /openapi.json از auth مستثنی‌ان تا مستندات همیشه لود بشه

اجرا: python3 api.py   (یا از طریق systemd سرویس)
"""

import sys
import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.responses import PlainTextResponse, RedirectResponse, HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'database')))
from db import Programs, Subdomains, LiveSubdomains, Http, Urls, Endpoints
from config import config

API_KEY = config().get("API_KEY", "")
EXEMPT_PATHS = {"/docs", "/redoc", "/openapi.json"}
PAGE_LIMIT_MAX = 500


# ====================== AUTH (هدر یا query param، برای راحتی مرور) ======================
class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not API_KEY or request.url.path in EXEMPT_PATHS:
            return await call_next(request)
        key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
        if key != API_KEY:
            return JSONResponse(
                {"detail": "Invalid or missing API key (header X-API-Key or ?api_key=...)"},
                status_code=401,
            )
        return await call_next(request)


app = FastAPI(title="Watch API")
app.add_middleware(APIKeyMiddleware)


def paginate(qs, page: int, limit: int):
    limit = min(max(limit, 1), PAGE_LIMIT_MAX)
    page = max(page, 1)
    return qs.skip((page - 1) * limit).limit(limit)


def build_url(path, **params):
    """لینک می‌سازه و اگه API_KEY ست شده، ?api_key= رو خودکار بهش اضافه می‌کنه
    تا کلیک روی لینک‌های داشبورد بدون نیاز به دستی زدن کلید کار کنه."""
    if API_KEY:
        params["api_key"] = API_KEY
    qs = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
    return f"{path}?{qs}" if qs else path


# ====================== ظاهر مشترک صفحات HTML ======================
PAGE_CSS = """
<style>
  body { font-family: 'Segoe UI', system-ui, sans-serif; background:#0d1117; color:#e6edf3;
         max-width:1100px; margin:30px auto; padding:20px; }
  h1 { color:#58a6ff; } h2 { color:#f0883e; } h3 { margin-bottom:4px; color:#58a6ff; }
  a { color:#58a6ff; text-decoration:none; }
  a:hover { color:#ff6b6b; text-decoration:underline; }
  .program { border:1px solid #30363d; border-radius:8px; padding:14px 18px; margin:14px 0; background:#161b22; }
  .links a, .badge { display:inline-block; padding:4px 10px; margin:3px 4px 3px 0;
                      background:#21262d; border:1px solid #30363d; border-radius:6px; font-size:13px; }
  .links a:hover, .badge:hover { background:#1f6feb; color:white; }
  .techs { margin-top:8px; }
  ul { padding-left:20px; } li { margin:4px 0; word-break:break-all; }
  .pagenav { color:#8b949e; margin:12px 0; }
  .badge-bf { background:#3d1a00; border:1px solid #ff8c00; color:#ffb84d; font-weight:600; }
  .badge-bf:hover { background:#ff8c00; color:#0d1117; }
  .fresh-banner { display:block; background:#122a1a; border:1px solid #2ea043; border-radius:8px;
                  padding:10px 16px; margin:16px 0; color:#3fb950; font-weight:600; }
  .fresh-banner:hover { background:#2ea043; color:#0d1117; text-decoration:none; }
</style>
"""


def render_page(title, body_html):
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{title}</title>{PAGE_CSS}</head><body>{body_html}</body></html>"


def html_list_page(title, items, page, limit, total, base_path):
    lis = ""
    for item in items:
        href = item if item.startswith("http") else f"https://{item}"
        lis += f'<li><a href="{href}" target="_blank" rel="noopener">{item}</a></li>\n'

    total_pages = max(1, (total + limit - 1) // limit)
    nav = f'<div class="pagenav">Page {page}/{total_pages} — total {total}'
    if page > 1:
        nav += f' | <a href="{build_url(base_path, page=page-1, limit=limit)}">« Prev</a>'
    if page < total_pages:
        nav += f' | <a href="{build_url(base_path, page=page+1, limit=limit)}">Next »</a>'
    nav += "</div>"

    home = build_url("/")
    body = f"<h2>{title}</h2>{nav}<ul>{lis}</ul>{nav}<br><a href='{home}'>← Back to Dashboard</a>"
    return HTMLResponse(render_page(title, body))


PROVIDERS = ["subfinder", "crtsh", "findomain", "assetfinder", "abuseipdb", "waybackurls"]
BF_PROVIDERS = ["staticBF", "dynamicBF"]  # shown first, styled distinctly -- highest-value finds


# ====================== داشبورد اصلی ======================
@app.get("/", response_class=HTMLResponse)
def dashboard():
    programs = list(Programs.objects().all())

    fresh_count = Http.objects(created_date__gte=datetime.now() - timedelta(hours=24)).count()
    fresh_link = build_url("/ui/http/fresh")
    fresh_banner = f'<a class="fresh-banner" href="{fresh_link}">🆕 Fresh HTTP results (last 24h): {fresh_count}</a>'

    sections = ""
    for p in programs:
        name = p.program_name
        c_sub = Subdomains.objects(program_name=name).count()
        c_live = LiveSubdomains.objects(program_name=name).count()
        c_http = Http.objects(program_name=name).count()
        c_urls = Urls.objects(program_name=name).count()
        c_eps = Endpoints.objects(program_name=name).count()

        techs = set()
        for h in Http.objects(program_name=name).only("tech"):
            if h.tech:
                techs.update(t.strip() for t in h.tech if t and t.strip())

        tech_html = "".join(
            f'<a class="badge" href="{build_url(f"/ui/http/tech/{name}/{t}")}">{t}</a>'
            for t in sorted(techs)
        )

        # bruteforce providers first and visually distinct, then the rest
        bf_html = ""
        for provider in BF_PROVIDERS:
            count = Subdomains.objects(program_name=name, providers=provider).count()
            if count:
                link = build_url(f"/ui/http/provider/{name}/{provider}")
                bf_html += f'<a class="badge badge-bf" href="{link}">🔥 {provider} ({count})</a>'

        provider_html = ""
        for provider in PROVIDERS:
            count = Subdomains.objects(program_name=name, providers=provider).count()
            if count:
                link = build_url(f"/ui/http/provider/{name}/{provider}")
                provider_html += f'<a class="badge" href="{link}">{provider} ({count})</a>'

        sub_link = build_url(f"/ui/subdomains/program/{name}")
        live_link = build_url(f"/ui/lives/program/{name}")
        http_link = build_url(f"/ui/http/program/{name}")
        urls_link = build_url(f"/ui/urls/program/{name}")
        eps_link = build_url(f"/ui/endpoints/program/{name}")
        wl_link = build_url(f"/api/wordlist/{name}")

        sections += f"""
        <div class="program">
          <h3>{name}</h3>
          <div class="links">
            <a href="{sub_link}">Subdomains ({c_sub})</a>
            <a href="{live_link}">Live ({c_live})</a>
            <a href="{http_link}">HTTP ({c_http})</a>
            <a href="{urls_link}">URLs ({c_urls})</a>
            <a href="{eps_link}">Endpoints ({c_eps})</a>
            <a href="{wl_link}">Wordlist (txt)</a>
          </div>
          <div class="techs">{tech_html}</div>
          <div class="techs">{bf_html}{provider_html}</div>
        </div>
        """

    docs_link = build_url("/docs")
    stats_link = build_url("/api/stats/by-program")
    body = (
        f"<h1>🔍 Watch Dashboard</h1>"
        f"{fresh_banner}"
        f"<p class='note'>Full API docs: <a href='{docs_link}'>/docs</a> | "
        f"Raw stats JSON: <a href='{stats_link}'>/api/stats/by-program</a></p>"
        f"{sections}"
    )
    return HTMLResponse(render_page("Watch Dashboard", body))


@app.get("/ui/http/fresh", response_class=HTMLResponse)
def ui_http_fresh(hours: int = 24, page: int = 1, limit: int = 100):
    cutoff = datetime.now() - timedelta(hours=hours)
    qs = Http.objects(created_date__gte=cutoff).only("url")
    total = qs.count()
    items = [h.url for h in paginate(qs, page, limit) if h.url]
    return html_list_page(f"Fresh HTTP ({hours}h)", items, page, limit, total, f"/ui/http/fresh?hours={hours}")


@app.get("/ui/http/provider/{program_name}/{provider}", response_class=HTMLResponse)
def ui_http_provider(program_name: str, provider: str, page: int = 1, limit: int = 100):
    """Http results don't store 'provider' directly -- it lives on Subdomains.
    Join: find subdomains tagged with this provider, then their Http records."""
    sub_names = [
        s.subdomain for s in Subdomains.objects(program_name=program_name, providers=provider).only("subdomain")
    ]
    qs = Http.objects(subdomain__in=sub_names).only("url")
    total = qs.count()
    items = [h.url for h in paginate(qs, page, limit) if h.url]
    title = f"{program_name} — Provider: {provider}"
    return html_list_page(title, items, page, limit, total, f"/ui/http/provider/{program_name}/{provider}")


# ====================== صفحات HTML قابل مرور ======================
@app.get("/ui/subdomains/program/{p_name}", response_class=HTMLResponse)
def ui_subdomains(p_name: str, page: int = 1, limit: int = 100):
    qs = Subdomains.objects(program_name=p_name).only("subdomain")
    total = qs.count()
    items = [s.subdomain for s in paginate(qs, page, limit)]
    return html_list_page(f"Subdomains — {p_name}", items, page, limit, total, f"/ui/subdomains/program/{p_name}")


@app.get("/ui/lives/program/{p_name}", response_class=HTMLResponse)
def ui_lives(p_name: str, page: int = 1, limit: int = 100):
    qs = LiveSubdomains.objects(program_name=p_name).only("subdomain")
    total = qs.count()
    items = [s.subdomain for s in paginate(qs, page, limit)]
    return html_list_page(f"Live Subdomains — {p_name}", items, page, limit, total, f"/ui/lives/program/{p_name}")


@app.get("/ui/http/program/{p_name}", response_class=HTMLResponse)
def ui_http(p_name: str, page: int = 1, limit: int = 100):
    qs = Http.objects(program_name=p_name).only("url")
    total = qs.count()
    items = [h.url for h in paginate(qs, page, limit) if h.url]
    return html_list_page(f"HTTP — {p_name}", items, page, limit, total, f"/ui/http/program/{p_name}")


@app.get("/ui/http/tech/{program_name}/{tech}", response_class=HTMLResponse)
def ui_http_tech(program_name: str, tech: str, page: int = 1, limit: int = 100):
    qs = Http.objects(program_name=program_name, tech=tech).only("url")
    total = qs.count()
    items = [h.url for h in paginate(qs, page, limit) if h.url]
    return html_list_page(f"{program_name} — Tech: {tech}", items, page, limit, total, f"/ui/http/tech/{program_name}/{tech}")


@app.get("/ui/urls/program/{p_name}", response_class=HTMLResponse)
def ui_urls(p_name: str, page: int = 1, limit: int = 200):
    qs = Urls.objects(program_name=p_name).only("url")
    total = qs.count()
    items = [u.url for u in paginate(qs, page, limit)]
    return html_list_page(f"URLs — {p_name}", items, page, limit, total, f"/ui/urls/program/{p_name}")


@app.get("/ui/endpoints/program/{p_name}", response_class=HTMLResponse)
def ui_endpoints(p_name: str, page: int = 1, limit: int = 100):
    qs = Endpoints.objects(program_name=p_name).order_by("-hit_count")
    total = qs.count()
    lis = ""
    for e in paginate(qs, page, limit):
        params_str = f" — params: {', '.join(e.params)}" if e.params else ""
        link = e.example_url or f"https://{e.subdomain}{e.path}"
        lis += f'<li><a href="{link}" target="_blank" rel="noopener">{e.path}</a> (hits: {e.hit_count}){params_str}</li>\n'
    total_pages = max(1, (total + limit - 1) // limit)
    nav = f'<div class="pagenav">Page {page}/{total_pages} — total {total}'
    if page > 1:
        nav += f' | <a href="{build_url(f"/ui/endpoints/program/{p_name}", page=page-1, limit=limit)}">« Prev</a>'
    if page < total_pages:
        nav += f' | <a href="{build_url(f"/ui/endpoints/program/{p_name}", page=page+1, limit=limit)}">Next »</a>'
    nav += "</div>"
    home = build_url("/")
    body = f"<h2>Endpoints — {p_name}</h2>{nav}<ul>{lis}</ul>{nav}<br><a href='{home}'>← Back to Dashboard</a>"
    return HTMLResponse(render_page(f"Endpoints — {p_name}", body))


# ====================== JSON API (بدون تغییر نسبت به قبل) ======================
@app.get("/api/stats/by-program")
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


@app.get("/api/stats")
def stats_total():
    return {
        "programs": Programs.objects().count(),
        "subdomains": Subdomains.objects().count(),
        "live_subdomains": LiveSubdomains.objects().count(),
        "http": Http.objects().count(),
        "urls": Urls.objects().count(),
        "endpoints": Endpoints.objects().count(),
    }


@app.get("/api/programs/all")
def all_programs():
    return {
        p.program_name: {"scopes": p.scopes, "ooscopes": p.ooscopes, "created_date": p.created_date}
        for p in Programs.objects().all()
    }


@app.get("/api/subdomains/all")
def all_subdomains(raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = Subdomains.objects().only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@app.get("/api/subdomains/program/{p_name}")
def subdomains_of_program(p_name: str, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = Subdomains.objects(program_name=p_name).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@app.get("/api/subdomains/domain/{domain}")
def subdomains_of_domain(domain: str, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = Subdomains.objects(scope=domain).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@app.get("/api/lives/all")
def all_lives(raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = LiveSubdomains.objects().only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@app.get("/api/lives/fresh")
def lives_fresh(hours: int = 24, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    cutoff = datetime.now() - timedelta(hours=hours)
    qs = LiveSubdomains.objects(created_date__gte=cutoff).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@app.get("/api/lives/program/{p_name}")
def lives_by_program(p_name: str, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = LiveSubdomains.objects(program_name=p_name).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


@app.get("/api/lives/domain/{domain}")
def lives_by_domain(domain: str, raw: Optional[int] = None, page: int = 1, limit: int = 100):
    qs = LiveSubdomains.objects(scope=domain).only("subdomain")
    if raw == 1:
        return PlainTextResponse("\n".join(s.subdomain for s in qs))
    return {"total": qs.count(), "page": page, "items": [s.subdomain for s in paginate(qs, page, limit)]}


# HTTP: مسیرهای قدیمی -- crawl scripts بهشون وابسته‌ن، عوضشون نکن
@app.get("/api/http/all")
def all_http(raw: Optional[int] = None, page: int = 1, limit: int = 200):
    qs = Http.objects().only("url")
    if raw == 1:
        return PlainTextResponse("\n".join(h.url for h in qs if h.url))
    return {"total": qs.count(), "page": page, "items": [h.url for h in paginate(qs, page, limit) if h.url]}


@app.get("/api/http/fresh")
def all_http_fresh(hours: int = 24, raw: Optional[int] = None, page: int = 1, limit: int = 200):
    cutoff = datetime.now() - timedelta(hours=hours)
    qs = Http.objects(created_date__gte=cutoff).only("url")
    if raw == 1:
        return PlainTextResponse("\n".join(h.url for h in qs if h.url))
    return {"total": qs.count(), "page": page, "items": [h.url for h in paginate(qs, page, limit) if h.url]}


@app.get("/api/http/tech/{program_name}/{tech}")
def http_by_tech(program_name: str, tech: str, raw: Optional[int] = None):
    qs = Http.objects(program_name=program_name, tech=tech).only("url")
    items = [h.url for h in qs if h.url]
    if raw == 1:
        return PlainTextResponse("\n".join(items))
    return {"total": len(items), "items": items}


@app.get("/api/urls")
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


@app.get("/api/endpoints")
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


@app.get("/api/wordlist/{program_name}", response_class=PlainTextResponse)
def wordlist_for_program(program_name: str):
    params = set()
    for e in Endpoints.objects(program_name=program_name).only("params"):
        params.update(e.params or [])
    return "\n".join(sorted(params))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)