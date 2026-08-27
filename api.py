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
from db import Programs, Subdomains, LiveSubdomains, Http, Urls, Endpoints, DnsBruteStatus
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
  .fresh-banner:hover { background:#2ea043; color:#0d1117; text-decoration:none; }  .badge-sm { display:inline-block; padding:1px 7px; margin-left:6px; font-size:11px;
              background:#21262d; border:1px solid #30363d; border-radius:10px; color:#8b949e; }
  .badge-sm.bf { background:#3d1a00; border-color:#ff8c00; color:#ffb84d; font-weight:600; }
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


def html_subdomain_list_page(title, rows, page, limit, total, base_path):
    """rows: list of (subdomain, providers_list) -- same as html_list_page but with
    provider badges shown next to each entry."""
    lis = ""
    for name, providers in rows:
        href = name if name.startswith("http") else f"https://{name}"
        badges = "".join(
            f'<span class="badge-sm{" bf" if p in BF_PROVIDERS else ""}">{p}</span>'
            for p in sorted(providers or [])
        )
        lis += f'<li><a href="{href}" target="_blank" rel="noopener">{name}</a>{badges}</li>\n'

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


def provider_counts(program_name, provider):
    """(found, live_http) -- computed with a single server-side aggregation
    (Mongo $lookup + $facet) instead of pulling thousands of subdomain names
    into Python and building a giant $in query. The old version was fetching
    up to ~14,600 full documents per provider per program on every dashboard
    load -- that's what was slowing the page down and causing timeouts."""
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


@app.get("/ui/subdomains/unique/{program_name}/{provider}", response_class=HTMLResponse)
def ui_subdomains_unique(program_name: str, provider: str, page: int = 1, limit: int = 100):
    rows, total = get_unique_provider_subdomains(program_name, provider, page, limit)
    title = f"{program_name} — Exclusive to: {provider}"
    return html_subdomain_list_page(title, rows, page, limit, total,
                                     f"/ui/subdomains/unique/{program_name}/{provider}")


# ====================== داشبورد اصلی ======================
@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Lightweight -- just counts, no cross-collection joins. Per-program
    detail (tech/provider badges, which need the expensive $lookup) lives on
    /ui/program/{name} now, computed one program at a time, only when opened."""
    programs = list(Programs.objects().all())

    fresh_count = Http.objects(created_date__gte=datetime.now() - timedelta(hours=24)).count()
    fresh_link = build_url("/ui/http/fresh")
    fresh_banner = f'<a class="fresh-banner" href="{fresh_link}">🆕 Fresh HTTP results (last 24h): {fresh_count}</a>'

    rows = ""
    for p in programs:
        name = p.program_name
        c_sub = Subdomains.objects(program_name=name).count()
        c_live = LiveSubdomains.objects(program_name=name).count()
        c_http = Http.objects(program_name=name).count()
        prog_link = build_url(f"/ui/program/{name}")
        rows += (
            f'<div class="program"><h3><a href="{prog_link}">{name}</a></h3>'
            f'<div class="links">'
            f'<a href="{prog_link}">Open program page</a>'
            f'<span class="note">Subdomains: {c_sub} | Live: {c_live} | HTTP: {c_http}</span>'
            f'</div></div>'
        )

    docs_link = build_url("/docs")
    stats_link = build_url("/api/stats/by-program")
    dnsbf_link = build_url("/ui/dns-bruteforce/status")
    body = (
        f"<h1>🔍 Watch Dashboard</h1>"
        f"{fresh_banner}"
        f"<p class='note'>Full API docs: <a href='{docs_link}'>/docs</a> | "
        f"Raw stats JSON: <a href='{stats_link}'>/api/stats/by-program</a> | "
        f"<a href='{dnsbf_link}'>DNS Bruteforce Status</a></p>"
        f"{rows}"
    )
    return HTMLResponse(render_page("Watch Dashboard", body))


@app.get("/ui/program/{name}", response_class=HTMLResponse)
def ui_program(name: str):
    """The detailed per-program view (tech badges, provider badges, exclusive
    finds). Split out from the main dashboard so opening it only computes
    for ONE program, not all of them at once."""
    c_sub = Subdomains.objects(program_name=name).count()
    c_live = LiveSubdomains.objects(program_name=name).count()
    c_http = Http.objects(program_name=name).count()
    c_urls = Urls.objects(program_name=name).count()
    c_eps = Endpoints.objects(program_name=name).count()

    techs = {t.strip() for t in Http.objects(program_name=name).distinct("tech") if t and t.strip()}
    tech_html = "".join(
        f'<a class="badge" href="{build_url(f"/ui/http/tech/{name}/{t}")}">{t}</a>'
        for t in sorted(techs)
    )

    # cheap counts only here -- no Http join. The found->live-http breakdown
    # is on the provider's own list page (computed once, on demand, there).
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

    unique_html = ""
    for provider in BF_PROVIDERS + PROVIDERS:
        count = unique_provider_count(name, provider)
        if count:
            cls = "badge badge-bf" if provider in BF_PROVIDERS else "badge"
            link = build_url(f"/ui/subdomains/unique/{name}/{provider}")
            unique_html += f'<a class="{cls}" href="{link}">{provider} only ({count})</a>'

    sub_link = build_url(f"/ui/subdomains/program/{name}")
    live_link = build_url(f"/ui/lives/program/{name}")
    http_link = build_url(f"/ui/http/program/{name}")
    urls_link = build_url(f"/ui/urls/program/{name}")
    eps_link = build_url(f"/ui/endpoints/program/{name}")
    wl_link = build_url(f"/api/wordlist/{name}")
    home = build_url("/")

    body = f"""
    <a href="{home}">← Back to Dashboard</a>
    <h2>{name}</h2>
    <div class="links">
      <a href="{sub_link}">Subdomains ({c_sub})</a>
      <a href="{live_link}">Live ({c_live})</a>
      <a href="{http_link}">HTTP ({c_http})</a>
      <a href="{urls_link}">URLs ({c_urls})</a>
      <a href="{eps_link}">Endpoints ({c_eps})</a>
      <a href="{wl_link}">Wordlist (txt)</a>
    </div>
    <div class="note" style="margin-top:12px;">Technologies:</div>
    <div class="techs">{tech_html}</div>
    <div class="note" style="margin-top:12px;">Providers (click for the found → live-http breakdown):</div>
    <div class="techs">{bf_html}{provider_html}</div>
    <div class="note" style="margin-top:12px;">Exclusive finds (this provider only, no overlap):</div>
    <div class="techs">{unique_html or '<span class="note">none</span>'}</div>
    """
    return HTMLResponse(render_page(f"Watch — {name}", body))
    return HTMLResponse(render_page("Watch Dashboard", body))


def html_url_list_page(title, http_objs, page, limit, total, base_path):
    """Same as html_subdomain_list_page but for Http documents (shows the URL,
    badges come from the underlying subdomain's providers)."""
    names = [h.subdomain for h in http_objs if h.subdomain]
    provider_map = {
        s.subdomain: s.providers
        for s in Subdomains.objects(subdomain__in=names).only("subdomain", "providers")
    }

    lis = ""
    for h in http_objs:
        if not h.url:
            continue
        badges = "".join(
            f'<span class="badge-sm{" bf" if p in BF_PROVIDERS else ""}">{p}</span>'
            for p in sorted(provider_map.get(h.subdomain, []))
        )
        lis += f'<li><a href="{h.url}" target="_blank" rel="noopener">{h.url}</a>{badges}</li>\n'

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


@app.get("/ui/http/fresh", response_class=HTMLResponse)
def ui_http_fresh(hours: int = 24, page: int = 1, limit: int = 100):
    cutoff = datetime.now() - timedelta(hours=hours)
    qs = Http.objects(created_date__gte=cutoff).only("url", "subdomain")
    total = qs.count()
    return html_url_list_page(f"Fresh HTTP ({hours}h)", list(paginate(qs, page, limit)),
                               page, limit, total, f"/ui/http/fresh?hours={hours}")


@app.get("/ui/http/provider/{program_name}/{provider}", response_class=HTMLResponse)
def ui_http_provider(program_name: str, provider: str, page: int = 1, limit: int = 100):
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

    class _Row:
        __slots__ = ("url", "subdomain")
        def __init__(self, url, subdomain):
            self.url, self.subdomain = url, subdomain

    rows = [_Row(i.get("url"), i.get("subdomain")) for i in items]
    title = f"{program_name} — Provider: {provider}"
    return html_url_list_page(title, rows, page, limit, total,
                               f"/ui/http/provider/{program_name}/{provider}")


# ====================== صفحات HTML قابل مرور ======================
@app.get("/ui/subdomains/program/{p_name}", response_class=HTMLResponse)
def ui_subdomains(p_name: str, page: int = 1, limit: int = 100):
    qs = Subdomains.objects(program_name=p_name).only("subdomain", "providers")
    total = qs.count()
    rows = [(s.subdomain, s.providers) for s in paginate(qs, page, limit)]
    return html_subdomain_list_page(f"Subdomains — {p_name}", rows, page, limit, total, f"/ui/subdomains/program/{p_name}")


@app.get("/ui/lives/program/{p_name}", response_class=HTMLResponse)
def ui_lives(p_name: str, page: int = 1, limit: int = 100):
    qs = LiveSubdomains.objects(program_name=p_name).only("subdomain")
    total = qs.count()
    page_items = list(paginate(qs, page, limit))
    names = [s.subdomain for s in page_items]
    # LiveSubdomains has no providers field -- join with Subdomains for this page only
    provider_map = {
        s.subdomain: s.providers
        for s in Subdomains.objects(subdomain__in=names).only("subdomain", "providers")
    }
    rows = [(n, provider_map.get(n, [])) for n in names]
    return html_subdomain_list_page(f"Live Subdomains — {p_name}", rows, page, limit, total, f"/ui/lives/program/{p_name}")


@app.get("/ui/http/program/{p_name}", response_class=HTMLResponse)
def ui_http(p_name: str, page: int = 1, limit: int = 100):
    qs = Http.objects(program_name=p_name).only("url", "subdomain")
    total = qs.count()
    return html_url_list_page(f"HTTP — {p_name}", list(paginate(qs, page, limit)),
                               page, limit, total, f"/ui/http/program/{p_name}")


@app.get("/ui/http/tech/{program_name}/{tech}", response_class=HTMLResponse)
def ui_http_tech(program_name: str, tech: str, page: int = 1, limit: int = 100):
    qs = Http.objects(program_name=program_name, tech=tech).only("url", "subdomain")
    total = qs.count()
    return html_url_list_page(f"{program_name} — Tech: {tech}", list(paginate(qs, page, limit)),
                               page, limit, total, f"/ui/http/tech/{program_name}/{tech}")


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


@app.get("/ui/dns-bruteforce/status", response_class=HTMLResponse)
def ui_dns_bruteforce_status():
    """Health-check page for the weekly DNS bruteforce jobs -- shows, per
    domain, whether it's feasible and when static/dynamic last actually ran.
    This is the quickest way to confirm the jobs are alive and progressing
    without digging through Telegram history or journalctl."""
    statuses = list(DnsBruteStatus.objects().order_by("program_name", "domain"))

    def fmt(dt):
        if not dt:
            return '<span class="note">never</span>'
        days_ago = (datetime.now() - dt).days
        stale = ' style="color:#f85149;"' if days_ago > 8 else ""
        return f'<span{stale}>{dt.strftime("%Y-%m-%d %H:%M")} ({days_ago}d ago)</span>'

    rows = ""
    for s in statuses:
        feasible_badge = (
            '<span class="badge" style="border-color:#3fb950;color:#3fb950;">yes</span>'
            if s.feasible else
            '<span class="badge" style="border-color:#f85149;color:#f85149;">no (wildcard)</span>'
        )
        rows += (
            f"<tr><td>{s.program_name}</td><td>{s.domain}</td><td>{feasible_badge}</td>"
            f"<td>{fmt(s.last_static_run)}</td><td>{fmt(s.last_dynamic_run)}</td></tr>"
        )

    home = build_url("/")
    body = f"""
    <a href="{home}">← Back to Dashboard</a>
    <h2>DNS Bruteforce Status</h2>
    <p class="note">Red timestamp = more than 8 days since last run (something's probably stuck --
    check <code>systemctl status watch-dns-static</code> / <code>watch-dns-dynamic</code>).</p>
    <table style="width:100%; border-collapse:collapse;">
      <tr style="text-align:left; border-bottom:1px solid #30363d;">
        <th style="padding:6px;">Program</th><th>Domain</th><th>Feasible</th>
        <th>Last static run</th><th>Last dynamic run</th>
      </tr>
      {rows}
    </table>
    """
    return HTMLResponse(render_page("DNS Bruteforce Status", body))


@app.get("/api/dns-bruteforce/status")
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