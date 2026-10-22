"""Shared helpers for the HTML and JSON routers."""
import json
from datetime import datetime, timedelta
from urllib.parse import parse_qs

from fastapi.responses import HTMLResponse

from backend.templating import templates
from database.db import Subdomains, LiveSubdomains, Http, Urls, Endpoints

PAGE_LIMIT_MAX = 500
PAGE_CSS = '<link rel="stylesheet" href="/static/css/app.css">'


def paginate(qs, page: int, limit: int):
    limit = min(max(limit, 1), PAGE_LIMIT_MAX)
    page = max(page, 1)
    return qs.skip((page - 1) * limit).limit(limit)


def build_url(path, **params):
    qs ="&".join(f"{k}={v}" for k, v in params.items() if v is not None)
    return f"{path}?{qs}" if qs else path


def render_page(title, body_html):
    return templates.get_template("legacy.html").render(title=title, body=body_html)


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


async def read_params(request) -> dict:
    body = await request.body()
    if "application/json" in request.headers.get("content-type", ""):
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            raise ValueError("request body is not valid JSON")
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        return data
    parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
    return {k: (v if len(v) > 1 else v[0]) for k, v in parsed.items()}
