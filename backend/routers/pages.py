"""HTML pages. Console pages render Jinja templates; legacy list pages keep their paths."""
import html
from datetime import datetime, timedelta
from urllib.parse import urlencode

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from backend.helpers import (
    build_url, html_list_page, html_subdomain_list_page, html_url_list_page, paginate, render_page,
    unique_provider_count, get_unique_provider_subdomains, BF_PROVIDERS, PROVIDERS,
)
from backend.models import TaskRun
from backend.search import SearchError, run_search
from backend.task_runner import ACTIVE_STATUSES, list_runs, read_log_tail, reconcile, serialize_run
from backend.tasks_registry import TASKS_REGISTRY, TOOL_TO_TASK
from backend.templating import templates
from database.change_events import event_label, recent_events
from database.db import (
    DnsBruteStatus, Endpoints, Finding, Http, LiveSubdomains, Programs, Subdomains, Urls,
)

router = APIRouter()

FINDING_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
FINDING_COLORS = {
    "critical": "#ff4d4f", "high": "#f85149", "medium": "#d29922",
    "low": "#58a6ff", "info": "#8b949e", "unknown": "#8b949e",
}


def _esc(value):
    return html.escape(str(value or ""))


def _severity_badge(severity):
    color = FINDING_COLORS.get(severity, FINDING_COLORS["unknown"])
    return f'<span class="badge" style="border-color:{color};color:{color};">{_esc(severity)}</span>'


def _page(request, template, active, **ctx):
    return templates.TemplateResponse(request, template, {"active": active, **ctx})


def _task_menu():
    return [{"id": t, "filter": e["arg_style"] == "filter_flag"} for t, e in TASKS_REGISTRY.items()]


def _tool_menu():
    return [{
        "tool": e["tool"],
        "name": e["name"],
        "heavy": e["heavy"],
        "whole_db": e["arg_style"] == "none",
    } for e in TASKS_REGISTRY.values()]


def _top_techs(program_name, limit=12):
    rows = Http._get_collection().aggregate([
        {"$match": {"program_name": program_name}},
        {"$unwind": "$tech"},
        {"$match": {"tech": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$tech", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}},
        {"$limit": limit},
    ])
    return [(r["_id"].strip(), r["n"]) for r in rows]


def _providers(program_name):
    rows = Subdomains._get_collection().aggregate([
        {"$match": {"program_name": program_name}},
        {"$unwind": "$providers"},
        {"$group": {"_id": "$providers", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}},
    ])
    return [(r["_id"], r["n"]) for r in rows]


def _event_rows(events):
    return [{
        "time": e.created_date.strftime("%Y-%m-%d %H:%M") if e.created_date else "",
        "program": e.program_name,
        "subdomain": e.subdomain or "",
        "label": event_label(e.event_type),
        "old": e.old_value or "",
        "new": e.new_value or "",
    } for e in events]


def _running_runs(**filters):
    out = []
    for run in TaskRun.objects(status__in=list(ACTIVE_STATUSES), **filters).order_by("-started_at"):
        run = reconcile(run)
        if run.status in ACTIVE_STATUSES:
            out.append(serialize_run(run))
    return out


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    cutoff = datetime.now() - timedelta(hours=24)
    kpis = {
        "programs": Programs.objects().count(),
        "subdomains": Subdomains.objects().count(),
        "live": LiveSubdomains.objects().count(),
        "http": Http.objects().count(),
        "urls": Urls.objects().count(),
        "endpoints": Endpoints.objects().count(),
    }
    fresh = {
        "subdomains": Subdomains.objects(created_date__gte=cutoff).count(),
        "http": Http.objects(created_date__gte=cutoff).count(),
    }
    cards = []
    for p in Programs.objects().order_by("program_name"):
        name = p.program_name
        cards.append({
            "name": name,
            "subs": Subdomains.objects(program_name=name).count(),
            "live": LiveSubdomains.objects(program_name=name).count(),
            "http": Http.objects(program_name=name).count(),
            "urls": Urls.objects(program_name=name).count(),
            "endpoints": Endpoints.objects(program_name=name).count(),
            "techs": _top_techs(name),
            "providers": _providers(name),
            "running": _running_runs(target=name),
        })
    findings = {r["_id"]: r["n"] for r in Finding._get_collection().aggregate([
        {"$match": {"status": "open"}},
        {"$group": {"_id": "$severity", "n": {"$sum": 1}}},
    ])}
    return _page(request, "dashboard.html", "dashboard", kpis=kpis, fresh=fresh, cards=cards,
                 tasks=_task_menu(), global_running=_running_runs(target=None),
                 events=_event_rows(recent_events(limit=8)), bf_providers=BF_PROVIDERS,
                 findings=findings)


@router.get("/ui/program/{name}", response_class=HTMLResponse)
def ui_program(name: str, request: Request):
    if Programs.objects(program_name=name).first() is None:
        raise HTTPException(status_code=404, detail="target not found")
    techs = _top_techs(name, limit=60)
    unique = []
    for provider in BF_PROVIDERS + PROVIDERS:
        count = unique_provider_count(name, provider)
        if count:
            unique.append((provider, count))
    runs = [serialize_run(r) for r in TaskRun.objects(target=name).order_by("-started_at").limit(10)]
    return _page(request, "program.html", "targets", name=name,
                 counts={
                     "subs": Subdomains.objects(program_name=name).count(),
                     "live": LiveSubdomains.objects(program_name=name).count(),
                     "http": Http.objects(program_name=name).count(),
                     "urls": Urls.objects(program_name=name).count(),
                     "endpoints": Endpoints.objects(program_name=name).count(),
                 },
                 techs=techs, providers=_providers(name), unique=unique, runs=runs,
                 running=_running_runs(target=name), tasks=_task_menu(), bf_providers=BF_PROVIDERS)


@router.get("/ui/targets", response_class=HTMLResponse)
def ui_targets(request: Request, ok: str = None, err: str = None):
    rows = []
    for p in Programs.objects().order_by("program_name"):
        rows.append({
            "name": p.program_name,
            "scopes": p.scopes,
            "ooscopes": p.ooscopes,
            "created": p.created_date.strftime("%Y-%m-%d") if p.created_date else "",
            "subs": Subdomains.objects(program_name=p.program_name).count(),
            "http": Http.objects(program_name=p.program_name).count(),
        })
    return _page(request, "targets.html", "targets", rows=rows, ok=ok, err=err)


@router.get("/ui/runs", response_class=HTMLResponse)
def ui_runs(request: Request, page: int = 1, status: str = None, tool: str = None):
    total, items = list_runs(page=page, limit=25, task_id=TOOL_TO_TASK.get(tool) if tool else None, status=status)
    rows = [serialize_run(r) for r in items]
    programs = [p.program_name for p in Programs.objects().order_by("program_name")]
    return _page(request, "runs.html", "runs", rows=rows, total=total, page=page, limit=25,
                 status=status, tool=tool, tools=_tool_menu(), programs=programs,
                 statuses=["queued", "running", "paused", "success", "failed", "stopped", "unknown"])


@router.get("/ui/runs/{run_id}", response_class=HTMLResponse)
def ui_run_log(run_id: str, request: Request, tail: int = 400):
    try:
        run = TaskRun.objects(id=ObjectId(run_id)).first()
    except (InvalidId, TypeError):
        run = None
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    run = reconcile(run)
    lines = read_log_tail(run, lines=tail)
    return _page(request, "run_log.html", "runs", run=serialize_run(run), lines="".join(lines),
                 running=run.status in ("queued", "running", "paused"))


@router.get("/ui/search", response_class=HTMLResponse)
def ui_search(request: Request, q: str = "", kind: str = None, page: int = 1):
    error = None
    result = None
    try:
        result = run_search(q, kind=kind if kind in ("subdomains", "http", "urls", "endpoints") else None,
                            page=page, limit=50)
    except SearchError as exc:
        error = str(exc)
    return _page(request, "search.html", "search", q=q, result=result, error=error, kind=kind, page=page,
                 limit=50)


@router.get("/ui/changes", response_class=HTMLResponse)
def ui_changes(request: Request, program: str = None):
    events = recent_events(limit=200, program_name=program or None)
    return _page(request, "changes.html", "changes", events=_event_rows(events), program=program or "",
                 programs=[p.program_name for p in Programs.objects().order_by("program_name")])


# ====================== legacy list pages (paths unchanged) ======================
@router.get("/ui/subdomains/unique/{program_name}/{provider}", response_class=HTMLResponse)
def ui_subdomains_unique(program_name: str, provider: str, page: int = 1, limit: int = 100):
    rows, total = get_unique_provider_subdomains(program_name, provider, page, limit)
    title = f"{program_name} — Exclusive to: {provider}"
    return html_subdomain_list_page(title, rows, page, limit, total,
                                     f"/ui/subdomains/unique/{program_name}/{provider}")



@router.get("/ui/http/fresh", response_class=HTMLResponse)
def ui_http_fresh(hours: int = 24, page: int = 1, limit: int = 100):
    cutoff = datetime.now() - timedelta(hours=hours)
    qs = Http.objects(created_date__gte=cutoff).only("url", "subdomain")
    total = qs.count()
    return html_url_list_page(f"Fresh HTTP ({hours}h)", list(paginate(qs, page, limit)),
                               page, limit, total, f"/ui/http/fresh?hours={hours}")


@router.get("/ui/http/provider/{program_name}/{provider}", response_class=HTMLResponse)
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
@router.get("/ui/subdomains/program/{p_name}", response_class=HTMLResponse)
def ui_subdomains(p_name: str, page: int = 1, limit: int = 100):
    qs = Subdomains.objects(program_name=p_name).only("subdomain", "providers")
    total = qs.count()
    rows = [(s.subdomain, s.providers) for s in paginate(qs, page, limit)]
    return html_subdomain_list_page(f"Subdomains — {p_name}", rows, page, limit, total, f"/ui/subdomains/program/{p_name}")


@router.get("/ui/lives/program/{p_name}", response_class=HTMLResponse)
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


@router.get("/ui/http/program/{p_name}", response_class=HTMLResponse)
def ui_http(p_name: str, page: int = 1, limit: int = 100):
    qs = Http.objects(program_name=p_name).only("url", "subdomain")
    total = qs.count()
    return html_url_list_page(f"HTTP — {p_name}", list(paginate(qs, page, limit)),
                               page, limit, total, f"/ui/http/program/{p_name}")


@router.get("/ui/http/tech/{program_name}/{tech}", response_class=HTMLResponse)
def ui_http_tech(program_name: str, tech: str, page: int = 1, limit: int = 100):
    qs = Http.objects(program_name=program_name, tech=tech).only("url", "subdomain")
    total = qs.count()
    return html_url_list_page(f"{program_name} — Tech: {tech}", list(paginate(qs, page, limit)),
                               page, limit, total, f"/ui/http/tech/{program_name}/{tech}")


@router.get("/ui/urls/program/{p_name}", response_class=HTMLResponse)
def ui_urls(p_name: str, page: int = 1, limit: int = 200):
    qs = Urls.objects(program_name=p_name).only("url")
    total = qs.count()
    items = [u.url for u in paginate(qs, page, limit)]
    return html_list_page(f"URLs — {p_name}", items, page, limit, total, f"/ui/urls/program/{p_name}")


@router.get("/ui/endpoints/program/{p_name}", response_class=HTMLResponse)
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


@router.get("/ui/dns-bruteforce/status", response_class=HTMLResponse)
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
        return f'<span{stale}>{dt.strftime("%b %d, %H:%M")} · {days_ago}d</span>'

    rows = ""
    for s in statuses:
        feasible_badge = (
            '<span class="badge" style="border-color:#3fb950;color:#3fb950;">yes</span>'
            if s.feasible else
            '<span class="badge" style="border-color:#f85149;color:#f85149;">no (wildcard)</span>'
        )
        rows += (
            f'<tr><td class="name" data-label="Domain">{s.domain}</td>'
            f'<td data-label="Program">{s.program_name}</td>'
            f'<td data-label="Feasible">{feasible_badge}</td>'
            f'<td class="ts" data-label="Last static">{fmt(s.last_static_run)}</td>'
            f'<td class="ts" data-label="Last dynamic">{fmt(s.last_dynamic_run)}</td></tr>'
        )

    home = build_url("/")
    body = f"""
    <a href="{home}">← Back to Dashboard</a>
    <h2>DNS Bruteforce Status</h2>
    <p class="note">Red timestamp = more than 8 days since last run (something's probably stuck --
    check <code>systemctl status watch-heavy</code>).</p>
    <div class="table-wrap"><table class="status">
      <thead><tr>
        <th>Domain</th><th>Program</th><th>Feasible</th>
        <th>Last static</th><th>Last dynamic</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    """
    return HTMLResponse(render_page("DNS Bruteforce Status", body))


def _count(qs_fn):
    try:
        return qs_fn()
    except Exception:
        return None


def _num(v):
    return f"{v:,}" if isinstance(v, int) else "—"


@router.get("/ui/crawl/status", response_class=HTMLResponse)
def ui_crawl_status():
    """Per-program crawl progress: URLs and endpoints discovered, and how many
    URLs were (re)crawled in the last 24h (the live-progress signal)."""
    cutoff = datetime.now() - timedelta(hours=24)
    rows = ""
    for p in Programs.objects().order_by("program_name"):
        name = p.program_name
        urls = _count(lambda: Urls.objects(program_name=name).count())
        eps = _count(lambda: Endpoints.objects(program_name=name).count())
        fresh = _count(lambda: Urls.objects(program_name=name, last_update__gte=cutoff).count())
        fresh_html = (f'<span style="color:#3fb950;">{fresh:,}</span>'
                      if isinstance(fresh, int) and fresh else _num(fresh))
        rows += (
            f'<tr><td class="name" data-label="Program">{name}</td>'
            f'<td class="num" data-label="URLs">{_num(urls)}</td>'
            f'<td class="num" data-label="Endpoints">{_num(eps)}</td>'
            f'<td class="num" data-label="Fresh URLs (24h)">{fresh_html}</td></tr>'
        )
    home = build_url("/")
    body = f"""
    <a href="{home}">← Back to Dashboard</a>
    <h2>Crawl Status</h2>
    <p class="note">katana crawl of HTTP targets (heavy-worker crawl lane). "Fresh URLs (24h)"
    is the live-progress signal — if it stays 0 while the crawl lane is running, something is stuck.</p>
    <div class="table-wrap"><table class="status">
      <thead><tr><th>Program</th><th>URLs</th><th>Endpoints</th><th>Fresh URLs (24h)</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    """
    return HTMLResponse(render_page("Crawl Status", body))


@router.get("/ui/x8/status", response_class=HTMLResponse)
def ui_x8_status():
    """Per-program x8 parameter-discovery progress: endpoints checked vs total,
    and the size of the exported per-program parameter wordlist."""
    rows = ""
    for p in Programs.objects().order_by("program_name"):
        name = p.program_name
        eps = _count(lambda: Endpoints.objects(program_name=name).count())
        checked = _count(lambda: Endpoints.objects(program_name=name, x8_checked=True).count())
        pct = (round(100 * checked / eps) if isinstance(eps, int) and isinstance(checked, int) and eps else 0)
        try:
            with open(f"/opt/watch/wordlists/{name}_params.txt") as fh:
                wl = sum(1 for line in fh if line.strip())
        except Exception:
            wl = 0
        rows += (
            f'<tr><td class="name" data-label="Program">{name}</td>'
            f'<td class="num" data-label="Endpoints">{_num(eps)}</td>'
            f'<td class="num" data-label="Checked">{_num(checked)}</td>'
            f'<td class="num" data-label="% done">{pct}%</td>'
            f'<td class="num" data-label="Params (wordlist)">{wl:,}</td></tr>'
        )
    home = build_url("/")
    body = f"""
    <a href="{home}">← Back to Dashboard</a>
    <h2>x8 Parameter Discovery</h2>
    <p class="note">Hidden-parameter discovery with x8 (heavy-worker param lane). "Checked" is how
    many unique endpoints x8 has tested; "Params" is the per-program wordlist exported to
    <code>/opt/watch/wordlists/{{program}}_params.txt</code>.</p>
    <div class="table-wrap"><table class="status">
      <thead><tr><th>Program</th><th>Endpoints</th><th>Checked</th><th>% done</th><th>Params (wordlist)</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    """
    return HTMLResponse(render_page("x8 Parameter Discovery", body))


def _options(values, current, any_label):
    out = [f'<option value="">{any_label}</option>']
    for value in values:
        selected = " selected" if value == current else ""
        out.append(f'<option value="{_esc(value)}"{selected}>{_esc(value)}</option>')
    return "".join(out)


@router.get("/ui/findings", response_class=HTMLResponse)
def ui_findings(program: str = None, severity: str = None, source: str = None,
                status: str = "open", page: int = 1, limit: int = 100):
    filters = {}
    if program:
        filters["program_name"] = program
    if severity in FINDING_SEVERITIES:
        filters["severity"] = severity
    if source:
        filters["source"] = source
    if status:
        filters["status"] = status
    page = max(page, 1)
    qs = Finding.objects(**filters).order_by("-first_seen")
    total = qs.count()

    rows = ""
    for f in paginate(qs, page, limit):
        matched = f.matched or f.target or ""
        target = (f'<a href="{_esc(matched)}" target="_blank" rel="noopener noreferrer">{_esc(matched)}</a>'
                  if matched.startswith(("http://", "https://")) else _esc(matched))
        first = f.first_seen.strftime("%b %d, %H:%M") if f.first_seen else ""
        rows += (
            f'<tr><td data-label="Severity">{_severity_badge(f.severity)}</td>'
            f'<td data-label="Source">{_esc(f.source)}</td>'
            f'<td data-label="Program">{_esc(f.program_name)}</td>'
            f'<td class="name" data-label="Name">{_esc(f.name)}</td>'
            f'<td data-label="Target">{target}</td>'
            f'<td class="ts" data-label="First seen">{_esc(first)}</td>'
            f'<td data-label="Status">{_esc(f.status)}</td></tr>'
        )
    if not rows:
        rows = '<tr><td colspan="7" class="note">No findings match these filters.</td></tr>'

    base = {"program": program, "severity": severity, "source": source, "status": status, "limit": limit}

    def link(p):
        return "/ui/findings?" + urlencode({**{k: v for k, v in base.items() if v}, "page": p})

    total_pages = max(1, (total + limit - 1) // limit)
    nav = f'Page {page}/{total_pages} — total {total:,}'
    if page > 1:
        nav += f' | <a href="{_esc(link(page - 1))}">« Prev</a>'
    if page < total_pages:
        nav += f' | <a href="{_esc(link(page + 1))}">Next »</a>'

    programs = [p.program_name for p in Programs.objects().order_by("program_name")]
    home = build_url("/")
    body = f"""
    <a href="{home}">← Back to Dashboard</a>
    <h2>Findings</h2>
    <form method="get" action="/ui/findings" class="note">
      <select name="program">{_options(programs, program, "All programs")}</select>
      <select name="severity">{_options(FINDING_SEVERITIES, severity, "Any severity")}</select>
      <select name="source">{_options(("nuclei", "takeover", "secret"), source, "Any source")}</select>
      <select name="status">{_options(("open", "triaged", "false_positive", "fixed"), status, "Any status")}</select>
      <button type="submit">Filter</button>
    </form>
    <p class="note">Deduplicated on target + check name. Only medium+ findings alert on Telegram.</p>
    <div class="table-wrap"><table class="status">
      <thead><tr>
        <th>Severity</th><th>Source</th><th>Program</th><th>Name</th>
        <th>Target</th><th>First seen</th><th>Status</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    <div class="pagenav">{nav}</div>
    """
    return HTMLResponse(render_page("Findings", body))
