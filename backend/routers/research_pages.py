"""
backend/routers/research_pages.py — Stage D3 Research Dashboard UI (HTML).

Server-rendered Jinja2 pages on top of the read-only D2 data layer
(``backend/research_data.py``). No self-HTTP, no data duplication: every
page calls the same helper functions the JSON API uses.

Routes:
- GET /ui/research                 -- Research / CVEs table
- GET /ui/research/{cve}           -- research detail (RESEARCH ONLY banner)
- GET /ui/xss                      -- XSS research candidates
- GET /ui/xss/{candidate_id}       -- candidate detail (test idea quarantined)
- GET /ui/kb                       -- Knowledge Base metadata table
- GET /ui/kb/{kid}                 -- KB document detail (plain-text content)
- GET /ui/reports                  -- persisted Markdown reports
- GET /ui/reports/{cve}            -- raw Markdown in an escaped <pre>
- GET /ui/reports/{cve}/download   -- read-only attachment (path-confined)

All pages are behind verify_api_key (same as the existing UI routes).
Nothing here writes, executes, fetches or renders untrusted HTML.
"""
from typing import Optional
from urllib.parse import parse_qs, urlencode

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from ai.knowledge.task_store import (
    ALLOWED_TRANSITIONS,
    StaleTaskError,
    TaskNotFound,
    TaskStoreError,
)
from backend import research_tasks
from backend import research_data as rdata
from backend.deps import API_KEY, build_url, verify_api_key
from backend.research_data import NotFoundError, ResearchDataError, severity_bucket
from backend.templating import templates

router = APIRouter()

_UI_AUTH = [Depends(verify_api_key)]

PAGE_SIZE_DEFAULT = 50
PAGE_SIZE_MAX = 100


def _ui_link(base: str, **params) -> str:
    """Query-string-correct link builder for the research UI.

    Unlike the shared ``build_url`` (pre-existing, dashboard-wide, does not
    percent-encode), this properly encodes user-supplied filter values so
    spaces/&//etc survive pagination and filter-chip removal links. The
    api_key follows the existing propagation convention.
    """
    query = {k: v for k, v in params.items() if v not in (None, "")}
    if API_KEY:
        query["api_key"] = API_KEY
    return f"{base}?{urlencode(query)}" if query else base


def _filter_chips(base: str, params: dict) -> list:
    """Active filter chips with one-filter-removal links (values preserved)."""
    chips = []
    active = {k: v for k, v in params.items() if v not in (None, "")}
    for key, value in active.items():
        rest = {k: v for k, v in active.items() if k != key}
        chips.append({"key": key, "value": value, "url": _ui_link(base, **rest)})
    return chips


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
        "research_url": build_url("/ui/research"),
        "queue_url": build_url("/ui/research/queue"),
        "research_tasks_url": build_url("/ui/research/tasks"),
        "xss_url": build_url("/ui/xss"),
        "kb_url": build_url("/ui/kb"),
        "reports_url": build_url("/ui/reports"),
    }
    base.update(extra)
    return base


def _page_params(page: int, limit: int) -> tuple[int, int]:
    limit = min(max(limit, 10), PAGE_SIZE_MAX)
    page = max(page, 1)
    return page, limit


def _pagination(total: int, page: int, limit: int, base_path: str, **filters) -> dict:
    total_pages = max(1, (total + limit - 1) // limit)
    page = min(page, total_pages)
    offset = (page - 1) * limit
    link = lambda p: _ui_link(base_path, page=p, limit=limit, **filters)
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "offset": offset,
        "prev_url": link(page - 1) if page > 1 else None,
        "next_url": link(page + 1) if page < total_pages else None,
    }


def _error_page(request, active: str, code: int, title: str, hint: str):
    return templates.TemplateResponse(
        request,
        "error.html",
        _ctx(request, active=active, page_title="Error", code=code, title=title, hint=hint),
        status_code=code,
    )


# Bounded, dependency-free urlencoded form parsing (python-multipart is not
# installed; Starlette's Request.form() requires it even for urlencoded, so the
# small workflow forms are parsed directly here with a hard size cap).
_MAX_FORM_BYTES = 65536
_MAX_FORM_FIELDS = 50


async def _form(request: Request) -> dict:
    body = await request.body()
    if len(body) > _MAX_FORM_BYTES:
        raise HTTPException(status_code=413, detail="form too large")
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" not in content_type:
        return {}
    parsed = parse_qs(
        body.decode("utf-8", errors="ignore"),
        keep_blank_values=True,
        max_num_fields=_MAX_FORM_FIELDS,
    )
    return {key: (values[0] if values else "") for key, values in parsed.items()}


# ------------------------------------------------------------------ research


@router.get("/ui/research", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_research(
    request: Request,
    q: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    sort: str = "cve",
    direction: str = "asc",
    page: int = 1,
    limit: int = PAGE_SIZE_DEFAULT,
):
    page, limit = _page_params(page, limit)
    filters = {"q": q, "severity": severity, "status": status}
    try:
        data = rdata.list_research(
            limit=limit, offset=(page - 1) * limit,
            q=q, severity=severity, status=status, sort=sort, direction=direction,
        )
        stats = rdata.research_stats()
        overview = rdata.get_overview()
    except ResearchDataError:
        return _error_page(request, "research", 400,
                           "Invalid filter", "The search/filter values are malformed.")
    for item in data["items"]:
        item["sev_bucket"] = severity_bucket(item.get("severity"))
        item["generated_date"] = str(item.get("generated_at") or "").split("T")[0] or None
        item["has_report"] = rdata.has_report(item["cve"])
        item["detail_url"] = build_url(f"/ui/research/{item['cve']}")
        item["report_url"] = build_url(f"/ui/reports/{item['cve']}") if item["has_report"] else None
    return templates.TemplateResponse(
        request,
        "research.html",
        _ctx(
            request,
            active="research",
            page_title="Research / CVEs",
            results=data["items"],
            sort=sort,
            direction=direction,
            q=q or "",
            severity=severity or "",
            status=status or "",
            chips=_filter_chips("/ui/research", filters),
            clear_url=_ui_link("/ui/research"),
            stats=stats,
            overview=overview,
            intel=rdata.research_intelligence_stats(),
            **_pagination(data["total"], page, limit, "/ui/research",
                          **filters, sort=sort, direction=direction),
        ),
    )


@router.get("/ui/research/queue", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_research_queue(
    request: Request,
    cve: Optional[str] = None,
    page: int = 1,
    limit: int = PAGE_SIZE_DEFAULT,
):
    """Stage R19: ranked R18 research queue (research planning only)."""

    page, limit = _page_params(page, limit)
    filters = {"cve": cve}
    try:
        data = rdata.list_research_queue(
            limit=limit, offset=(page - 1) * limit, cve=cve
        )
    except ResearchDataError:
        return _error_page(request, "research-queue", 400, "Invalid filter",
                           "The CVE filter is malformed.")
    for item in data["items"]:
        item["cve_url"] = build_url(f"/ui/research/{item['cve']}")
        item["program_url"] = (
            build_url(f"/ui/program/{item['program']}")
            if item.get("program")
            else None
        )
    try:
        task_by_queue = research_tasks.task_by_queue()
    except TaskStoreError:
        task_by_queue = {}
    return templates.TemplateResponse(
        request,
        "research_queue.html",
        _ctx(
            request,
            active="research-queue",
            page_title="Research Queue",
            results=data["items"],
            cve=cve or "",
            task_by_queue=task_by_queue,
            **_pagination(data["total"], page, limit, "/ui/research/queue",
                          **filters),
        ),
    )


# ------------------------------------------------------------------ tasks


def _render_research_task(
    request: Request, task_id: str, *, error=None, code: int = 200
):
    task = research_tasks.get_task(task_id).model_dump(mode="json")
    task["cve_url"] = build_url(f"/ui/research/{task['cve']}")
    task["program_url"] = build_url(f"/ui/program/{task['program']}")
    task["queue_url"] = build_url("/ui/research/queue", cve=task["cve"])
    return templates.TemplateResponse(
        request,
        "research_task_detail.html",
        _ctx(
            request,
            active="research-tasks",
            page_title=task["task_id"],
            task=task,
            error=error,
            next_statuses=sorted(
                ALLOWED_TRANSITIONS.get(task["status"], frozenset())
            ),
        ),
        status_code=code,
    )


@router.get("/ui/research/tasks", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_research_tasks(
    request: Request,
    status: Optional[str] = None,
    cve: Optional[str] = None,
    page: int = 1,
    limit: int = PAGE_SIZE_DEFAULT,
):
    page, limit = _page_params(page, limit)
    filters = {"status": status, "cve": cve}
    try:
        data = research_tasks.list_tasks(
            limit=limit, offset=(page - 1) * limit, status=status, cve=cve
        )
    except TaskStoreError:
        return _error_page(request, "research-tasks", 400, "Invalid filter",
                           "The status/CVE filter is malformed.")
    for item in data["items"]:
        item["cve_url"] = build_url(f"/ui/research/{item['cve']}")
        item["task_url"] = build_url(f"/ui/research/tasks/{item['task_id']}")
        item["queue_url"] = _ui_link("/ui/research/queue", cve=item["cve"])
    return templates.TemplateResponse(
        request,
        "research_tasks.html",
        _ctx(
            request,
            active="research-tasks",
            page_title="Research Tasks",
            results=data["items"],
            status=status or "",
            cve=cve or "",
            **_pagination(data["total"], page, limit, "/ui/research/tasks",
                          **filters),
        ),
    )


@router.get("/ui/research/tasks/{task_id}", response_class=HTMLResponse,
            dependencies=_UI_AUTH)
def ui_research_task_detail(request: Request, task_id: str):
    try:
        return _render_research_task(request, task_id)
    except TaskNotFound:
        return _error_page(request, "research-tasks", 404,
                           "Research task not found",
                           "No persisted research task exists for this id.")
    except TaskStoreError:
        return _error_page(request, "research-tasks", 400, "Invalid task id",
                           "Expected an id like rt-0123456789abcdef.")


@router.post("/ui/research/tasks", dependencies=_UI_AUTH)
async def ui_research_task_create(request: Request):
    fields = await _form(request)
    try:
        research_tasks.create_task(
            cve=fields.get("cve", ""),
            program=fields.get("program", ""),
            queue_id=fields.get("queue_id", ""),
            title=fields.get("title") or None,
        )
    except TaskStoreError as exc:
        return _error_page(request, "research-tasks", 400,
                           "Unable to start research", str(exc))
    return RedirectResponse(_ui_link("/ui/research/tasks"), status_code=303)


@router.post("/ui/research/tasks/{task_id}", dependencies=_UI_AUTH)
async def ui_research_task_update(request: Request, task_id: str):
    fields = await _form(request)
    try:
        research_tasks.update_task(
            task_id,
            expected_version=fields.get("expected_version"),
            status=fields.get("status") or None,
            notes=fields.get("notes", ""),
            blocker=fields.get("blocker", ""),
            result_summary=fields.get("result_summary", ""),
        )
    except StaleTaskError as exc:
        try:
            return _render_research_task(request, task_id, error=str(exc), code=409)
        except TaskStoreError:
            return _error_page(request, "research-tasks", 409,
                               "Stale research task", str(exc))
    except TaskNotFound:
        return _error_page(request, "research-tasks", 404,
                           "Research task not found",
                           "No persisted research task exists for this id.")
    except TaskStoreError as exc:
        try:
            return _render_research_task(request, task_id, error=str(exc), code=400)
        except TaskStoreError:
            return _error_page(request, "research-tasks", 400,
                               "Invalid update", str(exc))
    return RedirectResponse(
        _ui_link(f"/ui/research/tasks/{task_id}"), status_code=303
    )


@router.get("/ui/research/{cve}", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_research_detail(request: Request, cve: str):
    try:
        detail = rdata.get_research(cve)
    except NotFoundError:
        return _error_page(request, "research", 404,
                           "Research artifact not found",
                           "No persisted research JSON exists for this CVE.")
    except ResearchDataError:
        return _error_page(request, "research", 400,
                           "Invalid CVE identifier",
                           "Expected a CVE id like CVE-2026-1234.")
    cve = detail["cve"]
    detail["sev_bucket"] = severity_bucket(detail.get("severity"))
    detail["nuclei"] = rdata.nuclei_summary(cve)
    detail["report_url"] = build_url(f"/ui/reports/{cve}") if rdata.has_report(cve) else None
    try:
        intel = rdata.cve_intelligence(cve)
    except ResearchDataError:
        intel = {"cve": cve, "available": False, "relevance": [], "queue": []}
    for row in intel.get("relevance") or []:
        row["program_url"] = (
            build_url(f"/ui/program/{row['program']}")
            if row.get("program")
            else None
        )
    for item in intel.get("queue") or []:
        item["program_url"] = (
            build_url(f"/ui/program/{item['program']}")
            if item.get("program")
            else None
        )
    try:
        tasks = research_tasks.list_tasks(limit=100, cve=cve)["items"]
    except TaskStoreError:
        tasks = []
    task_by_queue = {}
    for task in tasks:
        task["task_url"] = build_url(f"/ui/research/tasks/{task['task_id']}")
        task["program_url"] = (
            build_url(f"/ui/program/{task['program']}")
            if task.get("program")
            else None
        )
        task_by_queue[task["queue_id"]] = task["task_id"]
    vulnerability_type = str(detail.get("vulnerability_type") or "").lower()
    kb_types = " ".join(intel.get("vulnerability_types") or []).lower()
    kb_cwes = {str(c).upper() for c in (intel.get("cwes") or [])}
    xss_related = (
        "xss" in vulnerability_type
        or "cross-site scripting" in vulnerability_type
        or "xss" in kb_types
        or detail.get("cwe") == "CWE-79"
        or "CWE-79" in kb_cwes
    )
    # Fallback: the persisted local report is derived from the CVE's trusted
    # references; a literal XSS mention there is a safe "applicable" signal.
    if not xss_related and rdata.has_report(cve):
        try:
            report_text = (rdata.get_report(cve).get("markdown") or "")[:200000].lower()
        except ResearchDataError:
            report_text = ""
        xss_related = "xss" in report_text or "cross-site scripting" in report_text
    cross_nav = {
        "queue_cve_url": _ui_link("/ui/research/queue", cve=cve),
        "tasks_cve_url": _ui_link("/ui/research/tasks", cve=cve),
        "kb_cve_url": _ui_link("/ui/kb", cve=cve),
        "xss_search_url": _ui_link("/ui/xss", q=cve) if xss_related else None,
        "cve_task_count": len(tasks),
    }
    return templates.TemplateResponse(
        request,
        "research_detail.html",
        _ctx(request, active="research", page_title=cve, r=detail, cve=cve,
             intel=intel, tasks=tasks, task_by_queue=task_by_queue,
             **cross_nav),
    )


# ----------------------------------------------------------------------- xss


@router.get("/ui/xss", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_xss(
    request: Request,
    q: Optional[str] = None,
    status: Optional[str] = None,
    type: Optional[str] = None,
    context: Optional[str] = None,
    page: int = 1,
    limit: int = PAGE_SIZE_DEFAULT,
):
    page, limit = _page_params(page, limit)
    filters = {"q": q, "status": status, "type": type, "context": context}
    try:
        data = rdata.list_xss(
            limit=limit, offset=(page - 1) * limit,
            status=status, xss_type=type, context=context, q=q,
        )
    except ResearchDataError:
        return _error_page(request, "xss", 400, "Invalid filter",
                           "The search/filter values are malformed.")
    for item in data["items"]:
        item["detail_url"] = build_url(f"/ui/xss/{item['candidate_id']}")
    return templates.TemplateResponse(
        request,
        "xss.html",
        _ctx(
            request,
            active="xss",
            page_title="XSS Research Candidates",
            results=data["items"],
            q=q or "",
            status=status or "",
            type=type or "",
            context=context or "",
            chips=_filter_chips("/ui/xss", filters),
            clear_url=_ui_link("/ui/xss"),
            **_pagination(data["total"], page, limit, "/ui/xss", **filters),
        ),
    )


_CVE_IN_TEXT_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _first_cve(candidate: dict) -> str | None:
    """First CVE id literally present in a candidate record (validated regex).

    Only used to build a trusted, regex-validated link to existing research;
    it never invents an id.
    """

    def walk(value):
        if isinstance(value, dict):
            for item in value.values():
                found = walk(item)
                if found:
                    return found
        elif isinstance(value, (list, tuple)):
            for item in value:
                found = walk(item)
                if found:
                    return found
        elif isinstance(value, str):
            for match in _CVE_IN_TEXT_RE.finditer(value):
                candidate_id = match.group(0)
                if rdata.CVE_RE.match(candidate_id):
                    return candidate_id
        return None

    return walk(candidate)


@router.get("/ui/xss/{candidate_id}", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_xss_detail(request: Request, candidate_id: str):
    try:
        cand = rdata.get_xss(candidate_id)
    except NotFoundError:
        return _error_page(request, "xss", 404, "Candidate not found",
                           "No persisted XSS candidate exists for this id.")
    except ResearchDataError:
        return _error_page(request, "xss", 400, "Invalid candidate id",
                           "Expected an id like xss-0123456789abcdef.")
    cand["kb_refs"] = [
        {"id": str(ref), "url": build_url(f"/ui/kb/{ref}")}
        for ref in (cand.get("references") or [])
        if rdata.KB_ID_RE.match(str(ref))
    ]
    # Display-only enrichment: linkify evidence knowledge_ids that are valid
    # KB ids (values themselves are untouched persisted text).
    for item in cand.get("source_evidence") or []:
        if isinstance(item, dict):
            kid = str(item.get("knowledge_id") or "")
            if rdata.KB_ID_RE.match(kid):
                item["kb_url"] = build_url(f"/ui/kb/{kid}")
    # Deterministic cross-navigation: link the candidate back to research when
    # a CVE id is literally present (regex-validated, never constructed).
    cand["cve"] = _first_cve(cand)
    cand["research_url"] = (
        build_url(f"/ui/research/{cand['cve']}") if cand["cve"] else None
    )
    cand["queue_url"] = (
        _ui_link("/ui/research/queue", cve=cand["cve"]) if cand["cve"] else None
    )
    # Optional R7 LLM research (read-only, fail-safe): missing or malformed
    # records render as a neutral absence state, never as an error page.
    # validated_id is the normalized candidate id (get_xss already validated).
    llm = None
    llm_error = None
    try:
        llm = rdata.get_xss_llm_research(cand.get("candidate_id") or candidate_id)
    except NotFoundError:
        llm = None
    except ResearchDataError:
        llm = None
        llm_error = True
    return templates.TemplateResponse(
        request,
        "xss_detail.html",
        _ctx(request, active="xss", page_title=candidate_id, c=cand,
             llm=llm, llm_error=llm_error),
    )


# ------------------------------------------------------------------ knowledge


@router.get("/ui/kb", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_kb(
    request: Request,
    q: Optional[str] = None,
    cve: Optional[str] = None,
    tag: Optional[str] = None,
    page: int = 1,
    limit: int = PAGE_SIZE_DEFAULT,
):
    page, limit = _page_params(page, limit)
    filters = {"q": q, "cve": cve, "tag": tag}
    try:
        data = rdata.list_kb(limit=limit, offset=(page - 1) * limit, q=q, cve=cve, tag=tag)
    except ResearchDataError:
        return _error_page(request, "kb", 400, "Invalid filter",
                           "The search/filter values are malformed.")
    for item in data["items"]:
        item["detail_url"] = build_url(f"/ui/kb/{item['knowledge_id']}")
        item["indexed_date"] = str(item.get("indexed_at") or "").split("T")[0] or None
        item["cve"] = next(
            (str(t)[4:] for t in (item.get("tags") or []) if str(t).lower().startswith("cve:")),
            None,
        )
        item["cve_search_url"] = (
            _ui_link("/ui/research", q=item["cve"])
            if item["cve"] and rdata.CVE_RE.match(item["cve"])
            else None
        )
    return templates.TemplateResponse(
        request,
        "kb.html",
        _ctx(
            request,
            active="kb",
            page_title="Knowledge Base",
            results=data["items"],
            q=q or "",
            cve=cve or "",
            tag=tag or "",
            chips=_filter_chips("/ui/kb", filters),
            clear_url=_ui_link("/ui/kb"),
            **_pagination(data["total"], page, limit, "/ui/kb", **filters),
        ),
    )


@router.get("/ui/kb/{kid}", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_kb_detail(request: Request, kid: str):
    try:
        doc = rdata.get_kb(kid)
    except NotFoundError:
        return _error_page(request, "kb", 404, "Knowledge document not found",
                           "No persisted KB document exists for this id.")
    except ResearchDataError:
        return _error_page(request, "kb", 400, "Invalid knowledge id",
                           "Expected an id like kb-0123456789abcdef.")
    doc["cve"] = next(
        (str(t)[4:] for t in (doc.get("tags") or []) if str(t).lower().startswith("cve:")),
        None,
    )
    doc["research_url"] = (
        build_url(f"/ui/research/{doc['cve']}")
        if doc["cve"] and rdata.CVE_RE.match(doc["cve"])
        else None
    )
    doc["queue_url"] = (
        _ui_link("/ui/research/queue", cve=doc["cve"])
        if doc["cve"] and rdata.CVE_RE.match(doc["cve"])
        else None
    )
    doc["tasks_url"] = (
        _ui_link("/ui/research/tasks", cve=doc["cve"])
        if doc["cve"] and rdata.CVE_RE.match(doc["cve"])
        else None
    )
    return templates.TemplateResponse(
        request,
        "kb_detail.html",
        _ctx(request, active="kb", page_title=doc.get("knowledge_id") or "KB", doc=doc),
    )


# ------------------------------------------------------------------- reports


@router.get("/ui/reports", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_reports(
    request: Request,
    q: Optional[str] = None,
    page: int = 1,
    limit: int = PAGE_SIZE_DEFAULT,
):
    page, limit = _page_params(page, limit)
    try:
        data = rdata.list_reports(limit=limit, offset=(page - 1) * limit, q=q)
    except ResearchDataError:
        return _error_page(request, "reports", 400, "Invalid filter",
                           "The search/filter values are malformed.")
    for item in data["items"]:
        item["detail_url"] = build_url(f"/ui/reports/{item['cve']}")
        item["download_url"] = build_url(f"/ui/reports/{item['cve']}/download")
    return templates.TemplateResponse(
        request,
        "reports.html",
        _ctx(
            request,
            active="reports",
            page_title="Research Reports",
            results=data["items"],
            q=q or "",
            **_pagination(data["total"], page, limit, "/ui/reports", **{"q": q}),
        ),
    )


def _report_or_error(request: Request, cve: str):
    try:
        return None, rdata.get_report(cve)
    except NotFoundError:
        return _error_page(request, "reports", 404, "Report not found",
                           "No persisted Markdown report exists for this CVE. "
                           "Reports are generated by the research pipeline."), None
    except ResearchDataError:
        return _error_page(request, "reports", 400, "Invalid CVE identifier",
                           "Expected a CVE id like CVE-2026-1234."), None


@router.get("/ui/reports/{cve}", response_class=HTMLResponse, dependencies=_UI_AUTH)
def ui_report_detail(request: Request, cve: str):
    err, report = _report_or_error(request, cve)
    if err:
        return err
    return templates.TemplateResponse(
        request,
        "report_detail.html",
        _ctx(
            request,
            active="reports",
            page_title=f"Report — {report['cve']}",
            report=report,
            research_url=build_url(f"/ui/research/{report['cve']}"),
            download_url=build_url(f"/ui/reports/{report['cve']}/download"),
        ),
    )


@router.get("/ui/reports/{cve}/download", dependencies=_UI_AUTH)
def ui_report_download(request: Request, cve: str):
    err, report = _report_or_error(request, cve)
    if err:
        return err
    return PlainTextResponse(
        report["markdown"],
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{report["cve"]}.md"',
        },
    )
