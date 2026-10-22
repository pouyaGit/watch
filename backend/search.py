"""Global search. Grammar: free text plus key:value filters.

  tech:<name>        HTTP only, exact (case-insensitive) technology match
  status:<code>      HTTP and URLs, exact status code
  provider:<name>    subdomains with this provider; HTTP of those subdomains
  program:<name>     restrict to one program
"""
from mongoengine import Q

from database.db import Subdomains, Http, Urls, Endpoints

KEYS = ("tech", "status", "provider", "program")
PROVIDER_SUBDOMAIN_CAP = 5000
GROUPS = ("subdomains", "http", "urls", "endpoints")


class SearchError(ValueError):
    pass


def parse_query(raw):
    text_parts, filters = [], {}
    for token in (raw or "").split():
        key, sep, value = token.partition(":")
        if sep and key.lower() in KEYS and value:
            filters[key.lower()] = value
        else:
            text_parts.append(token)
    return " ".join(text_parts), filters


def _status(value):
    if not value.isdigit():
        raise SearchError(f"status must be a number, got {value!r}")
    return int(value)


def _page(qs, page, limit):
    return qs.skip((page - 1) * limit).limit(limit)


def run_search(raw, kind=None, page=1, limit=50):
    text, flt = parse_query(raw)
    if not text and not flt:
        return None
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    program = flt.get("program")
    status = _status(flt["status"]) if "status" in flt else None
    results = {}

    def wanted(name):
        return kind in (None, name)

    def group(name, qs, to_row):
        total = qs.count()
        results[name] = {"total": total, "items": [to_row(x) for x in _page(qs, page, limit)] if kind == name else [to_row(x) for x in qs.limit(10)]}

    if wanted("subdomains"):
        qs = Subdomains.objects()
        if text:
            qs = qs.filter(subdomain__icontains=text)
        if program:
            qs = qs.filter(program_name=program)
        if "provider" in flt:
            qs = qs.filter(providers=flt["provider"])
        group("subdomains", qs.only("program_name", "subdomain", "providers"),
              lambda s: {"program": s.program_name, "subdomain": s.subdomain, "providers": s.providers})

    if wanted("http"):
        qs = Http.objects()
        if text:
            qs = qs.filter(Q(subdomain__icontains=text) | Q(title__icontains=text) | Q(url__icontains=text))
        if program:
            qs = qs.filter(program_name=program)
        if "tech" in flt:
            qs = qs.filter(tech__iexact=flt["tech"])
        if status is not None:
            qs = qs.filter(status_code=status)
        if "provider" in flt:
            sub_qs = Subdomains.objects(providers=flt["provider"])
            if program:
                sub_qs = sub_qs.filter(program_name=program)
            names = [s.subdomain for s in sub_qs.only("subdomain").limit(PROVIDER_SUBDOMAIN_CAP)]
            qs = qs.filter(subdomain__in=names)
        group("http", qs.only("program_name", "url", "subdomain", "title", "status_code", "tech"),
              lambda h: {"program": h.program_name, "url": h.url, "subdomain": h.subdomain,
                         "status_code": h.status_code, "title": h.title, "tech": h.tech})

    if wanted("urls") and "tech" not in flt and "provider" not in flt:
        qs = Urls.objects()
        if text:
            qs = qs.filter(Q(url__icontains=text) | Q(path__icontains=text) | Q(params__icontains=text))
        if program:
            qs = qs.filter(program_name=program)
        if status is not None:
            qs = qs.filter(status_code=status)
        group("urls", qs.only("program_name", "url", "status_code"),
              lambda u: {"program": u.program_name, "url": u.url, "status_code": u.status_code})

    if wanted("endpoints") and not (flt.keys() & {"tech", "status", "provider"}):
        qs = Endpoints.objects()
        if text:
            qs = qs.filter(Q(path__icontains=text) | Q(params__icontains=text))
        if program:
            qs = qs.filter(program_name=program)
        group("endpoints", qs.only("program_name", "subdomain", "path", "params", "hit_count"),
              lambda e: {"program": e.program_name, "subdomain": e.subdomain, "path": e.path,
                         "params": e.params, "hit_count": e.hit_count})

    return {"text": text, "filters": flt, "results": results}
