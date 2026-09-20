"""backend/attack_surface/repository.py — read-only attack-surface access.

The single read-only gateway between the attack-surface intelligence layer and
the recon data Watch already persists. It does **not** create a database, a
collection or a schema: it reuses the existing ``Http`` / ``Urls`` /
``Endpoints`` rows through the existing
:mod:`ai.researcher.target_intelligence` record converters and the existing
read-only Mongo accessor in :mod:`backend.observed_inventory`.

Two entry points:

- :func:`normalize_records` -- PURE. Converts injected record objects (or plain
  dicts) into normalized :class:`~backend.attack_surface.models.AttackSurfaceRecord`
  values. No IO; unit tests use this.
- :func:`load_snapshot` -- read-only. Loads records for one program (or a
  bounded set of programs) from Mongo, or from injected ``records``. Fail-soft:
  an unreachable database yields an explicit ``available: false`` snapshot, and
  a missing value is never invented.

No writes, no network beyond the local database read, no LLM, no subprocess,
no target interaction. URLs are treated as data and are never fetched.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

from backend.attack_surface.models import (
    AttackSurfaceRecord,
    AttackSurfaceSnapshot,
)

#: Bounded defaults so a large corpus can never produce an unbounded payload.
DEFAULT_MAX_PROGRAMS = 12
DEFAULT_MAX_ENDPOINTS = 3000
DEFAULT_MAX_URLS = 1000
DEFAULT_MAX_HTTP = 5000

_CACHE_TTL = 15.0
_UNAVAILABLE_TTL = 60.0

_ENDPOINT_PROJECTION = {
    "program_name": 1,
    "subdomain": 1,
    "path": 1,
    "params": 1,
    "param_records": 1,
    "hit_count": 1,
    "example_url": 1,
}
_URL_PROJECTION = {
    "program_name": 1,
    "subdomain": 1,
    "url": 1,
    "path": 1,
    "params": 1,
}
_HTTP_PROJECTION = {
    "program_name": 1,
    "subdomain": 1,
    "tech": 1,
}

_TECH_VERSION_RE = re.compile(
    r"^(?P<name>.*?)[\s:/_\-]+v?(?P<version>\d[\w.\-+]*)$"
)

_CACHE: dict[str, tuple[float, AttackSurfaceSnapshot]] = {}
_UNAVAILABLE_AT = 0.0

_GENERATED_FROM_LIVE = (
    "read-only projection of existing Http/Urls/Endpoints rows"
)
_GENERATED_FROM_INJECTED = "injected recon records (offline projection)"
_GENERATED_FROM_EMPTY = "no recon records available"


class _Doc:
    """Attribute shim so the existing ``from_document`` converters read dicts."""

    __slots__ = ("_data",)

    def __init__(self, data: dict):
        object.__setattr__(self, "_data", data)

    def __getattr__(self, name: str):
        data = object.__getattribute__(self, "_data")
        if name == "id":
            raw = data.get("_id")
            return "" if raw is None else str(raw)
        return data.get(name)


def _text(value: object, limit: int = 512) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def technology_name(label: object) -> str:
    """Strip an observed technology version, keeping the name only.

    ``nginx:1.24.0`` -> ``nginx``. A label without a parseable version is
    returned verbatim; a value is never guessed or upgraded.
    """

    if not isinstance(label, str):
        return ""
    text = label.strip()
    if not text or "\n" in text or "\r" in text:
        return ""
    match = _TECH_VERSION_RE.match(text)
    if not match:
        return text
    name = match.group("name").strip()
    return name or text


# ---------------------------------------------------------------------------
# Record coercion (pure)
# ---------------------------------------------------------------------------


def _coerce(record: object, kind: str):
    """Return a target-intelligence record from an object or a plain dict."""

    from ai.researcher.target_intelligence import (
        EndpointRecord,
        HttpRecord,
        UrlRecord,
    )

    mapping = {"http": HttpRecord, "url": UrlRecord, "endpoint": EndpointRecord}
    cls = mapping[kind]
    if isinstance(record, cls):
        return record
    if isinstance(record, dict):
        return cls.from_document(_Doc(record))
    raise TypeError(f"unsupported {kind} record: {type(record).__name__}")


def _endpoint_parameters(endpoint) -> list[tuple[str, str, str]]:
    """Return ``(name, method, location)`` triples for one endpoint.

    ``param_records`` (canonical provenance) wins when present; otherwise the
    endpoint's ``params`` list is used with the crawl defaults
    (``GET`` / ``query``). Parameter names are normalized and never invented.
    """

    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    records = getattr(endpoint, "param_records", ()) or ()
    for entry in records:
        name = _text(getattr(entry, "name", ""), 128)
        if not name:
            continue
        method = (_text(getattr(entry, "method", ""), 16) or "GET").upper()
        location = (_text(getattr(entry, "location", ""), 16) or "query").lower()
        key = (name, method, location)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    if out:
        return out
    for raw in getattr(endpoint, "params", ()) or ():
        name = _text(raw, 128)
        if not name:
            continue
        key = (name, "GET", "query")
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _path_of(url_record) -> str:
    raw_path = getattr(url_record, "path", "")
    if isinstance(raw_path, str) and ("\n" in raw_path or "\r" in raw_path):
        return ""
    path = _text(raw_path, 512)
    if path:
        return path if path.startswith("/") else "/" + path
    raw = _text(getattr(url_record, "url", ""), 1024)
    if not raw or "\n" in raw or "\r" in raw:
        return ""
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ""
    return parsed.path or "/"


def normalize_records(
    *,
    http_records: object = (),
    url_records: object = (),
    endpoint_records: object = (),
    programs: object = None,
) -> AttackSurfaceSnapshot:
    """Normalize existing recon records into the attack-surface snapshot.

    Pure and deterministic: the same input always yields the same output. One
    normalized record is produced per (endpoint, parameter, method, location)
    tuple. Domains/URLs/endpoints/parameters are counted across *all* observed
    rows, including endpoints that carry no parameters.
    """

    https = [_coerce(item, "http") for item in (http_records or ())]
    urls = [_coerce(item, "url") for item in (url_records or ())]
    endpoints = [_coerce(item, "endpoint") for item in (endpoint_records or ())]

    tech_by_subdomain: dict[tuple[str, str], set[str]] = {}
    for row in https:
        key = (_text(row.program_name, 128), _text(row.subdomain, 256))
        for label in row.tech:
            name = technology_name(label)
            if name:
                tech_by_subdomain.setdefault(key, set()).add(name)

    domains: set[str] = set()
    endpoint_keys: set[tuple[str, str, str]] = set()
    parameter_keys: set[tuple[str, str, str, str]] = set()
    url_keys: set[str] = set()
    records: list[AttackSurfaceRecord] = []
    record_keys: set[tuple] = set()

    def _emit(program: str, subdomain: str, endpoint_path: str, name: str,
              method: str, location: str, last_update: str | None,
              url: str) -> None:
        key = (program, subdomain, endpoint_path, name, method, location)
        if key in record_keys:
            return
        record_keys.add(key)
        records.append(
            AttackSurfaceRecord(
                program=program,
                subdomain=subdomain,
                url=url,
                endpoint=endpoint_path,
                parameter=name,
                method=method,
                location=location,
                technology=tuple(
                    sorted(tech_by_subdomain.get((program, subdomain), set()))
                ),
                source="watch",
                last_update=last_update,
            )
        )

    for row in endpoints:
        program = _text(row.program_name, 128)
        subdomain = _text(row.subdomain, 256)
        raw_path = row.path if isinstance(row.path, str) else ""
        if not raw_path.strip() or "\n" in raw_path or "\r" in raw_path:
            continue
        path = _text(raw_path, 512)
        if not path:
            continue
        if not path.startswith("/"):
            path = "/" + path
        if subdomain:
            domains.add(subdomain)
        endpoint_keys.add((program, subdomain, path))
        last_update = getattr(row, "last_update", None)
        for name, method, location in _endpoint_parameters(row):
            parameter_keys.add((program, subdomain, path, name))
            _emit(program, subdomain, path, name, method, location,
                  last_update, f"{path}?{name}=")

    for row in urls:
        program = _text(row.program_name, 128)
        subdomain = _text(row.subdomain, 256)
        path = _path_of(row)
        if not path:
            continue
        if subdomain:
            domains.add(subdomain)
        raw_url = _text(getattr(row, "url", ""), 1024)
        if raw_url:
            url_keys.add(raw_url)
        endpoint_keys.add((program, subdomain, path))
        last_update = getattr(row, "last_update", None)
        for raw in getattr(row, "params", ()) or ():
            name = _text(raw, 128)
            if not name:
                continue
            parameter_keys.add((program, subdomain, path, name))
            _emit(program, subdomain, path, name, "GET", "query",
                  last_update, f"{path}?{name}=")

    for row in https:
        subdomain = _text(row.subdomain, 256)
        if subdomain:
            domains.add(subdomain)

    requested = [
        _text(name, 128) for name in (programs or ()) if _text(name, 128)
    ]
    if not requested:
        requested = sorted(
            {
                _text(row.program_name, 128)
                for row in (*https, *urls, *endpoints)
                if _text(row.program_name, 128)
            }
        )

    records.sort(
        key=lambda item: (
            item.program,
            item.subdomain,
            item.endpoint,
            item.parameter,
            item.method,
            item.location,
        )
    )
    return AttackSurfaceSnapshot(
        programs=tuple(sorted(set(requested))),
        domains=tuple(sorted(domains)),
        url_count=len(url_keys),
        endpoint_count=len(endpoint_keys),
        parameter_count=len(parameter_keys),
        records=tuple(records),
        available=bool(records or endpoint_keys or url_keys),
        generated_from=_GENERATED_FROM_INJECTED,
    )


# ---------------------------------------------------------------------------
# Live read-only loading (Mongo)
# ---------------------------------------------------------------------------


def _mongo_ready(client) -> bool:
    global _UNAVAILABLE_AT
    now = time.monotonic()
    if _UNAVAILABLE_AT and (now - _UNAVAILABLE_AT) < _UNAVAILABLE_TTL:
        return False
    try:
        client.admin.command("ping")
        return True
    except Exception:
        _UNAVAILABLE_AT = now
        return False


def _known_programs(client) -> list[str]:
    try:
        from backend import observed_inventory

        return observed_inventory.list_programs()
    except Exception:
        return []


def _database(client):
    """Reuse the existing read-only database handle for the configured DB."""

    from backend.observed_inventory import _database as database_for

    return database_for(client)


def _counts_for(database, name: str) -> tuple[int, int, int, set[str]]:
    """Server-side discovery counts for one program (never loads rows).

    Returns ``(url_count, endpoint_count, parameter_count, domains)``. The
    counts are authoritative for the program; the bounded document sample used
    for candidate generation never changes them.
    """

    query = {"program_name": name}
    try:
        url_count = int(database["urls"].count_documents(query))
    except Exception:
        url_count = 0
    try:
        endpoint_count = int(database["endpoints"].count_documents(query))
    except Exception:
        endpoint_count = 0
    try:
        parameter_count = len(
            database["endpoints"].distinct("params", query)
        )
    except Exception:
        parameter_count = 0
    domains: set[str] = set()
    for collection in ("endpoints", "urls", "http"):
        try:
            domains.update(
                str(value)
                for value in database[collection].distinct(
                    "subdomain", query
                )
                if value
            )
        except Exception:
            continue
    return url_count, endpoint_count, parameter_count, domains


def _load_live(program: str | None, max_programs: int) -> AttackSurfaceSnapshot:
    client = None
    try:
        from backend.observed_inventory import _short_client

        client = _short_client()
    except Exception:
        client = None

    if client is None or not _mongo_ready(client):
        return AttackSurfaceSnapshot(
            programs=(),
            available=False,
            generated_from="database unavailable (read-only projection skipped)",
        )

    database = _database(client)
    if database is None:
        return AttackSurfaceSnapshot(
            programs=(),
            available=False,
            generated_from="database unavailable (read-only projection skipped)",
        )

    requested = _text(program, 128)
    if requested:
        names = [requested]
    else:
        names = _known_programs(client)[: max(max_programs, 0)]

    https: list[dict] = []
    urls: list[dict] = []
    endpoints: list[dict] = []
    domains: set[str] = set()
    url_count = endpoint_count = parameter_count = 0
    for name in names:
        query = {"program_name": name}
        u, e, p, subdomains = _counts_for(database, name)
        url_count += u
        endpoint_count += e
        parameter_count += p
        domains.update(subdomains)
        try:
            endpoints.extend(
                database["endpoints"]
                .find(query, _ENDPOINT_PROJECTION)
                .sort("hit_count", -1)
                .limit(DEFAULT_MAX_ENDPOINTS)
            )
        except Exception:
            pass
        try:
            urls.extend(
                database["urls"]
                .find(query, _URL_PROJECTION)
                .sort("last_update", -1)
                .limit(DEFAULT_MAX_URLS)
            )
        except Exception:
            pass
        try:
            https.extend(
                database["http"].find(query, _HTTP_PROJECTION).limit(
                    DEFAULT_MAX_HTTP
                )
            )
        except Exception:
            pass

    if not (https or urls or endpoints) and not (
        url_count or endpoint_count
    ):
        return AttackSurfaceSnapshot(
            programs=tuple(names),
            available=False,
            generated_from=_GENERATED_FROM_EMPTY,
        )

    snapshot = normalize_records(
        http_records=https,
        url_records=urls,
        endpoint_records=endpoints,
        programs=names,
    )
    return AttackSurfaceSnapshot(
        programs=snapshot.programs,
        domains=tuple(sorted(domains)) or snapshot.domains,
        url_count=url_count or snapshot.url_count,
        endpoint_count=endpoint_count or snapshot.endpoint_count,
        parameter_count=parameter_count or snapshot.parameter_count,
        records=snapshot.records,
        available=snapshot.available,
        generated_from=_GENERATED_FROM_LIVE,
        truncated=len(names) >= max_programs,
    )


def load_snapshot(
    program: str | None = None,
    *,
    records: dict | None = None,
    max_programs: int = DEFAULT_MAX_PROGRAMS,
    use_cache: bool = True,
) -> AttackSurfaceSnapshot:
    """Load the attack-surface snapshot read-only (fail-soft, never raises).

    ``records`` may inject already-loaded recon records for offline callers and
    tests; it is never read from disk or the network. When ``records`` is
    omitted the existing Mongo rows are read through the shared read-only
    accessor, with a short cache and an honest empty state on failure.
    """

    requested = _text(program, 128)
    if records is not None:
        snapshot = normalize_records(
            http_records=records.get("http_records"),
            url_records=records.get("url_records"),
            endpoint_records=records.get("endpoint_records"),
            programs=[requested] if requested else records.get("programs"),
        )
        return snapshot

    cache_key = requested or "*"
    now = time.monotonic()
    if use_cache:
        hit = _CACHE.get(cache_key)
        if hit and (now - hit[0]) < _CACHE_TTL:
            return hit[1]

    try:
        snapshot = _load_live(requested, max_programs)
    except Exception:
        snapshot = AttackSurfaceSnapshot(
            available=False,
            generated_from="attack-surface projection failed (fail-soft)",
        )

    if use_cache:
        _CACHE[cache_key] = (now, snapshot)
    return snapshot


def clear_cache() -> None:
    """Test helper: drop the derived snapshot cache (no persistence)."""

    global _UNAVAILABLE_AT
    _CACHE.clear()
    _UNAVAILABLE_AT = 0.0


__all__ = [
    "DEFAULT_MAX_PROGRAMS",
    "DEFAULT_MAX_ENDPOINTS",
    "DEFAULT_MAX_URLS",
    "DEFAULT_MAX_HTTP",
    "technology_name",
    "normalize_records",
    "load_snapshot",
    "clear_cache",
]
