"""Stage R61 additive real recon snapshot and normalization layer.

Offline-first, read-only extraction of one Watch program's reconnaissance rows
into a deterministic JSON snapshot, plus reconstruction of the existing record
classes for the R30.2/R31 inventory path through the existing
``build_inventory(program, records=...)`` injection point.

Pipeline position (additive; nothing existing is modified)::

    MongoDB (read-only, program-scoped, projection-based, bounded)
        -> raw projected records
        -> existing Record classes (ai.researcher.target_intelligence)
        -> normalized deterministic snapshot (this module)
        -> records= injection
        -> existing R30.2 / R31-R38 pipeline

Hard boundaries:

- Read-only: only ``find`` / ``find_one`` with projections, a deterministic
  server-side sort and an explicit limit. No insert/update/delete/replace,
  no index creation, no drop, no bulk write, no cursor without a limit.
- Program-scoped: every query filters on one exact ``program_name`` and rows
  whose relationship key does not match are skipped and counted.
- Mongo ``_id`` is excluded from every projection and never appears in a
  snapshot. Record identity is a deterministic natural-key reference
  (``rec-<16 hex>``) derived from the program, collection and stable natural
  key, so the same input always produces the same reference.
- Timestamps are not part of the snapshot: they are dropped so identity and
  serialized output stay deterministic.
- No intelligence: this layer performs no matching, scoring, version
  comparison, inference or verdict. It only projects stored values. The
  existing R30.2/R31 engines consume the reconstructed records subsequently.
- No network, DNS, subprocess, browser, scanner or LLM activity: a stored URL
  is DATA and is never fetched or resolved.

Bounded extraction: each collection is read with an explicit limit of
``cap * fetch_factor`` rows (server-sorted deterministically), then reduced to
``cap`` rows by the documented in-memory priority order. The full collection is
never materialized.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ParamRecord,
    SubdomainRecord,
    UrlRecord,
)
from backend.observed_inventory import _Document

RULE_VERSION = "r61-1"
SNAPSHOT_VERSION = 1

DEFAULT_CAPS: dict[str, int] = {
    "subdomains": 500,
    "live_subdomains": 500,
    "http": 300,
    "urls": 1000,
    "endpoints": 1000,
}
DEFAULT_FETCH_FACTOR = 5
MONGO_TIMEOUT_MS = 800
MONGO_SOCKET_MS = 30000

COLLECTIONS: tuple[str, ...] = (
    "subdomains",
    "live_subdomains",
    "http",
    "urls",
    "endpoints",
)

PROJECTIONS: dict[str, dict] = {
    "subdomains": {
        "_id": 0,
        "program_name": 1,
        "subdomain": 1,
        "scope": 1,
        "providers": 1,
    },
    "live_subdomains": {
        "_id": 0,
        "program_name": 1,
        "subdomain": 1,
        "scope": 1,
        "ips": 1,
        "cdn": 1,
    },
    "http": {
        "_id": 0,
        "program_name": 1,
        "subdomain": 1,
        "scope": 1,
        "ips": 1,
        "tech": 1,
        "title": 1,
        "status_code": 1,
        "url": 1,
        "final_url": 1,
        "favicon": 1,
    },
    "urls": {
        "_id": 0,
        "program_name": 1,
        "subdomain": 1,
        "url": 1,
        "path": 1,
        "params": 1,
        "sources": 1,
    },
    "endpoints": {
        "_id": 0,
        "program_name": 1,
        "subdomain": 1,
        "path": 1,
        "example_url": 1,
        "params": 1,
        "params_from_crawl": 1,
        "params_from_x8": 1,
        "x8_checked": 1,
        "hit_count": 1,
        "param_records": 1,
    },
}

PROGRAM_PROJECTION: dict = {
    "_id": 0,
    "program_name": 1,
    "scopes": 1,
    "ooscopes": 1,
}

SERVER_SORTS: dict[str, list[tuple[str, int]]] = {
    "subdomains": [("subdomain", 1)],
    "live_subdomains": [("subdomain", 1)],
    "http": [("subdomain", 1), ("url", 1)],
    "urls": [("url", 1)],
    "endpoints": [("hit_count", -1), ("subdomain", 1), ("path", 1)],
}

MAX_SUBDOMAIN = 256
MAX_SCOPE = 256
MAX_URL = 2048
MAX_PATH = 2048
MAX_TITLE = 512
MAX_TECH = 512
MAX_PARAM = 128
MAX_SOURCE = 64
MAX_IP = 256
MAX_CDN = 64
MAX_FAVICON = 256

_ESCAPED_AMP_RE = re.compile(r"\\+u0026")
_HTML_AMP = "&amp;"
_INTERESTING_PATH_RE = re.compile(
    r"(api|graphql|admin|auth|login|token|upload|redirect|internal)",
    re.IGNORECASE,
)
_SINGLE_LINE_RE = re.compile(r"[\r\n]+")
_REF_RE = re.compile(r"^rec-[0-9a-f]{16}$")


class SnapshotError(ValueError):
    """Deterministic, secret-free snapshot validation failure."""


def _single_line(value: object, limit: int) -> str:
    text = _SINGLE_LINE_RE.sub(" ", str(value if value is not None else ""))
    return text.strip()[:limit]


def _string_list(values: object, limit: int) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = _single_line(item, limit)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return sorted(out)


def _optional_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def canonicalize_url(value: object) -> str:
    """Conservative deterministic URL canonicalization.

    Only the encoding artifacts observed by the mapping audit are rewritten:

    - literal ``\\u0026`` escapes become ``&`` (repeatedly, for double escapes);
    - literal ``&amp;`` HTML entities become ``&`` (repeatedly);
    - trailing backslash and whitespace artifacts are stripped.

    Nothing else is touched: percent-encoding, query parameter order and path
    casing are preserved. The stored semantic parameter lists remain
    authoritative and are never re-derived from the URL.
    """

    text = _single_line(value, MAX_URL)
    text = _ESCAPED_AMP_RE.sub("&", text)
    while _HTML_AMP in text:
        text = text.replace(_HTML_AMP, "&")
    text = text.rstrip("\\")
    return text.strip()[:MAX_URL]


def record_ref(program: str, collection: str, natural_key: Sequence[object]) -> str:
    """Deterministic natural-key-derived record reference (never ``_id``)."""

    if not isinstance(program, str) or not program.strip():
        raise SnapshotError("program must be a non-empty string")
    if collection not in COLLECTIONS:
        raise SnapshotError(f"unknown collection: {collection!r}")
    if not isinstance(natural_key, (list, tuple)):
        raise SnapshotError("natural_key must be a list or tuple")
    basis = json.dumps(
        {
            "collection": collection,
            "natural_key": [str(part) for part in natural_key],
            "program": program,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "rec-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _convert_subdomain(program: str, document: dict) -> tuple[str, dict | None]:
    record = SubdomainRecord.from_document(_Document(document))
    if not record.program_name or not record.subdomain:
        return "malformed", None
    if record.program_name != program:
        return "other", None
    return "ok", {
        "record_ref": record_ref(
            program, "subdomains", (record.subdomain,)
        ),
        "program_name": record.program_name,
        "subdomain": _single_line(record.subdomain, MAX_SUBDOMAIN),
        "scope": _single_line(record.scope, MAX_SCOPE),
        "providers": _string_list(record.providers, MAX_SOURCE),
    }


def _convert_live_subdomain(
    program: str, document: dict
) -> tuple[str, dict | None]:
    name = _single_line(document.get("program_name"), MAX_SUBDOMAIN)
    subdomain = _single_line(document.get("subdomain"), MAX_SUBDOMAIN)
    if not name or not subdomain:
        return "malformed", None
    if name != program:
        return "other", None
    return "ok", {
        "record_ref": record_ref(
            program, "live_subdomains", (subdomain,)
        ),
        "program_name": name,
        "subdomain": subdomain,
        "scope": _single_line(document.get("scope"), MAX_SCOPE),
        "ips": _string_list(document.get("ips"), MAX_IP),
        "cdn": _single_line(document.get("cdn"), MAX_CDN),
    }


def _convert_http(program: str, document: dict) -> tuple[str, dict | None]:
    record = HttpRecord.from_document(_Document(document))
    if not record.program_name or not record.subdomain:
        return "malformed", None
    if record.program_name != program:
        return "other", None
    return "ok", {
        "record_ref": record_ref(
            program, "http", (record.subdomain, record.url)
        ),
        "program_name": record.program_name,
        "subdomain": _single_line(record.subdomain, MAX_SUBDOMAIN),
        "scope": _single_line(record.scope, MAX_SCOPE),
        "ips": _string_list(record.ips, MAX_IP),
        "tech": _string_list(record.tech, MAX_TECH),
        "title": _single_line(record.title, MAX_TITLE),
        "status_code": _optional_int(record.status_code),
        "url": canonicalize_url(record.url),
        "final_url": canonicalize_url(record.final_url),
        "favicon": _single_line(record.favicon, MAX_FAVICON),
    }


def _convert_url(program: str, document: dict) -> tuple[str, dict | None]:
    record = UrlRecord.from_document(_Document(document))
    if not record.program_name or not record.subdomain:
        return "malformed", None
    if record.program_name != program:
        return "other", None
    return "ok", {
        "record_ref": record_ref(program, "urls", (record.url,)),
        "program_name": record.program_name,
        "subdomain": _single_line(record.subdomain, MAX_SUBDOMAIN),
        "url": canonicalize_url(record.url),
        "path": _single_line(record.path, MAX_PATH),
        "params": _string_list(record.params, MAX_PARAM),
        "sources": _string_list(record.sources, MAX_SOURCE),
    }


def _normalize_param_records(record: EndpointRecord) -> list[dict]:
    entries: dict[tuple[str, str, str, str], dict] = {}
    for entry in record.param_records:
        name = _single_line(entry.name, MAX_PARAM)
        if not name:
            continue
        key = (
            name,
            _single_line(entry.method, MAX_SOURCE),
            _single_line(entry.location, MAX_SOURCE),
            _single_line(entry.source, MAX_SOURCE),
        )
        entries.setdefault(
            key,
            {
                "name": key[0],
                "method": key[1],
                "location": key[2],
                "source": key[3],
            },
        )
    return [entries[key] for key in sorted(entries)]


def _convert_endpoint(program: str, document: dict) -> tuple[str, dict | None]:
    record = EndpointRecord.from_document(_Document(document))
    if not record.program_name or not record.subdomain:
        return "malformed", None
    if record.program_name != program:
        return "other", None
    return "ok", {
        "record_ref": record_ref(
            program, "endpoints", (record.subdomain, record.path)
        ),
        "program_name": record.program_name,
        "subdomain": _single_line(record.subdomain, MAX_SUBDOMAIN),
        "path": _single_line(record.path, MAX_PATH),
        "example_url": canonicalize_url(record.example_url),
        "params": _string_list(record.params, MAX_PARAM),
        "params_from_crawl": _string_list(
            record.params_from_crawl, MAX_PARAM
        ),
        "params_from_x8": _string_list(record.params_from_x8, MAX_PARAM),
        "x8_checked": record.x8_checked is True,
        "hit_count": _optional_int(record.hit_count),
        "param_records": _normalize_param_records(record),
    }


_CONVERTERS = {
    "subdomains": _convert_subdomain,
    "live_subdomains": _convert_live_subdomain,
    "http": _convert_http,
    "urls": _convert_url,
    "endpoints": _convert_endpoint,
}


def _endpoint_priority(record: dict) -> tuple:
    return (
        0 if record["params"] else 1,
        0 if record["param_records"] else 1,
        -(record["hit_count"] or 0),
        record["subdomain"],
        record["path"],
    )


def _url_priority(record: dict) -> tuple:
    return (
        0 if record["params"] else 1,
        0 if _INTERESTING_PATH_RE.search(record["path"] or "") else 1,
        record["subdomain"],
        record["url"],
    )


def _http_priority(record: dict) -> tuple:
    return (
        0 if record["tech"] else 1,
        0 if record["status_code"] not in (404, None) else 1,
        record["subdomain"],
        record["url"],
    )


_PRIORITY_KEYS = {
    "subdomains": lambda record: (record["subdomain"],),
    "live_subdomains": lambda record: (record["subdomain"],),
    "http": _http_priority,
    "urls": _url_priority,
    "endpoints": _endpoint_priority,
}

_OUTPUT_KEYS = {
    "subdomains": lambda record: (record["subdomain"], record["record_ref"]),
    "live_subdomains": lambda record: (
        record["subdomain"],
        record["record_ref"],
    ),
    "http": lambda record: (
        record["subdomain"],
        record["url"],
        record["record_ref"],
    ),
    "urls": lambda record: (
        record["subdomain"],
        record["url"],
        record["record_ref"],
    ),
    "endpoints": lambda record: (
        record["subdomain"],
        record["path"],
        record["record_ref"],
    ),
}


def _normalize_records(
    program: str,
    collection: str,
    documents: Iterable[dict],
    cap: int,
) -> tuple[list[dict], dict]:
    convert = _CONVERTERS[collection]
    stats = {
        "fetched": 0,
        "selected": 0,
        "skipped_other_program": 0,
        "malformed": 0,
        "duplicates_dropped": 0,
    }
    normalized: list[dict] = []
    for document in documents:
        stats["fetched"] += 1
        try:
            status, record = convert(program, document)
        except Exception:
            status, record = "malformed", None
        if status == "other":
            stats["skipped_other_program"] += 1
            continue
        if status != "ok" or record is None:
            stats["malformed"] += 1
            continue
        normalized.append(record)
    normalized.sort(key=_PRIORITY_KEYS[collection])
    deduped: list[dict] = []
    seen: set[str] = set()
    for record in normalized:
        reference = record["record_ref"]
        if reference in seen:
            stats["duplicates_dropped"] += 1
            continue
        seen.add(reference)
        deduped.append(record)
    selected = deduped[:cap]
    selected.sort(key=_OUTPUT_KEYS[collection])
    stats["selected"] = len(selected)
    return selected, stats


def _validate_program(program: object) -> str:
    if not isinstance(program, str) or not program.strip():
        raise SnapshotError("program must be a non-empty string")
    name = program.strip()
    if len(name) > 128 or _SINGLE_LINE_RE.search(name):
        raise SnapshotError("program must be a single-line name under 128 chars")
    return name


def _effective_caps(caps: Mapping | None) -> dict[str, int]:
    if caps is None:
        caps = {}
    if not isinstance(caps, Mapping):
        raise SnapshotError("caps must be a mapping")
    unknown = sorted(set(caps) - set(DEFAULT_CAPS))
    if unknown:
        raise SnapshotError(f"unknown cap keys: {unknown}")
    effective = dict(DEFAULT_CAPS)
    for key, value in caps.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise SnapshotError(f"cap {key!r} must be an integer")
        if value < 0:
            raise SnapshotError(f"cap {key!r} must be >= 0")
        effective[key] = value
    return effective


def _effective_fetch_factor(fetch_factor: object) -> int:
    if fetch_factor is None:
        return DEFAULT_FETCH_FACTOR
    if isinstance(fetch_factor, bool) or not isinstance(fetch_factor, int):
        raise SnapshotError("fetch_factor must be an integer >= 1")
    if fetch_factor < 1:
        raise SnapshotError("fetch_factor must be >= 1")
    return fetch_factor


def _effective_collections(collections: object) -> list[str]:
    if collections is None:
        return list(COLLECTIONS)
    requested = [str(item) for item in collections]
    unknown = sorted(set(requested) - set(COLLECTIONS))
    if unknown:
        raise SnapshotError(f"unknown collections: {unknown}")
    wanted = set(requested)
    return [name for name in COLLECTIONS if name in wanted]


def _default_database(client: object):
    database = None
    getter = getattr(client, "get_default_database", None)
    if callable(getter):
        try:
            database = getter()
        except Exception:
            database = None
    if database is None:
        database = client["watch"]
    return database


def _fetch_records(
    database: object,
    collection: str,
    program: str,
    limit: int,
) -> list[dict]:
    if limit <= 0:
        return []
    cursor = database[collection].find(
        {"program_name": program}, PROJECTIONS[collection]
    )
    cursor = cursor.sort(SERVER_SORTS[collection])
    cursor = cursor.limit(limit)
    return [document for document in cursor if isinstance(document, dict)]


def _fetch_program_metadata(database: object, program: str) -> dict | None:
    document = database["programs"].find_one(
        {"program_name": program}, PROGRAM_PROJECTION
    )
    if not isinstance(document, dict):
        return None
    return {
        "program_name": _single_line(
            document.get("program_name"), MAX_SUBDOMAIN
        ),
        "scopes": _string_list(document.get("scopes"), MAX_SCOPE),
        "ooscopes": _string_list(document.get("ooscopes"), MAX_SCOPE),
    }


def build_snapshot(
    program: str,
    *,
    client: object = None,
    uri: str | None = None,
    caps: Mapping | None = None,
    fetch_factor: int | None = None,
    collections: Sequence[str] | None = None,
    include_program: bool = True,
    timeout_ms: int = MONGO_TIMEOUT_MS,
) -> dict:
    """Build one deterministic, program-scoped recon snapshot.

    ``client`` may be injected (offline tests / callers that own a read-only
    client). When omitted, a short-timeout ``pymongo.MongoClient`` is created
    from ``uri`` or the environment-provided ``WATCH_MONGO_URI`` and closed
    before returning. The database handle is derived like the existing
    read-only adapter (default database, ``watch`` fallback).
    """

    name = _validate_program(program)
    effective_caps = _effective_caps(caps)
    factor = _effective_fetch_factor(fetch_factor)
    selected_collections = _effective_collections(collections)

    owns_client = client is None
    if owns_client:
        from pymongo import MongoClient

        from ai.config import require_mongo_uri

        resolved = uri or require_mongo_uri()
        client = MongoClient(
            resolved,
            serverSelectionTimeoutMS=timeout_ms,
            connectTimeoutMS=timeout_ms,
            socketTimeoutMS=MONGO_SOCKET_MS,
        )
    try:
        database = _default_database(client)
        metadata = (
            _fetch_program_metadata(database, name)
            if include_program
            else None
        )
        collection_payload: dict[str, dict] = {}
        total_selected = 0
        total_fetched = 0
        for collection in selected_collections:
            cap = effective_caps[collection]
            documents = _fetch_records(
                database, collection, name, cap * factor
            )
            records, stats = _normalize_records(
                name, collection, documents, cap
            )
            collection_payload[collection] = {
                "stats": stats,
                "records": records,
            }
            total_selected += stats["selected"]
            total_fetched += stats["fetched"]
    finally:
        if owns_client:
            close = getattr(client, "close", None)
            if callable(close):
                close()

    return {
        "snapshot_version": SNAPSHOT_VERSION,
        "rule_version": RULE_VERSION,
        "program": name,
        "read_only": True,
        "research_only": True,
        "caps": {
            collection: effective_caps[collection]
            for collection in selected_collections
        },
        "fetch_factor": factor,
        "program_metadata": metadata,
        "collections": collection_payload,
        "stats": {
            "total_fetched": total_fetched,
            "total_selected": total_selected,
            "collections": {
                collection: collection_payload[collection]["stats"]
                for collection in selected_collections
            },
        },
    }


def snapshot_to_json(snapshot: Mapping) -> str:
    """Canonical deterministic JSON for one snapshot (sorted keys, 2-space)."""

    _validate_snapshot(snapshot)
    return (
        json.dumps(
            snapshot,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def save_snapshot(snapshot: Mapping, path: str | Path) -> Path:
    """Write one snapshot to ``path`` deterministically (no DB access)."""

    target = Path(path)
    target.write_text(snapshot_to_json(snapshot), encoding="utf-8")
    return target


def load_snapshot(path: str | Path) -> dict:
    """Read and validate one snapshot from disk (no DB access)."""

    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SnapshotError(
            f"invalid snapshot file: {source}"
        ) from exc
    return _validate_snapshot(payload)


def _validate_snapshot(snapshot: object) -> dict:
    if not isinstance(snapshot, Mapping):
        raise SnapshotError("snapshot must be a mapping")
    if snapshot.get("snapshot_version") != SNAPSHOT_VERSION:
        raise SnapshotError("unsupported snapshot version")
    if snapshot.get("rule_version") != RULE_VERSION:
        raise SnapshotError("unsupported snapshot rule version")
    program = snapshot.get("program")
    if not isinstance(program, str) or not program.strip():
        raise SnapshotError("snapshot program must be a non-empty string")
    collections = snapshot.get("collections")
    if not isinstance(collections, Mapping):
        raise SnapshotError("snapshot collections must be a mapping")
    for name, payload in collections.items():
        if name not in COLLECTIONS:
            raise SnapshotError(f"unknown snapshot collection: {name!r}")
        if not isinstance(payload, Mapping):
            raise SnapshotError(f"snapshot collection {name!r} malformed")
        records = payload.get("records")
        if not isinstance(records, list):
            raise SnapshotError(f"snapshot records {name!r} must be a list")
        for record in records:
            if not isinstance(record, Mapping):
                raise SnapshotError("snapshot record must be a mapping")
            reference = record.get("record_ref")
            if not isinstance(reference, str) or not _REF_RE.match(reference):
                raise SnapshotError(
                    f"malformed record reference: {reference!r}"
                )
    return dict(snapshot)


def _snapshot_records(snapshot: Mapping, collection: str) -> list[dict]:
    payload = snapshot.get("collections", {}).get(collection) or {}
    return list(payload.get("records") or [])


def records_for_inventory(snapshot: Mapping) -> dict:
    """Reconstruct existing record classes for ``build_inventory(records=...)``.

    Returns the exact mapping expected by
    ``backend.observed_inventory.build_inventory(program, records=...)``:
    ``http_records`` / ``url_records`` / ``endpoint_records`` /
    ``subdomain_records`` built from the snapshot's deterministic
    ``record_ref`` values, with no MongoDB access.
    """

    _validate_snapshot(snapshot)
    http_records = [
        HttpRecord(
            program_name=record.get("program_name", ""),
            subdomain=record.get("subdomain", ""),
            scope=record.get("scope", ""),
            ips=tuple(record.get("ips") or ()),
            tech=tuple(record.get("tech") or ()),
            title=record.get("title", ""),
            status_code=record.get("status_code"),
            headers=(),
            url=record.get("url", ""),
            final_url=record.get("final_url", ""),
            favicon=record.get("favicon", ""),
            last_update=None,
            record_id=record["record_ref"],
        )
        for record in _snapshot_records(snapshot, "http")
    ]
    url_records = [
        UrlRecord(
            program_name=record.get("program_name", ""),
            subdomain=record.get("subdomain", ""),
            url=record.get("url", ""),
            path=record.get("path", ""),
            params=tuple(record.get("params") or ()),
            sources=tuple(record.get("sources") or ()),
            status_code=None,
            last_update=None,
            record_id=record["record_ref"],
        )
        for record in _snapshot_records(snapshot, "urls")
    ]
    endpoint_records = [
        EndpointRecord(
            program_name=record.get("program_name", ""),
            subdomain=record.get("subdomain", ""),
            path=record.get("path", ""),
            example_url=record.get("example_url", ""),
            params=tuple(record.get("params") or ()),
            params_from_crawl=tuple(record.get("params_from_crawl") or ()),
            params_from_x8=tuple(record.get("params_from_x8") or ()),
            x8_checked=record.get("x8_checked") is True,
            hit_count=record.get("hit_count"),
            param_records=tuple(
                ParamRecord(
                    name=entry.get("name", ""),
                    method=entry.get("method", ""),
                    location=entry.get("location", ""),
                    source=entry.get("source", ""),
                )
                for entry in record.get("param_records") or ()
            ),
            last_update=None,
            record_id=record["record_ref"],
        )
        for record in _snapshot_records(snapshot, "endpoints")
    ]
    subdomain_records = [
        SubdomainRecord(
            program_name=record.get("program_name", ""),
            subdomain=record.get("subdomain", ""),
            scope=record.get("scope", ""),
            providers=tuple(record.get("providers") or ()),
            record_id=record["record_ref"],
        )
        for record in _snapshot_records(snapshot, "subdomains")
    ]
    return {
        "http_records": http_records,
        "url_records": url_records,
        "endpoint_records": endpoint_records,
        "subdomain_records": subdomain_records,
    }


__all__ = [
    "RULE_VERSION",
    "SNAPSHOT_VERSION",
    "DEFAULT_CAPS",
    "DEFAULT_FETCH_FACTOR",
    "COLLECTIONS",
    "SnapshotError",
    "build_snapshot",
    "save_snapshot",
    "load_snapshot",
    "snapshot_to_json",
    "records_for_inventory",
    "canonicalize_url",
    "record_ref",
]
