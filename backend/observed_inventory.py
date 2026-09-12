"""backend/observed_inventory.py — Stage R30.2 observed inventory composition.

Read-only composition over *existing* Watch data:

- ``database.Http.tech``            -> technologies + technology versions
- ``database.Endpoints.path``       -> paths
- ``database.Endpoints.params`` /
  ``database.Endpoints.param_records`` -> parameters (+ provenance)
- ``database.Urls.path`` / ``url``  -> component/plugin inference evidence
- ``database.Programs`` / ``Subdomains`` -> program/subdomain membership

Stage R31.3 (additive) runs the pure R31.2 path inference
(``ai.knowledge.component_inference``) over the loaded URL/endpoint/HTTP
evidence and merges the inferred components/plugins into the inventory before
projection. The R30.2 pure builder is untouched; inference is deterministic and
fail-soft (a rule failure returns the inference-free inventory unchanged).

No persistence, no Mongo writes, no new collections, no network, no DNS, no
subprocess, no LLM, no Nuclei/browser/PoC, no target interaction, no findings,
no alerts. The reader is fail-soft: one malformed record never erases the
program inventory, and an unreachable database yields an explicit empty
inventory (``NOT_AVAILABLE_IN_CURRENT_DATA``) instead of fabricated evidence.

The Mongo client used here is a short-timeout, read-only client derived from the
already-configured mongoengine connection settings (no credential is ever
hard-coded or logged).
"""

from __future__ import annotations

import atexit
import time
from typing import Any, Optional

from ai.knowledge.component_inference import (
    apply_inferred_items,
    infer_inventory_items,
)
from ai.knowledge.observed_inventory import (
    RULE_VERSION,
    build_inventory_summary,
    build_observed_inventory,
)
from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    SubdomainRecord,
    UrlRecord,
)
from ai.schemas.observed_inventory import inventory_projection

MAX_PROGRAMS = 200

_CACHE_TTL = 10.0
_UNAVAILABLE_TTL = 60.0
_MONGO_TIMEOUT_MS = 800

_UNSET = object()
_CLIENT: Any = _UNSET
_CACHE: dict[str, tuple[float, dict]] = {}
_UNAVAILABLE_AT = 0.0

_COLLECTIONS = {
    "programs": {
        "program_name": 1,
        "scopes": 1,
        "ooscopes": 1,
    },
    "subdomains": {
        "program_name": 1,
        "subdomain": 1,
        "scope": 1,
        "providers": 1,
    },
    "http": {
        "program_name": 1,
        "subdomain": 1,
        "tech": 1,
        "url": 1,
        "final_url": 1,
    },
    "urls": {
        "program_name": 1,
        "subdomain": 1,
        "url": 1,
        "path": 1,
    },
    "endpoints": {
        "program_name": 1,
        "subdomain": 1,
        "path": 1,
        "params": 1,
        "params_from_crawl": 1,
        "params_from_x8": 1,
        "x8_checked": 1,
        "hit_count": 1,
        "param_records": 1,
    },
}


class _Document:
    """Attribute shim so existing ``from_document`` converters can read dicts."""

    __slots__ = ("_data",)

    def __init__(self, data: dict):
        object.__setattr__(self, "_data", data)

    def __getattr__(self, name: str):
        data = object.__getattribute__(self, "_data")
        if name == "id":
            raw = data.get("_id")
            return "" if raw is None else str(raw)
        return data.get(name)


def _local_programs() -> list[str]:
    try:
        from ai.knowledge.relevance import load_program_definitions
        from backend import research_data as rd

        definitions = load_program_definitions(rd.PROGRAMS_DIR)
    except Exception:
        return []
    return sorted(
        {
            str(entry.get("program") or "").strip()
            for entry in definitions
            if str(entry.get("program") or "").strip()
        }
    )


def _short_client():
    """Short-timeout read-only Mongo client (derived, never hard-coded)."""

    global _CLIENT
    if _CLIENT is not _UNSET:
        return _CLIENT
    try:
        import mongoengine.connection as mcon

        settings = dict(mcon._connection_settings.get("default") or {})
        host = settings.get("host")
        if isinstance(host, (list, tuple)):
            host = host[0] if host else None
        if not host:
            _CLIENT = None
        else:
            from pymongo import MongoClient

            _CLIENT = MongoClient(
                host,
                serverSelectionTimeoutMS=_MONGO_TIMEOUT_MS,
                connectTimeoutMS=_MONGO_TIMEOUT_MS,
                socketTimeoutMS=_MONGO_TIMEOUT_MS,
            )
            atexit.register(_close_client)
    except Exception:
        _CLIENT = None
    return _CLIENT


def _close_client() -> None:
    """Close the derived read-only client at interpreter exit (best-effort)."""

    client = _CLIENT
    if client is None or client is _UNSET:
        return
    try:
        client.close()
    except Exception:
        pass


def _mongo_ready(client) -> bool:
    """Fast cached availability probe (local DB only; never external)."""

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


def _fetch_documents(program: str) -> Optional[dict]:
    """Raw read-only documents for one program; None when Mongo is offline."""

    client = _short_client()
    if client is None or not _mongo_ready(client):
        return None
    out: dict = {}
    try:
        database = client.get_database()
    except Exception:
        return None
    for name, projection in _COLLECTIONS.items():
        try:
            out[name] = list(
                database[name].find(
                    {"program_name": program}, projection
                )
            )
        except Exception:
            # One malformed/unreadable collection must not erase the rest.
            out[name] = []
    return out


def _records(documents: dict) -> dict:
    """Convert raw documents through the existing record converters."""

    http_records = []
    for item in documents.get("http") or ():
        try:
            http_records.append(
                HttpRecord.from_document(_Document(item))
            )
        except Exception:
            continue
    url_records = []
    for item in documents.get("urls") or ():
        try:
            url_records.append(
                UrlRecord.from_document(_Document(item))
            )
        except Exception:
            continue
    endpoint_records = []
    for item in documents.get("endpoints") or ():
        try:
            endpoint_records.append(
                EndpointRecord.from_document(_Document(item))
            )
        except Exception:
            continue
    subdomain_records = []
    for item in documents.get("subdomains") or ():
        try:
            subdomain_records.append(
                SubdomainRecord.from_document(_Document(item))
            )
        except Exception:
            continue
    return {
        "http_records": http_records,
        "url_records": url_records,
        "endpoint_records": endpoint_records,
        "subdomain_records": subdomain_records,
    }


def _empty_records() -> dict:
    return {
        "http_records": [],
        "url_records": [],
        "endpoint_records": [],
        "subdomain_records": [],
    }


def _apply_inference(data: Optional[dict], inventory):
    """Stage R31.3: merge R31.2 inferred components/plugins (fail-soft).

    Pure, read-only and additive: the inference never invents values beyond the
    anchored ``ai.knowledge.component_inference.RULES``; on any failure the
    original inventory is returned unchanged so technologies, versions and
    version associations are never affected.
    """

    records = data or {}
    try:
        inferred = infer_inventory_items(
            url_records=records.get("url_records") or (),
            endpoint_records=records.get("endpoint_records") or (),
            http_records=records.get("http_records") or (),
        )
        return apply_inferred_items(inventory, inferred)
    except Exception:
        return inventory


def _mongo_programs(client) -> list[str]:
    if client is None or not _mongo_ready(client):
        return []
    try:
        names = client.get_database()["programs"].distinct("program_name")
    except Exception:
        return []
    return sorted({str(name).strip() for name in names if str(name).strip()})


def list_programs() -> list[str]:
    """Known programs: local definitions plus (when reachable) Mongo rows."""

    names = set(_local_programs())
    names.update(_mongo_programs(_short_client()))
    return sorted(names)[:MAX_PROGRAMS]


def _build_records(
    program: str,
    records: Optional[dict] = None,
) -> Optional[dict]:
    if records is not None:
        merged = _empty_records()
        for key in merged:
            merged[key] = list(records.get(key) or ())
        return merged
    documents = _fetch_documents(program)
    if documents is None:
        return None
    return _records(documents)


def build_inventory(
    program: Optional[str] = None,
    *,
    records: Optional[dict] = None,
) -> list[dict]:
    """Deterministic observed inventory projections (read-only, fail-soft).

    ``program=None`` projects every known program. ``records`` may inject
    already-loaded records (tests, offline callers); it is never read from disk
    or the network. Stage R31.3 merges the R31.2 inferred components/plugins
    before projection; on inference failure the projection is unchanged.
    """

    requested = str(program or "").strip()
    if records is not None:
        target = requested or "unknown"
        data = _build_records(target, records)
        inventory = build_observed_inventory(target, **(data or {}))
        inventory = _apply_inference(data, inventory)
        return [inventory_projection(inventory)]

    if requested:
        names = [requested]
    else:
        names = list_programs()

    out: list[dict] = []
    for name in names[:MAX_PROGRAMS]:
        data = _build_records(name)
        if data is None:
            data = _empty_records()
        inventory = build_observed_inventory(name, **data)
        inventory = _apply_inference(data, inventory)
        out.append(inventory_projection(inventory))
    out.sort(key=lambda item: item["program"])
    return out


def get_inventory(
    program: str,
    *,
    records: Optional[dict] = None,
) -> Optional[dict]:
    """One program's observed inventory, or None when unknown (fail-soft)."""

    name = str(program or "").strip()
    if not name:
        return None
    if records is not None:
        return build_inventory(name, records=records)[0]
    now = time.monotonic()
    hit = _CACHE.get(name)
    if hit and (now - hit[0]) < _CACHE_TTL:
        return hit[1]
    if name not in set(list_programs()):
        return None
    data = _build_records(name)
    if data is None:
        data = _empty_records()
    inventory = build_observed_inventory(name, **data)
    inventory = _apply_inference(data, inventory)
    value = inventory_projection(inventory)
    _CACHE[name] = (now, value)
    return value


def get_inventory_summary() -> dict:
    """Compact deterministic inventory summary across known programs."""

    from ai.schemas.observed_inventory import ObservedAssetInventory

    models = [
        ObservedAssetInventory.model_validate(item)
        for item in build_inventory()
    ]
    return build_inventory_summary(models)


def clear_cache() -> None:
    """Test helper: drop derived caches (no persistence)."""

    global _UNAVAILABLE_AT
    _CACHE.clear()
    _UNAVAILABLE_AT = 0.0


__all__ = [
    "MAX_PROGRAMS",
    "RULE_VERSION",
    "list_programs",
    "build_inventory",
    "get_inventory",
    "get_inventory_summary",
    "clear_cache",
]
