"""Production Watch-data read adapters (Stage 2, B1/B2 read path).

Read-only projections of the existing Watch Mongo model
(``database.db``: ``Programs`` / ``Http`` / ``LiveSubdomains`` /
``Endpoints``) into the frozen 5B–5J record types. This module NEVER
imports ``database.db`` (which connects at import time) and never
imports ``mongoengine``/``pymongo``: every reader is constructed over
a duck-typed row source, so unit tests inject plain dicts and
production wiring injects thin collection shims.

Readers (all fail closed on malformed rows):

- ``WatchProgramReader`` protocol: ``get_program_row(program_name)``
  returns ``{"program_name", "scopes", "ooscopes"}`` or ``None``
  (program gone). ``DictProgramReader`` (in-memory/test),
  ``MongoProgramReader`` (injected ``find_one``-shaped collection).
- ``WatchAssetReader`` protocol: ``get_asset_rows(program_name,
  subdomain)`` returns a list of ``{"ips", "url"}`` observations
  from ``Http``-shaped and ``LiveSubdomains``-shaped rows.
  ``DictAssetReader`` / ``MongoAssetReader`` (two injected
  collections: http + live).

Builders (pure, deterministic):

- ``policy_for_program(reader, program_name)`` compiles the live
  ``(scopes, ooscopes)`` pair through the EXISTING
  ``ai.scope.policy.compile_policy`` — matching behavior, ooscope
  handling, and ``scope_lists_hash`` semantics are unchanged.
  Returns ``None`` when the program is gone (the 5D evaluator then
  denies with ``PROGRAM_NOT_FOUND``); malformed lists raise the
  existing closed ``PolicyError``.
- ``address_facts_for(asset_reader, program_name, subdomain)``
  merges ``Http.ips`` + ``LiveSubdomains.ips`` into a sorted,
  deduplicated address tuple for ``AddressReview`` construction
  (facts only — safety classification still happens in the frozen
  ``validate_answers`` gate at resolve time).
- ``inventory_records_for(program_row, canonical_host, scheme, port,
  asset_rows)`` builds the frozen ``ProgramRecord`` + ``AssetRecord``
  pair consumed by ``InMemoryInventoryRepository``.

Drift detection needs no new code: issuance binds
``scope_lists_hash_for(scopes, ooscopes)`` and both the 5C resolver
(comparing current vs authorized hash) and the 5D evaluator (fresh
policy re-read per evaluation) already fail closed on mismatch.
"""

from __future__ import annotations

from typing import Protocol

from ai.resolver.inventory import AssetRecord, ProgramRecord
from ai.scope.policy import CompiledScopePolicy, PolicyError, compile_policy

__all__ = [
    "WatchReadError",
    "WatchProgramReader",
    "DictProgramReader",
    "MongoProgramReader",
    "WatchAssetReader",
    "DictAssetReader",
    "MongoAssetReader",
    "policy_for_program",
    "address_facts_for",
    "inventory_records_for",
]


class WatchReadError(ValueError):
    """Watch-row read/validation failure (fail closed, secret-free)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in ("PROGRAM_ROW_MALFORMED", "ASSET_ROW_MALFORMED"):
            raise ValueError(f"unknown watch read code: {code!r}")
        safe = (detail or "")[:200]
        if "\n" in safe or "\r" in safe:
            raise ValueError("watch read detail must be single-line")
        super().__init__(f"{code}: {safe}" if safe else code)
        self.code = code
        self.detail = safe


def _program_row(
    program_name: object, scopes: object, ooscopes: object
) -> dict:
    if not isinstance(program_name, str) or not program_name.strip():
        raise WatchReadError("PROGRAM_ROW_MALFORMED", "bad program name")
    for label, entries in (("scopes", scopes), ("ooscopes", ooscopes)):
        if not isinstance(entries, (list, tuple)):
            raise WatchReadError(
                "PROGRAM_ROW_MALFORMED", f"bad program {label}"
            )
        for entry in entries:
            if not isinstance(entry, str) or not entry:
                raise WatchReadError(
                    "PROGRAM_ROW_MALFORMED", f"bad program {label} entry"
                )
    return {
        "program_name": program_name,
        "scopes": list(scopes),
        "ooscopes": list(ooscopes),
    }


def _asset_row(ips: object, url: object) -> dict:
    if ips is None:
        ips = []
    if not isinstance(ips, (list, tuple)):
        raise WatchReadError("ASSET_ROW_MALFORMED", "bad asset ips")
    for entry in ips:
        if not isinstance(entry, str):
            raise WatchReadError("ASSET_ROW_MALFORMED", "bad asset ip entry")
    if url is not None and not isinstance(url, str):
        raise WatchReadError("ASSET_ROW_MALFORMED", "bad asset url")
    return {"ips": list(ips), "url": url}


class WatchProgramReader(Protocol):
    """Read-only program-row accessor (dicts, never ORM objects)."""

    def get_program_row(self, program_name: str) -> dict | None: ...


class DictProgramReader:
    """In-memory program rows (tests; mirrors Programs documents)."""

    def __init__(self, rows: dict[str, dict] | None = None) -> None:
        self._rows: dict[str, dict] = dict(rows or {})

    def get_program_row(self, program_name: str) -> dict | None:
        if not isinstance(program_name, str):
            raise TypeError("get_program_row accepts only str")
        row = self._rows.get(program_name)
        if row is None:
            return None
        if not isinstance(row, dict):
            raise WatchReadError(
                "PROGRAM_ROW_MALFORMED", "program row is not a mapping"
            )
        return _program_row(
            row.get("program_name", program_name),
            row.get("scopes", []),
            row.get("ooscopes", []),
        )


class MongoProgramReader:
    """Collection-backed program rows (production read path).

    ``collection`` needs only ``find_one(filter) -> dict | None``
    (the real ``Programs`` collection satisfies this structurally).
    Queries by exact ``program_name`` — the model's unique index.
    """

    def __init__(self, collection: object) -> None:
        find_one = getattr(collection, "find_one", None)
        if not callable(find_one):
            raise TypeError(
                "MongoProgramReader requires a find_one collection, "
                f"not {type(collection).__name__}"
            )
        self._collection = collection

    def get_program_row(self, program_name: str) -> dict | None:
        if not isinstance(program_name, str):
            raise TypeError("get_program_row accepts only str")
        row = self._collection.find_one({"program_name": program_name})
        if row is None:
            return None
        if not isinstance(row, dict):
            raise WatchReadError(
                "PROGRAM_ROW_MALFORMED", "program row is not a mapping"
            )
        return _program_row(
            row.get("program_name", program_name),
            row.get("scopes", []),
            row.get("ooscopes", []),
        )


class WatchAssetReader(Protocol):
    """Read-only asset-row accessor (Http + LiveSubdomains shapes)."""

    def get_asset_rows(
        self, program_name: str, subdomain: str
    ) -> list[dict]: ...


class DictAssetReader:
    """In-memory asset rows keyed by ``(program_name, subdomain)``."""

    def __init__(
        self, rows: dict[tuple[str, str], list[dict]] | None = None
    ) -> None:
        self._rows: dict[tuple[str, str], list[dict]] = dict(rows or {})

    def get_asset_rows(
        self, program_name: str, subdomain: str
    ) -> list[dict]:
        if not isinstance(program_name, str) or not isinstance(
            subdomain, str
        ):
            raise TypeError("get_asset_rows accepts only str keys")
        out: list[dict] = []
        for row in self._rows.get((program_name, subdomain), []):
            if not isinstance(row, dict):
                raise WatchReadError(
                    "ASSET_ROW_MALFORMED", "asset row is not a mapping"
                )
            out.append(_asset_row(row.get("ips"), row.get("url")))
        return out


class MongoAssetReader:
    """Collection-backed asset rows (Http + LiveSubdomains shapes).

    ``http`` / ``live`` need only ``find(filter) -> list[dict]``
    over exact ``{"program_name", "subdomain"}`` matches (both models
    carry that unique index pair). Either collection may be ``None``
    when that source is not wired; reads then cover only the wired
    source.
    """

    def __init__(self, http: object = None, live: object = None) -> None:
        for name, collection in (("http", http), ("live", live)):
            if collection is not None and not callable(
                getattr(collection, "find", None)
            ):
                raise TypeError(
                    f"MongoAssetReader {name} requires a find collection, "
                    f"not {type(collection).__name__}"
                )
        if http is None and live is None:
            raise TypeError("MongoAssetReader requires at least one source")
        self._http = http
        self._live = live

    def get_asset_rows(
        self, program_name: str, subdomain: str
    ) -> list[dict]:
        if not isinstance(program_name, str) or not isinstance(
            subdomain, str
        ):
            raise TypeError("get_asset_rows accepts only str keys")
        out: list[dict] = []
        for collection in (self._http, self._live):
            if collection is None:
                continue
            rows = collection.find(
                {"program_name": program_name, "subdomain": subdomain}
            )
            if not isinstance(rows, (list, tuple)):
                raise WatchReadError(
                    "ASSET_ROW_MALFORMED", "asset read did not return rows"
                )
            for row in rows:
                if not isinstance(row, dict):
                    raise WatchReadError(
                        "ASSET_ROW_MALFORMED", "asset row is not a mapping"
                    )
                out.append(_asset_row(row.get("ips"), row.get("url")))
        return out


def policy_for_program(
    reader: WatchProgramReader, program_name: str
) -> CompiledScopePolicy | None:
    """Compile the LIVE program row into the frozen policy type.

    ``None`` (program gone) lets the 5D evaluator deny with
    ``PROGRAM_NOT_FOUND``; malformed rows raise the existing closed
    ``PolicyError`` via ``compile_policy`` (whole-policy invalid).
    """
    if not hasattr(reader, "get_program_row"):
        raise TypeError(
            "policy read requires a WatchProgramReader, "
            f"not {type(reader).__name__}"
        )
    row = reader.get_program_row(program_name)
    if row is None:
        return None
    try:
        return compile_policy(
            program_name=row["program_name"],
            scopes=row["scopes"],
            ooscopes=row["ooscopes"],
        )
    except PolicyError:
        raise
    except (KeyError, TypeError) as exc:
        raise WatchReadError(
            "PROGRAM_ROW_MALFORMED", "program row shape invalid"
        ) from exc


def address_facts_for(
    reader: WatchAssetReader, program_name: str, subdomain: str
) -> tuple[str, ...]:
    """Merge observed ``ips`` facts for review construction.

    Sorted + deduplicated inventory observations only. Safety
    classification stays in the frozen ``validate_answers`` gate at
    resolve time — this function never judges an address.
    """
    if not hasattr(reader, "get_asset_rows"):
        raise TypeError(
            "address read requires a WatchAssetReader, "
            f"not {type(reader).__name__}"
        )
    seen: set[str] = set()
    for row in reader.get_asset_rows(program_name, subdomain):
        for entry in row.get("ips", []):
            if isinstance(entry, str) and entry:
                seen.add(entry)
    return tuple(sorted(seen))


def inventory_records_for(
    program_row: dict,
    canonical_host: str,
    scheme: str,
    effective_port: int,
    asset_rows: list[dict] | None = None,
) -> tuple[ProgramRecord, AssetRecord]:
    """Build the frozen 5C inventory records from validated rows."""
    observed: list[str] = []
    for row in asset_rows or []:
        for entry in row.get("ips", []):
            if isinstance(entry, str) and entry:
                observed.append(entry)
    return (
        ProgramRecord(
            program_name=program_row["program_name"],
            scopes=tuple(program_row["scopes"]),
            ooscopes=tuple(program_row["ooscopes"]),
        ),
        AssetRecord(
            program_name=program_row["program_name"],
            canonical_host=canonical_host,
            scheme=scheme,
            effective_port=effective_port,
            ips_observed=tuple(sorted(set(observed))),
        ),
    )
