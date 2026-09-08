"""Read-only Target Intelligence projection (Phase 3A).

Projects the existing Watch reconnaissance inventory (Programs,
Subdomains, Http, Urls, Endpoints) into normalized
:class:`TargetIntelligence` objects. The projector is PURE and
DETERMINISTIC:

- READ-ONLY: it never inserts, updates, or deletes database
  records, never triggers recon, and performs no filesystem
  persistence. Inputs are plain inventory records (dependency
  injection), so unit tests use fixtures and production callers
  map MongoEngine documents via the ``from_document`` constructors
  — which use duck-typed attribute reads only. This module never
  imports ``database.db`` (which connects to MongoDB on import),
  ``mongoengine``, or any network/LLM/subprocess library.
- NO NETWORK: a URL from inventory is DATA and is never fetched,
  resolved, or followed. URL handling is stdlib ``urlsplit``
  parsing only.
- NO MATCHING: nothing here compares patterns to inventory,
  compares versions, or decides affected/unaffected. Version
  tokens parsed from technology labels are observations, never
  comparison inputs (the ``ai/correlator/version.py`` comparator
  is neither imported nor called).
- NO VERDICTS, NO SCOPE GRANTS, NO TARGET AUTHORITY: scope
  strings are preserved verbatim as observed inventory and can
  never become execution permission.

Program/subdomain attachment uses the canonical
``program_name``/``subdomain`` relationship fields present on
every inventory row — never hostname similarity. Rows belonging
to another program are excluded (isolation); rows with empty
relationship keys are skipped with a structured reason (never
guessed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Sequence
from urllib.parse import urlsplit

from pydantic import ValidationError

from ai.schemas.target_intelligence import (
    PROJECTION_VERSION,
    EndpointObservation,
    HttpObservation,
    ParamDetail,
    ScopeSnapshot,
    SourceRefs,
    TargetIntelligence,
    TechnologyObservation,
    UrlObservation,
    intelligence_id_for,
    snapshot_hash_for,
    target_key_for,
)

SkipReason = Literal[
    "missing_relationship",
    "malformed_url",
    "invalid_observation",
    "invalid_inventory",
]


class TargetIntelError(ValueError):
    """Deterministic, testable projector misuse/failure signal."""


@dataclass(frozen=True)
class ProjectionSkip:
    """One inventory row (or observation) safely skipped, and why."""

    subject: str
    reason: SkipReason
    detail: str


@dataclass(frozen=True)
class SubdomainProjection:
    """Projection outcome for one program + subdomain target."""

    intelligence: TargetIntelligence
    skipped: tuple[ProjectionSkip, ...] = ()


@dataclass(frozen=True)
class ProgramProjection:
    """Projection outcome for one program across its subdomains."""

    intelligence: tuple[TargetIntelligence, ...] = ()
    skipped: tuple[ProjectionSkip, ...] = ()


# ------------------------------------------------------------------
# Inventory records (plain-Python DI inputs mirroring database/db.py)
# ------------------------------------------------------------------


def _record_id_of(document: object) -> str:
    raw = getattr(document, "id", "")
    if raw is None:
        return ""
    text = str(raw).strip()
    return text


def _timestamp_of(document: object) -> str | None:
    for attr in ("last_update", "created_date"):
        raw = getattr(document, attr, None)
        if isinstance(raw, datetime):
            return raw.isoformat()
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return None


def _str_list(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)):
        return ()
    return tuple(
        item for item in raw if isinstance(item, str) and item
    )


@dataclass(frozen=True)
class ProgramRecord:
    """Mirrors database.Programs: name, scopes, ooscopes, id."""

    program_name: str = ""
    scopes: tuple[str, ...] = ()
    ooscopes: tuple[str, ...] = ()
    record_id: str = ""

    @classmethod
    def from_document(cls, document: object) -> "ProgramRecord":
        return cls(
            program_name=str(
                getattr(document, "program_name", "") or ""
            ),
            scopes=_str_list(getattr(document, "scopes", ())),
            ooscopes=_str_list(getattr(document, "ooscopes", ())),
            record_id=_record_id_of(document),
        )


@dataclass(frozen=True)
class SubdomainRecord:
    """Mirrors database.Subdomains (scope is a registrable-domain
    label string, e.g. ``example.com``)."""

    program_name: str = ""
    subdomain: str = ""
    scope: str = ""
    providers: tuple[str, ...] = ()
    record_id: str = ""

    @classmethod
    def from_document(cls, document: object) -> "SubdomainRecord":
        return cls(
            program_name=str(
                getattr(document, "program_name", "") or ""
            ),
            subdomain=str(getattr(document, "subdomain", "") or ""),
            scope=str(getattr(document, "scope", "") or ""),
            providers=_str_list(getattr(document, "providers", ())),
            record_id=_record_id_of(document),
        )


@dataclass(frozen=True)
class HttpRecord:
    """Mirrors database.Http. ``tech`` holds raw httpx tech-detect
    labels (e.g. ``nginx:1.24.0``); there is no separate version or
    confidence field anywhere in the row."""

    program_name: str = ""
    subdomain: str = ""
    scope: str = ""
    ips: tuple[str, ...] = ()
    tech: tuple[str, ...] = ()
    title: str = ""
    status_code: int | None = None
    headers: tuple[tuple[str, str], ...] = ()
    url: str = ""
    final_url: str = ""
    favicon: str = ""
    last_update: str | None = None
    record_id: str = ""

    @classmethod
    def from_document(cls, document: object) -> "HttpRecord":
        raw_headers = getattr(document, "headers", None)
        pairs: list[tuple[str, str]] = []
        if isinstance(raw_headers, dict):
            for key, value in raw_headers.items():
                if isinstance(key, str) and isinstance(value, str):
                    pairs.append((key, value))
        raw_status = getattr(document, "status_code", None)
        status = (
            raw_status
            if isinstance(raw_status, int)
            and not isinstance(raw_status, bool)
            else None
        )
        return cls(
            program_name=str(
                getattr(document, "program_name", "") or ""
            ),
            subdomain=str(getattr(document, "subdomain", "") or ""),
            scope=str(getattr(document, "scope", "") or ""),
            ips=_str_list(getattr(document, "ips", ())),
            tech=_str_list(getattr(document, "tech", ())),
            title=str(getattr(document, "title", "") or ""),
            status_code=status,
            headers=tuple(pairs),
            url=str(getattr(document, "url", "") or ""),
            final_url=str(getattr(document, "final_url", "") or ""),
            favicon=str(getattr(document, "favicon", "") or ""),
            last_update=_timestamp_of(document),
            record_id=_record_id_of(document),
        )


@dataclass(frozen=True)
class UrlRecord:
    """Mirrors database.Urls (crawl-level URL rows)."""

    program_name: str = ""
    subdomain: str = ""
    url: str = ""
    path: str = ""
    params: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    status_code: int | None = None
    last_update: str | None = None
    record_id: str = ""

    @classmethod
    def from_document(cls, document: object) -> "UrlRecord":
        raw_status = getattr(document, "status_code", None)
        status = (
            raw_status
            if isinstance(raw_status, int)
            and not isinstance(raw_status, bool)
            else None
        )
        return cls(
            program_name=str(
                getattr(document, "program_name", "") or ""
            ),
            subdomain=str(getattr(document, "subdomain", "") or ""),
            url=str(getattr(document, "url", "") or ""),
            path=str(getattr(document, "path", "") or ""),
            params=_str_list(getattr(document, "params", ())),
            sources=_str_list(getattr(document, "sources", ())),
            status_code=status,
            last_update=_timestamp_of(document),
            record_id=_record_id_of(document),
        )


@dataclass(frozen=True)
class ParamRecord:
    """Mirrors one database Endpoints.param_records entry."""

    name: str = ""
    method: str = ""
    location: str = ""
    source: str = ""


@dataclass(frozen=True)
class EndpointRecord:
    """Mirrors database.Endpoints. ``path`` arrives already
    normalized by ``database.normalize_path`` at write time; the
    projector never re-normalizes paths."""

    program_name: str = ""
    subdomain: str = ""
    path: str = ""
    example_url: str = ""
    params: tuple[str, ...] = ()
    params_from_crawl: tuple[str, ...] = ()
    params_from_x8: tuple[str, ...] = ()
    x8_checked: bool = False
    hit_count: int | None = None
    param_records: tuple[ParamRecord, ...] = ()
    last_update: str | None = None
    record_id: str = ""

    @classmethod
    def from_document(cls, document: object) -> "EndpointRecord":
        raw_params = getattr(document, "param_records", None)
        details: list[ParamRecord] = []
        if isinstance(raw_params, (list, tuple)):
            for entry in raw_params:
                if not isinstance(entry, dict):
                    continue
                details.append(
                    ParamRecord(
                        name=str(entry.get("name", "") or ""),
                        method=str(entry.get("method", "") or ""),
                        location=str(
                            entry.get("location", "") or ""
                        ),
                        source=str(entry.get("source", "") or ""),
                    )
                )
        raw_hits = getattr(document, "hit_count", None)
        hits = (
            raw_hits
            if isinstance(raw_hits, int)
            and not isinstance(raw_hits, bool)
            else None
        )
        return cls(
            program_name=str(
                getattr(document, "program_name", "") or ""
            ),
            subdomain=str(getattr(document, "subdomain", "") or ""),
            path=str(getattr(document, "path", "") or ""),
            example_url=str(
                getattr(document, "example_url", "") or ""
            ),
            params=_str_list(getattr(document, "params", ())),
            params_from_crawl=_str_list(
                getattr(document, "params_from_crawl", ())
            ),
            params_from_x8=_str_list(
                getattr(document, "params_from_x8", ())
            ),
            x8_checked=getattr(document, "x8_checked", False)
            is True,
            hit_count=hits,
            param_records=tuple(details),
            last_update=_timestamp_of(document),
            record_id=_record_id_of(document),
        )


# ------------------------------------------------------------------
# Observation parsing (deterministic, inference-free)
# ------------------------------------------------------------------

# Version-suffix shape mirrors the strip expression documented in
# ai/correlator/technology.py (e.g. "nginx:1.30.4",
# "Microsoft ASP.NET:4.0.30319"). Used ONLY to split an observed
# label into name + version token; never to compare versions.
_TECH_VERSION_RE = re.compile(
    r"^(?P<name>.*?)[\s:/_\-]+v?(?P<version>\d[\w.\-+]*)$"
)
_VERSION_TOKEN_RE = re.compile(r"^[0-9][0-9A-Za-z.\-_+]{0,63}$")

_PARAM_METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})
_PARAM_LOCATIONS = frozenset({"query", "body"})
_PARAM_SOURCES = frozenset({"crawl", "x8"})
_URL_SCHEMES = frozenset({"http", "https"})


def _split_technology(
    raw_label: str,
) -> tuple[str, str | None] | None:
    """Split ``name:version`` observation labels.

    Returns None when the label is unusable (blank). A present but
    unparseable version falls back to ``(whole label, None)`` —
    versions are never guessed.
    """

    if not isinstance(raw_label, str):
        return None
    if "\n" in raw_label or "\r" in raw_label:
        return None
    stripped = raw_label.strip()
    if not stripped:
        return None
    match = _TECH_VERSION_RE.match(stripped)
    if not match:
        return stripped, None
    name = match.group("name").strip()
    version = match.group("version")
    if not name or not _VERSION_TOKEN_RE.match(version):
        return stripped, None
    return name, version


def _parse_url(url: str) -> tuple[str, str, str] | None:
    """Parse scheme/host/path with stdlib only. Never fetches."""

    if not isinstance(url, str):
        return None
    if "\n" in url or "\r" in url:
        return None
    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    if scheme not in _URL_SCHEMES or not host:
        return None
    return scheme, host.lower(), parsed.path or "/"


# ------------------------------------------------------------------
# Projection
# ------------------------------------------------------------------


def _belongs(
    record_program: str, record_subdomain: str, program: str, sub: str
) -> bool:
    return record_program == program and record_subdomain == sub


def _project_technologies(
    https: Sequence[HttpRecord], skipped: list[ProjectionSkip]
) -> list[TechnologyObservation]:
    observations: dict[
        tuple[str, str | None, str, str], TechnologyObservation
    ] = {}
    for row in https:
        if not row.record_id:
            skipped.append(
                ProjectionSkip(
                    subject="http:missing-record-id",
                    reason="invalid_observation",
                    detail="Http row without a record id cannot be "
                    "referenced; tech labels skipped.",
                )
            )
            continue
        for label in row.tech:
            split = _split_technology(label)
            if split is None:
                skipped.append(
                    ProjectionSkip(
                        subject=f"http:{row.record_id}",
                        reason="invalid_observation",
                        detail=f"unusable technology label: {label!r}.",
                    )
                )
                continue
            name, version = split
            key = (name.casefold(), version, label.strip(), row.record_id)
            if key in observations:
                continue
            try:
                observations[key] = TechnologyObservation(
                    name=name,
                    observed_version=version,
                    raw_label=label.strip(),
                    record_ref=row.record_id,
                )
            except ValidationError as exc:
                skipped.append(
                    ProjectionSkip(
                        subject=f"http:{row.record_id}",
                        reason="invalid_observation",
                        detail=f"technology label rejected: {exc}.",
                    )
                )
    return [
        observations[key]
        for key in sorted(
            observations,
            key=lambda k: (k[0], k[1] or "", k[2], k[3]),
        )
    ]


def _project_http_rows(
    https: Sequence[HttpRecord], skipped: list[ProjectionSkip]
) -> list[HttpObservation]:
    rows: dict[str, HttpObservation] = {}
    for row in https:
        if not row.record_id:
            continue
        if row.record_id in rows:
            continue
        try:
            rows[row.record_id] = HttpObservation(
                record_ref=row.record_id,
                url=row.url,
                final_url=row.final_url,
                status_code=row.status_code,
                title=row.title,
                ips=sorted(set(row.ips)),
                header_names=sorted(
                    {name for name, _ in row.headers}
                ),
            )
        except ValidationError as exc:
            skipped.append(
                ProjectionSkip(
                    subject=f"http:{row.record_id}",
                    reason="invalid_observation",
                    detail=f"HTTP observation rejected: {exc}.",
                )
            )
    return [rows[key] for key in sorted(rows)]


def _project_urls(
    urls: Sequence[UrlRecord], skipped: list[ProjectionSkip]
) -> list[UrlObservation]:
    observations: dict[str, UrlObservation] = {}
    for row in urls:
        if not row.record_id:
            skipped.append(
                ProjectionSkip(
                    subject="url:missing-record-id",
                    reason="invalid_observation",
                    detail="Url row without a record id cannot be "
                    "referenced; skipped.",
                )
            )
            continue
        if not row.program_name or not row.subdomain:
            skipped.append(
                ProjectionSkip(
                    subject=f"url:{row.record_id}",
                    reason="missing_relationship",
                    detail="Url row without program/subdomain "
                    "relationship; never guessed.",
                )
            )
            continue
        parsed = _parse_url(row.url)
        if parsed is None:
            skipped.append(
                ProjectionSkip(
                    subject=f"url:{row.record_id}",
                    reason="malformed_url",
                    detail=f"unparseable URL stored as data: "
                    f"{row.url!r}; never fetched.",
                )
            )
            continue
        scheme, host, path = parsed
        if row.url in observations:
            continue
        try:
            observations[row.url] = UrlObservation(
                record_ref=row.record_id,
                url=row.url.strip(),
                scheme=scheme,
                host=host,
                path=path,
                params=sorted(set(row.params)),
                sources=sorted(set(row.sources)),
                status_code=row.status_code,
            )
        except ValidationError as exc:
            skipped.append(
                ProjectionSkip(
                    subject=f"url:{row.record_id}",
                    reason="malformed_url",
                    detail=f"URL observation rejected: {exc}.",
                )
            )
    return [observations[key] for key in sorted(observations)]


def _project_param_detail(
    entry: ParamRecord,
) -> ParamDetail | None:
    if (
        entry.method not in _PARAM_METHODS
        or entry.location not in _PARAM_LOCATIONS
        or entry.source not in _PARAM_SOURCES
    ):
        return None
    name = entry.name.strip() if isinstance(entry.name, str) else ""
    if (
        not name
        or len(name) > 128
        or "\n" in name
        or "\r" in name
    ):
        return None
    return ParamDetail(
        name=name,
        method=entry.method,  # type: ignore[typeddict-item]
        location=entry.location,  # type: ignore[typeddict-item]
        source=entry.source,  # type: ignore[typeddict-item]
    )


def _project_endpoints(
    endpoints: Sequence[EndpointRecord],
    skipped: list[ProjectionSkip],
) -> list[EndpointObservation]:
    observations: dict[str, EndpointObservation] = {}
    for row in endpoints:
        if not row.record_id:
            skipped.append(
                ProjectionSkip(
                    subject="endpoint:missing-record-id",
                    reason="invalid_observation",
                    detail="Endpoint row without a record id cannot "
                    "be referenced; skipped.",
                )
            )
            continue
        if not row.program_name or not row.subdomain:
            skipped.append(
                ProjectionSkip(
                    subject=f"endpoint:{row.record_id}",
                    reason="missing_relationship",
                    detail="Endpoint row without program/subdomain "
                    "relationship; never guessed.",
                )
            )
            continue
        if (
            not row.path
            or "\n" in row.path
            or "\r" in row.path
            or (
                row.example_url
                and ("\n" in row.example_url or "\r" in row.example_url)
            )
        ):
            skipped.append(
                ProjectionSkip(
                    subject=f"endpoint:{row.record_id}",
                    reason="invalid_observation",
                    detail="endpoint path/example_url malformed; "
                    "skipped without fetching.",
                )
            )
            continue
        details: dict[tuple[str, str, str, str], ParamDetail] = {}
        for entry in row.param_records:
            detail = _project_param_detail(entry)
            if detail is None:
                skipped.append(
                    ProjectionSkip(
                        subject=f"endpoint:{row.record_id}",
                        reason="invalid_observation",
                        detail=f"param record outside the canonical "
                        f"vocabulary skipped: {entry!r}.",
                    )
                )
                continue
            key = (
                detail.name,
                detail.method,
                detail.location,
                detail.source,
            )
            details.setdefault(key, detail)
        if row.path in observations:
            continue
        try:
            observations[row.path] = EndpointObservation(
                record_ref=row.record_id,
                path=row.path,
                example_url=row.example_url,
                params=sorted(set(row.params)),
                param_details=[
                    details[key] for key in sorted(details)
                ],
                hit_count=row.hit_count,
                x8_checked=row.x8_checked,
            )
        except ValidationError as exc:
            skipped.append(
                ProjectionSkip(
                    subject=f"endpoint:{row.record_id}",
                    reason="invalid_observation",
                    detail=f"endpoint observation rejected: {exc}.",
                )
            )
    return [observations[key] for key in sorted(observations)]


def project_subdomain(
    program: object,
    subdomain: object,
    *,
    https: Sequence[object] = (),
    urls: Sequence[object] = (),
    endpoints: Sequence[object] = (),
) -> SubdomainProjection:
    """Project one program + subdomain target from inventory rows.

    Only rows whose canonical ``program_name``/``subdomain`` match
    the requested target are attached; everything else is excluded
    by relationship, never by hostname guessing. Malformed rows
    for THIS target are skipped with structured reasons; the valid
    remainder still projects.
    """

    if not isinstance(program, ProgramRecord):
        raise TypeError(
            "project_subdomain requires a ProgramRecord, not "
            f"{type(program).__name__}"
        )
    if not isinstance(subdomain, SubdomainRecord):
        raise TypeError(
            "project_subdomain requires a SubdomainRecord, not "
            f"{type(subdomain).__name__}"
        )
    for row in (*https, *urls, *endpoints):
        if not isinstance(
            row, (HttpRecord, UrlRecord, EndpointRecord)
        ):
            raise TypeError(
                "inventory rows must be HttpRecord, UrlRecord, or "
                f"EndpointRecord, not {type(row).__name__}"
            )
    if not program.program_name or not program.program_name.strip():
        raise TargetIntelError("program_name must be non-empty")
    if not subdomain.subdomain or not subdomain.subdomain.strip():
        raise TargetIntelError("subdomain must be non-empty")
    if subdomain.program_name != program.program_name:
        raise TargetIntelError(
            "subdomain relationship mismatch: "
            f"{subdomain.program_name!r} != {program.program_name!r}; "
            "program membership is never inferred"
        )

    program_name = program.program_name
    sub = subdomain.subdomain
    skipped: list[ProjectionSkip] = []
    for row in (*https, *urls, *endpoints):
        if not row.program_name or not row.subdomain:  # type: ignore[union-attr]
            kind = type(row).__name__.replace("Record", "").lower()
            skipped.append(
                ProjectionSkip(
                    subject=f"{kind}:missing-relationship",
                    reason="missing_relationship",
                    detail="inventory row without program/subdomain "
                    "relationship; never guessed, never attached.",
                )
            )
    own_https = [
        row
        for row in https
        if isinstance(row, HttpRecord)
        and _belongs(row.program_name, row.subdomain, program_name, sub)
    ]
    own_urls = [
        row
        for row in urls
        if isinstance(row, UrlRecord)
        and _belongs(row.program_name, row.subdomain, program_name, sub)
    ]
    own_endpoints = [
        row
        for row in endpoints
        if isinstance(row, EndpointRecord)
        and _belongs(row.program_name, row.subdomain, program_name, sub)
    ]
    technologies = _project_technologies(own_https, skipped)
    http_observations = _project_http_rows(own_https, skipped)
    url_observations = _project_urls(own_urls, skipped)
    endpoint_observations = _project_endpoints(own_endpoints, skipped)

    scope_snapshot = ScopeSnapshot(
        program_scopes=sorted(set(program.scopes)),
        program_ooscopes=sorted(set(program.ooscopes)),
        subdomain_scope=subdomain.scope,
    )
    source_refs = SourceRefs(
        program_record_id=program.record_id,
        subdomain_record_id=subdomain.record_id,
        http_record_ids=sorted({row.record_id for row in own_https}),
        url_record_ids=sorted({row.record_id for row in own_urls}),
        endpoint_record_ids=sorted(
            {row.record_id for row in own_endpoints}
        ),
    )
    timestamps = sorted(
        {
            stamp
            for row in (*own_https, *own_urls, *own_endpoints)
            for stamp in [row.last_update]
            if stamp
        }
    )
    canonical = {
        "endpoint_observations": [
            item.model_dump(mode="json")
            for item in endpoint_observations
        ],
        "http_observations": [
            item.model_dump(mode="json") for item in http_observations
        ],
        "program_name": program_name,
        "projection_version": PROJECTION_VERSION,
        "scope_snapshot": scope_snapshot.model_dump(mode="json"),
        "source_refs": source_refs.model_dump(mode="json"),
        "subdomain": sub,
        "technologies": [
            item.model_dump(mode="json") for item in technologies
        ],
        "url_observations": [
            item.model_dump(mode="json") for item in url_observations
        ],
    }
    try:
        intelligence = TargetIntelligence(
            intelligence_id=intelligence_id_for(
                program_name, sub
            ),
            target_key=target_key_for(program_name, sub),
            program_name=program_name,
            subdomain=sub,
            scope_snapshot=scope_snapshot,
            technologies=technologies,
            http_observations=http_observations,
            url_observations=url_observations,
            endpoint_observations=endpoint_observations,
            source_refs=source_refs,
            observed_at=timestamps[-1] if timestamps else None,
            snapshot_hash=snapshot_hash_for(canonical),
        )
    except ValidationError as exc:
        raise TargetIntelError(
            f"projection failed contract validation: {exc}"
        ) from exc
    skipped.sort(key=lambda item: (item.subject, item.reason))
    return SubdomainProjection(
        intelligence=intelligence, skipped=tuple(skipped)
    )


def project_program(
    program: object,
    subdomains: Sequence[object] = (),
    *,
    https: Sequence[object] = (),
    urls: Sequence[object] = (),
    endpoints: Sequence[object] = (),
) -> ProgramProjection:
    """Project every subdomain target of one program.

    Only subdomains canonically attached to ``program`` are
    projected, in sorted order; subdomains of other programs are
    ignored (isolation). Deterministic for a given input set.
    """

    if not isinstance(program, ProgramRecord):
        raise TypeError(
            "project_program requires a ProgramRecord, not "
            f"{type(program).__name__}"
        )
    for sub in subdomains:
        if not isinstance(sub, SubdomainRecord):
            raise TypeError(
                "subdomains must be SubdomainRecord objects, not "
                f"{type(sub).__name__}"
            )
    own = sorted(
        (
            sub
            for sub in subdomains
            if isinstance(sub, SubdomainRecord)
            and sub.program_name == program.program_name
        ),
        key=lambda item: item.subdomain,
    )
    results: list[TargetIntelligence] = []
    skipped: list[ProjectionSkip] = []
    for sub in own:
        projected = project_subdomain(
            program,
            sub,
            https=https,
            urls=urls,
            endpoints=endpoints,
        )
        results.append(projected.intelligence)
        skipped.extend(projected.skipped)
    skipped.sort(key=lambda item: (item.subject, item.reason))
    return ProgramProjection(
        intelligence=tuple(results), skipped=tuple(skipped)
    )


__all__ = [
    "EndpointRecord",
    "HttpRecord",
    "ParamRecord",
    "ProgramProjection",
    "ProgramRecord",
    "ProjectionSkip",
    "SkipReason",
    "SubdomainProjection",
    "SubdomainRecord",
    "TargetIntelError",
    "UrlRecord",
    "project_program",
    "project_subdomain",
]
