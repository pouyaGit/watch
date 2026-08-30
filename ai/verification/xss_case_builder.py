"""Deterministic Watch-database-to-XSSCase adapter.

This module converts eligible Watch ``Endpoints`` inventory
rows into deterministic :class:`ai.schemas.xss.XSSCase`
objects. It is NOT an AI component:

- no LLM calls
- no network calls (the offline tldextract snapshot is used
  for registrable-domain extraction; MongoDB is touched only
  lazily inside ``build_pending`` when the caller did not
  inject an endpoint source)
- no payload generation
- no vulnerability classification or XSS verdict
- no browser, no HTTP execution

Flow::

    Watch DB inventory (Endpoints.param_records + params)
        ↓  scope + URL + (method/location/parameter) eligibility
    deterministic XSSCase objects (one per method/location/parameter)

Scope safety mirrors the EXISTING Watch semantics in
``database/db.py`` (``upsert_subdomain`` / ``get_domain_name``)
exactly; nothing new is invented and nothing is weakened:

    in-scope  <=>  get_domain_name(host) in program.scopes
                   and host not in program.ooscopes

where ``get_domain_name`` is the registrable domain
(eTLD+1) via tldextract. Both the ``example_url`` hostname
and the endpoint's recorded ``subdomain`` must pass this
rule (the recorded subdomain already passed it at ingestion
time; re-checking it only rejects scope-list drift, never
loosens anything). A missing program, an unknown program
name, or any out-of-scope / ooscopes host yields NO cases.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import tldextract

from ai.schemas.xss import XSSCase
from ai.schemas.xss_verification import (
    _canonical_json,
    _sha256_hex,
)

__all__ = [
    "XSSCaseBuilder",
    "get_domain_name",
]

# Eligible URL schemes. Only plain HTTP(S) endpoints are
# verified; anything else is rejected, never rewritten.
_ELIGIBLE_SCHEMES = ("http", "https")

# Program names that never produce cases, case-insensitively.
_UNKNOWN_PROGRAM_NAMES = {"", "unknown"}

# Deterministic case-id width (matches the "ct-" token style
# in ai.schemas.xss_verification).
_CASE_ID_HEX_LENGTH = 32

# Hard bound on discovery-evidence entry length so hostile or
# junk inventory rows cannot bloat the case.
_EVIDENCE_ENTRY_LIMIT = 200

# Offline public-suffix extraction: identical semantics to
# database.db.get_domain_name (tldextract eTLD+1) but pinned
# to the bundled suffix snapshot so the builder NEVER touches
# the network.
_OFFLINE_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def get_domain_name(url_or_host: str) -> str:
    """
    Registrable domain (eTLD+1) of a URL or hostname.

    Mirrors ``database.db.get_domain_name`` exactly
    (``f"{ext.domain}.{ext.suffix}"``) but uses the bundled
    public-suffix snapshot offline so no HTTP fetch can ever
    happen here. Empty/ungeneralisable inputs yield a value
    that cannot match any real scope entry, i.e. they fail
    the scope check.
    """

    ext = _OFFLINE_TLD_EXTRACT(url_or_host or "")
    return f"{ext.domain}.{ext.suffix}"


def _mongo_program_lookup(program_name: str):
    """Default program resolver (production only).

    Imported lazily so that importing this module (and all
    unit tests) never opens a MongoDB connection.
    """

    from database.db import Programs

    return Programs.objects(program_name=program_name).first()


def _mongo_pending_endpoints(limit: int):
    """Default bounded pending-endpoint cursor (production).

    "Pending" = an endpoint whose parameter consolidation
    already ran (``x8_checked``) and that carries parameters
    and an example URL. Deterministically ordered and hard
    limited; final eligibility is still decided by
    :meth:`XSSCaseBuilder.build` (scope, URL, parameters).
    Imported lazily for the same reason as above.
    """

    from database.db import Endpoints

    return (
        Endpoints.objects(
            example_url__ne=None,
            params__ne=[],
            x8_checked=True,
        )
        .order_by("+program_name", "+subdomain", "+path")
        .limit(limit)
    )


class XSSCaseBuilder:
    """
    Convert eligible Watch ``Endpoints`` rows into
    deterministic XSSCase objects — ONE CASE PER
    (method, location, parameter).

    Eligibility (all deterministic, all checked before any
    case is produced):

    - ``program_name`` resolves to an existing program and is
      not empty / ``"unknown"`` (case-insensitive).
    - ``example_url`` parses, has an http(s) scheme and a
      hostname. The URL is used verbatim as the case
      endpoint; nothing is normalized or rewritten.
    - The ``example_url`` hostname and the recorded
      ``subdomain`` both pass the existing Watch scope rule
      against the program's ``scopes`` / ``ooscopes``.
    - ``param_records`` (primary) yields at least one valid
      ``(method, location, parameter)`` tuple with a supported
      location (``query`` / ``body``) and non-empty method and
      parameter name. Records with an unsupported location or a
      missing method/location are skipped — never defaulted to
      GET/query. Legacy rows with empty ``param_records`` fall
      back to ``params`` treated as GET/query.

    Any failed check produces an empty list — never a
    partially scoped case, never an exception for
    data-quality reasons.
    """

    def __init__(self, program_lookup=None) -> None:
        """
        ``program_lookup`` is an injected callable mapping
        ``program_name -> program object (or None)``. The
        production default resolves against the Watch
        ``Programs`` collection lazily. Inject a fake for
        tests; nothing here touches MongoDB unless the
        default lookup is actually invoked.
        """

        self._program_lookup = (
            program_lookup if program_lookup is not None
            else _mongo_program_lookup
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, endpoint) -> list[XSSCase]:
        """Build the cases for one Endpoints row.

        Primary source: ``endpoint.param_records``. Exactly one
        case is produced for each unique
        ``(method, location, parameter)`` tuple. Unsupported
        locations are skipped; a record missing its method or
        location is skipped (never defaulted to GET/query).

        Legacy fallback: when ``param_records`` is empty the
        row predates method/location provenance, so
        ``endpoint.params`` is used and treated as GET/query.

        Returns an empty list when the endpoint is not
        eligible. Never raises for data-quality reasons.
        """

        program = self._resolve_program(endpoint)
        if program is None:
            return []

        url = self._eligible_url(endpoint)
        if url is None:
            return []

        host, example_url = url
        if not self._endpoint_in_scope(endpoint, host, program):
            return []

        candidates = self._candidate_items(endpoint)
        if not candidates:
            return []

        program_name = endpoint.program_name
        subdomain = endpoint.subdomain or ""
        path = endpoint.path or ""

        cases: list[XSSCase] = []
        for method, location, parameter, source in candidates:
            cases.append(
                XSSCase(
                    case_id=self._case_id(
                        program_name=program_name,
                        subdomain=subdomain,
                        path=path,
                        example_url=example_url,
                        parameter=parameter,
                        method=method,
                        parameter_location=location,
                    ),
                    # The hostname associated with the
                    # endpoint; the URL itself is preserved
                    # verbatim as the execution base so the
                    # executors perform parameter injection.
                    target=host,
                    endpoint=example_url,
                    # The method and location come from the
                    # discovery provenance, never defaulted
                    # from a hard-coded GET/query.
                    method=method,
                    parameter=parameter,
                    parameter_location=location,
                    source_type="endpoint",
                    discovery_evidence=self._discovery_evidence(
                        program_name=program_name,
                        subdomain=subdomain,
                        path=path,
                        parameter=parameter,
                        method=method,
                        location=location,
                        source=source,
                    ),
                    # Everything else stays at its schema
                    # default by contract: input_value=None,
                    # xss_type="unknown", context=default,
                    # framework=None, technology=[],
                    # waf=None, retrieved_knowledge_ids=[],
                    # status="NEW", confidence=0.0.
                )
            )
        return cases

    def build_pending(
        self,
        endpoints=None,
        *,
        limit: int = 200,
    ) -> list[XSSCase]:
        """
        Build cases for pending inventory rows, bounded.

        ``endpoints`` may be any iterable of Endpoints-like
        rows (inject a fake for tests). When omitted, the
        production default queries the Watch ``Endpoints``
        collection lazily with a deterministic order and a
        hard limit. The returned case count is also capped at
        ``limit``; ``limit <= 0`` yields no cases.
        """

        if limit is None or limit <= 0:
            return []
        if endpoints is None:
            endpoints = _mongo_pending_endpoints(limit)

        cases: list[XSSCase] = []
        for endpoint in endpoints:
            cases.extend(self.build(endpoint))
            if len(cases) >= limit:
                return cases[:limit]
        return cases

    # ------------------------------------------------------------------
    # Eligibility checks (deterministic)
    # ------------------------------------------------------------------

    def _resolve_program(self, endpoint):
        """Resolve the program; None means ineligible.

        A program named "Unknown" (or empty, case- and
        whitespace-insensitively) NEVER produces a case, even
        if a database row with that name existed.
        """

        program_name = (endpoint.program_name or "").strip()
        if program_name.lower() in _UNKNOWN_PROGRAM_NAMES:
            return None
        return self._lookup_program(endpoint.program_name)

    def _lookup_program(self, program_name: str):
        return self._program_lookup(program_name)

    @staticmethod
    def _eligible_url(endpoint):
        """Validate example_url; None means ineligible.

        Returns ``(hostname, example_url)``. The URL is used
        exactly as stored — no normalization, no rewriting,
        no parameter stripping. Query components already in
        the URL stay there: the executors inject parameters
        on top of this base URL (existing
        VerificationAttempt semantics).
        """

        example_url = endpoint.example_url
        if not example_url or not isinstance(example_url, str):
            return None
        try:
            parts = urlsplit(example_url)
            host = parts.hostname
            # Accessing .port raises ValueError for malformed
            # or non-numeric ports: reject those too.
            _ = parts.port
        except ValueError:
            # Malformed URL or invalid port.
            return None
        if (parts.scheme or "").lower() not in _ELIGIBLE_SCHEMES:
            return None
        if not host:
            return None
        return host, example_url

    @staticmethod
    def _host_in_scope(candidate: str, program) -> bool:
        """The EXISTING Watch scope rule for one hostname.

        Exact mirror of database.db.upsert_subdomain:
            rejected  <=>  candidate in program.ooscopes
                           or get_domain_name(candidate)
                              not in program.scopes
        """

        if candidate in (program.ooscopes or []):
            return False
        return get_domain_name(candidate) in (
            program.scopes or []
        )

    def _endpoint_in_scope(self, endpoint, host: str, program) -> bool:
        # The execution hostname must be in scope and not in
        # the ooscopes list.
        if not self._host_in_scope(host, program):
            return False
        # Defense in depth: the recorded subdomain passed
        # this same rule at ingestion time; re-checking it
        # rejects scope-list drift without ever loosening
        # the check.
        subdomain = endpoint.subdomain or ""
        if subdomain and not self._host_in_scope(
            subdomain, program
        ):
            return False
        return True

    def _candidate_items(self, endpoint) -> list[tuple]:
        """
        Deterministic candidate (method, location, name, source)
        tuples for one endpoint.

        Primary source: ``endpoint.param_records``. One item per
        unique (method, location, name); records from both crawl
        and x8 for the same (method/location/name) collapse into
        one deterministic item (first in sorted order is kept,
        so ``source`` is deterministic). Records with an
        unsupported location, an empty name, or an empty method
        are skipped — a missing method/location is NEVER
        defaulted to GET/query for structured records.

        Legacy fallback: when ``param_records`` is empty the row
        predates provenance; ``endpoint.params`` is used and
        each name is treated as (GET, query) with source
        "crawl".
        """

        records = getattr(endpoint, "param_records", None) or []
        if records:
            # Collect every valid (method, location, name, source)
            # tuple, then dedupe by (method, location, name) over
            # the SORTED set so the surviving source (and the
            # final ordering) is deterministic regardless of the
            # order records were written to the database.
            items: set[tuple] = set()
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                name = rec.get("name")
                method = rec.get("method")
                location = rec.get("location")
                source = rec.get("source")
                if not isinstance(name, str) or not name:
                    continue
                if not isinstance(method, str) or not method:
                    continue
                location = (location or "").strip().lower()
                if location not in ("query", "body"):
                    continue
                source = (
                    source if isinstance(source, str) and source
                    else "unknown"
                )
                items.add((method, location, name, source))

            by_key: dict[tuple, str] = {}
            for method, location, name, source in sorted(items):
                by_key.setdefault((method, location, name), source)
            return sorted(
                (method, location, name, by_key[(method, location, name)])
                for method, location, name in by_key
            )

        names = {
            p for p in (endpoint.params or [])
            if isinstance(p, str) and p != ""
        }
        return sorted(("GET", "query", name, "crawl") for name in names)

    # ------------------------------------------------------------------
    # Deterministic identifiers and evidence
    # ------------------------------------------------------------------

    @staticmethod
    def _case_id(
        *,
        program_name: str,
        subdomain: str,
        path: str,
        example_url: str,
        parameter: str,
        method: str,
        parameter_location: str,
    ) -> str:
        """
        Deterministic SHA-256 case identifier using the
        repository's canonical-JSON hashing style (same
        helpers as ``attempt_id_from_canonical``).

        The canonical includes the ACTUAL method and parameter
        location, so GET/query and POST/body cases for the same
        parameter yield different case IDs. The same database
        Endpoint row + method + location + parameter therefore
        ALWAYS yields the same case_id; no random UUIDs.
        """

        canonical = {
            "kind": "watch_xss_case",
            "program_name": program_name,
            "subdomain": subdomain,
            "path": path,
            "example_url": example_url,
            "method": method,
            "parameter": parameter,
            "parameter_location": parameter_location,
        }
        return "case-" + _sha256_hex(
            _canonical_json(canonical),
            length=_CASE_ID_HEX_LENGTH,
        )

    @staticmethod
    def _discovery_evidence(
        *,
        program_name: str,
        subdomain: str,
        path: str,
        parameter: str,
        method: str,
        location: str,
        source: str,
    ) -> list[str]:
        """
        Bounded, deterministic provenance entries tracing the
        case back to program, endpoint, parameter, method,
        location, and discovery source. No secrets, no database
        dumps, no free-form rows.
        """

        entries = [
            "source_type:endpoint",
            "origin:watch_endpoint_inventory",
            f"program_name:{program_name}",
            f"endpoint_subdomain:{subdomain}",
            f"endpoint_path:{path}",
            f"parameter:{parameter}",
            f"method:{method}",
            f"parameter_location:{location}",
            f"discovered_by:{source}",
        ]
        return [
            entry[:_EVIDENCE_ENTRY_LIMIT] for entry in entries
        ]


