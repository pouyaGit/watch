"""Stage R30.2 observed asset inventory derivation (pure engine).

Derives a deterministic, read-only *observed* inventory (technologies,
products, components, plugins, versions, parameters, paths) from
already-loaded Watch recon records, and feeds it into the existing R30.1
matching layer.

This module is **pure and offline**: no I/O, no network, no DNS, no LLM, no
subprocess, no Nuclei, no browser, no target interaction, no persistence and no
execution. It never invents a value: a category is empty when no persisted
source establishes it.

Sources reused (no new source is introduced):

- ``database.Http.tech`` -> technologies + technology versions
  (via the existing ``ai.researcher.target_intelligence`` projector, which
  also validates every observation);
- ``database.Endpoints.path`` -> paths;
- ``database.Endpoints.params`` / ``param_records`` -> parameters with the
  canonical method/location/source provenance.

There is no persisted component/plugin/product field anywhere in the current
Watch data model, so those collectors accept *explicit* already-loaded records
and return empty when none are provided. They never turn path segments or
technology implications into components/plugins/products.

Stage R30.3 (additive) additionally pairs each derived version with its owning
observed technology family (from the same Http.tech observation) so the R30.1
version evaluation can distinguish ``VERSION_MATCH_WITHIN_SAME_FAMILY`` from
``VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION``. Component ownership is only
taken from explicit structured records and stays ``""`` (unavailable)
otherwise; it is never inferred.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai.correlator.technology import normalize as normalize_technology
from ai.knowledge.asset_cve_matching import (
    normalize_parameter,
    normalize_version,
)
from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ProgramRecord,
    SubdomainRecord,
    TargetIntelError,
    UrlRecord,
    project_subdomain,
)
from ai.schemas.observed_inventory import (
    OBSERVED_INVENTORY_RULE_VERSION,
    ObservedAssetInventory,
    ObservedItem,
    ObservedParameterPath,
    ObservedVersionAssociation,
    inventory_id_for,
)

RULE_VERSION = OBSERVED_INVENTORY_RULE_VERSION

# Inventory sources (closed vocabulary; mirrored by the schema).
SOURCE_ASSET = "ASSET_INVENTORY"
SOURCE_TECHNOLOGY = "TECHNOLOGY_INVENTORY"
SOURCE_COMPONENT = "COMPONENT_INVENTORY"
SOURCE_PARAMETER = "PARAMETER_INVENTORY"
SOURCE_ENDPOINT = "ENDPOINT_INVENTORY"

# Evidence types (closed vocabulary; mirrored by the schema).
EVIDENCE_EXPLICIT = "EXPLICIT_FIELD"
EVIDENCE_ENDPOINT = "STRUCTURED_ENDPOINT"
EVIDENCE_PARAMETER = "STRUCTURED_PARAMETER"
EVIDENCE_TECHNOLOGY = "STRUCTURED_TECHNOLOGY"
EVIDENCE_COMPONENT = "STRUCTURED_COMPONENT"

_MAX_ITEMS = 2000
_MAX_EVIDENCE = 256
_MAX_LINE = 512
_SINGLE_LINE_RE = re.compile(r"[\r\n]+")


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _clean(value: object) -> str:
    text = str(value if value is not None else "")
    text = _SINGLE_LINE_RE.sub(" ", text).strip()
    return text[:_MAX_LINE]


def _item(
    value: object,
    source: str,
    evidence_type: str,
) -> ObservedItem | None:
    text = _clean(value)
    if not text:
        return None
    try:
        return ObservedItem(
            value=text, source=source, evidence_type=evidence_type
        )
    except ValueError:
        return None


def _dedupe(
    items: list[ObservedItem],
    key_fn,
) -> list[ObservedItem]:
    """Deduplicate by a deterministic key, preserving the first occurrence."""

    seen: set = set()
    out: list[ObservedItem] = []
    for item in items:
        key = key_fn(item)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= _MAX_ITEMS:
            break
    return out


def _sort_items(items: list[ObservedItem]) -> list[ObservedItem]:
    return sorted(
        items, key=lambda item: (item.value, item.source, item.evidence_type)
    )


def _explicit_items(
    records: object,
    *,
    default_source: str,
    default_evidence: str,
) -> list[ObservedItem]:
    """Collect explicit already-loaded records (never inferred).

    Each record may be an :class:`ObservedItem`, a mapping, or an object with
    a ``value`` attribute (plus optional ``source``/``evidence_type``).
    """

    out: list[ObservedItem] = []
    for record in records or ():
        if record is None:
            continue
        if isinstance(record, ObservedItem):
            out.append(record)
            continue
        if isinstance(record, dict):
            value = record.get("value")
            source = record.get("source") or default_source
            evidence_type = record.get("evidence_type") or default_evidence
        else:
            value = getattr(record, "value", None)
            source = getattr(record, "source", None) or default_source
            evidence_type = (
                getattr(record, "evidence_type", None) or default_evidence
            )
        item = _item(value, source, evidence_type)
        if item is not None:
            out.append(item)
    return out


def _normalize_path_key(path: object) -> str:
    text = _clean(path)
    if not text:
        return ""
    if not text.startswith("/"):
        text = "/" + text
    return text


# ---------------------------------------------------------------------------
# Category collectors (already-loaded projections / records in, items out)
# ---------------------------------------------------------------------------


def collect_technologies(projections: object) -> list[ObservedItem]:
    """Technologies from the existing target-intelligence projections."""

    items: list[ObservedItem] = []
    for projection in projections or ():
        for observation in getattr(projection, "technologies", ()) or ():
            name = _clean(getattr(observation, "name", ""))
            item = _item(
                name, SOURCE_TECHNOLOGY, EVIDENCE_TECHNOLOGY
            )
            if item is not None:
                items.append(item)
    return _sort_items(
        _dedupe(items, lambda item: normalize_technology(item.value))
    )


def collect_versions(projections: object) -> list[ObservedItem]:
    """Versions only from explicit technology-version evidence.

    Versions are never inferred from dates, defaults, package names or URL
    numbers. A versionless technology contributes nothing here.
    """

    items: list[ObservedItem] = []
    for projection in projections or ():
        for observation in getattr(projection, "technologies", ()) or ():
            version = getattr(observation, "observed_version", None)
            if not version:
                continue
            item = _item(
                version, SOURCE_TECHNOLOGY, EVIDENCE_TECHNOLOGY
            )
            if item is not None:
                items.append(item)
    return _sort_items(
        _dedupe(items, lambda item: normalize_version(item.value))
    )


def collect_paths(projections: object) -> list[ObservedItem]:
    """Paths only from existing persisted endpoint records (path-level)."""

    counts: dict[str, int] = {}
    display: dict[str, str] = {}
    for projection in projections or ():
        for endpoint in (
            getattr(projection, "endpoint_observations", ()) or ()
        ):
            path = _normalize_path_key(getattr(endpoint, "path", ""))
            if not path:
                continue
            counts[path] = counts.get(path, 0) + 1
            display.setdefault(path, _clean(getattr(endpoint, "path", "")))
    items: list[ObservedItem] = []
    for key in sorted(counts):
        item = _item(
            display.get(key, key), SOURCE_ENDPOINT, EVIDENCE_ENDPOINT
        )
        if item is not None:
            items.append(item)
    return items


def collect_parameters(projections: object) -> list[ObservedItem]:
    """Parameters only from existing persisted parameter records.

    Both the canonical ``param_records`` provenance and the aggregate
    ``params`` list are persisted Watch data; the union is used and the
    method/location/source detail is preserved as evidence lines.
    """

    names: dict[str, str] = {}
    for projection in projections or ():
        for endpoint in (
            getattr(projection, "endpoint_observations", ()) or ()
        ):
            for name in getattr(endpoint, "params", ()) or ():
                cleaned = _clean(name)
                if cleaned:
                    names.setdefault(
                        normalize_parameter(cleaned), cleaned
                    )
            for detail in (
                getattr(endpoint, "param_details", ()) or ()
            ):
                cleaned = _clean(getattr(detail, "name", ""))
                if cleaned:
                    names.setdefault(
                        normalize_parameter(cleaned), cleaned
                    )
    items: list[ObservedItem] = []
    for key in sorted(names):
        item = _item(
            names[key], SOURCE_PARAMETER, EVIDENCE_PARAMETER
        )
        if item is not None:
            items.append(item)
    return items


def collect_parameter_paths(
    projections: object,
) -> list[ObservedParameterPath]:
    """Parameter -> path-only endpoint linkage (additive Stage R31.5).

    A parameter is only component-scoped when the endpoint path that carries
    it is inside the inferred component's owning scope; this collector supplies
    that endpoint path. Deterministic, deduplicated and bounded; path-only.
    """

    pairs: dict[tuple[str, str], ObservedParameterPath] = {}
    for projection in projections or ():
        for endpoint in (
            getattr(projection, "endpoint_observations", ()) or ()
        ):
            path = _normalize_path_key(getattr(endpoint, "path", ""))
            if not path:
                continue
            names: list[str] = []
            for name in getattr(endpoint, "params", ()) or ():
                cleaned = _clean(name)
                if cleaned:
                    names.append(cleaned)
            for detail in (
                getattr(endpoint, "param_details", ()) or ()
            ):
                cleaned = _clean(getattr(detail, "name", ""))
                if cleaned:
                    names.append(cleaned)
            for cleaned in names:
                try:
                    record = ObservedParameterPath(
                        parameter=cleaned,
                        path=path,
                        source=SOURCE_PARAMETER,
                    )
                except ValueError:
                    continue
                key = (normalize_parameter(cleaned), path)
                pairs.setdefault(key, record)
    return [pairs[key] for key in sorted(pairs)][:_MAX_ITEMS]


def collect_products(records: object = ()) -> list[ObservedItem]:
    """Products only when explicitly represented in persisted records."""

    return _sort_items(
        _dedupe(
            _explicit_items(
                records,
                default_source=SOURCE_ASSET,
                default_evidence=EVIDENCE_EXPLICIT,
            ),
            lambda item: normalize_technology(item.value),
        )
    )


def collect_components(records: object = ()) -> list[ObservedItem]:
    """Components only from explicit persisted component records.

    Arbitrary URL path segments are never turned into components here.
    """

    return _sort_items(
        _dedupe(
            _explicit_items(
                records,
                default_source=SOURCE_COMPONENT,
                default_evidence=EVIDENCE_COMPONENT,
            ),
            lambda item: normalize_technology(item.value),
        )
    )


def collect_plugins(records: object = ()) -> list[ObservedItem]:
    """Plugins only from explicit persisted plugin evidence.

    A ``/wp-content/plugins/<slug>/`` path alone is never assumed to mean a
    plugin: the current Watch data model does not treat it as plugin evidence.
    """

    return _sort_items(
        _dedupe(
            _explicit_items(
                records,
                default_source=SOURCE_COMPONENT,
                default_evidence=EVIDENCE_COMPONENT,
            ),
            lambda item: normalize_technology(item.value),
        )
    )


def _association(
    *,
    version: object,
    family: object = "",
    component: object = "",
    source: str,
    evidence_type: str,
) -> ObservedVersionAssociation | None:
    text = _clean(version)
    if not text:
        return None
    try:
        return ObservedVersionAssociation(
            version=text,
            technology_family=_clean(family),
            component=_clean(component),
            source=source,
            evidence_type=evidence_type,
        )
    except ValueError:
        return None


def _association_from_record(
    record: object,
) -> ObservedVersionAssociation | None:
    """Coerce one explicit structured version-owner record (never inferred)."""

    if record is None:
        return None
    if isinstance(record, ObservedVersionAssociation):
        return record
    if isinstance(record, dict):
        version = record.get("version") or record.get("value")
        family = record.get("technology_family") or record.get("family")
        component = record.get("component")
        source = record.get("source") or SOURCE_TECHNOLOGY
        evidence_type = (
            record.get("evidence_type") or EVIDENCE_TECHNOLOGY
        )
    else:
        version = getattr(record, "version", None) or getattr(
            record, "value", None
        )
        family = getattr(record, "technology_family", "") or getattr(
            record, "family", ""
        )
        component = getattr(record, "component", "")
        source = getattr(record, "source", None) or SOURCE_TECHNOLOGY
        evidence_type = (
            getattr(record, "evidence_type", None) or EVIDENCE_TECHNOLOGY
        )
    return _association(
        version=version,
        family=family,
        component=component,
        source=source,
        evidence_type=evidence_type,
    )


def collect_version_associations(
    projections: object,
    records: object = (),
) -> list[ObservedVersionAssociation]:
    """Versions paired with their owning observed technology family.

    The owning family comes from the same persisted technology observation that
    produced the version (e.g. the ``WordPress:6.8.3`` Http.tech label).
    Components are only taken from *explicit structured records*; the current
    persisted Watch model has no component/plugin version source, so every
    technology-derived version reports ``component = ""`` (unavailable) and an
    owner is never inferred from paths, hostnames, parameters or keywords.
    """

    items: list[ObservedVersionAssociation] = []
    for projection in projections or ():
        for observation in getattr(projection, "technologies", ()) or ():
            version = getattr(observation, "observed_version", None)
            if not version:
                continue
            item = _association(
                version=version,
                family=getattr(observation, "name", ""),
                component="",
                source=SOURCE_TECHNOLOGY,
                evidence_type=EVIDENCE_TECHNOLOGY,
            )
            if item is not None:
                items.append(item)
    for record in records or ():
        item = _association_from_record(record)
        if item is not None:
            items.append(item)

    deduped: list[ObservedVersionAssociation] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        key = (
            normalize_version(item.version),
            normalize_technology(item.technology_family),
            normalize_technology(item.component),
        )
        if not key[0] or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= _MAX_ITEMS:
            break
    return sorted(
        deduped,
        key=lambda item: (
            normalize_version(item.version),
            normalize_technology(item.technology_family),
            normalize_technology(item.component),
            item.source,
            item.evidence_type,
        ),
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


@dataclass
class _Grouped:
    subdomains: dict[str, str]
    http: dict[str, list]
    urls: dict[str, list]
    endpoints: dict[str, list]


def _group_records(
    program: str,
    *,
    http_records: object,
    url_records: object,
    endpoint_records: object,
    subdomain_records: object,
) -> _Grouped:
    grouped = _Grouped(subdomains={}, http={}, urls={}, endpoints={})

    for record in subdomain_records or ():
        if isinstance(record, SubdomainRecord):
            owner = record.program_name
            sub = record.subdomain
            scope = record.scope
        elif isinstance(record, dict):
            owner = str(record.get("program_name") or "")
            sub = str(record.get("subdomain") or "")
            scope = str(record.get("scope") or "")
        else:
            owner = str(getattr(record, "program_name", "") or "")
            sub = str(getattr(record, "subdomain", "") or "")
            scope = str(getattr(record, "scope", "") or "")
        if owner == program and sub:
            grouped.subdomains.setdefault(sub, scope)

    for bucket, records in (
        (grouped.http, http_records),
        (grouped.urls, url_records),
        (grouped.endpoints, endpoint_records),
    ):
        for record in records or ():
            owner = str(getattr(record, "program_name", "") or "")
            sub = str(getattr(record, "subdomain", "") or "")
            if owner != program or not sub:
                continue
            bucket.setdefault(sub, []).append(record)
            grouped.subdomains.setdefault(sub, grouped.subdomains.get(sub, ""))
    return grouped


def collect_program_inventory(
    program: str,
    *,
    http_records: object = (),
    url_records: object = (),
    endpoint_records: object = (),
    subdomain_records: object = (),
    product_records: object = (),
    component_records: object = (),
    plugin_records: object = (),
    version_records: object = (),
) -> dict:
    """Derive the full category map for one program (pure, deterministic)."""

    program_name = _clean(program)
    grouped = _group_records(
        program_name,
        http_records=http_records,
        url_records=url_records,
        endpoint_records=endpoint_records,
        subdomain_records=subdomain_records,
    )

    projections: list = []
    skipped_subdomains: list[str] = []
    program_record = ProgramRecord(program_name=program_name)
    for sub in sorted(grouped.subdomains):
        subdomain_record = SubdomainRecord(
            program_name=program_name,
            subdomain=sub,
            scope=_clean(grouped.subdomains.get(sub, "")),
        )
        try:
            projected = project_subdomain(
                program_record,
                subdomain_record,
                https=grouped.http.get(sub, []),
                urls=grouped.urls.get(sub, []),
                endpoints=grouped.endpoints.get(sub, []),
            )
        except (TargetIntelError, ValueError, TypeError):
            skipped_subdomains.append(sub)
            continue
        projections.append(projected.intelligence)

    technologies = collect_technologies(projections)
    versions = collect_versions(projections)
    version_associations = collect_version_associations(
        projections, version_records
    )
    paths = collect_paths(projections)
    parameters = collect_parameters(projections)
    parameter_paths = collect_parameter_paths(projections)
    products = collect_products(product_records)
    components = collect_components(component_records)
    plugins = collect_plugins(plugin_records)

    evidence: list[str] = []
    for item in technologies:
        evidence.append(f"technology {item.value!r} from Http.tech")
    for projection in projections:
        for observation in getattr(projection, "technologies", ()) or ():
            version = getattr(observation, "observed_version", None)
            if version:
                evidence.append(
                    f"version {version!r} from Http.tech technology "
                    f"{_clean(getattr(observation, 'name', ''))!r}"
                )
    for item in version_associations:
        evidence.append(
            f"version {item.version!r} owned by technology family "
            f"{(item.technology_family or 'unavailable')!r} "
            f"(component {item.component or 'unavailable'!r}) "
            f"from {item.source}"
        )
    for item in paths:
        evidence.append(f"path {item.value!r} from Endpoints.path")
    for projection in projections:
        for endpoint in (
            getattr(projection, "endpoint_observations", ()) or ()
        ):
            for detail in (
                getattr(endpoint, "param_details", ()) or ()
            ):
                evidence.append(
                    f"parameter {_clean(getattr(detail, 'name', ''))!r} "
                    f"from Endpoints.param_records "
                    f"(method={_clean(getattr(detail, 'method', ''))} "
                    f"location={_clean(getattr(detail, 'location', ''))} "
                    f"source={_clean(getattr(detail, 'source', ''))})"
                )
    evidence = sorted({line for line in evidence if line})[:_MAX_EVIDENCE]

    sources = sorted(
        {
            item.source
            for collection in (
                technologies, products, components, plugins, versions,
                parameters, paths,
            )
            for item in collection
        }
        | {item.source for item in version_associations}
    )
    return {
        "program": program_name,
        "technologies": technologies,
        "products": products,
        "components": components,
        "plugins": plugins,
        "versions": versions,
        "version_associations": version_associations,
        "parameters": parameters,
        "parameter_paths": parameter_paths,
        "paths": paths,
        "sources": sources,
        "evidence": evidence,
        "generated_from": {
            "http_records": sum(
                len(grouped.http.get(sub, [])) for sub in grouped.http
            ),
            "endpoint_records": sum(
                len(grouped.endpoints.get(sub, []))
                for sub in grouped.endpoints
            ),
            "url_records": sum(
                len(grouped.urls.get(sub, [])) for sub in grouped.urls
            ),
            "subdomain_records": len(grouped.subdomains),
            "projected_subdomains": len(projections),
            "skipped_subdomains": len(skipped_subdomains),
            "version_associations": len(version_associations),
            "parameter_paths": len(parameter_paths),
        },
    }


def build_observed_inventory(
    program: str,
    **kwargs,
) -> ObservedAssetInventory:
    """Build the schema :class:`ObservedAssetInventory` for one program."""

    collected = collect_program_inventory(program, **kwargs)
    return ObservedAssetInventory(
        inventory_id=inventory_id_for(collected["program"]),
        program=collected["program"],
        technologies=collected["technologies"],
        products=collected["products"],
        components=collected["components"],
        plugins=collected["plugins"],
        versions=collected["versions"],
        version_associations=collected["version_associations"],
        parameter_paths=collected["parameter_paths"],
        parameters=collected["parameters"],
        paths=collected["paths"],
        sources=collected["sources"],
        evidence=collected["evidence"],
        generated_from=collected["generated_from"],
    )


def build_inventory_summary(inventories: object) -> dict:
    """Compact deterministic counts across observed inventories."""

    items = [
        item
        for item in (inventories or ())
        if isinstance(item, ObservedAssetInventory)
    ]
    by_program: dict[str, dict] = {}
    for item in items:
        by_program[item.program] = {
            "technologies": len(item.technologies),
            "products": len(item.products),
            "components": len(item.components),
            "plugins": len(item.plugins),
            "versions": len(item.versions),
            "version_associations": len(item.version_associations),
            "parameters": len(item.parameters),
            "parameter_paths": len(item.parameter_paths),
            "paths": len(item.paths),
            "sources": list(item.sources),
        }
    return {
        "total": len(items),
        "programs": sorted(by_program),
        "by_program": dict(sorted(by_program.items())),
        "rule_version": RULE_VERSION,
        "research_only": True,
    }


__all__ = [
    "RULE_VERSION",
    "SOURCE_ASSET",
    "SOURCE_TECHNOLOGY",
    "SOURCE_COMPONENT",
    "SOURCE_PARAMETER",
    "SOURCE_ENDPOINT",
    "EVIDENCE_EXPLICIT",
    "EVIDENCE_ENDPOINT",
    "EVIDENCE_PARAMETER",
    "EVIDENCE_TECHNOLOGY",
    "EVIDENCE_COMPONENT",
    "collect_program_inventory",
    "collect_technologies",
    "collect_products",
    "collect_components",
    "collect_plugins",
    "collect_versions",
    "collect_version_associations",
    "collect_parameters",
    "collect_parameter_paths",
    "collect_paths",
    "build_observed_inventory",
    "build_inventory_summary",
]
