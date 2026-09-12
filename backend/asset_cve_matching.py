"""backend/asset_cve_matching.py — Stage R30.1 asset <-> CVE composition.

Read-only composition that joins already-persisted CVE metadata (KnowledgeStore
synthesis documents + local ``*.cli.json`` research payloads) with the existing
local asset/program inventory, then projects through the pure
``ai.knowledge.asset_cve_matching`` engine.

Stage R30.3 adds an additive association step *before* the R30.1 version
evaluation: observed versions are paired with their explicit owning
technology family/component via ``ai.knowledge.version_component_association``
so a family-level version match can never be promoted into a component/plugin
match. The R30.1 engine semantics are untouched.

No new scoring formula, no new numeric opportunity score, no LLM, no network,
no DNS, no subprocess, no Nuclei, no browser, no target interaction, no
findings, no alerts, no PoC execution, no persistence and no new Mongo
collection. R17/R26/R29 are never mutated: this module only reads and derives.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Optional
from urllib.parse import urlsplit

from ai.knowledge.asset_cve_matching import (
    RULE_VERSION,
    evaluate_inventory,
    match_component,
    match_parameter,
    match_path,
    match_plugin,
    normalize_component,
    normalize_parameter,
    normalize_plugin,
    normalize_version,
)
from ai.knowledge.component_identity import (
    RULE_VERSION as IDENTITY_RESOLUTION_RULE_VERSION,
    expanded_cve_value_set,
    match_observed_identities,
    resolve_cve_identities,
)
from ai.knowledge.path_parameter_relevance import (
    RULE_VERSION as PATH_PARAMETER_RELEVANCE_RULE_VERSION,
    evaluate_path_parameter_relevance,
)
from ai.knowledge.version_component_association import (
    RULE_VERSION as ASSOCIATION_RULE_VERSION,
    evaluate_version_association,
)
from ai.knowledge.version_normalization import (
    RULE_VERSION as VERSION_NORMALIZATION_RULE_VERSION,
    build_version_evidence,
)
from ai.schemas.observed_inventory import (
    EVIDENCE_PROVENANCE_RULE_VERSION,
)

MAX_PROGRAMS = 100

# Stage R31.5 evidence-provenance vocabulary (closed, advisory-only).
PROVENANCE_STATES: tuple[str, ...] = ("EXPLICIT", "INFERRED", "MIXED")
SUPPORT_SCOPES: tuple[str, ...] = ("COMPONENT_SCOPED", "GLOBAL", "NONE")

# Bound on withheld-support evidence lines recorded additively.
MAX_WITHHELD_SUPPORT = 64

# Bound on identity-resolution evidence rows recorded additively per match.
MAX_IDENTITY_EVIDENCE = 64

# Bound on R31.8 path/parameter relevance evidence rows per match.
MAX_PATH_PARAMETER_EVIDENCE = 64

_METADATA_OBSERVED_KEYS = (
    ("plugins", "plugins"),
    ("components", "components"),
    ("versions", "versions"),
    ("parameters", "parameters"),
    ("paths", "paths"),
    ("products", "products"),
    ("categories", "categories"),
)


def _safe_list(value: Any) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple, set)) else [value]
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
        if len(out) >= 256:
            break
    return out


def _asset_identifier(program: str, asset_ids: object) -> str:
    """Privacy-preserving internal asset identity.

    Derived deterministically from the existing internal asset identities so
    raw target URLs/IPs/hostnames are never emitted in public-facing output.
    """

    assets = ",".join(sorted({str(a) for a in asset_ids or () if str(a).strip()}))
    basis = "\n".join([RULE_VERSION, str(program or ""), assets])
    return "asset-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _research_extras(payload: dict) -> dict:
    """Explicit affected-version/plugin hints from the local research payload."""

    research = payload.get("research") if isinstance(payload, dict) else {}
    if not isinstance(research, dict):
        research = {}
    cve_block = payload.get("cve") if isinstance(payload, dict) else {}
    if not isinstance(cve_block, dict):
        cve_block = {}
    versions = _safe_list(research.get("affected_versions")) + _safe_list(
        cve_block.get("affected_versions")
    )
    products = _safe_list(cve_block.get("products")) + _safe_list(
        research.get("affected_products")
    )
    plugins = [
        product for product in products if "plugin" in product.lower()
    ]
    return {
        "versions": versions,
        "products": products,
        "plugins": plugins,
    }


def _metadata_observed(payload: dict) -> dict:
    """Observed inventory hints already persisted in the research metadata.

    Current research payloads persist ``technologies`` (and sometimes
    ``assets``); other keys are read defensively so real evidence surfaces when
    present and nothing is invented when absent.
    """

    metadata = payload.get("metadata") if isinstance(payload, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    observed = {
        "plugins": [],
        "components": [],
        "versions": [],
        "parameters": [],
        "paths": [],
        "products": [],
        "categories": [],
    }
    for key, target in _METADATA_OBSERVED_KEYS:
        if key in metadata:
            observed[target] = _safe_list(metadata.get(key))
    return observed


def _contexts(cve: Optional[str]) -> list[dict]:
    from ai.knowledge.queue import local_cve_context
    from backend import research_data as rd

    try:
        return local_cve_context(
            rd._kb_store(), rd.RESEARCH_DIR, rd.PROGRAMS_DIR, cve=cve
        )
    except (OSError, ValueError):
        return []


def _blocker_codes(profile: dict, assets: object) -> dict[str, list[str]]:
    """Map the existing R18 blockers onto stable R30.1 codes per program."""

    from ai.knowledge.asset_cve_matching import normalize_blocker_code
    from ai.knowledge.queue import build_research_queue

    mapping: dict[str, list[str]] = {}
    try:
        items = build_research_queue(
            [{"vulnerability": profile, "assets": assets}]
        )
    except (OSError, ValueError):
        return mapping
    for item in items:
        program = str(getattr(item, "program", "") or "")
        if not program:
            continue
        mapping[program] = [
            normalize_blocker_code(code)
            for code in getattr(item, "blockers", []) or []
        ]
    return mapping


def _observed_from_assets(records: object) -> dict:
    observed = {
        "products": [],
        "components": [],
        "plugins": [],
        "technologies": [],
        "paths": [],
    }
    for record in records or ():
        for key, attribute in (
            ("products", "products"),
            ("components", "components"),
            ("technologies", "technologies"),
            ("paths", "paths"),
        ):
            for value in getattr(record, attribute, ()) or ():
                text = str(value or "").strip()
                if text and text not in observed[key]:
                    observed[key].append(text)
    return observed


def _merge_unique(*lists: object) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for values in lists:
        for value in values or ():
            text = str(value or "").strip()
            if text and text not in seen:
                seen.add(text)
                out.append(text)
    return out


def _inventory_values(program: str) -> dict[str, list]:
    """Stage R30.2 observed-inventory values for one program (fail-soft).

    Returns plain observed value lists for the R30.1 matcher input plus the
    Stage R30.3 version-association records and the Stage R31.5 structured
    provenance/parameter-path additions; the R30.1 matching rules are
    untouched.
    """

    try:
        from backend import observed_inventory

        inventory = observed_inventory.get_inventory(program)
    except Exception:
        return {}
    if not inventory:
        return {}
    out: dict[str, list] = {}
    for key in (
        "products",
        "components",
        "plugins",
        "technologies",
        "versions",
        "parameters",
        "paths",
    ):
        values: list[str] = []
        seen: set[str] = set()
        for item in inventory.get(key) or ():
            value = str(item.get("value") or "").strip()
            if value and value not in seen:
                seen.add(value)
                values.append(value)
        out[key] = values
    associations: list[dict] = []
    for item in inventory.get("version_associations") or ():
        if isinstance(item, dict):
            associations.append(item)
    out["version_associations"] = associations
    provenance: list[dict] = []
    for item in inventory.get("component_provenance") or ():
        if isinstance(item, dict):
            provenance.append(item)
    out["component_provenance"] = provenance
    parameter_paths: list[dict] = []
    for item in inventory.get("parameter_paths") or ():
        if isinstance(item, dict):
            parameter_paths.append(item)
    out["parameter_paths"] = parameter_paths
    out["inferred_components"] = []
    out["explicit_components"] = []
    out["inferred_plugins"] = []
    out["explicit_plugins"] = []
    for key, inferred_key, explicit_key in (
        ("components", "inferred_components", "explicit_components"),
        ("plugins", "inferred_plugins", "explicit_plugins"),
    ):
        for item in inventory.get(key) or ():
            if not isinstance(item, dict):
                continue
            value = str(item.get("value") or "").strip()
            if not value:
                continue
            evidence_type = str(
                item.get("evidence_type") or ""
            ).strip().upper()
            target = (
                out[inferred_key]
                if evidence_type.startswith("INFERRED")
                else out[explicit_key]
            )
            if value not in target:
                target.append(value)
    # Provenance alone also establishes inferred evidence (e.g. the inferred
    # item was deduplicated against an explicit one -> MIXED).
    for item in inventory.get("component_provenance") or ():
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "").strip().upper()
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        if category == "COMPONENT":
            if value not in out["inferred_components"]:
                out["inferred_components"].append(value)
        elif category == "PLUGIN":
            if value not in out["inferred_plugins"]:
                out["inferred_plugins"].append(value)
    return out


def _version_association_records(
    inventory_observed: dict, metadata_versions: object
) -> list[dict]:
    """Stage R30.3 association records for one program (never inferred).

    Inventory-derived associations keep their explicit owning family/component.
    Flat inventory versions and persisted research-metadata versions carry no
    established owner, so they enter as component-unavailable records; an owner
    is never guessed from URLs, hostnames, parameters, keywords or CVE text.
    """

    records: list[dict] = []
    covered: set[str] = set()
    for item in inventory_observed.get("version_associations") or ():
        if not isinstance(item, dict):
            continue
        version = str(item.get("version") or "").strip()
        if not version:
            continue
        records.append(
            {
                "version": version,
                "technology_family": str(
                    item.get("technology_family") or ""
                ).strip(),
                "component": str(item.get("component") or "").strip(),
                "source": str(
                    item.get("source") or "TECHNOLOGY_INVENTORY"
                ),
                "evidence_type": str(
                    item.get("evidence_type") or "STRUCTURED_TECHNOLOGY"
                ),
            }
        )
        covered.add(normalize_version(version))
    for value in inventory_observed.get("versions") or ():
        text = str(value or "").strip()
        if not text or normalize_version(text) in covered:
            continue
        records.append({"version": text})
    for value in metadata_versions or ():
        text = str(value or "").strip()
        if text:
            records.append({"version": text})
    return records


def _normalized_keys(values: object, normalizer) -> set[str]:
    keys: set[str] = set()
    for value in values or ():
        text = str(value or "").strip()
        if not text:
            continue
        normalized = normalizer(text)
        if normalized:
            keys.add(normalized)
    return keys


def _path_key(value: object) -> str:
    """Path-only key (no scheme/host/query/fragment) for scope comparison."""

    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text or text.startswith("//"):
        try:
            text = urlsplit(text).path or ""
        except ValueError:
            return ""
    text = text.split("?", 1)[0].split("#", 1)[0].strip()
    if not text:
        return ""
    if not text.startswith("/"):
        text = "/" + text
    return text


def _in_scope(path: object, scope: object) -> bool:
    path_key = _path_key(path)
    scope_key = _path_key(scope)
    if not path_key or not scope_key:
        return False
    scope_key = scope_key.rstrip("/") + "/"
    return path_key == scope_key.rstrip("/") or path_key.startswith(scope_key)


def _provenance_scopes(inventory_observed: dict) -> dict:
    """Normalized inferred value -> path-only owning scopes (R31.5)."""

    scopes: dict[str, dict[str, set[str]]] = {
        "component": {},
        "plugin": {},
    }
    normalizers = {
        "component": normalize_component,
        "plugin": normalize_plugin,
    }
    for item in inventory_observed.get("component_provenance") or ():
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "").strip().lower()
        if category not in scopes:
            continue
        value = str(item.get("value") or "").strip()
        scope = _path_key(item.get("scope_path") or "")
        normalized = normalizers[category](value) if value else ""
        if not normalized or not scope:
            continue
        scopes[category].setdefault(normalized, set()).add(scope)
    return scopes


def _parameter_locations(inventory_observed: dict) -> dict:
    """Normalized parameter -> set of path-only endpoints carrying it."""

    locations: dict[str, set[str]] = {}
    for item in inventory_observed.get("parameter_paths") or ():
        if not isinstance(item, dict):
            continue
        name = normalize_parameter(item.get("parameter") or "")
        path = _path_key(item.get("path") or "")
        if name and path:
            locations.setdefault(name, set()).add(path)
    return locations


def _support_gate(
    *,
    cve_components: object,
    cve_plugins: object,
    cve_parameters: object,
    cve_paths: object,
    observed_components: object,
    observed_plugins: object,
    observed_parameters: object,
    observed_paths: object,
    explicit_keys: dict,
    inferred_keys: dict,
    provenance_scopes: dict,
    parameter_locations: dict,
) -> dict:
    """Stage R31.5 deterministic component-scoped support gate.

    Distinguishes EXPLICIT / INFERRED / MIXED component-plugin evidence and,
    for inferred-only evidence, replaces global PARAMETER/PATH support with
    component-scoped support before it reaches the unchanged R30.1 engine.
    Explicit evidence is never gated. Withheld global support is recorded.
    """

    matched_inferred: dict[str, set[str]] = {
        "component": set(),
        "plugin": set(),
    }
    matched_explicit: dict[str, set[str]] = {
        "component": set(),
        "plugin": set(),
    }
    for category, cve_values, observed_values, matcher, normalizer in (
        (
            "component",
            cve_components,
            observed_components,
            match_component,
            normalize_component,
        ),
        (
            "plugin",
            cve_plugins,
            observed_plugins,
            match_plugin,
            normalize_plugin,
        ),
    ):
        for value in observed_values or ():
            text = str(value or "").strip()
            if not text:
                continue
            if matcher(cve_values, [text]) is None:
                continue
            normalized = normalizer(text)
            if not normalized:
                continue
            if normalized in inferred_keys.get(category, ()):
                matched_inferred[category].add(normalized)
            if normalized in explicit_keys.get(category, ()):
                matched_explicit[category].add(normalized)

    any_inferred = any(matched_inferred.values())
    any_explicit = any(matched_explicit.values())
    result = {
        "provenance": "EXPLICIT",
        "support_scope": "GLOBAL",
        "gating": False,
        "parameters": list(observed_parameters or ()),
        "paths": list(observed_paths or ()),
        "withheld": [],
    }
    if not any_inferred:
        return result
    if any_explicit:
        result["provenance"] = "MIXED"
        return result

    # Inferred-only component/plugin evidence: scope the support.
    result["provenance"] = "INFERRED"
    result["gating"] = True

    scopes: set[str] = set()
    for category in ("component", "plugin"):
        for key in matched_inferred[category]:
            scopes.update(provenance_scopes.get(category, {}).get(key, ()))
    scope_keys = [
        scope.rstrip("/") + "/" for scope in sorted(scopes)
    ]

    scoped_paths: list[str] = []
    for path in observed_paths or ():
        key = _path_key(path)
        if not key:
            continue
        if any(
            key == scope.rstrip("/") or key.startswith(scope)
            for scope in scope_keys
        ):
            scoped_paths.append(str(path))
    scoped_parameters: list[str] = []
    for parameter in observed_parameters or ():
        locations = parameter_locations.get(
            normalize_parameter(parameter), ()
        )
        if any(
            _in_scope(location, scope)
            for location in locations
            for scope in scope_keys
        ):
            scoped_parameters.append(str(parameter))

    result["parameters"] = scoped_parameters
    result["paths"] = scoped_paths
    result["support_scope"] = (
        "COMPONENT_SCOPED"
        if (scoped_parameters or scoped_paths)
        else "NONE"
    )

    withheld: list[str] = []
    cve_parameter_keys = _normalized_keys(
        cve_parameters, normalize_parameter
    )
    scoped_parameter_set = set(scoped_parameters)
    for parameter in observed_parameters or ():
        text = str(parameter)
        if text in scoped_parameter_set:
            continue
        if normalize_parameter(text) in cve_parameter_keys:
            withheld.append(
                f"parameter {text!r} observed globally "
                "(not component-scoped)"
            )
    if cve_paths and observed_paths:
        scoped_path_set = set(scoped_paths)
        unscoped_paths = [
            path
            for path in observed_paths
            if str(path) not in scoped_path_set
        ]
        hit = match_path(cve_paths, unscoped_paths)
        if hit is not None:
            withheld.append(
                f"path {hit.matched_value!r} observed globally "
                "(not component-scoped)"
            )
    result["withheld"] = sorted(set(withheld))[:MAX_WITHHELD_SUPPORT]
    return result


def build_matches(
    cve: Optional[str] = None, program: Optional[str] = None
) -> dict:
    """Deterministic asset <-> CVE match projection (read-only, fail-soft)."""

    requested_program = str(program or "").strip()
    results: list[dict] = []
    for context in _contexts(cve):
        from ai.knowledge.queue import vulnerability_profile

        cve_id = str(context.get("cve") or "").strip().upper()
        if not cve_id:
            continue
        profile = vulnerability_profile(
            context["document"], context.get("payload") or {}, cve_id
        )
        extras = _research_extras(context.get("payload") or {})
        metadata_observed = _metadata_observed(context.get("payload") or {})
        cve_products = _merge_unique(
            profile.get("products"), extras.get("products")
        )
        cve_plugins = _merge_unique(extras.get("plugins"))
        cve_versions = _merge_unique(extras.get("versions"))
        cve_components = _safe_list(profile.get("components"))
        cve_paths = [
            value for value in cve_components if "/" in value
        ]
        blockers_by_program = _blocker_codes(
            profile, context.get("assets") or []
        )

        # Stage R31.6: deterministic CVE-side identity resolution. The
        # resolver expands the CVE-side product/plugin/component values into
        # the alias set the unchanged R30.1 engine already understands
        # (e.g. ``wordpress_automatic_plugin`` -> ``wordpress-automatic`` and
        # ``automatic``). The R30.1 engine is unmodified; the adapter simply
        # feeds it the resolved value set in addition to the originals.
        identity_resolution = resolve_cve_identities(
            cve_products=cve_products,
            cve_plugins=cve_plugins,
            cve_components=cve_components,
        )
        resolved_products = expanded_cve_value_set(
            identity_resolution.resolutions, "PRODUCT"
        )
        resolved_plugins = expanded_cve_value_set(
            identity_resolution.resolutions, "PLUGIN"
        )
        resolved_components = expanded_cve_value_set(
            identity_resolution.resolutions, "COMPONENT"
        )
        if resolved_products:
            cve_products = _merge_unique(cve_products, resolved_products)
        if resolved_plugins:
            cve_plugins = _merge_unique(cve_plugins, resolved_plugins)
        if resolved_components:
            cve_components = _merge_unique(
                cve_components, resolved_components
            )

        grouped: dict[str, list] = {}
        for record in context.get("assets") or ():
            group = str(getattr(record, "program", "") or "")
            if not group:
                continue
            grouped.setdefault(group, []).append(record)

        for group_name in sorted(grouped):
            if requested_program and group_name != requested_program:
                continue
            records = grouped[group_name]
            observed = _observed_from_assets(records)
            observed["products"] = _merge_unique(
                observed["products"], metadata_observed["products"]
            )
            observed["components"] = _merge_unique(
                observed["components"], metadata_observed["components"]
            )
            observed["plugins"] = _merge_unique(
                observed["plugins"], metadata_observed["plugins"]
            )
            observed["paths"] = _merge_unique(
                observed["paths"], metadata_observed["paths"]
            )
            # Stage R31.5: values already observed from explicit sources
            # (asset records / persisted research metadata) are explicit.
            explicit_component_keys = _normalized_keys(
                observed["components"], normalize_component
            )
            explicit_plugin_keys = _normalized_keys(
                observed["plugins"], normalize_plugin
            )
            # Stage R30.2: merge the derived observed inventory (existing
            # Watch recon data) into the R30.1 matcher INPUT. R30.1 remains the
            # authority for matching semantics; no matching rule is changed.
            inventory_observed = _inventory_values(group_name)
            observed["products"] = _merge_unique(
                observed["products"], inventory_observed.get("products")
            )
            observed["components"] = _merge_unique(
                observed["components"], inventory_observed.get("components")
            )
            observed["plugins"] = _merge_unique(
                observed["plugins"], inventory_observed.get("plugins")
            )
            observed["technologies"] = _merge_unique(
                observed["technologies"],
                inventory_observed.get("technologies"),
            )
            observed_parameters = _merge_unique(
                metadata_observed["parameters"],
                inventory_observed.get("parameters"),
            )
            observed_paths = _merge_unique(
                observed["paths"], inventory_observed.get("paths")
            )
            observed_categories = _merge_unique(
                metadata_observed["categories"]
            )
            # Stage R31.5: classify observed component/plugin evidence and,
            # for inferred-only evidence, scope supporting PARAMETER/PATH
            # input before the unchanged R30.1 engine sees it.
            explicit_component_keys |= _normalized_keys(
                inventory_observed.get("explicit_components"),
                normalize_component,
            )
            explicit_plugin_keys |= _normalized_keys(
                inventory_observed.get("explicit_plugins"),
                normalize_plugin,
            )
            provenance_scopes = _provenance_scopes(inventory_observed)
            parameter_locations = _parameter_locations(inventory_observed)
            support_gate = _support_gate(
                cve_components=cve_components,
                cve_plugins=cve_plugins,
                cve_parameters=profile.get("parameters") or [],
                cve_paths=cve_paths,
                observed_components=observed["components"],
                observed_plugins=observed["plugins"],
                observed_parameters=observed_parameters,
                observed_paths=observed_paths,
                explicit_keys={
                    "component": explicit_component_keys,
                    "plugin": explicit_plugin_keys,
                },
                inferred_keys={
                    "component": _normalized_keys(
                        inventory_observed.get("inferred_components"),
                        normalize_component,
                    ),
                    "plugin": _normalized_keys(
                        inventory_observed.get("inferred_plugins"),
                        normalize_plugin,
                    ),
                },
                provenance_scopes=provenance_scopes,
                parameter_locations=parameter_locations,
            )
            # Stage R30.3: associate observed versions with their explicit
            # owning technology family/component BEFORE the R30.1 version
            # evaluation, so a family-level version match cannot be promoted
            # into a component/plugin match. R30.1 matching rules are
            # unchanged; only the observed-version input is filtered.
            association = evaluate_version_association(
                cve_families=_merge_unique(
                    cve_products, profile.get("technologies") or []
                ),
                cve_components=cve_components,
                cve_plugins=cve_plugins,
                cve_versions=cve_versions,
                observed_versions=_version_association_records(
                    inventory_observed, metadata_observed["versions"]
                ),
                observed_components=observed["components"],
                observed_plugins=observed["plugins"],
            )
            # Stage R31.7: deterministic version normalization/confidence
            # evidence over the exact inputs the R30.1 engine sees. Additive
            # only: parsing never changes what the engine receives or any
            # confidence/state field.
            version_normalization = build_version_evidence(
                cve_versions=cve_versions,
                observed_versions=list(association.engine_versions),
            )
            # Stage R31.8: deterministic path/parameter/method relevance
            # evidence over the same engine-eligible inputs, with R31.5
            # component scopes preserved. Additive only: it never rewrites
            # engine inputs and never changes confidence/state/blockers.
            component_scope_values = tuple(
                sorted(
                    {
                        scope
                        for category in provenance_scopes.values()
                        for scopes_for_value in category.values()
                        for scope in scopes_for_value
                    }
                )
            )
            path_parameter_relevance = (
                evaluate_path_parameter_relevance(
                    research_paths=cve_paths,
                    research_parameters=profile.get("parameters") or [],
                    # No structured HTTP-method field exists in the current
                    # research profile; absent data stays NO_EVIDENCE.
                    research_methods=profile.get("methods") or (),
                    observed_paths=support_gate["paths"],
                    observed_parameters=support_gate["parameters"],
                    parameter_locations=parameter_locations,
                    component_scopes=component_scope_values,
                    max_evidence=MAX_PATH_PARAMETER_EVIDENCE,
                )
            )
            asset_ids = [
                str(getattr(record, "asset", "") or "") for record in records
            ]
            asset_identifier = _asset_identifier(group_name, asset_ids)
            summary = evaluate_inventory(
                cve_id=cve_id,
                program=group_name,
                asset_identifier=asset_identifier,
                cve_products=cve_products,
                cve_components=cve_components,
                cve_plugins=cve_plugins,
                cve_technologies=profile.get("technologies") or [],
                cve_versions=cve_versions,
                cve_parameters=profile.get("parameters") or [],
                cve_paths=cve_paths,
                cve_vulnerability_types=profile.get("vulnerability_types")
                or [],
                observed_products=observed["products"],
                observed_components=observed["components"],
                observed_plugins=observed["plugins"],
                observed_technologies=observed["technologies"],
                observed_versions=list(association.engine_versions),
                observed_parameters=support_gate["parameters"],
                observed_paths=support_gate["paths"],
                observed_categories=observed_categories,
                blocker_codes=blockers_by_program.get(group_name, []),
            )
            # Additive R30.3 context (never a new score and never combined
            # with the R25/R26/R29 projections).
            summary["version_association_state"] = association.state
            summary["version_association_family"] = association.family
            summary["version_association_component"] = association.component
            summary["version_association_reason"] = association.reason
            summary["version_association_evidence"] = list(
                association.evidence
            )
            summary["version_association_rule_version"] = (
                ASSOCIATION_RULE_VERSION
            )
            # Additive R31.5 evidence-provenance context (never a new score).
            summary["evidence_provenance"] = support_gate["provenance"]
            summary["support_scope"] = support_gate["support_scope"]
            summary["withheld_support"] = list(support_gate["withheld"])
            summary["evidence_provenance_rule_version"] = (
                EVIDENCE_PROVENANCE_RULE_VERSION
            )
            # Additive R31.6 identity-resolution context: structured evidence
            # recording which CVE-side identities resolved against which
            # observed identities, never a new score.
            identity_matches = match_observed_identities(
                resolutions=identity_resolution.resolutions,
                observed_components=observed["components"],
                observed_plugins=observed["plugins"],
                observed_products=observed["products"],
            )
            summary["identity_resolution"] = [
                row.to_dict() for row in identity_matches
            ][:MAX_IDENTITY_EVIDENCE]
            summary["identity_resolution_rule_version"] = (
                IDENTITY_RESOLUTION_RULE_VERSION
            )
            # Additive R31.7 version-normalization context: structured,
            # bounded parsing/comparison evidence. Never a score; never alters
            # R30.1 confidence, blockers or the R31.5 support gate.
            summary["version_normalization"] = version_normalization
            summary["version_normalization_rule_version"] = (
                VERSION_NORMALIZATION_RULE_VERSION
            )
            # Additive R31.8 path/parameter relevance context: supporting
            # evidence only. Never a score and never authoritative over
            # component identity, R31.5 scope, R31.7 versions or R30.1 state.
            summary["path_parameter_relevance"] = path_parameter_relevance
            summary["path_parameter_relevance_rule_version"] = (
                PATH_PARAMETER_RELEVANCE_RULE_VERSION
            )
            results.append(summary)

    results.sort(key=lambda item: (item["cve_id"], item["program"]))
    results = results[:MAX_PROGRAMS]
    return {
        "cve": str(cve or "").strip().upper(),
        "program": requested_program,
        "total": len(results),
        "items": results,
        "rule_version": RULE_VERSION,
        "research_only": True,
    }


def get_matches(cve: str) -> list[dict]:
    """All per-program match summaries for one CVE (read-only)."""

    return build_matches(cve=cve)["items"]


def get_match_summary(cve: str, program: Optional[str] = None) -> dict:
    """Aggregate deterministic summary for a CVE (optionally one program)."""

    data = build_matches(cve=cve, program=program)
    items = data["items"]
    states: dict[str, int] = {}
    confidences: dict[str, int] = {}
    for item in items:
        states[item["asset_match_state"]] = (
            states.get(item["asset_match_state"], 0) + 1
        )
        confidences[item["asset_match_confidence"]] = (
            confidences.get(item["asset_match_confidence"], 0) + 1
        )
    strongest = None
    for item in items:
        if item["strongest_match"] is None:
            continue
        if strongest is None or _confidence_rank(
            item["strongest_confidence"]
        ) > _confidence_rank(strongest["strongest_confidence"]):
            strongest = item
    return {
        "cve": data["cve"],
        "program": str(program or "").strip(),
        "total": len(items),
        "states": dict(sorted(states.items())),
        "confidences": dict(sorted(confidences.items())),
        "strongest": strongest,
        "items": items,
        "rule_version": RULE_VERSION,
        "research_only": True,
    }


_CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

# Short-TTL derived cache (read-only; mirrors the existing research_data cache
# convention). Never persisted; cleared by tests.
_PROJECTION_TTL = 10.0
_PROJECTION_CACHE: dict[tuple[str, str], tuple[float, tuple]] = {}


def _confidence_rank(value: str) -> int:
    return _CONFIDENCE_RANK.get(str(value or "").upper(), 0)


def _projection_cached(cve: str, program: str) -> tuple:
    """Cached additive R26/R29 projection (deterministic; fail-soft)."""

    key = (cve, program)
    now = time.monotonic()
    hit = _PROJECTION_CACHE.get(key)
    if hit and (now - hit[0]) < _PROJECTION_TTL:
        return hit[1]
    try:
        data = build_matches(cve=cve, program=program)
    except (OSError, ValueError):
        data = {"items": []}
    items = data.get("items") or []
    if not items:
        values: tuple = ()
    else:
        item = items[0]
        values = (
            str(item.get("asset_match_confidence") or "NONE"),
            str(item.get("asset_match_state") or "UNKNOWN"),
            str(item.get("strongest_match_type") or ""),
            str(item.get("matched_component") or ""),
            str(item.get("matched_version") or ""),
            str(item.get("matched_parameter") or ""),
            tuple(item.get("resolved_blockers") or ()),
            tuple(item.get("remaining_blockers") or ()),
            str(item.get("match_summary") or ""),
        )
    _PROJECTION_CACHE[key] = (now, values)
    return values


def get_projection(cve: str, program: str) -> dict:
    """Additive R26/R29 context fields for one CVE -> program relationship.

    Use only as additional context: never changes the Money Score, R26.1
    opportunity class or R29.1 hunt priority.
    """

    key_cve = str(cve or "").strip().upper()
    key_program = str(program or "").strip()
    if not key_cve or not key_program:
        return {}
    values = _projection_cached(key_cve, key_program)
    if not values:
        return {
            "asset_match_confidence": "NONE",
            "asset_match_state": "UNKNOWN",
            "strongest_match_type": "",
            "matched_component": "",
            "matched_version": "",
            "matched_parameter": "",
            "resolved_blockers": [],
            "remaining_blockers": [],
            "asset_match_reason": "No deterministic asset match.",
        }
    (
        confidence,
        state,
        strongest_type,
        component,
        version,
        parameter,
        resolved,
        remaining,
        reason,
    ) = values
    return {
        "asset_match_confidence": confidence,
        "asset_match_state": state,
        "strongest_match_type": strongest_type,
        "matched_component": component,
        "matched_version": version,
        "matched_parameter": parameter,
        "resolved_blockers": list(resolved),
        "remaining_blockers": list(remaining),
        "asset_match_reason": reason,
    }


def clear_cache() -> None:
    """Test helper: drop the derived projection cache (no persistence)."""

    _PROJECTION_CACHE.clear()


__all__ = [
    "MAX_PROGRAMS",
    "build_matches",
    "get_matches",
    "get_match_summary",
    "get_projection",
    "clear_cache",
]
