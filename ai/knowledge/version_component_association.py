"""Stage R30.3 observed version <-> component association (pure adapter).

R30.1 evaluates a CVE version range against *any* observed version. That is
safe only when the observed version is known to belong to the same
technology/product/component family the CVE affects. A bare
``WordPress:6.8.3`` observation is not evidence that a ``WordPress plugin
XYZ`` at version 1.2.3 is installed.

This module associates each observed version with its explicit owning
technology family (and, only when a structured source establishes it, its
owning component/plugin) deterministically *before* R30.1 matching, then
classifies the version evidence into a closed vocabulary. The key R30.3
distinction is:

- ``VERSION_MATCH_WITHIN_SAME_FAMILY``: the observed version belongs to the
  same family and (when the CVE targets one) the same component/plugin the
  CVE affects. Existing R30.1 component/version semantics may combine.
- ``VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION``: a version matched the
  affected range but its owning component is not established. The observation
  is retained as technology-level evidence but is deliberately **not** passed
  into the R30.1 version matcher when the CVE targets a component/plugin, so
  it can never be promoted into a component/plugin match.

The module is pure and offline: no I/O, no network, no DNS, no LLM, no
subprocess, no browser, no Nuclei, no target interaction, no persistence. It
never invents a component/plugin owner: when no structured source exists the
association is *unavailable* and reported as such. Nothing here is a
vulnerability verdict; it is research relevance only.

R30.3 is additive: it does not change R17, R18, R25, R26, R29 or the R30.1
matching engine (``ai/knowledge/asset_cve_matching.py`` is untouched).
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.correlator.technology import normalize as normalize_technology
from ai.knowledge.asset_cve_matching import (
    evaluate_version,
    match_component,
    match_plugin,
    match_product,
    match_technology,
    normalize_version,
)
from ai.schemas.observed_inventory import (
    VERSION_ASSOCIATION_RULE_VERSION,
    ObservedVersionAssociation,
)

RULE_VERSION = VERSION_ASSOCIATION_RULE_VERSION

# Closed association-state vocabulary. Every state is a statement about the
# *version evidence only* -- never a vulnerability verdict and never a new
# global score.
VERSION_ASSOCIATION_STATES: tuple[str, ...] = (
    "VERSION_MATCH_WITHIN_SAME_FAMILY",
    "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION",
    "COMPONENT_ASSOCIATED_VERSION_UNKNOWN",
    "VERSION_OBSERVED_NO_MATCH",
    "FAMILY_MISMATCH",
    "VERSION_ASSOCIATION_UNKNOWN",
    "NO_VERSION_OBSERVATION",
)

_COMPONENT_GROUP = "component"
_FAMILY_GROUP = "family"
_MISMATCH_GROUP = "mismatch"
_UNKNOWN_GROUP = "unknown"


@dataclass(frozen=True)
class VersionAssociationResult:
    """Deterministic R30.3 association of one CVE to observed version data.

    ``engine_versions`` is the version evidence the R30.1 engine may evaluate
    for this CVE. It is intentionally empty for
    ``VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION`` so a family-level version
    can never combine with a component/plugin match into a false HIGH match.
    """

    state: str
    engine_versions: tuple[str, ...] = ()
    matched_version: str = ""
    matched_spec: str = ""
    family: str = ""
    component: str = ""
    component_available: bool = False
    evidence: tuple[str, ...] = ()
    reason: str = ""
    rule_version: str = RULE_VERSION
    research_only: bool = True


# ---------------------------------------------------------------------------
# Coercion (fail-soft; malformed records are skipped, never guessed)
# ---------------------------------------------------------------------------


def _coerce_record(record: object) -> ObservedVersionAssociation | None:
    if record is None:
        return None
    if isinstance(record, ObservedVersionAssociation):
        return record
    if isinstance(record, dict):
        version = record.get("version") or record.get("value")
        family = record.get("technology_family") or record.get("family")
        component = record.get("component")
        source = record.get("source") or "TECHNOLOGY_INVENTORY"
        evidence_type = (
            record.get("evidence_type") or "STRUCTURED_TECHNOLOGY"
        )
    else:
        version = getattr(record, "version", None) or getattr(
            record, "value", None
        )
        family = getattr(record, "technology_family", "") or getattr(
            record, "family", ""
        )
        component = getattr(record, "component", "")
        source = getattr(record, "source", None) or "TECHNOLOGY_INVENTORY"
        evidence_type = (
            getattr(record, "evidence_type", None)
            or "STRUCTURED_TECHNOLOGY"
        )
    try:
        return ObservedVersionAssociation(
            version=str(version or ""),
            technology_family=str(family or ""),
            component=str(component or ""),
            source=str(source),
            evidence_type=str(evidence_type),
        )
    except ValueError:
        return None


def coerce_associations(records: object) -> list[ObservedVersionAssociation]:
    """Deterministic, deduplicated, sorted association record list.

    Accepts schema models, serialized dicts (``version`` or ``value`` key) and
    duck-typed objects. Malformed records are skipped (fail-soft).
    """

    items: list[ObservedVersionAssociation] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for record in records or ():
        item = _coerce_record(record)
        if item is None:
            continue
        key = (
            normalize_version(item.version),
            normalize_technology(item.technology_family),
            normalize_technology(item.component),
            item.source,
            item.evidence_type,
        )
        if not key[0] or key in seen:
            continue
        seen.add(key)
        items.append(item)
    return sorted(
        items,
        key=lambda item: (
            normalize_version(item.version),
            normalize_technology(item.technology_family),
            normalize_technology(item.component),
            item.source,
            item.evidence_type,
        ),
    )


# ---------------------------------------------------------------------------
# Deterministic matching helpers (reuse the R30.1 normalizers/matchers)
# ---------------------------------------------------------------------------


def _values(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)):
        raw = [raw]
    out: list[str] = []
    for item in raw or ():
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
        if len(out) >= 256:
            break
    return out


def _family_match(family: str, cve_families: list[str]):
    """Same-family detection using the R30.1 product/technology matchers."""

    if not family or not cve_families:
        return None
    return match_product(cve_families, [family]) or match_technology(
        cve_families, [family]
    )


def _component_match(
    component: str, cve_components: list[str], cve_plugins: list[str]
):
    """Same-component detection using the R30.1 component/plugin matchers."""

    if not component:
        return None
    return match_component(cve_components, [component]) or match_plugin(
        cve_plugins, [component]
    )


def _observed_component_match(
    cve_components: list[str],
    cve_plugins: list[str],
    observed_components: list[str],
    observed_plugins: list[str],
) -> bool:
    return (
        match_component(cve_components, observed_components) is not None
        or match_plugin(cve_plugins, observed_plugins) is not None
    )


def _owner_for_version(
    records: list[ObservedVersionAssociation], version: str
) -> ObservedVersionAssociation | None:
    key = normalize_version(version)
    for record in records:
        if normalize_version(record.version) == key:
            return record
    return None


def _result(
    state: str,
    *,
    engine_versions: object = (),
    matched_version: str = "",
    matched_spec: str = "",
    family: str = "",
    component: str = "",
    component_available: bool = False,
    evidence: object = (),
    reason: str = "",
) -> VersionAssociationResult:
    return VersionAssociationResult(
        state=state,
        engine_versions=tuple(engine_versions),
        matched_version=matched_version,
        matched_spec=matched_spec,
        family=family,
        component=component,
        component_available=component_available,
        evidence=tuple(evidence),
        reason=reason,
    )


def _owner_evidence(
    version: str, family: str = "", component: str = ""
) -> tuple[str, ...]:
    return (
        f"observed version: {version}",
        f"observed technology family: {family or 'unavailable'}",
        (
            f"observed component: {component}"
            if component
            else "observed component: unavailable"
        ),
    )


def _no_match_result(
    evaluation: dict, records: list[ObservedVersionAssociation]
) -> VersionAssociationResult:
    version = str(evaluation.get("observed_version") or "")
    spec = str(evaluation.get("spec") or "")
    owner = _owner_for_version(records, version) if version else None
    return _result(
        "VERSION_OBSERVED_NO_MATCH",
        engine_versions=(),
        matched_version=version,
        matched_spec=spec,
        family=owner.technology_family if owner else "",
        component="",
        component_available=False,
        evidence=(
            *_owner_evidence(
                version, owner.technology_family if owner else ""
            ),
            f"cve affected range: {spec}",
            "association: observed version does not satisfy the range",
        ),
        reason=(
            f"observed version {version or 'unavailable'} does not satisfy "
            f"{spec or 'the affected range'}"
        ),
    )


def _family_mismatch_result(
    records: list[ObservedVersionAssociation],
) -> VersionAssociationResult:
    owners = sorted(
        {
            normalize_technology(record.technology_family)
            for record in records
            if record.technology_family
        }
    )
    return _result(
        "FAMILY_MISMATCH",
        engine_versions=(),
        evidence=tuple(
            f"observed technology family: {owner}" for owner in owners
        ) + (
            "association: no observed version belongs to the CVE product/"
            "component family",
        ),
        reason=(
            "observed version family "
            f"{', '.join(owners) or 'unavailable'} does not match the CVE "
            "product/component family"
        ),
    )


def _component_version_unknown_result(
    reason: str,
) -> VersionAssociationResult:
    return _result(
        "COMPONENT_ASSOCIATED_VERSION_UNKNOWN",
        engine_versions=(),
        component_available=True,
        evidence=(
            "observed component: matches the affected component/plugin",
            "observed version: unavailable",
            "association: component evidence retained; version evidence not "
            "combined",
        ),
        reason=reason,
    )


def _association_unknown_result(
    records: list[ObservedVersionAssociation],
) -> VersionAssociationResult:
    return _result(
        "VERSION_ASSOCIATION_UNKNOWN",
        engine_versions=(),
        evidence=tuple(
            f"observed version: {record.version}" for record in records
        ) + (
            "association: owning technology family/component could not be "
            "established deterministically",
        ),
        reason=(
            "observed version evidence exists but its owning technology "
            "family/component is not established; no component inference"
        ),
    )


def _no_version_result() -> VersionAssociationResult:
    return _result(
        "NO_VERSION_OBSERVATION",
        engine_versions=(),
        evidence=("observed version: unavailable",),
        reason="no observed version evidence for this CVE/program",
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_version_association(
    *,
    cve_families: object = (),
    cve_components: object = (),
    cve_plugins: object = (),
    cve_versions: object = (),
    observed_versions: object = (),
    observed_components: object = (),
    observed_plugins: object = (),
) -> VersionAssociationResult:
    """Associate observed versions with the CVE's family/component (pure).

    ``cve_families`` are the CVE product/technology names (the owning
    technology family candidates); ``cve_components`` / ``cve_plugins`` are
    the affected component/plugin names. ``observed_versions`` are R30.3
    association records (version + explicit owner). Component ownership is
    never inferred: a record without a component reports the component as
    unavailable.
    """

    families = _values(cve_families)
    components = _values(cve_components)
    plugins = _values(cve_plugins)
    specs = _values(cve_versions)
    records = coerce_associations(observed_versions)

    has_component_target = bool(components or plugins)
    cve_has_family = bool(families)

    groups: dict[str, list[ObservedVersionAssociation]] = {
        _COMPONENT_GROUP: [],
        _FAMILY_GROUP: [],
        _MISMATCH_GROUP: [],
        _UNKNOWN_GROUP: [],
    }
    for record in records:
        if _component_match(record.component, components, plugins):
            groups[_COMPONENT_GROUP].append(record)
        elif record.technology_family and cve_has_family:
            if _family_match(record.technology_family, families):
                groups[_FAMILY_GROUP].append(record)
            else:
                groups[_MISMATCH_GROUP].append(record)
        else:
            groups[_UNKNOWN_GROUP].append(record)

    def _evaluate(group: str) -> dict:
        return evaluate_version(
            specs, [record.version for record in groups[group]]
        )

    component_eval = _evaluate(_COMPONENT_GROUP)
    family_eval = _evaluate(_FAMILY_GROUP)
    unknown_eval = _evaluate(_UNKNOWN_GROUP)
    component_observed = _observed_component_match(
        components, plugins, _values(observed_components),
        _values(observed_plugins),
    )

    if has_component_target:
        # 1. Version explicitly owned by the affected component/plugin.
        if component_eval["state"] == "MATCH":
            version = component_eval["observed_version"]
            owner = _owner_for_version(
                groups[_COMPONENT_GROUP], version
            ) or groups[_COMPONENT_GROUP][0]
            return _result(
                "VERSION_MATCH_WITHIN_SAME_FAMILY",
                engine_versions=[
                    record.version for record in groups[_COMPONENT_GROUP]
                ],
                matched_version=version,
                matched_spec=component_eval["spec"],
                family=owner.technology_family,
                component=owner.component,
                component_available=True,
                evidence=(
                    *_owner_evidence(
                        version, owner.technology_family, owner.component
                    ),
                    f"cve affected range: {component_eval['spec']}",
                    "association: observed version belongs to the affected "
                    "component/plugin and family",
                ),
                reason=(
                    f"version {version} is associated with observed component "
                    f"{owner.component}; component/version evidence allowed"
                ),
            )
        # 2. Version owned by the same family but not by the component.
        if family_eval["state"] == "MATCH":
            version = family_eval["observed_version"]
            owner = _owner_for_version(groups[_FAMILY_GROUP], version)
            return _result(
                "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION",
                engine_versions=(),
                matched_version=version,
                matched_spec=family_eval["spec"],
                family=owner.technology_family if owner else "",
                component="",
                component_available=False,
                evidence=(
                    *_owner_evidence(
                        version, owner.technology_family if owner else ""
                    ),
                    f"cve affected range: {family_eval['spec']}",
                    "association: same technology family, but no structured "
                    "component/plugin version evidence",
                ),
                reason=(
                    f"version {version} belongs to the same technology family "
                    "but not to the affected component/plugin; component "
                    "match not inferred"
                ),
            )
        # 3. Version with no established owner (family/component unavailable).
        if unknown_eval["state"] == "MATCH":
            version = unknown_eval["observed_version"]
            owner = _owner_for_version(groups[_UNKNOWN_GROUP], version)
            return _result(
                "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION",
                engine_versions=(),
                matched_version=version,
                matched_spec=unknown_eval["spec"],
                family=owner.technology_family if owner else "",
                component="",
                component_available=False,
                evidence=(
                    *_owner_evidence(
                        version, owner.technology_family if owner else ""
                    ),
                    f"cve affected range: {unknown_eval['spec']}",
                    "association: owning component unavailable; component "
                    "match not inferred",
                ),
                reason=(
                    f"version {version} satisfies {unknown_eval['spec']} but "
                    "no observed component owns it; component match not "
                    "inferred"
                ),
            )
        # 4. No safe version association: report the most specific state.
        if groups[_COMPONENT_GROUP] and component_eval["state"] == "NO_MATCH":
            return _no_match_result(
                component_eval, groups[_COMPONENT_GROUP]
            )
        if groups[_FAMILY_GROUP] and family_eval["state"] == "NO_MATCH":
            return _no_match_result(family_eval, groups[_FAMILY_GROUP])
        if groups[_UNKNOWN_GROUP] and unknown_eval["state"] == "NO_MATCH":
            return _no_match_result(unknown_eval, groups[_UNKNOWN_GROUP])
        if groups[_MISMATCH_GROUP]:
            return _family_mismatch_result(groups[_MISMATCH_GROUP])
        if groups[_COMPONENT_GROUP] or component_observed:
            return _component_version_unknown_result(
                "affected component/plugin observed but no comparable version "
                "evidence exists"
            )
        if groups[_FAMILY_GROUP] or groups[_UNKNOWN_GROUP]:
            return _association_unknown_result(
                groups[_FAMILY_GROUP] + groups[_UNKNOWN_GROUP]
            )
        return _no_version_result()

    # CVE has no component/plugin target: family-level association decides.
    if groups[_FAMILY_GROUP]:
        if family_eval["state"] == "MATCH":
            version = family_eval["observed_version"]
            owner = _owner_for_version(groups[_FAMILY_GROUP], version)
            return _result(
                "VERSION_MATCH_WITHIN_SAME_FAMILY",
                engine_versions=[
                    record.version for record in groups[_FAMILY_GROUP]
                ],
                matched_version=version,
                matched_spec=family_eval["spec"],
                family=owner.technology_family if owner else "",
                component="",
                component_available=False,
                evidence=(
                    *_owner_evidence(
                        version, owner.technology_family if owner else ""
                    ),
                    f"cve affected range: {family_eval['spec']}",
                    "association: observed version belongs to the affected "
                    "technology family",
                ),
                reason=(
                    f"version {version} belongs to the affected technology "
                    "family; family/version evidence allowed"
                ),
            )
        if family_eval["state"] == "NO_MATCH":
            return _no_match_result(family_eval, groups[_FAMILY_GROUP])
    if groups[_UNKNOWN_GROUP]:
        if unknown_eval["state"] == "MATCH":
            version = unknown_eval["observed_version"]
            owner = _owner_for_version(groups[_UNKNOWN_GROUP], version)
            return _result(
                "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION",
                engine_versions=[
                    record.version for record in groups[_UNKNOWN_GROUP]
                ],
                matched_version=version,
                matched_spec=unknown_eval["spec"],
                family=owner.technology_family if owner else "",
                component="",
                component_available=False,
                evidence=(
                    *_owner_evidence(
                        version, owner.technology_family if owner else ""
                    ),
                    f"cve affected range: {unknown_eval['spec']}",
                    "association: owning family/component unavailable; "
                    "technology-level version evidence retained",
                ),
                reason=(
                    f"version {version} satisfies {unknown_eval['spec']} "
                    "without an established owning family/component"
                ),
            )
        if unknown_eval["state"] == "NO_MATCH":
            return _no_match_result(unknown_eval, groups[_UNKNOWN_GROUP])
    if groups[_MISMATCH_GROUP]:
        return _family_mismatch_result(groups[_MISMATCH_GROUP])
    if groups[_FAMILY_GROUP] or groups[_UNKNOWN_GROUP]:
        return _association_unknown_result(
            groups[_FAMILY_GROUP] + groups[_UNKNOWN_GROUP]
        )
    return _no_version_result()


def association_projection(result: VersionAssociationResult) -> dict:
    """Serialize one association result deterministically."""

    return {
        "state": result.state,
        "engine_versions": list(result.engine_versions),
        "matched_version": result.matched_version,
        "matched_spec": result.matched_spec,
        "family": result.family,
        "component": result.component,
        "component_available": result.component_available,
        "evidence": list(result.evidence),
        "reason": result.reason,
        "rule_version": result.rule_version,
        "research_only": result.research_only,
    }


__all__ = [
    "RULE_VERSION",
    "VERSION_ASSOCIATION_STATES",
    "VersionAssociationResult",
    "coerce_associations",
    "evaluate_version_association",
    "association_projection",
]
