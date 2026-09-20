"""Deterministic component binding evidence (evaluation only).

Pipeline position: Watchlist Snapshot -> Delta Intelligence -> Evidence Gap
Analysis -> Evidence Acquisition Plan -> Controlled Evidence Acquisition ->
**Component Binding Evidence** -> Candidate Finding.

This layer answers exactly one question:

    Does the supplied structured Watch evidence deterministically bind the
    observed asset to a specific software component?

It never discovers components, never guesses components, never scans, and
never performs network activity. It only evaluates supplied evidence records
against the existing Watch contracts.

Evidence-backed, not name-backed. A binding is only produced when a supplied
record explicitly ties a component to the target asset through an existing
Watch contract:

- ``COMPONENT_PROVENANCE`` records (R31.5 ``ObservedProvenance`` shape):
  an inferred component/plugin value with its canonical evidence path,
  owning directory scope, rule id and ``COMPONENT_INVENTORY`` source,
  scoped to the target asset's path scope.
- ``ASSET_MATCH`` records (R30.1 ``AssetCVEMatch`` shape): a COMPONENT or
  PLUGIN match row with an explicit ``asset_identifier`` equal to the
  target asset, an inventory source, and a non-empty ``evidence`` list.

Never accepted as component evidence (name-backed inference is forbidden):

- hostnames, URL paths/filenames, query parameters, WordPress technology
  detection, generic page content, CVE description/affected-product text,
  component names observed elsewhere in the same program inventory,
  family-level version associations, versions without asset ownership,
  temporal proximity, hostname/domain patterns.

States: ``BOUND`` / ``UNBOUND`` / ``INSUFFICIENT_EVIDENCE`` /
``CONFLICTING_EVIDENCE``. Conflicts between two distinct components are
never resolved, ranked or guessed. BOUND always carries non-empty evidence
references. Deterministic: identical input -> identical output; no
timestamps, randomness, network or environment state; stable ordering.

Integration: ``apply_binding_to_candidate`` lets the existing evidence-gap
layer consume a BOUND binding as component evidence (component identity only;
version identity remains a separate requirement and is never inferred from a
component binding).
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from ai.knowledge.component_identity import normalize_identity
from ai.research_agent.watchlist_evidence_gaps import analyze_candidate

RULE_VERSION = "watchlist-component-binding-1"

# ---------------------------------------------------------------------------
# Result states
# ---------------------------------------------------------------------------

BOUND = "BOUND"
UNBOUND = "UNBOUND"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"

STATES: tuple[str, ...] = (
    BOUND,
    UNBOUND,
    INSUFFICIENT_EVIDENCE,
    CONFLICTING_EVIDENCE,
)

# ---------------------------------------------------------------------------
# Binding rules (existing Watch contracts only; auditable)
# ---------------------------------------------------------------------------

RULE_ASSET_COMPONENT_PROVENANCE = "cb-r1-asset-component-provenance"
RULE_ASSET_COMPONENT_MATCH = "cb-r2-asset-component-match"

KIND_COMPONENT_PROVENANCE = "COMPONENT_PROVENANCE"
KIND_ASSET_MATCH = "ASSET_MATCH"

EVIDENCE_KINDS: tuple[str, ...] = (KIND_COMPONENT_PROVENANCE, KIND_ASSET_MATCH)

#: Auditable rule registry: id, evidence kind, prerequisites, binding logic,
#: and the provenance requirement for each rule.
RULES: tuple[dict, ...] = (
    {
        "rule_id": RULE_ASSET_COMPONENT_PROVENANCE,
        "evidence_kind": KIND_COMPONENT_PROVENANCE,
        "source_contract": "ai.schemas.observed_inventory.ObservedProvenance (R31.5)",
        "prerequisites": [
            "category in {COMPONENT, PLUGIN}",
            "non-empty value (the component identity)",
            "non-empty evidence_path (canonical evidence path)",
            "evidence_type in {INFERRED_COMPONENT, INFERRED_PLUGIN}",
            "source == COMPONENT_INVENTORY",
            "scope_path (or evidence_path) inside the target asset scope",
        ],
        "binding_logic": (
            "the inferred component's owning directory scope is inside the "
            "target asset's path scope, so the component is bound to that "
            "observed asset surface"
        ),
        "provenance_requirement": (
            "the record itself carries the canonical evidence path, scope, "
            "rule id and inventory source; those become the binding refs"
        ),
    },
    {
        "rule_id": RULE_ASSET_COMPONENT_MATCH,
        "evidence_kind": KIND_ASSET_MATCH,
        "source_contract": "ai.schemas.asset_cve_match.AssetCVEMatch (R30.1)",
        "prerequisites": [
            "match_type in {COMPONENT, PLUGIN}",
            "non-empty matched_value (the component identity)",
            "source in {COMPONENT_INVENTORY, ASSET_INVENTORY}",
            "asset_identifier explicitly equal to the target asset",
            "non-empty evidence list (match provenance)",
        ],
        "binding_logic": (
            "the existing matcher row explicitly identifies the component "
            "for the same privacy-preserving asset identifier"
        ),
        "provenance_requirement": (
            "the row's deterministic match_id plus its evidence list become "
            "the binding refs; CVE-mined metadata is never sufficient"
        ),
    },
)

_BINDING_MATCH_TYPES = frozenset({"COMPONENT", "PLUGIN"})
_BINDING_SOURCES = frozenset({"COMPONENT_INVENTORY", "ASSET_INVENTORY"})
_PROVENANCE_CATEGORIES = frozenset({"COMPONENT", "PLUGIN"})
_PROVENANCE_SOURCES = frozenset({"COMPONENT_INVENTORY"})
_PROVENANCE_EVIDENCE_TYPES = frozenset(
    {"INFERRED_COMPONENT", "INFERRED_PLUGIN"}
)

_ASSET_ID_RE = re.compile(r"^asset-[0-9a-f]{16}$")
_MATCH_ID_RE = re.compile(r"^am-[0-9a-f]{16}$")

#: Rejection reasons that mean "binding evidence exists but for another
#: asset/scope" (-> UNBOUND rather than INSUFFICIENT_EVIDENCE).
_ELSEWHERE_REASONS = frozenset(
    {"ASSET_IDENTITY_MISMATCH", "SCOPE_MISMATCH"}
)

_REEVALUATION_NOTE = (
    "a BOUND component binding is consumed as component identity evidence "
    "only; version identity remains a separate evidence requirement and is "
    "never inferred from the component binding"
)


# ---------------------------------------------------------------------------
# Deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def _path_key(value: object) -> str:
    """Path-only key (no scheme/host/query/fragment)."""

    text = str(value if value is not None else "").strip()
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


def _normalize_component(value: str) -> str:
    normalized = normalize_identity(value)
    return normalized or _text(value).lower()


def _evidence_ref(record: Mapping) -> str:
    match_id = _text(record.get("match_id"))
    if _MATCH_ID_RE.match(match_id):
        return match_id
    basis = {
        key: record.get(key)
        for key in (
            "kind",
            "match_id",
            "match_type",
            "matched_value",
            "source",
            "asset_identifier",
            "category",
            "value",
            "evidence_type",
            "evidence_path",
            "scope_path",
            "rule_id",
            "version",
            "technology_family",
            "component",
        )
        if key in record
    }
    digest = hashlib.sha256(_canonical(basis).encode("utf-8")).hexdigest()[:16]
    return "bref-" + digest


def _asset_block(asset: Mapping | None) -> dict:
    block: Mapping = asset if isinstance(asset, Mapping) else {}
    asset_id = _text(block.get("asset_identifier"))
    scopes = block.get("scope_paths")
    scope_paths: list[str] = []
    if isinstance(scopes, (list, tuple)):
        for item in scopes:
            key = _path_key(item)
            if key and key not in scope_paths:
                scope_paths.append(key)
    return {
        "asset_identifier": asset_id,
        "scope_paths": sorted(scope_paths),
    }


def _binding(
    *,
    component: str,
    category: str,
    rule_id: str,
    ref: str,
    kind: str,
    source: str,
    detail: str,
) -> dict:
    return {
        "component": component,
        "component_normalized": _normalize_component(component),
        "component_category": category,
        "rule_id": rule_id,
        "evidence_ref": ref,
        "evidence_kind": kind,
        "source": source,
        "detail": detail,
    }


def _rejection(ref: str, reason: str, detail: str) -> dict:
    return {"evidence_ref": ref, "reason": reason, "detail": detail}


# ---------------------------------------------------------------------------
# Per-record evaluation
# ---------------------------------------------------------------------------


def _classify_kind(record: Mapping) -> str:
    kind = _upper(record.get("kind") or record.get("evidence_kind"))
    if kind in EVIDENCE_KINDS:
        return kind
    if "match_type" in record or "matched_value" in record:
        return KIND_ASSET_MATCH
    if "category" in record or "evidence_path" in record:
        return KIND_COMPONENT_PROVENANCE
    return ""


def _evaluate_record(record: object, asset: Mapping) -> tuple[str, dict]:
    if not isinstance(record, Mapping):
        return "rejected", _rejection(
            "bref-invalid", "MALFORMED_RECORD", "record is not a mapping"
        )
    ref = _evidence_ref(record)
    kind = _classify_kind(record)

    # Version associations (R30.3) never bind: they carry no asset identity
    # and a technology-derived association may legitimately have
    # component="" by design. Never transformed into ownership.
    if not kind and (
        "version" in record or "technology_family" in record
    ):
        return "rejected", _rejection(
            ref,
            "VERSION_ASSOCIATION_IS_NOT_ASSET_BOUND",
            "version associations carry no asset identity; ownership is "
            "never inferred from a version association",
        )

    if kind == KIND_ASSET_MATCH:
        return _evaluate_asset_match(record, asset, ref)
    if kind == KIND_COMPONENT_PROVENANCE:
        return _evaluate_provenance(record, asset, ref)
    return "rejected", _rejection(
        ref,
        "UNKNOWN_EVIDENCE_KIND",
        "record kind is not part of the supported evidence vocabulary",
    )


def _evaluate_asset_match(
    record: Mapping, asset: Mapping, ref: str
) -> tuple[str, dict]:
    match_type = _upper(record.get("match_type"))
    value = _text(record.get("matched_value"))
    source = _upper(record.get("source"))

    if match_type not in _BINDING_MATCH_TYPES:
        reason = (
            "TECHNOLOGY_IS_NOT_COMPONENT_EVIDENCE"
            if match_type == "TECHNOLOGY"
            else "UNSUPPORTED_MATCH_TYPE"
        )
        return "rejected", _rejection(
            ref,
            reason,
            "only COMPONENT/PLUGIN match rows are component-binding evidence",
        )
    if not value:
        return "rejected", _rejection(
            ref, "MISSING_COMPONENT_VALUE", "match row carries no component value"
        )
    if source == "CVE_METADATA":
        return "rejected", _rejection(
            ref,
            "CVE_METADATA_IS_NOT_COMPONENT_EVIDENCE",
            "CVE description/affected-product text is never component evidence",
        )
    if source not in _BINDING_SOURCES:
        return "rejected", _rejection(
            ref,
            "UNSUPPORTED_SOURCE",
            "match row source is not an asset/component inventory source",
        )

    target_id = _text(asset.get("asset_identifier"))
    record_id = _text(record.get("asset_identifier"))
    if not target_id:
        return "rejected", _rejection(
            ref,
            "TARGET_ASSET_UNIDENTIFIED",
            "the target asset has no explicit identity to bind against",
        )
    if not record_id:
        return "rejected", _rejection(
            ref,
            "MISSING_ASSET_IDENTITY",
            "match row carries no explicit asset identity",
        )
    if record_id != target_id:
        return "rejected", _rejection(
            ref,
            "ASSET_IDENTITY_MISMATCH",
            "match row identifies a different asset",
        )

    evidence_list = record.get("evidence")
    usable_evidence = [
        _text(item) for item in evidence_list
    ] if isinstance(evidence_list, (list, tuple)) else []
    if not any(usable_evidence):
        return "rejected", _rejection(
            ref,
            "MISSING_PROVENANCE",
            "match row carries no provenance evidence list",
        )

    return "binding", _binding(
        component=value,
        category=match_type,
        rule_id=RULE_ASSET_COMPONENT_MATCH,
        ref=ref,
        kind=KIND_ASSET_MATCH,
        source=source,
        detail=(
            f"explicit {match_type} match row for the target asset with "
            f"{len(usable_evidence)} provenance entr(ies)"
        ),
    )


def _evaluate_provenance(
    record: Mapping, asset: Mapping, ref: str
) -> tuple[str, dict]:
    category = _upper(record.get("category"))
    value = _text(record.get("value"))
    evidence_type = _upper(record.get("evidence_type"))
    source = _upper(record.get("source") or "COMPONENT_INVENTORY")
    evidence_path = _path_key(record.get("evidence_path"))
    scope_path = _path_key(record.get("scope_path")) or evidence_path

    if category not in _PROVENANCE_CATEGORIES:
        return "rejected", _rejection(
            ref,
            "UNSUPPORTED_CATEGORY",
            "provenance category must be COMPONENT or PLUGIN",
        )
    if not value:
        return "rejected", _rejection(
            ref,
            "MISSING_COMPONENT_VALUE",
            "provenance record carries no component value",
        )
    if not evidence_path:
        return "rejected", _rejection(
            ref,
            "MISSING_PROVENANCE",
            "provenance record carries no canonical evidence path",
        )
    if source not in _PROVENANCE_SOURCES:
        return "rejected", _rejection(
            ref,
            "UNSUPPORTED_SOURCE",
            "provenance source is not the component inventory",
        )
    if evidence_type not in _PROVENANCE_EVIDENCE_TYPES:
        return "rejected", _rejection(
            ref,
            "UNSUPPORTED_EVIDENCE_TYPE",
            "provenance must come from a deterministic inferred component/"
            "plugin rule",
        )

    scope_paths = asset.get("scope_paths") or []
    if not scope_paths:
        return "rejected", _rejection(
            ref,
            "TARGET_ASSET_UNIDENTIFIED",
            "the target asset has no explicit scope to bind against",
        )
    if not any(_in_scope(scope_path, scope) for scope in scope_paths):
        return "rejected", _rejection(
            ref,
            "SCOPE_MISMATCH",
            "provenance scope is outside the target asset scope",
        )

    return "binding", _binding(
        component=value,
        category=category,
        rule_id=RULE_ASSET_COMPONENT_PROVENANCE,
        ref=ref,
        kind=KIND_COMPONENT_PROVENANCE,
        source=source,
        detail=(
            f"inferred {category} provenance scope {scope_path} is inside "
            "the target asset scope"
        ),
    )


# ---------------------------------------------------------------------------
# Public evaluation API
# ---------------------------------------------------------------------------


def evaluate_component_binding(
    *,
    cve_id: str = "",
    program: str = "",
    asset: Mapping | None = None,
    evidence: Iterable[object] | None = None,
) -> dict:
    """Evaluate whether supplied evidence binds a component to the asset.

    Pure, deterministic and read-only. Never mutates the supplied evidence.
    Returns the binding result with non-empty evidence references for BOUND
    and an explicit explanation for every unresolved state.
    """

    asset_block = _asset_block(asset)
    records = list(evidence) if evidence is not None else []

    bindings: list[dict] = []
    rejected: list[dict] = []
    elsewhere = False
    for record in records:
        outcome, payload = _evaluate_record(record, asset_block)
        if outcome == "binding":
            bindings.append(payload)
        else:
            rejected.append(payload)
            if payload["reason"] in _ELSEWHERE_REASONS:
                elsewhere = True

    groups: dict[str, list[dict]] = {}
    for item in bindings:
        key = item["component_normalized"] or item["component"].lower()
        groups.setdefault(key, []).append(item)

    state = INSUFFICIENT_EVIDENCE
    component = ""
    component_category = ""
    rule_id = ""
    explanation = ""
    candidate_components: list[dict] = []
    refs: list[dict] = []

    if bindings and len(groups) == 1:
        state = BOUND
        first = bindings[0]
        component = first["component"]
        component_category = first["component_category"]
        rule_id = first["rule_id"]
        refs = sorted(bindings, key=lambda item: (item["evidence_ref"],))
        explanation = (
            f"component {component!r} is deterministically bound to the "
            f"target asset by rule {rule_id} with {len(refs)} evidence "
            "reference(s)"
        )
    elif bindings:
        state = CONFLICTING_EVIDENCE
        candidate_components = sorted(
            (
                {
                    "component": items[0]["component"],
                    "component_category": items[0]["component_category"],
                    "evidence_refs": sorted(
                        item["evidence_ref"] for item in items
                    ),
                }
                for items in groups.values()
            ),
            key=lambda item: (
                item["component"].lower(),
                item["component_category"],
            ),
        )
        explanation = (
            "supplied evidence independently identifies "
            f"{len(candidate_components)} different components for the same "
            "asset; conflicts are never resolved, ranked or guessed"
        )
    elif elsewhere:
        state = UNBOUND
        explanation = (
            "component-binding evidence exists but references a different "
            "asset or scope; no component is bound to the target asset"
        )
    else:
        explanation = (
            "no component-binding evidence references the target asset; "
            "component identity remains unresolved"
        )

    return {
        "rule_version": RULE_VERSION,
        "cve_id": _upper(cve_id),
        "program": _text(program),
        "asset": asset_block,
        "state": state,
        "component": component,
        "component_category": component_category,
        "normalized_component": (
            _normalize_component(component) if component else ""
        ),
        "rule_id": rule_id,
        "evidence_refs": refs,
        "evidence_ref_count": len(refs),
        "candidate_components": candidate_components,
        "rejected": sorted(
            rejected, key=lambda item: (item["evidence_ref"], item["reason"])
        ),
        "explanation": explanation,
        "binding_rule_ids": [rule["rule_id"] for rule in RULES],
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


# ---------------------------------------------------------------------------
# Evidence gap integration (additive; inputs are never mutated)
# ---------------------------------------------------------------------------


def apply_binding_to_candidate(
    candidate: Mapping | None, binding: Mapping | None
) -> dict:
    """Return a candidate copy with the binding attached (additive).

    For BOUND bindings the component identity is projected into the
    candidate's ``matched_component`` and one provenance row derived from the
    binding evidence refs is appended, so the existing gap layer can consume
    it. Version identity is never touched. Nothing is applied for unresolved
    states, and an existing different component identity is never overwritten
    (``EXISTING_COMPONENT_CONFLICT``).
    """

    base: Mapping = candidate if isinstance(candidate, Mapping) else {}
    result: Mapping = binding if isinstance(binding, Mapping) else {}
    updated = copy.deepcopy(dict(base))

    state = _upper(result.get("state"))
    component = _text(result.get("component"))
    category = _upper(result.get("component_category")) or "COMPONENT"
    rule_id = _text(result.get("rule_id"))
    records = result.get("evidence_refs")
    refs = [dict(item) for item in records] if isinstance(records, list) else []

    block = {
        "state": state,
        "component": component,
        "component_category": category,
        "rule_id": rule_id,
        "evidence_refs": [item.get("evidence_ref", "") for item in refs],
        "explanation": _text(result.get("explanation")),
        "applied": False,
        "apply_reason": "",
    }

    if state == BOUND and component and refs:
        existing = _text(updated.get("matched_component"))
        if existing and _normalize_component(existing) != _normalize_component(
            component
        ):
            block["apply_reason"] = "EXISTING_COMPONENT_CONFLICT"
        else:
            if not existing:
                updated["matched_component"] = component
            rows = updated.get("match_rows")
            rows = list(rows) if isinstance(rows, list) else []
            if not any(
                _upper(row.get("match_type")) == category
                and _text(row.get("matched_value")) == component
                for row in rows
                if isinstance(row, Mapping)
            ):
                rows.append(
                    {
                        "match_id": _text(refs[0].get("evidence_ref")),
                        "match_type": category,
                        "matched_value": component,
                        "confidence": "LOW",
                        "source": rule_id,
                    }
                )
                updated["match_rows"] = rows
                updated["match_row_count"] = len(rows)
            block["applied"] = True
    elif state == BOUND:
        block["apply_reason"] = "BINDING_WITHOUT_EVIDENCE_REFS"

    updated["component_binding"] = block
    return updated


def reevaluate_with_binding(
    candidate: Mapping | None, binding: Mapping | None
) -> dict:
    """Re-run the existing gap layer with a binding applied (deterministic)."""

    base: Mapping = candidate if isinstance(candidate, Mapping) else {}
    updated_candidate = apply_binding_to_candidate(base, binding)
    base_gap = analyze_candidate(base)
    updated_gap = analyze_candidate(updated_candidate)

    base_states = {
        str(dim.get("evidence_type")): str(dim.get("state"))
        for dim in base_gap.get("dimensions") or []
    }
    updated_states = {
        str(dim.get("evidence_type")): str(dim.get("state"))
        for dim in updated_gap.get("dimensions") or []
    }
    state_changes = [
        {
            "evidence_type": evidence_type,
            "before": base_states.get(evidence_type, ""),
            "after": updated_states.get(evidence_type, ""),
        }
        for evidence_type in sorted(set(base_states) | set(updated_states))
        if base_states.get(evidence_type) != updated_states.get(evidence_type)
    ]

    return {
        "cve_id": str(base_gap.get("cve_id") or ""),
        "binding_state": _upper(
            binding.get("state") if isinstance(binding, Mapping) else ""
        ),
        "base_finding_readiness": str(base_gap.get("finding_readiness") or ""),
        "updated_finding_readiness": str(
            updated_gap.get("finding_readiness") or ""
        ),
        "changed": bool(state_changes),
        "state_changes": state_changes,
        "base_gap": base_gap,
        "updated_gap": updated_gap,
        "note": _REEVALUATION_NOTE,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "BOUND",
    "UNBOUND",
    "INSUFFICIENT_EVIDENCE",
    "CONFLICTING_EVIDENCE",
    "STATES",
    "RULES",
    "RULE_ASSET_COMPONENT_PROVENANCE",
    "RULE_ASSET_COMPONENT_MATCH",
    "KIND_COMPONENT_PROVENANCE",
    "KIND_ASSET_MATCH",
    "EVIDENCE_KINDS",
    "evaluate_component_binding",
    "apply_binding_to_candidate",
    "reevaluate_with_binding",
]
