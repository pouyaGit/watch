"""Stage R62 additive offline bridge: R61 snapshot -> R31-R38 -> R59/R60.

Connects the existing pieces without modifying any intelligence logic:

    R61 snapshot (sampled, deterministic)
        -> records_for_inventory -> build_inventory (R30.2)
        -> backend.asset_cve_matching.build_matches (R30.1 + R31-R38)
           with the new optional ``inventories=`` injection seam
        -> bounded research_context / intelligence_context
        -> R59 build_security_research_workflow
        -> R60 build_bug_bounty_copilot

Hard boundaries:

- Offline only: the injected matching path never reads MongoDB; the module
  makes no network, DNS, subprocess, browser, scanner or LLM call.
- No new intelligence: matching, hunt priority, evidence quality and every
  R31-R38 plan come from the existing hub; this module only projects bounded
  facts into the existing R59/R60 context contracts.
- Observations stay observations: no severity, confidence, vulnerability or
  authorization value is invented, and scope metadata never becomes
  authorization.
- Sampling is explicit: the produced contexts carry ``sampled: true`` and
  per-collection selection counters; they never claim completeness.
- Deterministic: same snapshot and same arguments produce identical contexts
  and identical downstream R59/R60 results.
"""

from __future__ import annotations

import json
import re
from typing import Mapping, Sequence

from ai.knowledge.bug_bounty_copilot import build_bug_bounty_copilot
from ai.knowledge.security_research_workflow import (
    build_security_research_workflow,
)
from ai.knowledge.specialist_eligibility import specialist_is_eligible
from backend.asset_cve_matching import build_matches
from backend.observed_inventory import build_inventory
from tests.local_e2e import recon_snapshot as rs

RULE_VERSION = "r62-1"

MAX_CONTEXT_DEPTH = 4
MAX_CONTEXT_LIST = 24
MAX_CONTEXT_KEYS = 32
MAX_REFS_PER_COLLECTION = 6

MATCHED_ASSET_STATES: tuple[str, ...] = (
    "CONFIRMED",
    "SUPPORTED",
    "WEAK",
)
SUPPORTED_SPECIALIST_CATEGORIES: tuple[str, ...] = (
    "RECON",
    "CVE_RESEARCH",
    "IDOR",
)

RECON_API_PATH_RE = re.compile(r"(^|/)api(/|$)", re.IGNORECASE)
RECON_GRAPHQL_PATH_RE = re.compile(r"(^|/)graphql(/|$)", re.IGNORECASE)
RECON_VERSION_PATH_RE = re.compile(r"(^|/)v\d+(/|$)", re.IGNORECASE)
IDOR_OBJECT_REFERENCE_RE = re.compile(r"\{(id|uuid|hash)\}|\{id\}-slug")

R31_LAYER_RULE_VERSION_KEYS: tuple[str, ...] = (
    "hunt_priority_rule_version",
    "hunt_action_plan_rule_version",
    "evidence_quality_rule_version",
    "research_intelligence_export_plan_rule_version",
    "research_memory_export_plan_rule_version",
    "research_learning_export_plan_rule_version",
    "research_strategy_export_plan_rule_version",
    "research_orchestration_export_plan_rule_version",
    "research_execution_authorization_export_plan_rule_version",
    "research_governance_export_plan_rule_version",
    "security_agent_framework_plan_rule_version",
    "xss_agent_plan_rule_version",
    "ssrf_agent_plan_rule_version",
    "sqli_agent_plan_rule_version",
)

INVENTORY_VALUE_KEYS: tuple[str, ...] = (
    "technologies",
    "versions",
    "parameters",
    "paths",
)

INVENTORY_COUNT_KEYS: tuple[str, ...] = (
    "technologies",
    "versions",
    "version_associations",
    "parameters",
    "parameter_paths",
    "paths",
)


class BridgeError(ValueError):
    """Deterministic, secret-free offline bridge failure."""


def _require_mapping(value: object, label: str) -> Mapping:
    if not isinstance(value, Mapping):
        raise BridgeError(f"{label} must be a mapping")
    return value


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _bounded_texts(items: object, limit: int = MAX_CONTEXT_LIST) -> list[str]:
    out: list[str] = []
    for item in items or ():
        text = _text(item.get("value") if isinstance(item, Mapping) else item)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _container_depth(value: object, depth: int = 0) -> int:
    if isinstance(value, Mapping):
        children = [
            _container_depth(item, depth + 1) for item in value.values()
        ]
    elif isinstance(value, (list, tuple)):
        children = [_container_depth(item, depth + 1) for item in value]
    else:
        return depth
    return max(children) if children else depth


def validate_context(value: object) -> None:
    """Fail closed when a context exceeds the R59/R60 bounded limits."""

    depth = _container_depth(value)
    if depth > MAX_CONTEXT_DEPTH:
        raise BridgeError(
            f"context depth {depth} exceeds {MAX_CONTEXT_DEPTH}"
        )
    if isinstance(value, Mapping):
        if len(value) > MAX_CONTEXT_KEYS:
            raise BridgeError("context mapping has too many keys")
        for item in value.values():
            validate_context(item)
    elif isinstance(value, (list, tuple)):
        if len(value) > MAX_CONTEXT_LIST:
            raise BridgeError("context list is too long")
        for item in value:
            validate_context(item)


def inventory_from_snapshot(snapshot: Mapping) -> dict:
    """Build the R30.2 observed inventory from an R61 snapshot (offline)."""

    _require_mapping(snapshot, "snapshot")
    records = rs.records_for_inventory(snapshot)
    program = _text(snapshot.get("program"))
    if not program:
        raise BridgeError("snapshot program must be non-empty")
    results = build_inventory(program, records=records)
    if len(results) != 1:
        raise BridgeError("expected exactly one inventory projection")
    inventory = results[0]
    _require_mapping(inventory, "inventory")
    return dict(inventory)


def match_summary_for(
    inventory: Mapping,
    *,
    cve: str,
    program: str | None = None,
) -> dict | None:
    """Run the existing R30.1/R31-R38 hub over an injected inventory."""

    cve_id = _text(cve)
    if not cve_id:
        raise BridgeError("cve must be a non-empty string")
    program_name = _text(program or inventory.get("program"))
    if not program_name:
        raise BridgeError("program must be a non-empty string")
    result = build_matches(
        cve=cve_id,
        program=program_name,
        inventories={program_name: dict(inventory)},
    )
    items = result.get("items") or []
    for item in items:
        if isinstance(item, Mapping) and _text(item.get("cve_id")) == cve_id:
            return dict(item)
    return None


def _collection_stats(snapshot: Mapping) -> dict:
    caps = snapshot.get("caps")
    caps = caps if isinstance(caps, Mapping) else {}
    collections = snapshot.get("collections")
    collections = collections if isinstance(collections, Mapping) else {}
    stats_out: dict = {}
    for name in sorted(collections):
        payload = collections.get(name)
        payload = payload if isinstance(payload, Mapping) else {}
        stats = payload.get("stats")
        stats = stats if isinstance(stats, Mapping) else {}
        selected = stats.get("selected")
        selected = selected if isinstance(selected, int) else 0
        fetched = stats.get("fetched")
        fetched = fetched if isinstance(fetched, int) else 0
        entry = {"selected": selected, "fetched": fetched}
        cap = caps.get(name)
        if isinstance(cap, int) and not isinstance(cap, bool):
            entry["cap"] = cap
            entry["cap_reached"] = cap > 0 and selected >= cap
        stats_out[name] = entry
    return stats_out


def _snapshot_records(
    snapshot: Mapping, collection: str, program: str
) -> list[Mapping]:
    collections = snapshot.get("collections")
    collections = collections if isinstance(collections, Mapping) else {}
    payload = collections.get(collection)
    payload = payload if isinstance(payload, Mapping) else {}
    records: list[Mapping] = []
    for record in payload.get("records") or ():
        if not isinstance(record, Mapping):
            continue
        if _text(record.get("program_name")) != program:
            continue
        records.append(record)
    return records


def _record_refs(snapshot: Mapping, program: str) -> dict:
    out: dict = {}
    for name in ("endpoints", "http", "urls", "subdomains"):
        refs: list[str] = []
        for record in _snapshot_records(snapshot, name, program):
            reference = _text(record.get("record_ref"))
            if reference:
                refs.append(reference)
            if len(refs) >= MAX_REFS_PER_COLLECTION:
                break
        out[name] = refs
    return out


def _r31_facts(r31: Mapping | None) -> dict:
    if not isinstance(r31, Mapping):
        return {}
    facts: dict = {}
    state = _text(r31.get("asset_match_state"))
    confidence = _text(r31.get("asset_match_confidence"))
    if state:
        facts["asset_match_state"] = state
    if confidence:
        facts["asset_match_confidence"] = confidence
    hunt = r31.get("hunt_priority")
    if isinstance(hunt, Mapping):
        band = _text(hunt.get("priority"))
        rank = hunt.get("priority_rank")
        blocked = hunt.get("blocked")
        if band:
            facts["hunt_priority_band"] = band
        if isinstance(rank, int) and not isinstance(rank, bool):
            facts["hunt_priority_rank"] = rank
        if isinstance(blocked, bool):
            facts["hunt_priority_blocked"] = blocked
    quality = r31.get("evidence_quality")
    if isinstance(quality, Mapping):
        level = _text(quality.get("evidence_quality"))
        strength = _text(quality.get("evidence_strength"))
        if level:
            facts["evidence_quality"] = level
        if strength:
            facts["evidence_strength"] = strength
    cve_id = _text(r31.get("cve_id"))
    if cve_id and state.upper() in MATCHED_ASSET_STATES:
        facts["cve_ids"] = [cve_id]
    else:
        facts["cve_ids"] = []
    rule_versions: dict = {}
    for key in R31_LAYER_RULE_VERSION_KEYS:
        value = _text(r31.get(key))
        if value:
            rule_versions[key] = value
    facts["r31_rule_versions"] = rule_versions
    return facts


def build_research_context(
    snapshot: Mapping,
    inventory: Mapping,
    *,
    r31: Mapping | None = None,
) -> dict:
    """Bounded R59/R60 research_context from snapshot + inventory + R31."""

    _require_mapping(snapshot, "snapshot")
    _require_mapping(inventory, "inventory")
    program = _text(inventory.get("program") or snapshot.get("program"))
    if not program:
        raise BridgeError("program must be non-empty")
    context: dict = {
        "program": program,
        "snapshot_version": snapshot.get("snapshot_version"),
        "snapshot_rule_version": _text(snapshot.get("rule_version")),
        "sampled": True,
        "collection_stats": _collection_stats(snapshot),
        "inventory_counts": {
            key: len(inventory.get(key) or ())
            for key in INVENTORY_COUNT_KEYS
        },
        "technologies": _bounded_texts(inventory.get("technologies")),
        "versions": _bounded_texts(inventory.get("versions")),
        "parameters": _bounded_texts(inventory.get("parameters")),
        "paths": _bounded_texts(inventory.get("paths")),
        "record_refs": _record_refs(snapshot, program),
    }
    context.update(_r31_facts(r31))
    validate_context(context)
    return context


def build_intelligence_context(
    snapshot: Mapping,
    inventory: Mapping,
    *,
    r31: Mapping | None = None,
    signals: Mapping | None = None,
) -> dict:
    """Bounded R59/R60 intelligence_context of existing layer references."""

    _require_mapping(snapshot, "snapshot")
    _require_mapping(inventory, "inventory")
    program = _text(inventory.get("program") or snapshot.get("program"))
    if not program:
        raise BridgeError("program must be non-empty")
    context: dict = {
        "program": program,
        "snapshot_version": snapshot.get("snapshot_version"),
        "snapshot_rule_version": _text(snapshot.get("rule_version")),
        "sampled": True,
        "specialist_signals": dict(signals) if isinstance(signals, Mapping) else {},
    }
    context.update(_r31_facts(r31))
    context.setdefault("cve_ids", [])
    context.setdefault("r31_rule_versions", {})
    validate_context(context)
    return context


def _observed_paths(snapshot: Mapping, inventory: Mapping) -> list[str]:
    program = _text(inventory.get("program") or snapshot.get("program"))
    paths: set[str] = set()
    for path in _bounded_texts(inventory.get("paths"), MAX_CONTEXT_LIST * 8):
        paths.add(path)
    for name in ("endpoints", "urls"):
        for record in _snapshot_records(snapshot, name, program):
            path = _text(record.get("path"))
            if path:
                paths.add(path)
    return sorted(paths)


def _endpoint_has_parameter_evidence(record: Mapping) -> bool:
    for key in (
        "params",
        "params_from_crawl",
        "params_from_x8",
        "param_records",
    ):
        value = record.get(key)
        if isinstance(value, (list, tuple)) and value:
            return True
    return False


def _idor_evidence(snapshot: Mapping, program: str) -> bool:
    for record in _snapshot_records(snapshot, "endpoints", program):
        path = _text(record.get("path"))
        if not IDOR_OBJECT_REFERENCE_RE.search(path):
            continue
        if _endpoint_has_parameter_evidence(record):
            return True
    return False


def specialist_signals(
    snapshot: Mapping,
    inventory: Mapping,
    *,
    r31: Mapping | None = None,
) -> dict:
    """Deterministically supported specialist context signals only.

    The emitted categories are verified against the existing R52 eligibility
    engine, so a signal can never make a specialist eligible unless the
    engine already accepts it. Categories without structured evidence stay
    absent (never UNKNOWN-invented and never keyword-guessed).
    """

    _require_mapping(snapshot, "snapshot")
    _require_mapping(inventory, "inventory")
    signals: dict = {}
    program = _text(inventory.get("program") or snapshot.get("program"))
    if not program:
        raise BridgeError("program must be non-empty")

    paths = _observed_paths(snapshot, inventory)
    has_graphql = any(RECON_GRAPHQL_PATH_RE.search(path) for path in paths)
    has_api = any(RECON_API_PATH_RE.search(path) for path in paths)
    if has_graphql or has_api:
        recon: dict = {"api_type": "GRAPHQL" if has_graphql else "REST"}
        if any(RECON_VERSION_PATH_RE.search(path) for path in paths):
            recon["api_versioning"] = "VERSIONED_OBSERVED"
        signals["RECON"] = recon

    if isinstance(r31, Mapping):
        cve_id = _text(r31.get("cve_id"))
        state = _text(r31.get("asset_match_state")).upper()
        if cve_id and state in MATCHED_ASSET_STATES:
            signals["CVE_RESEARCH"] = {"cve_metadata": cve_id}

    if _idor_evidence(snapshot, program):
        signals["IDOR"] = {"object_reference": "PATH_PARAMETER"}

    verified: dict = {}
    for category in SUPPORTED_SPECIALIST_CATEGORIES:
        context = signals.get(category)
        if not isinstance(context, Mapping) or not context:
            continue
        if specialist_is_eligible(category, dict(context)):
            verified[category] = dict(context)
    return verified


def run_workflow(research_context: Mapping) -> dict:
    """Run the existing R59 workflow builder over a bounded context."""

    return build_security_research_workflow(
        research_context=dict(research_context)
    )


def run_copilot(
    research_context: Mapping,
    intelligence_context: Mapping,
    workflow_result: Mapping,
    *,
    copilot_id: str,
) -> dict:
    """Run the existing R60 copilot over bounded contexts (advisory only)."""

    return build_bug_bounty_copilot(
        {"copilot_id": _text(copilot_id)},
        target_reference=_text(research_context.get("program")),
        research_context=dict(research_context),
        intelligence_context=dict(intelligence_context),
        workflow_result=dict(workflow_result),
    )


def pipeline(
    snapshot: Mapping,
    *,
    cve: str | None = None,
    copilot_id: str | None = None,
) -> dict:
    """Full offline chain: snapshot -> inventory -> R31-R38 -> R59 -> R60."""

    inventory = inventory_from_snapshot(snapshot)
    program = _text(inventory.get("program"))
    r31 = match_summary_for(inventory, cve=cve) if _text(cve) else None
    signals = specialist_signals(snapshot, inventory, r31=r31)
    research_context = build_research_context(
        snapshot, inventory, r31=r31
    )
    intelligence_context = build_intelligence_context(
        snapshot, inventory, r31=r31, signals=signals
    )
    workflow = run_workflow(research_context)
    copilot = run_copilot(
        research_context,
        intelligence_context,
        workflow,
        copilot_id=copilot_id or f"r62-{program}",
    )
    return {
        "inventory": inventory,
        "r31": r31,
        "specialist_signals": signals,
        "research_context": research_context,
        "intelligence_context": intelligence_context,
        "workflow": workflow,
        "copilot": copilot,
    }


def canonical_json(value: object) -> str:
    """Canonical JSON used by callers/tests for determinism checks."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


__all__ = [
    "RULE_VERSION",
    "MAX_CONTEXT_DEPTH",
    "MAX_CONTEXT_LIST",
    "MAX_CONTEXT_KEYS",
    "MATCHED_ASSET_STATES",
    "SUPPORTED_SPECIALIST_CATEGORIES",
    "BridgeError",
    "inventory_from_snapshot",
    "match_summary_for",
    "build_research_context",
    "build_intelligence_context",
    "specialist_signals",
    "validate_context",
    "run_workflow",
    "run_copilot",
    "pipeline",
    "canonical_json",
]
