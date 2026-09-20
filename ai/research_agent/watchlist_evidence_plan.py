"""Local watchlist evidence acquisition planning (planning only).

Consumes the structured output of the existing Evidence Gap Analysis layer
(``ai.research_agent.watchlist_evidence_gaps.analyze_candidate`` /
``analyze_snapshot``) and transforms MISSING / justified PARTIAL evidence
dimensions into a deterministic, machine-readable acquisition plan.

Pipeline position: Watchlist Snapshot -> Delta Intelligence -> Evidence Gap
Analysis -> **Evidence Acquisition Plan** -> Candidate Finding. This module
implements only the planning step.

Hard boundaries (encoded here, not just documented):

- Planning only: no HTTP, no MongoDB, no subprocess, no reconnaissance, no
  nuclei/ffuf, no crawling, no external APIs, no network, no execution of
  any acquisition method. Methods and sources are declarative descriptors.
- Deterministic: same gap payload -> byte-identical plan. No timestamps, no
  randomness, no environment-dependent output; stable step ids.
- Reuses the gap layer's state derivation; it never re-derives states from
  raw watchlist entries and never duplicates that logic.
- Conservative preservation of uncertainty:
  * technology identity != component identity;
  * component identity != version identity;
  * version association != component ownership;
  * a CVE watch signal != vulnerability confirmation;
  * a weak match != confirmed match.
- Existing evidence is never duplicated as an acquisition task: PRESENT and
  NOT_APPLICABLE dimensions produce no steps. PARTIAL dimensions produce a
  targeted step only when that step can materially resolve the remaining
  uncertainty; otherwise they are recorded as deferred with a reason.
- Stop conditions are explicit on every step and never claim an outcome has
  been achieved.
"""

from __future__ import annotations

from typing import Mapping

from ai.research_agent.watchlist_evidence_gaps import (
    COMPONENT_IDENTITY,
    COMPONENT_PROVENANCE,
    CVE_WATCH_SIGNAL,
    DIMENSIONS,
    MATCH_STATE,
    MISSING,
    NOT_APPLICABLE,
    PARTIAL,
    PRESENT,
    READINESS_READY,
    SOURCE_CONTEXT,
    TECHNOLOGY_IDENTITY,
    VERSION_ASSOCIATION,
    VERSION_IDENTITY,
    analyze_candidate,
    analyze_snapshot,
)

RULE_VERSION = "watchlist-evidence-plan-1"

# ---------------------------------------------------------------------------
# Vocabulary (declarative plan descriptors only; nothing is executed)
# ---------------------------------------------------------------------------

INSPECT_INVENTORY = "INSPECT_INVENTORY"
INSPECT_TECHNOLOGY_EVIDENCE = "INSPECT_TECHNOLOGY_EVIDENCE"
INSPECT_COMPONENT_PROVENANCE = "INSPECT_COMPONENT_PROVENANCE"
INSPECT_VERSION_EVIDENCE = "INSPECT_VERSION_EVIDENCE"
ACQUIRE_APPLICATION_RESPONSE = "ACQUIRE_APPLICATION_RESPONSE"
ACQUIRE_SOURCE_ASSET_EVIDENCE = "ACQUIRE_SOURCE_ASSET_EVIDENCE"

METHODS: tuple[str, ...] = (
    INSPECT_INVENTORY,
    INSPECT_TECHNOLOGY_EVIDENCE,
    INSPECT_COMPONENT_PROVENANCE,
    INSPECT_VERSION_EVIDENCE,
    ACQUIRE_APPLICATION_RESPONSE,
    ACQUIRE_SOURCE_ASSET_EVIDENCE,
)

EXISTING_INVENTORY = "EXISTING_INVENTORY"
TECHNOLOGY_FINGERPRINT = "TECHNOLOGY_FINGERPRINT"
COMPONENT_PROVENANCE_SOURCE = "COMPONENT_PROVENANCE"
VERSION_EVIDENCE = "VERSION_EVIDENCE"
APPLICATION_RESPONSE = "APPLICATION_RESPONSE"
SOURCE_ASSET = "SOURCE_ASSET"

SOURCES: tuple[str, ...] = (
    EXISTING_INVENTORY,
    TECHNOLOGY_FINGERPRINT,
    COMPONENT_PROVENANCE_SOURCE,
    VERSION_EVIDENCE,
    APPLICATION_RESPONSE,
    SOURCE_ASSET,
)

BLOCKING = "BLOCKING"
REQUIRED = "REQUIRED"
SUPPORTING = "SUPPORTING"

PRIORITIES: tuple[str, ...] = (BLOCKING, REQUIRED, SUPPORTING)

#: Plan-level states (never a security verdict).
PLAN_PLANNED = "ACQUISITION_PLANNED"
PLAN_NOT_REQUIRED = "NO_ACQUISITION_REQUIRED"
PLAN_NO_ACTIONABLE_STEPS = "NO_ACTIONABLE_STEPS"

PLAN_STATES: tuple[str, ...] = (
    PLAN_PLANNED,
    PLAN_NOT_REQUIRED,
    PLAN_NO_ACTIONABLE_STEPS,
)

_PRIORITY_RANK = {BLOCKING: 0, REQUIRED: 1, SUPPORTING: 2}

#: Deterministic priority per (evidence_type, gap state). Only MISSING and
#: PARTIAL rows can produce steps; PRESENT and NOT_APPLICABLE never do.
_PRIORITY: dict[tuple[str, str], str] = {
    (TECHNOLOGY_IDENTITY, MISSING): BLOCKING,
    (TECHNOLOGY_IDENTITY, PARTIAL): REQUIRED,
    (COMPONENT_IDENTITY, MISSING): BLOCKING,
    (COMPONENT_IDENTITY, PARTIAL): BLOCKING,
    (VERSION_IDENTITY, MISSING): BLOCKING,
    (VERSION_IDENTITY, PARTIAL): REQUIRED,
    (VERSION_ASSOCIATION, MISSING): REQUIRED,
    (VERSION_ASSOCIATION, PARTIAL): SUPPORTING,
    (CVE_WATCH_SIGNAL, MISSING): REQUIRED,
    (CVE_WATCH_SIGNAL, PARTIAL): SUPPORTING,
    (MATCH_STATE, MISSING): REQUIRED,
    (MATCH_STATE, PARTIAL): SUPPORTING,
    (COMPONENT_PROVENANCE, MISSING): REQUIRED,
    (COMPONENT_PROVENANCE, PARTIAL): SUPPORTING,
    (SOURCE_CONTEXT, MISSING): REQUIRED,
    (SOURCE_CONTEXT, PARTIAL): SUPPORTING,
}

#: Dimensions whose resolution presupposes a bound component identity.
_DEPENDS_ON_COMPONENT: frozenset[str] = frozenset(
    {VERSION_IDENTITY, VERSION_ASSOCIATION, COMPONENT_PROVENANCE}
)

_COMPONENT_BOUND_PRECONDITION = (
    "component identity is deterministically bound to the observed asset"
)

#: Deterministic acquisition chains. Each entry is a tuple of
#: (method, source, objective, stop_condition). All methods/sources come
#: from the declared vocabularies above; they are plan descriptors only.
_CHAINS: dict[tuple[str, str], tuple[tuple[str, str, str, str], ...]] = {
    (TECHNOLOGY_IDENTITY, MISSING): (
        (
            INSPECT_TECHNOLOGY_EVIDENCE,
            TECHNOLOGY_FINGERPRINT,
            "identify the technology identity observed for the watched asset",
            "stop when a technology identity is observed or the technology "
            "fingerprint evidence is exhausted",
        ),
        (
            ACQUIRE_APPLICATION_RESPONSE,
            APPLICATION_RESPONSE,
            "observe the technology identity from application response evidence",
            "stop when a technology identity is observed from an application "
            "response or no response evidence is available",
        ),
    ),
    (TECHNOLOGY_IDENTITY, PARTIAL): (
        (
            INSPECT_TECHNOLOGY_EVIDENCE,
            TECHNOLOGY_FINGERPRINT,
            "determine whether the observed technology evidence is "
            "component-specific rather than generic",
            "stop when the technology evidence is component-specific or "
            "remains generic-only after the defined source checks",
        ),
    ),
    (COMPONENT_IDENTITY, MISSING): (
        (
            INSPECT_INVENTORY,
            EXISTING_INVENTORY,
            "determine whether an existing inventory record binds a component "
            "identity to the watched asset",
            "stop when component identity is deterministically bound to the "
            "observed asset or the existing inventory is exhausted",
        ),
        (
            INSPECT_COMPONENT_PROVENANCE,
            COMPONENT_PROVENANCE_SOURCE,
            "inspect component provenance records for a component binding",
            "stop when component identity is deterministically bound from "
            "component provenance or the provenance checks are exhausted",
        ),
        (
            INSPECT_TECHNOLOGY_EVIDENCE,
            TECHNOLOGY_FINGERPRINT,
            "determine whether technology fingerprint evidence carries a "
            "component-level signal",
            "stop when a component-level signal is observed or the "
            "fingerprint evidence remains technology-only",
        ),
        (
            ACQUIRE_APPLICATION_RESPONSE,
            APPLICATION_RESPONSE,
            "acquire application response evidence that could bind a "
            "component identity",
            "stop when component identity is deterministically bound from an "
            "application response or the acquisition remains inconclusive",
        ),
        (
            ACQUIRE_SOURCE_ASSET_EVIDENCE,
            SOURCE_ASSET,
            "acquire source/asset evidence that could bind a component identity",
            "stop when component identity is deterministically bound from "
            "source/asset evidence or existing evidence remains insufficient "
            "after the defined source checks",
        ),
    ),
    (COMPONENT_IDENTITY, PARTIAL): (
        (
            INSPECT_COMPONENT_PROVENANCE,
            COMPONENT_PROVENANCE_SOURCE,
            "determine whether the unbound component-level signal binds to a "
            "component identity",
            "stop when component identity is deterministically bound to the "
            "observed asset or the signal remains unbound",
        ),
    ),
    (VERSION_IDENTITY, MISSING): (
        (
            INSPECT_INVENTORY,
            EXISTING_INVENTORY,
            "determine whether an existing inventory record binds a version "
            "identity to the observed component",
            "stop when a version identity is deterministically bound to the "
            "identified component or the existing inventory is exhausted",
        ),
        (
            INSPECT_VERSION_EVIDENCE,
            VERSION_EVIDENCE,
            "inspect version evidence for a component-bound version identity",
            "stop when version evidence is directly associated with the "
            "identified component or version evidence is exhausted",
        ),
        (
            ACQUIRE_APPLICATION_RESPONSE,
            APPLICATION_RESPONSE,
            "acquire application response evidence that could expose a "
            "component-bound version identity",
            "stop when a version identity is directly associated with the "
            "identified component or no response evidence is available",
        ),
    ),
    (VERSION_IDENTITY, PARTIAL): (
        (
            INSPECT_VERSION_EVIDENCE,
            VERSION_EVIDENCE,
            "determine whether the version signal binds to a component-bound "
            "version identity",
            "stop when a version identity is directly associated with the "
            "identified component or the signal remains unbound",
        ),
    ),
    (VERSION_ASSOCIATION, MISSING): (
        (
            INSPECT_VERSION_EVIDENCE,
            VERSION_EVIDENCE,
            "determine whether observed version evidence associates with the "
            "affected family",
            "stop when the version association against the affected family is "
            "determined or version evidence is exhausted",
        ),
        (
            INSPECT_COMPONENT_PROVENANCE,
            COMPONENT_PROVENANCE_SOURCE,
            "determine whether version association carries component ownership",
            "stop when version evidence is directly associated with the "
            "identified component or ownership remains unresolved",
        ),
    ),
    (VERSION_ASSOCIATION, PARTIAL): (
        (
            INSPECT_VERSION_EVIDENCE,
            VERSION_EVIDENCE,
            "determine whether the family-level version association can "
            "resolve to component-scoped ownership",
            "stop when version evidence is directly associated with the "
            "identified component or the association remains family-level",
        ),
    ),
    (CVE_WATCH_SIGNAL, MISSING): (
        (
            INSPECT_INVENTORY,
            EXISTING_INVENTORY,
            "determine whether the CVE is present in the existing watch "
            "inventory",
            "stop when a CVE watch signal is recorded or the existing "
            "inventory is exhausted",
        ),
    ),
    (CVE_WATCH_SIGNAL, PARTIAL): (
        (
            INSPECT_INVENTORY,
            EXISTING_INVENTORY,
            "determine whether the watch signal carries supporting queue "
            "context",
            "stop when the watch signal carries supporting context or the "
            "existing inventory is exhausted",
        ),
    ),
    (MATCH_STATE, MISSING): (
        (
            INSPECT_INVENTORY,
            EXISTING_INVENTORY,
            "determine whether existing inventory supports a deterministic "
            "asset match",
            "stop when a deterministic asset match state is established or "
            "the existing inventory is exhausted",
        ),
        (
            ACQUIRE_APPLICATION_RESPONSE,
            APPLICATION_RESPONSE,
            "acquire application response evidence for a deterministic asset "
            "match",
            "stop when the asset match state is established from "
            "deterministic evidence or existing evidence remains insufficient "
            "after the defined source checks",
        ),
    ),
    (MATCH_STATE, PARTIAL): (
        (
            ACQUIRE_APPLICATION_RESPONSE,
            APPLICATION_RESPONSE,
            "determine whether a stronger deterministic asset match exists",
            "stop when the match state is supported by deterministic evidence "
            "or remains weak/unknown after the defined source checks",
        ),
    ),
    (COMPONENT_PROVENANCE, MISSING): (
        (
            INSPECT_COMPONENT_PROVENANCE,
            COMPONENT_PROVENANCE_SOURCE,
            "determine whether the bound component identity has provenance",
            "stop when component provenance for the bound component identity "
            "is established or the provenance checks are exhausted",
        ),
        (
            INSPECT_INVENTORY,
            EXISTING_INVENTORY,
            "determine whether existing inventory carries component provenance",
            "stop when component provenance is found in existing inventory or "
            "the existing inventory is exhausted",
        ),
    ),
    (COMPONENT_PROVENANCE, PARTIAL): (
        (
            INSPECT_COMPONENT_PROVENANCE,
            COMPONENT_PROVENANCE_SOURCE,
            "determine whether the component-level signal carries provenance",
            "stop when component provenance is established for a bound "
            "component identity or the signal remains without provenance",
        ),
    ),
    (SOURCE_CONTEXT, MISSING): (
        (
            INSPECT_INVENTORY,
            EXISTING_INVENTORY,
            "determine whether existing inventory supplies source context",
            "stop when source context is established or the existing "
            "inventory is exhausted",
        ),
        (
            ACQUIRE_SOURCE_ASSET_EVIDENCE,
            SOURCE_ASSET,
            "acquire source/asset evidence supplying source context",
            "stop when source context is established from source/asset "
            "evidence or existing evidence remains insufficient after the "
            "defined source checks",
        ),
    ),
    (SOURCE_CONTEXT, PARTIAL): (
        (
            INSPECT_INVENTORY,
            EXISTING_INVENTORY,
            "determine whether existing inventory supplies stronger source "
            "context",
            "stop when source context is established from existing inventory "
            "or the existing inventory is exhausted",
        ),
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _dims_by_type(gap: Mapping) -> dict[str, Mapping]:
    out: dict[str, Mapping] = {}
    dimensions = gap.get("dimensions")
    if not isinstance(dimensions, (list, tuple)):
        return out
    for dimension in dimensions:
        if not isinstance(dimension, Mapping):
            continue
        evidence_type = _text(dimension.get("evidence_type"))
        if evidence_type in DIMENSIONS and evidence_type not in out:
            out[evidence_type] = dimension
    return out


def _as_gap_payload(payload: object) -> Mapping:
    """Return a gap payload; analyze raw entries through the gap layer.

    An already-analyzed gap payload (non-empty ``dimensions`` list) is used
    as-is. Anything else is treated as a watchlist entry/candidate and
    analyzed via the existing gap layer (never re-derived here).
    """

    if isinstance(payload, Mapping):
        dimensions = payload.get("dimensions")
        if isinstance(dimensions, (list, tuple)) and dimensions:
            return payload
    return analyze_candidate(payload if isinstance(payload, Mapping) else {})


def _step_id(cve_id: str, evidence_type: str, index: int) -> str:
    cve_token = (_text(cve_id) or "unknown").lower().replace(" ", "-")
    dim_token = evidence_type.lower().replace("_", "-")
    return f"eap-{cve_token}-{dim_token}-{index:02d}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_acquisition_plan(payload: Mapping | None) -> dict:
    """Build a deterministic acquisition plan from a gap payload.

    ``payload`` may be the output of ``analyze_candidate`` (preferred) or a
    raw watchlist candidate, which is passed through the existing gap layer.
    Neither form is mutated. The result is byte-identical for identical
    inputs.
    """

    gap = _as_gap_payload(payload)
    cve_id = _text(gap.get("cve_id")).upper()
    dims = _dims_by_type(gap)
    component_state = _text(
        dims.get(COMPONENT_IDENTITY, {}).get("state")
    )

    candidates: list[tuple[str, str, Mapping]] = []
    for evidence_type in DIMENSIONS:
        dimension = dims.get(evidence_type)
        if dimension is None:
            continue
        state = _text(dimension.get("state"))
        priority = _PRIORITY.get((evidence_type, state))
        if priority is None:
            # PRESENT / NOT_APPLICABLE / unknown states never become tasks.
            continue
        candidates.append((priority, evidence_type, dimension))

    candidates.sort(
        key=lambda item: (
            _PRIORITY_RANK[item[0]],
            DIMENSIONS.index(item[1]),
        )
    )

    steps: list[dict] = []
    deferred: list[dict] = []
    for priority, evidence_type, dimension in candidates:
        state = _text(dimension.get("state"))
        reason = _text(dimension.get("reason"))
        gap_strategy = dimension.get("acquisition_strategy")

        if evidence_type == COMPONENT_PROVENANCE and component_state != PRESENT:
            deferred.append(
                {
                    "evidence_type": evidence_type,
                    "state": state,
                    "reason": reason,
                    "deferred_reason": (
                        "component identity is unresolved, so component "
                        "provenance cannot be inspected yet"
                    ),
                }
            )
            continue

        chain = _CHAINS.get((evidence_type, state), ())
        previous_step_id = ""
        for index, (method, source, objective, stop_condition) in enumerate(
            chain, start=1
        ):
            step_id = _step_id(cve_id, evidence_type, index)
            preconditions: list[str] = []
            if (
                index == 1
                and evidence_type in _DEPENDS_ON_COMPONENT
                and component_state != PRESENT
            ):
                preconditions.append(_COMPONENT_BOUND_PRECONDITION)
            if previous_step_id:
                preconditions.append(
                    f"previous step ({previous_step_id}) remains unresolved"
                )
            steps.append(
                {
                    "step_id": step_id,
                    "evidence_type": evidence_type,
                    "priority": priority,
                    "dimension_state": state,
                    "objective": objective,
                    "method": method,
                    "source": source,
                    "preconditions": preconditions,
                    "stop_condition": stop_condition,
                    "reason": reason,
                    "gap_strategy": gap_strategy,
                }
            )
            previous_step_id = step_id

    priority_counts = {priority: 0 for priority in PRIORITIES}
    for step in steps:
        priority_counts[step["priority"]] += 1

    finding_readiness = _text(gap.get("finding_readiness"))
    if steps:
        plan_state = PLAN_PLANNED
    elif finding_readiness == READINESS_READY:
        plan_state = PLAN_NOT_REQUIRED
    else:
        plan_state = PLAN_NO_ACTIONABLE_STEPS

    return {
        "cve_id": cve_id,
        "evidence_state": _text(gap.get("evidence_state")),
        "finding_readiness": finding_readiness,
        "plan_state": plan_state,
        "steps": steps,
        "deferred": deferred,
        "step_count": len(steps),
        "priority_counts": priority_counts,
        "present": list(gap.get("present") or []),
        "partial": list(gap.get("partial") or []),
        "missing": list(gap.get("missing") or []),
        "not_applicable": list(gap.get("not_applicable") or []),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
        "rule_version": RULE_VERSION,
    }


def build_snapshot_acquisition_plan(snapshot: Mapping | None) -> dict:
    """Plan acquisition for every candidate in a watchlist snapshot.

    Read-only and deterministic: candidates are ordered by CVE id (the gap
    layer already sorts them). The input is never mutated.
    """

    analysis = analyze_snapshot(snapshot)
    candidates = [
        build_acquisition_plan(candidate)
        for candidate in analysis["candidates"]
    ]
    plan_counts = {state: 0 for state in PLAN_STATES}
    for plan in candidates:
        plan_counts[plan["plan_state"]] = (
            plan_counts.get(plan["plan_state"], 0) + 1
        )
    return {
        "snapshot_id": _text(analysis.get("snapshot_id")),
        "program": _text(analysis.get("program")),
        "cve_count": len(candidates),
        "plan_counts": plan_counts,
        "candidates": candidates,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
        "rule_version": RULE_VERSION,
    }


__all__ = [
    "RULE_VERSION",
    "METHODS",
    "SOURCES",
    "PRIORITIES",
    "PLAN_STATES",
    "INSPECT_INVENTORY",
    "INSPECT_TECHNOLOGY_EVIDENCE",
    "INSPECT_COMPONENT_PROVENANCE",
    "INSPECT_VERSION_EVIDENCE",
    "ACQUIRE_APPLICATION_RESPONSE",
    "ACQUIRE_SOURCE_ASSET_EVIDENCE",
    "EXISTING_INVENTORY",
    "TECHNOLOGY_FINGERPRINT",
    "COMPONENT_PROVENANCE_SOURCE",
    "VERSION_EVIDENCE",
    "APPLICATION_RESPONSE",
    "SOURCE_ASSET",
    "BLOCKING",
    "REQUIRED",
    "SUPPORTING",
    "PLAN_PLANNED",
    "PLAN_NOT_REQUIRED",
    "PLAN_NO_ACTIONABLE_STEPS",
    "build_acquisition_plan",
    "build_snapshot_acquisition_plan",
]
