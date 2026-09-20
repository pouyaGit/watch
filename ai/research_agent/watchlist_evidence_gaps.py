"""Local watchlist evidence-gap intelligence (structural analysis only).

Consumes an existing watchlist candidate representation (one entry shaped
like ``ai.research_agent.watchlist.build_entry`` output, or a whole
snapshot) and determines, deterministically:

1. What evidence is currently present.
2. What evidence is missing.
3. Which evidence categories are required before the candidate can become
   a properly supported finding.
4. A declarative evidence-acquisition plan for each gap.

Pipeline position: Watchlist Snapshot -> Delta Intelligence ->
Evidence Gap Analysis -> Evidence Acquisition Plan -> Candidate Finding.
This module implements only the Evidence Gap Analysis step.

Hard boundaries (encoded here, not just documented):

- Pure and deterministic: no HTTP, no MongoDB, no subprocess, no live
  scanning, no external APIs, no network. Operates entirely on supplied
  structured data; inputs are never mutated.
- No invented evidence: only the known watchlist entry fields are read.
  Unknown/unexpected input fields never become evidence.
- No confirmation inference: a technology, component, or version appearing
  in inventory is never treated as proof of exploitability. A technology
  identity such as WordPress is never treated as proof that a specific
  plugin is installed. A version association without component ownership
  never becomes component-specific evidence. Readiness states are
  ``INSUFFICIENT_EVIDENCE`` / ``EVIDENCE_PARTIAL`` / ``EVIDENCE_READY``;
  the words "confirmed", "exploitable", and "valid vulnerability" never
  appear in any output.
- Acquisition plans are declarative only (``inspect ...`` / ``acquire ...``
  strategy labels). Nothing is executed here.
"""

from __future__ import annotations

from typing import Mapping

RULE_VERSION = "watchlist-evidence-gaps-1"

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

TECHNOLOGY_IDENTITY = "TECHNOLOGY_IDENTITY"
COMPONENT_IDENTITY = "COMPONENT_IDENTITY"
VERSION_IDENTITY = "VERSION_IDENTITY"
VERSION_ASSOCIATION = "VERSION_ASSOCIATION"
CVE_WATCH_SIGNAL = "CVE_WATCH_SIGNAL"
MATCH_STATE = "MATCH_STATE"
COMPONENT_PROVENANCE = "COMPONENT_PROVENANCE"
SOURCE_CONTEXT = "SOURCE_CONTEXT"

#: Canonical dimension order. Every output list follows this order, so
#: results are deterministic regardless of input key ordering.
DIMENSIONS: tuple[str, ...] = (
    TECHNOLOGY_IDENTITY,
    COMPONENT_IDENTITY,
    VERSION_IDENTITY,
    VERSION_ASSOCIATION,
    CVE_WATCH_SIGNAL,
    MATCH_STATE,
    COMPONENT_PROVENANCE,
    SOURCE_CONTEXT,
)

PRESENT = "PRESENT"
MISSING = "MISSING"
PARTIAL = "PARTIAL"
NOT_APPLICABLE = "NOT_APPLICABLE"

STATES: tuple[str, ...] = (PRESENT, MISSING, PARTIAL, NOT_APPLICABLE)

#: Aggregate evidence rollup (descriptive only, not a verdict).
EVIDENCE_COMPLETE = "COMPLETE"
EVIDENCE_PARTIAL_STATE = "PARTIAL"
EVIDENCE_ABSENT = "ABSENT"

#: Conservative finding-readiness gate. Only EVIDENCE_READY may proceed
#: toward a candidate finding; nothing here asserts confirmation.
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
READINESS_PARTIAL = "EVIDENCE_PARTIAL"
READINESS_READY = "EVIDENCE_READY"

#: Version-association states that show version evidence was observed but
#: bound to no component (association without ownership).
OBSERVED_UNBOUND_ASSOCIATIONS: frozenset[str] = frozenset(
    {
        "FAMILY_MISMATCH",
        "VERSION_OBSERVED_NO_MATCH",
    }
)

WITHIN_FAMILY_ASSOCIATION = "VERSION_MATCH_WITHIN_SAME_FAMILY"

#: Blocker token (watchlist vocabulary) marking a technology-only match.
GENERIC_TECHNOLOGY_BLOCKER = "generic_technology_only"

_STRONG_MATCH_STATES: frozenset[str] = frozenset({"SUPPORTED", "CONFIRMED"})


# ---------------------------------------------------------------------------
# Declarative acquisition strategies (labels only; never executed)
# ---------------------------------------------------------------------------

_ACQUIRE: dict[tuple[str, str], str | None] = {
    (TECHNOLOGY_IDENTITY, MISSING): "inspect technology fingerprint evidence",
    (TECHNOLOGY_IDENTITY, PARTIAL): "inspect technology fingerprint evidence",
    (COMPONENT_IDENTITY, MISSING): "inspect existing inventory",
    (COMPONENT_IDENTITY, PARTIAL): "inspect component provenance",
    (VERSION_IDENTITY, MISSING): "inspect version evidence",
    (VERSION_IDENTITY, PARTIAL): "inspect version evidence",
    (VERSION_ASSOCIATION, MISSING): "inspect version evidence",
    (VERSION_ASSOCIATION, PARTIAL): "inspect version evidence",
    (CVE_WATCH_SIGNAL, MISSING): "inspect existing inventory",
    (CVE_WATCH_SIGNAL, PARTIAL): "inspect existing inventory",
    (MATCH_STATE, MISSING): "inspect existing inventory",
    (MATCH_STATE, PARTIAL): "acquire application response evidence",
    (COMPONENT_PROVENANCE, MISSING): "inspect component provenance",
    (COMPONENT_PROVENANCE, PARTIAL): "inspect component provenance",
    (SOURCE_CONTEXT, MISSING): "acquire source/asset evidence",
    (SOURCE_CONTEXT, PARTIAL): "inspect existing inventory",
}


# ---------------------------------------------------------------------------
# Input accessors (known fields only; unknown fields are never evidence)
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _match_rows(entry: Mapping) -> list[Mapping]:
    rows = entry.get("match_rows")
    if not isinstance(rows, (list, tuple)):
        return []
    return [row for row in rows if isinstance(row, Mapping)]


def _row_types(entry: Mapping) -> set[str]:
    return {_upper(row.get("match_type")) for row in _match_rows(entry)}


def _row_values(entry: Mapping, match_type: str) -> list[str]:
    return [
        _text(row.get("matched_value"))
        for row in _match_rows(entry)
        if _upper(row.get("match_type")) == match_type
        and _text(row.get("matched_value"))
    ]


def _blocker_tokens(entry: Mapping) -> set[str]:
    tokens: set[str] = set()
    for key in ("resolved_blockers", "remaining_blockers"):
        value = entry.get(key)
        if isinstance(value, (list, tuple)):
            tokens.update(str(item).strip().lower() for item in value)
    queue = entry.get("queue")
    if isinstance(queue, Mapping):
        blockers = queue.get("blockers")
        if isinstance(blockers, (list, tuple)):
            tokens.update(str(item).strip().lower() for item in blockers)
    return tokens


def _queue_present(entry: Mapping) -> bool:
    queue = entry.get("queue")
    return isinstance(queue, Mapping) and queue.get("present") is True


# ---------------------------------------------------------------------------
# Per-dimension analysis (each returns state + reason; never invents)
# ---------------------------------------------------------------------------


def _technology(entry: Mapping) -> tuple[str, str]:
    if _row_values(entry, "TECHNOLOGY"):
        if GENERIC_TECHNOLOGY_BLOCKER in _blocker_tokens(entry):
            return (
                PARTIAL,
                "technology observed in inventory but only a generic "
                "technology match supports it; not component-specific "
                "evidence",
            )
        return PRESENT, "technology identity observed in inventory match rows"
    if _upper(entry.get("strongest_match_type")) == "TECHNOLOGY":
        return (
            PARTIAL,
            "technology-level match signal without an observed technology "
            "match row",
        )
    return MISSING, "no technology identity observed in match rows"


def _component(entry: Mapping) -> tuple[str, str]:
    if _text(entry.get("matched_component")):
        return PRESENT, "component identity bound to the candidate"
    for match_type in ("COMPONENT", "PLUGIN", "PRODUCT"):
        if _row_values(entry, match_type):
            return (
                PARTIAL,
                f"{match_type} match signal observed but no component "
                "identity is bound to the candidate",
            )
    return MISSING, "no component identity bound to the candidate"


def _version(entry: Mapping) -> tuple[str, str]:
    # Version identity is bound identity only. Family-level association
    # signals (even within-family) never count here; they belong to
    # VERSION_ASSOCIATION. An UNKNOWN version therefore stays MISSING so
    # missing version evidence is preserved rather than upgraded.
    if _text(entry.get("matched_version")):
        return PRESENT, "version identity bound to the candidate"
    if _row_values(entry, "VERSION"):
        return (
            PARTIAL,
            "version match signal observed but no version identity is "
            "bound to the candidate",
        )
    return MISSING, "no version identity bound to the candidate"


def _association(entry: Mapping) -> tuple[str, str]:
    state = _upper(entry.get("version_association_state"))
    if not state:
        return MISSING, "no version association evidence supplied"
    if state == WITHIN_FAMILY_ASSOCIATION:
        return (
            PRESENT,
            "observed version associated within the affected family; "
            "association only, not component ownership",
        )
    return (
        PARTIAL,
        "version association evidence observed without an affected-family "
        "association",
    )


def _watch_signal(entry: Mapping) -> tuple[str, str]:
    if not _text(entry.get("cve_id")):
        return MISSING, "no CVE watch signal supplied"
    if _queue_present(entry):
        return PRESENT, "CVE is watched with supporting queue context"
    return (
        PARTIAL,
        "CVE is watched but queue context is absent",
    )


def _match(entry: Mapping) -> tuple[str, str]:
    state = _upper(entry.get("match_state"))
    if state in _STRONG_MATCH_STATES:
        return PRESENT, "match state indicates a strong asset match"
    if state == "WEAK":
        return PARTIAL, "match state indicates only a weak asset match"
    return MISSING, "match state carries no usable asset match"


def _provenance(
    entry: Mapping, component_state: str
) -> tuple[str, str]:
    if component_state == MISSING:
        return (
            NOT_APPLICABLE,
            "no component identity exists, so component provenance does "
            "not apply",
        )
    rows = _row_values(entry, "COMPONENT") + _row_values(entry, "PLUGIN")
    if rows:
        if _text(entry.get("matched_component")):
            return PRESENT, "bound component identity has provenance in match rows"
        return (
            PARTIAL,
            "component-level match signal exists but is not bound to a "
            "component identity",
        )
    if _text(entry.get("matched_component")):
        return (
            MISSING,
            "component identity is bound but has no provenance in match rows",
        )
    return (
        PARTIAL,
        "component-level signal without provenance in match rows",
    )


def _source(entry: Mapping) -> tuple[str, str]:
    if _match_rows(entry):
        return PRESENT, "observed inventory match rows supply source context"
    if _queue_present(entry):
        return (
            PARTIAL,
            "queue context exists but no observed match rows supply source "
            "context",
        )
    return MISSING, "no observed match rows or queue context available"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_candidate(entry: Mapping | None) -> dict:
    """Analyze evidence gaps for one watchlist candidate (deterministic).

    ``entry`` is a watchlist candidate representation (watchlist entry
    shape). Only known fields are read; unknown fields never become
    evidence. The input is never mutated.
    """

    candidate: Mapping = entry if isinstance(entry, Mapping) else {}
    cve_id = _upper(candidate.get("cve_id"))

    states: dict[str, tuple[str, str]] = {}
    states[TECHNOLOGY_IDENTITY] = _technology(candidate)
    states[COMPONENT_IDENTITY] = _component(candidate)
    states[VERSION_IDENTITY] = _version(candidate)
    states[VERSION_ASSOCIATION] = _association(candidate)
    states[CVE_WATCH_SIGNAL] = _watch_signal(candidate)
    states[MATCH_STATE] = _match(candidate)
    states[COMPONENT_PROVENANCE] = _provenance(
        candidate, states[COMPONENT_IDENTITY][0]
    )
    states[SOURCE_CONTEXT] = _source(candidate)

    dimensions: list[dict] = []
    present: list[str] = []
    partial: list[str] = []
    missing: list[str] = []
    not_applicable: list[str] = []
    acquisition_plan: list[dict] = []

    for dimension in DIMENSIONS:
        state, reason = states[dimension]
        strategy = _ACQUIRE.get((dimension, state))
        dimensions.append(
            {
                "evidence_type": dimension,
                "state": state,
                "reason": reason,
                "acquisition_strategy": strategy,
            }
        )
        if state == PRESENT:
            present.append(dimension)
        elif state == PARTIAL:
            partial.append(dimension)
        elif state == MISSING:
            missing.append(dimension)
        else:
            not_applicable.append(dimension)
        if state in (MISSING, PARTIAL) and strategy is not None:
            acquisition_plan.append(
                {
                    "evidence_type": dimension,
                    "acquisition_strategy": strategy,
                }
            )

    applicable_missing = [name for name in missing]
    applicable_partial = [name for name in partial]
    applicable_present = [name for name in present]

    if applicable_missing:
        readiness = INSUFFICIENT_EVIDENCE
    elif applicable_partial:
        readiness = READINESS_PARTIAL
    else:
        readiness = READINESS_READY

    if not applicable_missing and not applicable_partial:
        evidence_state = EVIDENCE_COMPLETE
    elif applicable_present or applicable_partial:
        evidence_state = EVIDENCE_PARTIAL_STATE
    else:
        evidence_state = EVIDENCE_ABSENT

    return {
        "cve_id": cve_id,
        "evidence_state": evidence_state,
        "finding_readiness": readiness,
        "dimensions": dimensions,
        "present": present,
        "partial": partial,
        "missing": missing,
        "not_applicable": not_applicable,
        "acquisition_plan": acquisition_plan,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
        "rule_version": RULE_VERSION,
    }


def analyze_snapshot(snapshot: Mapping | None) -> dict:
    """Analyze evidence gaps for every candidate in a watchlist snapshot.

    Deterministic: candidates sorted by CVE id. Read-only; the input is
    never mutated.
    """

    payload: Mapping = snapshot if isinstance(snapshot, Mapping) else {}
    entries = payload.get("entries")
    items = (
        [entry for entry in entries if isinstance(entry, Mapping)]
        if isinstance(entries, (list, tuple))
        else []
    )
    candidates = [analyze_candidate(entry) for entry in items]
    candidates.sort(key=lambda item: item["cve_id"])

    readiness_counts: dict[str, int] = {
        INSUFFICIENT_EVIDENCE: 0,
        READINESS_PARTIAL: 0,
        READINESS_READY: 0,
    }
    for candidate in candidates:
        readiness = candidate["finding_readiness"]
        readiness_counts[readiness] = readiness_counts.get(readiness, 0) + 1

    return {
        "snapshot_id": str(payload.get("snapshot_id") or ""),
        "program": str(payload.get("program") or ""),
        "cve_count": len(candidates),
        "readiness_counts": readiness_counts,
        "candidates": candidates,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
        "rule_version": RULE_VERSION,
    }


__all__ = [
    "RULE_VERSION",
    "DIMENSIONS",
    "TECHNOLOGY_IDENTITY",
    "COMPONENT_IDENTITY",
    "VERSION_IDENTITY",
    "VERSION_ASSOCIATION",
    "CVE_WATCH_SIGNAL",
    "MATCH_STATE",
    "COMPONENT_PROVENANCE",
    "SOURCE_CONTEXT",
    "PRESENT",
    "MISSING",
    "PARTIAL",
    "NOT_APPLICABLE",
    "STATES",
    "EVIDENCE_COMPLETE",
    "EVIDENCE_PARTIAL_STATE",
    "EVIDENCE_ABSENT",
    "INSUFFICIENT_EVIDENCE",
    "READINESS_PARTIAL",
    "READINESS_READY",
    "analyze_candidate",
    "analyze_snapshot",
]
