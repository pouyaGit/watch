"""backend/command_intelligence.py — Command Center intelligence projections.

Read-only, deterministic projections composed from data the existing
authorities already produced. Nothing here is a new security conclusion: the
conservative watchlist vocabulary (match states, evidence readiness, gap
dimensions, blockers) is aggregated and mapped, never upgraded.

- ``research_operations`` aggregates the existing candidate views from
  ``backend.watchlist_data`` into dashboard counters (match state, confidence,
  research status, evidence readiness/state, evidence-gap dimensions,
  remaining blockers) plus a bounded list of latest snapshot summaries.
- ``candidate_lifecycle`` maps one existing candidate view onto the five
  research pipeline stages Discovery -> Metadata -> Evidence -> Verification
  -> Review. Stage states describe research progress only; they are never a
  vulnerability verdict. This module never emits the words "confirmed",
  "exploitable" or "vulnerability".
- ``report_cves_for`` reuses the existing ``backend.research_data`` report
  existence check so the Review stage reflects a persisted report artifact
  when one exists.

No subprocess, no network, no Mongo writes, no LLM, no target interaction.
The input is never mutated.
"""

from __future__ import annotations

from collections import Counter
from typing import Callable, Iterable

STAGES: tuple[str, ...] = ("Discovery", "Metadata", "Evidence", "Verification",
                           "Review")

COMPLETE = "COMPLETE"
IN_PROGRESS = "IN_PROGRESS"
BLOCKED = "BLOCKED"
PENDING = "PENDING"
NOT_STARTED = "NOT_STARTED"

DEFAULT_LIFECYCLE_LIMIT = 50

#: Evidence dimensions that gate the Metadata stage (owned by the existing
#: watchlist_evidence_gaps vocabulary).
_METADATA_DIMENSIONS = ("TECHNOLOGY_IDENTITY", "COMPONENT_IDENTITY",
                        "VERSION_IDENTITY")

_PRESENT = "PRESENT"
_PARTIAL = "PARTIAL"
_READY = "EVIDENCE_READY"
_READINESS_PARTIAL = "EVIDENCE_PARTIAL"
_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"

MAX_COUNTER_ITEMS = 40


def _text(value: object, limit: int = 240) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _ranked(counter: Counter) -> dict:
    return {
        key: int(value)
        for key, value in sorted(
            counter.items(), key=lambda item: (-item[1], item[0])
        )
    }


def _dimension_state(candidate: dict, name: str) -> str:
    for dimension in candidate.get("gap_dimensions") or []:
        if not isinstance(dimension, dict):
            continue
        if _text(dimension.get("name"), 48) == name:
            return _text(dimension.get("state"), 24)
    return ""


# ---------------------------------------------------------------------------
# Research operations
# ---------------------------------------------------------------------------


def research_operations(overview: object) -> dict:
    """Aggregate existing watchlist candidate views into operations counters.

    Consumes exactly the payload returned by
    ``backend.watchlist_data.overview``. Deterministic ordering everywhere.
    """

    empty = {
        "available": False,
        "candidate_count": 0,
        "snapshots": [],
        "match_states": {},
        "confidence": {},
        "research_status": {},
        "readiness": {},
        "evidence_state": {},
        "missing_dimensions": [],
        "partial_dimensions": [],
        "blockers": [],
        "generated_from": "latest persisted watchlist snapshots",
    }
    if not isinstance(overview, dict) or not overview.get("available"):
        return empty

    match_states: Counter = Counter()
    confidence: Counter = Counter()
    research_status: Counter = Counter()
    readiness: Counter = Counter()
    evidence_state: Counter = Counter()
    missing: Counter = Counter()
    partial: Counter = Counter()
    blockers: Counter = Counter()
    snapshots: list[dict] = []
    candidate_count = 0

    for view in overview.get("programs") or []:
        if not isinstance(view, dict):
            continue
        snapshots.append({
            "program": _text(view.get("program"), 64),
            "snapshot_id": _text(view.get("snapshot_id"), 32),
            "created_utc": view.get("created_utc"),
            "cve_count": int(view.get("cve_count") or 0),
            "snapshot_count": int(view.get("snapshot_count") or 0),
            "previous_snapshot_id": _text(view.get("previous_snapshot_id"), 32),
            "delta_counts": dict(view.get("delta_counts") or {}),
            "match_state_counts": dict(view.get("match_state_counts") or {}),
            "readiness_counts": dict(view.get("readiness_counts") or {}),
        })
        for candidate in view.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            candidate_count += 1
            match_states[_text(candidate.get("match_state"), 32) or "UNKNOWN"] += 1
            confidence[_text(candidate.get("confidence"), 16) or "NONE"] += 1
            research_status[
                _text(candidate.get("research_status"), 40) or "UNKNOWN"
            ] += 1
            readiness[
                _text(candidate.get("finding_readiness"), 40) or "UNKNOWN"
            ] += 1
            evidence_state[
                _text(candidate.get("evidence_state"), 32) or "UNKNOWN"
            ] += 1
            for dimension in candidate.get("gap_missing") or []:
                missing[_text(dimension, 48)] += 1
            for dimension in candidate.get("gap_partial") or []:
                partial[_text(dimension, 48)] += 1
            for blocker in candidate.get("remaining_blockers") or []:
                blockers[_text(blocker, 96)] += 1

    def _items(counter: Counter, label: str) -> list[dict]:
        return [
            {label: key, "count": value}
            for key, value in _ranked(counter).items()
            if key
        ][:MAX_COUNTER_ITEMS]

    return {
        "available": True,
        "candidate_count": candidate_count,
        "snapshots": snapshots,
        "match_states": _ranked(match_states),
        "confidence": _ranked(confidence),
        "research_status": _ranked(research_status),
        "readiness": _ranked(readiness),
        "evidence_state": _ranked(evidence_state),
        "missing_dimensions": _items(missing, "dimension"),
        "partial_dimensions": _items(partial, "dimension"),
        "blockers": _items(blockers, "blocker"),
        "generated_from": "latest persisted watchlist snapshots",
    }


# ---------------------------------------------------------------------------
# Findings lifecycle
# ---------------------------------------------------------------------------


def _metadata_stage(candidate: dict) -> tuple[str, str]:
    component = _dimension_state(candidate, "COMPONENT_IDENTITY")
    version = _dimension_state(candidate, "VERSION_IDENTITY")
    technology = _dimension_state(candidate, "TECHNOLOGY_IDENTITY")
    if component == _PRESENT and version == _PRESENT:
        return COMPLETE, "component and version identity bound to the candidate"
    if any(state in (_PRESENT, _PARTIAL)
           for state in (component, version, technology)):
        return IN_PROGRESS, (
            "identity evidence partially observed; component/version binding "
            "is incomplete"
        )
    return BLOCKED, "no technology, component or version identity observed"


def _evidence_stage(candidate: dict) -> tuple[str, str]:
    readiness = _text(candidate.get("finding_readiness"), 40)
    if readiness == _READY:
        return COMPLETE, "existing evidence-gap projection reports EVIDENCE_READY"
    if readiness == _READINESS_PARTIAL:
        return IN_PROGRESS, (
            "existing evidence-gap projection reports EVIDENCE_PARTIAL"
        )
    if readiness == _INSUFFICIENT:
        return BLOCKED, (
            "existing evidence-gap projection reports INSUFFICIENT_EVIDENCE"
        )
    return NOT_STARTED, "no evidence-readiness projection available"


def candidate_lifecycle(candidate: object, *, has_report: bool = False) -> dict:
    """Map one candidate view onto the five research pipeline stages.

    Stage states describe research progress only. A persisted Markdown report
    marks the Review stage as COMPLETE (a review artifact exists); nothing here
    asserts a vulnerability.
    """

    data = candidate if isinstance(candidate, dict) else {}
    cve = _text(data.get("cve_id"), 64)
    stages: list[dict] = []

    if cve:
        stages.append({
            "stage": "Discovery",
            "state": COMPLETE,
            "detail": "candidate present in the latest persisted watchlist snapshot",
        })
    else:
        stages.append({
            "stage": "Discovery",
            "state": NOT_STARTED,
            "detail": "no watchlist candidate identity",
        })

    metadata_state, metadata_detail = _metadata_stage(data)
    stages.append({"stage": "Metadata", "state": metadata_state,
                   "detail": metadata_detail})

    evidence_state, evidence_detail = _evidence_stage(data)
    stages.append({"stage": "Evidence", "state": evidence_state,
                   "detail": evidence_detail})

    if evidence_state == COMPLETE:
        stages.append({
            "stage": "Verification",
            "state": PENDING,
            "detail": "evidence ready; verification is not performed by this view",
        })
    else:
        stages.append({
            "stage": "Verification",
            "state": BLOCKED,
            "detail": "blocked until the evidence stage reaches EVIDENCE_READY",
        })

    if has_report:
        stages.append({
            "stage": "Review",
            "state": COMPLETE,
            "detail": "a persisted research report exists for this CVE",
        })
    elif evidence_state == COMPLETE:
        stages.append({
            "stage": "Review",
            "state": PENDING,
            "detail": "no persisted research report exists yet",
        })
    else:
        stages.append({
            "stage": "Review",
            "state": BLOCKED,
            "detail": "blocked by upstream evidence/verification stages",
        })

    return {
        "cve_id": cve,
        "program": _text(data.get("program"), 64),
        "has_report": bool(has_report),
        "stages": stages,
    }


def report_cves_for(
    overview: object, probe: Callable[[str], bool] | None = None
) -> set[str]:
    """CVEs with a persisted research report (existing report authority).

    Uses ``backend.research_data.has_report`` by default. Fail-soft: any error
    degrades to "no report observed" rather than taking down the page.
    """

    if not isinstance(overview, dict):
        return set()
    if probe is None:
        try:
            from backend import research_data as rdata

            probe = rdata.has_report
        except Exception:
            return set()
    found: set[str] = set()
    for view in overview.get("programs") or []:
        if not isinstance(view, dict):
            continue
        for candidate in view.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            cve = _text(candidate.get("cve_id"), 64)
            if not cve or cve in found:
                continue
            try:
                if probe(cve):
                    found.add(cve)
            except Exception:
                continue
    return found


def lifecycle_view(
    overview: object,
    *,
    report_cves: Iterable[str] | None = None,
    limit: int = DEFAULT_LIFECYCLE_LIMIT,
) -> dict:
    """Aggregate the per-candidate lifecycle into a pipeline view."""

    empty = {
        "available": False,
        "stages": list(STAGES),
        "summary": [],
        "candidates": [],
        "candidate_count": 0,
    }
    if not isinstance(overview, dict) or not overview.get("available"):
        return empty

    reported = set(report_cves or ())
    per_stage: dict[str, Counter] = {stage: Counter() for stage in STAGES}
    candidates: list[dict] = []
    candidate_count = 0
    for view in overview.get("programs") or []:
        if not isinstance(view, dict):
            continue
        for candidate in view.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            cve = _text(candidate.get("cve_id"), 64)
            lifecycle = candidate_lifecycle(candidate, has_report=cve in reported)
            candidate_count += 1
            for stage in lifecycle["stages"]:
                per_stage[stage["stage"]][stage["state"]] += 1
            if len(candidates) < max(limit, 0):
                candidates.append(lifecycle)

    summary = []
    for stage in STAGES:
        counts = {key: int(value) for key, value in per_stage[stage].items()}
        summary.append({
            "stage": stage,
            "counts": counts,
            "total": sum(counts.values()),
            "complete": counts.get(COMPLETE, 0),
            "in_progress": counts.get(IN_PROGRESS, 0),
            "blocked": counts.get(BLOCKED, 0),
            "pending": counts.get(PENDING, 0),
            "not_started": counts.get(NOT_STARTED, 0),
        })

    return {
        "available": True,
        "stages": list(STAGES),
        "summary": summary,
        "candidates": candidates,
        "candidate_count": candidate_count,
    }


__all__ = [
    "STAGES",
    "COMPLETE",
    "IN_PROGRESS",
    "BLOCKED",
    "PENDING",
    "NOT_STARTED",
    "DEFAULT_LIFECYCLE_LIMIT",
    "research_operations",
    "candidate_lifecycle",
    "report_cves_for",
    "lifecycle_view",
]
