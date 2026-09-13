"""Stage R32.2 deterministic research history aggregator (pure engine).

Aggregates multiple read-only R32.1 research memory snapshots into a
deterministic history plan:

    "What does the accumulated research history look like?"

This is an **aggregation signal only**. It never executes research, never
acquires evidence, never contacts a target, never calls an LLM and never
touches Mongo. It counts existing snapshots only, never modifies history and
never infers a vulnerability.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic: fixed counting rules, closed vocabularies and a stable sort
  order (``count`` descending, code ascending). Byte-identical repeated
  output; no randomness, timestamps, hashes or external state.
- Aggregate-only and read-only: inputs are never mutated; non-dict and empty
  entries are skipped; nothing is repaired.
- Privacy: only closed codes and bounded counts are retained.
"""

from __future__ import annotations

from ai.knowledge.research_memory_snapshot import MAX_BLOCKERS
from ai.schemas.evidence_confidence import CONFIDENCE_BLOCKERS
from ai.schemas.evidence_feedback_calibration import (
    AREA_NONE,
    IMPROVEMENT_AREAS,
)
from ai.schemas.evidence_research_outcome import (
    OUTCOME_COMPLETED,
    OUTCOME_DEFERRED,
    OUTCOME_WAITING_FOR_EVIDENCE,
)
from ai.schemas.research_history import (
    MAX_PATTERNS,
    MAX_RECORDS,
    MAX_RECURRING,
    RESEARCH_HISTORY_RULE_VERSION,
    ResearchHistoryPlan,
    research_history_plan_projection,
)
from ai.schemas.research_pattern_plan import PATTERN_BY_AREA

RESEARCH_HISTORY_AGGREGATOR_RULE_VERSION = "r32-2"
RULE_VERSION = RESEARCH_HISTORY_AGGREGATOR_RULE_VERSION

MIN_RECURRENCE = 2

_MAX_BLOCKERS = MAX_BLOCKERS


def _upper(value: object) -> str:
    return str(value if value is not None else "").strip().upper()


def _records(snapshots: object) -> list[dict]:
    """Return bounded valid snapshot entries (dicts only, order preserved)."""

    if isinstance(snapshots, dict):
        candidates: list = [snapshots]
    elif isinstance(snapshots, (list, tuple)):
        candidates = list(snapshots)
    else:
        return []
    out: list[dict] = []
    for entry in candidates[:MAX_RECORDS]:
        if isinstance(entry, dict) and entry:
            out.append(entry)
    return out


def _counts(values: list[str]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for value in values:
        if value:
            counts[value] = counts.get(value, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def count_patterns(snapshots: object = None) -> list[tuple[str, int]]:
    """Deterministic structural-pattern counts across memory snapshots."""

    areas = [
        _upper(record.get("improvement_area"))
        for record in _records(snapshots)
    ]
    patterns = [
        PATTERN_BY_AREA[area] for area in areas
        if area in PATTERN_BY_AREA
    ]
    return _counts(patterns)


def aggregate_research_history(snapshots: object = None) -> dict:
    """Aggregate R32.1 snapshots into a deterministic history plan.

    Non-dict/empty entries are skipped. Counts classify by the snapshot
    ``outcome``; recurring blockers and improvement areas require at least
    ``MIN_RECURRENCE`` occurrences and are sorted by count then code.
    """

    records = _records(snapshots)
    total_records = len(records)

    successful = sum(
        1 for record in records
        if _upper(record.get("outcome")) == OUTCOME_COMPLETED
    )
    deferred = sum(
        1 for record in records
        if _upper(record.get("outcome")) == OUTCOME_DEFERRED
    )
    waiting = sum(
        1 for record in records
        if _upper(record.get("outcome")) == OUTCOME_WAITING_FOR_EVIDENCE
    )

    blocker_counts = _counts(
        [
            _upper(code)
            for record in records
            for code in (record.get("blockers") or ())
            if _upper(code) in CONFIDENCE_BLOCKERS
        ]
    )
    recurring_blockers = [
        code for code, count in blocker_counts
        if count >= MIN_RECURRENCE
    ][:MAX_RECURRING]

    area_counts = _counts(
        [
            _upper(record.get("improvement_area"))
            for record in records
            if _upper(record.get("improvement_area")) in IMPROVEMENT_AREAS
            and _upper(record.get("improvement_area")) != AREA_NONE
        ]
    )
    recurring_areas = [
        area for area, count in area_counts
        if count >= MIN_RECURRENCE
    ][:MAX_RECURRING]

    research_patterns = [
        {"pattern": pattern, "count": count}
        for pattern, count in count_patterns(records)
    ][:MAX_PATTERNS]

    plan = ResearchHistoryPlan(
        rule_version=RESEARCH_HISTORY_RULE_VERSION,
        total_records=total_records,
        successful_count=successful,
        deferred_count=deferred,
        waiting_count=waiting,
        recurring_blockers=recurring_blockers,
        recurring_improvement_areas=recurring_areas,
        research_patterns=research_patterns,
        research_only=True,
    )
    return research_history_plan_projection(plan)


__all__ = [
    "RESEARCH_HISTORY_AGGREGATOR_RULE_VERSION",
    "RULE_VERSION",
    "MIN_RECURRENCE",
    "MAX_RECORDS",
    "MAX_RECURRING",
    "MAX_PATTERNS",
    "_MAX_BLOCKERS",
    "count_patterns",
    "aggregate_research_history",
]
