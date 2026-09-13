"""Stage R33.2 deterministic historical candidate ranking (pure engine).

Ranks research candidates from read-only R32.1-style memory records:

    "Which candidate deserves higher research attention based on history?"

This is a **ranking signal only**. It never executes research, never acquires
evidence, never contacts a target, never calls an LLM and never touches Mongo.
It never uses or modifies the Money Score and never modifies the R29 queue.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Deterministic factor scoring only (documented deltas), stable sort order and
  byte-identical repeated output. No randomness, statistical model, ML,
  embeddings or probability.
- Read-only: inputs are never mutated; malformed records are skipped, never
  repaired.
- Privacy: only bounded counts, closed signal codes and caller-supplied
  candidate identity tokens are retained.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import CONFIDENCE_BLOCKERS
from ai.schemas.evidence_research_outcome import (
    OUTCOME_COMPLETED,
    OUTCOME_DEFERRED,
    OUTCOME_IN_PROGRESS,
    OUTCOME_WAITING_FOR_EVIDENCE,
)
from ai.schemas.evidence_feedback_calibration import AREA_TECHNOLOGY
from ai.schemas.historical_candidate_ranking import (
    MAX_CANDIDATES,
    MAX_RECORDS,
    MAX_SIGNALS,
    REASON_HISTORICAL_SCORE,
    REASON_NO_HISTORY,
    REASON_SINGLE_CANDIDATE,
    RESEARCH_CANDIDATE_RANKING_RULE_VERSION,
    SCORE_MAX,
    SCORE_MIN,
    SIGNAL_EVIDENCE_AVAILABILITY,
    SIGNAL_HISTORICAL_SUCCESS,
    SIGNAL_REPEATED_DEFER,
    SIGNAL_REPEATED_MISSING_EVIDENCE,
    SIGNAL_REPEATED_SUCCESS,
    SIGNAL_TECHNOLOGY_SUCCESS,
    SIGNAL_UNRESOLVED_BLOCKERS,
    HistoricalCandidateRankingPlan,
    historical_candidate_ranking_plan_projection,
)

RESEARCH_CANDIDATE_RANKING_PLANNER_RULE_VERSION = "r33-2"
RULE_VERSION = RESEARCH_CANDIDATE_RANKING_PLANNER_RULE_VERSION

IDENTITY_UNSPECIFIED = "UNSPECIFIED"

MIN_RECURRENCE = 2
MAX_BLOCKER_PENALTY = 3

DELTA_HISTORICAL_SUCCESS = 4
DELTA_REPEATED_SUCCESS = 2
DELTA_TECHNOLOGY_SUCCESS = 1
DELTA_EVIDENCE_AVAILABILITY = 1
DELTA_REPEATED_DEFER = -3
DELTA_REPEATED_MISSING_EVIDENCE = -2
DELTA_UNRESOLVED_BLOCKER = -1


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _records(candidates: object) -> list[dict]:
    if isinstance(candidates, dict):
        items: list = [candidates]
    elif isinstance(candidates, (list, tuple)):
        items = list(candidates)
    else:
        return []
    out: list[dict] = []
    for entry in items[:MAX_RECORDS]:
        if isinstance(entry, dict) and entry:
            out.append(entry)
    return out


def _group(records: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for record in records:
        identity = _text(record.get("candidate_identity"))
        identity = identity or IDENTITY_UNSPECIFIED
        groups.setdefault(identity, []).append(record)
        if len(groups) > MAX_CANDIDATES and identity not in groups:
            break
    return groups


def _latest_area(records: list[dict]) -> str:
    for record in reversed(records):
        area = _upper(record.get("improvement_area"))
        if area:
            return area
    return ""


def _recurring_blockers(records: list[dict]) -> list[str]:
    counts: dict[str, int] = {}
    for record in records:
        seen: set[str] = set()
        for item in record.get("blockers") or ():
            code = _upper(item)
            if code in CONFIDENCE_BLOCKERS and code not in seen:
                seen.add(code)
        for code in seen:
            counts[code] = counts.get(code, 0) + 1
    return [
        code for code, count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0])
        )
        if count >= MIN_RECURRENCE
    ]


def _candidate_score(records: list[dict]) -> dict:
    successful = sum(
        1 for record in records
        if _upper(record.get("outcome")) == OUTCOME_COMPLETED
    )
    in_progress = sum(
        1 for record in records
        if _upper(record.get("outcome")) == OUTCOME_IN_PROGRESS
    )
    waiting = sum(
        1 for record in records
        if _upper(record.get("outcome")) == OUTCOME_WAITING_FOR_EVIDENCE
    )
    deferred = sum(
        1 for record in records
        if _upper(record.get("outcome")) == OUTCOME_DEFERRED
    )
    recurring = _recurring_blockers(records)

    score = 0
    signals: list[str] = []

    if successful >= 1:
        score += DELTA_HISTORICAL_SUCCESS
        signals.append(SIGNAL_HISTORICAL_SUCCESS)
    if successful >= 2:
        score += DELTA_REPEATED_SUCCESS
        signals.append(SIGNAL_REPEATED_SUCCESS)
    if successful >= 1 and _latest_area(records) == AREA_TECHNOLOGY:
        score += DELTA_TECHNOLOGY_SUCCESS
        signals.append(SIGNAL_TECHNOLOGY_SUCCESS)
    if waiting + in_progress >= 1:
        score += DELTA_EVIDENCE_AVAILABILITY
        signals.append(SIGNAL_EVIDENCE_AVAILABILITY)

    if deferred >= MIN_RECURRENCE:
        score += DELTA_REPEATED_DEFER
        signals.append(SIGNAL_REPEATED_DEFER)
    if waiting >= MIN_RECURRENCE:
        score += DELTA_REPEATED_MISSING_EVIDENCE
        signals.append(SIGNAL_REPEATED_MISSING_EVIDENCE)
    if recurring:
        penalty = max(
            -MAX_BLOCKER_PENALTY,
            DELTA_UNRESOLVED_BLOCKER * len(recurring),
        )
        score += penalty
        signals.append(SIGNAL_UNRESOLVED_BLOCKERS)

    score = max(SCORE_MIN, min(SCORE_MAX, score))
    return {
        "score": score,
        "signals": signals[:MAX_SIGNALS],
        "successful": successful,
    }


def rank_historical_candidates(candidates: object = None) -> dict:
    """Rank candidates from memory records using closed historical signals.

    Each candidate record is an R32.1-style snapshot dict. Records are grouped
    by ``candidate_identity``; the deterministic score is the bounded sum of
    documented positive/negative deltas. Candidates sort by score descending,
    successful count descending, then identity ascending.
    """

    records = _records(candidates)
    groups = _group(records)

    if not groups:
        plan = HistoricalCandidateRankingPlan(
            rule_version=RESEARCH_CANDIDATE_RANKING_RULE_VERSION,
            candidate_scores=[],
            ranking_reason=REASON_NO_HISTORY,
            historical_signals=[],
            research_only=True,
        )
        return historical_candidate_ranking_plan_projection(plan)

    scored = []
    observed: set[str] = set()
    for identity, group in groups.items():
        result = _candidate_score(group)
        observed.update(result["signals"])
        scored.append(
            {
                "candidate_identity": identity,
                "score": result["score"],
                "records": len(group),
                "signals": result["signals"],
                "successful": result["successful"],
            }
        )

    scored.sort(
        key=lambda item: (
            -item["score"], -item["successful"], item["candidate_identity"],
        )
    )
    candidate_scores = [
        {
            "candidate_identity": item["candidate_identity"],
            "score": item["score"],
            "records": item["records"],
            "signals": item["signals"],
        }
        for item in scored
    ][:MAX_CANDIDATES]

    plan = HistoricalCandidateRankingPlan(
        rule_version=RESEARCH_CANDIDATE_RANKING_RULE_VERSION,
        candidate_scores=candidate_scores,
        ranking_reason=(
            REASON_SINGLE_CANDIDATE
            if len(candidate_scores) == 1
            else REASON_HISTORICAL_SCORE
        ),
        historical_signals=sorted(observed),
        research_only=True,
    )
    return historical_candidate_ranking_plan_projection(plan)


__all__ = [
    "RESEARCH_CANDIDATE_RANKING_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "IDENTITY_UNSPECIFIED",
    "MIN_RECURRENCE",
    "DELTA_HISTORICAL_SUCCESS",
    "DELTA_REPEATED_SUCCESS",
    "DELTA_TECHNOLOGY_SUCCESS",
    "DELTA_EVIDENCE_AVAILABILITY",
    "DELTA_REPEATED_DEFER",
    "DELTA_REPEATED_MISSING_EVIDENCE",
    "DELTA_UNRESOLVED_BLOCKER",
    "rank_historical_candidates",
]
