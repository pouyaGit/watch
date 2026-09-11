"""backend/research_outcomes.py — Stage R25.5 outcome projection layer.

Read/write adapter around the append-only :class:`OutcomeStore` for economic
research leads. Adds lead attribution (lead_id -> cve/program via the existing
R21 projection), deterministic timestamps and bounded aggregations for future
Money Score calibration.

The Money Score is NOT modified here; summaries are data collection only.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no PoC execution, no 5B-5J, no findings, no alerts, no Mongo writes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ai.knowledge.research_outcomes import (
    OutcomeStore,
    OutcomeValidationError,
)
from ai.schemas.research_outcome import (
    OUTCOME_RULE_VERSION,
    OUTCOME_STATUSES,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTCOMES_DIR = PROJECT_ROOT / "ai_data" / "research" / "outcomes"

MAX_SUMMARY_LEADS = 100


def outcome_store() -> OutcomeStore:
    """Fresh store per call so tests can redirect the directory."""

    return OutcomeStore(OUTCOMES_DIR)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_time(value: object) -> int:
    try:
        number = int(value if value is not None else 0)
    except (TypeError, ValueError):
        raise OutcomeValidationError(
            "time_spent_minutes must be an integer"
        ) from None
    if number < 0:
        raise OutcomeValidationError(
            "time_spent_minutes must be non-negative"
        )
    return number


def _resolve_lead(lead_id: str) -> tuple[str, str]:
    """Resolve lead_id -> (cve_id, program) via the existing R21 projection.

    Fail-closed: an unknown lead is rejected so an outcome can never be
    attributed to a CVE/program that does not exist in the research pipeline.
    """

    from backend import research_leads

    safe_id = str(lead_id or "").strip()
    try:
        lead = research_leads.get_lead(safe_id)
    except Exception as exc:
        raise OutcomeValidationError(f"unknown lead_id: {lead_id!r}") from exc
    return str(lead.get("cve_id") or ""), str(lead.get("program") or "")


def record_outcome(
    lead_id: str,
    status: str,
    time_spent_minutes: int = 0,
    note: str = "",
    source: str = "MANUAL",
    timestamp: Optional[str] = None,
) -> dict:
    """Validate, attribute and append one outcome (idempotent).

    Returns ``{"created": bool, "outcome": {...}}``. Never executes research,
    never contacts external sources, never predicts payouts.
    """

    if not str(lead_id or "").strip():
        raise OutcomeValidationError("lead_id is required")
    if not str(status or "").strip():
        raise OutcomeValidationError("status is required")
    minutes = _normalize_time(time_spent_minutes)
    note_text = str(note or "")
    cve_id, program = _resolve_lead(lead_id)
    if not cve_id or not program:
        raise OutcomeValidationError(
            "lead has no CVE/program attribution"
        )
    record, created = outcome_store().append(
        lead_id=str(lead_id).strip(),
        cve_id=cve_id,
        program=program,
        status=status,
        timestamp=str(timestamp) if timestamp else _utcnow(),
        researcher_note=note_text,
        time_spent_minutes=minutes,
        source=str(source or "MANUAL").strip().upper() or "MANUAL",
    )
    return {"created": created, "outcome": record.model_dump(mode="json")}


def list_outcomes(
    limit: int = 50,
    offset: int = 0,
    lead_id: Optional[str] = None,
    cve: Optional[str] = None,
    program: Optional[str] = None,
    status: Optional[str] = None,
) -> dict:
    """Capped deterministic outcomes slice (read-only)."""

    if status:
        from backend.research_data import ResearchDataError

        text = str(status).strip().upper()
        if text not in OUTCOME_STATUSES:
            raise ResearchDataError(f"invalid outcome status: {status!r}")
    return outcome_store().list(
        limit=limit,
        offset=offset,
        lead_id=lead_id,
        cve=cve,
        program=program,
        status=status,
    )


def get_outcome(outcome_id: str) -> dict:
    """One outcome by deterministic id (404-style when absent)."""

    record = outcome_store().get(outcome_id)
    return record.model_dump(mode="json")


def _confidence_for(terminal_attempts: int) -> str:
    """Deterministic outcome-data-quality class (collection volume only)."""

    if terminal_attempts <= 0:
        return "NONE"
    if terminal_attempts <= 2:
        return "LOW"
    if terminal_attempts <= 4:
        return "MEDIUM"
    return "HIGH"


def _empty_summary(lead_id: str) -> dict:
    return {
        "lead_id": lead_id,
        "attempts": 0,
        "terminal_attempts": 0,
        "accepted": 0,
        "duplicate": 0,
        "rejected": 0,
        "not_applicable": 0,
        "wasted_time": 0,
        "in_progress": 0,
        "total_time_spent_minutes": 0,
        "average_time_spent_minutes": 0,
        "latest_outcome": None,
        "outcome_confidence": "NONE",
        "data_quality": "NONE",
        "rule_version": OUTCOME_RULE_VERSION,
        "research_only": True,
    }


def summarize_lead_outcomes(lead_id: str) -> dict:
    """Bounded per-lead outcome aggregation (how did this lead perform?).

    Read-only; never touches the Money Score.
    """

    safe_id = str(lead_id or "").strip()
    records = outcome_store().all(lead_id=safe_id)
    summary = _empty_summary(safe_id)
    if not records:
        return summary

    counts = {status: 0 for status in OUTCOME_STATUSES}
    total_time = 0
    terminal_time = 0
    for record in records:
        status = record.status
        if status in counts:
            counts[status] += 1
        minutes = max(0, int(record.time_spent_minutes or 0))
        total_time += minutes
        if status != "IN_PROGRESS":
            terminal_time += minutes
    attempts = len(records)
    terminal = attempts - counts["IN_PROGRESS"]
    records.sort(key=lambda r: r.outcome_id)
    records.sort(key=lambda r: str(r.timestamp or ""), reverse=True)
    latest = records[0].model_dump(mode="json")
    summary.update(
        {
            "attempts": attempts,
            "terminal_attempts": max(0, terminal),
            "accepted": counts["ACCEPTED"],
            "duplicate": counts["DUPLICATE"],
            "rejected": counts["REJECTED"],
            "not_applicable": counts["NOT_APPLICABLE"],
            "wasted_time": counts["WASTED_TIME"],
            "in_progress": counts["IN_PROGRESS"],
            "total_time_spent_minutes": total_time,
            # average is over terminal outcomes only (in-progress time is
            # recorded but cannot yet be judged as spent or wasted)
            "average_time_spent_minutes": (
                int(terminal_time / terminal) if terminal > 0 else 0
            ),
            "latest_outcome": latest,
            "outcome_confidence": _confidence_for(terminal),
            "data_quality": _confidence_for(terminal),
        }
    )
    return summary


def lead_performance(lead_id: str) -> dict:
    """Feedback-readiness projection for a future R25.6 calibration stage.

    Answers "How did this lead perform historically?" with deterministic,
    bounded aggregates. It does NOT modify or recompute the Money Score.
    """

    summary = summarize_lead_outcomes(lead_id)
    terminal = int(summary["terminal_attempts"])
    accepted = int(summary["accepted"])
    duplicate = int(summary["duplicate"])
    rejected = int(summary["rejected"])
    wasted = int(summary["wasted_time"])
    not_applicable = int(summary["not_applicable"])
    return {
        "lead_id": summary["lead_id"],
        "attempts": summary["attempts"],
        "terminal_attempts": terminal,
        "accepted": accepted,
        "duplicate": duplicate,
        "rejected": rejected,
        "not_applicable": not_applicable,
        "wasted_time": wasted,
        "in_progress": summary["in_progress"],
        "acceptance_rate": (
            round(accepted / terminal, 4) if terminal > 0 else 0.0
        ),
        "duplicate_rate": (
            round(duplicate / terminal, 4) if terminal > 0 else 0.0
        ),
        "wasted_rate": round(wasted / terminal, 4) if terminal > 0 else 0.0,
        "total_time_spent_minutes": summary["total_time_spent_minutes"],
        "average_time_spent_minutes": summary["average_time_spent_minutes"],
        "latest_outcome": summary["latest_outcome"],
        "outcome_confidence": summary["outcome_confidence"],
        "data_quality": summary["data_quality"],
        "rule_version": summary["rule_version"],
        "research_only": True,
    }


def summarize_economic_outcomes() -> dict:
    """Global bounded outcome summary across all recorded leads."""

    store = outcome_store()
    records = store.all()
    counts = {status: 0 for status in OUTCOME_STATUSES}
    total_time = 0
    terminal_time = 0
    terminal = 0
    lead_ids: set[str] = set()
    for record in records:
        status = record.status
        if status in counts:
            counts[status] += 1
        if status != "IN_PROGRESS":
            terminal += 1
        minutes = max(0, int(record.time_spent_minutes or 0))
        total_time += minutes
        if status != "IN_PROGRESS":
            terminal_time += minutes
        lead_ids.add(record.lead_id)
    # Per-lead rollup, bounded and deterministic.
    leads = [
        summarize_lead_outcomes(lead_id)
        for lead_id in sorted(lead_ids)[:MAX_SUMMARY_LEADS]
    ]
    records.sort(key=lambda r: r.outcome_id)
    records.sort(key=lambda r: str(r.timestamp or ""), reverse=True)
    latest = records[0].model_dump(mode="json") if records else None
    return {
        "total_outcomes": len(records),
        "attempts": len(records),
        "terminal_attempts": terminal,
        "accepted": counts["ACCEPTED"],
        "duplicate": counts["DUPLICATE"],
        "rejected": counts["REJECTED"],
        "not_applicable": counts["NOT_APPLICABLE"],
        "wasted_time": counts["WASTED_TIME"],
        "in_progress": counts["IN_PROGRESS"],
        "total_time_spent_minutes": total_time,
        "average_time_spent_minutes": (
            int(terminal_time / terminal) if terminal > 0 else 0
        ),
        "leads_with_outcomes": len(lead_ids),
        "latest_outcome": latest,
        "outcome_confidence": _confidence_for(terminal),
        "data_quality": _confidence_for(terminal),
        "leads": leads,
        "rule_version": OUTCOME_RULE_VERSION,
        "research_only": True,
    }
