"""backend/product_validation.py — Stage R27.1 validation composition.

Read-only composition: joins the existing R26.2/R26.1 action-queue state with
the raw R25.7 session records and R25.5 outcome records per lead, then calls
the pure deterministic engine in ``ai.knowledge.product_validation``.

No new score, no persistence, no writes, no network, no DNS, no LLM, no
subprocess, no target interaction, no Nuclei, no browser, no PoC execution,
no findings, no alerts, no Mongo writes. Money Score is copied verbatim.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ai.knowledge.product_validation import (
    CONTINUE_PRODUCTIZATION,
    DEFAULT_MIN_LEADS,
    DEFAULT_MIN_SESSIONS,
    DEFAULT_MIN_TERMINAL_OUTCOMES,
    VALIDATION_VERSION,
    build_product_validation_report as _build_report,
    build_validation_dataset,
)

MAX_RECORDS = 100


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_sessions(lead_id: str) -> tuple[list[dict], str]:
    """(records, data_status) — status is PRESENT / NONE / UNAVAILABLE."""

    from backend import research_sessions

    try:
        items = research_sessions.list_sessions(
            limit=MAX_RECORDS, offset=0, lead_id=lead_id)["items"]
    except Exception:
        return [], "UNAVAILABLE"
    records = [s for s in items or [] if isinstance(s, dict)]
    return records, ("PRESENT" if records else "NONE")


def _read_outcomes(lead_id: str) -> tuple[list[dict], str]:
    from backend import research_outcomes

    try:
        items = research_outcomes.list_outcomes(
            limit=MAX_RECORDS, offset=0, lead_id=lead_id)["items"]
    except Exception:
        return [], "UNAVAILABLE"
    records = [o for o in items or [] if isinstance(o, dict)]
    return records, ("PRESENT" if records else "NONE")


def build_product_validation_report(
    min_sessions: int = DEFAULT_MIN_SESSIONS,
    min_outcomes: int = DEFAULT_MIN_TERMINAL_OUTCOMES,
    min_leads: int = DEFAULT_MIN_LEADS,
    cve: Optional[str] = None,
    program: Optional[str] = None,
    previous_status_by_lead: Optional[dict] = None,
    generated_at: Optional[str] = None,
) -> dict:
    """Build the deterministic validation report for the current corpus.

    Fail-soft: a failing action queue degrades to an empty dataset; session/
    outcome read failures become explicit UNAVAILABLE (never silent zeros).
    """

    from backend import research_action_queue

    try:
        actions = research_action_queue.list_actions(
            limit=research_action_queue.MAX_ACTIONS,
            offset=0,
            cve=cve,
            program=program,
        )["items"]
    except Exception:
        actions = []

    sessions_by_lead: dict = {}
    outcomes_by_lead: dict = {}
    availability_by_lead: dict = {}
    for action in actions or []:
        if not isinstance(action, dict):
            continue
        lead_id = str(action.get("lead_id") or "")
        if not lead_id:
            continue
        sessions, session_status = _read_sessions(lead_id)
        outcomes, outcome_status = _read_outcomes(lead_id)
        sessions_by_lead[lead_id] = sessions
        outcomes_by_lead[lead_id] = outcomes
        availability_by_lead[lead_id] = {
            "session_data": session_status,
            "outcome_data": outcome_status,
        }

    dataset = build_validation_dataset(
        actions,
        sessions_by_lead=sessions_by_lead,
        outcomes_by_lead=outcomes_by_lead,
        availability_by_lead=availability_by_lead,
    )
    return _build_report(
        dataset,
        min_sessions=min_sessions,
        min_terminal_outcomes=min_outcomes,
        min_leads=min_leads,
        previous_status_by_lead=previous_status_by_lead,
        generated_at=generated_at if generated_at is not None else _utcnow(),
    )


def product_validation_summary(
    min_sessions: int = DEFAULT_MIN_SESSIONS,
    min_outcomes: int = DEFAULT_MIN_TERMINAL_OUTCOMES,
    min_leads: int = DEFAULT_MIN_LEADS,
    cve: Optional[str] = None,
    program: Optional[str] = None,
) -> dict:
    """Compact UI/CLI-safe validation indicator (no misleading rates)."""

    report = build_product_validation_report(
        min_sessions=min_sessions,
        min_outcomes=min_outcomes,
        min_leads=min_leads,
        cve=cve,
        program=program,
    )
    totals = report["totals"]
    if totals["leads"] <= 0:
        data_status = "NO_DATA"
    elif report["product_decision"] == CONTINUE_PRODUCTIZATION:
        data_status = "SUFFICIENT"
    else:
        data_status = "INSUFFICIENT"
    return {
        "validation_version": VALIDATION_VERSION,
        "data_status": data_status,
        "product_decision": report["product_decision"],
        "leads": totals["leads"],
        "sessions": totals["sessions"],
        "terminal_outcomes": totals["terminal_outcomes"],
        "supported_hypotheses": list(report["supported_hypotheses"]),
        "research_only": True,
    }
