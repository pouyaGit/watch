"""backend/research_sessions.py — Stage R25.7 session lifecycle + performance.

Human research **time-accounting only**: create/start/complete/abandon
sessions against existing R21/R25 leads, link an optional R25.5 outcome, and
expose deterministic session/economic performance views.

NEVER executes research, never contacts targets or external services, never
creates outcomes automatically, never modifies the Money Score. No network,
no DNS, no LLM, no subprocess, no Nuclei, no browser, no PoC, no findings,
no alerts, no Mongo writes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ai.knowledge.research_sessions import (
    ALLOWED_SESSION_TRANSITIONS,
    SessionNotFound,
    SessionStore,
    SessionValidationError,
)
from ai.schemas.research_session import (
    SESSION_RULE_VERSION,
    ResearchSession,
    ResearchSessionEvent,
    event_id_for,
    session_id_for,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SESSIONS_DIR = PROJECT_ROOT / "ai_data" / "research" / "sessions"

_TERMINAL_OUTCOME_STATUSES = frozenset(
    {"ACCEPTED", "DUPLICATE", "REJECTED", "NOT_APPLICABLE", "WASTED_TIME"}
)


def session_store() -> SessionStore:
    """Fresh store per call so tests can redirect the directory."""

    return SessionStore(SESSIONS_DIR)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: object) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _minutes_between(start: object, end: object) -> Optional[int]:
    """Deterministic whole-minute delta; None when unparseable or negative."""

    first, second = _parse_ts(start), _parse_ts(end)
    if first is None or second is None:
        return None
    seconds = (second - first).total_seconds()
    if seconds < 0:
        return None
    return int(round(seconds / 60))


def _resolve_lead(lead_id: str) -> tuple[str, str]:
    from backend import research_leads

    safe_id = str(lead_id or "").strip()
    try:
        lead = research_leads.get_lead(safe_id)
    except Exception as exc:
        raise SessionValidationError(f"unknown lead_id: {lead_id!r}") from exc
    cve_id, program = str(lead.get("cve_id") or ""), str(lead.get("program") or "")
    if not cve_id or not program:
        raise SessionValidationError("lead has no CVE/program attribution")
    return cve_id, program


def _minutes(value: object, field: str) -> int:
    try:
        number = int(value if value is not None else 0)
    except (TypeError, ValueError):
        raise SessionValidationError(f"{field} must be an integer") from None
    if number < 0:
        raise SessionValidationError(f"{field} must be non-negative")
    return number


def _event(
    session: ResearchSession,
    event_type: str,
    timestamp: str,
    *,
    planned_minutes: Optional[int] = None,
    actual_minutes: int = 0,
    outcome_id: str = "",
    note: str = "",
) -> ResearchSessionEvent:
    planned = (
        int(session.planned_minutes)
        if planned_minutes is None
        else int(planned_minutes)
    )
    return ResearchSessionEvent(
        event_id=event_id_for(
            session_id=session.session_id,
            event_type=event_type,
            timestamp=timestamp,
            actual_minutes=actual_minutes,
            outcome_id=outcome_id,
            note=note,
        ),
        session_id=session.session_id,
        lead_id=session.lead_id,
        cve_id=session.cve_id,
        program=session.program,
        event_type=event_type,
        timestamp=timestamp,
        planned_minutes=planned,
        actual_minutes=actual_minutes,
        outcome_id=outcome_id,
        note=note,
        rule_version=SESSION_RULE_VERSION,
        research_only=True,
    )


def _append_event(event: ResearchSessionEvent) -> tuple[ResearchSessionEvent, bool]:
    return session_store().append_event(event)


def _assert_transition(session: ResearchSession, event_type: str) -> None:
    if session.status not in ALLOWED_SESSION_TRANSITIONS:
        raise SessionValidationError(
            f"invalid stored session status: {session.status!r}"
        )
    if event_type not in ALLOWED_SESSION_TRANSITIONS[session.status]:
        raise SessionValidationError(
            f"invalid session transition: {session.status} -> {event_type}"
        )


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def create_session(
    lead_id: str,
    planned_minutes: int = 0,
    note: str = "",
    timestamp: Optional[str] = None,
) -> dict:
    """Create a PLANNED session (idempotent; never auto-started).

    Explicit researcher action only: creating a session because a lead exists
    never happens anywhere in this module.
    """

    if not str(lead_id or "").strip():
        raise SessionValidationError("lead_id is required")
    planned = _minutes(planned_minutes, "planned_minutes")
    cve_id, program = _resolve_lead(lead_id)
    session_id = session_id_for(lead_id, planned, note)
    store = session_store()
    existing = store.fold(session_id)
    if existing is not None:
        return {"created": False, "session": existing.to_view()}
    ts = str(timestamp) if timestamp else _utcnow()
    origin = ResearchSession(
        session_id=session_id,
        lead_id=str(lead_id).strip(),
        cve_id=cve_id,
        program=program,
        status="PLANNED",
        created_at=ts,
        planned_minutes=planned,
        notes=note,
    )
    _append_event(_event(origin, "CREATED", ts, planned_minutes=planned, note=note))
    return {"created": True, "session": store.get(session_id).to_view()}


def start_session(
    session_id: str,
    timestamp: Optional[str] = None,
) -> dict:
    """Explicitly start a PLANNED session (metadata only, no testing)."""

    store = session_store()
    session = store.get(session_id)
    if session.status == "IN_PROGRESS":
        return {"created": False, "session": session.to_view()}
    _assert_transition(session, "STARTED")
    ts = str(timestamp) if timestamp else _utcnow()
    _append_event(_event(session, "STARTED", ts))
    return {"created": True, "session": store.get(session_id).to_view()}


def begin_session(
    lead_id: str,
    planned_minutes: int = 0,
    note: str = "",
) -> dict:
    """Convenience for an explicit CLI/UI start: create then start."""

    created = create_session(lead_id, planned_minutes=planned_minutes, note=note)
    session = created["session"]
    if session["status"] == "PLANNED":
        started = start_session(session["session_id"])
        return {"created": created["created"], "session": started["session"]}
    return created


def _validated_outcome(session: ResearchSession, outcome_id: str) -> str:
    if not outcome_id:
        return ""
    from backend import research_outcomes

    try:
        outcome = research_outcomes.get_outcome(outcome_id)
    except Exception as exc:
        raise SessionValidationError(
            f"unknown outcome_id: {outcome_id!r}"
        ) from exc
    if str(outcome.get("lead_id") or "") != session.lead_id:
        raise SessionValidationError(
            "outcome_id does not belong to this session's lead"
        )
    return outcome_id


def complete_session(
    session_id: str,
    actual_minutes: Optional[int] = None,
    outcome_id: str = "",
    note: str = "",
    ended_at: Optional[str] = None,
) -> dict:
    """Complete an IN_PROGRESS session; optional R25.5 outcome link.

    ``actual_minutes`` may be explicit or derived from the session's
    ``started_at`` to ``ended_at`` (now when omitted). Outcome creation is
    never automatic; the outcome must already exist for the same lead.
    """

    store = session_store()
    session = store.get(session_id)
    if session.status == "COMPLETED":
        # append-only immutability: a completed session is returned as-is
        return {"created": False, "session": session.to_view()}
    _assert_transition(session, "COMPLETED")
    outcome = _validated_outcome(session, str(outcome_id or "").strip())
    ts = str(ended_at) if ended_at else _utcnow()
    if actual_minutes is None:
        derived = _minutes_between(session.started_at, ts)
        if derived is None:
            raise SessionValidationError(
                "cannot derive actual_minutes: inconsistent or unparseable "
                "started_at/ended_at"
            )
        actual = derived
    else:
        actual = _minutes(actual_minutes, "actual_minutes")
    _append_event(
        _event(
            session,
            "COMPLETED",
            ts,
            actual_minutes=actual,
            outcome_id=outcome,
            note=note,
        )
    )
    return {"created": True, "session": store.get(session_id).to_view()}


def abandon_session(
    session_id: str,
    actual_minutes: Optional[int] = None,
    note: str = "",
    ended_at: Optional[str] = None,
) -> dict:
    """Abandon a PLANNED or IN_PROGRESS session (time accounting only)."""

    store = session_store()
    session = store.get(session_id)
    if session.status == "ABANDONED":
        return {"created": False, "session": session.to_view()}
    _assert_transition(session, "ABANDONED")
    ts = str(ended_at) if ended_at else _utcnow()
    if actual_minutes is None:
        derived = _minutes_between(session.started_at, ts)
        actual = derived if derived is not None else 0
    else:
        actual = _minutes(actual_minutes, "actual_minutes")
    _append_event(
        _event(session, "ABANDONED", ts, actual_minutes=actual, note=note)
    )
    return {"created": True, "session": store.get(session_id).to_view()}


# ---------------------------------------------------------------------------
# Read-only projections
# ---------------------------------------------------------------------------


def get_session(session_id: str) -> dict:
    return session_store().get(session_id).to_view()


def list_sessions(
    limit: int = 50,
    offset: int = 0,
    lead_id: Optional[str] = None,
    cve: Optional[str] = None,
    program: Optional[str] = None,
    status: Optional[str] = None,
) -> dict:
    return session_store().list(
        limit=limit,
        offset=offset,
        lead_id=lead_id,
        cve=cve,
        program=program,
        status=status,
    )


def _time_to_outcome_minutes(session: ResearchSession) -> Optional[int]:
    """Elapsed minutes from session end to its linked terminal outcome.

    Returns None unless the session is COMPLETED, links an existing R25.5
    outcome, the outcome is terminal, and both timestamps parse with a
    non-negative delta. This is wall-clock elapsed time only — it never
    claims causality.
    """

    if session.status != "COMPLETED" or not session.outcome_id:
        return None
    from backend import research_outcomes

    try:
        outcome = research_outcomes.get_outcome(session.outcome_id)
    except Exception:
        return None
    if str(outcome.get("status") or "").upper() not in _TERMINAL_OUTCOME_STATUSES:
        return None
    return _minutes_between(session.ended_at, outcome.get("timestamp"))


def summarize_session(lead_id: str) -> dict:
    """Deterministic per-lead session aggregate (time accounting only)."""

    safe_id = str(lead_id or "").strip()
    sessions = session_store().all(lead_id=safe_id)
    planned_time = sum(int(s.planned_minutes) for s in sessions)
    actual_time = sum(int(s.actual_minutes) for s in sessions)
    with_actual = [s for s in sessions if int(s.actual_minutes) > 0]
    completed = [s for s in sessions if s.status == "COMPLETED"]
    abandoned = [s for s in sessions if s.status == "ABANDONED"]
    in_progress = [s for s in sessions if s.status == "IN_PROGRESS"]
    planned = [s for s in sessions if s.status == "PLANNED"]
    samples = [
        value
        for value in (_time_to_outcome_minutes(s) for s in completed)
        if value is not None
    ]
    return {
        "lead_id": safe_id,
        "total_sessions": len(sessions),
        "planned_sessions": len(planned),
        "in_progress_sessions": len(in_progress),
        "completed_sessions": len(completed),
        "abandoned_sessions": len(abandoned),
        "planned_time": planned_time,
        "actual_time": actual_time,
        "average_actual_minutes": (
            int(actual_time / len(with_actual)) if with_actual else 0
        ),
        "estimated_vs_actual_delta": actual_time - planned_time,
        "time_to_outcome": (
            int(sum(samples) / len(samples)) if samples else None
        ),
        "time_to_outcome_samples": len(samples),
        "rule_version": SESSION_RULE_VERSION,
        "research_only": True,
    }


def lead_execution_performance(lead_id: str) -> dict:
    """§5 composed performance view: R25.2 + R25.5 + R25.7 (read-only).

    Does not modify the Money Score, does not create outcomes, does not
    adjust any score.
    """

    from backend import research_economics
    from backend import research_outcomes

    safe_id = str(lead_id or "").strip()
    projection = research_economics.get_research_economic_value(safe_id)
    outcome_summary = research_outcomes.summarize_lead_outcomes(safe_id)
    session_summary = summarize_session(safe_id)
    return {
        "lead_id": safe_id,
        "cve_id": projection.get("cve_id"),
        "program": projection.get("program"),
        "money_score": projection.get("money_score"),
        "priority": projection.get("priority"),
        "confidence": projection.get("confidence"),
        "planned_time": session_summary["planned_time"],
        "actual_time": session_summary["actual_time"],
        "total_sessions": session_summary["total_sessions"],
        "completed_sessions": session_summary["completed_sessions"],
        "abandoned_sessions": session_summary["abandoned_sessions"],
        "accepted": outcome_summary["accepted"],
        "duplicate": outcome_summary["duplicate"],
        "rejected": outcome_summary["rejected"],
        "wasted_time": outcome_summary["wasted_time"],
        "acceptance_rate": _rate(
            outcome_summary["accepted"], outcome_summary["terminal_attempts"]
        ),
        "wasted_rate": _rate(
            outcome_summary["wasted_time"], outcome_summary["terminal_attempts"]
        ),
        "average_actual_minutes": session_summary["average_actual_minutes"],
        "estimated_vs_actual_delta": session_summary[
            "estimated_vs_actual_delta"
        ],
        "time_to_outcome": session_summary["time_to_outcome"],
        "time_to_outcome_samples": session_summary["time_to_outcome_samples"],
        "in_progress_sessions": session_summary["in_progress_sessions"],
        "rule_version": SESSION_RULE_VERSION,
        "research_only": True,
    }


def _rate(numerator: int, denominator: int) -> float:
    if not denominator:
        return 0.0
    return round(int(numerator) / int(denominator), 4)


__all__ = [
    "SessionNotFound",
    "SessionValidationError",
    "SESSIONS_DIR",
    "session_store",
    "create_session",
    "start_session",
    "begin_session",
    "complete_session",
    "abandon_session",
    "get_session",
    "list_sessions",
    "summarize_session",
    "lead_execution_performance",
]
