"""Stage R83 deterministic AI activity / runtime status core (pure engine).

Answers:

    "What is the AI research runtime actually doing right now, and what did
     it do during the daily 12:00-00:00 Tehran work window?"

This core is **pure**: it derives the bounded activity contract from
already-collected facts (agent run records, research case records, a lock
liveness probe result, scheduler window configuration and a clock). It does
no I/O, no network, no LLM, no Mongo and no execution; the read-only collector
in ``backend/research_activity.py`` gathers the facts.

Truthfulness rules:

- Only fields that can be derived from real persisted state are populated.
- Anything not observable is ``null`` and named in
  ``observability.unavailable_fields`` (no fake heartbeat, no fake progress,
  no simulated stages).
- All user-facing daily-window math uses Asia/Tehran; the server timezone is
  never used.
- ``UNKNOWN`` means "the runtime state could not be observed" - it never
  means failure, and it is documented as such.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Mapping
from zoneinfo import ZoneInfo

from ai.knowledge.research_outcome_planner import SAFETY_BLOCK

RULE_VERSION = "r83-1"

TEHRAN = ZoneInfo("Asia/Tehran")
DEFAULT_TIMEZONE = "Asia/Tehran"
DEFAULT_WINDOW_START = "12:00"
DEFAULT_WINDOW_END = "00:00"

MAX_RUNS = 50
MAX_CASES = 32
MAX_TEXT_CHARS = 320
MAX_NOTES = 12

_SECRET_NOTE_RE = re.compile(
    r"(?i)(token|key|secret|password|authorization|bearer)\s*[:=]\s*\S+"
)

#: Closed overall status vocabulary.
STATUS_IDLE = "IDLE"
STATUS_RUNNING = "RUNNING"
STATUS_WAITING_FOR_EVIDENCE = "WAITING_FOR_EVIDENCE"
STATUS_COMPLETED = "COMPLETED"
STATUS_COMPLETED_WITH_REJECTIONS = "COMPLETED_WITH_REJECTIONS"
STATUS_ERROR = "ERROR"
STATUS_UNKNOWN = "UNKNOWN"

STATUSES: tuple[str, ...] = (
    STATUS_IDLE,
    STATUS_RUNNING,
    STATUS_WAITING_FOR_EVIDENCE,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_REJECTIONS,
    STATUS_ERROR,
    STATUS_UNKNOWN,
)

#: Real agent run statuses (ai.research_agent.scheduler) -> activity status.
RUN_STATUS_TO_ACTIVITY: dict[str, str] = {
    "RESEARCH_COMPLETED": STATUS_COMPLETED,
    "RESEARCH_PARTIAL": STATUS_COMPLETED_WITH_REJECTIONS,
    "RESEARCH_FAILED": STATUS_ERROR,
    "RESEARCH_BLOCKED": STATUS_IDLE,
}

LOCK_HELD = "held"
LOCK_FREE = "free"
LOCK_UNAVAILABLE = "unavailable"
LOCK_STATES: tuple[str, ...] = (LOCK_HELD, LOCK_FREE, LOCK_UNAVAILABLE)


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    text = " ".join(str(value if value is not None else "").split())
    return text[:limit]


def _parse_hhmm(value: object, default: str) -> tuple[int, int]:
    text = _text(value, 5) or default
    parts = text.split(":")
    if len(parts) != 2:
        parts = default.split(":")
    try:
        hour, minute = int(parts[0]), int(parts[1])
    except (TypeError, ValueError):
        hour, minute = int(default.split(":")[0]), int(default.split(":")[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        hour, minute = int(default.split(":")[0]), int(default.split(":")[1])
    return hour, minute


def to_tehran(value: object) -> datetime | None:
    """Parse an ISO timestamp (or datetime) into an aware Tehran datetime.

    Naive values are interpreted as Tehran wall-clock, matching the existing
    ``backend.tz`` storage convention. Unparseable values return ``None``.
    """

    if isinstance(value, datetime):
        moment = value
    else:
        text = _text(value, 64)
        if not text:
            return None
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=TEHRAN)
    try:
        return moment.astimezone(TEHRAN)
    except (OverflowError, ValueError):
        return None


def window_bounds(
    now: datetime,
    window_start: object = DEFAULT_WINDOW_START,
    window_end: object = DEFAULT_WINDOW_END,
) -> tuple[datetime, datetime]:
    """The daily window containing ``now`` (start inclusive, end exclusive).

    Supports windows crossing midnight (the real 12:00 -> 00:00 window).
    """

    moment = to_tehran(now) or datetime.now(TEHRAN)
    start_h, start_m = _parse_hhmm(window_start, DEFAULT_WINDOW_START)
    end_h, end_m = _parse_hhmm(window_end, DEFAULT_WINDOW_END)

    def _at(day: datetime, hour: int, minute: int) -> datetime:
        return day.replace(hour=hour, minute=minute, second=0, microsecond=0)

    start_today = _at(moment, start_h, start_m)
    if (start_h, start_m) == (end_h, end_m):
        # Zero-length window: use the previous 24h as a bounded window.
        return start_today - timedelta(days=1), start_today
    if (start_h, start_m) < (end_h, end_m):
        if moment < start_today:
            start = start_today - timedelta(days=1)
            return start, _at(start, end_h, end_m)
        return start_today, _at(start_today, end_h, end_m)
    # Crossing midnight (e.g. 12:00 -> 00:00).
    if moment.hour * 60 + moment.minute >= start_h * 60 + start_m:
        return start_today, _at(start_today + timedelta(days=1), end_h, end_m)
    start = start_today - timedelta(days=1)
    return start, _at(start_today, end_h, end_m)


def in_window(
    moment: datetime,
    window_start: object = DEFAULT_WINDOW_START,
    window_end: object = DEFAULT_WINDOW_END,
) -> bool:
    start, end = window_bounds(moment, window_start, window_end)
    return start <= to_tehran(moment) < end


def _iso(moment: datetime | None) -> str:
    return moment.isoformat() if moment else ""


def _duration_seconds(started: datetime | None, finished: datetime | None) -> float | None:
    if started is None or finished is None:
        return None
    seconds = (finished - started).total_seconds()
    return round(seconds, 3) if seconds >= 0 else None


def _bounded_failure(value: object) -> str:
    """Only safe error identifiers are kept (type/code text), never stacks."""

    if isinstance(value, Mapping):
        candidate = (
            value.get("error")
            or value.get("code")
            or value.get("type")
            or ""
        )
    else:
        candidate = value
    text = _text(candidate, 80)
    if not text:
        return ""
    # Keep token-shaped identifiers only; never paths or stack text.
    if any(char in text for char in ("/", "\\", "\n", "\t", ":")):
        text = text.split(":", 1)[0]
        text = "".join(
            char for char in text if char.isalnum() or char in ("_", "-", ".")
        )
    return text[:80]


def _block(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _top_reason(value: object) -> str:
    """Most frequent closed reason code (deterministic tie-break by code)."""

    counts = value if isinstance(value, Mapping) else {}
    best_code = ""
    best_count = 0
    for code, count in counts.items():
        try:
            number = int(count)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        text = _text(code, 64)
        if not text:
            continue
        if number > best_count or (
            number == best_count and (not best_code or text < best_code)
        ):
            best_code, best_count = text, number
    return best_code


def _run_projection(record: Mapping, window_start: datetime, window_end: datetime) -> dict:
    started = to_tehran(record.get("started_at"))
    finished = to_tehran(record.get("completed_at"))
    raw_status = _text(record.get("status"), 40).upper()
    results = [
        entry
        for entry in record.get("results") or ()
        if isinstance(entry, Mapping)
    ]
    failures = [
        entry
        for entry in record.get("failures") or ()
        if isinstance(entry, (Mapping, str))
    ]
    evidence_total = 0
    sources_total = 0
    for entry in results:
        try:
            evidence_total += int(entry.get("evidence") or 0)
            sources_total += int(entry.get("sources") or 0)
        except (TypeError, ValueError):
            continue
    plans = _text(record.get("plans_processed"), 8)
    try:
        plans_processed = int(plans or 0)
    except ValueError:
        plans_processed = 0
    single = results[0] if len(results) == 1 else {}
    activity_status = RUN_STATUS_TO_ACTIVITY.get(raw_status, STATUS_UNKNOWN)
    case_context = _block(record.get("case_context"))
    case_scheduling = _block(record.get("case_scheduling"))
    case_summary = _block(case_scheduling.get("summary"))
    return {
        "run_id": _text(record.get("run_id"), 64),
        "status": activity_status,
        "agent_status": raw_status,
        "skipped": _text(record.get("skipped"), 40),
        "started_at": _iso(started),
        "finished_at": _iso(finished),
        "duration_seconds": _duration_seconds(started, finished),
        "in_window": bool(
            started is not None and window_start <= started < window_end
        ),
        "plans_selected": _safe_int(record.get("plans_selected")),
        "plans_processed": plans_processed,
        "result_count": len(results),
        "evidence_count": evidence_total,
        "sources_count": sources_total,
        "failure_count": len(failures),
        "case_aware_state": _text(record.get("case_aware_state"), 32),
        "case_contexts": _safe_int(case_context.get("valid")),
        "case_malformed_contexts": _safe_int(case_context.get("malformed")),
        "case_eligible_plans": _safe_int(case_summary.get("plans_eligible")),
        "case_top_reason": _top_reason(case_scheduling.get("reason_counts")),
        "case_context_error": _text(case_context.get("error"), 48),
        "failures": [
            _bounded_failure(entry)
            for entry in failures[:4]
            if _bounded_failure(entry)
        ],
        "cve_id": _text(single.get("cve_id"), 64),
        "program": _text(single.get("program"), 64),
    }


def _case_projection(record: Mapping) -> dict:
    modified = to_tehran(record.get("modified_at"))
    changed = _safe_int(record.get("validation_accepted")) + _safe_int(
        record.get("validation_rejected")
    )
    return {
        "case_id": _text(record.get("case_id"), 96),
        "program": _text(record.get("program"), 64),
        "category": _text(record.get("category"), 64),
        "case_status": _text(record.get("case_status"), 40).upper(),
        "sufficiency_state": _text(
            record.get("sufficiency_state"), 40
        ).upper(),
        "decision_state": _text(record.get("decision_state"), 40).upper(),
        "available_count": _safe_int(record.get("available_count")),
        "missing_count": _safe_int(record.get("missing_count")),
        "actions_count": _safe_int(record.get("actions_count")),
        "accepted_hypotheses": _safe_int(record.get("validation_accepted")),
        "rejected_hypotheses": _safe_int(record.get("validation_rejected")),
        "modified_at": _iso(modified),
        "changed": changed,
    }


def _safe_note(value: object) -> str:
    """Notes never carry URLs or credential-like pairs."""

    text = _text(value)
    if not text or "://" in text:
        return ""
    return _SECRET_NOTE_RE.sub("[redacted]", text)[:MAX_TEXT_CHARS]


def _safe_int(value: object, maximum: int = 1_000_000) -> int:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
    if number < 0:
        return 0
    return min(number, maximum)


def build_activity_status(
    *,
    run_records: object = None,
    case_records: object = None,
    lock_state: str = LOCK_UNAVAILABLE,
    window_start: object = DEFAULT_WINDOW_START,
    window_end: object = DEFAULT_WINDOW_END,
    timezone_name: object = DEFAULT_TIMEZONE,
    scheduler_enabled: object = None,
    now: object = None,
    source_notes: object = None,
    source_errors: object = None,
) -> dict:
    """Build the bounded AI activity / runtime status contract."""

    moment = to_tehran(now) or datetime.now(TEHRAN)
    start, end = window_bounds(moment, window_start, window_end)

    runs = [
        _run_projection(record, start, end)
        for record in (run_records or ())
        if isinstance(record, Mapping)
    ][:MAX_RUNS]
    cases = [
        _case_projection(record)
        for record in (case_records or ())
        if isinstance(record, Mapping)
    ][:MAX_CASES]

    latest_run = runs[0] if runs else None
    latest_case = cases[0] if cases else None

    if lock_state not in LOCK_STATES:
        lock_state = LOCK_UNAVAILABLE

    if lock_state == LOCK_HELD:
        status = STATUS_RUNNING
        status_basis = "execution_lock_held"
    elif latest_run and latest_run["status"] == STATUS_ERROR:
        status = STATUS_ERROR
        status_basis = "latest_run_failed"
    elif latest_run and latest_run["status"] == STATUS_COMPLETED_WITH_REJECTIONS:
        status = STATUS_COMPLETED_WITH_REJECTIONS
        status_basis = "latest_run_partial"
    elif (
        latest_case
        and latest_case["case_status"] == "WAITING_FOR_EVIDENCE"
    ):
        status = STATUS_WAITING_FOR_EVIDENCE
        status_basis = "latest_case_waiting_for_evidence"
    elif latest_run and latest_run["status"] == STATUS_COMPLETED:
        status = STATUS_COMPLETED
        status_basis = "latest_run_completed"
    elif latest_run:
        status = latest_run["status"]
        status_basis = "latest_run_status"
    elif latest_case:
        status = STATUS_IDLE
        status_basis = "case_present_no_runs"
    elif lock_state == LOCK_FREE:
        status = STATUS_IDLE
        status_basis = "no_runs_no_cases"
    else:
        status = STATUS_UNKNOWN
        status_basis = "runtime_state_not_observable"

    daily_runs = [run for run in runs if run["in_window"]]
    daily_cases: list[dict] = []
    for case in cases:
        modified = to_tehran(case.get("modified_at"))
        if modified is not None and start <= modified < end:
            daily_cases.append(case)
    daily = {
        "window_start": _iso(start),
        "window_end": _iso(end),
        "window": f"{_text(window_start, 5)}-{_text(window_end, 5)} "
        f"{_text(timezone_name, 32) or DEFAULT_TIMEZONE}",
        "runs": len(daily_runs),
        "plans_processed": sum(run["plans_processed"] for run in daily_runs),
        "results": sum(run["result_count"] for run in daily_runs),
        "evidence_acquired": sum(
            run["evidence_count"] for run in daily_runs
        ),
        "cases_processed": len(daily_cases),
        "accepted_hypotheses": sum(
            case["accepted_hypotheses"] for case in daily_cases
        ),
        "rejected_hypotheses": sum(
            case["rejected_hypotheses"] for case in daily_cases
        ),
        "evidence_available": sum(
            case["available_count"] for case in daily_cases
        ),
        "evidence_missing": sum(
            case["missing_count"] for case in daily_cases
        ),
        "actions_generated": sum(
            case["actions_count"] for case in daily_cases
        ),
    }

    last_error = None
    if latest_run and latest_run["status"] == STATUS_ERROR:
        failures = [
            _bounded_failure(entry)
            for entry in (latest_run.get("failures") or ())
        ]
        failures = [failure for failure in failures if failure]
        last_error = failures[0] if failures else "RESEARCH_FAILED"

    unavailable: list[str] = []
    if lock_state == LOCK_UNAVAILABLE:
        unavailable.append("execution_lock_state")
    unavailable.append("in_flight_case_and_stage")
    if latest_run is None:
        unavailable.append("last_run")
    if latest_case is None:
        unavailable.append("current_case")

    notes: list[str] = []
    for item in source_notes or ():
        text = _safe_note(item)
        if text and text not in notes:
            notes.append(text)
        if len(notes) >= MAX_NOTES:
            break
    errors: list[str] = []
    for item in source_errors or ():
        text = _bounded_failure(item)
        if text and text not in errors:
            errors.append(text)
        if len(errors) >= MAX_NOTES:
            break

    return {
        "rule_version": RULE_VERSION,
        "status": status,
        "status_basis": status_basis,
        "server_time_tehran": _iso(moment),
        "window": {
            "start": _text(window_start, 5) or DEFAULT_WINDOW_START,
            "end": _text(window_end, 5) or DEFAULT_WINDOW_END,
            "timezone": _text(timezone_name, 32) or DEFAULT_TIMEZONE,
            "in_window": start <= moment < end,
            "current_start": _iso(start),
            "current_end": _iso(end),
            "scheduler_enabled": (
                bool(scheduler_enabled)
                if scheduler_enabled is not None
                else None
            ),
        },
        "current_run": None,
        "last_run": latest_run,
        "current_case": latest_case,
        "current_stage": None,
        "daily": daily,
        "totals": {
            "runs": len(runs),
            "results": sum(run["result_count"] for run in runs),
            "evidence_acquired": sum(
                run["evidence_count"] for run in runs
            ),
            "cases": len(cases),
        },
        "last_error": last_error,
        "observability": {
            "unavailable_fields": unavailable,
            "notes": notes,
            "source_errors": errors,
            "unknown_is_not_failure": True,
        },
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "TEHRAN",
    "DEFAULT_TIMEZONE",
    "DEFAULT_WINDOW_START",
    "DEFAULT_WINDOW_END",
    "STATUS_IDLE",
    "STATUS_RUNNING",
    "STATUS_WAITING_FOR_EVIDENCE",
    "STATUS_COMPLETED",
    "STATUS_COMPLETED_WITH_REJECTIONS",
    "STATUS_ERROR",
    "STATUS_UNKNOWN",
    "STATUSES",
    "RUN_STATUS_TO_ACTIVITY",
    "LOCK_HELD",
    "LOCK_FREE",
    "LOCK_UNAVAILABLE",
    "LOCK_STATES",
    "to_tehran",
    "window_bounds",
    "in_window",
    "build_activity_status",
]
