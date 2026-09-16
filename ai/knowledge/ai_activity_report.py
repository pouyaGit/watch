"""Stage R84 deterministic Telegram AI activity report formatter (pure).

Builds the bounded, mobile-friendly Telegram messages for the R83 AI activity
snapshot:

- a daily summary for one 12:00-00:00 Asia/Tehran window;
- bounded event reports derived from real transitions in the R83 snapshot
  (run started/completed/partial/failed, case waiting for evidence, human
  review required).

This module is pure: no I/O, no network, no Telegram client, no LLM, no Mongo
and no clock of its own (the caller passes the activity snapshot). Message
construction never invents activity: zero activity is reported as zero and
"AI is working" is only claimed when the R83 status is actually RUNNING.

Messages are safe for the existing Telegram HTML transport: dynamic values are
withheld when they carry URLs, paths, IPs or credential-like pairs, are
redacted when they look like secrets, and are HTML-escaped so bounded data can
never become Telegram markup.
"""

from __future__ import annotations

import re
from typing import Mapping

RULE_VERSION = "r84-1"

#: Telegram's hard limit is 4096 UTF-16 code units; bound well below it.
MAX_MESSAGE_CHARS = 3900
MAX_BULLETS = 6
MAX_EVENTS = 3

REPORT_DAILY = "DAILY_ACTIVITY"
REPORT_EVENT = "ACTIVITY_EVENT"

EVENT_RUN_STARTED = "RUN_STARTED"
EVENT_RUN_COMPLETED = "RUN_COMPLETED"
EVENT_RUN_COMPLETED_WITH_REJECTIONS = "RUN_COMPLETED_WITH_REJECTIONS"
EVENT_RUN_FAILED = "RUN_FAILED"
EVENT_CASE_WAITING_FOR_EVIDENCE = "CASE_WAITING_FOR_EVIDENCE"
EVENT_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"

EVENT_TYPES: tuple[str, ...] = (
    EVENT_RUN_STARTED,
    EVENT_RUN_COMPLETED,
    EVENT_RUN_COMPLETED_WITH_REJECTIONS,
    EVENT_RUN_FAILED,
    EVENT_CASE_WAITING_FOR_EVIDENCE,
    EVENT_HUMAN_REVIEW_REQUIRED,
)

STATUS_EMOJI: dict[str, str] = {
    "RUNNING": "🟢",
    "WAITING_FOR_EVIDENCE": "⏳",
    "COMPLETED": "✅",
    "COMPLETED_WITH_REJECTIONS": "⚠️",
    "ERROR": "🔴",
    "IDLE": "💤",
    "UNKNOWN": "❔",
}

RUN_STATUS_EMOJI: dict[str, str] = {
    "COMPLETED": "✅",
    "COMPLETED_WITH_REJECTIONS": "⚠️",
    "ERROR": "🔴",
    "IDLE": "💤",
    "UNKNOWN": "❔",
    "RUNNING": "🟢",
}

FOOTER = "Research only · No execution · Not confirmed"
SEPARATOR = "━━━━━━━━━━━━━━━━━━"

_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*\S+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+\S+")
_OBJECT_ID_RE = re.compile(r"\b[0-9a-fA-F]{24}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HTML_ESCAPES = (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"))


def _text(value: object, limit: int = 200) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _safe(value: object, limit: int = 200) -> str:
    """Bound dynamic text so it can never carry unsafe or markup content."""

    text = _text(value, limit)
    if not text:
        return ""
    if "://" in text or "/" in text or "\\" in text:
        return "[withheld]"
    # Bearer first: the generic key[:=]value rule would otherwise consume the
    # word "Bearer" and leave the credential itself visible.
    text = _BEARER_RE.sub("[redacted]", text)
    text = _SECRET_RE.sub("[redacted]", text)
    text = _OBJECT_ID_RE.sub("[redacted]", text)
    text = _IPV4_RE.sub("[withheld]", text)
    for raw, escaped in _HTML_ESCAPES:
        text = text.replace(raw, escaped)
    return text


def _block(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _int(value: object) -> int:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
    return number if number >= 0 else 0


def _bool(value: object) -> bool:
    return value is True


def snapshot_of(activity: Mapping) -> dict:
    """Bounded, deterministic transition snapshot used for event detection.

    Every value is sanitized: the snapshot is persisted in the deduplication
    state file, so it must never carry secrets, URLs, paths or target data.
    """

    activity = _block(activity)
    last_run = _block(activity.get("last_run"))
    case = _block(activity.get("current_case"))
    return {
        "status": _text(activity.get("status"), 40),
        "last_run_id": _safe(last_run.get("run_id"), 64),
        "last_run_status": _text(last_run.get("status"), 40),
        "case_id": _safe(case.get("case_id"), 96),
        "case_status": _text(case.get("case_status"), 40),
        "case_decision": _text(case.get("decision_state"), 40),
        "case_modified_at": _safe(case.get("modified_at"), 64),
        "last_error": _safe(activity.get("last_error"), 80),
    }


def daily_dedup_key(activity: Mapping) -> str:
    """Deterministic identity of one daily window report."""

    window = _block(_block(activity).get("window"))
    start = _text(window.get("current_start"), 64)
    return f"daily:{start}" if start else "daily:unknown-window"


def _observed_label(value: object) -> str:
    """Compact, safe observation time (minutes precision) for mobile reading."""

    text = _text(value, 64)
    if len(text) >= 16 and text[10:11] == "T":
        return f"{text[:10]} {text[11:16]}"
    return _safe(text, 64)


def _window_labels(activity: Mapping) -> tuple[str, str, str, bool]:
    window = _block(_block(activity).get("window"))
    start = _text(window.get("current_start"), 64)
    date = start[:10] if len(start) >= 10 else "unknown-date"
    start_hhmm = _text(window.get("start"), 5) or "12:00"
    end_hhmm = _text(window.get("end"), 5) or "00:00"
    timezone = _text(window.get("timezone"), 32) or "Asia/Tehran"
    window_label = f"{start_hhmm} → {end_hhmm} {timezone}"
    window_short = f"{start_hhmm}–{end_hhmm} {timezone.split('/')[-1]}"
    in_window = _bool(window.get("in_window"))
    return date, window_label, window_short, in_window


def _utf16_len(text: str) -> int:
    """Telegram counts UTF-16 code units, not Python characters."""

    return len(text.encode("utf-16-le")) // 2


def _bounded_message(parts: list[str]) -> str:
    text = "\n".join(parts)
    if _utf16_len(text) <= MAX_MESSAGE_CHARS:
        return text
    keep = MAX_MESSAGE_CHARS - len(FOOTER) - len(SEPARATOR) - 6
    truncated = text[:keep]
    while truncated and _utf16_len(truncated) > keep:
        truncated = truncated[:-32]
    return truncated.rstrip() + "\n…\n" + SEPARATOR + "\n" + FOOTER


def build_daily_report(activity: Mapping) -> dict:
    """Build the bounded daily AI activity Telegram report."""

    activity = _block(activity)
    status = _text(activity.get("status"), 40) or "UNKNOWN"
    status_basis = _text(activity.get("status_basis"), 64)
    daily = _block(activity.get("daily"))
    totals = _block(activity.get("totals"))
    last_run = _block(activity.get("last_run"))
    case = _block(activity.get("current_case"))
    observability = _block(activity.get("observability"))
    observed_at = _observed_label(activity.get("server_time_tehran"))
    date, window_label, window_short, in_window = _window_labels(activity)

    runs = _int(daily.get("runs"))
    cases_processed = _int(daily.get("cases_processed"))
    accepted = _int(daily.get("accepted_hypotheses"))
    rejected = _int(daily.get("rejected_hypotheses"))
    evidence_acquired = _int(daily.get("evidence_acquired"))
    actions = _int(daily.get("actions_generated"))

    lines: list[str] = [
        "🤖 WATCH AI DAILY REPORT",
        SEPARATOR,
        f"📅 {date}",
        f"⏱ {window_label}",
        "",
        f"{STATUS_EMOJI.get(status, '❔')} Status",
        status,
    ]
    if status == "RUNNING":
        lines.append("🟢 AI is RUNNING (execution lock held).")
    elif status_basis == "runtime_state_not_observable":
        lines.append("Runtime state could not be observed (UNKNOWN is not failure).")
    if status_basis:
        lines.append(f"basis: {_safe(status_basis, 64)}")
    if observed_at:
        lines.append(f"observed: {_safe(observed_at, 64)}")
    if last_run:
        duration = last_run.get("duration_seconds")
        duration_text = (
            f"{float(duration):.1f}s" if isinstance(duration, (int, float)) else "n/a"
        )
        lines.append(
            "last run: "
            f"{_safe(last_run.get('status'), 40) or 'UNKNOWN'} "
            f"{_safe(last_run.get('run_id'), 64)} ({duration_text})"
        )
    else:
        lines.append("last run: none recorded")

    lines += [
        "",
        "📊 Activity",
        f"Runs: {runs}",
        f"Plans processed: {_int(daily.get('plans_processed'))}",
        f"Results: {_int(daily.get('results'))}",
        f"Cases processed: {cases_processed}",
        f"Hypotheses accepted: {accepted}",
        f"Hypotheses rejected: {rejected}",
        f"Evidence acquired: {evidence_acquired}",
        f"Actions generated: {actions}",
        "",
        "🔎 Research",
    ]
    research_bullets: list[str] = []
    if case:
        research_bullets.append(
            "case "
            f"{_safe(case.get('case_id'), 96)} "
            f"[{_safe(case.get('program'), 64)} / {_safe(case.get('category'), 64)}]: "
            f"{_safe(case.get('case_status'), 40)}, "
            f"{_safe(case.get('sufficiency_state'), 40)}, "
            f"missing {_int(case.get('missing_count'))}"
        )
    waiting = _int(totals.get("cases"))
    if waiting:
        research_bullets.append(f"cases persisted: {waiting}")
    if runs == 0:
        research_bullets.append(
            f"No AI run was recorded during the {date} {window_short} window."
        )
    if not research_bullets:
        research_bullets.append("no research activity recorded")
    lines += [f"• {bullet}" for bullet in research_bullets[:MAX_BULLETS]]

    lines += ["", "⏳ Pending"]
    pending: list[str] = []
    if case and _int(case.get("missing_count")) > 0:
        pending.append(
            f"{_safe(case.get('case_id'), 96)}: "
            f"{_int(case.get('missing_count'))} missing decision-critical evidence"
        )
    if _text(case.get("case_status"), 40) == "WAITING_FOR_EVIDENCE":
        pending.append("case is WAITING_FOR_EVIDENCE (human-supplied evidence)")
    if not pending:
        pending.append("nothing pending observed")
    lines += [f"• {bullet}" for bullet in pending[:MAX_BULLETS]]

    lines += ["", "⚠️ Issues"]
    issues: list[str] = []
    if activity.get("last_error"):
        issues.append(f"last error: {_safe(activity.get('last_error'), 80)}")
    if rejected > 0:
        issues.append(f"rejected hypotheses in window: {rejected}")
    unavailable = [
        _safe(item, 64)
        for item in observability.get("unavailable_fields") or ()
        if _safe(item, 64)
    ]
    if unavailable:
        issues.append("unavailable: " + ", ".join(unavailable[:4]))
    if not issues:
        issues.append("none recorded")
    lines += [f"• {bullet}" for bullet in issues[:MAX_BULLETS]]

    lines += ["", SEPARATOR, FOOTER]
    message = _bounded_message(lines)
    return {
        "rule_version": RULE_VERSION,
        "report_type": REPORT_DAILY,
        "dedup_key": daily_dedup_key(activity),
        "window_in_progress": in_window,
        "message": message,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _run_event_type(activity_status: object) -> str:
    status = _text(activity_status, 40)
    if status == "COMPLETED_WITH_REJECTIONS":
        return EVENT_RUN_COMPLETED_WITH_REJECTIONS
    if status == "ERROR":
        return EVENT_RUN_FAILED
    return EVENT_RUN_COMPLETED


def event_reports(
    activity: Mapping, previous: object = None, *, limit: int = MAX_EVENTS
) -> list[dict]:
    """Bounded event reports for real transitions in the R83 snapshot.

    The first observation has no previous snapshot and is treated as a silent
    baseline: stale events are never replayed merely because the reporter was
    invoked for the first time (prevents "process was checked" spam).
    """

    activity = _block(activity)
    previous = _block(previous)
    if not previous:
        return []
    snapshot = snapshot_of(activity)
    reports: list[dict] = []

    if snapshot["status"] == "RUNNING" and previous.get("status") != "RUNNING":
        window = _block(activity.get("window"))
        window_start = _text(window.get("current_start"), 64)
        reports.append(
            {
                "rule_version": RULE_VERSION,
                "report_type": REPORT_EVENT,
                "event_type": EVENT_RUN_STARTED,
                "dedup_key": f"event:{EVENT_RUN_STARTED}:{window_start or 'window'}",
                "message": (
                    "🟢 WATCH AI\n"
                    f"{SEPARATOR}\n"
                    "AI research run started (execution lock held).\n"
                    f"window: {_safe(window_start, 64)}\n"
                    f"{SEPARATOR}\n{FOOTER}"
                ),
                "advisory": True,
                "research_only": True,
                "confirmation_state": "NOT_CONFIRMED",
            }
        )

    last_run = _block(activity.get("last_run"))
    run_id = _text(last_run.get("run_id"), 64)
    run_status = _text(last_run.get("status"), 40)
    changed = (
        previous.get("last_run_id") != snapshot["last_run_id"]
        or previous.get("last_run_status") != snapshot["last_run_status"]
    )
    if run_id and run_status in (
        "COMPLETED",
        "COMPLETED_WITH_REJECTIONS",
        "ERROR",
    ) and changed:
        event_type = _run_event_type(run_status)
        duration = last_run.get("duration_seconds")
        duration_text = (
            f"{float(duration):.1f}s"
            if isinstance(duration, (int, float))
            else "n/a"
        )
        body = [
            f"{RUN_STATUS_EMOJI.get(run_status, '❔')} WATCH AI RUN {run_status}",
            SEPARATOR,
            f"run: {_safe(run_id, 64)}",
            f"duration: {duration_text}",
            f"plans processed: {_int(last_run.get('plans_processed'))}",
            f"results: {_int(last_run.get('result_count'))}",
            f"evidence: {_int(last_run.get('evidence_count'))}",
        ]
        if run_status == "ERROR":
            body.append(f"error: {_safe(activity.get('last_error'), 80) or 'unspecified'}")
        body += [SEPARATOR, FOOTER]
        reports.append(
            {
                "rule_version": RULE_VERSION,
                "report_type": REPORT_EVENT,
                "event_type": event_type,
                "dedup_key": f"event:{event_type}:{run_id}",
                "message": "\n".join(body),
                "advisory": True,
                "research_only": True,
                "confirmation_state": "NOT_CONFIRMED",
            }
        )

    case = _block(activity.get("current_case"))
    case_id = _text(case.get("case_id"), 96)
    case_status = _text(case.get("case_status"), 40)
    case_modified = _text(case.get("modified_at"), 64)
    case_changed = (
        previous.get("case_id") != snapshot["case_id"]
        or previous.get("case_status") != snapshot["case_status"]
        or previous.get("case_modified_at") != snapshot["case_modified_at"]
    )
    if case_id and case_status == "WAITING_FOR_EVIDENCE" and case_changed:
        reports.append(
            {
                "rule_version": RULE_VERSION,
                "report_type": REPORT_EVENT,
                "event_type": EVENT_CASE_WAITING_FOR_EVIDENCE,
                "dedup_key": (
                    f"event:{EVENT_CASE_WAITING_FOR_EVIDENCE}:{case_id}:{case_modified}"
                ),
                "message": (
                    "⏳ WATCH AI CASE WAITING FOR EVIDENCE\n"
                    f"{SEPARATOR}\n"
                    f"case: {_safe(case_id, 96)}\n"
                    f"program: {_safe(case.get('program'), 64)}\n"
                    f"missing decision-critical evidence: "
                    f"{_int(case.get('missing_count'))}\n"
                    f"{SEPARATOR}\n{FOOTER}"
                ),
                "advisory": True,
                "research_only": True,
                "confirmation_state": "NOT_CONFIRMED",
            }
        )

    decision = _text(case.get("decision_state"), 40)
    if (
        case_id
        and decision == "READY_FOR_HUMAN_REVIEW"
        and (
            previous.get("case_decision") != decision
            or previous.get("case_modified_at") != snapshot["case_modified_at"]
        )
    ):
        reports.append(
            {
                "rule_version": RULE_VERSION,
                "report_type": REPORT_EVENT,
                "event_type": EVENT_HUMAN_REVIEW_REQUIRED,
                "dedup_key": (
                    f"event:{EVENT_HUMAN_REVIEW_REQUIRED}:{case_id}:{case_modified}"
                ),
                "message": (
                    "👤 WATCH AI HUMAN REVIEW REQUIRED\n"
                    f"{SEPARATOR}\n"
                    f"case: {_safe(case_id, 96)}\n"
                    f"program: {_safe(case.get('program'), 64)}\n"
                    "decision evidence is complete; human review is required.\n"
                    f"{SEPARATOR}\n{FOOTER}"
                ),
                "advisory": True,
                "research_only": True,
                "confirmation_state": "NOT_CONFIRMED",
            }
        )

    return reports[: max(int(limit), 0)]


__all__ = [
    "RULE_VERSION",
    "MAX_MESSAGE_CHARS",
    "MAX_BULLETS",
    "MAX_EVENTS",
    "REPORT_DAILY",
    "REPORT_EVENT",
    "EVENT_RUN_STARTED",
    "EVENT_RUN_COMPLETED",
    "EVENT_RUN_COMPLETED_WITH_REJECTIONS",
    "EVENT_RUN_FAILED",
    "EVENT_CASE_WAITING_FOR_EVIDENCE",
    "EVENT_HUMAN_REVIEW_REQUIRED",
    "EVENT_TYPES",
    "FOOTER",
    "snapshot_of",
    "daily_dedup_key",
    "build_daily_report",
    "event_reports",
]
