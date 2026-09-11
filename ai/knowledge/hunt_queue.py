"""Stage R29.1 deterministic personal hunt queue (pure engine).

Answers *"What should I personally investigate next?"* over the existing
R26.2 Action Queue plus R25.5 outcome history and R25.7 session history.

``hunt_priority`` is NOT a replacement for the R25.2 Money Score:

- Money Score is a deterministic 0-100 economic ranking over a CVE/program
  candidate; it is stable, product-oriented and unchanged by this stage.
- ``hunt_priority`` is a small closed-vocabulary tier (HUNT_NOW / HUNT_NEXT /
  VERIFY_FIRST / RESEARCH_LATER / SKIP_FOR_NOW) that orders *personal
  attention* using the Money Score plus workflow signals (active session,
  asset/evidence blockers, confidence, effort, and past research history).
- The Money Score is copied verbatim into the item; hunt_priority never
  mutates, rescales, re-weights or replaces it.

Pure functions only: no I/O, no network, no LLM, no subprocess, no Mongo, no
clock, no randomness.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ai.schemas.hunt_queue import (
    HUNT_PRIORITIES,
    HUNT_RULE_VERSION,
    HuntItem,
    hunt_id_for,
    hunt_item_projection,
)

# Tier order used for deterministic ranking (best -> worst).
HUNT_PRIORITY_ORDER: dict[str, int] = {
    name: index for index, name in enumerate(HUNT_PRIORITIES)
}

HISTORY_HIGH_NEGATIVE_RATE = 0.5

_CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
_EVIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

_ACTIVE_SESSION_STATUSES = frozenset({"IN_PROGRESS", "ACTIVE"})


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _confidence_rank(value: Any) -> int:
    return _CONFIDENCE_RANK.get(str(value or "").upper(), 0)


def _evidence_rank(value: Any) -> int:
    return _EVIDENCE_RANK.get(str(value or "").upper(), 0)


def has_active_session(action: Any, sessions: Any) -> bool:
    """True iff an R25.7 session is currently active for this lead."""

    status = str(_get(action, "current_status") or "").upper()
    if status == "IN_PROGRESS":
        return True
    session_status = str(_get(sessions, "session_status") or "").upper()
    if session_status in _ACTIVE_SESSION_STATUSES:
        return True
    if _coerce_int(_get(sessions, "in_progress_sessions")) > 0:
        return True
    return False


def _negative_rate(outcomes: Any) -> float:
    terminal = _coerce_int(_get(outcomes, "terminal_attempts"))
    if terminal <= 0:
        return 0.0
    negative = (
        _coerce_int(_get(outcomes, "duplicate"))
        + _coerce_int(_get(outcomes, "wasted_time"))
        + _coerce_int(_get(outcomes, "rejected"))
    )
    return negative / terminal


def classify_hunt_priority(action: Any, outcomes: Any, sessions: Any) -> str:
    """Deterministic personal-priority tier (documented precedence).

    First match wins:

    1. active session                          -> HUNT_NOW
    2. BLOCKED (status or class)               -> VERIFY_FIRST
    3. previously ACCEPTED outcome             -> HUNT_NOW
    4. HIGH_VALUE + HIGH confidence            -> HUNT_NOW
    5. GOOD_OPPORTUNITY + HIGH/MEDIUM conf     -> HUNT_NEXT
    6. RESEARCH_FIRST                          -> HUNT_NEXT
    7. LOW confidence (or LOW_CONFIDENCE)      -> VERIFY_FIRST
    8. high duplicate/wasted/rejected history  -> RESEARCH_LATER
    9. otherwise                               -> SKIP_FOR_NOW
    """

    action = action or {}
    if has_active_session(action, sessions):
        return "HUNT_NOW"

    status = str(_get(action, "current_status") or "").upper()
    opp_class = str(_get(action, "opportunity_class") or "").upper()
    if status == "BLOCKED" or opp_class == "BLOCKED":
        return "VERIFY_FIRST"

    if _coerce_int(_get(outcomes, "accepted")) > 0:
        return "HUNT_NOW"

    confidence = str(_get(action, "confidence") or "LOW").upper()
    if opp_class == "HIGH_VALUE" and confidence == "HIGH":
        return "HUNT_NOW"
    if opp_class == "GOOD_OPPORTUNITY" and confidence in ("HIGH", "MEDIUM"):
        return "HUNT_NEXT"
    if opp_class == "RESEARCH_FIRST":
        return "HUNT_NEXT"
    if confidence == "LOW" or opp_class == "LOW_CONFIDENCE":
        return "VERIFY_FIRST"
    if _negative_rate(outcomes) >= HISTORY_HIGH_NEGATIVE_RATE:
        return "RESEARCH_LATER"
    return "SKIP_FOR_NOW"


_REASON_BY_PRIORITY: dict[str, tuple[str, str]] = {
    "HUNT_NOW": (
        "ACTIVE_SESSION",
        "Active research session should be continued.",
    ),
    "VERIFY_FIRST": (
        "BLOCKED",
        "Asset relationship is not sufficiently established.",
    ),
    "RESEARCH_LATER": (
        "HIGH_DUPLICATE_WASTE",
        "Historical duplicate/wasted-time rate is high.",
    ),
    "SKIP_FOR_NOW": (
        "NO_STRONG_SIGNAL",
        "No strong research signal currently justifies time.",
    ),
}

_REASON_BY_CLASS: dict[str, tuple[str, str]] = {
    "GOOD_OPPORTUNITY": (
        "GOOD_OPPORTUNITY",
        "Strong opportunity with sufficient evidence.",
    ),
    "RESEARCH_FIRST": (
        "RESEARCH_FIRST",
        "Research candidate with existing evidence.",
    ),
    "LOW_CONFIDENCE": (
        "LOW_CONFIDENCE",
        "Evidence confidence is too low.",
    ),
}


def build_hunt_reason(
    priority: str, action: Any, outcomes: Any, sessions: Any
) -> tuple[str, str]:
    """Return ``(reason_code, reason_text)`` mapping to structured fields."""

    priority = str(priority or "").upper()
    action = action or {}
    status = str(_get(action, "current_status") or "").upper()
    opp_class = str(_get(action, "opportunity_class") or "").upper()
    confidence = str(_get(action, "confidence") or "LOW").upper()

    if priority == "HUNT_NOW":
        if has_active_session(action, sessions):
            return _REASON_BY_PRIORITY["HUNT_NOW"]
        if _coerce_int(_get(outcomes, "accepted")) > 0:
            return ("PREVIOUSLY_ACCEPTED",
                    "Previously accepted research direction.")
        return ("HIGH_VALUE_HIGH_CONFIDENCE",
                "High-value, high-confidence opportunity.")
    if priority == "HUNT_NEXT":
        if opp_class in _REASON_BY_CLASS:
            return _REASON_BY_CLASS[opp_class]
        return ("GOOD_OPPORTUNITY",
                "Strong opportunity with sufficient evidence.")
    if priority == "VERIFY_FIRST":
        if status == "BLOCKED" or opp_class == "BLOCKED":
            return _REASON_BY_PRIORITY["VERIFY_FIRST"]
        if confidence == "LOW" or opp_class == "LOW_CONFIDENCE":
            return _REASON_BY_CLASS["LOW_CONFIDENCE"]
        return _REASON_BY_PRIORITY["VERIFY_FIRST"]
    if priority == "RESEARCH_LATER":
        return _REASON_BY_PRIORITY["RESEARCH_LATER"]
    return _REASON_BY_PRIORITY["SKIP_FOR_NOW"]


def build_time_box(estimated_minutes: Any) -> str:
    """Deterministic time-box band from the existing effort estimate."""

    minutes = _coerce_int(estimated_minutes)
    if minutes <= 30:
        return "30 MIN"
    if minutes <= 60:
        return "60 MIN"
    if minutes <= 120:
        return "120 MIN"
    return "120 MIN + REVIEW"


def _historical_outcome(outcomes: Any) -> dict:
    latest = _get(outcomes, "latest_outcome")
    latest_status = "NONE"
    if isinstance(latest, Mapping) and latest.get("status"):
        latest_status = str(latest.get("status")).upper()
    return {
        "attempts": _coerce_int(_get(outcomes, "attempts")),
        "accepted": _coerce_int(_get(outcomes, "accepted")),
        "duplicate": _coerce_int(_get(outcomes, "duplicate")),
        "rejected": _coerce_int(_get(outcomes, "rejected")),
        "wasted": _coerce_int(_get(outcomes, "wasted_time")),
        "latest_outcome": latest_status,
        "data_quality": str(_get(outcomes, "data_quality") or "NONE"),
    }


def _historical_time(sessions: Any) -> dict:
    return {
        "total_time": _coerce_int(_get(sessions, "actual_time")),
        "average_time": _coerce_int(
            _get(sessions, "average_actual_minutes")),
        "latest_session_status": str(
            _get(sessions, "latest_session_status")
            or _get(sessions, "session_status") or "NONE"),
        "total_sessions": _coerce_int(_get(sessions, "total_sessions")),
        "planned_time": _coerce_int(_get(sessions, "planned_time")),
        "actual_time": _coerce_int(_get(sessions, "actual_time")),
    }


def build_hunt_item(action: Any, outcomes: Any, sessions: Any) -> HuntItem:
    """Compose one read-only personal hunt item (Money Score copied verbatim)."""

    action = action or {}
    lead_id = str(_get(action, "lead_id") or "")
    priority = classify_hunt_priority(action, outcomes, sessions)
    reason_code, reason_text = build_hunt_reason(
        priority, action, outcomes, sessions)
    estimated = _coerce_int(_get(action, "estimated_minutes"))
    return HuntItem(
        hunt_id=hunt_id_for(lead_id),
        lead_id=lead_id,
        cve_id=str(_get(action, "cve_id") or ""),
        program=str(_get(action, "program") or ""),
        money_score=_coerce_int(_get(action, "money_score")),
        money_priority=str(_get(action, "priority") or ""),
        opportunity_class=str(
            _get(action, "opportunity_class") or "DEFER"),
        current_status=str(_get(action, "current_status") or "DEFERRED"),
        recommended_action=str(
            _get(action, "recommended_action") or "DEFER"),
        confidence=str(_get(action, "confidence") or "LOW"),
        evidence_quality=str(_get(action, "evidence_quality") or "NONE"),
        estimated_minutes=estimated,
        why_now=[str(x) for x in _get(action, "why_now") or []],
        blockers=[str(x) for x in _get(action, "blockers") or []],
        next_step=str(_get(action, "next_step") or ""),
        historical_outcome=_historical_outcome(outcomes),
        historical_time=_historical_time(sessions),
        hunt_priority=priority,
        recommended_time_box=build_time_box(estimated),
        hunt_reason=reason_text,
        hunt_reason_code=reason_code,
        rule_version=HUNT_RULE_VERSION,
        research_only=True,
    )


def rank_hunt_queue(items: Iterable[HuntItem]) -> list[HuntItem]:
    """Deterministic ordering (no additional numeric score).

    1. hunt priority tier, 2. Money Score desc, 3. confidence desc,
    4. evidence quality desc, 5. estimated minutes asc, 6. CVE asc,
    7. program asc, 8. lead_id asc.
    """

    return sorted(
        items or (),
        key=lambda item: (
            HUNT_PRIORITY_ORDER.get(
                item.hunt_priority, len(HUNT_PRIORITY_ORDER)),
            -int(item.money_score),
            -_confidence_rank(item.confidence),
            -_evidence_rank(item.evidence_quality),
            int(item.estimated_minutes),
            item.cve_id,
            item.program,
            item.lead_id,
        ),
    )


def build_hunt_summary(items: Iterable[HuntItem]) -> dict:
    """Compact deterministic tier counts + top items."""

    items = list(items or ())
    by_priority = {name: 0 for name in HUNT_PRIORITIES}
    for item in items:
        by_priority[item.hunt_priority] = (
            by_priority.get(item.hunt_priority, 0) + 1)
    ranked = rank_hunt_queue(items)
    return {
        "total": len(items),
        "by_priority": dict(sorted(by_priority.items())),
        "top": [hunt_item_projection(item) for item in ranked[:3]],
        "rule_version": HUNT_RULE_VERSION,
        "research_only": True,
    }


__all__ = [
    "HUNT_PRIORITY_ORDER",
    "has_active_session",
    "classify_hunt_priority",
    "build_hunt_reason",
    "build_time_box",
    "build_hunt_item",
    "rank_hunt_queue",
    "build_hunt_summary",
]
