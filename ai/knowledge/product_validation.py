"""Stage R27.1 deterministic product validation (pure engine).

Answers the product question *"Does Watch help a researcher choose better
research opportunities?"* using ONLY data already produced by R25.2 (Money
Score), R25.5 (outcomes), R25.7 (sessions), R26.1 (opportunities), R26.2
(actions) and R26.3 (daily workflow).

This is an audit/metrics layer: it introduces **no new score**, never modifies
the Money Score, never claims statistical significance, never infers
causality and never fabricates relationships. Every metric states its
denominator. Missing data is explicit.

Pure deterministic functions of their inputs: no I/O, no network, no LLM, no
Mongo, no subprocess, no clock, no randomness.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

VALIDATION_VERSION = "r27-1"

DEFAULT_MIN_SESSIONS = 20
DEFAULT_MIN_TERMINAL_OUTCOMES = 20
DEFAULT_MIN_LEADS = 10

# Closed hypothesis statuses (never "PROVEN").
UNTESTABLE = "UNTESTABLE"
INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
DIRECTIONAL_SIGNAL = "DIRECTIONAL_SIGNAL"
SUPPORTED = "SUPPORTED"
HYPOTHESIS_STATUSES: tuple[str, ...] = (
    UNTESTABLE,
    INSUFFICIENT_DATA,
    DIRECTIONAL_SIGNAL,
    SUPPORTED,
)

# Product decisions (closed vocabulary).
CONTINUE_PRODUCTIZATION = "CONTINUE_PRODUCTIZATION"
COLLECT_MORE_DATA = "COLLECT_MORE_DATA"
RETHINK_WORKFLOW = "RETHINK_WORKFLOW"
PRODUCT_DECISIONS: tuple[str, ...] = (
    CONTINUE_PRODUCTIZATION,
    COLLECT_MORE_DATA,
    RETHINK_WORKFLOW,
)

SESSION_STARTED_STATUSES = frozenset({"IN_PROGRESS", "COMPLETED", "ABANDONED"})
TERMINAL_OUTCOME_STATUSES = frozenset({
    "ACCEPTED", "DUPLICATE", "REJECTED", "NOT_APPLICABLE", "WASTED_TIME",
})

# Direction margin for SUPPORTED: a deterministic product signal, NOT a
# statistical test (documented limitation).
SUPPORTED_MARGIN = 0.05
LEADS_PER_GROUP_MIN = 3

_LIMITATIONS: tuple[str, ...] = (
    "No statistical significance test is implemented; SUPPORTED means the "
    "predefined product thresholds and direction were met, not proof.",
    "Metrics are cross-sectional joins over current state; without external "
    "snapshots, blocked -> READY transitions are only measurable when the "
    "caller supplies a previous workflow.",
    "Correlation is not causation: attention, conversion and time metrics "
    "describe observed association only.",
    "Small samples are reported as INSUFFICIENT_DATA/UNTESTABLE and never "
    "extrapolated.",
    "No payout, bounty or monetary value is considered anywhere.",
    "Missing session/outcome data is explicit; UNAVAILABLE is never silently "
    "treated as zero.",
)


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


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _metric(value: Any = None, denominator: Any = None,
            denominator_label: str = "", missing: int = 0,
            note: str = "") -> dict:
    return {
        "value": value,
        "denominator": denominator,
        "denominator_label": denominator_label,
        "missing": missing,
        "note": note,
    }


def _rate(numerator: Any, denominator: Any, label: str,
          missing: int = 0, note: str = "") -> dict:
    n, d = _coerce_int(numerator), _coerce_int(denominator)
    return {
        "numerator": n,
        "denominator": d,
        "rate": (round(n / d, 4) if d > 0 else None),
        "denominator_label": label,
        "missing": missing,
        "note": note,
    }


def build_validation_dataset(
    opportunities: Iterable[Any],
    sessions_by_lead: Mapping[str, Any] | None = None,
    outcomes_by_lead: Mapping[str, Any] | None = None,
    availability_by_lead: Mapping[str, Any] | None = None,
) -> list[dict]:
    """Join existing data by lead_id only (no fabricated relationships).

    Each row carries the lead's opportunity/action state plus its raw session
    and outcome records and an explicit data-availability status per source.
    Deterministic ordering: lead_id ascending.
    """

    sessions_by_lead = sessions_by_lead or {}
    outcomes_by_lead = outcomes_by_lead or {}
    availability_by_lead = availability_by_lead or {}
    rows: list[dict] = []
    for item in opportunities or ():
        if not isinstance(item, Mapping):
            continue
        lead_id = str(item.get("lead_id") or "").strip()
        if not lead_id:
            continue
        sessions = [
            dict(s) for s in (sessions_by_lead.get(lead_id) or [])
            if isinstance(s, Mapping)
        ]
        outcomes = [
            dict(o) for o in (outcomes_by_lead.get(lead_id) or [])
            if isinstance(o, Mapping)
        ]
        availability = availability_by_lead.get(lead_id) or {}
        rows.append({
            "lead_id": lead_id,
            "cve_id": str(_get(item, "cve_id") or ""),
            "program": str(_get(item, "program") or ""),
            "money_score": _coerce_int(_get(item, "money_score")),
            "opportunity_class": str(
                _get(item, "opportunity_class") or "DEFER"),
            "action_status": str(
                _get(item, "current_status") or "DEFERRED"),
            "recommended_action": str(
                _get(item, "recommended_action") or "DEFER"),
            "confidence": str(_get(item, "confidence") or "LOW"),
            "evidence_quality": str(
                _get(item, "evidence_quality") or "NONE"),
            "estimated_minutes": _coerce_int(
                _get(item, "estimated_minutes")),
            "sessions": sessions,
            "outcomes": outcomes,
            "session_data": str(
                availability.get("session_data") or "NONE"),
            "outcome_data": str(
                availability.get("outcome_data") or "NONE"),
            "opportunity_data": "PRESENT",
        })
    rows.sort(key=lambda row: row["lead_id"])
    return rows


def _availability_counts(rows: list[dict], key: str) -> dict:
    counts = {"PRESENT": 0, "NONE": 0, "UNAVAILABLE": 0}
    for row in rows:
        status = str(row.get(key) or "NONE").upper()
        if status not in counts:
            status = "NONE"
        counts[status] += 1
    return {
        "present": counts["PRESENT"],
        "none": counts["NONE"],
        "unavailable": counts["UNAVAILABLE"],
        "leads": len(rows),
    }


def calculate_actionability(dataset: Iterable[Mapping]) -> dict:
    """A. Actionability counts over the surfaced opportunity queue."""

    rows = list(dataset or ())
    total = len(rows)
    statuses = [str(r.get("action_status") or "DEFERRED").upper()
                for r in rows]
    label = "all surfaced opportunities"
    return {
        "opportunities_surfaced": _metric(total, total, label),
        "actionable": _metric(
            statuses.count("READY") + statuses.count("IN_PROGRESS"),
            total, label,
            note="actionable = READY + IN_PROGRESS"),
        "ready": _metric(statuses.count("READY"), total, label),
        "blocked": _metric(statuses.count("BLOCKED"), total, label),
        "in_progress": _metric(
            statuses.count("IN_PROGRESS"), total, label),
    }


def calculate_follow_through(dataset: Iterable[Mapping]) -> dict:
    """B. Follow-through over sessions and outcome records."""

    rows = list(dataset or ())
    sessions = [s for row in rows for s in (row.get("sessions") or [])]
    outcomes = [o for row in rows for o in (row.get("outcomes") or [])]
    started = [
        s for s in sessions
        if str(s.get("status") or "").upper() in SESSION_STARTED_STATUSES
    ]
    completed = [
        s for s in sessions
        if str(s.get("status") or "").upper() == "COMPLETED"
    ]
    abandoned = [
        s for s in sessions
        if str(s.get("status") or "").upper() == "ABANDONED"
    ]
    in_progress = [
        s for s in sessions
        if str(s.get("status") or "").upper() == "IN_PROGRESS"
    ]
    outcome_available_leads = sum(
        1 for row in rows
        if str(row.get("outcome_data") or "").upper() != "UNAVAILABLE"
    )
    return {
        "leads": _metric(len(rows), len(rows), "leads in the dataset"),
        "sessions_total": _metric(len(sessions), len(sessions),
                                  "all session records"),
        "sessions_started": _metric(len(started), len(sessions),
                                    "all session records"),
        "sessions_completed": _metric(len(completed), len(started),
                                      "started sessions"),
        "sessions_abandoned": _metric(len(abandoned), len(started),
                                      "started sessions"),
        "sessions_in_progress": _metric(len(in_progress), len(sessions),
                                        "all session records"),
        "outcome_records_created": _metric(
            len(outcomes), outcome_available_leads,
            "leads with outcome data available"),
        "session_data": _availability_counts(rows, "session_data"),
        "outcome_data": _availability_counts(rows, "outcome_data"),
    }


def calculate_conversion(dataset: Iterable[Mapping]) -> dict:
    """C. Conversion ratios, each with an explicit denominator.

    Cross-sectional joins over current state (not longitudinal funnels).
    """

    rows = list(dataset or ())
    ready = [r for r in rows
             if str(r.get("action_status") or "").upper() == "READY"]
    ready_with_session = [
        r for r in ready
        if any(str(s.get("status") or "").upper() in SESSION_STARTED_STATUSES
               for s in (r.get("sessions") or []))
    ]
    sessions = [s for row in rows for s in (row.get("sessions") or [])]
    started = [s for s in sessions
               if str(s.get("status") or "").upper()
               in SESSION_STARTED_STATUSES]
    completed = [s for s in sessions
                 if str(s.get("status") or "").upper() == "COMPLETED"]
    leads_completed = [
        r for r in rows
        if any(str(s.get("status") or "").upper() == "COMPLETED"
               for s in (r.get("sessions") or []))
    ]
    leads_completed_with_terminal = [
        r for r in leads_completed
        if any(str(o.get("status") or "").upper()
               in TERMINAL_OUTCOME_STATUSES
               for o in (r.get("outcomes") or []))
    ]
    leads_terminal = [
        r for r in rows
        if any(str(o.get("status") or "").upper()
               in TERMINAL_OUTCOME_STATUSES
               for o in (r.get("outcomes") or []))
    ]
    leads_accepted = [
        r for r in leads_terminal if any(
            str(o.get("status") or "").upper() == "ACCEPTED"
            for o in (r.get("outcomes") or []))
    ]
    return {
        "ready_to_session": _rate(
            len(ready_with_session), len(ready),
            "currently READY opportunities"),
        "session_to_completed": _rate(
            len(completed), len(started), "started sessions"),
        "completed_to_terminal_outcome": _rate(
            len(leads_completed_with_terminal), len(leads_completed),
            "leads with a completed session"),
        "terminal_to_accepted": _rate(
            len(leads_accepted), len(leads_terminal),
            "leads with a terminal outcome"),
    }


def calculate_time_efficiency(dataset: Iterable[Mapping]) -> dict:
    """D. Time accounting across recorded sessions and outcomes."""

    rows = list(dataset or ())
    sessions = [s for row in rows for s in (row.get("sessions") or [])]
    outcomes = [o for row in rows for o in (row.get("outcomes") or [])]
    planned = sum(_coerce_int(s.get("planned_minutes")) for s in sessions)
    actual = sum(_coerce_int(s.get("actual_minutes")) for s in sessions)
    with_actual = [s for s in sessions
                   if _coerce_int(s.get("actual_minutes")) > 0]
    accepted = [o for o in outcomes
                if str(o.get("status") or "").upper() == "ACCEPTED"]
    accepted_time = sum(_coerce_int(o.get("time_spent_minutes"))
                        for o in accepted)
    return {
        "planned_minutes": _metric(planned, len(sessions),
                                   "all session records"),
        "actual_minutes": _metric(actual, len(sessions),
                                  "all session records"),
        "variance_minutes": _metric(actual - planned, len(sessions),
                                    "all session records"),
        "average_actual_minutes": _metric(
            (round(actual / len(with_actual), 2) if with_actual else None),
            len(with_actual), "sessions with recorded actual time > 0"),
        "accepted_outcome_time": _metric(
            (round(accepted_time / len(accepted), 2) if accepted else None),
            len(accepted), "ACCEPTED outcome records"),
    }


def calculate_blocker_resolution(
    dataset: Iterable[Mapping],
    previous_status_by_lead: Mapping[str, str] | None = None,
) -> dict:
    """E. Blocker metrics; blocked->READY needs caller-supplied history."""

    rows = list(dataset or ())
    blocked = [r for r in rows
               if str(r.get("action_status") or "").upper() == "BLOCKED"]
    blocked_with_session = [
        r for r in blocked
        if any(str(s.get("status") or "").upper() in SESSION_STARTED_STATUSES
               for s in (r.get("sessions") or []))
    ]
    blocked_with_outcome = [
        r for r in blocked
        if any(str(o.get("status") or "").upper() in TERMINAL_OUTCOME_STATUSES
               for o in (r.get("outcomes") or []))
    ]
    previous = previous_status_by_lead or {}
    previously_blocked = [
        r for r in rows
        if str(previous.get(str(r.get("lead_id") or ""), "")).upper()
        == "BLOCKED"
    ]
    became_ready = [
        r for r in previously_blocked
        if str(r.get("action_status") or "").upper() == "READY"
    ]
    if previously_blocked:
        became_ready_metric = _rate(
            len(became_ready), len(previously_blocked),
            "leads blocked in the previous workflow")
    else:
        became_ready_metric = _rate(
            0, 0, "leads blocked in the previous workflow",
            note="no previous workflow supplied; snapshots are external")
    return {
        "blocked_leads": _metric(len(blocked), len(rows),
                                 "leads in the dataset"),
        "blocked_became_ready": became_ready_metric,
        "blocked_to_session": _rate(
            len(blocked_with_session), len(blocked),
            "currently BLOCKED leads"),
        "blocked_to_outcome": _rate(
            len(blocked_with_outcome), len(blocked),
            "currently BLOCKED leads"),
    }


def _hypothesis_status(
    structurally_possible: bool,
    sample_size: int,
    required_sample: int,
) -> str:
    if not structurally_possible:
        return UNTESTABLE
    if sample_size < required_sample:
        return INSUFFICIENT_DATA
    return DIRECTIONAL_SIGNAL  # upgraded to SUPPORTED by callers


def _result(
    hypothesis_id: str,
    status: str,
    sample_size: int,
    required_sample: int,
    metric: str,
    observed_value: Any,
    comparison: str,
    reason: str,
) -> dict:
    return {
        "hypothesis_id": hypothesis_id,
        "status": status,
        "sample_size": sample_size,
        "required_sample": required_sample,
        "metric": metric,
        "observed_value": observed_value,
        "comparison": comparison,
        "reason": reason,
        "limitations": (
            "Deterministic product check only; no statistical test and no "
            "causal claim."
        ),
    }


def evaluate_hypotheses(
    dataset: Iterable[Mapping],
    min_sessions: int = DEFAULT_MIN_SESSIONS,
    min_terminal_outcomes: int = DEFAULT_MIN_TERMINAL_OUTCOMES,
    min_leads: int = DEFAULT_MIN_LEADS,
) -> list[dict]:
    """Evaluate H1-H5 with closed statuses; never reports PROVEN."""

    rows = list(dataset or ())
    sessions = [s for row in rows for s in (row.get("sessions") or [])]
    started = [s for s in sessions
               if str(s.get("status") or "").upper()
               in SESSION_STARTED_STATUSES]
    outcomes = [o for row in rows for o in (row.get("outcomes") or [])]
    terminal = [o for o in outcomes
                if str(o.get("status") or "").upper()
                in TERMINAL_OUTCOME_STATUSES]
    total_leads = len(rows)
    results: list[dict] = []

    # H1: higher Money Score opportunities receive more research attention.
    with_attention = [
        r for r in rows
        if any(str(s.get("status") or "").upper() in SESSION_STARTED_STATUSES
               for s in (r.get("sessions") or []))
    ]
    without_attention = [r for r in rows if r not in with_attention]
    h1_possible = total_leads > 0 and bool(with_attention) \
        and bool(without_attention)
    if not h1_possible:
        h1_status = (UNTESTABLE if total_leads == 0
                     else INSUFFICIENT_DATA)
        h1_reason = ("no opportunities to compare" if total_leads == 0
                     else "no attention group yet (no started sessions)")
    else:
        h1_status = _hypothesis_status(
            True, len(started), min_sessions)
        h1_reason = (
            "attention sample below the minimum" if h1_status
            == INSUFFICIENT_DATA else
            "observed direction compared on current session attention")
    if h1_possible:
        avg_with = round(
            sum(r["money_score"] for r in with_attention)
            / len(with_attention), 2)
        avg_without = round(
            sum(r["money_score"] for r in without_attention)
            / len(without_attention), 2)
        h1_observed = {
            "avg_money_with_attention": avg_with,
            "avg_money_without_attention": avg_without,
            "delta": round(avg_with - avg_without, 2),
        }
        if h1_status not in (UNTESTABLE, INSUFFICIENT_DATA):
            if (avg_with - avg_without) > 0:
                h1_status = (SUPPORTED
                             if (avg_with - avg_without) >= 5
                             and len(with_attention) >= LEADS_PER_GROUP_MIN
                             and len(without_attention)
                             >= LEADS_PER_GROUP_MIN
                             else DIRECTIONAL_SIGNAL)
            else:
                h1_status = DIRECTIONAL_SIGNAL
    else:
        h1_observed = {
            "avg_money_with_attention": None,
            "avg_money_without_attention": None,
            "delta": None,
        }
    results.append(_result(
        "H1", h1_status, len(started), min_sessions,
        "average Money Score with attention vs without",
        h1_observed,
        "with_attention_avg_money > without_attention_avg_money",
        h1_reason))

    # H2: READY converts to sessions more often than BLOCKED.
    ready = [r for r in rows
             if str(r.get("action_status") or "").upper() == "READY"]
    blocked = [r for r in rows
               if str(r.get("action_status") or "").upper() == "BLOCKED"]
    ready_with = [r for r in ready
                  if any(str(s.get("status") or "").upper()
                         in SESSION_STARTED_STATUSES
                         for s in (r.get("sessions") or []))]
    blocked_with = [r for r in blocked
                    if any(str(s.get("status") or "").upper()
                           in SESSION_STARTED_STATUSES
                           for s in (r.get("sessions") or []))]
    h2_possible = bool(ready) and bool(blocked)
    h2_status = (_hypothesis_status(True, len(started), min_sessions)
                 if h2_possible
                 else (UNTESTABLE if total_leads == 0
                       else INSUFFICIENT_DATA))
    h2_ready_rate = (round(len(ready_with) / len(ready), 4)
                     if ready else None)
    h2_blocked_rate = (round(len(blocked_with) / len(blocked), 4)
                       if blocked else None)
    if (h2_status not in (UNTESTABLE, INSUFFICIENT_DATA)
            and h2_ready_rate is not None and h2_blocked_rate is not None
            and h2_ready_rate > h2_blocked_rate):
        h2_status = (SUPPORTED
                     if len(ready) >= LEADS_PER_GROUP_MIN
                     and len(blocked) >= LEADS_PER_GROUP_MIN
                     else DIRECTIONAL_SIGNAL)
    results.append(_result(
        "H2", h2_status, len(started), min_sessions,
        "READY -> session rate vs BLOCKED -> session rate",
        {"ready_rate": h2_ready_rate, "blocked_rate": h2_blocked_rate},
        "ready_session_rate > blocked_session_rate",
        ("no READY/BLOCKED group pair to compare"
         if not h2_possible else
         "session sample below the minimum"
         if h2_status == INSUFFICIENT_DATA else
         "observed conversion compared on current state")))

    # H3: stronger evidence -> less wasted time.
    strong_evidence = [
        r for r in rows
        if str(r.get("evidence_quality") or "").upper()
        in ("HIGH", "MEDIUM")
        and any(str(o.get("status") or "").upper()
                in TERMINAL_OUTCOME_STATUSES
                for o in (r.get("outcomes") or []))
    ]
    weak_evidence = [
        r for r in rows
        if str(r.get("evidence_quality") or "").upper()
        in ("LOW", "NONE")
        and any(str(o.get("status") or "").upper()
                in TERMINAL_OUTCOME_STATUSES
                for o in (r.get("outcomes") or []))
    ]

    def _waste_rate(group: list[dict]) -> float | None:
        terminal_group = [
            o for r in group for o in (r.get("outcomes") or [])
            if str(o.get("status") or "").upper()
            in TERMINAL_OUTCOME_STATUSES
        ]
        if not terminal_group:
            return None
        wasted = sum(
            1 for o in terminal_group
            if str(o.get("status") or "").upper() == "WASTED_TIME")
        return round(wasted / len(terminal_group), 4)

    h3_possible = bool(strong_evidence) and bool(weak_evidence)
    h3_status = (_hypothesis_status(True, len(terminal),
                                    min_terminal_outcomes)
                 if h3_possible
                 else (UNTESTABLE if total_leads == 0
                       else INSUFFICIENT_DATA))
    h3_strong = _waste_rate(strong_evidence)
    h3_weak = _waste_rate(weak_evidence)
    if (h3_status not in (UNTESTABLE, INSUFFICIENT_DATA)
            and h3_strong is not None and h3_weak is not None
            and h3_strong < h3_weak):
        h3_status = (SUPPORTED
                     if len(strong_evidence) >= LEADS_PER_GROUP_MIN
                     and len(weak_evidence) >= LEADS_PER_GROUP_MIN
                     else DIRECTIONAL_SIGNAL)
    results.append(_result(
        "H3", h3_status, len(terminal), min_terminal_outcomes,
        "wasted-time rate: strong evidence vs weak evidence",
        {"strong_evidence_wasted_rate": h3_strong,
         "weak_evidence_wasted_rate": h3_weak},
        "strong_evidence_wasted_rate < weak_evidence_wasted_rate",
        ("no evidence groups with terminal outcomes"
         if not h3_possible else
         "terminal outcome sample below the minimum"
         if h3_status == INSUFFICIENT_DATA else
         "observed waste rate compared on current state")))

    # H4: recommendations reduce research on blocked leads.
    blocked_session_share = (
        round(len(blocked_with) / len(started), 4)
        if started else None
    )
    h4_status = (UNTESTABLE if total_leads == 0
                 else _hypothesis_status(True, len(started), min_sessions))
    if h4_status == DIRECTIONAL_SIGNAL and total_leads > 0:
        blocked_share = len(blocked) / total_leads
        if (blocked_session_share is not None
                and blocked_session_share < blocked_share):
            h4_status = SUPPORTED
        else:
            h4_status = DIRECTIONAL_SIGNAL
    results.append(_result(
        "H4", h4_status, len(started), min_sessions,
        "share of started sessions on currently BLOCKED leads",
        {"blocked_session_share": blocked_session_share,
         "blocked_lead_share": (round(len(blocked) / total_leads, 4)
                                if total_leads else None)},
        "blocked_session_share < blocked_lead_share",
        ("session sample below the minimum"
         if h4_status == INSUFFICIENT_DATA else
         "observed session distribution compared on current state")))

    # H5: accepted outcomes concentrate in high-confidence/high-value leads.
    high_value = [
        r for r in rows
        if str(r.get("confidence") or "").upper() == "HIGH"
        or str(r.get("opportunity_class") or "").upper()
        in ("HIGH_VALUE", "GOOD_OPPORTUNITY")
    ]
    other_value = [r for r in rows if r not in high_value]

    def _acceptance_rate(group: list[dict]) -> float | None:
        terminal_group = [
            o for r in group for o in (r.get("outcomes") or [])
            if str(o.get("status") or "").upper()
            in TERMINAL_OUTCOME_STATUSES
        ]
        if not terminal_group:
            return None
        accepted = sum(
            1 for o in terminal_group
            if str(o.get("status") or "").upper() == "ACCEPTED")
        return round(accepted / len(terminal_group), 4)

    h5_possible = bool(high_value) and bool(other_value)
    h5_status = (_hypothesis_status(True, len(terminal),
                                    min_terminal_outcomes)
                 if h5_possible
                 else (UNTESTABLE if total_leads == 0
                       else INSUFFICIENT_DATA))
    h5_high = _acceptance_rate(high_value)
    h5_other = _acceptance_rate(other_value)
    if (h5_status not in (UNTESTABLE, INSUFFICIENT_DATA)
            and h5_high is not None and h5_other is not None
            and (h5_high - h5_other) > 0):
        h5_status = (SUPPORTED if (h5_high - h5_other) >= SUPPORTED_MARGIN
                     and len(high_value) >= LEADS_PER_GROUP_MIN
                     and len(other_value) >= LEADS_PER_GROUP_MIN
                     else DIRECTIONAL_SIGNAL)
    results.append(_result(
        "H5", h5_status, len(terminal), min_terminal_outcomes,
        "acceptance rate: high-confidence/high-value vs other leads",
        {"high_value_acceptance_rate": h5_high,
         "other_acceptance_rate": h5_other},
        "high_value_acceptance_rate > other_acceptance_rate",
        ("no confidence/value groups with terminal outcomes"
         if not h5_possible else
         "terminal outcome sample below the minimum"
         if h5_status == INSUFFICIENT_DATA else
         "observed acceptance compared on current state")))

    return results


def _product_decision(
    rows: list[dict],
    sessions_started: int,
    terminal_outcomes: int,
    min_sessions: int,
    min_outcomes: int,
    min_leads: int,
) -> tuple[str, str]:
    if not rows:
        return (RETHINK_WORKFLOW,
                "no opportunities were surfaced by the pipeline")
    # Hard floor: zero-samples can never "continue productization" even when
    # degenerate thresholds are supplied.
    need_sessions = max(1, min_sessions)
    need_outcomes = max(1, min_outcomes)
    need_leads = max(1, min_leads)
    if (sessions_started < need_sessions
            or terminal_outcomes < need_outcomes
            or len(rows) < need_leads):
        return (
            COLLECT_MORE_DATA,
            "insufficient real research activity: "
            f"{sessions_started}/{need_sessions} started sessions, "
            f"{terminal_outcomes}/{need_outcomes} terminal outcomes, "
            f"{len(rows)}/{need_leads} leads",
        )
    return (
        CONTINUE_PRODUCTIZATION,
        "minimum sample thresholds met; hypotheses can be evaluated "
        "directionally (still not statistical proof)",
    )


def build_product_validation_report(
    dataset: Iterable[Mapping],
    min_sessions: int = DEFAULT_MIN_SESSIONS,
    min_terminal_outcomes: int = DEFAULT_MIN_TERMINAL_OUTCOMES,
    min_leads: int = DEFAULT_MIN_LEADS,
    previous_status_by_lead: Mapping[str, str] | None = None,
    generated_at: str = "",
) -> dict:
    """Deterministic product validation report (read-only, no new score)."""

    rows = list(dataset or ())
    min_sessions = max(0, _coerce_int(min_sessions, DEFAULT_MIN_SESSIONS))
    min_terminal_outcomes = max(
        0, _coerce_int(min_terminal_outcomes, DEFAULT_MIN_TERMINAL_OUTCOMES))
    min_leads = max(0, _coerce_int(min_leads, DEFAULT_MIN_LEADS))

    follow = calculate_follow_through(rows)
    sessions_started = _coerce_int(follow["sessions_started"]["value"])
    terminal_outcomes = sum(
        1 for row in rows for o in (row.get("outcomes") or [])
        if str(o.get("status") or "").upper() in TERMINAL_OUTCOME_STATUSES
    )
    hypotheses = evaluate_hypotheses(
        rows,
        min_sessions=min_sessions,
        min_terminal_outcomes=min_terminal_outcomes,
        min_leads=min_leads,
    )
    decision, reason = _product_decision(
        rows, sessions_started, terminal_outcomes, min_sessions,
        min_terminal_outcomes, min_leads)

    return {
        "validation_version": VALIDATION_VERSION,
        "generated_at": str(generated_at or ""),
        "thresholds": {
            "min_sessions": min_sessions,
            "min_terminal_outcomes": min_terminal_outcomes,
            "min_leads": min_leads,
        },
        "totals": {
            "leads": len(rows),
            "sessions": _coerce_int(follow["sessions_total"]["value"]),
            "sessions_started": sessions_started,
            "terminal_outcomes": terminal_outcomes,
            "opportunities": len(rows),
        },
        "data_coverage": {
            "opportunity_data": _availability_counts(rows,
                                                     "opportunity_data"),
            "session_data": _availability_counts(rows, "session_data"),
            "outcome_data": _availability_counts(rows, "outcome_data"),
        },
        "actionability": calculate_actionability(rows),
        "follow_through": follow,
        "conversion": calculate_conversion(rows),
        "time_efficiency": calculate_time_efficiency(rows),
        "blocker_resolution": calculate_blocker_resolution(
            rows, previous_status_by_lead),
        "hypotheses": hypotheses,
        "supported_hypotheses": [
            h["hypothesis_id"] for h in hypotheses
            if h["status"] == SUPPORTED
        ],
        "product_decision": decision,
        "decision_reason": reason,
        "limitations": list(_LIMITATIONS),
        "research_only": True,
    }
