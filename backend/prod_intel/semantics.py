"""backend/prod_intel/semantics.py — honest metric vocabulary.

State semantics (documented for section 16 of the Epic report):

``ok``                   the source was readable and the aggregation ran;
                         ``value`` is exact for the stated population.
``unknown``              the thing exists but its state cannot be
                         observed right now (e.g. worker liveness with no
                         heartbeat). Never rendered as a number.
``unavailable``          the source itself is missing/unreadable in this
                         deployment — never zero-filled.
``not_observed``         the source is readable but nothing happened in
                         the requested window (an OBSERVED empty set, not
                         missing data).
``insufficient_population`` for rates: the denominator is 0, so no
                         percentage exists. Rates are ``None``, never 0%.

``zero`` is only ever emitted from a readable source as an exact count.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

PROJECTION_RULE_VERSION = "production-intelligence-v1"

OK = "ok"
UNKNOWN = "unknown"
UNAVAILABLE = "unavailable"
NOT_OBSERVED = "not_observed"
INSUFFICIENT_POPULATION = "insufficient_population"

DEFAULT_WINDOW_HOURS = 168          # 7 days — bounded, documented
MAX_WINDOW_HOURS = 24 * 90          # hard cap: no unbounded scans


def window_bounds(hours: float | int | None = None
                  ) -> tuple[str, dict[str, Any]]:
    """(iso_lower, window_dict) for a time-window filter.

    ``hours=None`` means "all persisted history" (window is ``None`` in
    the provenance dict — the population statement, not a fake range).
    """
    if hours is None:
        return "", {"hours": None, "range": None, "kind": "all_history"}
    try:
        h = float(hours)
    except (TypeError, ValueError):
        h = DEFAULT_WINDOW_HOURS
    h = min(max(h, 0.0), float(MAX_WINDOW_HOURS))
    start = datetime.now(timezone.utc) - timedelta(hours=h)
    iso = start.isoformat()
    return iso, {"hours": h, "range": {"from": iso},
                 "kind": "rolling_window"}


def metric(value: Any, *, source: str, population: str,
           aggregation: str, time_range: dict[str, Any] | None = None,
           state: str = OK, **extra: Any) -> dict[str, Any]:
    """One fully-provenanced metric. ``value`` may be a count/list/None."""
    return {
        "value": value,
        "state": state,
        "source": source,
        "population": population,
        "aggregation": aggregation,
        "time_range": time_range or {"hours": None, "kind": "all_history"},
        "rule_version": PROJECTION_RULE_VERSION,
        **extra,
    }


def unavailable_metric(source: str, population: str, aggregation: str,
                       reason: str, **extra: Any) -> dict[str, Any]:
    """A metric whose source could not be read — value stays None."""
    return metric(None, source=source, population=population,
                  aggregation=aggregation, state=UNAVAILABLE,
                  reason=str(reason)[:200], **extra)


def rate(numerator: int, denominator: int, *, source: str,
         numerator_semantics: str, denominator_semantics: str,
         time_range: dict[str, Any] | None = None) -> dict[str, Any]:
    """Funnel conversion with an explicit denominator.

    A 0 denominator yields ``rate=None`` + ``insufficient_population`` —
    never 0%, never "0% success". Correlation only; no causality claim.
    """
    base = {
        "numerator": int(numerator),
        "denominator": int(denominator),
        "numerator_semantics": numerator_semantics,
        "denominator_semantics": denominator_semantics,
        "source": source,
        "time_range": time_range or {"hours": None, "kind": "all_history"},
        "rule_version": PROJECTION_RULE_VERSION,
        "interpretation": "descriptive correlation, not causation",
    }
    if int(denominator) <= 0:
        return {**base, "rate": None, "state": INSUFFICIENT_POPULATION}
    return {**base, "rate": round(int(numerator) / int(denominator), 4),
            "state": OK}


def in_window(ts: str, iso_lower: str) -> bool:
    """True when ``ts`` >= ``iso_lower`` ("" lower bound = everything).

    ISO-8601 UTC strings with offsets compare correctly lexicographically
    only when both carry offsets; persisted Watch timestamps all do.
    Unparseable timestamps count as OUT of a bounded window (never
    silently in).
    """
    if not iso_lower:
        return True
    if not ts:
        return False
    return str(ts) >= iso_lower


def dedupe_by(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in items:
        k = str(row.get(key) or "")
        if k and k not in seen:
            seen.add(k)
            out.append(row)
    return out
