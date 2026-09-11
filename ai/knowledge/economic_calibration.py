"""Stage R25.6 deterministic Money Score calibration (read-only audit).

Pure, offline, bounded functions that join the existing R25 economic
projections with the R25.5 research outcomes and measure whether the current
Money Score ordering appears economically useful against observed outcomes.

This module NEVER changes Money Score weights, never self-tunes, never
predicts payouts and never claims statistical significance. It evaluates the
r25-1 formula as-is and returns a deterministic recommendation state for a
human-reviewed future stage.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no browser, no PoC execution, no 5B-5J, no findings, no alerts, no Mongo
writes. Pure functions of their inputs: no clock, no randomness (the caller
supplies ``generated_at``).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

# Calibration engine rule version. Deliberately kept equal to the Money Score
# rule it evaluates: no new formula has been approved, so r25-1 is preserved.
CALIBRATION_RULE_VERSION = "r25-1"

DEFAULT_MIN_TERMINAL_OUTCOMES = 10

# Deterministic score bands (score_min inclusive, score_max inclusive),
# ordered highest first.
SCORE_BANDS: tuple[tuple[str, int, int], ...] = (
    ("P1", 85, 100),
    ("P2", 65, 84),
    ("P3", 45, 64),
    ("P4", 30, 44),
    ("P5", 0, 29),
)

SUFFICIENT_SAMPLE = "SUFFICIENT_SAMPLE"
INSUFFICIENT_SAMPLE = "INSUFFICIENT_SAMPLE"

# Recommendation states (never an automatic weight change).
NO_DATA = "NO_DATA"
INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
CONSISTENT = "CONSISTENT"
POSSIBLE_MISORDERING = "POSSIBLE_MISORDERING"
REVIEW_REQUIRED = "REVIEW_REQUIRED"

# Terminal (decided) statuses; IN_PROGRESS is excluded from terminal stats.
TERMINAL_STATUSES: tuple[str, ...] = (
    "ACCEPTED",
    "DUPLICATE",
    "REJECTED",
    "NOT_APPLICABLE",
    "WASTED_TIME",
)

NEGATIVE_STATUSES: tuple[str, ...] = (
    "DUPLICATE",
    "REJECTED",
    "NOT_APPLICABLE",
    "WASTED_TIME",
)

STATEMENT_WEIGHTS_UNCHANGED = "Money Score weights were not changed."

_LIMITATIONS: tuple[str, ...] = (
    "Descriptive audit only: no statistical significance test is implemented.",
    "Observational data only: no randomization and no causal inference.",
    "Outcomes are self-reported; identical submissions collapse into one "
    "content-addressed outcome (R25.5).",
    "No payout, bounty or monetary value is considered anywhere.",
    "IN_PROGRESS outcomes are excluded from terminal statistics and rates.",
    "The r25-1 Money Score formula is evaluated as-is; this report never "
    "changes weights or self-tunes.",
    "Empty bands carry no signal and are never used to justify conclusions.",
)


def band_for_score(money_score: Any) -> str:
    """Deterministic score band for a Money Score (clamped to [0, 100])."""

    try:
        score = int(money_score)
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(100, score))
    for name, lo, hi in SCORE_BANDS:
        if lo <= score <= hi:
            return name
    return "P5"  # unreachable: bands cover [0, 100]


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def _perf_map(performances: Any) -> dict:
    """Accept a {lead_id: performance} mapping or a list of performances."""

    if isinstance(performances, Mapping):
        return {
            str(key): value
            for key, value in performances.items()
            if isinstance(value, Mapping)
        }
    out: dict = {}
    for item in performances or ():
        if isinstance(item, Mapping) and item.get("lead_id"):
            out[str(item["lead_id"])] = item
    return out


def _row_for(projection: Mapping, performance: Mapping | None) -> dict:
    subs = projection.get("subscores") or {}
    perf = performance or {}
    terminal = int(perf.get("terminal_attempts") or 0)
    return {
        "lead_id": str(projection.get("lead_id") or ""),
        "cve_id": str(projection.get("cve_id") or ""),
        "program": str(projection.get("program") or ""),
        "money_score": int(projection.get("money_score") or 0),
        "priority": str(projection.get("priority") or ""),
        "band": band_for_score(projection.get("money_score") or 0),
        "confidence": str(projection.get("confidence") or ""),
        "confidence_score": int(subs.get("confidence") or 0),
        "value": int(subs.get("value") or 0),
        "effort": int(subs.get("effort") or 0),
        "risk": int(subs.get("risk") or 0),
        "attempts": int(perf.get("attempts") or 0),
        "terminal_outcomes": terminal,
        "in_progress": int(perf.get("in_progress") or 0),
        "accepted": int(perf.get("accepted") or 0),
        "duplicate": int(perf.get("duplicate") or 0),
        "rejected": int(perf.get("rejected") or 0),
        "not_applicable": int(perf.get("not_applicable") or 0),
        "wasted_time": int(perf.get("wasted_time") or 0),
        "total_time_spent_minutes": int(
            perf.get("total_time_spent_minutes") or 0
        ),
        "average_time_spent_minutes": int(
            perf.get("average_time_spent_minutes") or 0
        ),
        "acceptance_rate": float(perf.get("acceptance_rate") or 0.0),
        "duplicate_rate": float(perf.get("duplicate_rate") or 0.0),
        "wasted_rate": float(perf.get("wasted_rate") or 0.0),
        "data_quality": str(perf.get("data_quality") or "NONE"),
        "outcome_confidence": str(perf.get("outcome_confidence") or "NONE"),
    }


def build_calibration_dataset(
    projections: Iterable[Mapping], performances: Any
) -> list[dict]:
    """Join R25 projections with R25.5 outcomes by lead_id.

    Deterministic ordering: money_score DESC, CVE ASC, program ASC, lead_id ASC.
    A missing performance row yields an explicit zero-outcome row (never
    fabricated counts).
    """

    perf_map = _perf_map(performances)
    dataset: list[dict] = []
    for projection in projections or ():
        if not isinstance(projection, Mapping):
            continue
        lead_id = str(projection.get("lead_id") or "")
        dataset.append(_row_for(projection, perf_map.get(lead_id)))
    dataset.sort(
        key=lambda row: (
            -row["money_score"], row["cve_id"], row["program"], row["lead_id"]
        )
    )
    return dataset


def _aggregate(rows: Iterable[Mapping]) -> dict:
    rows = list(rows or ())
    counts = {status: 0 for status in TERMINAL_STATUSES}
    attempts = 0
    terminal = 0
    in_progress = 0
    total_time = 0
    terminal_time = 0
    leads_with_outcomes = 0
    for row in rows:
        attempts += int(row.get("attempts") or 0)
        terminal += int(row.get("terminal_outcomes") or 0)
        in_progress += int(row.get("in_progress") or 0)
        total_time += int(row.get("total_time_spent_minutes") or 0)
        # per-lead average is terminal-only (R25.5), reconstruct terminal time
        terminal_time += (
            int(row.get("average_time_spent_minutes") or 0)
            * int(row.get("terminal_outcomes") or 0)
        )
        if int(row.get("attempts") or 0) > 0:
            leads_with_outcomes += 1
        for status in TERMINAL_STATUSES:
            counts[status] += int(row.get(status.lower()) or 0)
    accepted = counts["ACCEPTED"]
    duplicate = counts["DUPLICATE"]
    rejected = counts["REJECTED"]
    not_applicable = counts["NOT_APPLICABLE"]
    wasted = counts["WASTED_TIME"]
    negative = duplicate + rejected + not_applicable + wasted
    return {
        "leads": len(rows),
        "leads_with_outcomes": leads_with_outcomes,
        "attempts": attempts,
        "terminal_outcomes": terminal,
        "in_progress": in_progress,
        "accepted": accepted,
        "duplicate": duplicate,
        "rejected": rejected,
        "not_applicable": not_applicable,
        "wasted_time": wasted,
        "acceptance_rate": _rate(accepted, terminal),
        "duplicate_rate": _rate(duplicate, terminal),
        "wasted_rate": _rate(wasted, terminal),
        "negative_rate": _rate(negative, terminal),
        "total_time_spent_minutes": total_time,
        "average_time_spent_minutes": (
            int(terminal_time / terminal) if terminal > 0 else 0
        ),
    }


def calculate_band_statistics(
    dataset: Iterable[Mapping], min_samples: int = DEFAULT_MIN_TERMINAL_OUTCOMES
) -> list[dict]:
    """Per-populated-band statistics with a deterministic sample status.

    Only bands that contain at least one lead are returned. Order is highest
    band first (P1 -> P5). Empty bands are never invented or reasoned about.
    """

    try:
        threshold = max(int(min_samples), 1)
    except (TypeError, ValueError):
        threshold = DEFAULT_MIN_TERMINAL_OUTCOMES
    rows = list(dataset or ())
    bands: list[dict] = []
    for name, lo, hi in SCORE_BANDS:
        band_rows = [row for row in rows if row.get("band") == name]
        if not band_rows:
            continue
        stats = _aggregate(band_rows)
        terminal = stats["terminal_outcomes"]
        stats.update(
            {
                "band": name,
                "score_min": lo,
                "score_max": hi,
                "sample_status": (
                    SUFFICIENT_SAMPLE
                    if terminal >= threshold
                    else INSUFFICIENT_SAMPLE
                ),
                "minimum_terminal_outcomes": threshold,
                # R25.6 4 aliases (identical observed values)
                "observed_acceptance_rate": stats["acceptance_rate"],
                "observed_waste_rate": stats["wasted_rate"],
                "observed_duplicate_rate": stats["duplicate_rate"],
                "observed_negative_rate": stats["negative_rate"],
                "observed_average_time": stats["average_time_spent_minutes"],
            }
        )
        bands.append(stats)
    return bands


def calculate_global_statistics(dataset: Iterable[Mapping]) -> dict:
    """Global statistics across the whole calibration dataset."""

    return _aggregate(list(dataset or ()))


def assess_score_ordering(
    bands: Iterable[Mapping],
    min_samples: int = DEFAULT_MIN_TERMINAL_OUTCOMES,
) -> tuple[str, list[str]]:
    """Deterministic recommendation state for the r25-1 ordering.

    Rules (documented, conservative):

    - no populated bands -> ``NO_DATA``;
    - no terminal outcomes anywhere -> ``INSUFFICIENT_DATA``;
    - fewer than two bands with ``SUFFICIENT_SAMPLE`` -> ``INSUFFICIENT_DATA``;
    - with >= 2 sufficient bands, comparing adjacent bands high -> low:
      - ``CONSISTENT`` when every higher band has equal-or-better acceptance
        and equal-or-lower wasted rate;
      - ``POSSIBLE_MISORDERING`` when every higher band performs strictly
        worse on both acceptance and wasted rate;
      - ``REVIEW_REQUIRED`` otherwise (mixed evidence).

    Statistical significance is never claimed.
    """

    band_list = [
        band for band in (bands or ()) if isinstance(band, Mapping)
    ]
    try:
        threshold = max(int(min_samples), 1)
    except (TypeError, ValueError):
        threshold = DEFAULT_MIN_TERMINAL_OUTCOMES

    if not band_list:
        return NO_DATA, ["no populated score bands in the calibration dataset"]

    total_terminal = sum(
        int(band.get("terminal_outcomes") or 0) for band in band_list
    )
    if total_terminal == 0:
        return INSUFFICIENT_DATA, [
            "no terminal research outcomes recorded yet",
        ]

    sufficient = [
        band
        for band in band_list
        if int(band.get("terminal_outcomes") or 0) >= threshold
    ]
    if not sufficient:
        return INSUFFICIENT_DATA, [
            f"no score band reaches {threshold} terminal outcomes",
        ]
    if len(sufficient) < 2:
        return INSUFFICIENT_DATA, [
            "fewer than two score bands have sufficient samples to compare "
            "ordering",
        ]

    sufficient.sort(key=lambda band: -int(band.get("score_min") or 0))
    pairs = list(zip(sufficient, sufficient[1:]))
    consistent = all(
        float(high.get("acceptance_rate") or 0.0)
        >= float(low.get("acceptance_rate") or 0.0)
        and float(high.get("wasted_rate") or 0.0)
        <= float(low.get("wasted_rate") or 0.0)
        for high, low in pairs
    )
    reversed_all = all(
        float(high.get("acceptance_rate") or 0.0)
        < float(low.get("acceptance_rate") or 0.0)
        and float(high.get("wasted_rate") or 0.0)
        > float(low.get("wasted_rate") or 0.0)
        for high, low in pairs
    )

    if consistent:
        return CONSISTENT, [
            "higher Money Score bands show equal-or-better observed "
            "acceptance and equal-or-lower observed wasted rates",
        ]
    if reversed_all:
        return POSSIBLE_MISORDERING, [
            "higher Money Score bands systematically show worse observed "
            "acceptance and higher observed wasted rates; human review "
            "required before any weight change",
        ]
    return REVIEW_REQUIRED, [
        "mixed evidence across score bands; ordering is not clearly "
        "consistent or misordered",
    ]


def build_calibration_report(
    projections: Iterable[Mapping],
    performances: Any,
    min_samples: int = DEFAULT_MIN_TERMINAL_OUTCOMES,
    generated_at: str = "",
) -> dict:
    """Offline calibration report for the r25-1 Money Score (read-only).

    Never changes weights, never self-tunes, never predicts payouts. The only
    clock-derived value is the caller-supplied ``generated_at`` metadata.
    """

    try:
        threshold = max(int(min_samples), 1)
    except (TypeError, ValueError):
        threshold = DEFAULT_MIN_TERMINAL_OUTCOMES
    try:
        from ai.knowledge.economics import RULE_VERSION as money_rule
    except Exception:  # pragma: no cover - economics is a stable sibling
        money_rule = "r25-1"
    dataset = build_calibration_dataset(projections, performances)
    bands = calculate_band_statistics(dataset, min_samples=threshold)
    global_stats = calculate_global_statistics(dataset)
    recommendation, reasons = assess_score_ordering(
        bands, min_samples=threshold
    )
    return {
        "rule_version": CALIBRATION_RULE_VERSION,
        "current_money_score_rule": str(money_rule),
        "generated_at": str(generated_at or ""),
        "minimum_terminal_outcomes": threshold,
        "total_leads": global_stats["leads"],
        "total_terminal_outcomes": global_stats["terminal_outcomes"],
        "bands": bands,
        "global_statistics": global_stats,
        "recommendation": recommendation,
        "recommendation_reasons": list(reasons),
        "limitations": list(_LIMITATIONS),
        "weights_unchanged": True,
        "statement": STATEMENT_WEIGHTS_UNCHANGED,
        "research_only": True,
    }
