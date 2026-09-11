"""backend/research_calibration.py — Stage R25.6 read-only calibration view.

Thin composition layer: gathers the existing R25 economic projections and the
R25.5 per-lead performance summaries, then calls the pure deterministic engine
in ``ai.knowledge.economic_calibration``.

READ-ONLY: no writes, no persistence, no network, no DNS, no LLM, no
subprocess, no target interaction, no Nuclei, no browser, no PoC execution,
no 5B-5J, no findings, no alerts. The Money Score is never modified and no
weights are ever changed or self-tuned.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ai.knowledge.economic_calibration import (
    DEFAULT_MIN_TERMINAL_OUTCOMES,
    build_calibration_report,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_report(
    min_samples: int = DEFAULT_MIN_TERMINAL_OUTCOMES,
    cve: Optional[str] = None,
    program: Optional[str] = None,
) -> dict:
    """Build the deterministic calibration report for the current corpus.

    Never writes, never tunes, never predicts payouts.
    """

    try:
        threshold = int(min_samples)
    except (TypeError, ValueError):
        threshold = DEFAULT_MIN_TERMINAL_OUTCOMES
    if threshold < 1:
        raise ValueError("min_samples must be >= 1")

    from backend import research_economics
    from backend import research_outcomes

    projections = research_economics.build_economics()
    if cve:
        from backend.research_data import normalize_cve

        cve = normalize_cve(cve)
        projections = [p for p in projections if p["cve_id"] == cve]
    if program:
        program = str(program).strip()
        projections = [p for p in projections if p["program"] == program]

    performances: dict = {}
    for projection in projections:
        lead_id = str(projection.get("lead_id") or "")
        if not lead_id:
            continue
        try:
            performances[lead_id] = research_outcomes.lead_performance(lead_id)
        except Exception:
            performances[lead_id] = {}
    return build_calibration_report(
        projections,
        performances,
        min_samples=threshold,
        generated_at=_utcnow(),
    )


def calibration_summary(
    min_samples: int = DEFAULT_MIN_TERMINAL_OUTCOMES,
) -> dict:
    """Compact read-only summary for the leads UI/CLI strip."""

    report = build_report(min_samples=min_samples)
    return {
        "rule_version": report["rule_version"],
        "current_money_score_rule": report["current_money_score_rule"],
        "minimum_terminal_outcomes": report["minimum_terminal_outcomes"],
        "terminal_outcomes": report["total_terminal_outcomes"],
        "total_leads": report["total_leads"],
        "recommendation": report["recommendation"],
        "weights_unchanged": report["weights_unchanged"],
        "statement": report["statement"],
        "research_only": True,
    }
