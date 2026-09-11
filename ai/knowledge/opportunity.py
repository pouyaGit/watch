"""Stage R26.1 deterministic opportunity intelligence (pure engine).

Composes the already-persisted R18/R21/R22/R23/R24/R25 signals into a
read-only research-opportunity view. This is a presentation/decision layer,
NOT a new scoring formula: the Money Score is copied verbatim and never
modified. No I/O, no network, no LLM, no Mongo, no subprocess, no execution.

Pure functions of their inputs: no clock, no randomness.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ai.schemas.research_opportunity import (
    OPPORTUNITY_RULE_VERSION,
    ResearchOpportunity,
    opportunity_id_for,
)

# Fixed class order used for ranking (best -> worst).
CLASS_ORDER: dict[str, int] = {
    "HIGH_VALUE": 0,
    "GOOD_OPPORTUNITY": 1,
    "RESEARCH_FIRST": 2,
    "LOW_CONFIDENCE": 3,
    "BLOCKED": 4,
    "DEFER": 5,
}

# Fixed why-now reason order (deterministic output).
WHY_NOW_ORDER: tuple[str, ...] = (
    "PUBLIC_POC",
    "EXPLOIT_AVAILABLE",
    "CRITICAL_PRIORITY",
    "HIGH_PRIORITY",
    "TECHNOLOGY_OBSERVED",
    "COMPONENT_OBSERVED",
    "PRODUCT_MATCHED",
    "HIGH_CONFIDENCE",
    "LOW_RESEARCH_EFFORT",
    "NO_TERMINAL_OUTCOME",
    "PREVIOUSLY_ACCEPTED",
    "PREVIOUSLY_DUPLICATED",
    "HIGH_WASTE_RATE",
    "ACTIVE_SESSION",
    "NO_SESSION_HISTORY",
)

# Lead reason codes that map 1:1 to why-now codes (existing structured data).
_LEAD_REASON_TO_WHY_NOW = {
    "PUBLIC_POC": "PUBLIC_POC",
    "EXPLOIT_AVAILABLE": "EXPLOIT_AVAILABLE",
    "TECHNOLOGY_OBSERVED": "TECHNOLOGY_OBSERVED",
    "COMPONENT_OBSERVED": "COMPONENT_OBSERVED",
    "PRODUCT_MATCHED": "PRODUCT_MATCHED",
}

# Effort score -> deterministic midpoint estimate in minutes (presentation of
# the existing R25 effort score bands; not a new score).
ESTIMATED_MINUTES_TABLE: tuple[tuple[int, int], ...] = (
    (25, 20),    # 15-30 min band midpoint
    (45, 45),    # 30-60 min band midpoint
    (65, 90),    # 1-2 h band midpoint
    (85, 240),   # 2-6 h band midpoint
    (100, 480),  # 1-3 days band midpoint
)

_CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
_EVIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

# Blockers that mean the asset relationship to the vulnerability is unproven.
_ASSET_UNVERIFIED_BLOCKER = "only generic technology match"
_PLUGIN_NOT_OBSERVED = "affected plugin not observed"
_COMPONENT_NOT_OBSERVED = "asset component not observed"


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def estimated_minutes_for(effort_score: Any) -> int:
    """Deterministic midpoint estimate from the existing R25 effort score."""

    try:
        score = int(effort_score)
    except (TypeError, ValueError):
        return 0
    score = max(0, min(100, score))
    for threshold, minutes in ESTIMATED_MINUTES_TABLE:
        if score <= threshold:
            return minutes
    return 480


def classify_opportunity(
    money_score: Any,
    confidence: str,
    blockers: Iterable[str],
    evidence_present: bool,
) -> str:
    """Deterministic research-attention class (never replaces Money Score).

    Precedence (documented; conservative):
      1. ``BLOCKED``            hard asset-match blockers present
      2. ``HIGH_VALUE``         money >= 65 and confidence HIGH
      3. ``GOOD_OPPORTUNITY``   money >= 45 and confidence >= MEDIUM
      4. ``RESEARCH_FIRST``     money >= 30 and evidence exists
      5. ``LOW_CONFIDENCE``     confidence LOW
      6. ``DEFER``              otherwise
    """

    try:
        money = int(money_score)
    except (TypeError, ValueError):
        money = 0
    conf = str(confidence or "LOW").strip().upper()
    blocker_set = {str(b).strip() for b in (blockers or ())}
    asset_unverified = _ASSET_UNVERIFIED_BLOCKER in blocker_set and (
        _PLUGIN_NOT_OBSERVED in blocker_set
        or _COMPONENT_NOT_OBSERVED in blocker_set
    )
    if asset_unverified:
        return "BLOCKED"
    if money >= 65 and conf == "HIGH":
        return "HIGH_VALUE"
    if money >= 45 and conf in ("HIGH", "MEDIUM"):
        return "GOOD_OPPORTUNITY"
    if money >= 30 and evidence_present:
        return "RESEARCH_FIRST"
    if conf == "LOW":
        return "LOW_CONFIDENCE"
    return "DEFER"


def _lead_reason_codes(lead: Any) -> set[str]:
    codes: set[str] = set()
    for reason in _get(lead, "reasons", []) or []:
        code = str(_get(reason, "code", "") or "").strip().upper()
        if code:
            codes.add(code)
    return codes


def build_why_now(
    lead: Any,
    economic: Any,
    outcomes: Any,
    sessions: Any,
    evidence: Any,
) -> list[str]:
    """Deterministic why-now codes mapped directly to structured fields."""

    candidates: set[str] = set()
    reason_codes = _lead_reason_codes(lead)
    for code, why in _LEAD_REASON_TO_WHY_NOW.items():
        if code in reason_codes:
            candidates.add(why)

    priority = str(_get(economic, "priority") or "").strip().upper()
    if priority == "P1_START_NOW":
        candidates.add("CRITICAL_PRIORITY")
    elif priority == "P2_HIGH":
        candidates.add("HIGH_PRIORITY")
    # R16 class is also accepted when composed directly from a queue row.
    priority_level = str(_get(lead, "priority_level") or "").upper()
    if priority_level == "CRITICAL_RESEARCH":
        candidates.add("CRITICAL_PRIORITY")
    elif priority_level == "HIGH_RESEARCH":
        candidates.add("HIGH_PRIORITY")

    if str(_get(economic, "confidence") or "").upper() == "HIGH":
        candidates.add("HIGH_CONFIDENCE")

    try:
        effort = int(_get(economic, "effort") or 0)
    except (TypeError, ValueError):
        effort = 0
    if 0 < effort <= 45:
        candidates.add("LOW_RESEARCH_EFFORT")

    try:
        terminal = int(_get(outcomes, "terminal_attempts") or 0)
    except (TypeError, ValueError):
        terminal = 0
    if terminal == 0:
        candidates.add("NO_TERMINAL_OUTCOME")
    if int(_get(outcomes, "accepted") or 0) > 0:
        candidates.add("PREVIOUSLY_ACCEPTED")
    if int(_get(outcomes, "duplicate") or 0) > 0:
        candidates.add("PREVIOUSLY_DUPLICATED")
    try:
        wasted_rate = float(_get(outcomes, "wasted_rate") or 0.0)
    except (TypeError, ValueError):
        wasted_rate = 0.0
    if terminal > 0 and wasted_rate >= 0.5:
        candidates.add("HIGH_WASTE_RATE")

    if str(_get(sessions, "session_status") or "NONE").upper() == "ACTIVE":
        candidates.add("ACTIVE_SESSION")
    try:
        total_sessions = int(_get(sessions, "total_sessions") or 0)
    except (TypeError, ValueError):
        total_sessions = 0
    if total_sessions == 0:
        candidates.add("NO_SESSION_HISTORY")

    return [code for code in WHY_NOW_ORDER if code in candidates]


def _recommended_action(
    opportunity_class: str, session_status: str
) -> str:
    if str(session_status or "NONE").upper() == "ACTIVE":
        return "CONTINUE_SESSION"
    return {
        "HIGH_VALUE": "START_RESEARCH",
        "GOOD_OPPORTUNITY": "START_RESEARCH",
        "RESEARCH_FIRST": "RESEARCH_WITH_EVIDENCE",
        "LOW_CONFIDENCE": "GATHER_EVIDENCE",
        "BLOCKED": "VERIFY_ASSET_MATCH",
        "DEFER": "DEFER",
    }.get(opportunity_class, "DEFER")


def build_opportunity(
    lead: Any,
    economic: Any,
    outcomes: Any,
    sessions: Any,
    evidence: Any,
) -> ResearchOpportunity:
    """Compose one read-only opportunity view (Money Score copied verbatim)."""

    blockers = list(_get(economic, "main_blockers") or []) or list(
        _get(lead, "blockers") or []
    )
    evidence_summary = dict(_get(evidence, "evidence_summary") or evidence or {})
    evidence_present = bool(
        int(_get(evidence_summary, "evidence_count") or 0) > 0
        or int(_get(evidence_summary, "source_count") or 0) > 0
    )
    opportunity_class = classify_opportunity(
        _get(economic, "money_score") or 0,
        str(_get(economic, "confidence") or "LOW"),
        blockers,
        evidence_present,
    )

    estimated = estimated_minutes_for(_get(economic, "effort") or 0)
    actual = int(_get(sessions, "actual_time") or 0)
    history = str(
        _get(sessions, "historical_time_status") or "NONE"
    ).upper()
    efficiency = _get(sessions, "efficiency_ratio")
    if not isinstance(efficiency, (int, float)):
        efficiency = None
    delta = (actual - estimated) if history != "NONE" else 0

    evidence_quality = str(
        _get(evidence_summary, "evidence_confidence") or "NONE"
    ).upper()
    if evidence_quality not in _EVIDENCE_RANK:
        evidence_quality = "NONE"

    session_status = str(_get(sessions, "session_status") or "NONE").upper()
    subs = _get(economic, "subscores")
    subs = subs if isinstance(subs, Mapping) else {}

    return ResearchOpportunity(
        opportunity_id=opportunity_id_for(str(_get(lead, "lead_id") or "")),
        lead_id=str(_get(lead, "lead_id") or ""),
        cve_id=str(_get(lead, "cve_id") or ""),
        program=str(_get(lead, "program") or ""),
        money_score=int(_get(economic, "money_score") or 0),
        money_priority=str(_get(economic, "priority") or ""),
        confidence=str(_get(economic, "confidence") or "LOW").upper(),
        confidence_score=int(subs.get("confidence") or 0),
        value_score=int(subs.get("value") or 0),
        effort_score=int(_get(economic, "effort") or 0),
        risk_score=int(subs.get("risk") or 0),
        asset_match=str(_get(economic, "asset_match") or "NONE"),
        evidence_quality=evidence_quality,
        research_status=str(
            _get(evidence_summary, "latest_research_status") or "NONE"
        ),
        outcome_status=str(_get(outcomes, "outcome_status") or "NONE"),
        session_status=session_status,
        estimated_minutes=estimated,
        actual_minutes=actual,
        time_delta_minutes=delta,
        efficiency_ratio=(
            round(float(efficiency), 4)
            if isinstance(efficiency, (int, float)) else None
        ),
        historical_time_status=history,
        accepted=int(_get(outcomes, "accepted") or 0),
        duplicate=int(_get(outcomes, "duplicate") or 0),
        rejected=int(_get(outcomes, "rejected") or 0),
        wasted=int(_get(outcomes, "wasted_time") or 0),
        acceptance_rate=float(_get(outcomes, "acceptance_rate") or 0.0),
        wasted_rate=float(_get(outcomes, "wasted_rate") or 0.0),
        opportunity_class=opportunity_class,
        recommended_action=_recommended_action(opportunity_class,
                                               session_status),
        why_now=build_why_now(lead, economic, outcomes, sessions, evidence),
        why_valuable=[str(x) for x in _get(economic, "why_valuable") or []],
        blockers=[str(x) for x in blockers],
        evidence_summary=evidence_summary,
        rule_version=OPPORTUNITY_RULE_VERSION,
        research_only=True,
    )


def _confidence_rank(value: Any) -> int:
    return _CONFIDENCE_RANK.get(str(value or "").upper(), 0)


def _evidence_rank(value: Any) -> int:
    return _EVIDENCE_RANK.get(str(value or "").upper(), 0)


def rank_opportunities(
    items: Iterable[ResearchOpportunity],
) -> list[ResearchOpportunity]:
    """Deterministic ordering (no new numeric score).

    1. opportunity class rank, 2. money DESC, 3. confidence DESC,
    4. evidence quality DESC, 5. effort ASC, 6. CVE ASC, 7. program ASC,
    8. lead_id ASC.
    """

    return sorted(
        items or (),
        key=lambda item: (
            CLASS_ORDER.get(item.opportunity_class, len(CLASS_ORDER)),
            -int(item.money_score),
            -_confidence_rank(item.confidence),
            -_evidence_rank(item.evidence_quality),
            int(item.effort_score),
            item.cve_id,
            item.program,
            item.lead_id,
        ),
    )


def build_opportunity_summary(
    items: Iterable[ResearchOpportunity],
) -> dict:
    """Compact deterministic class counts + top items."""

    items = list(items or ())
    by_class = {name: 0 for name in CLASS_ORDER}
    for item in items:
        by_class[item.opportunity_class] = by_class.get(
            item.opportunity_class, 0) + 1
    return {
        "total": len(items),
        "by_class": dict(sorted(by_class.items())),
        "top": [item.model_dump(mode="json") for item in items[:3]],
        "rule_version": OPPORTUNITY_RULE_VERSION,
        "research_only": True,
    }
