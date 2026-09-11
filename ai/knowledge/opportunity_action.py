"""Stage R26.2 deterministic Opportunity Action Queue (pure engine).

Composes the existing R26.1 :class:`ResearchOpportunity` view with the already-
persisted R25.7 (sessions) and R25.5 (outcomes) signals into a researcher-
oriented Action Queue that answers *"What should I work on first, and what
exactly is blocking the other items?"*

This is a presentation/decision layer; it does not modify the Money Score,
does not introduce a new numeric score, does not start research, and does
not write anywhere. No I/O, no network, no LLM, no Mongo, no subprocess,
no execution.

Pure functions of their inputs: no clock, no randomness.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ai.schemas.opportunity_action import (
    ACTION_CODES,
    ACTION_RULE_VERSION,
    ACTION_STATUSES,
    ACTION_STATUS_ORDER,
    OpportunityAction,
    action_id_for,
)
from ai.schemas.research_opportunity import (
    OPPORTUNITY_RULE_VERSION,
    opportunity_id_for,
)

# Opportunity class rank used for tie-breaks after status (best -> worst).
# Mirrors the R26.1 class ordering; documented here so the action layer is
# independent of opportunity.py's internal CLASS_ORDER.
_CLASS_ORDER: dict[str, int] = {
    "HIGH_VALUE": 0,
    "GOOD_OPPORTUNITY": 1,
    "RESEARCH_FIRST": 2,
    "LOW_CONFIDENCE": 3,
    "BLOCKED": 4,
    "DEFER": 5,
}

_CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
_EVIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

# Closed machine-readable blocker codes emitted by R26 / R25.2. New codes are
# NEVER invented here; an unknown code is preserved verbatim and surfaces as
# a generic "investigate the unknown blocker" next step. The translator
# converts ONLY existing structured blockers into researcher text.
_TRANSLATIONS: dict[str, str] = {
    "only generic technology match": (
        "Verify the CVE applies to this specific asset rather than "
        "generic technology."
    ),
    "affected plugin not observed": (
        "Confirm the affected component/plugin is present in the asset."
    ),
    "asset component not observed": (
        "Confirm the vulnerable component is present."
    ),
    "asset version unknown": (
        "Determine the affected version before investing research time."
    ),
    "no positive asset match signal": (
        "Confirm the asset matches the affected product or component."
    ),
    "missing historical data": (
        "Capture an initial research attempt to build historical data."
    ),
    "insufficient evidence": (
        "Collect authoritative public evidence for the CVE."
    ),
}

# Exact one-step vocabulary per action code. No exploit commands, no URLs,
# no security-testing commands.
_NEXT_STEP: dict[str, str] = {
    "VERIFY_ASSET_MATCH": "Confirm affected component/plugin presence.",
    "GATHER_EVIDENCE": "Collect authoritative public evidence for the CVE.",
    "START_RESEARCH": "Begin a time-boxed research session.",
    "CONTINUE_RESEARCH": "Continue the active research session.",
    "REVIEW_OUTCOME": "Review the previous research outcome before spending "
                       "more time.",
    "DEFER": "No high-value action is currently justified.",
}


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


def has_active_session(sessions: Any) -> bool:
    """True iff the R25.7 session summary indicates an active session.

    Accepts both vocabulary variants used across stages:
      - R25.7 explicit states: PLANNED / IN_PROGRESS
      - R26.1 fold status: ACTIVE
    """

    status = str(_get(sessions, "session_status") or "NONE").upper()
    if status in ("PLANNED", "IN_PROGRESS", "ACTIVE"):
        return True
    if _coerce_int(_get(sessions, "in_progress_sessions")) > 0:
        return True
    if _coerce_int(_get(sessions, "planned_sessions")) > 0:
        return True
    return False


def has_terminal_outcome(outcomes: Any) -> bool:
    """True iff the R25.5 outcomes summary indicates a terminal outcome."""

    if str(_get(outcomes, "outcome_status") or "NONE").upper() not in (
        "NONE", "", "IN_PROGRESS",
    ):
        return True
    accepted = _coerce_int(_get(outcomes, "accepted"))
    duplicate = _coerce_int(_get(outcomes, "duplicate"))
    rejected = _coerce_int(_get(outcomes, "rejected"))
    not_applicable = _coerce_int(_get(outcomes, "not_applicable"))
    wasted = _coerce_int(_get(outcomes, "wasted_time"))
    terminal_attempts = _coerce_int(_get(outcomes, "terminal_attempts"))
    if terminal_attempts > 0:
        return True
    return (accepted + duplicate + rejected + not_applicable + wasted) > 0


def classify_action(
    opportunity_class: str,
    sessions: Any,
    outcomes: Any,
    confidence: str,
) -> str:
    """Deterministic recommended-action precedence (documented).

    First match wins:

    1. active R25.7 session exists        -> CONTINUE_RESEARCH
    2. R26 opportunity_class == BLOCKED   -> VERIFY_ASSET_MATCH
    3. terminal outcomes, no active       -> REVIEW_OUTCOME
    4. confidence == LOW                  -> GATHER_EVIDENCE
    5. HIGH_VALUE / GOOD_OPPORTUNITY      -> START_RESEARCH
    6. RESEARCH_FIRST                     -> START_RESEARCH
    7. otherwise                          -> DEFER
    """

    if has_active_session(sessions):
        return "CONTINUE_RESEARCH"
    opp_class = str(opportunity_class or "").strip().upper()
    if opp_class == "BLOCKED":
        return "VERIFY_ASSET_MATCH"
    if has_terminal_outcome(outcomes) and not has_active_session(sessions):
        return "REVIEW_OUTCOME"
    if opp_class == "LOW_CONFIDENCE":
        return "GATHER_EVIDENCE"
    if opp_class in ("HIGH_VALUE", "GOOD_OPPORTUNITY"):
        return "START_RESEARCH"
    if opp_class == "RESEARCH_FIRST":
        return "START_RESEARCH"
    return "DEFER"


def translate_blockers(
    blockers: Iterable[str],
) -> list[dict[str, str]]:
    """Translate structured blocker codes into researcher-readable notes.

    Returns a list of dicts with the original machine code AND a human
    explanation; the machine code is NEVER dropped and a code with no
    mapping is preserved verbatim with a conservative "investigate the
    unknown blocker" explanation (NEVER invented vocabulary).
    """

    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in blockers or ():
        code = str(raw or "").strip()
        if not code or code in seen:
            continue
        seen.add(code)
        text = _TRANSLATIONS.get(code, "Investigate the unknown blocker code.")
        out.append({"code": code, "text": text})
    return out


def build_next_step(recommended_action: str) -> str:
    """Exactly one primary next step for the recommended action.

    Falls back to the DEFER step for unknown / unmapped actions.
    """

    action = str(recommended_action or "").strip().upper()
    if action in _NEXT_STEP:
        return _NEXT_STEP[action]
    return _NEXT_STEP["DEFER"]


def classify_status(
    opportunity_class: str,
    sessions: Any,
    outcomes: Any,
    recommended_action: str,
) -> str:
    """Derive the closed ``current_status`` from R21/R25/R26 signals.

    Documented precedence (first match wins):

    1. IN_PROGRESS — active R25.7 session OR CONTINUE_RESEARCH recommended
    2. COMPLETED   — terminal outcome AND no active session (post-research)
    3. BLOCKED     — opportunity_class == BLOCKED OR VERIFY_ASSET_MATCH
    4. DEFERRED    — recommended_action == DEFER
    5. READY       — otherwise (GATHER_EVIDENCE / START_RESEARCH / REVIEW_OUTCOME)

    This is a derived view: no new persistence lifecycle is created.
    """

    opp_class = str(opportunity_class or "").strip().upper()
    action = str(recommended_action or "").strip().upper()
    if has_active_session(sessions) or action == "CONTINUE_RESEARCH":
        return "IN_PROGRESS"
    if (
        opp_class == "COMPLETED"
        or has_terminal_outcome(outcomes)
        and not has_active_session(sessions)
        and action == "REVIEW_OUTCOME"
    ):
        return "COMPLETED"
    if opp_class == "BLOCKED" or action == "VERIFY_ASSET_MATCH":
        return "BLOCKED"
    if action == "DEFER":
        return "DEFERRED"
    return "READY"


def build_action_reason(
    opportunity_class: str,
    sessions: Any,
    outcomes: Any,
    confidence: str,
    recommended_action: str,
) -> str:
    """One-line deterministic reason for the chosen action.

    Single short sentence; never fabricated vulnerability claims; references
    the existing structured signals only.
    """

    opp_class = str(opportunity_class or "").strip().upper()
    action = str(recommended_action or "").strip().upper()
    conf = str(confidence or "LOW").strip().upper()
    if action == "CONTINUE_RESEARCH":
        status = str(_get(sessions, "session_status") or "NONE").upper()
        return (
            f"Active R25.7 session ({status}); continue before starting new work."
        )
    if action == "VERIFY_ASSET_MATCH":
        return (
            "Asset relationship to the vulnerability is unproven; confirm the "
            "plugin/component is present before investing research time."
        )
    if action == "REVIEW_OUTCOME":
        return (
            "Terminal research outcome already recorded; review it before "
            "starting a new attempt."
        )
    if action == "GATHER_EVIDENCE":
        return (
            f"Opportunity class is {opp_class}; collect authoritative "
            "evidence before research."
        )
    if action == "START_RESEARCH":
        if opp_class in ("HIGH_VALUE", "GOOD_OPPORTUNITY"):
            return (
                f"Opportunity class is {opp_class}; time-boxed research is "
                "warranted."
            )
        return (
            "Opportunity class is RESEARCH_FIRST; a structured session is "
            "warranted."
        )
    return (
        "No high-value research action is currently justified for this lead."
    )


def build_action(
    opportunity: Any,
    sessions: Any,
    outcomes: Any,
) -> OpportunityAction:
    """Compose one read-only OpportunityAction view (no writes)."""

    lead_id = str(_get(opportunity, "lead_id") or "")
    opp_id = str(
        _get(opportunity, "opportunity_id") or opportunity_id_for(lead_id)
    )
    opp_class = str(_get(opportunity, "opportunity_class") or "DEFER").upper()
    confidence = str(_get(opportunity, "confidence") or "LOW").upper()
    recommended_action = classify_action(
        opp_class, sessions, outcomes, confidence
    )
    status = classify_status(
        opp_class, sessions, outcomes, recommended_action
    )
    blockers_raw = list(_get(opportunity, "blockers") or [])
    blocker_entries = translate_blockers(blockers_raw)
    next_step = build_next_step(recommended_action)
    reason = build_action_reason(
        opp_class, sessions, outcomes, confidence, recommended_action
    )

    why_now = list(_get(opportunity, "why_now") or [])

    return OpportunityAction(
        action_id=action_id_for(lead_id),
        opportunity_id=opp_id,
        lead_id=lead_id,
        cve_id=str(_get(opportunity, "cve_id") or ""),
        program=str(_get(opportunity, "program") or ""),
        opportunity_class=opp_class,
        money_score=_coerce_int(_get(opportunity, "money_score")),
        priority=str(_get(opportunity, "money_priority") or ""),
        confidence=confidence,
        evidence_quality=str(
            _get(opportunity, "evidence_quality") or "NONE"
        ).upper(),
        effort_score=_coerce_int(_get(opportunity, "effort_score")),
        estimated_minutes=_coerce_int(
            _get(opportunity, "estimated_minutes")
        ),
        current_status=status,
        recommended_action=recommended_action,
        action_reason=reason,
        blockers=[entry["code"] for entry in blocker_entries],
        why_now=[str(x) for x in why_now],
        next_step=next_step,
        research_only=True,
        rule_version=ACTION_RULE_VERSION,
    )


def _confidence_rank(value: Any) -> int:
    return _CONFIDENCE_RANK.get(str(value or "").upper(), 0)


def _evidence_rank(value: Any) -> int:
    return _EVIDENCE_RANK.get(str(value or "").upper(), 0)


def rank_actions(
    items: Iterable[OpportunityAction],
) -> list[OpportunityAction]:
    """Deterministic ordering (no new numeric score).

    1. current_status (IN_PROGRESS, READY, BLOCKED, DEFERRED, COMPLETED)
    2. opportunity_class rank
    3. money_score DESC
    4. confidence DESC
    5. evidence_quality DESC
    6. estimated_minutes ASC
    7. CVE ASC
    8. program ASC
    9. lead_id ASC
    """

    return sorted(
        items or (),
        key=lambda item: (
            ACTION_STATUS_ORDER.get(
                item.current_status, len(ACTION_STATUS_ORDER)
            ),
            _CLASS_ORDER.get(
                item.opportunity_class, len(_CLASS_ORDER)
            ),
            -int(item.money_score),
            -_confidence_rank(item.confidence),
            -_evidence_rank(item.evidence_quality),
            int(item.estimated_minutes),
            item.cve_id,
            item.program,
            item.lead_id,
        ),
    )


def build_action_summary(
    items: Iterable[OpportunityAction],
) -> dict:
    """Compact deterministic summary (counts + top action).

    No generated clock / date dependency. The "top" item is the highest-
    ranked entry (status, class, money, confidence, ...); every other field
    is a deterministic aggregate.
    """

    items = list(items or ())
    counts = {name: 0 for name in ACTION_STATUSES}
    action_counts = {code: 0 for code in ACTION_CODES}
    for item in items:
        counts[item.current_status] = counts.get(item.current_status, 0) + 1
        action_counts[item.recommended_action] = (
            action_counts.get(item.recommended_action, 0) + 1
        )
    ranked = rank_actions(items)
    top = ranked[0] if ranked else None
    return {
        "total": len(items),
        "ready": counts.get("READY", 0),
        "blocked": counts.get("BLOCKED", 0),
        "in_progress": counts.get("IN_PROGRESS", 0),
        "deferred": counts.get("DEFERRED", 0),
        "completed": counts.get("COMPLETED", 0),
        "by_action": dict(sorted(action_counts.items())),
        "top_action": (
            top.recommended_action if top is not None else "DEFER"
        ),
        "top_lead": top.lead_id if top is not None else "",
        "top_program": top.program if top is not None else "",
        "top_reason": top.action_reason if top is not None else "",
        "top_cve": top.cve_id if top is not None else "",
        "top_money": top.money_score if top is not None else 0,
        "rule_version": ACTION_RULE_VERSION,
        "opportunity_rule_version": OPPORTUNITY_RULE_VERSION,
        "research_only": True,
    }