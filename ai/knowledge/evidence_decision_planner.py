"""Stage R31.16 deterministic evidence decision planner (pure engine).

Consumes one read-only R31.13 Evidence Acquisition Plan, one read-only R31.14
Evidence Prioritization Plan and one read-only R31.15 Evidence Confidence Plan
and projects a final research decision for one Asset<->CVE research candidate:

    "Is the current evidence sufficient, should research continue, is more
     evidence planning required, or should this candidate be deferred?"

This is a **decision signal only**. It never acquires evidence, never
contacts a target, never scans, never runs Nuclei, never crawls, never fuzzes,
never exploits, never calls an LLM, never touches Mongo and never renders a
probability, exploitability, severity, CVSS or payout judgement. It decides
the next research state, not an action.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Consume-only: the three upstream plans are read verbatim. The planner never
  recalculates R31.15 confidence, R31.14 priority or R31.13 acquisition, never
  recomputes R31.12 gaps and never inspects CVE data, the Money Score or the
  R29 hunt queue.
- Additive and read-only: inputs are never mutated; the result is a new dict
  with rule version ``r31-16``.
- Deterministic: closed decision/reason/state/vocabulary rules, documented
  precedence and byte-identical repeated output. No randomness, no
  timestamps, no hashes and no external state.
- Conservative: ``ACCEPT_EVIDENCE`` requires the R31.15 ``HIGH`` level *and*
  the ``SUFFICIENT_EVIDENCE`` category; terminal ``NONE`` acquisition goes to
  ``DEFER_RESEARCH`` before any confidence interpretation; malformed or
  missing inputs yield ``UNKNOWN`` and are never silently upgraded.
- Privacy: only closed codes and bounded, sanitized snapshots of the three
  source plans are retained; raw URLs, credentials, tokens, headers, query
  values and arbitrary source text are never copied.
"""

from __future__ import annotations

from ai.knowledge.evidence_acquisition_planner import (
    ACQUISITION_METHODS,
    MANUAL_RESEARCH,
    NO_ACQUISITION,
)
from ai.knowledge.evidence_prioritization_planner import METHOD_PRIORITY
from ai.schemas.evidence_confidence import (
    BLOCKER_MALFORMED_ACQUISITION_PLAN,
    BLOCKER_MISSING_PRIORITIZATION_ITEM,
    BLOCKER_NO_ACQUISITION_PLANNED,
    BLOCKER_UNKNOWN_ACQUISITION_METHOD,
    CATEGORY_BEHAVIOR_LIMITED,
    CATEGORY_IDENTITY_LIMITED,
    CATEGORY_PARAMETER_LIMITED,
    CATEGORY_PATH_LIMITED,
    CATEGORY_RESEARCH_INCOMPLETE,
    CATEGORY_SCOPE_LIMITED,
    CATEGORY_SUFFICIENT_EVIDENCE,
    CATEGORY_TECHNOLOGY_LIMITED,
    CATEGORY_VERSION_LIMITED,
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_HIGH,
    CONFIDENCE_LEVELS,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
    LIMITING_FACTORS,
    LIMITING_NONE,
    LIMITING_UPSTREAM_PLAN,
)
from ai.schemas.evidence_decision import (
    DECISION_ACCEPT_EVIDENCE,
    DECISION_CONTINUE_RESEARCH,
    DECISION_DEFER_RESEARCH,
    DECISION_REQUIRE_MORE_EVIDENCE,
    DECISION_UNKNOWN,
    EVIDENCE_DECISION_RULE_VERSION,
    MAX_ITEMS,
    NEXT_STATE_ACTIVE_RESEARCH,
    NEXT_STATE_COMPLETE,
    NEXT_STATE_DEFERRED,
    NEXT_STATE_UNKNOWN,
    NEXT_STATE_WAITING_FOR_EVIDENCE,
    REASON_EVIDENCE_SUFFICIENT,
    REASON_HUMAN_RESEARCH_REQUIRED,
    REASON_MISSING_HTTP_BEHAVIOR,
    REASON_MISSING_IDENTITY,
    REASON_MISSING_PARAMETER,
    REASON_MISSING_PATH,
    REASON_MISSING_SCOPE,
    REASON_MISSING_TECHNOLOGY,
    REASON_MISSING_VERSION,
    REASON_NO_PLAN_AVAILABLE,
    EvidenceDecisionPlan,
    decision_plan_projection,
)

EVIDENCE_DECISION_PLANNER_RULE_VERSION = "r31-16"
RULE_VERSION = EVIDENCE_DECISION_PLANNER_RULE_VERSION

# ---------------------------------------------------------------------------
# Deterministic R31.15 category -> decision reason mapping
# ---------------------------------------------------------------------------
# RESEARCH_INCOMPLETE is contextual: MANUAL_RESEARCH requires human research,
# every other RESEARCH_INCOMPLETE state has no narrower plan available.
_CATEGORY_REASON: dict[str, str] = {
    CATEGORY_SUFFICIENT_EVIDENCE: REASON_EVIDENCE_SUFFICIENT,
    CATEGORY_IDENTITY_LIMITED: REASON_MISSING_IDENTITY,
    CATEGORY_VERSION_LIMITED: REASON_MISSING_VERSION,
    CATEGORY_SCOPE_LIMITED: REASON_MISSING_SCOPE,
    CATEGORY_PATH_LIMITED: REASON_MISSING_PATH,
    CATEGORY_PARAMETER_LIMITED: REASON_MISSING_PARAMETER,
    CATEGORY_BEHAVIOR_LIMITED: REASON_MISSING_HTTP_BEHAVIOR,
    CATEGORY_TECHNOLOGY_LIMITED: REASON_MISSING_TECHNOLOGY,
}

# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _items(plan: dict) -> list[dict]:
    raw = plan.get("items")
    if not isinstance(raw, (list, tuple)):
        return []
    return [
        item for item in list(raw)[:MAX_ITEMS] if isinstance(item, dict)
    ]


def _level(value: str) -> str:
    return value if value in CONFIDENCE_LEVELS else CONFIDENCE_UNKNOWN


def _limiting(value: str) -> str:
    return value if value in LIMITING_FACTORS else LIMITING_UPSTREAM_PLAN


def _blockers(*groups: object) -> list[str]:
    out: list[str] = []
    for group in groups:
        for item in group or ():
            code = _upper(item)
            if code in CONFIDENCE_BLOCKERS and code not in out:
                out.append(code)
    return out


def _reason_for(category: str, method: str) -> str:
    if category == CATEGORY_RESEARCH_INCOMPLETE:
        return (
            REASON_HUMAN_RESEARCH_REQUIRED
            if method == MANUAL_RESEARCH
            else REASON_NO_PLAN_AVAILABLE
        )
    return _CATEGORY_REASON.get(category, REASON_NO_PLAN_AVAILABLE)


def _result(
    *,
    acquisition: dict,
    prioritization: dict,
    confidence: dict,
    decision: str,
    reason: str,
    level: str,
    next_state: str,
    required_evidence: str,
    blockers: list[str],
) -> dict:
    plan = EvidenceDecisionPlan(
        rule_version=EVIDENCE_DECISION_RULE_VERSION,
        decision=decision,
        decision_reason=reason,
        confidence_level=level,
        next_state=next_state,
        required_evidence=required_evidence,
        blockers=blockers,
        source_confidence_plan=confidence,
        source_priority_plan=prioritization,
        source_acquisition_plan=acquisition,
        research_only=True,
    )
    return decision_plan_projection(plan)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def plan_evidence_decision(
    acquisition_plan: object = None,
    prioritization_plan: object = None,
    confidence_plan: object = None,
) -> dict:
    """Decide the next research state for one candidate (read-only).

    The R31.13 acquisition method (terminal ``NONE`` first), then the R31.15
    confidence level/category, then the presence of an R31.14 prioritized
    evidence item drive the deterministic decision. Malformed or missing
    inputs yield ``UNKNOWN`` / ``NO_PLAN_AVAILABLE``; nothing is recomputed.
    """

    acquisition = _block(acquisition_plan)
    prioritization = _block(prioritization_plan)
    confidence = _block(confidence_plan)

    method = _upper(acquisition.get("acquisition_method"))
    target = _upper(acquisition.get("evidence_target"))
    level = _upper(confidence.get("confidence_level"))
    category = _upper(confidence.get("confidence_category"))
    limiting = _limiting(_upper(confidence.get("limiting_factor")))
    upstream_blockers = confidence.get("blockers")
    items = _items(prioritization)
    category_valid = (
        category in _CATEGORY_REASON
        or category == CATEGORY_RESEARCH_INCOMPLETE
    )

    # Malformed acquisition plan: no method at all.
    if not method:
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=DECISION_UNKNOWN,
            reason=REASON_NO_PLAN_AVAILABLE,
            level=_level(level),
            next_state=NEXT_STATE_UNKNOWN,
            required_evidence=LIMITING_UPSTREAM_PLAN,
            blockers=_blockers(
                upstream_blockers, [BLOCKER_MALFORMED_ACQUISITION_PLAN]
            ),
        )

    # Unknown acquisition method.
    if method not in ACQUISITION_METHODS:
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=DECISION_UNKNOWN,
            reason=REASON_NO_PLAN_AVAILABLE,
            level=_level(level),
            next_state=NEXT_STATE_UNKNOWN,
            required_evidence=LIMITING_UPSTREAM_PLAN,
            blockers=_blockers(
                upstream_blockers, [BLOCKER_UNKNOWN_ACQUISITION_METHOD]
            ),
        )

    # Method/target pairing (authority: R31.14 table, which mirrors R31.13).
    expected = METHOD_PRIORITY.get(method)
    if method != NO_ACQUISITION and (
        expected is None or target != expected[0]
    ):
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=DECISION_UNKNOWN,
            reason=REASON_NO_PLAN_AVAILABLE,
            level=_level(level),
            next_state=NEXT_STATE_UNKNOWN,
            required_evidence=LIMITING_UPSTREAM_PLAN,
            blockers=_blockers(
                upstream_blockers, [BLOCKER_MALFORMED_ACQUISITION_PLAN]
            ),
        )

    # Rule 4: terminal acquisition defers before any confidence reading.
    if method == NO_ACQUISITION:
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=DECISION_DEFER_RESEARCH,
            reason=REASON_NO_PLAN_AVAILABLE,
            level=_level(level),
            next_state=NEXT_STATE_DEFERRED,
            required_evidence=LIMITING_UPSTREAM_PLAN,
            blockers=_blockers(
                upstream_blockers, [BLOCKER_NO_ACQUISITION_PLANNED]
            ),
        )

    # Missing/malformed confidence plan: no trustable confidence reading.
    if level not in CONFIDENCE_LEVELS or not category_valid:
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=DECISION_UNKNOWN,
            reason=REASON_NO_PLAN_AVAILABLE,
            level=_level(level),
            next_state=NEXT_STATE_UNKNOWN,
            required_evidence=LIMITING_UPSTREAM_PLAN,
            blockers=_blockers(upstream_blockers),
        )

    # Rule 1: accept only HIGH + SUFFICIENT_EVIDENCE.
    if level == CONFIDENCE_HIGH:
        if category == CATEGORY_SUFFICIENT_EVIDENCE:
            return _result(
                acquisition=acquisition,
                prioritization=prioritization,
                confidence=confidence,
                decision=DECISION_ACCEPT_EVIDENCE,
                reason=REASON_EVIDENCE_SUFFICIENT,
                level=CONFIDENCE_HIGH,
                next_state=NEXT_STATE_COMPLETE,
                required_evidence=LIMITING_NONE,
                blockers=_blockers(upstream_blockers),
            )
        # Internally inconsistent upstream confidence: never accepted.
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=DECISION_UNKNOWN,
            reason=REASON_NO_PLAN_AVAILABLE,
            level=CONFIDENCE_HIGH,
            next_state=NEXT_STATE_UNKNOWN,
            required_evidence=LIMITING_UPSTREAM_PLAN,
            blockers=_blockers(upstream_blockers),
        )

    # Rule 2: MEDIUM confidence with a prioritized evidence path continues.
    if level == CONFIDENCE_MEDIUM:
        if items:
            return _result(
                acquisition=acquisition,
                prioritization=prioritization,
                confidence=confidence,
                decision=DECISION_CONTINUE_RESEARCH,
                reason=_reason_for(category, method),
                level=CONFIDENCE_MEDIUM,
                next_state=NEXT_STATE_ACTIVE_RESEARCH,
                required_evidence=limiting,
                blockers=_blockers(upstream_blockers),
            )
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=DECISION_UNKNOWN,
            reason=REASON_NO_PLAN_AVAILABLE,
            level=CONFIDENCE_MEDIUM,
            next_state=NEXT_STATE_UNKNOWN,
            required_evidence=LIMITING_UPSTREAM_PLAN,
            blockers=_blockers(
                upstream_blockers, [BLOCKER_MISSING_PRIORITIZATION_ITEM]
            ),
        )

    # Rule 3: LOW confidence with a prioritized evidence path waits for it.
    if level == CONFIDENCE_LOW:
        if items:
            return _result(
                acquisition=acquisition,
                prioritization=prioritization,
                confidence=confidence,
                decision=DECISION_REQUIRE_MORE_EVIDENCE,
                reason=_reason_for(category, method),
                level=CONFIDENCE_LOW,
                next_state=NEXT_STATE_WAITING_FOR_EVIDENCE,
                required_evidence=limiting,
                blockers=_blockers(upstream_blockers),
            )
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=DECISION_UNKNOWN,
            reason=REASON_NO_PLAN_AVAILABLE,
            level=CONFIDENCE_LOW,
            next_state=NEXT_STATE_UNKNOWN,
            required_evidence=LIMITING_UPSTREAM_PLAN,
            blockers=_blockers(
                upstream_blockers, [BLOCKER_MISSING_PRIORITIZATION_ITEM]
            ),
        )

    # Rule 5: UNKNOWN confidence (or any unrecognized state).
    return _result(
        acquisition=acquisition,
        prioritization=prioritization,
        confidence=confidence,
        decision=DECISION_UNKNOWN,
        reason=REASON_NO_PLAN_AVAILABLE,
        level=CONFIDENCE_UNKNOWN,
        next_state=NEXT_STATE_UNKNOWN,
        required_evidence=LIMITING_UPSTREAM_PLAN,
        blockers=_blockers(upstream_blockers),
    )


__all__ = [
    "EVIDENCE_DECISION_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "MAX_ITEMS",
    "plan_evidence_decision",
]
