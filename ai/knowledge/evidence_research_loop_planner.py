"""Stage R31.17 deterministic evidence research loop planner (pure engine).

Consumes one read-only R31.16 Evidence Decision Plan (backed by the read-only
R31.13 Evidence Acquisition Plan, R31.14 Evidence Prioritization Plan and
R31.15 Evidence Confidence Plan) and projects the next research lifecycle
state for one Asset<->CVE research candidate:

    "What is the current research lifecycle state, should the loop continue,
     what is the next allowed planning phase, and why is this transition
     valid?"

This is a **lifecycle planning signal only**. It never executes research,
never acquires evidence, never contacts a target, never scans, never runs
Nuclei, never crawls, never fuzzes, never exploits, never calls an LLM, never
touches Mongo and never renders a probability, exploitability, severity, CVSS
or payout judgement. It defines the loop state, not an action.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Consume-only: the upstream plans are read verbatim. The planner never
  recomputes acquisition, priority, confidence or decision, never recomputes
  R31.12 gaps and never inspects CVE data, the Money Score or the R29 hunt
  queue.
- Additive and read-only: inputs are never mutated; the result is a new dict
  with rule version ``r31-17``.
- Deterministic: closed lifecycle/phase/reason vocabularies, a documented
  decision→transition table and byte-identical repeated output. No
  randomness, no timestamps, no hashes and no external state.
- Conservative: only a valid R31.16 decision advances the lifecycle; a
  missing, unrecognized or ``UNKNOWN`` decision yields the terminal
  ``UNKNOWN`` / ``UNKNOWN`` / ``INVALID_INPUT`` state and is never silently
  upgraded.
- Privacy: only closed codes and bounded, sanitized snapshots of the four
  source plans are retained; raw URLs, credentials, tokens, headers, query
  values and arbitrary source text are never copied.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_LEVELS,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.evidence_decision import (
    DECISION_ACCEPT_EVIDENCE,
    DECISION_CONTINUE_RESEARCH,
    DECISION_DEFER_RESEARCH,
    DECISION_REQUIRE_MORE_EVIDENCE,
    DECISION_UNKNOWN,
    DECISIONS,
)
from ai.schemas.evidence_research_loop import (
    EVIDENCE_RESEARCH_LOOP_RULE_VERSION,
    LIFECYCLE_COMPLETED,
    LIFECYCLE_DEFERRED,
    LIFECYCLE_RESEARCH_ACTIVE,
    LIFECYCLE_UNKNOWN,
    LIFECYCLE_WAITING_FOR_EVIDENCE,
    MAX_ITEMS,
    PHASE_EVIDENCE_COLLECTION_PLANNING,
    PHASE_NONE,
    PHASE_UNKNOWN,
    REASON_CONTINUE_AFTER_MEDIUM_CONFIDENCE,
    REASON_EVIDENCE_ACCEPTED,
    REASON_INVALID_INPUT,
    REASON_NEED_MORE_EVIDENCE,
    REASON_RESEARCH_DEFERRED,
    EvidenceResearchLoopPlan,
    research_loop_plan_projection,
)

EVIDENCE_RESEARCH_LOOP_PLANNER_RULE_VERSION = "r31-17"
RULE_VERSION = EVIDENCE_RESEARCH_LOOP_PLANNER_RULE_VERSION

# ---------------------------------------------------------------------------
# Deterministic R31.16 decision -> lifecycle transition table
# ---------------------------------------------------------------------------
# decision -> (lifecycle_state, next_phase, transition_reason)
DECISION_TRANSITIONS: dict[str, tuple] = {
    DECISION_ACCEPT_EVIDENCE: (
        LIFECYCLE_COMPLETED,
        PHASE_NONE,
        REASON_EVIDENCE_ACCEPTED,
    ),
    DECISION_CONTINUE_RESEARCH: (
        LIFECYCLE_RESEARCH_ACTIVE,
        PHASE_EVIDENCE_COLLECTION_PLANNING,
        REASON_CONTINUE_AFTER_MEDIUM_CONFIDENCE,
    ),
    DECISION_REQUIRE_MORE_EVIDENCE: (
        LIFECYCLE_WAITING_FOR_EVIDENCE,
        PHASE_EVIDENCE_COLLECTION_PLANNING,
        REASON_NEED_MORE_EVIDENCE,
    ),
    DECISION_DEFER_RESEARCH: (
        LIFECYCLE_DEFERRED,
        PHASE_NONE,
        REASON_RESEARCH_DEFERRED,
    ),
}

# Closed decision → lifecycle state mapping (safe for direct assertion).
DECISION_LIFECYCLE_STATES: dict[str, str] = {
    decision: row[0] for decision, row in DECISION_TRANSITIONS.items()
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


def _level(*blocks: dict) -> str:
    """First valid R31.16/R31.15 confidence level wins, else UNKNOWN."""

    for block in blocks:
        value = _upper(block.get("confidence_level"))
        if value in CONFIDENCE_LEVELS:
            return value
    return CONFIDENCE_UNKNOWN


def _blockers(*groups: object) -> list[str]:
    out: list[str] = []
    for group in groups:
        for item in group or ():
            code = _upper(item)
            if code in CONFIDENCE_BLOCKERS and code not in out:
                out.append(code)
    return out


def _result(
    *,
    acquisition: dict,
    prioritization: dict,
    confidence: dict,
    decision_plan: dict,
    lifecycle: str,
    phase: str,
    reason: str,
    decision: str,
    level: str,
    blockers: list[str],
) -> dict:
    plan = EvidenceResearchLoopPlan(
        rule_version=EVIDENCE_RESEARCH_LOOP_RULE_VERSION,
        lifecycle_state=lifecycle,
        next_phase=phase,
        transition_reason=reason,
        decision=decision,
        confidence_level=level,
        blockers=blockers,
        source_decision_plan=decision_plan,
        source_confidence_plan=confidence,
        source_priority_plan=prioritization,
        source_acquisition_plan=acquisition,
        research_only=True,
    )
    return research_loop_plan_projection(plan)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def plan_evidence_research_loop(
    acquisition_plan: object = None,
    prioritization_plan: object = None,
    confidence_plan: object = None,
    decision_plan: object = None,
) -> dict:
    """Map one R31.16 decision to the next research lifecycle state.

    All four inputs are consumed read-only. A missing, unrecognized or
    ``UNKNOWN`` R31.16 decision yields ``UNKNOWN`` / ``UNKNOWN`` /
    ``INVALID_INPUT``; no state is ever inferred from the upstream plans
    directly.
    """

    acquisition = _block(acquisition_plan)
    prioritization = _block(prioritization_plan)
    confidence = _block(confidence_plan)
    decision_block = _block(decision_plan)

    decision = _upper(decision_block.get("decision"))
    level = _level(decision_block, confidence)
    blockers = _blockers(
        decision_block.get("blockers"), confidence.get("blockers")
    )

    row = DECISION_TRANSITIONS.get(decision)
    if row is None:
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision_plan=decision_block,
            lifecycle=LIFECYCLE_UNKNOWN,
            phase=PHASE_UNKNOWN,
            reason=REASON_INVALID_INPUT,
            decision=(
                decision if decision in DECISIONS else DECISION_UNKNOWN
            ),
            level=level,
            blockers=blockers,
        )

    return _result(
        acquisition=acquisition,
        prioritization=prioritization,
        confidence=confidence,
        decision_plan=decision_block,
        lifecycle=row[0],
        phase=row[1],
        reason=row[2],
        decision=decision,
        level=level,
        blockers=blockers,
    )


__all__ = [
    "EVIDENCE_RESEARCH_LOOP_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "DECISION_TRANSITIONS",
    "DECISION_LIFECYCLE_STATES",
    "MAX_ITEMS",
    "plan_evidence_research_loop",
]
