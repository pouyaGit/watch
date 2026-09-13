"""Stage R31.18 deterministic evidence research outcome tracker (pure engine).

Consumes one read-only R31.17 Evidence Research Loop Plan (backed by the
read-only R31.13 Evidence Acquisition Plan, R31.14 Evidence Prioritization
Plan, R31.15 Evidence Confidence Plan and R31.16 Evidence Decision Plan) and
projects the tracked research outcome for one Asset<->CVE research candidate:

    "What is the current research outcome, is the research cycle complete,
     is evidence still required, and is the candidate deferred?"

This is an **outcome tracking signal only**. It records state; it never
executes research, never acquires evidence, never contacts a target, never
scans, never runs Nuclei, never crawls, never fuzzes, never exploits, never
calls an LLM, never touches Mongo and never renders a probability,
exploitability, severity, CVSS or payout judgement.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Consume-only: the upstream plans are read verbatim. The tracker never
  recomputes acquisition, priority, confidence, decision or loop state and
  never inspects CVE data, the Money Score or the R29 hunt queue.
- Additive and read-only: inputs are never mutated; the result is a new dict
  with rule version ``r31-18``.
- Deterministic: a closed lifecycle→outcome table, a closed
  limiting-factor→remaining-need mapping and byte-identical repeated output.
  No randomness, no timestamps, no hashes and no external state.
- Conservative: only the four emitted R31.17 lifecycle states advance an
  outcome; a missing or unexpected lifecycle state yields ``UNKNOWN`` /
  ``INVALID_STATE`` and is never silently upgraded.
- Privacy: only closed codes and bounded, sanitized snapshots of the five
  source plans are retained; raw URLs, credentials, tokens, headers, query
  values and arbitrary source text are never copied.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_BLOCKERS,
    LIMITING_COMPONENT_IDENTITY,
    LIMITING_HTTP_BEHAVIOR,
    LIMITING_HUMAN_RESEARCH,
    LIMITING_NONE,
    LIMITING_PARAMETER,
    LIMITING_PATH,
    LIMITING_SCOPE,
    LIMITING_TECHNOLOGY,
    LIMITING_UPSTREAM_PLAN,
    LIMITING_VERSION,
)
from ai.schemas.evidence_research_loop import (
    LIFECYCLE_COMPLETED,
    LIFECYCLE_DEFERRED,
    LIFECYCLE_RESEARCH_ACTIVE,
    LIFECYCLE_WAITING_FOR_EVIDENCE,
)
from ai.schemas.evidence_research_outcome import (
    CATEGORY_EVIDENCE_ACCEPTED,
    CATEGORY_INVALID_STATE,
    CATEGORY_MORE_EVIDENCE_REQUIRED,
    CATEGORY_RESEARCH_CONTINUING,
    CATEGORY_RESEARCH_PAUSED,
    COMPLETION_COMPLETE,
    COMPLETION_INCOMPLETE,
    COMPLETION_NONE,
    COMPLETION_PARTIAL,
    COMPLETION_UNKNOWN,
    EVIDENCE_RESEARCH_OUTCOME_RULE_VERSION,
    MAX_ITEMS,
    NEED_HTTP_BEHAVIOR,
    NEED_HUMAN_RESEARCH,
    NEED_IDENTITY,
    NEED_NONE,
    NEED_PARAMETER,
    NEED_PATH,
    NEED_SCOPE,
    NEED_TECHNOLOGY,
    NEED_UNKNOWN,
    NEED_VERSION,
    OUTCOME_COMPLETED,
    OUTCOME_DEFERRED,
    OUTCOME_IN_PROGRESS,
    OUTCOME_UNKNOWN,
    OUTCOME_WAITING_FOR_EVIDENCE,
    EvidenceResearchOutcomePlan,
    research_outcome_plan_projection,
)

EVIDENCE_RESEARCH_OUTCOME_TRACKER_RULE_VERSION = "r31-18"
RULE_VERSION = EVIDENCE_RESEARCH_OUTCOME_TRACKER_RULE_VERSION

# ---------------------------------------------------------------------------
# Deterministic R31.17 lifecycle -> outcome table
# ---------------------------------------------------------------------------
# lifecycle_state -> (outcome, outcome_category, completion_state)
LIFECYCLE_OUTCOMES: dict[str, tuple] = {
    LIFECYCLE_COMPLETED: (
        OUTCOME_COMPLETED,
        CATEGORY_EVIDENCE_ACCEPTED,
        COMPLETION_COMPLETE,
    ),
    LIFECYCLE_RESEARCH_ACTIVE: (
        OUTCOME_IN_PROGRESS,
        CATEGORY_RESEARCH_CONTINUING,
        COMPLETION_PARTIAL,
    ),
    LIFECYCLE_WAITING_FOR_EVIDENCE: (
        OUTCOME_WAITING_FOR_EVIDENCE,
        CATEGORY_MORE_EVIDENCE_REQUIRED,
        COMPLETION_INCOMPLETE,
    ),
    LIFECYCLE_DEFERRED: (
        OUTCOME_DEFERRED,
        CATEGORY_RESEARCH_PAUSED,
        COMPLETION_NONE,
    ),
}

# ---------------------------------------------------------------------------
# Deterministic R31.15 limiting factor -> remaining need table
# ---------------------------------------------------------------------------

LIMITING_TO_REMAINING_NEED: dict[str, str] = {
    LIMITING_NONE: NEED_NONE,
    LIMITING_COMPONENT_IDENTITY: NEED_IDENTITY,
    LIMITING_VERSION: NEED_VERSION,
    LIMITING_SCOPE: NEED_SCOPE,
    LIMITING_PATH: NEED_PATH,
    LIMITING_PARAMETER: NEED_PARAMETER,
    LIMITING_HTTP_BEHAVIOR: NEED_HTTP_BEHAVIOR,
    LIMITING_TECHNOLOGY: NEED_TECHNOLOGY,
    LIMITING_HUMAN_RESEARCH: NEED_HUMAN_RESEARCH,
    LIMITING_UPSTREAM_PLAN: NEED_UNKNOWN,
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
    decision: dict,
    loop: dict,
    outcome: str,
    category: str,
    completion: str,
    need: str,
    blockers: list[str],
) -> dict:
    plan = EvidenceResearchOutcomePlan(
        rule_version=EVIDENCE_RESEARCH_OUTCOME_RULE_VERSION,
        outcome=outcome,
        outcome_category=category,
        completion_state=completion,
        remaining_need=need,
        blockers=blockers,
        source_loop_plan=loop,
        source_decision_plan=decision,
        source_confidence_plan=confidence,
        source_priority_plan=prioritization,
        source_acquisition_plan=acquisition,
        research_only=True,
    )
    return research_outcome_plan_projection(plan)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def track_evidence_research_outcome(
    acquisition_plan: object = None,
    prioritization_plan: object = None,
    confidence_plan: object = None,
    decision_plan: object = None,
    loop_plan: object = None,
) -> dict:
    """Map one R31.17 lifecycle state to the tracked research outcome.

    All five inputs are consumed read-only. A missing or unexpected lifecycle
    state yields ``UNKNOWN`` / ``INVALID_STATE`` / ``UNKNOWN`` / ``UNKNOWN``;
    no outcome is ever inferred from the upstream plans directly.
    ``remaining_need`` is derived from the R31.15 limiting factor for every
    non-complete outcome and is ``NONE`` once the cycle is complete.
    """

    acquisition = _block(acquisition_plan)
    prioritization = _block(prioritization_plan)
    confidence = _block(confidence_plan)
    decision = _block(decision_plan)
    loop = _block(loop_plan)

    lifecycle = _upper(loop.get("lifecycle_state"))
    limiting = _upper(confidence.get("limiting_factor"))
    blockers = _blockers(
        loop.get("blockers"),
        decision.get("blockers"),
        confidence.get("blockers"),
    )

    row = LIFECYCLE_OUTCOMES.get(lifecycle)
    if row is None:
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=decision,
            loop=loop,
            outcome=OUTCOME_UNKNOWN,
            category=CATEGORY_INVALID_STATE,
            completion=COMPLETION_UNKNOWN,
            need=NEED_UNKNOWN,
            blockers=blockers,
        )

    outcome, category, completion = row
    need = (
        NEED_NONE
        if lifecycle == LIFECYCLE_COMPLETED
        else LIMITING_TO_REMAINING_NEED.get(limiting, NEED_UNKNOWN)
    )
    return _result(
        acquisition=acquisition,
        prioritization=prioritization,
        confidence=confidence,
        decision=decision,
        loop=loop,
        outcome=outcome,
        category=category,
        completion=completion,
        need=need,
        blockers=blockers,
    )


__all__ = [
    "EVIDENCE_RESEARCH_OUTCOME_TRACKER_RULE_VERSION",
    "RULE_VERSION",
    "LIFECYCLE_OUTCOMES",
    "LIMITING_TO_REMAINING_NEED",
    "MAX_ITEMS",
    "track_evidence_research_outcome",
]
