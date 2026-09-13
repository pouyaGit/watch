"""Stage R31.19 deterministic evidence feedback calibration planner (pure).

Consumes one read-only R31.18 Evidence Research Outcome Plan (backed by the
read-only R31.13-R31.17 plans) and projects a reusable feedback signal for one
Asset<->CVE research candidate:

    "What feedback signal does this outcome produce, which research dimension
     needs improvement, and what should future planning stages be aware of?"

This is a **feedback-analysis signal only**. It never executes research,
never acquires evidence, never contacts a target, never scans, never runs
Nuclei, never crawls, never fuzzes, never exploits, never calls an LLM, never
touches Mongo and never renders a probability, exploitability, severity, CVSS
or payout judgement. It analyzes outcome signals and never changes previous
planner behavior.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Consume-only: the upstream plans are read verbatim. The planner never
  recomputes acquisition, priority, confidence, decision, loop state or
  outcome and never inspects CVE data, the Money Score or the R29 hunt queue.
- Additive and read-only: inputs are never mutated; the result is a new dict
  with rule version ``r31-19``.
- Deterministic: a closed outcome→feedback table, a closed
  remaining-need→improvement mapping and byte-identical repeated output. No
  randomness, no timestamps, no hashes and no external state.
- Conservative: only the five closed R31.18 outcomes produce a feedback row;
  any missing or unrecognized outcome yields ``UNKNOWN`` / ``UNKNOWN`` /
  ``PROCESS`` and is never silently upgraded.
- Privacy: only closed codes and bounded, sanitized snapshots of the six
  source plans are retained; raw URLs, credentials, tokens, headers, query
  values and arbitrary source text are never copied.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_LEVELS,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.evidence_feedback_calibration import (
    AREA_HTTP_BEHAVIOR,
    AREA_HUMAN_RESEARCH,
    AREA_IDENTITY,
    AREA_NONE,
    AREA_PARAMETER,
    AREA_PATH,
    AREA_PROCESS,
    AREA_SCOPE,
    AREA_TECHNOLOGY,
    AREA_UNKNOWN,
    AREA_VERSION,
    EVIDENCE_FEEDBACK_CALIBRATION_RULE_VERSION,
    FEEDBACK_CONTINUE,
    FEEDBACK_DEFER,
    FEEDBACK_EVIDENCE_GAP,
    FEEDBACK_SUCCESS,
    FEEDBACK_UNKNOWN,
    MAX_ITEMS,
    STRENGTH_HIGH,
    STRENGTH_LOW,
    STRENGTH_MEDIUM,
    STRENGTH_UNKNOWN,
    EvidenceFeedbackCalibrationPlan,
    feedback_calibration_plan_projection,
)
from ai.schemas.evidence_research_outcome import (
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
    OUTCOMES,
)

EVIDENCE_FEEDBACK_CALIBRATION_PLANNER_RULE_VERSION = "r31-19"
RULE_VERSION = EVIDENCE_FEEDBACK_CALIBRATION_PLANNER_RULE_VERSION

# ---------------------------------------------------------------------------
# Deterministic R31.18 outcome -> feedback table
# ---------------------------------------------------------------------------
# outcome -> (feedback_type, signal_strength, fixed_improvement_area|None)
OUTCOME_FEEDBACK: dict[str, tuple] = {
    OUTCOME_COMPLETED: (
        FEEDBACK_SUCCESS,
        STRENGTH_HIGH,
        AREA_NONE,
    ),
    OUTCOME_IN_PROGRESS: (
        FEEDBACK_CONTINUE,
        STRENGTH_MEDIUM,
        None,
    ),
    OUTCOME_WAITING_FOR_EVIDENCE: (
        FEEDBACK_EVIDENCE_GAP,
        STRENGTH_HIGH,
        None,
    ),
    OUTCOME_DEFERRED: (
        FEEDBACK_DEFER,
        STRENGTH_LOW,
        None,
    ),
    OUTCOME_UNKNOWN: (
        FEEDBACK_UNKNOWN,
        STRENGTH_UNKNOWN,
        AREA_PROCESS,
    ),
}

# ---------------------------------------------------------------------------
# Deterministic R31.18 remaining need -> improvement area table
# ---------------------------------------------------------------------------

REMAINING_NEED_TO_IMPROVEMENT: dict[str, str] = {
    NEED_NONE: AREA_NONE,
    NEED_IDENTITY: AREA_IDENTITY,
    NEED_VERSION: AREA_VERSION,
    NEED_SCOPE: AREA_SCOPE,
    NEED_PATH: AREA_PATH,
    NEED_PARAMETER: AREA_PARAMETER,
    NEED_HTTP_BEHAVIOR: AREA_HTTP_BEHAVIOR,
    NEED_TECHNOLOGY: AREA_TECHNOLOGY,
    NEED_HUMAN_RESEARCH: AREA_HUMAN_RESEARCH,
    NEED_UNKNOWN: AREA_UNKNOWN,
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
    """First valid R31.17/R31.15 confidence level wins, else UNKNOWN."""

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
    decision: dict,
    loop: dict,
    outcome_plan: dict,
    feedback_type: str,
    strength: str,
    area: str,
    outcome: str,
    level: str,
    blockers: list[str],
) -> dict:
    plan = EvidenceFeedbackCalibrationPlan(
        rule_version=EVIDENCE_FEEDBACK_CALIBRATION_RULE_VERSION,
        feedback_type=feedback_type,
        signal_strength=strength,
        improvement_area=area,
        outcome=outcome,
        confidence_level=level,
        blockers=blockers,
        source_outcome_plan=outcome_plan,
        source_loop_plan=loop,
        source_decision_plan=decision,
        source_confidence_plan=confidence,
        source_priority_plan=prioritization,
        source_acquisition_plan=acquisition,
        research_only=True,
    )
    return feedback_calibration_plan_projection(plan)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def plan_evidence_feedback_calibration(
    acquisition_plan: object = None,
    prioritization_plan: object = None,
    confidence_plan: object = None,
    decision_plan: object = None,
    loop_plan: object = None,
    outcome_plan: object = None,
) -> dict:
    """Map one R31.18 outcome to a reusable feedback calibration signal.

    All six inputs are consumed read-only. A missing or unrecognized outcome
    yields ``UNKNOWN`` / ``UNKNOWN`` / ``PROCESS``. ``improvement_area`` is
    fixed to ``NONE`` for a completed cycle and otherwise derives from the
    R31.18 ``remaining_need`` through the closed mapping table.
    """

    acquisition = _block(acquisition_plan)
    prioritization = _block(prioritization_plan)
    confidence = _block(confidence_plan)
    decision = _block(decision_plan)
    loop = _block(loop_plan)
    outcome_block = _block(outcome_plan)

    outcome = _upper(outcome_block.get("outcome"))
    level = _level(loop, confidence)
    blockers = _blockers(
        outcome_block.get("blockers"),
        loop.get("blockers"),
        confidence.get("blockers"),
    )

    row = OUTCOME_FEEDBACK.get(outcome)
    if row is None:
        return _result(
            acquisition=acquisition,
            prioritization=prioritization,
            confidence=confidence,
            decision=decision,
            loop=loop,
            outcome_plan=outcome_block,
            feedback_type=FEEDBACK_UNKNOWN,
            strength=STRENGTH_UNKNOWN,
            area=AREA_PROCESS,
            outcome=OUTCOME_UNKNOWN,
            level=level,
            blockers=blockers,
        )

    feedback_type, strength, fixed_area = row
    if fixed_area is not None:
        area = fixed_area
    else:
        remaining = _upper(outcome_block.get("remaining_need"))
        area = REMAINING_NEED_TO_IMPROVEMENT.get(remaining, AREA_UNKNOWN)

    return _result(
        acquisition=acquisition,
        prioritization=prioritization,
        confidence=confidence,
        decision=decision,
        loop=loop,
        outcome_plan=outcome_block,
        feedback_type=feedback_type,
        strength=strength,
        area=area,
        outcome=outcome,
        level=level,
        blockers=blockers,
    )


__all__ = [
    "EVIDENCE_FEEDBACK_CALIBRATION_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "OUTCOME_FEEDBACK",
    "REMAINING_NEED_TO_IMPROVEMENT",
    "MAX_ITEMS",
    "plan_evidence_feedback_calibration",
]
