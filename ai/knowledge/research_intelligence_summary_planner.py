"""Stage R31.20 deterministic research intelligence summary planner (pure).

Aggregates the read-only R31.13-R31.19 evidence pipeline plans into the final
research intelligence summary for one Asset<->CVE research candidate:

    "What is the final research intelligence status for this candidate?"

This is a **summary signal only**. It never executes research, never acquires
evidence, never contacts a target, never scans, never runs Nuclei, never
crawls, never fuzzes, never exploits, never calls an LLM, never touches Mongo
and never renders a probability, exploitability, severity, CVSS or payout
judgement. It aggregates existing plans and never changes previous planner
behavior.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Consume-only: the upstream plans are read verbatim. The planner never
  recomputes acquisition, priority, confidence, decision, loop, outcome or
  feedback and never inspects CVE data, the Money Score or the R29 hunt
  queue.
- Additive and read-only: inputs are never mutated; the result is a new dict
  with rule version ``r31-20``.
- Deterministic: a closed outcome→status/category table and byte-identical
  repeated output. No randomness, no timestamps, no hashes and no external
  state.
- Conservative: only the five closed R31.18 outcomes produce a status row; a
  missing or unrecognized outcome yields ``UNKNOWN`` / ``INVALID`` and is
  never silently upgraded.
- Privacy: only closed codes and bounded, sanitized snapshots of the three
  summary-source plans are retained; raw URLs, credentials, tokens, headers,
  query values and arbitrary source text are never copied.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_LEVELS,
    CONFIDENCE_UNKNOWN,
    COMPLETENESS_NONE,
    EVIDENCE_COMPLETENESS_LEVELS,
)
from ai.schemas.evidence_feedback_calibration import (
    FEEDBACK_TYPES,
    FEEDBACK_UNKNOWN,
    IMPROVEMENT_AREAS,
    AREA_UNKNOWN,
)
from ai.schemas.evidence_research_loop import (
    LIFECYCLE_STATES,
    LIFECYCLE_UNKNOWN,
)
from ai.schemas.evidence_research_outcome import (
    OUTCOME_COMPLETED,
    OUTCOME_DEFERRED,
    OUTCOME_IN_PROGRESS,
    OUTCOME_UNKNOWN,
    OUTCOME_WAITING_FOR_EVIDENCE,
    OUTCOMES,
)
from ai.schemas.research_intelligence_summary import (
    CATEGORY_EVIDENCE_REQUIRED,
    CATEGORY_INVALID,
    CATEGORY_ONGOING,
    CATEGORY_PAUSED,
    CATEGORY_SUCCESSFUL,
    MAX_ITEMS,
    RESEARCH_INTELLIGENCE_SUMMARY_RULE_VERSION,
    STATUS_ACTIVE,
    STATUS_COMPLETE,
    STATUS_DEFERRED,
    STATUS_UNKNOWN,
    STATUS_WAITING,
    ResearchIntelligenceSummaryPlan,
    research_summary_plan_projection,
)

RESEARCH_INTELLIGENCE_SUMMARY_PLANNER_RULE_VERSION = "r31-20"
RULE_VERSION = RESEARCH_INTELLIGENCE_SUMMARY_PLANNER_RULE_VERSION

# ---------------------------------------------------------------------------
# Deterministic R31.18 outcome -> summary status/category table
# ---------------------------------------------------------------------------
# outcome -> (research_status, summary_category)
OUTCOME_SUMMARY: dict[str, tuple] = {
    OUTCOME_COMPLETED: (STATUS_COMPLETE, CATEGORY_SUCCESSFUL),
    OUTCOME_IN_PROGRESS: (STATUS_ACTIVE, CATEGORY_ONGOING),
    OUTCOME_WAITING_FOR_EVIDENCE: (
        STATUS_WAITING,
        CATEGORY_EVIDENCE_REQUIRED,
    ),
    OUTCOME_DEFERRED: (STATUS_DEFERRED, CATEGORY_PAUSED),
    OUTCOME_UNKNOWN: (STATUS_UNKNOWN, CATEGORY_INVALID),
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


def _closed(value: object, allowed: tuple) -> str:
    text = _upper(value)
    return text if text in allowed else ""


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
    outcome: dict,
    feedback: dict,
    status: str,
    category: str,
    evidence_status: str,
    level: str,
    final_state: str,
    signal: str,
    area: str,
    blockers: list[str],
) -> dict:
    plan = ResearchIntelligenceSummaryPlan(
        rule_version=RESEARCH_INTELLIGENCE_SUMMARY_RULE_VERSION,
        research_status=status,
        evidence_status=evidence_status,
        confidence_level=level,
        final_state=final_state,
        feedback_signal=signal,
        improvement_area=area,
        blockers=blockers,
        summary_category=category,
        source_feedback_plan=feedback,
        source_outcome_plan=outcome,
        source_loop_plan=loop,
        research_only=True,
    )
    return research_summary_plan_projection(plan)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def plan_research_intelligence_summary(
    acquisition_plan: object = None,
    prioritization_plan: object = None,
    confidence_plan: object = None,
    decision_plan: object = None,
    loop_plan: object = None,
    outcome_plan: object = None,
    feedback_plan: object = None,
) -> dict:
    """Aggregate the R31.13-R31.19 plans into the final summary (read-only).

    The R31.18 outcome drives ``research_status``/``summary_category``; the
    remaining fields are consumed verbatim from the R31.15/R31.17/R31.19
    plans with closed-vocabulary fallbacks (``UNKNOWN``/``NONE``). Nothing is
    recomputed and no input is mutated.
    """

    acquisition = _block(acquisition_plan)
    prioritization = _block(prioritization_plan)
    confidence = _block(confidence_plan)
    decision = _block(decision_plan)
    loop = _block(loop_plan)
    outcome = _block(outcome_plan)
    feedback = _block(feedback_plan)

    outcome_value = _upper(outcome.get("outcome"))
    row = OUTCOME_SUMMARY.get(outcome_value)
    if row is None:
        status, category = STATUS_UNKNOWN, CATEGORY_INVALID
        outcome_value = OUTCOME_UNKNOWN
    else:
        status, category = row

    evidence_status = (
        _closed(
            confidence.get("evidence_completeness"),
            EVIDENCE_COMPLETENESS_LEVELS,
        )
        or COMPLETENESS_NONE
    )

    level = _closed(loop.get("confidence_level"), CONFIDENCE_LEVELS)
    if not level:
        level = _closed(confidence.get("confidence_level"),
                        CONFIDENCE_LEVELS)

    final_state = _closed(
        loop.get("lifecycle_state"), LIFECYCLE_STATES
    ) or LIFECYCLE_UNKNOWN

    signal = _closed(
        feedback.get("feedback_type"), FEEDBACK_TYPES
    ) or FEEDBACK_UNKNOWN

    area = _closed(
        feedback.get("improvement_area"), IMPROVEMENT_AREAS
    ) or AREA_UNKNOWN

    blockers = _blockers(
        feedback.get("blockers"),
        outcome.get("blockers"),
        loop.get("blockers"),
        confidence.get("blockers"),
    )

    return _result(
        acquisition=acquisition,
        prioritization=prioritization,
        confidence=confidence,
        decision=decision,
        loop=loop,
        outcome=outcome,
        feedback=feedback,
        status=status,
        category=category,
        evidence_status=evidence_status,
        level=level or CONFIDENCE_UNKNOWN,
        final_state=final_state,
        signal=signal,
        area=area,
        blockers=blockers,
    )


__all__ = [
    "RESEARCH_INTELLIGENCE_SUMMARY_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "OUTCOME_SUMMARY",
    "MAX_ITEMS",
    "plan_research_intelligence_summary",
]
