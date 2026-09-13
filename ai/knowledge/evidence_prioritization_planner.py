"""Stage R31.14 deterministic evidence prioritization planner (pure engine).

Consumes one read-only R31.13 Evidence Acquisition Plan and converts it into
a prioritized evidence roadmap for a human bug-bounty researcher:

    "Of the evidence this candidate still needs, which piece should I
     prioritize, why, what uncertainty does it reduce, how dependent is it
     on earlier evidence, and how important is completing it?"

This is a **planning signal only, and it is plan-only**. It never executes
the acquisition method, never contacts a target, never scans, never runs
Nuclei, never crawls, never fuzzes, never exploits, never calls an LLM, never
touches Mongo and never renders a probability, exploitability, severity, CVSS
or payout judgement. It decides priority order, not action.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Consume-only: the R31.13 acquisition plan is read verbatim. The planner
  never recalculates R31.12 gaps, never re-derives an acquisition method and
  never inspects CVE data, Money Score or the R29 hunt queue.
- Additive and read-only: the input plan is never mutated; the result is a
  new dict with rule version ``r31-14``.
- Deterministic: closed priority/uncertainty/dependency/importance
  vocabularies, a documented per-method mapping, a documented stable
  tie-break order and byte-identical repeated output. No randomness, no
  timestamps, no hashes and no external state.
- Terminal handling: a ``NONE`` acquisition method (or a missing/unknown
  method) yields an empty priority list with ``research_only=True``; nothing
  is invented.
- Privacy: only closed codes and a bounded, sanitized snapshot of the R31.13
  plan are retained; raw URLs, credentials, tokens, headers, query values and
  arbitrary source text are never copied.
"""

from __future__ import annotations

from ai.knowledge.evidence_acquisition_planner import (
    ACQUISITION_METHODS,
    COMPONENT_IDENTITY_LOOKUP,
    EXISTING_EVIDENCE_REVIEW,
    HTTP_BEHAVIOR_REVIEW,
    MANUAL_RESEARCH,
    PARAMETER_EVIDENCE_REVIEW,
    PATH_EVIDENCE_REVIEW,
    SCOPE_EVIDENCE_REVIEW,
    TECHNOLOGY_EVIDENCE_REVIEW,
    TARGET_COMPONENT_IDENTITY,
    TARGET_EXISTING_EVIDENCE,
    TARGET_HTTP_BEHAVIOR,
    TARGET_NONE,
    TARGET_PARAMETER,
    TARGET_PATH,
    TARGET_SCOPE,
    TARGET_TECHNOLOGY,
    TARGET_VERSION,
    VERSION_LOOKUP,
)
from ai.schemas.evidence_prioritization import (
    DEPENDENCY_BEHAVIORAL,
    DEPENDENCY_DERIVED,
    DEPENDENCY_INDEPENDENT,
    DEPENDENCY_UPSTREAM,
    EVIDENCE_PRIORITIZATION_RULE_VERSION,
    IMPORTANCE_CRITICAL,
    IMPORTANCE_HIGH,
    IMPORTANCE_LOW,
    IMPORTANCE_MEDIUM,
    PRIORITY_EXISTING_EVIDENCE,
    PRIORITY_HTTP_BEHAVIOR,
    PRIORITY_IDENTITY,
    PRIORITY_MANUAL_RESEARCH,
    PRIORITY_PARAMETER,
    PRIORITY_PATH,
    PRIORITY_REASONS,
    PRIORITY_SCOPE,
    PRIORITY_TECHNOLOGY,
    PRIORITY_VERSION,
    UNCERTAINTY_EXISTING_EVIDENCE,
    UNCERTAINTY_HUMAN_JUDGEMENT,
    UNCERTAINTY_HTTP_BEHAVIOR,
    UNCERTAINTY_IDENTITY,
    UNCERTAINTY_PARAMETER,
    UNCERTAINTY_PATH,
    UNCERTAINTY_SCOPE,
    UNCERTAINTY_TECHNOLOGY,
    UNCERTAINTY_VERSION,
    EvidencePrioritizationPlan,
    EvidencePriorityItem,
    prioritization_plan_projection,
)

EVIDENCE_PRIORITIZATION_PLANNER_RULE_VERSION = "r31-14"
RULE_VERSION = EVIDENCE_PRIORITIZATION_PLANNER_RULE_VERSION

# ---------------------------------------------------------------------------
# Priority logic (documented, deterministic)
# ---------------------------------------------------------------------------
# Tiers follow the stage request exactly:
#   1. existing evidence review (cheapest, highest information gain)
#   2. missing identity evidence
#   3. missing version evidence
#   4. scope confirmation
#   5. path/parameter evidence (path before parameter as a stable tie-break)
#   6. HTTP behavior evidence
#   7. technology evidence
#   8. manual research fallback

# Stable within-tier ordering used if a future plan ever carries more than one
# item: already-ordered priority tiers, path before parameter.
PRIORITY_ORDER: tuple[str, ...] = (
    EXISTING_EVIDENCE_REVIEW,
    COMPONENT_IDENTITY_LOOKUP,
    VERSION_LOOKUP,
    SCOPE_EVIDENCE_REVIEW,
    PATH_EVIDENCE_REVIEW,
    PARAMETER_EVIDENCE_REVIEW,
    HTTP_BEHAVIOR_REVIEW,
    TECHNOLOGY_EVIDENCE_REVIEW,
    MANUAL_RESEARCH,
)

# method -> (expected target, priority_rank, priority_reason,
#            uncertainty_category, dependency_level, completion_importance)
METHOD_PRIORITY: dict[str, tuple] = {
    EXISTING_EVIDENCE_REVIEW: (
        TARGET_EXISTING_EVIDENCE,
        1,
        PRIORITY_EXISTING_EVIDENCE,
        UNCERTAINTY_EXISTING_EVIDENCE,
        DEPENDENCY_INDEPENDENT,
        IMPORTANCE_HIGH,
    ),
    COMPONENT_IDENTITY_LOOKUP: (
        TARGET_COMPONENT_IDENTITY,
        2,
        PRIORITY_IDENTITY,
        UNCERTAINTY_IDENTITY,
        DEPENDENCY_INDEPENDENT,
        IMPORTANCE_CRITICAL,
    ),
    VERSION_LOOKUP: (
        TARGET_VERSION,
        3,
        PRIORITY_VERSION,
        UNCERTAINTY_VERSION,
        DEPENDENCY_UPSTREAM,
        IMPORTANCE_CRITICAL,
    ),
    SCOPE_EVIDENCE_REVIEW: (
        TARGET_SCOPE,
        4,
        PRIORITY_SCOPE,
        UNCERTAINTY_SCOPE,
        DEPENDENCY_UPSTREAM,
        IMPORTANCE_HIGH,
    ),
    PATH_EVIDENCE_REVIEW: (
        TARGET_PATH,
        5,
        PRIORITY_PATH,
        UNCERTAINTY_PATH,
        DEPENDENCY_DERIVED,
        IMPORTANCE_MEDIUM,
    ),
    PARAMETER_EVIDENCE_REVIEW: (
        TARGET_PARAMETER,
        5,
        PRIORITY_PARAMETER,
        UNCERTAINTY_PARAMETER,
        DEPENDENCY_DERIVED,
        IMPORTANCE_MEDIUM,
    ),
    HTTP_BEHAVIOR_REVIEW: (
        TARGET_HTTP_BEHAVIOR,
        6,
        PRIORITY_HTTP_BEHAVIOR,
        UNCERTAINTY_HTTP_BEHAVIOR,
        DEPENDENCY_BEHAVIORAL,
        IMPORTANCE_MEDIUM,
    ),
    TECHNOLOGY_EVIDENCE_REVIEW: (
        TARGET_TECHNOLOGY,
        7,
        PRIORITY_TECHNOLOGY,
        UNCERTAINTY_TECHNOLOGY,
        DEPENDENCY_DERIVED,
        IMPORTANCE_LOW,
    ),
    MANUAL_RESEARCH: (
        TARGET_EXISTING_EVIDENCE,
        8,
        PRIORITY_MANUAL_RESEARCH,
        UNCERTAINTY_HUMAN_JUDGEMENT,
        DEPENDENCY_INDEPENDENT,
        IMPORTANCE_HIGH,
    ),
}

# Closed per-method priority ranks (safe for direct test assertion).
METHOD_PRIORITY_RANKS: dict[str, int] = {
    method: row[1] for method, row in METHOD_PRIORITY.items()
}

# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------

MAX_ITEMS = 8


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def plan_evidence_prioritization(acquisition_plan: object = None) -> dict:
    """Prioritize the evidence selected by one R31.13 acquisition plan.

    ``acquisition_plan`` is the R31.13 result dict; it is consumed read-only.
    The selected acquisition method and evidence target are the only inputs
    that decide the roadmap: a ``NONE``/missing/unknown method yields an empty
    priority list, and a method whose upstream ``evidence_target`` does not
    match the method's deterministic target pair is treated as malformed and
    yields an empty list (never silently reinterpreted).
    """

    block = _block(acquisition_plan)
    method = _upper(block.get("acquisition_method"))
    target = _upper(block.get("evidence_target"))

    items: list[EvidencePriorityItem] = []
    row = METHOD_PRIORITY.get(method)
    if row is not None:
        expected_target = row[0]
        if target == expected_target:
            items.append(
                EvidencePriorityItem(
                    evidence_target=target,
                    acquisition_method=method,
                    priority_rank=row[1],
                    priority_reason=row[2],
                    uncertainty_category=row[3],
                    dependency_level=row[4],
                    completion_importance=row[5],
                )
            )

    plan = EvidencePrioritizationPlan(
        rule_version=EVIDENCE_PRIORITIZATION_RULE_VERSION,
        items=items[:MAX_ITEMS],
        source_acquisition_plan=block,
        research_only=True,
    )
    return prioritization_plan_projection(plan)


__all__ = [
    "EVIDENCE_PRIORITIZATION_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "PRIORITY_ORDER",
    "METHOD_PRIORITY",
    "METHOD_PRIORITY_RANKS",
    "ACQUISITION_METHODS",
    "PRIORITY_REASONS",
    "MAX_ITEMS",
    "plan_evidence_prioritization",
]
