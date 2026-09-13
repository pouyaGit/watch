"""Stage R31.15 deterministic evidence confidence aggregator (pure engine).

Consumes one read-only R31.13 Evidence Acquisition Plan and one read-only
R31.14 Evidence Prioritization Plan and projects a confidence assessment for
one Asset<->CVE research candidate:

    "How confident are we that the current evidence is sufficient, what
     confidence level does the candidate currently have, what evidence
     dimension limits confidence, and what prevents higher confidence?"

This is a **plan-only assessment signal**. It never acquires evidence, never
contacts a target, never scans, never runs Nuclei, never crawls, never fuzzes,
never exploits, never calls an LLM, never touches Mongo and never renders a
probability, exploitability, severity, CVSS or payout judgement.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Consume-only: the R31.13/R31.14 plans are read verbatim. The aggregator
  never recomputes R31.12 gaps, never re-derives an acquisition method or
  priority rank, and never inspects CVE data, the Money Score or the R29 hunt
  queue.
- Additive and read-only: inputs are never mutated; the result is a new dict
  with rule version ``r31-15``.
- Deterministic: closed level/category/completeness/limiting/alignment/blocker
  vocabularies, documented per-method rules and byte-identical repeated
  output. No randomness, no timestamps, no hashes and no external state.
- Conservative: confidence can only be ``HIGH`` when R31.13 selected existing
  evidence review *and* R31.14 emitted the aligned rank-1 priority item. A
  malformed, missing or misaligned upstream plan yields ``UNKNOWN``; it is
  never silently upgraded.
- Privacy: only closed codes and bounded, sanitized snapshots of the two
  source plans are retained; raw URLs, credentials, tokens, headers, query
  values and arbitrary source text are never copied.
"""

from __future__ import annotations

from ai.knowledge.evidence_acquisition_planner import (
    COMPONENT_IDENTITY_LOOKUP,
    EXISTING_EVIDENCE_REVIEW,
    HTTP_BEHAVIOR_REVIEW,
    MANUAL_RESEARCH,
    NO_ACQUISITION,
    PARAMETER_EVIDENCE_REVIEW,
    PATH_EVIDENCE_REVIEW,
    SCOPE_EVIDENCE_REVIEW,
    TECHNOLOGY_EVIDENCE_REVIEW,
    VERSION_LOOKUP,
)
from ai.knowledge.evidence_prioritization_planner import METHOD_PRIORITY
from ai.schemas.evidence_confidence import (
    ALIGNMENT_ALIGNED,
    ALIGNMENT_MISALIGNED,
    ALIGNMENT_NOT_APPLICABLE,
    BLOCKER_HTTP_BEHAVIOR_EVIDENCE_MISSING,
    BLOCKER_HUMAN_RESEARCH_REQUIRED,
    BLOCKER_IDENTITY_EVIDENCE_MISSING,
    BLOCKER_MALFORMED_ACQUISITION_PLAN,
    BLOCKER_MISSING_PRIORITIZATION_ITEM,
    BLOCKER_NO_ACQUISITION_PLANNED,
    BLOCKER_PARAMETER_EVIDENCE_MISSING,
    BLOCKER_PATH_EVIDENCE_MISSING,
    BLOCKER_PRIORITY_MISALIGNMENT,
    BLOCKER_SCOPE_EVIDENCE_MISSING,
    BLOCKER_TECHNOLOGY_EVIDENCE_MISSING,
    BLOCKER_UNKNOWN_ACQUISITION_METHOD,
    BLOCKER_VERSION_EVIDENCE_MISSING,
    CATEGORY_BEHAVIOR_LIMITED,
    CATEGORY_IDENTITY_LIMITED,
    CATEGORY_PARAMETER_LIMITED,
    CATEGORY_PATH_LIMITED,
    CATEGORY_RESEARCH_INCOMPLETE,
    CATEGORY_SCOPE_LIMITED,
    CATEGORY_SUFFICIENT_EVIDENCE,
    CATEGORY_TECHNOLOGY_LIMITED,
    CATEGORY_VERSION_LIMITED,
    COMPLETENESS_COMPLETE,
    COMPLETENESS_MINIMAL,
    COMPLETENESS_NONE,
    COMPLETENESS_PARTIAL,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
    EVIDENCE_CONFIDENCE_RULE_VERSION,
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
    MAX_ITEMS,
    EvidenceConfidencePlan,
    confidence_plan_projection,
)

EVIDENCE_CONFIDENCE_AGGREGATOR_RULE_VERSION = "r31-15"
RULE_VERSION = EVIDENCE_CONFIDENCE_AGGREGATOR_RULE_VERSION

# ---------------------------------------------------------------------------
# Deterministic per-method confidence mapping
# ---------------------------------------------------------------------------
# method -> (level, category, completeness, limiting_factor, blocker|None)
#
# HIGH is handled separately because it additionally requires the aligned
# R31.14 rank-1 priority item.
METHOD_CONFIDENCE: dict[str, tuple] = {
    EXISTING_EVIDENCE_REVIEW: (
        CONFIDENCE_HIGH,
        CATEGORY_SUFFICIENT_EVIDENCE,
        COMPLETENESS_COMPLETE,
        LIMITING_NONE,
        None,
    ),
    COMPONENT_IDENTITY_LOOKUP: (
        CONFIDENCE_MEDIUM,
        CATEGORY_IDENTITY_LIMITED,
        COMPLETENESS_PARTIAL,
        LIMITING_COMPONENT_IDENTITY,
        BLOCKER_IDENTITY_EVIDENCE_MISSING,
    ),
    VERSION_LOOKUP: (
        CONFIDENCE_MEDIUM,
        CATEGORY_VERSION_LIMITED,
        COMPLETENESS_PARTIAL,
        LIMITING_VERSION,
        BLOCKER_VERSION_EVIDENCE_MISSING,
    ),
    SCOPE_EVIDENCE_REVIEW: (
        CONFIDENCE_MEDIUM,
        CATEGORY_SCOPE_LIMITED,
        COMPLETENESS_PARTIAL,
        LIMITING_SCOPE,
        BLOCKER_SCOPE_EVIDENCE_MISSING,
    ),
    PATH_EVIDENCE_REVIEW: (
        CONFIDENCE_LOW,
        CATEGORY_PATH_LIMITED,
        COMPLETENESS_MINIMAL,
        LIMITING_PATH,
        BLOCKER_PATH_EVIDENCE_MISSING,
    ),
    PARAMETER_EVIDENCE_REVIEW: (
        CONFIDENCE_LOW,
        CATEGORY_PARAMETER_LIMITED,
        COMPLETENESS_MINIMAL,
        LIMITING_PARAMETER,
        BLOCKER_PARAMETER_EVIDENCE_MISSING,
    ),
    HTTP_BEHAVIOR_REVIEW: (
        CONFIDENCE_LOW,
        CATEGORY_BEHAVIOR_LIMITED,
        COMPLETENESS_MINIMAL,
        LIMITING_HTTP_BEHAVIOR,
        BLOCKER_HTTP_BEHAVIOR_EVIDENCE_MISSING,
    ),
    TECHNOLOGY_EVIDENCE_REVIEW: (
        CONFIDENCE_LOW,
        CATEGORY_TECHNOLOGY_LIMITED,
        COMPLETENESS_MINIMAL,
        LIMITING_TECHNOLOGY,
        BLOCKER_TECHNOLOGY_EVIDENCE_MISSING,
    ),
    MANUAL_RESEARCH: (
        CONFIDENCE_LOW,
        CATEGORY_RESEARCH_INCOMPLETE,
        COMPLETENESS_MINIMAL,
        LIMITING_HUMAN_RESEARCH,
        BLOCKER_HUMAN_RESEARCH_REQUIRED,
    ),
}

# Closed per-method confidence levels (safe for direct test assertion).
METHOD_CONFIDENCE_LEVELS: dict[str, str] = {
    method: row[0] for method, row in METHOD_CONFIDENCE.items()
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


def _coerce_int(value: object, default: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _items(prioritization: dict) -> list[dict]:
    raw = prioritization.get("items")
    if not isinstance(raw, (list, tuple)):
        return []
    return [
        item for item in list(raw)[:MAX_ITEMS] if isinstance(item, dict)
    ]


def _result(
    *,
    acquisition: dict,
    prioritization: dict,
    level: str,
    category: str,
    completeness: str,
    limiting: str,
    alignment: str,
    blockers: list[str],
) -> dict:
    plan = EvidenceConfidencePlan(
        rule_version=EVIDENCE_CONFIDENCE_RULE_VERSION,
        confidence_level=level,
        confidence_category=category,
        limiting_factor=limiting,
        evidence_completeness=completeness,
        priority_alignment=alignment,
        blockers=blockers,
        source_acquisition_plan=acquisition,
        source_prioritization_plan=prioritization,
        research_only=True,
    )
    return confidence_plan_projection(plan)


def _unknown_result(
    acquisition: dict,
    prioritization: dict,
    blockers: list[str],
    *,
    alignment: str = ALIGNMENT_NOT_APPLICABLE,
) -> dict:
    return _result(
        acquisition=acquisition,
        prioritization=prioritization,
        level=CONFIDENCE_UNKNOWN,
        category=CATEGORY_RESEARCH_INCOMPLETE,
        completeness=COMPLETENESS_NONE,
        limiting=LIMITING_UPSTREAM_PLAN,
        alignment=alignment,
        blockers=blockers,
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def aggregate_evidence_confidence(
    acquisition_plan: object = None,
    prioritization_plan: object = None,
) -> dict:
    """Aggregate one R31.13/R31.14 plan pair into a confidence assessment.

    Both inputs are consumed read-only. The confidence level is derived from
    the R31.13 acquisition method; ``HIGH`` additionally requires the aligned
    R31.14 rank-1 priority item. ``NONE``/missing/unknown/mismatched
    acquisition methods yield ``UNKNOWN`` and are never silently upgraded.
    A missing R31.14 plan yields ``NOT_APPLICABLE`` priority alignment while
    the method-based level remains deterministic (except for the HIGH rule,
    which requires the rank-1 item by definition).
    """

    acquisition = _block(acquisition_plan)
    prioritization = _block(prioritization_plan)

    method = _upper(acquisition.get("acquisition_method"))
    target = _upper(acquisition.get("evidence_target"))

    # Terminal acquisition: no evidence path is planned.
    if method == NO_ACQUISITION:
        return _unknown_result(
            acquisition,
            prioritization,
            [BLOCKER_NO_ACQUISITION_PLANNED],
        )

    row = METHOD_CONFIDENCE.get(method)
    if row is None:
        blocker = (
            BLOCKER_MALFORMED_ACQUISITION_PLAN
            if not method
            else BLOCKER_UNKNOWN_ACQUISITION_METHOD
        )
        return _unknown_result(
            acquisition, prioritization, [blocker]
        )

    # The R31.13 method -> target/rank pairing (authority: R31.14 table,
    # which itself mirrors R31.13). A mismatched target is malformed input.
    expected = METHOD_PRIORITY.get(method)
    if expected is None or target != expected[0]:
        return _unknown_result(
            acquisition,
            prioritization,
            [BLOCKER_MALFORMED_ACQUISITION_PLAN],
        )

    expected_rank = _coerce_int(expected[1])
    level, category, completeness, limiting, blocker = row

    # Priority alignment is evaluated only when an R31.14 plan is present.
    alignment = ALIGNMENT_NOT_APPLICABLE
    blockers: list[str] = [blocker] if blocker else []
    if prioritization:
        matching = [
            item
            for item in _items(prioritization)
            if _upper(item.get("acquisition_method")) == method
            and _upper(item.get("evidence_target")) == target
        ]
        rank_matches = any(
            _coerce_int(item.get("priority_rank")) == expected_rank
            for item in matching
        )
        if matching and rank_matches:
            alignment = ALIGNMENT_ALIGNED
        else:
            alignment = ALIGNMENT_MISALIGNED
            blockers.append(
                BLOCKER_MISSING_PRIORITIZATION_ITEM
                if not matching
                else BLOCKER_PRIORITY_MISALIGNMENT
            )

    # HIGH additionally requires the aligned rank-1 prioritization item.
    if method == EXISTING_EVIDENCE_REVIEW:
        if alignment == ALIGNMENT_ALIGNED:
            return _result(
                acquisition=acquisition,
                prioritization=prioritization,
                level=CONFIDENCE_HIGH,
                category=CATEGORY_SUFFICIENT_EVIDENCE,
                completeness=COMPLETENESS_COMPLETE,
                limiting=LIMITING_NONE,
                alignment=ALIGNMENT_ALIGNED,
                blockers=[],
            )
        return _unknown_result(
            acquisition,
            prioritization,
            blockers or [BLOCKER_MISSING_PRIORITIZATION_ITEM],
            alignment=alignment,
        )

    return _result(
        acquisition=acquisition,
        prioritization=prioritization,
        level=level,
        category=category,
        completeness=completeness,
        limiting=limiting,
        alignment=alignment,
        blockers=blockers,
    )


__all__ = [
    "EVIDENCE_CONFIDENCE_AGGREGATOR_RULE_VERSION",
    "RULE_VERSION",
    "METHOD_CONFIDENCE",
    "METHOD_CONFIDENCE_LEVELS",
    "MAX_ITEMS",
    "aggregate_evidence_confidence",
]
