"""Stage R53.5 deterministic finding state and confidence reasoning.

Derives the closed research state and the conservative confidence of a
finding candidate from the already-bounded upstream signals:

    "How strong is this research candidate, and how confident may we be?"

Hard boundaries encoded here:

- Conservative by construction: confidence is a meet (minimum) over upstream
  constraints plus explicit caps. No rule ever raises confidence, and
  agreement between multiple agents is never a boost.
- Evidence-plan granularity: a complete evidence *plan* never becomes
  collected evidence; the strongest state is ``CONFIRMED_OBSERVED``, which
  only records that the structured observation set is complete. It never
  confirms a vulnerability.
- Deterministic: state, confidence and reasons are pure functions of the
  bounded inputs.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  browser, no scanner, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.finding_assessment import (
    CONFIDENCE_REASONS,
    REASON_CONFLICT_CAP,
    REASON_EVIDENCE_PARTIAL_CAP,
    REASON_EVALUATION_DIAGNOSTIC_CAP,
    REASON_EVALUATION_QUALITY_CAP,
    REASON_EVALUATION_SAFETY_CAP,
    REASON_EVALUATION_UNAVAILABLE_CAP,
    REASON_INSUFFICIENT_EVIDENCE_CAP,
    REASON_NO_UPSTREAM_CONFIDENCE,
    REASON_UPSTREAM_CONTEXT_CONFIDENCE,
    REASON_UPSTREAM_EVIDENCE_CONFIDENCE,
    REASON_UPSTREAM_EVIDENCE_STATE,
    REASON_UPSTREAM_SPECIALIST_CONFIDENCE,
    REASON_UPSTREAM_STATUS,
    STATE_CONFIRMED_OBSERVED,
    STATE_CONFLICTED,
    STATE_EVIDENCE_SUPPORTED,
    STATE_INSUFFICIENT_EVIDENCE,
    STATE_NEEDS_MORE_EVIDENCE,
    STATE_RESEARCH_CANDIDATE,
    MAX_CONFIDENCE_REASONS,
)
from ai.schemas.finding_evidence import (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_MISSING,
    COMPLETENESS_PARTIAL,
    COMPLETENESS_UNKNOWN,
)

FINDING_STATE_RULE_VERSION = "r53-5"
RULE_VERSION = FINDING_STATE_RULE_VERSION

CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"
CONFIDENCE_UNKNOWN = "UNKNOWN"

_CONFIDENCE_RANK: dict[str, int] = {
    CONFIDENCE_UNKNOWN: 0,
    CONFIDENCE_LOW: 1,
    CONFIDENCE_MEDIUM: 2,
    CONFIDENCE_HIGH: 3,
}

_RANK_CONFIDENCE: dict[int, str] = {
    0: CONFIDENCE_UNKNOWN,
    1: CONFIDENCE_LOW,
    2: CONFIDENCE_MEDIUM,
    3: CONFIDENCE_HIGH,
}

_STATUS_INSUFFICIENT: tuple[str, ...] = ("CREATED", "UNKNOWN")
_RATING_STRONG: tuple[str, ...] = ("EXCELLENT", "GOOD")
_RATING_WEAK: tuple[str, ...] = ("WEAK", "CRITICAL")

#: Diagnostics that indicate a structural/quality cap of MEDIUM.
_DIAGNOSTICS_MEDIUM_CAP: tuple[str, ...] = (
    "UNSUPPORTED_HYPOTHESIS",
    "HYPOTHESIS_SAFETY_FLAGS_MISSING",
    "MISSING_EVIDENCE_REQUIREMENT",
    "EVIDENCE_INCONSISTENT",
    "EVIDENCE_REQUIRED_LIMITATION_MISSING",
    "PROVENANCE_INCOMPLETE",
    "PROVENANCE_INVENTED_LAYER",
    "GOVERNANCE_UNKNOWN",
    "GOVERNANCE_INCONSISTENT",
    "CONTEXT_TOO_SPARSE",
    "MALFORMED_GOVERNANCE",
    "MALFORMED_PROVENANCE",
    "MALFORMED_LIMITATIONS",
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip().upper()


def confidence_rank(level: object) -> int:
    """Deterministic rank of a confidence level (UNKNOWN is lowest)."""

    return _CONFIDENCE_RANK.get(_text(level), 0)


def min_confidence(*levels: object) -> str:
    """Meet of confidence levels: the result is never higher than any input."""

    if not levels:
        return CONFIDENCE_UNKNOWN
    return _RANK_CONFIDENCE[min(confidence_rank(level) for level in levels)]


def _ordered_reasons(reasons: list[str]) -> list[str]:
    ordered: list[str] = []
    for reason in CONFIDENCE_REASONS:
        if reason in reasons and reason not in ordered:
            ordered.append(reason)
    for reason in reasons:
        if reason not in ordered:
            ordered.append(reason)
    return ordered[:MAX_CONFIDENCE_REASONS]


def derive_finding_state(
    *,
    status: object,
    has_hypotheses: bool,
    context_fact_count: int,
    evidence_state: object,
    evidence_completeness: object,
    evidence_missing: bool,
    conflict_count: int,
    evaluation_present: bool,
    evaluation_rating: object,
    safety_state: object,
    hard_gate_state: object,
    diagnostic_codes: object,
) -> str:
    """Derive the closed finding state (read-only).

    Order of precedence: insufficient structured research, conflicts,
    incomplete evidence, then the complete-evidence states. A complete
    evidence plan never confirms a vulnerability; ``CONFIRMED_OBSERVED`` only
    records that the structured observation set is complete and internally
    consistent.
    """

    resolved_status = _text(status)
    resolved_evidence_state = _text(evidence_state)
    resolved_completeness = _text(evidence_completeness)
    resolved_rating = _text(evaluation_rating)
    resolved_safety = _text(safety_state)
    resolved_gate = _text(hard_gate_state)
    diagnostics = {
        _text(code) for code in (diagnostic_codes or ())
    }

    if not has_hypotheses:
        return STATE_INSUFFICIENT_EVIDENCE
    if resolved_status in _STATUS_INSUFFICIENT:
        return STATE_INSUFFICIENT_EVIDENCE
    if evidence_missing and context_fact_count == 0:
        return STATE_INSUFFICIENT_EVIDENCE
    if conflict_count > 0:
        return STATE_CONFLICTED
    if (
        resolved_evidence_state != "COMPLETE"
        or resolved_completeness
        in (COMPLETENESS_PARTIAL, COMPLETENESS_MISSING, COMPLETENESS_UNKNOWN)
    ):
        return STATE_NEEDS_MORE_EVIDENCE
    # Complete structured evidence plan.
    if (
        resolved_status == "COMPLETED"
        and evaluation_present
        and resolved_safety == "PASS"
        and resolved_gate == "PASS"
        and not diagnostics
        and resolved_rating in _RATING_STRONG
        and context_fact_count >= 5
    ):
        return STATE_CONFIRMED_OBSERVED
    if (
        resolved_status == "COMPLETED"
        and evaluation_present
        and resolved_safety == "PASS"
        and resolved_gate == "PASS"
    ):
        return STATE_EVIDENCE_SUPPORTED
    return STATE_RESEARCH_CANDIDATE


def derive_finding_confidence(
    *,
    state: object,
    status: object,
    result_confidence: object,
    evidence_confidence: object,
    context_confidence: object,
    evidence_state: object,
    evidence_completeness: object,
    evaluation_present: bool,
    evaluation_rating: object,
    safety_state: object,
    hard_gate_state: object,
    diagnostic_codes: object,
    conflict_count: int,
) -> dict:
    """Derive confidence conservatively (meet + explicit caps).

    Multiple agents agreeing is never a boost: correlation is not an input
    here, and no rule raises confidence above the upstream minimum.
    """

    resolved_state = _text(state)
    reasons: list[str] = []
    levels: list[str] = []

    for level, reason in (
        (result_confidence, REASON_UPSTREAM_SPECIALIST_CONFIDENCE),
        (evidence_confidence, REASON_UPSTREAM_EVIDENCE_CONFIDENCE),
        (context_confidence, REASON_UPSTREAM_CONTEXT_CONFIDENCE),
    ):
        text = _text(level)
        if text in CONFIDENCE_LEVELS:
            levels.append(text)
            reasons.append(reason)

    if _text(status) not in ("", "UNKNOWN"):
        reasons.append(REASON_UPSTREAM_STATUS)

    base = min_confidence(*levels) if levels else CONFIDENCE_UNKNOWN
    if base == CONFIDENCE_UNKNOWN:
        reasons.append(REASON_NO_UPSTREAM_CONFIDENCE)

    caps: list[str] = [CONFIDENCE_HIGH]

    def apply_cap(level: str, reason: str) -> None:
        caps.append(level)
        if reason not in reasons:
            reasons.append(reason)

    if not evaluation_present:
        apply_cap(CONFIDENCE_MEDIUM, REASON_EVALUATION_UNAVAILABLE_CAP)
    else:
        if _text(safety_state) == "DEGRADED":
            apply_cap(CONFIDENCE_LOW, REASON_EVALUATION_SAFETY_CAP)
        if _text(hard_gate_state) in ("CEILING_STRUCTURAL", "CEILING_SAFETY"):
            apply_cap(CONFIDENCE_LOW, REASON_EVALUATION_QUALITY_CAP)
        if _text(evaluation_rating) in _RATING_WEAK:
            apply_cap(CONFIDENCE_LOW, REASON_EVALUATION_QUALITY_CAP)
        elif _text(evaluation_rating) == "ACCEPTABLE":
            apply_cap(CONFIDENCE_MEDIUM, REASON_EVALUATION_QUALITY_CAP)
        diagnostics = {
            _text(code) for code in (diagnostic_codes or ())
        }
        if "CONFIDENCE_OVERSTATED" in diagnostics:
            apply_cap(CONFIDENCE_LOW, REASON_EVALUATION_DIAGNOSTIC_CAP)
        elif diagnostics & set(_DIAGNOSTICS_MEDIUM_CAP):
            apply_cap(CONFIDENCE_MEDIUM, REASON_EVALUATION_DIAGNOSTIC_CAP)

    if _text(evidence_completeness) != COMPLETENESS_COMPLETE:
        apply_cap(CONFIDENCE_MEDIUM, REASON_UPSTREAM_EVIDENCE_STATE)
    if _text(evidence_state) == "UNKNOWN":
        apply_cap(CONFIDENCE_MEDIUM, REASON_UPSTREAM_EVIDENCE_STATE)
    if conflict_count > 0 or resolved_state == STATE_CONFLICTED:
        apply_cap(CONFIDENCE_MEDIUM, REASON_CONFLICT_CAP)
    if resolved_state == STATE_NEEDS_MORE_EVIDENCE:
        apply_cap(CONFIDENCE_LOW, REASON_EVIDENCE_PARTIAL_CAP)
    if resolved_state == STATE_INSUFFICIENT_EVIDENCE:
        apply_cap(CONFIDENCE_LOW, REASON_INSUFFICIENT_EVIDENCE_CAP)

    confidence = min_confidence(base, *caps)
    return {
        "confidence": confidence,
        "confidence_reasons": _ordered_reasons(reasons),
    }


__all__ = [
    "FINDING_STATE_RULE_VERSION",
    "RULE_VERSION",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_MEDIUM",
    "CONFIDENCE_LOW",
    "CONFIDENCE_UNKNOWN",
    "confidence_rank",
    "min_confidence",
    "derive_finding_state",
    "derive_finding_confidence",
]
