"""Stage R55.3 deterministic research-priority rules (pure engine).

Derives the bounded, explainable research-priority signals of one finding
candidate (R53 finding or R54 correlated finding reference):

    "Which research finding should be investigated first, and why?"

Hard boundaries encoded here:

- Research ordering only: priority is a research-value/ordering signal, never
  truth probability. ``priority`` is not ``confidence``: the upstream
  confidence is only one small bounded factor, a high priority never upgrades
  confidence and multiple agreeing findings never inflate it.
- Severity is never computed: only an explicit structured upstream CVSS
  context contributes; otherwise severity stays ``UNKNOWN`` with
  ``NOT_ASSESSED``. Category names are never converted into severity.
- Impact stays potential unless an explicit upstream observed impact state
  exists; business impact is never asserted.
- Correlation is context, not a boost: conflicts reduce and cap the score,
  duplicate relationships select one deterministic representative and reduce
  redundant research effort. Agreement alone never increases priority.
- Safety first: unsafe outputs are deferred by the builder before scoring;
  a learning signal demanding a safety boundary also defers.
- Documented arithmetic: every contribution is a documented constant; the
  score is a bounded 0-100 sum with explicit band caps and no opaque magic.
- Deterministic: identical candidates always produce identical factors,
  reasons, caps and scores.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  browser, no scanner, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.cve_research_context_analysis import (
    CVSS_CRITICAL_OBSERVED,
    CVSS_HIGH_OBSERVED,
    CVSS_LOW_OBSERVED,
    CVSS_MEDIUM_OBSERVED,
    CVSS_NONE_OBSERVED,
    CVSS_UNKNOWN,
)
from ai.schemas.finding_assessment import (
    CONFIRMATION_NOT_CONFIRMED,
    IMPACT_OBSERVED,
    IMPACT_POTENTIAL,
    IMPACT_UNKNOWN,
    SEVERITY_SOURCE_CVSS_CONTEXT,
    SEVERITY_SOURCE_NOT_ASSESSED,
    STATE_CONFIRMED_OBSERVED,
    STATE_CONFLICTED,
    STATE_EVIDENCE_SUPPORTED,
    STATE_INSUFFICIENT_EVIDENCE,
    STATE_NEEDS_MORE_EVIDENCE,
    STATE_RESEARCH_CANDIDATE,
)
from ai.schemas.finding_correlation import (
    RELATIONSHIP_CONFLICTING,
    RELATIONSHIP_DUPLICATE,
    RELATIONSHIP_INDEPENDENT,
    RELATIONSHIP_RELATED,
    RELATIONSHIP_UNKNOWN,
)
from ai.schemas.finding_evidence import (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_MISSING,
    COMPLETENESS_PARTIAL,
    COMPLETENESS_UNKNOWN,
)
from ai.schemas.learning_recommendation import (
    REC_CALIBRATE_CONFIDENCE,
    REC_DEDUPLICATE_HYPOTHESES,
    REC_IMPROVE_CONTEXT_CAPTURE,
    REC_PRESERVE_PROVENANCE,
    REC_PRESERVE_SUCCESSFUL_PATTERN,
    REC_PRIORITIZE_EVIDENCE_PLANNING,
    REC_REVIEW_GOVERNANCE_REFERENCES,
    REC_RESTORE_SAFETY_BOUNDARY,
    REC_STRENGTHEN_HYPOTHESES,
    REC_UNKNOWN,
    sanitize_learning_recommendation,
)
from ai.schemas.research_priority import (
    BAND_CAP_LOW,
    BAND_CAP_MEDIUM,
    CONTEXT_COMPLETE,
    CONTEXT_MISSING,
    CONTEXT_PARTIAL,
    CORRELATION_CONFLICTING,
    CORRELATION_DUPLICATE_REDUNDANT,
    CORRELATION_DUPLICATE_REPRESENTATIVE,
    CORRELATION_INDEPENDENT,
    CORRELATION_RELATED,
    CORRELATION_UNAVAILABLE,
    CORRELATION_UNKNOWN,
    FACTOR_CONFLICT_CONSTRAINT,
    FACTOR_CONTEXT_COMPLETENESS,
    FACTOR_CORRELATION_CONTEXT,
    FACTOR_EVIDENCE_COMPLETENESS,
    FACTOR_FINDING_STATE,
    FACTOR_GOVERNANCE_CONSTRAINT,
    FACTOR_IMPACT_SIGNAL,
    FACTOR_LEARNING_CONSTRAINT,
    FACTOR_LEARNING_SIGNAL,
    FACTOR_PROVENANCE_COMPLETENESS,
    FACTOR_SEVERITY_SIGNAL,
    FACTOR_UPSTREAM_CONFIDENCE,
    GOVERNANCE_NOT_READY,
    GOVERNANCE_READY,
    GOVERNANCE_READY_NOT_READY,
    GOVERNANCE_READY_READY,
    GOVERNANCE_READY_UNKNOWN,
    GOVERNANCE_UNKNOWN_VALUE,
    LEARNING_AVOID_DUPLICATION,
    LEARNING_CALIBRATE_CONFIDENCE,
    LEARNING_IMPROVE_CONTEXT,
    LEARNING_PRESERVE_PATTERN,
    LEARNING_REQUIRE_MORE_EVIDENCE,
    LEARNING_REVIEW_GOVERNANCE,
    LEARNING_REVIEW_PROVENANCE,
    LEARNING_SAFETY_BOUNDARY,
    LEARNING_STRENGTHEN_HYPOTHESES,
    LEARNING_UNAVAILABLE,
    LEARNING_UNRECOGNIZED,
    MAX_FACTOR_CONTRIBUTION,
    MAX_PRIORITY_SCORE,
    MAX_REASONS,
    MIN_FACTOR_CONTRIBUTION,
    PRIORITY_LIMITATIONS,
    PRIORITY_REASONS,
    PROVENANCE_COMPLETE,
    PROVENANCE_INCOMPLETE,
    PROVENANCE_PARTIAL,
    REASON_COMPLETE_EVIDENCE,
    REASON_CONFIRMED_OBSERVED_STATE,
    REASON_CONFLICTED_STATE,
    REASON_CONFLICT_REQUIRES_REVIEW,
    REASON_CORRELATION_UNAVAILABLE,
    REASON_CVSS_CONTEXT_AVAILABLE,
    REASON_DUPLICATE_RESEARCH_REDUCTION,
    REASON_DUPLICATE_REPRESENTATIVE,
    REASON_EVIDENCE_SUPPORTED_STATE,
    REASON_GOVERNANCE_LIMITATION,
    REASON_HIGH_UPSTREAM_CONFIDENCE,
    REASON_IMPACT_UNKNOWN,
    REASON_INDEPENDENT_FINDINGS,
    REASON_INSUFFICIENT_CONTEXT,
    REASON_INSUFFICIENT_EVIDENCE_STATE,
    REASON_LEARNING_SIGNAL_AVOID_DUPLICATION,
    REASON_LEARNING_SIGNAL_CALIBRATE_CONFIDENCE,
    REASON_LEARNING_SIGNAL_IMPROVE_CONTEXT,
    REASON_LEARNING_SIGNAL_PRESERVE_PATTERN,
    REASON_LEARNING_SIGNAL_REQUIRES_EVIDENCE,
    REASON_LEARNING_SIGNAL_REVIEW_GOVERNANCE,
    REASON_LEARNING_SIGNAL_REVIEW_PROVENANCE,
    REASON_LEARNING_SIGNAL_SAFETY_BOUNDARY,
    REASON_LEARNING_SIGNAL_STRENGTHEN_HYPOTHESIS,
    REASON_LEARNING_SIGNAL_UNRECOGNIZED,
    REASON_LEARNING_UNAVAILABLE,
    REASON_LOW_UPSTREAM_CONFIDENCE,
    REASON_MEDIUM_UPSTREAM_CONFIDENCE,
    REASON_MISSING_EVIDENCE,
    REASON_NEEDS_MORE_EVIDENCE,
    REASON_OBSERVED_IMPACT,
    REASON_PARTIAL_CONTEXT,
    REASON_PARTIAL_EVIDENCE,
    REASON_POTENTIAL_IMPACT,
    REASON_PROVENANCE_INCOMPLETE,
    REASON_RESEARCH_CANDIDATE_STATE,
    REASON_RELATED_FINDINGS_CONTEXT,
    REASON_SEVERITY_NOT_ASSESSED,
    REASON_STRONG_CONTEXT,
    REASON_UNKNOWN_CORRELATION,
    REASON_UNKNOWN_EVIDENCE,
    REASON_UNKNOWN_UPSTREAM_CONFIDENCE,
    REFERENCE_REFERENCED,
    SOURCE_KIND_FINDING,
    SOURCE_KIND_REFERENCE,
    band_for_score,
)
from ai.schemas.security_agent_identity import (
    AGENT_CATEGORIES,
    CATEGORY_UNKNOWN,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.finding_evidence import EVIDENCE_ORIGINS

RESEARCH_PRIORITY_RULES_RULE_VERSION = "r55-3"
RULE_VERSION = RESEARCH_PRIORITY_RULES_RULE_VERSION

SUPPORTED_CATEGORIES: tuple[str, ...] = tuple(
    category for category in AGENT_CATEGORIES if category != CATEGORY_UNKNOWN
)

#: Minimum observed context facts for a complete research context.
CONTEXT_COMPLETE_MIN_FACTS = 5

#: Score ceilings for constraint caps (one below the next band floor).
CAP_LOW_SCORE = 44
CAP_MEDIUM_SCORE = 64

CORRELATION_MAX_SOURCES = 8
CORRELATION_MAX_RELATIONSHIPS = 16

# ---------------------------------------------------------------------------
# Documented contribution tables (fixed, not runtime configurable)
# ---------------------------------------------------------------------------

EVIDENCE_CONTRIBUTIONS: dict[str, int] = {
    COMPLETENESS_COMPLETE: 25,
    COMPLETENESS_PARTIAL: 12,
    COMPLETENESS_MISSING: 0,
    COMPLETENESS_UNKNOWN: 0,
}

CONTEXT_CONTRIBUTIONS: dict[str, int] = {
    CONTEXT_COMPLETE: 10,
    CONTEXT_PARTIAL: 5,
    CONTEXT_MISSING: 0,
}

STATE_CONTRIBUTIONS: dict[str, int] = {
    STATE_CONFIRMED_OBSERVED: 20,
    STATE_EVIDENCE_SUPPORTED: 16,
    STATE_RESEARCH_CANDIDATE: 12,
    STATE_NEEDS_MORE_EVIDENCE: 10,
    STATE_CONFLICTED: 4,
    STATE_INSUFFICIENT_EVIDENCE: 0,
}

CONFIDENCE_CONTRIBUTIONS: dict[str, int] = {
    "HIGH": 12,
    "MEDIUM": 8,
    "LOW": 4,
    "UNKNOWN": 0,
}

IMPACT_CONTRIBUTIONS: dict[str, int] = {
    IMPACT_OBSERVED: 10,
    IMPACT_POTENTIAL: 6,
    IMPACT_UNKNOWN: 0,
}

SEVERITY_CONTRIBUTIONS: dict[str, int] = {
    CVSS_CRITICAL_OBSERVED: 8,
    CVSS_HIGH_OBSERVED: 6,
    CVSS_MEDIUM_OBSERVED: 4,
    CVSS_LOW_OBSERVED: 2,
    CVSS_NONE_OBSERVED: 1,
    CVSS_UNKNOWN: 0,
}

#: Correlation is context/penalty only: relatedness or independent agreement
#: never boosts priority (multiple agreeing findings are not independent
#: evidence), while conflicts reduce it and redundant duplicates lose the
#: research-efficiency race against their deterministic representative.
CORRELATION_CONTRIBUTIONS: dict[str, int] = {
    CORRELATION_CONFLICTING: -10,
    CORRELATION_DUPLICATE_REDUNDANT: -6,
    CORRELATION_DUPLICATE_REPRESENTATIVE: 0,
    CORRELATION_RELATED: 0,
    CORRELATION_INDEPENDENT: 0,
    CORRELATION_UNKNOWN: 0,
    CORRELATION_UNAVAILABLE: 0,
}

LEARNING_CONTRIBUTIONS: dict[str, int] = {
    LEARNING_REQUIRE_MORE_EVIDENCE: 4,
    LEARNING_STRENGTHEN_HYPOTHESES: 4,
    LEARNING_AVOID_DUPLICATION: -3,
    LEARNING_REVIEW_GOVERNANCE: 0,
    LEARNING_REVIEW_PROVENANCE: 0,
    LEARNING_SAFETY_BOUNDARY: 0,
    LEARNING_PRESERVE_PATTERN: 0,
    LEARNING_CALIBRATE_CONFIDENCE: 0,
    LEARNING_IMPROVE_CONTEXT: 0,
    LEARNING_UNRECOGNIZED: 0,
    LEARNING_UNAVAILABLE: 0,
}

PROVENANCE_CONTRIBUTIONS: dict[str, int] = {
    PROVENANCE_COMPLETE: 4,
    PROVENANCE_PARTIAL: 2,
    PROVENANCE_INCOMPLETE: 0,
}

#: Higher rank wins in duplicate-representative selection.
EVIDENCE_RANK: dict[str, int] = {
    COMPLETENESS_COMPLETE: 3,
    COMPLETENESS_PARTIAL: 2,
    COMPLETENESS_UNKNOWN: 1,
    COMPLETENESS_MISSING: 0,
}

CONFIDENCE_RANK: dict[str, int] = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}

GOVERNANCE_RANK: dict[str, int] = {
    GOVERNANCE_READY_UNKNOWN: 0,
    GOVERNANCE_READY_NOT_READY: 1,
    GOVERNANCE_READY_READY: 2,
}

EVIDENCE_STATE_REASONS: dict[str, str] = {
    COMPLETENESS_COMPLETE: REASON_COMPLETE_EVIDENCE,
    COMPLETENESS_PARTIAL: REASON_PARTIAL_EVIDENCE,
    COMPLETENESS_MISSING: REASON_MISSING_EVIDENCE,
    COMPLETENESS_UNKNOWN: REASON_UNKNOWN_EVIDENCE,
}

CONTEXT_REASONS: dict[str, str] = {
    CONTEXT_COMPLETE: REASON_STRONG_CONTEXT,
    CONTEXT_PARTIAL: REASON_PARTIAL_CONTEXT,
    CONTEXT_MISSING: REASON_INSUFFICIENT_CONTEXT,
}

STATE_REASONS: dict[str, str] = {
    STATE_CONFIRMED_OBSERVED: REASON_CONFIRMED_OBSERVED_STATE,
    STATE_EVIDENCE_SUPPORTED: REASON_EVIDENCE_SUPPORTED_STATE,
    STATE_RESEARCH_CANDIDATE: REASON_RESEARCH_CANDIDATE_STATE,
    STATE_NEEDS_MORE_EVIDENCE: REASON_NEEDS_MORE_EVIDENCE,
    STATE_CONFLICTED: REASON_CONFLICTED_STATE,
    STATE_INSUFFICIENT_EVIDENCE: REASON_INSUFFICIENT_EVIDENCE_STATE,
}

CONFIDENCE_REASONS: dict[str, str] = {
    "HIGH": REASON_HIGH_UPSTREAM_CONFIDENCE,
    "MEDIUM": REASON_MEDIUM_UPSTREAM_CONFIDENCE,
    "LOW": REASON_LOW_UPSTREAM_CONFIDENCE,
    "UNKNOWN": REASON_UNKNOWN_UPSTREAM_CONFIDENCE,
}

IMPACT_REASONS: dict[str, str] = {
    IMPACT_OBSERVED: REASON_OBSERVED_IMPACT,
    IMPACT_POTENTIAL: REASON_POTENTIAL_IMPACT,
    IMPACT_UNKNOWN: REASON_IMPACT_UNKNOWN,
}

CORRELATION_REASONS: dict[str, str] = {
    CORRELATION_CONFLICTING: REASON_CONFLICT_REQUIRES_REVIEW,
    CORRELATION_DUPLICATE_REDUNDANT: REASON_DUPLICATE_RESEARCH_REDUCTION,
    CORRELATION_DUPLICATE_REPRESENTATIVE: REASON_DUPLICATE_REPRESENTATIVE,
    CORRELATION_RELATED: REASON_RELATED_FINDINGS_CONTEXT,
    CORRELATION_INDEPENDENT: REASON_INDEPENDENT_FINDINGS,
    CORRELATION_UNKNOWN: REASON_UNKNOWN_CORRELATION,
    CORRELATION_UNAVAILABLE: REASON_CORRELATION_UNAVAILABLE,
}

#: R44 recommendation type -> (factor value, contribution, reason).
LEARNING_SIGNAL_MAP: dict[str, tuple[str, int, str]] = {
    REC_RESTORE_SAFETY_BOUNDARY: (
        LEARNING_SAFETY_BOUNDARY,
        LEARNING_CONTRIBUTIONS[LEARNING_SAFETY_BOUNDARY],
        REASON_LEARNING_SIGNAL_SAFETY_BOUNDARY,
    ),
    REC_REVIEW_GOVERNANCE_REFERENCES: (
        LEARNING_REVIEW_GOVERNANCE,
        LEARNING_CONTRIBUTIONS[LEARNING_REVIEW_GOVERNANCE],
        REASON_LEARNING_SIGNAL_REVIEW_GOVERNANCE,
    ),
    REC_PRIORITIZE_EVIDENCE_PLANNING: (
        LEARNING_REQUIRE_MORE_EVIDENCE,
        LEARNING_CONTRIBUTIONS[LEARNING_REQUIRE_MORE_EVIDENCE],
        REASON_LEARNING_SIGNAL_REQUIRES_EVIDENCE,
    ),
    REC_STRENGTHEN_HYPOTHESES: (
        LEARNING_STRENGTHEN_HYPOTHESES,
        LEARNING_CONTRIBUTIONS[LEARNING_STRENGTHEN_HYPOTHESES],
        REASON_LEARNING_SIGNAL_STRENGTHEN_HYPOTHESIS,
    ),
    REC_DEDUPLICATE_HYPOTHESES: (
        LEARNING_AVOID_DUPLICATION,
        LEARNING_CONTRIBUTIONS[LEARNING_AVOID_DUPLICATION],
        REASON_LEARNING_SIGNAL_AVOID_DUPLICATION,
    ),
    REC_CALIBRATE_CONFIDENCE: (
        LEARNING_CALIBRATE_CONFIDENCE,
        LEARNING_CONTRIBUTIONS[LEARNING_CALIBRATE_CONFIDENCE],
        REASON_LEARNING_SIGNAL_CALIBRATE_CONFIDENCE,
    ),
    REC_IMPROVE_CONTEXT_CAPTURE: (
        LEARNING_IMPROVE_CONTEXT,
        LEARNING_CONTRIBUTIONS[LEARNING_IMPROVE_CONTEXT],
        REASON_LEARNING_SIGNAL_IMPROVE_CONTEXT,
    ),
    REC_PRESERVE_PROVENANCE: (
        LEARNING_REVIEW_PROVENANCE,
        LEARNING_CONTRIBUTIONS[LEARNING_REVIEW_PROVENANCE],
        REASON_LEARNING_SIGNAL_REVIEW_PROVENANCE,
    ),
    REC_PRESERVE_SUCCESSFUL_PATTERN: (
        LEARNING_PRESERVE_PATTERN,
        LEARNING_CONTRIBUTIONS[LEARNING_PRESERVE_PATTERN],
        REASON_LEARNING_SIGNAL_PRESERVE_PATTERN,
    ),
    REC_UNKNOWN: (
        LEARNING_UNRECOGNIZED,
        LEARNING_CONTRIBUTIONS[LEARNING_UNRECOGNIZED],
        REASON_LEARNING_SIGNAL_UNRECOGNIZED,
    ),
}

#: Highest-precedence first: the factor value uses the first present signal.
LEARNING_SIGNAL_PRECEDENCE: tuple[str, ...] = (
    REC_RESTORE_SAFETY_BOUNDARY,
    REC_REVIEW_GOVERNANCE_REFERENCES,
    REC_PRIORITIZE_EVIDENCE_PLANNING,
    REC_STRENGTHEN_HYPOTHESES,
    REC_DEDUPLICATE_HYPOTHESES,
    REC_CALIBRATE_CONFIDENCE,
    REC_IMPROVE_CONTEXT_CAPTURE,
    REC_PRESERVE_PROVENANCE,
    REC_PRESERVE_SUCCESSFUL_PATTERN,
    REC_UNKNOWN,
)

_CONSTRAINT_ORDER: dict[str, int] = {
    FACTOR_GOVERNANCE_CONSTRAINT: 0,
    FACTOR_CONFLICT_CONSTRAINT: 1,
    FACTOR_LEARNING_CONSTRAINT: 2,
}

_BASE_LIMITATIONS: tuple[str, ...] = (
    "NO_EXECUTION_PERFORMED",
    "NO_NETWORK_REQUESTS",
    "NO_VULNERABILITY_CONFIRMATION",
    "NO_EXPLOIT_GENERATION",
    "RESEARCH_ONLY",
    "PRIORITY_NOT_CONFIDENCE",
    "CONFIDENCE_NOT_UPGRADED",
    "NOT_CONFIRMED",
    "PRIORITY_RANKING_ONLY",
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _ordered_reasons(reasons: list[str]) -> list[str]:
    found = set(reasons)
    return [code for code in PRIORITY_REASONS if code in found][:MAX_REASONS]


# ---------------------------------------------------------------------------
# Candidate normalization
# ---------------------------------------------------------------------------


def _common_candidate(
    *,
    finding_id: str,
    category: str,
    specialist_name: str,
    agent_id: str,
    state: str,
    confidence: str,
    evidence_state: str,
    evidence_completeness: str,
    evidence_origin: str,
    context_fact_count: int,
    hypothesis_count: int,
    evidence_requirement_count: int,
    severity: str,
    severity_source: str,
    impact_state: str,
    impact_confidence: str,
    orchestration_id: str,
    governance_reference_state: str,
    governance_ready_state: str,
    governance_rule_version: str,
    finding_rule_version: str,
    source_stages: list[str],
    learning_recommendations: list[dict],
    embedded_conflict_count: int,
    source_kind: str,
    evaluation_rating: str = "",
    hard_gate_state: str = "",
    safety_state: str = "UNKNOWN",
) -> dict:
    if state not in STATE_CONTRIBUTIONS:
        state = STATE_INSUFFICIENT_EVIDENCE
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    if evidence_state not in ("COMPLETE", "PARTIAL", "UNKNOWN"):
        evidence_state = "UNKNOWN"
    if evidence_completeness not in EVIDENCE_CONTRIBUTIONS:
        evidence_completeness = COMPLETENESS_UNKNOWN
    if evidence_origin not in EVIDENCE_ORIGINS:
        evidence_origin = "UNKNOWN"
    if severity_source not in (
        SEVERITY_SOURCE_CVSS_CONTEXT,
        SEVERITY_SOURCE_NOT_ASSESSED,
    ):
        severity_source = SEVERITY_SOURCE_NOT_ASSESSED
    if severity not in SEVERITY_CONTRIBUTIONS:
        severity = CVSS_UNKNOWN
    if impact_state not in IMPACT_CONTRIBUTIONS:
        impact_state = IMPACT_UNKNOWN
    if impact_confidence not in CONFIDENCE_LEVELS:
        impact_confidence = "UNKNOWN"
    return {
        "finding_id": finding_id,
        "category": category,
        "specialist_name": specialist_name,
        "agent_id": agent_id,
        "state": state,
        "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
        "confidence": confidence,
        "evidence_state": evidence_state,
        "evidence_completeness": evidence_completeness,
        "evidence_origin": evidence_origin,
        "context_fact_count": _bounded_int(context_fact_count, 0, 64),
        "hypothesis_count": _bounded_int(hypothesis_count, 0, 64),
        "evidence_requirement_count": _bounded_int(
            evidence_requirement_count, 0, 64
        ),
        "severity": severity,
        "severity_source": severity_source,
        "impact_state": impact_state,
        "impact_confidence": impact_confidence,
        "orchestration_id": orchestration_id,
        "governance_reference_state": governance_reference_state,
        "governance_ready_state": governance_ready_state,
        "governance_rule_version": governance_rule_version,
        "finding_rule_version": finding_rule_version,
        "source_stages": list(source_stages),
        "learning_recommendations": list(learning_recommendations),
        "embedded_conflict_count": _bounded_int(
            embedded_conflict_count, 0, 64
        ),
        "source_kind": source_kind,
        "evaluation_rating": evaluation_rating,
        "hard_gate_state": hard_gate_state,
        "safety_state": safety_state,
    }


def finding_candidate(finding: object) -> dict:
    """Normalize one sanitized R53 finding into a priority candidate.

    Read-only: no value is inferred and no input is mutated.
    """

    if not isinstance(finding, dict):
        finding = {}
    identity = finding.get("identity") or {}
    assessment = finding.get("assessment") or {}
    evidence = finding.get("evidence") or {}
    context = finding.get("context") or {}
    hypotheses = finding.get("hypotheses") or {}
    correlation = finding.get("correlation") or {}
    provenance = finding.get("provenance") or {}
    governance = finding.get("governance") or {}

    context_fact_count = context.get("context_fact_count")
    if isinstance(context_fact_count, bool) or not isinstance(
        context_fact_count, int
    ):
        context_fact_count = len(context.get("affected_context") or ())

    planned = list(evidence.get("planned_requirements") or ())
    merged = [
        _upper(item.get("evidence_category"))
        for item in evidence.get("merged_requirements") or ()
        if isinstance(item, dict)
    ]
    requirement_count = len({item for item in planned if item} | set(merged))

    ready_state = GOVERNANCE_READY_UNKNOWN
    if _upper(governance.get("reference_state")) == REFERENCE_REFERENCED:
        ready_state = (
            GOVERNANCE_READY_READY
            if governance.get("ready") is True
            else GOVERNANCE_READY_NOT_READY
        )

    return _common_candidate(
        finding_id=_text(identity.get("finding_id")),
        category=_upper(identity.get("category")),
        specialist_name=_text(identity.get("specialist_name")),
        agent_id=_text(identity.get("agent_id")),
        state=_upper(finding.get("state")) or _upper(assessment.get("state")),
        confidence=_upper(assessment.get("confidence")) or "UNKNOWN",
        evidence_state=_upper(evidence.get("evidence_state")) or "UNKNOWN",
        evidence_completeness=_upper(
            evidence.get("evidence_completeness")
        )
        or COMPLETENESS_UNKNOWN,
        evidence_origin=_upper(evidence.get("evidence_origin")) or "UNKNOWN",
        context_fact_count=_bounded_int(context_fact_count, 0, 64),
        hypothesis_count=hypotheses.get("hypothesis_count") or 0,
        evidence_requirement_count=requirement_count,
        severity=_upper(assessment.get("severity")) or CVSS_UNKNOWN,
        severity_source=_upper(assessment.get("severity_source"))
        or SEVERITY_SOURCE_NOT_ASSESSED,
        impact_state=_upper(assessment.get("impact_state"))
        or IMPACT_UNKNOWN,
        impact_confidence=_upper(assessment.get("impact_confidence"))
        or "UNKNOWN",
        orchestration_id=_text(provenance.get("orchestration_id")),
        governance_reference_state=(
            _upper(governance.get("reference_state")) or "UNKNOWN"
        ),
        governance_ready_state=ready_state,
        governance_rule_version=_text(governance.get("rule_version")),
        finding_rule_version=_text(finding.get("rule_version")),
        source_stages=[
            _text(stage) for stage in provenance.get("source_stages") or ()
        ],
        learning_recommendations=[
            item
            for item in finding.get("learning_recommendations") or ()
            if isinstance(item, dict)
        ],
        embedded_conflict_count=len(correlation.get("conflicts") or ()),
        source_kind=SOURCE_KIND_FINDING,
        evaluation_rating=_upper(assessment.get("evaluation_rating")),
        hard_gate_state=_upper(assessment.get("hard_gate_state")),
        safety_state=_upper(assessment.get("safety_state")) or "UNKNOWN",
    )


def reference_candidate(reference: object) -> dict:
    """Normalize one sanitized R54 finding reference into a candidate.

    R54 references do not carry assessment-level impact or severity; both stay
    explicitly ``UNKNOWN``/``NOT_ASSESSED`` and are never inferred.
    """

    if not isinstance(reference, dict):
        reference = {}
    return _common_candidate(
        finding_id=_text(reference.get("finding_id")),
        category=_upper(reference.get("category")),
        specialist_name=_text(reference.get("specialist_name")),
        agent_id=_text(reference.get("agent_id")),
        state=_upper(reference.get("state")),
        confidence=_upper(reference.get("confidence")) or "UNKNOWN",
        evidence_state=_upper(reference.get("evidence_state")) or "UNKNOWN",
        evidence_completeness=_upper(
            reference.get("evidence_completeness")
        )
        or COMPLETENESS_UNKNOWN,
        evidence_origin=_upper(reference.get("evidence_origin"))
        or "UNKNOWN",
        context_fact_count=reference.get("context_fact_count") or 0,
        hypothesis_count=reference.get("hypothesis_count") or 0,
        evidence_requirement_count=(
            reference.get("evidence_requirement_count") or 0
        ),
        severity=CVSS_UNKNOWN,
        severity_source=SEVERITY_SOURCE_NOT_ASSESSED,
        impact_state=IMPACT_UNKNOWN,
        impact_confidence="UNKNOWN",
        orchestration_id=_text(reference.get("orchestration_id")),
        governance_reference_state=(
            _upper(reference.get("governance_state")) or "UNKNOWN"
        ),
        governance_ready_state=GOVERNANCE_READY_UNKNOWN,
        governance_rule_version="",
        finding_rule_version=_text(reference.get("finding_rule_version")),
        source_stages=[],
        learning_recommendations=[],
        embedded_conflict_count=0,
        source_kind=SOURCE_KIND_REFERENCE,
        evaluation_rating="",
        hard_gate_state="",
        safety_state="UNKNOWN",
    )


# ---------------------------------------------------------------------------
# Correlation context
# ---------------------------------------------------------------------------


def _relationship_types(relationships: list[dict]) -> list[str]:
    found = {
        _upper(item.get("relationship_type")) for item in relationships
    }
    return [
        relationship_type
        for relationship_type in (
            RELATIONSHIP_CONFLICTING,
            RELATIONSHIP_DUPLICATE,
            RELATIONSHIP_RELATED,
            RELATIONSHIP_INDEPENDENT,
            RELATIONSHIP_UNKNOWN,
        )
        if relationship_type in found
    ]


def duplicate_preference(candidate: dict) -> tuple:
    """Deterministic duplicate-representative quality preference (higher wins).

    Preference order: strongest available evidence, most complete context,
    upstream confidence, governance readiness, then provenance completeness.
    The stable finding id breaks a full tie in
    :func:`duplicate_representative`. List position is never used.
    """

    evidence_rank = EVIDENCE_RANK.get(
        _upper(candidate.get("evidence_completeness")), 0
    )
    context_rank = _bounded_int(candidate.get("context_fact_count"), 0, 64)
    confidence_rank = CONFIDENCE_RANK.get(
        _upper(candidate.get("confidence")), 0
    )
    governance_rank = GOVERNANCE_RANK.get(
        _upper(candidate.get("governance_ready_state")), 0
    )
    provenance_rank = (
        len(PROVENANCE_CONTRIBUTIONS)
        - 1
        - list(PROVENANCE_CONTRIBUTIONS).index(
            provenance_class(candidate)
        )
    )
    return (
        evidence_rank,
        context_rank,
        confidence_rank,
        governance_rank,
        provenance_rank,
    )


def duplicate_representative(candidate: dict, peer: dict) -> bool:
    """True when ``candidate`` deterministically represents ``peer``.

    Quality metrics decide first; on a full tie the lexicographically smaller
    stable finding id wins, matching the ranking tie-break.
    """

    candidate_key = duplicate_preference(candidate)
    peer_key = duplicate_preference(peer)
    if candidate_key != peer_key:
        return candidate_key > peer_key
    return _text(candidate.get("finding_id")) < _text(peer.get("finding_id"))


def _duplicate_redundant(
    finding_id: str, relationships: list[dict], by_id: dict
) -> bool:
    for relationship in relationships:
        if _upper(relationship.get("relationship_type")) != (
            RELATIONSHIP_DUPLICATE
        ):
            continue
        source = _text(relationship.get("source_finding_id"))
        target = _text(relationship.get("target_finding_id"))
        other = target if source == finding_id else source
        peer = by_id.get(other)
        if peer is None:
            continue
        if not duplicate_representative(by_id[finding_id], peer):
            return True
    return False


def build_correlation_contexts(
    candidates: list[dict],
    relationships: list[dict],
    clusters: list[dict],
    correlation_present: bool,
) -> tuple[dict[str, dict], list[str]]:
    """Build the per-candidate correlation context (read-only).

    Returns the context map and the sorted ids of relationship endpoints that
    are not part of the candidate set (structured mismatch, never guessed).
    """

    by_id = {
        _text(candidate.get("finding_id")): candidate
        for candidate in candidates
    }
    relationships_by_finding: dict[str, list[dict]] = {}
    unmatched: set[str] = set()
    for relationship in relationships:
        source = _text(relationship.get("source_finding_id"))
        target = _text(relationship.get("target_finding_id"))
        for finding_id, other in ((source, target), (target, source)):
            if not finding_id:
                continue
            if finding_id in by_id:
                relationships_by_finding.setdefault(finding_id, []).append(
                    relationship
                )
                if other and other not in by_id:
                    unmatched.add(other)
            elif other in by_id:
                unmatched.add(finding_id)

    duplicate_cluster_sizes: dict[str, int] = {}
    for cluster in clusters:
        if _upper(cluster.get("relationship_type")) != (
            RELATIONSHIP_DUPLICATE
        ):
            continue
        size = cluster.get("cluster_size")
        if isinstance(size, bool) or not isinstance(size, int):
            size = len(cluster.get("member_finding_ids") or ())
        for member in cluster.get("member_finding_ids") or ():
            member_id = _text(member)
            if member_id:
                duplicate_cluster_sizes[member_id] = max(
                    duplicate_cluster_sizes.get(member_id, 0),
                    _bounded_int(size, 0, 64),
                )

    contexts: dict[str, dict] = {}
    for candidate in candidates:
        finding_id = _text(candidate.get("finding_id"))
        relationships_for = relationships_by_finding.get(finding_id, [])
        relationship_types = _relationship_types(relationships_for)
        conflict_sources: list[str] = []
        relationship_ids: list[str] = []
        for relationship in relationships_for:
            relationship_id = _text(relationship.get("relationship_id"))
            if relationship_id and relationship_id not in relationship_ids:
                relationship_ids.append(relationship_id)
            if (
                _upper(relationship.get("relationship_type"))
                != RELATIONSHIP_CONFLICTING
            ):
                continue
            source = _text(relationship.get("source_finding_id"))
            target = _text(relationship.get("target_finding_id"))
            other = target if source == finding_id else source
            if other and other not in conflict_sources:
                conflict_sources.append(other)
        contexts[finding_id] = {
            "present": bool(correlation_present),
            "relationship_types": relationship_types,
            "conflict_count": relationship_types.count(
                RELATIONSHIP_CONFLICTING
            ),
            "duplicate_count": relationship_types.count(
                RELATIONSHIP_DUPLICATE
            ),
            "related_count": relationship_types.count(RELATIONSHIP_RELATED),
            "independent_count": relationship_types.count(
                RELATIONSHIP_INDEPENDENT
            ),
            "unknown_count": relationship_types.count(
                RELATIONSHIP_UNKNOWN
            ),
            "embedded_conflict_count": _bounded_int(
                candidate.get("embedded_conflict_count"), 0, 64
            ),
            "duplicate_cluster_size": duplicate_cluster_sizes.get(
                finding_id, 0
            ),
            "conflict_sources": sorted(conflict_sources)[
                :CORRELATION_MAX_SOURCES
            ],
            "relationship_ids": relationship_ids[
                :CORRELATION_MAX_RELATIONSHIPS
            ],
            "duplicate_redundant": _duplicate_redundant(
                finding_id, relationships_for, by_id
            ),
        }
    return contexts, sorted(unmatched)


def empty_correlation_context() -> dict:
    """Correlation context used when no R54 result was supplied."""

    return {
        "present": False,
        "relationship_types": [],
        "conflict_count": 0,
        "duplicate_count": 0,
        "related_count": 0,
        "independent_count": 0,
        "unknown_count": 0,
        "embedded_conflict_count": 0,
        "duplicate_cluster_size": 0,
        "conflict_sources": [],
        "relationship_ids": [],
        "duplicate_redundant": False,
    }


# ---------------------------------------------------------------------------
# Learning context
# ---------------------------------------------------------------------------


def learning_recommendations_for(
    candidate: dict, learning_result: object = None
) -> list[dict]:
    """Merge the candidate's R44 recommendations with matched container ones.

    The candidate's own recommendations are preserved; recommendations from an
    optional R44/R52 learning container are added only when their
    ``related_agent`` matches the candidate agent (and category, when set).
    No learning memory is modified and nothing is invented.
    """

    merged: list[dict] = []
    for item in candidate.get("learning_recommendations") or ():
        projected = sanitize_learning_recommendation(item)
        if projected and projected not in merged:
            merged.append(projected)
    if not isinstance(learning_result, dict):
        return merged
    agent_id = _text(candidate.get("agent_id"))
    category = _upper(candidate.get("category"))
    if not agent_id:
        return merged
    for item in learning_result.get("recommendations") or ():
        projected = sanitize_learning_recommendation(item)
        if not projected:
            continue
        if _text(projected.get("related_agent")) != agent_id:
            continue
        related_category = _upper(projected.get("related_category"))
        if related_category not in ("", "UNKNOWN", category):
            continue
        if projected not in merged:
            merged.append(projected)
    return merged


def learning_deferral(recommendations: list[dict]) -> bool:
    """True when an R44 safety-boundary signal defers the finding."""

    return any(
        _upper(item.get("recommendation_type"))
        == REC_RESTORE_SAFETY_BOUNDARY
        for item in recommendations
    )


def learning_review_governance(recommendations: list[dict]) -> bool:
    """True when an R44 governance-review signal constrains the finding."""

    return any(
        _upper(item.get("recommendation_type"))
        == REC_REVIEW_GOVERNANCE_REFERENCES
        for item in recommendations
    )


def _learning_factor(recommendations: list[dict]) -> tuple[dict, list[str]]:
    types: list[str] = []
    for recommendation_type in LEARNING_SIGNAL_PRECEDENCE:
        if any(
            _upper(item.get("recommendation_type")) == recommendation_type
            for item in recommendations
        ):
            types.append(recommendation_type)
    if not types:
        return (
            {
                "factor": FACTOR_LEARNING_SIGNAL,
                "value": LEARNING_UNAVAILABLE,
                "contribution": LEARNING_CONTRIBUTIONS[
                    LEARNING_UNAVAILABLE
                ],
            },
            [REASON_LEARNING_UNAVAILABLE],
        )
    value, contribution, _ = LEARNING_SIGNAL_MAP[types[0]]
    reasons = [LEARNING_SIGNAL_MAP[item][2] for item in types]
    return (
        {
            "factor": FACTOR_LEARNING_SIGNAL,
            "value": value,
            "contribution": contribution,
        },
        reasons,
    )


# ---------------------------------------------------------------------------
# Classifications
# ---------------------------------------------------------------------------


def context_class(candidate: dict) -> str:
    """Deterministic context class from the observed fact count."""

    facts = _bounded_int(candidate.get("context_fact_count"), 0, 64)
    if facts >= CONTEXT_COMPLETE_MIN_FACTS:
        return CONTEXT_COMPLETE
    if facts >= 1:
        return CONTEXT_PARTIAL
    return CONTEXT_MISSING


def provenance_class(candidate: dict) -> str:
    """Deterministic provenance class from structured reference presence."""

    signals = (
        _text(candidate.get("orchestration_id")),
        _text(candidate.get("agent_id")),
        _text(candidate.get("category")),
        _text(candidate.get("finding_rule_version")),
    )
    present = sum(1 for signal in signals if signal)
    if present == len(signals):
        return PROVENANCE_COMPLETE
    if present:
        return PROVENANCE_PARTIAL
    return PROVENANCE_INCOMPLETE


def governance_class(candidate: dict) -> str:
    """Deterministic governance class (referenced/not-ready/unknown)."""

    if _upper(candidate.get("governance_reference_state")) != (
        REFERENCE_REFERENCED
    ):
        return GOVERNANCE_UNKNOWN_VALUE
    if _upper(candidate.get("governance_ready_state")) == (
        GOVERNANCE_READY_NOT_READY
    ):
        return GOVERNANCE_NOT_READY
    return GOVERNANCE_READY


def _severity_class(candidate: dict) -> str:
    if _upper(candidate.get("severity_source")) != (
        SEVERITY_SOURCE_CVSS_CONTEXT
    ):
        return CVSS_UNKNOWN
    severity = _upper(candidate.get("severity"))
    if severity not in SEVERITY_CONTRIBUTIONS:
        return CVSS_UNKNOWN
    return severity


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _correlation_value(correlation: dict) -> str:
    relationship_types = correlation.get("relationship_types") or []
    if correlation.get("conflict_count") or correlation.get(
        "embedded_conflict_count"
    ):
        return CORRELATION_CONFLICTING
    if RELATIONSHIP_DUPLICATE in relationship_types:
        if correlation.get("duplicate_redundant"):
            return CORRELATION_DUPLICATE_REDUNDANT
        return CORRELATION_DUPLICATE_REPRESENTATIVE
    if RELATIONSHIP_RELATED in relationship_types:
        return CORRELATION_RELATED
    if RELATIONSHIP_INDEPENDENT in relationship_types:
        return CORRELATION_INDEPENDENT
    if RELATIONSHIP_UNKNOWN in relationship_types:
        return CORRELATION_UNKNOWN
    if correlation.get("present"):
        return CORRELATION_UNKNOWN
    return CORRELATION_UNAVAILABLE


def _correlation_reasons(correlation: dict) -> list[str]:
    reasons: list[str] = []
    value = _correlation_value(correlation)
    reasons.append(CORRELATION_REASONS[value])
    if not correlation.get("present"):
        reasons.append(REASON_CORRELATION_UNAVAILABLE)
    if value != CORRELATION_UNKNOWN and correlation.get("unknown_count"):
        reasons.append(REASON_UNKNOWN_CORRELATION)
    if (
        value == CORRELATION_DUPLICATE_REPRESENTATIVE
        and correlation.get("duplicate_count", 0) > 1
    ):
        reasons.append(REASON_DUPLICATE_RESEARCH_REDUCTION)
    return reasons


def _governance_constraint(governance: str) -> tuple | None:
    if governance == GOVERNANCE_NOT_READY:
        return (
            CAP_LOW_SCORE,
            FACTOR_GOVERNANCE_CONSTRAINT,
            BAND_CAP_LOW,
            REASON_GOVERNANCE_LIMITATION,
        )
    if governance == GOVERNANCE_UNKNOWN_VALUE:
        return (
            CAP_MEDIUM_SCORE,
            FACTOR_GOVERNANCE_CONSTRAINT,
            BAND_CAP_MEDIUM,
            REASON_GOVERNANCE_LIMITATION,
        )
    return None


def _active_constraints(
    candidate: dict,
    correlation: dict,
    recommendations: list[dict],
) -> list[tuple]:
    constraints: list[tuple] = []
    governance = _governance_constraint(governance_class(candidate))
    if governance:
        constraints.append(governance)
    if correlation.get("conflict_count") or correlation.get(
        "embedded_conflict_count"
    ):
        constraints.append(
            (
                CAP_MEDIUM_SCORE,
                FACTOR_CONFLICT_CONSTRAINT,
                BAND_CAP_MEDIUM,
                REASON_CONFLICT_REQUIRES_REVIEW,
            )
        )
    if learning_review_governance(recommendations):
        constraints.append(
            (
                CAP_MEDIUM_SCORE,
                FACTOR_LEARNING_CONSTRAINT,
                BAND_CAP_MEDIUM,
                REASON_LEARNING_SIGNAL_REVIEW_GOVERNANCE,
            )
        )
    constraints.sort(
        key=lambda item: (item[0], _CONSTRAINT_ORDER.get(item[1], 99))
    )
    return constraints


def evaluate_candidate(
    candidate: dict,
    correlation: dict,
    recommendations: list[dict],
) -> dict:
    """Compute the bounded, explainable priority of one eligible candidate.

    The score is the clamped sum of documented factor contributions; explicit
    band caps are applied in deterministic order and each cap is exposed as
    its own negative adjustment factor so the contributions always sum to the
    reported score.
    """

    # Embedded R43 conflicts travel on the finding; mirror them into the
    # correlation context without mutating the supplied context.
    correlation = dict(correlation)
    correlation["embedded_conflict_count"] = max(
        _bounded_int(correlation.get("embedded_conflict_count"), 0, 64),
        _bounded_int(candidate.get("embedded_conflict_count"), 0, 64),
    )

    factors: list[dict] = []
    reasons: list[str] = []

    completeness = _upper(candidate.get("evidence_completeness"))
    if completeness not in EVIDENCE_CONTRIBUTIONS:
        completeness = COMPLETENESS_UNKNOWN
    factors.append(
        {
            "factor": FACTOR_EVIDENCE_COMPLETENESS,
            "value": completeness,
            "contribution": EVIDENCE_CONTRIBUTIONS[completeness],
        }
    )
    reasons.append(EVIDENCE_STATE_REASONS[completeness])

    context = context_class(candidate)
    factors.append(
        {
            "factor": FACTOR_CONTEXT_COMPLETENESS,
            "value": context,
            "contribution": CONTEXT_CONTRIBUTIONS[context],
        }
    )
    reasons.append(CONTEXT_REASONS[context])

    state = _upper(candidate.get("state"))
    if state not in STATE_CONTRIBUTIONS:
        state = STATE_INSUFFICIENT_EVIDENCE
    factors.append(
        {
            "factor": FACTOR_FINDING_STATE,
            "value": state,
            "contribution": STATE_CONTRIBUTIONS[state],
        }
    )
    reasons.append(STATE_REASONS[state])

    confidence = _upper(candidate.get("confidence"))
    if confidence not in CONFIDENCE_CONTRIBUTIONS:
        confidence = "UNKNOWN"
    factors.append(
        {
            "factor": FACTOR_UPSTREAM_CONFIDENCE,
            "value": confidence,
            "contribution": CONFIDENCE_CONTRIBUTIONS[confidence],
        }
    )
    reasons.append(CONFIDENCE_REASONS[confidence])

    impact = _upper(candidate.get("impact_state"))
    if impact not in IMPACT_CONTRIBUTIONS:
        impact = IMPACT_UNKNOWN
    factors.append(
        {
            "factor": FACTOR_IMPACT_SIGNAL,
            "value": impact,
            "contribution": IMPACT_CONTRIBUTIONS[impact],
        }
    )
    reasons.append(IMPACT_REASONS[impact])

    severity = _severity_class(candidate)
    factors.append(
        {
            "factor": FACTOR_SEVERITY_SIGNAL,
            "value": severity,
            "contribution": SEVERITY_CONTRIBUTIONS[severity],
        }
    )
    if severity == CVSS_UNKNOWN:
        reasons.append(REASON_SEVERITY_NOT_ASSESSED)
    else:
        reasons.append(REASON_CVSS_CONTEXT_AVAILABLE)

    provenance = provenance_class(candidate)
    factors.append(
        {
            "factor": FACTOR_PROVENANCE_COMPLETENESS,
            "value": provenance,
            "contribution": PROVENANCE_CONTRIBUTIONS[provenance],
        }
    )
    if provenance == PROVENANCE_INCOMPLETE:
        reasons.append(REASON_PROVENANCE_INCOMPLETE)

    correlation_value = _correlation_value(correlation)
    factors.append(
        {
            "factor": FACTOR_CORRELATION_CONTEXT,
            "value": correlation_value,
            "contribution": CORRELATION_CONTRIBUTIONS[correlation_value],
        }
    )
    reasons.extend(_correlation_reasons(correlation))

    learning_factor, learning_reasons = _learning_factor(recommendations)
    factors.append(learning_factor)
    reasons.extend(learning_reasons)

    score = max(
        0,
        min(
            MAX_PRIORITY_SCORE,
            sum(item["contribution"] for item in factors),
        ),
    )

    for cap, factor_code, value, reason in _active_constraints(
        candidate, correlation, recommendations
    ):
        delta = min(0, cap - score)
        if delta < 0:
            factors.append(
                {
                    "factor": factor_code,
                    "value": value,
                    "contribution": delta,
                }
            )
            score += delta
        reasons.append(reason)
    score = max(0, min(MAX_PRIORITY_SCORE, score))

    return {
        "priority_score": score,
        "priority_band": band_for_score(score),
        "priority_factors": factors,
        "priority_reasons": _ordered_reasons(reasons),
    }


# ---------------------------------------------------------------------------
# Limitations
# ---------------------------------------------------------------------------


def priority_limitations(
    candidate: dict,
    correlation: dict,
    recommendations: list[dict],
    *,
    correlation_present: bool,
    correlation_incomplete: bool,
    deferred: bool = False,
) -> list[str]:
    """Deterministic, ordered limitations of one priority plan."""

    correlation = dict(correlation)
    correlation["embedded_conflict_count"] = max(
        _bounded_int(correlation.get("embedded_conflict_count"), 0, 64),
        _bounded_int(candidate.get("embedded_conflict_count"), 0, 64),
    )
    found = set(_BASE_LIMITATIONS)
    if _upper(candidate.get("evidence_completeness")) != (
        COMPLETENESS_COMPLETE
    ):
        found.add("EVIDENCE_INCOMPLETE")
    if context_class(candidate) == CONTEXT_MISSING:
        found.add("INSUFFICIENT_CONTEXT")
    if _upper(candidate.get("severity_source")) != (
        SEVERITY_SOURCE_CVSS_CONTEXT
    ):
        found.add("SEVERITY_NOT_ASSESSED")
    if _upper(candidate.get("impact_state")) != IMPACT_OBSERVED:
        found.add("IMPACT_NOT_OBSERVED")
    if not correlation_present:
        found.add("CORRELATION_UNAVAILABLE")
    if correlation_incomplete:
        found.add("CORRELATION_INCOMPLETE")
    if correlation.get("conflict_count") or correlation.get(
        "embedded_conflict_count"
    ):
        found.add("CONFLICT_PRESENT")
    if RELATIONSHIP_DUPLICATE in (
        correlation.get("relationship_types") or ()
    ):
        found.add("DUPLICATE_RELATIONSHIP")
    governance = governance_class(candidate)
    if governance == GOVERNANCE_UNKNOWN_VALUE:
        found.add("GOVERNANCE_UNKNOWN")
    elif governance == GOVERNANCE_NOT_READY:
        found.add("GOVERNANCE_NOT_READY")
    if provenance_class(candidate) != PROVENANCE_COMPLETE:
        found.add("PROVENANCE_INCOMPLETE")
    if not recommendations:
        found.add("LEARNING_UNAVAILABLE")
    if learning_review_governance(recommendations):
        found.add("LEARNING_GOVERNANCE_REVIEW")
    if deferred:
        found.add("SAFETY_DEFERRED")
    return [code for code in PRIORITY_LIMITATIONS if code in found]


def contribution_bounds() -> dict:
    """Expose the documented contribution range (explainability aid)."""

    return {
        "min": MIN_FACTOR_CONTRIBUTION,
        "max": MAX_FACTOR_CONTRIBUTION,
        "max_score": MAX_PRIORITY_SCORE,
    }


__all__ = [
    "RESEARCH_PRIORITY_RULES_RULE_VERSION",
    "RULE_VERSION",
    "SUPPORTED_CATEGORIES",
    "CONTEXT_COMPLETE_MIN_FACTS",
    "CAP_LOW_SCORE",
    "CAP_MEDIUM_SCORE",
    "CORRELATION_MAX_SOURCES",
    "CORRELATION_MAX_RELATIONSHIPS",
    "EVIDENCE_CONTRIBUTIONS",
    "CONTEXT_CONTRIBUTIONS",
    "STATE_CONTRIBUTIONS",
    "CONFIDENCE_CONTRIBUTIONS",
    "IMPACT_CONTRIBUTIONS",
    "SEVERITY_CONTRIBUTIONS",
    "CORRELATION_CONTRIBUTIONS",
    "LEARNING_CONTRIBUTIONS",
    "PROVENANCE_CONTRIBUTIONS",
    "EVIDENCE_RANK",
    "CONFIDENCE_RANK",
    "GOVERNANCE_RANK",
    "EVIDENCE_STATE_REASONS",
    "CONTEXT_REASONS",
    "STATE_REASONS",
    "CONFIDENCE_REASONS",
    "IMPACT_REASONS",
    "CORRELATION_REASONS",
    "LEARNING_SIGNAL_MAP",
    "LEARNING_SIGNAL_PRECEDENCE",
    "finding_candidate",
    "reference_candidate",
    "duplicate_preference",
    "duplicate_representative",
    "build_correlation_contexts",
    "empty_correlation_context",
    "learning_recommendations_for",
    "learning_deferral",
    "learning_review_governance",
    "context_class",
    "provenance_class",
    "governance_class",
    "evaluate_candidate",
    "priority_limitations",
    "contribution_bounds",
]
