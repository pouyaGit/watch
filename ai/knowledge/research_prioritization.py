"""Stage R55.4 deterministic research-prioritization builder (pure engine).

Consumes structured R53 finding-intelligence output (optionally enriched with
R54 correlation intelligence and R44 learning context) and produces a
deterministic, explainable research-priority ranking:

    R53 finding intelligence / standalone R53 findings / R54 references
      -> bounded priority candidates (stable finding ids)
      -> documented factor contributions (R55.3 rules)
      -> deterministic ranking (stable tie-breaks)
      -> provenance, governance summary and limitations
      -> research prioritization result

Hard boundaries encoded here:

- Research ordering only: R55 never executes anything, never confirms a
  vulnerability and never merges, rewrites or deletes findings. Every
  original finding, evidence reference, provenance reference, governance
  reference and limitation remains addressable through its stable finding id.
- Priority is not confidence: the result and every plan force
  ``confidence_effect = NONE`` and ``confirmation_state = NOT_CONFIRMED``;
  upstream finding confidence is preserved untouched (R55 is read-only over
  its inputs).
- Safety first: unsafe findings (non-research-only, unsafe confirmation,
  safety-failed, forbidden-claim, invalid provenance/governance or a learning
  safety-boundary signal) are never dropped and never boosted; they are
  preserved in the deferred set with an explicit reason and limitation.
- Fail closed: ambiguous (both orchestration-level and standalone finding
  inputs), malformed, unsupported or mis-versioned inputs are rejected or
  skipped with structured reasons; correlation endpoints that do not match
  the candidate set are recorded as a structured mismatch, never guessed.
- Deterministic: content-derived ids only; canonical ordering; stable
  tie-breaking; no timestamps, UUIDs, pids or randomness.
- Pure and offline: no I/O, no network, no DNS, no subprocess, no shell, no
  browser, no scanner, no database, no LLM, no wall-clock time.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.knowledge.agent_evaluation_rules import (
    CONFIRMATION_CLAIM_TOKENS,
    EXECUTION_CLAIM_TOKENS,
)
from ai.knowledge.research_priority_rules import (
    CONFIDENCE_RANK,
    EVIDENCE_RANK,
    RESEARCH_PRIORITY_RULES_RULE_VERSION,
    SUPPORTED_CATEGORIES,
    build_correlation_contexts,
    evaluate_candidate,
    finding_candidate,
    learning_deferral,
    learning_recommendations_for,
    priority_limitations,
    reference_candidate,
)
from ai.schemas.finding_assessment import CONFIRMATION_NOT_CONFIRMED
from ai.schemas.finding_correlation import (
    FINDING_CORRELATION_RULE_VERSION,
    sanitize_finding_relationship,
)
from ai.schemas.finding_correlation_result import (
    FINDING_CORRELATION_RESULT_RULE_VERSION,
    sanitize_correlation_cluster,
)
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.finding_result import (
    FINDING_RESULT_RULE_VERSION,
    sanitize_finding,
)
from ai.schemas.research_priority import (
    REASON_LEARNING_SIGNAL_SAFETY_BOUNDARY,
)
from ai.schemas.multi_agent_collaboration_result import (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)
from ai.schemas.research_priority import (
    BAND_DEFERRED,
    CONFLICT_NONE,
    CONFLICT_PRESENT,
    CONFLICT_UNKNOWN,
    FACTOR_SAFETY_ELIGIBILITY,
    GOVERNANCE_READY_NOT_READY,
    GOVERNANCE_READY_READY,
    PRIORITY_BAND_RANK,
    REASON_FORBIDDEN_CLAIM,
    REASON_INVALID_GOVERNANCE,
    REASON_INVALID_PROVENANCE,
    REASON_NON_RESEARCH_ONLY,
    REASON_SAFETY_DEFERRED,
    REASON_SAFETY_FAILURE,
    REASON_UNSAFE_CONFIRMATION,
    RESEARCH_PRIORITY_RULE_VERSION,
    SAFETY_DEFERRED_VALUE,
    SOURCE_KIND_FINDING,
    SOURCE_KIND_REFERENCE,
    sanitize_research_priority,
    ResearchPriorityPlan,
)
from ai.schemas.research_priority_result import (
    ERROR_CORRELATION_MISMATCH,
    ERROR_DUPLICATE_IDENTITY,
    ERROR_INVALID_INPUT,
    ERROR_LIMIT_EXCEEDED,
    ERROR_MALFORMED_FINDING,
    ERROR_UNSUPPORTED_CATEGORY,
    ERROR_UNKNOWN,
    MAX_FINDINGS,
    PRIORITIZATION_ID_PREFIX,
    RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
    SKIP_DUPLICATE_IDENTITY,
    SKIP_LIMIT_EXCEEDED,
    SKIP_MALFORMED_FINDING,
    SKIP_UNSUPPORTED_CATEGORY,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_PARTIAL,
    ResearchPrioritizationResultPlan,
    research_prioritization_result_plan_projection,
    sanitize_priority_error,
    sanitize_priority_skip,
)

RESEARCH_PRIORITIZATION_BUILDER_RULE_VERSION = "r55-4"
RULE_VERSION = RESEARCH_PRIORITIZATION_BUILDER_RULE_VERSION

_DIAGNOSTIC_DEFERRALS: dict[str, str] = {
    "PROVENANCE_INVENTED_LAYER": REASON_INVALID_PROVENANCE,
    "MALFORMED_PROVENANCE": REASON_INVALID_PROVENANCE,
    "MALFORMED_GOVERNANCE": REASON_INVALID_GOVERNANCE,
    "GOVERNANCE_INCONSISTENT": REASON_INVALID_GOVERNANCE,
}

_IMPACT_RANK: dict[str, int] = {
    "UNKNOWN": 0,
    "POTENTIAL": 1,
    "OBSERVED": 2,
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


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _error(
    error_category: str,
    finding_id: str = "",
    category: str = "",
    message: str = "",
) -> dict:
    return sanitize_priority_error(
        {
            "stage": "RESEARCH_PRIORITIZATION",
            "error_category": error_category,
            "finding_id": finding_id,
            "category": category,
            "message": message,
        }
    )


def _skip(
    finding_id: str, category: str, agent_id: str, reason: str
) -> dict:
    return sanitize_priority_skip(
        {
            "finding_id": finding_id,
            "category": category,
            "agent_id": agent_id,
            "reason": reason,
        }
    )


# ---------------------------------------------------------------------------
# Safety gate (fail closed; unsafe findings are deferred, never dropped)
# ---------------------------------------------------------------------------


def _claim_text(raw: dict) -> str:
    """Deterministic text projection of the forbidden-claim channels."""

    parts: list[str] = []
    context = raw.get("context")
    if isinstance(context, dict):
        for key in ("title", "summary", "technical_description"):
            parts.append(str(context.get(key) or ""))
    hypotheses = raw.get("hypotheses")
    if isinstance(hypotheses, dict):
        for reference in hypotheses.get("references") or ():
            if not isinstance(reference, dict):
                continue
            parts.append(str(reference.get("rationale") or ""))
            parts.append(str(reference.get("hypothesis_type") or ""))
            parts.append(
                " ".join(
                    str(signal)
                    for signal in reference.get("supporting_signals") or ()
                )
            )
    assessment = raw.get("assessment")
    if isinstance(assessment, dict):
        parts.append(str(assessment.get("impact_description") or ""))
        for item in assessment.get("remediation_items") or ():
            if isinstance(item, dict):
                parts.append(str(item.get("guidance") or ""))
    parts.append(" ".join(str(item) for item in raw.get("limitations") or ()))
    parts.append(str(raw.get("component_name") or ""))
    parts.append(str(raw.get("endpoint_reference") or ""))
    return " ".join(parts).upper()


def _has_forbidden_claim(raw: dict) -> bool:
    text = _claim_text(raw)
    return any(
        token in text
        for token in EXECUTION_CLAIM_TOKENS + CONFIRMATION_CLAIM_TOKENS
    )


def _deferral_reason(raw: dict) -> str:
    """Fail-closed safety classification; empty means eligible."""

    if not isinstance(raw, dict):
        return ""
    if raw.get("research_only") is not True:
        return REASON_NON_RESEARCH_ONLY
    assessment = raw.get("assessment")
    if not isinstance(assessment, dict):
        assessment = {}
    confirmation = _upper(
        assessment.get("confirmation_state")
        or raw.get("confirmation_state")
    )
    if confirmation and confirmation != CONFIRMATION_NOT_CONFIRMED:
        return REASON_UNSAFE_CONFIRMATION
    safety = _upper(assessment.get("safety_state"))
    gate = _upper(assessment.get("hard_gate_state"))
    if safety == "FAILED" or gate == "FAIL_SAFETY":
        return REASON_SAFETY_FAILURE
    if _has_forbidden_claim(raw):
        return REASON_FORBIDDEN_CLAIM
    diagnostics = {
        _upper(code) for code in assessment.get("diagnostic_codes") or ()
    }
    for code in sorted(diagnostics):
        reason = _DIAGNOSTIC_DEFERRALS.get(code)
        if reason:
            return reason
    return ""


def _identity_fields(raw: dict) -> tuple[str, str, str]:
    identity = raw.get("identity")
    if not isinstance(identity, dict):
        identity = {}
    finding_id = _text(identity.get("finding_id")) or _text(
        raw.get("finding_id")
    )
    category = _upper(identity.get("category")) or _upper(
        raw.get("category")
    )
    agent_id = _text(identity.get("agent_id")) or _text(raw.get("agent_id"))
    return finding_id, category, agent_id


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def _normalize_finding(
    raw: object,
) -> tuple[dict, str, str]:
    """Normalize one R53 finding entry (read-only).

    Returns ``(candidate, skip_reason, deferral_reason)``; an empty
    ``skip_reason`` means the entry is representable.
    """

    if not isinstance(raw, dict):
        return {}, SKIP_MALFORMED_FINDING, ""
    finding_id, category, _ = _identity_fields(raw)
    if not FINDING_ID_RE.match(finding_id):
        return {}, SKIP_MALFORMED_FINDING, ""
    if category not in SUPPORTED_CATEGORIES:
        return {}, SKIP_UNSUPPORTED_CATEGORY, ""
    sanitized = sanitize_finding(raw)
    if _text(sanitized.get("rule_version")) != FINDING_RESULT_RULE_VERSION:
        return {}, SKIP_MALFORMED_FINDING, ""
    candidate = finding_candidate(sanitized)
    if not FINDING_ID_RE.match(candidate["finding_id"]):
        return {}, SKIP_MALFORMED_FINDING, ""
    return candidate, "", _deferral_reason(raw)


def _normalize_reference(
    raw: object,
) -> tuple[dict, str, str]:
    """Normalize one R54 finding reference entry (read-only)."""

    if not isinstance(raw, dict):
        return {}, SKIP_MALFORMED_FINDING, ""
    finding_id, category, _ = _identity_fields(raw)
    if not FINDING_ID_RE.match(finding_id):
        return {}, SKIP_MALFORMED_FINDING, ""
    if category not in SUPPORTED_CATEGORIES:
        return {}, SKIP_UNSUPPORTED_CATEGORY, ""
    candidate = reference_candidate(raw)
    return candidate, "", _deferral_reason(raw)


# ---------------------------------------------------------------------------
# Correlation and learning parsing
# ---------------------------------------------------------------------------


def _parse_correlation(
    correlation_result: object,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Sanitize R54 relationships and clusters (read-only)."""

    relationships: list[dict] = []
    clusters: list[dict] = []
    errors: list[dict] = []
    if not isinstance(correlation_result, dict):
        return relationships, clusters, errors
    for raw in correlation_result.get("relationships") or ():
        projected = sanitize_finding_relationship(raw)
        if (
            not FINDING_ID_RE.match(_text(projected.get("source_finding_id")))
            or not FINDING_ID_RE.match(
                _text(projected.get("target_finding_id"))
            )
            or not _text(projected.get("relationship_id"))
        ):
            errors.append(
                _error(
                    ERROR_CORRELATION_MISMATCH,
                    message="malformed correlation relationship ignored",
                )
            )
            continue
        relationships.append(projected)
    for raw in correlation_result.get("clusters") or ():
        if not isinstance(raw, dict):
            errors.append(
                _error(
                    ERROR_CORRELATION_MISMATCH,
                    message="malformed correlation cluster ignored",
                )
            )
            continue
        clusters.append(sanitize_correlation_cluster(raw))
    return relationships, clusters, errors


# ---------------------------------------------------------------------------
# Plan construction
# ---------------------------------------------------------------------------


def _correlation_summary(correlation: dict) -> dict:
    return {
        "present": bool(correlation.get("present")),
        "relationship_types": list(
            correlation.get("relationship_types") or ()
        ),
        "conflict_count": correlation.get("conflict_count") or 0,
        "duplicate_count": correlation.get("duplicate_count") or 0,
        "related_count": correlation.get("related_count") or 0,
        "independent_count": correlation.get("independent_count") or 0,
        "unknown_count": correlation.get("unknown_count") or 0,
        "embedded_conflict_count": (
            correlation.get("embedded_conflict_count") or 0
        ),
        "duplicate_cluster_size": (
            correlation.get("duplicate_cluster_size") or 0
        ),
        "conflict_sources": list(correlation.get("conflict_sources") or ()),
        "relationship_ids": list(correlation.get("relationship_ids") or ()),
        "research_only": True,
    }


def _conflict_state(candidate: dict, correlation: dict) -> str:
    if correlation.get("conflict_count") or correlation.get(
        "embedded_conflict_count"
    ):
        return CONFLICT_PRESENT
    if correlation.get("present") or candidate.get("source_kind") == (
        SOURCE_KIND_FINDING
    ):
        return CONFLICT_NONE
    return CONFLICT_UNKNOWN


def _learning_summary(recommendations: list[dict]) -> dict:
    types: list[str] = []
    ids: list[str] = []
    for item in recommendations:
        recommendation_type = _upper(item.get("recommendation_type"))
        if recommendation_type and recommendation_type not in types:
            types.append(recommendation_type)
        recommendation_id = _text(item.get("recommendation_id"))
        if recommendation_id and recommendation_id not in ids:
            ids.append(recommendation_id)
    return {
        "available": bool(recommendations),
        "recommendation_types": types[:16],
        "recommendation_ids": ids[:16],
        "advisory_only": True,
    }


def _plan(
    candidate: dict,
    correlation: dict,
    recommendations: list[dict],
    *,
    evaluated: dict | None = None,
    position: int = 0,
    deferral_reason: str = "",
    correlation_present: bool,
    correlation_incomplete: bool,
) -> dict:
    deferred = bool(deferral_reason)
    if deferred:
        score = 0
        band = BAND_DEFERRED
        factors = [
            {
                "factor": FACTOR_SAFETY_ELIGIBILITY,
                "value": SAFETY_DEFERRED_VALUE,
                "contribution": 0,
            }
        ]
        reasons = [REASON_SAFETY_DEFERRED, deferral_reason]
    else:
        evaluated = evaluated or {}
        score = evaluated.get("priority_score") or 0
        band = evaluated.get("priority_band") or BAND_DEFERRED
        factors = list(evaluated.get("priority_factors") or ())
        reasons = list(evaluated.get("priority_reasons") or ())
    limitations = priority_limitations(
        candidate,
        correlation,
        recommendations,
        correlation_present=correlation_present,
        correlation_incomplete=correlation_incomplete,
        deferred=deferred,
    )
    payload = {
        "rule_version": RESEARCH_PRIORITY_RULE_VERSION,
        "finding_id": candidate.get("finding_id"),
        "category": candidate.get("category"),
        "specialist_name": candidate.get("specialist_name"),
        "agent_id": candidate.get("agent_id"),
        "state": candidate.get("state"),
        "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
        "confidence": candidate.get("confidence"),
        "confidence_effect": "NONE",
        "evidence_state": candidate.get("evidence_state"),
        "evidence_completeness": candidate.get("evidence_completeness"),
        "evidence_origin": candidate.get("evidence_origin"),
        "severity": candidate.get("severity"),
        "severity_source": candidate.get("severity_source"),
        "impact_state": candidate.get("impact_state"),
        "impact_confidence": candidate.get("impact_confidence"),
        "priority_score": score,
        "priority_band": band,
        "priority_factors": factors,
        "priority_reasons": reasons,
        "correlation_summary": _correlation_summary(correlation),
        "conflict_state": _conflict_state(candidate, correlation),
        "learning_summary": _learning_summary(recommendations),
        "ranking_position": position,
        "provenance": {
            "source_kind": candidate.get("source_kind"),
            "finding_rule_version": candidate.get(
                "finding_rule_version"
            ),
            "correlation_rule_version": (
                FINDING_CORRELATION_RULE_VERSION
                if correlation_present
                else ""
            ),
            "orchestration_id": candidate.get("orchestration_id"),
            "source_stages": list(candidate.get("source_stages") or ()),
            "evaluation_rating": candidate.get("evaluation_rating") or "",
            "hard_gate_state": candidate.get("hard_gate_state") or "",
            "safety_state": candidate.get("safety_state") or "UNKNOWN",
            "deterministic": True,
            "research_only": True,
        },
        "governance": {
            "rule_version": candidate.get("governance_rule_version"),
            "reference_state": candidate.get("governance_reference_state"),
            "ready_state": candidate.get("governance_ready_state"),
            "research_only": True,
        },
        "limitations": limitations,
        "research_only": True,
        "deterministic": True,
    }
    plan = ResearchPriorityPlan(**sanitize_research_priority(payload))
    return plan.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Ranking and container
# ---------------------------------------------------------------------------


def _ranking_key(candidate: dict, plan: dict) -> tuple:
    completeness = _upper(candidate.get("evidence_completeness"))
    confidence = _upper(candidate.get("confidence"))
    impact = _upper(candidate.get("impact_state"))
    return (
        -PRIORITY_BAND_RANK.get(plan.get("priority_band"), 0),
        -int(plan.get("priority_score") or 0),
        -EVIDENCE_RANK.get(completeness, 0),
        -CONFIDENCE_RANK.get(confidence, 0),
        -_IMPACT_RANK.get(impact, 0),
        _text(candidate.get("finding_id")),
    )


def _prioritization_id(
    ranked: list[dict],
    deferred: list[dict],
    skipped: list[dict],
) -> str:
    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
                "priority_rule_version": (
                    RESEARCH_PRIORITIZATION_BUILDER_RULE_VERSION
                ),
                "ranked": [
                    {
                        "finding_id": item["finding_id"],
                        "priority_score": item["priority_score"],
                        "priority_band": item["priority_band"],
                    }
                    for item in ranked
                ],
                "deferred": [
                    item["finding_id"] for item in deferred
                ],
                "skipped": [
                    {
                        "finding_id": item.get("finding_id"),
                        "reason": item.get("reason"),
                    }
                    for item in skipped
                ],
            }
        ).encode("utf-8")
    ).hexdigest()
    return PRIORITIZATION_ID_PREFIX + digest[:16]


def _governance_summary(candidates: list[dict]) -> dict:
    referenced: list[str] = []
    unknown: list[str] = []
    ready: list[str] = []
    not_ready: list[str] = []
    for candidate in candidates:
        finding_id = _text(candidate.get("finding_id"))
        if _upper(candidate.get("governance_reference_state")) == (
            "REFERENCED"
        ):
            referenced.append(finding_id)
            ready_state = _upper(candidate.get("governance_ready_state"))
            if ready_state == GOVERNANCE_READY_READY:
                ready.append(finding_id)
            elif ready_state == GOVERNANCE_READY_NOT_READY:
                not_ready.append(finding_id)
        else:
            unknown.append(finding_id)
    if referenced and unknown:
        state = GOVERNANCE_MIXED
    elif referenced:
        state = GOVERNANCE_CONSISTENT_REFERENCED
    else:
        state = GOVERNANCE_UNKNOWN
    return {
        "governance_state": state,
        "referenced_finding_ids": referenced,
        "unknown_finding_ids": unknown,
        "ready_finding_ids": ready,
        "not_ready_finding_ids": not_ready,
        "research_only": True,
    }


def _summary(
    candidates: list[dict],
    ranked: list[dict],
    deferred: list[dict],
    skipped: list[dict],
) -> dict:
    band_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "DEFERRED": 0,
    }
    for plan in ranked + deferred:
        band = plan.get("priority_band")
        if band in band_counts:
            band_counts[band] += 1
    scores = [int(plan.get("priority_score") or 0) for plan in ranked]
    return {
        "finding_count": len(candidates),
        "ranked_count": len(ranked),
        "deferred_count": len(deferred),
        "skipped_count": len(skipped),
        "band_counts": band_counts,
        "conflict_finding_count": sum(
            1
            for plan in ranked + deferred
            if plan.get("conflict_state") == CONFLICT_PRESENT
        ),
        "duplicate_finding_count": sum(
            1
            for plan in ranked + deferred
            if "DUPLICATE"
            in (plan.get("correlation_summary") or {}).get(
                "relationship_types", []
            )
        ),
        "related_finding_count": sum(
            1
            for plan in ranked + deferred
            if "RELATED"
            in (plan.get("correlation_summary") or {}).get(
                "relationship_types", []
            )
        ),
        "evidence_complete_count": sum(
            1
            for plan in ranked + deferred
            if plan.get("evidence_completeness") == "COMPLETE"
        ),
        "evidence_partial_count": sum(
            1
            for plan in ranked + deferred
            if plan.get("evidence_completeness") == "PARTIAL"
        ),
        "evidence_missing_count": sum(
            1
            for plan in ranked + deferred
            if plan.get("evidence_completeness") in ("MISSING", "UNKNOWN")
        ),
        "severity_assessed_count": sum(
            1
            for plan in ranked + deferred
            if plan.get("severity_source") == "CVSS_CONTEXT"
        ),
        "impact_observed_count": sum(
            1
            for plan in ranked + deferred
            if plan.get("impact_state") == "OBSERVED"
        ),
        "learning_available_count": sum(
            1
            for plan in ranked + deferred
            if (plan.get("learning_summary") or {}).get("available")
        ),
        "highest_score": max(scores) if scores else 0,
        "lowest_score": min(scores) if scores else 0,
        "research_only": True,
    }


def _container(
    *,
    ranked: list[dict],
    deferred: list[dict],
    skipped: list[dict],
    errors: list[dict],
    candidates: list[dict],
    finding_rule_version: str,
    correlation_rule_version: str,
    correlation_present: bool,
    correlation_incomplete: bool,
    fatal: bool = False,
) -> dict:
    if fatal:
        status = STATUS_FAILED
    elif ranked and (errors or skipped or deferred):
        status = STATUS_PARTIAL
    elif ranked:
        status = STATUS_COMPLETED
    elif errors or skipped or deferred:
        status = STATUS_PARTIAL
    else:
        status = STATUS_NO_FINDINGS

    limitations = list(_BASE_LIMITATIONS)
    if not correlation_present:
        limitations.append("CORRELATION_UNAVAILABLE")
    if correlation_incomplete:
        limitations.append("CORRELATION_INCOMPLETE")
    if any(
        plan.get("conflict_state") == CONFLICT_PRESENT
        for plan in ranked + deferred
    ):
        limitations.append("CONFLICT_PRESENT")
    if any(
        "DUPLICATE"
        in (plan.get("correlation_summary") or {}).get(
            "relationship_types", []
        )
        for plan in ranked + deferred
    ):
        limitations.append("DUPLICATE_RELATIONSHIP")
    if any(
        plan.get("evidence_completeness") != "COMPLETE"
        for plan in ranked + deferred
    ):
        limitations.append("EVIDENCE_INCOMPLETE")
    if any(
        plan.get("severity_source") != "CVSS_CONTEXT"
        for plan in ranked + deferred
    ):
        limitations.append("SEVERITY_NOT_ASSESSED")
    if any(
        plan.get("impact_state") != "OBSERVED"
        for plan in ranked + deferred
    ):
        limitations.append("IMPACT_NOT_OBSERVED")
    if any(
        not ((plan.get("provenance") or {}).get("orchestration_id"))
        for plan in ranked + deferred
    ):
        limitations.append("PROVENANCE_INCOMPLETE")
    if not any(
        (plan.get("learning_summary") or {}).get("available")
        for plan in ranked + deferred
    ):
        limitations.append("LEARNING_UNAVAILABLE")
    if deferred:
        limitations.append("SAFETY_DEFERRED")
    governance = _governance_summary(candidates)
    if governance["governance_state"] == GOVERNANCE_UNKNOWN:
        limitations.append("GOVERNANCE_UNKNOWN")

    result = ResearchPrioritizationResultPlan(
        rule_version=RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
        prioritization_rule_version=(
            RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION
        ),
        priority_rule_version=RESEARCH_PRIORITY_RULES_RULE_VERSION,
        finding_rule_version=finding_rule_version,
        correlation_rule_version=correlation_rule_version,
        prioritization_id=_prioritization_id(ranked, deferred, skipped),
        status=status,
        ranked_findings=ranked,
        deferred_findings=deferred,
        skipped_findings=skipped,
        errors=errors,
        summary=_summary(candidates, ranked, deferred, skipped),
        provenance={
            "rule_version": RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
            "priority_rule_version": RESEARCH_PRIORITY_RULES_RULE_VERSION,
            "finding_rule_version": finding_rule_version,
            "correlation_rule_version": correlation_rule_version,
            "source_kinds": sorted(
                {
                    _text(candidate.get("source_kind"))
                    for candidate in candidates
                    if _text(candidate.get("source_kind"))
                }
            ),
            "orchestration_ids": sorted(
                {
                    _text(candidate.get("orchestration_id"))
                    for candidate in candidates
                    if _text(candidate.get("orchestration_id"))
                }
            ),
            "source_categories": sorted(
                {
                    _upper(candidate.get("category"))
                    for candidate in candidates
                    if _upper(candidate.get("category"))
                }
            ),
            "source_agent_ids": sorted(
                {
                    _text(candidate.get("agent_id"))
                    for candidate in candidates
                    if _text(candidate.get("agent_id"))
                }
            ),
            "deterministic": True,
            "research_only": True,
        },
        governance=governance,
        limitations=limitations,
        confidence_effect="NONE",
        research_only=True,
        deterministic=True,
    )
    return research_prioritization_result_plan_projection(result)


def _fatal_result(errors: list[dict]) -> dict:
    return _container(
        ranked=[],
        deferred=[],
        skipped=[],
        errors=errors,
        candidates=[],
        finding_rule_version="",
        correlation_rule_version="",
        correlation_present=False,
        correlation_incomplete=False,
        fatal=True,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def prioritize(
    finding_intelligence: object = None,
    findings: object = None,
    correlation_result: object = None,
    learning_result: object = None,
) -> dict:
    """Prioritize structured R53 findings deterministically (read-only).

    Supply either one R53 finding-intelligence result or a standalone list of
    R53 findings, optionally enriched with one R54 correlation result and one
    R44/R52 learning result. Supplying both finding sources (or an ambiguous
    input) fails closed with ``INVALID_INPUT``. R55 preserves every finding:
    unsafe findings are deferred with explicit reasons and nothing is merged,
    rewritten or deleted.
    """

    # ------------------------------------------------------------------
    # Input validation (fail closed)
    # ------------------------------------------------------------------
    if finding_intelligence is not None and not isinstance(
        finding_intelligence, dict
    ):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message="finding_intelligence must be a mapping",
                )
            ]
        )
    if findings is not None and not isinstance(findings, (list, tuple)):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message="findings must be a list",
                )
            ]
        )
    if finding_intelligence is not None and findings is not None:
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message=(
                        "supply either finding_intelligence or findings, "
                        "not both"
                    ),
                )
            ]
        )
    if correlation_result is not None:
        if not isinstance(correlation_result, dict):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message="correlation_result must be a mapping",
                    )
                ]
            )
        if (
            _text(correlation_result.get("rule_version"))
            != FINDING_CORRELATION_RESULT_RULE_VERSION
        ):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message="correlation_result is not an R54 result",
                    )
                ]
            )
        for key in ("relationships", "clusters", "finding_references"):
            if key in correlation_result and not isinstance(
                correlation_result.get(key), (list, tuple)
            ):
                return _fatal_result(
                    [
                        _error(
                            ERROR_INVALID_INPUT,
                            message=(
                                f"correlation_result.{key} must be a list"
                            ),
                        )
                    ]
                )
    if learning_result is not None:
        if not isinstance(learning_result, dict):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message="learning_result must be a mapping",
                    )
                ]
            )
        if "recommendations" in learning_result and not isinstance(
            learning_result.get("recommendations"), (list, tuple)
        ):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message=(
                            "learning_result.recommendations must be a list"
                        ),
                    )
                ]
            )

    # ------------------------------------------------------------------
    # Normalize the structured inputs
    # ------------------------------------------------------------------
    source = ""
    finding_rule_version = ""
    if finding_intelligence is not None:
        if (
            _text(finding_intelligence.get("rule_version"))
            != FINDING_RESULT_RULE_VERSION
        ):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message="finding_intelligence is not an R53 result",
                    )
                ]
            )
        raw_entries = finding_intelligence.get("findings")
        if not isinstance(raw_entries, (list, tuple)):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message=(
                            "finding_intelligence.findings must be a list"
                        ),
                    )
                ]
            )
        source = SOURCE_KIND_FINDING
        finding_rule_version = FINDING_RESULT_RULE_VERSION
    elif findings is not None:
        raw_entries = list(findings or [])
        source = SOURCE_KIND_FINDING
    elif correlation_result is not None:
        raw_entries = list(
            correlation_result.get("finding_references") or []
        )
        source = SOURCE_KIND_REFERENCE
    else:
        raw_entries = []

    correlation_present = correlation_result is not None
    correlation_rule_version = (
        FINDING_CORRELATION_RULE_VERSION if correlation_present else ""
    )
    relationships, clusters, errors = _parse_correlation(
        correlation_result
    )

    candidates: list[dict] = []
    deferred_entries: list[tuple[dict, str]] = []
    skipped: list[dict] = []
    seen_ids: list[str] = []
    normalized_count = 0

    for raw in raw_entries:
        if source == SOURCE_KIND_REFERENCE:
            candidate, skip_reason, deferral_reason = _normalize_reference(
                raw
            )
        else:
            candidate, skip_reason, deferral_reason = _normalize_finding(
                raw
            )
        raw_dict = raw if isinstance(raw, dict) else {}
        finding_id, category, agent_id = _identity_fields(raw_dict)
        if skip_reason:
            skipped.append(
                _skip(finding_id, category, agent_id, skip_reason)
            )
            errors.append(
                _error(
                    {
                        SKIP_MALFORMED_FINDING: ERROR_MALFORMED_FINDING,
                        SKIP_UNSUPPORTED_CATEGORY: ERROR_UNSUPPORTED_CATEGORY,
                    }.get(skip_reason, ERROR_UNKNOWN),
                    finding_id,
                    category,
                    "finding is not a supported prioritization source",
                )
            )
            continue
        if finding_id in seen_ids:
            skipped.append(
                _skip(
                    finding_id,
                    category,
                    agent_id,
                    SKIP_DUPLICATE_IDENTITY,
                )
            )
            errors.append(
                _error(
                    ERROR_DUPLICATE_IDENTITY,
                    finding_id,
                    category,
                    "the same finding identity was supplied twice",
                )
            )
            continue
        if normalized_count >= MAX_FINDINGS:
            skipped.append(
                _skip(
                    finding_id,
                    category,
                    agent_id,
                    SKIP_LIMIT_EXCEEDED,
                )
            )
            errors.append(
                _error(
                    ERROR_LIMIT_EXCEEDED,
                    finding_id,
                    category,
                    "finding limit reached",
                )
            )
            continue
        seen_ids.append(finding_id)
        normalized_count += 1
        if deferral_reason:
            deferred_entries.append((candidate, deferral_reason))
        else:
            candidates.append(candidate)

    # Canonical order by stable finding id (never by list position).
    candidates.sort(key=lambda item: item["finding_id"])
    deferred_entries.sort(key=lambda item: item[0]["finding_id"])

    # ------------------------------------------------------------------
    # Correlation contexts (deterministic; mismatch is never guessed)
    # ------------------------------------------------------------------
    context_candidates = candidates + [
        candidate for candidate, _ in deferred_entries
    ]
    contexts, unmatched = build_correlation_contexts(
        context_candidates,
        relationships,
        clusters,
        correlation_present,
    )
    for finding_id in unmatched:
        errors.append(
            _error(
                ERROR_CORRELATION_MISMATCH,
                finding_id,
                message=(
                    "correlation references a finding outside the "
                    "candidate set"
                ),
            )
        )
    correlation_incomplete = bool(unmatched)

    # ------------------------------------------------------------------
    # Eligible candidates: evaluate and rank
    # ------------------------------------------------------------------
    evaluated: list[tuple[dict, dict]] = []
    for candidate in candidates:
        correlation = contexts[candidate["finding_id"]]
        recommendations = learning_recommendations_for(
            candidate, learning_result
        )
        if learning_deferral(recommendations):
            deferred_entries.append(
                (candidate, REASON_LEARNING_SIGNAL_SAFETY_BOUNDARY)
            )
            continue
        evaluated.append(
            (
                candidate,
                evaluate_candidate(
                    candidate, correlation, recommendations
                ),
            )
        )
    deferred_entries.sort(key=lambda item: item[0]["finding_id"])

    def _plan_sort_key(item: tuple[dict, dict]) -> tuple:
        candidate, scored = item
        provisional = {
            "priority_band": scored["priority_band"],
            "priority_score": scored["priority_score"],
        }
        return _ranking_key(candidate, provisional)

    evaluated.sort(key=_plan_sort_key)

    ranked_plans: list[dict] = []
    for position, (candidate, scored) in enumerate(evaluated, start=1):
        correlation = contexts[candidate["finding_id"]]
        recommendations = learning_recommendations_for(
            candidate, learning_result
        )
        ranked_plans.append(
            _plan(
                candidate,
                correlation,
                recommendations,
                evaluated=scored,
                position=position,
                correlation_present=correlation_present,
                correlation_incomplete=correlation_incomplete,
            )
        )
    deferred_plans: list[dict] = []
    for candidate, deferral_reason in deferred_entries:
        correlation = contexts[candidate["finding_id"]]
        recommendations = learning_recommendations_for(
            candidate, learning_result
        )
        deferred_plans.append(
            _plan(
                candidate,
                correlation,
                recommendations,
                deferral_reason=deferral_reason,
                correlation_present=correlation_present,
                correlation_incomplete=correlation_incomplete,
            )
        )

    if not finding_rule_version:
        versions = sorted(
            {
                _text(candidate.get("finding_rule_version"))
                for candidate in context_candidates
                if _text(candidate.get("finding_rule_version"))
            }
        )
        finding_rule_version = versions[0] if len(versions) == 1 else ""

    return _container(
        ranked=ranked_plans,
        deferred=deferred_plans,
        skipped=skipped,
        errors=errors,
        candidates=context_candidates,
        finding_rule_version=finding_rule_version,
        correlation_rule_version=correlation_rule_version,
        correlation_present=correlation_present,
        correlation_incomplete=correlation_incomplete,
    )


def prioritize_finding_intelligence(
    finding_intelligence: object = None,
    correlation_result: object = None,
    learning_result: object = None,
) -> dict:
    """Alias: prioritize one R53 finding-intelligence result."""

    return prioritize(
        finding_intelligence=finding_intelligence,
        correlation_result=correlation_result,
        learning_result=learning_result,
    )


def prioritize_findings(
    findings: object = None,
    correlation_result: object = None,
    learning_result: object = None,
) -> dict:
    """Alias: prioritize a standalone list of R53 findings."""

    return prioritize(
        findings=findings,
        correlation_result=correlation_result,
        learning_result=learning_result,
    )


def prioritize_correlated_findings(
    correlation_result: object = None,
    learning_result: object = None,
) -> dict:
    """Alias: prioritize the finding references of one R54 result."""

    return prioritize(
        correlation_result=correlation_result,
        learning_result=learning_result,
    )


def export_research_priorities(**kwargs) -> dict:
    """Alias for :func:`prioritize` (project naming pattern)."""

    return prioritize(**kwargs)


__all__ = [
    "RESEARCH_PRIORITIZATION_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "prioritize",
    "prioritize_finding_intelligence",
    "prioritize_findings",
    "prioritize_correlated_findings",
    "export_research_priorities",
]
