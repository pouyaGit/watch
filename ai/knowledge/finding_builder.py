"""Stage R53.6 deterministic finding builder (pure engine).

Transforms structured R38-R52 research outputs into structured research
finding candidates:

    specialist result / R52 orchestration result
      -> identity + context + hypothesis linkage + evidence linkage
      -> deterministic state + confidence + impact + remediation
      -> preserved correlation, references, provenance and governance
      -> finding intelligence result

Hard boundaries encoded here:

- Research finding candidates only: R53 never executes anything, never
  confirms a vulnerability and never fabricates evidence, hypotheses,
  impact, severity or remediation. Every finding forces
  ``confirmation_state = NOT_CONFIRMED``.
- Existing contracts only: specialist results, R42 evaluation results, R43
  collaboration results, R44 feedback results and R37 governance references
  are consumed through their own sanitizers. No upstream contract is
  modified and no parallel orchestration is created.
- No isolation loss: duplicate/related/conflicting correlation and every
  safe candidate are preserved; nothing is silently discarded.
- Fail closed: unsafe results (research_only false, forbidden claims,
  safety-failed evaluations) never become findings; malformed or
  unsupported inputs are skipped with structured reasons.
- Deterministic: content-derived ids only; no timestamps, UUIDs, pids or
  randomness.
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
from ai.knowledge.finding_reasoning import (
    build_assessment as _build_assessment,
)
from ai.knowledge.finding_reasoning import (
    build_finding_context as _build_context,
)
from ai.knowledge.finding_reasoning import (
    build_finding_identity as _build_identity,
)
from ai.knowledge.finding_reasoning import (
    known_context_facts,
)
from ai.knowledge.finding_state import (
    derive_finding_confidence,
    derive_finding_state,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.finding_evidence import (
    COMPLETENESS_COMPLETE,
    derive_evidence_completeness,
    derive_evidence_origin,
)
from ai.schemas.finding_result import (
    ERROR_INVALID_INPUT,
    ERROR_LIMIT_EXCEEDED,
    ERROR_MALFORMED_SPECIALIST_RESULT,
    ERROR_SAFETY_BLOCKED,
    ERROR_UNKNOWN,
    ERROR_UNSUPPORTED_CATEGORY,
    FINDING_RESULT_RULE_VERSION,
    FINDING_STAGE_CODES,
    INTELLIGENCE_ID_PREFIX,
    LIMITATION_ADVISORY_UNAVAILABLE,
    LIMITATION_ASSET_CONTEXT_UNAVAILABLE,
    LIMITATION_COLLABORATION_UNAVAILABLE,
    LIMITATION_CONFLICT_PRESENT,
    LIMITATION_CORRELATION_UNAVAILABLE,
    LIMITATION_DUPLICATE_CORRELATION_PRESENT,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_EVALUATION_UNAVAILABLE,
    LIMITATION_FEEDBACK_UNAVAILABLE,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_IMPACT_NOT_OBSERVED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NO_EVIDENCE_COLLECTED,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_REMEDIATION_UNAVAILABLE,
    LIMITATION_RESEARCH_CANDIDATE_ONLY,
    LIMITATION_SEVERITY_NOT_ASSESSED,
    MAX_FINDINGS,
    SKIP_FORBIDDEN_CLAIM,
    SKIP_LIMIT_EXCEEDED,
    SKIP_MALFORMED_RESULT,
    SKIP_SAFETY_FAILURE,
    SKIP_UNSUPPORTED_CATEGORY,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_PARTIAL,
    FindingIntelligenceResultPlan,
    FindingPlan,
    build_finding_governance_reference,
    finding_intelligence_result_plan_projection,
    sanitize_finding_error,
    sanitize_finding_governance,
    sanitize_finding_skip,
)
from ai.schemas.finding_context import MAX_CONTEXT_FACTS
from ai.schemas.finding_hypothesis import (
    sanitize_finding_hypothesis_linkage,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES, CATEGORY_UNKNOWN

FINDING_BUILDER_RULE_VERSION = "r53-6"
RULE_VERSION = FINDING_BUILDER_RULE_VERSION

SUPPORTED_CATEGORIES: tuple[str, ...] = tuple(
    category for category in AGENT_CATEGORIES if category != CATEGORY_UNKNOWN
)

_BASE_FINDING_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_NO_EVIDENCE_COLLECTED,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_RESEARCH_CANDIDATE_ONLY,
)

_SKIP_TO_ERROR: dict[str, str] = {
    SKIP_SAFETY_FAILURE: ERROR_SAFETY_BLOCKED,
    SKIP_FORBIDDEN_CLAIM: ERROR_SAFETY_BLOCKED,
    SKIP_UNSUPPORTED_CATEGORY: ERROR_UNSUPPORTED_CATEGORY,
    SKIP_MALFORMED_RESULT: ERROR_MALFORMED_SPECIALIST_RESULT,
    SKIP_LIMIT_EXCEEDED: ERROR_LIMIT_EXCEEDED,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _error(
    error_category: str,
    category: str = "",
    message: str = "",
    stage: str = "FINDING_INTELLIGENCE",
) -> dict:
    return sanitize_finding_error(
        {
            "stage": stage,
            "error_category": error_category,
            "category": category,
            "message": message,
        }
    )


def _skip(category: str, agent_id: str, reason: str) -> dict:
    return sanitize_finding_skip(
        {"category": category, "agent_id": agent_id, "reason": reason}
    )


def _claim_text(result: dict) -> str:
    """Deterministic text projection of forbidden-claim channels."""

    parts: list[str] = []
    for item in result.get("limitations") or ():
        parts.append(str(item))
    for hypothesis in result.get("hypotheses") or ():
        if not isinstance(hypothesis, dict):
            continue
        parts.append(str(hypothesis.get("hypothesis_type") or ""))
        parts.append(
            " ".join(
                str(signal)
                for signal in hypothesis.get("supporting_signals") or ()
            )
        )
        parts.append(
            " ".join(
                str(code) for code in hypothesis.get("limitations") or ()
            )
        )
    evidence = result.get("evidence_plan") or {}
    if isinstance(evidence, dict):
        parts.append(" ".join(str(item) for item in evidence.get(
            "evidence_items") or ()))
        parts.append(" ".join(str(item) for item in evidence.get(
            "limitations") or ()))
        parts.append(str(evidence.get("evidence_state") or ""))
    provenance = result.get("provenance") or {}
    if isinstance(provenance, dict):
        parts.append(" ".join(str(item) for item in provenance.get(
            "source_layers") or ()))
    governance = result.get("governance_reference") or {}
    if isinstance(governance, dict):
        for key in (
            "provenance_state",
            "trace_state",
            "audit_state",
            "explanation_state",
            "reference_state",
        ):
            parts.append(str(governance.get(key) or ""))
    return " ".join(parts).upper()


def _has_forbidden_claim(result: dict) -> bool:
    text = _claim_text(result)
    return any(
        token in text
        for token in EXECUTION_CLAIM_TOKENS + CONFIRMATION_CLAIM_TOKENS
    )


def _normalize_entry(raw: object) -> tuple[dict, str]:
    """Normalize an R52-style entry or a raw specialist result."""

    if not isinstance(raw, dict):
        return {}, SKIP_MALFORMED_RESULT
    if "result" in raw and not isinstance(raw.get("result"), dict):
        return (
            {
                "category": _upper(raw.get("category")),
                "agent_id": _text(raw.get("agent_id")),
                "specialist_name": _text(raw.get("specialist_name")),
                "result": {},
            },
            SKIP_MALFORMED_RESULT,
        )
    if isinstance(raw.get("result"), dict):
        result = raw["result"]
        identity = (
            result.get("agent_identity")
            if isinstance(result.get("agent_identity"), dict)
            else {}
        )
        category = _upper(raw.get("category")) or _upper(
            identity.get("category")
        ) or _upper(result.get("agent_category"))
        agent_id = _text(raw.get("agent_id")) or _text(
            identity.get("agent_id")
        )
        specialist_name = _text(raw.get("specialist_name")) or _text(
            identity.get("agent_name")
        )
    else:
        result = raw
        identity = (
            result.get("agent_identity")
            if isinstance(result.get("agent_identity"), dict)
            else {}
        )
        category = _upper(identity.get("category")) or _upper(
            result.get("agent_category")
        )
        agent_id = _text(identity.get("agent_id")) or _text(
            result.get("agent_id")
        )
        specialist_name = _text(identity.get("agent_name")) or _text(
            result.get("agent_name")
        )
    if not result:
        return {}, SKIP_MALFORMED_RESULT
    if not category or category not in SUPPORTED_CATEGORIES:
        return (
            {
                "category": category,
                "agent_id": agent_id,
                "specialist_name": specialist_name,
                "result": result,
            },
            SKIP_UNSUPPORTED_CATEGORY,
        )
    return (
        {
            "category": category,
            "agent_id": agent_id,
            "specialist_name": specialist_name,
            "result": result,
        },
        "",
    )


def _evaluation_for(
    evaluations: list[dict], agent_id: str, category: str
) -> dict | None:
    for evaluation in evaluations:
        if not isinstance(evaluation, dict):
            continue
        if (
            evaluation.get("evaluated_agent_id") == agent_id
            and evaluation.get("evaluated_agent_category") == category
        ):
            return evaluation
    for evaluation in evaluations:
        if not isinstance(evaluation, dict):
            continue
        if (
            evaluation.get("evaluated_agent_id") == agent_id
            and agent_id
        ):
            return evaluation
    return None


def _safety_reason(result: dict, evaluation: dict | None) -> str:
    if not isinstance(result, dict) or not result:
        return SKIP_MALFORMED_RESULT
    if result.get("research_only") is not True:
        return SKIP_SAFETY_FAILURE
    if _has_forbidden_claim(result):
        return SKIP_FORBIDDEN_CLAIM
    if isinstance(evaluation, dict):
        if _upper(evaluation.get("safety_state")) == "FAILED":
            return SKIP_SAFETY_FAILURE
        if _upper(evaluation.get("hard_gate_state")) == "FAIL_SAFETY":
            return SKIP_SAFETY_FAILURE
    return ""


def _context_confidence(context: object) -> str:
    if not isinstance(context, dict):
        return ""
    value = _upper(context.get("context_confidence"))
    return value if value in CONFIDENCE_LEVELS else ""


def _hypothesis_confidence_summary(references: list[dict]) -> dict:
    ranks = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    known = [
        reference.get("confidence")
        for reference in references
        if reference.get("confidence") in ranks
        and reference.get("confidence") != "UNKNOWN"
    ]
    if not known:
        return {
            "highest_confidence": "UNKNOWN",
            "lowest_confidence": "UNKNOWN",
            "confidence_state": "UNKNOWN",
        }
    highest = max(known, key=lambda item: ranks[item])
    lowest = min(known, key=lambda item: ranks[item])
    state = "AGREE" if len(set(known)) == 1 else "DIVERGENT"
    return {
        "highest_confidence": highest,
        "lowest_confidence": lowest,
        "confidence_state": state,
    }


def _planned_requirements(evidence_plan: object) -> list[str]:
    if not isinstance(evidence_plan, dict):
        return []
    out: list[str] = []
    for item in evidence_plan.get("evidence_items") or ():
        text = _upper(item)
        if text and text not in out:
            out.append(text)
    return out


def _merged_requirements(collaboration: object, agent_id: str) -> list[dict]:
    if not isinstance(collaboration, dict) or not agent_id:
        return []
    merged = collaboration.get("merged_evidence") or {}
    if not isinstance(merged, dict):
        return []
    out: list[dict] = []
    for item in merged.get("evidence_items") or ():
        if not isinstance(item, dict):
            continue
        sources = [
            _text(source) for source in item.get("source_agents") or ()
        ]
        if agent_id in sources:
            out.append(item)
    return out


def _groups_for(collaboration: object, agent_id: str) -> list[dict]:
    if not isinstance(collaboration, dict) or not agent_id:
        return []
    out: list[dict] = []
    for group in collaboration.get("hypothesis_groups") or ():
        if not isinstance(group, dict):
            continue
        agents = [_text(item) for item in group.get("participating_agents") or ()]
        if agent_id in agents:
            out.append(group)
    return out


def _conflicts_for(collaboration: object, agent_id: str) -> list[dict]:
    if not isinstance(collaboration, dict) or not agent_id:
        return []
    out: list[dict] = []
    for conflict in collaboration.get("conflicts") or ():
        if not isinstance(conflict, dict):
            continue
        subjects = [_text(item) for item in conflict.get("subjects") or ()]
        if agent_id in subjects:
            out.append(conflict)
    return out


def _feedback_event_for(
    feedback: object, agent_id: str, category: str
) -> dict | None:
    if not isinstance(feedback, dict):
        return None
    for event in feedback.get("events") or ():
        if not isinstance(event, dict):
            continue
        if (
            _text(event.get("source_agent")) == agent_id
            and _upper(event.get("source_category")) == category
        ):
            return event
    return None


def _learning_recommendations_for(
    feedback: object, agent_id: str
) -> list[dict]:
    if not isinstance(feedback, dict) or not agent_id:
        return []
    out: list[dict] = []
    for recommendation in feedback.get("recommendations") or ():
        if not isinstance(recommendation, dict):
            continue
        if _text(recommendation.get("related_agent")) == agent_id:
            out.append(recommendation)
    return out


def _build_finding(
    entry: dict,
    evaluation: dict | None,
    collaboration: object,
    feedback: object,
    advisory: object,
    governance: dict,
    orchestration_id: str,
    source_stages: list[str],
) -> dict:
    category = entry["category"]
    agent_id = entry["agent_id"]
    specialist_name = entry["specialist_name"]
    result = entry["result"]

    context_analysis = result.get("context_analysis")
    hypotheses = [
        item
        for item in (result.get("hypotheses") or ())
        if isinstance(item, dict)
    ]
    evidence_plan = (
        result.get("evidence_plan")
        if isinstance(result.get("evidence_plan"), dict)
        else {}
    )
    plan_rule_version = _text(evidence_plan.get("rule_version"))
    context_rule_version = (
        _text(context_analysis.get("rule_version"))
        if isinstance(context_analysis, dict)
        else ""
    )
    planned = _planned_requirements(evidence_plan)
    merged = _merged_requirements(collaboration, agent_id)

    identity = _build_identity(
        category,
        specialist_name,
        agent_id,
        result.get("rule_version"),
        [
            _upper(hypothesis.get("hypothesis_type"))
            for hypothesis in hypotheses
        ],
        planned,
        context_rule_version,
    )

    hypothesis_references: list[dict] = []
    for index, hypothesis in enumerate(hypotheses):
        hypothesis_references.append(
            {
                "rule_version": _text(hypothesis.get("rule_version")),
                "agent_id": agent_id,
                "agent_category": category,
                "hypothesis_index": index,
                "hypothesis_type": hypothesis.get("hypothesis_type"),
                "supporting_signals": hypothesis.get("supporting_signals"),
                "confidence": hypothesis.get("confidence"),
                "priority": hypothesis.get("priority"),
                "limitations": hypothesis.get("limitations"),
                "subject_reference": hypothesis.get("subject_reference"),
                "rationale": hypothesis.get("rationale"),
                "fingerprint": hypothesis.get("fingerprint"),
                "research_only": True,
            }
        )
    hypothesis_linkage = sanitize_finding_hypothesis_linkage(
        {
            "references": hypothesis_references,
            "hypothesis_count": len(hypothesis_references),
            "hypothesis_types": [
                reference["hypothesis_type"]
                for reference in hypothesis_references
            ],
            "confidence_summary": _hypothesis_confidence_summary(
                hypothesis_references
            ),
            "research_only": True,
        }
    )

    evidence_state = _upper(evidence_plan.get("evidence_state")) or "UNKNOWN"
    evidence_completeness = derive_evidence_completeness(
        evidence_state, planned, merged
    )
    evidence_origin = derive_evidence_origin(planned, merged)

    observed = known_context_facts(context_analysis)
    observed = observed[:MAX_CONTEXT_FACTS]
    collaboration_id = (
        _text(collaboration.get("collaboration_id"))
        if isinstance(collaboration, dict)
        else ""
    )
    evidence_references: list[str] = []
    if agent_id:
        evidence_references.append(f"{agent_id}:evidence_plan")
    if collaboration_id and merged:
        evidence_references.append(
            f"collab:{collaboration_id}:merged_evidence"
        )

    groups = _groups_for(collaboration, agent_id)
    conflicts = _conflicts_for(collaboration, agent_id)
    conflict_count = len(conflicts)
    duplicate_groups = sum(
        1
        for group in groups
        if _upper(group.get("correlation_type")) == "DUPLICATE"
    )

    has_hypotheses = bool(hypothesis_references)
    evaluation_present = isinstance(evaluation, dict)
    evaluation_rating = (
        _upper(evaluation.get("overall_rating"))
        if evaluation_present
        else ""
    )
    safety_state = (
        _upper(evaluation.get("safety_state"))
        if evaluation_present
        else "UNKNOWN"
    )
    hard_gate_state = (
        _upper(evaluation.get("hard_gate_state"))
        if evaluation_present
        else ""
    )
    diagnostic_codes: list[str] = []
    if evaluation_present:
        for diagnostic in evaluation.get("diagnostics") or ():
            if isinstance(diagnostic, dict):
                code = _upper(diagnostic.get("diagnostic_code"))
                if code and code not in diagnostic_codes:
                    diagnostic_codes.append(code)

    state = derive_finding_state(
        status=result.get("status"),
        has_hypotheses=has_hypotheses,
        context_fact_count=len(observed),
        evidence_state=evidence_state,
        evidence_completeness=evidence_completeness,
        evidence_missing=not (planned or merged),
        conflict_count=conflict_count,
        evaluation_present=evaluation_present,
        evaluation_rating=evaluation_rating,
        safety_state=safety_state,
        hard_gate_state=hard_gate_state,
        diagnostic_codes=diagnostic_codes,
    )
    confidence = derive_finding_confidence(
        state=state,
        status=result.get("status"),
        result_confidence=result.get("confidence"),
        evidence_confidence=evidence_plan.get("confidence"),
        context_confidence=_context_confidence(context_analysis),
        evidence_state=evidence_state,
        evidence_completeness=evidence_completeness,
        evaluation_present=evaluation_present,
        evaluation_rating=evaluation_rating,
        safety_state=safety_state,
        hard_gate_state=hard_gate_state,
        diagnostic_codes=diagnostic_codes,
        conflict_count=conflict_count,
    )

    assessment = _build_assessment(
        category,
        state,
        confidence["confidence"],
        confidence["confidence_reasons"],
        context_analysis,
        evaluation,
        has_hypotheses,
    )
    assessment["evaluation_present"] = evaluation_present
    assessment["evaluation_rating"] = evaluation_rating
    assessment["hard_gate_state"] = hard_gate_state
    assessment["safety_state"] = safety_state
    assessment["diagnostic_codes"] = diagnostic_codes

    context_block = _build_context(
        category,
        specialist_name,
        context_analysis,
        hypotheses,
        {"planned_requirements": planned},
    )

    # References
    evaluation_reference = {"reference_state": "UNKNOWN"}
    if evaluation_present:
        evaluation_reference = {
            "reference_state": "REFERENCED",
            "reference_id": _text(evaluation.get("evaluated_agent_id")),
            "overall_rating": evaluation_rating,
            "safety_state": safety_state,
            "hard_gate_state": hard_gate_state,
            "diagnostic_codes": diagnostic_codes,
        }
    collaboration_reference = {"reference_state": "UNKNOWN"}
    if collaboration_id:
        collaboration_reference = {
            "reference_state": "REFERENCED",
            "collaboration_id": collaboration_id,
        }
    feedback_reference = {"reference_state": "UNKNOWN"}
    event = _feedback_event_for(feedback, agent_id, category)
    recommendations = _learning_recommendations_for(feedback, agent_id)
    if isinstance(event, dict):
        feedback_reference = {
            "reference_state": "REFERENCED",
            "feedback_id": _text(event.get("feedback_id")),
        }
    elif recommendations:
        feedback_reference = {"reference_state": "REFERENCED"}
    if recommendations:
        feedback_reference["recommendation_ids"] = [
            _text(recommendation.get("recommendation_id"))
            for recommendation in recommendations
            if _text(recommendation.get("recommendation_id"))
        ]
    advisory_reference = {"reference_state": "UNKNOWN"}
    if isinstance(advisory, dict) and _upper(
        advisory.get("provider_state")
    ) == "OK":
        advisory_result = advisory.get("advisory_result")
        advisory_id = (
            _text(advisory_result.get("advisory_id"))
            if isinstance(advisory_result, dict)
            else ""
        )
        advisory_reference = {
            "reference_state": "REFERENCED",
            "advisory_id": advisory_id,
            "provider_state": _upper(advisory.get("provider_state")),
            "provider_kind": _upper(advisory.get("provider_kind")),
            "validation_state": (
                _upper(advisory_result.get("validation_state"))
                if isinstance(advisory_result, dict)
                else ""
            ),
        }

    # Limitations
    limitations = list(_BASE_FINDING_LIMITATIONS)
    if (
        evidence_state != "COMPLETE"
        or evidence_completeness != COMPLETENESS_COMPLETE
    ):
        limitations.append(LIMITATION_EVIDENCE_REQUIRED)
    if not observed:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)
        limitations.append(LIMITATION_ASSET_CONTEXT_UNAVAILABLE)
    if governance.get("reference_state") != "REFERENCED":
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    if not evaluation_present:
        limitations.append(LIMITATION_EVALUATION_UNAVAILABLE)
    if not collaboration_id:
        limitations.append(LIMITATION_COLLABORATION_UNAVAILABLE)
        limitations.append(LIMITATION_CORRELATION_UNAVAILABLE)
    if not recommendations and not isinstance(event, dict):
        limitations.append(LIMITATION_FEEDBACK_UNAVAILABLE)
    if advisory_reference.get("reference_state") != "REFERENCED":
        limitations.append(LIMITATION_ADVISORY_UNAVAILABLE)
    if conflict_count:
        limitations.append(LIMITATION_CONFLICT_PRESENT)
    if duplicate_groups:
        limitations.append(LIMITATION_DUPLICATE_CORRELATION_PRESENT)
    if assessment.get("remediation_state") != "AVAILABLE":
        limitations.append(LIMITATION_REMEDIATION_UNAVAILABLE)
    if assessment.get("impact_state") != "OBSERVED":
        limitations.append(LIMITATION_IMPACT_NOT_OBSERVED)
    if assessment.get("severity_source") != "CVSS_CONTEXT":
        limitations.append(LIMITATION_SEVERITY_NOT_ASSESSED)

    finding = FindingPlan(
        rule_version=FINDING_RESULT_RULE_VERSION,
        finding_id=identity["finding_id"],
        state=state,
        identity=identity,
        context=context_block,
        hypotheses=hypothesis_linkage,
        evidence={
            "rule_version": plan_rule_version,
            "evidence_state": evidence_state,
            "evidence_completeness": evidence_completeness,
            "evidence_origin": evidence_origin,
            "observed_context": observed,
            "planned_requirements": planned,
            "merged_requirements": merged,
            "evidence_references": evidence_references,
            "evidence_missing": not (planned or merged),
            "assumptions_recorded": False,
            "research_only": True,
        },
        assessment=assessment,
        correlation={
            "rule_version": "",
            "groups": groups,
            "conflicts": conflicts,
            "research_only": True,
        },
        references={
            "evaluation": evaluation_reference,
            "collaboration": collaboration_reference,
            "feedback": feedback_reference,
            "advisory": advisory_reference,
        },
        learning_recommendations=recommendations,
        provenance={
            "rule_version": FINDING_RESULT_RULE_VERSION,
            "category": category,
            "specialist_name": specialist_name,
            "agent_id": agent_id,
            "orchestration_id": orchestration_id,
            "source_stages": [
                stage for stage in source_stages if stage in FINDING_STAGE_CODES
            ],
            "deterministic": True,
            "research_only": True,
        },
        governance=governance,
        limitations=limitations,
        research_only=True,
        deterministic=True,
    )
    return finding.model_dump(mode="json")


def _intelligence_id(
    orchestration_id: str,
    findings: list[dict],
    skipped: list[dict],
    collaboration_id: str,
) -> str:
    basis = json.dumps(
        {
            "rule_version": FINDING_RESULT_RULE_VERSION,
            "orchestration_id": orchestration_id,
            "collaboration_id": collaboration_id,
            "findings": [
                {
                    "finding_id": finding.get("finding_id"),
                    "state": finding.get("state"),
                }
                for finding in findings
            ],
            "skipped": [
                {
                    "category": item.get("category"),
                    "reason": item.get("reason"),
                }
                for item in skipped
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return INTELLIGENCE_ID_PREFIX + digest[:16]


def _container(
    *,
    orchestration_id: str,
    findings: list[dict],
    skipped: list[dict],
    errors: list[dict],
    evaluations: list[dict],
    collaboration: object,
    feedback: object,
    advisory: object,
    governance: dict,
    source_stages: list[str],
    fatal: bool = False,
) -> dict:
    collaboration_dict = (
        collaboration if isinstance(collaboration, dict) else {}
    )
    feedback_dict = feedback if isinstance(feedback, dict) else {}
    advisory_dict = advisory if isinstance(advisory, dict) else {}
    collaboration_id = _text(collaboration_dict.get("collaboration_id"))

    if fatal:
        status = STATUS_FAILED
    elif findings and (errors or skipped):
        status = STATUS_PARTIAL
    elif findings:
        status = STATUS_COMPLETED
    elif errors or skipped:
        status = STATUS_PARTIAL
    else:
        status = STATUS_NO_FINDINGS

    safety_states: list[str] = []
    diagnostic_count = 0
    for evaluation in evaluations:
        if not isinstance(evaluation, dict):
            continue
        state = _upper(evaluation.get("safety_state"))
        if state in ("PASS", "DEGRADED", "FAILED", "UNKNOWN") and (
            state not in safety_states
        ):
            safety_states.append(state)
        diagnostic_count += len(evaluation.get("diagnostics") or ())

    limitations = list(_BASE_FINDING_LIMITATIONS)
    if governance.get("reference_state") != "REFERENCED":
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    if not evaluations:
        limitations.append(LIMITATION_EVALUATION_UNAVAILABLE)
    if not collaboration_id:
        limitations.append(LIMITATION_COLLABORATION_UNAVAILABLE)
        limitations.append(LIMITATION_CORRELATION_UNAVAILABLE)
    if not feedback_dict.get("recommendations") and not feedback_dict.get(
        "events"
    ):
        limitations.append(LIMITATION_FEEDBACK_UNAVAILABLE)
    if _upper(advisory_dict.get("provider_state")) != "OK":
        limitations.append(LIMITATION_ADVISORY_UNAVAILABLE)

    result = FindingIntelligenceResultPlan(
        rule_version=FINDING_RESULT_RULE_VERSION,
        intelligence_id=_intelligence_id(
            orchestration_id, findings, skipped, collaboration_id
        ),
        orchestration_id=orchestration_id,
        status=status,
        findings=findings,
        skipped_candidates=skipped,
        evaluation_summary={
            "present": bool(evaluations),
            "evaluated_count": len(evaluations),
            "safety_states": safety_states,
            "diagnostic_count": diagnostic_count,
        },
        collaboration_reference=(
            {
                "present": bool(collaboration_id),
                "collaboration_id": collaboration_id,
                "participant_count": len(
                    collaboration_dict.get("participating_agents") or ()
                ),
                "conflict_count": len(
                    collaboration_dict.get("conflicts") or ()
                ),
                "duplicate_group_count": sum(
                    1
                    for group in collaboration_dict.get("hypothesis_groups")
                    or ()
                    if isinstance(group, dict)
                    and _upper(group.get("correlation_type")) == "DUPLICATE"
                ),
                "related_group_count": sum(
                    1
                    for group in collaboration_dict.get("hypothesis_groups")
                    or ()
                    if isinstance(group, dict)
                    and _upper(group.get("correlation_type")) == "RELATED"
                ),
            }
            if collaboration_id
            else {"present": False}
        ),
        learning_reference={
            "present": bool(
                feedback_dict.get("events")
                or feedback_dict.get("recommendations")
            ),
            "event_count": len(feedback_dict.get("events") or ()),
            "classification_count": len(
                feedback_dict.get("classifications") or ()
            ),
            "signal_count": len(
                feedback_dict.get("learning_signals") or ()
            ),
            "recommendation_count": len(
                feedback_dict.get("recommendations") or ()
            ),
        },
        advisory_reference=(
            {
                "present": True,
                "provider_state": _upper(
                    advisory_dict.get("provider_state")
                ),
                "provider_kind": _upper(advisory_dict.get("provider_kind")),
                "validation_state": (
                    _upper(
                        (advisory_dict.get("advisory_result") or {}).get(
                            "validation_state"
                        )
                    )
                    if isinstance(
                        advisory_dict.get("advisory_result"), dict
                    )
                    else ""
                ),
                "safety_state": (
                    _upper(
                        (advisory_dict.get("advisory_result") or {}).get(
                            "safety_state"
                        )
                    )
                    if isinstance(
                        advisory_dict.get("advisory_result"), dict
                    )
                    else ""
                ),
                "advisory_id": (
                    _text(
                        (advisory_dict.get("advisory_result") or {}).get(
                            "advisory_id"
                        )
                    )
                    if isinstance(
                        advisory_dict.get("advisory_result"), dict
                    )
                    else ""
                ),
            }
            if advisory_dict
            else {"present": False}
        ),
        errors=errors,
        provenance={
            "rule_version": FINDING_RESULT_RULE_VERSION,
            "orchestration_id": orchestration_id,
            "finding_count": len(findings),
            "source_stages": [
                stage for stage in source_stages if stage in FINDING_STAGE_CODES
            ],
            "deterministic": True,
            "research_only": True,
        },
        governance=governance,
        limitations=limitations,
        research_only=True,
        deterministic=True,
    )
    return finding_intelligence_result_plan_projection(result)


def _fatal_result(
    errors: list[dict], governance_plan: object
) -> dict:
    governance = build_finding_governance_reference(governance_plan)
    return _container(
        orchestration_id="",
        findings=[],
        skipped=[],
        errors=errors,
        evaluations=[],
        collaboration=None,
        feedback=None,
        advisory=None,
        governance=governance,
        source_stages=["FINDING_INTELLIGENCE"],
        fatal=True,
    )


def build_finding_intelligence(
    orchestration_result: object = None,
    specialist_results: object = None,
    evaluation_results: object = None,
    collaboration_result: object = None,
    feedback_result: object = None,
    governance_plan: object = None,
) -> dict:
    """Build deterministic research finding candidates (read-only).

    Supply either one R52 orchestration result or standalone structured
    specialist results (with optional R42/R43/R44 artifacts). R53 creates
    research finding candidates only: nothing is executed, no vulnerability
    is confirmed, and unsafe or malformed candidates are skipped with
    structured reasons.
    """

    # ------------------------------------------------------------------
    # Input validation (fail closed)
    # ------------------------------------------------------------------
    if orchestration_result is not None and not isinstance(
        orchestration_result, dict
    ):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message="orchestration_result must be a mapping",
                )
            ],
            governance_plan,
        )
    if orchestration_result is not None and any(
        value is not None
        for value in (
            specialist_results,
            evaluation_results,
            collaboration_result,
            feedback_result,
        )
    ):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message=(
                        "supply either an orchestration_result or standalone "
                        "specialist inputs, not both"
                    ),
                )
            ],
            governance_plan,
        )
    for name, value, expected in (
        ("specialist_results", specialist_results, (list, tuple)),
        ("evaluation_results", evaluation_results, (list, tuple)),
    ):
        if value is not None and not isinstance(value, expected):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message=f"{name} must be a list",
                    )
                ],
                governance_plan,
            )
    for name, value in (
        ("collaboration_result", collaboration_result),
        ("feedback_result", feedback_result),
        ("governance_plan", governance_plan),
    ):
        if value is not None and not isinstance(value, dict):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message=f"{name} must be a mapping",
                    )
                ],
                governance_plan,
            )

    # ------------------------------------------------------------------
    # Normalize the structured inputs
    # ------------------------------------------------------------------
    orchestration_id = ""
    source_stages: list[str] = ["FINDING_INTELLIGENCE"]
    if isinstance(orchestration_result, dict):
        raw_entries = orchestration_result.get("specialist_results") or []
        evaluations = list(
            orchestration_result.get("evaluation_results") or []
        )
        collaboration = orchestration_result.get("collaboration_result")
        feedback = orchestration_result.get("feedback_result")
        advisory = orchestration_result.get("advisory_result")
        orchestration_id = _text(
            orchestration_result.get("orchestration_id")
        )
        provenance = orchestration_result.get("provenance") or {}
        if isinstance(provenance, dict):
            source_stages = [
                stage
                for stage in provenance.get("stages") or ()
                if stage in FINDING_STAGE_CODES
            ] + ["FINDING_INTELLIGENCE"]
        governance = sanitize_finding_governance(
            orchestration_result.get("governance")
        )
        if governance.get("reference_state") != "REFERENCED":
            governance = build_finding_governance_reference(
                governance_plan
            )
    else:
        raw_entries = list(specialist_results or [])
        evaluations = list(evaluation_results or [])
        collaboration = collaboration_result
        feedback = feedback_result
        advisory = None
        governance = build_finding_governance_reference(governance_plan)

    # ------------------------------------------------------------------
    # Build finding candidates (deterministic canonical order)
    # ------------------------------------------------------------------
    findings: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []

    for raw in raw_entries:
        entry, skip_reason = _normalize_entry(raw)
        category = entry.get("category", "")
        agent_id = entry.get("agent_id", "")
        if skip_reason:
            skipped.append(_skip(category, agent_id, skip_reason))
            errors.append(
                _error(
                    _SKIP_TO_ERROR.get(skip_reason, ERROR_UNKNOWN),
                    category,
                    "specialist result is not a supported finding source",
                )
            )
            continue
        evaluation = _evaluation_for(evaluations, agent_id, category)
        safety_reason = _safety_reason(entry["result"], evaluation)
        if safety_reason:
            skipped.append(_skip(category, agent_id, safety_reason))
            errors.append(
                _error(
                    _SKIP_TO_ERROR.get(safety_reason, ERROR_SAFETY_BLOCKED),
                    category,
                    "unsafe specialist result cannot become a finding",
                )
            )
            continue
        if len(findings) >= MAX_FINDINGS:
            skipped.append(_skip(category, agent_id, SKIP_LIMIT_EXCEEDED))
            errors.append(
                _error(
                    ERROR_LIMIT_EXCEEDED,
                    category,
                    "finding limit reached",
                )
            )
            continue
        try:
            finding = _build_finding(
                entry,
                evaluation,
                collaboration,
                feedback,
                advisory,
                governance,
                orchestration_id,
                source_stages,
            )
        except Exception:
            skipped.append(_skip(category, agent_id, SKIP_MALFORMED_RESULT))
            errors.append(
                _error(
                    ERROR_MALFORMED_SPECIALIST_RESULT,
                    category,
                    "finding construction failed",
                )
            )
            continue
        findings.append(finding)

    return _container(
        orchestration_id=orchestration_id,
        findings=findings,
        skipped=skipped,
        errors=errors,
        evaluations=evaluations,
        collaboration=collaboration,
        feedback=feedback,
        advisory=advisory,
        governance=governance,
        source_stages=source_stages,
    )


def findings_from_orchestration(orchestration_result: object = None) -> dict:
    """Alias: build finding intelligence from an R52 orchestration result."""

    return build_finding_intelligence(
        orchestration_result=orchestration_result
    )


def export_finding_intelligence(**kwargs) -> dict:
    """Alias for :func:`build_finding_intelligence` (project naming)."""

    return build_finding_intelligence(**kwargs)


__all__ = [
    "FINDING_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "SUPPORTED_CATEGORIES",
    "build_finding_intelligence",
    "findings_from_orchestration",
    "export_finding_intelligence",
]
