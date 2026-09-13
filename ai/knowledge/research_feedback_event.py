"""Stage R44.1 deterministic feedback event builder (pure engine).

Builds a bounded feedback event from previous structured research outcomes
(R42 evaluation results, R43 collaboration results, specialist attribution):

    "What did previous structured research produce that future research
     should consider?"

Hard boundaries encoded here:

- Learning only: consumes already-structured artifacts; it does not execute
  agents, run tests, access the network/database/browser, or call an LLM.
- R42/R43 are consumed, never recomputed.
- No runtime identity: the feedback id is a deterministic content token or a
  caller-supplied validated token; no timestamps, UUIDs or runtime ids.
- Malformed inputs are preserved through structural flags; nothing is
  silently accepted.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.schemas.agent_evaluation_result import (
    sanitize_agent_evaluation_result_plan,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.multi_agent_collaboration_result import (
    sanitize_multi_agent_collaboration_result,
)
from ai.schemas.research_feedback_event import (
    FEEDBACK_ID_PREFIX,
    FEEDBACK_ID_RE,
    FEEDBACK_STRUCTURAL_FLAGS,
    FLAG_INVALID_ENUM_VALUE,
    FLAG_MALFORMED_COLLABORATION_REFERENCE,
    FLAG_MALFORMED_EVALUATION_REFERENCE,
    FLAG_MALFORMED_GOVERNANCE,
    FLAG_MALFORMED_PROVENANCE,
    FLAG_MISSING_REQUIRED_FIELD,
    FLAG_NON_DETERMINISTIC_INPUT,
    FLAG_UNKNOWN_SOURCE_CATEGORY,
    ISSUE_NONE_OBSERVED,
    ISSUE_UNKNOWN,
    OBSERVED_ISSUES,
    OBSERVED_SUCCESSES,
    OUTCOME_TYPES,
    OUTCOME_UNKNOWN,
    RESEARCH_FEEDBACK_EVENT_RULE_VERSION,
    ResearchFeedbackEventPlan,
    SUCCESS_NONE_OBSERVED,
    SUCCESS_UNKNOWN,
    sanitize_feedback_collaboration_reference,
    sanitize_feedback_evaluation_reference,
    sanitize_feedback_governance,
    sanitize_feedback_provenance,
    sanitize_research_feedback_event,
    research_feedback_event_plan_projection,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

RESEARCH_FEEDBACK_EVENT_BUILDER_RULE_VERSION = "r44-1"
RULE_VERSION = RESEARCH_FEEDBACK_EVENT_BUILDER_RULE_VERSION

NONDETERMINISTIC_KEY_TOKENS: tuple[str, ...] = (
    "timestamp",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "evaluated_at",
    "runtime_id",
    "nonce",
    "uuid",
    "random",
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _has_nondeterministic_keys(value: object, depth: int = 0) -> bool:
    if depth > 4:
        return False
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key).lower()
            if any(token in name for token in NONDETERMINISTIC_KEY_TOKENS):
                return True
            if _has_nondeterministic_keys(child, depth + 1):
                return True
    elif isinstance(value, (list, tuple)):
        for item in list(value)[:32]:
            if _has_nondeterministic_keys(item, depth + 1):
                return True
    return False


def _evaluation_reference(value: object) -> dict:
    if not isinstance(value, dict):
        return sanitize_feedback_evaluation_reference(None)
    result = sanitize_agent_evaluation_result_plan(value)
    scores: dict[str, int] = {}
    for item in result.get("dimension_scores") or ():
        if not isinstance(item, dict):
            continue
        dimension = _text(item.get("dimension")).upper()
        score = item.get("score")
        if isinstance(score, bool) or not isinstance(score, int):
            continue
        scores[dimension] = max(0, min(100, score))
    diagnostics = [
        _text(item.get("diagnostic_code")).upper()
        for item in result.get("diagnostics") or ()
        if isinstance(item, dict) and _text(item.get("diagnostic_code"))
    ]
    return sanitize_feedback_evaluation_reference(
        {
            "present": True,
            "overall_score": result.get("overall_score"),
            "overall_rating": result.get("overall_rating"),
            "hard_gate_state": result.get("hard_gate_state"),
            "safety_state": result.get("safety_state"),
            "structural_score": scores.get("STRUCTURAL_VALIDITY", 0),
            "safety_score": scores.get("SAFETY_COMPLIANCE", 0),
            "evidence_score": scores.get("EVIDENCE_COMPLETENESS", 0),
            "confidence_score": scores.get(
                "CONFIDENCE_CALIBRATION", 0
            ),
            "dimension_scores_present": bool(scores),
            "diagnostic_codes": diagnostics,
            "deterministic": result.get("deterministic"),
            "research_only": result.get("research_only"),
        }
    )


def _collaboration_reference(value: object) -> dict:
    if not isinstance(value, dict):
        return sanitize_feedback_collaboration_reference(None)
    result = sanitize_multi_agent_collaboration_result(value)
    conflict_types: list[str] = []
    for item in result.get("conflicts") or ():
        if not isinstance(item, dict):
            continue
        text = _text(item.get("conflict_type")).upper()
        if text and text not in conflict_types:
            conflict_types.append(text)
    duplicate_groups = 0
    related_groups = 0
    for group in result.get("hypothesis_groups") or ():
        if not isinstance(group, dict):
            continue
        correlation_type = _text(group.get("correlation_type")).upper()
        if correlation_type == "DUPLICATE":
            duplicate_groups += 1
        elif correlation_type == "RELATED":
            related_groups += 1
    evidence = result.get("merged_evidence") or {}
    return sanitize_feedback_collaboration_reference(
        {
            "present": True,
            "participant_count": len(
                result.get("participating_agents") or ()
            ),
            "conflict_count": len(result.get("conflicts") or ()),
            "conflict_types": conflict_types,
            "duplicate_group_count": duplicate_groups,
            "related_group_count": related_groups,
            "merged_evidence_state": evidence.get("evidence_state"),
            "ranking_count": len(
                result.get("collaboration_rankings") or ()
            ),
            "deterministic": result.get("deterministic"),
            "research_only": result.get("research_only"),
        }
    )


def _participant_reference(
    collaboration_result: object,
    source_agent: str,
) -> tuple[dict, dict]:
    """Extract provenance and governance from a matching participant."""

    if not isinstance(collaboration_result, dict):
        return {}, {}
    result = sanitize_multi_agent_collaboration_result(
        collaboration_result
    )
    for agent in result.get("participating_agents") or ():
        if not isinstance(agent, dict):
            continue
        if _text(agent.get("agent_id")) == source_agent:
            return (
                sanitize_feedback_provenance(agent.get("provenance")),
                {},
            )
    return {}, {}


def _deterministic_feedback_id(
    category: str,
    agent: str,
    outcome_type: str,
    observed_issue: str,
    observed_success: str,
    evaluation_reference: dict,
    collaboration_reference: dict,
) -> str:
    basis = "|".join(
        [
            RESEARCH_FEEDBACK_EVENT_RULE_VERSION,
            category,
            agent,
            outcome_type,
            observed_issue,
            observed_success,
            hashlib.sha256(
                json.dumps(
                    evaluation_reference, sort_keys=True
                ).encode("utf-8")
            ).hexdigest()[:16],
            hashlib.sha256(
                json.dumps(
                    collaboration_reference, sort_keys=True
                ).encode("utf-8")
            ).hexdigest()[:16],
        ]
    )
    return FEEDBACK_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


def build_research_feedback_event(
    source_agent: object = None,
    source_category: object = None,
    evaluation_result: object = None,
    collaboration_result: object = None,
    outcome_type: object = None,
    observed_issue: object = None,
    observed_success: object = None,
    confidence: object = None,
    provenance: object = None,
    governance_reference: object = None,
    feedback_id: object = None,
) -> dict:
    """Build the deterministic feedback event (read-only).

    R42 evaluation and R43 collaboration results are projected into bounded
    references; malformed inputs raise structural flags rather than being
    silently discarded.
    """

    flags: list[str] = []

    evaluation_raw = evaluation_result
    if evaluation_raw is not None and not isinstance(
        evaluation_raw, dict
    ):
        flags.append(FLAG_MALFORMED_EVALUATION_REFERENCE)
        evaluation_raw = None
    collaboration_raw = collaboration_result
    if collaboration_raw is not None and not isinstance(
        collaboration_raw, dict
    ):
        flags.append(FLAG_MALFORMED_COLLABORATION_REFERENCE)
        collaboration_raw = None
    if provenance is not None and not isinstance(provenance, dict):
        flags.append(FLAG_MALFORMED_PROVENANCE)
        provenance = None
    if governance_reference is not None and not isinstance(
        governance_reference, dict
    ):
        flags.append(FLAG_MALFORMED_GOVERNANCE)
        governance_reference = None

    evaluation = _evaluation_reference(evaluation_raw)
    collaboration = _collaboration_reference(collaboration_raw)

    resolved_agent = _text(source_agent) or _text(
        evaluation_raw.get("evaluated_agent_id")
        if isinstance(evaluation_raw, dict) else ""
    )

    resolved_category = _text(source_category).upper()
    if not resolved_category:
        resolved_category = _text(
            evaluation_raw.get("evaluated_agent_category")
            if isinstance(evaluation_raw, dict) else ""
        ).upper()
    if not resolved_category:
        resolved_category = "UNKNOWN"
    if resolved_category not in AGENT_CATEGORIES:
        flags.append(FLAG_INVALID_ENUM_VALUE)
        resolved_category = "UNKNOWN"
    if resolved_category == "UNKNOWN":
        flags.append(FLAG_UNKNOWN_SOURCE_CATEGORY)

    resolved_outcome = _text(outcome_type).upper()
    if not resolved_outcome:
        flags.append(FLAG_MISSING_REQUIRED_FIELD)
        resolved_outcome = OUTCOME_UNKNOWN
    elif resolved_outcome not in OUTCOME_TYPES:
        flags.append(FLAG_INVALID_ENUM_VALUE)
        resolved_outcome = OUTCOME_UNKNOWN

    resolved_issue = _text(observed_issue).upper() or ISSUE_NONE_OBSERVED
    if resolved_issue not in OBSERVED_ISSUES:
        flags.append(FLAG_INVALID_ENUM_VALUE)
        resolved_issue = ISSUE_UNKNOWN

    resolved_success =(
        _text(observed_success).upper() or SUCCESS_NONE_OBSERVED
    )
    if resolved_success not in OBSERVED_SUCCESSES:
        flags.append(FLAG_INVALID_ENUM_VALUE)
        resolved_success = SUCCESS_UNKNOWN

    resolved_confidence = _text(confidence).upper()
    if resolved_confidence not in CONFIDENCE_LEVELS:
        resolved_confidence = "UNKNOWN"

    participant_provenance, participant_governance = (
        _participant_reference(collaboration_raw, resolved_agent)
    )
    resolved_provenance = (
        sanitize_feedback_provenance(provenance)
        if isinstance(provenance, dict)
        else participant_provenance
    )
    resolved_governance = (
        sanitize_feedback_governance(governance_reference)
        if isinstance(governance_reference, dict)
        else participant_governance
    )

    if _has_nondeterministic_keys(evaluation_raw) or (
        _has_nondeterministic_keys(collaboration_raw)
    ):
        flags.append(FLAG_NON_DETERMINISTIC_INPUT)

    provided_id = _text(feedback_id)
    if provided_id and FEEDBACK_ID_RE.match(provided_id):
        resolved_id = provided_id
    else:
        resolved_id = _deterministic_feedback_id(
            resolved_category,
            resolved_agent,
            resolved_outcome,
            resolved_issue,
            resolved_success,
            evaluation,
            collaboration,
        )

    sanitized = sanitize_research_feedback_event(
        {
            "rule_version": RESEARCH_FEEDBACK_EVENT_RULE_VERSION,
            "feedback_id": resolved_id,
            "source_agent": resolved_agent,
            "source_category": resolved_category,
            "evaluation_reference": evaluation,
            "collaboration_reference": collaboration,
            "outcome_type": resolved_outcome,
            "observed_issue": resolved_issue,
            "observed_success": resolved_success,
            "confidence": resolved_confidence,
            "provenance": resolved_provenance,
            "governance_reference": resolved_governance,
            "research_only": True,
            "structural_flags": flags,
        }
    )
    sanitized["rule_version"] = RESEARCH_FEEDBACK_EVENT_RULE_VERSION
    ordered_flags: list[str] = []
    for flag in FEEDBACK_STRUCTURAL_FLAGS:
        if flag in flags and flag not in ordered_flags:
            ordered_flags.append(flag)
    sanitized["structural_flags"] = ordered_flags

    plan = ResearchFeedbackEventPlan(**sanitized)
    return research_feedback_event_plan_projection(plan)


__all__ = [
    "RESEARCH_FEEDBACK_EVENT_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "NONDETERMINISTIC_KEY_TOKENS",
    "build_research_feedback_event",
]
