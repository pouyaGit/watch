"""Stage R43.5 deterministic collaboration export (pure engine).

Builds the unified multi-agent research collaboration result:

    specialist results
        -> collaboration input
        -> shared context
        -> hypothesis correlation
        -> evidence merge
        -> conflict analysis
        -> evaluation-aware ranking
        -> unified research result

Hard boundaries encoded here:

- Collaboration only: no agent execution, no subprocess, no network, no
  database, no browser, no LLM, no payloads, no scanning.
- R42 is consumed, never recomputed: evaluation results are used only as
  structured signals; the overall evaluation score is never interpreted as
  vulnerability probability, severity or exploitability.
- Safety is a hard boundary: critically unsafe results cannot outrank safe
  results, regardless of numerical confidence.
- Deterministic: rankings, summaries and the unified result are pure
  functions of the bounded input.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.collaboration_conflict_analyzer import (
    analyze_collaboration_conflicts,
)
from ai.knowledge.collaboration_evidence_merger import (
    merge_collaboration_evidence,
)
from ai.knowledge.hypothesis_correlator import correlate_hypotheses
from ai.knowledge.multi_agent_collaboration_input import (
    build_multi_agent_collaboration_input,
)
from ai.knowledge.shared_research_context import (
    shared_context_summary,
)
from ai.schemas.agent_evaluation_score import rating_for_score
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.multi_agent_collaboration_input import (
    sanitize_multi_agent_collaboration_input,
)
from ai.schemas.multi_agent_collaboration_result import (
    COLLABORATION_LIMITATIONS,
    DEGRADED_SAFETY_CEILING,
    FAILED_SAFETY_CEILING,
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN as SUMMARY_GOVERNANCE_UNKNOWN,
    FACTOR_EVALUATION_QUALITY,
    FACTOR_EVIDENCE_COMPLETENESS,
    FACTOR_GOVERNANCE_STATE,
    FACTOR_HYPOTHESIS_PRIORITY,
    FACTOR_PROVENANCE_COMPLETENESS,
    FACTOR_SAFETY_STATE,
    FACTOR_SPECIALIST_CONFIDENCE,
    MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION,
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN as SUMMARY_PROVENANCE_UNKNOWN,
    RANKING_WEIGHTS,
    SAFETY_BUCKET_DEGRADED,
    SAFETY_BUCKET_FAILED,
    SAFETY_BUCKET_SAFE,
    TOTAL_RANKING_WEIGHT,
    CollaborationRankingPlan,
    MultiAgentCollaborationResultPlan,
    collaboration_ranking_plan_projection,
    multi_agent_collaboration_result_plan_projection,
)
from ai.schemas.shared_research_context import SOURCE_LAYERS

MULTI_AGENT_COLLABORATION_EXPORTER_RULE_VERSION = "r43-6"
RULE_VERSION = MULTI_AGENT_COLLABORATION_EXPORTER_RULE_VERSION

CONFIDENCE_COMPONENTS: dict[str, int] = {
    "HIGH": 100,
    "MEDIUM": 70,
    "LOW": 40,
    "UNKNOWN": 20,
}

PRIORITY_COMPONENTS: dict[str, int] = {
    "HIGH": 100,
    "MEDIUM": 70,
    "LOW": 40,
    "UNKNOWN": 20,
}

EVIDENCE_COMPONENTS: dict[str, int] = {
    "COMPLETE": 100,
    "PARTIAL": 60,
    "UNKNOWN": 20,
}

PROVENANCE_COMPONENTS: dict[str, int] = {
    "COMPLETE": 100,
    "PARTIAL": 70,
    "UNKNOWN": 20,
}

SAFETY_COMPONENTS: dict[str, int] = {
    "PASS": 100,
    "DEGRADED": 50,
    "FAILED": 0,
}

EVALUATION_ABSENT_COMPONENT = 40

EXECUTION_CLAIM_TOKENS: tuple[str, ...] = (
    "PAYLOAD_SENT",
    "PAYLOAD_EXECUTED",
    "COMMAND_EXECUTED",
    "ATTACK_PERFORMED",
    "SCAN_PERFORMED",
    "EXPLOITED",
    "EXECUTED",
)

CONFIRMATION_CLAIM_TOKENS: tuple[str, ...] = (
    "VULNERABILITY_CONFIRMED",
    "CONFIRMED_VULNERABILITY",
    "CONFIRMED_EXPLOIT",
    "EXPLOIT_CONFIRMED",
    "IS_VULNERABLE",
    "VULNERABILITY_FOUND",
)


def _clamp(component: object, fallback: int = 20) -> int:
    if isinstance(component, bool) or not isinstance(component, int):
        return fallback
    return max(0, min(100, component))


def _claim_text(result: dict) -> str:
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
                str(code)
                for code in hypothesis.get("limitations") or ()
            )
        )
    return " ".join(parts).upper()


def _has_forbidden_claim(result: dict) -> bool:
    text = _claim_text(result)
    return any(
        token in text
        for token in EXECUTION_CLAIM_TOKENS + CONFIRMATION_CLAIM_TOKENS
    )


def _evaluation_for(
    evaluations: list[dict],
    agent_id: str,
    agent_category: str,
) -> dict | None:
    for evaluation in evaluations:
        if (
            evaluation.get("agent_id") == agent_id
            and evaluation.get("agent_category") == agent_category
        ):
            return evaluation
    for evaluation in evaluations:
        if evaluation.get("agent_id") == agent_id:
            return evaluation
    return None


def _safety_state(result: dict, evaluation: dict | None) -> str:
    if not result.get("research_only", True):
        return "FAILED"
    if _has_forbidden_claim(result):
        return "FAILED"
    if evaluation is not None:
        evaluation_safety = str(
            evaluation.get("safety_state") or ""
        ).upper()
        if evaluation_safety == "FAILED":
            return "FAILED"
        if (
            str(evaluation.get("hard_gate_state") or "").upper()
            == "FAIL_SAFETY"
        ):
            return "FAILED"
        if evaluation_safety == "DEGRADED":
            return "DEGRADED"
    return "PASS"


def _priority_component(result: dict) -> int:
    best = 20
    for hypothesis in result.get("hypotheses") or ():
        if not isinstance(hypothesis, dict):
            continue
        priority = str(hypothesis.get("priority") or "UNKNOWN").upper()
        best = max(best, PRIORITY_COMPONENTS.get(priority, 20))
    return best


def _provenance_state(result: dict) -> str:
    provenance = result.get("provenance") or {}
    state = str(
        provenance.get("provenance_state") or "UNKNOWN"
    ).upper()
    if state not in ("COMPLETE", "PARTIAL"):
        return "UNKNOWN"
    return state


def _governance_component(result: dict) -> int:
    governance = result.get("governance_reference") or {}
    state = str(governance.get("reference_state") or "UNKNOWN").upper()
    if state != "REFERENCED":
        return 30
    if governance.get("ready") is True:
        return 100
    return 70


def _rank_collaborators(collaboration: dict) -> list[dict]:
    results = [
        result
        for result in collaboration.get("specialist_results") or ()
        if isinstance(result, dict)
    ]
    evaluations = [
        evaluation
        for evaluation in collaboration.get("evaluation_results") or ()
        if isinstance(evaluation, dict)
    ]
    rankings: list[dict] = []
    for result in results:
        agent_id = result.get("agent_id") or ""
        agent_category = result.get("agent_category") or "UNKNOWN"
        evaluation = _evaluation_for(
            evaluations, agent_id, agent_category
        )
        safety_state = _safety_state(result, evaluation)
        evidence_state = str(
            (result.get("evidence_plan") or {}).get("evidence_state")
            or "UNKNOWN"
        ).upper()
        confidence = str(
            result.get("result_confidence") or "UNKNOWN"
        ).upper()
        if confidence not in CONFIDENCE_LEVELS:
            confidence = "UNKNOWN"
        factors = {
            FACTOR_SPECIALIST_CONFIDENCE: _clamp(
                CONFIDENCE_COMPONENTS.get(confidence, 20)
            ),
            FACTOR_HYPOTHESIS_PRIORITY: _priority_component(result),
            FACTOR_EVALUATION_QUALITY: _clamp(
                evaluation.get("overall_score")
                if evaluation is not None
                else EVALUATION_ABSENT_COMPONENT,
                EVALUATION_ABSENT_COMPONENT,
            ),
            FACTOR_EVIDENCE_COMPLETENESS: _clamp(
                EVIDENCE_COMPONENTS.get(evidence_state, 20)
            ),
            FACTOR_PROVENANCE_COMPLETENESS: _clamp(
                PROVENANCE_COMPONENTS.get(
                    _provenance_state(result), 20
                )
            ),
            FACTOR_GOVERNANCE_STATE: _clamp(
                _governance_component(result)
            ),
            FACTOR_SAFETY_STATE: _clamp(
                SAFETY_COMPONENTS.get(safety_state, 0)
            ),
        }
        weighted = sum(
            factors[factor] * RANKING_WEIGHTS[factor]
            for factor in RANKING_WEIGHTS
        )
        raw_score = (
            (weighted + (TOTAL_RANKING_WEIGHT // 2)) // TOTAL_RANKING_WEIGHT
            if TOTAL_RANKING_WEIGHT
            else 0
        )
        if safety_state == "FAILED":
            safety_bucket = SAFETY_BUCKET_FAILED
            raw_score = min(raw_score, FAILED_SAFETY_CEILING)
        elif safety_state == "DEGRADED":
            safety_bucket = SAFETY_BUCKET_DEGRADED
            raw_score = min(raw_score, DEGRADED_SAFETY_CEILING)
        else:
            safety_bucket = SAFETY_BUCKET_SAFE
        rankings.append(
            {
                "agent_id": agent_id,
                "agent_category": agent_category,
                "priority_score": raw_score,
                "priority_rating": rating_for_score(raw_score),
                "rank": 0,
                "factors": factors,
                "safety_state": safety_state,
                "safety_bucket": safety_bucket,
                "evaluation_present": evaluation is not None,
            }
        )

    rankings.sort(
        key=lambda entry: (
            entry["safety_bucket"],
            -entry["priority_score"],
            entry["agent_id"],
        )
    )
    ordered: list[dict] = []
    for index, entry in enumerate(rankings):
        ordered.append(
            collaboration_ranking_plan_projection(
                CollaborationRankingPlan(
                    rule_version=(
                        MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION
                    ),
                    agent_id=entry["agent_id"],
                    agent_category=entry["agent_category"],
                    priority_score=entry["priority_score"],
                    priority_rating=entry["priority_rating"],
                    rank=index + 1,
                    factors=entry["factors"],
                    safety_state=entry["safety_state"],
                    safety_bucket=entry["safety_bucket"],
                    evaluation_present=entry["evaluation_present"],
                )
            )
        )
    return ordered


def _governance_summary(collaboration: dict) -> dict:
    referenced: list[str] = []
    unknown: list[str] = []
    ready: list[str] = []
    not_ready: list[str] = []
    for result in collaboration.get("specialist_results") or ():
        if not isinstance(result, dict):
            continue
        label = result.get("agent_id") or ""
        governance = result.get("governance_reference") or {}
        state = str(
            governance.get("reference_state") or "UNKNOWN"
        ).upper()
        if state == "REFERENCED":
            if label not in referenced:
                referenced.append(label)
            if governance.get("ready") is True:
                if label not in ready:
                    ready.append(label)
            else:
                if label not in not_ready:
                    not_ready.append(label)
        else:
            if label not in unknown:
                unknown.append(label)
    if referenced and unknown:
        state = GOVERNANCE_MIXED
    elif referenced:
        state = GOVERNANCE_CONSISTENT_REFERENCED
    else:
        state = SUMMARY_GOVERNANCE_UNKNOWN
    return {
        "referenced_agents": referenced,
        "unknown_agents": unknown,
        "ready_agents": ready,
        "not_ready_agents": not_ready,
        "governance_state": state,
    }


def _provenance_summary(collaboration: dict) -> dict:
    layers: list[str] = []
    complete: list[str] = []
    partial: list[str] = []
    unknown: list[str] = []
    for result in collaboration.get("specialist_results") or ():
        if not isinstance(result, dict):
            continue
        label = result.get("agent_id") or ""
        provenance = result.get("provenance") or {}
        for layer in provenance.get("source_layers") or ():
            text = str(layer).strip().upper()
            if text in SOURCE_LAYERS and text not in layers:
                layers.append(text)
        state = str(
            provenance.get("provenance_state") or "UNKNOWN"
        ).upper()
        if state == "COMPLETE":
            if label not in complete:
                complete.append(label)
        elif state == "PARTIAL":
            if label not in partial:
                partial.append(label)
        else:
            if label not in unknown:
                unknown.append(label)
    ordered_layers = [layer for layer in SOURCE_LAYERS if layer in layers]
    if complete and not partial and not unknown:
        state = PROVENANCE_COMPLETE
    elif complete or partial:
        state = PROVENANCE_PARTIAL
    else:
        state = SUMMARY_PROVENANCE_UNKNOWN
    return {
        "source_layers": ordered_layers,
        "complete_agents": complete,
        "partial_agents": partial,
        "unknown_agents": unknown,
        "provenance_state": state,
    }


def export_multi_agent_collaboration(
    result_plans: object = None,
    evaluation_results: object = None,
    shared_context: object = None,
    collaboration_id: object = None,
) -> dict:
    """Build the unified, deterministic collaboration result (read-only)."""

    collaboration = build_multi_agent_collaboration_input(
        result_plans,
        evaluation_results=evaluation_results,
        shared_context=shared_context,
        collaboration_id=collaboration_id,
    )
    bounded = sanitize_multi_agent_collaboration_input(collaboration)

    groups = correlate_hypotheses(bounded)
    evidence = merge_collaboration_evidence(bounded)
    conflicts = analyze_collaboration_conflicts(bounded, groups)
    rankings = _rank_collaborators(bounded)

    plan = MultiAgentCollaborationResultPlan(
        rule_version=MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION,
        collaboration_rule_version=(
            MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION
        ),
        collaboration_id=bounded.get("collaboration_id") or "",
        participating_agents=bounded.get("participating_agents") or [],
        hypothesis_groups=groups,
        merged_evidence=evidence,
        conflicts=conflicts,
        collaboration_rankings=rankings,
        shared_context_summary=shared_context_summary(
            bounded.get("shared_context")
        ),
        governance_summary=_governance_summary(bounded),
        provenance_summary=_provenance_summary(bounded),
        collaboration_diagnostics=(
            bounded.get("collaboration_diagnostics") or []
        ),
        deterministic=True,
        research_only=True,
        limitations=list(COLLABORATION_LIMITATIONS),
    )
    return multi_agent_collaboration_result_plan_projection(plan)


__all__ = [
    "MULTI_AGENT_COLLABORATION_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "CONFIDENCE_COMPONENTS",
    "PRIORITY_COMPONENTS",
    "EVIDENCE_COMPONENTS",
    "PROVENANCE_COMPONENTS",
    "SAFETY_COMPONENTS",
    "EVALUATION_ABSENT_COMPONENT",
    "export_multi_agent_collaboration",
]
