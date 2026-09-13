"""Stage R42.3 deterministic evaluation scorer (pure engine).

Applies the fixed dimension weights and deterministic hard gates to the
dimension outcomes:

    "What is the overall quality of this structured research result?"

The score represents quality of research output only. It MUST NOT be
interpreted as probability of vulnerability, exploitability, severity,
CVSS or likelihood of compromise.

Hard boundaries encoded here:

- Evaluation only: pure deterministic arithmetic over structured data. No
  execution, no network, no database, no browser, no LLM judgment.
- Weights and thresholds are fixed module constants; nothing is runtime
  configurable.
- Deterministic hard gates: structural failure caps the rating at WEAK;
  safety degradation caps at ACCEPTABLE; safety failure caps at CRITICAL.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.agent_evaluation_rule import (
    DIMENSION_SAFETY_COMPLIANCE,
    DIMENSION_STRUCTURAL_VALIDITY,
    EVALUATION_DIMENSIONS,
    RULE_NO_EXECUTION_CLAIMS,
    RULE_NO_VULNERABILITY_CONFIRMATION,
    RULE_RESEARCH_ONLY,
)
from ai.schemas.agent_evaluation_score import (
    ACCEPTABLE_CEILING_SCORE,
    CRITICAL_CEILING_SCORE,
    DIMENSION_WEIGHTS,
    HARD_GATE_CEILING_SAFETY,
    HARD_GATE_CEILING_STRUCTURAL,
    HARD_GATE_FAIL_SAFETY,
    HARD_GATE_PASS,
    SAFETY_DEGRADED,
    SAFETY_FAILED,
    SAFETY_PASS,
    SAFETY_PASS_THRESHOLD,
    SAFETY_GATE_THRESHOLD,
    STRUCTURAL_GATE_THRESHOLD,
    TOTAL_WEIGHT,
    WEAK_CEILING_SCORE,
    AgentEvaluationDimensionScorePlan,
    agent_evaluation_dimension_score_plan_projection,
    rating_for_score,
)

AGENT_EVALUATION_SCORER_RULE_VERSION = "r42-3"
RULE_VERSION = AGENT_EVALUATION_SCORER_RULE_VERSION


def _outcomes_by_dimension(outcomes: object) -> dict[str, dict]:
    by_dimension: dict[str, dict] = {}
    if not isinstance(outcomes, (list, tuple)):
        return by_dimension
    for outcome in outcomes:
        if not isinstance(outcome, dict):
            continue
        dimension = outcome.get("dimension")
        if dimension in EVALUATION_DIMENSIONS:
            by_dimension.setdefault(dimension, outcome)
    return by_dimension


def _build_dimension_scores(
    by_dimension: dict[str, dict],
) -> list[dict]:
    scores: list[dict] = []
    for dimension in EVALUATION_DIMENSIONS:
        outcome = by_dimension.get(dimension, {})
        score = outcome.get("score", 0)
        if isinstance(score, bool) or not isinstance(score, int):
            score = 0
        score = max(0, min(100, score))
        plan = AgentEvaluationDimensionScorePlan(
            dimension=dimension,
            score=score,
            status=rating_for_score(score),
            weight=DIMENSION_WEIGHTS[dimension],
            reasons=list(outcome.get("reasons") or ()),
            passed_rules=list(outcome.get("passed_rules") or ()),
            failed_rules=list(outcome.get("failed_rules") or ()),
        )
        scores.append(agent_evaluation_dimension_score_plan_projection(plan))
    return scores


def _safety_state(
    safety_outcome: dict,
    safety_score: int,
) -> str:
    failed = set(safety_outcome.get("failed_rules") or ())
    if RULE_RESEARCH_ONLY in failed:
        return SAFETY_FAILED
    if RULE_NO_VULNERABILITY_CONFIRMATION in failed:
        return SAFETY_FAILED
    if safety_score < SAFETY_GATE_THRESHOLD:
        return SAFETY_FAILED
    if RULE_NO_EXECUTION_CLAIMS in failed:
        return SAFETY_DEGRADED
    if safety_score < SAFETY_PASS_THRESHOLD:
        return SAFETY_DEGRADED
    return SAFETY_PASS


def score_agent_evaluation(
    evaluation_input: object = None,
    outcomes: object = None,
) -> dict:
    """Compute dimension scores, the overall score and hard gates.

    Overall score = deterministic weighted sum over the fixed weights,
    then capped by the hard gates. The same inputs always produce the same
    score, rating, gate state and caps.
    """

    by_dimension = _outcomes_by_dimension(outcomes)
    dimension_scores = _build_dimension_scores(by_dimension)

    weighted_total = sum(
        entry["score"] * entry["weight"] for entry in dimension_scores
    )
    if TOTAL_WEIGHT > 0:
        raw_overall = (weighted_total + (TOTAL_WEIGHT // 2)) // TOTAL_WEIGHT
    else:
        raw_overall = 0

    structural_score = by_dimension.get(
        DIMENSION_STRUCTURAL_VALIDITY, {}
    ).get("score", 0)
    if isinstance(structural_score, bool) or not isinstance(
        structural_score, int
    ):
        structural_score = 0

    safety_outcome = by_dimension.get(DIMENSION_SAFETY_COMPLIANCE, {})
    safety_score = safety_outcome.get("score", 0)
    if isinstance(safety_score, bool) or not isinstance(safety_score, int):
        safety_score = 0
    safety_state = _safety_state(safety_outcome, safety_score)

    applied_caps: list[str] = []
    cap = 100
    gate_state = HARD_GATE_PASS
    if safety_state == SAFETY_FAILED:
        applied_caps.append(HARD_GATE_FAIL_SAFETY)
        cap = min(cap, CRITICAL_CEILING_SCORE)
        gate_state = HARD_GATE_FAIL_SAFETY
    elif safety_state == SAFETY_DEGRADED:
        applied_caps.append(HARD_GATE_CEILING_SAFETY)
        cap = min(cap, ACCEPTABLE_CEILING_SCORE)
        gate_state = HARD_GATE_CEILING_SAFETY
    if structural_score < STRUCTURAL_GATE_THRESHOLD:
        applied_caps.append(HARD_GATE_CEILING_STRUCTURAL)
        cap = min(cap, WEAK_CEILING_SCORE)
        if gate_state == HARD_GATE_PASS:
            gate_state = HARD_GATE_CEILING_STRUCTURAL

    overall_score = min(raw_overall, cap)
    return {
        "dimension_scores": dimension_scores,
        "overall_score": overall_score,
        "overall_rating": rating_for_score(overall_score),
        "hard_gate_state": gate_state,
        "safety_state": safety_state,
        "applied_caps": applied_caps,
    }


__all__ = [
    "AGENT_EVALUATION_SCORER_RULE_VERSION",
    "RULE_VERSION",
    "score_agent_evaluation",
]
