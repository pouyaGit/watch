"""Stage R42.5 deterministic agent evaluation exporter (pure engine).

Runs the full evaluation pipeline over a structured agent result:

    agent result
        -> evaluation input (R42.1)
        -> evaluation rules (R42.2)
        -> dimension scores + hard gates (R42.3)
        -> diagnostics (R42.4)
        -> evaluation result (R42.5)

Hard boundaries encoded here:

- Evaluation only: no execution, no network, no SQL, no database, no
  browser, no LLM call, no payloads, no exploit verification, no
  vulnerability confirmation. R42 judges structured research output only.
- Generic: supports R38-compatible results and every specialist result
  (R39/R40/R41 and future specialists) through the common contract.
- Deterministic: repeated evaluation of the same input is byte-identical.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.agent_evaluation_diagnostics import (
    collect_evaluation_diagnostics,
)
from ai.knowledge.agent_evaluation_input import (
    build_agent_evaluation_input,
)
from ai.knowledge.agent_evaluation_rules import (
    evaluate_evaluation_dimensions,
)
from ai.knowledge.agent_evaluation_scorer import score_agent_evaluation
from ai.schemas.agent_evaluation_result import (
    AGENT_EVALUATION_RESULT_RULE_VERSION,
    EVALUATION_LIMITATIONS,
    AgentEvaluationResultPlan,
    agent_evaluation_result_plan_projection,
)

AGENT_EVALUATION_EXPORTER_RULE_VERSION = "r42-5"
RULE_VERSION = AGENT_EVALUATION_EXPORTER_RULE_VERSION


def evaluate_agent_result(
    result_plan: object = None,
    agent_id: object = None,
    agent_category: object = None,
) -> dict:
    """Evaluate a structured agent result end to end (read-only).

    The result carries dimension scores, ordered diagnostics, the overall
    quality score and rating, the hard-gate state and the safety state.
    Nothing is executed and no vulnerability is confirmed or denied.
    """

    evaluation_input = build_agent_evaluation_input(
        result_plan,
        agent_id=agent_id,
        agent_category=agent_category,
    )
    outcomes = evaluate_evaluation_dimensions(evaluation_input)
    diagnostics = collect_evaluation_diagnostics(outcomes)
    scoring = score_agent_evaluation(evaluation_input, outcomes)

    plan = AgentEvaluationResultPlan(
        rule_version=AGENT_EVALUATION_RESULT_RULE_VERSION,
        evaluation_rule_version=AGENT_EVALUATION_RESULT_RULE_VERSION,
        evaluated_agent_id=evaluation_input["agent_id"],
        evaluated_agent_category=evaluation_input["agent_category"],
        evaluated_agent_rule_version=(
            evaluation_input["agent_rule_version"]
        ),
        evaluated_result_rule_version=(
            evaluation_input["result_rule_version"]
        ),
        overall_score=scoring["overall_score"],
        overall_rating=scoring["overall_rating"],
        dimension_scores=scoring["dimension_scores"],
        diagnostics=diagnostics,
        hard_gate_state=scoring["hard_gate_state"],
        safety_state=scoring["safety_state"],
        applied_caps=scoring["applied_caps"],
        deterministic=True,
        research_only=True,
        limitations=list(EVALUATION_LIMITATIONS),
    )
    return agent_evaluation_result_plan_projection(plan)


def export_agent_evaluation(
    result_plan: object = None,
    agent_id: object = None,
    agent_category: object = None,
) -> dict:
    """Alias for :func:`evaluate_agent_result` (project naming pattern)."""

    return evaluate_agent_result(
        result_plan, agent_id=agent_id, agent_category=agent_category
    )


__all__ = [
    "AGENT_EVALUATION_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "evaluate_agent_result",
    "export_agent_evaluation",
]
