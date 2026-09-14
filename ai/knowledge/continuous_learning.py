"""Stage R57.6 deterministic continuous-learning builder (pure engine).

Consumes structured R42-R56 research-workflow outputs and produces the
deterministic continuous-learning result:

    R42 evaluations / R43 collaboration / R44 feedback / R53 findings /
    R54 correlation / R55 prioritization / R56 human decisions
      -> normalized learning signals
      -> conservative learning patterns
      -> advisory calibration recommendations
      -> continuous learning result

Hard boundaries encoded here:

- Research-only learning intelligence: R57 never executes anything, never
  sends requests, never confirms a vulnerability and never modifies agents,
  rules, thresholds or strategies. Recommendations are advisory only.
- Human decisions are workflow feedback, never truth labels: R56 inputs are
  read through the preserved authority context and never interpreted as
  vulnerability truth.
- Fail closed: ambiguous (orchestration-level and standalone inputs at the
  same time), malformed, mis-versioned or unsafe inputs are rejected or
  skipped with structured reasons; nothing is silently repaired.
- Deterministic: content-derived ids only; canonical ordering; stable
  tie-breaking; no timestamps, UUIDs, pids or randomness.
- Pure and offline: no I/O, no network, no subprocess, no shell, no
  database, no LLM, no wall-clock time.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.continuous_learning_rules import (
    aggregate_governance,
    aggregate_patterns,
    build_calibration_recommendations as _calibration_recommendations,
    build_result_provenance,
    build_summary,
    dedupe_signals,
    learning_id,
    result_limitations,
    signals_from_collaboration,
    signals_from_correlation,
    signals_from_evaluations,
    signals_from_feedback,
    signals_from_findings,
    signals_from_human_review,
    signals_from_prioritization,
    unsafe_input_reason,
)
from ai.schemas.continuous_learning_result import (
    CONTINUOUS_LEARNING_RESULT_RULE_VERSION,
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_INPUT,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_SAFETY_BLOCKED,
    SKIP_MALFORMED_INPUT,
    SKIP_RULE_VERSION_MISMATCH,
    SKIP_SAFETY_BLOCKED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_SIGNALS,
    STATUS_PARTIAL,
    ContinuousLearningResultPlan,
    continuous_learning_result_plan_projection,
    sanitize_learning_error,
    sanitize_learning_skip,
)
from ai.schemas.finding_correlation_result import (
    FINDING_CORRELATION_RESULT_RULE_VERSION,
)
from ai.schemas.finding_result import FINDING_RESULT_RULE_VERSION
from ai.schemas.human_decision_result import (
    HUMAN_REVIEW_RESULT_RULE_VERSION,
)
from ai.schemas.research_priority_result import (
    RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
)

CONTINUOUS_LEARNING_BUILDER_RULE_VERSION = "r57-6"
RULE_VERSION = CONTINUOUS_LEARNING_BUILDER_RULE_VERSION

#: Mirrors the R52 orchestration-result rule version without importing the R52
#: schema module: the existing R42-R52 static contract forbids the
#: orchestrator module name inside ``ai/knowledge`` specialist modules.
ORCHESTRATION_RESULT_RULE_VERSION = "r52-6"

def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _error(
    error_category: str,
    input_kind: str = "",
    message: str = "",
) -> dict:
    return sanitize_learning_error(
        {
            "stage": "CONTINUOUS_LEARNING",
            "error_category": error_category,
            "input_kind": input_kind,
            "message": message,
        }
    )


def _skip(input_kind: str, reason: str, message: str = "") -> dict:
    return sanitize_learning_skip(
        {
            "input_kind": input_kind,
            "reason": reason,
            "message": message,
        }
    )


def _validate_container(
    value: object,
    input_kind: str,
    expected_rule_version: str,
) -> tuple[str, dict | None, dict | None]:
    """Validate one container input (fail closed on type/version/safety)."""

    if not isinstance(value, dict):
        return (
            ERROR_INVALID_INPUT,
            _skip(
                input_kind,
                SKIP_MALFORMED_INPUT,
                "input must be a mapping",
            ),
            _error(
                ERROR_INVALID_INPUT,
                input_kind,
                "input must be a mapping",
            ),
        )
    rule_version = _text(value.get("rule_version"))
    if expected_rule_version and rule_version != expected_rule_version:
        return (
            ERROR_RULE_VERSION_MISMATCH,
            _skip(
                input_kind,
                SKIP_RULE_VERSION_MISMATCH,
                "input rule version does not match the expected layer",
            ),
            _error(
                ERROR_RULE_VERSION_MISMATCH,
                input_kind,
                "input rule version does not match the expected layer",
            ),
        )
    safety_reason = unsafe_input_reason(value)
    if safety_reason:
        return (
            ERROR_SAFETY_BLOCKED,
            _skip(input_kind, SKIP_SAFETY_BLOCKED, safety_reason),
            _error(
                ERROR_SAFETY_BLOCKED,
                input_kind,
                safety_reason,
            ),
        )
    return "", None, None


def _run(
    *,
    orchestration_result: object = None,
    evaluation_results: object = None,
    collaboration_result: object = None,
    feedback_result: object = None,
    finding_intelligence: object = None,
    correlation_result: object = None,
    prioritization_result: object = None,
    human_review_result: object = None,
    stages: tuple[str, ...] = ("signals", "patterns", "recommendations"),
) -> dict:
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
                    "ORCHESTRATION_RESULT",
                    "orchestration_result must be a mapping",
                )
            ]
        )
    if orchestration_result is not None and any(
        value is not None
        for value in (
            evaluation_results,
            collaboration_result,
            feedback_result,
        )
    ):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    "ORCHESTRATION_RESULT",
                    (
                        "supply either an orchestration_result or the "
                        "standalone R42/R43/R44 inputs, not both"
                    ),
                )
            ]
        )
    if evaluation_results is not None and not isinstance(
        evaluation_results, (list, tuple)
    ):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    "EVALUATION_RESULTS",
                    "evaluation_results must be a list",
                )
            ]
        )

    skipped: list[dict] = []
    errors: list[dict] = []
    signals: list[dict] = []
    orchestration_id = ""

    # ------------------------------------------------------------------
    # Orchestration-level input (R52) or standalone layers
    # ------------------------------------------------------------------
    if orchestration_result is not None:
        error, skip_entry, error_entry = _validate_container(
            orchestration_result,
            "ORCHESTRATION_RESULT",
            ORCHESTRATION_RESULT_RULE_VERSION,
        )
        if error:
            return _fatal_result([error_entry])
        orchestration_id = _text(
            orchestration_result.get("orchestration_id")
        )
        signals.extend(
            signals_from_evaluations(
                orchestration_result.get("evaluation_results") or [],
                orchestration_id,
            )
        )
        signals.extend(
            signals_from_collaboration(
                orchestration_result.get("collaboration_result"),
                orchestration_id,
            )
        )
        signals.extend(
            signals_from_feedback(
                orchestration_result.get("feedback_result"),
                orchestration_id,
            )
        )
    else:
        if evaluation_results is not None:
            for evaluation in evaluation_results:
                if not isinstance(evaluation, dict):
                    skipped.append(
                        _skip(
                            "EVALUATION_RESULTS",
                            SKIP_MALFORMED_INPUT,
                            "evaluation entry must be a mapping",
                        )
                    )
                    errors.append(
                        _error(
                            ERROR_MALFORMED_INPUT,
                            "EVALUATION_RESULTS",
                            "evaluation entry must be a mapping",
                        )
                    )
                    continue
                safety_reason = unsafe_input_reason(evaluation)
                if safety_reason:
                    skipped.append(
                        _skip(
                            "EVALUATION_RESULTS",
                            SKIP_SAFETY_BLOCKED,
                            safety_reason,
                        )
                    )
                    errors.append(
                        _error(
                            ERROR_SAFETY_BLOCKED,
                            "EVALUATION_RESULTS",
                            safety_reason,
                        )
                    )
                    continue
                signals.extend(
                    signals_from_evaluations([evaluation], orchestration_id)
                )
        if collaboration_result is not None:
            error, skip_entry, error_entry = _validate_container(
                collaboration_result,
                "COLLABORATION_RESULT",
                "",
            )
            if error:
                skipped.append(skip_entry)
                errors.append(error_entry)
            else:
                signals.extend(
                    signals_from_collaboration(
                        collaboration_result, orchestration_id
                    )
                )
        if feedback_result is not None:
            error, skip_entry, error_entry = _validate_container(
                feedback_result,
                "FEEDBACK_RESULT",
                "",
            )
            if error:
                skipped.append(skip_entry)
                errors.append(error_entry)
            else:
                signals.extend(
                    signals_from_feedback(
                        feedback_result, orchestration_id
                    )
                )

    # ------------------------------------------------------------------
    # R53-R56 layer inputs
    # ------------------------------------------------------------------
    for value, input_kind, expected in (
        (
            finding_intelligence,
            "FINDING_INTELLIGENCE",
            FINDING_RESULT_RULE_VERSION,
        ),
        (
            correlation_result,
            "CORRELATION_RESULT",
            FINDING_CORRELATION_RESULT_RULE_VERSION,
        ),
        (
            prioritization_result,
            "PRIORITIZATION_RESULT",
            RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
        ),
        (
            human_review_result,
            "HUMAN_REVIEW_RESULT",
            HUMAN_REVIEW_RESULT_RULE_VERSION,
        ),
    ):
        if value is None:
            continue
        error, skip_entry, error_entry = _validate_container(
            value, input_kind, expected
        )
        if error:
            skipped.append(skip_entry)
            errors.append(error_entry)
            continue
        if input_kind == "FINDING_INTELLIGENCE":
            signals.extend(signals_from_findings(value))
        elif input_kind == "CORRELATION_RESULT":
            signals.extend(signals_from_correlation(value))
        elif input_kind == "PRIORITIZATION_RESULT":
            signals.extend(signals_from_prioritization(value))
        elif input_kind == "HUMAN_REVIEW_RESULT":
            signals.extend(signals_from_human_review(value))

    # ------------------------------------------------------------------
    # Aggregation (deterministic)
    # ------------------------------------------------------------------
    ordered_signals = dedupe_signals(signals)
    patterns: list[dict] = []
    recommendations: list[dict] = []
    if "patterns" in stages:
        patterns = aggregate_patterns(ordered_signals)
    if "recommendations" in stages:
        recommendations = _calibration_recommendations(patterns)

    return _container(
        signals=ordered_signals,
        patterns=patterns,
        recommendations=recommendations,
        skipped=skipped,
        errors=errors,
    )


def _container(
    *,
    signals: list[dict],
    patterns: list[dict],
    recommendations: list[dict],
    skipped: list[dict],
    errors: list[dict],
    fatal: bool = False,
) -> dict:
    if fatal:
        status = STATUS_FAILED
    elif not signals and not skipped and not errors:
        status = STATUS_NO_SIGNALS
    elif signals and not (skipped or errors):
        status = STATUS_COMPLETED
    elif signals:
        status = STATUS_PARTIAL
    else:
        status = STATUS_PARTIAL

    result = ContinuousLearningResultPlan(
        rule_version=CONTINUOUS_LEARNING_RESULT_RULE_VERSION,
        signal_rule_version="r57-1",
        pattern_rule_version="r57-2",
        recommendation_rule_version="r57-3",
        learning_id=learning_id(
            [signal.get("signal_id", "") for signal in signals],
            [pattern.get("pattern_id", "") for pattern in patterns],
            [
                recommendation.get("recommendation_id", "")
                for recommendation in recommendations
            ],
        ),
        status=status,
        signals=signals,
        patterns=patterns,
        calibration_recommendations=recommendations,
        skipped_inputs=skipped,
        errors=errors,
        summary=build_summary(signals, patterns, recommendations),
        provenance=build_result_provenance(signals),
        governance=aggregate_governance(signals),
        limitations=result_limitations(
            signals, patterns, recommendations, skipped
        ),
        advisory=True,
        human_authority=True,
        auto_applies=False,
        execution_authorized=False,
        vulnerability_confirmed=False,
        confirmation_state="NOT_CONFIRMED",
        research_only=True,
        deterministic=True,
    )
    return continuous_learning_result_plan_projection(result)


def _fatal_result(errors: list[dict]) -> dict:
    return _container(
        signals=[],
        patterns=[],
        recommendations=[],
        skipped=[],
        errors=errors,
        fatal=True,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_continuous_learning_result(
    orchestration_result: object = None,
    evaluation_results: object = None,
    collaboration_result: object = None,
    feedback_result: object = None,
    finding_intelligence: object = None,
    correlation_result: object = None,
    prioritization_result: object = None,
    human_review_result: object = None,
) -> dict:
    """Build the full deterministic continuous-learning result (read-only).

    Supply either one R52 orchestration result or standalone R42/R43/R44
    inputs, plus any of the R53-R56 layer results. R57 extracts normalized
    learning signals, conservative patterns and advisory calibration
    recommendations. Nothing is executed, confirmed or modified.
    """

    return _run(
        orchestration_result=orchestration_result,
        evaluation_results=evaluation_results,
        collaboration_result=collaboration_result,
        feedback_result=feedback_result,
        finding_intelligence=finding_intelligence,
        correlation_result=correlation_result,
        prioritization_result=prioritization_result,
        human_review_result=human_review_result,
        stages=("signals", "patterns", "recommendations"),
    )


def build_learning_signals(**kwargs) -> dict:
    """Build the result with normalized learning signals only."""

    kwargs["stages"] = ("signals",)
    return _run(**kwargs)


def aggregate_learning_patterns(**kwargs) -> dict:
    """Build the result with signals and conservative patterns."""

    kwargs["stages"] = ("signals", "patterns")
    return _run(**kwargs)


def build_calibration_recommendations(**kwargs) -> dict:
    """Build the result with signals, patterns and recommendations."""

    kwargs["stages"] = ("signals", "patterns", "recommendations")
    return _run(**kwargs)


def export_continuous_learning(**kwargs) -> dict:
    """Alias for :func:`build_continuous_learning_result`."""

    return build_continuous_learning_result(**kwargs)


__all__ = [
    "CONTINUOUS_LEARNING_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "build_continuous_learning_result",
    "build_learning_signals",
    "aggregate_learning_patterns",
    "build_calibration_recommendations",
    "export_continuous_learning",
]
