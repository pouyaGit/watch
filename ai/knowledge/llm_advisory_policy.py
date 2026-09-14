"""Stage R45.2 deterministic LLM advisory policy engine (pure engine).

Applies the fixed advisory policy to a bounded advisory input:

    "Which advisory mode is allowed for this structured input?"

Hard boundaries encoded here:

- Advisory only: the policy selects an explanation mode. It cannot grant
  execution, exploitation, payload, confirmation or attack-planning
  authority, and forbidden modes are rejected outright.
- Deterministic: the mode is a pure function of the bounded input; the same
  input always selects the same mode.
- The deterministic layers stay authoritative: the policy reads already
  computed layer outputs and never recomputes R42/R43/R44 logic.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.llm_advisory_policy import (
    ADVISORY_MODES,
    DEFAULT_ADVISORY_MODE,
    FORBIDDEN_ADVISORY_MODES,
    LLM_ADVISORY_POLICY_RULE_VERSION,
    MODE_CONFLICT_EXPLANATION,
    MODE_EXPLANATION,
    MODE_LEARNING_SUMMARY,
    MODE_RESEARCH_PRIORITY,
    LLMAdvisoryPolicyPlan,
    llm_advisory_policy_plan_projection,
)

LLM_ADVISORY_POLICY_ENGINE_RULE_VERSION = "r45-2"
RULE_VERSION = LLM_ADVISORY_POLICY_ENGINE_RULE_VERSION

# Deterministic mode conditions, checked in fixed order.
CONFLICT_EXPLANATION_CONDITION = "CONFLICTS_PRESENT"
LEARNING_SUMMARY_CONDITION = "LEARNING_SIGNALS_PRESENT"
RESEARCH_PRIORITY_CONDITION = "COLLABORATION_PRESENT"
EXPLANATION_CONDITION = "EVALUATION_PRESENT"

MODE_CONDITIONS: tuple[tuple[str, str], ...] = (
    (CONFLICT_EXPLANATION_CONDITION, MODE_CONFLICT_EXPLANATION),
    (LEARNING_SUMMARY_CONDITION, MODE_LEARNING_SUMMARY),
    (RESEARCH_PRIORITY_CONDITION, MODE_RESEARCH_PRIORITY),
    (EXPLANATION_CONDITION, MODE_EXPLANATION),
)

POLICY_DEFAULT_MODE = DEFAULT_ADVISORY_MODE
POLICY_ALLOWED_MODES = ADVISORY_MODES
POLICY_FORBIDDEN_MODES = FORBIDDEN_ADVISORY_MODES


class AdvisoryPolicyError(ValueError):
    """Deterministic policy rejection with preserved diagnostics."""

    def __init__(self, message: str, diagnostic: dict | None = None):
        super().__init__(message)
        self.diagnostic = diagnostic or {}


class ForbiddenAdvisoryModeError(AdvisoryPolicyError):
    """Raised when a forbidden advisory mode is requested."""


def is_allowed_advisory_mode(mode: object) -> bool:
    """Return True when the mode is in the closed allowed vocabulary."""

    return str(mode if mode is not None else "").strip().upper() in (
        ADVISORY_MODES
    )


def is_forbidden_advisory_mode(mode: object) -> bool:
    """Return True when the mode is in the closed forbidden vocabulary."""

    return str(mode if mode is not None else "").strip().upper() in (
        FORBIDDEN_ADVISORY_MODES
    )


def _condition_state(advisory_input: object) -> dict[str, bool]:
    value = advisory_input if isinstance(advisory_input, dict) else {}
    evaluation = value.get("evaluation_summary")
    evaluation = evaluation if isinstance(evaluation, dict) else {}
    collaboration = value.get("collaboration_summary")
    collaboration = collaboration if isinstance(collaboration, dict) else {}
    signals = value.get("learning_signals")
    signals = signals if isinstance(signals, (list, tuple)) else ()
    conflict_count = collaboration.get("conflict_count")
    if isinstance(conflict_count, bool) or not isinstance(
        conflict_count, int
    ):
        conflict_count = 0
    return {
        CONFLICT_EXPLANATION_CONDITION: bool(
            collaboration.get("present") and conflict_count > 0
        ),
        LEARNING_SUMMARY_CONDITION: bool(signals),
        RESEARCH_PRIORITY_CONDITION: bool(
            collaboration.get("present") and conflict_count <= 0
        ),
        EXPLANATION_CONDITION: bool(evaluation.get("present")),
    }


def select_advisory_mode(advisory_input: object = None) -> str:
    """Select the allowed advisory mode deterministically (read-only)."""

    conditions = _condition_state(advisory_input)
    for condition, mode in MODE_CONDITIONS:
        if conditions.get(condition):
            return mode
    return POLICY_DEFAULT_MODE


def resolve_advisory_mode(
    advisory_input: object = None, requested_mode: object = None
) -> str:
    """Resolve the advisory mode under policy.

    A forbidden mode is rejected with preserved diagnostics. An allowed mode
    is honored. An absent mode triggers deterministic selection. An unknown
    (non-vocabulary) non-empty mode is rejected.
    """

    text = str(requested_mode if requested_mode is not None else "").strip()
    if not text:
        return select_advisory_mode(advisory_input)
    normalized = text.upper()
    if normalized in FORBIDDEN_ADVISORY_MODES:
        raise ForbiddenAdvisoryModeError(
            f"forbidden advisory mode: {normalized}",
            {
                "rule_version": LLM_ADVISORY_POLICY_ENGINE_RULE_VERSION,
                "advisory_mode": normalized,
                "policy_state": "FORBIDDEN",
                "allowed_modes": list(ADVISORY_MODES),
                "forbidden_modes": list(FORBIDDEN_ADVISORY_MODES),
            },
        )
    if normalized not in ADVISORY_MODES:
        raise AdvisoryPolicyError(
            f"unknown advisory mode: {normalized}",
            {
                "rule_version": LLM_ADVISORY_POLICY_ENGINE_RULE_VERSION,
                "advisory_mode": normalized,
                "policy_state": "UNKNOWN",
                "allowed_modes": list(ADVISORY_MODES),
                "forbidden_modes": list(FORBIDDEN_ADVISORY_MODES),
            },
        )
    return normalized


def build_advisory_policy() -> dict:
    """Build the fixed deterministic advisory policy (read-only)."""

    plan = LLMAdvisoryPolicyPlan(
        rule_version=LLM_ADVISORY_POLICY_RULE_VERSION,
        allowed_modes=list(ADVISORY_MODES),
        forbidden_modes=list(FORBIDDEN_ADVISORY_MODES),
        default_mode=DEFAULT_ADVISORY_MODE,
        deterministic=True,
        research_only=True,
    )
    result = llm_advisory_policy_plan_projection(plan)
    result["rule_version"] = LLM_ADVISORY_POLICY_RULE_VERSION
    return result


__all__ = [
    "LLM_ADVISORY_POLICY_ENGINE_RULE_VERSION",
    "RULE_VERSION",
    "MODE_CONDITIONS",
    "CONFLICT_EXPLANATION_CONDITION",
    "LEARNING_SUMMARY_CONDITION",
    "RESEARCH_PRIORITY_CONDITION",
    "EXPLANATION_CONDITION",
    "POLICY_DEFAULT_MODE",
    "POLICY_ALLOWED_MODES",
    "POLICY_FORBIDDEN_MODES",
    "AdvisoryPolicyError",
    "ForbiddenAdvisoryModeError",
    "is_allowed_advisory_mode",
    "is_forbidden_advisory_mode",
    "select_advisory_mode",
    "resolve_advisory_mode",
    "build_advisory_policy",
]
