"""Stage R52.3 deterministic orchestration policy resolution (pure engine).

Resolves the explicit, bounded orchestration policy:

    "Which coordination steps may run, with which bounds?"

Hard boundaries encoded here:

- Orchestration/model only: policy resolution is validation of declarative
  data. It performs no execution, no network, no database, no browser, no LLM
  call and no target interaction.
- Fail closed: an invalid or malformed policy raises a structured
  :class:`OrchestrationPolicyError`; it is never silently widened or
  partially applied.
- No executable content: the policy contains closed values and bounded
  integers only; arbitrary instructions cannot enter it.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from pydantic import ValidationError

from ai.schemas.agent_orchestrator_policy import (
    AGENT_ORCHESTRATOR_POLICY_RULE_VERSION,
    DEFAULT_MAX_ADVISORY_REQUESTS,
    DEFAULT_MAX_EVIDENCE_ITEMS,
    DEFAULT_MAX_HYPOTHESES,
    DEFAULT_MAX_ORCHESTRATION_STAGES,
    DEFAULT_MAX_SPECIALISTS,
    MODE_AUTOMATIC,
    MAX_ORCHESTRATION_DEPTH,
    validate_orchestration_policy,
)

ORCHESTRATION_POLICY_RESOLVER_RULE_VERSION = "r52-3"
RULE_VERSION = ORCHESTRATION_POLICY_RESOLVER_RULE_VERSION


class OrchestrationPolicyError(ValueError):
    """Structured, deterministic invalid-policy failure."""


def default_orchestration_policy() -> dict:
    """Return the safe default policy (automatic, advisory disabled)."""

    return validate_orchestration_policy(
        {
            "mode": MODE_AUTOMATIC,
            "max_specialists": DEFAULT_MAX_SPECIALISTS,
            "max_hypotheses_processed": DEFAULT_MAX_HYPOTHESES,
            "max_evidence_items_processed": DEFAULT_MAX_EVIDENCE_ITEMS,
            "max_advisory_requests": DEFAULT_MAX_ADVISORY_REQUESTS,
            "max_orchestration_stages": DEFAULT_MAX_ORCHESTRATION_STAGES,
            "max_orchestration_depth": MAX_ORCHESTRATION_DEPTH,
        }
    )


def resolve_orchestration_policy(policy: object = None) -> dict:
    """Validate a caller policy, failing closed on any invalid value.

    ``None`` resolves to the safe default policy. A malformed policy, an
    unknown category, an out-of-bounds value, adversarial advisory wiring or
    recursive depth raises :class:`OrchestrationPolicyError`.
    """

    if policy is None:
        return default_orchestration_policy()
    if not isinstance(policy, dict):
        raise OrchestrationPolicyError(
            "orchestration policy must be a mapping"
        )
    try:
        projected = validate_orchestration_policy(policy)
    except (ValidationError, ValueError) as exc:
        raise OrchestrationPolicyError(str(exc)) from exc
    if projected.get("rule_version") != (
        AGENT_ORCHESTRATOR_POLICY_RULE_VERSION
    ):
        raise OrchestrationPolicyError("invalid policy rule_version")
    return projected


__all__ = [
    "ORCHESTRATION_POLICY_RESOLVER_RULE_VERSION",
    "RULE_VERSION",
    "OrchestrationPolicyError",
    "default_orchestration_policy",
    "resolve_orchestration_policy",
]
