"""Stage R38.3 deterministic security agent input validator (pure engine).

Validates and projects the common read-only input contract for future
security specialist agents:

    "Which bounded context may an agent consume, and what is absent?"

Hard boundaries encoded here:

- Framework/model only: no execution context, no agent runtime, no tool
  execution, no network, no LLM calls, no persistence.
- Input is read-only and never mutated; malformed blocks degrade to empty
  (unknown) blocks.
- Missing critical authorization context remains unknown: it is projected as
  an empty block and is never treated as unrestricted permission.
- Pure and offline; deterministic; privacy-redacted bounded output.
"""

from __future__ import annotations

from ai.schemas.security_agent_input import (
    SECURITY_AGENT_INPUT_RULE_VERSION,
    SecurityAgentInputPlan,
    security_agent_input_plan_projection,
)


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def validate_security_agent_input(
    agent_identity: object = None,
    research_context: object = None,
    memory_context: object = None,
    strategy_context: object = None,
    orchestration_context: object = None,
    authorization_context: object = None,
    governance_context: object = None,
) -> dict:
    """Project a bounded, read-only agent input contract (no mutation).

    Every block is sanitized and bounded; a missing/malformed authorization
    context stays an empty block (unknown), never a permissive default.
    """

    plan = SecurityAgentInputPlan(
        rule_version=SECURITY_AGENT_INPUT_RULE_VERSION,
        agent_identity=_block(agent_identity),
        research_context=_block(research_context),
        memory_context=_block(memory_context),
        strategy_context=_block(strategy_context),
        orchestration_context=_block(orchestration_context),
        authorization_context=_block(authorization_context),
        governance_context=_block(governance_context),
        research_only=True,
    )
    return security_agent_input_plan_projection(plan)


__all__ = [
    "SECURITY_AGENT_INPUT_RULE_VERSION",
    "validate_security_agent_input",
]
