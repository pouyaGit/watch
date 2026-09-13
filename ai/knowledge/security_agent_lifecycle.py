"""Stage R38.4 deterministic security agent lifecycle planner (pure engine).

Defines the conceptual lifecycle states of a future security specialist agent:

    "Where is this agent in its conceptual lifecycle, and which transitions
     are allowed?"

Hard boundaries encoded here:

- Framework/model only: states are conceptual labels; there is no runtime,
  execution, scheduling, persistence, queue, worker or autonomous loop.
- No timestamps and no persistence: repeated evaluation is byte-identical.
- Only legal transitions are allowed; malformed states yield UNKNOWN and are
  never silently reinterpreted.
- Pure and offline; read-only inputs.
"""

from __future__ import annotations

from ai.schemas.security_agent_lifecycle import (
    LIFECYCLE_INVALID,
    LIFECYCLE_UNKNOWN,
    LIFECYCLE_VALID,
    LIFECYCLE_STATES,
    PREVIOUS_NONE,
    SECURITY_AGENT_LIFECYCLE_RULE_VERSION,
    STATE_ANALYZING,
    STATE_COMPLETED,
    STATE_CREATED,
    STATE_FAILED,
    STATE_PLANNED,
    STATE_UNKNOWN,
    STATE_WAITING_EVIDENCE,
    SecurityAgentLifecyclePlan,
    security_agent_lifecycle_plan_projection,
)

SECURITY_AGENT_LIFECYCLE_PLANNER_RULE_VERSION = "r38-4"
RULE_VERSION = SECURITY_AGENT_LIFECYCLE_PLANNER_RULE_VERSION

# current state -> allowed next states (terminal states allow none)
TRANSITIONS: dict[str, tuple] = {
    STATE_CREATED: (STATE_PLANNED,),
    STATE_PLANNED: (STATE_ANALYZING, STATE_FAILED),
    STATE_ANALYZING: (
        STATE_WAITING_EVIDENCE, STATE_COMPLETED, STATE_FAILED,
    ),
    STATE_WAITING_EVIDENCE: (
        STATE_ANALYZING, STATE_COMPLETED, STATE_FAILED,
    ),
    STATE_COMPLETED: (),
    STATE_FAILED: (),
    STATE_UNKNOWN: (),
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def plan_security_agent_lifecycle(
    current_state: object = None,
    previous_state: object = None,
) -> dict:
    """Build the deterministic lifecycle plan (read-only).

    Missing/malformed states yield ``current_state=UNKNOWN`` with lifecycle
    validation ``UNKNOWN``. Legal transitions validate as ``VALID``; an
    illegal transition from a known previous state validates as ``INVALID``.
    """

    current = _upper(current_state)
    previous = _upper(previous_state)

    if current not in LIFECYCLE_STATES or current == STATE_UNKNOWN:
        plan = SecurityAgentLifecyclePlan(
            rule_version=SECURITY_AGENT_LIFECYCLE_RULE_VERSION,
            current_state=STATE_UNKNOWN,
            previous_state=PREVIOUS_NONE,
            allowed_transitions=[],
            lifecycle_state=LIFECYCLE_UNKNOWN,
            research_only=True,
        )
        return security_agent_lifecycle_plan_projection(plan)

    allowed = list(TRANSITIONS[current])

    if not previous or previous == PREVIOUS_NONE:
        resolved_previous = PREVIOUS_NONE
        validation = LIFECYCLE_VALID
    elif previous not in LIFECYCLE_STATES:
        resolved_previous = PREVIOUS_NONE
        validation = LIFECYCLE_UNKNOWN
    else:
        resolved_previous = previous
        if current in TRANSITIONS.get(previous, ()):
            validation = LIFECYCLE_VALID
        else:
            validation = LIFECYCLE_INVALID

    plan = SecurityAgentLifecyclePlan(
        rule_version=SECURITY_AGENT_LIFECYCLE_RULE_VERSION,
        current_state=current,
        previous_state=resolved_previous,
        allowed_transitions=allowed,
        lifecycle_state=validation,
        research_only=True,
    )
    return security_agent_lifecycle_plan_projection(plan)


__all__ = [
    "SECURITY_AGENT_LIFECYCLE_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "TRANSITIONS",
    "plan_security_agent_lifecycle",
]
