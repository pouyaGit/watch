"""EPIC7 Part 1: ObservationRuntime 11-state lifecycle — fail-closed.

Every transition records request_id, research_job_id, case_id, previous
and next state, reason, timestamp (logical tick), policy version, and the
authorization reference. Anything outside the explicit table — including
transitions out of terminal states and retries out of BLOCKED/REFUSED —
is refused. Retries are explicit only: TIMED_OUT/FAILED may return to
RECEIVED when the caller classifies the retry as safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aec.runtime.models import TransitionRefusal

STATES = (
    "RECEIVED",
    "VALIDATING",
    "AUTHORIZED",
    "DISPATCHED",
    "OBSERVING",
    "COLLECTING",
    "COMPLETED",
    "REFUSED",
    "BLOCKED",
    "TIMED_OUT",
    "FAILED",
)

TRANSITIONS: dict[str, tuple[str, ...]] = {
    "RECEIVED": ("VALIDATING", "BLOCKED"),
    "VALIDATING": ("AUTHORIZED", "REFUSED", "BLOCKED"),
    "AUTHORIZED": ("DISPATCHED", "BLOCKED"),
    "DISPATCHED": ("OBSERVING", "FAILED", "TIMED_OUT"),
    "OBSERVING": ("COLLECTING", "FAILED", "TIMED_OUT"),
    "COLLECTING": ("COMPLETED", "FAILED"),
    "COMPLETED": (),
    "REFUSED": (),
    "BLOCKED": (),
    "TIMED_OUT": ("RECEIVED",),   # explicit classified retry only
    "FAILED": ("RECEIVED",),      # explicit classified retry only
}

_TERMINAL = frozenset({"COMPLETED", "REFUSED", "BLOCKED"})


@dataclass(frozen=True)
class ObservationState:
    request_id: str
    research_job_id: str
    case_id: str
    policy_version: str
    authorization_reference: str
    state: str = "RECEIVED"
    transitions: tuple[dict[str, Any], ...] = ()
    actor_history: tuple[str, ...] = ()

    def transition(self, target: str, reason: str, actor: str,
                   tick: int) -> "ObservationState":
        if target not in TRANSITIONS.get(self.state, ()):
            raise TransitionRefusal(
                "INVALID_TRANSITION", self.state, target,
                "not in runtime transition table"
                if target in STATES else "unknown target state")
        if not isinstance(reason, str) or not reason.strip():
            raise TransitionRefusal(
                "EMPTY_REASON", self.state, target, "reason required")
        if not isinstance(actor, str) or not actor.strip():
            raise TransitionRefusal(
                "EMPTY_ACTOR", self.state, target, "actor required")
        if not isinstance(tick, int) or tick < 0:
            raise TransitionRefusal(
                "BAD_TICK", self.state, target,
                "tick must be a non-negative int")
        record = {
            "request_id": self.request_id,
            "research_job_id": self.research_job_id,
            "case_id": self.case_id,
            "previous_state": self.state,
            "next_state": target,
            "reason": reason.strip(),
            "timestamp": tick,
            "policy_version": self.policy_version,
            "authorization_reference": self.authorization_reference,
        }
        actors = self.actor_history
        if not actors or actors[-1] != actor.strip():
            actors = tuple(list(actors) + [actor.strip()])
        return ObservationState(
            request_id=self.request_id,
            research_job_id=self.research_job_id,
            case_id=self.case_id,
            policy_version=self.policy_version,
            authorization_reference=self.authorization_reference,
            state=target,
            transitions=tuple(list(self.transitions) + [record]),
            actor_history=actors,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "request_id": self.request_id,
            "research_job_id": self.research_job_id,
            "case_id": self.case_id,
            "policy_version": self.policy_version,
            "authorization_reference": self.authorization_reference,
            "transition_count": len(self.transitions),
            "transitions": list(self.transitions),
        }


def create_observation_state(
    request_id: str,
    research_job_id: str,
    case_id: str,
    policy_version: str,
    authorization_reference: str,
) -> ObservationState:
    """Create a runtime observation in RECEIVED. Refuses blank identities."""
    if not isinstance(request_id, str) or not request_id:
        raise ValueError("request_id required")
    if not isinstance(research_job_id, str) or not research_job_id:
        raise ValueError("research_job_id required")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id required")
    if not isinstance(policy_version, str) or not policy_version:
        raise ValueError("policy_version required")
    if not isinstance(authorization_reference, str) \
            or not authorization_reference:
        raise ValueError("authorization_reference required")
    return ObservationState(
        request_id=request_id,
        research_job_id=research_job_id,
        case_id=case_id,
        policy_version=policy_version,
        authorization_reference=authorization_reference,
    )


__all__ = ["ObservationState", "STATES", "TRANSITIONS",
           "create_observation_state"]