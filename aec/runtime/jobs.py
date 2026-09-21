"""ResearchJob lifecycle (EPIC 6 Part 2).

13 states, one explicit transition table. Every move records previous
state, next state, reason, logical tick, and actor. Ticks are logical
sequence numbers supplied by the caller — never wall clock — so runs
replay deterministically. Anything outside the table, including
self-transitions and empty reasons/actors, is refused.
"""

from __future__ import annotations

from typing import Any

from aec.runtime.models import ResearchJob, TransitionRefusal

STATES = (
    "DISCOVERED",
    "QUEUED",
    "ASSIGNED",
    "WAITING_AUTHORIZATION",
    "READY_FOR_OBSERVATION",
    "OBSERVATION_RUNNING",
    "EVIDENCE_PENDING",
    "ANALYSIS_PENDING",
    "REVIEW_REQUIRED",
    "COMPLETED",
    "BLOCKED",
    "FAILED",
    "EXPIRED",
)

TRANSITIONS: dict[str, tuple[str, ...]] = {
    "DISCOVERED": ("QUEUED", "BLOCKED"),
    "QUEUED": ("ASSIGNED", "BLOCKED", "EXPIRED"),
    "ASSIGNED": ("WAITING_AUTHORIZATION", "BLOCKED", "EXPIRED"),
    "WAITING_AUTHORIZATION": ("READY_FOR_OBSERVATION", "BLOCKED", "EXPIRED"),
    "READY_FOR_OBSERVATION": ("OBSERVATION_RUNNING", "BLOCKED", "EXPIRED"),
    "OBSERVATION_RUNNING": ("EVIDENCE_PENDING", "FAILED", "BLOCKED"),
    "EVIDENCE_PENDING": ("ANALYSIS_PENDING", "FAILED"),
    "ANALYSIS_PENDING": ("REVIEW_REQUIRED", "COMPLETED", "FAILED"),
    "REVIEW_REQUIRED": ("COMPLETED", "BLOCKED", "FAILED"),
    "FAILED": ("QUEUED", "BLOCKED"),
    "BLOCKED": ("QUEUED",),
    "EXPIRED": ("QUEUED",),
    "COMPLETED": (),
}

SOURCE_MODES = frozenset({"REAL_WATCH_DATA", "OFFLINE_FIXTURE"})

_TERMINAL_REQUEUE = frozenset({"FAILED", "BLOCKED", "EXPIRED"})


def create_job(job_id: str, case_id: str, candidate_id: str,
               source_mode: str, max_attempts: int = 3,
               specialist: str = "") -> ResearchJob:
    """Create a job in DISCOVERED. Refuses blank ids or bad modes."""
    if not job_id or not case_id or not candidate_id:
        raise ValueError("job, case, and candidate ids are required")
    if source_mode not in SOURCE_MODES:
        raise ValueError(f"unknown source mode: {source_mode!r}")
    if not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")
    return ResearchJob(
        job_id=job_id,
        case_id=case_id,
        candidate_id=candidate_id,
        source_mode=source_mode,
        max_attempts=max_attempts,
        specialist=specialist if isinstance(specialist, str) else "",
    )


def transition(job: ResearchJob, target: str, reason: str,
               actor: str, tick: int) -> ResearchJob:
    """Move a job once. Refuses anything outside the table."""
    if target not in TRANSITIONS.get(job.state, ()):
        raise TransitionRefusal(
            "INVALID_TRANSITION", job.state, target,
            "not in transition table" if target in STATES
            else "unknown target state")
    if not isinstance(reason, str) or not reason.strip():
        raise TransitionRefusal(
            "EMPTY_REASON", job.state, target, "reason required")
    if not isinstance(actor, str) or not actor.strip():
        raise TransitionRefusal(
            "EMPTY_ACTOR", job.state, target, "actor required")
    if not isinstance(tick, int) or tick < 0:
        raise TransitionRefusal(
            "BAD_TICK", job.state, target, "tick must be a non-negative int")
    attempts = job.attempts
    if target == "FAILED":
        attempts += 1
    if target == "QUEUED" and job.state in _TERMINAL_REQUEUE:
        if job.attempts >= job.max_attempts and job.state == "FAILED":
            raise TransitionRefusal(
                "RETRY_BUDGET_EXHAUSTED", job.state, target,
                f"attempts {job.attempts} >= max {job.max_attempts}")
    record = {
        "previous_state": job.state,
        "next_state": target,
        "reason": reason.strip(),
        "actor": actor.strip(),
        "tick": tick,
    }
    actors = job.actor_history
    if not actors or actors[-1] != actor.strip():
        actors = tuple(list(actors) + [actor.strip()])
    return ResearchJob(
        job_id=job.job_id,
        case_id=job.case_id,
        candidate_id=job.candidate_id,
        source_mode=job.source_mode,
        state=target,
        specialist=job.specialist,
        attempts=attempts,
        max_attempts=job.max_attempts,
        transitions=tuple(list(job.transitions) + [record]),
        actor_history=actors,
    )


def allowed_targets(state: str) -> tuple[str, ...]:
    """Legal next states for a state (empty for unknown states)."""
    return TRANSITIONS.get(state, ())


__all__ = ["STATES", "TRANSITIONS", "allowed_targets", "create_job",
           "transition"]
