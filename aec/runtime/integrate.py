"""EPIC7 Part 14+15: ResearchJob wiring and the specialist boundary.

The runtime never touches the ResearchJob state machine directly: this
module is the only bridge between the EPIC6 job lifecycle and the EPIC7
runtime. Specialists REQUEST observations through the existing
ResearchExecutor contract only; a specialist's request dict is validated
as a planning input here and never executed as-is.
"""

from __future__ import annotations

from typing import Any, Mapping

from aec.runtime import jobs as job_lifecycle
from aec.runtime.policy.models import is_observation_type

_SPECIALIST_FIELDS = (
    "case_id", "research_job_id", "target_id", "observation_type",
    "reason", "required_evidence_level",
)


def validate_specialist_request(specialist: Mapping[str, Any]) -> bool:
    """A specialist request is a planning input: all fields explicit,
    observation type from the closed allowlist, no raw URLs."""
    if not isinstance(specialist, Mapping):
        return False
    for field in _SPECIALIST_FIELDS:
        value = specialist.get(field)
        if not isinstance(value, str) or not value.strip():
            return False
    if not is_observation_type(specialist.get("observation_type")):
        return False
    target_id = specialist.get("target_id", "")
    if "://" in target_id or "/" in target_id:
        return False
    return True


def specialist_target_identity(specialist: Mapping[str, Any]) -> str:
    """The normalized target identity a specialist may request."""
    target_id = specialist.get("target_id", "")
    return target_id if isinstance(target_id, str) else ""


def advance_to_observation_running(job: Any, tick: int) -> Any:
    return job_lifecycle.transition(
        job, "OBSERVATION_RUNNING", "observation started by runtime",
        "runtime", tick)


def advance_evidence_pending(job: Any, tick: int) -> Any:
    return job_lifecycle.transition(
        job, "EVIDENCE_PENDING", "evidence collected by runtime",
        "runtime", tick)


def advance_analysis_pending(job: Any, tick: int) -> Any:
    return job_lifecycle.transition(
        job, "ANALYSIS_PENDING", "evidence ready for specialist analysis",
        "pipeline", tick)


def advance_to_blocked(job: Any, reason: str, tick: int) -> Any:
    return job_lifecycle.transition(
        job, "BLOCKED", reason, "runtime", tick)


def advance_to_failed(job: Any, reason: str, tick: int) -> Any:
    return job_lifecycle.transition(
        job, "FAILED", reason, "runtime", tick)


__all__ = [
    "advance_analysis_pending", "advance_evidence_pending",
    "advance_to_blocked", "advance_to_failed",
    "advance_to_observation_running", "specialist_target_identity",
    "validate_specialist_request",
]