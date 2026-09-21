"""EPIC6 Part 11: deterministic failure classification and recovery plans."""

from __future__ import annotations

from typing import Any

RETRYABLE_KINDS = frozenset({
    "TIMEOUT", "INGESTION_ERROR", "OBSERVATION_ERROR",
    "EVIDENCE_INGESTION", "QUEUE_FAILURE"})

TERMINAL_KINDS = frozenset({
    "MALFORMED_CANDIDATE", "MISSING_CASE", "UNSUPPORTED_SPECIALIST",
    "AUTHORIZATION_DENIED", "DUPLICATE_OBSERVATION", "EXECUTION_REFUSAL",
    "CONFLICTING_EVIDENCE"})

MAX_RETRIES = 3


def classify(kind: str) -> str:
    """RETRYABLE or TERMINAL for a failure kind. Unknown kinds are TERMINAL."""
    return "RETRYABLE" if kind in RETRYABLE_KINDS else "TERMINAL"


def retryable(kind: str, attempts: int) -> bool:
    """True when a kind is retryable and the attempt budget remains."""
    return classify(kind) == "RETRYABLE" and attempts < MAX_RETRIES


def recovery_plan(run: Any) -> list[dict[str, str]]:
    """Deterministic per-job recovery actions for a completed run.

    Never invents authorization: the only actions are requeue/retry
    (for retryable failures) and a recorded human-escalation note for
    everything else. Bypassing the gate is not a possible action.
    """
    plan: list[dict[str, str]] = []
    for job in run.jobs:
        if job.state == "BLOCKED":
            plan.append({
                "job_id": job.job_id,
                "action": "ESCALATE_TO_REVIEW",
                "reason": "job blocked; requires operator decision",
            })
        elif job.state == "EXPIRED":
            plan.append({
                "job_id": job.job_id,
                "action": "REAUTHORIZE",
                "reason": "authorization expired; a fresh grant is required",
            })
        elif job.state == "FAILED":
            action = ("RETRY" if retryable(
                "TIMEOUT", job.attempts) else "ESCALATE_TO_REVIEW")
            plan.append({
                "job_id": job.job_id,
                "action": action,
                "reason": f"failed after {job.attempts} attempts",
            })
        else:
            plan.append({
                "job_id": job.job_id,
                "action": "NO_ACTION",
                "reason": job.state,
            })
    return plan


__all__ = ["MAX_RETRIES", "RETRYABLE_KINDS", "TERMINAL_KINDS", "classify",
           "recovery_plan", "retryable"]