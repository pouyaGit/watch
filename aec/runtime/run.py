"""EPIC6 Part 8: ExecutionRun model — machine and human summaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Closed source-mode vocabulary every run carries.
SOURCE_MODES = frozenset({"REAL_WATCH_DATA", "OFFLINE_FIXTURE"})


@dataclass(frozen=True)
class ExecutionRun:
    """One deterministic execution-bridge pass over a candidate set."""

    run_id: str
    source_mode: str
    started_at: int
    completed_at: int
    candidate_count: int
    case_count: int
    job_count: int
    queued_count: int
    blocked_count: int
    waiting_authorization_count: int
    observation_count: int
    evidence_count: int
    review_required_count: int
    completed_count: int
    failed_count: int
    deduplicated_count: int
    duration: int
    replay_identity: str
    jobs: tuple[Any, ...]
    evidence: tuple[Any, ...]
    failures: tuple[dict[str, str], ...]
    review_records: tuple[dict[str, str], ...]
    blocked_reasons: tuple[dict[str, str], ...]
    policy_version: str = "v1"
    context: dict[str, Any] = None  # type: ignore[assignment]

    def machine_summary(self) -> dict[str, Any]:
        """Stable machine-readable counters (JSON-safe, claim-free)."""
        return {
            "run_id": self.run_id,
            "source_mode": self.source_mode,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.duration,
            "candidate_count": self.candidate_count,
            "case_count": self.case_count,
            "job_count": self.job_count,
            "queued_count": self.queued_count,
            "blocked_count": self.blocked_count,
            "waiting_authorization_count": self.waiting_authorization_count,
            "observation_count": self.observation_count,
            "evidence_count": self.evidence_count,
            "review_required_count": self.review_required_count,
            "completed_count": self.completed_count,
            "failed_count": self.failed_count,
            "deduplicated_count": self.deduplicated_count,
            "replay_identity": self.replay_identity,
            "policy_version": self.policy_version,
        }

    def human_summary(self) -> str:
        """Readable operational summary. Never claims a finding."""
        lines = [
            f"Execution run {self.run_id}",
            f"  source mode : {self.source_mode}",
            f"  policy      : {self.policy_version}",
            f"  candidates  : {self.candidate_count}",
            f"  cases       : {self.case_count}",
            f"  jobs        : {self.job_count}",
            f"  queued      : {self.queued_count}",
            f"  blocked     : {self.blocked_count}",
            f"  waiting auth: {self.waiting_authorization_count}",
            f"  observations: {self.observation_count}",
            f"  evidence    : {self.evidence_count}",
            f"  review req  : {self.review_required_count}",
            f"  completed   : {self.completed_count}",
            f"  failed      : {self.failed_count}",
            f"  deduplicated: {self.deduplicated_count}",
            f"  duration    : {self.duration} ticks",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "source_mode": self.source_mode,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "candidate_count": self.candidate_count,
            "case_count": self.case_count,
            "job_count": self.job_count,
            "queued_count": self.queued_count,
            "blocked_count": self.blocked_count,
            "waiting_authorization_count": self.waiting_authorization_count,
            "observation_count": self.observation_count,
            "evidence_count": self.evidence_count,
            "review_required_count": self.review_required_count,
            "completed_count": self.completed_count,
            "failed_count": self.failed_count,
            "deduplicated_count": self.deduplicated_count,
            "duration": self.duration,
            "replay_identity": self.replay_identity,
            "policy_version": self.policy_version,
            "jobs": [job.to_dict() for job in self.jobs],
            "evidence": [record.to_dict() for record in self.evidence],
            "failures": [dict(item) for item in self.failures],
            "review_records": [dict(item) for item in self.review_records],
            "blocked_reasons": [dict(item) for item in self.blocked_reasons],
            "context": dict(self.context or {}),
        }


__all__ = ["ExecutionRun"]