"""backend/research_agents/repository.py — candidate source + job store.

Two responsibilities:

- :func:`load_priority_candidates` -- read-only. Reuses the existing Attack
  Surface Intelligence payload (priority queue) and adapts it into
  :class:`CandidateRef` values. It never creates or mutates attack-surface
  data.
- :class:`ResearchJobStore` -- an in-memory job/result store with an optional
  JSON artifact path. The Command Center and API use the in-memory store only;
  no production database is written.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from backend.research_agents.models import (
    ACTIVE_JOB_STATUSES,
    CandidateRef,
    JobStatus,
    ResearchJob,
    ResearchResult,
)

DEFAULT_CANDIDATE_LIMIT = 50


def candidates_from_payload(payload: object,
                            limit: int | None = None) -> list[CandidateRef]:
    """Adapt an attack-surface payload's priority queue into candidate refs."""

    if not isinstance(payload, dict):
        return []
    entries = payload.get("priority_queue") or []
    out: list[CandidateRef] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        out.append(CandidateRef.from_any(entry))
        if limit is not None and len(out) >= max(limit, 0):
            break
    return out


def load_priority_candidates(
    program: str | None = None,
    *,
    records: dict | None = None,
    limit: int = DEFAULT_CANDIDATE_LIMIT,
    now: str | None = None,
) -> list[CandidateRef]:
    """Read-only candidate source backed by the attack-surface priority queue.

    Fail-soft: any failure degrades to an empty candidate list rather than
    raising into a request handler.
    """

    try:
        from backend.attack_surface import service as asurface

        payload = asurface.attack_surface_payload(
            program,
            records=records,
            priority_limit=max(limit, 0),
            now=now,
        )
    except Exception:
        return []
    return candidates_from_payload(payload, limit=limit)


class ResearchJobStore:
    """In-memory research job + result store (optionally JSON-backed)."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._jobs: dict[str, ResearchJob] = {}
        self._results: dict[str, ResearchResult] = {}
        if self.path is not None:
            self._load()

    # -- jobs --------------------------------------------------------------
    def add_job(self, job: ResearchJob) -> ResearchJob:
        """Insert a job; an existing job id is preserved (idempotent)."""

        with self._lock:
            existing = self._jobs.get(job.id)
            if existing is not None:
                return existing
            self._jobs[job.id] = job
            return job

    def update_job(self, job: ResearchJob) -> ResearchJob:
        with self._lock:
            self._jobs[job.id] = job
            return job

    def get_job(self, job_id: object) -> ResearchJob | None:
        return self._jobs.get(str(job_id or ""))

    def all_jobs(self) -> list[ResearchJob]:
        return sorted(
            self._jobs.values(),
            key=lambda job: (
                -int(job.priority_score),
                job.endpoint,
                job.parameter,
                job.category,
                job.id,
            ),
        )

    def jobs_by_status(self, status: object) -> list[ResearchJob]:
        wanted = str(status or "").upper()
        return [job for job in self.all_jobs() if job.status == wanted]

    def jobs_for_agent(self, agent_name: object) -> list[ResearchJob]:
        wanted = str(agent_name or "")
        return [job for job in self.all_jobs() if job.assigned_agent == wanted]

    def counts(self) -> dict:
        by_status = {status.value: 0 for status in JobStatus}
        for job in self._jobs.values():
            by_status[job.status] = by_status.get(job.status, 0) + 1
        return {
            "total": len(self._jobs),
            "active": sum(
                1 for job in self._jobs.values()
                if job.status in ACTIVE_JOB_STATUSES
            ),
            "by_status": by_status,
        }

    # -- results -----------------------------------------------------------
    def set_result(self, result: ResearchResult) -> ResearchResult:
        with self._lock:
            self._results[result.job_id] = result
            return result

    def get_result(self, job_id: object) -> ResearchResult | None:
        return self._results.get(str(job_id or ""))

    def all_results(self) -> list[ResearchResult]:
        return [
            self._results[key]
            for key in sorted(self._results)
        ]

    # -- housekeeping ------------------------------------------------------
    def clear(self) -> None:
        with self._lock:
            self._jobs.clear()
            self._results.clear()

    def _load(self) -> None:
        path = self.path
        if path is None or not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for row in (payload.get("results") if isinstance(payload, dict)
                    else []) or []:
            if not isinstance(row, dict) or not row.get("job_id"):
                continue
            self._results[str(row["job_id"])] = ResearchResult(
                job_id=str(row["job_id"]),
                agent_name=str(row.get("agent_name") or ""),
                confidence=str(row.get("confidence") or ""),
                findings=tuple(row.get("findings") or ()),
                evidence_required=tuple(row.get("evidence_required") or ()),
                blockers=tuple(row.get("blockers") or ()),
                created_at=row.get("created_at"),
                signals=tuple(row.get("signals") or ()),
                status=str(row.get("status") or JobStatus.WAITING_EVIDENCE.value),
                provider=str(row.get("provider") or ""),
                model=str(row.get("model") or ""),
                prompt_version=str(row.get("prompt_version") or ""),
                analysis_ms=int(row.get("analysis_ms") or 0),
                execution_mode=str(row.get("execution_mode") or "production"),
            )
        for row in (payload.get("jobs") if isinstance(payload, dict) else []) or []:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            self._jobs[str(row["id"])] = ResearchJob(
                id=str(row["id"]),
                candidate_id=str(row.get("candidate_id") or ""),
                category=str(row.get("category") or ""),
                endpoint=str(row.get("endpoint") or ""),
                parameter=str(row.get("parameter") or ""),
                priority_score=int(row.get("priority_score") or 0),
                status=str(row.get("status") or JobStatus.NEW.value),
                assigned_agent=str(row.get("assigned_agent") or ""),
                created_at=row.get("created_at"),
                updated_at=row.get("updated_at"),
                agent_category=str(row.get("agent_category") or ""),
                method=str(row.get("method") or "GET"),
                confidence=str(row.get("confidence") or ""),
                reasons=tuple(row.get("reasons") or ()),
                program=str(row.get("program") or ""),
                subdomain=str(row.get("subdomain") or ""),
                url=str(row.get("url") or ""),
            )

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "jobs": [job.to_dict() for job in self.all_jobs()],
            "results": [res.to_dict() for res in self.all_results()],
        }
        self.path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def to_dict(self) -> dict:
        counts = self.counts()
        return {
            "counts": counts,
            "jobs": [job.to_dict() for job in self.all_jobs()],
            "results": [res.to_dict() for res in self.all_results()],
        }


__all__ = [
    "DEFAULT_CANDIDATE_LIMIT",
    "candidates_from_payload",
    "load_priority_candidates",
    "ResearchJobStore",
]
