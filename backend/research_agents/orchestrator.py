"""backend/research_agents/orchestrator.py — candidate -> job -> agent (Part 3).

The orchestrator turns an Attack Surface candidate into a :class:`ResearchJob`,
queues it, assigns the matching specialist agent and produces the agent's
evidence plan. It only creates investigation plans:

- XSS candidate  -> XSS Research Agent
- IDOR candidate -> IDOR Research Agent
- SSRF candidate -> prepared (queued) for a future agent
- anything else  -> prepared (queued) for a future agent

It never executes exploitation, never touches a target and never confirms a
vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from backend.research_agents.models import (
    JOB_STATUS_FLOW,
    CandidateRef,
    JobStatus,
    ResearchJob,
    ResearchResult,
    job_id_for,
    utcnow_iso,
)
from backend.research_agents.registry import (
    AgentRegistry,
    build_default_registry,
)
from backend.research_agents.repository import ResearchJobStore


class OrchestratorError(ValueError):
    """Invalid lifecycle transition or orchestrator misuse."""


@dataclass(frozen=True)
class DispatchOutcome:
    """The job and (when assigned) the agent's evidence plan."""

    job: ResearchJob
    result: ResearchResult | None = None

    def to_dict(self) -> dict:
        return {
            "job": self.job.to_dict(),
            "result": self.result.to_dict() if self.result else None,
        }


class AgentOrchestrator:
    """Deterministic candidate -> research job orchestrator."""

    def __init__(
        self,
        registry: AgentRegistry | None = None,
        store: ResearchJobStore | None = None,
    ) -> None:
        self.registry = registry or build_default_registry()
        self.store = store or ResearchJobStore()

    # -- lifecycle ---------------------------------------------------------
    def _transition(
        self, job: ResearchJob, status: str, *, now: str | None = None
    ) -> ResearchJob:
        target = str(status or "").upper()
        if target not in {member.value for member in JobStatus}:
            raise OrchestratorError(f"unknown job status {status!r}")
        if target == job.status:
            return job
        if target not in JOB_STATUS_FLOW.get(job.status, ()):
            raise OrchestratorError(
                f"illegal transition {job.status} -> {target}"
            )
        return replace(job, status=target, updated_at=now or utcnow_iso())

    def transition(
        self, job_id: object, status: str, *, now: str | None = None
    ) -> ResearchJob:
        """Public lifecycle transition for one stored job."""

        job = self.store.get_job(job_id)
        if job is None:
            raise OrchestratorError(f"unknown job {job_id}")
        updated = self._transition(job, status, now=now)
        return self.store.update_job(updated)

    # -- job creation ------------------------------------------------------
    def create_job(
        self, candidate: object, *, now: str | None = None
    ) -> ResearchJob:
        """Create (or return the existing) NEW job for a candidate."""

        ref = CandidateRef.from_any(candidate)
        agent_category = ref.agent_category
        job_id = job_id_for(ref.id, agent_category)
        existing = self.store.get_job(job_id)
        if existing is not None:
            return existing
        timestamp = now or utcnow_iso()
        job = ResearchJob(
            id=job_id,
            candidate_id=ref.id,
            category=ref.category,
            endpoint=ref.endpoint,
            parameter=ref.parameter,
            priority_score=ref.priority_score,
            status=JobStatus.NEW.value,
            assigned_agent="",
            created_at=timestamp,
            updated_at=timestamp,
            agent_category=agent_category,
            method=ref.method,
            confidence=ref.confidence,
            reasons=ref.reasons,
            technology=ref.technology,
            program=ref.program,
            subdomain=ref.subdomain,
            url=ref.url,
        )
        return self.store.add_job(job)

    # -- dispatch ----------------------------------------------------------
    def dispatch(
        self, candidate: object, *, now: str | None = None
    ) -> DispatchOutcome:
        """Queue, assign and plan one candidate (idempotent)."""

        ref = CandidateRef.from_any(candidate)
        job = self.create_job(ref, now=now)
        if job.status != JobStatus.NEW.value:
            return DispatchOutcome(job, self.store.get_result(job.id))

        job = self.store.update_job(
            self._transition(job, JobStatus.QUEUED.value, now=now)
        )

        agent = self.registry.ready_for(ref.agent_category)
        if agent is None:
            result = ResearchResult(
                job_id=job.id,
                agent_name="",
                confidence="",
                evidence_required=(),
                blockers=(
                    "no ready specialist agent for category "
                    f"'{ref.agent_category}'",
                ),
                created_at=now or utcnow_iso(),
                status=JobStatus.WAITING_EVIDENCE.value,
            )
            self.store.set_result(result)
            return DispatchOutcome(job, result)

        job = self.store.update_job(
            replace(job, assigned_agent=agent.name)
        )
        job = self.store.update_job(
            self._transition(job, JobStatus.ASSIGNED.value, now=now)
        )
        job = self.store.update_job(
            self._transition(job, JobStatus.RUNNING.value, now=now)
        )

        analyzer = self.registry.analyzer_for(ref.agent_category)
        try:
            plan = analyzer(ref) if analyzer is not None else {}
        except Exception as exc:  # agent failures never take down the caller
            job = self.store.update_job(
                self._transition(job, JobStatus.FAILED.value, now=now)
            )
            result = ResearchResult(
                job_id=job.id,
                agent_name=agent.name,
                confidence="",
                blockers=(f"agent analysis failed: {exc}",),
                created_at=now or utcnow_iso(),
                status=JobStatus.FAILED.value,
            )
            self.store.set_result(result)
            return DispatchOutcome(job, result)

        evidence = tuple(plan.get("evidence_required") or ())
        status = (
            JobStatus.WAITING_EVIDENCE.value
            if evidence
            else JobStatus.COMPLETED.value
        )
        job = self.store.update_job(self._transition(job, status, now=now))
        result = ResearchResult(
            job_id=job.id,
            agent_name=str(plan.get("agent") or agent.name),
            confidence=str(plan.get("confidence") or ""),
            findings=tuple(plan.get("findings") or ()),
            evidence_required=evidence,
            blockers=tuple(plan.get("blockers") or ()),
            signals=tuple(plan.get("signals") or ()),
            created_at=now or utcnow_iso(),
            status=status,
        )
        self.store.set_result(result)
        return DispatchOutcome(job, result)

    def dispatch_many(
        self, candidates, *, now: str | None = None
    ) -> list[DispatchOutcome]:
        return [self.dispatch(candidate, now=now) for candidate in candidates]


__all__ = ["AgentOrchestrator", "DispatchOutcome", "OrchestratorError"]
