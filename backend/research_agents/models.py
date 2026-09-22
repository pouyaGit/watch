"""backend/research_agents/models.py — research job / result vocabulary.

Pure, dependency-free values shared by the registry, orchestrator and service.
Nothing here performs IO.

Lifecycle (Part 1):

    NEW -> QUEUED -> ASSIGNED -> RUNNING -> WAITING_EVIDENCE -> COMPLETED
    (FAILED is reachable from any active state.)

A job is an *investigation plan*, never an exploitation step. A result records
the evidence a specialist agent still requires and the blockers that prevent a
finding from being claimed; it never claims a vulnerability.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

#: Stable identifier for the deterministic orchestration rules shipped in v1.
RESEARCH_JOB_RULE_VERSION = "research-agents-1"


class JobStatus(str, Enum):
    """Research job lifecycle statuses.

    Part 1 vocabulary plus the Agent Runtime v1 additions (CLAIMED with a
    lease, CANCELLED, EXPIRED lease, TIMEOUT, TERMINAL_FAILED).  Every
    value is real runtime state — nothing here is inferred from the static
    registry.
    """

    NEW = "NEW"
    QUEUED = "QUEUED"
    ASSIGNED = "ASSIGNED"
    CLAIMED = "CLAIMED"
    RUNNING = "RUNNING"
    WAITING_EVIDENCE = "WAITING_EVIDENCE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    TERMINAL_FAILED = "TERMINAL_FAILED"


JOB_STATUSES: tuple[str, ...] = tuple(status.value for status in JobStatus)

#: Allowed lifecycle transitions (a status may always stay the same).
JOB_STATUS_FLOW: dict[str, tuple[str, ...]] = {
    JobStatus.NEW.value: (JobStatus.QUEUED.value, JobStatus.FAILED.value),
    JobStatus.QUEUED.value: (
        JobStatus.ASSIGNED.value,
        JobStatus.CLAIMED.value,
        JobStatus.CANCELLED.value,
        JobStatus.FAILED.value,
    ),
    JobStatus.ASSIGNED.value: (
        JobStatus.RUNNING.value,
        JobStatus.QUEUED.value,
        JobStatus.FAILED.value,
    ),
    JobStatus.CLAIMED.value: (
        JobStatus.RUNNING.value,
        JobStatus.QUEUED.value,      # released before start (no orphan)
        JobStatus.EXPIRED.value,     # lease lost before start
        JobStatus.CANCELLED.value,
        JobStatus.FAILED.value,
    ),
    JobStatus.RUNNING.value: (
        JobStatus.WAITING_EVIDENCE.value,
        JobStatus.COMPLETED.value,
        JobStatus.TIMEOUT.value,
        JobStatus.CANCELLED.value,
        JobStatus.FAILED.value,
    ),
    JobStatus.WAITING_EVIDENCE.value: (
        JobStatus.COMPLETED.value,
        JobStatus.RUNNING.value,
        JobStatus.CANCELLED.value,
        JobStatus.FAILED.value,
    ),
    # failure paths: retry while attempts remain, otherwise terminal
    JobStatus.FAILED.value: (
        JobStatus.QUEUED.value,
        JobStatus.TERMINAL_FAILED.value,
    ),
    JobStatus.TIMEOUT.value: (
        JobStatus.QUEUED.value,
        JobStatus.TERMINAL_FAILED.value,
    ),
    JobStatus.EXPIRED.value: (
        JobStatus.QUEUED.value,      # orphaned work returns to the queue
        JobStatus.FAILED.value,
    ),
    JobStatus.COMPLETED.value: (),
    JobStatus.CANCELLED.value: (),
    JobStatus.TERMINAL_FAILED.value: (),
}

#: States a job can never leave.
TERMINAL_JOB_STATUSES: frozenset[str] = frozenset({
    JobStatus.COMPLETED.value,
    JobStatus.CANCELLED.value,
    JobStatus.TERMINAL_FAILED.value,
})

#: Active (work-in-progress) statuses used by queue counters.
ACTIVE_JOB_STATUSES: frozenset[str] = frozenset({
    JobStatus.NEW.value,
    JobStatus.QUEUED.value,
    JobStatus.ASSIGNED.value,
    JobStatus.CLAIMED.value,
    JobStatus.RUNNING.value,
    JobStatus.WAITING_EVIDENCE.value,
})

#: Agent availability vocabulary.
AGENT_STATUSES: tuple[str, ...] = ("ready", "planned", "disabled")

#: Candidate category -> specialist agent category (Part 3 mapping).
CATEGORY_TO_AGENT: dict[str, str] = {
    "XSS_CANDIDATE": "xss",
    "IDOR_CANDIDATE": "idor",
    "SSRF_CANDIDATE": "ssrf",
    "FILE_UPLOAD_CANDIDATE": "file_upload",
    "AUTHZ_CANDIDATE": "authz",
    "AUTHORIZATION_CANDIDATE": "authz",
    "ACCESS_CONTROL_CANDIDATE": "authz",
}


def _text(value: object, limit: int = 512) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def utcnow_iso() -> str:
    """Current UTC time as ``YYYY-MM-DDTHH:MM:SSZ``."""

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def agent_category_for(category: object) -> str:
    """Map an attack-surface category to a specialist agent category."""

    text = _text(category, 64).upper()
    if text in CATEGORY_TO_AGENT:
        return CATEGORY_TO_AGENT[text]
    return text.lower().replace("_candidate", "")


def field(obj: object, name: str, default=None):
    """Read ``name`` from a dataclass or a mapping (candidate adapter)."""

    if isinstance(obj, dict):
        value = obj.get(name, default)
    else:
        value = getattr(obj, name, default)
    return default if value is None else value


def _tuple_of_text(value: object, limit: int = 24) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            text = _text(item, 240)
            if text and text not in out:
                out.append(text)
            if len(out) >= limit:
                break
        return tuple(out)
    return ()


@dataclass(frozen=True)
class CandidateRef:
    """Normalized attack-surface candidate consumed by the orchestrator.

    Adapts either the ``AttackSurfaceCandidate`` dataclass or the JSON priority
    queue entry into one shape, so agents never depend on the attack-surface
    package internals.
    """

    id: str = ""
    category: str = ""
    endpoint: str = ""
    parameter: str = ""
    method: str = "GET"
    priority_score: int = 0
    confidence: str = ""
    technology: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    program: str = ""
    subdomain: str = ""
    url: str = ""
    location: str = "query"
    source: str = "watch"

    @property
    def agent_category(self) -> str:
        return agent_category_for(self.category)

    @classmethod
    def from_any(cls, candidate: object) -> "CandidateRef":
        if isinstance(candidate, CandidateRef):
            return candidate
        try:
            score = int(field(candidate, "priority_score",
                              field(candidate, "score", 0)) or 0)
        except (TypeError, ValueError):
            score = 0
        return cls(
            id=_text(field(candidate, "id", ""), 64),
            category=_text(field(candidate, "category", ""), 64),
            endpoint=_text(field(candidate, "endpoint", ""), 512),
            parameter=_text(field(candidate, "parameter", ""), 128),
            method=(_text(field(candidate, "method", ""), 16) or "GET").upper(),
            priority_score=score,
            confidence=_text(field(candidate, "confidence", ""), 16).upper(),
            technology=_tuple_of_text(field(candidate, "technology", ())),
            reasons=_tuple_of_text(field(candidate, "reasons", ())),
            program=_text(field(candidate, "program", ""), 128),
            subdomain=_text(field(candidate, "subdomain", ""), 256),
            url=_text(field(candidate, "url", ""), 1024),
            location=_text(field(candidate, "location", ""), 16) or "query",
            source=_text(field(candidate, "source", ""), 32) or "watch",
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "agent_category": self.agent_category,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "priority_score": int(self.priority_score),
            "confidence": self.confidence,
            "technology": list(self.technology),
            "reasons": list(self.reasons),
            "program": self.program,
            "subdomain": self.subdomain,
            "url": self.url,
            "location": self.location,
            "source": self.source,
        }


def job_id_for(candidate_id: object, agent_category: object) -> str:
    """Deterministic, stable research-job id (``rj-`` + 16 hex chars)."""

    seed = "\x1f".join(
        _text(value, 256).lower()
        for value in (candidate_id, agent_category)
    )
    return "rj-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class ResearchJob:
    """One structured security investigation job (Part 1)."""

    id: str
    candidate_id: str
    category: str
    endpoint: str
    parameter: str
    priority_score: int
    status: str = JobStatus.NEW.value
    assigned_agent: str = ""
    created_at: str | None = None
    updated_at: str | None = None
    agent_category: str = ""
    method: str = "GET"
    confidence: str = ""
    reasons: tuple[str, ...] = ()
    technology: tuple[str, ...] = ()
    program: str = ""
    subdomain: str = ""
    url: str = ""
    rule_version: str = RESEARCH_JOB_RULE_VERSION
    # -- Agent Runtime v1 (all defaulted: Part-1 constructors stay valid) --
    mission: str = ""
    authorization_ref: str = ""
    claimed_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    attempt_count: int = 0
    max_attempts: int = 3
    lease_owner: str = ""
    lease_expires_at: str | None = None
    heartbeat_at: str | None = None
    timeout_seconds: int = 300
    result_ref: str = ""
    evidence_refs: tuple[str, ...] = ()
    case_ref: str = ""
    error: str = ""
    execution_mode: str = "production"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "candidate_id": self.candidate_id,
            "category": self.category,
            "agent_category": self.agent_category,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "priority_score": int(self.priority_score),
            "status": self.status,
            "assigned_agent": self.assigned_agent,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "technology": list(self.technology),
            "program": self.program,
            "subdomain": self.subdomain,
            "url": self.url,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "rule_version": self.rule_version,
            "mission": self.mission,
            "authorization_ref": self.authorization_ref,
            "claimed_at": self.claimed_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "attempt_count": int(self.attempt_count),
            "max_attempts": int(self.max_attempts),
            "lease_owner": self.lease_owner,
            "lease_expires_at": self.lease_expires_at,
            "heartbeat_at": self.heartbeat_at,
            "timeout_seconds": int(self.timeout_seconds),
            "result_ref": self.result_ref,
            "evidence_refs": list(self.evidence_refs),
            "case_ref": self.case_ref,
            "error": self.error,
            "execution_mode": self.execution_mode,
        }


@dataclass(frozen=True)
class ResearchResult:
    """Specialist-agent investigation result / evidence plan (Part 1)."""

    job_id: str
    agent_name: str
    confidence: str
    findings: tuple[str, ...] = ()
    evidence_required: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    created_at: str | None = None
    signals: tuple[str, ...] = ()
    status: str = JobStatus.WAITING_EVIDENCE.value
    rule_version: str = RESEARCH_JOB_RULE_VERSION
    # -- Agent Runtime v1: analysis provenance (never secrets) --
    provider: str = ""
    model: str = ""
    prompt_version: str = ""
    analysis_ms: int = 0
    execution_mode: str = "production"
    # Phase 3: validated structured analysis (LLM output is INPUT only)
    structured: dict = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.structured is None:
            object.__setattr__(self, "structured", {})

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "agent_name": self.agent_name,
            "confidence": self.confidence,
            "findings": list(self.findings),
            "evidence_required": list(self.evidence_required),
            "blockers": list(self.blockers),
            "signals": list(self.signals),
            "status": self.status,
            "created_at": self.created_at,
            "rule_version": self.rule_version,
            "provider": self.provider,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "analysis_ms": int(self.analysis_ms),
            "execution_mode": self.execution_mode,
            "structured": dict(self.structured or {}),
        }


@dataclass(frozen=True)
class AgentInfo:
    """A registered specialist agent (Part 2)."""

    key: str
    name: str
    category: str
    status: str = "ready"
    description: str = ""
    evidence_types: tuple[str, ...] = ()
    strategy: tuple[str, ...] = ()
    report_sections: tuple[str, ...] = ()
    confidence_model: str = ""

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "description": self.description,
            "evidence_types": list(self.evidence_types),
            "strategy": list(self.strategy),
            "report_sections": list(self.report_sections),
            "confidence_model": self.confidence_model,
        }


__all__ = [
    "RESEARCH_JOB_RULE_VERSION",
    "JobStatus",
    "JOB_STATUSES",
    "JOB_STATUS_FLOW",
    "ACTIVE_JOB_STATUSES",
    "TERMINAL_JOB_STATUSES",
    "AGENT_STATUSES",
    "CATEGORY_TO_AGENT",
    "utcnow_iso",
    "agent_category_for",
    "field",
    "CandidateRef",
    "job_id_for",
    "ResearchJob",
    "ResearchResult",
    "AgentInfo",
]
