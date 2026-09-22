"""backend/research_agents — Security Research Agent Orchestration (v1).

Converts Attack Surface Intelligence candidates into structured security
investigation jobs, assigns a specialist research agent, and produces the
evidence requirements a human/agent must satisfy before a finding could ever
be claimed.

Package layout:

- ``models``       -- research job / result / agent vocabulary + lifecycle.
- ``repository``   -- read-only candidate source + in-memory job store.
- ``registry``     -- specialist agent registry (register/list/get).
- ``agents``       -- the specialist agents (XSS, IDOR).
- ``orchestrator`` -- candidate -> job -> agent assignment -> evidence plan.
- ``service``      -- orchestration facade + Command Center payloads.

This framework **never executes exploitation**. It only creates investigation
plans and evidence requirements. No network, no LLM, no target interaction, no
Nuclei/browser/PoC, no writes to the production database.
"""

from __future__ import annotations

from backend.research_agents.models import (
    AGENT_STATUSES,
    JOB_STATUSES,
    RESEARCH_JOB_RULE_VERSION,
    AgentInfo,
    CandidateRef,
    JobStatus,
    ResearchJob,
    ResearchResult,
    job_id_for,
)
from backend.research_agents.registry import (
    AgentRegistry,
    build_default_registry,
)
from backend.research_agents.repository import (
    ResearchJobStore,
    candidates_from_payload,
    load_priority_candidates,
)
from backend.research_agents.orchestrator import (
    AgentOrchestrator,
    DispatchOutcome,
)
from backend.research_agents.service import (
    agents_payload,
    bootstrap_pipeline,
    command_center_payload,
    create_jobs,
    get_job,
    list_jobs,
    list_results,
    reset_pipeline,
)

__all__ = [
    "AGENT_STATUSES",
    "JOB_STATUSES",
    "RESEARCH_JOB_RULE_VERSION",
    "AgentInfo",
    "CandidateRef",
    "JobStatus",
    "ResearchJob",
    "ResearchResult",
    "job_id_for",
    "AgentRegistry",
    "build_default_registry",
    "ResearchJobStore",
    "candidates_from_payload",
    "load_priority_candidates",
    "AgentOrchestrator",
    "DispatchOutcome",
    "agents_payload",
    "bootstrap_pipeline",
    "command_center_payload",
    "create_jobs",
    "get_job",
    "list_jobs",
    "list_results",
    "reset_pipeline",
]
