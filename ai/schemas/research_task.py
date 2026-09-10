"""Research workflow task schema (Stage R20).

A :class:`ResearchTask` tracks the RESEARCH state of one R18 queue candidate
(CVE x program). It is research management only: statuses are TODO /
IN_PROGRESS / BLOCKED / DONE — never VERIFIED / VULNERABLE / EXPLOITED.

The task_id is deterministic (also in ``ai.knowledge.task_store``); timestamps
are workflow metadata only and never enter queue-intelligence decisions.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

RESEARCH_TASK_RULE_VERSION = "r20-1"

TASK_STATUSES: tuple[str, ...] = ("TODO", "IN_PROGRESS", "BLOCKED", "DONE")

MAX_TITLE_CHARS = 200
MAX_NOTES_CHARS = 4000
MAX_BLOCKER_CHARS = 500
MAX_RESULT_CHARS = 2000
MAX_REFERENCE_CHARS = 500
MAX_REFERENCES = 20
MAX_HISTORY = 50


class ResearchTaskAuditEntry(BaseModel):
    """One bounded audit record for a task mutation (no request payloads)."""

    at: str = ""
    previous_status: str = ""
    new_status: str = ""
    version: int = 1


class ResearchTask(BaseModel):
    """Additive persisted research-workflow task."""

    task_id: str
    cve: str
    program: str
    queue_id: str
    status: str = "TODO"
    title: str = ""
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""
    completed_at: str | None = None
    blocker: str = ""
    result_summary: str = ""
    references: list[str] = Field(default_factory=list)
    rule_version: str = RESEARCH_TASK_RULE_VERSION
    # Optimistic-concurrency token; incremented on every successful mutation.
    version: int = 1
    # Bounded audit history (most recent MAX_HISTORY entries).
    history: list[ResearchTaskAuditEntry] = Field(default_factory=list)
