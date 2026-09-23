"""Phase 1/2: persistent Campaign and CampaignObjective models.

A Campaign is a bounded, scope-pinned research campaign: it owns multiple
objectives, a cumulative budget, dependencies between objectives, and an
auditable state machine.  A Campaign NEVER exists without an explicit
scope_ref (fail closed at construction).

These models are deliberately separate from ``hunt.HuntObjective`` (one per
hunt-enabled job, owned by the Hunt Planner): campaign objectives exist
BEFORE jobs, carry dependencies and campaign budgets, and are linked to
jobs/hunt objectives by id after execution.  Nothing here executes
observations — the executor delegates each objective to the existing
Runtime + Hunt Planner.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

CAMPAIGN_RULE_VERSION = "campaign-orchestrator-v1"

# Phase 1: campaign states. BUDGET_EXHAUSTED is the explicit non-COMPLETED
# stop state required by Phase 7.
CAMPAIGN_STATES: tuple[str, ...] = (
    "DRAFT", "READY", "RUNNING", "PAUSED", "WAITING", "COMPLETED",
    "BLOCKED", "CANCELLED", "EXPIRED", "FAILED", "BUDGET_EXHAUSTED",
)
CAMPAIGN_TERMINAL: frozenset[str] = frozenset({
    "COMPLETED", "BLOCKED", "CANCELLED", "EXPIRED", "FAILED",
    "BUDGET_EXHAUSTED",
})

# Phase 2: objective states.
OBJECTIVE_STATES: tuple[str, ...] = (
    "QUEUED", "READY", "RUNNING", "WAITING", "BLOCKED", "RESOLVED",
    "REJECTED", "EXPIRED", "FAILED", "CANCELLED",
)
OBJECTIVE_TERMINAL: frozenset[str] = frozenset({
    "RESOLVED", "REJECTED", "EXPIRED", "FAILED", "CANCELLED",
})
OBJECTIVE_EXECUTABLE: frozenset[str] = frozenset({"READY"})

# Phase 3: dependency types.
DEPENDENCY_TYPES: tuple[str, ...] = ("REQUIRED", "OPTIONAL", "INFORMATIONAL")

# A REQUIRED dependency is satisfied once the prereq has CONCLUDED with a
# research result: RESOLVED (positive) or REJECTED (preserved negative
# finding) both produce a result B can consume as context.  Failure-state
# prereqs produce NO research result and permanently block dependents.
REQUIRED_DEP_ACCEPTABLE: frozenset[str] = frozenset({"RESOLVED",
                                                     "REJECTED"})
# Non-acceptable terminal dep states => dependent is permanently blocked.
REQUIRED_DEP_PERMANENT_FAIL: frozenset[str] = frozenset({
    "BLOCKED", "EXPIRED", "CANCELLED", "FAILED",
})

_CAMPAIGN_TRANSITIONS: dict[str, frozenset[str]] = {
    "DRAFT": frozenset({"READY", "CANCELLED"}),
    "READY": frozenset({"RUNNING", "PAUSED", "CANCELLED", "EXPIRED",
                        "FAILED"}),
    "RUNNING": frozenset({"PAUSED", "WAITING", "COMPLETED", "BLOCKED",
                          "CANCELLED", "EXPIRED", "FAILED",
                          "BUDGET_EXHAUSTED"}),
    "WAITING": frozenset({"READY", "RUNNING", "PAUSED", "COMPLETED",
                          "BLOCKED", "CANCELLED", "EXPIRED", "FAILED",
                          "BUDGET_EXHAUSTED"}),
    "PAUSED": frozenset({"READY", "CANCELLED", "EXPIRED", "FAILED"}),
    # terminal states have no outbound transitions (enforced below)
}

_OBJECTIVE_TRANSITIONS: dict[str, frozenset[str]] = {
    "QUEUED": frozenset({"READY", "WAITING", "BLOCKED", "CANCELLED",
                         "EXPIRED"}),
    "READY": frozenset({"RUNNING", "WAITING", "BLOCKED", "CANCELLED",
                        "EXPIRED", "FAILED"}),
    "RUNNING": frozenset({"RESOLVED", "REJECTED", "FAILED", "BLOCKED",
                          "WAITING", "CANCELLED"}),
    "WAITING": frozenset({"READY", "BLOCKED", "CANCELLED", "EXPIRED",
                          "FAILED"}),
    "BLOCKED": frozenset({"READY", "CANCELLED", "EXPIRED", "FAILED"}),
    # terminal: RESOLVED / REJECTED / EXPIRED / FAILED / CANCELLED
}


class CampaignStateError(ValueError):
    """Invalid campaign/objective state transition (fail closed)."""


class CampaignScopeError(ValueError):
    """Missing or inconsistent scope (fail closed at construction)."""


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_scope_ref(scope_ref: str) -> str:
    """Explicit authorized scope is mandatory (Phase 1, rule 16)."""

    text = str(scope_ref or "").strip()
    if not text:
        raise CampaignScopeError("campaign scope_ref is required")
    if not (text.startswith("watch:scope:") or text.startswith("fixture:")):
        raise CampaignScopeError(
            f"scope_ref must be watch:scope: or fixture: prefixed: {text[:40]}")
    return text


@dataclass
class Dependency:
    """Phase 3: bounded objective dependency."""

    objective_id: str            # dependent (the objective that waits)
    depends_on: str              # prerequisite objective id
    kind: str = "REQUIRED"       # REQUIRED | OPTIONAL | INFORMATIONAL

    def __post_init__(self) -> None:
        if self.kind not in DEPENDENCY_TYPES:
            raise ValueError(f"unknown dependency kind: {self.kind!r}")
        if not str(self.objective_id or "").strip() \
                or not str(self.depends_on or "").strip():
            raise ValueError("dependency endpoints are required")
        if self.objective_id == self.depends_on:
            raise ValueError("self-dependency is not allowed")

    def to_dict(self) -> dict[str, Any]:
        return {"objective_id": self.objective_id,
                "depends_on": self.depends_on, "kind": self.kind}

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> Dependency:
        return cls(objective_id=str(row.get("objective_id") or ""),
                   depends_on=str(row.get("depends_on") or ""),
                   kind=str(row.get("kind") or "REQUIRED"))


@dataclass
class CampaignObjective:
    """Phase 2: one research objective inside a campaign."""

    objective_id: str
    campaign_id: str
    category: str                 # canonical specialist category (XSS, ...)
    scope_ref: str                # must equal the campaign scope
    research_question: str
    hypothesis: str
    specialist: str = ""          # "" = selector decides from capability
    priority: int = 50
    state: str = "QUEUED"
    evidence_requirements: dict[str, Any] = field(default_factory=dict)
    dependencies: list[Dependency] = field(default_factory=list)
    budget: dict[str, int] = field(default_factory=dict)   # objective caps
    created_at: str = ""
    updated_at: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    # execution linkage (filled by the executor; never faked)
    job_id: str = ""
    hunt_objective_id: str = ""
    revision: int = 1
    attempts: int = 0
    termination_reason: str = ""
    termination_detail: str = ""

    def __post_init__(self) -> None:
        self.scope_ref = validate_scope_ref(self.scope_ref)
        if not str(self.objective_id or "").strip():
            raise ValueError("objective_id is required")
        if not str(self.campaign_id or "").strip():
            raise ValueError("campaign_id is required")
        if not str(self.category or "").strip():
            raise ValueError("objective category is required")
        if not str(self.research_question or "").strip():
            raise ValueError("research_question is required")
        if self.state not in OBJECTIVE_STATES:
            raise ValueError(f"unknown objective state: {self.state!r}")
        self.priority = max(0, min(100, int(self.priority)))
        if self.created_at == "":
            self.created_at = utcnow()
        if self.updated_at == "":
            self.updated_at = self.created_at

    @property
    def is_terminal(self) -> bool:
        return self.state in OBJECTIVE_TERMINAL

    def transition(self, new_state: str, *, reason: str = "",
                   detail: str = "", now: str | None = None) -> None:
        """Validated state transition; terminal states are immutable."""

        if self.state in OBJECTIVE_TERMINAL:
            raise CampaignStateError(
                f"objective {self.objective_id} is terminal "
                f"({self.state}); cannot transition to {new_state}")
        allowed = _OBJECTIVE_TRANSITIONS.get(self.state, frozenset())
        if new_state not in allowed:
            raise CampaignStateError(
                f"invalid objective transition {self.state}->{new_state}")
        self.state = new_state
        self.revision += 1
        self.updated_at = now or utcnow()
        if reason:
            self.termination_reason = (reason if new_state in OBJECTIVE_TERMINAL
                                       else self.termination_reason)
        if detail:
            self.termination_detail = (
                detail if new_state in OBJECTIVE_TERMINAL
                else self.termination_detail)

    def correct(self, new_state: str, *, reason: str, detail: str = "",
                now: str | None = None) -> None:
        """Sanctioned correction of a mis-labelled terminal objective.

        Only REJECTED->RESOLVED is accepted, and only with an explicit
        ``authoritative_gate_correction`` reason backed by evidence — the
        Evidence Gate stays authoritative and this never re-opens
        execution: the corrected state is terminal and candidates are
        READY-only, so a corrected objective can never run again.
        """

        if self.state != "REJECTED" or new_state != "RESOLVED":
            raise CampaignStateError(
                f"objective correction supports only REJECTED->RESOLVED "
                f"(got {self.state}->{new_state})")
        if not str(reason or "").startswith(
                "authoritative_gate_correction"):
            raise CampaignStateError(
                "objective correction requires an "
                "authoritative_gate_correction reason")
        if not str(detail or "").strip():
            raise CampaignStateError(
                "objective correction requires evidence")
        self.state = new_state
        self.revision += 1
        self.updated_at = now or utcnow()
        self.termination_reason = str(reason)[:400]
        self.termination_detail = str(detail)[:400]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_version": CAMPAIGN_RULE_VERSION,
            "objective_id": self.objective_id,
            "campaign_id": self.campaign_id,
            "category": self.category,
            "scope_ref": self.scope_ref,
            "research_question": self.research_question,
            "hypothesis": self.hypothesis,
            "specialist": self.specialist,
            "priority": self.priority,
            "state": self.state,
            "evidence_requirements": dict(self.evidence_requirements),
            "dependencies": [d.to_dict() for d in self.dependencies],
            "budget": dict(self.budget),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "provenance": dict(self.provenance),
            "job_id": self.job_id,
            "hunt_objective_id": self.hunt_objective_id,
            "revision": self.revision,
            "attempts": self.attempts,
            "termination_reason": self.termination_reason,
            "termination_detail": self.termination_detail,
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> CampaignObjective:
        return cls(
            objective_id=str(row.get("objective_id") or ""),
            campaign_id=str(row.get("campaign_id") or ""),
            category=str(row.get("category") or ""),
            scope_ref=str(row.get("scope_ref") or ""),
            research_question=str(row.get("research_question") or ""),
            hypothesis=str(row.get("hypothesis") or ""),
            specialist=str(row.get("specialist") or ""),
            priority=int(row.get("priority") or 50),
            state=str(row.get("state") or "QUEUED"),
            evidence_requirements=dict(row.get("evidence_requirements") or {}),
            dependencies=[Dependency.from_dict(d)
                          for d in (row.get("dependencies") or [])],
            budget={k: int(v) for k, v in
                    (row.get("budget") or {}).items()},
            created_at=str(row.get("created_at") or ""),
            updated_at=str(row.get("updated_at") or ""),
            provenance=dict(row.get("provenance") or {}),
            job_id=str(row.get("job_id") or ""),
            hunt_objective_id=str(row.get("hunt_objective_id") or ""),
            revision=int(row.get("revision") or 1),
            attempts=int(row.get("attempts") or 0),
            termination_reason=str(row.get("termination_reason") or ""),
            termination_detail=str(row.get("termination_detail") or ""),
        )


@dataclass
class Campaign:
    """Phase 1: persistent, scope-pinned research campaign."""

    campaign_id: str
    program: str
    scope_ref: str
    campaign_objective: str
    target_context: dict[str, Any] = field(default_factory=dict)
    participating_specialists: tuple[str, ...] = ()
    priority: int = 50
    state: str = "DRAFT"
    # limits: the campaign's cumulative caps; budget: consumed amounts.
    limits: dict[str, int] = field(default_factory=dict)
    budget: dict[str, int] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    # coordinator lease (Phase 13): one coordinator at a time
    lease_owner: str = ""
    lease_expires_at: str = ""
    termination_reason: str = ""
    termination_detail: str = ""
    termination_record: dict[str, Any] = field(default_factory=dict)
    revision: int = 1

    def __post_init__(self) -> None:
        self.scope_ref = validate_scope_ref(self.scope_ref)
        if not str(self.campaign_id or "").strip():
            raise ValueError("campaign_id is required")
        if not str(self.campaign_objective or "").strip():
            raise ValueError("campaign_objective is required")
        if self.state not in CAMPAIGN_STATES:
            raise ValueError(f"unknown campaign state: {self.state!r}")
        self.priority = max(0, min(100, int(self.priority)))
        self.limits = {k: int(v) for k, v in self.limits.items()}
        self.budget = {k: int(v) for k, v in self.budget.items()}
        if self.created_at == "":
            self.created_at = utcnow()
        if self.updated_at == "":
            self.updated_at = self.created_at

    @property
    def is_terminal(self) -> bool:
        return self.state in CAMPAIGN_TERMINAL

    def transition(self, new_state: str, *, reason: str = "",
                   detail: str = "", now: str | None = None) -> None:
        """Validated campaign state transition (every one is auditable).

        Terminal campaigns are immutable except for the DRAFT->READY boot.
        """

        if self.state in CAMPAIGN_TERMINAL:
            raise CampaignStateError(
                f"campaign {self.campaign_id} is terminal ({self.state}); "
                f"cannot transition to {new_state}")
        allowed = _CAMPAIGN_TRANSITIONS.get(self.state, frozenset())
        if new_state not in allowed:
            raise CampaignStateError(
                f"invalid campaign transition {self.state}->{new_state}")
        self.state = new_state
        self.revision += 1
        self.updated_at = now or utcnow()
        if new_state in CAMPAIGN_TERMINAL:
            self.termination_reason = reason or new_state
            if detail:
                self.termination_detail = detail
        elif reason:
            self.termination_reason = ""
            self.termination_detail = detail

    def scope_matches(self, scope_ref: str) -> bool:
        """Rule 15: objectives can never widen campaign scope."""

        return str(scope_ref or "") == self.scope_ref

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_version": CAMPAIGN_RULE_VERSION,
            "campaign_id": self.campaign_id,
            "program": self.program,
            "scope_ref": self.scope_ref,
            "campaign_objective": self.campaign_objective,
            "target_context": dict(self.target_context),
            "participating_specialists": list(self.participating_specialists),
            "priority": self.priority,
            "state": self.state,
            "limits": dict(self.limits),
            "budget": dict(self.budget),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "provenance": dict(self.provenance),
            "lease_owner": self.lease_owner,
            "lease_expires_at": self.lease_expires_at,
            "termination_reason": self.termination_reason,
            "termination_detail": self.termination_detail,
            "termination_record": dict(self.termination_record),
            "revision": self.revision,
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> Campaign:
        return cls(
            campaign_id=str(row.get("campaign_id") or ""),
            program=str(row.get("program") or ""),
            scope_ref=str(row.get("scope_ref") or ""),
            campaign_objective=str(row.get("campaign_objective") or ""),
            target_context=dict(row.get("target_context") or {}),
            participating_specialists=tuple(
                row.get("participating_specialists") or ()),
            priority=int(row.get("priority") or 50),
            state=str(row.get("state") or "DRAFT"),
            limits={k: int(v) for k, v in (row.get("limits") or {}).items()},
            budget={k: int(v) for k, v in (row.get("budget") or {}).items()},
            created_at=str(row.get("created_at") or ""),
            updated_at=str(row.get("updated_at") or ""),
            provenance=dict(row.get("provenance") or {}),
            lease_owner=str(row.get("lease_owner") or ""),
            lease_expires_at=str(row.get("lease_expires_at") or ""),
            termination_reason=str(row.get("termination_reason") or ""),
            termination_detail=str(row.get("termination_detail") or ""),
            termination_record=dict(row.get("termination_record") or {}),
            revision=int(row.get("revision") or 1),
        )


def validate_campaign_transition(old: str, new: str) -> None:
    """Standalone validator used by the store and tests."""

    if old in CAMPAIGN_TERMINAL:
        raise CampaignStateError(
            f"terminal campaign state {old} has no transitions")
    allowed = _CAMPAIGN_TRANSITIONS.get(old, frozenset())
    if new not in allowed:
        raise CampaignStateError(f"invalid campaign transition {old}->{new}")


def validate_objective_transition(old: str, new: str) -> None:
    if old in OBJECTIVE_TERMINAL:
        raise CampaignStateError(
            f"terminal objective state {old} has no transitions")
    allowed = _OBJECTIVE_TRANSITIONS.get(old, frozenset())
    if new not in allowed:
        raise CampaignStateError(f"invalid objective transition {old}->{new}")


__all__ = [
    "CAMPAIGN_RULE_VERSION", "CAMPAIGN_STATES", "CAMPAIGN_TERMINAL",
    "OBJECTIVE_STATES", "OBJECTIVE_TERMINAL", "OBJECTIVE_EXECUTABLE",
    "DEPENDENCY_TYPES", "REQUIRED_DEP_ACCEPTABLE",
    "REQUIRED_DEP_PERMANENT_FAIL",
    "CampaignStateError", "CampaignScopeError",
    "Dependency", "CampaignObjective", "Campaign",
    "validate_scope_ref", "validate_campaign_transition",
    "validate_objective_transition", "new_id", "utcnow",
]
