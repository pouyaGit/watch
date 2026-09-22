"""Hunt Planner persistence models (Phases 3-5, 8).

HuntObjective — persistent, auditable research objective.
HuntPlan — immutable plan definition + explicit state machine; state
changes are recorded as PlanTransition rows, never by rewriting a plan.
AuthorizationRecord / ObservationRecord — bridge and execution evidence.

All models are pure data with validated construction: no I/O, no LLM,
no network, no execution, no scope logic (that lives in authorization.py).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

PLAN_RULE_VERSION = "hunt-plan-v1"
OBJECTIVE_RULE_VERSION = "hunt-objective-v1"
PLANNER_VERSION = "hunt-planner-v1"
ADVISOR_PROMPT_VERSION = "hunt-planner-advisor-v1"

# ---------------------------------------------------------------- plans
PLAN_STATES: tuple[str, ...] = (
    "DRAFT",
    "VALIDATED",
    "AUTHORIZATION_REQUIRED",
    "AUTHORIZED",
    "EXECUTING",
    "COMPLETED",
    "PARTIAL",
    "REJECTED",
    "FAILED",
    "BLOCKED",
    "EXPIRED",
)

PLAN_TRANSITIONS: dict[str, frozenset[str]] = {
    "DRAFT": frozenset({"VALIDATED", "REJECTED", "EXPIRED"}),
    "VALIDATED": frozenset({"AUTHORIZATION_REQUIRED", "REJECTED",
                            "EXPIRED"}),
    "AUTHORIZATION_REQUIRED": frozenset({"AUTHORIZED", "BLOCKED",
                                         "REJECTED", "EXPIRED"}),
    "AUTHORIZED": frozenset({"EXECUTING", "BLOCKED", "EXPIRED",
                             "REJECTED"}),
    "EXECUTING": frozenset({"COMPLETED", "PARTIAL", "FAILED"}),
    "COMPLETED": frozenset(),
    "PARTIAL": frozenset(),
    "REJECTED": frozenset(),
    "FAILED": frozenset(),
    "BLOCKED": frozenset(),
    "EXPIRED": frozenset(),
}

PLAN_MUTABLE_STATES: frozenset[str] = frozenset({"DRAFT"})
# Definition may never change once the plan leaves DRAFT; state changes
# ride PlanTransition rows only.
PLAN_DEFINITIVE_SINCE: str = "VALIDATED"


class PlanError(ValueError):
    """Invalid plan construction or state transition."""


def plan_transition(current: str, new: str) -> str:
    if current not in PLAN_TRANSITIONS:
        raise PlanError(f"unknown plan state: {current!r}")
    if new not in PLAN_STATES:
        raise PlanError(f"unknown plan next state: {new!r}")
    if new not in PLAN_TRANSITIONS[current]:
        raise PlanError(f"illegal plan transition {current} -> {new}")
    return new


def new_id(prefix: str) -> str:
    import uuid
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _bounded(value: object, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


# ------------------------------------------------------------ objectives
@dataclass
class HuntObjective:
    """Persistent research objective (Phase 3). One per hunt-enabled job."""

    objective_id: str
    job_id: str
    specialist: str            # agent name (xss-agent, ...)
    category: str              # XSS / CVE_RESEARCH / ...
    scope_ref: str             # watch:scope:<program>/<subdomain>
    target_context: dict[str, Any]
    hypothesis: str
    research_objective: str
    evidence_requirements: dict[str, Any]
    state: str = "OPEN"
    priority: int = 50
    revision: int = 1
    iteration: int = 0
    plans_created: int = 0
    observations_run: int = 0
    llm_plans_used: int = 0
    termination_reason: str = ""
    termination_detail: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not (self.objective_id and self.job_id and self.scope_ref
                and self.specialist and self.category):
            raise ValueError("objective requires ids, specialist, scope_ref")
        if not self.provenance.get("source"):
            raise ValueError("objective requires provenance.source")
        if not (self.created_at and self.updated_at):
            raise ValueError("objective requires created_at/updated_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_version": OBJECTIVE_RULE_VERSION,
            "objective_id": _bounded(self.objective_id, 80),
            "job_id": _bounded(self.job_id, 80),
            "specialist": _bounded(self.specialist, 60),
            "category": _bounded(self.category, 40),
            "scope_ref": _bounded(self.scope_ref, 120),
            "target_context": dict(self.target_context),
            "hypothesis": _bounded(self.hypothesis, 300),
            "research_objective": _bounded(self.research_objective, 300),
            "evidence_requirements": dict(self.evidence_requirements),
            "state": self.state,
            "priority": int(self.priority),
            "revision": int(self.revision),
            "iteration": int(self.iteration),
            "plans_created": int(self.plans_created),
            "observations_run": int(self.observations_run),
            "llm_plans_used": int(self.llm_plans_used),
            "termination_reason": _bounded(self.termination_reason, 80),
            "termination_detail": _bounded(self.termination_detail, 300),
            "provenance": dict(self.provenance),
            "created_at": _bounded(self.created_at, 40),
            "updated_at": _bounded(self.updated_at, 40),
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "HuntObjective":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in row.items() if k in known
                      and k != "rule_version"})


# ----------------------------------------------------------------- plans
@dataclass(frozen=True)
class HuntPlan:
    """Immutable bounded Hunt Plan definition (Phase 4)."""

    plan_id: str
    objective_id: str
    job_id: str
    version: int
    parent_plan_id: str
    scope_ref: str
    specialist: str
    category: str
    reason: str
    hypotheses_addressed: tuple[str, ...]
    observations_requested: tuple[dict[str, Any], ...]
    required_evidence: tuple[str, ...]
    expected_information_gain: float
    gain_label: str                 # always "heuristic" for now
    safety_constraints: tuple[str, ...]
    authorization_requirements: tuple[str, ...]
    dependencies: tuple[str, ...]
    priority: int
    provenance: dict[str, Any]
    created_at: str

    def __post_init__(self) -> None:
        if not (self.plan_id and self.objective_id and self.scope_ref):
            raise PlanError("plan requires plan_id, objective_id, scope_ref")
        if self.version < 1:
            raise PlanError("plan version must be >= 1")
        if not self.observations_requested:
            raise PlanError("plan requires at least one observation request")
        for req in self.observations_requested:
            if not isinstance(req, dict) or not req.get("observation_type"):
                raise PlanError("observation request requires observation_type")
        if self.gain_label != "heuristic":
            raise PlanError("information gain may only be labelled heuristic")
        if not 0.0 <= float(self.expected_information_gain) <= 1.0:
            raise PlanError("expected_information_gain must be within 0..1")
        if not (self.provenance.get("planner")
                and self.created_at):
            raise PlanError("plan requires provenance.planner + created_at")

    @property
    def observation_types(self) -> tuple[str, ...]:
        return tuple(str(r.get("observation_type") or "")
                     for r in self.observations_requested)

    def definition_hash(self) -> str:
        """Stable hash of the immutable definition (recorded at EXECUTING)."""
        payload = {
            "plan_id": self.plan_id,
            "objective_id": self.objective_id,
            "version": self.version,
            "scope_ref": self.scope_ref,
            "observations_requested":
                [dict(r) for r in self.observations_requested],
            "required_evidence": list(self.required_evidence),
            "reason": self.reason,
        }
        blob = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_version": PLAN_RULE_VERSION,
            "plan_id": _bounded(self.plan_id, 80),
            "objective_id": _bounded(self.objective_id, 80),
            "job_id": _bounded(self.job_id, 80),
            "version": int(self.version),
            "parent_plan_id": _bounded(self.parent_plan_id, 80),
            "scope_ref": _bounded(self.scope_ref, 120),
            "specialist": _bounded(self.specialist, 60),
            "category": _bounded(self.category, 40),
            "reason": _bounded(self.reason, 400),
            "hypotheses_addressed":
                [_bounded(h, 240) for h in self.hypotheses_addressed][:6],
            "observations_requested": [
                {k: v for k, v in dict(r).items()}
                for r in self.observations_requested[:6]],
            "required_evidence":
                [_bounded(r, 80) for r in self.required_evidence][:12],
            "expected_information_gain": round(
                float(self.expected_information_gain), 4),
            "gain_label": self.gain_label,
            "safety_constraints":
                [_bounded(c, 120) for c in self.safety_constraints][:12],
            "authorization_requirements":
                [_bounded(a, 120) for a in self.authorization_requirements][:12],
            "dependencies": [_bounded(d, 80) for d in self.dependencies][:12],
            "priority": int(self.priority),
            "provenance": dict(self.provenance),
            "created_at": _bounded(self.created_at, 40),
            "definition_hash": self.definition_hash(),
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "HuntPlan":
        return cls(
            plan_id=str(row.get("plan_id") or ""),
            objective_id=str(row.get("objective_id") or ""),
            job_id=str(row.get("job_id") or ""),
            version=int(row.get("version") or 0),
            parent_plan_id=str(row.get("parent_plan_id") or ""),
            scope_ref=str(row.get("scope_ref") or ""),
            specialist=str(row.get("specialist") or ""),
            category=str(row.get("category") or ""),
            reason=str(row.get("reason") or ""),
            hypotheses_addressed=tuple(
                row.get("hypotheses_addressed") or ()),
            observations_requested=tuple(
                dict(r) for r in (row.get("observations_requested") or ())),
            required_evidence=tuple(row.get("required_evidence") or ()),
            expected_information_gain=float(
                row.get("expected_information_gain") or 0.0),
            gain_label=str(row.get("gain_label") or "heuristic"),
            safety_constraints=tuple(row.get("safety_constraints") or ()),
            authorization_requirements=tuple(
                row.get("authorization_requirements") or ()),
            dependencies=tuple(row.get("dependencies") or ()),
            priority=int(row.get("priority") or 50),
            provenance=dict(row.get("provenance") or {}),
            created_at=str(row.get("created_at") or ""),
        )


@dataclass(frozen=True)
class PlanTransition:
    plan_id: str
    from_state: str
    to_state: str
    reason: str
    at: str
    definition_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": _bounded(self.plan_id, 80),
            "from_state": self.from_state,
            "to_state": self.to_state,
            "reason": _bounded(self.reason, 200),
            "at": _bounded(self.at, 40),
            "definition_hash": _bounded(self.definition_hash, 32),
        }


# --------------------------------------------------------- authorization
@dataclass(frozen=True)
class AuthorizationRecord:
    """Result of the authorization bridge (Phase 8). Fail-closed."""

    auth_id: str
    plan_id: str
    objective_id: str
    job_id: str
    scope_ref: str
    target: str
    observation_types: tuple[str, ...]
    capability: str
    specialist: str
    purpose: str
    allowed_data: tuple[str, ...]
    safety_class: str
    status: str                     # GRANTED | DENIED
    reasons: tuple[str, ...]
    gate: str
    requested_at: str
    decided_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "auth_id": _bounded(self.auth_id, 80),
            "plan_id": _bounded(self.plan_id, 80),
            "objective_id": _bounded(self.objective_id, 80),
            "job_id": _bounded(self.job_id, 80),
            "scope_ref": _bounded(self.scope_ref, 120),
            "target": _bounded(self.target, 160),
            "observation_types": [str(t) for t in self.observation_types],
            "capability": _bounded(self.capability, 60),
            "specialist": _bounded(self.specialist, 60),
            "purpose": _bounded(self.purpose, 120),
            "allowed_data": [str(a) for a in self.allowed_data][:12],
            "safety_class": _bounded(self.safety_class, 40),
            "status": self.status,
            "reasons": [_bounded(r, 160) for r in self.reasons][:8],
            "gate": _bounded(self.gate, 80),
            "requested_at": _bounded(self.requested_at, 40),
            "decided_at": _bounded(self.decided_at, 40),
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "AuthorizationRecord":
        return cls(
            auth_id=str(row.get("auth_id") or ""),
            plan_id=str(row.get("plan_id") or ""),
            objective_id=str(row.get("objective_id") or ""),
            job_id=str(row.get("job_id") or ""),
            scope_ref=str(row.get("scope_ref") or ""),
            target=str(row.get("target") or ""),
            observation_types=tuple(row.get("observation_types") or ()),
            capability=str(row.get("capability") or ""),
            specialist=str(row.get("specialist") or ""),
            purpose=str(row.get("purpose") or ""),
            allowed_data=tuple(row.get("allowed_data") or ()),
            safety_class=str(row.get("safety_class") or ""),
            status=str(row.get("status") or ""),
            reasons=tuple(row.get("reasons") or ()),
            gate=str(row.get("gate") or ""),
            requested_at=str(row.get("requested_at") or ""),
            decided_at=str(row.get("decided_at") or ""),
        )


# ------------------------------------------------------------ observation
@dataclass(frozen=True)
class ObservationRecord:
    """One authorized observation execution (Phase 9 step 7-8)."""

    observation_id: str
    plan_id: str
    auth_id: str
    objective_id: str
    job_id: str
    observation_types: tuple[str, ...]
    rows_total: int
    new_rows: int
    new_refs: tuple[str, ...]
    source_counts: dict[str, int]
    outcome: str                    # ok | partial | unavailable
    error: str
    started_at: str
    completed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": _bounded(self.observation_id, 80),
            "plan_id": _bounded(self.plan_id, 80),
            "auth_id": _bounded(self.auth_id, 80),
            "objective_id": _bounded(self.objective_id, 80),
            "job_id": _bounded(self.job_id, 80),
            "observation_types": [str(t) for t in self.observation_types],
            "rows_total": int(self.rows_total),
            "new_rows": int(self.new_rows),
            "new_refs": [_bounded(r, 120) for r in self.new_refs][:30],
            "source_counts": {str(k): int(v)
                              for k, v in self.source_counts.items()},
            "outcome": self.outcome,
            "error": _bounded(self.error, 200),
            "started_at": _bounded(self.started_at, 40),
            "completed_at": _bounded(self.completed_at, 40),
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "ObservationRecord":
        return cls(
            observation_id=str(row.get("observation_id") or ""),
            plan_id=str(row.get("plan_id") or ""),
            auth_id=str(row.get("auth_id") or ""),
            objective_id=str(row.get("objective_id") or ""),
            job_id=str(row.get("job_id") or ""),
            observation_types=tuple(row.get("observation_types") or ()),
            rows_total=int(row.get("rows_total") or 0),
            new_rows=int(row.get("new_rows") or 0),
            new_refs=tuple(row.get("new_refs") or ()),
            source_counts=dict(row.get("source_counts") or {}),
            outcome=str(row.get("outcome") or ""),
            error=str(row.get("error") or ""),
            started_at=str(row.get("started_at") or ""),
            completed_at=str(row.get("completed_at") or ""),
        )


__all__ = [
    "ADVISOR_PROMPT_VERSION",
    "AuthorizationRecord",
    "HuntObjective",
    "HuntPlan",
    "OBJECTIVE_RULE_VERSION",
    "ObservationRecord",
    "PLANNER_VERSION",
    "PLAN_MUTABLE_STATES",
    "PLAN_RULE_VERSION",
    "PLAN_STATES",
    "PLAN_TRANSITIONS",
    "PlanError",
    "PlanTransition",
    "PLAN_DEFINITIVE_SINCE",
    "plan_transition",
    "new_id",
]
