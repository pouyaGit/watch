"""Research uncertainty model (Hunt Planner Phase 1).

Explicit states distinguish "we don't have evidence" from "evidence says
the hypothesis is false":

* ``NEEDS_EVIDENCE`` / ``READY_FOR_PLANNING`` / ``OBSERVATION_*`` — the
  hunt is still acquiring authorized evidence.
* ``REJECTED`` — the hypothesis is not supported by the authorized
  evidence that was actually observed (or the hunt disproved it).
* ``BLOCKED`` — authorization, capability or scope prevents progress.

The model is pure data + a validated transition table: no I/O, no LLM,
no network, no execution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

UNCERTAINTY_RULE_VERSION = "hunt-uncertainty-v1"

UNCERTAINTY_STATES: tuple[str, ...] = (
    "OPEN",
    "NEEDS_EVIDENCE",
    "READY_FOR_PLANNING",
    "PLANNED",
    "OBSERVATION_PENDING",
    "OBSERVATION_COMPLETE",
    "RESOLVED",
    "REJECTED",
    "BLOCKED",
)

TERMINAL_STATES: frozenset[str] = frozenset(
    {"RESOLVED", "REJECTED", "BLOCKED"})

# Allowed research-state transitions. Anything not listed fails closed.
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "OPEN": frozenset({"NEEDS_EVIDENCE", "READY_FOR_PLANNING",
                       "RESOLVED", "REJECTED", "BLOCKED"}),
    "NEEDS_EVIDENCE": frozenset({"READY_FOR_PLANNING", "RESOLVED",
                                 "REJECTED", "BLOCKED"}),
    "READY_FOR_PLANNING": frozenset({"PLANNED", "NEEDS_EVIDENCE",
                                     "RESOLVED", "REJECTED", "BLOCKED"}),
    "PLANNED": frozenset({"OBSERVATION_PENDING", "NEEDS_EVIDENCE",
                          "RESOLVED", "REJECTED", "BLOCKED"}),
    "OBSERVATION_PENDING": frozenset({"OBSERVATION_COMPLETE",
                                      "BLOCKED", "REJECTED", "RESOLVED"}),
    "OBSERVATION_COMPLETE": frozenset({"NEEDS_EVIDENCE", "READY_FOR_PLANNING",
                                       "RESOLVED", "REJECTED", "BLOCKED"}),
    "RESOLVED": frozenset(),
    "REJECTED": frozenset(),
    "BLOCKED": frozenset(),
}


class UncertaintyError(ValueError):
    """Invalid research-state transition or malformed uncertainty."""


def transition(current: str, new: str) -> str:
    """Validate and return ``new``; terminal states never move."""
    if current not in ALLOWED_TRANSITIONS:
        raise UncertaintyError(f"unknown current state: {current!r}")
    if new not in UNCERTAINTY_STATES:
        raise UncertaintyError(f"unknown next state: {new!r}")
    if new not in ALLOWED_TRANSITIONS[current]:
        raise UncertaintyError(
            f"illegal uncertainty transition {current} -> {new}")
    return new


def _bounded(value: object, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


@dataclass
class ResearchUncertainty:
    """Structured research-uncertainty snapshot for one hunt objective."""

    objective_id: str
    hypothesis: str
    state: str = "OPEN"
    supporting_observations: list[str] = field(default_factory=list)
    contradicting_observations: list[str] = field(default_factory=list)
    missing_evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_requested: list[str] = field(default_factory=list)
    evidence_collected: list[str] = field(default_factory=list)
    confidence: str = "insufficient"
    blockers: list[str] = field(default_factory=list)
    next_decision: str = ""
    research_objective: str = ""
    scope_ref: str = ""
    specialist: str = ""
    iteration: int = 0
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.state not in UNCERTAINTY_STATES:
            raise UncertaintyError(f"unknown state: {self.state!r}")
        if not self.objective_id or not self.scope_ref or not self.specialist:
            raise UncertaintyError(
                "uncertainty requires objective_id, scope_ref and specialist")
        if not self.provenance.get("created_at"):
            raise UncertaintyError("uncertainty requires provenance")

    def move(self, new_state: str, *, reason: str = "") -> None:
        transition(self.state, new_state)
        self.state = new_state
        self.next_decision = _bounded(reason or new_state, 120)

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_version": UNCERTAINTY_RULE_VERSION,
            "objective_id": _bounded(self.objective_id, 80),
            "hypothesis": _bounded(self.hypothesis, 300),
            "state": self.state,
            "supporting_observations":
                [_bounded(v, 120) for v in self.supporting_observations][:40],
            "contradicting_observations":
                [_bounded(v, 120) for v in self.contradicting_observations][:40],
            "missing_evidence": [
                {"item_code": _bounded(i.get("item_code", ""), 80),
                 "reason": _bounded(i.get("reason", ""), 200)}
                for i in self.missing_evidence[:12]],
            "evidence_requested":
                [_bounded(v, 80) for v in self.evidence_requested][:40],
            "evidence_collected":
                [_bounded(v, 120) for v in self.evidence_collected][:40],
            "confidence": _bounded(self.confidence, 40),
            "blockers": [_bounded(b, 120) for b in self.blockers][:8],
            "next_decision": _bounded(self.next_decision, 160),
            "research_objective": _bounded(self.research_objective, 300),
            "scope_ref": _bounded(self.scope_ref, 120),
            "specialist": _bounded(self.specialist, 60),
            "iteration": int(self.iteration),
            "provenance": dict(self.provenance),
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "ResearchUncertainty":
        return cls(
            objective_id=str(row.get("objective_id") or ""),
            hypothesis=str(row.get("hypothesis") or ""),
            state=str(row.get("state") or "OPEN"),
            supporting_observations=list(
                row.get("supporting_observations") or []),
            contradicting_observations=list(
                row.get("contradicting_observations") or []),
            missing_evidence=list(row.get("missing_evidence") or []),
            evidence_requested=list(row.get("evidence_requested") or []),
            evidence_collected=list(row.get("evidence_collected") or []),
            confidence=str(row.get("confidence") or "insufficient"),
            blockers=list(row.get("blockers") or []),
            next_decision=str(row.get("next_decision") or ""),
            research_objective=str(row.get("research_objective") or ""),
            scope_ref=str(row.get("scope_ref") or ""),
            specialist=str(row.get("specialist") or ""),
            iteration=int(row.get("iteration") or 0),
            provenance=dict(row.get("provenance") or {}),
        )

    def digest(self) -> str:
        """Stable digest of the snapshot for audit lineage."""
        blob = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "ALLOWED_TRANSITIONS",
    "UNCERTAINTY_RULE_VERSION",
    "UNCERTAINTY_STATES",
    "TERMINAL_STATES",
    "ResearchUncertainty",
    "UncertaintyError",
    "transition",
]
