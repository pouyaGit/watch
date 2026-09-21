"""Gap-state tracking (EPIC 2): WAITING_EVIDENCE → EVIDENCE_PARTIAL → EVIDENCE_READY.

``advance`` recomputes a case's state from artifact drafts: union coverage
0 holds WAITING, partial coverage moves one step forward, full coverage
moves to READY. States never move backward and never skip: READY is
reachable only through PARTIAL, and ``transition`` refuses any other move.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from aec.evidence.models import EvidenceArtifactDraft, EvidenceGapState, STATES

#: Closed refusal vocabulary for explicit transitions.
REFUSAL_CODES = frozenset({"INVALID_STATE", "INVALID_TRANSITION"})


@dataclass(frozen=True)
class TransitionOutcome:
    """Result of an explicit transition request."""

    ok: bool
    state: str | None
    refusal_code: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "state": self.state,
            "refusal_code": self.refusal_code,
        }


def initial_state(case_id: str) -> EvidenceGapState:
    """A case with no artifacts is waiting for evidence."""
    return EvidenceGapState(
        case_id=case_id,
        state="WAITING_EVIDENCE",
        known_fields=(),
        missing_fields=(),
        history=(),
    )


def _coverage(
    artifacts: Sequence[EvidenceArtifactDraft],
) -> tuple[frozenset[str], frozenset[str]]:
    known: set[str] = set()
    outstanding: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, EvidenceArtifactDraft):
            continue
        known.update(artifact.collected_fields)
        outstanding.update(artifact.missing_fields)
    return frozenset(known), frozenset(known | outstanding)


def advance(
    state: EvidenceGapState, artifacts: Sequence[EvidenceArtifactDraft] | None
) -> EvidenceGapState:
    """Recompute a case's gap state from artifact drafts.

    Pure and deterministic. Never moves backward: a lower coverage than the
    current state holds the state instead of regressing it.
    """
    items = artifacts if isinstance(artifacts, Sequence) and not isinstance(
        artifacts, (str, bytes)
    ) else ()
    known, universe = _coverage(items)
    ratio = len(known) / len(universe) if universe else 0.0
    if ratio >= 1.0:
        target = "EVIDENCE_READY"
    elif ratio > 0.0:
        target = "EVIDENCE_PARTIAL"
    else:
        target = "WAITING_EVIDENCE"
    current_index = STATES.index(state.state) if state.state in STATES else 0
    target_index = STATES.index(target)
    new_state = target if target_index > current_index else state.state
    history = state.history
    if new_state != state.state:
        history = tuple(list(history) + [state.state])
    return EvidenceGapState(
        case_id=state.case_id,
        state=new_state,
        known_fields=tuple(sorted(known)),
        missing_fields=tuple(sorted(universe - known)),
        history=history,
    )


def transition(current: str, proposed: str) -> TransitionOutcome:
    """Validate one explicit lifecycle move.

    The only allowed moves are staying in place and advancing exactly one
    step. Anything else — skips, backward moves, unknown names — is refused.
    """
    if current not in STATES or proposed not in STATES:
        return TransitionOutcome(ok=False, state=None, refusal_code="INVALID_STATE")
    current_index = STATES.index(current)
    proposed_index = STATES.index(proposed)
    if proposed_index == current_index or proposed_index == current_index + 1:
        return TransitionOutcome(ok=True, state=proposed, refusal_code=None)
    return TransitionOutcome(ok=False, state=None, refusal_code="INVALID_TRANSITION")


__all__ = [
    "REFUSAL_CODES",
    "TransitionOutcome",
    "advance",
    "initial_state",
    "transition",
]
