"""Execution ledger + idempotency + crash accounting (Phase 5H-core).

Narrow execution-accounting contract. This module performs NO
transport, owns NO verdict vocabulary, and enables NO live execution:
it records lifecycle transitions with CAS versioning so that exactly
one execution wins each ``(authorization_id, execution_stage)`` slot.

Semantics (frozen — AT-MOST-ONCE EXECUTION, never exactly-once):

- One ledger row per ``(authorization_id, execution_stage)``.
  A second registration for the same slot raises
  ``EXECUTION_REPLAY`` — the same authorization never executes twice.
- Same ``idempotency_key`` re-registered maps to
  ``EXECUTION_DUPLICATE`` (dedupe-on-read of the winner).
- A live (non-terminal) row re-entered maps to
  ``EXECUTION_IN_PROGRESS`` (poll, never second-start).
- Post-start ambiguity resolves to ``OUTCOME_UNKNOWN`` accounting:
  no evidence, no resume, retry only under a NEW authorization.
- Process-local locks are not used and not needed: the
  ``InMemoryExecutionLedger`` models single-process CAS faithfully
  and documents that cross-process uniqueness requires the
  production adapter (unique index + atomic CAS) before live use.
"""

from __future__ import annotations

from typing import Literal

from ai.schemas import evidence as ev

__all__ = [
    "ExecutionLifecycle",
    "ExecutionOutcome",
    "CrashPoint",
    "ExecutionRecord",
    "LedgerError",
    "DuplicateExecutionError",
    "ReplayExecutionError",
    "InProgressExecutionError",
    "InMemoryExecutionLedger",
    "crash_decision",
    "retry_requires_new_authorization",
]

ExecutionLifecycle = Literal[
    "REGISTERED",
    "STARTED",
    "SEALED_REF",
    "INCOMPLETE_REF",
    "UNKNOWN",
]

ExecutionOutcome = Literal[
    "none",
    "sealed",
    "incomplete",
    "unknown",
]

CrashPoint = Literal[
    "pre_start",
    "post_consume",
    "post_start",
    "transport_unknown",
    "pre_seal",
    "post_seal_pre_index",
    "post_index_pre_audit",
]

_TERMINALS = frozenset({"SEALED_REF", "INCOMPLETE_REF", "UNKNOWN"})


class LedgerError(ValueError):
    """Ledger misuse/failure signal (maps to EvidenceError codes)."""


class DuplicateExecutionError(LedgerError):
    """Idempotency key already bound (dedupe-on-read the winner)."""


class ReplayExecutionError(LedgerError):
    """Second execution under the same authorization (forbidden)."""


class InProgressExecutionError(LedgerError):
    """Execution already started and non-terminal (poll, no restart)."""


from pydantic import BaseModel, ConfigDict, field_validator


class ExecutionRecord(BaseModel):
    """One execution-accounting row (accounting, not authority)."""

    model_config = ConfigDict(extra="forbid")

    execution_id: str
    authorization_id: str
    execution_stage: str = "single"
    idempotency_key: str
    record_version: int = 1
    lifecycle: ExecutionLifecycle = "REGISTERED"
    outcome: ExecutionOutcome = "none"
    evidence_id: str | None = None
    registered_at: str = ""
    started_at: str = ""
    terminal_at: str = ""

    @field_validator("record_version")
    @classmethod
    def _version(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("record_version must be a positive integer")
        return value


class InMemoryExecutionLedger:
    """Deterministic in-memory ledger modeling CAS semantics.

    Single-process only: two processes (or two instances) do not
    share state, so cross-worker duplicate-execution protection
    requires the production adapter. Never use this class to claim
    cross-process guarantees.
    """

    def __init__(self) -> None:
        self._by_execution: dict[str, ExecutionRecord] = {}
        self._by_key: dict[str, str] = {}
        self._by_slot: dict[tuple[str, str], str] = {}

    def put_new(self, record: object) -> ExecutionRecord:
        """Register a new execution (fails on slot/key collision)."""
        if not isinstance(record, ExecutionRecord):
            raise TypeError(
                "ledger accepts only ExecutionRecord, "
                f"not {type(record).__name__}; raw dicts are never coerced"
            )
        slot = (record.authorization_id, record.execution_stage)
        if slot in self._by_slot:
            raise ReplayExecutionError(
                "authorization already bound to an execution for stage; "
                "retry requires a new authorization"
            )
        if record.execution_id in self._by_execution:
            raise DuplicateExecutionError(
                f"execution_id already registered: {record.execution_id}"
            )
        existing = self._by_key.get(record.idempotency_key)
        if existing is not None and existing != record.execution_id:
            raise DuplicateExecutionError(
                "idempotency key already bound to a different execution"
            )
        stored = record.model_copy(deep=True)
        self._by_execution[stored.execution_id] = stored
        self._by_key.setdefault(stored.idempotency_key, stored.execution_id)
        self._by_slot[slot] = stored.execution_id
        return stored.model_copy(deep=True)

    def get(self, execution_id: object) -> ExecutionRecord | None:
        """Load a ledger row by execution id, or None when unknown."""
        if not isinstance(execution_id, str):
            raise TypeError(
                "ledger lookup accepts only a string id, "
                f"not {type(execution_id).__name__}"
            )
        stored = self._by_execution.get(execution_id)
        return stored.model_copy(deep=True) if stored is not None else None

    def get_by_idempotency_key(
        self, idempotency_key: object
    ) -> ExecutionRecord | None:
        """Dedupe lookup for idempotent registration."""
        if not isinstance(idempotency_key, str):
            raise TypeError(
                "idempotency lookup accepts only a string key, "
                f"not {type(idempotency_key).__name__}"
            )
        execution_id = self._by_key.get(idempotency_key)
        if execution_id is None:
            return None
        return self.get(execution_id)

    def compare_and_swap(
        self,
        execution_id: object,
        expected_version: object,
        new_record: object,
    ) -> ExecutionRecord:
        """Atomic lifecycle transition guarded on record version."""
        if not isinstance(execution_id, str):
            raise TypeError(
                "CAS accepts only a string id, "
                f"not {type(execution_id).__name__}"
            )
        if not isinstance(expected_version, int) or isinstance(
            expected_version, bool
        ):
            raise TypeError("CAS expected_version must be an integer")
        if not isinstance(new_record, ExecutionRecord):
            raise TypeError(
                "CAS accepts only ExecutionRecord, "
                f"not {type(new_record).__name__}"
            )
        current = self._by_execution.get(execution_id)
        if current is None:
            raise LedgerError(f"no ledger row: {execution_id}")
        if current.record_version != expected_version:
            # Loser path: a live row means poll; anything else is a
            # conflict the caller must re-read, never overwrite.
            if current.lifecycle not in _TERMINALS:
                raise InProgressExecutionError(
                    "execution already started; poll, never second-start"
                )
            raise LedgerError(
                "ledger row changed under the caller; re-read before retry"
            )
        if new_record.execution_id != execution_id:
            raise LedgerError("CAS cannot rebind execution identity")
        if new_record.record_version != expected_version + 1:
            raise LedgerError("CAS requires exactly one version increment")
        if (new_record.authorization_id, new_record.execution_stage) != (
            current.authorization_id,
            current.execution_stage,
        ):
            raise LedgerError("CAS cannot rebind authorization or stage")
        stored = new_record.model_copy(deep=True)
        self._by_execution[execution_id] = stored
        return stored.model_copy(deep=True)

    # -- narrow lifecycle transitions (CAS-guarded) -------------------

    def mark_started(
        self, execution_id: str, *, started_at: str = ""
    ) -> ExecutionRecord:
        """REGISTERED → STARTED (exactly-once start gate)."""
        current = self.get(execution_id)
        if current is None:
            raise LedgerError(f"no ledger row: {execution_id}")
        if current.lifecycle != "REGISTERED":
            if current.lifecycle in ("STARTED",):
                raise InProgressExecutionError(
                    "execution already started; poll, never second-start"
                )
            raise LedgerError(
                "terminal execution cannot restart; new authorization needed"
            )
        return self.compare_and_swap(
            execution_id,
            current.record_version,
            current.model_copy(
                update={
                    "lifecycle": "STARTED",
                    "record_version": current.record_version + 1,
                    "started_at": started_at,
                }
            ),
        )

    def _mark_terminal(
        self,
        execution_id: str,
        lifecycle: str,
        outcome: str,
        *,
        evidence_id: str | None = None,
        terminal_at: str = "",
    ) -> ExecutionRecord:
        current = self.get(execution_id)
        if current is None:
            raise LedgerError(f"no ledger row: {execution_id}")
        if current.lifecycle != "STARTED":
            raise LedgerError(
                "only a started execution may reach a terminal state"
            )
        return self.compare_and_swap(
            execution_id,
            current.record_version,
            current.model_copy(
                update={
                    "lifecycle": lifecycle,
                    "outcome": outcome,
                    "evidence_id": evidence_id,
                    "record_version": current.record_version + 1,
                    "terminal_at": terminal_at,
                }
            ),
        )

    def mark_sealed(
        self, execution_id: str, evidence_id: str, *, terminal_at: str = ""
    ) -> ExecutionRecord:
        """STARTED → SEALED_REF (evidence indexed under this execution)."""
        return self._mark_terminal(
            execution_id,
            "SEALED_REF",
            "sealed",
            evidence_id=evidence_id,
            terminal_at=terminal_at,
        )

    def mark_incomplete(
        self, execution_id: str, evidence_id: str, *, terminal_at: str = ""
    ) -> ExecutionRecord:
        """STARTED → INCOMPLETE_REF (partial evidence, never verifier)."""
        return self._mark_terminal(
            execution_id,
            "INCOMPLETE_REF",
            "incomplete",
            evidence_id=evidence_id,
            terminal_at=terminal_at,
        )

    def mark_unknown(
        self, execution_id: str, *, terminal_at: str = ""
    ) -> ExecutionRecord:
        """STARTED → UNKNOWN (transport-ambiguous; no evidence exists).

        The old execution never resumes and never hands off. Retry
        requires a new authorization (new round for ambiguous stored
        SUBMIT) — see :func:`retry_requires_new_authorization`.
        """
        return self._mark_terminal(
            execution_id, "UNKNOWN", "unknown", terminal_at=terminal_at
        )


_CRASH_TABLE: dict[str, dict[str, object]] = {
    "pre_start": {
        "retry": True,
        "same_authz_usable": True,
        "new_authz_required": False,
        "evidence": "none",
        "audit": "AUTHORIZATION_only",
        "verifier": False,
    },
    "post_consume": {
        "retry": True,
        "same_authz_usable": False,
        "new_authz_required": False,
        "evidence": "none",
        "audit": "AUTHORIZATION_CONSUMED",
        "verifier": False,
    },
    "post_start": {
        "retry": True,
        "same_authz_usable": False,
        "new_authz_required": False,
        "evidence": "BUILDING_abandoned",
        "audit": "EXECUTION_STARTED",
        "verifier": False,
    },
    "transport_unknown": {
        "retry": True,
        "same_authz_usable": False,
        "new_authz_required": True,
        "evidence": "OUTCOME_UNKNOWN_no_bytes",
        "audit": "EXECUTION_TERMINAL_unknown",
        "verifier": False,
    },
    "pre_seal": {
        "retry": True,
        "same_authz_usable": False,
        "new_authz_required": True,
        "evidence": "OUTCOME_UNKNOWN_no_bytes",
        "audit": "EXECUTION_TERMINAL_unknown",
        "verifier": False,
    },
    "post_seal_pre_index": {
        "retry": False,
        "same_authz_usable": False,
        "new_authz_required": False,
        "evidence": "ORPHAN_reindex_only",
        "audit": "EVIDENCE_SEALED_missing",
        "verifier": "after_reindex_only",
    },
    "post_index_pre_audit": {
        "retry": False,
        "same_authz_usable": False,
        "new_authz_required": False,
        "evidence": "SEALED_indexed",
        "audit": "AUDIT_GAP",
        "verifier": "evidence_eligible_audit_gap_separate",
    },
}


def crash_decision(point: CrashPoint) -> dict[str, object]:
    """Deterministic crash-state mapping (pure decision table)."""
    try:
        return dict(_CRASH_TABLE[point])
    except KeyError:
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", f"unknown crash point: {point!r}"
        ) from None


def retry_requires_new_authorization(record: ExecutionRecord) -> bool:
    """True once transport may have started (post-consume states).

    REGISTERED rows (pre-start, unconsumed) may still use their
    authorization; every other lifecycle requires a new one. This
    function never mints permission — it only classifies.
    """
    if not isinstance(record, ExecutionRecord):
        raise TypeError(
            "retry_requires_new_authorization accepts only ExecutionRecord, "
            f"not {type(record).__name__}"
        )
    return record.lifecycle != "REGISTERED"
