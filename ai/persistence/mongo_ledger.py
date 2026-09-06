"""Mongo-backed execution ledger (Stage 2, B2 persistence seam).

``MongoExecutionLedger`` implements the full
``InMemoryExecutionLedger`` surface (``put_new`` / ``get`` /
``get_by_idempotency_key`` / ``compare_and_swap`` plus the narrow
``mark_started`` / ``mark_sealed`` / ``mark_incomplete`` /
``mark_unknown`` transitions) over an injected ``MongoCollection``
driver. No duplicate event schema: ``ai.execution.ledger.
ExecutionRecord`` is the only row type, serialized via
``model_dump(mode="json")`` / ``model_validate``.

Document shape (one document per execution)::

    {
      "_id": <execution_id>,                 # unique
      "slot": "<authorization_id>|<stage>",  # unique (at-most-once slot)
      "idempotency_key": <sha256>,           # unique
      "record_version": <int>,               # CAS guard
      "document": <ExecutionRecord json>,
    }

Semantics preserved with the in-memory ledger:

- ``put_new``: slot bound → ``ReplayExecutionError``; execution id
  bound → ``DuplicateExecutionError``; idempotency key bound to a
  different execution → ``DuplicateExecutionError``.
- ``compare_and_swap``: missing row → ``LedgerError``; version
  mismatch on a live row → ``InProgressExecutionError``; on a
  terminal row → ``LedgerError``; identity/stage rebind or non-+1
  step → ``LedgerError``.
- Transitions enforce the same lifecycle preconditions
  (``REGISTERED → STARTED → SEALED_REF | INCOMPLETE_REF | UNKNOWN``).
- Driver outages propagate as ``MongoUnavailableError`` (fail
  closed). Error details are static and secret-free.
"""

from __future__ import annotations

from pydantic import ValidationError

from ai.execution.ledger import (
    DuplicateExecutionError,
    ExecutionRecord,
    InProgressExecutionError,
    LedgerError,
    ReplayExecutionError,
    _TERMINALS,
)
from ai.persistence.driver import DuplicateKeyError, MongoCollection

__all__ = [
    "LEDGER_UNIQUE_INDEXES",
    "MongoExecutionLedger",
]

#: Unique indexes production wiring must ensure on the collection.
LEDGER_UNIQUE_INDEXES: tuple[tuple[str, ...], ...] = (
    ("_id",),
    ("slot",),
    ("idempotency_key",),
)


def _slot_for(authorization_id: str, execution_stage: str) -> str:
    return f"{authorization_id}|{execution_stage}"


class MongoExecutionLedger:
    """Persistent execution ledger (same contract as the in-memory one)."""

    def __init__(self, collection: MongoCollection) -> None:
        for method in ("find_one", "find", "insert_one", "replace_one"):
            if not callable(getattr(collection, method, None)):
                raise TypeError(
                    "ledger requires a MongoCollection driver, "
                    f"missing: {method}"
                )
        self._collection = collection

    # -- internals ---------------------------------------------------

    @staticmethod
    def _to_document(record: ExecutionRecord) -> dict:
        return {
            "_id": record.execution_id,
            "slot": _slot_for(
                record.authorization_id, record.execution_stage
            ),
            "idempotency_key": record.idempotency_key,
            "record_version": record.record_version,
            "document": record.model_dump(mode="json"),
        }

    @staticmethod
    def _from_document(stored: dict) -> ExecutionRecord | None:
        try:
            return ExecutionRecord.model_validate(stored.get("document", {}))
        except (ValidationError, AttributeError, TypeError):
            return None

    # -- registration / lookup / CAS -----------------------------------

    def put_new(self, record: object) -> ExecutionRecord:
        if not isinstance(record, ExecutionRecord):
            raise TypeError(
                "ledger accepts only ExecutionRecord, "
                f"not {type(record).__name__}; raw dicts are never coerced"
            )
        slot = _slot_for(record.authorization_id, record.execution_stage)
        if self._collection.find_one({"slot": slot}) is not None:
            raise ReplayExecutionError(
                "authorization already bound to an execution for stage; "
                "retry requires a new authorization"
            )
        if self._collection.find_one({"_id": record.execution_id}) is not None:
            raise DuplicateExecutionError(
                f"execution_id already registered: {record.execution_id}"
            )
        existing = self._collection.find_one(
            {"idempotency_key": record.idempotency_key}
        )
        if existing is not None and existing.get("_id") != record.execution_id:
            raise DuplicateExecutionError(
                "idempotency key already bound to a different execution"
            )
        try:
            self._collection.insert_one(self._to_document(record))
        except DuplicateKeyError as exc:
            # Lost a race between the read checks and the insert (only
            # observable under real concurrency — found by the Stage 6
            # dedicated-Mongo run). Classify by what is actually bound
            # NOW so the domain contract matches the in-memory ledger
            # exactly: a slot held by another execution is a replay
            # (retry needs a new authorization); any other collision is
            # a duplicate registration. Read failures fail closed via
            # the driver's own unavailable error.
            slot_row = self._collection.find_one({"slot": slot})
            if (
                slot_row is not None
                and slot_row.get("_id") != record.execution_id
            ):
                raise ReplayExecutionError(
                    "authorization already bound to an execution for stage; "
                    "retry requires a new authorization"
                ) from exc
            raise DuplicateExecutionError(
                "execution registration collided; re-read before retry"
            ) from exc
        return record.model_copy(deep=True)

    def get(self, execution_id: object) -> ExecutionRecord | None:
        if not isinstance(execution_id, str):
            raise TypeError(
                "ledger lookup accepts only a string id, "
                f"not {type(execution_id).__name__}"
            )
        stored = self._collection.find_one({"_id": execution_id})
        if stored is None:
            return None
        return self._from_document(stored)

    def get_by_idempotency_key(
        self, idempotency_key: object
    ) -> ExecutionRecord | None:
        if not isinstance(idempotency_key, str):
            raise TypeError(
                "idempotency lookup accepts only a string key, "
                f"not {type(idempotency_key).__name__}"
            )
        stored = self._collection.find_one({"idempotency_key": idempotency_key})
        if stored is None:
            return None
        return self._from_document(stored)

    def compare_and_swap(
        self,
        execution_id: object,
        expected_version: object,
        new_record: object,
    ) -> ExecutionRecord:
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
        current = self._collection.find_one({"_id": execution_id})
        if current is None:
            raise LedgerError(f"no ledger row: {execution_id}")
        if current.get("record_version") != expected_version:
            live = self._from_document(current)
            if live is not None and live.lifecycle not in _TERMINALS:
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
        if _slot_for(
            new_record.authorization_id, new_record.execution_stage
        ) != current.get("slot"):
            raise LedgerError("CAS cannot rebind authorization or stage")
        replaced = self._collection.replace_one(
            {"_id": execution_id, "record_version": expected_version},
            self._to_document(new_record),
        )
        if not replaced:
            # Won the read check but lost the versioned replace under
            # concurrency (found by the Stage 6 dedicated-Mongo run).
            # Classify like the read path so live-row loss stays
            # InProgressExecutionError exactly as the in-memory ledger.
            current = self._collection.find_one({"_id": execution_id})
            live = self._from_document(current) if current is not None else None
            if live is not None and live.lifecycle not in _TERMINALS:
                raise InProgressExecutionError(
                    "execution already started; poll, never second-start"
                )
            raise LedgerError(
                "ledger row changed under the caller; re-read before retry"
            )
        stored = self._collection.find_one({"_id": execution_id})
        record = self._from_document(stored or {})
        if record is None:  # pragma: no cover - defensive
            raise LedgerError(f"no ledger row: {execution_id}")
        return record

    # -- narrow lifecycle transitions (CAS-guarded) ----------------------

    def mark_started(
        self, execution_id: str, *, started_at: str = ""
    ) -> ExecutionRecord:
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
        return self._mark_terminal(
            execution_id, "UNKNOWN", "unknown", terminal_at=terminal_at
        )
