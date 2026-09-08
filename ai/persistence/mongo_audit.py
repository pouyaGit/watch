"""Mongo-backed audit sink (Stage 2, B2 persistence seam).

``MongoAuditSink`` persists ``ai.audit.trail.AuditRecord`` rows
through an injected ``MongoCollection`` driver. Append-only: the
only write is ``append`` (insert); there is deliberately no update,
delete, or rewrite API — historical audit events are immutable.

Document shape (one document per audit record)::

    {
      "_id": "<execution_id>:<seq>",   # unique (ordering key)
      "execution_id": <ex-…>,
      "seq": <int>,
      "document": <AuditRecord model_dump(mode=json)>,
    }

Semantics:

- ``append`` accepts only genuine ``AuditRecord`` instances (raw
  dicts raise ``TypeError`` — the same discipline as
  ``InMemoryAuditSink``). A duplicate ``(execution_id, seq)`` insert
  fails closed with ``AuditPersistenceError`` (replay must be
  detected by the caller, never silently merged).
- ``AuditRecord`` itself enforces the secret-screening validators
  (connection strings, passwords, keys, tokens rejected at
  construction), so no credential or raw-body material can persist
  through this seam; evidence bodies/samples have no field here at
  all (hashes + codes only).
- Driver outages propagate as ``MongoUnavailableError`` (fail
  closed). Error details are static and secret-free.
"""

from __future__ import annotations

from ai.audit.trail import AuditRecord
from ai.persistence.driver import DuplicateKeyError, MongoCollection

__all__ = [
    "AUDIT_UNIQUE_INDEXES",
    "AuditPersistenceError",
    "MongoAuditSink",
]

#: Unique indexes production wiring must ensure on the collection.
AUDIT_UNIQUE_INDEXES: tuple[tuple[str, ...], ...] = (("_id",),)


class AuditPersistenceError(ValueError):
    """Audit append refused (duplicate or malformed, never merged)."""


class MongoAuditSink:
    """Append-only audit persistence (insert-only by construction)."""

    def __init__(self, collection: MongoCollection) -> None:
        for method in ("find_one", "find", "insert_one", "replace_one"):
            if not callable(getattr(collection, method, None)):
                raise TypeError(
                    "audit sink requires a MongoCollection driver, "
                    f"missing: {method}"
                )
        self._collection = collection

    def append(self, record: object) -> None:
        if not isinstance(record, AuditRecord):
            raise TypeError(
                "audit sink accepts only AuditRecord, "
                f"not {type(record).__name__}"
            )
        key = f"{record.execution_id}:{record.seq}"
        try:
            self._collection.insert_one(
                {
                    "_id": key,
                    "execution_id": record.execution_id,
                    "seq": record.seq,
                    "document": record.model_dump(mode="json"),
                }
            )
        except DuplicateKeyError as exc:
            raise AuditPersistenceError(
                "audit event already recorded; refused"
            ) from exc

    def records_for(self, execution_id: str) -> list[AuditRecord]:
        """Read the ordered audit trail for one execution (read-only)."""
        if not isinstance(execution_id, str):
            raise TypeError("records_for accepts only a string execution id")
        rows = self._collection.find({"execution_id": execution_id})
        out: list[AuditRecord] = []
        for row in sorted(rows, key=lambda item: item.get("seq", 0)):
            try:
                out.append(AuditRecord.model_validate(row.get("document", {})))
            except Exception:
                continue
        return out
