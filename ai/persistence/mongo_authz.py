"""Mongo-backed authorization store (Stage 2, B2 persistence seam).

``MongoAuthorizationStore`` implements the EXISTING
``ai.authorizer.store.AuthorizationStore`` trust-root interface over
an injected ``MongoCollection``-shaped driver (see
``ai.persistence.driver``): no new authorization model, no schema
change, no weakened validation.

Document shape (one document per issuance record)::

    {
      "_id": <authorization_id>,          # unique
      "idempotency_key": <full sha256>,   # unique
      "record_version": <int>,            # CAS guard
      "lifecycle": <ISSUED|CONSUMED|...>,
      "document": <IssuedExecutionAuthorization model_dump(mode=json)>,
    }

Semantics preserved byte-for-behavior with
``InMemoryAuthorizationStore``:

- ``put_new``: typed-only input; ``_id`` collision or idempotency key
  bound to a different id → ``DuplicateIdempotencyKeyError``.
- ``get`` / ``get_by_idempotency_key``: opaque-string ids only;
  malformed ids → ``TypeError``/``None`` exactly like the in-memory
  adapter (``get`` type-checks; key lookup returns ``None`` when
  absent).
- ``compare_and_swap``: missing row → ``RecordNotFoundError``;
  version mismatch → ``VersionConflictError``; identity rebind or
  non-+1 version step → ``AuthorizationStoreError``.
- Stored documents re-validate through
  ``IssuedExecutionAuthorization`` on every read: a row that no
  longer validates is treated as absent (``None``) for lookups and
  as ``RecordNotFoundError`` for CAS — a corrupt row can never
  become authority.
- Driver outages (``MongoUnavailableError``) propagate unchanged:
  callers fail closed; nothing is cached, retried, or synthesized
  here. No connection strings, credentials, nonces, or payload
  bytes ever enter error details.
"""

from __future__ import annotations

from pydantic import ValidationError

from ai.authorizer.store import (
    AuthorizationStoreError,
    DuplicateIdempotencyKeyError,
    RecordNotFoundError,
    VersionConflictError,
)
from ai.persistence.driver import (
    DuplicateKeyError,
    MongoCollection,
    MongoUnavailableError,
)
from ai.schemas.execution_authorization import IssuedExecutionAuthorization

__all__ = [
    "AUTHZ_UNIQUE_INDEXES",
    "MongoAuthorizationStore",
]

#: Unique indexes production wiring must ensure on the collection.
AUTHZ_UNIQUE_INDEXES: tuple[tuple[str, ...], ...] = (
    ("_id",),
    ("idempotency_key",),
)

class MongoAuthorizationStore:
    """Persistent issuance store (same contract as the in-memory one).

    Single-process AND cross-process CAS both hold when the backing
    collection enforces the declared unique indexes atomically (the
    production requirement the in-memory fake explicitly lacks).
    """

    def __init__(self, collection: MongoCollection) -> None:
        for method in ("find_one", "find", "insert_one", "replace_one"):
            if not callable(getattr(collection, method, None)):
                raise TypeError(
                    "authorization store requires a MongoCollection driver, "
                    f"missing: {method}"
                )
        self._collection = collection

    # -- internals ---------------------------------------------------

    @staticmethod
    def _to_document(record: IssuedExecutionAuthorization) -> dict:
        return {
            "_id": record.authorization_id,
            "idempotency_key": record.idempotency_key,
            "record_version": record.record_version,
            "lifecycle": record.lifecycle,
            "document": record.model_dump(mode="json"),
        }

    @staticmethod
    def _from_document(stored: dict) -> IssuedExecutionAuthorization | None:
        try:
            return IssuedExecutionAuthorization.model_validate(
                stored.get("document", {})
            )
        except (ValidationError, AttributeError, TypeError):
            return None

    # -- AuthorizationStore interface ---------------------------------

    def put_new(
        self, record: object
    ) -> IssuedExecutionAuthorization:
        if not isinstance(record, IssuedExecutionAuthorization):
            raise TypeError(
                "issuance store accepts only IssuedExecutionAuthorization, "
                f"not {type(record).__name__}; raw dicts are never coerced"
            )
        if self._collection.find_one({"_id": record.authorization_id}) is not None:
            raise DuplicateIdempotencyKeyError(
                f"authorization_id already issued: {record.authorization_id}"
            )
        existing = self._collection.find_one(
            {"idempotency_key": record.idempotency_key}
        )
        if existing is not None and existing.get("_id") != record.authorization_id:
            raise DuplicateIdempotencyKeyError(
                "idempotency key already bound to a different authorization"
            )
        try:
            self._collection.insert_one(self._to_document(record))
        except DuplicateKeyError as exc:
            # Lost a race: re-read to report the precise collision.
            # Any outcome here fails closed without inventing a record.
            raise DuplicateIdempotencyKeyError(
                "issuance collided under concurrency; re-read before retry"
            ) from exc
        return record.model_copy(deep=True)

    def get(
        self, authorization_id: object
    ) -> IssuedExecutionAuthorization | None:
        if not isinstance(authorization_id, str):
            raise TypeError(
                "authorization lookup accepts only an opaque string id, "
                f"not {type(authorization_id).__name__}"
            )
        stored = self._collection.find_one({"_id": authorization_id})
        if stored is None:
            return None
        return self._from_document(stored)

    def get_by_idempotency_key(
        self, idempotency_key: object
    ) -> IssuedExecutionAuthorization | None:
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
        authorization_id: object,
        expected_version: object,
        new_record: object,
    ) -> IssuedExecutionAuthorization:
        if not isinstance(authorization_id, str):
            raise TypeError(
                "CAS accepts only an opaque string id, "
                f"not {type(authorization_id).__name__}"
            )
        if not isinstance(expected_version, int) or isinstance(
            expected_version, bool
        ):
            raise TypeError("CAS expected_version must be an integer")
        if not isinstance(new_record, IssuedExecutionAuthorization):
            raise TypeError(
                "CAS accepts only IssuedExecutionAuthorization, "
                f"not {type(new_record).__name__}"
            )
        current = self._collection.find_one({"_id": authorization_id})
        if current is None:
            raise RecordNotFoundError(
                f"no issuance record: {authorization_id}"
            )
        if current.get("record_version") != expected_version:
            raise VersionConflictError(
                "issuance record changed under the caller; "
                "re-read before retrying"
            )
        if new_record.authorization_id != authorization_id:
            raise AuthorizationStoreError(
                "CAS cannot rebind authorization identity"
            )
        if new_record.record_version != expected_version + 1:
            raise AuthorizationStoreError(
                "CAS requires exactly one version increment"
            )
        replaced = self._collection.replace_one(
            {"_id": authorization_id, "record_version": expected_version},
            self._to_document(new_record),
        )
        if not replaced:
            raise VersionConflictError(
                "issuance record changed under the caller; "
                "re-read before retrying"
            )
        stored = self._collection.find_one({"_id": authorization_id})
        record = self._from_document(stored or {})
        if record is None:  # pragma: no cover - defensive
            raise RecordNotFoundError(
                f"no issuance record: {authorization_id}"
            )
        return record


