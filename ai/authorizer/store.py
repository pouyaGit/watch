"""Authoritative issuance store abstraction (Phase 5B).

The store is the trust root for authorization authenticity: a record
returned by this store was written by the issuance service under its
ACL. Anything not loaded through this boundary is data, not authority.

Only two backends exist in 5B:

- ``InMemoryAuthorizationStore``: deterministic, dependency-free test
  adapter modeling CAS semantics exactly (per-record version check).
  It models single-process CAS faithfully; cross-process uniqueness
  requires the production adapter below and MUST NOT be assumed from
  this class (its docstring + report state this explicitly).

- Production Mongo adapter: NOT implemented in 5B (requires 5H-core
  persistence decisions). Required before live execution; the
  ``AuthorizationStore`` protocol below is its contract.

No filesystem JSON, dict, LLM output, scheduler message, TestPlan,
artifact metadata, or log is authoritative and none is accepted here.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ai.schemas.execution_authorization import IssuedExecutionAuthorization


class AuthorizationStoreError(ValueError):
    """Base error for issuance-store misuse/failure (sanitized)."""


class RecordNotFoundError(AuthorizationStoreError):
    """No issuance record exists for the requested identifier."""


class VersionConflictError(AuthorizationStoreError):
    """CAS guard failed: the record changed under the caller."""


class DuplicateIdempotencyKeyError(AuthorizationStoreError):
    """The idempotency key is already bound to a different record."""


@runtime_checkable
class AuthorizationStore(Protocol):
    """Narrow authoritative store contract (5B trust root interface).

    ``runtime_checkable`` so the 5B service layer gates on this
    contract (not on one concrete backend): any backend implementing
    the four methods structurally — including the Stage 2 Mongo
    adapter — is admitted, while dicts/JSON/strings still fail the
    gate. Method-only protocols support runtime checks.
    """

    def put_new(
        self, record: IssuedExecutionAuthorization
    ) -> IssuedExecutionAuthorization:
        """Persist a newly issued record (fails on id/key collision)."""
        ...  # pragma: no cover

    def get(
        self, authorization_id: str
    ) -> IssuedExecutionAuthorization | None:
        """Load the genuine record, or None when unknown."""
        ...  # pragma: no cover

    def get_by_idempotency_key(
        self, idempotency_key: str
    ) -> IssuedExecutionAuthorization | None:
        """Dedupe lookup for idempotent issuance."""
        ...  # pragma: no cover

    def compare_and_swap(
        self,
        authorization_id: str,
        expected_version: int,
        new_record: IssuedExecutionAuthorization,
    ) -> IssuedExecutionAuthorization:
        """Atomic lifecycle/lease transition guarded on record version."""
        ...  # pragma: no cover


class InMemoryAuthorizationStore:
    """Deterministic in-memory adapter modeling CAS semantics.

    Suitable for unit tests and offline review. NOT a cross-process
    store: two processes (or two instances) do not share state, so
    duplicate-execution protection across workers requires the
    production adapter. Never use this class to claim cross-process
    guarantees.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, IssuedExecutionAuthorization] = {}
        self._by_key: dict[str, str] = {}

    def put_new(
        self, record: object
    ) -> IssuedExecutionAuthorization:
        if not isinstance(record, IssuedExecutionAuthorization):
            raise TypeError(
                "issuance store accepts only IssuedExecutionAuthorization, "
                f"not {type(record).__name__}; raw dicts are never coerced"
            )
        if record.authorization_id in self._by_id:
            raise DuplicateIdempotencyKeyError(
                f"authorization_id already issued: {record.authorization_id}"
            )
        existing = self._by_key.get(record.idempotency_key)
        if existing is not None and existing != record.authorization_id:
            raise DuplicateIdempotencyKeyError(
                "idempotency key already bound to a different authorization"
            )
        stored = record.model_copy(deep=True)
        self._by_id[stored.authorization_id] = stored
        self._by_key.setdefault(stored.idempotency_key, stored.authorization_id)
        return stored.model_copy(deep=True)

    def get(self, authorization_id: object) -> IssuedExecutionAuthorization | None:
        if not isinstance(authorization_id, str):
            raise TypeError(
                "authorization lookup accepts only an opaque string id, "
                f"not {type(authorization_id).__name__}"
            )
        stored = self._by_id.get(authorization_id)
        return stored.model_copy(deep=True) if stored is not None else None

    def get_by_idempotency_key(
        self, idempotency_key: object
    ) -> IssuedExecutionAuthorization | None:
        if not isinstance(idempotency_key, str):
            raise TypeError(
                "idempotency lookup accepts only a string key, "
                f"not {type(idempotency_key).__name__}"
            )
        authz_id = self._by_key.get(idempotency_key)
        if authz_id is None:
            return None
        return self.get(authz_id)

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
        current = self._by_id.get(authorization_id)
        if current is None:
            raise RecordNotFoundError(
                f"no issuance record: {authorization_id}"
            )
        if current.record_version != expected_version:
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
        stored = new_record.model_copy(deep=True)
        self._by_id[authorization_id] = stored
        return stored.model_copy(deep=True)


__all__ = [
    "AuthorizationStore",
    "AuthorizationStoreError",
    "DuplicateIdempotencyKeyError",
    "InMemoryAuthorizationStore",
    "RecordNotFoundError",
    "VersionConflictError",
]
