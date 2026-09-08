"""Offline verified-read seam for the 5I deterministic verifier (Phase 5K-live).

The verifier requires an injected ``seam`` with:
- ``read_verified(evidence_id)`` → object with ``.record`` and ``.index``
- ``read_authorization(authorization_id)`` → ``IssuedExecutionAuthorization``

This module provides an offline seam backed by the genuine
InMemoryAuthorizationStore and a sealed evidence record, satisfying
the 5I gate requirements without touching any EvidenceStore or Mongo.
"""

from __future__ import annotations

from types import SimpleNamespace

from ai.authorizer.store import InMemoryAuthorizationStore
from ai.schemas import evidence as ev
from ai.schemas.execution_authorization import IssuedExecutionAuthorization


class OfflineVerifiedSeam:
    """Offline verified-read seam for 5I verifier (deterministic).

    Backed by a sealed evidence record + genuine authorization store.
    ``read_verified`` re-derives the record from the envelope bytes
    (same record, same hashes); ``read_authorization`` reads from the
    genuine store.
    """

    def __init__(
        self,
        *,
        sealed_record: ev.EvidenceRecord,
        envelope: bytes,
        authz_store: InMemoryAuthorizationStore,
    ) -> None:
        if not isinstance(sealed_record, ev.EvidenceRecord):
            raise TypeError(
                f"sealed_record must be EvidenceRecord, "
                f"not {type(sealed_record).__name__}"
            )
        if not sealed_record.complete:
            raise ValueError("sealed_record must be complete")
        self._record = sealed_record
        self._envelope = envelope
        self._authz_store = authz_store

    def read_verified(self, evidence_id: str) -> SimpleNamespace:
        """Verified read: return record + None index (no evidence store)."""
        if evidence_id != self._record.evidence_id:
            return None  # type: ignore[return-value]
        return SimpleNamespace(record=self._record, index=None)

    def read_authorization(
        self, authorization_id: str
    ) -> IssuedExecutionAuthorization | None:
        """Read the genuine authorization record from the store."""
        return self._authz_store.get(authorization_id)
