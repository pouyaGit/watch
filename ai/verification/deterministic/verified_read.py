"""Injected verified-read seam for 5I (Phase 5I).

The verifier never opens a blob store, index, database, or network
handle. It receives an injected ``VerifiedRead`` seam that performs
the 5H verified read (blob bytes -> typed parse -> recomputed triple
-> index-claim comparison) and returns the sealed record plus the
index claims it saw. The gate then RE-VERIFIES everything it can
from the envelope bytes it was handed: the seam is a transport, not
an authority.

``StoreVerifiedRead`` composes the frozen 5H ``EvidenceStore`` with
the same index object and an authorization lookup callable; it adds
no new persistence semantics and no write capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from ai.evidence.index import IndexEntry
from ai.evidence.store import EvidenceStore
from ai.schemas import evidence as ev
from ai.schemas.execution_authorization import (
    IssuedExecutionAuthorization,
)

__all__ = [
    "IndexClaims",
    "VerifiedEvidence",
    "VerifiedRead",
    "StoreVerifiedRead",
    "read_verified_input",
]


@dataclass(frozen=True)
class IndexClaims:
    """What the durable index claims about one evidence id."""

    evidence_id: str
    execution_id: str
    authorization_id: str
    content_hash: str
    bindings_hash: str
    observations_hash: str
    lifecycle: str
    tombstoned: bool = False
    quarantined: bool = False

    @classmethod
    def from_entry(cls, entry: IndexEntry) -> "IndexClaims":
        return cls(
            evidence_id=entry.evidence_id,
            execution_id=entry.execution_id,
            authorization_id=entry.authorization_id,
            content_hash=entry.content_hash,
            bindings_hash=entry.bindings_hash,
            observations_hash=entry.observations_hash,
            lifecycle=entry.lifecycle,
            tombstoned=entry.tombstoned,
            quarantined=entry.quarantined,
        )


@dataclass(frozen=True)
class VerifiedEvidence:
    """Sealed record + index claims from one verified read."""

    record: ev.EvidenceRecord
    index: IndexClaims | None = None


class VerifiedRead(Protocol):
    """Narrow read seam: verified evidence + provenance lookup.

    ``read_by_content_hash`` resolves stored-round SUBMIT legs pinned
    by sealed ``submit_evidence_ref`` content hashes; it returns a
    tuple (zero, one, or many) so ambiguous pairing is visible to the
    verifier and never guessed.
    """

    def read_verified(self, evidence_id: str) -> VerifiedEvidence: ...

    def read_authorization(
        self, authorization_id: str
    ) -> IssuedExecutionAuthorization | None: ...

    def read_by_content_hash(
        self, content_hash: str
    ) -> tuple[ev.EvidenceRecord, ...]: ...


class StoreVerifiedRead:
    """Verified-read adapter over the frozen 5H store (read-only)."""

    def __init__(
        self,
        store: EvidenceStore,
        index: object,
        authorization_lookup: Callable[
            [str], IssuedExecutionAuthorization | None
        ]
        | None = None,
    ) -> None:
        if not isinstance(store, EvidenceStore):
            raise TypeError(
                "verified read wraps only EvidenceStore, "
                f"not {type(store).__name__}"
            )
        if not callable(getattr(store, "get_by_evidence_id", None)):
            raise TypeError("store missing capability: get_by_evidence_id")
        get_entry = getattr(index, "get_by_evidence_id", None)
        if not callable(get_entry):
            raise TypeError("index missing capability: get_by_evidence_id")
        self._store = store
        self._index = index
        self._get_entry = get_entry
        self._authorization_lookup = authorization_lookup

    def read_verified(self, evidence_id: str) -> VerifiedEvidence:
        record = self._store.get_by_evidence_id(evidence_id)
        entry = self._get_entry(evidence_id)
        claims = IndexClaims.from_entry(entry) if entry is not None else None
        return VerifiedEvidence(record=record, index=claims)

    def read_authorization(
        self, authorization_id: str
    ) -> IssuedExecutionAuthorization | None:
        if self._authorization_lookup is None:
            return None
        return self._authorization_lookup(authorization_id)

    def read_by_content_hash(
        self, content_hash: str
    ) -> tuple[ev.EvidenceRecord, ...]:
        lookup = getattr(self._index, "lookup_by_content_hash", None)
        if not callable(lookup):
            return ()
        try:
            entries = lookup(content_hash)
        except Exception:
            return ()
        out: list[ev.EvidenceRecord] = []
        for entry in entries:
            try:
                out.append(self._store.get_by_evidence_id(entry.evidence_id))
            except Exception:
                continue
        return tuple(out)


def read_verified_input(
    seam: object, evidence_id: str
) -> VerifiedEvidence:
    """Invoke the seam with type enforcement (no fallback parsing)."""
    if not (
        callable(getattr(seam, "read_verified", None))
        and callable(getattr(seam, "read_authorization", None))
    ):
        raise TypeError(
            "5I requires a VerifiedRead seam (read_verified + "
            f"read_authorization), got {type(seam).__name__}"
        )
    result = seam.read_verified(evidence_id)  # type: ignore[attr-defined]
    if not isinstance(result, VerifiedEvidence):
        raise TypeError(
            "VerifiedRead.read_verified must return VerifiedEvidence, "
            f"not {type(result).__name__}"
        )
    return result
