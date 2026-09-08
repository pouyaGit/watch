"""Typed evidence index abstraction (Phase 5H).

The index is the ONLY queryable evidence surface. Blobs are
key-addressed; all execution/authorization/content lookups resolve
here. Every mutation is conditional (CAS on ``record_version``);
read-modify-write without a version guard is structurally
unavailable — no generic update/patch API exists.

Production MongoDB remains behind the B2 gate: ``B2_BLOCKED`` is True
and ``MongoEvidenceIndexAdapter`` fails closed on any use. The
deterministic ``InMemoryEvidenceIndex`` fake models unique indexes,
CAS versioning, duplicate-key behavior, tombstones, and quarantine
for tests. It does NOT pretend to be production Mongo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from ai.schemas import evidence as ev

__all__ = [
    "B2_STATUS",
    "B2_BLOCKED",
    "IndexLifecycle",
    "IndexEntry",
    "EvidenceIndex",
    "InMemoryEvidenceIndex",
    "IndexDuplicateError",
    "IndexVersionConflict",
    "MongoEvidenceIndexAdapter",
]

#: B2 remains BLOCKED in Phase 5H. Production Mongo access is
#: designed but not enabled; the stub adapter below fails closed.
B2_STATUS = "BLOCKED"
B2_BLOCKED = True

IndexLifecycle = Literal[
    "SEALED",
    "INCOMPLETE",
    "INDEXED",
    "QUARANTINED",
    "TOMBSTONED",
]

_EVIDENCE_ID_RE = re.compile(r"^ev-[0-9a-f]{32}$")
_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")
_AUTHZ_ID_RE = re.compile(r"^authz-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class IndexDuplicateError(ValueError):
    """Unique-index collision with differing content (fail closed)."""


class IndexVersionConflict(ValueError):
    """CAS version guard mismatch (loser re-reads, never overwrites)."""


def _check_id(pattern: re.Pattern[str], value: object, label: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", f"invalid index {label}"
        )
    return value


def _check_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", f"invalid index {label}"
        )
    return value


@dataclass(frozen=True)
class IndexEntry:
    """One immutable-indexed evidence pointer (versioned for CAS).

    Binding fields and hashes are frozen at insert. Only the
    lifecycle annotation (``SEALED → INDEXED → QUARANTINED |
    TOMBSTONED``), ``record_version``, and operator annotations may
    advance — and only via the narrow CAS transitions below.
    """

    evidence_id: str
    execution_id: str
    authorization_id: str
    execution_stage: str
    execution_class: str
    content_hash: str
    bindings_hash: str
    observations_hash: str
    artifact_id: str
    program_name: str
    lifecycle: IndexLifecycle = "SEALED"
    record_version: int = 1
    quarantined: bool = False
    quarantine_reason: str | None = None
    tombstoned: bool = False
    tombstone_policy: str | None = None
    indexed_at: str = ""
    sealed_at: str = ""


class EvidenceIndex:
    """Narrow index seam (conditional mutations only)."""

    def insert_if_absent(self, entry: IndexEntry) -> bool: ...
    def get_by_evidence_id(self, evidence_id: str) -> IndexEntry | None: ...
    def get_by_execution_id(self, execution_id: str) -> IndexEntry | None: ...
    def get_by_authorization_id(
        self, authorization_id: str
    ) -> tuple[IndexEntry, ...]: ...
    def lookup_by_content_hash(
        self, content_hash: str
    ) -> tuple[IndexEntry, ...]: ...
    def mark_indexed(
        self,
        evidence_id: str,
        *,
        expected_version: int,
        indexed_at: str = "",
    ) -> IndexEntry: ...
    def quarantine(
        self,
        evidence_id: str,
        *,
        expected_version: int,
        reason: str,
    ) -> IndexEntry: ...
    def tombstone(
        self,
        evidence_id: str,
        *,
        expected_version: int,
        policy: object,
    ) -> IndexEntry: ...


class InMemoryEvidenceIndex:
    """Deterministic fake index (tests only).

    Models: unique ``evidence_id`` / ``execution_id`` /
    ``(authorization_id, execution_stage)`` / ``content_hash→ids``
    lookups, CAS versioning, duplicate-key behavior (identical
    re-insert is a no-op success; same key with differing bindings or
    hashes raises ``IndexDuplicateError``), stale-writer conflicts
    (``IndexVersionConflict``), tombstones, and quarantine flags.
    """

    def __init__(self) -> None:
        self._by_evidence: dict[str, IndexEntry] = {}
        self._by_execution: dict[str, str] = {}
        self._by_slot: dict[tuple[str, str], str] = {}
        self._by_content: dict[str, list[str]] = {}

    @staticmethod
    def _validate(entry: IndexEntry) -> IndexEntry:
        if not isinstance(entry, IndexEntry):
            raise TypeError(
                "index accepts only IndexEntry, "
                f"not {type(entry).__name__}"
            )
        _check_id(_EVIDENCE_ID_RE, entry.evidence_id, "evidence_id")
        _check_id(_EXECUTION_ID_RE, entry.execution_id, "execution_id")
        _check_id(_AUTHZ_ID_RE, entry.authorization_id, "authorization_id")
        _check_hash(entry.content_hash, "content_hash")
        _check_hash(entry.bindings_hash, "bindings_hash")
        _check_hash(entry.observations_hash, "observations_hash")
        if (
            not isinstance(entry.record_version, int)
            or isinstance(entry.record_version, bool)
            or entry.record_version < 1
        ):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "index record_version invalid"
            )
        return entry

    def insert_if_absent(self, entry: IndexEntry) -> bool:
        entry = self._validate(entry)
        existing = self._by_evidence.get(entry.evidence_id)
        if existing is not None:
            if (
                existing.execution_id != entry.execution_id
                or existing.authorization_id != entry.authorization_id
                or existing.content_hash != entry.content_hash
                or existing.bindings_hash != entry.bindings_hash
                or existing.observations_hash != entry.observations_hash
            ):
                raise IndexDuplicateError(
                    "evidence_id bound to differing content; refused"
                )
            return False
        if entry.execution_id in self._by_execution:
            raise IndexDuplicateError(
                "execution_id already indexed; retry needs new execution"
            )
        slot = (entry.authorization_id, entry.execution_stage)
        if slot in self._by_slot:
            raise IndexDuplicateError(
                "authorization slot already indexed; at-most-once"
            )
        self._by_evidence[entry.evidence_id] = entry
        self._by_execution[entry.execution_id] = entry.evidence_id
        self._by_slot[slot] = entry.evidence_id
        self._by_content.setdefault(entry.content_hash, []).append(
            entry.evidence_id
        )
        return True

    def get_by_evidence_id(self, evidence_id: str) -> IndexEntry | None:
        _check_id(_EVIDENCE_ID_RE, evidence_id, "evidence_id")
        return self._by_evidence.get(evidence_id)

    def get_by_execution_id(self, execution_id: str) -> IndexEntry | None:
        _check_id(_EXECUTION_ID_RE, execution_id, "execution_id")
        evidence_id = self._by_execution.get(execution_id)
        if evidence_id is None:
            return None
        return self._by_evidence.get(evidence_id)

    def get_by_authorization_id(
        self, authorization_id: str
    ) -> tuple[IndexEntry, ...]:
        _check_id(_AUTHZ_ID_RE, authorization_id, "authorization_id")
        return tuple(
            entry
            for entry in self._by_evidence.values()
            if entry.authorization_id == authorization_id
        )

    def lookup_by_content_hash(
        self, content_hash: str
    ) -> tuple[IndexEntry, ...]:
        _check_hash(content_hash, "content_hash")
        return tuple(
            self._by_evidence[evidence_id]
            for evidence_id in self._by_content.get(content_hash, [])
            if evidence_id in self._by_evidence
        )

    def _cas(
        self, evidence_id: str, expected_version: int
    ) -> IndexEntry:
        _check_id(_EVIDENCE_ID_RE, evidence_id, "evidence_id")
        if (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
        ):
            raise TypeError("CAS expected_version must be an integer")
        current = self._by_evidence.get(evidence_id)
        if current is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "index entry missing for CAS"
            )
        if current.record_version != expected_version:
            raise IndexVersionConflict(
                "index row changed under caller; re-read before retry"
            )
        return current

    def mark_indexed(
        self,
        evidence_id: str,
        *,
        expected_version: int,
        indexed_at: str = "",
    ) -> IndexEntry:
        current = self._cas(evidence_id, expected_version)
        if current.lifecycle == "INDEXED":
            return current
        if current.lifecycle not in ("SEALED", "INCOMPLETE"):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED",
                "only sealed terminals may become indexed",
            )
        if not isinstance(indexed_at, str):
            raise TypeError("indexed_at must be a string")
        updated = IndexEntry(
            **{
                **current.__dict__,
                "lifecycle": "INDEXED",
                "record_version": current.record_version + 1,
                "indexed_at": indexed_at,
            }
        )
        self._by_evidence[evidence_id] = updated
        return updated

    def quarantine(
        self,
        evidence_id: str,
        *,
        expected_version: int,
        reason: str,
    ) -> IndexEntry:
        current = self._cas(evidence_id, expected_version)
        if not isinstance(reason, str) or not reason.strip():
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "quarantine requires a reason"
            )
        if len(reason) > 200 or "\n" in reason or "\r" in reason:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "quarantine reason not single-line"
            )
        updated = IndexEntry(
            **{
                **current.__dict__,
                "lifecycle": "QUARANTINED",
                "record_version": current.record_version + 1,
                "quarantined": True,
                "quarantine_reason": reason.strip(),
            }
        )
        self._by_evidence[evidence_id] = updated
        return updated

    def tombstone(
        self,
        evidence_id: str,
        *,
        expected_version: int,
        policy: object,
    ) -> IndexEntry:
        from ai.evidence.store import RetentionPolicy

        current = self._cas(evidence_id, expected_version)
        if not isinstance(policy, RetentionPolicy):
            raise TypeError(
                "tombstone accepts only RetentionPolicy, "
                f"not {type(policy).__name__}"
            )
        updated = IndexEntry(
            **{
                **current.__dict__,
                "lifecycle": "TOMBSTONED",
                "record_version": current.record_version + 1,
                "tombstoned": True,
                "tombstone_policy": policy.policy_id,
            }
        )
        self._by_evidence[evidence_id] = updated
        return updated

    def entry_count(self) -> int:
        return len(self._by_evidence)


class MongoEvidenceIndexAdapter:
    """Production Mongo adapter stub (B2-gated, fail-closed).

    Design placeholder only. Every operation raises
    ``EVIDENCE_MALFORMED`` with a B2-blocked code path while
    ``B2_BLOCKED`` is True. No credentials, connection strings, or
    deployment topology exist here by design.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED",
            "B2 BLOCKED: production Mongo adapter unavailable",
        )

    def __getattr__(self, name: str) -> object:
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED",
            "B2 BLOCKED: production Mongo adapter unavailable",
        )
