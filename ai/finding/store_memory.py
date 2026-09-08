"""5J persistence seams (Phase 5J, offline).

Three pieces:

- ``FindingStore`` ABC: the narrow persistence contract (insert-only,
  program-scoped reads). ``FindingStoreMemory`` is the offline
  implementation: ``dict[(program_name, finding_id)]`` with
  put-if-absent + byte-compare refusal — the same discipline as the
  5H blob layer. There is deliberately NO update / patch / delete /
  upsert API on the security record (test-asserted absent); archival
  and tombstoning flip store-entry metadata, never finding bytes.
- ``WorkflowStore`` ABC + ``WorkflowStoreMemory``: the SEPARATE
  operational record (acknowledged / assignee / labels / comments /
  resolution / state) with CAS versioning. It shares NO writable
  field with the security record except ``finding_id``.
- ``MongoFindingStoreAdapter``: B2-blocked stub. It exposes the
  future adapter shape (two-collection split is documented in the
  class docstring) but fails closed on construction AND on every
  method. No credentials, no connections, no indexes executed.

Crash recovery for both current and future backends is replay-safe
inserts: every write is idempotent by key; job checkpoints live
OUTSIDE the security store.
"""

from __future__ import annotations

import re as _re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass

__all__ = [
    "B2_STATUS",
    "B2_BLOCKED",
    "PERSISTED",
    "DEDUPLICATED",
    "CORRUPT_COLLISION",
    "FindingStore",
    "StoredFinding",
    "FindingStoreMemory",
    "WorkflowState",
    "WorkflowRecord",
    "WorkflowStore",
    "WorkflowStoreMemory",
    "WorkflowVersionConflict",
    "MongoFindingStoreAdapter",
]

#: B2 remains BLOCKED in Phase 5J. Production Mongo access is
#: specified but not enabled; the stub adapter below fails closed.
B2_STATUS = "BLOCKED"
B2_BLOCKED = True

PERSISTED = "PERSISTED"
DEDUPLICATED = "DEDUPLICATED"
CORRUPT_COLLISION = "CORRUPT_COLLISION"

_FINDING_ID_RE = _re.compile(r"^xf-[0-9a-f]{32}$")

#: Security-record lifecycle (forward-only; transitions are events).
LIFECYCLE_PERSISTED = "PERSISTED"
LIFECYCLE_ARCHIVED = "ARCHIVED"
LIFECYCLE_TOMBSTONED = "TOMBSTONED"


class WorkflowVersionConflict(ValueError):
    """CAS version guard mismatch (loser re-reads, never overwrites)."""


@dataclass(frozen=True)
class StoredFinding:
    """One persisted security record + store metadata (bytes immutable)."""

    program_name: str
    finding_id: str
    payload: bytes
    lifecycle: str = LIFECYCLE_PERSISTED
    materialized_at: str = ""
    tombstone_reason: str | None = None
    tombstoned_by: str | None = None


class FindingStore(ABC):
    """Narrow insert-only finding persistence contract."""

    @abstractmethod
    def put(
        self, program_name: str, finding_id: str, payload: bytes
    ) -> str:
        """Put-if-absent; ``PERSISTED`` | ``DEDUPLICATED`` | ``CORRUPT_COLLISION``."""

    @abstractmethod
    def get_entry(
        self, program_name: str, finding_id: str
    ) -> StoredFinding | None:
        """Fetch one entry by program-scoped key (None when absent)."""

    @abstractmethod
    def list_ids(self, program_name: str) -> tuple[str, ...]:
        """Finding ids for EXACTLY one program (isolation by key)."""

    @abstractmethod
    def tombstone(
        self,
        program_name: str,
        finding_id: str,
        *,
        reason: str,
        actor: str,
    ) -> bool:
        """Mark tombstoned (bytes retained, hidden from default reads)."""

    @abstractmethod
    def archive(self, program_name: str, finding_id: str) -> bool:
        """Mark archived (bytes retained, query-side default-hide)."""


def _check_key(program_name: str, finding_id: str) -> tuple[str, str]:
    if not program_name or not program_name.strip():
        raise ValueError("program_name must be non-empty")
    if "\n" in program_name or "\r" in program_name:
        raise ValueError("program_name must be single-line")
    if not _FINDING_ID_RE.match(finding_id or ""):
        raise ValueError(f"invalid finding_id: {finding_id!r}")
    return program_name, finding_id


def _check_payload(payload: bytes) -> bytes:
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        raise ValueError("finding payload must be non-empty bytes")
    return bytes(payload)


class FindingStoreMemory(FindingStore):
    """Deterministic in-memory finding store (tests only, never Mongo).

    A small lock guards atomic check-and-insert so concurrent
    identical materializations collapse to one record; safety still
    comes from key-identity rules (put-if-absent + byte-compare),
    never from the lock alone.
    """

    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], StoredFinding] = {}
        self._lock = threading.Lock()

    def put(
        self, program_name: str, finding_id: str, payload: bytes
    ) -> str:
        program_name, finding_id = _check_key(program_name, finding_id)
        raw = _check_payload(payload)
        with self._lock:
            existing = self._objects.get((program_name, finding_id))
            if existing is not None:
                if existing.payload != raw:
                    return CORRUPT_COLLISION
                return DEDUPLICATED
            self._objects[(program_name, finding_id)] = StoredFinding(
                program_name=program_name,
                finding_id=finding_id,
                payload=raw,
            )
            return PERSISTED

    def get_entry(
        self, program_name: str, finding_id: str
    ) -> StoredFinding | None:
        program_name, finding_id = _check_key(program_name, finding_id)
        with self._lock:
            return self._objects.get((program_name, finding_id))

    def list_ids(self, program_name: str) -> tuple[str, ...]:
        if not program_name or not program_name.strip():
            raise ValueError("program_name must be non-empty")
        with self._lock:
            return tuple(
                sorted(
                    fid
                    for (program, fid) in self._objects
                    if program == program_name
                )
            )

    def tombstone(
        self,
        program_name: str,
        finding_id: str,
        *,
        reason: str,
        actor: str,
    ) -> bool:
        from dataclasses import replace

        program_name, finding_id = _check_key(program_name, finding_id)
        if not reason or not reason.strip() or len(reason) > 120:
            raise ValueError("tombstone requires a bounded reason")
        if "\n" in reason or "\r" in reason:
            raise ValueError("tombstone reason must be single-line")
        if not actor or not actor.strip() or len(actor) > 120:
            raise ValueError("tombstone requires a bounded actor")
        with self._lock:
            existing = self._objects.get((program_name, finding_id))
            if existing is None:
                return False
            self._objects[(program_name, finding_id)] = replace(
                existing,
                lifecycle=LIFECYCLE_TOMBSTONED,
                tombstone_reason=reason.strip(),
                tombstoned_by=actor.strip(),
            )
            return True

    def archive(self, program_name: str, finding_id: str) -> bool:
        from dataclasses import replace

        program_name, finding_id = _check_key(program_name, finding_id)
        with self._lock:
            existing = self._objects.get((program_name, finding_id))
            if existing is None:
                return False
            if existing.lifecycle == LIFECYCLE_TOMBSTONED:
                return False
            self._objects[(program_name, finding_id)] = replace(
                existing, lifecycle=LIFECYCLE_ARCHIVED
            )
            return True


WorkflowState = str

#: Allowed workflow transitions (mutable ops record ONLY; the security
#: record is untouched by every one of these).
_WORKFLOW_EDGES: dict[str, frozenset[str]] = {
    "OPEN": frozenset({"ACKNOWLEDGED"}),
    "ACKNOWLEDGED": frozenset({"OPEN", "RESOLVED"}),
    "RESOLVED": frozenset({"REOPENED"}),
    "REOPENED": frozenset({"ACKNOWLEDGED", "RESOLVED"}),
}


@dataclass(frozen=True)
class WorkflowRecord:
    """One CAS-versioned operational record (no security fields)."""

    finding_id: str
    program_name: str
    state: str = "OPEN"
    acknowledged: bool = False
    assignee: str | None = None
    labels: tuple[str, ...] = ()
    comments: tuple[str, ...] = ()
    resolution_note: str | None = None
    version: int = 1


class WorkflowStore(ABC):
    """Narrow CAS workflow contract (operational metadata ONLY)."""

    @abstractmethod
    def get_or_create(
        self, finding_id: str, program_name: str
    ) -> WorkflowRecord:
        """Fetch or initialize the OPEN workflow record (version 1)."""

    @abstractmethod
    def transition(
        self,
        finding_id: str,
        program_name: str,
        *,
        expected_version: int,
        state: str | None = None,
        acknowledged: bool | None = None,
        assignee: str | None = None,
        add_labels: tuple[str, ...] = (),
        add_comment: str | None = None,
        resolution_note: str | None = None,
    ) -> WorkflowRecord:
        """CAS-guarded workflow mutation (version mismatch → conflict)."""


class WorkflowStoreMemory(WorkflowStore):
    """Deterministic in-memory workflow store (tests only)."""

    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], WorkflowRecord] = {}
        self._lock = threading.Lock()

    def get_or_create(
        self, finding_id: str, program_name: str
    ) -> WorkflowRecord:
        program_name, finding_id = _check_key(program_name, finding_id)
        with self._lock:
            existing = self._objects.get((program_name, finding_id))
            if existing is not None:
                return existing
            record = WorkflowRecord(
                finding_id=finding_id, program_name=program_name
            )
            self._objects[(program_name, finding_id)] = record
            return record

    def transition(
        self,
        finding_id: str,
        program_name: str,
        *,
        expected_version: int,
        state: str | None = None,
        acknowledged: bool | None = None,
        assignee: str | None = None,
        add_labels: tuple[str, ...] = (),
        add_comment: str | None = None,
        resolution_note: str | None = None,
    ) -> WorkflowRecord:
        from dataclasses import replace

        program_name, finding_id = _check_key(program_name, finding_id)
        with self._lock:
            existing = self._objects.get((program_name, finding_id))
            if existing is None:
                raise KeyError(f"no workflow record for {finding_id!r}")
            if existing.version != expected_version:
                raise WorkflowVersionConflict(
                    f"expected version {expected_version}, "
                    f"stored {existing.version}"
                )
            next_state = state if state is not None else existing.state
            if next_state != existing.state and (
                next_state not in _WORKFLOW_EDGES.get(existing.state, ())
            ):
                raise ValueError(
                    f"illegal workflow transition "
                    f"{existing.state} -> {next_state}"
                )
            labels = tuple(existing.labels)
            for label in add_labels:
                if (
                    isinstance(label, str)
                    and label
                    and label not in labels
                ):
                    labels = labels + (label,)
            comments = tuple(existing.comments)
            if add_comment is not None:
                if (
                    not isinstance(add_comment, str)
                    or not add_comment
                    or len(add_comment) > 500
                    or "\n" in add_comment
                    or "\r" in add_comment
                ):
                    raise ValueError("comment must be bounded single-line")
                comments = comments + (add_comment,)
            if assignee is not None and (
                not isinstance(assignee, str)
                or not assignee
                or len(assignee) > 120
            ):
                raise ValueError("assignee must be a bounded string")
            if resolution_note is not None and (
                not isinstance(resolution_note, str)
                or len(resolution_note) > 500
            ):
                raise ValueError("resolution_note must be bounded")
            updated = replace(
                existing,
                state=next_state,
                acknowledged=(
                    acknowledged
                    if acknowledged is not None
                    else existing.acknowledged
                ),
                assignee=(
                    assignee if assignee is not None else existing.assignee
                ),
                labels=labels,
                comments=comments,
                resolution_note=(
                    resolution_note
                    if resolution_note is not None
                    else existing.resolution_note
                ),
                version=existing.version + 1,
            )
            self._objects[(program_name, finding_id)] = updated
            return updated


class MongoFindingStoreAdapter(FindingStore):
    """B2-blocked production adapter stub (specified, never enabled).

    Future shape (B2-gated, NOT built here): two collections —
    ``sealed_findings`` (unique index ``(program_name, finding_id)``;
    inserts only) and ``finding_workflows`` (``finding_id`` unique;
    CAS via version field). Every method below fails closed until B2
    is explicitly closed by a later authorized phase.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError(
            "MongoFindingStoreAdapter is B2-blocked: "
            "production MongoDB access is not enabled"
        )

    def put(
        self, program_name: str, finding_id: str, payload: bytes
    ) -> str:
        raise RuntimeError(
            "MongoFindingStoreAdapter is B2-blocked: "
            "production MongoDB access is not enabled"
        )

    def get_entry(
        self, program_name: str, finding_id: str
    ) -> StoredFinding | None:
        raise RuntimeError(
            "MongoFindingStoreAdapter is B2-blocked: "
            "production MongoDB access is not enabled"
        )

    def list_ids(self, program_name: str) -> tuple[str, ...]:
        raise RuntimeError(
            "MongoFindingStoreAdapter is B2-blocked: "
            "production MongoDB access is not enabled"
        )

    def tombstone(
        self,
        program_name: str,
        finding_id: str,
        *,
        reason: str,
        actor: str,
    ) -> bool:
        raise RuntimeError(
            "MongoFindingStoreAdapter is B2-blocked: "
            "production MongoDB access is not enabled"
        )

    def archive(self, program_name: str, finding_id: str) -> bool:
        raise RuntimeError(
            "MongoFindingStoreAdapter is B2-blocked: "
            "production MongoDB access is not enabled"
        )
