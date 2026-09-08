"""Mongo-backed evidence blob + index stores (Stage 2, B2 seams).

``MongoBlobStore`` implements the ``ai.evidence.blob_store.BlobStore``
CAS surface; ``MongoEvidenceIndex`` implements the
``ai.evidence.index.EvidenceIndex`` conditional-mutation surface —
both over an injected ``MongoCollection`` driver. Blob/index
separation is preserved exactly as the architecture requires.

Blob document shape::

    {
      "_id": <content_hash>,   # unique; server-derived key only
      "payload": <bytes>,      # canonical envelope bytes
      "quarantined": <bool>,
      "quarantine_reason": <str | None>,
    }

Index document shape::

    {
      "_id": <evidence_id>,                    # unique
      "execution_id": <ex-…>,                  # unique
      "slot": "<authorization_id>|<stage>",    # unique (at-most-once)
      "content_hash": <sha256>,
      "record_version": <int>,                 # CAS guard
      "lifecycle": <str>,
      "document": <IndexEntry model_dump(mode=json)>,
    }

Integrity rules (unchanged from the fakes):

- Keys are derived, never caller-selected; ``put_if_absent`` with
  same key + differing bytes fails closed (never overwrite).
- Reads re-validate types; corrupt rows fail closed via
  ``EVIDENCE_MALFORMED`` / ``EVIDENCE_HASH_MISMATCH``.
- Only sealed terminals persist (callers enforce; adapters validate
  row shape, never seal anything themselves).
- Quarantine annotates; deletion requires an explicit retention
  policy object and never happens here (no delete API exists).
- Driver outages propagate as ``MongoUnavailableError`` (fail
  closed). No secrets, bodies, or connection strings in errors.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict

from ai.evidence.index import (
    IndexDuplicateError,
    IndexEntry,
    IndexVersionConflict,
)
from ai.persistence.driver import DuplicateKeyError, MongoCollection
from ai.schemas import evidence as ev

__all__ = [
    "BLOB_UNIQUE_INDEXES",
    "INDEX_UNIQUE_INDEXES",
    "MongoBlobStore",
    "MongoEvidenceIndex",
]

#: Unique indexes production wiring must ensure on the collections.
BLOB_UNIQUE_INDEXES: tuple[tuple[str, ...], ...] = (("_id",),)
INDEX_UNIQUE_INDEXES: tuple[tuple[str, ...], ...] = (
    ("_id",),
    ("execution_id",),
    ("slot",),
)

_EVIDENCE_ID_RE = re.compile(r"^ev-[0-9a-f]{32}$")
_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")
_AUTHZ_ID_RE = re.compile(r"^authz-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _check_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", f"invalid store {label}"
        )
    return value


def _check_entry(entry: IndexEntry) -> IndexEntry:
    if not isinstance(entry, IndexEntry):
        raise TypeError(
            "index accepts only IndexEntry, "
            f"not {type(entry).__name__}"
        )
    for pattern, value, label in (
        (_EVIDENCE_ID_RE, entry.evidence_id, "evidence_id"),
        (_EXECUTION_ID_RE, entry.execution_id, "execution_id"),
        (_AUTHZ_ID_RE, entry.authorization_id, "authorization_id"),
    ):
        if not isinstance(value, str) or not pattern.match(value):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", f"invalid index {label}"
            )
    for value, label in (
        (entry.content_hash, "content_hash"),
        (entry.bindings_hash, "bindings_hash"),
        (entry.observations_hash, "observations_hash"),
    ):
        _check_hash(value, label)
    if (
        not isinstance(entry.record_version, int)
        or isinstance(entry.record_version, bool)
        or entry.record_version < 1
    ):
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", "index record_version invalid"
        )
    return entry


def _slot_for(authorization_id: str, execution_stage: str) -> str:
    return f"{authorization_id}|{execution_stage}"


class MongoBlobStore:
    """Persistent content-addressed blob CAS (same rules as memory)."""

    def __init__(self, collection: MongoCollection) -> None:
        for method in ("find_one", "find", "insert_one", "replace_one"):
            if not callable(getattr(collection, method, None)):
                raise TypeError(
                    "blob store requires a MongoCollection driver, "
                    f"missing: {method}"
                )
        self._collection = collection

    def put_if_absent(
        self, content_hash: str, payload: bytes, *, enforce_identity: bool = True
    ) -> bool:
        key = _check_hash(content_hash, "content hash")
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError(
                "blob payloads must be bytes, "
                f"not {type(payload).__name__}"
            )
        raw = bytes(payload)
        if enforce_identity and hashlib.sha256(raw).hexdigest() != key:
            raise ev.EvidenceError(
                "EVIDENCE_HASH_MISMATCH",
                "payload bytes do not match claimed content hash",
            )
        existing = self._collection.find_one({"_id": key})
        if existing is not None:
            if existing.get("payload") != raw:
                raise ev.EvidenceError(
                    "EVIDENCE_HASH_MISMATCH",
                    "same key with differing bytes refused",
                )
            return False
        try:
            self._collection.insert_one(
                {
                    "_id": key,
                    "payload": raw,
                    "quarantined": False,
                    "quarantine_reason": None,
                }
            )
        except DuplicateKeyError:
            existing = self._collection.find_one({"_id": key})
            if existing is None or existing.get("payload") != raw:
                raise ev.EvidenceError(
                    "EVIDENCE_HASH_MISMATCH",
                    "same key with differing bytes refused",
                )
            return False
        return True

    def get(self, content_hash: str) -> bytes | None:
        stored = self._collection.find_one({"_id": _check_hash(content_hash, "content hash")})
        if stored is None:
            return None
        payload = stored.get("payload")
        return bytes(payload) if payload is not None else None

    def exists(self, content_hash: str) -> bool:
        return self.get(content_hash) is not None

    def verify(self, content_hash: str) -> bool:
        key = _check_hash(content_hash, "content hash")
        raw = self.get(key)
        if raw is None:
            return False
        return hashlib.sha256(raw).hexdigest() == key

    def quarantine(self, content_hash: str, *, reason: str) -> None:
        key = _check_hash(content_hash, "content hash")
        if not isinstance(reason, str) or not reason.strip():
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "quarantine requires a reason"
            )
        if len(reason) > 200 or "\n" in reason or "\r" in reason:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "quarantine reason not single-line"
            )
        stored = self._collection.find_one({"_id": key})
        if stored is None:
            return
        record = dict(stored)
        record["quarantined"] = True
        record["quarantine_reason"] = reason.strip()
        self._collection.replace_one({"_id": key}, record)

    def quarantined(self, content_hash: str) -> bool:
        stored = self._collection.find_one(
            {"_id": _check_hash(content_hash, "content hash")}
        )
        return bool(stored and stored.get("quarantined"))

    def list_hashes(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                row["_id"]
                for row in self._collection.find({})
                if isinstance(row.get("_id"), str)
            )
        )


class MongoEvidenceIndex:
    """Persistent evidence index (same conditional rules as memory)."""

    def __init__(self, collection: MongoCollection) -> None:
        for method in ("find_one", "find", "insert_one", "replace_one"):
            if not callable(getattr(collection, method, None)):
                raise TypeError(
                    "index requires a MongoCollection driver, "
                    f"missing: {method}"
                )
        self._collection = collection

    # -- internals ---------------------------------------------------

    @staticmethod
    def _to_document(entry: IndexEntry) -> dict:
        return {
            "_id": entry.evidence_id,
            "execution_id": entry.execution_id,
            "slot": _slot_for(entry.authorization_id, entry.execution_stage),
            "content_hash": entry.content_hash,
            "record_version": entry.record_version,
            "lifecycle": entry.lifecycle,
            "document": asdict(entry),
        }

    @staticmethod
    def _from_document(stored: dict) -> IndexEntry:
        return IndexEntry(**{
            key: value
            for key, value in stored.get("document", {}).items()
        })

    def _cas(self, evidence_id: str, expected_version: int) -> dict:
        if not isinstance(expected_version, int) or isinstance(
            expected_version, bool
        ):
            raise TypeError("CAS expected_version must be an integer")
        current = self._collection.find_one({"_id": evidence_id})
        if current is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "index entry missing for CAS"
            )
        if current.get("record_version") != expected_version:
            raise IndexVersionConflict(
                "index row changed under caller; re-read before retry"
            )
        return current

    # -- EvidenceIndex interface ---------------------------------------

    def insert_if_absent(self, entry: IndexEntry) -> bool:
        entry = _check_entry(entry)
        existing = self._collection.find_one({"_id": entry.evidence_id})
        if existing is not None:
            current = self._from_document(existing)
            if (
                current.execution_id != entry.execution_id
                or current.authorization_id != entry.authorization_id
                or current.content_hash != entry.content_hash
                or current.bindings_hash != entry.bindings_hash
                or current.observations_hash != entry.observations_hash
            ):
                raise IndexDuplicateError(
                    "evidence_id bound to differing content; refused"
                )
            return False
        if (
            self._collection.find_one({"execution_id": entry.execution_id})
            is not None
        ):
            raise IndexDuplicateError(
                "execution_id already indexed; retry needs new execution"
            )
        if (
            self._collection.find_one(
                {"slot": _slot_for(entry.authorization_id, entry.execution_stage)}
            )
            is not None
        ):
            raise IndexDuplicateError(
                "authorization slot already indexed; at-most-once"
            )
        try:
            self._collection.insert_one(self._to_document(entry))
        except DuplicateKeyError as exc:
            raise IndexDuplicateError(
                "index identity collision; refused"
            ) from exc
        return True

    def get_by_evidence_id(self, evidence_id: str) -> IndexEntry | None:
        if not isinstance(evidence_id, str) or not _EVIDENCE_ID_RE.match(
            evidence_id
        ):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "invalid index evidence_id"
            )
        stored = self._collection.find_one({"_id": evidence_id})
        if stored is None:
            return None
        return self._from_document(stored)

    def get_by_execution_id(self, execution_id: str) -> IndexEntry | None:
        if not isinstance(execution_id, str) or not _EXECUTION_ID_RE.match(
            execution_id
        ):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "invalid index execution_id"
            )
        stored = self._collection.find_one({"execution_id": execution_id})
        if stored is None:
            return None
        return self._from_document(stored)

    def get_by_authorization_id(
        self, authorization_id: str
    ) -> tuple[IndexEntry, ...]:
        if not isinstance(authorization_id, str) or not _AUTHZ_ID_RE.match(
            authorization_id
        ):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "invalid index authorization_id"
            )
        # The driver seam supports flat exact-equality filters only, so
        # the program-side scan below keeps this method portable across
        # the fake and real drivers without query-language drift.
        return tuple(
            self._from_document(row)
            for row in self._collection.find({})
            if row.get("document", {}).get("authorization_id")
            == authorization_id
        )

    def lookup_by_content_hash(
        self, content_hash: str
    ) -> tuple[IndexEntry, ...]:
        _check_hash(content_hash, "content_hash")
        return tuple(
            self._from_document(row)
            for row in self._collection.find({"content_hash": content_hash})
        )

    def mark_indexed(
        self,
        evidence_id: str,
        *,
        expected_version: int,
        indexed_at: str = "",
    ) -> IndexEntry:
        current = self._cas(evidence_id, expected_version)
        record = self._from_document(current)
        if record.lifecycle == "INDEXED":
            return record
        if record.lifecycle not in ("SEALED", "INCOMPLETE"):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED",
                "only sealed terminals may become indexed",
            )
        if not isinstance(indexed_at, str):
            raise TypeError("indexed_at must be a string")
        updated = IndexEntry(
            **{
                **record.__dict__,
                "lifecycle": "INDEXED",
                "record_version": record.record_version + 1,
                "indexed_at": indexed_at,
            }
        )
        replaced = self._collection.replace_one(
            {"_id": evidence_id, "record_version": expected_version},
            self._to_document(updated),
        )
        if not replaced:
            raise IndexVersionConflict(
                "index row changed under caller; re-read before retry"
            )
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
        record = self._from_document(current)
        updated = IndexEntry(
            **{
                **record.__dict__,
                "lifecycle": "QUARANTINED",
                "record_version": record.record_version + 1,
                "quarantined": True,
                "quarantine_reason": reason.strip(),
            }
        )
        replaced = self._collection.replace_one(
            {"_id": evidence_id, "record_version": expected_version},
            self._to_document(updated),
        )
        if not replaced:
            raise IndexVersionConflict(
                "index row changed under caller; re-read before retry"
            )
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
        record = self._from_document(current)
        updated = IndexEntry(
            **{
                **record.__dict__,
                "lifecycle": "TOMBSTONED",
                "record_version": record.record_version + 1,
                "tombstoned": True,
                "tombstone_policy": policy.policy_id,
            }
        )
        replaced = self._collection.replace_one(
            {"_id": evidence_id, "record_version": expected_version},
            self._to_document(updated),
        )
        if not replaced:
            raise IndexVersionConflict(
                "index row changed under caller; re-read before retry"
            )
        return updated

    def entry_count(self) -> int:
        return len(self._collection.find({}))
