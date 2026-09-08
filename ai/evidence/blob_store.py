"""Content-addressed blob store (Phase 5H).

Immutable CAS for sealed evidence byte envelopes. Storage key is
server-derived only::

    blobs/sha256/<content_hash>

Caller-selected keys are structurally unrepresentable: every method
takes ``content_hash`` + bytes and derives the key internally.

Semantics (frozen):

- SHA-256 identity over the canonical envelope bytes.
- ``put_if_absent``: identical re-put is a no-op success; same key
  with differing bytes fails closed (never overwrite).
- Atomic temp-write + fsync + rename; read-back verification before
  the put is reported durable; no partial object is ever exposed as
  durable.
- ``quarantine`` annotates (never mutates bytes); destructive removal
  requires an explicit retention policy object (see
  ``ai.evidence.store``) and is never automatic.

This module performs NO network, NO DNS, NO subprocess, NO MongoDB,
NO browser, NO Nuclei, NO LLM access. The filesystem backend below is
a deterministic test implementation confined to an explicit root
directory supplied by the caller (tests use controlled temp dirs).
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Protocol

from ai.schemas import evidence as ev

__all__ = [
    "BLOB_KEY_PREFIX",
    "BLOB_KEY_RE",
    "blob_key_for",
    "BlobStore",
    "BlobStats",
    "InMemoryBlobStore",
    "FilesystemCASBlobStore",
]

#: Server-controlled key prefix. No caller input enters the key other
#: than the validated content hash itself.
BLOB_KEY_PREFIX = "blobs/sha256/"

BLOB_KEY_RE = re.compile(r"^blobs/sha256/[0-9a-f]{64}$")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def blob_key_for(content_hash: str) -> str:
    """Derive the server-controlled storage key for a content hash."""
    if not isinstance(content_hash, str) or not _SHA256_RE.match(
        content_hash
    ):
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", "blob key requires a sha256 content hash"
        )
    return BLOB_KEY_PREFIX + content_hash


def _check_hash(content_hash: object) -> str:
    if not isinstance(content_hash, str) or not _SHA256_RE.match(
        content_hash
    ):
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", "content hash must be sha256 hex"
        )
    return content_hash


def _check_bytes(payload: object) -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError(
            "blob payloads must be bytes, "
            f"not {type(payload).__name__}"
        )
    return bytes(payload)


class BlobStore(Protocol):
    """Narrow CAS seam. Keys are derived, never caller-selected."""

    def put_if_absent(
        self,
        content_hash: str,
        payload: bytes,
        *,
        enforce_identity: bool = True,
    ) -> bool: ...
    def get(self, content_hash: str) -> bytes | None: ...
    def exists(self, content_hash: str) -> bool: ...
    def verify(self, content_hash: str) -> bool: ...
    def quarantine(self, content_hash: str, *, reason: str) -> None: ...
    def quarantined(self, content_hash: str) -> bool: ...
    def list_hashes(self) -> tuple[str, ...]: ...


@dataclass
class BlobStats:
    """Deterministic accounting snapshot (no secrets)."""

    objects: int = 0
    bytes_total: int = 0
    quarantined: int = 0


class InMemoryBlobStore:
    """Deterministic fake CAS (tests only; never production Mongo).

    Models put-if-absent, duplicate-key, corruption (via explicit
    ``corrupt`` helper), and quarantine. Thread-hostile on purpose:
    callers must not rely on process-local locking — the store API
    itself is race-safe by key-identity rules.
    """

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}
        self._quarantined: dict[str, str] = {}
        self.put_calls: int = 0

    def put_if_absent(
        self, content_hash: str, payload: bytes, *, enforce_identity: bool = True
    ) -> bool:
        key = _check_hash(content_hash)
        raw = _check_bytes(payload)
        if enforce_identity and hashlib.sha256(raw).hexdigest() != key:
            raise ev.EvidenceError(
                "EVIDENCE_HASH_MISMATCH",
                "payload bytes do not match claimed content hash",
            )
        self.put_calls += 1
        existing = self._objects.get(key)
        if existing is not None:
            if existing != raw:
                raise ev.EvidenceError(
                    "EVIDENCE_HASH_MISMATCH",
                    "same key with differing bytes refused",
                )
            return False
        self._objects[key] = raw
        return True

    def get(self, content_hash: str) -> bytes | None:
        key = _check_hash(content_hash)
        raw = self._objects.get(key)
        return bytes(raw) if raw is not None else None

    def exists(self, content_hash: str) -> bool:
        return self.get(content_hash) is not None

    def verify(self, content_hash: str) -> bool:
        key = _check_hash(content_hash)
        raw = self._objects.get(key)
        if raw is None:
            return False
        return hashlib.sha256(raw).hexdigest() == key

    def quarantine(self, content_hash: str, *, reason: str) -> None:
        key = _check_hash(content_hash)
        if not isinstance(reason, str) or not reason.strip():
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "quarantine requires a reason"
            )
        if len(reason) > 200 or "\n" in reason or "\r" in reason:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "quarantine reason not single-line"
            )
        self._quarantined[key] = reason.strip()

    def quarantined(self, content_hash: str) -> bool:
        return _check_hash(content_hash) in self._quarantined

    def quarantine_reason(self, content_hash: str) -> str | None:
        return self._quarantined.get(_check_hash(content_hash))

    def delete_after_retention_policy(
        self, content_hash: str, *, policy: object
    ) -> bool:
        """Operator-gated blob removal (never automatic).

        Requires a ``RetentionPolicy``-shaped object with
        ``allow_blob_deletion is True``. Anything else fails closed.
        The store tombstones the index first; this only removes bytes.
        """
        key = _check_hash(content_hash)
        if not getattr(policy, "allow_blob_deletion", False) is True:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED",
                "blob deletion requires an explicit deletion policy",
            )
        if key not in self._objects:
            return False
        del self._objects[key]
        return True

    def list_hashes(self) -> tuple[str, ...]:
        return tuple(sorted(self._objects))

    def corrupt(self, content_hash: str, *, flip_last_byte: bool = True) -> None:
        """Test-only corruption injector (fault-injection, not an API)."""
        key = _check_hash(content_hash)
        raw = self._objects.get(key)
        if raw is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "cannot corrupt absent object"
            )
        mutated = bytearray(raw)
        if not mutated:
            mutated.append(0xFF if flip_last_byte else 0x00)
        else:
            mutated[-1] ^= 0xFF
        self._objects[key] = bytes(mutated)

    def stats(self) -> BlobStats:
        total = sum(len(raw) for raw in self._objects.values())
        return BlobStats(
            objects=len(self._objects),
            bytes_total=total,
            quarantined=len(self._quarantined),
        )


class FilesystemCASBlobStore:
    """Deterministic filesystem CAS test implementation.

    Confined to ``root`` (tests pass a controlled temp dir). Layout::

        <root>/blobs/sha256/<content_hash>

    Writes: create temp file in the same directory, fsync, atomic
    ``os.replace`` with ``O_EXCL``-style guard (link-then-check), then
    read-back verification. Existing objects are never overwritten:
    a same-key/differing-bytes collision fails closed.
    """

    def __init__(self, root: str) -> None:
        if not isinstance(root, str) or not root:
            raise TypeError("filesystem CAS requires a root directory")
        self._root = root
        self._quarantined: dict[str, str] = {}
        prefix_dir = self._prefix_dir()
        os.makedirs(prefix_dir, exist_ok=True)

    def _prefix_dir(self) -> str:
        return os.path.join(self._root, "blobs", "sha256")

    def _path_for(self, content_hash: str) -> str:
        key = _check_hash(content_hash)
        digest = key.split("/")[-1]
        base = self._prefix_dir()
        # Digest is [0-9a-f]{64} by validation: no traversal possible.
        return os.path.join(base, digest)

    def put_if_absent(
        self, content_hash: str, payload: bytes, *, enforce_identity: bool = True
    ) -> bool:
        key = _check_hash(content_hash)
        raw = _check_bytes(payload)
        if enforce_identity and hashlib.sha256(raw).hexdigest() != key:
            raise ev.EvidenceError(
                "EVIDENCE_HASH_MISMATCH",
                "payload bytes do not match claimed content hash",
            )
        path = self._path_for(key)
        if os.path.exists(path):
            with open(path, "rb") as handle:
                existing = handle.read()
            if existing != raw:
                raise ev.EvidenceError(
                    "EVIDENCE_HASH_MISMATCH",
                    "same key with differing bytes refused",
                )
            return False
        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=directory, prefix=".tmp-", suffix=".blob"
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            # Atomic publish: O_EXCL-style guard — if a racing writer
            # published first, compare instead of overwriting.
            try:
                fd2 = os.open(
                    path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444
                )
            except FileExistsError:
                with open(path, "rb") as handle:
                    existing = handle.read()
                if existing != raw:
                    raise ev.EvidenceError(
                        "EVIDENCE_HASH_MISMATCH",
                        "same key with differing bytes refused",
                    )
                return False
            with os.fdopen(fd2, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        # Read-back verification before reporting durable.
        with open(path, "rb") as handle:
            stored = handle.read()
        if stored != raw:
            raise ev.EvidenceError(
                "EVIDENCE_HASH_MISMATCH", "read-back verification failed"
            )
        if enforce_identity and hashlib.sha256(stored).hexdigest() != key:
            raise ev.EvidenceError(
                "EVIDENCE_HASH_MISMATCH", "read-back verification failed"
            )
        try:
            os.chmod(path, 0o444)
        except OSError:
            pass
        return True

    def get(self, content_hash: str) -> bytes | None:
        path = self._path_for(_check_hash(content_hash))
        try:
            with open(path, "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            return None

    def exists(self, content_hash: str) -> bool:
        return os.path.exists(self._path_for(_check_hash(content_hash)))

    def verify(self, content_hash: str) -> bool:
        key = _check_hash(content_hash)
        raw = self.get(key)
        if raw is None:
            return False
        return hashlib.sha256(raw).hexdigest() == key

    def quarantine(self, content_hash: str, *, reason: str) -> None:
        key = _check_hash(content_hash)
        if not isinstance(reason, str) or not reason.strip():
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "quarantine requires a reason"
            )
        if len(reason) > 200 or "\n" in reason or "\r" in reason:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "quarantine reason not single-line"
            )
        self._quarantined[key] = reason.strip()

    def quarantined(self, content_hash: str) -> bool:
        return _check_hash(content_hash) in self._quarantined

    def delete_after_retention_policy(
        self, content_hash: str, *, policy: object
    ) -> bool:
        """Operator-gated blob removal (never automatic)."""
        key = _check_hash(content_hash)
        if not getattr(policy, "allow_blob_deletion", False) is True:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED",
                "blob deletion requires an explicit deletion policy",
            )
        path = self._path_for(key)
        try:
            os.unlink(path)
        except FileNotFoundError:
            return False
        return True

    def list_hashes(self) -> tuple[str, ...]:
        base = self._prefix_dir()
        try:
            names = os.listdir(base)
        except FileNotFoundError:
            return ()
        out = [
            name
            for name in names
            if _SHA256_RE.match(name) and not name.startswith(".tmp-")
        ]
        return tuple(sorted(out))

    def stats(self) -> BlobStats:
        total = 0
        for digest in self.list_hashes():
            try:
                total += os.path.getsize(os.path.join(self._prefix_dir(), digest))
            except OSError:
                continue
        return BlobStats(
            objects=len(self.list_hashes()),
            bytes_total=total,
            quarantined=len(self._quarantined),
        )
