"""Immutable content-addressed Artifact Store (Phase 4D).

Stores artifacts that have ALREADY passed Phase 4C deterministic
validation::

    VALID ArtifactReference + exact artifact bytes
                        |
                        v
    immutable, content-addressed, integrity-checked record

The store is STORAGE ONLY. It is NOT a generator, executor,
verifier, matcher, scope engine, finding store, LLM, collector,
scheduler, or database. It stores validated bytes and retrieves
them with full integrity revalidation. It never decides whether
a target is vulnerable, never decides scope, never executes
content, never produces evidence or findings, and never assigns
verdicts.

Identity model (Phase 4C semantics preserved exactly):

- ``content_hash``: SHA-256 over the exact artifact bytes. The
  authoritative content identity; record files are keyed by it.
- ``artifact_id``: ``art-`` + 16 hex deterministic alias of
  (artifact_type, test_plan_id, content_hash, schema_version).
  The index key; binds content to exactly one TestPlan.
- Same bytes + same reference converge (idempotent put). A
  one-byte difference yields a distinct content record. The same
  content under a contradictory identity/binding is REJECTED,
  never merged or overwritten.

Storage follows the ``PatternStore`` / ``KnowledgeStore``
conventions: file-backed JSON under a root directory, atomic
temp-file + rename writes (here with per-write unique temp names
plus flush + fsync), deterministic ordering, strict schemas with
``extra="forbid"``, and fail-closed integrity errors. No MongoDB,
no network, no LLM, no subprocess, no pickle.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from ai.researcher.artifact_validator import (
    HttpArtifactContent,
    validate_http_safety,
    validate_xss_payload,
)
from ai.researcher.nuclei_artifact_validator import (
    parse_template_content,
    validate_nuclei_safety,
)
from ai.schemas.artifact import (
    SCHEMA_VERSION as ARTIFACT_SCHEMA_VERSION,
    ArtifactReference,
    artifact_id_for,
    content_hash_for_bytes,
    max_bytes_for,
)

STORE_SCHEMA_VERSION = "artifact_store/v1"

_ALLOWED_TYPES = frozenset(
    {"nuclei_template", "xss_payload", "http_request_spec"}
)

_ART_ID_RE = re.compile(r"^art-[0-9a-f]{16}$")
_TP_ID_RE = re.compile(r"^tp-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_RECORD_ENVELOPE_KEYS = frozenset(
    {"reference", "content_b64", "content_hash", "schema_version"}
)


class ArtifactStoreError(ValueError):
    """Base error for deterministic, testable store failures."""


class ArtifactIdentityConflictError(ArtifactStoreError):
    """Same identity bound to contradictory content or bindings."""


class ArtifactNotFoundError(ArtifactStoreError):
    """A read targeted an unknown artifact identity."""


class ArtifactCorruptError(ArtifactStoreError):
    """Stored bytes fail integrity validation; never repaired."""


@dataclass(frozen=True)
class StoredArtifact:
    """One immutable stored artifact: reference + exact bytes.

    Data only. No filesystem paths, no file handles, no
    executors, no authority. The bytes are the exact validated
    content (never transformed); ``reference`` is the bound
    Phase 4C reference as stored.
    """

    reference: ArtifactReference
    content: bytes


@dataclass(frozen=True)
class PutResult:
    """Outcome of :meth:`ArtifactStore.put`."""

    stored: StoredArtifact
    created: bool


_TEMP_COUNTER = itertools.count()


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    """Atomic binary write: unique temp + flush + fsync + rename.

    A crash can leave at most an orphan temp file, never a
    half-written record visible to readers. The temp name is
    unique per write (pid + thread + counter), so concurrent
    writers never share — and unlink under — each other's temp
    file.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    unique = f"{os.getpid()}.{threading.get_ident()}.{next(_TEMP_COUNTER)}"
    temp_path = path.with_name(f"{path.name}.{unique}.tmp")
    with open(temp_path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def _write_json_atomic(path: Path, payload: dict) -> None:
    """Atomic JSON write with deterministic key ordering."""

    _write_bytes_atomic(
        path,
        (
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    )


class ArtifactStore:
    """File-backed immutable store for validated artifacts.

    Layout under ``root_dir`` (default ``ai_data/artifacts``)::

        index.json
        records/<content_hash>.json

    Record filenames derive ONLY from regex-validated
    ``content_hash`` values (``^[0-9a-f]{64}$``); index keys are
    ONLY regex-validated ``artifact_id`` values. No artifact field
    (type, plan, provenance, metadata, …) ever influences a path.
    """

    def __init__(self, root_dir: str | Path = "ai_data/artifacts") -> None:
        self.root_dir = Path(root_dir)
        self.records_dir = self.root_dir / "records"
        self.index_path = self.root_dir / "index.json"
        # Instance-level mutex for the index read-modify-write
        # cycle. Record files are content-addressed and written
        # atomically, so they are safe regardless; the lock keeps
        # concurrent puts from silently dropping each other's index
        # entries. Cross-process writers are out of scope.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Paths and validation helpers
    # ------------------------------------------------------------------

    def _record_path(self, content_hash: str) -> Path:
        if not _SHA256_RE.match(content_hash or ""):
            raise ArtifactStoreError(
                "invalid content_hash for storage path: "
                f"{content_hash!r}"
            )
        return self.records_dir / f"{content_hash}.json"

    @staticmethod
    def _check_artifact_id(artifact_id: str) -> None:
        if not _ART_ID_RE.match(artifact_id or ""):
            raise ArtifactStoreError(
                f"malformed artifact_id rejected: {artifact_id!r}"
            )

    @staticmethod
    def _check_content_hash(content_hash: str) -> None:
        if not _SHA256_RE.match(content_hash or ""):
            raise ArtifactStoreError(
                f"malformed content_hash rejected: {content_hash!r}"
            )

    # ------------------------------------------------------------------
    # Reference / content verification (existing validators only)
    # ------------------------------------------------------------------

    def _verify_reference_and_content(
        self, reference: ArtifactReference, content: bytes
    ) -> ArtifactReference:
        """Re-validate identity, bindings, size, and contract safety.

        Uses only the Phase 4C deterministic validators; introduces
        no new Nuclei/XSS/HTTP semantics. The specificity gate is
        NOT re-run here (it needs caller fixtures and was already
        proven when the VALID reference was minted); structural
        contract + safety gates are re-checked so mutated bytes can
        never enter the store as VALID.
        """

        if not isinstance(reference, ArtifactReference):
            raise TypeError(
                "ArtifactStore.put accepts only ArtifactReference, "
                f"not {type(reference).__name__}"
            )
        if not isinstance(content, (bytes, bytearray)):
            raise TypeError(
                "artifact content must be bytes, not "
                f"{type(content).__name__}"
            )
        raw = bytes(content)

        if reference.artifact_type not in _ALLOWED_TYPES:
            raise ArtifactStoreError(
                f"unknown artifact_type rejected: "
                f"{reference.artifact_type!r}"
            )
        if reference.validation_state != "VALID":
            raise ArtifactStoreError(
                f"only VALID artifacts are stored; got "
                f"{reference.validation_state!r} (UNVALIDATED is never "
                "promoted, REJECTED is never reclassified)"
            )
        if not _TP_ID_RE.match(reference.test_plan_id or ""):
            raise ArtifactStoreError(
                "reference carries an invalid test_plan_id"
            )
        limit = max_bytes_for(reference.artifact_type)
        if len(raw) > limit:
            raise ArtifactStoreError(
                f"artifact content exceeds {limit} bytes for "
                f"{reference.artifact_type!r}"
            )
        digest = content_hash_for_bytes(raw)
        if reference.content_hash != digest:
            raise ArtifactStoreError(
                "reference content_hash does not match the supplied "
                "artifact bytes"
            )
        expected_id = artifact_id_for(
            artifact_type=reference.artifact_type,
            test_plan_id=reference.test_plan_id,
            content_hash=reference.content_hash,
            schema_version=reference.artifact_schema_version,
        )
        if reference.artifact_id != expected_id:
            raise ArtifactStoreError(
                "reference artifact_id does not match the "
                "deterministic basis"
            )
        # Genuine-instance check: re-parse through the contract so a
        # facsimile built from raw mappings cannot slip through.
        try:
            reverified = ArtifactReference.model_validate(
                reference.model_dump(mode="json")
            )
        except ValidationError as exc:
            raise ArtifactStoreError(
                f"reference write validation failed: {exc}"
            ) from exc
        if reverified != reference:
            raise ArtifactStoreError(
                "reference is not stable under revalidation"
            )

        safety_errors: list[str] = []
        if reference.artifact_type == "nuclei_template":
            try:
                template = parse_template_content(raw)
            except (ValueError, TypeError) as exc:
                raise ArtifactStoreError(
                    f"nuclei content fails contract parsing: {exc}"
                ) from exc
            safety_errors.extend(validate_nuclei_safety(template))
        elif reference.artifact_type == "http_request_spec":
            try:
                text = raw.decode("utf-8")
                payload = json.loads(text)
            except (UnicodeDecodeError, ValueError) as exc:
                raise ArtifactStoreError(
                    f"http content fails contract parsing: {exc}"
                ) from exc
            if not isinstance(payload, dict):
                raise ArtifactStoreError(
                    "http content must be a JSON object"
                )
            try:
                http_content = HttpArtifactContent.model_validate(payload)
            except ValidationError as exc:
                raise ArtifactStoreError(
                    f"http content fails contract validation: {exc}"
                ) from exc
            safety_errors.extend(validate_http_safety(http_content))
        else:  # xss_payload: inert-bytes gate from Phase 4C.
            safety_errors.extend(validate_xss_payload(raw))
        if safety_errors:
            raise ArtifactStoreError(
                "artifact content fails deterministic safety "
                f"revalidation: {safety_errors[0]}"
            )
        return reverified

    # ------------------------------------------------------------------
    # Index handling
    # ------------------------------------------------------------------

    def _load_index(self) -> dict:
        if not self.index_path.exists():
            return {"artifacts": {}, "version": 1}
        try:
            index = json.loads(
                self.index_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise ArtifactCorruptError(
                "artifact-store index is not valid JSON: "
                f"{self.index_path}"
            ) from exc
        if not isinstance(index, dict):
            raise ArtifactCorruptError(
                "artifact-store index must be a JSON object"
            )
        artifacts = index.get("artifacts")
        if not isinstance(artifacts, dict):
            raise ArtifactCorruptError(
                "artifact-store index has no valid artifacts map"
            )
        return index

    def _save_index(self, index: dict) -> None:
        artifacts = index.get("artifacts", {})
        ordered = {key: artifacts[key] for key in sorted(artifacts)}
        _write_json_atomic(
            self.index_path,
            {"artifacts": ordered, "version": 1},
        )

    @staticmethod
    def _check_index_entry(artifact_id: str, entry: object) -> dict:
        if not isinstance(entry, dict):
            raise ArtifactCorruptError(
                "artifact-store index entry must be a JSON object: "
                f"{artifact_id}"
            )
        for field in (
            "artifact_type",
            "content_hash",
            "test_plan_id",
            "path",
        ):
            if not isinstance(entry.get(field), str):
                raise ArtifactCorruptError(
                    f"artifact-store index entry for {artifact_id} "
                    f"has an invalid {field!r}"
                )
        if entry["artifact_type"] not in _ALLOWED_TYPES:
            raise ArtifactCorruptError(
                f"artifact-store index entry for {artifact_id} has "
                f"an unknown artifact_type: "
                f"{entry['artifact_type']!r}"
            )
        if not _SHA256_RE.match(entry["content_hash"]):
            raise ArtifactCorruptError(
                f"artifact-store index entry for {artifact_id} has "
                "an invalid content_hash"
            )
        if not _TP_ID_RE.match(entry["test_plan_id"]):
            raise ArtifactCorruptError(
                f"artifact-store index entry for {artifact_id} has "
                "an invalid test_plan_id"
            )
        expected_path = f"records/{entry['content_hash']}.json"
        if entry["path"] != expected_path:
            raise ArtifactCorruptError(
                "artifact-store index path does not match record: "
                f"{artifact_id}"
            )
        return entry

    # ------------------------------------------------------------------
    # Record handling
    # ------------------------------------------------------------------

    def _record_payload(
        self, reference: ArtifactReference, content: bytes
    ) -> dict:
        return {
            "content_b64": base64.b64encode(bytes(content)).decode("ascii"),
            "content_hash": reference.content_hash,
            "reference": reference.model_dump(mode="json"),
            "schema_version": STORE_SCHEMA_VERSION,
        }

    def _load_record(self, content_hash: str) -> StoredArtifact:
        """Load, validate, and integrity-check one record file.

        Fail closed on malformed JSON, unknown schema version,
        unknown artifact type, schema violations, hash mismatch,
        identity mismatch, oversized content, or safety-gate
        failure. Never repairs, never returns partial data, never
        executes content.
        """

        path = self._record_path(content_hash)
        if not path.exists():
            raise ArtifactCorruptError(
                "artifact-store index references a missing "
                f"record: {content_hash}"
            )
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ArtifactCorruptError(
                f"artifact record is not valid JSON: {path}"
            ) from exc
        if not isinstance(envelope, dict):
            raise ArtifactCorruptError(
                f"artifact record must be a JSON object: {path}"
            )
        if set(envelope.keys()) != _RECORD_ENVELOPE_KEYS:
            raise ArtifactCorruptError(
                f"artifact record envelope is malformed: {path}"
            )
        if envelope["schema_version"] != STORE_SCHEMA_VERSION:
            raise ArtifactCorruptError(
                "artifact record has unsupported schema_version "
                f"{envelope['schema_version']!r}: {path}"
            )
        if envelope["content_hash"] != content_hash:
            raise ArtifactCorruptError(
                "artifact record content_hash does not match "
                f"filename: {path}"
            )
        if not isinstance(envelope["content_b64"], str):
            raise ArtifactCorruptError(
                f"artifact record content is not a string: {path}"
            )
        try:
            raw = base64.b64decode(envelope["content_b64"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ArtifactCorruptError(
                f"artifact record content is not valid base64: {path}"
            ) from exc
        if content_hash_for_bytes(raw) != content_hash:
            raise ArtifactCorruptError(
                "artifact record content hash does not match "
                f"stored bytes: {path}"
            )
        if not isinstance(envelope["reference"], dict):
            raise ArtifactCorruptError(
                f"artifact record reference must be an object: {path}"
            )
        try:
            reference = ArtifactReference.model_validate(
                envelope["reference"]
            )
        except ValidationError as exc:
            raise ArtifactCorruptError(
                "artifact record fails contract validation: "
                f"{path}: {exc}"
            ) from exc
        if reference.content_hash != content_hash:
            raise ArtifactCorruptError(
                "artifact record reference hash does not match "
                f"filename: {path}"
            )
        expected_id = artifact_id_for(
            artifact_type=reference.artifact_type,
            test_plan_id=reference.test_plan_id,
            content_hash=reference.content_hash,
            schema_version=reference.artifact_schema_version,
        )
        if reference.artifact_id != expected_id:
            raise ArtifactCorruptError(
                f"artifact record identity is inconsistent: {path}"
            )
        if reference.artifact_schema_version != ARTIFACT_SCHEMA_VERSION:
            raise ArtifactCorruptError(
                f"artifact record schema_version mismatch: {path}"
            )
        if reference.validation_state != "VALID":
            raise ArtifactCorruptError(
                "artifact record carries a non-VALID validation "
                f"state ({reference.validation_state!r}): {path}"
            )
        # Deterministic safety re-check on read (existing gates
        # only; specificity was proven at VALID-mint time and needs
        # caller fixtures, so it is not re-run here).
        self._verify_reference_and_content(reference, raw)
        return StoredArtifact(reference=reference, content=raw)

    def _load_entry_stored(
        self, artifact_id: str, entry: dict
    ) -> StoredArtifact:
        stored = self._load_record(entry["content_hash"])
        if stored.reference.artifact_id != artifact_id:
            raise ArtifactCorruptError(
                "artifact-store index artifact_id does not match "
                f"record: {artifact_id}"
            )
        if stored.reference.artifact_type != entry["artifact_type"]:
            raise ArtifactCorruptError(
                "artifact-store index artifact_type does not match "
                f"record: {artifact_id}"
            )
        if stored.reference.test_plan_id != entry["test_plan_id"]:
            raise ArtifactCorruptError(
                "artifact-store index test_plan_id does not match "
                f"record: {artifact_id}"
            )
        return stored

    # ------------------------------------------------------------------
    # Public write API
    # ------------------------------------------------------------------

    def put(
        self, reference: object, content: object
    ) -> PutResult:
        """Persist one VALID artifact idempotently.

        The exact same (reference, bytes) written twice yields one
        record (``created=False`` on the repeat). A record file is
        written atomically before the index; concurrent identical
        writers converge on the single identity-bound record.
        Conflicts fail closed:

        - same ``artifact_id`` bound to different
          content/hash/bindings →
          :class:`ArtifactIdentityConflictError`;
        - same ``content_hash`` with a contradictory artifact
          identity (different ``artifact_id``, i.e. a different
          TestPlan/type/version basis) →
          :class:`ArtifactIdentityConflictError`.

        Stored content is never overwritten and never deleted.
        """

        if not isinstance(content, (bytes, bytearray)):
            raise TypeError(
                "ArtifactStore.put accepts only bytes content, "
                f"not {type(content).__name__}"
            )
        verified = self._verify_reference_and_content(
            reference, bytes(content)  # type: ignore[arg-type]
        )
        raw = bytes(content)  # type: ignore[arg-type]
        with self._lock:
            return self._put_locked(verified, raw)

    def _put_locked(
        self, verified: ArtifactReference, raw: bytes
    ) -> PutResult:
        """Index-mutating half of :meth:`put` (caller holds lock)."""

        index = self._load_index()
        artifacts = index["artifacts"]

        entry = artifacts.get(verified.artifact_id)
        if entry is not None:
            checked = self._check_index_entry(
                verified.artifact_id, entry
            )
            if checked["content_hash"] != verified.content_hash:
                raise ArtifactIdentityConflictError(
                    f"artifact_id {verified.artifact_id} is already "
                    "bound to a different content_hash; stored "
                    "artifacts are immutable and never overwritten"
                )
            stored = self._load_entry_stored(
                verified.artifact_id, checked
            )
            if stored.reference != verified:
                raise ArtifactIdentityConflictError(
                    f"artifact_id {verified.artifact_id} is already "
                    "bound to different reference bindings; "
                    "contradictory identities are rejected"
                )
            if stored.content != raw:
                raise ArtifactIdentityConflictError(
                    f"artifact_id {verified.artifact_id} is already "
                    "bound to different content bytes; stored "
                    "content is immutable"
                )
            return PutResult(stored=stored, created=False)

        # Same content under a contradictory identity (e.g. a
        # different TestPlan): reject, never merge.
        record_path = self._record_path(verified.content_hash)
        if record_path.exists():
            stored = self._load_record(verified.content_hash)
            if stored.reference.artifact_id != verified.artifact_id:
                raise ArtifactIdentityConflictError(
                    "content_hash "
                    f"{verified.content_hash} is already bound to "
                    f"artifact {stored.reference.artifact_id!r}; the "
                    "same content cannot be re-bound to "
                    f"{verified.artifact_id!r}"
                )
            # Identical bytes re-validated to the identical
            # reference but missing from the index (e.g. a prior
            # crash between record write and index write): re-attach
            # the index entry deterministically instead of
            # erroring, then return the stored record.
            if stored.reference != verified or stored.content != raw:
                raise ArtifactIdentityConflictError(
                    "content_hash "
                    f"{verified.content_hash} collides with "
                    "different stored bindings; rejected"
                )
        else:
            _write_json_atomic(
                record_path,
                self._record_payload(verified, raw),
            )
            stored = self._load_record(verified.content_hash)

        artifacts[verified.artifact_id] = {
            "artifact_type": verified.artifact_type,
            "content_hash": verified.content_hash,
            "path": f"records/{verified.content_hash}.json",
            "test_plan_id": verified.test_plan_id,
        }
        self._save_index(index)
        return PutResult(
            stored=self._load_entry_stored(
                verified.artifact_id,
                artifacts[verified.artifact_id],
            ),
            created=True,
        )

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def get(self, artifact_id: str) -> StoredArtifact | None:
        """Return one stored artifact by id, or None when unknown.

        Malformed ids raise :class:`ArtifactStoreError`;
        corrupted records raise :class:`ArtifactCorruptError`.
        """

        self._check_artifact_id(artifact_id)
        index = self._load_index()
        entry = index["artifacts"].get(artifact_id)
        if entry is None:
            return None
        return self._load_entry_stored(
            artifact_id, self._check_index_entry(artifact_id, entry)
        )

    def get_by_content_hash(
        self, content_hash: str
    ) -> StoredArtifact | None:
        """Return the artifact stored under one content hash."""

        self._check_content_hash(content_hash)
        path = self.records_dir / f"{content_hash}.json"
        if not path.exists():
            index = self._load_index()
            for entry_id, entry in index["artifacts"].items():
                checked = self._check_index_entry(entry_id, entry)
                if checked["content_hash"] == content_hash:
                    return self._load_entry_stored(entry_id, checked)
            return None
        stored = self._load_record(content_hash)
        index = self._load_index()
        entry = index["artifacts"].get(stored.reference.artifact_id)
        if entry is None:
            raise ArtifactCorruptError(
                "artifact record is missing an index entry: "
                f"{stored.reference.artifact_id}"
            )
        return self._load_entry_stored(
            stored.reference.artifact_id,
            self._check_index_entry(
                stored.reference.artifact_id, entry
            ),
        )

    def exists(self, artifact_id: str) -> bool:
        """True iff ``artifact_id`` resolves to a valid record."""

        return self.get(artifact_id) is not None

    def list(
        self,
        *,
        artifact_type: str | None = None,
    ) -> list[StoredArtifact]:
        """List stored artifacts, ordered by ``artifact_id``.

        Only an artifact-type filter exists (closed vocabulary).
        There is deliberately no target, scope, severity, or
        score filtering: the store owns no target authority.
        """

        if artifact_type is not None and (
            artifact_type not in _ALLOWED_TYPES
        ):
            raise ArtifactStoreError(
                f"unknown artifact_type filter: {artifact_type!r}"
            )
        index = self._load_index()
        results: list[StoredArtifact] = []
        for artifact_id in sorted(index["artifacts"]):
            entry = self._check_index_entry(
                artifact_id, index["artifacts"][artifact_id]
            )
            if (
                artifact_type is not None
                and entry["artifact_type"] != artifact_type
            ):
                continue
            results.append(self._load_entry_stored(artifact_id, entry))
        return sorted(results, key=lambda item: item.reference.artifact_id)


__all__ = [
    "STORE_SCHEMA_VERSION",
    "ArtifactCorruptError",
    "ArtifactIdentityConflictError",
    "ArtifactNotFoundError",
    "ArtifactStore",
    "ArtifactStoreError",
    "PutResult",
    "StoredArtifact",
]
