"""Deterministic read-only Artifact Retrieval & Integrity Audit (Phase 4E).

Read-only query layer over the immutable Phase 4D
:class:`ArtifactStore`::

    ArtifactStore
        |
        +--> retrieve by artifact_id / content_hash (store passthrough)
        +--> retrieve by test_plan_id / hypothesis_id / match_id /
        |    snapshot_hash / artifact_type (binding filters)
        +--> deterministic provenance audit (PASS / FAIL / INCONCLUSIVE)
        +--> full read-only integrity sweep (structured report)
        v
    read-only audit/query results

STRICTLY READ-ONLY with respect to stored artifacts. This module
never generates, mutates, deletes, replaces, executes, or
reclassifies artifacts. It never calls an LLM, never touches the
network, never spawns subprocesses, never invokes verifiers or
executors, never creates findings, never assigns verdicts, and
never decides scope. Artifact content remains inert bytes.

- Retrieval returns only artifacts actually stored, in
  ``artifact_id`` order, duplicate-free. Corruption encountered
  during retrieval propagates (fail closed) — it is surfaced by
  the sweep, never silently skipped.
- The provenance audit is a structural integrity check only:
  PASS means "bindings are internally consistent", FAIL means "a
  structural property is violated", INCONCLUSIVE means "the
  stored data genuinely cannot establish the property" (e.g. an
  optional binding is absent). No vulnerability, scope, or
  execution semantics exist here.
- The integrity sweep enumerates the index and the records
  directory deterministically, invokes the store's own integrity
  checks per record, reports corruption/orphans explicitly, and
  never repairs, deletes, rewrites, or reattaches anything.
"""

from __future__ import annotations

import json as _json
import re
from dataclasses import dataclass, field
from typing import Literal

from ai.knowledge.artifact_store import (
    ArtifactCorruptError,
    ArtifactStore,
    ArtifactStoreError,
    StoredArtifact,
)
from ai.schemas.artifact import (
    SCHEMA_VERSION as ARTIFACT_SCHEMA_VERSION,
    artifact_id_for,
    content_hash_for_bytes,
)

AuditOutcome = Literal["PASS", "FAIL", "INCONCLUSIVE"]

_ALLOWED_TYPES = frozenset(
    {"nuclei_template", "xss_payload", "http_request_spec"}
)

_ART_ID_RE = re.compile(r"^art-[0-9a-f]{16}$")
_TP_ID_RE = re.compile(r"^tp-[0-9a-f]{16}$")
_HYP_ID_RE = re.compile(r"^hyp-[0-9a-f]{16}$")
_TM_ID_RE = re.compile(r"^tm-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RECORD_FILE_RE = re.compile(r"^[0-9a-f]{64}\.json$")


class ArtifactRetrievalError(ValueError):
    """Base error for deterministic retrieval misuse/failure."""


# ------------------------------------------------------------------
# Input validation
# ------------------------------------------------------------------


def _require_binding(value: object, pattern: re.Pattern[str], name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a string, not {type(value).__name__}; "
            "raw non-string bindings are never coerced"
        )
    if not pattern.match(value):
        raise ArtifactRetrievalError(
            f"malformed {name} rejected: {value!r}"
        )
    return value


def _require_artifact_type(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(
            "artifact_type must be a string, not "
            f"{type(value).__name__}"
        )
    if value not in _ALLOWED_TYPES:
        raise ArtifactRetrievalError(
            f"unknown artifact_type rejected: {value!r}"
        )
    return value


def _require_store(store: object) -> ArtifactStore:
    if not isinstance(store, ArtifactStore):
        raise TypeError(
            "retrieval operates only on ArtifactStore, not "
            f"{type(store).__name__}; raw paths or dicts are never "
            "accepted"
        )
    return store


# ------------------------------------------------------------------
# Retrieval
# ------------------------------------------------------------------


def _matches(
    stored: StoredArtifact,
    *,
    test_plan_id: str | None,
    hypothesis_id: str | None,
    match_id: str | None,
    snapshot_hash: str | None,
    artifact_type: str | None,
) -> bool:
    reference = stored.reference
    if test_plan_id is not None and reference.test_plan_id != test_plan_id:
        return False
    if hypothesis_id is not None and reference.hypothesis_id != hypothesis_id:
        return False
    if match_id is not None and reference.match_id != match_id:
        return False
    if snapshot_hash is not None and reference.snapshot_hash != snapshot_hash:
        return False
    if artifact_type is not None and reference.artifact_type != artifact_type:
        return False
    return True


def get_by_binding(
    store: object,
    *,
    test_plan_id: object = None,
    hypothesis_id: object = None,
    match_id: object = None,
    snapshot_hash: object = None,
    artifact_type: object = None,
) -> tuple[StoredArtifact, ...]:
    """Retrieve stored artifacts matching all given bindings.

    Every supplied binding is strictly validated (malformed
    values raise); at least one filter is required. Results are
    the exact stored objects (reference + bytes), ordered by
    ``artifact_id``, duplicate-free. Nothing is synthesized,
    inferred, or mutated; corruption propagates fail-closed via
    the store's own integrity checks.
    """

    resolved = _require_store(store)
    filters: dict[str, str | None] = {
        "test_plan_id": None,
        "hypothesis_id": None,
        "match_id": None,
        "snapshot_hash": None,
        "artifact_type": None,
    }
    if test_plan_id is not None:
        filters["test_plan_id"] = _require_binding(
            test_plan_id, _TP_ID_RE, "test_plan_id"
        )
    if hypothesis_id is not None:
        filters["hypothesis_id"] = _require_binding(
            hypothesis_id, _HYP_ID_RE, "hypothesis_id"
        )
    if match_id is not None:
        filters["match_id"] = _require_binding(
            match_id, _TM_ID_RE, "match_id"
        )
    if snapshot_hash is not None:
        filters["snapshot_hash"] = _require_binding(
            snapshot_hash, _SHA256_RE, "snapshot_hash"
        )
    if artifact_type is not None:
        filters["artifact_type"] = _require_artifact_type(artifact_type)
    if all(value is None for value in filters.values()):
        raise ArtifactRetrievalError(
            "get_by_binding requires at least one binding filter; "
            "unfiltered enumeration is not exposed"
        )
    results = [
        stored
        for stored in resolved.list()
        if _matches(
            stored,
            test_plan_id=filters["test_plan_id"],
            hypothesis_id=filters["hypothesis_id"],
            match_id=filters["match_id"],
            snapshot_hash=filters["snapshot_hash"],
            artifact_type=filters["artifact_type"],
        )
    ]
    results.sort(key=lambda item: item.reference.artifact_id)
    return tuple(results)


def get_by_test_plan_id(
    store: object, test_plan_id: object
) -> tuple[StoredArtifact, ...]:
    """All stored artifacts bound to one TestPlan (id-ordered)."""

    return get_by_binding(
        store,
        test_plan_id=_require_binding(test_plan_id, _TP_ID_RE, "test_plan_id"),
    )


def get_by_hypothesis_id(
    store: object, hypothesis_id: object
) -> tuple[StoredArtifact, ...]:
    """All stored artifacts carrying one hypothesis binding."""

    return get_by_binding(
        store,
        hypothesis_id=_require_binding(
            hypothesis_id, _HYP_ID_RE, "hypothesis_id"
        ),
    )


def get_by_match_id(
    store: object, match_id: object
) -> tuple[StoredArtifact, ...]:
    """All stored artifacts carrying one match binding."""

    return get_by_binding(
        store,
        match_id=_require_binding(match_id, _TM_ID_RE, "match_id"),
    )


def get_by_snapshot_hash(
    store: object, snapshot_hash: object
) -> tuple[StoredArtifact, ...]:
    """All stored artifacts carrying one snapshot binding."""

    return get_by_binding(
        store,
        snapshot_hash=_require_binding(
            snapshot_hash, _SHA256_RE, "snapshot_hash"
        ),
    )


# ------------------------------------------------------------------
# Provenance audit
# ------------------------------------------------------------------


@dataclass(frozen=True)
class ProvenanceCheck:
    """One structural provenance property and its verdict."""

    name: str
    outcome: AuditOutcome
    detail: str


@dataclass(frozen=True)
class ProvenanceAudit:
    """Structural provenance audit of one stored artifact.

    PASS: every checkable binding is internally consistent.
    FAIL: at least one structural property is violated.
    INCONCLUSIVE: no violation, but an optional binding is
    absent so presence cannot be established. Integrity-only:
    carries no vulnerability, scope, or execution semantics.
    """

    artifact_id: str
    outcome: AuditOutcome
    checks: tuple[ProvenanceCheck, ...] = field(default_factory=tuple)


def audit_provenance(stored: object) -> ProvenanceAudit:
    """Audit the structural provenance of one stored artifact.

    Recomputes content hash and artifact identity from the stored
    bytes, re-validates every binding shape, schema version, and
    validation state. Pure function of the stored object; reads
    nothing else and writes nothing.
    """

    if not isinstance(stored, StoredArtifact):
        raise TypeError(
            "audit_provenance accepts only StoredArtifact, not "
            f"{type(stored).__name__}; raw dicts are never coerced"
        )
    reference = stored.reference
    content = bytes(stored.content)
    checks: list[ProvenanceCheck] = []

    checks.append(
        ProvenanceCheck(
            name="content_hash",
            outcome=(
                "PASS"
                if reference.content_hash == content_hash_for_bytes(content)
                else "FAIL"
            ),
            detail=(
                "content_hash matches SHA-256 of stored bytes"
                if reference.content_hash
                == content_hash_for_bytes(content)
                else "content_hash does not match stored bytes"
            ),
        )
    )
    try:
        expected_id = artifact_id_for(
            artifact_type=reference.artifact_type,
            test_plan_id=reference.test_plan_id,
            content_hash=reference.content_hash,
            schema_version=reference.artifact_schema_version,
        )
    except Exception:  # noqa: BLE001 - any basis failure is FAIL
        expected_id = None
    checks.append(
        ProvenanceCheck(
            name="artifact_id",
            outcome=(
                "PASS" if reference.artifact_id == expected_id else "FAIL"
            ),
            detail=(
                "artifact_id matches the deterministic basis"
                if reference.artifact_id == expected_id
                else "artifact_id does not match the deterministic basis"
            ),
        )
    )
    checks.append(
        ProvenanceCheck(
            name="artifact_type",
            outcome=(
                "PASS"
                if reference.artifact_type in _ALLOWED_TYPES
                else "FAIL"
            ),
            detail=(
                f"artifact_type {reference.artifact_type!r} is in the "
                "closed vocabulary"
                if reference.artifact_type in _ALLOWED_TYPES
                else f"artifact_type {reference.artifact_type!r} is "
                "outside the closed vocabulary"
            ),
        )
    )
    checks.append(
        ProvenanceCheck(
            name="test_plan_id",
            outcome=(
                "PASS"
                if _TP_ID_RE.match(reference.test_plan_id or "")
                else "FAIL"
            ),
            detail="test_plan_id is well-formed",
        )
    )
    for name, value, pattern in (
        ("hypothesis_id", reference.hypothesis_id, _HYP_ID_RE),
        ("match_id", reference.match_id, _TM_ID_RE),
        ("snapshot_hash", reference.snapshot_hash, _SHA256_RE),
    ):
        if value is None:
            checks.append(
                ProvenanceCheck(
                    name=name,
                    outcome="INCONCLUSIVE",
                    detail=f"{name} is absent; presence cannot be "
                    "established from stored data",
                )
            )
        elif pattern.match(value):
            checks.append(
                ProvenanceCheck(
                    name=name,
                    outcome="PASS",
                    detail=f"{name} is well-formed",
                )
            )
        else:
            checks.append(
                ProvenanceCheck(
                    name=name,
                    outcome="FAIL",
                    detail=f"{name} is malformed: {value!r}",
                )
            )
    checks.append(
        ProvenanceCheck(
            name="artifact_schema_version",
            outcome=(
                "PASS"
                if reference.artifact_schema_version
                == ARTIFACT_SCHEMA_VERSION
                else "FAIL"
            ),
            detail=(
                "artifact_schema_version matches artifact/v1"
                if reference.artifact_schema_version
                == ARTIFACT_SCHEMA_VERSION
                else "artifact_schema_version mismatch"
            ),
        )
    )
    checks.append(
        ProvenanceCheck(
            name="validation_state",
            outcome="PASS" if reference.validation_state == "VALID" else "FAIL",
            detail=(
                "validation_state is VALID"
                if reference.validation_state == "VALID"
                else f"validation_state is {reference.validation_state!r}, "
                "not VALID"
            ),
        )
    )
    outcomes = [check.outcome for check in checks]
    overall: AuditOutcome
    if "FAIL" in outcomes:
        overall = "FAIL"
    elif "INCONCLUSIVE" in outcomes:
        overall = "INCONCLUSIVE"
    else:
        overall = "PASS"
    return ProvenanceAudit(
        artifact_id=reference.artifact_id,
        outcome=overall,
        checks=tuple(checks),
    )


# ------------------------------------------------------------------
# Integrity sweep
# ------------------------------------------------------------------


@dataclass(frozen=True)
class IntegrityFailure:
    """One explicitly surfaced integrity problem (never repaired)."""

    kind: str
    subject: str
    detail: str


@dataclass(frozen=True)
class IntegritySweepReport:
    """Read-only integrity sweep over index + records directory.

    ``total_records`` counts index entries examined plus orphan
    files found. ``valid_records`` counts entries passing the
    store's own integrity checks. ``corrupt_records`` counts
    entries/files failing validation. ``orphan_records`` counts
    well-formed but unindexed record files. ``failures`` carries
    every problem explicitly, ordered by (kind, subject).
    Informational only: nothing is repaired, deleted, rewritten,
    or reattached.
    """

    total_records: int
    valid_records: int
    corrupt_records: int
    orphan_records: int
    failures: tuple[IntegrityFailure, ...] = field(default_factory=tuple)


def _sorted_index_ids(index: dict) -> list[str]:
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ArtifactCorruptError(
            "artifact-store index has no valid artifacts map"
        )
    return sorted(artifacts)


def _disk_record_hashes(store: ArtifactStore) -> list[str]:
    """Content hashes implied by on-disk record filenames, sorted.

    Only names directory entries; reads no file contents and
    trusts no file contents. Non-conforming names are reported
    separately as unexpected files.
    """

    try:
        names = sorted(item.name for item in store.records_dir.iterdir())
    except OSError:
        return []
    return [
        name[:-5] for name in names if _RECORD_FILE_RE.match(name)
    ]


def _unexpected_files(store: ArtifactStore) -> list[str]:
    """Non-record names in the records directory, sorted.

    Includes leftover ``*.tmp`` files (crash leftovers or
    in-flight writes): they are reported explicitly rather than
    silently skipped, and never treated as records.
    """

    try:
        names = sorted(item.name for item in store.records_dir.iterdir())
    except OSError:
        return []
    return [name for name in names if not _RECORD_FILE_RE.match(name)]


def verify_all(store: object) -> IntegritySweepReport:
    """Run a read-only integrity sweep over one ArtifactStore.

    Deterministic: enumeration is sorted, failure ordering is
    (kind, subject), and no timestamps, PIDs, or filesystem
    ordering leak into the result. Pure reads — the store is
    never written, repaired, or pruned.
    """

    resolved = _require_store(store)
    failures: list[IntegrityFailure] = []
    valid = 0
    corrupt = 0
    orphans = 0

    try:
        if not resolved.index_path.exists():
            # Mirror the store: a missing index is an empty store,
            # not corruption. On-disk files (if any) are still
            # classified below.
            raw_index: dict = {"artifacts": {}, "version": 1}
        else:
            raw_index = _json.loads(
                resolved.index_path.read_text(encoding="utf-8")
            )
            if not isinstance(raw_index, dict):
                raise ArtifactCorruptError(
                    "artifact-store index must be a JSON object"
                )
        index_ids = _sorted_index_ids(raw_index)
        indexed_hashes = {
            str(raw_index["artifacts"][entry_id].get("content_hash"))
            for entry_id in index_ids
            if isinstance(raw_index["artifacts"][entry_id], dict)
        }
    except (OSError, ValueError, ArtifactStoreError) as exc:
        failures.append(
            IntegrityFailure(
                kind="index_error",
                subject="index.json",
                detail=f"index unreadable: {exc}",
            )
        )
        for content_hash in _disk_record_hashes(resolved):
            orphans += 1
            failures.append(
                IntegrityFailure(
                    kind="orphan_record",
                    subject=content_hash,
                    detail="record unreferenced: index unreadable, "
                    "reference status unknown; not reattached",
                )
            )
        for name in _unexpected_files(resolved):
            corrupt += 1
            failures.append(
                IntegrityFailure(
                    kind="unexpected_file",
                    subject=name,
                    detail="non-record file in records directory",
                )
            )
        failures.sort(key=lambda item: (item.kind, item.subject))
        corrupt = len(
            [item for item in failures if item.kind != "orphan_record"]
        )
        return IntegritySweepReport(
            total_records=corrupt + orphans,
            valid_records=0,
            corrupt_records=corrupt,
            orphan_records=orphans,
            failures=tuple(failures),
        )

    seen_hashes: dict[str, list[str]] = {}
    for entry_id in index_ids:
        entry = raw_index["artifacts"][entry_id]
        if isinstance(entry, dict) and isinstance(
            entry.get("content_hash"), str
        ):
            seen_hashes.setdefault(entry["content_hash"], []).append(entry_id)
    for content_hash in sorted(seen_hashes):
        if len(seen_hashes[content_hash]) > 1:
            for entry_id in seen_hashes[content_hash]:
                corrupt += 1
                failures.append(
                    IntegrityFailure(
                        kind="duplicate_binding",
                        subject=entry_id,
                        detail="content_hash "
                        f"{content_hash} is referenced by multiple "
                        "index entries: "
                        + ",".join(seen_hashes[content_hash]),
                    )
                )

    for entry_id in index_ids:
        try:
            resolved.get(entry_id)
        except ArtifactStoreError as exc:
            corrupt += 1
            failures.append(
                IntegrityFailure(
                    kind="entry_error",
                    subject=entry_id,
                    detail=str(exc),
                )
            )
        else:
            valid += 1

    indexed_set = set(indexed_hashes)
    for content_hash in _disk_record_hashes(resolved):
        if content_hash in indexed_set:
            continue
        try:
            resolved.get_by_content_hash(content_hash)
        except ArtifactStoreError as exc:
            message = str(exc)
            if "missing an index entry" in message:
                orphans += 1
                failures.append(
                    IntegrityFailure(
                        kind="orphan_record",
                        subject=content_hash,
                        detail="record exists on disk but is not "
                        "referenced by the index; not reattached",
                    )
                )
            else:
                corrupt += 1
                failures.append(
                    IntegrityFailure(
                        kind="record_error",
                        subject=content_hash,
                        detail=message,
                    )
                )
        else:
            orphans += 1
            failures.append(
                IntegrityFailure(
                    kind="orphan_record",
                    subject=content_hash,
                    detail="record exists on disk but is not "
                    "referenced by the index; not reattached",
                )
            )

    for name in _unexpected_files(resolved):
        corrupt += 1
        failures.append(
            IntegrityFailure(
                kind="unexpected_file",
                subject=name,
                detail="non-record file in records directory",
            )
        )

    failures.sort(key=lambda item: (item.kind, item.subject))
    # Recompute counts from the explicit failure list so the
    # arithmetic stays consistent even when one entry yields
    # multiple findings (e.g. duplicate bindings).
    corrupt = len(
        [item for item in failures if item.kind != "orphan_record"]
    )
    orphans = len(
        [item for item in failures if item.kind == "orphan_record"]
    )
    return IntegritySweepReport(
        total_records=valid + corrupt + orphans,
        valid_records=valid,
        corrupt_records=corrupt,
        orphan_records=orphans,
        failures=tuple(failures),
    )


__all__ = [
    "AuditOutcome",
    "ArtifactRetrievalError",
    "IntegrityFailure",
    "IntegritySweepReport",
    "ProvenanceAudit",
    "ProvenanceCheck",
    "audit_provenance",
    "get_by_binding",
    "get_by_hypothesis_id",
    "get_by_match_id",
    "get_by_snapshot_hash",
    "get_by_test_plan_id",
    "verify_all",
]
