"""Production-grade evidence store orchestration (Phase 5H).

Narrow, typed, observation-only persistence over frozen 5H-core:

- Canonical envelope: ``hashing.canonical_json(record.model_dump(
  mode="json"))`` UTF-8 bytes. No second hashing implementation.
- Blob key (server-derived): ``blobs/sha256/<content_hash>``.
  ``evidence_id`` is never the blob identity.
- Write order: validate → verify hashes → browser-bounds check →
  serialize → blob put-if-absent → read-back verify → conditional
  index insert → CAS mark-indexed → ledger CAS → audit.
- Reads: bytes → typed parse → recompute all three hashes → compare
  index claims vs. sealed bindings → serve, else quarantine as
  CORRUPT (any integrity failure quarantines; tombstone/quarantine
  refusals are re-raised without double-quarantine).
- No update/patch/mutate/rebind API exists anywhere in this module
  (structurally absent, test-asserted).
- Role capabilities (``EvidenceWriter`` / ``EvidenceReader`` /
  ``EvidenceVerifier`` / ``EvidenceSweeper`` / ``EvidenceOperator``)
  structurally restrict operations; they are not comments.
- Retention is hooks/state only (TTL eligibility, tombstone, GC
  eligibility). No automatic destructive deletion exists.

NO network, NO DNS, NO subprocess, NO MongoDB, NO browser, NO
Nuclei, NO LLM. Production Mongo remains B2-gated (see
``ai.evidence.index``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from ai.evidence import hashing
from ai.evidence.builder import verify_record
from ai.evidence.blob_store import blob_key_for
from ai.evidence.handoff import (
    assemble_handoff,
    bind_provenance,
    verify_provenance_for_handoff,
)
from ai.evidence.index import IndexDuplicateError, IndexEntry, IndexVersionConflict
from ai.evidence.orphan import validate_reindex
from ai.limits.ceilings import CEILINGS
from ai.schemas import evidence as ev

__all__ = [
    "BROWSER_CEILING_KEYS",
    "BROWSER_BOUND_SHORTNAMES",
    "check_browser_observation_bounds",
    "canonical_envelope_bytes",
    "parse_envelope",
    "StoreError",
    "PersistResult",
    "RetentionPolicy",
    "retention_eligible",
    "EvidenceStore",
    "EvidenceWriter",
    "EvidenceReader",
    "EvidenceVerifier",
    "EvidenceSweeper",
    "EvidenceOperator",
]

#: Central 5H ceiling keys backing the seven 5G browser dimensions
#: (single source of truth lives in ``ai.limits.ceilings``).
BROWSER_CEILING_KEYS: tuple[str, ...] = (
    "browser_dialog_events",
    "browser_frame_events",
    "browser_popup_events",
    "browser_console_entries",
    "browser_oracle_events",
    "browser_dom_observation_bytes",
    "browser_storage_keys",
)

#: Legacy 5G short names (alias view only, never authoritative).
BROWSER_BOUND_SHORTNAMES: tuple[str, ...] = (
    "dialog_events",
    "frame_events",
    "popup_events",
    "console_entries",
    "oracle_events",
    "dom_observation_bytes",
    "storage_keys",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class StoreError(ValueError):
    """Typed store failure (secret-free, single-line detail)."""


def _fail(code: str, detail: str = "") -> StoreError:
    return StoreError(f"{code}: {detail}"[:220] if detail else code)


def check_browser_observation_bounds(
    observation: ev.BrowserObservation,
) -> None:
    """Validate a NEW browser observation against central ceilings.

    Applies at persist/attach time only — reads of already-sealed
    records use schema validation alone, so tightening ceilings never
    retroactively invalidates existing evidence. Raises
    ``ev.EvidenceError`` on violation.
    """
    if not isinstance(observation, ev.BrowserObservation):
        raise TypeError(
            "browser bounds check accepts only BrowserObservation, "
            f"not {type(observation).__name__}"
        )
    limits = (
        ("dialog_marker_hashes", CEILINGS["browser_dialog_events"]),
        ("oracle_event_hashes", CEILINGS["browser_oracle_events"]),
        ("eval_marker_hashes", CEILINGS["browser_oracle_events"]),
    )
    for attr, ceiling in limits:
        count = len(getattr(observation, attr))
        if count > ceiling:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED",
                f"browser {attr} count {count} above ceiling {ceiling}",
            )


def canonical_envelope_bytes(record: ev.EvidenceRecord) -> bytes:
    """Canonical envelope bytes for a sealed record (frozen form)."""
    if not isinstance(record, ev.EvidenceRecord):
        raise TypeError(
            "envelope accepts only EvidenceRecord, "
            f"not {type(record).__name__}"
        )
    return hashing.canonical_json(
        record.model_dump(mode="json")
    ).encode("utf-8")


def parse_envelope(payload: bytes) -> ev.EvidenceRecord:
    """Parse + typed-validate envelope bytes (no hash check)."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError(
            "envelope parse accepts only bytes, "
            f"not {type(payload).__name__}"
        )
    try:
        return ev.EvidenceRecord.model_validate_json(bytes(payload))
    except Exception as exc:
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", "envelope bytes do not parse"
        ) from exc


@dataclass(frozen=True)
class PersistResult:
    """Deterministic outcome of one persist call (accounting only)."""

    evidence_id: str
    execution_id: str
    authorization_id: str
    content_hash: str
    blob_key: str
    lifecycle: str
    indexed: bool
    deduped: bool
    audit_gap: bool = False


@dataclass(frozen=True)
class RetentionPolicy:
    """Explicit operator retention policy (deletion requires one).

    Deletion is never automatic and never a mutation: tombstone first
    (index flag), blob removal only via ``allow_blob_deletion`` after
    a tombstone exists. Audit records of removal are permanent.
    """

    policy_id: str
    scope_program: str | None = None
    ttl_seconds: int | None = None
    allow_blob_deletion: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not self.policy_id.strip():
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "retention policy requires an id"
            )
        if len(self.policy_id) > 120:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "retention policy id over cap"
            )
        if self.ttl_seconds is not None and (
            not isinstance(self.ttl_seconds, int)
            or isinstance(self.ttl_seconds, bool)
            or self.ttl_seconds < 0
        ):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "retention ttl invalid"
            )


def retention_eligible(
    entry: IndexEntry, policy: RetentionPolicy, *, now_epoch: int
) -> bool:
    """TTL eligibility predicate (pure; no deletion performed)."""
    if not isinstance(entry, IndexEntry):
        raise TypeError(
            "retention eligibility accepts only IndexEntry, "
            f"not {type(entry).__name__}"
        )
    if not isinstance(policy, RetentionPolicy):
        raise TypeError(
            "retention eligibility accepts only RetentionPolicy, "
            f"not {type(policy).__name__}"
        )
    if policy.ttl_seconds is None:
        return False
    if policy.scope_program is not None and (
        entry.program_name != policy.scope_program
    ):
        return False
    try:
        indexed_at = int(entry.indexed_at) if entry.indexed_at else 0
    except (TypeError, ValueError):
        indexed_at = 0
    return (now_epoch - indexed_at) >= policy.ttl_seconds


class EvidenceStore:
    """Narrow immutable evidence persistence (5H production seam).

    Composes caller-supplied blob + index fakes with optional ledger
    and audit sinks. Crash-hook injection (``hooks`` mapping
    edge-name → callable) exists for deterministic crash-window
    tests; hooks raising abort the write at that edge (forward-only
    recovery via orphan re-index).
    """

    HOOK_EDGES: tuple[str, ...] = (
        "before_blob",
        "after_blob",
        "before_index",
        "after_index",
        "before_ledger",
        "after_ledger",
        "before_audit",
        "after_audit",
    )

    def __init__(
        self,
        blobs: Any,
        index: Any,
        *,
        ledger: Any = None,
        audit: Any = None,
        hooks: dict[str, Callable[[], None]] | None = None,
        audit_reads: bool = False,
    ) -> None:
        for name, dep in (("blobs", blobs), ("index", index)):
            if dep is None:
                raise TypeError(f"evidence store requires: {name}")
        for method in (
            "put_if_absent",
            "get",
            "exists",
            "quarantine",
            "list_hashes",
        ):
            if not callable(getattr(blobs, method, None)):
                raise TypeError(f"blob store missing capability: {method}")
        for method in (
            "insert_if_absent",
            "get_by_evidence_id",
            "get_by_execution_id",
            "mark_indexed",
            "quarantine",
            "tombstone",
        ):
            if not callable(getattr(index, method, None)):
                raise TypeError(f"index missing capability: {method}")
        self._blobs = blobs
        self._index = index
        self._ledger = ledger
        self._audit = audit
        self._audit_reads = bool(audit_reads)
        self._hooks = dict(hooks) if hooks else {}
        for name in self._hooks:
            if name not in self.HOOK_EDGES:
                raise ev.EvidenceError(
                    "EVIDENCE_MALFORMED", f"unknown hook edge: {name!r}"
                )

    # -- internals ---------------------------------------------------

    def _run_hook(self, edge: str) -> None:
        hook = self._hooks.get(edge)
        if hook is not None:
            hook()

    def _audit_append(self, record: object) -> None:
        if self._audit is None:
            raise ev.EvidenceError("EVIDENCE_MALFORMED", "audit sink absent")
        append = getattr(self._audit, "append", None)
        if append is None:
            # Plain list sink.
            if isinstance(self._audit, list):
                self._audit.append(record)
                return
            raise TypeError("audit sink is not appendable")
        append(record)

    def _annotate(
        self,
        *,
        record: ev.EvidenceRecord,
        transition: str,
        error_code: str | None = None,
        scope_note: str = "",
    ) -> None:
        from ai.audit.trail import AuditRecord

        hashes: dict[str, str] = {}
        if (
            record.bindings_hash
            and record.observations_hash
            and record.content_hash
        ):
            hashes = {
                "bindings_hash": record.bindings_hash,
                "observations_hash": record.observations_hash,
                "content_hash": record.content_hash,
            }
        self._audit_append(
            AuditRecord(
                seq=self._audit_seq(record),
                execution_id=record.execution_id,
                authorization_id=record.authorization_id,
                evidence_id=record.evidence_id,
                transition=transition,  # type: ignore[arg-type]
                actor="evidence-store/5H",
                program_name=record.program_name,
                host=record.target.host,
                scope_decision=(scope_note or "store")[:200],
                artifact_id=record.artifact_id,
                artifact_content_hash=record.artifact_content_hash,
                evidence_hashes=hashes,
                error_code=error_code,
            )
        )

    def _audit_seq(self, record: ev.EvidenceRecord) -> int:
        if isinstance(self._audit, list):
            return len(self._audit)
        records = getattr(self._audit, "records", None)
        if isinstance(records, list):
            return len(records)
        return 0

    @staticmethod
    def _index_entry_for(record: ev.EvidenceRecord) -> IndexEntry:
        assert record.bindings_hash and record.observations_hash
        assert record.content_hash
        return IndexEntry(
            evidence_id=record.evidence_id,
            execution_id=record.execution_id,
            authorization_id=record.authorization_id,
            execution_stage=record.execution_stage,
            execution_class=record.execution_class,
            content_hash=record.content_hash,
            bindings_hash=record.bindings_hash,
            observations_hash=record.observations_hash,
            artifact_id=record.artifact_id,
            program_name=record.program_name,
            lifecycle=(
                "INCOMPLETE" if record.lifecycle == "INCOMPLETE" else "SEALED"
            ),
            sealed_at=record.sealed_at,
        )

    # -- writes --------------------------------------------------------

    def persist_sealed(self, record: ev.EvidenceRecord) -> PersistResult:
        """Persist one sealed terminal (SEALED or INCOMPLETE).

        Safe order: validate → verify → bounds → serialize → blob →
        read-back → conditional index → CAS mark-indexed → ledger CAS
        → audit. BUILDING records are rejected. Idempotent: identical
        re-persist is a no-op success.
        """
        if not isinstance(record, ev.EvidenceRecord):
            raise TypeError(
                "persist accepts only EvidenceRecord, "
                f"not {type(record).__name__}"
            )
        if record.lifecycle not in ("SEALED", "INCOMPLETE"):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED",
                "only sealed terminals may persist; BUILDING refused",
            )
        # 1-2. typed validation is structural (pydantic); re-verify
        # frozen triple hashes (fail closed on any drift).
        verify_record(record)
        if (
            record.bindings_hash is None
            or record.observations_hash is None
            or record.content_hash is None
        ):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "seal hashes absent"
            )
        # 3. browser bounds for NEW records (reads stay schema-only).
        if record.browser is not None:
            check_browser_observation_bounds(record.browser)
        # 4. canonical envelope (frozen form).
        envelope = canonical_envelope_bytes(record)
        blob_key = blob_key_for(record.content_hash)
        # 5-6. blob put-if-absent + read-back verification.
        # Evidence identity is the frozen triple hash (verified above
        # and on every read); the blob layer stores the envelope under
        # the sealed content_hash without re-hashing it.
        self._run_hook("before_blob")
        self._blobs.put_if_absent(
            record.content_hash, envelope, enforce_identity=False
        )
        self._run_hook("after_blob")
        stored = self._blobs.get(record.content_hash)
        if stored is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "blob missing after put"
            )
        reparsed = parse_envelope(stored)
        verify_record(reparsed)
        if (
            reparsed.bindings_hash != record.bindings_hash
            or reparsed.observations_hash != record.observations_hash
            or reparsed.content_hash != record.content_hash
        ):
            self._quarantine_blob(
                record.content_hash, "read-back hash divergence"
            )
            raise ev.EvidenceError(
                "EVIDENCE_HASH_MISMATCH", "read-back divergence"
            )
        # 7. conditional index insert (dedupe-on-read the winner).
        self._run_hook("before_index")
        entry = self._index_entry_for(record)
        try:
            inserted = self._index.insert_if_absent(entry)
        except IndexDuplicateError:
            existing = self._index.get_by_evidence_id(record.evidence_id)
            if existing is not None and (
                existing.content_hash == record.content_hash
                and existing.bindings_hash == record.bindings_hash
                and existing.observations_hash
                == record.observations_hash
                and existing.execution_id == record.execution_id
            ):
                return self._persist_result(
                    record, blob_key, indexed=True, deduped=True
                )
            raise ev.EvidenceError(
                "EVIDENCE_BINDING_MISMATCH",
                "index identity collision with differing content",
            )
        current = self._index.get_by_evidence_id(record.evidence_id)
        assert current is not None
        if current.lifecycle in ("SEALED", "INCOMPLETE"):
            try:
                self._index.mark_indexed(
                    record.evidence_id,
                    expected_version=current.record_version,
                    indexed_at=record.sealed_at,
                )
            except IndexVersionConflict:
                pass  # Racing indexer won; dedupe-on-read applies.
        self._run_hook("after_index")
        # 8. ledger CAS (best-effort forward; absent ledger = skip).
        self._run_hook("before_ledger")
        self._ledger_cas(record)
        self._run_hook("after_ledger")
        # 9. audit (post-seal failure → AUDIT_GAP, never mutation).
        audit_gap = False
        self._run_hook("before_audit")
        try:
            self._annotate(
                record=record,
                transition="EVIDENCE_SEALED",
                scope_note="store:indexed",
            )
        except Exception:
            audit_gap = True
            try:
                from ai.audit.trail import gap_record

                self._audit_append(
                    gap_record(
                        seq=self._audit_seq(record),
                        execution_id=record.execution_id,
                        authorization_id=record.authorization_id,
                        missing_from="STORE_INDEXED",
                        actor="evidence-store/5H",
                    )
                )
            except Exception:
                pass
        self._run_hook("after_audit")
        return self._persist_result(
            record,
            blob_key,
            indexed=True,
            deduped=not inserted,
            audit_gap=audit_gap,
        )

    def _persist_result(
        self,
        record: ev.EvidenceRecord,
        blob_key: str,
        *,
        indexed: bool,
        deduped: bool,
        audit_gap: bool = False,
    ) -> PersistResult:
        return PersistResult(
            evidence_id=record.evidence_id,
            execution_id=record.execution_id,
            authorization_id=record.authorization_id,
            content_hash=record.content_hash or "",
            blob_key=blob_key,
            lifecycle=record.lifecycle,
            indexed=indexed,
            deduped=deduped,
            audit_gap=audit_gap,
        )

    def _ledger_cas(self, record: ev.EvidenceRecord) -> None:
        ledger = self._ledger
        if ledger is None:
            return
        get = getattr(ledger, "get", None)
        if not callable(get):
            return
        try:
            row = get(record.execution_id)
        except Exception:
            return
        if row is None or getattr(row, "lifecycle", None) != "STARTED":
            return
        terminal_at = record.sealed_at
        try:
            if record.lifecycle == "INCOMPLETE":
                ledger.mark_incomplete(
                    record.execution_id,
                    record.evidence_id,
                    terminal_at=terminal_at,
                )
            else:
                ledger.mark_sealed(
                    record.execution_id,
                    record.evidence_id,
                    terminal_at=terminal_at,
                )
        except Exception:
            # Ledger losers re-read; ambiguous commit is never
            # assumed — the index already holds the durable truth and
            # sweep reconciles forward.
            return

    def _quarantine_blob(self, content_hash: str, reason: str) -> None:
        try:
            self._blobs.quarantine(content_hash, reason=reason)
        except Exception:
            pass

    # -- reads (verify-everything) --------------------------------------

    def _load_verified(self, *, entry: IndexEntry) -> ev.EvidenceRecord:
        if entry.tombstoned:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "evidence tombstoned; not servable"
            )
        if entry.quarantined or entry.lifecycle == "QUARANTINED":
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "evidence quarantined; not servable"
            )
        raw = self._blobs.get(entry.content_hash)
        if raw is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "index points to missing bytes"
            )
        record = parse_envelope(raw)
        verify_record(record)
        if (
            record.bindings_hash != entry.bindings_hash
            or record.observations_hash != entry.observations_hash
            or record.content_hash != entry.content_hash
        ):
            raise ev.EvidenceError(
                "EVIDENCE_HASH_MISMATCH",
                "index claims diverge from sealed bytes",
            )
        if (
            record.evidence_id != entry.evidence_id
            or record.execution_id != entry.execution_id
            or record.authorization_id != entry.authorization_id
        ):
            raise ev.EvidenceError(
                "EVIDENCE_BINDING_MISMATCH",
                "index keys diverge from sealed bindings",
            )
        return record

    def _corrupt(
        self, *, entry: IndexEntry, record: ev.EvidenceRecord | None
    ) -> ev.EvidenceError:
        reason = "integrity mismatch on read"
        self._quarantine_blob(entry.content_hash, reason)
        try:
            current = self._index.get_by_evidence_id(entry.evidence_id)
            if current is not None and not current.quarantined:
                self._index.quarantine(
                    entry.evidence_id,
                    expected_version=current.record_version,
                    reason=reason,
                )
        except (IndexVersionConflict, ev.EvidenceError):
            pass
        if record is not None:
            try:
                self._annotate(
                    record=record,
                    transition="EXECUTION_TERMINAL",
                    error_code="EVIDENCE_HASH_MISMATCH",
                    scope_note="store:integrity-failure",
                )
            except Exception:
                pass
        return ev.EvidenceError("EVIDENCE_HASH_MISMATCH", reason)

    def get_by_evidence_id(self, evidence_id: str) -> ev.EvidenceRecord:
        from ai.evidence.index import _check_id as _check
        from ai.evidence.index import _EVIDENCE_ID_RE as _RE

        _check(_RE, evidence_id, "evidence_id")
        entry = self._index.get_by_evidence_id(evidence_id)
        if entry is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "evidence index entry missing"
            )
        try:
            record = self._load_verified(entry=entry)
        except ev.EvidenceError as exc:
            message = str(exc)
            if "tombstoned" in message or "quarantined; not servable" in message:
                raise
            raise self._corrupt(entry=entry, record=None)
        if self._audit_reads:
            try:
                self._annotate(
                    record=record,
                    transition="EXECUTION_TERMINAL",
                    scope_note="store:retrieved",
                )
            except Exception:
                pass
        return record

    def get_by_execution_id(self, execution_id: str) -> ev.EvidenceRecord:
        from ai.evidence.index import _check_id as _check
        from ai.evidence.index import _EXECUTION_ID_RE as _RE

        _check(_RE, execution_id, "execution_id")
        entry = self._index.get_by_execution_id(execution_id)
        if entry is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "execution not indexed"
            )
        return self.get_by_evidence_id(entry.evidence_id)

    def get_by_authorization_id(
        self, authorization_id: str
    ) -> tuple[ev.EvidenceRecord, ...]:
        from ai.evidence.index import _check_id as _check
        from ai.evidence.index import _AUTHZ_ID_RE as _RE

        _check(_RE, authorization_id, "authorization_id")
        entries = self._index.get_by_authorization_id(authorization_id)
        out: list[ev.EvidenceRecord] = []
        for entry in entries:
            out.append(self.get_by_evidence_id(entry.evidence_id))
        return tuple(out)

    def verify_integrity(self, evidence_id: str) -> bool:
        """Re-verify one indexed record (True) or raise on corruption."""
        self.get_by_evidence_id(evidence_id)
        return True

    # -- quarantine / re-index / retention --------------------------------

    def quarantine_evidence(self, evidence_id: str, *, reason: str) -> None:
        entry = self._index.get_by_evidence_id(evidence_id)
        if entry is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "cannot quarantine unindexed evidence"
            )
        if not isinstance(reason, str) or not reason.strip():
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "quarantine requires a reason"
            )
        self._quarantine_blob(entry.content_hash, reason.strip()[:200])
        try:
            self._index.quarantine(
                evidence_id,
                expected_version=entry.record_version,
                reason=reason.strip()[:200],
            )
        except IndexVersionConflict:
            current = self._index.get_by_evidence_id(evidence_id)
            if current is None or not current.quarantined:
                raise

    def reindex_from_blob(
        self,
        content_hash: str,
        *,
        claimed_evidence_id: str,
        claimed_execution_id: str,
        claimed_authorization_id: str,
    ) -> PersistResult:
        """Forward-only orphan recovery under ORIGINAL keys only."""
        if not _SHA256_RE.match(content_hash or ""):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "re-index requires a content hash"
            )
        raw = self._blobs.get(content_hash)
        if raw is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "re-index bytes missing"
            )
        record = parse_envelope(raw)
        orphan_class = validate_reindex(
            record,
            claimed_evidence_id=claimed_evidence_id,
            claimed_execution_id=claimed_execution_id,
            claimed_authorization_id=claimed_authorization_id,
        )
        self._run_hook("before_index")
        entry = self._index_entry_for(record)
        self._index.insert_if_absent(entry)
        current = self._index.get_by_evidence_id(record.evidence_id)
        assert current is not None
        if current.lifecycle in ("SEALED", "INCOMPLETE"):
            try:
                self._index.mark_indexed(
                    record.evidence_id,
                    expected_version=current.record_version,
                    indexed_at=record.sealed_at,
                )
            except IndexVersionConflict:
                pass
        self._run_hook("after_index")
        try:
            self._annotate(
                record=record,
                transition="ORPHAN_REINDEXED",
                scope_note=f"store:{orphan_class}",
            )
        except Exception:
            pass
        return self._persist_result(
            record,
            blob_key_for(record.content_hash or ""),
            indexed=True,
            deduped=False,
        )

    def tombstone_evidence(
        self, evidence_id: str, *, policy: RetentionPolicy
    ) -> None:
        """Index tombstone under an explicit policy (no byte mutation)."""
        if not isinstance(policy, RetentionPolicy):
            raise TypeError(
                "tombstone accepts only RetentionPolicy, "
                f"not {type(policy).__name__}"
            )
        entry = self._index.get_by_evidence_id(evidence_id)
        if entry is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "cannot tombstone unindexed evidence"
            )
        try:
            record = self._load_verified(entry=entry)
        except ev.EvidenceError:
            record = None
        self._index.tombstone(
            evidence_id,
            expected_version=entry.record_version,
            policy=policy,
        )
        if record is not None:
            try:
                self._annotate(
                    record=record,
                    transition="EXECUTION_TERMINAL",
                    scope_note=f"store:tombstoned:{policy.policy_id}"[:200],
                )
            except Exception:
                pass

    # -- 5I handoff ---------------------------------------------------------

    def prepare_handoff(
        self,
        evidence_id: str,
        authorization: object | None = None,
        *,
        execution_started_at: str = "",
    ) -> object:
        """Assemble a verifier handoff for SEALED+complete+valid bytes.

        Rejects BUILDING (unpersistable), INCOMPLETE (default),
        missing, corrupt, hash-mismatched, unbound, and
        unauthenticated-provenance records. Contains references and
        hashes only — never classification.
        """
        record = self.get_by_evidence_id(evidence_id)
        handoff = assemble_handoff(record)
        if authorization is not None:
            handoff = bind_provenance(handoff, authorization)
            verify_provenance_for_handoff(
                handoff,
                authorization,
                execution_started_at=execution_started_at,
            )
        try:
            self._annotate(
                record=record,
                transition="VERIFIER_HANDOFF",
                scope_note="store:handoff",
            )
        except Exception:
            pass
        return handoff


class _CapabilityBase:
    """Shared capability wrapper (no forbidden ops by construction)."""

    def __init__(self, store: EvidenceStore) -> None:
        if not isinstance(store, EvidenceStore):
            raise TypeError(
                "capabilities wrap only EvidenceStore, "
                f"not {type(store).__name__}"
            )
        self._store = store


class EvidenceWriter(_CapabilityBase):
    """Writer: persist + read-back new immutable evidence only."""

    def persist_sealed(self, record: ev.EvidenceRecord) -> PersistResult:
        return self._store.persist_sealed(record)

    def get_by_evidence_id(self, evidence_id: str) -> ev.EvidenceRecord:
        return self._store.get_by_evidence_id(evidence_id)

    def verify_integrity(self, evidence_id: str) -> bool:
        return self._store.verify_integrity(evidence_id)


class EvidenceReader(_CapabilityBase):
    """Reader: verified reads only."""

    def get_by_evidence_id(self, evidence_id: str) -> ev.EvidenceRecord:
        return self._store.get_by_evidence_id(evidence_id)

    def get_by_execution_id(self, execution_id: str) -> ev.EvidenceRecord:
        return self._store.get_by_execution_id(execution_id)

    def get_by_authorization_id(
        self, authorization_id: str
    ) -> tuple[ev.EvidenceRecord, ...]:
        return self._store.get_by_authorization_id(authorization_id)

    def verify_integrity(self, evidence_id: str) -> bool:
        return self._store.verify_integrity(evidence_id)


class EvidenceVerifier(_CapabilityBase):
    """Verifier (5I seam): read-only handoff assembly input."""

    def prepare_handoff(
        self,
        evidence_id: str,
        authorization: object | None = None,
        *,
        execution_started_at: str = "",
    ) -> object:
        return self._store.prepare_handoff(
            evidence_id,
            authorization,
            execution_started_at=execution_started_at,
        )

    def get_by_evidence_id(self, evidence_id: str) -> ev.EvidenceRecord:
        return self._store.get_by_evidence_id(evidence_id)


class EvidenceSweeper(_CapabilityBase):
    """Sweeper: quarantine + re-index metadata only (never bytes)."""

    def quarantine_evidence(self, evidence_id: str, *, reason: str) -> None:
        self._store.quarantine_evidence(evidence_id, reason=reason)

    def reindex_from_blob(
        self,
        content_hash: str,
        *,
        claimed_evidence_id: str,
        claimed_execution_id: str,
        claimed_authorization_id: str,
    ) -> PersistResult:
        return self._store.reindex_from_blob(
            content_hash,
            claimed_evidence_id=claimed_evidence_id,
            claimed_execution_id=claimed_execution_id,
            claimed_authorization_id=claimed_authorization_id,
        )

    def verify_integrity(self, evidence_id: str) -> bool:
        return self._store.verify_integrity(evidence_id)


class EvidenceOperator(_CapabilityBase):
    """Operator: retention policy only (never surviving bytes)."""

    def retention_eligible(
        self, evidence_id: str, policy: RetentionPolicy, *, now_epoch: int
    ) -> bool:
        entry = self._store._index.get_by_evidence_id(evidence_id)
        if entry is None:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "retention check on unindexed evidence"
            )
        return retention_eligible(entry, policy, now_epoch=now_epoch)

    def tombstone_evidence(
        self, evidence_id: str, *, policy: RetentionPolicy
    ) -> None:
        self._store.tombstone_evidence(evidence_id, policy=policy)
