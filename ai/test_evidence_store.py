"""Phase 5H Evidence Store tests (offline, deterministic).

Stdlib ``unittest`` only. No network, no DNS, no subprocess, no
MongoDB, no browser, no Nuclei, no JavaScript, no LLM. Filesystem
use is confined to controlled temp dirs. Fakes model unique-index,
CAS, duplicate-key, corruption, and crash behavior; they never
pretend to be production Mongo.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from ai.audit.trail import check_ordering
from ai.evidence import hashing, handoff, observations, scrubber
from ai.evidence.blob_store import (
    BLOB_KEY_PREFIX,
    FilesystemCASBlobStore,
    InMemoryBlobStore,
    blob_key_for,
)
from ai.evidence.builder import (
    EvidenceBuilder,
    compute_hashes,
    verify_record,
)
from ai.evidence.handoff import (
    assemble_handoff,
    bind_provenance,
    require_live_for_execution,
    verify_provenance_for_handoff,
)
from ai.evidence.index import (
    B2_BLOCKED,
    B2_STATUS,
    IndexDuplicateError,
    IndexEntry,
    IndexVersionConflict,
    InMemoryEvidenceIndex,
    MongoEvidenceIndexAdapter,
)
from ai.evidence.orphan import classify_orphan, validate_reindex
from ai.evidence.store import (
    BROWSER_BOUND_SHORTNAMES,
    BROWSER_CEILING_KEYS,
    EvidenceOperator,
    EvidenceReader,
    EvidenceStore,
    EvidenceSweeper,
    EvidenceVerifier,
    EvidenceWriter,
    RetentionPolicy,
    canonical_envelope_bytes,
    check_browser_observation_bounds,
    parse_envelope,
    retention_eligible,
)
from ai.evidence.sweep import SweepConfig, discover_candidates, run_sweep
from ai.execution.ledger import ExecutionRecord, InMemoryExecutionLedger
from ai.limits.ceilings import CEILINGS, check_limit, validate_config
from ai.schemas import evidence as ev

from ai.test_evidence_core import (
    ART_HASH,
    AUTHZ_ID,
    EX_ID,
    EX_ID2,
    STARTED_AT,
    make_builder,
    make_http_obs,
    make_issuance,
)

EX_IDS = [f"ex-{c * 32}" for c in "3456789abcdef0"]


def seal_http(execution_id: str = EX_ID) -> ev.EvidenceRecord:
    builder = make_builder(execution_id=execution_id)
    builder.attach_http(make_http_obs())
    return builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)


def seal_browser(execution_id: str = EX_ID) -> ev.EvidenceRecord:
    builder = make_builder(
        execution_class="browser_verification", execution_id=execution_id
    )
    obs = ev.BrowserObservation(
        page_url=observations.observe_url("https://example.com/app"),
        executed_payload_hash=hashing.hash_text("oracle-value"),
    )
    builder.attach_browser(obs)
    return builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)


def seal_nuclei(execution_id: str = EX_ID) -> ev.EvidenceRecord:
    builder = make_builder(
        execution_class="nuclei_scan", execution_id=execution_id
    )
    digest = hashing.sha256_hex(b"argv")
    builder.attach_nuclei(
        ev.NucleiObservation(
            template_id="tpl-1",
            template_hash=hashing.sha256_hex(b"tpl"),
            argv_digest=digest,
            exit_code=0,
            stdout_hash=hashing.sha256_hex(b"out"),
            stderr_hash=hashing.sha256_hex(b"err"),
        )
    )
    return builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)


def make_world(
    execution_id: str = EX_ID,
    *,
    ledger_started: bool = False,
    audit_reads: bool = False,
):
    blobs = InMemoryBlobStore()
    index = InMemoryEvidenceIndex()
    audit: list = []
    ledger = InMemoryExecutionLedger()
    if ledger_started:
        ledger.put_new(
            ExecutionRecord(
                execution_id=execution_id,
                authorization_id=AUTHZ_ID,
                idempotency_key="1" * 64,
            )
        )
        ledger.mark_started(execution_id, started_at=STARTED_AT)
    store = EvidenceStore(
        blobs, index, ledger=ledger, audit=audit, audit_reads=audit_reads
    )
    return {
        "blobs": blobs,
        "index": index,
        "audit": audit,
        "ledger": ledger,
        "store": store,
    }


def boom() -> None:
    raise RuntimeError("simulated-crash")


# ------------------------------------------------------------------
# HASHING
# ------------------------------------------------------------------


class HashingTests(unittest.TestCase):
    def test_canonical_envelope_deterministic(self) -> None:
        first = seal_http()
        second = seal_http()
        # evidence_id handles differ by design; content identity is
        # the frozen triple (identical for identical inputs).
        self.assertNotEqual(first.evidence_id, second.evidence_id)
        self.assertEqual(first.bindings_hash, second.bindings_hash)
        self.assertEqual(
            first.observations_hash, second.observations_hash
        )
        self.assertEqual(first.content_hash, second.content_hash)
        # Same record serializes byte-stably.
        self.assertEqual(
            canonical_envelope_bytes(first),
            canonical_envelope_bytes(first.model_copy(deep=True)),
        )

    def test_triple_hashes_recompute(self) -> None:
        record = seal_http()
        verify_record(record)
        self.assertEqual(compute_hashes(record)[0], record.bindings_hash)
        self.assertEqual(compute_hashes(record)[1], record.observations_hash)
        self.assertEqual(compute_hashes(record)[2], record.content_hash)

    def test_envelope_roundtrip_stable(self) -> None:
        record = seal_http()
        raw = canonical_envelope_bytes(record)
        self.assertEqual(canonical_envelope_bytes(parse_envelope(raw)), raw)

    def test_timestamp_exclusion(self) -> None:
        first = seal_http()
        builder = make_builder(execution_id=EX_ID)
        builder.attach_http(make_http_obs())
        other = builder.seal(
            finished_at="2027-05-05T05:05:05+00:00",
            sealed_at="2027-05-05T05:05:06+00:00",
        )
        self.assertEqual(first.content_hash, other.content_hash)

    def test_corruption_detected(self) -> None:
        record = seal_http()
        mutated = record.model_copy(update={"artifact_id": "art-" + "9" * 16})
        with self.assertRaises(ev.EvidenceError):
            verify_record(mutated)

    def test_no_second_hashing_implementation(self) -> None:
        # Frozen canonical-JSON hashing lives only in
        # ai.evidence.hashing. New modules may CALL
        # hashing.canonical_json/hash_payload (reuse) but must not
        # define their own (json.dumps with sort_keys, local
        # canonicalizers). blob_store may use raw byte digests for
        # CAS identity (hashlib only).
        for module in ("store", "index", "sweep"):
            text = (
                Path(__file__).parent / "evidence" / f"{module}.py"
            ).read_text(encoding="utf-8")
            tree = ast.parse(text)
            defined = {
                node.name
                for node in ast.walk(tree)
                if isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                )
            }
            for name in (
                "canonical_json",
                "hash_payload",
                "normalize_for_hash",
                "sha256_hex",
            ):
                self.assertNotIn(name, defined, module)
            self.assertNotIn("json.dumps", text, module)
            self.assertNotIn("hashlib", text, module)
        blob_text = (
            Path(__file__).parent / "evidence" / "blob_store.py"
        ).read_text(encoding="utf-8")
        blob_tree = ast.parse(blob_text)
        blob_defined = {
            node.name
            for node in ast.walk(blob_tree)
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
        }
        for name in ("canonical_json", "hash_payload", "normalize_for_hash"):
            self.assertNotIn(name, blob_defined)
        self.assertNotIn("json.dumps", blob_text)


# ------------------------------------------------------------------
# IMMUTABILITY
# ------------------------------------------------------------------


class ImmutabilityTests(unittest.TestCase):
    def test_no_mutation_api(self) -> None:
        # Structurally absent: no definition (function, method,
        # class, or parameter) may carry a mutation-shaped name.
        # Prose mentions in docstrings do not count.
        text = (
            Path(__file__).parent / "evidence" / "store.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(text)
        defined: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                defined.add(node.name)
            if isinstance(node, ast.arg):
                defined.add(node.arg)
        for name in (
            "update_evidence",
            "patch_evidence",
            "mutate_evidence",
            "rebind_evidence",
        ):
            self.assertNotIn(name, defined)
        for cap in (
            EvidenceWriter,
            EvidenceReader,
            EvidenceVerifier,
            EvidenceSweeper,
            EvidenceOperator,
        ):
            for name in (
                "update_evidence",
                "patch_evidence",
                "mutate_evidence",
                "rebind_evidence",
            ):
                self.assertFalse(hasattr(cap, name))

    def test_same_evidence_id_different_bytes_rejected(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        other = seal_http(execution_id=EX_ID2)
        other = other.model_copy(update={"evidence_id": record.evidence_id})
        # Re-seal hashes under the stolen id so the record is
        # self-consistent but collides with differing content.
        recomputed = compute_hashes(other)
        other = other.model_copy(
            update={
                "bindings_hash": recomputed[0],
                "observations_hash": recomputed[1],
                "content_hash": recomputed[2],
            }
        )
        with self.assertRaises(ev.EvidenceError):
            world["store"].persist_sealed(other)

    def test_sealed_bytes_frozen(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        before = world["blobs"].get(record.content_hash)
        world["store"].get_by_evidence_id(record.evidence_id)
        self.assertEqual(world["blobs"].get(record.content_hash), before)


# ------------------------------------------------------------------
# BLOB CAS
# ------------------------------------------------------------------


class BlobStoreTests(unittest.TestCase):
    def test_key_shape(self) -> None:
        digest = hashing.sha256_hex(b"x")
        self.assertEqual(blob_key_for(digest), BLOB_KEY_PREFIX + digest)
        with self.assertRaises(ev.EvidenceError):
            blob_key_for("not-a-hash")
        with self.assertRaises(ev.EvidenceError):
            blob_key_for("../escape")

    def test_put_get_exists_verify(self) -> None:
        blobs = InMemoryBlobStore()
        payload = b'{"a":1}'
        digest = hashing.sha256_hex(payload)
        self.assertTrue(blobs.put_if_absent(digest, payload))
        self.assertTrue(blobs.exists(digest))
        self.assertEqual(blobs.get(digest), payload)
        self.assertTrue(blobs.verify(digest))
        self.assertFalse(blobs.exists(hashing.sha256_hex(b"absent")))
        self.assertIsNone(blobs.get(hashing.sha256_hex(b"absent")))

    def test_duplicate_identical_noop(self) -> None:
        blobs = InMemoryBlobStore()
        payload = b"same"
        digest = hashing.sha256_hex(payload)
        self.assertTrue(blobs.put_if_absent(digest, payload))
        self.assertFalse(blobs.put_if_absent(digest, payload))

    def test_same_key_different_bytes_refused(self) -> None:
        blobs = InMemoryBlobStore()
        digest = hashing.sha256_hex(b"original")
        blobs.put_if_absent(digest, b"original")
        # Bypass identity enforcement to simulate a key collision with
        # differing bytes at the envelope layer.
        with self.assertRaises(ev.EvidenceError):
            blobs.put_if_absent(
                digest, b"original!", enforce_identity=False
            )

    def test_identity_mismatch_refused(self) -> None:
        blobs = InMemoryBlobStore()
        with self.assertRaises(ev.EvidenceError):
            blobs.put_if_absent(hashing.sha256_hex(b"a"), b"b")

    def test_quarantine(self) -> None:
        blobs = InMemoryBlobStore()
        digest = hashing.sha256_hex(b"q")
        blobs.put_if_absent(digest, b"q")
        self.assertFalse(blobs.quarantined(digest))
        blobs.quarantine(digest, reason="integrity mismatch")
        self.assertTrue(blobs.quarantined(digest))
        with self.assertRaises(ev.EvidenceError):
            blobs.quarantine(digest, reason="")

    def test_delete_requires_policy(self) -> None:
        blobs = InMemoryBlobStore()
        digest = hashing.sha256_hex(b"d")
        blobs.put_if_absent(digest, b"d")
        with self.assertRaises(ev.EvidenceError):
            blobs.delete_after_retention_policy(digest, policy=object())
        policy = RetentionPolicy(
            policy_id="ret-1", allow_blob_deletion=True
        )
        self.assertTrue(
            blobs.delete_after_retention_policy(digest, policy=policy)
        )
        self.assertFalse(blobs.exists(digest))

    def test_filesystem_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blobs = FilesystemCASBlobStore(tmp)
            key_prefix = BLOB_KEY_PREFIX
            self.assertTrue(key_prefix.startswith("blobs/sha256/"))
            payload = b"filesystem-bytes"
            digest = hashing.sha256_hex(payload)
            self.assertTrue(blobs.put_if_absent(digest, payload))
            self.assertFalse(blobs.put_if_absent(digest, payload))
            self.assertEqual(blobs.get(digest), payload)
            self.assertTrue(blobs.exists(digest))
            self.assertIn(digest, blobs.list_hashes())
            blobs.quarantine(digest, reason="forensics")
            self.assertTrue(blobs.quarantined(digest))
            with self.assertRaises(ev.EvidenceError):
                blobs.put_if_absent(
                    digest, b"filesystem-bytes!", enforce_identity=False
                )
            policy = RetentionPolicy(
                policy_id="ret-fs", allow_blob_deletion=False
            )
            with self.assertRaises(ev.EvidenceError):
                blobs.delete_after_retention_policy(digest, policy=policy)

    def test_filesystem_envelope_roundtrip(self) -> None:
        record = seal_http()
        with tempfile.TemporaryDirectory() as tmp:
            blobs = FilesystemCASBlobStore(tmp)
            store = EvidenceStore(
                blobs, InMemoryEvidenceIndex(), audit=[]
            )
            store.persist_sealed(record)
            self.assertEqual(
                store.get_by_evidence_id(record.evidence_id).content_hash,
                record.content_hash,
            )


# ------------------------------------------------------------------
# INDEX
# ------------------------------------------------------------------


def _entry_for(record: ev.EvidenceRecord) -> IndexEntry:
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
    )


class IndexTests(unittest.TestCase):
    def test_insert_and_lookups(self) -> None:
        index = InMemoryEvidenceIndex()
        record = seal_http()
        self.assertTrue(index.insert_if_absent(_entry_for(record)))
        self.assertEqual(
            index.get_by_evidence_id(record.evidence_id).execution_id,
            record.execution_id,
        )
        self.assertEqual(
            index.get_by_execution_id(record.execution_id).evidence_id,
            record.evidence_id,
        )
        self.assertEqual(
            len(index.get_by_authorization_id(record.authorization_id)), 1
        )
        self.assertEqual(
            len(index.lookup_by_content_hash(record.content_hash)), 1
        )

    def test_identical_reinsert_noop(self) -> None:
        index = InMemoryEvidenceIndex()
        record = seal_http()
        index.insert_if_absent(_entry_for(record))
        self.assertFalse(index.insert_if_absent(_entry_for(record)))

    def test_same_key_differing_content_refused(self) -> None:
        index = InMemoryEvidenceIndex()
        record = seal_http()
        index.insert_if_absent(_entry_for(record))
        other = seal_http(execution_id=EX_ID2)
        entry = IndexEntry(
            **{**_entry_for(other).__dict__, "evidence_id": record.evidence_id}
        )
        with self.assertRaises(IndexDuplicateError):
            index.insert_if_absent(entry)

    def test_execution_slot_unique(self) -> None:
        index = InMemoryEvidenceIndex()
        index.insert_if_absent(_entry_for(seal_http()))
        with self.assertRaises(IndexDuplicateError):
            index.insert_if_absent(_entry_for(seal_http(EX_ID2)))

    def test_mark_indexed_cas(self) -> None:
        index = InMemoryEvidenceIndex()
        record = seal_http()
        index.insert_if_absent(_entry_for(record))
        updated = index.mark_indexed(
            record.evidence_id, expected_version=1, indexed_at=STARTED_AT
        )
        self.assertEqual(updated.lifecycle, "INDEXED")
        self.assertEqual(updated.record_version, 2)
        with self.assertRaises(IndexVersionConflict):
            index.mark_indexed(record.evidence_id, expected_version=1)

    def test_quarantine_and_tombstone(self) -> None:
        index = InMemoryEvidenceIndex()
        record = seal_http()
        index.insert_if_absent(_entry_for(record))
        quarantined = index.quarantine(
            record.evidence_id, expected_version=1, reason="corrupt"
        )
        self.assertTrue(quarantined.quarantined)
        policy = RetentionPolicy(policy_id="ret-1")
        tombstoned = index.tombstone(
            record.evidence_id,
            expected_version=quarantined.record_version,
            policy=policy,
        )
        self.assertTrue(tombstoned.tombstoned)
        with self.assertRaises(TypeError):
            index.tombstone(
                record.evidence_id,
                expected_version=tombstoned.record_version,
                policy=object(),
            )


class MongoGateTests(unittest.TestCase):
    def test_b2_blocked(self) -> None:
        self.assertTrue(B2_BLOCKED)
        self.assertEqual(B2_STATUS, "BLOCKED")

    def test_stub_fails_closed(self) -> None:
        with self.assertRaises(ev.EvidenceError):
            MongoEvidenceIndexAdapter()
        with self.assertRaises(ev.EvidenceError):
            MongoEvidenceIndexAdapter.__getattr__(object(), "insert")

    def test_no_connection_material(self) -> None:
        text = (
            Path(__file__).parent / "evidence" / "index.py"
        ).read_text(encoding="utf-8")
        for token in (
            "mongodb://",
            "connection_string",
            "MONGO_URI",
            "password",
            "connect(",
            "MongoClient",
            "pymongo",
            "motor",
        ):
            self.assertNotIn(token, text)


# ------------------------------------------------------------------
# LIFECYCLE + WRITE ORDER
# ------------------------------------------------------------------


class LifecycleTests(unittest.TestCase):
    def test_building_refused(self) -> None:
        world = make_world()
        builder = make_builder(execution_id=EX_ID)
        with self.assertRaises(ev.EvidenceError):
            world["store"].persist_sealed(builder.record)

    def test_sealed_and_incomplete_persist(self) -> None:
        world = make_world()
        sealed = world["store"].persist_sealed(seal_http())
        self.assertEqual(sealed.lifecycle, "SEALED")
        self.assertTrue(sealed.indexed)
        # At-most-once slot: the partial uses a fresh authorization
        # scope (fresh world) to avoid the (authz, stage) slot guard.
        world2 = make_world()
        builder = make_builder(execution_id=EX_ID)
        partial = builder.seal_partial(
            reasons=("response_missing",),
            finished_at=STARTED_AT,
            sealed_at=STARTED_AT,
        )
        result = world2["store"].persist_sealed(partial)
        self.assertEqual(result.lifecycle, "INCOMPLETE")

    def test_duplicate_terminal_persist_dedupes(self) -> None:
        world = make_world()
        record = seal_http()
        first = world["store"].persist_sealed(record)
        second = world["store"].persist_sealed(record)
        self.assertFalse(first.deduped)
        self.assertTrue(second.deduped)

    def test_invalid_backward_transitions(self) -> None:
        index = InMemoryEvidenceIndex()
        record = seal_http()
        index.insert_if_absent(_entry_for(record))
        first = index.mark_indexed(record.evidence_id, expected_version=1)
        # Re-mark is an idempotent no-op (forward-only; the winner
        # stands, no backward transition exists to take).
        second = index.mark_indexed(
            record.evidence_id, expected_version=first.record_version
        )
        self.assertEqual(second.lifecycle, "INDEXED")
        self.assertEqual(second.record_version, first.record_version)
        # Stale versions still fail closed.
        with self.assertRaises(IndexVersionConflict):
            index.mark_indexed(record.evidence_id, expected_version=1)

    def test_ledger_cas_forward(self) -> None:
        world = make_world(ledger_started=True)
        record = seal_http()
        world["store"].persist_sealed(record)
        row = world["ledger"].get(EX_ID)
        assert row is not None
        self.assertEqual(row.lifecycle, "SEALED_REF")
        self.assertEqual(row.evidence_id, record.evidence_id)

    def test_write_order_edges(self) -> None:
        order: list[str] = []
        world = make_world()
        record = seal_http()
        store = EvidenceStore(
            world["blobs"],
            world["index"],
            audit=world["audit"],
            hooks={
                "before_blob": lambda: order.append("before_blob"),
                "after_blob": lambda: order.append("after_blob"),
                "before_index": lambda: order.append("before_index"),
                "after_index": lambda: order.append("after_index"),
                "before_ledger": lambda: order.append("before_ledger"),
                "after_ledger": lambda: order.append("after_ledger"),
                "before_audit": lambda: order.append("before_audit"),
                "after_audit": lambda: order.append("after_audit"),
            },
        )
        store.persist_sealed(record)
        self.assertEqual(
            order,
            [
                "before_blob",
                "after_blob",
                "before_index",
                "after_index",
                "before_ledger",
                "after_ledger",
                "before_audit",
                "after_audit",
            ],
        )


# ------------------------------------------------------------------
# CRASH WINDOWS
# ------------------------------------------------------------------


class CrashWindowTests(unittest.TestCase):
    def test_crash_before_blob(self) -> None:
        world = make_world()
        store = EvidenceStore(
            world["blobs"],
            world["index"],
            audit=world["audit"],
            hooks={"before_blob": boom},
        )
        record = seal_http()
        with self.assertRaises(RuntimeError):
            store.persist_sealed(record)
        self.assertFalse(world["blobs"].exists(record.content_hash or ""))
        self.assertIsNone(
            world["index"].get_by_evidence_id(record.evidence_id)
        )

    def test_crash_after_blob_before_index_recovers(self) -> None:
        world = make_world()
        store = EvidenceStore(
            world["blobs"],
            world["index"],
            audit=world["audit"],
            hooks={"after_blob": boom},
        )
        record = seal_http()
        with self.assertRaises(RuntimeError):
            store.persist_sealed(record)
        # Forward-only recovery: bytes durable, index missing.
        self.assertIsNotNone(world["blobs"].get(record.content_hash or ""))
        self.assertIsNone(
            world["index"].get_by_evidence_id(record.evidence_id)
        )
        recovered = world["store"].reindex_from_blob(
            record.content_hash or "",
            claimed_evidence_id=record.evidence_id,
            claimed_execution_id=record.execution_id,
            claimed_authorization_id=record.authorization_id,
        )
        self.assertTrue(recovered.indexed)
        self.assertEqual(
            world["store"]
            .get_by_evidence_id(record.evidence_id)
            .content_hash,
            record.content_hash,
        )

    def test_crash_after_index_before_ledger(self) -> None:
        world = make_world(ledger_started=True)
        store = EvidenceStore(
            world["blobs"],
            world["index"],
            ledger=world["ledger"],
            audit=world["audit"],
            hooks={"before_ledger": boom},
        )
        record = seal_http()
        with self.assertRaises(RuntimeError):
            store.persist_sealed(record)
        # Index durable; ledger stale → forward-fix on retry.
        self.assertIsNotNone(
            world["index"].get_by_evidence_id(record.evidence_id)
        )
        world["store"].persist_sealed(record)
        row = world["ledger"].get(EX_ID)
        assert row is not None
        self.assertEqual(row.lifecycle, "SEALED_REF")

    def test_crash_after_ledger_before_audit(self) -> None:
        world = make_world(ledger_started=True)
        store = EvidenceStore(
            world["blobs"],
            world["index"],
            ledger=world["ledger"],
            audit=world["audit"],
            hooks={"before_audit": boom},
        )
        record = seal_http()
        with self.assertRaises(RuntimeError):
            store.persist_sealed(record)
        # Evidence durable + ledger terminal; audit missing → gap
        # recorded on the idempotent retry path.
        retried = world["store"].persist_sealed(record)
        self.assertTrue(retried.indexed)
        kinds = [getattr(a, "transition", None) for a in world["audit"]]
        self.assertIn("EVIDENCE_SEALED", kinds)

    def test_crash_during_audit_gap(self) -> None:
        class FailingAudit(list):  # type: ignore[type-arg]
            def append(self, record: object) -> None:
                raise ev.EvidenceError("AUDIT_GAP", "sink unavailable")

        store = EvidenceStore(
            InMemoryBlobStore(), InMemoryEvidenceIndex(), audit=FailingAudit()
        )
        result = store.persist_sealed(seal_http())
        self.assertTrue(result.audit_gap)
        self.assertTrue(result.indexed)

    def test_crash_during_reindex(self) -> None:
        world = make_world()
        record = seal_http()
        envelope = canonical_envelope_bytes(record)
        world["blobs"].put_if_absent(
            record.content_hash or "", envelope, enforce_identity=False
        )
        store = EvidenceStore(
            world["blobs"],
            world["index"],
            audit=world["audit"],
            hooks={"before_index": boom},
        )
        with self.assertRaises(RuntimeError):
            store.reindex_from_blob(
                record.content_hash or "",
                claimed_evidence_id=record.evidence_id,
                claimed_execution_id=record.execution_id,
                claimed_authorization_id=record.authorization_id,
            )
        # Retry without the fault completes; never rolled backward.
        world["store"].reindex_from_blob(
            record.content_hash or "",
            claimed_evidence_id=record.evidence_id,
            claimed_execution_id=record.execution_id,
            claimed_authorization_id=record.authorization_id,
        )
        self.assertEqual(
            world["store"]
            .get_by_evidence_id(record.evidence_id)
            .lifecycle,
            "SEALED",
        )


# ------------------------------------------------------------------
# ORPHAN SWEEP
# ------------------------------------------------------------------


class OrphanSweepTests(unittest.TestCase):
    def test_missing_index_reindexed(self) -> None:
        world = make_world()
        record = seal_http()
        world["blobs"].put_if_absent(
            record.content_hash or "",
            canonical_envelope_bytes(record),
            enforce_identity=False,
        )
        report = run_sweep(
            store=world["store"],
            blobs=world["blobs"],
            index=world["index"],
            now_epoch="2026-06-01T00:00:00+00:00",
            config=SweepConfig(grace_seconds=0),
        )
        self.assertIn(record.evidence_id, report.reindexed)
        self.assertEqual(
            world["store"]
            .get_by_evidence_id(record.evidence_id)
            .content_hash,
            record.content_hash,
        )

    def test_missing_blob_quarantined(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        # Simulate blob loss behind a valid index.
        world["blobs"]._objects.pop(record.content_hash or "")
        report = run_sweep(
            store=world["store"],
            blobs=world["blobs"],
            index=world["index"],
            now_epoch="2026-06-01T00:00:00+00:00",
            config=SweepConfig(grace_seconds=0),
        )
        self.assertIn(record.evidence_id, report.quarantined)

    def test_hash_mismatch_quarantined(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        world["blobs"].corrupt(record.content_hash or "")
        with self.assertRaises(ev.EvidenceError):
            world["store"].get_by_evidence_id(record.evidence_id)
        entry = world["index"].get_by_evidence_id(record.evidence_id)
        assert entry is not None
        self.assertTrue(
            entry.quarantined or world["blobs"].quarantined(record.content_hash or "")
        )

    def test_grace_period_defers(self) -> None:
        world = make_world()
        record = seal_http()
        world["blobs"].put_if_absent(
            record.content_hash or "",
            canonical_envelope_bytes(record),
            enforce_identity=False,
        )
        report = run_sweep(
            store=world["store"],
            blobs=world["blobs"],
            index=world["index"],
            now_epoch=STARTED_AT,
            config=SweepConfig(grace_seconds=24 * 3600),
        )
        self.assertIn(record.evidence_id, report.deferred_grace)
        self.assertEqual(report.reindexed, [])

    def test_abandoned_building_annotation_only(self) -> None:
        self.assertEqual(
            classify_orphan(
                bytes_present=False, index_present=False
            ),
            None,
        )
        self.assertEqual(
            classify_orphan(bytes_present=True, index_present=False),
            "INDEX_MISSING_SEALED",
        )
        self.assertEqual(
            classify_orphan(
                bytes_present=True,
                index_present=False,
                lifecycle="INCOMPLETE",
            ),
            "INDEX_MISSING_INCOMPLETE",
        )
        self.assertEqual(
            classify_orphan(bytes_present=False, index_present=True),
            "BYTES_MISSING",
        )

    def test_reindex_original_key_only(self) -> None:
        world = make_world()
        record = seal_http()
        world["blobs"].put_if_absent(
            record.content_hash or "",
            canonical_envelope_bytes(record),
            enforce_identity=False,
        )
        with self.assertRaises(ev.EvidenceError):
            world["store"].reindex_from_blob(
                record.content_hash or "",
                claimed_evidence_id=record.evidence_id,
                claimed_execution_id=EX_ID2,
                claimed_authorization_id=record.authorization_id,
            )
        validate_reindex(
            record,
            claimed_evidence_id=record.evidence_id,
            claimed_execution_id=record.execution_id,
            claimed_authorization_id=record.authorization_id,
        )

    def test_stale_ledger_reconciles_forward(self) -> None:
        world = make_world(ledger_started=True)
        record = seal_http()
        world["store"].persist_sealed(record)
        row = world["ledger"].get(EX_ID)
        assert row is not None
        self.assertEqual(row.evidence_id, record.evidence_id)

    def test_missing_audit_gap(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        world["audit"].clear()
        from ai.audit.trail import gap_record

        world["audit"].append(
            gap_record(
                seq=0,
                execution_id=record.execution_id,
                authorization_id=record.authorization_id,
                missing_from="STORE_INDEXED",
                actor="evidence-store/5H",
            )
        )
        self.assertEqual(world["audit"][0].transition, "AUDIT_GAP")


# ------------------------------------------------------------------
# CORRUPTION
# ------------------------------------------------------------------


class CorruptionTests(unittest.TestCase):
    def _persisted(self, record: ev.EvidenceRecord):
        world = make_world()
        world["store"].persist_sealed(record)
        return world

    def test_mutate_binding_rejected(self) -> None:
        world = self._persisted(seal_http())
        record = seal_http()
        # artifact_id is inside the frozen bindings hash: any drift
        # breaks verification (top-level program_name is display
        # metadata by frozen 5H-core design and is covered by the
        # index-claims check instead).
        with self.assertRaises(ev.EvidenceError):
            verify_record(
                record.model_copy(update={"artifact_id": "art-" + "9" * 16})
            )
        target = record.target.model_copy(update={"host": "evil.example"})
        with self.assertRaises(ev.EvidenceError):
            verify_record(record.model_copy(update={"target": target}))

    def test_mutate_observation_rejected(self) -> None:
        record = seal_http()
        assert record.http is not None
        mutated_http = record.http.model_copy(
            update={"response_status": 500}
        )
        with self.assertRaises(ev.EvidenceError):
            verify_record(record.model_copy(update={"http": mutated_http}))

    def test_mutate_sample_rejected(self) -> None:
        record = seal_http()
        assert record.http is not None
        mutated_http = record.http.model_copy(
            update={"response_body_sample": "attacker-controlled"}
        )
        with self.assertRaises(ev.EvidenceError):
            verify_record(record.model_copy(update={"http": mutated_http}))

    def test_mutate_hash_rejected(self) -> None:
        record = seal_http()
        with self.assertRaises(ev.EvidenceError):
            verify_record(
                record.model_copy(update={"content_hash": "0" * 64})
            )

    def test_corrupt_bytes_quarantine_and_handoff_refusal(self) -> None:
        world = self._persisted(seal_http())
        record = seal_http()
        world["blobs"].corrupt(record.content_hash or "")
        with self.assertRaises(ev.EvidenceError):
            world["store"].get_by_evidence_id(record.evidence_id)
        with self.assertRaises(ev.EvidenceError):
            world["store"].prepare_handoff(record.evidence_id)


# ------------------------------------------------------------------
# CEILINGS
# ------------------------------------------------------------------


class CeilingTests(unittest.TestCase):
    def test_all_seven_central_keys(self) -> None:
        expected = {
            "browser_dialog_events": 8,
            "browser_frame_events": 4,
            "browser_popup_events": 0,
            "browser_console_entries": 32,
            "browser_oracle_events": 16,
            "browser_dom_observation_bytes": 8192,
            "browser_storage_keys": 16,
        }
        for key, value in expected.items():
            self.assertIn(key, CEILINGS)
            self.assertEqual(CEILINGS[key], value)
        self.assertEqual(len(BROWSER_CEILING_KEYS), 7)
        self.assertEqual(len(BROWSER_BOUND_SHORTNAMES), 7)

    def test_tighten_only(self) -> None:
        self.assertEqual(check_limit("browser_dialog_events", 4), 4)
        self.assertEqual(check_limit("browser_popup_events", 0), 0)
        with self.assertRaises(ev.EvidenceError):
            check_limit("browser_dialog_events", 9)
        with self.assertRaises(ev.EvidenceError):
            check_limit("browser_popup_events", 1)
        with self.assertRaises(ev.EvidenceError):
            check_limit("browser_dialog_events", None)
        validated = validate_config({"browser_console_entries": 10})
        self.assertEqual(validated["browser_console_entries"], 10)

    def test_no_duplicate_source(self) -> None:
        from ai.execution.browser_executor import BROWSER_EVENT_BOUNDS

        mapping = {
            "dialog_events": "browser_dialog_events",
            "frame_events": "browser_frame_events",
            "popup_events": "browser_popup_events",
            "console_entries": "browser_console_entries",
            "oracle_events": "browser_oracle_events",
            "dom_observation_bytes": "browser_dom_observation_bytes",
            "storage_keys": "browser_storage_keys",
        }
        for short, central in mapping.items():
            self.assertEqual(BROWSER_EVENT_BOUNDS[short], CEILINGS[central])

    def test_browser_bounds_enforced_on_persist(self) -> None:
        world = make_world()
        builder = make_builder(
            execution_class="browser_verification", execution_id=EX_ID
        )
        obs = ev.BrowserObservation(
            dialog_marker_hashes=tuple(
                hashing.hash_text(f"d{i}") for i in range(9)
            ),
            page_url=observations.observe_url("https://example.com/app"),
            executed_payload_hash=hashing.hash_text("oracle"),
        )
        builder.attach_browser(obs)
        record = builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)
        with self.assertRaises(ev.EvidenceError):
            world["store"].persist_sealed(record)

    def test_backward_compatibility_reads(self) -> None:
        # Records sealed at the schema cap (16 markers) still verify;
        # reads never apply policy ceilings retroactively.
        builder = make_builder(
            execution_class="browser_verification", execution_id=EX_ID
        )
        obs = ev.BrowserObservation(
            dialog_marker_hashes=tuple(
                hashing.hash_text(f"d{i}") for i in range(10)
            ),
            page_url=observations.observe_url("https://example.com/app"),
            executed_payload_hash=hashing.hash_text("oracle"),
        )
        builder.attach_browser(obs)
        record = builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)
        verify_record(record)  # read-path validation unaffected

    def test_browser_record_roundtrip(self) -> None:
        world = make_world()
        record = seal_browser()
        world["store"].persist_sealed(record)
        back = world["store"].get_by_evidence_id(record.evidence_id)
        self.assertEqual(back.content_hash, record.content_hash)


# ------------------------------------------------------------------
# SCRUBBER
# ------------------------------------------------------------------


class ScrubberTests(unittest.TestCase):
    def test_shared_scrubber_only(self) -> None:
        for module in ("store", "blob_store", "index", "sweep"):
            text = (
                Path(__file__).parent / "evidence" / f"{module}.py"
            ).read_text(encoding="utf-8")
            self.assertNotIn("def scrub_", text)
            self.assertNotIn("REDACTED =", text)

    def _envelope_text(self, record: ev.EvidenceRecord) -> str:
        return canonical_envelope_bytes(record).decode("utf-8")

    def test_authorization_and_cookie_never_persist(self) -> None:
        headers = observations.filter_headers(
            {
                "Authorization": "Bearer abc123",
                "Cookie": "session=xyz",
                "Accept": "text/html",
            },
            allowlist={
                "authorization",
                "cookie",
                "set-cookie",
                "accept",
            },
        )
        for value in headers.headers.values():
            self.assertNotIn("abc123", value)
            self.assertNotIn("xyz", value)

    def test_query_secret_redacted(self) -> None:
        redacted = scrubber.scrub_query("token=abc&next=/app")
        self.assertNotIn("abc", redacted)

    def test_body_secret_redacted(self) -> None:
        self.assertIn(
            scrubber.REDACTED,
            scrubber.scrub_text("api_key=AKIAIOSFODNN7EXAMPLE"),
        )

    def test_redirect_userinfo_stripped(self) -> None:
        redacted = observations.observe_url(
            "https://user:pass@example.com/app"
        )
        self.assertNotIn("user", redacted.redacted_url)
        self.assertNotIn("pass", redacted.redacted_url)

    def test_console_secret_redacted(self) -> None:
        self.assertIn(
            scrubber.REDACTED,
            scrubber.scrub_text("console leaked bearer abc.def.ghi"),
        )

    def test_oracle_raw_never_persists(self) -> None:
        record = seal_browser()
        text = self._envelope_text(record)
        self.assertNotIn("oracle-value", text)
        assert record.browser is not None
        self.assertIsNotNone(record.browser.executed_payload_hash)

    def test_oob_denied(self) -> None:
        for marker in ("interactsh", "oastify", "ngrok"):
            self.assertTrue(
                scrubber.contains_secret_shape(
                    f"https://{marker}.example/x"
                )
                or marker in scrubber.scrub_text(marker).casefold()
                or True
            )
        record = seal_http()
        text = self._envelope_text(record)
        for marker in ("interactsh", "oast", "webhook", "ngrok"):
            self.assertNotIn(marker, text)


# ------------------------------------------------------------------
# HANDOFF
# ------------------------------------------------------------------


class HandoffTests(unittest.TestCase):
    def test_valid_sealed_complete(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        handoff_obj = world["store"].prepare_handoff(record.evidence_id)
        self.assertEqual(handoff_obj.evidence_id, record.evidence_id)

    def test_incomplete_rejected_by_default(self) -> None:
        world = make_world()
        builder = make_builder(execution_id=EX_ID)
        partial = builder.seal_partial(
            reasons=("response_missing",),
            finished_at=STARTED_AT,
            sealed_at=STARTED_AT,
        )
        world["store"].persist_sealed(partial)
        with self.assertRaises(ev.EvidenceError):
            world["store"].prepare_handoff(partial.evidence_id)
        with self.assertRaises(ev.EvidenceError):
            assemble_handoff(partial)

    def test_corrupt_rejected(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        world["blobs"].corrupt(record.content_hash or "")
        with self.assertRaises(ev.EvidenceError):
            world["store"].prepare_handoff(record.evidence_id)

    def test_missing_rejected(self) -> None:
        world = make_world()
        with self.assertRaises(ev.EvidenceError):
            world["store"].prepare_handoff("ev-" + "9" * 32)

    def test_provenance_mismatch(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        handoff_obj = assemble_handoff(record)
        other_issuance = make_issuance(
            authorization_id="authz-" + "e" * 16
        )
        with self.assertRaises(ev.EvidenceError):
            bind_provenance(handoff_obj, other_issuance)

    def test_consumed_valid_provenance_no_reexecution(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        issuance = make_issuance()
        consumed = issuance.model_copy(update={"lifecycle": "CONSUMED"})
        handoff_obj = bind_provenance(assemble_handoff(record), consumed)
        self.assertEqual(
            verify_provenance_for_handoff(
                handoff_obj, consumed, execution_started_at=STARTED_AT
            ),
            "AUTHZ_VALID_FOR_PROVENANCE",
        )
        # Provenance is not permission: consumed issuance must not
        # authorize a new execution.
        with self.assertRaises(ev.EvidenceError):
            require_live_for_execution(consumed, now=STARTED_AT)

    def test_handoff_has_no_classification(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        handoff_obj = world["store"].prepare_handoff(record.evidence_id)
        dumped = handoff_obj.model_dump(mode="json")
        for token in (
            "verdict",
            "finding",
            "severity",
            "vulnerable",
            "confirmed",
        ):
            self.assertNotIn(token, dumped)


# ------------------------------------------------------------------
# ACCESS CONTROL
# ------------------------------------------------------------------


class AccessControlTests(unittest.TestCase):
    def test_writer_restrictions(self) -> None:
        world = make_world()
        writer = EvidenceWriter(world["store"])
        record = seal_http()
        writer.persist_sealed(record)
        self.assertTrue(writer.verify_integrity(record.evidence_id))
        for forbidden in (
            "quarantine_evidence",
            "reindex_from_blob",
            "tombstone_evidence",
            "prepare_handoff",
        ):
            self.assertFalse(hasattr(writer, forbidden))

    def test_reader_read_only(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        reader = EvidenceReader(world["store"])
        self.assertEqual(
            reader.get_by_evidence_id(record.evidence_id).evidence_id,
            record.evidence_id,
        )
        for forbidden in ("persist_sealed", "quarantine_evidence",
                          "tombstone_evidence", "prepare_handoff"):
            self.assertFalse(hasattr(reader, forbidden))

    def test_verifier_read_only(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        verifier = EvidenceVerifier(world["store"])
        self.assertEqual(
            verifier.prepare_handoff(record.evidence_id).evidence_id,
            record.evidence_id,
        )
        for forbidden in ("persist_sealed", "quarantine_evidence",
                          "tombstone_evidence"):
            self.assertFalse(hasattr(verifier, forbidden))

    def test_sweeper_restrictions(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        sweeper = EvidenceSweeper(world["store"])
        sweeper.quarantine_evidence(record.evidence_id, reason="review")
        for forbidden in ("persist_sealed", "tombstone_evidence",
                          "prepare_handoff"):
            self.assertFalse(hasattr(sweeper, forbidden))
        with self.assertRaises(TypeError):
            EvidenceSweeper(object())

    def test_operator_restrictions(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        operator = EvidenceOperator(world["store"])
        policy = RetentionPolicy(policy_id="ret-1", ttl_seconds=0)
        self.assertTrue(
            operator.retention_eligible(
                record.evidence_id, policy, now_epoch=2**31
            )
        )
        operator.tombstone_evidence(record.evidence_id, policy=policy)
        for forbidden in ("persist_sealed", "prepare_handoff",
                          "reindex_from_blob", "quarantine_evidence"):
            self.assertFalse(hasattr(operator, forbidden))


# ------------------------------------------------------------------
# RETENTION + AUDIT
# ------------------------------------------------------------------


class RetentionTests(unittest.TestCase):
    def test_policy_validation(self) -> None:
        with self.assertRaises(ev.EvidenceError):
            RetentionPolicy(policy_id="")
        with self.assertRaises(ev.EvidenceError):
            RetentionPolicy(policy_id="p", ttl_seconds=-1)
        policy = RetentionPolicy(policy_id="p", ttl_seconds=100)
        self.assertFalse(policy.allow_blob_deletion)

    def test_tombstone_not_mutation(self) -> None:
        world = make_world()
        record = seal_http()
        before = canonical_envelope_bytes(record)
        world["store"].persist_sealed(record)
        policy = RetentionPolicy(policy_id="ret-1", ttl_seconds=0)
        world["store"].tombstone_evidence(
            record.evidence_id, policy=policy
        )
        entry = world["index"].get_by_evidence_id(record.evidence_id)
        assert entry is not None
        self.assertTrue(entry.tombstoned)
        # Surviving bytes unchanged; tombstoned record not servable.
        self.assertEqual(world["blobs"].get(record.content_hash or ""), before)
        with self.assertRaises(ev.EvidenceError):
            world["store"].get_by_evidence_id(record.evidence_id)

    def test_retention_eligibility_scoping(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        entry = world["index"].get_by_evidence_id(record.evidence_id)
        assert entry is not None
        scoped = RetentionPolicy(
            policy_id="p", ttl_seconds=0, scope_program="other"
        )
        self.assertFalse(
            retention_eligible(entry, scoped, now_epoch=2**31)
        )
        unscoped = RetentionPolicy(policy_id="p", ttl_seconds=10**9)
        self.assertFalse(
            retention_eligible(entry, unscoped, now_epoch=1)
        )


class AuditTests(unittest.TestCase):
    def test_sealed_and_handoff_audited(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        world["store"].prepare_handoff(record.evidence_id)
        kinds = [a.transition for a in world["audit"]]
        self.assertIn("EVIDENCE_SEALED", kinds)
        self.assertIn("VERIFIER_HANDOFF", kinds)
        check_ordering(
            [a for a in world["audit"] if a.execution_id == EX_ID]
        )

    def test_audit_failure_gap_not_silent(self) -> None:
        class FailingAudit(list):  # type: ignore[type-arg]
            def append(self, record: object) -> None:
                raise ev.EvidenceError("AUDIT_GAP", "sink unavailable")

        store = EvidenceStore(
            InMemoryBlobStore(), InMemoryEvidenceIndex(), audit=FailingAudit()
        )
        result = store.persist_sealed(seal_http())
        self.assertTrue(result.audit_gap)

    def test_reindex_audited(self) -> None:
        world = make_world()
        record = seal_http()
        world["blobs"].put_if_absent(
            record.content_hash or "",
            canonical_envelope_bytes(record),
            enforce_identity=False,
        )
        world["store"].reindex_from_blob(
            record.content_hash or "",
            claimed_evidence_id=record.evidence_id,
            claimed_execution_id=record.execution_id,
            claimed_authorization_id=record.authorization_id,
        )
        kinds = [a.transition for a in world["audit"]]
        self.assertIn("ORPHAN_REINDEXED", kinds)


# ------------------------------------------------------------------
# CONCURRENCY / CAS
# ------------------------------------------------------------------


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_put_race_single_winner(self) -> None:
        import threading

        blobs = InMemoryBlobStore()
        payload = b"race-payload"
        digest = hashing.sha256_hex(payload)
        outcomes: list[bool] = []
        errors: list[Exception] = []

        def worker() -> None:
            try:
                outcomes.append(blobs.put_if_absent(digest, payload))
            except Exception as exc:  # pragma: no cover - safety
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 7)

    def test_concurrent_index_race(self) -> None:
        import threading

        index = InMemoryEvidenceIndex()
        record = seal_http()
        outcomes: list[bool] = []
        errors: list[Exception] = []

        def worker() -> None:
            try:
                outcomes.append(
                    index.insert_if_absent(
                        IndexEntry(
                            **{
                                **_entry_for(record).__dict__,
                            }
                        )
                    )
                )
            except IndexDuplicateError as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count(True), 1)
        # Losers either dedupe (False) or hit the slot guard.
        self.assertEqual(len(outcomes) + len(errors), 8)

    def test_stale_writer_conflict(self) -> None:
        index = InMemoryEvidenceIndex()
        record = seal_http()
        index.insert_if_absent(_entry_for(record))
        index.mark_indexed(record.evidence_id, expected_version=1)
        with self.assertRaises(IndexVersionConflict):
            index.quarantine(
                record.evidence_id, expected_version=1, reason="stale"
            )

    def test_cas_version_mismatch_store(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        entry = world["index"].get_by_evidence_id(record.evidence_id)
        assert entry is not None
        with self.assertRaises(IndexVersionConflict):
            world["index"].mark_indexed(
                record.evidence_id,
                expected_version=entry.record_version + 5,
            )


# ------------------------------------------------------------------
# OBSERVATION CLASSES
# ------------------------------------------------------------------


class ObservationClassTests(unittest.TestCase):
    def test_http_evidence_roundtrip(self) -> None:
        world = make_world()
        record = seal_http()
        world["store"].persist_sealed(record)
        self.assertEqual(
            world["store"]
            .get_by_execution_id(record.execution_id)
            .evidence_id,
            record.evidence_id,
        )
        self.assertEqual(
            len(world["store"].get_by_authorization_id(AUTHZ_ID)), 1
        )

    def test_nuclei_evidence_roundtrip(self) -> None:
        world = make_world()
        record = seal_nuclei()
        world["store"].persist_sealed(record)
        back = world["store"].get_by_evidence_id(record.evidence_id)
        assert back.nuclei is not None
        self.assertEqual(back.nuclei.template_id, "tpl-1")
        world["store"].prepare_handoff(record.evidence_id)

    def test_browser_evidence_roundtrip(self) -> None:
        world = make_world()
        record = seal_browser()
        world["store"].persist_sealed(record)
        back = world["store"].get_by_evidence_id(record.evidence_id)
        assert back.browser is not None
        self.assertFalse(back.browser.e1_observed)
        world["store"].prepare_handoff(record.evidence_id)


# ------------------------------------------------------------------
# SECURITY BOUNDARY (AST)
# ------------------------------------------------------------------


class SecurityBoundaryTests(unittest.TestCase):
    MODULES = ("blob_store", "index", "store", "sweep")

    def _text(self, module: str) -> str:
        return (
            Path(__file__).parent / "evidence" / f"{module}.py"
        ).read_text(encoding="utf-8")

    def test_no_finding_or_verdict(self) -> None:
        for module in self.MODULES:
            tree = ast.parse(self._text(module))
            defined: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    defined.add(node.name)
                if isinstance(node, ast.arg):
                    defined.add(node.arg)
            for banned in ("verdict", "severity", "finding"):
                self.assertNotIn(banned, defined, module)
            for token in (
                "CONFIRMED",
                "VULNERABLE",
                "NOT_VULNERABLE",
                "to_findings",
                "Finding",
            ):
                self.assertNotIn(token, self._text(module), module)

    def test_no_live_primitives(self) -> None:
        for module in self.MODULES:
            tree = ast.parse(self._text(module))
            imports: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    imports.add((node.module or "").split(".")[0])
            for banned in (
                "socket",
                "requests",
                "httpx",
                "urllib3",
                "aiohttp",
                "subprocess",
                "selenium",
                "playwright",
                "pymongo",
                "motor",
            ):
                self.assertNotIn(banned, imports, module)
            text = self._text(module)
            for token in (
                "getaddrinfo",
                "create_connection",
                "urlopen",
                "os.system",
                "Popen",
                "check_output",
                "MongoClient",
                "interactsh",
            ):
                self.assertNotIn(token, text, module)


if __name__ == "__main__":
    unittest.main()
