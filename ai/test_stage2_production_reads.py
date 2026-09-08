"""Stage 2 B1+B2 tests (persistence seams, still fully dry-run).

Stdlib ``unittest`` only. No network, no DNS, no sockets, no
subprocess, no MongoDB server, no browser, no Nuclei, no LLM, no
Git. Every Mongo-shaped adapter runs over ``FakeMongoCollection``;
no production credentials exist anywhere in this file.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from ai.authorizer import store as authz_store_mod
from ai.authorizer.service import (
    consume_authorization,
    get_issued_authorization,
    issue_authorization,
    revoke_authorization,
)
from ai.authorizer.store import (
    AuthorizationStore,
    DuplicateIdempotencyKeyError,
    InMemoryAuthorizationStore,
    RecordNotFoundError,
    VersionConflictError,
)
from ai.execution.ledger import (
    DuplicateExecutionError,
    ExecutionRecord,
    InProgressExecutionError,
    InMemoryExecutionLedger,
    LedgerError,
    ReplayExecutionError,
)
from ai.evidence import hashing as hash_mod
from ai.evidence.blob_store import InMemoryBlobStore
from ai.evidence.index import (
    IndexDuplicateError,
    IndexEntry,
    IndexVersionConflict,
    InMemoryEvidenceIndex,
)
from ai.evidence.store import EvidenceStore, canonical_envelope_bytes
from ai.evidence.sweep import discover_candidates, run_sweep
from ai.persistence.driver import (
    DuplicateKeyError,
    FakeMongoCollection,
    MongoUnavailableError,
)
from ai.persistence.mongo_audit import AUDIT_UNIQUE_INDEXES, MongoAuditSink
from ai.persistence.mongo_authz import AUTHZ_UNIQUE_INDEXES, MongoAuthorizationStore
from ai.persistence.mongo_evidence import (
    BLOB_UNIQUE_INDEXES,
    INDEX_UNIQUE_INDEXES,
    MongoBlobStore,
    MongoEvidenceIndex,
)
from ai.persistence.mongo_ledger import LEDGER_UNIQUE_INDEXES, MongoExecutionLedger
from ai.persistence.watch_reads import (
    DictAssetReader,
    DictProgramReader,
    MongoAssetReader,
    MongoProgramReader,
    WatchReadError,
    address_facts_for,
    policy_for_program,
)
from ai.audit.trail import AuditRecord
from ai.resolver.dns import DnsError
from ai.resolver.inventory_addresses import AddressReview, InventoryAddressSource
from ai.schemas import evidence as ev
from ai.stage1_offline_pipeline import EndpointView
from ai.stage2_dryrun import (
    Stage2Config,
    Stage2Error,
    default_stage2_stores,
    run_stage2_dryrun,
)

import ai.persistence.driver as driver_mod
import ai.persistence.mongo_authz as mongo_authz_mod
import ai.persistence.mongo_ledger as mongo_ledger_mod
import ai.persistence.mongo_audit as mongo_audit_mod
import ai.persistence.mongo_evidence as mongo_evidence_mod
import ai.persistence.watch_reads as watch_reads_mod
import ai.resolver.inventory_addresses as b1_mod
import ai.stage2_dryrun as stage2_mod

PROGRAM = "acme"
HOST = "example.com"
SUBDOMAIN = "example.com"
NOW = "2026-01-15T00:00:00+00:00"
ISSUED_AT = "2026-01-01T00:00:00+00:00"
EXPIRES_AT = "2026-02-01T00:00:00+00:00"
IP_A = "8.8.8.8"
IP_B = "8.8.4.4"

TP_ID = "tp-" + "a" * 16
HYP_ID = "hyp-" + "b" * 16
EX_ID = "ex-" + "c" * 32


def _endpoint(**overrides) -> EndpointView:
    base = {
        "program_name": PROGRAM,
        "subdomain": SUBDOMAIN,
        "path": "/search",
        "example_url": f"https://{HOST}/search?q=1",
        "params": ("q",),
    }
    base.update(overrides)
    return EndpointView(**base)


def _config(**overrides) -> Stage2Config:
    base = {
        "program_rows": {
            PROGRAM: {
                "program_name": PROGRAM,
                "scopes": [HOST],
                "ooscopes": [],
            }
        },
        "asset_rows": {
            (PROGRAM, SUBDOMAIN): [{"ips": [IP_A], "url": None}]
        },
    }
    base.update(overrides)
    return Stage2Config(**base)


def _authz_request():
    from ai.schemas.artifact import artifact_id_for, content_hash_for_bytes
    from ai.schemas.execution_authorization import ArtifactBinding, TargetBinding
    from ai.schemas.execution_authorization import AuthorizationRequest
    from ai.resolver.inventory import scope_lists_hash_for

    content = b'{"body":null,"headers":{},"method":"GET","path":"/search","query_params":{"q":""}}'
    digest = content_hash_for_bytes(content)
    artifact_id = artifact_id_for(
        artifact_type="http_request_spec",
        test_plan_id=TP_ID,
        content_hash=digest,
    )
    return AuthorizationRequest(
        test_plan_id=TP_ID,
        hypothesis_id=HYP_ID,
        artifact=ArtifactBinding(
            artifact_id=artifact_id,
            artifact_type="http_request_spec",
            content_hash=digest,
            test_plan_id=TP_ID,
            hypothesis_id=HYP_ID,
        ),
        target=TargetBinding(
            program_name=PROGRAM,
            host=HOST,
            scheme="https",
            effective_port=443,
            scope_lists_hash=scope_lists_hash_for([HOST], []),
        ),
        execution_class="http_probe",
        execution_phase="single",
        plan_method="GET",
        artifact_method="GET",
        expires_at=EXPIRES_AT,
        caller_scope="manual",
        issuer_identity="human-review-board",
    )


def _mongo_authz_store() -> MongoAuthorizationStore:
    return MongoAuthorizationStore(
        FakeMongoCollection(list(AUTHZ_UNIQUE_INDEXES))
    )


# ------------------------------------------------------------------
# 5B service accepts the protocol (contract extension, same semantics)
# ------------------------------------------------------------------


class ServiceProtocolTests(unittest.TestCase):
    def test_issue_consume_revoke_over_mongo_store(self) -> None:
        store = _mongo_authz_store()
        first = issue_authorization(store, _authz_request(), now=ISSUED_AT)
        # Idempotent re-issuance returns the same record.
        second = issue_authorization(store, _authz_request(), now=ISSUED_AT)
        self.assertEqual(
            first.authorization_id, second.authorization_id
        )
        live = get_issued_authorization(store, first.authorization_id)
        self.assertIsNotNone(live)
        consumed = consume_authorization(
            store, first.authorization_id, now=NOW
        )
        self.assertEqual(consumed.lifecycle, "CONSUMED")
        # Second consume fails closed (already consumed).
        from ai.schemas.execution_authorization import AuthzError

        with self.assertRaises(AuthzError):
            consume_authorization(store, first.authorization_id, now=NOW)

    def test_revoke_over_mongo_store(self) -> None:
        store = _mongo_authz_store()
        issued = issue_authorization(store, _authz_request(), now=ISSUED_AT)
        revoked = revoke_authorization(store, issued.authorization_id)
        self.assertEqual(revoked.lifecycle, "REVOKED")

    def test_dicts_still_rejected(self) -> None:
        store = _mongo_authz_store()
        with self.assertRaises(TypeError):
            issue_authorization(store, {}, now=ISSUED_AT)
        with self.assertRaises(TypeError):
            get_issued_authorization({}, "authz-" + "0" * 16)

    def test_protocol_is_runtime_checkable(self) -> None:
        self.assertTrue(
            isinstance(_mongo_authz_store(), AuthorizationStore)
        )
        self.assertTrue(
            isinstance(InMemoryAuthorizationStore(), AuthorizationStore)
        )
        self.assertFalse(isinstance({}, AuthorizationStore))

    def test_corrupt_row_never_becomes_authority(self) -> None:
        store = _mongo_authz_store()
        issued = issue_authorization(store, _authz_request(), now=ISSUED_AT)
        collection = store._collection
        raw = collection.raw(issued.authorization_id)
        raw["document"]["lifecycle"] = "SUPERUSER"
        collection.replace_one({"_id": issued.authorization_id}, raw)
        self.assertIsNone(
            get_issued_authorization(store, issued.authorization_id)
        )


# ------------------------------------------------------------------
# Authz adapter CAS parity
# ------------------------------------------------------------------


class MongoAuthzAdapterTests(unittest.TestCase):
    def test_cas_conflict_and_rebind(self) -> None:
        store = _mongo_authz_store()
        issued = issue_authorization(store, _authz_request(), now=ISSUED_AT)
        progressed = issued.model_copy(
            update={"lifecycle": "CONSUMED", "record_version": 2}
        )
        # Wrong expected version.
        with self.assertRaises(VersionConflictError):
            store.compare_and_swap(issued.authorization_id, 99, progressed)
        # Identity rebind.
        other = progressed.model_copy(
            update={"authorization_id": "authz-" + "f" * 16}
        )
        with self.assertRaises(Exception):
            store.compare_and_swap(issued.authorization_id, 1, other)
        # Missing row.
        with self.assertRaises(RecordNotFoundError):
            store.compare_and_swap(
                "authz-" + "e" * 16, 1, progressed
            )

    def test_driver_outage_fails_closed(self) -> None:
        store = _mongo_authz_store()
        store._collection.fail_always()
        with self.assertRaises(MongoUnavailableError):
            issue_authorization(store, _authz_request(), now=ISSUED_AT)


# ------------------------------------------------------------------
# Ledger adapter parity
# ------------------------------------------------------------------


def _ledger_row(execution_id: str = EX_ID) -> ExecutionRecord:
    return ExecutionRecord(
        execution_id=execution_id,
        authorization_id="authz-" + "b" * 16,
        execution_stage="single",
        idempotency_key="0" * 64,
    )


class MongoLedgerAdapterTests(unittest.TestCase):
    def _ledger(self) -> MongoExecutionLedger:
        return MongoExecutionLedger(
            FakeMongoCollection(list(LEDGER_UNIQUE_INDEXES))
        )

    def test_full_lifecycle_and_replay(self) -> None:
        ledger = self._ledger()
        ledger.put_new(_ledger_row())
        # Same slot replay.
        with self.assertRaises(ReplayExecutionError):
            ledger.put_new(_ledger_row(execution_id="ex-" + "d" * 32))
        # Same key, different execution.
        other = _ledger_row(execution_id="ex-" + "d" * 32).model_copy(
            update={"authorization_id": "authz-" + "c" * 16,
                    "execution_stage": "oracle"}
        )
        with self.assertRaises(DuplicateExecutionError):
            ledger.put_new(other)
        started = ledger.mark_started(EX_ID, started_at=NOW)
        self.assertEqual(started.lifecycle, "STARTED")
        with self.assertRaises(InProgressExecutionError):
            ledger.mark_started(EX_ID, started_at=NOW)
        sealed = ledger.mark_sealed(EX_ID, "ev-" + "1" * 32, terminal_at=NOW)
        self.assertEqual(sealed.lifecycle, "SEALED_REF")
        with self.assertRaises(LedgerError):
            ledger.mark_sealed(EX_ID, "ev-" + "1" * 32, terminal_at=NOW)

    def test_unknown_and_cas(self) -> None:
        ledger = self._ledger()
        ledger.put_new(_ledger_row())
        ledger.mark_started(EX_ID, started_at=NOW)
        unknown = ledger.mark_unknown(EX_ID, terminal_at=NOW)
        self.assertEqual(unknown.lifecycle, "UNKNOWN")
        current = ledger.get(EX_ID)
        with self.assertRaises(LedgerError):
            ledger.compare_and_swap(
                EX_ID,
                current.record_version + 5,
                current.model_copy(
                    update={"record_version": current.record_version + 6}
                ),
            )

    def test_driver_outage_fails_closed(self) -> None:
        ledger = self._ledger()
        ledger._collection.fail_always()
        with self.assertRaises(MongoUnavailableError):
            ledger.put_new(_ledger_row())


# ------------------------------------------------------------------
# Audit adapter
# ------------------------------------------------------------------


def _audit_record(seq: int = 0) -> AuditRecord:
    return AuditRecord(
        seq=seq,
        execution_id=EX_ID,
        authorization_id="authz-" + "b" * 16,
        transition="AUTHORIZATION",
        at=NOW,
        actor="stage2-test",
        program_name=PROGRAM,
        host=HOST,
    )


class MongoAuditAdapterTests(unittest.TestCase):
    def _sink(self) -> MongoAuditSink:
        return MongoAuditSink(
            FakeMongoCollection(list(AUDIT_UNIQUE_INDEXES))
        )

    def test_append_orders_and_rejects_duplicates(self) -> None:
        sink = self._sink()
        sink.append(_audit_record(0))
        sink.append(_audit_record(1))
        rows = sink.records_for(EX_ID)
        self.assertEqual([row.seq for row in rows], [0, 1])
        from ai.persistence.mongo_audit import AuditPersistenceError

        with self.assertRaises(AuditPersistenceError):
            sink.append(_audit_record(0))
        with self.assertRaises(TypeError):
            sink.append({"seq": 9})

    def test_driver_outage_fails_closed(self) -> None:
        sink = self._sink()
        sink._collection.fail_always()
        with self.assertRaises(MongoUnavailableError):
            sink.append(_audit_record(0))


# ------------------------------------------------------------------
# Evidence adapters
# ------------------------------------------------------------------


class MongoEvidenceAdapterTests(unittest.TestCase):
    def _stores(self):
        blobs = MongoBlobStore(
            FakeMongoCollection(list(BLOB_UNIQUE_INDEXES))
        )
        index = MongoEvidenceIndex(
            FakeMongoCollection(list(INDEX_UNIQUE_INDEXES))
        )
        return blobs, index

    def _entry(self, evidence_id: str = "ev-" + "1" * 32) -> IndexEntry:
        return IndexEntry(
            evidence_id=evidence_id,
            execution_id=EX_ID,
            authorization_id="authz-" + "b" * 16,
            execution_stage="single",
            execution_class="http_probe",
            content_hash="a" * 64,
            bindings_hash="b" * 64,
            observations_hash="c" * 64,
            artifact_id="art-" + "d" * 16,
            program_name=PROGRAM,
        )

    def test_blob_put_get_dedupe_collision(self) -> None:
        blobs, _ = self._stores()
        payload = b'{"sealed": true}'
        key = hash_mod.sha256_hex(payload)
        self.assertTrue(blobs.put_if_absent(key, payload))
        self.assertFalse(blobs.put_if_absent(key, payload))
        self.assertEqual(blobs.get(key), payload)
        self.assertTrue(blobs.verify(key))
        with self.assertRaises(ev.EvidenceError):
            blobs.put_if_absent(key, b'{"sealed": false}')
        blobs.quarantine(key, reason="test-quarantine")
        self.assertTrue(blobs.quarantined(key))

    def test_index_insert_cas_lifecycle(self) -> None:
        _, index = self._stores()
        entry = self._entry()
        self.assertTrue(index.insert_if_absent(entry))
        self.assertFalse(index.insert_if_absent(entry))
        with self.assertRaises(IndexDuplicateError):
            import dataclasses

            index.insert_if_absent(
                dataclasses.replace(entry, content_hash="f" * 64)
            )
        self.assertIsNotNone(index.get_by_evidence_id(entry.evidence_id))
        self.assertIsNotNone(index.get_by_execution_id(EX_ID))
        self.assertEqual(
            len(index.get_by_authorization_id("authz-" + "b" * 16)), 1
        )
        self.assertEqual(len(index.lookup_by_content_hash("a" * 64)), 1)
        marked = index.mark_indexed(
            entry.evidence_id, expected_version=1, indexed_at=NOW
        )
        self.assertEqual(marked.lifecycle, "INDEXED")
        with self.assertRaises(IndexVersionConflict):
            index.mark_indexed(
                entry.evidence_id, expected_version=1, indexed_at=NOW
            )

    def test_driver_outage_fails_closed(self) -> None:
        blobs, index = self._stores()
        blobs._collection.fail_always()
        with self.assertRaises(MongoUnavailableError):
            blobs.put_if_absent("a" * 64, b"x", enforce_identity=False)
        index._collection.fail_always()
        with self.assertRaises(MongoUnavailableError):
            index.insert_if_absent(self._entry())


# ------------------------------------------------------------------
# B1 address source
# ------------------------------------------------------------------


def _review(host: str = HOST, addresses=(IP_A,)) -> AddressReview:
    return AddressReview(
        program_name=PROGRAM,
        canonical_host=host,
        addresses=tuple(addresses),
        source="watch-inventory:Http.ips",
        reviewer="stage2-test",
        reviewed_at=NOW,
    )


class B1AddressSourceTests(unittest.TestCase):
    def test_serves_reviewed_facts_without_dns(self) -> None:
        source = InventoryAddressSource(
            program_name=PROGRAM, reviews=[_review()]
        )
        self.assertEqual(source.resolve(HOST), (IP_A,))

    def test_unknown_host_has_no_fallback(self) -> None:
        source = InventoryAddressSource(
            program_name=PROGRAM, reviews=[_review()]
        )
        with self.assertRaises(DnsError) as ctx:
            source.resolve("unknown.example.com")
        self.assertEqual(ctx.exception.code, "DNS_NXDOMAIN")

    def test_conflicting_facts_fail_closed(self) -> None:
        source = InventoryAddressSource(
            program_name=PROGRAM,
            reviews=[_review(addresses=(IP_A,)), _review(addresses=(IP_B,))],
        )
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_RESOLUTION_FAILED")

    def test_unsafe_facts_fail_whole_set(self) -> None:
        source = InventoryAddressSource(
            program_name=PROGRAM, reviews=[_review(addresses=("127.0.0.1",))]
        )
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_UNSAFE_ADDRESS")

    def test_stale_facts_fail_closed(self) -> None:
        source = InventoryAddressSource(
            program_name=PROGRAM,
            reviews=[_review()],
            max_age_seconds=60,
            now_iso="2026-06-01T00:00:00+00:00",
        )
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_RESOLUTION_FAILED")

    def test_empty_review_rejected_at_construction(self) -> None:
        with self.assertRaises(ValueError):
            AddressReview(
                program_name=PROGRAM,
                canonical_host=HOST,
                addresses=(),
                reviewed_at=NOW,
            )

    def test_cross_program_review_rejected(self) -> None:
        with self.assertRaises(ValueError):
            InventoryAddressSource(
                program_name="other",
                reviews=[_review()],
            )


# ------------------------------------------------------------------
# Watch read path
# ------------------------------------------------------------------


class WatchReadsTests(unittest.TestCase):
    def test_policy_from_live_row(self) -> None:
        reader = DictProgramReader(
            {PROGRAM: {"program_name": PROGRAM, "scopes": [HOST],
                       "ooscopes": []}}
        )
        policy = policy_for_program(reader, PROGRAM)
        self.assertIsNotNone(policy)
        self.assertEqual(
            policy.scope_lists_hash,
            reader.get_program_row(PROGRAM) and policy.scope_lists_hash,
        )

    def test_missing_program_is_none(self) -> None:
        reader = DictProgramReader({})
        self.assertIsNone(policy_for_program(reader, "ghost"))

    def test_malformed_row_fails_closed(self) -> None:
        reader = DictProgramReader(
            {PROGRAM: {"program_name": PROGRAM, "scopes": "nope",
                       "ooscopes": []}}
        )
        with self.assertRaises(WatchReadError):
            policy_for_program(reader, PROGRAM)

    def test_mongo_readers_over_fake_driver(self) -> None:
        programs = FakeMongoCollection()
        programs.insert_one(
            {"_id": PROGRAM, "program_name": PROGRAM, "scopes": [HOST],
             "ooscopes": []}
        )
        http = FakeMongoCollection()
        http.insert_one(
            {"_id": "h1", "program_name": PROGRAM, "subdomain": SUBDOMAIN,
             "ips": [IP_A], "url": None}
        )
        live = FakeMongoCollection()
        live.insert_one(
            {"_id": "l1", "program_name": PROGRAM, "subdomain": SUBDOMAIN,
             "ips": [IP_B], "url": None}
        )
        program_reader = MongoProgramReader(programs)
        asset_reader = MongoAssetReader(http=http, live=live)
        policy = policy_for_program(program_reader, PROGRAM)
        self.assertIsNotNone(policy)
        facts = address_facts_for(asset_reader, PROGRAM, SUBDOMAIN)
        self.assertEqual(facts, tuple(sorted({IP_A, IP_B})))
        self.assertEqual(
            address_facts_for(asset_reader, PROGRAM, "ghost.example.com"), ()
        )

    def test_no_database_db_import(self) -> None:
        for module in ("database.db", "mongoengine", "pymongo"):
            self.assertNotIn(module, sys.modules)


# ------------------------------------------------------------------
# Stage 2 dry-run (+ replay/dedupe/safety battery)
# ------------------------------------------------------------------


class Stage2DryRunTests(unittest.TestCase):
    def test_persistence_backed_dryrun(self) -> None:
        result = run_stage2_dryrun(_endpoint(), _config())
        self.assertTrue(result.verification_outcome.accepted)
        outcome = result.verification_outcome.result.outcome
        self.assertIn(outcome, ("UNKNOWN", "POTENTIAL"))
        self.assertNotEqual(outcome, "CONFIRMED")
        # Consumed authorization is the expected post-execution state.
        self.assertEqual(result.authorization.lifecycle, "CONSUMED")
        # 5J dry-run refuses non-CONFIRMED without error.
        self.assertIsNotNone(result.materialization_outcome)
        self.assertFalse(result.materialization_outcome.accepted)
        # Sweep ran in report mode over the mongo-backed seams.
        self.assertIsNotNone(result.sweep_report)
        self.assertEqual(result.sweep_report.reindexed, [])
        self.assertEqual(result.sweep_report.quarantined, [])

    def test_scope_drift_fails_closed(self) -> None:
        config = _config(post_issuance_scopes=([], []))
        with self.assertRaises(Stage2Error) as ctx:
            run_stage2_dryrun(_endpoint(), config)
        self.assertEqual(ctx.exception.code, "RESOLUTION_FAILED")

    def test_scope_hash_unchanged_allows(self) -> None:
        result = run_stage2_dryrun(_endpoint(), _config())
        self.assertEqual(result.scope_evaluation.decision, "ALLOWED")

    def test_missing_program_fails_closed(self) -> None:
        with self.assertRaises(Stage2Error) as ctx:
            run_stage2_dryrun(_endpoint(), _config(program_rows={}))
        self.assertEqual(ctx.exception.code, "PROGRAM_UNKNOWN")

    def test_missing_addresses_no_fallback(self) -> None:
        with self.assertRaises(Stage2Error) as ctx:
            run_stage2_dryrun(_endpoint(), _config(asset_rows={}))
        self.assertEqual(ctx.exception.code, "RESOLUTION_FAILED")

    def test_excluded_host_denied(self) -> None:
        endpoint = _endpoint(
            subdomain="excluded.example.com",
            example_url="https://excluded.example.com/search?q=1",
        )
        config = _config(
            program_rows={
                PROGRAM: {"program_name": PROGRAM, "scopes": [HOST],
                          "ooscopes": ["excluded.example.com"]}
            },
            asset_rows={
                (PROGRAM, "excluded.example.com"): [
                    {"ips": [IP_A], "url": None}
                ]
            },
        )
        with self.assertRaises(Stage2Error) as ctx:
            run_stage2_dryrun(endpoint, config)
        self.assertIn(
            ctx.exception.code, ("RESOLUTION_FAILED", "SCOPE_DENIED")
        )

    def test_mongo_outage_no_unsafe_continuation(self) -> None:
        stores = default_stage2_stores()
        stores.authz_collection.fail_always()
        with self.assertRaises(Stage2Error) as ctx:
            run_stage2_dryrun(_endpoint(), _config(), stores=stores)
        self.assertEqual(ctx.exception.code, "AUTHZ_FAILED")


class ReplayDedupeTests(unittest.TestCase):
    def test_duplicate_evidence_persist_dedupes(self) -> None:
        result = run_stage2_dryrun(_endpoint(), _config())
        record = result.evidence_record
        blobs = MongoBlobStore(
            FakeMongoCollection(list(BLOB_UNIQUE_INDEXES))
        )
        index = MongoEvidenceIndex(
            FakeMongoCollection(list(INDEX_UNIQUE_INDEXES))
        )
        store = EvidenceStore(blobs, index, ledger=None, audit=[])
        first = store.persist_sealed(record)
        second = store.persist_sealed(record)
        self.assertFalse(first.deduped)
        self.assertTrue(second.deduped)
        self.assertEqual(first.content_hash, second.content_hash)

    def test_orphan_sweep_reindexes_without_deletion(self) -> None:
        result = run_stage2_dryrun(_endpoint(), _config())
        record = result.evidence_record
        blobs = MongoBlobStore(
            FakeMongoCollection(list(BLOB_UNIQUE_INDEXES))
        )
        index = MongoEvidenceIndex(
            FakeMongoCollection(list(INDEX_UNIQUE_INDEXES))
        )
        # Blob bytes present, index entry absent: orphan by construction.
        # (The blob key is the sealed content_hash, not the envelope
        # digest — identical to how EvidenceStore persists.)
        blobs.put_if_absent(
            record.content_hash, canonical_envelope_bytes(record),
            enforce_identity=False,
        )
        candidates = discover_candidates(
            blobs=blobs, index=index, now_epoch="2026-06-01T00:00:00+00:00",
            grace_seconds=0,
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].orphan_class, "INDEX_MISSING_SEALED")
        store = EvidenceStore(blobs, index, ledger=None, audit=[])
        report = run_sweep(
            store=store, blobs=blobs, index=index,
            now_epoch="2026-06-01T00:00:00+00:00",
        )
        self.assertEqual(report.reindexed, [record.evidence_id])
        self.assertEqual(report.quarantined, [])
        self.assertIsNotNone(index.get_by_evidence_id(record.evidence_id))


class Stage2SafetyTests(unittest.TestCase):
    def test_live_gates_closed(self) -> None:
        from ai.execution import http_executor as hx
        from ai.execution import nuclei_executor as nx

        self.assertIs(hx.LIVE_TRAFFIC_ENABLED, False)
        self.assertIs(nx.LIVE_NUCLEI, False)

    def test_no_live_or_legacy_execution(self) -> None:
        before = set(sys.modules)
        run_stage2_dryrun(_endpoint(), _config())
        introduced = set(sys.modules) - before
        for module in ("database.db", "playwright", "pymongo", "mongoengine"):
            self.assertNotIn(module, introduced)
        for name in (
            "ai.stage1_offline_pipeline",
            "ai.stage2_dryrun",
            "ai.persistence.driver",
            "ai.persistence.mongo_authz",
            "ai.persistence.mongo_ledger",
            "ai.persistence.mongo_audit",
            "ai.persistence.mongo_evidence",
            "ai.persistence.watch_reads",
            "ai.resolver.inventory_addresses",
        ):
            source = Path(sys.modules[name].__file__).read_text(
                encoding="utf-8"
            )
            imports = [
                line.strip()
                for line in source.splitlines()
                if line.strip().startswith(("import ", "from "))
            ]
            for line in imports:
                self.assertNotIn("database.db", line)
                self.assertNotIn("socket", line)
                self.assertNotIn("subprocess", line)
                self.assertNotIn("playwright", line)
                self.assertNotIn("verification.verifier", line)
                self.assertNotIn("verification.http_executor", line)
                self.assertNotIn("verification.browser_executor", line)
                self.assertNotIn("verification.composite_executor", line)
                self.assertNotIn("verification.xss_pipeline", line)
                self.assertNotIn("deterministic.materialization", line)
                self.assertNotIn("XssFindings", line)
        import ai.resolver.inventory_addresses as b1

        self.assertNotIn("socket", dir(b1))

    def test_no_authorization_or_scope_bypass(self) -> None:
        # Double-consume is rejected; scope verdicts come only from
        # the frozen evaluator (DENIED tested above).
        stores = default_stage2_stores()
        result = run_stage2_dryrun(_endpoint(), _config(), stores=stores)
        from ai.schemas.execution_authorization import AuthzError

        with self.assertRaises(AuthzError):
            consume_authorization(
                stores.authz,
                result.authorization.authorization_id,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
