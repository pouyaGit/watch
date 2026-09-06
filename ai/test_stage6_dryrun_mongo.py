"""Stage 6 persistence-backed dry run against the dedicated test Mongo.

Skip-safe like the Stage 3 suite: every test SKIPS cleanly unless
``WATCH_TEST_MONGO_URI``/``WATCH_TEST_MONGO_DB`` explicitly select a
dedicated test database (production names refused). When a server is
present this proves, against REAL persistence: the complete dry-run
flow with durable records; restart/re-read across a fresh client;
orphan-sweep reindexing over real blob+index backends; and that no
production database, credential, or ``database.db`` path is ever
touched. Still zero live target traffic (the dry-run asserts its own
live gates closed).
"""

from __future__ import annotations

import unittest

from ai.evidence.store import EvidenceStore, canonical_envelope_bytes
from ai.evidence.sweep import discover_candidates, run_sweep
from ai.persistence.mongo_audit import AUDIT_UNIQUE_INDEXES, MongoAuditSink
from ai.persistence.mongo_authz import AUTHZ_UNIQUE_INDEXES, MongoAuthorizationStore
from ai.persistence.mongo_evidence import (
    BLOB_UNIQUE_INDEXES,
    INDEX_UNIQUE_INDEXES,
    MongoBlobStore,
    MongoEvidenceIndex,
)
from ai.persistence.mongo_ledger import LEDGER_UNIQUE_INDEXES, MongoExecutionLedger
from ai.stage1_offline_pipeline import EndpointView
from ai.stage2_dryrun import Stage2Config, Stage2Stores, run_stage2_dryrun
from ai.test_b3_mongo_integration import RealMongoCase, _resolve_test_target

PROGRAM = "acme"
HOST = "example.com"
SUBDOMAIN = "example.com"
IP_A = "8.8.8.8"


def _endpoint() -> EndpointView:
    return EndpointView(
        program_name=PROGRAM,
        subdomain=SUBDOMAIN,
        path="/search",
        example_url=f"https://{HOST}/search?q=1",
        params=("q",),
    )


def _config() -> Stage2Config:
    return Stage2Config(
        program_rows={
            PROGRAM: {"program_name": PROGRAM, "scopes": [HOST], "ooscopes": []}
        },
        asset_rows={(PROGRAM, SUBDOMAIN): [{"ips": [IP_A], "url": None}]},
    )


def _real_stores(case: RealMongoCase) -> Stage2Stores:
    authz_col, _ = case.mkcol("s6dry_authz", AUTHZ_UNIQUE_INDEXES)
    ledger_col, _ = case.mkcol("s6dry_ledger", LEDGER_UNIQUE_INDEXES)
    audit_col, _ = case.mkcol("s6dry_audit", AUDIT_UNIQUE_INDEXES)
    blob_col, _ = case.mkcol("s6dry_blob", BLOB_UNIQUE_INDEXES)
    index_col, _ = case.mkcol("s6dry_index", INDEX_UNIQUE_INDEXES)
    return Stage2Stores(
        authz=MongoAuthorizationStore(authz_col),
        ledger=MongoExecutionLedger(ledger_col),
        audit=MongoAuditSink(audit_col),
        blobs=MongoBlobStore(blob_col),
        index=MongoEvidenceIndex(index_col),
    )


class Stage6MongoDryRunTests(RealMongoCase):
    def test_real_mongo_dryrun_end_to_end(self) -> None:
        stores = _real_stores(self)
        result = run_stage2_dryrun(_endpoint(), _config(), stores=stores)
        self.assertTrue(result.verification_outcome.accepted)
        outcome = result.verification_outcome.result.outcome
        self.assertIn(outcome, ("UNKNOWN", "POTENTIAL"))
        self.assertNotEqual(outcome, "CONFIRMED")
        self.assertEqual(result.authorization.lifecycle, "CONSUMED")
        self.assertIsNotNone(result.materialization_outcome)
        self.assertFalse(result.materialization_outcome.accepted)
        self.assertIsNotNone(result.sweep_report)
        # Durable records exist on the server, not just in memory.
        authz_id = result.authorization.authorization_id
        self.assertIsNotNone(stores.authz.get(authz_id))
        execution_id = result.evidence_record.execution_id
        ledger_row = stores.ledger.get(execution_id)
        self.assertIsNotNone(ledger_row)
        self.assertEqual(ledger_row.lifecycle, "SEALED_REF")
        audit_rows = stores.audit.records_for(execution_id)
        self.assertTrue(len(audit_rows) >= 2)
        # Sealed envelopes are keyed by content_hash with
        # enforce_identity=False (payload is envelope bytes, whose
        # sha256 is not the content hash by design) — so assert
        # existence plus exact envelope bytes, not hash identity.
        self.assertTrue(
            stores.blobs.exists(result.evidence_record.content_hash)
        )
        self.assertEqual(
            stores.blobs.get(result.evidence_record.content_hash),
            canonical_envelope_bytes(result.evidence_record),
        )
        entry = stores.index.get_by_evidence_id(
            result.evidence_record.evidence_id
        )
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.content_hash, result.evidence_record.content_hash
        )

    def test_real_mongo_restart_reread(self) -> None:
        import pymongo as _pymongo

        from ai.test_b3_mongo_integration import PymongoCollectionAdapter

        stores = _real_stores(self)
        result = run_stage2_dryrun(_endpoint(), _config(), stores=stores)
        authz_id = result.authorization.authorization_id
        execution_id = result.evidence_record.execution_id
        evidence_id = result.evidence_record.evidence_id
        content_hash = result.evidence_record.content_hash
        # Fresh client, fresh adapters, same server collections:
        # everything must read back identical (hashes/IDs/references).
        target = _resolve_test_target()
        assert target is not None
        uri, db_name = target
        fresh = _pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        try:
            fresh_db = fresh[db_name]
            names = {name: None for name in self._owned}
            cols = {
                name: PymongoCollectionAdapter(fresh_db[name]) for name in names
            }
            authz2 = MongoAuthorizationStore(cols[self._owned[0]])
            ledger2 = MongoExecutionLedger(cols[self._owned[1]])
            audit2 = MongoAuditSink(cols[self._owned[2]])
            blobs2 = MongoBlobStore(cols[self._owned[3]])
            index2 = MongoEvidenceIndex(cols[self._owned[4]])
            reread_authz = authz2.get(authz_id)
            self.assertIsNotNone(reread_authz)
            self.assertEqual(
                reread_authz.artifact.content_hash,
                result.authorization.artifact.content_hash,
            )
            reread_row = ledger2.get(execution_id)
            self.assertIsNotNone(reread_row)
            self.assertEqual(reread_row.lifecycle, "SEALED_REF")
            self.assertTrue(len(audit2.records_for(execution_id)) >= 2)
            self.assertTrue(blobs2.exists(content_hash))
            reread_entry = index2.get_by_evidence_id(evidence_id)
            self.assertIsNotNone(reread_entry)
            self.assertEqual(reread_entry.content_hash, content_hash)
        finally:
            fresh.close()

    def test_real_mongo_orphan_sweep(self) -> None:
        stores = _real_stores(self)
        result = run_stage2_dryrun(_endpoint(), _config(), stores=stores)
        record = result.evidence_record
        orphan_blobs_col, _ = self.mkcol("s6dry_orphan_blob", BLOB_UNIQUE_INDEXES)
        orphan_index_col, _ = self.mkcol("s6dry_orphan_index", INDEX_UNIQUE_INDEXES)
        orphan_blobs = MongoBlobStore(orphan_blobs_col)
        orphan_index = MongoEvidenceIndex(orphan_index_col)
        orphan_blobs.put_if_absent(
            record.content_hash,
            canonical_envelope_bytes(record),
            enforce_identity=False,
        )
        candidates = discover_candidates(
            blobs=orphan_blobs,
            index=orphan_index,
            now_epoch="2026-06-01T00:00:00+00:00",
            grace_seconds=0,
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].orphan_class, "INDEX_MISSING_SEALED")
        store = EvidenceStore(orphan_blobs, orphan_index, ledger=None, audit=[])
        report = run_sweep(
            store=store,
            blobs=orphan_blobs,
            index=orphan_index,
            now_epoch="2026-06-01T00:00:00+00:00",
        )
        self.assertEqual(report.reindexed, [record.evidence_id])
        self.assertEqual(report.quarantined, [])
        self.assertIsNotNone(
            orphan_index.get_by_evidence_id(record.evidence_id)
        )

    def test_real_mongo_never_touches_production(self) -> None:
        import pymongo as _pymongo

        target = _resolve_test_target()
        assert target is not None
        uri, db_name = target
        self.assertNotIn(db_name, ("watch", "admin", "local", "config"))
        self.assertNotIn("/watch?", uri)
        self.assertNotIn("/watch/", uri.split("?", 1)[0].rsplit("/", 1)[-1:])
        probe = _pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        try:
            host, _port = probe.address
            self.assertIn(host, ("127.0.0.1", "localhost"))
            for name in self._db.list_collection_names():
                self.assertTrue(
                    name.startswith("b3t_") or name.startswith("system."),
                    f"unexpected collection: {name}",
                )
        finally:
            probe.close()
        from ai.execution import http_executor as hx
        from ai.execution import nuclei_executor as nx

        self.assertIs(hx.LIVE_TRAFFIC_ENABLED, False)
        self.assertIs(nx.LIVE_NUCLEI, False)
        import sys as _sys

        self.assertNotIn("database.db", _sys.modules)


if __name__ == "__main__":
    unittest.main()
