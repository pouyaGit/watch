"""Stage 3 real-Mongo integration (optional, skip-safe).

Validates the Stage 2 Mongo adapters against a REAL server: unique
index enforcement, duplicate/idempotency behavior, CAS races under
thread concurrency, ledger slot uniqueness, evidence duplicate
persistence, audit append-only uniqueness, and driver failure mapping.

SAFETY (hard rules, all test-enforced):

- These tests NEVER connect unless ``WATCH_TEST_MONGO_URI`` is
  explicitly set in the environment. When absent (or when ``pymongo``
  is unavailable, or the server is unreachable), every test SKIPS
  cleanly — never fails, never falls back, never touches anything.
- Production ``.env`` files are NEVER read automatically; only the two
  ``WATCH_TEST_MONGO_*`` variables are consulted.
- The production database name (``watch``) plus ``admin``/``local``/
  ``config`` are REFUSED: if the resolved test database name (or the
  database path embedded in the URI) matches, the suite skips instead
  of connecting.
- Tests create/drop ONLY their dedicated ``b3t_*`` collections inside
  the dedicated test database. No other database or collection is
  created, read, or dropped.
- Connection strings and credentials NEVER enter assertion messages,
  error details, or logs (all user-visible strings are static).

Concurrency expectations: the domain-level conflict errors
(``DuplicateIdempotencyKeyError`` / ``VersionConflictError`` /
``ReplayExecutionError`` / ``DuplicateExecutionError`` /
``InProgressExecutionError`` / ``AuditPersistenceError`` /
``EVIDENCE_*``) must remain UNCHANGED under races — exactly one thread
wins, every loser maps to the domain conflict, nothing is swallowed.
"""

from __future__ import annotations

import hashlib
import os
import threading
import unittest
from unittest import mock
from urllib.parse import urlsplit

TEST_URI_ENV = "WATCH_TEST_MONGO_URI"
TEST_DB_ENV = "WATCH_TEST_MONGO_DB"
DEFAULT_TEST_DB = "watch_b3_stage3_test"

#: Database names this suite refuses to touch (production first).
FORBIDDEN_DATABASES = frozenset({"watch", "admin", "local", "config"})

_COLLECTION_PREFIX = "b3t_"


def _resolve_test_target() -> tuple[str, str] | None:
    """Return ``(uri, db_name)`` or ``None`` when the suite must skip.

    Refusals (return ``None`` → skip) are fail-safe: a forbidden
    database name or an unreadable URI can never become a connection.
    The URI itself is never logged or embedded in messages.
    """

    uri = (os.environ.get(TEST_URI_ENV) or "").strip()
    if not uri:
        return None
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    if parts.scheme not in ("mongodb", "mongodb+srv"):
        return None
    embedded = (parts.path or "").strip("/").split("/")[0]
    if embedded in FORBIDDEN_DATABASES:
        return None
    db_name = (os.environ.get(TEST_DB_ENV) or "").strip() or DEFAULT_TEST_DB
    if db_name in FORBIDDEN_DATABASES or "/" in db_name or not db_name:
        return None
    return uri, db_name


class PymongoCollectionAdapter:
    """Narrow driver-surface adapter over a real ``pymongo`` collection.

    Implements exactly the ``MongoCollection`` subset
    (``find_one``/``find``/``insert_one``/``replace_one``) so the
    production adapters run unmodified. ``pymongo`` duplicate-key
    failures map to the fake driver's ``DuplicateKeyError`` message;
    every other driver/connectivity failure maps to
    ``MongoUnavailableError`` (fail closed). No URI, credential, or
    payload bytes ever enter an exception message.
    """

    def __init__(self, collection) -> None:
        for method in ("find_one", "find", "insert_one", "replace_one"):
            if not callable(getattr(collection, method, None)):
                raise TypeError(f"collection missing driver method: {method}")
        self._collection = collection

    def _unavailable(self, exc: BaseException):
        from ai.persistence.driver import MongoUnavailableError

        raise MongoUnavailableError("store unavailable") from exc

    def find_one(self, filter):  # noqa: A002
        try:
            return self._collection.find_one(dict(filter))
        except Exception as exc:
            raise self._unavailable(exc)

    def find(self, filter):  # noqa: A002
        try:
            return list(self._collection.find(dict(filter)))
        except Exception as exc:
            raise self._unavailable(exc)

    def insert_one(self, document: dict) -> None:
        from ai.persistence.driver import DuplicateKeyError

        try:
            self._collection.insert_one(dict(document))
        except Exception as exc:
            if type(exc).__name__ == "DuplicateKeyError":
                raise DuplicateKeyError("unique index collision; refused") from exc
            raise self._unavailable(exc)

    def replace_one(self, filter, replacement: dict) -> bool:  # noqa: A002
        try:
            result = self._collection.replace_one(dict(filter), dict(replacement))
        except Exception as exc:
            raise self._unavailable(exc)
        return bool(result.matched_count)


def _ensure_unique_indexes(raw_collection, index_sets) -> None:
    for fields in index_sets:
        if fields == ("_id",):
            continue  # MongoDB enforces _id uniqueness by construction.
        raw_collection.create_index(
            [(field, 1) for field in fields],
            unique=True,
            name="b3t_" + "_".join(fields),
        )


def _run_concurrent(count, func):
    """Run ``func(slot)`` on ``count`` threads; return ordered outcomes."""

    outcomes: list = [None] * count
    barrier = threading.Barrier(count + 1)

    def _worker(slot: int) -> None:
        barrier.wait(timeout=30)
        try:
            outcomes[slot] = ("ok", func(slot))
        except Exception as exc:  # noqa: BLE001 — outcomes recorded per slot
            outcomes[slot] = ("error", type(exc).__name__, str(exc)[:120])

    threads = [threading.Thread(target=_worker, args=(slot,)) for slot in range(count)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=30)
    for thread in threads:
        thread.join(timeout=60)
    for thread in threads:
        if thread.is_alive():
            raise AssertionError("worker thread did not terminate")
    return outcomes


class RealMongoCase(unittest.TestCase):
    """Shared skip-safe real-Mongo harness (per-test collections)."""

    @classmethod
    def setUpClass(cls) -> None:
        target = _resolve_test_target()
        if target is None:
            raise unittest.SkipTest(
                "WATCH_TEST_MONGO_URI absent or refused; "
                "real-Mongo integration skipped"
            )
        try:
            import pymongo  # noqa: F401
        except ImportError as exc:
            raise unittest.SkipTest("pymongo unavailable; skipping") from exc
        import pymongo as _pymongo

        uri, db_name = target
        client = _pymongo.MongoClient(
            uri,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
            socketTimeoutMS=5000,
        )
        try:
            client.admin.command("ping")
        except Exception as exc:
            client.close()
            raise unittest.SkipTest("test mongo unreachable; skipping") from exc
        cls._client = client
        cls._db = client[db_name]
        cls._db_name = db_name

    @classmethod
    def tearDownClass(cls) -> None:
        client = getattr(cls, "_client", None)
        if client is not None:
            try:
                for name in cls._db.list_collection_names():
                    if name.startswith(_COLLECTION_PREFIX):
                        cls._db[name].drop()
            finally:
                client.close()

    def setUp(self) -> None:
        self._owned: list[str] = []

    def tearDown(self) -> None:
        for name in self._owned:
            try:
                self._db[name].drop()
            except Exception:
                pass
        self._owned = []

    def mkcol(self, suffix: str, index_sets):
        name = f"{_COLLECTION_PREFIX}{suffix}_{self._testMethodName}"[:110]
        raw = self._db[name]
        raw.drop()
        _ensure_unique_indexes(raw, index_sets)
        self._owned.append(name)
        return PymongoCollectionAdapter(raw), raw


def _authz_record(authz_id: str, key_seed: str):
    from ai.test_b1_dial_policy import GOOD_ARTIFACT, make_authz

    record = make_authz(authz_id=authz_id)
    return record.model_copy(
        update={"idempotency_key": hashlib.sha256(key_seed.encode()).hexdigest()}
    )


class RealMongoAuthzTests(RealMongoCase):
    def test_unique_indexes_and_duplicate_idempotency(self) -> None:
        from ai.authorizer.store import DuplicateIdempotencyKeyError
        from ai.persistence.mongo_authz import (
            AUTHZ_UNIQUE_INDEXES,
            MongoAuthorizationStore,
        )

        collection, _ = self.mkcol("authz", AUTHZ_UNIQUE_INDEXES)
        store = MongoAuthorizationStore(collection)
        first = _authz_record("authz-" + "a" * 16, "seed-one")
        store.put_new(first)
        # Same _id again → domain duplicate (server-enforced _id index).
        with self.assertRaises(DuplicateIdempotencyKeyError):
            store.put_new(first)
        # Same idempotency key on a different id → domain duplicate
        # (server-enforced idempotency_key index).
        clash = _authz_record("authz-" + "b" * 16, "seed-one")
        clash = clash.model_copy(update={"idempotency_key": first.idempotency_key})
        with self.assertRaises(DuplicateIdempotencyKeyError):
            store.put_new(clash)

    def test_concurrent_same_idempotency_key(self) -> None:
        from ai.authorizer.store import DuplicateIdempotencyKeyError
        from ai.persistence.mongo_authz import (
            AUTHZ_UNIQUE_INDEXES,
            MongoAuthorizationStore,
        )

        collection, _ = self.mkcol("authz_race", AUTHZ_UNIQUE_INDEXES)
        store = MongoAuthorizationStore(collection)
        shared_key = hashlib.sha256(b"shared-race-key").hexdigest()

        def _issue(slot: int):
            record = _authz_record(f"authz-{slot:016x}", f"ignored-{slot}").model_copy(
                update={"idempotency_key": shared_key}
            )
            return store.put_new(record).authorization_id

        outcomes = _run_concurrent(8, _issue)
        winners = [o for o in outcomes if o[0] == "ok"]
        losers = [o for o in outcomes if o[0] == "error"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 7)
        for outcome in losers:
            self.assertEqual(outcome[1], "DuplicateIdempotencyKeyError")

    def test_concurrent_distinct_requests(self) -> None:
        from ai.persistence.mongo_authz import (
            AUTHZ_UNIQUE_INDEXES,
            MongoAuthorizationStore,
        )

        collection, _ = self.mkcol("authz_distinct", AUTHZ_UNIQUE_INDEXES)
        store = MongoAuthorizationStore(collection)

        def _issue(slot: int):
            return store.put_new(
                _authz_record(f"authz-{100 + slot:016x}", f"distinct-{slot}")
            ).authorization_id

        outcomes = _run_concurrent(8, _issue)
        self.assertTrue(all(o[0] == "ok" for o in outcomes), outcomes)

    def test_cas_race_single_winner(self) -> None:
        from ai.authorizer.store import VersionConflictError
        from ai.persistence.mongo_authz import (
            AUTHZ_UNIQUE_INDEXES,
            MongoAuthorizationStore,
        )

        collection, _ = self.mkcol("authz_cas", AUTHZ_UNIQUE_INDEXES)
        store = MongoAuthorizationStore(collection)
        record = _authz_record("authz-" + "c" * 16, "cas-seed")
        store.put_new(record)

        def _cas(slot: int):
            current = store.get(record.authorization_id)
            assert current is not None
            nxt = current.model_copy(
                update={"lifecycle": "CONSUMED", "record_version": 2}
            )
            return store.compare_and_swap(
                record.authorization_id, 1, nxt
            ).record_version

        outcomes = _run_concurrent(4, _cas)
        winners = [o for o in outcomes if o[0] == "ok"]
        losers = [o for o in outcomes if o[0] == "error"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0][1], 2)
        self.assertTrue(losers)
        for outcome in losers:
            self.assertEqual(outcome[1], "VersionConflictError")
        self.assertEqual(store.get(record.authorization_id).record_version, 2)


class RealMongoLedgerTests(RealMongoCase):
    def _record(self, execution_id: str, authorization_id: str, key_seed: str):
        from ai.execution.ledger import ExecutionRecord

        return ExecutionRecord(
            execution_id=execution_id,
            authorization_id=authorization_id,
            execution_stage="single",
            idempotency_key=hashlib.sha256(key_seed.encode()).hexdigest(),
        )

    def test_ledger_slot_uniqueness_concurrent(self) -> None:
        from ai.execution.ledger import ReplayExecutionError
        from ai.persistence.mongo_ledger import (
            LEDGER_UNIQUE_INDEXES,
            MongoExecutionLedger,
        )

        collection, _ = self.mkcol("ledger_slot", LEDGER_UNIQUE_INDEXES)
        ledger = MongoExecutionLedger(collection)

        def _claim(slot: int):
            return ledger.put_new(
                self._record(
                    f"ex-{slot:032x}", "authz-" + "d" * 16, f"ledger-{slot}"
                )
            ).execution_id

        outcomes = _run_concurrent(8, _claim)
        winners = [o for o in outcomes if o[0] == "ok"]
        losers = [o for o in outcomes if o[0] == "error"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 7)
        for outcome in losers:
            self.assertEqual(outcome[1], "ReplayExecutionError")

    def test_ledger_cas_race_live_row(self) -> None:
        from ai.execution.ledger import InProgressExecutionError
        from ai.persistence.mongo_ledger import (
            LEDGER_UNIQUE_INDEXES,
            MongoExecutionLedger,
        )

        collection, _ = self.mkcol("ledger_cas", LEDGER_UNIQUE_INDEXES)
        ledger = MongoExecutionLedger(collection)
        execution_id = "ex-" + "e" * 32
        ledger.put_new(self._record(execution_id, "authz-" + "e" * 16, "cas-ledger"))

        def _start(slot: int):
            current = ledger.get(execution_id)
            assert current is not None
            nxt = current.model_copy(
                update={
                    "lifecycle": "STARTED",
                    "record_version": 2,
                    "started_at": "2026-01-15T00:00:00+00:00",
                }
            )
            return ledger.compare_and_swap(execution_id, 1, nxt).lifecycle

        outcomes = _run_concurrent(4, _start)
        winners = [o for o in outcomes if o[0] == "ok"]
        losers = [o for o in outcomes if o[0] == "error"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0][1], "STARTED")
        self.assertTrue(losers)
        for outcome in losers:
            self.assertEqual(outcome[1], "InProgressExecutionError")

    def test_ledger_idempotency_key_conflict(self) -> None:
        from ai.execution.ledger import DuplicateExecutionError
        from ai.persistence.mongo_ledger import (
            LEDGER_UNIQUE_INDEXES,
            MongoExecutionLedger,
        )

        collection, _ = self.mkcol("ledger_key", LEDGER_UNIQUE_INDEXES)
        ledger = MongoExecutionLedger(collection)
        ledger.put_new(self._record("ex-" + "1" * 32, "authz-" + "1" * 16, "same-key"))
        with self.assertRaises(DuplicateExecutionError):
            ledger.put_new(
                self._record("ex-" + "2" * 32, "authz-" + "2" * 16, "same-key")
            )


class RealMongoAuditTests(RealMongoCase):
    def _record(self, seq: int, execution_id: str):
        from ai.audit.trail import AuditRecord

        return AuditRecord(
            seq=seq,
            execution_id=execution_id,
            authorization_id="authz-" + "b" * 16,
            transition="AUTHORIZATION",
            at="2026-01-15T00:00:00+00:00",
            actor="b3-test",
            program_name="acme",
            host="authorized.example.com",
        )

    def test_audit_append_only_uniqueness(self) -> None:
        from ai.persistence.mongo_audit import (
            AUDIT_UNIQUE_INDEXES,
            AuditPersistenceError,
            MongoAuditSink,
        )

        collection, _ = self.mkcol("audit", AUDIT_UNIQUE_INDEXES)
        sink = MongoAuditSink(collection)
        execution_id = "ex-" + "f" * 32
        sink.append(self._record(0, execution_id))
        sink.append(self._record(1, execution_id))
        with self.assertRaises(AuditPersistenceError):
            sink.append(self._record(1, execution_id))
        ordered = sink.records_for(execution_id)
        self.assertEqual([record.seq for record in ordered], [0, 1])

    def test_concurrent_duplicate_audit_sequence(self) -> None:
        from ai.persistence.mongo_audit import (
            AUDIT_UNIQUE_INDEXES,
            MongoAuditSink,
        )

        collection, _ = self.mkcol("audit_race", AUDIT_UNIQUE_INDEXES)
        sink = MongoAuditSink(collection)
        execution_id = "ex-" + "a" * 32

        def _append(slot: int):
            sink.append(self._record(0, execution_id))
            return slot

        outcomes = _run_concurrent(6, _append)
        winners = [o for o in outcomes if o[0] == "ok"]
        losers = [o for o in outcomes if o[0] == "error"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 5)
        for outcome in losers:
            self.assertEqual(outcome[1], "AuditPersistenceError")


class RealMongoEvidenceTests(RealMongoCase):
    def test_blob_duplicate_behavior(self) -> None:
        from ai.evidence import hashing as hash_mod
        from ai.persistence.mongo_evidence import (
            BLOB_UNIQUE_INDEXES,
            MongoBlobStore,
        )

        collection, _ = self.mkcol("blob", BLOB_UNIQUE_INDEXES)
        store = MongoBlobStore(collection)
        payload = b'{"sealed": true}'
        digest = hash_mod.sha256_hex(payload)
        self.assertTrue(store.put_if_absent(digest, payload))
        self.assertFalse(store.put_if_absent(digest, payload))
        self.assertTrue(store.verify(digest))
        other = b'{"sealed": false}'
        with self.assertRaises(Exception) as ctx:
            store.put_if_absent(digest, other, enforce_identity=False)
        self.assertEqual(getattr(ctx.exception, "code", ""), "EVIDENCE_HASH_MISMATCH")

    def test_concurrent_duplicate_blob_writes(self) -> None:
        from ai.evidence import hashing as hash_mod
        from ai.persistence.mongo_evidence import (
            BLOB_UNIQUE_INDEXES,
            MongoBlobStore,
        )

        collection, _ = self.mkcol("blob_race", BLOB_UNIQUE_INDEXES)
        store = MongoBlobStore(collection)
        payload = b"race-payload-bytes"
        digest = hash_mod.sha256_hex(payload)

        def _put(slot: int):
            return store.put_if_absent(digest, payload)

        outcomes = _run_concurrent(6, _put)
        # Exactly one True (first writer), rest False (dedupe no-op);
        # no thread may raise (idempotent success under concurrency).
        self.assertTrue(all(o[0] == "ok" for o in outcomes), outcomes)
        self.assertEqual(sum(1 for o in outcomes if o[1] is True), 1)
        self.assertTrue(store.verify(digest))

    def test_index_concurrent_insert(self) -> None:
        from ai.evidence.index import IndexEntry
        from ai.persistence.mongo_evidence import (
            INDEX_UNIQUE_INDEXES,
            MongoEvidenceIndex,
        )

        collection, _ = self.mkcol("evindex", INDEX_UNIQUE_INDEXES)
        store = MongoEvidenceIndex(collection)

        def _entry(suffix: str, auth_suffix: str | None = None) -> IndexEntry:
            return IndexEntry(
                evidence_id="ev-" + suffix,
                execution_id="ex-%s" % suffix,
                authorization_id="authz-" + (auth_suffix or "b" * 16),
                execution_stage="single",
                execution_class="http_probe",
                content_hash="a" * 64,
                bindings_hash="b" * 64,
                observations_hash="c" * 64,
                artifact_id="art-" + "d" * 16,
                program_name="acme",
            )

        first = _entry("c" * 32)
        self.assertTrue(store.insert_if_absent(first))
        self.assertFalse(store.insert_if_absent(first))

        def _insert(slot: int):
            return store.insert_if_absent(
                _entry(f"{slot:032x}", f"{slot:016x}")
            )

        outcomes = _run_concurrent(4, _insert)
        self.assertTrue(all(o[0] == "ok" and o[1] is True for o in outcomes))


class RealMongoDriverFailureTests(RealMongoCase):
    def test_driver_failure_fails_closed(self) -> None:
        import pymongo as _pymongo

        from ai.persistence.driver import MongoUnavailableError
        from ai.persistence.mongo_authz import (
            AUTHZ_UNIQUE_INDEXES,
            MongoAuthorizationStore,
        )
        from ai.test_b1_dial_policy import make_authz

        target = _resolve_test_target()
        assert target is not None
        uri, _ = target
        dead = _pymongo.MongoClient(
            uri, serverSelectionTimeoutMS=200, connectTimeoutMS=200
        )
        dead.close()
        store = MongoAuthorizationStore(
            PymongoCollectionAdapter(dead[self._db_name]["b3t_dead_authz"])
        )
        with self.assertRaises(MongoUnavailableError):
            store.put_new(make_authz())
        with self.assertRaises(MongoUnavailableError):
            store.get("authz-" + "b" * 16)


class SafetyGuardTests(unittest.TestCase):
    """Always-run guards (no server needed): refusal logic is unit-tested."""

    def test_absent_uri_resolves_to_skip(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            saved = os.environ.pop(TEST_URI_ENV, None)
            try:
                self.assertIsNone(_resolve_test_target())
            finally:
                if saved is not None:
                    os.environ[TEST_URI_ENV] = saved

    def test_production_database_names_refused(self) -> None:
        with mock.patch.dict(
            os.environ,
            {TEST_URI_ENV: "mongodb://localhost:27017", TEST_DB_ENV: "watch"},
        ):
            self.assertIsNone(_resolve_test_target())
        with mock.patch.dict(
            os.environ,
            {TEST_URI_ENV: "mongodb://localhost:27017/watch?authSource=admin"},
        ):
            self.assertIsNone(_resolve_test_target())

    def test_non_mongo_scheme_refused(self) -> None:
        with mock.patch.dict(
            os.environ, {TEST_URI_ENV: "http://localhost:27017/test"}
        ):
            self.assertIsNone(_resolve_test_target())


if __name__ == "__main__":
    unittest.main()
