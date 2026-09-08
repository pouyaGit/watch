"""Focused Phase 5H-core production authorization-store tests.

Stdlib ``unittest`` only. No network, no DNS, no sockets, no
subprocess, no MongoDB server, no browser, no Nuclei, no LLM, no Git.
The Mongo-shaped adapter runs over ``FakeMongoCollection`` (unique
indexes, atomic conditional updates, failure injection); no
production credentials exist anywhere in this file.

Covers the 5H-core contract: put/get round trip with exact field
preservation, duplicate rejection, atomic ISSUED -> CONSUMED
single-use (exactly one winner under concurrency), stale-version CAS
rejection, expired rejection, malformed-document fail-closed, driver
outage fail-closed, protocol conformance, production index design,
and confirmation that all live switches remain disabled.
"""

from __future__ import annotations

import threading
import unittest

from ai.authorizer.service import (
    consume_authorization,
    get_issued_authorization,
    issue_authorization,
    revoke_authorization,
)
from ai.authorizer.store import (
    AuthorizationStore,
    AuthorizationStoreError,
    DuplicateIdempotencyKeyError,
    RecordNotFoundError,
    VersionConflictError,
)
from ai.persistence.driver import FakeMongoCollection, MongoUnavailableError
from ai.persistence.mongo_authz import (
    AUTHZ_COLLECTION_NAME,
    AUTHZ_DATABASE_NAME,
    AUTHZ_INDEXES,
    AUTHZ_UNIQUE_INDEXES,
    MongoAuthorizationStore,
    ensure_authz_indexes,
)
from ai.schemas.artifact import artifact_id_for, content_hash_for_bytes
from ai.schemas.execution_authorization import (
    ArtifactBinding,
    AuthzError,
    AuthorizationRequest,
    TargetBinding,
)

NOW = "2026-01-01T00:00:00+00:00"
LATER = "2026-01-02T00:00:00+00:00"
EXPIRY = "2030-01-01T00:00:00+00:00"
AFTER_EXPIRY = "2031-06-01T00:00:00+00:00"
SCOPE_HASH = "b" * 64
TP_ID = "tp-" + "a" * 16


def _content(tag: str = "payload") -> str:
    return content_hash_for_bytes(("mongo-authz-" + tag).encode("utf-8"))


def _request(**overrides):
    content = _content(overrides.pop("tag", "payload"))
    base = {
        "test_plan_id": TP_ID,
        "artifact": ArtifactBinding(
            artifact_id=artifact_id_for(
                artifact_type="nuclei_template",
                test_plan_id=TP_ID,
                content_hash=content,
            ),
            artifact_type="nuclei_template",
            content_hash=content,
            test_plan_id=TP_ID,
        ),
        "target": TargetBinding(
            program_name="acme",
            host="203.0.113.7",
            scheme="https",
            effective_port=8443,
            scope_lists_hash=SCOPE_HASH,
        ),
        "execution_class": "nuclei_scan",
        "plan_method": "GET",
        "artifact_method": "GET",
        "expires_at": EXPIRY,
    }
    base.update(overrides)
    return AuthorizationRequest(**base)


def _store() -> MongoAuthorizationStore:
    return MongoAuthorizationStore(
        FakeMongoCollection(list(AUTHZ_UNIQUE_INDEXES))
    )


class RoundTripTests(unittest.TestCase):
    def test_put_get_round_trip_preserves_every_field(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        loaded = store.get(issued.authorization_id)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(
            loaded.model_dump(mode="json"), issued.model_dump(mode="json")
        )

    def test_get_by_idempotency_key_returns_same_record(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        again = store.get_by_idempotency_key(issued.idempotency_key)
        self.assertIsNotNone(again)
        assert again is not None
        self.assertEqual(again.authorization_id, issued.authorization_id)

    def test_unknown_ids_return_none(self) -> None:
        store = _store()
        self.assertIsNone(store.get("authz-" + "0" * 16))
        self.assertIsNone(store.get_by_idempotency_key("0" * 64))

    def test_denormalized_binding_projection_pinned(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        raw = store._collection.raw(issued.authorization_id)
        assert raw is not None
        self.assertEqual(raw["authorization_id"], issued.authorization_id)
        self.assertEqual(raw["lifecycle"], "ISSUED")
        self.assertEqual(raw["record_version"], 1)
        self.assertEqual(raw["execution_class"], "nuclei_scan")
        self.assertEqual(raw["program_name"], "acme")
        self.assertEqual(raw["host"], "203.0.113.7")
        self.assertEqual(raw["scheme"], "https")
        self.assertEqual(raw["effective_port"], 8443)
        self.assertEqual(raw["scope_lists_hash"], SCOPE_HASH)
        self.assertEqual(raw["artifact_id"], issued.artifact.artifact_id)
        self.assertEqual(raw["artifact_hash"], issued.artifact.content_hash)
        self.assertEqual(raw["test_plan_id"], TP_ID)
        self.assertEqual(raw["expires_at"], EXPIRY)
        self.assertGreater(raw["expires_at_epoch"], 0)


class DuplicateTests(unittest.TestCase):
    def test_duplicate_authorization_id_rejected(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        with self.assertRaises(DuplicateIdempotencyKeyError):
            store.put_new(issued.model_copy(deep=True))

    def test_duplicate_idempotency_key_rejected(self) -> None:
        store = _store()
        first = issue_authorization(store, _request(), now=NOW)
        # Same logical basis, distinct issuance nonce → distinct
        # authorization_id, identical idempotency key.
        from ai.schemas.execution_authorization import (
            authorization_id_for,
            generate_issuance_nonce,
            idempotency_key_for,
        )

        nonce = generate_issuance_nonce()
        impostor = first.model_copy(
            update={
                "authorization_id": authorization_id_for(
                    test_plan_id=first.test_plan_id,
                    artifact_id=first.artifact.artifact_id,
                    content_hash=first.artifact.content_hash,
                    program_name=first.target.program_name,
                    host=first.target.host,
                    execution_class=first.execution_class,
                    scope_lists_hash=first.target.scope_lists_hash,
                    issuance_nonce=nonce,
                ),
                "issuance_nonce": nonce,
            }
        )
        self.assertEqual(
            impostor.idempotency_key,
            idempotency_key_for(
                test_plan_id=first.test_plan_id,
                artifact_id=first.artifact.artifact_id,
                content_hash=first.artifact.content_hash,
                program_name=first.target.program_name,
                host=first.target.host,
                execution_class=first.execution_class,
                scope_lists_hash=first.target.scope_lists_hash,
                caller_scope=first.caller_scope,
            ),
        )
        self.assertNotEqual(
            impostor.authorization_id, first.authorization_id
        )
        with self.assertRaises(DuplicateIdempotencyKeyError):
            store.put_new(impostor)

    def test_idempotent_reissuance_returns_winner(self) -> None:
        store = _store()
        first = issue_authorization(store, _request(), now=NOW)
        second = issue_authorization(store, _request(), now=NOW)
        self.assertEqual(first.authorization_id, second.authorization_id)


class SingleUseConsumeTests(unittest.TestCase):
    def test_store_consume_issued_to_consumed(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        consumed = store.consume_single_use(
            issued.authorization_id, now=LATER
        )
        self.assertEqual(consumed.lifecycle, "CONSUMED")
        self.assertEqual(consumed.record_version, 2)
        self.assertEqual(
            consumed.authorization_id, issued.authorization_id
        )
        # Persisted state is CONSUMED with all fields preserved.
        reloaded = store.get(issued.authorization_id)
        assert reloaded is not None
        self.assertEqual(reloaded.lifecycle, "CONSUMED")
        self.assertEqual(reloaded.record_version, 2)
        self.assertEqual(
            reloaded.artifact.content_hash, issued.artifact.content_hash
        )

    def test_second_consume_rejected_without_mutation(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        store.consume_single_use(issued.authorization_id, now=LATER)
        with self.assertRaises(VersionConflictError):
            store.consume_single_use(issued.authorization_id, now=LATER)
        reloaded = store.get(issued.authorization_id)
        assert reloaded is not None
        self.assertEqual(reloaded.lifecycle, "CONSUMED")
        self.assertEqual(reloaded.record_version, 2)

    def test_service_consume_over_mongo_store_single_use(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        consumed = consume_authorization(
            store, issued.authorization_id, now=LATER
        )
        self.assertEqual(consumed.lifecycle, "CONSUMED")
        with self.assertRaises(AuthzError) as ctx:
            consume_authorization(store, issued.authorization_id, now=LATER)
        self.assertEqual(ctx.exception.code, "AUTHZ_ALREADY_CONSUMED")

    def test_revoke_over_mongo_store(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        revoked = revoke_authorization(store, issued.authorization_id)
        self.assertEqual(revoked.lifecycle, "REVOKED")
        with self.assertRaises(VersionConflictError):
            store.consume_single_use(issued.authorization_id, now=LATER)

    def test_concurrent_consume_exactly_one_winner(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        attempts = 8
        barrier = threading.Barrier(attempts)
        winners: list[str] = []
        losers: list[str] = []
        guard = threading.Lock()

        def _attempt() -> None:
            barrier.wait()
            try:
                won = store.consume_single_use(
                    issued.authorization_id, now=LATER
                )
                with guard:
                    winners.append(won.authorization_id)
            except VersionConflictError:
                with guard:
                    losers.append("conflict")
            except RecordNotFoundError:  # pragma: no cover - defensive
                with guard:
                    losers.append("missing")

        threads = [
            threading.Thread(target=_attempt) for _ in range(attempts)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), attempts - 1)
        final = store.get(issued.authorization_id)
        assert final is not None
        self.assertEqual(final.lifecycle, "CONSUMED")
        self.assertEqual(final.record_version, 2)


class CasTests(unittest.TestCase):
    def test_stale_version_rejected(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        progressed = issued.model_copy(
            update={"lifecycle": "CONSUMED", "record_version": 100}
        )
        with self.assertRaises(VersionConflictError):
            store.compare_and_swap(issued.authorization_id, 99, progressed)

    def test_identity_rebind_rejected(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        other = issued.model_copy(
            update={
                "authorization_id": "authz-" + "f" * 16,
                "record_version": 2,
            }
        )
        with self.assertRaises(AuthorizationStoreError):
            store.compare_and_swap(issued.authorization_id, 1, other)

    def test_non_increment_version_rejected(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        jumped = issued.model_copy(update={"record_version": 3})
        with self.assertRaises(AuthorizationStoreError):
            store.compare_and_swap(issued.authorization_id, 1, jumped)

    def test_missing_row_rejected(self) -> None:
        store = _store()
        issue_authorization(store, _request(), now=NOW)
        missing_id = "authz-" + "e" * 16
        progressed = issue_authorization(
            store, _request(tag="missing-row"), now=NOW
        ).model_copy(
            update={
                "authorization_id": missing_id,
                "lifecycle": "CONSUMED",
                "record_version": 2,
            }
        )
        with self.assertRaises(RecordNotFoundError):
            store.compare_and_swap(missing_id, 1, progressed)

    def test_cas_decision_is_single_conditional_write(self) -> None:
        # The transition decision lives fully in one conditional
        # update: the preceding read is an integrity gate (refusal
        # only) and the guard is re-asserted in the write filter, so
        # concurrent writers still serialize with exactly one winner
        # (proven by the concurrent-consume test).
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        progressed = issued.model_copy(
            update={"lifecycle": "CONSUMED", "record_version": 2}
        )
        store._collection.calls.clear()
        store.compare_and_swap(issued.authorization_id, 1, progressed)
        self.assertEqual(
            store._collection.calls,
            ["find_one", "find_one_and_update"],
        )


class ExpiryTests(unittest.TestCase):
    def test_store_consume_rejects_expired(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        with self.assertRaises(VersionConflictError):
            store.consume_single_use(
                issued.authorization_id, now=AFTER_EXPIRY
            )
        # No mutation: still ISSUED at version 1.
        reloaded = store.get(issued.authorization_id)
        assert reloaded is not None
        self.assertEqual(reloaded.lifecycle, "ISSUED")
        self.assertEqual(reloaded.record_version, 1)

    def test_service_consume_rejects_expired_over_mongo(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        with self.assertRaises(AuthzError) as ctx:
            consume_authorization(
                store, issued.authorization_id, now=AFTER_EXPIRY
            )
        self.assertEqual(ctx.exception.code, "AUTHZ_EXPIRED")

    def test_malformed_expiry_never_persists(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        broken = issued.model_copy(update={"expires_at": "not-a-time"})
        with self.assertRaises(AuthorizationStoreError):
            store.put_new(broken)


class MalformedDocumentTests(unittest.TestCase):
    def _corrupt(self, store: MongoAuthorizationStore, authz_id: str) -> None:
        raw = store._collection.raw(authz_id)
        assert raw is not None
        raw["document"]["lifecycle"] = "SUPERUSER"
        store._collection.replace_one({"_id": authz_id}, raw)

    def test_corrupt_row_never_becomes_authority(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        self._corrupt(store, issued.authorization_id)
        self.assertIsNone(store.get(issued.authorization_id))
        self.assertIsNone(
            store.get_by_idempotency_key(issued.idempotency_key)
        )
        self.assertIsNone(
            get_issued_authorization(store, issued.authorization_id)
        )

    def test_corrupt_row_cas_is_not_found(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        progressed = issued.model_copy(
            update={"lifecycle": "CONSUMED", "record_version": 2}
        )
        self._corrupt(store, issued.authorization_id)
        with self.assertRaises(RecordNotFoundError):
            store.compare_and_swap(
                issued.authorization_id, 1, progressed
            )

    def test_corrupt_row_consume_is_not_found(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        self._corrupt(store, issued.authorization_id)
        with self.assertRaises(RecordNotFoundError):
            store.consume_single_use(issued.authorization_id, now=LATER)
        with self.assertRaises(AuthzError) as ctx:
            consume_authorization(store, issued.authorization_id, now=LATER)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_FOUND")

    def test_drifted_projection_is_not_authority(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        raw = store._collection.raw(issued.authorization_id)
        assert raw is not None
        raw["lifecycle"] = "CONSUMED"  # projection drift; payload ISSUED
        store._collection.replace_one({"_id": issued.authorization_id}, raw)
        self.assertIsNone(store.get(issued.authorization_id))

    def test_untyped_inputs_rejected(self) -> None:
        store = _store()
        with self.assertRaises(TypeError):
            store.put_new({"authorization_id": "authz-" + "0" * 16})
        with self.assertRaises(TypeError):
            store.get({"authorization_id": "x"})
        with self.assertRaises(TypeError):
            store.get_by_idempotency_key(b"0" * 64)
        with self.assertRaises(TypeError):
            store.compare_and_swap("authz-" + "0" * 16, "1", {})  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            store.consume_single_use(b"authz-" + b"0" * 16, now=LATER)  # type: ignore[arg-type]


class OutageTests(unittest.TestCase):
    def test_driver_outage_fails_closed_without_secrets(self) -> None:
        store = _store()
        issued = issue_authorization(store, _request(), now=NOW)
        store._collection.fail_always()
        for operation in (
            lambda: store.put_new(issued.model_copy(deep=True)),
            lambda: store.get(issued.authorization_id),
            lambda: store.get_by_idempotency_key(issued.idempotency_key),
            lambda: store.compare_and_swap(
                issued.authorization_id,
                1,
                issued.model_copy(
                    update={"lifecycle": "CONSUMED", "record_version": 2}
                ),
            ),
            lambda: store.consume_single_use(
                issued.authorization_id, now=LATER
            ),
        ):
            with self.assertRaises(MongoUnavailableError) as ctx:
                operation()
            text = str(ctx.exception).casefold()
            for marker in ("mongodb://", "password", "secret", "bearer "):
                self.assertNotIn(marker, text)

    def test_service_issue_over_outage_fails_closed(self) -> None:
        store = _store()
        store._collection.fail_always()
        with self.assertRaises(MongoUnavailableError):
            issue_authorization(store, _request(tag="outage"), now=NOW)


class WiringTests(unittest.TestCase):
    def test_protocol_conformance(self) -> None:
        self.assertTrue(isinstance(_store(), AuthorizationStore))
        from ai.authorizer.store import InMemoryAuthorizationStore

        self.assertTrue(
            isinstance(InMemoryAuthorizationStore(), AuthorizationStore)
        )
        self.assertFalse(isinstance({}, AuthorizationStore))

    def test_index_design_declared(self) -> None:
        self.assertIn(("_id",), AUTHZ_UNIQUE_INDEXES)
        self.assertIn(("idempotency_key",), AUTHZ_UNIQUE_INDEXES)
        self.assertIn(("lifecycle",), AUTHZ_INDEXES)
        self.assertIn(("expires_at_epoch",), AUTHZ_INDEXES)
        self.assertIn(("execution_class",), AUTHZ_INDEXES)
        self.assertEqual(AUTHZ_DATABASE_NAME, "watch")
        self.assertEqual(AUTHZ_COLLECTION_NAME, "execution_authorizations")

    def test_ensure_indexes_reports_without_driver(self) -> None:
        ensured = ensure_authz_indexes(object())
        self.assertIn("idempotency_key", ensured)
        self.assertIn("expires_at_epoch", ensured)

    def test_factory_requires_uri_and_never_hardcodes(self) -> None:
        import pathlib

        from ai.persistence.mongo_authz import production_authz_store

        source = pathlib.Path(
            __import__("ai.persistence.mongo_authz", fromlist=["x"]).__file__
        ).read_text(encoding="utf-8")
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                self.assertNotIn("pymongo", stripped)
        self.assertNotIn("mongodb://", source)
        with self.assertRaises(Exception):
            production_authz_store(uri="")

    def test_lane_accepts_production_store(self) -> None:
        from ai.live_validation.lane import ControlledLiveValidationLane

        lane = ControlledLiveValidationLane(authz_store=_store())
        result = lane.run(
            "CVE-2026-1557", "https://example.com", mode="dry_run"
        )
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "DRY_RUN_NOT_PERFORMED")

    def test_live_switches_remain_disabled(self) -> None:
        import os

        from ai.execution.nuclei_executor import LIVE_NUCLEI
        from ai.execution.nuclei_launcher import LIVE_LAUNCH_ENABLED

        self.assertIs(LIVE_NUCLEI, False)
        self.assertIs(LIVE_LAUNCH_ENABLED, False)
        self.assertNotIn(
            os.environ.get("WATCH_AI_LIVE_VALIDATION", "")
            .strip()
            .casefold(),
            ("1", "true", "yes", "on"),
        )


class BindingImmutabilityTests(unittest.TestCase):
    """Post-issuance bindings cannot move through the store (req §8)."""

    def _issued(self):
        store = _store()
        return store, issue_authorization(store, _request(), now=NOW)

    def _attempt(self, store, issued, **changes):
        progressed = issued.model_copy(
            update={
                "lifecycle": "CONSUMED",
                "record_version": issued.record_version + 1,
                **changes,
            }
        )
        with self.assertRaises(AuthorizationStoreError):
            store.compare_and_swap(
                issued.authorization_id, issued.record_version, progressed
            )

    def test_target_rebind_rejected(self) -> None:
        store, issued = self._issued()
        tampered_target = issued.target.model_copy(
            update={"host": "evil.example.com"}
        )
        self._attempt(store, issued, target=tampered_target)
        self.assertEqual(store.get(issued.authorization_id).lifecycle, "ISSUED")

    def test_scope_hash_rebind_rejected(self) -> None:
        store, issued = self._issued()
        tampered_target = issued.target.model_copy(
            update={"scope_lists_hash": "0" * 64}
        )
        self._attempt(store, issued, target=tampered_target)

    def test_port_rebind_rejected(self) -> None:
        store, issued = self._issued()
        tampered_target = issued.target.model_copy(
            update={"effective_port": 443}
        )
        self._attempt(store, issued, target=tampered_target)

    def test_artifact_rebind_rejected(self) -> None:
        store, issued = self._issued()
        tampered_artifact = issued.artifact.model_copy(
            update={"content_hash": "f" * 64}
        )
        self._attempt(store, issued, artifact=tampered_artifact)

    def test_execution_class_rebind_rejected(self) -> None:
        store, issued = self._issued()
        self._attempt(store, issued, execution_class="http_probe")

    def test_expiry_rebind_rejected(self) -> None:
        store, issued = self._issued()
        self._attempt(store, issued, expires_at="2035-01-01T00:00:00+00:00")

    def test_lifecycle_only_advance_allowed(self) -> None:
        store, issued = self._issued()
        progressed = issued.model_copy(
            update={"lifecycle": "CONSUMED", "record_version": 2}
        )
        result = store.compare_and_swap(
            issued.authorization_id, 1, progressed
        )
        self.assertEqual(result.lifecycle, "CONSUMED")
        self.assertEqual(result.target.host, issued.target.host)
        self.assertEqual(
            result.artifact.content_hash, issued.artifact.content_hash
        )

    def test_lease_only_advance_allowed(self) -> None:
        from ai.schemas.execution_authorization import StoredStageLeases

        store = _store()
        issued = issue_authorization(
            store,
            _request(
                execution_phase="submit",
                stored_round_id="sr-" + "9" * 32,
            ),
            now=NOW,
        )
        assert issued.stored_leases is not None
        progressed = issued.model_copy(
            update={
                "stored_leases": StoredStageLeases(
                    round_id=issued.stored_leases.round_id,
                    submit_lease="CONSUMED",
                    read_lease="PENDING",
                ),
                "record_version": 2,
            }
        )
        result = store.compare_and_swap(
            issued.authorization_id, 1, progressed
        )
        assert result.stored_leases is not None
        self.assertEqual(result.stored_leases.submit_lease, "CONSUMED")


class IndexInitTests(unittest.TestCase):
    """Index creation is deterministic and safe to repeat (req §4)."""

    def test_repeated_init_is_safe_and_stable(self) -> None:
        class RecordingCollection:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], bool]] = []

            def create_index(self, keys, unique: bool = False):
                self.calls.append((list(keys), bool(unique)))
                return "+".join(keys)

        collection = RecordingCollection()
        first = ensure_authz_indexes(collection)
        second = ensure_authz_indexes(collection)
        self.assertEqual(first, second)
        self.assertIn("idempotency_key", first)
        self.assertIn("lifecycle", first)
        self.assertIn("expires_at_epoch", first)
        self.assertIn("execution_class", first)
        # Unique flag correct per index kind; _id left to the driver
        # (no create call emitted for it).
        created = [name for name in first if name != "_id"]
        self.assertEqual(len(collection.calls), 2 * len(created))
        kinds = dict(
            zip(created, [unique for _, unique in collection.calls])
        )
        self.assertTrue(kinds["idempotency_key"])
        self.assertFalse(kinds["lifecycle"])
        self.assertFalse(kinds["expires_at_epoch"])
        self.assertFalse(kinds["execution_class"])


if __name__ == "__main__":
    unittest.main()
