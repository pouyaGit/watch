"""Mongo-backed authorization store (Stage 2 / Phase 5H-core).

``MongoAuthorizationStore`` implements the EXISTING
``ai.authorizer.store.AuthorizationStore`` trust-root interface over
an injected ``MongoCollection``-shaped driver (see
``ai.persistence.driver``): no new authorization model, no schema
change, no weakened validation.

Document shape (one document per issuance record)::

    {
      "_id": <authorization_id>,          # unique
      "idempotency_key": <full sha256>,   # unique
      "record_version": <int>,            # CAS guard
      "lifecycle": <ISSUED|CONSUMED|...>, # state guard
      "expires_at": <RFC3339 string>,
      "expires_at_epoch": <float seconds>,# numeric expiry guard
      "execution_class": <class>,
      "program_name": <program>,
      "host": <canonical host>,
      "scheme": <http|https>,
      "effective_port": <int>,
      "scope_lists_hash": <sha256>,
      "artifact_id": <art-...>,
      "artifact_hash": <sha256>,
      "test_plan_id": <tp-...>,
      "issuer_identity": <issuer>,
      "document": <IssuedExecutionAuthorization model_dump(mode=json)>,
    }

The top-level fields are a denormalized binding projection of the
sealed ``document`` subfield: they let the atomic state-transition
filters pin authorization identity, expiry, execution class,
target scope, and artifact identity server-side in a single
operation. ``document`` remains the sole authority payload and is
re-validated through ``IssuedExecutionAuthorization`` on every read.

Semantics preserved byte-for-behavior with
``InMemoryAuthorizationStore``:

- ``put_new``: typed-only input; ``_id`` collision or idempotency key
  bound to a different id → ``DuplicateIdempotencyKeyError``.
- ``get`` / ``get_by_idempotency_key``: opaque-string ids only;
  malformed ids → ``TypeError``/``None`` exactly like the in-memory
  adapter (``get`` type-checks; key lookup returns ``None`` when
  absent).
- ``compare_and_swap``: a SINGLE atomic conditional update
  (``find_one_and_update`` filtered on ``_id`` + ``record_version``).
  No decision is taken from a prior read: the write succeeds only
  when the guard still holds at apply time. A miss is classified by
  one follow-up read (missing/corrupt row → ``RecordNotFoundError``,
  otherwise ``VersionConflictError``); identity rebind, non-+1
  version step, or ANY post-issuance binding drift (target, scope,
  artifact, class, expiry — only ``lifecycle``/``record_version``/
  ``stored_leases`` may advance) → ``AuthorizationStoreError``.
- ``consume_single_use``: atomic single-use transition
  ISSUED → CONSUMED with the full guard in ONE filter
  (``_id`` + ``record_version`` + ``lifecycle == ISSUED`` +
  ``expires_at_epoch > now``). The replacement is built from the
  validated current row; concurrent losers observe no match and
  receive ``VersionConflictError`` (exactly one winner). Expired,
  consumed, revoked, or corrupt rows fail closed without mutating.
- Stored documents re-validate through
  ``IssuedExecutionAuthorization`` on every read: a row that no
  longer validates is treated as absent (``None``) for lookups and
  as ``RecordNotFoundError`` for CAS — a corrupt row can never
  become authority.
- Driver outages (``MongoUnavailableError``) propagate unchanged:
  callers fail closed; nothing is cached, retried, or synthesized
  here. No connection strings, credentials, nonces, or payload
  bytes ever enter error details.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import ValidationError

from ai.authorizer.store import (
    AuthorizationStoreError,
    DuplicateIdempotencyKeyError,
    RecordNotFoundError,
    VersionConflictError,
)
from ai.persistence.driver import (
    DuplicateKeyError,
    MongoCollection,
    MongoUnavailableError,
)
from ai.schemas.execution_authorization import IssuedExecutionAuthorization

__all__ = [
    "AUTHZ_UNIQUE_INDEXES",
    "AUTHZ_INDEXES",
    "AUTHZ_COLLECTION_NAME",
    "AUTHZ_DATABASE_NAME",
    "MongoAuthorizationStore",
    "ensure_authz_indexes",
    "production_authz_store",
]

#: Unique indexes production wiring must ensure on the collection.
AUTHZ_UNIQUE_INDEXES: tuple[tuple[str, ...], ...] = (
    ("_id",),
    ("idempotency_key",),
)

#: Non-unique query/guard indexes production wiring should ensure.
#: ``lifecycle`` + ``expires_at_epoch`` back liveness sweeps and the
#: atomic consume guard; ``execution_class`` scopes operational reads.
AUTHZ_INDEXES: tuple[tuple[str, ...], ...] = (
    ("lifecycle",),
    ("expires_at_epoch",),
    ("execution_class",),
)

#: Production database/collection names (match the repo's ``watch``
#: database convention from ``ai.collectors.http.HTTPCollector``).
AUTHZ_DATABASE_NAME = "watch"
AUTHZ_COLLECTION_NAME = "execution_authorizations"


#: Record fields no caller may alter after issuance. A CAS successor
#: may advance ONLY ``lifecycle``, ``record_version`` (exactly +1),
#: and ``stored_leases`` (independent SUBMIT/READ lease gates). Every
#: other field — target/pinned address, scope hash, artifact/template
#: identity, execution class, expiry, test-plan/issuer binding — is
#: frozen at issuance; any drift fails closed.
_MUTABLE_CAS_FIELDS = frozenset(
    {"lifecycle", "record_version", "stored_leases"}
)


def _require_bindings_preserved(
    current: IssuedExecutionAuthorization,
    new_record: IssuedExecutionAuthorization,
) -> None:
    """Refuse any post-issuance binding mutation (fail closed).

    Compares the full validated records field-by-field and permits
    differences only in ``_MUTABLE_CAS_FIELDS``. The store therefore
    cannot be used to rebind target, scope, artifact, class, expiry,
    or any other issuance-time binding — those require a NEW
    authorization minted through the typed issuance boundary.
    """
    if not isinstance(current, IssuedExecutionAuthorization) or not isinstance(
        new_record, IssuedExecutionAuthorization
    ):
        raise TypeError(
            "binding comparison accepts only IssuedExecutionAuthorization"
        )
    old_dump = current.model_dump(mode="json")
    new_dump = new_record.model_dump(mode="json")
    for key in old_dump:
        if key in _MUTABLE_CAS_FIELDS:
            continue
        if key not in new_dump or new_dump[key] != old_dump[key]:
            raise AuthorizationStoreError(
                "CAS cannot alter issuance bindings after issuance"
            )
    for key in new_dump:
        if key in _MUTABLE_CAS_FIELDS or key in old_dump:
            continue
        raise AuthorizationStoreError(
            "CAS cannot alter issuance bindings after issuance"
        )


def _expires_epoch(expires_at: object) -> float:
    """Numeric expiry instant (same rule as the 5B service layer).

    ``datetime.fromisoformat``; naive timestamps read as UTC. Anything
    unparseable fails closed — an authorization without a legible
    expiry can never be persisted or consumed.
    """
    if not isinstance(expires_at, str) or not expires_at:
        raise AuthorizationStoreError(
            "authorization expiry malformed; refused"
        )
    try:
        instant = datetime.fromisoformat(expires_at)
    except (ValueError, TypeError) as exc:
        raise AuthorizationStoreError(
            "authorization expiry malformed; refused"
        ) from exc
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.timestamp()


class MongoAuthorizationStore:
    """Persistent issuance store (same contract as the in-memory one).

    Single-process AND cross-process CAS both hold when the backing
    collection enforces the declared unique indexes atomically (the
    production requirement the in-memory fake explicitly lacks).
    """

    def __init__(self, collection: MongoCollection) -> None:
        for method in (
            "find_one",
            "find",
            "insert_one",
            "replace_one",
            "find_one_and_update",
        ):
            if not callable(getattr(collection, method, None)):
                raise TypeError(
                    "authorization store requires a MongoCollection driver, "
                    f"missing: {method}"
                )
        self._collection = collection

    # -- internals ---------------------------------------------------

    @staticmethod
    def _to_document(record: IssuedExecutionAuthorization) -> dict:
        target = record.target
        artifact = record.artifact
        return {
            "_id": record.authorization_id,
            "authorization_id": record.authorization_id,
            "idempotency_key": record.idempotency_key,
            "record_version": record.record_version,
            "lifecycle": record.lifecycle,
            "expires_at": record.expires_at,
            "expires_at_epoch": _expires_epoch(record.expires_at),
            "execution_class": record.execution_class,
            "program_name": target.program_name,
            "host": target.host,
            "scheme": target.scheme,
            "effective_port": target.effective_port,
            "scope_lists_hash": target.scope_lists_hash,
            "artifact_id": artifact.artifact_id,
            "artifact_hash": artifact.content_hash,
            "test_plan_id": record.test_plan_id,
            "issuer_identity": record.issuer_identity,
            "document": record.model_dump(mode="json"),
        }

    @staticmethod
    def _from_document(stored: dict) -> IssuedExecutionAuthorization | None:
        try:
            candidate = stored.get("document", {})
            record = IssuedExecutionAuthorization.model_validate(candidate)
        except (ValidationError, AttributeError, TypeError):
            return None
        # The denormalized guard fields must agree with the sealed
        # payload; a row whose projection drifted from its document
        # is corrupt and can never become authority.
        try:
            expected = MongoAuthorizationStore._to_document(record)
        except AuthorizationStoreError:
            return None
        for key in (
            "authorization_id",
            "idempotency_key",
            "record_version",
            "lifecycle",
            "expires_at",
            "execution_class",
        ):
            if stored.get(key) != expected.get(key):
                return None
        return record

    # -- AuthorizationStore interface ---------------------------------

    def put_new(
        self, record: object
    ) -> IssuedExecutionAuthorization:
        if not isinstance(record, IssuedExecutionAuthorization):
            raise TypeError(
                "issuance store accepts only IssuedExecutionAuthorization, "
                f"not {type(record).__name__}; raw dicts are never coerced"
            )
        if self._collection.find_one({"_id": record.authorization_id}) is not None:
            raise DuplicateIdempotencyKeyError(
                f"authorization_id already issued: {record.authorization_id}"
            )
        existing = self._collection.find_one(
            {"idempotency_key": record.idempotency_key}
        )
        if existing is not None and existing.get("_id") != record.authorization_id:
            raise DuplicateIdempotencyKeyError(
                "idempotency key already bound to a different authorization"
            )
        try:
            self._collection.insert_one(self._to_document(record))
        except DuplicateKeyError as exc:
            # Lost a race: re-read to report the precise collision.
            # Any outcome here fails closed without inventing a record.
            raise DuplicateIdempotencyKeyError(
                "issuance collided under concurrency; re-read before retry"
            ) from exc
        return record.model_copy(deep=True)

    def get(
        self, authorization_id: object
    ) -> IssuedExecutionAuthorization | None:
        if not isinstance(authorization_id, str):
            raise TypeError(
                "authorization lookup accepts only an opaque string id, "
                f"not {type(authorization_id).__name__}"
            )
        stored = self._collection.find_one({"_id": authorization_id})
        if stored is None:
            return None
        return self._from_document(stored)

    def get_by_idempotency_key(
        self, idempotency_key: object
    ) -> IssuedExecutionAuthorization | None:
        if not isinstance(idempotency_key, str):
            raise TypeError(
                "idempotency lookup accepts only a string key, "
                f"not {type(idempotency_key).__name__}"
            )
        stored = self._collection.find_one({"idempotency_key": idempotency_key})
        if stored is None:
            return None
        return self._from_document(stored)

    def compare_and_swap(
        self,
        authorization_id: object,
        expected_version: object,
        new_record: object,
    ) -> IssuedExecutionAuthorization:
        """Atomic version-guarded transition (single conditional write).

        Post-issuance bindings are frozen: only ``lifecycle``,
        ``record_version``, and ``stored_leases`` may differ from the
        stored row; any other drift raises ``AuthorizationStoreError``
        without mutating.

        The mutation applies only when ``{_id, record_version}`` still
        matches at apply time, so concurrent writers serialize with
        exactly one winner: the pre-write reads only reproduce the
        in-memory adapter's failure precedence (missing/corrupt →
        ``RecordNotFoundError``, drift → ``VersionConflictError``) and
        can only refuse early — a row that changes between the read
        and the write misses the write filter and classifies as a
        conflict, never as a success. A write miss is classified by
        one follow-up read made only to name the failure.
        """
        if not isinstance(authorization_id, str):
            raise TypeError(
                "CAS accepts only an opaque string id, "
                f"not {type(authorization_id).__name__}"
            )
        if not isinstance(expected_version, int) or isinstance(
            expected_version, bool
        ):
            raise TypeError("CAS expected_version must be an integer")
        if not isinstance(new_record, IssuedExecutionAuthorization):
            raise TypeError(
                "CAS accepts only IssuedExecutionAuthorization, "
                f"not {type(new_record).__name__}"
            )
        # Pre-write classification reads (refusal only, never
        # authority): missing/corrupt row → RecordNotFound; version
        # drift → VersionConflict — the same precedence as the
        # in-memory adapter. These reads grant nothing: the transition
        # decision below stays fully in the single conditional update,
        # whose filter re-asserts the guard at apply time (a row that
        # changes between the read and the write misses the filter and
        # classifies as a conflict, never as a success).
        current = self._collection.find_one({"_id": authorization_id})
        current_record = (
            None if current is None else self._from_document(current)
        )
        if current_record is None:
            raise RecordNotFoundError(
                f"no issuance record: {authorization_id}"
            )
        if current_record.record_version != expected_version:
            raise VersionConflictError(
                "issuance record changed under the caller; "
                "re-read before retrying"
            )
        if new_record.authorization_id != authorization_id:
            raise AuthorizationStoreError(
                "CAS cannot rebind authorization identity"
            )
        if new_record.record_version != expected_version + 1:
            raise AuthorizationStoreError(
                "CAS requires exactly one version increment"
            )
        _require_bindings_preserved(current_record, new_record)
        replacement = self._to_document(new_record)
        # ``_id`` is immutable: the filter pins identity, the update
        # carries every other field.
        replacement.pop("_id", None)
        matched = self._collection.find_one_and_update(
            {"_id": authorization_id, "record_version": expected_version},
            {"$set": replacement},
        )
        if matched is not None:
            return new_record.model_copy(deep=True)
        current = self._collection.find_one({"_id": authorization_id})
        if current is None or self._from_document(current) is None:
            raise RecordNotFoundError(
                f"no issuance record: {authorization_id}"
            )
        raise VersionConflictError(
            "issuance record changed under the caller; "
            "re-read before retrying"
        )

    # -- atomic single-use consume ------------------------------------

    def consume_single_use(
        self, authorization_id: object, *, now: str
    ) -> IssuedExecutionAuthorization:
        """Atomically consume one ISSUED authorization (ISSUED→CONSUMED).

        The full single-use guard — ``_id`` + ``record_version`` +
        ``lifecycle == ISSUED`` + ``expires_at_epoch > now`` — is one
        atomic filter, so N concurrent consumers produce exactly one
        CONSUMED winner; every loser observes no match and receives
        ``VersionConflictError``. Expired, consumed, revoked, corrupt,
        or unknown rows fail closed without mutating anything.
        """
        if not isinstance(authorization_id, str):
            raise TypeError(
                "consume accepts only an opaque string id, "
                f"not {type(authorization_id).__name__}"
            )
        now_epoch = _expires_epoch(now)
        current = self._collection.find_one({"_id": authorization_id})
        if current is None:
            raise RecordNotFoundError(
                f"no issuance record: {authorization_id}"
            )
        record = self._from_document(current)
        if record is None:
            raise RecordNotFoundError(
                f"no issuance record: {authorization_id}"
            )
        if record.lifecycle != "ISSUED":
            raise VersionConflictError(
                "authorization not consumable; re-read before retrying"
            )
        if _expires_epoch(record.expires_at) <= now_epoch:
            raise VersionConflictError(
                "authorization not consumable; re-read before retrying"
            )
        progressed = record.model_copy(
            update={
                "lifecycle": "CONSUMED",
                "record_version": record.record_version + 1,
            }
        )
        update_doc = self._to_document(progressed)
        # ``_id`` is immutable: the filter pins identity, the update
        # carries every other field.
        update_doc.pop("_id", None)
        matched = self._collection.find_one_and_update(
            {
                "_id": authorization_id,
                "record_version": record.record_version,
                "lifecycle": "ISSUED",
                "expires_at_epoch": {"$gt": now_epoch},
            },
            {"$set": update_doc},
        )
        if matched is None:
            # Lost a race (or the row changed under us): fail closed,
            # never retry the consume here.
            raise VersionConflictError(
                "authorization not consumable; re-read before retrying"
            )
        return progressed.model_copy(deep=True)


def ensure_authz_indexes(collection: object) -> tuple[str, ...]:
    """Ensure production indexes; returns the ensured index names.

    Unique: ``_id`` (driver default) + ``idempotency_key``.
    Non-unique: ``lifecycle``, ``expires_at_epoch``,
    ``execution_class``. Accepts any collection exposing
    ``create_index`` (real pymongo) and is a no-op description for
    driver fakes lacking it.
    """
    create = getattr(collection, "create_index", None)
    ensured: list[str] = []
    if not callable(create):
        return tuple(
            ["_id", "idempotency_key", "lifecycle",
             "expires_at_epoch", "execution_class"]
        )
    for fields in AUTHZ_UNIQUE_INDEXES:
        if fields == ("_id",):
            ensured.append("_id")
            continue
        create(list(fields), unique=True)
        ensured.append("+".join(fields))
    for fields in AUTHZ_INDEXES:
        create(list(fields), unique=False)
        ensured.append("+".join(fields))
    return tuple(ensured)


def production_authz_store(
    *,
    uri: str | None = None,
    database: str = AUTHZ_DATABASE_NAME,
    collection_name: str = AUTHZ_COLLECTION_NAME,
    timeout_ms: int = 5000,
) -> MongoAuthorizationStore:
    """Build the production store from environment configuration.

    Credentials come exclusively from ``WATCH_MONGO_URI`` (via
    ``ai.config.require_mongo_uri``) unless an explicit ``uri`` is
    passed by the operator caller. The driver is imported lazily so
    this module never connects at import time and never carries
    credentials. No live-execution switch is touched here.
    """
    if uri is None:
        from ai.config import require_mongo_uri as _require_uri

        uri = _require_uri()
    if not isinstance(uri, str) or not uri:
        raise AuthorizationStoreError(
            "production store requires a MongoDB URI; refused"
        )
    import importlib as _importlib

    pymongo = _importlib.import_module("pymongo")
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
    client.admin.command("ping")
    collection = client[database][collection_name]
    ensure_authz_indexes(collection)
    return MongoAuthorizationStore(collection)
