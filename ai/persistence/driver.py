"""Driver seam for Stage 2 Mongo-shaped adapters (offline-safe).

``MongoCollection`` is the narrow driver subset every adapter in this
package is written against::

    find_one(filter) -> dict | None
    find(filter) -> list[dict]
    insert_one(document) -> None            (raises DuplicateKeyError)
    replace_one(filter, replacement) -> bool (True = matched+replaced)
    find_one_and_update(filter, update) -> dict | None
        (atomic conditional update; None = no row matched)

The subset matches the real driver surface one-to-one so production
wiring can inject a genuine collection object without adapter
changes. ``FakeMongoCollection`` implements the same subset
in-memory with declared unique indexes, exact-equality filters (plus
the minimal ``{"$gt": value}`` numeric predicate used by guarded
state transitions), a lock serializing mutating ops (so concurrent
CAS tests prove exactly-once semantics), and failure injection —
unit tests never need a server.

Error model (secret-free, single-line, closed):

- ``DuplicateKeyError``: unique-index collision (mapped by adapters
  to the domain duplicate errors: ``DuplicateIdempotencyKeyError``,
  ``IndexDuplicateError``, ledger ``DuplicateExecutionError``…).
- ``VersionMismatchError`` is NOT a driver error: adapters detect
  ``replace_one(...) is False`` and map it to the domain CAS
  conflicts (``VersionConflictError``, ``IndexVersionConflict``,
  ledger ``LedgerError``…).
- ``MongoUnavailableError``: connectivity/timeout/unknown driver
  failure. Adapters fail closed on it (no unsafe continuation) and
  never log connection strings, credentials, or payload bytes.
"""

from __future__ import annotations

from typing import Protocol

__all__ = [
    "MongoCollection",
    "MongoDriverError",
    "MongoUnavailableError",
    "DuplicateKeyError",
    "FakeMongoCollection",
    "UpdateError",
]


class MongoDriverError(ValueError):
    """Base driver failure (transport/persistence only, never a verdict)."""


class MongoUnavailableError(MongoDriverError):
    """The backing store cannot serve the request (fail closed)."""


class DuplicateKeyError(MongoDriverError):
    """A declared unique index rejected the write."""


class UpdateError(MongoDriverError):
    """An update document was malformed (fail closed, never applied)."""


class MongoCollection(Protocol):
    """Narrow driver subset (real collections satisfy this structurally)."""

    def find_one(self, filter: dict) -> dict | None: ...  # noqa: A002
    def find(self, filter: dict) -> list[dict]: ...  # noqa: A002
    def insert_one(self, document: dict) -> None: ...
    def replace_one(self, filter: dict, replacement: dict) -> bool: ...  # noqa: A002
    def find_one_and_update(
        self, filter: dict, update: dict  # noqa: A002
    ) -> dict | None: ...


def _match(document: dict, filter: dict) -> bool:  # noqa: A002
    """Filter match (flat keys, deterministic).

    Values match by exact equality, except a ``{"$gt": number}``
    predicate value, which matches when the stored value is numeric
    and strictly greater. Only ``$gt`` is supported; anything else
    fails closed (no match) rather than broadening a guard filter.
    """
    if not isinstance(filter, dict):
        raise TypeError("filter must be a dict")
    for key, value in filter.items():
        if not isinstance(key, str):
            raise TypeError("filter keys must be strings")
        if isinstance(value, dict):
            if set(value) != {"$gt"}:
                return False
            bound = value["$gt"]
            stored = document.get(key)
            if (
                not isinstance(stored, (int, float))
                or isinstance(stored, bool)
                or not isinstance(bound, (int, float))
                or isinstance(bound, bool)
            ):
                return False
            if not stored > bound:
                return False
            continue
        if key not in document or document[key] != value:
            return False
    return True


class FakeMongoCollection:
    """In-memory driver fake (tests only; never production Mongo).

    ``unique_indexes`` declares unique key-sets, e.g.
    ``[("_id",), ("execution_id", "seq")]``. ``insert_one`` enforces
    them (``DuplicateKeyError``). ``replace_one`` matches on exact
    equality (including the CAS version field) and returns whether a
    document was replaced. ``fail_next`` / ``fail_always`` inject
    ``MongoUnavailableError`` to prove fail-closed behavior.
    """

    def __init__(
        self,
        unique_indexes: list[tuple[str, ...]] | None = None,
    ) -> None:
        import threading as _threading

        self._docs: dict[str, dict] = {}
        self._unique: list[tuple[str, ...]] = [
            tuple(index) for index in (unique_indexes or [("_id",)])
        ]
        if ("_id",) not in self._unique:
            self._unique.append(("_id",))
        self._fail_always: str | None = None
        self._fail_next: str | None = None
        self._lock = _threading.Lock()
        self.calls: list[str] = []

    def fail_next(self, message: str = "injected driver failure") -> None:
        self._fail_next = message

    def fail_always(self, message: str = "injected driver outage") -> None:
        self._fail_always = message

    def heal(self) -> None:
        self._fail_always = None
        self._fail_next = None

    def _maybe_fail(self, op: str) -> None:
        self.calls.append(op)
        if self._fail_always is not None:
            raise MongoUnavailableError("store unavailable")
        if self._fail_next is not None:
            self._fail_next = None
            raise MongoUnavailableError("store unavailable")

    def _check_unique(self, document: dict, skip_id: str | None = None) -> None:
        for index in self._unique:
            try:
                key = tuple(document[field] for field in index)
            except KeyError:
                continue
            for doc_id, existing in self._docs.items():
                if skip_id is not None and doc_id == skip_id:
                    continue
                try:
                    other = tuple(existing[field] for field in index)
                except KeyError:
                    continue
                if other == key:
                    raise DuplicateKeyError(
                        "unique index collision; refused"
                    )

    def find_one(self, filter: dict) -> dict | None:  # noqa: A002
        self._maybe_fail("find_one")
        for document in self._docs.values():
            if _match(document, filter):
                return dict(document)
        return None

    def find(self, filter: dict) -> list[dict]:  # noqa: A002
        self._maybe_fail("find")
        return [
            dict(document)
            for document in self._docs.values()
            if _match(document, filter)
        ]

    def insert_one(self, document: dict) -> None:
        self._maybe_fail("insert_one")
        if not isinstance(document, dict):
            raise TypeError("document must be a dict")
        if "_id" not in document:
            raise ValueError("document requires an _id")
        record = dict(document)
        with self._lock:
            self._check_unique(record)
            self._docs[record["_id"]] = record

    def replace_one(self, filter: dict, replacement: dict) -> bool:  # noqa: A002
        self._maybe_fail("replace_one")
        if not isinstance(replacement, dict):
            raise TypeError("replacement must be a dict")
        with self._lock:
            for doc_id, document in self._docs.items():
                if _match(document, filter):
                    record = dict(replacement)
                    record["_id"] = doc_id
                    self._check_unique(record, skip_id=doc_id)
                    self._docs[doc_id] = record
                    return True
            return False

    def find_one_and_update(
        self, filter: dict, update: dict  # noqa: A002
    ) -> dict | None:
        """Atomic conditional update; returns the pre-update document.

        Supports ``$set`` (flat keys) and ``$inc`` (numeric) only;
        any other operator fails closed with ``UpdateError`` and
        applies nothing. The match + mutation hold the collection
        lock, so concurrent guarded transitions serialize: exactly
        one winner per guard.
        """
        self._maybe_fail("find_one_and_update")
        if not isinstance(update, dict):
            raise TypeError("update must be a dict")
        with self._lock:
            for doc_id, document in self._docs.items():
                if _match(document, filter):
                    updated = dict(document)
                    for operator, changes in update.items():
                        if operator == "$set":
                            if not isinstance(changes, dict):
                                raise UpdateError("malformed $set")
                            for key, value in changes.items():
                                if not isinstance(key, str) or key == "_id":
                                    raise UpdateError("malformed $set")
                                updated[key] = value
                        elif operator == "$inc":
                            if not isinstance(changes, dict):
                                raise UpdateError("malformed $inc")
                            for key, value in changes.items():
                                if not isinstance(key, str):
                                    raise UpdateError("malformed $inc")
                                current = updated.get(key)
                                if (
                                    not isinstance(current, (int, float))
                                    or isinstance(current, bool)
                                    or not isinstance(value, (int, float))
                                    or isinstance(value, bool)
                                ):
                                    raise UpdateError("malformed $inc")
                                updated[key] = current + value
                        else:
                            raise UpdateError(
                                f"unsupported update operator: {operator}"
                            )
                    self._check_unique(updated, skip_id=doc_id)
                    self._docs[doc_id] = updated
                    return dict(document)
            return None

    def stored_count(self) -> int:
        return len(self._docs)

    def raw(self, doc_id: str) -> dict | None:
        stored = self._docs.get(doc_id)
        return dict(stored) if stored is not None else None


def _safe_detail(detail: str) -> str:
    text = (detail or "")[:200]
    if "\n" in text or "\r" in text:
        raise ValueError("persistence error detail must be single-line")
    lowered = text.casefold()
    for marker in (
        "mongodb://",
        "password",
        "api_key",
        "secret",
        "bearer ",
        "-----begin",
    ):
        if marker in lowered:
            raise ValueError(
                "persistence error detail carries suspected secret material"
            )
    return text


