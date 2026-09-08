"""Driver seam for Stage 2 Mongo-shaped adapters (offline-safe).

``MongoCollection`` is the narrow driver subset every adapter in this
package is written against::

    find_one(filter) -> dict | None
    find(filter) -> list[dict]
    insert_one(document) -> None            (raises DuplicateKeyError)
    replace_one(filter, replacement) -> bool (True = matched+replaced)

The subset matches the real driver surface one-to-one so production
wiring can inject a genuine collection object without adapter
changes. ``FakeMongoCollection`` implements the same subset
in-memory with declared unique indexes, exact-equality filters, and
failure injection — unit tests never need a server.

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
]


class MongoDriverError(ValueError):
    """Base driver failure (transport/persistence only, never a verdict)."""


class MongoUnavailableError(MongoDriverError):
    """The backing store cannot serve the request (fail closed)."""


class DuplicateKeyError(MongoDriverError):
    """A declared unique index rejected the write."""


class MongoCollection(Protocol):
    """Narrow driver subset (real collections satisfy this structurally)."""

    def find_one(self, filter: dict) -> dict | None: ...  # noqa: A002
    def find(self, filter: dict) -> list[dict]: ...  # noqa: A002
    def insert_one(self, document: dict) -> None: ...
    def replace_one(self, filter: dict, replacement: dict) -> bool: ...  # noqa: A002


def _match(document: dict, filter: dict) -> bool:  # noqa: A002
    """Exact-equality filter match (flat keys only, deterministic)."""
    if not isinstance(filter, dict):
        raise TypeError("filter must be a dict")
    for key, value in filter.items():
        if not isinstance(key, str):
            raise TypeError("filter keys must be strings")
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
        self._docs: dict[str, dict] = {}
        self._unique: list[tuple[str, ...]] = [
            tuple(index) for index in (unique_indexes or [("_id",)])
        ]
        if ("_id",) not in self._unique:
            self._unique.append(("_id",))
        self._fail_always: str | None = None
        self._fail_next: str | None = None
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
        self._check_unique(record)
        self._docs[record["_id"]] = record

    def replace_one(self, filter: dict, replacement: dict) -> bool:  # noqa: A002
        self._maybe_fail("replace_one")
        if not isinstance(replacement, dict):
            raise TypeError("replacement must be a dict")
        for doc_id, document in self._docs.items():
            if _match(document, filter):
                record = dict(replacement)
                record["_id"] = doc_id
                self._check_unique(record, skip_id=doc_id)
                self._docs[doc_id] = record
                return True
        return False

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


