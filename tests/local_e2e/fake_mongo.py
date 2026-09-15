"""Minimal in-memory MongoDB test double for the R61 snapshot layer.

Read support only: equality-filtered ``find``/``find_one``, projections,
``sort`` and ``limit``. Every write method raises and is recorded so tests can
prove that the snapshot builder never mutates the database.
"""

from __future__ import annotations

import json
from pathlib import Path


class FakeWriteError(AssertionError):
    """Raised when snapshot code attempts a database write."""


_WRITE_METHODS = (
    "insert_one",
    "insert_many",
    "update_one",
    "update_many",
    "replace_one",
    "delete_one",
    "delete_many",
    "find_one_and_update",
    "find_one_and_replace",
    "find_one_and_delete",
    "bulk_write",
    "create_index",
    "create_indexes",
    "ensure_index",
    "drop",
    "drop_collection",
    "rename",
)


def _sort_key(value: object) -> tuple:
    if value is None:
        return (3, "")
    if isinstance(value, bool):
        return (2, int(value))
    if isinstance(value, (int, float)):
        return (1, value)
    return (0, str(value))


def _sort_specs(key_or_list, direction=None) -> list[tuple[str, int]]:
    if isinstance(key_or_list, str):
        return [(key_or_list, 1 if direction is None else int(direction))]
    specs = []
    for item in key_or_list or ():
        if isinstance(item, str):
            specs.append((item, 1))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            specs.append((str(item[0]), int(item[1])))
        else:
            raise TypeError(f"unsupported sort spec: {item!r}")
    return specs


def _apply_projection(document: dict, projection: dict | None) -> dict:
    if not projection:
        return dict(document)
    includes = [
        key
        for key, value in projection.items()
        if value and key != "_id"
    ]
    if includes:
        projected = {
            key: document[key] for key in includes if key in document
        }
        if projection.get("_id") and "_id" in document:
            projected["_id"] = document["_id"]
        return projected
    excluded = {
        key for key, value in projection.items() if not value
    }
    return {
        key: value
        for key, value in document.items()
        if key not in excluded
    }


def _matches(document: dict, query: dict) -> bool:
    if not isinstance(query, dict):
        raise TypeError("query must be a mapping")
    for key, expected in query.items():
        if document.get(key) != expected:
            return False
    return True


class FakeCursor:
    def __init__(self, documents: list[dict]) -> None:
        self._documents = list(documents)

    def sort(self, key_or_list, direction=None) -> "FakeCursor":
        specs = _sort_specs(key_or_list, direction)
        for field, sort_direction in reversed(specs):
            self._documents.sort(
                key=lambda doc: _sort_key(doc.get(field)),
                reverse=sort_direction < 0,
            )
        return self

    def limit(self, count: int) -> "FakeCursor":
        self._documents = self._documents[: max(0, int(count))]
        return self

    def __iter__(self):
        return iter(list(self._documents))

    def __len__(self) -> int:
        return len(self._documents)


class FakeCollection:
    def __init__(self, documents: list[dict] | None = None) -> None:
        self.documents = [
            dict(document) if isinstance(document, dict) else document
            for document in (documents or [])
        ]
        self.ignore_query = False
        self.read_calls: list[tuple] = []
        self.write_attempts: list[str] = []
        self._client = None

    def bind(self, client: "FakeClient") -> None:
        self._client = client

    def _record_write(self, method: str) -> None:
        self.write_attempts.append(method)
        if self._client is not None:
            self._client.write_attempts.append((method, self))
        raise FakeWriteError(
            f"the snapshot layer must not call {method}"
        )

    def find(self, query: dict, projection: dict | None = None) -> FakeCursor:
        self.read_calls.append(("find", dict(query), dict(projection or {})))
        return FakeCursor(
            [
                _apply_projection(document, projection)
                for document in self.documents
                if isinstance(document, dict)
                and (self.ignore_query or _matches(document, query))
            ]
        )

    def find_one(self, query: dict, projection: dict | None = None):
        self.read_calls.append(("find_one", dict(query), dict(projection or {})))
        for document in self.documents:
            if isinstance(document, dict) and _matches(document, query):
                return _apply_projection(document, projection)
        return None

    def __getattr__(self, name: str):
        if name in _WRITE_METHODS:
            def _write(*args, **kwargs):
                return self._record_write(name)

            return _write
        raise AttributeError(name)


class FakeDatabase:
    def __init__(self, collections: dict[str, list[dict]] | None = None) -> None:
        self._collections: dict[str, FakeCollection] = {}
        for name, documents in (collections or {}).items():
            self._collections[name] = FakeCollection(documents)

    def __getitem__(self, name: str) -> FakeCollection:
        if name not in self._collections:
            self._collections[name] = FakeCollection([])
        return self._collections[name]

    def list_collection_names(self) -> list[str]:
        return sorted(self._collections)


class FakeClient:
    def __init__(self, collections: dict[str, list[dict]] | None = None) -> None:
        self._database = FakeDatabase(collections)
        self.write_attempts: list[tuple] = []
        self.closed = False
        for name in self._database.list_collection_names():
            self._database[name].bind(self)

    def get_default_database(self) -> FakeDatabase:
        return self._database

    def __getitem__(self, name: str) -> FakeCollection:
        collection = self._database[name]
        collection.bind(self)
        return collection

    def close(self) -> None:
        self.closed = True


def load_fixture(path: str | Path | None = None) -> dict:
    fixture = (
        Path(path)
        if path is not None
        else Path(__file__).parent / "fixtures" / "indeed_raw_sample.json"
    )
    return json.loads(fixture.read_text(encoding="utf-8"))


def client_from_fixture(fixture: dict, *, program: str | None = None) -> FakeClient:
    collections = {
        name: list(fixture.get(name) or [])
        for name in (
            "programs",
            "subdomains",
            "live_subdomains",
            "http",
            "urls",
            "endpoints",
        )
    }
    if program is not None:
        for name in (
            "programs",
            "subdomains",
            "live_subdomains",
            "http",
            "urls",
            "endpoints",
        ):
            collections[name] = [
                document
                for document in collections[name]
                if document.get("program_name") == program
            ]
    return FakeClient(collections)
