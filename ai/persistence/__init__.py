"""Production persistence adapters (Stage 2, B2 read/persist seams).

Offline-safe Mongo-shaped adapters behind the EXISTING 5B/5H/5J
seams. Every adapter is constructed over an injected
``MongoCollection``-shaped driver (see ``ai.persistence.driver``):

- unit tests inject ``FakeMongoCollection`` (in-memory, unique-index
  + CAS-replace semantics, failure injection) — no server, no
  credentials, no production data;
- production wiring may inject a real collection object exposing the
  same narrow method subset (``find_one`` / ``find`` /
  ``insert_one`` / ``replace_one``); the subset was chosen to match
  that surface exactly.

Global rules for this package (all test-enforced):

- No live network execution, no DNS, no sockets, no subprocess, no
  browser, no Nuclei, no LLM. These modules persist bytes and
  records only.
- No ``database.db`` import anywhere (it connects at import time).
  Watch-row reads go through duck-typed readers in
  ``ai.persistence.watch_reads``.
- No credential/secret logging: error details are closed, static,
  single-line strings; raw driver exceptions are mapped, never
  re-raised verbatim.
- ``LIVE_TRAFFIC_ENABLED`` / ``LIVE_NUCLEI`` are never referenced
  here, let alone modified.
"""

from __future__ import annotations

__all__: list[str] = []
