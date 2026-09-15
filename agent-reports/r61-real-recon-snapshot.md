# R61 — Real Recon Snapshot & Normalization Layer

- **Date:** 2026-09-15
- **Repository:** `/opt/watch`
- **Parent HEAD:** `7516161` (`feat(copilot): add r60 watch bug bounty copilot`)
- **Task type:** Additive implementation. No production module changed, no test changed, no push.
- **Scope:** First part of the normalization boundary from
  `agent-reports/real-data-mapping-audit.md`: offline-first real recon
  snapshot + normalization only. The R59/R60 bridge is **not** implemented.

---

## 1. Implementation Summary

A new, isolated, additive package implements the first half of the proposed
normalization boundary:

```
MongoDB (read-only, program-scoped, projection-based, bounded)
        -> raw projected records
        -> existing Record classes / _Document compatibility
        -> normalized deterministic snapshot
        -> records= injection
        -> existing R30.2 / R31-R38 pipeline
```

Key properties:

- **Read-only and bounded:** only `find` / `find_one` with projections, a
  deterministic server-side sort and an explicit `limit(cap * fetch_factor)`.
  No insert/update/delete/replace, no index creation, no drop, no bulk write,
  no unbounded cursor.
- **Program-scoped:** every collection query filters on one exact
  `program_name`; rows whose relationship key does not match are defensively
  skipped and counted.
- **Reuses existing adapters:** the raw document -> record conversion uses
  `backend.observed_inventory._Document` (the `_id` -> `id` compatibility
  shim) and the existing `ai.researcher.target_intelligence` record classes
  (`SubdomainRecord`, `HttpRecord`, `UrlRecord`, `EndpointRecord`). No
  matching, scoring, version comparison or inference logic is duplicated.
- **Deterministic:** stable ordering at three levels (server sort, in-memory
  priority selection, final output sort), content-independent natural-key
  `record_ref` identity, no timestamps, canonical JSON with sorted keys.
- **Offline replay:** `save_snapshot` / `load_snapshot` + `records_for_inventory`
  produce the exact mapping consumed by the **existing, unmodified**
  `backend.observed_inventory.build_inventory(program, records=...)`.
- **No `_id` exposure:** every projection explicitly excludes `_id`
  (`"_id": 0`) and no snapshot field can carry it.
- **No network/execution:** a stored URL is data; it is never fetched,
  resolved, or executed. The module does not import `pymongo` at import time
  (only inside `build_snapshot` when no client is injected).

---

## 2. Files Created / Modified

Created (all additive, isolated under `tests/local_e2e/`):

| File | Lines | Role |
|---|---|---|
| `tests/local_e2e/__init__.py` | 1 | Package marker |
| `tests/local_e2e/recon_snapshot.py` | 840 | Snapshot builder + normalization + replay API |
| `tests/local_e2e/fake_mongo.py` | 240 | In-memory read-only Mongo double (write attempts raise) |
| `tests/local_e2e/test_recon_snapshot.py` | 721 | Deterministic tests A–N |
| `tests/local_e2e/test_recon_inventory_integration.py` | 145 | Snapshot -> `build_inventory(records=...)` integration |
| `tests/local_e2e/fixtures/indeed_raw_sample.json` | 263 | Tiny sanitized Indeed-shaped fixture |
| `agent-reports/r61-real-recon-snapshot.md` | this file | Report |

Modified: **none**. Production modules under `backend/`, `ai/`, `database/`,
`crawl/`, `ns/` are untouched, as are existing tests, R59/R60, execution and
authorization code.

---

## 3. Snapshot Schema

Top level (canonical JSON, `sort_keys=True`, 2-space indent, trailing newline):

```json
{
  "snapshot_version": 1,
  "rule_version": "r61-1",
  "program": "indeed",
  "read_only": true,
  "research_only": true,
  "caps": {"<collection>": 0},
  "fetch_factor": 5,
  "program_metadata": {"program_name": "...", "scopes": [], "ooscopes": []},
  "collections": {
    "<collection>": {
      "stats": {
        "fetched": 0,
        "selected": 0,
        "skipped_other_program": 0,
        "malformed": 0,
        "duplicates_dropped": 0
      },
      "records": []
    }
  },
  "stats": {
    "total_fetched": 0,
    "total_selected": 0,
    "collections": {"<collection>": "same stats object"}
  }
}
```

Record shapes (every record carries `record_ref`; no `_id`, no timestamps):

| Collection | Fields |
|---|---|
| `subdomains` | `record_ref`, `program_name`, `subdomain`, `scope`, `providers[]` |
| `live_subdomains` | `record_ref`, `program_name`, `subdomain`, `scope`, `ips[]`, `cdn` |
| `http` | `record_ref`, `program_name`, `subdomain`, `scope`, `ips[]`, `tech[]`, `title`, `status_code`, `url`, `final_url`, `favicon` |
| `urls` | `record_ref`, `program_name`, `subdomain`, `url`, `path`, `params[]`, `sources[]` |
| `endpoints` | `record_ref`, `program_name`, `subdomain`, `path`, `example_url`, `params[]`, `params_from_crawl[]`, `params_from_x8[]`, `x8_checked`, `hit_count`, `param_records[{name, method, location, source}]` |

Normalization rules:

- all string fields are single-lined and length-bounded per field
  (URL/path 2048, title/tech 512, params 128, sources/IP 256, …);
- list fields are sorted and deduplicated (`providers`, `ips`, `tech`,
  `params`, `params_from_crawl`, `params_from_x8`, `sources`);
- `param_records` entries are deduplicated and sorted by
  `(name, method, location, source)`; entries with an empty name are dropped;
- `status_code` / `hit_count` stay integers when stored, else `null`;
- `x8_checked` is normalized to a strict boolean;
- `created_date` / `last_update` are dropped entirely (deterministic identity
  and byte-stable snapshots);
- HTTP `headers` are never projected, so header values (for example cookies)
  cannot reach the snapshot; a regression test asserts a fixture secret cookie
  value never appears in serialized output.

Public API:

```python
build_snapshot(program, *, client=None, uri=None, caps=None,
               fetch_factor=None, collections=None,
               include_program=True, timeout_ms=800) -> dict
save_snapshot(snapshot, path) -> Path
load_snapshot(path) -> dict
snapshot_to_json(snapshot) -> str
records_for_inventory(snapshot) -> dict   # for build_inventory(records=...)
canonicalize_url(value) -> str
record_ref(program, collection, natural_key) -> str
```

---

## 4. Cap Policy

Defaults (also the documented regression-tested values):

| Collection | Default cap |
|---|---|
| `subdomains` | 500 |
| `live_subdomains` | 500 |
| `http` | 300 |
| `urls` | 1000 |
| `endpoints` | 1000 |

- Every cap is configurable per call via `caps={...}` (unknown keys,
  booleans, non-integers and negatives raise `SnapshotError`; `0` yields an
  empty collection). `fetch_factor` (default 5, must be >= 1) controls the
  bounded read window.
- Reads are `find(query, projection).sort(...).limit(cap * fetch_factor)`,
  so a collection is never materialized in full.
- Selection after the bounded fetch:
  - `endpoints`: params present → provenance present → `hit_count` descending
    → `subdomain` → `path`;
  - `urls`: params present → interesting-path signal (api/graphql/admin/auth/
    login/token/upload/redirect/internal, derived only from the stored path)
    → `subdomain` → `url`;
  - `http`: tech present → non-404 status → `subdomain` → `url`;
  - `subdomains` / `live_subdomains`: `subdomain`.
- Impact numbers are never invented; ordering uses stored fields only.
- Final output is re-sorted by the stable natural key so the snapshot does
  not depend on selection order.

---

## 5. Deterministic Identity Strategy

```python
record_ref = "rec-" + sha256(canonical_json({
    "collection": collection,
    "natural_key": [raw stable values],
    "program": program,
}))[:16]
```

Natural keys:

| Collection | Natural key |
|---|---|
| `subdomains` | `(subdomain,)` |
| `live_subdomains` | `(subdomain,)` |
| `http` | `(subdomain, raw_url)` |
| `urls` | `(raw_url,)` |
| `endpoints` | `(subdomain, stored_path)` |

Properties, each covered by a test:

- the same input always produces the same `record_ref` (and the same
  snapshot bytes);
- refs are collection-scoped (a shared key never collides across
  collections);
- refs never depend on Mongo `_id` (all fixture `_id` values can be replaced
  without changing the snapshot);
- `_id` never appears in the serialized snapshot;
- the existing `_Document` + `from_document` compatibility is preserved for
  callers that do pass `_id`-bearing documents (`record_id` becomes the string
  form of `_id` there), while the snapshot path uses the deterministic ref;
- timestamps are excluded from identity and from the snapshot.

`record_ref` is the stable handle a future R59/R60 bridge will use; that bridge
is out of scope for this task.

---

## 6. URL Normalization Strategy

Conservative and idempotent (`canonicalize_url`), only rewriting the artifact
classes identified by the mapping audit:

| Artifact | Rule |
|---|---|
| literal `\u0026` (one or more backslashes before `u0026`) | regex `\\+u0026` → `&` |
| HTML entity `&amp;` | repeated replacement → `&` (handles `&amp;amp;`) |
| trailing backslash artifacts | trailing `\` stripped |
| leading/trailing whitespace / newlines | single-lined and stripped |

Explicit non-changes (regression-tested):

- percent-encoding is preserved verbatim (`%3A`, `%2F`, …);
- query parameter order is preserved;
- path casing is preserved;
- the stored `params` / `params_from_crawl` / `params_from_x8` lists remain
  authoritative and are never re-derived from the URL (e.g. a URL containing
  `&amp;` keeps the stored `["amp;co", "hl"]` params exactly);
- `path` is taken from the stored field (already normalized at write time)
  and is not recomputed.

`canonicalize_url(canonicalize_url(x)) == canonicalize_url(x)` is asserted.

---

## 7. Tests Executed

All test invocations were offline; no test connected to MongoDB. Existing
tests were not modified.

### 7.1 New focused tests

```text
./venv/bin/python -m pytest tests/local_e2e -q -p no:cacheprovider
59 passed, 14 subtests passed in 0.65s
```

Coverage maps to the required A–N matrix:

| Requirement | Test |
|---|---|
| A same input → same snapshot | `TestSnapshotDeterminism.test_same_input_same_snapshot`, `test_input_order_does_not_matter` |
| B same input → same record_ref | `TestSnapshotDeterminism.test_record_refs_are_stable`, `test_record_refs_ignore_mongo_ids`, `test_record_ref_is_collection_scoped` |
| C `_id` never serialized | `TestNoIdExposure.test_id_key_and_values_never_serialized`, `test_snapshot_records_use_rec_refs` |
| D ordering deterministic | `TestOrdering.test_output_ordering_is_deterministic`, `test_endpoint_priority_prefers_params_provenance_and_hits`, `test_url_priority_prefers_params_then_interesting_paths` |
| E caps enforced | `TestCapsAndBounds.test_default_caps_are_the_documented_values`, `test_caps_are_enforced`, `test_zero_cap_yields_empty_collection`, `test_fetch_is_bounded_by_cap_times_factor`, `test_caps_are_validated`, `test_fetch_factor_is_validated` |
| F program isolation | `TestProgramIsolation.*` incl. query-scope assertion and rogue-row defensive counting |
| G parameter provenance | `TestProvenanceAndFields.test_parameter_provenance_is_preserved` |
| H `x8_checked` / `hit_count` | `TestProvenanceAndFields.test_x8_and_hit_count_are_preserved`, `test_status_and_technology_are_preserved` |
| I URL canonicalization | `TestUrlCanonicalization.*` (idempotence, escapes, entities, trailing backslash, encoding preserved) |
| J params authoritative | `TestParamsAuthoritative.*` |
| K load without Mongo | `TestOfflineReplay.test_save_and_load_roundtrip_without_mongo`, `test_load_rejects_malformed_snapshots` |
| L feeds inventory builder | `TestOfflineReplay.test_records_for_inventory_roundtrip`, `test_loaded_snapshot_feeds_inventory_builder` + integration file |
| M no DB writes | `TestNoDatabaseWrites.*` (write attempts recorded and zero; write methods raise; module source token scan) |
| N malformed/empty fail safe | `TestMalformedAndEmpty.*` (malformed rows counted/skipped, non-mappings ignored, empty snapshot, invalid program) |

### 7.2 Integration test (requirement 13)

`tests/local_e2e/test_recon_inventory_integration.py` builds the snapshot from
the sanitized fixture, saves/loads it without Mongo, reconstructs records and
calls the **existing** `backend.observed_inventory.build_inventory(program,
records=...)`. Verified survivors: `technologies` (nginx, jQuery, HSTS,
Cloudflare, HTTP), `versions` (1.24.0, 3.5.1), `version_associations`
(nginx/1.24.0, jQuery/3.5.1), `parameters` (co, continue, client, kw, sid),
`paths` (`/auth`, `/notifications/api/{id}/getNotificationsCount`,
`/signals/log`), `parameter_paths` (`co`/`continue` → `/auth`, `client` →
notifications path) and inventory `sources` (TECHNOLOGY_INVENTORY,
PARAMETER_INVENTORY, ENDPOINT_INVENTORY). Determinism is asserted by rebuilding
the inventory from the same snapshot and comparing canonical JSON. A
`mock.patch` guard proves `_fetch_documents` is never called on the injection
path.

### 7.3 Relevant existing pure tests (no live Mongo)

```text
./venv/bin/python -m pytest ai/test_target_intelligence.py ai/test_target_matcher.py \
    tests/test_component_inference.py tests/test_hunt_priority.py -q -p no:cacheprovider
235 passed in 2.36s

./venv/bin/python -m pytest tests/test_observed_inventory.py \
    -k "not BackendRealCorpus and not R301Integration and not Cli and not Api and not Ui \
        and not no_persistence_side_effects and not money_not_touched" -q -p no:cacheprovider
36 passed, 25 deselected, 5 subtests passed in 0.91s

./venv/bin/python -m pytest tests/test_asset_cve_matching.py \
    -k "not BackendRealCorpus and not AdditiveIntegration and not Cli and not Api and not Ui \
        and not no_persistence_side_effects and not money_not_touched" -q -p no:cacheprovider
56 passed, 23 deselected, 6 subtests passed in 0.65s
```

The deselected cases are the pre-existing backend/CLI/API/UI tests that call
`build_inventory()` / `build_matches()` without mocks and would read the live
Google DB (documented in `agent-reports/real-data-mapping-audit.md`); they were
intentionally not executed, per the "no live Mongo reads" instruction.

Totals: **386 passed, 25 subtests passed, 0 failed** across the new and
relevant existing focused tests.

---

## 8. Git Status and HEAD

Working tree after implementation (before the single commit):

```text
$ git status --short
 D utils.zip
?? agent-reports/R31-final-github-audit.md
?? agent-reports/local-testing-readiness-audit.md
?? agent-reports/real-data-mapping-audit.md
?? agent-reports/r61-real-recon-snapshot.md
?? agent-reports/stage-r31-5-planning-audit.md
?? tests/local_e2e/
?? watch.zip
```

Current HEAD before the commit: `7516161`.

Only the six new `tests/local_e2e/` files and this report are staged for the
single allowed commit; all pre-existing worktree items (` D utils.zip`,
`?? watch.zip`, earlier untracked audit reports) are left untouched and are
**not** part of the commit.

---

## 9. Safety Confirmations

- **No MongoDB writes occurred.** The implementation and every test use only
  `find` / `find_one` reads. The in-memory double records and raises on any
  write attempt, and a source-token regression test asserts no write operator
  exists in the snapshot module. No live DB connection was made during this
  task: all snapshot builds used the injected in-memory client, and all
  inventory tests used `records=`.
- **No active security testing occurred.** No scans, crawling, fuzzing,
  exploitation, payloads or requests were sent to Indeed or any target. No
  DNS resolution, browser automation, nuclei or subprocess execution. Stored
  URLs are treated as data only.
- **No VPS / Google VM access.** Nothing was read from or written to the VPS
  or Google VM in this task; no SSH, no remote command, no configuration
  change.
- **No push performed.** `git push` was not run; no remote state was touched.
- **No production code modified.** `backend/`, `ai/`, `database/`, `crawl/`,
  `ns/`, R59, R60, execution and authorization code are untouched; existing
  tests are untouched.

---

## 10. Next Step (out of scope of this task)

The second half of the boundary remains intentionally unimplemented: the
bounded R59/R60 bridge (project R31-R38 summary references into
`intelligence_context` / `research_context`, plus deterministic specialist
signal seeding). The snapshot API is ready for it: `load_snapshot` +
`records_for_inventory` feed the R30.2/R31 chain, and `record_ref` provides
stable handles for a future bridge.
