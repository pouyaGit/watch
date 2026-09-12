# Stage R31.2 Review — Are inferred components/plugins consumed by CVE matching?

Review-only task. No code was modified, nothing was committed.

## Verdict (short)

**No.** R31.2 inference is correctly implemented and tested in isolation, but
its output never reaches CVE matching, the API, or the UI:

- `build_real_observed_inventory()` (the only function that applies R31.2
  inference) has **no production caller** — only 3 test methods call it.
- The runtime inventory read path used by matching/API/UI is
  `backend/observed_inventory.get_inventory()`, which rebuilds projections from
  `Http`/`Endpoints`/`Subdomains` and **never calls the R31.2 inference** (and
  does not read the `Urls` collection at all).
- The R30.1 matching engine and the R30.3 backend adapter **are** ready to
  consume components/plugins; the missing piece is upstream data wiring.

R31.3 is the missing integration stage.

## 1. Files inspected

Requested:

- `ai/knowledge/component_inference.py`
  - `infer_inventory_items()` (lines 252-318): produces
    `ObservedItem`s with `source="COMPONENT_INVENTORY"` and
    `evidence_type="INFERRED_COMPONENT"` / `"INFERRED_PLUGIN"`.
  - `apply_inferred_items()` (lines 326-391): merges into an
    `ObservedAssetInventory`; explicit items win; returns the same object when
    nothing new is inferred.
- `ai/knowledge/inventory_loader.py`
  - `build_real_observed_inventory()` (lines 46-65): loads MongoEngine records,
    calls `build_observed_inventory()`, then `infer_inventory_items()` +
    `apply_inferred_items()`, and returns the in-memory model.
- `ai/schemas/observed_inventory.py`
  - `EVIDENCE_TYPES` (lines 50-58) now includes `INFERRED_COMPONENT` and
    `INFERRED_PLUGIN`.
  - `ObservedAssetInventory.components` / `.plugins` (lines 224-225) and
    `.version_associations` (lines 232-234) are the model fields an inferred
    item lands in.
- `ai/knowledge/asset_cve_matching.py`
  - `match_component()` (283-304) / `match_plugin()` (307-323): the R30.1
    matchers for the two categories.
  - `calculate_match_confidence()` (609-657): component/plugin matches combine
    with version/supporting evidence.
  - `evaluate_inventory()` (967-1028): accepts `observed_components` and
    `observed_plugins` (981-982) and runs both matchers (995-996).

Supporting (needed to trace consumption; not in the original inspect list):

- `backend/observed_inventory.py` — the live read path:
  `_COLLECTIONS` (51-79), `_records()` (196-227), `build_inventory()` (267-303),
  `get_inventory()` (306-333), `get_inventory_summary()` (336-345).
- `backend/asset_cve_matching.py` — the R30.1 consumer:
  `_inventory_values()` (194-231), `_observed_from_assets()` (162-181),
  `_metadata_observed()` (100-135), `build_matches()` evaluation call
  (385-407).
- `ai/knowledge/observed_inventory.py` — `collect_components()` (301) and
  `collect_plugins()` (319) accept **explicit records only**; no path
  inference.
- `backend/routers/research.py` (846-856) and
  `backend/routers/research_pages.py` (598-599) — API/UI inventory consumers,
  both using `backend.observed_inventory`.
- `ai/knowledge/relevance.py` — `AssetRecord` (127-149) has `components` but
  no `plugins` field; the R17 relevance path is separate.

Graph verification:
`trace_path(inbound, build_real_observed_inventory)` → 3 callers, all in
`tests/test_component_inference.py`.
`trace_path(inbound, get_inventory)` → `backend.asset_cve_matching._inventory_values`,
`backend.asset_cve_matching.build_matches`, `api_research_inventory_program`,
`ui_research_lead_detail` (+3 tests).
`infer_inventory_items` / `apply_inferred_items` have no production caller
except `build_real_observed_inventory`.

## 2. Architecture (current, verified)

```
                         PERSISTED DB COLLECTIONS
        Http.tech      Urls.path      Endpoints.path      Subdomains
            │              │               │                 │
            │              │               │                 │
   ┌────────┴──────────────┴───────────────┴─────────────────┴─────────┐
   │ PATH A — R31.2 loader (ai/knowledge/inventory_loader.py)          │
   │ load_program_inventory_records()   [MongoEngine, database.db]     │
   │   -> build_observed_inventory()    [R30.2 pure, no inference]     │
   │   -> infer_inventory_items()       [R31.2 rules]                  │
   │   -> apply_inferred_items()        [merge components/plugins]     │
   │   -> ObservedAssetInventory (IN MEMORY ONLY)                      │
   └───────────────────────────────────────────────────────────────────┘
             ✗ NO PRODUCTION CALLER (only tests)   ✗ NOT PERSISTED
             ✗ NOT READ BY API/UI/MATCHING

   ┌───────────────────────────────────────────────────────────────────┐
   │ PATH B — runtime inventory read path (backend/observed_inventory) │
   │ pymongo read-only: Http(tech), Endpoints(path/params), Subdomains │
   │   (Urls collection NOT read; Http.url NOT projected)              │
   │   -> build_observed_inventory()    [R30.2 pure, no inference]     │
   │   -> inventory_projection()        [API/UI/JSON]                  │
   └──────────────────────────────┬────────────────────────────────────┘
                                  │ components=[], plugins=[]
                                  ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │ CVE MATCHING (backend/asset_cve_matching.build_matches)           │
   │ _inventory_values()  -> components/plugins (always empty today)   │
   │ _metadata_observed() -> payload metadata components/plugins       │
   │ _observed_from_assets() -> AssetRecord components (no plugins)    │
   │                       ▼                                            │
   │ evaluate_version_association()  [R30.3]                           │
   │ evaluate_inventory()            [R30.1 engine — READY]            │
   └───────────────────────────────────────────────────────────────────┘
                                  │
              API /api/research/matches/...  +  UI lead detail
```

The two paths are **disconnected**: the inferred component/plugin evidence
produced by PATH A is thrown away after the function returns, while PATH B —
the only path matching/API/UI use — builds an inference-free inventory.

## 3. Answers to the review checks

### 3.1 Is component/plugin evidence persisted in ObservedInventory?

Depends on the meaning of "persisted":

- **In the in-memory `ObservedAssetInventory` model:** yes. After
  `build_real_observed_inventory()`, `components`/`plugins` contain
  `ObservedItem`s with `source=COMPONENT_INVENTORY` and `evidence_type`
  `INFERRED_COMPONENT`/`INFERRED_PLUGIN`; `evidence` carries the
  `... inferred from path ... (rule ...)` lines and `generated_from` carries
  `inferred_components`, `inferred_plugins`,
  `component_inference_rule_version="r31-2"`.
- **Durably persisted (Mongo/JSON):** no. There is no new collection, field or
  file; the model is rebuilt on demand. This is by design (R31.2 was forbidden
  to change database schemas), but it means inference must be re-applied by
  every read path.
- **In the runtime projection used by matching/API/UI:** no.
  `backend/observed_inventory.get_inventory()` never calls R31.2 inference, so
  the served `components`/`plugins` lists remain empty unless research metadata
  or asset records independently supply values.

### 3.2 Is `asset_cve_matching.py` able to consume components/plugins?

**Yes — at both engine and adapter level.** The blocker is only upstream.

- Engine: `evaluate_inventory()` accepts `observed_components` /
  `observed_plugins` and runs `match_component()` / `match_plugin()`
  (ai/knowledge/asset_cve_matching.py:981-996). Confidence already handles
  COMPONENT/PLUGIN (`calculate_match_confidence`, 609-657) and blocker codes
  `component_not_observed` / `plugin_not_observed` are resolved from real
  matches only (686-705).
- Adapter: `backend/asset_cve_matching._inventory_values()` already extracts
  `components` and `plugins` from the inventory projection
  (backend/asset_cve_matching.py:211-225) and passes them into
  `evaluate_inventory()` (398-400); they are also passed into
  `evaluate_version_association()` (378-379).
- Because `_inventory_values()` receives projections from
  `backend.observed_inventory` (which never contains inferred items), the lists
  it forwards are empty in practice. The adapter code path is exercised only by
  tests that mock the inventory or inject metadata.

### 3.3 Missing integration for R31.3

The minimal, non-invasive wiring is in the **runtime read path**
(`backend/observed_inventory.py`), so that API/UI/matching all benefit from one
change:

1. **Read the missing persisted evidence.**
   - Add the `urls` collection to `_COLLECTIONS` (currently absent,
     backend/observed_inventory.py:51-79) with at least
     `program_name`, `subdomain`, `path`.
   - Add `url`/`final_url` to the `http` projection if HTTP-URL-based inference
     is desired (currently only `tech` is projected, lines 63-67).
   - Convert `Urls` rows via `UrlRecord.from_document` and return
     `url_records` from `_records()` (196-227) / `_build_records()` (248-264).
2. **Apply R31.2 inference in the read path, then merge.**
   In `build_inventory()` / `get_inventory()` (267-333), after
   `build_observed_inventory(...)` call
   `infer_inventory_items(url_records=..., endpoint_records=...,
   http_records=...)` and `apply_inferred_items(inventory, inferred)` before
   `inventory_projection(...)`. Keep the pure R30.2 layer inference-free; do
   not add inference inside `build_observed_inventory()`.
   - Preserve fail-soft behavior (a rule failure must not empty the inventory).
   - Consider an opt-in/opt-out flag for tests and offline callers.
3. **Cache/summary consistency.**
   `get_inventory()` caches projections for 10s and `get_inventory_summary()`
   rebuilds via `build_inventory()`; inference must be deterministic so cached
   and uncached results match, and the summary must reflect inferred counts.
4. **Preserve provenance through flattening (design decision).**
   `_inventory_values()` (backend/asset_cve_matching.py:210-225) keeps only the
   item `value`, discarding `evidence_type` (`STRUCTURED_COMPONENT` vs
   `INFERRED_COMPONENT`/`INFERRED_PLUGIN`). If R31.3 wants inferred evidence to
   weigh differently (e.g. never promote alone), the adapter needs to carry the
   evidence type alongside the value. If inferred and explicit component
   evidence are intentionally equivalent, document that decision.
5. **R30.3 interaction to test.**
   Once inferred components/plugins flow in, `evaluate_version_association()`
   will match them as `observed_components`/`observed_plugins` and can change
   `version_association_state` from `NO_VERSION_OBSERVATION` to
   `COMPONENT_ASSOCIATED_VERSION_UNKNOWN` for CVEs targeting that
   component/plugin. Inferred evidence creates no `version_associations`
   (no versions are inferred), so `VERSION_MATCH_*` states remain based on
   explicit evidence. R31.3 should lock this behavior with tests.
6. **R17 boundary.**
   `ai/knowledge/relevance.AssetRecord` (127-149) carries `components` but no
   `plugins`, and is built from program definitions/research metadata
   (`assets_from_programs`, `assets_from_research_metadata`), not from the
   observed inventory. Inferring components/plugins will not change R17 unless
   a separate wiring is explicitly requested.

Recommended R31.3 acceptance test (end-to-end, mocked DB read):

```
records (Http.tech + Urls.path + Endpoints.path)
  -> backend.observed_inventory.get_inventory("dell")   # mocked pymongo
  -> components/plugins present with INFERRED_* provenance
  -> backend.asset_cve_matching.build_matches(...)      # matching CVE
  -> strongest_match_type in {COMPONENT, PLUGIN}
```

plus: technologies/versions/associations unchanged, fail-soft on inference
error, determinism, and no new global score.

### 3.4 Implementation

No implementation was performed. `git status` shows only the pre-existing
R31.2 implementation files and this report; no code file was touched.

## 4. Gap summary

| # | Gap | Severity | Evidence |
|---|---|---|---|
| G1 | `build_real_observed_inventory()` has no production caller; inferred evidence is discarded after return | **Blocking** | `trace_path` inbound = tests only |
| G2 | `backend/observed_inventory` does not apply R31.2 inference | **Blocking** | backend/observed_inventory.py:267-333 |
| G3 | `Urls` collection is never read by the runtime read path | High | `_COLLECTIONS`, backend/observed_inventory.py:51-79 |
| G4 | `Http.url`/`final_url` not projected for HTTP-URL inference | Medium | `_COLLECTIONS` http keys, lines 63-67 |
| G5 | `evidence_type` (explicit vs inferred) is dropped when flattening inventory values | Medium (policy decision) | backend/asset_cve_matching.py:210-225 |
| G6 | API/UI inventory views therefore show 0 inferred components/plugins | High (symptom of G2/G3) | routers research.py:856, research_pages.py:599 |
| G7 | Inferred component presence changes R30.3 `version_association_state` (COMPONENT_ASSOCIATED_VERSION_UNKNOWN) without version linkage | Low (expected, needs tests) | backend/asset_cve_matching.py:368-380 |
| G8 | R17 relevance records carry components but no plugins; separate path | Info | ai/knowledge/relevance.py:127-149 |

## 5. Recommended next stage

**R31.3 — Wire R31.2 inferred component/plugin evidence into the observed
inventory read path (backend), so API/UI/CVE matching consume it.**

Scope:

1. Extend `backend/observed_inventory` to read `urls` (and optionally
   `http.url`/`final_url`), build `UrlRecord`s, and apply
   `infer_inventory_items` + `apply_inferred_items` in
   `build_inventory()`/`get_inventory()`/`get_inventory_summary()`.
2. Preserve fail-soft caching and deterministic output; keep the pure R30.2
   builder inference-free.
3. Decide and document whether inferred evidence keeps a provenance marker
   through `backend/asset_cve_matching._inventory_values`.
4. Add end-to-end tests: inferred plugin/component visible in the inventory
   projection and becomes a `PLUGIN`/`COMPONENT` match; technologies,
   versions, and version associations unchanged; R30.1/R30.3 semantics and
   rule versions unchanged; no R17/R25/R26/R29 changes; no DB schema changes.
5. Keep the stage read-only and offline-testable, with the same no-score /
   no-execution boundaries as R31.2.

## 6. Method notes

- Graph tools used: `index_status`, `search_graph`, `trace_path` (inbound),
  `check_index_coverage` — all inspected paths report
  `no_recorded_issue` (best-effort signal; source was still read).
- Direct source reads and grep were used to confirm every cited line.
- No tests were run for the review itself (no code changed); the existing
  R31.2 suite remains green as of the implementation stage.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.2 Review
- Role: Code Review Agent
