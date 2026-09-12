# Stage R31.3 — Wire R31.2 Component/Plugin Inference into Runtime Inventory

Implementation report for the local WSL repository (`/opt/watch`).

- Stage: R31.3
- Action: local code changes only (no deployment, no VM edits, no commit)
- Scope: backend runtime inventory read path + integration tests

## Summary

R31.2 inferred components/plugins are now produced by the runtime read path
(`backend.observed_inventory`) and therefore flow simultaneously to:

- API inventory (`/api/research/inventory/...`),
- UI inventory (research lead detail panel),
- CVE matching (`backend.asset_cve_matching` -> R30.1 engine).

The R30.2 pure builder is untouched; the R30.1/R30.2/R30.3 rule versions are
unchanged; no database field was added or written.

## Files changed

Modified:

- `backend/observed_inventory.py` (R31.3, +69/-17)
  - new read-only projections: `url`/`final_url` added to `http`, new `urls`
    collection (`program_name`, `subdomain`, `url`, `path`),
  - `_records()` now converts `Urls` rows through the existing
    `UrlRecord.from_document` converter and returns `url_records`,
  - new `_empty_records()` helper (now includes `url_records`),
  - new `_apply_inference()`: runs `infer_inventory_items()` and
    `apply_inferred_items()` before projection, fail-soft (any failure returns
    the inference-free inventory),
  - `build_inventory()` / `get_inventory()` now merge inference before
    `inventory_projection()`; `get_inventory_summary()` inherits it via
    `build_inventory()`.

New:

- `tests/test_component_plugin_wiring.py` (14 tests)
  Inventory wiring, API route, UI panel, CVE matching end-to-end, fail-soft,
  determinism, schema validity, rule-version canaries.

Not changed in this stage (R31.2 artifacts remain as delivered):

- `ai/knowledge/component_inference.py`, `ai/knowledge/inventory_loader.py`,
  `ai/schemas/observed_inventory.py`.

Example R31.3 diff (backend/observed_inventory.py):

```diff
+from ai.knowledge.component_inference import (
+    apply_inferred_items,
+    infer_inventory_items,
+)
...
+    "urls": {
+        "program_name": 1,
+        "subdomain": 1,
+        "url": 1,
+        "path": 1,
+    },
...
+        inferred = infer_inventory_items(
+            url_records=records.get("url_records") or (),
+            endpoint_records=records.get("endpoint_records") or (),
+            http_records=records.get("http_records") or (),
+        )
+        return apply_inferred_items(inventory, inferred)
...
-    value = inventory_projection(build_observed_inventory(name, **data))
+    inventory = build_observed_inventory(name, **data)
+    inventory = _apply_inference(data, inventory)
+    value = inventory_projection(inventory)
```

## Design decisions

1. **One wiring point.** Inference is applied inside the shared backend read
   functions (`build_inventory`/`get_inventory`), so API, UI, and CVE matching
   all consume the same projection without touching each consumer. The routers
   (`backend/routers/research.py`, `backend/routers/research_pages.py`) already
   call `observed_inventory.get_inventory(...)` and needed no changes.
2. **R30.2 pure builder stays pure.** `ai/knowledge/observed_inventory.py`
   (and `build_observed_inventory`) was not modified. Inference is applied
   post-build via the existing R31.2 `apply_inferred_items`, which copies
   technologies, products, versions, version associations, parameters and
   paths unchanged and only appends new component/plugin items.
3. **Urls collection included.** `Urls.path` is read for the first time in
   this path (`_COLLECTIONS["urls"]` + `UrlRecord` conversion). `Http.url` /
   `final_url` are also projected so HTTP-URL path evidence can contribute.
   `Endpoints.path` was already read and is passed to the inference.
4. **Deterministic and fail-soft.** `infer_inventory_items` sorts/dedupes
   paths and values, so cached and uncached projections match. `_apply_inference`
   catches any failure and returns the original inventory, so inference can
   never erase technologies/versions/associations.
5. **No provenance change in matching.** `backend/asset_cve_matching._inventory_values`
   still flattens component/plugin values and discards `evidence_type`. This is
   a deliberate, documented decision: inferred evidence is anchored and
   deterministic (`ai/knowledge/component_inference.RULES`), so it is consumed
   with the same R30.1 semantics as explicit evidence. No scoring or confidence
   rule was changed.
6. **No persistence / schema changes.** No new Mongo collection, field, or
   write; `Urls`/`Http` are read with field projections only. The only schema
   change in the R31.x series remains the R31.2 pydantic vocabulary
   (`INFERRED_COMPONENT`, `INFERRED_PLUGIN`).
7. **No version inference.** Inferred components/plugins create no
   `version_associations`; R30.3 association states remain based on explicit
   version evidence. Inferred presence can still select
   `COMPONENT_ASSOCIATED_VERSION_UNKNOWN` when the CVE targets the observed
   component/plugin.

## Before / after data flow

Before R31.3 (verified in `agent-reports/stage-r31-2-review.md`):

```
Http.tech ─┐
Endpoints ─┤ backend/observed_inventory.get_inventory()
Urls   ✗   ├   -> build_observed_inventory()  [R30.2, no inference]
           │   -> projection components=[], plugins=[]
           └─> API/UI/CVE matching see 0 components / 0 plugins
```

After R31.3:

```
Http.tech/url/final_url ─┐
Endpoints.path ──────────┤ backend/observed_inventory.get_inventory()
Urls.path/url ───────────┤   -> build_observed_inventory()      [R30.2 pure]
                         │   -> infer_inventory_items()         [R31.2 rules]
                         │   -> apply_inferred_items()          [additive merge]
                         │   -> projection with components/plugins
                         └─> API /api/research/inventory/...
                             UI  /ui/research/leads/<id>
                             CVE matching build_matches()
                               -> _inventory_values()
                               -> evaluate_version_association()   [R30.3]
                               -> evaluate_inventory()             [R30.1]
```

## Tests executed

Required suite (task-specified):

```
python -m unittest tests.test_observed_inventory \
                   tests.test_asset_cve_matching \
                   tests.test_version_component_association -q
Ran 181 tests in 21.183s
OK
```

Full R31 suite (required + R31.2 + new R31.3 integration):

```
python -m unittest tests.test_observed_inventory \
                   tests.test_asset_cve_matching \
                   tests.test_version_component_association \
                   tests.test_component_inference \
                   tests.test_component_plugin_wiring -q
Ran 244 tests in 20.941s
OK
```

New integration test (`tests/test_component_plugin_wiring.py`, 14 tests)
covers, with Mongo mocked at the raw-document boundary:

- `Http.tech = WordPress`, `Urls.path = /wp-content/plugins/test-plugin/`,
  `Endpoints.path = /assets/ckeditor/plugins/` ->
  inventory `plugins = [test-plugin]` (`INFERRED_PLUGIN`) and
  `components = [CKEditor]` (`INFERRED_COMPONENT`);
- technologies / versions / version associations preserved
  (`rule_version` stays `r30-2`);
- API route `/api/research/inventory/dell` serves the inferred items;
- UI lead-detail inventory panel renders `test-plugin` and `CKEditor`;
- CVE matching produces `COMPONENT` **and** `PLUGIN` matches for a synthetic
  CVE, strongest match `COMPONENT` (explicitly not only `TECHNOLOGY`);
- a negative control with URL/endpoint evidence removed yields no
  COMPONENT/PLUGIN match (proves the inferred evidence is the cause);
- inference failure is fail-soft; repeated reads are deterministic;
- no target identifiers leak; rule versions unchanged; schema-valid output.

Additional regression batch:

```
python -m unittest tests.test_research_api tests.test_hunt_queue \
                   tests.test_opportunity_action_queue \
                   tests.test_research_leads tests.test_research_workflow -q
Ran 228 tests in 42.778s
FAILED (failures=6)
```

The 6 failures (`tests.test_hunt_queue` x3, `tests.test_opportunity_action_queue`
x3) are **pre-existing at the current HEAD**: they reproduce identically with
the R31.3 change stashed, and are unrelated to R31.3. The task-required suites
are fully green.

## Example output

Input (mocked Mongo documents): `Http.tech = WordPress`, `Urls.path =
/wp-content/plugins/test-plugin/`, `Endpoints.path =
/assets/ckeditor/plugins/`.

`backend.observed_inventory.get_inventory("dell")`:

```
technologies: ['WordPress']
versions:     []
associations: []
components:   [('CKEditor', 'INFERRED_COMPONENT')]
plugins:      [('test-plugin', 'INFERRED_PLUGIN')]
```

`backend.asset_cve_matching.build_matches(...)` with a synthetic CVE whose
component is `CKEditor` and whose affected product is `test-plugin`:

```
strongest_match_type: COMPONENT
strongest_confidence: MEDIUM
asset_match_state:    SUPPORTED
all match types:      ['COMPONENT', 'PLUGIN']
matched_component:    CKEditor
```

With versioned tech (`WordPress:6.8.3`) the same chain additionally preserves
`versions: ['6.8.3']` and `version_associations: [('6.8.3', 'WordPress')]`,
and R30.3 reports `FAMILY_MISMATCH` because the observed WordPress version does
not belong to the synthetic CVE's `test-plugin` family (expected R30.3
behavior; no version association is invented for inferred components).

## Known limitations

- `evidence_type` (`INFERRED_*` vs `STRUCTURED_*`) is not propagated into the
  R30.1 matcher input; inferred and explicit component/plugin values are
  treated equivalently. This is intentional for R31.3 (no scoring change) but
  means no downstream distinction if a future stage needs it.
- Inference only proves *presence* of a component/plugin; it creates no
  versions and no `version_associations` (no version inference).
- The rule coverage is exactly `ai/knowledge/component_inference.RULES`
  (WordPress plugins/mu-plugins/themes, CKEditor/FCKfinder/FCKeditor/TinyMCE,
  Drupal modules, Joomla components/modules, jQuery); other frameworks need a
  new anchored rule.
- The `Urls` projection reads only `program_name/subdomain/url/path`; no
  params/sources are read (not needed for path inference).
- `build_inventory()` over all programs now performs inference per program;
  bounded by `MAX_PROGRAMS=200` and the R31.2 caps, but it remains a
  read-only, on-demand computation (no persistence/caching beyond the existing
  10s projection cache in `get_inventory`).
- R17 relevance records still do not consume inferred components/plugins (out
  of scope; the R17 path is separate).
- 6 pre-existing test failures in `hunt_queue` /
  `opportunity_action_queue` at HEAD are unrelated to this stage.

## Validation commands

```
$ git diff --stat
 ai/knowledge/inventory_loader.py | 25 ++++++++++--
 ai/schemas/observed_inventory.py | 13 ++++--
 backend/observed_inventory.py    | 86 ++++++++++++++++++++++++++++++++--------
 3 files changed, 101 insertions(+), 23 deletions(-)

$ git status --short
 M ai/knowledge/inventory_loader.py
 M ai/schemas/observed_inventory.py
 M backend/observed_inventory.py
?? agent-reports/stage-r31-2-component-inference.md
?? agent-reports/stage-r31-2-review.md
?? ai/knowledge/component_inference.py
?? tests/test_component_inference.py
?? tests/test_component_plugin_wiring.py

$ git diff --check
(clean)
```

Note: `ai/knowledge/inventory_loader.py` and
`ai/schemas/observed_inventory.py` are the prior R31.2 working-tree changes
(not modified by R31.3); `backend/observed_inventory.py` is the R31.3 change.

## Boundary confirmation

- Local WSL-only changes; no deployment, no VM edits, no commit.
- Read-only: no Mongo writes, no new collections/fields, no persistence.
- No network/DNS/subprocess/LLM/Nuclei/browser/PoC/target interaction.
- No new score; no R17/R18/R25/R26/R29 changes; R30.1/R30.2/R30.3 rule
  versions and semantics unchanged.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.3
- Role: Component/Plugin Inference Wiring Implementation Agent
