# Stage R31.5 — Evidence Provenance and Component-Scoped Support

Local WSL implementation. No commit, no push, no VM access, no deployment.

## Objective

Make the asset/CVE pipeline distinguish **explicit** from **path-inferred**
component/plugin evidence and require supporting PARAMETER/PATH evidence to be
**component-scoped** before it can promote inferred-only evidence to
HIGH/CONFIRMED. Preserve all existing R30.1 semantics for explicit evidence and
keep the R30.1 engine untouched.

## Problem

R31.3/R31.4 made real, path-inferred components/plugins flow into matching
(Dell: CKEditor, dell-virtual-rack-theme, jQuery, TinyMCE, wp-smushit), but the
adapter flattened observed items to plain value strings and dropped
`evidence_type`, `source` and the owning path. R30.1 confidence rule 3
(`COMPONENT/PLUGIN + supporting PARAMETER/PATH -> HIGH`) therefore treated a
single path-inferred component exactly like a structured explicit component and
allowed *any* globally observed parameter/path to promote it.

Verified before this stage (planning audit):

```
evaluate_inventory(
    cve_components=["CKEditor"], cve_parameters=["src"],
    observed_components=["CKEditor"],   # inferred from one path
    observed_parameters=["src"],        # observed elsewhere on the asset
)
-> COMPONENT HIGH CONFIRMED
```

The `src` parameter was never proven to belong to CKEditor. This is a
false-positive regression created by R31.3/R31.4 interacting with unchanged
R30.1 rules.

## Current R30.1 Interaction

- `ai/knowledge/asset_cve_matching.py` is **not modified** in this stage: no
  rule change, no rule-version change, no alias change, no
  `match_component()`/`match_plugin()` change.
- The fix lives entirely in the backend adapter
  (`backend/asset_cve_matching.py`), which adapts the **inputs** supplied to
  `evaluate_inventory()`. This mirrors the R30.3 precedent (family-scoped
  version filtering at the adapter, engine unchanged).
- R30.3 version association remains unchanged and independent: a version match
  (`VERSION` + component/plugin) can still reach HIGH on its own.

## Design

```
R31.4 inference (component_inference)
        |  components/plugins + provenance {value, evidence_path, scope_path, rule}
        v
inventory schema (ObservedAssetInventory.component_provenance, parameter_paths)
        |  path-only, bounded, serialized in the projection
        v
backend observed_inventory projection (R31.3 read path, unchanged shape + 2 fields)
        v
backend asset/CVE adapter (build_matches)
        |
        +-- classify observed component/plugin evidence:
        |      explicit (STRUCTURED_*/EXPLICIT_FIELD/asset/metadata)
        |      inferred (INFERRED_*/provenance)
        |      -> MIXED when both
        |
        +-- explicit or mixed: pass global support (today's behavior)
        |
        +-- inferred-only:
        |      compute owning scopes of the matched inferred values
        |      pass ONLY component-scoped paths/parameters
        |      record withheld global support additively
        v
unchanged R30.1 engine (evaluate_inventory)
```

## Data Model

New additive schema members in `ai/schemas/observed_inventory.py`:

- `EVIDENCE_PROVENANCE_RULE_VERSION = "r31-5"`.
- `ObservedProvenance`:
  `value`, `category` (COMPONENT|PLUGIN), `evidence_type`
  (INFERRED_COMPONENT|INFERRED_PLUGIN), `evidence_path`, `scope_path`,
  `rule_id`, `source`.
- `ObservedParameterPath`: `parameter`, `path`, `source`.
- `ObservedAssetInventory.component_provenance` and
  `ObservedAssetInventory.parameter_paths` (both default empty, deduplicated,
  bounded by `MAX_ITEMS = 2000`).
- `_path_only()` sanitizer used by both models: strips scheme/host via
  `urlsplit`, drops query/fragment, forces a leading `/`, bounds length.

The inventory projection carries both fields automatically
(`inventory_projection` = `model_dump(mode="json")`). No Mongo collection,
field or write was added.

## Scope Algorithm

`ai/knowledge/component_inference.py` now computes a canonical owning scope per
inferred value while it already has the regex match (no new path scan):

- value-capturing rules (`/wp-content/plugins/<slug>/`) → scope includes the
  captured segment: `/wp-content/plugins/wp-smushit/`;
- fixed directory-token rules (`/ckeditor/`, `/tinymce/`, ...) → scope
  includes the token: `/assets/ckeditor/`;
- fixed filename rules (jQuery) → scope is the containing directory:
  `/assets/js/`.

Path-only string slicing; deterministic; patterns and rules are unchanged.

The adapter (`backend/asset_cve_matching.py`) determines support scope with
deterministic normalized prefix/segment checks (no fuzzy matching):

- a support **path** is `COMPONENT_SCOPED` when it equals or starts with one of
  the matched inferred values' owning scopes (segment-boundary prefix,
  trailing `/` enforced);
- a support **parameter** is `COMPONENT_SCOPED` only when at least one
  `parameter_paths` endpoint carrying that parameter is inside a matched scope
  (parameters never inherit scope from the asset as a whole);
- multiple inferred components are evaluated per CVE: only the scopes of the
  values that actually match that CVE's components/plugins are used, so an
  CKEditor-scoped parameter cannot support TinyMCE.

`ai/knowledge/observed_inventory.py` adds `collect_parameter_paths()` which
emits the parameter → path-only endpoint linkage from the existing
`Endpoints`-derived projections (deduplicated, bounded by `_MAX_ITEMS`).

## Matching Behavior

Closed vocabularies:

- `evidence_provenance`: `EXPLICIT` | `INFERRED` | `MIXED`
- `support_scope`: `COMPONENT_SCOPED` | `GLOBAL` | `NONE`

Decision table (per CVE × program):

| Observed component/plugin evidence matching the CVE | Provenance | Support passed to R30.1 | Result |
|---|---|---|---|
| any explicit (with or without inferred) | `EXPLICIT` or `MIXED` | global parameters/paths (today's behavior) | unchanged |
| inferred-only | `INFERRED` | only component-scoped parameters/paths | HIGH only when scoped support or a version association exists |
| inferred-only, no scoped support | `INFERRED` | none | component-only MEDIUM/SUPPORTED; global support withheld and recorded |
| no component/plugin match | `EXPLICIT` (neutral) | global | unchanged |

Additive summary fields (no new score, no existing field reinterpreted):

- `evidence_provenance`
- `support_scope`
- `withheld_support` (bounded by `MAX_WITHHELD_SUPPORT = 64`, path-only text)
- `evidence_provenance_rule_version = "r31-5"`

## Files Changed

- `ai/schemas/observed_inventory.py` — `ObservedProvenance`,
  `ObservedParameterPath`, two additive inventory fields, bounds/validators,
  path-only sanitizer, rule-version constant.
- `ai/knowledge/component_inference.py` — `_owner_scope()`; `infer_inventory_items()`
  returns structured `provenance`; `apply_inferred_items()` merges provenance
  additively (even when an explicit item wins), preserves `parameter_paths`,
  and records the provenance rule version.
- `ai/knowledge/observed_inventory.py` — `collect_parameter_paths()` and its
  wiring into `collect_program_inventory()`/`build_observed_inventory()` and
  summary counts.
- `backend/asset_cve_matching.py` — provenance classification, scope gate,
  withheld-support recording, additive summary fields; O(N) seen-set dedup in
  `_merge_unique()`/`_inventory_values()` (see Performance).
- `tests/test_component_inference.py` — one assertion updated: explicit item
  still wins in the category list, and the inferred provenance is now retained
  additively (intended R31.5 MIXED groundwork).
- `tests/test_component_evidence_provenance.py` — new focused module (15 tests).
- `agent-reports/stage-r31-5-evidence-provenance.md` — this report.

`ai/knowledge/asset_cve_matching.py` and `ai/knowledge/vulnerability_fingerprint.py`
(R31.1) were **not** modified.

## Tests

Commands (venv used because it carries the project dependencies):

```bash
./venv/bin/python -m unittest tests.test_component_inference -q
./venv/bin/python -m unittest tests.test_component_plugin_wiring -q
./venv/bin/python -m unittest tests.test_observed_inventory -q
./venv/bin/python -m unittest tests.test_asset_cve_matching -q
./venv/bin/python -m unittest tests.test_version_component_association -q
./venv/bin/python -m unittest tests.test_component_evidence_provenance -q
```

New module coverage (`tests/test_component_evidence_provenance.py`):

1. provenance propagation through the real backend read path (value,
   INFERRED evidence type, evidence path, scope, rule id) + parameter-path
   linkage;
2. privacy: full-URL inputs become path-only (inference and schema);
3. FP regression: inferred component + unrelated global parameter →
   not HIGH/CONFIRMED, withheld recorded;
4. explicit compatibility: explicit component + global parameter keeps
   HIGH/CONFIRMED;
5. scoped support: parameter under the component scope → COMPONENT_SCOPED and
   allowed to promote;
6. unrelated support: not COMPONENT_SCOPED, no promotion;
7. MIXED: explicit + inferred same component → MIXED, explicit semantics win;
8. determinism under input-order permutation;
9. multiple inferred components: CKEditor-scoped parameter does not support
   TinyMCE, and does support CKEditor;
10. fail-soft malformed provenance; existing technologies/versions/parameters/
    paths intact;
11. provenance bounded by `MAX_ITEMS`.

## Test Results

```
tests.test_component_inference                Ran 53 tests  OK
tests.test_component_plugin_wiring            Ran 14 tests  OK
tests.test_observed_inventory                 Ran 61 tests  OK
tests.test_asset_cve_matching                 Ran 79 tests  OK
tests.test_version_component_association      Ran 41 tests  OK
tests.test_component_evidence_provenance      Ran 15 tests  OK
combined                                      Ran 263 tests OK (0 failures)
```

`git diff --check` is clean.

## False-Positive Regression

Before R31.5 (verified in the planning audit; engine called with global
support):

```
COMPONENT HIGH CONFIRMED
summary: "Exact affected product/component observed."
```

After R31.5 (adapter, inferred-only CKEditor, `src` observed at `/api/users`,
unrelated to `/assets/ckeditor/`):

```
COMPONENT MEDIUM SUPPORTED
evidence_provenance: INFERRED
support_scope:       NONE
withheld_support:    ["parameter 'src' observed globally (not component-scoped)"]
```

The inferred component match is retained; the unrelated global parameter no
longer promotes it, and the withheld evidence is recorded additively.

## Explicit Compatibility

Same shape with `STRUCTURED_COMPONENT` evidence (no inferred provenance):

```
COMPONENT HIGH CONFIRMED
evidence_provenance: EXPLICIT
support_scope:       GLOBAL
withheld_support:    []
```

Existing explicit R30.1 behavior is preserved; all R30.1 suites pass unchanged.

## Determinism

- Inference already selects a canonical `(path, rule_id, value)` per normalized
  value; the scope is derived from that same canonical match.
- Scope/parameter maps are built from sets and sorted where order matters;
  withheld lines are sorted and bounded.
- Test 8 permutes component/plugin/provenance/parameter/path/parameter-path
  order and asserts identical
  `strongest_match_type`/`strongest_confidence`/`asset_match_state`/
  `evidence_provenance`/`support_scope`/`withheld_support`/
  `evidence_provenance_rule_version`.
- Re-running the suites repeatedly produces identical results (no clock, no
  randomness, no LLM, no network).

## Privacy

- `ObservedProvenance.evidence_path`/`scope_path` and
  `ObservedParameterPath.path` are path-only by construction and by schema
  validator (`_path_only` strips scheme/host/query/fragment).
- Test 2 feeds `https://example.com/assets/ckeditor/ckeditor.js` and asserts the
  stored evidence path is `/assets/ckeditor/ckeditor.js` with no `://` and no
  `example.com`.
- `withheld_support` contains only parameter names and path-only strings.
- No program/target identifiers are introduced; existing inventory privacy
  behavior is unchanged.

## Performance

- Provenance/scope processing is a single linear pass:
  path scope check is O(observed_paths × matched_scopes) with precomputed
  path keys and segment-prefix comparisons; parameter scoping is
  O(observed_parameters) against a prebuilt normalized parameter→locations map.
  No path is scanned against every component; no O(N²).
- Measured with a synthetic 200,001-path projection:
  - inferred (gating active): **0.51 s** end-to-end `build_matches`;
  - explicit (no gating): **1.36 s**.
- While measuring, the pre-existing adapter list dedup (`value not in list`)
  was found to be O(N²) on large path lists. It is now an order-preserving
  seen-set in `_merge_unique()` and `_inventory_values()`; output is unchanged
  (all existing tests pass). This is required for the R31.5 provenance path to
  be usable on real Dell-sized inventories (247k urls + 67k endpoints).
- Bounds: `component_provenance`/`parameter_paths` ≤ `MAX_ITEMS = 2000`;
  `withheld_support` ≤ `MAX_WITHHELD_SUPPORT = 64`; evidence lists unchanged.

## Live Validation

Remote Mongo was **not reachable** during this task (`mongo ping: False`), so
live validation was **not** run and is not claimed. Per the rules, Mongo was
not troubleshooted or modified.

When Mongo is reachable, run (read-only, no VM access needed beyond the
existing WSL-side configured connection):

```bash
./venv/bin/python - <<'PY'
from backend.observed_inventory import get_inventory
inv = get_inventory("dell")
print("components:", [i["value"] for i in inv["components"]])
print("plugins:", [i["value"] for i in inv["plugins"]])
print("provenance:", inv["component_provenance"][:5])
print("parameter_paths:", len(inv["parameter_paths"]))
PY
```

Expected Dell evidence remains CKEditor, dell-virtual-rack-theme, jQuery,
TinyMCE, and plugin wp-smushit, now with structured path-only provenance and
scopes. The synthetic inferred-only FP case is already covered deterministically
by Test 3.

## Risks / Remaining Work

- **R31.6 identity resolution (not in scope):** CVE-side plugin extraction is
  still `"plugin" in product.lower()` and alias coverage is minimal
  (`PLUGIN_ALIASES` has one entry). R31.5 deliberately does not add aliases or
  slug extraction.
- **Neutral provenance default:** CVEs with no component/plugin involvement
  report `evidence_provenance = EXPLICIT` and `support_scope = GLOBAL`
  (non-gating). This is documented in the test module; a future stage may add a
  distinct non-applicable marker if needed.
- **Exact prefix scoping:** scopes are case-sensitive path prefixes derived from
  the canonical inferred path; a differently-cased support path is treated as
  unscoped rather than guessed.
- **Parameter linkage bound:** `parameter_paths` is capped at 2000 entries; for
  very large endpoint sets some parameter locations may not be represented, in
  which case the parameter is conservatively treated as unscoped.
- **No R26/R29 propagation:** the new additive fields are exposed on the
  asset/CVE match summary; the R26/R29 projection schemas remain untouched
  (their `extra="forbid"` field sets are unchanged).
- **Live validation pending** Mongo reachability.
- Historical R31.2/R31.3/R31.4 reports still describe the pre-R31.5 shape; they
  are historical records and were not edited.

## Git Status

```
$ git status --short
 M ai/knowledge/component_inference.py
 M ai/knowledge/observed_inventory.py
 M ai/schemas/observed_inventory.py
 M backend/asset_cve_matching.py
 M tests/test_component_inference.py
 D utils.zip
?? agent-reports/stage-r31-5-planning-audit.md
?? tests/test_component_evidence_provenance.py
?? watch.zip

$ git diff --stat
 ai/knowledge/component_inference.py | 109 +++++++++--
 ai/knowledge/observed_inventory.py  |  50 +++++
 ai/schemas/observed_inventory.py    | 204 ++++++++++++++++++++
 backend/asset_cve_matching.py       | 364 +++++++++++++++++++++++++++++++++++-
 tests/test_component_inference.py   |   9 +-
 utils.zip                           | Bin 3104837 -> 0 bytes
 6 files changed, 716 insertions(+), 20 deletions(-)
```

`utils.zip` (deletion) and `watch.zip` (untracked) are unrelated pre-existing
module-sync artifacts and were not touched. The untracked planning audit report
from the previous stage was not modified. This stage's new report and test
module are the only new files.

## Scope / Safety

- No VM access, no Google VM modification, no deployment.
- No commit, no push.
- No unrelated files changed; `utils.zip`/`watch.zip` untouched.
- No LLM, no network calls in tests, no Nuclei/browser/PoC execution, no target
  interaction, no Mongo writes/collections, no findings materialization, no
  notifications.
- No Money Score / R17 / R25 / R26 / R29 changes; no candidate ranking changes;
  no research scheduler changes.
- R30.1 engine (`ai/knowledge/asset_cve_matching.py`) unchanged; rule versions
  unchanged (`r30-1`, `r30-2`, `r30-3`, `r31-2`); R31.5 metadata carries the new
  `r31-5` provenance rule version.

Agent / Model
Model: deepseek-v4.1-flash
Stage: R31.5 Evidence Provenance and Component-Scoped Support
Role: coding agent
