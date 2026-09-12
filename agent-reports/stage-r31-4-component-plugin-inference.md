# Stage R31.4 Component Plugin Inference

## Objective

Improve the scalability of the observed-inventory component/plugin inference
(`ai/knowledge/component_inference.py`) so that ruled paths are no longer
dropped on large real inventories. The runtime inventory for `dell` showed:

```
components: []
plugins:    []
```

even though matching persisted paths exist. The goal is full-coverage,
deterministic, bounded inference without changing the rule semantics or the
R31.3 backend wiring.

## Current Limitation

R31.2/R31.3 inference collected every distinct path from URL / endpoint / HTTP
records, then **globally sorted** the union and truncated it to the first
`MAX_PATHS = 20000` entries before applying any rule:

```python
paths = sorted(
    set(_collect_paths(endpoint_records))
    | set(_collect_paths(url_records))
    | set(_collect_paths(http_records))
)[:MAX_PATHS]
```

Because the truncation is lexicographic, the paths that actually match the
anchored rules can fall outside the window on a real corpus. The Dell
inventory has 77,726 distinct paths; the first 20,000 sorted paths contained
neither `wp-content` nor `ckeditor`, so inference returned zero components and
zero plugins despite ruled paths being present in the data.

## Root Cause

The root cause is the arbitrary lexicographic `[:MAX_PATHS]` truncation, not
the rules and not the backend wiring:

- `MAX_PATHS` was a safety cap on **input paths**, applied before matching.
- Path patterns such as `/wp-content/plugins/<slug>/` and
  `/assets/ckeditor/...` start with letters that sort late (`w`) or are
  preceded by thousands of unrelated `/aaa`, `/api`, `/assets`, ... paths.
- The cap therefore silently discarded the only paths that could ever match,
  producing an empty inference result on large inventories while all smaller
  fixtures (unit tests) passed.

## Investigation

Inspected files:

- `ai/knowledge/component_inference.py` — rule table, path extraction,
  `infer_inventory_items()`, `apply_inferred_items()`, constants
  (`MAX_PATHS=20000`, `MAX_ITEMS=2000`, `MAX_EVIDENCE=256`,
  `MAX_PATH_LEN=2048`).
- `backend/observed_inventory.py` — R31.3 wiring: `_fetch_documents()` reads
  `Http`/`Urls`/`Endpoints`/`Subdomains`, `_apply_inference()` calls
  `infer_inventory_items()` + `apply_inferred_items()` before projection.
- `ai/knowledge/observed_inventory.py` — pure R30.2 builder (untouched).
- `tests/test_component_inference.py` — rule/negative/determinism/merge/loader
  coverage; no test exercised a corpus larger than the cap.
- Repo-wide grep for `MAX_PATHS` / `_collect_paths`: only the inference module
  used them (no external callers or tests).

Important findings:

- Live Dell data (captured while remote Mongo was reachable during R31.3):
  77,726 distinct paths; capped inference → components 0 / plugins 0; the same
  records with `MAX_PATHS` monkeypatched away → components 4
  (`CKEditor`, `dell-virtual-rack-theme`, `jQuery`, `TinyMCE`) and plugin 1
  (`wp-smushit`) in ~2.0s.
- Matching rules are anchored and cheap; the cap was the only reason they were
  skipped.
- `_collect_paths()` returned a sorted list, but its result was immediately
  converted back to a set and sorted again in `infer_inventory_items()`, so
  three sorts/sets were built per run — pure overhead.

Note: the remote Mongo host was reachable intermittently during this stage and
was **down** while this task ran, so the final live "after" run could not be
re-executed (see Real Inventory Validation).

## Design Decision

Remove the arbitrary input truncation and scan **every distinct path**, while
keeping the output and evidence bounded and the result deterministic:

1. **No path cap.** `MAX_PATHS` and the `[:MAX_PATHS]` slice are removed. Every
   distinct observed path is evaluated exactly once per rule.
2. **Single path set, no global sort.** `_collect_paths()` (three sorted lists
   + three sets + one sorted union) is replaced by `_distinct_paths(*groups)`,
   which builds one set in a single pass. Set iteration order is irrelevant
   because of point 3.
3. **Canonical per-value selection.** Instead of "first match in sorted path
   order wins", the engine keeps, per normalized value, the canonical best
   candidate `(path, rule_id, value)` (lexicographically smallest matching
   path). The result is therefore independent of input record order and of
   Python set iteration order, and it matches the previous sorted-path choice
   for every existing test.
4. **Bounded output unchanged.** `MAX_ITEMS=2000` still caps emitted items and
   `MAX_EVIDENCE=256` still caps evidence; `MAX_PATH_LEN=2048` still bounds
   each path string. No rules, categories, evidence types, rule versions or
   public API changed.

Why this is the right minimal fix: it removes the hidden-data-loss bug, turns
the algorithm into a single O(paths × rules) pass, eliminates redundant
sorting, and keeps determinism without a global sort (important at scale where
sorting hundreds of thousands of strings is the dominant cost after matching).

## Files Changed

- `ai/knowledge/component_inference.py`
  - removed `MAX_PATHS` and the lexicographic truncation;
  - replaced `_collect_paths` with order-free `_distinct_paths`;
  - per-value canonical best-match selection; evidence built from the chosen
    candidates; docstring updated.
- `tests/test_component_inference.py`
  - new `TestScalability` class with 4 deterministic regression tests:
    `test_no_lexicographic_path_cap` (25k filler paths must not hide ruled
    paths), `test_bounded_output_on_dense_matches` (2,500 distinct matches →
    `MAX_ITEMS`/`MAX_EVIDENCE` bounds), `test_canonical_path_per_value`,
    `test_no_path_cap_constant_remains`.
- `agent-reports/stage-r31-4-component-plugin-inference.md` (this report).

No other files changed. The R31.3 backend wiring, the R30.2 builder, the rule
table, and the schemas are untouched.

## Tests Executed

```bash
# required pre-change baseline
./venv/bin/python - <<'PY'
from backend.observed_inventory import get_inventory
inv = get_inventory("dell")
print("technologies:", len(inv["technologies"]))
print("components:", inv["components"][:20])
print("plugins:", inv["plugins"][:20])
print("generated:", inv["generated_from"])
PY

# focused tests
./venv/bin/python -m unittest tests.test_component_inference -q
./venv/bin/python -m unittest tests.test_component_plugin_wiring -q
./venv/bin/python -m unittest tests.test_observed_inventory -q
./venv/bin/python -m unittest tests.test_asset_cve_matching \
    tests.test_version_component_association -q

# syntax / hygiene
./venv/bin/python -m py_compile \
    ai/knowledge/component_inference.py tests/test_component_inference.py
git diff --check
```

(`./venv/bin/python` is the repository virtualenv; the host `python` is not
guaranteed to have the project dependencies installed.)

## Test Results

```
tests.test_component_inference                  -> Ran 53 tests ... OK
tests.test_component_plugin_wiring              -> Ran 14 tests ... OK
tests.test_observed_inventory                   -> Ran 61 tests ... OK
tests.test_asset_cve_matching +
tests.test_version_component_association        -> Ran 120 tests ... OK
                                                    (248 tests total, 0 failures)

py_compile                                      -> OK
git diff --check                                -> clean
```

## Real Inventory Validation

Required baseline command at the start of this task (remote Mongo was
unreachable at that moment, so the reader fail-softs to an empty inventory —
this is the R31.3 offline behavior, not the inference bug):

```
technologies: 0
components: []
plugins: []
generated: {'http_records': 0, 'endpoint_records': 0, 'url_records': 0,
            'subdomain_records': 0, 'projected_subdomains': 0,
            'skipped_subdomains': 0, 'version_associations': 0}
```

Live Dell "before" (captured during R31.3 while Mongo was reachable):

```
components: []
plugins:    []
distinct paths: 77,726   (first 20,000 contained no ruled patterns)
```

Live uncapped run of the same Dell records (R31.3 monkeypatch evidence):

```
components: CKEditor, dell-virtual-rack-theme, jQuery, TinyMCE
plugins:    wp-smushit
```

R31.4 deterministic reproduction with the same known Dell paths (25,005
distinct paths: 25,000 filler + the Dell evidence):

```
BEFORE (old lexicographic cap=20000):
  components: []
  plugins:    []
AFTER (R31.4 full scan):
  components: ['CKEditor', 'dell-virtual-rack-theme', 'jQuery', 'TinyMCE']
  plugins:    ['wp-smushit']
```

The after result matches the earlier live uncapped Dell result exactly. A live
`get_inventory("dell")` re-run is pending the remote Mongo being reachable
again; the expected `components` are `CKEditor`, `dell-virtual-rack-theme`,
`jQuery`, `TinyMCE` and the expected `plugins` are `wp-smushit` (the inventory
now scans all 77,726 paths). This is the only validation item not executed
live in this stage.

## Performance Considerations

- **Algorithm:** one pass over distinct paths × 12 rules, O(N × R). The old
  code was O(N log N) for two redundant global sorts plus a scan of at most
  20,000 paths; the new code removes the sorts and scans everything.
- **Measured:** 200,005 distinct paths → `infer_inventory_items()` in **1.48s**
  (4 components, 1 plugin, 5 evidence lines). The live Dell corpus (77,726
  paths) is well under that.
- **Memory:** one set of distinct path strings (the records are already in
  memory), plus one dict per category keyed by normalized value holding a
  3-tuple. Output stays bounded by `MAX_ITEMS=2000` and `MAX_EVIDENCE=256`.
- **Worst case:** time/memory grow linearly with distinct paths and distinct
  matched values. That is inherent to full-coverage matching; the previous cap
  only appeared cheaper because it silently discarded data. In the runtime
  path, remote Mongo fetch/record conversion dominates wall time (minutes),
  so inference (seconds) is not the bottleneck.
- No early termination is used, because stopping early would reintroduce
  nondeterministic/partial coverage.

## Risks / Remaining Work

- **Live after-validation pending:** remote Mongo was unreachable during this
  stage, so `get_inventory("dell")` could not be re-run live; deterministic
  reproduction and the prior live uncapped evidence both show the expected
  result. Re-run the baseline command when Mongo is reachable.
- **Very large corpora:** there is no input cap anymore; multi-million-path
  corpora would take proportionally longer. If this ever becomes an issue, the
  right next step is cheap anchor pre-filtering per rule (e.g. substring
  pre-checks) rather than truncating paths.
- **Rule coverage is still table-bound:** only the anchored rules in `RULES`
  infer anything; no new rules were added in this stage.
- **Historical docs:** the R31.2/R31.3 reports still describe the old
  `MAX_PATHS` cap; they are historical records and were intentionally not
  edited.
- `MAX_PATH_LEN=2048` path truncation remains (pre-existing, tested).

## Git Status

```
$ git status --short
 M ai/knowledge/component_inference.py
 M tests/test_component_inference.py
 D utils.zip
?? watch.zip

$ git diff --stat ai/knowledge/component_inference.py tests/test_component_inference.py
 ai/knowledge/component_inference.py | 58 ++++++++++++++++++++++--------------
 tests/test_component_inference.py   | 56 ++++++++++++++++++++++++++++++++++
 2 files changed, 91 insertions(+), 23 deletions(-)
```

Only the two intentional files are modified by this stage (plus this report,
untracked until the human reviews). `utils.zip` (deletion) and `watch.zip`
(untracked) are unrelated pre-existing/module-sync entries and were not
touched.

No commit, no push, no VM access, no deployment.

Agent / Model
Model: deepseek-v4.1-flash
Stage: R31.4 Component Plugin Inference
Role: coding agent
