# Stage R31.2 — Deterministic Component/Plugin Inference

Implementation report for the local Watch repository (`/opt/watch`).

- Rule version: `r31-2`
- Action: local implementation only (no deployment, no target interaction)
- Scope: infer components/plugins from already-persisted paths

## 1. Files changed

New:

- `ai/knowledge/component_inference.py` (405 lines)
  Pure, offline inference engine: versioned rule table, path extraction,
  `ObservedItem` output, additive inventory merge.
- `tests/test_component_inference.py` (575 lines, 49 tests)
  Deterministic offline tests for rules, sources, negatives, determinism,
  merge behavior, loader integration and safety invariants.

Modified:

- `ai/knowledge/inventory_loader.py` (46 -> 65 lines)
  `build_real_observed_inventory()` now runs the inference engine over the
  loaded URL/endpoint/HTTP records and merges the inferred items into the
  observed inventory.
- `ai/schemas/observed_inventory.py` (13 lines changed)
  `EVIDENCE_TYPES` gains `INFERRED_COMPONENT` and `INFERRED_PLUGIN`, and the
  module docstring documents the R31.2 policy. No other schema field changed;
  no database schema and no database model was touched.

Validation summary:

```
$ git diff --stat
 ai/knowledge/inventory_loader.py | 25 ++++++++++++++++++++++---
 ai/schemas/observed_inventory.py | 13 ++++++++++---
 2 files changed, 32 insertions(+), 6 deletions(-)

$ git status --short
 M ai/knowledge/inventory_loader.py
 M ai/schemas/observed_inventory.py
?? ai/knowledge/component_inference.py
?? tests/test_component_inference.py
```

`git diff --check` is clean. Nothing was committed.

## 2. Design decisions

### 2.1 Inference lives in a new isolated module

`ai/knowledge/component_inference.py` owns all path-based inference. Rules are
declarative `InferenceRule` records in a single tuple `RULES`, each with a
stable `rule_id`; adding a rule does not require touching the loader, the
observed-inventory builders or R30.x code.

### 2.2 Only anchored path conventions, no keyword guessing

Every rule is anchored to a well-known technology path layout and is matched
against path boundaries (`(?:^|/)... (?:/|$)`, case-insensitive). Values are
either a fixed canonical name (`CKEditor`) or a single path segment captured
from the anchored path and validated with a strict slug shape
(`^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$`). `..`, percent-encoding and whitespace
are rejected. A generic `/plugins/` or `/modules/` path is never inferred;
Drupal/Joomla rules require their technology-specific anchors
(`sites/*/modules`, `modules/contrib`, `com_*`, `mod_*`).

Initial requested rules:

| rule_id | pattern (anchored) | output | evidence_type |
|---|---|---|---|
| `ckeditor` | `.../ckeditor/` | component `CKEditor` | `INFERRED_COMPONENT` |
| `wordpress-plugin` | `/wp-content/plugins/<slug>/` | plugin `<slug>` | `INFERRED_PLUGIN` |
| `wordpress-mu-plugin` | `/wp-content/mu-plugins/<slug>/` | plugin `<slug>` | `INFERRED_PLUGIN` |
| `wordpress-theme` | `/wp-content/themes/<slug>/` | component `<slug>` | `INFERRED_COMPONENT` |

Extendable set added in the same table (kept small and evidence-anchored):

`fckeditor`, `ckfinder`, `tinymce`, `drupal-module-sites`,
`drupal-module-contrib`, `joomla-component`, `joomla-module`,
`jquery-asset` (`jquery[-.|version].min.js`).

Theme decision: a WordPress theme slug is emitted as a **component**, not a
product, because R31.2 targets components/plugins and a theme slug is the
component identity. No product inference is performed (products stay explicit).

### 2.3 Path-only, host-safe

`_path_from_record()` accepts URL paths and endpoint paths; full URLs are
parsed with stdlib `urlsplit` and only `parsed.path` is used. Schemes,
hostnames, query strings and fragments are never used as evidence and never
appear in output. Dicts, `path`, `example_url`, `url` and `final_url` are
supported, so URL records, endpoint records and HTTP rows can all contribute
(the task allowed HTTP URLs "if needed").

### 2.4 Existing schema objects, no new schema

Output is the existing `ObservedItem` with
`source="COMPONENT_INVENTORY"` and the new evidence types. The only schema
change is extending the closed `EVIDENCE_TYPES` vocabulary with the two
required `INFERRED_*` values; bare `INFERRED`, `GUESSED` and `LLM_DERIVED`
remain invalid. No new model class, no new field, no DB migration.

### 2.5 Inference is applied in the loader, not in `build_observed_inventory`

R30.2 `build_observed_inventory()` semantics are intentionally preserved
(inference-free, all R30.2 tests pass unchanged). `inventory_loader.py` builds
the regular inventory and then merges inferences additively:

- explicit items always win (an inferred value whose normalized key already
  exists is dropped; if nothing new remains, the original object is returned);
- `technologies`, `products`, `versions`, `version_associations`, `parameters`
  and `paths` are copied unchanged;
- `sources` gains `COMPONENT_INVENTORY` when it was absent;
- `generated_from` gains `inferred_components`, `inferred_plugins` and
  `component_inference_rule_version = "r31-2"`;
- inference is wrapped fail-soft in the loader: a rule failure can never break
  the existing inventory.

### 2.6 Determinism

Path candidates are deduplicated and sorted before rule application, so input
record order never affects the result. Values are deduplicated by normalized
key; output items are sorted. `MAX_PATHS=20000`, `MAX_ITEMS=2000`,
`MAX_EVIDENCE=256` bound the work and the output.

## 3. Tests executed

pytest is not installed in the project venv (`No module named pytest`), so the
repository-standard unittest runner was used for the requested files plus the
R30.3 regression file:

```
python -m unittest tests.test_observed_inventory \
                   tests.test_asset_cve_matching \
                   tests.test_version_component_association \
                   tests.test_component_inference -q
```

Focused R31.2 run:

```
python -m unittest tests.test_component_inference
```

Coverage in `tests/test_component_inference.py` (49 tests):

- requested examples: CKEditor, WordPress plugin, WordPress theme;
- extra rules: mu-plugins, single-file plugin, CKFinder/FCKeditor, TinyMCE,
  Drupal sites/contrib, Joomla `com_`/`mod_`, jQuery asset variants;
- record sources: endpoint path, URL path, HTTP URL, `final_url`,
  `example_url`, full-URL fallback, dict records, relative paths, query
  strings;
- negatives: generic `/plugins/` and `/modules/`, lookalikes
  (`ckeditor-guide`, `tinymce-history`), traversal (`..`, `..%2f`),
  encoded/spaced slugs, empty/None/malformed records, newlines, over-long
  paths;
- determinism: repeatability, input-order independence, dedup, case
  insensitivity, unique rule ids;
- merge: category preservation, explicit-wins, no-op identity, schema
  revalidation;
- loader integration: real `build_real_observed_inventory()` path with mocked
  DB records, determinism, inference failure fail-soft;
- safety: no execution/network/persistence tokens, evidence vocabulary,
  rule version, R30 rule versions unchanged.

## 4. Test results

```
$ python -m unittest tests.test_component_inference tests.test_observed_inventory \
                   tests.test_asset_cve_matching tests.test_version_component_association -q
Ran 230 tests in 21.027s
OK
```

Breakdown: 49 new R31.2 tests, 41 R30.3 tests, 81 R30.2 tests and 59 R30.1
tests — all passing. `git diff --check` is clean.

Live-DB note: `build_real_observed_inventory("dell")` requires MongoDB
(`database/db.py` connects at import and `Http.objects(...)` queries the
`watch` database). No `mongod` is running in this environment (only the local
machine was used; no deployment or service was started, per the workflow
rules), so the live call could not be executed here. The exact same loader
function was exercised with `load_program_inventory_records` mocked to return
Dell-shaped `HttpRecord`/`UrlRecord`/`EndpointRecord`/`SubdomainRecord`
objects. Once MongoDB is available on the target machine, the call should run
unchanged and infer components/plugins wherever the anchored paths exist.

## 5. Example output

Input evidence (Dell-like records injected through the loader, same shapes as
`database.db`):

```
Http.url          : /wp-content/plugins/akismet/  (http_records)
Urls.path         : /assets/ckeditor/plugins/
Urls.path         : /wp-content/plugins/contact-form-7/includes/js/x.js
Endpoints.path    : /wp-content/themes/twentytwentyfour/style.css
Http.tech         : WordPress:6.8.3
```

`build_real_observed_inventory("dell")` result (mocked DB read):

```
technologies: 1 ['WordPress']
components:   2 [('CKEditor', 'INFERRED_COMPONENT'),
                 ('twentytwentyfour', 'INFERRED_COMPONENT')]
plugins:      1 [('contact-form-7', 'INFERRED_PLUGIN')]
versions:     1 ['6.8.3']
associations: 1
generated_from: {'inferred_components': 2, 'inferred_plugins': 1,
                 'component_inference_rule_version': 'r31-2'}
```

JSON projection (projection excerpt):

```json
{
  "components": [
    {"value": "CKEditor", "source": "COMPONENT_INVENTORY",
     "evidence_type": "INFERRED_COMPONENT"},
    {"value": "twentytwentyfour", "source": "COMPONENT_INVENTORY",
     "evidence_type": "INFERRED_COMPONENT"}
  ],
  "plugins": [
    {"value": "contact-form-7", "source": "COMPONENT_INVENTORY",
     "evidence_type": "INFERRED_PLUGIN"}
  ],
  "sources": ["COMPONENT_INVENTORY", "ENDPOINT_INVENTORY",
              "TECHNOLOGY_INVENTORY"],
  "evidence_inferred": [
    "component 'CKEditor' inferred from path '/assets/ckeditor/plugins/' (rule ckeditor)",
    "component 'twentytwentyfour' inferred from path '/wp-content/themes/twentytwentyfour/style.css' (rule wordpress-theme)",
    "plugin 'contact-form-7' inferred from path '/wp-content/plugins/contact-form-7/includes/js/x.js' (rule wordpress-plugin)"
  ]
}
```

The task's known evidence (`/assets/ckeditor/plugins/`) now yields component
`CKEditor`, and the WP plugin/theme examples yield plugin `contact-form-7`
and component `twentytwentyfour`.

## 6. Remaining limitations

- Live verification against the local `watch` MongoDB could not be executed in
  this environment (no running `mongod`; starting services is out of scope).
  Verification used the identical loader function with mocked records.
- Products remain un-inferred by design (task scoped to components/plugins);
  themes are classified as components.
- Rules cover the requested technologies plus a small anchored extension set;
  additional frameworks need new `RULES` entries (isolated and versioned by
  `rule_id`).
- A path can only prove the *presence* of a plugin/theme/component, never a
  version. Version inference is out of scope and R30.3 version associations
  are untouched (inferred components get no `version_associations`).
- Evidence is capped (`MAX_EVIDENCE=256`) and items capped (`MAX_ITEMS`,
  `MAX_PATHS`); very large inventories keep the deterministic first slice.
- The API/UI/R30.x matching path reads inventories through
  `backend/observed_inventory.py`, which is not the R31 loader; wiring the
  inferred items into that read path would be a separate integration change
  (not requested for R31.2).
- No database schema, field or model was changed; the only schema change is
  the two additive `INFERRED_*` evidence-type vocabulary entries.

## 7. Boundary confirmation

- Deterministic, read-only, offline-testable, additive.
- No new global score; R17/R18/R25/R26/R29 and R30.1/R30.3 logic untouched.
- No network, DNS, subprocess, Nuclei, browser, PoC/exploit, target
  interaction, persistence or Mongo writes.
- No credentials touched; `.env`, `database/db.py` and deployment untouched.
- No commit was made.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.2
- Role: Component/Plugin Inference Implementation Agent
