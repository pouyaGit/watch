# R31.8 Path / Parameter Relevance

Local WSL implementation. No commit, no push, no VM access, no deployment.

## 1. Objective

Add deterministic, conservative path/parameter/method relevance **evidence** to
the research-side Asset<->CVE matching pipeline: does an observed
endpoint/path/parameter meaningfully suggest that the observed asset is
relevant to a CVE's vulnerability surface? The result is supporting evidence
for later prioritization/verification stages. It never proves exploitability
and never independently elevates a match to HIGH/CONFIRMED.

## 2. Architecture Audit

Traced before implementation:

- **R30.1 (`ai/knowledge/asset_cve_matching.py`, untouched).**
  `evaluate_inventory()` consumes `cve_paths`, `cve_parameters`,
  `observed_paths`, `observed_parameters`; `match_path()` is a token-subset
  supporting signal; `match_parameter()` is exact-name supporting. A
  `PATH`/`PARAMETER` match only participates in confidence when combined with
  component/plugin/product evidence (rule 3), and is supporting-only
  otherwise.
- **R30.2 (`ai/knowledge/observed_inventory.py`).** Observed paths come from
  `Endpoints.path` (`ObservedItem`, `STRUCTURED_ENDPOINT`, path-only);
  parameters from `Endpoints.params` / `param_records` (`ObservedItem`,
  `STRUCTURED_PARAMETER`, names only). R31.5 added
  `ObservedParameterPath` (parameter -> path-only endpoint) linkage.
- **R30.3 (`version_component_association`).** Associates observed versions
  with owning family/component and returns `engine_versions`. R31.8 does not
  interact with it.
- **R31.1 (`vulnerability_fingerprint`).** Orphaned and not wired; untouched.
- **R31.5 (`component_inference` provenance + adapter gate).** The adapter
  classifies observed component/plugin evidence as EXPLICIT/INFERRED/MIXED,
  computes `provenance_scopes`, `parameter_locations` and, for inferred-only
  evidence, passes only component-scoped paths/parameters to the engine. R31.8
  consumes exactly those engine-eligible sets and the same scope/location maps,
  so the R31.5 gate remains authoritative.
- **R31.6 (`component_identity`).** CVE-side identity resolution expands
  product/plugin/component values; the adapter's `cve_paths` are derived from
  the (resolved) profile components containing "/". R31.8 consumes those
  values unchanged.
- **R31.7 (`version_normalization`).** Independent version evidence attached
  additively; R31.8 does not read, duplicate or modify it.
- **CVE research data.** Research payloads contain **no structured
  path/route/endpoint/method keys**; structured path/parameter data exists
  only in the KB synthesis documents (`components` containing "/",
  `parameters`), surfaced by `vulnerability_profile()`. The adapter derives
  `cve_paths = [value for value in cve_components if "/" in value]` and
  `cve_parameters = profile["parameters"]`. No structured method source
  exists today.
- **Observed endpoint representation.** `ObservedAssetInventory.paths` and
  `.parameters` plus `ObservedParameterPath`; the projection exposes no
  observed HTTP method, so method comparisons currently resolve to
  NO_EVIDENCE/INDETERMINATE.

## 3. Files Changed

- `ai/knowledge/path_parameter_relevance.py` — **new** pure module
  (`PATH_PARAMETER_RELEVANCE_RULE_VERSION = "r31-8"`): normalization, indexed
  deterministic matching, bounded evidence, credential sanitization.
- `tests/test_path_parameter_relevance.py` — **new** focused suite (40 tests:
  A–X coverage plus hermetic backend integration and a scale guard).
- `backend/asset_cve_matching.py` — **modified additively** (+46/-2): imports
  the module, hoists `provenance_scopes`/`parameter_locations` (reused by the
  R31.5 gate, no behavior change), computes
  `evaluate_path_parameter_relevance(...)` over the R31.5-gated observed sets,
  and attaches `summary["path_parameter_relevance"]` +
  `summary["path_parameter_relevance_rule_version"]`.
- `agent-reports/stage-r31-8-path-parameter-relevance.md` — this report.

No schema, R30.1/R30.2/R30.3/R31.1/R31.5/R31.6/R31.7 file was modified.

## 4. Deterministic Matching Model

**Path normalization** (`normalize_path`):

1. control characters collapsed, value bounded to 256 chars;
2. full URLs reduced to their path (scheme/host dropped);
3. query string and fragment removed;
4. repeated slashes collapsed (`/a//b` -> `/a/b`);
5. leading slash enforced; trailing slash stripped (root stays `/`);
6. case and path characters preserved (no lowercasing, no URL decoding);
7. credential-like material redacted first (see section 6).

So `/wp-json/foo`, `/wp-json/foo/` and `/wp-json//foo` all normalize to
`/wp-json/foo`, and a path is never matched as a substring.

**Path matching** (`evaluate_path_parameter_relevance`):

- `EXACT_PATH`: exact normalized membership in the observed path index.
  `/foo` does not match `/foobar` or `/notfoo/bar` (segment boundaries).
- `PATH_PREFIX`: only when the research path is an explicit subtree, i.e. its
  raw value ends with `/`.
- `PATH_PATTERN`: explicit trailing wildcard `/*`.
- An exact research path never gains implicit prefix semantics.
- Ambiguous research syntax (`{...}`, whitespace) is `AMBIGUOUS`/`UNKNOWN`
  with `INDETERMINATE`; nothing is inferred from CVE prose.

**Parameter matching** (`normalize_parameter`):

- only the parameter **name** is used; `?file=abc` -> `file`; values are
  dropped before comparison or evidence;
- exact normalized-name membership (reusing the project's
  `normalize_parameter` separator/case convention); `file` never matches
  `filename`, `profile` or `file_id` unless the research explicitly lists
  that name;
- multiple research parameters additionally produce one `PARAMETER_SET` row
  (`MATCH` if any listed parameter was observed).

**Method matching** (`normalize_method`):

- uppercase exact membership against the HTTP method vocabulary
  (`GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/TRACE`);
- `HTTP_METHOD`/`MATCH` or `NO_MATCH` when both research and observed methods
  exist; research method without observed methods -> `INDETERMINATE`;
  missing research method -> `NO_EVIDENCE`/`INDETERMINATE` (never inferred).

**Evidence types**: `EXACT_PATH`, `PATH_PREFIX`, `PATH_PATTERN`,
`EXACT_PARAMETER`, `PARAMETER_SET`, `HTTP_METHOD`, `NO_EVIDENCE`,
`AMBIGUOUS`, `UNKNOWN`.

**Comparison states**: `MATCH`, `NO_MATCH`, `INDETERMINATE`; the aggregate
summary adds `NO_EVIDENCE` when no research dimension exists.

**Resolution methods**: `EXACT`, `NORMALIZED`, `PREFIX`, `PATTERN`,
`PARAMETER_EXACT`, `METHOD_EXACT`, `NO_METHOD`.

**Precedence**: rows are ordered exact path/parameter -> method ->
prefix -> parameter set -> pattern -> no evidence -> ambiguous/unknown, with
MATCH before INDETERMINATE before NO_MATCH inside each type. All dimensions
are preserved as separate rows; nothing is flattened into one score.

**Bounds**: ≤256 research items per dimension, ≤64 evidence rows per match,
≤256 chars per field; the observed index is bounded only by input size.

## 5. R31.5 / R31.7 Compatibility

- **R31.5 scope**: R31.8 evaluates `support_gate["paths"]`/`["parameters"]`,
  i.e. exactly the sets the unchanged R30.1 engine receives. For inferred-only
  component evidence those are component-scoped, so generic paths (e.g.
  `/api/users`) are withheld and never appear as evidence. Each row carries
  `component_scoped`, computed from the inferred provenance scopes, and the
  summary exposes `component_scoped`. Explicit/mixed evidence keeps the
  existing global behavior.
- **R31.7 versions**: R31.8 is an independent evidence dimension. It does not
  parse, alter or reorder versions, and does not touch `version_state`,
  `version_normalization` or `version_association_state`. Tests V and W run
  the adapter and a direct `evaluate_inventory()` call with the same inputs and
  assert identical engine fields, including when versions are NO_MATCH or
  INDETERMINATE/UNKNOWN.

## 6. Privacy / Sanitization

- Evidence stores **paths only** (query/fragment/scheme/host removed) and
  **parameter names only**; parameter values are discarded during
  normalization. The observation display for paths is the normalized
  path-only form.
- `_sanitize` redacts, before any evidence is built: `scheme://user:pass@`
  userinfo, `Bearer <token>`, and secret-like `key=value` / `key: value`
  pairs (`password`, `token`, `secret`, `api_key`, `session`, `cookie`,
  `authorization`, ...).
- Tests: module-level P/Q feed `?token=SECRET`, `https://user:pass@host/...`
  and `Authorization: Bearer abc123` and assert none of the secret substrings
  appear in the serialized evidence; the adapter integration test asserts the
  `path_parameter_relevance` block is value-free.
- Known boundary: legacy R30.1 summary fields are intentionally untouched;
  the real inventory collector stores parameter names without values, so
  values do not occur in production data.

## 7. Test Results

Commands (executed):

```bash
./venv/bin/python -m unittest tests.test_path_parameter_relevance -q
./venv/bin/python -m unittest tests.test_path_parameter_relevance \
    tests.test_version_normalization tests.test_component_evidence_provenance \
    tests.test_component_identity tests.test_component_inference \
    tests.test_component_plugin_wiring tests.test_observed_inventory \
    tests.test_asset_cve_matching tests.test_version_component_association -q
./venv/bin/python -m py_compile ai/knowledge/path_parameter_relevance.py \
    backend/asset_cve_matching.py tests/test_path_parameter_relevance.py
git diff --check
```

Results:

```
tests.test_path_parameter_relevance           Ran 40 tests  OK   (new)
tests.test_version_normalization              Ran 47 tests  OK
tests.test_component_evidence_provenance      Ran 15 tests  OK
tests.test_component_identity                 Ran 57 tests  OK
tests.test_component_inference                Ran 53 tests  OK
tests.test_component_plugin_wiring            Ran 14 tests  OK
tests.test_observed_inventory                 Ran 61 tests  OK
tests.test_asset_cve_matching                 Ran 79 tests  OK
tests.test_version_component_association      Ran 41 tests  OK
combined                                      Ran 407 tests OK (0 failures)

py_compile                                    OK
git diff --check                              clean
```

Coverage maps to the required areas: A/B/C path exact/mismatch/boundary,
D trailing slash, E query removal, F fragment, G explicit prefix/pattern,
H unsupported prose, I/J/K/L parameter exact/mismatch/collision/set,
M/N/O method match/mismatch/missing, P/Q value and credential redaction,
R empty/null, S malformed, T bounds, U component scope, V/W version
authority, X backward compatibility plus hermetic backend integration.

## 8. Real Corpus Sanity Check

Read-only scan of the local research corpus via `local_cve_context()` +
`vulnerability_profile()` (6 CVE contexts have KB synthesis documents; the
other 3 payloads have no KB document and therefore no structured components):

```
CVE-2024-27956   0 paths 0 params  -> NO_EVIDENCE
CVE-2024-42327   0 paths 0 params  -> NO_EVIDENCE
CVE-2024-5376    0 paths 0 params  -> NO_EVIDENCE
CVE-2025-3102    0 paths 0 params  -> NO_EVIDENCE
CVE-2025-4893    0 paths 0 params  -> NO_EVIDENCE
CVE-2026-1557    2 paths 2 params  -> MATCH
  EXACT_PATH       MATCH      research=wp-content/plugins/wp-responsive-images/image_handler.php
                              observed=/wp-content/plugins/wp-responsive-images/image_handler.php
  EXACT_PATH       NO_MATCH   research=plugins.trac.wordpress.org/browser/.../wpresponsiveimages.php
  EXACT_PARAMETER  MATCH      research=secondary observed=secondary
  EXACT_PARAMETER  MATCH      research=src observed=src (parameter set MATCH)
```

Counts: 6 CVE contexts; **1** with structured path evidence; **1** with
structured parameter evidence; **0** with structured method evidence; **5**
produce `NO_EVIDENCE` because the research has no structured route/parameter
data. No corpus research path is ambiguous, so no `UNKNOWN` row occurs in the
corpus; unsupported prose is covered by synthetic tests. Research data was not
modified.

## 9. Performance Check

Synthetic benchmark (module-level; observed index rebuilt per call unless
reuse is requested):

```
25,000 paths, 1,000 params, 1 CVE, build index   -> 0.176 s
25,000 paths, 1,000 params, 5 CVEs, build index  -> 1.031 s  (~0.21 s/CVE)
25,000 paths, 1,000 params, 5 CVEs, reuse index  -> 0.002 s
50,000 paths, 2,000 params, 5 CVEs, reuse index  -> 0.002 s
```

Complexity is O(observed_paths + observed_parameters + research_items) per
evaluation with O(1) research lookups; there is no path x parameter cross
scan, and doubling the corpus does not increase per-research-item cost. The
adapter currently rebuilds the index per (CVE, program) at ~0.2 s per 25k
paths; the module accepts a prebuilt `ObservedRelevanceIndex` for callers that
want to reuse it. The in-suite scale guard runs 25k paths + 1k parameters and
asserts completion and bounded evidence.

## 10. Security Review

Inspected every new evidence field (`observed_path`, `research_path`,
`observed_parameter`, `research_parameter`, `observed_method`,
`research_method`, `reason`, counts). Findings:

- No secret-like data can enter R31.8 evidence: values are dropped by
  normalization and credential patterns are redacted by `_sanitize`.
- Regression tests P/Q cover query values, bearer tokens and userinfo.
- The only path by which a secret-like value could still appear in the overall
  match summary is the pre-existing R30.1 fields, which R31.8 is forbidden to
  change; real inventory collection stores parameter names only, so values do
  not occur in production data.
- No logging of secret values anywhere in the new module.

## 11. Git Scope

```
$ git status --short
 M backend/asset_cve_matching.py
 D utils.zip
?? agent-reports/stage-r31-5-planning-audit.md
?? ai/knowledge/path_parameter_relevance.py
?? tests/test_path_parameter_relevance.py
?? watch.zip

$ git diff --stat          # tracked changes only
 backend/asset_cve_matching.py | 48 ++++++++++++++++++++++++++++++++++++++--
 utils.zip                     | Bin 3104837 -> 0 bytes
```

Intentionally changed by R31.8: `ai/knowledge/path_parameter_relevance.py`
(new), `tests/test_path_parameter_relevance.py` (new),
`backend/asset_cve_matching.py` (additive), and this report.

Unrelated pre-existing changes observed and left untouched: `D utils.zip`,
`?? watch.zip`, `?? agent-reports/stage-r31-5-planning-audit.md`.
Previous-stage authorities verified untouched: R30.1 engine, R31.6 identity,
R30.3 association, R31.7 normalization, observed-inventory schema, R31.1
fingerprint.

## 12. Conclusion

PASS — R31.8 is implemented, integrated additively, tested (40 focused tests;
407 total regression tests passing), benchmarked, and documented. The R30.1
engine and all R31.x authorities are untouched, no secret values enter the new
evidence, and no commit/push/VM/deploy action was taken.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.8
- Role: coding agent
