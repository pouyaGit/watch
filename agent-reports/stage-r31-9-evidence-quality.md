# R31.9 Evidence Quality & Confidence Gate

Local WSL implementation. No commit, no push, no VM access, no deployment.

## 1. Objective

Add a deterministic, explainable evidence-quality layer that evaluates the
quality, completeness, scope and internal consistency of the evidence
supporting one Asset<->CVE research candidate. It is **additive audit
metadata**: R30.1 remains authoritative for match/confidence semantics,
R31.5 for provenance/scope, R31.6 for identity, R31.7 for versions and R31.8
for path/parameter relevance. No existing field is overwritten or
reinterpreted, no numeric "probability of vulnerability" is produced, and the
layer never creates a 5J finding.

## 2. Architecture Audit

Traced before implementation:

- **R30.1 (`ai/knowledge/asset_cve_matching.py`, untouched).**
  `evaluate_inventory()` produces `strongest_match_type`,
  `strongest_confidence`, `asset_match_state`, `matched_component/version/
  parameter`, `resolved_blockers`, `remaining_blockers`, `version_state` and
  the serialized per-type matches. Its component+PATH/PARAMETER rule 3 and
  VERSION rules remain the only authority over confidence/state.
- **R30.2 (`ai/knowledge/observed_inventory.py`).** Observed paths/parameters
  and (R31.5) `parameter_paths` linkage; no HTTP method is exposed in the
  current projection.
- **R30.3 (`version_component_association`).** Produces
  `version_association_state`; non-matching observed versions are deliberately
  withheld from the engine, so `VERSION_OBSERVED_NO_MATCH` is the
  authoritative version-negative signal even when `version_state` is
  `UNKNOWN`.
- **R31.1 (`vulnerability_fingerprint`).** Orphaned; untouched.
- **R31.5 (provenance/scope).** `evidence_provenance`
  (EXPLICIT/INFERRED/MIXED), `support_scope`
  (COMPONENT_SCOPED/GLOBAL/NONE), `withheld_support`, and the component-scoped
  gate. R31.9 consumes these and adds `matched_explicit`/`matched_inferred`
  sets to the internal gate result for conflict detection (additive only).
- **R31.6 (`component_identity`).** `identity_resolution` rows are consumed
  for identity completeness; identity logic is untouched.
- **R31.7 (`version_normalization`).** `version_normalization.rows`
  (`comparison`, `cve_kind`, `cve_evidence_class`) and the parsed
  `cve_versions`/`observed_versions` lists are consumed read-only.
- **R31.8 (`path_parameter_relevance`).** `path_parameter_relevance.evidence`
  and `.summary` (`path_match`, `parameter_match`, `component_scoped`,
  `method`) are consumed read-only.
- **Backend (`backend/asset_cve_matching.py`).** Composes all of the above per
  (CVE, program) and now attaches the R31.9 block last.

No R31.9 logic duplicates version parsing, path matching, identity resolution
or the R30.1 engine.

## 3. Files Changed

- `ai/knowledge/evidence_quality.py` — **new** pure module
  (`EVIDENCE_QUALITY_RULE_VERSION = "r31-9"`): dimension evaluation, conflict
  detection, completeness, bounded quality classification.
- `tests/test_evidence_quality.py` — **new** focused suite (36 tests:
  A–Z coverage, false-positive guards, hermetic backend integration,
  performance guard).
- `backend/asset_cve_matching.py` — **modified additively** (+49/-0): imports
  the module, adds `matched_explicit`/`matched_inferred` keys to the R31.5
  gate result (no behavior change), computes `component_conflict`, calls
  `evaluate_evidence_quality(...)` after all other additive blocks, and
  attaches `summary["evidence_quality"]` +
  `summary["evidence_quality_rule_version"]`.
- `agent-reports/stage-r31-9-evidence-quality.md` — this report.

R30.1, R30.2, R30.3, R31.1, R31.5, R31.6, R31.7 and R31.8 files are
untouched (verified with `git diff --name-only`).

## 4. Evidence Dimensions

Twelve dimensions are evaluated independently (each with `state`, `reason`,
`source`, `authoritative`/`supporting`, `completeness`):

| Dimension | What it reads | Role |
|---|---|---|
| `ASSET_IDENTITY` | strongest match type/confidence | authoritative |
| `COMPONENT_IDENTITY` | matched component, R31.5 provenance | authoritative |
| `COMPONENT_PROVENANCE` | EXPLICIT/INFERRED/MIXED | supporting |
| `VERSION_COMPATIBILITY` | `version_state` + R30.3 association state | authoritative |
| `VERSION_EVIDENCE` | R31.7 rows/kinds/classes | supporting |
| `PATH_RELEVANCE` | R31.8 path rows + `component_scoped` | supporting |
| `PARAMETER_RELEVANCE` | R31.8 parameter rows + `component_scoped` | supporting |
| `METHOD_RELEVANCE` | R31.8 method summary | supporting |
| `SCOPE` | R31.5 `support_scope` | supporting |
| `PROVENANCE` | R31.5 `evidence_provenance` | supporting |
| `AMBIGUITY` | R31.8 `AMBIGUOUS`/`UNKNOWN` rows, R31.7 `UNKNOWN` kinds | supporting |
| `CONFLICTS` | computed conflict records | authoritative |

Closed vocabularies: levels `HIGH/MEDIUM/LOW/INSUFFICIENT`; states
`STRONG/SUPPORTING/WEAK/UNKNOWN/CONFLICTING`; strengths
`STRONG/SUPPORTING/WEAK/NONE`; consistency `CONSISTENT/CONFLICTING/UNKNOWN`;
completeness `EVALUATED/NOT_AVAILABLE/NOT_APPLICABLE/UNKNOWN`.

## 5. Authoritative vs Supporting Evidence

- **Authoritative**: asset identity, component/plugin identity,
  version compatibility (including the R30.3 `VERSION_OBSERVED_NO_MATCH`
  negative), component conflicts and version conflicts.
- **Supporting**: component provenance/scope, version evidence class,
  path/parameter/method relevance, ambiguity.

Authoritative negative evidence always wins: a `NO_MATCH` version (via
`version_state` or `version_association_state`) forces `INSUFFICIENT`
regardless of matching path/parameter evidence; authoritative conflicts force
`INSUFFICIENT` + `CONFLICTING`. Supporting evidence can never lift a candidate
above the identity/version decision.

## 6. Conflict Detection

Deterministic, bounded (`MAX_CONFLICTS = 8`), preserved in `conflicts` and
`evidence_gaps`:

1. **Component conflict** (`authoritative`): the R31.5 gate matched both an
   explicit and an inferred observed component/plugin whose normalized
   identities are disjoint (`matched_explicit ∩ matched_inferred = ∅` within
   the same category). Same-value explicit+inferred is MIXED, never a conflict.
2. **Version conflict** (`authoritative`): engine `version_state` disagrees
   with R31.7 rows (`NO_MATCH` state + a `MATCH` row, or `MATCH` state + only
   `NO_MATCH` rows). The multi-version corpus case (one exact version observed
   among many listed) is not a conflict by construction.
3. **Scope conflict** (`supporting`): inferred-only identity with only global
   path/parameter matches (`support_scope` not `COMPONENT_SCOPED`). Caps the
   level at `LOW`.

Conflicts are never hidden: they appear in `conflicts`, drive
`evidence_consistency = CONFLICTING`, and are also listed as gaps.

## 7. Completeness Model

Per dimension (aggregate over evidence-bearing dimensions only: asset
identity, component identity, version compatibility, version evidence, path,
parameter, method):

- `NOT_AVAILABLE` — the research lacks the information (no affected version,
  no structured path/parameter/method), so absence is not a negative match;
- `EVALUATED` — a comparison was actually performed (MATCH, NO_MATCH,
  indeterminate evaluation, or an identity was established);
- `UNKNOWN` — research data exists but could not be evaluated;
- `NOT_APPLICABLE` — meta dimensions (scope, provenance, ambiguity, conflicts)
  that are classifications rather than missing-information signals.

The result exposes `evidence_completeness.overall`, per-dimension values and
`evaluated_dimensions`/`not_available_dimensions` lists.

## 8. Evidence Strength / Quality Rules

First-match decision rules (documented, no numeric score):

1. Authoritative version negative (`NO_MATCH` engine or association state) →
   `INSUFFICIENT`, reason "authoritative version NO_MATCH blocks this
   candidate".
2. Authoritative conflict → `INSUFFICIENT` + `CONFLICTING`.
3. No target-specific identity at all (`asset_match_state = UNKNOWN` without a
   component) → `INSUFFICIENT`.
4. `CONFIRMED` + (explicit/mixed provenance or component-scoped support) and
   no conflicts → `HIGH`.
5. `CONFIRMED` but inferred without scoped support → `MEDIUM`.
6. `SUPPORTED` + scoped/explicit evidence → `MEDIUM`; inferred + global-only
   → `LOW`.
7. `WEAK` with a component identity → `LOW`; supporting-only → `INSUFFICIENT`.
8. Scope conflict caps at `LOW`; unresolved ambiguity caps `HIGH` to `MEDIUM`.

`evidence_strength` is the bounded mapping `HIGH→STRONG`, `MEDIUM→SUPPORTING`,
`LOW→WEAK`, `INSUFFICIENT→NONE`; it is a classification, never a probability.
`evidence_reasons` explains the final level; `evidence_gaps` records missing
or blocking evidence (bounded: `MAX_GAPS=16`, `MAX_REASONS=16`).

## 9. R31.5 Compatibility

- `evidence_provenance` and `support_scope` are consumed, never rewritten.
- Inferred-only identity with `support_scope = GLOBAL/NONE` yields `LOW` at
  best (or a supporting scope conflict), so global path/parameter evidence
  cannot upgrade inferred component ownership.
- Component-scoped support (`COMPONENT_SCOPED`) is recognized as strong scope
  evidence and can accompany a `HIGH` result together with explicit/version
  evidence.
- The gate's new `matched_explicit`/`matched_inferred` keys are purely
  additive inputs for conflict detection; gate behavior and
  `support_scope`/`provenance`/`withheld_support` outputs are unchanged.

## 10. R31.7 Compatibility

R31.7 outputs are consumed read-only. `MATCH` rows/kinds inform
`VERSION_EVIDENCE`; `INDETERMINATE`/`UNKNOWN`/`AMBIGUOUS` never become
`MATCH`. Version `NO_MATCH` remains authoritative, and the R30.3
`VERSION_OBSERVED_NO_MATCH` association state is treated as the same
authoritative negative when the engine state is `UNKNOWN` (R30.3 withholds
non-matching versions by design). Version parsing is not reimplemented.

## 11. R31.8 Compatibility

R31.8 evidence types (`EXACT_PATH`, `PATH_PREFIX`, `PATH_PATTERN`,
`EXACT_PARAMETER`, `PARAMETER_SET`, `HTTP_METHOD`, `NO_EVIDENCE`,
`AMBIGUOUS`, `UNKNOWN`) and comparison states are consumed read-only; no
path/parameter matching is reimplemented. Path/parameter/method evidence is
always supporting, never authoritative; `NO_EVIDENCE` and `AMBIGUOUS` states
map to `UNKNOWN`/gaps rather than negative matches.

## 12. False-Positive Guard Tests

`tests/test_evidence_quality.py` proves each required case:

| Case | Result |
|---|---|
| 1. path MATCH alone | `INSUFFICIENT` (never HIGH/CONFIRMED) |
| 2. parameter MATCH alone | `INSUFFICIENT` |
| 3. method MATCH alone | `INSUFFICIENT` (method is supporting only) |
| 4. inferred component + generic global path | `LOW`, not `HIGH` |
| 5. version NO_MATCH + path/parameter MATCH | `INSUFFICIENT` (authoritative block) |
| 6. version INDETERMINATE + path MATCH | remains indeterminate; never `MATCH`/`HIGH` |
| 7. explicit component + compatible version + scoped exact path | `HIGH` (architecture permits it) |
| 8. conflicting component evidence | `INSUFFICIENT` + `CONFLICTING`, never `HIGH` |

Integration guards exercise the same cases through
`backend/asset_cve_matching.build_matches` with hermetic fixtures.

## 13. Privacy / Sanitization

- The engine emits only classifications, counts, normalized dimension names,
  blocker codes and static reason strings. It never copies raw observed paths,
  parameter names/values, headers or methods from the evidence it consumes.
- Tests assert that secret-looking inputs (`?token=SECRET`,
  `Authorization: Bearer ...`) never appear in the serialized R31.9 block
  (`test_Z_privacy_no_raw_values_copied`,
  `test_privacy_in_adapter_quality_block`).
- R31.8 already sanitizes its inputs; R31.9 introduces no new raw-value
  storage, so there is no new credential surface.

## 14. Test Results

Commands executed:

```bash
./venv/bin/python -m unittest tests.test_evidence_quality -q
./venv/bin/python -m unittest tests.test_evidence_quality \
    tests.test_path_parameter_relevance tests.test_version_normalization \
    tests.test_component_evidence_provenance tests.test_component_identity \
    tests.test_component_inference tests.test_component_plugin_wiring \
    tests.test_observed_inventory tests.test_asset_cve_matching \
    tests.test_version_component_association -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile ai/knowledge/evidence_quality.py \
    backend/asset_cve_matching.py tests/test_evidence_quality.py
git diff --check
```

Results:

```
tests.test_evidence_quality                  Ran 36 tests  OK   (new)
tests.test_path_parameter_relevance          Ran 40 tests  OK
tests.test_version_normalization             Ran 47 tests  OK
tests.test_component_evidence_provenance     Ran 15 tests  OK
tests.test_component_identity                Ran 57 tests  OK
tests.test_component_inference               Ran 53 tests  OK
tests.test_component_plugin_wiring           Ran 14 tests  OK
tests.test_observed_inventory                Ran 61 tests  OK
tests.test_asset_cve_matching                Ran 79 tests  OK
tests.test_version_component_association     Ran 41 tests  OK
combined R31 regression                      Ran 443 tests OK (0 failures)

complete project suite (discover tests)      Ran 2086 tests
  37 failures + 3 errors -- all pre-existing and identical with the R31.9
  change reverted (page_render, routers_fixes, daily_research_workflow,
  hunt_queue, opportunity_action_queue, product_api, research_economics_api,
  research_ui). No new failure is attributable to R31.9.

py_compile                                   OK
git diff --check                             clean
```

The required A–Z coverage is present: all dimensions absent (A), explicit/
inferred/mixed identity (B/C/D/E), version MATCH/NO_MATCH/INDETERMINATE/
UNKNOWN (F/G/H/I), path/parameter/method (J–N), scoped/global support (O/P),
authoritative/component/version conflicts (Q/R/S), supporting evidence cannot
override version mismatch (T/U), inferred generic path cannot be HIGH (V),
explicit+version+scoped path is HIGH (W), bounded output (X), determinism (Y),
privacy (Z), plus hermetic backend integration.

## 15. Real Corpus Sanity Check

Read-only scan over `local_cve_context()` (6 CVE contexts with KB synthesis
documents) combined with a deterministic synthetic Dell observed fixture
(explicit `image_handler.php` component, version `1.0` associated with
`WP Responsive Images`, `src`/`secondary` parameters, matching path). No
research data was modified; Mongo was not reachable
(`mongo ping: False`), so observed data is synthetic and clearly labelled.

```
candidates examined: 6
levels: HIGH 1, MEDIUM 0, LOW 0, INSUFFICIENT 5
strong component evidence: 1
strong version evidence:   1
R31.8 path/parameter evidence: 1
conflicts: 0
authoritative negatives: 0 (baseline fixture)

CVE-2026-1557   engine=COMPONENT HIGH CONFIRMED   quality=HIGH  STRONG
CVE-2024-27956  engine=NONE      LOW  WEAK        quality=INSUFFICIENT
CVE-2024-42327  engine=NONE      LOW  WEAK        quality=INSUFFICIENT
CVE-2024-5376   engine=NONE      LOW  WEAK        quality=INSUFFICIENT
CVE-2025-3102   engine=NONE      LOW  WEAK        quality=INSUFFICIENT
CVE-2025-4893   engine=NONE      LOW  WEAK        quality=INSUFFICIENT
```

Variant with observed version `2.0.0` (mismatch vs `<=1.0`):
`CVE-2026-1557` → engine `MEDIUM/SUPPORTED`, association
`VERSION_OBSERVED_NO_MATCH`, quality `INSUFFICIENT`, authoritative negative
recorded (1/6 candidates in that variant). This demonstrates the gate blocking
a candidate whose engine state is not yet negative.

## 16. Performance Check

The quality layer is O(number of dimensions) and never rescans URLs,
endpoints, subdomains or parameters (R31.8 already summarized them).

```
1 candidate    -> 0.06 ms
100 candidates -> 2.72 ms  (~27 us/candidate)
1000 candidates-> 23.24 ms (~23 us/candidate)
```

The in-suite guard evaluates 100 candidates in < 5 s (actual ~3 ms) and the
full 6-candidate corpus scan above completes in milliseconds.

## 17. Security Review

Reviewed every new field (`evidence_quality`, `evidence_state`,
`evidence_strength`, `evidence_consistency`, `evidence_completeness`,
`dimensions`, `evidence_gaps`, `evidence_reasons`, `conflicts`, `counts`,
`rule_version`):

- No query parameter values, passwords, cookies, Authorization headers,
  bearer tokens, API keys or session IDs can be stored: the engine only emits
  classifications/counts/static strings and never copies consumed raw values.
- Regression tests (`test_Z_...`, adapter privacy test) feed secret-like
  values and assert absence from the serialized output.
- No logging of secret values; no network/LLM; deterministic and explainable.
- The layer is research-side only and cannot create a 5J authoritative
  finding; it never modifies candidate ranking, Money Score, R17/R25.2/R26/R29
  or R30.1 fields.

## 18. Git Scope

```
$ git status --short
 M backend/asset_cve_matching.py
 D utils.zip
?? agent-reports/stage-r31-5-planning-audit.md
?? ai/knowledge/evidence_quality.py
?? tests/test_evidence_quality.py
?? watch.zip

$ git diff --stat          # tracked changes only
 backend/asset_cve_matching.py | 49 +++++++++++++++++++++++++++++++++++++++++
 utils.zip                     | Bin 3104837 -> 0 bytes
 2 files changed, 49 insertions(+)
```

Intentionally changed by R31.9: `ai/knowledge/evidence_quality.py` (new),
`tests/test_evidence_quality.py` (new), `backend/asset_cve_matching.py`
(additive, +49/-0), and this report.

Unrelated pre-existing changes left untouched: `D utils.zip`, `?? watch.zip`,
`?? agent-reports/stage-r31-5-planning-audit.md`.
Previous-stage authority files verified untouched: R30.1 engine, R30.3
association, R31.5 modules/schema, R31.6 identity, R31.7 normalization, R31.8
relevance.

## 19. Conclusion

PASS — R31.9 is implemented, integrated additively, documented and tested:
36 focused tests and 443 combined R31 regression tests pass; the complete
project suite shows only the 40 pre-existing failures that are identical with
this change reverted; `py_compile` and `git diff --check` are clean. R30.1 and
all previous R31.x authorities are untouched, no secret values can enter the
new evidence, and no commit/push/VM/deploy action was taken.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.9
- Role: coding agent
