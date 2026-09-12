# Stage R31.7 — Version Confidence and Normalization

Local WSL implementation. No commit, no push, no VM access, no deployment.

## Objective

Add a deterministic, conservative version normalization and confidence layer so
CVE-side affected versions and observed versions are parsed into structured data
(kind, precision, bounds, comparison) instead of ambiguous strings, while
preserving all existing R30.1/R31.x behavior. Parsing must never inflate
confidence; it is evidence only.

## Architecture Trace

1. **CVE affected versions enter** in `backend/asset_cve_matching._research_extras()`
   (backend/asset_cve_matching.py:103-122) from the local research payload's
   `research.affected_versions` plus `cve.affected_versions`; they are merged
   into `cve_versions` in `build_matches()` and passed unchanged to the R30.1
   engine (`cve_versions=cve_versions`). `ai/knowledge/queue.vulnerability_profile()`
   does **not** carry versions (only `version_expected`).
2. **Observed versions are extracted** by `ai/knowledge/observed_inventory.collect_versions()`
   and `collect_version_associations()` from `Http.tech` technology labels via
   the target-intelligence projection; `backend/observed_inventory` projects
   them; the adapter reads them through `_inventory_values()` (versions +
   `version_associations`) and `_metadata_observed()`.
3. **R30.3 attaches versions to owning families/components** in
   `ai/knowledge/version_component_association.evaluate_version_association()`
   and returns `engine_versions` — the only observed versions eligible for
   version matching (family/component-scoped; unassociated versions are
   withheld when the CVE targets a component/plugin).
4. **R30.1 currently sees versions** as plain string lists:
   `evaluate_inventory(cve_versions=..., observed_versions=list(association.engine_versions))`.
   Inside the engine, `_parse_version()` extracts the first numeric token and
   `_satisfies()` handles comparators/ranges/comma-OR; `match_version()` sets
   `version_state`.
5. **Version matching affects confidence/blockers**: a `VERSION` match is a
   target-specific match (rules 2/6 in `calculate_match_confidence`), can
   resolve the `version_unknown` blocker (`resolve_blockers`), and feeds
   `_asset_state`. It does not by itself reach HIGH unless combined with a
   component/plugin (or product) per the untouched R30.1 rules.
6. **Version data shapes**: adapter inputs are `list[str]`; R30.3 association
   records are dicts (`version`, `technology_family`, `component`, `source`,
   `evidence_type`); engine internals are integer tuples. R31.7 adds a
   structured parse object but does not change any of these shapes.

## Corpus Version Inventory

Inspected all 9 `ai_data/research/*.cli.json` payloads (`research.affected_versions`
and `cve.affected_versions`):

| CVE | raw affected version(s) | parsed kind | normalized | corpus status |
|---|---|---|---|---|
| CVE-2026-1557 | `<=1.0` | UPPER_BOUND (inclusive) | `<=1.0`, bound `1.0` | supported |
| CVE-2026-78203 | `< 7.1.2 (confirmed against v7.1.1, commit 625a26b)` | UPPER_BOUND (exclusive) | `<7.1.2` | supported (parenthetical stripped) |
| CVE-2026-78205 | `1.4.19` … `1.4.39` (21 values) | EXACT each | `1.4.19` … `1.4.39` | supported |
| CVE-2026-78207 | `<= 4.4.0` | UPPER_BOUND (inclusive) | `<=4.4.0` | supported |
| CVE-2024-27956, CVE-2024-42327, CVE-2024-5376, CVE-2025-3102, CVE-2025-4893 | none | — | — | no version data |

Observed versions in the current data model are concrete numeric labels from
`Http.tech` (e.g. `6.8.3`, `1.24.0`, `3.7.1`).

**NOT present in the corpus** (implemented only as spec-required, conservative
coverage): leading `v`, leading zeros, `>=`/`>`, hyphen/en-dash/`to` ranges,
`before`/`up to`, `1.x`/`1.2.x` wildcards, prerelease/build suffixes. None of
these forms is invented from CVE prose; unsupported prose stays `UNKNOWN`.

## Version Model

Closed vocabularies (all deterministic, all in `version_normalization.py`):

- **Kinds** (`VERSION_KINDS`): `EXACT`, `PREFIX`, `RANGE`, `LOWER_BOUND`,
  `UPPER_BOUND`, `WILDCARD`, `UNKNOWN`. `PREFIX` is emitted for `1.2*`
  (component-prefix constraint); `WILDCARD` for `1.x` / `1.2.x` / `1.2.*`.
- **Evidence classes** (`EVIDENCE_CLASSES`): `EXACT_OBSERVED`,
  `NORMALIZED_EXACT`, `EXPLICIT_RANGE`, `WILDCARD_RANGE`, `AMBIGUOUS`,
  `UNKNOWN`. This is *parsing* confidence, never vulnerability confidence.
- **Comparisons** (`COMPARISONS`): `MATCH`, `NO_MATCH`, `INDETERMINATE`.
- **Resolution methods** (`RESOLUTION_METHODS`): `EXACT_PARSE`, `NORMALIZED`,
  `OPERATOR_PARSE`, `RANGE_PARSE`, `WILDCARD_PARSE`, `NO_METHOD`.

Structured result (`VersionParse`): `raw_version`, `normalized_version`,
`version_kind`, `evidence_class`, `resolution_method`, `comparison_operator`,
`components`, `wildcard_prefix`, `lower_bound`, `upper_bound`,
`lower_inclusive`, `upper_inclusive`, `precision`, `reason`, `evidence`.

- **Precision** is the count of numeric components; versions are never padded.
  `1` / `1.2` / `1.2.3` stay distinct; `1.2` ≠ `1.2.0`.
- **Comparison**: component-wise numeric order. Same length → exact result.
  Different length: a non-zero extra component is a real difference
  (`1.2.3` vs `1.2` → NO_MATCH); an all-zero extra component is a precision
  ambiguity and returns `INDETERMINATE` (`1.2` vs `1.2.0`). Callers may opt
  into zero-padding with `allow_precision_expansion=True`.
- **Bounds**: `<=`/`<` exclusive flags are explicit; `before` = exclusive
  upper bound, `up to` = inclusive upper bound. Bound checks use the same
  precision-safe comparator, so `<=1.0` vs observed `1` is `INDETERMINATE`.
- **Wildcards/prefix**: `1.x` matches concrete versions whose first component
  is exactly `1`; `1.2.x` matches first two components exactly `1.2`; `1.2*`
  is the component-prefix equivalent. `10.0` never matches `1.x`. No substring
  matching is used.
- **Unknown/ambiguous**: empty values, unsupported prose (`latest`,
  `affected versions`, `~1.2`, bare `*`/`x`), invalid shapes (`1..2`, `1.2-`,
  `1,2`), reversed ranges, and ASCII hyphen ranges without spaces stay
  `UNKNOWN` with the (bounded) raw value preserved and no normalized version.

## Files Changed

- `ai/knowledge/version_normalization.py` — **new** pure module (RULE_VERSION
  `r31-7`): parsing, precision-safe comparison, conservative constraint
  evaluation, bounded structured evidence.
- `tests/test_version_normalization.py` — **new** focused suite (47 tests).
- `backend/asset_cve_matching.py` — additive adapter integration (+19 lines):
  import, bounded `build_version_evidence()` call over the exact inputs the
  engine receives, and three summary fields.

`ai/knowledge/asset_cve_matching.py` (R30.1), `ai/knowledge/component_identity.py`
(R31.6), `ai/knowledge/version_component_association.py` (R30.3),
`ai/knowledge/vulnerability_fingerprint.py` / schema (R31.1), the R31.5
provenance modules and all schemas are **not modified** (verified with
`git diff --name-only`).

## Rules Added

Normalization/parsing rules (all deterministic, no fuzzy logic):

1. Control characters collapsed; whitespace trimmed; value bounded to 128
   chars.
2. URL-like values (`://` or `//`) are redacted and `UNKNOWN`.
3. Parenthetical qualifiers are stripped before parsing
   (`< 7.1.2 (confirmed…)` → `< 7.1.2`).
4. Unicode en-dash/em-dash/minus normalized to `-` with surrounding spaces.
5. Trailing punctuation ` ;,.` trimmed.
6. Optional leading `v`/`V` stripped for concrete versions and bounds.
7. Leading zeros per component normalized (`01.0` → `1.0`) without padding.
8. Numeric dot-separated components only; anything else is `UNKNOWN`.
9. Comparators `<=`, `<`, `>=`, `>`, `=`, `==` parsed as bounded/exact
   constraints; no implicit operator from prose.
10. Prose operators `before` (exclusive upper) and `up to` (inclusive upper)
    parsed conservatively.
11. Ranges require a spaced ASCII hyphen, `to` (case-insensitive), or an
    en/em-dash; both bounds must be concrete; reversed ranges are `UNKNOWN`.
12. Wildcards `x`/`X`/`*` are trailing components only; fixed prefix must be
    all numeric; bare `*`/`x` is `UNKNOWN`.
13. Trailing `*` attached to a numeric component (`1.2*`) becomes `PREFIX`.
14. Every parse records a bounded reason/evidence; evidence rows are bounded
    and deduplicated by construction.

## Integration

- The adapter computes `build_version_evidence(cve_versions=cve_versions,
  observed_versions=list(association.engine_versions))` immediately after the
  R30.3 association and attaches:
  - `summary["version_normalization"]` — `rule_version`, parsed `cve_versions`,
    parsed `observed_versions`, bounded `rows`, `counts`;
  - `summary["version_normalization_rule_version"] = "r31-7"`.
- **R30.1 was NOT modified.** The engine still receives the original
  `cve_versions` and `observed_versions=list(association.engine_versions)`
  exactly as before; R31.7 does not rewrite, filter, or reorder engine inputs.
- R31.5 provenance/scoped-support gating is unchanged and remains authoritative
  for inferred component support; R31.6 identity resolution is unchanged.

## Confidence Safety

- R31.7 output is attached to the summary as evidence; it does not feed
  `calculate_match_confidence`, `_asset_state`, `resolve_blockers`, the R31.5
  support gate, Money Score, R17/R25.2/R26/R29 or candidate ranking.
- A version parse can therefore never turn MEDIUM into HIGH or SUPPORTED into
  CONFIRMED, and can never resolve a blocker by itself.
- Verified: with `cve_versions=["<=1.0"]` and observed `0.9` (R31.7 comparison
  MATCH), the adapter summary stays `VERSION` / `LOW` / `WEAK`, identical to a
  direct `evaluate_inventory()` call with the same inputs.

## Known Corpus Cases

| CVE | raw | parsed kind | normalized | comparison vs observed | limitation |
|---|---|---|---|---|---|
| CVE-2026-1557 | `<=1.0` | UPPER_BOUND inclusive | `<=1.0` | 0.9 → MATCH; 1.1 → NO_MATCH; 1 → INDETERMINATE | precision-safe bound; 1 vs 1.0 not decided |
| CVE-2026-78203 | `< 7.1.2 (confirmed against v7.1.1, commit 625a26b)` | UPPER_BOUND exclusive | `<7.1.2` | 7.1.1 → MATCH; 7.1.2 → NO_MATCH | parenthetical stripped; prose ignored |
| CVE-2026-78205 | `1.4.19` … `1.4.39` | EXACT ×21 | unchanged | each exact vs observed | only exact equality |
| CVE-2026-78207 | `<= 4.4.0` | UPPER_BOUND inclusive | `<=4.4.0` | 4.4.0 → MATCH; 4.4.1 → NO_MATCH | none |

Unsupported corpus forms: none — every affected-version string present in the
current corpus parses. (The 5 payloads without versions produce no evidence
rows.)

## False-Positive Protection

- Unsupported prose is never treated as an exact version (`latest`,
  `affected versions` → `UNKNOWN`; comparison `INDETERMINATE`).
- Precision ambiguity is explicit, not forced: `1.2` vs `1.2.0` →
  `INDETERMINATE`; a `<=1.0` bound against observed `1` → `INDETERMINATE`.
- No substring/fuzzy matching: `1.x` vs `10.0` → `NO_MATCH`;
  `1.2` vs `1.20` → `NO_MATCH`; `1.2.3` vs `1.2.30` → `NO_MATCH`;
  `1.2.3-rc1` is `UNKNOWN` (prerelease not supported/needed by the corpus).
- ASCII hyphen ranges without spaces (`1.0-1.5`) are `UNKNOWN` rather than
  guessed; reversed ranges are `UNKNOWN`.
- URL-like values are redacted and `UNKNOWN`.
- Existing R30.1 behavior (including its own looser parsing) is untouched, so
  no previously working match is silently removed or added.

## Tests

```bash
./venv/bin/python -m unittest tests.test_version_normalization -q
./venv/bin/python -m unittest tests.test_component_identity -q
./venv/bin/python -m unittest tests.test_component_inference -q
./venv/bin/python -m unittest tests.test_component_plugin_wiring -q
./venv/bin/python -m unittest tests.test_observed_inventory -q
./venv/bin/python -m unittest tests.test_asset_cve_matching -q
./venv/bin/python -m unittest tests.test_version_component_association -q
./venv/bin/python -m unittest tests.test_component_evidence_provenance -q
./venv/bin/python -m py_compile ai/knowledge/version_normalization.py \
    backend/asset_cve_matching.py tests/test_version_normalization.py
git diff --check
```

Results:

```
tests.test_version_normalization            Ran 47 tests  OK   (new)
tests.test_component_identity               Ran 57 tests  OK
tests.test_component_inference              Ran 53 tests  OK
tests.test_component_plugin_wiring          Ran 14 tests  OK
tests.test_observed_inventory               Ran 61 tests  OK
tests.test_asset_cve_matching               Ran 79 tests  OK
tests.test_version_component_association    Ran 41 tests  OK
tests.test_component_evidence_provenance    Ran 15 tests  OK
combined                                    Ran 367 tests OK (0 failures)

py_compile                                   OK
git diff --check                             clean
```

The new suite covers all 26 required areas: exact/leading-v/whitespace/leading
zero parsing, precision preservation, numeric comparison, precision
`INDETERMINATE`, upper/lower/inclusive/exclusive bounds, ranges (hyphen,
en-dash, `to`), wildcards (major/minor/star/prefix), invalid values, unknown
prose, determinism, evidence generation, evidence bounds, privacy redaction
(URL and credential-like), no substring/fuzzy matching, adapter integration,
confidence non-promotion, and R30.1/R30.3/R31.5/R31.6 regression canaries.

## Validation

- **Offline**: all tests execute with no network/LLM/subprocess/Mongo.
- **Synthetic**: spec-required forms (ranges, en-dash, wildcards, `before`,
  `up to`, precision cases) are covered by deterministic unit tests.
- **Local corpus**: all current affected-version strings were parsed with
  `build_version_evidence()` over the local `ai_data/research/*.cli.json`
  payloads; results are in "Known Corpus Cases".
- **Live Mongo**: **NOT performed** — remote Mongo was unreachable during this
  stage (`mongo ping: False`); no live validation is claimed. When reachable,
  `get_inventory("dell")` + `build_matches` will show
  `version_normalization_rule_version = "r31-7"` with parsed rows; none of the
  required tests depends on it.

## Safety / Privacy

- No secrets, credentials, authorization headers, cookies, request URLs or
  target identifiers are added to evidence. `build_version_evidence()` only
  emits the bounded raw/normalized version strings, kinds, precision,
  comparison and a bounded reason.
- URL-like version values (`://` or `//`) and credential-like values
  (`Authorization:`, `Bearer <token>`, `X-API-Key`, `X-Auth-Token`,
  `password=`, `passwd=`, `cookie:`, `set-cookie`, `session=`, common
  OAuth/AWS secret tokens) are redacted to `[redacted]` before any parsing
  or evidence construction; the privacy tests assert these tokens never
  appear in the evidence JSON.
- R31.7 is pure and offline: no I/O, network, DNS, LLM, subprocess, browser,
  Nuclei, target interaction, persistence or execution.

## Working Tree

```
$ git status --short
 M backend/asset_cve_matching.py
 D utils.zip
?? agent-reports/stage-r31-5-planning-audit.md
?? ai/knowledge/version_normalization.py
?? tests/test_version_normalization.py
?? watch.zip

$ git diff --stat   # tracked changes only
 backend/asset_cve_matching.py | 19 +++++++++++++++++++
 utils.zip                     | Bin 3104837 -> 0 bytes
```

Intentional R31.7 files: new `ai/knowledge/version_normalization.py`, new
`tests/test_version_normalization.py`, modified
`backend/asset_cve_matching.py` (additive), and this report
(`agent-reports/stage-r31-7-version-normalization.md`, new).

Unrelated pre-existing changes (untouched): `D utils.zip`, `?? watch.zip`,
`?? agent-reports/stage-r31-5-planning-audit.md`.

## Limitations

- Prerelease/build metadata (`1.2.3-rc1`, `1.2.3+build`) is unsupported and
  returns `UNKNOWN`; the current corpus does not contain such versions.
- Leading-zero and `v`-prefixed bounds are normalized for comparison, but the
  engine still receives the original raw strings (R31.7 does not rewrite
  inputs).
- Whitespace-free ASCII hyphen ranges (`1.0-1.5`) are treated as `UNKNOWN`
  (would be ambiguous with hyphenated versions).
- Wildcard/prefix matching is component-based only; `1.x` does not match
  `1`-only observed values (`INDETERMINATE`) because the observed precision is
  lower than the wildcard prefix.
- Evidence rows are bounded (64 versions per side, 64 rows, 4 evidence lines
  per parse, 128 chars per value); beyond that, later entries are truncated
  deterministically.
- R30.1's own version parsing remains authoritative for matching; where it
  interprets a string differently (e.g. en-dash ranges as an exact token),
  R31.7 evidence shows the conservative view but deliberately does not change
  the engine outcome.
- Live Mongo validation is pending connectivity.

## Conclusion

PASS — R31.7 is implemented additively, all 366 focused/regression tests pass,
`git diff --check` is clean, the R30.1 engine and all R31.x authorities are
untouched, and no commit/push/VM/deployment action was taken.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.7
- Role: coding agent
