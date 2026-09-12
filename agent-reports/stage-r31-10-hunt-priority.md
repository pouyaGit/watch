# R31.10 Evidence-Aware Hunt Priority

Local WSL implementation. No commit, no push, no VM access, no deployment.

## 1. Objective

Add a deterministic, explainable hunt-ordering signal for research-side
Asset<->CVE candidates, built from the evidence already produced by
R30.1/R31.5/R31.6/R31.7/R31.8/R31.9:

    "Given the evidence currently available, which candidate deserves my
     limited bug-bounty verification time first?"

It prioritises strong identity, compatible versions, explicit/scoped
evidence, exact path/parameter relevance and consistency, and deprioritises
authoritative mismatches, conflicts, inferred-unscoped identity, generic
technology-only evidence and large evidence gaps. It is a hunt prioritisation
signal only: not exploitability, not CVSS, not a payout prediction, not a
probability of vulnerability, and never a 5J finding.

## 2. Architecture Audit

Traced before implementation:

- **R29 personal hunt queue (`ai/knowledge/hunt_queue.py`,
  `backend/hunt_queue.py`, `ai/schemas/hunt_queue.py`).** Owns the
  `hunt_priority` closed vocabulary (HUNT_NOW/HUNT_NEXT/VERIFY_FIRST/
  RESEARCH_LATER/SKIP_FOR_NOW) and the Money Score copy. R31.10 does **not**
  modify it; the R29 queue still ranks on its own rules and the R31.10 signal
  is attached to the Asset<->CVE candidate summary only.
- **R30.1 matching (`ai/knowledge/asset_cve_matching.py`, untouched).**
  Consumed fields: `strongest_match_type`, `strongest_confidence`,
  `asset_match_state`, `matched_component`, `matched_version`,
  `matched_parameter`, `resolved_blockers`, `remaining_blockers`,
  `version_state`.
- **R30.2 observed inventory.** Only through the sanitized summary produced by
  the adapter; no corpus scan.
- **R30.3 version association.** `version_association_state` is consumed as the
  authoritative version signal when the engine withheld non-matching versions.
- **R31.1 fingerprint.** Orphaned; untouched.
- **R31.5 provenance/scope.** `evidence_provenance` and `support_scope`
  consumed read-only; no scope logic changed.
- **R31.6 identity.** `identity_resolution` indirectly consumed via R31.9; not
  reimplemented.
- **R31.7 version normalization.** `version_normalization.rows` (comparison,
  kind, evidence class) and `observed_versions` consumed read-only; no version
  parsing.
- **R31.8 path/parameter relevance.** `path_parameter_relevance.summary` and
  `.evidence` consumed read-only; no path/parameter matching.
- **R31.9 evidence quality.** The full block (`evidence_quality`,
  `evidence_strength`, `evidence_consistency`, `evidence_gaps`, `conflicts`)
  is consumed read-only; R31.9 decision rules are not reimplemented.
- **R25.2/R26 Money/opportunity/action structures.** Untouched; no schema or
  scoring change.

Existing naming: R29 already owns a *string* `hunt_priority` on hunt queue
items. R31.10 adds a *structured dict* `summary["hunt_priority"]` plus
`summary["hunt_priority_rule_version"]` on the Asset<->CVE match summary
(a different structure that previously had no such field). No collision.

## 3. Files Changed

- `ai/knowledge/hunt_priority.py` — **new** pure module
  (`HUNT_PRIORITY_RULE_VERSION = "r31-10"`): bounded additive scoring,
  terminal blockers, documented reason codes, stable tie-break keys.
- `tests/test_hunt_priority.py` — **new** focused suite (46 tests: A–Z
  coverage, false-positive guards 1–12, hermetic backend integration,
  performance guard).
- `backend/asset_cve_matching.py` — **modified additively** (+28/-0): imports
  the module, attaches `summary["hunt_priority"]` and
  `summary["hunt_priority_rule_version"]` after the R31.9 block. No existing
  field renamed/removed and no engine input changed.
- `agent-reports/stage-r31-10-hunt-priority.md` — this report.

R30.1/R30.2/R30.3/R31.1/R31.5/R31.6/R31.7/R31.8/R31.9 and all R29 files are
untouched (verified with `git diff --name-only`).

## 4. Ranking Model

Ordered decision model over a bounded additive score (0..100), never a
probability:

1. **Terminal authoritative blockers** → `DEFER`, score 0 (see section 6).
2. **Bounded additive score** from fixed, documented constants.
3. **Priority thresholds**: `P0 >= 80`, `P1 >= 60`, `P2 >= 40`,
   `P3 >= 20`, otherwise `DEFER`.

Fixed constants (all exposed as adjustments with reason codes):

```
Base: HIGH 60, MEDIUM 40, LOW 20, INSUFFICIENT 0
+ component/plugin identity       +10
+ exact observed version MATCH    +15
+ family version MATCH            +12
+ range/wildcard version MATCH    +8
+ explicit provenance             +6
+ mixed provenance                +4
+ component-scoped support        +6
+ exact path MATCH                +4
+ prefix/pattern path MATCH       +2
+ exact parameter MATCH           +3
+ method MATCH                    +2
+ no remaining blockers           +4
- inferred + unscoped identity    -6
- version unresolved (observed)   -4
- >=3 evidence gaps               -4
- supporting (non-authoritative) conflict -10
- each remaining blocker          -2
```

Every adjustment is recorded in `adjustments` as `{code, delta}` and surfaced
in `positive_reasons`/`negative_reasons` with the code and signed delta. The
score is clamped to `[0, 100]` and never described as a probability.

## 5. Priority Rules

- `P0`: strongest actionable candidates — HIGH evidence quality with explicit
  or component-scoped identity, compatible version evidence, and no
  authoritative blockers. Reachable by guard case 8 (explicit component +
  exact version + scoped exact path/parameter).
- `P1`: MEDIUM quality with explicit or scoped identity (and typically a
  version signal); actionable but below the strongest.
- `P2`: component identity present but weaker provenance/version/support.
- `P3`: LOW quality, inferred identity with global-only support, or
  supporting-only evidence that still has a real component relationship.
- `DEFER`: authoritative blockers, R31.9 `INSUFFICIENT`, or score below 20.

Priority levels are a closed vocabulary `P0/P1/P2/P3/DEFER` with fixed ranks
`0..4`; `priority_rank` is the deterministic sort key.

## 6. Authoritative Blockers

Terminal, score 0, `DEFER`:

- `VERSION_NO_MATCH` — `version_state == "NO_MATCH"` or
  `version_association_state == "VERSION_OBSERVED_NO_MATCH"` (R30.3 withholds
  non-matching versions, so the association state is the authoritative signal).
- `AUTHORITATIVE_CONFLICT` — any R31.9 conflict with
  `severity == "authoritative"` (component or version conflict).
- `EVIDENCE_INSUFFICIENT` — R31.9 evidence quality `INSUFFICIENT`. By R31.9
  construction no explicit actionable signal can coexist with INSUFFICIENT
  (any component/version action raises quality), so this is terminal.
- `NO_ASSET_IDENTITY` — no product/component/plugin identity and no version
  mismatch (defensive; usually already INSUFFICIENT).

No path/parameter/method evidence can lift a blocked candidate: the terminal
branch returns before any scoring. R31.5 has no explicit "scope exclusion"
state, so `support_scope = NONE` is treated as a downgrade (-6 for inferred
unscoped), not a terminal exclusion; this is documented behavior.

## 7. R31.9 Compatibility

R31.9 output is consumed read-only: `evidence_quality` sets the base score and
terminal `INSUFFICIENT`; `evidence_consistency`/`conflicts` drive the
supporting-conflict penalty; `evidence_gaps` drive the gap penalty and the
reported gaps; `evidence_strength` is copied into the result verbatim. R31.9
classification rules are never reimplemented or altered.

## 8. R30.1 Compatibility

R30.1 fields are inputs only; their semantics and values are unchanged and
still present in the summary. The integration test `test_engine_fields_unchanged`
compares the adapter summary against a direct `evaluate_inventory()` call with
the exact same inputs for `strongest_match_type`, `strongest_confidence`,
`asset_match_state`, `remaining_blockers` and `version_state`. The Money Score
canary (`test_money_score_unchanged`) builds economics before and after a match
and asserts equality.

## 9. R31.5 / R31.6 / R31.7 / R31.8 Compatibility

- **R31.5**: `evidence_provenance` (+/- adjustment) and `support_scope`
  (scoped bonus, inferred-unscoped penalty) are consumed read-only. Scope
  authority is unchanged: inferred-only identity with global support cannot
  reach P0 (guard 4) and component-scoped support ranks above global support.
- **R31.6**: identity resolution is untouched; explicit/strong identity comes
  through `matched_component` and R31.9's component-identity dimension.
- **R31.7**: version rows/kinds/classes and `observed_versions` are consumed
  read-only; no version parsing. Exact observed MATCH > family MATCH >
  range/wildcard MATCH > unresolved; NO_MATCH is terminal.
- **R31.8**: `path_match`, `parameter_match`, `component_scoped` and method
  summary are consumed read-only; no path/parameter matching. Exact path >
  prefix/pattern; parameters and methods are supporting-only.

## 10. Deterministic Tie-Breaking

`tie_break_key` is a stable, JSON-serializable list designed for ascending
sort:

```
[priority_rank, -hunt_score, evidence_quality_rank, -confidence_rank,
 match_type_rank, exact_version_flag, component_scoped_flag, cve_id]
```

`priority_rank` 0..4 (P0 best, DEFER worst); quality ranks HIGH..INSUFFICIENT
0..3; confidence ranks HIGH..NONE 3..0 (negated so HIGH sorts first); match
type order COMPONENT/PLUGIN/PRODUCT/VERSION/TECHNOLOGY/PARAMETER/PATH/
VULNERABILITY_TYPE; exact-version and scoped flags prefer 1; CVE id
lexicographic. Two candidates with identical evidence always produce identical
keys (test V); repeated evaluation is byte-identical (test W). No randomness,
clock or hash ordering is used.

## 11. False-Positive Guard Tests

Required guards proved in `tests/test_hunt_priority.py`:

| # | Guard | Result |
|---|---|---|
| 1 | exact path MATCH alone | `DEFER` (never P0) |
| 2 | exact parameter MATCH alone | `DEFER` |
| 3 | method MATCH alone | `DEFER` |
| 4 | inferred component + global generic path | P3, never P0/P1 |
| 5 | version NO_MATCH | `DEFER` + `VERSION_NO_MATCH` even with path/parameter MATCH |
| 6 | authoritative component conflict | `DEFER`, never P0/P1 |
| 7 | R31.9 INSUFFICIENT with blocker | `DEFER` |
| 8 | explicit component + compatible version + scoped exact path | `P0` |
| 9 | same candidate evaluated twice | identical result (test W) |
| 10 | Money Score unchanged | integration canary passes |
| 11 | R30.1 confidence unchanged | integration comparison passes |
| 12 | R31.7/R31.8 evidence structures unchanged | integration test asserts rule versions and presence |

## 12. Privacy / Sanitization

- The result stores only closed reason codes, bounded counts, bounded sanitized
  gap/blocker text and the CVE id (pattern-safe). Raw URLs, query values,
  headers, cookies, tokens and secrets are never copied.
- `_safe_text` redacts userinfo (`://user:pass@`), bearer tokens
  (`Bearer <token>`) and secret-like `key=value`/`key: value` pairs, and
  collapses control characters before anything enters the result.
- Tests: `test_Y_privacy_no_secrets_in_output` feeds
  `?token=SECRET`, `Authorization: Bearer abc123` and `password=hunter2` and
  asserts none appear in the serialized output; the adapter privacy test feeds
  a secret-looking path/parameter and asserts the `hunt_priority` block is
  clean.
- R31.8/R31.9 already sanitize their own evidence; R31.10 adds no new raw
  storage.

## 13. Test Results

Commands executed:

```bash
./venv/bin/python -m unittest tests.test_hunt_priority -q
./venv/bin/python -m unittest tests.test_hunt_priority \
    tests.test_evidence_quality tests.test_path_parameter_relevance \
    tests.test_version_normalization tests.test_component_evidence_provenance \
    tests.test_component_identity tests.test_component_inference \
    tests.test_component_plugin_wiring tests.test_observed_inventory \
    tests.test_asset_cve_matching tests.test_version_component_association -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile ai/knowledge/hunt_priority.py \
    backend/asset_cve_matching.py tests/test_hunt_priority.py
git diff --check
```

Results:

```
tests.test_hunt_priority                    Ran 46 tests  OK   (new)
tests.test_evidence_quality                 Ran 36 tests  OK
tests.test_path_parameter_relevance         Ran 40 tests  OK
tests.test_version_normalization            Ran 47 tests  OK
tests.test_component_evidence_provenance    Ran 15 tests  OK
tests.test_component_identity               Ran 57 tests  OK
tests.test_component_inference              Ran 53 tests  OK
tests.test_component_plugin_wiring          Ran 14 tests  OK
tests.test_observed_inventory               Ran 61 tests  OK
tests.test_asset_cve_matching               Ran 79 tests  OK
tests.test_version_component_association    Ran 41 tests  OK
combined R31 regression                     Ran 489 tests OK (0 failures)

complete project suite (discover tests)     Ran 2132 tests
  37 failures + 3 errors -- all pre-existing and identical with the R31.10
  change reverted (verification: same discovery with
  backend/asset_cve_matching.py stashed produced the same non-R31.10 failure
  set). No new failure is attributable to R31.10.

py_compile                                  OK
git diff --check                            clean
```

Required A–Z coverage is present: HIGH/MEDIUM/LOW/INSUFFICIENT (A–D),
R30.1 CONFIRMED/SUPPORTED/WEAK/UNKNOWN (E–H), version exact/no-match/
indeterminate (I–K), exact path/parameter/method (L–N), scoped/global support
(O–P), inferred/explicit/conflict identity (Q–R), authoritative blocker and
gaps (S–U), tie-breaking/determinism/bounds (V–X), privacy (Y), existing Money
Score canary (Z), plus hermetic backend integration.

## 14. Real Corpus Sanity Check

Read-only scan over `local_cve_context()` (6 CVE contexts with KB synthesis
documents) combined with a deterministic synthetic Dell observed fixture
(explicit `image_handler.php` component, `src` parameter/path, version
association). Mongo was not reachable, so observed data is synthetic and
labelled as such; research data was not modified.

Observed version `1.0` (matches `<=1.0` for CVE-2026-1557):

```
candidates examined: 6
priorities: P0 1, P1 0, P2 0, P3 0, DEFER 5
quality:    HIGH 1, INSUFFICIENT 5
blocked by version mismatch: 0
blocked by conflict: 0
strong component identity: 1
strong version evidence:   1
R31.8 path evidence:       1
top candidate: CVE-2026-1557 (COMPONENT, HIGH confidence, P0, score 99)
deferred sample: CVE-2024-27956 (DEFER; blockers
                 EVIDENCE_INSUFFICIENT, NO_ASSET_IDENTITY)
```

Observed version `2.0.0` (mismatch):

```
priorities: P0 0, P1 0, P2 0, P3 0, DEFER 6
quality:    INSUFFICIENT 6
blocked by version mismatch: 1 (CVE-2026-1557)
strong version evidence: 0
```

The matching candidate reaches the strongest actionable priority; the
mismatching variant is correctly blocked by `VERSION_NO_MATCH`.

## 15. Performance Check

The layer operates only on candidate summaries and never scans MongoDB, URLs,
endpoints or subdomains.

```
1 candidate     -> 0.08 ms
100 candidates  -> 2.66 ms  (~27 us/candidate)
1000 candidates -> 32.37 ms (~32 us/candidate)
```

Cost is O(evidence dimensions + bounded reason lists); the in-suite guard
ranks 1000 candidates in < 5 s (actual ~32 ms).

## 16. Security Review

Reviewed `hunt_priority`, `priority_rank`, `hunt_score`, `blocked`,
`evidence_quality/strength/consistency`, `blocking_reasons`,
`positive_reasons`, `negative_reasons`, `evidence_gaps`,
`remaining_blocker_codes`, `adjustments`, `tie_break_key`, `reason`:

- No probability or exploitability claim exists; `hunt_score` is a bounded
  ordering key with documented fixed constants.
- No raw URLs/values/headers/tokens can enter: only closed codes, bounded
  counts and `_safe_text`-sanitized text are retained; regression tests cover
  secret-like inputs.
- No LLM, no network, no execution; deterministic and explainable.
- Research-side only: no 5J finding is created; Money Score, R17/R25.2/R26/R29
  and R30.1 fields are untouched.

## 17. Git Scope

```
$ git status --short
 M backend/asset_cve_matching.py
 D utils.zip
?? agent-reports/stage-r31-5-planning-audit.md
?? ai/knowledge/hunt_priority.py
?? tests/test_hunt_priority.py
?? watch.zip

$ git diff --stat          # tracked changes only
 backend/asset_cve_matching.py | 28 ++++++++++++++++++++++++++++
 utils.zip                     | Bin 3104837 -> 0 bytes
```

Intentionally changed by R31.10: `ai/knowledge/hunt_priority.py` (new),
`tests/test_hunt_priority.py` (new), `backend/asset_cve_matching.py`
(additive, +28/-0), and this report.

Unrelated pre-existing changes left untouched: `D utils.zip`, `?? watch.zip`,
`?? agent-reports/stage-r31-5-planning-audit.md`.
Previous-stage authority files verified untouched (R30.1 engine, R30.3,
R31.5/R31.6/R31.7/R31.8/R31.9 modules, R29 hunt queue modules/schemas).

Note/limitation: R31.10 is exposed on the Asset<->CVE candidate summary
(`summary["hunt_priority"]`, `summary["hunt_priority_rule_version"]`). Wiring
it into the R29 queue projection/schema would be a separate additive change;
R29's own `hunt_priority` and ordering remain authoritative and unchanged.

## 18. Conclusion

PASS — R31.10 is implemented, integrated additively, documented and tested:
46 focused tests and 489 combined R31 regression tests pass; the complete
project suite (2132 tests) shows only the pre-existing failures that are
identical with this change reverted; `py_compile` and `git diff --check` are
clean. R30.1 and all previous R31.x authorities are untouched, existing
scores/priorities are unchanged, no secret values can enter the new ranking
structure, and no commit/push/VM/deploy action was taken.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.10
- Role: coding agent
