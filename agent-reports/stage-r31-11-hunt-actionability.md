# R31.11 Hunt Actionability Refinement

Local WSL implementation. No commit, no push, no VM access, no deployment.

## 1. Goal

Build the next deterministic research-side Hunt Queue Intelligence layer on
top of the completed R31.10 Evidence-Aware Hunt Priority. R31.11 consumes the
existing R31.10 priority/score/tie-break projection for one Asset<->CVE
research candidate and derives a stable action-ordering signal for a human
bug-bounty hunter:

    "Of the candidates R31.10 already ranked, which ones are immediately
     verification-ready, which need strong manual review, which are only
     supporting context, which are low value, and which are terminally
     blocked?"

It is an **ordering/actionability refinement only**:

- research-side only; never connected to 5J, sealed findings, notifications
  or authoritative verification;
- R29 Hunt Queue semantics, R30.1 matching, R31.9 evidence quality and the
  R31.10 scoring constants/priority assignment are untouched;
- R31.10 is not rescored and its scoring logic is not duplicated;
- weak/inferred evidence can never become a confirmation or an
  immediate-verification candidate;
- terminal blockers from R31.9/R31.10 are preserved and can never be
  overridden;
- output is bounded, deterministic, explainable, machine-readable and stable
  across repeated runs;
- integration is additive: no existing R29/R31 field is overwritten.

## 2. Existing Integration Point Inspected

Before coding, these were read in full:

- **R31.10 engine (`ai/knowledge/hunt_priority.py`).** The consume-only
  surface: `rule_version`, `priority`, `priority_rank`, `hunt_score`,
  `blocked`, `evidence_quality`, `evidence_strength`, `evidence_consistency`,
  `blocking_reasons`, `positive_reasons`, `negative_reasons`,
  `remaining_blocker_codes`, `adjustments`, `tie_break_key`, `reason`.
  R31.11 reads the priority as the authoritative base ordering, the
  `blocked` flag as the terminal signal, the adjustment/reason codes for
  provenance/anchor/version/path signals, and the `tie_break_key` as the
  secondary sort key. No R31.10 constant or rule was reimplemented.
- **R31.10 backend wiring (`backend/asset_cve_matching.py:946-971`).** The
  additive block that attaches `summary["hunt_priority"]` and
  `summary["hunt_priority_rule_version"]` after the R31.9 block. R31.11 is
  attached immediately after it, using the same read-only locals
  (`summary["hunt_priority"]`, `support_gate["provenance"]`,
  `support_gate["support_scope"]`).
- **R29 hunt queue (`ai/knowledge/hunt_queue.py`,
  `ai/schemas/hunt_queue.py`, `backend/hunt_queue.py`).** R29 owns the
  string `hunt_priority` tier vocabulary (HUNT_NOW/HUNT_NEXT/VERIFY_FIRST/
  RESEARCH_LATER/SKIP_FOR_NOW) and the Money Score copy. R31.11 does not
  import, call, mutate or extend any of it; the R29 file and schema are
  byte-identical.
- **R30.1 matching (`ai/knowledge/asset_cve_matching.py`).** Untouched; its
  fields (`strongest_match_type`, `strongest_confidence`,
  `asset_match_state`, `remaining_blockers`, `version_state`, ...) are only
  seen through the R31.10 projection.
- **R31.5/R31.6/R31.7/R31.8/R31.9.** `evidence_provenance`/`support_scope`
  are re-read as optional read-only hints. Version compatibility, path
  relevance and evidence quality are consumed through the R31.10 projection
  (`EXACT_VERSION_MATCH`, `EXACT_PATH_MATCH`, `evidence_quality`,
  `evidence_consistency`, `blocking_reasons`, `remaining_blocker_codes`),
  not re-evaluated from raw inventory.

Existing naming: R29 already has a string `hunt_priority` on hunt queue
items; R31.10 added a structured dict `hunt_priority` on the Asset<->CVE match
summary. R31.11 adds new keys only: `hunt_actionability` (dict) and
`hunt_actionability_rule_version` (string). No collision.

## 3. Files Changed

- `ai/knowledge/hunt_actionability.py` — **new** pure module
  (`ACTIONABILITY_RULE_VERSION = "r31-11"` / `HUNT_ACTIONABILITY_RULE_VERSION`):
  closed states/ranks/next-actions, closed reason codes, deterministic
  downgrade guards, bounded ordering key.
- `backend/asset_cve_matching.py` — **modified additively** (+15/-0): import
  and attach `summary["hunt_actionability"]` +
  `summary["hunt_actionability_rule_version"]` after the R31.10 block. No
  existing field renamed, removed or changed; no engine input changed.
- `tests/test_hunt_actionability.py` — **new** focused suite (45 tests).
- `agent-reports/stage-r31-11-hunt-actionability.md` — this report.

No deployment/systemd/VM file was touched. No dependency was added (stdlib
`re` only). No network/LLM/subprocess/Mongo call was introduced.

## 4. Design / Decision Summary

R31.11 is a small layered classifier:

1. **Terminal first.** `blocked == True` -> `BLOCKED`, full stop. Blocker
   codes/remaining blockers are copied sanitised and bounded.
2. **Base mapping from R31.10 priority.** `P0 -> IMMEDIATE_VERIFICATION`,
   `P1 -> STRONG_MANUAL_REVIEW`, `P2 -> SUPPORTING_CONTEXT`,
   `P3 -> LOW_VALUE_DEFERRED`, `DEFER -> LOW_VALUE_DEFERRED`. Missing/absent
   priority -> `LOW_VALUE_DEFERRED` with `MISSING_PRIORITY_SIGNAL`; an
   unrecognised value -> `LOW_VALUE_DEFERRED` with `UNRECOGNIZED_PRIORITY`.
3. **Downgrade-only guards for `P0`.** A `P0` candidate is raised to
   `IMMEDIATE_VERIFICATION` only when all of these hold; otherwise it is
   downgraded to `STRONG_MANUAL_REVIEW` with the failing reason code(s):
   - `evidence_quality == HIGH`;
   - `evidence_consistency == CONSISTENT`;
   - no `remaining_blocker_codes`;
   - provenance resolves to `EXPLICIT` (from the explicit R31.5 hint, or
     from `EXPLICIT_PROVENANCE`/`MIXED_PROVENANCE`/`INFERRED_UNSCOPED_IDENTITY`
     reason codes; unknown provenance cannot be immediate);
   - a strong anchor exists: component-scoped support, exact observed
     version match, or exact observed path match (`COMPONENT_SCOPED_SUPPORT`,
     `EXACT_VERSION_MATCH`, `EXACT_PATH_MATCH` adjustment codes or an explicit
     `COMPONENT_SCOPED` scope hint).
4. **No upgrades.** Guards can only move a state toward
   `LOW_VALUE_DEFERRED`/`BLOCKED`; `P1`/`P2`/`P3`/`DEFER` are never promoted.
   `INFERRED`/`MIXED`/unknown provenance can never reach
   `IMMEDIATE_VERIFICATION`.
5. **Machine-readable explanation.** Every result carries
   `reason_codes` (closed vocabulary, first code is the source priority),
   `reason` (fixed deterministic text), `next_action` (closed advisory label)
   and the consumed source facts (`source_priority`, `source_hunt_score`,
   `source_priority_rank`, `source_evidence_quality`,
   `source_evidence_consistency`, `source_rule_version`, `source_reason`,
   `source_blocking_reasons`, `source_remaining_blockers`).
6. **Privacy.** The module carries its own `_safe_text` (same regex policy
   as R31.10): control characters collapsed, URL userinfo redacted, bearer
   tokens redacted, secret-like `key=value`/`key: value` pairs redacted,
   values bounded to 160 chars. Only closed codes, bounded counts and
   sanitised text enter the result.

Evidence dimensions consumed (requirement 6):

| Dimension | Consumed as |
|---|---|
| evidence quality | `evidence_quality == HIGH` readiness guard; `P0..DEFER` base |
| asset/component identity | R31.10 priority (identity contributes to the score) + `COMPONENT_SCOPED_SUPPORT`/provenance |
| version compatibility | `blocked` for `NO_MATCH`; `EXACT_VERSION_MATCH` as strong anchor |
| provenance/scope | explicit/unknown/inferred/mixed readiness guard; scope hint |
| path/parameter relevance | `EXACT_PATH_MATCH` as strong anchor; parameter/method only influence R31.10 |
| blockers/conflicts | `blocked`, `blocking_reasons`, `remaining_blocker_codes`, `EVIDENCE_INCONSISTENT` |
| observed-vs-inferred | provenance resolution + `INFERRED_UNSCOPED_IDENTITY` negative code; no confirmation is derived |

## 5. New Rule / Version Constant

```python
ACTIONABILITY_RULE_VERSION = "r31-11"
HUNT_ACTIONABILITY_RULE_VERSION = ACTIONABILITY_RULE_VERSION
RULE_VERSION = ACTIONABILITY_RULE_VERSION
```

Attached additively as:

```python
summary["hunt_actionability"] = evaluate_hunt_actionability(
    hunt_priority=summary["hunt_priority"],
    evidence_provenance=support_gate["provenance"],
    support_scope=support_gate["support_scope"],
)
summary["hunt_actionability_rule_version"] = "r31-11"
```

## 6. Actionability States and Meaning

Closed vocabulary `HUNT_ACTIONABILITY_STATES` with ascending action rank:

| State | Rank | `next_action` | Meaning |
|---|---|---|---|
| `IMMEDIATE_VERIFICATION` | 0 | `VERIFY_WITH_EXISTING_EVIDENCE` | Highest-confidence actionable candidate; R31.10 `P0` that passed every readiness guard. Verify first with the existing evidence workflow. |
| `STRONG_MANUAL_REVIEW` | 1 | `MANUAL_REVIEW` | Strong candidate (`P1`, or `P0` that failed a readiness guard); requires human review before verification. |
| `SUPPORTING_CONTEXT` | 2 | `COLLECT_MORE_EVIDENCE` | `P2`; supporting/manual-context candidate, not yet a verification target. |
| `LOW_VALUE_DEFERRED` | 3 | `DEFER` | `P3`, non-terminal `DEFER`, missing or unrecognised priority; low value under current evidence. |
| `BLOCKED` | 4 | `RESOLVE_BLOCKERS_FIRST` | R31.10 `blocked == True`; terminal authoritative blocker present, not actionable until resolved. |

`IMMEDIATE_VERIFICATION` is an actionability/ordering state only. It is not a
confirmation of a vulnerability, not exploitability, not CVSS, not a
probability and never a 5J finding.

## 7. Blocker Handling

- `BLOCKED` is decided before any scoring/refinement and is never overridden
  by quality, provenance, path or version fields.
- `blocking_reasons` and `remaining_blocker_codes` are copied read-only,
  bounded (`MAX_SOURCE_CODES = 8`) and sanitised.
- Version mismatch (`VERSION_NO_MATCH`), authoritative conflict
  (`AUTHORITATIVE_CONFLICT`), insufficient evidence
  (`EVIDENCE_INSUFFICIENT`) and no asset identity (`NO_ASSET_IDENTITY`) all
  arrive as R31.10 `blocked == True` and map to `BLOCKED` with
  `SOURCE_BLOCKED`.
- A non-terminal R31.10 `DEFER` (score < 20, `blocked == False`, with
  `EVIDENCE_INSUFFICIENT` appended to `blocking_reasons`) is classified
  `LOW_VALUE_DEFERRED`, not `BLOCKED`; the authoritative `blocked` flag is
  respected.
- `P0` candidates with unresolved `remaining_blocker_codes` are downgraded to
  `STRONG_MANUAL_REVIEW` (`REMAINING_BLOCKERS_PRESENT`) — blockers prevent
  immediate verification but never promote.

## 8. Ordering / Tie-Break Behavior

`action_order_key` is a stable, JSON-serializable list for ascending sort:

```
[actionability_rank, ...R31.10 tie_break_key]
```

`actionability_rank` 0..4 (best -> terminal last) is primary; the R31.10
`tie_break_key` (`priority_rank`, `-hunt_score`, quality rank, confidence
rank, match-type rank, exact-version flag, scoped flag, CVE id) is preserved
verbatim (sanitised, bounded to 16 items) as the secondary key, so within one
actionability state the R31.10 ordering is unchanged. Identical inputs always
produce identical keys; repeated evaluation is byte-identical; missing
`tie_break_key` degrades to `[rank]` deterministically. No randomness, clock
or hash ordering is used.

## 9. Tests Executed and Exact Results

```bash
./venv/bin/python -m unittest tests.test_hunt_actionability -v
./venv/bin/python -m unittest tests.test_hunt_actionability \
    tests.test_hunt_priority tests.test_evidence_quality \
    tests.test_path_parameter_relevance tests.test_version_normalization \
    tests.test_component_evidence_provenance tests.test_component_identity \
    tests.test_component_inference tests.test_component_plugin_wiring \
    tests.test_observed_inventory tests.test_asset_cve_matching \
    tests.test_version_component_association -q
./venv/bin/python -m unittest tests.test_hunt_queue -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile ai/knowledge/hunt_actionability.py \
    backend/asset_cve_matching.py tests/test_hunt_actionability.py
git diff --check
```

Results:

```
tests.test_hunt_actionability                     Ran 45 tests   OK  (new)
combined R31 + R31.11 regression                  Ran 534 tests  OK
tests.test_hunt_queue                             Ran 61 tests   3 failures
    (pre-existing: money-score corpus drift 50 vs 53; identical with the
     R31.11 backend change stashed)
complete project suite (discover tests)           Ran 2177 tests
    37 failures + 3 errors — failure-name set byte-identical before/after
    the R31.11 change (40 lines diffed clean); no new failure
py_compile                                        OK
git diff --check                                  clean
```

Required coverage is present:

| Required case | Test(s) |
|---|---|
| highest-confidence actionable | `test_A_explicit_scoped_exact_is_immediate`, `test_I_strong_fixture_is_immediate` |
| medium/supporting | `test_B_p1_is_strong_manual_review`, `test_B_p2_is_supporting_context` |
| weak/inferred | `test_C_p3_is_low_value_deferred`, `test_C_inferred_scoped_p0_never_immediate`, `test_C_inferred_unscoped_code_is_detected_without_hint` |
| blocked | `test_D_blocked_flag_never_overridden`, `test_D_blocked_never_mutates_source` |
| version mismatch | `test_D_version_mismatch_is_blocked` |
| authoritative conflict | `test_D_authoritative_conflict_is_blocked` |
| insufficient evidence | `test_D_insufficient_evidence_is_blocked` |
| stable ordering/tie-breaking | `TestOrderingAndDeterminism` (5 tests) |
| R31.10 regression | `TestR3110Regression` (3 tests: exact P0/P1/P2/P3/DEFER snapshots, deep-copy non-mutation, recompute equality) |
| R29 regression | `TestR29Regression` (4 tests: queue snapshot equality, vocabulary/rule version, no leaked field, ordering/reasons stable) |

Additional guards covered: quality-not-HIGH, mixed/unknown/inferred
provenance, supporting conflict, remaining blockers, no strong anchor, and
downgrade-never-upgrades. Bounds/privacy/JSON tests cover reason-code caps,
source-copy caps, order-key cap and secret redaction.

## 10. Regression Results

- **R31.10 unchanged.** `hp.RULE_VERSION == "r31-10"` and
  `hp.HUNT_PRIORITY_RULE_VERSION == "r31-10"` asserted. Exact snapshots
  (`P0`/100, `P1`/60, `P2`/48, `P3`/28, non-terminal `DEFER`/10,
  blocked `DEFER`/0) are asserted before and after R31.11 evaluation; the
  R31.10 input dict is deep-copy equal after classification; re-running
  R31.10 produces byte-identical JSON. Backend integration asserts
  `hunt_priority_rule_version == "r31-10"` and the R31.10 `P0`/`DEFER`
  outcomes still hold with all R31.7/R31.8/R31.9 fields present.
- **R29 unchanged.** The R29 queue snapshot (items, ranking, summary,
  classifications) is JSON-identical before and after R31.11 runs; the R29
  rule version is still `r29-1`; R29 items contain no R31.11 field; R29
  ordering/reasons are stable.
- **R30.1/R31.5–R31.9 unchanged.** Full-suite failure-name set is
  byte-identical before and after (37 failures + 3 errors, all pre-existing
  Mongo/corpus-drift failures). `tests.test_hunt_queue` failures were
  reproduced with the R31.11 backend change stashed.
- **Money Score canary** (`test_I_money_score_unchanged`) passes.

## 11. Performance

```
1 candidate     ->  0.17 ms
100 candidates  ->  5.00 ms  (~50 us/candidate)
1000 candidates -> 45.68 ms  (~46 us/candidate)
```

Cost is O(evidence dimensions + bounded copies); no Mongo/URL/subdomain scan
occurs at this layer.

## 12. Limitations / Intentionally Deferred Work

- Exposure is limited to the Asset<->CVE candidate summary
  (`hunt_actionability`, `hunt_actionability_rule_version`). Wiring the signal
  into the R29 queue projection/schema/UI is deliberately deferred — that
  would touch R29, which this stage must not modify.
- R31.11 consumes the R31.10 projection plus optional R31.5 provenance/scope
  hints; it does not re-read raw inventory, and it does not re-run version or
  path matching. If `hunt_priority` is absent (e.g. an older summary), the
  result is a deterministic `LOW_VALUE_DEFERRED` with
  `MISSING_PRIORITY_SIGNAL`.
- The strong-anchor bar is conservative: family/range version matches alone
  (without scoped support, an exact observed version, or an exact path) yield
  `STRONG_MANUAL_REVIEW`, never `IMMEDIATE_VERIFICATION`.
- No real-corpus/Mongo run was added; all tests are hermetic and offline. The
  pre-existing project-suite failures are unchanged and unrelated.
- `IMMEDIATE_VERIFICATION` remains an advisory ordering label; no execution,
  scanning, notification, sealed finding or authoritative verification was
  added.

## 13. Git Scope

```
$ git status --short
 M backend/asset_cve_matching.py
 D utils.zip
?? agent-reports/stage-r31-5-planning-audit.md
?? ai/knowledge/hunt_actionability.py
?? tests/test_hunt_actionability.py
?? watch.zip

$ git diff --stat          # tracked changes only
 backend/asset_cve_matching.py | 15 +++++++++++++++
 utils.zip                     | Bin 3104837 -> 0 bytes
```

Intentionally changed by R31.11: `ai/knowledge/hunt_actionability.py` (new),
`tests/test_hunt_actionability.py` (new), `backend/asset_cve_matching.py`
(additive, +15/-0), and this report. Unrelated pre-existing changes
(`D utils.zip`, `?? watch.zip`, `?? agent-reports/stage-r31-5-planning-audit.md`)
were left untouched. No commit, no push, no VM/deployment action.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.11
- Role: coding agent
