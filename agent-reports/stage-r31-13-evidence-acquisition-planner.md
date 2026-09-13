# R31.13 Evidence Acquisition Planner

Local WSL implementation. No commit, no push, no VM access, no deployment.
Plan-only stage: no acquisition method is ever executed.

## 1. Goal

Build the next deterministic research-side layer on top of R31.10 Hunt
Priority, R31.11 Hunt Actionability and R31.12 Hunt Action Planner. For each
Asset<->CVE research candidate, R31.13 determines:

1. what evidence is currently missing,
2. what minimum evidence type would close the selected gap,
3. what safe research method could acquire that evidence,
4. what completion condition would indicate the gap is sufficiently
   addressed.

The planner consumes R31.12's selected action as the authoritative input for
choosing the acquisition plan. It is **PLAN-ONLY**: it never executes the
acquisition method, never performs HTTP, browser, Nuclei, crawl, fuzz, scan or
exploit activity, never calls an LLM, never touches the network or MongoDB,
never creates a 5J finding and never modifies R29/R30.1/R31.7/R31.8/R31.9/
R31.10/R31.11/R31.12 semantics or the Money Score. It describes **what
evidence is needed**, never **how to attack**.

## 2. Existing Integration Points Inspected

Read in full before coding:

- **R31.12 (`ai/knowledge/hunt_action_planner.py`).** Consumed fields:
  `action` (closed action vocabulary imported as constants), `evidence_gap`
  (closed gap vocabulary imported as constants), `confidence`,
  `estimated_effort`, `action_order_key`. No R31.12 rule was reimplemented.
- **R31.11 (`ai/knowledge/hunt_actionability.py`).** Consumed states:
  `actionability` (`BLOCKED`, `LOW_VALUE_DEFERRED`, `IMMEDIATE_VERIFICATION`,
  imported as constants) and `action_order_key`. No actionability rule was
  reimplemented.
- **R31.10 (`ai/knowledge/hunt_priority.py`).** Consumed fields: `priority`,
  `hunt_score`, `blocked`. No scoring or gating rule was reimplemented.
- **R31.9 (`ai/knowledge/evidence_quality.py`).** Consumed only indirectly
  through the R31.10/R31.12 projections; R31.13 performs no gap-line parsing
  and no gap detection of its own.
- **R30.1 (`ai/knowledge/asset_cve_matching.py`).** Confirmed canonical
  blocker codes and `strongest_match_type` values that flow through the
  upstream projections; nothing is re-derived.
- **R31.5 evidence provenance / R31.6 component identity / R31.7 version
  normalization / R31.8 path-parameter relevance (`backend/asset_cve_matching.py`,
  `ai/schemas/observed_inventory.py`).** Consumed only through the upstream
  read-only locals (`support_gate["provenance"]`,
  `support_gate["support_scope"]`, `summary["strongest_match_type"]`); none of
  their rules are duplicated.
- **R29 hunt queue (`ai/knowledge/hunt_queue.py`,
  `ai/schemas/hunt_queue.py`).** Untouched; not imported or extended.
- **Backend integration (`backend/asset_cve_matching.py:1003`).** The R31.12
  block; R31.13 is attached immediately after it.

## 3. Files Changed

- `ai/knowledge/evidence_acquisition_planner.py` — **new** pure module
  (`EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION = "r31-13"`, 814 lines):
  closed acquisition-method/target/completion/effort/confidence/reason
  vocabularies, deterministic R31.11/R31.12 mapping, defensive conflict
  handling, bounded ordering key.
- `backend/asset_cve_matching.py` — **modified additively** (+23/-0): import
  plus `summary["evidence_acquisition_plan"]` and
  `summary["evidence_acquisition_plan_rule_version"]` immediately after the
  R31.12 block. No existing field renamed, removed or changed; no engine
  input changed.
- `tests/test_evidence_acquisition_planner.py` — **new** focused suite
  (60 tests, 1513 lines).
- `agent-reports/stage-r31-13-evidence-acquisition-planner.md` — this report.

No deployment/systemd/VM file was touched. No dependency was added (stdlib
`re` only). No network/LLM/subprocess/Mongo call was introduced.

## 4. Design Decisions

- **Consume, never recompute.** The planner takes the R31.10 dict, R31.11
  dict and R31.12 dict as read-only inputs. It never calls
  `evaluate_hunt_priority`, `evaluate_hunt_actionability`, `plan_hunt_action`
  or any gap-detection helper (asserted by `test_17_module_never_calls_upstream_engines`).
- **R31.12 is the only gap selector.** The planner never re-derives a gap
  from R31.10/R31.9 signals. A behavioral test feeds an R31.10 projection with
  an explicit version-gap signal and a R31.12 plan that selected a path gap;
  R31.13 follows R31.12 (`PATH_EVIDENCE_REVIEW`, `GAP_PATH`).
- **Terminal-first.** `BLOCKED` (either projection) and `LOW_VALUE_DEFERRED`
  are terminal; a terminal R31.12 action (`RESOLVE_BLOCKERS`/`DEFER`) is
  terminal for acquisition planning.
- **A valid action plan is required.** A missing or unrecognized R31.12 action
  yields a deterministic `NONE` plan (`ACTION_PLAN_MISSING` /
  `UNKNOWN_ACTION`); it never guesses an acquisition from the actionability
  state alone.
- **Action/gap consistency is validated.** Each known non-terminal R31.12
  action has exactly one gap it can select (the R31.12 `_GAP_ACTION` pairing).
  A present-but-different `evidence_gap` yields a defensive `NONE` plan with
  `ACTION_PLAN_CONFLICT`; the inconsistent upstream gap is not copied. An
  absent/empty gap field carries no contradicted selection, so the action's
  deterministic gap pair is used.
- **IMMEDIATE + gap action follows R31.12.** R31.12 can legitimately downgrade
  an `IMMEDIATE_VERIFICATION` candidate with non-explicit provenance to a gap
  action. R31.13 honors the authoritative R31.12 action and adds
  `SOURCE_IMMEDIATE` to explain the downgraded origin. For the normal
  immediate case (R31.12 `VERIFY_EXISTING_EVIDENCE`) the result is the
  specified `EXISTING_EVIDENCE_REVIEW` with confidence `HIGH`, effort `LOW`.
- **The three scalar hints are read-only parity inputs.** `evidence_provenance`,
  `support_scope` and `strongest_match_type` are accepted by the signature for
  pipeline parity but can never change the plan or invent a gap, because
  R31.12 is the only gap selector. This is documented in the module docstring.
- **One primary plan.** The result carries exactly one closed acquisition
  method, its rank, evidence target, selected gap, completion condition,
  bounded reason codes, a static advisory reason and a qualitative
  confidence/effort.
- **No operational attack content.** Method labels are review/lookup/review
  labels; reasons are static project-authored text. The output contains no
  payloads, exploit strings, fuzzing dictionaries, scanner commands, Nuclei
  templates, request bodies, bypass techniques, exploitation sequences or
  target-specific instructions (asserted by
  `test_32_no_operational_attack_content`).

## 5. Closed Acquisition Vocabulary

`ACQUISITION_METHODS` (rank, target, default effort):

| Method | Rank | Evidence target | Effort | Meaning |
|---|---|---|---|---|
| `EXISTING_EVIDENCE_REVIEW` | 0 | `EXISTING_EVIDENCE` | LOW | Review already collected evidence; no new target interaction. |
| `VERSION_LOOKUP` | 1 | `VERSION` | MEDIUM | Acquire authoritative/public version information from an allowed research source. |
| `COMPONENT_IDENTITY_LOOKUP` | 2 | `COMPONENT_IDENTITY` | MEDIUM | Acquire authoritative/public component/plugin/product identity information. |
| `SCOPE_EVIDENCE_REVIEW` | 3 | `SCOPE` | MEDIUM | Confirm the observed evidence belongs to the correct program/component scope. |
| `PATH_EVIDENCE_REVIEW` | 4 | `PATH` | LOW | Confirm the path/resource relationship using existing collected evidence. |
| `PARAMETER_EVIDENCE_REVIEW` | 5 | `PARAMETER` | LOW | Confirm parameter presence/relevance using existing collected evidence. |
| `HTTP_BEHAVIOR_REVIEW` | 6 | `HTTP_BEHAVIOR` | MEDIUM | Determine what HTTP behavior evidence would be needed for the gap. |
| `TECHNOLOGY_EVIDENCE_REVIEW` | 7 | `TECHNOLOGY` | MEDIUM | Determine what technology evidence would establish the technology relationship. |
| `MANUAL_RESEARCH` | 8 | `EXISTING_EVIDENCE` | HIGH | Human research required when no narrower safe method can be selected. |
| `NONE` | 9 | `NONE` | UNKNOWN | No acquisition planned (deferred, blocked or malformed plan). |

Additional closed vocabularies: `EVIDENCE_TARGETS` (`VERSION`,
`COMPONENT_IDENTITY`, `SCOPE`, `PATH`, `PARAMETER`, `HTTP_BEHAVIOR`,
`TECHNOLOGY`, `EXISTING_EVIDENCE`, `NONE`), `COMPLETION_CONDITIONS` (12 fixed
labels listed in §6), `ESTIMATED_EFFORTS` (`LOW`/`MEDIUM`/`HIGH`/`UNKNOWN`),
`ACQUISITION_CONFIDENCES` (`HIGH`/`MEDIUM`/`LOW`) and 15 closed
`REASON_CODES`. No numeric probability, exploitability, severity, CVSS or
payout field exists.

## 6. Deterministic Mapping

First match wins; R31.11 terminals are checked before the R31.12 action:

| # | Condition | Method | Target | Gap | Completion condition | Confidence / effort |
|---|---|---|---|---|---|---|
| 1 | R31.11 `BLOCKED` (or R31.10 `blocked`) | `NONE` | `NONE` | `GAP_NONE` | `BLOCKERS_RESOLVED_BEFORE_RESEARCH` | HIGH / UNKNOWN |
| 2 | R31.11 `LOW_VALUE_DEFERRED` | `NONE` | `NONE` | `GAP_NONE` | `REACTIVATE_ONLY_IF_PRIORITY_CHANGES` | HIGH / UNKNOWN |
| 3 | Action `VERIFY_EXISTING_EVIDENCE` | `EXISTING_EVIDENCE_REVIEW` | `EXISTING_EVIDENCE` | `GAP_NONE` | `EXISTING_EVIDENCE_REVIEWED` | HIGH / LOW |
| 4 | Action `VERIFY_VERSION` | `VERSION_LOOKUP` | `VERSION` | `GAP_VERSION` | `VERSION_COMPATIBILITY_EXPLICITLY_ESTABLISHED` | R31.12 / R31.12 |
| 5 | Action `VERIFY_COMPONENT_IDENTITY` | `COMPONENT_IDENTITY_LOOKUP` | `COMPONENT_IDENTITY` | `GAP_COMPONENT_IDENTITY` | `COMPONENT_IDENTITY_EXPLICITLY_ESTABLISHED` | R31.12 / R31.12 |
| 6 | Action `VERIFY_SCOPE` | `SCOPE_EVIDENCE_REVIEW` | `SCOPE` | `GAP_SCOPE` | `EVIDENCE_SCOPE_EXPLICITLY_ESTABLISHED` | R31.12 / R31.12 |
| 7 | Action `VERIFY_PATH` | `PATH_EVIDENCE_REVIEW` | `PATH` | `GAP_PATH` | `PATH_RELEVANCE_EXPLICITLY_ESTABLISHED` | R31.12 / R31.12 |
| 8 | Action `VERIFY_PARAMETER` | `PARAMETER_EVIDENCE_REVIEW` | `PARAMETER` | `GAP_PARAMETER` | `PARAMETER_RELEVANCE_EXPLICITLY_ESTABLISHED` | R31.12 / R31.12 |
| 9 | Action `COLLECT_HTTP_EVIDENCE` | `HTTP_BEHAVIOR_REVIEW` | `HTTP_BEHAVIOR` | `GAP_HTTP` | `RELEVANT_HTTP_BEHAVIOR_EVIDENCE_ESTABLISHED` | R31.12 / R31.12 |
| 10 | Action `COLLECT_TECHNOLOGY_EVIDENCE` | `TECHNOLOGY_EVIDENCE_REVIEW` | `TECHNOLOGY` | `GAP_TECHNOLOGY` | `TECHNOLOGY_RELATIONSHIP_EXPLICITLY_ESTABLISHED` | R31.12 / R31.12 |
| 11 | Action `MANUAL_REVIEW` | `MANUAL_RESEARCH` | `EXISTING_EVIDENCE` | `GAP_NONE` | `HUMAN_RESEARCH_COMPLETED` | R31.12 / R31.12 |
| 12 | Missing/blank R31.12 action | `NONE` | `NONE` | `GAP_NONE` | `REQUIRES_VALID_ACTION_PLAN` | LOW / UNKNOWN |
| 13 | Terminal action `RESOLVE_BLOCKERS` | `NONE` | `NONE` | `GAP_NONE` | `BLOCKERS_RESOLVED_BEFORE_RESEARCH` | HIGH / UNKNOWN |
| 14 | Terminal action `DEFER` | `NONE` | `NONE` | `GAP_NONE` | `REACTIVATE_ONLY_IF_PRIORITY_CHANGES` | HIGH / UNKNOWN |
| 15 | Unknown action | `NONE` | `NONE` | `GAP_NONE` | `REQUIRES_VALID_ACTION_PLAN` | LOW / UNKNOWN |
| 16 | Action/gap mismatch | `NONE` | `NONE` | `GAP_NONE` | `REQUIRES_VALID_ACTION_PLAN` | LOW / UNKNOWN |

Confidence/effort for rows 4–11 are consumed from the validated R31.12
`confidence`/`estimated_effort` when they are inside the closed vocabularies
(so a single-gap R31.12 `HIGH` and a multiple-gap `MEDIUM` are preserved);
otherwise deterministic per-method fallbacks are used. Rows 1–3 and 12–16 are
fixed and never consume upstream confidence/effort.

## 7. Conflict Handling

- **Action vs gap.** Every known non-terminal action expects exactly one gap
  (R31.12 `_GAP_ACTION` pairing): `VERIFY_VERSION`↔`GAP_VERSION`,
  `VERIFY_COMPONENT_IDENTITY`↔`GAP_COMPONENT_IDENTITY`,
  `VERIFY_SCOPE`↔`GAP_SCOPE`, `VERIFY_PATH`↔`GAP_PATH`,
  `VERIFY_PARAMETER`↔`GAP_PARAMETER`,
  `COLLECT_HTTP_EVIDENCE`↔`GAP_HTTP`,
  `COLLECT_TECHNOLOGY_EVIDENCE`↔`GAP_TECHNOLOGY`,
  `VERIFY_EXISTING_EVIDENCE`/`MANUAL_REVIEW`↔`GAP_NONE`.
  A present-but-different `evidence_gap` yields the defensive `NONE` plan with
  `ACTION_PLAN_CONFLICT` (confidence LOW, effort UNKNOWN). The inconsistent
  upstream gap and the expected gap are both excluded from `reason_codes`; no
  reinterpretation occurs.
- **Absent gap field.** An absent/empty `evidence_gap` contains no
  contradicted upstream selection, so the action's deterministic gap pair is
  used (still action-authoritative, never independently detected).
- **Terminal action precedence.** An R31.12 terminal action wins over all
  other fields even when the R31.11 state is not terminal.
- **Unknown/blank action.** `UNKNOWN_ACTION` / `ACTION_PLAN_MISSING`; no
  acquisition is guessed.

## 8. Terminal Handling

- R31.11 `BLOCKED` or R31.10 `blocked=True` → `NONE`,
  `BLOCKERS_RESOLVED_BEFORE_RESEARCH`, `SOURCE_BLOCKED`; this fires before the
  R31.12 plan is read, so forged gap plans cannot override blockers.
- R31.11 `LOW_VALUE_DEFERRED` → `NONE`,
  `REACTIVATE_ONLY_IF_PRIORITY_CHANGES`, `SOURCE_DEFERRED`; same precedence.
- R31.12 `RESOLVE_BLOCKERS` and `DEFER` are terminal for planning and map to
  the same two terminal plans regardless of the R31.11 state.
- `evidence_target = NONE`, `evidence_gap = GAP_NONE`,
  `acquisition_rank = 9` on every terminal plan.

## 9. Privacy / Bounds Behavior

- The planner keeps its own `_safe_text` (same policy as R31.10–R31.12):
  control characters collapsed, URL userinfo redacted, bearer tokens
  redacted, secret-like `key=value` / `key: value` pairs redacted, values
  bounded to 160 chars. It is applied to all copied upstream fields
  (`source_action`, `source_actionability`, `source_priority`) and to every
  string item in `acquisition_order_key`.
- R31.12 gap lines/bodies are never copied: only the closed gap constant is
  stored in `evidence_gap`/`reason_codes`; `reason` and
  `completion_condition` are static project-authored labels.
- Bounds: `MAX_REASON_CODES = 8`, `MAX_ORDER_KEY = 16`, `MAX_VALUE_LEN = 160`;
  `source_hunt_score` is a coerced bounded integer; reason codes are
  de-duplicated and capped.
- Output keys (stable order): `rule_version`, `acquisition_method`,
  `acquisition_rank`, `evidence_target`, `evidence_gap`,
  `completion_condition`, `reason_codes`, `reason`, `source_action`,
  `source_actionability`, `source_priority`, `source_hunt_score`,
  `confidence`, `estimated_effort`, `acquisition_order_key`, `research_only`.
- `research_only` is always `True` (asserted for every branch).

## 10. Ordering Behavior

`acquisition_order_key` is a stable, JSON-serializable list for ascending
sort:

```
[acquisition_rank, ...R31.12 action_order_key]
```

The R31.12 `action_order_key` is preserved exactly, sanitised and bounded to
16 items; an absent R31.12 key yields `[acquisition_rank]`. No randomness, no
timestamps, no hash-based ordering and no external state. Identical inputs
always produce identical keys and byte-identical repeated output.

## 11. Exact Tests and Results

```bash
./venv/bin/python -m unittest tests.test_evidence_acquisition_planner -v
./venv/bin/python -m unittest tests.test_evidence_acquisition_planner \
    tests.test_hunt_action_planner tests.test_hunt_actionability \
    tests.test_hunt_priority tests.test_evidence_quality \
    tests.test_path_parameter_relevance tests.test_version_normalization \
    tests.test_component_evidence_provenance tests.test_component_identity \
    tests.test_component_inference tests.test_component_plugin_wiring \
    tests.test_observed_inventory tests.test_asset_cve_matching \
    tests.test_version_component_association tests.test_hunt_queue -q
./venv/bin/python -m unittest discover -s tests -t . -q
./venv/bin/python -m py_compile ai/knowledge/evidence_acquisition_planner.py \
    backend/asset_cve_matching.py tests/test_evidence_acquisition_planner.py
git diff --check
```

Results:

```
tests.test_evidence_acquisition_planner            Ran 60 tests   OK  (new)
combined R31.10-R31.13 + R29/R30/R31 regression    Ran 708 tests
    3 failures — pre-existing R29 money-score corpus drift (expected 53 vs
    current 50) in tests.test_hunt_queue: TestCli.test_human_output,
    TestBackend.test_money_score_unchanged, TestBackend.test_real_corpus
complete project suite (discover tests)            Ran 2290 tests
    37 failures + 3 errors — failure/error-name set byte-identical to the
    pre-change baseline (40 sorted lines, diff clean); no new failure
py_compile                                         OK
git diff --check                                   clean
```

Required coverage mapping (all 34 prompt cases):

| # | Required case | Test(s) |
|---|---|---|
| 1 | BLOCKED -> NONE | `TestTerminalActionability.test_1_blocked_maps_to_none` |
| 2 | LOW_VALUE_DEFERRED -> NONE | `TestTerminalActionability.test_2_low_value_deferred_maps_to_none` |
| 3 | IMMEDIATE -> EXISTING_EVIDENCE_REVIEW | `TestDeterministicMapping.test_3_immediate_maps_to_existing_evidence_review` |
| 4 | VERIFY_VERSION -> VERSION_LOOKUP | `...test_4_verify_version_maps_to_version_lookup` |
| 5 | VERIFY_COMPONENT_IDENTITY -> COMPONENT_IDENTITY_LOOKUP | `...test_5_verify_component_identity_maps_to_lookup`, `...test_5_plugin_gap_still_component_identity` |
| 6 | VERIFY_SCOPE -> SCOPE_EVIDENCE_REVIEW | `...test_6_verify_scope_maps_to_scope_review` |
| 7 | VERIFY_PATH -> PATH_EVIDENCE_REVIEW | `...test_7_verify_path_maps_to_path_review` |
| 8 | VERIFY_PARAMETER -> PARAMETER_EVIDENCE_REVIEW | `...test_8_verify_parameter_maps_to_parameter_review` |
| 9 | COLLECT_HTTP_EVIDENCE -> HTTP_BEHAVIOR_REVIEW | `...test_9_collect_http_maps_to_http_review` |
| 10 | COLLECT_TECHNOLOGY_EVIDENCE -> TECHNOLOGY_EVIDENCE_REVIEW | `...test_10_collect_technology_maps_to_technology_review` |
| 11 | MANUAL_REVIEW -> MANUAL_RESEARCH | `...test_11_manual_review_maps_to_manual_research`, `...test_11_supporting_context_gap_still_maps_by_action` |
| 12 | missing action plan -> NONE | `TestMalformedPlans.test_12_missing_plan_maps_to_none`, `...test_12_missing_plan_with_immediate_state_is_none` |
| 13 | unknown action -> NONE | `...test_13_unknown_action_maps_to_none`, `...test_13_blank_action_maps_to_none` |
| 14 | action/gap mismatch -> defensive conflict | `...test_14_action_gap_mismatch_is_defensive_conflict`, `...test_14_mismatch_is_never_reinterpreted`, `...test_14_manual_review_with_gap_is_conflict`, `...test_14_missing_gap_field_uses_action_pair` |
| 15 | terminal blocker overrides all gaps | `TestTerminalPrecedence.test_15_blocker_overrides_every_gap`, `...test_15_blocked_state_overrides_every_gap` |
| 16 | deferred overrides all gaps | `...test_16_deferred_overrides_every_gap`, `...test_16_defer_action_is_terminal_for_planning`, `...test_16_resolve_blockers_action_is_terminal_for_planning` |
| 17 | R31.12 gap never independently recomputed | `TestGapAuthority.test_17_r3112_selected_gap_is_not_recomputed`, `...test_17_technology_hint_never_overrides_r3112`, `...test_17_module_never_calls_upstream_engines` |
| 18 | stable repeated output | `TestDeterminismAndOrdering.test_18_repeated_output_is_byte_identical`, `...test_18_repeated_call_returns_equal_dict` |
| 19 | stable acquisition_order_key | `...test_19_acquisition_order_key_starts_with_rank`, `...test_19_acquisition_order_key_preserves_r3112_order`, `...test_19_stable_sorting_between_candidates` |
| 20 | no mutation of hunt_priority | `TestNoMutation.test_20_no_mutation_of_hunt_priority` |
| 21 | no mutation of hunt_actionability | `TestNoMutation.test_21_no_mutation_of_hunt_actionability` |
| 22 | no mutation of hunt_action_plan | `TestNoMutation.test_22_no_mutation_of_hunt_action_plan` |
| 23 | R31.10 regression | `TestR3110Regression` (2 tests: P0/100, P1/60, P2/48, P3/28, blocked DEFER/0; non-mutation + recompute equality) |
| 24 | R31.11 regression | `TestR3111Regression` (all five states, non-mutation, recompute equality) |
| 25 | R31.12 regression | `TestR3112Regression` (rule version, five action snapshots, non-mutation, source-field equality) |
| 26 | R29 regression | `TestR29Regression` (queue snapshot equality; no new field; `r29-1`) |
| 27 | Money Score unchanged | `TestBackendIntegration.test_backend_money_score_unchanged` |
| 28 | privacy/redaction | `TestPrivacyAndBounds.test_28_privacy_no_secrets_in_output`, `...test_28_privacy_unknown_action_is_redacted`, `...test_28_privacy_secret_source_priority_is_redacted` |
| 29 | bounded output | `...test_29_bounded_output` |
| 30 | JSON serializability | `...test_30_json_serializable` |
| 31 | research_only always true | `...test_31_research_only_always_true` |
| 32 | no operational attack content | `...test_32_no_operational_attack_content` |
| 33 | exact rule version | `...test_33_exact_rule_version` |
| 34 | closed vocabulary enforcement | `...test_34_closed_vocabulary_enforcement`, `...test_34_reason_code_vocabulary_is_closed`, `...test_34_gap_vocabulary_not_duplicated` |

Backend integration tests are hermetic (mocked inventory/contexts, no live
Mongo): additive fields/rule versions; the P0 strong fixture plans
`EXISTING_EVIDENCE_REVIEW` while `hunt_priority` stays P0/96 and
`hunt_actionability` stays `IMMEDIATE_VERIFICATION`; the path-only fixture
plans `NONE`/`SOURCE_BLOCKED`; source fields mirror R31.10-R31.12; the
acquisition order key preserves R31.12; Money Score canary passes.

## 12. Baseline Regression Comparison

- A pre-change baseline was captured before any R31.13 file existed:
  `unittest discover` ran **2230 tests / 37 failures / 3 errors**. After the
  change the suite ran **2290 tests / 37 failures / 3 errors** (the +60 are
  the new R31.13 tests). The sorted `FAIL:`/`ERROR:` line sets of the two runs
  are byte-identical (`diff` clean, 40 lines each): **no new failure or error
  is attributable to R31.13**.
- The 3 R29 `tests.test_hunt_queue` money-score failures (53 vs 50) and the
  remaining 34 failures + 3 errors are pre-existing corpus/Mongo-dependent
  failures, unchanged from the R31.10/R31.11/R31.12 baselines.
- R31.10 exact snapshots (P0/100, P1/60, P2/48, P3/28, blocked DEFER/0),
  R31.11 states (`IMMEDIATE_VERIFICATION`, `STRONG_MANUAL_REVIEW`,
  `SUPPORTING_CONTEXT`, `LOW_VALUE_DEFERRED`, `BLOCKED`), R31.12 rule version
  and all five sampled actions, the R29 queue snapshot (`r29-1`) and the
  Money Score canary are asserted unchanged.
- `hunt_priority`, `hunt_actionability` and `hunt_action_plan` input dicts are
  deep-copy equal after planning.

## 13. Performance

```
1 candidate     ->  0.04 ms  (37.5 us/candidate, fixed overhead)
100 candidates  ->  1.96 ms  (19.6 us/candidate)
1000 candidates -> 21.50 ms  (21.5 us/candidate)
```

Cost is O(action/gap signals + bounded copies); no corpus, URL, endpoint,
subdomain, HTTP or Mongo access occurs at this layer. The module is pure and
stateless.

## 14. Limitations / Deferred Work

- **Metadata inspection note.** The codebase-memory index generation predates
  this task's new files; `check_index_coverage` reported no recorded issue for
  every cited existing path and the new files were verified by direct source
  read and tests. No parse/coverage limitation affects the claims above.
- The three scalar hints (`evidence_provenance`, `support_scope`,
  `strongest_match_type`) are accepted for pipeline parity only; by design
  they cannot alter the plan because R31.12 is the only gap selector. If a
  future stage needs hint-level validation, that must be designed explicitly
  rather than added silently.
- The plan is exposed on the Asset<->CVE candidate summary
  (`evidence_acquisition_plan`, `evidence_acquisition_plan_rule_version`).
  Wiring it into the R29 queue schema/projection or UI is deliberately
  deferred because R29 must not be modified by this stage.
- `MANUAL_RESEARCH` is the fallback when R31.12 selects `MANUAL_REVIEW` (no
  narrower explicit gap). It is a planning label only; no human workflow,
  assignment or notification is created here.
- Confidence/effort for gap-targeted acquisitions are consumed from R31.12
  when valid (preserving its single-gap `HIGH` vs multiple-gap `MEDIUM`
  distinction) with deterministic per-method fallbacks otherwise.
- The acquisition plan is advisory only and is never executed by this code.
  No HTTP request, browser action, Nuclei run, crawl, fuzzing, scan,
  exploitation, LLM call, Mongo access or target interaction exists anywhere
  in the new module, and none is scheduled by it.
- No real-corpus/Mongo run was added; all tests are hermetic and offline.

## 15. Git Scope

```
$ git status --short
 M backend/asset_cve_matching.py
 D utils.zip
?? agent-reports/stage-r31-5-planning-audit.md
?? ai/knowledge/evidence_acquisition_planner.py
?? tests/test_evidence_acquisition_planner.py
?? watch.zip

$ git diff --stat          # tracked changes only
 backend/asset_cve_matching.py | 23 +++++++++++++++++++++++
 utils.zip                     | Bin 3104837 -> 0 bytes
```

Intentionally changed by R31.13: `ai/knowledge/evidence_acquisition_planner.py`
(new), `tests/test_evidence_acquisition_planner.py` (new),
`backend/asset_cve_matching.py` (additive, +23/-0), and this report. Unrelated
pre-existing changes (`D utils.zip`, `?? watch.zip`,
`?? agent-reports/stage-r31-5-planning-audit.md`) were left untouched. No
commit, no push, no VM/deployment action.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: R31.13
- Role: coding agent
