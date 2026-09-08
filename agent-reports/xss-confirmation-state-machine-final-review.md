# XSS Confirmation State Machine — Oracle Integration FINAL Security + Diff Review

**Review type:** READ-ONLY. No source file was modified; only this report was created.
**Repository:** `/opt/watch` · Branch `main` (HEAD `a3ad8c1`)
**Date:** 2026-09-02
**Plan reviewed:** `agent-reports/xss-confirmation-state-machine-plan.md`
**Implementation claim:** `agent-reports/xss-confirmation-state-machine-implementation.md`

---

## 1. Executive Verdict

**STATUS: READY WITH WARNINGS**

The oracle-integration implementation is **safe, correctly bound, and faithful
to the approved state-machine design**. Every security check required by the
plan is implemented in `_oracle_execution_proof`, runs BEFORE any acceptance
path, and is exercised by tests that go through the production `verify()`
path (not just helper functions). The mandated demotion of the old
browser-only chain+token CONFIRMED path to POTENTIAL (SINK_REACHED) is
present and verified. No false-CONFIRMED path, no cross-attempt/cross-run
oracle acceptance, and no anti-harvest boundary violation was found within
the approved threat model.

The non-blocking warnings are functional limitations that the approved design
explicitly permits: (a) real planner oracle payloads are ~400–405 chars, so
E3 is always disabled for them (the plan estimated ~230–260 and said "often
disabled"); (b) the implementation report lists `xss_verification.py` in both
its changed and pre-existing file lists, which the actual git diff resolves
(the file carries both pre-existing oracle fields and the new
`oracle_identity` field); (c) the usual documented limitations (two browser
runs per candidate, unknown-context capped at POTENTIAL, per-process
run_salt, pre-existing crawl/config test failures).

Commit is **approved with the documented warnings below**.

---

## 2. Git / Diff Integrity Review

`git status --short` and `git diff --stat` inspected. `git diff --check`: clean.

### Files attributable to THIS implementation (state-machine integration)
| File | Change | Verified |
|---|---|---|
| `ai/schemas/xss_verification.py` | `VerificationAttempt.oracle_identity` added | Yes (diff) |
| `ai/schemas/xss_finding.py` | `confirmation_state`, `oracle_channels` added | Yes (diff) |
| `ai/verification/verifier.py` | State machine, `_classify_oracle`, `_oracle_execution_proof`, demotion, factory | Yes (source) |
| `ai/verification/xss_pipeline.py` | `run_salt` keyword passthrough | Yes (diff) |
| `watch_xss_verify.py` | `import secrets` + `secrets.token_hex(32)` per run | Yes (diff) |
| `ai/test_xss_verification.py` | 125 tests (41 oracle-matrix + demotion updates) | Yes (ran) |
| `ai/test_xss_pipeline.py` | +1 run_salt forward/default test | Yes (ran) |
| `ai/test_browser_executor.py` | verifier-integration test updated to demotion assertion | Yes (ran) |
| `ai/test_xss_oracle.py` (untracked) | +7 `OracleAttemptFactoryTests` | Yes (ran) |

### Pre-existing changes (untouched by this task, in the SAME working tree)
`AGENTS.md`, `README-watch-updated.md` (D), `ai/test_http_executor.py`,
`ai/test_watch_param_discovery.py`, `ai/test_xss_case_builder.py`,
`ai/verification/browser_executor.py` (oracle infrastructure + boundary fix),
`ai/verification/http_executor.py`, `crawl/watch_param_discovery.py`,
`database/*`, `tests/*`, `wordlists/`, and untracked
`ai/verification/oracle.py` + `agent-reports/*`.

### Report inconsistency resolved
The implementation report lists `ai/schemas/xss_verification.py` in both
"Files Changed" and "Pre-existing changes". The ACTUAL git diff shows BOTH
---

## 3. Oracle Payload Length Investigation (Part 2)

Measured with the production planner:

- `script_block` / `generic`: payload = **400 chars**; URL-encoded = 616.
- `html_body` / `html_attribute`: payload = **405 chars**; URL-encoded = 623.
- `url`: unsupported (payload 0).

### Why ~400 chars
`JS_W_SOURCE` (the inline double-round FNV-1a transform, bit-identical to
Python) is 311 chars, including the embedded 32-char seed, two `for` loops,
the hex-padding literal `'00000000'`, and `Math.imul(...)>>>0` terms. Plus
E1 action `alert(d);` (9), E2 action
`new Image().src='/.watch-oracle/'+d;` (36), and the HTML skeleton.

### Is it intentional / compatible with the approved design?
**Yes.** `xss-oracle-design.md` §10 explicitly states: "payload = delivery
skeleton + inline snippet …; Bounded length; **if > 240 chars, E3 disabled
for the attempt**." The E3-240 rule is the approved rule, and 400 > 240
triggers it. The state-machine plan's §16 estimate ("~230–260 chars; E3 is
often disabled") was **inaccurate** — it never measured the real
`JS_W_SOURCE`. This is not accidental payload inflation; it is the compact
transform written in the (pre-existing) oracle-implementation task.

### Impact
- **URL length:** 616-623 encoded — well within typical 2k-8k server limits;
  trivial for most targets. Conservative FN only on very restrictive servers.
- **Browser execution:** fine (self-contained inline script).
- **Query injection:** fine (URL-encoded single param value).
- **E1/E2:** unaffected — both fire on real 400-char payloads.
- **Anti-harvest:** unaffected (D never in payload).
- **Reflected confirmation:** unaffected (S1 uses the paired HTTP attempt's
  LLM-pattern reflection; S4 uses the oracle attempt's execution).
- **E3:** always disabled for real planner payloads. E3 is now **inert in
  production**; it is only exercised via hand-built short-payload tests.

### Classification: **WARNING** (functional limitation)
Not a security issue. The E3-disable rule is the approved one; never weakened.
Commit is not blocked; the plan's expectation that E3 is "often" usable is
not realized — documented and tested (`test_E3_payload_over_240_disabled`).

---

## 4. `_oracle_execution_proof` Review (Part 3)

File/function: `ai/verification/verifier.py:_oracle_execution_proof`.

| Expected check | Status | Evidence |
|---|---|---|
| 1. Evidence identity binding (`attempt_id`, `request_url==endpoint`, `request_method`) | **PASS** | lines 907-912; also `_enforce_evidence_binding` downgrades to ERROR on mismatch |
| 2. Oracle pair validation (`validate_oracle_pair`) | **PASS** | lines 915-922; shape, D==W(S), D!=S |
| 3. Run freshness (`oracle_seed(run_salt, oracle_identity, phase)==seed`) | **PASS** | lines 925-933 |
| 4. Candidate identity (`oracle_identity==candidate attempt_id`) | **PASS** | lines 936-942; `verify()` resolves candidate by logical_pair only for the registered oracle attempt |
| 5. Same-origin final URL + E2 event origin | **PASS** | lines 950-954 (`_origin_of(final)==origin(endpoint)`); E2 origin re-checked inside `evaluate_e2_network` |
| 6. Exact E1/E2/E3 predicates | **PASS** | lines 973-984 |
| 7. Anti-harvest using ONLY PreExecutionInput | **PASS** | lines 960-971 |
| 8. No post-execution evidence enters anti-harvest | **PASS** | PreExecutionInput only (payload/bound/intended/actual); TypeError guard in oracle.py; dom/console/network/storage never passed |

**Ordering:** all 8 checks execute in sequence and any failure returns
`False` immediately; the E1/E2/E3 predicates run LAST (step 7) and their
result is returned only after all security checks. `_classify_oracle` returns
`CONFIRMED` only after `_oracle_execution_proof` ok AND (for reflected) the
paired HTTP reflection check. No dangerous acceptance path precedes any
security check.
claims are true: the file contains the pre-existing oracle-infrastructure
fields (`DialogEvent`, `NetworkOracleEvent`, `EvalInvocation`, `oracle_seed`,
`oracle_value`, `oracle_version`, `dialog_events`, `oracle_network_events`,
`eval_invocations`, `intended_request_url`, `actual_request_url`) AND this
task's new `oracle_identity`. Not an implementation defect — a minor wording
ambiguity. Verified against `git diff -- ai/schemas/xss_verification.py`.

### Not modified (Part 14 scope check) — verified empty diffs
`ai/verification/composite_executor.py`, `ai/verification/xss_case_builder.py`,
---

## 5. E1 Security Review (Part 4)

`evaluate_e1_dialog` (oracle.py): `kind in {alert, confirm, prompt}` AND
`message == D` (full-string equality). The verifier passes only
`evidence.dialog_events` (executor-owned Playwright listener). Copy attacks
within the approved threat model (copying S, correlation token, query param,
URL, page content) cannot equal D — D is absent from all pre-execution
material (anti-harvest) and non-copy values cannot equal it (S is 32-hex, D
is 16-hex). A page can only reach D by computing W(S) — the explicitly
accepted A4 residual assumption, not a bug. D in console echo
(`dialog:alert:<D>`) does not affect E1 because E1 reads only dialog_events.
Tests: `test_seed_copied_not_e1`, `test_d_in_console_not_oracle`, and the
matrix E1-confirmed tests. No violations within the approved threat model.

---

## 6. E2 Security Review (Part 5)

`evaluate_e2_network` + executor `_record_oracle_request` channel. Verified:

- only `oracle_network_events` are considered (generic `network_requests`
  never passed to E2; `test_d_in_generic_network_not_e2`).
- non-navigation (`is_navigation` guard + executor excludes navigation).
- same-origin enforced vs `attempt.endpoint` origin tuple.
- exact decoded pathname `/.watch-oracle/<D>`; exactly one `unquote`.
- query never participates in matching (path-only comparison).
- `/.watch-oracle/<D>/foo` rejected (`path != expected`), tested via verifier.
- `/foo/.watch-oracle/<D>` rejected, tested.
- navigation to oracle path rejected, tested.
- cross-origin rejected, tested.
- double-encoded rejected (single decode renders `%DD`, not D), tested.
- D in generic telemetry is not E2, tested.
- The boundary fix (pre-this-task) `_is_oracle_request_url` excludes oracle
  requests from the generic sink in BOTH `_on_request_finished` and
  `_on_response` — verified in source.

**PASS** — E2 is exact, structurally isolated, and cannot be accepted through
ordinary request material.

---

## 7. E3 Security Review (Part 6)

`evaluate_e3_eval`: operator in `{"eval", "setTimeout:string"}` AND recorded
value == full payload AND `len(payload) <= 240`. The verifier applies it to
`attempt.payload` (recomputed — `e3_enabled` from the planner is never
trusted). No prefix/truncated comparison. >240 → False (disabled) even for an
exact-looking record. E3 alone → `JAVASCRIPT_EXECUTION` (never
`OBSERVABLE_EFFECT` — that requires E2 in channels). False positives: none —
exact equality of the full payload string via an executor-owned
instrumentation hook; a benign page cannot produce the payload string as an
eval argument without executing it. Tests: boundary, prefix-reject, over-240,
exact, and channel/state assertions.

**PASS** — E3 cannot create a false positive under the approved model and
alone never establishes OBSERVABLE_EFFECT.

---

## 8. Anti-harvest Review (Part 7)

Verifier constructs `PreExecutionInput(payload, bound_input,
intended_request_url, actual_request_url)` only; remaining fields
(`request_body`, `response_snippet`, `referrer_derived`,
`pre_execution_inputs`) default empty. The scanner checks D absent in each
field plus `seed_count_in_payload==1`. Post-execution channels
(dialog_events, oracle_network_events, eval_invocations, dom_changes,
console_messages, network_requests, storage_writes) are NEVER passed. The
TypeError guard in `anti_harvest_violations` makes accidental post-execution
scanning structurally impossible. E2's own oracle request cannot trigger a
violation (never in the pre-input; only in oracle_network_events, validated
by `evaluate_e2_network`; excluded from the generic sink). E1's dialog echo
into console does not self-contradict (console unscanned). Tests at unit and
verifier level: `test_anti_harvest_holds_on_oracle_attempt`,
`test_d_in_payload_rejected`, `test_d_in_intended_url_rejected`,
`test_d_in_actual_url_rejected` — all confirmed.

**PASS.**
---

## 9. Reflected XSS State Machine Review (Part 8)

- **CONFIRMED = meaningful HTTP reflection (S1) + valid oracle execution
  (S4).** `_classify_oracle` for non-DOM flavours REQUIRES the paired HTTP
  attempt/evidence satisfying `_http_path_confirms` (lines 846-855).
- **Reflection alone cannot confirm:** HTTP path returns POTENTIAL
  (REFLECTION) only (line 740). Tested via existing + new fixtures.
- **Browser chain/token alone cannot confirm:** `_classify_browser` returns
  at most POTENTIAL (SINK_REACHED) (line 806). Tested
  (`test_reflection_plus_correlated_browser_yields_potential`,
  `test_positive_2_reflected_browser_potential`).
- **Same logical_pair_id:** oracle attempt preserves the candidate's
  `logical_pair_id`; pairing maps are keyed by it. Tested
  (`test_wrong_logical_pair_rejected`).
- **`oracle_identity == candidate browser attempt_id`:** enforced (check 4;
  `test_wrong_oracle_identity_rejected`).
- **Evidence cannot be borrowed:** per-attempt evidence binding +
  registered-oracle-only eligibility (identity check on the dict value) +
  candidate binding. `test_duplicate_oracle_attempt_per_pair_fails_closed`.
- **Pairing never depends on list position:** maps by `logical_pair_id`;
  `http_evidence_by_pair` prefers the confirming attempt as a safety net.
- **Missing HTTP pair prevents reflected confirmation:**
  `test_missing_http_pair_not_confirmed`.
- **Redirect handling:** `intended_request_url` (pre-redirect) and
  `actual_request_url` (final) are distinct; the verifier does NOT require
  intended == actual; cross-origin final URL rejects oracle proof
  (`test_cross_origin_final_url_rejected`).

**PASS.**

---

## 10. DOM XSS State Machine Review (Part 9)

- **Valid E1/E2/E3 oracle proof = CONFIRMED without source_to_sink:**
  `_classify_oracle` for DOM/mutation skips the HTTP requirement; proof is
  S4-only. Tested (`test_E2_without_chain_confirmed`).
- **source + sink + token without oracle = POTENTIAL (SINK_REACHED):**
  `test_browser_only_potential`, `test_benign_echo_page_not_confirmed`.
- **Old browser-only CONFIRMED genuinely gone:** grep of all CONFIRMED
  returns in `verifier.py` shows exactly two sites: line 857 (oracle path)
  and line 1139 (legacy stored path, explicitly out of scope). The old
  `_classify_browser` CONFIRMED is replaced by POTENTIAL+SINK_REACHED.
  `test_dom_complete_source_to_sink_yields_potential`,
  `test_positive_3_dom_chain_potential`, `test_dom_browser_only_yields_no
  confirmed`, `test_mutation_browser_only_yields_no_confirmed`, and the
  browser-executor integration test confirm.
- Benign echo/telemetry/storage/beacon/referrer/DOM-copy fixtures produce no
  CONFIRMED in the new matrix.

**PASS** — no residual branch can produce browser-only CONFIRMED except the
out-of-scope stored path, which is plan-accepted.

---

## 11. run_salt / Replay Review (Part 11)

- Fresh `run_salt = secrets.token_hex(32)` generated once per
  `build_production_pipeline` call in `watch_xss_verify.py`.
- `run_salt` exists only in verifier memory: NOT persisted on attempts,
  evidence, or findings; NOT passed to the LLM; NOT exposed as an oracle
  value (D is `W(sha256(run_salt‖identity‖phase)[:16])`, not the salt).
- Stale seed from another run fails: check 3 re-derives under the verifier's
  current salt; different salt ⇒ different seed ⇒ reject
  (`test_stale_run_salt_rejected`).
- Same attempt from another run cannot reuse old D: seed differs ⇒ D differs
  ⇒ predicates fail.
- `oracle_identity` is the seed input (not the oracle attempt's own id),
  breaking the circular dependency.
- `run_salt=None`: oracle integration disabled (no oracle attempts planned),
  `_oracle_execution_proof` fail-closed returns False, existing behavior
  preserved except the mandated browser demotion. Tested
  (`test_plan_builder_unsalted_has_no_oracle_attempt`,
  `XSSVerifierOraclePlanTests`).

**PASS.**

---

## 12. Oracle Attempt Factory Review (Part 12)

`build_oracle_verification_attempt` (verifier module):
- **No circular dependency:** seed = `oracle_seed(run_salt,
  candidate.attempt_id, "oracle")` → payload = planner payload → oracle
  attempt_id derived from that payload. Direction: candidate identity →
  seed → payload → oracle attempt_id. There is no seed-from-oracle-attempt
  edge. Verified by source + `OracleAttemptFactoryTests`.
- `oracle_identity` = candidate `attempt_id`; `logical_pair_id` preserved;
  `phase = "oracle"`; `oracle_seed`, `oracle_value`, `oracle_version` set
  from planner; decipher(payload) distinct attempt_id; planner owns
  S/D/W/snippet/payload; LLM `delivery_pattern` recorded for attribution
  only and cannot alter the oracle. Unsupported context ⇒ `None`
  (`test_unsupported_context_yields_no_oracle_attempt`).
- `payload_origin="model_generated"`, empty knowledge/source ids — no false
  knowledge attribution.

**PASS.**

---

## 13. Finding Semantics Review (Part 10)

Verified in source and tests:
- Reflection only: `POTENTIAL` + `confirmation_state="REFLECTION"` +
  `oracle_channels=[]`.
- Sink reached without oracle: `POTENTIAL` + `"SINK_REACHED"` + `[]`.
- E1: `CONFIRMED` + `"JAVASCRIPT_EXECUTION"` + `["E1"]`.
- E2: `CONFIRMED` + `"OBSERVABLE_EFFECT"` + `["E2"]`.
- E3: `CONFIRMED` + `"JAVASCRIPT_EXECUTION"` + `["E3"]`.
- Multiple channels: sorted channels; state = OBSERVABLE_EFFECT iff E2
  present; otherwise JAVASCRIPT_EXECUTION; deterministic; no severity
  inflation (`test_E1_plus_E2_channels`).
- `oracle_channels`/`confirmation_state` are set only in `_build_finding`
  from values derived by `_oracle_execution_proof` (verifier-only). The LLM
  and executor have no input path to these fields; schema defaults keep
  legacy producers working.

**PASS.**
---

## 14. Test Quality / Results (Part 13)

Tests were inspected (not counted only) and **exercise the production
`XSSVerifier.verify()` path** via `_FakeExecutor`/`_run_oracle_scenario`
producing structured `VerificationEvidence`, plus real `BrowserEvidenceExecutor`
in `test_browser_executor.py`. Critical properties and their tests:

- E1 exact/kind: `E1DialogPredicateTests` + verifier matrix `test_E1_confirmed`.
- E2 exact/one-decode/query-ignored/non-nav/same-origin/prefix/suffix:
  `E2NetworkPredicateTests` + verifier `XSSVerifierOracleSecurityTests`
  (`test_E2_navigation_rejected`, `test_E2_cross_origin_rejected`,
  `test_E2_path_suffix_rejected`, `test_E2_double_encoded_rejected`).
- E3 exact/<=240/no-prefix: `E3EvalPredicateTests` + verifier
  (`test_E3_payload_over_240_disabled`, `test_E3_prefix_match_rejected`).
- Anti-harvest (D pre-harvest rejected; E2 not mis-scanned):
  `test_anti_harvest_holds_on_oracle_attempt`, `test_d_in_payload_rejected`,
  `test_d_in_intended_url_rejected`, `test_d_in_actual_url_rejected`,
  `test_d_in_generic_network_not_e2`.
- Run-salt replay: `RunSaltReplayTests` + `test_stale_run_salt_rejected`.
- Cross-attempt evidence: evidence binding tests;
  `test_wrong_oracle_identity_rejected`; `test_duplicate_oracle_attempt_per_pair_fails_closed`.
- Logical-pair mismatch: `test_wrong_logical_pair_rejected`.
- Reflected pairing: `test_reflected_paired_http_and_oracle_e2_yield_confirmed`,
  `test_missing_http_pair_not_confirmed`.
- DOM confirmation: `XSSVerifierOracleDOMatrixTests`.
- Old CONFIRMED demotion: `test_reflection_plus_correlated_browser_yields_
  potential`, `test_positive_2_reflected_browser_potential`,
  `test_dom_complete_source_to_sink_yields_potential`,
  `test_browser_evidence_with_chain_confirmed` (browser executor integration).
- Benign copies: `BenignSpoofRegressionTests` + verifier benign fixtures.

All pass (see §20). `python -m compileall -q ai`: OK.

---

## 15. Unintended Scope Review (Part 14)

No unrelated refactors or behavior changes outside XSS verification were
introduced by this task:
- Executors not re-touched (browser/http changes predate this task).
- `oracle.py` not changed by this task (untracked; pre-existing).
- No researcher/LLM/knowledge modifications.
- Schema changes confined to the plan's MUST-ADD list
  (`oracle_identity`, `confirmation_state`, `oracle_channels`); no
  speculative fields added.
- No dependency changes; no formatting-only noise beyond the touched files.
- `AGENTS.md` change is the pre-existing agent-reports workflow doc from an
  earlier task.

---

## 16. Findings Ranked by Severity

1. **INFO / WARNING — E3 inert in production.** Real planner payloads are
   400–405 chars > 240; E3 never fires for production oracle attempts (only
   in tests via hand-built short payloads). Approved rule; E1/E2 unaffected;
   conservative (fewer confirmations), never a false positive.
2. **INFO — Plan payload-length estimate inaccurate** (~230–260 assumed;
   400–405 actual). The implementation report states ~405 accurately and
   tests assert it. No code change required.
3. **INFO — Report file-attribution wording.** `xss_verification.py` listed
   in both changed/pre-existing sets; resolved by git diff (both are true).
4. **INFO — Pre-existing test infra failures** (`test_watch_param_discovery`
   x8 flag test; `test_watch_xss_verify` config import). Unrelated to this
   task; present before it.

No security findings, no cross-attempt/cross-run violations, no false-CONFIRMED
path within the approved threat model.
---

## 17. Exact Files / Functions Involved

- `ai/verification/verifier.py` — `build_oracle_verification_attempt`,
  `XSSVerifier.__init__`, `verify`, `_build_plan_from_analysis`,
  `_classify`, `_classify_browser`, `_classify_oracle`,
  `_oracle_execution_proof`, `_http_path_confirms`, `_build_finding`,
  `ORACLE_ATTEMPT_PHASE`, `_origin_of`.
- `ai/schemas/xss_verification.py` — `VerificationAttempt.oracle_identity`.
- `ai/schemas/xss_finding.py` — `XSSFinding.confirmation_state`,
  `XSSFinding.oracle_channels`.
- `ai/verification/xss_pipeline.py` — `build_default_verifier(*, run_salt)`.
- `watch_xss_verify.py` — `build_production_pipeline` (`secrets.token_hex(32)`).
- Reused as-is: `ai/verification/oracle.py` (predicates, planner,
  `PreExecutionInput`, `anti_harvest_violations`);
  `ai/verification/browser_executor.py` (E1/E2/E3 evidence + sink boundary).

---

## 18. Commit Approval

**Approved, with the warnings in §16.** No blockers. Recommended
(non-blocking) follow-up: revisit oracle payload length if E3-on-real-payloads
is ever desired — explicitly optional and out of this plan's scope.

---

## 19. Remaining Warnings / Limitations

- E3 disabled for real planner payloads (functional; approved rule).
- `xss_type=unknown`/unsupported context → no oracle attempt → capped at
  POTENTIAL (systemic FN, plan-accepted).
- Stored XSS unchanged (legacy single-phase path, plan-accepted out of scope).
- Mutation shares DOM browser branch; no mutation redesign (plan-accepted).
- `run_salt` is per-process; a restart invalidates planned oracle attempts
  (plan-accepted single-run verify()).
- Two browser runs per candidate (cost; plan-accepted).
- `new Function` oracle hook still v1.1 (plan-accepted out of scope).
- W is a deterministic oracle, not a cryptographic PRF; Watch-aware
  adversarial page computing W(S) is the accepted A4 residual (not a bug).

---

## 20. Exact Test Commands / Results

Executed (all local, no network/target requests):

| Command | Result |
|---|---|
| `python -m unittest ai.test_xss_oracle` | 66 OK |
| `python -m unittest ai.test_xss_verification` | 125 OK |
| `python -m unittest ai.test_browser_executor` | 57 OK |
| `python -m unittest ai.test_xss_pipeline` | 12 OK |
| `python -m unittest ai.test_http_executor` | 58 OK |
| `python -m unittest ai.test_composite_executor` | 14 OK |
| `python -m unittest ai.test_xss_case_builder` | 47 OK |
| `python -m unittest ai.test_knowledge_store` | 15 OK |
| `python -m unittest ai.test_xss_researcher` | 12 OK |
| `python -m unittest ai.test_openrouter` | 26 OK |
| `python -m unittest ai.test_xss_llm_researcher` | 36 OK |
| `python -m compileall -q ai` | OK |
| `git diff --check` | OK |

Pre-existing, unrelated failures observed but NOT caused by this task:
1. `ai.test_watch_param_discovery` — 1 FAIL in `X8RunParserTests` (x8 flag
   parsing, crawl subsystem, pre-existing working-tree change).
2. `test_watch_xss_verify` / `ai.test_watch_param_discovery` under discovery —
   `from config import config` import shadowing by `ai/config.py`
   (pre-existing repo-structural issue).

`git status --short`, `git diff --stat`, and `git diff --check` were
inspected; nothing was modified by this review.
`ai/schemas/xss.py`, all `ai/researcher/*`, `ai/knowledge/*`, `ai/llm/*`.