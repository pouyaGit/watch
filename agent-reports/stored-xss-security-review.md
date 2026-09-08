# Stored XSS Security Review

## Verdict
READY

## Scope

READ-ONLY independent review (second pass) of the Stored XSS oracle-round
implementation after a small hardening patch addressing prior warnings
W1/W2/W3. Previous verdict: READY WITH WARNINGS (no false-CONFIRMED path;
warnings W1 MEDIUM-functional, W2/W3 LOW, W4–W6 INFO). This pass re-verified
the full CONFIRMED path, the three fixes, and regressions. Only
`ai/verification/verifier.py` and `ai/test_xss_stored_round.py` changed since
the prior review; no architecture, oracle, reflected/DOM, crawler, LLM,
database, or pipeline work was touched. Nothing was staged, committed, or
pushed.

## Files Reviewed

- `ai/verification/verifier.py` — `_submit_accepted` markers,
  `_stored_oracle_proof` step 5, `discover_stored_read_url` fallback
  (re-read in full with surrounding gates)
- `ai/test_xss_stored_round.py` — 5 new regression tests (read in full)
- Re-confirmed untouched: `ai/verification/oracle.py`,
  `composite_executor.py`, `xss_pipeline.py`, `watch_xss_verify.py`,
  `http_executor.py`, `browser_executor.py`, schemas (empty diff-stat)
- Reference: prior review conclusions re-validated against current source
  (2 CONFIRMED sites, legacy shim, gating, proof order all unchanged
  except the three fixes below)

## Production Call Graph

Unchanged: `watch_xss_verify.main → build_production_pipeline
(secrets.token_hex(32)) → build_default_verifier → XSSVerifier →
verify() → stored gated rounds`. The patch alters no composition; stored
rounds use the same fresh run salt (entrypoint salt test still passes).

## Stored CONFIRMED Path

Unchanged 12-gate chain (plan → SUBMIT → acceptance → discovery → READ →
binding → round → pair/fresh → origin/order/clean → harvest → E1/E2/E3 →
classifier → finding), with step 5 now strictly stronger (see Fix 2).
`_classify_stored_oracle` remains the sole stored verdict path;
`_classify_stored` still returns POTENTIAL unconditionally.

## Draft Identity / Seed Ownership Analysis

Unchanged since prior review (re-verified, no edits in this area):
draft canonical → candidate_id → S → D → O → final ids; oracle_identity =
draft id; verifier re-derives S/D locally. Q1 answer stands: NO, an
unrelated attempt cannot produce the same expected D (sha256/salt-bound;
per-retry seq suffix intact).

## Round Binding Analysis

Unchanged (round_id-only pairing, duplicate/incomplete fail closed,
single-use per run). Re-verified S1/S3/N6/N9/P5 still pass.

## Oracle Binding Analysis

Unchanged (S/D cross-leg equality, `validate_oracle_pair`, `W(S)==D`
recomputed, exact E1/E2/E3 vs own D). D still absent from payload/URL/body/
logs/round_id/LLM inputs/findings.

## Clean READ Analysis

Unchanged (executor bare navigation + discovery-time + post-READ checks).
W5 (SUBMIT-token omission in post-READ check) intentionally left as-is per
scope orders.

## READ Discovery Analysis

Changed only by Fix 3 (below). D1/D2/D3 order, cross-origin/downgrade/
unclean fail-closed (no fallback on present-but-unacceptable hint), and
D-bound verdict all re-verified intact — N17/S5/S5b still pass.

## Anti-Harvest Analysis

Unchanged (SUBMIT+READ `PreExecutionInput` only; TypeError guard; seed-count
+ D-absence). N14–N16 still pass.

## Pre-existing XSS Analysis

Unchanged: D_old (even with E1+E2 firing) cannot satisfy D_B predicates
(N3/S9 pass).

## Cross-Round Analysis

Unchanged: all mixes fail at binding/consistency/predicates (S1/S3/N6/P5
pass).

## Cross-Candidate Analysis

Unchanged (N9/S1 pass; LLM boundary intact — verdicts never read LLM output).

## Cross-Run Replay Analysis

Unchanged: freshness re-derived under live salt (N8/S2 pass).

## Legacy Path Analysis

Unchanged: `_classify_stored` POTENTIAL-only; new plans never emit
`phase="stored"` (N19 passes).

## Unsupported Workflow Analysis

Unchanged: unsupported context → zero attempts/SUBMITs (S14/F5);
unsupported shape → pre-transport ERROR (F4); auth/CSRF fail closed.

## Executor Trust Boundary

Unchanged: executors evidence-only, no verdict vocabulary; verifier sole
authority.

## LLM Trust Boundary

Unchanged: pattern/attribution strings only; stored attempts hardcode
`payload_origin="model_generated"`.

## E1 Analysis

Unchanged: exact kind + full-message equality on executor-owned
`dialog_events` only.

## E2 Analysis

Unchanged: non-navigation, exact origin, single-decode exact path,
query ignored by approved design.

## E3 Analysis

Unchanged: >240 disabled, exact full-value equality (P4 passes).

## Test Audit

New tests (all in `ai/test_xss_stored_round.py`, all through `verify()`):
- `test_csrf_field_name_is_not_failure` — SUBMIT body with `csrf_token` /
  `csrfmiddlewaretoken` fields + "CSRF protection enabled" text → accepted,
  signal ≠ `csrf_required`. Directly pins Fix 1 (fails pre-fix).
- `test_explicit_csrf_failure_wording_rejected` — "CSRF validation failed:
  missing csrf token" → `(False, "csrf_required")`. Pins explicit semantics.
- `test_explicit_csrf_failure_no_read_no_confirm` — same wording through
  `verify()` → 1 call (SUBMIT only), no CONFIRMED. Pins gating.
- `test_S5c_read_final_origin_must_match_endpoint_origin` — intended==final
  (evil origin) but endpoint is the case origin, E1(D) present, binding
  intact (asserts rebuilt==planned id, so only step 5 can reject). Would
  CONFIRM pre-fix; rejected post-fix. Non-vacuous by construction.
- `test_S5d_same_host_different_port_location_rejected` — same-host :8443
  Location → 1 call, no CONFIRMED, `read_location_unknown` audit note.
Pre-existing `test_csrf_marked_submit_fails_closed` ("invalid csrf token")
still passes (matches narrowed "invalid csrf" phrase). S5b (same-registrable
same-port hint) still passes — fallback not broken. Mocked-evidence tests
remain unit assurance for classifier logic; real-integration assurance still
rests on the localhost E2E (unchanged, passing).

## Real E2E Audit

Unchanged and passing (62-test run, 0 skips): real HTTP + real Playwright +
real planner payload through `verify()` → CONFIRMED; no evidence injection.

## Attack Matrix

Prior 22-row matrix re-verified (all PASS, no change), plus 3 new rows:

| Attack | Expected | Actual | Verdict |
|---|---|---|---|
| csrf_token field name in SUBMIT body | accepted, not csrf_required | accepted (new test) | PASS |
| "CSRF validation failed" body | csrf_required, no READ | 1 call, INCONCLUSIVE (new tests) | PASS |
| intended==final=evil, endpoint=case origin, E1(D) | NOT CONFIRMED | INCONCLUSIVE (S5c) | PASS |
| same-host different-port Location | no READ target | 1 call + audit note (S5d) | PASS |
| submit-only / reflection-only / old-D / wrong-D/S / cross-round / cross-candidate / cross-run / generic-channel D / token-everywhere / dirty URL / cross-origin / downgrade / duplicates / timestamps / unsupported / auth / E3>240 / legacy | fail closed | unchanged, all PASS | PASS |

## Findings

No CRITICAL, HIGH, or MEDIUM findings. W1/W2/W3 addressed:
- **W1 (was MEDIUM-functional) — ADDRESSED.** Bare `"csrf"` removed from
  `_SUBMIT_REJECT_BODY_MARKERS`; replaced with explicit failure phrases
  (`invalid csrf`, `csrf validation failed`, `csrf token invalid/mismatch/
  expired`, `missing csrf token`, `csrf_required`; existing token-failure
  phrases kept). Mapping to `csrf_required` preserved via the
  csrf/token-substring rule. Fail-closed behavior intact: genuine failures
  still block READ and can never CONFIRM (Rule 2a caps SUBMIT at POTENTIAL;
  proof requires READ execution). No broad new keywords added.
- **W2 (was LOW) — ADDRESSED.** `_stored_oracle_proof` step 5 now requires
  final==intended AND final==`read_attempt.endpoint` origin (parity with
  reflected check 5). No new cross-origin behavior; strictly tighter.
- **W3 (was LOW) — ADDRESSED.** Discovery fallback now requires the same
  effective port (scheme-defaulted) in addition to registrable-domain
  equality. Fast path, downgrade protection, and domain bound unchanged;
  strictly tighter, fail-closed.
- No new security issue introduced by the patch (all gates equal or
  stricter; no new CONFIRMED site — still exactly two; no semantic change
  to acceptance beyond marker narrowing, which only converts
  INCONCLUSIVE→proceed, never toward CONFIRMED without full proof).

## Warnings

- W4/W5/W6 (INFO) intentionally untouched per scope orders.
- Inherited INFO (unchanged): E3 inert on real ~400-char payloads; A4
  Watch-aware residual; per-process run_salt.

## Remaining Assurance Gaps

Prior gaps 1–3 stand (verify-level bad-shape gating test, multi-payload
production-builder test, structural serialization) — unchanged by this
patch, none blocking. New gap: none (each fix carries its regression test).

## Final Security Verdict

**READY.** All tests pass (62 stored incl. 5 new; 318 across
verification/oracle/HTTP/browser/pipeline suites; compileall and
`git diff --check` clean), no false-CONFIRMED path exists, W1/W2/W3 are
correctly addressed with strictly-tightening, fail-closed changes, and no
unrelated behavior changed (only `verifier.py` + stored-round tests
modified; nothing staged/committed/pushed).

---

Method: READ-ONLY except the three ordered hardening edits and their tests
plus this report (written fresh after deleting the prior file). Test
results: `ai.test_xss_stored_round` 62 OK; `ai.test_xss_verification` +
`ai.test_xss_oracle` + `ai.test_http_executor` + `ai.test_browser_executor`
+ `ai.test_xss_pipeline` 318 OK; `compileall -q ai watch_xss_verify.py` OK;
`git diff --check` clean on touched files.
