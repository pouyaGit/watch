# XSS Production Integration Review

## Verdict

READY WITH WARNINGS

The committed XSS execution-oracle confirmation state machine (`f74fd2f`) is
correctly wired into the real production flow (`watch_xss_verify.py` →
`XSSVerificationPipeline` → `XSSVerifier` → `CompositeVerificationExecutor` →
`HTTPEvidenceExecutor` / `BrowserEvidenceExecutor`). Tracing the production
call graph end-to-end, a fresh `run_salt` is minted per production run and
reaches the verifier; oracle attempts are planned per candidate; browser
oracle evidence is produced only by the executor-owned channels and is
consumed by a single fail-closed proof path (`_oracle_execution_proof`); the
old browser-chain/token CONFIRMED path is demoted to POTENTIAL (SINK_REACHED)
in production; reflected confirmation requires a same-pair meaningful HTTP
reflection in addition to execution proof; DOM confirmation requires only
valid oracle proof; and replay/cross-run/cross-attempt acceptance is blocked
by freshness, identity, pair, and binding checks. No production path was found
that can incorrectly produce CONFIRMED, bypass oracle proof, mix candidates or
runs, disable oracle integration unintentionally, or weaken the approved
confirmation model.

The warnings below are functional limitations / coverage gaps that do not
weaken the confirmation model. They should be tracked but do not block the
integration.

## Scope

- Reviewed artifact: commit `f74fd2f` (= `a3ad8c1` + XSS confirmation
  state-machine) as checked out in the current working tree, plus the
  untracked pre-existing oracle-infrastructure files that production imports at
  runtime (`ai/verification/oracle.py`, and the unstaged oracle-integration
  hunks in `ai/verification/browser_executor.py`,
  `ai/verification/http_executor.py`, `ai/schemas/xss_verification.py`).
- Mandate: determine whether the implemented state machine works correctly when
  invoked through the real production `watch_xss_verify.py` flow. Treat the
  implementation and approved confirmation-state-machine plan as authoritative.
- READ-ONLY: no source, test, schema, config, or report modified; nothing
  staged/committed/pushed. Working tree `git status --short` md5 was
  byte-identical before and after the review (`fc25bfd…`).
- The Oracle infrastructure work and the state-machine commit (`f74fd2f`) are
  separate commits in this tree; production runs against the full working
  tree, so both are part of the runtime composition. This review evaluates the
  composition, not a hypothetical standalone checkout of `f74fd2f` alone.

## Production Call Graph

`watch_xss_verify.py` is the only production entry point driving XSS
verification (no daemon/webhook/cron caller exists; scheduler wiring is
explicitly deferred per the module docstring). Exact chain:

```
watch_xss_verify.main(argv)
 └─ build_production_pipeline(provider_name)          [watch_xss_verify.py:233]
     ├─ build_orchestrator(...)                        [watch_xss_verify.py:209]
     │    ├─ KnowledgeStore(ai_data/knowledge)
     │    ├─ XSSResearcher(store)
     │    ├─ XSSLLMResearcher(build_llm_provider(...)) [watch_xss_verify.py:192]
     │    └─ XSSOrchestrator(knowledge_researcher, llm_researcher)
     ├─ HTTPEvidenceExecutor()                          [watch_xss_verify.py:253]
     ├─ BrowserEvidenceExecutor()                       [watch_xss_verify.py:254]
     ├─ build_default_verifier(http_executor, browser_executor,
     │        run_salt=secrets.token_hex(32))           [watch_xss_verify.py:255-259]
     │    └─ XSSVerifier(CompositeVerificationExecutor(http, browser),
     │                   run_salt=<fresh>)              [xss_pipeline.py:143-149]
     └─ XSSVerificationPipeline(orchestrator, verifier) [watch_xss_verify.py:260]
             └─ pipeline.run(case)                      [xss_pipeline.py:96-107]
                 ├─ orchestrator.analyze(case)          (one call, exceptions propagate)
                 └─ verifier.verify(analysis)           (one call, exceptions propagate)
run loop: run_job(...)                                  [watch_xss_verify.py:331]
  ├─ mongo_already_verified(case_id) → skip if XssFindings already has case_id
  ├─ pipeline.run(case)                                (exception → log, continue)
  └─ mongo_persist(case, result) → XssFindings document
```

Verification internal path (single plane):

```
XSSVerifier._build_plan_from_analysis(analysis)         [verifier.py:436]
  per LLM suggested_payload:
    HTTP_REFLECTION attempt (non-DOM/mutation)          phase="http"
    BROWSER_EXECUTION attempt                           phase="browser"
    ORACLE attempt (only if run_salt is not None and not stored)
        → build_oracle_verification_attempt(...)        [verifier.py:106]
XSSVerifier.verify → executor.execute per attempt → CompositeVerificationExecutor
  ├─ HTTP_REFLECTION → HTTPEvidenceExecutor.execute
  └─ BROWSER_EXECUTION → BrowserEvidenceExecutor.execute (plain + oracle attempts)
     └─ _execute_with_wall_clock_bound → worker process
         → _run_attempt → _navigate (same-origin + redirect audit)
         → _post_navigation_observation
         → VerificationEvidence with dialog_events / oracle_network_events /
           eval_invocations / intended_request_url / actual_request_url
XSSVerifier.verify → _enforce_evidence_binding → _classify per attempt
  ├─ stored → _classify_stored          (legacy stored round-trip only)
  ├─ oracle → _classify_oracle → _oracle_execution_proof
  ├─ browser → _classify_browser        (capped POTENTIAL SINK_REACHED)
  └─ http   → _http_path_confirms       (at most POTENTIAL REFLECTION)
→ XSSFinding (with confirmation_state, oracle_channels)
```

The composite executor is a pure dispatcher by `attempt.mode`
(composite_executor.py:86-116); it never rewrites attempts/evidence, never
falls through on unknown modes, raises on a missing configured executor
(→ verifier `_safe_execute` → bound ERROR evidence), and never classifies.

## Run-Salt / Oracle Lifecycle

- Fresh per-run salt: `run_job` (default) calls `build_production_pipeline()`
  and `main()` builds the pipeline once per process; `secrets.token_hex(32)`
  is invoked on every pipeline build (watch_xss_verify.py:258). Pooling/caching
  is absent; the salt cannot be overridden by CLI arguments (CI offers only
  `--provider`, `--filter`, `--max-cases`, `--max-minutes`).
- The salt is held only in `XSSVerifier.run_salt`; it is never persisted on
  attempts/evidence/findings, never logged, never passed to the LLM, and never
  placed on the wire (the seed S, not the salt, is embedded in the payload's
  inline transform).
- Oracle attempts are planned only when `self.run_salt is not None`
  (verifier.py:518); `None` disables oracle integration (fail closed): no oracle
  attempt is created, `_oracle_execution_proof` returns False
  (verifier.py:902-904), and the mandated browser demotion still applies.
  No production path passes `run_salt=None`; the `build_default_verifier`
  default is exercised only by tests.
- Object lifecycle: pipeline (hence verifier and its salt) is constructed once
  per `main()`; the same verifier serves all cases in a run — correct, because
  the salt is run-scoped and each case's oracle seed is
  `oracle_seed(run_salt, candidate.attempt_id, phase)`. A new process/`main()`
  mints a new salt; a hypothetical embedded caller would rebuild the pipeline per
  run (no such caller exists).
- No silent fallback: pipeline exceptions propagate (xss_pipeline docstring);
  the only broad `except` blocks in `run_job` log and continue to the next case
  without producing a verdict or re-running an attempt outside the verifier.
- Playwright availability: `sync_playwright` import is guarded
  (browser_executor.py:46); when unavailable, the owned-session path fails on
  the first browser operation and every path returns bound ERROR/TIMEOUT
  evidence (→ INCONCLUSIVE). There is no fallback that bypasses the browser.

## Reflected XSS Path

Trace of a reflected candidate (`xss_type=reflected`):

- The plan builder emits one HTTP attempt (phase `http`), one plain-browser
  attempt (phase `browser`), and one oracle attempt (phase `oracle`) for the
  same `logical_pair_id` and canonical tuple (method, parameter, location,
  endpoint, payload, attribution).
- HTTPEvidenceExecutor issues the plain request and the verifier requires
  `_http_path_confirms` (reflection at a meaningful location +
  observed_correlation_token == attempt token) for the **paired** HTTP
  attempt/evidence of the pair — enforced in both `_classify_browser` and
  `_classify_oracle` for non-DOM flavours (verifier.py:787-796, 846-855).
- Oracle attempt: `OraclePlanner.plan(candidate.attempt_id, ...)` builds a
  payload containing S (seed) but never D; the browser `goto` navigates to the
  bound URL carrying the payload; the page-side payload runs the JS transform
  and can produce an `alert(<D>)` (E1), a same-origin
  `new Image().src='/.watch-oracle/'+D` (E2), and/or an eval-family invocation
  of the payload (E3).
- `_oracle_execution_proof` (verifier.py:859-993) enforces, in order; any
  failure → INCONCLUSIVE:
  1. evidence identity binding (attempt_id / request_url / request_method),
  2. `validate_oracle_pair(seed, value)` (shape, D == W(S), D != S),
  3. run freshness: `oracle_seed(self.run_salt, oracle_identity, phase) == seed`
     (stale/cross-run evidence rejected),
  4. candidate identity: `oracle_identity == candidate_attempt.attempt_id`
     (resolved by `logical_pair_id`; duplicate oracle attempt per pair fails
     closed),
  5. same-origin final URL == endpoint origin (redirect target rejection),
  6. anti-harvest over `PreExecutionInput` (payload, bound input, intended and
     actual URLs) — post-execution oracle channels are never scanned,
  7. exact predicates: E1 (kind in {alert,confirm,prompt} and message == D),
     E2 (non-navigation, exact decoded path `/.watch-oracle/<D>`, single decode,
     same-origin), E3 (exact eval/setTimeout:string value == payload, enabled
     only when len(payload) <= 240).
- If proof passes AND (non-DOM) the paired HTTP evidence satisfies S1
  (`_http_path_confirms`), then CONFIRMED with `confirmation_state` =
  OBSERVABLE_EFFECT (E2 in channels) or JAVASCRIPT_EXECUTION (E1/E3 only).
- Stage mapping: HTTP REFLECTION, SOURCE_REACHED (advisory), SINK_REACHED are
  all capped at POTENTIAL; only a valid oracle proof (JAVASCRIPT_EXECUTION /
  OBSERVABLE_EFFECT) confirms. Checks satisfied:
  - HTTP reflection must be meaningful (`_http_path_confirms`).
  - Browser oracle execution must be valid E1/E2/E3 on the oracle attempt.
  - Oracle attempt preserves the candidate's `logical_pair_id`; pairing maps are
    keyed by `logical_pair_id` (never list position); `oracle_identity` must
    equal the paired candidate's attempt_id; a duplicate oracle attempt per pair
    fails closed.
  - Run freshness enforced (check 3).
  - Anti-harvest enforced (check 6) over pre-execution material only.
  - Same-origin enforced (check 5 + browser navigation policy + E2 re-check).
  - Redirect: initial-navigation cross-origin hops raise; only final-origin
    equality on the endpoint is required (intended != actual is allowed for
    redirects); cross-origin final URL rejects proof
    (`test_cross_origin_final_url_rejected`).
  - Missing HTTP reflection → `_http_path_confirms` false → no CONFIRMED
    (`test_missing_http_pair_not_confirmed`).
  - Old browser chain+token evidence cannot confirm: `_classify_browser` caps
    at POTENTIAL / SINK_REACHED.
- Covered by tests through `XSSVerifier.verify`: `test_reflected_paired_http_and_oracle_e2_yield_confirmed`,
  `test_wrong_logical_pair_rejected`, `test_wrong_oracle_identity_rejected`,
  demotion tests.
## DOM XSS Path

- DOM/mutation cases: the plan builder skips the HTTP attempt entirely; one
  plain-browser candidate + one oracle attempt per suggested payload.
- Oracle execution is the authoritative confirmation mechanism: `_classify_oracle`
  skips the HTTP-pair requirement for DOM/mutation (verifier.py:839-857);
  source/sink and runtime-token observations remain advisory attribution and
  are never required for oracle confirmation.
- Source/sink observations remain advisory: `_classify_browser` for DOM/mutation
  caps at POTENTIAL (SINK_REACHED); `correlation_token` and
  `correlation_token_in_runtime` are identity-only binding, never execution
  proof.
- Old browser-only chain+token CONFIRMED cannot survive in production: all
  CONFIRMED returns in verifier.py are exactly two sites — the oracle path
  (line 857) and the legacy stored round-trip (line 1139, explicitly out of
  scope). `_classify_browser` never returns CONFIRMED for any xss_type.
- Oracle confirmation does not incorrectly require an HTTP reflection pair for
  DOM (`test_dom_e2_without_chain_confirmed`).
- Unsupported oracle contexts remain POTENTIAL rather than becoming CONFIRMED
  through a fallback: `OraclePlanner` marks the context unsupported,
  `build_oracle_verification_attempt` returns None, no oracle attempt is
  planned, and the candidate stays POTENTIAL (no fallback skeleton).
- Execution evidence is bound to the correct attempt/candidate/run via
  `_enforce_evidence_binding` + oracle checks 1/3/4.
- Tests: `test_dom_complete_source_to_sink_yields_potential`,
  `test_positive_3_dom_chain_potential`,
  `test_dom_browser_only_yields_no_confirmed`,
  `test_mutation_browser_only_yields_no_confirmed`,
  `XSSVerifierOracleDOMatrixTests`.

## Oracle Evidence Boundary

E1 (`evaluate_e1_dialog`, oracle.py:409):
- Exact full-string equality: message == D. Accepted kinds are exactly
  {alert, confirm, prompt} (`_E1_DIALOG_KINDS`).
- D is never accepted from a generic browser channel: E1 reads only
  `evidence.dialog_events` (executor-owned Playwright dialog listener);
  console/network/dom/storage channels are never inspected by the E1 predicate,
  and only oracle-flavoured attempts reach `_classify_oracle`.

E2 (`evaluate_e2_network`, oracle.py:441):
- Exact same-origin oracle pathname `/.watch-oracle/<D>` after exactly one
  decoding step (the predicate decodes the recorded path once and compares
  exactly; double-encoding is rejected).
- Non-navigation request only: the executor records only page-initiated
  non-navigation requests into `oracle_network_events` (both `requestfinished`
  and `response` gate on `_is_navigation_request`), and the predicate itself
  skips `is_navigation` events.
- An oracle request is handled as oracle evidence and excluded from the generic
  `network_requests` sink (`_is_oracle_request_url` filter), so it cannot
  accidentally become generic network evidence or trip the anti-harvest
E3 (`evaluate_e3_eval`, oracle.py:481):
- Exact full payload match for the operators {eval, setTimeout:string}; enabled
  only when len(payload) <= 240; no truncation or prefix matching
  (len(payload) > 240 → False).
- Never treated as S5 by itself: E3 alone yields JAVASCRIPT_EXECUTION; only E2
  yields OBSERVABLE_EFFECT.

Anti-harvest / benign echoes:
- `anti_harvest_violations` accepts ONLY a `PreExecutionInput` (structural
  boundary; TypeError otherwise). The verifier builds it from pre-execution
  strings only (payload, bound_input = `payload~~token`, intended/actual
  request URLs); post-execution channels (dialog_events, oracle_network_events,
  eval_invocations, dom_changes, console_messages, network_requests,
  storage_writes) are never passed, so D is never scanned from post-execution
  channels.
- Benign URL/path echo cannot produce oracle confirmation: E1/E2 require the
  executor-owned events carrying D; benign fixtures (`test_benign_echo_page_not_confirmed`,
  `test_d_in_payload_rejected`, `test_d_in_generic_network_not_e2`) pass.
- T / correlation_token is identity only — never execution proof.

## Browser Integration

- Production invokes the same `BrowserEvidenceExecutor` used by tests: real
  Playwright session (`sync_playwright` launch + `browser.new_context()`),
  default constructor, no test-only configuration.
- The oracle payload reaches the browser: the oracle attempt's planner payload
  is bound into `state.bound_url` exactly like any browser attempt (GET
  navigation only; POST/PUT returns ERROR evidence → INCONCLUSIVE, never a
  confirmed oracle).
- Instrumentation is enabled in the real executor path:
  `context.add_init_script(_build_init_script(capability))` installs the
  per-attempt transport keyed by a random capability (Python-generated,
  closure-only; page JS cannot forge authenticated events).
- Playwright context isolation: a fresh `browser.new_context()` per attempt is
  created and closed in a `finally`; owned sessions are closed at the end. No
  browser artifacts leak between attempts.
- Oracle events survive serialization/transport: dialog/oracle-network/eval
  events are Pydantic fields of `VerificationEvidence`, pickled through the
  worker `result_queue` and delivered intact to the verifier.
  scanner.
- The query string never participates in matching.
- Navigation/redirect: navigations are same-origin enforced
  (`_canonical_target_origin` + `_navigate` origin equality + HTTPS-downgrade
  rejection); the redirect chain is audited hop-by-hop (same-origin, bounded)
  and the verifier re-checks final-origin equality (check 5). A redirect
  cannot produce a valid oracle event from an unrelated final origin.
- No generic browser event is promoted to oracle evidence: E1/E2/E3 read only
  the executor-owned structured channels; oracle URLs are excluded from the
  generic sink (`_is_oracle_request_url`).
- No stale browser context/evidence can be reused: context closed per attempt;
  evidence carries the producing attempt_id; the verifier enforces binding, so
  a stale/previous-attempt event fails binding → ERROR → INCONCLUSIVE.

## HTTP/Browser Pairing

For one candidate (one suggested LLM payload) the plan produces:

- a plain HTTP attempt (non-DOM/mutation; phase `http`),
- a plain browser candidate attempt (phase `browser`),
- an oracle browser attempt (phase `oracle`).

Identity derivations (`xss_verification.py`):

- `attempt_id` = deterministic SHA-256 over the canonical tuple including mode
  and phase (distinct for http / browser / oracle).
- `logical_pair_id` = deterministic SHA-256 over the same canonical WITHOUT mode
  and phase but WITH method — shared by all three attempts of one logical
  verification; different methods do not pair.
- `correlation_token` derives from `attempt_id` + phase (distinct per attempt).
- The oracle attempt preserves the candidate's `logical_pair_id` and sets
  `oracle_identity = candidate.attempt_id`; seed = `oracle_seed(run_salt,
  candidate.attempt_id, phase="oracle")` (breaks the circular seed/payload
  dependency).
- `intended_request_url` (pre-redirect) vs `actual_request_url` (final) are
  recorded separately by both executors; the verifier enforces only
  final-origin equality (redirects allowed same-origin).

Pairing is by `logical_pair_id` only (via `http_evidence_by_pair`,
`oracle_attempt_by_pair`, `candidate_attempt_by_pair`), never by list position.
`oracle_identity == candidate_attempt_id` is required; a duplicate oracle
attempt for the same pair fails closed.

Redirects: an oracle event is accepted only when the final URL origin equals the
endpoint origin; a valid-looking oracle event from a different final origin is
rejected (`_oracle_execution_proof` check 5 + browser navigation policy).

The HTTP evidence required for reflected confirmation corresponds to the same
candidate and target: `_http_path_confirms` requires the paired HTTP
attempt/evidence for the pair to reflect meaningfully with the same originating
correlation token bound to the attempt (`_token_matches`).
## Replay / Cross-Run Analysis

- Every production run receives a fresh run_salt: `secrets.token_hex(32)` is
  minted per `build_production_pipeline()` call, once per `main()`; no CLI/env/
  database path can override it, and there is no module-level caching of a
  salt.
- `oracle_seed`/`oracle_value` therefore change between runs: S =
  sha256(run_salt ‖ candidate.attempt_id ‖ phase); D = W(S). Both depend on the
  per-run salt, so identical attempt IDs in a later run produce different S/D.
- An old oracle event cannot be replayed into a new run: `_oracle_execution_proof`
  check 3 re-derives the seed under the verifier's current salt; a stale seed
  yields a mismatch → INCONCLUSIVE; even if planting a stale event, the E1/E2
  predicates compare against the attempt's current D and fail. Covered by
  `test_stale_run_salt_rejected` + `RunSaltReplayTests`.
- An oracle event from candidate A cannot confirm candidate B: per-attempt
  evidence binding (attempt_id) + the oracle attempt must be the registered
  oracle attempt for the pair + `oracle_identity == candidate_attempt_id` +
  `logical_pair_id` scoping. Cross-attempt evidence fails these checks.
- An event from another attempt (e.g., the plain-browser attempt's own dialog)
  cannot confirm the current oracle attempt: evidence is keyed by
  `attempt_id` and bound by `_enforce_evidence_binding`.
- Deterministic attempt IDs do not defeat run freshness: attempt IDs are
  deterministic per payload, but seeds/values incorporate the salt, so
  determinism is orthogonal to replay protection.
- The salt is never persisted; a stale snapshot of the DB/deviation cannot be
  used to compute a future D without the run salt.

## Verdict Authority

Every status assignment flows through `XSSVerifier._classify`. Production
producers of statuses:

- CONFIRMED: exactly two return sites — `_classify_oracle` (line 857, valid
  oracle execution proof) and `_classify_stored` (line 1139, legacy stored
  SUBMIT/READ round-trip — explicitly out of oracle scope and plan-accepted).
- POTENTIAL: `_classify_browser` (SINK_REACHED) and `_http_path_confirms`
  (REFLECTION) cap here.
- INCONCLUSIVE: default for every failed precondition.
- NOT_VULNERABLE: never produced.
- No legacy path can produce CONFIRMED for reflected or DOM without valid
  oracle proof: `_classify_browser` caps at POTENTIAL; the HTTP path caps at
  POTENTIAL; only `_classify_oracle` (with the full `_oracle_execution_proof`)
  confirms non-stored XSS.
- `browser_verified` is set from `evidence.browser.executed_script`
  (executor advisory) in `_build_finding`, purely for documentation; it never
  influences status. `executed_script`, `matched_correlation_token`,
  `correlation_token_in_runtime` are executor-advisory fields; the verifier
  re-derives every verdict from structured channels and exact string matches.
- `confirmation_state` / `oracle_channels` are populated by the verifier only:
  REFLECTION / SINK_REACHED / JAVASCRIPT_EXECUTION / OBSERVABLE_EFFECT with the
  matching channels (E1/E2/E3), or None/[] on the legacy stored and failure
  paths. Findings carry them consistently; no LLM/executor path can set them.
- `case_status()` in watch_xss_verify.py only aggregates already-produced
  finding statuses for the persisted document field; it cannot invent a
  verdict.
## Error / Failure Semantics

Every production failure mode resolves to non-confirmation (never optimistic
CONFIRMED):

| Failure mode | Production behavior | Outcome |
|---|---|---|
| Playwright unavailable (`sync_playwright=None`) | browser worker raises on first operation; execute → ERROR/TIMEOUT evidence | INCONCLUSIVE |
| Browser launch / context fails | `_execute` catches `_BrowserSecurityError` / `_UnsupportedBrowserRequest` / crash / unexpected → ERROR evidence | INCONCLUSIVE |
| Oracle context unsupported | `OraclePlanner` unsupported → no oracle attempt planned; candidate stays | POTENTIAL |
| Oracle payload generation fails | `plan()` raises ValueError → `build_oracle_verification_attempt` returns None → no oracle attempt | POTENTIAL |
| Oracle instrumentation fails | missing capability → `_BrowserSecurityError` → ERROR evidence | INCONCLUSIVE |
| HTTP request fails / timeout / 5xx | HTTP evidence attempt_status ERROR/TIMEOUT → `_http_path_confirms` false / binding fails | not CONFIRMED |
| Browser timeout | `_BrowserTimeout` → attempt_status TIMEOUT → Rule 1 INCONCLUSIVE | INCONCLUSIVE |
| Redirect crosses origin / HTTPS downgrade | browser executor raises `_BrowserSecurityError`; verifier check 5 also rejects | INCONCLUSIVE |
| Malformed / non-evidence executor return | `_safe_execute` → ERROR evidence | INCONCLUSIVE |
| Evidence-attempt binding mismatch | `_enforce_evidence_binding` → ERROR evidence | INCONCLUSIVE |
| Oracle evidence duplicated | oracle_attempt_by_pair keeps the first; a duplicate fails closed; predicates are boolean | no severity increase |
| Oracle evidence missing | empty channels → `_oracle_execution_proof` False → INCONCLUSIVE | INCONCLUSIVE |
| Anti-harvest violation | check 6 fails → INCONCLUSIVE | INCONCLUSIVE |
| Stale salt / cross-run replay | check 3 fails → INCONCLUSIVE | INCONCLUSIVE |

The only broad exception handlers in production are in `run_job` around the
pipeline and persist calls: they log and continue to the next case; they never
produce a findings document or a status, and never re-execute an attempt
outside the verifier. The pipeline itself propagates all exceptions unchanged
(xss_pipeline.py docstring), so infrastructure failures never become
CONFIRMED/POTENTIAL/NOT_VULNERABLE.
## Test Coverage

Ran locally (safe; no network/target requests):

| Suite | Result |
|---|---|
| `ai.test_xss_oracle` | 66 OK |
| `ai.test_xss_verification` | 125 OK |
| `ai.test_xss_pipeline` | 12 OK |
| `ai.test_composite_executor` | 14 OK |
| `ai.test_http_executor` | 58 OK |
| `ai.test_browser_executor` | 57 OK (includes `BrowserEvidenceExecutorVerifierIntegrationTests`, which drives the real browser executor through `XSSVerifier.verify`) |
| `python3 -m compileall -q ai watch_xss_verify.py` | OK |

Total: 332 tests pass (66 + 125 + 12 + 14 + 58 + 57). The verifier decision table is tested through the real
`XSSVerifier.verify()` path using structured fake evidence, and the browser
integration tests drive the actual Playwright executor.

Coverage gaps vs. the real production composition (not defects):

1. No test constructs `watch_xss_verify.build_production_pipeline()` — nothing
   asserts that the entrypoint mints a fresh `run_salt` and forwards it, or that
   the produced verifier plans oracle attempts. `ai/test_watch_xss_verify.py`
   tests `run_job` with injected fakes only.
2. No single automated test assembles the real HTTPExecutor + BrowserExecutor +
   XSSVerifier in the same order as `build_production_pipeline` (the closest is
   the browser-executor verifier integration test, which omits the HTTP
   executor and real pairing).
3. No test covers Mongo persistence of the new `confirmation_state` /
   `oracle_channels` finding fields (the entrypoint suite asserts generic
   mapping only).
4. `ai/test_watch_xss_verify.py` is not runnable in this layout due to the
   pre-existing `from config import config` shadowing by `ai/config.py`
   (documented in the earlier review).

A test passing is not evidence the production composition is correct: the
composition is source-traced here (all production wiring follows
`build_production_pipeline`), and the network/browser end-to-end path is an
assurance gap, not a demonstrated defect.

## Bypass-Path Search

Searched for `XSSVerifier(`, `.verify(`, `CONFIRMED`, `browser_verified`,
`executed_script`, `matched_correlation_token`, `correlation_token_in_runtime`,
`oracle_identity`, `run_salt`, `OraclePlanner`, `OracleAttemptFactory`.

- `XSSVerifier(` callers: `ai/verification/xss_pipeline.py:143`
  (production, via `build_default_verifier`) and ~40+ test call sites. No
  production caller passes `run_salt=None`.
- `OraclePlanner` production caller: only `build_oracle_verification_attempt`
  (verifier.py:125). `OracleAttemptFactory` is a test-only name; production
  uses the module function `build_oracle_verification_attempt`.
- `CONFIRMED` production sites: only the two verifier return sites (oracle +
  legacy stored), the `_STATUS_TO_CONFIDENCE` mapping, and the aggregation in
  `watch_xss_verify.case_status`. The LLM is explicitly forbidden from
  returning CONFIRMED (xss_llm_researcher.py:478-485).
- `browser_verified` is set only in `_build_finding` (advisory). `executed_script`
  / `matched_correlation_token` / `correlation_token_in_runtime` are
  executor-advisory fields reflected into evidence strings only; the classifier
  never uses them to decide status.
- No daemon/webhook/CLI caller other than `watch_xss_verify` can invoke the
  verifier with a wrong configuration.

Classification: production callers = watch_xss_verify (A); test callers = all
test modules (B); no legacy/dead callers found (C); no unclear callers (D).

## Findings

### CRITICAL
None.

### HIGH
None.

### MEDIUM

1. **E3 effectively inert on real production payloads** (`E3_PAYLOAD_LENGTH`)
   - Severity: MEDIUM (functional / estimation — conservative only, never a
     false positive).
   - File/function: `ai/verification/oracle.py:297` (`E3_MAX_PAYLOAD_LENGTH=240`),
     planner payloads ~400–405 chars due to the 311-char `JS_W_SOURCE` inline
     transform; `_oracle_execution_proof` step 7 / `evaluate_e3_eval`.
   - Failure path: every production oracle payload exceeds 240 chars, so E3 is
     always disabled in production oracle attempts; E1/E2 remain the working
     oracles.
   - Security impact: none — it is a missing confirmation channel (conservative
     FN), never an over-confirmation.
   - Why tests miss it: E3 tests use hand-built short payloads; the length was
     measured at review time (400–405 chars).
   - Fix direction (not implemented): document the E3-240 rule as intentional,
     or introduce a shorter inline oracle transform if E3 coverage on real
     payloads is ever desired.

2. **Entrypoint run_salt composition is untested**
   - Severity: MEDIUM (assurance gap).
   - File/function: `watch_xss_verify.build_production_pipeline`
     (lines 233-263) and `ai/test_watch_xss_verify.py` (no `run_salt` /
     `build_production_pipeline` references).
   - Failure path: none today — the wiring is verified by source inspection —
     but no automated test would catch a future regression that passes
     `run_salt=None` (oracle silently disabled) in the entrypoint.
   - Security impact: latent; no current defect.
   - Why tests miss it: the entrypoint suite tests `run_job` with injected
     fakes only and never constructs the production pipeline.
   - Fix direction: add a test asserting `build_production_pipeline()` yields
     a verifier with `run_salt` non-None, and that a stale-seed scenario is
     rejected through `verify`.

3. **No end-to-end composition test (real HTTP + browser + verifier)**
   - Severity: MEDIUM (assurance gap).
   - File/function: production assembly in `build_production_pipeline`;
     closest test is `BrowserEvidenceExecutorVerifierIntegrationTests`
     (browser-only, no real HTTP executor or pair flow).
   - Failure path: none identified; manual trace of the composition is
     complete and correct.
   - Why tests miss it: an end-to-end test would need Playwright and a
     disposable HTTP server; the repo separates executor tests by layer.
   - Fix direction: an opt-in integration test wiring the exact assembly.

### LOW

1. `ai/test_watch_xss_verify.py` `from config import config` shadowing by
   `ai/config.py` — the entrypoint suite is not runnable in this layout
   (pre-existing; unrelated to the state machine; documented in the earlier
   final review).
2. Duplicate-oracle-attempt-per-pair fails closed by design, but there is no
   production-side signal beyond the audit note that the second attempt was
   ignored; low observability (functional, not security).
3. E3 `setTimeout:string` operator naming is executor/E3-consistent but easy to
   confuse with `setTimeout`; low maintainability note.

## Required Follow-Up

1. Add an entrypoint test that `build_production_pipeline()` produces a verifier
   with a fresh non-None `run_salt` (MEDIUM-2).
2. Consider an opt-in end-to-end test assembling real HTTP + browser executors
   and the verifier exactly as `build_production_pipeline` does (MEDIUM-3).
3. Document the E3-240-on-real-payloads reality in the design doc so it stays an
   informed choice (MEDIUM-1).
4. Fix/document the pre-existing `config` shadowing blocking
   `ai/test_watch_xss_verify.py` (LOW-1).
5. No code changes were made by this review; no commit/push performed.

## Files Inspected

- `watch_xss_verify.py`
- `ai/verification/xss_pipeline.py`
- `ai/verification/verifier.py`
- `ai/verification/composite_executor.py`
- `ai/verification/browser_executor.py`
- `ai/verification/http_executor.py`
- `ai/verification/oracle.py`
- `ai/schemas/xss_verification.py`
- `ai/schemas/xss_finding.py`
- `ai/researcher/xss_llm_researcher.py`, `ai/researcher/xss_orchestrator.py`
- `ai/verification/xss_case_builder.py`
- `ai/test_xss_oracle.py`, `ai/test_xss_verification.py`, `ai/test_xss_pipeline.py`,
  `ai/test_composite_executor.py`, `ai/test_http_executor.py`,
  `ai/test_browser_executor.py`, `ai/test_watch_xss_verify.py`
- Reference reports under `agent-reports/` (xss-confirmation-design.md,
  xss-confirmation-state-machine-plan.md,
  xss-confirmation-state-machine-implementation.md,
  xss-confirmation-state-machine-final-review.md, xss-oracle-design.md,
  xss-final-staging-plan.md)

## Commands / Tests Run

```
git status --short                       (unchanged before/after; md5 fc25cdb1…)
git show --stat --oneline f74fd2f
grep / callsite analysis (XSSVerifier(, build_default_verifier, run_salt,
    OraclePlanner, OracleAttemptFactory, CONFIRMED, browser_verified, …)
python3 -m unittest ai.test_xss_oracle ai.test_xss_verification ai.test_xss_pipeline \
        ai.test_composite_executor ai.test_http_executor     → 275 OK
python3 -m unittest ai.test_browser_executor                  → 57 OK
python3 -m compileall -q ai watch_xss_verify.py               → OK
```

README of the run: `git status --short` md5 before and after review identical
(`fc25cdb1…`); no file outside `agent-reports/` was created or modified.
