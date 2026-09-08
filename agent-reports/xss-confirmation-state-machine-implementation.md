# XSS Confirmation State Machine — Oracle Integration Implementation

**Date:** 2026-09-02
**Task:** Integrate the execution oracle (E1/E2/E3, anti-harvest, run_salt) into
the XSS confirmation state machine per the approved plan.

---

## Implementation Summary

**STATUS: IMPLEMENTED** — all 7 phases completed. No stop condition was reached.

The execution oracle is now fully integrated into the XSS confirmation state
machine. The existing oracle predicates, planner, anti-harvest, and browser
evidence channels are reused as-is (no modifications to `oracle.py`,
`browser_executor.py`, `http_executor.py`, `composite_executor.py`, or
`xss_case_builder.py`). The verifier now owns classification authority over
oracle evidence, and the mandated demotion of the old browser-only CONFIRMED
path is in effect.

---

## Files Changed

### Schema (additive, backward compatible)

- `ai/schemas/xss_verification.py` — added `VerificationAttempt.oracle_identity:
  str | None = None` (pre-oracle candidate identity for seed/payload cycle
  resolution and run-freshness re-derivation).
- `ai/schemas/xss_finding.py` — added `XSSFinding.confirmation_state: str | None
  = None` and `XSSFinding.oracle_channels: list[str] = Field(default_factory=list)`
  (verifier-derived authoritative classification detail; never LLM-controlled).

### Verifier (core change)

- `ai/verification/verifier.py`:
  - `__init__(executor, *, run_salt=None)` — keyword-only, default-None,
    backward-compatible. `None` disables oracle integration fail-closed.
  - `build_oracle_verification_attempt(...)` — module-level factory; breaks the
    seed/payload circular dependency by seeding from the candidate's
    `attempt_id`. Returns `None` for unsupported planner contexts. Uses
    `payload_origin="model_generated"`, empty knowledge/source ids (no false
    knowledge attribution).
  - `_build_plan_from_analysis` — adds one oracle attempt per suggested payload
    when `run_salt` is set AND context is supported. Stored XSS (out of scope)
    never receives an oracle attempt. Unknown/unsupported contexts → no oracle
    attempt (candidate stays POTENTIAL — no fallback skeleton invented).
  - `verify()` — pairing maps (`oracle_attempt_by_pair`, `candidate_attempt_by_pair`)
    keyed by `logical_pair_id`; `_classify_with_detail` returns `(status,
    confirmation_state, oracle_channels)`.
  - `_classify` — routes oracle attempts to `_classify_oracle`, plain browser
    attempts to `_classify_browser` (demoted), stored to `_classify_stored`
    (unchanged).
  - `_classify_oracle` — DOM/mutation: no HTTP pair required; reflected/unknown:
    requires `_http_path_confirms` on the paired HTTP attempt.
  - `_oracle_execution_proof` — 7‑step check (evidence binding, pair validity,
    run freshness, oracle identity, same-origin final URL, anti-harvest via
    `PreExecutionInput`, exact E1/E2/E3 predicates). Returns channels + state.
  - `_classify_browser` — **MANDATED DEMOTION**: `return "POTENTIAL"` with
    `confirmation_state="SINK_REACHED"` instead of the old `"CONFIRMED"`.
  - `_build_finding` — populates `confirmation_state` and `oracle_channels`.
  - Class docstring updated to reflect the new state machine.

### Production Composition

- `ai/verification/xss_pipeline.py` — `build_default_verifier(http_executor,
  browser_executor, *, run_salt=None)` keyword passthrough.
- `watch_xss_verify.py` — `import secrets`; `build_production_pipeline` generates
  one fresh `run_salt=secrets.token_hex(32)` per process run. The salt is NEVER
  persisted on attempts/evidence/findings and NEVER exposed to the LLM.

### Tests

- `ai/test_xss_verification.py` — 125 tests (was 84). 11 demotion-justified tests
  updated (chain+token CONFIRMED → POTENTIAL); 41 new oracle-matrix tests
  covering reflected, DOM, E1/E2/E3, E2-only-without-chain, E3 short-payload,
  stale run, wrong D, D in pre-execution, cross-origin final URL, missing HTTP
  pair, wrong oracle identity, wrong logical pair, seed copied, D in generic
  telemetry/navigation/console/storage, E2 navigation/cross-origin/path-suffix/
  double-encoded, E3 >240 disabled, E3 prefix rejected, D in payload rejected,
  duplicate oracle events, duplicate oracle attempt per pair, benign echo page,
  benign telemetry, and plan-builder shape verification.
- `ai/test_xss_oracle.py` — 66 tests (was 59). Added 7 `OracleAttemptFactoryTests`
  (seed binds to candidate identity, distinct attempt_id, determinism,
  run-salt separation, seed once in payload, D never in payload, unsupported
  context → None, anti-harvest holds on oracle attempt).
- `ai/test_xss_pipeline.py` — 12 tests (was 11). Added `run_salt` default-None
  and passthrough test.
- `ai/test_browser_executor.py` — verifier-integration test
  `test_valid_browser_evidence_with_chain_confirmed` updated to assert
  demoted POTENTIAL + SINK_REACHED (justified behavior change).

### Files NOT Modified

- `ai/verification/oracle.py` — reused as-is (predicates, planner, anti-harvest,
  PreExecutionInput).
- `ai/verification/browser_executor.py` — reused as-is (evidence production
  already complete; oracle requests excluded from generic sink).
- `ai/verification/http_executor.py`, `ai/verification/composite_executor.py`,
  `ai/verification/xss_case_builder.py` — unchanged.
- `ai/researcher/*`, `ai/knowledge/*`, `ai/llm/*`, `ai/schemas/xss.py` —
  unchanged (LLM never sees run_salt/seed/value/oracle payloads).

---

## E1/E2/E3 Integration

- **E1** (dialog exact D): `evaluate_e1_dialog` — exact kind in
  {alert,confirm,prompt}, message == D. Establishes JAVASCRIPT_EXECUTION.
- **E2** (network exact `/.watch-oracle/<D>`): `evaluate_e2_network` — same-
  origin, non-navigation, single decode, exact path, query ignored. Establishes
  JAVASCRIPT_EXECUTION + OBSERVABLE_EFFECT.
- **E3** (eval-family exact payload): `evaluate_e3_eval` — exact equality,
  payload <= 240 chars (disabled otherwise; never prefix-matched). Establishes
  JAVASCRIPT_EXECUTION only. The plan's real oracle payloads are ~405 chars,
  so E3 is always disabled via the planner; E3 confirmation is tested via
  hand-built short-payload oracle attempts. The verifier recomputes the 240
  bound itself; `e3_enabled` is never trusted.

**Channel combination:** E1+E2, E1+E3, E2+E3, E1+E2+E3 — deterministic sorted
channels, state = OBSERVABLE_EFFECT if E2 present else JAVASCRIPT_EXECUTION.
Multiple channels never increase severity.

---

## run_salt Handling

- `run_salt` is a verifier-side keyword argument defaulting to `None` (disabled).
- When set, the plan builder adds one oracle attempt per candidate payload.
- Freshness re-derivation: `oracle_seed(run_salt, oracle_identity, phase) ==
  oracle_seed`. Stale or cross-run evidence fails here.
- The salt is generated once per production process run via
  `secrets.token_hex(32)` in `watch_xss_verify.py`.
- It is NEVER persisted on attempts, evidence, or findings, and NEVER passed to
  the LLM, executors, or any other component.

---

## Anti-Harvest Integration

The verifier constructs `PreExecutionInput` per oracle attempt with:
`payload`, `bound_input` (payload + "~~" + token), `intended_request_url`,
`actual_request_url`, `request_body=""`, `response_snippet=""`,
`referrer_derived=""`, `pre_execution_inputs=()`.

Post-execution channels (dialog_events, oracle_network_events, eval_invocations,
dom_changes, console_messages, network_requests, storage_writes) are NEVER
passed to the scanner. The structural boundary enforced by `PreExecutionInput`
prevents accidental mis-scans.

---

## Binding / Replay Checks

All 8 checks enforced in `_oracle_execution_proof` (in order, any failure →
reject):
1. Evidence identity binding (attempt_id/url/method) — defence in depth.
2. `validate_oracle_pair(seed, value)` — shape, D == W(S), D != S.
3. Run freshness — `oracle_seed(run_salt, oracle_identity, phase) == seed`.
4. Candidate identity — `oracle_identity == candidate.attempt_id`.
5. Same-origin — `_origin(actual_request_url) == _origin(endpoint)`.
6. Anti-harvest — `anti_harvest_violations(seed, D, pre) == []`.
7. Exact predicates — E1/E2/E3 over executor-owned channels.
8. Duplicates/replays — existence-based; replicated events cause no change;
   stale run_salt rejected at check 3.

---

## Reflected Confirmation Behavior

CONFIRMED = S1 (meaningful HTTP reflection via `_http_path_confirms`) + S4
(valid oracle execution proof on the paired oracle attempt) + binding + freshness
+ anti-harvest. The plain browser attempt (chain+token) is demoted to POTENTIAL
(SINK_REACHED). Without run_salt, the oracle attempt is never created — the
candidate stays at POTENTIAL.

---

## DOM Confirmation Behavior

CONFIRMED = S4 only (valid oracle execution proof). No HTTP pair required.
Source/sink evidence is advisory attribution (never required for oracle
confirmation — this closes the `location.hash` / handler-set sink FN gap).
S2∧S3∧token without oracle → POTENTIAL (SINK_REACHED) — the mandated demotion
of the old DOM false-positive CONFIRMED path.

---

## Mandated Demotion

The old browser-only CONFIRMED path (chain + token + data-stage evidence) is
demoted to POTENTIAL (SINK_REACHED). This applies to the shared DOM/mutation
browser branch. The `return "CONFIRMED"` in `_classify_browser` is replaced
with `return "POTENTIAL", "SINK_REACHED", []`. This is the explicit, intended
security fix that kills the existing DOM false-positive path where a benign
echo page could produce a well-formed chain and token-in-channel hits.

---

## Test Results

| Suite | Tests | Result |
|---|---|---|
| `ai.test_xss_oracle` | 66 | OK |
| `ai.test_xss_verification` | 125 | OK |
| `ai.test_browser_executor` | 57 | OK |
| `ai.test_browser_executor_smoke` | 12 | OK |
| `ai.test_xss_pipeline` | 12 | OK |
| `ai.test_http_executor` | 58 | OK |
| `ai.test_composite_executor` | 14 | OK |
| `ai.test_xss_case_builder` | 47 | OK |
| `ai.test_knowledge_store` | 15 | OK |
| `ai.test_xss_researcher` | 12 | OK |
| `ai.test_xss_llm_researcher` | 36 | OK |
| `ai.test_openrouter` | 26 | OK |
| **Full `ai/` discovery** | **628** (2 pre-existing errors) | 626 OK |

### Pre-existing errors (2, unrelated to this task)

1. `test_watch_param_discovery` — `crawl/watch_param_discovery.py` does
   `from config import config`; when `unittest discover -s ai` runs, `ai/config.py`
   shadows the root `config.py` (the root module has a `config` attribute,
   `ai/config.py` does not). The `crawl/` subsystem is scope-protected
   (unrelated).
2. `test_watch_xss_verify` — same `config` import issue in `watch_xss_verify.py`
   at line 89. The import failure is pre-existing in HEAD — my changes
   (`import secrets`, `run_salt` injection) only added code after line 89 and
   did not touch the config import.

Both errors are pre-existing repo structural issues with the `config` module
shadowing (independent of this task). They were present in the prior task's
full-discovery output (579 tests, 577 OK, same 2 errors).

### Static checks

- `python -m compileall -q ai`: OK.
- `git diff --check`: OK (no whitespace errors).

---

## Remaining Limitations

1. **E3 disabled for real planner payloads** (~405 chars > 240 bound). E1/E2
   carry confirmation; E3 is a supplementary channel tested via hand-built
   short-payload oracle attempts.
2. **Unknown context** (`xss_type=unknown` / `context.type=unknown`) → no
   oracle attempt → candidate capped at POTENTIAL. Documented FN.
3. **Stored XSS** remains on its out-of-scope legacy path (SUBMIT/READ round
   trip + token); no oracle integration, no `confirmation_state` on stored
   findings.
4. **Mutation XSS** shares the demoted DOM browser branch; no mutation-specific
   redesign.
5. **`run_salt` is per-process-run** — a restart invalidates the salt and
   previously-planned oracle attempts cannot be re-verified. Acceptable for
   single-run `verify()`.
6. **Two browser runs per candidate** (plain + oracle) doubles browser cost.
   Acceptable for inventory-scale v1.

---

## Git Status

My changes:
  8 files modified (schema, verifier, pipeline, tests, production script).

Pre-existing changes (untouched by this task):
  AGENTS.md, README-watch-updated.md, ai/schemas/xss_verification.py,
  ai/test_http_executor.py, ai/test_watch_param_discovery.py,
  ai/test_xss_case_builder.py, ai/verification/browser_executor.py,
  ai/verification/http_executor.py, crawl/watch_param_discovery.py,
  database/*, tests/*, wordlists/, plus untracked agent-reports/
  (including the oracle implementation and this report).

`git diff --check`: OK. No commits, no pushes.

---

## Verdict

**ORACLE INTEGRATION COMPLETE** — the execution oracle is wired into the XSS
confirmation state machine as the sole route to CONFIRMED. The old browser-only
data-stage CONFIRMED path is demoted to POTENTIAL. All evidence binding,
freshness, identity, anti-harvest, and exact-predicate checks are enforced.
No stop condition was encountered. Schema, oracle.py, browser_executor.py,
http_executor.py, and all researcher/knowledge/LLM files remain unchanged.