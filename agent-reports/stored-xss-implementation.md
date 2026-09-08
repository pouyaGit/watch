# Stored XSS Implementation

## Verdict
IMPLEMENTED

## Executive Summary

The unsafe legacy Stored XSS confirmation predicate (paired HTTP reflection
+ SUBMIT/READ correlation-token equality + token-in-runtime-channel yielding
CONFIRMED) has been replaced with the approved gated oracle-round flow:
SUBMIT (HTTP, oracle payload carrying S) → READ discovery (Location →
endpoint → body link) → clean READ (browser, bare navigation) → exact
E1/E2/E3 proof of the round's OWN D → CONFIRMED. The legacy token path can
now yield at most POTENTIAL and never a confirming verdict. Reflected/DOM
confirmation is byte-for-byte behaviorally unchanged (all 125 verifier, 66
oracle, and related suites pass unmodified except the explicitly rewritten
stored tests). No stop condition was reached; `oracle.py` was not modified.

Proved end-to-end by a localhost real-browser integration test (real HTTP +
real Playwright executors through `XSSVerifier.verify()` → CONFIRMED on E1).

## Baseline

Recorded before any modification (`git status --short`):

```
M AGENTS.md
D README-watch-updated.md
M ai/schemas/xss_verification.py
M ai/test_browser_executor.py
M ai/test_http_executor.py
M ai/test_watch_param_discovery.py
M ai/test_xss_case_builder.py
M ai/test_xss_oracle.py
M ai/verification/browser_executor.py
M ai/verification/http_executor.py
M crawl/watch_param_discovery.py
M database/change_events.py
M database/db.py
?? agent-reports/
?? ai/verification/oracle.py
?? tests/__init__.py ... ?? wordlists/
```

`ai/verification/verifier.py`, `ai/schemas/xss_finding.py`,
`ai/test_xss_verification.py` were clean at baseline (only the oracle-state
machine commit `f74fd2f` applied). All pre-existing modifications were left
untouched. Baseline tests: `ai.test_xss_oracle` 66 OK,
`ai.test_xss_verification` 125 OK, `ai.test_xss_pipeline` 12 OK,
`ai.test_http_executor` 58 OK, `ai.test_browser_executor` 57 OK.

## Design Followed

Authoritative spec: `agent-reports/stored-xss-design-plan.md`
(READY FOR IMPLEMENTATION), plus the oracle/confirmation/production reviews.
Implemented as specified with two documented implementation-level
resolutions (neither weakens any invariant):

1. **Seed-ownership cycle.** The mission text asks for
   `oracle_identity == SUBMIT.attempt_id` with
   `S = oracle_seed(run_salt, SUBMIT attempt_id, "stored_submit")`. That is
   literally unimplementable: the SUBMIT `attempt_id` is derived from the
   payload O, O embeds S, and S would derive from the attempt_id — a cycle.
   Resolution (identical in form to the approved reflected §6.2 pattern): a
   draft SUBMIT attempt is built from the LLM pattern first; its id is the
   stable per-candidate identity the seed is minted against; both final
   attempts carry `oracle_identity == draft_id`. Cross-candidate confusion
   remains impossible (draft id binds case+endpoint+method+parameter+payload
   +attribution), freshness re-derives from the stored identity, and no
   circular edge exists.
2. **Per-retry freshness.** `round_seq` is folded into the draft identity
   (phase suffix `stored_submit+rN` for N>0), so retries mint fresh S/D as
   the design requires ("fresh round_id/S/D, never reuse"). Verified by
   P5/S3 (old-round D rejected by the new round).

Unsupported-oracle-context yields zero attempts (no SUBMIT, INCONCLUSIVE,
SUBMIT count == 0 asserted) — the "do not submit unprovable payloads" rule.

## Implementation Changes

- `ai/schemas/xss_verification.py`: `VerificationAttempt.round_id`,
  `StoredXSSPhaseObservation.round_id`, `VerificationEvidence`
  (`request_body_hash`, `response_body_hash`, `redirect_chain`,
  `location_header`, `object_hint`) — all optional/defaulted.
- `ai/schemas/xss_finding.py`: `XSSFinding.round_id`, `XSSFinding.read_url`
  (audit only).
- `ai/verification/verifier.py`: `build_stored_round`,
  `stored_round_id`, plan-builder stored branch, gated round execution in
  `verify()`, `discover_stored_read_url`, `_submit_accepted`,
  `_stored_oracle_proof`, `_classify_stored_oracle`, demoted
  `_classify_stored` shim, finding annotation.
- `ai/verification/http_executor.py`: SUBMIT shape gate
  (`unsupported_submit_shape`, never POST→GET), redirect-chain/Location/
  body-hash forensics.
- `ai/verification/browser_executor.py`: clean `stored_read` navigation
  (no payload binding), round-tagged READ observation.
- Tests: new `ai/test_xss_stored_round.py` (57 tests); rewrote 5 legacy
  stored tests in `ai/test_xss_verification.py` (justified behavior change);
  updated `_attempts_for_analysis` docstring/shape (stored now uses rounds).

## SUBMIT Implementation

`phase="stored_submit"`, `mode=HTTP_REFLECTION` (composite routes to the
HTTP executor with no dispatcher change). Shape gate in
`HTTPEvidenceExecutor._execute`: GET/HEAD require query location;
POST/PUT/PATCH require body/form location with a parameter name; anything
else → structured ERROR `unsupported_submit_shape` (F4 asserts the executor
never touches the network for it). The submitted value is the complete
planner oracle payload O. Forensics on every success: request-body hash
(urlencoded bytes, or intended URL for query SUBMITs), response-body hash,
redirect chain (bounded), raw `Location`, `object_hint` (= Location;
page-controlled hint, never proof). `response_body_truncated` semantics
unchanged (restored after an accidental nulling caught by
`test_response_body_size_bounded`).

## READ Implementation

`phase="stored_read"`, `mode=BROWSER_EXECUTION`. The browser executor
bypasses query-binding entirely and navigates the verifier-discovered URL
bare (scheme-validated); fresh per-attempt context (existing isolation);
oracle instrumentation unchanged; E1/E2/E3 channels recorded as usual.
READ observation (`StoredXSSPhaseObservation` READ + `round_id`) is emitted
when the token appears OR any oracle channel fires; it carries no D.
Discovery (`discover_stored_read_url`): same-origin Location → case
endpoint → bounded same-origin body-link scan; cross-origin/downgrade/
unclean hints fail closed (a present-but-unacceptable hint does NOT fall
back — avoids reading the wrong object); registrable-domain outer bound via
offline tldextract (same-registrable host accepted as hint only, S5b).

## Round Binding

`round_id = "sr-" + sha256(run_salt ‖ 0x00 ‖ candidate_id ‖ 0x00 ‖ seq)[:32]`
shared by exactly one SUBMIT+READ; distinct `attempt_id`s; shared
`oracle_identity`; pairing by `round_id` only (never list position);
duplicate phase-per-round and duplicate rounds fail closed with audit notes;
single-use via `consumed_rounds`; retries mint new rounds.

## Oracle Integration

Planner reused untouched (`OraclePlanner.plan` with
`phase="stored_submit"`, candidate identity, LLM pattern attribution-only).
Payload O contains S once, never D/run_salt/round_id (asserted P-shape
tests). Proof order mirrors `_oracle_execution_proof`: dual-leg binding →
round binding → pair validity + cross-leg S/D equality → freshness from
SUBMIT-candidate identity → READ same-origin → strict timestamp ordering →
clean READ → dual pre-input anti-harvest → exact E1/E2/E3 (E2 origin = READ
origin; E3 recomputed ≤240). E2 ⇒ OBSERVABLE_EFFECT, else
JAVASCRIPT_EXECUTION.

## Anti-Harvest

Two `PreExecutionInput` scans (SUBMIT: O, O~~token, SUBMIT URLs; READ: O,
READ URLs). D in either rejects. Post-execution channels never scanned
(E1/E2 legitimately contain D after execution). Covered N14–N16 (URL
pollution rejected at discovery AND post-READ).

## Pre-existing XSS Defense

Per-round unique D is primary (N3/S9: D_old with E1+E2 firing still
INCONCLUSIVE/POTENTIAL, never CONFIRMED); clean READ + round binding +
freshness are structural; baseline READ intentionally not implemented as
mandatory (design: optional/default-off; no baseline code added, no extra
browser request, baseline can never suppress a valid D_new proof).

## State Machine

SUBMIT_ATTEMPTED → SUBMIT_ACCEPTED → STORAGE_ATTRIBUTED → READ_REACHED →
JAVASCRIPT_EXECUTION → OBSERVABLE_EFFECT → CONFIRMED. SUBMIT alone caps at
POTENTIAL/REFLECTION (reflection about the submission endpoint only);
accepted+clean+bound READ without S4 caps at POTENTIAL/STORAGE_ATTRIBUTED
(only with a token/payload storage signal); everything else INCONCLUSIVE;
NOT_VULNERABLE never produced.

## Legacy Behavior

`_classify_stored` (token predicate) demoted to a POTENTIAL-only shim; new
plans never emit `phase="stored"` (builder emits `stored_submit`/
`stored_read` only); legacy attempts route to the shim (N19: full
legacy-CONFIRMED-shaped evidence incl. SUBMIT+READ phases + runtime token
→ POTENTIAL, never CONFIRMED). Old DB findings untouched (verifier affects
new runs only; no migration needed).

## Failure Semantics

All fail closed (asserted): SUBMIT timeout/5xx/WAF/auth/CSRF/unsupported
shape → INCONCLUSIVE + READ count 0 (F1–F4, auth tests); unsupported oracle
context → SUBMIT count 0 (S14/F5); READ cross-origin/downgrade/unavailable/
malformed/missing-channels → INCONCLUSIVE or POTENTIAL (N17/N18/N20,
F6–F8); duplicates → fail closed + audit note (S13); 401/403 → 
...[truncated 6150 chars]