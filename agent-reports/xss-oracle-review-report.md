# XSS Execution-Oracle — Security Review Report

**Review type:** READ-ONLY security audit. No files were modified.
**Repository:** `/opt/watch` · Branch `main` (HEAD `a3ad8c1`)
**Date:** 2026-09-02
**Scope:** Anti-harvest / E2 data-flow contradiction + secondary oracle audit
+ test-quality review of the completed execution-oracle implementation.

---

## Overall Verdict

**READY WITH REQUIRED TEST GAP.**

The oracle primitives (seed/value derivation, W(S) JS/Python bit-identity,
planner trust boundary, E1/E2/E3 evidence predicates, seed validators) are
correct, deterministic, and individually well-tested. The verifier is
structurally untouched.

The single blocking issue is the **anti-harvest vs. E2 trust boundary is
real but accidental and untested**:

- `anti_harvest_violations()` is NOT wired into any production code path
  (it is referenced only in its own module, a schema comment, and the test
  file). It is a pure string scanner with **no notion of the executor-owned
  post-execution oracle request**, so it CANNOT itself distinguish a
  pre-execution D-copy from the legitimate E2 `/.watch-oracle/<D>` request.
- The E2 oracle request URL (which legitimately contains D) is recorded not
  only in the dedicated `oracle_network_events` list but ALSO in the generic
  `browser.network_requests` sink.
- There is **no regression test** proving the required complement:
  `E2 accepts D-in-oracle-path` AND `anti-harvest rejects D-in-pre-execution
  field` on the same D.

This is not an active exploit today (nothing is wired), but it is a required
integration guard and a required test.

---

## Primary Anti-harvest / E2 Finding

### The design requirement
`xss-oracle-design.md` mandates **D MUST NOT appear on the wire** (AH1/AH2 in
Section 10: "D is never on the wire anywhere") yet simultaneously defines E2
as **the payload issuing `/.watch-oracle/<D>`** — deliberately putting D on
the wire *after* execution. These reconcile only if the implementation splits
**pre-execution request material** (where D must be absent) from the
**executor-owned post-execution oracle request** (where D is the intended
signal). Section 3.1 of the design makes this explicit: *"D-path = trusted
### A. Can `anti_harvest_violations()` receive the E2 oracle request URL?
- **In production today: No.** `grep` across `ai/` shows
  `anti_harvest_violations` is called nowhere in the executors, verifier, or
  pipeline. The only references are:
  - `ai/verification/oracle.py` (its definition),
  - `ai/schemas/xss_verification.py:488` (a code comment),
  - `ai/test_xss_oracle.py` (unit tests).
  The verifier (`ai/verification/verifier.py`) has an **empty `git diff`** and
  contains no references to `oracle`, `anti_harvest`, `evaluate_e[123]`,
  `oracle_seed`, or `oracle_value`.
- **In principle / in tests: Yes.** The function accepts arbitrary string
  fields. If any caller passes the E2 oracle URL (e.g. as `actual_request_url`
  or a pre-execution input), the function will scan it for D.

### B. Does it incorrectly flag D as an anti-harvest violation?
- **Yes — by design of the function, if it ever receives the E2 URL.**
  `anti_harvest_violations` treats D appearing as a substring of *any*
  provided field (payload, bound_input, intended/actual URL, body, response,
  referrer, pre-execution inputs) as `oracle_value_on_wire:<name>`. It has
  **no parameter and no logic to exempt the executor-owned oracle request.**
  So the function, as written, makes NO distinction between:
  1. an ordinary/pre-execution request string that happens to contain D; and
  2. the E2 oracle request `/.watch-oracle/<D>`.
  Both would yield `oracle_value_on_wire:*`.

### C. Where is the oracle request excluded today?
- The exclusion is **implicit, at the evidence-construction layer only**:
  - `VerificationEvidence.intended_request_url = state.bound_url` → the
    navigation URL (carries payload + seed S), never the oracle URL.
  - `VerificationEvidence.actual_request_url = state.final_url or
    state.bound_url` → the navigation **response** URL, never the oracle URL
    (E2 oracle requests are `new Image()` subresources, not navigation, so
    they never become `final_url`).
  - The E2 request is recorded in the dedicated
    `oracle_network_events: list[NetworkOracleEvent]`.
- However, the browser executor **also records the same E2 URL into the
  generic runtime network channel**: `_on_request_finished` calls
  `state.sinks.append_network(url)` for every non-navigation request and
  *then* calls `_record_oracle_request`. The D-containing URL is therefore
  present in `browser.network_requests` (shared sink) as well as in
  `oracle_network_events`. That generic sink is a place a naive future
  anti-harvest pass could scan and falsely flag D.

### D. Is the exclusion explicit and structurally safe, or accidental?
- **Accidental / fragile.** Reasons:
  1. `anti_harvest_violations` has no concept of "executor-owned oracle
     evidence." It cannot itself separate pre-execution D-copy from the E2
     oracle request. The safety rests entirely on the *caller never passing*
     post-execution oracle material — a property that is not enforced,
     encoded, or documented in the function's contract beyond its docstring.
  2. The E2 URL is not confined to the dedicated E2 field; it also lands in
     the shared `network_requests` sink, increasing the chance a caller
     treats it as ordinary request material.
  3. The design's Section 10 wording "E2 predicate … plus onwire(D)=false"
     has no corresponding code that reconciles "D is on the wire in E2" with
     "D is not on the wire pre-execution." The reconciliation exists only as
     a documentation/architecture intent, not as a check.

### E. Does E1's on-wire check remain correct when an E2 event is also present?
- **Yes.** `evaluate_e1_dialog` operates only on `dialog_events` against the
  expected value D; it is fully independent of `oracle_network_events`,
  `anti_harvest_violations`, and `actual_request_url`.
- When both E1 (dialog message == D) and E2 (path contains D) fire, both are
  legitimate post-execution evidence; D appearing in both is expected and does
  not corrupt E1. The pre-execution invariant (D absent from payload, bound
  input, intended URL) is maintained separately and is not affected by the
  presence of an E2 event.
- Nuance/risk: there is currently **no single enforcement point** that
  verifies D appears ONLY in post-execution channels (dialog message, oracle
  network path) and NOT in pre-execution fields. That reconciliation belongs
  to the future state machine and is untested (see Test Gaps).

### Bottom line on the primary question
No active/in-production false rejection exists because `anti_harvest_violations`
is not wired anywhere. But the implementation does not structurally encode the
required pre-execution vs. post-execution split, and it scatters the E2 URL
into a shared sink. This is a **latent integration hazard** and the associated
boundary test is **missing**. This is exactly the contradiction the review
question suspected, and it must be closed before the predicates are wired into
the confirmation state machine.
---

## Exact Code Paths Inspected

- `ai/verification/oracle.py` (all 566 lines):
  - `fnv1a32` / `_utf16_code_units` / `_hex8` / `oracle_value_from_seed` (W)
  - `oracle_seed` (S derivation)
  - `is_valid_seed` / `is_valid_oracle_value` / `validate_oracle_pair`
  - `JS_W_SOURCE`, `build_oracle_snippet`, `_JS_E1_ACTION`, `_JS_E2_ACTION`
  - `OraclePlan` / `OraclePlanner.plan` (trust boundary)
  - `evaluate_e1_dialog` / `evaluate_e2_network` / `evaluate_e3_eval`
  - `_origin` and `anti_harvest_violations`
- `ai/schemas/xss_verification.py`: `DialogEvent`, `NetworkOracleEvent`,
  `EvalInvocation`, `VerificationAttempt` oracle fields,
  `VerificationEvidence` oracle/URL fields.
- `ai/verification/browser_executor.py`: `_on_dialog`,
  `_record_oracle_request`, `_on_request_finished`, `_on_response`,
  `_build_bound_url`, `_navigation` (final_url), `_build_evidence`
  (lines ~1660-1735).
- `ai/verification/http_executor.py`: `intended_request_url`,
  `actual_request_url` assignment.
- `ai/verification/verifier.py`: confirmed no diff, no oracle references.
- `ai/test_xss_oracle.py`: full test list (see Test-Quality Review).

---

## E1 Review — DIALOG ORACLE

Inspection of `evaluate_e1_dialog`:
- Exact full-string `message == expected_value` (D) **and**
  `kind in {alert, confirm, prompt}`.
- `evaluate_e1_dialog` returns `False` if `expected_value` is not a valid
  16-hex oracle value (shape guard).
- Spoof variants are all rejected and tested: `D+suffix`, `prefix+D`,
  whitespace-padded D, D-as-substring, wrong case, partial D, and the seed S
  (`test_spoof_variants_fail`). `test_empty_events_fail` covers empty lists.
- **Verdict: correct and safe.** No issues.

## E2 Review — NETWORK ORACLE

Inspection of `evaluate_e2_network` and `_record_oracle_request`:
- Percent-decodes the path **once**: `unquote(urlsplit(url).path)`.
- Compares the decoded path **exactly** to `ORACLE_PATH_PREFIX + D`
  (`/.watch-oracle/<D>`); no substring/suffix/prefix matching.
- Query never participates (compares `path`, not `url`).
- Navigation rejected (`is_navigation` guard in predicate; executor never
  records navigation via `_on_request_finished`/`_on_response`).
- Cross-origin rejected; **same-origin enforced** by exact origin tuple
  equality (`_origin(url) == _origin(endpoint)`).
- Single-segment enforcement: post-prefix remainder must not contain `/`
  (defence in depth; D is hex so cannot contain `/`).
- `_record_oracle_request` requires the decoded path to `startswith(
  ORACLE_PATH_PREFIX)` before recording, records the raw URL + decoded path,
  `is_navigation=False`, and excludes navigation via callee call-sites.
- The oracle path is `/.watch-oracle/<D>` with a **404 acceptable** (the
  attempt is the signal); no OOB canary; no raw S in the path.
- **Verdict: E2 predicate itself is correct.** The only issue is the
  anti-harvest boundary described in the Primary Finding (E2 URL also enters
  the generic network sink; no explicit anti-harvest exemption).

## E3 Review — EVAL ORACLE

Inspection of `evaluate_e3_eval`:
- Exact `value == payload` (P) and operator in `{eval, "setTimeout:string"}`.
- **Disabled** (`return False`) whenever `len(payload) > 240` — even for an
  exact-looking record (`test_disabled_for_long_payloads`). Never approximates
  truncated prefixes (`test_truncated_prefix_never_passes`). Boundary 240
  enabled (`test_boundary_240_still_enabled`). `new Function` is unsupported /
  rejected (`test_unsupported_operator_fails`) and documented as v1.1.
- **Verdict: correct and safe.**

## Seed / W Review

- **S:** `sha256(run_salt \x00 attempt_id \x00 phase)[:16].hex()` — exactly 32
  lowercase hex. Deterministic. NUL-joined prevents field-boundary aliasing
  (`test_field_boundary_cannot_alias`)). Run-salt, attempt, and phase each
  participate (`test_salt_participates`, `test_phase_and_attempt_participate`).
- **W(S):** `h1 = fnv1a32(S)`, `h2 = fnv1a32(hex8(h1)+':'+S)`,
  `D = hex8(h1)+hex8(h2)` (exactly 16 lowercase hex). FNV-1a over UTF-16 code
  units (`_utf16_code_units`), 32-bit wrap multiply (`& 0xFFFFFFFF`).
- **JS parity:** `JS_W_SOURCE` uses `Math.imul(...)` and `>>> 0`, 8-digit zero
  padding — mirrors Python bit-for-bit. `test_python_matches_javascript` and
  `test_embedded_js_source_matches_python` run live Node (v24.20.0 present),
  no skips. `fnv1a32('a') == 0xE40C292C` and `fnv1a32('') == 0x811C9DC5`.
- `validate_oracle_pair`: enforces S shape, D shape, `D == W(S)`, and `D != S`.
- **Verdict: correct. W is a deterministic execution oracle, not a
  cryptographic PRF (as designed).**

## Planner Trust-Boundary Review

- `OraclePlanner.plan` derives S/D/W itself from trusted identifiers and a
  run salt; the LLM `delivery_pattern` is recorded for attribution only and is
  **never executed and never permitted to alter seed/value/snippet/expected
  oracle** (`test_llm_pattern_cannot_control_oracle`).
- Supported contexts (planner-owned skeletons): `html_body`,
  `html_attribute`, `script_block`, `generic`. Unsupported context (e.g.
  `url`) is returned with `supported=False` + `unsupported_reason`
  (`test_unsupported_context_is_explicit`).
- Planner self-checks: payload.contains(seed)==1 and D not in payload
  (`test_payload_contains_seed_once_and_never_value`).
- **Verdict: correct. LLM cannot control S/D/W/expected-oracle/snippet/**
## Browser Transport Review (executor-owned evidence)

- **Dialogs:** `_on_dialog` is a Playwright `page.on('dialog')` listener. Only
  the executor appends `DialogEvent`; page JavaScript cannot directly reach
  `state.dialog_events`. The legacy console record is preserved unchanged.
- **Network:** `_record_oracle_request` builds `NetworkOracleEvent` from the
  Playwright request/response objects inside `requestfinished`/`response`
  handlers. Page JS has no path to these lists.
- **Eval:** `EvalInvocation` entries are appended by the instrumentation
  transport hook (`operator in {eval, setTimeout:string}`), executor-owned.
- **Cross-checks:** `_install_network_policy` aborts cross-origin traffic at
  runtime; navigation vs subresource is distinguished via
  `_is_navigation_request` / `resource_type`; HTTPS→HTTP downgrade and
  cross-origin navigation are rejected (`_navigation`).
- **Verdict: executor-owned transport is sound; page JS cannot directly inject
  fake `DialogEvent` / `NetworkOracleEvent` / `EvalInvocation`.** (Note: the
  E2 URL enters both the dedicated oracle list and the generic
  `network_requests` sink, per the Primary Finding.)

## Binding Review (intended vs actual URL)

- Browser executor: `intended_request_url = state.bound_url` (navigation URL
  with bound input+S) and `actual_request_url = state.final_url or
  state.bound_url` (post-redirect navigation URL). Redirect info preserved in
  `state.final_url` and the `nav_redirects` audit; never destroyed.
- HTTP executor: records `intended_request_url` before send and
  `actual_request_url = final_url or intended_request_url` after following
  redirects (`_final_url` is now consumed).
- Seed/value are bound to `attempt_id + phase + run_salt`; replay of an old D
  against a new run salt/attempt is rejected (`RunSaltReplayTests`).
- **Verdict: correct. Binding D to request identity is a future state-machine
  decision not implemented here (fine for this task).**

## Anti-harvest Secondary Checks (properties 1–4)

1. **D not in generated payload:** planner raises `oracle_value_on_wire:
   payload` if `value in payload`; snippet contains only S once. ✓
2. **D not in bound attacker input:** bound input is attacker/LLM-delivered;
   D is never on the wire and is derived from a seed only the planner places
   in the payload body. No production check currently scans bound input, but
   D cannot legitimately appear there. ✓ (enforcement test-only via
   `anti_harvest_violations`).
3. **D not in intended URL before execution:** browser/HTTP intended URLs are
   built from endpoint + bound input (S only), never D. ✓
4. **D appears ONLY in post-execution dialog / oracle request:** in the
   produced evidence D appears in dialog message and oracle network URL/path —
   and, per the Primary Finding, also in the generic `network_requests` sink.
   So property 4 is violated notationally by the sink leak, though not by any
   pre-execution field. This is the latent hazard. ⚠
  payload-composition semantics.
execution evidence."*