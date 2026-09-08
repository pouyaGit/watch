# XSS Execution-Oracle — Anti-Harvest / E2 Evidence-Boundary Fix Report

**Repository:** `/opt/watch`
**Task:** Fix ONLY the anti-harvest / E2 evidence-boundary issue identified
by the security review (`agent-reports/xss-oracle-review-report.md`,
verdict: READY WITH REQUIRED TEST GAP). No confirmation state machine, no
verdict-logic changes, no E1/E2/E3 wiring, no Stored-XSS or Mutation-XSS work.
**Date:** 2026-09-02

---

## Implementation Verdict

**ORACLE BOUNDARY FIXED**

The pre-execution vs. post-execution evidence boundary is now explicit and
structurally enforced:

- `anti_harvest_violations(...)` scans **only** pre-execution material, which
  is bundled into a dedicated `PreExecutionInput` structure. It raises
  `TypeError` if handed anything that is not a `PreExecutionInput`, so
  `NetworkOracleEvent` / `DialogEvent` (post-execution oracle evidence)
  **cannot** be passed to the scanner by accident.
- The generic `browser.network_requests` sink no longer receives E2 oracle
  requests (`/.watch-oracle/<D>`). Oracle requests now flow **only** into the
  executor-owned `oracle_network_events` channel, where `evaluate_e2_network`
  validates them independently (D is the expected signal there).
- The complementary property is proven by new regression tests on the SAME D:
  `anti-harvest rejects D in pre-execution fields` AND `E2 accepts D in the
  oracle path`.

**FULL XSS CONFIRMATION IS NOT IMPLEMENTED.** As before, the E1/E2/E3
predicates and the anti-harvest scanner remain isolated and are not wired into
`XSSVerifier._classify`. Global verdict behaviour is unchanged.

---

## Exact Root Cause

`anti_harvest_violations()` (in `ai/verification/oracle.py`) was a pure string
scanner that treated D appearing in *any* supplied string field as
`oracle_value_on_wire:<field>`. It had no notion of executor-owned oracle
evidence and no structural guard, so it could not itself distinguish:

1. a pre-execution D-copy (harvest; must be rejected), from
2. the legitimate E2 request `/.watch-oracle/<D>` (executor-owned,
   post-execution evidence; D is the intended signal and must be accepted).

Additionally, the browser executor recorded the same E2 URL into BOTH the
dedicated `oracle_network_events` list AND the generic `browser.network_requests`
sink (`_on_request_finished` / `_on_response` appended unconditionally before
calling `_record_oracle_request`). The generic sink is where a naive future
anti-harvest pass could scan and falsely flag the D-containing URL.

No active false rejection existed because the scanner is not wired into any
production path — the hazard was latent, structural, and untested.

---

## Files Changed

Only the following files were touched by this task:

- `ai/verification/oracle.py` — added `PreExecutionInput` (frozen dataclass);
  changed `anti_harvest_violations(seed, oracle_value, pre)` to accept exactly
  one `PreExecutionInput`; added an `isinstance` guard raising `TypeError` for
  any non-pre-execution argument; added a section comment documenting the
  explicit EVIDENCE BOUNDARY; added `PreExecutionInput` to `__all__`.
- `ai/verification/browser_executor.py` — added module-level helper
  `_is_oracle_request_url(url)`; in the `requestfinished` and `response`
  listeners, E2 oracle requests are now excluded from the generic
  `network_requests` sink (they are still recorded in
  `oracle_network_events`). Non-oracle runtime requests are preserved
  unchanged.
- `ai/test_xss_oracle.py` — updated the existing anti-harvest test to the new
  `PreExecutionInput` API; added `EvidenceBoundaryTests` (TEST 1–6, 8) and
  `EvidenceBoundaryAPITests` (structural API-boundary proofs).
- `ai/test_browser_executor.py` — added
  `BrowserEvidenceExecutorOracleBoundaryTests` (TEST 7 + sink-preservation
  companions); fixed a latent scoping bug in the fake harness
  `FakePage.emit_response` (class-body `from_main_frame = from_main_frame`
  raised `NameError`, so the `response` listener path was previously
  untestable).

`ai/verification/verifier.py`, `ai/schemas/xss_verification.py`,
`ai/verification/http_executor.py` were NOT modified by this task.

---

## Anti-Harvest Boundary Design

### The invariant, made explicit

```
D in payload / bound input / intended URL / response / referrer /
pre-execution input
    => ANTI-HARVEST VIOLATION

D in executor-owned DialogEvent          => E1 evidence
D in executor-owned NetworkOracleEvent   => E2 evidence
D in arbitrary generic network telemetry => NOT E2
```

### Structural enforcement (not caller discipline)

`ai/verification/oracle.py` now defines:

```python
@dataclass(frozen=True)
class PreExecutionInput:
    payload: str
    bound_input: str = ""
    intended_request_url: str = ""
    actual_request_url: str = ""
    request_body: str = ""
    response_snippet: str = ""
    referrer_derived: str = ""
    pre_execution_inputs: tuple[str, ...] = ()

def anti_harvest_violations(
    seed: str,
    oracle_value: str,
    pre: PreExecutionInput,
) -> list[str]:
```

- `PreExecutionInput` has **no** `url`/`path`/`message`/dialog/network-oracle
  fields, so post-execution oracle evidence has no representation in it.
- The function raises `TypeError` unless `pre` is a `PreExecutionInput`, making
  a mistaken `NetworkOracleEvent` argument an immediate, loud failure rather
  than a silent mis-scan.
- The E1/E2 predicates (`evaluate_e1_dialog`, `evaluate_e2_network`) are the
  **only** validators of post-execution oracle evidence. This separation is
  documented in the module and proven by tests that show both sides of the
  boundary on the same D value.

---

## Generic Network Sink Decision

Decision: **exclude** E2 oracle requests from the generic sink.

Preferred architecture adopted:

```
browser.network_requests  = generic runtime network observations
oracle_network_events     = executor-owned, explicitly classified oracle observations
```

- Both `_on_request_finished` and `_on_response` now check
  `_is_oracle_request_url(url)` (decoded path starts with `/.watch-oracle/`)
  before appending to `state.sinks.network_requests`. Oracle URLs are skipped
  in the generic sink but still passed to `_record_oracle_request`, so they
  remain fully observable as E2 evidence in `oracle_network_events`.
- This was safe: no existing behaviour or test depended on the oracle request
  appearing in `browser.network_requests`. All non-oracle runtime network
  evidence is preserved (proven by
  `test_generic_runtime_requests_still_observed`, including a `/watch-oracle/`
  lookalike path that is NOT an oracle request and stays in the generic sink).
- No generic network evidence was removed.

---

## E1 Behavior

Unchanged. `evaluate_e1_dialog` still requires an exact full-string
`DialogEvent.message == D` with `kind in {alert, confirm, prompt}`. D appearing
in an executor-owned dialog is E1 evidence and is validated ONLY by this
predicate. TEST 8 proves E1 remains valid when E1 and E2 both legitimately
contain D.

## E2 Behavior

Unchanged matching rules. `evaluate_e2_network` still requires a
page-initiated, non-navigation, same-origin request whose percent-decoded
pathname equals `/.watch-oracle/<D>` exactly (query ignored). D appearing in an
executor-owned `NetworkOracleEvent` is E2 evidence and is validated ONLY by
this predicate.

What changed is the *producer* side: the E2 URL no longer leaks into the
generic sink, and the executor's oracle recording is unchanged in the dedicated
channel. The anti-harvest scanner and E2 are now provably complementary
(TEST 3).

---

## Regression Tests

### `ai/test_xss_oracle.py` — `EvidenceBoundaryTests`

- **TEST 1** `test_d_in_pre_execution_url_rejected_by_anti_harvest` — D in the
  pre-execution URL → anti-harvest returns `oracle_value_on_wire:
  intended_request_url`.
- **TEST 2** `test_e2_accepts_valid_oracle_event` — valid E2 event
  `/.watch-oracle/<D>` → `evaluate_e2_network` accepts.
- **TEST 3** `test_anti_harvest_rejects_e2_independently_accepts` — same D in a
  pre-execution URL AND in a valid E2 event: anti-harvest rejects the
  pre-execution field while E2 independently accepts the oracle event.
- **TEST 4** `test_e2_not_rejected_for_d_in_url` — a valid E2 request is not
  rejected merely because its own URL contains D.
- **TEST 5** `test_generic_request_with_d_is_not_e2` — a normal request with D
  (query string) but not classified as an oracle event is NOT valid E2.
- **TEST 6** `test_echoed_d_in_telemetry_is_not_e2` — a copied/echoed D in
  generic telemetry (path `/beacon/<D>`) is NOT valid E2.
- **TEST 8** `test_e1_valid_when_e1_and_e2_both_contain_d` — E1 stays valid
  when E1 and E2 both contain D.
- Plus per-field rejection coverage
  (`test_anti_harvest_rejects_pre_execution_with_d`,
  `test_anti_harvest_rejects_actual_request_url_with_d`,
  `test_anti_harvest_rejects_every_pre_execution_field`) proving D is rejected
  in payload, bound input, intended/actual URL, request body, response snippet,
  referrer, and extra pre-execution inputs.

### `ai/test_xss_oracle.py` — `EvidenceBoundaryAPITests` (structural API test)

- `test_network_oracle_event_is_not_pre_execution_input` — passing a
  `NetworkOracleEvent` as `pre` raises `TypeError`.
- `test_network_oracle_event_has_no_pre_execution_shape` — the field sets of
  `NetworkOracleEvent` and `PreExecutionInput` are disjoint; the scanner's only
  input type cannot represent oracle evidence.
- `test_pre_execution_inputs_reject_oracle_event_objects` — oracle events are
  not expressible as extra string inputs; no `oracle_value_on_wire` violation
  is produced from non-representable oracle evidence.

### `ai/test_browser_executor.py` — `BrowserEvidenceExecutorOracleBoundaryTests`

- **TEST 7** `test_oracle_request_recorded_as_e2_not_in_generic_sink` — after
  the sink cleanup, a page-initiated `/.watch-oracle/<D>` request remains
  observable in `oracle_network_events`, is valid E2 via `evaluate_e2_network`,
  and does NOT appear in `browser.network_requests` (no D in the generic
  sink).
- `test_oracle_response_path_also_excluded_from_generic_sink` — same property
  via the `response` listener path.
- `test_generic_runtime_requests_still_observed` — non-oracle runtime requests
  (including a `/watch-oracle/` lookalike path) remain generic evidence and are
  not misclassified as oracle events.

---

## Full Test Results

All commands run from `/opt/watch` (Python 3.12.3, node v24.20.0).

| Suite | Result |
|---|---|
| `ai.test_xss_oracle` | **59 OK** (was 46; +13 boundary/API tests), no skips |
| `ai.test_xss_verification` | **84 OK** |
| `ai.test_browser_executor` (real Chromium) | **57 OK** (was 54; +3 boundary tests) |
| `ai.test_browser_executor_smoke` (real Chromium) | **12 OK** |
| `ai.test_http_executor`, `ai.test_composite_executor`, `ai.test_xss_case_builder`, `ai.test_knowledge_store`, `ai.test_xss_researcher`, `ai.test_xss_llm_researcher`, `ai.test_openrouter` | **208 OK** |

Full `ai/` discovery (`python -m unittest discover -s ai -p "test_*.py"`):
579 tests, 577 OK, 2 import errors — both PRE-EXISTING and unrelated to this
task:

- `test_watch_param_discovery`: `crawl/watch_param_discovery.py` does
  `from config import config`, which fails against `ai/config.py`. The `crawl/`
  subsystem is scope-protected and was not touched.
- `test_watch_xss_verify`: root `watch_xss_verify.py` has the same `config`
  import issue.

These two modules were already modified/failing before this task (visible in
the pre-existing working-tree state) and are outside the AI-oracle change
surface.

Non-unit checks:

- `python -m py_compile` on `oracle.py`, `browser_executor.py`,
  `test_xss_oracle.py`, `test_browser_executor.py`: **OK**.
- `git diff --check`: **OK** (no whitespace errors).

---

## Remaining Limitations (unchanged from the oracle implementation)

- W is a deterministic execution oracle, not a cryptographic PRF; a
  Watch-aware adversarial page that extracts S and computes W itself remains
  locally indistinguishable from execution (design Assumption A4).
- E1/E2/E3 predicates and the anti-harvest scanner are intentionally isolated;
  they are not yet wired into `XSSVerifier._classify`.
- There is still no single enforcement point reconciling "D appears ONLY in
  post-execution channels" across a full attempt — that reconciliation belongs
  to the future confirmation state machine (still out of scope).
- `new Function` eval hooks remain v1.1; E3 stays disabled above 240-char
  payloads; Stored-XSS SUBMIT→READ and Mutation-XSS redesign remain out of
  scope.

---

## Explicit Scope Answers

- **Was the verifier modified?** NO. `ai/verification/verifier.py` has an
  empty `git diff`.
- **Was the confirmation state machine modified?** NO. None exists yet and none
  was introduced.
- **Were E1/E2/E3 wired into `XSSVerifier`?** NO.
- **Was Stored-XSS SUBMIT→READ or Mutation-XSS redesigned?** NO.
- **Was final verdict logic changed?** NO.

---

## Git Diff / Status Summary

Task changes (`git diff --stat` for this task's subset of the working tree):

```
 ai/verification/browser_executor.py | ~30 lines added (sink exclusion + helper)
 ai/test_browser_executor.py         | ~178 lines added (boundary tests + fake fix)
```
plus edits in the untracked `ai/verification/oracle.py` (PreExecutionInput +
scanner signature) and `ai/test_xss_oracle.py` (API migration + boundary tests).

Note: `git status` also shows many PRE-EXISTING unrelated modifications that
predate this task and were left untouched: `AGENTS.md`, `README-watch-updated.md`
(D), `ai/schemas/xss_verification.py`, `ai/test_http_executor.py`,
`ai/test_watch_param_discovery.py`, `ai/test_xss_case_builder.py`,
`ai/verification/http_executor.py`, `crawl/watch_param_discovery.py`,
`database/*`, `tests/*`, `wordlists/`, and the untracked `agent-reports/`
contents (including the prior oracle implementation and this report).

`git diff --check`: **OK**. No commits or pushes were made.

---

## Bottom Line

**ORACLE BOUNDARY FIXED** — the anti-harvest scanner is now structurally
pre-execution-only (`PreExecutionInput` + `TypeError` guard), E2 oracle
evidence is validated only by `evaluate_e2_network`, and the E2 URL no longer
leaks into the generic network sink. The required complement is proven by
regression tests on the same D value.

**FULL XSS CONFIRMATION IS NOT IMPLEMENTED** — no state machine, no verdict
changes, no E1/E2/E3 wiring.
