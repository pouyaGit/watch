# Optional external-provider shadow layer

Use this reference when a HERMES milestone adds an optional, external intelligence provider to Research without changing the primary Research provider or protected routing modules.

## Procedure

1. **Audit before implementation.** Trace scheduler/daemon → Research runner → provider adapter → transport. Read the current adapter, secret source, config, database schema, and protected M17/M18/M24/Finding-Routing surfaces. Capture baseline hashes, `quick_check`, exact table names/counts, service state, and the primary model/provider. Do not call the external provider during the audit.
2. **Write offline contract tests first.** Isolate `HERMES_DB`, state, skills, and notification sinks before importing modules that can open stores. Test one behavior at a time: missing configuration, valid configuration candidate, HTTP 401/402/403/408/429/5xx, malformed and oversized responses, timeout, redaction, endpoint validation, no redirects, deterministic idempotency, per-run and daily ceilings, consecutive-failure cutoff, and no fatal propagation.
3. **Implement one provider boundary.** Keep configuration, state transitions, persistence, and transport in `lib/<provider>.py`; do not spread provider HTTP calls through Research. Read secrets from the established file/environment path at call time. Keep the key out of source, fixtures, reports, SQLite, argv, process environment dumps, and exception text. Expose only a small interface such as `health()`, `request_shadow()`, `disable(reason)`, and `status()`.
4. **Make the boundary fail closed.** Enumerate the provider states explicitly. Treat missing config as `DISABLED`/`UNCONFIGURED`; classify auth/payment/quota/rate-limit/timeout/network/response failures; persist exhaustion and auth as terminal until operator recovery; persist a bounded cooldown for rate limits; cap retries. No provider exception may become a Research, daemon, or scheduler failure.
5. **Bound and authenticate the request.** Use a fixed HTTPS provider origin, public-address validation, no untrusted redirects, explicit timeout, bounded request and response bytes, a deterministic request ID, run ID, model, state hash, provider status, latency, and response validation. Keep provider-specific error bodies out of logs and reports. Never use a secret-bearing URL.
6. **Integrate downstream only.** Call the provider after the authoritative Research artifact exists, under the existing per-run guard and a second `try/except` at the Research seam. Store the result as advisory/shadow intelligence or disagreement data. The deterministic Research policy must remain authoritative; no provider result may create findings, confirm vulnerabilities, alter confidence/priority/closure, invoke Nuclei/M6, modify M17/M18/M24/Finding Routing, or become a scheduler/daemon dependency.
7. **Persist budget truth before the request.** Use additive tables for request/run/state/failure metadata and a transaction that atomically records the request identity and accounting. Count the daily ceiling from persisted UTC-day rows, not only an in-memory counter. Make the same state/model/schema/consumer identity resolve to the same row after restart or retry; do not replace a successful row with a second provider call.
8. **Run the live probe separately.** After offline tests and regressions pass, record provider state, budget, daemon health, and Research run count. Send exactly the operator-approved number of smallest synthetic requests, outside `research_daily.py`, the scheduler, and target traffic. Stop after that count. A classified failure is valid evidence; a successful response still does not prove the full Research integration unless separately exercised.
9. **Certify from measured evidence.** Re-run focused and relevant regression suites, then perform read-only final checks: `quick_check`, raw table count plus explicitly named filtered count, exact table-aware row counts, Research deltas, provider row counts, protected hashes, service state, and resource sample. Distinguish append-only live churn from task-caused changes. Programmatically validate every required report section and terminal key. Keep `READY FOR PRODUCTION: NO` when any required test, persistence check, live check, or report consistency check remains unverified.

## Pitfalls

- A legacy adapter can coexist with a new optional boundary. Audit both call paths; do not assume the old test proves the new path is wired or safe.
- Set isolation environment variables before imports. A test that only sets them in a child process can still open the production store during module import.
- A request that returns 200 is not enough to certify the milestone: response schema validation, persistence, idempotency, isolation, and the exact call count still require separate evidence.
- Never claim exact remaining credit, token price, or dollar cost unless the provider exposes it. Conservative request ceilings are not a fake balance calculator.
- Count the actual alert table (`alert_queue` in the current schema), not an assumed table name; report filtered table counts only when the excluded names are named.
- A successful suite with interpreter cleanup warnings is still a measured pass only when the exit code and assertions are captured; disclose the warning rather than calling the output pristine.
- Do NOT add a contract or enum entry to the shared provider module just because your new consumer needs a different shape — the contract set feeds a schema digest other components (Research, benchmarks, adapters) depend on, so a new entry silently invalidates their expectations. Translate through an ALREADY-REGISTERED closed enum with a deliberately PARTIAL map, and reject any option with no honest equivalent instead of rounding it to the nearest one; assert an unmapped option is rejected so the partial map cannot quietly grow into a lossy catch-all.
- The provider's per-run and per-day budget is usually SHARED with its first consumer. Before wiring a second consumer, state plainly that calling it spends the first consumer's budget, and leave the wiring unwired rather than silently consuming another component's allowance; an implemented-but-unwired adapter is an honest state, an unwired-but-called one is a budget theft.
- A per-run/per-day ceiling of `0` must mean "no Hermes-side cap". A `max(1, int(cfg))` clamp silently turns a configured 0 into 1, and a `count >= cap` check then refuses every call after the first. When the requirement is "call as often as the workload needs", fix the CLAMP and the COMPARISON, not the configured number: a raised number is still an arbitrary ceiling. Prove it with a same-day repeat test plus a non-vacuous control that a non-zero cap still enforces.

## Verify the request contract from the provider's own schema, not from your notes

A local docstring recording `criteria: {...}|[...]` is an assumption, not a
contract, and it survives for years because the branch that would exercise it is
rarely called. When a provider rejects a request with a validation error:

1. **Read the error's `loc` path and `type` verbatim.** `loc: [body, questions, X, criteria]`
   with `type: dict_type` names the field AND the expected JSON type. That is more
   precise than any local note, and it cost one request to obtain.
2. **Check whether the provider publishes its OpenAPI/schema document.** Most modern
   APIs serve `/openapi.json` publicly and unauthenticated. That is a read-only
   GET, costs no provider request, no key, and no quota — reach for it BEFORE
   spending a request, and before trial-and-error.
3. Only when no published schema exists, spend ONE request on the corrected shape
   justified by the error. Never send multiple candidate payloads to discover a
   schema.
4. The proven fact is often narrower than it looks: "this field must be a dict,
   not an array" can be certain while "this is the exact nesting the provider
   wants" is not. Report the certain part as certain and list the unproven part.

Then:

- **Fix the representation at ONE builder and route every call site through it.**
  When the same payload is constructed in two transports, a fix applied to one
  leaves the other broken; a shared builder makes the drift impossible. A builder
  that takes a bare string will iterate it character-by-character — reject a
  string explicitly rather than producing a `KeyError` on the first letter.
- **Classify a validation status as a contract failure, not an outage.** A
  4xx-body-validation status falling through to a generic `UNAVAILABLE` state is
  how a deterministic client bug gets recorded as a flaky provider and retried for
  days. Give it a name in the EXISTING state vocabulary, assert it arms no
  cooldown and no retry, and leave the neighbouring status mappings byte-identical
  unless the milestone's scope covers them — an unrelated status remap will fail an
  existing suite and tempt you to retarget the test instead of reverting.
- After fixing, **re-run a request that the final code produces**, or prove the
  generated payload is byte-identical to the one that succeeded. A live result
  obtained before the last edit does not certify the final state.

## A request that is refused is a result to classify, not a failure to retry

Persist the failure class, and make sure a contract error cannot be mistaken for
capacity pressure: distinguish "the provider said our request is malformed" from
"the provider is busy" and from "we are rate limited". Only the last two justify a
backoff. When a client-side error is misclassified as transient, the state machine
degrades and the next legitimate caller inherits someone else's mistake.
- A provider call added to a pipeline must be isolated so an absent, slow, failing, or malformed answer degrades to the DETERMINISTIC result that was computed first, and the deterministic result must be what the pipeline uses whenever the provider is unavailable. Test the timeout by making the provider overrun a bounded thread, not by asserting the elapsed wall clock.
 - If evidence was generated before a later source edit, invalidate and regenerate the evidence/report; do not patch a stale PASS label.

## Verification recipe

Use a small read-only script after the final edit to record:

```text
service state and PID
PRAGMA quick_check
raw tables = COUNT(sqlite_master type='table')
filtered tables = raw minus explicitly named bookkeeping tables
exact counts for research runs/articles/analyses/retries/patterns/skills/candidates
exact counts for provider runs/requests/failures/state
Research-specific deltas versus baseline
protected SHA-256 aggregates
CPU/RSS/FD/runtime sample
report headings and terminal-key presence
```

Do not use the presence of a mock fallback, a successful provider response, or a zero Research delta as a substitute for each individual check.
