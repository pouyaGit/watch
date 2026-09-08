# Bounded Provider Retry Policy — Implementation Report

Date: 2026-09-06
Stage: NEXT research-only engineering stage after frozen fail-soft/degraded
mode and frozen provider-health aggregate telemetry.
Status: Implemented, tested (184 tests green), offline only. Not committed.

## 1. Exact files changed

New (previously implemented in workspace, verified + fixed in this task):

- `ai/researcher/retry_policy.py` — the ONLY new production module.
  Single-purpose 429-only policy: `is_retryable_429()`,
  `clamp_retry_delay()`, `empty_retry_histogram()`,
  `sleep_before_429_retry()`. This task fixed a docstring/default
  mismatch (docstring said 1.0s, code default is 2.0s).

Modified in this task:

- `ai/researcher/cve_batch.py` — batch-layer single 429 retry +
  **retry-outcome classification fix** (see §6).
- `ai/research_cli.py` — CLI-layer single 429 retry +
  **same classification fix** (see §6).
- `ai/test_provider_telemetry.py` — updated ONE stale expectation
  (`test_no_double_counting_cli_payload`, see §5); injected no-op
  sleep seam into `test_telemetry_counts_only`.
- `ai/test_provider_fail_soft.py` — behavior unchanged; injected no-op
  sleep seam into the batch `_run` helper and the CLI 429 test so the
  suite never really sleeps.

New in this task:

- `ai/test_provider_retry.py` — 29 focused tests covering all 14
  required scenarios at both CLI and batch layers.

Verified unchanged (frozen contracts intact):

- `ai/researcher/provider_errors.py` — `classify_provider_failure()`,
  `outage_bucket_for_info()`, `OUTAGE_BUCKETS`,
  `empty_outage_histogram()` untouched.
- `ai/researcher/degraded.py` — fail-soft builders untouched.
- Nuclei lane (`run_nuclei_offline_stage`, `NucleiPipeline`,
  `prepare_for_watch` never referenced from `cve_batch.py`) untouched.
- No changes to `ns/`, `crawl/`, `database/`, Nuclei/CVE execution, no
  second provider, no `ai_data/` or `agent-reports/` artifacts touched
  by tests (temp dirs only).

## 2. Retry policy (as implemented)

- HTTP 429 → exactly ONE additional attempt, no loop, no counter, no
  policy table: straight-line code (`initial call → sleep → second
  call → done`). `is_retryable_429()` returns True only for
  transient results with `status_code == 429`.
- Retry success → `research_status="completed"`, `llm_status="ok"`,
  the genuine `ResearchResult.model_dump()` preserved (provenance
  honest, nothing faked).
- Retry transient failure (429/402/5xx/network) → existing degraded
  path (`completed_degraded`, `authoritative=False`,
  `research_only=True`, `nuclei_candidate=False`).
- Retry programming/non-transient error → re-raised (CLI, caller sees
  `failed`) / recorded `failed` (batch). Never hidden.
- HTTP 402 / 5xx / network-timeout / programming errors on the FIRST
  attempt → immediate existing degraded/failed path, zero retry calls.
- `--skip-llm` → LLM never invoked, no retry keys set beyond
  `retry_attempted=False`, counters zero.
- Layering invariant (exactly one retry per CVE globally): the CLI
  converts every 429 into a payload (never propagates), so the batch
  layer only retries 429s raised directly by its injected
  `research_fn` — which the real CLI never produces. The two layers
  can never stack. Mixed-batch test asserts per-CVE call counts
  (`{retried: 2, others: 1}`).

## 3. Backoff implementation / default

- `sleep_before_429_retry(delay=None, sleep_fn=None)` is the single
  seam. Default delay `DEFAULT_RETRY_429_DELAY_SECONDS = 2.0`,
  hard cap `MAX_RETRY_429_DELAY_SECONDS = 5.0` via `clamp_retry_delay`
  (negative → 0.0, NaN/garbage → default, huge → cap).
- Rationale for 2.0s: 429 signals a rate-limit bucket; one short
  pause gives the provider bucket time to refill without stalling the
  batch, while the worst-case overhead stays bounded at ~2s per
  429 CVE. Deliberately NOT exponential — there is no second retry for
  backoff to serve.
- Injectability: batch layer takes `retry_sleep_fn` /
  `retry_429_delay` parameters; CLI layer keeps its frozen
  `_research_single_cve(cve_id, skip_llm)` signature and the seam is
  the module-level `sleep_before_429_retry` import, patchable at
  `ai.researcher.retry_policy.sleep_before_429_retry` (the CLI imports
  it at call time, so patching works). All tests inject recorders /
  no-ops: the full 111-test required suite runs in ~7s with zero real
  sleeps (previously ~12s+ for 35 tests due to real 2s sleeps).
- Tests assert: seam called exactly once with the configured delay
  for 429; never called for 402/5xx/network/programming/success/
  skip-llm; configured delay `0.25` passes through; `9999` clamps to
  `5.0`.

## 4. Telemetry semantics

- Existing `provider_outages = {http_402, http_429, http_5xx, network}`
  schema UNCHANGED (keys, order, zeroed-always-present). No
  per-CVE retry keys in any aggregate output (`RESULT_KEYS` unchanged;
  asserted by test).
- New aggregate-only `provider_retries = {attempted, succeeded,
  exhausted}`, always present, zeroed when no retry occurs.
  `attempted` = CVEs where the single 429 retry was actually attempted
  (≤ number of CVEs by construction — exactly one sink entry per CVE);
  `succeeded` = retry converted the CVE to `completed`; `exhausted` =
  retry attempted without successful research. Counts only, no
  payloads/secrets.
- `provider_outages` counts provider failures ENCOUNTERED, not final
  status: initial 429 always increments `http_429` once; a failed
  retry increments its own bucket again (429→429 gives `http_429=2`;
  429→503 gives `http_429=1, http_5xx=1`; 429→network gives
  `http_429=1, network=1`); retry success erases nothing
  (`http_429` stays 1). No double counting: each outage EVENT is
  tallied exactly once — the CLI emits an ordered `outage_events`
  list plus the single `outage_bucket` stamp, and the batch tallies
  stamped events without re-classifying messages (fallback
  classification only for pre-stamp legacy payloads).
- On the per-CVE CLI payload keys (`outage_events`,
  `retry_attempted`, `retry_succeeded`): these are inter-layer
  propagation fields, NOT telemetry — they are the minimal mechanism
  by which the batch layer tallies each event exactly once across the
  CLI/batch boundary. The aggregate output (the actual telemetry)
  remains strictly aggregate-only, so no schema change was needed and
  none was made.

## 5. Pre-existing test updated (one, with justification)

- `ai/test_provider_telemetry.py::test_no_double_counting_cli_payload`
  was written pre-retry: it drives the real CLI with an always-429
  researcher and asserted `http_429 == 1`. Under the specified retry
  semantics (initial 429 + exhausted-retry 429 = two encountered
  failures) the correct count is `http_429 == 2` — the task spec
  mandates this explicitly ("429 -> 429: ... http_429=2"), and the
  sibling test `test_429_increments_http_429` in the same file already
  expects 2. The test's anti-double-counting PURPOSE is preserved and
  strengthened: it now asserts `outage_events == [http_429, http_429]`,
  aggregate `http_429 == 2` with total exactly 2 (no third count from
  stamp+fallback stacking), `provider_retries == attempted:1 /
  exhausted:1`, and exactly one seam sleep (patched, no real sleep).
  Before this update it was the single failure in the suite; after,
  all green.

## 6. Bug found and fixed during this task

- Symptom: new tests `test_429_then_network` (batch) and
  `test_cli_429_then_network_degraded` (CLI) observed `http_429=2,
  network=0` instead of `http_429=1, network=1`.
- Root cause: the retry call executes inside the initial-failure
  `except` block, so Python attaches the initial 429 as the retry
  exception's implicit `__context__`. `classify_provider_failure()`
  (frozen — correctly) follows `__context__` during status
  extraction, so a retry failure carrying no status of its own
  (network/timeout) inherited HTTP 429 from OUR control flow, not
  from any provider signal. (Retry failures WITH their own status,
  e.g. 503, were unaffected — own status wins.)
- Fix (in `cve_batch.py` and `research_cli.py` retry handlers only):
  detach `retry_exc.__context__` for the duration of the
  classification call, then restore it (tracebacks and re-raise
  semantics preserved). Frozen `provider_errors.py` untouched;
  first-attempt classification untouched (no control-flow artifact
  there). Both failing tests pass after the fix; all other suites
  remain green.

## 7. Proof of exactly-one retry

- Structural: straight-line code, no loop construct, no counter, no
  backoff table anywhere in `retry_policy.py` / call sites.
- Behavioral: `test_exactly_one_retry_invariant` (always-429 fake →
  exactly 2 provider calls, 1 sleep, `attempted=1`);
  `test_mixed_multi_cve_batch` asserts the exact per-CVE call map
  `{9911: 2, 9912: 2, 9913: 1, 9914: 1, 9915: 1, 9916: 1}`;
  CLI tests assert `len(calls) == 2` for retried CVEs and `== 1` for
  402/503/programming/success/skip-llm.

## 8. Exact test counts / results

New `ai/test_provider_retry.py`: 29 tests — OK (0.2s, zero sleeps).

- `RetryPolicyUnitTests` (3): 429-only retryability, zeroed schema,
  default bound + clamp.
- `BatchRetryTests` (14): scenarios 1–11 incl. mixed batch with exact
  aggregates, always-429 invariant, 429→programming-error fails
  loudly, counts-only/no-secrets telemetry.
- `CliRetryTests` (9): 429→success completed/`llm_status=ok` with
  honest provenance; 429→429/503/network degraded with exact
  `outage_events`; 402/503 no-retry-no-sleep; programming error
  raises unretried; success/skip-llm retry markers absent.
- `RetrySeamTests` (3): scenario 12 — one seam call with configured
  delay, cap enforcement, never-fired for other classes.

Required suites (one command): `ai.test_provider_fail_soft`,
`ai.test_provider_telemetry`, `ai.test_cve_batch`,
`ai.test_research_cli`, `ai.test_openrouter`, `ai.test_provider_retry`
→ **111 tests, OK (~7s)**.

Broader focused research/Nuclei suite: `ai.test_researcher`,
`ai.test_xss_researcher`, `ai.test_xss_llm_researcher`,
`ai.test_knowledge_store`, `ai.test_llm`,
`ai.test_nuclei_offline_prepare`,
`ai.test_nuclei_cve_2026_1557_dryrun` → **73 tests, OK**.

`git diff --check` on all touched files: clean.

## 9. Safety verification

- All new/updated tests block `socket.create_connection`, `socket`,
  `getaddrinfo`, `subprocess.run`, `subprocess.Popen` (raise on use);
  CLI tests inject researcher/CVE/discovery fakes and temp
  `RESEARCH_DIR`; batch tests use temp research/report dirs.
- Aggregate blobs asserted free of `sealed`, `confirmed`, `live_http`,
  `live_nuclei`, key names; per-CVE result keys unchanged.
- No `prepare_for_watch` / live target selection referenced from the
  batch lane (existing AST-guard test still green); degraded payloads
  keep `nuclei_candidate=False`; no SealedFinding/5J/CONFIRMED
  materialization anywhere in the lane.
- No commits, no pushes, no VPS/VM contact, no unrelated files
  modified (only the files listed in §1).

## 10. Limitations

- CLI backoff configurability is seam-only (patchable function), not
  a CLI flag — forced by the frozen `_research_single_cve(cve_id,
  skip_llm)` signature, which an existing test pins. Production delay
  is therefore fixed at 2.0s unless the module constant changes.
- A 429 followed by a non-transient retry error records
  `exhausted=1` alongside `failed` status (retry WAS attempted and did
  not yield research) — a judgment call, spec-silent on this combo.
- `outage_events`/`retry_attempted`/`retry_succeeded` ride on stored
  per-CVE CLI JSON artifacts; third-party hand-rolled payloads lacking
  them fall back to legacy classification (unchanged behavior).

## 11. Recommended next stage

Provider-side caching / request coalescing for duplicate CVE research
within a batch (dedupe identical LLM calls before they hit the rate
limit), reusing the same aggregate-only telemetry pattern
(`provider_cache: {hits}`) — reduces 429s at the source without
touching the frozen fail-soft/retry contracts. Explicitly NOT
recommended: broader retry (5xx/network), retry budgets, or a second
provider — all rejected by this stage's constraints for good reason.
