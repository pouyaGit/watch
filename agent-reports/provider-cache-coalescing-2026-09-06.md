# Provider-side Request Coalescing / Per-Batch CVE Research Cache — Implementation Report

Date: 2026-09-06
Stage: NEXT research-only engineering stage after frozen
fail-soft/degraded, frozen provider-health aggregate telemetry, and
frozen bounded-429-only retry policy.
Status: Implemented, tested (137+237 tests green), offline only.
Not committed.

## 1. Exact files changed

Modified in this task:

- `ai/researcher/cve_batch.py` —
  - Removed the existing input-level deduplication loop that
    silently dropped duplicate CVE entries from
    `cves_requested` / `results`. Replaced with explicit per-CVE
    normalization while preserving the full input list.
  - Added the per-batch in-memory coalescing cache (a single local
    `dict[str, dict]` created and dropped inside
    `run_cve_batch`).
  - Wired `provider_cache: {hits}` into the aggregate output
    (always present, zeroed when no hit).
  - Added the cache line to the markdown summary.

New in this task:

- `ai/test_provider_cache.py` — 26 focused tests covering all the
  scenarios in the spec.

Verified unchanged (frozen contracts intact):

- `ai/researcher/provider_errors.py` — `classify_provider_failure`,
  `outage_bucket_for_info`, `OUTAGE_BUCKETS`, the entire outage
  histogram machinery untouched.
- `ai/researcher/retry_policy.py` — `is_retryable_429`,
  `clamp_retry_delay`, `empty_retry_histogram`,
  `sleep_before_429_retry`, the bounded 429-only retry path
  untouched.
- `ai/researcher/degraded.py` — fail-soft builders untouched.
- `ai/research_cli.py` — single-CVE CLI signature and behavior
  unchanged (no cache anywhere on the CLI path).
- Nuclei lane (`run_nuclei_offline_stage`, `NucleiPipeline`,
  `prepare_for_watch` never referenced from `cve_batch.py`)
  untouched. No `RESULT_KEYS` change.

## 2. Cache scope and lifecycle

- **Scope**: strictly one `run_cve_batch` invocation. The cache
  object is a local `dict` created inside the function and
  discarded on return.
- **No module-global mutable cache**: verified by a test that
  runs the batch twice and asserts both invocations perform
  exactly one provider call each.
- **No disk persistence**: no `ai_data` cache directory; no
  aggregate cache field on disk beyond the in-memory aggregate;
  verified by a test that asserts no `*cache*` files exist
  anywhere under the temp research dir.
- **No cross-process state**: no IPC, no shared memory, no env
  variable, no Mongo, no Redis. The cache lives only in the
  calling process and only for the duration of one batch.
- **Single-CVE CLI path**: unchanged. `ai.research_cli.research`
  / `_research_single_cve` does not import or consult the cache
  (a test asserts the CLI signature is still
  `(cve_id, skip_llm)` and that two CLI invocations
  independently invoke the provider).

## 3. Cache key and normalization

- **Key**: the normalized CVE identifier — same
  `(raw or "").strip().upper()` rule the existing
  `run_cve_batch` already used (no new normalization
  algorithm).
- The same key is used for the cache lookup, the research
  function call, the `cves_requested` entries, and the per-CVE
  result `cve` field, so a duplicate cannot end up under
  different keys.

## 4. Duplicate semantics (option A)

`cves_requested` keeps the **original** requested list (full
length, including duplicates), per the documented A semantics.
`results` is parallel to `cves_requested` (same length, same
order). The cache hit is reported separately via
`provider_cache.hits`. Existing behavior that silently
deduplicated the input list was intentionally removed: the
spec says "Later occurrence of the same normalized CVE-X must
reuse the already-produced research outcome" — that requires
the duplicate to still surface in the output so the caller can
see it was processed.

## 5. Retry interaction

- The first occurrence of a CVE gets the frozen bounded-429
  retry policy exactly as before. If the first attempt 429s
  and the retry succeeds, the cached value is the
  `completed` result. If the retry exhausts or fails with a
  different transient, the cached value is the
  `completed_degraded` result.
- A duplicate CVE never triggers an additional LLM call. The
  total provider call count for a batch of N duplicates of the
  same CVE is **2** (initial + retry) or **1** (success on
  first attempt), never `2N` or `N`.
- Tests prove this: `test_429_then_success_then_duplicate`
  asserts exactly 2 calls + 2 hits for 3 entries;
  `test_429_exhausted_then_duplicate` asserts exactly 2 calls
  + 1 hit; `test_429_then_503_then_duplicate` and
  `test_429_then_network_then_duplicate` assert the same
  (no extra calls).

## 6. Hard-failure behavior (documented choice)

**Programming / non-transient failures are NOT cached.** A
duplicate of a failed CVE simply re-runs the normal research
flow. Rationale:

1. The frozen `failed` contract (`research_status="failed"`,
   `error` set, no degraded fallback) is a loud, observable
   state. Caching it would hide a programming bug from the
   caller and risk poisoning a batch with a stale failure
   after the underlying issue is fixed mid-batch.
2. The cache is only useful for **terminal** LLM outcomes
   (`completed` and `completed_degraded`) where the result is
   deterministic for a given CVE in the run. A programming
   error is by definition non-deterministic and may be
   transient (e.g. a flaky local file or a brief missing
   dependency).
3. The spec explicitly allows "Prefer NOT caching hard failures
   unless the existing architecture strongly requires it." It
   does not.

The new tests `test_programming_error_not_cached_duplicate_replays`
and `test_persistent_hard_failure_stays_failed` lock this
behavior in: a first-call `TypeError` stays failed; if a
duplicate happens to succeed on retry, the second entry
reflects the success; a persistently failing CVE never
registers a cache hit and is recorded as `failed` N times.

## 7. Artifact behavior

A duplicate CVE reuses the original artifact reference
(`item["artifacts"]["research"]` from the first occurrence).
`run_cve_batch` writes one `ai_data/research/<CVE>.batch.json`
file per **result** entry (so duplicate CVEs each get a file
pointing at the same research artifact), but no extra
`ai_data/research/<CVE>.cli.json` is produced for the
duplicate — that file is written once, by the first
occurrence's normal `research_one_cve` flow. There is no
duplicate Nuclei generation, no duplicate offline
preparation, no duplicate template validation.

## 8. Telemetry schema

- **`provider_outages`** (existing, frozen): unchanged. The
  histogram counts provider failures **encountered** by
  actual first-occurrence research. A cache hit is not a
  provider event. The `provider_outages_retry_counts_unchanged_by_cache`
  test asserts the histogram for a
  `429-429-429` batch of the same CVE is
  `http_429: 2` (initial + exhausted retry), exactly the same
  as if the duplicate had not existed.
- **`provider_retries`** (existing, frozen): unchanged. Only
  the first occurrence of a CVE contributes a retry event;
  duplicates never add to the retry counter.
- **`provider_cache`** (new): always present, single key
  `hits`, integer count, zeroed when no hit. No CVE IDs, no
  payloads, no secrets, no error text — counts only.
- **`RESULT_KEYS`** unchanged: no per-CVE cache field added.
  Aggregate-only telemetry as specified.
- Markdown summary gained a `provider_cache: hits=N` line.

## 9. Exact test counts / results

- New `ai/test_provider_cache.py` — **26 tests, OK (~0.2s)**
  organized as:
  - `BasicCoalescingTests` (3)
  - `MultipleDuplicatesTests` (2)
  - `MixedBatchTests` (2)
  - `RetryInteractionTests` (4)
  - `StatusPreservationTests` (2)
  - `HardFailureTests` (2)
  - `CacheScopeTests` (3)
  - `CliCacheTests` (2)
  - `TelemetryTests` (6) including a
    `telemetry_counts_only_no_secrets_no_cve_ids` scan.
- Required suite (one command):
  `ai.test_provider_fail_soft`,
  `ai.test_provider_telemetry`, `ai.test_provider_retry`,
  `ai.test_cve_batch`, `ai.test_research_cli`,
  `ai.test_openrouter`, `ai.test_provider_cache` →
  **137 tests, OK (~7.6s)**.
- Broader focused research/Nuclei suite (10 files):
  `ai.test_researcher`, `ai.test_xss_researcher`,
  `ai.test_xss_llm_researcher`, `ai.test_knowledge_store`,
  `ai.test_llm`, `ai.test_nuclei_offline_prepare`,
  `ai.test_nuclei_cve_2026_1557_dryrun`,
  `ai.test_research_pattern`, `ai.test_artifact`,
  `ai.test_pattern_projector` → **237 tests, OK**.
- `git diff --check` on touched files: clean.

## 10. Proof of no cross-batch cache

- `test_two_separate_batches_do_not_share_cache` runs the
  same research_fn twice (with the same duplicate CVE) and
  asserts both runs perform exactly 1 provider call each, with
  `provider_cache.hits == 0` for both. If the cache were a
  module global, the second run would either share the first
  run's call (zero calls) or maintain hit state from the
  first run.
- `test_no_module_global_mutable_cache` runs two duplicate
  batches consecutively and asserts each independently sees
  exactly one provider call and one cache hit — a global
  cache would make the second batch's duplicate a "miss"
  (no provider call, no hit) or vice versa.
- `test_cache_object_not_persisted_to_disk` asserts no
  `*cache*` files anywhere under the temp research dir, and
  no on-disk cache under the cwd's `ai_data/`.

## 11. Safety verification

- All tests block `socket.create_connection`, `socket`,
  `getaddrinfo`, `subprocess.run`, `subprocess.Popen`
  (raise on use). CLI tests inject researcher/CVE/discovery
  fakes and temp `RESEARCH_DIR`. Batch tests use temp
  research/report dirs.
- Aggregate blobs asserted free of `sealed`, `confirmed`,
  `live_http`, `live_nuclei`, `ready_for_scan`, and key
  names; per-CVE result keys unchanged.
- No `prepare_for_watch` / live target selection referenced
  from the batch lane; degraded payloads keep
  `nuclei_candidate=False`; no SealedFinding/5J/CONFIRMED
  materialization anywhere in the lane.
- No commits, no pushes, no VPS/VM contact, no unrelated
  files modified.
- The CLI `_research_single_cve` signature remains exactly
  `(cve_id, skip_llm)` — asserted by
  `test_cli_research_single_signature_unchanged`. The
  `inspect.signature` test in `test_cve_batch.py` is
  preserved (still passes).

## 12. Limitations

- The cache is an in-memory dict inside the batch function —
  it is not thread-safe (no locks). Single-threaded batch
  use only, which matches the existing batch lane.
- A duplicate of a failed CVE re-runs the normal research
  flow, which costs one extra `research_fn` call per
  duplicate. This is the documented anti-poisoning choice;
  callers that need a faster path should fix the underlying
  failure or remove duplicates from the input.
- A CVE that transitions from `completed` to
  `completed_degraded` (impossible with the current flow,
  since status is fixed at first execution) would not be
  re-cached; the spec is silent on this and the frozen
  retry policy does not produce such a transition.
- The cache is per-process. Two parallel batch invocations
  in the same process would each have their own cache,
  which is correct (independent batches) but does not
  coalesce across them.

## 13. Recommended next stage

Lightweight intra-batch cross-CVE reference-context reuse:
if multiple CVEs in the same batch share reference URLs
(very common in the XSS and CVE-2026-1557 cases already
studied), fetch/discover once and reuse the
`ReferenceContext` across CVEs. Reuses the same
aggregate-only telemetry pattern (`provider_dedup` or
extend `provider_cache` with `reference_reuse`).
Explicitly NOT recommended: cross-batch persistence (would
invalidate the "one research call per CVE per batch"
contract), broadening retry policy, or introducing a second
provider — all rejected by this stage's constraints for good
reason.
