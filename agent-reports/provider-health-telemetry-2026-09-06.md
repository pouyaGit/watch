# Provider Health Telemetry — Implementation Report

Date: 2026-09-06
Mode: research-only, dry-run. WSL-only. No commit. No push.
Prior stage contract (fail-soft/degraded mode) unchanged.

## 1. Files changed

- MOD `ai/researcher/provider_errors.py` — added aggregate-only
  telemetry helpers reusing the existing classifier:
  `OUTAGE_BUCKETS`, `empty_outage_histogram()`,
  `outage_bucket_for_info(info)`. No classifier logic touched.
- MOD `ai/research_cli.py` — `_research_single_cve` stamps a single
  machine-readable `outage_bucket` on the payload (`None` on
  success/`--skip-llm`, bucket string on degraded). Fail-soft
  semantics, payload shapes, and Nuclei behavior untouched.
- MOD `ai/researcher/cve_batch.py` — `research_one_cve` accepts an
  optional `outage_sink` list (one entry per CVE: bucket or `None`);
  `run_cve_batch` tallies it into aggregate `provider_outages`;
  `write_batch_markdown` adds one telemetry line. Per-CVE
  `RESULT_KEYS` unchanged. No Nuclei execution changes, no
  retry/backoff, no second provider.
- NEW `ai/test_provider_telemetry.py` — 18 focused offline unittests.

No changes to `ns/`, `crawl/`, `database/`, providers, credentials,
or Nuclei execution semantics.

## 2. Telemetry schema

Aggregate JSON gains one always-present field:

```json
"provider_outages": {
  "http_402": 0,
  "http_429": 0,
  "http_5xx": 0,
  "network": 0
}
```

- Counts only: plain integers, one per outage class per batch.
- No exception payloads, no provider response bodies, no API
  keys/secrets, no CVE-specific sensitive text (asserted: aggregate
  blob contains none of `sk-or`, `openrouter_api_key`,
  `watch_mongo_uri`, `sealed`, `confirmed`, `live_http`,
  `live_nuclei`).
- Stable schema: emitted zeroed when no outage occurs.
- Per-CVE results carry no new keys (`RESULT_KEYS` tuple asserted
  unchanged in tests); telemetry is aggregate-only.
- Markdown report keeps all existing lines and adds exactly one:
  `- provider_outages: http_402=X http_429=Y http_5xx=Z network=W`.

## 3. Classification mapping

Single mapping function `outage_bucket_for_info(info)` over the
EXISTING `ProviderFailureInfo` — no second classification system:

| classifier result | bucket |
| --- | --- |
| transient, HTTP 402 | `http_402` |
| transient, HTTP 429 | `http_429` |
| transient, HTTP 500/502/503/504 | `http_5xx` |
| transient, timeout/network (`network_timeout`, no status) | `network` |
| non-transient / programming error | none (`None`) |
| successful LLM call | none |
| `--skip-llm` | none |

Both degraded paths use it: the CLI stamps
`outage_bucket_for_info(info)` at classification time; the batch
exception path calls the same function on the same classifier
output. For degraded payloads that predate the stamp (hand-rolled
or legacy), `_fallback_outage_bucket` re-wraps the recorded
`llm_error` message in the provider error type and runs it through
the SAME `classify_provider_failure` — counts only, message never
stored.

## 4. How double counting is prevented

- Exactly one tally point per CVE: `research_one_cve` appends
  exactly one entry (bucket or `None`) to `outage_sink` on every
  return path (invalid format, non-transient, transient-raise,
  degraded-payload, success).
- The two surfacing routes are mutually exclusive per CVE: either
  `research_fn` raises (batch classifies + tallies once) or it
  returns a payload (batch tallies the stamp once). The CLI layer
  only stamps — it never aggregates — so a failure passing through
  both layers is counted once.
- Verified end-to-end: real `_research_single_cve` with an injected
  HTTP 429 failure produces a payload stamped `http_429`; feeding
  that payload through `run_cve_batch` yields
  `http_429 == 1` and histogram sum `== 1`.

## 5. Batch semantics (preserved)

- `processed = completed + completed_degraded` (unchanged).
- `failed = actual failed only` (unchanged).
- Exit code: `0` iff `failed == 0` (unchanged).
- Existing aggregate keys (`batch_version`, `generated_at`, `mode`,
  `authoritative`, `cves_requested`, `completed`,
  `completed_degraded`, `processed`, `failed`, `results`,
  `artifacts`) all preserved; `provider_outages` is additive.
- Degraded contract intact: `authoritative=False`,
  `research_only=True`, `nuclei_candidate=False`, no live execution.

## 6. Exact test counts/results

New suite `ai.test_provider_telemetry`: **18 tests, all pass**.

- Mapping (6): stable key order, 402→`http_402`,
  429→`http_429`, each of 500/502/503/504→`http_5xx`,
  network/timeout→`network`, non-transient (401/404/TypeError/
  ValueError-JSON/RuntimeError)→`None`.
- Batch (12): 402/429/each-5xx/network increment exactly their
  bucket; programming error, success, and `--skip-llm` leave a
  zeroed histogram; mixed 6-CVE batch
  (402+429+5xx+network+hard-failure+success) yields
  `{http_402:1, http_429:1, http_5xx:1, network:1}` with
  completed=1/completed_degraded=4/failed=1/processed=5;
  CLI→batch no-double-count; zero-outage zeroed histogram;
  counts-only + `RESULT_KEYS` unchanged; markdown outage line.

Regression:

- Required set (`test_provider_fail_soft`,
  `test_provider_telemetry`, `test_cve_batch`,
  `test_research_cli`, `test_openrouter`): **82 tests, OK**
  (fail-soft 17/17 still pass — semantics unchanged).
- Broader focused research/Nuclei suite (+ `test_knowledge_store`,
  `test_xss_researcher`, `test_xss_llm_researcher`,
  `test_nuclei_offline_prepare`, `test_nuclei_ready`,
  `test_correlation`, `test_research_pattern`):
  **204 tests, OK**.
- `git diff --check` on all touched files: clean.

## 7. Safety verification

- Offline only: new tests patch `socket`/`subprocess` for the
  mixed-batch run; telemetry paths perform no I/O beyond the
  existing JSON/markdown artifact writes.
- No target-side requests, no Nuclei execution (offline
  decision lane only), no browser, no DNS probing.
- No 5J, no SealedFinding, no CONFIRMED, no
  `LIVE_HTTP`/`LIVE_NUCLEI` (asserted on the aggregate blob).
- No retries/backoff added; no second provider; no secrets added.

## 8. Limitations

- Histogram is per-batch and in-memory; cross-batch trending
  requires a future aggregator reading the persisted aggregate
  JSON files.
- Unstamped degraded payloads rely on message re-wrap fallback;
  a degraded payload with an empty/garbled `llm_error` and no
  stamp counts nothing (fail-safe undercount, never a
  misattribution).
- Buckets are coarse by design (`http_5xx` groups four codes);
  per-code drill-down is intentionally omitted for this stage.

## 9. Recommended next stage

Build a bounded retry-budget policy driven by this telemetry:
e.g. `http_429` → honor a single capped backoff retry within the
same run before degrading; `http_402` → degrade immediately, never
retry (billing signal); `http_5xx`/`network` → degrade immediately
in-batch but flag the batch for a scheduled re-run. Keep the
fail-soft contract and this histogram schema frozen while adding
the policy, so retry effectiveness can be measured as
`completed_degraded → completed` conversions per bucket.
