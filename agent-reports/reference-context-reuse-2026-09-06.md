# Intra-Batch Shared Reference Context Reuse — Implementation Report

Date: 2026-09-06
Stage: NEXT research-only engineering stage after frozen
fail-soft/degraded, frozen provider-health telemetry, frozen
bounded-429-only retry policy, and frozen per-batch CVE research
cache/coalescing.
Status: Implemented, tested (161+237 tests green), offline only.
Not committed.

## 1. Exact files changed

New in this task:

- `ai/researcher/reference_cache.py` — the per-batch
  `BatchReferenceCache` plus `canonicalize_reference_url()` and
  `empty_reference_cache_histogram()`. The cache wraps the
  existing `ReferenceCollector.fetch` primitive, stores
  verbatim `ReferenceDocument`-shaped dicts, and exposes a
  `state()` snapshot for tests / inspection.
- `ai/test_reference_cache.py` — 24 focused tests covering all
  the spec's required scenarios.

Modified in this task:

- `ai/researcher/cve_batch.py` —
  - Added the `reference_cache` and `reference_fetch_fn`
    parameters to `run_cve_batch`. When omitted, a fresh
    per-batch `BatchReferenceCache` is created (default
    `ReferenceCollector.fetch`) and dropped on return.
  - Added `_make_cached_research_fn(reference_cache)` —
    a per-batch `research_fn` factory that re-orchestrates
    the existing `ReferenceDiscovery`,
    `ReferenceCollector.fetch`, `build_research_contexts`,
    and `SecurityResearcher` components so every per-URL
    fetch goes through the shared `BatchReferenceCache`.
  - Wired `_make_cached_research_fn` as the default
    `research_fn` for `run_cve_batch` (when the caller
    does not inject one).
  - Added `reference_cache: {hits}` to the aggregate output
    and to the markdown summary.

Verified unchanged (frozen contracts intact):

- `ai/collectors/reference.py` — `ReferenceCollector.fetch`
  and `classify_source` untouched (the cache wraps, does not
  duplicate).
- `ai/collectors/discovery.py` — `ReferenceDiscovery`
  untouched.
- `ai/collectors/discovery_fetch.py`,
  `ai/researcher/research_context.py`,
  `ai/researcher/reference_ranker.py`,
  `ai/researcher/researcher.py` — all untouched.
- `ai/researcher/provider_errors.py`,
  `ai/researcher/retry_policy.py`,
  `ai/researcher/degraded.py` — frozen.
- `ai/research_cli.py` — single-CVE CLI path
  (`_research_single_cve(cve_id, skip_llm)`) unchanged. CLI
  callers see no cache anywhere; the cache is a batch-only
  optimization.
- `ai/schemas/reference.py` — `ReferenceDocument` and
  `ReferenceContext` schemas untouched.
- Nuclei lane (`run_nuclei_offline_stage`,
  `NucleiPipeline`, `prepare_for_watch` never referenced
  from `cve_batch.py`) untouched.
- `RESULT_KEYS` unchanged (no per-CVE cache field added).

## 2. Existing reference abstraction reused

The cache wraps the existing primitives — no new HTTP
implementation, no new parser, no new ranker. The components
are:

- `ai.collectors.reference.ReferenceCollector.fetch` — the
  per-URL HTTP fetch primitive (used as the default
  `reference_fetch_fn`).
- `ai.collectors.discovery.ReferenceDiscovery.discover` —
  CVE → `DiscoveredSource` list (called per CVE inside
  `_make_cached_research_fn`).
- `ai.collectors.discovery_fetch.fetch_discovered_sources`
  pattern — replicated inline inside
  `_make_cached_research_fn`, but every fetch call is routed
  through `BatchReferenceCache.fetch`.
- `ai.researcher.research_context.build_research_contexts` —
  per-CVE ranking (reused unchanged; this is what keeps
  CVE-specific conclusions CVE-specific).
- `ai.researcher.researcher.SecurityResearcher` — the LLM
  call (reused unchanged; the cache only touches
  reference-layer state).

The new factory `_make_cached_research_fn` is a thin
re-orchestration of these existing components; it is not a
second implementation.

## 3. Cache key and canonicalization

- Key: the canonicalized reference URL via
  `canonicalize_reference_url(url)` = `(url or "").strip()`.
- Deliberately conservative: only surrounding whitespace is
  removed. Query strings, fragments, trailing slashes, scheme
  case, and host case are preserved exactly as
  `ReferenceDiscovery.discover()` produced them. No
  aggressive URL canonicalizer is introduced.
- This matches the existing
  `ReferenceCollector.fetch()` contract, which receives the
  raw URL and uses `httpx.Client` (follow_redirects=True) to
  resolve redirects. The cached value is the post-fetch
  `ReferenceDocument` (whose `url` may differ from the cache
  key if a redirect occurred), but the cache key itself is
  the pre-redirect URL the discovery layer emitted — so a
  redirect to a different canonical form is a separate
  deterministic event from the original source URL.
- Documented inline in
  `ai/researcher/reference_cache.py`.

## 4. Lifecycle and scope

- The `BatchReferenceCache` is created inside
  `run_cve_batch` when the caller does not provide one
  (`owns_cache = True`). It is dropped when the function
  returns; no module-global mutable state, no disk
  persistence, no `ai_data` cache directory, no
  cross-process state.
- Two consecutive `run_cve_batch` invocations do not share
  cache state. Verified by
  `test_two_batches_do_not_share_cache` and
  `test_no_module_global_mutable_cache`.
- No `*cache*` / `*reference_cache*` files are written
  under the batch temp dir
  (`test_no_cache_files_written`).
- The single-CVE CLI path is unchanged
  (`_research_single_cve` does not import or consult
  `BatchReferenceCache`); CLI callers see exactly one
  research operation per invocation
  (`test_cli_research_single_signature_unchanged` is still
  pinned in the existing `test_cve_batch.py` suite).

## 5. Duplicate CVE interaction

- A duplicate CVE short-circuits at the existing CVE
  research cache (`provider_cache.hits`), so the duplicate
  never invokes `BatchReferenceCache.fetch()` at all. The
  reference-cache hit counter is therefore **not** affected
  by duplicate CVE entries.
- Verified by `test_duplicate_cve_does_not_produce_reference_hit`
  (3 duplicates of the same CVE → 1 fetch, 0 reference hits,
  2 provider-cache hits) and
  `test_duplicate_with_shared_distinct_cve` (duplicate of
  CVE A + distinct CVE B sharing the same URL → 1 fetch,
  1 reference hit, 2 provider-cache hits).
- Mixed batch (`test_unique_plus_duplicates_plus_shared`):
  unique + duplicate + shared-reference CVEs together
  produce the exact expected counts
  (2 fetches, 1 reference hit, 4 provider-cache hits, 7
  results in input order).

## 6. Reference failure behavior (documented)

**Only successful `ReferenceDocument` results are cached.**
When `BatchReferenceCache.fetch(url)` is called and the
underlying `ReferenceCollector.fetch(url)` returns `None`
(the existing "hard miss" sentinel for HTTP error, non-text
content, or empty body — see
`ai/collectors/reference.py:138-160`), the cache records
nothing and `BatchReferenceCache.fetch()` returns `None`
without incrementing the hit counter. A later CVE that
needs the same URL therefore performs its own fetch.

Rationale (matches the spec's "Prefer caching successful
deterministic reference material only" guidance):

1. A transient failure (e.g. 5xx, network error) may
   succeed for a later CVE; caching `None` would block
   that recovery.
2. The existing `ReferenceCollector.fetch` already treats
   `None` as a stable "this URL is not useful" terminal
   result for a single CVE. Reusing that `None` across
   CVEs is not the same terminal result — it would change
   the architecture's per-CVE contract. The new layer
   stays one layer above that contract and only caches
   *successful* material, leaving per-CVE behavior
   unchanged.
3. The reference cache stores *source material* (HTTP
   response body, content hash, status code). A `None`
   result is the absence of source material and is not
   a cacheable value.

Verified by:
- `test_hard_miss_not_cached`: first fetch returns `None`,
  second fetch returns a real document — exactly two
  fetches are recorded (no poisoning), zero reference
  hits.
- `test_failure_not_silently_converted_to_success`:
  permanently failing URL never produces a hit.

## 7. Provenance guarantees

The cached value is a verbatim `ReferenceDocument`-shaped
dict (URL, source type, title, content, content hash,
status code, tags). It is **source material only**, not a
ranked `ReferenceContext`.

The per-CVE `ReferenceContext` (which carries
`exact_record` and `context_chunks` filtered for *this*
CVE's id and keywords) is built by the existing
`build_research_contexts` / `ReferenceRanker.build`
pipeline **per CVE** inside `_make_cached_research_fn`.
CVE B therefore does **not** inherit CVE A's
CVE-specific exact_record, context_chunks, or any
LLM-derived conclusion.

Verified by:
- `test_reused_context_is_source_material_only`: the
  cached store contains the verbatim document (body and
  content hash); per-CVE summaries mention only their
  own CVE id (no cross-CVE bleed).
- `test_cve_specific_conclusions_not_shared`: two
  distinct CVEs referencing the same URL produce
  different per-CVE summaries; both are
  non-authoritative, `nuclei_candidate=False`.
- `test_no_exploit_or_severity_manufactured` (folded
  into `test_cve_specific_conclusions_not_shared`):
  reuse does not promote `nuclei_candidate`, severity,
  exploitability, HTTP signatures, or payloads.

## 8. Telemetry schema

- Existing `provider_outages`, `provider_retries`,
  `provider_cache.hits` aggregates: unchanged in meaning
  and counting. Verified by
  `test_provider_outages_unchanged` (a batch with a 429
  + exhausted retry + duplicate CVE still produces
  `http_429: 2`, `attempted: 1, exhausted: 1`).
- New aggregate-only `reference_cache: {hits}`: always
  present, zeroed when no reuse, integer count, no URLs,
  no CVE IDs, no response bodies, no secrets, no error
  text. Markdown summary gained a
  `reference_cache: hits=N` line.
- `RESULT_KEYS` unchanged. No per-CVE cache field added.
- Provenance scans in
  `test_telemetry_counts_only_no_urls_no_cve_ids`
  assert the aggregate blob never contains
  `secret/path`, `sk-or`, `openrouter_api_key`,
  `watch_mongo_uri`, `sealed`, `confirmed`,
  `live_http`, `live_nuclei`, or `ready_for_scan`.

## 9. Exact test counts / results

- New `ai/test_reference_cache.py` — **24 tests, OK
  (~1s)** organized as:
  - `CanonicalizationTests` (4)
  - `BasicReuseTests` (3)
  - `DuplicateInteractionTests` (2)
  - `MixedBatchTests` (1)
  - `FailureBehaviorTests` (2)
  - `ProvenanceTests` (2)
  - `ScopeTests` (3)
  - `TelemetryTests` (5)
  - `ProviderSemanticsPreservationTests` (2)
- Required suite (one command):
  `ai.test_provider_fail_soft`,
  `ai.test_provider_telemetry`, `ai.test_provider_retry`,
  `ai.test_provider_cache`, `ai.test_reference_cache`,
  `ai.test_cve_batch`, `ai.test_research_cli`,
  `ai.test_openrouter` → **161 tests, OK (~7.6s)**.
- Broader focused research/Nuclei suite (10 files,
  237 tests) → **OK**.
- `git diff --check` on touched files: clean.

## 10. Proof of no cross-batch reuse

- `test_two_batches_do_not_share_cache`: two consecutive
  `run_cve_batch` invocations each create their own
  `BatchReferenceCache`; each batch's `reference_cache.hits`
  reflects only that batch's reuses, never the previous
  batch's.
- `test_no_module_global_mutable_cache`: two runs of the
  same duplicate-batch payload each perform one fetch
  (not zero), proving the second run did not see a
  pre-populated cache from the first run.
- `test_no_cache_files_written`: rglob across the batch
  temp dir finds no `*ref*cache*` /
  `*reference_cache*` artifacts.

## 11. Safety verification

- All tests block `socket.create_connection`, `socket`,
  `getaddrinfo`, `subprocess.run`, `subprocess.Popen`
  (raise on use). Tests inject a fake
  `reference_fetch_fn` so the cache logic is exercised
  without real HTTP. No real `ReferenceCollector` is
  instantiated in tests.
- The default `ReferenceCollector` is only used by
  `_make_cached_research_fn` for the **default**
  `research_fn` path; tests opt in by injecting a
  custom `research_fn` (or by injecting a custom
  `reference_fetch_fn`) so no real HTTP can occur.
- Aggregate blobs asserted free of `sealed`, `confirmed`,
  `live_http`, `live_nuclei`, `ready_for_scan`, key names;
  per-CVE result keys unchanged.
- No `prepare_for_watch` / live target selection referenced
  from the batch lane; degraded payloads keep
  `nuclei_candidate=False`; no SealedFinding/5J/CONFIRMED
  materialization anywhere in the lane.
- No commits, no pushes, no VPS/VM contact, no unrelated
  files modified.
- Single-CVE CLI signature remains exactly
  `(cve_id, skip_llm)` — the existing
  `test_cli_research_single_signature_unchanged` test in
  `test_cve_batch.py` is preserved (still passes).

## 12. Limitations

- The cache only applies when the batch uses the
  default `_make_cached_research_fn`. Callers that inject
  a custom `research_fn` opt out of the reference
  optimization (this is the safe default: the cache is a
  thin wrapper around the standard discovery+fetch
  flow, not a transport-level concern).
- The cache is not thread-safe (matches the existing
  single-threaded batch lane).
- URL canonicalization is whitespace-only by design.
  `https://x.test/a` and `https://x.test/a?b=1` are
  treated as distinct URLs. This avoids subtle
  semantic changes but means a single URL with many
  tracking-param variants will not be coalesced.
- A redirect from URL X to URL Y results in two cache
  entries (X is the cache key, but the cached
  `ReferenceDocument` carries the post-redirect URL Y in
  its `url` field). Subsequent CVEs that need URL Y
  independently will not see the cached entry unless
  they also reference URL X.

## 13. Recommended next stage

Conservative query-string and fragment normalization for
the reference cache key, controlled by a feature flag so
the safer whitespace-only behavior remains the default.
This would coalesce URLs that differ only in tracking
parameters (e.g. `?utm_source=...`, `#fragment`) without
risking semantic change for URLs whose query strings
carry meaning (e.g. `?id=...`, `?token=...` would remain
distinct). Reuse the same aggregate-only telemetry
pattern; do NOT broaden it to per-URL or per-CVE keys.
Explicitly NOT recommended: cross-batch persistence,
disk-backed reference cache, second provider, or
broadening retry policy — all rejected by this stage's
constraints for good reason.
