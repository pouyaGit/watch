# Reference Cache + URL Canonicalization — Security Review

Stage: REVIEW + VALIDATION only. No live execution, no Nuclei, no
asset fingerprinting, no 5J/materialization, no alerts, no real
research batch was run. All verification is deterministic/offline.

Verdict: **GO** (no code change required).

---

## 1. Scope

Reviewed the following (review/validation only; nothing modified):

- `ai/researcher/reference_cache.py` — `BatchReferenceCache` +
  `canonicalize_reference_url`
- `ai/researcher/cve_batch.py` — batch integration (per-batch cache
  instantiation, `_make_cached_research_fn`, aggregate telemetry)
- `ai/researcher/research_context.py` — per-CVE context building
- `ai/collectors/discovery_fetch.py` — reference integration
- `ai/researcher/reference_quality.py` — Reference Quality Gate
  (reuses `canonicalize_reference_url` for dedup)
- `ai/research_cli.py` — single-CVE flow quality-gate integration
- Tests: `ai/test_reference_cache.py`,
  `ai/test_reference_url_canonicalization.py` (new), plus the four
  Reference Quality test modules.
- Real artifact: `ai_data/research/batch-2026-09-07T103348.083192Z.json`

The Reference Quality Gate checkpoint `01beeeb` was NOT modified.
`reference_cache.py` is tracked at that checkpoint with no working-tree
diff; the two new cache test modules are untracked (reviewed only).

## 2. Architecture reviewed

```
CVE batch (run_cve_batch)
   │ process CVE → _research_single_cve / _make_cached_research_fn
   ▼
ReferenceDiscovery.discover → DiscoveredSource.url
   │
   ▼  per-URL
BatchReferenceCache.fetch  (canonicalized cache KEY; original URL to fetch_fn)
   │   hit → reuse stored ReferenceDocument
   │   miss → ReferenceCollector.fetch(original URL); store only on success
   ▼
discovered_documents (per-CVE list, built from cached document fields)
   ▼
build_research_contexts  (per-CVE ranking)  → raw contexts
   ▼
gate_reference_contexts  (per-CVE quality gate; canonical dedup key)
   ▼
ReferenceContext list (per-CVE fresh objects)
   ▼
SecurityResearcher
```

The cache is batch-local, in-memory, non-global, non-persistent,
non-authoritative, research-only, and transparent to downstream
research semantics.

## 3. BatchReferenceCache lifecycle

- Instantiated once per `run_cve_batch` (`cve_batch.py:988-1000`).
  Caller-supplied instance honored; otherwise a fresh empty
  `BatchReferenceCache` is created and dropped on return.
- **No module-global mutable cache.** The only module-level state is
  the immutable `_TRACKING_PARAMS_EXACT` frozenset.
- **No filesystem persistence.** `reference_cache.py` has no disk I/O.
  Verified by `test_no_cache_files_written`.
- **No Mongo/db persistence and no cross-process state.** The store is
  a plain instance dict living only for the batch invocation.
- Lifecycle verified by `test_two_batches_do_not_share_cache`,
  `test_no_module_global_mutable_cache`, and
  `test_no_cache_sharing_between_batches` (each batch re-fetches).

## 4. Cache semantics

- **Successful `ReferenceDocument` results are cached.**
  `reference_cache.py:185-188`: `document = self.fetch_fn(original); if
  document is not None: self._store[key] = document`.
- **Failed/None results are NOT cached.** A `None` return (the
  `ReferenceCollector.fetch` "hard miss" sentinel) records nothing, so
  a later CVE needing the same URL will perform its own fetch.
  Verified by `test_hard_miss_not_cached` and `test_miss_not_cached`.
- **Cache hits reuse the existing fetched document** (same object
  identity; `is` equality asserted in tests). `hits` counter
  increments only on reuse; the first fetch is a miss and is not
  counted.
- **Cache does not alter document content.** Stored `ReferenceDocument`
  is returned verbatim; its URL/content/hash/status are never
  rewritten (`test_cached_document_not_rewritten`).

## 5. URL canonicalization rules

`canonicalize_reference_url` (`reference_cache.py:93-141`):

- Strips surrounding whitespace only.
- Drops the URL fragment (`#...`).
- Drops only tracking params: `gclid`, `fbclid`, and any `utm_*`
  prefix (case-sensitive, exact lowercase names).
- Preserves every other parameter byte-for-byte, in original order,
  with original percent-encoding. No `id`/`token`/`key`/`page`/`q`/
  unknown-param removal.
- Never lowercases host/path, never touches trailing slash, never
  reorders params, never decodes/re-encodes, never changes scheme,
  never resolves redirects, no network.
- Reuses stdlib `urllib.parse` (`urlsplit`/`urlunsplit`) — same
  library already used by `ReferenceCollector`. Deliberately does NOT
  reuse `ai.resolver.canonicalization` (that normalizer lowercases
  hosts, which the cache must not do).

Canonicalization is **cache-key-only**: the fetcher receives the
original whitespace-stripped URL, and the stored document's URL remains
the original. Confirmed by `test_fetch_receives_exact_discovered_url`
and empirical check (stored URL = `https://example.com/a?utm_source=x`
after a fragment-variant hit).

## 6. 25-case adversarial matrix

All cases are covered deterministically by the focused test modules
(offline, mocks only; verified by the passing suite) or by direct
empirical verification below:

| # | Case | Expected | Covered by | Status |
|---|------|----------|------------|--------|
| 1 | exact duplicate URL → hit | hit | test_two_distinct_cves_share_url | PASS |
| 2 | whitespace variant → hit | hit | test_whitespace_url_still_works / test_whitespace_still_stripped | PASS |
| 3 | fragment variant → hit | hit | test_different_fragments_one_fetch_one_hit | PASS |
| 4 | utm_* variant → hit | hit | test_utm_source_variants_one_fetch / test_utm_campaign_variants_one_fetch | PASS |
| 5 | gclid variant → hit | hit | test_gclid_variants_one_fetch | PASS |
| 6 | fbclid variant → hit | hit | test_fbclid_variants_one_fetch | PASS |
| 7 | id difference → MISS | miss | test_id_differs / test_must_remain_distinct | PASS |
| 8 | token difference → MISS | miss | test_token_differs | PASS |
| 9 | key difference → MISS | miss | test_key_differs | PASS |
| 10 | page difference → MISS | miss | test_page_differs | PASS |
| 11 | q difference → MISS | miss | test_q_differs | PASS |
| 12 | arbitrary unknown param difference → MISS | miss | test_unknown_param_differs / test_must_remain_distinct | PASS |
| 13 | trailing slash difference → MISS | miss | test_must_remain_distinct (`/a` vs `/a/`) | PASS |
| 14 | scheme difference → MISS | miss | test_must_remain_distinct (http vs https) | PASS |
| 15 | hostname difference → MISS | miss | test_must_remain_distinct (`x.test` vs `X.test`) | PASS |
| 16 | query-order difference → MISS | miss | test_query_order_not_changed / test_query_order_preserved_on_fetch | PASS |
| 17 | successful result cached | cached | test_reused_context_is_source_material_only | PASS |
| 18 | None result NOT cached | not cached | test_hard_miss_not_cached / test_miss_not_cached | PASS |
| 19 | first successful document reused unchanged | unchanged | test_cached_document_not_rewritten / test_canonical_merge_inside_one_batch | PASS |
| 20 | isolated between two BatchReferenceCache instances | isolated | test_no_module_global_mutable_cache / test_no_cache_sharing_between_batches | PASS |
| 21 | duplicate URL across two CVEs does not share context | isolated | test_reused_context_is_source_material_only / test_cve_specific_conclusions_not_shared | PASS |
| 22 | canonical key does not mutate original URL | no mutation | test_fetch_receives_exact_discovered_url | PASS |
| 23 | fragment removal does not alter stored URL | unchanged | test_cached_document_not_rewritten (empirical confirm too) | PASS |
| 24 | tracking param removal does not alter stored URL | unchanged | test_fetch_receives_exact_discovered_url | PASS |
| 25 | cache hit does not invoke ReferenceCollector.fetch again | no re-fetch | all hit tests assert single URL in `calls` | PASS |

Additionally verified empirically (no network): the forge scenario in
section 7 — `fetch(https://example.com/a?utm_source=x)` stores key
`.../a`; a later `https://example.com/a?token=secret` produces key
`.../a?token=secret`, a **distinct** key → separate fetch (no forging).

## 7. Cross-CVE isolation verification

CVE-A and CVE-B both reference the same canonical URL. Verified by
`test_reused_context_is_source_material_only`,
`test_cve_specific_conclusions_not_shared`, `CrossCveTests` in
`test_reference_quality_gate.py`, and a direct offline simulation:

- **fetch happens once** (`calls == [shared]`).
- **ReferenceDocument may be reused** (cache hit returns the same
  document object).
- **research contexts are separately constructed** — `build_research_
  contexts` is called once per CVE, producing distinct list/dict
  objects.
- **CVE-A does not receive CVE-B identity and vice versa** — gated
  contexts for A contain only A's id; gated contexts for B contain
  only B's id.
- **Quality Gate is applied independently per CVE** — `gate_reference_
  contexts` called with each CVE's id and known_urls.
- **no mutable context object is shared** — `_make_cached_research_fn`
  builds a fresh `discovered_documents` list and fresh
  `ReferenceContext` objects per CVE from the (value-type) cached
  document.

The cache shares only deterministic fetched source material
(`ReferenceDocument`), never CVE-scoped research context or LLM
conclusions.

## 8. Reference Quality Gate interaction

`gate_reference_contexts` (`reference_quality.py`) reuses
`canonicalize_reference_url` **only** as a per-CVE dedup key
(Rule 5, `reference_quality.py:161-165`). Rules are unaffected:

- **Rule 1 (known-URL integrity):** entry URL must be a member of the
  CVE's `known_urls` (built from actually-fetched documents) — a
  cache hit still yields a document whose URL passed the fetch, so it
  is a member of `known_urls`. No un-fetched URL can appear fetched.
- **Rule 2 (current-CVE identity):** `exact_record` must contain the
  current CVE id; unchanged, applied per CVE.
- **Rule 3 (foreign-CVE-only rejection):** entries mentioning only
  foreign CVE ids dropped; unchanged.
- **Rule 4 (invalid/empty context rejection):** unchanged.
- **Rule 5 (dedup):** same canonical key keeps only the first
  occurrence; the surviving entry keeps its ORIGINAL source URL
  (`test_canonical_duplicates_merge_without_url_rewrite`).

**No weakening.** The dedicated forge case is safe:
`fetched .../a?utm_source=x` vs `forged .../a?token=secret` produce
different canonical keys, so a "forged" un-fetched URL cannot masquerade
as the fetched one. Empirically confirmed.

## 9. Batch / single-CVE behavior

- **Batch:** `run_cve_batch` creates `BatchReferenceCache` per call;
  default flow wraps research via `_make_cached_research_fn`. Not
  reused across separate CLI invocations. Duplicate references inside
  one batch hit the cache; hits preserve existing research behavior
  (document reused; per-CVE contexts rebuilt). Failures not cached.
  Aggregate `reference_cache` telemetry is counts-only
  (`{"hits": int}`) with no URLs/content/CVE IDs; verified by
  `test_telemetry_counts_only_no_urls_no_cve_ids` and
  `test_reference_cache_always_present`. Reference quality telemetry
  is counts-only and unchanged (parity tests pass).
- **Single-CVE:** `ai.research_cli._research_single_cve` has **no**
  batch/reference cache at all — no cross-run cache. It applies only
  the deterministic quality gate. The original
  `fetch_discovered_sources` (per-URL, uncached) primitive is
  unchanged. No single-CVE cache was added. `test_no_module_global_
  mutable_cache` confirms no residual global state.

## 10. Security findings

Treated as an evidence-integrity boundary. Findings:

1. **NO CACHE SECURITY BYPASS FOUND** — cache poisoning via
   canonicalization collisions is not possible: only `gclid`/`fbclid`/
   `utm_*` collapse, which is the documented, intended tracking-param
   semantics. Semantic params (`id`, `token`, `key`, `page`, `q`,
   unknown) never collapse. Scheme/host/path/trailing-slash/order all
   remain distinct.
2. **No cross-CVE context contamination** — only `ReferenceDocument`
   (value source material) is shared; per-CVE `ReferenceContext` and
   gating are rebuilt each CVE (Section 7).
3. **No failed-result poisoning** — `None` is never cached, so a
   transient failure cannot be frozen and handed to a later CVE;
   late-batch retries are possible (Section 4).
4. **No stale-data persistence** — cache is per-batch only, dropped on
   return; nothing written to disk/db.
5. **No mutation of cached documents** — documents stored/returned
   verbatim; downstream only reads fields.
6. **No mutable shared context** — per-CVE context objects are fresh.

One LOW/INFORMATIONAL observation (by design, not a defect): a URL
that uses a `utm_*`/`gclid`/`fbclid` parameter as its *real* content
selector would collapse to one cache entry across two distinct
requests (e.g. `?utm_source=public` vs `?utm_source=private`). This is
inherent to the documented tracking-param semantics and the cache-key
contract; it does not weaken the quality-gate identity/source rules
because gating happens after cache reuse and is re-scoped per CVE. It
is explicitly out of scope per the spec ("utm_* is deliberately
treated as non-semantic tracking").

**Classification:** NO CRITICAL / HIGH / MEDIUM findings.

## 11. Focused test results

```
python -m unittest ai.test_reference_cache ai.test_reference_url_canonicalization
Ran 57 tests ... OK

python -m unittest ai.test_reference_quality_gate \
    ai.test_reference_quality_decision_boundary \
    ai.test_batch_reference_quality_parity \
    ai.test_single_cve_quality_parity
Ran 89 tests ... OK
```

All 146 focused tests pass.

## 12. Broader regression results

```
python -m unittest discover -s ai -p "test_*.py" -b
Ran 2860 tests; FAILED (failures=3, errors=4, skipped=11)
```

Classification of the 7 non-passing entries — none related to the
reference cache / canonicalization feature:

- **4 import errors** (`test_legacy_severance_5k`, `test_p1_security_
  hardening`, `test_watch_param_discovery`, `test_watch_xss_verify`):
  `ImportError: cannot import name 'config' from 'config'
  (/opt/watch/ai/config.py)` — a module-path/namespace clash in the
  legacy / `crawl` / XSS-verify subsystems, which AGENTS.md says not to
  modify. **PRE-EXISTING / UNRELATED.**
- **`test_no_database_db_import`** (`test_stage2_production_reads`):
  fails only under `discover -b` because other modules import
  `pymongo`/`database.db` into the shared interpreter before this
  test runs; passes in isolation. **TEST-ISOLATION ISSUE.**
- **2 Nuclei failures** (`test_template_content_is_safe_and_grounded`,
  `test_offline_prepare_reproduces_stored_template`): tied to the
  modified `ai_data/nuclei/generated/CVE-2026-1557.yaml` and
  `ai/researcher/nuclei_pipeline.py`, which are among the *known
  unrelated working-tree modifications* outside this stage's scope.
  **PRE-EXISTING / UNRELATED.**

No FEATURE REGRESSION attributable to the reference cache.

## 13. Real artifact verification

`ai_data/research/batch-2026-09-07T103348.083192Z.json` (existing
artifact, not re-run):

- `reference_cache: {hits: 0}` — consistent with no shared reference
  URLs among the batch's CVEs. Present and well-formed (counts only).
- `reference_quality: {checked: 3, rejected: 2}` — matches the sum of
  per-CVE items (1557: rejected 0; 78203: rejected 1; 78205: rejected
  1). Counts only; no URLs/CVE text leak into aggregate telemetry.
- Research semantics normal: `completed=3`, `authoritative=false`,
  no fabricated content, offline Nuclei lane did not contact assets
  (`candidate_count=0`, `target_count=0`, `targets=[]`).
- Cache behavior did not alter research semantics.

## 14. Observations / limitations

- The two new test modules are untracked; the implementation
  (`reference_cache.py`) is already tracked at the prior checkpoint
  with no working-tree diff. This review did not modify anything.
- Coverage is best-effort; caching that bypasses via alternate URL
  representations is bounded by the conservative canonicalizer, which
  collapses only fragments + tracking params. Unicode/casing/percent
  variations remain distinct (documented behavior).
- The `utm_*`-as-semantic LOW observation is inherent, intended
  behavior (see Section 10 item 6).
- No live batch was run; no live-network, Nuclei, fingerprinting, 5J,
  or alert paths were exercised (per instructions).

## 15. Code changes

No defect discovered.

**CODE CHANGE REQUIRED: NO**

## 16. Final verdict

**GO**
