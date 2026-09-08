# Reference URL Canonicalization (Cache-Key Only) — Implementation Report

Date: 2026-09-06
Stage: NEXT research-only engineering stage after frozen per-batch reference cache
Mode: research-only, cache-key optimization only. No fetch-semantics change.

## 1. Exact files changed

1. `ai/researcher/reference_cache.py` (modified, +76 / -10 approx)
   - `canonicalize_reference_url()` extended: whitespace strip (kept) + fragment
     removal + tracking-query-param removal (`utm_*`, `gclid`, `fbclid`).
   - `BatchReferenceCache.fetch()` now uses the canonicalized value as the
     lookup/store key but passes the original (whitespace-stripped) discovered
     URL to `fetch_fn` (`ReferenceCollector.fetch` in production).
   - Module docstring updated to document the key rules and the reuse of
     stdlib `urllib.parse` (same library already used by
     `ai.collectors.reference.ReferenceCollector`).
2. `ai/test_reference_url_canonicalization.py` (new, 33 tests)
   - Focused offline suite for this stage only.

NOT modified (verified): `ai/researcher/provider_errors.py`,
`ai/researcher/retry_policy.py`, `ai/researcher/degraded.py`, Nuclei
execution, fail-soft semantics, provider telemetry semantics, CVE cache
semantics, `research_cli` single-CVE behavior. No other subsystem files
touched.

## 2. Canonicalization rules (cache key only)

Given input `url`:

1. Non-string (`None`, etc.) → `""`. Empty/whitespace-only → `""` (fetch
   short-circuits to `None`, no `fetch_fn` call — unchanged behavior).
2. `stripped = url.strip()` (backward compatible with the previous
   whitespace-only canonicalization).
3. Parse with stdlib `urllib.parse.urlsplit` (the parsing library already
   used by `ai.collectors.reference`). Parse failure → fall back to
   `stripped` (never raises).
4. Fragment: dropped unconditionally (`urlunsplit(..., "")`).
5. Query: split the raw query string on the literal `&` character; for each
   chunk, take the parameter name as `chunk.split("=", 1)[0]` (raw, no
   decoding) and drop the chunk iff the name is exactly `gclid`, exactly
   `fbclid`, or starts with `utm_` (case-sensitive). All other chunks —
   including empty chunks — are kept verbatim, in original order, with
   original percent-encoding. Rejoin with `&`.
6. Reassemble with `urlunsplit((scheme, netloc, path, new_query, ""))`.
   Scheme, netloc, and path are passed through untouched: no lowercasing,
   no trailing-slash normalization, no percent decode/re-encode, no scheme
   normalization, no redirect resolution.
7. Any exception during steps 3–6 → return `stripped` (fail-safe to the
   previous whitespace-only behavior).

The `ai.resolver.canonicalization` target canonicalizer was deliberately
NOT reused: it lowercases hosts (and otherwise normalizes) in ways this
cache is forbidden from applying.

## 3. Examples of URLs that merge (same cache key)

| URL A | URL B | Shared key |
|---|---|---|
| `https://example.test/a#one` | `https://example.test/a#two` | `https://example.test/a` |
| `https://example.test/a#one` | `https://example.test/a` | `https://example.test/a` |
| `https://x.test/a?id=1&utm_source=a` | `https://x.test/a?id=1&utm_source=b` | `https://x.test/a?id=1` |
| `https://x.test/a?utm_campaign=one` | `https://x.test/a?utm_campaign=two` | `https://x.test/a` |
| `https://x.test/a?gclid=AAA` | `https://x.test/a?gclid=BBB` | `https://x.test/a` |
| `https://x.test/a?fbclid=AAA` | `https://x.test/a?fbclid=BBB` | `https://x.test/a` |
| `https://x.test/a?utm_source=a` | `https://x.test/a` | `https://x.test/a` |
| `https://x.test/a?gclid=A&fbclid=B` | `https://x.test/a` | `https://x.test/a` |
| `"  https://example.test/a  "` | `https://example.test/a` | `https://example.test/a` |

## 4. Examples that MUST remain distinct (separate fetches, verified by test)

- `https://x.test/a?id=1` vs `https://x.test/a?id=2`
- `https://x.test/a?token=a` vs `https://x.test/a?token=b`
- `https://x.test/a?key=a` vs `https://x.test/a?key=b`
- `https://x.test/a?page=1` vs `https://x.test/a?page=2`
- `https://x.test/a?q=a` vs `https://x.test/a?q=b`
- `https://x.test/a?zzz=1` vs `https://x.test/a?zzz=2` (unknown params)
- `https://x.test/a` vs `https://x.test/a?b=1` (query presence)
- `https://x.test/a` vs `https://x.test/a/` (trailing slash)
- `http://x.test/a` vs `https://x.test/a` (scheme)
- `https://x.test/a` vs `https://X.test/a` (host case)
- `https://x.test/A` vs `https://x.test/a` (path case)
- `https://x.test/a?b=2&a=1` vs `https://x.test/a?a=1&b=2` (order significant)

## 5. Proof original fetch URL is preserved (cache-key ONLY)

`BatchReferenceCache.fetch()` computes `key = canonicalize_reference_url(...)`
for `_store` lookup/insert but calls `self.fetch_fn(original)` where
`original` is the whitespace-stripped discovered URL with fragment and full
query intact. The stored value is the verbatim `ReferenceDocument` returned
by the fetch primitive; its `url`/content/hash/status are never rewritten.

Regression test (`CacheKeyOnlyRegressionTests.test_fetch_receives_exact_discovered_url`):
fetching `https://example.test/a?id=1&utm_source=first#one` then
`https://example.test/a?id=1&utm_source=second#two` produces exactly one
fetch call, `fetch_calls == ["https://example.test/a?id=1&utm_source=first#one"]`
(fragment `#one` and `utm_source=first` intact), `hits == 1`, and the stored
document's `url` equals the first URL byte-for-byte. Additional tests assert
whitespace-padded URLs still fetch the stripped URL (prior behavior) and that
the cached document URL is never rewritten.

## 6. Cache lifecycle

- Strictly per `run_cve_batch` invocation: created inside `run_cve_batch`
  when the caller passes none (or caller-supplied for tests), dropped on
  return. No module-global cache, no disk persistence, no Mongo/Redis, no
  cross-process state. `run_cve_batch` wiring untouched.
- Only successful `ReferenceDocument` results are stored; `None` (hard miss)
  is never cached, so a transient failure cannot poison later CVEs
  (`FetchSafetyTests.test_miss_not_cached` covers the miss path with a
  fragment-bearing URL).
- Telemetry unchanged: aggregate-only `reference_cache: {hits}` schema
  exactly as before; no per-URL telemetry added.

## 7. Exact test counts/results

New suite `ai.test_reference_url_canonicalization`: **33 tests, OK** (0.084 s).

| Class | Tests |
|---|---|
| `CanonicalizeUnitTests` | 10 (whitespace, empty/None, fragment, tracking×2, semantic-preserved, must-remain-distinct, order, percent-encoding, malformed) |
| `FragmentCacheTests` | 3 (merge→1 fetch/1 hit, fetch URL unchanged, doc not rewritten) |
| `TrackingCacheTests` | 4 (`utm_source`, `utm_campaign`, `gclid`, `fbclid` variants → 1 fetch) |
| `SemanticCacheTests` | 6 (`id`, `token`, `key`, `page`, `q`, unknown → separate fetches) |
| `MixedCacheTests` | 2 (tracking+semantic mix; order-significance) |
| `FetchSafetyTests` | 3 (empty/None, malformed, miss-not-cached) |
| `CacheKeyOnlyRegressionTests` | 2 (exact fetch URL; whitespace compat) |
| `BatchIsolationTests` | 3 (in-batch merge via `run_cve_batch`; no sharing between two batches; default-cache isolation) |

Required regression suites (single run): **161 tests, OK** (7.6 s):

```text
python -m unittest ai.test_provider_fail_soft ai.test_provider_telemetry \
  ai.test_provider_retry ai.test_provider_cache ai.test_reference_cache \
  ai.test_cve_batch ai.test_research_cli ai.test_openrouter
# Ran 161 tests — OK
```

Broader focused research/Nuclei suite:
`ai.test_researcher ai.test_knowledge_store ai.test_nuclei_offline_prepare
ai.test_nuclei_ready ai.test_reference_url_canonicalization` — **53 tests, OK**.

`git diff --check` on the two touched files: clean (exit 0). Note: the repo
working tree contains pre-existing trailing-whitespace warnings in unrelated
files (`ai/config.py`, `ai/correlator/version.py`, etc.); none are from this
change.

## 8. Safety verification

- Every test in the new file runs under socket/subprocess block guards
  (`socket.create_connection` / `socket.socket` / `socket.getaddrinfo` /
  `subprocess.run` / `subprocess.Popen` raise on use); batch tests reuse the
  `run_cve_batch` harness with temp dirs and a `retry_sleep_fn` no-op.
- No real `ReferenceCollector` HTTP requests: all fetches use fake
  `reference_fetch_fn` callables returning synthetic dict documents.
- No Nuclei, no browser, no DNS, no target-side requests, no 5J, no
  `SealedFinding`, no `CONFIRMED`, no `LIVE_HTTP` / `LIVE_NUCLEI` anywhere in
  the change or tests (verified by construction; telemetry blob assertions in
  the pre-existing suite remain green).
- Malformed URLs (`":::not a url:::"`, `"https://"`, `"://missing-scheme"`,
  NUL byte) and empty/`None` inputs are exercised and never raise.

## 9. Limitations

1. Tracking-name matching is case-sensitive lowercase (`utm_*`, `gclid`,
   `fbclid` only). Uppercase variants (e.g. `UTM_SOURCE=x`) are treated as
   semantic and stay distinct — conservative by design, at the cost of a
   missed merge.
2. A bare trailing `?` (`https://x.test/a?`) collapses to `https://x.test/a`
   via stdlib `urlsplit`/`urlunsplit` round-trip (empty query is not
   preserved). Semantically equivalent; accepted.
3. Percent-encoded tracking names (e.g. `utm%5Fsource=x`) are NOT stripped
   (name comparison is on the raw chunk) — conservative miss, not a
   correctness issue.
4. Query-parameter order is significant (`?a=1&b=2` ≠ `?b=2&a=1`): no
   reordering is performed, so some semantically identical URLs still fetch
   twice. This is the mandated conservative choice.
5. Redirect targets are never merged with source URLs: a fetch that redirects
   stores the post-redirect document under the source-derived canonical key.
   Two different source URLs redirecting to the same target still fetch twice.
6. `fetch_fn` receives the whitespace-stripped URL (prior behavior), not the
   raw string with surrounding whitespace. "Original URL preserved" therefore
   means modulo surrounding whitespace — documented and tested.

## 10. Recommended next stage

Conservative redirect-target coalescing *within* the batch: after a miss,
record `document.url` (the post-redirect URL stored by `ReferenceCollector`)
as an alias key pointing at the same stored document, so a later CVE that
directly discovers the redirect target reuses the already-fetched bytes
without a second fetch. Must keep: fetch primitive receives the discovered
URL unchanged; stored documents verbatim; alias entries never override a
directly-fetched document; `None` never cached/aliased; aggregate-only
`{hits}` telemetry unchanged; per-batch in-memory scope only. All with the
same offline, fake-fetch test discipline used here.
