# Reference Context Quality Gate — Implementation Report

Date: 2026-09-06
Stage: NEXT research-only engineering stage after frozen per-batch reference
cache + frozen conservative URL canonicalization.
Mode: research-only, deterministic validation only. No ranking change, no LLM,
no network, no persistent state.

## 1. Exact files changed

1. `ai/researcher/reference_quality.py` (new, 170 lines)
   - `gate_reference_contexts(contexts, *, cve_id, known_urls=None)` plus
     `QualityGateResult` (`contexts`, `rejected`) and
     `empty_reference_quality_histogram()`.
2. `ai/researcher/cve_batch.py` (modified, surgical)
   - `_make_cached_research_fn(reference_cache, quality_sink=None)`: gates
     `contexts_raw` after `build_research_contexts`, before
     `ReferenceContext` construction / `SecurityResearcher`; appends one
     boolean per gated CVE to `quality_sink`.
   - `run_cve_batch`: per-batch `quality_events` list, passed as the sink
     for the default wrapper only; new always-present aggregate field
     `reference_quality: {checked, rejected}`; one markdown line.
3. `ai/test_reference_quality_gate.py` (new, 27 tests, ~755 lines)

NOT modified (verified by inspection of the edit history this session):
`provider_errors.py`, `retry_policy.py`, `degraded.py`, provider-cache
semantics, reference-cache semantics, URL canonicalization rules, Nuclei
execution, `research_cli` single-CVE path (single-CVE flow not wired to the
gate; only the batch default wrapper gates).

## 2. Quality-gate contract

- Pure function over one CVE's `contexts_raw` dict list. Returns the SAME
  dict objects in the SAME order (filter-only; never reorders, never
  mutates, never fabricates, never adds claims).
- `rejected=True` iff a non-empty input lost at least one entry.
- Never raises on malformed input (`None`/non-list/non-dict handled).
- Reuses existing pieces only: `ReferenceRanker.CVE_PATTERN` for CVE-id
  scanning, frozen `canonicalize_reference_url` for dedup keys,
  `ReferenceDocument`/`ReferenceContext` value types. No new parser, no new
  hash algorithm, no new ranking.

## 3. Identity validation

- `exact_record`, when present, must be a non-empty string containing the
  current CVE id (case-insensitive, same `re.escape` semantics the ranker
  uses). An exact record scoped to another CVE drops the entry.
- Entry-level foreign-CVE rule: CVE ids found anywhere in the entry's
  scoped text (`exact_record` + chunks) that exclude the current CVE drop
  the entry. Entries mentioning no CVE id are kept (fallback tolerance for
  keyword-scoped vendor material the existing ranker legitimately emits).
- Missing/empty `cve_id` fails closed (non-empty input dropped, rejected).

## 4. Source integrity rules

- Entry must be a dict with a non-empty string `url`; when `known_urls`
  (the discovery/fetch layer's actual source URLs for this CVE) is
  supplied, membership is required — synthetic/foreign URLs rejected.
- Entries with no `exact_record` and no non-empty chunk are dropped
  (empty reference content). Non-list `context_chunks` drops the entry.
- Hash note (documented, no invention): the existing `ReferenceContext`
  schema carries no hash and no raw content, so hash validation is not
  supported by the existing schema. The gate performs no hash check;
  upstream content hashes are preserved untouched (gate never mutates).

## 5. Dedup behavior

- Within one CVE, entries whose URLs share the frozen canonical key keep
  only the first occurrence (e.g. `?id=1&utm_source=a#one` vs
  `?id=1&utm_source=b#two` collapse). The survivor keeps its ORIGINAL
  source URL — canonicalization is used for the dedup key only, exactly
  as in the frozen cache stage. Distinct URLs stay distinct.

## 6. Cross-CVE isolation proof

- Same `ReferenceDocument` may be reused across CVEs (reference cache
  unchanged); contexts are rebuilt per CVE by the existing pipeline and
  gated per CVE. Proven by test: one shared vendor document mentioning
  both CVE-2026-8001 and CVE-2026-8002 yields gated contexts for A
  containing A but not B, and vice versa; and an A-scoped entry gated as
  B is dropped entirely (no bleed via shared URL).

## 7. Ranking preservation

- Gate is filter-only: relative order of survivors identical to input,
  `priority` scores untouched, entry objects identical (`is` checks in
  tests). Partial removal keeps relative order of the rest.

## 8. Failure behavior

- All-invalid input → empty list. No fabricated replacement, no added
  exploit/severity/impact/payload claims, nothing authoritative.
- The existing pipeline proceeds with zero reference contexts, so
  `SecurityResearcher` (and the unchanged Nuclei candidate lane) decides
  conservatively on CVE metadata alone. Fail-soft/degraded, retry, and
  Nuclei semantics untouched. Batch test asserts `completed` (not failed),
  `nuclei_candidate=False`, `authoritative=False` for a fully-gated CVE.

## 9. LLM boundary

- Gate executes inside `_make_cached_research_fn` after
  `build_research_contexts` and before `ReferenceContext` construction /
  `SecurityResearcher.research`. Deterministic, offline; AST test proves
  the module has no socket/subprocess/httpx/requests/urllib/LLM-call
  surface. Gated dicts convert cleanly to `ReferenceContext` (schema test).

## 10. Telemetry decision

- Implemented the optional aggregate-only field (integrated cleanly, so
  kept rather than internal): `reference_quality: {checked, rejected}`,
  always present, integer counts only — no CVE IDs, no URLs, no contents,
  no error payloads. `checked` = gated first-occurrence CVEs (duplicates
  reuse the provider-cache outcome and are never re-gated); `rejected` =
  gated CVEs where the gate removed ≥1 entry. Custom `research_fn` flows
  report zeros. One markdown line added
  (`- reference_quality: checked=N rejected=M`); existing
  `reference_cache`-count assertions unaffected (no shared substring).
- Proven by batch test with real default wrapper + mocked
  discovery/collector/researcher: `{checked: 2, rejected: 1}` exact, plus
  report-content assertions.

## 11. Exact test counts/results

New suite `ai.test_reference_quality_gate`: **27 tests, OK**.

| Class | n | Covers |
|---|---|---|
| IdentityTests | 6 | valid pass, narrative pass, foreign exact/chunk reject, malformed identity, non-list input |
| SourceIntegrityTests | 6 | unknown URL, no-filter mode, empty URL, empty content, no-hash-invention, non-list chunks |
| DedupTests | 3 | same-URL collapse, canonical merge w/o URL rewrite, distinct stay distinct |
| CrossCveTests | 2 | shared-doc isolation via real `build_research_contexts`, no bleed via shared URL |
| RankingTests | 2 | order+scores preserved, partial removal keeps order |
| FailureBehaviorTests | 2 | all-invalid→empty, no-claims blob |
| LlmBoundaryTests | 2 | schema conversion, AST surface check |
| BatchTelemetryTests | 4 | histogram schema, zeroed custom flow, default-flow exact counts, no-leak |

Required regression run (9 suites incl. canonicalization): **194 tests, OK**.
Broader focused run (`researcher`, `knowledge_store`,
`nuclei_offline_prepare`, `nuclei_ready`, `reference_quality_gate`,
`reference_url_canonicalization`, `reference_cache`): **104 tests, OK**.
`git diff --check` on touched files: clean (exit 0; remaining tree-wide
whitespace warnings are pre-existing in unrelated files).

## 12. Safety verification

- All 27 tests run under socket/subprocess block guards; batch tests use
  temp dirs, fake fetch fns returning `ReferenceDocument` objects, mocked
  discovery/collector/researcher/candidates — no real `ReferenceCollector`
  HTTP, no Nuclei, no browser, no DNS, no target-side requests, no 5J, no
  `SealedFinding`, no `CONFIRMED`, no `LIVE_HTTP`/`LIVE_NUCLEI`.
- During development, wiring mistakes surfaced as `failed` rows (dict-vs-
  object fetch return; incomplete fake CVE attributes) — both fixed in
  test fakes only; implementation needed no changes after review.

## 13. Limitations

1. Single-CVE `research_cli` flow is NOT gated (only the batch default
   wrapper); single-CVE behavior intentionally unchanged.
2. Custom injected `research_fn` flows bypass the gate (opt-in, as with
   the reference cache); they report zeroed quality telemetry.
3. Chunk-level mixed entries (valid exact + foreign chunk) are kept via
   the exact record's scoping — such entries cannot arise from the real
   ranker (≤1 chunk per entry by construction); only synthetic inputs hit
   this path.
4. Hash validation absent by design (schema carries none).
5. `known_urls` uses post-redirect document URLs (matches what
   `build_research_contexts` actually consumed); a context URL must equal
   a consumed document URL exactly (no canonical fuzzy-match on the
   integrity check — dedup is where canonicalization applies).

## 14. Recommended next stage

Gate the single-CVE `research_cli` path with the same function (shared
helper, no signature change to `_research_single_cve`'s public contract),
emitting the same `{checked, rejected}` pair into the per-CVE payload
metadata (counts only). This closes the parity gap between batch and
single-CVE lanes while keeping all frozen semantics intact. Same offline,
fake-fetch test discipline required.
