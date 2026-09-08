# Batch Reference Quality Observability Parity — Implementation Report

Date: 2026-09-06
Stage: Batch / Single Reference Quality Observability Alignment
Mode: research-only, offline, non-authoritative, observability-only

## 1. Exact files changed

1. `ai/researcher/cve_batch.py` (MOD — only production file touched)
   - `RESULT_KEYS` gains trailing `"reference_quality"` (schema-stable
     ordering; existing `tuple(item.keys()) == RESULT_KEYS` assertions
     keep passing since they compare against the constant).
   - `_make_cached_research_fn` wrapper payload gains per-CVE
     `"reference_quality": {"checked": 1, "rejected": 0|1}` derived
     from the SAME `gate_reference_contexts` result (source of truth,
     never recalculated).
   - New `_per_cve_reference_quality(payload)` extractor: copies exactly
     the two integer counts from a payload's gate outcome, else `None`.
     Copies — never recalculates, never invents.
   - `research_one_cve` copies the payload outcome onto
     `result["reference_quality"]` on the shared completed/degraded
     payload path only. Early-return paths (invalid format,
     non-transient failure, batch-layer degraded payloads built without
     gating) leave it `None`.
   - Duplicate cache-hit branch additionally copies the quality dict so
     duplicate items expose equal values without sharing mutable state.
   - Aggregate `reference_quality`, markdown, provider/retry/cache
     telemetry, Nuclei lane: untouched.
2. `ai/test_batch_reference_quality_parity.py` (NEW, 21 tests, A–Q +
   gate-singularity + safety).
3. `ai/research_cli.py`: NOT modified (single-CVE already emits the
   field exactly as required; left untouched per the change boundary).

No commit, no push, no network contact. No Git operations performed.

## 2. Exact behavior change

Each batch result item now carries its own gate outcome:

```json
{ "cve": "CVE-2026-1557", "...": "...",
  "reference_quality": { "checked": 1, "rejected": 1 } }
```

- Source of truth: the existing gate result already computed in the
  research flow (`_research_single_cve` / `_make_cached_research_fn`).
  The batch layer only copies the two counts via
  `_per_cve_reference_quality` — no independent quality semantics
  anywhere in result formatting.
- Still exactly one gate implementation:
  `ai.researcher.reference_quality.gate_reference_contexts` (AST-asserted;
  the only quality-named def in `cve_batch.py` is the int-copying
  extractor).
- `None` semantics (documented, tested): `reference_quality is None`
  means "no research result to derive from" — invalid CVE format,
  non-transient hard failure, batch-layer degraded builds without
  gating, and batch-layer double-raise with no returned payload. Counts
  are never invented for these paths.

## 3. Single-vs-batch telemetry comparison

| Layer | Field | Value |
|---|---|---|
| Single-CVE payload | `reference_quality` | `{"checked": 1, "rejected": 0\|1}` (unchanged) |
| Batch result item | `reference_quality` | identical copy of the payload's outcome, or `None` when not derivable |
| Batch aggregate | `reference_quality` | unchanged: `{checked: #gated first-occurrences, rejected: #with removals}` |

Verified: `aggregate.checked == #{items with quality is not None}`
and `aggregate.rejected == #{items with rejected == 1}` on the default
flow (test D); identical synthetic inputs through direct single-CVE
execution and the batch path produce equal `reference_quality` (test L).

## 4. Duplicate-cache behavior

- Duplicate CVEs reuse the cached completed/degraded result: one
  provider call, `provider_cache.hits == 1`, existing ordering kept.
- Both items expose equal `reference_quality` values; the hit branch
  copies (not shares) the counts dict — mutating one item's object
  does not affect the other (test F).

## 5. Degraded / retry behavior

- completed → quality preserved (A/B/C).
- 429 → success (batch-layer retry returning a payload) → preserved,
  retry telemetry `attempted/succeeded` unchanged (G).
- 429 → 429, 503, network-error degraded payloads carrying the
  pre-failure gate outcome → preserved with `completed_degraded` (H/I/J).
- Batch-layer double-raise (no payload exists) → `None`, failure
  semantics unchanged, nothing invented (documented edge test).
- skip-LLM → preserved (`completed`, researcher never called) (K).
- Hard failures (invalid format, non-transient raise) → `failed`,
  `reference_quality is None`, error strings unchanged (Q).

## 6. Secrecy verification

- Every non-`None` item quality has exactly keys `{"checked",
  "rejected"}`, both `int` (booleans explicitly rejected) (M/N).
- Quality blobs contain no URLs, CVE IDs, contents, titles, hashes,
  keys, or exception text (O); full-aggregate scan finds no
  SealedFinding/CONFIRMED/LIVE_HTTP/LIVE_NUCLEI/READY_FOR_SCAN.
- Research provenance unchanged.

## 7. Safety verification

- Tests block `socket.create_connection/socket/getaddrinfo` and
  `subprocess.run/Popen`; fake discovery/fetch/researcher; no Mongo,
  no external HTTP/DNS, no Nuclei execution, no browser, no targets.
- All items `authoritative=False`, `nuclei_candidate=False` in fixtures;
  no 5J interaction; research-only preserved.

## 8. Test commands and exact counts/results

New suite (21 tests, OK):

```
python -m unittest ai.test_batch_reference_quality_parity -v
Ran 21 tests — OK
```

Coverage: A (completed), B (partial reject), C (all-rejected→completed),
D (aggregate match), E (individual values), F (duplicate cache + copy
isolation), G (429→success), H (429→429 degraded), I (503), J (network),
K (skip-LLM), L (single-vs-batch parity), M (exact keys), N (integers),
O (no leaks), P (ordering), Q (2× hard failure), gate-singularity, safety.

Regression (all OK):

```
python -m unittest ai.test_provider_fail_soft ai.test_provider_telemetry \
  ai.test_provider_retry ai.test_provider_cache ai.test_reference_cache \
  ai.test_reference_url_canonicalization ai.test_reference_quality_gate \
  ai.test_cve_batch ai.test_research_cli ai.test_single_cve_quality_parity \
  ai.test_batch_reference_quality_parity
Ran 237 tests — OK

python -m unittest ai.test_researcher ai.test_nuclei_offline_prepare \
  ai.test_nuclei_ready
Ran 5 tests — OK
```

## 9. Diff-check result

```
git diff --check -- ai/researcher/cve_batch.py ai/research_cli.py \
  ai/test_batch_reference_quality_parity.py
exit=0 (clean)
```

(Repo-wide checks were deliberately not run: they surface known
pre-existing whitespace warnings in unrelated files.)

## 10. Limitations

- `reference_quality: None` on hard-failure / no-payload paths is a
  deliberate "unknown", not a count; consumers must handle `None`.
- Batch markdown table does not gained a per-CVE column (JSON items
  carry the data; aggregate line unchanged) — markdown left frozen.
- Legacy custom `research_fn` payloads without the field yield `None`
  per item while the aggregate stays zeroed (frozen custom-flow behavior).

## 11. Git operations

Explicit statement: no Git operations were performed — no commit, no
push, no branch, no tag, no stash, no checkout. Only working-tree file
edits plus the new test module and this report.
