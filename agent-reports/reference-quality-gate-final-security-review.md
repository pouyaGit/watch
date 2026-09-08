# Reference Quality Gate — Final Security + Correctness Review

Review + validation only. No code, tests, schemas, telemetry, or
artifacts modified. No commit, no push. No live target execution, no
Nuclei, no fingerprinting, no 5J/materialization, no alerts. Known
unrelated working-tree modifications left untouched.

Previous checkpoint: `f58ffe8e4cb58cbcacea5985c31411f4437d9cc3`
(`feat(ai): retain direct GitHub technical evidence`).
Previous integration verdict: GO (NO CODE CHANGE REQUIRED).

## 1. Scope

Reviewed ONLY the gate and its immediate integration:

- `ai/researcher/reference_quality.py` (170 lines, read in full; mtime
  2026-09-06, untracked, unchanged by feature commit and by this stage)
- `ai/research_cli.py` — single-CVE path, gate block lines 193–220
  (untracked, unchanged)
- `ai/researcher/cve_batch.py` — batch path, gate block lines ~185–215
  (tracked at HEAD, zero worktree diff)
- `ai/researcher/research_context.py` — provenance forward/strip,
  58 lines, read in full (tracked at HEAD, zero diff)
- `ai/collectors/reference_ranker.py` — ranker + fallback, 519 lines,
  read in full (tracked at HEAD, zero diff)
- `ai/collectors/discovery_fetch.py` — provenance attach, 48 lines,
  read in full (tracked at HEAD, zero diff)

Relevant tests read and executed:
`ai/test_reference_ranker_technical_fallback.py` (526 lines),
`ai/test_reference_quality_gate.py`,
`ai/test_reference_quality_decision_boundary.py`,
`ai/test_reference_cache.py`,
`ai/test_reference_url_canonicalization.py`,
`ai/test_batch_reference_quality_parity.py`,
`ai/test_single_cve_quality_parity.py`.

## 2. Files reviewed

Same list as §1. State verified before review: the four tracked files
show zero unstaged and zero staged diff against HEAD; the two support
files remain untracked and outside the checkpoint. No file was modified
during this review (verification scripts lived in `/tmp` only).

## 3. Threat model

The gate is a TRUST BOUNDARY between untrusted fetched reference
material (arbitrary third-party web content: GitHub pages, advisories,
blogs) and the LLM research context. Attacker-controlled inputs include:
fetched page bodies, URLs, titles, source-type labels, and (for the
fallback) discovery tags/queries. The gate's job is to ensure only
material that is (a) actually fetched for this CVE (known-URL
integrity), (b) scoped to the current CVE identity, (c) non-empty, and
(d) deduplicated can reach `SecurityResearcher`. Anything the gate
keeps with `exact_record=None` must carry no identity claim at all.
The gate must never invent, mutate, or inject content — it is
filter-only. Provenance (`discovery_tags`/`discovery_query`) is itself
untrusted metadata and must never become trusted evidence.

## 4. 20-case adversarial matrix

Deterministic offline harness (`/tmp/opencode/gate_adversarial_matrix.py`,
socket + subprocess patched to raise): CVE=`CVE-2026-78203`,
foreign=`CVE-2025-54381` / `CVE-2026-99999`. Result: 21/21 PASS
(20 required cases + 1 no-mutation check).

| # | TEST CASE | EXPECTED | ACTUAL | PASS/FAIL |
| --- | --- | --- | --- | --- |
| 1 | exact_record foreign + chunk current | REJECT | REJECT | PASS — Rule 2: non-None exact must contain current CVE |
| 2 | exact_record current + chunk foreign | ACCEPT | ACCEPT | PASS — anchored to current; cross-ref tolerated, not foreign-only |
| 3 | multiple foreign CVEs, no current | REJECT | REJECT | PASS — Rule 3 foreign-only drop |
| 4 | current CVE only in URL | ACCEPT | ACCEPT | PASS — URL not in scoped text; kept CVE-less, exact None, no claim |
| 5 | current CVE only in title | ACCEPT | ACCEPT | PASS — title not in scoped text; no identity from metadata |
| 6 | current CVE only in source_type | ACCEPT | ACCEPT | PASS — source_type not in scoped text |
| 7 | current CVE only in discovery provenance | ACCEPT | ACCEPT | PASS — provenance stripped before gate; no leak into emitted dict |
| 8 | empty exact_record + empty chunks | REJECT | REJECT | PASS — Rules 2 + 4 |
| 9 | malformed chunks (non-list; non-string/blank items) | REJECT | REJECT | PASS — dropped as empty, never raises |
| 10 | non-dict context entries | REJECT | REJECT | PASS — skipped, rejected=True |
| 11 | duplicate URLs, different content | REJECT-second | REJECT-second | PASS — Rule 5, first wins, original preserved |
| 12 | canonical duplicates (fragment + utm_*) | REJECT-second | REJECT-second | PASS — key-only canonicalization; survivor keeps ORIGINAL url |
| 13 | whitespace/case variants of CVE in exact | ACCEPT | ACCEPT | PASS — Rule 2 case-insensitive, whitespace-tolerant |
| 14 | missing known_urls (None) | ACCEPT | ACCEPT | PASS — documented relaxation; both callers always pass known_urls |
| 15 | URL not in known_urls | REJECT | REJECT | PASS — Rule 1, forged URLs cannot enter |
| 16 | GitHub repository root (end-to-end) | REJECT | REJECT | PASS — zero fallback chunks, Rule 4 |
| 17 | GitHub technical page, invalid provenance | REJECT | REJECT | PASS — predicates fail closed, no slice produced |
| 18 | GitHub technical page, foreign-CVE-only | REJECT | REJECT | PASS — slice produced upstream, Rule 3 drops it |
| 19 | GitHub page, current + foreign CVE | ACCEPT | ACCEPT | PASS — current-anchored narrative kept |
| 20 | fallback context, exact_record=None | ACCEPT | ACCEPT | PASS — kept CVE-less; gate returns SAME object, no invention |
| X | gate mutation/injection check | ACCEPT | ACCEPT | PASS — identical object returned, input unmutated, no CVE injected |

Cases 4–7 are the critical metadata-confusion probes: in every one the
CVE appears ONLY in non-evidence fields, and in every one the gate
correctly refuses to treat it as identity — the entry survives solely
as unattributed CVE-less content (or not at all), never as a scoped
claim. No bypass exists in any metadata channel.

## 5. GitHub fallback review

`_technical_github_fallback` (`ai/collectors/reference_ranker.py:273–390`),
invoked only when the narrative branch yields zero chunks (lines
460–478). Verified by source read + tests G–L, E–F:

- Only `github.com`: stdlib `urlsplit` hostname equality; `www`,
  enterprise hosts, `raw.githubusercontent.com`, `gist.github.com`,
  malformed URLs denied.
- Only approved path types: `TECHNICAL_GITHUB_PATH_SEGMENTS` =
  `{blob, commit, issues, pull}`, matched on segment boundaries at
  `/<owner>/<repo>/<kind>/…` depth ≥ 4. `/tree/`, `/compare/`,
  `/releases/`, `/security/advisories/`, roots, `/search`, `/topics`,
  profiles all yield `[]`. Repo named `blob-store` correctly denied.
- Only approved provenance predicates: (`nvd_reference` tag AND query
  == CVE) OR (CVE in query AND `cve_in_title`/`cve_in_body`/
  `cve_in_repo_name`). Priority, confidence,
  `security_research_signal` alone confer nothing; product-only
  searches denied; missing provenance → legacy empty.
- No generic GitHub search heuristics anywhere in the implementation.
- Repository roots can never qualify (depth check).
- Fallback is strictly upstream of the gate: ranker output →
  `build_research_contexts` (provenance stripped) →
  `gate_reference_contexts` → `SecurityResearcher`, in BOTH paths.
  Foreign-only fallback slices are demonstrably killed by Rule 3
  (matrix case 18).

NO SECURITY BYPASS FOUND in the fallback.

## 6. Batch/single parity review

`ai/research_cli.py:193–220` vs `ai/researcher/cve_batch.py:185–215`
(cache path lines 178–184 mirror `discovery_fetch.py:42–43`):

- Identical order in both: discovery → fetch → provenance →
  `build_research_contexts` → unconditional `gate_reference_contexts`
  (no conditional guard — neither path can skip the gate) →
  `ReferenceContext` conversion → `SecurityResearcher`.
- Identical `known_urls` construction from fetched documents.
- Identical counts-only `reference_quality` (`checked:1`,
  `rejected:0|1`) derived from the SAME gate result, never
  recalculated; batch additionally fans the boolean into
  `quality_sink` for the aggregate histogram.
- Parity suites (`test_batch_reference_quality_parity`,
  `test_single_cve_quality_parity`) assert same-contexts agreement,
  gate-before-researcher ordering, telemetry shape/secrecy, skip-llm
  and fail-soft preservation. All pass.

## 7. Fail-soft boundary review

Import + symbol scan of the three deterministic modules:

- `reference_quality.py`: imports `re`, `dataclasses` only (+
  function-local ranker/canonicalizer). Zero I/O surface.
- `reference_ranker.py`: imports `re` + `ReferenceContext` schema;
  the single `urllib` reference is `urllib.parse.urlsplit` (pure
  string parsing, no network).
- `research_context.py`: imports `ReferenceRanker` only.
- The gate: no LLM calls, no HTTP, no subprocess, no MongoDB, no
  Nuclei, no fingerprinting — confirmed by source (no such symbols)
  AND by execution (whole fallback test module runs under
  socket/subprocess patches; this review's matrix ran under the same
  blocks).
- Malformed input is fail-closed, never fail-open: non-dict entries
  skipped, blank URLs dropped, blank exact dropped, non-list chunks
  dropped, all-invalid input → `[]` with `rejected=True`, empty input
  → `[]` with `rejected=False`. No exception paths exist that could
  convert malformed evidence into accepted evidence. No "improvement"
  needed or made.

## 8. Focused test results

```
python -m unittest ai.test_reference_ranker_technical_fallback \
  ai.test_reference_quality_gate \
  ai.test_reference_quality_decision_boundary \
  ai.test_reference_cache \
  ai.test_reference_url_canonicalization \
  ai.test_batch_reference_quality_parity \
  ai.test_single_cve_quality_parity
Ran 174 tests — OK (all pass)
```

## 9. Regression results

```
python -m unittest discover -s ai -p "test_*.py" -b
Ran 2860 tests in ~58s — FAILED (failures=3, errors=4, skipped=11)
```

Identical outcome to the integration-stage run (no code changed since,
so no drift possible). Classification of all 7:

- PRE-EXISTING / UNRELATED (2): `test_nuclei_cve_2026_1557_dryrun.
  test_template_content_is_safe_and_grounded` and
  `test_nuclei_offline_prepare.
  test_offline_prepare_reproduces_stored_template` — Nuclei
  template-vs-artifact mismatches against the locally modified
  `ai_data/nuclei/generated/CVE-2026-1557.yaml`; Nuclei is explicitly
  out of scope.
- TEST-ISOLATION ISSUE (1): `test_stage2_production_reads.
  test_no_database_db_import` — `sys.modules` pollution under bulk
  discovery ordering only; passes standalone (`Ran 39 tests — OK`).
- PRE-EXISTING / UNRELATED (4 loader errors):
  `test_legacy_severance_5k`, `test_p1_security_hardening`,
  `test_watch_param_discovery`, `test_watch_xss_verify` — bulk-discovery
  import-order conflicts; loaded individually they run, with failures
  confined to the pre-existing modified Nuclei-boundary and
  param-discovery files. Untouched per scope rules.

Zero FEATURE REGRESSION entries.

## 10. Real artifact verification

Inspected existing artifacts only (no new pipeline run):
`ai_data/research/batch-2026-09-07T103348.083192Z.json` + per-CVE
batch/CLI files + the measured replay in
`agent-reports/reference-quality-github-evidence-real-validation.md`.

- Aggregate: mode `research-only`, `authoritative=False`; 3
  requested / 3 processed / 0 failed / 0 degraded; zero provider
  outages; `reference_quality={checked:3, rejected:2}`.
- 78203 (`rejected:1`): vulnerable `views.py` blob + fix commit +
  researcher PoC + advisory retained; repository root absent (zero
  chunks → Rule 4). Retained CVE-less slices carry `exact_record=None`
  with zero CVE ids in full scoped text — no fabrication. CLI research
  text cites only the blob/commit/PoC URLs.
- 78205 (`rejected:1`): vulnerable `uri.py` blob + advisory retained;
  repository root absent; issue #5644 ABSENT from retained evidence —
  its fetched page names only CVE-2025-54381, so Rule 3 drops it
  (the CLI research text shows the issue URL among NVD references with
  3 foreign-CVE mentions, confirming the content scoping that justifies
  the drop).
- 1557 (`rejected:0`): `GOOD_CANDIDATE` 0.95, template generated,
  `semantic_validation.valid=True`, 5/5 contexts kept. Intact; the
  LLM-side `nuclei_candidate` flag flip vs baseline has zero material
  effect (decision/confidence/generation/validation identical) — LLM
  variance, not a regression.
- Offline-preparation blocks confirm no live execution surface used
  (1557 shows the pre-existing offline template path with zero
  targets/findings; 7820x carry only the informational
  decision-only `nuclei_error` strings, unchanged from baseline).

## 11. Security findings

### Critical

None.

### High

None.

### Medium

None.

### Low

None.

### Informational

1. **Cross-referenced entries are kept, not hidden** (matrix case 2,
   `reference_quality.py:147–156`): an entry whose `exact_record`
   carries the current CVE but whose chunks also name a foreign CVE is
   ACCEPTED. Correct per the Rule 3 contract (rejects only
   foreign-ONLY text) — the foreign mention stays visible to the LLM
   inside a correctly-attributed entry rather than being silently
   stripped. Not a bypass; noted so future rule-tightening proposals
   do not misread it as one.
2. **`known_urls=None` relaxation** (`reference_quality.py:117`):
   when `known_urls` is omitted, Rule 1 is skipped. Both production
   callers pass it unconditionally (verified §6); the relaxation
   exists for legacy/test callers. Defense-in-depth note: any future
   caller must pass `known_urls`. No change required.
3. **Large-file head slices may miss anchored lines** (pre-documented):
   bounded verbatim slices of big rendered GitHub pages can carry
   chrome without reaching the cited lines (e.g. views.py L275–L315),
   while small files/diffs/prose retain substance. Noise, not
   misinformation (no claims fabricated). Fetcher/ranker improvement
   candidate — out of scope for this review.

**NO SECURITY BYPASS FOUND.** All five trust-boundary properties
(A–E) hold under adversarial probing, including metadata-channel
confusion attempts (cases 4–7), provenance-forgery attempts (case 17),
foreign-identity smuggling (cases 1, 3, 18), and synthetic-URL
injection (case 15).

## 12. Limitations

- The matrix probes gate + ranker logic on synthetic fixtures; real
  fetched-page replay was covered by the pre-existing real-validation
  report (measured AFTER run), not repeated here — re-running fetches
  would add no new gate-logic information.
- Per-CVE batch artifacts persist counts-only `reference_quality`, not
  full context lists; AFTER-state content claims rest on the measured
  replay documented in the real-validation report plus this review's
  synthetic matrix.
- Broader-suite failures ( §9) limit what the full discover run can
  certify, but all are outside the reviewed scope and classified.
- LLM-output variance (decision labels, candidacy flags) is out of
  scope for a deterministic-gate review and was not treated as signal.

## 13. Final verdict

**GO WITH OBSERVATION**

Rationale: no bypass, no defect, no code change required; the gate and
its integration satisfy every acceptance property. The OBSERVATION
carries forward the three pre-documented non-blocking notes
(informational findings 1–3 above: cross-reference visibility,
`known_urls` caller discipline, large-file slice reach) for future
work. No blocker exists.

CODE CHANGE REQUIRED: NO.
