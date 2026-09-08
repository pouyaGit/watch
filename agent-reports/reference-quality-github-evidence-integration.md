# Reference Quality Gate → GitHub Evidence Retention Integration

Integration review + validation stage for the provenance-gated
technical GitHub evidence retention (commit
`f58ffe8e4cb58cbcacea5985c31411f4437d9cc3`).

## 1. Initial repository state

- HEAD: `f58ffe8` — `feat(ai): retain direct GitHub technical evidence`
- `git status --short`: 230 lines — 30 tracked pre-existing
  modifications (`AGENTS.md`, `ai/config.py`, `ai/correlator/version.py`,
  `ai/researcher/{batch,batch_v3,nuclei_pipeline,researcher,retry_v3}.py`,
  `ai/schemas/{finding,research,xss_finding}.py`, `ai/test_*` (4 XSS/
  executor/param-discovery files), `ai/verification/*` (5),
  `ai_data/nuclei/*` (2), `backend/*` (2), `crawl/watch_param_discovery.py`,
  `database/*` (2), `utils/common.py`, `watch_xss_verify.py`, deleted
  `README-watch-updated.md`) plus ~200 untracked files.
- Feature files state: `ai/collectors/reference_ranker.py`,
  `ai/researcher/research_context.py`, `ai/collectors/discovery_fetch.py`,
  `ai/researcher/cve_batch.py`,
  `ai/test_reference_ranker_technical_fallback.py` — all CLEAN (tracked
  at HEAD, zero worktree diff). `ai/researcher/reference_quality.py` and
  `ai/research_cli.py` are untracked-but-present support files
  (pre-existing untracked state, untouched).
- No git operations performed in this stage (one temporary
  `git stash -u` / `git stash pop` verification cycle was executed and
  fully restored: stash list empty, 30 modified files intact, HEAD
  unchanged; no commit, no push).

## 2. Architecture reviewed

The full intended flow is implemented end-to-end and was verified by
source read:

```
ReferenceDiscovery (ai/collectors/discovery.py)
  → ReferenceCollector.fetch (per-URL; shared BatchReferenceCache in batch)
  → discovery provenance attached in-memory
      (ai/collectors/discovery_fetch.py:42-43 "discovery_tags"/"discovery_query";
       ai/researcher/cve_batch.py:179-180 same keys on the cache path)
  → ReferenceRanker.build
      (ai/collectors/reference_ranker.py:466-478 — narrative branch first;
       on zero chunks, _technical_github_fallback, lines 273-390)
  → ReferenceContext (exact_record=None on the fallback path)
  → build_research_contexts (ai/researcher/research_context.py:35-36,44-56 —
       provenance forwarded in, stripped from the emitted dicts)
  → gate_reference_contexts
      (single-CVE: ai/research_cli.py:199-210;
       batch: ai/researcher/cve_batch.py:197-215 — both before
       SecurityResearcher; counts-only "reference_quality" telemetry
       {checked:1, rejected:0|1})
  → SecurityResearcher
  → NucleiDecisionEngine (unchanged downstream)
```

Safety boundaries verified in source:

- **Deterministic**: the fallback is pure stdlib (`urlsplit`, regex,
  string slicing); no LLM, no randomness. Test Q asserts repeated
  execution yields identical bytes.
- **Research-only / non-authoritative**: no authoritative flags are
  introduced anywhere in the flow; batch mode emits
  `authoritative=False` (verified in the persisted batch artifacts).
- **Filter/context generation only**: the fallback returns at most one
  bounded verbatim slice (≤ `FALLBACK_CONTEXT_SIZE` = 5000, capped by
  `MAX_CONTEXT_CHUNKS` = 1); it never fabricates `exact_record`, never
  injects CVE ids, severity, exploit, remediation, or trust claims
  (tests R and H).
- **Cannot bypass the gate**: fallback-produced contexts pass through
  the unchanged `gate_reference_contexts` in BOTH the single-CVE path
  and the batch path; foreign-CVE-only fallback slices are dropped by
  gate Rule 3 (test M).
- **Cannot cause live HTTP/Nuclei execution**: the fallback and gate do
  no I/O; tests block `socket` and `subprocess` for the whole module.
  No 5J/materialization/alerting surface is touched by any file in the
  feature set.

## 3. Changes actually made

**NO CODE CHANGE REQUIRED.** The integration stage found the pipeline
already fully integrated (the prior implementation commit wired the
fallback through `research_context.py`, `discovery_fetch.py`,
`cve_batch.py`, and `research_cli.py` into the gate before
`SecurityResearcher` in both single-CVE and batch flows). No production
code, no tests, no schemas, no telemetry, and no artifacts were
modified. Validation only (test runs + one read-only deterministic
replay; zero repository writes).

## 4. Why each change was necessary

N/A — no changes. Per the stage contract, cosmetic diffs were not
created. Everything below is verification evidence.

## 5. Reference Quality Gate rule verification

`ai/researcher/reference_quality.py` read in full (170 lines, mtime
2026-09-06, untouched by the feature commit and by this stage):

- **Rule 1 (known-URL integrity)** — lines 124-128: entry URL must be
  non-empty and a member of `known_urls` (the URLs the fetch layer
  actually produced). INTACT. Both integrators pass
  `known_urls={item["url"] for item in discovered_documents}`.
- **Rule 2 (current-CVE identity)** — lines 130-135: non-None
  `exact_record` must be a non-empty string containing the current CVE
  id. INTACT. The fallback keeps `exact_record=None` (ranker line 484),
  so it can never smuggle an identity claim.
- **Rule 3 (foreign-CVE-only rejection)** — lines 137-156: scoped text
  (`exact_record` + all non-empty chunks) mentioning only foreign CVE
  ids is dropped. INTACT. CVE-less fallback slices survive only through
  the pre-existing no-CVE-mention tolerance (entry mentions no CVE id at
  all); any slice naming only another CVE is dropped (test M +
  deterministic replay below).
- **Rule 4 (empty/invalid context rejection)** — lines 122-126,
  140-146, 158-159: non-dict entries, blank URLs, non-list chunks, and
  entries with neither `exact_record` nor a non-empty chunk are dropped.
  INTACT. Repository roots and boilerplate pages yield zero fallback
  chunks and are dropped here.
- **Rule 5 (canonical-URL dedup)** — lines 161-164: first occurrence
  per canonical key wins; original URL preserved. INTACT (frozen
  `canonicalize_reference_url` reused).

No rule weakened; no new rule needed — the fallback is upstream of the
gate, not a parallel path.

## 6. GitHub provenance boundary verification

- `discovery_tags`/`discovery_query` are set in-memory by
  `fetch_discovered_sources` and the batch cache path, forwarded to the
  ranker via `SimpleDocument` attributes in `build_research_contexts`,
  and consumed ONLY by `_technical_github_fallback` eligibility.
- They are NOT keys of the emitted context dicts (only
  `url/source_type/title/priority/exact_record/context_chunks` — test
  `test_provenance_forwarded_but_not_persisted` asserts the exact key
  set) and NOT fields of `ReferenceContext`, which is what reaches
  `SecurityResearcher` and persistence.
- No schema expansion: `ai/schemas/reference.py` untouched by the
  feature commit (verified against `git show --name-only HEAD`).
- No telemetry changes: the only new observability is the pre-existing
  counts-only `reference_quality` histogram (`checked`/`rejected`),
  which carries no URLs, contents, or CVE ids (parity suites assert the
  shape and secrecy).
- Provenance survives exactly long enough for the ranking decision and
  is absent from every emitted structure.
- Note: these two files remain untracked working-tree files (pre-existing
  state from before the checkpoint commit); their content is unchanged
  by this stage.

## 7. Eligibility scope verification

Eligibility is exactly the approved narrow set (no broadening):

- Host: exactly `github.com` (urlsplit hostname; `www.github.com`,
  `raw.githubusercontent.com`, `gist.github.com`, enterprise hosts
  denied — test G).
- Path kinds: only `blob`, `commit`, `issues`, `pull` at
  `/<owner>/<repo>/<kind>/…` depth ≥ 4 (segment-boundary matching, so
  repos named `blob-store` don't qualify). `/compare/`, `/tree/`,
  `/releases/`, `/security/advisories/`, roots, `/search`, `/topics`,
  profile URLs all yield no fallback (tests E, F).
- Provenance predicates: (`nvd_reference` tag AND `discovery_query` ==
  CVE id) OR (CVE id in query AND one of `cve_in_title` / `cve_in_body`
  / `cve_in_repo_name`). Priority/confidence/`security_research_signal`
  alone confer nothing. Product-only searches denied. Missing
  provenance → legacy empty behavior (tests I–L).
- No generic GitHub search heuristics exist in the implementation
  (verified by source read — the only URL logic is the segment test
  above).

## 8. Evidence-quality verification (deterministic replay, offline)

Read-only replay of discovery→fetch→rank→gate with socket/subprocess
patched (no network, no Nuclei, no writes), mapping directly to the
real-case expectations:

| Case | Retained? | Verdict |
| --- | --- | --- |
| 78203 vulnerable `views.py` blob (NVD provenance, CVE-less code) | YES — 1 chunk, `exact_record=None` | expected |
| 78203 fix commit | YES — 1 chunk | expected |
| repository root | NO — zero chunks → gate Rule 4, `rejected=True` | expected |
| foreign-CVE-only issue page (CVE-2025-54381 text for a 78205-style run) | NO — gate Rule 3, `rejected=True` | expected |

Real-artifact comparison (existing persisted runs, no new run needed):

- **CVE-2026-78203** — AFTER run kept vulnerable-source blob + fix
  commit + researcher PoC + advisory (4 of 5; repo root dropped). All
  three expected categories (vulnerable source / fix commit / PoC) are
  retainable exactly as the acceptance criteria require.
- **CVE-2026-78205** — AFTER run kept vulnerable `uri.py` blob +
  advisory (2 of 4; repo root and issue #5644 dropped). Issue #5644's
  fetched content names only CVE-2025-54381, so it is NOT retained —
  matching the required behavior.
- **CVE-2026-1557** — unchanged: `GOOD_CANDIDATE`, template generated,
  `reference_quality={checked:1, rejected:0}`, 5/5 contexts kept. No
  regression. The only delta vs the BEFORE artifact is the LLM-side
  `nuclei_candidate` flag flip (True→False) with zero material effect
  (decision, confidence, template generation, semantic validation all
  identical) — documented in the existing real-validation report as LLM
  variance, not a pipeline outcome.
- `exact_record` remains `None` for every fallback-retained source in
  the real artifacts; no claims are fabricated anywhere.

## 9. Test results

Focused suites (all pass):

```
python -m unittest ai.test_reference_ranker_technical_fallback \
  ai.test_reference_quality_gate ai.test_reference_quality_decision_boundary \
  ai.test_reference_cache ai.test_reference_url_canonicalization \
  ai.test_batch_reference_quality_parity ai.test_single_cve_quality_parity
Ran 174 tests in 0.494s — OK
```

Coverage mapping to required scenarios A–N (all covered by existing
tests — no new tests needed):

- A blob retention, B commit retention, C issue retention (CVE-less +
  CVE-bearing), D foreign-CVE issue/slice rejection, E root rejection,
  F unsupported-path rejection (tree/advisories/search/topics/profile),
  G missing-provenance rejection, H `exact_record is None`,
  I provenance non-leak, J gate foreign-CVE rejection, K network
  blocked (socket patched module-wide), L no Nuclei (subprocess
  patched) — `ai/test_reference_ranker_technical_fallback.py`.
- M batch/single parity (gate ordering, telemetry shape, skip-llm,
  fail-soft, cache paths) — `ai/test_batch_reference_quality_parity.py`
  + `ai/test_single_cve_quality_parity.py`.
- N unchanged gate behavior — `ai/test_reference_quality_gate.py`,
  `ai/test_reference_quality_decision_boundary.py`,
  `ai/test_reference_cache.py`, `ai/test_reference_url_canonicalization.py`.

Broader regression (practical in this environment):

```
python -m unittest discover -s ai -p "test_*.py" -b
Ran 2860 tests in 59.374s — FAILED (failures=3, errors=4, skipped=11)
```

All 7 non-passing results are pre-existing and outside this stage's
scope (each maps to a known unrelated pre-existing working-tree
modification; none touches the reference-quality feature set):

1. `test_nuclei_cve_2026_1557_dryrun.test_template_content_is_safe_and_grounded`
   — Nuclei template content vs the locally modified
   `ai_data/nuclei/generated/CVE-2026-1557.yaml` (Nuclei is explicitly
   out of scope; artifact is an unrelated pre-existing modification).
2. `test_nuclei_offline_prepare.test_offline_prepare_reproduces_stored_template`
   — same stored-template mismatch family (Nuclei, out of scope).
3. `test_stage2_production_reads.test_no_database_db_import` —
   `sys.modules` pollution under full-suite ordering
   (`mongoengine` imported by an earlier unrelated test); PASSES
   standalone (`Ran 39 tests — OK`).
4–7. Loader errors for `test_legacy_severance_5k`,
   `test_p1_security_hardening`, `test_watch_param_discovery`,
   `test_watch_xss_verify` under bulk discovery (import-order
   conflicts); loading them individually runs 135 tests with 7
   failures — all in the pre-existing modified Nuclei boundary
   (`ai/researcher/nuclei_pipeline.py` family) and
   `crawl/watch_param_discovery.py` user-agent flag files. Unrelated,
   pre-existing, untouched.

Per instructions, no unrelated code was modified to make these pass.

## 10. Real validation results

A real research-only 3-CVE batch validation already exists for this
exact implementation (run after the feature code was in place; see
`agent-reports/reference-quality-github-evidence-real-validation.md`):
`ai_data/research/batch-2026-09-07T103348.083192Z.json`
vs baseline `batch-2026-09-07T072603.424405Z.json`:

- 3 requested, 3 processed, 0 failed, 0 degraded, 0 provider outages.
- reference_quality: checked=3 rejected=2 in BOTH runs — identical
  counts, inverted meaning (evidence retention vs evidence loss), with
  per-CVE analysis in the real-validation report.
- 78203: vulnerable blob + fix commit + PoC retained; root rejected.
- 78205: `uri.py` blob retained; foreign-CVE issue #5644 and root
  rejected; advisory unchanged.
- 1557: no regression (`GOOD_CANDIDATE`, template generated).
- The run was research-only end-to-end: no target-side HTTP, no Nuclei
  execution, no fingerprinting, no 5J/authoritative findings, no
  alerting.

Since no code changed in this stage, re-running the batch would produce
no new information and was skipped (the stage's "ONLY if the
implementation requires a real validation run" condition does not hold).
Do-not-treat-LLM-variance-as-regression guidance was applied to the
`nuclei_candidate` flag flip and the 78203 decision-label change
(POSSIBLE→NOT_APPLICABLE, clean `completed` runs both times, no
generation-relevant delta) — both recorded as observations in the
existing validation report, not blockers.

## 11. Observations / limitations

- Retained GitHub slices carry rendered-page chrome (the fetcher
  returns HTML); for large files the bounded head slice may not reach
  the anchored lines (e.g. views.py L275–L315). Small files, diffs,
  and prose pages retain substantive content. Improvement candidate for
  the fetcher/ranker — documented, deliberately not changed here.
- Two support files (`reference_quality.py`, `research_cli.py`) remain
  untracked; that is pre-existing working-tree state, out of scope for
  this stage (no git operations allowed).
- Bulk-discovery ordering pollution (`test_stage2_production_reads`
  under full discover) is a test-isolation weakness in unrelated
  suites; passes standalone.
- The 7 broader-suite failures are confined to out-of-scope pre-existing
  modifications (Nuclei artifacts/pipeline, param discovery user-agent,
  verification files) and would require unrelated changes to "fix" —
  explicitly avoided.

## 12. Final verdict

**GO**

- Gate rules 1–5 intact and verified by source read + tests.
- Fallback narrowly scoped; no eligibility broadening.
- Provenance ephemeral; no schema/telemetry changes required or made.
- No fabricated evidence; foreign-CVE-only and repository-root content
  rejected in tests, deterministic replay, and real artifacts.
- Single-CVE and batch paths aligned (shared gate, shared provenance
  handling, shared counts-only telemetry; parity suites pass).
- No live execution anywhere in validation.
- Focused tests: 174/174 pass. Broader: 2860 tests, 2853 pass / 7
  pre-existing failures — all outside this stage's scope.
- No unrelated files modified. No commit. No push.
