# Final Activation Gate — Watch AI Research Agent — 2026-09-07

Verification-only stage. No architecture redesign, no speculative features,
no new engineering stage. One concrete activation blocker was found
(malformed provider env value) and fixed with the smallest possible
config-only change (no production code modified).

## 1. Environment verified

- Host: `/opt/watch` (WSL). CPU 8 cores, RAM 7.7 GiB (6.5 GiB available),
  disk 1007 G total / 935 G available. Output dirs
  `ai_data/research`, `ai_data/nuclei/{generated,results,findings}` all
  writable (verified by `python -m ai.research_cli check`).
- `python -m ai.research_cli check`: provider config OK
  (`AI_PROVIDER=openrouter`, `OPENROUTER_API_KEY` set,
  `OPENROUTER_MODEL=minimax/minimax-m3:free`), research-track imports OK,
  NucleiRunner dry-run surface present. Only FAIL is
  `WATCH_MONGO_URI is not configured` — the fail-closed behavior working
  as designed (no sandbox Mongo exists on this box right now; see §12).
- Sandbox used for live runs: in-process empty-Mongo substitute
  (mongomock) via a throwaway driver outside the repo
  (`/tmp/opencode/sandbox_cli.py`), process-only `WATCH_MONGO_URI`
  (never persisted). Zero Watch assets — identical posture to the prior
  empty-DB sandbox setup. All research-lane code ran unmodified.

## 2. Architecture verified (code-read, current implementation)

- Lane: `CVECollector` (NVD) → `ReferenceDiscovery` →
  `ReferenceCollector`/`fetch_discovered_sources` → deterministic
  `gate_reference_contexts` → `SecurityResearcher` (LLM, parsed +
  schema-validated into `ResearchResult`) → batch Nuclei lane
  (`NucleiDecisionEngine` + `DetectionSpecExtractor`, `prepare_offline`
  only when a prior-art template exists).
- Research-only: every payload carries `mode: research-only`,
  `authoritative: False`, `research_only: True`
  (`ai/research_cli.py`, `ai/researcher/cve_batch.py`,
  `ai/researcher/degraded.py`).
- LLM non-authoritative: `ResearchResult` is a hypothesis object;
  degraded fallback forces `nuclei_candidate=False`,
  `public_exploit=None`, `actively_exploited=None`,
  `bug_bounty_relevance=0`, `severity=None`.
- Nuclei non-authoritative: `prepare_offline` performs no HTTP/DNS/
  sockets/subprocess/Nuclei execution/fingerprinting (by construction);
  dry-run findings always have `matched=false`. `prepare_for_watch` is
  never referenced from the batch lane. `NucleiRunner.run(execute=...)`
  defaults to dry-run and requires `READY_FOR_SCAN`, which the offline
  lane never produces (empty caller-provided selection).
- Repo-wide check of the research lane: no `SealedFinding`, no 5J
  materialization, no `LIVE_HTTP`/`LIVE_NUCLEI`, no notification/alerting
  calls, no browser/target-side activity. Target execution stays
  separated behind scope gates untouched by this track.

## 3. Safety gates A–N

- A (batch isolation): VERIFIED live — CVE-2026-1557 failed, the other
  three completed; batch exit recorded per-CVE status, aggregate written.
- B (402/429/5xx/network fail-soft): VERIFIED by code
  (`provider_errors.classify_provider_failure` + `degraded.*`) and suite
  (`test_provider_fail_soft` OK). No outage occurred in this run
  (all-zero outage histogram), so no live retry was exercised today;
  retry semantics are unit-covered (`test_provider_retry` OK).
- C (bounded retry only): VERIFIED — single 429-only retry, no loop
  (`retry_policy.py`; `provider_retries` all zero today, schema present).
- D (no key logging/persistence): VERIFIED — provider never logs the key
  (`ai/llm/openrouter.py` docstring + error paths carry status/type
  only); artifact scan of all 6 new files: no API key/credential/secret
  (one `PASSWORD` hit investigated: the literal string `DB_PASSWORD`
  inside Nuclei detection-idea prose about WordPress config constants —
  not a credential).
- E (env-based provider config): VERIFIED — `OPENROUTER_API_KEY`,
  `OPENROUTER_MODEL`, `OPENROUTER_MAX_TOKENS`, `WATCH_MONGO_URI` all from
  environment; no hard-coded secrets found in the research lane.
- F (Mongo fail-closed): VERIFIED — empty URI refuses with a clear
  message (`require_mongo_uri`); `check` reports NOT RUNNABLE instead of
  proceeding.
- G (artifacts non-authoritative): VERIFIED — `authoritative: False` in
  all 6 new artifacts; schema check enforces it.
- H (quality gate deterministic/filter-only): VERIFIED —
  `gate_reference_contexts` never reorders/mutates/fabricates; per-CVE
  `reference_quality` counts-only; aggregate `checked=4, rejected=3`
  reconciles with per-CVE values.
- I (foreign-CVE isolation): VERIFIED by code (CVE-identity + known-URL
  rules) and suite (`test_reference_quality_gate`,
  `test_reference_quality_decision_boundary` OK).
- J (empty context → conservative): VERIFIED — all-invalid input yields
  empty contexts; degraded path forces `nuclei_candidate=False`; all
  three completed CVEs decided `NOT_APPLICABLE` with `nuclei_candidate`
  false from the LLM as well.
- K/L (no implicit Nuclei execution / target selection): VERIFIED —
  batch lane uses `prepare_offline` with an empty selection only;
  `run_results` empty; no commands executed (ps clean, see §11).
- M (no target-side activity): VERIFIED — lane network surface is httpx
  to NVD + public reference hosts + OpenRouter only; no browser, no DNS
  probing, no subprocess in the offline lane.
- N (semantic validation before candidacy): VERIFIED —
  `NucleiSemanticValidator` gates generation; no template was generated
  without prior art and a GOOD_CANDIDATE decision (zero generated today,
  correctly — see §6).

## 4. Single-CVE result

`research --cve CVE-2026-78205` (sandbox driver): exit 0.
`ai_data/research/CVE-2026-78205.cli.json`: `research_status=completed`,
`llm_status=ok` (real LLM call — proves the §13 env fix),
`reference_quality={checked:1, rejected:1}`,
`discovered=4/fetched=4/contexts=1`, `nuclei_candidate=false` with a
sound logic-gap reason, `authoritative=False`, `research_only=True`,
`outage_bucket=None`, no retry. No live target interaction.

## 5. Batch result

`batch --file` with 4 CVEs: exit 1 (one per-CVE failure, by design).
Aggregate `ai_data/research/batch-2026-09-07T044453.111813Z.json`:
`completed=3, completed_degraded=0, processed=3, failed=1`;
outages/retries/cache histograms all zeroed-but-present (internally
consistent); `reference_quality={checked:4, rejected:3}`;
report `agent-reports/cve-batch-run-2026-09-07T044453.111813Z.md` generated.
Per-CVE `reference_quality` present on all completed items; the failed
item carries `None` (documented "not derivable, never invented").
Duplicate/ordering/cache semantics remain unit-covered (no extra live
calls spent re-proving them).

## 6. Realistic dry-run result (coverage of the 4 required cases)

| CVE | Case | Outcome |
| --- | --- | --- |
| CVE-2026-1557 | known Nuclei prior art | `failed` — LLM returned `affected_products` as objects, pydantic `ValidationError` (non-transient response-shape error → fail-loud per contract). Full offline lane for this CVE stays covered by stored artifact + `test_nuclei_cve_2026_1557_dryrun` / `test_nuclei_offline_prepare` (both OK). |
| CVE-2026-78203 | authenticated interaction, unsuitable for generic unauthenticated Nuclei | `completed`, `nuclei_candidate=false`, decision `NOT_APPLICABLE` |
| CVE-2026-78205 | protocol/logic issue | `completed`, `nuclei_candidate=false`, decision `NOT_APPLICABLE` (conservative, as expected) |
| CVE-2026-78207 | no reliable candidate expected (library-level) | `completed`, `nuclei_candidate=false`, decision `NOT_APPLICABLE` |

No Nuclei process spawned, no template executed against any target,
no Watch asset contacted (empty inventory; empty offline selections).

## 7. Provider behavior

- Pre-fix, `OPENROUTER_MODEL` resolved to a 49-char polluted value
  (model slug glued to `OPENROUTER_MAX_TOKENS=8192`); post-fix it is the
  clean 23-char slug and `OPENROUTER_MAX_TOKENS=8192` stands alone.
- This run: 4 real LLM attempts, 0 outages, 0 retries, 3 completions +
  1 fail-loud validation failure. No 402/429/5xx observed today, so the
  degraded path was not live-exercised; it remains code- and
  unit-verified (`test_provider_fail_soft`, `test_provider_telemetry`,
  `test_provider_retry`, `test_provider_cache` all OK).
- Telemetry keys (`outage_bucket`/`outage_events`/`retry_attempted`/
  `retry_succeeded`/`provider_outages`/`provider_retries`/
  `provider_cache`) present and consistent in every new artifact.

## 8. Reference-quality behavior

- Single-CVE and batch flows gate through the same function; per-CVE
  counts copied verbatim (source of truth), aggregate tallied from the
  same sink. Today: gate removed entries on all 3 completed CVEs
  (`rejected=1` each), including the real-LLM single-CVE run
  (4 fetched → 1 kept context). No cross-CVE contamination possible:
  gate is per-CVE with `known_urls` scoping; shared batch reference
  cache reuses fetched documents only, never CVE-specific conclusions.

## 9. Nuclei boundary

- Fresh CVEs: decision-only lane (`DetectionSpecExtractor` +
  `NucleiDecisionEngine`), `nuclei_error` records "no source template …
  decision only, no generation", `offline_preparation=null`. No
  generation, no validation, no dry-run commands — correct for CVEs with
  no prior art.
- Stored `ai_data/nuclei/generated/CVE-2026-1557.yaml` untouched; no
  templates added or modified. Findings dir holds only the pre-existing
  `CVE-2026-1557.json`; results dir likewise. No new findings written.

## 10. Output schema

All 6 artifacts written today (1 `.cli.json`, 4 per-CVE `.batch.json`,
1 aggregate) validate against their schemas (required keys present,
`authoritative=False`, `mode=research-only`); no secrets, no API keys,
no credentials, no fabricated evidence markers, no authoritative state,
no `LIVE_HTTP`/`LIVE_NUCLEI`, no `SealedFinding`, no 5J materialization,
no target response data. One stale-file keyword hit triaged as prose,
not a secret (see §3-D).

## 11. Network safety

- Verification unit tests run fully offline/mocked (socket/subprocess
  guards in the boundary suites, all OK).
- Live research runs contacted only NVD (`services.nvd.nist.gov`),
  public reference hosts (vendor GitHub, advisories), and the configured
  OpenRouter endpoint — the intended CLI behavior. No target-side
  security testing performed. Post-run `ps` shows no `nuclei`, browser,
  or scanner processes.

## 12. Resource / operational check

- CPU 8, RAM 7.7 GiB, disk 935 G free: compatible with the research-only
  workload (batch of 4 + full 2817-test suite ran concurrently without
  pressure). Process lifetime: single CVE ~1 min, batch of 4 ~9 min
  (dominated by NVD rate-limit spacing + provider latency).
- Operational prerequisites for the intended runtime (not code defects):
  (a) `WATCH_MONGO_URI` must point at the real/sandbox Mongo — this box
  has none running, hence `check` reports NOT RUNNABLE and the CLI fails
  closed; (b) provider quota must be healthy (402s were seen yesterday;
  none today); (c) `.env` provider values must stay well-formed (fixed
  today — recommend a startup assertion or comment guard, future
  improvement, not a blocker).

## 13. Full test counts

- `python -W ignore -m unittest discover ai -p 'test_*.py'`:
  **Ran 2817 tests — FAILED (failures=1, errors=4, skipped=11).**
- Exact failures (all isolated as unrelated to the AI research pipeline;
  no AI-pipeline test failed):
  - `ERROR test_legacy_severance_5k`, `ERROR test_p1_security_hardening`,
    `ERROR test_watch_xss_verify`: legacy repo-root `watch_xss_verify`
    script import collision (`from config import config` resolves to
    `ai/config.py` under discover). XSS-verify/crawl scope, not the AI
    research lane; untouched per scope protection.
  - `ERROR test_watch_param_discovery`: imports `crawl.*` (protected
    subsystem) with the same `config` collision. Untouched per scope
    protection.
  - `FAIL test_no_database_db_import`
    (`test_stage2_production_reads`): asserts `mongoengine` absent from
    `sys.modules`, but an earlier module in the alphabetically-discovered
    full run imports it first. Passes in isolation: **39/39 OK** —
    suite-ordering artifact, not a pipeline defect.
- Focused AI-pipeline regression set (researcher, research CLI, CVE
  batch, provider fail-soft/telemetry/retry/cache, reference cache, URL
  canonicalization, quality gate, single/batch parity, decision
  boundary, Nuclei offline prepare + readiness + 1557 dryrun, openrouter,
  llm, knowledge store, XSS researcher + LLM researcher, real-research):
  **Ran 356 tests — OK.**
- Concrete blocker found and fixed during this gate: `.env` line for
  `OPENROUTER_MODEL` had `OPENROUTER_MAX_TOKENS=8192` concatenated onto
  it (missing newline), producing an invalid 49-char model slug that
  would fail every real LLM call. Fix: split into two lines (config-only;
  no production code touched). Verified: `check` prints the clean slug
  and this gate completed 4 real LLM interactions post-fix.

## 14. Exact failures, if any

1. CVE-2026-1557 live-batch item: `ValidationError … affected_products.0
   … Input should be a valid string` — model returned objects against the
   schema; classified non-transient (response-shape error, correctly NOT
   retried/degraded), recorded `failed`, batch continued. Handled by the
   existing contract; full-lane coverage for this CVE remains via stored
   artifact + passing offline-lane unit tests.
2. Full-discover suite: 1 failure + 4 errors, all triaged above as
   out-of-scope legacy imports / ordering artifact; zero AI-pipeline
   test failures.

## 15. GO / NO-GO decision

**GO**

## 16. Exact remaining disabled capabilities

Research-only AI activation is ready for: CVE collection (NVD),
reference discovery/collection, deterministic quality gating, LLM
research with fail-soft degradation, conservative Nuclei candidate
decisions, offline template preparation/dry-run command construction,
and research artifact emission to `ai_data/` + batch reports to
`agent-reports/`.

Remains explicitly DISABLED (nothing below was activated or enabled by
this gate):

- target-side live execution (no LIVE_HTTP / LIVE_NUCLEI / browser runs)
- automatic authoritative findings (no CONFIRMED-from-research, no
  SealedFinding)
- 5J materialization
- automatic notification/alerting
- any other live execution path (`prepare_for_watch`, asset
  fingerprinting, Nuclei binary execution)

Nothing was activated automatically by this verification.

## 17. Explicit statement

**No Git operations were performed.**
