# Stage R24.15 — Model Sync + Controlled R24 Activation

## Status
**R24 MANUAL CONTROLLED RUN = GO.** Model reconciled with a single-line `.env`
change; exactly one real R24 scheduler run executed (`RESEARCH_COMPLETED`,
1 plan, 0 failures, ~115 s, within all budgets); all safety invariants hold.
Timer left untouched — R24 hourly activation NOT enabled in this stage.

## 1. Preflight
- `git rev-parse HEAD` → `71fef7ce69bf1f24837b05cf7bf0478daed762ee` — matches
  expected. No commit, no push performed.
- `git status --short`: only pre-existing entries (`M wordlists/dell_params.txt`,
  `M wordlists/indeed_params.txt` from unrelated pipeline activity; untracked
  `stage-r23-2` report, `stage-r24-13/14` reports, `ai_data/*`, `crawl/output/`,
  `dns-bruteforce/`). The `.env` edit does not appear (file is untracked/
  ignored — no tracked-file modification).
- `test -f agent-reports/stage-r24-12-production-opt-in.md` → present.
- Wall time at run: 10:03–10:05 UTC = 13:33–13:35 Asia/Tehran — outside the
  18:00–00:00 window, so the manual run used the CLI-supported `--force`
  override (forced=true recorded in the run artifact).

## 2. Exact model reconciliation
- Before: verified exact line 19 of `/opt/watch/.env`:
  `OPENROUTER_MODEL=minimax/minimax-m3:free`
- Change (single line only, via anchored replacement; no full-file read, no
  secret exposure):
  `OPENROUTER_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free`
- After: `grep "^OPENROUTER_MODEL=" /opt/watch/.env` returns exactly the
  required value on line 19.
- `OPENROUTER_API_KEY=SET`, `WATCH_MONGO_URI=SET` (booleans only; values never
  printed).
- Untouched: `ai/llm/openrouter.py` (code fallback stays `minimax` by design —
  env takes precedence), systemd units, all other `.env` settings, all source
  code. No `daemon-reload` (unit files unchanged; oneshot service re-reads
  `EnvironmentFile` on every firing).

## 3. Configuration state (manual run)
- Effective env for the invocation: `WATCH_RESEARCH_ENABLED=true`,
  `WATCH_RESEARCH_DISCOVERY=true`, `WATCH_RESEARCH_NETWORK=true`,
  `WATCH_RESEARCH_LLM=true` (process env of one shell command only — systemd,
  `.env` research flags, and code untouched; discovery/LLM remain disabled by
  default everywhere else).
- Kept defaults (code): window `18:00–00:00 Asia/Tehran`, `max_minutes=300`,
  `max_plans=5`, `max_sources=12`.
- R24 discovery budgets (code defaults, all active): `discovery_max_plans=1`,
  `max_rounds=1`, `max_queries_per_plan=3`, `max_discovered=5`,
  `max_fetched=3`, `max_bytes_per_source=2000000`, `max_bytes_per_run=4000000`,
  `max_llm_calls=1`, `deadline_seconds=120`, `llm_max_retries=0`,
  fallback model unset (no paid escalation path).
- Execution path: real production scheduler —
  `ai.research_cli agent run --force --limit 1 --json` →
  `ResearchScheduler.run_once` → `_build_research_agent` (discovery=true) →
  `DiscoveryResearchAgent` (netguard transport + `LoopBudgets` + primary
  OpenRouter provider, no fallback). Not a synthetic unit test.
- Lock note: the first invocation (10:03:12Z) returned `skipped=locked`
  because the default lock path `/run/watch-research.lock` is not creatable by
  the unprivileged shell (the service normally obtains it via
  `RuntimeDirectory=`). It persisted nothing — zero side effects, zero
  network/LLM. The single real run used `WATCH_RESEARCH_LOCK` pointed at
  `/tmp` (outside the repo; no repo pollution, no systemd change).

## 4. Manual run evidence
- Start: `2026-09-11T10:03:53Z` (`13:33:53+03:30`); end: `10:05:48Z`
  (`13:35:48+03:30`); runtime ~115 s (within the 120 s discovery deadline and
  the 300 min scheduler budget). CLI exit 0.
- `run_id`: `run-20260911T100353Z`; `status`: `RESEARCH_COMPLETED`;
  `forced: true`, `in_window: false`, `dry_run: false`, `failures: []`.
- Selected plans: 1/1 — `r22-38d26f10681e9a0f` (`CVE-2026-1557 → dell`,
  deterministic top-priority R22 plan). Processed: 1.
- Result: `result_id loop-12f2e459394d3256`, `status RESEARCH_COMPLETED`,
  `sources 5`, `evidence 1`.
- Per-item loop detail (exact queries issued, discovered-vs-fetched split,
  unknown/inference counts, per-call LLM accounting, destination URL list):
  **NOT VERIFIED from artifacts** — the scheduler persists the summary run
  record only; the full `DiscoveryPlanResult.loop_result` (which carries
  `llm_status`/`llm_error`/`llm_model`/`llm_calls_used`) is not written by this
  path. No second run was attempted to recover it. Run-level LLM signal is
  positive (`RESEARCH_COMPLETED`, `failures: []`, grounded `evidence: 1`
  against 5 hash-verified sources) under hard caps (max 1 LLM call, 0 retries,
  no fallback — a second paid model was never an option).
- Artifact: `ai_data/research/agent/runs/run-20260911T100353Z.json` (718 bytes,
  atomic single write; read in full — IDs/counts/status only, no secrets).

## 5. Source/discovery/fetch/evidence metrics (observed)
- Plans selected / processed: 1 / 1. Failures: 0.
- Sources (summary count): 5. Evidence (grounded, hash-verified): 1.
- Discovery/fetch/query/byte-level counters and the destination list:
  NOT VERIFIED from persisted artifacts (see §4); structurally bounded by
  `LoopBudgets` (≤3 queries/plan, ≤5 discovered, ≤3 fetched, ≤2 MB/source,
  ≤4 MB/run) and routed exclusively through the netguard fetcher, which
  rejects target/program hosts, metadata endpoints, and non-public addresses.

## 6. LLM result
- Provider: OpenRouter primary only, built with `llm_model '' → None`, so
  `OPENROUTER_MODEL` from the reloaded `.env` governed:
  `nvidia/nemotron-3-ultra-550b-a55b:free` (reconciled in §2 before the run).
- Fallback: none configured (`llm_fallback_model=''`);
  `llm_max_retries=0`. No model substitution occurred or was possible.
- Outcome classification at run level: success (`RESEARCH_COMPLETED`, no
  failures, no error entries). Per-call `llm_status`/`llm_error` fields:
  NOT VERIFIED from artifacts (unp persisted by design in this path).

## 7. Safety verification
- No research process remains (`pgrep research_cli|research_agent|
  discovery_runner` → none); no Nuclei/browser/PoC processes observed.
- No target contact: discovery fetching passes only through the netguard
  fetcher (program-host/metadata/private-IP rejection); the run's 5 sources
  are public-research URLs by construction; no 5B–5J path exists in the
  discovery code.
- No Nuclei, no browser, no PoC, no 5B–5J execution, no findings, no alerts —
  the R24 loop result types force `production_finding=False` via schema
  validators and default `public_research_only=True`; the persisted run record
  contains no finding/alert fields at all.
- Storage atomic/idempotent: run record written once (temp+rename);
  `store_research_loop` correctly wrote nothing because
  `r22-38d26f10681e9a0f.r24-loop-1.loop.json` already existed from the data
  sync (idempotent `written=False`, no overwrite). All four R23 artifacts keep
  their `Sep 10 18:00` timestamps — untouched. Only one repo file changed in
  the run window: the new run record.
- R23 behavior intact: hourly timer firings continue to skip cleanly
  (`10:00 UTC: RESEARCH_BLOCKED / outside_window`, deactivated successfully).

## 8. Timer state
- `watch-research.timer`: `enabled`, `active` — NOT modified in this stage.
- `watch-research.service`: unit file unchanged (still R23-only env:
  `ENABLED=true`, `NETWORK=true`; no discovery/LLM lines).
- R24 hourly activation deliberately NOT enabled.

## 9. Blockers
- None blocking the manual validation — it is complete and clean.
- Known reporting limitation: per-query/per-URL/LLM-call detail is not
  persisted by the `agent run` summary path; if the operational stage requires
  that granularity in artifacts, it needs a code change (out of scope here —
  no code was touched).

## 10. Exact next action (NOT performed)
To make the existing hourly `watch-research.timer` execute R24
discovery/LLM inside the configured window, apply ONLY this to
`/etc/systemd/system/watch-research.service`, then
`sudo systemctl daemon-reload` (no `.env`, code, or timer-file change):
`Environment="WATCH_RESEARCH_DISCOVERY=true"` and
`Environment="WATCH_RESEARCH_LLM=true"`.
Do NOT start the service manually afterward; let the next in-window hourly
trigger (first one inside 18:00–00:00 Asia/Tehran) perform the first scheduled
R24 execution, then review its journal before declaring steady state.

## Agent / Model
- Model: Miuz Spark
- Stage: R24.15
- Role: Model Sync + Controlled R24 Activation
