# Stage R24.17 — First Scheduled R24 Execution Verification

## Status
**R24 FIRST SCHEDULED RUN = GO.** Read-only verification only; nothing was
modified in this stage.

## 1. First in-window execution
- Window: 18:00–00:00 Asia/Tehran = 14:30–20:30 UTC.
- Prior firings (11:00, 12:00, 13:00, 14:00 UTC) all skipped cleanly
  (`outside_window`, exit 0) — R24-armed unit behaves identically out of window.
- **First in-window firing: 15:00:10 UTC = 18:30:12 +0330** (inside window).
  - Timer activation: `Starting watch-research.service` at 15:00:10 UTC.
  - Service end: `Deactivated successfully` / `Finished` at 15:02:08 UTC
    (~118 s wall time, within the 120 s discovery deadline and 300 min budget).
  - `run_id`: `run-20260911T150012Z`. Exit: `code=exited, status=0/SUCCESS`.
  - Journal: `STATUS: RESEARCH_COMPLETED`, `Plans selected: 2`,
    `Plans processed: 1`,
    `r22-38d26f10681e9a0f CVE-2026-1557 -> dell [RESEARCH_COMPLETED]
    evidence=1 sources=5`, research-only mode line.

## 2. Scheduler path
- Chain confirmed: `watch-research.timer` → `watch-research.service`
  (timer `Starting` line + `TriggeredBy` linkage) → `ResearchScheduler`
  (`RUN:`/`STATUS:` record lines, persisted run artifact) → **R24
  `DiscoveryResearchAgent`** (not inferred from exit code):
  - The unit carried `WATCH_RESEARCH_DISCOVERY=true` +
    `WATCH_RESEARCH_LLM=true` since the R24.16 reload (before the 11:00 firing).
  - The result ID `loop-12f2e459394d3256` uses the discovery-loop ID scheme
    and is bit-identical to the R24.15 manual discovery run's result for the
    same plan (deterministic per-plan loop ID — same code path).
  - `selected 2 / processed 1` proves the discovery budget cap engaged:
    `DiscoveryResearchAgent.run_plans` slices to `discovery_max_plans=1`,
    while the R23 agent path would have processed both selected plans.

## 3. Persisted run artifact
- Path: `ai_data/research/agent/runs/run-20260911T150012Z.json` (718 bytes,
  written atomically at 15:02:08 UTC).
- `status`: `RESEARCH_COMPLETED`; `failures: []`; `skipped: null`.
- Selected plans: 2; processed plans: 1
  (`r22-38d26f10681e9a0f`, `CVE-2026-1557 → dell`, `RESEARCH_COMPLETED`,
  `evidence 1`, `sources 5`).
- Runtime: `started_at 18:30:12+03:30` → `completed_at 18:32:08+03:30` (~116 s).
- `forced: false`, `in_window: true`, `enabled: true`, `network: true`,
  `llm: true`, `window: 18:00-00:00 Asia/Tehran`, `dry_run: false`.
- Artifact contains IDs/counts/status/timestamps only — no secrets.

## 4. R24 loop result
- Loop-result persistence is idempotent per plan (`plan_id + r24-loop-1`):
  `store_research_loop` correctly wrote nothing because
  `r22-38d26f10681e9a0f.r24-loop-1.loop.json` already existed from the data
  sync (no overwrite, no duplicate). Therefore per-item loop detail for this
  scheduled execution:
  - `result_id`: `loop-12f2e459394d3256` (from run artifact)
  - `queries`: NOT PERSISTED
  - `discovered sources`: NOT PERSISTED (summary `sources: 5`)
  - `fetched sources`: NOT PERSISTED (summary `sources: 5`)
  - `evidence`: 1 (summary count; grounded, hash-verified)
  - `inference`: NOT PERSISTED
  - `unknown`: NOT PERSISTED
  - `LLM calls`: NOT PERSISTED (structurally capped at ≤1 call, 0 retries,
    no fallback)
  - `LLM status`: run-level success (`RESEARCH_COMPLETED`, `failures: []`);
    per-call `llm_status`: NOT PERSISTED
  - `LLM model`: run-level effective model per §5; per-call echo:
    NOT PERSISTED
  - `LLM error`: none recorded (`failures: []`); per-call field:
    NOT PERSISTED
  - `final status`: `RESEARCH_COMPLETED`

## 5. Model
- Scheduled service resolves the model from `EnvironmentFile=/opt/watch/.env`:
  `OPENROUTER_MODEL='nvidia/nemotron-3-ultra-550b-a55b:free'` — matches the
  reconciled expectation (re-verified, unchanged).
- `OPENROUTER_API_KEY = SET`; `WATCH_MONGO_URI = SET` (booleans only; values
  never printed).

## 6. Safety verification (read-only)
- No target URL/host interaction: discovery fetching is netguard-routed only
  (program/metadata/non-public rejection); journal shows research-only mode.
- No monitored-asset HTTP request; no Nuclei process; no browser process;
  no PoC execution; no 5B–5J execution.
- No finding created; no alert created (run artifact carries no
  finding/alert fields; loop types force `production_finding=false` via schema
  validators and default `public_research_only=true`).
- `production_finding=false` (schema-forced); `public_research_only=true`
  (loop-result default, validator-enforced).
- R23 artifacts not overwritten: all four `r22-*.r23-1.*` files keep
  `Sep 10 18:00` timestamps/sizes; loop files untouched.

## 7. Idempotency / storage
- Exactly one new repo file from the scheduled run: the run record above.
  IDs are deterministic (`run-…T150012Z` matches the 15:00 firing;
  `loop-12f2e…` matches the plan's loop ID from the R24.15 manual run).
- No duplicates, no overwrites, no temp files left behind.

## 8. Timer health
- `watch-research.timer`: `enabled` + `active`; schedule unchanged (hourly).
- Next firing: `Fri 2026-09-11 17:00:00 UTC` (20:30 Tehran — in-window).
- Service returned to `inactive (dead)` normally after the oneshot run
  (exit 0; same after the 16:00 UTC run).
- Note (observed, out of scope): a second scheduled in-window run at
  16:00 UTC also completed at run level (`RESEARCH_COMPLETED`, 2 selected /
  1 processed, no failures) with plan-level `RESEARCH_PARTIAL`
  (evidence=1, sources=5) — normal fail-soft behavior, steady state healthy.

## 9. Verdict
**R24 FIRST SCHEDULED RUN = GO**
- Actual timer-triggered in-window execution: yes (15:00 UTC).
- R24 discovery path confirmed (§2).
- No safety violation (§6).
- Result persisted (§3, §7).
- No target interaction, no Nuclei/browser/PoC, no finding/alert (§6).
- Timer remains healthy (§8).

## Agent / Model
- Model: Miuz Spark
- Stage: R24.17
- Role: First Scheduled R24 Execution Verification
