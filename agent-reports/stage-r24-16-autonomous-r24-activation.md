# Stage R24.16 — Autonomous R24 Activation

## Status
**ACTIVATED (timer-armed, not yet executed).** The existing
`watch-research.timer` will run R24 discovery + LLM on its normal hourly
schedule; the first in-window execution is expected at 15:00 UTC
(18:30 Asia/Tehran). No manual service start was performed in this stage.

## 1. Git HEAD
- `git rev-parse HEAD` → `71fef7ce69bf1f24837b05cf7bf0478daed762ee` — matches
  expected. No commit, no push.
- Required reports present: `stage-r24-12-production-opt-in.md`,
  `stage-r24-15-model-sync-controlled-run.md`.

## 2. Exact systemd changes
- File modified (only file in this stage):
  `/etc/systemd/system/watch-research.service`
- Change: inserted exactly two lines after
  `Environment="WATCH_RESEARCH_NETWORK=true"` (exact-anchor insertion, guarded
  by assertions: anchor present exactly once; no pre-existing DISCOVERY/LLM
  `Environment=` entries):
  `Environment="WATCH_RESEARCH_DISCOVERY=true"`
  `Environment="WATCH_RESEARCH_LLM=true"`
- Untouched: `ENABLED=true`, `NETWORK=true`, lock path, `ExecStart`, user,
  window/budget handling (code defaults), resource limits, timer unit, `.env`,
  all source code. No fallback model added.
- Notable observation: the repo copy (`systemd/watch-research.service` at
  HEAD) carries an R24.8 comment block plus explicit
  `Environment="WATCH_RESEARCH_DISCOVERY=false"`; the installed production
  unit predates that and had no DISCOVERY entry at all (code default `false`
  governed). The activation intentionally added only the two `=true` lines —
  no repo-to-etc copy, no extra lines.

## 3. Daemon-reload result
- `sudo systemctl daemon-reload` → OK.

## 4. systemd-analyze result
- `systemd-analyze verify /etc/systemd/system/watch-research.service` →
  exit 0. Only pre-existing warnings on unrelated units
  (`RuntimeMaxSec` vs `Type=oneshot` on param-discovery/crawl/dns units;
  `OOMScoreAdjust` in `watch-heavy.slice`); nothing on `watch-research.*`.

## 5. Effective R24 configuration
- `systemctl show watch-research.service -p Environment`:
  `WATCH_RESEARCH_ENABLED=true`, `WATCH_RESEARCH_NETWORK=true`,
  `WATCH_RESEARCH_DISCOVERY=true`, `WATCH_RESEARCH_LLM=true`,
  `WATCH_RESEARCH_LOCK=/run/watch-research/research.lock` (+ explicit PATH).
  (EnvironmentFile secrets are not shown by this property — secrets-safe.)
- Discovery budgets, window (`18:00–00:00 Asia/Tehran`), `max_minutes=300`,
  `max_plans=5`, timezone: unchanged code defaults (verified in R24.13/15).

## 6. Model value
- `OPENROUTER_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free` (from R24.15
  single-line `.env` sync; re-verified, unchanged in this stage).
- `OPENROUTER_API_KEY=SET`, `WATCH_MONGO_URI=SET` (booleans only; values never
  printed).

## 7. Timer state
- `watch-research.timer`: `enabled` + `active` (unchanged; timer unit file
  untouched).
- `systemctl list-timers`: next firing `Fri 2026-09-11 11:00:00 UTC`
  (14:30 Tehran — outside the research window, expected clean skip).
- `watch-research.service`: `inactive (dead)` since the 10:00 UTC hourly skip
  (`outside_window`, exit 0). **No manual start performed in this stage**
  (no `systemctl start`, no direct CLI run; the recorded Main PID belongs to
  the scheduled 10:00 UTC firing).

## 8. Confirmation of activation state
- Service has R24 `discovery=true` + `LLM=true` (effective env, §5).
- All pre-existing R23 settings unchanged (§2).
- Timer schedule unchanged (hourly `OnCalendar`, `Persistent=true`).

## 9. Safety verification
- No `research_cli` / `research_agent` / `discovery_runner` processes active.
- No Nuclei, browser, or PoC processes active.
- No manual research run active; no target contact, no 5B–5J, no
  findings/alerts produced in this stage (activation only — nothing executed).

## 10. Expected next scheduled execution
- Next timer firing: 11:00 UTC (outside window → expected `outside_window`
  skip, no R24 work).
- First expected in-window R24 execution: **15:00 UTC = 18:30 Asia/Tehran**
  (first hourly `:00` firing inside 18:00–00:00 Tehran, i.e. 14:30–20:30 UTC).
  Window guard, single-flight lock, discovery budgets (1 plan / 1 round /
  ≤3 queries / ≤5 discovered / ≤3 fetched / ≤4 MB / ≤1 LLM call / 120 s),
  netguard, and fail-soft LLM handling (0 retries, no fallback) all apply.

## 11. Blockers
- None. Activation is complete; do NOT wait for the timer in this stage.

## Agent / Model
- Model: Miuz Spark
- Stage: R24.16
- Role: Autonomous R24 Activation
