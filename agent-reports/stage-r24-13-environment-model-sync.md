# Stage R24.13 — Environment & Model Sync Verification

## Status
**CONDITIONAL GO** — code, tests, data, systemd, and process state all verified
clean; two non-blocking flags recorded for the next operational stage
(research-model value differs from expectation; one committed report file is
deleted in the worktree). No activation performed in this stage.

## 1. Code Sync
- Current HEAD: `71fef7ce69bf1f24837b05cf7bf0478daed762ee`
  (`feat(research): complete public-source discovery R24`)
- Expected R24 commit: `71fef7ce69bf1f24837b05cf7bf0478daed762ee`
- Match: **yes — HEAD equals the expected commit.**
- Git working-tree state (`git status --short`):
  - ` D agent-reports/stage-r24-12-production-opt-in.md` — the file is tracked
    in `71fef7c` (278 lines) but deleted in the worktree (unstaged deletion;
    `git diff --stat` shows 1 file, 278 deletions). Not repaired in this
    read-only stage; flagged for reconciliation.
  - Pre-existing untracked (unchanged, not touched):
    `agent-reports/stage-r23-2-final-google-vm.md`, `ai_data/knowledge/`,
    `ai_data/reports/`, `crawl/output/`, `dns-bruteforce/`.
- `SchedulerConfig` exposes the full R24 surface (`discovery`,
  `discovery_max_plans`, `discovery_max_rounds`,
  `discovery_max_queries_per_plan`, `discovery_max_discovered`,
  `discovery_max_fetched`, `discovery_max_bytes_per_source`,
  `discovery_max_bytes_per_run`, `discovery_max_llm_calls`,
  `discovery_deadline_seconds`, `llm_model`, `llm_fallback_model`,
  `llm_max_retries`) with conservative defaults.

## 2. R24 Test Status
- Actual result already obtained (not rerun): the 10-module R24 battery
  (`tests.test_research_agent`, `tests.test_research_agent_r24_1`,
  `tests.test_research_agent_r24_2`, `tests.test_research_agent_r24_3`,
  `tests.test_research_agent_r24_4`, `tests.test_research_agent_r24_5`,
  `tests.test_research_agent_r24_6`, `tests.test_research_agent_r24_8`,
  `tests.test_research_agent_r24_10`, `tests.test_research_agent_r24_11`)
  → **Ran 487 tests — OK** (exit 0).
- Expected baseline: 487 tests OK — **met exactly.**

## 3. Model Configuration
- **Miuz Spark = coding/agent model** (this verification session; writes the
  report, runs no production workload).
- **OPENROUTER_MODEL = application's optional research LLM** (used only by the
  research agent's synthesis step; never the agent model; no substitution made).
- Expected research model: `nvidia/nemotron-3-ultra-550b-a55b:free`
- Observed OPENROUTER_MODEL (effective value from the service's
  `EnvironmentFile`, `.env`): `minimax/minimax-m3:free` — **differs from the
  expected value; reported as-is, NOT changed.**
- Verbatim process-environment snippet output (bare shell, no dotenv load):
  `WATCH_RESEARCH_ENABLED=None`, `WATCH_RESEARCH_NETWORK=None`,
  `WATCH_RESEARCH_DISCOVERY=None`, `WATCH_RESEARCH_LLM=None`,
  `WATCH_RESEARCH_WINDOW_START=None`, `WATCH_RESEARCH_WINDOW_END=None`,
  `WATCH_RESEARCH_MAX_MINUTES=None`, `WATCH_RESEARCH_MAX_PLANS=None`,
  `WATCH_RESEARCH_MAX_SOURCES=None`, `WATCH_RESEARCH_TIMEZONE=None`,
  `OPENROUTER_MODEL=None`, `OPENROUTER_MAX_TOKENS=UNSET`.
- Secrets (SET/UNSET only, values never recorded):
  `OPENROUTER_API_KEY=UNSET`, `WATCH_MONGO_URI=UNSET` (process environment;
  the service resolves them at runtime via `EnvironmentFile=/opt/watch/.env`).

## 4. Data Sync
- `ai_data/research/agent` file count (excluding `*.lock`): **15** —
  expected count = 15 — **met exactly.**
- Both R24 loop artifacts exist:
  - `r22-38d26f10681e9a0f.r24-loop-1.loop.json` — present
  - `r22-fda96966ea7af4ae.r24-loop-1.loop.json` — present
- Existing R23 artifacts preserved: both `r22-*.r23-1.json` result files, both
  `r22-*.r23-1.md` reports, and all 9 `runs/run-*.json` run records remain in
  place, unmodified.
- R24 data sync was additive: only the two `r24-loop-1.loop.json` files were
  added; nothing was overwritten or removed under `ai_data/research/agent`.

## 5. Systemd State
- `watch-research.service` (installed unit matches repo; read via
  `systemctl cat`, not modified): `Type=oneshot`, `User=pouya_behnia`,
  `WorkingDirectory=/opt/watch`, `EnvironmentFile=/opt/watch/.env`,
  `RuntimeDirectory=watch-research`, outer `flock` on
  `/run/watch-research/service.lock`, app lock
  `WATCH_RESEARCH_LOCK=/run/watch-research/research.lock`,
  `TimeoutStartSec=330min`, least-privilege hardening intact,
  `MemoryMax=1G`, `CPUQuota=150%`.
- Service policy environment: `WATCH_RESEARCH_ENABLED=true`,
  `WATCH_RESEARCH_NETWORK=true` — and nothing else.
- `watch-research.timer`: `is-enabled` → `enabled`; `is-active` → `active`
  (hourly `OnCalendar`, `Persistent=true`, `AccuracySec=1min`). Observed only;
  not changed.
- `WATCH_RESEARCH_DISCOVERY`: **absent/unset** — R24 discovery remains disabled
  by default; no opt-in activated.
- `WATCH_RESEARCH_LLM`: **absent/unset** — LLM remains at its safe disabled
  default (`llm=False`); no paid-model escalation configured
  (`llm_model=''`, `llm_fallback_model=''`).
- Research window: `18:00–00:00 Asia/Tehran` (code defaults
  `window_start='18:00'`, `window_end='00:00'`, `timezone='Asia/Tehran'`).
- Max minutes: `300`. Max plans: `5` (`max_sources=12`).
- None of these values were modified.

## 6. Running Processes
- `pgrep -af 'research_cli|research_agent|discovery_runner'` matched only its
  own wrapper shell process — **no research/discovery operation was running
  during verification.**

## 7. Safety Boundary
- No R24 production activation performed.
- No target interaction of any kind.
- No Nuclei execution.
- No browser execution.
- No PoC execution.
- No 5B–5J execution.
- No finding or alert creation.
- No scheduler run, no test rerun, no systemd change, no `.env`/secret change,
  no MongoDB change, no application-code change, no commit, no push.

## 8. Final Decision
**CONDITIONAL GO for the NEXT operational R24 activation stage.** All sync
gates pass (commit match, 487 tests OK, 15 data files including both loop
artifacts, systemd clean with discovery off, zero running processes). Before
any LLM-enabled operational run, resolve: (1) the research-model difference
(configured `minimax/minimax-m3:free` vs expected
`nvidia/nemotron-3-ultra-550b-a55b:free`); (2) the worktree deletion of the
committed `stage-r24-12-production-opt-in.md` report.

## Agent / Model
- Model: Miuz Spark
- Stage: R24.13
- Role: Environment & Model Sync Verification
