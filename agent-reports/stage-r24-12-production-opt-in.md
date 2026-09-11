# Stage R24.12 — Controlled Production Opt-in Activation on Google VM

Status: **NOT ACTIVATED — NO-GO.** R24 preconditions failed on this VM.
No production change was made. No R24 discovery was enabled.

Per the task gate ("If the manual run fails, DO NOT enable the timer"),
no timer change, no service start, and no configuration change was performed
for R24. The existing R23 research timer/service was left completely untouched.

## 1. VM identity

- `hostname`: `instance-20260905-110257` (Google Compute Engine VM — correct
  target machine)
- `whoami`: `pouya_behnia`
  (`uid=1001(pouya_behnia)`, groups include `sudo`, `google-sudoers`, `docker`)
- `pwd`: `/opt/watch`, branch `main`
- Clock at verification: `Fri Sep 11 06:18–06:20 UTC 2026`
  = `Fri Sep 11 09:48–09:50 +0330 2026 (Asia/Tehran)` —
  **outside** the 18:00–00:00 Asia/Tehran research window.
- Kernel: `Linux instance-20260905-110257 6.17.0-1022-gcp #25-Ubuntu SMP`;
  uptime ~1 day 23:54; load ~0.40. No VPS touched (this host only).

## 2. Git revision (deployed revision is R23, NOT R24)

- `git rev-parse HEAD`: `5dc174f292d7d4e53de296558a6acda8cb5d2933`
- `git log --oneline -3`:
  - `5dc174f feat(research): add autonomous research scheduler (R23)`
  - `42644bc fix(ui): repair research navigation and recent operations`
  - `3f066c0 feat(research): add execution planning`
- `git log --all --oneline --grep="R24"`: empty — **no R24 commit exists** in
  any branch/history.
- `git log --all --oneline --grep="iscovery"`: only `ae143a3 fix: harden x8
  parameter discovery` (unrelated crawl/param-discovery subsystem).
- `git status --short`: only pre-existing untracked paths
  (`agent-reports/stage-r23-2-final-google-vm.md`, `ai_data/knowledge/`,
  `ai_data/reports/`, `crawl/output/`, `dns-bruteforce/`); zero tracked
  modifications. No commit, no push, no reset performed.

## 3. Preflight — referenced stage inputs (ALL MISSING)

The three required input reports do not exist on this VM or in git:

- `agent-reports/stage-r24-11-llm-reliability.md` → **not found**
- `agent-reports/stage-r24-9-controlled-opt-in.md` → **not found**
- `agent-reports/stage-r24-10-fetch-ranking-hardening.md` → **not found**

Full `agent-reports/` listing (172 entries) inspected: newest research entry is
`stage-r23-2-final-google-vm.md`; no `*r24*` file of any kind exists.

## 4. Preflight — R24 modules (ALL ABSENT)

- Repo-wide grep for `WATCH_RESEARCH|RESEARCH_DISCOVERY|DiscoveryResearch|R24`
  finds only R23 wiring (`WATCH_RESEARCH_ENABLED/NETWORK/LOCK` in
  `ai/research_agent/scheduler.py`, `systemd/watch-research.service`, R23 tests).
- Definitive grep for
  `DISCOVERY|DiscoveryResearch|max_rounds|max_queries_per_plan|max_discovered|max_fetched|max_bytes_per|llm_max_retries|max_llm_calls|deadline_seconds|FALLBACK_MODEL|fallback_model`
  returns **zero R24 hits** (only unrelated: `DISCOVERY_EVIDENCE_LIMIT` const in
  `watch_xss_verify.py`, param-discovery cron line, reference-ranker tag const).
- Concretely absent from the codebase:
  - `WATCH_RESEARCH_DISCOVERY` — no producer, no consumer, no default
  - `DiscoveryResearchAgent` — no class, no import, no scheduler hook
  - R24 budget keys (`max_plans=1/max_rounds=1/max_queries_per_plan=3/
    max_discovered=5/max_fetched=3/max_bytes_per_source/max_bytes_per_run/
    max_llm_calls=1/deadline_seconds=120/llm_max_retries=0`) — none parsed in
    `SchedulerConfig.from_env()` (which handles only
    `ENABLED/WINDOW_START/WINDOW_END/MAX_MINUTES/MAX_PLANS/TIMEZONE/NETWORK/LLM/
    MAX_SOURCES/KB_INGEST/LOCK/AGENT_DIR/RESEARCH_DIR`)
  - `WATCH_RESEARCH_LLM_FALLBACK_MODEL` — absent everywhere (nothing to keep empty)
  - R24 fetch/ranking/transport/netguard chain — `sources.py` is the R23
    `ResearchSourceCollector` (stored-archive + bounded fetch); no R24 priority
    stage exists
- `database/db.py`: **untouched** (not even read for this task).

## 5. Tests

Existing suites (pass):

- `python3 -m unittest tests.test_research_agent` → **Ran 92 tests — OK**
- `python3 -m unittest ai.test_openrouter` → **Ran 33 tests — OK**

Requested R24 suites (all missing — `ModuleNotFoundError`, `errors=1` each):

- `tests.test_research_agent_r24_1` … `_r24_6`, `_r24_8`, `_r24_10`, `_r24_11`
  → **none importable**; `ls tests/ | grep -i r24` → no match.
- The task's "full existing suite" therefore cannot pass as specified: 9 of 11
  listed modules do not exist. This alone blocks activation.

`git diff --check` → clean (no output, exit 0).

## 6. Exact configuration (NO CHANGE — deliberate)

No file, unit, or environment variable was modified for R24. Setting
`WATCH_RESEARCH_DISCOVERY=true` was **deliberately NOT done**: with no code
consuming it, the flag would be a dead variable that falsely signals an active
opt-in while changing nothing — worse than leaving the explicit absent state.

Current intentional state (verified, names only — no secret values printed):

- `.env`: **zero** `WATCH_RESEARCH_*` keys; has `AI_PROVIDER`,
  `OPENROUTER_API_KEY`, `OPENROUTER_MAX_TOKENS`, `OPENROUTER_MODEL` (names only).
  No `WATCH_RESEARCH_DISCOVERY`, no `WATCH_RESEARCH_LLM*` fallback key.
- `watch-research.service` Environment (installed == repo, diff exit 0):
  - `WATCH_RESEARCH_ENABLED=true`, `WATCH_RESEARCH_NETWORK=true` (R23 only)
  - `WATCH_RESEARCH_LOCK=/run/watch-research/research.lock`
  - No `WATCH_RESEARCH_DISCOVERY`, no `WATCH_RESEARCH_LLM`,
    no fallback-model variable, no R24 budget variables.
- R23 pipeline behavior: unchanged. No aggressive budgets. No paid-model
  escalation path configured anywhere.

## 7. Systemd validation (NO CHANGE — deliberate)

- `diff systemd/watch-research.service /etc/systemd/system/watch-research.service`
  → identical (exit 0). Timer diff → identical (exit 0).
- `systemd-analyze verify` on both repo units → exit 0 (only pre-existing
  warnings on unrelated units: `RuntimeMaxSec` vs `Type=oneshot` on
  watch-param-discovery/crawl/dns units; `OOMScoreAdjust` in watch-heavy.slice;
  nothing on `watch-research.*` itself).
- `systemctl daemon-reload` → **NOT executed**: nothing changed, so a reload
  would be a no-op write to production systemd state; skipped per minimal scope.
- No second timer/scheduler created. Installed research units: exactly
  `watch-research.service` + `watch-research.timer` (no duplicates).
- Service user: `User=pouya_behnia`, `WorkingDirectory=/opt/watch`,
  `RuntimeDirectory=watch-research` (mode 0750). `/run/watch-research` absent
  while idle — expected (created at start by `RuntimeDirectory=`); lock path
  `/run/watch-research/research.lock` + outer `flock service.lock` therefore valid.
- No old R24 process running (`ps aux | grep research` → only the grep/verify
  probes themselves).
- Storage writable by service user: `ai_data/`, `ai_data/research/`,
  `ai_data/research/agent/` all owned `pouya_behnia`; write probe
  (`touch` + `rm` as `pouya_behnia`) succeeded. Existing R23 artifacts present
  (`r22-*.r23-1.json/.md`, `runs/run-20260910T*.json`) — left untouched.

## 8. Manual run (NOT EXECUTED — precondition failure, per gate)

No manual `watch-research.service` run was started for R24, deliberately:

- There is no R24 discovery code path to exercise — a forced
  `systemctl start watch-research.service` (or `--force` CLI run) would execute
  the **R23** agent only and could be misread as R24 verification.
- Current wall time (09:48 Tehran) is outside the Tehran window, so a
  non-forced run would only reproduce the already-observed `outside_window` skip.
- No direct Python invocation was used either (nothing to bypass systemd for).

For context (read-only, no action taken): the last scheduled R23 execution at
`06:00:10 UTC` exited `status=0/SUCCESS` with `RESEARCH_BLOCKED /
SKIPPED: outside_window / Plans selected: 0` — the window guard works.

Preferred plan `CVE-2026-1557` exists in the R22 projection (dry-run shows 2
eligible plans: `CVE-2026-1557 -> dell`, `CVE-2026-1557 -> indeed`), but without
R24 code no discovery chain
(`ResearchScheduler -> DiscoveryResearchAgent -> R24 discovery -> netguard ->
transport -> ranking/fetch -> evidence -> LLM -> research-only storage`) exists
to verify, so the plan was **not** consumed.

## 9. Safety (holds vacuously — nothing R24 executed)

No R24 run occurred, so all safety invariants hold by non-execution:

- No target URLs/hosts/IPs/HTTP contact; no Nuclei; no browser; no PoC;
  no verifier; no 5B–5J contact; no findings; no alerts.
- Only-public-research-sources property unverifiable for R24 (no R24 fetcher
  exists); R23 `validate_source_url` (SSRF/program-host/metadata guards) was not
  modified.
- Program names never entered any LLM context in this task (no LLM call made).
- No secrets printed: `.env` inspected by key name only; Mongo URI never shown
  (scheme + ping + count only — see §10).

## 10. Observe (R23 steady-state only; no R24 run to capture)

- `systemctl status watch-research.timer`: `enabled`, `active (waiting)` since
  Sep 10 17:35 UTC; next trigger `Fri 2026-09-11 07:00:00 UTC`
  (10:30 Tehran — inside the 18:00–00:00 window? No: 10:30 is outside, so the
  next hourly firing is also expected to skip cleanly; the first in-window
  firing is the 14:30–15:00 UTC band).
- `systemctl status watch-research.service`: `inactive (dead)` since 06:00:10 UTC
  (clean exit, `CPU: 417ms`) — service exits cleanly after each oneshot skip.
- `journalctl -u watch-research.service` (last 5 firings 02:00–06:00 UTC): every
  run `RESEARCH_BLOCKED / SKIPPED: outside_window / selected 0 / processed 0 /
  MODE: research-only`. No errors.
- `journalctl -u watch-research.timer`: only the `Started` line (no errors).
- Runtime/budgets/sources/evidence/LLM/network-destinations for R24:
  **none** — no R24 run exists to measure. Nothing to report as
  `production_finding` or `public_research_only` beyond the R23
  `research-only (authoritative=False)` steady state.

## 11. Timer (NO CHANGE — already active for R23, left alone)

- `systemctl is-enabled watch-research.timer` → `enabled`
- `systemctl is-active watch-research.timer` → `active`
- `systemctl list-timers watch-research.timer` → `NEXT Fri 2026-09-11 07:00 UTC`
  (hourly `OnCalendar`, `Persistent=true`, `AccuracySec=1min`).
- Per the task gate, the timer was **NOT** enabled/started by this task (it was
  already enabled since Sep 10 17:35 UTC for R23) and must **NOT** be treated as
  R24 activation. No second start of the service was performed.

## 12. First automated run (NOT APPLICABLE)

No scheduled execution was waited for or triggered under R24: with no R24 code,
the next hourly firing will be another R23 `outside_window` skip. The task's
"wait for ONE scheduled execution" step is moot until R24 lands. Timer remains
`active (waiting)`; service remains `inactive (dead)` between triggers.

## 13. Post-run check

- `WATCH_RESEARCH_DISCOVERY=true` does **NOT** remain anything — it was never
  set. The absent state is the intentional safe state; see rollback (§15).
- No second lock/scheduler/process: single service+timer, single app lock path,
  single outer flock path, zero research processes idle.
- Storage artifacts: pre-existing R23 results/run records valid, atomic
  (temp+rename writer), untouched by this task.
- No secrets in logs/artifacts: journals contain only run IDs/status/counts;
  nothing was written to reports (no API keys, no URIs, no tokens).
- Mongo: reachable via the existing configured URI — `ping ok=1.0`,
  `http assets: 4540` (URI value never printed).
- R23 services unaffected: `watch.timer active`, `watch.service inactive`
  (normal oneshot idle), `watch-api active`; research timer/service state as in
  §10–11; zero file modifications (`git diff --check` clean).

## 14. R23 health (explicit)

- Core pipeline timers present and scheduled (`watch`, `watch-crawl-all`,
  `watch-param-discovery`, `watch-dns-*`); no research interference observed.
- Research agent CLI (default env, no service overrides): `Enabled: false`,
  `Window: 18:00-00:00 Asia/Tehran`, `In window: false`,
  `Next run: 2026-09-11T18:00:00+03:30`, `Network: enabled`, `LLM: disabled`,
  2 eligible `CVE-2026-1557` plans in dry-run preview — deterministic R23
  behavior, unchanged.

## 15. Rollback procedure (nothing to roll back; exact inverse if ever set)

No rollback was performed (nothing healthy-or-otherwise was changed). If a
future stage sets the flag and needs to revert, the exact inverse is:

```bash
# 1. Remove (or set false) ONLY the discovery flag in the service unit:
#    delete the line: Environment="WATCH_RESEARCH_DISCOVERY=true"
#    (preferred: absent over false; never add fallback-model lines)
sudoedit /etc/systemd/system/watch-research.service
# 2. Reload without touching R23 units:
sudo systemctl daemon-reload
# 3. If the research timer must be stopped without touching R23:
sudo systemctl disable --now watch-research.timer
#    (leaves watch.timer, watch.service, watch-api, crawl/dns units running)
# 4. Verify:
systemctl is-enabled watch-research.timer  # expect: disabled (or not-found if removed)
systemctl status watch-research.service     # expect: inactive (dead)
git diff --check
```

Current state already equals the rolled-back state (flag absent, R23 timer
running its safe skip loop).

## 16. GO / NO-GO

**NO-GO for R24.12 activation.** Reasons (any one alone blocks):

1. Deployed revision is R23 (`5dc174f`); zero R24 commits in history.
2. All three prerequisite stage reports (R24-9/10/11) are missing.
3. `DiscoveryResearchAgent` / `WATCH_RESEARCH_DISCOVERY` / all R24 budget and
   fallback-model keys are absent from code, units, and env.
4. 9 of 11 required test modules do not exist (existing 92 + 33 tests pass,
   but the R24 contract is unverifiable).
5. With no R24 path, the mandated manual systemd run + safety observation
   cannot be performed honestly; per the task gate the timer must therefore
   NOT be enabled for R24.

What is healthy (and preserved): R23 timer active, window guard skipping
cleanly, Mongo reachable, storage writable, R23 services unaffected, working
tree clean, no secrets exposed.

Next step for the owning stage: land the R24 diff (discovery agent + budgets +
fallback-model plumbing + `tests/test_research_agent_r24_{1..6,8,10,11}` +
stage reports R24-9/10/11) and re-run this activation checklist from §1.

## Agent / Model
- Model: opencode/muse-spark-1.3-contributor-free
- Stage: R24.12
- Role: Controlled Production Opt-in Activation
