# EPIC9 — Autonomous AI Operations Window v1

Status: **READY TO PUSH: YES**
Branch: `agent/daily-development`
Base: `3b977ae` (EPIC8) / production main `2fcc1f9`

## 1. Mission (§25 contract)

Connect the existing Watch capabilities into an operational loop: a
window-gated, bounded, recurring AI operations dispatcher — NOT a
persistent 12-hour daemon.

## 2. Architecture audit findings (§1, actual, not assumed)

- Window: `SchedulerConfig` defaults `12:00`/`00:00`/`Asia/Tehran`
  (env-overridable via `WATCH_RESEARCH_WINDOW_*`).
- Scheduler: `ResearchScheduler` one-shot, invoked by
  `ai/research_cli.py agent run` under `watch-research.service`
  (oneshot, `flock`, `RuntimeDirectory=watch-research`),
  `watch-research.timer` hourly (`OnCalendar=hourly, Persistent=true`).
- Deployed unit differs from repo: `DISCOVERY=true, LLM=true` (owner-set).
- Agent Runtime: bounded one-shot (`cli run`), lease 30s, worker TTL
  120s, `sweep()` stale-lease recovery, flock claim — NO systemd unit,
  no cron, no launcher anywhere (deliberate policy).
- Stores/queues: `RuntimeStore` (jobs, audit), `CampaignStore`
  (objectives, leases, `OBJECTIVE_EXECUTABLE={"READY"}`,
  `OBJECTIVE_TERMINAL`, scope validation on load),
  `HuntStore` (`NEEDS_EVIDENCE` open state), `FindingStore`
  (candidate lifecycle, verification objectives).
- Schedules: research timer hourly; nightly pipeline 00:00 Tehran;
  heavy jobs 06:00 Tehran; report timer hourly.
- Production schedules and the AEC read-only manifest (116 pinned
  files incl. `systemd/watch-research.service`) verified.

## 3. AI Operations Window (§2)

ONE authority: `backend/ai_ops/window.py`
(`AIWindow`, `DEFAULT_WINDOW`, `START=12:00`, `END=00:00`,
`TIMEZONE=Asia/Tehran`). Semantics: start inclusive, end exclusive,
midnight-crossing, `start==end` closed, naive input = UTC
(fail-closed), ZoneInfo conversions (DST-safe where the tz has DST).
`ai/research_agent/scheduler.py` now DELEGATES (`parse_hhmm`,
`in_window`, `next_window_start`, field defaults) — no duplicate
window literal exists outside the authority (AST-guarded by test).
Boundaries verified: 11:59 CLOSED, 12:00 OPEN, 23:59 OPEN,
00:00 CLOSED; 48-point all-day sweep: scheduler == dispatcher.

## 4. Dispatcher (§3–§9)

`backend/ai_ops/`: `config` (fail-safe disabled; `WATCH_AI_OPS_*`
budgets: max_seconds 600, max_work 4, per-target 2, per-campaign 1,
attempts 3, backoff 900s, tick minute 30), `discovery` (fail-closed
classification over the four EXISTING stores, explicit reasons
NOT_AUTHORIZED / WAITING_FOR_EVIDENCE / DEPENDENCY_BLOCKED /
ALREADY_RUNNING / TERMINAL / RETRY_NOT_DUE / OUT_OF_WINDOW /
INVALID_STATE / BUDGET_DEFERRED + per-item detail; per-source
fail-soft errors, never silent), `priority` (documented total order:
class rank → persisted priority DESC → age → scope → id; bounded
fairness caps + round-robin-by-cap; no opaque score, no
security-quality ranking), `dispatcher` (one tick: lock → window gate
→ sweep → discover → select → bounded execution between units only
(WALL_BUDGET / WORK_BUDGET / WINDOW_CLOSED → STOP_GRACEFULLY) →
persist), `state` (operations state file, process-vs-operations
separation), `activity` (11-name strict taxonomy through the EXISTING
audit stream), `cli` (`tick`, read-only `status [--at]` what-if).

Execution uses EXISTING entrypoints only: real bounded
`AgentWorker` drain, `execute_campaign`, `run_findings` — no new
queue, no executor re-implementation, Evidence Gate / authorization
remain with the existing layers (dispatcher never calls
transition/evidence/authz APIs — AST-guarded).

## 5. NEEDS_EVIDENCE (§6)

`classify_hunt_objective(NEEDS_EVIDENCE)` is permanently
non-executable; a full tick cannot mutate it (production readback
after the real tick: `obj-ee1f9d358598` still `NEEDS_EVIDENCE`), and
one waiting objective does not block other work (test: NEEDS_EVIDENCE
+ executable job → job executes, waiting event emitted).

## 6. Scheduler integration (§10)

ONE hourly tick: `research_cli agent run` → research pass →
`_ai_ops_after_research()` (fail-soft, opt-in
`WATCH_AI_OPS_ENABLED`). NO second scheduler, NO new unit/timer/daemon
(tests assert absence). Enablement travels via `/opt/watch/.env`
(gitignored), which the pinned unit already loads through its
existing `EnvironmentFile=/opt/watch/.env` line — the unit file stays
byte-identical to its AEC pinned hash (an earlier unit edit was
caught by the AEC readonly guard and REVERTED).

## 7. Runtime state (§12) — process vs operations

`ai_ops_state.json`: OFF_WINDOW / IDLE / DISCOVERING / EXECUTING /
WAITING_FOR_EVIDENCE / BLOCKED / COMPLETED_TICK / FAILED (+ tick
records, stop_reasons, deferred, recovered_interrupted). Process
liveness stays in `worker.json` TTL — the panel reports BOTH facts:

    Process:  NOT RUNNING       (no heartbeat, no claim otherwise)
    AI ops:   IDLE / BLOCKED / WAITING FOR EVIDENCE / ...

A dispatcher tick NEVER writes a heartbeat (test-verified).

## 8. Activity (§13) + taxonomy

ai_window_opened/closed, ai_tick_started/completed,
work_discovered/selected/started/completed/blocked,
waiting_for_evidence, tick_budget_exhausted — each with timestamp,
tick id, counts/reasons/ids; unknown names RAISE (nothing fabricated).
All 11 registered in `prod_intel.EVENT_CATEGORY` (feed-visible).

## 9. SOC UI/API (§14/§15)

`overview_payload()["ai_ops"]` + home panel: window label + OPEN /
CLOSED, operations state (display mapping), current/last/next tick,
work discovered/executable/waiting/blocked/terminal with by-reason
breakdown, process running/not-running with reason, and the explicit
"normally NO worker process between bounded ticks is healthy"
explanation. New authenticated endpoint `/api/intel/ai-ops`
(401 without key, schema-tested, no secrets in response).

## 10. Production validation (§16) — REAL, no fabricated work

Real bounded tick `tick-20260923T162242Z-bd333781` (in window,
production data, worktree code):

    OUTCOME: COMPLETED_TICK
    DISCOVERED: total=52 executable=0 waiting=1 blocked=51
    EXECUTED: 0

- A outside-window: dispatcher gate returns
  SKIPPED_OUT_OF_WINDOW (deterministic tests + status what-if;
  real out-of-window ticks resume automatically after 00:00 Tehran).
- B/C window-open discovery: 52 real items classified with reasons.
- D: no genuinely executable work exists today (queue empty; campaigns
  COMPLETED/BLOCKED; all candidates VERIFIED/DUPLICATE/BLOCKED;
  verification objectives EXPIRED/FAILED/VERIFIED; research plans
  case-gated) — NO fake work created (per instruction).
- E: blocked/waiting states demonstrated (51 blocked w/ reasons,
  1 waiting = PROVIDE_EVIDENCE objective).
- F: NEEDS_EVIDENCE untouched (readback above).
- G bounded: budgets persisted (max_work/max_seconds/per-target).
- H activity: 6 audit events with tick id — read back from
  production `audit.jsonl`.
- I runtime state: `ai_ops_state.json` persisted (state BLOCKED =
  honest "work exists, none executable, evidence pending").
- J next tick: computed at the timer's hourly cadence.
- K recovery: interrupted-tick recovery flag + sweep() + lock release
  all test-verified; real tick exited cleanly.

LLM: the dispatcher itself performs ZERO LLM calls (no LLM code path;
runners construct default deterministic RuntimeConfig). Validation:
0 calls, **0 paid calls**.

## 11. Tests (§20)

- New: **221 tests in 8 suites, all green**
  (window 42, discovery 41, priority 21, dispatcher 36,
  runtime_state+activity+config 45, security 19, api_ui 18+,
  integration 19 — exact per-suite runs OK).
- Full regression: 51-suite battery (43 certified + EPIC8 + EPIC9) →
  **47 OK / 4 FAILED — the 4 fail IDENTICALLY under untouched
  production baseline** (mongo unreachable today:
  `test_agent_runtime_core`, `test_prod_intel_{failure_security,
  production,targets}`) → zero EPIC9 regressions, environmental.
- AEC: **78 modules / 2,149 tests / 0 failed** (after reverting the
  pinned-unit edit; first AEC run correctly caught it).

## 12. Security (§21)

AST import boundary (no network/process libs in `backend/ai_ops/`),
no eval/exec/dynamic import, no LLM/provider/secret text in the
package, discovery AST-verified read-only (no evidence/transition/
enqueue APIs), dispatcher only touches sweep/emit/state-save,
NEEDS_EVIDENCE + scope (campaign AND objective) enforced twice
(store load + classifier), cross-target/campaign isolation tested,
R53 (`finding_correlation` in backend/) = 0, paid-model grep = 0,
credential-shaped fragments removed from source (SECRET_CONTENT
hygiene), `/api/intel/ai-ops` auth 401/200 + no secrets in payload.

## 13. Performance (§22)

Tick on real production state: 0.88s wall for 52-item discovery +
classification + persistence; budgets cap execution at 600s/4 units;
discovery cost = one bounded read per existing store (no polling,
no full scans outside store sizes); zero LLM calls.

## 14. Documentation (§23)

`docs/ai-operations-window.md` — window, tick model, dispatcher
lifecycle, eligibility reasons, NEEDS_EVIDENCE behavior, fairness
budgets, runtime-state semantics (process vs operations), scheduler
integration, recovery, and production operations (status/tick CLI,
`.env` enablement).

## 15. Delivery (§25)

Staged as an EXPLICIT file list (EPIC9 files only; the other ~168
worktree leftovers and the production dirty 27 untouched; systemd unit
reverted to its pinned hash). Committed on `agent/daily-development`,
pushed via `push_safe.sh`, promotion request created — **stopping for
Telegram APPROVE**.

## 16. Known limitations

- No executable production work existed at validation time → the
  execution path was proven with the REAL default runners (empty
  queue, store-bound) plus injected-runner tests; the first REAL
  in-window service tick (next hourly, via `.env` opt-in) will
  dispatch when eligibility exists.
- Stranded `VERIFYING` candidate states (crash artifact of the
  finding pipeline) are reported ALREADY_RUNNING-style, not recovered
  by the dispatcher (finding-domain concern).
- 4 battery suites environmentally red today (mongo) — independent of
  EPIC9, proven by baseline A/B.

EPIC9 — Autonomous AI Operations Window v1

**READY TO PUSH: YES**
