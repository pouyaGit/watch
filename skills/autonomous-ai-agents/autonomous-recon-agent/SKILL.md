---
name: autonomous-recon-agent
description: "Use when building autonomous 24/7 recon agents."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [autonomous, recon, bug-bounty, scope-guard, safety, systemd]
    related_skills: [hermes-agent, offensive-osint]
---

# Autonomous Recon Agent on Hermes

Persistent, autonomous bug bounty reconnaissance agent that runs 24/7 on a VPS via systemd, controlled via Telegram, with scope/safety/rate-limit guards.

## When to Use

- Building any autonomous recon agent that must survive SSH disconnect, reboot, session loss
- Deploying Hermes as a background service (not interactive chat)
- Implementing scope validation, rate limiting, safety guards for target interaction
- Creating persistent job queues with crash recovery
- Auditing or extending an existing deployment: what actually exists, what it depends on, where a new layer belongs

**This skill builds the PRODUCER** - the passive 24/7 collector whose rule is never to send a
detection payload. The consumer side, a scheduled job that hunts the store's fresh records and does
probe in scope, is `recurring-recon-hunt`. They deliberately differ on that one axis: do not import
this skill's passive-only rule into a hunt, and do not import the hunt's active probes here.

## Core Architecture

```
hermes-recon/
├── lib/           # scope_guard, safety, store, workers, analyzer, notify, model_budget, routing
│                  # (llm_queue / llm_budget / llm_worker were DELETED — see the banner below)
├── scripts/       # autonomous cycle, reporter, CT baseline
├── bin/           # CLI wrapper mapping 1:1 to Telegram commands
├── targets/       # Per-target isolated dirs (assets, dns, http, findings...)
├── state/         # SQLite DB, rate state, target health, control flags
├── logs/          # Cycle logs
└── systemd/       # Service + timer units
```

## Mandatory Components (checklist for OPERATIONAL)

- [ ] Persistent systemd service + timers (cycle + daily)
- [ ] Persistent state/database (SQLite: jobs, assets, findings, cycles)
- [ ] Persistent job queue (survives restart, validates on recovery)
- [ ] Scope Guard (exact-match, no auto-expansion, UNKNOWN=OUT)
- [ ] Safety Guard (global ceiling <=15 req/s, per-target adaptive backoff)
- [ ] Resource monitoring (CPU/RAM/disk thresholds to pause new jobs)
- [ ] Crash recovery (RUNNING to PENDING revalidation on startup)
- [ ] Telegram Bot (authenticated commands, priority alerts, daily report)
- [ ] Structured findings (fingerprint dedup, lifecycle, manual verification)
- [ ] Target-isolated directories, historical evidence, change detection
- [ ] Emergency stop (Telegram + local CLI + systemd)
- [ ] NO port scanning, NO exploitation, NO brute force, NO aggressive fuzzing

## Implementation Patterns

Scope Guard: exact match only. Wildcard `*.x.com` matches `a.x.com` but NOT `x.com` itself. Normalize host (lowercase, strip scheme/path/port), validate syntax, then match. Every asset passes before entering recon queue.

Safety Guard: token-bucket limiter, global ceiling 15 req/s, default 2 req/s per target. On 429/403/408/502/503/504: halve rate, backoff, pause target on sustained rejection. Never bypass WAF or rotate IPs to evade.

Job Queue: SQLite with atomic claim (`UPDATE ... WHERE status=PENDING`). Priority high/medium/low, oldest-first within priority. On startup recover RUNNING to PENDING with delay and revalidate scope plus safety.

Recon Workers: GET-only, low-impact, max 200KB body, 3 redirect hops, skip state-changing paths (logout/delete/update). Allowed: DNS A/AAAA/CNAME/MX/TXT/NS/CAA, passive CT subdomain discovery, HTTP status/title/headers/TLS, robots.txt and sitemap.xml, JS endpoint extraction.

Passive subdomain enumeration: run several independent free sources rather than one — more than one certificate-transparency API, a host-search API, urlscan, a rapid-DNS aggregator, and web-archive CDX. Each source is an independent fetcher with its own health record (ok/fail counters, last error, `disabled_until`): auto-disable a source after repeated failures for a cooldown, because some rate-limit aggressively from a datacentre IP out of the box and a retry loop just burns the cycle. Pace sources with a short sleep, run the sweep on a per-target cadence (hours, not every cycle) stored in the key-value state, and validate every returned name through the scope guard before admitting it — third-party results are untrusted. Store which source produced each host so provenance survives, and keep a raw JSONL record per sweep for evidence.

Analyzer: passive patterns only. Missing security headers, server banner exposure, permissive CORS, debug text, dir listing, weak TLS, robots references, JS endpoints, dangling-CNAME takeover heuristic (POTENTIAL only, never verified). Every finding carries confidence plus evidence plus impact hypothesis plus manual-verification-required flag.

XSS discovery (static-first, non-exploitative): feed the pipeline from HTTP recon — extract same-host links (with their query parameters), same-host `<script src>` files and inline `<script>` blocks. Analyse public JS for attacker-controlled sources (`location.*`, `document.URL`/`referrer`, `window.name`, `postMessage event.data`, `localStorage`/`sessionStorage`, `URLSearchParams`) and dangerous sinks (`innerHTML`/`outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `Function`, jQuery `html`/`append`/`prepend`/`after`/`before`), then CORRELATE source → assignment → function → sink instead of reporting every source or sink. Sanitizers/encoders found between source and sink lower confidence rather than being ignored. Same-host scripts are queued by content hash so unchanged files are never re-analysed. Depth: `references/xss-discovery.md`.

Telegram layer: two distinct message classes — an interval-gated operational status (exactly one message per 10 minutes, built by ONE shared builder that `/status` also calls) and event-driven security alerts delivered through a persisted alert queue in SQLite (dedup key = finding identity + severity + confidence, bounded retry with backoff, LOW suppressed into the digest, startup recovery for unacknowledged findings). Telegram is a notification/control plane only: findings live in the DB, so a delivery outage can never lose one. Commands map 1:1 in `bin/hermes-recon`: status detail health targets findings unread high finding-<id> ack-<id> today report daily jobs xss pause resume stop emergency target-NAME cycle flags. Depth: `references/telegram-intelligence-layer.md`.

Finding data contract: two tables hold findings (`findings`, `xss_candidates`) and one canonical view is the read contract over both — new fields are a schema column + idempotent migration + whitelisted optional kwarg + exposure in the view, never a new table or an alias column for a concept that already exists under another name. Absent means NULL; never backfill a default severity/confidence/classification/reason, and derive evidence only from what the analysis actually produced (bounded excerpt from real evidence, chain `SOURCE -> [TRANSFORM] -> SINK` only from observed values, `None` when the chain cannot be established). Classification and correlation are read by the view, never recomputed in it, and stored correlation relationships are exposed exactly as persisted. Depth — column reuse map, migration and update-COALESCE patterns, multi-group correlation resolution, the anchor-guarded edit procedure for quote-heavy source, and the per-stage focused-test shape: `references/finding-data-contract.md`.

## Deployment Procedure

1. Create target dirs plus scope file: `mkdir -p /root/hermes-recon/targets/<name>/{assets,changes,dns,findings,http,javascript,logs,parameters,recon,reports,technologies,urls}`
2. Install core libs plus scripts from `templates/`
3. Initialize database: run store init so the SQLite schema (jobs, assets, findings, cycles, kv) is created
4. **Prefer a resident daemon over timer+oneshot.** A oneshot cycle on a systemd timer cannot hold in-memory rate state, jitter, escalation backoff or a startup recovery pass, and two ticks can overlap. Run one long-lived `scripts/daemon.py` under a user unit with `Restart=always`, `RestartSec=15`, `StartLimitBurst=5/600s`, and `WatchdogSec=180` plus `sd_notify(READY=1/WATCHDOG=1)` from the loop. The daemon invokes each cycle as an isolated subprocess with a hard timeout, so a worker crash never kills the scheduler. Keep a separate oneshot unit for the emergency stop.
5. Contain resources in the unit itself: `CPUQuota=80%`, `MemoryMax=1G`, `TasksMax=64`, `Nice=10`, plus app-level load/RAM/disk gates that stop new jobs.
6. Enable linger so the user unit survives logout/reboot: `loginctl enable-linger root`, then `systemctl --user enable --now hermes-recon`
7. Add an independent watchdog cron job (`no_agent=true`, empty stdout = silence) that alerts when `state/heartbeat.json` goes stale, the unit is inactive, or a stop flag is set — systemd cannot report the failure of systemd itself.
8. Verify with a real cycle, then check `status`, `findings` and the DB counts (see Verification below).

> **DELETED BY THE OPERATOR — do not rebuild.** The recon tree must NOT carry its own LLM task
> queue or admission/budget gate. This layer was built (storage-only queue, reservation gate,
> worker) and then explicitly deleted, together with its `llm_tasks` / `llm_budget_reservations`
> schema, its tests and its README section. The accepted design is host-side instead: model work
> runs as host cron jobs with a small read-only spend ledger (see "Host-side spend ledger + pinning
> paid analysis work"). Treat the description below as historical only, and rebuild nothing from it
> without an explicit request. Additionally, the runtime implementation resides in `/root/hermes-recon/` 
> rather than `/home/ubuntu/`, with the daemon managing persistent state, job queues, and cycle 
> execution through systemd.

## Persistent LLM Task Queue (storage layer for the future model stage)

When the deterministic analyzer is to be augmented with a model stage, build the queue as its own
phase first: a persistent table plus a storage-only API, with no provider, router, network call,
token counting, pricing or execution. Producers are the existing deterministic code; the future
separate worker and provider router consume the table.

- Put the table in the SAME database and the SAME `SCHEMA` string in `lib/store.py`, so the existing `conn()` creates and migrates it on every open, and add its columns to the existing migration whitelist. Do not add a second DB file, and do not switch `journal_mode` to WAL until a concurrent writer actually exists.
- Keep the API in `lib/llm_queue.py` on top of `store.conn()` / `store.fingerprint()` — the same layering as `lib/notify.py` and `lib/findings_state.py`: enqueue, get, get_by_cache_key, claim_next, complete, fail, retry, count, recover_stale.
- Dedup identity is `target + task_type + input_hash + prompt_version`, hashed with the existing `store.fingerprint()`; enqueue returns the EXISTING task id whenever that identity is present, so identical work is never duplicated while different task types on the same target are never merged. The same key is the future result-cache key.
- Provider/model/tier/token/cost/budget columns are caller-written metadata. The queue must not price, count tokens, route, or trust the model's result fields; `verified` in the queue is a queue-local flag and never the deterministic verification state of a finding.
- Depth — schema, state model, claiming SQL, recovery semantics, payload bounds, test matrix: `references/llm-task-queue.md`.

### Budget gate + auto switch (the layer above the queue) — DELETED, do not rebuild

> Historical only: this module pair was deleted with the queue above. Recon owns a *spend ledger and
> a gate script*, not an admission engine; paid-model decisions are made in the host/cron boundary.

Once the queue exists, the model stage is two modules: `lib/llm_budget.py` (admission, lanes,
reservations, recovery) and `lib/llm_worker.py` (claim → admit → host LLM call → account → complete).
The host stays the owner of provider/model configuration, credentials, routing, retry/backoff, timeout,
token accounting, pricing, caching and fallback; Recon owns only whether a task may start, the lane
policy, the pre-dispatch reservation, admission control and the daily budget. Both modules stay
stdlib-only — no client, SDK, key, price table or second retry path in the tree.

- **No paid call without a successful pre-dispatch reservation**, and
  `committed actual + active reservations <= daily budget` for the operator's (Tehran) day — checked
  and inserted in ONE transaction over persistent rows, never an in-process counter or a process lock.
- Lanes are LOGICAL (`free` / `paid` / `deferred`); a task only REQUESTS one through the queue's `tier`
  metadata column. A lane is usable only when the operator declared it (a host auxiliary-task slot, or
  `main` for the host's main model), because the gate cannot prove a route is free before the call.
- Safe defaults make "no unexpected paid calls" the resting state: budget enabled, paid OFF,
  auto-switch ON, exhaustion defers, no lane declared (an undeclared lane defers instead of guessing).
- Post-call truth is read from the host result (provider/model/tokens/cost); an unreported cost accounts
  the reservation with its provenance recorded, never zero; a malformed or negative reported cost is
  refused rather than clamped.
- Recovery is deterministic and persistent: a TTL sweep plus an orphan sweep (a reservation whose task
  is no longer `running`), composed with the queue's own stale-task recovery. A budget deferral is not
  a failure — give the retry attempt back when returning the task to the queue.
- Depth — ledger table and accounting SQL, lane decision table, estimate adapter, worker sequence,
  config knobs, test-harness pitfalls, verifier items: `references/llm-budget-gate.md`.

### Host-side spend ledger + pinning paid analysis work

The recon tree has no LLM of its own, so expensive analysis runs as HOST work (Hermes cron jobs).
Two things make that safe:

- **Set an explicit `context_length` for every custom-provider model.** An OpenAI-compatible custom
  provider whose model list has no `context_length` makes the host resolve the window as 1 and refuse
  to start with "context window of 1 tokens, below minimum 64,000". Set it per model
  (`custom_providers.<n>.models.<model_id>.context_length`) AND on the provider entry itself, which is
  the documented fallback for every model the entry serves. `hermes config set` accepts dotted paths
  with list indexes (`custom_providers.0.models.complex.context_length 131072`), so never hand-edit
  config.yaml. Prefer a conservative value (host minimum 64K) — under-claiming only compresses earlier,
  over-claiming fails at request time — and confirm through the host's own resolver
  (`hermes_cli.config_providers.get_custom_provider_context_length`) rather than by re-reading the YAML.
- **Meter real spend, never an estimate you invented.** The host records per-model usage
  (`session_model_usage` in its state DB: `api_call_count`, input/output/cache tokens,
  `estimated_cost_usd`, `cost_status`, `cost_source`, `billing_base_url`). Read that as the ledger and
  only fall back to a configurable price table when `cost_status`/`cost_source` say the host has no
  price for the model id (routers usually report none, so the self-computed figure is the real cap
  input). Keep a separate append-only local ledger for calls the host cannot see, add both, and scope
  to one day window. Report out-of-scope spend (direct provider, sibling routes) as its own line rather
  than silently folding it into the cap.
- **One policy number per budget, enforced once.** If a second gate exists anywhere in the tree, give
  both the same default and add an automated check that they still agree — two budget systems that
  drift apart is the actual risk, not the arithmetic. Cap the model alias the policy names, not every
  non-free route, so an unrelated route cannot silently consume the allowance.
- **A read-only preflight cannot cap concurrency; only a lock or a reservation can.** A check-then-spend
  gate (`allow_complex()` -> provider call -> append to an unlocked ledger) lets two concurrent paid jobs
  both pass below the refusal ratio and overshoot the cap, because neither ledger read can see the other's
  in-flight cost — and a call's real cost is only knowable after it returns. Refusal at ratio 0.9 leaves
  roughly 10% of the cap as headroom for one call's overshoot. Prove the guarantee by construction before
  claiming it: `grep -c "flock\|fcntl" lib/model_budget.py` returning 0 means no mutual exclusion, so the
  honest verdict is "unenforced under parallelism". A hard cap needs an exclusive lock around check+reserve
  (or a reservation row), not a larger ratio. Once the lock exists: refuse when `committed >= cap*ratio`
  OR `committed + estimate > cap*ratio` (testing only the HARD cap lets one reservation land past the
  safety margin), release a reservation whose call never happened, and do NOT write a ledger row in
  `finalize()` by default — the daily total already sums host accounting plus the local ledger, so a second
  row double-counts. The guard that pauses jobs must use the SAME admission rule as the reservation, or the
  two disagree and the deferred state flaps every cycle.
- **Enforce at the scheduler boundary, because a per-turn model switch does not exist.** No tool lets a
  running agent downgrade its own model, so "refuse the paid call and stay on free" means: (a) the
  heavy jobs are monitor-gated, (b) a cheap pre-run script prints the gate verdict into the job's
  context and the prompt makes it stop immediately on REFUSE, and (c) a separate `no_agent` cron job
  (no LLM, so it cannot spend what it protects) pauses/resumes the paid-pinned jobs on the transition
  and stays silent otherwise. Only (c) is refusal BEFORE dispatch: (b) is read by the paid model itself,
  so a REFUSE there still pays for that run's prompt tokens — treat the prompt gate as a limiter with a
  floor, and never claim "no provider call for refused work" on the strength of it. Make the MONITOR
  digest itself the budget-aware gate and it becomes a real pre-dispatch refusal: configure expensive jobs
  with `--monitor-script` on a byte-stable digest, and on refusal emit the PREVIOUS digest byte-for-byte
  (never advance the stored digest) so the host sees no change and never starts the agent, while the pending
  input change stays pending for the next eligible window. Keep timestamps and gate output OUT of the digest,
  or it changes every tick and never suppresses; a persisted DEFERRED record plus an empty reservation file
  is the evidence, not the log line.
- **`--model`/`--provider` are CLI-only.** The agent's cron tool cannot set a model, so pin those jobs
  with `hermes cron create ... --model complex --provider <custom name>` and read the jobs store back
  to confirm `model`/`provider`/`monitor_script` actually landed.

## Pitfalls and Rules

- Never auto-expand scope: third-party infra referenced by in-scope targets is NOT authorized. Unknown means out of scope.
- Never exploit: a suspicious pattern is a potential finding, not a confirmed vuln. Stop, document, report, request manual verification.
- Rate ceiling is not the operating target: run substantially lower by default, back off automatically on defensive signals.
- LLM never runs shell directly: Planner to structured job to policy validation to safety guard to approved worker. In the reference implementation the planner is deterministic Python (`planner()` in `scripts/cycle.py`), so read the LLM-free rule below before assuming any inference step exists.
- **This architecture is LLM-free by design — do not hunt for an LLM client, and do not invent one.** All analysis is deterministic regex in `lib/analyzer.py` and `lib/xss.py`: no model, no API key, no SDK, no inference call anywhere in the tree. The only coupling to Hermes is a `subprocess` call to `hermes send --to telegram` in `lib/notify.py` for message transport, so recon completes whether or not any model provider is reachable. When asked to audit or extend "the LLM layer", establish presence with an exhaustive case-insensitive grep across ALL file types (recon output and logs legitimately contain hostnames like `llm.nativeedge.<domain>`, which is the usual false positive) and report where the integration actually lives rather than describing a plausible one. Once the persistent task queue exists, `lib/llm_queue.py` and the `llm_tasks` table WILL appear in that grep — they are storage only (no HTTP, no SDK, no key, no model call), so report them as the queue layer, never as a provider integration. Once the budget phase exists, `lib/llm_budget.py` and `lib/llm_worker.py` appear too: the worker calls the HOST's LLM facade (`ctx.llm.complete_structured`), so report it as the budget-gated host call — the tree still owns no client, key, price or retry.
- **The tree is stdlib-only; keep it that way.** Every outbound HTTP call uses `urllib.request` (crt.sh, certspotter, OTX, rapiddns, urlscan, hackertarget, web.archive.org). Adding a third-party SDK — `openai`, `requests`, `httpx`, anything — introduces the repo's first external dependency and breaks its deploy story; new layers must stay urllib-based.
- **If an LLM analysis stage is ever added, put the budget gate ABOVE the job loop, never inside it.** `execute_job()` runs within a `while True` loop bounded by per-type budgets that sum to roughly 300 jobs per cycle, every 30 minutes. A model call wired naively at that depth is ~300 ungoverned paid calls per cycle. Insert at the analyzer boundary (the `analyze_*` call sites in `scripts/cycle.py`) and gate on budget plus cache before dispatch, reusing the existing content-hash discipline (`js_recon` is already hash-gated) as the cache key.
- **Prove a false-alarm from a meter before acting on it.** A router route you did not intend to cap appearing in the spend ledger is a classification bug in the ledger, not real overspend: check whether the match is on the model id (what the policy names) or on the provider URL (too broad, and it will bill free routes).
- **Clean synthetic verification entries out of a live ledger.** A hand-written test row stays counted in the daily total forever and can push the gate into refusal; use a throwaway ledger via env in the selftest instead of writing to the real one.
- **A cap test with zero usage does not test refusal.** `cap=0.0005, used=0.00` still passes the gate because `0.0 < cap*ratio`; force the refusal branch with `cap=0` or a usage row, otherwise the "guard works" claim is untested.
- **Never give a polled child a PIPE the poll loop does not drain.** A supervisor that spawns the cycle with `stdout=PIPE` and only calls `communicate()` after `poll()` returns will deadlock: the cycle emits thousands of per-job lines, the 64 KiB pipe fills, and the child blocks forever inside `write()`. The symptoms are distinctive and misleading — the daemon reports `rc=-9` after the full timeout, `consec_fail` climbs, the failure backoff escalates to an hour, no `cycles` row is written, the heartbeat goes stale and recon silently stops producing while the process still looks alive. Diagnose it from the child itself: `/proc/<pid>/syscall` showing syscall 1 (`write`) on fd 1, and `/proc/<pid>/fd/1` pointing at a `pipe:[...]` that no process is reading. Fix by redirecting the child to a log FILE (`stdout=open(path,'a'), stderr=STDOUT`), never a pipe, and tail that file for the summary line.
- **Refresh the heartbeat DURING a cycle, not only between cycles.** If the supervisor writes it once per loop iteration, every observation made while a cycle runs sees a stale age, so the watchdog and any "heartbeat newer than N seconds" acceptance check fail on a healthy system. Write it from the cycle poll loop (every ~60 s) and keep the cycle count separately.
- **A wall clock that starts after the planner does not bound the planner.** Set `cycle_started` before the planning phase, or a cycle can consume its entire window fetching CT/passive data and then have no time for any job.
- **Bound each job, not just the cycle.** A server that accepts the connection and trickles bytes resets a socket read timeout indefinitely, so one fetch can eat the whole window (observed: output frozen for 5+ minutes, child parked in `poll()` while the cycle cap waited for the job to return). Use `signal.alarm(JOB_MAX_S)` around the job call with a handler raising a custom exception, and treat the timeout as a normal job failure — it interrupts a blocking `recv`, which a socket-level `timeout=` does not. This only works while the cycle process stays single-threaded; a helper thread makes SIGALRM delivery unsafe.
- Worker failures must not crash the system: isolate, timeout, retry with backoff, log, recover job state.
- High signal over coverage: prefer 10 useful findings over 100k noisy endpoints. Deduplicate aggressively with stable fingerprints.
- When uncertain: do nothing active, record the event, report it, wait for human review.
- **Mark per-host work done with an explicit column, never by "result is empty".** A queue selector like `WHERE dns_a=''` re-picks the same host forever when the lookup legitimately returns nothing. Use a `dns_at` timestamp set on completion (observed: one host re-checked dozens of times, wasting the whole cycle budget).
- **Priority-only job ordering starves job types.** Strict `high` first meant DNS discovery jobs consumed every cycle and HTTP recon executed zero times, so no findings could ever be produced. Use per-type budgets plus fair-share selection (pick the type with the lowest `used/budget` ratio).
- **Never let a per-type budget be bypassed by a fallback in the claim function.** A `claim_job(preferred_type=X)` that falls back to "any pending job" when no X job exists silently runs over-budget work: the caller saw `open=['dns_recon']` while HTTP kept executing (11 jobs against a budget of 3). Make the type filter strict and let the caller iterate the types that still have budget. Also do not decrement the counter for no-op jobs to "give the slot back" — that lets real work exceed the cap; instead cancel the drained job and skip the increment.
- **Guard against two cycles running at once, and make a skipped cycle visible.** A daemon tick and a manual run can overlap, doubling target traffic and corrupting per-type budget accounting. Take an `fcntl.flock` on `state/cycle.lock` (auto-released on exit, so a crash never leaves a stale lock), open it `"a+"` so a losing invocation cannot truncate the holder's recorded pid, and return a distinct exit code (e.g. 9 = skipped). Critically: the supervisor must NOT count that code as a successful cycle — an early version logged `cycle end rc=0 dur=0s` and incremented the cycle counter while doing nothing, which would make a long-held lock look like healthy operation. Treat skipped as "neither success nor failure", do not touch the cycle/failure counters, and retry sooner than the normal interval.
- **Bound the cycle's wall clock.** Give the loop a hard deadline (e.g. `HERMES_CYCLE_MAX_S`, 900 s) that breaks out cleanly leaving remaining jobs `PENDING`. Without it, a hung cycle holds the single-instance lock forever and every subsequent tick is skipped.
- **Verify budgets from the database, not from the loop's own counter.** Measure with `SELECT job_type, COUNT(*) ... WHERE started_at >= <run_start>` after every change to the claim/budget path. A run once reported 254 jobs against a 240 budget and 235 DNS against a cap of 200; the counter alone would never have shown it. Clear `__pycache__` after editing `lib/` as routine hygiene, but do not assume a cache explains an accounting mismatch — instrument the loop (per-iteration progress log gated by an env var) and read the sequence.
- **Under systemd the PATH is minimal.** Resolve helper binaries by absolute path or a `which`-then-fallback chain (`/usr/local/bin/hermes`, never `/usr/bin/hermes` — that path does not exist on a standard install).
- **Emergency-stop units must not be able to fail on notification.** Prefix the alert `ExecStart` with `-` so a messaging outage cannot abort the stop itself.
- **Hermes cron `script` must live in `~/.hermes/scripts/` (relative); absolute paths are rejected.** Put a thin shim there that `runpy.run_path()`s the real script in the recon tree.
- **Passive CT data is overwhelmingly stale.** Of 232 CT-derived hosts, only 11 still resolved. Record DNS liveness and only spend target-facing HTTP requests on live hosts.
- **Quiet the noisy rules.** Bare `Access-Control-Allow-Origin: *` without `Allow-Credentials` is common and usually intentional — reporting it produces low-signal findings and trains the operator to ignore alerts. Require a reflected/third-party origin with credentials before raising CORS.
- **DNS work needs no target traffic.** Local-resolver lookups can carry a far larger per-cycle budget than target-facing HTTP; budgeting them together wastes the cycle on the cheap work and starves the expensive work (or the reverse).
- **Never send a detection payload to prove a finding — static and passive evidence only.** No `<script>`/`alert()`/`javascript:`/event-handler/SVG payloads, no stored-payload submission, no crafted `postMessage`, no account creation just to test. If confirming a candidate would require injecting input, record the candidate with its evidence and leave it for human verification. Reflection analysis must fetch the URL exactly as discovered and analyse the parameter values already present in it — never mutate parameters to test.
- **Cap confidence for flows found inside library/vendor bundles.** A bundle contains the library's own sinks (jQuery's `.html()`/`append()`, its own `postMessage` handlers), so a naive source→sink scan reports the framework as the vulnerability and every page with a bundled library yields HIGH candidates. Detect library filenames/content signatures and cap those at LOW with an explicit reason; reserve HIGH for flows in application code. A name-hint list alone gives false negatives: a theme/utility bundle like `*-util.min.js` matches none of the usual hints (verify by calling the detector on a live candidate row, not by reading the hint table), so treat minified/aggregated `*.min.js` as a suspect too and re-check the detector against the real rows before claiming the cap holds.
- **Re-read the chain before trusting a HIGH out of a minified bundle.** A same-statement or same-window label match links a source NAME to a sink with no real path: a one-line bundle yields chains like `e = !0 -> element.innerHTML` and `e = !0 -> Function`, where the first hop is a literal and the `localStorage` label sits elsewhere in the same line. Require the recorded `data_flow` to name the source itself, add an explicit rule for literal / self-written-storage / `URLSearchParams.append` values (a scanner with only a source-label table rates them HIGH), and keep the sink-alone case below HIGH — a dangerous sink with no traced source must never be reported as HIGH.
- **Persist model-stage review decisions back into the DB.** A downgrade that exists only in the dataflow markdown report is not applied: the candidate row keeps its original `confidence`/`severity`, so the operator's alert view drifts from the analysis. After any review run, compare the report's verdicts with the rows (`SELECT candidate_id,confidence,severity,status FROM xss_candidates`) and treat a mismatch as a broken write-back path, not a display quirk.
- **Check that a named concept exists before tracing it.** When asked to trace spec identifiers (`COMPLEX_PAID` / `FREE_MODEL` / `DETERMINISTIC`-style lanes), grep for the identifiers first. If nothing matches, the mechanism is really cron `--model`/`--provider` pins plus `no_agent` / `monitor_script` jobs — name those real call sites in the answer rather than mapping comments onto an enum that does not exist.
- **Encode finding strength into the alert dedup key** (`kind:id:severity:confidence`). Identical re-observations then never re-alert, while a genuine confidence/severity increase produces a new key and is reported as an UPDATE alert. Take the "already known" baseline as ANY prior alert record for that finding (including a suppressed LOW one) — otherwise a LOW→HIGH strengthening is sent as a first-time alert instead of an update.
- **Never block the supervisor on the child process.** Poll the cycle subprocess and publish status/alerts plus the watchdog ping from that polling loop; a blocking `subprocess.run` delays HIGH alerts and the interval status by the whole cycle duration (observed: status over 12 minutes late while a cycle ran). `Popen` + `poll()` + a short sleep is the entire fix.
- **Backfill any column a filter depends on, and COALESCE in the query.** Adding a column that `/unread`-style queries filter on silently hides every pre-existing row (NULL fails `IN (...)`), so findings the operator was tracking disappear from the view. Backfill in the schema migration and derive the value in the query too.
- **Edit quote-heavy Python with an anchor-guarded bulk script, not repeated find/replace.** On a module whose strings carry escaped quotes, a hand-written pattern keeps the escaping, misses, and returns a "patch FAILED" report instead of a silent no-op; also, a short anchor like a bare `("name", "TEXT")` tuple matches both a schema string and a migration list. Read the raw file, list every `(old, new)` pair, require an exact count of 1 for ALL pairs before writing anything (exit without writing if any fails), then `ast.parse` and grep the changed region back out of the file to confirm what landed. Depth: `references/finding-data-contract.md`.
- **A new column must also be added to every writer's field list, or the value is silently dropped.** Upserts built from a fixed whitelist of column names skip anything not listed, so code that clearly passes a value (e.g. provenance for a discovered host) writes nothing and no error is raised. After the first write of a new field, assert the column is actually populated — do not trust the call site.
- **Expect a manual cycle to be skipped while the supervisor's cycle holds the lock.** The single-instance guard returns its distinct skip code and does nothing — that is correct behaviour, not a broken change. Wait for the supervisor's cycle to end and re-run, or let the normal schedule pick the work up; never "fix" it by removing the lock.
- **Make verification scanners precise or they lie in both directions.** Strip string and comment tokens with a real tokenizer before scanning source for dangerous constructs — analyzer sink tables contain words like `eval` and a naive grep trips on them — and bound function-body extraction at the next top-level `def`, or the scan silently includes unrelated later functions. Treat a surprising FAIL as a scanner bug until you have confirmed which line matched.
- **Bound the SERIALIZED payload, not the value you passed in.** Truncating each oversized string still leaves a nested payload over the column cap, and re-wrapping a preview can inflate it again because JSON escaping doubles quotes — build the wrapper, measure the final length and shrink until it fits, then assert `len(stored) <= cap` with a fixture of many small rows rather than one giant string (a single oversized string is caught by per-value truncation and proves nothing).
- **Declare queue-layer uniqueness as an explicit `CREATE UNIQUE INDEX`, not an inline `UNIQUE` column.** The repo migrates columns by diffing `PRAGMA table_info` against a whitelist and issuing `ALTER TABLE ... ADD COLUMN`, which cannot carry a constraint — a database that gained the column that way silently loses the dedup guarantee.
- **Crash-recovery sweeps must respect the attempt budget.** A stale-`running` sweep that always requeues loops forever on a task that can never succeed: send exhausted tasks (`attempts >= max_attempts`) to `failed` in the same pass and requeue the rest, and only touch rows in `running`.
- **Keep `succeeded`/`failed` out of the claim predicate and increment `attempts` at claim time.** `WHERE status IN ('queued','retry')` is what makes a finished task unreclaimable; re-arming a failed task must be an explicit call that checks the budget, never a side effect of enqueueing.
- **Stage a storage layer as storage-only and PROVE it.** For any queue/cache phase, assert with a tokenizer-stripped scan that every `INSERT`/`UPDATE`/`DELETE` in the module targets its own table, that it contains no URL and no network/exec/provider construct, and that a byte-identical snapshot of every pre-existing table is unchanged after queue traffic — that trio is what lets you claim the phase changed nothing else.
- **Replay the running system against a COPY before calling a phase safe.** Copy `state/hermes.db` to a temp path, point `HERMES_DB` at it and exercise the daemon startup path (`recover_jobs`), `claim_job`, the status/reporter builders and the new layer; it proves the supervisor's next cycle will work without generating target traffic or mutating live state.

- **Continuous queue: "pending work exists" must be the scheduler condition, not a fixed interval.** A planner only fills the queue at the top of a cycle, so with a fixed 30-minute cycle the queue drains partway through and the agent sits idle with capacity left. Make the scheduler re-run the planner the moment a cycle ends while work remains (a short busy-recheck interval, plus a log line naming how many jobs still rest), and keep the long interval only as the idle fallback. Releasing the same cycle window back to back is what removes the idle trough.
- **A restart must not inherit the previous code's `next_cycle` deadline.** Persisting `next_cycle` across restarts is right for continuity but wrong when the value is in the future and work exists: the freshly (re)started daemon waits out a stale window computed by an older scheduler. At startup, if the queue has *any* pending work, resume immediately (log the remaining seconds you skipped); only honour the saved deadline when the queue is genuinely empty.
- **Never shadow the loop-control global in the startup path.** Assigning to a name like `_running` (a local that only *looks* private) inside a function that also touches the module-level flag `_running` sets the global to that value and makes `while _running:` exit on the first iteration — the daemon starts, logs a healthy startup, and exits cleanly, so systemd restart-loops it instead of crashing loudly (`NRestarts` climbing while the log shows normal startups is the signature). Use a distinctly named local, or a `global` statement with a deliberate value.
- **Local (zero-network) analysis is what makes a queue non-empty by design.** Coverage gap classes that need no target traffic — technology fingerprinting, passive security/config analysis, version/CVE correlation, endpoint and parameter extraction, finding correlation, target refresh — can run at high budget without touching the rate ceiling. Gate them on stored samples existing (you cannot analyse a response you never saved), and persist the response/JS samples needed to re-analyse offline.
- **Order analysis-job selection by least-recently-covered, not by sample recency.** Selecting candidates with `ORDER BY captured_at DESC` re-picks the same newest hosts every pass while older ones starve forever, because the selection never consults the coverage ledger. Join against coverage state and pick the hosts whose target+module has the oldest (or no) coverage mark, so every host is eventually reached; the executor marking coverage on completion is what makes the rotation advance.
- **A planner starvation bug can masquerade as a bad test — and vice versa.** A per-class ceiling smaller than the eligible host count means one pass legitimately serves only the ceiling's worth of hosts, so a test asserting "this specific host must be planned" fails on correct behaviour. Assert the real invariant instead (every eligible host becomes eligible within N passes; no ineligible host is ever planned), and drive the passes the way production does by marking coverage as each batch is consumed — otherwise a genuine starvation bug hides behind an artificial harness that never advances state.
- **Derive staleness for a given work class from its OWN coverage timestamp, never from an asset's `last_seen`.** `last_seen` is updated by whichever job touches the asset first (typically DNS), so hosts that have never had an HTTP fetch read as "fresh" and the planner reports a false "no gap" for a target with zero HTTP coverage. Key each staleness check to the completion timestamp of that module.
- **A transient negative result must not be recorded as a permanent one.** DNS lookups that fail once were being stored as resolved-with-no-address and never retried, so thousands of hosts were permanently written off as dead. Record the attempt, and let a staleness rule re-plan hosts whose resolution is old or whose result was empty, so a transient resolver failure self-heals.
- **Arbitrate the two message classes in ONE function or the boundary emits both.** When a 10-minute pulse and a 30-minute full status are gated by separate checks, the tick where both intervals have elapsed sends two messages. Have a single dispatcher decide which one (if either) is due and return what it sent, so a caller can never double-fire.
- **Fix a rendering bug where the string is built, not where it is displayed.** A status builder that joins with `"\\n".join(lines)` emits a literal backslash-n instead of newlines — visible only in the delivered message, invisible in `py_compile` and in any test that inspects the returned text's length. Assert on the actual rendered text of a builder, not just that it returns a string.
- **Verify a new module's own logic before blaming its integration.** Two bugs in a freshly written analysis module (a tech-fingerprint helper that ignored server headers entirely, and passive config rules narrow enough to never fire) looked like a wiring problem from the executor's zero-count output; exercising the module's functions directly against synthetic headers/body showed both immediately. Test the unit against a fixture before debugging the pipeline.

## Verification Checklist (run these, do not assume)

- Scope Guard: unit-test near-misses (`evil-dell.com`, bare `dell.com` when only `*.dell.com` is listed, invalid syntax) and assert IN_SCOPE/OUT_OF_SCOPE/UNKNOWN.
- Analyzer: feed synthetic response headers/bodies and assert each rule fires (missing headers, banner, CORS, debug text, dir listing, weak TLS, robots, dangling CNAME, JS endpoints/sourcemap/secret-hint).
- Dedup: call `add_finding()` twice with identical inputs; assert the same `finding_id` returns with `is_new=False` and the row count stays 1.
- Budgets: run a cycle, then `SELECT job_type, COUNT(*) ... WHERE started_at >= <run_start>`; assert each type is within budget.
- Crash recovery: `kill -9` the daemon, wait, then check a new MainPID, `NRestarts`, and that interrupted `RUNNING` jobs returned to `PENDING`.
- Flags: pause/resume/stop/emergency each toggle the flag file and are reported by `flags`; emergency stop must be reachable three ways (CLI, systemd unit, Telegram).
- Delivery: send one real alert and confirm it arrives; verify the notifier resolves its binary under the unit's bare PATH.
- Field/persistence stage: run its focused test with `HERMES_DB` pointed at a temp file before importing the store module, and assert save/reload round-trips, a minimal legacy row still loading, absent optionals staying absent (no crash, no fabricated value), analysis verdict == persisted row == canonical view, and production row counts unchanged before/after. Run the earlier stages' tests too and report each exact summary line — a later stage that passes while an earlier one regressed is not a pass.
- Alerting policy: the interval gate returns False inside the window and True once elapsed; a status is publishable while a cycle subprocess is still running; HIGH delivers immediately; re-registering an unchanged finding queues nothing; LOW queues suppressed (no message) yet stays visible in the summary; a strengthened finding produces an UPDATE alert; a failed delivery keeps the finding and stops retrying after the bounded attempt count.
- XSS module: run the deterministic case matrix (source→sink pairs, sanitizer lowers confidence, safe text sink produces nothing, reflected value in attribute context, reflected value HTML-encoded → LOW, fingerprint stable under line/query changes, changed file detected by content hash, library bundle capped LOW). Every case must pass with no payload involved.
- Durability: reinitialise the notification layer in a separate process and assert unacknowledged findings, their alert state and the pending queue all survive.
- Queue layer: assert the table carries every field with `journal_mode` unchanged and only one DB file; claim is atomic under N real competing processes (each id claimed exactly once, disjoint sets); a completed task is never claimed again; retry is refused past `max_attempts`; a database predating the table gains it on first open with existing rows intact; a stale `running` task is requeued while a fresh one is left alone.
- Budget layer: assert no paid admission is possible without a reservation returned BEFORE dispatch; N real competing processes cannot exceed one day's budget (exactly `floor(budget/reserve)` admits, losers leave no half-written row); a failed call releases its reservation while a retry reserves afresh (one reservation per attempt, never two at once); an abandoned reservation is freed by the TTL or orphan sweep and the budget is genuinely usable again; a fresh process reopening the DB sees identical accounting; the persisted provider/model/tokens/cost came from the host result; an LLM answer or a task payload claiming a bigger budget changes nothing; every recon table is byte-identical after worker traffic.
- Budget accounting: on the same day across sections, `committed + active` must be measured from the ledger — a shared synthetic day makes unrelated reservations bleed into the arithmetic, so scope every assertion to one budget day.
- Milestone verifiers can fail on a TIMING window, not a regression: a "heartbeat newer than N seconds" check against a supervisor that only writes it per cycle (e.g. 300 s window vs a 1800 s interval) fails between cycles. Confirm the unit is active and the last cycle completed before reporting it — and never report a pre-existing unrelated FAIL as caused by your change.
- **There is NO git repository for this project; do not run git at all** (no status, diff, commit, stash, reset, push). Report changed files with a plain file list/line counts instead of `git diff --stat` / `git status --short`, and never treat a commit as part of the deliverable.
- **Attribute the model on every message.** Every Telegram message the operator receives must END with a final `Model: ...` line naming the model that actually produced it: `Model: none (deterministic — no LLM)` for deterministic builders (status, alerts, daily report, watchdog/guard notices), `Model: free` / `Model: complex (DeepSeek)` for routed model work, or the exact model id plus provider for an interactive session. Enforce it once at the delivery choke point (append if the last lines carry no `Model:` line, so an agent-built message is never double-attributed) and, for model-run cron jobs, print the exact required line into the job's pre-run context so the agent echoes it verbatim. The spec file the operator maintains (`/home/ubuntu/telegram.txt`, a numbered CRLF document) must carry the rule too — insert a new numbered section before its `# END` marker and preserve the file's existing line-ending convention.
- Deliver a phase the way this user expects: the requested deliverable sections in order, a plain accounting of every changed file, a plain statement of what was verified vs assumed, real test commands with their summary lines, and a closing `READY TO PUSH` / `NOT READY TO PUSH` verdict with remaining issues — but see the no-git rule above: no `git status`, no `git diff`, no commit. When a phase spec prescribes its own skeleton (e.g. `PHASE N IMPLEMENTATION COMPLETE` with Files changed / behaviour / lane / tests / verification / `git diff --stat` / `git status --short`), follow it verbatim — and say plainly which changed files are untracked and therefore absent from `git diff --stat`. If an acceptance criterion cannot be satisfied, stop and report the exact blocker instead of shipping a weakened architecture.
- **A "close only these blockers, do not re-audit" request gets a per-blocker verdict with measured evidence.** For each item: VERIFIED or BLOCKED, the function/line/query that proves it, and — when blocked — the exact missing evidence. Probe small and targeted only: grep the function name, read a narrow line range, call the tree's own functions against live rows, run the existing selftests. Never restart the broad audit, dump whole files, or re-derive the project map. "Proven" means a measured value (threshold arithmetic, a DB row, a detector's return on real inputs) — never a comment, a prompt instruction, or an identifier's name. Depth and probe recipes: `references/gate-and-readiness-verification.md`.
- **Report existing tests exactly as they ran, and change no production code to green them.** Give each selftest's exact PASS/FAIL/SKIPPED counts and exit code, name the failing checks verbatim, and classify each failure as environment-dependent (a spec file outside the tree, a host config value) or a real regression — never silently drop one, and never invent a test framework to fill a gap. If a blocker has no test, that absence IS the finding.
- **Never run a payload or mutate state to answer a verification question.** Static/passive evidence only: read rows, call classifiers, run the deterministic selftests. Findings that would need injected input stay as manual-verification items.

## Capability audits

- Answer "what can this system actually do" by proving INVOCATION, never by reading filenames, docs or
  prompts: for each capability establish installed / referenced / invoked / producing persisted results,
  and cite both the call site and runtime evidence (per-module `activity_events` counts, `jobs` status
  counts, cycle-log job lines, `jobs.json` `last_run_at`/`state`/`monitor_state`/`repeat.completed`,
  `deliveries.db`, `urls.source` provenance, `passive.source_status()`).
- A binary on PATH is neither proof of use nor proof of identity — check the shebang or `--version` before
  mapping a familiar tool name onto a capability.
- Grep every declared limit for a read site before repeating it as a limit; constants and DB columns are
  routinely declared and never enforced.
- "An LLM could write X" is never a capability. It exists only when code stores, validates, runs and links
  the result back to a finding.
- Report shape: exact counts, a capability matrix (FULL / PARTIAL / NOT IMPLEMENTED / AVAILABLE BUT UNUSED /
  DISABLED), gaps grouped by area rather than ranked by an invented score, roadmap entries carrying
  WHY / GAP / LOCATION / DEPENDENCIES / COST / SAFETY / OUTPUT, and a verdict that names the missing
  evidence. Depth and probe recipes: `references/capability-audit.md`.

## Templates

Starter files live in `templates/`: scope_guard.py, safety.py, store.py, workers.py, analyzer.py, notify.py, cycle.py, reporter.py, hermes-recon CLI, systemd service plus timer units, and core_llm_probe.py (E2E probe that drives the host's real LLM facade with an injected caller — run it with the host interpreter, not the daemon's). Each template is a known-good starting point to copy and adapt per deployment.
