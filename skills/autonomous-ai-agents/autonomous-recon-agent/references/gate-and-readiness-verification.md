# Gate and readiness verification

How to answer "is this tree safe to run / did these blockers get closed" with measured evidence instead of a fresh audit. The always-on rules live in SKILL.md; this file is the map, the probe recipes and the report shape.

## Where the gates actually live

- **Budget policy** — `lib/model_budget.py`: `CAP_USD` (env `HERMES_COMPLEX_DAILY_CAP`, default 0.50), `REFUSE_AT` (`HERMES_COMPLEX_REFUSE_RATIO`, 0.90), `usage_today()` (host `session_model_usage` merged with the local append-only ledger), `active_block()` (expired block returns None), `allow_complex()` (operator block -> cap -> 90% threshold -> allow), `record()` (unlocked append), `set_block()` / `clear_block()`, `reserved_usd()` / `commitments()` (recorded + live reservations), and the reservation API `reserve()` / `release()` / `finalize()` / `reap()` under an `flock` on `state/complex_budget.lock`. `allow_complex()` refuses on `committed = recorded + reserved`, so a reservation counts exactly like recorded spend.
- **Budget enforcement** — `scripts/budget_guard.py` (cron `no_agent`, ~15 min: calls `allow_complex()` and pauses/resumes the ids listed in `state/complex_jobs.json` via `hermes cron pause|resume`; silent when nothing changes), `scripts/complex_gate.py` (CLI, exit 3 = refuse, meant to be the first step of a paid job), `scripts/cron_context.py` (prints the `BUDGET GATE:` line into the job context), and the job prompt's STEP 0 (agent-side stop).
- **Two real pre-invocation refusals exist; the prompt is not one of them.** (1) the scheduler pause (`budget_guard.py` pausing the pinned ids) and (2) the budget-aware MONITOR digest: `cron_context.py --stable` runs before the agent, and on refusal it must emit the PREVIOUS digest byte-for-byte so the host sees no change and never starts the agent. Plain (`--view`) context mode and the job prompt's STEP 0 run inside a paid session, so a REFUSE there still pays for that run's prompt tokens — never use those two as proof of "no provider call". Evidence for the refusal path: byte-identical monitor output + empty `state/complex_reservations.json` + a DEFERRED record.
- **Routing** — cron job pins (`model=complex`, `provider=<custom>`) for paid analysis work; unpinned jobs = free model; `no_agent` scripts and `monitor_script` digests = deterministic (zero tokens). There is no lane enum in the tree; ask for the real call sites, not a name.
- **Severity / confidence** — `lib/xss.py`: `SOURCES`, `SINKS`, `SAFE_SINKS`, `SANITIZERS`, `analyze_flow()`, `_confidence()` (sanitized -> LOW, library -> LOW, `has_flow AND strong_sink AND source` -> HIGH, `has_flow` -> MEDIUM, else LOW/None), `looks_like_library()`, `library_tier()` (library / suspect / None — evidence-based, so a `*-util.min.js` theme bundle is caught where a name-hint list is not), the source classes (`ATTACKER_CONTROLLED` … `STATIC_LITERAL` via `classify_source()`), `sink_class()`, `is_url_params_sink()` (URL construction is not a sink), `source_in_chain()`, `severity_gate()`, `severity_of_confidence()` / `store._sev()` (HIGH->High, MEDIUM->Medium, else Low). The gate only ever LOWERS the older confidence model, so re-run the gate on the row before believing a stored HIGH.
- **Dedup** — `xss.fingerprint()` (section-59 key), `store.add_xss_candidate()`, `store.add_finding()` (fingerprint upsert, UPDATED/REAPPEARED), `store.enqueue(dedup=True)`.
- **Correlation** — `lib/analysis.py correlate_findings()`: host-level co-occurrence only (>=3 finding types, or XSS candidate + HTTP findings on one host), emitted as Low/Info, never asserts a chain. Root-cause correlation lives in `correlate_root_cause()`: DUPLICATE (same host/file/source/sink, or identical fingerprint), ROOT_CAUSE_GROUP (same js_file + normalized chain across candidates), RELATED_FINDING (same file + sink class from different sources, requires >=2 distinct sources); persisted in `correlation_groups` with the group id written back to each member, CLI `scripts/correlate.py`. Also `store.apply_classification()` (downgrade / FALSE_POSITIVE / DUPLICATE persistence + `finding_reviews` audit) and `scripts/reclassify_xss.py`.

## Probe recipes (small and targeted)

- Trace a function: search the module for `def <name>` / `^def ` / `^class ` to get line numbers, then read only that range. Do not dump the file.
- Live DB, read-only: `python3 -c "import sys;sys.path.insert(0,'lib');import store;c=store.conn();print([dict(r) for r in c.execute('SELECT ...')])"` — DB is `state/hermes.db` and `store.conn()` also runs the schema/migration pass.
- Test a classifier on real data instead of reading its hint table: import the module and call it with stored fields, e.g. `xss.looks_like_library(row['js_file'], row['evidence'])`.
- Concurrency guarantee: `grep -c "flock\|fcntl" lib/model_budget.py` — 0 means no mutual exclusion anywhere in the budget path. When the lock exists, prove the INVARIANT with N real competing reservers: exactly `floor((cap*ratio - recorded)/estimate)` grants, and `recorded + reserved <= cap` at all times.
- Pinning / enforcement: read `/root/.hermes/cron/jobs.json` directly and print `id/name/model/provider/no_agent/monitor_script` plus the prompt lines mentioning gate/budget/refuse; compare the ids with `state/complex_jobs.json` and the pause flag in `state/budget_guard.json`.
- Corroborate every report claim against the DB before believing it: a downgrade, status or severity that exists only in the dataflow markdown is not applied.

## Selftest inventory (run these; add none)

- `scripts/budget_selftest.py` — ledger, price table, block/threshold arithmetic, rollover (isolates ledger/prices/block in a temp dir).
- `scripts/xss_selftest.py` — mandated XSS case matrix: source/sink detection, sanitizer downgrade, confidence model, library cap, fingerprint dedup, change detection, both report formats.
- `scripts/verify_routing.py` — provider/model config and context_length, complex pinning + guard wiring, §28 model attribution for every message class.
- `scripts/phase34_selftest.py` — planner gap-filling, coverage rotation, fairness, queue accounting (completed vs cancelled).
- `scripts/telegram_selftest.py` — Telegram intelligence layer against a throwaway DB and a file sink.
- Capture each run's exit code directly; piping a selftest through `head`/`tail` masks the real exit status, and a shell loop that pipes every suite can report success for a suite that actually failed — write each run to a file and read `$?` per suite.
- `scripts/fix_selftest.py` — reservation race + committed arithmetic, routing decisions (COMPLEX_PAID / DEFERRED / FREE_MODEL / DETERMINISTIC), source classification (literal / self-written / externally influenced storage, `URLSearchParams.append`, vendor tiers), the misattributed bundle candidates, persistent downgrade + false-positive + misattribution, root-cause/duplicate correlation, and the live safety invariants. It copies the live DB and points `HERMES_STATE_DIR` / `HERMES_USAGE_DB` at a temp dir, so it never writes production state.

## Claim -> what actually proves it

- "Paused means paid work is refused" — the guard pauses the pinned ids AND those ids are exactly the complex-pinned jobs.
- "Refusal happens before provider dispatch" — provable from the scheduler pause OR from the monitor digest emitting unchanged output with no reservation; a prompt-level STEP 0 cannot prove it.
- "Deferred work costs nothing" — prove a persisted DEFERRED record + an empty reservation file + byte-identical monitor output; a prompt string that says "deferred" is not a mechanism.
- "Concurrent calls cannot exceed the cap" — needs a lock plus a reservation row; prove it with N real competing processes and the committed arithmetic, not with the presence of the lock.
- "A dangerous sink alone cannot be HIGH" — holds only if `has_flow AND source` are required; then check that a recorded HIGH's chain actually names its source.
- "Library/vendor flows are capped" — call the detector on the real candidate rows, never judge it by its hint list.

## Report shape this operator expects

Per blocker: **VERIFIED** or **BLOCKED**, plus the function:line, query or measured value that proves it. When BLOCKED, state the exact missing evidence. Tests: exact PASS/FAIL/SKIPPED counts and exit codes, failing check names verbatim, and whether a failure is environment-dependent (a spec file outside the tree, a host config value) or a real regression. Close with the single binary verdict the request defines (READY / NOT READY FOR PRODUCTION) and what would have to change. No payloads, no state changes, no production edits made to green a test.
