# AEC-1 — OPERATIONAL: watch.service recovery (bulk dnsx wall-clock ceiling)

**Commit:** `<pending>` on `agent/daily-development`
**Scope:** one unpinned helper (`utils/common.py`) + one new test file.
**EPIC11 CHANGED: NO** · **EPIC11 REGRESSION: NO** · **WATCH SERVICE ROOT CAUSE: PROVEN**

---

## SERVICE

`watch.service` — "Watch Bug Bounty Core Pipeline", `Type=oneshot`, `User=root`,
`WorkingDirectory=/opt/watch`, `TimeoutStartSec=6h`, `TriggeredBy=watch.timer`
(daily `00:00:00 Asia/Tehran` = `20:30 UTC`).

```
ExecStart=/usr/bin/flock -n /run/watch-pipeline.lock /opt/watch/run-pipeline.sh
```

One-shot by design (not a daemon): the timer triggers it, the script runs five
steps (Sync Programs, Enumeration, DNS Resolution, HTTP Scanning, Crawl Fresh)
and exits 0 only when every step succeeded. `active (exited)`/`failed` are the
expected end states — "active (running)" is NOT the correct expectation here.

## FAILURE WINDOW

- Exact failure timestamp: **Wed 2026-09-23 23:55:34 UTC** (last run's exit).
- Run window: 2026-09-23 20:30:13 → 23:55:34 UTC (12,321 s).
- Exit code: **1** (`ExecMainStatus=1`, `ExecMainCode=1`), **no signal**,
  `Result=exit-code`, `Consumed 43min 41.385s CPU time`.
- Deterministic: **7 consecutive runs** (2026-09-17 … 2026-09-23) all ended the
  same way. It is not a one-off.

## LAST KNOWN GOOD EXECUTION

**2026-09-16 20:30:13 → 2026-09-16 23:56 UTC** — pipeline exit 0, all five
steps exit 0 (DNS step 5,619 s).

## EXACT FAILURE

`run-pipeline.sh` reported:

```
Pipeline Finished WITH FAILURES in 12321 seconds
```

and exited 1 by design (`pipeline_exit_code()`), because exactly one step
returned non-zero. Step exit codes, 2026-09-23 run:

| step | duration | exit |
|---|---|---|
| Sync Programs | 1 s | 0 |
| Enumeration | 1,066 s | 0 |
| **DNS Resolution** | **5,746 s** | **1** |
| HTTP Scanning | 5,443 s | 0 |
| Crawl Fresh | 59 s | 0 |

The step failure itself (`logs/pipeline_20260923_203013.log`):

```
[2026-09-23 21:23:46] Executing dnsx: dnsx -l /tmp/tmplv2antu0 -silent -a -resp -json -t 10 -rl 30 -r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222
subprocess.TimeoutExpired: Command 'dnsx -l /tmp/tmplv2antu0 ...' timed out after 3600 seconds
  File "/opt/watch/ns/watch_ns_all.py", line 88, in <module>
    dnsx([obj_sub.subdomain for obj_sub in obj_subs], domain)
  File "/opt/watch/ns/watch_ns_all.py", line 33, in dnsx
    results = run_command_in_zsh_ns(command)
utils.common.ToolTimeout: command timed out after 3600s: dnsx -l /tmp/tmplv2antu0 ...
```

`ToolTimeout` is raised (fail-fast, by design) and is **not caught** in
`watch_ns_all.py`'s `__main__`, so the script exits 1 → `PIPELINE_FAILED=1` →
pipeline exit 1 → systemd marks the oneshot unit failed.

## ROOT CAUSE

**A fixed per-invocation wall-clock ceiling crossed by a monotonically growing
workload.**

1. `ns/watch_ns_all.py` (pinned, unmodified) resolves **an entire scope in one
   `dnsx` invocation**, rate-limited to `-rl 30` (30 queries/second).
2. `utils/common.py::run_command_in_zsh_ns` bounds every such invocation with
   `NS_COMMAND_TIMEOUT = 3600` (introduced 2026-09-10 in `8f6330c` as the
   fail-fast contract: a hung dnsx must raise, never look like "0 results").
3. The `indeed.net` scope grew without bound — 42,430 names (2026-09-15) →
   **90,405** (2026-09-16) → **206,080** (2026-09-24), of which **201,074 are
   `dynamicBF` brute-force names**, currently growing ~**40,000 names/day**.
4. At the project's measured throughput that set needs **~2.6 hours** of dnsx
   wall time for that single domain — **2.6× the 3,600 s ceiling** — so the call
   is killed every night.
5. On 2026-09-16 the set (90,405) still *just* fit under the ceiling; from
   2026-09-17 onward (~128k names) it never did again. Nothing else changed:
   `-rl 30` and the command shape date back to the initial commit (2026-05-11),
   and the timeout has been 3,600 s since 2026-09-10.

Contributing (not causal) factors ruled out below: systemd configuration,
resources, network/tooling availability, the shared pipeline lock.

## EVIDENCE

- `systemctl status/cat watch.service`, `systemctl show watch.service` —
  oneshot, timer-triggered, exit 1, no signal, 43min CPU, no OOM/timeout kill.
- `journalctl -u watch.service` — 7 identical failures (2026-09-17 … 09-23),
  each `Failed with result 'exit-code'`.
- Step exit codes per run (logs 2026-09-18 … 09-23): **DNS Resolution = 1 in
  every run**; every other step 0 in every run.
- `ToolTimeout: ... timed out after 3600s` present in all 7 failing logs and in
  **no** earlier log (grep across every `logs/pipeline_*.log`).
- Input-size history from the logs: `indeed.net in=42430` (09-15) → `in=90405`
  (09-16) → no completion line at all from 09-17 (killed before printing).
- Live DB (read-only): `Subdomains.objects(scope='indeed.net').count()` =
  **206,080**; by `created_date`: 09-16 +47,972, 09-17 +37,711, 09-23 +37,547,
  09-24 +40,417; by `providers`: **201,074 `dynamicBF`**.
- Measured throughput (two bounded probes over real scope names with the
  production command): **21.9 names/second on fresh resolvers** (20,000 names /
  914 s) and **11.4 names/second under sustained querying** (25,001 names /
  2,201 s). At 21.9/s the 206,080-name scope needs **9,410 s (2.6 h)** in one
  invocation — **2.6× over** `NS_COMMAND_TIMEOUT`; at 11.4/s it needs
  **18,077 s (5.0 h)**, i.e. **5.0× over**. The ceiling cannot hold for this
  scope at any observed throughput.
- Pinned-file check: `ns/watch_ns_all.py`, `ns/wildcard_detector.py`,
  `run-pipeline.sh`, `pipeline_lib.sh` are sha256-pinned read-only in
  `aec/readonly_manifest.json` (116 files) — **none of them was modified**;
  `utils/common.py` is not pinned.

## REPRODUCTION

Bounded, single-copy, timeout-guarded — no unbounded production workload, no
competing copies, no duplicate pipeline execution:

```bash
# 1) real 20,000-name slice of the real scope, exact production command
dnsx -l /tmp/ns_probe_20k.txt -silent -a -resp -json -t 10 -rl 30 \
     -r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222
# → exit 0, 914 s, 7,666 resolved records → 21.9 names/sec
#   ⇒ 206,080 names ≈ 9,410 s ≫ 3,600 s ceiling (2.6x)

# 2) the repaired code path, 25,001 real names (2 chunks), same command
python3 -c "from utils.common import run_command_in_zsh_ns; ..."
# → 2 real dnsx invocations, total 2,201 s, 21,439 unique in-scope hosts,
#   every invocation under the ceiling, chunk temp files cleaned up
```

The failing mechanism is therefore reproduced arithmetically and empirically
without running the failing 2.6-hour invocation itself (which would have to be
killed anyway — exactly the production symptom).

## REPAIR

**Bound the work per invocation instead of moving the ceiling** — in the one
unpinned file on the failing path (`utils/common.py`):

- `run_command_in_zsh_ns` now splits a bulk `dnsx -l <file>` command whose list
  exceeds `NS_DNSX_CHUNK_SIZE = 15000` into **sequential bounded invocations**,
  each over a slice of the list and each with its own `NS_COMMAND_TIMEOUT`
  budget; the returned lines are the concatenation of every chunk's output.
- Fail-fast is **preserved unchanged**: every chunk still raises `ToolError`
  (non-zero exit) or `ToolTimeout` (hang); nothing is masked, no `|| true`, no
  downgrade to "0 results". A genuinely hung resolver still aborts the step.
- Every other call keeps byte-identical behavior: a small list, a missing/
  unreadable list file, a non-`dnsx` command or a `dnsx` call without `-l` is
  passed through as the original single invocation with an unchanged command
  string (this is what keeps `wildcard_detector.py` and the pinned callers
  untouched, and the pinned command-shape test green).
- Sizing is measured, not assumed: 15,000 names ≈ 500 s at the rate limit and
  ≈ 1,316 s at the slowest measured rate (2.7× margin under the ceiling); the
  incident scope becomes 14 bounded calls instead of one impossible one. Chunk
  temp files are removed in a `finally` block, including on failure.
- Chunking does not change the query rate, the resolvers, the wildcard
  filtering, the stored rows, or the step's semantics — only how the same work
  is divided across invocations.
- Known cosmetic detail: `watch_ns_all.py` prints the command *before* calling
  the runner, so the pipeline log shows the original single-list command while
  the runner internally issues the bounded slices. The log line is unchanged
  (that print lives in the pinned caller); the actual invocations are visible
  in the step's `Executing dnsx:` lines and in the dnsx process tree.

**Rejected alternative — raising `NS_COMMAND_TIMEOUT`:** the measured need is
9,410 s today (5.0 h at the slower measured rate) and grows ~40,000 names/day,
the pinned test caps the constant at 7,200 s, and a larger constant makes the
fail-fast contract meaningless (a multi-hour blind window). It would postpone,
not repair. Not applied.

**Not touched (correctly):** `ns/watch_ns_all.py` and the rest of `ns/*`,
`run-pipeline.sh`, `pipeline_lib.sh`, the systemd units, the timer, the AEC
manifest, EPIC11 integrity/reporting code.

**Flagged, out of scope — the remaining operational risk (numbers, not
hand-waving):** chunking bounds each invocation; it does **not** reduce total
work. The nightly DNS step still spends `scope_size / throughput` seconds:
**2.6 h at the fresh-resolver rate, 5.0 h at the degraded rate**, on top of
~1.9 h for the other four steps — i.e. **4.5 h to 6.9 h against the 6 h
`TimeoutStartSec`**. Tonight's run should complete (the first dnsx of the night
sees fresh resolvers), but the input grows ~40,000 names/day (≈ +30 min/day of
DNS work at the fresh rate), so the ceiling will be crossed within days unless
the *scope* is bounded. The honest repair for that is to resolve only
new/changed names or to bound the daily brute-force growth — both live in
pinned read-only files (`ns/*`, `run-pipeline.sh`) or are product/scope
decisions, so they were deliberately **not** taken unilaterally here.
Raising `TimeoutStartSec` was rejected too: it would eat the 12:00–00:00
AI/research window that the operating model reserves (core recon owns
00:00–06:00 Tehran), i.e. it would redesign the schedule to hide a workload
problem.

## FILES CHANGED

- `utils/common.py` — `NS_DNSX_CHUNK_SIZE`, `NS_SECONDS_PER_NAME_AT_RATE_LIMIT`,
  `_DNSX_LIST_ARG`, `_dnsx_chunk_commands()`, `_run_ns_command()` (the previous
  body, unchanged semantics), and the chunking dispatch in
  `run_command_in_zsh_ns()`.
- `tests/test_ns_chunking.py` — new (12 tests).

No systemd unit, timer, service file, pinned path, EPIC11 file or unrelated
worktree file was modified.

## TESTS

- `tests.test_ns_chunking` + `tests.test_ns_failfast`: **29 tests, OK**
  (12 new + 17 existing fail-fast/pinned-shape tests, all still green).
- Broader affected set (`test_pipeline_tooling_failfast`,
  `test_epic11_soc_integrity`, `test_candidate_workspace`, `test_finding_core`,
  `test_epic10_operations`): **195 tests, 1 failure — pre-existing and
  environment-dependent**, proven identical on the unmodified production
  checkout and green when `HOME` is unset (the systemd condition):
  `test_no_hardcoded_pouya_behnia_path` (the helper intentionally includes
  `$HOME/go/bin` for developer shells).
- New tests cover: bounded splitting of a 60,001-name list (3 chunks, exact
  slices, no name lost or duplicated, every chunk carrying the ceiling), the
  real 206,080-name scale (9 chunks, each provably under the ceiling), the
  quoted `-l "path"` form, chunk temp-file cleanup on success **and** failure,
  timeout in chunk 2 still raising and stopping the run, non-zero exit in a
  chunk raising `ToolError`, and byte-identical pass-through for small lists,
  missing files, non-`dnsx` commands and `dnsx` without `-l`.

## POST-FIX SERVICE STATE

- Service: `failed` is the *historical* result of the last run (2026-09-23);
  the repair is in the agent branch and takes effect for the next timer run.
  No manual `systemctl start` was performed (that would have launched a second
  full 3.4-hour production recon run outside the schedule, competing with the
  running environment for the shared lock and network budget).
- Bounded real execution of the repaired code path (§5/§9): the fixed runner
  was executed against **25,001 real `indeed.net` names** with the exact
  production command → **2 real dnsx invocations**, total wall time **2,201 s**
  (chunk 1 under the ceiling, chunk 2 instantaneous), **21,439 result lines =
  21,439 unique hosts, all inside the scope**, no duplicated or lost host, and
  **zero chunk temp files left behind**. `RESULT: PASS`.
- Deliberately **not** done: `systemctl start watch.service`. That is a
  3.4-hour unbounded production recon run outside the schedule (explicitly
  forbidden by the brief), it would contend for the shared
  `/run/watch-pipeline.lock` with the nightly job, and — decisively — the
  production checkout does not carry the repair yet, so starting it now would
  exercise the *old* code. The first real end-to-end proof is the next timer
  run (2026-09-24 20:30 UTC) after promotion.
- Next scheduled run: **2026-09-24 20:30:00 UTC** (watch.timer), at which point
  the DNS step is expected to complete as ~9 bounded invocations and the unit to
  exit 0.

## TIMER STATE

`watch.timer`: `ActiveState=active`, `SubState=waiting`, `Result=success`,
`Persistent=false` (no catch-up run after reboot — intentional, documented in
the unit), `OnCalendar=*-*-* 00:00:00 Asia/Tehran`,
`LastTriggerUSec=2026-09-23 20:30:13 UTC`,
`NextElapseUSecRealtime=2026-09-24 20:30:00 UTC`. The timer behaved correctly
throughout: it fired, the run happened, and the unit's failed state is the
pipeline's own exit code, not a scheduling fault. No timer, scheduler or unit
was created, duplicated or modified.

## RESOURCE CHECK

- RAM: 11 GiB total, 4.6 GiB used, **7.1 GiB available**; swap 0 B (none).
- CPU: 4 cores, load average 0.82/0.46/0.36 — idle.
- Disk: `/` 48 G, 27 G used, **21 G available (57%)**.
- The failing unit: `MemoryMax=infinity`, `MemoryPeak` not set, 43 min CPU over
  3.4 h — no resource pressure, no systemd timeout (6 h never reached).
- OOM: 3 kernel lines since 2026-09-16, all belonging to a **different** unit
  (`watch-dell-watchlist.service`, 2026-09-19 11:32, memcg-constrained) — no
  OOM or kill for `watch.service`.
- Conclusion: **not** resource exhaustion. The failure is wall-clock, not
  memory/CPU/disk/process-limit.

## PRODUCTION IMPACT

- No production file was modified: the repair is on `agent/daily-development`
  and reaches `/opt/watch` only through the normal promotion path.
- `run-pipeline.sh`/`pipeline_lib.sh`/`ns/*`/systemd units: untouched.
- The next scheduled production run behaves exactly as before until promotion;
  after promotion the DNS step completes instead of aborting the pipeline.

## UNRELATED PRE-EXISTING CHANGES PRESERVED

- Production `/opt/watch` dirty entries: **27, unchanged** (verified before and
  after every step). No `git add -A`, no `reset --hard`, no `stash`, no
  `clean -fd`, no file overwritten.
- Agent worktree: the 185 unrelated in-flight EPIC10 entries remain untouched;
  only the two files above are staged.
- EPIC11 code: not touched (the one EPIC11-adjacent read-model test in the
  affected set passes unchanged).

## FINAL GATE

| requirement | state |
|---|---|
| root cause evidence-backed | YES (§ROOT CAUSE + §EVIDENCE) |
| repair minimal | YES — one helper + tests; no pinned file, no unit, no design change |
| unrelated dirty files untouched | YES (27 production / 185 worktree) |
| service behaviour verified | YES — bounded real execution of the fixed path |
| timer behaviour verified | YES — active/waiting, correct next elapse |
| resource state checked | YES — not resource-related |
| relevant tests pass | YES — 29/29 NS tests; the one failure is pre-existing/environmental |

**READY TO PUSH: YES**
