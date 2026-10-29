# Closing a milestone: verification-honesty rules

Use when a brief is a CLOSURE / FINAL VERIFICATION / status-check: the build is
done and the only job is to prove it and write the gate. These rules govern the
measurement itself, which is where a closure milestone most easily goes wrong —
not because the code is broken, but because a number got read wrong.

## 1. A recited "already verified" list is a claim, not evidence

Closure briefs often restate prior results ("Focused: 222/222", "suites have
already been added") so the responder can skip straight to the gate. Re-verify
every recited number from the machine. The recitation is a claim about a
previous session, and the whole point of the closure brief is to establish
ground truth.

The highest-risk item is a suite the brief says was added to a shared runner:

- confirm the edit is **present in the runner source** (grep the runner for the
  suite name) — a scripted edit that reported success can have matched nothing;
- confirm the suite **actually produced a row** in the results artifact;
- compare the results row count against the runner's suite count. 38 rows when 41
  suites are defined means three never ran, no matter how green the rest look.

A suite absent from the results file was never run. Saying otherwise because the
brief described it as wired is the exact failure the gate exists to prevent.

### Two of your own numbers disagreeing is a STOP, not a rounding error

When two statements cannot both be true — "38 suites ran, mine are absent"
beside "41/41" — the gate is not closable on either. Re-derive both from the
filesystem before writing anything: the runner's `sha256`, its declared suite
count, the executed row count, and the executed suite names. Do not pick the
reading that lets you finish.

A scripted edit to a shared runner that "reported success" may have matched
nothing. Verify the edit landed by grepping the runner source for the new suite
and counting its invocation sites, not by trusting the edit script's own success
message. Record `RUNNER_SHA256` and both counts in the report so the next reader
can check the wiring without re-running anything.

## 2. A backgrounded wrapper that returns is not a run

`nohup cmd > log 2>&1 &` and `cmd &` return instantly and report success even if
the command was never launched or died at startup. For a gate that must finish:

- prefer a **foreground run** with a timeout larger than the measured total
  (budget from per-suite durations, with margin);
- if a background run is unavoidable, first confirm the process exists and the
  artifact is **growing**, then poll;
- read terminal markers (`FAILED_SUITES:`, `INTEGRITY_RC:`) from the artifact,
  not from the wrapper's exit status.

A wrapper exit code of 0 means the wrapper finished, nothing more.

### `setsid`/`nohup` are worse than a bare `&` for a gate artifact

Under this harness a `setsid ... &` or `nohup ... &` launch **dies when the
tool call returns** — the process is reaped with the shell. The trap is that the
*previous* run's artifact is still on disk, so every later poll reads a stale
file that looks exactly like a fresh result.

Two checks that catch it, both required before quoting any number:

```bash
date '+now %H:%M:%S'
stat -c '%y' state/<m>/regression/results.tsv | cut -c1-19   # must be ~now
```

Also: `pgrep -f <script>` can match the poll's own shell, so a `RUNNING` answer
is not proof the runner is alive. Confirm progress by the artifact's **mtime and
row count** instead. For a long suite list the reliable shape is to launch in one
call and poll in separate calls, watching the row count climb (0 → N) — that is
what distinguishes a live run from a dead wrapper.

## 2a. An append-only per-suite log inverts "N for N" failure counts

Many runners truncate their summary artifact (`: > results.tsv`) but **append**
to each per-suite log (`>> $REG_DIR/<label>.log`). That asymmetry fabricates a
pattern that looks damning and is not real.

If three attempts are made and the per-suite log holds seven clean summaries
against one traceback, the suite failed **once**. Re-reading the same stale
`results.tsv` and reporting "failed on every run" is a fabricated finding that
sends you to investigate working code.

Before declaring a failure reproducible, count both directions in the
append-only log:

```bash
grep -c '<suite success marker>' state/<m>/regression/<label>.log   # clean runs
grep -c 'Traceback'                   state/<m>/regression/<label>.log # failures
```

When a suite reproduces only "inside the runner", reproduce it by hand under the
runner's conditions one factor at a time: standalone several consecutive times;
with the daemon running; with the daemon stopped; after the immediately
preceding suite; with the production DB held open by another process. A suite
that is 12/12 clean standalone was never a regression, no matter how many stale
artifacts appeared to say otherwise — and the correct report says so explicitly
rather than leaving the earlier claim standing.

## 3. One green counter does not close a gate

A regression battery commonly emits both `FAILED_SUITES: N` and
`INTEGRITY_RC: N`, and they can disagree. Report both plus the actual row count.
When they disagree, resolve which is authoritative and say which you relied on —
do not quote only the one that reads well.

For a snapshot-based integrity counter, the nonzero code is frequently an
**artifact of whole-file hashing**, not a mutation. Classify it before reporting
it; see `read-only-layer-build.md` § "Whole-file hashing cannot certify 'no
mutation'" for the signal table that separates a WAL checkpoint (bytes and mtime
move; size, schema, row counts, and checksums all agree) from a real write.

Reporting that as mutation is as false as hiding it. Neither is acceptable.

## 4. The controlled window is the authoritative mutation measurement

A before/after comparison taken while a daemon is writing measures the daemon.
When the closure brief requires "PRODUCTION MUTATION BY <this work>: 0":

1. stop the writer,
2. exercise the new surface hard (every route, every filter, hostile input, and
   every refused write method),
3. compare per-table `COUNT(*)` **and** a per-table row checksum, plus the full
   schema object list,
4. run `quick_check` / `integrity_check` / `foreign_key_check`,
5. restart the writer and confirm it is `active` before reporting.

Report the table count and the total row count compared alongside the delta, so
the number is falsifiable. A delta of 0 across 197 tables and ~1.2M rows is a
claim a reader can check; "no mutation" is not.

Per-table checksums matter: they detect a same-size rewrite, which a whole-file
`sha256` cannot distinguish from a checkpoint.

## 5. Re-verify after a late change to shared rendering

If a late checkpoint touches a shared render/helper module, the earlier focused
results are stale. Re-run every suite that exercises the shared module before
writing the gate, and say that you did. Claiming a pre-change count as the final
count is a stale-verification error even when the change was small and even when
it turns out to be harmless.

## 6. Preserve data findings; never normalize them

When live counts differ from an earlier spec, **both numbers are real and both
are reported.** Do not reconcile them to make a table look tidy, and do not
quietly update the spec figure.

Two distinct shapes, worth distinguishing because they mean different things:

- **time-varying growth** (a URL/case count that rose between spec and build
  because the system is still running) — live is authoritative, note the delta;
- **a curated set that shrank** (the spec claimed 4 patterns, the table holds 2)
  — that is a finding, not noise, and it is reported plainly.

When a query **unions a second source**, the table count and the query count
differ and both are legitimate source-derived numbers. Print both with the
reason; never pick one.

## 7. Write the limitations you actually found

A closure report earns its PASS by being specific about what is weak. Include:

- defects found and fixed during verification, especially the *silent* class
  (an error rendered as a plausible empty state) — that is the valuable content;
- checks that were **false failures** in your own suite, and why the check was
  wrong rather than the code;
- every genuine limitation, including ones that reflect on shared infrastructure
  you deliberately did not edit;
- any figure that looks contradictory, explained in place.

Do not resolve a contradiction by deleting the weaker number. Explain it.
