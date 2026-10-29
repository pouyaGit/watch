# Regression failure disposition

Use this reference when a completed full-regression artifact has failed suites and
the task is classification-only: no feature work, no production repair unless a
failure is proven to be a new Day 1 regression.

## Evidence order

1. Read the current run artifact and preserve its run id, suite count, pass/fail/skip
   counts, inner runner exit code, duration, and artifact path.
2. Read the preserved pre-change baseline separately. Do not substitute baseline
   numbers for current-run numbers.
3. For every failed suite, obtain the exact failed check and the full available
   output. A final separator line (`====`) is not an assertion.
4. Inspect the failed check's source and the smallest data/call path it exercises.
5. Only then assign one classification.

## Keep a SET of baselines, not one

One prior artifact is not enough to classify a failure, because a single baseline run
can be spuriously healthy for a timing-dependent suite: the same suite that TIMED OUT
in a live run PASSED in a later network-isolated/overlay run, so the most recent
pre-change baseline alone would have made it look introduced. Preserve at least two
pre-change artifacts — one from a run under the same conditions as the current one and
one older from normal/host conditions — and classify against whichever reproduces the
failure identity. A baseline produced under isolation conditions is evidence only for
suites that actually do network or filesystem work under those conditions.

Diff the SET of failing script paths, never the aggregate counts. Equal
`N passed / M failed / K suites` in both runs proves nothing: two runs can swap four
failures and keep the same totals. Compute, per artifact:

- `baseline ∩ current` — same script failing in both; then compare the normalized
  assertion text with durations and temp-dir/UUID tokens stripped, because timings
  differ every run and a per-run temp path makes an identical failure look new.
- `baseline − current` — suites that now PASS. Report them as improvements; a suite
  moving FAIL→PASS is not a regression and must not inflate the pass count silently.
- `current − baseline` — the only rows that can be INTRODUCED. Each one is either
  proven introduced or left UNKNOWN.

When a normalized assertion cannot be extracted (a trailing separator line, a temp-dir
path as the whole summary), say the check text is unrecoverable and fall back to the
state transition (FAIL→FAIL across artifacts) plus the suite's own source. Do not
invent assertion identity from a separator.

## Validate the baseline HARNESS before trusting its verdicts

A baseline run is evidence only if its harness actually exercised the real code
path. Check the harness, not just its output, before any of its numbers reach a
classification table.

The failure mode is a fixture that cannot support the suite's own assertions: a
scratch tree whose database is a symlink (sqlite will not resolve a WAL-mode
target through it), a tree seeded with an empty or hand-written schema, or a
`mode=ro` source whose tables the suite never touches. Suites then PASS for the
wrong reason — `SELECT` against a missing table returns zero rows, `assertEqual`
on an empty list is vacuously true — and the baseline prints a healthy `0` exit
code for a suite that is in fact broken in both arms.

That inverts the comparison. A suite that genuinely fails after the change and
trivially passed in the baseline is reported `NEW_REGRESSION` when the truth is
`ENVIRONMENTAL` or a pre-existing break, and the final gate carries a fabricated
count into the one number the user reads first.

Before using a baseline row, confirm:

- The fixture database was a real copy of the live schema (SQLite `backup()` from
  a `mode=ro` source, not a symlink and not a hand-built DDL subset), so the
  suite's tables and columns exist.
- The suite's failure is visible when you break it — a harness that cannot fail
  is not a baseline. Perturb one input and confirm it goes red.
- Row counts in the baseline are non-trivial where the suite asserts on counts.
  All-zero fixture data plus a passing suite means the assertion is vacuous, not
  satisfied.
- The baseline ran the same script text as the current run (compare hashes), not
  an older revision of it.

When the first baseline turns out to be unsound, discard it entirely, re-run it
with a real fixture, and re-derive every classification from the corrected run.
Do not keep the convenient rows from the broken run and re-collect only the
inconvenient ones — the whole table shares one trust basis. State the discarded
run and the reason in the report, because a reader who saw the first table has to
know it was wrong.

Corollary: a scratch tree built for baseline purposes needs its OWN real
database copy. Reusing a symlink to the live DB to save disk produces a baseline
that measures nothing.

## Test scratch dirs accumulate into a real failure mode

Suites that copy a large DB into a `mkdtemp` dir and never clean up leak
hundreds of megabytes **per run**. Under sustained milestone work this fills the
volume, and an unrelated suite then fails with `sqlite3.OperationalError: disk
I/O error` while creating a table in its own fresh temp dir.

The signature: a suite that is clean standalone, repeatedly, fails only inside
the full runner, on a write to a brand-new temp file. Before blaming the
milestone, measure the volume and count the leaked dirs by prefix:

```bash
du -sh /tmp
ls -1d /tmp/<prefix>_* 2>/dev/null | wc -l
du -shc /tmp/<prefix>_* 2>/dev/null | tail -1
```

Only delete paths matching the known test prefixes, assert each is a directory
under `/tmp`, and verify production is intact afterwards (table count,
`quick_check`, `integrity_check`, `foreign_key_check`, a known row count) before
reporting. Reclaiming `/tmp` is environmental housekeeping, not a code fix —
never "fix" a working suite to work around a full disk.

Ordering trap: an apparent `disk I/O error` that vanishes after cleanup is an
environmental finding, but it is **not** proof that a reproducible-looking
failure is now explained. Re-run the suite **inside** the runner after cleanup
before retiring the claim, and keep the raw failure text in the report.

## Truncate the artifact before a re-run, then read rows not the summary

A battery that appends to its own `results.tsv` / `battery.log` makes its own
summary line lie on the second run. `FAILED_SUITES` is computed over every row
ever written, so a run where 2 suites still fail can print the previous run's
`FAILED_SUITES: 0` while the freshly appended rows carry `rc=1`. The stale number
is the one a reader trusts, and it is the opposite of the truth.

Truncate first, then read the machine truth back out of the rows rather than off
the summary line:

```bash
: > state/<m>/regression/results.tsv && : > state/<m>/regression/battery.log
bash state/<m>/regression/battery.sh
awk -F'\t' '$2!=0' state/<m>/regression/results.tsv   # the authoritative set
```

A suite list that changed between runs — suites added, removed, or renamed —
makes the same corruption worse, because a diff of the two tables then means
nothing. When a milestone adds suites to a shared battery, say so in the report
so a reader can tell a genuinely new row from a leftover one.

Keep the intermediate failing run as evidence: it is what justifies any
retargeting work, so the report cites the per-suite before/after, not only the
final `0`.

## Establish the edit window from mtimes before trusting a baseline

A baseline that finished BEFORE the earliest source change of the milestone cannot be
affected by that milestone. Derive the boundary mechanically: list every `*.py` under
the repo whose mtime is newer than the baseline artifact's completion time, excluding
`state/`, and take the earliest as the edit-window start. Cite the protected-file hash
comparison separately — a hash match proves the untouched files are untouched, while
the mtime scan bounds WHICH runs can be causally involved at all. Without this, a
baseline is an undated assumption.

## Reachability is a shortlist filter, not causation

Compute each failed suite's transitive import closure (AST `Import`/`ImportFrom`
resolved against `lib/` and `scripts/`, walked recursively) and report which of the
milestone's own modules it reaches. This narrows the candidate set cheaply, but a
module being importable is not a code path executing:

- closure contains the module AND the identical failure is in a pre-change baseline →
  `PRE_EXISTING` (reachability without causation; say both facts).
- closure contains the module AND no baseline shows the failure → the row is a
  candidate, still `UNKNOWN` until a focused reproduction isolates the check.
- closure does not contain the module → a code regression through the milestone is
  structurally impossible; the remaining possible channels are data the suite reads
  from shared state and the shared store itself, which must be stated explicitly
  rather than assumed away.

## A suite that copies LIVE state has a moving input

A verifier that copies the live DB into its work directory and then asserts
row-count or timing properties can fail from state growth alone: recon keeps running
between the baseline run and the current one, so row counts and table sizes move
under a fixed codebase. Such a failure cannot be split into code-dependent vs
volume-dependent without a fresh single-suite run. When that run is forbidden by the
stage, the honest disposition is `UNKNOWN` with the missing evidence named
specifically: the per-check evidence file that was never written, and the check text
the runner never persisted.

## The shared runner's table may not include the milestone's own suites

The canonical runner's suite list is fixed in its own source and predates the current
milestone, so `K/K suites, N passed` says nothing about the new layer. Treat the
shared-runner result (regression gate) and the milestone's own focused suites
(correctness gate) as two separate evidence objects, and state in the report that the
new layer's suites are not covered by the shared table. Never let a green shared
number be read as coverage of work the table cannot see.

## Disposition matrix

| Evidence | Class | Required action |
|---|---|---|
| Same normalized failed assertion exists in the preserved baseline; touched Day 1 files/data are unchanged | `PRE_EXISTING` | Record baseline path, matching check, and identity evidence; do not repair unrelated code. |
| Targeted run proves the assertion expects an obsolete label/count/contract, or the fixture's expected seed is contradicted by the current fixture producer | `STALE_TEST` | Record old expected value, observed value, and exact producer/consumer path; do not call the filename alone sufficient. |
| Test output names DNS, upstream fetch, cooldown, freshness, wall clock, or a controlled no-network differential | `ENVIRONMENTAL` | Keep the failure; never convert it to PASS. Record the environment evidence and residual uncertainty. |
| Suite explicitly fails because a required historical baseline file is absent | `BASELINE_ARTIFACT_MISSING` | Do not manufacture the baseline. Record the path and missing artifact. |
| Failure is absent from all preserved baselines and the Day 1 module/data path is demonstrably involved | `NEW_REGRESSION` | Write a focused red test, fix only the proven root cause, rerun targeted and relevant regression suites. |
| Attribution or root cause is not established | `UNKNOWN` | Leave unresolved; do not infer from runner labels or a short summary. |

## Controlled differential recipes

### Network/DNS

For a suite that calls DNS or an upstream fetch, run the exact suite once in the
normal environment and once under a network-isolated namespace or with its declared
transport stub. A failure that changes only in the no-network arm is environmental
for that test; a failure reproduced in both arms requires code/fixture analysis.
Do not apply this recipe to offline suites that never call DNS.

### Stale assertion

Compare the failed assertion with the current consumer's contract and run the
consumer once with a minimal fixture. Examples: a status test expecting an old label
while the renderer emits a renamed field, or a seed helper producing a different
count than the test's hard-coded expectation. This proves `STALE_TEST` only when
the current producer's contract is documented or directly exercised; filename alone
is not evidence.

### Baseline artifact

Read the baseline path and existence mode first. If the suite has an explicit
`baseline available` check and the file is absent, classify
`BASELINE_ARTIFACT_MISSING`. Never create a fake baseline or save a new snapshot
solely to satisfy the check. Keep the missing path as a limitation.

### Shared store/authority path

A failure in a suite that imports the shared store or canonical authority layer is
not automatically Day 1-related. Trace the actual call/data path and compare the
failed input with preserved baselines. If a shared layer changed but the exact
before/after counters or identity evidence are absent, retain `UNKNOWN` for the
attribution and do not call it a new regression.

## Reporting rules

Report a table with one row per failed suite and, when a suite has multiple distinct
checks, one disposition per check. Include exact assertion text, observed output,
classification, Day 1-related verdict, and evidence paths. For every `UNKNOWN`, list
the exact missing artifact or unrun observation rather than a general hedge, and
separate "what is missing" from "what was tried". Name the single unresolved candidate
suite in the `CRITICAL_*` field even when the proven count is zero, so a reader cannot
mistake `NOT_CLEAR` for `CLEAR`. State counts by class and
keep the core suite results separate from regression failure classifications. A
current-run wrapper exit code is not the regression verdict; the inner runner's
completion marker and exit code control the gate.

If any important Day 1-related failure remains `UNKNOWN`, the technical status is
`INCOMPLETE`, even if no `NEW_REGRESSION` is proven. If no new regression and no
important unknown remains, report `PASS` while retaining all environmental,
pre-existing, stale-test, and missing-baseline limitations.

## M11 bounded check-specific recipe

For a failure such as `the events table grew only by the one-time migration amount`,
do not classify from the one-line runner summary. Reconstruct the exact accounting
on a consistent frozen copy (SQLite `backup()` is safer than `cp` for a WAL DB):

1. Snapshot the learning table counts before any learning call.
2. Run the real learning entry point the same number of times as the suite.
3. Record `events_new` for every run, then compute
   `growth = after.learning_events - before.learning_events`,
   `expected = runs[0].events_new`, and `delta = growth - expected`.
4. Compare the source-table fingerprint before/after and require it unchanged.
5. Report `growth == expected` and `delta == 0` from the reproduction; do not call
   the check green if the current artifact lacks the raw counters.
6. Keep the reproduction artifact separate from the full-run artifact. A full
   runner may retain only a separator/check name, while a targeted run can contain
   the exact values.
7. Trace `run_learning → persist_events → learning_event_upsert` and separately
   inspect `case_insert`, `case_event_add`, `case_event_latest`, lease fencing, and
   the shared `conn()` implementation. Shared code does not imply relevance: cite
   function-level call/data evidence. If none of those functions participates in
   the event write, record `DAY1_STORE_PATH_RELEVANCE: NONE`.

A one-time first-run migration is valid when the test itself allows it: `new[0]`
may be non-zero, but runs 2..N must be zero and the row-count growth must equal
`new[0]`. Do not turn a passing check-4 reproduction into a claim that unrelated
checks in the same suite passed; report those separately.
