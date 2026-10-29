---
name: hermes-verification-discipline
description: Use when verifying Hermes or reporting test results.
---

# Hermes verification discipline

Rules learned the hard way while closing Phase 2A and AUTH-1. Each one caused a
false report — a "regression" that did not exist, a stale result presented as
current, or a green tick that measured the wrong thing.

## A 200 ON A WRITE PATH IS NOT A WRITE, AND A 404 IS NOT AN ABSENCE

Two false positives in one round, both from reading a status code as a
result:

1. A CDN answered `200` to `POST /path/asset.js` and to `POST /path/`.
   The script recorded "write accepted". In fact the POST returned the
   **identical 15-byte default object** (`//HTTP:default`) that the same
   host returns for `GET /path/` - the edge serves its default object
   regardless of method. "The write was accepted" is falsified by
   "the response is byte-identical to the default object".

2. The takeover fingerprint fired on `"Access Denied"`,
   `"Unsupported Request"` and `&#58;`, classifying the host as S3. The
   `Server` header said `AkamaiNetStorage`; `&#58;` is HTML-entity `:`,
   used across vendors.

Rules:
- A status code is not an outcome. For a write, compare the response
  body to the **default/fallback body** the same host returns for a path
  that cannot exist. Identical means the method is being served the
  default, not that state changed.
- For a target opened by a probe, compare against a host that CANNOT
  exist (an impossible tenant, an impossible path). If both answer the
  same shape, the probe measures the platform, not the target.
- A signature built from strings must be run against a control from a
  different vendor before it is believed.

## WHICH DAY IT IS DOES NOT DECIDE WHETHER EVIDENCE IS STALE

A dozen background-process notifications arrived carrying older exit
codes than the machine's current state (a `1` failure from a run that
was fixed, a `72 passed` from before a section was added). Each looked
like a regression until compared against the current artifact.

- When a notification disagrees with your memory, **re-run the check
  from the machine and compare mtimes**; do not act on the notification's
  exit code alone, and do not act on memory alone either.
- Record the confirmation, not the alarm: "the current run is
  `104 passed, 0 failed`" is the report; the stale `72` is not news.

A coverage measurement reported 1,282 probed hosts by testing
`if host in filetext`. Re-measured with a hostname BOUNDARY check it
was **1,142** - 140 hosts lower.

The cause: `"dell.com"` is a substring of
`"agileattachmentutility.us.dell.com"`, so every child host that was
read also marked its PARENT domain as read. A plain `in` test cannot
tell a host from a host's suffix.

That was the second coverage figure in the same hunt inflated by a
matching rule rather than by the work (the first was a hand-written
file list). Both reported a number about the bookkeeping.

> **Rule: match hostnames on boundaries, never as substrings. And when
> correcting a coverage figure DOWNWARD, record both numbers and say
> which is right - a reader who saw the old figure needs to know it
> was wrong, not just that a new one exists.**

### The performance trap that comes with the fix

A per-host regex over 71,000 hosts across 277 files never finishes.
Invert it: tokenise each file ONCE into hostname-shaped tokens and
intersect with the universe set. O(files x tokens) instead of
O(files x hosts). A measurement that does not complete is not a
measurement.

## DERIVE THE INPUT LIST FROM THE FILESYSTEM, NEVER FROM MEMORY

A coverage measurement listed the artifacts that record requests by
hand. The list named **27 files that do not exist** - `round3_x.json`
when the real output was `round3_x.log` - and omitted files that do.
`hiringlab.indeed.com`, probed across five phases, was counted as
**never probed**. The measurement said 163 hosts probed; derived from
the directory instead, it said **1,282**.

A nine-fold error from one wrong assumption about a file extension,
and it failed silently: the run completed, the numbers looked
plausible, and the only symptom was a count that was too small.

> **Rule: build the input list with `os.listdir`/`search_files`, then
> filter. A hand-written list of filenames is a guess. And when a
> measurement tool reports a count, ask what it would have reported
> if a file it expected were missing - if the answer is "a smaller
> number, silently", the list is the bug.**

Corollary for coverage claims specifically: **name the numerator AND
 the denominator.** "The work is done" is a claim about a set; without
the set's size the sentence cannot be checked. On one target the
shortlist was 95 hosts and the live universe was 72,427 - so "the
environment is finished" was true of 0.1 % of the target and the
sentence should have been "the shortlist is finished".

## A NUMBER CAN BE TRUE AND STILL BE UNFINDABLE

An audit that extracted every integer from every note's tables and
fenced blocks and checked it against the artifacts the note cited
flagged three numbers. All three were correct:

  - two byte offsets inside a JavaScript bundle, quoted from a live
    search that was never written to an artifact,
  - one row count, derived from a list the artifact stores as ROWS
    rather than as a total.

The finding is about the audit's method and the note's habit, not the
numbers. A figure a reader cannot reach is a figure a reader has to
take on trust, and "I measured it and did not save it" is how a note
acquires one.

> **Rule: every number in a deliverable should name the artifact that
> lets the next reader check it - including derived ones. If a figure
> comes from a live search, save the search's output; if it is a count
> over rows, say which key holds the rows.**

Two corollaries when the AUDIT itself is the instrument:

  - a number stored with thousands separators (`2,702`) will not match
    a search for the bare digits (`2702`). Compare both forms, or strip
    separators from the artifact before searching. The first version of
    this audit reported a supported number as unsupported for exactly
    that reason.
  - read the key the data is actually under. A field named
    `product_paths` held an INT (a total) while the LIST was under
    `product`; reading the obvious-looking name returned "0 hosts" and
    almost became a finding.

## 2. Never report a run you did not observe

Backgrounded launches (`&`, `nohup`, `setsid`) launched from a tool call die when
that call returns. A "run" whose only evidence is an old `results.tsv` is not a
run.

- Run long suites in the FOREGROUND, or poll a file whose mtime provably advances
  (print `date` and the mtime together).
- Before quoting any result, confirm the artifact is newer than the change that
  produced it. `stat -c %y <log>` vs `stat -c %y <script>` settles it.
- **A results table that is all-green is still not a run you observed.** The
  near-miss: a rerun timed out, so the only evidence available was the PREVIOUS
  run's green artifact, and reading it produces a PASS for a run that never
  completed. Before quoting a table, confirm it was written by THIS invocation —
  mtime newer than the invocation start, or a run id that matches the one you
  just launched. If the rerun did not finish, the result is UNVERIFIED, full stop.
- A wrapper reporting exit code 0 may be reporting the shell, not the test.
  Read the embedded exit status.

## 2. `pgrep -f <pattern>` matches your own command

The pattern appears in the shell invocation that runs `pgrep`, so you get a false
"still running". This produced phantom "the battery never finished" and "the
test never executed" conclusions.

- Match a unique marker, or read the pids you captured, not a fresh pattern.
- Cross-check against a second signal: an advancing row count, a growing log.

## 3. Append-mode logs accumulate across runs

The regression battery uses `>>` and never truncates per-suite logs. One
traceback in the log does NOT mean the suite fails every time — count
occurrences of the failure signature and the success signature together before
concluding anything.

Corollary: "it failed four times in a row" was wrong. It failed **once**; the
other three were re-reads of the same stale file.

- When a per-suite log is append-only across many runs, the authoritative signal
  is the LAST result line it wrote, and better still the run's own per-suite
  artifact (the results table row for that suite). Never conclude from the first
  `FAIL` lines you find with `head` — those can be from a run weeks earlier that
  failed for a reason since fixed.
- A resource refusal in a stale log (e.g. `server-unsafe:disk 93%`) while the
  current run had plenty of free space is the same trap: you will explain the
  current failure with a historical cause. Check the run's timestamp against the
  log's entries before adopting any explanation.

## 4. Whole-file hashes cannot see content — and a live WAL DB has no stable bytes

A whole-file `sha256` cannot distinguish a real write from ordinary SQLite
bookkeeping. The mechanism is commonly misattributed: it is NOT only
checkpointing. Measured over 8 samples at 5s intervals with production running,
the main DB file took **8 distinct hashes and grew ~360KB while its WAL stayed at
exactly the same byte size for every sample** — continuous writers push WAL
content back into the main file continuously.

Consequence: byte identity of a live WAL database is a property of a QUIESCED
MACHINE, not of your code. A test asserting `sha256(db) == sha256(db)` measures
host load, and will pass or fail for reasons unrelated to the suite. Do not
"fix" it by stopping the daemon — an E2E suite may not require a stopped system.

- Measure SEMANTIC state instead, read-only: schema hash (`sqlite_master`),
  protected per-table `COUNT(*)`, and row-level invariants (GROUP BY state
  distributions), plus `PRAGMA quick_check` / `integrity_check` /
  `foreign_key_check`.
- Get consistency from SQLite, not from timing: open `mode=ro` and run inside
  `BEGIN DEFERRED`, so every query in the window sees one point-in-time view. No
  sleep, no retry loop, no quiescing.
- Keep the raw hash/size/mtime in the evidence output for forensics; just do not
  make it the gate.
- When proving "my run did not mutate production", assert the semantic delta is
  empty AND the integrity pragmas are clean — that is strictly more targeted than
  a file hash, because it catches a schema or row-state change that a
  re-written-but-equivalent file would hide.
- Prove the replacement contract is non-vacuous: mutate a COPY (a row update, a
  row insert, a schema change) and require detection, then restore and require
  the identical fingerprint back. A semantic gate that only ever passes is as
  worthless as the byte hash was.
- `shutil.copy2()` / `cp` of a live WAL DB does **not** capture the WAL, and the
  result can fail `integrity_check` with `Freelist: size is N but should be N+1`
  because the main file's header still describes a WAL that is absent. Use
  SQLite's own backup API (`src.backup(dst)`) to snapshot a live database. This
  bites every suite that copies production to a frozen fixture.
- Read table and column names from the real schema (`PRAGMA table_info`) before
  writing invariants against them. Guessed names (`hunt_cases.state`, a
  `targets` table) fail with `no such column` and, worse, a wrong-but-existing
  column name would silently fingerprint the wrong thing.
- This applies to every throwaway capture/audit script, not just to test
  fixtures. Take one `PRAGMA table_info` pass over every table the script
  touches before writing a single query. Event/lineage tables commonly key on
  `event_id` + `sequence` + `object_type` and keep the payload in a JSON
  `metadata` column; provider-request tables commonly use `request_id`, `state`,
  `provider_status`; queue/config/target tables frequently do not exist under
  the obvious name at all. When unsure of a name, list candidates with
  `WHERE name LIKE '%x%'` and read the real shape instead of guessing.
- Report both numbers. Never silently convert a raw non-zero exit into 0.

## 5. Live row counts measure the daemon, not your change

With the daemon running, every table drifts on its own. A before/after
comparison in that window accuses the daemon of being your change — and that
false accusation was made twice here.

- Prefer an assertion that is true REGARDLESS of concurrent activity: a semantic
  fingerprint of the rows your run could actually write, with a `BEGIN DEFERRED`
  read view (see §4). A gate that requires a stopped daemon is a test that
  cannot be run in production hours.
- **A regression battery can leave the service STOPPED, and a later milestone can
  inherit that.** A test harness that stops a service to get a stable comparison
  may not restart it, and the next milestone finds an `inactive (dead)` unit
  that nobody stopped. Check the unit in the baseline phase of EVERY milestone,
  not only when something looks broken.
- When you must quiesce, treat stopping the daemon as a bounded, disclosed
  action: stop, exercise, compare, restart, then confirm the service is `active`
  with `NRestarts=0` before reporting. Briefs that forbid "disabling production
  writers merely to make tests pass" are ruling out exactly this — a test that
  only passes on a stopped system has been made deterministic by breaking
  production, not by fixing the test.
- Classify deltas in runtime tables (`jobs`, `worker_events`, `urls`, ...) as
  normal daemon activity, and say so explicitly.
- A test whose admission/scheduling check reads LIVE host state (CPU, load, RAM,
  a reserve window held by another service) is host-dependent by construction.
  The admission gate is usually RIGHT and the test's expectation wrong: when a
  real run legitimately holds a reserve, the correct worker count is lower than
  the test asserts. Pin the test's environment inputs after the section that
  exercises the real gate unstubbed, so the policy stays covered and the
  concurrency contract becomes deterministic. Prove it on a quiet host with N
  consecutive runs, and state that the live gate still returns the reduced
  value.

## 6. Re-read your own report before gating it

The user halted Phase 2A because one message said the battery's Phase 2A suites
were absent while the same closure claimed `REGRESSION: 41/41`.

- Print your claimed numbers back at yourself and check they agree.
- Verify counts from the declared source (grep the script) AND the executed
  artifact (read the results), not from the run you remember.
- **Grep the delivered file for every literal field name the brief required.**
  Prose headings are not field labels: a report with all the content but
  `SKILL_EFFECTIVENESS:` absent from it scores as missing when the gate is a
  literal-field check. Score the report itself before calling it done —
  `for f in required: assert f in text`.
- When a background notification arrives for work you already consumed, treat it
  as a free re-check rather than noise: compare its numbers against live
  state, and if it invalidates a claim you already published, correct the
  report explicitly instead of leaving the bad claim standing.
- **A notification's "final" block is a snapshot of when THAT process stopped, not of
  now.** A watch loop that breaks out on its first hit (job appears, file created)
  reports the intermediate state it left behind, and a later replay of it reads like
  current news. Re-read the artifact before acting on any headline it carries.
- **Before believing a notification that a commit was BLOCKED, check the commit is
  still reachable.** A gate result belongs to the exact sha it ran against: after an
  `--amend`, the blocked pre-amend object is unreferenced and its notification
  describes nothing real. `git merge-base --is-ancestor <sha> HEAD` (non-zero = the
  sha is an orphan) settles it in one line; compare the notification's sha against
  `git log --oneline -1` before reporting a deploy problem.

## 7. Test harnesses leak state into later suites

- Setting `os.environ[...]` at MODULE level mutates the process environment for
  every later suite. It pointed two suites at an empty temp DB and broke them.
  Pass an explicit env to the subprocess; never mutate `os.environ` at import.
- Retargeting a stale assertion is legitimate, but say so. Rewritten assertions
  are weaker evidence than untouched ones, and several of those retargets were
  made *stronger* (hardcoded count -> proved against a captured baseline).

## 8. A swallowed error is the most dangerous class of bug

`db.rows()` caught `sqlite3.Error` and returned `[]`, so a timeout rendered as
"no data" and the HTTP Explorer showed 0 assets while holding 22,515. Six such
bugs were found this way.

- Never render an error as an empty state. Count it, surface it, fail loudly.
- When a value is "not found", distinguish: absent, inaccessible, and broken.

## 9. Interpreter mismatches are deployment bugs

`bcrypt` is importable only by `/usr/bin/python3`; the bare `python3` on PATH is
a venv without it. Both are "python3" to a human.

- Confirm the interpreter the SERVICE uses, and run every script with it.
- Validate schema claims against the real table, not an assumed column.

## 10. Honest INCOMPLETE beats a manufactured PASS

Report `INCOMPLETE` with the exact remaining work when a gate is not met. The
user accepts that verdict; they reject a PASS that rests on an unverified claim.

Corollary for a fix that cannot yet be observed end to end: if the natural
production cycle has not yet fired, DO NOT wait indefinitely and DO NOT let the
absence of a new row become an implied success. Instead exercise the exact
production functions the daemon runs, against production state, in the service
own environment (inherited from the live process environ, not your shell), and
record the decision it produces. Then state plainly that the live proof covers
the identical code path while the first natural cycle has not yet run. That is
evidence; an inferred success is not.

Corollaries this user's briefs restate every time, so they are standing rules:
- Increasing a call count, token count, or queue throughput is never success. The
  gate is a measurable improvement in the work product; if the useful-output
  count is 0, report 0 and stop.
- When the honest answer is "the system correctly refuses this population", say
  INCOMPLETE and leave the guard alone. Do not widen the guard to turn
  INCOMPLETE into PASS, and do not invent a new eligibility category to justify
  the units that were excluded.
- A domain guard that declines a record is a *result*, not a crash: report it as
  a legitimate decline, with the function and line that produced it, and cite the
  module's own test if one asserts the same refusal.

## 11. A refusal cascade is one root cause, not N failures

One gate can fail every dependent check at once. Symptom: a suite reports 8-10
fails that all name worker/thread/slot/queue behaviour while every pure-logic
check passes.

- Read the FIRST failure's detail string, not the last check name. The cascade
  reported `admission grants capacity when resources are free :: (0,
  'server-unsafe:disk 93%')` and every other failure was its consequence.
- When a check that asserts the happy path fails on a *resource* verdict, measure
  the resource before blaming the code: `df -h`, free memory, load average, open
  file descriptors.
- Then ask who filled it. Leaked fixtures from the test suite itself are a
  common and self-inflicted cause; find the generator with a `du -sh` ranking plus
  a `grep -rl <prefix> scripts/*.py`, confirm no live process holds the files
  (`lsof`, `/proc/*/cwd`), and delete only the recognised prefix patterns.
- Re-run the suite in isolation after the cleanup. If it goes green, the
  classification is PRE_EXISTING/ENVIRONMENTAL with the cause named — not
  NEW_REGRESSION — and the fix belongs in a hygiene item, not in the milestone
  that tripped over it.

## 12. Clean up the fixtures you create, in the same milestone
A dry run on a DB copy is the right way to validate an executor, but each copy is
a full multi-hundred-MB file and they accumulate.

- Write dry-run scratch to one disposable directory and remove it when the run
  finishes, including on the failure path.
- After any milestone that made copies, check the disk share of the scratch
  directory you own before blaming the host.
- A test suite that creates a per-run copy and does not clean it will keep
  pushing the host over a safety threshold until the *next* milestone's suite
  fails for that reason. Report the recurrence as a separate hygiene item; do not
  fix the suite you do not own inside an unrelated milestone.
- **Cleanup is I/O like any other — never run it while a suite is reading.** Freeing
  several GB of fixtures in parallel with a regression battery made an unrelated
  suite fail with `sqlite3.OperationalError: disk I/O error`, which reads exactly
  like database corruption and is not. Sequence cleanup strictly before or after
  the run, never during it.
- When a suite fails on an I/O or resource error but you did not change the code it
  exercises, suspect your own concurrent disk activity FIRST, before blaming the
  code or the host. Prove it by re-running that one suite in isolation with nothing
  else touching the disk, and confirm integrity afterwards (`quick_check`). A clean
  isolated re-run plus an intact database makes the classification ENVIRONMENTAL /
  self-inflicted — and you must say *you* caused it rather than filing it as
  pre-existing.
- **Scale the audit to the whole class, not the reported symptom.** A brief naming
  "~18 leaking suites" was wrong by 8x: an AST sweep of every `mkdtemp` /
  `TemporaryDirectory` / `mkstemp` call site found 189 sites in 153 scripts and
  73 distinct prefixes. Count creation sites mechanically
  (`ast.walk` for `*.mkdtemp`, extracting the `prefix=` constant, including
  format-string heads like `"m23_bnd_%s_"` -> `m23_bnd_`) before quoting a number.
- **The suite that OWNS a tempdir must own its lifecycle.** A drop-in
  `owned_mkdtemp()` that writes the creating PID into the dir, registers `atexit`
  cleanup, and returns a `str` subclass is the smallest correct fix; replacing
  150+ call sites is mechanical and safe when every rewritten file is re-parsed
  with `ast.parse` before being written.
- **Reaping siblings by prefix alone is unsafe under parallel runs** — it deletes
  the fixture a concurrently-running suite is using. Reap only siblings whose
  recorded owner PID is no longer alive (`os.kill(pid, 0)`); ownerless dirs are
  reaped only past an age threshold. Prove it: a sibling stamped with a LIVE pid
  must survive another suite's reaping, and breaking that one guard must turn
  exactly that check red.
- Prove every lifecycle the contract claims: success, real `AssertionError` in a
  child process, raised exception, `SIGKILL`ed subprocess residue reaped by the
  next run, repeated execution, and parallel safety. A `SIGKILL` cannot run
  `atexit`, so residue needs the age/PID reaper — do not conclude "no leak" from
  one kill that happened to land after teardown.
- **Bulk-edit traps, each of which fails loudly if you run the suites:** a
  substring import check (`"mod" in src`) is always true once the rewritten CALL
  SITE contains that string, so the import is silently never added — use `ast`;
  an import hoisted after first use is a latent `NameError` in every affected
  file; an import hoisted ABOVE `from __future__ import annotations` is a
  `SyntaxError`. Verify import/usage ORDER across the whole tree, and parse
  every file after editing.
- **Sentinel proof for any bulk `/tmp` cleanup:** create unrelated sentinel dir
  and file first, verify `INTACT` after, then remove them yourself. Never broad
  `rm -rf /tmp/...`; resolve ownership from the AST, skip live-owner dirs, and
  leave unidentified content (including system dirs) alone and report it.
- When re-running a check after a bulk edit, remember background notifications
  replay a PRE-bulk snapshot: a delayed "exit=1" notification is not current
  state. Re-run before concluding anything.
- `database is locked` from a live service is a WRITABLE-state fact, not a
  failure of your code. Probe it before retrying — open a connection, issue
  `BEGIN IMMEDIATE`, roll it back — because retrying a doomed write burns turns
  and the answer is one line. When the live DB is locked and the assertion needs
  a write, run the same scenario against a copy of the file and say so in the
  report instead of forcing the write or stalling the milestone.
- The same `BEGIN IMMEDIATE` failure has two distinct causes that look alike
  from the traceback: a CONCURRENT writer holding the lock, and YOUR OWN open
  implicit transaction from an earlier statement. Distinguish by probing the lock
  first; only the second is yours to fix.

## 13. The shape the production caller actually passes is part of the contract

A renderer can be correct in isolation and still be broken in the app, because
the caller hands it a different container shape than the test does. Symptom: the
focused suite is fully green, the page still behaves as if every filter is
inactive.

- Read the seam, not just the callee: how the server/route builds the argument
  and what the function does with it. `urllib.parse.parse_qs` yields
  `{"live": ["1"]}`; a renderer's `qs.get("live") == "1"` is never true for a
  list, so the comparison silently never matches.
- The first pass of a test must reproduce the CALLER's shape, not a convenient
  one. A test that passes `{"live": "1"}` when production passes
  `{"live": ["1"]}` certifies a path that never runs.
- Any view helper that reads a container it did not build needs ONE shape-agnostic
  reader (`def qs_value(qs, key, default=None)` handling both dict and
  list/tuple values), shared by every call site.
- **Verify the unit fix against the live service, not just the suite.** The
  property under test — link renders as active, filter narrows the result set —
  is only proven by fetching the real page over HTTP with a real session. A
  75/75 unit pass coexisted with a live page that marked nothing active.
- Strip the URL fragment before parsing it in tests the way a browser would; the
  fragment never reaches the server, and comparing `"0#http" == "0"` manufactures
  a failure while `"0#http" == "1"` hides a real one.

## 14. Join a census on the same key the production code joins on

A read-only census that reports "missing prerequisite" for rows that clearly
exist is usually the census joining on the wrong key, not a data gap.

- Read the production call path and copy its identity expression exactly: a
  work-item builder resolving `plan.correlation_id -> exposure_correlations.dedup_key`
  cannot be re-implemented as "join on host". A correlation row whose `host`
  column is NULL is a perfectly valid exposure; host-join silently drops it and
  manufactures a false MISSING_PREREQUISITE.
- The tell is a NULL-able column standing in for the real key, and a
  suspiciously round split in the results (5 of 9 "missing").
- When the two disagree, the production expression wins and the census is
  rewritten. A census that misclassifies a legitimate decline as a recoverable
  one inverts the milestone's conclusion.

## 15. Falsify a signal before it earns weight in a contract

An apparently strong corroboration signal is a hypothesis until measured. This
one looked decisive and was worthless:

- `assets.last_seen` within 24h read as "recent change". Measured: for every
  target, fresh-24h count exactly equalled total asset count (35/35, 889/889) —
  the column is a recon-SWEEP timestamp that every asset gets refreshed by, so
  it carries no change information at all.
- Before a signal enters a contract, check whether it can distinguish the
  population that qualifies from one that must not: a value identical across
  every row cannot separate anything.
- Signals that are per-row constants (a sweep timestamp, a recomputed count, a
  "fresh" flag maintained by the loop that collects the data) are disqualified,
  and each exclusion gets a named regression test.

## 16. Prove the fix non-vacuously before believing it

After a fix goes green, revert the fix alone and confirm the new checks go red.
A check that passes both ways is not testing the defect.

- Revert the two changed lines (not the file), run the suite, and record the
  count. If the checks stay green, they are measuring something else and the
  PASS is void.
- Do the same for a newly added requirement: a test written after the code it
  describes passes on the first run by construction. Demonstrate the RED state.
- Prefer a temporary in-place revert of the changed lines over reconstructing
  "the old version", so the comparison isolates exactly what you claim to have
  fixed.
- The same proof applies to a milestone that adds a guard rather than a fix. If
  the new verdict is `NOT_JUSTIFIED` for every real row, the positive branch is
  only proven by a synthetic fixture; state that the fixture proves reachability,
  not that production can reach it. Reporting a green suite over a mechanism
  nothing exercises is how an unused module ships looking integrated.
- **A revert script that raises is not a revert.** An in-place edit driven by
  `str.replace`/`str.index` on a multi-line anchor silently produced an
  un-reverted file, and the "pristine" run that followed actually executed the
  change it was meant to disprove. The failure surfaced only via a background
  notification showing `ValueError` and `cp: cannot stat`. Guard every
  mechanical revert: assert the target text is gone, assert the replacement is
  present, re-parse, and diff against the backup — then verify the final file is
  byte-identical to the intended version before quoting any result. A conclusion
  drawn on an invalid experiment is worse than none: correct it in the report
  explicitly, naming what the original evidence failed to prove and what the
  valid re-run shows.

 ## 17. Prove a subsystem is LIVE by calling it, not by reading it

 A capability can look fully implemented, be invoked from the live path, and
 still have never executed once — because the storage it depends on was never
 created. Reading the call site proves nothing; only execution against production
 does.

 - **Call the function against the production handle and record the exception.**
 Reading `SELECT * FROM skills` inside a module proves the query text exists.
 Running `deterministic_retrieval(prod_conn)` proves the table does not.
 - **A defensive existence guard is a capability gap wearing the costume of
 robustness.** `skill_conn = c if _has_table(c, "skills") else None` is
 correct, careful code — and it silently turns the whole feature into a no-op
 for as long as the table is absent. When auditing, evaluate the guard in
 production (`_has_table(...)` -> `False`) and report the resulting `None` /
 disabled path as the finding. Robustness that quietly no-ops must be made
 visible in telemetry, or it reads as a working feature forever.
 - **Sub-systems routinely share one name.** An audit found four distinct things
 called "skill": platform agent skills (bundled markdown, genuinely live), a
 canonical Skill Factory (code present, backing tables absent, never run), a
 legacy table pair (schema present, zero rows), and generated markdown
 artifacts (2 files, one of them a self-declared synthetic fixture). Enumerate
 every namespace before counting any of them, and label which are live.
 - **"Live code path" and "live data path" are different claims.** The chain may
 be real for its first hops and dead at the fourth. Report the exact hop where
 it ends, not a verdict on the whole chain.
 - **Zero is a measurement, not a gap in your work.** A subsystem with 0 rows
 across every table is a finding to report plainly; do not manufacture
 instances to make the audit look productive, and do not assume an empty table
 is an error in your census before confirming the table is meant to exist.

 ## 18. Attribute a live-DB change only after enumerating every writer

 Naming the wrong process as the cause of byte drift sends the investigation at
 the wrong subsystem, and the wrong name gets published.

 - Enumerate all holders before attributing: walk `/proc/*/fd` for symlinks
 containing the DB filename and print each pid with its cmdline. A cause
 assigned from "the processes I already suspected" is a guess.
 - **A service whose name says read-only may still hold a write handle.** A
 presentation-layer Web UI process held `hermes.db-wal` open continuously and
 was invisible to any search for "the daemon" or "the research job".
 - Prefer a service-unit inventory (`systemctl --user list-units`) over guessing
 which long-lived processes exist; units are the ground truth for what is
 *supposed* to be running.
 - Correct an already-published attribution the same way you correct any other
 bad claim (§6): state what the earlier claim got wrong, not just the new
 answer.

 ## 19. Verify the brief's premise before auditing inside it

 Briefs assert facts about the system ("at project start a set of skills was
 imported from repository X"). The premise may be unsupported.

 - Search for the asserted provenance with the mechanism that would have left a
 trace — a URL regex across all reports, code, state and config; a manifest;
 an install record. Absence across every one of those is a real answer.
 - When the premise cannot be substantiated, report it as `UNKNOWN` with the
 searches listed. Never infer the repository from what the system resembles,
 and never soften it into a guess.
 - A brief that names a specific count ("~18 suites") is a premise too — measure
   it (§12) rather than inheriting the number.
 - **Verify the brief's premises recursively, including its own citations.** A
   milestone restating 15 seeded items "with PortSwigger as a source" is asserting
   those sources resolve. Batch a status-code check over every stored locator
   (`curl -o /dev/null -w '%{http_code}' -L`) and read the failures: vendor docs
   get reorganised and stale paths rot to 404 while every content check still
   passes informally. A meaningful fraction of "high quality provenance" was
   dead links.
 - **A content-extractor's "not found" is not evidence a URL is dead.** It can be
   a rate limit or a keyless-backend error. Confirm with a raw HTTP status code
   before calling a citation broken, and search for the current canonical path
   rather than guessing a replacement — then verify the replacement live BEFORE
   it goes in.

## 20. A permissive gate is proven by its REJECTS, not its accepts

A gate that passes everything under review has not been tested. When you tune a
validation/safety gate — especially by loosening it to stop rejecting sound
content — hold two corpora and re-run BOTH after every single change:

- **DEGENERATE**: inputs that must be rejected (shallow filler, generic
  instructions, good content with no provenance, content that discusses one
  concept while hypothesising about another).
- **ADVERSARIAL**: instructions that must be blocked (exploit, destructive,
  credential, autonomous-confirmation phrasings).

Loosening a forbidden-vocabulary gate produces false positives on SAFE text, and
the trap is matching a term without regard to how it is used:

- **Noun usage is not an instruction.** `a read-modify-write operation` is a
  concurrency mechanism, `a generic shell` is UI chrome, `a WAF/proxy layer in
  front of the application` is a false-positive indicator. Match destructive and
  exploit terms only in *action position* (`delete the record`,
  `use a payload to test`, `bypass the auth check`, `submit a DELETE`).
- **Scope negation to the ENCLOSING CLAUSE** (delimit on `.;,()|`), not a fixed
  character window. A window over-reaches — clearing unsafe text that merely sits
  near a negation — and under-reaches at the same time, missing `no active
  parameter-pollution probing is performed` when the negation falls just outside
  it.
- **Split on clause delimiters and SKIP negated clauses entirely; do not narrow
  the window instead.** Narrowing leaves a second judgement to get wrong. A
  clause whose leading verb marks it as a prohibition (`no X is ever sent`, `no
  connection is opened`, `no step is replayed`) states a restriction and must
  survive; the same clause set judged on verbs alone is what makes a guard
  reject your own correct content. This is the same clause split you already use
  for action-position matching — do it once and use it for both.
- **Two checks are needed and they are not interchangeable:** an action-position
  pattern (send / issue / repeat / attempt) AND a prohibited-act term list
  (exfiltrate, brute force, sqlmap, read the api key). `exfiltrate the records`
  is a request whatever verb precedes it, so a verb-gated rule alone silently
  passes it.
- **A new guard needs a MUST-BE-KEPT corpus, not only an adversarial one.** Take
  the real, already-approved content the gate will see and assert it survives.
  A guard that is only exercised against attacks will look right and will reject
  correct text; real security content is dense with prohibitions, which is
  exactly what a naive verb match misreads.
- **Past-tense passive capture is evidence review, not theft.**
  `passive inspection of already-captured token headers` must not match a
  credential-theft rule; guard the verb with a negative lookbehind for
  `already-`/`previously-`/`stored-`.
- **A minimum-LENGTH heuristic on required content fields is the wrong tool.** It
  rejects legitimate terse domain terms (`user_id`, `object id`) and breaks
  previously-green suites. Judge whether the text says *anything*, not how long
  it is. When such a rule breaks an existing green suite, the rule is wrong, not
  the suites.
- **Anchored-concept beats pairwise word overlap** for "internal consistency".
  Overlap of arbitrary content words tests vocabulary, not coherence; require the
  family's canonical concept term to appear on both sides of the reasoning chain.

Tuning a gate this way is exactly where escapes appear: relaxing the safety list
to fix false positives let real escapes through, and only the adversarial corpus
caught them. Report the reject counts, never just the accept count.

Corollary for review/gate work: a rule that fires on well-written content is
itself evidence of a defect. Before concluding that a subject under review is
bad, confirm the failing rule is wrong — dump the exact clause and the exact
match, and fix the rule.

## 21. Never hardcode an absolute production STRUCTURAL count

A test asserting `COUNT(*) FROM sqlite_master == 198` breaks on every legitimate
additive migration, and the suite then reads as a corruption alarm.

- Assert the exact known-additive SET (`added <= {"users", "skills", ...}`) plus
  per-object invariants (each protected table present, each row count above its
  baseline), never a total.
- This is a retarget in the legitimate sense (§7) and is usually STRONGER than the
  count it replaces, because it also catches a table that is quietly removed.
- If a count must be quoted in a report, quote the delta you caused.

## 22. An audit record that reports counters is evidence, not decoration

- A metrics/run-record writer commonly **silently defaults any unrecognised key
  to 0**. Passing a plausible-but-unknown key name produces a record claiming
  "0 validated" while N rows exist. Read the store's canonical counter-key map
  and use those exact names, then read the persisted row back to confirm.
- `cannot start a transaction within a transaction` when a finalizer issues
  `BEGIN IMMEDIATE` means the caller left an implicit transaction open — commit
  first. It also means that finalizer had **never run in production before**;
  running the whole pipeline end to end once is the only proof, and code that
  merely reads correctly is not a substitute (§17).
- Terminal rows are deliberately immutable. When an early run recorded a wrong
  value, do not rewrite it: emit a corrected run under a new id and say so in the
  report. Preserving the error is what makes the ledger trustworthy.
- When a versioned/immutable store holds the content, apply every correction as a
  NEW VERSION. Never overwrite: the prior version is the evidence of what was
  believed when.

## 23. A diagnostic probe is a write until proven otherwise

A verification step performed to CONFIRM something is still an action against
production, and a "read-only" intent does not make it one.

- **Passing an override is not proof of no side effect.** Constructing a helper
  with `store=None` to avoid persisting can be silently defeated by a fallback
  inside it: `if self._store is not None: return self._store; import store;
  return store` resolves to the global handle and writes anyway. Read the
  accessor before trusting the argument you passed.
- **Diff row counts across the probe and attribute every delta.** A count that
  moved between two of your own checks is yours, even when you never issued a
  write. Identify the row by timestamp/run id and say so.
- Never report `PRODUCTION MUTATION: NONE` while a row you created sits in the
  table. When a brief mandated read-only and the probe wrote anyway, the honest
  headline is the correction itself, stated first, with the mechanism — not a
  footnote under a list of findings.
- The same rule covers any "verify it is inert" step: assert the absence of the
  effect from the artifact, not from the signature of the call.
- **A `mode=ro` handle cannot run a production entry point that persists
  anything.** Executing the real function against a read-only connection fails
  with `attempt to write a readonly database` the moment it records its
  decision. That is the handle being correct, not the code being broken. Use a
  writable connection for a live end-to-end proof, and then count every record it
  wrote as your own delta (first rule above) — never report a probe as read-only
  after it has written.

## 24. Reachability, consumption, and effectiveness are three claims

A capability milestone ends with a component made selectable. The next milestone
is asked whether that mattered, and the three claims are not interchangeable.

- Evidence that a branch is reachable, that a record was consumed, and that a
  case was created with a provider decision are all the SAME claim: reachability.
  None of them is evidence of value.
- The measure that matters is the supporting-outcome rate for the work the
  capability is bound to. A rising route/consumption count against a flat zero
  in supporting outcomes is not progress, and reporting it as such is the
  overfitting failure the milestone exists to prevent.
- A rising share on the new path is not automatically better. If the new routes
  are drawing work onto units whose governing premise is already contradicted in
  persisted data, the increase is wasted work. Check the outcome classification
  of the work the new routes actually attracted.
- A small sample gets `INSUFFICIENT_SAMPLE` and the required count, stated in the
  first screen. It is a valid deliverable, not a shortfall. Distinguish the two
  verdicts the operator needs: system healthy enough to keep running, and enough
  evidence to advance the program's claims. They can legitimately disagree.
- **A target count can be unreachable at the system's real cadence, and that is a
  finding, not a failure of patience.** Measure the interval between natural runs
  (read the job table's own history) and state the arithmetic: a target of 10 at a
  ~3h03m cadence needs ~6 more hours, so the window could not reach it. Report
  `SAMPLE_INSUFFICIENT` with the reached count and the hours required. Never reset
  a timer, inject a signal, or manufacture a job to close the gap.
- **Historical records of the same class count toward the sample** when the brief
  says "natural" rather than "new since baseline" — they came from normal
  execution. Report the EFFECTIVE independent size beside the raw count: 8 samples
  drawn from 3 host conditions is 3 observations, and quoting only "8" is the
  overstatement. A cycle that re-decides existing cases yields decisions but no
  NEW qualifying samples — count the new lineage, not the decisions.
- **Duplicate units inflate every count you quote.** Before reporting a sample
  size, group by host/correlation and report the distinct-unit count next to it.
- Observation must not change what it observes: freeze the semantic fingerprint,
  attribute every delta, and prove the registry or config the milestone claims to
  leave alone is unchanged. Do not modify a definition, threshold, or policy on
  the strength of one unflattering observation.
- Do not invoke a fallback or metered provider to prove it works. If the primary
  resolved every decision, record `NOT_USED` with the reason and cite the earlier
  bounded validation.

### Closing the gap that §24 just opened

§24 is about measuring a capability. The next milestone after it is usually asked
to WIRE that capability in, and that milestone has a trap §24 does not name.

- **A suite written to freeze a measured finding is a ratchet, and the next
  milestone will have to break it.** A calibration suite asserting "42/42 plans
  are byte-identical with and without a Skill" is correct when written and
  becomes a blocker when the behaviour is fixed on purpose. Invert its
  assertions in the same edit, keep a `SUPERSEDED HISTORY` note naming what it
  used to assert, and say in the report that the suite was rewritten and why.
  Editing a test to match new behaviour without disclosing it is indistinguishable
  from weakening a test — the disclosure is what separates them.
- **`BASE != GUIDED` proves CONTENT INTEGRATION, not effectiveness. Report the two
  as separate verdicts** (`INTEGRATION: PROVEN` / `EFFECTIVENESS:
  NOT_YET_MEASURED`) so the second cannot be read as carried by the first.
  A changed plan is a precondition for a changed outcome, never a substitute.
- **When you have just closed a content gap, the right next action is to re-run
  the effectiveness observation unchanged** — the question it answers has changed
  from "is this wired at all" to "does the new shape move the outcome
  distribution". Expect the answer to be structural rather than statistical, and
  check the CONSUMER's decision function before the sample count: if it never
  reads the field you just wired, no sample size will ever move the outcome.
  That is a `NO_MEASURED_EFFECT` with a named mechanism, which is a stronger
  deliverable than a bigger sample.

### Merge into an existing validated artifact, do not replace it

The smallest correct way to make stored content affect behaviour is a bridge
layer, not a rewrite of the consumer.

- **Run the existing validators AFTER the merge, never before.** Merging first
  means the pre-existing safety, scope and rate guards judge the merged result,
  so a data source can only ever be rejected or trimmed by them — it can never
  relax them. Validating first means the guards never see the new content at all.
- **Bind the consumer's own validator into the bridge; do not reimplement it.** A
  duplicate pattern list is a second, weaker copy of a safety rule that will drift
  from the first. Take it as a parameter (a one-line `bind_safety_validator()`
  at import time) so a Skill is judged by exactly the rules the content it
  augments is judged by.
- **State the precedence as a numbered list and honour it in code.** Scope/safety
  policy > the safety guard > hard execution constraints > explicit signal
  evidence > the new content > generic fallback. Then ASSERT the protected levels
  are byte-identical with and without the new content across the real population
  — that is what proves a data source cannot widen scope or loosen a limit, and it
  is a stronger claim than "the code looks careful".
- **A validator that returns a WHITELISTED object silently drops the fields you
  added.** If `validate_x()` returns `{k: raw[k] for k in keys}`, any new key you
  merge in is gone after the round-trip and the feature reads as integrated while
  contributing nothing. Carry what the whitelist drops in the record that
  survives (provenance, lineage), and prove survival with a round-trip assertion
  rather than by inspecting the pre-validation dict.
- **Guidance text is data, never a command.** Parse list-typed fields into the
  planner's existing contract and let the existing validators judge them. Do not
  introduce an execution path for a new text field, and do not add an LLM call to
  translate stored text.
- **Select ONE source deterministically** (eligible-first, then signal-text
  overlap, then family, then confidence, then id) rather than blending several.
  A blend is unreviewable, and the plan ends up citing a source that shaped only
  part of it.
- **Prove the bridge non-vacuously by disabling it**, and expect a broad failure
  count — a bridge test that still passes with the bridge off is measuring the
  base literals. Restore the file byte-for-byte afterwards and re-run.

For the capture protocol, lineage ordering, outcome classification, and the
report shape, see `references/effectiveness-observation.md`.

## 25. An "unavailable" alert is a claim about a past event

A status persisted on a case is a record of one decision at one timestamp, and
probing the live system usually contradicts it. Treat the alert as a hypothesis
with a specific mechanism, and resolve it by measurement rather than by reading
more code in the direction you already suspect.

- Read the REASON field beside the status; the status is generated at many call
  sites and the reason names the one that fired.
- One live probe settles provider health. A healthy provider plus a persisted
  `UNAVAILABLE` reframes the work as a consumer bug — check how the consumer
  handles the provider's success states (an idempotency/cache hit that returns a
  sentinel with an empty payload is the classic case) before touching config.
- A service's environment is not yours. When a call succeeds in your shell and
  fails for the daemon, diff the live process env against the unit's
  `EnvironmentFile` lines, resolve the credential's actual source (a runtime
  resolver may read an indirectly-named variable), and reproduce the failure by
  removing exactly that one variable.
- **A finding dated before your change is not evidence about your change.** A
  scary traceback sitting in a long-lived log may predate the work by days;
  check the log file's mtime and the entry's own timestamp before adopting it as
  an explanation. Confirm the unit's exit status and its last stdout line before
  deciding it crashed: a `status=0/SUCCESS` unit that stopped on request is a
  clean stop, not a failure, and the two demand opposite responses.
- See `hermes-provider-outage-diagnosis` for the full triage, including the
  routing analysis for subsystems that appear dormant.

### A downstream failure class is a claim about the CLASSIFIER, not the subject

The layer above applies one level down, and the level that catches you is a
labelled error class. `MISSING_CHOICES`, `MISSING_FIELD`, `EMPTY_RESPONSE` and
friends are produced by a parser; they describe what a decoder could not find.
Repeating one back to the operator as the root cause launders an unverified
label into a finding — and the two causes it can stand for need different fixes
in different files.

- A parse-layer class is consistent with BOTH "the model returned nothing" and
  "the model returned a perfect answer that the decoder could not finish
  reading". Capture the raw payload and find out which, before reporting either.
  The usual mechanism is trailing bytes the producer appended after a complete
  value (a stream terminator on a non-streaming response), which a strict
  whole-body decode turns into a "missing field" error.
- Cross-check with a validator applied to the INNER decoded object, not the
  envelope. If that passes with zero errors while the pipeline reports failure,
  the content is fine and the defect is in the parse layer — say that, and name
  the file the fix belongs in.
- Probe size and scope hypotheses with a ladder (real / half / 2x), not one
  extreme sample, and print the real input-length distribution before accepting
  a brief's asserted scale. Non-monotonic latency or one identical error at
  every rung disproves a volume theory that a single large test would appear to
  support.
- When a measurement is unavailable (an empty `usage` object means tok/s is not
  computable), name the missing field. Never back into the number from wall time
  and a guessed output size.
- Recipe, discrimination table, and the ladder: `hermes-provider-outage-diagnosis`
  -> `references/envelope-and-size-probes.md`.

## 26. A keyword gate that never matches is a silent no-op

A routing or evidence gate can be green, syntactically valid, and match nothing.
The mechanism hides because a suite that only checks the accepting path passes
regardless. Verify by distribution over the real population, not by suite status.

- **`\b` does not split on `_` or `-`.** `\buser\b` never matches `user_id`,
  `api_key` or `owner-id` — the most common real identifiers, so a keyword gate
  silently misses exactly the values it was written for. Use an explicit
  separator class `[\s_\-./:]+`.
- **A separator class then misses position 0.** `re.search(r"[\s_]+user[\s_]")`
  needs a character *before* the first token, so a single-element list, or the
  first item of a joined string, never matches. Use `(?:^|SEP)` so the
  anchor-at-start alternation is part of the pattern rather than an assumption.
- **The mirror failure is a gate that matches the wrong population — and a
  synonym list is the usual cause.** An acceptance gate keyed on a hardcoded list
  of hedge phrases ("cannot confirm", "does not prove", …) rejects a model that
  hedges differently however rigorously, and parks those rows in a review state
  nothing ever drains. Symptom: a funnel counter stuck at 0 while the rows the
  counter counts DO exist in a non-accepting state. The tell is the bias — the
  test asks "does the text contain a listed hedge?" instead of "does the text
  overclaim?", so the default verdict is reject and unlisted-but-valid phrasing
  is indistinguishable from bad content. Invert the test so the default is
  accept and only an explicit overclaim is escalated.
- **Walk the whole chain, not the counter that is zero.** A stage counter reading
  0 is a symptom; the row it counts may sit in a neighbouring state (a review
  state, a quarantine state) that is itself the finding. Enumerate the
  state distribution of the target table and read the populated state before
  concluding the stage never ran. Check too whether a review state has any
  drain — no verdict column and no queued alert means a row parked there is
  permanent, and that unreachability is the real defect.
- **Never match against `repr()` of a container.** Stringifying a list yields
  `"['user_id', 'owner_id']"`, so the keyword scan runs against a Python
  literal, not the values. Join members explicitly. The tell: only multi-element
  cases fail, because `str(['user_id'])` still contains the token by accident —
  so a one-item fixture certifies a path that never runs.
- Fixing the above can un-break an unrelated assertion in the same pattern; when
  a trailing `(?![a-z0-9])`-style guard exists, the new pattern must preserve it
  or the next two checks fail. Re-run the full focused suite, not the one check.
- When routing is widened to make a previously-dormant branch reachable, measure
  the new distribution over the **whole real population** and check the
  fallback's share actually dropped. Unchanged output means the new rules matched
  nothing.

## 27. Architecture & Gate Decision Discipline

When a milestone evaluates whether to introduce or build an architectural layer:
- **Do not default to BUILD:** The decision must strictly satisfy all gates (including non-duplication and measurable evidence impact). If downstream consumers (e.g. `classify()`, outcome learners) cannot consume or act on the new signals, the layer produces dead data paths and must be evaluated as `DEFER` or `DO_NOT_BUILD`.
- **Offline validation of decision boundaries:** Even in a design-only milestone, write an explicit test fixture (e.g. `scripts/test_*_decision.py`) that tests all gate conditions (hostile rejection, scope expansion, rate expansion, fail-closed handling, human gate invariants) so the decision boundaries are verified by executable assertions rather than prose.
- **Run the full regression battery cleanly:** Re-verify `day6_battery.sh` alone to prove `PRODUCTION_MUTATION: NONE` via identical DB checksums and row counts.

## 28. Disk code vs running daemon / service process divergence

Python binds modules at process startup and does not auto-reload modified files. Tests executed in fresh test processes import the newest code on disk by construction, while a running background daemon or web service continues serving the memory state from when it was started.

- **Never assume an on-disk fix is what the running service is serving.** If a user reports a bug that already appears fixed in source code or in standalone test scripts, inspect the running service PID, start time (`ps -eo pid,lstart,cmd`), and whether it needs a reload/restart (`systemctl --user restart <service>`).
- **Probe the live HTTP port / socket directly before writing code.** Compare `curl` output against fresh module rendering (`python3 -c "import mod..."`). If the on-disk renderer produces the new behavior but `curl http://...` returns the old markup, the root cause is a stale running process, not broken or missing code.
- **Differentiate test-runner environment from production daemon environment.** A test suite importing modules directly tests the filesystem; a live integration check testing against `http://127.0.0.1:<port>` tests the process. When verifying fixes reported in production, always probe the live endpoint.
- Investigate bug reproduction reports across both code and process state.** When the user reports an issue (e.g. malformed date or missing menu) and points to a suspected code line that actually looks correct in disk code, check both the algorithm logic AND whether the issue was reproduced against a stale long-running service. Do not blindly rewrite working on-disk algorithms before checking what the live process is executing.

## 29. An auto-deploy gate needs the discipline above, applied to ITSELF

A gate that classifies, tests, restarts and reverts has the same failure modes as
the milestone it replaces, and they surface as automation defects. Full procedure,
hard-rule design, negative-test discipline, and the daemon-contention re-run in
`hermes-test-gated-autodeploy`.

- **Classify by path and fail closed: a file on neither list is high-risk.** An
  open whitelist silently routes a newly created file to the cheap tier because
  nobody remembered to register it.
- **Prove the gate BLOCKS before trusting it to deploy.** A negative test that
  breaks a dead function, or renames a key passed to a defensive `.get()`, leaves
  every suite green and the gate ships the break. Break the executed path — the
  escaper every render calls — and confirm the suite goes red standalone first.
- **A test-only integrity assertion can fail from daemon contention, and the fix
  is a re-run with the writer `SIGSTOP`ped, never a silent pass.** Pausing is
  reversible and does not stop the unit; if the re-run is still red the commit is
  genuinely at fault.
- **A hard-rule hit must not auto-revert.** Reverting a security-relevant change
  is itself a decision; leave the commit in place, deploy nothing, and hand the
  diff to the operator. Reserve auto-revert for test failures.
- **Read the gate's own logged input before theorising about a wrong
  classification.** When a tier comes out unexpected, diff the commit
  (`git show --name-status`) against the change set the gate actually consumed,
  side by side, before forming a cause. A single-ref `git diff <sha>^` is the
  WORKING TREE, so a background daemon's writes fold in and fail-closed
  classification turns that into a spurious high-risk block. Blaming revert
  history (a guess) instead cost several turns and buried the real defect; a
  correct cause is found by the two-form diff comparison in one call.
- **Risk is the path mask, not git's status code.** Discard `A`/`M`/`R`/`C`
  entirely: a re-added or renamed file is the same risk as a modified one, and a
  rename is classified on its NEW path. See `hermes-test-gated-autodeploy`.
- **A wall-clock assertion is a flake, not a verdict** — but diagnose it before
  exempting it. Locate the assertion and check what it measures: a latency ratio
  around real work is load-sensitive, a ratio against a stub is a real
  regression. Re-run a bounded number of times, never a silent pass.

 For the full step order, the live-vs-theoretical decision table, and the
 read-only connection recipe, see `references/capability-audit.md`. The
 context-vs-execution retrieval split, the human-approval boundary, and the
 review-gate shape live in the `hermes-skill-governance` skill.

## 30. A recurring alert is three different writes, and only one is reversible

An operator told to "approve them all" about a pending backlog is issuing one
instruction for at least three semantically distinct writes. Resolve the vocabulary
BEFORE touching production state, or you will fabricate an attestation.

- **Notification acknowledgement** (set `status=ACKNOWLEDGED` + `acked_at`) clears a
  recurring "N unacknowledged" banner and nothing else: the finding stays, the prior
  value is restorable, and it makes no claim about validity. This is the reversible one.
- **Confirmation** asserts a human judged the artefact real. Never synthesise it from a
  bulk instruction over rows that carry no verdict — that is fabricated attestation,
  and it is the failure a "human confirms all findings" rule exists to prevent.
- **Closing a review queue entry** (a case parked on a judgement state) is a third
  write against a separate table, usually not drained by the first at all.
- **Recurring banners are not a stable backlog.** Count the population at the moment of
  the request and again after the write: a live producer inserts rows during the work,
  so "unacknowledged went from N to 0" can be true and still under-report what is queued.
  Quote both counts and the time between them.
- **A lifecycle guard on one column is not a guard on the row.** A write path that skips
  the `status` update for already-disposed rows still updates confidence/severity/verdict
  columns unconditionally. Post-run, query the status x verdict cross-tab — split states
  are the evidence the guard's scope is narrower than its name suggests.
- **Present the decision list grouped by underlying signal, never as N rows** (§24's
  duplicate-unit rule applied to a disposition queue), and carry the evidence-quality
  flags that make a blind approve meaningless: a truncated basis and a conflict count
  above zero mean contradictory evidence, not merely thin evidence.

For the HERMES-specific queues, tables and the ack-then-reclassify ordering, see
`references/human-disposition.md`; `scripts/human_review_digest.py` is the
read-only grouped triage to run first (it also separates infrastructure-shaped
entries from real judgement calls).

## 31. A recompute that never re-reads the source is a column rewrite

A script whose job is to re-derive a verdict from archived evidence can silently fall
back to recomputing from the stored verdict columns, still print plausible output, and
still persist. The tell is a counter in its own result that is uniformly zero/false.

- Run the tool with its dry-run/JSON mode first and read that counter BEFORE persisting.
  All-false on every row means the evidence lookup found nothing and the output is a
  function of the existing columns, not a re-analysis.
- The usual mechanism is a key-shape mismatch between two tables that should join on a
  name (glob-suffixed scope string in one, bare slug in the other) rather than a value
  mismatch — so it degrades silently instead of erroring.
- Report it as a limitation of the run, not a clean result, even when the persisted
  outcome looks right. "The verdict is unchanged" is not the same claim as "the verdict
  was re-derived and came out the same".

## 32. An injected dependency bypasses the code path under test

The single most expensive false-green in this project: a probe lane wrapped
`crawler.fetch_one` in its own local closure (which owned the run's rate limiter and
health objects) and passed that closure into `run()`. Every test called
`run(fetch=fake)`, so the closure was REPLACED in every test and never executed once.
58 tests passed while every production sweep died instantly.

- **A test double for a dependency does not exercise the wrapper around it.** When
the component under test adapts a dependency through an internal closure, adapter,
method, or factory, injecting the dependency skips exactly that code. Exercise the
real one by patching the dependency AT ITS SOURCE (`crawler.fetch_one = fake`) and
calling the entry point with no injection at all.
- Coverage is not proof of execution. Ask of every green suite: "which line of the
defect could have run here?" If the answer is none, the suite is measuring the
fixture.
- Test the lifecycle, not just the verdict: assert the collaborator was actually
CONSTRUCTED and passed (limiter is not None, health is not None), and that a full
sweep satisfies its own accounting invariant (`probed == written == ledger lines ==
rows`).
- Add a static grep to the suite over the source files for the shape that caused it,
so the same defect cannot return silently. Skip comment lines in that grep — an
explanatory comment naming the bad pattern will otherwise trip your own guard.
- Related: an `if not container:` guard is a latent failure whenever ANY caller
pre-populates a different key first. Guard per key (`if "x" not in container:`), and
never make initialisation depend on the container being entirely empty.

## 33. When an aggregate counter disagrees with per-row state, read the rows

A lane reported `resolvable: 0` against 15 candidates while its own telemetry said
`resolved: 52` and every candidate carried a populated `page_url`. The aggregate was
the artifact: it recomputed resolution with a hand-built empty lookup table instead
of reading the field the pipeline had already filled.

- Before believing a count you just produced, find a second, independently populated
  source for the same fact — a field on the row, a module-level counter, a stored
  summary — and reconcile. Disagreement means one of the two is measuring something
  else, and the cheap one is usually yours.
- Enumerate the candidate's real keys (`sorted(row.keys())`) before assuming what the
  selector returns. A field the selector already provides (`resolved`, `probe_url`)
  is the authority; rebuilding it from raw tables is how a measurement drifts from
  the pipeline it claims to describe.
- Read the production function signatures before calling them (`build_page_index(c,
  rows)` takes a cursor and the rows; `_get_candidates(c)` takes a cursor). A guard
  clause that swallows the resulting `TypeError` as "unresolved" turns a call-shape
  mistake into a confident zero.
- The same rule settles a deployment question: the JOB TABLE's own status is the
  authoritative record of whether a job ran and how it ended. A gate LOG's last
  lines are a different artifact and may describe a superseded commit; before
  reporting `BLOCKED`/`NOT_DEPLOYED`, read the job's status/error row AND confirm the
  commit is still reachable (`git merge-base --is-ancestor <sha> HEAD`, §6).

## 34. A hard-rule block on your own diff can be a diff-SHAPE artifact

The gate's rules read text, so a pure re-indentation is indistinguishable from a
deletion. Re-indenting a guarded block (wrapping a loop that contains a scope check
in `try/finally` to hold one connection) made the guard appear as a REMOVED line and
tripped "removes a safety/auth guard".

- Fix the SHAPE, do not clear the rule: keep the original block at its original
  indentation and move the new work into a small helper that owns its own resource.
  A per-item open/close costs nothing at this request rate and removes the artifact.
- Verify the claim mechanically before committing: regex the added lines of
  `git diff <base> -- <files>` and require 0 hits, and separately assert that NO
  removed line mentions a guard keyword at all. Both checks are one call and they
  distinguish a real removal from an indentation change.
- Never reach for `--allow-manual` to get past it, and never weaken the rule.

## 35. A full-file rewrite from a file read in a CONVERSATION is a guess

Regenerating a production module from a summary of it (rather than a fresh read)
produces a plausible file that is silently missing helpers the module already had.
The refusal is correct: a stale read is not a read.

- For a write you did not make and cannot verify, prefer a targeted edit
  (`patch` old_string/new_string) over a whole-file `write_file`, so unreviewed
  content is never carried along or dropped.
- A backup you make by COPYING the current file to a sibling is worthless if it was
  already a broken copy — a whole-file rewrite can leave the copy with the same
  truncation. When a rewrite is suspected, reconstruct only the missing region and
  verify the pieces you did not author are byte-identical besides your edit.
- Corollary for edits to a file that has moved on: if the tool reports the file was
  modified since your last read, that is a signal another writer is active — re-read,
  merge, and specify exactly what you changed.

## 36. A file written without its owning process is not deployed

Python binds modules at process start, so a fix committed AFTER the service's last
restart is not the code the service is running. This bit a lane whose commit landed
four minutes after the daemon's start time, leaving the running process on the older
code.

- Compare the commit time against the unit's `systemctl --user show <svc> -p
  ExecMainStartTimestamp --value` before describing a change as live.
- The operational tell that a change is real and not merely written: the production
  artifact it produces. A sweep that had been PENDING for minutes and then runs to
  completion is evidence; a green suite is not.
- Report state, not intent: "committed and deployed" requires the gate's DEPLOYED
  line AND an active unit with `NRestarts=0`, and the daemon's start time newer than
  the commit.

For the lane-level recipe — exercising an injected dependency's real path, proving a
lane INERT vs WIRED vs RAN, measuring an acceptance count against production data, and
reading the arming flag from both the unit and the live process — see
`references/probe-lane-verification.md`. For clearing a genuine added-execution
hard-rule block on the operator's authority (the review record, the pass, and the
separate arming decision), see `references/hard-rule-manual-pass.md`.

## 37. Another writer on the same tree

A production repo can have a second agent committing to the same files. The failure is
silent: your edit is replaced on disk, `git commit` reports "nothing to commit", and the
work LOOKS landed because HEAD moved to a message you never wrote.

- **`git commit` reporting "no changes added" is a red flag, not a no-op.** Immediately
  compare `git log -1 --format='%H%n%an <%ae>%n%B'` against the message you wrote. A
  subject line that is not yours means a concurrent writer beat you to that file.
- Confirm silently-superseded vs lost: if the file is clean and holds an equivalent
  change, your work is superseded — say so and name the commit. Do not re-apply it and
  do not "improve" theirs.
- Before writing, check `ps -eo pid,etimes,args` for other agent processes, and
  `git log --format='%h %ad %s' --date=format:'%H:%M'` for commits you did not author.
  A commit landing minutes after yours, touching a file you just edited, is the signal.
- Attribution rules do not transfer. If a lane the operator reserved for one specific
  implementer was written by a different tool, REPORT the red-line breach with the
  commit id — do not silently adopt or repair it.
- **A file you wrote from a paste still gives YOU the live-env obligation.** The paste
  is the operator's; the file on disk is yours. Before calling the change live, re-read
  the running process yourself, and verify the paste's own premise — which flags are set,
  hence what becomes reachable — against the live service instead of inheriting its
  claim (§41).

## 38. Another writer's module is not verified by its own tests

When a peer implements lanes in the same repo, their test files are claims, not evidence.

- Run the peer's suites yourself with the repo's own interpreter before counting their
  work as done. First confirm the suite generates no traffic
  (`grep -nE "urlopen|requests\.|http\.client|subprocess\.run" <suite>`) so running it is
  safe by inspection, then execute it and quote its own final line.
- Verify the acceptance criteria no unit test can cover: is the module actually
  REACHABLE (imported by the planner/cycle, not only by its own test), does its arming
  flag appear in the unit, does a binary it needs exist (`command -v <tool>`). A lane
  that is unwired and unarmed is inert — "implemented" and "active" are different
  verdicts, and the operator's question is usually about the second.
- Read their gate state too: a commit can exist in git while its gate result is
  `BLOCKED`, and the running daemon may predate it (§36).

## 39b. A negative reachability verdict must name scheme, port and vantage

"host is dead" / "no response" / "status 0" is a statement about the probe, not
about the host. Three separate incidents in one project came from writing the
probe's limitation down as a property of the target:

- `eucservices.dell.com` was recorded `NO-RESPONSE` after an HTTPS-only test. The
  host was alive the entire time on 8443 and 80 (a live Plesk panel) - the verdict
  was "the wrong port", not "the wrong host".
- `avx.dell.com` and `ak-confluence*.gtie.dell.com` were recorded dead. They
  resolve fine; the actual error was an SSL hostname mismatch.
- `grax.ins.dell.com` timed out from one host. A public prober also returned `522`
  (upstream connection timeout), which is what turned a weak claim into a strong
  one: unreachable from the public internet, not "blocked from my vantage".

Rule: a negative reachability verdict must state (a) which scheme(s) were tried,
(b) which port(s) were tried, and (c) whether a second independent vantage
confirmed it. One vantage only => write `UNREACHABLE-FROM-<vantage>`, never
"closed". Why a host is unreachable is usually a separate, unproven question -
keep it in a sentence that says the evidence cannot decide between the readings
(offline now vs closed since the crawl). A 522-timeout from a public prober counts
as a second vantage; a 200 from one while our probe times out invalidates the
negative verdict entirely.

## 39c. A text assertion must not span markdown markup

`has("host was then retested")` fails when the note renders the name as
`` `host` `` **was then retested** - the markup characters break the substring, and
whitespace normalization (`" ".join(f.split())`) does not remove backticks or
asterisks. Assert on a span lying inside one run of prose, or strip markdown
markers in the flattener. When an assertion fails immediately after you added the
exact sentence it targets, suspect the markup boundary before the content.

**This fired SIX times in one round** - always the same way: a sentence was written
normally, the assertion targeted a span that happened to include `**bold**` or
`` `code` ``, and the check failed while the text was visibly present. Two habits
prevent it:

1. **Write assertions against short spans that carry no formatting.** Assert on the
   distinctive nouns and verbs, not on a whole clause that may contain emphasis.
2. **Before believing a FAIL, print the flattened text around the target**
   (`flat[flat.find("keyword")-90:...]`). One call shows whether the markup is the
   cause - and confirms the sentence really is there. This is faster than re-wording
   the note, which changes the artifact to suit the test.

## 39d. A phase whose reader is broken must be GUARDED, not merely documented

A phase that reads zero records and still writes an artifact that looks clean is
worse than one that crashes: the artifact gets cited as evidence. Two instances:

- A TLS/certificate reader died on every host with `'bytes' object has no attribute
  'encode'`, recorded `requests: 0` with **no verdict key at all**, and wrote
  `{"certs": {...}}` anyway - so the note then cited a certificate name that
  appeared in no artifact.
- A parser consumed 6,971 input lines, extracted zero records, printed "success",
  and wrote a clean artifact (the input was ANSI-colour-wrapped).

Rule: when you replace a broken phase, do not leave the broken one runnable.
Install a guard that exits non-zero with a message naming the replacement, and gate
the old behaviour behind an explicit env var (e.g. `SUPERSEDED`, `exit 3`,
`FOO_ALLOW_BROKEN=1`). A phase re-runnable by a stray command will eventually
overwrite a good artifact with a misleading one, and the mislabelled artifact is
what a later reader trusts.

Corollary: a verdict that only reaches the log is not a verdict. Store the verdict
**and the counts it rests on** inside the artifact, or no verifier can assert
against it. "Printed to stdout" and "written to the artifact" are different
deliverables, and only the second one survives the session.

## 39e. Re-measure with a fresh, correct probe, never by editing the harness that broke

A read-only measurement script is code like any other, and editing the version that just
failed risks re-importing its mistake. Write the measurement as a BRAND-NEW minimal
script in scratch, using the real signatures you just read.

- Correctness tells: print the row's keys, prefer the pipeline's own populated field
  over recomputation, and confirm the batch runs end to end (§33).
- Bound the output. A probe that dumps an unbounded structure truncates the very numbers
  you needed; print counts plus one informative line per entity.
- Delete the superseded variant so the next session does not run the wrong one.

## 39f. A correction applied to the facts but not the conclusions is worse than none

When a measurement refutes your own claim, the fix must reach **every** section that
depended on it - facts, inference, impact, severity, and the "what a triager will ask"
paragraph. Correcting only the observations leaves a document that reads as updated
while its conclusion still rests on the refuted claim.

A worked example from this project: a host was reported as serving a control panel "at a
Dell hostname". Measurement showed the panel returns a byte-identical response to **any**
`Host` header, including an invented one - so the hostname contributes nothing and the
panel is not branded. Sections 2 and 3 were corrected first, and the report still carried
"an attacker gets a Dell-branded URL" and "a convincing Dell-branded login could be stood
up" in its Impact section. Under a triager, that is a finding rejected in the first read.
The check that catches it: after any correction, re-read the **Impact** and **Severity**
sections specifically, and strike the claims the measurement removed rather than
describing the caveat elsewhere.

Corollary: assert the withdrawal in the verifier. A `has("withdrawn") and
has("credential phishing")` check, plus one for each replacement sentence, means the
report cannot silently regain the refuted claim on a later edit.

## 39g. A static scan that fires on most of its inputs is measuring the harness

A detector whose hit rate is a large fraction of the corpus has not found
vulnerabilities; it has found that its patterns match ordinary source code. Quantify the
rate before reading any hit.

Three concrete causes, each of which made a source-to-sink JS scan fire on 162 of 1,334
files before being fixed:

* **Minified identifiers matched as flows.** In minified code `n`, `e`, `t` are assigned
  something on nearly every line, so "`n` is assigned from a URL source" and "`n` is used
  near a sink" are both true by coincidence. Require names of at least three characters,
  or match only names the author chose.
* **A match INSIDE A STRING LITERAL counted as code.** Escape-aware quoting must be
  checked before accepting any match. Bundles that concatenate string fragments to build a
  `new Function` body contain `location.href` in quotes and are not sources.
* **The window around a sink was a fixed character count.** In a minified bundle that puts
  unrelated code "near" a sink. Limit a direct-flow match to the sink's **own expression**
  (to its matching close paren or statement end).

When the surviving hits are all one shape, name that shape and judge it. In the scan above
every remaining hit was `anchor.href = location.href` - reading the page's own URL into an
anchor, which is URL normalisation, not attacker data reaching a sink. "No finding" with
the shape identified is a result; "N hits" without it is noise.

Two more precision failures in the same family, both from a RANKER rather than a detector:

* **A ranker keyed on free text inside the URL ranks junk.** Scoring candidates by substrings
  of the path put a URL-encoded multilingual path first with score 62, because the percent-encoded
  bytes happened to contain the letters of `admin`, `debug`, `env` and `show`. The path is
  attacker- and language-influenced text; rank on STRUCTURED fields (parameter names) instead.
* **Match parameter names by set membership, not substring.** Single-letter and short names (`s`,
  `pid`, `id`) match inside longer names, so nearly every candidate scores and the ordering stops
  discriminating. Keep an explicit list and intersect it.

After any change to a ranker, print the top N with their full fields and read them. A ranker that
looks correct in source can still order a junk row first, and nothing but reading the output shows it.
And **count a filtered noise class rather than dropping it silently** - a filter that removes rows
without reporting how many hides a real member of the set it was written to exclude.

## 39h. A verifier that fetches the live target makes the suite non-deterministic

One verifier fetched a target over the network (`HTTPSConnection(HOST, 443)`), so a transient
network blip surfaced as **13 content failures** - byte-identical in the report to a real
regression. A suite that can be red for reasons unrelated to the artifact is worse than no
suite: it trains you to ignore red.

Rules:

1. **Cache the fetched bytes** when the evidence is collected, read from cache on later runs.
2. **A request that never completed is SKIPPED, never FAILED.** Thread the fetch's status into
   the assertion (a `net_status=0` parameter on the single `check()` funnel).
3. **Prove it offline**: `unshare -n python3 <verifier>` must give `exit=0`, zero FAIL, and a
   non-zero SKIPPED count. If it fails, the verifier is network-coupled.
4. **A silent skip must be visible at suite level.** Count and print `SKIPPED`, so a fully
   offline run cannot be mistaken for a full pass.

Proving it: the same verifier went from `13 FAIL` to `0 FAIL / 16 SKIPPED` under `unshare -n`.

## 39i. Encoding your own test payload destroys the test

Probing whether a reflected value can escape its HTML attribute with
`?p=zq%22onx` proves nothing: **the quote was percent-encoded by the tester**, so the server
never saw a quote. The test cannot fail, so it answers nothing.

Send **raw, unencoded** metacharacters, and read the encoding of what comes back:

```
raw "  -> value="...zq%22onx"      %22
raw '  -> value="...zq%27onx"      %27
raw <  -> value="...zq%3Cx%3Ey"    %3C %3E
raw \  -> value="...zq%5Cxonx"     %5C
```

Re-encoding of every dangerous character means the value cannot terminate the attribute -
which is the correct behaviour, and a finding only if one of them survives raw.

Same class: any probe whose input you normalised before sending (lowercased, trimmed,
truncated, escaped) cannot discriminate the sink's handling.

## 39j. Reading a `search` endpoint as an enumeration undercounts

An inventory built from a search query is not an enumeration. `search?q=a` returned 18
repositories; the registry held **25** - and all **seven** missing names lacked the letter
`a`. The seven included the two largest repositories in the registry.

Rules:

1. **A wrong count can understate exposure, not just overstate it.** A false positive gets
   caught in review; an undercount ships.
2. Confirm any inventory with **two independent methods** (object count from the resource
   itself + a union of several differently-shaped queries) and require them to agree.
3. **A single query can be arbitrarily wrong** (`q=1` -> 0, `q=m` -> 8, `q=e` -> 25).
4. State the enumeration method in the report so the reader can recheck the number.

## 39k. An empty result is a hypothesis about the probe, not a finding about the target

Four separate failures in one round shared this shape: a request pattern that yielded
"nothing" and was read as "there is nothing".

* `manifests/latest` -> 404 for 16 of 17 repositories: they are tagged by **version**, not
  `latest`. A 404 for a tag that does not exist looks identical to an empty repository.
* `tags[-1]` picked a **signature artifact** (`sha256-*.sig`) as if it were an image tag.
* Four repositories still 404'd - they are **OCI indexes**, and the registry said so in the
  error body: `OCI index found, but accept header does not support OCI indexes`. The error
  text was never read.
* A pattern for credential names could not match `license_key` at all, so "zero secrets" was
  untested rather than negative.

Rules:

1. **When most inputs return the same empty result, the probe is wrong, not the population.**
   Abort (`exit 4`) rather than emitting a verdict over unread data.
2. **Read the error body.** The registry named the exact cause; the phase discarded the text.
3. **Match the request to the resource's own conventions** (its tag list, its media types)
   before concluding anything is absent.
4. Widen the pattern and re-run before believing a zero: "no hit" from a pattern that cannot
   express the thing you are looking for is not a negative result.

## 39l. Prove the comparator is stable before comparing anything

Comparing two responses proves nothing unless each arm is repeatable first. Concretely:

* ServiceNow embeds a per-response CSRF token (`g_ck`), so `sha256` differs between two
  *identical* requests - a cross-arm hash comparison is then pure noise. Stripping the token
  was not enough either; a second rotating element remained.
* The fix that worked: an **in-arm stability baseline** - fetch the same URL three times, take
the intersection of the line-sets, then diff the intersections between arms. Only lines that
survive repetition in both arms can carry meaning.

Order of operations: **stability -> single variable -> comparison.** Skip step one and the
verdict is either a false positive or has no verdict at all.

## 39m. A change log built from single observations reports transitions that never happened

A `status_changed` / `title_changed` event derived from ONE sample per side cannot tell a real
transition from a response that varies between requests. Measured example: two Dell hosts were
logged `401 -> 200`, and six **identical** requests to one of them returned

```
401 (26 B) / 200 (47,242 B) / 401 / 200 (45,894 B) / 401 / 401
```

The `200` was an **F5 BIG-IP ASM challenge page** (`window["bobcmn"]`, `TSPD_101`, a support ID,
a CAPTCHA prompt) - no application data at all. So the log recorded a transition that never
happened, and the "exposure" reading was an artifact of two samples straddling a fluctuating
response.

Rules:

1. **Re-sample a change-event row several times before believing it.** Identical requests
   producing different statuses mean the log's two samples disagree with each other.
2. **Identify WHAT the changed response is before judging the change.** A `200` that is a bot
   challenge, a stock error page, or a CDN default object is not content. Grep the body for the
   appliance's own markers (`bobcmn`, `TSPD`, `_Incapsula_Resource`, `cf-chl`, support IDs).
3. **A status code is not a payload** - and a challenge page answering `200` is a correctly
   configured appliance, not a finding.
4. **A change log is a lead generator, not evidence.** It tells you where to look; the verdict
   comes from re-measuring the host, never from the row.

## 39n. A number in prose must reconcile with the artifact, or a verifier pins it green

Three wrong numbers survived review in one round, each by a different mechanism.

- **The arithmetic was never done.** A report said "read 88 layers and skipped 145" while the
  artifact said 88 read + 122 skipped against 184 declared. `88+145 = 233 != 184` is the entire
  test. A sum you can do by hand is covered by no assertion - do it, in the session, for every
  figure that is part of a larger figure. The tell is a withheld/dependent number that cannot
  be re-added to the total.
- **A verifier that greps a SENTENCE certifies the prose, not the claim.**
  `check(has("read 88 layers and skipped 145"))` was GREEN because the text contained exactly
  the wrong number. When you correct a figure, also fix the assertion to require the right
  value AND add `not has(<the wrong string>)`, so the bad number cannot return.
- **A dedupe'd sample described as corpus-wide.** "no source->sink flow across the JS corpus"
  was measured over **44 hosts** while **2,415** hosts in the same corpus serve JS (2%) - the
  sample had been deduped by bundle name precisely to AVOID the rest. The per-file verdict was
  correct; the scope sentence overstated it ~50x. Put the numerator AND the denominator in the
  note and assert both, so a later reader cannot widen the sentence. This is the failure a
  negative verdict is most prone to, because nothing about it looks wrong.

Corollary on counts that look like constants: a collection's document count is often a
**rolling window**, not a property of the collection. The same key measured 252,677 and then
200,026 hours apart, over 27 distinct days with thin edges. Quote a corpus count with the time
it was taken or not at all.

Tool trap found while re-measuring: a date field stored as a **string** makes a range query
(`{"created_date": {"$gte": "2026-09-01"}}`) return **0** documents silently - the same
empty-result shape as 39k, produced by the query rather than the data. Filter on the string's
prefix, or convert first.

## 39o. A name a config API ACCEPTS is not a name the system RECOGNISES

Registering a scheduled job with a toolset name that does not exist succeeded, and the stored
record carried the invalid name verbatim. Nothing validates enum-shaped values at write time, so
the defect would have surfaced only as a job running without the tools it needs - and a job that
runs is not obviously a job that runs wrong.

Rules:

1. **Validate every enum-shaped value against the code's OWN validator before trusting it.** Import
   the registry that enforces the values and ask it directly
   (`validate_toolset("file") -> True`, `validate_toolset("files") -> False`). A create/update
   response echoing your input is confirmation of STORAGE, not of validity.
2. **Read the allowed values from the source that enforces them**, never from a field name or a
   plausible spelling. The real name and the guessed name differed by one character, and the guess
   was the more natural English word.
3. **Fire a scheduled job ONCE before its first natural fire**, with a transient prompt that forbids
   side effects. A syntactically valid schedule and working plumbing are different claims, and the
   first production fire is otherwise the first test.
4. Read the stored job back and check each field you set landed - a field silently ignored at write
   time is indistinguishable, from the schedule alone, from a field that works.

## 40. A gate log is a temporal sequence, not a status field

Reading a gate log's last lines answers "how did the most recent run end". A question
about a SPECIFIC commit needs the block whose sha matches.

- Do not quote a `tail` as the result for the commit you just made. Locate the run by
  its sha (or count blocks) before reporting DEPLOYED/BLOCKED.
- A later run's DEPLOYED does not retroactively clear an earlier commit's BLOCKED. If a
  superseded commit was blocked and the current HEAD deployed with the same content, the
  difference is which tree the gate saw — compare the gate's own logged plan/level block
  (§29) rather than assuming a log line belongs to your sha.

## 41. Three-valued logic reported as two values invents a finding

A resolver or matcher that returns *yes / no / unknown* is routinely collapsed to *yes / no*, and the
collapsed middle surfaces as a confident negative. Two instances in one round, both from scripts whose
verdict function had exactly two return values:

- A ranker's own result field printed as the boolean `False` while the function actually returns
  `None` when a host is out of scope. **A truthy-looking `False` where the real value is `None` is the
  tell**: it survives a `if not x:` guard and reads as a measured negative.
- A classifier returned `None` both for "a plain page" and for "an edge challenge I have no rule
  for", so an unidentified WAF page entered the shortlist as a normal application response.

Rule: **when a matcher can fail to decide, its unknown case must be its own returned value and its own
reported class** - a distinct verdict string, counted separately, never folded into either the pass or
the fail total. Applies to reachability (`UNKNOWN-VANTAGE`), block classification
(`UNCLASSIFIED-RESPONSE`), and scope (`UNRESOLVED-SCOPE`). A two-valued summary of a three-valued
decision is a fabricated value, and it fabricates in the direction that looks like work done.

## 42. Test the gate with the values the GATE holds, not the ones you typed

Assert-safe gates are cheap to mis-test, and the mistake always looks like a real defect. Two shape
errors from one round, both produced by hand-typing the expected value:

- **A missing substring looked like an encoding bug.** A needle was "not found" in a haystack that
  visibly contained it, three separate times. The cause was the tester's own string: typed once with
  an extra word inside a phrase, once with a dropped word. `repr()` and a per-code-point dump of both
  sides settled it in one call and proved the data was clean ASCII.
- **`'None'` (a string) compared against `None` (the object)** made four correct rejections print as
  FAIL for four consecutive test iterations.

Rule: **build the test input BY CONCATENATION from the constant under test**
(`page = "Please " + NEEDLE`) instead of retyping it, print `repr()` of both sides on any unexpected
result, and compare against the exact sentinel the function returns. Before reporting a FAIL, ask
whether the FAIL could be the test's own literal - this is the same class as 39c (markup spanning an
assertion) and 39i (encoding your own payload), and it costs the same turns to chase.

## 43. A derived total inherits its source's defect; a guard class comes from provenance

- **Correcting an input set means re-deriving or re-labelling every figure derived from
  it.** An inventory went 18 -> 25 (39j); a pull total of `897,655` stayed as the sum over
  the **18 rows enumerated first**, inheriting the undercount the fix had removed. Label
  the basis or re-sum.
- **A figure recalled from memory is wrong often enough to stop doing it.** Two byte sizes
  written from memory were 27.2/22.9 MB in the artifact, not the 32.6/24.0 written. Read
  from the artifact in the same call that writes the number; have the verifier pin the
  artifact value AND `not has(<the wrong string>)`.
- **A violation guard classifies by PROVENANCE, and provenance is a measurement.** A guard
  flagged `programs/wien.json` as an agent violation; it was the operator's input - mtime
  **2 ms after** the program's DB `created_date`, while the agent's last write was 28 min
  earlier, and the sync script reads `programs/*.json` as its documented input path. Line
  the mtime up against the other actor's own record before reporting or clearing.
- **A guard needs a class per writer** (agent-allowed / pipeline-output / operator-input).
  Two classes lose a distinction; folding operator input into allowed hides real
  violations. State which side it errs on, and after every change re-prove it still
  catches a genuine violation - a classifier that only ever says COMPLIANT is not one.

## 44. `urlopen(timeout=)` does not bound DNS, and one hung socket parks the run

A sweep sat **sleeping 400+ s with zero progress and no error**, on one host. Four
restarts traced to unbounded waits.

- **`urlopen(url, timeout=N)` does not bound the `getaddrinfo` inside its connect path.**
  Add `socket.setdefaulttimeout(N)` AND run the probe in a worker thread with a hard
  `join()` deadline, returning a distinct `PROBE-WATCHDOG-TIMEOUT` verdict. A bare
  `getaddrinfo` has no deadline either - wrap it the same way, `DNS-RESOLVE-TIMEOUT`
  separate from "unresolved" (§41). Abandoning a daemon thread is the correct cost: one
  probe must never cost the run.
- **Prove the watchdog on the host that hung AND on a healthy host** - one validated only
  against dead hosts may have broken every normal probe. Measured: hung host 28 s (the
  deadline), healthy host 0.4 s.
- **`do_wait` + a live child + an unchanged log mtime is a hung probe, not a running
  phase.** `ps -o etime=,stat=,wchan=` plus the log's mtime age settles it; a rate over
  50-60 s (count a growing artifact twice) is the cheapest proof that "working" is 0.
- **Persist candidates the moment they are found, state periodically.** A killed run
  discarded 20 found candidates; after the fix a later kill lost nothing - the fix is
  proven by the kill that FOLLOWS it, not by reading the code.
- **Interleave rather than exhaust.** When one input is 63 % of the population, depth-first
  starves everything else: round-robin with a stated per-host cap, and report the
  held-back count (39g).

## Detailed cases

Topics 41 and later — the specific incidents behind the rules above — live in
`references/round-by-round-lessons.md`. Read that file when a rule looks
unfamiliar or you need the measured numbers.
