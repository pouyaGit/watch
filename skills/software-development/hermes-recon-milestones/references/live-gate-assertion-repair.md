# Repairing a live gate that contradicts its own contract

Use when a live verification is red while the implementation is provably unchanged and
the diagnosis says the ASSERTION is at fault. The goal is one stable, deterministic gate
that accepts every state the contract allows and rejects every state it does not — not a
green line.

## 1. Classify before touching anything

Decide which component is at fault; a data change only SELECTS which branch a legitimate
execution takes, so it is never by itself the class.

| Evidence | Class | Action |
|---|---|---|
| Implementation byte-identical across every baseline + edit window, inputs unchanged, and the assertion encodes an invariant the implementation's own contract never guaranteed | **TEST_STALE** | repair the assertion |
| Implementation byte-identical, inputs unchanged, assertion matches the contract, result depends on live runtime state | ENVIRONMENTAL | accept with the limitation disclosed |
| Failing code path changed by you, or an input you moved | INTRODUCED | fix the code |
| Failure text identical in every pre-change baseline | PRE_EXISTING | leave it, report it |
| Code/input identity cannot be established | UNKNOWN | gate stays INCOMPLETE |

Proof bar for TEST_STALE — all three, not convenience:

1. **Contract text**: the docstring/comment/code branch showing the observed value is
   deliberately produced (`if <in-flight>: return None`, plus the fallback that fires only
   when nothing is in flight).
2. **Identity**: sha (+ mtime) of implementation and test files identical across every
   baseline run, the certification window and this closure; the milestone's file list
   shows none of the assertion's input tables moved.
3. **Pre-baseline counterexamples**: correct production rows, written by the system with
   no test involved, that already violated the assertion BEFORE the first baseline — the
   invariant was never guaranteed, so baseline PASS rows only prove the branch was not
   selected then.

Never reclassify a non-baseline failure to PRE_EXISTING (no baseline evidence exists for
it), never to ENVIRONMENTAL merely because production data changed, and never report it
as resolved while any of the three proofs is missing. TEST_STALE and ENVIRONMENTAL are
distinct classes: report the state mechanism AND the class, never one collapsed into the
other.

## 1b. An UNOBSERVABLE gate is its own class — do not call it STALE or ENVIRONMENTAL

A gate can be *unobservable* rather than wrong: it asserts something the running system
cannot hold, so it flips on host activity alone. This is neither TEST_STALE (the contract
may be fine) nor ENVIRONMENTAL (nothing environmental will make it pass) — the assertion
itself is unmeasurable and must be REPLACED with a semantic equivalent.

Canonical case: a "did not mutate production" gate implemented as
`sha256(db) == sha256(db)`, or as `hash AND size AND mtime_ns` equality, against a LIVE
WAL database. Five services write continuously; measured over 8 samples at 5s intervals
the main file took 8 distinct hashes and grew ~360KB while the WAL never changed size.
Byte identity of a live WAL DB is a property of a QUIESCED MACHINE.

- Diagnose by MEASUREMENT, not theory: sample DB size / WAL size / mtimes / hash N times
  and print the table. If the hash differs while the WAL is constant, the file is being
  written by ordinary activity — no checkpoint storm, no corruption, no code change
  required to explain it. State the writer set from `/proc/*/fd` links; a long-lived
  service (e.g. a web UI) counts and is easy to miss when the daemon unit is stopped.
- A suite's own comment admitting the defect ("daemon drift makes this gate fail closed")
  is a pointer to the fix, not an excuse to keep the gate.
- Repair by PRESERVING INTENT, not by deleting the assertion: state what the gate was
  really proving (e.g. "this run did not mutate production"), then express it as a
  read-only semantic fingerprint (schema hash + protected row counts + row-level GROUP BY
  invariants) inside `BEGIN DEFERRED`, plus `quick_check` / `integrity_check` /
  `foreign_key_check`. Keep raw hash/size/mtime in the evidence for forensics.
- Then prove non-vacuity: mutate a COPY (row update, row insert, schema change) and
  require detection; restore and require the identical fingerprint back; and require the
  gate to report clean after restore DESPITE the raw bytes differing — that last one is
  what proves bytes are no longer the gate.
- Enumerate every OTHER site carrying the same gate. One brief reported 5 failing suites;
  all 5 shared the defect in 4 different spellings (`sha(prod)!=ph or size!=...`,
  `changed=(after_sha!=ph or ...)`, ...). Grep for the shape, not the check name.
- Snapshotting a live WAL DB for fixtures: use SQLite's backup API, not `shutil.copy2` /
  `cp`. A raw file copy omits the WAL and can fail `integrity_check` with
  `Freelist: size is N but should be N+1`. Read column names from `PRAGMA table_info`
  before writing invariants — a guessed column silently fingerprints the wrong thing.

## 2. Read the contract; repair only the assertion

- Find the vocabulary the implementation already owns (`STOP_*`, `CYCLE_*`, state
  constants) and derive the acceptance set from it at runtime —
  `frozenset(getattr(M, n) for n in dir(M) if n.startswith("STOP_"))`. Inventing a second
  vocabulary creates a second state machine to keep in sync.
- Replace the narrow predicate with a branch predicate covering every contractually valid
  outcome — canonical reason / in-flight counter / newly created work — plus structural
  validation: missing field, non-int or negative counter, unknown state, unknown reason
  and a FAILED/terminal state are always rejected. Each branch returns a `why` string that
  goes into the check detail, so a red line explains itself.
- Do not edit the implementation to satisfy the test. Changing it requires evidence that
  the CONTRACT itself is wrong, which is an exceptional, explicitly-evidenced case; an
  unreachable constant in the implementation is recorded as a limitation, not silently
  repaired here.
- Grep the test tree for the check NAME before renaming one; other suites key on names.
- **Discriminator against "a failing safety assertion is repaired in the code it
  guards"**: if the implementation's contract documents the observed value as correct,
  the assertion moves; if the implementation admits the observed value is wrong, the code
  moves. State in the report which side changed.
- Reject the tempting weakening edits explicitly: a larger sleep, a retry loop, a retry
  budget, or a second attempt at the same byte comparison. These hide the unobservability
  instead of removing it, and they are the edits a reviewer must never accept for an
  unobservable gate.

## 3. Prove it with a branch-complete matrix

Add deterministic, DB-free cases beside the check (same file, same run) — each pins an
exact verdict, never a range:

- every valid branch accepted: created work; in-flight counter with no work created;
  in-flight counter with reason=None; resolved/canonical reason; several in-flight items;
- every invalid state rejected: all-zero with reason=None, malformed counter type,
  negative counter, unknown state, terminal/FAILED state, invented reason;
- determinism: evaluate the whole matrix twice, assert the two verdict vectors and the
  expected vector are identical (`got is expected`, never `got or True`);
- no-write: snapshot the counters the assertion could conceivably touch immediately
  before and after the matrix and require equality.

Synthetic cases are necessary but not sufficient — the branch the stale assertion
rejected must also be observed on REAL state:

1. **Executed fixture on an isolated copy**: copy the production DB to a temp dir, repoint
   `store.BASE`/`store.DB`/`HERMES_DB` at it, remove the ONLY ingredient that made the
   system skip the branch (e.g. clear the fingerprint table ON THE COPY), block
   `socket`/`subprocess`, run the cycle, record both verdicts — stale `FAIL` / repaired
   `PASS`. Production inputs stay untouched; verify their counts afterwards.
2. **Read-only rows**: select the historical production rows satisfying exactly the old
   predicate's failure condition, run the new predicate over them, and print the
   old-invariant verdict inline in the check detail as proof the change does work.

The other branch is exercised by N consecutive runs of the live gate itself; record each
run's exit code, verdict counts and stop reason so branch selection stays visible.

- A component's dry-run mode reads decision logic with zero persistence, but it also skips
  the counters gates read at PERSIST time (made/created counters only increment when a row
  is actually written), so it can select a DIFFERENT branch than a real run. Use it to
  learn what the logic decides, then confirm branch selection with a real run on the copy —
  never cite a dry-run branch as the live one.

## 4. Bound the live-daemon race by mechanism, not by counter equality

Comparing production row counts across a ~9 s window fails whenever the daemon finishes a
job inside it — a false "the verification wrote production" alarm. Repair attribution by
proving mechanism:

- **Isolation**: assert `store.DB == <temp path>`, `HERMES_DB` points at the same temp
  path, temp ≠ production, and every `sqlite3.connect` in the suite's own source that
  touches production carries `mode=ro`. Scan EXECUTABLE lines only — strip comment lines
  first, or your own explanatory comment about `sqlite3.connect(PROD)` is counted as a
  connection and the check fails for a reason that is not a defect.
- **Reachable-family protection**: add a strict before/after equality over the only table
  family the component can write, with a disclosure clause for the one legitimate
  concurrent writer (a new row only that writer can create) — plain drift with no such row
  still fails.
- **Window recording**: keep a strict `deltas ⊆ {disclosed live counters}` rule for every
  other observed table, print the deltas and the window length as the check detail, and
  fail on any delta outside the disclosed set. Never widen the set to go green.
- Do not stop or pause the daemon to make the gate pass unless a stopped daemon is part of
  the test's stated contract. A gate that only passes on a stopped system has been made
  deterministic by breaking production, not by fixing the test.

## 5. Stabilise and report

- Run the focused suites, then N (≥6) consecutive bounded live runs with the FINAL file
  hash; all must be green with identical verdict counts. Disclose development iterations
  (crashes, false-positive self-scans) separately, naming which hash they ran on and that
  they were fixed before the recorded runs — they are not production regressions.
- **Run those repeats with production UP.** A determinism repair validated only on a
  quiesced host has not demonstrated what it claims; the whole point is that the gate now
  holds while legitimate writers run.
- Record wall / user+sys / peak RSS of the run itself (sample `/proc/<pid>/status`; a
  cumulative `ru_maxrss` high-water mark belongs to earlier sessions and must be labelled
  as such) and the peak open fd count.
- **Delete every temp DB copy you created.** Live suites copy the whole production DB per
  run and do not self-clean; at ~316 MB each, leaked copies fill the disk between
  milestones. Verify zero remain — and delete only what THIS milestone created (see the
  cleanup rule in SKILL.md Report rules).
- Snapshot integrity read-only before/after: `PRAGMA quick_check`, schema/table count,
  entity counts, the component's production table counts, ceilings and budget literals,
  no provider calls, no target requests.
- A snapshot/baseline suite that fails for a missing baseline stays red exactly as in the
  pre-change baselines — never run its `--save` to manufacture a baseline.
- Report with the brief's mandated template verbatim and stop after the report; the
  cross-day gate's full verification rule (PENDING until it fires, per-item verification
  with `NO_ELIGIBLE_CASE` for items with no eligible case, never trigger it) lives in
  SKILL.md Report rules.
- When an earlier milestone left a documented INCOMPLETE that this one closes, the report
  must state the previous verdict's exact reason and the new evidence that discharges it.
  "Pass criteria all met" is not evidence; the prior failing check, re-run green, is.
