# Completing a regression battery that did not finish in one process

Use when a run of `scripts/m11_regression.py` (or any shared runner) died part-way:
finish the missing rows with the runner's own definitions and produce one certified
result. Restarting the whole battery is the fallback of last resort — it re-executes
already-certified rows against a state that has since moved, so it can neither
reproduce nor supersede what you already proved.

## 1. Establish process state before deciding anything

1. Read the launch/termination record, not your memory of it:
   `~/.hermes/logs/process-results/proc_*.json` → `command`, `started_at`, `exit_code`,
   `completion_reason`, `termination_source`, `output`. The wrapper's `echo <LABEL>=$?`
   lands in `output`; a SIGTERM'd wrapper reports the signal form (143 / -15) with
   `termination_source: agent_close`.
2. Confirm from the machine: full process table, then `/proc/*/cmdline`,
   `/proc/*/environ`, `/proc/*/fd` for the output path; check for zombies. Discard your
   own pid — `grep`/`pgrep` for the run's name matches its own command line.
3. Bounded observation: snapshot size+mtime+row-count, wait 60–90 s, snapshot again.
   Unchanged and no process → TERMINATED. Advancing or a live child → ACTIVE (then only
   a bounded wait, never an open-ended one). Never poll indefinitely.
4. Read the output's tail: summary block / runner exit line present? Which rows exist?
   That decides whether a complete result already exists before you run anything.

## 2. Compute the gap mechanically

Parse every `PASS|FAIL|MISSING` row from the partial output and from a complete baseline
run (same runner → same suite order). Gap = baseline suite names minus observed names.
Assert: gap ∩ observed = ∅ (nothing gets re-run by accident) and partial + gap = full
suite count. The brief's stated missing set must equal the computed gap; a mismatch
means you are looking at the wrong artifact — stop and reconcile before running.

## 3. Preflight per batch

Daemon/service state, `PRAGMA quick_check`, schema/table count, required suite scripts
exist, no competing process on the same output file. Query the DB through a read-only
URI (`file:...?mode=ro`) — verification must not write. If a prerequisite is missing,
classify that row honestly from the failure text; do not fabricate fixtures to turn a
live check green.

## 4. Reuse the runner's definitions without editing it

A module-level runner executes its whole battery on import — do not import it, do not
copy its lists by hand, do not modify it or any test definition.

```python
import ast
src = open(RUNNER).read()          # read only
for node in ast.parse(src).body:   # SUITES, PREEXISTING, ENV_DEPENDENT
    if isinstance(node, ast.Assign):
        ... ast.literal_eval(node.value)
```

Issue the runner's identical call per row — `subprocess.run([PY, rel], cwd=BASE,
capture_output=True, text=True, timeout=900)` — with its identical summary/tag/format
rules, over the gap list only.

## 5. Batching and evidence

- Budget each batch from the prior run's per-row durations (`\d+\.\d+s` in the baseline
  rows): target ≈ ≤200 s expected against a ~300 s ceiling, and put the single longest
  row alone in its batch.
- Flush each completed row to the evidence file immediately (`open(..., "a").flush()`)
  so a cut mid-batch keeps partial progress.
- Write to a SEPARATE artifact (e.g. `/tmp/...`). Never let partial rows overwrite the
  production evidence file the runner owns (`state/<m>_evidence/*.json`) — that file is
  the prior complete result.
- Record every batch's exit code; the aggregate is a row-level count, not a process
  verdict.
- Diagnostics for a failing row go to their own file: a diagnostic rerun never replaces
  the recorded certification row.
- **Re-run ONE failing suite in a clean environment before classifying a batch of
  identical open-failures.** Several unrelated suites dying with the same
  `sqlite3.OperationalError: unable to open database file` is usually an env var the cell
  inherited from an earlier probe (`HERMES_DB` pointing at a temp dir already deleted),
  not a code regression — the affected scripts are exactly the ones that read
  `os.environ.get("HERMES_DB") or …`. Pop the variable (or set it to the runner's path),
  re-run one: a pass on unchanged hashes makes the class the harness environment, never
  INTRODUCED, while the original failing output is still reported.
- The ~300 s cell ceiling is a hard kill that also drops in-kernel state, whatever
  `timeout_s` you asked for: size each cell from the prior durations, flush every row to
  the evidence file as it lands, and resume FROM THE FILE rather than from memory.

## 6. Merge with provenance

Merge observed + recovered rows in runner order into one artifact whose header states
which process produced which row range, how each ended (exit marker / signal / batch
rc), and that no single process ran the full set. If no single-process exit code
exists, write exactly that and report each real exit code instead of inferring one.

## 7. Classify the complete failure set

Runner labels (`[REGRESSION]`) are hypotheses. For each failure:

| Evidence in baselines (`_2` / `_5` / `_v3`) | Class |
|---|---|
| FAIL in the pre-change baselines, same assertion text (durations stripped) | PRE_EXISTING |
| PASS in pre-change baselines, FAIL later but before your edit window | PRE_EXISTING (note the time/env mechanism) |
| FAIL whose cause is wall clock / live upstream / cooldown / current DB state | ENVIRONMENTAL — must also show code identity + input non-modification |
| PASS in every baseline, implementation + test byte-identical, and the assertion encodes an invariant the implementation's documented contract never guaranteed (proved by correct PRE-baseline production rows that already violated it) | **TEST_STALE** — repair the assertion, not the code |
| PASS in every baseline, and code identity or input change cannot be excluded | UNKNOWN |
| PASS in every baseline, and your code/data changed the failing path | INTRODUCED |

Proving ENVIRONMENTAL for a non-baseline failure needs all of: sha+mtime of the failing
module and its test scripts identical across every baseline run and the edit window; its
input tables absent from the before/after delta; the assertion's mechanism shown to read
live state; ideally a second probe at a different moment. Disclose that the passing
baseline condition cannot be reproduced retroactively — that residual uncertainty is why
`READY FOR PRODUCTION` stays NO while any live verification fails.

TEST_STALE is a distinct class, not a shade of ENVIRONMENTAL: a data change only SELECTS
which branch a legitimate execution takes. If the assertion is narrower than the
implementation's documented contract, the class is TEST_STALE — report the state
mechanism alongside it, because both are true facts about different components — and
collapse into ENVIRONMENTAL only when the assertion matches the contract and live state
alone explains the difference. `references/live-gate-assertion-repair.md` carries the
three-part proof bar and the repair procedure.

Verdict: `133/133 observed` + complete failure set + `INTRODUCED = 0` + `UNKNOWN = 0` →
regression gate PASS, otherwise INCOMPLETE or FAILED. Report counts as `X/133 PASS,
Y FAIL, Z MISSING` with the real exit codes; the cross-day gate's full verification rule lives in SKILL.md (Report rules).

## 8. Integrity after the run (read-only)

`PRAGMA quick_check`; schema/table count; article/pattern/skill/candidate counts not
decreased; protected file hashes unchanged (any intentional change disclosed with its
before→after value); ceilings and budget literals unchanged and no env override; milestone
files you did not touch verified by mtime; target-request counters read from the suites
that measure them.
