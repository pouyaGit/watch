---
name: hermes-test-gated-autodeploy
description: "Use when wiring a gate that auto-deploys or reverts commits."
category: software-development
---

# Test-gated automated deploy

For a system that deploys itself with no human in the loop: presentation changes
ship on a web suite, decision/authority changes sit behind a stricter safety
gate, and anything suspicious stops the deploy instead of waiting for approval.

The governing rule: **the gate replaces a human decision, so the gate must be
stricter than the human would have been.** A gate that is right often and wrong
quietly is worse than no gate, because it removes the checkpoint it was built to
replace.

## 1. Baseline the history before wiring any gate

A gate without a baseline commit cannot revert, so nothing is gated yet.

- Check whether `.git` is actually usable: `git log -n 1` and `git branch -v`.
  A repo with an `objects/` directory but no reachable `HEAD` is a broken
  baseline — re-`init` it, and **back it up first** (`cp -a .git .git.bak_<date>`)
  so the prior history is recoverable.
- Create a **bare remote outside the working tree** (`/root/<project>.git`) and
  point `origin` at it. A local `.git` alone is not a backup; the working copy
  and its history are the same failure domain. Verify with
  `git rev-parse HEAD origin/master | uniq -c` returning one line.
- `.gitignore` must cover runtime state, logs, and every credential path. Confirm
  the secret files live **outside** the repository and that the pattern (`*.env`,
  `*.key`) would catch them if they did not. Never echo a secret to verify this.
- Adopt the admin identity the deployer will use (`git config user.email/name`)
  so automation never needs a global config.

## 2. Classify by path, and fail closed

Two tiers, and the third outcome is the important one.

- **LOW_RISK** — presentation surfaces only (view helpers, renderers, query
  formatting, copy, styles).
- **HIGH_RISK** — decision, authority, auth, scope, and persistence modules.
- **Anything not on either list is HIGH_RISK.** An open whitelist means a new
  file lands in the cheap tier by default; the file count is discovered by the
  gate, not by the author remembering to register it.

Suites are selected from the tier, never hand-picked per commit. Map each
high-risk module to its own safety-verify plus the module's focused suite, and
always run the standing auth/security and read-only-isolation suites on any
high-risk deploy.

- **Prefer the repo's existing suite list over a new inventory.** Parse it with
  `ast` and reuse the declared names; re-deriving the list produces a second
  source of truth that drifts.
- **A deploy that touches no runtime file restarts nothing.** A docs-only commit
  should report `services: (none)` rather than bouncing a live daemon.

### Pin BOTH git refs, or the working tree becomes the change set

`git diff --name-status <sha>^` — one ref — compares against the **working
tree**, not the commit. Every file a background process wrote since the commit
lands in the gate's input, and an unknown path is HIGH_RISK by fail-closed, so a
pure-presentation commit gets the authority suite list. Write `git diff A B` with
both refs in **every** call: the change-set query, the unified diff, and the
per-file hard-rule scan (all three had this bug independently).

Prove it before trusting it — run both forms and diff the output:

```
git diff <sha>^            --unified=0 -- lib/foo.py   # vs WORKING TREE
git diff <sha>^ <sha>      --unified=0 -- lib/foo.py   # vs the COMMIT
```

A gate that reads the working tree cannot be reasoned about, because its input
changes while it runs.

### Risk is the path mask alone — never the status code

Classify from the final path and discard git's `A`/`M`/`D`/`R`/`C` label
entirely. Risk is a property of *where a file lives*, not of how git happened to
describe the change: a re-added or renamed `lib/` file is HIGH_RISK and a
renamed-into `web/` file is LOW_RISK, identically. For a rename, key on the NEW
path (the last tab-separated field) — that is the file the tree will serve.

Order the checks so the most specific wins: an explicit HIGH_RISK path beats a
`web/` prefix (the `web/` package holds both view helpers and the auth/server/db
surfaces), then docs, then the LOW list or its prefix, then fail closed.

## 3. Hard rules are grep, never judgement

A semantic "does this look like a bypass" check is unreviewable and will
eventually be wrong. Deterministic string patterns over the diff's added and
removed lines are auditable and stable.

Scan the diff of a high-risk file for two classes:

- **Added capability** — new `os.system`/`subprocess`/`eval`/`exec` bindings, a
  disabled `no_exploitation`/scope flag, a `bypass*` symbol, a guard replaced by
  a lambda.
- **Removed guard** — a line mentioning a safety or auth token (`in_scope`,
  `verify_password`, `check_csrf`, `no_exploitation`) appearing on the **removed**
  side. Check the removed side explicitly: an addition-only scan cannot see a
  deleted check, which is the case that matters most.

Also pair patterns: a guard string in either side plus its early `return` in the
added side means the guard's control flow was restructured.

- **A hard-rule hit must NOT auto-revert.** Reverting a security-relevant change
  is itself a decision, and the operator asked to see the diff. Leave the commit
  in place, do not deploy, do not restart anything, and report the specific file,
  pattern, and line. Reserve auto-revert for *test* failures.
- Keep a diagnostic-only escape hatch (`--allow-manual`) for inspecting what a
  change would trip, and never wire it into the hook.

### A rule that matches prose forbids documenting the thing it forbids

Two failure modes make a hard rule unusable, and both surface the moment you
write the gate's own regression suite (a suite that asserts bypasses are caught
necessarily contains the forbidden strings):

- **Skip comments.** A line whose first non-space char is `#` is documentation.
  Filter it before matching, on both the added and removed sides.
- **Anchor to code shape, not the bare word.** `r"bypass\w*"` matches any string
  containing "bypass" — including a test label, a docstring, an error message.
  Anchor to the *shape of a change*: `r"\bbypass[_a-zA-Z0-9]*\s*=\s*(True|1)"`
  catches a bypass flag being switched on and ignores every mention of the word.
  The same applies to `eval`/`exec`: match the call, not the substring.
- **Scope the scan to the authority tier.** A rule that fires on any path blocks
  every security test from ever being added. Scope to the high-risk paths and
  their prefixes.
- **Keep the gate's own scripts out of the authority prefix.** `scripts/` is not
  a runtime surface, and putting `ci_gate.py` or its regression suite under a
  scanned prefix makes the gate refuse its own maintenance commits. If the gate
  lives beside the product in a scanned directory, either exempt that path
  explicitly or accept that every gate change needs `--no-verify`, which is how
  a gate gets quietly disabled.
- **Assert non-vacuity in both directions after narrowing.** Every "no hit" case
  above would also pass if you had simply muted the rule, so add cases that still
  trip it as real code: the same pattern as a comment (no hit) and as an
  assignment (hit). A filter that cannot be shown to still catch its target is a
  filter that has disabled the rule.

## 4. A negative test must break the EXECUTED path

Proving the gate blocks is mandatory, and getting it wrong wastes the most time:
two attempts produced a *passing* gate on a *broken* commit.

- **Breaking a dead function proves nothing.** Adding a function nobody calls
  leaves every suite green, so the gate deploys it. The tell is a suite that
  passes while the diff is obviously wrong.
- **A defensive accessor is unbreakable by design.** Renaming a key passed to
  `dict.get()` returns `None` and the code degrades silently — the suite passes
  and the gate ships a blank field. This is worse than a crash: nothing is red.
- Break something on the **critical path of the suite** — the escaper every
  render calls, the query the assertion reads, the route the test exercises.
- Verify the break the cheap way before spending a gate run: run the suite
  standalone and confirm it goes red. A green standalone run means the negative
  test is vacuous.
- **Record and revert every negative test, and check the revert restored the
  behaviour** by re-running the suite, not by reading the revert commit. A
  negative-test commit that is accidentally deployed is itself an incident.
- **Commit the fix under test BEFORE writing the test that exercises it.** A test
  whose cleanup runs `git reset --hard <sha>` against the live tree will destroy
  the uncommitted gate change it is supposed to be testing. The suite then
  measures a stale gate, fails for a reason that no longer exists, and sends you
  chasing a bug you already fixed. The tell: the fix vanishes from disk
  partway through debugging, and the on-disk module still has the old signature.
- **Run classification/rule tests in a scratch repo under `$TMPDIR`, never the
  live tree.** A full `cp -a` of a project carrying gigabytes of runtime
  artifacts times out; `--plan`-only checks need only git metadata plus a few
  files, so seed a minimal repo with a copy of the gate script. Nothing outside
  `$TMPDIR` gets committed, reverted, or hard-reset.

## 5. Do not override the environment a suite was written against

- A read-only suite reads the **production** database through its own read-only
  URI. Pointing `HERMES_DB` at a non-existent path from the runner produces a
  `KeyError` that the gate faithfully reports as a failure — an infrastructure
  mistake wearing a test failure's clothes. Do not "isolate" a suite that is
  already isolated by contract.
- **Show the failing assertion, not the last line of output.** A summary line of
  `====` blocks is a block with no reason, and the reason is the entire point.
  Extract the `FAIL`/`Traceback` lines into the summary.
- **Set a sink env var for notifications during the run**
  (`HERMES_NOTIFY_SINK=off`) so a long suite cannot page the operator from
  inside the gate.

## 6. Distinguish a real regression from daemon contention

A live daemon writing while a read-only integrity suite runs is the classic false
block, and the correct handling is a **re-run, never a silent pass**.

- Classify the failure text against a known contention list (row-count drift,
  DB hash change, table-count change). On a match, `SIGSTOP` the writing
  process, re-run that suite, and `SIGCONT` in a `finally`.
- `SIGSTOP`/`SIGCONT` is reversible and does not stop the unit, so a suite that
  can only pass on a stopped service is not being satisfied by breaking
  production. Do not `systemctl stop`.
- If the re-run is still red, the commit caused it: block and revert. Report the
  re-run, not the first attempt, and say which classification applied.

### Wall-clock assertions are flakes, not verdicts

The same handling applies to a suite whose assertions measure elapsed time — a
login-latency ratio, a timeout bound, a duration threshold. Under the gate's own
load these trip on identical code; standalone they pass repeatedly, and a
gate that blocks on them trains the operator to reach for `--no-verify`.

- Maintain a small list of timing-sensitive assertion texts and re-run a failed
  suite a **bounded** number of times (2 is enough to separate a spike from a
  real break). Never a silent pass: report the re-run and which classification
  applied. A genuinely broken assertion fails the re-runs too and blocks.
- Diagnose it properly before adding the exemption: locate the assertion in the
  suite and check what it measures. A wall-clock ratio bound around real work is
  a load-sensitive test, whereas a ratio measured against a stub is a real
  regression. Record which one you found, because the fix differs.
- Do not widen the exemption until it swallows the suite's other assertions —
  the match is on the failure text, so a broad substring can silently reclassify
  a genuine failure as a flake.

## 7. Activation and rollback

- A `post-commit` hook is the smallest deployable unit: it needs no daemon, no
  path-watcher race, and it runs where the commit is made. Log to a file
  (`>>` append, never truncate) so history survives.
- Document the `--no-verify` escape hatch in the hook's own comment. It stays in
  the reflog, so it is never truly silent.
- **Confirm the gate actually ran** by reading the log and the git state after
  the commit. A hook that failed to install looks exactly like a gate that
  passed.
- After a block, verify the service is `active` and the app still serves
  (`/healthz`, one real page). A gate that reverts code but leaves a dead service
  has traded a bad commit for a down product.
- Every deploy is its own commit so `git revert` and `git reset --hard <sha>`
  are both available. Push only after a green gate.

## 8. Reporting

- One line per deploy, on the operator's own channel: what changed, the risk
  level, the suites run, the outcome, and the services restarted.
- Write the same record to a timestamped JSON artifact under `state/`, so a
  later reader can re-run the comparison.
- **Disclose the gate's own misclassification.** If a low-risk change was
  classified high, or a risk tier is too coarse, say so with the cause and the
  fix. An automation the operator cannot predict is one they will disable.
  This applies doubly when *you* misread the cause: the first explanation you
  gave may have been wrong, and correcting it in place is worth more than
  quietly shipping the fix. Re-derive the cause from the gate's own logged
  input (`git show`, both `git diff` forms) rather than from your earlier
  narrative, and say plainly when the narrative was the thing that was wrong.
- **State the residual risk explicitly, once, when handing over**: which changes
  now ship with no human in the loop, and what a passing gate does not prove
  about them. Offer the narrowing option (e.g. require an env var for the
  high-risk tier) and let the operator choose.

## Pitfalls that cost time

- Truncating a suite's failure to its last output line makes every block
  unactionable.
- **A single-ref `git diff` is the working tree, not the commit.** It silently
  folds in whatever a background daemon has written since, and fail-closed
  classification turns that into a spurious high-risk block.
- **Blaming the wrong cause and then "fixing" it.** When a tier comes out
  unexpected, read the gate's own logged input before theorising — `git show` on
  the commit and both `git diff` forms side by side. A confident wrong cause
  sends the next several turns down the wrong path and buries the real defect.
- A rule matching the bare word `bypass`/`eval` fires on comments, docstrings and
  test labels, and then blocks the regression suite that proves the rules work.
- `git reset --hard <sha>` in a test's cleanup destroys uncommitted work in the
  live tree — including the change under test.
- Bundling the gate script with the change under test makes the commit's own
  tier wrong, and it will run the wrong suite list against itself.
- A daemon-contention or wall-clock failure blocks a correct commit and the
  operator reads it as a bad change.
- `--allow-manual` wired into the hook silently disables the hard rules.
- Assuming the hook ran because the commit succeeded: git ignores a failing
  `post-commit` hook's exit code unless the hook itself rejects the commit.
- Leaving negative-test commits in history. Rewind to the last real commit and
  force-push with `--force-with-lease` after an in-place test.
