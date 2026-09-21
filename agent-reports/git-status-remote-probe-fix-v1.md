# Git Status Remote Probe Fix v1 (Epic 0.2.2)

## Bug description

`check_auth.py --json` (run by hand in the worktree) reported
`{"method": "ssh", "reasons": [], "verdict": "READY"}` — `ssh -T`
authenticated (exit 1 with "successfully authenticated", GitHub's normal
shell-denied success) and `git ls-remote origin` succeeded. But
`status.sh` showed `push BLOCKED` / `reason REMOTE_UNAVAILABLE…`.

## Root cause

Two conflicting repository-validity checks around one frozen checker:

- `check_auth.py --repo DIR` gates on `os.path.isdir(DIR/.git)`. A **linked
  worktree** carries `.git` as a *file* (pointer to the real gitdir), so the
  gate fails with "not a git repository" → `BLOCKED` / `REMOTE_UNREACHABLE`.
  The agent workspace (`/opt/watch/.worktrees/watch-agent/.git`) is exactly
  such a file.
- The operator running the checker **bare** (CWD inside the worktree) skips
  that gate — `git config` is worktree-aware — and gets `READY`.

`status.sh` passed `--repo "$REPO"` explicitly, so it always tripped the
gate while the operator's own invocation did not: same checker, two answers.
On top of that, `status.sh` ran its own ssh double-probe for the
Authentication section, whose "available" verdict visibly contradicted the
`BLOCKED` push line without explaining why.

## Fix (`status.sh` only — `check_auth.py` untouched, promotion untouched)

- The checker is invoked **once**, with cwd inside `REPO` and **no `--repo`
  flag** — byte-for-byte the operator's own invocation — and its JSON is the
  single source of truth for every section.
- Removed the duplicate ssh auth probe (the exit-1-on-success semantics stay
  owned by the checker). The Authentication section is now derived: ssh
  available iff `method == ssh`; helper/gh lines annotated with `(in use)`
  iff the checker selected them. Status can no longer contradict the checker.
- The Push capability section renders the already-fetched verdict; no second
  invocation, no re-interpretation.
- Fail-closed exactly as specified: missing checker → `CHECKER_UNAVAILABLE`,
  invalid JSON → `CHECKER_OUTPUT_UNPARSEABLE`, anything but `READY` →
  `BLOCKED`. Never READY on any of these paths.
- Incidental find while fixing: the 0.2.1 parser read the wrong `sed` lines
  on BLOCKED (first reason code landed in "method", all-codes line was never
  read). The parser now emits a stable 3-line layout (verdict / method /
  codes).

## Tests (`tests/test_git_status.py`, written first — 1 failed pre-fix)

- New: linked worktree (real `git worktree add`, `.git` file) + exit-1 ssh
  success text + succeeding `ls-remote` → `push READY` / `method ssh`
  (failed pre-fix with `BLOCKED REMOTE_UNREACHABLE` — the reported bug).
- New: linked worktree with no auth → still `BLOCKED`, never READY.
- Kept: READY displays READY, BLOCKED displays BLOCKED + reason, garbage
  checker output fails closed, no token/password output, display contract
  (sections, redaction, exit 0).

Results: new suite 7/7; `test_git_auth` 9/9, `test_promotion_operator` 15/15,
delivery 82/82, AEC 179/179 — all green. `git diff --check` clean.

## Commit

One commit: `fix(workflow): fix git status remote readiness probe` — do not
push, do not merge.

**READY TO PUSH.** Waiting for operator.
