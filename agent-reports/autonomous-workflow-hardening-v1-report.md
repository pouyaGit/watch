# Autonomous Workflow Hardening v1 — Report

## TASK

Reduce manual Git/Agent management overhead and create a reliable
autonomous development workflow for the Watch project, operating only in the
development worktree `/opt/watch/.worktrees/watch-agent` (never modifying
`/opt/watch`).

Deliverables:

- Git hygiene (ignore development-only artifacts; preserve source, tests,
  reports and deterministic research artifacts).
- A small operational helper layer under `scripts/watch-agent/`
  (`start.sh`, `status.sh`, `review.sh`, `sync.sh`).
- Workflow documentation at `docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md`.
- Safety: helpers are visibility/preparation tools only.
- Testing, commit, and this report.

## SUMMARY

The repository is a single Git repository with two working trees sharing
one object store:

- production checkout `/opt/watch` on `main`;
- development worktree `/opt/watch/.worktrees/watch-agent` on
  `agent/daily-development`.

Inspection found two hygiene issues and no operational helper layer:

1. `.worktrees/` was not ignored, so the agent worktree appeared as an
   untracked project change in the production checkout.
2. `.gitignore` contained a corrupted line,
   `!programs/watch_sync_programs.pyai_data/raw/`, created by two rules that
   had been merged without a newline. This both failed to un-ignore
   `programs/watch_sync_programs.py` and failed to ignore the runtime
   directory `ai_data/raw/`.

Both were fixed without removing files and without changing existing
tracked content. A read-only helper layer and a workflow document were
added. All four helper scripts pass `bash -n`, run successfully from any
working directory, and use only read-only Git commands plus `git fetch`
(explicitly permitted). No destructive or production-touching command
exists in any script.

## FILES CHANGED

Modified:

- `.gitignore`
  - added `# Development worktrees` + `.worktrees/`
  - repaired the corrupted line into two rules:
    `!programs/watch_sync_programs.py` and `ai_data/raw/`

New:

- `scripts/watch-agent/start.sh` (executable)
- `scripts/watch-agent/status.sh` (executable)
- `scripts/watch-agent/review.sh` (executable)
- `scripts/watch-agent/sync.sh` (executable)
- `docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md`
- `agent-reports/autonomous-workflow-hardening-v1-report.md` (this report)

No source, test, template, `ai/`, `backend/`, `database/`, `ns/`, `crawl/`
or Nuclei/CVE file was changed.

## IMPLEMENTATION DETAILS

### Git hygiene (`.gitignore`)

- `.worktrees/` is now ignored (anchored to the repository root), so the
  development worktree no longer appears as an untracked change.
- The corrupted merged line was split into
  `!programs/watch_sync_programs.py` (restores the intended un-ignore; the
  file is already tracked, so this is a no-op today) and `ai_data/raw/`
  (restores the intended runtime-data ignore).
- No existing ignore rule was removed. Existing deliberate ignores were
  preserved: `ai_data/research/`, `ai_data/cve/`, `.env`, `crawl/output/`,
  `dns-bruteforce/work/`, logs, caches, virtualenvs.
- Meaningful reports and documentation remain tracked (`agent-reports/`,
  `docs/`, `scripts/` are not ignored).

### Helper layer (`scripts/watch-agent/`)

All scripts resolve the worktree root from their own location
(`<root>/scripts/watch-agent/../..`), operate via `git -C <worktree>`, and
therefore work from any current directory. Each supports `NO_COLOR` and
uses ANSI colour only on a TTY.

- `start.sh [--attach]` — prints the worktree/production paths, the invoked
  directory (and warns if invoked from the production checkout), the
  current branch, short HEAD + subject, whether the expected agent branch
  is checked out, clean/dirty status with the changed files, and the correct
  tmux create/attach command. `--attach` attaches only when a TTY and the
  session already exists; otherwise it warns instead of erroring.
- `status.sh` — branch, commit, upstream tracking and ahead/behind versus
  `origin/main` and `main`, working-tree status, the latest 10 commits,
  pending (untracked/modified) agent reports, and the most recent report
  files.
- `review.sh` — review base resolution (`WATCH_BASE_BRANCH` → `origin/main`
  → `main`), commits since the base, changed files, diff stat, tests changed
  in the range, agent reports changed in the range, the latest report's
  `COMMIT STATUS` / `PUSH STATUS` / `READY TO PUSH` values, and an overall
  `READY TO PUSH` assessment. It never merges and never pushes.
- `sync.sh` — runs `git fetch <remote>` (default `origin`) and reports
  branch relationships and unpushed commits. It never merges, rebases,
  resets, cleans or pushes, and continues gracefully when the fetch fails
  (e.g. offline).

### Safety guarantees

Verified by scanning every script: the only Git subcommands used are
`branch`, `diff`, `fetch`, `log`, `remote`, `rev-list`, `rev-parse`,
`status`. There is no `push`, `reset`, `clean`, `merge`, `rebase`, `rm`,
`mv`, force-checkout, branch delete, worktree remove or stash manipulation.
No script writes to `/opt/watch` or restarts services.

### Review-base note

In the inspected environment the local `main` had been fast-forwarded by the
operator to the agent branch, so "commits since `main`" was empty while
`origin/main` remained the true integration baseline. `review.sh` therefore
resolves the base as `WATCH_BASE_BRANCH` → `origin/main` → `main` and prints
the base it used, which keeps the review meaningful in both states.

## TESTS

Shell syntax:

```
for f in scripts/watch-agent/*.sh; do bash -n "$f"; done
```

Script execution (from the worktree and from `/tmp` to prove
cwd-independence):

```
scripts/watch-agent/start.sh
scripts/watch-agent/start.sh --attach
scripts/watch-agent/status.sh
scripts/watch-agent/review.sh
scripts/watch-agent/sync.sh
```

Hygiene checks:

```
git check-ignore -v .worktrees/ ai_data/raw/ agent-reports/ scripts/ docs/
git status --porcelain --ignored=no
git diff --check
git -C /opt/watch status --short        # read-only production check
```

## RESULTS

- `bash -n` — **all four scripts pass syntax validation**.
- `start.sh` — **exit 0**; correct environment, branch, HEAD, dirty status
  and tmux guidance. `--attach` on a non-TTY now warns
  ("stdout is not a terminal") instead of failing to open a terminal.
- `status.sh` — **exit 0**; branch `agent/daily-development`, commit
  `6504828`, `vs origin/main behind 0, ahead 2`, `vs main behind 0, ahead 0`,
  no upstream configured (reported as a warning, not an error), latest
  commits and recent reports listed.
- `review.sh` — **exit 0**; base `origin/main`, 2 commits, 12 changed files,
  diff stat, `tests/test_command_center.py` flagged as the changed test, the
  changed agent report listed, and the latest report fields parsed
  (`COMMIT STATUS: COMMITTED — 4f46a6c…`, `PUSH STATUS: NOT PUSHED — MANUAL
  PUSH REQUIRED`, `READY TO PUSH: YES`). Assessment correctly reported
  `READY TO PUSH: NO` only because the working tree was dirty at the time
  (this mission's files were still uncommitted).
- `sync.sh` — **exit 0**; `git fetch origin` succeeded, relationships
  reported, unpushed commits listed, and no local branch changed.
- All scripts run with exit 0 from `/tmp` (cwd-independent).
- `.gitignore` verification: `.worktrees/` → ignored (`.gitignore:66`),
  `ai_data/raw/` → ignored (`.gitignore:58`), `agent-reports/`, `scripts/`,
  `docs/` → not ignored. `git diff --check` clean.
- Production checkout not modified (`git -C /opt/watch` is read-only
  inspection only).

## COMMIT STATUS

```
COMMIT STATUS:
  COMMITTED — 0af7538
```

## PUSH STATUS

```
PUSH STATUS:
  NOT PUSHED — MANUAL PUSH REQUIRED
```

## READY TO PUSH

```
READY TO PUSH:
  YES
```

The implementation is complete, the helper scripts are syntactically valid
and run correctly, the `.gitignore` hygiene fixes are verified, only
intended files are changed, the production checkout was not modified, and
the code commit exists. Push remains a manual operator action.
