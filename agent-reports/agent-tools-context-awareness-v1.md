# Agent Tools Context Awareness v1 — Report

## TASK

Make the autonomous workflow helper scripts under `scripts/watch-agent/`
(`start.sh`, `status.sh`, `review.sh`, `sync.sh`) context aware so they behave
correctly in both supported environments instead of assuming they always run
inside the agent worktree:

1. Production checkout — `/opt/watch`
2. Agent development worktree — `/opt/watch/.worktrees/watch-agent`

Before this task, running a helper from the production checkout produced
misleading agent-only warnings such as `expected agent branch
agent/daily-development`. After this task, one command tells the operator the
current mode (`PRODUCTION` or `AGENT`) and the correct next action regardless
of where it is run.

Constraints respected: only `scripts/watch-agent/` and related documentation
were modified; no application code was touched; `/opt/watch` was never
modified; nothing was merged, rebased, reset or pushed.

## SUMMARY

A shared context detector, `scripts/watch-agent/_context.sh`, is now sourced
by all four helpers. It resolves:

- the directory of the running helper (`WATCH_SCRIPT_DIR`),
- the repository root of the running helper (`WATCH_WORKTREE_ROOT`),
- the production checkout (`WATCH_PRODUCTION_DIR`, `WATCH_PROD_DIR`,
  default `/opt/watch`),
- the agent worktree (`WATCH_AGENT_DIR`, default
  `<production>/.worktrees/watch-agent`),
- the invocation directory (`WATCH_INVOKED_FROM`).

It then sets `WATCH_MODE` to `PRODUCTION`, `AGENT` or `UNKNOWN`:

- `WATCH_WORKTREE_ROOT == WATCH_PRODUCTION_DIR` -> `PRODUCTION`;
- `WATCH_WORKTREE_ROOT == WATCH_AGENT_DIR` -> `AGENT`;
- otherwise, if the checkout is on `agent/daily-development` -> `AGENT`;
- otherwise -> `UNKNOWN` (behaves like the agent workflow without production
  guidance).

The detector is read-only: it only canonicalises paths, reads the current
branch and prints guidance. It never writes, checks out or changes any ref.

Behavior by mode:

- **status.sh**
  - Production: prints `MODE: PRODUCTION`, the production branch/commit,
    production working-tree state and recent production commits, then prints
    the agent workspace path and the suggested `cd` command. It then exits
    before any agent-only warning. No false warnings.
  - Agent: prints `MODE: AGENT`, then the existing overview (branch, remote
    tracking, working tree, commits, pending/recent reports) and keeps the
    `expected agent branch` warning only when the branch is genuinely wrong.
- **review.sh**
  - Production: explains that review should normally run from the agent
    workspace, shows the current production state, the agent workspace
    location, and explicitly states that no agent review was performed.
  - Agent: unchanged pre-push review (commits/files since base, diff stat,
    tests/reports changed, latest report fields, `READY TO PUSH` assessment).
- **start.sh**
  - Production: shows the agent workspace location and how to enter it, plus
    production state and tmux guidance. `--attach` is intentionally ignored
    in production so the operator enters the agent workspace first.
  - Agent: branch, `HEAD`, working-tree state, tmux status and next commands.
- **sync.sh**
  - Production: prints `MODE: PRODUCTION` and production sync status
    (`vs origin/main`, `vs main`, unpushed commits), then notes that agent
    branch checks are skipped.
  - Agent: prints `MODE: AGENT` and the agent branch sync status
    (`vs origin/main`, `vs main`, `vs agent/daily-development`, unpushed
    commits).

Documentation `docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md` gained a
"Production vs Agent Workspace" section, an updated directory layout, updated
helper descriptions, the new `WATCH_AGENT_DIR` override and a safety note
that context detection is read-only.

No destructive Git operation is present anywhere: the scripts only use
`rev-parse`, `branch --show-current`, `log`, `status`, `diff`, `rev-list`
and `fetch`.

## FILES CHANGED

New:

- `scripts/watch-agent/_context.sh` — shared context detection (executable).

Modified:

- `scripts/watch-agent/status.sh` — context-aware production vs agent output.
- `scripts/watch-agent/review.sh` — production short-circuit + no false review.
- `scripts/watch-agent/start.sh` — context-aware entry guidance.
- `scripts/watch-agent/sync.sh` — production vs agent sync status.
- `docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md` — "Production vs Agent Workspace"
  and related updates.

Not modified: any application code, `ns/`, `crawl/`, `database/`, Nuclei/CVE,
`/opt/watch`.

## TESTS

Syntax:

```bash
bash -n scripts/watch-agent/*.sh
# -> SYNTAX OK
```

Safety scan (no destructive/unexpected Git verbs; only comments and error
strings matched `checkout`):

```bash
grep -nE "git_? +(push|merge|rebase|reset|clean|checkout|switch|stash|branch +-D)" scripts/watch-agent/*.sh
grep -nE "\brm\b|rm -rf|> /opt/watch|touch /opt/watch|mv /opt/watch" scripts/watch-agent/*.sh
# -> no unsafe commands
```

Whitespace:

```bash
git diff --check
# -> clean
```

Functional — agent workspace (real):

```bash
cd /opt/watch/.worktrees/watch-agent
NO_COLOR=1 scripts/watch-agent/status.sh    # MODE: AGENT, normal overview
NO_COLOR=1 scripts/watch-agent/start.sh     # MODE: AGENT, branch/HEAD/tmux/next
NO_COLOR=1 scripts/watch-agent/review.sh    # MODE: AGENT, full pre-push review
NO_COLOR=1 scripts/watch-agent/sync.sh      # MODE: AGENT, fetch + agent sync
```

Functional — production checkout (simulated, because `/opt/watch` must not be
modified). A throwaway Git checkout was created under `/tmp/opencode` with the
updated helper copies, and `WATCH_PROD_DIR` was pointed at it so the path-based
detector classifies it as production:

```bash
mkdir -p /tmp/opencode/watch-prod-sim/scripts/watch-agent
cp /opt/watch/.worktrees/watch-agent/scripts/watch-agent/*.sh \
   /tmp/opencode/watch-prod-sim/scripts/watch-agent/
git -C /tmp/opencode/watch-prod-sim init -q
# ... baseline commit ...

cd /tmp/opencode/watch-prod-sim
export WATCH_PROD_DIR=/tmp/opencode/watch-prod-sim
NO_COLOR=1 scripts/watch-agent/status.sh    # MODE: PRODUCTION, no false warning
NO_COLOR=1 scripts/watch-agent/start.sh     # MODE: PRODUCTION, agent workspace hint
NO_COLOR=1 scripts/watch-agent/review.sh    # MODE: PRODUCTION, "no agent review"
NO_COLOR=1 scripts/watch-agent/sync.sh      # MODE: PRODUCTION, production sync
```

The simulated production checkout is on `master` (definitely not
`agent/daily-development`), which is exactly the case that previously
triggered the false `expected agent branch` warning. All four scripts printed
`MODE: PRODUCTION` and produced no agent-branch warning.

## RESULTS

- `bash -n` passed for all scripts including `_context.sh`.
- All four helpers detect `MODE: AGENT` from the real worktree and behave as
  before there.
- All four helpers detect `MODE: PRODUCTION` from the simulated production
  checkout and print the agent workspace path plus the suggested
  `cd /opt/watch/.worktrees/watch-agent` command.
- No `expected agent branch agent/daily-development` warning is emitted in
  production mode.
- `review.sh` in production explicitly reports that no agent review was
  performed.
- `sync.sh` performs only `git fetch` plus reporting; no merge, rebase, reset,
  clean or push exists in any script.
- `git diff --check` reported no whitespace errors.
- `/opt/watch` was not modified.

Known limitation: production detection is path based. A copy of the helpers
placed somewhere other than the production checkout or the agent worktree
reports `MODE: UNKNOWN` (and then behaves like the agent workflow) unless it
is on `agent/daily-development`. This is intentional and prevents accidental
destructive behavior in unrecognised checkouts.

## COMMIT STATUS

Committed on `agent/daily-development`.

## PUSH STATUS

Not pushed. Push is always manual.

## READY TO PUSH

YES
