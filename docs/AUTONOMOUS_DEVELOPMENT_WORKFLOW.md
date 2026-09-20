# Watch — Autonomous Development Workflow

This document describes the two-workspace model used to develop Watch
autonomously, the branch and commit rules, and the helper commands under
`scripts/watch-agent/`.

The goal is simple: an operator should manage the autonomous agent with a
few commands instead of a long sequence of manual `git` and `tmux`
invocations, and no helper command should ever be able to push, reset, or
touch production.

---

## 1. Workspaces

Watch uses **one repository** with **two working trees**:

| Workspace | Path | Branch | Purpose |
|-----------|------|--------|---------|
| Production checkout | `/opt/watch` | `main` | Runs production services, jobs, systemd units and the live database connections. |
| Development worktree | `/opt/watch/.worktrees/watch-agent` | `agent/daily-development` | Where the autonomous agent reads, edits, tests and commits. |

Both working trees share the same Git object store and refs
(`/opt/watch/.git`). A commit made in the worktree is immediately visible
as a ref to the production checkout, but **the production working tree
files are never touched** by agent operations.

### Hard rules

- **Never edit files under `/opt/watch` directly.** All development happens
  in `/opt/watch/.worktrees/watch-agent`.
- Never modify production services, systemd units, running processes,
  production databases, or production configuration from the agent.
- The worktree directory (`.worktrees/`) is ignored by Git so it never
  appears as an untracked project change.

### Production vs Agent Workspace

The helper commands are **context aware**. Every helper detects where it is
running and adapts:

| Where you run it | Detected mode | Path |
|------------------|---------------|------|
| Production checkout | `MODE: PRODUCTION` | `/opt/watch` |
| Autonomous worktree | `MODE: AGENT` | `/opt/watch/.worktrees/watch-agent` |

- `/opt/watch` = **production**. It runs production services, jobs, systemd
  units and the live database connections. A helper run here shows
  production state and points you at the agent workspace; it does **not**
  emit agent-only warnings such as `expected agent branch ...`.
- `/opt/watch/.worktrees/watch-agent` = **autonomous development**. A helper
  run here shows the agent branch, `HEAD`, commits, reports and the
  `READY TO PUSH` assessment.

The single question "am I in production or in the agent workspace?" is
therefore answered for you: whichever copy of the helper you run, its
`MODE:` line tells you where you are, and when you are in production it
prints the exact command to move to the agent workspace.

Detection is path based. The helper resolves its own checkout root and
compares it with the production checkout (`WATCH_PROD_DIR`, default
`/opt/watch`) and the agent worktree (`WATCH_AGENT_DIR`, default
`<production>/.worktrees/watch-agent`). The shared logic lives in
`scripts/watch-agent/_context.sh`, which is sourced by all four helpers.
If a checkout matches neither path but is on `agent/daily-development`, it
is treated as `MODE: AGENT`; otherwise the mode is `UNKNOWN` and the helper
behaves like an agent workspace without production guidance.

Example — running `status.sh` from production:

```text
== Context ==
  MODE: PRODUCTION
  ...

  Production checkout detected.
  Agent workspace:
    /opt/watch/.worktrees/watch-agent
  Suggested command:
    cd /opt/watch/.worktrees/watch-agent
```

Example — running `status.sh` from the agent worktree:

```text
== Context ==
  MODE: AGENT
  ...
```

---

## 2. Directory layout

```
/opt/watch/                       # production checkout (main)
├── .git/                         # shared object store + refs
├── .gitignore                    # ignores .worktrees/, runtime data, secrets
├── .worktrees/
│   └── watch-agent/              # development worktree (agent/daily-development)
│       ├── scripts/watch-agent/  # operational helper commands
│       │   ├── _context.sh       # shared production/agent context detection
│       │   ├── start.sh
│       │   ├── status.sh
│       │   ├── review.sh
│       │   └── sync.sh
│       ├── docs/                 # this document and other docs
│       ├── agent-reports/        # task reports (permanent project artifacts)
│       └── ...                   # source, tests, templates, ai/
└── ...
```

Tracked / preserved by Git:

- source code (`ai/`, `backend/`, `web/`, `database/`, ...)
- tests (`tests/`, `ai/test_*.py`)
- documentation (`docs/`, `README.md`, `AGENTS.md`)
- agent reports (`agent-reports/`)
- deterministic research artifacts that are already tracked

Ignored by Git (runtime / generated / development-only):

- `.worktrees/` — the agent worktree itself
- `.env` — credentials
- `ai_data/research/`, `ai_data/cve/`, `ai_data/raw/` — runtime research data
- `crawl/output/`, `dns-bruteforce/work/` — crawler / DNS runtime output
- `*.log`, `*.tmp`, Python caches, virtualenvs, IDE files

> Ignoring `ai_data/research/` is deliberate: research output is runtime
> data, not source. Do not "fix" this by force-adding large generated
> artifacts. Meaningful, deterministic research evidence belongs in
> `agent-reports/` or an explicit tracked location, not in the runtime dir.

---

## 3. Branch model

```
origin/main ──●───────────────●  (integration baseline)
               \             /
                ●───●───●───●    agent/daily-development (agent commits)
```

- `main` — production / integration branch. Only humans fast-forward or
  merge into it. The agent never pushes it.
- `agent/daily-development` — the agent's working branch. All autonomous
  commits land here.
- `origin/main` — the remote baseline used for review and unpushed-commit
  comparison.

The review base is resolved in this order:

1. `WATCH_BASE_BRANCH` (explicit override), else
2. `origin/main`, else
3. `main`.

`origin/main` is preferred because the local `main` may already have been
fast-forwarded to the agent branch by the operator, which would make
"commits since main" empty.

---

## 4. tmux workflow

The agent runs inside a tmux session so long-running work survives
disconnects.

- Session name: `watch-agent` (override with `WATCH_TMUX_SESSION`).
- Create: `tmux new -s watch-agent -c /opt/watch/.worktrees/watch-agent`
- Attach: `tmux attach -t watch-agent`
- Detach: `Ctrl-b` then `d`

`scripts/watch-agent/start.sh` prints the correct create/attach command for
the current state. Pass `--attach` to attach automatically when the session
already exists.

---

## 5. Helper commands

All helpers live in `scripts/watch-agent/`. They are **read-only visibility
and preparation tools** and they are **context aware** (see
"Production vs Agent Workspace" above). They never push, merge, rebase,
reset, clean, delete files, or touch production.

| Command | Purpose |
|---------|---------|
| `scripts/watch-agent/start.sh [--attach]` | Show the detected mode, environment, branch, HEAD, clean/dirty status and tmux guidance. In production it points at the agent workspace; in the agent worktree it shows the agent branch and next commands. |
| `scripts/watch-agent/status.sh` | One-command overview. In production: `MODE: PRODUCTION`, production state and a `cd` hint. In the agent worktree: `MODE: AGENT`, branch, commit, remote tracking, changed files, latest commits, pending agent reports. |
| `scripts/watch-agent/review.sh` | Pre-merge/pre-push review: commits and files since the base, tests/report availability, latest report READY TO PUSH, and an overall assessment. Run from production it explains that review normally runs from the agent workspace and performs no agent review. |
| `scripts/watch-agent/sync.sh` | Fetch `origin` and show branch relationships (production sync status or agent branch sync status). No merge, no reset, no rebase, no push. |
| `scripts/watch-agent/_context.sh` | Shared context detection sourced by the helpers. Not run directly. |

Environment overrides (all optional):

| Variable | Default | Meaning |
|----------|---------|---------|
| `WATCH_PROD_DIR` | `/opt/watch` | Production checkout path. |
| `WATCH_AGENT_DIR` | `<production>/.worktrees/watch-agent` | Agent worktree path. |
| `WATCH_AGENT_BRANCH` | `agent/daily-development` | Expected agent branch. |
| `WATCH_MAIN_BRANCH` | `main` | Integration branch. |
| `WATCH_BASE_BRANCH` | `origin/main` | Review base override. |
| `WATCH_TMUX_SESSION` | `watch-agent` | tmux session name. |
| `WATCH_REMOTE` | `origin` | Git remote. |
| `NO_COLOR` | unset | Disable ANSI colour in script output. |

---

## 6. Commit rules

- Inspect first: `git status`, `git diff`, `git log --oneline -10`.
- Commit only the files that belong to the current task.
- Never commit secrets, `.env` values, credentials, or large runtime data.
- Write a concise, descriptive message consistent with the repository style
  (`feat(area): ...`, `fix(area): ...`, `docs(...): ...`,
  `perf(research): ...`, ...).
- Do not amend or rewrite shared history.
- Do not commit unrelated pre-existing changes.

Checklist before committing:

```bash
git status                 # only intended files changed
git diff --check           # no whitespace errors
# run the relevant tests
git add <intended files>
git commit -m "feat(area): concise description"
```

---

## 7. Push rules

- **Push is always manual.** The agent and all helper scripts never push.
- The operator reviews the branch with `review.sh`, then pushes manually
  when satisfied.
- Never force-push or rewrite shared history.
- Never push directly to `main` from the agent workflow.

---

## 8. Review flow

1. `scripts/watch-agent/sync.sh` — fetch `origin` and confirm branch
   relationships.
2. `scripts/watch-agent/status.sh` — confirm the branch, commit, clean tree
   and pending reports.
3. `scripts/watch-agent/review.sh` — read commits, changed files, tests and
   the latest report's READY TO PUSH assessment.
4. Run the relevant tests yourself (the review helper only reports
   availability).
5. Push manually when `READY TO PUSH: YES`.

`review.sh` reports `READY TO PUSH: YES` only when:

- the working tree is clean,
- there is at least one commit since the base, and
- the latest agent report contains `READY TO PUSH: YES`.

It never merges and never pushes.

---

## 9. Daily operation examples

### Start of a session

```bash
cd /opt/watch/.worktrees/watch-agent
scripts/watch-agent/start.sh            # environment + tmux guidance
scripts/watch-agent/start.sh --attach   # attach if the session exists
```

### During development

```bash
scripts/watch-agent/status.sh           # quick overview any time
git status && git diff                  # inspect before committing
# ... edit, test, commit ...
```

### Before integration / push

```bash
scripts/watch-agent/sync.sh             # fetch origin, show relationships
scripts/watch-agent/review.sh           # commits, files, tests, readiness
# operator pushes manually
```

### A complete autonomous task

```bash
cd /opt/watch/.worktrees/watch-agent
scripts/watch-agent/start.sh
# implement the task
git status && git diff --check
python3 -m unittest tests.test_<relevant>     # run focused tests
git add <files> && git commit -m "feat(area): ..."
# write agent-reports/<task>-report.md
git add agent-reports/<task>-report.md && git commit -m "docs(report): ..."
scripts/watch-agent/review.sh
```

---

## 10. Safety guarantees

The helper scripts are intentionally incapable of destructive actions:

- no `git push`
- no `git reset --hard`
- no `git clean`
- no file deletion
- no merge / rebase / stash manipulation
- no modification of the production checkout
- no service restarts

Context detection (via `scripts/watch-agent/_context.sh`) is itself
read-only: it resolves paths, reads the current branch and prints guidance.
It never writes, checks out, or changes any ref.

They only read Git state, `git fetch` remote refs (safe), and print
guidance. Any destructive or production action remains an explicit human
decision.
