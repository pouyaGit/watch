# Stage R23.2-DEPLOY — Research Agent Deployment

## 0. Determination (not a guess)

**B) The R23 implementation exists only as uncommitted WSL working-tree files.**

Evidence:

- `git log --all --oneline --decorate -- ai/research_agent
  systemd/watch-research.service` → **empty**. No commit on any branch, stash,
  or tag contains the R23 paths (only branch is `main`; stash list empty; no
  tags).
- Live `git ls-remote origin HEAD` → `42644bc` (the D8 commit), identical to
  WSL `main`. Origin does **not** contain R23.
- WSL `main` == origin HEAD (`42644bc`); the local `origin/main` ref is merely
  stale (`3f066c0`, refreshed on next fetch — harmless).
- Google VM (`pouya_behnia@35.202.201.30:/opt/watch`): branch `main` at
  `42644bc`, working tree clean, **all 11 expected R23 paths MISSING**.

There is therefore **no existing R23 commit to deploy** — not locally, not on
origin, not on the VM. Per instructions, **no commit was invented and nothing
was pushed**.

## 1. Where the R23 implementation was found

`/opt/watch` on this WSL box, branch `main`, as uncommitted changes only:

**Modified tracked files** (`git diff --stat`: 8 files, **395 insertions, 0
deletions** — purely additive):

1. `ai/research_cli.py` (+274)
2. `backend/routers/pages.py` (+7)
3. `backend/routers/programs.py` (+1)
4. `backend/routers/research.py` (+16)
5. `backend/routers/research_pages.py` (+62)
6. `backend/routers/runs.py` (+1)
7. `web/templates/base.html` (+2)
8. `web/templates/dashboard.html` (+32)

**New untracked files** (all 11 expected paths PRESENT, plus 2 UI templates):

9. `ai/research_agent/__init__.py`
10. `ai/research_agent/agent.py`
11. `ai/research_agent/scheduler.py`
12. `ai/research_agent/sources.py`
13. `ai/research_agent/prompts.py`
14. `ai/research_agent/storage.py`
15. `ai/schemas/research_agent.py`
16. `backend/research_agent.py`
17. `tests/test_research_agent.py`
18. `systemd/watch-research.service` (includes the R23.2
    `WATCH_RESEARCH_ENABLED=true` / `WATCH_RESEARCH_NETWORK=true` lines)
19. `systemd/watch-research.timer`
20. `web/templates/research_agent.html`
21. `web/templates/research_agent_run.html`

## 2. Exact commit(s) involved

None. No R23 commit exists. Reference commits on both sides:

- WSL `main` = `42644bc` "fix(ui): repair research navigation and recent
  operations"
- Origin live HEAD = `42644bc` (same commit)
- Google VM `main` = `42644bc` (same commit)

## 3. WSL vs Google VM state before deployment

| | WSL (`/opt/watch`) | Google VM (`/opt/watch`) |
|---|---|---|
| Branch | `main` | `main` |
| HEAD | `42644bc` | `42644bc` |
| Tree | R23 changes uncommitted (§1) | clean (only VM-local untracked runtime dirs) |
| R23 source files | all present (uncommitted) | all 11 paths MISSING |
| `database/db.py` | unmodified | — (not touched by this task) |

VM working tree (untouched, VM-local only): `agent-reports/stage-r23-2-final-google-vm.md`,
`ai_data/knowledge/`, `ai_data/reports/`, `crawl/output/`, `dns-bruteforce/`.

## 4. How deployment / synchronization was performed

**It was not — deployment is blocked pending a manual user commit+push.**
There is no commit to pull, so no VM-side `git pull`/`checkout` was run (there
was nothing correct to update to). All VM access was read-only:

- SSH key: the brief's `$env:USERPROFILE\.ssh\google_watch` maps here to
  `/mnt/c/Users/Pouya/.ssh/google_watch`, which SSH refuses (mode 777 on the
  Windows mount). A `0600` copy was staged at `~/.ssh/google_watch` for this
  read-only inspection only (key verified loadable, ed25519).
- VM commands executed (read-only, `BatchMode=yes`, timeouts):
  `git status --short`, `git branch --show-current`, `git log --oneline -8`,
  and a `test -e` existence loop over the 11 expected R23 paths.

**What the user must run manually** (exact recipe; `database/db.py`,
`ai_data/*`, and `agent-reports/*` stay out — note `ai_data/knowledge/` and
`ai_data/reports/` are *not* gitignored, so never use `git add -A`):

```
cd /opt/watch
git add \
  ai/research_agent/__init__.py \
  ai/research_agent/agent.py \
  ai/research_agent/scheduler.py \
  ai/research_agent/sources.py \
  ai/research_agent/prompts.py \
  ai/research_agent/storage.py \
  ai/schemas/research_agent.py \
  backend/research_agent.py \
  tests/test_research_agent.py \
  systemd/watch-research.service \
  systemd/watch-research.timer \
  web/templates/research_agent.html \
  web/templates/research_agent_run.html \
  ai/research_cli.py \
  backend/routers/pages.py \
  backend/routers/programs.py \
  backend/routers/research.py \
  backend/routers/research_pages.py \
  backend/routers/runs.py \
  web/templates/base.html \
  web/templates/dashboard.html
git status --short   # must show ONLY the 21 paths above; database/db.py absent
git diff --cached --check
git commit -m "feat(research): add autonomous research scheduler (R23)"
git push             # <-- user runs this manually
```

Then on the VM (normal Git workflow): `git pull --ff-only` (clean tree, will
fast-forward), followed by the §6–§8 checks.

## 5. Exact Google VM commit after deployment

Not applicable — no deployment occurred. VM remains at `42644bc`.

## 6. File verification

- WSL: all 11 expected R23 paths PRESENT (plus the 2 UI templates).
- Google VM: all 11 expected R23 paths MISSING (verified via `test -e` loop).
- `systemd/watch-research.service` on WSL contains
  `Environment="WATCH_RESEARCH_ENABLED=true"` and
  `Environment="WATCH_RESEARCH_NETWORK=true"`, and does **not** contain
  `WATCH_RESEARCH_LLM=true` (LLM remains disabled for first activation, as
  required).

## 7. Test result

Not run on the VM (no test file there — nothing to run). WSL suite status for
the record: `python3 -m unittest tests.test_research_agent` → 92 tests OK
(R23.1 report). Post-deployment VM command:

```
python3 -m unittest tests.test_research_agent
```

## 8. systemd-analyze result

Not run on the VM (no unit files there). WSL: `systemd-analyze verify
systemd/watch-research.service systemd/watch-research.timer` → exit 0 (R23.2
report). Post-deployment VM commands (read-only, no install/reload/enable):

```
systemd-analyze verify systemd/watch-research.service systemd/watch-research.timer
```

Units must **not** be copied to `/etc/systemd/system`, no `daemon-reload`, no
enable/start — timer activation is a separate explicit step.

## 9. Confirmation timer was NOT activated

Confirmed: no `daemon-reload`, no `enable`, no `start` was executed anywhere.
The units exist only under `/opt/watch/systemd/` on WSL (not installed); the
VM has no unit files at all.

## 10. Confirmation service was NOT started

Confirmed: `watch-research.service` was never started (manually or otherwise);
no research run, no Nuclei, no PoC, no 5B–5J contact was triggered by this
task.

## 11. Any remaining issue

1. **Blocking**: R23 is uncommitted → user must commit (exact list in §4) and
   push, then fast-forward the VM. Until then the VM cannot receive R23.
2. The stale local `origin/main` ref (`3f066c0`) refreshes itself on the next
   fetch; harmless.
3. `ai_data/knowledge/` and `ai_data/reports/` are untracked-but-not-ignored
   on both sides — the explicit file list in §4 (never `git add -A`) keeps
   generated artifacts out of the deployment commit.
4. `ai_data/research/` IS gitignored, so agent result JSONs are correctly
   excluded from git by default and are not a deployment substitute.

## Agent / Model
- Model: opencode-go/deepseek-flash
- Stage: R23.2-DEPLOY
- Role: Research Agent Deployment
