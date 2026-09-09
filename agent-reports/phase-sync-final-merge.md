# Phase Sync Final Merge — WSL/Google One-Clean-Sync

Date: 2026-09-09 (UTC). Operator task: ONE clean synchronization of all valid
changes, preserving both WSL work and Google changes. No push. No history
rewrite. No reset/clean. No Mongo changes.

> Note: an earlier report under this same filename described the 3fb65cc merge
> itself. Per agent-report rules it was deleted and this file was created FROM
> SCRATCH for the current final-sync task. History of the earlier merge is
> summarized in §1, not appended.

## 1. Starting state

- WSL starting HEAD: `3fb65cc66e2a88186c2eebd85ace879a0d6497e9`
  (`Merge remote-tracking branch 'origin/main'`)
  - Parent 1 (WSL fail-fast): `ba44f02f4283f7aa1889a697df49f6b0ab83715f`
    (`fix(pipeline): fail fast on missing tooling`)
  - Parent 2 (Google checkpoint): `012d3583b3de9692ac65c62d6ba6db433efaff82`
    (`chore: checkpoint controlled validation and pipeline work`)
  - Merge base of the two parents: `9af6308`
    (`feat: implement live egress boundary B7`)
  - The 3fb65cc merge itself was a clean auto-merge (no conflicting hunks);
    WSL content + Google mode-only change on `run-pipeline.sh` resolved with
    the WSL fail-fast blob kept at mode 100755.
- Google starting HEAD: `012d3583b3de9692ac65c62d6ba6db433efaff82`
  (same as `origin/main` / `origin/HEAD` at sync time; verified via
  `git rev-parse origin/main` and `git merge-base HEAD origin/main`
  = 012d358, i.e. origin/main is an ancestor of WSL HEAD — already merged).
- This sync runs on the WSL-side checkout (`/opt/watch`, branch `main` at
  3fb65cc). All work below is reconciled INTO this WSL tree.

WSL worktree at start (`git status --short`):

```text
 D Watch_README_completed.md:Zone.Identifier
?? agent-reports/knowledge-base-reality-check.md
?? agent-reports/phase-5k-live-b10-lab-1-environment.md
?? agent-reports/phase-5k-live-b10-lab-2-vulnerability-validation.md
?? agent-reports/phase-5k-live-b10-lab-3-nuclei-template-validation.md
?? agent-reports/phase-5k-live-b10-lab-4-watch-e2e-validation.md
?? agent-reports/phase-5k-live-b10-lab-5-implementation.md
?? agent-reports/phase-5k-live-b10-lab-5-security-review.md
?? agent-reports/phase-5k-live-b10-lab-6-design.md
?? agent-reports/phase-5k-live-b10-lab-7-implementation.md
?? agent-reports/phase-sync-final-merge.md
?? agent-reports/phase-sync-google-checkpoint.md
?? agent-reports/phase-sync-wsl.md
?? agent-reports/stage-r1-seed-readback.md
```

Google worktree as reported for this task (NOT present as files in this
checkout; see §4 on accessibility):

```text
 M ai/research_cli.py
 M run-heavy-guarded.sh
?? agent-reports/knowledge-base-reality-check.md
?? agent-reports/phase-5k-live-b10-lab-1-environment.md
?? agent-reports/phase-5k-live-b10-lab-2-vulnerability-validation.md
?? agent-reports/phase-5k-live-b10-lab-3-nuclei-template-validation.md
?? agent-reports/phase-5k-live-b10-lab-4-watch-e2e-validation.md
?? agent-reports/phase-5k-live-b10-lab-5-implementation.md
?? agent-reports/phase-5k-live-b10-lab-5-security-review.md
?? agent-reports/phase-5k-live-b10-lab-6-design.md
?? agent-reports/phase-5k-live-b10-lab-7-implementation.md
?? agent-reports/phase-sync-google-checkpoint.md
?? agent-reports/stage-r1-seed-readback.md
?? ai/knowledge/xss_seed.py
?? ai/lab/
?? ai/reports/
?? ai/test_lab_adapter.py
?? ai/test_lab_argv.py
?? ai/test_lab_evidence_store.py
?? ai/test_lab_schemas.py
?? ai/test_lab_verdict.py
?? ai/test_lab_verifier.py
?? ai/test_stage_r1.py
?? ai_data/knowledge/
?? crawl/output/
?? dns-bruteforce/
```

## 2. Inspection performed before modifying anything

- `git status --short`, `git branch -vv`, `git log --oneline --graph --all -20`,
  `git remote -v`, `git diff --check`, `git diff --summary`.
- `git show --stat 012d358`; `git diff --stat 012d358..HEAD` (WSL fail-fast
  side: 9 files, +780/-88) and `git diff --stat HEAD..012d358` (mirror).
- `git stash list` (empty), `git reflog`, `git ls-files ai_data ai/lab
  ai/knowledge`, `git check-ignore` on candidate runtime paths,
  `git fsck --lost-found` (only pre-existing cline-checkpoint dangling
  objects; no Google R1/lab blobs recoverable).
- `git ls-files --stage run-heavy-guarded.sh run-pipeline.sh` + worktree
  `stat -c %a` for modes; `git log --all --oneline -S alterx --` and
  `-- run-heavy-guarded.sh` for tooling history.
- Full read of `run-heavy-guarded.sh` (74 lines, no PATH block, mode 644),
  `ai/research_cli.py` (614 lines, pre-R1 baseline: no `kb` group, no
  `write_reference_archive`), `.gitignore` (58/59: `ai_data/research/` and
  `ai_data/cve/` ignored; `ai_data/knowledge/` NOT ignored but runtime data
  per §5), `utils/common.py` canonical `WATCH_TOOL_PATH`
  (robust, explicitly forbids hardcoding `/home/pouya_behnia/go/bin`),
  `tests/test_pipeline_tooling_failfast.py` (asserts no hardcoded home).
- `ls -laR dns-bruteforce ai_data crawl/output ai/lab ai/reports`:
  `ai/lab/`, `ai/reports/`, `ai/test_lab_*`, `ai/test_stage_r1.py`,
  `ai/knowledge/xss_seed.py`, `ai_data/knowledge/`, `crawl/output/` all
  ABSENT in this tree; `dns-bruteforce/` contains only an empty `work/`
  dir; `ai_data/research/*.cli.json` present (tracked-ignored runtime).
- Read all overlapping reports present locally (`knowledge-base-reality-check`,
  `stage-r1-seed-readback`, lab-1..lab-7 incl. 5-security-review and 6-design,
  both prior sync reports) to avoid re-inventing Google code from prose.
- `grep -rn "alterx|go/bin|GOBIN|GOPATH"` and `setup-weekly-jobs.sh`
  (`Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:..."`
  on all 5 heavy units; `ExecStart=/opt/watch/run-heavy-guarded.sh`).

## 3. Files reconciled (this commit)

Tracked source change (1):

| File | Change |
|------|--------|
| `run-heavy-guarded.sh` | +21-line robust tool-PATH block (see §5); git mode 100644 → 100755 (see §6) |

New reports committed (13, all under `agent-reports/`, consistent with the
project convention that sync/validation reports are tracked):

- `knowledge-base-reality-check.md`
- `phase-5k-live-b10-lab-1-environment.md`
- `phase-5k-live-b10-lab-2-vulnerability-validation.md`
- `phase-5k-live-b10-lab-3-nuclei-template-validation.md`
- `phase-5k-live-b10-lab-4-watch-e2e-validation.md`
- `phase-5k-live-b10-lab-5-implementation.md`
- `phase-5k-live-b10-lab-5-security-review.md`
- `phase-5k-live-b10-lab-6-design.md`
- `phase-5k-live-b10-lab-7-implementation.md`
- `phase-sync-google-checkpoint.md` (pre-existing Google checkpoint record)
- `phase-sync-wsl.md` (pre-existing WSL sync-prep record)
- `stage-r1-seed-readback.md` (R1 implementation record)
- `phase-sync-final-merge.md` (this report)

Earlier history (WSL fail-fast + Google B8/B9/B10 checkpoint) is already
preserved in 3fb65cc and untouched by this commit.

## 4. Conflicts / decisions

1. `ai/research_cli.py` (Google `M`, +295-line R1 `kb` group +
   `write_reference_archive` per the R1 report): the Google working-tree
   modification is NOT reachable from this checkout — not in any commit
   (`git diff ba44f02..012d358 -- ai/research_cli.py` is empty), not in
   stash/reflog/dangling objects. Decision: NOT re-implemented or invented
   from prose; local baseline kept byte-identical. No blind checkout/reset.
2. `ai/knowledge/xss_seed.py`, `ai/test_stage_r1.py`, `ai/lab/*` (12+ files),
   `ai/test_lab_*.py` (6 files), `ai/reports/`: all reported as Google
   untracked, all absent here, none recoverable via git objects.
   Decision: reports describing them ARE preserved (§3); code is NOT
   fabricated. Staging a prose-derived guess would violate "no unrelated
   changes" and the XSS/KB attribution rules.
3. `run-heavy-guarded.sh` (Google `M`, 0-line diff per R1 report + PATH/perm
   intent per this task): Google bytes inaccessible, so the fix was
   implemented natively in this tree following existing project conventions
   (`utils/common.py` + `setup-weekly-jobs.sh`) instead of copying an
   unseen diff. Time-window/lock/exec semantics untouched.
4. `Watch_README_completed.md:Zone.Identifier` deletion: Windows ADS artifact,
   unrelated to this sync. Decision: left UNSTAGED and UNCOMMITTED
   (explicit pathspec commit); worktree deletion preserved as-is.
5. Runtime data (`crawl/output/`, `dns-bruteforce/`, `ai_data/knowledge/`,
   `ai_data/research/*.references.json`): `crawl/output/` and
   `ai_data/knowledge/` do not exist here; `dns-bruteforce/` holds only an
   empty `work/` dir (git cannot track empty dirs — nothing staged);
   `ai_data/research/` is gitignored (`.gitignore:58`). Decision: nothing
   generated committed, per instructions and the prior checkpoint precedent
   (crawl/dns-bruteforce excluded as machine output/wordlists).
6. `.gitignore` noted anomaly (line 57 `!programs/watch_sync_programs.pyai_data/raw/`
   reads as a collapsed line) left UNTOUCHED as out-of-scope; no ignore rules
   changed in this sync.
7. No production/live-validation behavior touched: `ai/live_validation/`,
   `ai/verification/`, `ai/evidence/`, `ai/finding/`, `ns/`, `crawl/`,
   `database/` all clean (`git diff HEAD --name-only` outside this commit's
   pathspec is only the excluded Zone.Identifier deletion).

## 5. PATH / tooling fix

Problem: `run-heavy-guarded.sh` is the `ExecStart` of all 5 heavy systemd
units but set no PATH itself; systemd PATH is minimal and never sources
`~/.zshrc`, so Go tools (notably `alterx`, expected via `~/go/bin` on the
Google VM at `/home/pouya_behnia/go/bin/alterx`) fail to resolve in
heavy-job context. Python-side resolution was already robust
(`utils/common.py::WATCH_TOOL_PATH` = `/opt/watch/venv/bin` + `$HOME/go/bin`
+ `/root/go/bin` + `/usr/local/go/bin` + `/usr/local/bin` + `/usr/bin` +
`/bin`, with an explicit no-hardcoded-home rule enforced by
`tests/test_pipeline_tooling_failfast.py::TestToolDiscovery`).

Fix (append-only block after `set -euo pipefail`, before `LOCKFILE`):

```bash
HEAVY_TOOL_DIRS="/opt/watch/venv/bin"
if [ -n "${HOME:-}" ]; then
    HEAVY_TOOL_DIRS="$HEAVY_TOOL_DIRS:$HOME/go/bin"
fi
HEAVY_TOOL_DIRS="$HEAVY_TOOL_DIRS:/root/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin"
export PATH="$HEAVY_TOOL_DIRS:${PATH:-}"
```

Properties:

- No username hardcoded in executable lines (verified:
  `grep -v '^#' run-heavy-guarded.sh | grep pouya_behnia` → no match).
  The literal `/home/pouya_behnia/go/bin` appears ONLY in comments as the
  documented non-example, mirroring `utils/common.py:16`.
- Functional check: with `HOME=/home/pouya_behnia`, the exported PATH
  contains `/home/pouya_behnia/go/bin` (via `$HOME/go/bin`); with
  `HOME=/root` it resolves `/root/go/bin`; systemd unit dirs
  (`/opt/watch/venv/bin`, `/usr/local/go/bin`, `/root/go/bin`) all covered.
- `bash -n` syntax OK; guard behavior re-verified (in-window run prints the
  banner and `exec`s the child; `exec "$@"` / window / lock logic
  byte-untouched apart from the prepended block).
- Complements (does not duplicate/conflict) the systemd
  `Environment="PATH=..."` lines in `setup-weekly-jobs.sh` for hosts that
  invoke the guard outside those units.

## 6. .sh executable-bit fix

- `run-heavy-guarded.sh`: git mode `100644 → 100755` via
  `chmod +x` (worktree `stat` = 755) + `git update-index --chmod=+x`
  (index = 100755, verified `git ls-files --stage`). Direct systemd
  `ExecStart` requires the bit; previously only `run-pipeline.sh` had it
  (still 100755, untouched — the `TestGitExecutableBit` test keeps passing).
- `git diff HEAD --summary` for this file: `mode change 100644 => 100755`
  plus the 21-line PATH content change. No other `.sh` modes altered
  (`pipeline_lib.sh`, `setup-*.sh` remain 100644, out of scope).

## 7. Tests run / results

Smallest relevant suite (pipeline fail-fast covers the PATH/exec-bit area;
KB/XSS suites are the AGENTS.md regression set for the R1/lab-adjacent
surface — all offline, no live/Nuclei/Mongo writes):

```bash
python3 -m unittest tests.test_pipeline_tooling_failfast \
  ai.test_knowledge_store ai.test_xss_researcher \
  ai.test_xss_llm_researcher ai.test_openrouter
```

Result: **Ran 108 tests — OK** (~3s; only pre-existing output: one
mongoengine `uuidRepresentation` DeprecationWarning + mocked-puredns command
echo lines, both non-failing).

Plus: `bash -n run-heavy-guarded.sh` → syntax OK; `git diff --check` →
clean; `stat`/index mode checks (§6); `$HOME`-parametrized PATH export
checks (§5). No destructive/live security validation run.

## 8. Final commit

- Hash: `4dd8513ed66c6c3a50e60cb23f8be2ee50d401b9`
  (sync commit as first created; this report's hash field was filled in a
  `--no-edit` amend that changes only this file, so confirm the final hash
  with `git log -1 --format=%H` — reported in the operator handoff).
- Message: `chore(sync): reconcile WSL/Google trees, heavy-job PATH+exec fix and pending reports`
- Parent: `3fb65cc66e2a88186c2eebd85ace879a0d6497e9` (single-parent,
  non-merge commit; `git log --oneline -2` shows it directly atop 3fb65cc).
- `git status --short` after commit: only
  ` D Watch_README_completed.md:Zone.Identifier` (intentionally excluded).
- `git diff --stat HEAD~1..HEAD` scope: 14 files (1 `.sh` + 13 reports).
- No push performed (no `git push` invoked; `git status -sb` shows
  `ahead 1` vs `origin/main`, left for an explicit human decision).
- No remote history altered; no `git reset --hard`; no `git clean`.

## 9. Intentionally excluded files (and why)

| Path | State | Reason |
|------|-------|--------|
| `Watch_README_completed.md:Zone.Identifier` (deletion) | Tracked deletion left unstaged | Windows ADS artifact; task explicitly excludes it absent a convention requiring it |
| `ai/research_cli.py` (Google R1 mods) | Inaccessible — NOT staged, baseline kept | Google worktree diff unreachable via repo state; not re-invented |
| `ai/knowledge/xss_seed.py`, `ai/test_stage_r1.py` | Inaccessible — not created | Same as above; reports preserved instead |
| `ai/lab/*` (12+ files), `ai/test_lab_*.py` (6), `ai/reports/` | Inaccessible — not created | Same as above; lab-1..7 reports preserved instead |
| `ai_data/knowledge/`, `ai_data/research/*.references.json` | Absent / gitignored — not committed | Generated runtime data; `ai_data/research/` ignored per `.gitignore:58` |
| `crawl/output/` | Absent — nothing to stage | Scheduled-crawler machine output per checkpoint precedent |
| `dns-bruteforce/` (only empty `work/`) | Nothing committable — not staged | ~630 MB wordlists + tool output per checkpoint precedent; git cannot track the empty dir |
| `.env`, `*.log`, `venv/`, `*.db` etc. | Untouched | Standard ignores; secret-bearing paths never staged |

## 10. Confirmations

- Mongo data/volumes: **unchanged**. No `mongo*` command run, no
  `ai_data/nuclei/*` or `ai_data/research/*.cli.json` modified, no
  `ai/persistence/*` touched, no containers/volumes touched. Only
  `run-heavy-guarded.sh` + `agent-reports/*.md` in the commit.
- Push: **not performed**. Single local commit only; upstream left at
  `012d358`; sync push remains an explicit human decision.
- Destructive ops: **none** — no `reset --hard`, no `clean`, no untracked
  deletion, no checkout-overwrite. The one deleted-then-recreated path is
  this report file itself, per the mandatory fresh-report workflow.

---
Report generated:
`agent-reports/phase-sync-final-merge.md`
