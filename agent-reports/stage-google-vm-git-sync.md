# Google VM Git Sync — Tracked/Untracked Collision Reconciliation

## Status
**SYNCED.** `HEAD == origin/main == 27dda2d` via fast-forward-only pull.
No source code, `.env`, systemd units, or `database/db.py` touched. No reset,
no `git clean`, no push, no blind deletions.

## 1. Previous / target state
- Previous HEAD: `71fef7ce69bf1f24837b05cf7bf0478daed762ee`
  (`feat(research): complete public-source discovery R24`)
- Target (`origin/main` after `git fetch origin main`, exit 0):
  `27dda2d5f859dabb9aa0d9e5531cbd241bda9b98`
  (`feat(research): align research window with AI schedule`)
- Pre-existing working-tree state (left alone throughout):
  `M wordlists/dell_params.txt`, `M wordlists/indeed_params.txt`
  (unrelated pipeline activity) and untracked runtime dirs
  (`ai_data/knowledge/`, `ai_data/reports/`, `crawl/output/`,
  `dns-bruteforce/`). Incoming diff (101 files, +33501/−48, mostly
  tests/web/R25–R30 research tracks) has zero overlap with those paths.

## 2. Collision comparison (working tree untouched during inspect)
Method: `sha256sum <local>` vs `git show origin/main:<path> | sha256sum`
(note: without `2>&1`, so error text can never pollute a hash — see §4).

| File | Local SHA256 | Origin SHA256 | Verdict |
|---|---|---|---|
| `agent-reports/stage-r23-2-final-google-vm.md` | `302afec8…7f2f2683` | identical | identical — removed |
| `agent-reports/stage-r24-13-environment-model-sync.md` | `5325b38f…02fb7092` | identical | identical — removed |
| `agent-reports/stage-r24-14-pre-activation-reconciliation.md` | `c5b06c5d…170300f6a` | identical | identical — removed |
| `agent-reports/stage-r24-15-model-sync-controlled-run.md` | `60afa782…bdd63732` | identical | identical — removed |
| `agent-reports/stage-r24-16-autonomous-r24-activation.md` | `d8003b00…874453e1d` | identical | identical — removed |

(Full hashes in §5; prefixes above are unambiguous.)

## 3. Safe reconciliation performed
- The 5 byte-identical untracked files were removed individually with `rm`
  (no `git clean`, no wildcards) so the pull could materialize the tracked
  versions. No differing content was deleted.
- `agent-reports/stage-r24-17-first-scheduled-run.md` (local-only report from
  the prior stage) was moved — not deleted — to
  `/tmp/watch-git-reconcile-20260911T164151Z/stage-r24-17-first-scheduled-run.md`
  (SHA256 `fc8e6c04b6ee424c054703cdb53514eaa4a3f24aaa48f3f8ed3b6fbfc523522a`,
  verified after the move). See §4 for why, and the one-line restore command.

## 4. Correction: r24-17 is NOT tracked by origin
- During inspection, the comparison loop used `2>&1`, which piped git's
  `fatal: path … does not exist in 'origin/main'` error text into `sha256sum`.
  The resulting `4020…` hash was the hash of that error message, misread as
  "origin content differs".
- Re-verified cleanly: `git show origin/main:<that path>` → exit 128
  (`does not exist`); `git ls-tree origin/main -- agent-reports/` lists only
  the 5 files from §2; `git log --all -- <that path>` → empty. **Origin has
  never tracked `stage-r24-17-first-scheduled-run.md`.** No pull collision
  existed for it; the backup move was harmless over-caution and the file is
  intact.
- To restore it as an untracked local file (NOT done here — left for the
  operator): `cp /tmp/watch-git-reconcile-20260911T164151Z/stage-r24-17-first-scheduled-run.md agent-reports/` then re-verify its SHA256 against
  `fc8e6c04…23522a`.

## 5. Pull result
- `git pull --ff-only origin main` → exit 0, `Updating 71fef7c..27dda2d`,
  `Fast-forward`, 101 files changed (+33501/−48).
- Final HEAD: `27dda2d5f859dabb9aa0d9e5531cbd241bda9b98`.
- `git log --oneline -3`: `27dda2d feat(research): align research window
  with AI schedule` / `26bf486 feat(research): R23-R30.2 research
  intelligence, economics, opportunity workflow, hunt queue and asset
  inventory` / `71fef7c feat(research): complete public-source discovery R24`.

## 6. Final verification
- `git status --short`: only the pre-existing `M wordlists/*` entries and the
  pre-existing untracked runtime dirs, plus this new untracked report. No
  unexpected modifications.
- All five §2 report files: tracked = yes, present = yes.
- `git diff --check` → clean.

## 7. Full SHA256 record
- `stage-r23-2-final-google-vm.md`:
  local = origin = `302afec8b26fa9cadf878ec30d8d16c3840241dab038da532b2fc90b7f2f2683`
- `stage-r24-13-environment-model-sync.md`:
  local = origin = `5325b38f574701bdb1f003a06a91a4a66e32532eebfe8bafee6bf02fb7092585`
- `stage-r24-14-pre-activation-reconciliation.md`:
  local = origin = `c5b06c5dcfa52f5288985cfd16eda982b77a7b6e09ac0d573132f1c170300f6a`
- `stage-r24-15-model-sync-controlled-run.md`:
  local = origin = `60afa782344f193c02aa6e5f9a9333e15f514ad06ffea74d86e2dd76bdd63732`
- `stage-r24-16-autonomous-r24-activation.md`:
  local = origin = `d8003b00b6cc5d2df96803201b359f159677f580bff6ede88b747453e1d690d1`
- `stage-r24-17-first-scheduled-run.md` (local-only, backed up, origin n/a):
  `fc8e6c04b6ee424c054703cdb53514eaa4a3f24aaa48f3f8ed3b6fbfc523522a`

This report is untracked, unstaged, and uncommitted by instruction.

## Agent / Model
- Model: opencode/muse-spark-1.3-contributor-free
- Stage: Google VM Git Sync
- Role: Deployment / Git Reconciliation Agent
