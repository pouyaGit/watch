# Autonomous Promotion Operator v1 (Epic 0.1)

## Old workflow

```
Agent develops
  → git commit                                    (agent)
  → git push origin agent/daily-development       (manual)
  → cd /opt/watch                                 (manual)
  → git merge agent/daily-development             (manual, no gate)
  → git push origin main                          (manual, no gate)
```

The merge into `main` was a bare manual command: nothing verified approval,
nothing re-checked the delivery verdict at merge time, nothing pinned which
commit was reviewed, and nothing recorded the decision. A stale review could
promote new, unseen commits.

## New workflow

```
Agent develops
  → git commit                                    (agent)
  → promotion/request.sh                          (agent: prepares, no merge/push)
  → operator reviews the request file
  → promotion/approve.sh --confirm APPROVE        (operator, explicit word)
  → promotion/promote.sh --yes [--dry-run]        (operator: gated merge+push)
```

`scripts/watch-agent/promotion/`:

- `status.sh` — read-only: branch, commit, remote state, pending request,
  approval state, last promotion event. Writes nothing.
- `request.sh` — writes `agent-reports/promotions/PROMOTION-REQUEST-*.md`
  (source branch, commit, changed files, test result, delivery verdict, diff-
  guard risk) and records `PROMOTION_REQUESTED`. No merge. No push. Never
  overwrites an existing request.
- `approve.sh` — writes `<request>.approval.json` pinning request + commit +
  operator. Requires `--confirm APPROVE`, refuses double approval. No merge.
  No push.
- `promote.sh` — the ONLY command that may merge main. Six gates in order:
  request exists → approval matches → branch HEAD still equals the approved
  commit → delivery verdict exactly `READY FOR PROMOTION` → diff guard `PASS`
  → `--yes` on this invocation. Then fetch, verify fetched == approved,
  `merge --no-ff`, `push origin main`. Any failure → `BLOCKED` +
  `PROMOTION_BLOCKED` in the audit log.
- `audit.py` — append-only JSON-lines log (`AUDIT.log`) with `record`, `list`,
  `verify` (sequence + vocabulary check).
- `PROMOTION_REQUEST_TEMPLATE.md` — Telegram-ready format (format only; no
  Telegram API integration).

## Safety boundaries

- The promotion operator prepares; only `promote.sh --yes` merges, and only
  after a recorded human approval. There is no automatic approval path and no
  flag that skips a gate.
- A request goes stale the moment the branch moves: the approved commit is
  compared to the live HEAD at promote time, and the fetched commit is
  compared again before the merge. Review-then-sneak-in-more-commits cannot
  promote.
- No `--force`, no reset, no clean, no checkout of other branches, no rebase,
  no `--no-verify` anywhere in the layer (test-enforced). The push is a plain
  fast-forward-tolerant `push origin main`; a non-fast-forward remote rejects
  instead of being overwritten.
- No credentials anywhere: no password/token flags, prompts, headers or
  storage. Authority is the operator typing `APPROVE` on a trusted terminal
  plus `--yes` at promote time. (This is why the approval input is a
  confirmation word, not the "approval token" of the original sketch — a token
  would have to be stored and compared, which the security rules forbid.)
- `status.sh` and the default `request.sh`/`promote.sh` paths are read-only
  toward production; `promote.sh` touches the main checkout only after all
  gates pass, and `--dry-run` touches nothing at all (not even the audit log).

## Operator approval model

1. Read the request file (commit, files, tests, delivery verdict, risk).
2. `approve.sh --request <file> --operator <name> --confirm APPROVE`.
3. Re-verify delivery if the branch moved since the request (the request is
   then stale and `promote.sh` will refuse it — generate a fresh one).
4. `promote.sh --request <file> --yes` (add `--dry-run` first to preview).
5. Confirm `PROMOTION_COMPLETED` and check `status.sh`.

One approval authorizes one commit. New commits need a new request.

## Rollback

The merge is a regular `--no-ff` merge commit, so rollback is standard git:

```
cd /opt/watch
git log --oneline -3            # identify the merge commit
git revert -m 1 <merge-sha>     # revert on main (no history rewrite)
git push origin main
```

The audit log (`PROMOTION_COMPLETED` with the merged sha) tells you exactly
which merge to revert. Never `reset --hard` a shared branch.

## Verification

```
cd /opt/watch/.worktrees/watch-agent
/opt/watch/venv/bin/python3 -m unittest tests.test_promotion_operator
```

15 tests: determinism, approval-before-promotion, stale-commit block, missing
delivery block, forbidden-path block, audit order, no secrets, no destructive
git, no automatic merge, dry-run — all against throwaway repos under TMPDIR,
never the real worktree or production.
