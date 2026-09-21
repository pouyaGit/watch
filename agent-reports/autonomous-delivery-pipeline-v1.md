# Autonomous Delivery Pipeline v1 — Epic 0

**Scope:** remove manual Git friction from the Watch autonomous development workflow
without giving up auditability, human control or production safety.

**What this epic delivers:** a delivery layer at `scripts/watch-agent/delivery/` that
tracks delivery state, validates promotion readiness, analyses change risk, produces a
machine-readable report, and documents credential-independent Git operation.

**What this epic does not do:** it never pushes, never merges, never deploys, never
touches production, never modifies systemd units or `.env`, never stores credentials.
It prepares a promotion; a human performs it.

All work happened inside `/opt/watch/.worktrees/watch-agent` on `agent/daily-development`.
Production `/opt/watch` was read only.

---

## 1. The current problem

The workflow before this epic was:

```
agent develops -> git commit -> manual git push branch -> manual merge into main -> manual push main
```

Measured consequences in this repository:

- **Promotion is a judgement call, not a verdict.** Three Git steps per epic are typed by
  hand, and nothing computes "is this ready?" — the operator is the only gate, with no
  machine-checkable evidence attached to the decision.
- **Nothing detects that production moved.** Production advanced from `4eb4c97` to
  `aabe725` while the agent worktree still pointed at an older base. No part of the
  workflow noticed, and a stale-base merge is exactly how a "safe" promotion becomes a
  silent revert. `check.sh` now reports this as `PRODUCTION_UNTOUCHED`.
- **The workspace is legitimately dirty.** The agent branch carries ~168 unrelated
  uncommitted entries (investigation engine, dashboards) alongside the files that belong
  to a given epic. Distinguishing "what this epic changes" from "what happens to be lying
  around" was manual.
- **Forbidden changes have no guard.** The authority chain (`ai/execution/`,
  `ai/verification/`, `ai/authorizer/`, `ai/finding/`, `ai/limits/`, `ai/live_validation/`,
  `ai/evidence/`, `ai/schemas/`), `backend/tasks_registry.py`, `watch_xss_verify.py`,
  `AGENTS.md`, `run-pipeline.sh`, `systemd/` and `.env` must not be promoted by an agent
  commit. Before this epic that rule lived only in prose.
- **Reports are prose.** No delivery report carried the commit, the file set, the tests,
  the risk and a recommendation in a form another tool can read.

## 2. The new workflow

```
agent develops
        |
        v
  git commit                     <- agent, one commit per epic
        |
        v
  delivery/check.sh              <- six required checks, machine verdict
        |
        v
  delivery/report.sh             <- DELIVERY-REPORT-<date>.md + .json + Telegram block
        |
        v
  human approval                 <- operator reads the report, decides
        |
        v
  safe promotion (manual)        <- push agent branch, open PR, merge in the UI,
                                    update the production checkout
```

The pipeline replaces the *friction* (knowing what to push, whether it is safe, and what
changed) while keeping every *decision* with the operator. The only thing that contacts a
remote is the operator's own Git client, with the operator's own credentials.

Existing helpers `scripts/watch-agent/{start,status,review,sync}.sh` are unchanged and
still cover session setup and branch synchronization. `delivery/` adds the readiness
dimension on top of them.

## 3. Components

| Path | Role | Guarantees |
|---|---|---|
| `delivery/policy.py` | Deterministic policy: allowed/forbidden paths, secret/env/system patterns, guard paths, the six required checks, promotion rules | Pure module: no execution, no filesystem access, no network, no `open()`, no subprocess. `--document`, `--fingerprint`, `--verdict` are read-only. |
| `delivery/diff_guard.py` | Change-risk analyzer over `git diff --name-status` / `git status --porcelain` plus unified diff text | Returns `PASS` / `BLOCK`. Blocks on forbidden paths, secrets, env files, systemd units, guard deletions, live-gate flips, traversal, binary changes. Writes nothing; unparseable input is a BLOCK (exit 2), never a silent pass. |
| `delivery/status.sh` | Delivery state: branch, latest commit, remote status, unpushed commits, merge readiness, test status, changed-files summary | Read-only: no fetch, no write, no `>` redirection anywhere in the script. |
| `delivery/check.sh` | Pre-promotion validation: `BRANCH`, `COMMIT`, `TESTS`, `PATH_GUARD`, `REPORT`, `PRODUCTION_UNTOUCHED` | Prints `READY FOR PROMOTION`, `READY FOR PROMOTION (X SKIPPED)` or `BLOCKED` with reasons. Exit 0/1. Never pushes, merges, rebases or deploys. |
| `delivery/report.sh` | Machine-readable delivery report under `agent-reports/delivery/` | Writes `DELIVERY-REPORT-<date>.md`, `.json` and `production-baseline.json` — and nothing else, anywhere. Includes a Telegram-ready summary block. |
| `tests/test_delivery_policy.py` | Policy tests | Allowed paths, forbidden paths, severities, promotion rules, determinism, purity (AST scan). |
| `tests/test_delivery_guard.py` | Guard + script tests | Parsing, verdicts, secrets, live-gate flips, determinism, no-writes (AST + cwd snapshot), safe failure, exit codes, and the shell scripts' own safety (no push/merge/reset literals, `bash -n`, read-only status). |

The verdict is always computed by `policy.py`; the shell scripts only gather facts. That
keeps one deterministic rule set instead of two divergent ones, and `--fingerprint` pins
exactly which policy produced a given verdict.

## 4. Safety model

**Fail-closed by construction.**

- A missing check, an unknown check name, an unknown check state or an unparseable change
  record all produce `BLOCKED`. Nothing is "assumed fine".
- The guard's exit codes are explicit: `0` PASS, `1` BLOCK, `2` invalid input (also
  reported as BLOCK). A caller can never read a crash as approval.
- The exclusion/reason vocabulary is closed and sorted, so a verdict is reproducible and
  diffable.

**Deny by default.**

- A path is `ALLOWED` only if it matches the allowlist and nothing else. Unknown paths are
  warnings the human sees, never silent approvals; forbidden/secret/env/system paths are
  hard blocks, including *new* files created inside a forbidden directory.
- Classification precedence is fixed: `FORBIDDEN` > `SECRET` > `ENV` > `SYSTEM` >
  `ALLOWED` > `UNKNOWN`, so a secret inside a forbidden directory cannot be downgraded.
- Deleting a guard file (`policy.py`, `diff_guard.py`, the three scripts, the two test
  modules) is a BLOCK — a guard cannot be removed by the thing it guards.

**No self-promotion.**

- The shell scripts contain no `git push`, `git merge`, `git rebase`, `git reset`,
  `git clean`, force flags or `--no-verify`; `tests/test_delivery_guard.py` asserts those
  literals are absent and that the scripts never `cd` into or target production.
- Live-capability flips are blocked at the diff level: any added line that enables a
  `LIVE_*` / `WATCH_AI_LIVE*` flag is `LIVE_GATE_FLIP` → BLOCK.
- `status.sh` performs no fetch, so a read-only status call cannot move a ref.

**Production is observed, never touched.**

- `PRODUCTION_UNTOUCHED` compares the live production HEAD and dirty-entry count against
  `agent-reports/delivery/production-baseline.json` (recorded by `report.sh`). If
  production moved since the baseline, promotion is blocked with both values printed.

## 5. Usage examples

```bash
cd /opt/watch/.worktrees/watch-agent

# 1. Where am I?
scripts/watch-agent/delivery/status.sh

# 2. Am I allowed to promote this?
scripts/watch-agent/delivery/check.sh                 # full run, includes tests
scripts/watch-agent/delivery/check.sh --no-tests      # fast, tests SKIPPED (labelled)
scripts/watch-agent/delivery/check.sh --json          # machine verdict + evidence

# 3. Produce the report (writes agent-reports/delivery/)
scripts/watch-agent/delivery/report.sh
scripts/watch-agent/delivery/report.sh --stdout       # print only, write nothing
scripts/watch-agent/delivery/report.sh --telegram     # one compact summary block

# 4. Ask the guard about a change set directly
git diff --name-status main...HEAD | scripts/watch-agent/delivery/diff_guard.py --json
scripts/watch-agent/delivery/diff_guard.py --name-status /tmp/ns.txt --diff /tmp/d.diff

# 5. Inspect the policy itself
scripts/watch-agent/delivery/policy.py --document | head -40
scripts/watch-agent/delivery/policy.py --fingerprint
```

Sample verdicts:

```
DIFF GUARD: BLOCK
  files checked : 2
  policy        : delivery-policy/v1  f0c1d2e3a4b5c6d7
  BLOCK FORBIDDEN_PATH    ai/verification/verifier.py  — authority chain, production entry point or protected directory
  WARN  UNKNOWN_PATH      notes/scratch.py             — outside the delivery policy allowlist
```

```
== Verdict ==
  BLOCKED
  reasons: CHECK_BLOCKED:BRANCH CHECK_BLOCKED:PATH_GUARD

  This script prepares promotion only: no push, no merge, no deploy.
  Operator next step: review, then push the agent branch and open a PR.
```

## 6. Credential-independent Git operation

The delivery layer performs **no** authenticated operation, so it needs **no** credential:
no token, no password, no SSH key, no credential helper of its own. That is the point —
the automation cannot leak or store what it never holds.

The operator performs the Git steps with credentials that already live outside the
repository. All of these work without putting a secret in the repo:

- **SSH deploy key (recommended).** A key whose private half lives in `~/.ssh/` (or an
  agent) and whose public half is a read/write deploy key on the repository. Select it per
  invocation without editing any tracked file:
  `GIT_SSH_COMMAND='ssh -i ~/.ssh/watch_deploy -o IdentitiesOnly=yes' git push origin agent/daily-development`
- **Existing credential helper.** `git config --get credential.helper` shows the OS-level
  helper (libsecret/`osxkeychain`/`manager`). If it is configured, `git push` simply works
  and the secret stays in the OS keyring, not in this checkout.
- **GitHub CLI device flow.** `gh auth login` authenticates the CLI interactively and
  stores the token in the CLI's own config (`~/.config/gh/`), outside the repository;
  `gh pr create` then needs no credential handling in scripts.
- **Ephemeral token in the environment.** For one-off CI-style runs:
  `GIT_ASKPASS=/bin/echo GIT_TOKEN=... ` never written to a file — the token exists only
  for the duration of that command.

Rules the layer enforces by design:

- The remote URL stays credential-free (`https://github.com/pouyaGit/watch.git`) — a
  token must never be embedded in `remote.origin.url`, because that writes it into
  `.git/config`.
- `.env`, `.env.*`, `*.pem`, `*.key`, `*id_rsa*`, `*credentials*`, `*secret*`, `.netrc`
  and `.ssh/*` are `BLOCK` paths, so the guard refuses to promote a commit that adds them.
- Added diff lines that look like credential material (private-key headers, cloud
  access-key IDs, repository and chat-platform token prefixes, database URIs that embed
  a username and password, and quoted password or API-key assignments) are
  `SECRET_CONTENT` → BLOCK, even if the file path looks benign.
- The delivery scripts are asserted to never read or write a credential file and never
  call a network tool.

Rotating credentials therefore never invalidates this layer: there is nothing to rotate
inside it.

## 7. Future automation points (deliberately not enabled in v1)

Each of these is a deliberate, reviewable next step — none is implemented here:

1. **Automatic agent-branch push.** Requires a scoped deploy key with write access to
   `agent/daily-development` only, plus a policy rule that allows a push when
   `check.sh` returns `READY FOR PROMOTION`. Not enabled: the epic's target workflow
   mentions it, but pushing before the operator has read the report contradicts
   "human approval only when required" until the rule is formally agreed.
2. **Scheduled readiness sweep.** `systemd` timer running `check.sh` hourly and
   `report.sh` daily. Explicitly out of scope (systemd must not be modified here).
3. **Pull-request creation.** `gh pr create --fill` driven by the report's `Recommendation`
   section once credential handling is confirmed by the operator.
4. **Auto-merge after green checks.** Would need: N consecutive PASS verdicts, an
   allowlist-only diff, and an explicit operator opt-in flag — plus a branch-protection
   rule on the GitHub side, which is the real enforcement point.
5. **Change-risk scoring.** Today risk is binary plus warnings; a scored version could
   weight diff size, touched-subsystem criticality and test coverage delta.
6. **Delivery metrics.** Time-to-promotion, blocked-reason histogram and baseline drift
   from the `DELIVERY-REPORT-*.json` history.
7. **Notification.** `report.sh --telegram` already emits a send-ready block; wiring it to
   a bot token is a separate, reviewable step.
8. **Baseline automation.** Recording the production baseline automatically at promotion
   time (today `report.sh` does it explicitly).

## 8. Verification performed

```bash
cd /opt/watch/.worktrees/watch-agent
PYTHONDONTWRITEBYTECODE=1 /opt/watch/venv/bin/python3 -m unittest \
    tests.test_delivery_policy tests.test_delivery_guard -v
scripts/watch-agent/delivery/check.sh
scripts/watch-agent/delivery/status.sh
scripts/watch-agent/delivery/report.sh
```

Observed: 82/82 delivery tests pass; `check.sh` returns `READY FOR PROMOTION` for the
committed epic and `BLOCKED` (with reasons) while delivery files are still uncommitted;
`status.sh` exits 0 and writes nothing; `report.sh` writes exactly three files under
`agent-reports/delivery/`.

## 9. Rollback

The layer is additive and inert. To roll back: delete `scripts/watch-agent/delivery/`,
`tests/test_delivery_policy.py`, `tests/test_delivery_guard.py`,
`agent-reports/delivery/` and this document. Nothing else references them, no service was
registered, no credential was created, and no production file was modified — so rollback
is a revert of one commit with no migration to unwind.
