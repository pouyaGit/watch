# Credentialless Git Operations v1 (Epic 0.2)

## Current problem

Every push from the agent workspace stops at an interactive prompt:

```
git push origin agent/daily-development
Username:
Password:
```

No credential helper is configured on this machine, `gh` is not installed,
and the origin remote uses HTTPS (`https://github.com/pouyaGit/watch.git`),
so there is no non-interactive credential source. This blocks autonomous
operation: any push — branch delivery or approved promotion — stalls waiting
for a human typing a password.

## Supported auth methods (priority order)

`scripts/watch-agent/git/check_auth.py` probes in this order; the first
available method wins:

1. **Existing SSH authentication** — `ssh -T git@github.com` semantics
   (BatchMode, 8 s timeout). Highest priority: no secret material involved,
   keys stay in the operator's `~/.ssh`.
2. **Configured Git credential helper** — e.g. `manager`, `cache`, `osxkeychain`.
   The plaintext `store` helper is explicitly rejected (see security model).
3. **GitHub CLI authentication** — `gh auth status`, only if `gh` is already
   installed and logged in. The layer never installs or logs in `gh` itself.

A personal-access token via environment variable is *read* at runtime only in
the sense that a pre-configured credential helper or `gh` session may use one
internally. The layer itself never accepts, prints, writes, or stores a token:
there is no `--token` flag, no `GITHUB_TOKEN` handling, and no code path that
touches token material anywhere in `scripts/watch-agent/`.

## Security model

- **Detection, not possession.** The layer asks "is auth available?" — it never
  asks "what is the secret?". `check_auth.py` matches only the SSH success
  message and exit codes; it cannot output a credential because none ever
  enters it.
- **Fail-closed.** No method available → `BLOCKED` with closed-vocabulary
  reasons (`SSH_UNAVAILABLE`, `NO_CREDENTIAL_HELPER`, `GH_NOT_AUTHENTICATED`,
  `REMOTE_UNREACHABLE`). `push_safe.sh` refuses the push before git runs.
- **No force, no bypass, no config writes.** `push_safe.sh` rejects any
  dash-leading argument except `--repo`/`--dry-run` (this rules out `--force`,
  `--force-with-lease`, `--no-verify`, `-f` by construction) and contains no
  `git config` invocation. The push is always a plain
  `git push <remote> <branch>`: a non-fast-forward remote rejects instead of
  being overwritten.
- **No silent remote changes.** Nothing in the layer edits remote URLs; a
  missing origin is `REMOTE_UNREACHABLE`, not an invitation to guess one.
- **No secret output.** `status.sh` redacts userinfo from remote URLs
  (`https://user:***@host` → `https://[redacted]@host`) before display, and
  only helper *names* (never values) are reported.
- **No `~/.ssh` modification, no token creation, no plaintext store.**
  `credential.helper=store` is treated as *unavailable*, not as a method.

## Components

- `git/status.sh` — read-only: SSH / helper / gh state, origin URL
  (redacted), protocol, push capability from local readiness only. Writes
  nothing, probes no network beyond the SSH/gh binaries themselves.
- `git/check_auth.py` — pure checker: `READY` (exit 0) or `BLOCKED` (exit 1)
  with reasons; `--json` for machine consumers. No network modules, no
  filesystem writes, no credential access (test-enforced by source scan).
- `git/push_safe.sh` — `push_safe.sh [--repo DIR] [--dry-run] <remote>
  <branch>`: re-checks auth, then pushes. Used by
  `promotion/promote.sh` for the final `push origin main` (Epic 0.1
  integration, additive only — no auth logic duplicated in promote.sh).

## Operator setup (pick one; all happen outside the repo)

```bash
# Option 1 — SSH (recommended)
ssh-keygen -t ed25519 -C "watch-agent"        # if no key exists
cat ~/.ssh/id_ed25519.pub                     # add to GitHub → Settings → Keys
ssh -T git@github.com                         # expect "successfully authenticated"
# then, optionally, switch this checkout's remote to SSH:
git remote set-url origin git@github.com:pouyaGit/watch.git

# Option 2 — credential helper (requires a helper that is NOT plaintext store)
git config --global credential.helper manager # or cache/osxkeychain
git fetch origin                                # one interactive login, then cached
git config --get credential.helper            # must NOT print "store"

# Option 3 — GitHub CLI (if already installed)
gh auth login
gh auth status
```

Verify with: `scripts/watch-agent/git/status.sh` then
`scripts/watch-agent/git/check_auth.py` (expect `READY`).

## Rollback

Nothing in this epic changes repository state, git configuration, remotes, or
`~/.ssh`: there is no setup to undo. If the layer misbehaves, stop calling it
— `promote.sh` keeps working only through `push_safe.sh`, and reverting the
Epic 0.2 commit restores the direct `git push` line. To decommission fully,
delete `scripts/watch-agent/git/` and revert the three-line `push_safe.sh`
hunk in `promote.sh`.

## Verification

```
cd /opt/watch/.worktrees/watch-agent
/opt/watch/venv/bin/python3 -m unittest tests.test_git_auth
```

9 tests against throwaway repos with hermetic git config and stand-in
ssh/gh binaries: BLOCKED-with-reasons when nothing is configured, READY on
SSH, secret redaction, force-flag rejection, missing-auth push refusal, no
repository writes (porcelain + config + file list snapshotted).
