# Packaging a verified read-only surface as a supervised service

Depth for the "Building a read-only layer" rules in SKILL.md. Applies when a
milestone ends with a working read-only HTTP/UI surface that only runs when a
test starts it, and the next operational task is to make it run continuously
under systemd. The governing hazard: **a service that is "running" is not
evidence that it is supervised, isolated, or actually reachable.**

This task adds no product capability. It is packaging plus proof.

## Read the existing unit before writing one

Never guess interpreter, user, working directory, environment, or logging. Start
from the sibling unit that already runs:

```bash
systemctl --user cat hermes-recon.service
systemctl --user show hermes-recon.service \
  -p ExecStart -p WorkingDirectory -p Restart -p RestartSec \
  -p EnvironmentFile -p NoNewPrivileges -p ProtectSystem -p PrivateTmp \
  -p FragmentPath
```

Adopt what the sibling established — interpreter path, `WorkingDirectory`,
`Restart` policy, `StartLimitBurst`, hardening set, and the `append:`-to-`logs/`
stdout/stderr pattern. A new unit that invents its own conventions is a unit the
next maintainer cannot reason about.

Two deviations are usually correct, and each needs a stated reason:

- **No `WatchdogSec`** unless the process writes a heartbeat. A watchdog on a
  request/response server kills a healthy *idle* process, which is the normal
  state of a low-traffic loopback service.
- **No `After=<sibling>` when the dependency runs the wrong way.** A read-only
  view over a database should come up independently and serve a partial/empty
  view on a fresh boot. Verify that claim rather than asserting it: a WAL-mode
  database has no `-wal`/`-shm` sidecars until a writer opens it, so test a
  read-only open against a **copy** made with `sqlite3.Connection.backup()` and
  confirm the query answers with no sidecars present.

## Scope the hardening to what the process actually does

A read-only service needs no write access to the state directory. Give it the
narrowest `ReadWritePaths` that works — the log directory alone — rather than
copying the sibling's broader grant. Set `CPUQuota`/`MemoryMax` lower than the
daemon's: this is a low-traffic presentation process (observed ~11 MB RSS
against a 512 MB cap is the right order of magnitude).

`CapabilityBoundingSet=` empty, `NoNewPrivileges=true`, `PrivateTmp=true`,
`ProtectSystem=full` are all compatible with a stdlib HTTP server and worth
having. Do not add sandboxing that breaks the app — verify by starting it, not
by reading the unit.

## Prove isolation in BOTH directions, with PIDs

Claiming "the UI is isolated from the execution plane" is worthless without a
measurement. Snapshot the sibling's `MainPID` and `NRestarts` before, then:

- **Kill the new service hard** (`kill -9`), never the daemon. Show HTTP failing,
  then systemd auto-recovering it within `RestartSec`, then HTTP serving again.
  Assert the daemon's `MainPID` is **byte-identical** and its `NRestarts` still
  0, and that a state sample (case/activity/outcome/asset/job counts) has an
  **empty delta**.
- **Restart the sibling** and show the new service needed no manual action, kept
  its own PID, and kept serving.

An empty state delta plus an unchanged daemon PID is the proof. "It didn't crash"
is not.

## Verify the bind, including the negatives

`is-active` says nothing about exposure. Check the socket and check the
counter-cases explicitly:

```bash
ss -ltnp | grep 8787                                    # expect 127.0.0.1:8787
ss -ltn | grep -E '0\.0\.0\.0:8787|\[::\]:8787' && echo EXPOSED   # must be empty
curl -s -o /dev/null -w '%{http_code}\n' http://$(hostname -I | awk '{print $1}'):8787/
```

The routable-IP probe must fail. Report `PUBLIC_EXPOSURE: NO` only after the
negative checks return nothing. Add no firewall rule — a loopback bind does not
need one, and adding one changes host firewall state the brief did not ask for.

## Boot persistence without rebooting production

`systemctl --user is-enabled` plus the `default.target.wants/` symlink is
sufficient proof. Do **not** reboot a production VPS to test a symlink; the
evidence gained does not justify the disruption. If a boot-specific risk exists
(such as the missing-WAL-sidecar case above), test that specific risk directly
against a copy instead.

## Re-run the full content-aware integrity check afterwards

Installing a service changes *when* the read path runs, so the prior closure
proof no longer describes current behaviour. Re-run the controlled
daemon-stopped audit (row counts + per-table checksums + schema) with the
service live. Note that `FILE_SHA256_CHANGED` may now read `False` — under a
real long-lived service with the writer stopped there is no checkpoint to
rewrite the file — so a previously observed WAL drift need not reproduce. Record
what this run showed rather than what the last one showed.

## Widening an existing loopback bind to a public interface

Loopback packaging is the default posture; widening an already-supervised
service is a separate task with a different failure mode. The service keeps
working perfectly while its threat model changes completely. The governing
hazard is a config edit that appears to take effect and does not.

### Preflight: two read-only facts that gate the decision

Both are cheap to check, and each changes what you must *tell the user* rather
than what you must build.

- **Is there at least one usable account?** An auth-gated service whose account
  table is empty is a public login form with nothing behind it — a brute-force
  target that can never succeed. Enumerate the account table before opening the
  port. If it is empty, provisioning a real account (generated credential, no
  default, no password in source) is part of this task, not a follow-up.
- **What is actually filtering the port?** Check `ufw status`, `iptables -S INPUT`
  and the default `INPUT` policy. A host with no firewall means the port is
  reachable from the entire internet and the only brake is the application's own
  rate limiter — that is a disclosure, not a detail. If a firewall *is* active,
  add the single minimal rule for the one port and touch nothing else: do not
  flush, do not alter the SSH rule, do not widen anything else.

### An env-var bind override is defeated by an explicit CLI argument

The usual unit expresses the bind twice — a config variable for the operator and
a command-line default for the app — and the command line wins. Setting only the
variable reloads and restarts cleanly, keeps serving the OLD address, and reports
no error. Treat the unit's *effective* command line as the source of truth, not
the variable you edited:

```bash
systemctl --user cat <unit>.service
systemctl --user show <unit>.service -p ExecStart -p Environment
ss -ltnp | grep ':<port>'
```

Change the application default back to the safe loopback value and let the unit
opt in, so an unconfigured launch is still safe. Copy the unit before editing;
rollback is then two substitutions, and the report can name them.

### Authentication gates, and the cookie that fights plain HTTP

Assert that every route except the login endpoint requires a session — check
the redirect or 401, not merely that a protected page exists. Then:

- On a plain-HTTP deployment a `Secure` session cookie is silently fatal: the
  browser refuses to store or return it, so login appears to succeed and every
  subsequent request is unauthenticated. Keep `HttpOnly` and `SameSite`, omit
  `Secure`, and state the consequence plainly.
- Header sets assembled inline per response path drift. Adding an auth layer
  tends to route normal pages through a *different* response helper that drops
  `X-Frame-Options`, COOP and CORP. Centralize every response through one header
  emitter and check the headers on an **authenticated** page, not only on the
  public login page.
- A credential that has appeared in chat, a log, or a report is disclosed. Tell
  the user to rotate it in the same message; a procedurally strong password is
  not neutralised by having been generated.
- If TLS would require a proxy, certificate, or domain and the task is a
  temporary IP-only bind, disclose the absence instead of adding it unasked —
  and offer the encrypted path that needs no new infrastructure: an SSH local
  forward (`ssh -L <port>:127.0.0.1:<port>`) against the loopback bind.

### Test-harness failures on a public bind are usually the harness

A sweep over an auth-gated public service yields plausible-looking failures that
belong to the probe. Reclassify before reporting any of them as exposure:

- **A cookie jar emptied by the preceding logout** makes every later probe
  unauthenticated, so an endpoint "returning 200 instead of redirecting" is the
  login page, not a bypass. Re-run with a fresh authenticated session and also
  assert the response body does not contain the protected content.
- **Health/liveness endpoints are often intentionally unauthenticated.** If the
  contract names exactly one public route, reconcile the probe with the contract
  explicitly rather than silently widening the public surface.
- **A port scan of the host finds SSH.** A low port answering is not a Hermes
  route and must not be reported as one.

The rule is the one the rest of this file already follows: a failure you have
*explained* is an artifact; a failure you have merely tolerated is an unresolved
gate.

## Report the access path honestly

A loopback-only service is reachable by `http://127.0.0.1:<port>/` on the host
and, if needed, over an SSH tunnel. If authentication is out of scope for the
task, say plainly that none exists *because the bind is loopback* and that it
would be unacceptable on any wider bind — do not let a reader infer the service
is safe to expose.

Name the encryption state of the path explicitly rather than leaving it implied:
transport, whether TLS is configured, whether credential traffic is encrypted,
and what is filtering the port. A summary block of a few labelled lines
(`TRANSPORT`, `TLS`, `AUTHENTICATION`, `PASSWORD TRANSPORT ENCRYPTION`) is read in
seconds and cannot be skimmed past the way prose is. Report the count of
architecture elements the change did not add (tables, workers, schedulers,
agents, queues, LLM calls) — on a pure bind change every one of those is zero,
and stating it is what makes the "small change" claim checkable.

Disclose as limitations: unbounded append-log growth (no rotation), no alerting
on repeated restart-loop exhaustion, and that the sibling was restarted
gracefully rather than crashed.
