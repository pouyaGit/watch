# SQLite lock forensics: who actually holds the write lock

Use when the daemon crash-loops on `sqlite3.OperationalError: database is locked`,
or when a lock traceback names a call site you believe is not the real cause.

## 1. A crash-loop at STARTUP is a holder problem, not a code problem

A daemon that starts, prints `startup: loading state`, and dies seconds later at
`recover_jobs()` / `kv_set()` — repeatedly, with systemd incrementing
`NRestarts` — is not failing at its own logic. It cannot get a write
transaction, so the holder is OUTSIDE the service. Read the traceback file
(`logs/daemon_stderr.log`, which the unit's `StandardError=` names) before
reading any `lib/` code: the failing frame is the victim, not the cause.

Check `systemctl --user show hermes-recon -p ActiveState,SubState,MainPID,NRestarts`
first. `SubState=auto-restart` with a rising `NRestarts` is the signature; a single
`MainPID=0` reading is just a sample between restarts and proves nothing.

## 2. Identify the holder from the kernel, not from the traceback

`/proc/locks` is the ground truth. Filter it for the inode of the db and of its
WAL/SHM siblings — the lock is usually on `<db>-wal`, NOT on `<db>`, so a check
keyed on the main file's inode alone reports "no locks" while writes are blocked.
A `POSIX ADVISORY WRITE` line naming a PID is the holder; the following READ
lines are its own connections in the same process.

Then confirm the fd→process mapping:

```python
import glob, os
DB = os.path.realpath("state/hermes.db")
for fd in glob.glob("/proc/[0-9]*/fd/*"):
    try: tgt = os.readlink(fd)
    except OSError: continue
    if tgt != DB and not tgt.startswith(DB + "-"): continue
    pid = fd.split("/")[2]
    cmd = open("/proc/%s/cmdline" % pid, "rb").read().replace(b"\0", b" ").decode(errors="replace")
    print(pid, os.path.basename(tgt), cmd[:120])
```

Read the cmdline before blaming production. A holder that is the agent's own
tooling (a kernel runner, a test process, an ad-hoc script) is a
SELF-INFLICTED hold, and the honest report says so plainly rather than
attributing it to the milestone.

## 3. Agent-side holds are invisible to the service and outlive the suite

A long-lived agent process that imported `lib/store.py` keeps a module-level
sqlite connection bound to the LIVE db even after the suite points `HERMES_DB` at
a temp path — the env var only affects connections opened after it is set. The
suite finishes, the process does not exit, and the open write transaction keeps
the WAL locked for the rest of the session.

Enumerate and close every connection still alive in the process before deciding
the lock cannot be cleared:

```python
import gc, sqlite3
conns = [o for o in gc.get_objects() if isinstance(o, sqlite3.Connection)]
for c in conns:
    try: c.rollback(); c.close()
    except sqlite3.ProgrammingError: pass   # already closed — expected
```

Then re-read `/proc/locks` for the WAL inode and require it EMPTY before
concluding recovery. Also check `PRAGMA quick_check` and `journal_mode` after
release, and confirm the service came back (`MainPID` non-zero, `NRestarts`
stopped climbing, plane respawned).

## 4. Prevent it in the suite, not just at recovery time

The durable fix is an isolation guard at the top of the suite, before any write:
resolve `PRAGMA database_list` through the store's own `conn()` and exit non-zero
unless the path equals the fixture. Record the resolved path in the output so the
proof is visible in the log. Without it the next fixture in the same process
re-leaks silently.
