# Fix: systemd Go-tool PATH in setup-weekly-jobs.sh

## Root cause

The five heavy-job systemd services run as `User=root`, so `$HOME` resolves
to `/root`. Their `Environment="PATH=..."` contained only
`/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin`,
but the Go-built DNS/HTTP tools (`dnsx`, `puredns`, `alterx`, `httpx`) are
actually installed at `/home/pouya_behnia/go/bin/`. That directory was in
neither the systemd PATH nor root's `$HOME`-derived Go bin, so the tools were
invisible to every systemd-launched heavy job. `run-heavy-guarded.sh` resolves
PATH dynamically from `$HOME`, which is `/root` under systemd — hence it could
not cover the real install location either.

## Exact file changed

- `/opt/watch/setup-weekly-jobs.sh` — ONLY this file. No other file touched
  (`run-heavy-guarded.sh` unmodified, no systemd units touched directly, no Go
  reinstalls, no new test infrastructure).

## Exact behavior change

All five generated service `Environment` PATH lines (dns-precheck:50,
crawl-all:91, param-discovery:133, dns-static:174, dns-dynamic:215) changed
from:

```
Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin"
```

to:

```
Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/home/pouya_behnia/go/bin:/usr/local/bin:/usr/bin:/bin"
```

`/home/pouya_behnia/go/bin` is appended right after `/root/go/bin`,
grouping the Go install locations; all existing entries keep their order.
Schedules, `User=root`, `WorkingDirectory`, slice, limits, `ExecStart`
commands, windows, and timer behavior are byte-identical (file still 274
lines; 5× `User=root`, 5× `OnCalendar`, 5× `run-heavy-guarded.sh` all intact).

## Validation performed

1. `bash -n setup-weekly-jobs.sh` → `SYNTAX_OK`.
2. `grep -n 'Environment="PATH='` → exactly 5 lines (50/91/133/174/215), all
   containing `/home/pouya_behnia/go/bin` in the position above.
3. Negative check: no `PATH=` line remains without the new directory.
4. Integrity check: line count unchanged (274), all 5 `User=root`,
   all 5 `OnCalendar` schedules, all 5 `run-heavy-guarded.sh` ExecStarts
   present and unmodified.
5. Note: `/home/pouya_behnia/go/bin/` does not exist on this container, so
   binary presence could not be re-verified here; the task's verified
   versions (dnsx v1.3.1, puredns v2.1.1, httpx v1.11.0, alterx executable)
   on the target host stand, and no reinstall was performed per scope.

## Confirmation that only the intended PATH entries changed

The edit was a literal replace-all of the one exact PATH string (5
occurrences); the only byte difference in the file is the inserted
`:/home/pouya_behnia/go/bin` segment on those 5 lines. Ordering, users,
schedules, limits, commands, and windows verified unchanged (see above).

## Tests / result

- No existing test file covers `setup-weekly-jobs.sh` (repo references only
  `bash -n setup-weekly-jobs.sh` in README as its validation), so per scope
  no test was added and no new infrastructure created.
- Result: syntax check passed; all 5 service PATHs now include the real Go
  tool directory; everything else preserved.

## No Git operations performed

No `git` command was run in this task (no status/diff/add/commit/push).
The modified script and this report are left uncommitted for manual review.

## Agent / Model

- Model: Muse Spark (muse-spark)
- Stage: systemd Go-tool PATH fix
- Role: implementation
