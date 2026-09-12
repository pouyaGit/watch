# Stage Schedule Alignment — Pipeline vs AI Window

## Objective

Align the daily systemd schedules with the intended operating windows:

- 00:00–06:00 Tehran — core pipeline / recon
- 06:00–12:00 Tehran — heavy jobs
- 12:00–00:00 Tehran — AI / research / XSS

The concrete defect is that the core pipeline (`watch.service`) was still being
triggered at 12:00 Tehran (`Pipeline run started -- Sat Sep 12 12:00:10 +0330
2026`). The fix must remove the 12:00 core trigger, keep the core pipeline in
its recon window, leave the AI/research window authoritative and untouched, and
leave the heavy-job weekly timers unchanged.

## Current Root Cause

There is no `systemd/watch.timer` file in the repository. The authoritative
definition is embedded in the installer `setup-core-pipeline.sh`, which writes
the unit with `sudo tee "${SYSTEMD_DIR}/watch.timer"`:

```
[Unit]
Description=Run Watch Core Pipeline every 12 hours (Asia/Tehran)
...
# EXACTLY 00:00 and 12:00 Tehran time.
OnCalendar=*-*-* 00:00:00 Asia/Tehran
OnCalendar=*-*-* 12:00:00 Asia/Tehran   <-- fired at 12:00 Tehran
Persistent=false
```

`OnCalendar=*-*-* 12:00:00 Asia/Tehran` made systemd start `watch.service`
exactly at 12:00 Tehran, which is the observed `12:00:10 +0330` pipeline run.

Verified that this is the only source that can create the 12:00 trigger:

- `grep -rln "watch\.timer\|watch\.service"` across scripts/units →
  only `setup-core-pipeline.sh`.
- Repo-wide `OnCalendar` inventory after the fix:
  - `systemd/watch-research.timer` → `hourly` (AI/research; unchanged)
  - `setup-core-pipeline.sh` → only `00:00:00 Asia/Tehran` (fixed)
  - `setup-weekly-jobs.sh` → five heavy-job timers at `06:00:00 Asia/Tehran`
    on Fri / Sat / Sun / Mon,Tue / Wed,Thu (unchanged)
- `ai/research_agent/scheduler.py` keeps the authoritative AI window
  (`window_start="12:00"`, `window_end="00:00"`, `Asia/Tehran`); the hourly
  `watch-research.timer` only ticks the scheduler and never starts the core
  pipeline.
- `systemd/watch.timer` does not exist as a separate repo file, so there is no
  duplicate definition to reconcile; re-running the fixed installer overwrites
  the same `/etc/systemd/system/watch.timer` path.

## Files Inspected

- `setup-core-pipeline.sh` (defines and installs `watch.service` + `watch.timer`)
- `systemd/watch-research.timer`
- `systemd/watch-research.service`
- `setup-weekly-jobs.sh` (heavy-job timers; unchanged)
- `run-pipeline.sh`, `pipeline_lib.sh` (entrypoint/lock behavior; unchanged)
- `ai/research_agent/scheduler.py` (AI window `12:00–00:00`; unchanged)
- `backend/tasks_registry.py` (registry comment; unchanged)
- `tests/test_core_pipeline_unit.py` (existing schedule regression test)
- `tests/test_pipeline_tooling_failfast.py`, `tests/test_research_agent.py`
- `README.md` (schedule documentation; unchanged)
- Repo-wide scan for `OnCalendar` / `watch.timer` / `12:00`

## Changes Made

1. `setup-core-pipeline.sh`
   - Removed `OnCalendar=*-*-* 12:00:00 Asia/Tehran` from the `watch.timer`
     heredoc; the only remaining trigger is `*-*-* 00:00:00 Asia/Tehran`.
   - Updated the timer description from
     `Run Watch Core Pipeline every 12 hours (Asia/Tehran)` to
     `Run Watch Core Pipeline daily at 00:00 (Asia/Tehran)`.
   - Updated the schedule comments to state the 12:00–00:00 window belongs to
     AI/research and that there is no 12:00 core trigger.
   - Updated the `TimeoutStartSec=6h` comment ("leaves ~18h before the next
     daily core run") to match the new cadence.

2. `tests/test_core_pipeline_unit.py`
   - Updated the module docstring to the new cadence.
   - Replaced `test_timer_cadence_unchanged` (which asserted the 12:00 line)
     with `test_timer_cadence_aligned`.
   - Added `test_exactly_one_core_oncalendar`,
     `test_no_12_00_core_pipeline_trigger`, and
     `test_research_hourly_timer_unchanged`.

No other file was changed for this stage.

## Intended Final Schedule

| Window (Asia/Tehran) | Owner | Definition | Status |
|---|---|---|---|
| 00:00–06:00 | Core pipeline / recon | `watch.timer`: `OnCalendar=*-*-* 00:00:00 Asia/Tehran`, `Persistent=false`, `TimeoutStartSec=6h` | fixed |
| 06:00–12:00 | Heavy jobs | `setup-weekly-jobs.sh`: `06:00:00 Asia/Tehran` (Fri/Sat/Sun/Mon,Tue/Wed,Thu) | unchanged |
| 12:00–00:00 | AI / research / XSS | `watch-research.timer` hourly + `SchedulerConfig` window `12:00`–`00:00` | unchanged |

**Does the core pipeline have ANY 12:00 trigger after the fix? No.**

- The extracted `watch.timer` (from the installer) contains exactly one
  `OnCalendar` line: `*-*-* 00:00:00 Asia/Tehran`.
- A repo-wide search for `OnCalendar=*-*-* 12:00` returns no executable
  source; the only remaining occurrence is a historical report
  (`agent-reports/stage-core-pipeline-runtime-hardening.md`) documenting the
  old state, which is intentionally not modified.

## Validation

Commands executed (local WSL only):

```bash
bash -n setup-core-pipeline.sh
./venv/bin/python -m unittest tests.test_core_pipeline_unit -v
./venv/bin/python -m unittest tests.test_core_pipeline_unit \
    tests.test_pipeline_tooling_failfast -q
./venv/bin/python -m unittest tests.test_research_agent -q
grep -rn "OnCalendar" . --exclude-dir=venv --exclude-dir=.git \
    --exclude-dir=__pycache__ --exclude="*.md"
git diff --check
```

Results:

```
bash -n setup-core-pipeline.sh                       -> SYNTAX_OK

tests.test_core_pipeline_unit                        -> Ran 11 tests ... OK
  (includes systemd-analyze verify on the extracted watch.service)

tests.test_core_pipeline_unit +
tests.test_pipeline_tooling_failfast                 -> Ran 30 tests ... OK

tests.test_research_agent (AI 12:00-00:00 window)    -> Ran 94 tests ... OK

git diff --check                                     -> clean
```

Extracted `watch.timer` unit text after the fix:

```ini
[Unit]
Description=Run Watch Core Pipeline daily at 00:00 (Asia/Tehran)

[Timer]
Unit=watch.service

# EXACTLY 00:00 Tehran time (core pipeline / recon window 00:00-06:00).
# The 12:00-00:00 window belongs to AI/research; there is no 12:00 core trigger.
OnCalendar=*-*-* 00:00:00 Asia/Tehran

# Never execute a missed run after reboot.
Persistent=false

[Install]
WantedBy=timers.target
```

Repo-wide `OnCalendar` inventory after the fix:

```
./systemd/watch-research.timer:7:OnCalendar=hourly
./setup-core-pipeline.sh:59:OnCalendar=*-*-* 00:00:00 Asia/Tehran
./setup-weekly-jobs.sh:68:OnCalendar=Fri *-*-* 06:00:00 Asia/Tehran
./setup-weekly-jobs.sh:110:OnCalendar=Sat *-*-* 06:00:00 Asia/Tehran
./setup-weekly-jobs.sh:151:OnCalendar=Sun *-*-* 06:00:00 Asia/Tehran
./setup-weekly-jobs.sh:192:OnCalendar=Mon,Tue *-*-* 06:00:00 Asia/Tehran
./setup-weekly-jobs.sh:233:OnCalendar=Wed,Thu *-*-* 06:00:00 Asia/Tehran
```

## Regression Protection

Deterministic, offline tests added to the existing
`tests/test_core_pipeline_unit.py`, which parses the unit bodies directly out of
`setup-core-pipeline.sh` (no systemd contact):

- `test_exactly_one_core_oncalendar` — asserts the `watch.timer` body has
  exactly one `OnCalendar`, equal to `*-*-* 00:00:00 Asia/Tehran`.
- `test_no_12_00_core_pipeline_trigger` — asserts there is no
  `OnCalendar=...12:00` in the timer body, no `OnCalendar=*-*-* 12:00` anywhere
  in the installer, and that the old "every 12 hours" description cannot
  return.
- `test_timer_cadence_aligned` — keeps `Unit=watch.service`,
  `Persistent=false`, and no `RandomizedDelaySec`.
- `test_research_hourly_timer_unchanged` — keeps the AI/research timer at
  `OnCalendar=hourly` + `Persistent=true`; the 12:00–00:00 window itself stays
  locked by the existing `tests/test_research_agent.py` window assertions
  (still passing).

Because `setup-core-pipeline.sh` is the single installer of `watch.timer`
(verified by repo-wide grep), any attempt to re-add a 12:00 trigger must touch
that file, and the tests above fail immediately.

Operational note (not performed here): the installed
`/etc/systemd/system/watch.timer` on the target host still holds the old
schedule until the corrected installer is re-run there. The script already
performs `systemctl daemon-reload` and `systemctl restart watch.timer`, and it
overwrites the same unit path, so re-running it replaces (never duplicates) the
timer. Per task rules, no VM access or deployment was performed.

## Git Status

```
$ git status --short
 M backend/observed_inventory.py
 M setup-core-pipeline.sh
 M tests/test_core_pipeline_unit.py
 M tests/test_observed_inventory.py
 D utils.zip
?? agent-reports/stage-r31-3-mongo-inventory-init-fix.md
?? agent-reports/stage-schedule-alignment-pipeline-ai-window.md
?? watch.zip
```

This task changed only:

```
$ git diff --stat setup-core-pipeline.sh tests/test_core_pipeline_unit.py
 setup-core-pipeline.sh           |  9 +++++----
 tests/test_core_pipeline_unit.py | 41 +++++++++++++++++++++++++++++++++++-----
 2 files changed, 41 insertions(+), 9 deletions(-)
```

The remaining entries are pre-existing / unrelated and were not touched:
`backend/observed_inventory.py` and `tests/test_observed_inventory.py` are the
previous R31.3 Mongo-init work; `utils.zip` / `watch.zip` come from an external
sync/archive process. The new report file is this document.

## Scope / Safety

- No VM modifications: the Google VM was not SSH'd into or changed.
- No deployment: no units were installed, enabled, restarted, or reloaded.
- No Git commit and no Git push.
- No unrelated files changed: only `setup-core-pipeline.sh` and
  `tests/test_core_pipeline_unit.py` are part of this fix.
- No unrelated code refactored; the research scheduler and its window are
  untouched, heavy-job timers are untouched, pipeline implementation logic is
  untouched.
- The fix is source-level and minimal, in the installer that actually defines
  the schedule.

## Agent / Model
- Model: deepseek-v4.1-flash
- Stage: Schedule Alignment / Pipeline-vs-AI Window Separation
- Role: coding agent
