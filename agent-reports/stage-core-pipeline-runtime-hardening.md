# Stage: Core Pipeline Runtime Environment Hardening

- Date: 2026-09-10
- Scope: core `watch.service` runtime environment only
- Environment: WSL2 development box (systemd 255; `systemd-analyze` available)
- Predecessor: `agent-reports/stage-ns-failfast.md` (NS now fails loudly on a
  missing/broken `dnsx`), `agent-reports/dns-failure-diagnosis.md`

---

## 1. Problem

`setup-core-pipeline.sh` generated `watch.service` with `User=root` but:

- **no explicit `Environment="PATH=..."`** — unlike the five heavy jobs, which
  received the Go-tool PATH in commit `bedff46`. The core service relied on
  `run-pipeline.sh` doing `source ~/.zshrc` + `source venv/bin/activate`, which
  is not a reliable systemd environment (`.zshrc` may not exist for root, is not
  sourced by a non-interactive systemd shell, and the tools live at
  `/home/pouya_behnia/go/bin`, which is not in root's default PATH).
- **no real execution timeout.** `Type=oneshot` disables `TimeoutStartSec` by
  default, so a genuinely hung pipeline could run forever. The previous attempt
  at a bound used `RuntimeMaxSec=`, which systemd **ignores for
  `Type=oneshot`** (the service is inactive the moment `ExecStart` finishes, so
  the "max runtime while active" check never applies).

With NS Fail-Fast now raising instead of returning `[]`, the PATH gap surfaces
as a hard exit-127 failure rather than a fake successful empty DNS run, making
this environment fix the correct next step.

---

## 2. Exact files changed

1. `setup-core-pipeline.sh` — added `Environment="PATH=..."` and
   `TimeoutStartSec=6h` to the generated `watch.service`; added
   `Environment`/`TimeoutStartUSec`/`RuntimeMaxUSec` to the post-install
   `systemctl show` verification output. Nothing else in the file changed.
2. `tests/test_core_pipeline_unit.py` — **new** focused regression test (8
   tests) that parses the installer and locks the PATH, the oneshot timeout,
   the absence of `RuntimeMaxSec=`, unchanged ExecStart/KillMode/TimeoutStopSec,
   and unchanged timer cadence.
3. `agent-reports/stage-core-pipeline-runtime-hardening.md` — this report.

No other file was modified. `run-pipeline.sh`, `run-heavy-guarded.sh`,
`setup-weekly-jobs.sh`, `pipeline_lib.sh`, and the timer cadence are untouched.

---

## 3. Before / after PATH

**Before:** no `Environment=` directive on `watch.service`. Under systemd the
service ran with the manager's minimal default PATH plus whatever `source
~/.zshrc` / `source venv/bin/activate` happened to set at runtime; it did not
reliably include `/home/pouya_behnia/go/bin`.

**After (exact generated line):**

```
Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/home/pouya_behnia/go/bin:/usr/local/bin:/usr/bin:/bin"
```

This is byte-identical to the heavy-job PATH added in `setup-weekly-jobs.sh`
(commit `bedff46`), including the real Go install location
`/home/pouya_behnia/go/bin`. The heavy jobs' PATH fix was not modified.

---

## 4. Timeout mechanism and exact value

```
TimeoutStartSec=6h
```

- Mechanism: `TimeoutStartSec=`, **not** `RuntimeMaxSec=`.
- Exact value: `6h` = 21600 seconds.
- Rationale: longer than the 5.5 h (`RuntimeMaxSec=330min`) ceiling used by the
  heaviest weekly jobs, and about half the 12 h timer cadence — so a hung run is
  terminated with ~6 h of margin before the next scheduled run, while a
  legitimately long full pipeline (sync → enum → DNS → HTTP → crawl-fresh) is
  not cut off prematurely.

---

## 5. Why this timeout works with the actual service `Type`

`watch.service` is `Type=oneshot`. Per `systemd.service(5)`:

- `RuntimeMaxSec=` — "Configures a maximum time for the service to run … **this
  setting does not have any effect on `Type=oneshot` services, as they terminate
  immediately after activation completed.**" A oneshot unit goes inactive as
  soon as its `ExecStart` processes exit, so a max-runtime-while-active timer is
  never engaged. This is exactly the warning the earlier jobs hit.
- `TimeoutStartSec=` — "Configures the time to wait for the service to start up
  … **except when `Type=oneshot` is used, in which case the timeout is disabled
  by default.**" For a oneshot service, the start job is not considered complete
  until the `ExecStart` command(s) finish, so this timer measures the full
  pipeline duration and terminates the unit (respecting `KillMode=control-group`)
  if the bound is exceeded.

Therefore `TimeoutStartSec=6h` is the directive that actually bounds a hung
`Type=oneshot` pipeline; `RuntimeMaxSec=` would be silently ignored and is
deliberately **not** present (enforced by a regression test).

---

## 6. Validation commands and results

All commands were run offline on WSL; no service was installed, started, or
contacted.

```
bash -n setup-core-pipeline.sh
  -> OK
bash -n setup-weekly-jobs.sh run-pipeline.sh run-heavy-guarded.sh pipeline_lib.sh
  -> OK

# Extract the unit exactly as the installer writes it (no sudo, no /etc writes)
awk '/sudo tee .*watch\.service.*<< .UNIT./{f=1;next} f&&/^UNIT$/{exit} f{print}' \
    setup-core-pipeline.sh > /tmp/opencode/units/watch.service
cat -A /tmp/opencode/units/watch.service
  -> shows Environment="PATH=..." and TimeoutStartSec=6h

# Effective-directive checks
grep -E '^[[:space:]]*Environment=' /tmp/opencode/units/watch.service
  -> Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/home/pouya_behnia/go/bin:/usr/local/bin:/usr/bin:/bin"
grep -E '^[[:space:]]*TimeoutStartSec=' /tmp/opencode/units/watch.service
  -> TimeoutStartSec=6h
grep -E '^[[:space:]]*RuntimeMaxSec=' /tmp/opencode/units/watch.service
  -> (no match; correct)

# systemd's own validator on the generated unit
systemd-analyze verify /tmp/opencode/units/watch.service
  -> exit 0, no warnings

# Focused + regression tests
python3 -m unittest tests.test_core_pipeline_unit tests.test_ns_failfast \
    tests.test_pipeline_tooling_failfast tests.test_dynamic_dns_hardening
  -> Ran 60 tests ... OK (8 new core-pipeline-unit tests included)

git -c core.whitespace=cr-at-eol diff --check
  -> clean
```

`test_core_pipeline_unit.py` asserts, among others:
`Environment="PATH=<exact string>"` present, `TimeoutStartSec=6h` present,
`RuntimeMaxSec=` directive absent, `Type=oneshot`, `KillMode=control-group`,
`TimeoutStopSec=30s`, unchanged `ExecStart` (`flock` + `run-pipeline.sh`), and
unchanged timer cadence; it also runs `systemd-analyze verify` when available.

---

## 7. Timer cadence confirmation

The entire `watch.timer` block is unchanged. Verified in the file and asserted
by tests:

```
Unit=watch.service
OnCalendar=*-*-* 00:00:00 Asia/Tehran
OnCalendar=*-*-* 12:00:00 Asia/Tehran
Persistent=false
```

No `RandomizedDelaySec`. The weekly-heavy-job schedule in
`setup-weekly-jobs.sh` was not touched. The only generated-unit changes are the
two `[Service]` directives (PATH + timeout) and the expanded `systemctl show`
diagnostic line.

---

## 8. No production pipeline executed

No pipeline or service was run. `run-pipeline.sh` was not executed; no systemd
unit was installed or started; no target scanning, DNS, network, database, or
production data was touched. Validation was limited to shell syntax checks,
unit-text extraction, `systemd-analyze verify`, and offline unit tests.

---

## 9. Remaining risks

- **Applying the change requires running the installer on the host**
  (`sudo bash setup-core-pipeline.sh`). Only the repository file was edited; the
  installed `/etc/systemd/system/watch.service` is not updated until then.
- **`source ~/.zshrc` in `run-pipeline.sh`** (unchanged, per scope) may still
  adjust PATH for the child shell. The explicit systemd `Environment=` is now the
  reliable baseline, and `utils/common.py`'s `WATCH_TOOL_PATH` also prepends the
  canonical tool directories, so this is mitigated but not eliminated.
- **6 h may be too short for a future, larger pipeline.** The value is a single
  documented line in `setup-core-pipeline.sh`; re-evaluate if the full run
  approaches the bound.
- `systemd-analyze verify` ran under WSL's systemd 255; the VM's systemd version
  may differ. Both `Environment=` and `TimeoutStartSec=` are long-standing,
  stable directives, so syntax is expected to hold.
- Root's ability to descend into `/home/pouya_behnia/go/bin` (directory
  permissions) is assumed; the PATH entry can only work if the directory is
  traversable by `root` (normally true).

---

## 10. Explicit statements

- No LLM used in the implementation or tests.
- No network used.
- No Go tools installed or reinstalled.
- No Dynamic DNS files changed.
- No Static DNS files changed.
- No systemd unit was installed, started, or modified on any host.
- No timer scheduling or cadence changed.
- No Git operations performed (no add/commit/push).
- No push performed.

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: Core Pipeline Runtime Hardening
- Role: Systemd / Pipeline Reliability
