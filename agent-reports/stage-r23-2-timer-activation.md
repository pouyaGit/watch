# Stage R23.2 — Timer Activation

## 0. Outcome up front

System-level activation was **not completed in this environment**: installing,
enabling, or starting a system unit requires root, and this session runs as
unprivileged user `pouya` with no passwordless sudo (`Permission denied` on
`/etc/systemd/system`, `Interactive authentication required` from systemctl).
The timer is therefore **not installed, not enabled, not active**, and **no
service run occurred**. Everything verifiable without root was verified; one
concrete activation blocker in the unit file was fixed minimally (see §9).

## 1. Pre-activation checks

- **Test suite**: `python3 -m unittest tests.test_research_agent` → **Ran 92
  tests … OK** (run both before and after the §9 fix).
- **Code reviewed**: `ai/research_agent/` (`agent.py`, `scheduler.py`,
  `sources.py`, `prompts.py`, `storage.py`), `ai/schemas/research_agent.py`
  (status vocabulary locked to RESEARCH_COMPLETED/PARTIAL/BLOCKED/FAILED;
  VULNERABLE/VERIFIED/EXPLOITED/FINDING rejected; evidence requires trusted
  content hash; Nuclei candidates forced `executed=False`, `target_url=None`;
  `production_finding` forced False), `backend/research_agent.py` (read-only,
  fail-soft view layer; no fetching, no LLM, no writes).
- **Live scheduler check** (`python3 -m ai.research_cli agent status`,
  read-only, zero network/LLM) at 20:40 Asia/Tehran:
  `Enabled: false`, `Window: 18:00-00:00 Asia/Tehran`, `In window: true`,
  `Max runtime: 300m`, `Max plans: 5`, `Network: enabled`, `LLM: disabled`,
  `Next run: 2026-09-11T18:00:00+03:30`, 2 eligible plans
  (CVE-2026-1557 → dell / indeed). Window evaluation uses the explicit
  `Asia/Tehran` timezone, and the disabled default means any timer-fired `agent
  run` exits early as `skipped: disabled` unless explicitly enabled.
- **Secret scan of both unit files**: no `api_key`, password, secret, token, or
  Mongo credential strings present.

## 2. Exact systemd units inspected

`systemd/watch-research.service` (post-§9 fix):

```
[Unit]
Description=Watch Autonomous Research Agent (research-only, bounded)
Documentation=file:/opt/watch/agent-reports/stage-r23-autonomous-research-scheduler.md
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=pouya_behnia
WorkingDirectory=/opt/watch
EnvironmentFile=/opt/watch/.env
RuntimeDirectory=watch-research
RuntimeDirectoryMode=0750
Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin"
Environment="WATCH_RESEARCH_ENABLED=true"
Environment="WATCH_RESEARCH_NETWORK=true"
Environment="WATCH_RESEARCH_LOCK=/run/watch-research/research.lock"
ExecStart=/usr/bin/flock -n /run/watch-research/service.lock \
    /opt/watch/venv/bin/python3 -m ai.research_cli agent run
TimeoutStartSec=330min
TimeoutStopSec=30s
KillMode=control-group
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/opt/watch/ai_data /opt/watch/logs /run/watch-research
MemoryMax=1G
CPUQuota=150%

[Install]
WantedBy=multi-user.target
```

`systemd/watch-research.timer` (unmodified):

```
[Unit]
Description=Run Watch Autonomous Research Agent hourly (exact window enforced by the service)

[Timer]
Unit=watch-research.service
OnCalendar=hourly
Persistent=true
AccuracySec=1min

[Install]
WantedBy=timers.target
```

`systemd-analyze verify` on both files: exit 0, no warnings.

## 3. Environment / configuration verified

- **User**: `User=pouya_behnia` — non-root as required. Note: this UID does
  **not** exist on this box (see §10); it is a prerequisite for the Google VM.
- **ExecStart**: invokes the existing research-agent CLI
  (`python3 -m ai.research_cli agent run`) — no new entrypoint, no wrapper
  script, no architecture change.
- **WATCH_RESEARCH_ENABLED=true**: was supplied by **neither** the unit nor
  `.env` (`.env` contains zero `WATCH_RESEARCH_*` keys) — a concrete blocker,
  fixed by adding it explicitly to the unit (§9).
- **WATCH_RESEARCH_NETWORK=true**: likewise absent; added explicitly for
  auditability (code default is already true; dry-run stays zero-network).
- **WATCH_RESEARCH_LLM**: deliberately left at its safe default (disabled →
  deterministic/offline mode). `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`,
  `OPENROUTER_MAX_TOKENS`, `AI_PROVIDER` are all present in `.env`, so the
  condition for opting in is satisfied, but autonomous hourly LLM spend is a
  policy decision for the VM owner; enabling it later is a one-line,
  deliberate follow-up.
- **Bounds intact**: `TimeoutStartSec=330min` (covers the 300m budget +
  margin; `RuntimeMaxSec` correctly not used with `Type=oneshot`),
  `MemoryMax=1G`, `CPUQuota=150%`, task caps enforced in the scheduler
  (max 5 plans, max 300 min, max 12 sources, 6000-char doc cap).
- **Lock behavior**: `RuntimeDirectory=watch-research` (mode 0750) hosts both
  `/run/watch-research/service.lock` (outer `flock -n` in ExecStart) and
  `/run/watch-research/research.lock` (in-app `flock(2)` via
  `WATCH_RESEARCH_LOCK`; different paths so the two locks cannot conflict).
- **Secrets**: environment carries no secret values — only `PATH`, scheduler
  policy flags, and the lock path. Credentials stay in `.env`
  (`EnvironmentFile`), which is gitignored and never echoed into units.

## 4. Test results

- `python3 -m unittest tests.test_research_agent` → **Ran 92 tests … OK**
  (before the §9 fix and re-run after it; identical result).
- `systemd-analyze verify systemd/watch-research.service
  systemd/watch-research.timer` → exit 0.
- `git diff --check` → clean.

## 5. Exact activation commands (with outcomes)

All run as unprivileged `pouya`; every privileged step failed as expected
(no workaround attempted):

1. `cp systemd/watch-research.service systemd/watch-research.timer
   /etc/systemd/system/` → `Permission denied` (exit 1) for both files.
2. `sudo -n systemctl daemon-reload` → `sudo: a password is required`
   (exit 1).
3. `systemctl enable watch-research.timer` → `Failed to enable unit:
   Interactive authentication required.` (exit 1).
4. `systemctl start watch-research.timer` → `Failed to start
   watch-research.timer: Interactive authentication required.` (exit 1).

No `daemon-reload`, `enable`, or `start` took effect. `watch-research.service`
was never started manually.

## 6. Timer status and next scheduled run

- `systemctl status watch-research.timer` → `Unit watch-research.timer could
  not be found.`
- `systemctl list-timers --all | grep watch-research` → no match.
- Once installed on the VM, the schedule is `OnCalendar=hourly` (no invented
  schedule; matches the R23 design of an hourly trigger with the service
  enforcing the exact 18:00–00:00 Asia/Tehran window).

## 7. Whether a service run occurred

**No.** No service run occurred: the unit is not installed, the timer was
never enabled or started, both journals report `-- No entries --`, and no
`ai.research_cli agent run` process exists. (The R23.1 artifacts under
`ai_data/research/agent/` came from manual CLI invocations, not from systemd.)

## 8. Research safety verification

- Safety architecture unchanged: schema-forbidden statuses, trusted-hash
  evidence, research-only Nuclei candidates, `production_finding=False`,
  SSRF-guarded bounded public sources, no target/program fetching.
- Window not bypassed: the service never ran; additionally the code gate was
  verified live (`In window: true` at 20:40 Tehran via explicit tz) and by the
  test suite (disabled-default and out-of-window runs exit `skipped` before any
  network/LLM/work). A run can only proceed when explicitly enabled **and**
  inside 18:00–00:00 Asia/Tehran.
- Overlap safety: `OnCalendar=hourly` can fire while a ≤330 min run is still
  active; overlapping research is prevented by the outer `flock -n` (second
  instance exits immediately) with the in-app `flock(2)` as defense in depth
  — enforced by locks, not by the schedule.
- `Persistent=true` is understood: after downtime, at most one catch-up
  trigger fires at boot, and it still passes through the same enabled/window
  gate plus both locks before any work.

## 9. Any changes made

One minimal fix for a concrete activation blocker (§3): added two explicit
policy lines (plus an explanatory comment) to
`systemd/watch-research.service`:

```
Environment="WATCH_RESEARCH_ENABLED=true"
Environment="WATCH_RESEARCH_NETWORK=true"
```

Without these, an activated timer would fire a worker that immediately exits
`skipped: disabled`. Focused verification re-run: 92/92 tests OK,
`systemd-analyze verify` clean, `git diff --check` clean. No architecture,
provider, scanning, Nuclei, PoC, 5B–5J, finding, or alert changes;
`database/db.py` untouched; no git operations performed.

## 10. Any remaining limitations

1. **Activation itself is blocked in this environment** (no root, no
   passwordless sudo). It must be performed on the Google VM by a privileged
   operator: copy the two unit files to `/etc/systemd/system/`,
   `daemon-reload`, `enable --now watch-research.timer`, then verify with the
   §5–§8 commands.
2. **Service user**: `pouya_behnia` does not exist on this box (hostname
   `DESKTOP-G0VG53D`, operator `pouya`) — this environment is evidently not
   the Google VM. The `User=` line was intentionally left unchanged; the VM
   must provide that account (or its designated service account, as a
   deliberate VM-side decision).
3. **LLM stays disabled** for first activation (deterministic/offline mode);
   opting into autonomous LLM spend is a one-line owner decision
   (`WATCH_RESEARCH_LLM=true`, creds already present).
4. Hourly triggers outside 18:00–00:00 exit early by design (not a defect).
5. R23 working-tree changes remain uncommitted per instructions (no commit/push
   performed).

## Agent / Model
- Model: opencode-go/deepseek-flash
- Stage: R23.2
- Role: Timer Activation
