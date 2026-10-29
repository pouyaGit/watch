---
name: hermes-runtime-implementation
category: autonomous-ai-agents
description: Implement runtime changes for Hermes Agent.
---
# Hermes Runtime Implementation

Procedural skill for modifying the live Hermes Agent runtime (Python scripts, systemd units, SQLite schema) to achieve autonomous operation with proper Telegram cadence and activity tracking.

## Triggers
- User requests changes to Hermes daemon, Telegram scheduling, activity pulse, or planner behavior.
- Need to add persistent activity events, adjust notification intervals, or fix idle/planner issues.

## Procedure
1. **Locate the runtime files**
   - Daemon supervisor: `/root/hermes-recon/scripts/daemon.py`
   - Cycle worker: `/root/hermes-recon/scripts/cycle.py`
   - Notification layer: `/root/hermes-recon/lib/notify.py`
   - Status builder: `/root/hermes-recon/lib/status.py`
   - Findings/activity state: `/root/hermes-recon/lib/findings_state.py`
   - Database: `/root/hermes-recon/state/hermes.db`
   - Systemd units: `/root/hermes-recon/systemd/*.service`

2. **Add persistent activity event store**
   - Create table `activity_events` in `hermes.db` with columns: `event_id`, `timestamp`, `target`, `module`, `job_type`, `items_processed`, `items_created`, `status`.
   - Add `log_activity_event()` in `findings_state.py` to insert rows.
   - Call `log_activity_event()` from `cycle.py` after each job finishes (see `execute_job` completion).

3. **Implement 10‑minute activity pulse**
   - In `status.py`, add `build_pulse()` that queries `activity_events` for the last 600 seconds and aggregates by module/target.
   - In `notify.py`, keep two interval constants: `ACTIVITY_INTERVAL_S = 600` and `STATUS_INTERVAL_S = 1800`.
   - Modify `send_status(force=False)` to check `kv_get("last_pulse_ts")` vs `ACTIVITY_INTERVAL_S` for pulse, and `kv_get("last_status_ts")` vs `STATUS_INTERVAL_S` for full status.
   - Pulse message format per spec §28: short header, per‑module lines, "No meaningful activity" fallback.

4. **Implement 30‑minute full status**
   - Reuse existing `build_status()` (already builds full status).
   - Ensure it includes per‑target coverage (DNS, HTTP, JS, endpoints, parameters, findings).
   - Add per‑target summary by querying assets/urls/js_assets grouped by target.

5. **Fix planner idle behavior**
   - In `cycle.py` planner, when queue is empty, re‑scan for coverage gaps: stale DNS, unchecked HTTP, unanalyzed JS, parameter gaps, technology gaps, security‑analysis gaps.
   - Enqueue jobs with fair‑share scheduling across targets (already present via `per_type` budgets).
   - Ensure `daemon.py` does not sleep indefinitely when work exists; the 30‑second tick already calls `notify.send_status()` and delivers alerts.

6. **Verify systemd/cron ownership**
   - Confirm only `hermes-recon.service` runs the daemon (systemd `Restart=always`).
   - No separate cron jobs for Telegram; the daemon’s loop handles cadence.
   - Run `systemctl daemon-reload` and `systemctl restart hermes-recon` after changes.

7. **Test cadence**
   - Temporarily reduce intervals (e.g., 30 s pulse, 60 s status) via env vars or config.
   - Observe Telegram output: pulse every 10 min, full status every 30 min, alerts immediate.
   - Restart daemon and verify no duplicate workers, state preserved, scheduler resumes.

## Pitfalls & Rules
- **Never use Git/GitHub** — all verification via filesystem, processes, logs, SQLite.
- **Safety limits immutable** — 15 req/s global ceiling, no exploitation, no port scanning, no payloads.
- **Activity pulse must use deltas** — query `activity_events` WHERE `timestamp > now - 600`; never use lifetime counters.
- **Single scheduler owner** — daemon loop is the only component that calls `notify.send_status()`; do not add a second timer.
- **Parameter extraction zero count** — trace `http_check` → `assetlib.extract_assets` → `upsert_url` → `urls.params`; ensure `params` column populated and `status.py` counts `urls_with_params`.
- **Security analysis breadth** — analyzer must emit finding types beyond XSS (info disclosure, CORS, open redirect, API exposure, auth surface, JWT, CSRF, SSRF indicators, debug exposure, tech version, dependency CVE, subdomain takeover, sensitive files, security headers). Use existing safe analysis modules only.
- **Target fairness** — planner must prefer targets with oldest `last_seen` or missing coverage; fair-share budgets already exist, ensure they are not starved.
- **Restart resilience** — `activity` singleton and `activity_events` persist across restarts; daemon recovery sequence (`recover_jobs`, `alert_recovery`) must run before first cycle. `last_pulse_ts` and `last_status_ts` must be wall-clock timestamps so a restart does not force an immediate full-status resend; never use `force=True` in production.
- **Verify event diversity** — a pulse that only shows `job_type` is insufficient evidence. Inspect the actual call graph and database rows for DNS, HTTP, JS, endpoint/parameter extraction, technology analysis, security analysis, finding creation, and deduplication; require distinct module/job-type values and meaningful counts before claiming completion.
- **Full status must include per-target coverage** — `build_status()` must show a matrix of DNS/HTTP/JS per target; global aggregates alone do not satisfy Phase 2.
- **Schema includes duration** — `activity_events` has a `duration` column (float seconds) populated from `cycle.py` job timing; pulse queries should include it for future analysis.

## References
- `references/telegram-cadence.md` — message formats, interval constants, scheduler integration, and file-sink verification.
- `references/activity-events-schema.md` — SQL schema, pulse query, and event producer checklist.
- `references/planner-gap-detection.md` — coverage gap detection logic.
