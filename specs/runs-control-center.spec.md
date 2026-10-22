# Spec — Runs & Control Center for the Watch dashboard

Audience: an implementer (e.g. Haiku) working in this repo (`/opt/watch`).
Goal: replace the stale, incomplete `/ui/runs` page with a real control center
that (a) shows everything running on the server right now with its results,
(b) lets the operator launch any tool on any scope for any duration, and
(c) exposes stop / pause / resume / re-run / next controls.

Keep the codebase's existing style (FastAPI + mongoengine + server-rendered
HTML in `backend/routers/pages.py` + small JS in `web/static/js/app.js`).

---

## 1. Current state (read this first)

Launchable work is defined and run through four places:

- `backend/tasks_registry.py` — a **static allowlist** (`TASKS_REGISTRY`) of 9
  scripts the dashboard may launch: `enum`, `dns_resolve`, `http`,
  `crawl_fresh`, `crawl_all`, `param_discovery`, `dns_precheck`, `dns_static`,
  `dns_dynamic`. Each entry has `name`, `script`, `default_args`, `filter`
  (whether it accepts `--filter <domain>`). Task ids and scripts come ONLY from
  this table (security). Keep this allowlist model.
- `backend/task_runner.py` — launches a registry script as a **detached process
  group**, writes a `TaskRun` row, a waiter thread records the exit code, and
  `reconcile()` corrects a status by checking the PID is alive. `stop_task()`
  signals the process group (SIGTERM, then SIGKILL). Logs go to
  `/opt/watch/logs/tasks/`.
- `backend/routers/tasks.py` — endpoints: `GET /api/tasks`,
  `GET /api/tasks/runs`, `GET /api/tasks/runs/{id}/log`,
  `POST /api/tasks/{task_id}/run`, `POST /api/tasks/{task_id}/stop`.
- `backend/models.py` — `TaskRun`: `task_id, target, started_at, finished_at,
  status(running|success|failed|stopped|unknown), exit_code, triggered_by,
  pid, log_path`.

**Why `/ui/runs` is effectively broken:** a `TaskRun` is created ONLY when a
script is launched through the dashboard. The real, continuous work now runs
under **systemd** and never touches `TaskRun`:

- `watch.service` (+`watch.timer`) — the 12h pipeline (sync → enum → ns → http).
- `watch-heavy.service` — the 24/7 heavy worker that rotates lanes
  `brute → crawl → param` (see `watch_heavy_worker.py`).
- `watch-ct-stream.service` — real-time Certificate Transparency ingestion.

So the operator can't see what is actually running, and the Runs page shows
three stale rows from weeks ago. This spec fixes that and adds launch + control.

---

## 2. Goals

- **G1 — Live visibility:** one page shows everything running now: the systemd
  services (pipeline, heavy worker + its *current lane*, CT stream) AND any
  ad-hoc dashboard runs, each with status, start time, elapsed, current
  activity, and a live log tail.
- **G2 — Launch panel:** pick one or more tools × a scope (all / chosen
  programs / chosen domains) × a duration (until stopped / N minutes) and start.
- **G3 — Controls:** per run — stop, pause, resume, re-run; for multi-step runs
  and the heavy worker — "next/skip". For systemd services — stop/restart.
- **G4 — Results:** each finished run shows what it produced (new subdomains /
  live / http for its scope) with links to the filtered list pages.

## 3. Non-goals / hard constraints

- **Security first.** Never run an arbitrary command. Tool identity comes only
  from the registry allowlist; scope domains/programs MUST exist in the
  `Programs` collection (reject anything else — this prevents scanning
  out-of-scope or attacker-chosen hosts). systemd control is limited to an
  allowlist of exactly three unit names.
- **Small VPS (2 cores / 4 GB).** Do not let the UI spawn unbounded parallel
  heavy jobs. Ad-hoc launches run **serially** (a queue), and must not fight the
  `watch-heavy.service`. Prefer one heavy job at a time.
- **Auth.** Every new endpoint stays behind the existing auth middleware
  (session login or `X-API-Key`), like the rest of `/api/*`.
- The dashboard/API process runs as **root** (it already does via
  `watch-api.service`), so `systemctl` calls and signals work.

---

## 4. Data model changes — `backend/models.py`

Extend `TaskRun` (keep existing fields, all new ones optional/defaulted):

```
tool         StringField()          # canonical tool/stage, e.g. "x8", "subfinder", "ns"
scope_kind   StringField()          # "all" | "programs" | "domains"
scope        ListField(StringField())   # the chosen programs or domains ([] when all)
max_minutes  IntField()             # duration budget; None = until stopped
source       StringField(default="dashboard")  # dashboard | systemd | heavy-lane | pipeline
group_id     StringField()          # RunGroup id when one launch expands to many invocations
summary      DictField()            # {"new_subs":N,"new_live":N,"new_http":N} filled at finish
```

Add `paused` to the allowed `status` values:
`running | paused | success | failed | stopped | unknown`.

(A separate `RunGroup` document is optional; `group_id` on `TaskRun` is enough.)

---

## 5. Registry changes — `backend/tasks_registry.py`

The operator asked to run these tools by name: **katana, x8, subfinder, crtsh,
ns, http** (plus the existing aggregates). Individual enum sources take a
**positional domain** argument (e.g. `python enum/watch_subfinder.py dell.com`),
NOT `--filter`. So add an `arg_style` to every entry:

- `arg_style = "filter_flag"` → pass `--filter <domain>` (crawl_all, param,
  dns_static/dynamic/precheck).
- `arg_style = "positional_domain"` → pass the domain as the last argv
  (per-domain enum sources + `ns/watch_ns.py`).
- `arg_style = "none"` → whole-DB scripts, no scope arg (watch_enum_all,
  watch_ns_all, watch_http_all, crawl_fresh).

Add these entries (scripts already exist in the repo):

| task_id | script | arg_style | max_minutes? |
|---|---|---|---|
| `subfinder` | `enum/watch_subfinder.py` | positional_domain | no (runner timeout) |
| `crtsh` | `enum/watch_crtsh.py` | positional_domain | no |
| `certspotter` | `enum/watch_certspotter.py` | positional_domain | no |
| `ns_domain` | `ns/watch_ns.py` | positional_domain | no |
| `brute` | `ns/watch_brute_worker.py` | filter_flag | yes (`--max-minutes`) |

Keep the existing 9. Also add a per-entry `supports_all` flag (true for
`arg_style="none"` and for `--filter`-less whole-DB runs).

Each entry gains `tool` (canonical short name used in the UI and `TaskRun.tool`).

---

## 6. Scope → invocation expansion (new helper in `task_runner.py`)

`expand_invocations(task_id, scope_kind, scope, max_minutes) -> list[argv]`:

- Validate `task_id` against the registry; validate every domain in `scope`
  exists as a `Programs.scopes` entry (or every program name exists). Reject
  otherwise with `RunError`.
- `scope_kind == "all"`:
  - `arg_style="none"` or `supports_all` → **one** invocation, no scope arg.
  - per-domain-only tools → expand to one invocation **per in-scope domain**
    (all domains of all programs).
- `scope_kind == "programs"` → gather each program's `scopes`, then as above.
- `scope_kind == "domains"` → use the given domains directly.
- Append `--max-minutes <n>` only when the script supports it; otherwise the
  runner enforces the budget itself (see §7).

One UI launch = one `group_id`; each expanded argv = one child `TaskRun` with
that `group_id`. Children run **sequentially** (a worker thread / queue), so the
box is never overwhelmed.

## 7. Duration enforcement — `task_runner.py`

- Scripts that accept `--max-minutes`: pass it through.
- Scripts that don't (enum sources, ns, http, crawl_fresh): the runner starts a
  watchdog that SIGTERMs (then SIGKILLs) the process group after `max_minutes`,
  and marks the run `stopped`.
- `max_minutes is None` ("until stopped") → no watchdog; only a manual stop ends
  it. Clamp any provided value to `1..1440`.

## 8. Live view of systemd-managed work — NEW `GET /api/tasks/live`

Return a single list combining:

1. **System services** — for each of `watch.service`, `watch-heavy.service`,
   `watch-ct-stream.service`: read
   `systemctl show <unit> --property=ActiveState,SubState,ExecMainStartTimestamp,MainPID`
   (subprocess). Map to `{source:"systemd", unit, name, status, started_at,
   elapsed, activity}`.
2. **Heavy worker current lane** — `watch_heavy_worker.py` must write a small
   JSON state file `/opt/watch/logs/heavy_state.json` whenever it switches lanes:
   `{"lane":"crawl","target":"digicert.com","since":"<iso>","cycle":N}`. The API
   reads it to fill the heavy service's `activity` (e.g. "crawl → digicert.com").
   *(Small change to `watch_heavy_worker.py`: write this file in `run_lane()`.)*
3. **Pipeline current stage** — parse the tail of the newest
   `/opt/watch/logs/pipeline_*.log` for the last `===== <stage> =====` marker to
   show the pipeline's current stage.
4. **Ad-hoc dashboard runs** — all `TaskRun(status in {running,paused})` after
   `reconcile()`, with their `tool`, `scope`, elapsed, `group_id`.

Poll this endpoint from the UI every ~5s.

## 9. Launch — NEW `POST /api/runs`

Body: `{"tools": ["x8"], "scope_kind": "domains", "scope": ["dell.com"],
"max_minutes": 30}` (max_minutes null = until stopped).

- Validate tools (registry) and scope (Programs). For each tool, call
  `expand_invocations(...)`, create the child `TaskRun`s with a shared
  `group_id`, enqueue them, and return `{group_id, created: N}`.
- A single background queue runs children one at a time (serial). Status 201.

Keep the existing `POST /api/tasks/{task_id}/run` for backward compatibility
(or reimplement it on top of `/api/runs`).

## 10. Controls

Endpoints (all POST, auth-gated):

- `/api/tasks/runs/{id}/stop` — exists; set status `stopped`.
- `/api/tasks/runs/{id}/pause` — `os.killpg(pgid, SIGSTOP)`, status `paused`.
- `/api/tasks/runs/{id}/resume` — `os.killpg(pgid, SIGCONT)`, status `running`.
- `/api/tasks/runs/{id}/rerun` — launch a new run with the same
  `tool/scope/max_minutes`; returns the new run.
- `/api/groups/{group_id}/next` — stop the current child; the queue advances to
  the next invocation.
- `/api/groups/{group_id}/stop` — stop the whole group (current child +
  dequeue the rest).
- `/api/system/{unit}/{action}` — `action ∈ {stop,restart}`, `unit` ∈ the
  three-unit allowlist only. Runs `systemctl <action> <unit>`.

> Note on pause: SIGSTOP freezes the process; long-lived network scans may drop
> connections when resumed. Document this in the UI tooltip. Fine for the stated
> use. (Pausing the *heavy worker lane* is phase 3 — see §12.)

## 11. Results summary

When a child `TaskRun` finishes (`_waiter`), compute and store `summary`:
count `Subdomains`, `LiveSubdomains`, `Http` with `created_date >= started_at`
restricted to the run's scope (by `program_name`/`scope`). UI shows e.g.
"→ 12 new subs · 3 live · 1 http" linking to the existing filtered pages
(`/ui/subdomains/program/{p}`, `/ui/lives/program/{p}`, `/ui/http/program/{p}`).

## 12. Heavy-worker control channel (PHASE 3, optional)

To pause/skip the heavy worker's current lane from the UI:
`watch_heavy_worker.py` reads `/opt/watch/logs/heavy_control.json` between and
during lanes: `{"command":"skip"|"pause"|"resume"|"stop-after-lane"}`. The API
writes this file; the worker acts on it (skip = terminate the current lane
child; pause = SIGSTOP the child and wait; etc.). Until this exists, the UI
shows the heavy service and offers only systemd stop/restart for it.

## 13. UI — rebuild `/ui/runs` (`backend/routers/pages.py` + `web/`)

Three sections on one page, auto-refreshing the first via `/api/tasks/live`:

- **A. Live now** — rows for system services (pipeline + stage, heavy + lane,
  CT stream) and running/paused ad-hoc runs. Columns: name, scope/target,
  status badge, elapsed, current activity, actions `[log] [stop] [pause/resume]
  [next]` (actions shown only where they apply: systemd rows get `[stop]
  [restart]`; ad-hoc rows get the full set).
- **B. Launch** — a form:
  - Tools: multi-select checkboxes (subfinder, crtsh, certspotter, enum-all, ns,
    http, katana/crawl_all, x8/param, brute, dns_precheck).
  - Scope: radio `All` / `Programs` (multi-select populated from `Programs`) /
    `Domains` (multi-select or textarea of in-scope domains).
  - Duration: radio `Until stopped` / `Minutes` (number input).
  - `[Run]` → `POST /api/runs`.
- **C. History** — the existing paginated `TaskRun` list, plus `tool`, `scope`,
  duration, result `summary`, and `[log] [re-run]` per row.

Log viewer: a drawer/modal that polls `/api/tasks/runs/{id}/log?tail=300` every
3s while the run is live. Reuse the existing log endpoint.

## 14. Security checklist (must all hold)

- [ ] `task_id`/tool only from `TASKS_REGISTRY`; no free-form script/args.
- [ ] every scope domain ∈ some `Programs.scopes`; every program ∈ `Programs`.
- [ ] `systemctl` control restricted to `{watch.service, watch-heavy.service,
      watch-ct-stream.service}` and actions `{stop, restart}` only.
- [ ] `max_minutes` clamped to `1..1440`; null allowed only for "until stopped".
- [ ] all endpoints behind the existing auth middleware.
- [ ] no shell=True with interpolated input; argv lists only (as task_runner
      already does).

## 15. Acceptance criteria

1. `/ui/runs` shows `watch-heavy.service` live **with its current lane and
   target** (e.g. "crawl → digicert.com"), the pipeline with its current stage,
   and CT stream — all auto-refreshing.
2. Launching **x8 on dell.com for 30 min** from the UI: appears in "Live now",
   its log tails live, and on finish it shows result counts + working links.
3. Launching **subfinder on all programs, until stopped** expands to one child
   per domain, runs them serially, and can be stopped as a group.
4. stop / pause / resume / re-run work on an ad-hoc run; stop/restart work on the
   three systemd services.
5. No way to run an arbitrary command or scope an out-of-scope domain; all
   endpoints require auth.

## 16. Suggested implementation order

- **Phase 1 (fix the broken page):** `GET /api/tasks/live` (systemd + running
  TaskRuns), `heavy_state.json` written by `watch_heavy_worker.py`, rebuild the
  "Live now" + "History" sections. No new launching yet.
- **Phase 2 (launch panel):** registry `arg_style`/new tools,
  `expand_invocations`, serial queue, `POST /api/runs`, duration watchdog,
  result summaries, the "Launch" form.
- **Phase 3 (advanced control):** pause/resume, rerun, group next/stop, systemd
  stop/restart buttons, heavy-worker control channel.

## 17. Files to touch

- `backend/models.py` — extend `TaskRun`.
- `backend/tasks_registry.py` — `arg_style`, `tool`, new entries.
- `backend/task_runner.py` — `expand_invocations`, serial queue, duration
  watchdog, pause/resume, summaries, systemd helpers.
- `backend/routers/tasks.py` — new endpoints (`/api/tasks/live`, `/api/runs`,
  pause/resume/rerun, group next/stop, `/api/system/...`).
- `backend/routers/pages.py` — rebuild the `/ui/runs` handler/template.
- `web/static/js/app.js` + `web/templates/` — Live auto-refresh, Launch form,
  log drawer.
- `watch_heavy_worker.py` — write `logs/heavy_state.json` per lane (Phase 1) and
  read `logs/heavy_control.json` (Phase 3).

---

### Appendix — current registry tasks (reference)

`enum, dns_resolve, http, crawl_fresh` (whole-DB, no filter);
`crawl_all, param_discovery, dns_precheck, dns_static, dns_dynamic`
(accept `--filter <domain>` + `--max-minutes`).
