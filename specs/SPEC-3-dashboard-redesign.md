# SPEC 3 — Dashboard v2: a professional bug-hunter console

**Target project:** `/opt/watch`. FastAPI (`api.py`) on `0.0.0.0:5000`,
mongoengine models in `database/db.py`, venv `/opt/watch/venv`.
**Design inspiration:** the `main-full-backup` branch's `web/` (Jinja templates
`base.html`, `macros.html`, `dashboard.html`, `programs.html`, `program.html`,
`domains.html`, `http_list.html`, `endpoints_list.html`, `search.html`,
`runs.html`, `dns_status.html`, `changes.html`) and `backend/routers/`
(`pages.py`, `programs.py`, `runs.py`, `tasks.py`, `system.py`) + the task
runner (`backend/task_runner.py`, `backend/tasks_registry.py`,
`backend/models.py:TaskRun`). **Reuse those patterns; do NOT pull in any
`ai/`, `backend/research*`, `backend/soc`, `backend/aec`, or `web/.../research|soc|aec`
code.** This dashboard is for recon only.

**Depends on SPEC 2** (auth). Build on top of it; all new routes sit behind the
session/API-key auth from SPEC 2.

---

## 1. Goal

Turn the current inline-HTML `api.py` into a **professional, fast, dark-themed
recon console** that a bug-bounty hunter actually wants to live in: add/remove
targets, run and stop recon stages per target, search everything, and pivot
quickly through subdomains / live hosts / HTTP / URLs / endpoints / params —
with providers, tech, status codes, and "what's new" front and center.

---

## 2. Architecture (refactor, keep it clean)

1. Introduce **Jinja2 templates** + **static assets**:
   - `web/templates/` (base + pages), `web/static/css/app.css`, `web/static/js/app.js`.
   - Mount `StaticFiles` at `/static`; configure `Jinja2Templates(directory="web/templates")`.
2. Split `api.py` into FastAPI **routers** under a new `backend/` *recon-only*
   package (create fresh; do not import the ai branch's backend):
   - `backend/__init__.py`
   - `backend/routers/pages.py`    — HTML pages (dashboard, program, lists, search, runs, dns status, changes)
   - `backend/routers/targets.py`  — add/remove/list targets (Programs CRUD) JSON+form
   - `backend/routers/tasks.py`    — run/stop/status of recon stages
   - `backend/routers/data_api.py` — the existing JSON `/api/*` endpoints (move them here unchanged in behavior)
   - `backend/task_runner.py`, `backend/tasks_registry.py` — ported, recon-only (see §5)
   - `backend/models.py` — `TaskRun` model (port from full branch) + nothing else
3. `api.py` becomes thin: build `FastAPI`, add SPEC-2 middleware, `include_router(...)`
   each router, mount static, run uvicorn. **Preserve every existing route path**
   (`/`, `/ui/...`, `/api/...`) so nothing breaks; you are reorganizing, not renaming.
4. Keep all DB access through `database/db.py` models and helpers. Server-side
   `count()`/aggregation only — never load whole collections into Python.

---

## 3. Visual design (make it excellent)

- Dark, high-contrast, monospace-accented "hacker console" aesthetic, but clean
  and modern (think a well-built SOC console, not a toy). Reuse/extend the color
  system already in `api.py:PAGE_CSS` (`#0d1117` bg, `#58a6ff` headings,
  `#f0883e` accent, GitHub-dark palette). Put it in `web/static/css/app.css`.
- Persistent **left sidebar** (or top nav): Dashboard · Targets · Search · Runs ·
  DNS Bruteforce · Recent Changes. A global **search box** in the header on every
  page.
- Responsive (usable on a laptop and a phone). No heavy frontend framework —
  vanilla JS + fetch + a tiny bit of CSS. Optional: a single small lib (e.g.
  htmx) is acceptable if it reduces custom JS; if used, vendor it into
  `web/static/` (no CDN dependency, the server may be offline).
- Every table: sortable columns, client-or-server pagination, a per-column
  filter box, copy-to-clipboard on hostnames/URLs, and row counts.
- Accessibility: readable contrast in dark mode, keyboard focus states.

---

## 4. Pages & features (the hunter's needs)

### 4.1 Dashboard (`GET /`)
- Top KPI row: total programs, subdomains, live subs, HTTP services, URLs,
  endpoints — all server-side counts (reuse `/api/stats`).
- **"Fresh in last 24h"** banner: new subdomains + new HTTP since 24h ago, each a
  click-through. (Reuse the `created_date`/`last_update` fields.)
- One **card per program** (target) showing: counts (subs/live/http/urls/endpoints),
  top technologies (badges, from `Http.tech`), providers present (badges), and a
  **Run** control (see §5). Bruteforce providers `staticBF`/`dynamicBF` get a
  distinct highlighted badge (they're the high-value finds nobody else has).
- A compact **Recent Changes** widget (new live sub, status/title change, new
  http) from the change-events timeline if present (`database/change_events.py`).

### 4.2 Targets (`/ui/targets`) + add/remove — **NEW**
- List all programs with scopes, ooscopes, counts, created date.
- **Add target** form (and `POST /api/targets`): fields `program_name`,
  `scopes` (newline/comma list), `ooscopes` (optional list). On submit:
  `upsert_program(program_name, scopes, ooscopes, {})` from `database/db.py`.
  Validate: non-empty program_name (slug `[a-z0-9_-]+`), each scope a bare apex
  domain (no scheme/path), dedupe, lowercase. Reject duplicates with a clear msg.
- **Remove target** (`POST /api/targets/{name}/delete`, confirm in UI): call
  `delete_program_and_related(program_name)`. Require a typed confirmation of the
  program name in the UI before enabling the delete button (destructive).
- **Edit scopes** (`POST /api/targets/{name}`): re-`upsert_program` with new
  scope/ooscope lists (keeps existing data).

### 4.3 Per-target view (`/ui/program/{name}`)
- Tabs/sections: Subdomains · Live · HTTP · URLs · Endpoints · Params · DNS-BF status.
- **Subdomains by provider**: a provider breakdown (counts per provider:
  subfinder, crtsh, findomain, assetfinder, abuseipdb, wayback, staticBF,
  dynamicBF, **ctstream** [from SPEC 1]) with a click to list that provider's
  unique subs. Reuse existing `provider_counts`/`unique_provider_count`/
  `get_unique_provider_subdomains` logic from `api.py`.
- **HTTP by provider** and **HTTP by tech**: filter HTTP services by the
  originating provider and by technology badge (existing
  `/ui/http/provider/...` and `/ui/http/tech/...` behavior — keep).
- HTTP table columns a hunter wants: host, status (color-coded 2xx/3xx/4xx/5xx),
  title, tech badges, IPs, final_url (redirect target), favicon hash, last_update.
- Endpoints/params: show normalized endpoints and discovered parameters
  (`Endpoints`, `Urls.params`), with quick filters.

### 4.4 Global Search (`/ui/search?q=...`) — **make it great**
- One box searches across: Subdomains (`subdomain`), HTTP (`subdomain`,`title`,`url`,`tech`),
  URLs (`url`,`path`,`params`), Endpoints (`path`), Params. Optional `program=` filter.
- Results grouped by type with counts, each row click-through to its detail/list.
- Support simple operators: `tech:nginx`, `status:200`, `provider:ctstream`,
  `program:dell`, plain substrings. Implement as server-side mongoengine queries
  (regex on indexed fields; cap results + paginate). Document the grammar on the page.
- Fast: never scan whole collections; use indexed fields and `limit`.

### 4.5 Runs (`/ui/runs`) — live task status (see §5)
- Table of recent `TaskRun`s: task, target (if any), status (running/success/
  failed/stopped), started, duration, exit code, pid, link to log tail.
- Auto-refreshing status badges (poll `/api/tasks/.../status.json` every few sec).

### 4.6 DNS bruteforce status (`/ui/dns-bruteforce/status`) and Recent Changes
(`/ui/changes`) — port the existing/full-branch pages.

---

## 5. Run / Stop recon stages from the dashboard — **core feature**

Reuse the **security-hardened** pattern from the full branch. Non-negotiable:
user input NEVER builds a command; only allowlisted registry entries run.

### 5.1 `backend/tasks_registry.py` (allowlist)
Port it, with `ALLOWED_SCRIPT_DIRS = ("enum", "ns", "http", "crawl")` and these
entries (task_id → {name, script abspath, default_args}):

| task_id | script | default_args |
|---|---|---|
| `enum` | `enum/watch_enum_all.py` | `[]` |
| `dns_resolve` | `ns/watch_ns_all.py` | `[]` |
| `http` | `http/watch_http_all.py` | `[]` |
| `crawl_fresh` | `crawl/watch_crawl_fresh.py` | `[]` |
| `crawl_all` | `crawl/watch_crawl_all.py` | `["--max-minutes","300"]` |
| `param_discovery` | `crawl/watch_param_discovery.py` | `["--max-minutes","180"]` |
| `dns_precheck` | `ns/watch_dns_precheck.py` | `["--max-minutes","60"]` |
| `dns_static` | `ns/watch_dns_static.py` | `["--max-minutes","180"]` |
| `dns_dynamic` | `ns/watch_dns_dynamic.py` | `["--max-minutes","180"]` |

Keep the import-time validation (forbidden shell chars, path confinement under
`/opt/watch/<allowed dir>/`, fail closed). The core 12h `watch.timer` pipeline
stays on systemd and is intentionally NOT in the registry.

### 5.2 `backend/task_runner.py`
Port it. Spawn with `subprocess.Popen(argv, start_new_session=True,
cwd="/opt/watch", stdout→log file, stderr=STDOUT, stdin=DEVNULL,
env={**os.environ,"TASK_RUN_ID":str(run.id)})`. Record `TaskRun{task_id, target,
status="running", pid, started_at, log_path}`. Logs to `/opt/watch/logs/tasks/<task_id>-<runid>.log`.

**Add a per-target option**: `run_task(task_id, target=None, ...)`. When `target`
is a program name, validate it exists in `Programs`, resolve its first scope, and
append `["--filter", <scope_or_program>]` **only if** the script supports
`--filter` (enum/ns/http/crawl/param scripts accept `--filter <domain>`; verify
each script's argparse before enabling it per-target; if a script lacks
`--filter`, run it global and note that in the UI). Target value must be matched
against the DB allowlist (existing program names) — never passed raw from the
client into argv beyond a validated, existing scope string.

**Add STOP** (the full branch had run but no stop):
```python
def stop_task(run_id) -> TaskRun   # SIGTERM the process GROUP (os.killpg(os.getpgid(pid), SIGTERM)),
                                   # wait up to 10s, then SIGKILL; set status="stopped", finished_at=now.
```
`start_new_session=True` makes the child a group leader, so killing the group
reaps its tool subprocesses (httpx, katana, puredns, …) too. Guard against
killing an already-dead pid and against pid reuse (only kill if the TaskRun is
still `running` and `_pid_alive`).

### 5.3 `backend/routers/tasks.py` (routes, all auth-protected)
| Method | Path | Action |
|---|---|---|
| GET  | `/api/tasks` | list registry + latest status per task |
| POST | `/api/tasks/{task_id}/run` | launch (optional form/json `target`) → TaskRun |
| POST | `/api/tasks/{task_id}/stop` | stop the latest running run (or `?run_id=`) |
| GET  | `/api/tasks/{task_id}/status.json` | `{status,pid,started_at,exit_code}` |
| GET  | `/api/tasks/runs` | paginated recent `TaskRun`s |
| GET  | `/api/tasks/runs/{run_id}/log?tail=200` | last N log lines (read-only) |

UI: on each program card and the per-target page, a **Run ▾** menu (enum / resolve
/ http / crawl / BF…) and, while running, a **Stop** button + live status badge.
Concurrency guard: refuse to start a task that is already `running` for the same
`(task_id, target)` (return the existing run).

### 5.4 `backend/models.py`
Port `TaskRun` (fields: `task_id, target(optional, new), started_at, finished_at,
status[running|success|failed|stopped], exit_code, triggered_by, pid, log_path`;
indexes on `task_id,-started_at` and `status`). `mark_finished()` in the scripts
already sets success/failed via `backend.task_report` + `TASK_RUN_ID` — keep that
path working (the restored scripts already import `backend.task_report`
defensively; ensure `backend/task_report.py` + `backend/models.py` exist so the
guarded import resolves and status is accurate).

---

## 6. Safety & scope (bug-hunter discipline)
- **Running a stage performs ACTIVE recon** against that target's scope. That's
  intended, but: never run a stage for a program/scope that isn't in the DB; the
  target selector is a dropdown of existing programs only.
- Respect `ooscopes` — the scripts already do; don't bypass them.
- Destructive actions (delete target) require typed confirmation + are POST-only.
- No raw shell anywhere. `shell=False`, argv lists, registry allowlist, path
  confinement. User input can only select a `task_id` from the registry and a
  `target` that already exists in `Programs`.

---

## 7. Acceptance criteria
1. `/` renders the new dashboard with per-program cards, KPIs, fresh-24h, and
   Run controls. All counts are server-side.
2. Add a target via the UI → it appears, `Programs` doc created via
   `upsert_program`. Delete (with typed confirm) → gone via
   `delete_program_and_related`.
3. Click **Run → enum** on a target → a `TaskRun` goes `running` with a real pid;
   the Runs page shows it live; log tail is viewable.
4. Click **Stop** → process group is killed, status flips to `stopped` within
   ~10s, no orphaned tool processes remain (`pgrep -g <pgid>` empty).
5. Search `tech:nginx program:dell` returns only dell nginx HTTP rows; `status:200`,
   `provider:ctstream` filters work; results paginate.
6. Subdomains-by-provider and HTTP-by-provider/tech views match existing data.
7. All pages require login (SPEC 2); `/api/*` still works with a valid API key.
8. Every existing route path still resolves (no regressions).
9. `python -m py_compile` clean across all new/edited files; `GET /` returns 200
   logged-in, `303`→`/login` logged-out.
10. No `ai/`/`research`/`soc`/`aec` imports anywhere in the new code
    (`grep -rE "import (ai|backend\.(research|soc|aec))" backend/ api.py` → empty).

## 8. Suggested build order
1. Scaffolding: templates dir, static, Jinja setup, base.html + nav, move PAGE_CSS → app.css.
2. Port `TaskRun` model + `task_report.py` + `task_runner.py` + `tasks_registry.py` (recon-only).
3. `targets.py` (add/remove/edit) — smallest valuable slice.
4. `tasks.py` run/stop/status + Runs page.
5. Refactor existing `/ui` + `/api` routes into `pages.py`/`data_api.py` unchanged.
6. Global search.
7. Polish: fresh-24h, provider/tech badges, recent changes, copy-to-clipboard, sorting.
