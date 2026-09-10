# Stage R20 — Deterministic Research Workflow

## 1. Objective

Turn the R18 research queue into a small persistent **research workflow**: a
researcher can take a queue candidate (CVE x program), track TODO /
IN_PROGRESS / BLOCKED / DONE, record notes/blocker/result, with a bounded audit
history and safe concurrent updates. Research management only — never
validation, exploitation, or a finding.

## 2. Exact files changed

- `ai/schemas/research_task.py` — **new**. `ResearchTask` /
  `ResearchTaskAuditEntry` Pydantic models, statuses, and bounded field limits.
- `ai/knowledge/task_store.py` — **new**. `ResearchTaskStore`: deterministic
  task ids, state machine, atomic local-JSON persistence, optimistic
  concurrency (version + advisory lock), bounded audit history, validation.
- `backend/research_tasks.py` — **new**. Thin adapter exposing the default
  `ai_data/research/tasks` directory and read/write helpers (the routers hold
  no storage or state-machine logic).
- `backend/routers/research.py` — read/write API endpoints.
- `backend/routers/research_pages.py` — workflow UI routes + CVE-detail task
  panel wiring; dependency-free bounded urlencoded form parsing (python-multipart
  is not installed).
- `web/templates/base.html` — "Research Tasks" sidebar link.
- `web/templates/research_tasks.html` — **new** task list.
- `web/templates/research_task_detail.html` — **new** task detail + transition form.
- `web/templates/research_queue.html` — per-item `Start Research` / `Open task`.
- `web/templates/research_detail.html` — Research Tasks panel + start controls.
- `tests/test_research_workflow.py` — **new**, 32 tests.

No existing field, id, or intelligence projection changed.

## 3. Persistence design

- Local JSON only, one file per task under `ai_data/research/tasks/<task_id>.json`
  (the same local data root as the rest of the research track). **No Mongo.**
- **Deterministic id**: `task_id = "rt-" + sha256("r20-1\n<cve>\n<program>\n<queue_id>")[:16]`
  — no randomness, no timestamps in identity.
- **Atomic**: write to a temp file in the same directory, `flush`+`fsync`, then
  `os.replace`; a crash never leaves a half-written task and no `.tmp` remains.
- **Idempotent create**: the same CVE/program/queue_id returns the existing
  task (`created=False`) and never duplicates or overwrites.
- **Corruption-resistant**: a malformed task file is skipped by `list` and
  raises a clean error on `get`; it never breaks the workflow.
- **Bounded**: title 200, notes 4000, blocker 500, result 2000 chars;
  references ≤ 20 entries ≤ 500 chars; audit history ≤ 50 entries.

## 4. State machine

```
TODO --------> IN_PROGRESS
IN_PROGRESS --> BLOCKED   (requires a non-empty blocker)
IN_PROGRESS --> DONE      (requires a non-empty result_summary)
BLOCKED ------> IN_PROGRESS
DONE          (terminal; no outgoing transition)
```

Only these directed transitions are accepted; any other change is rejected.
`status == current` is allowed as a plain field update (no transition). Gates
are checked against the resulting state, so a status change can never bypass the
required blocker/result fields. There is no VERIFIED / VULNERABLE / EXPLOITED
state.

## 5. API (key-gated, read/write)

- `GET /api/research/tasks?limit&offset&status&cve` — bounded list (limit ≤ 100),
  deterministic `task_id` ascending.
- `GET /api/research/tasks/{task_id}` — one task (400 malformed / 404 missing).
- `POST /api/research/tasks` — create; returns `{created, task}`; 201.
- `PATCH /api/research/tasks/{task_id}` — update with required
  `expected_version`; 400 validation/transition, 409 stale, 404 missing.

All endpoints are behind `verify_api_key` + the global `APIKeyMiddleware`.
Inputs are strictly validated (`CVE-…`, `program`, `rq-…` queue id, `rt-…` task
id); no arbitrary paths are built. Responses contain only task fields — no
secrets, no request payloads.

## 6. UI

- `/ui/research/tasks` — list with status filter, pagination, empty state, and a
  persistent `RESEARCH WORKFLOW — NOT VERIFIED` banner.
- `/ui/research/tasks/{task_id}` — task detail: status, notes, blocker, result,
  references, bounded audit history, and a transition form (allowed next states
  only + pre-filled fields + hidden `expected_version`).
- `/ui/research/queue` — each item has `Start Research` (POST) or `Open task`
  when a task already exists.
- `/ui/research/<cve>` — a Research Tasks panel listing tasks for the CVE plus
  `Start Research` controls for queue candidates without a task.

Forms are plain server-rendered POSTs (Jinja + redirect); no new frontend
framework. DONE is presented as "research completed", never "vulnerability
confirmed"; BLOCKED shows the blocker.

## 7. Concurrency model

Optimistic concurrency (compare-and-swap):
- every task carries a monotonic `version`, starting at 1;
- `PATCH` requires the caller's `expected_version`;
- the mutation runs under an exclusive `fcntl.flock` on
  `ai_data/research/tasks/.tasks.lock`, so read-check-write is serialized;
- a stale `expected_version` raises `StaleTaskError` → HTTP 409 (UI re-renders
  with an error panel). A newer state is never silently overwritten.

## 8. Audit model

Every mutation (create + each update) appends a `ResearchTaskAuditEntry`
`{at, previous_status, new_status, version}`. History is bounded to the most
recent 50 entries and stores no request bodies or arbitrary payloads.
`completed_at` is set on the transition into DONE.

Example (from a real run): `TODO -> IN_PROGRESS (v2) -> IN_PROGRESS (v3) ->
DONE (v4)`.

## 9. Tests

- New focused suite `tests/test_research_workflow.py`: **32 tests, OK**,
  covering create, deterministic id, duplicate-create idempotency, every valid
  transition, invalid transitions, DONE/BLOCKED gates, bounded notes/references,
  API auth, API validation (422/400), pagination (≤ 100), HTML escaping, stale
  update (409), audit history, atomic persistence (no `.tmp`, valid JSON),
  true concurrent create/update, corruption-resistant listing, and source-level
  no-network/no-subprocess/no-Mongo/no-LLM scans.
- Regression: `ai.test_research_queue` (R18) and
  `tests.test_research_intelligence_ui` (R19) plus research API and the AI
  R12–R18 suites — **310 tests OK**; mandatory XSS/LLM + KB suites —
  **115 tests OK**. `py_compile` clean; `git diff --check` clean.

## 10. Security review

- Local JSON persistence only; no Mongo, no network, no subprocess, no LLM, no
  Nuclei, no browser, no target interaction, no execution, no alerts, no
  findings.
- A source-level test asserts `ai/knowledge/task_store.py` and
  `backend/research_tasks.py` import no network/db/LLM modules and reference no
  Mongo/subprocess/requests/socket/`ai.llm`.
- Strict input validation + regex-confined ids prevent path traversal; the
  store only ever writes `<root>/<rt-…>.json` under the configured directory.
- Jinja autoescaping remains on; a hostile title/notes test asserts escaping.
- API is key-gated and returns only bounded task fields.

## 11. Limitations

- Timestamps/staleness: `updated_at`/`completed_at` are workflow metadata only
  and never influence queue intelligence (which stays deterministic).
- The store uses one file per task (no index); listing scans a bounded
  directory (fine at the expected scale).
- python-multipart is not installed, so the workflow forms are parsed by a
  small built-in bounded urlencoded parser instead of FastAPI `Form`.
- Cross-process concurrency relies on POSIX `flock`; on non-POSIX platforms the
  version check still rejects stale writes but is not lock-serialized.
- The store is local data under `ai_data/research/tasks/`; it is not the
  production database and is intentionally not backed up by the app.

## 12. Explicit confirmation

- **No network.**
- **No LLM.**
- **No Nuclei.**
- **No active validation.**
- **No production Mongo.**
- **No production mutation.**
- **No alerts.**
- **No Git operations** (no add/commit/push).

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R20
- Role: Research Workflow
