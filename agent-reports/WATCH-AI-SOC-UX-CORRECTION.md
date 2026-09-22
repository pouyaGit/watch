# WATCH — AI SOC UX correction (SOC-only sidebar + truthful agent status)

**Task** — browser verification of the live AI SOC showed two problems: the
legacy Research navigation was still in the primary sidebar, and the Agents
page showed `PLANNED` / `ready` statuses that did not describe the real
runtime. Fixed as one coherent change.

**Production impact** — production was only inspected (read-only). No file in
`/opt/watch` was modified; nothing changes live until the promotion workflow
merges this branch and the service is reloaded.

---

## Problem 1 — why the Research links were still visible

The previous fix did **not** remove the legacy navigation: it wrapped the whole
legacy block (Overview / Discovery / Operations / Changes / **Research** /
System) in a collapsed `<details class="nav-legacy">` disclosure *inside*
`<nav class="sidebar-nav">`. So the Research destinations were still rendered
in the primary sidebar — one click (and one visible "Legacy / Engineering"
section header) away. The links, their `nav-group` labels and the disclosure
header were all still in the product sidebar's DOM.

### Exact navigation change

`web/templates/base.html` now renders only:

```
AI SOC   → Overview, Agents, Missions / Activity, Cases, Evidence,
           Knowledge, Handoff
System   → Runs, Tasks, API docs
```

* the entire legacy block (Command Center, Attack Surface, Dashboard,
  Programs, Discovery, Operations, Changes, **all ten Research items**, and the
  `Legacy / Engineering` disclosure header) is gone from the sidebar — no
  dropdown, no disclosure, no second navigation system, no page-specific CSS
  hiding; the fix is in the one shared layout;
* the three System links are now literal paths with `api_key_qs` propagation
  (`/ui/runs`, `/ui/tasks`, `/docs`) instead of `{{ runs_url }}` /
  `{{ tasks_url }}` / `{{ docs_url }}`, which rendered `href=""` on every page
  whose handler does not pass those variables (AEC and SOC pages);
* `web/static/css/soc/soc.css` drops the now-unused `.nav-legacy` rules;
* **no route, template or page was deleted** — every legacy destination stays
  directly reachable at its original URL (proven by route-table + HTTP 200
  checks in the regression suite). Engineering access is by direct URL, outside
  the product sidebar.

---

## Problem 2 — what `PLANNED` actually means, and the real state model

### Inspection findings (code/runtime/data, not guesses)

* `PLANNED` comes from the **agent identity planners** (`ai/knowledge/*_agent_*identity.py`,
  wired through `ai.knowledge.specialist_registry`): it is an *identity*
  lifecycle label. `idor_bola_agent_identity.py` states plainly that the
  identity lifecycle is restricted to `CREATED`/`PLANNED`.
* `ai/knowledge/security_agent_lifecycle.py` (R38.4) documents the conceptual
  states (`CREATED, PLANNED, ANALYZING, WAITING_EVIDENCE, COMPLETED, FAILED`)
  and states: *"Framework/model only: states are conceptual labels; there is no
  runtime, execution, scheduling, persistence, queue, worker or autonomous
  loop."*
* The only component that can report queue/job counters for these agents is
  `backend.research_agents.service.agents_payload()` → per-agent `queue`,
  `job_count`, `active_jobs`, `available` (`available = agent.status == "ready"`).
  **That module is not part of the deployed tree** (`ModuleNotFoundError` in
  production), so in production no runtime reports anything for any agent.
* The XSS identity planner declares **no** `lifecycle_state` at all (it is
  `None`), and the previous adapter did `status = declared or "ready"` — so the
  single `ready` row on the live page was a **substituted default**, not a
  runtime fact. Likewise `available = bool(stats.get("available", True))`
  defaulted to *available* with no runtime, and the Queue / Active jobs / Jobs
  columns rendered `0` although nothing tracks them.

### Truthful lifecycle model now used

Status is **derived from what the runtime reports**, never defaulted:

| Status | Meaning (grounded condition) |
| --- | --- |
| `PLANNED` | a definition exists but no agent runtime reports this agent → it cannot be executing or accepting work (production today, all agents) |
| `READY` | the agent runtime is deployed and reports the agent able to accept work, nothing executing (`available`, `active_jobs == 0`) |
| `ACTIVE` | the agent runtime reports jobs executing right now (`active_jobs > 0`) |

* `IDLE` is deliberately **not** used: the runtime exposes only definition
  readiness, queue depth and job counts, which cannot distinguish "idle with no
  work" from "ready for work" — showing IDLE would be a guess. Documented in
  `backend/soc/agents.py`.
* A third case exists in code: runtime deployed but the agent not marked ready
  → still `PLANNED` ("registered but not marked ready").
* Queue / active / total are `None` (rendered **not tracked**) unless a runtime
  actually reports them; the index page states
  "No agent runtime is deployed in this environment…".
* The registry's own declared value is shown separately as **Declared
  lifecycle** (verbatim, or `NOT DECLARED` for XSS) so nothing is hidden and
  nothing is invented.

### Real vs empty data on the agent pages (deployed tree, verified)

| Block | Source | Production state |
| --- | --- | --- |
| Identity, specialization, declared capabilities/techniques/areas | `ai.knowledge.specialist_registry` (8 definitions: xss, ssrf, sqli, idor, jwt, oauth, recon, cve_research) | **real declarations** |
| Runtime queue/active/total, "accepting work" | `backend.research_agents.service` | **absent → not tracked, status PLANNED** |
| Knowledge-base sources | `backend.research_data` | **real: 30 documents, platform-wide — relabelled "not attributed to this agent"** (they carry no agent field) |
| Research-loop records (CVE) | `ai_data/research/agent/*.loop.json` | **real: 2 loop records (CVE-2026-1557), platform-wide — relabelled** |
| Findings/research recorded *against the agent* | `backend.investigation_engine.memory` | **absent → explicit empty state** ("No research is recorded against this agent", plus why) |
| Target cases | AEC case explorer (18 cases: idor 8, xss 4, ssrf 3, authz 1, file_upload 2) | **real, matched by vulnerability category** and explicitly labelled "association by category — it does not mean this agent executed the case"; sqli/jwt/oauth/recon/cve_research show the empty state |

The detail page gained **Capability** ("Not executable in this deployment…"
when no runtime exists, plus "declared capabilities are planned, not
implemented"), **Runtime**, per-block provenance labels, and a
**"Where this page's data comes from"** panel. No job, activity, finding,
article, case or runtime state was created anywhere.

---

## Files changed

| File | Change |
| --- | --- |
| `web/templates/base.html` | sidebar = AI SOC + System only; legacy block removed; System links literal + keyed |
| `web/templates/soc/agents.html` | truthful status badge + meaning, untracked counters, status legend |
| `web/templates/soc/agent_detail.html` | identity/runtime/capability/knowledge/history/cases/sources blocks with explicit empty states |
| `backend/soc/agents.py` | derived status model, `_runtime_report()`, `status_meaning`, `declared_lifecycle`, `None` counters, history scopes + memory availability, capability + sources blocks |
| `web/static/css/soc/soc.css` | drop unused `.nav-legacy` rules |
| `tests/test_soc_ux_correction.py` | **new** regression suite (25 tests) |
| `tests/test_soc_ui_stabilization.py` | nav assertions inverted to the SOC-only contract |
| `tests/test_soc_ui_navigation.py` | legacy vars/label asserted *absent*; sidebar groups pinned to `["AI SOC", "System"]` |
| `tests/test_ui_redesign.py` | sidebar contract asserted inside the sidebar block |
| `tests/test_attack_surface_api.py`, `tests/test_command_center.py` | legacy items asserted out of the sidebar (routes/anchors still asserted) |
| `tests/test_research_navigation.py`, `tests/test_dashboard_navigation.py` | sidebar contract asserted against the shipped template (these modules drive the *deployed* app, so the contract holds before and after promotion); route/content assertions kept |
| `tests/test_aec_ui_apikey.py` | api_key propagation now asserted on the sidebar links that exist (SOC links) |
| `agent-reports/WATCH-AI-SOC-UX-CORRECTION.md` | this report |

Untouched: `backend/routers/soc.py`, AEC, `ai/knowledge`, auth middleware,
database schema, runtime/evidence/authorization systems, `api.py`, every legacy
route and template.

## Tests / results

| Suite | Result |
| --- | --- |
| `tests/test_soc_ux_correction.py` (new) | **25 OK** — written RED first (every sidebar + status assertion failed before the fix) |
| full SOC batch (ux + stabilization + mounting + `test_soc_ui_*`) | **139 OK** |
| AEC regression `discover -p "test_aec_*.py"` | **2149 OK** (baseline unchanged) |
| updated navigation/UI batch (`soc_ui_navigation`, `ui_redesign`, `attack_surface`, `command_center`, `soc_ui_stabilization`) | **107 OK** |
| `test_research_navigation` (isolated) | **14 OK** |
| `test_page_render` + `test_aec_ui_apikey` | **22 OK** |
| delivery + read-only guards | **100 OK**, `READ-ONLY VERIFIED` (116 pinned, no drift) |
| mounted-app smoke, deployed module set, committed entrypoint | **PASS (68/68)** — SOC pages 200, legacy pages 200, 401 anonymous/bad key, `/static` + `/docs` exempt, sidebar SOC-only, all statuses `PLANNED` with untracked counters |
| `tests/test_dashboard_navigation.py` | my updated test **OK alone (1 test, 2.5 s)**; the module as a whole still hangs in this environment on two *pre-existing* data-dependent route tests (`test_every_research_destination_route_resolves`, `test_specific_routes_not_swallowed_by_generic_cve`) that read production data — untouched by this change and identical on the base revision, because those modules drive the deployed app, not this worktree |

Caveats stated honestly: the two hanging tests above are environmental
(the same module has hung/timed out in every previous run here); batch runs of
`test_research_navigation` fail only because earlier test modules shadow `backend`
for it (it pins `/opt/watch` on `sys.path`) — isolated run is green.

## Delivery

* Commit: `fix(soc): drop legacy research nav and make agent status truthful`
* Push: `push_safe.sh origin agent/daily-development` (auth READY)
* Promotion request: created, awaiting exactly one APPROVE
* Production: `main` = `246df67`, `api.py` clean, **27 dirty entries untouched**
