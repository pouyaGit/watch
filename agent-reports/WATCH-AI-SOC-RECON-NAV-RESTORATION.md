# WATCH — Recon Ops navigation restoration + SOC Overview metric/runtime truth

**Task** — browser verification of the live AI SOC navigation redesign showed
that core Watch Recon Operations navigation had been removed from the primary
sidebar (AI SOC is an additional intelligence layer, not a replacement), and
that the SOC Overview dashboard disagreed with the Agents page
(`Agents: 0` vs 8 registered) and showed an unexplained `Status: UNKNOWN`.

**Production impact** — production was only inspected (read-only, one
read-only run of the existing activity collector to verify what runtime state
is genuinely observable).  Nothing changes live until the promotion workflow
merges this branch and the service is reloaded.

---

## 1. What Recon navigation was missing

The previous correction replaced the whole legacy block with an SOC-only
sidebar — the *entire* core recon surface disappeared from primary
navigation, not just the old research links:

Programs · Subdomains · Live · HTTP · Fresh HTTP · Wordlists · URLs ·
Endpoints · Parameter Discovery · Recent Changes — all gone (the sidebar
rendered only `AI SOC` + `System`).  This was over-correction: only the
OLD research navigation was supposed to be removed.

## 2. What was restored (primary navigation now)

`web/templates/base.html` sidebar, in product-architecture order:

```
Recon Ops  Programs, Subdomains, Live, HTTP, Fresh HTTP, Wordlists,
           URLs, Endpoints, Parameter Discovery, Recent Changes
AI SOC     Overview, Agents, Missions / Activity, Cases, Evidence,
           Knowledge, Handoff
System     Runs, Tasks, API docs
```

Group labels render uppercase via the existing `.nav-group` CSS
(`text-transform: uppercase`), so the browser shows **RECON OPS / AI SOC /
SYSTEM** exactly as specified.  No Research group, no Legacy/Engineering
section, no dropdown, no page-specific hack; the fix is in the one shared
layout.  All links are literal paths with `api_key_qs` propagation (same
pattern as the SOC links), so no handler can render an empty `href`.

**Route mapping — existing routes only, two disclosures:**

| Label | Route | Note |
| --- | --- | --- |
| Programs | `/ui/programs` | existing |
| Subdomains | `/ui/domains` | **the product's own mapping** — the dashboard's "Subdomains" stat card already links `domains_url`; the page is the live-host table (its search box says "Search subdomain…") |
| Live | `/ui/domains` | the dashboard's "Live" stat card links the same `domains_url`; page title is "Live Domains" |
| HTTP | `/ui/http` | existing |
| Fresh HTTP | `/ui/http/fresh` | existing |
| Wordlists | `/ui/wordlists` | **no Wordlists page ever existed** (repo-wide and git-history search empty); only per-program downloads via the existing `/api/wordlist/{program}` API. A minimal read-only index page was added that only *lists* those existing artifacts — no new data source, no generation, GET-only |
| URLs | `/ui/urls` | existing |
| Endpoints | `/ui/endpoints` | existing |
| Parameter Discovery | `/ui/parameters` | existing |
| Recent Changes | `/ui/changes` | existing |

Subdomains and Live intentionally share `/ui/domains` — exactly what the
dashboard's own two stat cards do; there is no separate top-level Subdomains
or Lives page (never was, in git history).  The Fresh HTTP handler gained
`active="http-fresh"` so its own row highlights on `/ui/http/fresh`.

## 3. What old Research navigation stayed removed

Research Cases, Research / CVEs, Research Queue, Research Tasks, Research
Leads, Research Plans, Research Agent, XSS, old Knowledge Base, old Reports —
still absent from the primary sidebar, asserted per page.  Command Center,
Dashboard and Attack Surface also stay out (not part of the two surfaces).
Every one of their routes remains mounted and directly reachable (HTTP 200
proven).

## 4. Why Overview showed `Agents = 0`

`backend/soc/overview.py` counted agents with
`backend.research_agents.registry.build_default_registry().list_agents()` —
a module that is **not part of the deployed tree** (`ModuleNotFoundError`),
swallowed by `except Exception: pass` → `0`.  `/ui/soc/agents` uses a
different source (`backend.soc.agents.agents_index()`, layered over
`ai.knowledge.specialist_registry` → 8 declared specialists).  Two different
sources: two different numbers.  (In the worktree, where the unpromoted
module exists, the same bug produced `5` — still disagreeing with the Agents
page.)

## 5. How the Agents metric is now derived

`overview_payload()` now calls **`backend.soc.agents.agents_index()` — the
exact projection the Agents page renders** — so the two surfaces can never
disagree.  Nothing is hardcoded; a test proves derivation by patching the
projection to `count=3` with ACTIVE/READY/PLANNED statuses and asserting the
Overview reports `3` and the matching split.

The card is truthfully labelled and split:

- **Agents registered** = `index["count"]` (the big number — 8 in production)
- sub-line: **`N ready · N active · N planned`** from the same payload's
  statuses, so "registered" can never be misread as "operational"

## 6. Runtime status semantics

**Verified against real data, not assumed.**  `backend/soc/activity.py`
`_runtime_status()` called the *pure* R83 engine with **no arguments**
(`run_records=None, case_records=None, lock_state=unavailable`), which by
construction returns `UNKNOWN / runtime_state_not_observable` — "nobody
looked" masquerading as "not observable".  Meanwhile the existing read-only
collector `backend/research_activity.collect_activity()` (already used by
the Command Center and the research-activity status endpoint; no Mongo, no
network, no writes) reports, when run read-only against production data:

- **50 scheduler run records**, **1 research case record**, lock probe
  **free** → `status: IDLE`, `status_basis: latest_run_status`, rule `r83-1`

So UNKNOWN was **not** the correct representation.  `_runtime_status()` now
calls that same collector; Overview and Activity share one function, so both
pages (and the Command Center/API) show identical runtime facts.  Semantics
now:

- status comes from the closed R83 vocabulary (`IDLE/RUNNING/…/UNKNOWN`)
  derived from persisted facts — **nothing fabricated**: no ACTIVE unless
  the lock is held, no IDLE unless the engine derives it from real records
- `UNKNOWN` appears only when the collector itself is unavailable, and the
  Overview now explains it verbatim in the product's own words: *"Runtime
  state could not be observed — UNKNOWN is not failure."* (a test forces
  the collector to fail and asserts that explanation renders)
- the section states its source (run records / case records / lock probe)

The truthful agent model from the previous task is untouched: PLANNED/READY/
ACTIVE derivation, provenance panels, empty states, no fabricated activity.

## 7. Files changed

| File | Change |
| --- | --- |
| `web/templates/base.html` | `Recon Ops` group (10 links) restored ahead of AI SOC; product's original icons reused |
| `web/templates/wordlists.html` | **new** read-only wordlists index template |
| `backend/routers/pages.py` | **new** `GET /ui/wordlists` (lists existing per-program wordlist API artifacts) |
| `backend/routers/programs.py` | Fresh HTTP handler marks `active="http-fresh"` |
| `backend/soc/overview.py` | agents from `agents_index()` + `agent_counts` split |
| `backend/soc/activity.py` | `_runtime_status()` → `research_activity.collect_activity()` (shared real source) |
| `web/templates/soc/home.html` | "Agents registered" + ready/active/planned split; UNKNOWN explained; runtime source stated |
| `tests/test_recon_soc_navigation.py` | **new** regression suite (26 tests: composition, functionality, Overview metric, runtime semantics) |
| `tests/test_soc_ux_correction.py` | sidebar contract updated to the two-surface architecture (recon labels allowed *and* required; research labels still forbidden) |
| `tests/test_soc_ui_navigation.py` | group pin + recon hrefs |
| `tests/test_research_navigation.py` | forbidden-label set narrowed to old research (core recon restored) |
| `tests/test_ui_redesign.py` | sidebar contract: recon presence, research/legacy absence |
| `agent-reports/WATCH-AI-SOC-RECON-NAV-RESTORATION.md` | this report |

Untouched: AEC, auth middleware, database schema, runtime/evidence/
authorization systems, `api.py`, all legacy routes/templates, the truthful
SOC agent model.

## 8. Tests / results

| Suite | Result |
| --- | --- |
| `tests.test_recon_soc_navigation` (new) | **26 OK** — written RED first (19 failures + 1 error: missing recon group/links, missing wordlists route, non-derived metric, non-collector runtime, unexplained UNKNOWN) |
| recon + ux + stabilization + soc_ui_navigation batch | **90 OK** |
| SOC batch (routes, agents, cases, activity, handoff, overview, mounting) | **77 OK** |
| nav/UI batch: research_navigation, attack_surface, command_center, page_render, ui_redesign | **14 + 13 + 13 + 7 + 19 OK** |
| `test_dashboard_navigation` shipped-template test | **1 OK** (module still hangs on two pre-existing data-dependent route tests in this environment — unchanged, they drive the deployed app) |
| AEC regression `discover -p "test_aec_*.py"` | **2149 OK** (baseline unchanged) |
| delivery + read-only guards | **100 OK**, `READ-ONLY VERIFIED` (116 pinned, no drift) |
| mounted smoke, deployed module set, committed entrypoint | **PASS (95/95)** — sidebar groups `Recon Ops/AI SOC/System`, all 10 recon links 200, wordlists links the existing API, overview == agents-page count, status split adds up, Overview/Activity runtime identical |

Caveat stated honestly: batch runs of `test_research_navigation` can fail
from cross-module `backend` shadowing (it pins `/opt/watch` on `sys.path`);
the isolated run is green (14 OK).  Production API key is not in the agent
environment (`[REDACTED]`), so live checks are 401-on-anonymous only.

## 9. Delivery

* Commit: `feat(nav): restore recon ops navigation and align the soc overview with the agent registry` (see `git log`)
* Push: `push_safe.sh origin agent/daily-development` (auth READY)
* Promotion request: created, awaiting exactly one APPROVE — no merge to main
* Production: `main` = `83226af`, `api.py` clean, **27 dirty entries untouched**

## READY TO PUSH: YES

when all of these hold (verified at gate time):

- core Recon navigation restored ✔ (10 links, existing routes, resolved 200)
- AI SOC navigation intact ✔ (7 links unchanged)
- old Research navigation absent ✔ (asserted per page)
- Overview and Agents metrics consistent ✔ (same projection; split labelled)
- no fake data ✔ (derivation tests; collector-backed status; UNKNOWN explained)
- tests pass ✔ (all suites above)
- delivery gates pass ✔ (BRANCH/COMMIT/TESTS/PATH_GUARD/REPORT/PRODUCTION)
- production untouched until approved promotion ✔
