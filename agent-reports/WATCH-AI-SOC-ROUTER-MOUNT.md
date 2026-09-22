# HOTFIX — Mount the promoted AI SOC router (production integration)

## Status: COMPLETE — READY FOR PROMOTION

## Objective

SOC-1..SOC-5 (AI SOC UI) was promoted to main (`94e2383`) with
`backend/routers/soc.py` complete and tested but **inert**: the production
entrypoint `api.py` never registered it, so the eight GET-only `/ui/soc/*`
routes were unreachable. This hotfix completes the production integration
through the normal agent workflow — no redesign, no new surface.

## Change to `api.py` (2 lines, nothing else)

```python
 from backend.routers import research_pages
+from backend.routers import soc as soc_router
 from config import config
```

```python
 app.include_router(product_api_router.router)
+app.include_router(soc_router.router)
```

Existing import style reused (`from backend.routers import X as Y_router`
+ `app.include_router(Y_router.router)`), appended last so no existing
route can be shadowed. No other file was modified; the SOC router and the
SOC adapters are untouched.

## Routes mounted (8, GET-only — the promoted surface)

`/ui/soc/` · `/ui/soc/agents` · `/ui/soc/agents/{slug}` · `/ui/soc/cases` ·
`/ui/soc/cases/{case_id}` · `/ui/soc/activity` · `/ui/soc/handoff` ·
`/ui/soc/handoff/{job_id}`

SOC-1..SOC-5 shipped a UI-only surface: there is **no** `/api/soc` JSON
endpoint, and the regression test pins that none was invented by this mount
(`/ui/soc/*` is the whole surface).

## Authentication verification (mounted app, real middleware)

| Probe | Result |
| --- | --- |
| `GET /ui/soc/` (no key) | 401 |
| `GET /ui/soc/` (invalid key) | 401 |
| `GET /ui/soc/` (`X-API-Key`) | 200 |
| `GET /ui/soc/` (`?api_key=`) | 200 |
| all 8 SOC routes, anonymous + invalid key | 401 every time |
| unknown path (`/ui/soc/definitely-not-a-route`, no key) | 401 (gate runs before routing) |
| `api_key_qs` propagation on SOC links | present |
| `app.user_middleware` | `["APIKeyMiddleware"]` only |
| `EXEMPT_PATHS` | unchanged `{/docs, /redoc, /openapi.json}` |
| `/static` (present asset / missing asset, no key) | 200 / 404 — still unauthenticated, unchanged |
| `/logs/tasks` mount | unchanged |
| AEC routes on the mounted app | none (AEC stays inert; boundary untouched) |
| pre-existing routes (14 pinned, incl. pre-existing POSTs) | all present, methods unchanged |
| new mutation endpoints | none (SOC remains GET-only) |

## Tests

- **NEW (RED first):** `tests/test_soc_router_mounting.py` — 28 tests.
  RED observed before the fix: **11 failures + 1 error** (helper bug) with
  `/ui/soc/` returning 404 through the production app; GREEN after the
  mount: **28 tests OK**. Verified against the *committed* `api.py` blob
  (28 OK) as well as the working tree.
- SOC suite (`tests/test_soc_ui_*.py`): **61 tests OK**.
- Full AEC regression: **2149 tests OK** (baseline unchanged).
- Read-only guard (`scripts/check_aec_readonly.py`): **READ-ONLY VERIFIED**
  — 116 pinned files, no drift, no read-only path changed.
- Mounted-app smoke test (`api.py` + real `APIKeyMiddleware`, 44 probes):
  **PASS** — SOC pages 200 authorised / 401 anonymous, unknown SOC ids 404,
  pre-existing routes 200/401 as before, `/static` + docs exemptions intact.
- Related existing suites: `test_page_render` 7 OK, `test_command_center`
  13 OK, `test_command_center_operations` 15 OK,
  `test_command_center_intelligence` 16 OK, `test_attack_surface_api` 13 OK,
  `test_ui_redesign` 19 OK, `test_aec_readonly_guard` 18 OK,
  `test_delivery_policy` 35 OK, `test_delivery_guard` 47 OK.
- Pre-existing, environment-dependent (not caused by this change, proven by
  running each module against the unmounted baseline): `test_dashboard_navigation`
  21 run / 4 failures, `test_research_activity_api` 14 run / 1 failure — both
  need persisted research fixtures that this workspace has no data for;
  identical results with and without the SOC mount.

## Delivery gates

`delivery/check.sh` (BRANCH, COMMIT, TESTS, PATH_GUARD, REPORT,
PRODUCTION_UNTOUCHED) and `delivery/diff_guard.py` results are recorded in
`agent-reports/delivery/` (runtime artifacts, untracked).

## Production: untouched, with one hazard to know about

`/opt/watch` was not written to by this task (no commit, no merge, no file
change). The recorded baseline was refreshed with the sanctioned
`delivery/report.sh` after verifying the production delta since the previous
baseline (`9ebf57b..94e2383`) is exactly the operator's merge of the
already-approved SOC promotion — no third-party writes.

**Hazard for the promotion step:** production `/opt/watch` currently carries
an *uncommitted* operator edit to `api.py` that mounts the AEC router by
hand (`from backend.routers import aec` + `app.include_router(aec.router)`).
This hotfix also changes `api.py`, so the merge into production will contend
with that dirty file. The operator must decide how to carry the manual AEC
mount across (commit it, or re-apply it) — production must not silently lose
its AEC routes. The committed tree deliberately still does not mount AEC
(AEC mounting remains an operator decision, and this task must not touch it);
the regression test pins that.

**Second hazard (workspace hygiene):** the agent worktree also carries an
unrelated, uncommitted in-flight epic (research-agents / investigation-engine
routers, new modules and tests, plus matching `api.py` hunks that import
modules which are not committed). Those hunks were deliberately **not**
promoted — committing them would import non-existent modules in production.
Only the two SOC lines were staged to the index; the rest stays uncommitted
in the worktree, exactly as the delivery layer expects for unrelated work.

## Files changed

- `api.py` (+2 lines: SOC router import + include)
- `tests/test_soc_router_mounting.py` (new, 28 tests)

## Commit

`fix(soc): mount ai soc router in api.py` on `agent/daily-development`

## READY FOR PROMOTION: YES
