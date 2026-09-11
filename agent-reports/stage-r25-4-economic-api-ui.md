# Stage R25.4 — Money Queue API + Minimal Research UI

## Status
**IMPLEMENTED (read-only presentation only).** The Money Score is now visible
where the researcher already works: a key-gated API and the existing Research
Leads pages. No R25.2 formulas changed, no R15–R24 logic changed, no
persistence, no findings, no active paths.

## 1. API routes

In `backend/routers/research.py` (declared before generic
`/api/research/{cve}` so `economics` is never captured as a CVE id):

- `GET /api/research/economics?limit=&offset=&cve=&program=` →
  `research_economics.list_research_economics(...)` directly (no scoring
  logic in the router). `limit` clamps to `[1, 100]`; malformed CVE → 400
  via the existing `_bad` mapping.
- `GET /api/research/economics/{lead_id}` →
  `research_economics.get_research_economic_value(lead_id)` directly.
  Unknown/malformed id → 404 `"economic projection not found"`.

Both routes reuse `dependencies=_AUTH` (`verify_api_key`, HTTP 401 without
key), return the R25.3 projection verbatim (`research_only: true`,
`rule_version: "r25-1"`), never mention payouts, never assert
vulnerability confirmation, never trigger execution, never contact
external sources.

## 2. UI changes

No new page, no redesign, no framework, no charts/polling/websocket/chat.
All server-rendered read-only Jinja, existing patterns only:

- `backend/routers/research_pages.py::ui_research_leads` — attaches
  `{money_score, money_priority}` per lead from
  `research_economics.build_economics()` inside try/except (projection
  failure degrades to `None`, never a dashboard failure), then sorts
  money DESC / CVE ASC / program ASC with projection-less leads last.
- `web/templates/research_leads.html` — one compact `Money` column
  (`53 · P3` badge with full band in `title`; `—` when absent), empty
  state extended with `MONEY QUEUE: no research candidates`, colspan 8→9.
- `backend/routers/research_pages.py::ui_research_lead_detail` — passes
  `econ` (fail-soft `None`) into the existing template context.
- `web/templates/research_lead_detail.html` — one compact
  `ECONOMIC RESEARCH` panel: Money Score, Priority (`P3 — MEDIUM`),
  Confidence, Effort (`1–2 h` + score), Asset Match, Recommended action,
  Subscores (`Value 59 / Confidence 71 / Effort 47 / Risk 85`),
  Why valuable, Main blockers; muted `No economic projection` fallback.
- `web/static/css/custom.css` — two additive badge variants only:
  `.badge-sm.prio-p1` (accent-orange), `.badge-sm.prio-p2`
  (accent-blue); P3–P5 reuse the default badge (deliberately no
  red/green verdict colors — this is attention, not severity).

## 3. Real corpus verification

API and UI both show, for `dell` and `indeed`:

```
CVE-2026-1557 → dell / indeed
Money Score = 53 | Priority = P3_MEDIUM | Confidence = HIGH
Effort = 1–2 h | Action = VERIFY_ASSET_MATCH_FIRST
```

Verified via TestClient against the live app (list 200/total 2,
detail 200/53, unknown id 404) and via rendered HTML (Money cells
`53 · P3` ×2 in money order dell→indeed; detail block contains all
required rows). No artifact was persisted or altered.

## 4. Test counts

`tests/test_research_economics_api.py` — **21 tests, all OK** (~2 s):

- Auth (1): 401 without key on both routes (or 200/404 when keyless).
- List (8): shape + `r25-1`/`research_only` + limit cap, exact corpus
  values, money/CVE/program ordering, cve/program/combined filters,
  limit/offset, limit bounding, malformed CVE → 400, empty filter,
  no-payout/no-verdict vocabulary scan.
- Detail (3): full 17-key shape, unknown id → 404, malformed id → 404.
- UI (6): Money column + ordering, `prio-p3` indicator, detail economic
  block (all required rows), missing-projection fallback (mocked
  projection failure still renders 200), empty state
  (`MONEY QUEUE: no research candidates`), research-only wording scoped
  to the R25.4 blocks (page banners/disclaimers keep their sanctioned
  `NOT VERIFIED` / `PRODUCTION FINDING` phrasing).
- Safety (2): new router handlers contain no execution tokens and call
  the projection layer directly (no `assess_economic_value` in routing).

## 5. Regression results

- R25.2 engine `tests.test_research_economics`: **91 OK**.
- R25.3 projection `tests.test_research_economics_projection`: **33 OK**.
- R25.4 new `tests.test_research_economics_api`: **21 OK**.
- `tests.test_research_api`: **29 OK**.
- R21/R22 pure-logic classes (leads + execution, excl. Mongo-bound
  API/UI classes): **54 OK**.
- Existing `leads` / `research plan` CLI output verified unchanged.
- `git diff --check` — clean.

Pre-existing limitation, unchanged: the Mongo-dependent API/UI classes
(`TestLeadsApi/Ui`, `TestPlansApi/Ui`) stall in this offline environment
identically with and without R25.4 changes (proven pre-existing in R25.3
via `git stash` A/B on pristine `HEAD 71fef7c`; single tests pass in
isolation). The one environmental trap found while testing: `GET /`
(dashboard root) hangs on Mongo — new UI tests render only the research
leads pages, which return 200 in ~ms.

## 6. Safety verification

- Endpoints are GET-only, key-gated, bounded (`clamp_limit`), and return
  the projection verbatim — `research_only: true`, `rule_version:
  "r25-1"` preserved end-to-end (API JSON and rendered HTML).
- No payout prediction, no vulnerability confirmation, no execution
  trigger, no external contact in any new path (router handlers import
  only the projection module; templates escape all values by default).
- Projection failures degrade (missing badge / fallback line), never
  blank a page; verified by mocked-failure tests for both list context
  and detail context.
- No writes: API/UI layers call only the read-only R25.3 projection;
  no new collections, workers, timers, or background jobs.
- No LLM calls added; no R25.2/R15–R24 code touched
  (`git diff` on `ai/knowledge/economics.py`: none).

## 7. Pre-existing failures

None introduced. The only known failures in the wider suite are the
pre-existing Mongo/offline-environment stalls documented in §5, which
predate R25 and are unaffected by it.

## 8. Implementation discrepancies

- UI priority renders `P3 — MEDIUM` (humanized) while API/CLI keep the
  raw `P3_MEDIUM` enum — intentional, presentation-only.
- `skipped` entries from the R25.3 projection are not surfaced in the
  leads list (only `items` render); they remain available via the
  `skipped` key on the API list response.
- Detail lookup accepts `rl-…` ids only (consistent with R21); a
  `plan_id → projection` alias was deferred to a later stage if needed.
- No Git operations performed (no add/commit/push). Modified files are
  additive only: `backend/routers/research.py` (+38),
  `backend/routers/research_pages.py` (+40),
  `web/templates/research_lead_detail.html` (+32),
  `web/templates/research_leads.html` (+6),
  `web/static/css/custom.css` (+4); new: `tests/test_research_economics_api.py`.

## Agent / Model
- Model: Miuz Spark
- Stage: R25.4
- Role: Money Queue API + Minimal Research UI
