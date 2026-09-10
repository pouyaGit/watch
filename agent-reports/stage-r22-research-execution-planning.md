# Stage R22 — Research Execution Planning

## 1. Objective

Turn the existing deterministic R21 Research Lead into a compact, deterministic
Research Execution Plan answering: *"For this Research Lead, what exactly should
the researcher investigate next, in what order, and what evidence should be
reviewed?"* Research-only: guides ordering and evidence targets without
performing active validation or claiming vulnerability.

## 2. Exact files changed

New:

- `backend/research_execution.py` — deterministic Research Execution Plan
  projection (on-demand over R15–R21 local outputs, no persistence, no network).
- `web/templates/research_plans.html` — R22 plans list page (read-only).
- `web/templates/research_plan_detail.html` — R22 plan detail page.
- `tests/test_research_execution.py` — 45 focused offline tests.

Modified (display/wiring only — no R15–R21 algorithms or R20 state machine changed):

- `ai/research_cli.py` — unified `research` top-level parser: legacy
  `research --cve` and new `research plan [--cve --program --lead --limit --json]`
  share the same `research` command with an optional subparser `plan`
  (previously conflicting duplicate subparser fixed). `run_research_plan()` renders
  compact human output and `--json` deterministic output.
- `backend/routers/research.py` — `GET /api/research/plans` and
  `GET /api/research/plans/{plan_id}` (key-gated, bounded pagination,
  deterministic ordering), declared before the generic `/api/research/{cve}`
  catch-all.
- `backend/routers/research_pages.py` — `/ui/research/plans` +
  `/ui/research/plans/{plan_id}` (auth, read-only, bounded); lead detail CTA
  `Research Execution Plan →`; CVE detail exposes the plan when available;
  `plans_url` in `_ctx`.
- `backend/routers/pages.py` — dashboard builds `plans_summary` (fail-soft) and
  exposes `plans_url`.
- `web/templates/base.html` — Research Plans entry in the Research sidebar
  (between Research Leads and XSS).
- `web/templates/dashboard.html` — compact Research Plans KPI/card (ready/blocked/
  completed, top 3, CTA), without redesign.
- `web/templates/research_lead_detail.html` — Research Execution Plan CTA when a
  plan exists.
- `web/templates/research_detail.html` — Research Execution Plan quick action and
  inline plan panel (steps, evidence targets, unknowns) when a plan exists.

Untouched: all R15–R21 scoring/intelligence/relevance/queue logic, R20 task
state machine, `database/`, `ns/`, `crawl/`, Nuclei/CVE pipelines. No background
workers, no Mongo dependency beyond existing read-only intelligence.

## 3. Data flow

```
R18 list_research_queue()  ── CVE×program candidates (priority class/score,
                              relevance/score, queue_id, blockers, reasons)
R15 cve_intelligence()[exploitability] (auth/priv/ui/poc/complexity, read-only)
R16 priority              (priority class/score, via queue)
R17 relevance             (technology/component/version rows, via cve_intelligence)
R21 ResearchLead          (lead_id, status, recommended_next_step, blockers,
                            priority/relevance levels, task linkage)
R20 task_by_queue()       (task_id/status, reflected in lead status)
           │
           v
ResearchExecutionPlan { plan_id, lead_id, cve_id, program, queue_id, task_id,
  priority_score, relevance_score, status, steps[], evidence_targets[],
  unknowns[], blockers[], recommended_start, rule_version, metadata }
           │
           v
CLI `research plan` │ GET /api/research/plans (+/{plan_id}) │
  /ui/research/plans (+/{plan_id}) │ lead detail CTA │ CVE detail plan panel │
  dashboard Research Plans KPI
```

No persistence: plans are generated on-demand from live R21/R18 state,
idempotent within rule version `r22-1`. A plan exists iff an R18 candidate and
its R21 lead exist — weaker/non-candidate CVEs yield no plan.

## 4. Plan schema

```python
ResearchExecutionPlan {
  plan_id: "r22-" + sha256("r22-1\\n{cve}\\n{program}")[:16]
  lead_id: str              # rl-... from R21
  cve_id: str
  program: str
  queue_id: str
  task_id: str | None
  priority_score: int
  relevance_score: int
  status: RESEARCH_PLAN_READY | RESEARCH_PLAN_BLOCKED | RESEARCH_PLAN_COMPLETED
  steps: [{order, code, title, purpose, source, status}]  # READY/BLOCKED/INFORMATIONAL
  evidence_targets: [{code, description, source, required}]
  unknowns: [str]
  blockers: [str]            # verbatim R18/R21 blockers
  recommended_start: str | None  # most actionable emitted step (PoC-first; see §15)
  rule_version: "r22-1"
  metadata: {priority_level, relevance_level, recommended_next_step, lead_status}
}
```

`plan_id` deterministic from `cve_id + program + rule_version (r22-1)` — no
clock, no random. Bounded: `MAX_PLANS=100` for build; UI caps rendered items;
API `clamp_limit` enforces `limit ∈ [1,100]`.

## 5. Step rules

Deterministic precedence (removed steps preserve relative order):

1. `REVIEW_CVE_SUMMARY` — when `cve_intelligence(cve).available` is true.
2. `REVIEW_EXPLOITABILITY` — when any exploitability field is known (not
   `None`/`"unknown"`/`""`): `authentication_required`, `privilege_required`,
   `user_interaction_required`, `exploit_available`, `public_poc`,
   `active_exploitation`, `exploit_complexity`.
3. `REVIEW_PUBLIC_POC` — only when `public_poc == "true"` (never on `"unknown"`).
4. `REVIEW_REFERENCES` — when `payload.research.references` non-empty.
5. `REVIEW_TECHNOLOGY_MATCH` — when relevance reasons contain `"technology match"`.
6. `REVIEW_COMPONENT_MATCH` — only when relevance reasons contain
   `plugin`/`component`/`product match` (not merely `document.components`).
7. `REVIEW_PARAMETER_MATCH` — when `document.parameters` non-empty.
8. `REVIEW_VERSION` — when `payload.research.affected_versions` non-empty.
9. `REVIEW_ASSET_EVIDENCE` — when `relevance_row.matched_assets` non-empty.
10. `REVIEW_RESEARCH_TASK` — when `lead.task_id` exists.

Only supported steps are emitted; `UNKNOWN` never becomes a positive step.
`REVIEW_PUBLIC_POC` is the canonical example of the UNKNOWN guard.

## 6. Evidence target rules

Deterministic, ordered per `EVIDENCE_ORDER`; only when justified by local data.
Never claims evidence was collected — describes what should be reviewed.

| Code | Source | Fires only when |
|---|---|---|
| `CVE_REFERENCE` | research/reference | CVE intel available |
| `VENDOR_ADVISORY` | research/reference | references contain wordfence/vendor/advisory/bulletin/trac.wordpress.org |
| `PUBLIC_POC` | exploitability/public_poc | `public_poc == "true"` |
| `EXPLOIT_REFERENCE` | exploitability/exploit_available | `exploit_available == "true"` |
| `AFFECTED_COMPONENT` | research/component | `document.components` non-empty |
| `AFFECTED_PARAMETER` | research/parameter | `document.parameters` non-empty |
| `AFFECTED_VERSION` | research/version | affected_versions non-empty |
| `ASSET_TECHNOLOGY` | relevance/technology | relevance reasons contain technology match |
| `ASSET_COMPONENT` | relevance/component | relevance reasons contain plugin/component/product match |
| `ASSET_VERSION` | relevance/version | (reserved — no positive asset-version signal in current corpus) |
| `RESEARCH_TASK_CONTEXT` | research/task | `lead.task_id` exists |

## 7. Unknown handling

Unresolved facts are explicitly preserved, never silently converted to positive
or negative. Produced from:

- Exploitability unknowns where field is strictly `"unknown"`:
  `authentication requirement unknown`, `privilege requirement unknown`,
  `user interaction requirement unknown`, `exploit availability unknown`,
  `public PoC unknown`, `active exploitation unknown`, `exploit complexity unknown`.
- Absent KB signals: `affected component not identified`, `affected parameter unknown`,
  `affected version unknown` when the corresponding field is empty.
- Informational blockers: `affected plugin not observed`, `asset component not
  observed`, `asset version unknown`, `only generic technology match — asset
  specificity unknown`.
- Relevance `unknown_factors` (verbatim, deduplicated, order-preserved).

For the real corpus, component/version unknowns remain explicit while still
providing an actionable plan — no claim that the target is vulnerable.

## 8. Status rules

Allowed statuses (research planning only, never production finding terms):

- `RESEARCH_PLAN_READY`
- `RESEARCH_PLAN_BLOCKED`
- `RESEARCH_PLAN_COMPLETED`

Derivation (from R21 lead status, which itself reflects R20 task state):

- `RESEARCH_COMPLETED` lead → `RESEARCH_PLAN_COMPLETED`
- `RESEARCH_BLOCKED` lead → `RESEARCH_PLAN_BLOCKED`
- otherwise → `RESEARCH_PLAN_READY`

Never uses `VULNERABLE` / `VERIFIED` / `EXPLOITED` / `FINDING` / `CONFIRMED`.

## 9. CLI / API / UI

CLI:

```
python -m ai.research_cli research plan
python -m ai.research_cli research plan --cve CVE-2026-1557 --program dell
python -m ai.research_cli research plan --lead rl-af7ecfba1a86fc83
python -m ai.research_cli research plan --json
python -m ai.research_cli research plan --limit 1 --json
```

Human output is compact per spec:

```
Research Execution Plan
=======================

#1 CVE-2026-1557 -> dell
Plan: r22-38d26f10681e9a0f
Status: RESEARCH_PLAN_READY
Recommended start:
  REVIEW_PUBLIC_POC
Steps:
  1. Review CVE summary [REVIEW_CVE_SUMMARY]
  ...
Evidence targets:
  - CVE_REFERENCE
  ...
Unknowns:
  - asset version unknown
  ...
```

API (read-only, key-gated, bounded pagination, deterministic ordering):

- `GET /api/research/plans?limit=&offset=&cve=&program=&lead=` → `{total, offset, limit, items}`
- `GET /api/research/plans/{plan_id}` → plan or 404
- Declared before generic CVE routes; malformed ids → 400, absent → 404,
  missing key → 401, `limit` clamped to 100, `offset` ≥ 0.

Dashboard / UI:

- Sidebar: Research Leads + Research Plans (no redesign).
- `/ui/research/plans` — list + filters (CVE/program/status) + summary counts.
- `/ui/research/plans/{plan_id}` — steps, evidence targets, unknowns, blockers,
  priority/relevance, lead/CVE links.
- Lead detail CTA: "Research Execution Plan →" (only when a plan exists).
- CVE detail: quick action + inline plan panel when a plan exists (`plan`).
- Dashboard: compact Research Plans KPI/card (ready/blocked/completed, top 3).
- Every plan page carries the banner: `RESEARCH PLAN — NOT VERIFIED`.
- Autoescaping mandatory; tested with hostile HTML/script in `program`.

## 10. Real corpus results

`research plan --cve CVE-2026-1557` (and API/UI projections) yield two actionable
plans:

- `CVE-2026-1557 → dell` — `r22-38d26f10681e9a0f`, `RESEARCH_PLAN_READY`
- `CVE-2026-1557 → indeed` — `r22-fda96966ea7af4ae`, `RESEARCH_PLAN_READY`

Both have:

- `status = RESEARCH_PLAN_READY` and `recommended_start = REVIEW_PUBLIC_POC`.
- Public PoC step + `REVIEW_EXPLOITABILITY` + WordPress technology evidence
  (`ASSET_TECHNOLOGY`).
- No false component match step/target (correctly absent — only generic tech match
  in the corpus, no observed plugin/component).
- Explicit unknowns: `asset version unknown`, `affected plugin not observed`, etc.
- No claim that the target is vulnerable; no active validation.

Weaker/non-candidate CVEs (e.g. `CVE-2024-0001`) correctly yield no plan.

The CLI parser fix was verified directly: `research --help` no longer raises
`conflicting subparser: research`, and `research plan --help` + `research
--cve CVE-...` both work.

## 11. Tests

`tests/test_research_execution.py` — 53 focused offline tests (no network, no
Nuclei, no Mongo writes):

- Plan-id determinism, uniqueness, cross-import stability, traversal rejection.
- Deterministic ordering: rank order matches R21/R18; step and evidence ordering
  respect their precedence; byte-identical idempotence (`sha256` stable).
- Real corpus composition (12 tests): strong candidate fields, both programs,
  public PoC step/evidence, corpus `recommended_start = REVIEW_PUBLIC_POC` for
  dell/indeed with `steps[]` display order unchanged, `recommended_start` always
  references an emitted step, WordPress technology evidence with no false
  component claim, unknowns remain explicit, no vulnerable wording, whitelisted
  step/evidence codes, UNKNOWN→no-positive-step, weaker CVE yields no spurious
  plan.
- `recommended_start` selection (7 tests): PoC-first when present, UNKNOWN
  `public_poc` never selects `REVIEW_PUBLIC_POC`, no-PoC but known
  exploitability → `REVIEW_EXPLOITABILITY`, technology-only →
  `REVIEW_TECHNOLOGY_MATCH`, fallback → `REVIEW_CVE_SUMMARY`, `None` when no
  steps, always-references-emitted-step plus determinism over all plans.
- Status semantics (2 tests): derivation from lead; no `VULNERABLE/...` in statuses.
- API (6 tests): 401 without key, list/detail, 404s, pagination bounds (100 cap,
  offset-beyond-total), filters (cve/program/lead), correct route precedence
  before `/api/research/{cve}`, no traversal via plan id.
- CLI (7 tests): `research plan` list/filters/`--json`/`--limit`/`--lead`,
  help, legacy `research` still requires `--cve`.
- UI (6 tests): list banner/links, detail banner/plan, lead detail CTA,
  CVE detail plan exposure, escaping, research-only wording, dashboard KPI.
- Safety (3 tests): no `socket/subprocess/requests/llm/nuclei` imports, no
  `VULNERABLE/VERIFIED/EXPLOITED` status vocabulary, idempotent SHA.

Regressions run together (171 tests, all OK):

- `tests.test_research_execution` — 53 OK
- `tests.test_research_leads` — 24 OK
- `tests.test_research_api` — 29 OK
- `tests.test_research_workflow` — 32 OK
- `tests.test_research_navigation` — 14 OK
- `tests.test_research_intelligence_ui` — 19 OK
- `git diff --check` — clean

## 12. Security review

- Deterministic `plan_id` (regex `^r22-[0-9a-f]{16}$`); invalid ids map to
  400/404, never filesystem access (no path construction from plan ids).
- Bounded pagination (`clamp_limit` ≤ 100, `offset ≥ 0`); no unbounded scans.
- API key auth on every new route (`verify_api_key`); missing key → 401.
- Autoescaping on all new pages; hostile `<script>` / `<b>` in `program` /
  unknowns renders as `&lt;script&gt;`.
- No `socket`/`subprocess`/`urllib`/`requests`/`httpx`/`llm`/`openai`/`anthropic`
  imports in `backend/research_execution.py`; no 5B–5J, no Nuclei, no browser,
  no subprocess.
- Research-only wording enforced: every new page carries `RESEARCH PLAN — NOT
  VERIFIED` (or `RESEARCH LEAD — NOT VERIFIED`) and no `VULNERABLE`/`VERIFIED`/
  `EXPLOITED`/`FINDING`/`CONFIRMED` statuses or step text.
- Read-only projection: no writes, no persistence, no alerts, no findings,
  no active validation.

## 13. Limitations

- Plans exist only for CVE×program pairs with an R18 candidate and thus an R21
  lead; other CVEs appear as "no plan" by omission (not as a negative plan).
- `recommended_start` no longer tracks the first displayed step; it follows the
  separate `RECOMMENDED_START_ORDER` ranking documented in §15 (PoC-first when
  supported, otherwise exploitability → technology → component → parameter →
  version → asset → references → summary). `steps[]` display order is still
  fixed `STEP_ORDER` precedence.
- `ASSET_VERSION` evidence target is structurally supported but not emitted for
  the current corpus (no positive asset-version signal).
- `created_at`/`updated_at` remain absent/empty for idempotence; `task_id` is
  carried through from the lead but plan status shadows lead status, not a
  separate task store read.

## 14. Explicit confirmation

- No network — no `socket`/`urllib`/`requests`/`httpx` fetches added.
- No LLM — no `ai.llm` / provider imports or calls.
- No Nuclei — no template generation/run/validation.
- No active validation — GET-only renders of persisted local artifacts.
- No production findings — statuses/wording stay research-only.
- No alerts — no alerting code touched or added.
- No Git operations — no commit, amend, or push performed.

## 15. recommended_start fix (final)

Problem: `recommended_start` was `steps[0]["code"]`, i.e. the first emitted
step in fixed `STEP_ORDER` precedence, so the real corpus yielded
`REVIEW_CVE_SUMMARY` for `CVE-2026-1557 → dell` even though `PUBLIC_POC=true`
makes `REVIEW_PUBLIC_POC` the most useful actionable start.

Fix (`backend/research_execution.py`, no R15–R21 / R20 changes, no persistence):
new `RECOMMENDED_START_ORDER` plus `_recommended_start_for(steps)` used by
`_build_plan`. Selection precedence:

1. `REVIEW_PUBLIC_POC` (only emitted when `public_poc == "true"`)
2. `REVIEW_EXPLOITABILITY`
3. `REVIEW_TECHNOLOGY_MATCH`
4. `REVIEW_COMPONENT_MATCH`
5. `REVIEW_PARAMETER_MATCH`
6. `REVIEW_VERSION`
7. `REVIEW_ASSET_EVIDENCE`
8. `REVIEW_REFERENCES`
9. `REVIEW_CVE_SUMMARY`
10. `None` when there are no steps (with a first-emitted-step fallback for
    ranked codes outside this list, e.g. a task-only plan).

`steps[]` ordering is untouched. Only an actually emitted step can be chosen,
and UNKNOWN can never cause a positive recommendation because `steps[]` itself
is never emitted for UNKNOWN values. Status semantics unchanged.

Exact tests/results (`python3 -m unittest`, all offline):

- `tests.test_research_execution` — 53 tests, OK (includes the 7 new
  `TestRecommendedStart` tests and the corpus `REVIEW_PUBLIC_POC` assertions
  for dell/indeed).
- `tests.test_research_leads` + `tests.test_research_api` — 53 tests, OK.
- `tests.test_research_workflow` + `tests.test_research_navigation` +
  `tests.test_research_intelligence_ui` — 65 tests, OK.
- `git diff --check` — clean.

Real corpus result (verified via `list_plans(cve="CVE-2026-1557")`):

- `CVE-2026-1557 → dell`: `status = RESEARCH_PLAN_READY`,
  `recommended_start = REVIEW_PUBLIC_POC`.
- `CVE-2026-1557 → indeed`: `status = RESEARCH_PLAN_READY`,
  `recommended_start = REVIEW_PUBLIC_POC`.

Still holding: no vulnerability claim (`VULNERABLE`/`VERIFIED`/`EXPLOITED`/
`FINDING` absent from plan blobs), component/version unknowns remain explicit
(`asset version unknown`, `affected plugin not observed`), no active
validation, no Nuclei, no LLM, no network.

Limitations after the fix:

- `recommended_start` is a pointer into `steps[]`, not an extra step — consumers
  must still read the full ordered `steps[]`.
- A task-only plan (only `REVIEW_RESEARCH_TASK` emitted) falls back to that
  step rather than `None`, since it is the sole actionable item.
- `REVIEW_RESEARCH_TASK` is otherwise unranked: a linked task does not
  outrank evidence review as a starting point.

## Agent / Model

- Model: muse-spark
- Stage: R22
- Role: Research Execution Planning
