# Stage R21 — Actionable Research Leads

## 1. Objective

Turn the existing deterministic R15–R20 research intelligence into a
compact, actionable "Research Lead" projection answering: *"Why should
a researcher investigate this CVE against this program?"* Research only.

## 2. Exact files changed

New:

- `backend/research_leads.py` — deterministic Research Lead projection
  (composition over R15–R18 outputs + R20 linkage, read-only, on-demand,
  no persistence).
- `web/templates/research_leads.html` — R21 leads list page (read-only).
- `web/templates/research_lead_detail.html` — R21 lead detail page.
- `tests/test_research_leads.py` — 24 focused tests (offline).

Modified (display/wiring only — no algorithm changes):

- `backend/routers/research.py` — GET `/api/research/leads` and
  `/api/research/leads/{lead_id}` (key-gated, bounded, read-only),
  declared before the `/api/research/{cve}` catch-all (same convention
  as the tasks/queue routes).
- `backend/routers/research_pages.py` — `/ui/research/leads` +
  `/ui/research/leads/{lead_id}` (auth, read-only) before
  `/ui/research/{cve}`; `leads_url` in `_ctx`; CVE detail exposes the
  relevant lead (`lead`) when one exists.
- `backend/routers/pages.py` — dashboard builds `leads_summary` +
  `leads_url` (fail-soft; recon never fails on research data).
- `backend/routers/programs.py`, `backend/routers/runs.py` — `leads_url`
  added to nav context for the shared sidebar.
- `web/templates/base.html` — one Research Leads entry in the existing
  Research sidebar group (no redesign).
- `web/templates/dashboard.html` — compact Research Leads section
  (actionable/blocked/completed cards, top leads, CTA).
- `web/templates/research_detail.html` — `Research lead (...)` quick
  action when the CVE has a lead.
- `ai/research_cli.py` — `research leads [--cve --program --limit
  --json]` + `run_leads()` (deterministic human-readable output).

Untouched: all R15–R20 scoring/state-machine/persistence/schema logic,
`database/` (pre-existing unrelated `db.py` change left alone), `ns/`,
`crawl/`, Nuclei/CVE pipelines.

## 3. Data flow

```
R18 list_research_queue() ── CVE×program candidates (priority class/score,
                             relevance/score, queue_id, blockers, reasons)
        │
        ├─ per CVE: cve_intelligence()['exploitability'] (R15, read-only)
        │           cve_intelligence()['relevance']     (R17, read-only)
        ├─ per queue_id: research_tasks mapping        (R20, read-only)
        v
ResearchLead { lead_id, cve_id, program, queue_id, task_id,
  priority_score/level, relevance_score/level,
  exploitability_summary, asset_match_summary, reasons[], blockers[],
  recommended_next_step, status, rule_version }
        v
CLI `research leads` │ GET /api/research/leads (+/{lead_id}) │
  /ui/research/leads (+/{lead_id}) │ dashboard Research Leads section │
  CVE detail lead CTA
```

No persistence: leads are generated on-demand (idempotent; `created_at` /
`updated_at` remain empty metadata). A lead exists only when an R18 queue
candidate exists — a CVE with no deterministic relevance yields none
(exactly mirroring R18).
## 4. Reason codes

Every reason is `{code, text, source}` and is emitted ONLY on an explicit
positive underlying value. UNKNOWN/absent values never produce a reason.

Exploitability (source `exploitability`, from structured R15 fields):

| Code | Text | Fires only when |
|---|---|---|
| `PUBLIC_POC` | Public PoC available | `public_poc == "true"` |
| `EXPLOIT_AVAILABLE` | Exploit available | `exploit_available == "true"` |
| `UNAUTHENTICATED` | Unauthenticated | `authentication_required == "false"` |
| `NO_USER_INTERACTION` | No user interaction required | `user_interaction_required == "false"` |
| `LOW_ATTACK_COMPLEXITY` | Low attack complexity | `exploit_complexity == "low"` |

Asset relevance (source `relevance`, from explicit R17 reasons/matches):

| Code | Text | Fires only when |
|---|---|---|
| `TECHNOLOGY_OBSERVED` | Affected technology observed | a `technology match: …` reason |
| `COMPONENT_OBSERVED` | Affected component observed | plugin/component/product-match reason |
| `PARAMETER_OBSERVED` | Affected parameter observed | a parameter reason |
| `PRODUCT_MATCHED` | Matching product/plugin observed | matched assets non-empty |

Priority (source `priority`):

| Code | Text | Fires only when |
|---|---|---|
| `CRITICAL_PRIORITY` | Critical research priority | class `CRITICAL_RESEARCH` |
| `HIGH_PRIORITY` | High research priority | class `HIGH_RESEARCH` |

## 5. Blocker rules

Uses the existing R18 hard blockers verbatim on the lead (`blockers[]`):
`only generic technology match`, `affected plugin not observed`,
`asset component not observed`, `asset version unknown`. Unknowns are never
silently positive — the queue unknowns stay visible on the R18 queue and
leads stay blocked (status `RESEARCH_BLOCKED`) while their next step is
`REVIEW_ASSET_MATCH` / `WAIT_FOR_MORE_EVIDENCE`.

## 6. Next-action rules (`recommended_next_step`)

Deterministic order (first match wins):

1. Task DONE            → `RESEARCH_COMPLETED`
2. Task BLOCKED          → `WAIT_FOR_MORE_EVIDENCE`
3. Critical/high priority AND positive relevance (LOW/MEDIUM/HIGH)
                             → `START_RESEARCH` — even with informational
                               hard blockers. This is the explicit
                               CVE-2026-1557 → dell.com behaviour.
4. Any remaining hard blockers → `REVIEW_ASSET_MATCH`
5. Otherwise                   → `WAIT_FOR_MORE_EVIDENCE`

Status shadows this: `RESEARCH_COMPLETED` on DONE; `RESEARCH_BLOCKED`
while the next step is REVIEW/WAIT; otherwise `RESEARCH_LEAD`.
`lead_id` is `rl-` + deterministic sha256(cve, program) (rule version
`r21-1`; mirrors `queue_id_for` / `task_id_for`).
## 7. Real corpus example (`research leads --cve CVE-2026-1557 --program dell`)

```
Research Leads
==============

#1 CVE-2026-1557 \u2192 dell
Priority: 80 / CRITICAL_RESEARCH
Relevance: 20 / LOW
Status: RESEARCH_LEAD
Lead id: rl-af7ecfba1a86fc83
Why investigate:
  Public PoC available (PUBLIC_POC)
  Exploit available (EXPLOIT_AVAILABLE)
  Unauthenticated (UNAUTHENTICATED)
  No user interaction required (NO_USER_INTERACTION)
  Low attack complexity (LOW_ATTACK_COMPLEXITY)
  Affected technology observed (TECHNOLOGY_OBSERVED)
  Matching product/plugin observed (PRODUCT_MATCHED)
  Critical research priority (CRITICAL_PRIORITY)
Blockers:
  only generic technology match
  affected plugin not observed
  asset component not observed
  asset version unknown
Next action:
  START_RESEARCH
```

(`research leads` also renders a second RESEARCH_LEAD for `indeed`;
`leads_summary()` reports total 2, actionable 2, blocked 0, completed 0.)

## 8. Tests

`tests/test_research_leads.py` (24 tests, offline): lead-id
determinism/uniqueness; rank-order preservation vs R18; strong-candidate
fields; all 8 positive R15/R17/R16 codes with correct sources;
UNKNOWN/absent/keyword-only values yield no positive reason; R18 blocker
propagation; strong candidate START_RESEARCH/RESEARCH_LEAD; weak blocked
candidate → REVIEW_ASSET_MATCH/RESEARCH_BLOCKED; ineligible priority →
WAIT_FOR_MORE_EVIDENCE; DONE task → completed+task_id; BLOCKED task →
WAIT; API auth (401 without key), list/detail, 404s, pagination/filters;
UI banners/links/dashboard CTA/escaping/research-only wording;
source scan; idempotent output.

Results:

- `tests.test_research_leads` — 24 OK
- R15–R20 regressions: `ai.test_research_queue` 24 OK,
  `ai.test_research_priority` 27 OK, `ai.test_asset_relevance` 25 OK,
  `ai.test_exploitability_intelligence` 46 OK, `ai.test_intelligence`
  32 OK, `ai.test_knowledge_store` 15 OK
- UI/workflow regressions: `tests.test_research_navigation` 14 OK,
  `tests.test_research_intelligence_ui` 19 OK,
  `tests.test_research_workflow` 32 OK, `tests.test_research_api`
  29 OK, `tests.test_xss_llm_dashboard` 14 OK
- `git diff --check` — clean

Pre-existing: `tests/test_research_ui.py` keeps its two known
corpus-dependent failures (documented at D6), untouched.
## 9. Security review

- GET-only API/UI, key-gated, bounded (`clamp_limit`), deterministic,
  read-only: errors map to 400/404; no writes, no mutation paths.
- Ids validated by regex (`RL_LEAD`, CVE, program); arbitrary filesystem
  paths impossible; downloads/`|safe` absent (templates use autoescaping).
- Hostile persisted values (HTML/script in lead fields) render escaped
  (covered by `test_escaping`).
- No socket/subprocess/LLM/requests/threading/5B-5J imports in the new
  module (covered by `test_no_network_subprocess_llm_sources`).
- Explicit `RESEARCH LEAD — NOT VERIFIED` banner on list/detail pages;
  dashboard + CVE detail word leads as research planning; status/next-step
  vocabulary contains no VULNERABLE/VERIFIED/EXPLOITED/FINDING.
- `?api_key=` propagation in new UI links follows the existing
dashboard convention (`build_url`/`_ui_link`); no new secret material.

## 10. Limitations

- Leads exist only for CVE×program pairs with an R18 queue candidate
  (positive priority × asset relevance). No queue candidate → no lead;
  such pairs surface only `WAIT_FOR_MORE_EVIDENCE` semantics by omission.
- Summaries/steps are deterministic heuristics over R15–R18 outputs — a
  START_RESEARCH lead is a research recommendation, never evidence.
- On-demand generation: no `created_at`/`updated_at` clock values
  (empty metadata) to preserve idempotence.

## 11. Explicit confirmation

- No network — no requests/sockets/URL fetching added.
- No LLM — no model/provider imports or calls.
- No Nuclei — no template generation/run/validation.
- No active validation — GET-only renders of persisted artifacts.
- No production finding — statuses/wording stay research-only.
- No alerts — no alerting code touched or added.
- No Git operations — no commit/push performed.

## Agent / Model

- Model: cline-gpt-5 (Cline)
- Stage: R21
- Role: Actionable Research Leads
