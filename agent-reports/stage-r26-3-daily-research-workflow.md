# Stage R26.3 — Opportunity Daily Workflow

## Status
**IMPLEMENTED (derived, read-only workflow).** R26.3 turns the existing R26.2
Action Queue into a compact daily researcher workflow that answers *"What
should I work on today?"* and *"What changed since the previous research
state?"* — with no new score, no persisted snapshots and no security testing.

Hard boundaries held: no Money Score change, no r25-2, no R15–R25 formula or
lifecycle change, no R26.1 classification change, no R26.2 precedence change,
no LLM/network/DNS/Nuclei/browser/PoC/target interaction, no findings/alerts,
no payout/bounty prediction, no automatic research/outcomes/tuning, no Mongo,
no systemd, no `.env`, no snapshots, no git add/commit/push.

## 1. Architecture

```
R26.2 Action Queue  (R26.1 opportunities + R25.5 outcomes + R25.7 sessions)
        │
        ▼
backend/daily_research.py   (composition only; no persistence)
        ├─ list_actions(...) + per-lead session/outcome enrichment
        ▼
ai/knowledge/daily_research.py   (pure deterministic engine)
   build_top_opportunities / build_daily_plan / build_blocked_work /
   build_in_progress_work / build_recommendations / build_daily_workflow /
   compare_workflows / build_workflow_summary
        │
        ▼
ai/schemas/daily_research.py  (DailyWorkflow / WorkflowChange, r26-3)
        │
   ┌────┼─────────────────────────┐
   ▼    ▼                         ▼
CLI `workflow daily` /     API /api/research/workflow/{daily,summary}
`workflow diff` (files    UI: DAILY RESEARCH WORKFLOW section on the
as INPUTS only)           existing Research Leads page
```

Fail-soft everywhere: a failing action queue or enrichment degrades to an
empty/partially enriched workflow; malformed items are skipped; nothing is
invented.

## 2. Daily workflow model (`ai/schemas/daily_research.py`)

`DailyWorkflow` fields: `workflow_version (= r26-3), total_opportunities,
ready, blocked, in_progress, deferred, completed, top_actions,
top_opportunities, blocked_items, in_progress_items, changed_items,
recommendations, items, research_only (= true)`.

- `items` is the full ranked enriched action list (all items) used for
  deterministic comparison; it is derived on demand and **never persisted**.
- `extra="forbid"`; `research_only` forced `true`; bounded item lists and
  recommendations. No payout/target/execution fields exist or can be
  injected. No new numeric score.
- `WorkflowChange` validates the closed change vocabulary.

## 3. Top opportunities

`build_top_opportunities(items, top_n=5)` slices the already-ranked R26.2
order (top-N default 5) and projects exactly the spec fields: `lead_id,
cve_id, program, opportunity_class, money_score, confidence,
evidence_quality, estimated_minutes, current_status, recommended_action,
why_now, blockers, next_step` (plus the existing `priority` for display).

## 4. Today's research plan

`build_daily_plan(items)` emits one entry per **READY** opportunity in
existing R26.2 action ranking order: `lead_id, cve_id, program,
recommended_action, estimated_minutes, reason, next_step`. No persisted task
is created — recommendation only.

## 5. Blocked work

`build_blocked_work(items)` exposes each `BLOCKED` item with money score,
machine blocker codes, human blocker explanations (reusing R26.2
`translate_blockers`; unknown codes keep a conservative fallback), the
recommended action, and the next step. Example:

```
CVE-2026-1557 → dell
  only generic technology match
  affected plugin not observed
Next: Confirm affected component/plugin presence.
```

## 6. In-progress work

`build_in_progress_work(items, sessions_by_lead)` exposes active R25.7
sessions (`session_id, planned_minutes, actual_minutes, status`) per
IN_PROGRESS lead with `CONTINUE_RESEARCH`. No session is ever created or
started by this layer.

## 7. Diff model (`compare_workflows(previous, current)`)

Pure, in-memory, no snapshots, no clock, no I/O. Accepts a list of items or a
workflow document containing one of `items` / `top_opportunities` /
`top_actions` / `blocked_items`; malformed input raises `ValueError`.
Detects exactly the closed vocabulary:

`NEW, REMOVED, CLASS_CHANGED, ACTION_CHANGED, MONEY_CHANGED,
CONFIDENCE_CHANGED, EVIDENCE_CHANGED, SESSION_CHANGED, OUTCOME_CHANGED`.

Each change: `{lead_id, cve_id, program, change_type, before, after, reason}`.
Ordering is `lead_id` ASC then fixed change-type order. Session/outcome
changes fall back to `current_status` IN_PROGRESS / COMPLETED when the
enriched fields are absent.

## 8. Recommendation logic

Deterministic, from structured counts only (no LLM prose, no invented facts):

| Condition | Recommendation |
|---|---|
| no opportunities | "No research opportunity currently requires action." |
| in_progress > 0 | "Continue the active research session." |
| READY with class HIGH_VALUE | "Start the highest-value research opportunity." |
| all items BLOCKED | "Resolve asset-match blockers before spending research time." |
| completed/terminal outcomes | "Review completed research outcomes before starting additional work." |
| other READY items | "Work the ready research opportunities." |

Multiple applicable recommendations are emitted in that fixed order; empty
input yields the no-action message.

## 9. CLI

```
python -m ai.research_cli workflow daily [--limit N --class C --status S --cve X --program P --json]
python -m ai.research_cli workflow diff --previous <json-file> --current <json-file> [--json]
```

Observed real-corpus output:

```
DAILY RESEARCH WORKFLOW

READY: 0
BLOCKED: 2
IN PROGRESS: 0

TOP OPPORTUNITIES

#1 BLOCKED
    CVE-2026-1557 → dell
    Money: 53 / P3_MEDIUM
    Action: VERIFY_ASSET_MATCH

    NEXT:
    Confirm affected component/plugin presence.

BLOCKED WORK

#1 CVE-2026-1557 → dell
   only generic technology match
   affected plugin not observed

RECOMMENDATION

Resolve asset-match blockers before spending research time.
```

`workflow diff` reads the two JSON files as **inputs only**; it validates
JSON and structure, prints grouped changes, never modifies the files and
never persists anything. Malformed/missing files exit 1 with a stderr error.

## 10. API

Key-gated, GET-only, declared before `/api/research/{cve}`:

| Route | Behavior |
|---|---|
| `GET /api/research/workflow/daily` | workflow (`limit` 1..50, `cve`, `program`, `class`, `status`) |
| `GET /api/research/workflow/summary` | compact counts + top action |

Responses carry `workflow_version: r26-3` and `research_only: true`. No POST/
PUT/DELETE (405/401). No snapshot persistence.

## 11. UI

One compact section on the existing Research Leads page (no new page, no
charts, no polling, no websocket, no calendar):

- header `Daily research workflow` + `r26-3 · read-only`;
- READY / BLOCKED / IN PROGRESS / COMPLETED counters (existing `stat-card`);
- `Today's plan` list when any READY item exists;
- `Top opportunities` table (CVE, program, class, money, action) reusing
  existing table/badge styles;
- the first deterministic recommendation.

The section is fail-soft: a workflow failure renders nothing extra and never
breaks the leads list.

## 12. Tests

New `tests/test_daily_research_workflow.py` — **69 tests, all OK** (~2.3 s):

- schema: forced version/research flags, closed change types, forbidden
  fields rejected, bounded lists, no forbidden model fields.
- top opportunities: default/custom top-N, field shape/order, empty,
  malformed items skipped.
- daily plan: READY-only, fields, order.
- blocked work: codes + human explanations, unknown-code fallback.
- in-progress work: active-session detail, non-active skipped, no sessions.
- recommendations: empty, all-blocked, high-value ready, ready-only, active
  session, completed, multi-recommendation order.
- workflow: counts for all five statuses, empty, deterministic, summary,
  no duplicate score fields.
- compare: NEW, REMOVED, CLASS_CHANGED, ACTION_CHANGED, MONEY_CHANGED,
  CONFIDENCE_CHANGED, EVIDENCE_CHANGED, SESSION_CHANGED (plus fallback),
  OUTCOME_CHANGED, unchanged, deterministic/type order, all document keys,
  malformed inputs, empty workflows.
- backend: real corpus, filters (class/status/cve/program), summary,
  compare, determinism, no snapshot dir or writes, Money Score unchanged.
- CLI: daily human/JSON/filters, no payout/execution flags, diff read-only
  proof (input bytes unchanged), diff JSON/no-change, malformed files.
- API: auth, daily shape, summary, filters/bounds, no write endpoints, no
  payout vocabulary.
- UI: workflow section, research-only tokens, no polling/websocket.
- safety: executable-token scan, no persistence tokens, engine purity,
  Money/r26-1/r26-2 constants unchanged, calibration unchanged.

Regression run (all OK): R25.2 91, R25.3 33, R25.4 21, R25.5 64, R25.6 48,
R25.7 66, R26.1 60, R26.2 82, R26.3 69 (**534 OK**) plus R21/R22 logic
classes 54 OK. `git diff --check` clean.

## 13. Real corpus verification

No data was fabricated or written. Expected state confirmed:

```
workflow_version   r26-3
total              2
READY              0
BLOCKED            2
IN PROGRESS        0
top opportunity    CVE-2026-1557 → dell  (BLOCKED, VERIFY_ASSET_MATCH, 53 / P3_MEDIUM)
blocked work       2 items with blocker codes + human explanations
recommendation     Resolve asset-match blockers before spending research time.
sessions           0        outcomes 0
Money Score        53 / P3_MEDIUM (unchanged)
calibration        INSUFFICIENT_DATA, weights UNCHANGED
snapshots dir      absent
```

## 14. Safety audit

- **research_only = true** on every model, backend projection, API response,
  CLI output and UI render.
- **No network / DNS / subprocess / LLM / Nuclei / browser / PoC / target
  interaction / findings / alerts**: static executable-token scans on all
  three new modules.
- **No payout/bounty prediction**: no payout fields or vocabulary anywhere.
- **No automatic research / outcome creation / tuning**: the workflow only
  reads R26.2/R25.5/R25.7 state; Money Score constants (`MONEY_W_*`,
  `RULE_VERSION = "r25-1"`), R26.1 (`r26-1`) and R26.2 (`r26-2`) are
  asserted unchanged; `build_economics()` identical before/after.
- **No persistence / no snapshots / no Mongo / no systemd**: the snapshot
  directory is never created; `workflow diff` only reads caller-supplied
  files and the backend module contains no write tokens.
- No R15–R26 formula/lifecycle changes; no `.env`; no git add/commit/push.

## 15. Limitations

- **Presentation layer only**: the workflow derives from existing action
  state; it is not evidence and cannot confirm a vulnerability.
- **Diff needs compatible inputs**: comparison uses `items` when present,
  otherwise falls back to `top_opportunities`/`top_actions`/`blocked_items`
  (top-N only). Snapshots are external by design; this stage does not create
  them.
- **No date semantics**: there is no "today" clock dependency — the workflow
  is the current derived state, and "diff" is caller-driven.
- **Enrichment uses existing private helpers** (`_sessions_for` /
  `_outcomes_for` / `list_actions`) — read-only composition, no new engine.
- **In-progress items** appear only when an actual R25.7 session record is
  IN_PROGRESS; the count is derived from action status independently.
- **Empty/absent data are explicit** (`NONE`), never inferred or penalized.

## 16. Exact next-stage recommendation

**R26.4 — Researcher Follow-Through Metrics (read-only, derived).**

1. Measure whether the daily workflow actually drives action: count of days
   with a READY top action, sessions started after a workflow surfaced the
   lead, and outcomes recorded against previously blocked items — all
   derived on demand from existing R25.5/R25.7 records (no new persistence,
   no new scoring).
2. Keep snapshots external; if a history is ever required, require a
   separate reviewed stage with an append-only store (R25.5/R25.7 pattern)
   and never feed it back into the Money Score.
3. Optionally add a `workflow diff --normalize` presentation flag to compare
   re-ordered item lists; still no scoring impact.
4. Preserve all boundaries: research-only, no execution/targets/payouts, no
   LLM/network/Mongo, no automatic tuning, r25-1 / r26-1 / r26-2 / r26-3
   unchanged.

## Agent / Model
- Model: Miuz Spark (opencode-go/deepseek-v4.1-flash)
- Stage: R26.3
- Role: Daily Research Workflow
