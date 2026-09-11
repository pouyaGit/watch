# Stage R26.2 — Opportunity Action Queue

## Status
**IMPLEMENTED (read-only decision/presentation layer).** R26.2 turns the
existing R26 Opportunity Intelligence into a deterministic,
researcher-oriented Action Queue that answers *"What should I work on
first, and what exactly is blocking the other items?"*

This is a presentation/decision layer ONLY:

- No Money Score change (R25.1 unchanged).
- No new numeric score; the existing Money Score is copied verbatim.
- No LLM, no network, no DNS, no subprocess, no target interaction, no
  Nuclei, no browser, no PoC execution, no findings, no alerts, no
  payout/bounty prediction.
- No automatic research start, no automatic outcome creation, no
  automatic score adjustment.
- No background workers, no systemd changes, no `.env` changes, no
  Mongo writes, no new persistence lifecycle (this is a derived view
  composed from R26.1 + R25.5 + R25.7).
- No R15–R25 formula/lifecycle changes, no commit/push.

## 1. Architecture

```
R18 queue  ─►  R21 lead  ─►  R26.1 opportunity (read-only view)
                              │
                              ├─ R25.7 sessions  (active?)
                              ├─ R25.5 outcomes  (terminal?)
                              └─ R26.1 class    (BLOCKED / HIGH_VALUE / ...)
                                              │
                                              ▼
                ai/knowledge/opportunity_action.py  (pure engine)
                classify_action / classify_status / translate_blockers
                build_next_step / build_action / rank_actions
                build_action_summary
                                              │
                                              ▼
                backend/research_action_queue.py  (compose, fail-soft)
                                              │
                              ┌───────────────┼─────────────────┐
                              ▼               ▼                 ▼
                  CLI opportunity    API /api/research/      UI: NEXT
                  action-list /      opportunities/actions    ACTION
                  action-show /      /summary/{lead_id}       column +
                  action-summary                              lead panel
```

Fail-soft: malformed leads, missing sessions/outcomes, or backend
failures never break the queue; missing data is explicit `NONE`.

## 2. Action model (`ai/schemas/opportunity_action.py`)

Fields: `action_id, opportunity_id, lead_id, cve_id, program,
opportunity_class, money_score, priority, confidence, evidence_quality,
effort_score, estimated_minutes, current_status, recommended_action,
action_reason, blockers, why_now, next_step, research_only,
rule_version`.

- `action_id = "oa-" + sha256(rule_version + lead_id)[:16]`
  (deterministic; `rule_version = "r26-2"`).
- `extra="forbid"`; enums validated for class/status/action/confidence/
  evidence-quality; `rule_version` fixed `r26-2`; `research_only`
  forced `true`.
- No payout/bounty/reward/target-URL/IP/domain/credential/exploit-command/
  execution-command/production-finding fields exist or can be injected.
- No new numeric score is added (`money_score` is copied verbatim from
  R26.1).

## 3. Action states (closed vocabulary)

`current_status ∈ {READY, BLOCKED, IN_PROGRESS, COMPLETED, DEFERRED}`.
Derived from existing R21/R25/R26 signals only — no new persistence
lifecycle. Precedence (`classify_status`):

| Order | Status | Rule |
|---:|---|---|
| 1 | `IN_PROGRESS` | active R25.7 session OR `CONTINUE_RESEARCH` recommended |
| 2 | `COMPLETED`   | terminal R25.5 outcome + no active session + `REVIEW_OUTCOME` |
| 3 | `BLOCKED`     | opportunity_class `BLOCKED` OR `VERIFY_ASSET_MATCH` recommended |
| 4 | `DEFERRED`    | recommended_action `DEFER` |
| 5 | `READY`       | otherwise (start/gather/research) |

## 4. Recommended-action precedence (`classify_action`)

Closed vocabulary: `VERIFY_ASSET_MATCH, GATHER_EVIDENCE, START_RESEARCH,
CONTINUE_RESEARCH, REVIEW_OUTCOME, DEFER`. First match wins
(**documented**):

| Order | Rule | Result |
|---:|---|---|
| 1 | active R25.7 session (`session_status` ∈ `PLANNED`/`IN_PROGRESS`/`ACTIVE` OR `planned_sessions`/`in_progress_sessions > 0`) | `CONTINUE_RESEARCH` |
| 2 | R26 opportunity_class `BLOCKED` | `VERIFY_ASSET_MATCH` |
| 3 | terminal R25.5 outcome (`outcome_status ∉ {NONE, IN_PROGRESS}` OR `accepted/duplicate/rejected/wasted > 0` OR `terminal_attempts > 0`) and no active session | `REVIEW_OUTCOME` |
| 4 | opportunity_class `LOW_CONFIDENCE` | `GATHER_EVIDENCE` |
| 5 | opportunity_class ∈ `{HIGH_VALUE, GOOD_OPPORTUNITY}` | `START_RESEARCH` |
| 6 | opportunity_class `RESEARCH_FIRST` | `START_RESEARCH` |
| 7 | otherwise | `DEFER` |

This rule intentionally checks the R26.1 class (not raw confidence) so
it stays aligned with the Money Score composition and never introduces
a fresh scoring factor.

## 5. Blocker translation (`translate_blockers`)

Structured blocker codes emitted by R26/R25 are mapped to
researcher-readable text. The machine-readable code is **always
preserved** in `blockers`, the human explanation is rendered alongside.
No new blocker codes are invented.

| Code | Researcher text |
|---|---|
| `only generic technology match` | Verify the CVE applies to this specific asset rather than generic technology. |
| `affected plugin not observed` | Confirm the affected component/plugin is present in the asset. |
| `asset component not observed` | Confirm the vulnerable component is present. |
| `asset version unknown` | Determine the affected version before investing research time. |
| `no positive asset match signal` | Confirm the asset matches the affected product or component. |
| `missing historical data` | Capture an initial research attempt to build historical data. |
| `insufficient evidence` | Collect authoritative public evidence for the CVE. |
| (unknown code) | "Investigate the unknown blocker code." (conservative fallback; never fabricated vocabulary) |

## 6. Next step (`build_next_step`)

Exactly **one** primary next step per action. No exploit commands, no
target URLs, no security-testing commands.

| Action | Next step |
|---|---|
| `VERIFY_ASSET_MATCH` | Confirm affected component/plugin presence. |
| `GATHER_EVIDENCE` | Collect authoritative public evidence for the CVE. |
| `START_RESEARCH` | Begin a time-boxed research session. |
| `CONTINUE_RESEARCH` | Continue the active research session. |
| `REVIEW_OUTCOME` | Review the previous research outcome before spending more time. |
| `DEFER` | No high-value action is currently justified. |

Static executable-token scan in `tests/test_opportunity_action_queue.py`
asserts none of the steps contain `payload`, `inject`, `exploit `,
`curl `, `nuclei `, `nmap `, `msfconsole`, `bash `, `target `,
`http://`, `https://`.

## 7. Queue ordering (`rank_actions`)

Deterministic, **no new numeric score** introduced:

1. `current_status` (IN_PROGRESS, READY, BLOCKED, DEFERRED, COMPLETED)
2. opportunity class (HIGH_VALUE → DEFER)
3. Money Score descending
4. confidence descending
5. evidence quality descending
6. estimated minutes ascending
7. CVE ascending
8. program ascending
9. lead_id ascending

## 8. Daily action summary (`build_action_summary`)

Compact, deterministic counts: `total, ready, blocked, in_progress,
deferred, completed`, `by_action` map, plus `top_action, top_lead,
top_program, top_reason, top_cve, top_money`. No generated clock/date
dependency.

## 9. Pure engine (`ai/knowledge/opportunity_action.py`)

Pure functions only: `has_active_session`, `has_terminal_outcome`,
`classify_action`, `classify_status`, `translate_blockers`,
`build_next_step`, `build_action_reason`, `build_action`,
`rank_actions`, `build_action_summary`. No I/O, no network, no LLM,
no subprocess, no execution, no clock.

## 10. Backend (`backend/research_action_queue.py`)

Composition only. Wraps R26.1 `build_opportunities()` and folds in
R25.7 sessions (`_sessions_for`) and R25.5 outcomes (`_outcomes_for`)
into a deterministic, ranked `build_action_queue()`. Public API:

- `build_action_queue()` → ranked `list[dict]`
- `list_actions(limit, offset, opportunity_class, status, cve, program)` →
  bounded slice with envelope (`total/offset/limit/items/rule_version/
  research_only`)
- `get_action(lead_id)` → one action by deterministic id (404 when
  absent)
- `action_summary()` → compact counts + top action

Fail-soft: a backend or session/outcome failure in the helper is
caught per-lead; the queue never crashes the dashboard.

## 11. CLI

```
python -m ai.research_cli opportunity action-list
       [--class BLOCKED|...] [--status BLOCKED|...] [--cve CVE-...]
       [--program dell] [--limit 50] [--json]

python -m ai.research_cli opportunity action-show --lead-id rl-... [--json]

python -m ai.research_cli opportunity action-summary [--json]
```

Observed current output (matches the spec):

```
ACTION QUEUE

#1 BLOCKED
    CVE-2026-1557 → dell
    Money: 53 / P3
    Confidence: HIGH
    Action: VERIFY_ASSET_MATCH (VERIFY ASSET)

    Blocker:
      only generic technology match
      affected plugin not observed
      asset component not observed
      asset version unknown

    Next:
      Confirm affected component/plugin presence.
```

## 12. API

Three read-only, key-gated, GET-only endpoints — declared **before**
`/api/research/opportunities/{lead_id}` so "actions" is not captured
as a lead id, and before `/api/research/{cve}`.

| Route | Behavior |
|---|---|
| `GET /api/research/opportunities/actions` | ranked list (filters: `class, status, cve, program`, bounded `limit/offset`) |
| `GET /api/research/opportunities/actions/summary` | compact counts + top action |
| `GET /api/research/opportunities/actions/{lead_id}` | one action; malformed/unknown → 404 |

`POST/PUT/PATCH/DELETE` → 401/405. No payout vocabulary in any response.
Every response carries `research_only: true` and `rule_version: r26-2`.

## 13. UI (minimal, existing pages only, no charts/polling/redesign)

- **Research Leads list** (`/ui/research/leads`): added a compact
  `Next action` column with `action-*` badge classes
  (`action-verify-asset-match`, `action-gather-evidence`,
  `action-start-research`, `action-continue-research`,
  `action-review-outcome`, `action-defer`). Title attribute carries
  the current_status.
- **Lead detail** (`/ui/research/leads/{lead_id}`): added a `Next
  action` panel with `NEXT ACTION` (action code + human label),
  `WHY` (deterministic reason), `BLOCKER` (machine code), `NEXT STEP`
  (exactly one), and `STATUS` (current_status). A short note
  reiterates that this is a read-only decision layer.

## 14. Tests (`tests/test_opportunity_action_queue.py`)

**82 tests, all OK (~2.0 s)**:

- **Schema** (10 tests): deterministic action id; action id differs
  from opportunity id; minimal model; malformed field rejection;
  forced `rule_version` + `research_only`; payout-field rejection;
  target/execution-field rejection; no forbidden model fields;
  extra-field rejection.
- **Action precedence** (8 tests): every rule including
  active-session-overrides-everything; every action code reachable;
  default DEFER.
- **Status derivation** (5 tests): IN_PROGRESS / COMPLETED / BLOCKED
  / DEFERRED / READY.
- **Blocker translation** (5 tests): known codes translated; machine
  code preserved; unknown codes kept with conservative fallback;
  deduplication; empty input.
- **Next step** (3 tests): exact steps per action; unknown action
  falls back to DEFER; **no exploit / target / shell language**.
- **Composition** (10 tests): deterministic; dell real-corpus
  (`BLOCKED` + `VERIFY_ASSET_MATCH`); active session triggers
  `CONTINUE_RESEARCH`; terminal outcome triggers `REVIEW_OUTCOME`;
  LOW_CONFIDENCE class triggers `GATHER_EVIDENCE`; HIGH_VALUE triggers
  `START_RESEARCH`; blockers preserved; **no-history does not change
  money**; malformed lead handled gracefully; missing opportunity
  class defaults to DEFER.
- **Ranking** (3 tests): deterministic; status-first ordering;
  money-within-status ordering.
- **Summary** (3 tests): counts and top fields; top lead/program;
  empty summary.
- **Backend** (9 tests): real-corpus projection; `BLOCKED +
  VERIFY_ASSET_MATCH` for both leads; summary keys; filters
  (`class`, `status`, `cve`, `program`); limit/offset preserves
  ranking; **Money Score unchanged**; **no payout/target fields**;
  invalid lead id and unknown lead id both 404.
- **CLI** (6 tests): action-list (human + JSON + filter); action-show
  (human + errors); action-summary (human + JSON).
- **API** (8 tests): list, summary, detail; filters; 404; **no write
  endpoints** (POST/PUT/PATCH/DELETE → 401/405); no payout vocabulary;
  `research_only` and `rule_version` present.
- **UI** (3 tests): leads column renders `Next action` + `VERIFY
  ASSET`; lead-detail panel renders `Next action`, `NEXT STEP`,
  `BLOCKER`, action code, next-step text; panel contains only
  read-only vocabulary.
- **Safety** (8 tests): no execution tokens in new files
  (`subprocess`, `socket`, `requests`, `httpx`, `openai`, `anthropic`,
  `ai.llm`, `nuclei.`, `Popen`, `selenium`, `playwright`,
  `os.system`, `urlopen`); engine purity; ranking purity; summary
  purity; **Money Score constants unchanged** (R25.1 weights + rule
  version); **no duplicate score field**; calibration unchanged
  (`INSUFFICIENT_DATA` + `weights_unchanged=True`); every
  recommended_action in the closed enum.

## 15. Real corpus verification

No data was fabricated or written. Both real leads:

```
CVE-2026-1557 → dell / indeed
opportunity_class  BLOCKED
money_score        53 / P3_MEDIUM
confidence         HIGH
evidence           HIGH (R26.1 unchanged)
sessions           0 (none)
outcomes           0 (none)
calibration        INSUFFICIENT_DATA  (R25.6 unchanged)
money_score_field  unchanged (53, copied verbatim from R26.1)
─────────────────────────────────────────────────────────────────────
R26.2 action:
  action_id         oa-8796970d0b5db714 (deterministic; r26-2)
  opportunity_id    op-27deff4809384156 (R26.1)
  lead_id           rl-af7ecfba1a86fc83
  cve_id            CVE-2026-1557
  program           dell
  opportunity_class BLOCKED
  current_status    BLOCKED
  recommended_action VERIFY_ASSET_MATCH
  action_reason     Asset relationship to the vulnerability is unproven;
                    confirm the plugin/component is present before
                    investing research time.
  blockers          [only generic technology match,
                    affected plugin not observed,
                    asset component not observed,
                    asset version unknown]
  why_now           [PUBLIC_POC, EXPLOIT_AVAILABLE,
                    CRITICAL_PRIORITY, TECHNOLOGY_OBSERVED,
                    PRODUCT_MATCHED, HIGH_CONFIDENCE,
                    NO_TERMINAL_OUTCOME, NO_SESSION_HISTORY]
  next_step         Confirm affected component/plugin presence.
  research_only     true
  rule_version      r26-2
```

`indeed` lead produces the same `(BLOCKED, VERIFY_ASSET_MATCH,
Confirm affected component/plugin presence.)` triple. The summary
collapses to:

```
total=2  ready=0  blocked=2  in_progress=0  deferred=0  completed=0
top_action=VERIFY_ASSET_MATCH  top_lead=rl-af7ecfba1a86fc83
top_program=dell
```

`ai_data/research/{sessions,outcomes}` still do not exist; no rows were
written; calibration still reports `INSUFFICIENT_DATA` and
`weights_unchanged=True`.

## 16. Safety audit

- **research_only = true** on every model, every backend projection,
  every API response, every CLI projection, every UI render.
- **No network / DNS / subprocess / LLM / Nuclei / browser / PoC /
  target interaction / findings / alerts**: static executable-token
  scan on all three new modules (see test
  `test_no_execution_tokens`).
- **No payout/bounty prediction**: no payout fields or vocabulary;
  every schema token, API response, CLI projection and UI render is
  asserted clean.
- **No automatic tuning / no Money Score modification**: the engine
  copies `money_score` from R26.1; `MONEY_W_*` constants and
  `RULE_VERSION = "r25-1"` asserted unchanged; no r25-2.
- **r25-1 preserved**; **r26-1 preserved** (no changes to
  `ai/schemas/research_opportunity.py`, `ai/knowledge/opportunity.py`,
  `backend/research_opportunities.py`).
- **No new persistence**: every backend helper composes existing R26.1
  / R25.5 / R25.7 data and is read-only; no `open(..., O_APPEND)`,
  no `fsync`, no Mongo `insert_one`, no `update_one`, no `save()`, no
  `put()`.
- No R15–R25 formula/lifecycle changes; no MongoDB; no systemd/.env;
  no git add/commit/push.

## 17. Limitations

- **Presentation layer only**: status/action/ranking are deterministic
  heuristics over existing signals; they are not new evidence and
  cannot confirm a vulnerability.
- **Active session detection** accepts both the R25.7 vocabulary
  (`PLANNED`/`IN_PROGRESS`) and the R26.1 fold status (`ACTIVE`); a
  later stage may want to consolidate vocabulary. Either way no
  scoring change is implied.
- **`UNKNOWN` blocker codes** are surfaced verbatim with a conservative
  "Investigate the unknown blocker code." explanation; we never invent
  a domain-specific translation for an unseen code.
- **`CONTINUE_RESEARCH` after REVIEW_OUTCOME**: precedence rule 3
  guards against this — `REVIEW_OUTCOME` is only emitted when there is
  no active session. A future stage can re-introduce
  `REVIEW_OUTCOME`+`START_RESEARCH` if researcher semantics evolve.
- **Queue ordering is a total order over the listed keys**; adding
  future signals would require an explicit, reviewed stage (not
  automatic).
- **Empty/absent data are explicit** (`NONE`), never inferred or
  penalized.
- **Real corpus still produces 0 sessions / 0 outcomes**; the queue
  therefore surfaces `BLOCKED` + `VERIFY_ASSET_MATCH` for both leads.
  When the first research session / outcome is recorded, the queue
  re-derives automatically (no migration needed).

## 18. Exact next-stage recommendation

**R26.3 — Opportunity Daily-Diff Snapshot (read-only).**

1. Build a deterministic, versioned, OFFLINE-only daily snapshot of
   the action queue (status × lead × action × money × evidence) and
   render a Markdown "what changed" report in `agent-reports/` without
   any new persistence path or background worker.
2. Keep the snapshot in memory / tmp only; never persist to Mongo or
   to a new file under `ai_data/`. Researchers should be able to diff
   `today` vs. `yesterday` via the CLI / API / UI without any side
   effect.
3. If persistence is later approved, require an append-only store
   following the R25.5 / R25.7 pattern (deterministic ids, no
   update-in-place) and gate it behind an explicit, reviewed
   `r26-snapshot-1`; never feed it back into the Money Score.
4. Preserve all current boundaries: research-only, no execution /
   targets / payouts, no LLM / network / Mongo, no automatic tuning,
   r25-1 unchanged, r26-1 unchanged, r26-2 unchanged.

## Agent / Model
- Model: Miuz Spark (opencode-go/deepseek-v4.1-flash)
- Stage: R26.2
- Role: Opportunity Action Queue