# Stage R25.7 — Research Execution Economics

## Status
**IMPLEMENTED (time-accounting only).** The R25 Money Queue and R25.5 outcome
capture are now connected to the existing research workflow through an
append-only **research session** model. The system measures the economic
efficiency of research decisions (planned vs actual time, session lifecycle,
optional outcome linkage) and performs **no security testing of any kind**.

No Money Score formula change, no r25-2, no R15–R24 change, no LLM, no
network, no Nuclei/browser/PoC, no findings/alerts, no payout prediction, no
automatic tuning, no systemd/.env changes, no commit/push.

## 1. Implementation summary

```
explicit researcher action
        │
        ├── UI "Start research session" ──┐
        ├── CLI `economics session start` ─┼─► backend/research_sessions
        └── API POST /economics/sessions ──┘        │
                                                     ▼
                        ai/schemas/research_session.py (validated event + view)
                                                     │
                                                     ▼
                ai/knowledge/research_sessions.py (append-only JSONL event log)
                                                     │
                                                     ▼
   create/start/complete/abandon · get/list · summarize_session
   lead_execution_performance = R25.2 + R25.5 + R25.7 (read-only)
                                                     │
                                                     ▼
                CLI / key-gated API / lead-detail UI
```

- Sessions are **never** auto-created or auto-started because a lead exists:
  every session begins with an explicit human action.
- Starting a session records metadata only. No scanning, probing, target
  contact, Nuclei, browser, PoC, or validation exists or is authorized.
- Outcome linkage is optional and explicit; outcomes are never created or
  inferred automatically.

## 2. Schema (`ai/schemas/research_session.py`)

Persisted form: `ResearchSessionEvent` (immutable lifecycle event).
Derived view: `ResearchSession` (deterministic fold).

View fields: `session_id, lead_id, cve_id, program, status, created_at,
started_at, ended_at, outcome_id, planned_minutes, actual_minutes, notes,
rule_version, research_only` + derived `variance_minutes`,
`efficiency_ratio` (via `to_view()`).

- statuses: `PLANNED / IN_PROGRESS / COMPLETED / ABANDONED`
- event types: `CREATED / STARTED / COMPLETED / ABANDONED`
- `rule_version` fixed `r25-1`; `research_only` forced `true`
- identifiers validated: `rs-…` session, `re-…` event, `rl-…` lead,
  `ro-…` outcome, CVE/program shapes
- timestamps must be parseable ISO-8601; minutes are 0..100000 integers;
  notes whitespace-normalized and ≤ 2000 chars
- `extra="forbid"`: no target URL, IP/domain, credential, execution, payout
  or verdict fields exist or can be injected (tests enumerate them)

## 3. Lifecycle (`backend/research_sessions.py`)

```
create_session  → PLANNED
start_session   → IN_PROGRESS
complete_session→ COMPLETED   (requires IN_PROGRESS; optional outcome link)
abandon_session → ABANDONED   (allowed from PLANNED or IN_PROGRESS)
```

- Transitions are enforced by `ALLOWED_SESSION_TRANSITIONS`; invalid
  transitions raise `SessionValidationError` (API 400).
- `create` is idempotent (content-addressed id); `start` is idempotent while
  IN_PROGRESS; `complete`/`abandon` are idempotent once terminal.
- `begin_session()` is the explicit CLI/UI convenience that creates **and**
  starts in one human action; `create_session` itself never appends STARTED
  (asserted by test).
- Lead attribution is resolved through the existing R21 `get_lead`; unknown
  leads are rejected.

## 4. Storage (`ai/knowledge/research_sessions.py`)

- One JSONL event log `ai_data/research/sessions/sessions.jsonl`.
- Atomic single-line appends (`O_APPEND` + `os.fsync`) under an exclusive
  `fcntl.flock` (`.sessions.lock`); concurrent writers never interleave.
- **Append-only / no deletion / no update-in-place**: every lifecycle
  transition is a new immutable line; the view is a fold.
- Malformed lines are skipped and counted (`malformed`) — fail-soft reads.
- Deterministic ids: `session_id = rs-<sha16(rule, lead, planned, note)>`,
  `event_id = re-<sha16(rule, session, type, ts, actual, outcome, note)>`.
- No Mongo, no network, no subprocess, no LLM.

## 5. Time accounting

- `planned_minutes` set at creation (immutable).
- `actual_minutes` at completion/abandon: explicit value **or** derived from
  `started_at → ended_at` (whole minutes, half-up). Negative/inconsistent
  explicit values and negative derived durations are rejected.
- No background timer, no machine monitoring — the clock is only ever an
  explicit timestamp.
- Exposed: `variance_minutes = actual - planned` (may be negative),
  `efficiency_ratio = planned / actual` (only when actual > 0, else `None`).
- `time_to_outcome` (per completed session): elapsed minutes from session
  `ended_at` to the linked terminal R25.5 outcome's `timestamp`; `None` when
  no link, non-terminal, unparseable, or negative. Wall-clock only; no
  causality claim.

## 6. Economic lead performance (§5 view)

`lead_execution_performance(lead_id)` composes R25.2 + R25.5 + R25.7 without
modifying any formula:

```
lead_id, cve_id, program, money_score, priority, confidence,
planned_time, actual_time, total_sessions, completed_sessions,
abandoned_sessions, accepted, duplicate, rejected, wasted_time,
acceptance_rate, wasted_rate, average_actual_minutes,
estimated_vs_actual_delta, time_to_outcome, time_to_outcome_samples,
in_progress_sessions, rule_version, research_only
```

Money Score is read from the existing R25.2 projection; outcomes from R25.5;
time from R25.7. No score adjustment occurs anywhere.

## 7. CLI

```
python -m ai.research_cli economics session start    --lead-id rl-... [--planned-minutes N] [--note ...] [--json]
python -m ai.research_cli economics session complete --session-id rs-... [--actual-minutes N] [--outcome-id ro-...] [--note ...] [--json]
python -m ai.research_cli economics session abandon  --session-id rs-... [--actual-minutes N] [--note ...] [--json]
python -m ai.research_cli economics session list     [--lead-id --cve --program --status --limit --offset --json]
python -m ai.research_cli economics session show     --session-id rs-... [--json]
python -m ai.research_cli economics session summary  --lead-id rl-... [--json]
```

Observed current output:

```
$ python3 -m ai.research_cli economics session list
RESEARCH SESSIONS: none recorded

$ python3 -m ai.research_cli economics session summary --lead-id rl-af7ecfba1a86fc83
Money Score:       53 (P3_MEDIUM)
Sessions:          0 (completed=0, abandoned=0)
Planned time:      0 min
Actual time:       0 min
Est/actual delta:  0 min
```

Unknown flags (`--payout`, `--target`, `--execute`, `--nuclei`) exit 2; no
payout/target/execution options exist.

## 8. API

Key-gated (`verify_api_key`), all declared before
`/api/research/economics/{lead_id}` so literal paths are not captured:

| Route | Behavior |
|---|---|
| `POST /api/research/economics/sessions` | create PLANNED (idempotent, 201) |
| `POST .../sessions/{session_id}/start` | explicit start |
| `POST .../sessions/{session_id}/complete` | complete + optional outcome link |
| `POST .../sessions/{session_id}/abandon` | abandon |
| `GET .../sessions` | bounded list with filters |
| `GET .../sessions/{session_id}` | one session |
| `GET .../sessions/summary?lead_id=` | R25.2+R25.5+R25.7 performance view |

Validation: `extra="forbid"` bodies (unknown/target/payout fields → 422),
unknown lead → 400, unknown session → 404, invalid transitions → 400,
`limit` bounded 1..100. No route executes research, starts workers, or
contacts external services.

## 9. UI

Minimal addition to the existing lead detail page — a `Research session`
panel (no new page, no dashboard redesign):

```
Money Score: 53
Planned:     N min
Sessions:    N
Actual:      N min
```

- Zero/terminal state: a `Start research session` form (planned minutes +
  note) — explicit human action.
- Active session: `Complete session` form (actual minutes, optional outcome
  id, note) and `Abandon session` form (optional actual minutes, reason).
- Copy states it is time accounting only: no security testing is performed
  or authorized. No scan/exploit/verify/run-nuclei controls exist.

## 10. Tests

New `tests/test_research_sessions.py` — **66 tests, all OK** (~2.7 s):

- schema: all statuses/event types, invalid status, malformed ids, minute
  bounds, note bounds/normalization, timestamp validation, unknown-field and
  forbidden-field rejection, fixed rule version, `research_only`, derived
  variance/efficiency.
- ids: deterministic session/event ids, distinctness.
- store: append + fold, full lifecycle fold, duplicate event idempotency,
  append-only line counts, out-of-order duplicate tolerance, malformed-line
  skip, unknown/malformed get, filters/limit/order, no writes on reads.
- lifecycle: create→PLANNED and **not auto-started**, idempotent create,
  start/complete, complete requires IN_PROGRESS, complete-after-abandon
  rejected, complete idempotent, abandon from both states, start idempotent,
  `begin_session`, unknown lead, negative minutes.
- time: derived minutes from timestamps, zero duration (`efficiency None`),
  negative derived duration rejected, summary time fields.
- outcome linking: same-lead link + `time_to_outcome`, wrong-lead rejected,
  unknown outcome rejected, **no automatic outcome creation**, non-terminal
  outcome → no time-to-outcome.
- performance view: exact field list, composition, rates, delta, unknown
  lead; Money Score unchanged by sessions.
- API: auth, full lifecycle, abandon route, validation/422/400/404, filters,
  Money unchanged.
- CLI: start/complete/show/list/summary JSON + human, abandon, errors,
  payout/target/execute/nuclei flags rejected.
- UI: zero state, active state + completion redirect, abandon, invalid
  completion error page, session panel vocabulary scan.
- real corpus: zero sessions/outcomes, Money 53/53, calibration
  INSUFFICIENT_DATA, no files written.
- safety: executable-token scan, `create_session` contains no STARTED,
  formula constants unchanged, no forbidden model fields.

Regression run (all OK): R25.2 91, R25.3 33, R25.4 21, R25.5 64, R25.6 48
(combined 257 OK) plus R21/R22 logic classes 54 OK. `git diff --check` clean.

## 11. Real corpus verification

No session or outcome was created; `ai_data/research/sessions/` and
`ai_data/research/outcomes/` do not exist.

- `CVE-2026-1557 → dell` and `→ indeed`: sessions = **0**, actual time = 0.
- R25.5 outcomes = **0**.
- Money Score = **53 / P3_MEDIUM** (both), unchanged.
- Calibration = **INSUFFICIENT_DATA**, weights **UNCHANGED**.
- `economics session list` → `RESEARCH SESSIONS: none recorded`.

## 12. Safety audit

- **No network / DNS / LLM / subprocess / browser / Nuclei / PoC / findings /
  alerts**: static executable-token scans on all three new modules; storage
  is local JSONL only; API routes only call the lifecycle/summary functions.
- **No target interaction and no target fields**: schema forbids unknown
  fields and contains no URL/IP/domain/credential columns.
- **No automatic start**: create never appends STARTED (source test);
  every session needs an explicit UI/CLI/API action.
- **No automatic outcome creation or inference**: linking verifies an
  existing same-lead R25.5 outcome; outcomes are never created by the
  session layer.
- **No score adjustment**: formulas untouched (`MONEY_W_*` constants and
  `RULE_VERSION = "r25-1"` asserted); `build_economics()` is identical before
  and after session lifecycle operations.
- **r25-1 preserved; no r25-2.**
- **research_only = true** on every schema/view/API response.
- No R15–R24 changes; no Mongo; no systemd/.env; no git add/commit/push.

## 13. Limitations

- **Content-addressed session ids**: an identical create submission collapses
  to one session. Additional sessions for the same lead must differ in
  planned minutes or note. Re-issuing `session start` after completion
  returns the completed session (idempotent) rather than creating a new one.
- **Completion requires IN_PROGRESS**; create→complete without a start is
  rejected by design. Abandon works from PLANNED or IN_PROGRESS.
- **Derived actual minutes** are whole minutes with half-up rounding from
  explicit ISO timestamps; no continuous monitoring or background timers
  exist by design.
- **`time_to_outcome`** measures wall-clock elapsed time from session end to
  the linked outcome timestamp; it is not causal and is omitted when
  negative/unparseable/non-terminal.
- **Self-reported data**: sessions and outcomes are researcher entries;
  `average_actual_minutes` aggregates sessions with recorded time (>0).
- **Bounded lists**: list endpoints cap at 100; summaries read the full
  event log (accurate but O(file)).
- The session layer deliberately has no editing/deletion; corrections are new
  sessions or (for outcomes) new outcome records.

## 14. Exact next-stage recommendation

**R25.8 — Session-Aware Efficiency Calibration (read-only design + report).**

1. Extend the R25.6 calibration audit with session-derived efficiency
   metrics per Money Score band: planned vs actual time, completion/abandon
   rates, and time-to-outcome when linked — still **no weight changes** and
   no automatic tuning.
2. Keep the R25.6 minimum-sample rule; sessions alone do not justify
   recalibration, and `r25-1` remains authoritative until an explicit,
   reviewed `r25-2` is approved.
3. Optionally add a small convenience so a completed session can prefill the
   R25.5 outcome form with its session id — the outcome still must be
   recorded explicitly by the researcher (never automatic).
4. Preserve all boundaries: research-only, no execution/targets/payouts, no
   LLM, no MongoDB, no background workers/timers.

## Agent / Model
- Model: Miuz Spark (opencode-go/deepseek-v4.1-flash)
- Stage: R25.7
- Role: Research Execution Economics
