# Stage R27.1 — Researcher Value Loop / Product Validation

## Status
**IMPLEMENTED (audit/metrics layer) — PRODUCT DECISION: `COLLECT_MORE_DATA`.**

A deterministic, read-only product-validation layer now measures whether the
existing R25/R26 economic research workflow creates researcher value, using
only data already produced by those stages. No new score, no Money Score
change, no r25-2, no LLM/network/execution, no automatic calibration, no
snapshot persistence, no background workers, no systemd/.env changes, no
commit/push.

## 1. Product question

*"Does Watch help a researcher choose better research opportunities?"*

The layer answers with decomposable metrics + explicit hypothesis statuses
over existing data only: R25.2 Money Score, R25.5 outcomes, R25.7 sessions,
R26.1 opportunities, R26.2 actions, R26.3 daily workflow. No payout/reward
data is used or referenced as a value signal.

## 2. Metrics (all deterministic; every metric states its denominator)

**A. Actionability** — opportunities surfaced / actionable (READY+IN_PROGRESS)
/ ready / blocked / in-progress, each with denominator "all surfaced
opportunities".

**B. Follow-through** — sessions total, sessions started (denominator: all
session records), completed and abandoned (denominator: started sessions),
in-progress, outcome records created (denominator: leads with outcome data
available), plus explicit `session_data` / `outcome_data` coverage counts
(PRESENT / NONE / UNAVAILABLE).

**C. Conversion** — each as numerator/denominator/rate with denominator
label: `ready → session` (currently READY opportunities), `session →
completed` (started sessions), `completed → terminal outcome` (leads with a
completed session), `terminal → accepted` (leads with a terminal outcome).
NaN rates are `null`, never zero-filled.

**D. Time efficiency** — planned minutes, actual minutes, variance, average
actual minutes (denominator: sessions with recorded actual > 0), accepted
outcome time (denominator: ACCEPTED outcome records).

**E. Blocker resolution** — blocked leads (denominator: leads), blocked →
session and blocked → outcome (denominator: currently BLOCKED leads), and
blocked → READY (only when the caller supplies a previous workflow status
map; otherwise `null` with an explicit "snapshots are external" note).

## 3. Hypotheses (never reported as proven)

| ID | Hypothesis | Metric / comparison |
|---|---|---|
| H1 | Higher Money Score opportunities receive more research attention | avg money with attention vs without; `>` |
| H2 | READY converts to sessions more often than BLOCKED | ready-session rate vs blocked-session rate; `>` |
| H3 | Stronger evidence requires less wasted time | wasted rate strong vs weak evidence; `<` |
| H4 | Recommendations reduce research on blocked leads | blocked share of sessions vs blocked share of leads; `<` |
| H5 | Accepted outcomes concentrate in high-confidence/high-value leads | acceptance rate high-value vs other; `>` |

Closed statuses: `UNTESTABLE`, `INSUFFICIENT_DATA`, `DIRECTIONAL_SIGNAL`,
`SUPPORTED` (no "PROVEN"). Each result carries hypothesis_id, status,
sample_size, required_sample, metric, observed_value, comparison, reason and
limitations. `SUPPORTED` means the predefined thresholds and direction were
met — explicitly not statistical significance (no statistical test is
implemented).

## 4. Sample requirements

Defaults: `MIN_SESSIONS = 20`, `MIN_TERMINAL_OUTCOMES = 20`,
`MIN_LEADS = 10`; configurable via CLI/API (`min_sessions`, `min_outcomes`,
`min_leads`). A hard floor of 1 is applied internally so degenerate zero
thresholds cannot declare "CONTINUE_PRODUCTIZATION" on zero samples.

## 5. Methodology

- **Data join by `lead_id` only** (session_id/outcome_id preserved within the
  lead's records); no relationship is fabricated.
- **Missing data is explicit**: per-lead `session_data` / `outcome_data`
  status is PRESENT / NONE / UNAVAILABLE; UNAVAILABLE never silently becomes
  zero. Opportunity coverage is reported separately.
- **Cross-sectional joins**: without persisted snapshots, conversion and
  blocker metrics describe current-state association, not longitudinal
  funnels; blocked→READY requires a caller-supplied previous workflow.
- **No causality**: the report says "observed association"; correlation is not
  causation.
- **No new numeric score**: the output stays decomposable; the product
  decision is a closed status, not a number.
- **Product decision rules**: no leads → `RETHINK_WORKFLOW`; any threshold
  shortfall → `COLLECT_MORE_DATA`; all thresholds met → `CONTINUE_PRODUCTIZATION`.

Files: `ai/knowledge/product_validation.py` (pure engine),
`backend/product_validation.py` (composition), CLI `product validation`, API
`GET /api/research/product-validation`, compact UI indicator.

## 6. Current corpus results

No data was fabricated or written.

```
WATCH PRODUCT VALIDATION

Leads: 2
Sessions: 0
Terminal outcomes: 0

ACTIONABILITY
Ready: 0
Blocked: 2
In progress: 0

FOLLOW-THROUGH
Sessions started: 0
Sessions completed: 0
Sessions abandoned: 0
Outcome records: 0

CONVERSION    ready→session n/a, session→completed n/a,
              completed→terminal n/a, terminal→accepted n/a
TIME          Planned 0 min, Actual 0 min, Variance 0 min,
              Average actual n/a, Accepted outcome time n/a
BLOCKERS      Blocked leads 2, Blocked→session 0.0, Blocked→outcome 0.0,
              Blocked→ready n/a (no previous workflow supplied)

HYPOTHESES
H1  INSUFFICIENT_DATA  (sample 0/20)
H2  INSUFFICIENT_DATA  (sample 0/20)
H3  INSUFFICIENT_DATA  (sample 0/20)
H4  INSUFFICIENT_DATA  (sample 0/20)
H5  INSUFFICIENT_DATA  (sample 0/20)

No product hypothesis is currently supported.

PRODUCT DECISION: COLLECT_MORE_DATA
insufficient real research activity: 0/20 started sessions,
0/20 terminal outcomes, 2/10 leads
```

Money Score remains `53 / P3_MEDIUM`, opportunities remain `BLOCKED`,
actions remain `VERIFY_ASSET_MATCH`, calibration remains `INSUFFICIENT_DATA`,
and `ai_data/research/{sessions,outcomes,snapshots}` do not exist. No claim of
product success is made.

## 7. Tests

New `tests/test_product_validation.py` — **47 tests, all OK** (~2.7 s):

- dataset joins by lead, malformed items skipped, explicit missing data,
  deterministic order; actionability counts/denominators/empty;
  follow-through counts, PLANNED-not-started; conversion rates and
  zero-denominator `null`; time totals/averages/empty; blocker metrics and
  blocked→READY requiring a previous workflow.
- hypotheses: empty → all UNTESTABLE; real zero-data → all
  INSUFFICIENT_DATA; a crafted 6-lead fixture → all five SUPPORTED; small
  groups → DIRECTIONAL_SIGNAL; raised thresholds → INSUFFICIENT_DATA; result
  shape/closed statuses (no PROVEN).
- report: empty → RETHINK_WORKFLOW, real corpus shape, degenerate-zero
  thresholds cannot bypass the floor, deterministic, no new score keys.
- backend: real corpus, filters, summary, determinism, no persistence,
  Money Score unchanged.
- CLI: human output (all statuses + no-claim line + decision), JSON,
  filters/thresholds, payout/execution flags rejected.
- API: auth, shape/version/research_only, filters/thresholds, 422 bounds,
  no write endpoint, no payout keys.
- UI: compact indicator (`PRODUCT VALIDATION`, `Data: INSUFFICIENT`,
  decision), research-only tokens.
- safety: executable-token scan, no persistence tokens, engine purity,
  r25-1 / r26-1 / r26-2 / r26-3 constants unchanged.

Regression run (all OK): R25.2 91, R25.3 33, R25.4 21, R25.5 64, R25.6 48,
R25.7 66, R26.1 60, R26.2 82, R26.3 69, R27.1 47 (**581 OK**) plus R21/R22
logic classes 54 OK. `git diff --check` clean.

## 8. Product decision

**`COLLECT_MORE_DATA`** — deterministic rule: with `0/20` started sessions,
`0/20` terminal outcomes and `2/10` leads, thresholds are not met. Watch has
**not** demonstrated economic/researcher value yet; the honest next step is
to run real research sessions and record real outcomes, then re-run this
validation with sufficient samples.

## 9. Limitations

- **No statistical test**: SUPPORTED is a predefined product check, not
  significance; no p-values or confidence intervals exist yet.
- **Cross-sectional joins**: longitudinal funnels (e.g. blocked→READY) need
  caller-supplied history because snapshots are deliberately not persisted.
- **Self-reported data**: sessions/outcomes are researcher entries; nothing
  is verified or enriched here.
- **No payout/reward consideration**: value is measured as research
  attention, conversion and time only.
- **Small samples**: INSUFFICIENT_DATA/UNTESTABLE outcomes are never
  extrapolated; rates with zero denominators render as `null`, not 0.
- **UI indicator is intentionally minimal** (no percentages when sample size
  is insufficient).
- **Consolidation note**: the working tree contained a stale partial R27.1
  fragment (a duplicate `product` CLI parser/handler and a duplicate API
  route/helper expecting a different, non-existent engine signature). It
  caused an argparse `conflicting subparser: product` error and duplicated
  the API path; it was removed and replaced by the single spec-aligned
  implementation reported here. No other stage's logic was touched.

## 10. Exact next-stage recommendation

**R27.2 — Real Outcome Accrual (manual, ethical, no automation).**

1. Have the researcher act on the two current leads through the existing
   R25.7 session flow and R25.5 outcome capture (asset-match verification is
   the recorded next step; nothing is executed automatically).
2. Accumulate real sessions/outcomes until at least `MIN_SESSIONS=20` and
   `MIN_TERMINAL_OUTCOMES=20` across `MIN_LEADS=10` before drawing any
   product conclusion; re-run `product validation` unchanged.
3. Only after SUPPORTED signals appear, consider an explicit, reviewed
   calibration/productization stage; never auto-tune and never add r25-2
   without human approval.
4. Preserve all boundaries: research-only, no execution/targets/payouts, no
   LLM/network/Mongo, no snapshots/workers, r25-1 / r26-1 / r26-2 / r26-3
   unchanged.

## Agent / Model
- Model: Miuz Spark (opencode-go/deepseek-v4.1-flash)
- Stage: R27.1
- Role: Researcher Value Loop / Product Validation
