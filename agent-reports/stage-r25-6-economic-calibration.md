# Stage R25.6 — Outcome-Calibrated Money Score

## Status
**IMPLEMENTED (offline, read-only calibration audit).** The R25.5 outcome
records are now joined to the R25 Money Score projections and evaluated
deterministically. The calibration only *reports* whether the r25-1 ordering
appears economically useful against observed research outcomes.

**No Money Score weight was changed.** `RULE_VERSION = "r25-1"` is preserved,
and the report carries `weights_unchanged: true` plus the statement
"Money Score weights were not changed." No automatic tuning exists.

No R15–R24 change, no LLM, no network, no execution, no Nuclei/browser, no
findings/alerts, no payout prediction, no systemd/.env changes, no fabricated
outcomes, no commit/push.

## 1. Architecture

```
R25.2 economic engine (r25-1, untouched)
        │  build_economics()
        ▼
R25 projections ────────────────┐
                                ├──► backend/research_calibration.build_report()   (read-only)
R25.5 outcomes ─────────────────┘            │
   lead_performance()                        ▼
                              ai/knowledge/economic_calibration.py  (pure, offline)
                                build_calibration_dataset()
                                calculate_band_statistics()
                                calculate_global_statistics()
                                assess_score_ordering()
                                build_calibration_report()
                                             │
                       ┌─────────────────────┼──────────────────────┐
                       ▼                     ▼                      ▼
             CLI `economics calibration`  GET API  /economics/calibration  leads-page strip
```

- `ai/knowledge/economic_calibration.py` — pure deterministic engine. No
  clock, no randomness (the caller supplies `generated_at`), no I/O, no
  imports of execution/LLM/network modules.
- `backend/research_calibration.py` — thin read-only composition: gathers
  projections and per-lead performances, applies cve/program filters and calls
  the engine. No scoring logic.
- `backend/research_outcomes.lead_performance()` is the outcome source of
  truth, exactly as required.

## 2. Calibration dataset

`build_calibration_dataset(projections, performances)` joins by `lead_id`
and returns deterministic rows (money DESC, CVE ASC, program ASC, lead_id
ASC):

`lead_id, cve_id, program, money_score, priority, band, confidence,
confidence_score, value, effort, risk, attempts, terminal_outcomes,
in_progress, accepted, duplicate, rejected, not_applicable, wasted_time,
total_time_spent_minutes, average_time_spent_minutes, acceptance_rate,
duplicate_rate, wasted_rate, data_quality, outcome_confidence`

A missing performance row yields explicit zeros (`data_quality: NONE`) —
counts are never fabricated. No payout amount is read, joined, or emitted.

## 3. Score-band methodology

Deterministic bands, highest first (inclusive bounds):

| Band | Range |
|---|---|
| P1 | 85–100 |
| P2 | 65–84 |
| P3 | 45–64 |
| P4 | 30–44 |
| P5 | 0–29 |

Scores are clamped to `[0, 100]` before banding. Only **populated** bands
(bands containing at least one lead) are returned; empty bands are never
invented and never justify a conclusion. Per populated band:

`leads, attempts, terminal_outcomes, in_progress, accepted, duplicate,
rejected, not_applicable, wasted_time, acceptance_rate, duplicate_rate,
wasted_rate, negative_rate, total_time_spent_minutes,
average_time_spent_minutes, sample_status`, plus the R25.6 §4 aliases
`observed_acceptance_rate, observed_waste_rate, observed_duplicate_rate,
observed_negative_rate, observed_average_time`.

Rates use **terminal outcomes as the denominator**; `IN_PROGRESS` is excluded
from terminal statistics. Band/global `average_time_spent_minutes` uses
terminal-only time (reconstructed from the per-lead terminal average), while
`total_time_spent_minutes` includes all recorded time.

Global statistics carry the same metrics across the whole dataset.

## 4. Minimum sample rule

`DEFAULT_MIN_TERMINAL_OUTCOMES = 10` (configurable via `--min-samples` /
`min_samples` query parameter; values `< 1` are rejected):

- **SUFFICIENT_SAMPLE** — band terminal outcomes ≥ threshold
- **INSUFFICIENT_SAMPLE** — otherwise

The threshold is exposed in the report (`minimum_terminal_outcomes`) and on
every band. An insufficient band can never drive a recommendation.

## 5. Recommendation logic (deterministic, conservative)

| State | Rule |
|---|---|
| `NO_DATA` | no populated bands (no calibration leads) |
| `INSUFFICIENT_DATA` | populated bands but 0 terminal outcomes; or fewer than 2 bands with `SUFFICIENT_SAMPLE` |
| `CONSISTENT` | ≥2 sufficient bands and, comparing adjacent bands high→low, every higher band has equal-or-better acceptance **and** equal-or-lower wasted rate |
| `POSSIBLE_MISORDERING` | ≥2 sufficient bands and every higher band is strictly worse on **both** acceptance and wasted rate |
| `REVIEW_REQUIRED` | ≥2 sufficient bands but mixed evidence |

The signal is built only from observed research outcomes: positive =
`ACCEPTED`; negative = `DUPLICATE` + `REJECTED` + `NOT_APPLICABLE` +
`WASTED_TIME`. No bounty/payout value is used. No statistical significance is
claimed (documented in `limitations`). Recommendations never mutate weights.

## 6. CLI

```
python -m ai.research_cli economics calibration
python -m ai.research_cli economics calibration --json
python -m ai.research_cli economics calibration --min-samples 25
python -m ai.research_cli economics calibration --cve CVE-2026-1557 --program dell
```

Observed current output:

```
ECONOMIC CALIBRATION

Rule: r25-1
Minimum sample: 10
Leads: 2
Terminal outcomes: 0

P1: no leads
P2: no leads
P3: leads=2 terminal=0 accept=0.00 duplicate=0.00 wasted=0.00 avg_time=0m [INSUFFICIENT_SAMPLE]
P4: no leads
P5: no leads

Recommendation: INSUFFICIENT_DATA
  - no terminal research outcomes recorded yet
Money Score weights: UNCHANGED
```

`--json` emits the full report. `--min-samples 0` and malformed `--cve`
exit 1 with an error on stderr.

## 7. API

- `GET /api/research/economics/calibration?min_samples=&cve=&program=`
  — key-gated (same `verify_api_key`), read-only, returns the full report:
  `rule_version: r25-1`, `current_money_score_rule: r25-1`,
  `research_only: true`, `weights_unchanged: true`,
  `minimum_terminal_outcomes`, dataset totals, `bands`,
  `global_statistics`, `recommendation`, `recommendation_reasons`,
  `limitations`, `generated_at` (metadata only).
- Declared before `/api/research/economics/{lead_id}` so `calibration` is not
  captured as a lead id.
- Bounded `min_samples` (`ge=1`), malformed CVE → 400.
- **No write endpoint exists** (POST → 405/401).

## 8. UI decision

UI was kept to the smallest useful strip because it fit the existing
architecture without complexity (no new page, no charts, no polling). The
existing Research Leads page now shows a compact read-only band:

```
ECONOMIC CALIBRATION   INSUFFICIENT_DATA
Rule r25-1 · Sample 0 terminal outcomes · Minimum 10 · Weights UNCHANGED
```

It is fail-soft: a calibration failure degrades to no strip, never breaks the
leads list. The lead detail page is unchanged from R25.5.

## 9. Tests

New `tests/test_research_economics_calibration.py` — **48 tests, all OK**
(~1.7 s):

- empty dataset → `NO_DATA`; zero-outcome corpus → `INSUFFICIENT_DATA`;
  single sufficient band → `INSUFFICIENT_DATA`; sufficient multiple bands →
  `CONSISTENT`; `POSSIBLE_MISORDERING`; `REVIEW_REQUIRED`; custom threshold.
- dataset join/zero-fill/ordering; all six R25.5 statuses counted;
  `IN_PROGRESS` excluded from terminal stats and rates; acceptance / duplicate
  / wasted / negative rates; average time; band boundaries 0–100; only
  populated bands; threshold exposure; determinism.
- report contract: keys, r25-1 preservation (`rule_version`,
  `current_money_score_rule` equals `economics.RULE_VERSION`),
  `weights_unchanged`, exact statement, no significance claim, no payout
  keys/fields, deterministic output.
- backend: real corpus zero-outcome report, filters, malformed CVE,
  `min_samples` validation, summary, read-only proof.
- API: auth, shape, filters, `min_samples`, 422 bounds, malformed CVE 400,
  route precedence, no write method, timestamp-insensitive determinism,
  Money Score unchanged after the call.
- CLI: human output, JSON, options, errors.
- UI: calibration strip text on the leads page.
- Safety: executable-token scan, no self-tuning/write tokens, formula
  constants unchanged, engine purity.

Regression run (all OK): `tests.test_research_economics` 91,
`tests.test_research_economics_projection` 33,
`tests.test_research_economics_api` 21, `tests.test_research_outcomes` 64
(combined 209 OK) plus the R21/R22 logic classes 54 OK. `git diff --check`
clean.

## 10. Real corpus verification

Real corpus used as-is; **no outcome was created** and no artifact was
modified (`ai_data/research/outcomes/` still does not exist).

- Leads: `CVE-2026-1557 → dell` and `CVE-2026-1557 → indeed`, Money Score
  `53 / P3_MEDIUM` (R25.3 output unchanged).
- R25.5 outcomes: `none recorded`.
- Calibration: `Leads: 2`, `Terminal outcomes: 0`,
  `Recommendation: INSUFFICIENT_DATA`, `Money Score weights: UNCHANGED`.
- The report contains no proposed weights and `bands` contains only the
  populated P3 band (INSUFFICIENT_SAMPLE).

## 11. Safety audit

- **No network / DNS / LLM / subprocess / browser / Nuclei / execution**:
  the engine is pure; both new modules pass executable-token scans; the API
  route has no write method and calls only the read-only composition.
- **No payout prediction**: no payout/bounty/reward fields or values; rates
  are only observed outcome counts.
- **No automatic self-tuning**: the engine contains no weight symbols, no
  assignment/write paths; `weights_unchanged` is asserted.
- **No R15–R24 modifications**; `ai/knowledge/economics.py` untouched.
- **No R25.2 formula changes**: `MONEY_W_VALUE = 0.55`,
  `MONEY_W_CONFIDENCE = 0.15`, `MONEY_W_EFFORT_EFF = 0.15`,
  `MONEY_W_RISK_AVOID = 0.15`, `RULE_VERSION = "r25-1"` asserted unchanged.
- **r25-1 preserved**: report `rule_version == current_money_score_rule ==
  "r25-1"`; a future formula must be an explicit `r25-2` with r25-1
  reproducibility kept.
- **research_only = true** on every report/API response.
- Reads only: no writes/persistence/Mongo; `git diff --check` clean; no
  git add/commit/push.

## 12. Limitations

- **No statistical significance test.** The recommendation is a descriptive
  policy over observed rates, not an inference; small samples are treated as
  insufficient by construction.
- **Zero current signal.** With 0 terminal outcomes the audit can only say
  `INSUFFICIENT_DATA`; no ordering conclusion is possible.
- **Observational/self-reported outcomes.** R25.5 records are researcher
  entries; identical submissions collapse into one content-addressed record.
- **Acceptance/waste only.** Calibration ignores effort/duplicate-value
  trade-offs beyond the explicit rates; no payout or impact weighting.
- **Band granularity.** Comparisons only between populated bands with
  sufficient samples; empty bands are silent.
- **`generated_at` metadata** is the only clock-derived field; ordering and
  calculations are deterministic.
- **No automatic remediation.** Even `POSSIBLE_MISORDERING` only requests
  human review; nothing is tuned by this stage.

## 13. Exact next-stage recommendation

**R25.7 — Outcome Accrual + Human-Reviewed Calibration Decision (no formula
change by default).**

1. Keep capturing outcomes (R25.5) with no scoring feedback until at least
   two bands each reach `MIN_TERMINAL_OUTCOMES = 10` terminal outcomes.
2. Re-run `economics calibration`; if `POSSIBLE_MISORDERING` or
   `REVIEW_REQUIRED` appears, produce a written calibration review with the
   band table, sample sizes and explicit limitations — not a weight change.
3. Only if a change is justified, create `r25-2` as a separate, reviewed
   stage that keeps the r25-1 formula reproducible and re-evaluates both
   rules side by side.
4. Optional later hardening: add a proper interval/association test (e.g.
   Wilson intervals or Fisher exact per adjacent band pair) as an additive
   read-only statistic; it must never auto-tune weights.
5. Preserve all current boundaries: pure/offline, no payouts, no execution,
   no LLM, research-only.

## Agent / Model
- Model: Miuz Spark (opencode-go/deepseek-v4.1-flash)
- Stage: R25.6
- Role: Outcome-Calibrated Money Score
