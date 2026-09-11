# Stage R26.1 — Economic Opportunity Intelligence

## Status
**IMPLEMENTED (read-only composition).** A deterministic Opportunity
Intelligence layer now composes the existing R18/R21/R22/R23/R24/R25.2/R25.5/
R25.7 signals into a researcher-oriented opportunity view that answers *"Why
is this research lead worth my time right now?"*

This is **not** a new scoring formula: the Money Score is copied verbatim and
never modified. No r25-2, no R15–R25 formula/lifecycle changes, no LLM, no
network, no Nuclei/browser/PoC, no target interaction, no findings/alerts, no
payout/bounty prediction, no automatic research/outcome creation, no
automatic score adjustment, no systemd/.env changes, no commit/push.

## 1. Architecture

```
R18 queue ─► R21 lead ─► R22 plan ─► R23/R24 evidence
                    │
                    ├─ R25.2 Money Score projection (verbatim)
                    ├─ R25.5 outcome performance (R25.7 compose)
                    └─ R25.7 session time summary
                              │
                              ▼
        backend/research_opportunities.py (read-only composition)
                              │
                              ▼
        ai/knowledge/opportunity.py (pure deterministic engine)
        build_opportunity / classify_opportunity / build_why_now /
        rank_opportunities / build_opportunity_summary
                              │
                              ▼
        ai/schemas/research_opportunity.py (extra="forbid" view)
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
       CLI `opportunity`  API /api/research/opportunities  leads + lead-detail UI
```

Fail-soft: malformed leads and leads without an R25.2 projection are skipped;
missing evidence/outcomes/sessions become explicit `NONE`; nothing is
fabricated.

## 2. Schema (`ai/schemas/research_opportunity.py`)

Fields: `opportunity_id, lead_id, cve_id, program, money_score,
money_priority, confidence, confidence_score, value_score, effort_score,
risk_score, asset_match, evidence_quality, research_status, outcome_status,
session_status, estimated_minutes, actual_minutes, time_delta_minutes,
efficiency_ratio, historical_time_status, accepted, duplicate, rejected,
wasted, acceptance_rate, wasted_rate, opportunity_class, recommended_action,
why_now, why_valuable, blockers, evidence_summary, rule_version,
research_only`.

- `opportunity_id = "op-" + sha256(rule_version + lead_id)[:16]`
  (deterministic; `rule_version = "r26-1"`).
- `extra="forbid"`; enums validated for class/action/confidence/evidence/
  session/historical-time; `rule_version` fixed `r26-1`; `research_only`
  forced `true`.
- No payout/bounty/reward/target-URL/IP/domain/credential/exploit-command/
  execution-command/production-finding fields exist or can be injected.

## 3. Classification rules (documented, conservative)

`classify_opportunity(money_score, confidence, blockers, evidence_present)`,
first match wins:

| Order | Class | Rule |
|---:|---|---|
| 1 | `BLOCKED` | `only generic technology match` **and** (`affected plugin not observed` or `asset component not observed`) — the asset relationship to the vulnerability is unproven |
| 2 | `HIGH_VALUE` | money ≥ 65 **and** confidence `HIGH` |
| 3 | `GOOD_OPPORTUNITY` | money ≥ 45 **and** confidence ≥ `MEDIUM` |
| 4 | `RESEARCH_FIRST` | money ≥ 30 **and** evidence exists (evidence_count or source_count > 0) |
| 5 | `LOW_CONFIDENCE` | confidence `LOW` |
| 6 | `DEFER` | otherwise |

The class is presentation/decision only and never replaces the Money Score.
`asset version unknown` alone does **not** block. Recommended actions:
`CONTINUE_SESSION` (active session) else `VERIFY_ASSET_MATCH` (BLOCKED),
`START_RESEARCH` (HIGH_VALUE/GOOD_OPPORTUNITY), `RESEARCH_WITH_EVIDENCE`
(RESEARCH_FIRST), `GATHER_EVIDENCE` (LOW_CONFIDENCE), `DEFER`.

## 4. Why-now logic

Only codes mapped directly to existing structured fields are emitted, in a
fixed order:

`PUBLIC_POC`, `EXPLOIT_AVAILABLE` (R21 reason codes), `CRITICAL_PRIORITY` /
`HIGH_PRIORITY` (R25.2 `P1_START_NOW`/`P2_HIGH` or R16
`CRITICAL_RESEARCH`/`HIGH_RESEARCH`), `TECHNOLOGY_OBSERVED`,
`COMPONENT_OBSERVED`, `PRODUCT_MATCHED` (R21 reason codes),
`HIGH_CONFIDENCE` (confidence HIGH), `LOW_RESEARCH_EFFORT` (effort score
1–45), `NO_TERMINAL_OUTCOME` (terminal outcomes = 0), `PREVIOUSLY_ACCEPTED`,
`PREVIOUSLY_DUPLICATED` (R25.5 counts), `HIGH_WASTE_RATE` (wasted_rate ≥ 0.5
with terminal outcomes), `ACTIVE_SESSION` (R25.7 IN_PROGRESS),
`NO_SESSION_HISTORY` (no sessions). No invented reasons.

## 5. Economic / time composition

- Money/sub-scores are copied verbatim from the R25.2 projection:
  `money_score, money_priority, confidence, confidence_score, value_score,
  effort_score, risk_score, asset_match, why_valuable`.
- `estimated_minutes` is a deterministic midpoint of the existing R25 effort
  band (≤25→20, ≤45→45, ≤65→90, ≤85→240, else 480) — presentation of an
  existing score, not a new one.
- With no sessions: `actual_minutes=0`, `efficiency_ratio=null`,
  `historical_time_status=NONE`, `time_delta_minutes=0`, and no penalty is
  applied to class/money. With history: `actual_minutes` from R25.7,
  `time_delta = actual - estimated`, `efficiency_ratio = planned/actual`.
- Outcomes (R25.5): `accepted, duplicate, rejected, wasted,
  acceptance_rate, wasted_rate, outcome_status` — exposed but **never** fed
  back into the Money Score.

## 6. Evidence composition

From R23 results and R24 loop artifacts only (no fetches):
`evidence_summary = {source_count, evidence_count, strongest_source_tier,
evidence_confidence, latest_research_status}`. `evidence_quality` mirrors
`evidence_confidence`; `research_status` mirrors the latest R23/R24 status.
Missing data is explicit `NONE`.

## 7. Ranking

Deterministic, no new numeric score:

1. opportunity class (`HIGH_VALUE` → `DEFER`)
2. Money Score descending
3. confidence descending
4. evidence quality descending
5. effort ascending
6. CVE ascending
7. program ascending
8. lead_id ascending

## 8. CLI

```
python -m ai.research_cli opportunity list [--limit --cve --program --json]
python -m ai.research_cli opportunity show --lead-id rl-... [--json]
python -m ai.research_cli opportunity summary [--json]
```

Observed current output:

```
OPPORTUNITY QUEUE

#1 BLOCKED
    CVE-2026-1557 → dell
    Money: 53 / P3_MEDIUM
    Confidence: HIGH
    Evidence: HIGH
    Effort: 90 min
    Action: VERIFY_ASSET_MATCH

    Why now:
      PUBLIC_POC
      EXPLOIT_AVAILABLE
      CRITICAL_PRIORITY
      TECHNOLOGY_OBSERVED
      PRODUCT_MATCHED
      HIGH_CONFIDENCE
      NO_TERMINAL_OUTCOME
      NO_SESSION_HISTORY

OPPORTUNITIES: 2
```

## 9. API

Key-gated, read-only, declared before `/api/research/{cve}`:

| Route | Behavior |
|---|---|
| `GET /api/research/opportunities` | ranked list (`limit/offset/cve/program`, bounded) |
| `GET /api/research/opportunities/summary` | class counts + top |
| `GET /api/research/opportunities/{lead_id}` | one opportunity; malformed/unknown → 404 |

No POST/PUT/DELETE (POST → 405/401). Responses carry `research_only: true`
and `rule_version: r26-1`; no payout vocabulary.

## 10. UI

Minimal, existing pages only, no charts/polling/redesign:

- Research Leads list: compact `Opportunity` column with class badges
  (`opp-blocked`, `opp-high-value`, `opp-good-opportunity`,
  `opp-low-confidence`, `opp-defer`); Money ordering from R25.4 is unchanged.
- Lead detail: `Opportunity intelligence` panel with Class, Recommended
  action, Evidence (quality + counts/tier/status), Historical outcome,
  Historical time, Why now, Why valuable, Blockers, and an explicit
  research-only note.

## 11. Tests

New `tests/test_research_opportunities.py` — **60 tests, all OK** (~3.1 s):

- schema: deterministic id, malformed-field rejection, forced rule/research
  flags, forbidden fields absent/rejected.
- estimated-minutes bands.
- classification: every class, BLOCKED precedence over HIGH_VALUE, the
  blocked-condition boundary, full class coverage.
- why-now: lead-reason mapping, fixed order, no invented reasons, outcome and
  session reasons, active-session reason.
- composition: no-history behavior, history composition, history does not
  change money/class, blockers, active-session action, why_valuable copied,
  all fields present.
- ranking: class order, money/confidence/effort tie-breaks, CVE/program/
  lead_id tie-breaks, summary.
- backend: real corpus, explicit missing history, filters/limit/offset,
  malformed candidates skipped, missing economic projection skipped,
  missing evidence/sessions/outcomes explicit, detail/summary errors,
  deterministic output, Money Score unchanged, no duplicate score fields.
- API: auth, list/detail/summary shape, filters, 404s, no write method, no
  payout vocabulary.
- CLI: human/JSON list, filters, show, errors, summary.
- UI: leads column, lead-detail panel, research-only vocabulary.
- safety: executable-token scan, engine purity, Money Score constants
  unchanged, calibration unchanged.

Regression run (all OK): R25.2 91, R25.3 33, R25.4 21, R25.5 64, R25.6 48,
R25.7 66, R26.1 60 (combined **383 OK**) plus R21/R22 logic classes 54 OK.
`git diff --check` clean.

## 12. Real corpus verification

No data was fabricated or written. Both leads:

```
CVE-2026-1557 → dell / indeed
opportunity_id  op-… (deterministic)
opportunity_class BLOCKED  (asset match unverified: generic tech + plugin/component not observed)
money_score     53 / P3_MEDIUM
confidence      HIGH (score 71)   value 59 / effort 47 / risk 85
evidence        HIGH · 11 sources / 10 evidence · tier TRUSTED · RESEARCH_COMPLETED
outcome_status  NONE   session_status NONE   historical_time_status NONE
efficiency_ratio null   actual_minutes 0
recommended_action VERIFY_ASSET_MATCH
why_now         PUBLIC_POC, EXPLOIT_AVAILABLE, CRITICAL_PRIORITY,
                TECHNOLOGY_OBSERVED, PRODUCT_MATCHED, HIGH_CONFIDENCE,
                NO_TERMINAL_OUTCOME, NO_SESSION_HISTORY
```

The output explicitly shows missing historical data (`NONE`), Money stays
`53 / P3_MEDIUM`, calibration stays `INSUFFICIENT_DATA` with weights
`UNCHANGED`, and `ai_data/research/{sessions,outcomes}` still do not exist.

## 13. Safety audit

- **No network / DNS / subprocess / LLM / Nuclei / browser / PoC / target
  interaction / findings / alerts**: static executable-token scans on all
  three new modules; composition reads only local persisted artifacts.
- **No payout/bounty prediction**: no payout fields or vocabulary; outcomes
  and time are exposed but never converted to money.
- **No automatic tuning / no Money Score modification**: the engine copies
  `money_score`; `build_economics()` is identical before/after; `MONEY_W_*`
  constants and `RULE_VERSION = "r25-1"` asserted unchanged; no r25-2.
- **r25-1 preserved**; opportunity layer has its own `r26-1` presentation
  rule version, separate from the Money Score rule.
- **research_only = true** on every model/API/CLI output.
- No R15–R25 formula/lifecycle changes; no MongoDB; no systemd/.env; no git
  add/commit/push.

## 14. Limitations

- **Presentation layer only**: classification, why-now and ranking are
  deterministic heuristics over existing signals; they are not new evidence
  and cannot confirm a vulnerability.
- **`BLOCKED` is asset-relationship scoped**: it means the vulnerability↔asset
  match is unproven (generic tech + plugin/component not observed), not that
  the lead is permanently unusable; `VERIFY_ASSET_MATCH` is the next step.
- **Estimated minutes are band midpoints** of the existing effort score, not a
  measurement; actual time is researcher-reported.
- **No causal claims**: history (outcomes, sessions, efficiency) is exposed
  but never used to adjust scores or ranking beyond fixed deterministic
  tie-breaks.
- **Empty bands/absent data are explicit** (`NONE`), never inferred or
  penalized.
- **Evidence composition is metadata-only**: it counts and ranks existing
  R23/R24 artifacts; it does not reinterpret content or fetch anything.
- Opportunity ordering is a total order over the listed keys; adding future
  signals would require an explicit, reviewed stage (not automatic).

## 15. Exact next-stage recommendation

**R26.2 — Opportunity-Outcome Snapshot & Delta Review (read-only).**

1. Persist nothing new by default; instead produce an offline, versioned
   read-only snapshot report of the opportunity queue (class × lead × money ×
   evidence × history) so researchers can compare week over week without any
   new write path or background worker.
2. If persistence is later approved, require an append-only store following
   the R25.5/R25.7 pattern (deterministic ids, no update-in-place), and keep
   it out of scoring until an explicit, reviewed `r25-2` is approved.
3. Optionally add opportunity-aware filtering to `opportunity list` (e.g.,
   `--class`) as a pure presentation filter; no new scoring.
4. Preserve all current boundaries: research-only, no execution/targets/
   payouts, no LLM/network/Mongo, no automatic tuning, r25-1 unchanged.

## Agent / Model
- Model: Miuz Spark (opencode-go/deepseek-v4.1-flash)
- Stage: R26.1
- Role: Economic Opportunity Intelligence
