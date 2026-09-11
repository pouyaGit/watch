# Stage R29.1 — Personal Bug-Bounty Hunt Queue

## Status
**IMPLEMENTED (personal research workflow).** A deterministic "what should I
personally investigate next?" queue now sits on top of the existing R26.2
Action Queue, R25.5 outcomes and R25.7 sessions. It is research-only and
performs no execution, network, scoring change or persistence.

No Money Score change, no r25-2, no R26.1/R26.2/R26.3/R27.1 methodology change,
no LLM/network/DNS/Nuclei/browser/PoC/target interaction, no findings/alerts,
no bounty prediction, no auto-submit/auto-research/auto-tune, no Mongo,
workers, systemd or `.env` changes.

## 1. Rationale

The Money Score is a good *economic* 0–100 ranking, but personal research
time is a different question. A lead can be economically high yet currently
blocked, low-confidence, or historically wasteful — and an already-active
session should be continued rather than abandoned for a marginally higher
number. R29.1 adds a small, closed-vocabulary **hunt tier** for personal work
ordering, reusing existing signals only.

## 2. Hunt model (`ai/schemas/hunt_queue.py`, 174 lines)

`HuntItem` fields: `hunt_id, lead_id, cve_id, program, money_score,
money_priority, opportunity_class, current_status, recommended_action,
confidence, evidence_quality, estimated_minutes, why_now, blockers, next_step,
historical_outcome, historical_time, hunt_priority, recommended_time_box,
hunt_reason, hunt_reason_code, research_only, rule_version` (additive:
`hunt_reason_code`, `recommended_time_box`).

- `hunt_id = "hq-" + sha256(rule_version + lead_id)[:16]` (deterministic).
- `rule_version` fixed `r29-1`; `research_only` forced `true`; `extra="forbid"`.
- No payout/bounty/reward/target/IP/domain/credential/exploit-command/
  execution-command/production-finding fields.

**How `hunt_priority` differs from Money Score (documented in the module):**
Money Score is a stable, product-oriented 0–100 economic rank over a
CVE/program candidate and is copied into the item verbatim. `hunt_priority` is
a personal-work **tier** (HUNT_NOW / HUNT_NEXT / VERIFY_FIRST / RESEARCH_LATER
/ SKIP_FOR_NOW) that orders attention using the Money Score plus workflow
signals (active session, blockers, confidence, effort, history). It never
mutates, rescales, re-weights or replaces the Money Score, and it is not a new
numeric score.

## 3. Priority tiers and exact precedence (`ai/knowledge/hunt_queue.py`, 339 lines)

Closed tiers: `HUNT_NOW, HUNT_NEXT, VERIFY_FIRST, RESEARCH_LATER,
SKIP_FOR_NOW`. First match wins (verbatim order):

| # | Condition | Tier |
|---:|---|---|
| 1 | active session (`current_status == IN_PROGRESS`, `session_status == ACTIVE/IN_PROGRESS`, or `in_progress_sessions > 0`) | `HUNT_NOW` |
| 2 | BLOCKED (`current_status == BLOCKED` or `opportunity_class == BLOCKED`) | `VERIFY_FIRST` |
| 3 | previous `ACCEPTED` outcome | `HUNT_NOW` |
| 4 | `HIGH_VALUE` + confidence `HIGH` | `HUNT_NOW` |
| 5 | `GOOD_OPPORTUNITY` + confidence `HIGH`/`MEDIUM` | `HUNT_NEXT` |
| 6 | `RESEARCH_FIRST` | `HUNT_NEXT` |
| 7 | confidence `LOW` or `LOW_CONFIDENCE` | `VERIFY_FIRST` |
| 8 | terminal history with `(duplicate + wasted + rejected) / terminal >= 0.5` | `RESEARCH_LATER` |
| 9 | otherwise | `SKIP_FOR_NOW` |

Consequences verified: active beats blocked; blocked beats an accepted
outcome; accepted/high-value+high → HUNT_NOW; a high-waste but not
otherwise-classified lead → RESEARCH_LATER; RESEARCH_FIRST beats waste
history (rule 6 before 8). Tiers are never silently reordered.

## 4. History handling

`historical_outcome`: `attempts, accepted, duplicate, rejected, wasted,
latest_outcome, data_quality`. `historical_time`: `total_time, average_time,
latest_session_status, total_sessions, planned_time, actual_time`. History is
**context only**: it never modifies Money Score, never confirms a new
vulnerability, and leads with no history are not penalized (a
high-value/high-confidence lead with zero history is still HUNT_NOW).

## 5. Time-box logic

`build_time_box(estimated_minutes)`: ≤30 → `30 MIN`; 31–60 → `60 MIN`;
61–120 → `120 MIN`; >120 → `120 MIN + REVIEW`. Nothing is scheduled, no
timers start, no background jobs exist.

## 6. Ranking

1. hunt priority tier, 2. Money Score descending, 3. confidence descending,
4. evidence quality descending, 5. estimated minutes ascending, 6. CVE
ascending, 7. program ascending, 8. lead_id ascending. No additional numeric
score.

## 7. CLI

```
python -m ai.research_cli hunt [--limit 50 --cve X --program P
  --priority TIER --class C --status S --json]
```

Observed real-corpus output:

```
PERSONAL HUNT QUEUE

#1 VERIFY_FIRST
CVE-2026-1557 → dell
Money: 53 / P3
Confidence: HIGH
Evidence: HIGH
Time box: 120 MIN

WHY:
Asset relationship is not sufficiently established.

NEXT:
Confirm affected component/plugin presence.
```

`--json` emits the ranked items (empty filter → `[]`); malformed CVE → exit 1;
payout/target/execute flags → exit 2.

## 8. API

Internal read-only routes only (no public API, no new product surface),
declared before `/api/research/{cve}` and reusing the existing auth:

| Route | Behavior |
|---|---|
| `GET /api/research/hunt` | ranked hunt list (`limit/offset/cve/program/priority/class/status`) |
| `GET /api/research/hunt/summary` | tier counts + top items |

No POST/PUT/DELETE (405/401). No persistence.

## 9. UI

Existing Research Leads page (no new dashboard, no charts/polling/
animations) now shows a **Personal hunt queue** panel with the five
requested sections, each rendered only when populated:

```
🔥 HUNT NOW   ➡️ HUNT NEXT   ⚠️ VERIFY FIRST   🕒 RESEARCH LATER   ⏸ SKIP FOR NOW
```

Each item shows CVE → program, Money Score / priority, time box, and the
tier reason (max 5 per tier, "+N more"). The lead detail page adds a
**Personal hunt decision** panel: Priority, Why, Time box, Historical
(attempts/accepted/duplicate/wasted/time), Next, and the disclaimer
*"Research prioritization only — does not confirm vulnerability."* Both are
fail-soft and read-only.

## 10. Real corpus

No data fabricated or written. Both leads:

- `CVE-2026-1557 → dell` / `→ indeed`: Money `53 / P3_MEDIUM`, class
  `BLOCKED`, action `VERIFY_ASSET_MATCH`, sessions 0, outcomes 0.
- Hunt priority `VERIFY_FIRST`; reason *"Asset relationship is not
  sufficiently established."*; time box `120 MIN` (from existing
  `estimated_minutes = 90`); `rule_version r29-1`; `research_only true`.
- Money scores still `[53, 53]`; calibration still `INSUFFICIENT_DATA` with
  `weights_unchanged=True`; no new `ai_data/` directories.

## 11. Tests (`tests/test_hunt_queue.py`, 711 lines — **61 tests, all OK**)

- schema: deterministic id, field set, forbidden-field rejection, closed
  tiers/time boxes, forced rule/research flags, no `hunt_score`.
- every tier and full precedence (active, active-beats-blocked,
  blocked-beats-accepted, accepted, high-value+high, good-opportunity,
  research-first, low-confidence, high-waste, research-first-beats-waste,
  default/zero, all tiers reachable).
- reasons map to structured fields for each code.
- time-box bands (0/30/31/60/61/90/120/121/480).
- history aggregation, defaults, no-history not penalized, history does not
  change money.
- ranking: tier first, money, effort ascending, full tie-break, summary.
- backend: real corpus, filters (priority/class/status/cve/program),
  detail/summary/errors, determinism, no persistence, Money Score unchanged.
- CLI: human output, JSON + filters, no payout flags.
- API: auth, list/summary shape, filters, no write endpoint, no payout
  vocabulary.
- UI: hunt sections on leads page, hunt panel + disclaimer on lead detail,
  no charts/polling.
- safety: executable-token scan, no persistence tokens, engine purity,
  r25-1/r26-1/r26-2/r26-3 constants unchanged, no forbidden model fields.

Regression run (all OK): R29.1 61, R28.1 33, R28.2 contract 25 + client 33,
R25.2 91, R25.3 33, R25.4 21, R25.5 64, R25.6 48, R25.7 66, R26.1 60,
R26.2 82, R26.3 69, R27.1 47 (**733 OK**) plus research API + navigation 43
OK. `git diff --check` clean.

## 12. Safety audit

- `research_only: true` on every schema instance, backend projection, API
  response, CLI output and UI render.
- No network/DNS/subprocess/LLM/Nuclei/browser/PoC/target interaction/
  findings/alerts, no payout prediction, no automatic research/outcomes/
  tuning, no persistence/Mongo/systemd/`.env`.
- Static executable-token scan on all three new modules; backend contains no
  write tokens.
- Money Score copied verbatim (constants asserted unchanged); R26.1/R26.2/
  R26.3 rule versions unchanged.
- No public API or product surface added; the two routes are internal
  read-only.

## 13. Limitations

- Personal tiering is a deterministic heuristic over existing signals, not
  evidence and not a vulnerability confirmation.
- `hunt_priority` is rule-based (no calibration); its precedence is explicit
  and intentionally conservative (blocked beats accepted).
- History is cross-sectional per lead over current stores; no longitudinal
  analytics are added.
- Time boxes derive from the existing effort estimate (band midpoint); they
  are guidance, never a scheduled timer.
- The UI shows at most 5 items per tier (with a "+N more" hint); full lists
  are available via CLI/API.

## 14. Exact next-stage recommendation

**R29.2 — Personal Hunt Journal (offline, read-only).**

1. Add a read-only CLI/UI "hunt journal" that reflects the existing R25.7
   sessions and R25.5 outcomes grouped under the current hunt tiers — purely
   derived, no new persistence and no automatic outcome creation.
2. If outcome-driven tier calibration is ever wanted, gate it behind a
   separate reviewed stage; never auto-tune, and never let history change the
   Money Score.
3. Keep the boundaries: research-only, no execution/targets/payouts, no
   LLM/network/Mongo, r25-1 / r26-1 / r26-2 / r26-3 / r29-1 unchanged.

## Agent / Model
- Model: Miuz Spark (opencode-go/deepseek-v4.1-flash)
- Stage: R29.1
- Role: Personal Bug-Bounty Hunt Queue
