# Stage R25.2 — Deterministic Economic Engine

**Status: IMPLEMENTED / TESTED.** No source code outside the economic engine
changed, no data changed, no MongoDB writes, no systemd change, no `.env`
change, no target interaction, no Nuclei/browser/PoC execution, no 5B–5J path
entered, no commit/push.

Objective: a deterministic, explainable Money Score that prioritizes
bug-bounty/security research by expected research value, composed purely from
the existing R15–R24 outputs.

---

## 1. Implementation Files

| File | Purpose |
|---|---|
| `ai/knowledge/economics.py` | Pure deterministic engine: `EconomicValue` dataclass, `assess_economic_value(lead, plan, intel, payload, task, r23, r24)`, component formulas, `economic_projection()` serializer. No imports beyond stdlib. |
| `ai/schemas/knowledge.py` | Additive standalone `KnowledgeEconomicValue` schema (R25.1 fields + `research_only` forced True via validator). Existing R15–R18 semantics untouched. |
| `tests/test_research_economics.py` | 91 offline unit tests covering every formula, cap, band, action, and safety invariant. |

No CLI/API/UI built (deferred to R25.3/R25.4). No persistence. No modification
to `database/db.py`, R15–R24 modules, or any out-of-scope file.

---

## 2. Formula Verification

All arithmetic uses integer/half-up rounding (`floor(x + 0.5)`), matching the R18
convention. Every constant lives in one module namespace; `rule_version =
"r25-1"`.

### VALUE

`V = half_up(0.30*P + 0.35*R + 0.20*SEV + 0.15*EX)`

- **P** = R16 `priority_score` (from lead, fallback intel priority score)
- **R** = R17 `relevance_score` (from lead, fallback relevance row)
- **SEV**: numeric `cve.cvss_score × 10` when available; else severity text
  mapping `critical=90 / high=75 / medium=55 / low=30`; else `0`
- **EX**: `public_poc=true +55`, `exploit_available=true +30`,
  `active_exploitation=true +15`; clamp 0–100. `false`/`unknown` add 0.

Verified: `P=80, R=20, SEV=75, EX=85 → 58.75 → V=59`.

### CONFIDENCE (5)

`C = clamp(50 + 15*structured_cvss + 20/12/5*best_R23_conf +
20/12/6*best_R24_tier + 10/5*relevance_class − 15*conflicts(cap −30) −
12*generic_only − 6*asset_blockers(cap −20) − 2*unknowns(cap −20), 0, 100)`

Plus hard cap `C ≤ 35` when no R15/R16 knowledge document exists.

Classes: `HIGH ≥ 70`, `MEDIUM ≥ 45`, else `LOW`.

Verified (dell): `50 + 15 + 20 + 20 − 12 − 18 − 4 = 71 → HIGH`.

### EFFORT (6)

`E = clamp(50 − exploit_discount(cap −25) − 8*unauth − 7*no_ui −
12*specific_match − 5*parameter − 5*version + 12*version_unknown +
10*plugin_not_observed + 10*component_not_observed + 15*generic_only +
8*no_result + 8*no_component, 10, 100)`

Verified (dell): `50 − 25 + 12 + 10 + 10 + 15 − 8 − 7 − 5 − 5 = 47 → 1–2 h`.

### RISK

```
DUP = clamp(20*poc + 15*active + 10*nuclei + 10*report + 5*prior +
            8*IN_PROGRESS + 5*BLOCKED, 0, 60)
FP  = clamp(12*generic + 8*version_unknown + 8*plugin + 8*component +
            8*conflicts + 6*relevance_LOW, 0, 40)
K   = clamp(DUP + FP, 0, 100)
```

Verified (dell): `DUP = 20+10+10+5 = 45`; `FP = 12+8+8+8+6 = 42 → 40`;
`K = 85`.

### MONEY

`raw = 0.55*V + 0.15*C + 0.15*(100−E) + 0.15*(100−K)`

Caps applied in exactly this order (each recorded in `caps_applied`):

1. `C < 45` → `M ≤ 60`
2. `K ≥ 70` → `M ≤ 55`
3. `E ≥ 85` → `M ≤ 60`
4. `V < 30` → `M ≤ 45`
5. `P=R=EX=0` → `M ≤ 40`

Then `M = clamp(half_up(raw), 0, 100)`.

Verified (dell): `raw = 0.55*59 + 0.15*71 + 0.15*53 + 0.15*15 = 53.3 → 53`.
Cap #2 (`K≥70 → 55`) is recorded but does not reduce the score (53 < 55).
Final **Money Score = 53 → P3_MEDIUM**.

### Priority bands

| Money | Band |
| 85–100 | `P1_START_NOW` |
| 65–84 | `P2_HIGH` |
| 45–64 | `P3_MEDIUM` |
| 30–44 | `P4_LOW` |
| 0–29 | `P5_DEFER` |

### Actions (first match)

1. task `DONE` → `COMPLETED`
2. task `IN_PROGRESS` → `CONTINUE`
3. task `BLOCKED` → `UNBLOCK_OR_SKIP`
4. `P1_START_NOW` → `START_NOW`
5. `P2_HIGH` → `START_TIME_BOXED`
6. `P3_MEDIUM` + asset-specific blocker → `VERIFY_ASSET_MATCH_FIRST`
7. `P3_MEDIUM` → `MONITOR`
8. `P4_LOW`/`P5_DEFER` → `MONITOR`/`DEFER`

Verified (dell): `P3_MEDIUM` + `asset version unknown` blocker →
`VERIFY_ASSET_MATCH_FIRST`.

---

## 3. Test Count / Results

```
$ python3 -m unittest tests.test_research_economics
Ran 91 tests in 0.010s
OK
```

Coverage groups (91 tests):

- Half-up rounding (3)
- VALUE formula: exact calc, severity numeric/text/fallback/none, exploit
  maturity additive + clamp, unknown/false neutrality, clamp bounds (9)
- CONFIDENCE: base, structured CVSS, R23 levels, R24 levels, relevance class,
  conflicts cap, generic blocker, asset blocker cap, no-knowledge cap, clamp (11)
- EFFORT: base, PoC discount, exploit cap, unauth/no-ui, specific match,
  parameter/version, blockers, no-result, no-component, min/max clamp (12)
- RISK: zero, DUP components, DUP cap, FP components, FP cap, relevance LOW,
  task states, K clamp (10)
- MONEY: all five caps, cap ordering (7)
- Priority bands (2)
- Actions: task states, P1, P3+asset-blocker, P5 (6)
- Unknown neutrality / false vs unknown (4)
- Conflicts (2)
- Blockers (1)
- Task states (1)
- Report/result existence (4)
- R23 evidence (2)
- R24 tier (2)
- Determinism + repeated execution (2)
- Schema validation + `research_only` forced (3)
- Safety: no payout inference, research_only flag, no LLM/network/subprocess,
  rule_version fixed (4)
- Properties: score bounds 0–100, monotonicity, deterministic output (3)
- Effort estimate labels (7)
- Confidence classes (5)
- Asset match classification (5)

---

## 4. Real Corpus Scores

Recomputed by loading the actual persisted artifacts
(`ai_data/research/CVE-2026-1557.cli.json`, R23/R24 agent results, R18 queue,
R21 leads, R22 plans, R15–R17 intelligence) through the engine. Nothing
persisted.

### CVE-2026-1557 → dell

| Field | Value |
|---|---|
| lead_id | `rl-af7ecfba1a86fc83` |
| plan_id | `r22-38d26f10681e9a0f` |
| **money_score** | **53** |
| priority | `P3_MEDIUM` |
| confidence | `HIGH` |
| effort | 47 (1–2 h) |
| asset_match | `TECHNOLOGY_ONLY` |
| subscores | V=59, C=71, E=47, K=85 (DUP=45, FP=40) |
| caps_applied | `risk 70 or above` |
| action | `VERIFY_ASSET_MATCH_FIRST` |
| r23_confidence | HIGH (7 evidence, 6 sources) |
| r24_tier | TRUSTED |

### CVE-2026-1557 → indeed

| Field | Value |
|---|---|
| lead_id | `rl-d1d66e2ee9d8467c` |
| plan_id | `r22-fda96966ea7af4ae` |
| **money_score** | **53** |
| priority | `P3_MEDIUM` |
| confidence | `HIGH` |
| effort | 47 (1–2 h) |
| asset_match | `TECHNOLOGY_ONLY` |
| subscores | V=59, C=71, E=47, K=85 (DUP=45, FP=40) |
| caps_applied | `risk 70 or above` |
| action | `VERIFY_ASSET_MATCH_FIRST` |
| r23_confidence | HIGH (6 evidence, 6 sources) |
| r24_tier | TRUSTED |

Both programs score identically because they share the same CVE intelligence
(R15/R16/R17/R23/R24 are CVE-keyed) and the same four asset blockers; the R23
evidence count differs (7 vs 6) but both resolve to `HIGH` best confidence.

This matches the R25.1 worked-example projection for `CVE-2026-1557 → dell`
(estimated Money Score ~55, capped by `K≥70`, → `P3_MEDIUM`); the exact
deterministic recompute lands at 53.

### Full corpus ordering

The current corpus has exactly 2 leads (the only R18 queue candidates):

| Money | Priority | CVE | Program | Effort | Action |
|---:|---|---|---|---|---|
| 53 | P3_MEDIUM | CVE-2026-1557 | dell | 1–2 h | VERIFY_ASSET_MATCH_FIRST |
| 53 | P3_MEDIUM | CVE-2026-1557 | indeed | 1–2 h | VERIFY_ASSET_MATCH_FIRST |

Ordering is deterministic: by money desc, then CVE asc, then program asc.

---

## 5. Cap Behavior

All five Money Score caps are unit-tested independently and in combination:

- **Confidence cap** (`C<45 → M≤60`): exercised via `only generic technology
  match` blocker (`C=38`).
- **Risk cap** (`K≥70 → M≤55`): the binding cap on the real corpus
  (`K=85`). Recorded even when raw < cap.
- **Effort cap** (`E≥85 → M≤60`): exercised via four simultaneous blockers
  (`E=97`).
- **Value-low cap** (`V<30 → M≤45`): exercised with zero value inputs.
- **No-value-signal cap** (`P=R=EX=0 → M≤40`): exercised with high severity
  but no priority/relevance/exploit — confirms severity alone cannot push a
  lead past 40.

Cap ordering is preserved: each cap is applied as `min(M, cap)` in the exact
sequence specified, and every applied cap is named in `caps_applied`.

---

## 6. Unknown Handling

- Unknown tri-states contribute exactly zero — verified equal to absent fields
  and to `false` for exploitability signals (unknown ≠ false: both add 0, but
  they are never conflated in the tri-state normalization).
- Unknown does not invent asset version or parameter matches.
- The engine is safe with all-None inputs (bounded score, `research_only=True`).
- Confidence `unknown_factors` from R16/R17/R22 are counted (capped −20); the
  separate per-signal unknown preservation in the upstream modules is
  respected, not duplicated.

---

## 7. Regression Results

R15–R24 behavior verified unchanged:

```
tests.test_research_agent ... Ran 92 tests OK
tests.test_research_leads ... OK
tests.test_research_execution ... OK
tests.test_research_workflow ... OK
tests.test_research_intelligence_ui ... OK
tests.test_research_agent_r24_1 … r24_6 ... OK
tests.test_research_agent_r24_8, r24_10, r24_11 ... OK
tests.test_research_ui ... 39 tests (1 pre-existing failure, see below)
tests.test_research_navigation ... OK
tests.test_research_api ... OK
tests.test_xss_presentation ... OK
```

The single `test_research_ui` failure
(`test_research_sort_toggle_inverts_order`) is **pre-existing**: it fails
identically on the unmodified `HEAD` (verified via `git stash`). It is
unrelated to R25.2. No R15–R24 module or schema semantics were altered.

---

## 8. Safety Verification

- **Deterministic and local:** pure function of the 7 inputs; no network, DNS,
  LLM, subprocess, timers (verified: no `subprocess`/`requests`/`urllib`/
  `socket`/`http.client` imports; no `openai`/`claude`/`llm` imports).
- **Read-only:** no writes, no persistence, no Mongo, no production mutation.
- **Research-only semantics:** output never says `VULNERABLE`/`VERIFIED`/
  `EXPLOITED`/`FINDING`/`CONFIRMED`. No `$`, `payout`, or `dollar` strings.
- **Unknown preservation:** unknown inputs add no points.
- **Bounded:** fixed constants, clamped scores 0–100, capped lists.
- **`research_only` forced True** at both the dataclass default and the schema
  validator (validator test confirms a `False` input is overridden to `True`).
- **No payout inference:** Money Score does not use program payout/reward data
  (none exists), does not use `research.bug_bounty_relevance` (model-generated,
  excluded), and never implies a payout amount or probability.
- **No target interaction:** consumes only already-persisted CVE/research/asset
  records.

---

## 9. Design vs. Implementation Discrepancies

None of substance. Notes:

- The `_unique_unknowns` helper reads unknowns from R16 (`priority.
  unknown_factors`), R17 (relevance row `unknown_factors`), and R22 (`plan.
  unknowns`), deduplicated and capped at −20 — matching the "each unique
  R16/R17/R22 unknown → −2 (cap −20)" rule.
- R23 `affected_parameters`/`affected_versions` are consumed (in addition to
  payload `research.parameters`/`affected_versions`) for the effort
  parameter/version-known discounts, since the research agent surfaces them.
  This is an additive read of an existing R23 output, not a re-derivation.
- The `asset_match` classification reads R17 relevance reasons via the intel
  relevance row, falling back to lead reasons when the row is absent — both are
  projections of the same R17 match logic, never an independent match.

---

## 10. Deferred (per R25.1 11)

- R25.3 — read-only projection + CLI (`backend/research_economics.py`,
  `research_cli economics`).
- R25.4 — API + minimal decision UI.
- R25.5 — outcome capture + calibration loop (the only justification for
  changing weights → `r25-2`).
- R25.6 — close data gaps (asset-version matching, parameter-match fix,
  program reward metadata, exploit freshness with explicit `as_of`).
- R25.7+ — monetization surfaces, only after R25.5.

---

## Agent / Model
- Model: Miuz Spark
- Stage: R25.2
- Role: Deterministic Economic Engine
