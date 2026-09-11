# Stage R25.1 — Economic Research Prioritization Design

**Status: DESIGN / AUDIT ONLY.** No source code changed, no data changed, no
MongoDB writes, no systemd change, no `.env` change, no target interaction, no
Nuclei/browser/PoC execution, no 5B–5J path entered, no commit/push.

Objective: maximize real-world bug-bounty / security-research value. From this
stage on, features are judged by (1) higher-value vulnerability identification,
(2) reduced wasted researcher time, (3) better prioritization, (4) higher
probability of actionable findings, and (5) future monetizable intelligence/API
capability. Cosmetic dashboard work is explicitly not a goal.

This document audits the existing R15–R24 pipeline, determines which economic
signals the persisted data model actually supports, and specifies a
deterministic **Money Score** model with explicit VALUE / CONFIDENCE / EFFORT /
RISK components, a researcher decision output, a monetization ranking, an
additive architecture, an implementation order, and explicit non-goals and
safety boundaries.

---

## 1. Current Architecture Findings

### 1.1 Pipeline map (read-only audit of `HEAD 71fef7c` + working tree)

| Stage | Implementation | Output artifact | Persistence |
|---|---|---|---|
| R15 Exploitability | `ai/knowledge/intelligence.py` (+`ai/schemas/knowledge.py::KnowledgeExploitability`) | tri-states: `authentication_required`, `privilege_required`, `user_interaction_required`, `exploit_available`, `public_poc`, `active_exploitation`, `exploit_complexity`; CVSS structural letters `AV/AC/AT/PR/UI` + `source`; `conflicts[]`; verbatim evidence | KnowledgeStore JSON (`ai_data/knowledge/`), projected onto synthesis docs at ingest |
| R16 Priority | `ai/knowledge/intelligence.py::summarize_research_priority` (+`KnowledgeResearchPriority`) | `score` 0–100, class (`CRITICAL_RESEARCH`/…/`INSUFFICIENT_DATA`), `reasons[]`, `negative_factors[]`, `unknown_factors[]`, `evidence[]`, rule `r16-1` | KnowledgeStore JSON |
| R17 Asset relevance | `ai/knowledge/relevance.py` (+`KnowledgeAssetRelevance`) | `relevance` class, `score` 0–100, match reasons (`exact product match` +50, `exact plugin/component match` +35, `technology match` +20, `component/path match` +20, `vulnerability type` +10, `keyword overlap` +5), `matched_assets[]`, `matched_programs[]`, `unknown_factors[]`, rule `r17-1` | **Live only** (document field defaults `UNKNOWN`; assets unavailable at ingest time) |
| R18 Research queue | `ai/knowledge/queue.py` (+`KnowledgeResearchQueueItem`) | `queue_score = round(0.60*priority + 0.40*relevance)`, `rank`, `blockers[]`, `unknown_factors[]`, evidence, `queue_id = rq-<sha16(rule,cve,program)>`, rule `r18-1` | On-demand, no persistence |
| R19 Dashboard/API | `backend/research_data.py`, `backend/routers/research*.py`, `web/templates/research*.html` | read-only views over R15–R18 (10 s cache) | None |
| R20 Research workflow | `ai/knowledge/task_store.py`, `ai/schemas/research_task.py`, `backend/research_tasks.py` | `ResearchTask` state machine `TODO → IN_PROGRESS → BLOCKED/DONE`, notes/blocker/result summary, bounded audit history, deterministic `task_id` | `ai_data/research/tasks/` (**currently no tasks persisted**) |
| R21 Research leads | `backend/research_leads.py` | lead projection: `lead_id`, priority/relevance levels+scores, positive `reasons[]` codes, `blockers[]`, `recommended_next_step`, `status`, rule `r21-1` | On-demand, `created_at`/`updated_at` deliberately empty |
| R22 Execution plans | `backend/research_execution.py` | `plan_id`, ordered `steps[]` (10 codes), `evidence_targets[]` (11 codes), `unknowns[]`, `blockers[]`, `recommended_start`, `status`, rule `r22-1` | On-demand, no persistence |
| R23 Autonomous research | `ai/research_agent/agent.py`, `ai/schemas/research_agent.py` | `ResearchAgentResult`: status, `sources[]`, grounded `evidence[]` (`confidence HIGH/MEDIUM/LOW`, trusted `content_hash`), `inferences[]`, `unknowns[]`, affected versions/components/parameters, `nuclei_candidates[]` (never executed), `production_finding=false`, rule `r23-1` | `ai_data/research/agent/<plan>.r23-1.json` + `.md`; run records in `runs/` |
| R24 Public-source discovery | `ai/research_agent/{discovery_contract,providers,netguard,ranking,dedup,evidence,llm_loop,fetch_priority,...}.py` | per-source `tier` (`TRUSTED`/`SEMI_TRUSTED`/`DISCOVERY_ONLY`/`GENERIC`), `category` (11 values), `source_quality` 0.0–1.0, lifecycle, grounded evidence, unknowns, budget counters; LLM loop result, rule `r24-1` / `r24-loop-1` | `ai_data/research/agent/<plan>.r24-loop-1.loop.json`; per-plan discovery results also loadable via `storage.list_results` |

### 1.2 Current corpus state (read-only observation)

- 6 CVEs have R15/R16 synthesis documents in the KB; `priority --all` returns the
  expected classes (CVE-2026-1557 = 80/`CRITICAL_RESEARCH`; others 18–38).
- R18 queue has **exactly 2 candidates**: `CVE-2026-1557 → dell` and
  `CVE-2026-1557 → indeed`, both `queue_score=56` (priority 80, relevance 20).
  Every other corpus CVE produces no candidate because local asset relevance is
  `NONE`/`UNKNOWN` (honest, not a matching defect).
- R21 leads: 2; R22 plans: 2 (`RESEARCH_PLAN_READY`, `recommended_start =
  REVIEW_PUBLIC_POC`).
- R23 results: both plans exist; `dell` has 7 HIGH-confidence grounded evidence
  items / 6 sources, `indeed` 6 HIGH / 6 sources; both `RESEARCH_PARTIAL`.
- R24 loop results: both plans `RESEARCH_COMPLETED`; e.g. `dell` discovered 5
  `TRUSTED` sources (4 `vendor_advisory`, 1 `nvd_cve`), 3 evidence items with
  `confidence=LOW`, `source_quality=0.82`.
- R20 task store: empty. Reports exist for all 6 corpus CVEs
  (`ai_data/reports/<CVE>.md`).
- Program definitions (`programs/*.json`) carry only `program_name`, `scopes`,
  `ooscopes`. **There is no payout/reward metadata anywhere.**
- Persisted research payloads (`ai_data/research/<CVE>.cli.json`) additionally
  carry numeric `cve.cvss_score`, `cve.cvss_vector`, `research.severity`,
  `research.public_exploit`, `research.actively_exploited`,
  `research.bug_bounty_relevance` (model-generated 0–10), `research.affected_versions`,
  `research.references`, `metadata.{assets,programs,technologies,...}`,
  `generated_at`.

### 1.3 Audit findings that constrain the economic model

1. **Parameter match is not implemented.** `ai/knowledge/relevance.py:327`
   accepts `parameters` but never uses it. R21's `PARAMETER_OBSERVED` reason
   (`backend/research_leads.py:104`) checks for `"parameter"` in R17 reasons,
   which R17 never emits → the code path is unreachable. `REVIEW_PARAMETER_MATCH`
   in R22 is vulnerability-side only (`doc.parameters`), not an asset match.
2. **Version match is not implemented.** `AssetRecord` has no version field,
   R17 has no version rule, and R18 reports the `asset version unknown` blocker
   when the CVE declares versions. No positive asset-version signal exists.
3. **Numeric severity exists but is not projected through R15–R22.** R15 stores
   only CVSS structural letters; R16 deliberately does not compute a score.
   The persisted numeric `cvss_score`/`severity` can be read read-only by a new
   projection without touching R15–R22.
4. **R24 artifacts are not wired into R21/R22/backend yet.** The loop results
   exist on disk and are loadable via `ai.research_agent.storage.load_research_loop`,
   but no lead/plan currently consumes `tier`/`source_quality`/evidence
   confidence. The economic layer must read them directly (read-only).
5. **`source_quality` is host/tier-derived, not content-derived.** The current
   `dell` R24 evidence is `TRUSTED` / 0.82 quality but `confidence=LOW` and the
   claims are page titles from vendor search pages. An economic confidence model
   must therefore prefer `tier` + evidence `confidence`, and treat
   `source_quality` alone as insufficient.
6. **`bug_bounty_relevance` is model-generated (LLM) and uncalibrated.** Per the
   project KB rules it must remain `model_generated` and cannot be treated as
   confirmed evidence. It is excluded from the v1 score.
7. **No duplicate/historical-outcome data exists.** R20 status, existing R23/R24
   results and report files are the only "previously researched" signals.
   Duplicate likelihood can only be a labeled proxy (public PoC / KEV / Nuclei
   presence), never an observed fact.
8. **No exploit freshness data exists.** No per-reference/PoC dates are stored;
   `generated_at` is artifact-generation time, not exploit publication time.
   Clock-dependent age must not enter a deterministic score in v1.

---

## 2. Available Signals

The model below consumes only persisted, local, deterministic data. "Supported"
means the signal exists and is already computed or directly readable without
inventing or re-deriving intelligence.

### 2.1 Requested signal inventory

| Requested signal | Status | Where it comes from |
|---|---|---|
| CVSS severity | **Partial** | numeric `cve.cvss_score` + `research.severity` in the persisted payload (read-only); R15 has only structural letters `AV/AC/AT/PR/UI`; R16 intentionally computes no score |
| Exploit availability | **Supported** | R15 `exploit_available` tri-state |
| Public PoC | **Supported** | R15 `public_poc` tri-state |
| Unauthenticated exploitation | **Supported** | R15 `authentication_required == "false"` |
| No user interaction | **Supported** | R15 `user_interaction_required == "false"` |
| Attack complexity | **Supported** | R15 `exploit_complexity` (`low`/`high`) + CVSS `AC` letter |
| Attack vector | **Supported** | R15 CVSS `AV` letter (`N/A/L/P`) |
| Technology match | **Supported** | R17 `technology match: …` (+20) |
| Exact product match | **Supported** | R17 `exact product match: …` (+50) |
| Component match | **Supported** | R17 `exact plugin/component match` (+35) and `component/path match` (+20) |
| Parameter match | **Not supported** | R17 ignores `parameters`; R21 `PARAMETER_OBSERVED` unreachable (§1.3.1) |
| Version match | **Not supported** | no asset version data; only the `asset version unknown` blocker (§1.3.2) |
| Observed asset | **Supported** | R17 `matched_assets[]` / `matched_programs[]` |
| Public exploit/reference quality | **Partial** | R24 `tier`, `category`, `source_quality`, evidence `confidence` (only after discovery runs; content quality weak today) |
| Exploit freshness | **Not supported** | no PoC/reference dates; `generated_at` is artifact time (§1.3.8) |
| Research evidence quality | **Supported (partial)** | R23 evidence `confidence` + trusted hash; R24 tier/quality/confidence; KB `evidence_quality` (mostly `UNKNOWN`) |
| Confidence | **Supported (composed)** | R15 structured-vs-prose + `conflicts[]`; R16/R17 `unknown_factors[]`; R18 `blockers[]`; R22 `unknowns[]`; R23/R24 evidence confidence |
| Expected researcher effort | **Derived, not stored** | new deterministic heuristic over R22 steps/unknowns/blockers + R15/R17 specificity |
| Duplicate likelihood | **Proxy only** | `public_poc`, `active_exploitation`, `nuclei_candidate`; "already researched" via reports/R23/R24 results/R20 status |
| False-positive risk | **Derived (partial)** | R18/R21 blockers, R15 `conflicts[]`, R17 generic-only match, `unknown_factors[]` |
| Known/previously researched | **Supported** | R20 task status; `ai_data/reports/<CVE>.md`; R23/R24 result existence |

### 2.2 Exact per-Lead / per-Plan information available today

**R21 Research Lead** (`backend/research_leads.py`):
`lead_id`, `cve_id`, `program`, `queue_id`, `task_id`, `priority_score`,
`priority_level`, `relevance_score`, `relevance_level`, `exploitability_summary`
(text), `asset_match_summary` (text), `reasons[]` (`{code,text,source}`),
`blockers[]`, `recommended_next_step`, `status`, `rule_version`.

**R22 Research Execution Plan** (`backend/research_execution.py`):
`plan_id`, `lead_id`, `cve_id`, `program`, `queue_id`, `task_id`,
`priority_score`, `relevance_score`, `status`, `steps[]`
(`REVIEW_CVE_SUMMARY`, `REVIEW_EXPLOITABILITY`, `REVIEW_PUBLIC_POC`,
`REVIEW_REFERENCES`, `REVIEW_TECHNOLOGY_MATCH`, `REVIEW_COMPONENT_MATCH`,
`REVIEW_PARAMETER_MATCH`, `REVIEW_VERSION`, `REVIEW_ASSET_EVIDENCE`,
`REVIEW_RESEARCH_TASK`), `evidence_targets[]`, `unknowns[]`, `blockers[]`,
`recommended_start`, `metadata` (priority/relevance levels, next step, lead
status).

**Reachable enrichment per CVE (read-only):**
- `backend.research_data.cve_intelligence(cve)`: full R15 `exploitability`
  (tri-states + CVSS structural + conflicts), R16 `priority`, R17 `relevance`
  rows per program, R18 `queue`.
- `backend.research_data.get_research(cve)`: `cvss_score`, `cvss_vector`,
  `severity`, `public_exploit`, `bug_bounty_relevance`, `references`,
  `affected_versions`, `nuclei_candidate`, `endpoints`, `parameters`, etc.
- `ai.research_agent.storage.load_research_loop(plan_id)`: R24 discovery
  sources/evidence with `tier`, `category`, `source_quality`, `confidence`,
  `eligible`, `ineligible_reason`, budgets, unknowns.
- `ai.research_agent.storage.load_result(plan_id, "r23-1")`: R23 result with
  sources/evidence/unknowns.
- `backend.research_tasks.task_store()`: R20 task status/notes (currently none).
- `ai_data/reports/<CVE>.md` existence: prior report written.

### 2.3 Signals deliberately **not** used in v1 and why

- `research.bug_bounty_relevance` (model-generated, uncalibrated) — excluded.
- Program payout/reward metadata — does not exist. Money Score is **not** a
  payout/dollar prediction.
- Exploit freshness/CVE age — requires a clock; deterministic scoring must take
  an explicit `as_of` input later, otherwise it is non-deterministic.
- Asset version / parameter matching — not implemented; must not be faked.
- Any global "security confidence" synthesized across sources — forbidden by
  the KB model; confidence is per-input provenance quality only.

---

## 3. Proposed Score Model

### 3.1 Design principles

1. **Expected value, not CVSS ranking.** Value is dominated by asset
   specificity, exploit readiness and impact together. A medium-severity
   vulnerability with an exact component match, public PoC, unauthenticated
   access and an observed asset must be able to outrank a critical CVE with only
   a generic technology match.
2. **Four separate axes.** VALUE (upside), CONFIDENCE (grounding), EFFORT
   (researcher time), RISK (duplicate + false-positive + already-researched).
   Each is 0–100; unknown contributes **no points**, never a negative.
3. **Compose, do not duplicate.** R16 priority and R17 relevance are reused
   verbatim. The new engine only adds impact (persisted severity), exploit
   maturity, evidence maturity, effort and risk. No matching logic is
   reimplemented.
4. **Bounded and deterministic.** Integer arithmetic, half-up rounding, fixed
   weights, `rule_version = "r25-1"`, no clocks, no randomness, no LLM, no
   network, no subprocess.
5. **Explainable always.** Every non-zero score has `reasons[]`; every cap is
   recorded in `caps_applied[]`.

### 3.2 Component definitions

Let (all 0–100 integers unless noted):

- `P` = R16 `priority_score`
- `R` = R17 `relevance_score`
- `SEV` = severity signal
- `EX` = exploit maturity
- `OBS` = asset observability
- `C` = confidence score
- `E` = effort score (higher = more effort)
- `K` = risk score (higher = more likely wasted work)

#### VALUE (V, 0–100)

```
V = half_up( 0.30*P + 0.35*R + 0.20*SEV + 0.15*EX )
```

Rationale: R16 already encodes exploitability/access/complexity priority;
R17 encodes asset specificity; `SEV` adds impact (which R16 does not); `EX`
adds concrete public-exploit readiness. Relevance (0.35) intentionally
outweighs raw priority (0.30) so a well-matched medium CVE can beat a poorly
matched critical. `OBS` is folded into relevance evidence and reported
separately in the UX (see §6) rather than double-weighted.

`SEV`:
- if persisted numeric `cve.cvss_score` exists: `SEV = clamp(round(score*10), 0, 100)`
  (read-only; no CVSS calculation);
- else if `research.severity` exists: `critical=90, high=75, medium=55, low=30`;
- else `0` (unknown; no penalty).

`EX`:
- `public_poc == "true"` +55; `exploit_available == "true"` +30;
  `active_exploitation == "true"` +15; clamp 0–100.
- `false`/`unknown` add 0.

#### CONFIDENCE (C, 0–100) — see §5

#### EFFORT (E, 0–100) — see §6

#### RISK (K, 0–100)

```
DUP = clamp( 20*public_poc + 15*active_exploitation + 10*nuclei_candidate
             + 10*report_exists + 5*prior_result_exists
             + 8*(task=IN_PROGRESS) + 5*(task=BLOCKED), 0, 60 )

FP  = clamp( 12*generic_only_match + 8*asset_version_unknown
             + 8*plugin_not_observed + 8*asset_component_not_observed
             + 8*(conflicts present) + 6*(relevance=LOW), 0, 40 )

K   = clamp(DUP + FP, 0, 100)
```

`DUP` is explicitly a **public-exposure proxy**, not an observed duplicate
count. `report_exists` / `prior_result_exists` mean the platform has already
invested research time (a re-research discount), which is why they sit in RISK
alongside genuine duplicate exposure.

#### MONEY SCORE (M, 0–100)

```
raw = 0.55*V + 0.15*C + 0.15*(100 - E) + 0.15*(100 - K)

caps (applied highest first, each recorded):
  1. C < 45 (LOW confidence)          -> M = min(M, 60)
  2. K >= 70                          -> M = min(M, 55)
  3. E >= 85 (very high effort)       -> M = min(M, 60)
  4. V < 30 (weak value)              -> M = min(M, 45)
  5. no positive value signal other
     than severity (P=R=EX=0)         -> M = min(M, 40)

M = clamp(half_up(raw), 0, 100)
```

Weights: VALUE 55, CONFIDENCE 15, EFFORT-efficiency 15, RISK-avoidance 15.
The caps encode the multiplicative realities that an additive model cannot:
low-confidence, high-risk, high-effort or low-value leads are capped rather
than merely docked. This is deliberately conservative — the goal is to protect
researcher time, not to make numbers look good.

### 3.3 Priority bands

| Money | Priority | Meaning |
|---:|---|---|
| 85–100 | `P1_START_NOW` | High expected value, grounded, low effort/risk |
| 65–84 | `P2_HIGH` | Strong candidate; time-box and start |
| 45–64 | `P3_MEDIUM` | Real but gated by blockers or duplicate exposure |
| 30–44 | `P4_LOW` | Monitor; only pursue if capacity remains |
| 0–29 | `P5_DEFER` | Insufficient value or evidence; do not spend hours |

### 3.4 Worked examples (illustrative projections, not results)

Weights are a first policy, not a calibration. The numbers below show the model
behaves as intended.

**A. Real corpus lead — `CVE-2026-1557 → dell`** (P=80, R=20, CVSS 7.5,
`public_poc=true`, `exploit_available=true`, `nuclei_candidate=true`, R23 HIGH
evidence, R24 TRUSTED/LOW evidence, blockers = generic tech / plugin / component
/ version unknown, report exists):

- `V = 0.30*80 + 0.35*20 + 0.20*75 + 0.15*85 ≈ 59`
- `C = 73` (structured + R23 HIGH + R24 TRUSTED − blocker/unknown caps) → HIGH
- `E = 42` (PoC discount, but +12/+10/+10/+15 for the four blockers) → 30–60 min
- `K = 30 (DUP) + 40 (FP) = 70` → risk cap
- `raw ≈ 56.6 → 57`; `K≥70` caps at **55** → `P3_MEDIUM`
- Action: `VERIFY_ASSET_MATCH_FIRST` (plugin not observed, version unknown)

**B. Synthetic medium CVE with exact component match** (P=55, R=70, CVSS 5.3,
`public_poc=true`, `exploit_available=false`, observed assets, version unknown):

- `V ≈ 59`; `C = 65`; `E = 10` (15–30 min); `K = 28`
- `M = 67` → `P2_HIGH`

**C. Synthetic critical CVE with weak asset relevance** (P=90, R=20, CVSS 9.5,
no PoC, no component/parameter, generic tech only, no R23/R24 results):

- `V ≈ 53`; `C = 28 (LOW)`; `E = 100`; `K = 40`
- `M ≈ 42` → `P4_LOW`

B > A > C in Money terms even though C has the highest CVSS: exactly the
economic behavior required.

---

## 4. Proposed Formulas / Weights (single reference)

| Component | Formula | Weights |
|---|---|---|
| VALUE | `0.30*priority + 0.35*relevance + 0.20*severity + 0.15*exploit_maturity` | 30/35/20/15 |
| CONFIDENCE | `clamp(50 + 15*structured_cvss + 20/12/5*best_R23_conf + 20/12/6*best_R24_tier + 10/5*relevance_class − 15*conflicts(cap −30) − blocker_penalty(cap −20) − 2*unknowns(cap −20), 0, 100)` | see §5 |
| EFFORT | `clamp(50 − exploit_discount(cap −25) − 8*unauth − 7*no_ui − 12*specific_match − 5*parameter_known − 5*version_known + 12*version_unknown + 10*plugin_not_observed + 10*component_not_observed + 15*generic_only + 8*no_agent_result + 8*no_component, 10, 100)` | see §6 |
| RISK | `clamp(DUP,0,60) + clamp(FP,0,40)` | §3.2 |
| MONEY | `clamp(half_up(0.55*V + 0.15*C + 0.15*(100−E) + 0.15*(100−K)), 0, 100)` then caps | 55/15/15/15 |

All arithmetic is integer/half-up (`floor(x + 0.5)`), matching the R18 rounding
convention. Every constant lives in one module namespace so calibration cannot
drift; the rule version increments when any constant changes.

---

## 5. Confidence Model

**Definition:** confidence that the *inputs* (exploitability facts, evidence,
asset match) are grounded and mutually consistent — **not** confidence that a
target is vulnerable and **not** a payout probability. Unknown stays unknown; a
missing signal never subtracts points.

| Adjustment | Value |
|---|---|
| Base | +50 |
| R15 `cvss.source == "structured"` | +15 |
| Best R23 evidence confidence: HIGH / MEDIUM / LOW | +20 / +12 / +5 |
| Best R24 evidence tier: TRUSTED / SEMI_TRUSTED / DISCOVERY_ONLY | +20 / +12 / +6 |
| R17 relevance class HIGH / MEDIUM | +10 / +5 |
| Each R15 `conflicts[]` entry | −15 (cap −30) |
| Blockers: `only generic technology match` | −12 |
| Each of `affected plugin not observed`, `asset component not observed`, `asset version unknown` | −6 (blocker total cap −20) |
| Each unique R16/R17/R22 unknown | −2 (cap −20) |
| No R15/R16 knowledge document | cap `C ≤ 35` |

Classes: `HIGH ≥ 70`, `MEDIUM ≥ 45`, otherwise `LOW`.
Deliver `confidence_basis[]` (the fired adjustments) so the researcher sees
*why*, and keep `asset_match` separate: a HIGH-confidence CVE fact set with a
technology-only asset match must read as "vulnerability facts confident; asset
match unproven", never as "target likely vulnerable".

---

## 6. Effort Model

**Definition:** deterministic estimate of researcher time to reach a
go/no-go decision or a reportable check for this lead. It is a heuristic, not a
measurement; there is no stored time-tracking data in the pipeline.

| Adjustment | Value |
|---|---|
| Base | 50 |
| `public_poc=true` | −20 |
| `exploit_available=true` | −10 (combined exploit discount capped at −25) |
| `authentication_required=false` | −8 |
| `user_interaction_required=false` | −7 |
| R17 exact product/plugin/component/path match | −12 |
| Affected parameter identified | −5 |
| Affected version known | −5 |
| `asset version unknown` blocker | +12 |
| `affected plugin not observed` blocker | +10 |
| `asset component not observed` blocker | +10 |
| `only generic technology match` blocker | +15 |
| No R23 and no R24 result for the plan | +8 |
| No affected component identified | +8 |

Clamp `[10, 100]`. Bands:

| Effort score | Estimate |
|---:|---|
| 10–25 | 15–30 min |
| 26–45 | 30–60 min |
| 46–65 | 1–2 h |
| 66–85 | 2–6 h |
| 86–100 | 1–3 days |

The estimate is always published as a **range** and labelled "estimate"; it
must never be presented as a commitment.

---

## 7. Researcher Decision Output

One deterministic projection per lead (a Money Score detail object; nothing is
implemented in this stage):

```text
Money Score: 67
Priority:    P2 — HIGH
Confidence:  MEDIUM
Effort:      15–30 min (estimate)
Action:      START NOW — time-boxed

Why valuable:
  - Exact plugin/component match observed on 3 assets
  - Public PoC + exploit availability (ready-made check)
  - Persisted severity 5.3 (medium impact)
Main blockers:
  - asset version unknown (verify applicability first)
Recommended action:
  START NOW — check the plugin/version on the matched assets, then reuse the PoC.
```

Structured fields (for API/UI, sorted deterministically by Money Score then
CVE then program):

| Field | Type | Source |
|---|---|---|
| `cve_id`, `program`, `lead_id`, `plan_id`, `queue_id`, `task_id` | strings | R20–R22 |
| `money_score` | int 0–100 | §4 |
| `priority` | `P1_START_NOW`…`P5_DEFER` | §3.3 |
| `confidence` + `confidence_basis[]` | class + reasons | §5 |
| `effort` + `effort_estimate` | int + human range | §6 |
| `asset_match` | `PRODUCT` / `COMPONENT` / `PATH` / `TECHNOLOGY_ONLY` / `NONE` | R17 reasons |
| `why_valuable[]` | bounded strings | fired VALUE/EX/SEV adjustments |
| `main_blockers[]` | bounded strings | R18/R21/R22 blockers (verbatim) |
| `recommended_action` | enum | §7 rules below |
| `subscores` | `{value, confidence, effort, risk}` | §3.2 |
| `evidence_summary` | `{r23_confidence, r24_tier, sources, evidence}` | R23/R24 |
| `caps_applied[]` | bounded strings | §3.2 caps |
| `rule_version` | `"r25-1"` | fixed |
| `research_only` | `true` | forced |

Deterministic action rules (first match wins):
1. task `DONE` → `COMPLETED`; task `IN_PROGRESS` → `CONTINUE`;
   task `BLOCKED` → `UNBLOCK_OR_SKIP`.
2. `P1_START_NOW` → `START_NOW`.
3. `P2_HIGH` → `START_TIME_BOXED`.
4. `P3_MEDIUM` with asset-specific blockers (`plugin/component/version`) →
   `VERIFY_ASSET_MATCH_FIRST`.
5. `P3_MEDIUM` otherwise → `MONITOR`.
6. `P4_LOW` / `P5_DEFER` → `MONITOR` / `DEFER`.

Vocabulary stays research-only. No `VULNERABLE`/`VERIFIED`/`EXPLOITED`/
`FINDING`/`CONFIRMED`, and no "will pay / worth $X" wording.

---

## 8. Monetization Opportunities

Money Score is designed as the decision layer that makes the pipeline
commercially meaningful. Ranking below uses a simple additive heuristic over
**Revenue potential (1–5)**, **Implementation difficulty (1=easy … 5=hard)**,
**Data advantage (1–5)**, and **Time-to-market (1=slow … 5=fast)**, with
`Composite = Revenue + Data advantage + Time-to-market − Difficulty`.

| Rank | Opportunity | Rev | Diff | Data adv | TTM | Composite | What it reuses / needs |
|---:|---|---:|---:|---:|---:|---:|---|
| 1 | Premium bug-bounty prioritization tooling (internal first, then licensed seats) | 4 | 2 | 5 | 5 | **12** | Money Score + R18/R21/R22 queue; needs calibration loop only |
| 2 | Continuous CVE × asset economic alerting ("this new CVE matches your stack; score 78") | 4 | 3 | 5 | 4 | **10** | R17 asset matching + R25 scoring; needs watched asset inventory ingest |
| 3 | Vulnerability prioritization API (feed the Money Score + reasons/blockers to other teams) | 4 | 3 | 4 | 4 | **9** | read-only JSON projection; needs tenancy/auth/quota + SLA |
| 4 | Historical vulnerability intelligence (evidence-backed CVE/exploit/score timeline with provenance) | 3 | 2 | 5 | 3 | **9** | KB hashes + R23/R24 evidence + snapshots; needs outcome/time history |
| 5 | Research-as-a-service (managed research on prioritized leads) | 5 | 4 | 4 | 2 | **7** | R23/R24 + human analyst; high ops/legal load |
| 6 | Managed reconnaissance/research incl. remediation guidance | 5 | 5 | 3 | 2 | **5** | would approach active-validation boundaries; separate authorization required |

Strategic note: the defensible asset is not the score formula but the
**evidence-grounded, provenance-preserving corpus** behind it (R15 tri-states
with verbatim evidence, content-hash-grounded R23/R24 evidence, deterministic
provenance and trust tiers). That is what a raw LLM feed cannot copy. The
fastest route is #1 (prove decision value internally), then #2/#3 once an
outcome loop and a tenant-safe read API exist. **Prerequisite for all of them:
outcome capture** (which leads produced accepted findings vs. wasted time).
Without outcomes the weights remain a policy, not a product.

---

## 9. Avoid Bad Directions

Explicitly rejected — these look impressive but do not increase revenue or
research yield:

- **Cosmetic dashboard work** (new charts, skins, animations) without a
  decision effect.
- **Unnecessary LLM calls in prioritization.** The score must be deterministic;
  LLMs stay confined to research extraction, already grounded in R23/R24.
- **Generic chat UI** over security data; no researcher decision benefit.
- **Unbounded crawling / mass collection** of low-quality data (more pages ≠
  more value; R24 already caps and ranks).
- **Fabricated precision**: inventing payout figures, "probability of
  vulnerability", or CVSS-like numbers from prose.
- **Re-deriving CVSS or duplicating R16/R17/R18 logic** inside the economic
  layer.
- **Treating model-generated fields** (e.g. `bug_bounty_relevance`) as evidence.
- **Treating unknown as negative** or as a positive signal.
- **Auto-exploitation / active validation / Nuclei runs** as part of
  prioritization (safety boundary, and illegal for untrusted assets).
- **Global "security confidence" synthesized across sources** (violates the KB
  attribution model).
- **Gamified leaderboards/duplicate-counters** without real outcome data.

---

## 10. Architecture Proposal (minimal additive)

```
R15 exploitability ─┐
R16 priority ───────┼─► R18 queue ─► R21 lead ─► R22 plan
R17 relevance ──────┘        │             │
R20 task state ──────────────┼─────────────┤
R23 results (evidence) ──────┼─────────────┤   payload: cvss_score/severity
R24 loop (tier/quality) ─────┘             │   (read-only)
                                           ▼
                    NEW ai/knowledge/economics.py   (pure, deterministic)
                    ├── EconomicValue dataclass (value/confidence/effort/risk/
                    │   money/priority/action/reasons/blockers/unknowns/caps)
                    ├── assess_economic_value(lead, plan, intel, payload,
                    │   task, r23, r24) -> EconomicValue
                    └── economic_projection() for schema serialization (r25-1)
                                           ▼
                    NEW ai/schemas/knowledge.py::KnowledgeEconomicValue
                    (additive, standalone like KnowledgeResearchQueueItem)
                                           ▼
                    NEW backend/research_economics.py (read-only composition)
                                           ▼
        CLI `research_cli economics` │ API GET /api/research/economics
        (list + detail, key-gated,   │ UI: Money Score column + lead/plan
        bounded, deterministic)      │ detail block (minimal, decision-first)
```

Rules:
- **No new persistence in v1.** Everything is an on-demand projection, exactly
  like R21/R22. Optional outcome/snapshot storage is a later, separately
  authorized stage.
- **No duplicate engines.** R16 priority, R17 relevance and R18 blockers are
  consumed as-is; the economic layer only composes and adds impact/maturity/
  effort/risk.
- **No changes to R15–R24 modules.** Existing functions keep their signatures
  and byte-stable outputs.
- **Read-only reads** of `ai_data/knowledge`, `ai_data/research/*.cli.json`,
  `ai_data/research/agent/*.json`, `ai_data/reports/*`, `programs/*.json`.
- **CLI/API/UI are presentational only**; all logic lives in the pure module so
  it is unit-testable offline.

---

## 11. Recommended Implementation Order

1. **R25.2 — Deterministic economics engine + tests.**
   `ai/knowledge/economics.py`, additive
   `KnowledgeEconomicValue` schema, focused offline unittest suite (weights,
   caps, unknown-neutrality, determinism, idempotence, no network/LLM).
   Recompute the real corpus and freeze `r25-1` constants. No UI/API.
2. **R25.3 — Read-only projection + CLI.**
   `backend/research_economics.py` (compose R21 leads + R22 plans + R23/R24
   artifacts + payload severity + R20 status), CLI
   `python -m ai.research_cli economics [--cve --program --limit --json]`.
3. **R25.4 — API + minimal decision UI.**
   `GET /api/research/economics` and `/api/research/economics/{lead_id}`
   (key-gated, bounded), one Money Score column on the leads list and a compact
   decision block on lead/plan detail. No redesign.
4. **R25.5 — Outcome capture + calibration loop.**
   Record researcher outcomes per lead (accepted/duplicate/dead/wasted time)
   and report score-band vs outcome. This is the monetization prerequisite and
   the only justification for changing weights (`r25-2`).
5. **R25.6 — Close data gaps (optional, separately authorized).**
   Asset-version matching (extend R17 inputs), parameter-match fix (use R17
   `parameters` or remove the dead `PARAMETER_OBSERVED` path), program reward
   metadata, exploit freshness with an explicit `as_of` input.
6. **R25.7+ — Monetization surfaces.**
   Read API + alerting + historical intelligence, only after R25.5 shows the
   score correlates with real outcomes.

Order rationale: pure engine first (cheapest to validate and impossible to
misuse), then read-only surfaces, then the feedback loop that turns a policy
into a product. No step requires touching R15–R24 internals.

---

## 12. Explicit Non-Goals

- No code, data, Mongo, systemd, or `.env` changes in this stage.
- No implementation of the score or UX yet.
- No LLM participation in prioritization; no new LLM calls.
- No target interaction, scanning, exploitation, PoC execution, browser or
  Nuclei runs; no 5B–5J path.
- No findings, alerts, or production mutation.
- No payout/dollar predictions or guarantee language.
- No cosmetic dashboard redesign.
- No duplicate priority/relevance/queue engine.
- No treating model-generated fields as evidence.
- No clock-dependent "freshness" in v1 (requires explicit `as_of`).
- No global security-confidence synthesis across sources.
- No commit/push.

---

## 13. Safety Boundaries

- **Deterministic and local:** pure function of persisted local artifacts;
  no network, no DNS, no LLM, no subprocess, no timers.
- **Read-only:** no writes, no persistence, no Mongo, no production data
  mutation; all inputs are the same local files the R19–R24 read layers use.
- **Research-only semantics:** outputs never say `VULNERABLE`/`VERIFIED`/
  `EXPLOITED`/`FINDING`/`CONFIRMED`; Money Score is research-attention
  prioritization, not a vulnerability verdict or payout forecast.
- **Unknown preservation:** unknown inputs add no points and are surfaced in
  `unknowns[]`/`evidence_summary`; `false` and `unknown` are never conflated.
- **Provenance retained:** every contributing signal keeps its R15–R24 source;
  confidence is per-input grounding, never a synthesized global claim.
- **Bounded:** fixed input sizes, capped lists, bounded strings, clamped
  scores; no unbounded scans.
- **Model-generated data is labeled and excluded** from scoring in v1;
  if ever used it must carry `model_generated=true` and a capped weight.
- **No target/program data leaves the boundary:** the economic layer consumes
  only already-persisted CVE/research/asset records; it performs no outbound
  requests, so R24's target-isolation invariants are preserved.
- **No secrets:** no credentials, `.env` values, or tokens are read or emitted.

---

## Agent / Model
- Model: Miuz Spark
- Stage: R25.1
- Role: Economic Research Prioritization Design
