# R70 — Research Outcome & Action Planning

Date: 2026-09-15
Base commit: `cde786f3e8fe3032ea390d5897683396b4aca6fa` (R69)
Rule version: `r70-1`

## 1. Objective

Turn validated research hypotheses into actionable output: for every accepted
hypothesis derive the evidence gap that matters, then produce a ranked,
correlated, safe research action that answers "what should a human researcher
investigate next, and why?" — without executing anything and without changing
the R65/R66 safety boundary.

## 2. Architecture inspected

- R64–R69 pipeline (`tests/local_e2e/r64_research.py`): Mongo -> R61 snapshot
  -> R62 bridge -> R68 evidence selection -> R69 skills -> OpenRouter -> R65
  grounding -> R66 per-hypothesis validation -> artifact.
- Existing planners: `ai/knowledge/hunt_action_planner.py` (R31.12),
  `ai/knowledge/evidence_acquisition_planner.py` (R31.13),
  `ai/knowledge/evidence_prioritization_planner.py` (R31.14),
  `ai/knowledge/research_prioritization.py` (R55.4),
  `ai/knowledge/hypothesis_correlator.py` (R43.3).
- Shared schemas: `ai/schemas/research_priority.py`,
  `ai/schemas/evidence_confidence.py`, R69
  `ai/knowledge/security_skills/`.

Finding: the R31.12–R31.14 chain plans actions for Asset<->CVE candidates and
R55.4 ranks finding intelligence; no existing engine consumes validated LLM
research hypotheses. R70 reuses their conventions verbatim (plan-only, closed
vocabularies, bounded strings, no probabilities/severity, read-only result
dicts with rule versions) instead of extending them with a foreign input
shape.

## 3. Implementation

New deterministic engine `ai/knowledge/research_outcome_planner.py`:

- `build_research_outcomes(hypotheses)` — one bounded outcome per accepted
  hypothesis (input order).
- `build_research_actions(outcomes)` — correlate outcomes with the same
  evidence gap into one action.
- `rank_research_actions(actions)` — deterministic ranking.
- `summarize_research_actions(actions)` — bounded plan summary.
- `plan_research_actions(hypotheses, limit=8)` — the composed plan.

Integration (`tests/local_e2e/r64_research.py`, rule version `r70-1`):

- after R66 validation, `plan_research_actions(research["hypotheses"])` is
  added to the result envelope as the top-level `action_plan`;
- the CLI prints a bounded `RESEARCH ACTIONS (ranked, advisory only)`
  section;
- R65/R66 validation, evidence resolution, skills, safety block, provider and
  Mongo behavior are unchanged.

## 4. Action model

Outcome (per accepted hypothesis): `hypothesis_ref` (`H1`, ...), `title`,
`category`, `priority`, `confidence`, `evidence_state`, `current_evidence`
(bounded canonical observations/derived signals/selected refs),
`hypothesis_missing_evidence`, `gap_id`, `evidence_gap`,
`research_objective`, `recommended_next_action`, `expected_evidence`,
`reason_for_action`, `safe_stopping_condition`, advisory flags.

Action (per correlated gap): `action_id` (`A1`, ... ranked),
`gap_id`, `category`, `objective`, `recommended_action`,
`expected_evidence`, `reason`, `stopping_condition`, `hypothesis_refs`,
`hypothesis_titles`, `hypothesis_count`, `evidence_states`, `priority`,
`confidence`, `score` (`total` + documented `factors`), `safety`.

Closed evidence states: `CORROBORATED`, `STRUCTURE_AND_SIGNAL`,
`STRUCTURAL_ONLY`, `DERIVED_ONLY`, `NONE`.

## 5. Evidence-gap logic

Category -> gap mapping:

| Category | Gap | Core missing evidence |
| --- | --- | --- |
| IDOR | `OBJECT_AUTHORIZATION` | object identity + authorization/ownership behavior |
| SSRF | `SERVER_SIDE_FETCH` | server-side fetch behavior + controlled destination |
| XSS | `REFLECTION_CONTEXT` | reflection + execution context |
| SQLI | `QUERY_BEHAVIOR` | input influence + database/query behavior |
| JWT | `TOKEN_VALIDATION` | actual token structure + validation characteristics |
| OAUTH | `OAUTH_FLOW_ARTIFACTS` | actual OAuth/OIDC flow artifact + redirect/token evidence |
| CVE_RESEARCH | `COMPONENT_MAPPING` | technology + exact version + mapping + applicability |
| RECON | `ENDPOINT_BEHAVIOR` | purpose, behavior, authentication, response evidence |
| (unknown) | `ADDITIONAL_EVIDENCE` | evidence tied to the stated uncertainty |

Each gap carries a fixed, safe objective/action/expected-evidence/reason/
stopping condition. The planner never claims the gap evidence exists; it
states what is missing and what offline review would resolve it.

## 6. Ranking logic

Bounded, documented integer factor points (no probabilities):

- priority: HIGH 30 / MEDIUM 20 / LOW 10;
- confidence: HIGH 20 / MEDIUM 10 / LOW 5 / UNKNOWN 0;
- evidence completeness: CORROBORATED 15 / STRUCTURE_AND_SIGNAL 5 /
  STRUCTURAL_ONLY 2 / DERIVED_ONLY 0 / NONE 0;
- information gain: behavior gaps 20 / component mapping 15 / structural 10;
- correlation coverage: 2 points per correlated hypothesis (max 4 hypotheses).

`score.total` is the sum; ranking is total desc, then canonical category
order, then `gap_id`. Deterministic and explainable from `score.factors`.

## 7. Duplicate correlation

Outcomes are grouped by `gap_id` (category-scoped by construction). Several
hypotheses that need the same evidence produce one action listing all
`hypothesis_refs`. Demonstrated on the real Mongo run: three accepted RECON
hypotheses (internal API path, Cloudflare challenge tokens, admin parameters)
collapsed into one `ENDPOINT_BEHAVIOR` action.

## 8. Category handling

All eight specialist categories plus the generic fallback are covered.
Honest limitation: when the bounded context contains no behavior evidence for
a category, the plan can only demand that evidence (e.g., IDOR, SSRF, XSS,
SQLI, JWT, OAUTH all surface "missing behavior/token/flow evidence" actions);
it cannot manufacture an actionable finding. The real Mongo run only produced
RECON actions for exactly that reason.

## 9. Safety

Plan and action safety blocks force `advisory=true`, `research_only=true`,
`execution_performed=false`, `vulnerability_confirmed=false`,
`exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
`human_authority_required=true`. Actions are offline review steps; there is
no execution engine, no target interaction, no authorization and no
persistence change. Tests assert no execution vocabulary and no
URL/IP/Mongo-id/credential leakage.

## 10. Focused tests

- `ai/test_research_outcome_planner.py` — **16 passed, 21 subtests**
  (outcome per accepted hypothesis, category gap mapping, evidence-state
  vocabulary, duplicate correlation, distinct gaps, category-aware actions,
  action safety flags, deterministic ranking, tie-breaks, bounds/summary,
  empty/invalid handling, bounded text, no execution semantics, no sensitive
  leakage, unconfirmed state preserved).

## 11. Local E2E

- `tests/local_e2e/test_r64_research.py` — **107 passed, 37 subtests**
  (includes new R70 envelope/plan/correlation/persistence integration tests).
- `pytest tests/local_e2e -q` — **249 passed, 63 subtests**.
- Adjacent suites (`ai/test_research_outcome_planner.py`,
  `ai/test_security_skills.py`, `ai/test_openrouter.py`, `ai/test_llm.py`,
  `tests/test_research_priority.py`,
  `tests/test_evidence_confidence_aggregator.py`) — **190 passed, 48
  subtests**.

## 12. Real fixture run

- Provider/model: `openrouter` / `nvidia/nemotron-3-ultra-550b-a55b:free`
- Status: `COMPLETED_WITH_REJECTIONS` (2 accepted / 1 rejected)
- Artifact: `ai_data/research/r70/r64-indeed-2ea29240244dcf5b.json`
- Ranked actions:
  - `A1 [LOW] RECON` — endpoint purpose/authentication/response behavior
    (score 37, H1);
  - `A2 [LOW] CVE_RESEARCH` — technology/version component mapping
    (score 34, H2).

## 13. Real Mongo / Indeed run

- Executed: yes; read-only; Indeed only; R61 caps unchanged; 81 evidence
  items.
- Attempt 1: model responded but all 4 hypotheses were rejected by the
  unchanged R65/R66 rules (derived-signal-only IDOR; MEDIUM confidence on an
  "internal endpoint" topic capped LOW; 19 evidence refs > 8; unsupported HIGH
  confidence) -> `ERROR`, no artifact.
- Attempt 2 (one disclosed retry): `COMPLETED_WITH_REJECTIONS`, 3 accepted
  (all RECON) / 3 rejected.
- Artifact: `ai_data/research/r70/r64-indeed-ddd4831a4ecf7077.json`
- Ranked action: `A1 [MEDIUM] RECON` — `ENDPOINT_BEHAVIOR` (score 51)
  covering H1 internal API path, H2 Cloudflare challenge tokens, H3 admin
  parameters; objective/expected evidence/reason/stop condition as printed.
- No Mongo writes (collection counts identical before/after).

## 14. R68 comparison

- R68 output: hypotheses with resolved evidence and per-hypothesis validation
  — e.g. "Possible IDOR" with `missing_evidence` listed but no plan.
- R70 output: the same hypothesis now yields a bounded outcome and a ranked
  action: missing `OBJECT_AUTHORIZATION` evidence, the offline review step,
  the expected evidence, the reason, and the stopping condition. The
  researcher no longer has to interpret `missing_evidence` themselves.

## 15. R69 comparison

- R69 improved hypothesis quality (skills reduced name-based over-inference)
  but stopped at "hypothesis + listed gaps".
- R70 turns those gaps into ranked actions, correlates duplicate gaps, and
  makes the next step explicit. R69 fixture accepted 3 hypotheses with no
  plan; R70 fixture accepted 2 and produced 2 ranked actions; R70 Mongo
  accepted 3 and produced 1 correlated action.

## 16. Actual quality improvement

- The artifact now answers "what next, why, what evidence, when to stop" with
  deterministic, explainable output instead of leaving gaps implicit.
- Duplicate correlation works on real data (3 RECON hypotheses -> 1 action).
- It does not oversell: the real Mongo leads remain weak structural leads and
  the plan says exactly which behavior evidence would change that; all output
  stays `NOT_CONFIRMED`.
- Remaining limitation: with a purely structural bounded context, actions
  necessarily ask for behavior evidence that the current dataset does not
  contain. R70 makes that constraint explicit rather than inventing findings.

## 17. Files changed

- `ai/knowledge/research_outcome_planner.py` (new)
- `ai/test_research_outcome_planner.py` (new)
- `tests/local_e2e/r64_research.py` (integration + `r70-1`)
- `tests/local_e2e/test_r64_research.py` (integration + version updates)
- `agent-reports/r70-research-outcome-action-planning.md` (this report)

## 18. Commit

One local commit: `feat(ai): add research outcome action planning`
(hash reported in the final task response). No push.
