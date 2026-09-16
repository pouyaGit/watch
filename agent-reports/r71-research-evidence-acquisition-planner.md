# R71 — Research Evidence Acquisition Planner

Date: 2026-09-16
Base commit: `497fc151cb732ce549d7770f48f0015b283f0979` (R70)
Rule version: `r71-1`

## 1. Objective

Add the next practical layer after R70: for every ranked R70 research action,
produce a bounded, deterministic **evidence acquisition plan** that answers

    "What evidence should the researcher acquire next to resolve this
     hypothesis, which required evidence already exists, what would the
     acquired evidence change, in what order and from which bounded sources
     should it be acquired, and when do we stop?"

R71 is plan-only: it never executes an acquisition, never contacts a target,
never sends requests, never calls an LLM, and never confirms anything.

## 2. Existing planners inspected first (architecture-first)

| Planner | Stage | Finding |
| --- | --- | --- |
| `ai/knowledge/hunt_action_planner.py` | R31.12 | Selects one Asset<->CVE hunt action from R31.10/R31.11 projections; gap vocabulary `GAP_VERSION`, `GAP_HTTP`, ... |
| `ai/knowledge/evidence_acquisition_planner.py` | R31.13 | Maps one R31.12 action to an acquisition method/target/completion condition; input-coupled to `hunt_priority` + `hunt_actionability` + `hunt_action_plan` |
| `ai/knowledge/evidence_prioritization_planner.py` | R31.14 | Re-prioritizes one R31.13 plan; consumes only R31.13 output |
| `ai/knowledge/research_outcome_planner.py` | R70 | Correlation/ranking of validated research hypotheses; category->gap mapping, closed safety block |

The R31.12–R31.14 chain plans acquisition for Asset<->CVE candidates and is
coupled to the R31.10/R31.11/R31.12 projection shape and gap vocabulary. It
cannot consume a validated LLM research hypothesis or an R70 action without an
invented foreign mapping.

## 3. Reuse / composition decision

R71 **composes with** the existing framework instead of creating a competing
one:

- The shared acquisition-method vocabulary is imported from R31.13:
  `COMPONENT_IDENTITY_LOOKUP` (component mapping) and
  `HTTP_BEHAVIOR_REVIEW` (endpoint behaviour); R71 extends the vocabulary with
  the research-category methods the R31 chain does not have
  (`AUTHORIZATION_BEHAVIOR_REVIEW`, `FETCH_BEHAVIOR_REVIEW`,
  `RESPONSE_CONTEXT_REVIEW`, `QUERY_BEHAVIOR_REVIEW`,
  `TOKEN_ARTIFACT_REVIEW`, `OAUTH_ARTIFACT_REVIEW`,
  `ADDITIONAL_EVIDENCE_REVIEW`).
- The category order, category->gap mapping (`gap_id_for`), R70 safety block
  and R70 rule version are imported from
  `ai/knowledge/research_outcome_planner.py`, so **R70 remains the single
  source of truth for gaps and actions**.
- R69 skills are consumed through `SIGNAL_SKILLS` / `skill_by_id`: each plan
  carries the relevant `skill_refs` and the skill's bounded
  `required_evidence`.
- Conventions are mirrored exactly (pure/offline, closed vocabularies,
  bounded/sanitised text, documented integer factor points, no probabilities,
  read-only result dicts with a rule version).

No R31 file was modified; no parallel acquisition framework was created.

## 4. Implementation

New deterministic engine
`ai/knowledge/research_evidence_acquisition_planner.py`:

- `build_evidence_acquisition_plans(action_plan)` — one bounded plan per R70
  action (input order).
- `order_evidence_acquisition_plans(plans)` — deterministic ordering.
- `summarize_evidence_acquisition(plans)` — bounded summary.
- `plan_evidence_acquisition(action_plan, limit=8)` — the composed result
  (`rule_version="r71-1"`, `source_action_rule_version` consumed from R70).

Integration in `tests/local_e2e/r64_research.py` (rule version `r71-1`):

- after R70, `plan_evidence_acquisition(action_plan)` is added to the
  envelope as top-level `acquisition_plan`;
- the CLI prints a bounded
  `EVIDENCE ACQUISITION PLAN (ranked, advisory only)` section;
- R65/R66 validation, R68 evidence resolution, R69 skills, the safety block,
  provider and Mongo behaviour are unchanged.

## 5. Acquisition model

Per plan: `plan_id` (`P1`...), `order`, `action_ref`, `gap_id`, `category`,
`hypothesis_refs`, `hypothesis_count`, `skill_refs`, `skill_required_evidence`,
`acquisition_method`, `evidence_gap`, `acquisition_goal`, `required_evidence`
(per item: `requirement_kind`, `description`, `status`, `information_gain`,
`evidence`), `currently_available_evidence`, `missing_evidence`,
`hypothesis_missing_evidence`, `acquisition_sources`, `acquisition_steps`
(`step`, `source`, `operation`, `requirement_kinds`, `expected`, `risk`,
`information_gain`, `depends_on`), `expected_result`, `decision_impact`,
`decision_impact_note`, `stopping_condition`, `acquisition_priority`
(`information_gain`, `acquisition_risk`, `reuse_hypotheses`, `order_key`),
`safety`, advisory flags.

Closed vocabularies:

- sources: `EXISTING_SNAPSHOT`, `EXISTING_EVIDENCE`,
  `AUTHORIZED_TEST_CONTEXT`, `RESPONSE_OBSERVATION`, `DOCUMENTATION`,
  `COMPONENT_METADATA`, `VERSION_MAPPING`, `HUMAN_REVIEW`;
- statuses: `AVAILABLE`, `MISSING`;
- decision impact: `SUPPORTS`, `WEAKENS`, `RESOLVES`, `REMAINS_UNRESOLVED`
  (mapped from *if confirming / if contradicting / if complete / if
  unavailable*; explicitly a prediction, not an occurrence);
- risks: `LOW`, `MEDIUM` (`AUTHORIZED_TEST_CONTEXT` is the only medium-risk
  source; no high-risk source exists in R71).

## 6. Evidence availability logic (existing evidence first)

For every requirement kind, R71 inspects only the canonical evidence the R70
outcomes already carry (canonical observation refs and derived Watch signals)
and matches it with a bounded per-requirement matcher (ref-kind set and, for
object references, the object-reference path pattern):

- matching evidence exists -> `AVAILABLE` with the bounded evidence entries;
- no matching evidence -> `MISSING`;
- no matching R70 outcome for a referenced hypothesis -> every requirement is
  `MISSING` (fail-safe: the planner never claims evidence exists).

Only missing requirements generate acquisition steps; available items are
never requested again and appear in step 1 (`EXISTING_EVIDENCE`) as
confirmation of the available/missing split. When everything is available the
plan collapses to the existing-evidence step and states *"No new acquisition
is required"*.

Example (fixture, IDOR):

    AVAILABLE: OBJECT_REFERENCE (path with {id}), WATCH_SIGNAL (IDOR)
    MISSING:   AUTHORIZATION_OUTCOME, OWNERSHIP_BINDING

## 7. Category mappings

| Category | Gap | R71 method | Core requirements | Sources |
| --- | --- | --- | --- | --- |
| IDOR / BOLA | `OBJECT_AUTHORIZATION` | `AUTHORIZATION_BEHAVIOR_REVIEW` | object reference, authorization outcome, ownership binding, signal | snapshot, response observation, authorized test context, human review |
| SSRF | `SERVER_SIDE_FETCH` | `FETCH_BEHAVIOR_REVIEW` | input surface, fetch behavior, destination control, signal | snapshot, response observation, authorized test context, human review |
| XSS | `REFLECTION_CONTEXT` | `RESPONSE_CONTEXT_REVIEW` | input surface, response context, encoding, signal | snapshot, response observation, documentation, human review |
| SQLI | `QUERY_BEHAVIOR` | `QUERY_BEHAVIOR_REVIEW` | input surface, query response, reproducibility, signal | snapshot, response observation, authorized test context, human review |
| JWT | `TOKEN_VALIDATION` | `TOKEN_ARTIFACT_REVIEW` | token artifact, validation artifact, signal | snapshot, response observation, documentation, human review |
| OAUTH | `OAUTH_FLOW_ARTIFACTS` | `OAUTH_ARTIFACT_REVIEW` | flow artifact, redirect handling, validation artifact | snapshot, response observation, documentation, human review |
| CVE_RESEARCH | `COMPONENT_MAPPING` | `COMPONENT_IDENTITY_LOOKUP` (R31.13) | technology, version, component binding, signal | snapshot, component metadata, version mapping, documentation, human review |
| RECON | `ENDPOINT_BEHAVIOR` | `HTTP_BEHAVIOR_REVIEW` (R31.13) | endpoint purpose, method/auth, response behavior, signal | snapshot, response observation, documentation, authorized test context, human review |
| unknown | `ADDITIONAL_EVIDENCE` | `ADDITIONAL_EVIDENCE_REVIEW` | supporting observation, corroborating observation | snapshot, response observation, human review |

Sources are category-appropriate by construction (e.g. CVE_RESEARCH never
uses `AUTHORIZED_TEST_CONTEXT`; only behaviour categories do). `BOLA`/`IDOR_BOLA`
are accepted as IDOR aliases. A name is not evidence: a bare `assertion`
parameter is **not** treated as an available OAuth flow artifact (fixed during
real-run review; see §12).

## 8. Acquisition ordering

Steps: step 1 is always `EXISTING_EVIDENCE` (prerequisite: confirm the
available/missing split and reuse what exists). Remaining steps are candidates
`(missing requirement, eligible source)` sorted by documented bounded points:

1. information gain (behaviour/authorization/token/flow items 20,
   identity/mapping/signal items 15, surface/purpose items 10; human review 5
   as the escalation fallback),
2. risk rank (`LOW` 0, `MEDIUM` 1),
3. stable source order (existing snapshot, stored response observation,
   component metadata, version mapping, documentation, authorized test
   context, human review),
4. requirement prerequisite order as final tie-break.

Steps are capped at 6 and each step depends on step 1.

Plans are ordered by: information gain desc, risk asc, reuse (hypothesis
count) desc, canonical category order, gap id, action ref.

## 9. Correlation

R71 does not re-correlate hypotheses; it consumes R70's correlation. Every R70
action already merges hypotheses that share a gap, and its
`hypothesis_refs`/`hypothesis_count` become the plan's references, so shared
uncertainty produces **one** plan with shared requirements and shared ordered
steps. Real evidence: Mongo attempt 2 produced one `ENDPOINT_BEHAVIOR` plan
covering `H1, H3` (R70 had correlated the two RECON hypotheses into `A1`).

## 10. Safety

Plans and the result envelope carry the unchanged R70 safety block:
`advisory=true`, `research_only=true`, `execution_performed=false`,
`vulnerability_confirmed=false`, `exploit_authorized=false`,
`confirmation_state=NOT_CONFIRMED`, `human_authority_required=true`.

- No execution engine, no target interaction, no authorization; the
  `AUTHORIZED_TEST_CONTEXT` source is an *identification* step only ("this
  plan does not perform it").
- Mongo stays read-only (verified: identical collection counts before/after),
  Indeed only, R61 caps unchanged.
- No payloads, exploit strings, scanner commands or request bodies exist in
  the module; output is redacted/bounded (credential-like pairs, bearer
  tokens).

## 11. Focused tests

- `ai/test_research_evidence_acquisition_planner.py` — **27 passed** (R70
  action -> plan, existing evidence detection, missing evidence detection,
  available evidence not re-requested, parameter-name-is-not-an-artifact,
  category-aware sources, CVE never uses authorized test context, skill refs,
  correlation, deterministic ordering, gain/risk step ordering, bounds,
  decision impact, closed statuses, stopping conditions, empty/malformed
  fail-safe, limit validation, redaction/no execution vocabulary, summary).
- `ai/test_research_outcome_planner.py` — **16 passed** (R70 unchanged).
- `tests/local_e2e/test_r64_research.py` — **112 passed** (includes 5 new R71
  envelope/availability/correlation/category/persistence integration tests).
- `pytest tests/local_e2e -q` — **254 passed, 63 subtests**.
- Adjacent suites (R70 planner, R69 skills, OpenRouter, LLM, research
  priority, evidence confidence aggregator, R31.12/R31.13/R31.14 planners) —
  **374 passed** in the combined run.

## 12. Real fixture run

Provider/model: real `openrouter` / `nvidia/nemotron-3-ultra-550b-a55b:free`
(no fake provider). Runtime-only 900s timeout wrapper at
`/tmp/opencode/r71_live_run.py` (loads `.env`, replaces only `_real_provider`);
repository unchanged. Disclosed attempts:

| # | Result | Notes |
| --- | --- | --- |
| 1 | `COMPLETED_WITH_REJECTIONS` 2 accepted / 1 rejected | P1 IDOR, P2 RECON (pre step tie-break refinement) |
| 2 | `COMPLETED_WITH_REJECTIONS` 1 accepted / 3 rejected | P1 CVE_RESEARCH (pre OAuth availability fix) |
| 3 | `COMPLETED_WITH_REJECTIONS` 2 accepted / 1 rejected | final code; P1 IDOR (H1), P2 RECON (H2) |

Artifact (attempt 3, final code):
`ai_data/research/r71/r64-indeed-2ea29240244dcf5b.json`
(`COMPLETED_WITH_REJECTIONS`, summary: 2 plans, 3 requirements available,
5 missing, risk bands 2x MEDIUM; no `://`, no `sk-`, no `Bearer`).

## 13. Real Mongo / Indeed run

Read-only, Indeed-only, R61 caps unchanged (subdomains 500, live_subdomains
500, http 300, urls 1000, endpoints 1000; fetch factor 5); 81 evidence items;
signals `IDOR`, `RECON`; skills `idor-bola`, `oauth`, `api-security`.
Collection counts (11 collections incl. programs/subdomains/live_subdomains/
http/urls/endpoints/dns_brute_status/change_event/xss_findings/
execution_authorizations/task_run) are **identical before and after** all
runs: zero writes.

Disclosed attempts:

| # | Result | Notes |
| --- | --- | --- |
| 1 | `ERROR` | no hypothesis survived validation (grounding) -> no artifact |
| 2 | `COMPLETED_WITH_REJECTIONS` 3 accepted / 1 rejected | plans P1 OAUTH (H2), P2 RECON (H1, H3); pre-fix superseded artifact |
| 3 | `ERROR` | too many evidence refs on one hypothesis -> no artifact |
| 4 | `COMPLETED_WITH_REJECTIONS` 1 accepted / 5 rejected | final code; P1 RECON (H1) |

Artifact (attempt 4, final code):
`ai_data/research/r71/r64-indeed-b1ebaaf9f2211f82.json`
(`COMPLETED_WITH_REJECTIONS`, summary: 1 plan, 2 requirements available
(`ENDPOINT_PURPOSE`, `WATCH_SIGNAL`), 2 missing (`METHOD_AUTH`,
`RESPONSE_BEHAVIOR`), risk band 1x MEDIUM; provider metadata
`openrouter / nvidia/nemotron-3-ultra-550b-a55b:free`; hygiene clean).

Real output shape:

    R70: A1 [MEDIUM] RECON :: "Determine the purpose, authentication requirement
         and response behavior of the observed surface."

    R71: P1 [RECON] ENDPOINT_BEHAVIOR :: "Acquire stored endpoint purpose,
         method/authentication and response-behavior evidence..."
         Available: ENDPOINT_PURPOSE, WATCH_SIGNAL (from the selected evidence)
         Missing:   METHOD_AUTH, RESPONSE_BEHAVIOR
         Sources in order: EXISTING_EVIDENCE (verify/reuse) ->
           RESPONSE_OBSERVATION -> DOCUMENTATION -> AUTHORIZED_TEST_CONTEXT ->
           HUMAN_REVIEW
         Decision impact: SUPPORTS / WEAKENS / RESOLVES / REMAINS_UNRESOLVED
         Stop: "...keep the observation structural and the hypothesis
         NOT_CONFIRMED."

The sources and steps are grounded in the actual selected evidence and
context; nothing was manufactured.

## 14. R70 comparison

- R70 answered *"what should be investigated next, why, what evidence is
  missing"* at the action level (one review recommendation per correlated
  gap).
- R71 answers *"acquire which evidence, what already exists, from where, in
  which order, what would it change, when to stop"* at the evidence level:
  it splits requirements into `AVAILABLE`/`MISSING`, refuses to re-request
  what exists, enumerates bounded category-appropriate sources and ordered
  steps, and states the predicted decision impact.
- Correlation is preserved: R70's H1+H3 RECON action became one R71 plan with
  both hypotheses (Mongo attempt 2).
- R71 also found and removed an overclaim risk on real data: a bare
  `assertion` parameter was initially matched as an available OAuth flow
  artifact; it is now correctly `MISSING` (name != artifact).

## 15. Actual quality improvement

- The artifact now tells the researcher exactly which evidence to acquire,
  which of it is already present, the bounded source order, the expected
  result, and the safe stopping condition — the missing step between R70's
  "review endpoint behavior" and actual evidence gathering.
- Existing evidence detection is honest: paths/signals are `AVAILABLE`;
  behaviour/authorization/token/redirect/response artifacts are `MISSING`
  when the bounded context does not contain them, so plans demand the precise
  missing evidence instead of inventing findings.
- All output remains `NOT_CONFIRMED`; decision impact is explicitly a
  prediction.

## 16. Limitations

- The bounded R61/R68 context contains mostly structural observations, so
  behaviour requirements are usually `MISSING`; R71 makes that constraint
  explicit and plans the acquisition rather than pretending it happened.
- `AUTHORIZED_TEST_CONTEXT` is an identification-only source; no test is
  authorized or performed by this layer.
- Model variance on real runs: 7 real provider calls total (3 fixture,
  4 Mongo); some returned honest fail-closed `ERROR` envelopes before an
  accepted run.
- R71 ranks by documented research factors only; it carries no
  probabilities, severity or exploitability and does not judge impact.

## 17. Files changed

- `ai/knowledge/research_evidence_acquisition_planner.py` (new)
- `ai/test_research_evidence_acquisition_planner.py` (new)
- `tests/local_e2e/r64_research.py` (integration + `r71-1`)
- `tests/local_e2e/test_r64_research.py` (integration + version update)
- `agent-reports/r71-research-evidence-acquisition-planner.md` (this report)

R65/R66 validation gates, the R68 evidence contract, the R69 skill layer, the
R70 action planner and the safety boundary are unchanged.

## 18. Commit

One local commit: `feat(ai): add research evidence acquisition planner`
(hash reported in the final task response). No push.
