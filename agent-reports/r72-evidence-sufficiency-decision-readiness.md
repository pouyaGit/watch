# R72 — Evidence Sufficiency & Decision Readiness

Date: 2026-09-16
Base commit: `e078353fe8362cc5194808e5f44385da1e7e9187` (R71)
Rule version: `r72-1`

## 1. Objective

Add the next research layer after R71: for every R71 acquisition plan produce
a bounded readiness record that answers

    "Do we currently have enough evidence to make a meaningful research
     decision about this hypothesis, and if not, exactly what evidence is
     still blocking the decision?"

R72 is advisory, research-only, human-reviewable, evidence-grounded and
fail-closed. It is not a vulnerability confirmation engine, not a finding
generator, not an exploitability scorer and not an authorization mechanism.

## 2. Architecture inspected first

| Concept | Stage | Finding |
| --- | --- | --- |
| `ai/knowledge/research_outcome_planner.py` | R70 | Outcomes/actions, category->gap map, closed evidence states, safety block; source of truth for actions |
| `ai/knowledge/research_evidence_acquisition_planner.py` | R71 | Requirement split (`AVAILABLE`/`MISSING`), sources, ordered steps, expected result, stopping condition; source of truth for acquisition |
| `ai/knowledge/evidence_confidence_aggregator.py` + `ai/schemas/evidence_confidence.py` | R31.15 | Confidence level over R31.13/R31.14 plans with completeness levels, limiting factors and closed blocker codes; input-coupled to the Asset<->CVE chain |
| `ai/knowledge/evidence_prioritization_planner.py` | R31.14 | R31.13-only prioritization; not a sufficiency concept |
| `ai/knowledge/research_prioritization.py` | R55.4 | Finding-intelligence priority ranking; "priority is not confidence", `confirmation_state = NOT_CONFIRMED` |

## 3. Reuse / composition decision

- The R31.15 confidence framework cannot consume R70/R71 research-layer
  outputs, and re-deriving an R31-style confidence level here would create a
  competing confidence framework. R72 therefore computes **no confidence level
  and no probability**.
- R72 composes: it consumes the R71 requirement statuses (the research-layer
  completeness signal), mirrors R31.15's *conventions* (closed completeness
  vocabularies, explicit blocker codes, bounded/sanitized read-only
  projections, fail-closed unknown handling), and reuses R70's
  `SAFETY_BLOCK`, `EVIDENCE_STATES` and rule version plus the R71 rule
  version.
- R70 remains the source of truth for outcomes/actions; R71 remains the
  source of truth for acquisition plans. R72 re-derives neither gap nor
  acquisition and never writes back.

## 4. Readiness model

New deterministic engine
`ai/knowledge/research_decision_readiness_planner.py`:

- `build_readiness_records(action_plan, acquisition_plan)` — one bounded
  record per R71 plan (input order).
- `summarize_readiness(records)` — bounded summary (counts, bands, top
  record).
- `plan_decision_readiness(action_plan, acquisition_plan, limit=8)` — the
  composed result (`rule_version="r72-1"`, source rule versions consumed).

Per record: `readiness_id` (`R1`...), `order`, `plan_ref`, `action_ref`,
`hypothesis_refs`, `hypothesis_titles`, `hypothesis_count`, `category`,
`gap_id`, `evidence_gap`, `evidence_state` (+`evidence_states`),
`required_evidence` (kind, class, status), `available_evidence`,
`missing_evidence`, `acquisition_status`, `sufficiency_state`,
`decision_state`, `blocking_requirements`, `blocking_codes`,
`non_blocking_missing_requirements`, `decision_basis`, `next_decision_step`,
`stop_condition`, `safety`, advisory flags.

Requirement classes (closed): `SUPPORT` (object reference, input surface,
endpoint purpose, technology/version identity, supporting observation, watch
signal) vs `DECISION` (authorization/ownership, fetch/destination, response
context/encoding, query response/reproducibility, token/validation/flow/redirect
artifacts, component binding, method/auth, response behavior, corroborating
observation). Unknown kinds default to `DECISION` (fail-closed).

R72 does not copy raw observation refs/facts: `available_evidence` carries
kind + class only, so the new output surface adds no raw-data leak path.

## 5. Sufficiency states

Closed vocabulary: `INSUFFICIENT`, `PARTIALLY_SUFFICIENT`,
`SUFFICIENT_FOR_REVIEW`.

`SUFFICIENT_FOR_REVIEW` means only that a human researcher has enough evidence
for a meaningful review decision. It never means the vulnerability is real and
never means "confirmed".

## 6. Decision states

Closed vocabulary: `NEEDS_EVIDENCE`, `READY_FOR_HUMAN_REVIEW`,
`REMAINS_UNRESOLVED`. No `VULNERABLE`/`EXPLOITABLE`/`CONFIRMED` state exists.
Acquisition status is `PLANNED`, `NOT_REQUIRED` or `UNAVAILABLE`.

## 7. Deterministic rules

Let `decision_missing` / `decision_available` be the missing/available
`DECISION`-class requirements of the R71 plan (first match wins):

1. no requirements at all -> `INSUFFICIENT` + `REMAINS_UNRESOLVED` +
   `UNAVAILABLE`, basis `NO_REQUIREMENTS`, blocker `NO_REQUIRED_EVIDENCE`;
2. `decision_missing` empty -> `SUFFICIENT_FOR_REVIEW` +
   `READY_FOR_HUMAN_REVIEW`, basis `ALL_REQUIRED_EVIDENCE_AVAILABLE`,
   acquisition `PLANNED` if any support requirement is still missing else
   `NOT_REQUIRED`;
3. `decision_available` empty -> `INSUFFICIENT` + `NEEDS_EVIDENCE`, basis
   `NO_DECISION_EVIDENCE`, all missing decision requirements are blocking;
4. otherwise -> `PARTIALLY_SUFFICIENT` + `NEEDS_EVIDENCE`, basis
   `PARTIAL_DECISION_EVIDENCE`, missing decision requirements are blocking.

Structural-only support therefore remains `INSUFFICIENT` even with
`priority=HIGH`/`confidence=HIGH`: sufficiency is never inferred from
priority, confidence, skill presence, parameter/endpoint/technology names or
model wording. Unknown R71 statuses default to `MISSING`.

## 8. R71 integration

- `required_evidence`, `available_evidence` and `missing_evidence` are the
  R71 split verbatim (kind + class).
- `acquisition_status` is derived from the R71 missing set.
- `blocking_requirements`/`blocking_codes` identify the missing
  decision-critical R71 requirements (descriptions from the R71 plan).
- `next_decision_step` references the R71 plan and action:
  `ACQUIRE_MISSING_DECISION_EVIDENCE` with the R71 sources and the blocking
  targets, or `HUMAN_REVIEW_SUFFICIENT_EVIDENCE`, or
  `NO_ACTION_UPSTREAM_PLAN_INVALID`.
- `stop_condition` is the R71 plan's stopping condition (a fixed default is
  used only when the plan is malformed).
- No second acquisition plan is generated.

## 9. Category handling

R72 consumes the R70/R71 category and gap mapping unchanged (IDOR/BOLA ->
`OBJECT_AUTHORIZATION`, SSRF -> `SERVER_SIDE_FETCH`, XSS ->
`REFLECTION_CONTEXT`, SQLI -> `QUERY_BEHAVIOR`, JWT -> `TOKEN_VALIDATION`,
OAUTH -> `OAUTH_FLOW_ARTIFACTS`, CVE_RESEARCH -> `COMPONENT_MAPPING`, RECON ->
`ENDPOINT_BEHAVIOR`). The category itself never makes a hypothesis
sufficient; only requirement availability does. Category-aware blocking is
covered by tests (e.g. JWT with an observed token artifact but no validation
artifact blocks on `VALIDATION_ARTIFACT`; CVE blocks on `COMPONENT_BINDING`).

## 10. Correlation

R72 preserves R70/R71 correlation exactly: one readiness record per R71 plan,
and R71 plans are already one-per-correlated-R70-action. On the real Mongo run
the two accepted RECON hypotheses (`H1`, `H2`) produced one action, one
acquisition plan and one readiness record covering `H1, H2` — not duplicates.

## 11. Safety

Records and envelope carry the unchanged safety block:
`advisory=true`, `research_only=true`, `execution_performed=false`,
`vulnerability_confirmed=false`, `exploit_authorized=false`,
`confirmation_state=NOT_CONFIRMED`, `human_authority_required=true`.

- No execution engine, no target requests, no authorization.
- Mongo read-only (verified: identical collection counts before/after),
  Indeed only, R61 caps unchanged.
- No credentials, raw URLs, IPs or Mongo identifiers in generated output
  (hygiene asserted in tests and inspected in artifacts).

## 12. Focused tests

`ai/test_research_decision_readiness_planner.py` — **26 passed**: R71 plan ->
readiness record, requirement classification, available vs missing flow,
insufficient (incl. structurally-only with HIGH priority), partial
sufficiency, sufficient-for-review, support-not-blocking, closed
sufficiency/decision/basis/instruction vocabularies, blocking identification,
R71 plan/action/sources/targets references, R71 stopping condition, category
awareness, correlation, evidence-state reporting, bands/summary,
deterministic output, empty/malformed fail-closed, missing-required-evidence
unresolved, unknown status -> missing, limit validation, safety flags,
no confirmation/execution semantics, sensitive-data hygiene.

## 13. Local E2E

- `tests/local_e2e/test_r64_research.py` — **118 passed** (includes 6 new R72
  envelope/readiness/correlation/category/persistence integration tests).
- `pytest tests/local_e2e -q` — **260 passed, 63 subtests**.
- Adjacent suites (R70/R71 planners, R69 skills, OpenRouter, LLM, research
  priority, evidence confidence aggregator, R31.12/R31.13/R31.14 planners) —
  **400 passed** in the combined run.

## 14. Real fixture run

Provider/model: real `openrouter` /
`nvidia/nemotron-3-ultra-550b-a55b:free`; runtime-only 900s timeout wrapper at
`/tmp/opencode/r71_live_run.py` (loads `.env`, replaces only `_real_provider`);
repository unchanged. One real call, no retry.

- Status: `COMPLETED` (2 accepted / 0 rejected).
- Artifact: `ai_data/research/r72/r64-indeed-2ea29240244dcf5b.json`
  (29,308 bytes), `research_run_version = r72-1`.
- Readiness: `R1 [IDOR] OBJECT_AUTHORIZATION INSUFFICIENT / NEEDS_EVIDENCE`
  (blocking `AUTHORIZATION_OUTCOME`, `OWNERSHIP_BINDING`); `R2 [RECON]
  ENDPOINT_BEHAVIOR INSUFFICIENT / NEEDS_EVIDENCE` (blocking `METHOD_AUTH`,
  `RESPONSE_BEHAVIOR`).
- Hygiene: no `://`, no `sk-`, no `Bearer`; safety block unchanged.

## 15. Real Mongo / Indeed run

Read-only, Indeed-only, R61 caps unchanged (subdomains 500, live_subdomains
500, http 300, urls 1000, endpoints 1000; fetch factor 5); 81 evidence items;
signals `IDOR`, `RECON`. One real call, no retry.

- Status: `COMPLETED_WITH_REJECTIONS` (2 accepted / 2 rejected).
- Artifact: `ai_data/research/r72/r64-indeed-b1ebaaf9f2211f82.json`
  (21,983 bytes), `research_run_version = r72-1`,
  `openrouter / nvidia/nemotron-3-ultra-550b-a55b:free`.
- R70: `A1 [LOW] RECON` for `H1, H2`; R71: one `P1 ENDPOINT_BEHAVIOR` plan;
  R72: `R1 [RECON] ENDPOINT_BEHAVIOR INSUFFICIENT / NEEDS_EVIDENCE`,
  `evidence_state = STRUCTURE_AND_SIGNAL`, available `ENDPOINT_PURPOSE`,
  `WATCH_SIGNAL`, blocking `METHOD_AUTH`, `RESPONSE_BEHAVIOR`,
  basis `NO_DECISION_EVIDENCE`, next step
  `ACQUIRE_MISSING_DECISION_EVIDENCE` via plan `P1`/action `A1`.
- Zero writes: 11 collections (programs, subdomains, live_subdomains, http,
  urls, endpoints, dns_brute_status, change_event, xss_findings,
  execution_authorizations, task_run) identical before and after.

This is the expected honest outcome for a mostly structural bounded dataset:
`INSUFFICIENT` + `NEEDS_EVIDENCE`, with the exact blocking evidence named.

## 16. R70/R71 comparison

- R70: "What should I investigate?" -> ranked, correlated actions.
- R71: "What evidence should I acquire, and what already exists?" -> bounded
  acquisition plans with sources, ordered steps, expected result and stop
  condition.
- R72: "Do I have enough evidence to decide yet?" -> a closed sufficiency
  state, a closed decision state, explicit blockers, a decision basis, and a
  next decision step that points back at the R71 plan. A hunter no longer has
  to interpret `missing_evidence` themselves to know whether the hypothesis is
  decidable.

## 17. Actual quality improvement

- Decision readiness is now explicit and honest: on both real runs every
  accepted hypothesis is `INSUFFICIENT` / `NEEDS_EVIDENCE` with the precise
  blocking requirements named, which is the truthful state of a
  structural-only bounded sample.
- The layer refuses to upgrade on priority/confidence/names, so it cannot
  overstate weak leads.
- Correlation survives the whole chain (two RECON hypotheses -> one action ->
  one plan -> one readiness record).
- The artifact now contains a reviewer-readable "can we decide yet?" block
  alongside the investigation and acquisition plans.

## 18. Limitations

- Sufficiency is a deterministic gate over the R71 requirement split; it does
  not judge whether the acquired evidence, once obtained, would be convincing
  (that remains human review).
- Because the bounded Indeed snapshot contains no response/authorization/
  token/redirect observations, real output is expected to remain
  `INSUFFICIENT` until behavior evidence is actually acquired outside this
  plan-only layer.
- `PARTIALLY_SUFFICIENT` and `SUFFICIENT_FOR_REVIEW` are reachable and
  covered by tests, but not observed on this bounded real dataset.
- No probabilities, severity, exploitability or CVSS are produced, by design.

## 19. Files changed

- `ai/knowledge/research_decision_readiness_planner.py` (new)
- `ai/test_research_decision_readiness_planner.py` (new)
- `tests/local_e2e/r64_research.py` (integration + `r72-1`)
- `tests/local_e2e/test_r64_research.py` (integration + version update)
- `agent-reports/r72-evidence-sufficiency-decision-readiness.md` (this report)

R65/R66 validation gates, R68 evidence contract, R69 skill layer, R70 action
planner, R71 acquisition planner and the safety boundary are unchanged.

## 20. Commit

One local commit: `feat(ai): add evidence sufficiency decision readiness`
(hash reported in the final task response). No push.
