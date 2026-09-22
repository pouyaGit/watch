# AUTONOMOUS HUNT PLANNER v1

Watch — bounded autonomous research-control loop over the existing
authorized observation boundary.

Status: implemented, tested, delivered for promotion.
Baseline: `main = 928f55f` (prior Epics: AI Agent Runtime v1,
AI Agent Intelligence v1, Autonomous Research Intelligence v1).
Delivery branch: `agent/daily-development`.

============================================================
1. ARCHITECTURE (textual flow)
============================================================

OBJECTIVE -> RESEARCH STATE -> MISSING EVIDENCE -> HUNT PLAN
-> VALIDATE -> AUTHORIZATION GATE -> AUTHORIZED OBSERVATION PLAN
-> OBSERVATION RUNTIME (typed, store-boundary read) -> NEW EVIDENCE
(in-memory rows) -> EVIDENCE GATE (read-only interim decision)
-> LEARNING -> RE-PLAN or EXPLICIT TERMINATION

    +--------------------------- backend/research_agents/hunt/ ---
    | uncertainty.py    9 explicit states; terminal states never move
    | models.py         HuntObjective, HuntPlan (immutable definition +
    |                   state machine), AuthorizationRecord,
    |                   ObservationRecord, PlanTransition, versioning
    | store.py          append-only JSONL beside the runtime store:
    |                   objectives (revisions), plans (definitions),
    |                   transitions (state history + definition hash),
    |                   authorizations, observations — fcntl-locked
    | registry.py       closed observation-type registry (6 types the
    |                   codebase actually supports) + validator +
    |                   forbidden-instruction scanner
    | missing_evidence.py  deterministic rules v1 (9 rules), heuristic
    |                   information-gain labels, satisfiability flags
    | planner.py        deterministic candidates + transparent scoring;
    |                   bounded R51-shaped LLM advisor request; strict
    |                   advisor mapping; trusted final plan builder
    | authorization.py  request builder + gate wrapping the EXISTING
    |                   AuthorizationChecker + capability allowlist;
    |                   per-observation stale reverification
    | executor.py       the bounded loop + hard budgets + explicit
    |                   termination reasons (HUNT_RULE_VERSION =
    |                   "autonomous-hunt-planner-v1")
    | audit.py          hunt_lineage / hunt_authorization /
    |                   hunt_lineage_final events, scrubbed
    +------------------------------------------------------------------
    integrated by runtime.py: config fields (hunt_max_*; 0 = off),
    type-scoped FixtureObservations/ReadStoreObservations.observe
    (types=..., legacy path byte-identical), KnowledgeLoader
    query_hints, Worker._run_hunt + Worker._hunt_advisor (free-only,
    same provider abstraction), _run_phases splice BEFORE the single
    authoritative analysis/gate, research contract structured["hunt"].

Nothing new executes anything: observations still flow only through
the injected ObservationProvider (ReadStoreObservations / fixtures —
read-only store reads under job.authorization_ref); authorization only
through AuthorizationChecker; cases/evidence only through the existing
post-analysis gate path (the hunt package has NO case/evidence
persistence calls — AST-tested).

============================================================
2. RESEARCH UNCERTAINTY MODEL
============================================================

ResearchUncertainty (hunt/uncertainty.py): hypothesis,
supporting_observations, contradicting_observations, missing_evidence
(items), evidence_requested (observation ids), evidence_collected
(row keys), confidence, blockers, next_decision (state),
research_objective, scope_ref, specialist, provenance, iteration.

States (exactly nine, distinct, enforced): OPEN, NEEDS_EVIDENCE,
READY_FOR_PLANNING, PLANNED, OBSERVATION_PENDING,
OBSERVATION_COMPLETE, RESOLVED, REJECTED, BLOCKED.
Terminal: RESOLVED / REJECTED / BLOCKED — they never move again
(transition() raises UncertaintyError). "We don't have evidence"
(NEEDS_EVIDENCE) and "evidence says the hypothesis is false"
(REJECTED via hypothesis_rejected_no_signal after ALL allowed types
were observed with zero category signals) are different states and
different termination reasons.

============================================================
3. MISSING EVIDENCE ENGINE
============================================================

Deterministic rules v1 (MISSING_EVIDENCE_RULE_VERSION
"hunt-missing-evidence-v1"): capability required-type gaps,
confidence-below-required, observation-evidence count gap, type
coverage debt (allowed type never observed), category-signal absence,
technology-signal absence (CVE), knowledge-correlation absence (CVE),
parameter-inventory absence (XSS), knowledge-reference requirement.

Every item: item_id (stable hash), item_code, priority (1-4),
reason, hypothesis_affected, expected_information_gain with
gain_label="heuristic" and scoring_method="heuristic_transparent_v1",
authorization_requirements, observation_type_suggestions (registry ∩
capability ∩ still-unread), satisfiable flag. Same inputs => same
output (tested). The example contract holds: the planner emits
OBSERVATION_REQUIRED semantics (e.g. http-rows for a technology
signal), never "send XSS payload" (forbidden-instruction scanner).

============================================================
4. HUNT OBJECTIVES
============================================================

HuntObjective: objective_id, job_id, specialist, category, scope_ref,
target_context (program/subdomain/mode/allowed types), hypothesis,
research_objective ("Determine whether the authorized observation set
… contains sufficient evidence, across all observation types allowed
to <specialist>, to support or reject the hypothesis"), persisted
evidence_requirements, state, priority, provenance
(source/created_by/job_id), created_at/updated_at, iteration,
plans_created, observations_run, llm_plans_used, termination_reason,
termination_detail. Persistent + auditable: append-only revision
history in hunt_objectives.jsonl; every state change validated against
the uncertainty transition table; SOC reads revision history directly.

============================================================
5. HUNT PLAN MODEL
============================================================

HuntPlan: plan_id, objective_id, version, parent_plan_id (version
chain), scope_ref, specialist, category, reason (auditable scoring
sentence), hypotheses_addressed, observations_requested (typed,
validated), required_evidence, expected_information_gain +
gain_label="heuristic", safety_constraints, authorization_requirements,
dependencies, priority, state, provenance (planner,
planner_version, scoring_method, created_by="trusted_code",
model_requested/model_resolved/prompt_version/latency when advisory,
advisor notes), definition_hash().

States: DRAFT -> VALIDATED -> AUTHORIZATION_REQUIRED -> AUTHORIZED ->
EXECUTING -> COMPLETED / PARTIAL / REJECTED / FAILED / EXPIRED
(+ AUTHORIZATION_REQUIRED -> BLOCKED, EXPIRED; VALIDATED -> REJECTED).
Illegal jumps raise (tested). Definitions are immutable: the EXECUTING
transition freezes definition_hash; later mutation of the same
plan_id/version is refused by the store (tested). Old plan versions
are never overwritten; re-planning appends version N+1 with
parent_plan_id.

============================================================
6. OBSERVATION REGISTRY
============================================================

Closed registry, only types the codebase supports (READ_ONLY,
required_authorization "watch:scope", allowed_scope
"job.authorization_ref", executes_http False):
url-rows (db.Urls), parameter-rows (Urls/Endpoints params),
endpoint-rows (db.Endpoints), http-rows (db.Http status/title/tech),
header-rows (db.Http headers, sensitive-scrubbed), kb-rows (bounded
KB selection via the existing knowledge loader + query hints).
Each declares description, inputs, outputs, evidence_produces, risk
class READ_ONLY, cost class LOW/MEDIUM, prerequisites. Validation
rejects unknown types, types outside the capability allowlist,
unsupported inputs (allowlist: subdomain/limit/query_hints +
planning metadata), kb-rows without query hints, and any
forbidden-instruction text. No execution capability was invented.

============================================================
7. INFORMATION-GAIN LOGIC
============================================================

build_candidates(): per candidate (unread allowed type x the missing
items it can satisfy): evidence_value (priority-weighted missing
items), hypothesis coverage, information gain (normalized evidence
value), cost (registry), risk (registry), dependency readiness
(scope present), integer score, and a human-auditable reason string:
"Selected because <type> addresses <N> missing evidence item(s)
(<codes>) for hypothesis … while requiring an already-authorized
read-only observation within the fixed scope reference."

Labeled honestly: gain_label="heuristic",
scoring_method="heuristic_transparent_v1" — NOT exact information
gain, and never an LLM-only ranking (the advisor can only REORDER
types that deterministic candidates already justify; unknown/
invented types are dropped and recorded).

============================================================
8. LLM PLANNING ADVISOR
============================================================

Worker._hunt_advisor(): resolve_free_config (free-only guard:
paid/unknown/missing-key/provider misconfig all raise free_only
before any provider construction) -> select_provider ->
complete_with_status over the SAME R51-sanitized request envelope
(sections: research_context + learning_signals only; no URLs, no
secrets, no raw DB rows, bounded size pre-checked against
context_max_chars -> context_too_large fail-closed).
Prompt version: hunt-planner-advisor-v1. The model answers in the
existing strict {summary, insights[{insight_code,text}],
recommendations[{...}]} contract; OBS_<TYPE> codes are extracted and
re-validated against registry ∩ capability; forbidden-instruction
scan applies to every text (exploit/shell/code/network/credential/
finding-claim/scope-expansion/action-verb patterns — with action
context required so honest safety phrasing like "payload testing is
out of scope" is NOT flagged). Output is ADVISORY: objective_
interpretation, candidate_observations, rationale, evidence_expected,
dependencies, blockers, confidence, recommended_priority are recorded,
but the final Hunt Plan is always constructed by trusted code.
Every rejection (unknown type, forbidden content, malformed shape)
is recorded in outcome.llm_advisory {used, calls, rejected[],
errors[]} and in plan provenance notes; on any advisor failure the
loop CONTINUES deterministically (no paid fallback, no silent model
substitution — structurally impossible under the guard).

============================================================
9. AUTHORIZATION BRIDGE
============================================================

Hunt Plan -> AuthorizationRequest (hunt/authorization.py: plan id,
scope_ref, target, observation_types, capability, specialist, purpose,
allowed_data, safety_class READ_ONLY, job id) -> AuthorizationGate:

1. plan.scope_ref must equal job.authorization_ref (scope widening
   impossible; model itself refuses empty scope),
2. the EXISTING AuthorizationChecker.verify(job) runs (same
   fail-closed scope/target logic the runtime uses before any
   observation today),
3. every observation type must be in the capability allowlist,
4. every type must be in the registry.

Any exception -> DENIED (fail closed), plan ->
AUTHORIZATION_REQUIRED -> BLOCKED, objective -> BLOCKED, audit event
hunt_authorization recorded, NO observation executes.
Before EVERY single typed read the granted authorization is
re-verified (stale reverification: scope/target changes or
capability drift => pre-observation refusal recorded as a follow-up
DENIED authorization + explicit stale_authorization termination).

============================================================
10. EXECUTION LOOP
============================================================

Per objective, per iteration (executor):
1 create/retrieve objective (state OPEN)          12 decide: gate +
2 deterministic research state (real rows)           missing-evidence
3 missing evidence (deterministic)                13 NEEDS_EVIDENCE:
4 sufficiency check (authoritative gate +            new plan version
  no satisfiable missing) => RESOLVED             14 budgets checked
5 budgets (plans/observations/iterations/secs)       every iteration
6 candidates + deterministic scoring               Hard limits:
7 optional bounded LLM advice (validated)          max_plans_per_
8 trusted plan construction + validation             objective 3*
  (DRAFT -> VALIDATED; hunt_plan_created +          max_observations 6*
  hunt_replanned when version>1)                   max_planning_
9 authorization request + gate                       iterations 4*
  (granted => AUTHORIZED; denied => BLOCKED)       max_llm_planning_
10 EXECUTING (definition hash frozen) + reverify     calls 2*
  + typed observe per type (or kb loader)          max_seconds 60*
  + ObservationRecord (id/type/outcome/refs)       per_type_limit 25,
  + OBSERVED learning items + activity events      max_consecutive_
11 interim Evidence Gate (read-only, in-memory        observation_
  synthetic evidence rows — never persisted)        failures 2
  + ResearchUncertainty refresh + hunt_lineage      (* defaults;
  audit + research_state_updated activity            --hunt/--hunt-*
  + re-plan or terminate                              CLI overridable;
                                                     0 disables)

The loop NEVER runs when config.hunt_max_plans == 0 (default) —
existing behavior is byte-identical without --hunt.

============================================================
11. RE-PLANNING
============================================================

After each executed plan the objective re-evaluates (state
OBSERVATION_COMPLETE -> NEEDS_EVIDENCE -> READY_FOR_PLANNING -> …).
Remaining satisfiable missing evidence yields plan version N+1 with
parent_plan_id = previous plan (hunt_replanned activity emitted).
All plan definitions, transitions (incl. definition hashes),
authorizations, and observation records are append-only and preserved
(tested: version history intact after multi-plan runs).

============================================================
12. TERMINATION / SAFETY
============================================================

Explicit reasons only — never "completed" when state is unknown:
sufficient_evidence (RESOLVED; gate + no satisfiable missing),
hypothesis_rejected_no_signal (REJECTED), no_authorized_observation_
can_reduce_uncertainty (BLOCKED/REJECTED), authorization_denied /
scope_invalid (BLOCKED), required_capability_unavailable (BLOCKED),
max_plans_per_objective_reached / max_observations_reached /
max_planning_iterations_reached / runtime_budget_exhausted
(NEEDS_EVIDENCE — research still incomplete, loop stopped on budget),
observation_runtime_unavailable (BLOCKED), stale_authorization
(BLOCKED), plan_validation_failed (BLOCKED, defensive),
hunt_loop_error:<Exc> (honest worker-level degradation).
Termination detail strings carry the concrete gate reason / denial
reason / budget numbers.

============================================================
13. SPECIALIST INTEGRATION (XSS + CVE_RESEARCH)
============================================================

One planner infrastructure for both: same objective/plan models, same
authorization bridge, same observation runtime, same gate semantics,
same activity/audit model, same learning. Specialist differences live
ONLY in: capability allowlist (XSS: http-rows/url-rows/parameter-rows;
CVE_RESEARCH: http-rows/kb-rows), evidence requirements, and
specialist missing-evidence rules (XSS parameter inventory; CVE
technology signal + knowledge correlation). Both are exercised by
real production jobs (Phase 17) and by worker-level integration tests.

============================================================
14. SOC CHANGES
============================================================

Agent page (soc/agent_detail.html + agents.py): "Hunt objectives"
panel from real records — objective id/state/termination, iteration/
plan/observation/LLM-call counts, research objective text, ACTIVE plan
(id/version/state/types), PENDING observation (authorized/executing
plan without completed observation), PLAN VERSIONS list with gain +
label, RECENT OUTCOMES (plan terminals + observation outcomes), WHY
this observation was selected (the plan's auditable reason), honest
empty state ("No hunt objectives recorded … yet") — no fake counters.
_INTEL_ACTIONS now includes every hunt activity name so recent
research activity shows hunt events.

Case page (soc/case_detail.html + cases.py): contract hunt block
(objective, state, termination reason, iterations, plan/observation
ids, missing_remaining, rows_added, LLM advisory usage — from
structured["hunt"]) + hunt_detail fetched from the real HuntStore
(hypothesis, ALL plan versions with reasons, executed observations
with outcome/+rows, authorization statuses, termination detail).

Activity: hunt_objective_created, missing_evidence_detected,
hunt_plan_created, plan_validated, authorization_requested,
authorization_granted/rejected, observation_started,
observation_completed, research_state_updated, hunt_replanned,
hunt_terminated — all emitted from the loop itself (real rows in
runtime_activity), all whitelisted for SOC display.

============================================================
15. AUDIT / PROVENANCE
============================================================

Reconstructable lineage per iteration (audit events, append-only):
objective -> uncertainty digest + state -> missing codes -> gate
reason/confidence -> candidate/scoring method -> advisor
(model_requested, model_resolved, prompt_version, latency,
accepted/rejected/error) -> plan id/version/definition hash ->
authorization id/status/reasons -> observation types/rows added ->
missing remaining. Plus hunt_authorization per gate decision and
hunt_lineage_final (termination reason, all plan ids, observation
ids, LLM calls, elapsed_ms, rule version). Activity rows are scrubbed
(`[REDACTED]` + URL scrub, bounded detail); secrets can never reach
audit payloads (tested). Research contract structured["hunt"] carries
the same summary into the stored result.

============================================================
16. SECURITY VERIFICATION
============================================================

tests/test_hunt_planner_safety.py (24 tests) proves, behaviorally and
via AST over the whole hunt package: no network/shell imports
(socket/requests/urllib/http/aiohttp/httpx/subprocess/ctypes), no
eval/exec/compile/os.system-style calls, no case/evidence persistence
calls anywhere in the package (store spies stay at 0 during a real
loop), observation executes ONLY in executor through the injected
provider, scope widening refused by validator AND gate, invented
capabilities/types refused, exploit/shell/code/network instructions
refused (scanner), authorization precedes observe (spy sequence),
advisor cannot upgrade gate confidence (overconfident advisor +
weak rows => gate still non-creating, objective not RESOLVED), advisor
request carries no unrestricted history/URLs/credentials, unknown and
paid models rejected before provider construction, secrets scrubbed,
plan definitions immutable after execution, duplicate EXECUTING
refused, loop bounded (iterations/plans/obs), concurrent objective
updates serialized by store lock with consistent strictly-increasing
revisions, stale authorization rejected on reverification.

============================================================
17. FAILURE / RECOVERY
============================================================

tests/test_hunt_planner_failure.py (19 tests): LLM unavailable /
timeout / malformed response / context overflow / unknown-type
advice => advisory errors recorded, deterministic planning continues,
job completes honestly; invalid scope => BLOCKED before any
observation (no objective even created when authorization_ref is
missing); authorization denial => plan BLOCKED + DENIED record +
authorization_rejected activity; partial observation => plan PARTIAL
with per-type honest records (failed type = "unavailable" + error,
successful types = "ok"); dead observation runtime => explicit
observation_runtime_unavailable BLOCKED after N consecutive failures;
gate/evidence-store failure SURFACES (never a fake result); memory
failure => hunt continues with learn_* errors recorded; plan
persistence failure => worker degrades honestly
(hunt_loop_error in contract, job completion truthful, no fabricated
hunt state); stale/tampered plan hash detected; duplicate plan
rejected; unknown state transitions rejected; budgets always bound
the loop; REJECTED termination only with no_signal proof.

============================================================
18. KNOWN LIMITATIONS
============================================================

- Observation novelty is bounded by the store: typed reads reach
  collections the legacy first read's budget never touched (in
  production the legacy read spends its budget on db.Urls, so
  http-rows/endpoint rows are genuinely new), but the underlying
  data is still the current authorized snapshot — the planner
  acquires evidence, it does not create new external measurement.
- kb-rows runs through the existing knowledge loader (bounded, dedup
  by id); query hints improve targeting but KB coverage is fixed.
- Information gain is a labeled heuristic, not a mathematical
  expectation (declared in every candidate/plan payload).
- The advisor is advisory-only; with a free-router outage the loop
  degrades to deterministic planning (by design).
- Confidence semantics are exactly the existing Evidence Gate's
  (deterministic); the planner can never raise them.
- Objective-per-job: one hunt objective per runtime job in v1
  (multi-objective budgets share the same store and are additive).
- Forbidden-instruction scanning is deliberately conservative: some
  benign advisory phrasings may cause advisor rejection; the
  deterministic path always remains (fail closed, never fail open).
- Real (Phase 17) validation runs are bounded single invocations of
  `run --max-jobs 1 --hunt …`; no persistent worker / systemd change.

============================================================
19. LIMITS / COST CONTROL
============================================================

Free-only enforced at provider construction (free_only guard) AND
budgeted at the loop (max LLM calls per objective, default 2;
`--hunt-llm-plans` to tune, 0 disables advisor calls). Context size
pre-bounded (context_max_chars) before any request. Requested vs
resolved model, call count, latency recorded in plan provenance +
audit lineage. Observations bounded (count + per-type row budget 25),
iterations bounded, wall-clock bounded (hunt_max_seconds default 60,
job timeout still governs). Concurrency: single worker lease +
flock'd stores; no new threads, no systemd changes.

============================================================
20. REAL VALIDATION + TESTS + DELIVERY
============================================================

Tests (new): tests/test_hunt_planner_core.py (58 OK),
test_hunt_planner_safety.py (24 OK), test_hunt_planner_failure.py
(19 OK), test_hunt_planner_soc.py (15 OK) — 116 new tests green.
Regression: agent runtime core 32 OK; agent intelligence OK;
research intelligence suites 70 OK; AEC 2149 OK; SOC UX 26 OK;
recon navigation 26 OK; runtime E2E smoke OK (hunt absent when
disabled); delivery gates + diff guard + secret scan via check.sh.
Real production jobs (Phase 17): see "REAL PRODUCTION JOBS" section
appended after APPROVE + execution (promotion request below).

Known pre-existing baseline failures are unchanged and not hidden:
test_research_agent (1 data-location), dashboard navigation flake,
3 stale battery entries (r82 sidebar / CVE sort / legacy cases).

------------------------------------------------------------
PRODUCTION VALIDATION FINDINGS — defects found by REAL runs
(fixed in this promotion; Phase 17 exists exactly for this)
------------------------------------------------------------

Run 1 (job-xss-1d9cb07e56, deterministic hunt before --llm wiring):
loop itself verified in production — objective obj-4166d2685ddd,
2 plans (genuine re-plan v1->v2), 2 GRANTED authorizations, 3 typed
observations, RESOLVED / sufficient_evidence, 12 objective revisions.

Run 2 (job-xss-447203e643, real openrouter/free analysis + hunt):
found THREE defects, all fixed with regression tests before this
promotion:

1. advisory_id was generated as adv-<12 hex> but the provider schema
   requires ADVISORY_ID_RE ^adv-[0-9a-f]{16}$ -> both LLM advisor
   calls in that run were rejected pre-flight
   ("advisory_id is malformed"); the loop degraded honestly to
   deterministic planning (by design) and the job still COMPLETED
   with case case-cd39108f032c (final analysis LLM: openrouter/free,
   prompt xss-agent-analysis-v2, gate high).
2. The follow-up structural checks then exposed advisory_mode and
   source_layer outside their closed enums, source_refs using
   unlisted layers/free-text references, limitations using free text,
   and a request above MAX_CONTEXT_CHARS (4000 canonical). The hunt
   request is now fully conformed: advisory_mode RESEARCH_PRIORITY,
   source_layer MULTI, R44/R45 source refs with <=40-char lowercase
   references (incl. the scope reference required by Phase 7),
   ADVISORY_INPUT_LIMITATIONS codes only, worst-case request
   canonical 3769/4000 — proven by sanitize_provider_context in the
   test suite (advisory_id + full-request structural test).
3. Contract rows_added was reset by every executed plan and reported
   only the last plan's additions; it now accumulates across all
   plans (test asserts contract total == sum of observation records).

Observation honesty note: typed reads DID add genuinely new rows in
production (http-rows +1, parameter-rows +22 beyond the legacy first
read's budget); url-rows returned 0 new rows (already covered) and is
recorded honestly as an ok observation with 0 new rows — never as a
fabricated gain.

Delivery: work on agent/daily-development; explicit file staging
(production 27 dirty entries untouched); check.sh gates; push via
push_safe.sh; promotion request; STOP at Telegram APPROVE.
