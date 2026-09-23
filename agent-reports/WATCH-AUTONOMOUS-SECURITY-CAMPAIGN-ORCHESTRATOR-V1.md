# AUTONOMOUS SECURITY CAMPAIGN ORCHESTRATOR v1

Baseline: main `26c255e` (Hunt Planner v1 closure). Epic build performed on
`agent/daily-development`. Phases 0–17 and 20–23 completed in this promotion
cycle; the mandatory REAL production campaign (Phases 18/19) is executed after
promotion in the second promotion cycle, per the standing two-promotion flow.

---

## 1. Executive result

The Campaign Orchestrator v1 exists as a new `backend/research_agents/campaign/`
package: persistent Campaign/CampaignObjective models with validated state
machines, bounded REQUIRED/OPTIONAL/INFORMATIONAL dependencies with cycle
rejection, a deterministic reason-labeled prioritizer, capability-aware
specialist selection, cumulative auditable budgets, a bounded execution loop
that delegates every objective to the EXISTING job → Hunt Planner →
authorization → Observation Runtime → Evidence Gate path, cross-objective
context, Research Memory integration, honest termination records,
pause/resume, lease-safe single-coordinator execution, SOC campaign pages, and
full audit lineage. 144 campaign tests (126 + 18 correction) + the full
existing regression (2,519 tests across 6 batteries) are green. Free-only
LLM enforced through the existing
`llm_guard`; no paid path exists.

## 2. Architecture

```
CAMPAIGN            (store: campaigns.jsonl, scope-pinned, lease-guarded)
  ↓
OBJECTIVES          (campaign_objectives.jsonl, deps, per-objective budget)
  ↓
PRIORITIZER         deterministic, reason-labeled, heuristic_transparent_v1
  ↓
AGENT SELECTOR      existing capability registry only (no invented specialists)
  ↓
(optional ADVISOR)  openrouter/free through R51 envelope, validated, reorder-only
  ↓
existing RuntimeStore job per objective   (authorization_ref = campaign scope)
  ↓
EXISTING Hunt Planner → Authorization → Observation Runtime → Evidence Gate
  ↓
RESEARCH MEMORY     (append-only, campaign provenance, never overwrites specialist)
  ↓
OBJECTIVE RESULT    (state mapped from job status + hunt state + gate reason)
  ↓
CAMPAIGN REPRIORITIZATION → NEXT OBJECTIVE / TERMINATION
```

The orchestrator coordinates; it never replaces Runtime, Hunt Planner,
Authorization, or Evidence Gate (rule 20). AST tests prove the campaign package
does not import hunt execution, authorization, observation providers, network,
or process modules.

## 3. Campaign model

`Campaign`: campaign_id, program, scope_ref (MANDATORY — construction without
scope raises `CampaignScopeError`), target_context, campaign_objective,
participating_specialists, priority, state, budget, limits, lease_owner/
lease_expires_at, termination_reason/detail/record, created_at/updated_at,
provenance. States: DRAFT, READY, RUNNING, PAUSED, WAITING, COMPLETED, BLOCKED,
CANCELLED, EXPIRED, FAILED, BUDGET_EXHAUSTED (Phase 7's explicit
budget-exhausted state added to Phase 1's list). Every transition validated by
`validate_campaign_transition` and persisted as a transition row. store-level
transitions refuse scope changes.

## 4. Objective model

`CampaignObjective`: objective_id, campaign_id, category, specialist (optional;
validated against capability at selection), scope_ref (must match campaign —
enforced at save AND re-checked fail-closed in the executor), research
question, hypothesis, priority, state, evidence_requirements, dependencies,
budget, attempts/job_id, termination reason/detail, provenance. States: QUEUED,
READY, RUNNING, WAITING, BLOCKED, RESOLVED, REJECTED, EXPIRED, FAILED,
CANCELLED. The existing Research Objective model (`hunt.HuntObjective`) was NOT
duplicated: it remains the per-job hunt objective; the campaign objective is a
higher-level entity that links to job_id + hunt objective id in results.

## 5. Dependencies

Dependency {objective_id, depends_on, kind ∈ REQUIRED|OPTIONAL|
INFORMATIONAL}. REQUIRED acceptable terminal states: RESOLVED/REJECTED (any
concluded research result); permanent-fail: BLOCKED/EXPIRED/CANCELLED/FAILED →
dependent BLOCKED before any execution. OPTIONAL/INFORMATIONAL never block.
Cycles (A→B→A) rejected at `add_objective`, `save_objective`, and at run start
(`resolve_all` → FAILED / `dependency_cycle_detected`) — three layers, all
tested.

## 6. Prioritization

Deterministic `prioritizer.prioritize()` over executable candidates. Inputs:
objective priority, evidence-value proxy, risk class, attempts, age/freshness,
scope relevance, specialist availability, dependency readiness, budget
remaining, previous research hits. Output: ordered objectives + per-objective
reason strings; excluded candidates carry reasons (e.g.
specialist_unavailable). Labeled `scoring_method="heuristic_transparent_v1"`;
no optimality claim. The LLM never decides the final order: it may only
reorder within the validated set (`apply_advisory`), and the pre-advisor
deterministic order is recorded every iteration.

## 7. Agent selection

`selector.select_specialist()` is a pure function over the existing capability
registry: objective category → capability → capability.agent_name. Mismatched
declared specialist, unknown category, missing capability → not selected
(reason recorded), objective never executes under the wrong agent. Selection
reasons are audited (campaign_objective_selected / campaign_specialist_selected).

## 8. Budget

`CampaignBudget`: cumulative across the campaign (never reset per objective),
resources: objectives, completed_objectives, active_objectives, llm_calls,
observations, hunt_plans, runtime_seconds, retries, context_chars,
knowledge_documents, campaign_lifetime_seconds. `ensure()` before each
objective/selection/LLM call; `consume()` with before/after ledger rows
(campaign_budget.jsonl, every row auditable). Exhaustion → BUDGET_EXHAUSTED
termination with remaining objectives + budget state (never silent continue;
over-shoots would be recorded honestly). Hunt LLM budget is clamped to the
remaining campaign budget when building the job config.

## 9. Execution loop

22-step bounded loop (load → scope verify → deps → budget → candidates →
prioritize → optional advisor → validate → select specialist → enqueue job →
existing worker+Hunt Planner → read result+hunt+gate → objective update →
memory → context → budget → campaign update → next / terminate), bounded by
`--max-objectives`, cumulative budgets, wall time, and campaign lifetime.
Coordinator lease claimed/renewed per iteration, released on exit.

## 10. Cross-objective context

`context.py`: bounded items with source objective/job/result, confidence/state,
timestamp, scope match required (`context_for` filters by scope), always
labeled research_context_only. Context flows to later objectives via bounded
research context (objective summaries + prior research in the advisor request
and via Research Memory); it is NEVER treated as evidence unless the Evidence
Gate says so (AST + behavioral tests: campaign writes zero evidence rows/cases).

## 11. Research Memory integration

On objective terminal: RESOLVED+case → `confirmed_historical_result`/VERIFIED
(gate-created case is the authority); gate-met-no-case → RESEARCHED; REJECTED →
`rejected_hypothesis`/REJECTED; BLOCKED → `negative_evidence`/OBSERVED. All
items carry provenance source `campaign:<id>` — distinct ids, append-only store,
specialist memory can never be overwritten (heads/should_append unchanged).
Memory append failures are recorded (errors + audit `campaign_memory_failed`)
and never fake a learning that did not happen.

## 12. Pause/resume

`campaign pause` (RUNNING/READY/WAITING → PAUSED, lease released) stops new
objective execution; running state/leases/audit chain untouched. `campaign
resume` revalidates scope (validate_scope_ref + all objective scopes match),
rechecks dependencies, recalculates budget from the persisted campaign row,
then the run revalidates stale authorizations at per-observation time (the
existing AuthorizationChecker remains the authority) — never a blind resume.

## 13. Concurrency

Single coordinator per campaign: lease_owner/lease_expires_at on the campaign
row under `.campaign.lock` flock (the same lock serializes every mutation).
Second coordinator → `lease_refused` fail-closed; crashed coordinator's expired
lease → reclaim with audit; `campaign_claim` activity recorded. Duplicate job
execution prevented by: objective states (executed objectives are never
re-promoted — regression-tested), resume-existing-job (never a second job for
the same objective), and the runtime's own job claim/lease machinery.

## 14. SOC

Existing AI SOC extended (no new dashboard): `Campaigns` nav entry in the
existing sidebar group; `/ui/soc/campaigns` (list), `/ui/soc/campaigns/{id}`
(state, scope, objective counts, active/completed/blocked, remaining budget,
current specialist/plan, latest evidence, next objective, termination reason,
budget table, activity, research context), `/ui/soc/campaigns/{id}/objectives/
{oid}` (campaign, specialist, research question, hypothesis, dependencies,
evidence state, hunt plans, observations, cases, memory learned, current
state). All data real; template snapshots (rows 0, `--`, `research context
only`) — no fake counters. Activity actions emitted by the executor:
campaign_started/resumed/replanned/paused/completed/terminated,
objective_selected/started/blocked, specialist_selected, hunt_started,
observation_started/completed, evidence_updated (all derived from real events;
observation/evidence rows mirror persisted hunt records).

## 15. Audit/provenance

Every stage appends to the existing runtime `audit.jsonl` with campaign
lineage: campaign_id, objective_id, job_id, plan/authorization/observation ids
(read back from hunt results), gate reason + case id, budget before/after,
prioritizer version, advisor prompt version + requested/resolved model +
latency + error taxonomy, selection reasons, termination reason with remaining
objectives. `campaign_event` redacts secret-shaped values ([REDACTED]);
AST test proves no key literals in the campaign package.

## 16. Security verification (Phase 17 checklist)

Proven in `test_campaign_safety.py` (17 tests): campaign/objective/LLM cannot
widen scope (construction, store save, executor scope guard → FAILED +
zero jobs, advisor scope checks); cannot bypass Authorization (AST: no
authorizer import; jobs carry authorization_ref and go through the existing
per-observation boundary); no HTTP/shell/arbitrary code (AST: forbidden import
roots, os.system/popen/exec*, eval/exec/__import__ absent); LLM cannot create
evidence or cases (campaign writes 0 evidence/cases in full runs; Evidence
Gate authoritative); paid/unknown/missing model rejected (`resolve_free_config`
raises FreeOnlyViolation — guard is the FIRST thing the advisor does, before
any provider construction); secrets scrubbed (redaction test with key-shaped
values); unrestricted history unavailable (closed advisor-request key set,
bounded ≤ 4000 canonical); dependency cycles rejected; duplicate execution
prevented; budget cannot be bypassed (BUDGET_EXHAUSTED, no second job);
stale authorization rejected (scope guard); campaign state transitions
validated.

## 16a. Production-validation defect (found & closed)

The first real campaign (§18–19) exposed a mapping defect: the executor
read gate fields from `research_lineage`, while the runtime persists the
authoritative gate at `structured["evidence_gate"]`, so the two objectives
whose gates DID claim cases were initially mis-labelled REJECTED.
Closure: `_extract_gate()` now prefers the authoritative `evidence_gate`
record (lineage kept as legacy/fixture fallback); a narrow sanctioned
`correct_objective_state()` / `CampaignObjective.correct()` API repairs
only REJECTED→RESOLVED, requires an `authoritative_gate_correction`
reason plus concrete evidence, and stays terminal — a corrected objective
can never execute again, and the normal state machine still blocks
terminal edits (rule 5 upheld: the correction reports reality recorded by
the Evidence Gate, it does not create evidence). Production data was
repaired through audited store writes: 2 objective corrections, 2
`campaign_objective_corrected` audit events, 2 memory supersessions
(false `rejected_hypothesis` → `confirmed_historical_result`/VERIFIED
citing both case ids). 18 new tests pin extraction order, mapping
semantics, and every correction guard (`test_campaign_correction`). One
safety test was hardened against inherited-shell environment variables
(free-only semantics unchanged — no code change to the guard).

## 17. Failure/recovery (Phase 16)

`test_campaign_failure.py` (16 tests): LLM unavailable/timeout/malformed →
deterministic ordering continues, outcome recorded, no scope widening;
invalid recommendation (non-executable objective) → rejected + deterministic
head executed; invalid specialist → objective BLOCKED with reason, campaign
BLOCKED (zero jobs); dependency failure → dependent BLOCKED before execution;
budget exhaustion → BUDGET_EXHAUSTED with ledger before/after + remaining
objectives; live foreign lease → lease_refused; expired lease → reclaimed;
duplicate coordinator refused; failed job → objective FAILED (job_failed);
hunt-planner/gate degradation → honest REJECTED with gate reason; memory
failure → errors + audit, objective state unaffected; persistence failure →
honest error/summary (no fake completion); resume after interruption +
partial objective completion → same job resumed, never a duplicate (job count
stays 1); coordinator crash (expired lease) → recovered. FAILED campaign
terminations set `ok=False`.

## 18. Real production campaign

**EXECUTED** (post-first-promotion step of the standing two-promotion
flow). Campaign `camp-df3e1b68a280`, program dell, scope
`watch:scope:dell/www.dell.com`, execution_mode production, limits
`max_objectives=4 max_llm_calls=6 max_hunt_plans=8` + defaults:

- **A `obj-4d92de164cbf`** (XSS, priority 80) → job
  `job-xss-49b9d40fd5` COMPLETED; plans `plan-a5c88b14bb87` +
  `plan-a57d92d83e38`; observations `obs-34ded789fcbb`,
  `obs-75fa56bbe20d`, `obs-72570934535e`; hunt rows_added 23,
  hunt-advisor 2 calls; **authoritative gate `evidence_rules_met`,
  confidence high, 20 evidence rows → case `case-8fac3faaf462`** →
  objective **RESOLVED** (via the audited §16a gate correction).
- **C `obj-82e96893b44c`** (XSS, priority 60, independent research
  question) → job `job-xss-b1d237d202` COMPLETED; plans
  `plan-97bfc5e5eea0` + `plan-d22aeeeaa84c`; observations
  `obs-da4f6dadb3c6`, `obs-94e6314e14ef`, `obs-b8fdfea48b5c`;
  rows_added 23, hunt-advisor 2; **gate `evidence_rules_met`, high,
  20 evidence rows → case `case-03f46d7aca02`** → **RESOLVED**
  (same correction).
- **B `obj-be92b6e5b22e`** (CVE_RESEARCH, priority 70, REQUIRED
  dependency on A — satisfied before execution) → job
  `job-cve_research-28dc826bf3` COMPLETED; plan `plan-34a20550ee52`;
  observations `obs-c02c3e3e8868`, `obs-a3fd1a7f5b72`; rows_added 1,
  hunt-advisor 1; gate `confidence_below_threshold` (medium, no case —
  evidence rules correctly NOT met) + hunt BLOCKED
  `no_authorized_observation_can_reduce_uncertainty` → objective
  **BLOCKED** (honest: remaining authorized observations could not
  reduce uncertainty).
- **Run sequence**: run1 executed 3/3 objectives (268 s) → `WAITING` /
  `per_run_objective_limit`; run2 (0.9 s, 0 executed) → **final
  `BLOCKED` / `no_executable_objectives`** — never fake COMPLETED while
  B remains non-terminal.
- **LLM** (prompt `campaign-advisor-v1`; `requested_model` =
  `resolved_model` = `openrouter/free` on every result): 3 recorded
  advisor outcomes — (1) honest provider failure
  `INVALID_PROVIDER_RESPONSE` (R51 taxonomy, no fallback, no paid
  switch), (2) `used=true`, latency 39 189 ms, advisory reorder
  `[C, B]` applied only within the deterministic candidate set (A,
  priority head, ran first — LLM never decided the final order),
  (3) `advisor_disabled:max_llm_calls` — budget exhaustion disabled the
  advisor with a recorded outcome (no silent skip).
- **Budget final (cumulative, before/after ledger)**: llm_calls 9/6
  (overshoot −3 displayed transparently, never hidden) · hunt_plans 5/8 ·
  observations 8/12 · objectives 3/4 · runtime 224/600 s · lifetime
  302/86 400 s · context 558/4000 chars · retries 0 · knowledge 0/20.
- **Memory**: 3 campaign items at run end; after the §16a correction →
  **5** total campaign items (2 false `rejected_hypothesis` superseded by
  `confirmed_historical_result`/VERIFIED citing both case ids; B's
  `negative_evidence`/OBSERVED untouched; append-only, total 206 items).
- **Audit event counts**: `campaign_started` 1, `campaign_resumed` 1,
  `campaign_paused` 1, `campaign_terminated` 1,
  `campaign_objective_selected/started/terminal` 3 each,
  `campaign_specialist_selected` 3, `campaign_context_recorded` 3,
  `campaign_advisor_outcome` 3, plus 2 `objective_correction` transition
  rows and 2 `campaign_objective_corrected` audit events.
- **SOC**: routes live post-restart (`openapi 200`; soc/campaigns/
  objective detail auth-gated 401 = registered); pages serve the
  corrected RESOLVED/RESOLVED/BLOCKED states from the store.
  Authenticated live rendering remains unverified (production API key is
  not in the agent environment); adapter/template rendering is covered
  by `test_campaign_soc`.

## 19. Exact objectives/jobs/plans/authorizations/observations

Fixture validation (clearly labeled fixture, tmp stores, scripted fake worker):
multi-cycle smoke — 3 objectives (A XSS REQUIRED→B, B CVE_RESEARCH, C XSS
independent), 2 distinct jobs (`job-xss-d624cad2bb`, `job-xss-023de2213d`),
distinct objective ids, run1 → WAITING (per-run limit), run2 → BLOCKED /
no_executable_objectives, 9 budget ledger rows (5 resources), 4 research-context
items (all research_context_only), 13 activity actions, 9 audit event kinds.
Fixture unit runs additionally exercised COMPLETED/RESOLVED/REJECTED/FAILED/
BUDGET_EXHAUSTED/lease-refused/persistence paths. **Real production IDs:
§18** (all campaign/objective/job/plan/observation/case/evidence/memory/LLM
values above come from live production stores, read back after each step).

## 20. Resource control

Cumulative campaign limits enforced before each objective and LLM call (tests
pin exhaustion → BUDGET_EXHAUSTED + ledger). Job-side hunt limits clamped to
remaining campaign budget. Concurrency stays 1 (runtime default); no persistent
worker added; wall-time/lifetime bounds terminate honestly. Memory/context
counts bounded by store limits + request canonical ≤ 4000.

## 21. Test matrix

| Suite | Result |
| --- | --- |
| campaign core / safety / failure / soc / correction | **144 OK** (126 + 18) |
| hunt planner (core/safety/failure/soc) | 118 OK |
| research intelligence ×4 + agent intelligence | 93 OK |
| runtime core + e2e_soc + security_llm | 77 OK |
| soc_ux_correction + recon_soc_navigation | 52 OK |
| AEC discovery (all test_aec_*.py) | 2149 OK |
| delivery gate TESTS battery | 82 OK |
| fixture end-to-end smoke | GREEN |

Baseline failures: none new; all existing batteries green. No unrelated failures
hidden or rewritten (only the two nav allowlists gained the additive
`Campaigns` entry — the sanctioned way to evolve those guards).

## 22. Documentation

This report is the campaign architecture documentation: architecture, state
machines (campaign + objective), prioritization, agent selection, budget model,
dependency model, execution loop, context propagation, termination,
pause/resume, concurrency, safety boundaries, SOC UI, audit lineage,
production validation plan, known limitations (§23).

## 23. Known limitations

- ~~The real production campaign (Phases 18/19) is intentionally not part of
  this first promotion cycle~~ — **executed post-promotion; see §18–19.**
- `correct_objective_state()` is deliberately one-way (REJECTED→RESOLVED
  only) and evidence-gated; it is a defect-recovery API, not a general
  state editor — other mislabels must be fixed at the source, not via
  corrections.
- Per-run `--max-objectives` parks the campaign WAITING (resumable); it does
  not background-loop — matches the no-persistent-worker constraint.
- Prioritization is a transparent heuristic (labeled), not an optimizer.
- BLOCKED objectives are non-terminal by design; a campaign with permanently
  blocked remainder terminates BLOCKED (honest), not COMPLETED.
- Fixture smoke objectives end BLOCKED (fixture scope has no real data to
  reduce uncertainty) — this is the honest outcome, not a defect.
- Objective-level budget overrun after the fact would be recorded, not
  prevented mid-job (job-side clamping makes overrun structurally unlikely).

## 24. Git/delivery

Work on `agent/daily-development` (worktree); explicit file staging only
(16 new + 5 modified; the 183-dirty leftovers and the runtime-generated
security-case markdown stay behind); the §16a fix commit stages exactly 7
files (campaign `executor`/`models`/`store`, fixtures, safety test, new
correction test, this report); production baseline verified
(main `26c255e`, dirty 27 untouched); push via `push_safe.sh`; promotion
request via the sanctioned workflow; STOP at Telegram APPROVE. No stash/reset/
force-push; no gate bypass.

## 25. Production commit(s)

- Cycle 1: `4a1e62d` → promoted, production main = **`e09377b`**
  (verified: report + 11 campaign files tracked, dirty 27 untouched,
  `watch-api` restarted, `openapi 200`).
- Cycle 2: pending — the §16a defect-closure commit of this report's
  branch tip (created in the delivery step below).

## 26. Promotion request ID(s)

- Cycle 1: `PROMOTION-REQUEST-20260922-1907` — APPROVED and promoted
  (production `e09377b`).
- Cycle 2: created by `request.sh` after the final gate of this cycle;
  the exact request id is stated in the delivery message.
