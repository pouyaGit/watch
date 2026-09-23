# AUTONOMOUS FINDING VERIFICATION & TRIAGE v1

Epic baseline: production `main = f3c1fc1`. Work performed exclusively in
`/opt/watch/.worktrees/watch-agent` on `agent/daily-development`.
Report cycle 1 (pre-promotion). Phases 19-21 (real production validation)
are executed AFTER Telegram APPROVE, per the Epic's own Phase 24 ordering.

## 1. Executive result

Built the controlled layer between RESEARCH / CAMPAIGN RESULTS and TRUSTED
SECURITY CASES / ANALYST HANDOFF — as the lifecycle

  CANDIDATE -> TRIAGE -> CORRELATION -> DEDUP -> VERIFICATION OBJECTIVE ->
  EXISTING HUNT PLANNER -> EXISTING AUTHORIZATION ->
  EXISTING OBSERVATION RUNTIME -> EVIDENCE -> VERIFICATION GATE ->
  VERIFIED / REJECTED / INCONCLUSIVE / BLOCKED -> CASE PACKAGE -> HANDOFF

It is NOT another orchestration layer: observation planning stays in the
Hunt Planner, execution stays in the Observation Runtime, scope decisions
stay in the Authorization boundary, and the Evidence Gate remains the only
authority that can produce VERIFIED. The LLM advisor (openrouter/free,
free-only, no fallback) recommends; it never decides, never executes,
never creates evidence, cases, severity or CVE applicability.

New package: `backend/research_agents/finding/` (15 modules).
New SOC surface: `backend/soc/findings.py` + routes + 2 templates +
additive Findings nav entry + additive Cases/Handoff rows.
140 new tests in 4 new suites (plus 5 pre-existing suites that cover the
unrelated R53 layer, untouched and green). Deterministic fixture pipeline
reaches VERIFIED with a real gate chain (plan ids, auth ids, observation
ids, `evidence_rules_met`); production runs follow after APPROVE.

## 2. Architecture

```
RESEARCH (job result + evidence, persisted)
  -> CANDIDATE (extract.py — deterministic, never verifies)
  -> TRIAGE (triage.py — deterministic priority + reason codes)
  -> CORRELATION / DEDUP (correlate.py + dedupe.py — structured signals only)
  -> VERIFICATION OBJECTIVE (verification.py — bounded, scoped)
  -> EXISTING HUNT PLANNER (builds the plan inside the existing worker)
  -> EXISTING AUTHORIZATION (AuthorizationChecker, every observation)
  -> EXISTING OBSERVATION RUNTIME (only execution boundary)
  -> EVIDENCE (runtime rows + quality.py deterministic metadata)
  -> VERIFICATION GATE (gate.py — reads ONLY the authoritative
       structured["evidence_gate"] + evidence quality; LLM not in signature)
  -> VERIFIED / REJECTED / INCONCLUSIVE / BLOCKED
  -> CASE (case_package.py — only gate-verified candidates become
       VERIFIED cases; READY_FOR_REVIEW -> HANDED_OFF -> CLOSED)
  -> HANDOFF (read-only rows + detail fallback in backend/soc/handoff.py)
```

Modules: models (CandidateFinding/VerificationObjective/CasePackage with
validated state machines), store (append-only JSONL + flock + severity
provenance guard + gate-gated VERIFIED transitions), limits (cumulative
fail-closed budgets), audit (`finding_event`/`lineage_row` with secret
scrub), advisor (R51 envelope, EXPLANATION mode), executor (bounded loop).

## 3. Candidate model

`candidate_id, source_job, source_campaign, source_objective, specialist,
scope_ref, target, endpoint, vulnerability_class, hypothesis,
supporting_signals, missing_evidence, confidence + confidence_provenance,
lifecycle_state, severity + severity_provenance, duplicate_of,
correlation, evidence_refs, provenance, created_at, updated_at`.
12 states: DETECTED, TRIAGED, NEEDS_EVIDENCE, VERIFICATION_PLANNED,
VERIFICATION_PENDING, VERIFYING, VERIFIED, REJECTED, INCONCLUSIVE,
DUPLICATE, BLOCKED, EXPIRED — with an explicit transition map; terminal
states immutable; VERIFIED requires the authoritative gate result at the
store level. A candidate is never called a verified vulnerability.

## 4. Triage

`triage()` is a pure deterministic function (no LLM parameter exists):
evidence completeness vs the capability's EvidenceRequirements, confidence
provenance, duplicate likelihood, scope validity (watch:/fixture: only),
endpoint, vulnerability class, previous verification attempts, existing
cases, specialist support, research freshness. Output: state, priority
(0-100, persisted in provenance), missing evidence, duplicate candidates,
recommended verification path (deterministic evidence types), reason codes.

## 5. Correlation

Structured signals only: scope_ref, vulnerability class, endpoint shape,
normalized parameter, shared evidence refs, shared target. Relations:
SAME_CANDIDATE / POSSIBLE_DUPLICATE / RELATED_CANDIDATE / INDEPENDENT,
each with reason codes + provenance + rule_version. Semantic similarity
(hypothesis text) is never consulted — identical hypotheses with different
class/scope correlate INDEPENDENT (tested).

## 6. Deduplication

Deterministic canonical selection: pipeline-committed candidates win over
fresh ones (state-tier), then earliest created_at, then candidate_id.
The loser is marked DUPLICATE with `canonical_id` + correlation metadata;
its evidence and provenance are preserved (never deleted, never merged);
candidates outside DEDUPE_STATES (terminal/verification-bound) are never
demoted or destroyed — tested both directions.

## 7. Verification Objective

12 states (CREATED ... EXPIRED), scope forced to its candidate's scope,
budget + attempts, `gate_reason` only settable from the authoritative
gate, and the store refuses VERIFIED without `evidence_rules_met`.
Planning is delegated: the objective becomes a research job consumed by
the EXISTING worker, where the EXISTING Hunt Planner builds the plan; the
verification layer adds no planner (rule 18/20 honored).

## 8. Verification Gate

`gate.decide()` reads: job status, the persisted
`structured["evidence_gate"]` (authoritative, lineage fallback), evidence
quality rows, hunt termination. Outcomes VERIFIED (gate met + authoritative
+ direct supporting evidence), REJECTED (contradicting evidence or
disqualifying `no_hypothesis` or scope mismatch), BLOCKED (hunt blocked /
authorization denied / job failed), INCONCLUSIVE (everything else,
including gate record absent). `advisor_fn` does not appear in its
signature (AST-tested); "LLM confidence = high" can never become VERIFIED.

## 9. Evidence quality

`quality.py`: deterministic classification from the actual observation
source — reliability class (observed/research/advisory), direct vs
indirect, supporting/contradicting/neutral stance, verification-relevance
(verification job vs background), authoritative-eligible. Reliability
values are computed by rule from source + observation type; never invented.

## 10. LLM advisor

`advisor.py`: R51 envelope (adv- id, EXPLANATION mode — the closed
`VULNERABILITY_CONFIRMATION` mode is forbidden by schema), openrouter/free
through the existing free-only guard, request hard-trimmed to 4000 chars
deterministically. Output mapped into candidate_interpretation /
missing_evidence / verification_recommendations / conflicting_evidence /
related_cases / confidence (advisory) / blockers. Validator rejects:
unknown observation types, scope expansion, authority claims (severity,
CVE, confirmed), forbidden content (URLs, commands, exploits, claims).
All rejections are recorded (used=false + reason). Phase 21 max_llm_calls
enforced with honest `advisor_disabled` outcomes.

## 11. Severity / risk provenance

Default UNASSESSED everywhere. Non-UNASSESSED severity is only accepted
with explicit `knowledge_base_cvss:` provenance (model __post_init__ AND
store-level guard on add/save for candidates and cases — double-enforced).
LLM-sourced severity/CVE applicability/affected-versions/impact are
rejected at the advisor boundary (authority-claim rejection) and have no
write path into candidates, cases, or packages.

## 12. Case lifecycle

CANDIDATE -> TRIAGED -> VERIFYING -> VERIFIED -> READY_FOR_REVIEW ->
HANDED_OFF -> CLOSED; terminal alternatives REJECTED, INCONCLUSIVE,
DUPLICATE (+BLOCKED resumable). Cases are created only for verification-
bound candidates (never every candidate), and `case -> VERIFIED` is
refused by the store unless the candidate itself is gate-VERIFIED with
`gate_result=evidence_rules_met` (tested: raises FindingStateError).
Only verified candidates become VERIFIED security cases; insufficient
evidence remains a candidate.

## 13. Case package

`build_package()` (Phase 13 fields verbatim): title, target, scope,
endpoint_context, vulnerability_class, authoritative_verification
(decision + gate reason + detail + confidence + case_id), evidence_ids +
evidence_timeline with quality classes, observations (obs ids), research
history, related_candidates, duplicate relationships, knowledge consulted,
verification_plan (plan/auth/obs ids), verification_outcome,
confidence_provenance, severity_provenance, limitations
(no exploit, no payload, no fabricated PoC, no fabricated confidence,
gate decides, no paid model), recommended_analyst_next_step
(deterministic from the gate outcome + missing evidence).
No secrets: audit/handoff secret-scrub tested (api_key-style keys dropped).

## 14. Handoff

Read-only, integrated into the EXISTING SOC Handoff: finding case rows are
prepended into `handoff_index` (legacy reports bounded so finding rows can
never be starved by the legacy list limit), and `handoff_detail(job_id)`
falls back to a finding-package view exposing verified status, evidence
summary (labels only), provenance, target/scope, research lineage,
analyst notes, limitations + a candidate-not-yet-verified disclaimer when
applicable. API keys, secrets, DB internals and unauthorized targets are
never exposed (scrub + no-payload tests). No external submission
automation exists (Phase 14 out of scope, honored).

## 15. SOC

- `Findings` nav entry (AI SOC group, additive; allowlists updated in the
  two sanctioned guard tests, mirroring the Campaigns precedent).
- `/ui/soc/findings`: candidate index with state, verification state,
  evidence count, duplicate status, severity provenance, last
  verification, counts (verified/duplicate/in-verification), honest empty
  state ("no candidate findings yet", "waiting for real persisted
  research results").
- `/ui/soc/findings/{id}`: Phase 15 candidate detail in full — hypothesis,
  evidence with quality classes, missing evidence, related candidates +
  canonical links, verification objective (budget, plan/auth/obs ids),
  gate decision + reasoning, severity provenance, ADVISORY-labeled LLM
  block, handoff readiness, limitations, provenance, research history,
  transition timeline.
- Cases page: `kind` column distinguishes candidate-case vs verified-case
  vs gate-case vs aec-case; finding case rows carry evidence count,
  severity provenance, last verification, next action.
- Activity: all 13 required actions persisted from real transitions
  (candidate_detected ... case_handoff_ready) — all rows come from real
  persisted state; no fabricated activity.

## 16. Audit / provenance

`finding_event(stage, payload)` + `lineage_row(...)` per Phase 16:
candidate_id, verification_id, plan_id, job_id, campaign_id, objective_id,
specialist, model requested/resolved, prompt version, evidence refs, gate
result, lifecycle transitions with reason codes — recorded in the runtime
audit stream AND in finding-store transition/lineage rows rendered on the
candidate detail. Secret-key scrub on audit payloads (tested).

## 17. Security verification (Phase 18 — all boxes)

suite `tests/test_finding_verification_safety.py`, each item AST/static or
behavioral: candidate/verification/LLM cannot widen scope; LLM cannot
confirm/create evidence/create an authoritative case/execute
HTTP/shell/code/exploits (module import scans + advisor boundary);
authorization cannot be bypassed (pre-enqueue AuthorizationChecker +
denial path leaves candidate/ver BLOCKED with journal=0); unknown
observation rejected; duplicate execution prevented (WAITING resumes the
SAME job, never a second); severity fabricated rejected (model+store);
CVE applicability fabricated rejected; secrets scrubbed (audit + handoff);
unrestricted history unavailable (bounded context/histories); Evidence
Gate authoritative (store refuses VERIFIED without gate reason); paid,
unknown and missing models rejected (free-only guard); force-decide with
fabricated structured LLM confidence changes nothing.

## 18. Failure / recovery (Phase 17)

suite `tests/test_finding_failure.py`: malformed candidate (fail-closed
construction), missing provenance (traceability fields mandatory),
invalid scope (rejected before store — `invalid_scope:` skip, zero rows),
duplicate candidate (extract-twice -> DUPLICATE, one verification),
conflicting candidate (independent + both evidences), correlation failure
(malformed endpoint -> INDEPENDENT, no crash), verification plan failure
(worker raises -> FAILED + candidate BLOCKED, summary.error, honest
termination_reason), authorization denial, observation failure (job failed
-> FAILED/BLOCKED), evidence persistence failure (Fragile store ->
`evidence_unreadable`, never a fake decision; Phase-B read failure ->
FAILED + BLOCKED), gate failure (no gate record -> INCONCLUSIVE
`gate_record_absent`, never VERIFIED), LLM unavailable (advisor_provider_
error recorded, gate unaffected), LLM malformed (used=false recorded),
context overflow (advisor_disabled:context_too_large at max_context_chars
small), duplicate verification (verification_exists guard), stale
verification (EXECUTING resumes the same job), concurrent verification
(same job id, `ran==1`, never a second execution), case persistence
failure (package branch reports `package:` error, gate decision still
recorded), handoff generation failure (handoff_view raises -> empty
handoff dict, detail still renders). Expected outcomes honored: honest
state, no fake verification/case/evidence anywhere.

## 19. Real XSS validation

PENDING — scheduled for post-promotion (Phase 24 ordering: "After APPROVE:
... run production validation"). Plan: JOB A real XSS result ->
candidate -> triage -> verification -> gate, reporting exact candidate,
verification, plan, job, authorization, observation and evidence IDs, gate
result, final lifecycle state, case ID if created. Result may be VERIFIED /
REJECTED / INCONCLUSIVE / BLOCKED per real evidence — never forced.

## 20. Real CVE validation

PENDING — same sequencing, JOB B with the CVE_RESEARCH specialist against
real Watch research state + real Knowledge. Exact IDs reported in the
cycle-2 addendum. No VERIFIED will be forced.

## 21. Real deduplication validation

PENDING — same sequencing: the two real XSS research jobs already in
production (`job-xss-49b9d40fd5`, `job-xss-b1d237d202` — same class,
same scope) give a genuine cross-job duplicate pair; canonical choice,
DUPLICATE marking, evidence/provenance preservation and "no duplicate
verified case" will be demonstrated on real persisted data (Phase 20),
not fabricated. The deterministic logic is already exercised by
extract-twice dedup tests in all four suites.

## 22. Resource usage

Limits (fail-closed, cumulative, audited): max_candidates_per_job 10,
max_candidates_total 60, max_verification_objectives 6,
max_verification_observations 12, max_llm_calls 6, max_context_chars
4000, max_historical_candidates 20, max_related_cases 6,
max_verification_runtime_seconds 600, max_retries 3, worker concurrency 1.
Every consumption records before/after/reason rows (finding budget ledger
file); exhaustion raises BudgetExhausted and the run records an honest
limit reason instead of proceeding. Runtime/CPU/RSS instrumentation comes
from the real production runs (cycle 2 report section 22).

## 23. Tests

Cycle-1 totals (worktree, `PYTHONDONTWRITEBYTECODE=1`, every suite
isolated in its own process — no cross-module shadowing):
- NEW finding suites: core 74, verification_safety 37, failure 16,
  soc 13 = **140 OK**
- PRE-EXISTING R53 finding suites (untouched): safety 17, builder 33,
  context 18, evidence 13, hypothesis 9, identity 9, state 26,
  correlation 44, correlation_rules 40, correlation_safety 17 = **226 OK**
  (their `test_backend_does_not_import_r54` isolation guard tripped on my
  `finding_correlations.jsonl` file name during the first battery — a real
  contract break I fixed by renaming the data file to
  `finding_links.jsonl`; production baseline was verified OK before and
  after)
- Regression: campaign 144, hunt 118, intelligence 93 (research 70 +
  agent_intelligence 23), runtime 77, SOC/nav 52 = **484 OK**
- AEC discover: **2149 OK**
- **GRAND TOTAL: 2999 tests green, zero failures, zero errors, no
  hidden baseline failures** (the only baseline issue ever seen was the
  R53 isolation guard above, caused by this Epic and fixed in it).
Delivery gates (check.sh / diff guard / secret scan) run at commit time —
their exact output is quoted in section 26.

## 24. Documentation

This report (candidate model, triage, correlation, dedup, verification
objective/gate, evidence quality, case lifecycle, severity provenance,
handoff, audit lineage, safety boundaries, resource limits, real
validation status, known limitations) + Phase-0 architecture map + R53
relationship addendum. Module docstrings carry the phase mapping. The
new pages self-describe honest states (advisory banners, empty states).

## 25. Known limitations

1. Cycle-1 has NO production finding data yet: real XSS/CVE/dedup runs
   (sections 19-21) execute after APPROVE per Phase 24; cycle-2 adds exact
   IDs.
2. Blocked verifications are not auto-resumed by a later run (auth denials
   and blocked hunts stay BLOCKED honestly; retry is a deliberate action).
3. INCONCLUSIVE/REJECTED candidates are terminal in v1 (no re-verification
   loop — bounded by rule 26).
4. Correlation uses structured signals only (no semantic embedding — by
   design, rule "never identical from semantic similarity").
5. Case packages are built for gate-verified candidates; rejected/
   inconclusive cases keep their decision on the candidate page instead of
   a full analyst package.
6. The pre-existing R53 finding-intelligence layer (ai/**, NOT_CONFIRMED
   claim-safety build) is untouched and complementary: R53 = offline
   within-research claim safety; this Epic = persisted cross-run
   verification lifecycle. No feature of either duplicates the other.
7. Runtime CPU/RSS and live advisor latency are recorded in cycle 2 (real
   production runs), not fabricated here.

## 26. Git / delivery

Branch: `agent/daily-development`, base `dc3376d` (= production `f3c1fc1`
content). Explicit-file staging only (NEVER `git add -A`): exactly 32
files staged from a reviewed list (+8588/-8); the ~168 unrelated worktree
leftovers and production's 27 dirty entries untouched (verified:
`web/templates/command_center.html` and other pre-existing dirt stayed
out of the staged set). Delivery flow executed:
1. 2999-test battery all green (isolated suites),
2. explicit 32-file stage + staged-set verification (32 == 32),
3. commit `ca9a6d5` ("finding: Autonomous Finding Verification & Triage
   v1 (bounded candidate layer)"),
4. `push_safe.sh origin agent/daily-development` -> `dc3376d..ca9a6d5`
   (fail-closed push),
5. `report.sh` baseline refresh (DELIVERY-REPORT-2026-09-23 written),
6. `check.sh` -> **READY FOR PROMOTION**: PASS BRANCH, PASS COMMIT
   (1 ahead of main), PASS TESTS (82 OK), PASS PATH_GUARD (no forbidden
   path/secret/environment file; LARGE_DIFF advisory only), PASS REPORT
   (this report included), PASS PRODUCTION (unchanged: f3c1fc1, 27 dirty).
   WARN only: 168 unrelated uncommitted entries stay behind (by design).
7. `promotion/request.sh` -> STOP at Telegram APPROVE (rules 33/34).

## 27. Exact production commit(s)

- Cycle 1: agent commit **`ca9a6d5`** on `agent/daily-development`
  (pushed, `dc3376d..ca9a6d5`). Production remains **`f3c1fc1`** until
  Telegram APPROVE (rule 34); no merge, push to main, or deploy has
  happened.
- Cycle 2 (post-approval): promotion merge + service restart + real
  production validation (sections 19-21) — exact IDs appended then.

## 28. Promotion request ID(s)

- Cycle 1: created by `promotion/request.sh` AFTER the delivery gates
  PASS; the authoritative ID lives in `agent-reports/promotions/` and is
  quoted verbatim in the Telegram delivery message (rules 33/34 — the
  agent performs commit/push/promotion and stops for APPROVE).
- Cycle 2: to be created if the post-promotion validation requires it.

---

READY TO PUSH: YES
