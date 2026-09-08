# Deterministic TestPlan Builder (Phase 4B) — Implementation Report

## 1. Verdict

**IMPLEMENTED**

A deterministic TestPlan construction layer converting one bound
Hypothesis into one PROPOSED TestPlan (test intent only) is
implemented in one new module, proven by 63 focused tests
(adversarial matrix A–AF plus a pure in-memory integration
chain), with every required regression suite passing unchanged.
One minimal additive extension to `ai/schemas/test_plan.py` was
objectively required for hypothesis/match/snapshot binding; all
pre-existing identity keys reproduce byte-for-byte.

## 2. Actual Repository Findings

Authority was the worktree code, not prior reports. Confirmed:

- **TestPlan contract** (`ai/schemas/test_plan.py`): `TestPlan`
  with `test_plan_id` (`tp-` alias of full-SHA-256 key),
  `hypothesis_id` binding, descriptive `TargetRef`, closed
  `TestCategory` (xss_reflected/xss_stored/xss_dom/xss_generic/
  nuclei_cve/nuclei_generic/http_signature/http_probe), closed
  `ExecutionType` (http_verification/browser_verification/
  nuclei_scan/http_probe), closed `VerifierType` (xss_verifier/
  nuclei_verifier/http_matcher/manual_review), constrained
  `HttpRequestSpec` (relative path, newline-safe maps, no
  credentials/commands), content-hashed `ArtifactRef`,
  lifecycle PROPOSED → APPROVED/REJECTED/SUPERSEDED/CANCELLED
  (APPROVED = syntax approval, never authorization). The pre-4B
  key basis (hypothesis + target + category + execution +
  objective + spec + verifier) had NO match/snapshot binding.
- **Verifier/execution representation**: the three enums live
  ONLY in `test_plan.py` (no consumer in `nuclei_pipeline.py`
  or the XSS stack references them); they are vocabulary, not
  runtime hooks — the builder targets them without touching or
  invoking any runtime. No XSS payload, Nuclei template, or
  browser capability is constructed anywhere in this phase.
- **Hypothesis contract** (Phase 4A shape): `hypothesis_id`,
  optional `match_id`/`snapshot_hash`, closed
  `hypothesis_type`/`pattern_kind`, descriptive target
  (program/subdomain/scope/endpoint/technology_snapshot/
  observed_at), verbatim `ResearchProvenance`, neutral priority.
  The engine emits only vulnerability_relevance and
  technique_relevance; technology_relevance/attack_surface
  exist in the enum but have no producer.
- **Neighbors**: matcher/TI/projector/store unchanged and
  unimported except as typed inputs; `scope_policy.py` exists
  and was deliberately NOT imported.

## 3. Exact Contract Implemented

```python
build_test_plan_from_hypothesis(
    hypothesis: Hypothesis,
    *,
    match: TargetPatternMatch | None = None,
    pattern: VulnerabilityPattern | AttackPattern | None = None,
    target_intelligence: TargetIntelligence | None = None,
) -> PlanResult  # CREATED | UNSUPPORTED | REJECTED

build_test_plans_from_hypotheses(
    hypotheses: list[Hypothesis] | tuple,
    *,
    match_resolver=None,      # match_id -> match | None
    pattern_resolver=None,    # pattern_id -> pattern | None
    target_resolver=None,     # snapshot_hash -> TI | None
) -> tuple[PlanResult, ...]   # sorted by hypothesis_id, deduped
```

`PlanResult` (frozen): `outcome`, `plan` (TestPlan on CREATED),
deterministic `reason`, `hypothesis_id`. Typed inputs only —
raw dicts/strings/IDs → `TypeError`. Binding gates (REJECTED):
non-PROPOSED lifecycle; `hypothesis.pattern_id` vs supplied
pattern; `hypothesis.match_id` vs supplied match (unverifiable
binding also REJECTED); `hypothesis.snapshot_hash` + program/
subdomain vs supplied TI; match↔pattern type agreement and
match↔TI observation agreement. Derivation (UNSUPPORTED unless
safe): vulnerability_relevance → CVE/GHSA ids ⇒
nuclei_cve/nuclei_scan/nuclei_verifier; matched endpoint ⇒
http_probe/http_probe/http_matcher; otherwise ⇒
http_probe/http_probe/manual_review. technique_relevance
requires the bound AttackPattern's technique label to carry an
explicit `xss` token (reflect→xss_reflected/http_verification,
dom→xss_dom/browser_verification,
stored→xss_stored/browser_verification, else
xss_generic/http_verification, all with xss_verifier);
missing pattern or non-XSS technique ⇒ UNSUPPORTED.
technology_relevance/attack_surface ⇒ UNSUPPORTED (no safe rule;
no generic-execution escape hatch).

Request spec as DATA only: path = hypothesis endpoint when
spec-valid else `/`; method = single distinct pattern surface
method for the path else GET; query params = pattern-declared ∩
target-observed query names with EMPTY values; headers always
`{}`; body always None — no credentials, tokens, secrets,
cookies, absolute URLs, or payloads invented. Preconditions are
closed templates keyed by matched criteria (none without a
match); objective/expected-behavior/required-evidence are fixed
intent templates naming IDs only, asserting no vulnerability,
no authorization, no finding. Provenance is the hypothesis
provenance verbatim; `artifact_ref` stays None; status
PROPOSED.

## 4. Files Changed

| File | Action | Why |
|---|---|---|
| `ai/researcher/test_plan_builder.py` | CREATED (~470 lines) | Deterministic builder: single + batch APIs, `PlanResult`, binding gates, closed derivation tables, safe request-spec construction |
| `ai/test_test_plan_builder.py` | CREATED (63 tests) | Matrix A–AF + pure integration chain |
| `ai/schemas/test_plan.py` | MINIMAL ADDITIVE EXTENSION | Optional `match_id`/`snapshot_hash` fields + optional key-basis params + factory passthrough (§5) |
| `agent-reports/test-plan-builder-implementation.md` | CREATED | This report (written from scratch; no prior file existed) |

No other file was created, modified, or renamed. Matcher, TI,
projector, store, hypothesis engine, scope policy, Nuclei/XSS
runtimes, collectors, crawler, and database models are
untouched.

## 5. TestPlan Identity / Idempotency

Mirroring the proven Phase 4A pattern: `TestPlan` gains
`match_id` (`^tm-…`) and `snapshot_hash` (64-hex), both
optional/validated/default-None; `test_plan_idempotency_key`
and `build_test_plan` accept both and include them in the
canonical basis ONLY when non-empty. Proven: legacy calls
reproduce legacy keys byte-for-byte; bound calls diverge.
Guarantees (tested): same hypothesis + same context → same
`test_plan_id` (modulo audit-only `created_at`); different
hypothesis/snapshot/target/execution/spec/verifier → distinct
identities; stale snapshot against a bound hypothesis →
REJECTED (never reuses an identity); preconditions stay
excluded metadata per the existing basis (converge by design);
duplicates dedupe; input kwarg order irrelevant; batch sorted
by `hypothesis_id`.

## 6. Hypothesis Binding

`TestPlan.hypothesis_id == hypothesis.hypothesis_id`
(constructor-enforced); target copied verbatim from the
hypothesis target (program/subdomain/scope/endpoint/
technology_snapshot/observed_at); provenance copied verbatim;
`match_id`/`snapshot_hash` carried from the hypothesis onto
the plan. Supplied context is cross-checked field-by-field
(§3); anything unverifiable or contradictory → REJECTED.
Non-PROPOSED hypotheses → REJECTED (plans build only from live
proposals).

## 7. Match Binding

When a match is supplied, `hypothesis.match_id ==
match.match_id` and `hypothesis.pattern_id ==
match.pattern_id` are enforced, plus match↔pattern type
agreement; the plan's `match_id` then equals the match alias,
making plan→match audit exact. Hypotheses without match
binding plus a supplied match → REJECTED (unverifiable).
Preconditions derive exclusively from the bound match's closed
criteria lists via fixed templates — no prose interpolation.

## 8. Snapshot Binding

When TI is supplied, `hypothesis.snapshot_hash ==
target.snapshot_hash` plus program/subdomain agreement are
enforced, with match↔TI observation agreement as defense in
depth; the plan's `snapshot_hash` equals the TI hash. A bound
hypothesis evaluated against a different snapshot → REJECTED,
so stale snapshots cannot reuse a plan identity (tested both
as single-build REJECTED and as distinct-identity across
snapshots). Hypotheses without snapshot binding plus supplied
TI → REJECTED.

## 9. Request Safety

`HttpRequestSpec` validators (relative path, newline-safe maps)
are the hard boundary, asserted hostile: path/Header/query
CRLF and absolute-URL paths raise `ValidationError` at the
contract. The builder additionally never emits risky content:
path allowlist (hypothesis endpoint or `/`), single-method
rule else GET, observed-intersection query NAMES with empty
values, zero headers, null body, and a defensive fallback to
the default spec. Proven: no cookie/authorization/CSRF/token/
secret/session/password/bearer string appears; no
command/shell/subprocess/browser_script/javascript/callback/
payload_executor key exists on any plan.

## 10. Execution / Verifier Boundary

Category/execution/verifier come ONLY from the §3 tables over
closed enums; prose, severity, CVSS, urgency, and
instruction-shaped text are never read (proven: CRITICAL/
10.0/CVSS-vector patterns build byte-identical triple+spec).
An HTTP plan never requests, a Nuclei plan never scans, a
browser plan never launches — the builder imports no client,
runner, or automation library, and `artifact_ref` is always
None (no templates, payloads, or scripts generated).
Unsupported inputs (non-XSS techniques, pattern-less
technique hypotheses, technology_relevance/attack_surface)
→ UNSUPPORTED, never a guessed triple. Verifiers remain the
sole future authority; plans reference verifier TYPES only.

## 11. Scope Boundary

Scope policy is absent from the import graph (AST-proven);
no scope computation, no ooscope inspection, no
`scope_allowed`/`execution_allowed`/`authorized` field exists.
Target scope travels as descriptive TI/hypothesis data only,
and every CREATED reason plus the objective state that the
artifact is never authorization and executors must re-resolve
target and scope.

## 12. LLM / Network / Subprocess / DB Boundary

AST import scans prove the builder imports schemas + stdlib
dataclasses/typing only: no LLM/provider/embedding/model/
agent/prompt, no requests/httpx/urllib/socket/DNS/browser
automation, no subprocess/os/sys/shutil, no
database/mongo/store/knowledge. Full single + batch builds run
with `socket.socket` disabled; a temp-dir test proves zero
filesystem side effects. No TestPlan store exists in this
phase — in-memory objects only.

## 13. Adversarial Test Coverage

63 tests: A wrong-type hypothesis → TypeError; B legacy
binding-less hypothesis builds hypothesis-only; C–F
match/pattern/snapshot/program mismatches + type disagreement
+ non-PROPOSED lifecycle → REJECTED; G–I unsupported types/
technique-without-pattern/non-XSS-technique → UNSUPPORTED;
J–L/AA–AC identity matrix (repeat convergence, snapshot/
hypothesis divergence, kwarg-order irrelevance, legacy-key
compat, stale-snapshot REJECTED); M–O contract CRLF rejection
(path/header/query); P–R hostile command/CRITICAL/EXPLOIT
prose inert with byte-identical derivation and PROPOSED
status; S–W import scans + network-disabled + side-effect +
no-finding/no-scope field scans; X no execution artifacts;
Y no verdict/evidence fields; Z cross-program isolation; AD
APPROVED-as-syntax-only proof; AE/AF field-absence scans;
AB batch dedupe; batch resolver ordering/isolation/
unresolvable coverage.

## 14. Integration Test

Pure in-memory chain: GroundedClaim → projector → pattern →
TI projection → matcher → hypothesis engine → builder →
PROPOSED TestPlan, asserting plan↔hypothesis↔match↔snapshot
binding and scanning the final artifact for verdict/scope/
execution/evidence authority (none present). No database,
network, LLM, subprocess, or execution at any step.

## 15. Exact Test Results

From `/opt/watch`:

```
python3 -m unittest ai.test_test_plan_builder
  Ran 63 tests — OK
python3 -m unittest ai.test_hypothesis_testplan ai.test_research_pattern \
  ai.test_pattern_projector ai.test_pattern_store \
  ai.test_target_intelligence ai.test_target_matcher ai.test_hypothesis_engine
  Ran 404 tests — OK
python3 -m unittest ai.test_ingestion_schema ai.test_ingestion_grounding \
  ai.test_knowledge_store ai.test_knowledge_ingestion
  Ran 132 tests — OK
python3 -m unittest ai.test_openrouter ai.test_xss_researcher \
  ai.test_xss_llm_researcher ai.test_xss_orchestrator \
  ai.test_xss_verification ai.test_xss_oracle
  Ran 294 tests — OK
python3 -m compileall -q ai   (clean)
```

No unrelated pre-existing failures encountered in any runnable
suite. Correlator live scripts (MongoDB + network, 0 unittest
cases) are not runnable here and unaffected (untouched).

## 16. Limitations

1. `created_at` is audit-only wall-clock metadata excluded
   from identity (all-phases convention); identity comparisons
   exclude it.
2. Technique coverage is XSS-only by explicit token rule;
   non-XSS techniques are UNSUPPORTED until a future phase
   defines safe derivations — a deliberate under-build.
3. technology_relevance/attack_surface hypotheses are
   UNSUPPORTED (no producer emits them today; no escape hatch
   invented).
4. Query values are always empty and bodies always null: plans
   specify *where*, never *with what* — payload design belongs
   to a later artifact phase with its own safety gates.
5. Resolver freshness (TOCTOU between resolve and build) is
   the caller's responsibility; the builder re-validates every
   resolved object through the binding gates.
6. `nuclei_cve` plans reference the verifier type only; template
   specificity/safety gates (adversarial-review H1/H2) must
   still be satisfied before any future generation/execution.

## 17. Explicit Git No-Op Confirmation

**No Git operation was performed.** No `git status`, `diff`,
`add`, `commit`, `checkout`, `switch`, `restore`, `reset`,
`merge`, `branch`, `stash`, or any other git command was run.
Unrelated working-tree state was not inspected, staged,
modified, or cleaned.

## 18. Recommended Next Safe Phase

The smallest safe next phase is **deterministic artifact
reference binding** (plan → content-hashed `ArtifactRef`
without generating executable content): define how a future
generator binds Nuclei-template/XSS-payload bytes to a plan
via hash alias with specificity/safety validators as code
gates (H1/H2), still without executing anything. Do NOT build
LLM generation, executors, schedulers, queues, verification,
feedback loops, or findings until artifact references exist
with fixture proofs that untrusted bytes cannot reach
execution.

---

*Phase 4B ends at Hypothesis + deterministic structured
context → PROPOSED TestPlan. No Git operations were
performed; the index is untouched. Report created at
`/opt/watch/agent-reports/test-plan-builder-implementation.md`.*
