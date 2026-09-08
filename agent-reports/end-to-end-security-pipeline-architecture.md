# Phase 5K — End-to-End Security Pipeline / Activation Architecture Review (READ-ONLY)

Status: ARCHITECTURE REVIEW ONLY. No file modified, no code written, no
Git operation, no network/DNS/browser/Nuclei/subprocess/LLM/Mongo, no
activation. All findings below come from static repository inspection
(Read/Glob/Grep only). B1/B2/B4/B5 remain BLOCKED.

## 1. Executive Verdict

**PASS (conditional): the frozen 5B→5J chain is sound end-to-end; production
activation is NOT authorized.**

Authority flows downhill exactly once with no inversion inside the frozen
chain: LLM/research propose (type-level CONFIRMED-rejection in
Hypothesis/TestPlan/Pattern/TargetIntelligence schemas) → issuance
authorizes (5B, store-provenance authority) → resolution/scoping gate
(5C/5D, typed, re-checked fresh at execution) → sealed executors observe
(5E/5F/5G, literal `LIVE_* = False`, verdict-free) → canonical builder
seals (only `EvidenceBuilder.begin` construction site outside tests) →
5I classifies (ONLY classification authority) → 5J materializes
(CONFIRMED-only, fresh revalidation, verbatim severity). Every security
transition is typed (`extra="forbid"`), version-pinned (~20 pins, no
silent cross-version consumption found), and test-gated.

The blocking risk is OUTSIDE the frozen chain: a live legacy parallel
pipeline (World A) remains runnable and writable, two same-named finding
types share one version string, and the dashboard owns a subprocess
task-trigger that could one day point at a live job. Three P0, five P1,
six P2, three P3 gaps below — all grounded in inspected code, none
requiring redesign of 5B–5J. No live execution, no production
persistence, and no blocker closure is authorized by this report.

## 2. Complete Component Inventory

| Component | Phase | Input | Output | Authority | Can execute? | Can classify? | Can persist? | Can notify? |
|---|---|---|---|---|---|---|---|---|
| Collectors (`ai/collectors/*`: cve, discovery, exploit, http, nuclei_template, reference) | Research | External sources | Typed research records | Facts only (collection) | No | No | ai_data research files | No |
| KnowledgeStore / PatternStore / ArtifactStore (`ai/knowledge/*`) | Knowledge | Collector records | Versioned patterns/artifacts w/ provenance | Facts only; "never produces findings" (docstring-enforced, test-gated) | No | No | ai_data/{knowledge,patterns,artifacts} | No |
| SecurityResearcher / XSSLLMResearcher (`ai/researcher/researcher.py`, `xss_llm_researcher.py`) | Research | Knowledge | `ResearchResult` (parsed LLM JSON, validated) | Proposal only (LLM text validated, never authority) | No | No | No | No |
| TargetIntelligence projector (`target_intelligence.py`) | Intel | DB recon docs | Program/Subdomain/Http/Url/Param projections (`target_intelligence/v1`) | Facts only; "NOT a security verdict" in schema | No | No | No | No |
| TargetMatcher (`target_matcher.py`) | Relevance | Pattern + TargetIntel | Match + CriterionOutcome | Proposal only (match ≠ vulnerability) | No | No | No | No |
| HypothesisEngine | Hypothesis | Match | `Hypothesis` (`hypothesis/v1`, status PROPOSED; CONFIRMED-like rejected at type level) | Proposal only | No | No | No | No |
| TestPlanBuilder | TestPlan | Hypothesis | `TestPlan` (`testplan/v1`, PROPOSED; CONFIRMED/NOT_VULNERABLE/VERIFIED rejected) | Execution description only | No | No | No | No |
| Artifact retrieval/validation (`artifact_retrieval.py`, `artifact_validator.py`, `nuclei_artifact_validator.py`) | Artifact | TestPlan + ArtifactStore | Validated `ArtifactReference` + bytes (safety/specificity gates) | Content safety only | No | No | ArtifactStore reads | No |
| Readiness (`test_plan_readiness.py`) | Gate | Plan + store | Readiness report | Pre-execution checklist, not permission | No | No | No | No |
| Authorizer service/store (`ai/authorizer/*`, 5B) | Authorization | `AuthorizationRequest` | `IssuedExecutionAuthorization` (`execution_authorization/v1`, nonce, TTL, CAS lifecycle) | Execution permission (store provenance = authority; dicts never coerced) | No | No | Authz store (memory/Mongo) | No |
| Resolver 5C (`ai/resolver/*`) | Target Resolution | Authz target | `TargetResolution` (`target_resolution/v1`, resolution_id) | Canonical identity only | No | No | No | No |
| Scope evaluator 5D (`ai/scope/*`) | Scope | Authz + resolution | `ScopeEvaluation` (`scope_evaluation/v1`, ALLOWED/DENIED/INCONCLUSIVE; INCONCLUSIVE never authorizes) | Scope permission | No | No | No | No |
| Sealed executors 5E/5F/5G (`ai/execution/*`) | Executor | Authz + resolution + evaluation + artifact | Sealed `EvidenceRecord` + result | Observation generation only (literal `LIVE_*=False`, verdict/severity/confirmed banned by tests) | Bounded, gated (fresh authz re-read, binding checks, ledger CAS consume) | No | Via builder→store only | No |
| EvidenceBuilder/Store/Index/Blob/Handoff 5H (`ai/evidence/*`) | Evidence | Executor observations | SEALED triple-hashed record; `EvidenceHandoff` (hashes only) | Immutable observation record (no verdict fields exist) | No | No | Blob+index (CAS, quarantine, tombstone) | No |
| Deterministic verifier 5I (`ai/verification/deterministic/*`) | Verifier | `VerifierInput` (handoff + envelope + pins) | `ClassificationResult` (`classification-result/v1`, hashed) | ONLY classification authority (CONFIRMED/severity/eligibility) | No | YES (only) | No | No |
| 5I seam `materialize_finding` | (seam) | ClassificationResult | 5I `SealedFinding` / None | Narrow default-deny helper, NOT production path | No | No | No | No |
| Finding pipeline 5J (`ai/finding/*`) | Finding | ClassificationResult + trusted infra | 5J `SealedFinding` (`sealed-finding/v1`), workflow record, alert | ONLY finding-materialization authority (CONFIRMED-only) | No | No | In-memory stores only | Offline seam only |
| Legacy World A (`verifier.py`, `http/browser/composite_executor.py`, `xss_pipeline.py`, schemas) | Legacy | `XSSCase` + LLM analysis | `XSSVerificationResult.findings: list[XSSFinding]` | NONE (execute-and-judge; hard-blocked) | YES (ungated requests/playwright) | YES (bypass) | Via watch_xss_verify only | No |
| `watch_xss_verify.py` job | Legacy ops | Endpoints (Mongo) | `XssFindings` Mongo docs | NONE (production bypass path) | YES (drives World A) | Via World A | Mongo `XssFindings` | No |
| Legacy Nuclei (`nuclei_runner.py::to_findings`, `nuclei_pipeline.py::save_findings`) | Legacy | Run results + caller severity | `NucleiFinding` + `ai_data/nuclei/findings/*.json` | NONE (stdout⇒matched; hard-blocked) | YES (`run(execute=True)` subprocess) | YES (bypass) | Research JSON files | No |
| `database/db.py` (+`XssFindings`, recon models, upserts) | Persistence | Crawler/job dicts | Mongo docs; Telegram recon alerts on write | Recon storage only | No | No | YES (Mongo) | YES (recon-only: title/status/new-http) |
| Dashboards/APIs (`app.py`, `app_local.py`, `api.py`, `backend/*`) | Presentation/ops | Mongo recon collections | HTML/JSON recon views; task subprocess trigger | NONE (recon display + allowlisted task launch) | YES (task runner spawns registered scripts) | No | TaskRun docs | No (no finding alerts exist) |

Test coverage anchors (by suite, inspected): 5B authorization, 5C
resolver, 5D scope, 5E/5F/5G executors (incl. `LIVE_* is False` and
no-legacy-surface tests), 5H core/store, 5I verifier (97), 5J pipeline
(84), plus negative-surface tests in artifact retrieval, pattern store,
target matcher, and evidence core.

## 3. Authority Flow

WHO decides, per transition (verified in code):

- Research/Pattern/Hypothesis/TestPlan: PROPOSE. Schemas type-reject
  CONFIRMED/NOT_VULNERABLE/VERIFIED (`hypothesis.py:264`,
  `test_plan.py:242-243`, `research_pattern.py:6-7`,
  `target_intelligence.py:7-8`). LLM JSON is parsed then validated
  (`researcher.py:parse_llm_json`, `xss_llm_researcher.py`
  validators); attribution errors are typed failures, never verdicts.
- Authorization: PERMIT. `issue_authorization` is the only dict→authority
  path; `IssuerContext.is_authority` is literally `False` so views can't
  be mistaken for permission; executors re-read fresh issuance from the
  store and call `require_live_for_execution` (stale copies can't
  resurrect consumed authority — `http_executor.py:2406-2420` pattern
  repeated per executor).
- Scope: PERMIT-scope. `require_allowed` with binding match on
  (authorization_id, execution_id, resolution_id); scope-drift
  (`scope_lists_hash_current` vs issuance) fails closed; INCONCLUSIVE
  never authorizes (`scope_evaluation.py:311`).
- Executor: OBSERVE. Typed-input gates (`isinstance` on all four
  authorities + artifact bytes + `ex-` handle), binding validation,
  ledger claim + authorization CAS consume BEFORE transport, bounded
  observations, no verdict/severity/confirmed tokens (test-banned).
- Evidence: RECORD. Builder is the single construction site
  (`builder.py:432`; executors call `EvidenceBuilder.begin`; only tests
  otherwise); `FORBIDDEN_EVIDENCE_FIELDS` + `extra="forbid"` make
  verdict-shaped fields unrepresentable; triple hashes make tampering
  detectable on every read.
- 5I: CLASSIFY (only). Pure functions over sealed bytes + pinned
  registry; advisory booleans/text never authority; NOT_VULNERABLE
  unreachable by construction.
- 5J: MATERIALIZE (only). `ClassificationResult` + trusted infra in,
  nothing else; no reclassification (equality/registry/policy lookups
  only), no severity computation (verbatim triple copy, literal-scan
  tested), CONFIRMED-only narrowing of 5I's broader ceiling.

Leak points found: (a) legacy World A collapses execute+classify+persist
into one call graph (§7, P0-1); (b) 5I's `materialize_finding` admits
POTENTIAL and stays importable next to 5J's CONFIRMED-only `materialize`
(§17, P0-2); (c) severity-adjacent free fields survive on legacy schemas
(`XSSFinding.confidence`, `NucleiFinding.severity`) with no version pins
(§7, P1-4). No leak inside the frozen chain: each gate re-verifies
rather than trusting upstream output.

## 4. Type / Contract Flow

Strong boundary (typed, `extra="forbid"`, test-pinned): Authorization →
Resolution → Evaluation → Executor result → EvidenceRecord → Handoff →
VerifierInput → ClassificationResult → SealedFinding (5J) → stores.
`model_dump`/`model_validate` crossings audited: `nuclei_pipeline.py:355`
(dump of legacy findings to dicts → file: SAFE direction, display only),
`hypothesis_engine.py:325` + `test_plan_builder.py:474,477`
(`model_validate` of internally-built provenance refs: same-process,
typed input), `artifact_validator.py:102` (bytes→typed content with
safety errors), `researcher.py:276` (LLM JSON→`ResearchResult`: parsed
then schema-validated — the correct untrusted→typed pattern).

Weaker-type entry points (all fail-closed, none reach a stronger
boundary): `model_copy(update=...)` skips pydantic validation — an
INCONCLUSIVE/out-of-vocab `outcome` can be smuggled into a COPIED
`ClassificationResult` instance; 5J authority/eligibility refuse it
(tested in 5J suite) but any FUTURE consumer that reads `.outcome`
without revalidation inherits the hole (§17, P2-2). `XssFindings.findings`
is `ListField(DictField())` — untyped dicts persisted as "evidence for
reporting" with zero schema (§8, P1-4). `audit_metadata: dict[str,str]`
on issuance and workflow labels/comments are the only sanctioned
free-text zones, and both are excluded from hashes/identity by
construction.

No silent cross-version consumption: every gate compares exact pinned
strings (`execution_authorization/v1`, `target_resolution/v1`,
`scope_evaluation/v1`, `evidence/v1`, `evidence-handoff/v1`,
`classification-result/v1`, `sealed-finding/v1`,
`5i-rules/v1`, `5i-severity-policy/v1`, `5j-eligibility-policy/v1`,
`5j-alert-policy/v1`); skew fails closed at each gate independently
(§11). `EvidenceHandoff`/`VerifiedEvidence`/`SealedFinding` cross only
as whole typed objects, never as field subsets.

## 5. Execution Authorization Chain

`Authorization → TargetResolution → ScopeEvaluation → Executor →
Evidence` verified per path: `http_executor.run` (ll.2369+)
type-checks all four inputs, re-reads FRESH issuance from the store,
`require_live_for_execution`, `_check_binding`, ALLOWED-only +
scope-drift + `require_allowed` triple-match, artifact revalidation +
bounded translation with no socket on failure, ledger claim +
authorization CAS consume pre-transport. Nuclei (`run`, l.1308) and
browser (`run`, l.1418) follow the same frozen pattern (per-phase
reports + test matrices; `LIVE_NUCLEI`/`LIVE_BROWSER` literal-False with
no assignment path). All three seal exclusively through
`EvidenceBuilder.begin` (only non-test construction sites:
`http_executor.py:2221`, `nuclei_executor.py:1572`,
`browser_executor.py:1730`). No executor runs without live issuance +
fresh resolution + ALLOWED evaluation + revalidated artifact + bounded
execution — each verified independently per path in code, with
`LIVE_GATE_BLOCKED`/`AUTHZ_NOT_LIVE` as the closed outcomes. The
counter-example that proves the rule: legacy World A executors
(`ai/verification/http_executor.py:requests.Session`,
`browser_executor.py:playwright`) execute UNCONDITIONALLY with no
authorization/scope/ledger concepts at all (§7, P0-1/P1-1).

## 6. Evidence Chain

`Executor → EvidenceBuilder → Seal → EvidenceStore → EvidenceHandoff →
5I`: single-use builder (spent after seal; no reassign/rebind/repair
API, test-asserted absent), frozen triple over bindings/observations/
content, canonical envelope bytes, blob put-if-absent + read-back +
conditional index + CAS mark-indexed + ledger CAS + audit (store
ordering inspected). Handoff carries references + hashes only;
INCOMPLETE → `HANDOFF_REJECTED` (data-state, never a negative);
provenance distinguishes CONSUMED-as-provenance from live permission.
Identities pinned end-to-end: program, canonical target tuple,
artifact id + content hash, authorization id + nonce lineage,
scope-lists hash, execution/execution-stage, derivation/template
hashes. No evidence can be created outside the canonical builder:
the only `EvidenceRecord(` site is `builder.py:432`; the only
`EvidenceBuilder.begin` callers are the three sealed executors (+
tests). Quarantine/tombstone/orphan/sweep are hooks/state only, never
mutation.

## 7. Verifier → Finding Chain

`ClassificationResult → 5I authority → 5J eligibility → fresh evidence
→ SealedFinding → persistence → notification` verified in `ai/finding/*`:
POTENTIAL (meaningful reflection, storage-attributed, nuclei-advisory,
legacy single-pass) → `OUTCOME_NOT_FINDING_ELIGIBLE`; UNKNOWN → same;
smuggled INCONCLUSIVE (via `model_copy`) → `AUTHORITY_STRUCTURE_INVALID`;
NOT_VULNERABLE → `ELIGIBILITY_INVARIANT_VIOLATION`; HTTP reflection and
Nuclei advisory can never be CONFIRMED in 5I (POTENTIAL ceilings +
unreachable transitions, both test-asserted) and therefore never reach
5J persistence. Severity flows verbatim (write-site + literal
structural tests). Stored XSS linkage (SUBMIT→READ→EXECUTION→
classification→finding) is pinned, never rebound. Dedup is by
deterministic id with byte-compare refusal; alerts fire only on fresh
persists with deterministic alert ids.

## 8. Legacy Bypass Audit

| Path | Creates? | Persists? | Exposes? | Alerts? | Verdict |
|---|---|---|---|---|---|
| `XSSVerifier.verify` / `_build_finding` | YES (`XSSFinding`, incl. POTENTIAL) | via job | via Mongo docs | No | HARD-BLOCK |
| `XSSVerificationPipeline.run` / `build_default_verifier` | passes through | No (returns result) | No | No | HARD-BLOCK (live composition) |
| Direct `XSSFinding(` | YES (free fields, raw payload) | if handed to job | via Mongo docs | No | HARD-BLOCK |
| Direct `NucleiFinding(` | YES (caller severity, `matched`) | via pipeline | via JSON files | No | HARD-BLOCK |
| `NucleiRunner.to_findings` | YES (stdout⇒matched) | via pipeline | via JSON files | No | HARD-BLOCK |
| `NucleiPipeline.to_findings` + `save_findings` → `ai_data/nuclei/findings/*.json` | YES | YES (research files) | files on disk, no .py readers found | No | HARD-BLOCK |
| `watch_xss_verify.main` → `mongo_persist` → `XssFindings` | drives World A | YES (POTENTIAL/INCONCLUSIVE rows, raw payloads, no pins) | Mongo collection; NO readers outside the job itself (writer + self-dedup only) | No | HARD-BLOCK + MIGRATION REQUIRED |
| 5I `materialize_finding` (admits POTENTIAL) | YES (POTENTIAL-capable) | No (no callers; flag False) | No | No | DEPRECATED (see P0-2) |
| `XSSVerificationResult.findings` list | n/a (carrier) | n/a | one attribute access from any future consumer | No | DEPRECATED |
| Dashboards/APIs (`app.py`, `api.py`, `backend/*`) | No | No | No finding routes/endpoints (recon only, verified) | recon-only | SAFE |
| Telegram (`telegram.py`) + `notifications.py` | No | No | recon strings only | YES — recon only (title/status/new-http, DB-write-triggered) | SAFE (with P1-3 pattern warning) |
| `ai_data/nuclei/results/*.json` | No (run logs) | research only | files on disk | No | SAFE (housekeeping) |
| Tests constructing legacy findings | YES (in-memory) | No | No | No | SAFE |

Net: no legacy path can reach 5J persistence/notification (type +
import-surface tested), but World A remains a COMPLETE parallel
production-capable pipeline (runnable CLI → live traffic → Mongo
persistence) that shares nothing with 5B–5J except the target
environment.

## 9. API / Dashboard / Alert Boundary

Authoritative finding source: the 5J in-memory store (no API serves it
yet — correct for this phase). Read paths: recon only (Flask
programs/subdomains/lives/http; FastAPI pages/programs/runs/changes/
search + JSON mirrors). Write paths: recon Mongo writes + TaskRun docs
+ ChangeEvent docs; NO finding write path exists anywhere outside the
two legacy factories. Alert paths: `db.py:upsert_http` →
`notify_title/status/new_http` → `telegram.Bot` (recon, synchronous,
DB-write-coupled); `notify_new_live_subdomain` currently commented out
at call site (`db.py:306`); ChangeEvent aggregation feeds dashboard
only. Legacy paths: none readable (XssFindings: zero non-job readers;
nuclei JSON: zero .py readers). Future injection paths to guard: any
new `/api/v2/findings` reader MUST serve 5J store only (never
`XssFindings`/JSON peers); any finding-alert hook MUST originate from
`FINDING_PERSISTED` events (never DB-write triggers — the recon alert
pattern must not be copied); `tasks_registry.py` MUST NOT gain
verify/nuclei/finding jobs without a dedicated activation review
(P1-2).

## 10. Persistence Boundary

5J security records (insert-only `FindingStoreMemory`, no update/patch/
delete/upsert — AST-asserted) and workflow records (separate
`WorkflowStoreMemory`, CAS versions, disjoint field sets — asserted)
are separate documents with `finding_id` as the only shared field;
workflow mutation provably preserves finding bytes (byte-compare test).
Deterministic identity, put-if-absent dedup, byte-compare refusal, and
append-only audit verified in implementation. When B2 opens, the
specified (never built) shape must be: `sealed_findings` collection,
unique `(program_name, finding_id)`, application-level insert-only
(MongoEngine documents are mutable by default — expose no update
method); `finding_workflows` collection, `finding_id` unique,
`findAndModify` on expected version; duplicate-key →
read-back-compare (identical = benign replay + dedup audit; differing =
quarantine path, loud audit, no overwrite); crash recovery = replay-safe
inserts with job checkpoints outside the security store. Do NOT open B2
in any 5K follow-up without the §14 control list.

## 11. Replay / Recovery

| Event | Expected | Security impact | Recovery |
|---|---|---|---|
| Process crash mid-materialize | No partial finding (single put; no multi-write tx) | None | Re-run; idempotent re-persist |
| Duplicate materialization | `DEDUPLICATED`, same bytes + id, no re-notify | None | No-op |
| Duplicate notification | Impossible by construction (ledger claim + dedup gate) | None | Ledger audit |
| Partial persistence | N/A (one atomic put per backend) | None | Retry |
| Audit sink failure | Swallowed; pipeline continues | Audit gap only (gap event where supported) | Gap reconciliation, never evidence/finding mutation |
| Evidence unavailable post-persist | `PERSISTED_UNVERIFIABLE` read flag | None (history stands; never "safe") | Restore/quarantine evidence; flag clears on re-verify |
| Corrupted evidence | Triple/index checks fail → NO FINDING (pre) / UNVERIFIABLE (post) | None | Quarantine path, loud audit |
| Workflow race | CAS conflict; loser re-reads | None (ops-only) | Retry with fresh version |
| Verifier/rule/policy/eligibility version change | Old pins fail closed; new pins fork new finding ids | Old findings remain valid under old pins | Re-materialize from original classifications; retain both |
| Stale evidence (quarantine/tombstone between classify and persist) | Fresh-read liveness gates → NO FINDING | None | Re-execute under new authorization |

No scenario mutates historical security facts in any backend.

## 12. Version Compatibility

~20 pins traced (`artifact/v1`, `hypothesis/v1`, `testplan/v1`,
`target_intelligence/v1`, `vulnerability_pattern/v1`,
`execution_authorization/v1`, `target_resolution/v1`,
`scope_evaluation/v1`, `target-resolver/v1`, `scope-evaluator/v1`,
`evidence/v1`, `evidence-handoff/v1`, `classification-result/v1`,
`sealed-finding/v1` ×2, `5i-rules/v1`, `5i-severity-policy/v1`,
`5j-eligibility-policy/v1`, `5j-alert-policy/v1`, executor schema
versions, oracle `ORACLE_VERSION=1`). No phase silently consumes a
foreign version: each gate compares exact strings and fails closed
(inspected at 5B issuance, 5C/5D evaluation, executor binding checks,
5H seal, 5I gate+registry, 5J authority+eligibility). Residual risks:
(a) version-string sprawl with no central registry — a new pin can be
added without registering its downgrade semantics (§17, P2-3);
(b) the duplicated `sealed-finding/v1` across two different shapes
(§17, P0-3); (c) `model_copy` bypass of Literal validation noted in
§4 (P2-2). Fail-closed holds everywhere checked.

## 13. Multi-Program Isolation

Binding chain per stage (all equality-checked, all fail closed):
issuance `target.program_name` → resolution binding → evaluation
binding → executor `_check_binding` → builder copies (program +
target tuple) → seal triple (target tuple, artifact, authz, scope
hash) → handoff pins → 5I gate (program/target/artifact/plan axes) →
classification pins → 5J fresh revalidation (all axes + internal
program consistency) → finding pins + `(program, finding_id)` store
keys + program-scoped list/get. Conceptual tests: A-evidence +
B-classification → triple/axis mismatch, NO FINDING (tested 5I+5J);
A-authorization + B-target → issuance binding mismatch at executor
AND 5I provenance AND 5J revalidation; A-artifact + B-evidence →
content-hash mismatch at translator, seal, and revalidation;
A-finding + B-workflow → store key miss (tested). One documented
asymmetry: the 5H triple covers `target.program_name` but not
top-level `record.program_name`; 5I checks both against the handoff
but not against each other — 5J added the internal check (P2-1).
Isolation holds; no cross-program read path exists (all list/get
operations require explicit program).

## 14. Secret Flow

Sealed-layer discipline (scrubber + observations + builder): secret
headers/params redacted, userinfo stripped, query hashed, bodies
hash-participating with bounded samples, dial IPs bounded. Findings
(5J): hashes/IDs/pins/summaries only — no field exists for cookies,
auth headers, bearer tokens, oracle S/D, OOB, bodies, console/DOM,
stdout, or LLM text (`extra="forbid"`, exact-36-field test). Audit
(5H/5I/5J): hashes + codes, secret-screened, secrecy-scanned in tests.
Notifications (5J seam): IDs only. Leakage surfaces found — ALL
legacy-side: `XSSFinding.payload_reference` (raw payload) +
`reflection/verification_evidence` free strings → persisted verbatim
into Mongo `XssFindings.findings` dicts; `NucleiFinding.raw_output`
(unbounded stdout) → Mongo-less JSON files on disk; `upsert_http`
persists raw `headers`/`url`/`title` to Mongo AND forwards title
strings to Telegram (`db.py:321-367` — any title/header content,
including reflected secrets or attacker-controlled strings, reaches
a third-party messenger on every DB write); `ai_data/nuclei/
results/*.json` embeds full Nuclei stdout (warnings, network errors,
target strings). No secret path reaches 5I/5J outputs; every secret
path found terminates in legacy recon/research storage or Telegram.

## 15. Live Activation Safety

NOTHING is activated by this review. Per-gate checklists for any
future (separately authorized) activation:

- `LIVE_TRAFFIC_ENABLED=True` (B1): production AddressSource
  reviewed + pinned dial policy (registrable-domain/port/downgrade/
  userinfo/IP-literal rules executed, not documented); executor
  ceilings re-proven under adversarial redirect/DNS; rollback = flag
  to False (literal, single assignment; no code path sets True —
  verified). Prereq: B1 closure review + live-traffic test matrix.
- `LIVE_NUCLEI=True` (B4+B2): payload-corpus source-of-truth (B4)
  closed with signed template provenance; Nuclei specificity policy
  versioned (5I→CONFIRMED path still absent by design — activating
  the runner without it yields advisory-only evidence, correctly);
  subprocess containment (cwd/argv/env allowlists already frozen).
- `LIVE_BROWSER=True` (B5): containment review (Playwright isolation,
  egress policy, oracle anti-harvest under live network, wall-clock
  bounds); B5 closure review.
- B1/B2/B4/B5 closure each requires: prerequisites above + security
  review + offline test matrix green + operational controls (audit
  pipeline, quarantine drills, key rotation) + rollback (flag/pin
  revert; findings remain valid under old pins per §11).
- World A MUST be severed (P0-1) before ANY activation: while
  `watch_xss_verify.py` runs ungated live traffic, flipping 5E/5F/5G
  flags cannot make the system safe — the legacy job would still
  execute outside all authorization.

Do NOT claim any blocker ready to close. All four remain BLOCKED.

## 16. End-to-End Trust Model

```
UNTRUSTED                          │ attacker-controlled: LLM text,
(external sources, LLM output,     │ pages, stdout, headers, titles
 page content, Nuclei stdout)      │ → treated as DATA, never authority
        │ parse + schema-validate  │
        ▼                          │
RESEARCH (facts only)              │ trust: NONE (validated containers)
        │ project/match/propose    │
        ▼                          │
PROPOSAL (Hypothesis/TestPlan)     │ trust: NONE (type-rejects verdicts)
        │ issuance (human/board)   │
        ▼                          │
AUTHORIZATION (5B permission)      │ trust: RISES (store provenance)
        │ resolve + evaluate       │
        ▼                          │
EXECUTION (5E/5F/5G bounded obs.)  │ trust: CHECKED (fresh re-reads,
        │ seal (triple hash)       │ binding validation, CAS consume)
        ▼                          │
EVIDENCE (immutable record)        │ trust: RISES (tamper-evident,
        │ handoff + provenance     │ single builder, hash-verified)
        ▼                          │
VERIFICATION (5I classification)   │ trust: PEAK (only authority that
        │ eligibility + revalid.   │ can say CONFIRMED/severity)
        ▼                          │
FINDING (5J sealed materialize)    │ trust: DERIVED (equality-bound to
        │ persist + notify         │ evidence+classification, nothing else)
        ▼                          │
OPERATIONS (workflow/alerts/dash)  │ trust: DESCENDS (mutable ops layer
                                   │ strictly separated from security)
```

Trust increases at exactly three steps: issuance (human/board
provenance), sealing (tamper-evidence), classification (proof
evaluation). No accidental inversion found in the frozen chain: every
downstream stage re-verifies rather than trusting; audit never grants;
timestamps never identify; workflow never touches security. The two
inversions that exist are both legacy-side and both documented:
World A trusts executor output as verdict input inside one call, and
`to_findings` trusts stdout shape as `matched`.

## 17. End-to-End Threat Model

(Attack → Gate → Fallback → Audit; all gates inspected, most
test-enforced.)

- Prompt injection → LLM-output validators + type-level verdict
  rejection → untrusted-data posture → no audit (rejected at parse).
- Poisoned research/pattern → provenance attribution + matcher
  criteria + artifact safety/specificity validators → proposal dies
  pre-issuance → validator errors.
- Malicious target / scope confusion → 5C canonicalization + 5D
  allowlist + fresh executor re-checks → closed DENY codes → scope
  audit records.
- Authorization forgery → store-provenance authority (dicts never
  coerced) + nonce/TTL/CAS + fresh re-read → `AUTHZ_NOT_LIVE` →
  executor/audit errors.
- Target/artifact rebinding → per-stage binding equality (translator,
  seal triple, handoff, 5I gate, 5J revalidation) → first-mismatch
  refusal → gate reason codes.
- Evidence tampering → triple recomputation + index-claim comparison
  on every read → quarantine, never reinterpreted → integrity audit.
- Forged classification → 5J authority (type + hash + pins + registry
  + severity recomputation + fresh-record binding) → NO FINDING →
  `FINDING_ELIGIBILITY_REJECTED`.
- Severity/finding injection → verbatim-copy + recomputation check +
  closed schemas → NO FINDING → rejection audit.
- Legacy bypass (all §7 paths) → 5J input-type unreachability +
  import-surface tests → NO FINDING; production risk isolated to the
  legacy job itself (P0-1).
- Duplicate finding/alert → deterministic ids + put-if-absent +
  alert ledger → dedup no-op → `FINDING_DEDUPLICATED`.
- Cross-program contamination → full-axis equality + program-scoped
  keys → NO FINDING → binding-mismatch audit.
- Version downgrade → exact-pin gates at every stage → fail closed →
  pin-mismatch reasons.
- Stale evidence → fresh-read liveness (quarantine/tombstone/index)
  → NO FINDING pre-persist; UNVERIFIABLE flag post-persist.
- Secret leakage → scrubber/redaction + closed finding/audit schemas
  + secrecy tests; residual legacy surfaces enumerated (§14).
- Persistence corruption → byte-compare refusal, no overwrite →
  `FINDING_STORE_REFUSED`, bytes + history retained.
- Workflow privilege escalation → separate CAS document, disjoint
  fields, no security PATCH → conflict/illegal-transition errors;
  security bytes provably untouched.

## 18. Integration Gaps

P0 BLOCKING (must resolve before any activation or production read):

- P0-1 — Runnable legacy live pipeline: `watch_xss_verify.py main()`
  (argparse CLI, `__main__` guard) drives ungated World A executors
  (`requests.Session`, playwright, no LIVE gates, no authorization/
  scope/ledger concepts) and persists to Mongo `XssFindings`. Bypasses
  5B–5J entirely with a single command. Grounded: `watch_xss_verify.py`
  :66/451/516, `ai/verification/http_executor.py:212`,
  `browser_executor.py:667`, `db.py:162`.
- P0-2 — Dual finding-minting APIs: 5I `materialize_finding` admits
  POTENTIAL (`FINDING_ELIGIBLE_OUTCOMES`) and stays importable next to
  5J's CONFIRMED-only `materialize`. One wrong import in future wiring
  launders POTENTIAL into findings around 5J eligibility. Mitigated
  today (flag False, no production callers); the API surface is the
  hazard. Grounded: `materialization.py:101`,
  `deterministic/__init__.py:75-78`.
- P0-3 — Shared finding identity surface: 5I `SealedFinding` and 5J
  `SealedFinding` share class name AND `finding_schema_version`
  `sealed-finding/v1` with different fields and different id
  derivations (5I lacks the eligibility pin). Co-storage or cross-
  `model_validate` confuses them silently (both `extra="forbid"` only
  rejects unknown fields, not missing ones... note: 5J shape has MORE
  required fields so 5I→5J validation fails closed, but 5J→5I
  validation SUCCEEDS while dropping security fields — the dangerous
  direction). Grounded: `materialization.py:45-85` vs
  `ai/finding/sealed.py:35-52`.

P1 HIGH:

- P1-1 — World A executors execute unconditionally (no live gates,
  no ceilings import); any current/future caller gets live traffic
  with zero authorization. Grounded as above.
- P1-2 — Dashboard subprocess trigger (`POST /api/tasks/{id}/run`,
  API-key-only) + append-a-line registry (`tasks_registry.py:8`):
  adding a verify/nuclei job (or editing the registry file on a
  compromised host) converts the dashboard into a remote live-
  execution trigger. Registry currently crawl/DNS-only (contained).
- P1-3 — Alert-on-DB-write pattern (`db.py:321-367`): any writer
  triggers Telegram; raw titles/headers/URLs flow to a third party
  and persist in Mongo. A future finding hook copied from this
  pattern would leak finding-adjacent content and alert on forged
  rows. Finding alerts must originate from `FINDING_PERSISTED`
  events only.
- P1-4 — `XssFindings` persists POTENTIAL/INCONCLUSIVE rows, free
  confidence, raw payloads/evidence strings, no version pins, as
  untyped dicts; sole writer/reader is the legacy job (contained
  today) — any dashboard read would launder non-findings into
  authority. MIGRATION REQUIRED before serving.
- P1-5 — `ai_data/nuclei/findings/*.json` (+ `results/*.json` with
  full stdout) persist caller severity + unbounded `raw_output` as
  world-readable files beside future 5J storage; no .py readers
  found, but the `findings` naming invites confusion.

P2 MEDIUM:

- P2-1 — 5H triple omits top-level `record.program_name` (covers
  `target.program_name`); 5I checks both against the handoff but not
  each other (gate.py:151-152 tautological for honest handoffs);
  5J added the internal check. Frozen; document, don't redesign.
- P2-2 — `model_copy` skips validation: out-of-vocab outcomes smuggle
  into copied instances; only consumers that revalidate (5J does)
  are safe.
- P2-3 — ~20 version pins, no central registry; downgrade safety is
  per-gate, not global. A new pin without gate coverage fails OPEN
  by omission (process gap, not code gap).
- P2-4 — `XSSVerificationResult.findings` remains a consumable list;
  `xss_pipeline.run` passes it through — one attribute access from
  authority in any future consumer.
- P2-5 — Telegram/recon helpers are call-site-unauthenticated library
  functions; finding alerts must use the 5J ledger+identity seam,
  never this pattern.
- P2-6 — "INCONCLUSIVE" means three different things (scope decision
  vs matcher verdict vs legacy finding status); reason-code confusion
  across phases is currently harmless (all fail closed) but brittle.

P3 LOW:

- P3-1 — Research JSON artifacts embed noisy stdout (version
  warnings, network errors); housekeeping, no security semantics.
- P3-2 — Dozens of `__main__` CLI surfaces (crawl/ns/enum/http)
  outside the task-registry allowlist: intentional for ops, but each
  is an unreviewed live-traffic path adjacent to the security chain
  (out of 5K scope per AGENTS.md subsystem rules; noted for
  completeness).
- P3-3 — World A redirect/DNS/IP policy predates the 5E
  registrable-domain discipline; moot while hard-blocked, relevant
  only if World A code is ever reused.

Counts: P0=3, P1=5, P2=6, P3=3.

## 19. Production Readiness Matrix

DO NOT declare production-ready. Current state per capability:

| Capability | Current state | Required before production | Blocker |
|---|---|---|---|
| HTTP execution | Sealed offline impl, gates frozen, tests green | B1 source review + live dial policy + live matrix | B1 |
| Nuclei execution | Sealed offline impl, advisory-only | B4 corpus truth + specificity policy for CONFIRMED | B4 (+B2) |
| Browser/XSS execution | Sealed offline impl, oracle/stored proofs | B5 containment + live-network review | B5 |
| Evidence | Frozen, triple-hashed, CAS, quarantine/tombstone | Production Mongo adapters (B2) | B2 |
| Verifier 5I | Implemented, PASS, pure | None (done) | — |
| Finding 5J | Implemented, PASS, in-memory only | B2 adapters; resolve P0-2/P0-3 | B2 |
| Persistence | In-memory + B2-blocked stubs | Mongo collections per §10 + unique indexes | B2 |
| Alerts | Offline seam only; recon Telegram only | `FINDING_PERSISTED`-originated alert path; never DB-write pattern | (design done) |
| API | Recon only; no finding routes | 5J-store-only `/api/v2/findings` readers | — |
| Dashboard | Recon + task runner; no finding views | Finding views from 5J store; registry change control | — |
| Scheduler | Manual task trigger (allowlist); systemd core (out of scope) | Scheduled 5B–5J runs with idempotency + ceilings | ops phase |
| Recovery | Replay-safe inserts; dedup; UNVERIFIABLE flags | B2 crash-recovery drills | B2 |
| Observability | Append-only audits per phase; gap events | Centralized audit collection + alerting on gaps | ops phase |
| Legacy severance | Hard-blocked in 5I/5J; still runnable (P0-1) | Sever/delete World A job + factories or gate behind explicit flag | P0-1 |

## 20. Recommended Next Phase

**Test hardening + legacy severance (no new capability):** (1) resolve
P0-3 (diverge the two `SealedFinding` version strings or delete the 5I
seam shape now that 5J exists) and P0-2 (narrow or remove 5I
`materialize_finding`'s POTENTIAL path); (2) gate `watch_xss_verify.py`
behind an explicit non-default flag or remove its `__main__` live path
(P0-1) — all test-proven, all offline, zero blocker impact. Next AFTER
that: **blocker closure in dependency order B1 → B4/B5 → B2**, each
with its §15 checklist; production persistence (B2 adapters) only after
legacy severance lands, otherwise new Mongo collections coexist with
live legacy writes. No new architecture phase is needed for the frozen
chain itself — it is reviewed and sound. No live-executor work until
its blocker review exists.

## 21. Remaining Blockers

B1 = BLOCKED. B2 = BLOCKED. B4 = BLOCKED. B5 = BLOCKED. None closed,
none touched, none ready to close (per-gate prerequisites in §15).

LIVE_BROWSER = False. LIVE_NUCLEI = False. LIVE_TRAFFIC_ENABLED = False.
All three verified as literals in `ai/execution/*` with no assignment
path (5E/5F/5G frozen reports + test-pinned).

No implementation. No production activation. No live execution.
