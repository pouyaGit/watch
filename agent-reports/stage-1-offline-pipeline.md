# Stage 1 — Offline Authorized Pipeline (5B–5J Dry-Run)

## 1. Stage objective

Build the first production-wiring layer for the deterministic 5B–5J
architecture: one orchestration module connecting the existing offline
pieces end-to-end for a single Watch endpoint, while keeping ALL live
execution disabled. No new authorization, scope, evidence, or finding
models; no parallel duplicates; smallest possible orchestration
surface (one module + one test module).

## 2. Architectural context

The authoritative chain is the phased 5B–5J pipeline:

* 5B Authorizer (`ai/authorizer`) — `AuthorizationRequest` (intent) →
  `IssuedExecutionAuthorization` (authority by reference only),
  `InMemoryAuthorizationStore` with CAS semantics.
* 5C Resolver (`ai/resolver`) — `TargetResolver` over an injected
  `InventoryRepository` + `DnsResolver`, emitting immutable
  `TargetResolution` facts (never permission).
* 5D Scope (`ai/scope`) — `ScopeEvaluator` over an injected
  `PolicyStore`, emitting `ScopeEvaluation`
  (`ALLOWED` / `DENIED` / `INCONCLUSIVE`, semantics frozen).
* 5E/5F/5G Executors (`ai/execution`) — offline in Stage 1;
  `LIVE_TRAFFIC_ENABLED = False`, `LIVE_NUCLEI = False`, browser live
  execution gated. Only the pure 5E translator
  (`translate_bounded_request`) is used, producing an execution SPEC.
* 5H Evidence (`ai/evidence`) — `EvidenceBuilder` → sealed
  `EvidenceRecord` (triple-hash integrity) → in-memory `EvidenceStore`.
* 5I Verifier (`ai/verification/deterministic`) — `verify_handoff()`
  (integrity/provenance gate, first-failure-wins) →
  `ClassificationResult` (`UNKNOWN` / `POTENTIAL` / `CONFIRMED`;
  `NOT_VULNERABLE` unreachable by construction).
* 5J Finding (`ai/finding`) — `materialize()` (CONFIRMED-only
  eligibility) over in-memory stores (dry-run).

The legacy World A pipeline (`ai/verification/verifier.py`,
`http_executor.py`, `browser_executor.py`, `composite_executor.py`,
`xss_pipeline.py`; sole driver `watch_xss_verify`, permanently
disabled in Phase 5K) was not revived, reconnected, or imported.

## 3. Exact pipeline flow implemented (`run_stage1`)

```
EndpointView
 -> build_test_plan() [http_probe / http_probe / http_matcher]
 -> build_validated_reference(..., "http_request_spec")  [must be VALID]
 -> AuthorizationRequest -> issue_authorization() [InMemory store]
 -> TargetResolver.resolve() [InMemoryInventory + FakeDnsResolver]
 -> ScopeEvaluator.evaluate()  [or evaluate_chain() when redirect_hops set]
 -> hx.translate_bounded_request()  [SPEC ONLY — nothing launched]
 -> EvidenceBuilder synthetic HttpObservation (HTTP 200, inert body) -> seal()
 -> EvidenceStore.persist_sealed() [in-memory] -> StoreVerifiedRead seam
 -> VerifierInput -> verify_handoff()  [existing 5I entry point]
 -> materialize()  [existing 5J entry point, in-memory infra]
```

Failure mapping (`Stage1Error`, closed codes, wiring-only, never a
verdict): `ARTIFACT_NOT_READY`, `AUTHZ_FAILED`, `RESOLUTION_FAILED`
(non-`RESOLVED`), `SCOPE_DENIED`, `SCOPE_INCONCLUSIVE`,
`SPEC_FAILED`, `EVIDENCE_FAILED`, `VERIFY_BLOCKED`,
`LIVE_GATE_VIOLATION`. Scope stops precede spec/evidence construction.
The synthetic evidence carries no oracle marker, so the frozen 5I
classifier honestly answers `UNKNOWN` and 5J refuses with
`OUTCOME_NOT_FINDING_ELIGIBLE` — no `CONFIRMED` is manufactured.

## 4. Files created and their purpose

* `ai/stage1_offline_pipeline.py` (~450 lines) — the orchestration
  module. Defines `EndpointView` (duck-typed Endpoints projection:
  `program_name`, `subdomain`, `path`, `example_url`, `params`,
  `method`), `Stage1Config` (scopes/ooscopes, fake DNS answers,
  fixed clock instants, optional redirect hops), `Stage1Error`
  (closed wiring-error vocabulary), `Stage1Result` (all intermediate
  records + verification/materialization outcomes + audit notes),
  and `run_stage1()` (steps above). Deterministic identity
  derivation: `hyp-` (hypothesis), `tp-` (test plan via existing
  factory), `art-` (artifact via existing factory), `ex-`
  (execution, `sha256("stage1-ex"|plan|artifact|program|host)`).
* `ai/test_stage1_offline.py` (11 tests, stdlib `unittest` only) —
  happy path, envelope round-trip, scope DENIED, scope INCONCLUSIVE
  via address-less redirect hop, ooscope exclusion DENIED, expired
  authorization failure, shared-store determinism, live gates closed,
  live runners refuse, no legacy-store import, no live/legacy
  execution.

No existing file was modified by this stage.

## 5. Existing contracts reused

* `ai.schemas.test_plan.build_test_plan`, `ai.schemas.hypothesis`
  (`TargetRef`, `ResearchProvenance`), `ai.schemas.artifact`
  (`artifact_id_for`, `content_hash_for_bytes`, `ArtifactReference`).
* `ai.researcher.artifact_validator.build_validated_reference`.
* `ai.authorizer.service.issue_authorization`,
  `ai.authorizer.store.InMemoryAuthorizationStore` (issuance/CAS/lease
  semantics untouched; Mongo persistence explicitly deferred).
* `ai.resolver.resolver.TargetResolver`,
  `ai.resolver.inventory` (`InMemoryInventoryRepository`,
  `ProgramRecord`, `AssetRecord`, `scope_lists_hash_for`),
  `ai.resolver.dns.FakeDnsResolver`,
  `ai.resolver.canonicalization.canonicalize_host`,
  `ai.schemas.target_resolution.ResolutionRequest`.
* `ai.scope.evaluator.ScopeEvaluator` (+ `HopObservation`),
  `ai.scope.policy.InMemoryPolicyStore`.
* `ai.execution.http_executor.translate_bounded_request` (pure) and
  the `LIVE_TRAFFIC_ENABLED` / `LIVE_NUCLEI` gate constants
  (read-only).
* `ai.evidence.builder.EvidenceBuilder`, `ai.evidence.observations`
  (`observe_url`, `observe_body`), `ai.evidence.blob_store`
  (`InMemoryBlobStore`), `ai.evidence.index`
  (`InMemoryEvidenceIndex`), `ai.evidence.store`
  (`EvidenceStore.persist_sealed`, `canonical_envelope_bytes`,
  `parse_envelope`), `ai.evidence.handoff`
  (`assemble_handoff`, `bind_provenance`).
* `ai.verification.deterministic.pipeline.verify_handoff`,
  `ai.verification.deterministic.models` (`VerifierInput`,
  pinned `VERIFIER_VERSION`/`RULES_VERSION`/`POLICY_VERSION`),
  `ai.verification.deterministic.verified_read.StoreVerifiedRead`.
* `ai.finding.materializer` (`FindingInfrastructure`,
  `materialize`), `ai.finding.store_memory`
  (`FindingStoreMemory`, `WorkflowStoreMemory`),
  `ai.finding.notify` (`RecordingNotificationSink`,
  `AlertLedgerMemory`).

## 6. Safety boundaries and live-execution gates verified

* `_assert_live_gates_closed()` runs at pipeline start and again
  immediately before spec translation; any non-`False` gate raises
  `Stage1Error(LIVE_GATE_VIOLATION)`.
* Tests assert `hx.LIVE_TRAFFIC_ENABLED is False` and
  `nx.LIVE_NUCLEI is False` by identity.
* Tests prove `LiveNucleiRunner().launch()` raises the Nuclei
  `ExecutorError` and `RealSocketFactory().connect()` raises the HTTP
  `ExecutorError` (separate classes — asserted independently).
* The module imports only `ai.verification.deterministic` (verified
  by import-line scan in tests); the retired 5I materialization seam
  is never imported.
* The module never imports `database.db`, `mongoengine`, `pymongo`,
  or `XssFindings` on any import line (verified by scan); `sys.modules`
  contains no `database.db` or `playwright` after a full run.

## 7. Explicit confirmations (each verified, none merely claimed)

* No network traffic was performed: the pipeline has no transport
  call; the only executor function used is the pure
  `translate_bounded_request`; all stores/resolvers are in-memory
  fakes. Verified by the 11-test suite (no test performs I/O; the
  full run completes in ~0.03 s with no sockets).
* No DNS/network resolution was performed: `FakeDnsResolver` serves a
  fixed `8.8.8.8` mapping; unknown hosts raise `DNS_NXDOMAIN`
  without leaving the process. Verified by code inspection + tests.
* No subprocess was launched: no `subprocess` import or call exists
  in the new module; `nuclei -validate`/runner paths are never
  referenced. Verified by import scan + tests.
* No browser was launched: `playwright` is absent from `sys.modules`
  after a run; no browser executor is imported. Verified by test.
* No Nuclei execution was launched: `LIVE_NUCLEI is False`,
  `LiveNucleiRunner().launch` raises, and no runner is ever
  instantiated for execution in the module. Verified by tests.
* No Mongo/`database.db` import occurred: import-line scan +
  post-run `sys.modules` assertion. (`database.db` opens a Mongo
  connection at import time, so its absence is load-bearing.)
* No legacy `XssFindings` write occurred: the token appears on no
  import line; no Mongo adapter exists in this stage. Verified by test.
* No legacy World-A verification pipeline was used: module imports
  reference only `verification.deterministic`; legacy modules retain
  `LEGACY_NON_PRODUCTION = True` (asserted in tests). Note:
  `ai.verification.verifier` etc. may appear in `sys.modules`
  transitively via the parent `ai.verification` package `__init__`
  (which names them for offline unit tests) — that import-time
  presence is not execution, and no legacy entry point is called.

## 8. Determinism behavior

All derived identities are deterministic hashes of the input
(`hyp-`, `tp-` via the existing factory, `art-` via the existing
factory, `ex-` via `sha256("stage1-ex"|…)`). Independent runs are
nevertheless NOT byte-identical, for two architecture-mandated
reasons:

1. The 5B `authorization_id` embeds a random issuance nonce
   (`generate_issuance_nonce`), so each issuance is a distinct
   authorization by design (idempotency is on the idempotency key,
   not the authorization id).
2. `evidence_id` is a random handle (`generate_evidence_id`); handles
   are excluded from content identity by design but ARE included in
   `ClassificationResult`/`compute_result_hash`.

Consequence: `bindings_hash`/`observations_hash`/`content_hash` and
the classification outcome/reason are repeatable when issuance is
idempotent (same `InMemoryAuthorizationStore` passed to both runs —
the determinism test does exactly this and also asserts the evidence
handles differ while content matches). `authorization_id`,
`evidence_id`, and `result_hash` legitimately differ across
independent runs.

## 9. Test suites executed and exact results

* `python3 -m unittest ai.test_stage1_offline` — **11 tests, OK**.
* Regression (existing suites, unmodified code):
  `ai.test_deterministic_verifier ai.test_finding_pipeline
  ai.test_execution_authorization ai.test_scope_evaluator
  ai.test_evidence_store ai.test_evidence_core
  ai.test_legacy_severance_5k` — **590 tests, OK**.
* Regression: `ai.test_http_pinned_executor ai.test_nuclei_executor
  ai.test_artifact ai.test_test_plan_builder
  ai.test_test_plan_readiness ai.test_artifact_retrieval` —
  **410 tests, OK**.
* Regression (XSS/knowledge layer per repo guidance):
  `ai.test_xss_verification ai.test_knowledge_store
  ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter
  ai.test_xss_orchestrator ai.test_xss_pipeline` — **255 tests, OK**.

## 10. Known limitations / architectural blockers

* Happy-path outcome is `UNKNOWN` (5J refusal), not a finding: the
  `http_probe` class has no oracle derivation, so sealed HTTP
  reflection alone cannot reach `POTENTIAL`/`CONFIRMED` under the
  frozen rules. A `POTENTIAL`-ceiling or oracle-`CONFIRMED`
  demonstration requires the browser/oracle or stored-round path
  (future stage).
* `evidence_id`/`result_hash` non-repeatability across independent
  runs (see §8) — inherent to the handle design, not a defect.
* No Mongo adapters yet (5B authz store, ledger, audit/evidence
  backends, orphan sweep all in-memory) — B2 work, explicitly
  deferred.
* No production `AddressSource` (B1) and no sandbox/egress boundary
  (B3) — live execution stays blocked.
* `EndpointView` is a manual projection; no adapter reads live
  `database.db.Endpoints` rows yet (that import would open Mongo).

## 11. Files intentionally NOT modified

`ns/`, `crawl/`, `database/db.py`, `config.py`, `requirements.txt`,
`.env`, `README*`, `nuclei/watch_nuclei_all.py`,
`ai/verification/verifier.py`, `ai/verification/http_executor.py`,
`ai/verification/browser_executor.py`,
`ai/verification/composite_executor.py`,
`ai/verification/xss_pipeline.py`,
`ai/verification/deterministic/materialization.py` (retired,
hard-blocked), all live-gate constants, all systemd units. No
packages installed. No Git operations performed (read-only
`status`/`diff --check` only, and only where the task required
showing them).

## 12. Stage 1 acceptance criteria

| Criterion | Result |
|---|---|
| Offline chain Endpoint→…→5J dry-run implemented | PASS |
| Existing 5B–5J contracts reused, no duplicates | PASS |
| `InMemoryAuthorizationStore`, issuance/CAS preserved, no Mongo | PASS |
| Deterministic/fake resolver, no DNS/network | PASS |
| `ScopeEvaluator` unweakened; DENIED/INCONCLUSIVE preserved | PASS (tested) |
| Spec-only execution; live runners blocked; gates unmodified | PASS (tested) |
| Existing evidence sealing/hashing contracts; no second format | PASS |
| Existing `verify_handoff()`; no manufactured CONFIRMED; no NOT_VULNERABLE | PASS (UNKNOWN + 5J refusal) |
| 5J dry-run, in-memory only; no `XssFindings` write; no Mongo adapter | PASS (tested) |
| Determinism where contracts require it | PASS (shared-store test) |
| Focused tests for all 8 required behaviors | PASS (11 tests) |
| Forbidden paths untouched | PASS |

## 13. Recommended next stage

Stage 2 — B1+B2 production reads (still no live traffic): production
`AddressSource` selection/review, Mongo adapters for the
authorization store, execution ledger, audit/evidence backends, and
orphan sweep behind the existing seams; scope policy compiled from
live `Programs` rows with `scope_lists_hash` drift detection;
persistence-backed dry-runs proving replay/dedupe. Keep `LIVE_*`
closed until B1+B2 land; B3 sandbox/egress review and any single-class
(`http_probe`-only) live pilot belong to Stage 3.

## 14. Final status

**PASS WITH LIMITATIONS** — the offline chain works end-to-end with
all safety properties verified by tests; the happy path terminates in
an honest `UNKNOWN` + 5J refusal (no finding produced), and
byte-identity across independent runs is architecturally
unachievable for handle-bound fields (see §8/§10).
