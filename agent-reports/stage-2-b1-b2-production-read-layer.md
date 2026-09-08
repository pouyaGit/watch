# Stage 2 — B1 + B2 Production Read/Persistence Layer (Still Fully Dry-Run)

## 1. Stage objective

Replace selected Stage 1 in-memory-only seams with
production-oriented adapters/read paths that can safely consume the
existing Watch/Mongo data model — while keeping ALL live network
execution disabled. The goal is persistence and reviewable reads,
NOT live traffic: no target HTTP, no DNS, no sockets, no browser,
no Nuclei, no subprocess in any Stage 2 path.

## 2. Architectural context

Stage 1 (`ai/stage1_offline_pipeline.py`, still byte-stable except a
test-hygiene fix, §20) proved the authorized chain end-to-end with
fakes. Stage 2 keeps every 5B–5J contract authoritative and reuses
all frozen types; it adds:

* B1: an explicitly reviewed, already-known-address source
  implementing the EXISTING `DnsResolver` protocol (no parallel
  resolver architecture). The pre-existing `ProductionAddressSource`
  is a live-DNS stub requiring an injected socket exchange and is
  deliberately NOT used here.
* B2: Mongo-shaped persistence behind the EXISTING store seams
  (`AuthorizationStore` protocol, ledger surface, audit sink,
  `BlobStore`/`EvidenceIndex` protocols) via an injected narrow
  driver subset. A `FakeMongoCollection` (unique indexes,
  CAS-replace, failure injection) stands in for the server, so no
  test needs credentials, a server, or production data.
* Production Watch-row reads (`Programs` scopes/ooscopes,
  `Http`/`LiveSubdomains` ips) through duck-typed readers —
  `database.db` (connects at import) is never imported.

## 3. Exact implementation flow (`run_stage2_dryrun`)

```
EndpointView
 -> TestPlan + validated http_request_spec artifact (frozen factories)
 -> DictProgramReader row -> compile_policy -> scope_lists_hash
 -> issue_authorization() on MongoAuthorizationStore [ISSUED]
 -> address_facts_for() -> AddressReview -> InventoryAddressSource (B1)
 -> inventory_records_for() -> TargetResolver.resolve() [5C, LIVE ok]
 -> policy_for_program() [live re-read] -> ScopeEvaluator.evaluate() [5D]
 -> translate_bounded_request() SPEC ONLY [5E translator]
 -> ledger.put_new -> consume_authorization -> ledger.mark_started
 -> audit append AUTHORIZATION + EXECUTION_STARTED [mongo sink]
 -> EvidenceBuilder synthetic HttpObservation -> seal()
 -> EvidenceStore.persist_sealed() [mongo blob+index] -> ledger.mark_sealed
 -> audit append EVIDENCE_SEALED
 -> StoreVerifiedRead -> verify_handoff() [5I] -> materialize() [5J dry-run]
 -> run_sweep() over the same mongo-backed seams [report mode]
```

Ordering mirrors executor discipline: resolution precedes
consume (5C requires LIVE permission; provenance accepts CONSUMED).

## 4. B1 implementation (`ai/resolver/inventory_addresses.py`)

`AddressReview` (frozen: program, canonical host, address list,
`source` e.g. `watch-inventory:Http.ips`, reviewer, reviewed_at) +
`InventoryAddressSource` (`DnsResolver` protocol, one instance per
program). Rules, all test-enforced: closed world per instance
(unknown host → `DNS_NXDOMAIN`, no fallback); conflicting reviews
for one slot poison it (`DNS_RESOLUTION_FAILED`, never first-wins);
every served set passes through the FROZEN `validate_answers`
(ceiling, whole-set safety, deterministic order — never
reimplemented); optional `max_age_seconds` + `now_iso` expiry
(stale → fail closed); empty review lists rejected at construction
(absence of facts must be absence of a review). No DNS, sockets,
subprocess, database, or LLM code exists in the module.

## 5. B2 authorization persistence (`ai/persistence/mongo_authz.py`)

`MongoAuthorizationStore` over the driver seam. Document:
`{_id: authz_id (unique), idempotency_key (unique), record_version,
lifecycle, document: <IssuedExecutionAuthorization json>}`. CAS /
idempotency / nonce / expiry / immutability semantics identical to
`InMemoryAuthorizationStore`; corrupt rows re-validate to absent
(never authority); driver outages propagate (fail closed); error
details static and secret-free. Single core-contract extension
required (see §14): `AuthorizationStore` is now
`@runtime_checkable` and `ai/authorizer/service.py` gates on the
protocol instead of the concrete class — dicts/JSON still fail the
gate; all existing service tests pass unchanged.

## 6. Execution ledger persistence (`ai/persistence/mongo_ledger.py`)

`MongoExecutionLedger` implements the FULL in-memory surface
(`put_new`/`get`/`get_by_idempotency_key`/`compare_and_swap` +
`mark_started`/`mark_sealed`/`mark_incomplete`/`mark_unknown`) with
identical rules. Documents keyed by execution id with unique
`(authorization_id|stage)` slot and idempotency key; slot bound →
`ReplayExecutionError`, key bound elsewhere →
`DuplicateExecutionError`, live-row CAS loss →
`InProgressExecutionError`. No schema duplication (`ExecutionRecord`
is the only row type). No transport code.

## 7. Audit persistence (`ai/persistence/mongo_audit.py`)

`MongoAuditSink`: insert-only `append(AuditRecord)` keyed
`<execution_id>:<seq>` (unique); duplicates fail closed with
`AuditPersistenceError` (never merged); `records_for()` ordered
read. `AuditRecord`'s own validators already reject secret-shaped
values; evidence bodies have no field here (hashes + codes only).

## 8. Evidence persistence (`ai/persistence/mongo_evidence.py`)

`MongoBlobStore` (CAS put/get/exists/verify/quarantine/list,
same-key-differing-bytes refused) and `MongoEvidenceIndex`
(insert/CAS lookups/`mark_indexed`/quarantine/tombstone with the
exact in-memory rules). One envelope, one hash discipline
(`canonical_envelope_bytes`; `verify_record` before/after every
write); blob/index separation preserved; no delete API; sealing
untouched; unsealed records cannot enter (callers persist sealed
terminals only; adapters validate row shape).

## 9. Orphan sweep integration

No sweep rewrite: the existing `discover_candidates`/`run_sweep`
are fully seam-based, so Stage 2 wires them over the mongo-backed
blob+index (`run_sweep(store=evidence_store, ...)` in the dry-run,
report mode). Proven by test: blob-bytes-without-index yields an
`INDEX_MISSING_SEALED` candidate and `run_sweep` re-indexes under
original keys with zero deletions/quarantines of healthy data.
Healthy dry-runs report zero actionable candidates (grace
deferral only).

## 10. Production scope read path (`ai/persistence/watch_reads.py`)

`WatchProgramReader` protocol + `DictProgramReader` (tests) +
`MongoProgramReader` (`find_one`-shaped collection,
`{"program_name"}` exact match on the model's unique index);
`WatchAssetReader` + `DictAssetReader` / `MongoAssetReader`
(`Http` + `LiveSubdomains` shapes, exact `(program, subdomain)`
match). `policy_for_program()` compiles the LIVE row through the
EXISTING `compile_policy` (matching, ooscopes, hash semantics
unchanged; `None` when the program is gone → 5D `PROGRAM_NOT_FOUND`
deny). `address_facts_for()` merges observed `ips` (sorted,
deduplicated, never judged — safety stays in `validate_answers`).
`inventory_records_for()` builds the frozen 5C records. Row
validation fails closed (`WatchReadError`); `compile_policy`
`PolicyError` propagates unchanged.

## 11. Scope drift behavior

Issuance binds `scope_lists_hash_for(live scopes, ooscopes)`; the
dry-run accepts `post_issuance_scopes` to replace scope lists for
all post-issuance reads. Drift then fails closed through EXISTING
contracts with no new code: the 5C resolver returns terminal
`SCOPE_DRIFT` (proven by test → `RESOLUTION_FAILED`), and any drift
reaching 5D is denied by the fresh-policy re-read. Unchanged hashes
evaluate `ALLOWED` (proven by test).

## 12. Replay/dedupe behavior (all proven by tests)

* Same request + idempotency key → same authorization record
  (service-level, over the mongo store); double-consume →
  `AUTHZ_ALREADY_CONSUMED`.
* Duplicate ledger slot → `ReplayExecutionError`; key bound
  elsewhere → `DuplicateExecutionError` (dedupe-on-read preserved).
* Duplicate sealed-evidence persist → deduped no-op success with
  identical content hash.
* Audit duplicate `(execution_id, seq)` → `AuditPersistenceError`
  (never merged); `records_for` returns seq order.
* Missing addresses → `RESOLUTION_FAILED`, no DNS/network fallback
  (closed-world `DNS_NXDOMAIN` at the source).
* Conflicting address facts → poisoned slot →
  `DNS_RESOLUTION_FAILED`.
* Driver outage at any seam → `MongoUnavailableError` → closed
  `Stage2Error` (issuance/ledger/audit/evidence paths all covered);
  nothing is cached, retried, or synthesized.

## 13. Files created

* `ai/resolver/inventory_addresses.py` — B1 reviewed-facts source.
* `ai/persistence/__init__.py` — package rules (no live I/O, no
  `database.db`, no secrets in errors).
* `ai/persistence/driver.py` — `MongoCollection` protocol (pymongo
  surface subset), closed errors, `FakeMongoCollection` (unique
  indexes, CAS replace, failure injection).
* `ai/persistence/mongo_authz.py` — B2 issuance store.
* `ai/persistence/mongo_ledger.py` — B2 execution ledger.
* `ai/persistence/mongo_audit.py` — B2 audit sink.
* `ai/persistence/mongo_evidence.py` — B2 blob + index stores.
* `ai/persistence/watch_reads.py` — Watch row readers + builders.
* `ai/stage2_dryrun.py` — persistence-backed dry-run
  (`run_stage2_dryrun`, `default_stage2_stores`, `Stage2Config`,
  `Stage2Error`, `Stage2Result/Stores`).
* `ai/test_stage2_production_reads.py` — 39 tests.

## 14. Files modified (3, minimal and documented)

* `ai/authorizer/store.py` — `AuthorizationStore` protocol is now
  `@runtime_checkable` (+docstring). Reason: the 5B service layer
  must gate on the contract, not one backend, or no B2 adapter can
  ever be admitted without duplicating issuance logic.
* `ai/authorizer/service.py` — 6 type gates switched from the
  concrete `InMemoryAuthorizationStore` to the `AuthorizationStore`
  protocol (`issue`/`get`/`consume`/`revoke`/submit-lease/read-lease
  paths). No semantic change: non-store inputs still raise
  `TypeError`; all existing authorization tests pass unchanged.
* `ai/test_stage1_offline.py` — order-independence fix only (see
  §20): `sys.modules` absence assertions replaced by
  before/after-run snapshot diffs. No Stage 1 logic touched.

## 15. Existing contracts reused

5B service + `IssuedExecutionAuthorization`/`AuthorizationRequest`;
5C `TargetResolver`/`ResolutionRequest`/`InMemoryInventoryRepository`/
`ProgramRecord`/`AssetRecord`/`scope_lists_hash_for`/`validate_answers`;
5D `ScopeEvaluator`/`compile_policy`/`InMemoryPolicyStore`; 5E
`translate_bounded_request`; 5H `EvidenceBuilder`/`EvidenceStore`/
`canonical_envelope_bytes`/`verify_record`/`AuditRecord`/
`ExecutionRecord`; 5I `verify_handoff`/`VerifierInput`/pinned
versions; 5J `materialize`/memory stores; sweep
(`discover_candidates`/`run_sweep`)/orphan (`classify_orphan`)/
`observe_url`/`observe_body`; TestPlan/artifact factories. No
duplicate model was created for authorization, scope, resolution,
evidence, verification, finding, or execution authority.

## 16. Safety guarantees (each test-verified, none merely claimed)

`LIVE_TRAFFIC_ENABLED is False`, `LIVE_NUCLEI is False` (identity
asserts on every dry-run); live runners refuse when probed (never
launched); module import-line scans across all 9 new modules prove
no `database.db`/`socket`/`subprocess`/`playwright`/World-A/retired-seam/`XssFindings`
references; snapshot diffs prove a dry-run introduces no
`database.db`/`playwright`/`pymongo`/`mongoengine` modules; scope
DENIED and double-consume paths prove no scope/authorization
bypass; excluded-host and unknown-program paths fail closed;
finding persistence stays in-memory (finding Mongo adapter remains
B2-blocked by design — no finding bytes reach any B2 store).

## 17. Tests added (`ai/test_stage2_production_reads.py`, 39 tests)

Service-protocol (5), authz-adapter CAS/outage (2), ledger parity
(3), audit (2), evidence adapters (3), B1 source (7: serve,
unknown-host, conflict, unsafe-set, stale, empty-review,
cross-program), watch reads (5: live policy, missing program,
malformed row, mongo readers over fake driver, no-db-import),
dry-run (7: happy, drift, hash-unchanged, missing program,
missing addresses, excluded host, outage), replay/dedupe (2:
evidence dedupe, orphan reindex), safety (3: gates, import/module
hygiene, no-bypass).

## 18. Exact test commands

```
python3 -m unittest ai.test_stage2_production_reads
python3 -m unittest ai.test_stage1_offline
python3 -m unittest ai.test_execution_authorization ai.test_scope_evaluator \
  ai.test_target_resolver ai.test_evidence_store ai.test_evidence_core \
  ai.test_deterministic_verifier ai.test_finding_pipeline \
  ai.test_legacy_severance_5k ai.test_b1_dial_policy
python3 -m unittest ai.test_http_pinned_executor ai.test_nuclei_executor \
  ai.test_artifact ai.test_artifact_store ai.test_artifact_retrieval \
  ai.test_test_plan_builder ai.test_test_plan_readiness \
  ai.test_hypothesis_testplan ai.test_hypothesis_engine \
  ai.test_xss_verification ai.test_knowledge_store ai.test_xss_researcher \
  ai.test_xss_llm_researcher ai.test_openrouter ai.test_xss_orchestrator \
  ai.test_xss_pipeline ai.test_composite_executor ai.test_nuclei_ready \
  ai.test_target_matcher ai.test_target_intelligence
```

## 19. Exact test results

* Stage 2 new: **39/39 OK**.
* Stage 1 regression: **11/11 OK** (unchanged behavior).
* Batch 1 (stage1+stage2+authz+scope+resolver+evidence+verifier+
  finding+severance+b1): **818/818 OK**.
* Batch 2 (executors+artifacts+plans+XSS/knowledge/LLM/targets):
  **976/976 OK**.
* Combined verified: **1794 passing, 0 failures**.
* `git diff --check` over all 13 stage files: **clean**.

## 20. Limitations/blockers

* Happy path still terminates in honest `UNKNOWN` + 5J refusal (no
  oracle derivation in `http_probe`); unchanged from Stage 1.
* `evidence_id`/5B-nonce handle randomness (§8 of the Stage 1
  report) still applies; determinism asserted on content hashes.
* No real-Mongo integration run exists (fake driver only); the
  driver subset was chosen to match the real collection surface
  1:1, but live-server behavior (index enforcement, write concern)
  is unproven — first production wiring must create the declared
  unique indexes (`AUTHZ/LEDGER/AUDIT/BLOB/INDEX_UNIQUE_INDEXES`).
* Finding persistence intentionally absent (5J dry-run only).
* One Stage 1 test assertion was genuinely incorrect and fixed:
  global `sys.modules` absence checks for `playwright` are
  order-dependent (other suites load it at collection); replaced by
  before/after-run snapshot diffs in both suites.
* Pre-existing repo-wide `git diff --check` noise
  (`ai/correlator/version.py` whitespace) is untouched and unrelated.

## 21. Explicitly untouched files

`ns/`, `crawl/`, `database/db.py`, `config.py`, `requirements.txt`
(no installs), `.env`, `README*`, systemd units, `run-pipeline.sh`,
`run-heavy-guarded.sh`, `nuclei/watch_nuclei_all.py`, all legacy
verification files, `ai/verification/deterministic/
materialization.py`, both live-gate constants, all production
secrets. No Git operations performed (read-only status/diff only).

## 22. Security review

Attack surface added: zero live paths. New code persists bytes and
reviewed facts only, behind typed gates that reject dicts/JSON.
Threats considered: (a) conflicting inventory facts → poisoned slot,
fail closed (tested); (b) stale facts → expiry gate (tested);
(c) corrupt authz/ledger/index rows → re-validation to absent or
CAS conflict, never authority (tested for authz); (d) driver outage
→ typed unavailable error, no caching/retry/synthesis (tested per
seam); (e) secret leakage → closed static error details + existing
`AuditRecord` secret-screening validators (no connection strings or
credentials exist in the package); (f) scope drift → existing
`SCOPE_DRIFT` terminal/deny (tested); (g) cross-program confusion →
exact-pair inventory gate + per-program sources (tested).
Residual risk: fake-driver/real-server semantic divergence on
concurrent CAS races — mitigated by declaring the exact unique
indexes production must create and by mapping (not masking) race
losses to the domain conflict errors.

## 23. Stage acceptance matrix

| Criterion | Result |
|---|---|
| B1 explicit review tied to program/host/authz/scope, no DNS/sockets | PASS |
| Missing/stale/ambiguous/conflicting facts fail closed, no silent choice | PASS (tested) |
| No new scope semantics | PASS (existing `compile_policy`/evaluator) |
| Mongo authz adapter: CAS/idempotency/nonce/expiry/immutability preserved | PASS |
| No schema change, no duplicate model, secret-free errors | PASS |
| Testable without a server (driver seam + fake) | PASS |
| Ledger append/idempotency/identity/ordering preserved | PASS |
| Audit append-only, schema preserved, no secret/body logging | PASS |
| Evidence envelope/hashing/sealing unchanged; blob/index split kept | PASS |
| Orphan sweep wired, report mode, zero deletions | PASS |
| Scope read from Watch rows; drift fails closed | PASS |
| Persistence-backed dry-run, no live I/O of any kind | PASS |
| All 10 replay/dedupe items proven | PASS |
| Full safety battery | PASS |
| Stage 1 suite unchanged and green | PASS |
| Forbidden paths untouched | PASS |

## 24. Recommended Stage 3

B3 sandbox/egress review (isolated network namespace, egress
allowlist, resource enforcement inside the boundary) followed by a
single-class live pilot (`http_probe` via 5E against allowlisted
programs with per-hop fresh scope evaluation), real-Mongo
integration proving index enforcement under concurrency, and
production `AddressSource` selection/review sign-off. Nuclei and
browser execution stay blocked until their own reviews land.

## 25. Final status

**PASS** — all Stage 2 objectives implemented and verified
(1794 tests green, stage files diff-clean); known limits are
explicit (§20) and no live path was opened.
