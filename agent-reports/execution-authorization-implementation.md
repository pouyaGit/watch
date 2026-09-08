# Phase 5B — ExecutionAuthorization Implementation Report

## 1. Verdict

**IMPLEMENTED AND VERIFIED.** Phase 5B is complete within its strict scope:
the ExecutionAuthorization contract, server-side authorization-by-reference
boundary, authoritative issuance abstraction with CAS single-consume, lifecycle,
canonical artifact binding, exactly-one semantics, HTTP method contract, XSS
derivation + stored-lease contracts, target/scope/fixture/CDN bindings, issuer
context separation, sanitized error model, and 66 focused deterministic tests —
all passing, with 564 existing regression tests still green and no unrelated
code touched. No executor, resolver, scope evaluator, evidence, verifier, or
live-execution path was created or enabled.

## 2. Files created

| File | Lines | Purpose |
|---|---|---|
| `ai/schemas/execution_authorization.py` | ~700 | Closed-vocab contract: bindings, request/record/context models, pure helpers, `AuthzError` |
| `ai/authorizer/__init__.py` | ~45 | Typed boundary exports only |
| `ai/authorizer/store.py` | ~185 | `AuthorizationStore` protocol + deterministic `InMemoryAuthorizationStore` (CAS) |
| `ai/authorizer/service.py` | ~430 | Issuance, typed retrieval, consume/revoke, binding validators, exactly-one resolution, stage leases |
| `ai/test_execution_authorization.py` | ~700 | 66 focused offline deterministic tests |

## 3. Files modified

**None.** Zero existing repository files were edited, renamed, moved, or
deleted. In particular: `ai/schemas/test_plan.py` (still permits DELETE —
rejected at 5B intake instead), `ai/schemas/artifact.py`,
`ai/knowledge/artifact_store.py`, all authorizer-adjacent researcher/
verification modules, `database/db.py`, scheduler/crawler code — all
untouched. The deferred DELETE schema convergence is documented in §25.

## 4. Exact implementation scope

Implemented (5B.1–5B.17): authorization contract with closed enums;
authorization-by-reference authenticity (Option B, signatures deferred);
issuance-store abstraction (protocol + in-memory deterministic adapter; Mongo
adapter deferred to 5H-core); monotonic lifecycle; CAS single-consume with
`max_executions=1`; canonical `ArtifactReference`/`artifact_id_for` binding
with legacy `artifact_ref` structurally unrepresentable; exactly-one artifact
resolution with `NOT_READY`/`ARTIFACT_AMBIGUOUS`/`ARTIFACT_BINDING_MISMATCH`
terminals; method allowlist with `METHOD_NOT_ALLOWED`/`TRANSLATION_REJECTED`
and no coercion; XSS derivation contract (Model 1) with P≠O explicitness;
stored-XSS one-round/two-lease state machine; effective-port target binding;
scope-policy-hash binding (no evaluation); fixture/CDN pins; issuer
request/context separation; 15-code sanitized error model. Out of scope and
not touched: 5C–5J runtimes, executors, verifiers, evidence, DNS, egress,
scheduler, findings, Mongo production data.

## 5. Authorization authenticity implementation

Normative Option B as specified. `issue_authorization(store, request)` is the
only minting path (issuer side); `get_issued_authorization(store, opaque_id)`
is the only loading path (executor side) and returns only genuine
`IssuedExecutionAuthorization` instances re-validated through the contract.
No `authorize_from_dict/json/blob` constructor exists anywhere — verified by
construction (no such symbol) and by tests 02–05 (dict, JSON round-trip,
LLM-shaped object, and unknown-but-well-formed id all rejected with
`TypeError`/`AUTHZ_NOT_FOUND`). Deterministic `authorization_id` (with 128-bit
`issuance_nonce`) and `idempotency_key` are dedupe keys only. Signatures were
not implemented per the architecture's deferral.

## 6. Issuance store abstraction

`AuthorizationStore` protocol (`put_new`, `get`, `get_by_idempotency_key`,
`compare_and_swap`) is the trust-root contract for the future production
adapter. `InMemoryAuthorizationStore` implements it deterministically:
typed-input enforcement (raw dicts → `TypeError`), duplicate id/key collision
→ `DuplicateIdempotencyKeyError`, CAS guarded on `record_version` with exactly
+1 increment enforcement and identity-rebind refusal, deep-copy isolation on
every read/write. It models single-process CAS faithfully and is documented
(in docstring and §25) as NOT a cross-process store — cross-process uniqueness
requires the production adapter with a real unique index before live execution.

## 7. Lifecycle

`ISSUED → CONSUMED / REVOKED / EXPIRED`, monotonic, no resurrection.
`_is_live()` centralizes liveness: non-ISSUED states map to
`AUTHZ_ALREADY_CONSUMED`/`AUTHZ_REVOKED`/`AUTHZ_EXPIRED`/`AUTHZ_NOT_LIVE`, and
wall-clock expiry (`expires_at <= now`) is enforced on every consume/lease
operation even if the sweeper has not yet marked EXPIRED. Expiry is mandatory
at issuance (`expires_at > issued_at`, else `INVALID_AUTHORIZATION_REQUEST`).
`revoke_authorization` is issuer-side CAS `ISSUED → REVOKED`; non-ISSUED
revocation fails closed. Tested by 07–12.

## 8. CAS/consume semantics

`consume_authorization` performs read → liveness → CAS(`ISSUED→CONSUMED`,
version+1). The loser of a race surfaces deterministically: version conflict
maps to `AUTHZ_ALREADY_CONSUMED` ("concurrent consume lost; no retry") —
never a second execution permission. `issue_authorization` is idempotent on
the idempotency key (returns the existing record, including the
race-lost path via `DuplicateIdempotencyKeyError` → winner lookup). Tested by
12–17, including a direct stale-version CAS conflict test (15).

## 9. Artifact identity

Canonical identity is `artifact_id_for()` over
`(type, test_plan_id, content_hash, schema_version)`, enforced inside
`ArtifactBinding._identity_consistency`. A legacy content-keyed id
(`"art-" + hash[:16]`) fails validation structurally (test 19 proves the two
derivations disagree and the legacy form raises `ValidationError`), so
`TestPlan.artifact_ref` identities are unrepresentable in 5B bindings without
any silent reconciliation. Authorization binds artifact triple + schema
version + (where present) hypothesis/match/snapshot, each checked for exact
equality at resolution (tests 20–27).

## 10. Exactly-one artifact semantics

`resolve_authorized_artifact(record, candidates)` implements Option A: zero
candidates → `NOT_READY`; more than one → `ARTIFACT_AMBIGUOUS` (even when one
matches — test 29 uses two stored records where one is the authorized bytes);
single candidate compared field-by-field to the bound triple plus conditional
provenance bindings → `ARTIFACT_BINDING_MISMATCH` on any divergence. No
first/first-by-id/any-VALID/any-of-type path exists. Non-`ArtifactReference`
candidates and non-list inputs raise `TypeError`.

## 11. HTTP method contract

`ALLOWED_METHODS = {GET, POST, PUT, PATCH, HEAD, OPTIONS}`;
`FORBIDDEN_METHODS = {DELETE, CONNECT, TRACE}` documented. `check_method_pair`
returns OK only for equal allowed pairs; forbidden/unknown either side →
`METHOD_NOT_ALLOWED`; allowed-but-unequal → `TRANSLATION_REJECTED`. Issuance
refuses mismatched pairs, and `AuthorizationRequest` schema itself forbids
DELETE (test 40), so the legacy `TestPlan.DELETE` permissiveness is contained
at 5B intake without modifying `test_plan.py`. All six allowed methods and all
three forbidden methods are individually tested (30–38); test 39 pins the
mismatch terminal at both layers.

## 12. Target binding

`TargetBinding(program_name, host, scheme, effective_port: int, path_scope,
snapshot_ref?, scope_policy_version, scope_lists_hash)` with
`effective_port_for()` defaulting (http→80, https→443; rejects bool/out-of-
range/unknown-scheme). `validate_target_binding` requires exact equality on
program/host/scheme/port/scope-hash plus path-scope agreement — cross-program
same-host confusion is structurally impossible since `(program_name, host)`
are both compared (tests 41–46 each mutate exactly one axis).

## 13. Scope binding

Authorization carries `scope_policy_version` + `scope_lists_hash` as data and
re-checks the hash at target validation, but performs zero scope evaluation:
no import of `ScopePolicy`, no DNS, no URL logic anywhere in 5B (verified by
AST sweep, §20). The `ProductReadiness ≠ URL Scope Authority` distinction is
preserved by keeping evaluation entirely in future 5D.

## 14. XSS derivation contract

`XSSDerivationContract` binds source P (`source_artifact_id`,
`source_content_hash`) plus `planner_id` (`oracle-planner` literal),
`planner_version`, `oracle_version`, `allowed_context` (the four planner
contexts from `oracle.py`), `allowed_skeleton_family`, `execution_phase`,
`seed_rule` and `run_salt_authority` literals. Issuance refuses contracts
whose source diverges from the bound artifact. `validate_derivation_binding`
requires exact contract equality plus source↔artifact coherence. P≠O is
explicit: the contract never claims the derived payload equals artifact bytes;
test 47 pins the distinction and test 57 pins deterministic dual-hash view
construction. Oracle payload generation, E1/E2/E3, and planner code are
untouched. Mismatch axes tested individually (48–52).

## 15. Stored XSS lease contract

One round authorization carries `StoredStageLeases(round_id, submit_lease,
read_lease)` starting `PENDING/PENDING`. Pure `transition_submit/read`
constructors enforce the legal graph (`PENDING → CONSUMED/FAILED/SKIPPED`,
terminals absorbing). `consume_submit_lease` / `consume_read_lease` are
independent CAS-gated service operations, each re-checking authorization
liveness first. Tests pin the critical invariant both directions: READ
consumable without prior SUBMIT (own gate, test 54 — second READ refused),
and SUBMIT consumption leaving READ `PENDING` (test 55). No resolver/scope
runtime was built; the leases expose the typed gates 5C/5D will satisfy.

## 16. Fixture binding

`FixtureBinding(fixture_set_id ^fix-…, fixture_version, non-empty
fixture_hashes, family_binding)` — hashes only; raw bytes are
unrepresentable (test 59: non-hash fixture value → `ValidationError`; dict
shaped like a binding → `TypeError`). `validate_fixture_binding` requires
exact equality with the pinned authorization copy. No fixture registry
runtime, no LLM/research/plan/artifact/target derivation path.

## 17. CDN binding

`CdnMappingBinding(mapping_version, mapping_hash)` carried and pinned;
inequality detectable (test 60). No redirect behavior implemented; sibling-
host inference remains impossible (no eTLD+1 logic anywhere in 5B).

## 18. Issuer context

`AuthorizationRequest` (mintable only into issuance, never consumable:
`consume`/`get` reject it by type — test 61) is separated from
`IssuedExecutionAuthorization` (consumable only via typed loading).
`IssuerContext` carries `is_authority: Literal[False] = False` structurally
plus the R-B19 informational fields (plan/hypothesis/artifact/target/scope/
readiness/validation/fixture/class/resource/TTL/replay notes), and is refused
by both issuance and retrieval (test 62). Non-issuer principals
(`llm-researcher`, `scheduler`, `collector`, empty) are rejected at schema
(test 63) and non-model inputs at service (test 64).

## 19. Error model

`AuthzError(code, detail)` with the 15 architecture codes; unknown codes
rejected at construction; details bounded (300 chars) and screened against
secret markers (`mongodb://`, `password`, `api_key`, `secret`, `bearer `,
`-----begin`) — constructor raises rather than leak (test 65). Service layers
never propagate raw exceptions: store races map to `AUTHZ_ALREADY_CONSUMED`/
`LEASE_NOT_LIVE`, malformed instants to `INVALID_AUTHORIZATION_REQUEST`
(test 66 pins message-size/brevity hygiene).

## 20. Security invariants

Verified by inspection + tests (mapping): 1. READY→AUTHORIZED impossible (no
readiness input exists in the authorizer; issuance requires explicit request).
2–5. TestPlan/artifact-VALID/LLM/research cannot become authority (typed
inputs only; tests 02–05, 61–64). 6. JSON cannot become authority (no
deserialization constructor; tests 02–03). 7. Deterministic id is not proof
(dedupe-only; unknown id → NOT_FOUND, test 05). 8. Exactly one artifact
(§10). 9. Legacy ref unrepresentable (§9). 10. DELETE cannot execute (§11).
11. P/O distinct (§14). 12. SUBMIT ⇏ READ (§15). 13. Revoked/expired/consumed
refused (§7). 14. Cross-program confusion impossible (§12). 15–16. No scope/
DNS in 5B (AST sweep clean, §24). 17–18. No execution/classification (no
transport/verdict symbols; sweep clean). 19. No verifier invoked (no verifier
imports). 20. No network (no socket/request imports; all tests offline).

## 21. Test inventory

66 tests in `ai/test_execution_authorization.py`, numbered to the task spec:
authenticity 01–09, lifecycle 10–12, concurrency/idempotency 13–17, artifact
18–29, method 30–40, target 41–46, XSS/leases 47–57, fixtures/CDN 58–60,
issuer 61–64, hygiene 65–66. One file, stdlib `unittest`, no fixtures files,
no network, deterministic (fixed timestamps; only randomness is the issuance
nonce, asserted by format/uniqueness, never by value).

## 22. Test results

`python3 -m unittest ai.test_execution_authorization`: **66 tests, OK
(0.034 s)**. Per-class: Authenticity 9/9, Lifecycle 3/3, Concurrency 5/5,
Artifact 12/12, Method 11/11, Target 6/6, XSS 11/11, Fixture/CDN 3/3, Issuer
4/4, Hygiene 2/2.

## 23. Regression results

- `ai.test_artifact ai.test_artifact_store ai.test_artifact_retrieval
  ai.test_test_plan_readiness ai.test_hypothesis_testplan
  ai.test_hypothesis_engine`: **301 tests, OK**.
- `ai.test_xss_oracle ai.test_xss_verification ai.test_composite_executor
  ai.test_http_executor`: **263 tests, OK**.
- `compileall` on all new files: OK.
- Total: 66 new + 564 existing green, 0 failures. No unrelated failures
  encountered, so no unrelated code was touched.

## 24. Any failures

None. No new-test failures, no regression failures, no compile failures.
Two implementation-time defects were found and fixed before testing: a
leftover placeholder stub with invalid syntax in `service.py` (removed), and
the `issuance_nonce` (32-hex) sharing the 64-hex key validator (split into
dedicated nonce/key validators). Both were caught by import/smoke checks, not
by test failures.

## 25. Deferred work

1. Production Mongo issuance adapter implementing `AuthorizationStore`
   (unique indexes on `authorization_id` + `idempotency_key`, CAS) — required
   before live execution; in-memory adapter must never be mistaken for it.
2. `TestPlan.HttpRequestSpec` DELETE removal (schema convergence) — contained
   at 5B intake; migration is a later schema task.
3. `ScopePolicy` → `ProductReadinessPolicy` rename — out of 5B scope.
4. Fixture registry runtime, CDN registry runtime, TargetResolver (5C), scope
   evaluator + canonicalizer (5D), evidence/idempotency substrate (5H-core),
   and all 5E–5J work — explicitly not started.
5. Open architecture questions (§38 of the spec: egress topology, unique-index
   backend) — unchanged; safe defaults already recorded there.

## 26. Confirmation that no executor was implemented

No HTTP/browser/Nuclei executor, sandbox, network handling, resolver, scope
logic, canonicalizer runtime, DNS/egress code, evidence store/runtime,
verifier runtime, XSS runtime, scheduler, queue, pipeline, or finding was
implemented or modified. The authorizer performs zero transport and owns zero
verdict vocabulary. 5B implementation ≠ execution enablement: no new live
execution path exists.

## 27. Confirmation that no live target was touched

No target was resolved, probed, or executed against. No HTTP request was sent
(offline test suite; no socket/request imports in new code). No Nuclei
invocation, no browser launch, no verifier invocation, no finding creation.
All validation is local and deterministic.

## 28. Confirmation that no Git commands were run

No Git command of any kind was run — no status/diff/add/commit/log/branch/
switch/checkout/restore/reset/stash/merge/fetch/pull/push, nor any other Git
operation. The user handles push manually.
