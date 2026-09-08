# Phase 5H-core — Production Mongo Authorization Store

**Date:** 2026-09-08
**Scope:** Production MongoDB-backed `AuthorizationStore` for Controlled
Live Validation ONLY. No live egress enabled, no Nuclei executed, no live
authorization issued, no unrelated pipeline code touched, no commits,
no pushes, no pulls, no resets — all pre-existing working-tree changes
preserved as found.

## 1. Architecture reviewed

- `ai/authorizer/store.py` — `AuthorizationStore` runtime-checkable
  protocol (exactly 4 methods: `put_new`, `get`,
  `get_by_idempotency_key`, `compare_and_swap`); `InMemoryAuthorizationStore`
  (single-process CAS fake, explicitly NOT cross-process safe);
  error vocabulary (`AuthorizationStoreError`, `DuplicateIdempotencyKeyError`,
  `RecordNotFoundError`, `VersionConflictError`).
- `ai/authorizer/service.py` — typed issuance boundary:
  `issue_authorization` (idempotent on idempotency key, race returns winner),
  `get_issued_authorization` (re-validates through the schema),
  `consume_authorization` (liveness re-read + single-consume CAS, race maps
  to `AUTHZ_ALREADY_CONSUMED`), `revoke_authorization`, lease consumes.
  Liveness rule (`_is_live`): CONSUMED/REVOKED/EXPIRED/non-ISSUED/past-expiry
  all refuse.
- `ai/schemas/execution_authorization.py` — `IssuedExecutionAuthorization`
  (frozen record; `max_executions = 1`; lifecycle ISSUED/CONSUMED/REVOKED/
  EXPIRED; legal transitions map), `TargetBinding`, `ArtifactBinding`
  (plan-bound canonical identity), request/issuer separation. NOTE: the
  issuance record carries NO `execution_id`/`resolution_id` — those
  identities are created at resolution/execution time and bound via
  `TargetResolution`/`ScopeEvaluation` lineage, never stored on the
  authorization. The store therefore binds `authorization_id` plus the
  full issuance lineage (target, scope hash, artifact, class, expiry).
- `ai/persistence/driver.py` — narrow `MongoCollection` seam
  (`find_one`/`find`/`insert_one`/`replace_one`, now plus atomic
  `find_one_and_update`); `FakeMongoCollection` (unique indexes,
  failure injection).
- `ai/persistence/mongo_authz.py` — pre-existing `MongoAuthorizationStore`
  over the injected seam (kept, hardened — see §3).
- Mongo conventions reused: `WATCH_MONGO_URI` via
  `ai.config.require_mongo_uri()` (env-only credentials), `watch`
  database (as in `HTTPCollector`), `serverSelectionTimeoutMS=5000`,
  sanitized error details (no URIs/secrets), lazy driver import so
  persistence modules never connect at import time.
- `ai/live_validation/lane.py` — `ControlledLiveValidationLane` already
  accepts an injected `authz_store`; annotation widened to the
  `AuthorizationStore` protocol (DI only, no gate change).

## 2. Files changed

| File | Change |
|------|--------|
| `ai/persistence/driver.py` | `find_one_and_update(filter, update)` added to the `MongoCollection` protocol (+ `UpdateError`); `FakeMongoCollection` implements it atomically under a lock (`$set` flat keys, `$inc` numerics, `_id` immutable, unknown operators fail closed); filter matcher gains minimal `{"$gt": number}` numeric predicate (all other shapes fail closed to no-match); mutating fake ops lock-serialized so concurrent-CAS tests prove exactly-once. |
| `ai/persistence/mongo_authz.py` | Denormalized binding projection + `expires_at_epoch`; `compare_and_swap` as a single conditional `find_one_and_update` (InMemory-identical failure precedence; guard re-asserted in the write filter); NEW atomic `consume_single_use` (full ISSUED+version+expiry guard in one filter); NEW post-issuance binding-immutability guard (`_require_bindings_preserved` — only `lifecycle`/`record_version`/`stored_leases` may advance); projection/payload coherence check on every read; `ensure_authz_indexes()` + `production_authz_store()` factory (env URI, lazy driver import). |
| `ai/live_validation/lane.py` | `authz_store` parameter widened `InMemoryAuthorizationStore` → `AuthorizationStore` protocol. Default still in-memory. No gate logic touched. |
| `ai/test_mongo_authorization_store.py` | NEW — 42 focused offline tests (see §8). |

Unrelated dirty files (`ai/execution/netns_sandbox.py`,
`ai/test_b7_egress_boundary.py`, B8 report, `run-pipeline.sh`,
`crawl/output/`, `dns-bruteforce/`) were already modified/untracked
before this task and were NOT touched.

## 3. Collection name

Database `watch`, collection **`execution_authorizations`**
(`AUTHZ_DATABASE_NAME` / `AUTHZ_COLLECTION_NAME`).

## 4. Document schema

One document per issuance record. `_id` = `authorization_id`.
`document` = sealed `IssuedExecutionAuthorization`
(`model_dump(mode="json")`) — the sole authority payload, re-validated
through the schema on every read. Denormalized guard/binding projection
(top level, lets atomic filters pin bindings server-side):

- identity/state/version: `authorization_id`, `idempotency_key`,
  `record_version` (CAS guard), `lifecycle` (state guard)
- expiry: `expires_at` (RFC3339), `expires_at_epoch` (numeric guard;
  naive→UTC rule identical to the 5B service)
- execution binding: `execution_class`, `program_name`, `host` (pinned
  address, preserved exactly), `scheme`, `effective_port`,
  `scope_lists_hash` (scope hash), `test_plan_id`, `issuer_identity`
- artifact/template identity: `artifact_id`, `artifact_hash`
  (content hash)

Field mapping to the required list: `execution_id`/`resolution_id` are
NOT issuance-record fields (see §1 NOTE) — execution binding is enforced
downstream by resolution/scope lineage (`TargetResolution` +
`ScopeEvaluation` + executor `_check_binding`), which re-reads the live
authorization from THIS store. `target_hash`/`scope_hash`/`pinned_address`
are covered by (`program_name`,`host`,`scheme`,`effective_port`) +
`scope_lists_hash`. Malformed or incomplete documents fail closed:
payload schema failure OR projection/payload drift → treated as absent
(`None` on reads, `RecordNotFoundError` on CAS/consume) — a corrupt row
can never become authority.

## 5. Indexes

- Unique: `(_id)` (driver default), `(idempotency_key)` —
  `AUTHZ_UNIQUE_INDEXES`.
- Non-unique: `(lifecycle)`, `(expires_at_epoch)`, `(execution_class)` —
  `AUTHZ_INDEXES` (liveness sweeps, consume guard, operational reads).
- No TTL index (authority rows are never auto-deleted); no other indexes.
- `ensure_authz_indexes()` is idempotent and safe to repeat (tested:
  two consecutive calls return identical names with identical
  unique/non-unique flags; `_id` left to the driver).

## 6. Atomic CAS mechanism

- `compare_and_swap`: pure input guards (types → InMemory-identical
  failure precedence: missing/corrupt → `RecordNotFoundError`, drift →
  `VersionConflictError`, identity rebind / non-+1 step / binding drift →
  `AuthorizationStoreError`) → ONE `find_one_and_update({_id,
  record_version}, {$set: replacement})`. Pre-write reads can only refuse
  early; the write filter re-asserts the guard at apply time, so a row
  changing mid-flight misses and conflicts — never succeeds. Never
  read + unconditional-write.
- `consume_single_use(authorization_id, *, now)`: successor built from the
  validated live row (only `lifecycle`→CONSUMED, version +1), then ONE
  `find_one_and_update` with the full single-use filter `{_id,
  record_version, lifecycle: ISSUED, expires_at_epoch: {$gt: now}}`.
  N concurrent consumers → exactly one match; losers observe no match →
  `VersionConflictError`, no retry. Expired/consumed/revoked/corrupt/
  unknown rows fail closed with zero mutation.
- Binding immutability: `_require_bindings_preserved` diffs the full
  validated records and permits differences ONLY in `lifecycle`,
  `record_version`, `stored_leases`. Target, pinned address, scope hash,
  artifact/template identity, execution class, expiry, test-plan/issuer
  binding, issuance nonce, methods, phases — all frozen; drift raises
  `AuthorizationStoreError` before any write. (Service flows — consume,
  revoke, lease gates — only ever advance the three mutable fields.)

## 7. Failure semantics

Mongo failures are NEVER interpreted as missing/consumed/valid/empty:
`MongoUnavailableError` (connection failure, timeout, injected outage)
propagates unchanged from every operation; callers fail closed with
nothing cached, retried, or synthesized. Duplicate key (both `_id` and
`idempotency_key` races) → `DuplicateIdempotencyKeyError` (fail closed,
re-read to classify). CAS conflict → `VersionConflictError`. Missing or
corrupt document → `RecordNotFoundError` / `None`. Expired → refused at
store level (`consume_single_use` epoch guard) AND service level
(`_is_live`), without mutation. All error details sanitized — no URIs,
credentials, nonces, or payload bytes (asserted by tests).

## 8. Tests/results

New `ai/test_mongo_authorization_store.py` — **42 tests, all offline over
`FakeMongoCollection`, no live server**:

1. put/get round trip (exact field equality) + idempotency-key read +
   binding-projection pinning — PASS
2. duplicate authorization_id — PASS
3. ISSUED→CONSUMED success (store-level + persisted-state check) — PASS
4. second consume rejected without mutation (store + service level) — PASS
5. stale-version / identity-rebind / non-+1-step / missing-row CAS — PASS
6. expired rejected without mutation (store + service `AUTHZ_EXPIRED`) — PASS
7. malformed document rejected (payload corruption, projection drift,
   malformed expiry, untyped inputs) — PASS
8. Mongo outage fails closed, secret-free, on all five operations — PASS
9. concurrent consume (8 threads + barrier): exactly 1 winner, 7
   conflicts, terminal CONSUMED v2 — PASS
10. repeated index init safe/stable/correct unique flags — PASS
11. post-issuance binding immutability (target/host/scope/port/artifact/
    class/expiry tamper refused; lifecycle-only and lease-only advances
    allowed) — PASS
12. protocol conformance, lane DI acceptance (dry-run), live-switch
    assertion — PASS

## 9. Live-validation switches remain disabled

- `ai/execution/nuclei_executor.py` — `LIVE_NUCLEI = False`
- `ai/execution/nuclei_launcher.py` — `LIVE_LAUNCH_ENABLED = False`
- `WATCH_AI_LIVE_VALIDATION` unset/non-truthy in this environment
- Asserted `is False` / non-truthy by the new suite
  (`test_live_switches_remain_disabled`). No code path in this task
  references or modifies any of them. No new API endpoint, no FastAPI
  wiring, no scope/egress/sandbox change, no authorization issued.

## 10. Remaining B10 blockers

1. Operator-controlled dedicated IP-literal target not designated
   (see B10.1 preflight).
2. Pinned template file not materialized at
   `/srv/watch/scratch/nuclei/CVE-2026-1557.yaml`.
3. Fresh single-use `nuclei_scan` authorization not issued (store ready
   via `production_authz_store()` + `issue_authorization`; issuance is an
   explicit operator act, NOT performed here).
4. Production MongoDB reachability/credentials unproven here by design
   (factory pings on construction; no live infra touched).
5. Explicit go-decision + simultaneous switch enablement — operator act.

## 11. Final verification

- Focused suite: `ai.test_mongo_authorization_store` — **42 tests, 0
  failures, 0 errors (OK)**.
- Regression: `+ ai.test_execution_authorization +
  ai.test_stage2_production_reads + ai.test_live_validation +
  ai.test_knowledge_store + ai.test_xss_researcher +
  ai.test_xss_llm_researcher + ai.test_openrouter` — **309 tests total,
  0 failures, 0 errors (OK)**.
- `git diff --check` — clean.
- Changed files (this task): `ai/persistence/driver.py`,
  `ai/persistence/mongo_authz.py`, `ai/live_validation/lane.py`,
  `ai/test_mongo_authorization_store.py` (new),
  `agent-reports/phase-5h-core-production-authorization-store.md` (this file).
- `git status --short` (pre-existing unrelated entries preserved):
  `M agent-reports/phase-5k-live-b8-runtime-kernel-validation.md`,
  `M ai/execution/netns_sandbox.py`, `M ai/live_validation/lane.py`,
  `M ai/persistence/driver.py`, `M ai/persistence/mongo_authz.py`,
  `M ai/test_b7_egress_boundary.py`, `M run-pipeline.sh`,
  `?? agent-reports/phase-5h-core-production-authorization-store.md`,
  `?? agent-reports/phase-5k-live-b10-controlled-validation-runbook.md`,
  `?? agent-reports/phase-5k-live-b10.1-activation-preflight.md`,
  `?? agent-reports/phase-5k-live-b8-retest-runtime-validation.md`,
  `?? agent-reports/phase-5k-live-b8.1-sandbox-fixes.md`,
  `?? agent-reports/phase-5k-live-b9-final-security-review.md`,
  `?? ai/test_mongo_authorization_store.py`, `?? crawl/output/`,
  `?? dns-bruteforce/`.
- `git diff --stat` (scoped to this task's tracked files):
  `ai/live_validation/lane.py | 8 +-`, `ai/persistence/driver.py |
  115 +-`, `ai/persistence/mongo_authz.py | 358 +-`
  (remaining stat lines belong to pre-existing unrelated changes).
- No commit, no push, no pull, no reset/stash/checkout performed.
  No live switches enabled. No authorization issued.

---
Report generated:
`agent-reports/phase-5h-core-production-authorization-store.md`
