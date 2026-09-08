# Phase B10.2 — Production Mongo Authorization Store Verification

**Date:** 2026-09-08
**Host:** Google VM hosting `/opt/watch` (phase run locally as instructed)
**Scope:** Prove the 5H-core `MongoAuthorizationStore` against the REAL Watch
MongoDB. No git pull/push/commit/reset/stash/checkout. All pre-existing
working-tree changes preserved. No live validation, no Nuclei execution, no
DNS/network reconnaissance, no authorization for real execution. Synthetic
TEST-NET records only, all removed afterwards.

## 1. Environment summary (secrets redacted)

- `WATCH_MONGO_URI`: present via project `.env` + `ai.config.require_mongo_uri()`
  (existing convention). Shell env alone does NOT carry it.
- Redacted identity: `mongodb://127.0.0.1:27017/watch`, auth configured.
  No password, full URI, API key, or token printed anywhere in this phase.
- Mongo service: `mongod --auth --bind_ip_all` running (PID 4528);
  docker `mongo` container Up 2 days; `mongod`/`mongodb` systemd units inactive
  (containerized deployment — not modified).
- Current Watch database: `watch` (matches `AUTHZ_DATABASE_NAME`).

## 2. Sanitized Mongo connectivity result

`production_authz_store()` (the actual production factory, no fakes)
constructed successfully: internal `ping` passed → connectivity + auth OK.
Returned `MongoAuthorizationStore` conforming to the runtime-checkable
`AuthorizationStore` protocol (`isinstance` True).

## 3. Production store construction result

CONSTRUCTION: OK — `watch.execution_authorizations` via factory defaults
(`serverSelectionTimeoutMS=5000`, index assurance on construction).

## 4. Collection/index verification

`ensure_authz_indexes()` run twice against the real collection — identical
results (idempotent). Real `index_information()`:

- `_id_` — default identity index
- `idempotency_key_1` — UNIQUE
- `lifecycle_1` — non-unique
- `expires_at_epoch_1` — non-unique
- `execution_class_1` — non-unique
- TTL indexes: NONE (verified absent — authority rows never auto-expire)

Baseline before writes: `count_documents({}) == 0` (no production
authorization records exist; nothing to disturb).

## 5. Synthetic round-trip result

Synthetic record via the real schema/service path (`AuthorizationRequest` →
`issue_authorization`): program `b10-2-test`, host `192.0.2.1` (TEST-NET-1,
non-routable), port 8443, `execution_class="nuclei_scan"`, 1-hour expiry,
synthetic `nuclei_template` artifact, no credentials/sensitive data.

- put → get by `authorization_id`: PASS, byte-exact field equality
- get by idempotency key: PASS, same record
- binding check (host/class/ISSUED): PASS
- malformed seam (`_from_document` on corrupt/empty dicts, zero DB writes):
  PASS (returns `None` — fail closed)

Note on §8 ID format: the schema mandates `authz-[0-9a-f]{16}`, so the
suggested `authz-b10-2-test-<random>` prefix is not schema-compliant;
records were instead identified by `program_name="b10-2-test"` +
TEST-NET host, with exact-`_id` cleanup.

## 6. Atomic consume result

- One `consume_single_use`: lifecycle CONSUMED, version 1→2, persisted — PASS
- Second consume: rejected (`VersionConflictError`), state frozen at
  CONSUMED v2 — PASS

## 7. Concurrency result

6 threads × `consume_single_use` on one fresh synthetic record (barrier start,
single shared production store): **exactly 1 winner, 5
`VersionConflictError` losers**, final state CONSUMED v2 — PASS. Real-Mongo
atomicity confirmed (mirrors the 8-thread fake-backed unit test).

## 8. Failure semantics result (real store)

- Duplicate `authorization_id` put → `DuplicateIdempotencyKeyError` — PASS
- Stale version CAS → `VersionConflictError` — PASS
- Expired record: store-level consume → `VersionConflictError` (no mutation,
  still ISSUED v1); service-level `consume_authorization` →
  `AUTHZ_EXPIRED` — PASS
- No connectivity error was observed; driver-error mapping (outage →
  `MongoUnavailableError`, never "not found"/"consumed"/valid) is covered by
  the offline suite. No infrastructure was disturbed.

## 9. Cleanup result

All 3 synthetic records deleted by exact `_id` (`delete_one`, 1 doc each);
post-delete `get` → `None` for each; final `count_documents({}) == 0` —
identical to the pre-run baseline, so no production record was touched
(none existed) and no residue remains. No unsafe bulk deletion performed.

## 10. Live safety result

- `LIVE_NUCLEI == False`, `LIVE_LAUNCH_ENABLED == False` (asserted)
- `WATCH_AI_LIVE_VALIDATION` unset (asserted non-truthy)
- No Nuclei process started (pgrep: none)
- No `ControlledLiveValidationLane.run(..., mode="live")` invoked
- No external target contacted; only loopback MongoDB traffic occurred
- No TEST-NET connections observed

## 11. Exact tests/results

- Real-Mongo verification script (`/tmp/b10_2_verify.py`, outside the repo):
  **27/27 PASS** (construction, round-trip ×5, malformed seam, duplicate,
  stale CAS, consume ×3, second-consume, no-mutation, expired ×3,
  concurrent ×2, cleanup ×7, no-residue).
- `python3 -m unittest ai.test_mongo_authorization_store
  ai.test_execution_authorization ai.test_stage2_production_reads
  ai.test_live_validation`: **220 tests, 0 failures, 0 errors (OK)**.
- `git diff --check`: clean.
- Full-repo suite NOT run (per instructions: inexpensive subsets only).

## 12. Final classification

**BLOCKED**

Rationale: production-store verification fully SUCCEEDS — the
production-store blocker is removed — but per the B10.1 preflight the
operator target, pinned template file, and fresh live authorization are
still missing. This phase authorizes nothing further.

## 13. Final output

- Final classification: **BLOCKED** (store VERIFIED; target/template/live
  authorization still pending operator action)
- Exact test results: 27/27 real-Mongo checks PASS; 220/220 unit tests OK;
  `git diff --check` clean
- Changed files (this phase): `agent-reports/
  phase-5k-live-b10.2-production-mongo-verification.md` (this report) only.
  Procedure script `/tmp/b10_2_verify.py` lives outside the repo. No
  application code modified.
- `git status --short`: unchanged from phase start — `M
  agent-reports/phase-5k-live-b8-runtime-kernel-validation.md`,
  `M ai/execution/netns_sandbox.py`, `M ai/live_validation/lane.py`,
  `M ai/persistence/driver.py`, `M ai/persistence/mongo_authz.py`,
  `M ai/test_b7_egress_boundary.py`, `M run-pipeline.sh`, plus the
  pre-existing `??` entries (this report now included). No entry added,
  removed, or reverted by this phase.
- Git operations performed: NONE (no pull/push/commit/reset/stash/
  checkout/clean).
- Live egress: DISABLED (verified §10; no switch touched).

---
Report generated:
`agent-reports/phase-5k-live-b10.2-production-mongo-verification.md`
