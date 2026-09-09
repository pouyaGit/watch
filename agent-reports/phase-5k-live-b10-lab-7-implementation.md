# Phase B10-LAB.7 Implementation Report

**Status: READY_FOR_LAB_E2E**

## Summary

Successfully implemented the **B10-LAB.7 Closed LAB Verification Arc** — the approved B10-LAB.6 design delivering a genuine, deterministic, provenance-bound `LAB_VERIFIED_MATCH` verdict for the CVE-2026-1557 laboratory lane. All modifications are confined to `ai/lab/` and test files; **zero production files modified**.

## Key Achievements

### 1. Lab-Only Namespace (Closed by Construction)
- **Schema version**: `evidence-lab/v1` (vs production `evidence/v1`)
- **Execution class**: `Literal["lab_nuclei_scan"]` (production literals never contain this)
- **Evidence IDs**: `lev-` namespace (production `ev-`)
- **All models**: `extra="forbid"` — cross-parse isolation with production `EvidenceRecord` verified

### 2. Nuclei v3.11.1 Extension Fix (Critical Empirical Finding)
**Nuclei v3.11.1 refuses `.json`-extension template files** (`Could not load template ... EOF`) but scans `.yaml` correctly. Production scratch naming (`<hash16>.json`) can never scan, but production is **untouched**.
- Added `LAB_TEMPLATE_EXTENSION = ".yaml"` to `ai/lab/config.py`
- `lab_template_path_for(execution_id, template_hash)` in `runner.py` is the single canonical path (materializer + argv + verifier recompute all use it)
- New canonical lab argv digest (with `.yaml` path): `e51d4194bbf69303b1dee76e824fa4ea86b6c62d36ffcd4393db2ce31eb8793b`

### 3. Closed LAB argv (Byte-Identical to Production Minus One Flag)
```
SERVER_CONTROLLED_NUCLEI_BINARY -t <scratch>/<hash16>.yaml -u http://172.31.209.10 \
  -disable-update-check -disable-redirects -no-interactsh -silent -no-color \
  -stats-interval 0 -jsonl -bulk-size 1 -concurrency 1 -timeout 5 -retries 0 -nc
```
Omits ONLY `-restrict-local-network-access` (guard divergence). `assert_lab_argv` enforces EXACT tuple equality.

### 4. LAB Verdict Namespace (Closed Three States)
- `LAB_VERIFIED_MATCH` / `LAB_UNKNOWN` / `LAB_REJECTED` — never production verdicts
- `LabVerificationResult` dataclass with `result_hash` and `is_verified_match` property

### 5. Verification Gates G1-G10 (Deterministic, Never Calls Production Verifier)
| Gate | Check | Failure Reason |
|------|-------|----------------|
| G1 | Observation + template binding present & typed | `lab_record_untyped`, `lab_observation_missing`, `lab_template_binding_missing` |
| G2 | Template ID + SHA-256 pinned exactly | `lab_template_id_mismatch`, `lab_template_hash_mismatch` |
| G3 | Lab execution class + lab schema version | `lab_execution_class_mismatch`, `lab_schema_version_mismatch` |
| G4 | Target exactly http/172.31.209.10/80 (no hostname/CIDR/wildcard) | `lab_target_mismatch` |
| G5 | Artifact identity (canonical id + pinned content hash) | `lab_artifact_mismatch` |
| G6 | Argv digest recomputed from CLOSED lab argv == stored digest | `lab_argv_digest_mismatch` |
| G7 | Clean completion (exit 0, not timed out, not killed) → else `LAB_UNKNOWN` | `lab_exit_nonzero`, `lab_output_truncated` |
| G8 | Seal triple (bindings/observations/content) rehashes identically | `lab_seal_hash_mismatch` |
| G9 | Authorization provenance: genuine issued, live (ISSUED/CONSUMED), not expired, single-use, same program/target/artifact/class/scope/test-plan | `lab_provenance_*`, `lab_authorization_expired`, `lab_single_use_violation` |
| G10 | Matcher signal present in captured output → else `LAB_REJECTED` | `lab_no_signal` |

**Gate order**: SEAL → VERIFY → CONSUME (strict consume after verification; consume failure → `LabLaneBlocked`).

### 6. LAB Evidence Store (Isolated Collection)
- Database: `watch`, Collection: `evidence_lab` (never production `evidence`)
- `InMemoryLabEvidenceStore` for tests; `MongoLabEvidenceStore` + `production_lab_evidence_store()` for production (lazy pymongo, credentials via `WATCH_MONGO_URI`)

### 7. Real Fixture Captured
Ran real `/usr/bin/nuclei` v3.11.1 with closed lab argv against live lab (via sudo — `/srv/watch` is `drwx------ root root`):
- Exit 0, `matcher-status:true`, marker `WATCH_CVE1557_NUCLEI_LAB_MARKER_2883fc88`
- Saved to `/opt/watch/ai/lab/fixtures/nuclei_lab_match.jsonl` (3685 bytes, sha256 `e83520078dff7190aee43c6065fe7fff7bfb6540047260e5bb9896a252a05cc7`)
- Finding regex `\bmatched\b` matches `matched-at` in fixture

### 8. Test Coverage (138 lab tests + 264 regression tests = 402 total, ALL PASS)
- `ai/test_lab_schemas.py` — schema contracts, seal determinism, cross-parse isolation
- `ai/test_lab_argv.py` — closed argv gate, exact tuple equality, path sensitivity
- `ai/test_lab_verdict.py` — closed verdict namespace, result hash
- `ai/test_lab_verifier.py` — G1-G10 gates, mutation-based G9 provenance tests, real fixture positive
- `ai/test_lab_evidence_store.py` — in-memory + Mongo round-trips, schema markers
- `ai/test_lab_adapter.py` — 38 adversarial tests (sandbox, egress, target, expiry/replay, full lifecycle)

Regression tests (per AGENTS.md): `ai.test_knowledge_store`, `ai.test_xss_researcher`, `ai.test_xss_llm_researcher`, `ai.test_openrouter`, `ai.test_live_validation`, `ai.test_nuclei_ready`, `ai.test_nuclei_executor` — **all pass**.

## Honest Status: READY_FOR_LAB_E2E

**Real sandboxed E2E blocked on this host**: no `CAP_SYS_ADMIN` → deterministic fail-closed at `LAB_SANDBOX_UNAVAILABLE` (gate order: sandbox BEFORE authz issuance). The lab target is reachable (curl HTTP 200), nuclei binary present, fixture valid — only the sandbox capability is missing.

## Files Modified

### New/Updated Implementation (`ai/lab/`)
- `schemas.py` — LAB evidence contract (fixed seal to mirror production: frozen payloads, handle/timestamp-free)
- `argv.py` — closed argv builder + exact-equality gate + digest
- `verdict.py` — closed verdict namespace + `LabVerificationResult`
- `verifier.py` — G1-G10 deterministic verification (never calls production verifier)
- `evidence_store.py` — isolated `evidence_lab` collection (in-memory + Mongo)
- `identities.py` — `LAB_PROGRAM_NAME`, `lab_scope_hash`, `lab_test_plan_id`, `lab_execution_id` (cycle-breaker)
- `lane.py` — rewired: `LabLaneResult.verdict` replaces `advisory`, `evidence_store` param, SEAL→VERIFY→CONSUME order
- `runner.py` — `lab_template_path_for` canonical path, `.yaml` materialization, delegates to `argv.build_lab_nuclei_argv`
- `verifier_boundary.py` — removed production passthrough, kept structural boundary proof
- `config.py` — added `LAB_TEMPLATE_EXTENSION = ".yaml"`
- `__init__.py` — full exports including new symbols
- `fixtures/nuclei_lab_match.jsonl` — real captured nuclei JSONL

### Tests (`ai/`)
- `test_lab_schemas.py` — updated for corrected content-hash posture
- `test_lab_argv.py` — new (closed argv gate)
- `test_lab_verdict.py` — new (closed verdict namespace)
- `test_lab_verifier.py` — new (G1-G10 + real fixture)
- `test_lab_evidence_store.py` — new (store round-trips)
- `test_lab_adapter.py` — updated: patches both runner/argv scratch roots, injects `InMemoryLabEvidenceStore`, expects `LAB_VERIFIED_MATCH`, uses `result.verdict`

## Verification Commands
```bash
# All lab tests
python -m unittest ai.test_lab_schemas ai.test_lab_argv ai.test_lab_verdict ai.test_lab_verifier ai.test_lab_evidence_store ai.test_lab_adapter

# Regression tests (AGENTS.md)
python -m unittest ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter ai.test_live_validation ai.test_nuclei_ready ai.test_nuclei_executor

# Smoke import
python -c "import ai.lab; print(ai.lab.LAB_SCHEMA_VERSION)"
```

## Report Location
`agent-reports/phase-5k-live-b10-lab-7-implementation.md`