# Phase 5H — Production-Grade Evidence Store: Implementation Report

## 1. Verdict

**PASS.** The 5H Evidence Store layer is implemented per
`agent-reports/evidence-store-architecture.md` as an offline,
deterministic, observation-only persistence seam: immutable sealed
`EvidenceRecord` envelopes, server-derived content-addressed blobs
(`blobs/sha256/<content_hash>`), frozen-hash identity, idempotent
writes, CAS-guarded indexing, forward-only crash recovery, orphan
sweep with quarantine, read-time integrity verification, 5I handoff
reuse, retention hooks without auto-deletion, audit integration, and
centralized 5G browser ceilings. No 5I classification, no findings,
no verdicts. B2 and B5 remain BLOCKED. New suite: 93 tests, all
passing. Full regression: 822 tests, all passing.

## 2. Files created

- `ai/evidence/blob_store.py` (413 lines) — CAS blob abstraction:
  `BlobStore` protocol, `InMemoryBlobStore` fake,
  `FilesystemCASBlobStore` deterministic test backend (temp-dir
  confined, temp-write + fsync + atomic publish + read-back verify),
  `blob_key_for`, quarantine, operator-gated
  `delete_after_retention_policy`.
- `ai/evidence/index.py` (373 lines) — typed index abstraction:
  `IndexEntry` (frozen, CAS-versioned), `EvidenceIndex` seam,
  `InMemoryEvidenceIndex` fake (unique `evidence_id`/`execution_id`/
  `(authorization_id, stage)` indexes, CAS, tombstone, quarantine),
  `MongoEvidenceIndexAdapter` B2-gated stub (fails closed),
  `B2_STATUS = "BLOCKED"`, `B2_BLOCKED = True`.
- `ai/evidence/store.py` (953 lines) — `EvidenceStore`
  orchestration (validate → verify → bounds → serialize → blob →
  read-back → conditional index → CAS mark-indexed → ledger CAS →
  audit), canonical envelope helpers, browser-bounds check,
  `PersistResult`, `RetentionPolicy`, `retention_eligible`, five
  role capabilities (Writer/Reader/Verifier/Sweeper/Operator).
- `ai/evidence/sweep.py` (258 lines) — `discover_candidates` /
  `run_sweep` over the blob/index set-diff reusing
  `classify_orphan`, grace periods, quarantine vs. original-key
  re-index, `SweepReport`.
- `ai/test_evidence_store.py` (1620 lines) — 93-test offline suite
  (stdlib `unittest`; temp dirs only).
- `agent-reports/evidence-store-implementation.md` (this report).

## 3. Files modified

Two narrow adapter seams (no behavior change to 5E/5F/5G semantics):

- `ai/limits/ceilings.py` (+19 lines) — seven central browser keys
  plus `_ZERO_ALLOWED_DIMENSIONS` exemption for the legitimately-zero
  `browser_popup_events` ceiling (same exemption shape as the
  pre-existing `nuclei_retries`).
- `ai/execution/browser_executor.py` (alias seam only) —
  `BROWSER_EVENT_BOUNDS` converted from an independent dict literal
  into a read-through alias (`_BrowserEventBoundsView`) of the
  central `browser_*` ceiling keys; value-identical
  (dialog 8, frame 4, popup 0, console 32, oracle 16, DOM 8192,
  storage 16). `default_resource_limits()` output unchanged.

Legacy protection: `ai/verification/browser_executor.py`,
`ai/verification/oracle.py`, `ai/verification/verifier.py`,
`ai/verification/xss_pipeline.py`,
`ai/verification/xss_case_builder.py`,
`ai/verification/composite_executor.py` — NOT modified (absent from
git status). `git diff --check` on all new/touched files is clean.

## 4. Frozen contracts reused

No duplication: `EvidenceRecord` / `EvidenceBuilder`
(`begin/attach_*/seal/seal_partial`, `verify_record`,
`compute_hashes`) / `BrowserObservation` / `NucleiObservation` /
`HttpObservation` / `hashing` (`canonical_json`, `hash_payload`,
`sha256_hex` — new code only *calls* them; AST test forbids local
redefinitions) / `scrubber` (single shared instance; AST test
forbids a second scrubber) / `InMemoryExecutionLedger` (optional
ledger CAS target) / audit trail (`AuditRecord`, `gap_record`,
`check_ordering`) / `classify_orphan` / `validate_reindex` /
`assemble_handoff` / `bind_provenance` /
`verify_provenance_for_handoff` / `require_live_for_execution`
(negative test) / `CEILINGS` / `check_limit` / `validate_config` /
`IssuedExecutionAuthorization` (handoff provenance fixtures).
`BROWSER_EVENT_BOUNDS` remains importable for existing 5G tests.

## 5. Ceiling centralization

`CEILINGS` is the single source of truth for exactly the specified
values: `browser_dialog_events=8`, `browser_frame_events=4`,
`browser_popup_events=0`, `browser_console_entries=32`,
`browser_oracle_events=16`, `browser_dom_observation_bytes=8192`,
`browser_storage_keys=16`. Existing `check_limit`/`validate_config`
mechanics reused (tighten-only verified by tests, including
over-ceiling, `None`, and positive-popup rejections). 5G keeps no
authoritative copy: its mapping is a read-through view with a
short→central keymap, asserted value-equal by test. Ceilings are
policy only — they never enter evidence hashes. Reads never apply
ceilings retroactively (verified: a 10-marker record still passes
`verify_record`; only new persists are bounds-checked).

## 6. Blob CAS

Key `blobs/sha256/<content_hash>`, derived by `blob_key_for` from a
validated sha256 hex; malformed/traversal keys rejected. Semantics:
identical re-put → no-op success (`False`); same key with differing
bytes → fail closed (`EVIDENCE_HASH_MISMATCH`, never overwrite);
filesystem backend uses same-directory temp file + fsync + atomic
publish with an `O_EXCL`-style collision guard + read-back byte
verification + read-only chmod; no partial object is ever reported
durable. `enforce_identity` flag: strict byte-digest CAS by default;
the evidence store passes `False` because evidence identity is the
frozen triple hash (verified above and on every read), while the blob
layer still enforces key format, collision refusal, and read-back
byte equality. Quarantine annotates; deletion requires a
`RetentionPolicy` with `allow_blob_deletion is True`, else fails
closed — and is never invoked automatically.

## 7. Evidence Store

`EvidenceStore(blobs, index, ledger=None, audit=None, hooks=None)`
with capability-checked dependencies and injectable crash-hook edges
(`before/after_blob/index/ledger/audit`). Narrow surface: persist,
three retrievals, integrity verification, quarantine, re-index,
tombstone, handoff. Structurally absent (AST-asserted on
definitions): `update_evidence`, `patch_evidence`,
`mutate_evidence`, `rebind_evidence`. Canonical envelope is
`hashing.canonical_json(record.model_dump(mode="json"))` UTF-8 —
frozen form, byte-stable across round-trips (tested).

## 8. Index adapter

`insert_if_absent` (identical re-insert → `False`; same
`evidence_id` with differing bindings/hashes, same `execution_id`,
or same `(authorization_id, stage)` slot → `IndexDuplicateError`),
point lookups by evidence/execution/authorization/content-hash,
`mark_indexed` / `quarantine` / `tombstone` all CAS on
`record_version` (`IndexVersionConflict` on stale writers; re-mark of
an INDEXED entry is an idempotent no-op). `tombstone` accepts only
`RetentionPolicy` (typed, `TypeError` otherwise). No generic update
dictionaries, no RMW without a guard — the Pattern Store race shape
is structurally unavailable.

## 9. Mongo B2 gate

`MongoEvidenceIndexAdapter` raises `EVIDENCE_MALFORMED` (B2-blocked)
in `__init__` and on any attribute access. Module text contains no
credentials, connection strings, topology, or driver imports
(AST/text-asserted: no `pymongo`/`motor`/`MongoClient`/`connect(`/
`mongodb://`). `B2_STATUS = "BLOCKED"`, `B2_BLOCKED = True`.

## 10. Lifecycle

Enforced exactly: `BUILDING` records rejected at persist;
`SEALED`/`INCOMPLETE` persist; `SEALED → INDEXED` via conditional
insert + CAS mark; `ORPHANED` / `CORRUPT` / `AUDIT_GAP` exist only as
index/sweep/audit states — `ORPHANED` is never an `EvidenceRecord`
byte state (reindex returns the ORIGINAL lifecycle). No backward
transitions; sealed bytes never mutated (tombstone is an index flag;
bytes verified byte-identical after tombstoning).

## 11. Write ordering

Implemented order: (1) typed validation, (2) `verify_record`
triple-hash check, (3) browser-bounds check for new records,
(4) canonical serialization, (5) blob put-if-absent, (6) read-back
get + parse + re-verify + hash comparison (divergence →
quarantine + `EVIDENCE_HASH_MISMATCH`), (7) conditional index insert
+ CAS mark-indexed (version losers dedupe-read), (8) ledger CAS
(best-effort forward; absent/non-STARTED rows skipped; ambiguous
commits never assumed — index holds durable truth), (9) audit
`EVIDENCE_SEALED` with post-seal failure mapped to `AUDIT_GAP`
(best-effort gap record, evidence untouched). Hook-edge order test
pins the sequence.

## 12. Concurrency/CAS

Duplicate identical persist → deduped success; duplicate differing
content under one `evidence_id` → `EVIDENCE_BINDING_MISMATCH`;
multi-threaded put race (8 threads) → exactly one winner;
multi-threaded index-insert race → exactly one winner, losers
dedupe/conflict; stale `expected_version` → `IndexVersionConflict`.
No locks assumed; uniqueness comes from key rules + version guards.

## 13. Orphan sweep

`discover_candidates` diffs blob listing vs. index: blob-without-
index → `INDEX_MISSING_SEALED`/`_INCOMPLETE` (grace-deferred, then
re-indexed under original keys via `validate_reindex`);
index-without-blob → `BYTES_MISSING` (quarantine, serve refused);
claim-divergent bytes → `BINDING_AMBIGUOUS` (quarantine);
unparseable bytes → `BINDING_AMBIGUOUS` (quarantine, never delete).
`run_sweep` executes one epoch with `SweepReport`
(candidates/reindexed/quarantined/deferred_grace/audit_gap). Sweep
never synthesizes identity and never deletes. Abandoned `BUILDING`
state is annotation-only (nothing exists to recover — pure
`classify_orphan` table covered by test).

## 14. Corruption handling

Every read: bytes → typed parse → `verify_record` → content/
bindings/observations hash comparison → index-claims vs. sealed-
bindings comparison. Any integrity failure (including unparseable
bytes and missing bytes) quarantines blob + index, emits an audit
annotation where a record is available, refuses serving and refuses
handoff — while tombstone/quarantine refusals re-raise without
double-quarantine. Bytes preserved for forensics; repair-in-place is
impossible (no API). Bit-flip corruption test confirms quarantine +
handoff refusal.

## 15. Scrubbing

No new scrubber (AST-asserted). Secrets verified redacted/absent:
Authorization/Cookie header values, query secrets, body secrets
(`api_key=…`), userinfo in redirect URLs, console bearer leakage,
raw oracle values (only `executed_payload_hash` persists), OOB
markers (never in envelopes). Envelope-bytes tests assert absence.

## 16. Access control

Structural capabilities: Writer (persist + read-back + verify only),
Reader (verified reads only), Verifier (handoff + read only),
Sweeper (quarantine + re-index + verify only), Operator (retention
eligibility + tombstone only). Each constructor type-checks its
store; `hasattr` tests assert every forbidden method is absent from
each role.

## 17. Audit

Reuses `AuditRecord`/`gap_record`; vocabulary-safe mapping that
preserves `check_ordering`: persist → `EVIDENCE_SEALED` (hashes),
handoff → `VERIFIER_HANDOFF`, re-index → `ORPHAN_REINDEXED`,
post-seal failures → `AUDIT_GAP`, quarantine/integrity/tombstone/
retrieval annotations → `EXECUTION_TERMINAL` with
`store:<event>` scope notes (never secrets). Retrieval audit is
opt-in (`audit_reads`, default off). Persist+handoff chains pass
`check_ordering`; failing sinks yield `audit_gap=True` on the
result, never silence.

## 18. Retention

`RetentionPolicy` (validated id, optional program scope, optional
non-negative TTL, `allow_blob_deletion` default `False`);
`retention_eligible` pure TTL predicate (scope-aware; `None` TTL
never eligible); `tombstone_evidence` flips the index entry only
(bytes byte-identical afterwards; tombstoned records unservable);
blob deletion additionally gated per-call on the policy flag and
never invoked by the store itself. Deletion is therefore never a
mutation of sealed bytes.

## 19. 5I handoff

Reuses `assemble_handoff`/`bind_provenance`/
`verify_provenance_for_handoff`. Rejects BUILDING (unpersistable),
INCOMPLETE by default, missing, corrupt, hash-mismatched, binding-
divergent, and unauthenticated provenance (wrong authorization →
`HANDOFF_REJECTED`). Consumed-issuance provenance verifies
(`AUTHZ_VALID_FOR_PROVENANCE`) while `require_live_for_execution`
still refuses it — provenance grants no re-execution. Handoff
payloads contain ids/hashes only (asserted free of
verdict/finding/severity/vulnerable/confirmed keys).

## 20. Test matrix

93 tests across Hashing (6), Immutability (3), Blob (10), Index (6),
MongoGate (3), Lifecycle (6), Crash windows (6), Orphan/sweep (8),
Corruption (5), Ceilings (6), Scrubber (8), Handoff (7), Access
control (5), Retention (3), Audit (3), Concurrency (4), Observation
classes (3), Security boundary AST (2) — covering every required
category: canonical/hash/timestamp/corruption; immutability/no-
update/same-id-divergence; CAS/duplicate/race/stale-writer;
orphan seven-case shapes + original-key re-index; binding/
observation/sample/hash/byte mutations + quarantine + handoff
refusal; seven ceilings + tighten-only + alias + backward compat;
nine scrubber shapes; lifecycle transitions + dedupe; valid/
incomplete/corrupt/missing/provenance/consumed handoff; five roles;
TTL/tombstone/GC gating; all seven crash windows; AST bans on
finding/verdict/severity/`CONFIRMED`/`VULNERABLE`/
`NOT_VULNERABLE`/OOB-collector/live-Mongo/live-network tokens.

## 21. Exact test counts

- `ai.test_evidence_store`: **93 tests — OK** (0.45s).

## 22. Regression results

All passing, no existing test modified:

- `ai.test_evidence_core` + `ai.test_execution_authorization` +
  `ai.test_scope_evaluator` + `ai.test_target_resolver`:
  **403 tests — OK**.
- `ai.test_http_pinned_executor` + `ai.test_nuclei_executor`:
  **207 tests — OK**.
- `ai.test_browser_executor_5g` + `ai.test_browser_executor_smoke`:
  **123 tests — OK** (5G alias seam value-identical; no 5G behavior
  change).
- `ai.test_knowledge_store` + `ai.test_xss_researcher` +
  `ai.test_xss_llm_researcher` + `ai.test_openrouter`:
  **89 tests — OK**.
- Regression total: **822 tests — OK**. Combined with the new suite:
  **915 tests green.**

## 23. Crash-window verification

Each window fault-injected via store hooks and recovered
forward-only: before-blob → nothing durable; after-blob/before-
index → orphan → `reindex_from_blob` restores servability;
after-index/before-ledger → index durable, ledger stale →
idempotent retry completes `SEALED_REF`; after-ledger/before-audit
→ retry completes with `EVIDENCE_SEALED` audited; audit-sink
failure → `audit_gap=True`, evidence still indexed; re-index crash
→ retry completes, never rolled backward. Ledger-forward test uses
the real `InMemoryExecutionLedger` (`REGISTERED → STARTED →
SEALED_REF` with the persisted `evidence_id`).

## 24. B1 status

BLOCKED (unchanged): production `AddressSource` selection/review
deferred. 5H consumes only injected resolution facts.

## 25. B2 status

**B2 = BLOCKED** (unchanged): no production Mongo connection exists;
the adapter is a fail-closed stub. Remaining before B2 can close:
provisioned topology + credentials-via-secret-store (outside code),
reviewed migration creating the four collections with unique
indexes/roles from §7 of the architecture report, CAS-only data
access review, blob-store durability/restore drill, sweep daemon
scheduling, full §21-equivalent suite green against real backends,
signed retention/tombstone policy. A passing fake-adapter suite
does not close B2.

## 26. B4 status

BLOCKED (unchanged): payload-corpus source-of-truth review deferred.
5H stores artifact hashes only.

## 27. B5 status

**B5 = BLOCKED** (unchanged): `LIVE_BROWSER = False` verified at
runtime; no browser containment implemented; no live execution path
added by 5H.

## 28. Known limitations

- Fakes model single-process CAS faithfully; cross-worker
  uniqueness still requires the production adapter (documented, not
  claimed).
- `FilesystemCASBlobStore` is a deterministic test backend, not a
  production object store (no object-lock/retention-mode,
  no multi-node replication).
- `indexed_at` is a free-form string (ISO instant in practice);
  TTL math treats unparseable values as epoch 0 (fail-toward-
  eligible, operator-visible via tombstone audit — never silent).
- Tombstoned blobs are not auto-GC'd; GC requires an explicit
  operator call with a deletion-enabled policy.
- `browser_popup_events = 0` required a minimal `check_limit`
  exemption (same shape as the pre-existing `nuclei_retries`
  exemption); negatives still rejected, positives still
  `LIMIT_EXCEEDED`.

## 29. Deferred items

Production Mongo adapter + migration + roles; object-store backend
with retention-mode; sweep daemon scheduling; audit backend +
retention purge; 5I verifier (handoff consumer); 5J scheduler/E2E;
B1/B2/B4/B5 closures (each needs separate review).

## 30. Exact next phase

**5I Deterministic Verifier** — consume only `EvidenceHandoff`
references (`SEALED` + integrity-valid + complete, or explicitly
permitted `INCOMPLETE` channels) with `verify_provenance_for_
handoff` provenance, implement deterministic classification rules
over sealed observations, and keep all verdict logic out of 5H.
Do not start 5J until 5I handoff matrices for all three observation
classes (5E/5F/5G) are green. Do not close B2/B5.

---

Mandatory explicit statements: MongoDB production accessed = NO ·
network = NO · DNS = NO · subprocess = NO · browser = NO ·
JavaScript = NO · LLM = NO · Git = NO · live browser = NO ·
LIVE_BROWSER = False · B2 = BLOCKED · B5 = BLOCKED · finding
generation = NO · verdict generation = NO · evidence mutation = NO ·
OOB = DENIED. Files created: `ai/evidence/blob_store.py`,
`ai/evidence/index.py`, `ai/evidence/store.py`,
`ai/evidence/sweep.py`, `ai/test_evidence_store.py`,
`agent-reports/evidence-store-implementation.md`. Files modified
(seams only): `ai/limits/ceilings.py`,
`ai/execution/browser_executor.py`.
