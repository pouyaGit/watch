# Phase 4D — Artifact Store: Implementation Report

## 1. Verdict

**IMPLEMENTED.** Phase 4D establishes the read-only,
content-addressed persistence boundary exactly as specified:

```
VALID ArtifactReference + exact artifact bytes
                    |
                    v
immutable, content-addressed, integrity-checked record
```

The store persists already-validated artifacts and retrieves them
with full integrity revalidation. No artifacts are generated,
executed, verified, or reclassified. No findings, verdicts, scope
decisions, LLM calls, network access, subprocess execution,
scheduling, queues, or MongoDB writes were introduced. All new
tests pass (53/53) and all regression suites pass with zero new
failures.

## 2. Actual repository findings

Inspected before writing any code (no prior report was trusted):

- `ai/schemas/artifact.py` — Phase 4C contract confirmed as
  reported: `ArtifactReference` with `artifact_id = art-` +
  deterministic alias of (type, plan, hash, version),
  `content_hash` = SHA-256 over exact bytes, closed
  `ArtifactType` (`nuclei_template` | `xss_payload` |
  `http_request_spec`) and `ValidationState` (`UNVALIDATED` |
  `VALID` | `REJECTED`) vocabularies, provenance fields, size
  limits (32 KiB / 4 KiB / 16 KiB), `extra="forbid"`. Not modified.
- `ai/researcher/artifact_validator.py` — pure entry point
  (`build_validated_reference`, `validate_reference_binding`,
  `HttpArtifactContent`, `validate_xss_payload`,
  `validate_http_safety`); imports only stdlib/pydantic plus the
  Phase 4C schemas. Reused for put/read revalidation. Not modified.
- `ai/researcher/nuclei_artifact_validator.py` — H1/H2 gates
  (`parse_template_content`, `validate_nuclei_safety`,
  `validate_nuclei_specificity`). Only the structural/safety
  parsers are reused by the store; the specificity gate is
  deliberately NOT re-run in storage (it needs caller fixtures
  and was already proven when the VALID reference was minted).
  Not modified.
- `ai/knowledge/pattern_store.py` — storage conventions reused:
  file-backed JSON under a root dir, `records/<key>.json` +
  sorted `index.json`, atomic temp-file + rename writes (here
  hardened with per-write unique temp names, flush + fsync),
  deterministic ordering, `extra="forbid"` strict schemas,
  idempotent put, identity-conflict errors, fail-closed
  corruption errors, no delete API. Its unique-temp-name
  hardening was adopted; its predictable-temp weakness in the
  older `KnowledgeStore._write_json_atomic` (shared
  `<name>.tmp`) was NOT copied. Neither file modified.
- `ai/knowledge/store.py` — content-hash-as-deduplication-key
  discipline confirmed (`content_hash` verified against bytes on
  read). Same principle applied to artifact bytes. Not modified.
- `ai/schemas/test_plan.py`, `hypothesis.py`, `target_match.py`,
  `target_intelligence.py` — identity/binding field shapes
  confirmed for preservation (no new adapter needed). Not modified.

## 3. Exact store contract

New file `ai/knowledge/artifact_store.py`
(`STORE_SCHEMA_VERSION = "artifact_store/v1"`):

```python
store.put(reference: ArtifactReference, content: bytes) -> PutResult
store.get(artifact_id: str) -> StoredArtifact | None
store.get_by_content_hash(content_hash: str) -> StoredArtifact | None
store.exists(artifact_id: str) -> bool
store.list(*, artifact_type: str | None = None) -> list[StoredArtifact]  # id-ordered

StoredArtifact(reference: ArtifactReference, content: bytes)  # frozen; data only
PutResult(stored: StoredArtifact, created: bool)
```

PUT policy: only `validation_state == VALID` is stored.
`UNVALIDATED` and `REJECTED` raise `ArtifactStoreError` — never
promoted, never reclassified. No verdict is introduced; the
reference's own state is preserved verbatim.

Errors (all `ValueError` subclasses, mirroring `PatternStore`):
`ArtifactStoreError` (base), `ArtifactIdentityConflictError`
(contradictory identity/bindings), `ArtifactNotFoundError`
(reserved), `ArtifactCorruptError` (any integrity failure).

## 4. Directory layout

```
<root>/                      # default ai_data/artifacts; tests use temp dirs
    index.json               # {"artifacts": {artifact_id: {artifact_type,
                             #   content_hash, test_plan_id, path}}, "version": 1}
    records/
        <content_hash>.json  # one envelope per SHA-256 content identity
```

Record envelope (exact key set enforced):
`{"reference": {...}, "content_b64": "...", "content_hash":
"<sha256>", "schema_version": "artifact_store/v1"}`.
Content is base64-encoded (bytes-safe; no pickle/marshal, no
object deserialization). Index entries are minimal
(`artifact_type`, `content_hash`, `test_plan_id`, `path`) and
every duplicated field is cross-checked against the record on
read. Record filenames derive ONLY from regex-validated
content hashes; index keys ONLY from regex-validated
artifact ids. No user-controlled metadata ever influences a path.

## 5. Content-addressing rules

- `content_hash = SHA256(exact artifact bytes)` (Phase 4C
  function, reused — not redefined). Two identical contents
  converge to one record; one-byte difference yields a distinct
  hash, identity, and record (proven by tests F/AZ).
- `artifact_id` recomputed from (type, plan, hash, version) on
  every put and every read; mismatch fails closed.
- Same content under a contradictory identity (different plan →
  different `artifact_id`, same `content_hash`) is REJECTED with
  `ArtifactIdentityConflictError` — never merged, never
  re-bound (test AB). Same identity with different
  content/hash/bindings is likewise rejected (tests AA/AC).
- No UUIDs, timestamps, filesystem names, random or model IDs
  anywhere in identity.

## 6. Atomic write design

`_write_bytes_atomic`: mkdir parents → unique temp name
(`<name>.<pid>.<thread>.<counter>.tmp`) → write full bytes →
flush → `os.fsync` → `os.replace` (atomic rename). A crash
leaves at most an orphan temp file, never a half-written
record; concurrent writers never share a temp file. Record file
is written and re-read-validated before the index is updated;
the index itself is written through the same atomic path with
sorted keys. An instance-level mutex guards the index
read-modify-write cycle so concurrent puts cannot drop each
other's entries (regression caught during testing: 8-thread
distinct-put initially yielded 1 index entry; after the lock,
8/8 persist — test AT). Tests X/Y prove no `.tmp` leftovers
and byte-complete records.

## 7. Integrity / revalidation design

On PUT (`_verify_reference_and_content`, existing validators
only — no new Nuclei/XSS/HTTP semantics): typed inputs →
closed type → state must be VALID → well-formed plan id → size
limit → `content_hash` recomputation → `artifact_id`
recomputation → genuine-instance re-parse → per-type safety
re-check (`parse_template_content` + `validate_nuclei_safety`;
`HttpArtifactContent` + `validate_http_safety`;
`validate_xss_payload`). Any failure raises, nothing is written.

On GET (`_load_record` + `_load_entry_stored`): index entry
shape → record JSON shape/exact keys → envelope schema
version → filename/hash agreement → base64 validity →
recomputed-bytes hash → reference re-parse → reference/hash
agreement → identity recomputation → reference schema version
→ state still VALID → full safety re-check → index/record
cross-check (id, type, plan). First failure raises
`ArtifactCorruptError`; corrupted content is never returned as
valid. The specificity gate is not re-run on read (needs
caller fixtures; proven at VALID-mint time) — documented in
§15.

## 8. Immutability design

No `update_content`, `delete`, `remove`, `purge`, `clear`, or
`replace` API exists (asserted by tests AC/AD). Re-put of the
identical (reference, bytes) returns the stored record with
`created=False` (test Z). Any same-id divergence (hash,
bindings, bytes) raises conflict; stored bytes are never
overwritten. New content always means a new identity. No
retention/GC/TTL in this phase.

## 9. Corruption handling

Fail-closed `ArtifactCorruptError` (never silent repair, never
guessing) for: malformed JSON (O), missing record (P),
envelope key/shape violations, unsupported schema versions
(record or reference, T), hash-field mismatch (Q), invalid
base64, recomputed-bytes hash mismatch (AZ), reference schema
violations including smuggled `verdict` metadata or dropped
`test_plan_id` (R), `artifact_id` mismatch (S), non-VALID state
(U), plan-swap with recomputed id caught via index cross-check,
missing index entry, unknown index artifact types, and
corrupted indexes — garbage JSON or bad entries fail `get`
and `list` alike (AU). Path traversal, absolute paths, and
malformed ids are rejected before any filesystem touch (V/W).

## 10. Binding / provenance preservation

`artifact_id`, `artifact_type`, `content_hash`, `test_plan_id`,
`hypothesis_id`, `match_id`, `snapshot_hash`,
`artifact_schema_version`, `validation_state` are stored
verbatim and verified on read. Provenance survives the
round-trip exactly (AX); snapshot-bound artifacts from
different observation states remain distinct identities with
their own bindings (AW). Wrong hash/id/plan/hypothesis/match/
snapshot/type bindings are each proven rejected (G–M), and
unknown types fail closed (N).

## 11. Security boundaries

The module imports only `base64/binascii/itertools/json/os/
re/threading`, `pathlib/dataclasses`, `pydantic`, the Phase 4C
contract, and the two existing Phase 4C validator modules. AST
tests prove the absence of: LLM/model/embedding imports (AJ),
network imports (AK), subprocess imports (AL), database
imports (AM), `scope_policy` (AN), verifier/oracle/executor/
browser/Nuclei-runtime imports (AO), finding creation (AP),
verdict fields (AQ), authorization fields (AR), and runtime
invocation calls. Nuclei/XSS/HTTP content is stored as inert
bytes and never executed, sent, resolved, or classified
(AH/AI/AG). `StoredArtifact` carries only `reference` +
`content` — no paths, handles, or executors (AF).

## 12. Adversarial test coverage (A–AZ)

`ai/test_artifact_store.py` — 53 tests, all passing:

| ID | Coverage | Result |
|----|----------|--------|
| A | VALID accepted, bytes + reference round-trip | ✅ |
| B | UNVALIDATED rejected | ✅ |
| C | REJECTED rejected | ✅ |
| D | deterministic content-addressed path | ✅ |
| E | same content converges | ✅ |
| F | one-byte difference → distinct record | ✅ |
| G | wrong content_hash rejected | ✅ |
| H | wrong artifact_id rejected | ✅ |
| I | wrong TestPlan binding rejected | ✅ |
| J | wrong hypothesis binding rejected | ✅ |
| K | wrong match binding rejected | ✅ |
| L | wrong snapshot binding rejected | ✅ |
| M | wrong artifact type rejected | ✅ |
| N | unknown artifact type rejected | ✅ |
| O | malformed record rejected | ✅ |
| P | missing content rejected | ✅ |
| Q | content-hash corruption detected | ✅ |
| R | metadata corruption detected | ✅ |
| S | artifact_id corruption detected | ✅ |
| T | schema-version corruption detected | ✅ |
| U | validation-state corruption detected | ✅ |
| V | path traversal rejected | ✅ |
| W | absolute path rejected | ✅ |
| X | no predictable temp collisions / leftovers | ✅ |
| Y | atomic write behavior | ✅ |
| Z | repeated put idempotent | ✅ |
| AA | conflicting duplicate rejected | ✅ |
| AB | same content + different plan rejected | ✅ |
| AC | immutable content (no mutation API) | ✅ |
| AD | no delete API | ✅ |
| AE | deterministic list ordering | ✅ |
| AF | no executable handles | ✅ |
| AG | XSS inert bytes | ✅ |
| AH | Nuclei never executed | ✅ |
| AI | HTTP never requested | ✅ |
| AJ–AO | import boundaries | ✅ |
| AP | no finding creation | ✅ |
| AQ | no verdict fields | ✅ |
| AR | no authorization fields | ✅ |
| AS | concurrent same-content convergence (8 threads) | ✅ |
| AT | concurrent distinct-artifact isolation (8 threads) | ✅ |
| AU | corrupted index fails closed | ✅ |
| AV | rogue duplicate entry fails closed, genuine intact | ✅ |
| AW | snapshot-bound artifacts distinguishable | ✅ |
| AX | provenance intact after read | ✅ |
| AY | returned bytes exactly equal (all 3 types) | ✅ |
| AZ | one-byte corruption detected | ✅ |

## 13. Integration test

`IntegrationTests.test_full_chain_put_get` runs with temp-dir
storage and no network/DB/LLM/subprocess/Nuclei/browser/HTTP/
verifier:

```
KnowledgeSourceClaims(SECONDARY) → GroundedClaim → project_claim
→ VulnerabilityPattern → TargetIntelligence → MATCH → Hypothesis
(CREATED) → TestPlan (CREATED) → VALID ArtifactReference
→ ArtifactStore.put() → ArtifactStore.get() → integrity revalidation
```

Retrieved bytes equal the original exact bytes; reference,
plan, and snapshot bindings all match.

## 14. Exact test results

- `python3 -m unittest ai.test_artifact_store` → **53 tests, OK**
- `ai.test_artifact ai.test_hypothesis_testplan
  ai.test_research_pattern ai.test_pattern_projector
  ai.test_pattern_store ai.test_target_intelligence
  ai.test_target_matcher ai.test_hypothesis_engine
  ai.test_test_plan_builder` → **523 tests, OK**
- `ai.test_ingestion_schema ai.test_ingestion_grounding
  ai.test_knowledge_store ai.test_knowledge_ingestion` →
  **132 tests, OK**
- `ai.test_openrouter ai.test_xss_researcher
  ai.test_xss_llm_researcher ai.test_xss_verification
  ai.test_xss_oracle` → **265 tests, OK**
- `python3 -m compileall -q ai` → **OK**

## 15. Limitations

1. The specificity (H1) gate is enforced at VALID-mint time, not
   re-run on store read (it requires caller fixtures the store
   never holds); reads re-check identity, hash, schema, and
   safety gates. A VALID reference whose matcher logic changed
   meaning without byte changes is not a meaningful threat
   (bytes are immutable and hash-bound), but the boundary is
   explicit.
2. Audit-only `metadata` mutations that remain schema-valid are
   not cryptographically detected (metadata is excluded from
   identity by Phase 4C design); any schema-violating metadata
   fails closed on read.
3. The write mutex is instance-level; cross-process concurrent
   writers to one directory are out of scope (records stay safe
   via atomic content-addressed writes; only concurrent index
   updates across processes are unprotected).
4. Crash between record write and index write leaves an orphan
   record that a re-put deterministically re-attaches (same
   identity + bytes required); no garbage collection exists in
   this phase.
5. No deletion, retention, TTL, or quota policy — future concern.

## 16. Explicit Git no-op confirmation

**No Git command was executed in this phase.** No `git status`,
`diff`, `add`, `commit`, `checkout`, `switch`, `restore`,
`reset`, `merge`, `branch`, `stash`, or any other Git operation
was run. No unrelated working-tree files were inspected,
staged, modified, or cleaned. Two new files were created; zero
existing files were modified.

## 17. Recommended next safe phase

A **deterministic retrieval/query** phase over the immutable
store: read-only lookups by TestPlan (`test_plan_id →
artifacts`), provenance audits, and store-integrity sweep
tooling (verify-all-records reporting, orphan detection) —
still with no generation, no execution, no verification, no
LLM, and no mutation of stored records. Executor integration
must remain a separate, later phase with its own authorization
boundary.
