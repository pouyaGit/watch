# Phase 4E — Deterministic Artifact Retrieval & Integrity Audit: Implementation Report

## 1. Verdict

**IMPLEMENTED.** Phase 4E establishes the read-only retrieval and
integrity-audit layer over the immutable Phase 4D ArtifactStore
exactly as specified:

```
ArtifactStore
    +--> binding retrieval (read-only, id-ordered)
    +--> provenance audit (PASS / FAIL / INCONCLUSIVE)
    +--> integrity sweep (structured, never mutating)
    v
read-only audit/query results
```

Strictly read-only: no generation, mutation, deletion,
replacement, execution, verification, findings, verdicts, scope
decisions, LLM calls, network access, subprocess, scheduling, or
executor integration. All new tests pass (45/45) and all
regression suites pass with zero new failures.

## 2. Actual repository findings

Inspected before writing any code (no prior report was trusted):

- `ai/knowledge/artifact_store.py` (759 lines) — confirmed as
  reported: immutable file-backed store (`index.json` +
  `records/<content_hash>.json`), `put` restricted to VALID
  references with full hash/identity/safety revalidation,
  `get`/`get_by_content_hash`/`exists`/`list` (id-ordered) with
  fail-closed `ArtifactCorruptError`, same-content/different-plan
  re-binding rejected, no delete API, instance mutex around the
  index read-modify-write cycle. **Not modified** — no additive
  change proved necessary.
- `ai/schemas/artifact.py` — Phase 4C identity semantics
  confirmed (`artifact_id_for`, `content_hash_for_bytes`,
  closed type/state vocabularies, `ARTIFACT_SCHEMA_VERSION =
  "artifact/v1"`). Reused verbatim for audit recomputation.
  Not modified.
- `ai/researcher/artifact_validator.py`,
  `nuclei_artifact_validator.py` — VALID-minting and safety
  gates confirmed; the store (not retrieval) remains their only
  consumer. Not modified.
- `ai/researcher/__init__.py` — exports only the XSS researcher
  symbols; researcher→knowledge imports already have precedent
  (`xss_researcher` consumes `KnowledgeStore`), so placing the
  read layer in `ai/researcher/` introduces no layering debt.
- `ai/test_artifact_store.py` — helper functions (`_bound_plan`,
  `_template_bytes`, `_benign`/`_vulnerable`, `_valid_nuclei`,
  `_valid_xss`, `_valid_http`, `_forge`) confirmed present and
  reused by import (single source of truth, no duplication
  drift). Not modified.
- `ai/schemas/test_plan.py`, `hypothesis.py`, `target_match.py`,
  `target_intelligence.py`, `ai/knowledge/pattern_store.py` —
  binding field shapes confirmed; no adapter required.

## 3. Exact files created / modified

Created (2), modified (0):

- `ai/researcher/artifact_retrieval.py` (new) — retrieval,
  provenance audit, integrity sweep. Imports only `json`/`re`,
  `dataclasses`, the `ArtifactStore` read API, and the Phase 4C
  hash/identity functions. No filesystem writes, no `open()`
  calls at all (directory names only, for orphan enumeration).
- `ai/test_artifact_retrieval.py` (new) — 45-test A–AR matrix.

Module-boundary note: the preferred `ai/researcher/
artifact_retrieval.py` location was adopted as-is. It is the
cleaner boundary because retrieval serves researcher-side
consumers (plan/hypothesis/match/snapshot bindings), researcher→
knowledge imports already exist, and zero store modifications
were required.

## 4. Retrieval API

```python
get_by_test_plan_id(store, test_plan_id) -> tuple[StoredArtifact, ...]
get_by_hypothesis_id(store, hypothesis_id) -> tuple[StoredArtifact, ...]
get_by_match_id(store, match_id) -> tuple[StoredArtifact, ...]
get_by_snapshot_hash(store, snapshot_hash) -> tuple[StoredArtifact, ...]
get_by_binding(store, *, test_plan_id=None, hypothesis_id=None,
               match_id=None, snapshot_hash=None,
               artifact_type=None) -> tuple[StoredArtifact, ...]
```

Semantics: store instance only (raw paths/dicts raise
`TypeError`); every binding strictly validated against the
Phase 4C shapes (`tp-`/`hyp-`/`tm-`/SHA-256, closed artifact
vocabulary) with malformed values raising
`ArtifactRetrievalError`; `get_by_binding` requires at least one
filter (unfiltered enumeration is not exposed). Returns the
exact stored objects (reference + bytes) for all three artifact
types, ordered by `artifact_id`, duplicate-free. Nothing is
synthesized or inferred — a TestPlan may have 0..n artifacts
(all returned). Corruption encountered during retrieval
propagates through the store's own checks (fail closed).

## 5. Provenance audit API

```python
audit_provenance(stored: StoredArtifact) -> ProvenanceAudit
ProvenanceAudit(artifact_id, outcome, checks: tuple[ProvenanceCheck, ...])
ProvenanceCheck(name, outcome, detail)
outcome ∈ {PASS, FAIL, INCONCLUSIVE}
```

Nine structural checks: `content_hash` (recomputed from stored
bytes), `artifact_id` (recomputed basis), `artifact_type`
(closed vocabulary), `test_plan_id` (shape), `hypothesis_id` /
`match_id` / `snapshot_hash` (PASS if well-formed,
INCONCLUSIVE if absent, FAIL if malformed), schema version,
validation state. Overall: FAIL if any check fails, else
INCONCLUSIVE if any check is inconclusive, else PASS. Pure
function of the stored object. No `CONFIRMED` / `VULNERABLE` /
`NOT_VULNERABLE` / `SAFE` exists anywhere in this module.

## 6. Integrity sweep API

```python
verify_all(store) -> IntegritySweepReport
IntegritySweepReport(total_records, valid_records, corrupt_records,
                     orphan_records, failures: tuple[IntegrityFailure, ...])
IntegrityFailure(kind, subject, detail)
```

Procedure (all enumeration sorted; failure order is
(kind, subject)): load index (missing index = empty store, per
store semantics) → flag duplicate content-hash bindings →
`store.get()` per index entry (the store's own integrity checks,
verbatim) → classify each unindexed on-disk record via
`get_by_content_hash` (`missing an index entry` → orphan, any
other integrity error → corrupt) → flag non-record filenames
(including `*.tmp` leftovers — reported, never silently
skipped). Counts are recomputed from the explicit failure list
so arithmetic stays consistent. Nothing is repaired, deleted,
rewritten, or reattached — verified by file-hash snapshots.

## 7. Deterministic ordering rules

Every output is ordered by `artifact_id` (retrieval results,
sweep-valid iteration, `list()` passthrough); index keys are
iterated sorted; record filenames are iterated sorted; failures
sort by (kind, subject). No filesystem enumeration order,
insertion order, timestamp, PID, or thread scheduling leaks
into any result (proven by repeated-call equality tests).

## 8. Corruption behavior

Every corruption class is represented explicitly as an
`IntegrityFailure` (sweep) or a propagating `ArtifactStoreError`
(retrieval): malformed records, missing records, index/record
disagreement, unknown index artifact types, record and
reference schema-version mismatches, content-hash mismatches,
artifact-id mismatches, binding mismatches, duplicate
bindings, unexpected files, and unreadable indexes. Filesystem
names are never trusted over record contents; index metadata is
never trusted over record contents (cross-checked both ways).

## 9. Orphan detection behavior

"Orphan" = a well-formed content-addressed record file present
on disk but unreferenced by the valid index (including the
index-unreadable case, where reference status is explicitly
marked unknown). Orphans are reported with subject =
content-hash and are never reattached, repaired, or deleted
(re-attachment would be a write and a binding decision — both
out of scope).

## 10. Security / import boundaries

The module imports only `json`/`re`, `dataclasses`, the store's
read API, and Phase 4C hash/identity helpers. AST tests prove
the absence of: network (Y), subprocess (Z), LLM/model/prompt
(AA), database (AB), verifier/executor/browser/scheduler/queue/
scope-policy/finding imports (AC–AE), runtime invocation calls
and any `open()` usage (X), scope-authority identifiers (AD),
finding creation (AE), and any mutation API or write
primitives — `put/delete/remove/update/write/save/repair/
reattach/prune`, `mkdir/unlink/os.replace/os.rename/
write_text/.put(` (AF). Artifact bytes are returned untransformed
and never executed.

## 11. Adversarial test matrix (A–AR, 45 tests)

| ID | Coverage | Result |
|----|----------|--------|
| A | retrieval by TestPlan ID (exact refs + bytes) | ✅ |
| B | retrieval by Hypothesis ID | ✅ |
| C | retrieval by Match ID | ✅ |
| D | retrieval by Snapshot hash | ✅ |
| E | combined binding filters | ✅ |
| F | artifact-type filtering (+ unknown rejected) | ✅ |
| G | deterministic ordering | ✅ |
| H | duplicate-free results | ✅ |
| I | missing binding → empty tuple | ✅ |
| J | malformed binding rejected (incl. no-filter, non-store) | ✅ |
| K | corrupted record surfaced as corruption | ✅ |
| L | corrupted index surfaced as corruption | ✅ |
| M | orphan record detected, not reattached/deleted | ✅ |
| N | unrelated artifact never appears | ✅ |
| O | cross-program identity isolation | ✅ |
| P | provenance audit PASS | ✅ |
| Q | provenance audit FAIL (bytes + identity forgery) | ✅ |
| R | audit never emits vulnerability verdicts | ✅ |
| S | sweep detects all corrupted records (3/3 named) | ✅ |
| T | sweep never mutates files (hash snapshot) | ✅ |
| U | sweep never deletes files | ✅ |
| V | repeated sweep identical | ✅ |
| W | exact stored bytes, all three types | ✅ |
| X | never executes content (AST + no `open`) | ✅ |
| Y–AF | import/mutation/scope/finding boundaries | ✅ |
| AG | enumeration order cannot change output | ✅ |
| AH | index/record disagreement surfaced | ✅ |
| AI | missing record surfaced | ✅ |
| AJ | malformed record surfaced | ✅ |
| AK | unknown artifact type surfaced | ✅ |
| AL | schema-version mismatch surfaced | ✅ |
| AM | content-hash mismatch surfaced | ✅ |
| AN | artifact-id mismatch surfaced | ✅ |
| AO | binding mismatch surfaced | ✅ |
| AP | snapshot-bound artifacts distinguishable | ✅ |
| AQ | multiple artifacts per TestPlan all returned (3/3) | ✅ |
| AR | same-bytes/different-plan follows store identity (re-bind rejected; single stored identity surfaced) | ✅ |

AR interpretation note: the Phase 4D store forbids binding
identical bytes to a second plan, so two live records can never
share content bytes; the test proves the store invariant holds
(re-bind raises `ArtifactIdentityConflictError`) and retrieval
surfaces exactly the one stored identity per plan.

## 12. Exact test results

- `python3 -m unittest ai.test_artifact_retrieval` → **45 tests, OK**
- `ai.test_artifact_store ai.test_artifact
  ai.test_hypothesis_testplan ai.test_research_pattern
  ai.test_pattern_projector ai.test_pattern_store
  ai.test_target_intelligence ai.test_target_matcher
  ai.test_hypothesis_engine ai.test_test_plan_builder` →
  **576 tests, OK**
- `ai.test_ingestion_schema ai.test_ingestion_grounding
  ai.test_knowledge_store ai.test_knowledge_ingestion` →
  **132 tests, OK**
- `ai.test_openrouter ai.test_xss_researcher
  ai.test_xss_llm_researcher ai.test_xss_verification
  ai.test_xss_oracle` → **265 tests, OK**
- `python3 -m compileall -q ai` → **OK**

## 13. Limitations

1. Retrieval propagates store corruption fail-closed: one corrupt
   record fails a whole filtered query until the sweep flags it.
   This is intentional (never silently skip), but operators must
   consult `verify_all` output when retrieval raises.
2. `get_by_binding` evaluates filters over `store.list()`, i.e.
   O(n) full validation per query — fine for audit-scale stores,
   not indexed for large-scale serving (no secondary index was
   added, per immutability constraints).
3. The specificity (H1) gate is not re-proven by audit/sweep
   (needs caller fixtures; proven at VALID-mint time and
   enforced by the store on write).
4. Audit-only `metadata` mutations that remain schema-valid are
   not cryptographically detectable (metadata is excluded from
   identity by Phase 4C design).
5. No pagination, no full-text search, no secondary indexes —
   deliberate; this layer is audit/query over authoritative
   bindings only.

## 14. Explicit Git no-op confirmation

**No Git command was executed in this phase.** No `git status`,
`diff`, `add`, `commit`, `checkout`, `switch`, `restore`,
`reset`, `merge`, `branch`, `stash`, or any other Git operation
was run. No unrelated working-tree files were inspected,
staged, modified, or cleaned. Two new files were created; zero
existing files were modified.

## 15. Recommended next safe phase

A **deterministic TestPlan→artifact readiness report** phase:
given a TestPlan, report which artifact types exist, which
bindings are covered, and which integrity checks pass — still
read-only, still no generation or execution. Any executor
integration (Nuclei/XSS/HTTP runtimes, verifiers, schedulers,
finding creation) must remain a separate later phase behind its
own explicit authorization boundary, consuming only
sweep-clean, audit-PASS artifacts.
