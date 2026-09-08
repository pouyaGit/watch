# Pattern Store (Phase 2C) — Implementation Report

## 1. Verdict

**IMPLEMENTED**

A file-backed, lifecycle-aware Pattern Store for the Phase 2A
contracts is implemented in one new module, proven by 52 focused
tests, with every required regression suite passing unchanged and
zero existing files modified.

## 2. Repository Storage Findings

The authoritative persistence architecture is
`ai/knowledge/store.py::KnowledgeStore`:

- **Backend:** file-backed JSON, no MongoDB. Default root
  `ai_data/knowledge` (sibling `ai_data/nuclei` confirms the
  `ai_data/<subsystem>` layout convention). Documents live as
  `<content-hash>.json` under `documents/`; a sorted `index.json`
  (`{"documents": {hash: {"knowledge_id", "path"}}, "version": 1}`)
  is the lookup structure.
- **Identity:** full SHA-256 content hashes are canonical;
  `kb-…` is a short alias. Claim/source ids (`clm-…`, `src-…`)
  are SHA-256-derived the same way.
- **Atomicity:** temp file + atomic rename (`_write_json_atomic`);
  no locking anywhere in the class.
- **Integrity:** every read re-validates (`content_hash` ↔ bytes ↔
  filename ↔ `knowledge_id` ↔ index entry, aggregate recompute);
  failures raise `KnowledgeStoreIntegrityError(ValueError)`.
  Corruption is never repaired.
- **Retrieval:** `get_by_hash` / `get_by_id` (None when unknown),
  `retrieve(...)` scans all records and returns matches ordered by
  id — O(N) scans are the accepted house pattern.
- **Deduplication:** identical content converges on one record
  (re-ingest merges provenance, first metadata wins).

The reports were not followed blindly: the architecture report's
"pattern store" was design prose with no code behind it, so every
behavior below was derived from the two authorities that do exist —
`ai/schemas/research_pattern.py` (identity + lifecycle semantics)
and `ai/knowledge/store.py` (persistence mechanics).

## 3. Storage Design

New module `ai/knowledge/pattern_store.py` (`PatternStore`,
default root `ai_data/patterns`), placed beside `KnowledgeStore`
because it reuses that storage shape without touching its behavior:

```
ai_data/patterns/
  index.json                  # {"patterns": {pattern_id: entry}, "version": 1}, keys sorted
  records/<idempotency_key>.json
```

Index entries carry exactly
`{pattern_type, idempotency_key, semantic_key, path}` where `path`
is always `records/<idempotency_key>.json`. Records are keyed by
the full 64-hex `idempotency_key` (the content-addressed key, as
document hashes are for KnowledgeStore); the index is keyed by
`pattern_id` (the short alias). Filenames and index keys derive
ONLY from regex-validated keys (`^[0-9a-f]{64}$`,
`^vp-|ap-[0-9a-f]{16}$`); no pattern field ever influences a path.

Public API (typed in/out, no raw dicts):

- `put(pattern) -> PutResult(pattern, created)` — idempotent write.
- `get(pattern_id) -> Pattern | None` — None when unknown.
- `get_by_idempotency_key(key) -> Pattern | None` — exact
  provenance-bound identity.
- `get_by_semantic_key(key) -> list[Pattern]` — all provenance
  variants, ordered by `pattern_id`.
- `list(*, pattern_type, status, semantic_key)` — research-side
  filters only, ordered by `pattern_id`.
- `transition(pattern_id, *, status, supersedes, retirement_reason)`
  — allowlisted lifecycle moves.

There is intentionally no `delete`: history stays auditable;
obsolescence is expressed via `SUPERSEDED`/`RETIRED`. Errors are a
small `ValueError`-rooted hierarchy matching the
`KnowledgeStoreIntegrityError` precedent: `PatternStoreError`
(base), `PatternIdentityConflictError`, `PatternNotFoundError`,
`PatternCorruptError`, `InvalidPatternTransitionError`
(`TypeError` for non-pattern `put` input, mirroring the
projector's input-boundary convention).

## 4. Serialization

One record file is a strict three-key envelope —
`{"pattern": <model_dump(mode="json")>, "pattern_type":
"vulnerability" | "attack", "schema_version":
"vulnerability_pattern/v1" | "attack_pattern/v1"}` — written with
`json.dumps(sort_keys=True, indent=2) + "\n"` (the KnowledgeStore
byte convention). The string-literal `pattern_type` discriminator
reconstructs the exact model without relying on Python class
names; envelope and inner `schema_version` must both match the
discriminator's contract version. JSON only — the module contains
no `pickle`/`marshal` import or call (asserted by source scan) and
stored bytes parse with plain `json.loads`. Serialization is
deterministic: the same factory-built pattern persisted into two
fresh stores yields byte-identical record files (tested).

## 5. Identity

Phase 2A semantics are preserved exactly and never redefined
(`semantic_key` = provenance-free basis, `idempotency_key` =
semantic + sorted provenance, `pattern_id` = `vp-`/`ap-` alias).
Defense in depth on every write, trusting no caller input:

1. `put` accepts only `VulnerabilityPattern`/`AttackPattern`
   instances (`TypeError` otherwise — arbitrary `BaseModel`
   subclasses and raw dicts are refused).
2. Nested submodels must be genuine validated instances
   (`VulnerabilityFacts`/`AttackFacts`, `ResearchProvenance`,
   `ModelInterpretation`), closing the `model_construct`-from-dump
   facsimile path whose nested dicts and silently-dropped smuggled
   extras would otherwise launder through re-serialization.
3. The pattern is re-parsed via `model_validate`, which re-runs
   the contract's own semantic/idempotency recomputation
   validators — tampered `pattern_id`/`semantic_key`/
   `idempotency_key` all fail here (each proven by test).
4. The `pattern_id` alias is recomputed again via the public
   `vulnerability_pattern_id_from_key` /
   `attack_pattern_id_from_key` factories, and the `vp-`/`ap-`
   prefix is checked against the concrete model type, so one type
   can never masquerade as the other.

Every read repeats the same verification (contract validation +
filename ↔ `idempotency_key` ↔ index-entry ↔ `semantic_key` +
prefix/type consistency), so tampering at rest fails closed too.

## 6. Idempotency and Conflicts

- **Same `pattern_id` + identical content:** idempotent success.
  Repeat `put` returns the stored record with `created=False`
  (tested, including byte-equality of the returned pattern).
- **Same `pattern_id` + different `idempotency_key`:**
  `PatternIdentityConflictError`; stored provenance is never
  overwritten (tested via a reseeded index entry, since two valid
  patterns cannot otherwise share an id — the alias derives from
  the key).
- **Identity-equal repeats differing only in identity-excluded
  prose/metadata** (e.g. `created_at`, `title`): converge on the
  first stored bytes; later variants are ignored, never merged
  (tested implicitly by double-put equality; `created_at` is
  schema-default audit metadata outside identity by Phase 2A
  design).
- **Same `semantic_key` + different provenance:** distinct
  `pattern_id`s, distinct records, each retaining its own full
  provenance. No overwrite, no silent merge (tested: sibling
  record byte-identical after a variant `put`).

## 7. Semantic Lookup / Merge

No merge on write — merging is the projector's job
(`project_claims` already unions provenance); the store groups.
`get_by_semantic_key` returns every record sharing exactly the
deterministic Phase 2A `semantic_key`, ordered by `pattern_id`.
No fuzzy matching, no string similarity, no title/description
comparison, no LLM — semantic equality IS key equality (a
two-variant convergence test proves grouping, per-record
provenance preservation, and deterministic ordering). Semantic
scan is O(N) over the sorted index, the same tradeoff
`KnowledgeStore.retrieve` makes; documented rather than indexed,
per the no-premature-indexing rule.

## 8. Lifecycle

Exactly the Phase 2A statuses `ACTIVE` / `SUPERSEDED` / `RETIRED`
— no `CONFIRMED`, `VERIFIED`, `NOT_VULNERABLE`, `EXPLOITED`, or
`SAFE` exists anywhere (invalid statuses raise
`InvalidPatternTransitionError`, each proven by test). Transition
allowlist, enforced before persistence on top of the schema's own
precondition checks:

- `ACTIVE → SUPERSEDED` (requires same-type `supersedes`;
  cross-type ids rejected by the contract's `vp-`/`ap-` regexes,
  double-checked by the store),
- `ACTIVE → RETIRED`, `SUPERSEDED → RETIRED` (require
  non-blank `retirement_reason`),
- same-status calls are idempotent no-ops,
- `RETIRED` is terminal; all other moves raise.

Supersede integrity: target must exist (`PatternNotFoundError`
otherwise), self-supersede rejected, cycles rejected by walking
the `supersedes` chain with a bounded iteration cap (A→B then B→A
proven rejected). Transitions rewrite only lifecycle fields of
the same identity-bound record file (identity keys provably
unchanged after transition); superseded/retired records stay in
the store with facts and provenance intact. `RETIRED` means
"research became obsolete" — the docstrings and report state
explicitly it is never a target-safety verdict.

## 9. Atomicity / Concurrency

Atomicity reuses the KnowledgeStore temp-file + rename primitive
with one hardening fix discovered by test: the shared
`<name>.json.tmp` temp name races when two threads write
concurrently (`FileNotFoundError` on replace). The store uses
per-write unique temp names (pid + thread ident + counter), so
concurrent identical writers both complete their atomic renames
and readers only ever see whole records (proven by an 8-thread
identical-`put` test converging on one record). Crash windows
match KnowledgeStore semantics: record-before-index ordering
means a crash leaves at most an orphan record file (adopted
harmlessly by the next identical `put`) — never a half-visible
record, and post-operation scans assert no `*.tmp` residue.
Limitation (shared with KnowledgeStore, documented): the index
read-modify-write is not locked, so two *distinct* patterns
written at the exact same instant could drop one index entry;
callers needing that guarantee must serialize distinct puts.
Identical concurrent puts always converge.

## 10. Corruption Handling

Assume the disk is hostile. Every read path fails closed with
`PatternCorruptError` — never partial data, never silent repair
(re-reads stay corrupt, proven by test): malformed JSON, malformed
envelope, unknown `pattern_type`, unsupported `schema_version`,
contract validation failure (tampered facts, emptied `claim_ids`,
bad provenance), identity/filename/index mismatch, type
masquerade (`vp-` record under the `attack` discriminator),
missing record file, malformed index. Forbidden smuggled fields
(`scope_allowed`, `command`, `verdict: CONFIRMED`, …) are rejected
by the contracts' `extra="forbid"` during record validation
(proven). A missing index entry for an existing file (crash
orphan) is re-adopted only through the validated `put` path, not
by repair logic.

## 11. Security Boundary

Proven by architecture and tests:

- **No LLM** — no provider/client/completion symbol in the module.
- **No network** — no `requests`/`urllib`/`httpx`/`socket`
  symbol; `put`/`get`/`list`/semantic lookup all run with
  `socket.socket` disabled (test).
- **No subprocess/execution** — no `subprocess`/`eval`/`exec`;
  record content is inert JSON data, never interpreted.
- **No scope authority** — no `scope_allowed`/`allow_scope`
  storage semantics; smuggled scope keys fail validation.
- **No target authority** — no `target`/`target_affected`/
  `scope`/`match_score`/`execution_allowed` semantics; `list()`
  exposes only type/status/semantic-key filters.
- **No finding/verdict authority** — no `confirmed`/`verified`/
  `evidence`/`finding_status` logic; lifecycle cannot express a
  verdict (exhaustively asserted over serialized stored patterns).
- **Path safety** — traversal (`../`), absolute, separator, and
  null-byte ids are rejected before touching the filesystem
  (failed lookups leave the tree byte-identical, tested);
  hostile `title`/`description`/product strings persist as data
  while record filenames remain `<64-hex>.json` only (tested).

## 12. Tests

Exact commands and results (from `/opt/watch`):

```
python3 -m unittest ai.test_pattern_store
  Ran 52 tests in 0.293s — OK

python3 -m unittest ai.test_research_pattern
  Ran 54 tests — OK            (Phase 2A unchanged)

python3 -m unittest ai.test_hypothesis_testplan
  Ran 47 tests — OK            (Phase 1 unchanged)

python3 -m unittest ai.test_pattern_projector
  Ran 54 tests — OK            (Phase 2B unchanged)

python3 -m unittest ai.test_ingestion_schema ai.test_ingestion_grounding \
  ai.test_knowledge_store ai.test_knowledge_ingestion
  Ran 132 tests — OK           (grounding/knowledge boundary unchanged)

python3 -m unittest ai.test_openrouter ai.test_xss_researcher \
  ai.test_xss_llm_researcher ai.test_xss_orchestrator \
  ai.test_xss_verification ai.test_xss_oracle
  Ran 294 tests — OK           (provider/XSS stack unchanged)

python3 -m compileall -q ai   (clean)
```

The 52 new tests map to the required matrix: basic storage 1–7,
identity 8–14 (conflict via reseeded index; all three tamper
vectors), semantic convergence 15–18, lifecycle 19–28 (incl.
cross-type supersede, reason enforcement, terminal RETIRED,
filter validation), corruption 29–35 (incl. masquerade and
no-repair), persistence 36–40 (restart, byte-identical
serialization, JSON-only, no temp residue, 8-thread convergence),
security 41–49 (symbol scan, network-disabled ops, traversal,
field-as-path, malicious-record rejection, foreign-authority
scan), plus the `GroundedClaim → project_claim → put → get`
round-trip integration test (no network/LLM/MongoDB/subprocess).

## 13. Files Changed

| File | Action | Why |
|---|---|---|
| `ai/knowledge/pattern_store.py` | CREATED (~700 lines) | `PatternStore` (put/get/lookups/list/transition), error hierarchy, atomic-write + identity + lifecycle logic |
| `ai/test_pattern_store.py` | CREATED (52 tests) | Full §12 matrix incl. integration test |
| `agent-reports/pattern-store-implementation.md` | CREATED | This report |

No existing file was created, modified, or renamed. No Git
operation was performed.

## 14. Compatibility

Purely additive: the store consumes Phase 2A contracts, factories,
and identity functions as-is (one deliberate non-import: the
private `_idempotency_key_from_semantic` is never touched —
revalidation goes through public model validation plus the public
`*_id_from_key` factories). The projector is unmodified and its
54 tests pass unchanged, confirming Phase 2B → 2C compatibility
alongside the explicit integration test. `KnowledgeStore`,
ingestion, provider, and XSS suites pass unmodified; `compileall`
is clean. The pre-existing `crawl/watch_param_discovery.py`
working-tree state was not touched or evaluated (out of scope).

## 15. Limitations

1. Semantic/provenance scans are O(N) over the sorted index
   (house pattern, shared with `KnowledgeStore.retrieve`);
   fine at research-pattern volumes, revisit only with evidence.
2. No locking on the index read-modify-write: identical
   concurrent writes converge, but two *distinct* patterns raced
   in the same instant could drop an index entry — callers must
   serialize distinct puts if that window matters.
3. Crash-orphaned record files are adopted only via a later
   validated `put`, never by background repair (repair is a
   future explicit phase).
4. Identity-equal repeats keep the first stored
   identity-excluded prose/metadata; the store never reconciles
   divergent `title`/`description`/`interpretation` across
   provenance variants (that is projector/merge policy, not
   storage policy).
5. `transition` returns the re-validated record but does not
   append a history log; prior lifecycle states are not retained
   beyond the supersession chain (`supersedes` links).

## 16. Recommended Next Step

The smallest safe next phase is **read-only Target Intelligence
projection** over the recon inventory (`Http`/`Endpoints`/`Urls`:
technology + version + endpoint snapshot, no AI, no execution),
which gives the future deterministic matcher something to join
patterns against without granting any new authority. Store-side,
nothing blocks it: `get_by_semantic_key`/`list` already expose
everything a matcher needs to consume patterns. Do not build the
matcher, hypothesis engine, or any fetching/scheduling until that
read-only projection exists and is covered by fixture tests.

---

*Phase 2C ends at VulnerabilityPattern / AttackPattern → Pattern
Store. No Git operations were performed; the index is untouched.
Report created at
`/opt/watch/agent-reports/pattern-store-implementation.md`.*
