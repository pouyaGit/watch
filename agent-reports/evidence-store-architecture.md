# Phase 5H — Evidence Store Architecture (READ-ONLY)

## 1. Verdict

**VERDICT: ARCHITECTURE SUFFICIENT TO UNBLOCK 5H DETAILED DESIGN —
NO IMPLEMENTATION AUTHORIZED BY THIS DOCUMENT.** The production-grade
Evidence Store layer is designed below as a strictly observation-only,
immutable, content-addressed store over the frozen 5H-core contracts.
It persists sealed `EvidenceRecord` objects, preserves immutability
and content-addressed identity, supports retrieval/indexing, crash
recovery, orphan sweep, audit integrity, idempotent race-safe writes,
cross-worker concurrency, future MongoDB adapters, and 5E/5F/5G
observations (including `BrowserObservation`). It NEVER decides
vulnerability, severity, findings, or exploitability — 5I owns
classification. B2 and B5 remain BLOCKED. No code, tests, MongoDB,
network, DNS, subprocess, browser, Nuclei, JS, LLM, or Git activity
was performed or is authorized by this report.

## 2. Current 5H-core state

Existing, frozen, inspected read-only (no modifications):

- `ai/schemas/evidence.py` (`SCHEMA_VERSION = "evidence/v1"`):
  `EvidenceRecord` (lifecycle `BUILDING | SEALED | INCOMPLETE`;
  `ORPHANED` explicitly NOT an evidence-byte state), `HttpObservation`,
  `NucleiObservation`, `BrowserObservation` (bounded marker-hash
  tuples ≤16, `e1/e2/e3_observed` advisory booleans only,
  `executed_payload_hash`, redacted `page_url`, `storage_keys_hash`,
  `channels_truncated`), `TargetIdentity`, snapshot/derivation/template
  bindings, `FORBIDDEN_EVIDENCE_FIELDS` (verdict/finding/matched/
  vulnerable/confirmed/severity/…), `extra="forbid"` everywhere, random
  `ev-…`/`ex-…` handles via `secrets` (uniqueness only).
- `ai/evidence/builder.py`: one-way `EvidenceBuilder`
  (`begin → attach_http/attach_nuclei/attach_browser → seal |
  seal_partial`); single-use (post-seal calls raise
  `EVIDENCE_IMMUTABLE`); no `reassign/rebind/repair/reattach/
  supersede/patch/append` API (test-asserted absent). Frozen triple
  identity: `bindings_hash` (binding fields, `evidence_id` excluded),
  `observations_hash` (transport facts + content hashes, raw samples
  excluded), `content_hash` (bounded persisted samples only).
  `REQUIRED_OBSERVATIONS` maps each execution class to its completing
  channel (`browser_verification → ("browser",)`).
- `ai/evidence/hashing.py`: SHA-256 only; canonical JSON
  (`sort_keys=True`, `separators=(",",":")`, `ensure_ascii=False`,
  UTF-8); `normalize_for_hash` (absent==null, newline normalization,
  no float/bytes/set leaves); `AUDIT_ONLY_KEYS` refused inside hash
  payloads (timestamps can never fork identity — double protection
  with the payload builders).
- `ai/evidence/observations.py`: URL/header/body observation policy
  (redirect chain 5 + overflow flag; headers 32/128/1KiB/8KiB total;
  request 16KiB transport / 2KiB sample; response 512KiB transport /
  8KiB sample / 2MiB decompressed / 10x ratio; binary hash-only;
  request/response header allowlists; no `fetch(redacted_url)` API by
  design).
- `ai/evidence/scrubber.py`: single shared redactor (secret header
  values → `[REDACTED]`, secret query/form values → `[REDACTED]`,
  userinfo stripped, free-text secret shapes → `[REDACTED]`,
  `sanitized_reason` closed codes, `contains_secret_shape` screen).
- `ai/execution/ledger.py` (`InMemoryExecutionLedger`): CAS-versioned
  lifecycle `REGISTERED → STARTED → SEALED_REF | INCOMPLETE_REF |
  UNKNOWN`; one row per `(authorization_id, execution_stage)`
  (second registration → `EXECUTION_REPLAY`); idempotency-key dedupe
  (`EXECUTION_DUPLICATE`); live-row re-entry → `EXECUTION_IN_PROGRESS`;
  single-process only (cross-process uniqueness explicitly requires
  the production adapter).
- `ai/audit/trail.py`: append-only `AuditRecord` per transition
  (`AUTHORIZATION → EXECUTION_STARTED → EXECUTION_STAGE →
  EVIDENCE_SEALED → EXECUTION_TERMINAL → VERIFIER_HANDOFF`, plus
  `AUDIT_GAP`/`ORPHAN_REINDEXED` siblings); hashes+codes only, never
  secrets/raw bodies; pre-start audit failure blocks execution,
  post-start failure emits a separate `AUDIT_GAP` (never mutates
  sealed evidence).
- `ai/evidence/orphan.py`: pure `classify_orphan`
  (`INDEX_MISSING_SEALED | INDEX_MISSING_INCOMPLETE | BYTES_MISSING |
  BINDING_AMBIGUOUS`) + `validate_reindex` (recompute all three
  hashes, claimed keys must equal sealed bindings byte-identically,
  only `SEALED`/`INCOMPLETE` re-indexable; never mints identity,
  never changes bindings, never writes bytes).
- `ai/evidence/handoff.py`: `assemble_handoff` (only `SEALED` +
  `complete` + hash-valid records; `INCOMPLETE` → `HANDOFF_REJECTED`
  as data-state, not classification) + `bind_provenance` +
  `verify_provenance_for_handoff` (`AUTHZ_VALID_FOR_PROVENANCE` for
  legitimately `CONSUMED` provenance; `CONSUMED` ≠ permission to
  re-execute — the ledger owns replay). `EvidenceHandoff` is a
  reference (ids + hashes), never content, never verdict.
- `ai/limits/ceilings.py`: frozen `CEILINGS` (http/nuclei/browser wall
  times, connect/read/stall timeouts, body/transport/sample/
  decompressed sizes, compression ratio 10, redirect_hops 5,
  requests_per_execution 7, dns_answers 8, browser_pages/contexts 1,
  nuclei concurrency/rate/retries, output/temp/memory/CPU caps,
  pending_authorizations 1000); tighten-only (`LIMIT_EXCEEDED` above
  ceiling, `LIMIT_UNKNOWN` for unknown/unbounded/non-numeric),
  boot-asserted via `validate_config`.
- Executors 5E/5F/5G (inspected): sealed records already flow through
  `EvidenceBuilder.begin/attach_*/seal(/seal_partial)` with
  scrub-before-hash; 5G records `BROWSER_EVENT_BOUNDS` v1 test-only
  bounds (`dialog_events 8`, `frame_events 4`, `popup_events 0`,
  `console_entries 32`, `oracle_events 16`,
  `dom_observation_bytes 8192`, `storage_keys 16`) pending a 5H
  ceiling extension.

## 3. Security invariants

Frozen (non-negotiable, test-gated):

1. The store holds facts, never classifications. No field, index,
   API, or document in 5H may carry `CONFIRMED / VULNERABLE /
   NOT_VULNERABLE / severity / finding / exploitability`. 5I owns
   deterministic classification; 5H sits semantically below it.
2. Sealed bytes are immutable. No UPDATE semantics for sealed
   evidence (see §4). Correction = new record linked to the prior
   record, never mutation.
3. Content identity is deterministic (SHA-256 over canonical JSON,
   §5). Handles (`evidence_id`, `execution_id`) are random and carry
   no meaning.
4. Timestamps/audit metadata never enter hashes. Scrub-before-hash
   everywhere applicable (§13).
5. `complete=true` means "required observations present and hashes
   verify" — NOT vulnerable / NOT not-vulnerable.
6. `INCOMPLETE` / `OUTCOME_UNKNOWN` / `ORPHANED` / `CORRUPT` /
   `AUDIT_GAP` are never security-positive and never
   verifier-consumable as positives (§15, §19).
7. Caller never selects storage keys (§5). Writer cannot alter sealed
   bytes; verifier cannot mutate; sweeper cannot modify contents;
   operator deletion requires explicit policy (§16, §18).
8. OOB remains DENIED end-to-end (no callback-shaped fields stored,
   hashed, or indexed).

## 4. Evidence lifecycle

Normative states (evidence bytes vs. index explicitly separated):

- `BUILDING` (worker-local builder only; never handed off, never
  indexed, never queryable as evidence).
- `SEALED` (builder spent; triple hashes computed; bytes frozen).
  Terminal for bytes.
- `INCOMPLETE` (sealed partial: `seal_partial` with closed reasons
  such as `channels_partial`, `body_over_cap`, `chain_over_cap`).
  Terminal for bytes; handoff only where 5I's contract explicitly
  permits incomplete channels (default: refused).
- Index representation layered on top: `INDEXED` (durable bytes +
  verified index entry), `ORPHANED` (index-state only: bytes without
  index, index without bytes, or hash mismatch — see §10). `ORPHANED`
  never mutates bytes.

Allowed transitions:

- `BUILDING → SEALED` (all required observations present, bindings
  valid, hashes computed).
- `BUILDING → INCOMPLETE` (bounded partial; closed reason recorded).
- `SEALED → INDEXED` (durable write + hash re-verification + atomic
  index insert; §9).
- `INCOMPLETE → INDEXED` (same durability path; flagged partial).
- Failure paths: `BUILDING → ORPHANED` (abandoned builder; index/
  audit annotation only, no bytes to preserve beyond the worker's
  scratch); `SEALED (not yet INDEXED) → ORPHANED` (crash between seal
  and index; recoverable via re-index of byte-identical bytes, §10);
  `INDEXED → CORRUPT` (detected hash mismatch on read; quarantine,
  never silent repair); `* → AUDIT_GAP` (post-start audit failure
  annotated alongside, never as evidence mutation).

Ordering invariant: SEALED bytes must be durable BEFORE the record
becomes INDEXED. An index entry pointing to missing/corrupt bytes is
never valid (read path re-verifies before serving; §9, §11).

## 5. Content-addressed identity

- `evidence_id`: random `ev-<32hex>` handle (uniqueness only).
  Primary lookup key for operators/APIs, NOT content identity.
- Content identity: frozen triple (`bindings_hash`,
  `observations_hash`, `content_hash`), each SHA-256 over its frozen
  field list via `hash_payload` (canonical JSON). Field lists remain
  frozen; any extension requires a schema-version bump (see §12, §20).
- Canonical serialization: the single shared path
  (`bindings_payload` / `observations_payload` / `content_payload` →
  `normalize_for_hash` → `canonical_json` → `sha256_hex`). No
  per-caller variants, no `repr()`, no floats, no timestamp leaves
  (refused by `AUDIT_ONLY_KEYS`).
- Storage key (production): deterministic and server-derived —
  `blobs/sha256/<content_hash>` for the canonical byte envelope
  (which embeds all three hashes), with the operator handle
  `ev/<evidence_id>` existing ONLY in the Mongo index, never as a
  blob name. Rationale: identical bytes deduplicate naturally;
  distinct executions never collide (bindings contain `execution_id`
  + `authorization_id`, so distinct executions hash distinctly);
  caller-selected keys are structurally impossible (key is a pure
  function of bytes the server sealed).
- Duplicate write behavior: byte-identical re-put is a no-op success
  (compare-and-keep; returns the existing handle mapping). Same
  `evidence_id` with differing bytes is rejected (`EVIDENCE_HASH_
  MISMATCH` / duplicate-key, never overwrite). Concurrent writers
  race safely on the unique index (§9).
- Atomicity: single-blob conditional put (if-absent); index insert in
  the same transaction boundary where supported, otherwise
  write-verify-index with idempotent re-index (§9).
- Corruption detection: every read re-parses the typed record and
  recomputes all three hashes (`verify_record`); mismatch →
  `CORRUPT` + quarantine (§11). Background sweep re-verifies a
  bounded sample plus every orphan candidate (§10).

## 6. Storage architecture recommendation

**Recommendation: (C) content-addressed blob store + MongoDB index.**

- Blobs: immutable CAS objects keyed by `content_hash`
  (`blobs/sha256/<content_hash>`). MVP may be a filesystem CAS
  directory with atomic `write-tmp + fsync + rename` and read-only
  permissions post-seal; production is an S3-compatible object store
  with object-lock / retention (compliance mode) and versioning
  suspended (versions would suggest mutability — keep exactly one
  immutable version per key).
- Index/state: MongoDB (`evidence_index`, `execution_ledger`,
  `audit_trail`, `sweep_state`; §7–§8). Mongo holds references +
  hashes + bindings + lifecycle, never the source of truth for bytes.
- Why not (A) MongoDB-only: 16MiB document limits, backup/restore
  coupling of bytes with mutable state, weaker immutability story
  (update API exists even when policy forbids it), costlier scans for
  sweep verification.
- Why not (B) filesystem-blobs-only: no cross-worker CAS, no
  transactional index, no queryability (by execution/authorization/
  program/host/artifact), orphan detection reduces to directory walks.
- Why not (D) alternatives (e.g. git, log-structured merge stores):
  git mints mutable refs and invites history rewriting; LSM extras
  add operational surface without improving the immutability or
  auditability posture.
- Security/correctness wins of (C): immutability (blob keys cannot be
  overwritten to new content without changing identity); atomicity
  (conditional put + transactional index); corruption (hash-keyed
  reads self-verify); backups (blob snapshots independent of index
  dumps; restore = re-verify + re-index); scale (blobs scale
  independently; index stays small); queryability (Mongo secondary
  indexes); orphan handling (set-diff of blob listing vs. index, §10);
  retention (index tombstones + blob GC only after grace + policy,
  §18); operational simplicity (two failure domains with a narrow
  contract between them).

## 7. MongoDB adapter design

(B2 remains BLOCKED — design only, no implementation.)

Collections (all `extra="forbid"`-shaped application models; Mongo
stores the same typed documents):

1. `evidence_index`: one document per `evidence_id`.
   Identity: `_id = evidence_id`. Unique indexes: `_id`;
   `(execution_id)` unique (one evidence per execution in `single`
   stage; multi-stage 5J reserves compound `(execution_id,
   execution_stage)` unique); `(authorization_id, execution_stage)`
   unique (mirrors ledger slot); secondary: `(program_name,
   target_host)`, `(artifact_id)`, `(content_hash)`, `(lifecycle,
   indexed_at)`. Immutable fields (application-enforced + role-
   enforced, §16): all binding fields, all three hashes,
   `content_hash` blob key, `sealed_at`. Mutable ONLY: `lifecycle`
   (`SEALED → INDEXED`), `indexed_at`, `quarantine` annotation,
   `tombstone` (retention only). State transitions via CAS on
   `record_version` (see §9).
2. `execution_ledger` (production counterpart of
   `InMemoryExecutionLedger`): `_id = execution_id`; unique
   `(authorization_id, execution_stage)`; unique `idempotency_key`;
   `record_version` CAS; transitions `REGISTERED → STARTED →
   SEALED_REF | INCOMPLETE_REF | UNKNOWN` via `findOneAndUpdate`
   with `record_version` guard (or multi-document transaction
   coupling ledger terminal + index insert, §9).
3. `audit_trail`: `_id = (execution_id, seq)` compound unique;
   append-only (insert-only role; no updates/deletes except
   retention-policy purge, §18); secondary `(authorization_id,
   seq)`, `(evidence_id)`.
4. `sweep_state`: `_id = sweep_epoch`; stores cursor, grace-period
   watermark, quarantine list, operator annotations. Single-writer
   (sweeper role) with CAS on `epoch_version`.

CAS semantics: every state change is `findOneAndUpdate({…, 
record_version: expected}, {$set: {…, record_version: expected+1}})`
and the loser re-reads (live row → poll; terminal row → no-op /
conflict, never overwrite). Seal+index coupling uses a Mongo
multi-document transaction where available (ledger terminal + index
insert + first audit entries atomically); where transactions are
unavailable, the order is strictly blobs → verify → index (idempotent
insert-if-absent) → ledger terminal → audit, with crash recovery via
re-index (§10, §19).

Retry behavior: idempotent retries only (same bytes, same keys);
exponential backoff with jitter on transient errors; duplicate-key
on re-insert is success (dedupe-on-read the winner), never an error
surfaced as failure. Write concern `majority`, read concern
`majority` (handoff reads `linearizable` where supported).
Consistency: index reads are monotonic per execution (ledger terminal
implies index present or recoverable orphan — never "valid but
missing").

No credentials, connection strings, hosts, or deployment topology are
specified (intentionally omitted).

## 8. Index design

`evidence_index` is the ONLY queryable evidence surface (blobs are
key-addressed, never scanned for semantics):

- Point lookup: `evidence_id → {blob_key=content_hash, triple hashes,
  bindings, lifecycle}`.
- Execution join: `execution_id → evidence_id` (via ledger
  `evidence_id` pointer + index unique `execution_id`).
- Operator queries: by `authorization_id`, `program_name +
  target_host`, `artifact_id`, `content_hash` (dedupe inspection),
  `lifecycle + indexed_at` (sweep cursors).
- The index stores hashes redundantly (denormalized from the blob
  envelope) so reads can reject without fetching bytes on key
  mismatch, then re-verify against bytes before serving.
- No full-text, no raw-sample, no secret-bearing secondary indexes.
  Samples never enter index keys.

## 9. Atomicity/concurrency model

Explicitly NOT the in-memory Pattern Store RMW race (read-modify-
write without a guard). All production mutations are conditional:

- Duplicate evidence submission (same bytes, same `evidence_id`):
  blob put-if-absent + index insert-if-absent → both succeed as
  no-ops; callers receive the winner. No version bump.
- Same evidence submitted by multiple workers: unique index decides
  exactly one winner; losers read the winner (dedupe-on-read).
- Same execution finishing twice: ledger slot unique
  `(authorization_id, execution_stage)` → second finish raises
  `EXECUTION_REPLAY`; no second evidence row is created.
- Worker crash after object write, before index write: bytes exist,
  index missing → `INDEX_MISSING_SEALED` orphan; sweep re-indexes
  byte-identical bytes under the ORIGINAL keys after full
  re-verification (§10). Never mints a new identity.
- Worker crash after index write, before ledger terminal: index
  present, ledger stale → recovery completes the ledger CAS from the
  index (forward-only), then audit annotation.
- Worker crash between seal and index: same as object-without-index
  (above). Seal itself is worker-local and never half-persisted
  (builder either seals in memory or it does not; only sealed bytes
  are ever written).
- Concurrent seal of the same execution: impossible to both win —
  builder instances are worker-local; the first durable seal + index
  wins; the second fails closed on the ledger slot.

## 10. Orphan detection/sweep

Seven normative cases:

1. Object exists, index missing → `INDEX_MISSING_SEALED` (or
   `_INCOMPLETE`): re-index after `validate_reindex` (recompute
   triple hashes, claimed keys == sealed bindings). Recoverable.
2. Index exists, object missing → `BYTES_MISSING`: quarantine the
   index entry (serve nothing), emit integrity-failure audit, page
   operator. Never synthesize bytes, never delete the index silently.
3. Index exists, hash mismatch (index hashes ≠ recomputed blob
   hashes) → `CORRUPT`: quarantine + integrity-failure audit; blob
   retained for forensics; index marked corrupt, never served.
4. `BUILDING` abandoned (worker death, no sealed bytes): index/audit
   annotation only (`ORPHANED` note with grace watermark); no bytes
   to recover; scratch GC after grace.
5. `SEALED` but not `INDEXED`: case-1 recovery path (re-index).
6. Audit missing (evidence indexed, terminal audit absent): emit
   `AUDIT_GAP` annotation; evidence remains servable (audit is
   accounting, not authority) but handoff carries the gap flag.
7. Ledger says `SEALED_REF` but evidence absent: treat as case 2
   (`BYTES_MISSING`) + ledger annotation; verifier handoff refused
   until recovery.

Sweep protocol: periodic epoch (cursor in `sweep_state`); set-diff
blob listing vs. index in bounded pages; grace period (default ≥24h
from `sealed_at` before any quarantine action, longer for
`INCOMPLETE`); quarantine (index flag + operator-visible list, bytes
preserved); re-index (original keys only, verified); corruption state
(terminal flag, bytes preserved, never served); operator visibility
(dedicated quarantine dashboard query + audit events per action);
audit trail (one `ORPHAN_REINDEXED` / integrity-failure record per
action, §17). Sweep MUST NOT silently delete evidence. Destructive
deletion requires a separate retention policy with explicit
authorization (§18).

## 11. Integrity/corruption model

- At-rest: blob key == `content_hash`; read path recomputes
  `content_hash` over stored bytes and all three record hashes via
  `verify_record` before serving or handing off.
- In-flight: writer computes hashes pre-put; post-put read-back
  verification before index insert (first writer; dedupe winners skip
  redundant verification but retain the stored verification flag).
- Mismatch handling: `CORRUPT` quarantine (index flag), bytes
  preserved, serve refused, handoff refused, integrity-failure audit,
  operator paging. Recovery is re-put of the ORIGINAL bytes from a
  verified backup followed by re-verification — never an in-place
  "fix".
- Stale index/ledger: resolved forward (re-index / complete ledger
  CAS), never by rolling back sealed state.

## 12. 5G browser ceiling extension

The seven 5G dimensions become first-class central limits WITHOUT
duplicating constants:

- Exact names (new keys in `CEILINGS`, pending values confirmed as
  the current v1 bounds): `browser_dialog_events = 8`,
  `browser_frame_events = 4`, `browser_popup_events = 0`,
  `browser_console_entries = 32`, `browser_oracle_events = 16`,
  `browser_dom_observation_bytes = 8192`, `browser_storage_keys = 16`.
- Schema location: `ai/limits/ceilings.py` `CEILINGS` (single source
  of truth). `BROWSER_EVENT_BOUNDS` in the 5G executor becomes a
  read-through alias removed in the same change that lands the
  central keys (one atomic commit; no dual-source window).
- Validation: `check_limit` / `validate_config` apply unchanged
  (tighten-only, boot-asserted). `BrowserObservation` marker-tuple
  caps (≤16) are cross-checked against the new ceiling keys at
  builder time (fail closed on divergence).
- Backward compatibility: existing sealed records (v1 bounds) remain
  valid — ceilings tighten future enforcement, never retroactively
  invalidate sealed bytes. `evidence_schema_version` stays
  `evidence/v1`; a future shape change (not this extension) would
  bump to `evidence/v2` with dual-read support.
- Serialization: ceilings never enter evidence hashes (they are
  policy, not content); the enforced values enter audit annotations
  only.
- Enforcement ownership: executors enforce at capture (5G runner
  fact processing); builder re-checks bounds at seal; store
  re-validates typed bounds on read (defense in depth, single
  constant source).
- Additional dimensions: none required now. If 5J introduces
  scheduling fan-out, candidates (`evidence_objects_per_sweep_page`,
  `handoff_batch`) must arrive as NEW ceiling keys through the same
  tighten-only process — never ad-hoc constants.

## 13. Scrubbing/secret handling

Scrub-before-hash is load-bearing (hashes cover redacted bytes, so
verifiers can recompute without ever seeing secrets). Secret
locations analyzed:

- Cookies / `Authorization` / API keys / bearer tokens / session IDs
  / CSRF tokens: NEVER persist (header allowlists exclude them;
  `scrub_headers` redacts any residual shape; `contains_secret_shape`
  screens error paths). May be counted (presence bit) but never
  stored or hashed in raw form.
- Query parameters / fragments / POST bodies: names may persist;
  secret-shaped VALUES redacted pre-hash (`scrub_query`,
  body-sample policy). Fragments never enter canonical URLs.
- Response headers / redirect `Location`s: allowlisted names only;
  values scrubbed; credential-bearing redirects rejected at the
  executor (never reach the store).
- Browser console / DOM / storage keys: console lines scrubbed and
  bounded (hashes of capped samples only); DOM marker observations
  are hashes, never raw markup; storage persists key-hashes only,
  values never.
- Oracle values (O): `executed_payload_hash` (hash) persists; raw
  oracle value never persists in evidence or index.
- Payloads (P): artifact `content_hash` persists; raw payload bytes
  live in the artifact store, not duplicated into evidence beyond
  bounded, scrubbed samples where the observation contract permits.
- Error messages: closed codes + bounded secret-screened suffixes
  only (`sanitized_reason`).

Four-way distinction (normative): MAY STORE (non-secret transport
facts, allowlisted headers, redacted samples); MUST HASH (content
identity of whatever is stored + hashes of non-stored binary/undecodable
content); MUST REDACT (any secret-shaped value before hashing);
MUST NEVER PERSIST (cookies, auth headers, raw tokens/keys, raw OOB
URLs, userinfo, raw bodies beyond sample caps). Existing scrubber
semantics are not weakened — extensions only add shapes, never remove
them.

## 14. Evidence binding

Every record is cryptographically/content-bound to all applicable
axes; the verifier re-checks each axis at handoff (§15):

- `execution_id`, `authorization_id` (ledger slot + index uniques).
- `program_name`, canonical `host`, `scheme`, `effective_port`,
  `path_scope` (`TargetIdentity`, verbatim copy of authorization
  values).
- `TargetResolution` identity (`canonical_target_hash`,
  `resolution_id`) and `ScopeEvaluation` identity
  (`evaluation_id`, `scope_lists_hash` via snapshot binding) —
  recorded in the record's snapshot/binding section.
- Artifact identity (`artifact_id`, `artifact_content_hash`,
  `test_plan_id`, `template_hash` where applicable).
- Payload identity where applicable (`artifact_content_hash` +
  channel hash, e.g. body hash for HTTP).
- Oracle identity where applicable (`executed_payload_hash =
  hash(oracle_value)` for 5G; raw oracle never stored).
- `execution_class` (`http_probe | http_verification | nuclei_scan |
  browser_verification`) gating `REQUIRED_OBSERVATIONS`.

Binding rules: values copied verbatim from the live authorization
(record, not caller claims); content hashes recomputed independently
at seal AND at every read; claimed index keys must equal sealed
embedded bindings byte-identically (`validate_reindex`); sealed
evidence can never be rebound (no API, no index mutation of binding
fields). Evidence is therefore non-transplantable: bytes moved to a
different execution/authorization/target fail hash + binding checks
and are refused (`EVIDENCE_BINDING_MISMATCH` / `HANDOFF_REJECTED`).

## 15. 5I handoff contract

5I receives `EvidenceHandoff` references + hashes only (never raw
bulk content beyond what the handoff explicitly embeds):

- Eligibility: `SEALED + INTEGRITY-VALID (triple hashes recompute) +
  COMPLETE (required channel present)` — or explicitly-supported
  `INCOMPLETE` channels ONLY where the 5I contract names them
  (default: `HANDOFF_REJECTED` for incomplete).
- Refused: `BUILDING`, missing, corrupt, hash-mismatched, unbound
  (binding re-check fails), unauthenticated provenance (issuance
  record absent/forged/revoked/expired-at-start/binding-mismatched),
  mutable (lifecycle not a sealed terminal).
- Provenance subtlety (frozen): legitimately `CONSUMED`
  authorizations REMAIN valid provenance
  (`AUTHZ_VALID_FOR_PROVENANCE`); `CONSUMED` grants no re-execution
  permission (ledger replay guard owns that).
- 5H never pre-classifies: handoff carries no verdict-shaped field
  (`extra="forbid"` + `FORBIDDEN_EVIDENCE_FIELDS` enforced at both
  layers).

## 16. Access control

Five separated roles (Mongo roles + application gates):

- Writer (executors): blob put-if-absent + index insert-if-absent +
  ledger CAS forward only. Cannot update/delete sealed blobs or
  sealed index bindings. No read of quarantine internals beyond own
  execution.
- Reader (operators/debuggers): read verified records by
  `evidence_id`/`execution_id`; receives redacted samples only; no
  write whatsoever.
- Verifier (5I): read-only handoff assembly input; receives immutable
  references; cannot mutate blobs, index, ledger, or audit.
- Sweeper: list blobs vs. index, set quarantine/re-index flags,
  write `sweep_state`, emit audit. Cannot modify blob contents or
  sealed bindings; re-index restores ORIGINAL keys only.
- Operator/admin: sole holder of retention-policy deletion
  capability (dual-control + explicit policy object + audit, §18);
  cannot mutate sealed bytes (deletion ≠ mutation: tombstone in the
  index, blob GC only after grace, audit preserved).

## 17. Audit model

Events (one append-only record each): `BUILDING` (executor-local
annotation, optional), `SEALED` (`EVIDENCE_SEALED` with triple
hashes), `INDEXED` (index insert + blob key), retrieval (reader/
verifier access with handle + hash, no content), integrity failure
(`CORRUPT`/`BYTES_MISSING`/mismatch with expected vs. actual hash
prefixes — never full secret-bearing bytes), orphan detection,
quarantine, sweep (epoch + action + keys), deletion (policy id +
authorization + tombstone), handoff (`VERIFIER_HANDOFF` with handoff
hashes). Audit records carry hashes + decisions + codes only.
Integrity: `(execution_id, seq)` unique, gap-detectable ordering via
`check_ordering`; `AUDIT_GAP` entries for post-start failures (never
silent success; pre-start audit failure blocks the dependent step).

## 18. Retention/privacy

- Retention hooks: per-program TTL + global default TTL on the index
  (`indexed_at + ttl → eligible`); quarantine TTL (shorter);
  audit TTL (longest — audit outlives evidence).
- TTL expiry → tombstone (index flag, serve refused, handoff
  refused), then blob GC only after a second grace window AND an
  explicit authorized sweep run. Two-phase, never single-step.
- Legal/operator deletion: named policy object (id + reason +
  scope predicate) + dual authorization + pre-deletion export-to-
  vault (where legally required) + `deletion` audit record. Bulk
  predicates are allowlisted (by program, by time range, by
  `evidence_id` list) — never free-form queries.
- Sensitive-data handling: redaction at capture means most PII never
  reaches the store; where a redaction gap is later found, the remedy
  is tombstone + GC of affected records (as deletion, §4) plus a
  scrubber-shape addition — never an in-place rewrite.
- Deletion ≠ mutation: tombstones and GC remove availability; they
  never alter the bytes or hashes of any surviving record, and the
  audit trail records the removal permanently.

## 19. Failure/crash model

| Failure | Classification | Handling |
|---|---|---|
| Object (blob) write failure | retryable (pre-seal-durable) | idempotent retry, same key; never index |
| Index write failure (post-blob) | `ORPHANED` (recoverable) | retry insert-if-absent; sweep re-index |
| Mongo transaction failure | retryable / `UNKNOWN` | retry on transient labels; on ambiguity resolve via re-read (ledger+index), never assume commit |
| Duplicate key (same keys+bytes) | success (dedupe) | return winner |
| Duplicate key (same keys, differing bytes) | `CORRUPT`-adjacent, fail closed | refuse, quarantine, operator page |
| Worker crash after object write | `ORPHANED` (`INDEX_MISSING_SEALED`) | sweep re-index (§10) |
| Worker crash after index write | ledger-stale, forward-fix | complete ledger CAS from index |
| Crash between seal and index | `ORPHANED` | re-index original keys |
| Process crash / power loss | per window above | same as crash windows; no partial blob ever indexed (read-back verify gates index) |
| Partial object | never durable | temp-key writes + read-back verify; partials GC'd from scratch |
| Corrupted object | `CORRUPT` | quarantine, refuse serve/handoff, preserve bytes |
| Stale index / stale ledger | forward recovery | re-index / complete CAS; never roll back sealed state |
| Audit failure pre-start | block | fail closed, no execution |
| Audit failure post-start | `AUDIT_GAP` | annotate alongside; evidence unaffected |
| Orphan sweep failure | retryable, epoch-scoped | cursor retained; next epoch resumes; no partial quarantine |
| Clock skew | tolerated | timestamps are metadata only; ordering from `seq`/CAS, never wall-clock; TTL uses max(sealed_at, indexed_at) with skew margin |
| Concurrent seal | single winner | ledger slot + index uniques decide; loser fails closed |
| Concurrent index insert | single winner | insert-if-absent; loser reads winner |

No failure produces a security-positive verdict. `UNKNOWN` carries no
bytes and never hands off.

## 20. Backward compatibility

- Reusable as-is: `EvidenceRecord` shapes, `EvidenceBuilder` +
  `verify_record`, triple-hash field lists, `hash_payload` canonical
  form, scrubber, `classify_orphan`/`validate_reindex`, handoff
  assemble/verify, `CEILINGS` + `check_limit`, ledger transition
  vocabulary. No 5H-core, 5E, 5F, or 5G component is modified by this
  architecture phase.
- Required adapters (implementation phase): blob-store CAS client
  implementing put-if-absent/get/verify; Mongo collections + roles
  (§7); `BROWSER_EVENT_BOUNDS` → central `CEILINGS` alias removal
  (one atomic commit); sweep daemon reusing `orphan.py` pure
  functions.
- Required schema extensions: seven `browser_*` ceiling keys (§12);
  optional `indexed_at`/`quarantine`/`tombstone` index annotations
  (index-only, never hashed, never in evidence bytes).
- Compatibility risks: dual-source ceiling window (mitigated by
  atomic alias removal); index annotation creep into hashed payloads
  (mitigated by `AUDIT_ONLY_KEYS` + payload-builder tests); novice
  implementers reaching for RMW updates (mitigated by role design +
  CAS-only code review gate).
- 5G guarantees preserved (verified against
  `agent-reports/browser-xss-executor-implementation.md`):
  `BrowserObservation` remains valid and unchanged; B5 remains
  BLOCKED; `LIVE_BROWSER` remains `False`; no live browser work
  enters 5H; no finding/verdict logic enters 5H (structurally
  excluded by `extra="forbid"` + `FORBIDDEN_EVIDENCE_FIELDS`).

## 21. Test strategy

Offline, deterministic, no live dependencies. Planned suites (design
only — nothing implemented here):

- Canonical serialization: golden vectors (key order, separators,
  unicode, newline normalization, absent==null, int/bool strictness,
  float/bytes/set rejection, timestamp-key refusal).
- Content hash: triple-hash recomputation vectors; tamper-in-every-
  field mutation tests (each must break exactly its hash).
- Identity binding: cross-execution transplant attempts (all eight
  axes, one at a time) → `EVIDENCE_BINDING_MISMATCH`/`HANDOFF_REJECTED`.
- Duplicate write: same-bytes idempotency; same-keys-differing-bytes
  refusal.
- Concurrent write: N-worker same-key race harness (threads with a
  fake CAS forefront) → exactly one winner, losers dedupe-read; plus
  a dedicated regression test that fails if any RMW-without-guard
  pattern is introduced.
- Immutability: attempt every mutation spelling against sealed
  records/blobs/index bindings → refused.
- Index/object consistency: matrix of present/missing/mismatched ×
  blob/index/ledger/audit → expected classification per §10/§19.
- Corruption: bit-flip fixtures at every byte class (bindings,
  observations, samples, hashes) → `CORRUPT` quarantine path.
- Orphan detection/quarantine/recovery/re-index: all seven §10 cases
  incl. grace-period boundaries and original-keys-only enforcement.
- Crash windows: fault injection between each lifecycle edge
  (seal→blob, blob→verify, verify→index, index→ledger,
  ledger→audit) → expected §19 outcome.
- CAS transitions: legal/illegal ledger+index transitions, version-
  guard losers, stale-reader behavior.
- Audit gaps: pre-start block vs. post-start `AUDIT_GAP` annotation.
- Access control: role-matrix tests (each role × each forbidden
  operation → refused).
- Retention hooks: TTL/tombstone/GC state machine on fakes; deletion-
  vs-mutation distinction tests.
- Browser ceilings: central-keys alias tests, tighten-only tests,
  builder cross-checks, backward-compat seal vectors.
- Scrubber integration: secret-shape fixtures across every §13
  location → redacted-pre-hash assertions + recomputation checks.
- 5E/5F/5G evidence: per-class golden sealed records incl. a 5G
  `BrowserObservation` vector (E1/E2/E3 advisory shapes, truncated
  channels, dropped cross-origin signals).
- 5I handoff: eligible/ineligible matrix (BUILDING/corrupt/missing/
  mismatched/unbound/unauthenticated/mutable → refused; SEALED+
  complete+valid → handoff with provenance checks incl. CONSUMED-
  provenance acceptance).
- No-finding/verdict semantics: AST + schema tests asserting no
  verdict-shaped field, name, or token anywhere in 5H.

## 22. B1/B2/B4/B5 status

- B1 = BLOCKED: production `AddressSource` selection/review deferred.
  (Unchanged; 5H consumes only injected resolution facts.)
- B2 = BLOCKED: production Mongo authorization/ledger/audit/evidence
  adapters + sweep deferred. This architecture defines the adapter
  and transaction model but implements nothing.
- B4 = BLOCKED: production payload-corpus source-of-truth review
  deferred. (Unchanged; 5H stores artifact hashes, never corpus
  semantics.)
- B5 = BLOCKED: browser network/containment boundary deferred.
  `LIVE_BROWSER = False` holds; no live browser work enters 5H.

## 23. Blocking prerequisites

Before B2 can CLOSE (all required, in order): (i) Mongo topology +
  backup/restore runbook approved (no credentials in code); (ii) the
  four collections + unique indexes + roles of §7 created by reviewed
  migration; (iii) CAS-only data-access layer implemented with no
  RMW path (reviewer-verified + race-harness green); (iv) blob store
  (filesystem-CAS MVP or object store) with conditional-put +
  read-back-verify + independent restore drill green; (v) sweep
  daemon implemented on `orphan.py` semantics with grace/quarantine/
  audit verified on fault-injection suite; (vi) full §21 offline
  suite green including concurrency + crash-window + access-control
  matrices; (vii) retention/tombstone policy signed off (legal/
  operator). None of these are satisfied by this document.

## 24. Proposed implementation order

1. Centralize the seven `browser_*` ceiling keys (§12; atomic alias
   removal). 2. Blob CAS client (put-if-absent/get/verify/GC) on
   filesystem-CAS fakes. 3. Mongo index/ledger/audit/sweep-state
   schema + unique indexes + roles (§7–§8) behind B2-gated adapters.
4. Seal→blob→verify→index→ledger→audit write path with CAS-only
   mutations (§9). 5. Read path with re-verification (§11). 6. Sweep
   daemon (§10). 7. Handoff assembly gate (§15). 8. Retention/
   tombstone hooks (§18). 9. Full §21 suite. At every step, 5H-core /
   5E / 5F / 5G remain untouched except through the narrow adapter
   seams named in §20.

## 25. Exact next phase recommendation

Implement 5H exactly in the §24 order (ceilings first, then blob CAS,
then Mongo adapters behind the B2 gate, then write/read/sweep/
handoff/retention with the §21 suite green throughout). Do not start
5I deterministic-verifier work until sealed→indexed→handoff flows for
all three observation classes (5E/5F/5G) round-trip through the §15
contract on fakes. Do not close B2 until all §23 prerequisites are
met and separately reviewed.

## 26. Explicit non-actions

This architecture phase performed and authorizes none of the
following: no source-code modification, no test creation, no MongoDB
access, no network access, no DNS, no subprocess execution, no
browser launch, no Nuclei execution, no JavaScript execution, no LLM
calls, no Git operations/commits/pushes, no evidence mutation, no
finding generation, no verdict generation, no B2 closure, no B5
closure, no live execution of any kind.

---

Mandatory statements: code modified = NO · tests added = NO ·
MongoDB accessed = NO · network = NO · DNS = NO · subprocess = NO ·
browser launched = NO · JavaScript executed = NO · LLM called = NO ·
Git = NO · evidence mutated = NO · finding generation = NO · verdict
generation = NO · B2 = BLOCKED · B5 = BLOCKED · LIVE_BROWSER = False ·
OOB = DENIED.
