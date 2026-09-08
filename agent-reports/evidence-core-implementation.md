# Phase 5H-core — Evidence Contract + Execution Accounting: Implementation Report

## 1. Verdict

**IMPLEMENTED AND VERIFIED.** Phase 5H-core is complete within its strict
scope: the evidence/v1 contract, split identity with three frozen hashes,
canonical SHA-256 hashing, BUILDING→SEALED|INCOMPLETE lifecycle with
spent-builder immutability, complete/incomplete data-state semantics,
OUTCOME_UNKNOWN ledger accounting, one shared secret scrubber,
observation-only URL/header/body contracts, Nuclei advisory-only evidence
with a hard 5F guard, browser/XSS dual-hash P/O evidence, eight-axis
bindings with no-rebind invariant, execution ledger with CAS idempotency
(AT-MOST-ONCE, exactly-once disclaimed), deterministic crash table, orphan
classification/recovery validation, append-only audit with gap records,
immutable tighten-only ceilings (24 dimensions), and the verdict-free
EvidenceHandoff with the AUTHZ_LIVE_FOR_EXECUTION vs
AUTHZ_VALID_FOR_PROVENANCE distinction explicit in code and tests —
110 focused offline deterministic tests passing, 838 existing regression
tests still green, no unrelated code touched, no live execution enabled.

## 2. Files created

| File | Purpose |
|---|---|
| `ai/schemas/evidence.py` | evidence/v1 pydantic contract: IDs, `EvidenceError`, target/snapshot/derivation/template bindings, redacted URL, header snapshot, HTTP/Nuclei/browser observations, `EvidenceRecord`, verdict-field ban |
| `ai/evidence/__init__.py` | Subpackage marker |
| `ai/evidence/hashing.py` | One shared canonical hashing module (SHA-256, canonical JSON, absent==null normalization, audit-key refusal) |
| `ai/evidence/scrubber.py` | ONE shared redaction module (headers, query, text, userinfo, URLs, closed-code `sanitized_reason`) |
| `ai/evidence/observations.py` | URL canonicalization/observation, redirect-chain cap, header allowlist + caps, body hash/sample policy |
| `ai/evidence/builder.py` | Immutable `EvidenceBuilder`/sealer, frozen hash-payload builders, completeness rules, `verify_record` |
| `ai/evidence/orphan.py` | Orphan classification + original-key-only re-index validation (pure, no I/O) |
| `ai/evidence/handoff.py` | `EvidenceHandoff`, `assemble_handoff`, `bind_provenance`, `require_live_for_execution`, `verify_provenance_for_handoff` |
| `ai/execution/__init__.py` | Subpackage marker |
| `ai/execution/ledger.py` | `ExecutionRecord`, `InMemoryExecutionLedger` (CAS), lifecycle transitions, crash table, new-authz classifier |
| `ai/audit/__init__.py` | Subpackage marker |
| `ai/audit/trail.py` | `AuditRecord`, `gap_record`, `check_ordering`, transition order |
| `ai/limits/__init__.py` | Subpackage marker |
| `ai/limits/ceilings.py` | 24 immutable ceilings + tighten-only `check_limit`/`validate_config` |
| `ai/test_evidence_core.py` | 110 focused offline deterministic tests |

## 3. Files modified

**None.** Zero existing repository files were edited, renamed, moved, or
deleted. In particular: `ai/schemas/artifact.py`,
`ai/schemas/execution_authorization.py`, `ai/authorizer/*`,
`ai/verification/*`, `ai/researcher/nuclei_runner.py` (including the
legacy `to_findings` stdout→matched path — deliberately NOT redesigned
here; the 5F removal/gating obligation is enforced by a guard test in
§14 and recorded in §28), `database/db.py`, and all existing tests are
untouched. Two defects found during testing were fixed in NEW code only:
case-sensitive allowlist comparison in `observations.filter_headers`
(header names are case-insensitive; allowlists are lowercase) and an
under-specified test using the wrong execution class for a stored-READ
seal.

## 4. Exact scope

Implemented (§5H.1–5H.22 of the task): evidence/v1 schema; random
`ev-`/`ex-` handles + split hash identity; canonical hashing; lifecycle;
complete/incomplete; OUTCOME_UNKNOWN accounting; shared scrubber; URL,
header, and body contracts; Nuclei advisory contract (no live run, no
runner changes); browser/XSS dual-hash contract (no oracle changes);
eight-axis bindings; no-rebind invariant; ledger + idempotency + crash
mapping; orphan contract (no sweeper integration); audit + gap contract;
ceilings (helpers/tests only, no executor integration); handoff with the
live-vs-provenance distinction; focused tests; this report. Not started
and not enabled: 5C–5J, scheduler, queue, findings, classification,
CONFIRMED/NOT_VULNERABLE, any runtime or network path.

## 5. Evidence schema

`ai/schemas/evidence.py` (`evidence/v1`): `EvidenceRecord` carries
`evidence_id`, `execution_id`, `authorization_id`, `execution_stage`,
`artifact_id`, `artifact_content_hash`, `target` (+ top-level
`program_name`), `hypothesis_id`, `test_plan_id`, `match_id`,
`snapshot_binding`, `derivation_binding`, `template_binding`, `complete`,
`lifecycle`, the three seal hashes, one optional observation per class
(`http`, `nuclei`, `browser`), `incomplete_reasons`, and audit-only
timestamps. Every model uses `extra="forbid"`; `FORBIDDEN_EVIDENCE_FIELDS`
(`verdict/finding/matched/vulnerable/confirmed/not_vulnerable/severity/
exploited`) is enforced by tests against every evidence, observation,
handoff, and audit model.

## 6. Identity

`generate_evidence_id()` → `ev-` + 32 hex, `generate_execution_id()` →
`ex-` + 32 hex (128-bit `secrets`, format-tested only). Both are handles:
content identity is the frozen triple computed by `builder.compute_hashes`
— `bindings_hash` (identity/bindings; `evidence_id` excluded),
`observations_hash` (transport facts + content hashes; raw samples
excluded), `content_hash` (exactly the persisted bounded samples).
Timestamps never participate (payload builders exclude them AND
`hashing` refuses audit-only keys — double protection).

## 7. Hashing

`ai/evidence/hashing.py`: SHA-256 only; canonical JSON (`sort_keys=True`,
`separators=(",",":")`, `ensure_ascii=False`, UTF-8); `normalize_for_hash`
(newline-normalizes text, preserves bool/int/null/list/mapping, rejects
floats/bytes/sets/objects and audit-only keys); absent-optional ==
explicit-null by construction (payload builders emit null for every
absent optional). Tests prove: determinism, key-order independence,
timing exclusion, null==absent, `repr`/set/float rejection, timestamp
refusal.

## 8. Lifecycle

`EvidenceBuilder`: `begin()` (typed issuance record only — raw dicts
→ `TypeError`, 5B discipline) → `attach_http/nuclei/browser()` (once
each; replacement → `EVIDENCE_IMMUTABLE`) → `seal()` (complete →
SEALED) or `seal_partial()` (explicit closed-vocabulary reasons →
INCOMPLETE). The builder spends on seal; any further call raises
`EVIDENCE_IMMUTABLE`. ORPHANED exists only in `orphan.py` as an index
classification. Legal: BUILDING→SEALED, BUILDING→INCOMPLETE. No
SEALED→BUILDING/INCOMPLETE, no INCOMPLETE→SEALED, no
reassign/rebind/repair/reattach/supersede/patch/append symbols anywhere
(test-asserted absent on the class and both modules).

## 9. Complete/incomplete

`seal()` enforces per-class required observations (HTTP: status + body
hash; Nuclei: exit facts + hashes + template pin; browser: executed
payload hash + page URL), snapshot pin presence, oracle-stage derivation
presence, and nuclei-class template presence — else `EVIDENCE_INCOMPLETE`
without sealing. `seal_partial()` seals `complete=false` terminal
evidence. INCOMPLETE never maps to any verdict (schema ban + handoff
refusal; tests pin both directions).

## 10. OUTCOME_UNKNOWN

Ledger `STARTED→UNKNOWN` terminal (`mark_unknown`): no `evidence_id`,
no resume, no handoff, retry only under a NEW authorization (ledger
replay guard refuses same-authorization re-registration with
`ReplayExecutionError`); ambiguous stored SUBMIT additionally requires a
new round (crash table: `transport_unknown`/`pre_seal` →
`new_authz_required: True`). Unknown executions are never reconstructed
from logs (no such API exists).

## 11. Secret redaction

`ai/evidence/scrubber.py` is the single scrubber for all paths: secret
header values → `[REDACTED]` (exact names + token/secret/apikey/session/
auth patterns + secret-shaped values); secret query/form values →
`[REDACTED]` (names preserved); userinfo stripped; connection URIs
(mongo/postgres/mysql/redis/amqp), private-key blocks, bearer/basic
credentials, AKIA/GitHub/XOX/Sk-live shapes redacted in free text;
`sanitized_reason` maps failures to 15 closed codes (≤200 chars,
secret-screened, unknown codes refused). Error details carrying secret
markers raise instead of leaking (mirrors 5B `AuthzError` discipline at
the 200-char bound the task requires).

## 12. URL policy

`observe_url` persists only the redacted canonical URL (≤2048 chars) +
`canonical_hash` + `redacted_query_hash`. Canonical form lowercases
scheme/host, strips trailing dots/userinfo/fragments, preserves query
byte-exact for hashing; non-http(s)/hostless input → `EVIDENCE_MALFORMED`
fail-closed. Redirect chains capped at 5 (+1 overflow slot with explicit
flag). The module contains no fetch/socket/request symbols
(test-asserted): evidence URLs are unexecutable observations.

## 13. Header policy

Architecture allowlists implemented verbatim (request 12 + response 14 +
vendor-banner hints), default-deny with `truncated` flag on any drop,
case-insensitive matching, secret-value redaction after filtering. Caps:
32 headers, 128-char names, 1 KiB values, 8 KiB total — each pinned by a
dedicated test.

## 14. Nuclei evidence

`NucleiObservation`: template id/hash (hash recomputed from projected
bytes at `attach_nuclei`, which also pins `template_binding`), argv
digest, exit code, timed_out/killed, stdout/stderr hashes always, bounded
samples, `finding_like_text_present` advisory boolean. Schema contains no
matched/vulnerable/confirmed field (test-asserted). The existing
`NucleiRunner.to_findings()` stdout→matched path was NOT modified per
scope; instead a guard test asserts no 5H-core module imports or consults
`nuclei_runner`/`to_findings`, and the 5F gate obligation is documented
in §28: `to_findings` MUST be deleted or hard-gated (`legacy_unsafe=True`,
forbidden in executor paths) before 5F, with a hostile-stdout
non-confirmation test.

## 15. Browser/XSS evidence

`BrowserObservation`: marker-hash channels (dialog/oracle/eval, ≤16 each),
advisory E1/E2/E3 booleans, `executed_payload_hash` O recorded
independently of artifact hash P (dual-hash rule; `attach_browser`
accepts O on the observation or explicitly — never copies P),
redacted `page_url`, storage-keys hash, round identity. Oracle runtime
untouched. Stored SUBMIT/READ are separate records (distinct
`evidence_id`/`execution_id`, shared `round_id`); READ references the
SUBMIT record by immutable `content_hash` only.

## 16. Binding model

Eight axes frozen in `builder.bindings_payload` + `verify_provenance_for_
handoff`: (1) authorization — id/nonce copied, liveness store-side;
(2) execution — id/stage copied, lease CAS ledger-side; (3) target —
tuple copied, canonicalization recomputed; (4) artifact — triple copied,
content hash recomputed from store bytes; (5) test plan — ids copied,
equality-checked; (6) stage/derivation — contract hash copied, executed
hash computed from wire bytes; (7) scope-policy pin — hashes copied,
per-hop decisions recomputed fresh at handoff time (5D); (8) freshness —
instants observed, window-checked at handoff. Detectable: wrong authz,
wrong execution, wrong program, wrong target, wrong artifact, wrong plan,
wrong snapshot/scope pin, wrong derivation, modified observations,
modified content (each with a dedicated test).

## 17. Immutability

Sealed records verify on read (`verify_record` recomputes all three
hashes); any divergence → `EVIDENCE_HASH_MISMATCH` naming the hash.
Second seal, observation replacement, and post-seal builder use all raise
`EVIDENCE_IMMUTABLE`. Recovery (`orphan.validate_reindex`) restores
original index entries only after hash re-verification + byte-identical
key equality; altered bytes and new-execution keys are refused.

## 18. Idempotency

`InMemoryExecutionLedger` models the production contract: `put_new`
(one row per `(authorization_id, stage)` — second registration →
`ReplayExecutionError`; key collision → `DuplicateExecutionError`),
`compare_and_swap` (version-guarded +1, identity/stage-rebind refusal;
loser on a live row → `InProgressExecutionError`, never a second start),
`mark_started/sealed/incomplete/unknown` narrow transitions. AT-MOST-ONCE
EXECUTION preserved; exactly-once explicitly disclaimed in the module
docstring. `EXECUTION_IN_PROGRESS` / `EXECUTION_DUPLICATE` /
`EXECUTION_REPLAY` / `OUTCOME_UNKNOWN` are distinct, separately tested
states. Single-process fidelity only — cross-process requires the Mongo
unique-index + CAS adapter before live use (documented on the class).

## 19. Crash matrix implementation

`ledger.crash_decision` pure table covers all seven task rows
(pre_start, post_consume, post_start, transport_unknown, pre_seal,
post_seal_pre_index, post_index_pre_audit) with retry/same-authz/
new-authz/evidence/audit/verifier outcomes; `retry_requires_new_
authorization` returns False only for REGISTERED rows. Correction
implemented as specified: pre-start reuse only when unconsumed and
unstarted; post-consume never mints a second execution (replay guard);
post-start ambiguity → UNKNOWN + new authorization; seal-then-crash →
orphan re-index only; index-then-crash → AUDIT_GAP sibling record, never
evidence mutation. Each row has a dedicated test.

## 20. Orphan handling

`orphan.classify_orphan` pure table: bytes-without-index →
INDEX_MISSING_SEALED/INCOMPLETE (recoverable candidates); index-without-
bytes → BYTES_MISSING (corruption, quarantine); ambiguous → 
BINDING_AMBIGUOUS (quarantine). `validate_reindex` enforces all
preconditions (typed input, sealed terminal, hash re-verification,
byte-identical original keys) and returns the recovery class. No byte
writes, no new identities, no rebinding — structurally (no such symbols)
and by test.

## 21. Audit

`ai/audit/trail.py`: `AuditRecord` (seq, execution/authorization/
evidence ids, stage, transition, at/actor, program/host, scope decision,
artifact triple, evidence hashes, error code — all bounded ≤200 chars,
secret-screened, `extra="forbid"`, verdict-field-free); legal order
AUTHORIZATION→EXECUTION_STARTED→EXECUTION_STAGE→EVIDENCE_SEALED→
EXECUTION_TERMINAL→VERIFIER_HANDOFF enforced by `check_ordering`
(contiguous seq, non-decreasing positions, gap/orphan annotations
order-exempt); `gap_record` builds separate AUDIT_GAP entries.
Pre-start audit failure blocks execution (fail-closed — no permission
API reads audit, test-pinned); post-start failure is a gap sibling.

## 22. Resource ceilings

`ai/limits/ceilings.py` freezes all 24 architecture values verbatim
(60/120/15 s walls; 10/10/10 s connect/read/stall; 16 KiB request;
512 KiB transport / 8 KiB sample / 2 MiB decompressed / 10× ratio;
5 hops / 7 reqs / 8 DNS; 1 page / 1 context; Nuclei 1 / ≤5 s⁻¹ / 0
retries / 1 MiB capture; 16 MiB temp; 512 MiB RLIMIT_AS; 60 s RLIMIT_CPU;
1000 pending). `check_limit`/`validate_config` enforce tighten-only
(over → LIMIT_EXCEEDED; unknown/unbounded/non-numeric → LIMIT_UNKNOWN).
Every ceiling breach-tested in a loop plus dedicated
tighten/loosen/unknown/unbounded tests. No executor integration (5E–5G).

## 23. EvidenceHandoff

`ai/evidence/handoff.py`: `EvidenceHandoff` (references + three hashes +
`HandoffProvenance`; `extra="forbid"`; verdict-field-free by test).
`assemble_handoff` requires SEALED + complete + hash-valid (INCOMPLETE →
HANDOFF_REJECTED as data-state; tampered → EVIDENCE_HASH_MISMATCH naming
the hash). `bind_provenance` pins issuance nonce/issued/expiry from the
genuine record. No CONFIRMED/NOT_VULNERABLE/matched/vulnerable/severity
anywhere on the path.

## 24. AUTHZ_LIVE vs AUTHZ_PROVENANCE distinction

Explicit in code (`handoff.py` module docstring + two separate
functions), tests (`BindingTest.test_live_vs_provenance_distinction`,
`test_consumed_legitimate_accepted`, `test_forged_authz_rejected`,
`test_revoked_rejected`, `HandoffTest.test_consumed_provenance_accepted`),
and here:

- `require_live_for_execution` (execution permission, checked BEFORE
  execution): only `ISSUED` + unexpired passes. `CONSUMED` → 
  `AUTHZ_NOT_LIVE`. A consumed authorization is NEVER permission to
  execute again (ledger replay guard enforces the same invariant from
  the accounting side).
- `verify_provenance_for_handoff` (historical provenance, checked AT
  handoff): requires the issuance record to exist (`None` → 
  HANDOFF_REJECTED), identity match, issuance-nonce match (forgery
  detection; unbound/empty nonces rejected), lifecycle `ISSUED` or
  `CONSUMED` (`REVOKED`/post-start-`EXPIRED` → HANDOFF_REJECTED),
  issuance window covering execution start (issued_at ≤ start <
  expires_at — the authorization was valid when execution began), and
  full binding equality (artifact/target/plan/derivation).
- A legitimate CONSUMED authorization returns
  `AUTHZ_VALID_FOR_PROVENANCE` for its own sealed evidence. CONSUMED is
  the expected post-execution state, not invalidation — and it grants
  zero execution permission.

## 25. Tests

110 tests in `ai/test_evidence_core.py` (stdlib `unittest`, offline,
deterministic; randomness asserted by format/uniqueness only):
Identity 7, Lifecycle 7, Completeness 5, Unknown 4, Hash 4, Secrets 9,
URL 6, Headers 6, Nuclei 6, XSS 6, Binding 10, Idempotency 5, Crash 7,
Orphan 6, Audit 6, Limits 6, Handoff 8, Body policy 3. Result:
`python3 -m unittest ai.test_evidence_core` — **110 tests, OK**.

## 26. Regression

- New + 5B/artifact/hypothesis suites (`test_evidence_core`,
  `test_execution_authorization`, `test_artifact`, `test_artifact_store`,
  `test_artifact_retrieval`, `test_test_plan_readiness`,
  `test_hypothesis_testplan`, `test_hypothesis_engine`): **477 tests, OK**.
- XSS/executor/knowledge suites (`test_xss_oracle`,
  `test_xss_verification`, `test_composite_executor`, `test_http_executor`,
  `test_xss_stored_round`, `test_browser_executor`, `test_knowledge_store`,
  `test_openrouter`, `test_xss_researcher`, `test_xss_llm_researcher`):
  **471 tests, OK**.
- `compileall` on all new files: OK.
- Total: 110 new + 838 existing green, 0 failures.

## 27. Failures

Two pre-report defects, both fixed in NEW code before completion (no
existing code touched): (1) `filter_headers` compared lowercased header
names against mixed-case allowlists, dropping legitimate headers —
fixed by case-folding the allowlist once (caught by `test_name_cap`);
(2) stored-READ test used the HTTP execution class, failing completeness
— fixed by using `browser_verification` for the READ seal. No new-test
failures, no regression failures, no compile failures at completion.

## 28. Deferred 5C–5J work

5C TargetResolver, 5D ScopeEvaluator/canonicalizer-enforcement, 5E HTTP
executor, 5F Nuclei executor (including MANDATORY deletion or hard-gating
of `NucleiRunner.to_findings` — guard-tested here, removal enforced by
gate G-5F), 5G XSS executor, 5H-store production backend (Mongo unique
indexes + CAS per the frozen §27 architecture decision, sweep, retention),
5I verifier runtime + classifiers, 5J E2E. Open architecture questions
unchanged: egress topology (safe default stands) and retention-period
sign-off (defaults implemented as constants-in-waiting, not code).

## 29. Security invariants

1. Evidence is never authority (no permission API reads evidence).
2. Evidence is never a verdict (schema ban + handoff gates + tests).
3. Sealed evidence cannot mutate (spent builder, no update symbols).
4. Incomplete/unknown never reach the verifier (assembly gates).
5. Duplicate workers cannot both execute (CAS + replay/in-progress guards).
6. Crash recovery cannot hijack evidence (original-key-only re-index).
7. Audit failure cannot mutate sealed evidence (gap siblings).
8. Evidence cannot leak credentials (single scrubber + hash-default).
9. LLM cannot consume raw evidence (no such import path exists).
10. Nuclei output cannot become a finding (advisory-only schema + 5F gate).
11. Browser content cannot become verifier authority (hash channels only).
12. P and O remain distinct (dual hashes + expectation rules for 5I).
13. Ceilings are tighten-only and boot-asserted (helpers + tests).
14. Cross-program confusion impossible (`(program_name, host)` key).
15. Handoff is one-way and verdict-free. 16. CONSUMED is provenance, never
    permission (live-vs-provenance split, code + tests).

## 30. Confirmation that no live execution was enabled

No live execution was enabled. No TargetResolver, scope evaluation, HTTP/
Nuclei/XSS transport, DNS/egress, scheduler, queue, browser launch,
oracle invocation, Nuclei invocation, network request, verifier runtime,
classification, finding, CONFIRMED/NOT_VULNERABLE label, or production
backend was created, modified, or invoked. All new modules are pure and
deterministic (no socket/request/subprocess/database/LLM imports); the
entire test suite runs offline. 5H-core establishes contracts and local
deterministic infrastructure only.

## 31. Confirmation that no Git commands were run

No Git commands were run. Not `git status`, `git diff`, `git add`,
`git commit`, `git log`, `git branch`, `git switch`, `git checkout`,
`git restore`, `git reset`, `git stash`, `git merge`, `git fetch`,
`git pull`, `git push`, nor any other Git operation whatsoever. All work
was performed through direct file operations and Python test execution.
