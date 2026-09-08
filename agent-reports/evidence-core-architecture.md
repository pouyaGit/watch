# Phase 5H-core — Evidence Contract + Idempotency + Audit + Resource Ceilings
# READ-ONLY SECURITY ARCHITECTURE — NO IMPLEMENTATION

## 1. Executive verdict

**VERDICT: ARCHITECTURE SUFFICIENT TO UNBLOCK 5H-core CONTRACT WORK —
PROVIDED EVERY NORMATIVE CHOICE BELOW IS IMPLEMENTED VERBATIM AND EVERY
IMPLEMENTATION GATE IN §35 PASSES. NO LIVE EXECUTION IS AUTHORIZED BY THIS
DOCUMENT.**

This design freezes the immutable evidence and execution-accounting substrate
that MUST exist before Watch performs live HTTP, Nuclei, or XSS execution.
It sits strictly downstream of Phase 5B
(`agent-reports/execution-authorization-architecture.md`,
`agent-reports/execution-authorization-implementation.md`) and upstream of
5C–5J. The load-bearing decisions:

1. **Evidence identity is split, not singular (§5).** `evidence_id` (random,
   128-bit) is a handle only. Deterministic content identity lives in three
   frozen hashes — `bindings_hash`, `observations_hash`, `content_hash` —
   each with a closed field list. Timing never enters any hash.
2. **Four-state lifecycle (§6):** `BUILDING → SEALED | INCOMPLETE`, plus
   `ORPHANED` as an *index* state, never an evidence-mutation state. Sealed
   bytes are immutable; the only legal recovery re-indexes byte-identical
   bytes under their original key after hash re-verification.
3. **Complete/incomplete is execution-data state (§7); OUTCOME_UNKNOWN is
   not evidence (§8).** Only `complete=true` + all bindings valid + all
   hashes valid may enter verifier handoff. `INCOMPLETE` and
   `OUTCOME_UNKNOWN` are never positive, never negative, never
   verifier-consumable.
4. **One hash algorithm (§9): SHA-256 over canonical JSON**
   (`sort_keys=True`, `separators=(",",":")`, `ensure_ascii=False`,
   UTF-8 bytes). No `repr()`, no unordered serialization, no hashed
   timestamps.
5. **Hash-default bodies (§10) + single redaction policy (§11).** Bodies are
   hash-always/sample-sometimes (8 KiB evidence sample cap, 512 KiB
   transport cap, 2 MiB decompressed cap, ratio abort). One shared scrubber
   covers headers, URLs, stdout/stderr, logs, errors, browser storage.
6. **URLs and headers are observations, never authority (§12–§13).**
   Canonical form for comparison, redacted form for persistence, allowlisted
   headers only, bounded counts/sizes.
7. **Nuclei stdout and browser page text are raw observations (§14–§15).**
   `stdout → matched/vulnerable/confirmed` is prohibited by schema and by
   test. XSS artifact payload P and oracle payload O remain separately
   represented with dual hashes; inequality expected on oracle paths.
8. **Binding + no-rebinding (§16–§17).** Evidence copies authorization values
   verbatim and recomputes content hashes independently; the verifier
   re-checks all eight binding axes. Sealed evidence can never be reassigned.
9. **Idempotency (§19): 5B's claim is FROZEN — AT-MOST-ONCE EXECUTION with
   AT-LEAST-ONCE EVIDENCE AVAILABILITY** via cross-process unique index +
   atomic CAS. Process-local locks confer nothing. Exactly-once is
   explicitly disclaimed.
10. **Crash matrix (§20) + orphan recovery (§18) + audit ordering (§21).**
    Post-start ambiguity requires a new authorization (new round for stored
    SUBMIT ambiguity). Audit failure before start blocks execution; after
    start it creates a separate gap record, never an evidence mutation.
11. **Resource ceilings (§23) are immutable, tighten-only, boot-asserted, and
    enforced at the transport/worker/subprocess/filesystem/capture points
    (§24)** — never as constructor metadata alone.
12. **Backend decision (§27): MongoDB unique index + atomic CAS** (single
    executor database, three collections, version-guarded updates). The
    dedicated lock-service alternative is rejected for 5H-core.
13. **LLM boundary (§29): evidence does not enter LLM context by default.**
    Any future summarization needs an allowlist + redaction pass; none is
    authorized here. Verifier handoff (§30) is one-way, verdict-free.

Two items remain genuinely open (§38): egress-topology final selection
(safe default: sidecar proxy for Nuclei + pinned adapter/proxy for
HTTP/browser) and retention-period sign-off (safe defaults specified).
Neither blocks 5H-core contract work; both block live-fire phases.

---

## 2. Actual repository findings

Verified by direct reads. Repository HEAD is source of truth; where reports
and code diverge, code governs and the divergence is recorded.

1. `ai/schemas/artifact.py:56–164` — closed `ArtifactType`
   (`nuclei_template/xss_payload/http_request_spec`), closed
   `ValidationState`, size caps (32/4/16 KiB), `artifact_id_for()` over
   `(type, test_plan_id, content_hash, schema_version)` with canonical JSON
   (`sort_keys`, `separators=(",",":")`, `ensure_ascii=False`, UTF-8).
   Metadata is audit-only, identity-excluded, verdict-key-forbidden.
   **This canonical-JSON function is the precedent §9 generalizes.**
2. `ai/knowledge/artifact_store.py:1–80` — file-backed content-addressed
   store: keyed by `content_hash`, indexed by `artifact_id`, atomic
   temp-file + rename + fsync writes, `threading.Lock` instance-level with
   documented "cross-process writers are out of scope". Integrity rechecked
   on read. **The cross-process caveat is exactly what the 5H-core
   EvidenceStore must not inherit (§25, §27).**
3. `ai/schemas/execution_authorization.py` (947 lines) + `ai/authorizer/`
   — 5B as reported: Option B by-reference, typed API only, no
   `authorize_from_*` constructors, `max_executions=1`, exactly-one
   artifact, DELETE excluded, derivation contract, two stage leases,
   scope-hash binding without evaluation, 15-code sanitized error model.
   `CALLER_SCOPES = {manual, scheduled, retry-new-authz}` (`service.py:50`).
   `AuthorizationStore` protocol (`put_new/get/get_by_idempotency_key/
   compare_and_swap`) with version-guarded CAS and identity-rebind refusal
   (`store.py:135–175`). In-memory adapter explicitly not cross-process.
4. `ai/verification/http_executor.py:38–66,159–216,400–529` — evidence
   provider posture (no verdict vocabulary by test-enforced invariant);
   header redaction exists but is narrow (`cookie/authorization/
   proxy-authorization` request; `set-cookie/www-authenticate/
   proxy-authenticate` response; placeholder `[REDACTED]`); redirect loop is
   manual with `allow_redirects=False`, cycle set on **raw URL strings**
   (case/trailing-dot sensitive — gap §18 of 5B arch carries forward);
   cross-host redirect rule is **eTLD+1 equality** (`_check_redirect_safety`,
   `:503–520`) with `None or ""` port comparison — **both must be replaced
   by the §16 exact-host rule and effective-port rule before 5E**;
   `301/302 + POST/PUT/PATCH/DELETE → GET` coercion includes DELETE in the
   match tuple (`:478–484`) — dead today (DELETE never reaches executor) but
   must be cleaned in 5E; timeout/redirect/body-cap are **constructor
   parameters** (`timeout=10.0, max_redirects=5, max_body_bytes=512 KiB`)
   — the exact "limits as metadata" pattern §24 must replace with
   enforced ceilings; error sanitization is value-substitution +
   200-char truncation (`_sanitize_reason`).
5. `ai/verification/browser_executor.py:59–67` — hard caps exist:
   64 runtime entries, 240-char entry length, 8 chain steps, 120-char
   descriptions, 200-char error reasons, 5 navigation hops, 512 KiB body,
   10 s navigation + 5 s observation window. Fresh context per attempt,
   capability transport, same-origin route policy. Sound core to WRAP.
6. `ai/verification/oracle.py:1–80` — deterministic oracle
   (`S = sha256(salt‖0x00‖attempt‖0x00‖phase)[:16]`, FNV1a32 over UTF-16
   code units, `D = hex8(h1)+hex8(h2)`), seed-on-wire / value-never-on-wire
   anti-harvest property, no classification logic. P≠O by construction.
7. `ai/researcher/nuclei_runner.py:33–38,205–326` — `timeout=120`
   constructor arg, `subprocess.run(capture_output, text, timeout)` with no
   capture cap, no argv beyond `-t/-u/-no-color`, no binary pin/checksum,
   no env scrub, no `shell=False` explicitness, `TIMEOUT → status TIMEOUT
   + error=str(exc)` (raw exception text into evidence — prohibited by
   §11), and **`to_findings(): matched = COMPLETED and output.strip()`**
   (`:283–286`) — the legacy stdout→matched path that **must be deleted /
   hard-gated before 5F** (carried as §14 invariant + §35 gate).
8. `ai/schemas/xss_verification.py:387–840` — current evidence structures:
   `BrowserExecutionObservation` (advisory booleans + structured channels,
   chain well-formedness validator), `VerificationAttempt` (oracle
   seed/value/version/identity, `round_id`, `payload_origin`
   knowledge/model_generated), `VerificationEvidence` (redacted headers,
   truncated body, reflection, browser, WAF, stored phases, oracle channels,
   SUBMIT forensics `request_body_hash/response_body_hash/redirect_chain/
   location_header/object_hint`, intended/actual URLs, started/finished
   timestamps, `error_reason`, `expected_behavior` LLM hint, minimal
   negative-control fields). **Discrepancies vs 5H-core needs:** no
   `evidence_id/execution_id/authorization_id/stage` fields; no
   `complete` flag; no `bindings_hash/observations_hash/content_hash`;
   timestamps are wall-clock ISO strings (must be excluded from hashes per
   §9); `response_body_truncated` is unbounded-by-schema; `error_reason`
   is free text; `location_header/object_hint` capped only by producer
   discipline (2048-char slice in http_executor). All are EXTEND/REPLACE
   items (§34), never reused as authority-bearing identity.
9. `database/db.py:29–56,162–183,554–565` — MongoEngine with per-collection
   `meta.indexes` precedent: `Programs.program_name` unique,
   `(program_name, subdomain)` unique on Subdomains/Http/LiveSubdomains,
   `(program_name, url)` unique on Urls, `(program_name, subdomain, path)`
   unique on Endpoints, `XssFindings.case_id` unique. **Precedent supports
   the §27 unique-index decision.** Hardcoded Mongo credentials in source
   (`:35–38`, `mongodb://pouya:YourStrongPassword123@…`) — pre-existing
   secret-handling violation; 5H-core must never log/repeat connection
   strings and errors at the resolver/store boundary must be sanitized.
   `get_domain_name` is eTLD+1 via tldextract — advisory only, never scope
   authority.
10. No evidence/audit/idempotency runtime exists in-tree. No `EvidenceStore`,
    no audit-trail collection, no execution ledger, no retention sweeper, no
    subprocess RLIMIT code, no DNS-answer caps, no decompression-ratio
    guards. All are NEW (§34). `XSSVerificationAudit` (counts + notes) is
    per-result statistics, not an append-only audit trail — must not be
    mistaken for one.

**Discrepancy log (report vs HEAD):** (a) 5B arch §28 proposed ceilings
(60 s HTTP / 120 s Nuclei / 15 s browser, 16 KiB request, 512 KiB response,
2 MiB decompressed) — HEAD executors use 10 s HTTP timeout, 120 s Nuclei
timeout, 10+5 s browser split; 5H-core §23 reconciles these normatively.
(b) 5B arch assumed a future `ExecutionAuthorizations` collection — HEAD
has no such collection; §27 defines it. (c) 5B arch §24 described
`evidence_id` random + `complete: bool` — HEAD `VerificationEvidence` has
neither; §5–§7 define them as new contract fields.

---

## 3. Current evidence structures

| Structure | Location | 5H-core verdict |
|---|---|---|
| `VerificationEvidence` (+ attempt, reflection, WAF, stored phases, oracle channels, SUBMIT forensics) | `ai/schemas/xss_verification.py:684–787` | EXTEND: keep transport-fact shape; ADD identity (`evidence_id`, `execution_id`, `authorization_id`, `execution_stage`), ADD `complete`, ADD three hashes, ADD binding refs; BOUND free-text fields; FORBID verdict-shaped extras |
| `BrowserExecutionObservation` | `:387–449` | WRAP: keep channelled shape + chain validator; ADD per-channel caps + token-presence rule frozen in §15; advisory booleans stay advisory |
| `VerificationAttempt` | `:452–516` | REUSE AS-IS upstream; evidence must reference it, never embed mutable copies of it |
| `HTTPEvidenceExecutor` transport core | `ai/verification/http_executor.py` | WRAP (§34): keep manual-redirect + redaction shape; replace eTLD+1/port-compare with §16/§13 rules; move limits into enforced ceilings |
| `BrowserEvidenceExecutor` + oracle + composite dispatcher | `browser_executor.py`, `oracle.py` | WRAP: preserve isolation/capability/anti-harvest verbatim |
| `NucleiRunResult` + `to_findings` | `ai/researcher/nuclei_runner.py` | ISOLATE transport facts; REPLACE `to_findings` (delete/gate) |
| `XSSVerificationAudit` | `xss_verification.py:796–806` | ISOLATE: statistics only; never the append-only audit trail (§21 is NEW) |
| `ArtifactStore` | `ai/knowledge/artifact_store.py` | REUSE AS-IS (pattern precedent for §25 store design; code not shared) |

---

## 4. Revised trust hierarchy

**UNTRUSTED (never authority, never parsed as authorization, never a
verdict):** LLM output and research prose; pre-validation artifact bytes;
TestPlan intent; HTTP response bodies, `Location` values, object hints;
browser page content/console/JS/DOM; DNS answers; Nuclei stdout/stderr/exit
codes; callback data; timing values; userinfo-bearing URLs; raw error
strings; inventory values older than current resolution; sealed-evidence
bytes *as commands* (they are evidence even to the verifier).

**VALIDATED DATA (one narrow property each, never transitive):**
ResearchPattern; TargetIntelligence (observation); TargetPatternMatch
(relevance); Hypothesis/TestPlan intent; VALID ArtifactReference +
hash-verified bytes (contract/safety); Readiness READY (structural
completeness); pinned fixture bytes (specificity input); canonicalized URLs
(syntax only). `VALID ≠ in-scope`; `READY ≠ authorized`; `canonical ≠
allowed`.

**AUTHORITY (only permit/deny sources):** issuance-record-backed
`IssuedExecutionAuthorization` loaded via typed API (5B); authoritative
scope policy + program lists read fresh (5D); fresh target resolution (5C);
deterministic validators (scope evaluator, canonicalizer, artifact
revalidator, fixture-pinned specificity); pinned egress enforcement;
immutable ceilings module (§23) + boot assertion.

**EVIDENCE (new in this phase):** sealed, immutable, hash-split,
secret-minimized, `complete`-flagged raw observations. Consumable only when
`complete=true` with live, revalidated bindings. Never authority, never a
verdict, never mutable into authority.

**VERIFIER (sole classifier):** consumes complete bound evidence only,
revalidates everything, never writes evidence, never drives execution.
No Nuclei/HTTP verifier exists yet; their absence blocks 5I, never 5H-core.

**AUDIT (accounting, not authority):** append-only transition log + gap
records. Reconstructs authorization→execution→evidence→handoff without
trusting any single record. Never consulted as permission.

---

## 5. Evidence identity

### 5.1 Canonical identity tuple (normative)

Every evidence record carries exactly one value for each field below.
Field names are frozen:

| Field | Form | Meaning |
|---|---|---|
| `evidence_id` | `ev-` + 32 lowercase hex (128-bit `secrets.token_hex(16)`) | Random handle. Uniqueness only; no content meaning |
| `execution_id` | `ex-` + 32 lowercase hex (128-bit random, minted once per execution start) | Binds all stage-records of one execution |
| `authorization_id` | opaque `authz-…` (5B) | Copied verbatim from the loaded issuance record |
| `execution_stage` | closed enum `single \| submit \| read \| oracle` | Which lease/phase produced this record (5B `ExecutionPhase` vocabulary) |
| `artifact_id` | `art-…` plan-bound (5B §7) | Copied from authorization binding |
| `artifact_content_hash` | SHA-256 hex | Copied from authorization binding; independently recomputed at revalidation |
| `target_identity` | `(program_name, host, scheme, effective_port:int, path_scope)` | Copied from authorization; host is canonicalized form (§12 of this doc) |
| `program_name` | exact program row key | Part of target identity; repeated top-level for index isolation |
| `hypothesis_id` | `hyp-…` or null | Copied where the authorization binds one; never fabricated |
| `test_plan_id` | `tp-…` | Copied from authorization |
| `match_id` | `tm-…` or null | Copied where bound; never fabricated |
| `snapshot_binding` | `{snapshot_ref, scope_policy_version, scope_lists_hash, fixture_set_id, fixture_version, cdn_mapping_version+hash}` or null fields where not applicable | Copied pin values from authorization |
| `derivation_binding` | `XSSDerivationContract` digest + `executed_payload_hash` (null on non-oracle paths) | Contract hash copied from authorization; executed hash computed from wire bytes |
| `template_binding` | `{template_id, template_hash}` for Nuclei; null otherwise | Recomputed from projected bytes (§14) |

`snapshot_binding` is descriptive **pin data**, not permission: drift is
detected by comparison, never auto-accepted.

### 5.2 Hash participation (normative, frozen)

- **`bindings_hash = SHA256(canonicalJSON(B))`** where `B` =
  `{authorization_id, execution_id, execution_stage, artifact_id,
  artifact_content_hash, target_identity{program_name, host, scheme,
  effective_port, path_scope}, test_plan_id, hypothesis_id, match_id,
  snapshot_binding{pins}, derivation_contract_hash, template_binding,
  evidence_schema_version}`.
  `evidence_id` is EXCLUDED (handle, not content).
- **`observations_hash = SHA256(canonicalJSON(O))`** where `O` =
  `{execution_class, canonical_request{method, canonical_url_redacted,
  headers_allowlisted_redacted, body_hash}, canonical_response{status,
  headers_allowlisted_redacted, body_hash, body_sample_hash},
  redirect_chain_canonical_redacted, dial_ips, dns_answers_redacted,
  nuclei{exit_code, timed_out, killed, template_hash, stdout_hash,
  stderr_hash, argv_digest}, browser{dialog_marker_hashes,
  oracle_event_hashes, e_flags, executed_payload_hash, page_url_redacted,
  storage_keys_hash}, transport_outcome}`.
  Raw bodies, raw stdout/stderr, raw page text, raw console text are
  EXCLUDED (only their hashes participate).
- **`content_hash = SHA256(canonicalJSON(C))`** where `C` =
  `{body_sample_bytes_capped, stdout_sample_capped, stderr_sample_capped,
  console_sample_capped, dialog_markers_capped, oracle_events_capped,
  redirect_chain_capped, header_snapshot_capped}` — i.e. exactly the
  bounded persisted samples. Verifies stored bytes, not the world.

**MUST NOT affect any hash:** wall-clock timestamps (`started_at`,
`finished_at`, `sealed_at`), durations, worker PIDs/hostnames, attempt
counters, log offsets, scheduler metadata, audit sequence numbers,
caller-supplied labels, LLM text, `expected_behavior`, notes. Timing data
MUST NOT affect deterministic content identity: two executions with
identical bindings and identical transport facts but different durations
produce identical `bindings_hash` and `observations_hash`.

`evidence_schema_version = "evidence/v1"` participates in `bindings_hash`.

---

## 6. Evidence lifecycle

### 6.1 States (normative — exactly four)

- **`BUILDING`** (alias OPEN): worker-owned, in-memory (or
  worker-local temp file under quota), unsealed, unindexed, invisible to
  verifier and to other workers. Mutations allowed only by the owning
  worker before seal.
- **`SEALED`**: hashes computed and verified, `complete` assigned, bytes
  frozen, content-addressed write done. Immutable. The only
  verifier-eligible state (additionally requiring `complete=true`, §7).
- **`INCOMPLETE`**: sealed partial record (`complete=false`). Immutable
  like SEALED. Never verifier-eligible. Terminal.
- **`ORPHANED`**: not a byte-state — an *index* state meaning "SEALED (or
  INCOMPLETE) bytes exist but are not reachable under their
  `execution_id`/`authorization_id` index entries" (index write failed or
  crashed). Recovery may restore reachability; it never touches bytes.

### 6.2 Legal transitions

```
BUILDING → SEALED        (all required bindings + hashes verify; complete assigned)
BUILDING → INCOMPLETE    (seal attempted but required observations missing; hashes over present fields verify)
BUILDING → ∅             (abandoned pre-seal: OUTCOME_UNKNOWN path; no record persists)
SEALED   → (no transitions; terminal, immutable)
INCOMPLETE → (no transitions; terminal, immutable)
(SEALED | INCOMPLETE) + index-missing → ORPHANED (classification by sweep, not a byte mutation)
ORPHANED → SEALED | INCOMPLETE (re-index only, §18; bytes untouched, byte-identical verification required)
```

**Illegal (each with a dedicated negative test):** `SEALED → BUILDING`;
`INCOMPLETE → SEALED`; `SEALED → INCOMPLETE`; any `→` that changes
`authorization_id/execution_id/target/artifact/bindings/hashes`;
`ORPHANED → new execution_id`; append/patch/repair/rebind/reattach of
sealed bytes under any name including "migration", "backfill", "fixup",
"re-ingest".

Seal is single-writer: the owning worker seals exactly once. Any second
seal attempt for the same `execution_id`+stage is rejected
(`EVIDENCE_IMMUTABLE`).

---

## 7. Complete/incomplete semantics

- `complete: true` means: every required observation for the stage's
  evidence schema is present (request facts, response/process facts,
  chain, hashes, binding refs), every required binding validates, every
  required hash verifies. Closed per-class required-field lists live in
  the `evidence/v1` schema (5H-core contract; no backend needed to freeze
  the lists).
- `complete: false` means: sealed partial — observations exist but at
  least one required element is missing or unverifiable (truncated chain
  beyond cap with overflow flag, body beyond cap with hash-only fallback,
  killed subprocess with exit facts but no output hash, browser death
  after partial channel capture). The record states what is present and
  names the missing elements by code (`EVIDENCE_INCOMPLETE` + detail
  naming the absent fields). It is still hash-covered and immutable.
- Terminal semantics: both `SEALED+complete=true` and `INCOMPLETE` are
  terminal for the execution stage. No stage ever leaves terminal state.
- **Normative rules:** only `complete=true` + all required bindings valid
  + all required hashes valid may enter verifier handoff (§30).
  `INCOMPLETE` MUST NOT be interpreted as a negative finding
  (NOT_VULNERABLE). `INCOMPLETE` MUST NOT be interpreted as a positive
  finding (matched/vulnerable/CONFIRMED). It is execution-data state only.
  Schema enforces this with `extra="forbid"` on all verdict-shaped fields
  and no verdict vocabulary anywhere in the evidence module (review gate).

---

## 8. OUTCOME_UNKNOWN semantics

`OUTCOME_UNKNOWN` is the terminal label for executions where transport may
have started but final state cannot be established: worker crash during
request; connection timeout after bytes may have been sent; browser process
death; Nuclei process death or kill after transport start; crash before
evidence sealing; `requests` timeout with ambiguous server-side effect.

Normative answers:

- **Whether evidence exists:** no sealed evidence exists. A `BUILDING`
  record may exist worker-locally; it is abandoned (deleted under quota),
  never sealed posthumously, never reconstructed from logs. The execution
  ledger records `OUTCOME_UNKNOWN` with the last known stage; that ledger
  entry is accounting, not evidence.
- **Whether retry is allowed:** yes, but NEVER under the same
  authorization. Retry requires a **new authorization** (new issuance,
  new `authorization_id`, new `idempotency_key` with `caller_scope`
  `retry-new-authz`). For stored SUBMIT ambiguity, retry additionally
  requires a **new round** (`round_id` fresh; the old round is dead —
  a possibly-persisted payload with unknown state must never be READ
  under the same round).
- **Whether authorization may be reused:** no. The consumed authorization
  stays CONSUMED. Re-driving the same `authorization_id` returns
  `AUTHZ_ALREADY_CONSUMED` / `EXECUTION_REPLAY`.
- **Whether Stored XSS READ may proceed:** no. READ is never scheduled
  after a SUBMIT with unknown outcome (§11 of 5B arch preserved).
- **Whether verifier may consume it:** no. `OUTCOME_UNKNOWN` has no sealed
  bytes and no handoff object. Any verifier call with an unknown-outcome
  execution reference is rejected (`HANDOFF_REJECTED`).

Rationale: the transport-unknown window (bytes may have left the process)
makes exactly-once unprovable; at-most-once execution is preserved by
forcing new-authorization re-drive while evidence availability is
preserved by keeping the unknown ledger entry queryable.

---

## 9. Hash model

**Canonical choice: SHA-256 everywhere.** Justification: already the
project standard (`content_hash_for_bytes`, `artifact_id_for`,
`content_hash_for_mapping`); 256-bit second-preimage resistance exceeds
the threat (accidental collision, substitution attempts); stdlib-available
deterministically; no new negotiation surface. No alternative is
permitted in 5H-core.

**Canonical serialization (frozen, generalizes
`artifact.py:113–119`):**

1. Model → plain JSON value: mappings only (`dict[str, JSON]`), lists,
   strings, integers, booleans, null. No sets, tuples, floats (ports and
   counts are integers; no NaN/Infinity representable — presence →
   schema rejection), no bytes (bytes enter only via hashes or via
   explicitly-hex/base64-encoded sample fields with a named encoding), no
   datetimes (timestamps excluded from hashes by §5.2).
2. `json.dumps(value, sort_keys=True, separators=(",", ":"),
   ensure_ascii=False)` — key order fixed, no whitespace, Unicode
   preserved as written (not `\uXXXX`-escaped).
3. UTF-8 encode the resulting string. Hash the bytes with SHA-256.
   Hex digest lowercase (64 chars).
4. Field order therefore never matters at input; the digest input order
   is always lexicographic-by-key at every nesting level. Lists preserve
   author order (redirect chains, header snapshots: order is content and
   is hashed as ordered).
5. Integers: decimal JSON integers, no leading zeros, no `1.0`. Booleans:
   `true`/`false` (never `1`/`0`). Null: `null`, and **absent ≡ null is
   FALSE** — a missing optional field and an explicit null MUST serialize
   identically (normalizer injects null for absent optionals before
   hashing) so producer omission cannot fork identity.
6. Newlines/binary: sample text fields are normalized to `\n` line
   endings before hashing; binary samples are hashed as bytes with a
   `sample_encoding` tag (`utf8-text` or `base64`) that participates in
   the hash.
7. Never `repr()`. Never `str(dict)`. Never platform-default encodings.
   Never hash an in-memory object address, iterator order, or timestamp.

Normalizer + hash functions are pure, dependency-free, and shared by
evidence sealing and verifier revalidation (one implementation, both
callers — no per-side variants).

---

## 10. Content policy

**Default: hash always, sample sometimes, full bodies never.**

| Content | Persisted by default | Hash persisted | Sample cap |
|---|---|---|---|
| Request body | hash only | `request_body_hash` SHA-256 of exact wire bytes, always | bounded sample (≤2 KiB) only under explicit per-program flag |
| Response body | hash only | `response_body_hash` SHA-256 of exact received bytes, always | bounded sample ≤8 KiB evidence field (transport may read up to 512 KiB to compute the hash, then discards beyond the sample) |
| Nuclei stdout/stderr | hash only | `stdout_hash`/`stderr_hash` always | combined sample ≤8 KiB (stdout+stderr ≤1 MiB capture cap, then truncate-for-evidence) |
| Browser console/page text | hashes + markers only | per-channel hashes always | markers/samples ≤8 KiB total |
| Decompressed bodies | never beyond cap | hash of decompressed prefix | decompressed ≤2 MiB with compression-ratio abort (≤10× declared size; any gzip bomb shape → abort + `LIMIT_EXCEEDED` + INCOMPLETE) |

Transport caps (enforced, §24): request ≤16 KiB; response post-decompression
evidence sample ≤8 KiB / transport read ≤512 KiB / decompressed ≤2 MiB;
redirect hops ≤5; requests per execution ≤7; chunk-stall timeout aborts slow
drips (body beyond cap → hash-what-was-read + overflow flag, never silent
truncation). Content-Type handling: `text/*`, `*json*`, `*xml*`,
`*x-www-form-urlencoded` are sample-eligible text; `image/*, audio/*,
video/*, font/*, octet-stream, pdf, zip/gzip` are hash-only (no sample,
`sample_omitted: binary-content-type`); charset decoded as declared with
UTF-8-with-replacement fallback, and undecodable bytes fall back to
hash-only. Decompression limited to `gzip/deflate/br` single pass with the
ratio guard; nested archives are not decompressed.

---

## 11. Secret redaction

**Single evidence redaction policy (one shared scrubber, used by HTTP,
Nuclei, browser, audit, and any future summarizer — no per-executor
variants).**

Redact (value → `[REDACTED]`, key preserved) in persisted evidence, audit,
logs, and errors:

- Headers: `Authorization, Cookie, Set-Cookie, Proxy-Authorization,
  Proxy-Authenticate, WWW-Authenticate, X-Api-Key, Api-Key` (case- and
  `-`-insensitive, plus any `*token*`, `*secret*`, `*api*key*`,
  `*session*`, `*auth*` header name pattern).
- URL userinfo (`user:pass@` → stripped; password always redacted even in
  forensic chain copies) and secret-shaped query/form values: parameters
  named `*password* *passwd* *secret* *token* *api_key* *apikey*
  *access_token* *refresh_token* *session* *auth* *bearer* *private_key*
  *connection*string* *mongo*` (values → `[REDACTED]`, names preserved).
- Body/secret patterns: `mongodb://`, `postgres://`, `mysql://`,
  `redis://`, `amqp://` URIs (full value redacted); `-----BEGIN … PRIVATE
  KEY-----` blocks; `Bearer <…>`, `Basic <…>`; `AKIA…`-shaped keys,
  `ghp_/gho_/github_pat_`, `xox[bpas]-`, `sk-live/sk-test` — on
  high-confidence operational-secret match the evidence seals with the
  value redacted and a `secret_redacted: true` flag; tuning of broader
  heuristics is 5H-store work and MUST bias toward over-redaction.
- Browser storage keys/values, stdout/stderr secret-pattern hits,
  Nuclei output secret hits, error strings carrying any of the above.

**SECURITY-CRITICAL SECRET vs NORMAL TARGET DATA:** secrets are
credential-shaped values that authenticate or authorize (tokens, keys,
passwords, cookies, connection strings, private keys, session identifiers).
Normal target data is everything else — page text, reflection snippets,
status codes, banner strings, correlation tokens (non-secret by policy),
timing values. Target data is bounded and hashed; secrets are never
persisted, never hashed into identity (secret header values excluded from
hashes — preserves `http_executor` precedent), never logged.

**Prohibitions (each test-pinned):** no raw exception strings into
evidence (sanitized reason codes only, ≤200 chars); no secrets into audit
(hashes + decisions only); no secrets into LLM context (§29 — evidence
does not enter LLM context by default at all).

---

## 12. URL evidence

Each evidence record stores two URL forms per hop:

- `canonical_url`: full canonicalization per 5B arch §18 (lowercased
  scheme/host, trailing-dot stripped, IDNA punycode, defaulted effective
  port recorded separately, dot-segments resolved, double-encoding
  rejected, fragment dropped, query preserved byte-exact for transport).
  Used for scope comparison, cycle detection, cache keys.
- `redacted_url`: `canonical_url` with userinfo stripped and secret-shaped
  query/form values replaced (`?token=[REDACTED]`). This is the ONLY form
  persisted in evidence/audit.

Stored per hop: `{seq, canonical_hash, redacted_url_capped(2 KiB),
redacted_query_hash}`. Raw query strings are retained ONLY under the same
explicit per-program flag as body samples, capped at 2 KiB, redacted.
Fragments are never stored (never sent). `Location`/object-hint strings are
scrubbed identically (capped 2 KiB) before persistence. Redirect chain
capped at 5 hops + overflow flag.

**Normative statement: evidence URLs are observations only. They cannot
authorize future requests.** No executor, scheduler, resolver, or verifier
may treat a persisted URL as permission, allowlist entry, or replay
target. Re-execution requires fresh authorization + fresh resolution +
fresh scope evaluation. Review gate: no import path from evidence-store
read APIs into executor request-construction code.

---

## 13. Header evidence

**Allowlist (persisted; everything else dropped):**

- Request: `Host, User-Agent(watch-fixed value only), Accept,
  Accept-Language, Accept-Encoding, Content-Type, Content-Length,
  Referer(canonicalized), Origin(canonicalized), X-Requested-With,
  If-None-Match, If-Modified-Since`.
- Response: `Content-Type, Content-Length, Content-Encoding, Server,
  X-Powered-By, X-Content-Type-Options, X-Frame-Options,
  Content-Security-Policy, Location(redacted form), Strict-Transport-Security,
  WAF-vendor banner headers (values truncated, names allowlisted per
  vendor list), ETag, Last-Modified, Date, Status`.

**Default-deny:** `Cookie/Authorization/Set-Cookie/proxy-*/WWW-Authenticate`
values never persisted (key + `[REDACTED]`); unknown headers dropped
(name hashed into an `unknown_headers_hash` counter so presence is
detectable without storage). Caps: ≤32 headers per message, name ≤128
chars, value ≤1 KiB, total header snapshot ≤8 KiB; overflow → truncate with
`headers_truncated: true` flag (flag participates in observations hash;
dropped bytes do not).

---

## 14. Nuclei evidence

Nuclei output is **untrusted evidence** — hostile-template-controlled bytes
that must survive a compromised-template threat without becoming a verdict.

Persisted per Nuclei execution: `template_id + template_hash` (SHA-256 of
the exact projected YAML bytes — recomputed, never copied from the
template file name); `argv_digest` (SHA-256 of the exact argv list);
`target_identity` (copied from authorization); `exit_code` (integer),
`timed_out`/`killed` booleans; `stdout_hash`, `stderr_hash` (always);
bounded samples (combined ≤8 KiB); `finding_like_text_present: bool`
(advisory — records that the output *contains* finding-shaped words, never
what they assert).

**Explicitly prohibited (schema + test):** `stdout → matched`;
`stdout → vulnerable`; `stdout → confirmed`; any path by which
nonempty/pretty/keyword-bearing output becomes a positive label. The only
consumer of Nuclei evidence is the future 5I classifier under conservative
positive bars; the 5H-core contract exposes no boolean or label the
classifier could inherit blindly. `NucleiRunner.to_findings` must be
deleted or hard-gated (`legacy_unsafe=True`, forbidden in executor paths)
before 5F — §35 gate G-5F asserts its absence.

---

## 15. Browser/XSS evidence

Per browser execution, persisted as hashes + bounded markers (never raw
page dumps):

- `dialog_events`: capped list (≤16) of `{kind, marker_hash}` — the oracle
  marker string itself is hashed, not stored.
- `oracle_network_events`: capped list (≤16) of `{path_hash,
  marker_hash}` for `/.watch-oracle/<D>` hits.
- `eval_invocations`: capped list (≤16) of `{snippet_hash, marker_hash}`.
- `e_flags`: `{E1, E2, E3}` booleans as *executor-observed predicate
  outputs* (advisory; verifier recomputes independently).
- `executed_payload_hash` (SHA-256 of exact wire bytes O) AND
  `artifact_content_hash` (P, copied from authorization) — **separately
  represented, always**. Oracle paths expect inequality; plain
  HTTP-reflection paths expect equality; violations → `EVIDENCE_MALFORMED`,
  no handoff (§10 of 5B arch preserved).
- `request/response` facts and `redirect_chain` per §10/§12 (redacted,
  capped); `page_url` canonical + redacted (observation only).
- Stored round: SUBMIT record and READ record are separate evidence rows
  sharing `round_id` but with distinct `evidence_id`/`execution_id`s;
  clean-READ attestation (`fresh_context: true`, `prior_storage_cleared:
  true`) recorded as booleans; READ evidence additionally binds the
  SUBMIT `evidence_id` by hash reference (not by mutation).

Page content is never persisted beyond the 8 KiB total sample budget;
arbitrary browser page text can never become evidence authority — only the
structured oracle channels plus verifier-recomputed predicates classify.

---

## 16. Evidence binding

Each evidence record binds to eight axes. For each: what is copied, what
is recomputed, and what the verifier checks:

| Axis | Copied verbatim from authorization | Independently recomputed | Verifier revalidation |
|---|---|---|---|
| Authorization | `authorization_id`, issuance nonce reference, lifecycle-live proof token | nothing (provenance is store-side) | reloads issuance record via typed API; `AUTHZ_NOT_LIVE` → `HANDOFF_REJECTED` |
| Execution | `execution_id`, `execution_stage` | worker asserts stage-lease ownership (CAS) | `execution_id`+stage match the ledger; lease consumed by the same worker |
| Target | full `target_identity` tuple + `scope_policy_version/hash` | canonicalized host/port re-derived at seal; dial-IP set observed | re-resolves current inventory; mismatch → stale (`HANDOFF_REJECTED`) |
| Artifact | `artifact_id`, `artifact_content_hash`, type | content hash recomputed from store bytes at seal | recomputes `artifact_id_for()`; any divergence → reject |
| Test plan | `test_plan_id`, `hypothesis_id`, `match_id` | nothing | exact-equality vs plan record |
| Stage/derivation | derivation-contract hash, `round_id`, phase | `executed_payload_hash` from wire bytes; P/O equality expectation checked | contract equality + dual-hash expectation |
| Scope policy | `scope_lists_hash`, CDN mapping version+hash | per-hop scope decisions recomputed from fresh lists | replays scope evaluation over the sealed chain; any DENY-hop → reject |
| Freshness | `issued_at`, `expires_at`, `sealed_at` | nothing (timestamps observed) | `sealed_at ≤ expires_at`; staleness window per 5I policy |

A verifier MUST detect: wrong artifact, wrong target, wrong program
(`program_name` is part of the isolation key — cross-program same-host
confusion structurally impossible), wrong authorization, wrong execution,
stale evidence (target reassigned / scope lists drifted / authorization
expired post-seal), altered observations (`observations_hash` mismatch),
altered content (`content_hash` mismatch). Any single failure →
`HANDOFF_REJECTED`, no partial consumption.

---

## 17. Immutability

Sealed evidence (SEALED or INCOMPLETE) is immutable by construction:
content-addressed storage keyed by `content_hash`, no update API on the
store (§25), `extra="forbid"` schemas with no patch constructors, and
CAS-free terminal states (there is nothing to CAS *to* — terminals absorb
all transitions).

**No-rebinding invariant (normative):** a sealed record can never be
reassigned to another authorization, execution, target, artifact, program,
or test plan. There is no `reassign()`, no `repaired_copy()`, no
`supersede()`, no "same bytes, new key" writer. Orphan recovery (§18) may
restore an index entry **only if** the original binding tuple
(`authorization_id, execution_id, stage, artifact triple, target tuple,
contract hash`) is byte-identical to the sealed bytes' embedded bindings
AND both `bindings_hash` and `content_hash` re-verify. Any byte difference
→ recovery refused, record stays ORPHANED, operators paged.

---

## 18. Orphan recovery

**Orphan** = sealed bytes exist and verify, but no reachable index entry
under (`execution_id` | `authorization_id` | `evidence_id`) — typically
"seal succeeded, index write crashed" or "index write succeeded, ack lost".

- **Detection:** periodic sweep (5H-store runtime; contract here) scans
  content-addressed extents for records absent from all three indexes, and
  scans index entries pointing at absent bytes (the latter are corruption,
  not orphans — quarantined, never "repaired" by synthesis).
- **Classification:** `INDEX_MISSING_SEALED` (recoverable candidate),
  `INDEX_MISSING_INCOMPLETE` (recoverable candidate, stays INCOMPLETE),
  `BYTES_MISSING` (corruption — never recoverable by construction),
  `BINDING_AMBIGUOUS` (bytes verify but match multiple index intents —
  never recovered; quarantined).
- **Recovery preconditions (ALL required):** bytes parse under
  `evidence/v1` schema; `bindings_hash` + `content_hash` recompute-equal;
  embedded binding tuple equals the claimed index key exactly; referenced
  authorization record still exists (liveness NOT required — recovery is
  accounting restoration, not re-authorization); no live index entry
  already claims the key (collision → quarantine, page operator).
- **Re-index conditions:** recovery writes ONLY the missing index
  entries, containing the original keys + hashes — never new bindings,
  never a new `execution_id`. The operation is idempotent and logged to
  the audit trail as `ORPHAN_REINDEXED` with both hashes.
- **Garbage collection / retention:** unrecoverable orphans are retained
  per §33 quarantine retention, then deleted with tombstones. Recovered
  orphans follow normal evidence retention. Sweep metrics (orphan count,
  age histogram, recovery outcomes) are monitored with alert thresholds
  (§35 gate G-5H-core asserts sweep + quarantine paths on fakes).

No evidence may ever be attached to a new execution through recovery.

---

## 19. Idempotency

**Frozen model (5B claim reviewed and KEPT): AT-MOST-ONCE EXECUTION with
AT-LEAST-ONCE EVIDENCE AVAILABILITY, via cross-process unique index +
atomic CAS.** Review outcome: the claim is sound and correctly scoped —
"at-most-once" refers to transport execution (one CAS winner per
authorization/lease), "at-least-once" refers to evidence *read
availability* (dedupe-on-read serves the winner's sealed bytes to losers
after binding revalidation). It does not promise exactly-once transport
(the transport-unknown window makes that unprovable) and does not promise
availability of evidence that was never sealed (OUTCOME_UNKNOWN has no
bytes to serve). No correction needed; the wording is frozen as normative.

- **`idempotency_key`** (5B, unchanged): plan + artifact triple + target
  binding + execution class + scope-lists hash + caller scope (fixed
  vocabulary `manual/scheduled/retry-new-authz`) + issuance nonce.
  Deterministic dedupe key only — never proof.
- **`execution_id`**: random 128-bit, minted once by the CAS winner at
  `EXECUTION_STARTED`. Losers never mint one.
- **Lifecycle:** `ISSUED → CONSUMED` (single execution) / stage leases
  `PENDING → CONSUMED/FAILED/SKIPPED` (stored rounds) — all CAS-guarded
  on `record_version`, exactly +1, identity-rebind refused (5B
  `store.py:135–175` semantics generalized to the execution ledger).
- **Lease:** the CAS win IS the lease. No TTL-based lease expiry exists
  (expiry would reintroduce double-execution); crashed holders resolve
  through the crash matrix (§20), not through lease timeout.
- **Consumed state:** authorization CONSUMED + sealed evidence indexed →
  duplicate request returns the existing `evidence_id` ONLY after binding
  revalidation against current resolution (stale target → refuse serve,
  `STALE_EVIDENCE`, new authorization required).
- **Duplicate request:** same key, no record → proceed; live lease →
  `EXECUTION_IN_PROGRESS` (poll, never second-start); sealed →
  dedupe-on-read above; unknown → `OUTCOME_UNKNOWN` path (§8).
- **In-progress / unknown / sealed:** three distinct CAS-observable states
  with distinct responses; conflating in-progress with unknown is a
  defect (gate test).

Process-local locks (threading, file locks, in-memory dicts) confer zero
cross-process guarantees and MUST NOT appear in the idempotency path
except as best-effort local coalescing *inside* a correct CAS.

---

## 20. Crash matrix

Legend: `retry?` = new attempt allowed; `same-authz?` = reuse permitted
(ALWAYS NO post-start); `evidence` = resulting record state; `verifier` =
handoff eligibility (ALWAYS NO except row 8).

| # | Crash point | Retry? | Same authz? | New authz? | New execution_id? | Evidence state | Audit state | Verifier? |
|---|---|---|---|---|---|---|---|---|
| 1 | Before authorization consume | yes | yes (still ISSUED) | not needed | none yet | none | `AUTHORIZATION_ISSUED` only | no |
| 2 | After consume, before EXECUTION_STARTED | yes, re-drive | NO — consume already won; re-drive reads winner binding | only if record lost (never: store is durable) | winner's id kept | none (ledger `START_PENDING`) | `AUTHORIZATION_CONSUMED` + gap note | no |
| 3 | Before EXECUTION_STARTED (holder crash) | yes, same binding | n/a (same execution resumes intake) | no | same (already minted) | none | `EXECUTION_STARTED` retried idempotently on same key | no |
| 4 | After EXECUTION_STARTED, pre-transport | yes, same execution continues | n/a | no | same | BUILDING (worker-local) | `EXECUTION_STARTED` present | no |
| 5 | After request bytes may have left process | yes, ONLY new authz | NO | YES (`retry-new-authz`) | YES fresh | old: abandoned BUILDING → ledger `OUTCOME_UNKNOWN`; new: fresh BUILDING | `OUTCOME_UNKNOWN` terminal for old id | NO (old); new id only when sealed complete |
| 6 | After response received, pre-seal | depends: unambiguous response facts → same execution may seal; ambiguous → row 5 | n/a | only if ambiguous | same if sealing; fresh if ambiguous | SEALED/INCOMPLETE or OUTCOME_UNKNOWN | terminal accordingly | only if sealed complete |
| 7 | Before evidence seal (crash) | row 5 rules (transport may have started → unknown) | NO | YES | YES | none sealed; ledger `OUTCOME_UNKNOWN` | `OUTCOME_UNKNOWN` | no |
| 8 | After evidence seal, pre-index | recovery, not retry | n/a | no | same | SEALED + ORPHANED(index) | `EVIDENCE_SEALED` missing → sweep finds orphan | YES after re-index (§18) — the ONLY post-crash verifier path |
| 9 | After index write, pre-audit | no retry (work is done) | n/a | no | same | SEALED, indexed | `AUDIT_GAP` record (§21) | yes (evidence complete; audit gap is separate) |
| 10 | Before audit write (pre-start) | blocked | yes (unconsumed) | no | none | none | missing START → execution refused until audit restored | no |
| 11 | After audit write | normal flow | n/a | no | same | per stage | complete chain | per evidence state |
| 12 | Worker dies (any point) | per row matching death point | per row | per row | per row | BUILDING abandoned on worker-local death; sealed bytes survive (content-addressed) | ledger shows last acked transition; unacked work → unknown/orphan per rows 5/8 | per row |
| 13 | Process restarts | same as 12; no in-memory state trusted across restart | NO post-start | YES post-start | YES post-start | re-derived from store, never from memory | re-read from audit trail | per row |
| 14 | Duplicate queue message | no (dedupe-on-read) | n/a | no | same winner | winner's bytes served after revalidation | `EXECUTION_DUPLICATE` note | winner's eligibility only |
| 15 | Duplicate scheduler invocation (distinct caller key) | distinct keys are distinct intent BY DEFINITION (rate-limited per program/window; double-issuance is operator-visible) | n/a | second issuance exists independently | fresh | independent | independent chains | independent |

Post-start rows share one invariant: **the same authorization never
executes twice, and the old execution never "completes later"** — orphans
are re-indexed, never finished; unknowns are re-driven under new keys,
never resumed.

---

## 21. Audit ordering

Append-only, write-ahead START / write-once terminals, one record per
transition. Required logical ordering per execution (sequence numbers
enforce; out-of-order arrival → quarantined, never reordered by rewrite):

```
AUTHORIZATION (issued/consumed) → EXECUTION_STARTED → EXECUTION_STAGE (per stage/lease)
  → EVIDENCE_SEALED (hashes) → EXECUTION_TERMINAL (complete/incomplete/unknown)
  → VERIFIER_HANDOFF (accepted/rejected)
```

Audit records are accounting, never authority: no executor reads audit to
decide permission (permission comes from the issuance store + live
bindings); no verifier trusts audit over recomputed hashes.

**Audit-storage failure:** BEFORE execution (START unaudited) → fail
closed, no transport, `AUDIT_GAP` blocks intake. AFTER execution start →
do NOT mutate sealed evidence; write a separate `AUDIT_GAP` record
(`execution_id`, missing sequence range, last-good hash, error code) that
the sweep reconciles. The 5A seal/annotate contradiction is resolved: gap
records are siblings of evidence, never annotations on it.

---

## 22. Audit content

Each audit record: `{execution_id, authorization_id, evidence_id (post-seal
only), stage, transition, at (ISO wall-clock, audit-only, never hashed),
actor (worker identity, never a secret), target_binding (canonical host +
program + port + path_scope), scope_decision + reason_code, artifact triple
(ids + hashes), fixture_binding (hashes), derivation refs (contract hash +
phase), evidence hashes (post-seal: all three), error_code (closed
vocabulary, §32)}`.

MUST NOT contain: credentials, connection strings, raw bodies, raw browser
pages, raw stdout/stderr, raw DB exceptions, secret query/form values,
full header snapshots, LLM text. Decisions are recorded as codes +
bounded reason strings (≤200 chars, secret-screened at construction like
5B `AuthzError`).

The chain `authorization → execution(s) → evidence → verifier handoff` is
reconstructable from audit alone (ids + hashes), while trust comes from
recomputation, never from audit prose.

---

## 23. Resource ceilings

Global immutable ceilings module (`evidence/v1` companion, frozen here,
implemented in 5H-core). Operator configuration may ONLY tighten. Boot
asserts `configured ≤ ceiling` on every dimension; any exceed attempt or
any unknown/unbounded value → fail closed at boot (`LIMIT_EXCEEDED` /
`LIMIT_UNKNOWN`, no executor starts).

Reconciled against HEAD reality (10 s HTTP timeout, 120 s Nuclei, 10+5 s
browser in-tree) with conservative tightening where HEAD is looser than
the 5B proposal:

| Dimension | Immutable ceiling (tighten-only) | Notes |
|---|---|---|
| HTTP wall time per execution | 60 s | HEAD default 10 s transport; ceiling bounds total incl. redirects |
| Nuclei wall time per execution | 120 s | matches HEAD `timeout=120`; no increase permitted |
| Browser wall time per execution | 15 s (10 nav + 5 obs) | matches HEAD split exactly |
| Connect timeout | 10 s | per-attempt dial cap |
| Read timeout | 10 s | per-read cap |
| Chunk-stall timeout | 10 s | slow-drip kill |
| Request body size | 16 KiB | larger → `TRANSLATION_REJECTED` pre-start |
| Response transport read | 512 KiB | then stop, hash, overflow flag |
| Response evidence sample | 8 KiB | hash-default beyond |
| Decompressed size | 2 MiB | with ratio abort |
| Compression ratio | 10× declared | bomb shape → abort + `LIMIT_EXCEEDED` + INCOMPLETE |
| Redirect hops | 5 | per-hop scope enforced |
| Requests per execution | 7 | initial + hops + one retry-space inside same execution pre-transport only |
| DNS answers evaluated | 8 | any-denied → deny; beyond → deny |
| Browser pages / contexts | 1 / 1 | per execution; overflow → refuse start |
| Nuclei concurrency / rate / retries | 1 / ≤5/s / 0 | argv-pinned |
| Nuclei stdout+stderr capture | ≤1 MiB | then kill + hash-what-was-read |
| Temp storage per execution | 16 MiB | executor-owned `0700` dir, `O_NOFOLLOW`, exclusive create |
| Memory per subprocess | 512 MiB RLIMIT_AS | sandbox-enforced |
| CPU per subprocess | 60 s RLIMIT_CPU | sandbox-enforced |
| Pending authorizations | 1000 | overflow rejects issuance |

Do NOT optimize for convenience: these are containment boundaries, and
every live-fire gate (§35) tests at least one ceiling breach.

---

## 24. Enforcement locations

A limit that exists only in Python metadata is not a boundary. Each
ceiling binds to an enforcement point:

- **Transport (pinned adapter):** connect/read/chunk-stall timeouts,
  response-size cap, decompression cap + ratio abort, per-hop scope,
  redirect/request counts, DNS-answer cap.
- **Worker (supervisor):** wall-time kill (HTTP 60 s / Nuclei 120 s /
  browser 15 s) + reap check (zombie/orphan subprocess reaped, recorded).
- **Subprocess (sandbox):** `RLIMIT_AS`/`RLIMIT_CPU`, env scrub, argv
  allowlist, `shell=False`, capture caps, kill-on-ceiling with
  `timed_out/killed` facts recorded into evidence (not prose).
- **Browser (executor + mp supervise):** page/context counts, navigation +
  observation windows, route policy (defense-in-depth behind
  resolver/proxy pinning).
- **Filesystem:** temp quota per execution, `0700` ownership, `O_NOFOLLOW`,
  post-run deletion, evidence-sample caps at seal time.
- **Evidence capture:** sample caps, header allowlist + count/size caps,
  chain caps, redaction pass (a cap bypass that leaks a secret is a
  defect, not an overflow).
- **DNS/resolver:** answer-count cap, per-address IP policy, rebinding
  detection (first-resolution pin per execution, mismatch → abort).
- **Queue/scheduler:** pending-authorization cap, per-program/window rate
  limits on issuance, caller-scope vocabulary enforcement, duplicate-message
  dedupe-on-read.

Constructor parameters may *reflect* ceilings (defaulting at or below
them) but never *define* them: the ceilings module + boot assert +
point-enforcement above is the boundary. A test constructs each executor
with an over-ceiling value and expects boot/init refusal.

---

## 25. EvidenceStore architecture

Future immutable store (contract frozen here; backend in 5H-store). Server-side,
content-addressed, mirroring `ArtifactStore` atomic-write discipline lifted
to cross-process durability:

- **Writes:** `put_sealed(record) -> evidence_id` — single call that
  validates schema, recomputes all three hashes, checks binding coherence
  vs the issuance record, performs atomic content-addressed write
  (temp-file + rename + fsync, unique temp names), then atomically inserts
  index entries. Partial failure → orphan path (§18), never half-visible
  evidence.
- **Reads:** `get_by_evidence_id`, `get_by_execution_id`,
  `get_by_authorization_id` — all return deep copies; all re-verify hashes
  on read (like `ArtifactStore` read-path revalidation); mismatch →
  `EVIDENCE_HASH_MISMATCH`, quarantine, page operator.
- **Scans:** `orphan_scan()` (bytes-without-index + index-without-bytes),
  `retention_scan()` (expiry + tombstone eligibility).
- **MUST NOT provide:** `update`, `patch`, `reassign`, `rebind`,
  `delete_arbitrary`, `set_verdict`, or any verdict-mutating helper. No
  such symbol may exist in the module (static review gate, mirroring the
  5B `authorize_from_*` absence gate).
- **Atomicity:** bytes-first-then-index; readers never observe
  half-written bytes (exclusive-create + fsync ordering); concurrent
  writers converge on content-hash keys (same bytes → same key,
  idempotent; different bytes under same execution key → second writer
  gets `EVIDENCE_IMMUTABLE`).
- **Integrity:** content-addressing (`content_hash` = storage key) or
  explicitly-justified equivalent (WORM volume with hash manifest —
  rejected as default for operational cost; content-addressing is the
  frozen choice).

---

## 26. Concurrency

Adversarial pairs analyzed; each resolves to a store primitive, never to a
process-local lock:

- Two workers / same authorization / same stage: CAS `ISSUED→CONSUMED`
  (or lease CAS) — exactly one winner executes; losers read back the
  winner's `execution_id` and poll/serve, never start.
- Two workers / same `execution_id` / same evidence: content-key
  idempotence — second `put_sealed` with byte-identical bytes succeeds
  silently (same key); with differing bytes fails `EVIDENCE_IMMUTABLE`.
- Same idempotency key / different process / restart / retry: unique
  index on `idempotency_key` — duplicate issuance fails closed at the
  store (`DuplicateIdempotencyKeyError` → winner lookup, 5B semantics).
- Same evidence / duplicate queue message / duplicate scheduler
  invocation: dedupe-on-read + `EXECUTION_DUPLICATE` audit note.
- Restart mid-lease: no memory trusted; winner re-derived from ledger;
  crashed-holder rows resolve per §20 (unknown, never auto-resumed).

**Mongo guarantees relied on:** unique-index enforcement (atomic at the
storage engine), single-document atomic compare-and-set via
`findOneAndUpdate` with version predicate (all-or-nothing, linearizable
within the replica set). **NOT relied on:** multi-document transactions
for the hot path (kept single-document to avoid transaction-timeout
windows); any causality spanning two documents (bytes + index) is
reconciled by the orphan sweep, not by transactions. Anything needing
cross-document atomicity the database cannot give is redesigned into
single-document CAS + sweep (this is why orphans exist as a designed
state, not as a failure surprise).

---

## 27. Mongo/backend decision

**NORMATIVE CHOICE: MongoDB unique index + atomic update/CAS — the 5B
report's preferred safe default is FROZEN as the 5H-core architecture.**
The dedicated lock/idempotency service is REJECTED for 5H-core: it adds a
new stateful component, a new failover story, and a new consistency
boundary for zero additional guarantee (it would itself need exactly the
unique-index + CAS semantics Mongo already provides, plus cross-service
clock agreement for leases — which §19 eliminates by design).

MongoEngine setup in HEAD (`database/db.py`) already demonstrates the
required pattern (`meta.indexes` with `unique: True` on five collections);
the executor database follows the same pattern in its own database/collections
(isolated from crawl/inventory collections — never co-mingled, so
crawler write pressure cannot contend with execution CAS).

- **Collections:** `exec_authorizations` (5B issuance records),
  `exec_ledger` (execution lifecycle + stage leases, one document per
  execution), `exec_evidence_index` (evidence_id/execution_id/
  authorization_id → content_hash + three hashes + completeness), plus the
  content-addressed byte extents (filesystem WORM or GridFS-equivalent —
  backend detail for 5H-store; contract here requires bytes-immutable +
  hash-keyed).
- **Unique indexes:** `exec_authorizations(authorization_id)`,
  `exec_authorizations(idempotency_key)`, `exec_ledger(execution_id)`,
  `exec_ledger(authorization_id, execution_stage)` (one row per stage),
  `exec_evidence_index(evidence_id)`, `exec_evidence_index(execution_id,
  execution_stage)`.
- **Lifecycle update semantics:** all transitions are
  `findOneAndUpdate({id, record_version: expected}, {$set: {…,
  record_version: expected+1}})`; zero matched documents → read-then-map
  to `VersionConflictError`/`EXECUTION_IN_PROGRESS`/`EXECUTION_DUPLICATE`
  (never blind retry — losers follow the §19 loser path).
- **Version field:** `record_version: int`, monotonically +1, identity
  fields immutable under CAS (rebind attempt → refusal, 5B
  `store.py:165–175` generalized).
- **Orphan scan:** queries for index-absent sealed bytes (extent listing
  vs index) and byte-absent index entries; runs on a schedule plus at
  boot; results feed §18 classification.
- **Crash behavior:** per §20; durability comes from journaled writes
  (majority write concern on CAS + index inserts; read concern majority
  for verifier handoff reads).

No database changes are made in this phase (§41).

---

## 28. Access control

| Principal | Write evidence | Seal | Read evidence | Orphan recovery | Retention | Hand to verifier |
|---|---|---|---|---|---|---|
| Owning executor worker | BUILDING bytes only | own stage only | own records | no | no | no (emits handoff request; handoff service assembles) |
| Handoff service | no | no | sealed + complete only | no | no | yes (one-way, §30) |
| Sweep/recovery job | no | no | sealed bytes + indexes | re-index only (§18) | quarantine recommendation | no |
| Retention job | tombstone only | no | hashes + metadata | no | yes (per §33) | no |
| Human operator / auditor | no | no | redacted reads, role-gated, logged | approve-only | hold-only | no |
| Verifier | no | no | sealed + complete via handoff only | no | no | n/a (consumer) |
| LLM / research agent / scheduler / artifact generator | **NO** (all forms) | **NO** | **NO** (no raw evidence reads) | **NO** | **NO** | **NO** |

Prohibitions enforced by module ACL + import gates (executor evidence-write
symbols unimportable from researcher/scheduler/LLM packages — static test),
not by string-field checks. The handoff service holds read-sealed +
handoff-emit rights and no write rights; recovery holds re-index rights
and no byte-write rights; retention holds tombstone rights and no
content-delete rights (tombstones hide, never overwrite).

---

## 29. LLM boundary

**Normative rule: EVIDENCE DOES NOT ENTER LLM CONTEXT BY DEFAULT.** No
research, planning, summarization, or triage prompt receives evidence
bytes, samples, URLs, headers, stdout/stderr, console text, or hashes
(except artifact-content hashes already visible pre-execution) unless ALL
of the following hold: an explicit per-use allowlist names the exact
fields; the redaction pass (§11) has run; samples are bounded (≤2 KiB per
field); no secret-shaped, authority-shaped, or credential-shaped field is
included; no evidence field is ever interpreted as an instruction,
permission, or follow-up target (no direct execution feedback loop —
follow-ups need new plans + new authorizations through the normal gates).

This phase defines the boundary only: no summarizer is designed, no
prompt template is touched, and the implementation gate (§35 G-5H-core)
includes a context-flow audit asserting zero evidence→LLM imports.

---

## 30. Verifier handoff

Immutable handoff object `EvidenceHandoff{evidence_id, execution_id,
authorization_id, execution_stage, artifact triple + hashes, target tuple,
contract/template hashes, bindings_hash, observations_hash, content_hash,
complete: true, sealed_at, issuance-record copy}`. Assembled ONLY by the
handoff service, ONLY for `SEALED + complete=true` records. Contains
references + hashes — **never a vulnerability verdict, never a label,
never a severity, never matched/vulnerable/CONFIRMED/NOT_VULNERABLE.**

Verifier independently revalidates before touching content: schema parse;
all three hashes recomputed; `complete=true`; authorization live (typed
reload); execution binding (ledger match); target binding (fresh
resolution — stale → reject); artifact binding (`artifact_id_for()`
recompute); derivation/template expectations (P/O equality rule);
scope-policy replay over the sealed chain; freshness (`sealed_at ≤
expires_at`). **Any mismatch → `HANDOFF_REJECTED`.** No partial credit, no
"accept observations, flag bindings" mode. Handoff is one-way: results
never flow back into execution (no verdict-driven re-probing).

---

## 31. Error model

Bounded, non-secret, closed vocabulary (extends 5B's 15 codes; unknown
codes rejected at construction; details ≤200 chars, secret-screened):

```
EVIDENCE_NOT_FOUND  EVIDENCE_IMMUTABLE  EVIDENCE_BINDING_MISMATCH
EVIDENCE_HASH_MISMATCH  EVIDENCE_INCOMPLETE  EVIDENCE_MALFORMED
OUTCOME_UNKNOWN  EXECUTION_DUPLICATE  EXECUTION_IN_PROGRESS
EXECUTION_REPLAY  ORPHAN_EVIDENCE  ORPHAN_REINDEXED  AUDIT_GAP
LIMIT_EXCEEDED  LIMIT_UNKNOWN  HANDOFF_REJECTED  STALE_EVIDENCE
AUTHZ_NOT_LIVE (5B re-export, handoff context)
```

No raw exception strings. No connection strings. No credentials. No
file paths beyond the executor-owned temp dir name. No query values.
Service layers map raw failures (DB errors, timeouts, crashes) to these
codes at the boundary — the mapping itself is reviewed as a gate item.

---

## 32. Retention

Safe defaults (operator-tunable within bounds; shortening below minimums
requires security sign-off; holds override everything):

- Sealed evidence: 180 days, then tombstone (index hides, bytes
  quarantined 30 days, then destroyed). Tombstone record
  `{evidence_id, content_hash, destroyed_at, reason, authorizer}` persists
  1 year — deletion never silently replaces history.
- Audit trail + gap records: 1 year (append-only; never deleted early).
- Orphan quarantine: 30 days (recovery window), then tombstone path.
- Legal/security hold: boolean flag on index entries; held records are
  exempt from all deletion passes until hold release (release itself
  audited).

Deletion semantics: hide-then-destroy with tombstones; no in-place
overwrite; no key reuse (`evidence_id`/`execution_id` never recycled);
retention-sweep runs are audited (counts destroyed/held/skipped). Access
logging: every evidence read logs `{reader, evidence_id, at, purpose}`
(hashed purpose codes, no content).

---

## 33. Threat model

For each: attacker input → boundary → attack → control → residual risk.

1. **Evidence rebinding** — forged `execution_id` on stolen bytes →
   seal/lookup → attach bytes to attacker's execution → §16 eight-axis
   revalidation + §17 no-rebind invariant → residual: issuance-store
   compromise (out of scope, monitored).
2. **Mutation after sealing** — worker writes "fixup" → store API →
   second write under same key → no update symbol exists + content-key
   collision → `EVIDENCE_IMMUTABLE` → residual: storage-layer bitrot
   (hash-on-read detects; quarantine).
3. **Forged evidence** — synthesized record with copied hashes → handoff →
   pass as genuine → hashes recomputed by verifier, not compared as
   strings; provenance requires store read → reject → residual: none
   structural.
4. **Hash collision/substitution** — crafted body with same SHA-256 →
   seal → second-preimage → SHA-256 strength + dual-hash (observations +
   content) → residual: cryptographic (accepted, standard).
5. **Secret leakage** — credential in response/URL/stdout → capture →
   persist to evidence/audit/LLM → §11 scrubber + hash-default + no-LLM
   rule → residual: novel secret shapes (over-redaction bias + tuning).
6. **LLM evidence injection** — prompt containing evidence-shaped text →
   scheduler intake → mint execution → typed channel (no parse path) +
   §29 boundary → residual: none structural.
7. **Nuclei stdout as finding** — `matched=true` text in stdout → handoff →
   CONFIRMED → §14 prohibition + `to_findings` deletion + 5I bars →
   residual: none after deletion (gate-enforced).
8. **Browser page text as oracle evidence** — page echoes marker without
   execution → channel → predicate true → capability transport +
   exact-predicate + anti-harvest + hash channels (§15) → residual:
   renderer 0-day (sandboxed).
9. **XSS P/O confusion** — report O as P → binding → misattributed
   authorization → dual hashes + equality-expectation rule → malformed →
   residual: planner-version drift (contract pins versions).
10. **Duplicate execution** — replay `authorization_id` → intake → second
    transport → CAS single-consume + loser reads winner → residual: none
    structural.
11. **Crash/retry execution** — retry same authz post-start → intake →
    double side-effect → §20 (new-authz rule) + `EXECUTION_REPLAY` →
    residual: operator re-drive latency (accepted).
12. **Orphan hijack** — claim orphan bytes for new execution → recovery →
    attach → byte-identical + original-key-only rule (§18) → residual:
    sweep-monitoring gap (alerted).
13. **Audit gap exploitation** — suppress audit write → execute unaudited →
    pre-start fail-closed + post-start gap records + sweep → residual:
    short unreconciled window (bounded, alerted).
14. **Resource exhaustion** — many authorizations → issuance → store/queue
    flood → 1000-pending cap + per-program rate limits → residual:
    distributed issuance cost (rate-limited, visible).
15. **Oversized response** — 100 MB body → capture → disk/memory blowout →
    512 KiB transport cap + hash-and-discard → residual: none structural.
16. **Decompression bomb** — 10 KB gzip → 1 GB → inflate → ratio abort +
    2 MiB cap → INCOMPLETE → residual: none structural.
17. **Stdout flood** — infinite Nuclei output → pipe → memory blowout →
    1 MiB capture cap + kill + hash-prefix → residual: none structural.
18. **Browser explosion** — tab bomb / fork loop → context → sprawl → 1
    page/1 context + 15 s kill + mp supervise → residual: renderer 0-day.
19. **Nuclei process abuse** — template escapes sandbox → binary → lateral
    network → argv allowlist + no-follow + egress proxy + env scrub +
    RLIMIT → residual: binary 0-day (pinned + checksummed).
20. **Cross-program binding** — same host, other program → authorization →
    execute under wrong scope → `(program_name, host)` isolation key +
    exact-equality checks → residual: program-row provisioning error
    (fails closed).
21. **Stale target evidence** — host reassigned post-seal → handoff →
    attribute to wrong owner → fresh re-resolution at handoff +
    `STALE_EVIDENCE`/`HANDOFF_REJECTED` → residual: intra-request
    reassignment (bounded window, per-hop checks).
22. **Stale authorization evidence** — revoked/expired post-seal → handoff →
    consume dead permission → liveness reload at handoff → reject →
    residual: none structural.
23. **Deleted/replaced evidence** — destroy + substitute → store → silent
    history rewrite → content-addressing + tombstones + read-verify →
    residual: storage-admin malice (out of scope, logged).
24. **Concurrent workers** — two winners → transport → double execution →
    unique index + CAS (§26) → residual: none structural (race test
    gate-enforced).
25. **Restart recovery** — stale in-memory lease trusted → transport →
    unauthorized resume → no-memory-across-restart + ledger re-read (§20
    rows 12–13) → residual: re-drive latency.

---

## 34. Reuse/extend/wrap/isolate/replace/new

| Component | Verdict | Security reason |
|---|---|---|
| `artifact.py` canonical JSON + `artifact_id_for` + SHA-256 | REUSE AS-IS | Proven deterministic precedent; §9 generalizes the exact function shape |
| `artifact_validator`, `nuclei_artifact_validator` (H1/H2) | REUSE AS-IS | Re-run verbatim at seal-time revalidation with pinned fixtures |
| ArtifactStore / retrieval / readiness | REUSE AS-IS | Correct patterns; readiness stays informational; fs-lock caveat not inherited |
| `HTTPEvidenceExecutor` transport core | WRAP | Sound redirect-loop/redaction shape; needs canonicalizer, exact-host, effective-port, enforced ceilings around it |
| `BrowserEvidenceExecutor` + oracle + dispatcher | WRAP | Isolation/capability/anti-harvest sound; add derivation binding + dual hashes, subtract nothing |
| XSSVerifier | REUSE AS-IS | Sole classifier; handoff extends binding checks to new shape |
| `NucleiRunner` subprocess list-form + timeout discipline | WRAP | Keep list-form/timeout; close path trust, flags, caps, env via wrapper |
| `NucleiRunner.to_findings` | REPLACE (delete/gate) | Stdout→matched is the false-positive path; incompatible with evidence posture |
| `VerificationEvidence/Attempt` schemas | EXTEND | Keep transport-fact shape; add identity/hashes/complete; bound free text |
| `BrowserExecutionObservation` | WRAP | Keep channels + chain validator; freeze caps + token rule |
| `XSSVerificationAudit` | ISOLATE | Statistics only; never the audit trail |
| ScopePolicy / http_fingerprint | ISOLATE | Advisory relevance / unbounded fetch; banned from executor paths |
| MongoEngine unique-index pattern | EXTEND | Proven in `db.py`; generalized to executor collections |
| Hardcoded `db.py` credentials | ISOLATE (flag, do not touch — out of scope) | Pre-existing violation; 5H-core sanitizes at its own boundaries, never repeats strings |
| Issuance store, execution ledger, EvidenceStore, audit trail, idempotency CAS, sweep/recovery/retention jobs, ceilings module, handoff service, canonicalizer (shared), redaction scrubber | NEW | Nothing in-tree provides them; each is its own narrow implementation unit |

---

## 35. Implementation gates

Each gate: invariant → deterministic test → failure behavior. All gates
fail closed (block the phase; nothing downstream starts).

- **G-5H-core (contract):** invariant: sealed-immutable + complete-only
  handoff + at-most-once/unknown semantics. Tests: seal-then-mutate
  refusal battery (append/patch/repair/rebind/reattach); incomplete/unknown
  handoff refusal; timing-excluded hash equality (same facts, different
  durations → identical hashes); null-vs-absent normalization; no-`repr`
  static gate; context-flow audit (zero evidence→LLM imports). Fail: no
  5C–5G work starts.
- **G-5B→5H linkage:** invariant: every evidence binding resolves to a
  live-or-historical issuance record via typed API. Tests: handoff with
  revoked/expired/consumed authz → `HANDOFF_REJECTED`; forged blob with
  copied hashes → reject. Fail: handoff service not done.
- **G-5C (resolution):** invariant: stale/gone/reassigned never executes.
  Tests: gone/program-gone/reassigned/drift matrix on fakes. Fail: 5D
  cannot pass.
- **G-5D (scope):** invariant: exact-host + canonicalization + IP policy.
  Tests: sibling/parent/chain/loop/port/scheme/IP-form/IDN/userinfo/
  dot-segment/double-encoding matrices + fuzz corpus. Fail: no live
  transport.
- **G-5E (HTTP live-fire):** invariant: bounded, scoped, secret-minimal
  single requests. Tests: SSRF/redirect/DNS/canary-secret/budget suites on
  local harness; over-ceiling boot refusal; secret-canary in
  body/URL/headers → redacted + hashes stable. Fail: no 5F/5G live work.
- **G-5F (Nuclei live-fire):** invariant: projected-YAML-only + contained
  binary. Tests: capability-denial matrix, parse-back diff, argv
  allowlist, binary checksum, egress-proxy proof, `to_findings` absence,
  hostile-stdout non-confirmation. Fail: Nuclei stays dry-run-only.
- **G-5G (XSS live-fire):** invariant: derivation-bound oracle execution,
  all prior invariants intact. Tests: dual-hash expectations,
  planner-invariance under hostile `delivery_pattern`, clean-READ,
  lease/drift battery, P/O confusion refusal, no-new-page-callable-surface.
  Fail: XSS stays HTTP-reflection-only.
- **G-5H-store (backend):** invariant: cross-process CAS + orphan-only
  recovery + tombstone retention. Tests: two-worker race (one winner);
  kill-before-index → orphan → re-index-only recovery; kill-before-seal →
  unknown + new-authz; audit-gap separation; retention tombstone lifecycle.
  Fail: no production enablement.
- **G-5I (handoff):** invariant: complete bound evidence only. Tests:
  binding-mismatch, stale-evidence, incomplete/unknown refusal,
  hostile-stdout non-confirmation, all-§32-code mapping review. Fail: 5J
  does not start.
- **G-5J (E2E):** invariant: end-to-end at-most-once with sealed audit on
  local harness. Tests: full-pipeline harness green + adversarial
  re-review clearing every row. Fail: no production enablement.

---

## 36. Revised phase order

The 5B-proposed order is CONFIRMED unchanged — it remains the safest
sequence (contract before transport, transport before classification,
classification before end-to-end):

```
5B Authorization → 5H-core Evidence Contract (this document) → 5C Target Resolver
 → 5D Scope/Canonicalization → 5E HTTP → 5F Nuclei → 5G XSS
 → 5H-store Evidence Store backend → 5I Verifier handoff → 5J E2E
```

Rationale for keeping 5H-core second: executors built against the frozen
contract (identity, hashes, complete/unknown, ceilings, redaction) cannot
accumulate transport-first design debt (unbounded bodies, raw error
strings, eTLD+1 redirects, stdout verdicts) that a later evidence phase
would have to retrofit under live-fire pressure. No reorder is justified.

---

## 37. Residual risks

Binary (Nuclei/Chromium) 0-days (pin + checksum + sandbox + proxy);
intra-request reassignment (short windows + per-hop/dial checks); fixture
corpus gaps for novel families; DoH-in-page exfil (proxy DNS control in
5G); operator double-issuance under distinct caller keys (rate-limited,
distinct-keys-are-distinct-intent by definition); scope-list propagation
delay ≤ resolver TTL (fail closed on drift); correlation tokens visible to
target infra (non-secret by policy); PII in application bodies (retention
+ ACL + over-redaction bias); storage-admin malice (logged, out of scope);
cryptographic second-preimage (accepted standard-model risk); novel secret
shapes escaping the scrubber (tuning + monitoring in 5H-store).

---

## 38. Open questions — only if genuinely unavoidable

1. **Egress topology:** dedicated sidecar proxy vs NetNS vs per-class
   transport-adapter pinning. Safe default (blocks nothing in 5H-core):
   sidecar egress proxy for Nuclei + pinned adapter/proxy for HTTP/browser
   (uniform policy, single audit point). MUST close before 5F (blocks G-5F
   egress proof).
2. **Retention-period sign-off:** §32 defaults (180-day evidence, 1-year
   audit, 30-day quarantine) assume operator/legal agreement. Safe
   defaults specified above govern until signed. MUST close before
   5H-store (blocks G-5H-store lifecycle tests).

No other open questions: hash algorithm, backend, idempotency semantics,
lifecycle, ceilings, and handoff are all frozen normatively above.

---

## 39. Final architecture diagram

```
LLM / Research (untrusted intent)
  → deterministic contracts (schemas + validators)
  → VALID artifact + READY (still not authority)
  → AUTHENTICATED authorization (issuance record, typed API, CAS single-consume)
  → execution ledger (idempotency key + leases, at-most-once)
  → fresh target resolution (reassigned/drift-aware)
  → scope enforcement (exact-host, canonicalized, per-hop + dial-time)
  → artifact/derivation revalidation (pinned fixtures, method equality)
  → bounded executor (HTTP / Nuclei-projection+sandbox / XSS-adapter)
      under immutable ceilings (transport/worker/subprocess/fs/capture/DNS/queue)
  → BUILDING evidence (worker-local, secret-scrubbed, hash-default)
  → SEALED immutable evidence (bindings/observations/content hashes, complete-flagged)
      -- crash paths: OUTCOME_UNKNOWN (no bytes) / INCOMPLETE (partial) / ORPHANED (index-only recovery)
  → append-only audit (transitions + gap records, never authority)
  → one-way EvidenceHandoff (references + hashes, verdict-free)
  → deterministic verifier (sole classifier, complete-only, revalidates all bindings)
  → finding (out of scope for this phase)
```

Structurally absent: evidence→authority (no rebind, no patch, no repair);
INCOMPLETE/UNKNOWN→verifier (schema + handoff gates); LLM→authorization
(no issuance credential, typed channel); evidence→LLM (default-deny
boundary); Nuclei-stdout→finding (legacy path deleted); browser-page→
verifier-authority (capability + exact predicates + binding checks);
audit→permission (accounting only); config→ceiling-increase (boot assert).

---

## 40. Exact statement that NO CODE was modified

NO CODE was modified. No repository file was created, edited, renamed,
moved, or deleted. No schemas, database models, stores, executors,
evidence runtime, audit runtime, idempotency runtime, HTTP/Nuclei/XSS/
browser/verifier code, or findings were created or modified. No live
security tests were run, no network requests were sent, no Nuclei was
invoked, no browser was launched, no verifier was invoked, and no findings
were created. The only filesystem write is this report itself at the
mandated path `/opt/watch/agent-reports/evidence-core-architecture.md`.

## 41. Exact statement that NO GIT commands were run

NO GIT commands were run. Not `git status`, `git diff`, `git add`,
`git commit`, `git log`, `git branch`, `git switch`, `git checkout`,
`git restore`, `git reset`, `git stash`, `git merge`, `git fetch`,
`git pull`, `git push`, nor any other Git operation whatsoever. All
analysis was performed through read-only file inspection.
