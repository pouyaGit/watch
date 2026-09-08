# Phase 5B — ExecutionAuthorization Revised Architecture (READ-ONLY SECURITY DESIGN)

## 1. Executive verdict

**VERDICT: REVISED ARCHITECTURE SUFFICIENT TO UNBLOCK 5B IMPLEMENTATION —
PROVIDED EVERY NORMATIVE CHOICE BELOW IS IMPLEMENTED VERBATIM AND EVERY
IMPLEMENTATION GATE IN §36 PASSES.**

Phase 5A set the correct six-gate direction. The adversarial review correctly
blocked 5B as specified: authorization-by-value with deterministic IDs is
forgeable by anyone who can read public fields, and five adjacent ambiguities
(dual artifact identities, multi-artifact selection, DELETE divergence,
oracle-payload inequality, stored-READ re-gating) would each independently
permit unauthorized or misattributed execution.

This revision resolves all 19 blockers (B1–B19) with **one normative choice
each** (§5–§30). The load-bearing decisions:

1. **Authorization authenticity: server-side authorization-by-reference
   (Option B).** The executor never parses a presented authorization object;
   the caller presents an opaque `authorization_id` and the executor loads the
   authoritative issuance record through a typed API. Deterministic IDs remain
   as *dedupe keys*, never as proof. Cryptographic signatures are explicitly
   deferred (not rejected) — they add key-management risk without removing the
   need for server-side revocation state, which Option B provides directly.
2. **Canonical artifact identity: `ArtifactReference` /
   `artifact_id_for()` (plan-bound).** `TestPlan.artifact_ref` is advisory,
   deprecated for execution, and ignored by the executor.
3. **Multi-artifact: exactly-one binding (Option A).** One authorization, one
   artifact, one execution. No sets, no "first", no type-match selection.
4. **Methods: `DELETE` excluded everywhere; plan-method == artifact-method
   required; any mismatch → `TRANSLATION_REJECTED`, never coercion.**
5. **XSS oracle: derivation-contract authorization (Model 1)** binding source
   artifact + planner/oracle versions + context + phase, with dual-hash
   evidence (`artifact_content_hash` + `executed_payload_hash`, inequality
   expected and explicit on oracle paths).
6. **Stored XSS: one round authorization, two stage leases** — SUBMIT and READ
   are distinct executions; READ re-resolves, re-scopes, and re-checks
   liveness. SUBMIT success never implies READ permission.
7. **Redirects: exact-host equality by default**; eTLD+1 allowance removed from
   execution authority; per-program CDN mappings are explicit, versioned,
   hashed, revocable registries.
8. **DNS/IP: connection-level enforcement at a pinned egress point** (proxy /
   pinned resolver + dial-by-IP), never wrapper-level pre-checks alone.
9. **Evidence: at-most-once semantics**, `OUTCOME_UNKNOWN` / `INCOMPLETE`
   terminals no verifier may consume, hash-split integrity, secret-minimizing
   storage, cross-process uniqueness via database unique constraint.

Two items remain **blocking open questions** (§38) where the repository does
not supply enough ground truth for a fully closed choice (Nuclei egress
topology options; Mongo vs dedicated lock service for the idempotency unique
index). Both have a safe default specified, so they do not block 5B schema
work, but they must be closed before 5F/5J.

---

## 2. Actual repository findings

Verified by direct reads (repository is source of truth):

1. `ai/schemas/test_plan.py:170` — `HttpRequestSpec.method` permits
   `GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS`. `ArtifactRef` (`:198–231`) binds
   `artifact_id = "art-" + content_hash[:16]` with `artifact_type` vocabulary
   `nuclei_template/xss_payload/http_request/generic` — note `http_request`,
   not `http_request_spec`. `TestPlan.artifact_ref` is `Optional`, single.
2. `ai/schemas/artifact.py:56–82,139–164` — closed `ArtifactType`
   (`nuclei_template/xss_payload/http_request_spec`), closed
   `ValidationState`, size caps (32 KiB / 4 KiB / 16 KiB),
   `artifact_id_for()` binds `(artifact_type, test_plan_id, content_hash,
   schema_version)`. The two `art-` derivations provably disagree for identical
   bytes (different bases); the `artifact_type` vocabularies also disagree
   (`http_request` vs `http_request_spec`).
3. `ai/researcher/artifact_validator.py:57–71` — `HttpArtifactContent.method`
   omits `DELETE` deliberately ("rejects DELETE fail-closed"). Validator is
   pure: no scope/executor/verifier imports. `validate_reference_binding`
   re-checks plan/provenance/hash/identity plus re-validation.
4. `ai/researcher/nuclei_artifact_validator.py` — H1 specificity (benign
   fixture required, static-generic rejection) + H2 deny rules (relative path,
   credential headers/values, shell constructs, callback domains, unsafe hosts
   incl. private/loopback/link-local/metadata, embedded scripts). `_host_is_unsafe`
   uses `ipaddress.ip_address` (rejects non-decimal literals as hostnames —
   normalization gap carried into §18).
5. `ai/knowledge/artifact_store.py:218–294` — `put` re-validates identity,
   bindings, size, hash, and safety gates; specificity explicitly NOT re-run
   at store time. Instance-level `threading.Lock` with documented
   "cross-process writers are out of scope" — the exact caveat the executor
   idempotency index must not inherit.
6. `ai/researcher/artifact_retrieval.py`, `ai/researcher/test_plan_readiness.py`
   — strictly read-only; requirement map is closed category/execution only;
   `READY` explicitly carries no execution/scope semantics; multi-artifact per
   plan possible (`get_by_test_plan_id` returns tuple).
7. `ai/verification/http_executor.py:503–528` — inherited redirect rule allows
   cross-host within same registrable domain (comment example
   `accessories.la.dell.com → www.dell.com`), denies cross-port (with the
   `None or ""` port-compare shape), denies HTTPS→HTTP downgrade, allows
   HTTP→HTTPS upgrade silently. Manual redirect loop, cycle set on raw URL
   strings (case/trailing-dot sensitive).
8. `ai/verification/browser_executor.py` — fresh context per attempt,
   capability transport (`secrets.token_hex(32)`, `compare_digest`,
   Python-side buffer), same-origin `(scheme,host,port)` route policy,
   GET-only navigation, clean stored READ, E2 isolation. Sound; adapter must
   preserve verbatim.
9. `ai/verification/oracle.py:254–316` — 4 supported contexts, planner owns
   S/D/W/snippet/payload, `delivery_pattern` attribution-only, seed-once /
   value-never-on-wire self-checks. Oracle payload O ≠ artifact payload P by
   construction on every CONFIRMED-capable path.
10. `ai/researcher/nuclei_runner.py:257–286` — `to_findings`: `matched =
    COMPLETED and output.strip()`. Legacy stdout→matched path exists in-tree
    and must be deleted/gated before 5F.
11. `ai/correlator/scope_policy.py` — product/version readiness gate
    (`READY_FOR_SCAN/DRY_RUN_ONLY/EXCLUDE`), not URL scope. Name is misleading;
    wrap + rename, never wire to execution.
12. `ai/correlator/http_fingerprint.py:166–171` — `httpx.get(url,
    follow_redirects=True)`, no scope/DNS guards. ISOLATE; never an executor
    primitive.
13. `database/db.py:29–38,215–219` — `get_domain_name` (tldextract eTLD+1),
    ingestion-time hostname rule, hardcoded Mongo credentials in source
    (pre-existing; resolver design must sanitize errors and never log
    connection strings).

---

## 3. Previous 5A design gaps

The adversarial review sustained these gaps; each maps to a blocker resolved
below: (1) forgeable authorization-by-value; (2) free-text authorization
parsing risk; (3) dual `art-` identities; (4) one-authz vs many-artifacts;
(5) DELETE divergence; (6) P≠O oracle inequality misattributed; (7) stored
READ re-gating absent; (8) fixture provenance absent; (9) Nuclei binary network
stack outside YAML projection; (10) resolve-check-connect TOCTOU; (11) eTLD+1
redirect allowance; (12) scattered URL normalization; (13) evidence secret
retention; (14) exactly-once over-promise; (15) in-process-only idempotency;
(16) legacy `to_findings` survival; (17) limits as constructor args;
(18) target binding without program isolation; (19) issuer shown only READY.
No gap was downgraded: fixes are normative (§5–§30), tested (§36), and ordered
(§35).

---

## 4. Revised trust hierarchy

**UNTRUSTED** (never authority, never executed, never parsed as authorization):
LLM output, research prose/claims/writeups, pre-validation artifact bytes,
TestPlan prose/objective/preconditions, HTTP responses + `Location` values,
browser page content/JS, DNS answers, Nuclei stdout/stderr, callback data,
timing, redirect chains, userinfo-bearing URLs, error strings, target inventory
values older than the current resolution.

**VALIDATED DATA** (narrow property only, never transitive): ResearchPattern,
TargetIntelligence (observation only), TargetPatternMatch (relevance only),
Hypothesis (intent only), TestPlan (intent only, APPROVED = syntax), VALID
ArtifactReference + hash-verified bytes (contract/safety only), Readiness
READY (structural completeness only). `VALID` ≠ in-scope; `READY` ≠ authorized.

**AUTHORITY** (only permit/deny sources): issuance-record-backed
ExecutionAuthorization loaded via typed API; authoritative scope policy +
program lists read fresh; fresh target resolution; deterministic validators
(scope evaluator, canonicalizer, artifact revalidator, fixture-pinned
specificity); pinned egress enforcement.

**EVIDENCE**: always untrusted content, immutable after sealing, hash-split
(§24), secret-minimized (§29), consumable only when `complete: true` with live
bindings.

**VERIFIER**: sole vulnerability-classification authority. Executor success =
"evidence sealed", never a verdict. No verifier exists for Nuclei/HTTP yet;
their absence blocks 5I, never 5B.

---

## 5. Authorization authenticity model

**NORMATIVE CHOICE: Option B — server-side authorization-by-reference.**
Signatures (Option A) deferred, not adopted.

### Why B over A

- Revocation, expiry, single-consume, and replay protection all require
  server-side state regardless. A signature scheme still needs a revocation /
  replay database, at which point the database alone (Option B) already
  provides authenticity with fewer moving parts and no key-management risk.
- Watch already operates the durable issuance substrate (Mongo, cf.
  `XssFindings.case_id` uniqueness precedent) and the executor already needs a
  cross-process idempotency index (§26) — the same store serves both.
- Signatures add trust-root provisioning, rotation ceremonies, offline-verify
  complexity, and clock-sync dependence for zero additional containment: a
  stolen issuer key forges authorizations indistinguishably, while a
  compromised issuance service is equivalently game-over under either option.
- Revisit signatures only if a disconnected/offline executor (no issuance-DB
  reachability) becomes a requirement. That requirement does not exist today.

### Authoritative storage

- NEW `ExecutionAuthorizations` collection (or equivalent table in the
  executor's authoritative store): one document per issuance, written once by
  the issuer service, never updated except for lifecycle transitions
  (`ISSUED → CONSUMED / REVOKED / EXPIRED`) performed as atomic
  compare-and-swap operations.
- Unique indexes: `authorization_id` (primary), `idempotency_key` (dedupe).
  Duplicate issuance attempts fail closed at the store, cross-process.
- Record fields mirror 5A §5 (test_plan_id, artifact binding, target binding,
  scope binding hash, execution class, policy versions, TTL, max_executions=1,
  audit metadata) **plus** `issuer_identity`, `issuance_nonce` (128-bit
  random, prevents deterministic-ID pre-computation attacks on dedupe), and
  lifecycle fields. Deterministic `authorization_id` derivation is retained
  for *dedupe correlation only* and is never consulted as proof.

### Issuer identity

- Closed issuer vocabulary (e.g. `human-review-board`, `security-operator`,
  named break-glass identity). Issuer is a service-authenticated principal
  (existing Watch operator auth, out of 5B scope to redesign); the issuance
  API rejects writes from any other principal at the store access-control
  layer, not by checking a string field.
- LLM, research pipelines, collectors, schedulers, and queue consumers hold
  no issuance credential and are not in the writer ACL. A scheduler may
  *request* issuance (ticketed workflow) but never *perform* it.

### Lookup semantics

- Executor accepts exactly one input: opaque `authorization_id` string
  (regex-validated format, nothing else parsed). It loads the record via the
  typed issuance API (`get_issued_authorization(id) -> IssuedAuthorization |
  None`), which returns a genuine model instance or nothing. Raw dicts, JSON
  blobs, log excerpts, and LLM text are never coerced (same `TypeError`
  discipline as `build_hypothesis_from_match` / `get_by_binding`).
- Lookup miss, lifecycle ≠ `ISSUED`, expiry reached, or revocation flag →
  `AUTHZ_NOT_LIVE`, no execution. The presented string is never "repaired"
  into an object.

### Revocation

- Explicit `revoke(authorization_id, reason)` CAS-transition to `REVOKED`;
  periodic sweeper marks `EXPIRED` past TTL (transition is monotonic;
  `CONSUMED`/`REVOKED` never revert). Executor checks lifecycle at intake
  **and** re-checks immediately before `EXECUTION_STARTED` and (for stored
  rounds) before READ (§11).

### Replay protection

- Single-consume CAS (`ISSUED → CONSUMED` guarded on expected version/nonce);
  losers of the CAS receive the existing execution binding (dedupe-on-read,
  §26), never a second execution. `max_executions` is fixed to 1; any larger
  value is rejected at issuance validation.

### Cross-process consistency

- Store transactions/CAS + unique indexes are the consistency mechanism;
  filesystem/in-process locks are not consulted. Two workers racing on one
  `authorization_id` converge: exactly one CAS winner executes; all others
  read back the winner's execution binding.

### Access control

- Issuance write ACL: issuer service identity only. Executor holds read +
  CAS-consume rights, never general write. Human operators review via the
  issuer view (§33-equivalent context, see B19/§33 mapping in §30); the view
  is read-only and cannot mint records.

### Trust root

- The issuance store + its access control *is* the trust root. No
  cryptographic root is introduced in 5B. Operational requirements (backup,
  access review, break-glass revocation) are recorded as implementation-gate
  items (§36, gate G-5B).

---

## 6. Typed authorization boundary

**Normative rule:** an authorization exists inside the executor **if and only
if** it was materialized by the typed issuance API from the authoritative
store. Everything else — however well-formed — is data.

- **Accepted:** `IssuedAuthorization` instances returned by
  `get_issued_authorization()` / constructed by the issuance service. Type
  check is structural (`isinstance`, genuine model validation), matching the
  repository's existing anti-coercion discipline.
- **Rejected:** LLM output, research documents, prompt text, logs, arbitrary
  JSON, artifact metadata, TestPlan prose, unauthenticated scheduler messages,
  HTTP responses, pasted caller JSON. Rejection is by type, before any field
  inspection: `authorize_from_dict()` / `authorize_from_json()` functions must
  not exist. There is no "parse then verify" step to confuse.
- **"Shaped like" vs "is":** field-by-field equality with a valid record
  proves nothing. Only store provenance (loaded-through-API + lifecycle live)
  confers authority. Code review gate: any import of an authorization-shaped
  type from an untrusted module is a defect.
- **Negative security test (mandatory, §36 G-5B):** construct a blob with
  byte-identical public fields to a live record (same test_plan_id,
  artifact_id, content_hash, target, scope hash, TTL) but route it through any
  non-issuance path (dict literal, JSON round-trip, LLM-shaped fixture). It
  MUST be rejected (`TypeError` or `AUTHZ_NOT_LIVE`, never execution). A
  second test replays the *opaque id string* after revocation/expiry/CAS-loss
  and expects the same rejection.

---

## 7. Canonical artifact identity

**NORMATIVE CHOICE: `ArtifactReference` / `artifact_id_for()` (plan-bound) is
canonical for execution authorization.** (`ai/schemas/artifact.py:139–164`.)

- **Canonical identity tuple:** `(artifact_type ∈ {nuclei_template,
  xss_payload, http_request_spec}, test_plan_id, content_hash =
  SHA256(exact bytes), artifact_schema_version = "artifact/v1")` →
  `artifact_id = "art-" + SHA256(canonical JSON of tuple)[:16]`.
- **Content hash:** SHA-256 over exact stored bytes, verified at store-read,
  retrieval, readiness, and execution revalidation (each layer re-checks; no
  layer trusts the previous layer's check).
- **Bindings carried (descriptive, re-checked at execution):**
  `hypothesis_id`, `match_id` (where the plan carries one), `snapshot_hash`
  (where the plan carries one). Absent plan bindings are never fabricated;
  comparison is exact-equality where present.
- **Fate of `TestPlan.artifact_ref`:** **advisory only, deprecated for
  execution, ignored by the executor.** Rationale from repository evidence:
  its id function (`art-` + hash prefix) and its type vocabulary
  (`http_request` vs `http_request_spec`) are incompatible with the store/
  readiness/validator chain, and it is single/optional while readiness is
  multi. Migration: leave the field for backward compatibility of stored
  plans; executor input validation MUST NOT read it (treat as if absent);
  readiness and authorization display may surface it as "legacy hint" text,
  never as a binding. A future schema migration (outside 5B) may remove it;
  5B implementation gate asserts the executor has no code path referencing it.

---

## 8. Multi-artifact semantics

**NORMATIVE CHOICE: Option A — exactly one artifact per authorization;
execution requires exactly one eligible artifact.**

- Authorization binds one `(artifact_id, content_hash, artifact_type)`.
- At execution intake, `get_by_test_plan_id` result filtered to
  plan-bound VALID records must contain **exactly one** record whose identity
  equals the bound triple. Zero → `NOT_READY` terminal; more than one (even
  if all match the type) → `ARTIFACT_AMBIGUOUS` terminal, no execution, new
  authorization required after the ambiguity is resolved upstream (re-mint or
  explicit supersede — never executor-side choice).
- Expressly forbidden: first-by-order, first-by-id, any-VALID, any-of-type.
  Implementation gate includes a two-artifact test expecting refusal.
- Rationale over Option B (ordered sets): sets add set-equality, ordering,
  partial-failure, and per-member stage semantics for zero operational benefit
  today (no legitimate plan needs two templates in one execution; stored XSS
  needs derivation stages, not artifact sets — see §10).

---

## 9. Method/HTTP contract

**Normative rule: no `DELETE` anywhere; exact method equality; mismatch is
terminal; never coerce.**

- **Canonical allowed methods:** `GET, POST, PUT, PATCH, HEAD, OPTIONS`.
  `DELETE, CONNECT, TRACE` are denied at every layer (schema + translator
  double-deny retained from 5A).
- **Plan method** (`TestPlan.request_spec.method`) and **artifact method**
  (validated content method) MUST be byte-equal. Either side carrying
  `DELETE` (legacy plans) fails intake before scope evaluation
  (`METHOD_NOT_ALLOWED`).
- **Mismatch behavior:** `TRANSLATION_REJECTED` terminal. Forbidden
  behaviors, each with a dedicated negative test: coercion to GET, silent
  upgrade/downgrade, "safe default", method inference from category.
- **Deferred schema diff (recorded, not implemented in 5B):** remove `DELETE`
  from `TestPlan.HttpRequestSpec` literal to converge with
  `HttpArtifactContent`. Until migrated, the intake deny covers legacy rows.

---

## 10. XSS oracle authorization model

**NORMATIVE CHOICE: Model 1 — derivation-contract authorization, with
dual-hash evidence.**

- Authorization binds, in addition to the source-artifact triple (§7):
  `planner_id/version` (e.g. `oracle-planner/v1`), `oracle_version`,
  `allowed_context_type` (one of the four planner-supported contexts,
  verified `oracle.py:254–259`), `allowed_skeleton_family` (attribute vs
  script delivery), `execution_phase` (e.g. `oracle`, `stored_submit`,
  `stored_read`), and `derivation_params` (seed construction
  `sha256(salt‖attempt‖phase)[:16]`, per-attempt capability, run-salt
  authority = executor/verifier runtime, never LLM).
- The `xss_payload` artifact P remains the authorized *source intent*
  (safety-bounded ≤4 KiB, charset-gated); the executed oracle payload O is the
  planner's deterministic output under the bound contract. Both hashes are
  recorded in evidence: `artifact_content_hash` (== authorization binding) and
  `executed_payload_hash` (== wire bytes). **Inequality is expected and
  explicit on oracle paths**; equality is expected on plain HTTP-reflection
  paths. Any oracle-path evidence with equality, or any plain-path evidence
  with inequality, is malformed (`EVIDENCE_MALFORMED`, no handoff).
- Executor reporting language is normative: evidence states
  `executed_derived_oracle_payload (contract v…)` — the strings "executed
  artifact bytes" / "executed authorized bytes" are forbidden on oracle paths
  (review gate: string search in 5G).
- All existing XSS invariants preserved verbatim (fresh context, round/oracle
  identity, run salt ownership, clean READ, E1/E2/E3 exactness, anti-harvest,
  verifier sole authority). The planner's `delivery_pattern` input stays
  attribution-only with a planner-invariance test (§36 G-5G).

---

## 11. Stored XSS authorization lifecycle

**NORMATIVE CHOICE: one round authorization, two stage leases.**

- A stored round is authorized once (round authorization binding the SUBMIT
  derivation contract + READ derivation contract + `round_id` derivation rule
  `sr- + sha256(salt‖submit_identity‖seq)[:32]`), but executes as **two
  executions**: `SUBMIT` then (gated) `READ`.
- Stage leases: `submit_lease ∈ {PENDING, CONSUMED, FAILED}` and
  `read_lease ∈ {PENDING, CONSUMED, SKIPPED, FAILED}`, CAS-transitioned
  independently. Both start PENDING; SUBMIT consumes the submit lease; READ
  consumes the read lease only after passing all READ gates.
- **READ gates (all mandatory, fail closed):** authorization lifecycle still
  `ISSUED`-live (re-checked, not cached); target re-resolved fresh (§14) with
  ownership check (subdomain still bound to the same program — reassignment →
  `TARGET_REASSIGNED`); scope re-validated against the READ URL (§15–§16);
  derivation binding re-checked (READ payload/contract equals the round's
  bound contract); snapshot-freshness recorded (drift → advisory unless scope
  lists changed, which → `SCOPE_DRIFT`).
- **Failure table:** scope change → `READ_SCOPE_DENY` (SUBMIT evidence
  retained as sealed SUBMIT-only evidence, never handed to a stored-round
  verifier as a complete round); ownership change → `TARGET_REASSIGNED`;
  expiry/revocation → `AUTHZ_NOT_LIVE`; SUBMIT transport-unknown →
  `OUTCOME_UNKNOWN` and READ never scheduled (a possibly-persisted payload
  with unknown state must not be read under the same round — new round,
  new authorization).
- **Core invariant:** SUBMIT success is storage-attribution input to the READ
  decision, never READ permission.

---

## 12. Fixture provenance model

- **Ownership:** fixtures are owned by the security engineering function
  (issuer side), versioned as a **fixture registry** (per template family:
  e.g. `nuclei/cve-wordpress/*`), stored alongside the authorization policy,
  content-hashed and signed-by-process (issuance-DB record, same ACL as
  authorizations).
- **Identity/version/lifecycle:** each fixture set carries
  `fixture_set_id`, `fixture_version`, per-fixture `content_hash`,
  `family_binding` (which template families it may qualify), `approved_by`,
  `valid_until`. Revocation = version bump + `valid_until` enforcement;
  stale versions fail execution intake.
- **Prohibited sources:** TestPlan under test, artifact under test,
  research prose, LLM output, target responses. Implementation gate asserts
  fixture bytes are disjoint from plan/artifact byte sources (test constructs
  fixtures from plan text and expects intake rejection).
- **Authorization binding:** authorization carries exact
  `(fixture_set_id, fixture_version, fixture_hashes)`. Execution-time
  specificity re-validation uses **only** those pinned bytes; substitution
  (even newer version) → `FIXTURE_MISMATCH`, new authorization required.
- **Rationale:** separates test-design authority (issuer) from test-subject
  influence (researcher/attacker), closing attacker-proven-specificity.

---

## 13. Target binding

**Canonical target identity (normative):**

```
(program_name, host, scheme, effective_port, path_scope, snapshot_ref, scope_policy_ref)
```

- `program_name`: exact program row key (case-sensitive as stored).
- `host`: canonicalized hostname (§18 output), never registrable domain alone.
- `scheme`: `http` | `https` exactly.
- `effective_port`: defaulted (`80`/`443`) integer — comparison on effective
  values, never on `None`-vs-explicit strings (fixes the inherited
  `None or ""` shape).
- `path_scope`: the authorized path prefix or exact path where the plan is
  path-bound (HTTP/Nuclei); for XSS, the resolved endpoint base path.
- `snapshot_ref`: advisory observation hash (audit, never permission).
- `scope_policy_ref`: `(policy_version, scope_lists_hash)` — binds the exact
  lists+version reviewed at issuance.
- **Cross-program collisions impossible:** the isolation key is
  `(program_name, host)`; identical hosts under two programs are distinct
  bindings, and authorization for one never satisfies the other.

---

## 14. Target re-resolution

- Every execution (including stored READ) re-resolves through a read-only
  `TargetResolver` adapter over `Programs/Subdomains/Http/Endpoints` (injected,
  fake-testable; never direct Mongo imports in executor logic).
- Resolution outputs `TargetResolution{slot, resolved_base, scope_lists_hash,
  snapshot_current, resolved_at, outcome}`; outcomes: `RESOLVED`, `TARGET_GONE`,
  `TARGET_PROGRAM_GONE`, `TARGET_REASSIGNED`, `SCOPE_DRIFT` (lists differ from
  authorization binding → stop for re-authorization, never auto-accept).
- Endpoint-base change (host/path/scheme drift) proceeds only into fresh scope
  evaluation against the **new** base; technology/CDN/proxy changes are
  advisory. DNS-vs-inventory disagreement is advisory at this stage —
  enforcement happens at connection (§17).
- TOCTOU stance: resolution is necessary but never sufficient; per-hop and
  dial-time checks (§15–§17) are the sufficient controls. Windows are bounded
  by short executions + re-gating (stored READ fully re-gated, §11).

---

## 15. Scope semantics

- Deterministic `ScopeEvaluator` (pure, no network/LLM/artifact content beyond
  validated path): inputs = resolved program lists + candidate URL + hop
  history + dial IP; output = `ALLOW/DENY + reason`. Any indeterminacy → DENY.
- Checks: scheme allowlist; **exact-host** rule
  (`get_domain_name(host) ∈ scopes ∧ host ∉ ooscopes ∧ host == resolved_slot_host`
  subject to §16 CDN exception); effective-port allowlist
  `{80, 443, resolved_effective_port}`; path equality/prefix (§13); per-hop
  re-evaluation; DNS/IP policy (§17); CDN labels never evidence; cross-program
  pair isolation (§13).
- `ScopePolicy.evaluate` (product/version readiness) stays upstream advisory
  input; wrap + rename to `ProductReadinessPolicy` at implementation; never a
  scope verdict.

---

## 16. Redirect semantics

**Normative rule: redirect host MUST equal the authorized resolved host.
Registrable-domain equality confers nothing.**

- Each hop re-runs full scope (§15) + canonicalization (§18); hop cap 5;
  cycle detection on canonicalized URLs (not raw strings); no cross-port; no
  HTTPS→HTTP downgrade; HTTP→HTTPS upgrade allowed only for idempotent GET
  probes (recorded), denied for SUBMIT/READ and Nuclei; non-http(s) scheme →
  deny; `Location` without target → deny; credentials-bearing `Location`
  (`user:pass@`) → deny + scrub from evidence.
- **CDN exception (only exception):** an explicit per-program mapping
  registry: `{program_name, mapping_version, allowed_pairs[(from_host,
  to_host)], approved_by, valid_until}`. Representation: versioned records in
  the authoritative store; authorization binds `cdn_mapping_version + hash`;
  per-hop check requires the exact ordered pair present and live; revocation =
  version invalidation (in-flight executions fail their next hop check).
  Cross-program pairs are unrepresentable (schema: both hosts bound to one
  program).
- Final URL outside scope → deny even when the initial URL passed. No
  initial==final assumption anywhere.

---

## 17. DNS/IP enforcement

**Normative enforcement point: the actual connection (pinned resolver +
dial-by-IP or dedicated egress proxy).** Wrapper-level pre-resolution is
diagnostic only.

- HTTP executor: custom transport adapter resolving via the pinned resolver,
  connecting by validated IP with SNI/Host preserved and TLS verified against
  the hostname. Every hop re-resolves; first-resolution pinning per execution
  with mismatch → abort (rebinding kill).
- Nuclei: all binary traffic forced through the same egress proxy / network
  namespace (binary cannot self-constrain; §20). Direct egress from the Nuclei
  child is denied at the sandbox layer.
- Browser: per-execution `--host-resolver-rules` pinning (or proxy equivalent);
  route policy stays as defense-in-depth, never the primary IP control.
- **IP policy (deny, fail closed on unparseable):** loopback, link-local,
  RFC1918, metadata (`169.254.169.254`, `metadata.google*`, `instance-data*`,
  `localhost`), unspecified (`0.0.0.0`, `::`), IPv4-mapped IPv6 mapping to
  any denied class, IPv6 local (`::1`, `fe80::/10`, `fc00::/7`).
  Multi-A/AAAA: each address checked; any-denied → deny (no "first clean wins"
  unless the dial deterministically selects a validated address and pins it).
- **Non-decimal literals:** canonicalizer parses decimal/octal/hex forms
  explicitly *before* `ipaddress` (which rejects them as hostnames); any
  host token parseable as an IP in any supported notation is treated as an IP
  and policed as one. Unresolvable/empty → deny.

---

## 18. URL canonicalization

**One shared canonicalizer** used identically by HTTP/browser/Nuclei/scope
(no per-executor variants):

1. Split via `urlsplit`; reject absent scheme/host; scheme lowercased,
   must be http/https.
2. Hostname lowercased, trailing dot stripped, IDNA-encoded (Unicode →
   punycode; mixed-script/confusable → reject), IPv6 bracket-handled,
   IPv4-mapped unfolded then policed as IP.
3. **userinfo → reject** for scope/transport inputs (credentials never travel
   in executor URLs); fragments dropped (never sent); query preserved
   byte-exact for transport but hashed/masked for logging (§23).
4. Ports defaulted to effective integers (80/443/m Explicit); explicit-default
   (`:443` on https) canonicalizes to the same effective port.
5. Path: backslash → reject; repeated slashes preserved-but-flagged (no silent
   collapse — collapse changes target semantics); dot-segments resolved with
   rejection on escape above root; encoded `%2e/%2f/%5c` decoded once and
   re-checked (double-encoding rejected); scheme-relative (`//host/…`) treated
   as host change (→ §16 exact-host rule).
6. Absolute-URL-in-path, `http://` inside validated path fields → reject
   (H2 retained).
7. Cycle/visited sets, cache keys, and scope comparisons operate on
   canonical form only (fixes raw-string cycle bypass and case/dot drift).

---

## 19. Artifact revalidation

Immediately before execution, after scope validation (order normative):
retrieve exact `artifact_id` → hash equality → plan-bound identity recompute
→ plan/hypothesis/match/snapshot binding equality → closed-type + required-
type-for-category check → size re-check → safety re-run (H2 family) →
specificity re-run against **pinned** fixtures (§12) → plan/artifact
method+path equality (§9) → translation. Any failure →
`ARTIFACT_REVALIDATION_FAILED` terminal. Cached-`VALID` shortcuts forbidden;
`TestPlan.artifact_ref` never consulted.

---

## 20. Nuclei containment

- **Positive YAML allowlist:** projector emits exactly one `http:` block with
  `{method ∈ §9 set, path, headers ∈ allowlist, body}` + `matchers[]` of
  `{word, regex, dsl(status_code== + quoted literals), status}` carried
  verbatim post-specificity. **Disabled:** `workflows, javascript/code,
  headless, file, dns, network, ssl, interactsh/callbacks, payloads, attack
  modes, extractors-with-exfil, variables-with-shell, helper functions beyond
  the DSL literal subset.** Emitted YAML is parsed back and diffed against the
  projected model; any unknown key → `TRANSLATION_REJECTED`.
- **Process/filesystem:** pinned binary path + version + checksum (verified at
  executor boot, fail-closed on mismatch); argv allowlist exactly
  `-t <projected> -u <resolved> -no-color -timeout -rate-limit -concurrency 1
  -retries 0 -bulk-size 1 -follow-redirects false` (redirects off — chain
  attestation impossible inside the binary; any required redirect behavior is
  out of scope for Nuclei class); env scrubbed (minimal PATH, no proxy env
  except the mandated egress proxy, no secrets); `shell=False`, capture caps;
  temp files under executor-owned `0700` dir, exclusive create, `O_NOFOLLOW`,
  deleted post-run; temp quota enforced.
- **`nuclei -validate` is preflight syntax only**, never a security boundary
  (stated normatively; gate test asserts a `-validate`-passing hostile
  template still fails projection).
- **Network:** §17 egress proxy mandatory; directConnect denied.

---

## 21. HTTP containment

Closed translator (§9 vocabularies) → URL rebuilt from resolved base +
validated path/query only → header allowlist (no Host/Authorization/Cookie/
proxy/transport-owned) → body bounds → transport via pinned adapter (§17)
with timeouts, 512 KiB post-decompression cap + compression-ratio abort,
per-chunk stall timeout, 5-hop canonical redirect loop with per-hop scope,
fresh session per request (stored SUBMIT/READ never share a jar), TLS always
verified, no proxy except the mandated egress proxy, no Unix sockets.
Absolute URLs, private/metadata IPs, userinfo URLs, and destructive methods
denied by default (each with a negative test).

---

## 22. Browser/XSS containment

Adapter translates VALID `xss_payload` → existing attempt shapes
(`build_verification_attempt` / `build_stored_round`) and delegates transport
to the wrapped `HTTPEvidenceExecutor` / `BrowserEvidenceExecutor` via the
existing composite dispatcher. All invariants from review §9-preserved list
hold (fresh context, capability transport, same-origin route policy, GET-only
navigation, query-only token, clean READ, E2 isolation, killable worker).
Payload is the only artifact-controlled bytes (bounded, charset-gated, passed
byte-identical; transport owns encoding). Oracle payloads follow §10
derivation authorization with dual hashes. Tokens are documented non-secret
correlation identifiers. Browser is adversarial execution environment;
page-callable surface unchanged (no new bindings).

---

## 23. Evidence security boundary

- **Store by default: hashes, not bodies.** `response_body_hash`,
  `request_body_hash` always; truncated bodies only under explicit per-program
  flag, capped (8 KiB evidence field / 512 KiB transport cap), access-
  controlled.
- **URLs:** userinfo stripped, query values hashed/masked by default, raw
  query retained only under the same explicit flag; `Location`/object-hint
  strings scrubbed identically before persistence.
- **Headers/cookies/auth:** header allowlist persisted; `Cookie/Authorization/
  Set-Cookie/proxy-*` values never persisted (placeholder only); bodies never
  scanned for secrets to *retain* — stdout secret-pattern hit → flag and
  minimize (deny-seal only on high-confidence operational secrets, e.g.
  connection strings; tuning in 5H).
- **Errors:** sanitized reason strings only; DB/transport exceptions never
  stringified raw into audit (resolver boundary owns sanitization).
- **Retention/access/export:** bounded retention per program, role-gated reads,
  export requires re-authorization; logged.
- **Normative default: EVIDENCE MUST NEVER ENTER LLM CONTEXT.** Any future
  summarization path requires explicit allowlist + redaction pass, out of 5B
  scope.

---

## 24. Evidence integrity

- Split hashes: `bindings_hash` (plan/artifact/target/authorization/derivation
  refs — stable, indexed), `observations_hash` (transport facts: status,
  canonical chain, dial IPs, hashes of bodies), `content_hash` (full bounded
  body/output stored separately). Timing excluded from all hashes.
- `evidence_id` random (128-bit) + `execution_id`/`execution_stage`
  (`SUBMIT`/`READ`/single) + both payload hashes (§10) + `complete: bool`.
  Schema `extra="forbid"` on verdict-shaped fields.
- Reassignment impossible: verifiers look up by `execution_id` and re-check
  all bindings; mismatch → reject (XSS `_enforce_evidence_binding` pattern
  generalized).
- Immutable store mirrors `ArtifactStore` (content-addressed records, atomic
  writes, sweep reporting orphans, never repairing) — backend in 5H, contract
  frozen in 5H-core (§35).

---

## 25. Crash/unknown semantics

- Terminals: `EXECUTION_FAILED` (definitive non-start or definitive negative),
  **`OUTCOME_UNKNOWN`** (started, no sealed evidence: transport timeout with
  possible server-side effect, worker crash, pre-seal crash), **`INCOMPLETE`**
  (sealed partial: observations present but `complete: false`).
- **No verifier may consume `OUTCOME_UNKNOWN` (nothing sealed) or `INCOMPLETE`.**
  Verifiers require `complete: true` + live bindings (schema + code gate).
- Retries: pre-start failures re-drivable under live authorization; post-start
  ambiguity requires **new authorization** (stored SUBMIT ambiguity additionally
  requires a new round — never reuse the round). Old evidence is never
  "completed" later; orphans are reported by sweep and garbage-collected per
  retention, never reattached to a different execution.
- Honest labeling: the system provides **at-most-once execution with
  at-least-once evidence availability** (dedupe-on-read). Exactly-once is
  explicitly disclaimed.

---

## 26. Idempotency/concurrency

- **Basis:** authorization `idempotency_key` (plan + artifact triple + target
  binding + class + scope-lists hash + caller scope from a fixed vocabulary +
  issuance nonce). Same key resubmitted: no record → proceed; sealed →
  return existing `evidence_id` only after binding re-validation against
  current resolution (stale-target serve refused); live lease →
  `EXECUTION_IN_PROGRESS` (poll, never second-start); unknown → `OUTCOME_UNKNOWN`
  path (§25).
- **Cross-process mechanism:** database unique index on `idempotency_key` +
  atomic CAS lifecycle (`ISSUED→CONSUMED` on start; stage leases for stored
  rounds). Filesystem/in-process locks are not consulted. Crash matrix:
  pre-start crash → safe re-drive; mid-transport → unknown/new-authz;
  post-seal-pre-index → orphan via sweep + defined recovery (re-index the
  sealed record under its original key after hash verification — the *only*
  permitted reattachment, because the bytes are already sealed and bound);
  post-index-pre-audit → audit gap recorded in a *separate* audit record
  (never by mutating sealed evidence — resolves the 5A seal/annotate
  contradiction).
- **Caller scope:** fixed vocabulary (e.g. `scheduled`, `manual`, `retry-new-
  authz`), never free strings; distinct keys are distinct intent by definition,
  rate-limited per program/window at the scheduler.

---

## 27. Legacy Nuclei path handling

- **Normative:** `NucleiRunner.to_findings()` (stdout-nonempty → matched)
  **must be deleted or hard-gated before 5F integration.** Permitted forms:
  deletion, or a guard raising unless an explicit `legacy_unsafe=True` flag
  passed only by archived tests (flag itself forbidden in executor code paths
  by review gate).
- Nuclei stdout/stderr are raw evidence only; output alone can never become
  `CONFIRMED` (or any positive label) — stated as a 5I verifier invariant with
  a negative test (hostile stdout asserting compromise classifies at most
  informational).

---

## 28. Resource ceilings

Global immutable ceilings module (operator config may only tighten; boot
asserts `config ≤ ceiling`, fail-closed):

| Dimension | Ceiling (default; tighten-only) | Enforcement point |
|---|---|---|
| Wall time / exec | 60 s HTTP, 120 s Nuclei, 15 s browser (10 nav + 5 obs) | wrapper + worker kill + reap check |
| Connect / read / chunk-stall | 10 s / 10 s / 10 s | pinned adapter |
| Request / response / decompressed | 16 KiB / 512 KiB / 2 MiB + ratio abort | transport cap |
| Redirects / requests / DNS answers | 5 hops / 7 reqs / 8 addrs | loop + resolver cap |
| Browser | 1 page, 1 context, worker kill | executor + mp supervise |
| Nuclei | concurrency 1, rate ≤5/s, retries 0, stdout+stderr ≤1 MiB | argv + capture cap |
| Temp / memory / CPU | quota per exec + subprocess RLIMIT_AS/CPU | sandbox |
| Pending authorizations | 1000 (overflow rejects issuance) | issuance store |

Unknown/unbounded → refuse to start (`LIMIT_UNKNOWN`).

---

## 29. Secret handling

- Executor inputs contain no secrets by schema (credential-shaped headers/
  values rejected at validation + intake). Authenticated testing is out of
  scope (5A default: unauthenticated only; future vault is a separate design).
- Runtime: resolver connection strings owned outside executor logic; errors
  sanitized at adapter boundary; hardcoded `db.py` credentials never logged
  (explicit review gate); evidence minimized per §23; audit carries hashes +
  decisions only.
- Credentials never enter identity hashes (URL/body-structure only, secret
  header values excluded — preserves existing `http_executor` precedent).

---

## 30. Audit model

Append-only, write-ahead (START) / write-once (terminals), one record per
transition: `execution_id, authorization_id, stage_lease, transition, at,
actor, target slot + resolved base, scope decision + reason, artifact triple +
fixture pin, derivation refs, evidence hashes (post-seal), error codes`.
No secrets, no full bodies (hashes + bounded reasons). Correlatable
`authorization → execution(s) → evidence → verifier input` without trusting
any single record. Audit-write failure pre-START blocks execution; post-START
failures land in a separate audit-gap record (never sealed-evidence mutation).

---

## 31. Verifier boundary

One-way handoff: sealed evidence + attempt + binding refs + issuance record
copy. Verifiers re-check bindings, hash integrity, freshness, and
`complete: true`, treating all content as untrusted (XSS posture generalized).
Results never flow back into execution (no verdict-driven re-probing;
follow-ups need new plans + authorizations). Executor success vocabulary
excludes all verdict terms by schema and by review gate. 5I adds Nuclei/HTTP
classifiers under the same posture with conservative positive bars.

---

## 32. Attack-path analysis

| # | Attacker input → boundary | Missing control (pre-revision) | Architectural control (this revision) | Residual |
|---|---|---|---|---|
| 1 | Forged authorization JSON → authz intake | authenticity | §5 issuance-record + typed API; §6 type rule | issuer-host compromise (o/s) |
| 2 | LLM-shaped authz blob → scheduler/queue | channel typing | §6 MIME-typed channel + negative test | none structural |
| 3 | `ArtifactRef` id substituted for plan-bound id → binding check | identity disambiguation | §7 canonical + ignore-legacy + disagree-test | legacy re-mint effort |
| 4 | Second VALID artifact for same plan → selection | selection rule | §8 exactly-one + AMBIGUOUS terminal | upstream re-mint latency |
| 5 | DELETE plan + GET artifact → translator | reconciliation | §9 equality + TRANSLATION_REJECTED + schema convergence diff | legacy DELETE rows until migrated |
| 6 | Planner drift / P≠O misreport → audit/verifier | derivation binding | §10 contract binding + dual hashes + forbidden strings | skeleton review burden |
| 7 | Scope revoked between SUBMIT/READ → READ | READ re-gate | §11 two leases + READ gates | intra-request change (bounded) |
| 8 | Attacker fixtures → H1 proof | fixture provenance | §12 registry + pinning + mismatch terminal | corpus gaps |
| 9 | Target 302 to sibling; Nuclei follows internally → network | binary containment | §20 no-follow + egress proxy + chain attestation | binary 0-day (sandbox) |
| 10 | Rebinding/multi-A → socket | dial-time binding | §17 pinned resolver/proxy + per-hop re-resolve | DoH-in-page (proxy DNS) |
| 11 | Sibling redirect (same eTLD+1) → scope | redirect rule | §16 exact-host + versioned CDN registry | curated-pair maintenance |
| 12 | `0x7f.0.0.1`, trailing dot, userinfo, IDN, `..` → canonicalizer/scope | shared normalization | §18 single canonicalizer + fuzz matrix | confusable-IDN policy tuning |
| 13 | Session in Location, cookie echo, stdout secret → evidence/store/LLM | minimization | §23 hash-default + scrubber + no-LLM rule + sanitized errors | PII in app bodies (retention/ACL) |
| 14 | Crash mid-transport → retry duplicates stored persist | unknown semantics | §25 OUTCOME_UNKNOWN + new-authz + new-round rules | operator re-drive latency |
| 15 | Seal/index/audit crash interleavings → orphan/gap | recovery ordering | §26 re-index-only + separate gap record | sweep monitoring |
| 16 | `to_findings` wired to handoff → stdout CONFIRMED | legacy deletion | §27 delete/gate + 5I bar | none after deletion |
| 17 | Slow drip, zip bomb, chain storm, chromedriver sprawl → resources | ceilings | §28 ceiling module + boot assert + sandbox caps | distributed issuance cost (rate-limit) |
| 18 | Same host, other program → authorization | target binding | §13 (program,host) isolation key + scope pair check | program-row provisioning errors (fail closed) |

---

## 33. Complete blocking requirement table

| ID | Requirement (frozen) | Resolves | Verified by |
|---|---|---|---|
| R-B1 | Issuance-record authenticity; executor loads via typed API; no parse-then-verify | F-forgery (A-1) | negative blob test; no `authorize_from_*` constructors exist |
| R-B2 | Typed channel; authorizations never parsed from text/logs/LLM/scheduler messages | A-2 | channel test; scheduler import ban on issuance writers |
| R-B3 | Plan-bound artifact identity canonical; legacy ref ignored | A-3 | disagree-test; grep gate: executor never references `artifact_ref` |
| R-B4 | Exactly-one artifact; ambiguity terminal | A-4 | two-artifact refusal test |
| R-B5 | Method allowlist sans DELETE; equality; mismatch terminal | A-5 | DELETE + mismatch matrix |
| R-B6 | Derivation-contract binding; dual hashes; forbidden report strings | A-6 | oracle-path hash tests; string gate |
| R-B7 | Round auth + two leases; READ re-gates; SUBMIT ⇏ READ | A-7 | lease + drift test battery |
| R-B8 | Issuer fixture registry; pinned hashes; prohibited-source test | A-8 | mismatch + disjointness tests |
| R-B9 | Projector allowlist + parse-back diff; pinned binary; no-follow; egress proxy | A-9 | capability-denial matrix; argv test |
| R-B10 | Pinned resolver/dial-by-IP/proxy; full IP-class denies; rebinding harness | A-10 | rebinding + multi-A + literal-form tests |
| R-B11 | Exact-host redirects; versioned CDN registry; per-hop checks | A-11 | sibling/parent/chain/loop matrix |
| R-B12 | Single canonicalizer covering §18 list; shared by all executors | A-12 | fuzz corpus; no-duplicate-normalization gate |
| R-B13 | Hash-default evidence; scrubbers; sanitized errors; no-LLM rule | A-13 | secret-canary tests; context-flow audit |
| R-B14 | OUTCOME_UNKNOWN/INCOMPLETE; verifier-consumes-complete-only; at-most-once label | A-14/15 | crash-matrix tests |
| R-B15 | DB unique index + CAS; orphan recovery; no fs-lock reliance | A-14/15 | two-worker race test |
| R-B16 | `to_findings` deleted/gated; stdout-never-CONFIRMED | A-16 | hostile-stdout test |
| R-B17 | Ceilings module + boot assert + sandbox enforcement | A-17 | over-config boot refusal; cap tests |
| R-B18 | (program,host,scheme,eff-port,path,policy-hash) binding | A-18 | cross-program confusion test |
| R-B19 | Issuer view (plan/hypothesis/artifact/resolution/scope/validation/fixtures/derivation/class/resources/TTL/replay) | READY≠AUTHORIZED | view-completeness test; READY-label misuse test |

---

## 34. Reuse/extend/wrap/isolate/replace/new table

| Component | Verdict | Security reason |
|---|---|---|
| HypothesisEngine, TestPlanBuilder, TargetIntelligence projector, TargetMatcher, KnowledgeStore | REUSE AS-IS | Authority-free, tested; executor must not import them (decoupling gate). |
| `artifact_validator`, `nuclei_artifact_validator` (H1/H2) | REUSE AS-IS | Re-run verbatim at execution revalidation with pinned fixtures; no new semantics. |
| ArtifactStore, ArtifactRetrieval, TestPlanReadiness | REUSE AS-IS | Correct store/readiness; readiness stays informational; store's fs-lock caveat not inherited by executor index. |
| HTTPEvidenceExecutor core (request build, redirect loop shape, redaction, bounded body) | WRAP | Sound transport core; needs pinned adapter, canonicalizer, per-hop scope, ceilings, dual-hash sealing around it. |
| BrowserEvidenceExecutor + OraclePlanner + composite dispatcher | WRAP | Isolation/capability/oracle ownership sound; adapter adds derivation binding + leases, subtracts nothing. |
| XSSVerifier | REUSE AS-IS | Sole classifier; handoff extends binding checks to new evidence shape. |
| NucleiRunner transport (`subprocess` list-form, timeout, dry-run default) | WRAP | Keep list-form/timeout discipline; close template-path trust, flags freedom, missing containment via wrapper (§20). |
| `NucleiRunner.to_findings` | REPLACE (delete/gate) | Stdout→matched heuristic is the false-CONFIRMED path; incompatible with evidence posture. |
| NucleiPipeline, NucleiTemplateGenerator, nuclei_validator | REUSE AS-IS (upstream only) | Generation/validation stays pre-execution; executor never calls generator. |
| ScopePolicy | WRAP + RENAME → ProductReadinessPolicy | Advisory relevance input only; name currently implies execution authority it must never carry. |
| xss_case_builder scope idiom, http redirect idiom | EXTEND into single ScopeEvaluator + canonicalizer | Correct fragments, insufficient coverage; extend, do not copy a fourth time. |
| HTTPFingerprintRunner.check | ISOLATE | Unbounded redirect/DNS behavior; keep in relevance flow, ban from executor paths (import gate). |
| HTTPCollector | REUSE AS-IS | Read-only intelligence projection. |
| watch_xss_verify job (case_id dedupe, per-case isolation, bounds) | EXTEND | Precedent generalized into cross-process idempotency + ceilings. |
| Issuance store, TargetResolver, ScopeEvaluator, canonicalizer, translators/projector, fixture registry, CDN registry, evidence store, audit trail, idempotency CAS, egress proxy config, ceilings module | NEW | Nothing in-tree provides them; each is its own narrow phase (§35). |

No replacement for stylistic reasons. The `ScopePolicy` rename is semantic
disambiguation (deferred to implementation, wrapped first).

---

## 35. Revised phase order

Safest sequence (deviation from 5A proposal: 5H-core before executors; schema
decisions front-loaded):

1. **5B Authorization + authenticity + issuer view** (issuance record, typed
   API, lifecycle, negative tests; canonical identity + exactly-one +
   method rule frozen as normative).
2. **5H-core Evidence contract + idempotency/CAS + audit ordering + ceilings
   module** (schemas, split hashes, terminals, unique-index contract, boot
   assert — no store backend yet).
3. **5C Target resolver** (read-only adapter, reassignment/drift outcomes).
4. **5D Scope + canonicalization + input validation** (evaluator, CDN
   registry schema, canonicalizer fuzz corpus, fixture-registry schema).
5. **5E HTTP executor** (translator + pinned adapter + per-hop scope, against
   5H-core substrate).
6. **5F Nuclei executor** (projector + parse-back gate + sandbox + egress +
   legacy-path deletion).
7. **5G XSS adapter** (derivation binding + leases + dual hashes, preserving
   all oracle invariants).
8. **5H-store Evidence store backend + sweep + retention/ACL.**
9. **5I Verifier handoff + Nuclei/HTTP classifiers** (complete-only,
   conservative bars, hostile-stdout tests).
10. **5J E2E** (local harness only; production after full re-review clearing
    every R-B row).

---

## 36. Implementation gates

Each gate: invariant → deterministic test requirement → failure behavior.
All gates fail closed (block the phase; nothing downstream starts).

- **G-5B (authenticity):** invariant: no non-issuance path yields authority.
  Tests: byte-identical-blob rejection; revocation/expiry/CAS-loss replay
  rejection; `authorize_from_dict/json` absence (static gate). Fail: 5B not done.
- **G-5H-core (evidence/idempotency):** invariant: at-most-once + complete-only
  consumption. Tests: crash matrix (pre-start/mid-transport/post-seal/
  post-index), orphan-recovery-only path, audit-gap separation, timing-excluded
  hashes. Fail: no executor phase starts.
- **G-5C (resolution):** invariant: stale/gone/reassigned targets never
  execute. Tests: gone/program-gone/reassigned/drift matrix on fakes. Fail:
  5D cannot pass (evaluator has no fresh input contract).
- **G-5D (scope):** invariant: exact-host + canonicalization + IP policy hold.
  Tests: §16–§18 matrices (sibling/parent/chain/loop/ports/schemes/IP forms/
  IDN/userinfo/dot-segments/double-encoding) + fuzz corpus green. Fail: no
  live transport anywhere.
- **G-5E (HTTP live-fire):** invariant: bounded, scoped, secret-minimal single
  requests. Tests: SSRF/redirect/DNS/canary-secret/budget suites against local
  harness; config-over-ceiling boot refusal. Fail: no 5F/5G live work.
- **G-5F (Nuclei live-fire):** invariant: projected-YAML-only + contained
  binary. Tests: capability-denial matrix, parse-back diff, argv allowlist,
  binary checksum, egress-proxy proof (direct egress blocked), legacy-path
  absence. Fail: Nuclei stays dry-run-only.
- **G-5G (XSS live-fire):** invariant: derivation-bound oracle execution with
  all prior invariants intact. Tests: dual-hash expectations, planner-
  invariance under hostile `delivery_pattern`, clean-READ, lease/drift
  battery, no-new-page-callable-surface. Fail: XSS stays HTTP-reflection-only.
- **G-5I (handoff):** invariant: verifiers consume complete bound evidence
  only. Tests: binding-mismatch, stale-evidence, incomplete/unknown refusal,
  hostile-stdout non-confirmation. Fail: 5J does not start.
- **G-5J (E2E):** invariant: end-to-end at-most-once with sealed audit on
  local harness. Tests: full-pipeline harness green + adversarial re-review
  clearing every R-B row. Fail: no production enablement.

---

## 37. Residual risks

Binary (Nuclei/Chromium) 0-days (pin + checksum + sandbox + proxy; tracked);
intra-request reassignment (short windows + per-hop/dial checks); fixture
corpus gaps for novel families (growth in 5F); DoH-in-page exfil (proxy DNS
control in 5G); operator double-issuance under distinct caller keys
(rate-limited; distinct-keys-are-distinct-intent by definition); scope-list
propagation delay ≤ resolver TTL (fail closed on drift); correlation tokens
visible to target infra (non-secret by policy); PII in application bodies
(retention + ACL in 5H-store).

---

## 38. Open questions

1. **Egress topology:** dedicated sidecar proxy vs NetNS vs transport-adapter
   pinning per class. Safe default: sidecar egress proxy for Nuclei + pinned
   adapter/proxy for HTTP/browser (uniform policy, single audit point).
   Close before 5F (blocks G-5F egress proof).
2. **Idempotency unique-index backend:** Mongo unique index (colocated with
   issuance store, preferred for operational simplicity) vs dedicated lock
   service. Safe default: Mongo unique index + CAS. Close before 5H-core
   implementation (blocks G-5H-core race test).
3. **Legacy `TestPlan.artifact_ref` removal timeline:** ignored immediately;
   physical removal is a later schema migration (no safety impact once the
   ignore-gate is tested).

---

## 39. Final architecture diagram

```
LLM / Research (untrusted intent)
  → deterministic contracts (schemas + validators)
  → validated artifact + READY (still not authority)
  → AUTHENTICATED explicit authorization (issuance record, typed API load)
  → fresh target resolution (reassigned/drift-aware)
  → scope enforcement (exact-host, canonicalized, per-hop + dial-time)
  → artifact/derivation revalidation (pinned fixtures, method equality)
  → bounded executor (HTTP / Nuclei-projection+sandbox / XSS-adapter)
  → immutable raw evidence (split hashes, secret-minimized, complete-flagged)
  → deterministic verifier (sole classifier, complete-only)
  → finding
```

Structurally absent: LLM→authorization (no issuance credential, typed channel);
READY→execution (lifecycle + binding gates); artifact→command/target
(projectors + egress + scope); target-response→scope-bypass (per-hop + dial
enforcement); Nuclei-stdout→CONFIRMED (legacy path deleted, conservative 5I
bars); browser-page→verifier-authority (capability + exact predicates +
anti-harvest + binding checks).

---

## 40. Explicit statement: no code modified

No repository file was modified in this design phase. No schemas, authorization
code, signing, database changes, executors, scope logic, or evidence logic
were implemented. No existing file was edited, renamed, moved, or deleted. The
only filesystem write is this report itself at the mandated path. No target
was executed against, no HTTP request was sent, no Nuclei invocation was
performed, no browser was launched, no verifier was invoked, and no finding
was created.

## 41. Explicit statement: no Git commands run

No Git commands were run in this phase — not `git status`, `git diff`,
`git add`, `git commit`, `git branch`, `git merge`, `git checkout`,
`git switch`, `git restore`, `git reset`, `git stash`, `git fetch`,
`git pull`, `git push`, `git log`, nor any other Git operation. All analysis
was performed through read-only file inspection.
