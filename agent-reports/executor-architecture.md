# Phase 5A — Executor Architecture Design (READ-ONLY)

## 0. Design Premise

**Central question:** *What is the smallest safe execution boundary that allows
Watch to execute an already-approved security TestPlan while preventing
AI/research artifacts from becoming arbitrary code or arbitrary network requests?*

**Answer (summary):** A six-gate, fail-closed pipeline interposed between a
`READY` TestPlan and any network/subprocess/browser action:

```
VALIDATED TestPlan + VALID Artifact + explicit ExecutionAuthorization
  → TargetReResolution (authoritative, fresh)
  → ScopeValidation (deterministic, URL+DNS+redirect aware)
  → ArtifactRevalidation (hash + binding + safety re-run)
  → BoundedTranslation (per-executor closed vocabulary)
  → BoundedExecution (sandbox + limits + network policy)
  → SealedEvidence → Verifier handoff
```

No gate may be skipped, reordered, cached across executions, or inferred from
another gate's output. The Executor never classifies, never authorizes, never
resolves scope by itself, and never executes bytes it has not just revalidated.
Each executor (HTTP probe, Nuclei, XSS) is a separate closed adapter with no
generic "run anything" interface.

This document is **design only**. No code was written, no behavior was changed.

---

## 1. Executive Summary

1. The current repository (Phases 1–4F + XSS oracle/verifier stack) already
   establishes the correct pre-execution invariant: everything from research to
   `TestPlanReadinessReport(outcome=READY)` is **intent + validated inert data**,
   never authority.
2. There is **no Executor yet**. The closest existing executors are
   `HTTPEvidenceExecutor`, `BrowserEvidenceExecutor`, `NucleiRunner`,
   and `HTTPFingerprintRunner` — each built for a narrower, older contract and
   none safe to reuse as a generic TestPlan executor without wrapping.
3. The critical missing object is a first-class **`ExecutionAuthorization`**,
   separate from `TestPlan.status`, `ArtifactReference.validation_state`, and
   `TestPlanReadinessReport.outcome`. `READY` must never imply "may execute".
4. The smallest safe boundary is: **authorize explicitly → re-resolve target
   fresh → re-validate scope deterministically → re-validate artifact bytes
   → translate through a closed per-class vocabulary → execute under hard
   sandbox/limits → seal immutable evidence → hand to verifier**.
5. The highest-risk reuse items are: `HTTPFingerprintRunner.check`
   (`httpx.get(..., follow_redirects=True)`, no SSRF guard — must be
   ISOLATED, never reused by the Executor); `NucleiRunner.run(execute=True)`
   (raw `subprocess.run` with caller-supplied template path — must be WRAPPED);
   and the registrable-domain-only scope idiom copied in three places
   (`database/db.py`, `xss_case_builder.py`, `http_executor.py`) which is
   necessary but **not sufficient** for execution scope.
6. H1 (matcher specificity) and H2 (unsafe interpolation) from the adversarial
   review are already gated at artifact-validation time by
   `nuclei_artifact_validator.py`. The Executor design preserves both gates and
   adds a second enforcement point: the Nuclei translation layer must re-apply
   the same deny rules and must never expand the artifact's closed schema into
   full Nuclei YAML capabilities.

---

## 2. Actual Repository Findings

All statements below were verified by reading the repository (source of truth).
Prior reports were used only as cross-references.

### 2.1 Deterministic research chain (Phases 1–4F)

| Component | File | Finding |
|---|---|---|
| `Hypothesis` | `ai/schemas/hypothesis.py` | UNTRUSTED intent only. Status `PROPOSED/SUPERSEDED/CANCELLED`; no verdict/authority fields; `extra="forbid"`. Identity = full SHA-256 over canonical basis (`program+subdomain+endpoint+type+normalized statement+pattern+sorted provenance+match_id+snapshot_hash`); `hypothesis_id` = `hyp-`+16 alias. `TargetRef` explicitly "descriptive, non-authoritative". LLM metadata excluded from identity. |
| `TestPlan` | `ai/schemas/test_plan.py` | UNTRUSTED intent. Status `PROPOSED/APPROVED/...`; `APPROVED` = "syntax/references passed", explicitly NOT confirmation. `HttpRequestSpec` constrained (method enum incl. `DELETE`, path must start with `/`, no newlines; headers/query `dict[str,str]`). `ArtifactRef` is a hash pointer, never embedded bytes. Identity binds `request_spec` canonical JSON + `hypothesis_id` + `match_id` + `snapshot_hash`. No `scope_allowed` field exists by design. |
| `ArtifactReference` | `ai/schemas/artifact.py` | Closed `ArtifactType` (`nuclei_template/xss_payload/http_request_spec`), closed `ValidationState` (`UNVALIDATED/VALID/REJECTED`). `VALID` = "passed contract/safety validation" only. `artifact_id = art-+SHA256(type+test_plan_id+content_hash+schema)[:16]`. Size caps: Nuclei 32 KiB, XSS 4 KiB, HTTP 16 KiB. `metadata` forbids `verdict/confirmed/scope_allowed/execution_allowed/authorized/finding/evidence` keys. |
| `TargetIntelligence` | `ai/schemas/target_intelligence.py` | Read-only recon snapshot. `scope_snapshot` = observed strings, explicitly NOT authority. `snapshot_hash` = SHA-256 over canonical observations; `intelligence_id` = stable slot. No fetch/resolve/execute fields. |
| `TargetPatternMatch` | `ai/schemas/target_match.py` | Relevance only (`MATCH/PARTIAL_MATCH/NO_MATCH/INCONCLUSIVE`). Deterministic score = `matched/(matched+unmatched+unknown)`. Identity binds matcher version + pattern + target_key + snapshot + sorted criteria. Rejects `verdict/confirmed/scope_allowed/command` extras. |
| `HypothesisEngine` | `ai/researcher/hypothesis_engine.py` | Pure/deterministic. No LLM, network, subprocess, DB, or scope import. Neutral `priority=0.0`. Statement built from IDs + closed enums only — hostile prose cannot enter. Binding failures → `REJECTED`; ineligible kinds → `SKIPPED`. |
| `TestPlanBuilder` | `ai/researcher/test_plan_builder.py` | Pure/deterministic. No payload generation. Closed `_derive_triple` from structured facts only (vuln+IDs → `nuclei_cve/nuclei_scan/nuclei_verifier`; endpoint → `http_probe`; XSS only when `AttackPattern.technique` contains `xss` token, else `UNSUPPORTED`). Request params = names only, empty values, only when pattern-declared AND inventory-observed. Headers always `{}`; body always `None`. |
| `ArtifactValidator` | `ai/researcher/artifact_validator.py` | Pure. `HttpArtifactContent` deliberately omits `DELETE`. `validate_xss_payload`: non-empty, UTF-8, no NUL/CR/LF/C0. HTTP/Nuclei share H2 gates. Nuclei requires fixtures for specificity; missing fixtures → `REJECTED`. `validate_reference_binding` re-checks plan/provenance/hash/identity + re-runs validation. No scope/verifier/executor imports. |
| `NucleiArtifactValidator` | `ai/researcher/nuclei_artifact_validator.py` | H1: `validate_nuclei_specificity` — benign fixture required, static-generic rejection (short <4 chars, generic tokens, status-only), benign-hit → fail, vulnerable-miss → fail. H2: `validate_nuclei_safety` — `DELETE` denied; relative-path only; no absolute URLs; credential headers/values denied; shell constructs/keywords/command-like content denied; callback domains (`interactsh/burpcollaborator/oastify/ngrok/webhook.site/...`) denied; unsafe hosts (private/loopback/link-local/metadata/localhost) denied; embedded script content denied; body CR/LF denied. |
| `ArtifactStore` | `ai/knowledge/artifact_store.py` | Immutable content-addressed file store (`records/<sha256>.json`, atomic write + fsync). Stores ONLY `VALID` references. Identity-conflict → error, never overwrite. Read path re-runs safety gates + hash/identity checks. No network/LLM/subprocess/verdict. |
| `ArtifactRetrieval` | `ai/researcher/artifact_retrieval.py` | Strictly read-only. `get_by_binding` requires ≥1 filter; no unfiltered enumeration. `audit_provenance` = structural PASS/FAIL/INCONCLUSIVE. `verify_all` sweep surfaces corruption/orphans, never repairs. |
| `TestPlanReadiness` | `ai/researcher/test_plan_readiness.py` | Read-only. Requirement map from closed category/execution only (`nuclei_*→nuclei_template`, `xss_*→xss_payload`, `http_*→http_request_spec`); prose never consulted. `READY` = required stored artifacts exist + bindings + provenance + integrity all pass. Explicitly NOT scope authorization, NOT execution permission. No execution/scope/authorization fields. |

### 2.2 Scope authority today (fragmented — key finding)

| Location | Semantics | Executor relevance |
|---|---|---|
| `database/db.py`: `Programs.scopes/ooscopes`, `get_domain_name()` (tldextract eTLD+1), `upsert_subdomain` rule (`get_domain_name(host) in scopes and host not in ooscopes`) | Authoritative program scope lists. Ingestion-time gate. Contains hardcoded Mongo credentials (pre-existing issue, out of scope for 5A except: Executor must never log/import them). | **Authoritative source** the Executor must consult at re-resolution time. But rule is hostname-only; it does not cover scheme/port/path/redirect/DNS/IP. |
| `ai/verification/xss_case_builder.py` | Exact mirror of the above rule, offline tldextract (`suffix_list_urls=()`), applied to both `example_url` hostname and recorded `subdomain`. Fail-closed (no case on miss). | Correct precedent for deterministic scope *construction*, but it runs at case-build time (stale by execution time). Executor must re-run an equivalent check at execution time, not trust it. |
| `ai/correlator/scope_policy.py` (`ScopePolicy.evaluate`) | **Not a URL scope policy.** Decides `READY_FOR_SCAN/DRY_RUN_ONLY/EXCLUDE` from `product_match/version_status/presence_status`. No host/scheme/port/redirect/DNS logic. | REUSE only as a *relevance* input; it must never be mistaken for execution scope authority. Naming is misleading — future phases should rename or wrap it (`ProductReadinessPolicy`). |
| `ai/verification/http_executor.py` `_check_redirect_safety` | Same-registrable-domain redirect gate + no cross-port + no HTTPS→HTTP downgrade + `http/https` only + cycle detection. Offline tldextract. | Strongest existing redirect control. REUSE pattern, but EXTEND with DNS/IP/absolute-URL/Host-header controls (currently missing). |
| `ai/verification/browser_executor.py` network policy | Exact `(scheme,host,port)` same-origin allow; everything else `abort`; document-type cross-origin surfaces error. | REUSE pattern for browser adapter. |

**Conclusion:** no single canonical "is this exact request in scope right now"
function exists. The Executor phase must create one (NEW) that composes
program lists + re-resolved target + per-request URL + redirect chain + DNS.

### 2.3 Existing execution-adjacent code

| Component | Finding |
|---|---|
| `ai/verification/http_executor.py` (`HTTPEvidenceExecutor`) | Evidence provider, never verdict authority (test-enforced). Query/body injection of `payload + "~~" + token`. Methods constrained by attempt construction (GET/HEAD query; POST/PUT/PATCH body-form). Manual redirect loop (`max_redirects=5`), `timeout=10s`, `max_body_bytes=512KiB`, bounded streaming, redirect chain + `request_body_hash`/`response_body_hash` (SHA-256), sensitive-header redaction (`cookie/authorization/proxy-authorization`, `set-cookie/...`), WAF BLOCK/TRANSFORM classification, `_UnsupportedRequest/_VerificationError/_TransportTimeout/_TransportError` → structured evidence (never exception-as-success). Missing vs 5A needs: no DNS/IP allowlist, no Host-header prohibition, no per-execution authorization binding, no idempotency key. |
| `ai/verification/browser_executor.py` (`BrowserEvidenceExecutor`) | Fresh isolated context per attempt; GET-only navigation (POST browser → explicit error, never downgraded); query-only token carrier; `stored_read` navigates clean (no payload/token bound); capability-protected instrumentation transport (`secrets.token_hex(32)`, `compare_digest`, Python-side buffer, page holds write-only callable); same-origin network policy; E2 oracle requests isolated from generic `network_requests`; wall-clock bound via `mp.Process` kill (`navigation_timeout + observation_window`); hard caps (64 runtime entries/240 chars, 512 chain events, 5 nav hops, 512 KiB body). Missing vs 5A: no authorization binding, no artifact translation layer (consumes `VerificationAttempt`, not `ArtifactReference`). |
| `ai/verification/oracle.py` | Trusted S/D/W derivation (`S=sha256(salt‖attempt‖phase)[:16]`, `D=W(S)` FNV-1a over UTF-16 units, JS-bit-identical). Exact E1/E2/E3 predicates. `PreExecutionInput` anti-harvest boundary (D must never appear pre-execution). Planner owns payload; LLM pattern is attribution only. |
| `ai/verification/verifier.py` (`XSSVerifier`) | Sole classification authority. `POTENTIAL` (meaningful reflection / `SINK_REACHED` demotion), `CONFIRMED` only via oracle E1/E2/E3 with pair-validity + run-freshness + candidate-identity + same-origin + anti-harvest (+ HTTP pair for reflected). Never `NOT_VULNERABLE`. `_enforce_evidence_binding` downgrades mismatched evidence to ERROR. Executor treated as untrusted input. |
| `ai/verification/composite_executor.py` | Pure dispatcher by `attempt.mode`; never classifies; missing-executor → `ValueError` (never fall-through). Correct precedent for per-class routing. |
| `ai/verification/xss_pipeline.py` | Pure connector (`orchestrator.analyze` → `verifier.verify`, exactly once each). No config construction, no verdict logic. |
| `ai/researcher/nuclei_runner.py` (`NucleiRunner`) | `build_command = [binary, -t, template, -u, target, -no-color]`. `_is_live_eligible` requires `scope_status==READY_FOR_SCAN` + non-empty target/program. Default dry-run; live only with `execute=True`. `subprocess.run(capture_output, timeout=120)`. `to_findings`: `matched = COMPLETED and output.strip()` + scope/presence/version passthrough. Gaps: template path is caller-supplied (no hash binding), no flags allowlist enforcement, no target re-resolution, no redirect/DNS/IP policy (delegated to nuclei binary), command/args are a list (good) but binary path is configurable (must be pinned). |
| `ai/researcher/nuclei_pipeline.py` (`NucleiPipeline.prepare_for_watch`) | Never live-scans. DetectionSpec → decision → generate (HTTP-only, destructive refusal) → semantic validation → `nuclei -validate` (syntax only) → target selection → dry-run → finding normalization. Establishes that `nuclei -validate` ≠ safety/authorization. |
| `ai/correlator/nuclei_generator.py` | HTTP-only generation; refuses `destructive`; requires reliable signature + method + path + matchers. Raw request `METHOD path?query HTTP/1.1` + headers. Query values percent-encoded. No shell/command fields. |
| `ai/correlator/http_fingerprint.py` (`HTTPFingerprintRunner.check`) | **Must be ISOLATED.** `httpx.get(url, follow_redirects=True)` over caller-supplied `urls` (built from `plugin_verifier.build_checks`), `timeout=10s`, no scope re-check, no redirect-bound, no DNS/IP guard, no response cap beyond `text[:200_000]`. Safe only inside the old `WatchAssetSelector` flow; must never become the Executor's HTTP primitive. |
| `ai/collectors/http.py` (`HTTPCollector`) | Read-only Mongo projection to `HTTPAsset`. No fetching. Safe to REUSE as intelligence input. |
| Mongo models (`database/db.py`) | `Programs` (scopes/ooscopes), `Subdomains`, `Http` (url/final_url/ips/tech/headers), `LiveSubdomains`, `Urls`, `Endpoints` (`param_records` with method/location/source), `XssFindings` (unique `case_id` idempotency). |
| Orchestration (`watch_xss_verify.py`, `backend/models.py`) | `watch_xss_verify.py` = sequential job: `Endpoints(x8_checked)` → `XSSCaseBuilder` → pipeline → `XssFindings` keyed by deterministic `case_id` (skip-when-exists). Bounds `--max-cases/--max-minutes`, failure isolation per case. No queue, no workers, no distributed lock, no authorization object. `TaskSchedule` exists in backend but is unrelated scheduling. No existing component provides execution authorization, idempotency keys, or evidence store. |

### 2.4 Existing tests (spot-checked)

`ai/test_http_executor.py`, `ai/test_browser_executor.py`,
`ai/test_xss_oracle.py`, `ai/test_xss_verification.py`,
`ai/test_xss_stored_round.py`, `ai/test_nuclei_ready.py`,
`ai/test_artifact*.py`, `ai/test_test_plan_readiness.py`,
`ai/test_watch_xss_verify.py`, `ai/test_hypothesis_engine.py`,
`ai/test_test_plan_builder.py` collectively enforce: evidence-not-verdict
separation, oracle exactness, redirect same-domain policy, transport-capability
auth, clean READ, no-downgrade, dry-run defaults, hash-bound identities,
fail-closed validation. No test today covers authorization, re-resolution,
cross-executor idempotency, or evidence immutability — all NEW in 5A.

---

## 3. Current Architecture Integration Point

```
Research → Pattern → TargetIntelligence → Matcher → Hypothesis
  → TestPlan → Artifact(bytes) → ArtifactStore → Retrieval
  → Provenance/Integrity Audit → TestPlanReadiness (READY/NOT_READY/INCONCLUSIVE)
  → *** [EXECUTION AUTHORIZATION BOUNDARY — DOES NOT EXIST YET] ***
  → Executor (NEW) → Raw Evidence (NEW) → Deterministic Verifier (exists: XSSVerifier; Nuclei/HTTP verifiers partial)
  → Finding
```

The Executor plugs in **after** `build_readiness_report` and **before** any
verifier. Its predecessors are frozen: it must accept `TestPlan`,
`StoredArtifact` (reference + bytes), `TestPlanReadinessReport`, and the new
`ExecutionAuthorization` as inputs, and must re-derive everything else fresh.
It must not import the hypothesis engine, test-plan builder, LLM layer,
`KnowledgeStore`, collectors, or fingerprint runner. It may call (read-only):
`ArtifactStore`/`artifact_retrieval` reads, the authoritative target/scope
resolvers (NEW thin adapters over `database.db.Programs/...`), and the
deterministic validators (`artifact_validator`, `nuclei_artifact_validator`).

The existing XSS executors sit **below** the new Executor as bounded
transport plugins: the new XSS adapter translates `VALID xss_payload artifact
+ authorization` into the existing `VerificationAttempt` shape (or a narrower
successor) and delegates transport to `HTTPEvidenceExecutor` /
`BrowserEvidenceExecutor` without weakening their invariants (fresh context,
round identity, salt, clean READ, oracle ownership stays with
`OraclePlanner`/verifier, never the Executor).

---

## 4. Trust Hierarchy

### 4.1 UNTRUSTED (never authority, never executed, never interpolated blindly)

- LLM output, research prose, claims, writeups, CVE descriptions.
- Generated hypotheses, TestPlans, artifact bytes **before** validation.
- `TargetRef` / target descriptions inside Hypothesis/TestPlan/artifact.
- `ScopeSnapshot` strings (observed inventory labels).
- HTTP responses (status/headers/body), redirect `Location` values, HTML/JS,
  DNS answers, Nuclei stdout/stderr, browser page content, callback data,
  timing, `object_hint`/`location_header` discovery hints.
- Attacker-controlled strings anywhere (payloads, parameter values, header
  values, paths before H2 validation).

### 4.2 TRUSTED ONLY AFTER DETERMINISTIC VALIDATION (per-execution, never cached as authority)

- `ResearchPattern` (schema-validated) → `TargetIntelligence` (projected) →
  `TargetMatch` (matched) → `Hypothesis` (engine-built) → `TestPlan`
  (builder-built) → `ArtifactReference(VALID)` → stored artifact bytes
  (hash-verified on read) → `TestPlanReadinessReport(READY)`.
- Each is trusted only for its narrow property (shape/binding/safety), never
  transitively: `VALID` ≠ in-scope; `READY` ≠ authorized; `MATCH` ≠ vulnerable.

### 4.3 AUTHORITY (the only things that can permit/deny execution)

1. **Explicit `ExecutionAuthorization`** (human/system-issued, signed/bound —
     §5). The single permit. Everything else is advisory.
2. **Scope policy + program lists** (`Programs.scopes/ooscopes` read fresh at
   execution time + NEW deterministic per-request scope evaluator).
3. **Target re-resolution** (authoritative DB/inventory read fresh at
   execution time — §6).
4. **Deterministic validators** (`artifact_validator`,
   `nuclei_artifact_validator`, scope evaluator, authorization checker).
5. **Deterministic verifier** (sole classifier; downstream of Executor).

### 4.4 Core invariant

```
READY ≠ AUTHORIZED.   VALID ≠ AUTHORIZED.   MATCH ≠ AUTHORIZED.
No combination of untrusted + validated-but-unauthorized inputs
can produce execution. Only (VALID TestPlan + VALID artifact +
fresh READY + matching AUTHORIZATION + fresh scope PASS) can.
```

---

## 5. Authorization Boundary

### 5.1 Contract (design; not implemented)

```python
# execution_authorization/v1 (NEW, deterministic, extra="forbid")
ExecutionAuthorization:
  authorization_id: str      # "authz-" + sha256(... )[:16]; full key = SHA-256 over binding basis
  idempotency_key: str       # full SHA-256 (canonical basis below)
  test_plan_id: str          # tp-…
  artifact_id: str           # art-… (exact bound artifact; NOT a type wildcard)
  content_hash: str          # full SHA-256 of exact bytes (redundant but explicit)
  hypothesis_id: str | None
  match_id: str | None
  snapshot_hash: str | None  # observation state the authorizer reviewed (advisory)
  target: TargetBinding      # program_name + subdomain (+ asset/record refs, advisory)
  scope_binding: ScopeBinding# program scopes/ooscopes snapshot + policy version (advisory)
  execution_class: Literal["http_probe","nuclei_scan","http_verification","browser_verification"]
  policy_version: str        # e.g. "executor-policy/v1"
  authorization_policy: str  # which human/system policy issued this (e.g. "manual-review/v3")
  issued_at / expires_at: str# ISO-8601 UTC; expires_at mandatory, short TTL
  state: Literal["ISSUED","CONSUMED","EXPIRED","REVOKED","CANCELLED"]
  max_executions: int = 1
  idempotency_scope: str     # opaque caller key, part of identity basis
  audit: {issued_by, reason, ticket_ref, ...}  # strings only, bounded, never secrets
  schema_version: "execution_authorization/v1"
```

Identity basis (all-or-nothing): `authorization_id`/`idempotency_key` bind
`(test_plan_id, artifact_id, content_hash, target program+subdomain,
execution_class, scope policy version + scope-list hash, policy_version,
idempotency_scope)`. Timestamps, issuer notes, and ticket refs are audit-only
and excluded from identity so re-issuance with identical bindings converges.

### 5.2 What must be explicitly authorized

The TestPlan identity, the exact artifact identity (id + content hash), the
target identity (program + subdomain slot), the execution class, and the scope
snapshot (lists + policy version) the decision was made against. Severity,
priority, LLM confidence, hypothesis confidence, readiness outcome, and prose
are never inputs and must be rejected if present (`extra="forbid"` + explicit
validator).

### 5.3 Binding semantics (fail closed)

Authorization binds to **exact target slot + exact artifact bytes +
exact TestPlan + exact execution class + exact scope-list hash**.
It does NOT bind to a live snapshot as permission: `snapshot_hash` is recorded
for audit, but the Executor always re-resolves fresh state and fails closed on
any mismatch that matters:

- artifact bytes/hash differ → `AUTHZ_ARTIFACT_MISMATCH`, no execution.
- `test_plan_id` differs → `AUTHZ_PLAN_MISMATCH`.
- target program/subdomain differ from authorization → `AUTHZ_TARGET_MISMATCH`.
- current scope lists differ from `scope_binding` hash → `AUTHZ_SCOPE_DRIFT`
  (re-review required; never auto-accept).
- `execution_class` differs from TestPlan `execution_type`/required artifact
  type → `AUTHZ_CLASS_MISMATCH`.
- expired (`now ≥ expires_at`), revoked, cancelled, or `max_executions`
  exhausted → `AUTHZ_NOT_LIVE`.
- unknown `policy_version` → `AUTHZ_UNKNOWN_POLICY`.

`ISSUED → CONSUMED` on first execution start (atomic compare-and-swap);
`CONSUMED` authorizations never execute again — retries reference the sealed
evidence via idempotency (§15), they do not re-enter the state machine.

---

## 6. Target Re-resolution Design

**Rule:** the Executor never trusts any target description older than the
current execution. `TargetRef`, `ScopeSnapshot`, `match.snapshot_hash`,
plan `endpoint`, and artifact target fields are all advisory.

### 6.1 Resolution protocol (every execution, in order)

1. Input supplies only the **target slot**: `(program_name, subdomain)`.
2. Executor calls the NEW read-only `TargetResolver` adapter (thin wrapper over
   `database.db.Programs` + `Subdomains`/`Http`/`Endpoints`; injected, never
   imported directly so tests can fake it):
   - load program row → current `scopes`/`ooscopes` + their content hash;
   - load subdomain/asset rows → liveness (exists? `Http`/`LiveSubdomains`
     fresh?), current canonical `example_url`/endpoint base, current
     technology snapshot + `observed_at`.
3. Compare against authorization + plan bindings and record a
   `TargetResolution` struct: `{slot, resolved_endpoint_base, scope_list_hash,
   snapshot_hash_current, resolved_at, outcome}`.
4. Outcomes:
   - target row missing → `TARGET_GONE` (terminal, no execution).
   - program missing/renamed → `TARGET_PROGRAM_GONE`.
   - scope lists changed since authorization → `SCOPE_DRIFT` (do not proceed
     to scope check; surface for re-authorization).
   - endpoint base changed (different host/path/scheme) → proceed to scope
     check against the **new** base; never silently reuse the old URL. If the
     new base fails scope → `SCOPE_DENY`.
   - technology changed → advisory only (recorded; does not permit/deny by
     itself — scope + authorization decide).
   - DNS resolved at request time differs from inventory `ips` → advisory;
     the request-time DNS/IP policy (§8) decides independently.

### 6.2 Staleness, redirects, DNS

- Stale `snapshot_hash` (plan vs current) never blocks by itself but is
  recorded; scope drift and scope denial block.
- Redirects do not update the resolved target: the initial request URL derives
  from the **resolved** base + validated artifact path; every redirect hop is
  re-checked (§7). A redirect that changes origin/scope terminates the
  execution (`SCOPE_REDIRECT_DENY`).
- DNS is resolved at request time by the transport (with its own guard, §8),
  never from inventory `ips`. DNS-rebinding (TTL games, multi-A rotation) is
  handled by pinning the first resolution per execution and re-checking every
  redirect hop + every connection against the IP policy; mismatch → abort.

---

## 7. Scope Enforcement Design

NEW deterministic `ScopeEvaluator` (pure, no network, no LLM, no artifact
content beyond the already-validated path). Runs **after** re-resolution,
**before** artifact translation, and **again per redirect hop / per connection**.

Inputs: resolved `(program, scopes, ooscopes)`, candidate initial URL,
redirect target URLs, dial IPs. Output: `ALLOW/DENY + reason`.

Checks (all must pass; any indeterminacy → `DENY`):

1. **Scheme**: `http/https` only. Anything else → DENY.
2. **Host**: `get_domain_name(host) in scopes and host not in ooscopes`
   (existing rule, preserved) **plus**: exact-host allow against resolved
   subdomain slot — sibling-subdomain, parent-domain, and cross-program reuse
   all DENY even when the registrable domain matches. Wildcard scope entries
   are matched by the same rule (registrable domain), but the exact-host check
   still applies: wildcard permits the domain family, never a specific
   unlisted sibling outside the resolved slot.
3. **Port**: allow `80/443` + port of resolved endpoint only; anything else
   (including `host:nonstandard` reached via redirect) → DENY.
4. **Path**: must equal the validated artifact path (HTTP/Nuclei) or the
   resolved endpoint path + single injected parameter (XSS); path traversal
   (`..`, backslash, absolute-URL-in-path) already rejected at H2 but
   re-checked here.
5. **Redirects**: every hop re-runs 1–4 + existing `http_executor` rules (same
   registrable domain, no cross-port, no HTTPS→HTTP downgrade, cycle
   detection, hop cap). Cross-host within same eTLD+1 is allowed **only** when
   the new host also passes check 2 against the same program (kills
   sibling-host redirect bypass). Final URL outside scope → DENY even if the
   initial URL passed (no `initial==final` assumption).
6. **DNS/IP**: resolve each hop fresh; DENY private/loopback/link-local/
   metadata (`169.254.169.254`, `metadata.google*`, `localhost`), RFC1918,
   IPv6 local (`::1`, `fe80::/10`, `fc00::/7`), and empty/unresolvable answers.
   Pin per execution; rebinding → abort.
7. **CDN/proxy**: CDN CNAME/IP is not scope evidence. Scope derives from Host
   + program lists, never from `cdn` labels or `Server` headers.
8. **Cross-program isolation**: `(program, host)` pair is the isolation key;
   the same hostname under two programs requires authorization for the exact
   program in the authorization object.

If scope cannot be deterministically established (missing program, malformed
URL, unresolvable suffix, DNS failure): **FAIL CLOSED (`SCOPE_UNKNOWN`)**.

---

## 8. Artifact Revalidation Design (immediately before execution)

Even for a `VALID` + `READY` artifact, the Executor re-runs this sequence
**after** scope validation, **before** translation (order matters: no wasted
translation of an unscopable request; no scope decision influenced by artifact
content):

1. Retrieve exact `artifact_id` from `ArtifactStore` (fail on miss/corruption).
2. `content_hash == SHA256(bytes)`; `artifact_id` recomputes from
   `(type, test_plan_id, hash, version)`.
3. `reference.test_plan_id == TestPlan.test_plan_id`;
   `hypothesis_id/match_id/snapshot_hash` equal the plan's bindings exactly.
4. `artifact_type` ∈ closed vocabulary and equals the type required by
   `(test_category, execution_type)` requirement map.
5. Size re-check against `MAX_*_BYTES`.
6. Re-run the applicable safety validator on the bytes (`validate_nuclei_safety`
   / `validate_http_safety` / `validate_xss_payload`); for Nuclei also re-run
   `validate_nuclei_specificity` when fixtures are available to the Executor
   (fixtures travel with the authorization context, never inside the artifact).
7. Cross-check translation-relevant bindings: TestPlan `request_spec.path` vs
   artifact `path`; TestPlan `execution_type` vs authorization
   `execution_class`; XSS category vs payload size/charset.
8. Only then call the per-executor translator (§9–11), which accepts **typed
   validated content only** (never raw bytes/dicts).

Any failure → `ARTIFACT_REVALIDATION_FAILED` (terminal for this execution;
evidence records the failure without response data).

---

## 9. HTTP Probe Executor Architecture

Closed vocabulary translator: `VALID http_request_spec artifact + TestPlan.request_spec + authorization` → `BoundedHttpRequest`:

- **Method**: allowlist `GET, POST, PUT, PATCH, HEAD, OPTIONS` (artifact schema
  already excludes `DELETE`; Executor additionally denies `DELETE/CONNECT/TRACE`
  even if a future schema drift reintroduces them — defense in depth).
- **Path**: relative only, must equal artifact path; ≤2048 chars; no CR/LF/NUL,
  no `//host`, no `http://`, no shell/script content (H2 re-applied).
- **Query**: names/values from validated artifact only; values bounded
  (≤1024 chars each, ≤16 params); no credential-shaped values.
- **Headers**: allowlist (`Accept`, `Accept-Language`, `User-Agent: WatchSecurityResearch/1.0`,
  `Content-Type: application/x-www-form-urlencoded` for body probes only).
  Deny `Host`, `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-*`,
  `Content-Length` (transport-owned), anything with CR/LF.
- **Body**: `None` or bounded plain data (≤16 KiB, no CR/LF/NUL, H2-clean).
- **URL**: built as `resolved_base_origin + validated path + validated query`;
  absolute URLs from artifact content are never used as request targets.
- **Transport policy**: timeout 10 s connect+read (configurable down only);
  `max_response_bytes = 512 KiB` (stream + truncate); `max_redirects = 5` with
  per-hop scope re-check; no cookie jar persistence across executions (fresh
  session per execution); no proxy unless explicitly configured by operator
  (never from artifact); TLS verification always on; no Unix sockets.
- **SSRF**: deny absolute-URL targets, private/loopback/link-local/metadata
  IPs, `localhost`, decimal/octal/hex IP obfuscations (normalize via
  `ipaddress` before check); Host header never attacker-controlled; redirect
  Location with credentials (`user:pass@`) → DENY.
- Prohibited by default (explicit): `DELETE/CONNECT/TRACE`, arbitrary Host/
  Authorization/Cookie/proxy, arbitrary absolute URLs, private IPs, metadata
  endpoints, localhost/loopback/link-local/RFC1918/IPv6-local, Unix sockets.

---

## 10. Nuclei Executor Architecture

**Requirement:** the stored template must never become an arbitrary Nuclei
program. The Executor executes a *projection* of the artifact, not the
artifact as code.

### 10.1 Translation, not passthrough

The canonical artifact (`NucleiTemplateContent`: `template_id/method/path/
headers/query_params/body/matchers`) is translated into a **generated,
ephemeral, executor-owned** Nuclei template file (temp dir, random name,
deleted after execution) containing ONLY:

- `id` = `artifact_id` (never artifact `template_id` — kills cross-artifact
  confusion), `http: [ { method, path, headers(allowlisted), body } ]`,
  matchers(word/regex/dsl/status) carried verbatim **after** specificity proof.
- Nothing else: no `workflows`, no `javascript`, no `code`, no `file:`,
  no `interactsh`, no `dns:`, no `network:`, no `headless:`, no `helpers`,
  no second `http` block, no `payloads:`/`attack:` cluster-bomb.

A NEW `NucleiTemplateProjector` (pure) performs this projection; any artifact
field outside the closed content schema fails translation (never ignored).

### 10.2 ALLOW / DENY / ALLOW-AFTER-VALIDATION

| Capability | Verdict |
|---|---|
| `http` GET/POST/PUT/PATCH/HEAD/OPTIONS to resolved target, relative path | ALLOW (within §7–9 bounds) |
| `word/regex/dsl/status` matchers that passed H1 (static + fixture gates) | ALLOW (verbatim) |
| `dsl` with `status_code==NNN` + quoted literals | ALLOW-AFTER-VALIDATION (local H1 re-run + literal allowlist; unparseable DSL → DENY) |
| `DELETE` method | DENY (schema + translator double-deny) |
| `workflows`, `javascript`/`code` blocks, `extractors` with `type: kval` exfil patterns, `payloads`/`attack: batteringram/pitchfork/clusterbomb`, `variables` with shell/backtick content | DENY |
| `interactsh`/callback URLs (`burpcollaborator/interactsh/oastify/ngrok/webhook.site/...`), absolute URLs in path/headers/params/body, unsafe hosts | DENY |
| `file:`/`dns:`/`network:`/`headless:`/`ssl:` protocol blocks | DENY (HTTP-only executor) |
| `self-contained`, `signature`, ` Carly ` metadata | ignored (never executed) |

`nuclei -validate` remains a preflight syntax check only; authorization and
safety come from the gates above, never from the binary's exit code.

### 10.3 Runtime boundary

- Pinned binary path (operator config, never from artifact/plan); flags
  allowlist exactly: `-t <projected-template> -u <resolved-url> -no-color
  -timeout <cap> -rate-limit <cap> -concurrency 1 -retries 0 -bulk-size 1`.
  No `-headless`, `-code`, `- workflow`, `- indiscriminate -a` flags accepted.
- Target list = single resolved URL (never a file of targets, never CIDR).
- Env scrubbed (`PATH` minimal, no proxy env unless operator-set, no secrets).
- `subprocess.run(argv-list, shell=False, timeout, capture_output, max output
  1 MiB)`; non-zero exit → `EXECUTION_FAILED` evidence (never a verdict).
- H1 preserved: matchers already proven specific at validation; Executor
  re-runs the static-specificity check on the projected matchers (cheap, no
  fixtures needed) and fails closed on drift.
- H2 preserved: request fields re-pass `validate_nuclei_safety` post-projection
  (projection bugs fail closed rather than widen).

---

## 11. XSS / Browser Executor Architecture

The new Executor is an **adapter**, not a replacement: the SUBMIT→READ→ORACLE→
OBSERVABLE→VERIFIER stack stays intact and the Executor never mints oracle
material.

### 11.1 Adapter contract

`VALID xss_payload artifact + TestPlan(xss_*) + authorization` →
existing-attempt construction (REUSE `build_verification_attempt` /
`build_stored_round` shapes), then delegate transport to the injected
`HTTPEvidenceExecutor` / `BrowserEvidenceExecutor` via
`CompositeVerificationExecutor`.

Preserved invariants (non-negotiable, test-guarded):

- Fresh isolated browser context per attempt; capability-protected transport;
  same-origin network policy; GET-only browser navigation (POST browser →
  explicit error); query-only token carrier.
- Stored rounds: SUBMIT (HTTP) gated before READ; READ navigates **clean**
  (payload/token reach the page only via server persistence); `round_id`,
  `oracle_identity`, ordering, and run-freshness enforced by verifier.
- Oracle: `S/D/W` minted by `OraclePlanner` under `run_salt`; Executor never
  sees `run_salt`, never generates `S/D`, never places `D` on the wire;
  E1/E2/E3 predicates evaluated only by verifier.
- `no navigation for E2`: oracle network events are page-initiated runtime
  requests, never top-level navigations; adapter must not construct navigations
  to `/.watch-oracle/`.

### 11.2 What the artifact may/may not control

The artifact supplies **only the payload string** (already bounded ≤4 KiB,
UTF-8, no CR/LF/C0/NUL). It never controls: endpoint (resolved base), method
(from `param_records` provenance via plan), parameter location, navigation
targets, origins, callbacks, headers, cookies, browser flags, file paths,
subprocess args, or oracle seeds. Payload is concatenated as
`payload + "~~" + correlation_token` by the existing executor — the adapter
passes the payload through byte-identically and never pre-decodes/encodes it
(the transport layer owns encoding).

The browser is treated as adversarial: page JS cannot read the capability,
cannot append to Python-side buffers, cannot promote its own events to oracle
evidence, and any transport-shape violation is dropped silently then surfaced
as missing-evidence (INCONCLUSIVE), never as success.

---

## 12. Evidence Model

Executor returns **evidence, never verdict**. Three first-class types:

```python
ExecutionAttempt:  # what was tried (input record)
  execution_id, authorization_id, test_plan_id, artifact_id, content_hash,
  execution_class, target slot + resolved endpoint base, scope_list_hash,
  started_at, attempt_seq (0 for single-shot; stored SUBMIT/READ share round_id)

ExecutionEvidence:  # what was observed (output record)
  evidence_id, execution_id, authorization_id, test_plan_id, artifact_id,
  target slot + resolved + final URLs, started_at/finished_at,
  transport: {method, request_url_initial, request_url_final, redirect_chain[],
    dns_observations[], request_body_hash, response_status,
    response_headers_redacted{}, response_body_hash, response_body_truncated? (bounded, opt-in)},
  browser_observations? (dialog/network-oracle/eval channels, capability-gated),
  nuclei_raw_output? (bounded 1 MiB, stdout+stderr separated, exit code, command argv),
  timing {durations_ms}, evidence_hash (SHA-256 over canonical evidence, minus itself),
  schema_version "execution_evidence/v1"

ExecutionError:    # why nothing observable exists (typed, not a verdict)
  execution_id, stage (AUTHORIZE/RESOLVE/SCOPE/REVALIDATE/TRANSLATE/EXECUTE/SEAL/HANDOFF),
  code (AUTHZ_* | TARGET_* | SCOPE_* | ARTIFACT_* | LIMIT_* | TRANSPORT_* | INTERNAL_*),
  detail (bounded, redacted), retryable: bool
```

Separation enforced by schema: `ExecutionEvidence` has **no** `status/
verdict/confirmed/severity/exploitability` fields (`extra="forbid"`); the only
outcome labels are transport facts (`http_status`, `timeout`, `blocked`).
Interpretation lives exclusively in verifier input mapping, never in evidence.

---

## 13. Evidence Integrity

- Raw evidence immutable after sealing: `evidence_hash = SHA256(canonical JSON
  of evidence minus hash field)`; any post-seal mutation breaks the hash.
- Bindings: `evidence.execution_id → authorization.authorization_id →
  (test_plan_id, artifact_id, content_hash, target slot, scope_list_hash)`.
  Evidence carries all five bindings redundantly so reassignment is detectable
  without a join.
- No reassignment: verifiers look up evidence by `execution_id` and re-check
  bindings; mismatched `test_plan_id/artifact_id/target` → evidence rejected
  (same pattern as `XSSVerifier._enforce_evidence_binding`).
- Evidence never declares a finding: schema rejection of verdict fields +
  code review gate.
- Store: content-addressed immutable evidence store mirroring `ArtifactStore`
  (`records/<evidence_hash>.json` + index by `evidence_id`; atomic writes;
  `verify_all`-style sweep) — NEW in a later phase (5H), designed here, not built.

---

## 14. Executor State Machine

```
AUTHORIZED ──▶ TARGET_RESOLVED ──▶ SCOPE_VALIDATED ──▶ ARTIFACT_REVALIDATED
  ──▶ TRANSLATED ──▶ EXECUTION_STARTED ──▶ EXECUTION_COMPLETED
  ──▶ EVIDENCE_SEALED ──▶ HANDOFF_TO_VERIFIER (terminal success)
```

Failure terminals (each bound to the stage that produced it, with typed code):

- `AUTHZ_REJECTED` (expired/revoked/mismatch) · `TARGET_UNRESOLVABLE`
  (`TARGET_GONE/SCOPE_DRIFT`) · `SCOPE_DENIED` (incl. redirect/DNS/IP deny) ·
  `ARTIFACT_INVALID` · `TRANSLATION_REJECTED` · `EXECUTION_FAILED/TIMEOUT/
  BLOCKED/LIMIT_EXCEEDED` · `SEAL_FAILED` (internal, never ships partial
  evidence) · `CANCELLED` (operator cancel before `EXECUTION_STARTED` only).

Legal transitions: strictly forward along the chain, plus `* → <stage>_FAILED`
/ `CANCELLED` (pre-start). Forbidden: skipping any gate; re-entering after
`EVIDENCE_SEALED`; `EXECUTION_STARTED` after expiry/cancel/scope-drift;
second `EXECUTION_STARTED` under one authorization (`max_executions=1`);
`HANDOFF_TO_VERIFIER` without a sealed evidence hash. No state named
`CONFIRMED/VULNERABLE/NOT_VULNERABLE` exists in this machine.

---

## 15. Idempotency / Concurrency

- Idempotency key = `authorization.idempotency_key` (binds plan + artifact +
  target slot + class + scope-list hash + caller scope). The Executor keeps an
  `executions` index keyed by it (DB-backed in production, same pattern as
  `XssFindings.case_id` uniqueness).
- Same key resubmitted:
  - no record → proceed (first execution).
  - record `EVIDENCE_SEALED/HANDOFF` → return existing `evidence_id` without
    re-executing (dedupe).
  - record `EXECUTION_STARTED` (lease live) → return `EXECUTION_IN_PROGRESS`
    (callers poll; never start a second execution).
  - record `EXECUTION_STARTED` with expired lease + outcome unknown →
    `OUTCOME_UNKNOWN` (human-gated re-drive with a **new** authorization;
    never blind retry — the network effect may already have happened, which
    matters for stored-XSS SUBMIT and state-changing probes).
- "Definitely did not start" (failure before `EXECUTION_STARTED`) vs "outcome
  unknown" (started, no sealed evidence) are distinct codes with distinct
  retry rules: pre-start failures are safe to re-drive under the same
  authorization (if still live); post-start ambiguity requires new
  authorization.
- Concurrency: atomic `ISSUED→CONSUMED` CAS + unique index on idempotency key;
  single-flight per key (advisory lock); stored SUBMIT/READ rounds serialized
  by construction (existing verifier gating preserved); Nuclei concurrency
  forced to 1 per execution; browser contexts never shared across executions.

---

## 16. Resource Limits (hard, fail closed when unknown/unbounded)

| Dimension | Limit (default; operator may only tighten) |
|---|---|
| Wall-clock per execution | 60 s HTTP probe; 120 s Nuclei; `navigation_timeout(10 s)+observation(5 s)` browser |
| Connect / read timeout | 10 s / 10 s |
| Max request size | 16 KiB (HTTP), artifact caps otherwise |
| Max response / evidence body | 512 KiB transport cap; evidence truncated field ≤ 8 KiB + full-body hash |
| Max redirects | 5, distinct-URL + cycle-checked |
| Max requests per execution | 1 initial + ≤5 redirect hops (HTTP); 1 Nuclei invocation; stored round = 1 SUBMIT + 1 READ |
| Max browser pages / time | 1 page, 1 context; wall-clock bound via killable worker |
| Subprocess (Nuclei only) | 120 s, 1 MiB captured output, `shell=False`, no retries |
| Nuclei concurrency / rate | `-concurrency 1`, explicit `-rate-limit` (e.g. 5/s), `-retries 0` |
| Max evidence size | 1 MiB per evidence record (enforced pre-seal) |
| Queue/scheduling | bounded pending authorizations (e.g. 1000); overflow rejects new `ISSUED` |

Unknown or unbounded values (missing timeout, missing cap, NaN budget) →
refuse to start (`LIMIT_UNKNOWN`).

---

## 17. Secret Handling

- Executor inputs never contain secrets: artifacts, plans, authorizations, and
  evidence schemas reject credential-shaped fields (`Authorization/Cookie/
  proxy-authorization` headers, bearer/basic values — H2 rules re-applied).
- Runtime secrets (if any, e.g. session tokens for authenticated testing) are
  **out of scope for 5A**: default is unauthenticated testing only. Any future
  authenticated mode requires a separate `CredentialVault` design (env-backed,
  short-lived, never persisted in evidence/logs/prompts).
- Redaction: request/response header redaction (existing `_redact` pattern
  extended to evidence + audit logs); URLs scrubbed of `user:pass@`; error
  strings sanitized (`_sanitize_reason` pattern, sensitive values replaced);
  evidence body truncation happens **before** logging.
- Credentials never enter identity: hashes cover URL/body-structure, never
  secret header values; `request_body_hash` input is URL/body bytes only
  (existing `http_executor` precedent preserved).
- LLM/research documents/artifacts/logs/evidence/prompts never receive secrets;
  audit logs carry hashes and decisions, never raw bodies or headers.

---

## 18. Audit Logging

Immutable, append-only audit trail (one record per state transition), fields:
`execution_id, authorization_id, transition, at, actor, target slot +
resolved base, scope decision + reason, artifact_id + content_hash,
evidence_hash (from SEAL on), error code (on failure)`. Properties:

- Written before the transition it records (write-ahead for START; write-once
  for terminals); never updated in place.
- No secrets, no full bodies (hashes + bounded reasons only).
- Correlatable: `authorization_id → execution_id → evidence_id → verifier
  input` joinable without trusting any single record.
- Transport: structured JSON lines to operator log + (later) DB collection
  with unique `execution_id+transition` index; log-write failure pre-START
  blocks execution, post-START is recorded as `AUDIT_GAP` on the evidence
  without mutating it.

---

## 19. Verifier Handoff

```
Executor ──(sealed ExecutionEvidence + ExecutionAttempt + binding refs)──▶ Verifier
```

- Handoff payload: `evidence` (hash-sealed), `attempt` (plan/artifact/target/
  authorization refs), `authorization` copy (for binding re-check), nothing else.
- Verifier re-checks bindings independently (plan/artifact/target/authorization
  match; evidence hash verifies; freshness/expiry re-checked) and treats all
  evidence content as untrusted input — same posture as
  `XSSVerifier._enforce_evidence_binding` today, extended to all three classes.
- Direction is one-way: verifier results never flow back into execution
  (no adaptive re-probing, no "confirm harder" loops driven by verdicts).
  Follow-up testing requires a new TestPlan + new authorization.
- Authority stays downstream: Executor success = "evidence sealed", never
  "vulnerability confirmed". Verifier remains the sole classifier; Nuclei/HTTP
  verifiers (to be built in later phases) must mirror the XSS verifier's
  evidence-as-untrusted posture and must never trust Nuclei stdout or HTTP
  status as a verdict.

---

## 20. Threat Model

Adversary controls all §4.1 inputs plus timing, concurrency, and stale/false
public data. Goals: arbitrary command, arbitrary requests, SSRF, scope escape,
credential theft, browser escape, false evidence, false CONFIRMED. Out of
scope: compromise of Watch infra itself, malicious maintainer commits, LLM
provider infra breach beyond output content. Every gate fails closed; human
review is a gate only where explicitly designated (authorization issuance).

---

## 21. Adversarial Attack Paths

Format per path: attack → boundary crossed → existing control → missing
control → proposed mitigation → residual risk.

1. **Arbitrary command via Nuclei template** → artifact→subprocess. Existing:
   H2 deny rules + HTTP-only generator + `nuclei -validate`. Missing: no
   executor-side projection/flags pinning. Mitigation: §10 projector +
   argv allowlist + `shell=False`. Residual: nuclei binary flaws (track, sandbox).
2. **Arbitrary network requests via artifact URL fields** → artifact→transport.
   Existing: H2 absolute-URL/callback/unsafe-host denies. Missing: no
   request-time URL reconstruction. Mitigation: §9 URL rebuilt from resolved
   base + validated path only. Residual: none structural.
3. **SSRF (absolute URL / redirect to internal)** → transport→network.
   Existing: redirect same-domain gate (HTTP), same-origin (browser). Missing:
   DNS/IP policy, obfuscated-IP normalization. Mitigation: §7–8 IP deny +
   per-hop re-check + pinning. Residual: DNS TTL races (mitigated by pinning;
   confirm with dial-time check in implementation).
4. **Private-IP / metadata-service access** → DNS→socket. Existing: H2
   `_host_is_unsafe` at validation. Missing: request-time enforcement.
   Mitigation: §7.6 dial-time IP check incl. `169.254.169.254/metadata.google`.
   Residual: IPv6 transition quirks (test matrix required).
5. **Out-of-scope testing (sibling/ooscope/cross-program)** → scope boundary.
   Existing: ingestion/case-builder hostname rule. Missing: execution-time
   check. Mitigation: §7 exact-host + program-pair check per request.
   Residual: scope-list propagation delay (fail closed on drift).
6. **Cross-program target confusion** → authorization→target. Existing:
   program-keyed identities. Missing: authorization not bound to program.
   Mitigation: §5 program in identity basis + §7 pair check. Residual: none.
7. **Credential leakage (headers into evidence/logs)** → executor→observability.
   Existing: `_redact`/`_sanitize_reason`. Missing: evidence-store redaction
   rule. Mitigation: §17 redaction at seal + audit-field allowlist. Residual:
   response bodies containing secrets (truncate + access-control evidence store).
8. **Browser escape / page-to-Python injection** → page→executor. Existing:
   capability transport, Python-side buffer, same-origin policy. Missing:
   nothing structural. Mitigation: preserve verbatim (§11); new adapter adds no
   page-callable surface. Residual: Playwright/Chromium 0-days (sandbox +
   killable worker + no secret in page context).
9. **Filesystem access (template path / record path traversal)** → artifact→fs.
   Existing: content-hash-keyed record paths; no artifact field influences path.
   Missing: Nuclei ephemeral template path discipline. Mitigation: random temp
   names under executor-owned dir, deleted post-run; record paths keep
   regex-validated-hash rule. Residual: temp-dir symlink races (use `O_NOFOLLOW`
   + owned dir perms in implementation).
10. **Arbitrary Nuclei capabilities (workflows/js/file/dns/headless)** → artifact→binary.
    Existing: none at runtime (only validation-time schema). Missing: runtime
    projection. Mitigation: §10.1–10.3 projector + flags allowlist. Residual:
    new Nuclei features (deny-by-default: unknown YAML keys → reject projector output).
11. **Callback abuse (interactsh/oastify/webhook)** → artifact→third party.
    Existing: H2 callback-domain denies. Missing: runtime exfil check.
    Mitigation: deny at translation + same-origin/dial-time network policy
    (callbacks are cross-origin by construction). Residual: DNS-only exfil via
    matcher-driven lookups (no `dns:` block allowed; Nuclei DNS still possible
    via binary — constrain with egress DNS allowlist in sandbox).
12. **False evidence (executor bug → SUCCEEDED)** → executor→verifier.
    Existing: verifier independent token/predicate checks (XSS). Missing:
    Nuclei/HTTP verifier equivalents. Mitigation: §19 binding re-check +
    evidence-as-untrusted for all classes. Residual: verifier bugs (differential
    testing + exact-predicate discipline).
13. **Evidence reassignment (A-evidence→B)** → store→verifier. Existing:
    attempt-binding enforcement (XSS). Missing: cross-class binding rule.
    Mitigation: §13 redundant bindings + hash + lookup-by-`execution_id`.
    Residual: none structural.
14. **Duplicate execution (retry/queue-dupe/restart)** → scheduler→executor.
    Existing: `case_id` uniqueness (XSS job only). Missing: generic idempotency.
    Mitigation: §15 idempotency index + CAS + single-flight. Residual: operator
    double-issuance with distinct caller keys (accepted: distinct keys =
    distinct intent).
15. **Stale target execution** → inventory→executor. Existing: snapshot_hash
    recorded. Missing: freshness enforcement. Mitigation: §6 re-resolution +
    drift surfacing. Residual: TOCTOU within one execution (bounded by short
    execution windows + per-hop re-checks).
16. **Stale authorization execution (replay)** → authz→executor. Existing:
    none. Missing: authorization object. Mitigation: §5 TTL + single-consume +
    scope-drift invalidation. Residual: clock skew (NTP + short TTL + skew
    bound in checker).
17. **Verifier bypass (executor-gated verdict)** → executor→finding. Existing:
    XSS pipeline owns no verdict fields. Missing: schema-level prohibition for
    new evidence. Mitigation: §12 `extra="forbid"` verdict fields + review
    gate. Residual: none structural.
18. **False CONFIRMED via broad Nuclei matcher** (H1) → matcher→finding.
    Existing: H1 specificity gate (Phase 4C). Missing: runtime re-proof.
    Mitigation: preserve H1 + §10 static re-check on projection. Residual:
    fixture coverage gaps (expand fixture corpus per template family in 5F).
19. **LLM-induced execution (prompt injection → auto-run)** → LLM→executor.
    Existing: no executor exists; LLM never calls tools. Missing: structural
    guarantee. Mitigation: §5 authorization cannot be minted by LLM paths
    (issuer allowlist: human/system policy only; LLM identity never an issuer).
    Residual: compromised issuer credentials (out of scope: infra).
20. **Generated-template matcher abuse (generic `word: [ok,200]` etc.)** (H1) →
    artifact→verdict quality. Existing: generic-token/short/status-only
    rejection. Missing: nothing structural. Mitigation: keep gates; Executor
    adds no matcher-creation path. Residual: DSL semantic drift (pin DSL
    literal allowlist in projector).
21. **Destructive HTTP methods** → artifact→target. Existing: `DELETE` excluded
    from HTTP artifact schema; Nuclei `DESTRUCTIVE_METHODS`. Missing:
    TestPlan `HttpRequestSpec` still permits `DELETE`. Mitigation: translator
    deny (`DELETE/CONNECT/TRACE`) regardless of schema drift + plan/artifact
    type cross-check. Residual: state-changing GET/POST (inherent to testing;
    bounded by scope + single-request + authorization).
22. **Redirect-based scope bypass** → response→transport. Existing:
    same-domain/no-downgrade/cycle checks. Missing: sibling-host + final-URL
    enforcement. Mitigation: §7.5. Residual: meta-refresh/JS-redirect bypass
    (HTTP executor follows HTTP redirects only; browser adapter treats
    JS-navigations as cross-origin-blocked unless same-origin — implementation
    must assert this).
23. **DNS rebinding** → DNS→socket. Existing: none. Missing: pinning +
    dial-time check. Mitigation: §6.2/§7.6. Residual: DoH inside page JS
    (browser sandbox egress controls in implementation).
24. **Host-header scope bypass** → artifact→transport. Existing: H2 header
    name rules (no explicit Host deny). Missing: Host prohibition.
    Mitigation: §9 header allowlist (no `Host`) + transport sets Host from URL.
    Residual: none structural.
25. **Timing/DoS (slowloris, huge body, fork bomb)** → target/executor.
    Existing: timeouts + body caps in XSS executors. Missing: uniform limits.
    Mitigation: §16 table + killable workers. Residual: distributed cost of
    many authorized executions (rate-limit authorizations per program/window
    in scheduler phase).

---

## 22. Reuse / Extend / Wrap / Isolate / Replace / New

| Component | Verdict | Rationale |
|---|---|---|
| `Hypothesis/TestPlan/Artifact/TargetIntelligence/TargetMatch` schemas + `hypothesis_engine` + `test_plan_builder` | **REUSE AS-IS** | Correct, tested, authority-free. Executor consumes; never modifies. |
| `artifact_validator` + `nuclei_artifact_validator` (H1/H2) | **REUSE AS-IS** (call from Executor revalidation) | No new safety semantics; re-run verbatim. Note `test_plan.py:HttpRequestSpec` still allows `DELETE` — translator denies regardless (do not change schema in 5A). |
| `ArtifactStore` + `artifact_retrieval` + `test_plan_readiness` | **REUSE AS-IS** | Storage/retrieval/readiness correct. Readiness stays informational; never promoted to authority. |
| `KnowledgeStore` / pattern projector / matcher | **REUSE AS-IS** (upstream only) | Executor must not import them; listed to forbid coupling. |
| `HTTPEvidenceExecutor` | **WRAP** (as transport plugin behind HTTP adapter) | Evidence discipline + redirect policy + redaction correct; needs authorization/idempotency/scope-per-hop shell around it. |
| `BrowserEvidenceExecutor` + `oracle.py` + `composite_executor` | **WRAP** (behind XSS adapter; oracle untouched) | Isolation + capability + clean-READ + E2 handling correct. Adapter translates artifact→attempt; never touches oracle internals. |
| `XSSVerifier` | **REUSE AS-IS** (downstream authority) | Sole classifier; handoff extends its binding checks to new evidence shape. |
| `NucleiRunner` | **WRAP** (strict sandbox wrapper; no direct use) | `subprocess` + dry-run default + eligibility shape worth keeping; template-path trust, flags freedom, and missing re-resolution must be closed by wrapper. |
| `NucleiPipeline` / `NucleiTemplateGenerator` / `nuclei_validator` | **REUSE AS-IS** (pre-execution only) | Generation/validation path stays upstream; Executor never calls generator. |
| `ScopePolicy.evaluate` | **WRAP + RENAME** (to `ProductReadinessPolicy`; use as advisory input only) | Misleading name; not URL scope. Never wire to execution decisions unwrapped. |
| `xss_case_builder` scope rule + `http_executor` redirect rule | **EXTEND** (into NEW `ScopeEvaluator`) | Correct idioms, insufficient coverage (DNS/IP/port/path/final-URL). Extend, don't copy-paste a fourth time. |
| `HTTPFingerprintRunner.check` | **ISOLATE** (never used by Executor) | `follow_redirects=True`, no scope/DNS guards. Keep for `WatchAssetSelector` relevance flow only; Executor gets its own bounded transport. |
| `HTTPCollector` | **REUSE AS-IS** (intelligence input) | Read-only projection; no execution surface. |
| `watch_xss_verify.py` job pattern | **EXTEND** (case_id idempotency + per-case isolation → generic idempotency + CAS) | Sequential-dedupe precedent; needs queue-safe generalization in scheduler phase. |
| Authorization, TargetResolver, ScopeEvaluator, translators, evidence store, audit trail, idempotency index | **NEW** | Nothing in the repo provides them; each gets its own narrow phase (§23). |

Nothing is REPLACED for stylistic reasons. The only rename (ScopePolicy) is
semantic disambiguation, deferred to implementation.

---

## 23. Proposed Implementation Phases (after 5A)

Each phase: narrow scope, explicit trust boundary, `unittest` suite mirroring
existing AI-test style, security review, no accidental execution authority.
No phase before 5J may perform live network/subprocess/browser actions outside
mocked transports.

- **5B — ExecutionAuthorization contracts.** Schema + identity/binding
  validators + TTL/state machine + issuer allowlist. Tests: binding mismatch
  matrix, expiry, replay, unknown policy. No resolver/scope/executor code.
- **5C — Target re-resolution boundary.** Read-only `TargetResolver` adapter
  over `Programs/Subdomains/Http/Endpoints` + `TargetResolution` struct +
  gone/drift/surfaced outcomes. Tests with fake DB. No network.
- **5D — ScopeEvaluator + executor input validation.** Pure per-request scope
  function (scheme/host/port/path/redirect/DNS-shape) + top-level
  `ExecutorInput` validator composing authorization + plan + artifact ref +
  resolution + scope. Tests: 25-path scope matrix (incl. sibling, redirect,
  IP-obfuscation, downgrade). No transport.
- **5E — HTTP probe executor.** Translator + wrapped transport (reuse
  `HTTPEvidenceExecutor` core) + limits + SSRF suite + evidence sealing for
  HTTP class. Mocked-transport tests; live-fire only against local harness.
- **5F — Nuclei executor.** Projector + flags/binary pinning + sandbox wrapper
  + H1/H2 re-enforcement + output-capped evidence. Tests: capability-denial
  matrix (workflows/js/interactsh/file/dns), projector fidelity, argv
  allowlist. No live targets until review.
- **5G — XSS executor adapter.** Artifact→attempt translation + SUBMIT/READ
  gating + existing-executor delegation + oracle non-interference proofs.
  Tests: clean-READ, no-downgrade, capability, round binding, E2 isolation.
- **5H — Evidence contract + immutable store + audit log.** Schemas,
  canonical hashing, content-addressed store + sweep, audit writer. Tests:
  tamper/reassignment/orphan matrices.
- **5I — Verifier handoff + Nuclei/HTTP verifiers (minimal).** Binding
  re-checks, one-way handoff, conservative Nuclei/HTTP classifiers
  (evidence-as-untrusted; high bar for any positive label). Tests: binding
  mismatch, stale evidence, broad-matcher demotion.
- **5J — End-to-end execution (gated).** Scheduler + idempotency index + CAS +
  single-flight + local-harness E2E; production enablement only after full
  adversarial re-review and explicit authorization-policy sign-off.

---

## 24. Blocking Security Requirements (must hold before any live execution)

1. `ExecutionAuthorization` schema + checker merged, with LLM-issuer
   impossibility (issuer allowlist enforced in code, not docs).
2. `ScopeEvaluator` merged with DNS/IP/redirect/final-URL coverage + fuzz
   matrix passing (obfuscated IPs, sibling hosts, downgrade, cycles).
3. Artifact revalidation (hash + bindings + H1/H2 re-run) enforced on every
   path; no cached-`VALID` shortcut.
4. Per-executor translators merged with closed vocabularies; generic-execute
   interface absent (assert by test: no function accepts raw shell/argv/URL).
5. Nuclei projector + argv/binary pinning + `shell=False` + output caps merged.
6. Evidence sealing + `extra="forbid"` verdict-field prohibition merged.
7. Idempotency index + `ISSUED→CONSUMED` CAS merged (even single-process file
   lock initial version acceptable; distributed lock before multi-worker).
8. Audit writer merged with secret-free field allowlist.
9. Full adversarial re-review of 5B–5I deltas passing with zero HIGH findings.
10. Operator runbook: authorization issuance policy, TTL/rate limits per
    program, evidence retention/access control, incident revocation procedure.

---

## 25. Open Questions / Limitations

1. **Authenticated testing** is excluded: no credential vault design exists;
   default stays unauthenticated. (Deliberate 5A scoping.)
2. **Scope-list distribution**: `Programs.scopes` live in Mongo; Executor needs
   a read path with freshness SLA — resolver caching TTL vs TOCTOU tradeoff
   unresolved (recommend ≤60 s cache + per-request re-check in 5C).
3. **`HttpRequestSpec.method` includes `DELETE`** while artifact schemas deny
   it — schema convergence (remove `DELETE` from plan spec) vs translator-deny
   is a 5D decision; translator-deny is the safe default either way.
4. **Nuclei egress DNS**: binary-initiated DNS during template execution is
   outside argv control; sandbox-level egress allowlist design deferred to 5F.
5. **Evidence retention/PII**: truncated bodies may contain PII; access control
   + retention + purge policy deferred to 5H/operations.
6. **Multi-worker idempotency**: 5A designs CAS + single-flight; the durable
   implementation (Mongo unique index vs external lock) is a 5J decision.
7. **`ScopePolicy` rename** requires touching correlator callers — deferred,
   wrapped first.

---

## 26. Final Architecture Diagram

```
 ┌─UNTRUSTED──────────────────────────────┐
 │ LLM / research prose / claims /        │
 │ hypotheses / plans / artifact bytes    │
 │ (pre-validation) / target responses /  │
 │ DNS / browser content / Nuclei output  │
 └───────────────┬────────────────────────┘
                 │ deterministic validators
                 ▼
 ┌─VALIDATED (still NOT authority)────────┐
 │ Pattern→Intel→Match→Hypothesis→Plan→   │
 │ ArtifactReference(VALID)→stored bytes→ │
 │ Readiness(READY)                       │
 └───────────────┬────────────────────────┘
                 │ + explicit human/system ExecutionAuthorization
                 ▼
 ════════ EXECUTION AUTHORIZATION BOUNDARY ════════
                 ▼
 ┌─EXECUTOR (no verdicts, no scope ownership)─────┐
 │ AUTHORIZED → TARGET_RESOLVED (fresh DB read)   │
 │   → SCOPE_VALIDATED (per-request + per-hop +   │
 │      DNS/IP, fail closed)                      │
 │   → ARTIFACT_REVALIDATED (hash+binding+H1/H2)  │
 │   → TRANSLATED (closed per-class vocabulary)   │
 │   → EXECUTION_STARTED (sandbox + limits)       │
 │   → EXECUTION_COMPLETED → EVIDENCE_SEALED      │
 │                                                │
 │ adapters: HTTP probe │ Nuclei │ XSS(SUBMIT/READ│
 │   → existing transports, wrapped, never raw)   │
 └───────────────┬────────────────────────────────┘
                 │ sealed immutable ExecutionEvidence (no verdict fields)
                 ▼
 ┌─DETERMINISTIC VERIFIER (sole classifier)───────┐
 │ XSSVerifier (exists) / Nuclei+HTTP (5I)        │
 │ evidence-as-untrusted, binding re-check        │
 └───────────────┬────────────────────────────────┘
                 ▼
              Finding
```

Forbidden paths (structurally absent): `LLM→command→target`,
`artifact→command→target`, `target-response→executor-decision→scope-bypass`,
`READY→execution` without authorization, `evidence→execution` feedback.

---

## 27. Explicit Statement — No Code Modified

No repository file was modified in this phase. No production code was created,
no existing file was edited, renamed, moved, or deleted (the only filesystem
write is this report itself, as mandated by the task). No target was executed
against, no HTTP request was sent, no Nuclei invocation was performed, no
browser was launched, no verifier was invoked, no finding was created.

## 28. Explicit Statement — No Git Commands Run

No Git command was run in this phase. Specifically, none of: `git status`,
`git diff`, `git add`, `git commit`, `git branch`, `git merge`, `git checkout`,
`git switch`, `git restore`, `git reset`, `git stash`, nor any other Git
operation. Compliance with the read-only constraint was maintained throughout.
