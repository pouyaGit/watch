# Phase 5A Executor Architecture — Adversarial Security Review (READ-ONLY)

## 1. Executive verdict

**VERDICT: ARCHITECTURE DIRECTIONALLY SOUND, NOT YET SAFE TO IMPLEMENT 5B
AGAINST AS SPECIFIED — 3 HIGH-SEVERITY STRUCTURAL GAPS MUST BE CLOSED FIRST.**

The 5A report (`agent-reports/executor-architecture.md`, 1030 lines, read in
full) correctly identifies the missing authorization boundary, correctly
refuses to promote `READY`/`VALID` to authority, and correctly isolates
`HTTPFingerprintRunner` and raw `NucleiRunner`. The six-gate pipeline order is
right, and the per-executor closed-vocabulary principle is the correct smallest
boundary.

However, hostile review against the **actual repository code** finds concrete
paths where the architecture as written still permits unauthorized execution,
scope escape, SSRF, evidence confusion, or authorization forgery. These are not
"fail closed will handle it" cases — they are places where the design either
contradicts itself, leaves the security-critical mechanism unspecified, or
misdescribes what existing code actually enforces. Severity counts:

- **HIGH: 9** (authorization forgery surface, authorized-bytes ≠ executed-bytes
  on the XSS oracle path, sibling-redirect allowance, no dial-time IP binding,
  Nuclei binary redirect/DNS escape, fixture provenance, plan/artifact
  DELETE + identity confusion, secret retention in evidence, TOCTOU/stored-READ
  re-resolution gap)
- **MEDIUM: 7** (idempotency staleness, evidence-hash partial coverage,
  URL-normalization gaps, port-compare bug inheritance, resource-cap
  enforceability, browser side-channel exfil, old Nuclei `to_findings` path
  survival)
- **LOW / INFO: 4** (naming, clock-skew bounds, redirect-upgrade policy,
  phase-ordering)

Nothing in this review requires live targets, HTTP requests, Nuclei, browsers,
verifiers, code changes, or Git. All findings are derived from reading the 5A
report plus the repository files listed in §2.

**Blocking consequence:** 5B (ExecutionAuthorization) must not be implemented
against the §5 contract alone. It needs: (a) an authentication mechanism for
authorizations (not just a schema), (b) resolution of the
authorized-artifact vs executed-oracle-payload contradiction, and (c) a
normative scope rule that does not permit sibling-host redirects. Details in
§18. Phase order must also change (§19): evidence/idempotency substrate before
executors.

---

## 2. Attack surface

Attacker controls every §4.1 UNTRUSTED input of the 5A report: LLM output,
research prose, hypotheses, TestPlans, pre-validation artifact bytes, target
descriptions, HTTP responses, redirect `Location`s, HTML/JS, DNS answers,
Nuclei stdout/stderr, browser page content, callback data, timing, malformed
data. Additionally assumed: attacker-influenced redirect chains and DNS zones
for in-scope hosts (standard bug-bounty threat model — the target itself is
partially hostile), concurrent scheduler/worker behavior, stale snapshots, and
read access to all non-secret repository state (schemas, validators, store
layouts). Not assumed: Watch infra compromise, maintainer malice, LLM-provider
infra breach, issuer private-key theft (but issuer-key *absence* is in scope —
see F-01).

Entry points reviewed: `TestPlan.HttpRequestSpec` (incl. `DELETE`),
`ArtifactRef` vs `ArtifactReference` duality, `ArtifactStore` read/write paths,
`test_plan_readiness` requirement map, `HTTPEvidenceExecutor` redirect/transport
code, `BrowserEvidenceExecutor` network policy + transport, `oracle.py`
anti-harvest boundary, `XSSVerifier` classification, `NucleiRunner` subprocess
path, `NucleiTemplateGenerator` output shape, H1/H2 validator regexes and token
lists, `ScopePolicy.evaluate`, `database/db.py` scope rule + hardcoded
credentials, `HTTPFingerprintRunner.check`, `xss_case_builder` scope mirror.

---

## 3. Trust-boundary analysis (per transition)

| Transition | Trusted (per 5A) | Remains untrusted (reviewer's correction) | Validation | Crosses? |
|---|---|---|---|---|
| LLM → research | nothing | all model text | grounding + quarantine (exists) | No, but instruction-shaped claim content survives grounding (prior M1, unaddressed by 5A) |
| research → pattern | schema-shaped claims | claim *values* | closed vocabularies | Values flow into pattern facts (attack_surface paths, params) → reach TestPlan request path/params. Correctly bounded downstream, but provenance is not purity. |
| pattern + intel → match | matcher code | pattern values, inventory rows | deterministic criteria | Match criteria (path/param) flow into plan endpoint/params. Bounded, but attacker-influenced path strings enter the plan. |
| match → hypothesis | engine code | statement IDs only | binding checks | Clean (statement built from IDs/enums only — verified). |
| hypothesis → TestPlan | builder code | endpoint, method, param names | `_derive_triple`, binding gates | **Method `DELETE` enters here**: `_request_method` returns the single pattern-declared method verbatim, and `HttpRequestSpec` permits `DELETE` (verified `test_plan.py:170`). A hostile pattern fact with `method=DELETE` yields a DELETE plan. 5A §9 translator-deny is the only backstop, and §8 revalidation does not list method reconciliation. |
| TestPlan → artifact | validator code | artifact bytes | H1/H2 + size + type | Clean at validation time, but **two artifact identity systems coexist** (§4, F-04). |
| artifact → store | store checks | bytes + reference | hash + identity + safety (no specificity re-run — documented) | Specificity proven at mint, not at store; acceptable only because 5A §8 re-runs specificity at execution. If 5F skips fixtures, the backstop vanishes. |
| store → retrieval → readiness | store code | nothing new | audit + sweep | Clean and correctly non-authoritative. |
| readiness → authorization | **nothing (correct)** | readiness report itself | must be none | **Gap**: 5A forbids inference but does not define what the issuer *does* read. A human issuer reading only the READY label will in practice infer authority from it. Procedural, but architecture should require the issuer view to include scope bindings + artifact bytes hash, not just the report. |
| authorization → resolution | authorization object | target slot strings | binding compare | **Gap**: no authentication on the object (F-01). String compare is fine after authenticity; without it, attacker mints the object. |
| resolution → scope | program lists + resolved base | URL, DNS, redirect chain | NEW evaluator (not yet code) | **Gaps**: sibling-redirect allowance (F-02), no dial-time binding (F-03), normalization holes (F-08). |
| scope → revalidation | scope verdict | artifact bytes | hash + binding + H1/H2 | Clean if fixtures present; broken if fixture provenance hostile (F-06). |
| revalidation → translation | typed content | nothing | projector allowlist | Clean for HTTP/XSS; **structurally unenforceable for Nuclei** beyond the emitted YAML (F-05). |
| translation → execution | argv/transport config | target responses, DNS, page | sandbox + limits | Limits are wrapper-config, not kernel/network enforcement (F-10, §12). |
| execution → evidence | executor code | all observations | hashing + redaction | Hash covers what the schema says; schema omits several security-relevant fields (F-07); redaction omits bodies/URLs (F-11). |
| evidence → verifier | nothing | all evidence | binding re-check + exact predicates | Clean for XSS; Nuclei/HTTP verifiers do not exist, and the old `to_findings` heuristic (`output.strip()` → matched) survives in-tree (F-12). |

---

## 4. Authorization findings

### F-01 (HIGH): Authorization has a schema but no authentication mechanism

- **Attack:** forge `ExecutionAuthorization` JSON with `issued_by: human`,
  matching `test_plan_id/artifact_id/content_hash`, valid TTL. Nothing in the
  §5 contract distinguishes this from a real authorization: `authorization_id`
  is a deterministic hash of public fields (anyone can recompute),
  `idempotency_key` likewise, `audit` is free strings, and no signature/MAC/
  key-identity field exists. "Issuer allowlist enforced in code" (B2) is a
  promise about *which identities may issue*, not a mechanism for *proving the
  presenter is that identity*. Scheduler/queue serialization forgery is the
  same attack.
- **Boundary crossed:** LLM/research → authorization.
- **Existing control:** none (object does not exist yet).
- **Missing control:** authenticity: signature (e.g. Ed25519 over canonical
  authorization bytes) or server-side issuance record that the checker queries
  (authorization-by-reference: presenter supplies only `authorization_id`, the
  Executor loads the authoritative row). 5A specifies authorization-by-value.
- **Mitigation:** make authorizations authorization-by-reference backed by an
  append-only issuance table writable only by the issuer service identity, or
  add `issuer_key_id + signature` fields with offline verification and key
  rotation. Either is a 5B blocker.
- **Residual:** issuer host compromise (accepted, out of scope).

### F-04 (HIGH): Two artifact identity systems with the same `art-` prefix

- **Attack:** `ai/schemas/test_plan.py::ArtifactRef.artifact_id =
  "art-" + content_hash[:16]` vs `ai/schemas/artifact.py::artifact_id_for =
  "art-" + SHA256(type+plan+hash+version)[:16]` (both verified in code). For
  identical bytes these yield *different* ids. `TestPlan.artifact_ref` (single,
  optional, content-keyed) vs readiness/store (plan-bound, multi-artifact per
  plan) disagree on what `artifact_id` means. An authorization binding
  `artifact_id` under one system does not resolve under the other; a confused
  implementation accepts a content-keyed ref as proof of a plan-bound identity
  (or vice versa), enabling artifact substitution across plans.
- **Existing control:** `validate_reference_binding` (plan-bound system only).
- **Missing control:** 5A never names which identity the authorization binds
  (it says "exact artifact identity (id + content hash)" without selecting the
  function). Normative choice + migration of `TestPlan.artifact_ref` required.
- **Mitigation:** bind authorization to the plan-bound `artifact_id_for`
  triple `(type, test_plan_id, content_hash)` explicitly; deprecate/ignore
  `TestPlan.artifact_ref` at execution (treat as advisory); add a test asserting
  the two functions disagree for the same bytes so no future code conflates them.
- **Residual:** legacy plans carrying only `artifact_ref` need re-minting.

### F-05b (HIGH, authorization-adjacent): Single-artifact binding vs multi-artifact plans

- **Attack:** readiness `get_by_test_plan_id` returns a tuple; `artifact_count`
  may exceed 1 (verified `test_plan_readiness.py`). Authorization binds one
  `artifact_id`. When two VALID artifacts exist for one plan (e.g. original +
  re-minted payload variant), the Executor's choice of *which* stored artifact
  to execute is unspecified. Attacker who can mint a second VALID artifact for
  the same plan (VALID is achievable for attacker-shaped but in-spec content —
  validators are safety gates, not intent gates) gets execution of their bytes
  under the victim's authorization.
- **Mitigation:** authorization binds the full set (exactly-one semantics:
  execution requires `count == 1` and id match), or binds an ordered tuple.
  Never "first in id order".

### F-13 (MEDIUM): Caller-controlled `idempotency_scope` splits or merges intent

- **Attack:** same logical intent with different caller keys → distinct
  authorizations → duplicate executions (stored-SUBMIT double-persist,
  Nuclei double-scan). Conversely, replayed key after `CONSUMED` returns stale
  sealed evidence for a changed target (evidence freshness is not part of the
  dedupe check in 5A §15).
- **Mitigation:** constrain `idempotency_scope` vocabulary (fixed set, never
  free string) and include target `scope_list_hash` + artifact hash in dedupe
  *equality* (already in basis — enforce re-check on hit, serve cached evidence
  only when all bindings still match current resolution).

---

## 5. Target-resolution findings

### F-09 (HIGH): TOCTOU windows; stored READ re-resolution unspecified

- **Attack/window 1 (all classes):** `TARGET_RESOLVED → … → EXECUTION_STARTED`
  spans two DB reads, DNS, and up to 6 HTTP hops. Scope lists, subdomain
  ownership, and endpoint base can change mid-flight. 5A records drift but only
  blocks on scope-list-hash mismatch at check time, not on change *during*
  redirect-following or Nuclei's internal redirect stack.
- **Attack/window 2 (stored XSS):** SUBMIT acceptance → READ discovery →
  clean READ navigation is the widest window in the architecture (network RTT +
  link harvesting). 5A does not state whether READ re-runs full re-resolution
  + scope + authorization-liveness. If the round inherits SUBMIT's gates,
  subdomain reassignment or scope revocation between SUBMIT and READ executes a
  browser session against a now-unauthorized target.
- **Existing control:** snapshot recording (advisory only — correctly).
- **Mitigation:** define the *unit of execution*: single-request classes
  re-check scope per hop (already specified — add dial-time check §6); stored
  rounds are **two executions** under one authorization, each re-resolving and
  re-scoping, with READ gated on authorization still live + scope PASS at READ
  time. State machine needs `READ_REAUTHORIZED` explicitly.
- **Residual:** intra-request reassignment (accepted; bounded by short windows
  + per-hop checks).

---

## 6. Scope findings

### F-02 (HIGH): "Same registrable domain" redirect allowance permits sibling-host escape

- **Attack:** initial URL `https://a.target.com/probe` (authorized slot =
  `a.target.com`) responds `302 Location: https://b.target.com/` where
  `b.target.com` is a sibling that is in `ooscopes`, or belongs to a different
  program, or is an attacker-influenced subdomain. 5A §7.5 inherits the
  existing `_check_redirect_safety` rule (verified `http_executor.py:503-520`):
  cross-host allowed when registrable domains are equal. 5A §7.2's exact-host
  check contradicts it without stating precedence. The code comment's own
  example (`accessories.la.dell.com → www.dell.com`) normalizes cross-host
  navigation. An implementation following the inherited rule literally will
  ALLOW the sibling redirect; the `ooscope`/cross-program check happens, per
  5A, against "the same program" — but the redirect target's program
  membership is resolved from the *same* program row, so a sibling in the same
  program but explicitly `ooscopes`-listed is the only denied case, while a
  sibling in *another* program or an unlisted attacker subdomain of the same
  eTLD+1 passes the domain-equality test and then fails open if the evaluator
  checks the original program's lists.
- **Existing control:** exact-host case-build rule (build time only, stale).
- **Mitigation (normative):** redirects may only stay on the **exact resolved
  host** (plus explicit allowlist for documented CDN host pairs, each entry
  pinned per program). Remove the eTLD+1 allowance from the execution path
  entirely; keep it, if at all, as a relevance heuristic upstream. State
  precedence explicitly: exact-host wins, domain-equality never permits.
- **Residual:** documented CDN pairs need per-program curation.

### F-03 (HIGH): No dial-time DNS/IP binding exists; pre-check cannot hold

- **Attack:** DNS rebinding / multi-A rotation / resolver race: pre-request
  `getaddrinfo` checked ALLOW (clean IP), transport's internal resolution at
  `connect()` returns attacker IP (private/metadata). `requests`/`httpx`/
  Chromium re-resolve internally; Python-level "resolve each hop fresh; pin per
  execution" (5A §7.6) without a custom dialer or egress firewall is advisory.
  Verified: no dial-time hook exists in `http_executor.py`, `browser_executor.py`
  (`route.continue_()` is URL-level, not socket-level), or `nuclei_runner.py`.
- **Mitigation:** require connection-level enforcement: custom `HTTPAdapter`
  resolving via a pinned, scope-checked resolver and connecting by IP with SNI/
  Host preserved + certificate verification against the hostname; Chromium
  `--host-resolver-rules` pinning per execution or a dedicated egress proxy
  that enforces the IP policy; Nuclei behind the same egress proxy (it cannot
  be trusted to self-constrain). Add B5 teeth: "DNS/IP enforcement **at the
  actual connection**, verified by test with a rebinding harness."
- **Residual:** DoH inside page JS (needs proxy-level DNS control).

### F-08 (MEDIUM): URL-normalization holes inherited from `urlsplit`-only parsing

Verified gaps, each reproducible against the current helpers:

- trailing dot (`shop.target.com.`): `hostname` keeps the dot; tldextract and
  string comparison behave inconsistently across the three scope copies.
- case: lowercased at compare in some paths, not all (`visited` set uses raw
  `next_url` string — `HTTPS://A…` vs `https://a…` bypasses cycle detection).
- userinfo (`https://allowed@evil/`): `hostname` strips it (scope sees
  `allowed`… actually sees `evil`? `urlsplit("https://allowed@evil/").hostname
  == "evil"` — scope correctly sees evil, but the *logged/requested* URL
  carries `allowed@`, leaking confusion into audit + potential credential
  carriage).
- encoded traversal (`%2e%2e`, `%2f`, `..`, backslash, double slash):
  artifact path gate rejects shell content but `..` normalization at request
  build is unspecified; `urljoin` with `Location: //evil/x` treats it as
  network-path reference (scheme-relative → host change) — handled by host
  check only if host check runs, which for `//` it does, but double-encoding
  through Nuclei's own normalization may differ.
- IP literal forms: `_host_is_unsafe` uses `ipaddress.ip_address` (rejects
  `0x7f.0.0.1`/octal? — actually `ipaddress` rejects non-decimal IPv4, so
  `http://0x7f.0.0.1/` parses as *hostname*, not IP, and passes the IP deny
  while connecting to 127.0.0.1 at socket level). Scope string checks see a
  "hostname"; the socket sees loopback. Concrete SSRF bypass shape.
- IDN/punycode: no normalization specified; `münchen.target.com` vs
  `xn--mnchen-3ya.target.com` compare unequal while resolving identically.
- `0.0.0.0` / `::` / IPv4-mapped `::ffff:127.0.0.1`: `is_private/is_loopback/
  is_link_local` coverage for `0.0.0.0` is `is_private=False` in some Python
  versions (it is `is_unspecified`); 5A's list names `0.0.0.0` in prose only
  for the HTTP executor, not in a shared IP-policy function. Inconsistent.
- **Mitigation:** single canonicalization function (lowercase, strip trailing
  dot, IDNA-encode, reject userinfo/fragments in scope input, normalize
  IP literals via `ipaddress` *after* explicit decimal/octal/hex parsing,
  `posixpath.normpath`-style dot-segment check + reject on `..`), shared by
  all three executors. Fuzz matrix blocker.

### F-08b (MEDIUM): Port-compare and upgrade-policy bugs inherited verbatim

- `(current.port or "") != (target.port or "")` (verified line 521):
  `None or ""` → `""` vs explicit `:443` → `443`: same effective port compares
  unequal (false deny, availability issue), while `:80` on http vs implicit 80
  has the same shape. More importantly the check compares *declared* ports,
  not effective ports after defaulting — `https://h/` → `https://h:443/` (same)
  is rejected. Annoyance now, but an implementer "fixing" it by defaulting
  ports may accidentally widen to allow `:8080`→`:80` transitions. Specify
  effective-port comparison + allowlist `{80, 443, resolved_port}`.
- HTTP→HTTPS upgrade is silently allowed (only downgrade denied). Upgrade
  changes trust (HSTS, cookie scope, different vhost). For probes this is low
  risk, but for stored-SUBMIT acceptance (cookies/auth state) it matters.
  Require same-scheme for SUBMIT/READ; allow upgrade only for idempotent GET
  probes, recorded explicitly.

---

## 7. HTTP findings

### F-10 (HIGH, shared with §6): `HttpRequestSpec.method` includes `DELETE`

- Verified `test_plan.py:170` permits `DELETE`; `HttpArtifactContent`
  (`artifact_validator.py:67`) deliberately omits it. 5A §9 promises
  translator double-deny, but §8 revalidation step 7 ("cross-check plan path")
  does not include method reconciliation, and the TestPlan identity hash binds
  `request_spec` *including* `DELETE`. A `DELETE /resource` plan with a
  corroborating `http_request_spec` artifact (which cannot express DELETE, so
  bindings trivially diverge) leaves the translator to choose: deny (correct
  but then what does the Executor do with a VALID artifact + mismatched plan —
  unspecified terminal?) or coerce to GET (wrong-method execution). Both
  outcomes are un-designed.
- **Mitigation:** remove `DELETE` from `HttpRequestSpec` (schema convergence,
  one-line change in a later phase — no 5A code change now, but record as
  required diff), plus normative translator rule: plan-method ≠ artifact-method
  → `TRANSLATION_REJECTED`, never coercion.

### F-11 (HIGH): Response/secret retention in evidence exceeds redaction design

- Redaction covers headers (`_redact`, verified) and sanitizes error strings,
  but evidence as designed carries: full redirect chain with raw `Location`
  values (attacker-controlled, may embed `user:pass@` or session tokens),
  `response_body_truncated` (bounded 8 KiB but still secret-capable),
  `nuclei_raw_output` 1 MiB, browser console/network excerpts, and error
  `detail` strings. Mongo credentials (`db.py:36-38` hardcoded — verified)
  live in the resolver process; any error path that stringifies the DB
  exception or URL leaks them into audit. 5A §17 redacts headers only.
- **Mitigation:** URL scrubber (strip userinfo, cap query retention, hash
  query values by default), body minimization (hash-only default; truncated
  bodies only under explicit per-program flag), evidence-store access control +
  retention/purge (already deferred — elevate to blocker for 5E+), resolver
  error sanitization (never stringify DB exceptions into audit).

### F-12b (MEDIUM): Transport limits are wrapper config, not enforcement

- `timeout=10`, `max_body_bytes`, `max_redirects` are constructor args on
  wrapper objects; a misconfigured caller (or a test double) silently widens
  them. No global ceiling, no server-side (proxy) enforcement. Streaming
  `iter_content` has no per-chunk stall timeout (slow drip holds to wall-clock
  only — acceptable) but auto-decompression means the 512 KiB cap should be
  specified as post-decompression (it is, implicitly — make explicit) with a
  compression-ratio abort. `requests` session cookie jar persists across hops
  within an execution (correct) — but 5A's "fresh session per execution" is
  the only cookie-erasure point; stored SUBMIT→READ must not share a jar
  (or attribution breaks). Specify jar scope per *request*, not per execution,
  for stored rounds.

---

## 8. Nuclei findings

### F-05 (HIGH): Projection cannot make hostile capabilities *structurally impossible*

- The claim "`workflows/javascript/file/dns/headless` never execute because
  the projector never emits them" holds only if (a) the projector is bug-free,
  (b) the `http:` block itself has no dangerous sub-keys, and (c) the binary
  honors only documented keys. None holds fully:
  - Within an allowed single `http:` block, Nuclei supports `payloads:`,
    `attack:`, `fuzzing:`, `matchers-condition:`, `stop-at-first-match`,
    redirect/refetch behaviors, and DSL helper functions — all reachable
    without leaving `http:`. 5A's DENY table names `payloads/attack` but the
    artifact schema has no field for them, so the threat is *emitter
    hallucination*, untestable by artifact validation. The projector needs a
    positive YAML-shape allowlist + a re-parse-and-diff gate (emitted YAML
    parsed back must equal the projected model, no unknown keys), which 5A
    does not specify.
  - Binary honors the file it is given; a symlink-swapped or pre-existing
    temp file at the random path, or a `template_path` confusion (old
    `build_command(template_path, target)` accepts any path — verified),
    executes arbitrary YAML. Random temp name + delete-after is necessary but
    insufficient without `O_NOFOLLOW`, exclusive create, and directory
    ownership.
  - The binary's own network stack (redirects, DNS, SNI, TLS) is outside argv
    control: `-u <resolved-url>` is a string; Nuclei follows the target's
    redirects per its own config, resolves DNS per system resolver, and can be
    steered by response content into out-of-scope hosts. 5A has no egress
    proxy requirement for Nuclei (browser/HTTP get route/redirect policies;
    Nuclei gets flags). Concrete escape: in-scope page 302s to sibling host;
    Nuclei follows (its `-follow-redirects` default) outside Watch scope logic.
- **Mitigation:** (1) positive-shape gate on emitted YAML (parse-back +
  unknown-key reject); (2) exclusive-create temp files under executor-owned
  `0700` dir, `O_NOFOLLOW`, fd-passing where possible; (3) mandatory egress
  proxy / network namespace for the Nuclei child with the same IP policy as
  §7; (4) `-follow-redirects false` (or explicit deny) + `-dns-*` pinning;
  (5) argv allowlist enforced by test (reflection over the argv builder).
- **Residual:** Nuclei binary vulnerabilities (track version pin + checksum).

### F-06 (HIGH): Specificity fixtures have no provenance rule

- 5A §8.6: "fixtures travel with the authorization context, never inside the
  artifact." Who mints them? If fixtures derive from the research pattern
  (vulnerable-example strings) or from TestPlan prose, the attacker supplies
  both the matcher *and* the test that proves it specific (benign fixture
  carefully dissimilar, vulnerable fixture containing the token). H1 then
  proves attacker-chosen specificity. Verified H1 mechanics
  (`nuclei_artifact_validator.py:567-661`) are sound *given honest fixtures*;
  fixture honesty is the unaddressed assumption.
- **Mitigation:** fixtures must be issuer-curated (per template family,
  versioned, stored alongside the authorization policy, never derived from the
  plan/artifact under test); re-running specificity at execution (5A §10.3)
  must use *pinned* fixtures by hash, recorded in the authorization.
- **Residual:** fixture coverage gaps (accepted; expand corpus in 5F).

### F-12 (HIGH, verifier-adjacent): Old Nuclei finding heuristic survives in-tree

- Verified `nuclei_runner.py:to_findings`: `matched = COMPLETED and
  output.strip()`. Any non-empty stdout becomes a matched finding, with
  scope/presence/version passthrough. 5A wraps `NucleiRunner` but does not
  require deleting or gating `to_findings`. An implementer wiring "verifier
  handoff" to the existing method reintroduces stdout-equals-vulnerable —
  the exact H1 bypass the whole Phase 4C effort closed.
- **Mitigation:** blocker: `to_findings` must be deleted or hard-gated
  (`raise` unless an explicit legacy flag) before 5F; the 5I Nuclei verifier
  starts from sealed evidence, never from `NucleiRunResult`.

---

## 9. XSS/browser findings

### F-07x (HIGH): Authorized artifact bytes ≠ executed bytes on the oracle path

- **Attack (design-level, no implementation bug needed):** authorization binds
  `artifact_id + content_hash` of the `xss_payload` artifact (payload P).
  On every path that can reach `CONFIRMED`, the actually-executed payload is
  the planner-owned oracle payload O (contains seed S, never D), minted by
  `OraclePlanner` from `(run_salt, candidate attempt_id, phase)` — verified
  `verifier.py:build_oracle_verification_attempt` and `build_stored_round`.
  O ≠ P by construction (different bytes, different hash). The authorization
  therefore permits P while the Executor transmits O. Anti-harvest, run-salt
  freshness, and candidate-identity checks (all verifier-side, all sound)
  authenticate O *to the verifier*, but nothing authenticates O *to the
  authorization*. Consequences: (a) the safety properties proven for P (size,
  charset, H2-equivalent payload gate) do not transfer to O — O is trusted by
  provenance (planner-owned) but unbounded by the artifact contract; (b) audit
  shows "executed authorized artifact A" while wire bytes were O; (c) a
  compromised-or-buggy planner (or a future "LLM delivery pattern influences
  skeleton" drift — the planner already accepts `delivery_pattern` input,
  currently attribution-only) becomes an unaudited code-execution path outside
  authorization.
- **Existing controls:** planner skeleton allowlist (4 contexts), seed-once +
  value-never-on-wire self-checks, verifier-side anti-harvest — all real, all
  downstream of the authorization gap.
- **Mitigation (choose one normatively before 5G):** (i) authorize the
  *derivation*, not the bytes: authorization binds `(artifact_id, planner
  version, context_type, run_salt id)` and the Executor verifies O was minted
  by the planner under those parameters (planner attestation in evidence);
  or (ii) execute P for transport proof AND O for execution proof as separate
  authorized steps, each bound. Either way, evidence must carry both hashes
  (`artifact_content_hash` + `executed_payload_hash`) with the inequality
  explicit and expected. The current 5A evidence schema carries one hash.
- **Residual:** planner skeleton review burden (small, stable surface).

### F-14 (MEDIUM): Browser side-channels outside route policy

- `context.route(".*")` intercepts requests the Playwright driver sees;
  DNS prefetch, HSTS upgrades, service-worker lifecycle (installed by an
  in-scope page, persisting beyond the attempt's page close into the
  context — though contexts are fresh per attempt, workers die with them;
  verify teardown kills them), WebSocket handshake (intercepted as request —
  okay), and `fetch` with `mode: no-cors` to a same-origin endpoint that
  302s cross-origin (redirect inside the browser network stack, re-checked by
  route handler — okay) are mostly covered. The uncovered case is **exfil
  encoding in supposedly-blocked requests**: blocked cross-origin runtime
  fetches are aborted, but their *attempt* (URL containing the token) is
  visible to the attacker's DNS/outer log if the abort happens after DNS
  resolution. Token-in-URL design means every runtime exfil attempt leaks the
  correlation token to the target's infrastructure regardless of blocking.
  Acceptable (token is single-use, not a secret) but the threat model should
  state it: tokens are bearer-identifiers, not capabilities, and must never
  gate anything beyond correlation.
- Page-to-Python injection: capability transport is sound (256-bit,
  `compare_digest`, silent drop — verified `browser_executor.py`); flooding
  with unauthenticated calls is bounded (512 events, stop-append). No finding
  beyond documenting token non-secrecy.

### Preserved invariants (confirmed by review)

Fresh context per attempt, GET-only browser navigation with explicit error
(never downgraded), query-only token carrier, clean stored READ, E2 oracle
isolation from generic `network_requests`, capability-gated instrumentation,
`_is_navigation_request` defense-in-depth, wall-clock killable worker, verifier
sole-authorship with `_enforce_evidence_binding` — all verified present and
all must be regression-tested against the adapter (5A §11 list is accurate and
complete; no subtraction found).

---

## 10. Evidence findings

### F-07 (MEDIUM): Evidence hash coverage is under-specified

- 5A §13: `evidence_hash = SHA256(canonical JSON minus itself)` with redundant
  bindings. Under-specified: are `redirect_chain` (attacker-controlled
  `Location` strings), `dns_observations`, raw `Location`/object hints,
  truncated bodies, and timing inside the hash? If the chain is hashed,
  attacker length/content choices produce distinct-but-valid hashes (no
  security harm, but dedupe/index must key on `execution_id`, never on the
  hash). If truncated bodies are hashed, two executions differing only past
  the 8 KiB truncation point hash differently while verifier-visible content
  is identical — evidence confusion across retries. If timing is hashed,
  identical logical evidence never dedupes.
- **Mitigation:** split hashes: `bindings_hash` (plan/artifact/target/authz —
  stable, indexed) vs `observations_hash` (transport facts) vs
  `content_hash(full bounded body, stored separately)`. Normative field lists
  in 5H; never hash timing.

### F-15 (MEDIUM): Timeout ambiguity and partial evidence

- `EXECUTION_STARTED` + transport timeout yields `ExecutionError(retryable?)`
  vs sealed partial evidence? For stored SUBMIT, a timeout after the server
  persisted is "unknown whether execution happened" — 5A §15 names the
  distinction but the state machine (§14) has no `OUTCOME_UNKNOWN` terminal;
  the listed terminals (`EXECUTION_FAILED/TIMEOUT/...`) read as retryable
  failures. Worse: `TIMEOUT` evidence that still carries observations (status
  arrived, body incomplete) invites verifier interpretation of partial data.
- **Mitigation:** explicit `OUTCOME_UNKNOWN` terminal (no evidence sealed, no
  verifier handoff, new authorization required); partial observations on
  timeout are either discarded or sealed as `INCOMPLETE` class that no
  verifier accepts (schema-level: verifiers require `complete: true`).

---

## 11. Idempotency/concurrency findings

### F-16 (HIGH): Exactly-once is promised; at-most-once + evidence-dedupe is what survives crashes

- Crash matrix against 5A §15: (a) crash before `EXECUTION_STARTED` → safe
  re-drive (no effect) ✓; (b) crash during transport → `OUTCOME_UNKNOWN`, new
  authz required ✓ (by design); (c) crash after seal but before index/state
  update → evidence exists on disk unindexed (the exact orphan shape
  `verify_all` already reports for artifacts); re-drive under the *same*
  authorization is `CONSUMED`-blocked while the evidence is orphaned —
  permanent wedging unless an orphan-recovery path exists (5A specifies none;
  artifact layer explicitly never reattaches orphans); (d) crash after index
  update but before audit write → `AUDIT_GAP` noted on evidence — but the
  evidence is already sealed, so the gap note cannot be added without breaking
  the seal (contradiction in §18).
- **Semantics verdict:** the design as written provides **at-most-once
  execution with at-least-once evidence availability**, not exactly-once. That
  is the *correct* choice for security testing (never double-persist a stored
  payload silently), but §15's "return existing evidence_id without
  re-executing" must be reframed as dedupe-on-read, and the CAS/index must be
  the artifact-store-hardened pattern (unique index + atomic record-before-
  index + sweep-visible orphans + defined recovery), noting `ArtifactStore`
  itself documents "cross-process writers are out of scope" (verified
  `artifact_store.py:186`) — the executor index cannot inherit that caveat;
  it needs a real cross-process unique constraint (Mongo unique index on
  idempotency key, mirroring `XssFindings.case_id`).

---

## 12. Resource/DoS findings

### F-10b (MEDIUM): Caps are constructor arguments, not ceilings

- Every limit in 5A §16 maps to a wrapper parameter (`timeout`,
  `max_body_bytes`, `max_redirects`, binary flags). No global ceiling object,
  no assertion that operator config ≤ ceiling, no enforcement point the
  attacker cannot shift by influencing configuration (e.g. per-program
  overrides). Nuclei/Chromium ignore Watch variables entirely (their flags are
  advisory to binaries with their own parsers).
- Enforceability checklist for 5E–5G: global ` ceilings` module with
  `assert config <= ceiling` at startup (fail-closed boot); subprocess
  `RLIMIT_AS/CPU` + cgroup or at minimum `timeout` + output-cap + temp-quota;
  browser context with `--disable-extensions --no-sandbox?` (note: sandbox
  *on* in production), worker `terminate` + child-reap verification (zombie
  Chromium containment); temp-dir quota + periodic sweep (orphan `*.tmp`
  handling mirrors the artifact store's `unexpected_file` reporting).
- Specific additions: compression-ratio abort (decompression bomb),
  per-chunk stall timeout (slow drip), DNS-answer cap (many-A/AAAA storm,
  IPv6 explosion), regex timeout for Nuclei `regex` matchers applied to
  attacker bodies (RE2 semantics? — Nuclei uses Go RE2, linear-time; state
  this assumption explicitly or bound matcher CPU), matcher-against-huge-body
  cost (body cap already bounds input; keep).

---

## 13. Secret-handling findings

### F-11 detail (HIGH retained from §7)

- Paths: artifact/TestPlan/authorization/target strings → logs/evidence;
  redirect `Location` + `object_hint` → discovery and READ-URL construction
  (stored flow builds READ URL from attacker `Location` — verified verifier
  `discover_stored_read_url` pattern; token/query from attacker URL persists
  into evidence); Nuclei stdout/stderr → evidence (echoed request may contain
  `Authorization` if a future plan carries one — schema allows arbitrary
  headers in `HttpRequestSpec` today); browser console/network excerpts →
  evidence; DB/Mongo errors → audit; LLM context (orchestrator passes case +
  context; evidence must never flow back into prompts — state explicitly).
- Hardcoded Mongo credentials in `database/db.py:36` (verified) mean every
  resolver-process memory dump, traceback, or config log is a credential
  incident. Out of 5A scope to fix, but 5C must specify: resolver reads via a
  credential-injected connection owned outside the executor, errors sanitized
  at the adapter boundary, connection strings never in audit.
- **Mitigation:** as §7 + secret-free evidence profile (hash-only bodies by
  default), URL scrubber, stdout secret-scanner (deny-seal on high-confidence
  secret pattern? — at minimum flag), and a stated rule: *evidence never
  enters LLM context* (prevents prompt exfiltration of any leaked secret).

---

## 14. LLM-boundary findings

### F-17 (structurally enforced, with one hole): LLM cannot reach execution except via issuer confusion

- Proven by code: LLM layer (`ai/llm/*`) has no tool calls, no retrieval, no
  network to targets; orchestrator never advances to VERIFYING; validators
  reject verdict/authority keys; planner treats `delivery_pattern` as
  attribution-only (verified `oracle.py` planner path); TestPlan builder reads
  no prose. Paths `LLM→executor`, `LLM→arbitrary target`, `LLM→arbitrary
  artifact execution`, `LLM→scope bypass` are all structurally absent —
  **provided** the authorization issuer is not LLM-reachable.
- **The hole is F-01:** with authorization-by-value and string `issued_by`,
  an LLM output containing a well-formed authorization-shaped JSON block could
  be mistaken for an authorization by a future scheduler/queue consumer that
  parses text (no such consumer exists today — the risk is greenfield
  construction in 5B/5J). Structural enforcement needed now: MIME-typed
  authorization channel (never parsed from free text), issuer signature, and
  a test asserting that an LLM-shaped blob (even byte-identical to a valid
  authorization's public fields) is rejected without a valid signature/
  issuance record.
- Scheduler-issued authorization is the same shape: schedulers must be
  *consumers* of authorizations, never issuers, unless the scheduler holds an
  issuer key under the same policy (then it *is* the issuer — name it).

---

## 15. Verifier-boundary findings

- XSS: `Executor→evidence→false CONFIRMED` remains impossible without oracle
  execution (verified exact E1/E2/E3 + freshness + identity + anti-harvest in
  `verifier.py` + `oracle.py`). No subtraction found in 5A. Verifier inputs
  stay fully untrusted (`_enforce_evidence_binding`, `_safe_execute`).
- `Artifact→matcher→false CONFIRMED`: matcher output feeds hypothesis/plan,
  never verdicts — clean.
- `Nuclei stdout→verifier→false CONFIRMED`: **the live grenade** (F-12). No 5I
  verifier exists; the only in-tree consumer maps non-empty stdout to matched.
  5A's handoff discipline is correct but must include deletion/gating of the
  old path as a 5F blocker, plus a rule that Nuclei evidence can yield at most
  a low-confidence signal pending matcher-specificity re-proof per execution.
- `Browser page→oracle→false CONFIRMED`: covered by capability + exact
  predicates + anti-harvest; 5A adds no page-controlled oracle input. The
  `delivery_pattern` attribution channel into the planner is the watch-item:
  add a test pinning planner output invariance under adversarial
  `delivery_pattern` strings (quotes, `{snippet}` markers, seed-like hex).
- Required 5I property (state now so 5H evidence serves it): verifiers accept
  only `complete: true` sealed evidence with live bindings; `INCOMPLETE`/
  `OUTCOME_UNKNOWN` never classify.

---

## 16. Complete finding table with severity

| ID | Title | Severity | § |
|---|---|---|---|
| F-01 | Authorization authenticity absent (forgery by value) | HIGH | §4 |
| F-02 | Sibling-host redirect allowance (eTLD+1) contradicts exact-host rule | HIGH | §6 |
| F-03 | No dial-time DNS/IP binding; rebinding/race unclosable at wrapper level | HIGH | §6 |
| F-04 | Dual artifact identities (`ArtifactRef` vs `ArtifactReference`) | HIGH | §4 |
| F-05 | Nuclei projection not structurally sufficient (emitter + binary network stack + temp) | HIGH | §8 |
| F-06 | Specificity fixture provenance undefined (attacker-provable H1) | HIGH | §8 |
| F-07x | Authorized bytes (P) ≠ executed bytes (O) on XSS oracle path | HIGH | §9 |
| F-09 | TOCTOU + stored-READ re-resolution unspecified | HIGH | §5 |
| F-10 | `DELETE` in plan schema vs deny in artifact schema; reconciliation missing | HIGH | §7 |
| F-11 | Secret retention in evidence/logs beyond header redaction | HIGH | §7/§13 |
| F-12 | Old `to_findings` stdout→matched path survives in-tree | HIGH | §8/§15 |
| F-16 | Crash-consistency promises exceed at-most-once reality; orphan/audit-seal contradiction | HIGH | §11 |
| F-07 | Evidence hash coverage under-specified (chain/timing/truncation) | MEDIUM | §10 |
| F-08 | URL normalization holes (trailing dot, case, userinfo, IP forms, IDN, 0.0.0.0) | MEDIUM | §6 |
| F-08b | Port-compare + upgrade-policy inheritance bugs | MEDIUM | §6 |
| F-13 | Caller-controlled `idempotency_scope` splits/merges intent; stale-evidence serve | MEDIUM | §4 |
| F-14 | Token-bearing blocked requests leak correlation token to target infra | MEDIUM | §9 |
| F-15 | No `OUTCOME_UNKNOWN`/`INCOMPLETE` terminal; partial-evidence interpretation risk | MEDIUM | §10 |
| F-10b | Limits as constructor args, not ceilings; binary-ignored caps | MEDIUM | §12 |
| F-17-hole | LLM-shaped authorization blob risk without typed channel + signature | MEDIUM (HIGH if 5B parses text) | §14 |
| F-18 | Issuer-view content undefined (READY-label inference hazard) | LOW | §3 |
| F-19 | Clock-skew bound + expiry enforcement clock unspecified | LOW | §11 |
| F-20 | Cookie-jar scope across stored SUBMIT→READ unspecified | LOW | §7 |
| F-21 | Phase-order 5E–5G before 5H risks executors without sealed substrate | INFO (process) | §19 |

Downgrades refused: all HIGH findings are architecturally realizable (each
maps to a concrete code path or a concrete absent mechanism), not hypothetical.

---

## 17. Detailed attack paths

### A-1. Forged authorization → arbitrary authorized-looking execution (F-01)

1. Attacker reads valid `(test_plan_id, artifact_id, content_hash)` triples
   from reports/logs (non-secret by design).
2. Attacker (or a confused scheduler parsing LLM-shaped text) presents
   authorization-by-value JSON with recomputed `authorization_id`, live TTL.
3. Checker validates bindings + expiry + scope-hash — all pass (all fields are
   public). Execution proceeds against an attacker-chosen target slot within
   scope lists. **No secret is required at any step.** Fix: §18 B2 teeth.

### A-2. Sibling redirect → out-of-scope host (F-02)

1. Authorized: `https://shop.target.com/probe` (slot `shop.target.com`).
2. Artifact path `/r` is H2-clean. Initial request passes scope.
3. Server (attacker-influenced zone) 302s to `https://admin.target.com/` (same
   eTLD+1, different host, `ooscopes`-listed or foreign-program).
4. Implementation following inherited `_check_redirect_safety` allows
   (registrable domains equal). Per-hop scope check against the *original*
   program's lists either passes (same-program sibling not listed) or is
   ambiguous (foreign program). Probe executes out of slot. Fix: exact-host
   redirect rule (§18 B4 teeth).

### A-3. DNS rebinding → metadata/private IP (F-03 + F-08)

1. Scope pre-check resolves `shop.target.com` → clean public IP. ALLOW.
2. Transport re-resolves at connect → `169.254.169.254` (rebound) or
   `http://0x7f.0.0.1/` (non-decimal literal bypassing string IP deny).
3. Request reaches metadata/loopback with Watch egress identity. Fix: pinned
   resolver + dial-by-IP + egress proxy (B5).

### A-4. DELETE confusion (F-10)

1. Hostile pattern fact declares `method: DELETE`; builder emits DELETE plan
   (schema-permitted, identity-bound).
2. Attacker mints VALID `http_request_spec` artifact (no method field conflict
   at validation — artifact has its own method, default GET).
3. Translator faces DELETE-plan/GET-artifact divergence with no specified
   terminal; coercion or misrouting yields wrong-method execution or silent
   deny-of-service on legitimate plans. Fix: schema convergence +
   mismatch-terminal.

### A-5. Nuclei escape via binary network stack (F-05)

1. Projected YAML is clean; flags allowlisted; `-u https://shop.target.com/x`.
2. Target 302s to `https://sibling.other-program.com/`; Nuclei follows
   internally (no Watch hook).
3. Matcher (specific, H1-passing) fires on attacker sibling; output returns;
   evidence sealed as in-scope execution. Fix: egress proxy + no-follow +
   post-hoc chain attestation (binary must emit chain evidence or its output
   is `INCOMPLETE`).

### A-6. Attacker-proven specificity (F-06)

1. Attacker crafts matcher `word: ["sync-token-9f3k"]` plus research text
   containing the same token as "vulnerable example".
2. Attacker-influenced fixtures: benign without token, vulnerable with token.
   H1 passes honestly.
3. Template executes; matcher fires on any reflection of the attacker's own
   token (server echoes input) → false signal laundered through a "proven"
   gate. Fix: pinned issuer-curated fixtures (B6 teeth).

### A-7. Oracle-payload authorization gap (F-07x)

1. Authorization binds artifact P (audited, bounded).
2. Executor (via adapter + verifier pipeline) transmits oracle payload O ≠ P.
3. Evidence + audit attest P; wire carried O. Any planner-behavior drift
   (skeleton change, `delivery_pattern` influence, seed-count bug) executes
   unaudited bytes under a valid authorization. Fix: authorize derivation +
   dual-hash evidence (B9 teeth).

### A-8. Stale-evidence serve on replay (F-13 + F-15)

1. Execution E1 seals evidence against target state S1.
2. Target changes (S2); caller replays same idempotency key.
3. Executor returns E1 evidence without re-execution; verifier (if it does not
   independently re-resolve freshness) classifies S1 observations as current.
   Fix: cached-evidence serve requires binding re-validation against current
   resolution or refusal.

### A-9. stdout→CONFIRMED via legacy path (F-12)

1. 5F implementer wires handoff to existing `to_findings` for expediency.
2. Any Nuclei stderr/stdout noise (version banner, template debug) becomes
   `matched=True` finding. False CONFIRMED at scale. Fix: delete/gate path.

### A-10. Secret capture in sealed evidence (F-11)

1. Redirect `Location: https://shop.target.com/cb?session=abc` (attacker or
   app-issued) enters chain verbatim; response sets cookie echoed in debug
   header captured beyond the redacted set; Nuclei echoes `Authorization` from
   a permissive plan header (schema allows today).
2. Sealed evidence + audit persist secrets; later log aggregation / LLM
   debugging context exfiltrates. Fix: scrubber + hash-only bodies + no-LLM
   rule.

---

## 18. Blocking requirements

B1–B15 as posed are **necessary but insufficient as stated**. Teeth added
(minimal deltas that convert documentation into enforcement):

- **B1 (authorization):** + authenticity mechanism (signature or
  authorization-by-reference with server-side issuance table). Schema alone
  blocks nothing (F-01).
- **B2 (issuer allowlist):** + typed channel rule: authorizations are never
  parsed from free text/LLM blobs/scheduler logs; MIME-typed API + signature/
  record check + negative test with byte-identical public fields, invalid
  authenticity (F-17-hole).
- **B3 (fresh resolution):** + stored READ as a second execution with full
  re-resolution/re-scope/liveness gates + named `READ_REAUTHORIZED` transition
  (F-09).
- **B4 (ScopeEvaluator):** + exact-host redirect rule (remove eTLD+1
  allowance), shared canonicalization function + fuzz matrix, effective-port
  comparison, same-scheme for state-changing classes (F-02, F-08, F-08b).
- **B5 (DNS/IP at connection):** + pinned resolver + dial-by-IP (or egress
  proxy) + non-decimal-IP parsing + `0.0.0.0`/mapped-v6 coverage; rebinding
  harness test (F-03).
- **B6 (artifact revalidation):** + pinned fixture hashes in authorization +
  issuer-curated fixture corpus + plan/artifact method reconciliation terminal
  (F-06, F-10).
- **B7 (closed translators):** + plan-vs-artifact method/path equality rule
  (mismatch → terminal, never coerce) + single-artifact-exactly-one rule for
  multi-artifact plans (F-10, F-05b) + dual artifact-identity disambiguation
  test (F-04).
- **B8 (Nuclei projection + sandbox):** + parse-back unknown-key reject +
  exclusive temp creation + egress proxy + no-follow + argv-allowlist test +
  `to_findings` deletion gate (F-05, F-12).
- **B9 (XSS adapter):** + authorized-derivation model with dual-hash evidence
  (`artifact_content_hash` + `executed_payload_hash`, inequality expected on
  oracle path) + planner-invariance test under adversarial `delivery_pattern`
  (F-07x).
- **B10/B11 (immutable + bound evidence):** + split hashes
  (bindings/observations/content), timing excluded, `complete` flag,
  `OUTCOME_UNKNOWN`/`INCOMPLETE` terminals that no verifier accepts (F-07, F-15).
- **B12 (idempotency/CAS):** + cross-process unique constraint (Mongo unique
  index, not in-process lock) + orphan-recovery path + audit-write ordering
  fixed (audit-before-seal or seal-includes-audit-hash; never annotate sealed
  evidence) (F-16).
- **B13 (limits):** + global ceilings module with boot assertion + binary-
  independent enforcement (proxy/cgroup/reap) + compression/streaming/DNS/
  regex budgets (F-10b).
- **B14 (secret-free):** + URL scrubber + body-minimization default +
  resolver-error sanitization + evidence-never-in-LLM-context rule (F-11).
- **B15 (sole classifier):** + `INCOMPLETE`/`OUTCOME_UNKNOWN` rejection in
  every verifier + legacy-path deletion proof (F-12, F-15).

**New blockers:** B16 dual-identity disambiguation (F-04); B17 fixture
provenance pinning (F-06); B18 derivation-authorization for oracle payloads
(F-07x); B19 egress enforcement for binary network stacks (F-05 second half).

---

## 19. Phase-order recommendation

Proposed `5B→5C→5D→5E→5F→5G→5H→5I→5J` is **unsafe in one respect**: executors
(5E–5G) precede the evidence/idempotency substrate (5H). Executors built first
will define their own ad-hoc evidence shapes and dedupe logic, guaranteeing
divergence from 5H and inviting the legacy-path mistake (F-12).

**Safer sequence (same phases, reordered):**

1. **5B Authorization schema + authenticity** (signature-or-reference + typed
   channel + issuer policy).
2. **5H-core Evidence schema + idempotency/CAS + audit ordering** (store
   backend may follow; the *schemas, hashes, terminals, and index contract*
   must precede executors).
3. **5C Target resolver** (read-only, fake-tested).
4. **5D Scope evaluator + input validation** (canonicalizer + fuzz matrix).
5. **5E HTTP executor** (against the 5H substrate).
6. **5F Nuclei executor** (projector + sandbox + legacy-path deletion).
7. **5G XSS adapter** (derivation-authorization + dual hash).
8. **5H-store Evidence store backend + sweep** (if split from core).
9. **5I Verifier handoff + Nuclei/HTTP classifiers** (with `INCOMPLETE`
   rejection).
10. **5J E2E** (local harness; production only after re-review clearing all
    HIGH findings).

Additionally: resolve F-04 identity choice and F-10 DELETE convergence inside
5B/5D (schema decisions), not inside executor phases where schedule pressure
favors coercion.

---

## 20. Residual risks (accepted after blockers, tracked not closed)

- Nuclei/Chromium binary vulnerabilities (pin + checksum + sandbox; residual).
- Intra-request target reassignment (bounded by short windows + per-hop checks).
- Fixture coverage gaps for novel template families (corpus growth in 5F).
- DNS DoH exfil inside page JS (proxy-level DNS control, 5G hardening).
- Operator double-issuance with distinct caller keys (distinct-keys =
  distinct-intent by definition; rate-limit authorizations per program/window).
- Scope-list propagation delay ≤ resolver TTL (fail closed on drift; document TTL).
- Correlation-token visibility to target infra (tokens are non-secret
  identifiers by policy; never gate on token secrecy).

---

## 21. Explicit statement that no code was modified

No repository file was modified in this review. No production code, test,
schema, configuration, or documentation file was created, edited, renamed,
moved, or deleted, with the sole exception of this review report itself at the
mandated path. No Executor was created. No target was executed against. No
HTTP request was sent. No Nuclei invocation was performed. No browser was
launched. No verifier was invoked. No finding was created.

## 22. Explicit statement that no Git commands were run

No Git command was run in this review. Specifically none of: `git status`,
`git diff`, `git add`, `git commit`, `git branch`, `git merge`, `git checkout`,
`git switch`, `git restore`, `git reset`, `git stash`, nor any other Git
operation (log, remote, fetch, pull, push, tag, reflog included). Repository
state was inspected with read-only file access only.
