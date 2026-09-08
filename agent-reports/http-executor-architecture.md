# Phase 5E — HTTP Executor
# READ-ONLY SECURITY ARCHITECTURE

> Mode: architecture/design only. No code was written, modified, or
> executed; no network, DNS, subprocess, browser, Nuclei, MongoDB,
> LLM, finding, or verdict activity was performed; no git operation
> was performed. All findings below come from read-only inspection
> of the repository at `/opt/watch`.

## 1. Executive verdict

**The secure HTTP executor is architecturally specified and ready
for phased implementation, with two BLOCKING gates before any live
traffic** (production DNS source selection, §22-B1; production
ledger/authorization-store adapters, §22-B2 — the latter already
tracked as 5J/B3). The central security property
`SCOPE-EVALUATED == ACTUALLY-DIALED` is closed by a single primary
mechanism: **IP-pinned socket transport (alternative D)** — an
explicit `http.client`-grade transport over an injected,
fake-testable socket factory, where the executor dials the pinned
IP literally, performs zero post-approval resolution, pins
SNI/Host to the canonical hostname, disables every implicit
library behavior (redirects, pooling, proxy-env, cookies,
auto-decompression), and re-submits each redirect hop to 5D before
touching the wire. Rejected alternatives (plain `requests` session,
httpx custom transport, mandatory-egress-proxy-as-primary) are
documented in §21 with reasons. No item below silently invents a
missing contract: every entry is classified FROZEN / DECIDED /
DEFERRED / BLOCKING.

## 2. Existing implementation assessment

Read-only findings on `ai/verification/http_executor.py` (932
lines), its tests, and neighbors:

- **Correct, reusable core (WRAP, not rewrite):** manual redirect
  loop with `allow_redirects=False` (§389–468); visited-set cycle
  check; per-status method handling; bounded chunked body read
  (§530–539); submit-shape gating (`_submit_shape_error`, POST never
  downgraded at build time); `_sanitize_reason` + header redaction
  discipline; `FakeSession` injection seam already used by 1108
  lines of tests.
- **Must be retired from the execution path (FROZEN prohibitions
  for 5E):** (a) same-eTLD+1 sibling-redirect allowance
  (`_check_redirect_safety`, F-02 — `authorized.example.com →
  evil.example.com` currently permitted); (b) raw-string `visited`
  set (case/dot/query drift defeats cycle detection); (c)
  `(current.port or "")` int/str port mix (F-08b); (d) unrefused
  userinfo in `Location`; (e) raw `target_host` reflected into
  errors; (f) implicit re-resolution — `session.request(url)`
  lets urllib3 resolve the hostname **again after** any check,
  which is precisely the resolve-A/approve-A/connect-B hole (§6
  answers why a pre-request DNS check is insufficient);
  (g) `requests.Session()` defaults: env-proxy trust, cookie
  persistence, connection pooling keyed by hostname;
  (h) `VerificationEvidence` legacy shape (reflection/WAF/status
  vocabulary) must NOT flow into 5H sealing — 5E emits 5H-core
  `HttpObservation` + sealed `EvidenceRecord` only, and the old
  stdout→matched-style paths stay deleted (F-12).
- **Neighbor contracts (all FROZEN, all reused):** `HttpObservation`
  already carries `dial_ips`, `redirect_chain: list[RedactedUrl]`,
  `transport_outcome`, and the DELETE-free method Literal;
  `ai/evidence/observations.py` already bounds headers (32/128/1K/
  8K), bodies (16K request, 512K transport, 8K sample, 2M
  decompressed, 10x ratio), and chains (5+overflow);
  `HttpArtifactContent` (H2) already bans DELETE, credential
  headers, shell/script/path content; `TestPlan.HttpRequestSpec`
  still admits DELETE — closed by 5B `check_method_pair`
  (plan==artifact, both allowlisted) plus the 5E translator re-check
  (§7), i.e. translator-deny wins without a schema migration.
- **Environment (verified, no install performed):** `requests`
  2.32.5, `urllib3` 2.6.3, `httpx` 0.28.1 present. Neither `requests`
  nor `httpx` exposes resolver injection: urllib3 resolves inside
  `HTTPConnection.connect()` via `socket.create_connection`, and
  httpcore offers no resolver seam either — hence any library-based
  primary would rest its core guarantee on overriding undocumented
  internals. This fact drives the alternative selection in §21.

## 3. Frozen contracts consumed

- **5B (FROZEN):** live `IssuedExecutionAuthorization` by typed
  reference only; `(authorization_id, execution_id)` binding;
  `max_executions = 1`; liveness re-asserted pre-execution;
  method-pair contract (`plan_method == artifact_method ∈
  {GET,POST,PUT,PATCH,HEAD,OPTIONS}` — DELETE never authorized);
  CAS consume/revoke; `NEVER_ISSUERS` (LLM/scheduler/collector/
  verifier cannot mint).
- **5C (FROZEN):** `TargetResolution` (RESOLVED-only input);
  canonical tuple `(program, canonical_host, scheme,
  effective_port)`; `DialBinding{addresses, effective_port,
  sni_host, pin_required}`; 8-answer ceiling; global-unicast-only
  observation; deterministic ids/hashes; `scope_view()`.
- **5D (FROZEN):** exact-host + single-level wildcard + absolute
  exclusion matching; program isolation; drift detection;
  per-hop independent evaluation (5-edge cap, canonical visited
  set, per-hop policy re-read); `require_allowed()` triple gate;
  ALLOWED/DENIED/INCONCLUSIVE (INCONCLUSIVE never authorizes);
  no eTLD+1/CDN/IP inference; 5D performs no DNS.
- **5H-core (FROZEN):** ledger CAS
  (`REGISTERED→STARTED→SEALED_REF/INCOMPLETE_REF/UNKNOWN`,
  replay/dedupe/in-progress semantics, crash table);
  `BUILDING→SEALED/INCOMPLETE` single-use builder (no
  reassign/rebind/repair); bindings/observations/content hash
  separation; scrubber (sole redaction authority); ceilings
  (§9 values, unmodified); audit transitions + ordering +
  AUDIT_GAP rule; orphan/reindex path.

## 4. Security invariants

1. Only `require_allowed() == ALLOWED` plus a live, consumed-by-us
   authorization starts transport. 2. The wire URL derives solely
   from resolved-base + revalidated artifact path/query — never
   from artifact/plan/TI strings. 3. Every connection dials a
   pinned IP from the current hop's approved binding; hostname
   strings never reach any resolver after approval. 4. SNI = Host
   header = canonical hostname on every TLS/cleartext request.
   5. Each redirect hop repeats the full 5C→5D→pin cycle; initial
   approval confers nothing downstream. 6. eTLD+1/CDN/CNAME/IP/
   ASN/certificate similarity authorizes nothing. 7. Method set is
   closed; method meaning never changes implicitly. 8. Pooling,
   proxy-env, cookies, auto-redirects, auto-decompression are
   disabled or explicitly re-implemented under caps.
   9. All observations are bounded; secrets never persist
   (shared scrubber). 10. Evidence distinguishes authorized /
   evaluated / dialed / responded identities. 11. At-most-once
   execution and at-least-once evidence stay separate (ledger vs
   seal/index/audit). 12. No verdicts, no LLM, no findings in 5E.

## 5. Threat model

Attacker controls: target strings, Unicode, redirect `Location`s
(incl. credentials/secrets/encoding tricks), DNS answers + timing
(rebinding, rotation, slow-drip), response bodies/headers
(decompression bombs, huge/lying Content-Length, chunked abuse,
malformed framing), connection behavior (stalls, resets,
downgrade attempts), historical inventory/TI, sibling/CDN hostnames.
Attacker goals: SSRF (loopback/link-local/RFC1918/CGNAT/metadata/
multicast/reserved/documentation space), sibling-host escape,
scope-drift execution, rebinding (approve A, connect B),
credential/secret exfiltration into evidence, response-bomb DoS,
double-execution of one-shot authorization, verdict fabrication.
Out of scope for 5E: target-side exploit semantics (no payload
judgment), binary-stack threats (5F), page-script threats (5G),
operator-key compromise, CA compromise (residual, §22).

## 6. Target/dial binding architecture (answers §4–§6 of the brief)

- **Why a pre-request DNS check is insufficient (FROZEN
  rationale):** check-then-connect is TOCTOU (answers rotate
  between check and SYN), and crucially the HTTP library performs
  its **own** resolution at connect time from the hostname string —
  so even a correct check is bypassed by design. The only closure
  is to never give the transport a hostname to resolve.
- **Binding rule (DECIDED):** after 5D ALLOWED for hop *h* with
  pinned set *P(h)*, the transport selects one address `d ∈ P(h)`
  (deterministic policy: first in 5C canonical numeric order;
  v4/v6 both permitted iff both pinned — FROZEN from 5C ordering)
  and opens the socket to `d` **literally**; the socket factory
  signature is `connect(ip_literal, port, timeout)` and it MUST
  raise on non-literal input (fail-closed type gate). No
  `getaddrinfo`, no `create_connection(hostname)`, no
  proxy-DNS anywhere on this path.
- **Host/SNI/destination coherence (DECIDED):** TLS
  `server_hostname` = canonical host; `check_hostname = True`
  against system CA store; HTTP `Host` header = canonical host
  (bracketed form for v6 literals is N/A — v6 destinations arise
  only as dial IPs under a DNS hostname's SNI); request-target is
  origin-form (`/path?query`); absolute-form and `CONNECT` are
  never emitted (proxy path deferred, §11). A mismatch at any
  layer aborts the hop (`TRANSPORT_BINDING_FAILURE`, terminal).
- **Per-hop freshness (DECIDED):** redirect hops re-run
  resolver→5D→pin (steps 9–11 of the redirect algorithm, §12);
  the initial binding is never reused past one hop.

## 7. HTTP transport architecture

- **Closed entry (DECIDED):** single function
  `execute_http(*, authorization, resolution, scope_evaluation,
  artifact_reference, artifact_bytes, execution_id, now, deps)`
  — typed records only (`TypeError` on dicts/URLs/strings);
  entry asserts: liveness, `require_allowed()` triple,
  `evaluation_id` freshness vs current policy hash (re-assert
  drift at entry — cheap, closes T-entry windows), ledger claim
  (below). No other public call path performs I/O; direct
  session/client construction is banned by test (import-scan +
  absence of any second transport function).
- **Translator (DECIDED, executor-arch §9 frozen inputs):**
  method = 5B-bound pair re-checked against closed allowlist
  (DELETE/CONNECT/TRACE denied even under schema drift);
  path = artifact path revalidated by H2 **and** equal to the
  plan-bound path; query = validated artifact params only
  (≤16 params, ≤1024 chars each, no credential-shaped values);
  headers = allowlist (`Accept`, `Accept-Language`,
  `User-Agent: WatchSecurityResearch/1.0`,
  `Content-Type: application/x-www-form-urlencoded` for body
  probes only) + deny (`Host`, `Authorization`, `Cookie`,
  `Set-Cookie`, `Proxy-*`, `Content-Length`, CR/LF bearers);
  body = None or ≤16 KiB H2-clean bytes; URL = resolved base
  authority + validated path/query (userformfilepath).
  Translator output is an immutable `BoundedHttpRequest`
  (new 5E type); translation failure is terminal before any
  socket exists.
- **Methods (FROZEN + DECIDED):** allowed
  GET/POST/PUT/PATCH/HEAD/OPTIONS; forbidden
  DELETE/CONNECT/TRACE/anything-else. Redirect method handling is
  explicit code, never library behavior: 303→GET; 301/302 with
  POST/PUT/PATCH→GET (legacy-compatible, recorded); 307/308
  preserve; all other combos preserve; a POST is never
  silently converted except by the two stated rules, and SUBMIT
  bodies are never forwarded across an upgrade without
  re-translation (DECIDED: hop request re-derives from the
  translator output + hop URL; bodies cross hops only on
  307/308 same-origin… more precisely same **exact-host** hops).
- **Pooling/keep-alive (DECIDED):** disabled in 5E v1 — one fresh
  connection per hop (≤6 per execution; negligible cost).
  Rationale: hostname-keyed pools reintroduce aliasing; IP-keyed
  pools add state for no needed gain. HTTP/1.1 only (no H2
  coalescing surface). TLS sessions not resumed across hops
  (fresh handshake per hop; resumption across executions banned).
- **Cookies/jars (DECIDED):** no jar across executions; no jar
  across hops except `Set-Cookie`→observation (evidence only);
  `Cookie` request header banned at translation. (Closes F-20
  cookie-scope ambiguity by elimination.)
- **Misc protocol (DECIDED):** `Expect: 100-continue` never sent;
  `Accept-Encoding` limited to `identity, gzip, deflate`
  (brotli/zstd declined → server falls back; unlisted encodings
  in responses → `TRANSPORT` failure, never raw passthrough);
  1xx skipped to final status; 204/304 → no-body path; trailers
  ignored; `Connection: close` always sent.

## 8. DNS architecture

- **Zero library DNS (DECIDED):** the transport performs no
  resolution primitive at all; the socket factory accepts IP
  literals only. Per-hop address supply reuses the **5C
  `DnsResolver` protocol** (injected `AddressSource`): resolve →
  cap (8) → classify (any-denied aborts) → 5D hop evaluation →
  pin → dial. The resolve→dial window contains no other lookup,
  closing rebinding structurally; rotation across hops yields a
  new 5D decision, never silent continuation.
- **v4/v6 (DECIDED):** both families flow through the same gate;
  mapped/zone-scoped forms refused at classification (5C);
  selection is first-in-canonical-order (deterministic, recorded
  as `dialed_address`); Happy-Eyeballs-style racing is banned
  (racing dials unapproved addresses by design).
- **Production source (BLOCKING B1):** interface frozen now;
  the production adapter choice (hardened system resolver with
  caps vs dedicated minimal resolver) is DEFERRED to 5E
  implementation with a mandatory review gate — **no live
  traffic until B1 closes**, because a misbehaving source
  (search-domain suffixing, honoring attacker TTL games without
  caps) would weaken observation even though dial-pinning holds.

## 9. TLS architecture

Verification ON, always: system CA store, `check_hostname=True`,
`server_hostname` = canonical host (SNI correct by construction);
TLS version floor = system default with explicit `TLSv1.2+`
minimum set in code (DECIDED); cipher customization banned
(defaults only). IP-literal dial + hostname verification is the
normative pattern (dial `d`, verify cert against name) —
hostname/IP mismatch, expiry, wrong-name, self-signed, or
handshake failure → `TLS_FAILURE` terminal, evidence sealed
INCOMPLETE with transport facts only. Downgrade: any hop
requiring cleartext where the chain was HTTPS → deny before
connect (5D rule, re-asserted at transport). TLS keying material
never logged; negotiated parameters (version/cipher) are audit
metadata at most (DEFERRED whether persisted). Certificates are
never scope evidence (FROZEN).

## 10. Host/SNI architecture

Single source of truth per hop: canonical hostname from the
hop's 5D decision. Emitted as: TLS SNI, HTTP `Host`, and audit
`host` field — all three from the same variable (DECIDED;
unit-test asserts the triple equality from the fake transport's
recorded calls). `Host` override from artifact/plan/redirect is
unrepresentable (translator denies the header; hop builder takes
no host parameter). `X-Forwarded-Host` never sent. Absolute-form
request targets never emitted.

## 11. Proxy architecture

- **5E v1: direct connections only (DECIDED).** Environment proxy
  variables are ignored (`trust_env`-equivalents disabled;
  constructor takes no proxy parameter); `Proxy-*` headers
  banned; `CONNECT` never emitted. Rationale: a proxy is a second
  resolver + second policy engine; shipping one by default to
  "solve" egress would merely move the binding problem.
- **Egress proxying as defense-in-depth (DEFERRED, non-blocking):**
  future design must specify IP-literal `CONNECT` targets
  authorized per hop, proxy-side DNS disabled (proxy resolves
  nothing; it connects to given literals), proxy credentials
  absent by design, and evidence recording the proxy path
  distinctly from the dial path. No 5E implementation may assume
  it.

## 12. Redirect state machine

States: `INITIAL → HOP(i, url, dial) → … → FINAL | ABORT(code)`.
Transition function per hop (no stage skippable; each maps to a
test in §20): 1. read `Location` (missing on 3xx → abort
`REDIRECT_INVALID`; multiple `Location`s → abort — first-wins is
attacker choice). 2. Reject on: userinfo present, control chars,
length > 2048, backslash anywhere, scheme ∉ {http,https}
(post-`urljoin`), empty host, `parts.port` invalid, encoded
`%00`/`%2e`-at-authority tricks (decoded-once + re-check;
double-encoding abort). 3. `urljoin(current_canonical, location)`
covers relative/absolute/scheme-relative uniformly. 4. 5C
canonicalize host (fail → abort). 5. Scheme gate (downgrade
abort; upgrade only `http_probe`, recorded). 6. 5D hop
evaluation vs freshly re-read policy (sibling/excluded/OOS →
abort; INCONCLUSIVE → abort — transport never proceeds without
ALLOWED). 7. Port allowlist `{80,443,resolved-port}` (violation
→ abort). 8. AddressSource resolve → cap/classify → pin new
`DialBinding` (any-denied → abort). 9. Dial `d ∈ P(h)` via
socket factory; record actual peer. 10. Emit hop observation.
Loop: canonical-URL visited set (scheme/host/port/path/query —
path compared exact, never normalized for authority) + 5-edge
counter; 6th edge or revisit → abort (`REDIRECT_LIMIT` /
`REDIRECT_INVALID`). IP-literal hop destinations: abort
(`REDIRECT_NOT_IN_SCOPE` — no IP scope in current policy).
`Location` secrets: deny-if-userinfo + scrubber-redact the
persisted hop URL (shared scrubber, no second redactor).

## 13. Request identity

Immutable `BoundedHttpRequest` + per-hop `HopTransportRecord`:
`{execution_id, authorization_id, resolution_id, evaluation_id,
program, canonical_target_hash, canonical_url (+hash),
scheme, effective_port, dialed_address, sni_host, method,
artifact_id, artifact_content_hash, hop_index, request_fingerprint
= sha256(canonical_url, method, body_hash, dialed_address)}`.
Evidence hashes: request line/body via 5H `observe_body` +
`RedactedUrl` (hashes participate; samples bounded); bindings
hash covers ids + artifact + scope/policy pins (follows 5H
`bindings_payload` field discipline — extend, don't fork);
timestamps/worker labels audit-only (never hashed). Hop index 0 =
initial; fingerprint binds the dial IP so evidence can prove
evaluated==dialed per hop.

## 14. Response bounding

Pre-check `Content-Length` (absent/lying → still stream under
caps, never pre-allocate trust); chunked framing parsed
strictly (framing error → abort, partial bytes still hashed as
INCOMPLETE evidence); per-chunk stall timer 10 s (any gap →
`STALL_TIMEOUT`); cumulative transport cap 512 KiB (stop +
`RESPONSE_LIMIT`, hash what arrived); decompression streaming
with running ratio guard 10x and 2 MiB output cap
(`DECOMPRESSION_LIMIT`); sample 8 KiB text-only (binary →
hash-only, explicit omission reason via `observe_body`);
malformed status line/headers → `TRANSPORT` abort (never
best-effort parse). Timeouts: connect 10 s, read 10 s, wall 60 s
per execution across hops (DECIDED: wall clock enforced by
deadline propagation, not per-hop reset — prevents 6×10 s
stretching).

## 15. Secret handling

Shared 5H scrubber exclusively. Request path: translator bans
credential headers outright (fail-closed at translation, so
secrets cannot reach the wire); query values secret-shaped →
translation reject (credential-shaped values banned per §7);
`Authorization`/`Cookie` can never be set (no header path
exists). Response path: `filter_headers` allowlists +
`scrub_headers`; `Set-Cookie`/`Www-Authenticate` values never
persist raw; bodies sampled text-only with secret-shape scan →
`[REDACTED]` substitution before persist (scrubber), hash covers
the redacted sample (DECIDED — hash must verify what is stored,
not what was discarded). Redirect `Location`s with userinfo
abort; secret-shaped query in hop URLs persists redacted-only
via `RedactedUrl`. Audit carries hashes/codes/ids only.

## 16. Evidence model

Per execution: one 5H `EvidenceRecord` (`http` channel,
`REQUIRED_OBSERVATIONS` already maps `http_probe`/
`http_verification` → `("http",)`): `HttpObservation` with
`request_url: RedactedUrl`, allowlisted `HeaderSnapshot`s,
body hashes + bounded samples, `response_status`,
`redirect_chain: list[RedactedUrl]`, `chain_truncated`,
`dial_ips` = per-hop dialed addresses in order (closes §16's
four-identity requirement together with bindings:
authorized=authz snapshot, evaluated=5D ids, dialed=`dial_ips`
+ fingerprints, responded=final `request_url`/status),
`transport_outcome` mapping (responded/timeout/
connection_error/killed/aborted_limit). Transport failure
before any byte → INCOMPLETE record (failures are still sealed
observations, never verdicts). Builder single-use discipline
(FROZEN) + ledger `mark_sealed/mark_incomplete/mark_unknown`
mapping (§17). No reflection/WAF/status-vocabulary fields enter
5H records (legacy `VerificationEvidence` stays out of the seal
path; verifier treats all 5E output as untrusted).

## 17. Execution ordering

FROZEN order (each step's failure is terminal with the stated
code; crash points map to the 5H crash table in §18):
1. typed-input gates (`TypeError` on forgeries) →
2. liveness re-assertion (`AUTHZ_NOT_LIVE`) →
3. fresh 5C resolution (note: resolution normally precedes 5E;
   5E re-validates binding, and re-resolves per redirect hop) →
4. 5D evaluation + `require_allowed()` triple →
5. artifact revalidation per executor-arch §8 (hash + bindings
   + H1/H2 re-run + plan/artifact method+path equality;
   `ARTIFACT_REVALIDATION_FAILED`) →
6. translation (`BoundedHttpRequest`) →
7. ledger `put_new(REGISTERED)` + `consume_authorization` CAS +
   `mark_started` (adjacent; §18 recovery) →
8. audit `AUTHORIZATION` + `EXECUTION_STARTED` (audit-write
   failure here blocks transport — FROZEN) →
9. per-hop: policy re-read → 5D hop → pin → connect →
   bounded exchange → hop observation →
10. seal (`SEALED`/`INCOMPLETE`) → ledger terminal mark →
11. audit `EVIDENCE_SEALED` + `EXECUTION_TERMINAL`
    (post-start audit failure → `AUDIT_GAP`, never seal mutation).
One-shot invariant: consumption happens exactly once per
authorization (CAS); any post-consume crash requires a NEW
authorization for retry (DECIDED recovery, §18).

## 18. Crash consistency

Ledger is the single crash-truth (FROZEN table): pre-start crash
→ safe re-registration path; consume↔STARTED gap crash →
recovery marks ledger UNKNOWN + audit gap, retry requires NEW
authorization (the ambiguous state is never resolved by
re-executing under the consumed id — this preserves at-most-once
while keeping at-least-once evidence honest: partial bytes, if
any, are sealed INCOMPLETE under the dead execution, never
handed off, eligible only for orphan-reindex accounting).
Transport-unknown (timeout vs server-acted ambiguity, e.g. POST
timeouts) → `mark_unknown`, no evidence bytes claimed, new-authz
retry (stored-SUBMIT rounds get new round ids — 5G concern
noted). Post-seal crashes → orphan sweep reindexes (DEFERRED
sweep mechanism, FROZEN semantics). 5E implementation must add a
deterministic crash-matrix test suite driving each crash point
with fakes (no real kills needed).

## 19. Failure model

Closed vocabulary (bounded/secret-free/deterministic-shape;
secret-bearing hints refused, not redacted): reuse FROZEN codes
`AUTHZ_NOT_LIVE`, `AUTHZ_BINDING_MISMATCH`,
`TARGET_BINDING_MISMATCH`, `TARGET_NOT_IN_SCOPE`,
`TARGET_EXCLUDED`, `SCOPE_DRIFT`, `RESOLUTION_BINDING_MISMATCH`,
`DIAL_BINDING_MISMATCH`, `UNSAFE_ADDRESS`, `REDIRECT_LIMIT`,
`REDIRECT_NOT_IN_SCOPE`, `REDIRECT_INVALID`,
`EXECUTION_REPLAY/DUPLICATE/IN_PROGRESS`, `OUTCOME_UNKNOWN`,
`LIMIT_EXCEEDED`, `ARTIFACT_REVALIDATION_FAILED`,
`HANDOFF_REJECTED`, `AUDIT_GAP`; add 5E-narrow codes only
(DECIDED, frozen at implementation): `TRANSPORT_TIMEOUT`
(connect/read/stall distinguished in detail suffix, closed set),
`TLS_FAILURE`, `TRANSPORT_BINDING_FAILURE` (peer/SNI/Host
divergence), `DNS_OBSERVATION_FAILED` (address-source failure —
never a silent empty set), `RESPONSE_LIMIT`,
`DECOMPRESSION_LIMIT`, `TRANSLATION_REJECTED` (reuse 5B code,
same meaning), `EXECUTION_ALREADY_CONSUMED` (CAS loss),
`EVIDENCE_SEAL_FAILED`. No other codes without an architecture
note. Mapping to `transport_outcome` + INCOMPLETE-vs-UNKNOWN is
tabulated at implementation (§23 step 5E.7).

## 20. Test architecture

Offline `unittest`, fake socket factory (records every
`(ip, port, sni, bytes)`; scripts responses/timeouts/resets/
malformed framing/gzip bombs; asserts dialed ∈ pinned and
hostname never resolved — factory raises on non-literal),
fake `AddressSource`, in-memory ledger/store/policy, frozen
5B/5C/5D fixtures. Matrix (minimum): AUTHORIZATION (8 cases
per brief) · TARGET (7) · DNS/DIAL (9 incl. stale-resolution,
id/binding mismatch, ceiling, v4/v6) · SCOPE (10 incl.
drift/stale-policy/upgrade/downgrade/cross-port) · REDIRECT
(13 incl. 5-allow/6-deny boundary both sides) · TRANSPORT
(Host/SNI mismatch, reuse-attempt refusal, H2-absence,
proxy-env ignored, TLS mismatch/expiry/wrong-name, all three
timeouts, body/response/compression caps, truncation
hash-honesty) · EVIDENCE (4-identity separation, hash
verification round-trip, secret-scrub fixtures incl.
`Location`-with-credentials, hop binding, crash-matrix incl.
consume-gap, forbidden-field scan: no verdict/finding/
severity/confirmed) · BOUNDARY (no second transport entry,
no raw-URL/Host/IP authority params, no LLM/network/subprocess
imports). Live-fire is banned until B1+B2 close; thereafter
local-harness only (loopback fake target speaking scripted
bytes — still no internet).

## 21. Rejected alternatives

- **A. Custom requests/urllib3 adapter with pinned connections
  (REJECTED as primary):** viable but the guarantee would rest
  on overriding `PoolManager.connection_from_host` /
  `HTTPConnection.connect` — version-sensitive internals;
  residual defaults (env proxies, cookies, redirect handling in
  sibling code paths) need per-version re-audit. Keep `requests`
  for recon-only paths (collectors/fingerprint, already
  isolated); forbidden in 5E transport (import-scan).
- **B. httpx custom transport (REJECTED):** same DNS-seam
  absence as A, plus HTTP/2 support becomes a coalescing
  liability rather than an asset. No compensating advantage
  over D.
- **C. Mandatory egress proxy as the binding mechanism
  (REJECTED as primary, DEFERRED as defense-in-depth):** moves
  resolution trust to the proxy (proxy DNS must then be
  constrained to literals, CONNECT targets authorized per hop)
  — strictly more trusted code, not less. Revisit only as an
  additional containment layer with the §11 contract.
- **E. Plain high-level client + pre-checks (REJECTED):**
  check-then-connect TOCTOU plus library re-resolution make
  the core property unstatable. Never permissible.
- **Selected: D. IP-pinned socket transport (DECIDED):** one
  injectable seam (`connect(ip_literal, port, timeout)`),
  zero post-approval resolution, explicit TLS/SNI/Host, no
  pooling/proxy/cookies/redirects to disable because none are
  implemented, full-fake testability down to the SYN. Cost:
  more 5E-owned code (framing, chunked, gzip guard) — bounded,
  deterministic, and testable, versus trusting opaque library
  behavior. HTTP/2 explicitly out of scope for 5E v1.

## 22. Open decisions/blockers

- **B1 BLOCKING (live traffic):** production `AddressSource`
  selection + review (system resolver hardening vs dedicated
  minimal resolver: search-domain disabling, timeout/rotation
  caps, answer-cap enforcement pre-classification). Interface
  frozen; source deferred. Nothing dials real IPs until closed.
- **B2 BLOCKING (live/multi-worker):** production Mongo adapters
  for authorization store + execution ledger (unique index +
  atomic CAS) + audit/evidence backends + orphan sweep. Semantics
  frozen; mechanism deferred (already B3/5J).
- **DEFERRED (non-blocking, safe defaults set):** egress proxy
  design (§11); negotiated-TLS-parameter persistence; HSTS
  handling (ignore: explicit scheme policy governs); request
  trailers; `If-None-Match` conditional semantics (allowed
  header, behavior explicit at implementation); per-program rate
  limits (operator policy, 5J); local-harness E2E shape.
- **DECIDED (closed here):** everything in §§6–20 not marked
  otherwise, including F-10 translator-deny, F-02/F-08
  retirement via 5D+§12, crash-recovery rule, secret-hash
  discipline (§15: hash covers redacted stored bytes).

## 23. Exact implementation plan for 5E

5E.1 — `BoundedHttpRequest` + translator (5B-bound method,
H1/H2 re-run, allowlists, closed `TRANSLATION_REJECTED`) with
unit matrix; no I/O. 5E.2 — pinned socket transport + socket-
factory seam + fake (dial assertions; no TLS yet; HTTP/1.1
framing). 5E.3 — TLS wrapper (SNI/verify/floor; failure
matrix). 5E.4 — bounded response pipeline (caps/stall/ratio/
truncation honesty) against scripted-byte fakes incl. bombs.
5E.5 — redirect state machine (§12) over fake transport +
fake 5D inputs (then real 5D). 5E.6 — lifecycle orchestration
(§17 order, ledger CAS, audit transitions, crash-matrix tests).
5E.7 — 5H sealing integration (`HttpObservation`, hashes,
`dial_ips`/chain, INCOMPLETE paths) + failure-code→outcome
table. 5E.8 — secret-scrub fixtures + forbidden-field/import
scans. 5E.9 — adversarial suite (§20) + local-harness readiness
review (harness itself is 5J work; 5E proves harness-testable).
Each step lands with tests; no step enables live traffic
(B1+B2 gates documented in code as runtime guards, not comments).

## 24. Security invariant checklist

[ ] ALLOWED-triple + live-authz + ledger-claim precede any socket.
[ ] Wire URL = resolved-base + revalidated artifact path/query only.
[ ] Every SYN targets a currently-pinned IP literal; no post-approval lookup exists in code (scan).
[ ] SNI = Host = canonical host from one variable (triple-equality test).
[ ] Hop *h+1* never inherits hop *h* (per-hop 5D + re-pin test).
[ ] eTLD+1/sibling/CDN/cert similarity authorizes nothing (negative tests).
[ ] Method set closed; no implicit rewrites (matrix test).
[ ] No pooling/cookies/proxy-env/redirects/auto-decode (default-kill tests).
[ ] Bounds enforced at every layer (cap matrix incl. 5-allow/6-deny).
[ ] Secrets banned from wire (translation) and store (scrubber) with fixture proofs.
[ ] Evidence separates authorized/evaluated/dialed/responded (field-level test).
[ ] At-most-once (ledger CAS) vs at-least-once (seal/index/audit) separated; crash matrix green.
[ ] No verdict/finding/severity/confirmed/LLM anywhere in 5E (scan + field tests).

---

- files created: `agent-reports/http-executor-architecture.md` (this report only)
- files modified: none (read-only phase; verified by inspection discipline — no editor write to any source file occurred)
- tests run: none (architecture phase; no code to test — existing suites untouched and unexecuted)
- live execution performed: NO (no network, DNS, subprocess, browser, Nuclei, MongoDB, or LLM calls of any kind)
- git operations performed: NO (no git command of any kind was run)
- blocking decisions: B1 production AddressSource selection (blocks live traffic); B2 production ledger/store/audit/evidence adapters + sweep (blocks live/multi-worker)
- next implementation phase: 5E implementation per §23 (5E.1→5E.9), gated by B1+B2 runtime guards

REPORT:
 /opt/watch/agent-reports/http-executor-architecture.md
