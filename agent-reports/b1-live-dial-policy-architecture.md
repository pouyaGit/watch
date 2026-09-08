# Phase B1 — Live Dial Policy Architecture (READ-ONLY)

Status: ARCHITECTURE ONLY. No source file modified, no test created,
no Git command run, no network/DNS/browser/Nuclei/subprocess/LLM/
Mongo/traffic used or enabled. `LIVE_TRAFFIC_ENABLED` unchanged
(`False`). B1/B2/B4/B5 remain BLOCKED.

Grounded in: `agent-reports/end-to-end-security-pipeline-architecture.md`,
`agent-reports/end-to-end-hardening-implementation.md` (5K),
`agent-reports/p1-security-hardening-implementation.md` (P1),
`http-executor-implementation.md` (5E), `target-resolver-implementation.md`
(5C), `scope-evaluator-implementation.md` (5D),
`nuclei-executor-implementation.md` (5F),
`browser-xss-executor-implementation.md` (5G),
`evidence-core-implementation.md` (5H-core), plus read-only inspection of
`ai/execution/`, `ai/resolver/`, `ai/evidence/`,
`ai/verification/deterministic/`, `ai/finding/`, `ai/limits/`,
`ai/audit/` (incl. `ai/execution/ledger.py`).

## 1. Executive verdict

**ARCHITECTURE READY FOR IMPLEMENTATION** — and explicitly NOT ready
for activation. The design below is complete and implementable
without redesigning 5C/5D/5E: every seam B1 needs already exists
frozen (`DnsResolver` DI, `TargetResolution`/`DialBinding`,
`HopResolver`, `SocketFactory`, `TlsWrapper`, per-hop re-resolution,
`getpeername` peer check, closed environment allowlists). B1
implementation is additive production adapters + tests behind the
existing live gates. B1 itself stays BLOCKED until the §19
activation checklist passes in a later, separately authorized phase.

Core invariant (unchanged, now given a production proof):

```
SCOPE-EVALUATED == ACTUALLY-DIALED
```

for every live HTTP SYN and, by the same pattern, every future
live browser/Nuclei transport.

## 2. Current frozen security invariants

B1 inherits these verbatim; none is weakened (all citations are
read-only observations of frozen code/reports):

1. Authorization permission comes only from store provenance:
   `IssuedExecutionAuthorization` re-read fresh plus
   `require_live_for_execution`; dicts never coerce
   (`ai/evidence/handoff.py`, 5E lifecycle steps 2–5 in
   `ai/execution/http_executor.py` ordering §9 of the 5E report).
2. `AUTHZ_VALID_FOR_EXECUTION` (live permission, consumed via CAS)
   and `AUTHZ_VALID_FOR_PROVENANCE` (`ai/evidence/handoff.py:46`,
   consumed authorizations reused as evidence history only) are
   independent markers; 5I consumes provenance, never permission.
3. Exact-host scope only; label-aware single-level wildcards;
   exclusion absolute; no eTLD+1; no IP/CIDR authorization
   (compile refusal); dual address gating, ALL must pass (5D).
4. `LIVE_TRAFFIC_ENABLED = False`, `LIVE_NUCLEI = False`,
   `LIVE_BROWSER = False` — literals, single assignment each,
   test-pinned; `RealSocketFactory.connect` /
   `SystemTlsWrapper.wrap` / `LiveNucleiRunner` /
   `LiveBrowserRunner` raise blocked codes; 5E `_check_live_gate`
   (`ai/execution/http_executor.py:1437`) refuses both
   `LIVE_TRAFFIC_ENABLED == True` and any `RealSocketFactory`,
   including by class name.
5. Transport dials only the pinned IP literal from the current
   hop's `DialBinding`; hostname-taking dial is unrepresentable on
   `SocketFactory` (`ai/execution/http_executor.py:598`); peer
   verified via `getpeername()` with mismatch →
   `TRANSPORT_BINDING_FAILURE` (`:1682`).
6. No pooling/keep-alive/cookies/proxy-env/auto-redirects in 5E
   transport (HTTP/1.1 only, `Connection: close`); redirects are
   manual with fresh `HopResolver.resolve_hop` + fresh
   `DialBinding` per hop, 5-edge cap, no inheritance.
7. Evidence is triple-hashed (`bindings`/`observations`/`content`),
   single-builder, `verify_record` on every read; handoff carries
   hashes + `AUTHZ_VALID_FOR_PROVENANCE` only.
8. Ledger is AT-MOST-ONCE per `(authorization_id,
   execution_stage)` with CAS; post-start ambiguity →
   `OUTCOME_UNKNOWN`, retry only under new authorization
   (`ai/execution/ledger.py`).
9. 5J materializes CONFIRMED-only findings from genuine 5I
   classifications; legacy objects cannot cross (5K/P1).

## 3. B1 threat model

Each item: attack → frozen-or-B1 gate → fail-closed code. Unless
noted "B1-new", the gate already exists frozen and B1 wires it to
a production adapter.

1. DNS rebinding → resolve-once-per-hop + pin + `getpeername`
   equality → `TRANSPORT_BINDING_FAILURE`. B1-new: the production
   `AddressSource` must resolve INSIDE the boundary immediately
   before the SYN (§4); any second lookup path is a violation.
2. DNS answer changes between resolution and dial → hop-0 refresh
   rule (§5: only the post-claim, pre-SYN resolution authorizes the
   dial) + peer check → `STALE_RESOLUTION` (B1-new code, §16) /
   `TRANSPORT_BINDING_FAILURE`.
3. Resolver/transport disagreement → dial-coherence equality
   (`dial.addresses == resolution.resolved_addresses`, port, SNI,
   `pin_required`, 5E `:1364`, 5F `:1023`) → `DIAL_BINDING_MISMATCH`.
4. IPv4/IPv6 selection mismatch → deterministic numeric ordering
   from `validate_answers` + dial takes `addresses[0]`
   canonically; any deviation → `DIAL_BINDING_MISMATCH`. B1-new:
   production source MUST preserve the frozen order (no
   Happy-Eyeballs reordering, §6/§10).
5. Hostname resolving to multiple authorized/unauthorized addresses
   → mixed sets fail whole (`validate_answers`: no "first clean
   wins") → `DNS_UNSAFE_ADDRESS`; ceiling 8 else
   `DNS_TOO_MANY_ANSWERS`.
6. Redirects → manual loop, per-hop re-resolve + re-evaluate +
   fresh binding, no inheritance → `SCOPE_DRIFT` /
   `REDIRECT_NOT_IN_SCOPE` / `REDIRECT_LIMIT`.
7. HTTPS SNI vs dialed IP mismatch → `check_sni_binding`
   (SNI == canonical host, never IP) → `TRANSPORT_BINDING_FAILURE`.
8. HTTP Host header mismatch → Host generated from the single
   canonical-host variable (frozen triple SNI==Host==canonical) →
   construction-time impossibility; test `HostTests` guards it.
9. Proxy environment variables → closed process environment +
   transport takes no proxy parameter (5E direct-only) → any
   proxy-shaped env at boot → `PROXY_DETECTED` (B1-new, §8).
10. `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` → same as 9; the
    production launcher scrubs them before exec (§8).
11. `NO_PROXY` abuse → same as 9 (scrubbed; allowlist semantics of
    `NO_PROXY` are never consulted).
12. PAC / system proxy discovery → no PAC fetch code exists on the
    path; 5G browser env allowlist excludes PAC/DNS/proxy vars;
    production browser profile pins `no-proxy` + `--host-resolver-rules`
    equivalent under B5 review (§8).
13. Transparent/intercepting proxies → TLS hostname verification
    against canonical host with system CAs + no custom roots makes
    interception a hard failure → `TLS_FAILURE`; deployment on a
    intercepting network is UNSUPPORTED (§14).
14. Connection pooling/reuse → pooling structurally absent in 5E
    (one socket per hop, closed in `finally`); B1 forbids adding
    any pool (§10); reuse attempt → `CONNECTION_REUSE_VIOLATION`
    (B1-new code).
15. Redirect connection reuse → new connection per hop is the only
    constructible path (socket closed per hop) (§10).
16. HTTP/2 connection coalescing → H2 out of scope for v1 (frozen);
    B1 forbids H2/H3 transports until a coalescing-proof design is
    reviewed (§10).
17. HTTP/3 / QUIC → same as 16: unsupported transport, fail closed.
18. Happy Eyeballs → forbidden racing algorithm in v1: sequential
    dial of the frozen-ordered pin list with per-attempt timeouts;
    family racing would break item 4's proof (§10).
19. Automatic DNS performed by the HTTP library → no high-level
    client exists on the path (AST-banned: `socket`/`urllib3`/
    `httpx`/`requests`/`create_connection` absent from 5E); the
    only dial primitive takes IP literals (§7).
20. libc resolver behavior (search domains, `ndots`, mDNS, LLMNR)
    → production `AddressSource` MUST NOT use bare `getaddrinfo`
    with ambient `resolv.conf` semantics; §4 requires explicit
    resolver configuration with search lists disabled and a
    pinned resolver identity recorded.
21. IPv4-mapped IPv6 → unfolded and policed as inner IPv4 in
    `classify_address`; non-canonical dial text rejected by
    `require_ip_literal` → `DIAL_BINDING_MISMATCH`.
22. CNAME chains → followed ONLY by the pinned production
    resolver, each link classified, only terminal A/AAAA passing
    classification pinned; CNAME identity itself never
    authorizes (no alias inference, consistent with 5D's ban on
    CNAME inference) (§4).
23. Service discovery (SRV/TXT-driven host selection) → no SRV/TXT
    lookup exists on the path; target host comes only from the
    authorized canonical tuple (§4).
24. CDN/shared infrastructure → IP says nothing about authority:
    shared-IP dialing is safe ONLY because SNI/Host/cert pin to
    the canonical host AND scope evaluated that exact host; a CDN
    edge serving a different host fails TLS/scope, never grants
    authority (no CDN/ASN authorization, per constraints).
25. TLS certificate validation → system CA store, hostname
    verification against canonical host, TLS ≥ 1.2, no custom
    roots, no insecure mode (§9). Never disabled to "solve" scope.
26. TLS SNI → exact canonical host, never IP, single variable
    with Host (§9).
27. Redirects to IP literals → `REDIRECT_NOT_IN_SCOPE` (no-IP
    scope policy, frozen).
28. Redirects to different ports → port allowlist
    `{80, 443, initial-effective-port}` + fresh evaluation (§11).
29. Redirects across schemes → `https→http` always denied;
    `http→https` only for `http_probe` (§11).
30. Timeout/cancellation races → bounded timeouts (connect/read/
    wall/stall ceilings); non-idempotent post-send ambiguity →
    `OUTCOME_UNKNOWN` with no evidence bytes (frozen); socket
    closed in `finally` (§13).
31. Stale authorization snapshots → fresh store re-read +
    `scope_lists_hash` drift compare at entry AND per hop →
    `SCOPE_DRIFT` / `AUTHZ_NOT_LIVE` (§13).
32. Concurrent scope changes → per-hop policy re-read with pinned
    hash compare; mid-chain change stops the chain (§13).
33. Network interface changes → peer re-verified per SYN
    (`getpeername` per connection, never cached across hops);
    interface flap during exchange → transport error, fail
    closed, never a finding (§13).
34. Container/host routing differences → deployment allowlist in
    §14: only direct-egress topologies supported in v1; anything
    else is UNSUPPORTED until reviewed.
35. NAT → address-preserving NAT is transparent to the proof
    (peer IP as seen by the socket is what is checked); NAT that
    rewrites destination to a different peer fails the peer
    check by design; carrier-grade address sharing changes
    nothing about SNI/Host/cert binding (§14).
36. Transparent egress gateways → same posture as 13/35:
    anything that breaks peer equality or TLS verification fails
    closed; gatewayed deployments are UNSUPPORTED in v1 (§14).
37. SSRF through proxy or redirect behavior → proxy path
    structurally absent (no proxy parameter, env scrubbed,
    `Proxy-*` banned, `CONNECT` never emitted) + redirect
    re-evaluation per hop; SSRF-shaped redirect (IP literal,
    userinfo, non-http scheme, bad port) → closed redirect
    codes (§8, §11).

## 4. Production AddressSource design (A)

Single authoritative source: a B1-new `ProductionAddressSource`
implementing the frozen `DnsResolver` protocol
(`ai/resolver/dns.py:103`) — the ONLY resolver the production
`HopResolver` may call. Specification:

- Where resolution happens: inside the security boundary, in the
  executor host process, at transport time per hop (never
  pre-computed, never cached across hops, never in a sidecar the
  executor cannot authenticate).
- Raw answers accepted then classified: the adapter returns RAW
  answer strings; `validate_answers` (ceiling 8, no truncation,
  whole-set failure, deterministic numeric order) stays the
  single acceptance gate — unchanged frozen code.
- Address filtering: `classify_address` unchanged (global unicast
  only; mapped unfolded; zoned denied; metadata/denied tokens
  denied pre-resolution).
- IPv4/IPv6 policy: both families permitted; order frozen
  (version, numeric); NO family racing/pinning override; dial
  takes `addresses[0]` (5E `:1644`); policy change requires a
  versioned `RESOLVER_VERSION` bump (new finding ids, §12 of the
  architecture review's replay table).
- TTL handling: NO cross-hop caching in v1 (fresh resolve per
  hop; redirect chain already re-resolves). TTL is recorded as
  observation metadata only if the resolver exposes it; it NEVER
  extends authority lifetime. Minimum-TTL or cache designs are
  explicitly out of v1.
- Freshness: resolution must occur AFTER the ledger claim +
  authorization CAS consume for that execution (post-claim,
  pre-SYN). The authorization-time pin is provenance, not
  permission for the dial wire (§5).
- CNAMEs: not authoritative, never scope-matched, never pinned
  as identity. The pinned resolver may follow CNAMEs internally
  ONLY to terminal A/AAAA; every link is logged as observation;
  only classified terminal addresses enter `resolved_addresses`.
  CNAME-chain length ceiling: 8 (mirrors `dns_answers`); over
  → `DNS_TOO_MANY_ANSWERS`.
- Resolver implementation (v1, concrete): explicit DNS stub to
  operator-configured resolver IP literals (no `resolv.conf`
  search domains, no `ndots` heuristics, no mDNS/LLMNR/NSS
  plugins), TCP-capable, 10 s timeout (frozen
  `connect_timeout_seconds` family), single attempt per hop
  (retries would smear freshness; transient failure is a
  fail-closed `DNS_TIMEOUT`, retried only under a NEW
  authorization per the ledger rule).
- Resolver identity/version captured per resolution:
  `{resolver_name, resolver_version, resolver_config_hash,
  transport (udp/tcp), server_ips, resolved_at, ttl_seen}` —
  hashed into `resolution_id` basis via a bumped
  `RESOLVER_VERSION` (e.g. `target-resolver/v1` stays the
  schema; the resolver NAME+VERSION string is what changes,
  e.g. `prod-dns-stub/v1`), so a resolver change forks finding
  identity instead of silently reinterpreting history.

## 5. TargetResolution → DialBinding design (B)

No frozen shape changes. Production binding chain (all
equality-checked, first mismatch wins, all fail closed):

1. Production wiring calls `HopResolver.resolve_hop` for hop 0
   (the initial URL) immediately pre-execution — the same
   interface redirect hops use — yielding a fresh
   `(TargetResolution, ScopeEvaluation)` pair bound to the live
   authorization + current policy. The authorization-time 5C
   record remains provenance; it MUST NOT be substituted as the
   dial-time pair (it predates the ledger claim).
2. Executor `_check_binding` (frozen): authz/execution/
   resolution id triple across all four records.
3. Dial-coherence equality (frozen, 5E `:1364`, mirrored 5F
   `:1023` and every redirect hop `:1986`):
   `dial.addresses == resolution.resolved_addresses` AND
   `dial.effective_port == resolution.effective_port` AND
   `dial.sni_host == resolution.canonical_host` AND
   `pin_required is True`.
4. Per-hop redirect: fresh `resolve_hop` → fresh pair → same
   checks; never reuse a prior binding for a new host/IP
   (frozen `test_no_previous_hop_inheritance`).

Immutable bound fields (union, all hashed into identity downstream):
`authorization_id`, `execution_id`, `resolution_id`,
`evaluation_id`, `program_name`, `canonical_host`, `scheme`,
`effective_port`, `resolved_addresses` (ordered pin list),
`scope_lists_hash` (authorized + current), `resolver
name/version`, `dial` (addresses/port/sni/pin).

It is structurally impossible for a caller to replace hostname,
IP, port, or scheme between authorization and dial: callers
supply no address-typed input anywhere on the path (frozen
`BoundedHttpRequest` has no raw-authority field; `SocketFactory`
takes IP literals; SNI/Host derive from one canonical variable;
`require_allowed()` re-checks the triple at each hop).

## 6. Actual socket dial mechanism (J)

Frozen 5E mechanism, adopted verbatim for B1 production with live
adapters substituted behind the same Protocols:

1. `dial_ip = require_ip_literal(dial.addresses[0])`
   (canonical-text enforcement) + membership in the pinned set
   + port/SNI equality (`:1642`).
2. `_check_live_gate()` — B1 implementation REPLACES this gate
   under the activation review (the only frozen-code touch, §21):
   allow only the reviewed live factory + reviewed TLS wrapper.
3. `socket_factory.connect(dial_ip, port, 10 s)` — live adapter:
   `socket.socket(family_for(dial_ip))` with NO `getaddrinfo`
   call (family derived from the already-classified literal),
   `settimeout(connect)`, `connect((dial_ip, port))`. Any
   hostname-shaped input is unrepresentable (type + runtime
   reject).
4. TLS (https): `check_sni_binding` then `tls_wrapper.wrap`
   (live adapter: `ssl.create_default_context()` system store,
   `minimum_version=TLSv1_2`, `check_hostname=True`,
   `server_hostname=canonical_host` — SNI + verification bound
   to the hostname, never the literal).
5. `peer = sock.getpeername()`; `peer[0] != dial_ip` →
   `TRANSPORT_BINDING_FAILURE` (no log-only mode).
6. Single bounded HTTP/1.1 exchange; socket closed in `finally`;
   never returned to any pool.

Trust boundary: everything up to and including the
`SocketFactory`/`TlsWrapper` Protocol signatures is trusted
frozen code; the live adapter implementations (raw `socket` +
`ssl` calls) are B1-new, review-gated, and confined to
`ai/execution/live_transport.py` (proposed, §21) — no other
module may import `socket`/`ssl`.

5F/5G follow the same pattern under their own blockers: 5F
subprocess argv/env allowlists stay frozen with a
`dial-coherence` pre-check before spawn (already at `:1023`);
binary-initiated DNS/redirects CANNOT satisfy the pin proof,
so live Nuclei additionally requires the B3 sandbox/egress
forcing design (namespace + literal-IP-only DNS stub +
egress firewall) — B1 covers HTTP only. 5G live browser
requires B5 containment (netns + forced egress proxy +
literal-IP-only DNS stub + pinned build); the closed
`BrowserExecutionSpec` (no proxy/DNS/env/callback fields) and
closed environment allowlist (no proxy/PAC/DNS vars,
`browser_executor.py:762`) are the frozen anchors B5 builds on.

## 7. No-implicit-DNS design (C)

- No high-level HTTP client on the path (frozen AST ban:
  `socket/urllib3/httpx/requests/aiohttp/create_connection`
  absent from 5E; same ban required for any B1-new module).
- The sole dial primitive (`SocketFactory.connect`) accepts IP
  literals only and raises on hostnames; family is derived from
  the literal, never resolved.
- The production `AddressSource` is the only code permitted to
  parse DNS wire format; it exposes answers, never a
  "connect-to-host" helper.
- B1 implementation tests must include a resolver-silence proof:
  live-path execution against a fixture that fails ANY
  unexpected egress DNS (deny-all DNS firewall in test) while
  the pinned stub serves scripted answers — any hidden lookup
  fails the test deterministically.
- libc surface: production process runs with `RES_OPTIONS`
  equivalent of `ndots:1 no-search` discipline via explicit stub
  config (no search domains), and B1 tests assert the stub
  config contains no search/name-server entries beyond the
  operator-pinned literals.

## 8. Proxy policy (D)

v1: proxies DISABLED entirely (adopts frozen 5E §11 decision).

- Transport constructor takes no proxy parameter; `Proxy-*`
  request headers banned at translation; `CONNECT` never
  emitted; response `Proxy-Authenticate` not allowlisted.
- Launcher MUST scrub `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/
  NO_PROXY/http_proxy/...` (both cases), plus `PAC`-shaped
  (`*_PAC`, `WPAD`) variables, from the executor process
  environment before exec; any proxy-shaped variable present
  at executor boot → `PROXY_DETECTED`, fail closed (B1-new
  check, §16). Scrub list is closed and versioned.
- Library defaults: no library on the path honors proxy env
  (raw `socket` + `ssl` only); 5G browser profile pins
  no-proxy under B5 review; 5F subprocess env stays on the
  frozen `(PATH, HOME, LANG, TMPDIR)`-family allowlist.
- Defense-in-depth egress proxy (documented in 5E §11 / 5F B3 /
  5G B5 designs) is explicitly DEFERRED, never a v1
  requirement, and if ever added must: resolve nothing itself,
  accept literal-IP destinations only, carry no credentials,
  and record the proxy path in evidence — it may only NARROW,
  never substitute, the dial proof.

## 9. TLS policy (E)

Frozen 5E contract, adopted as B1 production normative:

- SNI = canonical hostname exactly (`check_sni_binding`;
  IP SNI rejected); Host header from the same variable.
- Certificate validation: system CA store, `check_hostname=True`
  against the canonical host, TLS ≥ 1.2, no custom trust roots,
  no insecure mode, no IP-as-hostname verification.
- Minimum TLS version 1.2 at context construction; 1.3
  preferred where negotiated (no version pinning that would
  ossify).
- IP-literal targets: unreachable by policy (scope denies IP
  candidates; redirect-to-IP denied), so no IP-cert exception
  path exists. If scope ever grants an IP form, a separate
  review is required — B1 v1 has no such path.
- OCSP/CRL/AIA fetching is a known B5-gated side channel for
  browsers (per the 5G architecture report §13): for HTTP v1,
  soft-fail stapling semantics of the system verifier are
  accepted; hard-fail OCSP or custom responders are out of v1
  (no new network paths invented).
- Scope safety is NEVER achieved by touching verification:
  any `CERT_REQUIRED`-shaped bypass is a fail-closed
  `TLS_FAILURE`, never a finding.

## 10. Connection reuse policy (F)

v1: NO pooling, NO keep-alive, NO reuse — one fresh connection
per hop, closed in `finally` (frozen 5E shape). Rationale: reuse
destroys the per-SYN proof (`AUTHORIZED_IP ==
ACTUALLY_DIALED_IP` must be re-established at every SYN; a
pooled socket's peer was proven, if at all, under an older
binding). Consequences, all frozen or B1-required:

- HTTP/2: unsupported transport in v1. Coalescing (cross-origin
  connection reuse on one cert) is fundamentally incompatible
  with per-hop dial proof; any H2 design must prove
  per-origin pin isolation + per-stream binding and is out of
  v1 scope.
- HTTP/3/QUIC: unsupported (UDP, connection migration breaks
  peer stability assumptions outright).
- Happy Eyeballs (v4/v6 racing): forbidden in v1; sequential
  dial of the frozen-ordered pin list only.
- Any future pool requires: pool key = full binding hash,
  peer re-verified on checkout, eviction on any policy/resolver
  version change — documented here as the bar, not built.

## 11. Redirect architecture (G)

Frozen 5D + 5E contract; B1 adds only the production resolver
behind the existing `HopResolver` interface:

- `Location` parsed strictly (single value, ≤2048, no
  userinfo/controls/backslash/non-http(s)/encoded-authority/
  secret-shaped query) → `urljoin` → 5C canonicalization →
  scheme gate (downgrade never; upgrade only `http_probe`) →
  canonical-URL visited set (loop detection, deterministic) →
  fresh `resolve_hop` (re-resolution + fresh evaluation +
  `require_allowed` triple) → scope-drift compare → port
  allowlist → fresh `DialBinding` + address re-classification
  → new connection, never a resumed one.
- Max 5 edges (frozen `redirect_hops`); 6th → `REDIRECT_LIMIT`;
  body crosses hops only on 307/308 to the same exact host.
- IP-literal destinations → `REDIRECT_NOT_IN_SCOPE`, always.

## 12. Actual-dial proof model (H)

Not logs. A typed, hash-bound per-hop proof assembled by the
transport and sealed into 5H evidence. Frozen carriers already
exist; B1 extends (not redesigns) them:

- Per hop, the transport already binds (`HopRecord`,
  `ai/execution/http_executor.py:1235`): `execution_id`,
  `authorization_id`, `resolution_id`, `evaluation_id`,
  `program_name`, `canonical_host`, `scheme`, `effective_port`,
  `dialed_ip`, `sni_host`, `method`, `artifact_id`,
  `canonical_url`, `request_fingerprint =
  sha256(canonical_url, method, body_hash, dialed_ip)`.
- B1-required extension (additive fields on a versioned
  observation shape — any schema change is additive-only with a
  version bump; 5H semantics untouched): `actual_peer_ip`
  (from `getpeername`), `local_sockaddr`, `selected_address`
  (the pin consumed), `pin_list_hash` (hash of the ordered
  `resolved_addresses` actually pinned), `resolver_name`,
  `resolver_version`, `dial_binding_hash`,
  `target_resolution_hash` (= `canonical_target_hash` +
  `resolution_id`), `scope_evaluation_hash` (= `evaluation_id`),
  `tls_sni`, `tls_version_negotiated`, `tls_peer_cert_hash`
  (fingerprint, not content), `redirect_hop_index`,
  `connection_id` (per-SYN unique, e.g. `conn-` + 128-bit
  random; uniqueness only, never identity).
- The proof rule, checked at seal time (B1-new assertion in the
  production composition layer, re-verified by 5I's binding
  gate and 5J's fresh-read binding): `actual_peer_ip ==
  selected_address ∈ pinned ordered set` AND
  `dial_binding_hash` reproduces from the hop's
  `(resolution_id, evaluation_id, pin_list)` AND all three ids
  match the sealed record's bindings. Any inequality → no
  seal (pre-seal) or `PERSISTED_UNVERIFIABLE`-family handling
  (post-seal), never a finding.
- `HttpObservation.dial_ips` (ordered per-hop dialed
  addresses, frozen) plus the new `actual_peer_ip` per hop
  give 5I/5J a byte-comparable evaluated==dialed proof inside
  the already-frozen hash discipline (no second evidence
  authority; §15).

## 13. Race/failure handling (I)

Default FAIL-CLOSED everywhere; no failure state is a verdict,
a negative, or a finding (frozen 5E/5I/5J posture preserved):

- DNS changes after authorization → only the post-claim
  resolution authorizes (§5); mismatch with the
  authorization-time pin → `STALE_RESOLUTION`, abort before
  SYN. No retry under the same authorization (ledger
  AT-MOST-ONCE); retry requires fresh issuance.
- Scope changes after authorization → entry + per-hop
  `scope_lists_hash` compare → `SCOPE_DRIFT`, abort; mid-chain
  change stops the chain (frozen).
- Connection attempt races timeout → connect 10 s / read 10 s /
  wall 60 s / stall 10 s (frozen ceilings); timeout maps to
  closed `TRANSPORT_TIMEOUT`; non-idempotent post-send
  ambiguity → `OUTCOME_UNKNOWN` with no evidence bytes (frozen).
- Cancellation during connect → socket closed in `finally`;
  outcome `TRANSPORT_FAILURE`/`OUTCOME_UNKNOWN` per bytes-on-wire
  accounting; ledger terminal mark follows the frozen crash
  table (post-start ambiguity → UNKNOWN, never resume).
- Address becomes unsafe (re-classification at dial) →
  `UNSAFE_ADDRESS` abort before SYN (frozen re-check at 5E
  `:1381` pattern).
- Resolver returns unexpected address (not in pin set / over
  ceiling / malformed) → `DIAL_BINDING_MISMATCH` /
  `DNS_TOO_MANY_ANSWERS` / `DNS_MALFORMED_ANSWER`; whole-set
  failure, never subset dialing.
- Interface flap mid-exchange → transport error → fail closed;
  no evidence claims beyond bytes actually framed.

## 14. Network topology assumptions (K)

B1 v1 SUPPORTED: single-homed host or container with direct
egress, no intercepting middlebox, system CA bundle intact,
operator-controlled DNS stub reachable, stable interface
addresses for the execution window. Address-preserving NAT
(explicitly: destination-preserving) is transparent and
supported — the proof checks the socket peer, which NAT does
not alter from the initiator's view.

B1 v1 explicitly UNSUPPORTED (deployment MUST NOT run live
traffic here; executor boot asserts direct-egress markers and
refuses otherwise): corporate TLS-intercepting proxies,
transparent egress gateways that alter destination/TLS,
carrier-grade NAT with destination rewriting, VPNs that split
or rewrite egress asymmetrically, reverse-proxy-fronted
"origins" where the dialed peer is not the evaluated host's
address, multi-homed policy-routing hosts where the egress
interface (and thus visible peer path) is nondeterministic.
Container networking is supported ONLY in the direct-egress
form (bridge NAT preserving destination); host-network and
service-mesh sidecar injection are unsupported pending review.

## 15. 5H evidence integration (L)

No second evidence authority; no 5H semantic change. Mapping:

- `HttpObservation.dial_ips` + `redirect_chain` (frozen) carry
  the dialed pins; the B1 additive per-hop fields (§12) ride
  the same observation shape under a bumped observation
  schema version (additive-only; old pins fail closed per the
  frozen version-skew rule).
- `SnapshotBinding` (`snapshot_ref`, `scope_lists_hash`) +
  `DerivationBinding` + target tuple already bind program/
  target/artifact/plan/authorization lineage; the dial proof
  fields enter `observations_hash` input, so any dial fact
  change forks evidence identity and downstream finding ids
  (replay table holds: same inputs → same id; pin change →
  distinct id).
- Seal-time proof assertion (§12) runs before
  `EvidenceBuilder.seal`; `verify_record` on every read
  re-verifies the triple as today. `EvidenceHandoff` stays
  hashes-only; 5I's gate + 5J's fresh-read binding re-check
  the ids without new trust.
- Audit: `EXECUTION_STAGE` records carry the dial proof
  hashes (codes + hashes only, per the audit contract); audit
  never authorizes.

## 16. Failure-state taxonomy (M)

Closed vocabulary (B1-new codes marked ★; rest frozen):

- `DNS_NXDOMAIN`, `DNS_SERVFAIL`, `DNS_TIMEOUT`,
  `DNS_UNSAFE_ADDRESS`, `DNS_TOO_MANY_ANSWERS`,
  `DNS_RESOLUTION_FAILED`, `DNS_MALFORMED_ANSWER` (frozen 5C).
- `TRANSLATION_REJECTED`, `DIAL_BINDING_MISMATCH`,
  `UNSAFE_ADDRESS`, `TRANSPORT_FAILURE`, `TRANSPORT_TIMEOUT`,
  `TRANSPORT_BINDING_FAILURE`, `TLS_FAILURE`,
  `REDIRECT_INVALID`, `REDIRECT_LIMIT`,
  `REDIRECT_NOT_IN_SCOPE`, `SCOPE_DRIFT`, `OUTCOME_UNKNOWN`,
  `LIVE_GATE_BLOCKED`, `AUTHZ_NOT_LIVE` (frozen 5E/5D/5B).
- ★ `STALE_RESOLUTION` — post-claim resolution disagrees
  with the authorization-time pin.
- ★ `DIAL_MISMATCH` — reserved alias when the failure is
  specifically selected-address vs SYN-target divergence
  (today folded into `DIAL_BINDING_MISMATCH`; split only if
  operations need the distinction — default: keep folded).
- ★ `PROXY_DETECTED` — proxy-shaped environment or
  constructor parameter present at boot/launch.
- ★ `TLS_MISMATCH` — SNI/cert/hostname divergence beyond the
  frozen binding check (e.g. negotiated peer cert identity
  vs canonical host at the live adapter layer).
- ★ `CONNECTION_REUSE_VIOLATION` — any attempt to serve a hop
  from a non-fresh socket.
- ★ `UNEXPECTED_SOCKET_PEER` — `getpeername` unavailable or
  non-IP-shaped (finer split of `TRANSPORT_BINDING_FAILURE`
  reserved; default folded).
- ★ `MISSING_PROOF` — seal-time assertion cannot reproduce
  the §12 proof (fields absent or hash mismatch).

All are terminal-no-finding states (INCOMPLETE evidence at
most, never CONFIRMED-adjacent, never a negative verdict).

## 17. Trust-boundary diagram (N, text)

```
UNTRUSTED                        │ attacker-controlled: LLM text,
(external sources, LLM output,    │ pages, stdout, headers, titles,
 page content, Nuclei stdout)     │ DNS answers (until classified)
         │ parse + schema-validate│
         ▼                        │
RESEARCH (facts only)             │ trust: NONE (validated containers)
         │ project/match/propose  │
         ▼                        │
PROPOSAL (Hypothesis/TestPlan)    │ trust: NONE (type-rejects verdicts)
         │ issuance (human/board) │ ← 5B owns: permission ONLY
         ▼                        │
AUTHORIZATION (5B permission)     │ trust: RISES (store provenance;
                                  │ dicts never coerced; nonce/TTL/CAS)
         │ resolve (pinned stub)  │ ← 5C owns: canonical identity +
                                  │   classified pin list (DialBinding
                                  │   shape; enforcement downstream)
         ▼                        │
SCOPE (5D evaluation)             │ 5D owns: ALLOWED/DENY/INCONCLUSIVE
                                  │ on (program, canonical host,
                                  │ addresses, policy hash)
         │ bind (triple + pin)    │ ← executor owns (frozen 5E checks):
                                  │   id-triple + dial-coherence +
                                  │   per-hop require_allowed
         ▼                        │
DIAL BINDING (per-hop, fresh)     │ B1 owns: post-claim freshness,
                                  │ pin order, no-substitution proof
         │ SYN to literal IP      │ ← live transport owns (B1-new
         ▼                        │   adapter): literal-only dial,
TRANSPORT (bounded exchange)      │ SNI/Host/cert binding, peer
                                  │ check, fresh socket per hop
         │ seal (triple hash)     │ ← 5H owns: tamper-evident record;
         ▼                        │   seal-time proof assertion
EVIDENCE (immutable record)       │ trust: RISES (single builder)
         │ handoff + provenance   │
         ▼                        │
VERIFICATION (5I classification)  │ trust: PEAK (only CONFIRMED/
                                  │ severity authority; provenance
                                  │ input only, never permission)
         │ eligibility + revalid. │
         ▼                        │
FINDING (5J sealed materialize)   │ trust: DERIVED (CONFIRMED-only,
                                  │ equality-bound, nothing else)
```

Component→invariant ownership: 5B permission; 5C identity +
pin shape; 5D scope permission; executor (frozen checks)
binding enforcement; B1 adapters freshness + literal dial +
peer proof; 5H tamper-evidence; 5I classification; 5J
materialization. Audit/ledger own accounting, never authority.

## 18. Legacy bypass audit

Read-only re-verification for B1 (no file modified):

- `ai/verification/http_executor.py` (`requests.Session`,
  env-proxy trust, cookie jar, auto-redirects),
  `browser_executor.py` (playwright, ambient env),
  `composite_executor.py` (dispatcher into both),
  `verifier.py` (execute-and-judge), `xss_pipeline.py`
  (live composition), `watch_xss_verify.py` (Mongo
  persistence driver): all carry P1 `LEGACY_NON_PRODUCTION`
  markers; the sole production driver (`main`) exits 2
  without executing (5K, re-proven by P1 tests); the task
  registry cannot address them (import-time + runtime
  confinement, P1); no `backend/`/`api.py`/registry-script
  imports them (P1 AST tests). They cannot bypass B1 because
  they cannot run in production at all.
- `ai/researcher/nuclei_runner.py` (`run(execute=True)`
  subprocess + binary-owned network stack): research-only
  markers (P1); no production caller; binary-initiated DNS
  is precisely why live Nuclei additionally requires the B3
  sandbox/egress forcing design — B1 does not cover it.
- Frozen executors (`ai/execution/*`) cannot fall back to
  legacy: 5E `test_legacy_executor_not_imported` plus the live
  gates. B1 implementation must preserve these tripwires.
- Residual risk (accepted, documented): the legacy modules
  remain importable for offline tests. Deletion is NOT
  recommended in B1 (test churn without security gain);
  execution-reachability, not existence, is the controlled
  property, and it is test-gated (5K + P1 suites).

## 19. B1 activation checklist (O)

All must pass, in order, before `LIVE_TRAFFIC_ENABLED` may ever
become `True` (each item independently fail-closed; the flag
flip itself is a separately authorized act, not part of B1
implementation):

1. Production `AddressSource` selected: pinned stub, operator
   resolver literals, no search domains, TCP-capable, versioned
   name recorded; resolver review signed.
2. Deployment topology reviewed against §14 allowlist
   (direct-egress only); unsupported environments attested
   absent; boot-time topology assertion implemented.
3. Proxy behavior proven: env scrub + `PROXY_DETECTED` tests;
   no proxy parameter on any constructor; browser profile
   no-proxy (B5-tracked for 5G paths, HTTP v1 independent).
4. Live `SocketFactory`/`TlsWrapper` adapters reviewed (raw
   `socket`+`ssl` confined to one new module; no other module
   imports `socket`/`ssl` — AST test).
5. Dial-binding integration tested: coherence equalities,
   hop-0 refresh rule, per-hop re-resolution (105-test 5E
   matrix green against live adapters in a fixture network).
6. Actual-dial proof tested: §12 fields present, seal-time
   assertion green, mismatch cases produce closed codes.
7. Failure injection tested: every §16 code reachable in tests
   (DNS flap, rebinding fixture, peer-spoofing fake, proxy-env
   presence, TLS mismatch fake, reuse attempt, missing proof).
8. Evidence handoff tested: sealed live records verify,
   hand off, classify, and materialize through the frozen
   5H→5I→5J path in a fixture network.
9. Concurrency/race tests: parallel executions under distinct
   authorizations (no pin cross-talk), scope change mid-chain,
   timeout/cancel during connect, ledger CAS contention
   (in-memory; cross-process CAS is B2-gated for production).
10. Offline regression suite green (frozen 5B–5J + 5K + P1 +
    B1-new tests; the `LIVE_*` single-assignment tripwires
    updated explicitly and only as part of this review).
11. Explicit activation flag remains `False` until items 1–10
    are signed; the flip commit references this checklist.

## 20. Unresolved risks

1. Cross-process ledger CAS needs the B2 production adapter
   (unique index + atomic compare-and-swap); until B2, live
   traffic must be single-process (documented constraint, not
   a B1 design gap).
2. OCSP/AIA side channels for HTTP are accepted as
   system-verifier soft-fail (no new paths); strict PKI
   environments may need an explicit allowlist review at
   activation.
3. Resolver software itself (the pinned stub's DNS parser) is
   trusted code selected at implementation time; §19 item 1
   requires its review, but parser bugs are outside what this
   architecture can prove — defense is classification +
   ceiling + pin-order + peer check, all resolver-agnostic.
4. Time source for `resolved_at`/freshness is the operator
   clock; clock skew cannot grant authority (freshness is
   relative to the ledger claim in the same process, not
   absolute wall time).
5. 5F/5G live transports are NOT covered by B1 (B3/B4/B5 own
   their containment); B1 must not be cited as authorization
   for browser/Nuclei traffic.

## 21. Exact files that WOULD be modified in implementation

Frozen contracts modified: NONE (schemas, 5H, 5I, 5J, 5C/5D
logic, `BoundedHttpRequest`, observation shapes except by
additive versioned extension — none required for v1 proof
fields if carried as specified in §12/§15).

Would be CREATED (B1 implementation phase, not this report):

- `ai/execution/production_address_source.py` — pinned stub
  implementing `DnsResolver` (§4).
- `ai/execution/live_transport.py` — live `SocketFactory` +
  live `TlsWrapper` adapters (the ONLY module importing
  `socket`/`ssl`).
- `ai/execution/production_hop_resolver.py` — `HopResolver`
  backed by the production source + frozen 5C/5D calls,
  enforcing the hop-0 refresh rule (§5).
- `ai/execution/dial_proof.py` — §12 proof assembly + seal-time
  assertion helpers (pure; reused by tests).
- `ai/execution/egress_guard.py` — env scrub + `PROXY_DETECTED`
  + topology boot assertion (§8, §14).
- Deploy/runbook note (docs, not code): resolver literals,
  topology allowlist attestation, activation checklist sign-off.

Would be MODIFIED (gated by §19, each a reviewed one-line-class
change with tripwire-test updates):

- `ai/execution/http_executor.py` — `_check_live_gate` updated
  to admit ONLY the reviewed live factory/wrapper pair.
- `LIVE_TRAFFIC_ENABLED = False → True` in 5E only (5F/5G flags
  stay `False`; their tripwire tests updated explicitly).
- Corresponding `LIVE_*` single-assignment tripwire tests
  (`test_http_pinned_executor.py` gate tests) updated as part
  of the review, never silently.

## 22. Exact tests that WOULD be added

`ai/test_b1_dial_policy.py` (offline + fixture-network only;
no Internet, no production data), at minimum:

- AddressSource conformance: order preservation, ceiling,
  whole-set failure, mapped unfolding, CNAME-link logging,
  resolver identity/version capture, search-domain absence.
- Hop-0 refresh: stale authorization-time pin + changed fixture
  DNS → `STALE_RESOLUTION`, no SYN.
- Rebinding fixture: answer changes between resolve and SYN →
  abort, closed code, no evidence bytes beyond the failure.
- Peer-spoofing fake (`getpeername` ≠ dial IP) →
  `TRANSPORT_BINDING_FAILURE`.
- Proxy-env presence (each variable, both cases) →
  `PROXY_DETECTED` at boot; scrub proof (env seen by transport
  contains no proxy keys).
- TLS mismatch fakes (wrong SNI capture, cert-for-other-host)
  → `TLS_FAILURE`/`TLS_MISMATCH`.
- Reuse attempt (same socket object across hops) →
  `CONNECTION_REUSE_VIOLATION`.
- Missing-proof (drop a §12 field) → `MISSING_PROOF`, no seal.
- Resolver-silence: deny-all DNS firewall + scripted stub —
  full execution completes, proving no hidden lookup.
- Concurrency: parallel executions, mid-chain scope change,
  cancel-during-connect, ledger contention.
- End-to-end fixture-network: live adapters → seal → handoff
  → 5I → 5J with all ids bound (uses only the frozen path).

## 23. Explicit statements

- Architecture only: YES — this document designs, it does not
  build. B1 remains BLOCKED.
- No source files modified: YES — zero files created, edited,
  renamed, or deleted outside this report.
- No tests created: YES — no test file created or modified.
- No network used: YES — no connection, DNS query, or traffic
  of any kind was made; all claims derive from read-only
  inspection of frozen code and reports.
- No live traffic: YES — `LIVE_TRAFFIC_ENABLED` untouched
  (`False`); no execution performed.
- No MongoDB: YES — no client, query, or write; database files
  were not inspected beyond prior reports.
- No Git commands: YES — no Git invocation of any kind was run
  in this phase.

Final verdict: **ARCHITECTURE READY FOR IMPLEMENTATION**
(activation expressly NOT authorized; B1 stays BLOCKED pending §19).
