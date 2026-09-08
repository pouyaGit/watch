# Phase B1 — Live Dial Policy Implementation Report

## 1. VERDICT

**PASS — IMPLEMENTATION COMPLETE / LIVE DISABLED**

The B1 production live-dial policy is implemented exactly as specified
by `agent-reports/b1-live-dial-policy-architecture.md`, with production
activation FALSE. **B1 live traffic remains disabled.**
(`LIVE_TRAFFIC_ENABLED` is literally `False`; `LIVE_NUCLEI` and
`LIVE_BROWSER` are literally `False`.)

Core invariant holds by construction for every hop:

```
SCOPE-EVALUATED == ACTUALLY-DIALED
```

authorized canonical host + fresh target resolution + fresh scope
evaluation + immutable DialBinding + pinned IP-literal socket dial +
getpeername() verification + TLS SNI/Host binding + sealed evidence
proof form one unbroken, fail-closed chain. No live dial can occur:
the executor live gate admits the reviewed pair only when the flag is
`True`, and the flag is `False`.

## 2. Exact files created

1. `ai/execution/production_address_source.py` (400 lines)
2. `ai/execution/live_transport.py` (382 lines)
3. `ai/execution/production_hop_resolver.py` (554 lines)
4. `ai/execution/dial_proof.py` (434 lines)
5. `ai/execution/egress_guard.py` (155 lines)
6. `ai/test_b1_dial_policy.py` (1850 lines)
7. `agent-reports/b1-live-dial-policy-implementation.md` (this report)

## 3. Exact files modified

- `ai/execution/http_executor.py` — **only** `_check_live_gate` plus
  one private helper `_is_reviewed_b1_live_pair` (exact-type admission
  seam; activation still blocked). No other line touched. Frozen
  contracts, schemas, 5H/5I/5J logic, ceilings, and all other modules
  are byte-identical.

## 4. ProductionAddressSource implementation

`ai/execution/production_address_source.py` — `ProductionAddressSource`
implements the frozen `DnsResolver` protocol (`resolve()` body):

- Operator-pinned `server_ips` (IP literals only, distinct, immutable
  tuple); no ambient discovery, no search domains (exact canonical host
  only — non-canonical input is `DNS_MALFORMED_ANSWER` with zero
  exchange), no ndots/mDNS/LLMNR/NSS, no per-call resolver override
  (signature is `(self, canonical_host)` — AST-asserted).
- Identity/version explicit and immutable: `prod-dns-stub/v1`, config
  hash over (name, version, servers, transport), recorded per
  resolution in `ProductionAnswerInfo`.
- Wire layer is pure (`build_dns_query` / `parse_dns_response`); I/O is
  delegated to the injected `exchange` callable (production wiring:
  `live_transport.dns_tcp_exchange`). `exchange=None` fails closed —
  ambient DNS is never attempted. No `socket`/`ssl` import
  (AST-asserted). Single attempt per hop against the first server; no
  retries, no failover, no cross-hop cache.
- Answers flow exclusively through frozen `validate_answers` (ceiling
  8, whole-set failure, deterministic numeric order). No second
  address-authority implementation; no duplicated 5C logic.
- CNAMEs followed internally only to terminal A/AAAA; chain bounded at
  8; CNAME identity never authorizes (logged in `cname_chain`,
  CNAME-only packets fail closed); SRV/TXT/other types ignored by
  construction in the parser.

## 5. Live transport implementation

`ai/execution/live_transport.py` — the ONLY B1-new module importing
`socket`/`ssl` (AST-asserted across all five new modules):

- `LiveSocketFactory.connect(ip_literal, port, timeout)`: literal-only
  gate (hostname/URL/CIDR/empty rejected as `DIAL_BINDING_MISMATCH`),
  family derived from the literal (no `getaddrinfo`, no implicit DNS),
  bounded timeout, exactly one fresh `SOCK_STREAM` per call, unique
  per-SYN `connection_id` (`conn-` + 128-bit random). No pooling,
  no keep-alive, no reuse, no HTTP/2/3/QUIC/Happy-Eyeballs, no proxy
  (no env reads, no proxy parameters).
- `LiveTlsWrapper.wrap(raw_sock, sni_host, timeout)`: system CA store,
  `CERT_REQUIRED`, `check_hostname=True`, minimum TLS 1.2, SNI shape
  pre-checked (IP-as-SNI → `TLS_MISMATCH` before any I/O), no custom
  CA, no insecure mode. Sockets are consumed at wrap entry: a second
  wrap is `CONNECTION_REUSE_VIOLATION` even after a failed handshake.
- `verify_socket_peer(sock, expected_ip)`: `getpeername()` normalized
  and compared to the selected authorized IP; mismatch →
  `TRANSPORT_BINDING_FAILURE`, unavailable/non-IP peer →
  `UNEXPECTED_SOCKET_PEER`. Plus `tls_version_of`,
  `peer_cert_hash_of` (SHA-256 fingerprint, never content),
  `close_quietly`, and `dns_tcp_exchange` (single-attempt
  length-prefixed TCP DNS for the address source).

## 6. HopResolver integration

`ai/execution/production_hop_resolver.py` — `ProductionHopResolver`
implements the frozen `HopResolver` protocol body (plus one optional
`authz_time_addresses` provenance kwarg; no IP/dial/SNI/port/scheme
caller parameters — AST-asserted):

- Hop 0 (`resolve_initial`, post-claim): real `TargetResolver` (typed
  authz, liveness, canonicalization, inventory, drift, pinned DNS)
  → `STALE_RESOLUTION` when the fresh pin disagrees with the supplied
  authorization-time pin → real `ScopeEvaluator.evaluate` (must be
  `ALLOWED`) → dial-coherence equality → pair returned. The
  authorization-time resolution is never substituted.
- Redirects (`resolve_hop`): canonicalize → scheme gate (downgrade
  never; http→https only for `http_probe`) → port allowlist
  `{80, 443, initial}` → fresh DNS via production source → fresh
  `TargetResolution` → `HopObservation` appended → fresh
  `evaluate_chain` over the whole chain (policy re-read per hop) →
  fresh per-hop ALLOWED `ScopeEvaluation` → coherence checks. IP
  literals → `REDIRECT_NOT_IN_SCOPE`; 6th edge → `REDIRECT_LIMIT`;
  initial hop required first (`INITIAL_HOP_REQUIRED`).
- State keyed per `(authorization_id, execution_id)` (no cross-binding);
  frozen redirect limits/scheme rules preserved. Executor hop-0
  rewiring (calling `resolve_initial` post-claim instead of using the
  authz-time `res.dial`) is implemented and tested here; physical
  executor wiring is an activation-gate item (no live dial exists
  while the flag is `False`).

## 7. Dial proof implementation

`ai/execution/dial_proof.py` — pure, deterministic, typed
(`DialProof` frozen dataclass, version `b1-dial-proof/v1`):

- `assemble_dial_proof` checks: peer == selected ∈ pinned set; dial
  triple == resolution pins; SNI == canonical host == TLS SNI;
  authorization/execution/resolution id lineage; cert-hash presence
  rules (required for https, forbidden for http); `conn-` id shape.
- `verify_dial_proof` recomputes pin/dial hashes and re-checks every
  equality (tamper → `DIAL_MISMATCH`/`PROOF_BINDING_MISMATCH`;
  absent/untyped/version-skewed → `MISSING_PROOF`).
- `assert_proof_for_seal` enforces per-hop coverage (0..n-1, unique
  connection ids — no pooling) and returns the proof digest for audit
  metadata. `seal_with_dial_proof` asserts first, then invokes the
  caller's frozen 5H seal callable — never invoked on proof failure.
- No logs-as-proof; no second evidence store; no classification, no
  findings, no notification. `HttpObservation` schema untouched
  (`extra="forbid"` still rejects proof kwargs — tested), so the
  change is additive-by-absence: proof ids already ride the frozen
  sealed bindings (`dial_ips` + id triple inside the hash discipline).

## 8. Egress/proxy guard

`ai/execution/egress_guard.py` — v1 `DIRECT EGRESS ONLY / NO PROXY`:

- `check_environment`: any proxy-shaped key present (value ignored,
  empty included) → `PROXY_DETECTED`. Shapes: `*PROXY*` infix,
  `NO_PROXY` any case (allowlist semantics never consulted), `*_PAC`
  suffix, `PAC_URL`, `*WPAD*` — case-insensitive. No override
  parameter exists.
- `scrubbed_environment` returns a proxy-free copy for the launcher;
  boot must still `check_environment` afterwards (tested).
- `assert_topology` pins `{"direct", "direct-nat-preserving"}`;
  anything else → `TOPOLOGY_UNSUPPORTED`.
- No `ALLOW_*`/`DISABLE_*`/`SKIP_*`/bypass identifiers in code
  (AST-asserted on names/constants excluding the docstring).

## 9. HTTP executor integration

`_check_live_gate` now: exact reviewed pair
(`type(x) is LiveSocketFactory/LiveTlsWrapper` **and** module identity
against `ai.execution.live_transport` — never a name comparison) is
admitted **iff** `LIVE_TRAFFIC_ENABLED` is `True`; otherwise
`LIVE_GATE_BLOCKED`. All other factories keep frozen behavior (flag
`True` → blocked; `RealSocketFactory` isinstance or class-name →
blocked; offline fakes pass while disabled). Verified: genuine pair
blocked while disabled; fakes usable; same-name impostor from another
module not admitted; `RealSocketFactory` still blocked; legacy World-A
executors cannot present the pair. **The flag was not flipped.**

## 10. 5H evidence integration

Frozen 5H system used verbatim; no second authority; no schema change.
Seal-time proof assertion (`assert_proof_for_seal`) runs before the
frozen `EvidenceBuilder.seal/seal_partial` invocation via
`seal_with_dial_proof`; the returned digest is audit metadata. A record
with missing/inconsistent proof never reaches the seal callable
(tested: seal stub not invoked). 5I remains the sole deterministic
classifier; 5J the sole finding materializer — neither is called by B1
code (no imports; failure tests assert `outcome != "sealed"` and
`INCOMPLETE`/`UNKNOWN` lifecycles with no evidence bytes on ambiguity).

## 11. Fixture-network tests

`ai/test_b1_dial_policy.py`: 68 tests, offline + `127.0.0.1` loopback
fixtures only (one ephemeral-port TCP server helper; scripted DNS wire
packets via injected exchange). Full A–Z map: A pinned dial + peer
proof + fresh-ids; B ceiling; C mixed-set whole-set failure (+private,
+mapped-private); D rebinding→STALE; E stale pin→STALE (+matching pin
passes); F wrong selected→DIAL_MISMATCH; G peer mismatch; H hostname
rejected; I single-attempt spy + zero hidden lookups; J upper proxy;
K lower proxy (+PAC/WPAD, +empty value, +scrub proof); L IP-SNI
rejected pre-I/O; M handshake failure→TLS_FAILURE; N double-wrap
reuse violation; O per-hop re-resolution counts + same-host re-resolve;
P scope failure; Q IP literal; R port allow/deny; S downgrade;
T missing proof never seals; U tampered proof never seals;
V proof round-trip + digest + seal seam (+incoherent-bindings test);
W 8-thread parallel isolation; X close-during-connect→fail-closed;
Y timeout mapping (+refused loopback port); Z OUTCOME_UNKNOWN with
`evidence is None`, plus peer-mismatch→INCOMPLETE-never-positive.
Security-invariant tests: socket/ssl confinement, no HTTP
client/implicit-DNS/subprocess/shell, no proxy surface outside guard,
no caller-IP params, no legacy imports, literal-False single
assignment of all three flags, DialBinding immutability, pin-replace
and resolver-identity binding, deterministic ordering.

## 12. Security invariants verified

All 34 non-negotiable rules hold: no caller IP/host/port/scheme/
SNI/Host/address-list override (signatures + coherence); no
eTLD+1/suffix/CDN/ASN/cert-org authorization (exact-host frozen 5D);
no proxy/PAC/WPAD/env (guard + transport takes none); no client-side
DNS (`getaddrinfo`/`create_connection` absent; family from literal);
no hostname connect; no pooling/keep-alive/H2/H3/QUIC/Eyeballs;
no auto-redirects (manual loop, fresh resolve+scope+binding+socket per
redirect); TLS verified + SNI==Host==canonical; `getpeername()`
equality with closed mismatches; whole-set DNS validation, ceiling 8,
redirect ceiling 5; authz-time pin never reused as dial authorization
(`STALE_RESOLUTION`); post-start ambiguity → new authorization; no
failure becomes a finding (INCOMPLETE/UNKNOWN only); 5H/5I/5J sole
authorities untouched; `LIVE_TRAFFIC_ENABLED` literally `False`.

## 13. Focused test count

`ai.test_b1_dial_policy`: **68 tests — all pass** (~0.5 s).

## 14. Regression test count

Targeted frozen suites (5C/5D/5E/5H/5I/5J/5K/P1 + Nuclei/Browser
executors): **1040 tests — all pass**. Full `ai` suite
(`discover -t . -s ai`): **2548 tests, 1 failure** —
`test_watch_param_discovery.X8RunParserTests.
test_run_x8_user_agent_does_not_conflict_with_other_flags`, a
**pre-existing, unrelated crawl-subsystem failure** (x8 CLI parser
expectations; that test module imports nothing from `ai.execution`
— verified by AST — and B1 touches only `ai/execution/*` plus one
new test file).

## 15. Compile/static checks

`py_compile` clean on all six touched/new Python files; no tabs or
trailing whitespace; module imports verified (`LIVE_*` flags read
back `False` at runtime).

## 16. Explicit "no Git commands"

**No Git command of any kind was run** in this phase — no status,
diff, log, add, commit, checkout, reset, merge, push, nor
`git diff --check`. (Whitespace hygiene was checked with a file-content
scan instead.)

## 17. Explicit "no public/external network"

**No public/external network was used.** No Internet, no production
targets, no real security testing, no external DNS, no production
MongoDB, no Nuclei, no browser automation. Tests use scripted DNS
packets and `127.0.0.1` loopback fixtures created in the test file.

## 18. Explicit "live traffic remains disabled"

**B1 live traffic remains disabled.** `LIVE_TRAFFIC_ENABLED = False`
(unchanged literal, single assignment), `LIVE_NUCLEI = False`,
`LIVE_BROWSER = False`. The reviewed pair is gate-blocked while the
flag is `False` (tested).

## 19. Remaining B1 activation checklist items

Per architecture §19, none satisfied by implementation alone (in
order): (1) production resolver literals + resolver review sign-off;
(2) deployment topology attestation + boot assertion wiring;
(3) proxy scrub/`PROXY_DETECTED` deployment proof; (4) live adapter
review sign-off; (5) 5E-matrix-against-live-adapters green in fixture
network; (6) seal-time assertion green; (7) failure-injection reach
(§16 codes) signed; (8) frozen 5H→5I→5J handoff over fixture network;
(9) concurrency/race sign-off incl. cross-process ledger CAS (B2);
(10) full offline regression green incl. tripwires; (11) flag flip as
a separately authorized act referencing the checklist. Additionally:
executor hop-0 post-claim rewiring (call `resolve_initial`, dial the
fresh pin) must land as part of activation.

## 20. B2/B4/B5 status

Unchanged and out of scope: B2 (production Mongo adapters + sweep),
B4, B5 remain BLOCKED. B1 is not cited as authorization for
browser/Nuclei traffic (5F/5G flags stay `False`).

## 21. Unresolved risks

1. Cross-process ledger CAS still needs the B2 adapter — live traffic
   must be single-process until B2 (architecture §20.1, unchanged).
2. OCSP/AIA soft-fail semantics of the system verifier accepted for
   HTTP v1; strict-PKI sites need allowlist review at activation.
3. The pinned stub's DNS parser is trusted code pending §19-item-1
   review; defense (classification + ceilings + order + peer check)
   is resolver-agnostic.
4. `resolved_at` freshness is relative to the in-process ledger claim,
   not absolute wall time (clock skew cannot grant authority).
5. The full-suite single failure (crawl x8 parser test) is unrelated
   but should be triaged by the crawl subsystem owner so the suite is
   fully green before activation sign-off.

---

*Implementation executed with zero Git invocations, zero external
network use, and live traffic disabled throughout.*
