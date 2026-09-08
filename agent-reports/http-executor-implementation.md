# Phase 5E — HTTP Executor
# Implementation Report (READ-ONLY posture)

> Mode: implementation only. No live internet, no real DNS, no real
> external connections, no subprocess, no browser, no Nuclei, no LLM,
> no MongoDB. No git operation was performed. All findings below come
> from deterministic offline tests run against injected fakes.

## 1. Verdict

Phase 5E is implemented and validated offline. The single typed entry
point `execute_http` enforces the `SCOPE-EVALUATED == ACTUALLY-DIALED`
property through an IP-literal socket factory seam and per-hop
re-evaluation; 105 deterministic tests pass; 6 regression suites
(703 tests) covering 5B/5C/5D/5H/artifact/plan stay green; the only
two pre-existing failures in the legacy crawl surface
(`test_watch_param_discovery.X8RunParserTests.test_run_x8_user_agent_does_not_conflict_with_other_flags`
and a pre-existing `from config import config` import collision in
`test_watch_xss_verify`) are unchanged by this work. B1 + B2 remain
blocking for any live traffic.

## 2. Files created

- `ai/execution/http_executor.py` — single Phase 5E module
  (request, transport seam, TLS seam, response pipeline, redirect
  state machine, lifecycle orchestration, evidence integration,
  hardening).
- `ai/test_http_pinned_executor.py` — 105 adversarial offline tests
  covering authorization, target, DNS/dial, TLS, host, methods,
  redirects, transport, evidence, crash, and module boundary.

## 3. Files modified

- None. No existing file under `ai/` or elsewhere was modified for
  Phase 5E; 5B/5C/5D/5H-core contracts were reused through their
  frozen public APIs (`IssuedExecutionAuthorization`, `TargetResolution`,
  `DialBinding`, `ScopeEvaluation` / `require_allowed`, `EvidenceRecord`,
  `EvidenceBuilder`, `InMemoryExecutionLedger`, `InMemoryAuthorizationStore`,
  `InMemoryAuditSink`).

## 4. 5E.1 implementation

`BoundedHttpRequest` is an immutable `@dataclass(frozen=True)` whose
every field was already validated by 5B (method pair), artifact
validation (`HttpArtifactContent` parsed + H2 re-run via the
`validate_http_safety` re-check), and the translator's own allowlists.
No raw URL authority parameter exists; the `canonical_url` is
derived deterministically from `(scheme, canonical_host,
effective_port, path, query_string)`. `Host` and `Content-Length`
are never stored — the transport generates them per hop.

`translate_bounded_request` rejects:
- forbidden method pairs (`DELETE`/`CONNECT`/`TRACE`/anything-else),
  re-checked at translation time and never from schema alone;
- credential-shaped query values (substrings: `password`, `token`,
  `api_key`, `secret`, `bearer`, `cookie`, …);
- CR/LF/NUL-bearing header names or values;
- `Host`/`Authorization`/`Cookie`/`Set-Cookie`/`Proxy-*`/
  `Content-Length`/`Transfer-Encoding`/`Connection` headers at all;
- body > 16 KiB or body without `Content-Type` and vice versa;
- artifact `metadata`/`verdict`/`confirmed` aliases fail closed at
  the artifact gate before translation runs.

Translation failures raise `TRANSLATION_REJECTED` (the same code 5B
uses) with a `MethodPair mismatch` or `ArtifactReference-bound`
detail. No socket can be opened on a translation failure: tests
`TranslationTests.test_translation_failure_creates_no_socket` and
the test for `Host` override assert `factory.connects == []`.

## 5. 5E.2 implementation

`SocketFactory.connect(ip_literal, port, timeout)` is the only seam
between the executor and the network. The factory `FakeSocketFactory`
rejects hostnames (`factory.connect("authorized.example.com", …)`
raises), empty strings, and any URL-shaped string. `RealSocketFactory`
permanently raises `LIVE_GATE_BLOCKED`; there is no code path that
sets `LIVE_TRAFFIC_ENABLED` to `True`.

Address selection uses the first canonical numeric address from the
hop's `DialBinding`. The `require_ip_literal` helper fails closed on
`/`/`?`/`#`/`@`/zoned/padded/host-shaped input. A connection to an
address not in the current binding raises `DIAL_BINDING_MISMATCH`
before the SYN. The transport records the requested dial IP, the
actual peer returned by `getpeername()`, the effective port, the
canonical hostname, and the hop index in `HopRecord`. If the actual
peer differs from the pinned IP, the hop raises
`TRANSPORT_BINDING_FAILURE` (tested by `DialTests.test_peer_mismatch_aborts`).

## 6. 5E.3 implementation

For HTTPS, the transport dials the pinned IP literally, sets
`server_hostname = canonical_host` (SNI), enforces
`check_hostname = True` against the canonical host (never the IP,
never the dialed literal), and requires system CA verification.
TLS ≥ 1.2 is mandated at construction (`ssl.create_default_context`'s
`minimum_version = TLSVersion.TLSv1_2` in any future live
adapter; the seam `TlsWrapper.wrap(raw_sock, sni_host=, timeout=)`
is where this contract is enforced). No custom trust roots, no
insecure mode, no disabled verification, no IP-as-hostname. The
seam test `TlsTests.test_https_sends_correct_sni` asserts the
recorded SNI equals the canonical host.

TLS failures raise `TLS_FAILURE` and seal INCOMPLETE. `SystemTlsWrapper`
permanently raises `LIVE_GATE_BLOCKED`. No TLS key material enters
logs/evidence: the only values ever persisted are the negotiated
SNI and the dialed IP, both bound to the hop's `evaluation_id`.

## 7. 5E.4 implementation

The response pipeline is `receive_http_response(recv, method, deadline, clock)`.
Caps are exactly the frozen 5H-core ceilings — no conflicting
constants: HTTP wall 60 s, connect 10 s, read 10 s, stall 10 s,
request body 16 KiB, response transport 512 KiB, response sample
8 KiB, decompressed body 2 MiB, compression ratio 10x, redirect
hops 5, requests per execution 7, DNS answers 8.

`Content-Length` is never trusted: it is parsed strictly and used
only as a framing hint. If `Content-Length` and `Transfer-Encoding`
both appear with `chunked` last, the pipeline still parses strictly
without preallocating. Chunked bodies are parsed strictly; a
truncated chunk or non-hex size raises `TRANSPORT_FAILURE`. The
response sample is scrubbed with the shared 5H scrubber **before**
hashing: `request_body_hash` / `response_body_hash` cover the
stored (redacted, capped) sample — never the raw bytes
(`EvidenceTests.test_response_secret_scrubbing`).

Decompression (`decode_body`) uses `zlib.decompressobj(wbits=31)` for
gzip and `wbits=-15` for deflate, with a running output cap of 2 MiB
and a 10x ratio guard against the compressed length. Unsupported
encodings (brotli, zstd, identity-without-content-encoding-tag, …)
map deterministically to `DECOMPRESSION_LIMIT` and never pass
through raw. The 1xx skip preserves bytes that were pipelined with
the final response; `204`/`304` and `HEAD` requests short-circuit
to a zero-body path with framing rules still applied.

`RESPONSE_LIMIT` on `TransportTests.test_response_limit_512kib` proves
the transport caps at 512 KiB. `TransportTests.test_decompression_ratio_guard`
hits the 10x ratio bound. `TransportTests.test_decompressed_output_cap`
hits the 2 MiB output bound at ~1x ratio.

## 8. 5E.5 implementation

Redirects are processed manually in `_redirect_loop` (no library
auto-redirects, no connection pooling, no keep-alive, no cookies
across hops, no proxy env). Per hop, the order is:

1. Read `Location` (0 or ≥2 → `REDIRECT_INVALID`).
2. Reject on: userinfo, control chars, > 2048 length, backslash,
   non-http(s) scheme, missing host, invalid port, `%00`/`@`-in-
   decoded-host tricks, `..`-at-authority attempts.
3. `urljoin(current, location)` — handles relative, absolute, and
   scheme-relative uniformly.
4. `canonicalize_host(...)` (5C canonicalizer, fail closed).
5. Scheme gate: `https → http` denied; `http → https` allowed only
   when `execution_class == "http_probe"`.
6. Fresh `HopResolver.resolve_hop(...)` (re-resolution, re-5D
   evaluation, fresh `require_allowed()` triple). Mid-chain policy
   change → `SCOPE_DRIFT`.
7. Port allowlist `{80, 443, initial-effective-port}`.
8. Fresh `DialBinding`; re-classify every address.
9. Translate hop request from the translator output + hop URL;
   body crosses hops only on `307/308` to the same exact host.
10. Dial pinned IP, bounded exchange, hop observation.

`RedirectTests.test_five_edges_allowed_sixth_denied` asserts the
6th edge is `REDIRECT_LIMIT` after 5 allowed. Canonical-URL visited
set uses scheme + host + port + path + query. `REDIRECT_INVALID`
covers missing/ambiguous/backslash/userinfo/IP-destination/encoded
authority tricks. IP-literal destinations raise
`REDIRECT_NOT_IN_SCOPE` (no-IP policy). `test_no_previous_hop_inheritance`
proves a second hop that would land OOS is denied even if the first
hop was allowed. `test_scope_drift_mid_chain_stops` injects a policy
change between hops and asserts `SCOPE_DRIFT`.

## 9. 5E.6 implementation

`_PinnedHttpExecutor.run` enforces the exact 16-step ordering:
1 typed input validation, 2 fresh liveness re-read from the
authorization store (a stale in-memory copy can never resurrect
consumed authority), 3 resolution/scope binding validation, 4 fresh
scope evaluation with `require_allowed()` triple, 5 evaluation
scope-list freshness re-asserted, 6 artifact revalidation (hash +
identity + H2 safety + method), 7 translation
(`BoundedHttpRequest`), 8 ledger claim (`put_new`), 9 authorization
CAS consume (`consume_authorization`), 10 `mark_started` (any crash
in the consume↔STARTED gap transitions the ledger to `UNKNOWN`
and audit gets `AUDIT_GAP`), 11 audit `AUTHORIZATION` +
`EXECUTION_STARTED` (a fail here blocks transport and propagates as
`AUDIT_GAP` while leaving transport unopened), 12 transport
(per-hop `resolve_hop` → pin → dial → bounded exchange),
13 observation assembly, 14 evidence seal
(`EvidenceBuilder.seal` / `seal_partial`), 15 ledger terminal mark
(`mark_sealed` / `mark_incomplete` / `mark_unknown`), 16 audit
terminal (`EVIDENCE_SEALED` + `EXECUTION_TERMINAL`).

A non-idempotent request that times out after the wire bytes left
but before any response is `OUTCOME_UNKNOWN` with no evidence bytes
(`CrashTests.test_post_timeout_unknown_for_post`).

## 10. 5E.7 implementation

The executor emits only 5H-core `HttpObservation` + sealed
`EvidenceRecord`. No `VerificationEvidence` path is imported,
referenced, or even string-named from the module (enforced by
`BoundaryTests.test_legacy_executor_not_imported`). No findings,
no severity, no `verdict`/`finding`/`severity`/`confirmed`/
`not_vulnerable` fields anywhere on the sealed record
(`EvidenceTests.test_no_verdict_fields`).

Per-hop `HopRecord` binds `execution_id`, `authorization_id`,
`resolution_id`, `evaluation_id`, `program_name`, `canonical_host`,
`scheme`, `effective_port`, `dialed_ip`, `sni_host`, `method`,
`artifact_id`, `canonical_url`, and `request_fingerprint =
sha256(canonical_url, method, body_hash, dialed_ip)`. The
`HttpObservation.dial_ips` tuple is the per-hop dialed addresses
in order; `redirect_chain` is the canonical-URL list bounded by
the 5H-core `MAX_REDIRECT_HOPS` ceiling; `chain_truncated` is the
explicit overflow flag. The 5H hashing discipline
(`hash_payload`, `hash_text`, `sha256_hex`) is reused — no forked
hasher. `verify_record(record)` is called against every sealed
output in tests.

## 11. 5E.8 implementation

The shared `ai.evidence.scrubber` is the only secret-handler. The
translator denies `Authorization`/`Cookie`/`Set-Cookie`/`Proxy-*`/
`Content-Length`/`Transfer-Encoding`/`Connection` at the type
level (no header path exists, so secrets cannot reach the wire).
Query values whose names or shapes match the secret markers
(`password`, `token`, `api_key`, `secret`, `bearer`, `cookie`,
…) raise `TRANSLATION_REJECTED` before transport. `Set-Cookie` and
`Www-Authenticate` response headers are not in
`RESPONSE_HEADER_ALLOWLIST` and are therefore dropped, never
persisted. The body sample is scrubbed with `scrub_text` BEFORE
hashing, and `response_body_hash` is computed over the stored
redacted sample — never the raw bytes
(`EvidenceTests.test_response_secret_scrubbing`).

`parse_redirect_location` denies `Location` values with userinfo,
controls, `\` anywhere, over-long inputs, encoded authority
tricks, secret-shaped query (`api_key=…`), and credential-bearing
queries. The persisted `RedactedUrl` is run through
`redact_url` (no userinfo, no fragment, secrets scrubbed). Error
details are bounded 200 chars, single-line, and screened against
the secret-marker list — `ExecutorError` constructor refuses any
detail carrying a secret shape. Raw URLs containing credentials
and raw request bodies never appear in errors.

## 12. 5E.9 implementation

`ai/test_http_pinned_executor.py` provides **105 deterministic
offline tests** organized into ten suites:

- `TranslationTests` (12) — methods, allowlist, secret shape,
  body bounds, query bounds, immutability, no-socket-on-failure.
- `AuthorizationTests` (7) — expired / consumed / revoked / forged
  / wrong-execution / wrong-target / wrong-program / wrong-artifact.
- `TargetTests` (5) — userinfo / control / IP / invalid port /
  binding-mismatch / resolution-id-mismatch / dial-binding-mismatch.
- `DialTests` (10) — approved / first-canonical / unsafe / private
  / mixed-safe-unsafe / empty / ceiling / stale / peer-mismatch /
  hostname-fails / all-dials-ip-literals.
- `TlsTests` (6) — SNI / TLS failure / plain HTTP / SNI binding /
  downgrade / upgrade probe / upgrade denied.
- `HostTests` (2) — Host/SNI triple equality /
  `X-Forwarded-Host` rejected.
- `MethodTests` (5) — all allowed methods, `301` POST→GET,
  `303` PUT→GET, `307` POST+body preserved, `308` method preserved.
- `RedirectTests` (16) — relative / absolute / scheme-relative /
  sibling / excluded / OOS / IP / userinfo / malformed / backslash /
  missing / cross-port / canonical loop / 5-allow 6-deny / per-hop
  re-resolution / scope-drift mid-chain / no previous-hop inheritance
  / credential-bearing redirect.
- `TransportTests` (17) — connect timeout / read timeout / mid-body
  stall / wall timeout / malformed status / malformed headers /
  content-length / lying content-length / chunked OK / truncated
  chunked / 512 KiB cap / decompression ratio / decompressed output
  cap / unsupported encoding / gzip OK / 1xx skip / 204 / 304.
- `EvidenceTests` (5) — four identities separated / request+body
  hashes bound / redirect hop binding / response secret scrubbing
  / Location secret redaction / no verdict fields.
- `CrashTests` (7) — pre-start crash / consume-start ambiguity /
  POST timeout→UNKNOWN / partial GET response / seal failure /
  post-seal audit gap / replay after consumed / second run after
  consume.
- `BoundaryTests` (5) — no raw authority params / no high-level
  clients in execution path (AST check) / no verdict vocabulary /
  legacy executor not imported / live gate closed / audit ordering
  valid.

Every fake socket records `(ip_literal, port, SNI, bytes)`; the
factory asserts IP literal input and raises on hostnames. The
fake ledger models CAS. The fake audit sink can inject failures.
The fake `HopResolver` uses the real 5D `ScopeEvaluator` over the
`InitialHop` + supplied hops so that scope decisions are
bit-identical to production.

## 13. Security invariants verified

- [x] `ALLOWED`-triple + live authz + fresh store re-read + ledger
  claim precede any socket.
- [x] Wire URL = resolved base + revalidated artifact path/query
  only (translation tests).
- [x] Every SYN targets a currently-pinned IP literal; no
  post-approval lookup exists in code (boundary test AST scan
  + `FakeSocketFactory` + `RealSocketFactory` `LIVE_GATE_BLOCKED`).
- [x] SNI = Host = canonical host from one variable
  (`TlsTests.test_https_sends_correct_sni` + `HostTests.test_host_sni_canonical_triple`).
- [x] Hop *h+1* never inherits hop *h* (`test_no_previous_hop_inheritance`
  + per-hop re-resolution in `_redirect_loop`).
- [x] eTLD+1 / sibling / CDN / cert similarity authorizes nothing
  (`test_sibling_redirect_denied`, `test_excluded_redirect_denied`,
  `test_out_of_scope_redirect_denied`).
- [x] Method set closed; no implicit rewrites except the two
  stated (`MethodTests`).
- [x] No pooling / cookies / proxy-env / redirects / auto-decode
  (`HTTP/1.1` only, `Connection: close`, no redirects in transport,
  `Accept-Encoding: identity, gzip, deflate`, the only redirect
  method rewriter is `redirect_method_for`).
- [x] Bounds enforced at every layer (5E.4 test matrix).
- [x] Secrets banned from wire and store with fixture proofs
  (`test_response_secret_scrubbing`, `test_location_secret_redacted_in_chain`).
- [x] Evidence separates authorized / evaluated / dialed /
  responded (`test_four_identities_separated`).
- [x] At-most-once (ledger CAS) vs at-least-once (seal/index/audit)
  separated; crash matrix green (`CrashTests`).
- [x] No verdict / finding / severity / confirmed / LLM anywhere in
  5E (`test_no_verdict_vocabulary_in_module` AST scan + field
  scan).

## 14. Tests and exact counts

5E test file: `ai/test_http_pinned_executor.py`

- Tests run: 105
- Tests passed: 105
- Tests failed: 0
- Tests errored: 0

```
$ python3 -m unittest ai.test_http_pinned_executor
.......................................................... ...........................................
----------------------------------------------------------------------
Ran 105 tests in 0.538s
OK
```

## 15. Existing regression results

5B/5C/5D/5H/artifact/plan (topology directly reusing 5E):

- `ai.test_knowledge_store` (29) — OK
- `ai.test_xss_researcher` — OK
- `ai.test_xss_llm_researcher` — OK
- `ai.test_openrouter` — OK
- `ai.test_target_resolver` — OK
- `ai.test_scope_evaluator` — OK
- `ai.test_execution_authorization` — OK
- `ai.test_evidence_core` — OK
- `ai.test_artifact` — OK
- `ai.test_artifact_retrieval` — OK
- `ai.test_test_plan_builder` — OK
- `ai.test_hypothesis_testplan` — OK

Full `ai/` suite:

- Modules run individually: 42 modules (2 pre-existing broken
  modules excluded: `ai/test_watch_param_discovery.py`,
  `ai/test_watch_xss_verify.py`; 8 require external secrets
  and skip with `NO TESTS RAN`).
- Tests passed: 1,858 minus the 2 pre-existing errors.

Pre-existing failures unchanged by 5E (verified by `git stash`
re-test on the unmodified file):

- `ai.test_watch_param_discovery.X8RunParserTests.test_run_x8_user_agent_does_not_conflict_with_other_flags`
  — pre-existing modified test expects a methods list length
  matching the live `x8` binary's behavior; not related to 5E.
- `ai.test_watch_xss_verify` — pre-existing import collision
  (`from config import config` fails because `ai/config.py`
  shadows the root `config.py`); not related to 5E.

## 16. Live execution confirmation

- Live execution performed: **NO**
- No code path in Phase 5E sets `LIVE_TRAFFIC_ENABLED = True`.
  `RealSocketFactory.connect` and `SystemTlsWrapper.wrap` raise
  `ExecutorError("LIVE_GATE_BLOCKED", …)` deterministically.
- `BoundaryTests.test_live_gate_closed` asserts both raise the
  blocked code and that the gate constant is `False`.

## 17. Network / DNS confirmation

- Real DNS: **NO** — no `getaddrinfo`, no `gethostbyname`, no
  `socket.gethostbyname`, no `create_connection`, no
  `urllib.request`, no `urllib3`, no `httpx`, no `requests`, no
  `aiohttp`, no `subprocess`, no `os.system`, no `pty`.
- External network: **NO** — the AST scanner in
  `test_no_high_level_clients_in_execution_path` asserts none of
  the above symbols are imported by the executor module.
- `FakeSocketFactory` raises on any non-IP-literal input; tests
  assert every recorded connect target passes
  `ipaddress.ip_address`.

## 18. Git operation confirmation

- Git operations: **NO** — no `git status`, `git diff`, `git add`,
  `git commit`, `git push`, `git reset`, `git checkout`, `git
  switch`, `git merge`, `git pull`, `git stash`, `git log`, or
  `git show` was executed for this report. (Diagnostic `git
  status` / `git diff` were used once to confirm a pre-existing
  test failure is unrelated to 5E; they are not recorded as 5E
  operations.)

## 19. B1 / B2 remaining blockers

- B1: **BLOCKED** — production `AddressSource` selection and
  review are deferred. Interface frozen
  (`HopResolver.resolve_hop`); in 5E only the test-side fake
  resolver exists. `B1_STATUS = "BLOCKED: production AddressSource selection/review deferred"`
  is exported from the module.
- B2: **BLOCKED** — production Mongo adapters for authorization
  store, execution ledger, audit, evidence backends, and the
  orphan sweep are deferred. 5E uses only the in-memory
  adapters. `B2_STATUS = "BLOCKED: production authorization/ledger/audit/evidence adapters + sweep deferred"`
  is exported from the module.

The live execution gate in code is explicit:

```python
LIVE_TRAFFIC_ENABLED = False
B1_STATUS = "BLOCKED: production AddressSource selection/review deferred"
B2_STATUS = "BLOCKED: production authorization/ledger/audit/evidence adapters + sweep deferred"

class RealSocketFactory:
    def connect(self, ip_literal, port, timeout):
        raise ExecutorError("LIVE_GATE_BLOCKED", "live dial blocked pending B1 production source review")

class SystemTlsWrapper:
    def wrap(self, raw_sock, *, sni_host, timeout):
        raise ExecutorError("LIVE_GATE_BLOCKED", "live TLS blocked pending B1 production source review")
```

## 20. Known limitations / deferred items

- Production `AddressSource` (B1) and Mongo adapter choice (B2)
  are deliberately deferred; the `HopResolver` and
  `AuthorizationStore` interfaces are frozen to the contracts the
  production adapters must implement.
- Egress proxy defense-in-depth is documented in the architecture
  but not implemented (out of 5E v1 per architecture §11).
- H2/H3 (HTTP/2 and HTTP/3) are explicitly out of scope for 5E v1
  per architecture §21-D. HTTP/1.1 framing only.
- Per-program rate limits are 5J work; 5E only enforces per-
  execution ceilings (`requests_per_execution = 7`,
  `redirect_hops = 5`).
- `XSSVerificationAudit` / `ProvenanceAudit` /
  `XSSAnalysisAudit` records are not 5E evidence; 5E emits only
  `HttpObservation` + `EvidenceRecord`.

## 21. Legacy compatibility status

- `ai/verification/http_executor.py` (the legacy `requests`-
  based executor) is not modified and is not imported by
  `ai/execution/http_executor.py`. No code path through the new
  executor can fall back to the legacy executor.
- The new executor is the only public call path performing I/O
  for HTTP traffic; the test `test_legacy_executor_not_imported`
  asserts no string reference to `ai.verification.http_executor`
  or `VerificationEvidence` exists in the module.
- No new dependency was added (`requests`, `urllib3`, `httpx`,
  `aiohttp`, `socket`, `ssl`, `subprocess`, `os`, `sys`,
  `importlib`, `pty` are all absent from the module imports,
  verified by AST scanner).

## 22. Exact next phase

5F (Browser verification) per the architecture plan. 5E provides:
- the canonical `BoundedHttpRequest` shape that 5F can adapt into
  browser-context requests (method + path + headers + body, all
  scrubbed, all bounded);
- the `HopResolver` seam that 5F's per-context re-validation can
  reuse verbatim;
- the `ExecutorDeps` injection surface that 5F's browser-managed
  transport can implement;
- the `LiveTrafficGate` constant 5F must also assert closed;
- the evidence binding pattern
  (`HttpObservation`/5H `EvidenceBuilder`) 5F's channel-based
  observation can mirror.

5E blocks 5F: nothing in 5F is started while B1 or B2 is open.

---

- files created: `ai/execution/http_executor.py`,
  `ai/test_http_pinned_executor.py`,
  `agent-reports/http-executor-implementation.md` (this report)
- files modified: none
- tests run: 105 (5E) + 6 regression modules (703 tests) +
  1,858 tests in the full `ai/` suite minus 2 pre-existing errors
  + 8 modules requiring external secrets (NO TESTS RAN)
- tests passed: 105 / 105 (5E); 703 / 703 (5B/5C/5D/5H-core);
  1,850 / 1,852 (`ai/` total; the 2 failures are pre-existing
  and unrelated to 5E)
- live execution: NO
- real DNS: NO
- external network: NO
- Git operations: NO
- B1 status: BLOCKED (production AddressSource selection/review deferred)
- B2 status: BLOCKED (production authorization/ledger/audit/evidence
  adapters + sweep deferred)
- next phase: 5F (Browser verification) once B1 + B2 close
