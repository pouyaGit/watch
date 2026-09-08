# Stage 4 — Environment Validation and Production Boundary (Pilot NOT Activated)

## 1. Objective

Stage 3 left two environment-dependent properties explicitly unproven:
real Linux network-namespace/egress isolation, and real-Mongo
server-side indexes plus concurrency behavior. Stage 4 closes what
can be closed WITHOUT opening live target traffic: a deterministic
B3 sandbox validation harness against a controlled local fixture, a
machine-checkable 17-item pilot readiness assessment, and an honest
PASS/FAIL/UNPROVEN accounting. This is a VALIDATION stage. No live
execution was enabled, no target traffic occurred, and the pilot
remains CLOSED.

## 2. Environment used

- WSL2 (kernel 6.18.33.2-microsoft-standard-WSL2), uid 1000
  (non-root). `unshare -n` alone: Operation not permitted.
  `unshare -Urn` (user+network): permitted — genuine unprivileged
  kernel-enforced isolation is available; no root was used or needed.
- `ip` CLI present (`/usr/sbin/ip`); NO `iptables`/`nft` binaries;
  NO `mongod`/`mongosh`; `pymongo` 4.16 installed but port 27017
  refused (no server). No `WATCH_TEST_MONGO_URI` configured.
- Probes performed: read-only capability checks (fork+unshare probe
  child with no side effects) plus the gated harness runs below.
  Parent netns verified unchanged after every run.

## 3. B3 harness design

New `ai/execution/b3_validation.py` (1018 lines; B3 product
abstraction NOT rewritten, no live gate touched). Design:

- Double opt-in: every run requires caller `enable=True` AND
  `WATCH_STAGE4_NETNS=1`; default is `ValidationRefused` (maps to
  UNPROVEN, never PASS).
- Fixture `TEST ONLY / STAGE4 / NON-PRODUCTION` on RFC 5737 TEST-NET-1
  (`192.0.2.0/24`; A=`192.0.2.10`, B=`192.0.2.11`, port 18080):
  unroutable by design, so even misconfiguration cannot reach a real
  host. `guard_fixture_address()` admits ONLY exact-canonical fixture
  literals (+ namespace loopback solely for loopback-isolation
  tests); everything else refuses before any socket exists.
- Mechanics (stdlib only): `os.fork` + libc `unshare` into
  user+net namespaces, setgroups-deny + uid/gid mapping (identity
  captured pre-unshare — see §23), `lo` up + fixture /32 via short-lived
  waited `ip` children (test scaffolding, never a product shell
  path), in-process threaded fixture TCP server (raw HTTP bytes;
  drains request head before responding), results collected from a
  reaped child, parent wall-timeout + SIGKILL + `waitpid`.
- Transport primitives under test are the REAL product classes
  (`LiveSocketFactory`, `verify_socket_peer`, bounded
  `receive_http_response`/`decode_body`) — never `execute_http`
  end-to-end, which stays blocked by the frozen live gate (honest,
  gate-respecting coverage boundary). No curl/httpx/requests, no
  public/bounty/production/metadata targets (string-scan tested).
- Two genuine harness bugs were found and fixed during development
  (both failed SAFE — refusal/UNPROVEN rather than fake PASS):
  (a) uid/gid must be captured before unshare (post-unshare getuid
  reports overflow 65534, whose mapping write gets EPERM);
  (b) the classic WNOHANG pitfall — `waitpid` returns `(0,0)` for a
  live child and `WIFEXITED(0)` reads True, so the reap guard must
  check `wpid != 0` (missing guard deadlocked the collect loop;
  documented in-code at the guard).

## 4. Sandbox validation

Scenarios run per validation in ONE fresh non-persistent namespace:
`namespace` (isolation, no host-NIC inheritance), `veth` (pair
lifecycle), `routes` (no v4/v6 default route), `egress_matrix`,
`dns_pinned`, `timeouts`, `bytecaps`. Latest full run: **21 PASS,
1 UNPROVEN, 0 FAIL** (§6–§9 detail). A dedicated `hang` scenario
proves the parent wall-timeout → SIGKILL → reap path (PASS, ~4 s).

## 5. Network namespace results — PASS (with stated boundary)

- `namespace-isolated` PASS: child `net:[inode]` differs from parent
  on every run. `no-host-interface-inheritance` PASS: only `lo`
  (+ test veth while present) visible; no `eth0`/host NICs.
- `veth-lifecycle` PASS: pair created, verified present, deleted,
  verified gone — all inside the test netns.
- `parent-netns-unchanged` PASS and `no-orphan-process` PASS on every
  run (child always reaped; namespace never persisted via
  `ip netns add` — teardown is death-of-last-process by
  construction).
- NOT proven here: iptables/nft rule enforcement (no binaries) —
  recorded UNPROVEN, not smuggled into any PASS.

## 6. Egress filter results — PASS (FIB-enforced; mechanism explicit)

Enforcement mechanism proven: the namespace FIB itself (empty route
table, single-host fixture route, no default route). Unapproved
destinations fail IN THE KERNEL (`ENETUNREACH` observed on a raw SYN
for address B; product dial likewise refuses) — network-layer proof,
not application logic:

- allowed `(A, P)`: PASS (dial + `getpeername` peer proof + TCP-only
  `SO_TYPE` check + full HTTP round trip).
- `(A, P+1)`: PASS (refused). `(B, P)` / `(B, P+1)`: PASS (kernel
  FIB refusal + product refusal, dual observation).
- loopback / RFC1918 / link-local / metadata-style: PASS (all
  unreachable; loopback provably carries no fixture bytes, i.e. the
  namespace loopback is not a path to fixture or host).
- TCP-only: PASS (observed `SOCK_STREAM` on the allowed dial; the
  factory constructs no other socket type).
- Packet-filter (iptables/nft) rule layer: UNPROVEN (binaries absent).

## 7. DNS results — PASS (pinning; no lookup on path)

- `dns-hostname-never-dials` PASS: hostname rejected with
  `DIAL_BINDING_MISMATCH` before any I/O.
- `dns-pinned-no-lookup` PASS: with `socket.getaddrinfo` sabotaged to
  raise, the literal dial + peer proof still succeed — behaviorally
  proving no resolver sits on the dial path.
- A dedicated local resolver was deliberately NOT deployed: system
  DNS is not on the dial path by construction. Alternate-DNS-result
  bypass is impossible where no lookup occurs; redirect stale-binding
  reuse is refused by `REDIRECT_REQUIRES_FRESH_SCOPE` (Stage 3 suite,
  re-run green).

## 8. Resource enforcement results — PARTIAL (strict UNPROVEN overall)

Genuinely enforced live against the fixture:

- `timeout-stall-enforced` PASS: hold-open peer → `TRANSPORT_TIMEOUT`
  via the real bounded receive path with a real clock.
- `bytecap-transport-truncates` PASS: 600 KiB body stopped EXACTLY at
  the 512 KiB ceiling (`over_cap=True`).
- `bytecap-decompression-ratio` PASS: 200 KiB-from-bytes gzip refused
  with `DECOMPRESSION_LIMIT`.
- (Fixture fix during development: the server now drains the request
  head before responding — closing with an unread request RST-races
  the client read. Fixture-only change; product untouched.)

NOT proven: live SYN-timeout vs DROP (`timeout-syn-drop` UNPROVEN —
needs a packet filter), CPU/memory/process-count limits (no cgroup
delegation attempted) → item stays UNPROVEN overall. Connect-timeout
range gating remains unit-covered only.

## 9. Cleanup results — PASS

- Normal/teardown: namespace auto-destroyed (non-persistent),
  fixture threads joined, parent ns unchanged — every full run.
- Timeout: over-budget child SIGKILLed and reaped (`timeout-cleanup`
  PASS via dedicated hang run).
- Failure: child setup/scenario failures report as data; parent
  still reaps and reports (fail-safe path exercised during
  development: uid-map bug surfaced as UNPROVEN refusal, never PASS).
- `no-orphan-process` PASS on all runs; `no-orphan-namespace`
  holds by construction (no persistent netns ever created).

## 10. Mongo environment

No test server: `WATCH_TEST_MONGO_URI` unset, no `mongod` binary,
127.0.0.1:27017 refused. `pymongo` present but never connected (no
URI → no client constructed outside the skip-safe suite, which
skipped at `setUpClass`). Production `.env`/database `watch`/
credentials untouched — refusal logic unit-tested (3/3 OK).

## 11. Mongo index results — UNPROVEN

Server-side index metadata was NOT queried (no server). Declared
index sets (`AUTHZ/LEDGER/AUDIT/BLOB/INDEX_UNIQUE_INDEXES`) unchanged
and still created by the Stage 3 suite when a URI exists; duplicate-
write mapping remains fake-driver-proven only (Stage 2 suite green).

## 12. Mongo concurrency results — UNPROVEN (suite ready, unexecuted)

The 13 Stage 3 real-Mongo tests (7 race tests: same-key idempotency,
competing issuance, ledger slot race, ledger CAS race, audit sequence
race, duplicate blob writes, index race — exact winner/loser/domain-
error accounting, no swallowed exceptions) all SKIP cleanly without a
URI. No race results to report; nothing simulated in their place.

## 13. Mongo failure results — UNPROVEN against a server

Fail-closed mapping (unavailable/duplicates → domain errors, no
caching/synthesis/unsafe retry) remains fake-driver-proven
(Stage 2 suite green). Closed-client failure test exists in the
skip-safe suite; unexecuted here.

## 14. Persistence dry-run results — UNPROVEN (Part C)

The Mongo-backed Stage 2 flow against a dedicated test database
requires the absent test server → not run. The fake-driver Stage 2
dry-run suite re-ran green in Stage 4 (`ai.test_stage2_production_reads`
39/39), so pipeline behavior is unchanged; server-backed persistence
proof is outstanding. No target traffic, DNS, browser, Nuclei, or
subprocess exists in either path (Stage 2 suite asserts).

## 15. Readiness matrix

Machine-checkable via `ai/execution/pilot_readiness.py`
(`assess_readiness()` + `render_matrix()`; 487 lines). Evidence
discipline: LIVE-PROVEN (executed offline now), ENV-PROVEN (PASS
only on supplied green validation evidence), SUITE-CITED (structural
half asserted live + named green suite), STRICT-UNPROVEN (never
upgraded). With the real harness report supplied:

```
b1-address-source | PASS | fail-closed w/o transport + frozen allow/deny round-trip executed offline
b2-mongo-authorization | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
b2-ledger | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
b2-audit | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
b2-evidence-persistence | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
b3-network-namespace | PASS | harness checks green: isolated netns, no inheritance
b3-egress-filtering | PASS | harness checks green: FIB-enforced allowlist matrix
dial-proof-vs-actual-dial | UNPROVEN | proof format round-trip executed offline; production-shape dial unprovable (TEST-NET-1 unresolvable by design)
resource-enforcement | UNPROVEN | stall+bytecaps enforced live (3/3); CPU/mem/process-count UNPROVEN
redirect-fresh-scope | PASS | fresh resolve+evaluate+policy executed; stale reuse refused live
scope-drift | PASS | drifted authorization refused live with SCOPE_DRIFT
real-mongo-concurrency | UNPROVEN | server evidence: UNPROVEN; needs dedicated test-URI run
cleanup | PASS | harness checks green: teardown, reap, timeout kill
evidence-path | UNPROVEN | seal path suite-proven (Stage 1/2); server persistence needs test-URI run
deterministic-verification | PASS | pure verifier suite green (Stage 4 regressions)
finding-eligibility-unchanged | PASS | finding+severance suites green; no materialization-path change in Stage 4
live-gates-closed | PASS | LIVE_TRAFFIC/NUCLEI/BROWSER/PILOT all False; pilot config defaults False
SUMMARY | PASS=9 FAIL=0 UNPROVEN=8 | eligible=False
```

Without netns evidence the matrix is 6/0/11 (same UNPROVEN set plus
netns/egress/cleanup). `activation_eligible()` computes False in both
configurations. `HTTP_PROBE_PILOT_ENABLED` remains `False`; no
activation path exists in the module (AST-tested: no switch
assignment, no subprocess, no sockets).

## 16. Security review

| Threat | Mitigation (tested) | Remaining risk |
|---|---|---|
| SSRF / destination override | Exact-match egress policy; guard + FIB matrix green | Packet-filter layer UNPROVEN; pilot still closed |
| DNS rebinding / alternate-DNS bypass | No lookup on dial path (sabotage-tested); pin + fresh-resolve per hop | None on path; resolver hardening stays B1-owned |
| Host-header abuse | Translator forbids `host`; B3 never reads Host (Stage 3 tests, green) | None known |
| Redirect abuse | Fresh scope+policy per hop; stale reuse refused live (readiness proof) | Downgrade/upgrade rules rely on executor + hop resolver (suites green) |
| Private/metadata access | Triple-layer refusal (5C, B3, FIB — all green live) | None on dial path |
| Proxy bypass | `egress_guard` DIRECT-ONLY posture unchanged; harness uses no proxy | Env-based exfiltration out of scope of dial path |
| Namespace escape | Non-persistent userns netns; parent inode verified unchanged every run | Child runs mapped-root `ip` — short-lived, waited; no setuid vector added |
| Egress filter bypass | FIB allowlist proven; route table has no default | iptables/nft rules UNPROVEN — must precede activation |
| Stale authz / scope drift | Refused live at build/redirect/gate (readiness proofs + Stage 3 suite) | Freshness is exact-instant match (Stage 3 §22.5 caveat stands) |
| Replay | Ledger at-most-once slot (unit-proven); server CAS UNPROVEN | Real-server races outstanding |
| CAS races | Domain conflicts asserted exactly (suite ready); fake-driver green | Server-side unproven |
| Evidence tampering | Hash discipline + seal path unchanged; blob CAS unit-proven | Server persistence unproven |
| Resource exhaustion | Stall/bytecap/ratio enforced live; wall/connect ceilings unit-held | CPU/mem/process + SYN-DROP UNPROVEN |
| Orphan cleanup failure | Reap + ns-death + kill-path all green | None observed (3/3 stable runs) |
| Credential leakage | No credentials in fixtures/code; static error strings; prod DB refused by unit-tested guard | None known |

Zero risk is NOT claimed: activation additionally requires the
8 UNPROVEN items converted with server/privileged evidence.

## 17. Exact tests

```bash
python3 -m unittest ai.test_stage1_offline ai.test_stage2_production_reads ai.test_b3_boundary ai.test_b3_mongo_integration ai.test_b3_validation ai.test_pilot_readiness
python3 -m unittest ai.test_execution_authorization ai.test_scope_evaluator ai.test_target_resolver ai.test_evidence_store ai.test_evidence_core ai.test_deterministic_verifier ai.test_finding_pipeline ai.test_legacy_severance_5k ai.test_b1_dial_policy
python3 -m unittest ai.test_http_pinned_executor ai.test_nuclei_executor ai.test_artifact ai.test_artifact_store ai.test_artifact_retrieval ai.test_test_plan_builder ai.test_test_plan_readiness ai.test_hypothesis_testplan ai.test_hypothesis_engine ai.test_xss_verification ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter ai.test_xss_orchestrator ai.test_xss_pipeline ai.test_composite_executor ai.test_nuclei_ready ai.test_target_matcher ai.test_target_intelligence
WATCH_STAGE4_NETNS=1 python3 -m unittest ai.test_b3_validation.GatedValidationTests ai.test_pilot_readiness.GatedReadinessTests
git diff --check
git status --short
```

## 18. Exact test counts

- Stage 4 unit: `ai.test_b3_validation` 12 (10 run + 2 gated skips) OK;
  `ai.test_pilot_readiness` 11 (10 run + 1 gated skip) OK.
- Gated (opt-in, real namespaces): 3/3 OK, stable across 3 full runs
  (~7.4 s each; harness ledger 21 PASS / 1 UNPROVEN / 0 FAIL per run).
- Stage batch (1/2/3/4 unit): **122 tests OK** (8 env skips: 5 mongo
  classes + 3 gated).
- Batch 1 (authz/scope/resolver/evidence/verifier/finding/severance/B1):
  **768/768 OK**. Batch 2 (executors/artifacts/plans/XSS/LLM/targets):
  **976/976 OK**.
- Combined unit: **1866 tests, 0 failures**. Gated: **3/3 OK**.
- `git diff --check`: only the pre-existing
  `ai/correlator/version.py` whitespace noise (untouched, unrelated);
  all four Stage 4 files verified trailing-whitespace-free by direct
  scan (new files are untracked, outside `diff --check` scope).

## 19. Skipped/unproven tests

- 5 real-Mongo classes SKIP (no `WATCH_TEST_MONGO_URI`/server).
- Without opt-in, 3 gated tests SKIP (refusal path = UNPROVEN, never PASS).
- `timeout-syn-drop` UNPROVEN (needs packet filter). CPU/mem/process
  limits UNPROVEN (no cgroup delegation). Dial-proof-vs-production-
  dial UNPROVEN (TEST-NET-1 unresolvable by frozen design — a
  deliberate, documented limit, not an oversight).
- Part C server-backed dry run UNPROVEN (no test server).

## 20. Files created

- `ai/execution/b3_validation.py` (1018 lines) — harness + fixture.
- `ai/test_b3_validation.py` (205 lines) — 12 unit + 2 gated tests.
- `ai/execution/pilot_readiness.py` (487 lines) — 17-item assessment.
- `ai/test_pilot_readiness.py` (165 lines) — 11 unit + 1 gated test.
- `agent-reports/stage-4-environment-validation-and-production-boundary.md`
  (this report).

## 21. Files modified

NONE. Zero existing files modified — product abstraction, live
gates, B3 boundary, and all suites untouched.

## 22. Untouched files

`ns/`, `enum/`, `http/`, `crawl/`, `nuclei/watch_nuclei_all.py`,
legacy verification, systemd units, `run-pipeline.sh`,
`run-heavy-guarded.sh`, `.env`, production secrets, all live-gate
constants, all Stage 1–3 modules and tests. No Git operations beyond
read-only `status`/`diff --check`; nothing committed or pushed.

## 23. Limitations

1. Egress enforcement proven at the FIB layer only; iptables/nft
   rule proofs require binaries absent here.
2. SYN-DROP timeout and CPU/mem/process limits UNPROVEN (no packet
   filter / cgroup delegation in this environment).
3. Dial-proof-vs-actual-dial UNPROVEN by construction for fixture
   addresses (frozen `validate_answers` rejects TEST-NET-1); B1
   loopback proof + offline round-trip are the extant evidence.
4. All Mongo items UNPROVEN (no test server in WSL).
5. Part C server-backed dry run UNPROVEN for the same reason.
6. Harness `ip` CLI + fork/unshare scaffolding is validation-only
   tooling; the product gains no shell path (AST-tested).
7. `evaluated_at` exact-instant freshness caveat (Stage 3 §22.5)
   carries over untouched.

## 24. Recommendation

Stage 5 (or activation review) must, IN ORDER: (a) run the skip-safe
Mongo suite + Part C dry run against an explicitly configured
dedicated test URI/DB; (b) prove iptables/nft egress rules + SYN-DROP
+ cgroup limits on a root-capable host using this harness's fixture
shape; (c) resolve the freshness-skew policy; (d) re-render the
machine-checkable matrix and require 17/17 PASS with
`activation_eligible() == True` — and ONLY then consider a separately
authorized single-class `http_probe` pilot against controlled
fixtures. Nuclei/browser stay blocked until their own reviews.

## 25. Final status

**PASS WITH LIMITATIONS** — all Stage 4 runnable objectives met
(harness green 21/1/0 across 3 stable runs; readiness 9/0/8 with
evidence; 1866 unit + 3 gated tests, 0 failures; gates confirmed
closed; zero live traffic; zero files modified). The 8 UNPROVEN items
are environment-bound, precisely named, and block activation by
computation (`eligible=False`) — production readiness is NOT claimed.
