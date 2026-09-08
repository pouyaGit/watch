# Stage 3 — B3 Sandbox / Egress / http_probe Pilot Gate (Live Pilot CLOSED)

## 1. Stage objective

Implement and verify the B3 execution safety boundary: the smallest
possible production execution boundary in which a future authorized
HTTP probe can run ONLY when the full 5B–5J authority, resolution,
scope, evidence, and verification chain permits it. Prepare — but DO
NOT enable — a single-class `http_probe` live pilot behind an explicit
final gate. Nuclei and browser execution remain blocked. Real-Mongo
integration and concurrency validation were to be added as
skip-safe optional tests.

Result: boundary implemented and unit-verified; pilot gate proven
structurally and remains CLOSED; no live connection performed; no
live path opened; real-Mongo integration suite created but SKIPPED
(no test URI / no server in this environment).

## 2. Existing B3 architecture inspected

Before editing, the following were read in full (or in the operative
sections):

- `ai/execution/live_transport.py` — B1 `LiveSocketFactory`
  (IP-literal dial, one fresh socket per SYN, `connection_id`),
  `LiveTlsWrapper` (system CA, TLS≥1.2, SNI=canonical host),
  `verify_socket_peer`, `dns_tcp_exchange`. Only B1 module allowed
  `socket`/`ssl`.
- `ai/execution/egress_guard.py` — v1 policy is DIRECT-EGRESS-ONLY /
  NO-PROXY (`check_environment` → `PROXY_DETECTED`,
  `scrubbed_environment`, `assert_topology`). No per-target allowlist.
- `ai/execution/dial_proof.py` — `DialProof` per-hop actual-dial
  proof, `assemble/verify_dial_proof`, `assert_proof_for_seal`,
  `seal_with_dial_proof` (narrow 5H seam, no schema extension).
- `ai/execution/http_executor.py` — 5E IP-pinned executor,
  `LIVE_TRAFFIC_ENABLED = False`, `RealSocketFactory`/`SystemTlsWrapper`
  always raise `LIVE_GATE_BLOCKED`, B1 live-pair admission requires
  exact type identity + the master switch. `translate_bounded_request`,
  bounded HTTP/1.1 receive, redirect helpers, ceilings re-exported.
- `ai/execution/ledger.py` — at-most-once ledger, CAS versioning,
  `EXECUTION_REPLAY` / `EXECUTION_DUPLICATE` /
  `EXECUTION_IN_PROGRESS` / `OUTCOME_UNKNOWN` semantics.
- `ai/execution/production_address_source.py` — pinned B1 DNS stub
  (`DnsResolver` protocol, single TCP exchange, CNAME-internal-only,
  `validate_answers` as the single acceptance gate).
- `ai/execution/production_hop_resolver.py` — per-hop fresh
  resolve+evaluate wiring, `STALE_RESOLUTION` on authz-pin drift,
  redirect re-resolution with whole-chain re-evaluation.
- `ai/authorizer/*`, `ai/resolver/*` (`dns.classify_address` deny
  policy, `MAX_DNS_ANSWERS`), `ai/scope/*`, `ai/evidence/*`,
  `ai/verification/deterministic/*`, `ai/finding/*` — reused as
  frozen contracts (see §21).
- B1/B2 persistence adapters (`ai/persistence/driver.py`,
  `mongo_authz.py`, `mongo_ledger.py`, `mongo_audit.py`,
  `mongo_evidence.py`) with declared unique indexes
  (`AUTHZ/LEDGER/AUDIT/BLOB/INDEX_UNIQUE_INDEXES`).

Missing pieces identified (implemented in §3–§10, nothing duplicated):
(a) per-execution egress allowlist bound to the authorized triple —
`egress_guard.py` covers only proxy/topology; (b) sandbox/isolation
abstraction with lifetime + resource accounting — did not exist;
(c) outbound request-bound gate over `BoundedHttpRequest` — did not
exist as a standalone transport-entry check; (d) redirect→fresh-scope
binding object — `ProductionHopResolver` re-resolves but mints no
per-hop egress token; (e) dial-proof↔egress binding — proof verified
against 5C/5D but not against an egress token; (f) 15-condition pilot
gate object — did not exist; (g) real-Mongo skip-safe integration
tests — did not exist.

## 3. B3 boundary design

One new pure module, `ai/execution/b3_boundary.py` (1137 lines),
OFFLINE and DETERMINISTIC: no `socket`/`ssl`, no subprocess, no
database driver, no DNS, no LLM, no browser, no Nuclei, no findings,
no verdicts (AST-test-enforced, §16). Closed error vocabulary
`B3BoundaryError` (18 codes, secret-free single-line details).
No existing file was modified; no existing gate was weakened;
`LIVE_TRAFFIC_ENABLED` was not touched (still `False` in
`http_executor.py`).

## 4. Network isolation design

`acquire_sandbox()` / `release_sandbox()` with `SandboxSpec` /
`SandboxRelease` records. The mode set is `SANDBOX_MODES =
("dry-run-blocked",)` — the ONLY admitted mode. Rationale recorded
as data (`SANDBOX_PRODUCTION_BLOCKER`, asserted by tests, not prose):
production netns creation requires root/`CAP_SYS_ADMIN` and a reviewed
launcher; WSL cannot safely create or integration-test an isolated
namespace here, so acquisition records the intended boundary
parameters (dedicated netns; single veth with default route ONLY
toward the egress triple; nameserver pinned to the operator resolver
with no search domains; nftables/iptables allowlist of exactly
`(approved_address, effective_port, tcp)`; teardown on
completion/timeout/failure) plus the enforced budgets, while release
accounting proves bounded lifetime with exactly one release per
acquisition (`completed`/`timeout`/`failed`; unknown reasons fail
closed). No namespace, veth, filter, or child process is created by
Stage 3 code. DNS cannot bypass the 5C/B1-selected address because
the transport entry (`check_egress_dial`) accepts only the
policy-bound literal and the dial target remains bound to the approved
resolved address; Host/SNI alone authorize nothing.

## 5. Egress allowlist design

`EgressPolicy` (frozen) binds `authorization_id, execution_id,
program_name, canonical_host, approved_address, effective_port,
scheme, scope_lists_hash, resolution_id, evaluation_id,
policy_version="b3-egress-policy/v1"`. `build_egress_policy()`
requires genuine `IssuedExecutionAuthorization` / `TargetResolution`
/ `ScopeEvaluation` records and enforces: live lifecycle
(`ISSUED`/`CONSUMED`, else `STALE_AUTHORIZATION`); `http_probe`-only
(else `FORBIDDEN_EXECUTION_CLASS`); `RESOLVED` + full lineage binding
+ dial coherence (else `DIAL_BINDING_MISMATCH`); scope-hash equality
and clear drift flag (else `SCOPE_DRIFT`); `ALLOWED` decision (else
`EGRESS_DENIED`); selected address ∈ pinned `resolved_addresses` and
canonical (else `DIAL_BINDING_MISMATCH`); destination allowed per §6
(else `FORBIDDEN_DESTINATION`). `check_egress_dial()` authorizes
exactly one SYN on exact `(address, port, scheme, authorization_id,
resolution_id)` match — no wildcard, no range, no prefix, no proxy,
no host-header authorization, no destination override; missing policy
→ `MISSING_EGRESS_POLICY`, version skew → `STALE_EGRESS_POLICY`,
anything else → `EGRESS_DENIED` (fail closed).
`egress_policy_hash()` gives the deterministic audit identity.

## 6. Dial proof integration

`assert_dial_matches_egress()` reuses the EXISTING B1 proof format:
it calls `dial_proof.verify_dial_proof()` against the live 5C/5D
bindings (no second proof format created — `DialProofError`
sub-conditions map to `DIAL_PROOF_MISMATCH`), then requires
`actual_peer_ip == selected_address == policy.approved_address`.
URL hostname alone and Host/SNI alone are never proof; the proof is
consumed at the existing evidence/verifier seam (per-hop proofs feed
the unchanged `assert_proof_for_seal` path; B3 adds only the
egress-binding assertion on top).

## 7. HTTP executor design

Only `http_probe` is in scope: `build_egress_policy`,
`check_redirect_target`, `require_fresh_scope_for_redirect`, and the
pilot gate all reject any other `execution_class` with
`FORBIDDEN_EXECUTION_CLASS` (test-proven for `nuclei`). Out of scope
and structurally absent: Nuclei, browser, arbitrary subprocess/shell,
curl/httpx/requests invocation, proxy chaining, SSRF destination
override (AST-proven: none of `subprocess/os/sys/requests/httpx/
urllib/http/pymongo/mongoengine/database/playwright/selenium/
socket/ssl` is imported; no `popen/check_output/shell=True/eval/exec`
shapes). The executor entry takes only typed records
(`BoundedHttpRequest` by exact type name — dicts/URL strings raise
`TypeError`); the final connection target comes exclusively from the
authorized resolution/egress binding, never from request input.

## 8. Request/response bounds

Reused frozen ceilings (never redefined/loosened): `request_body_bytes`
(16 KiB), `response_transport_bytes` (512 KiB), `decompressed_bytes`
(2 MiB), `redirect_hops` (5), `requests_per_execution` (7),
`http_wall_seconds` (60), `connect_timeout_seconds` (10).
`check_request_bounds()` enforces: method ∈ frozen `ALLOWED_METHODS`;
URL ≤ `B3_MAX_URL_LENGTH` (= 2048 path + 16×(128+1024+2) query worst
case + 256 authority margin = 20768, derived from translator caps, not
weaker); headers ≤ 16, names ≤ 128, values ≤ 1024 (mirrors translator),
framing headers (`host/content-length/transfer-encoding/connection`)
denied; body ≤ ceiling; all six lineage ids present.
`check_response_budget()` enforces transport + decompression caps.
Sandbox budgets copy the ceiling values verbatim.

## 9. Redirect safety

Per redirect: `check_redirect_target()` (structural pre-check: no
https-downgrade, no non-`http_probe` upgrade path, canonical host,
IP-literal → `REDIRECT_NOT_IN_SCOPE`, bad port → `REDIRECT_INVALID`)
followed by mandatory `require_fresh_scope_for_redirect()`: the live
5B record re-presented (same id, same scope hash — redirects never
extend revoked/expired/drifted authorizations), a FRESH
`TargetResolution` + `ScopeEvaluation` pair (same authz/execution
lineage, new resolution/evaluation ids, `ALLOWED`), hop index within
the frozen budget of 5 (else `REDIRECT_LIMIT`), fresh pin address.
Reusing the previous hop's ids → `REDIRECT_REQUIRES_FRESH_SCOPE`;
the old policy provably cannot authorize the next dial (exact-match
refusal tested). `localhost` canonicalizes as DNS-kind, so it passes
only the structural pre-check and can never become policy: resolution
fails closed (no fixture/`NXDOMAIN`, or `validate_answers` rejects
the loopback answer) and `check_destination_allowed("localhost")`
→ `FORBIDDEN_DESTINATION` (test-proven).

## 10. Resource limits

Wall-clock (60 s), connect timeout (10 s), response transport cap,
decompression cap, redirect budget (5), request budget (7) — all from
`CEILINGS`, recorded per execution in `SandboxSpec`. `release_sandbox`
proves no orphan boundary survives: exactly one release per
acquisition across `completed`/`timeout`/`failed`. No generic
shell-based timeout wrapper was added (no subprocess exists in the
boundary); budgets ride the existing ceiling contract the transport
already enforces.

## 11. Real-Mongo integration setup

New `ai/test_b3_mongo_integration.py` (614 lines) with a
`PymongoCollectionAdapter` mapping the real `pymongo` collection onto
the narrow `MongoCollection` driver subset (`DuplicateKeyError` →
fake-driver message; all other driver failures →
`MongoUnavailableError`; URIs/credentials/payloads never in messages).
Hard safety: connects ONLY on explicit `WATCH_TEST_MONGO_URI`;
refuses non-`mongodb(_+srv)` schemes, refuses database `watch` /
`admin` / `local` / `config` whether from `WATCH_TEST_MONGO_DB` or
embedded in the URI path; creates/drops ONLY `b3t_*` collections in
the dedicated test database (default `watch_b3_stage3_test`); never
reads production `.env`. Refusal logic itself is unit-tested without a
server (`SafetyGuardTests`, 3 tests). Declared unique indexes are
created server-side per collection (`AUTHZ/LEDGER/AUDIT/BLOB/INDEX`
sets). Coverage when a URI is present: authz duplicate/idempotency +
CAS race (4), ledger slot uniqueness + live-row CAS race + key
conflict (3), audit append-only + duplicate sequence (2), evidence
blob duplicate/drift + index insert (3), closed-client driver failure
(1).

## 12. Concurrency results

NOT RUN against a server in this environment (see §14/§22): the five
real-Mongo classes SKIP at `setUpClass`. The race tests are written so
that, when run, exactly one thread wins and every loser maps to the
unchanged domain conflict (`DuplicateIdempotencyKeyError`,
`VersionConflictError`, `ReplayExecutionError`,
`InProgressExecutionError`, `DuplicateExecutionError`,
`AuditPersistenceError`; blob races assert idempotent
True-once/rest-False with zero exceptions). No race is masked: losing
outcomes assert the exact exception type names. Fake-driver CAS
semantics remain covered by the existing Stage 2 suite (green, §18).

## 13. Pilot gate state

CLOSED BY DEFAULT and CLOSED NOW. `HTTP_PROBE_PILOT_ENABLED is False`
(module constant; no code path sets `True` — AST-test-enforced, and a
`mock.patch` tamper simulation proves `evaluate_pilot_gate` detects a
flipped switch and denies). `PilotGateConfig().pilot_enabled` defaults
`False`; non-bool values (`"false"`) raise `TypeError`. The
15-condition conjunctive gate (`PILOT_GATE_CHECKS`, len asserted 15):
issued/live authz; resolved target; scope ALLOWED; scope fresh
(`evaluated_at == now`); B1 address review (`dns_source` + non-empty
pin); egress policy valid; dial proof valid; request bounded; ledger
admitted; sandbox/resource limits applied; evidence path ready;
verifier path ready; destination permitted; authorization fresh; no
scope drift. Default config → `(False, ("pilot gate closed by
default",))`; `check_pilot_gate` → `PILOT_GATE_CLOSED`. A fully
coherent fixture set under a test-only `pilot_enabled=True` config
evaluates allowed with ZERO I/O (socket constructor mocked to raise),
while `LIVE_TRAFFIC_ENABLED` stays `False` so no dial is physically
possible. `assert_nuclei_browser_blocked()` proves `LIVE_NUCLEI is
False` and `LIVE_BROWSER is False`.

## 14. Whether any live connection was performed

NO. No live connection was performed in Stage 3. New tests are fully
offline (scripted DNS packets, fake clocks, `mock`-guarded socket
constructor). The only sockets in the dependency chain belong to the
pre-existing B1 `127.0.0.1` loopback fixtures, which Stage 3 did not
invoke for new coverage. No public, bounty, production, localhost
service, metadata, or internal target was contacted.

## 15. Exact safety guarantees

- `LIVE_TRAFFIC_ENABLED is False`, `LIVE_NUCLEI is False`,
  `LIVE_BROWSER is False`, `HTTP_PROBE_PILOT_ENABLED is False`
  (identity asserts in every relevant run).
- No code path enables live execution for `execute=True` or any
  caller flag: B3 checks require the full typed 5B/5C/5D lineage plus
  policy/proof/sandbox objects that cannot be forged from strings.
- Private/loopback/link-local/multicast/metadata/garbage destinations
  fail closed at three layers (5C `validate_answers`, B3 destination
  check, exact-match dial check).
- Redirects cannot inherit authorization; stale/revoked/expired/drifted
  authorizations are refused at build, redirect, and gate time.
- No second authorization/proof/evidence/verification/finding format
  was created; 5H/5I/5J paths untouched (response→finding flow
  unchanged: only deterministic verification rules may produce
  findings; `NOT_VULNERABLE`/`CONFIRMED` manufacturing absent —
  asserted by string scan).
- Real-Mongo tests cannot touch production data (URI-gated,
  name-denylisted, prefix-scoped collections).

## 16. Tests added

- `ai/test_b3_boundary.py` (888 lines, 46 tests): egress exact
  binding + 7 coherent rejects (address/port/scheme/authz/resolution/
  version/absence/conflict), stale authz, scope drift, denied scope,
  forbidden class, forbidden destinations (private/loopback/metadata/
  garbage + routable negative), redirect fresh-scope + happy path +
  denied hop + target gate, URL/host-header overrides, dial-proof
  happy/mismatch/missing, request/response/redirect bounds, sandbox
  acquire/release/timeout/failure, pilot closed/full-pass/denials/
  tamper/gates/15-count, module hygiene (imports, subprocess shapes,
  legacy/retired paths, enablement assignments, no-dial proof).
- `ai/test_b3_mongo_integration.py` (614 lines): 13 real-Mongo tests
  (skip without URI) + 3 always-run safety-guard tests.

## 17. Exact test commands

```bash
python3 -m unittest ai.test_stage1_offline ai.test_stage2_production_reads ai.test_b3_boundary ai.test_b3_mongo_integration
python3 -m unittest ai.test_execution_authorization ai.test_scope_evaluator ai.test_target_resolver ai.test_evidence_store ai.test_evidence_core ai.test_deterministic_verifier ai.test_finding_pipeline ai.test_legacy_severance_5k ai.test_b1_dial_policy
python3 -m unittest ai.test_http_pinned_executor ai.test_nuclei_executor ai.test_artifact ai.test_artifact_store ai.test_artifact_retrieval ai.test_test_plan_builder ai.test_test_plan_readiness ai.test_hypothesis_testplan ai.test_hypothesis_engine ai.test_xss_verification ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter ai.test_xss_orchestrator ai.test_xss_pipeline ai.test_composite_executor ai.test_nuclei_ready ai.test_target_matcher ai.test_target_intelligence
git diff --check
git status --short
```

## 18. Exact test counts/results

- Stage 3 new unit: `ai.test_b3_boundary` **46/46 OK**.
- Real-Mongo integration: **3 run OK** (safety guards) + **5 class-level
  SKIPS** (`WATCH_TEST_MONGO_URI` absent; `pymongo` 4.16 present but no
  server on 127.0.0.1:27017, no `mongod` binary in WSL).
- Stage 1 regression: **11/11 OK**. Stage 2 regression: **39/39 OK**.
- Batch 1 (authz+scope+resolver+evidence+verifier+finding+severance+
  B1 dial policy): **768/768 OK**.
- Batch 2 (executors+artifacts+plans+XSS/knowledge/LLM/targets):
  **976/976 OK**.
- Combined: **1843 tests, 0 failures, 5 environment skips**.
- `git diff --check`: only pre-existing `ai/correlator/version.py`
  whitespace noise (untouched, unrelated — same as Stage 2 §20); all
  three Stage 3 files verified free of trailing whitespace by direct
  scan (untracked files are outside `git diff --check` scope).

## 19. Files created

- `ai/execution/b3_boundary.py` (1137 lines) — B3 boundary.
- `ai/test_b3_boundary.py` (888 lines) — 46 focused tests.
- `ai/test_b3_mongo_integration.py` (614 lines) — skip-safe
  real-Mongo + concurrency tests.
- `agent-reports/stage-3-b3-sandbox-egress-and-http-pilot.md` (this
  report).

## 20. Files modified

NONE. Zero existing files were modified (no invasive changes; no
gate refactor; `LIVE_TRAFFIC_ENABLED` untouched; `LIVE_NUCLEI`
untouched). In particular: `ns/`, `crawl/`, `database/`, `http/`,
`enum/`, `nuclei/watch_nuclei_all.py`, legacy verification, systemd
units, `run-pipeline.sh`, `run-heavy-guarded.sh`, `.env`, and all
production secrets untouched. No Git operations performed beyond
read-only `status`/`diff --check`; nothing committed, nothing pushed.

## 21. Existing contracts reused

5B `IssuedExecutionAuthorization` + `ALLOWED_METHODS` + lifecycle
literals; 5C `TargetResolution`/`DialBinding` + `classify_address`/
`validate_answers` deny policy + `canonicalize_host`; 5D
`ScopeEvaluation` (`ALLOWED`-only); B1 `ProductionHopResolver`
(fresh resolve/evaluate, used to mint genuine test bindings),
`LiveSocketFactory`/`LiveTlsWrapper` shapes (admission logic
untouched), `DialProof`/`verify_dial_proof` (sole proof format),
`check_environment` proxy/topology posture (unchanged, complementary);
`CEILINGS` (all budgets); evidence hashing (`hash_payload`,
`sha256_hex`); 5E `BoundedHttpRequest` +
`translate_bounded_request` + translator/header/body caps;
`InMemory*` stores and B1 fixture helpers for tests only;
`AUTHZ/LEDGER/AUDIT/BLOB/INDEX_UNIQUE_INDEXES` for real-Mongo index
creation; domain conflict errors asserted unchanged under races.

## 22. Limitations/blockers

1. Production network namespace NOT created and NOT tested:
   requires root/`CAP_SYS_ADMIN` + reviewed launcher; WSL cannot
   safely provide either → sandbox stays `dry-run-blocked` by design.
   A live dial is therefore structurally impossible in Stage 3
   (in addition to the closed switches).
2. Real-Mongo integration NOT executed: no `WATCH_TEST_MONGO_URI`
   configured, no `mongod` in WSL, port 27017 refused. Suite skips
   cleanly; server-side index enforcement and CAS races remain unproven
   against a live server until run where a dedicated test URI exists.
3. No live connection test performed (no isolated fixture could be
   proven safe in WSL) → pilot remains CLOSED; B3 verified
   structurally only.
4. `localhost` passes the *structural* redirect pre-check
   (canonicalizes as DNS-kind) and is killed downstream
   (resolution/scope/address gates) — documented, tested, no bypass.
5. `evaluation.evaluated_at == now` freshness is exact-string match:
   appropriate for a same-instant pilot call, to be revisited with a
   bounded skew window at activation review if operations require it.
6. Pre-existing repo-wide `git diff --check` noise
   (`ai/correlator/version.py`) and pre-existing working-tree
   modifications are untouched and unrelated.

## 23. Security review

Attack surface added: zero live paths (AST-proven import/shape
hygiene). New code only classifies, binds, budgets, and decides —
typed gates reject dicts/strings/URLs everywhere authority is
required. Threats considered: (a) wrong-address/port/scheme dial →
exact-match refusal (tested); (b) stolen Host header → translator
forbids `host`, B3 never reads it (tested); (c) redirect-to-evil →
fresh scope + new policy required, old policy refuses (tested);
(d) downgrade → denied (tested); (e) private/metadata/loopback dial →
triple-layer refusal (tested); (f) stale/revoked/drifted authz →
refused at build/redirect/gate (tested); (g) tampered master switch
→ detected denial (tested); (h) string `"false"` config → `TypeError`
(tested); (i) production-Mongo contact from tests → URI-gated +
name-denylisted + prefix-scoped, refusal unit-tested; (j) race
masking → exact-errorName assertions, no swallowing (written; server
run pending). Residual risks: netns behavior unproven by construction
(§22.1); real-server CAS/index behavior unproven (§22.2) — both
explicitly block activation, not just noted.

## 24. Stage acceptance matrix

| Criterion | Result |
|---|---|
| B3 boundary: no unrestricted host networking inheritance (blocked-by-default abstraction, exact-spec params) | PASS (structurally; netns creation blocked, §22.1) |
| Explicit egress policy bound to authz/execution/program/host/address/port/scheme/hash/resolution + version | PASS (46 tests) |
| No wildcard/proxy/host-header/override/redirect-reuse destination | PASS (tested) |
| Private/loopback/metadata rejected unless existing policy authorizes (it denies) | PASS (tested) |
| DNS cannot bypass 5C/B1-selected address; dial bound to approved address; redirects re-evaluated | PASS (tested) |
| Bounded lifetime + CPU/mem/process budgets where supported; cleanup on completion/timeout/failure | PASS (accounting; enforcement via ceilings) |
| Dial proof integrated, existing format only, consumed at evidence seam | PASS |
| `http_probe`-only; Nuclei/browser/arbitrary_exec absent | PASS (AST + gate tests) |
| Request/response/redirect/resource bounds enforced | PASS |
| Real-Mongo + concurrency tests added, production-safe, skip-clean | PASS (created; server run SKIPPED, §22.2) |
| 15-condition pilot gate, closed by default, Nuclei/browser stay false | PASS |
| No live connection performed | PASS (zero I/O proven) |
| 5H/5I/5J untouched; no CONFIRMED manufacturing; no parallel pipeline | PASS |
| Stage 1 + Stage 2 + all relevant regressions green | PASS (1843, 0 failures) |
| Forbidden paths untouched; no commits/pushes | PASS |

## 25. Recommended Stage 4

1. Run `ai.test_b3_mongo_integration` against an explicitly configured
   test URI (`WATCH_TEST_MONGO_URI` + `WATCH_TEST_MONGO_DB`) where a
   `mongod` exists; require all 13 to pass before any activation talk.
2. Reviewed launcher + netns integration test on a root-capable host
   (NOT WSL dev): prove namespace/veth/route/DNS-pin/egress-filter/
   teardown for the exact `SandboxSpec` parameters, then graduate the
   mode set beyond `dry-run-blocked` under sign-off.
3. Activation review for the `http_probe` pilot on allowlisted programs
   with per-hop fresh scope, ledger admission, and evidence/verification
   path audits — plus a decision on the `evaluated_at` skew window
   (§22.5). Nuclei/browser stay blocked until their own reviews land.
4. First-pilot traffic only against explicitly controlled fixtures;
   never public/bounty/production/metadata targets.

## 26. Final status

**PASS WITH LIMITATIONS** — all Stage 3 implementation and unit
verification objectives met (1843 tests green, 0 failures; pilot gate
proven and CLOSED; zero live I/O; zero files modified outside the
three new stage files + this report). Limitations are structural, not
residual test failures: production namespace creation blocked by the
WSL environment (§22.1) and real-Mongo integration unexecuted for
lack of a test server (§22.2) — both explicitly gate any future
activation, so "production ready" is NOT claimed.
