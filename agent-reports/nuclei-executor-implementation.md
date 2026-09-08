# Phase 5F v1 — Nuclei Executor Implementation Report

## 1. Verdict

**IMPLEMENTED, OFFLINE, FAIL-CLOSED.** Phase 5F v1 ships a closed
execution specification, an executor-time template safety gate, a
deterministic offline `FakeNucleiRunner`, and a permanently blocked
`LiveNucleiRunner`. No live process was created, no Nuclei binary was
executed, no DNS was performed, no transport occurred, no finding or
verdict is emitted anywhere in the new code path. All 102 new offline
tests pass; all 706 regression tests pass.

Explicit confirmations:

- `LIVE_NUCLEI = False` (literal constant, not configurable)
- `B3 = BLOCKED`
- live execution = NO
- Nuclei executed = NO
- subprocess executed = NO
- network = NO
- DNS = NO
- MongoDB = NO
- Git = NO

## 2. Files created

- `ai/execution/nuclei_executor.py` (new 5F v1 runtime)
- `ai/test_nuclei_executor.py` (new offline deterministic test suite)
- `agent-reports/nuclei-executor-implementation.md` (this report)

## 3. Files modified

None. No existing source file was edited. In particular:

- `ai/researcher/nuclei_runner.py` — untouched
- `ai/researcher/nuclei_pipeline.py` — untouched
- All frozen contracts (`ai/schemas/*`, `ai/evidence/*`, `ai/audit/*`,
  `ai/limits/*`, `ai/scope/*`, `ai/resolver/*`, `ai/authorizer/*`,
  `ai/execution/http_executor.py`, `ai/execution/ledger.py`) — untouched

## 4. Existing contracts reused

- **5B** — `IssuedExecutionAuthorization` (typed-only acceptance),
  liveness re-read via `get_issued_authorization`, CAS consume via
  `consume_authorization`, artifact identity via `artifact_id_for`,
  `ALLOWED_METHODS`.
- **5C** — `TargetResolution`, `canonical_target_hash_for`, dial
  coherence (addresses/port/SNI/pin), resolution identity binding.
- **5D** — `ScopeEvaluation`, `require_allowed()` triple gate.
- **4C/H1+H2** — `NucleiTemplateContent`, `parse_template_content`,
  `canonical_template_bytes`, `validate_nuclei_safety`,
  `validate_nuclei_specificity`, `GENERIC_TOKENS`,
  `MIN_SPECIFIC_TOKEN_LENGTH`, `build_validated_reference`
  (used when a `TestPlan` is supplied for revalidation).
- **5E pattern** — `InMemoryAuditSink` reused directly as the audit
  fake; ledger/audit/consume ordering mirrors the 5E lifecycle.
- **5H-core** — `EvidenceRecord`, `NucleiObservation`,
  `EvidenceBuilder` (`begin` with `execution_class="nuclei_scan"` +
  `attach_nuclei` + `seal`), shared `scrubber`, shared `hashing`,
  `InMemoryExecutionLedger`, `AuditRecord`/`gap_record`, and all
  resource values from `CEILINGS` (referenced, never redefined).

## 5. Template safety implementation

`validate_nuclei_safety_template(...)` returns an immutable
`TemplateSafetyReport` (`ALLOW`/`DENY` + deterministic reasons +
`denied_features`). It reuses H1/H2 and adds executor-time gates:

- Allowed top-level keys only (`template_id`, `method`, `path`,
  `headers`, `query_params`, `body`, `matchers`); every other block
  denies, including `dns`, `network`, `file`, `code`, `headless`,
  `javascript`, `browser`, `workflow(s)`, `interactsh`, `oast`,
  `fuzz(ing)`, `payloads`, `attack(s)`, `cluster(ing)`,
  `extractors`, `callback(s)`, `redirects`, `max-redirects`, `raw`,
  `http`, `tcp`, `ssl`, `websocket`, `variables`, `oob`, and any
  unknown block.
- OOB/callback markers (`interactsh`, `oast`, `burpcollaborator`,
  `oastify`, `dnslog`, `canarytokens`, `webhook.site`,
  `requestbin`, `ngrok`, `pipedream`) denied in any string value.
- Methods restricted to `GET/POST/PUT/PATCH/HEAD/OPTIONS`
  (`DELETE` denied even though the typed schema admits it).
- Authority gate: `Host`, `Authorization`, `Cookie`, `Set-Cookie`,
  `Proxy-*` headers denied; absolute URLs denied in path, query,
  header values, and body; authority-form (`//host`) and userinfo
  (`@`) paths denied; `Host:` lines in bodies denied.
- Raw-request gate: one reconstructed `METHOD path HTTP/1.1` line,
  bounded (1024), relative, no controls, no shell substitution.
- Matcher floors: status-only matchers denied, short/generic tokens
  denied, per-value 1024 cap, total regex surface cap
  (4×4096), matcher count bounded.
- Fixture half of H1 (`validate_nuclei_specificity`) runs whenever
  the caller supplies fixtures.
- `variables` blocks are denied in 5F v1 because the frozen typed
  content (`extra="forbid"`) carries no variables field; the
  implementation stays within the frozen shape rather than
  extending it.

## 6. Target binding

The target string is built **only** from
`resolution.scheme` + `resolution.canonical_host` +
`resolution.effective_port` (`build_target_string`), e.g.
`https://authorized.example.com` (default port omitted). The full
binding chain is checked: resolution↔authorization,
evaluation↔(authorization, execution, resolution) triple,
`RESOLVED`-only, program equality, canonical-host equality,
scheme/port equality, recomputed `canonical_target_hash`, dial
coherence (addresses == resolved, port, SNI, pin), non-empty
address set within the 8-answer ceiling, and scope-hash drift
(`SCOPE_DRIFT`). Any mismatch fails closed before spec
construction.

## 7. Execution specification

`NucleiExecutionSpec` is a frozen dataclass carrying only validated,
bound values: `execution_id`, `authorization_id`, `program_name`,
`canonical_host`, `scheme`, `effective_port`, `target_string`,
`artifact_id`, `template_id`, `template_hash`, `argv` (tuple),
`argv_digest`, `cwd` (deterministic scratch path bound to the
execution id), `environment` (tuple of the 5 allowlisted pairs),
`stdin_policy = "closed"`, stdout/stderr caps, typed
`ResourceLimitsSpec`, and `schema_version`. There is no raw
authority field, no executable field, no caller flags, and no
caller environment parameter (arbitrary caller environment is
structurally unrepresentable).

## 8. Runner design

- `NucleiRunner` is an injected `Protocol` whose only method is
  `launch(spec) -> NucleiRunResult`. It never receives a target URL,
  executable path, environment, CLI flags, or template path — only
  the closed spec.
- `FakeNucleiRunner` is deterministic and offline: no processes, no
  resolution, no transports. It records each invocation and returns
  scripted stdout/stderr/exit/timeout/killed facts.
- `LiveNucleiRunner` is permanently blocked: `launch` raises
  `ExecutorError("NUCLEI_EXECUTION_BLOCKED")` before any process
  primitive. No escape hatch exists.
- `B3NetnsNucleiRunner` is a documented placeholder for the only
  acceptable future live shape; it likewise always raises
  `NUCLEI_EXECUTION_BLOCKED`.

## 9. Live gate

`LIVE_NUCLEI = False` is a literal module constant. AST tests prove
the assignment is a `False` literal and that no configuration,
environment-variable, constructor-argument, artifact, CLI-flag, or
database-value path can change it (the module contains no
`os.environ`/`getenv` and no assignment other than the literal).
The executor additionally re-checks the flag inside
`FakeNucleiRunner.launch`.

## 10. Authorization lifecycle

Exact 20-step ordering implemented in `_NucleiExecutor.run`:

1. typed input validation (`TypeError` on dicts/blobs)
2. authorization liveness re-read from the store (ISSUED,
   unexpired, `execution_class == "nuclei_scan"`, `max_executions == 1`)
3. target/resolution binding validation
4. fresh scope evaluation presented + `require_allowed()` triple gate
5. (folded into 4) scope allow enforcement
6. artifact revalidation (hash + identity + H2 re-run; full
   `build_validated_reference` recheck when a `TestPlan` is supplied)
7. executor-time template safety gate (`ALLOW` required)
8. closed execution-spec construction
9. ledger `put_new(REGISTERED)` (replay → `EXECUTION_REPLAY`)
10. authorization CAS consume (race → `EXECUTION_ALREADY_CONSUMED`)
11. ledger `mark_started` (ambiguity → `OUTCOME_UNKNOWN` + `UNKNOWN`)
12. audit `AUTHORIZATION`
13. audit `EXECUTION_STARTED` (failure → no launch, `AUDIT_GAP`)
14. runner invocation (fake only; live raises blocked)
15. bounded result processing (over-cap → `SUBPROCESS_OUTPUT_LIMIT`;
    timeout → `SUBPROCESS_TIMEOUT`; killed → `SUBPROCESS_KILLED`)
16. `NucleiObservation` construction (observation only)
17. `EvidenceBuilder` integration (`begin`/`attach_nuclei`/`seal`;
    failure → `EVIDENCE_SEAL_FAILED` + `UNKNOWN`)
18. evidence seal
19. ledger terminal (`mark_sealed`; ambiguity → `OUTCOME_UNKNOWN`)
20. audit terminal (`EVIDENCE_SEALED` + `EXECUTION_TERMINAL`;
    late failure → separate `AUDIT_GAP`, evidence kept)

Only genuine `IssuedExecutionAuthorization` records are accepted;
no LLM/scheduler/collector/verifier principal can mint authority
(5B issuance boundary unchanged and reused).

## 11. Evidence integration

5H-core is reused without modification. Each sealed record carries
`execution_class = "nuclei_scan"`, `http = None`, and a
`NucleiObservation` with `template_id`, `template_hash`,
`argv_digest`, `exit_code`, `timed_out`, `killed`, `stdout_hash`,
`stderr_hash`, scrubbed samples, and `finding_like_text_present`.
No `NucleiFinding`, `Finding`, verdict, severity, confirmation, or
`NOT_VULNERABLE` state exists anywhere in the module (AST-verified).
`to_findings()` is never referenced (AST-verified). Finding-like
words (`vulnerable`, `matched`, `critical`, …) set only the
text-level boolean and are never promoted.

## 12. Output scrubbing

stdout/stderr are bounded by `nuclei_output_bytes`, newline
normalized, scrubbed with the **shared** 5H scrubber (no second
scrubber), and hashed **after** scrubbing; the hash covers exactly
the stored sample bytes. Over-cap output raises deterministic
`SUBPROCESS_OUTPUT_LIMIT` and no overflow bytes persist. Raw output
never enters exceptions (closed `ExecutorError` details only).

## 13. OOB handling

OOB is denied at the template gate (OOB markers, callback domains,
`interactsh`/`oast` blocks) and no OOB collector, callback URL, or
skeleton exists in the implementation. A runner-reported OOB maps
to the closed `OOB_NOT_AUTHORIZED` code path for future runners;
v1 has no such path reachable.

## 14. Resource specification

`ResourceLimitsSpec` records wall time (120 s), CPU (60 s), memory
(512 MiB), file descriptors (64), process count (1), file size
(16 MiB), stdout/stderr caps (1 MiB each), and scratch storage
(16 MiB) — ceiling values read from `CEILINGS`, never redefined.
No active rlimit/preexec/process-group behavior is implemented;
that belongs to B3. The runtime fails closed rather than running
without recorded limits.

## 15. Legacy compatibility

- **REUSED** — `NucleiTemplateContent`, `NucleiFixture`,
  `validate_nuclei_safety`, `validate_nuclei_specificity`,
  `parse_template_content`, `canonical_template_bytes`,
  `build_validated_reference`.
- **WRAPPED** — none (the generator is a 4C concern; the executor
  consumes only validated bytes, never calls generation).
- **RETIRED** — `NucleiRunner.run(execute=True)` and dry-run paths
  are unreachable from 5F (no import of
  `ai.researcher.nuclei_runner` exists in the 5F module).
- **FORBIDDEN** — `to_findings()` and `NucleiFinding` in 5F
  (AST-boundary tests fail the suite if either name appears).

## 16. Test matrix

Covered: authorization (expired/consumed/revoked/forged/wrong
execution/wrong target/wrong program/wrong artifact/wrong class/
replay), artifact (hash drift, byte drift, unsafe, specificity,
forbidden protocols, OOB, extractors, fuzzing/attack/clustering,
unknown blocks, variables, status-only/generic/oversized
matchers, destructive method, size, malformed bytes), authority
(Host/Authorization/Cookie/Proxy headers, absolute URLs in
path/query/body/headers, authority-form path, userinfo, body Host
line, end-to-end authority-template refusal), target (canonical
string, exact host, sibling, excluded, out-of-scope, program,
resolution, evaluation, drift, unresolved), argv (exact shape,
server binary, scratch-only template path, binding-derived
target, no shell, digest determinism), env (exact allowlist, no
inheritance, no proxy/secrets, immutability, execution binding),
process (live always blocked incl. direct launch, B3 blocked,
literal-False gate, fake recording, untyped rejection),
resource (ceiling reuse, stdout/stderr caps, timeout spec,
immutability, single-exchange shape), evidence (observation-only,
finding-like boolean, scrub+hash, stderr, normalization,
bindings, exit code), crash (consume ambiguity/race, start
ambiguity, timeout, killed, seal failure, pre-launch audit gap,
post-seal audit gap, replay, lifecycle order), boundary
(AST: no banned imports/calls, no legacy surface, literal gate,
non-configurable gate, no verdict names, no network primitives).

## 17. Exact test counts

`ai/test_nuclei_executor.py`: **102 tests, 102 passed, 0 failed.**

- AuthorizationTests: 10
- ArtifactSafetyTests: 18
- AuthorityTests: 13
- TargetBindingTests: 11
- ArgvTests: 6
- EnvironmentTests: 5
- ProcessGateTests: 7
- ResourceTests: 6
- EvidenceTests: 8
- CrashTests: 10
- BoundaryTests: 8

## 18. Regression results

- `ai.test_knowledge_store`, `ai.test_xss_researcher`,
  `ai.test_xss_llm_researcher`, `ai.test_openrouter`:
  **89 tests, 89 passed, 0 failed.**
- `ai.test_evidence_core`, `ai.test_execution_authorization`,
  `ai.test_artifact`, `ai.test_scope_evaluator`,
  `ai.test_target_resolver`: **459 tests, 459 passed, 0 failed.**
- `ai.test_http_pinned_executor`, `ai.test_artifact_store`,
  `ai.test_nuclei_ready`: **158 tests, 158 passed, 0 failed.**
- Regression total: **706 tests, 706 passed, 0 failed.**

## 19. Static boundary checks

AST tests parse `ai/execution/nuclei_executor.py` and assert: no
imports of `subprocess`/`socket`/`requests`/`httpx`/`urllib3`/
`aiohttp`/`urllib`; no references to process/transport/resolution
primitives (`Popen`, `create_subprocess_*`, `getaddrinfo`,
`gethostbyname`, `create_connection`, `urlopen`, `system`,
`execv`, `fork`, …); no `to_findings`/`NucleiFinding` names or
text; `LIVE_NUCLEI` assigned exactly once as a `False` literal;
no `os.environ`/`getenv`; no verdict-shaped definitions; no
network-primitive tokens. All 8 boundary tests pass.

## 20. Live execution confirmation

NO live execution occurred. The only runner exercised is
`FakeNucleiRunner` (in-memory scripted facts). `LiveNucleiRunner`
and `B3NetnsNucleiRunner` are proven (by direct-launch tests) to
raise `NUCLEI_EXECUTION_BLOCKED`.

## 21. Nuclei execution confirmation

NO Nuclei binary was executed. No `nuclei` process exists in any
code path; argv construction is a pure function over strings and
its exact output is asserted byte-for-byte in tests.

## 22. DNS confirmation

NO DNS was performed. The module contains no resolver, no lookup
call, and no transport; resolution facts arrive only as injected
typed `TargetResolution` records.

## 23. Network confirmation

NO network traffic occurred. The module imports no transport
client and opens no transports; the fake runner returns scripted
strings.

## 24. subprocess confirmation

NO subprocess was spawned and none can be spawned from the 5F
module: it imports no process-creation facility (AST-verified),
and both non-fake runners raise before any process primitive.

## 25. Git confirmation

NO git operation was performed (no status/diff/add/commit/
push/pull/log/show or any other git command).

## 26. B1 status

**B1 = BLOCKED.** Production AddressSource selection/review
remains pending. 5F treats B1 as blocking for live execution and
uses injected deterministic fakes only. (The architecture report's
"B1 lifted by 5E" is not authoritative; the 5E implementation
report still records B1 = BLOCKED.)

## 27. B2 status

**B2 = BLOCKED.** Production Mongo authorization/ledger/audit/
evidence adapters (plus sweep) remain pending. 5F uses only the
in-memory adapters with frozen semantics.

## 28. B3 status

**B3 = BLOCKED.** The Nuclei sandbox/egress boundary remains
pending under separate review. `LIVE_NUCLEI = False`; the only
acceptable future live runner (`B3NetnsNucleiRunner` shape) exists
solely as a non-executing placeholder. No netns/cgroups/seccomp/
landlock/iptables/eBPF/rlimit/process-group mechanism was
implemented in this phase.

## 29. B4 status

**B4 = deferred/blocking for the later production template-corpus
workflow.** Production template source-of-truth review remains
outstanding; 5F revalidates whatever bytes are bound to the
authorization hash but does not establish corpus provenance.

## 30. Known limitations

- Single-exchange templates only; `variables`, `extractors`,
  workflows, redirects-by-template, and all non-HTTP blocks are
  denied (conservative v1 posture inside the frozen typed shape).
- Specificity re-proof at execution time requires caller-supplied
  fixtures; otherwise execution relies on the issuance-time
  `VALID` state plus hash-identity revalidation and the H2 re-run.
- Post-seal audit loss is recorded as `AUDIT_GAP` with evidence
  kept (5H semantics); pre-launch audit loss blocks launch.
- `mark_started` ambiguity after a successful consume resolves to
  `UNKNOWN` with retry requiring a new authorization (5H crash
  matrix).

## 31. Deferred items

B3 sandbox/egress boundary and its review; B2 production
adapters + sweep; B1 production AddressSource selection/review;
B4 production template-corpus review; OOB collector design (no
skeleton shipped); per-program Nuclei rate limiting (5J);
template signing (5B hash identity already binds bytes).

## 32. Exact next phase

**5G Browser/XSS Executor** per the authoritative phase order
(5E HTTP Executor → 5F Nuclei Executor → 5G Browser/XSS Executor
→ 5H Evidence Store → 5I Verifier → 5J Scheduler/E2E). Phase
names and order are unchanged.

---

- files created: `ai/execution/nuclei_executor.py`,
  `ai/test_nuclei_executor.py`,
  `agent-reports/nuclei-executor-implementation.md`
- files modified: none
- tests run: 102 (5F) + 706 (regression) = 808
- tests passed: 808
- tests failed: 0
- live execution = NO
- Nuclei executed = NO
- subprocess executed = NO
- network = NO
- DNS = NO
- MongoDB = NO
- Git = NO
- LIVE_NUCLEI = False
- B3 = BLOCKED

REPORT:
 /opt/watch/agent-reports/nuclei-executor-implementation.md
