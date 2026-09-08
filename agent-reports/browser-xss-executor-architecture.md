# Phase 5G — Browser/XSS Executor
# READ-ONLY SECURITY ARCHITECTURE

> Mode: architecture/design only. No source file was created,
> modified, or executed; no test was created, modified, or run; no
> browser was launched; no Playwright, Chromium, Selenium, Firefox,
> or any browser binary was invoked; no JavaScript was executed; no
> subprocess was spawned; no network access, DNS resolution, LLM
> call, MongoDB access, finding emission, or verdict was performed;
> no git operation was performed. All findings below come from
> read-only inspection of the repository at `/opt/watch`.

## 1. Verdict

**5G v1 ships as a deterministic offline browser harness with
`LIVE_BROWSER = False`. No live browser execution is authorized by
this architecture.**

The central property `SCOPE-EVALUATED == ACTUALLY-DIALED` **cannot**
be established for a real browser by browser-level configuration
alone. A browser is an autonomous network agent: it owns its own
DNS, redirect chain, subresource fetching, script-initiated fetch,
frames, WebSockets, WebRTC, prefetch, service workers, update
channels, and certificate-status traffic. None of these can be
bound to a 5C `DialBinding` from inside the page or from a
renderer-process interception hook with proof-grade assurance.
Therefore:

> **5G v1 = closed browser execution specification + offline
> deterministic harness (`FakeBrowserRunner`) + permanently blocked
> live runner. A real browser may only ever run inside a future,
> separately reviewed network/containment boundary (B5) that is
> BLOCKING for any live traffic. Until B5 closes, the offline
> harness is the only path through which the executor returns a
> sealed `EvidenceRecord`. No live browser process is ever spawned
> by 5G v1.**

Corollary verdicts, all DECIDED:

- Browser execution is NEVER itself a finding; the browser produces
  execution facts and observation-only evidence.
- LLM output is NEVER a verdict; no LLM participates in 5G at any
  stage.
- Only deterministic verifier logic in 5I may eventually classify
  evidence as CONFIRMED. 5G emits no CONFIRMED, NOT_VULNERABLE,
  VULNERABLE, severity, or finding.
- OOB/callback-based proof remains DENIED in 5G v1 with no
  skeleton shipped.

## 2. Security invariants

1. Only `require_allowed() == ALLOWED` plus a live, consumed-by-us
   authorization (`execution_class == "browser_verification"`),
   plus a `RESOLVED` `TargetResolution` with a coherent binding,
   plus a `VALID` payload artifact whose content hash matches the
   bound `ArtifactBinding.content_hash`, plus a payload that
   passes the 5G payload-safety gate, plus a closed B5 review,
   starts any browser process. **B5 is BLOCKING in v1; the others
   are necessary but not sufficient.**
2. The initial navigation URL is derived exclusively from the
   5B/5C/5D binding (scheme + canonical host + effective port +
   validated path/query from the artifact). No caller-supplied
   arbitrary target may override it.
3. Every navigation hop is a new scope decision. A redirect is
   never silently followed: each hop is re-evaluated against
   freshly read policy, and any out-of-scope hop aborts the run.
4. P (authorized/submitted payload) and O (executor-owned executed
   oracle) have separate identities and hashes. Submitted payload
   is never proof of execution.
5. The browser context is ephemeral and single-use: no persistent
   profile, no inherited state, no cross-execution leakage by
   construction.
6. No verdict, severity, confirmation, or finding field ever
   appears in the sealed record. Observation channels carry
   hashes and bounded samples only.
7. At-most-once execution (ledger CAS) and at-least-once evidence
   (seal/index/audit) are separate, reusing the 5H crash matrix.
8. `file://`, `data:`/`blob:`/`javascript:` as authority,
   downloads, and local-filesystem access are denied by URL-scheme
   policy, not by page cooperation.

## 3. Frozen contracts reused

- **5B (FROZEN):** `IssuedExecutionAuthorization` accepted only by
  typed reference; `(authorization_id, execution_id)` binding;
  `max_executions = 1`; liveness re-asserted pre-execution; CAS
  consume; `NEVER_ISSUERS` (LLM/scheduler/collector/verifier
  cannot mint); `execution_class = "browser_verification"` is an
  existing closed vocabulary member; `XSSDerivationContract` with
  the P/O dual-hash rule (`source_content_hash` vs executed
  payload hash) is the frozen P/O identity mechanism.
- **5C (FROZEN):** `TargetResolution` (`RESOLVED`-only input);
  canonical tuple `(program_name, canonical_host, scheme,
  effective_port)`; `DialBinding`; 8-answer ceiling;
  deterministic ids/hashes; `scope_view()`.
- **5D (FROZEN):** exact-host + single-level wildcard + absolute
  exclusion matching; program isolation; drift detection;
  `require_allowed()` triple gate; ALLOWED/DENIED/INCONCLUSIVE
  (INCONCLUSIVE never authorizes); per-hop independent evaluation;
  5-edge redirect cap inherited.
- **5E (FROZEN, pattern):** offline-harness posture,
  `LIVE_GATE_BLOCKED` discipline, translator/binding checks,
  `InMemoryAuditSink` shape for tests.
- **5F (FROZEN, pattern):** `LIVE_X = False` literal gate,
  closed-spec + blocked-live-runner structure, `*_EXECUTION_BLOCKED`
  closed code before any process primitive, AST boundary tests.
- **5H-core (FROZEN):** `EvidenceRecord` lifecycle
  `BUILDING → SEALED | INCOMPLETE`; `REQUIRED_OBSERVATIONS`
  already maps `browser_verification → ("browser",)`; the frozen
  `BrowserObservation` is the ONLY browser observation channel:
  `dialog_marker_hashes`, `oracle_event_hashes`,
  `eval_marker_hashes` (≤16 hashes each), `e1_observed`,
  `e2_observed`, `e3_observed` (advisory booleans, not verdicts),
  `executed_payload_hash` (O, never P), `page_url: RedactedUrl`,
  `storage_keys_hash`, `channels_truncated`, `round_id`,
  `submit_evidence_ref`; `EvidenceBuilder.begin()` +
  `attach_browser()` + `seal`/`seal_partial`; shared scrubber,
  hashing, ledger, audit, orphan semantics.
- **Stored-XSS architecture (FROZEN reference):** submit/read
  phase split, clean READ navigation (no payload/token bound into
  the read URL; only server-side persistence may deliver oracle
  material), per-attempt correlation tokens, exact-match oracle
  predicates (E1 dialog / E2 same-origin network oracle /
  E3 eval), anti-harvest property (D never on the wire; only the
  seed S travels).
- **Artifact (FROZEN):** `ArtifactReference` with plan-bound
  identity; `xss_payload` type with its byte ceiling; revalidation
  per `validate_reference_binding`.

## 4. Browser threat model

Attacker controls: payload bytes (validated, not trusted), target
hostname/URL (validated, not trusted), redirect `Location`s, every
response body/header, subresource content, DNS answers
(rebinding, rotation), sibling hosts, historical inventory, and —
once script runs — the full in-page JavaScript environment
(DOM, storage, workers, network APIs). Attacker goals: scope
escape via any secondary request surface; sibling-host and
cross-origin exfiltration; credential/secret capture into
evidence; OOB callback to attacker infrastructure; persistent
state implantation (service worker, storage, cache) that
poisons later executions; renderer/browser sandbox escape to the
operator host; finding fabrication (page-injected events that
mimic oracle signals); double-execution of one-shot
authorizations; response-bomb / dialog-bomb DoS against the
operator.

Out of scope for 5G: target-side exploit semantics; HTTP (5E) and
Nuclei (5F) transports; operator-key or CA compromise; 5I verdict
semantics (5G must not pre-decide them).

Why the browser is worse than 5E/5F: 5E owns every byte on a
pinned-IP transport it implements; 5F at least reduces to one
subprocess with one argv. A browser multiplexes dozens of
independent network agents (renderer, network service, extensions
process, updater, OCSP fetcher, prefetch predictor, WebRTC stack)
behind one automation handle. Securing the initial URL secures
approximately one of them.

## 5. Target/navigation model

Construction rule (DECIDED): the initial navigation URL is
`base_authority` (scheme + canonical host + non-default effective
port, from 5C) plus the artifact-bound path/query only. The
artifact supplies DATA (path/query), never authority. Exact-host
match against `resolution.canonical_host`; no eTLD+1 inference, no
suffix matching, no sibling access, no public-suffix-list
authorization, no IP-literal authorization unless the authorized
canonical host is itself that literal. Scheme and effective port
are explicit; non-default ports are part of identity.

Canonicalization: lowercase scheme/host, strip trailing-dot hosts
and userinfo, drop fragments, preserve query byte-exact for
hashing; any unparseable or non-http(s) input fails closed.

Redirects as new scope decisions (DECIDED): redirect ceiling 5
edges (reuse `redirect_hops`); navigation ceiling 1 page
(`browser_pages`) in 1 context (`browser_contexts`); canonical
visited set over (scheme, host, port, path, query); loop ⇒
`REDIRECT_LIMIT`; 6th edge ⇒ `REDIRECT_LIMIT`; every hop
re-evaluated by 5D against freshly read policy; IP-literal hop ⇒
`REDIRECT_NOT_IN_SCOPE`; https→http downgrade denied; HSTS
upgrades are observed facts, never silent authority changes; the
final URL is recorded as a `RedactedUrl` observation, never
reused as a future target.

## 6. Network-request enforcement model

DECIDED: **in-browser request interception (route handlers,
`expose_binding` telemetry, init-script hooks) is telemetry, not
enforcement.** It runs in the same trust domain as the attacker
(the renderer) or one TOCTOU step away from it, and therefore
cannot prove `SCOPE-EVALUATED == ACTUALLY-DIALED`. Enforcement
requires an out-of-process boundary: the page's packets must be
physically unable to leave the authorized destination set. That
boundary is B5 (netns + forced egress proxy + literal-IP-only
DNS stub + egress firewall), which is BLOCKING and is NOT
designed or implemented in 5G.

Per-surface disposition for any future live runner (v1 harness:
all moot — the harness performs no requests):

| Surface | Disposition |
|---|---|
| Main-frame navigation (initial) | ALLOW once, from closed spec only |
| Main-frame redirect hop | Per-hop scope re-evaluation; deny+abort on miss |
| Same-origin subresource (script/style/img/font) | BLOCKING / REQUIRES B5 (allowlist = authorized origin, enforced at egress) |
| Cross-origin subresource | DENY (abort; abort of a document load surfaces an error, never silent success) |
| iframe/frame (same-origin) | BLOCKING / REQUIRES B5 (frame counted against frame ceiling; sandboxed) |
| iframe/frame (cross-origin) | DENY (no cross-origin frame may load; its events are never evidence for the authorized target) |
| fetch/XHR | Same-origin only under B5; cross-origin DENY |
| WebSocket (`ws`/`wss`) | DENY in v1 (no live use case; handshake escapes document policy) |
| WebRTC (ICE/STUN/TURN/host-candidate gathering) | DENY (peer-to-peer and mDNS/host candidates bypass origin policy; requires B5 design before any relaxation) |
| DNS prefetch / preconnect / prerender | DENY (disable: attacker-triggerable resolution outside any hook) |
| Service workers / workers / shared workers | DENY registration in v1 (persistence + background network agency); existing registrations impossible by fresh-profile construction |
| Downloads | DENY (no download may start; a download attempt aborts the run as INCOMPLETE) |
| HSTS upgrade / mixed-content upgrade | Observation only; upgrade never widens authority |
| Mixed-content downgrade / ws-from-https | DENY |
| CSP | Treated as target-controlled content, never as executor policy; CSP reports (if any) are observations, never gates |
| Browser extensions | DENY (no extension may be installed, enabled, or loaded; automation profile forbids the extensions process payload) |
| Browser update / component update | DENY (updates disabled by policy; update traffic is out-of-scope agency) |
| OCSP/CRL/AIA certificate-status traffic | BLOCKING / REQUIRES B5 (cannot be disabled safely per-host; B5 egress must explicitly permit the PKI endpoints or use a pinned trust path under review) |
| Captive-portal detection | DENY (disabled; portal probes are uncontrolled destinations) |
| Proxy env vars / PAC / system proxy | DENY inheritance (closed environment, no `HTTP(S)_PROXY`, no PAC, no system-proxy pickup; under B5 the egress proxy is executor-configured, never environment-derived) |

No hand-wave: anything not on an egress allowlist derived from
the 5D-ALLOWed origin set does not leave the boundary. Until B5
exists, the table's ALLOW rows are exercised only by the offline
harness against scripted facts.

## 7. Context isolation model

Ephemeral single-use browser context, structurally incapable of
cross-execution leakage (DECIDED):

- Fresh profile directory per execution (hash/execution-bound,
  mode 0700, destroyed in `finally`); never the default profile.
- No inherited cookies, `localStorage`, `sessionStorage`,
  IndexedDB, CacheStorage, service workers, permissions,
  credentials, password manager, autofill, sync identity,
  extensions, themes, or prior HSTS/HPKP state.
- Exactly 1 context and 1 page per execution (reuse
  `browser_contexts`, `browser_pages`); popups blocked
  (`popup count` ceiling 0 in v1 — a popup attempt is an abort
  event, not a new page).
- Shared cache disabled; network cache per-context and discarded
  with the profile.
- Storage writes during the run are observations (key hashes
  only, values never persisted raw); pre-existing storage cannot
  exist by construction, so any storage read of executor-planted
  state is a TestPlan/artifact bug, not evidence.
- Timezone/locale/geolocation fixed to deterministic neutral
  values; sensors (camera/mic/location) denied by permission
  default-deny.

## 8. XSS payload/oracle model

Unrestricted caller JavaScript is NOT an execution primitive.
The only script that runs in the page is (a) target-served
content and (b) the executor's own bounded instrumentation —
never caller-authored automation scripts (`page.evaluate` with
attacker-influenced strings is forbidden; evaluator-owned
read-only probes, if ever needed, are a B5-review item, not v1).

- **P (payload):** bytes bound to the authorization artifact
  (`content_hash`, plan-bound `artifact_id`); bounded by the
  `xss_payload` ceiling; inert DATA outside the target's own
  reflection/storage semantics; SHA-256 identity immutable for
  the run. P is submitted (reflected/query case: bound into the
  navigation query under the authorized parameter; stored case:
  submitted via the authorized submit channel, never via browser
  form automation against arbitrary endpoints).
- **O (oracle):** executor-owned, execution-specific,
  unpredictable (per-execution secret seed; only the seed travels,
  D is derived at observation time — anti-harvest preserved),
  bound to `(execution_id, canonical origin)`, bounded
  (16-hex-char D; bounded dialog/network/eval channels),
  non-sensitive (D is a random execution tag, not a credential).
  `executed_payload_hash` (O) is recorded on
  `BrowserObservation` and the derivation binding; P's hash is
  recorded separately. `submitted == proof` is structurally
  impossible: the verifier compares O-derived observations, and
  the executor never asserts that comparison.
- Pipeline separation: payload P → browser execution (fact
  collection) → observation (hashes + bounded samples) →
  deterministic verification in 5I. The executor owns the middle
  two; it never performs the last.

## 9. Frame/origin model

- Same-origin iframe: allowed only under B5, sandboxed
  (`allow-scripts` only as required by the test semantics under
  review; never `allow-top-navigation` / `allow-popups`);
  frame events attributed by frame origin; counted against the
  frame ceiling.
- Cross-origin iframe: never loads; any navigation to a
  cross-origin frame aborts the run (INCOMPLETE, never evidence
  for the authorized target).
- `window.open`/popups: blocked; opener relationships must not
  exist (`noopener` semantics by default-deny; no `window.opener`
  bridge to the authorized page).
- `postMessage`: inbound messages from non-authorized origins are
  ignored and never evidence; authorized-origin messages are
  observations (origin + bounded payload hash), never proof.
- `document.domain` relaxation: treated as hostile; a page that
  relaxes its origin is observed, and cross-origin attribution
  still applies (relaxation never merges origins for evidence).
- `Origin`/`Referer`/`referrer-policy`: outgoing request headers
  are target-observable facts; strict `referrer-policy`
  (`no-referrer` for any secondary surface under B5) so tokens
  never leak via Referer; tokens in URLs follow the stored-XSS
  rule (READ navigation is clean).

Cross-origin execution MUST NOT silently become proof: any
oracle-shaped signal (dialog text, network path, eval marker)
whose origin is not the authorized canonical origin is dropped
and logged as a blocked-event count, never recorded as an
oracle observation.

## 10. Resource ceilings

Reuse 5H `CEILINGS`; define nothing locally. Applicable frozen
values: `browser_wall_seconds = 15` (whole-run wall clock,
externally enforced with process-tree kill), `browser_pages = 1`,
`browser_contexts = 1`, `redirect_hops = 5`,
`requests_per_execution = 7` (upper bound on recorded
navigation/request events handed to evidence),
`response_transport_bytes`, `response_evidence_sample_bytes`,
`decompressed_bytes`, `compression_ratio`,
`temp_storage_bytes` (profile + capture scratch).

Required 5H extension (identified, NOT invented here): v1 needs
named dimensions for dialog count, frame count, popup count,
console-entry count, oracle-event count, DOM snapshot bytes,
and storage-observation bytes. Until 5H adopts them, 5G v1 uses
the existing generic discipline (stop-appending at small fixed
review-time bounds documented in the implementation phase) and
marks the extension as a blocking prerequisite for any live
runner, since an unbounded channel is a memory-exhaustion vector
(dialog-bomb/console-bomb).

## 11. Evidence model

5H-core only. One sealed `EvidenceRecord` with
`execution_class = "browser_verification"` and a single
`BrowserObservation`; `http`/`nuclei` unset. Channels:

- Navigation events (bounded list: final `RedactedUrl`,
  redirect chain as redacted URLs + per-hop scope decision
  codes), request/response metadata (hashes + allowlisted
  headers, never raw bodies), frame info (origin + sandbox
  flags, no content), dialog observations (kind + message hash
  + bounded redacted sample), oracle observations (E1/E2/E3
  predicate inputs as hashes + advisory booleans), DOM marker
  observations (hashes of exact marker strings + location kind),
  console observations (bounded, scrubbed), browser errors
  (closed codes), timing facts (durations only), execution
  identity (`execution_id`, `authorization_id`, `round_id`
  where applicable), P hash and O hash separately.

Scrub-before-hash throughout with the shared scrubber; no
second scrubber. Secrets (tokens, cookies, auth material)
never persist even in samples. FORBIDDEN: `Finding`, `verdict`,
`severity`, `CONFIRMED`, `NOT_VULNERABLE`, or any semantic
classification — structurally excluded by `extra="forbid"` plus
boundary tests.

## 12. Failure/crash model

Fail closed; no failure may produce a positive-shaped record.
Mapping (DECIDED, reusing the 5H crash matrix):

- Browser startup failure / binary missing / unsupported
  platform → pre-start: no evidence, ledger `UNKNOWN` only if
  consume already happened (else re-registrable), code
  `BROWSER_START_FAILED`, retry requires new authorization once
  consumed.
- Renderer/page crash, navigation timeout, request timeout,
  dialog hang (auto-dismiss deadline then abort), unexpected
  popup/download, service-worker registration attempt →
  transport-ambiguous: ledger `UNKNOWN`, no evidence bytes,
  codes `BROWSER_TIMEOUT` / `BROWSER_CRASH` /
  `NAVIGATION_BLOCKED`, retry only under new authorization.
- Scope-evaluator ambiguity / redirect out-of-scope / hop
  re-evaluation failure → `INCOMPLETE` seal with explicit
  incomplete reason when partial observations exist and are
  hash-verifiable, else `UNKNOWN`; never an allow.
- Network-interception failure (future B5 hook reports unhealthy)
  → `UNKNOWN`, run refused before navigation.
- Evidence-seal failure → `EVIDENCE_SEAL_FAILED`, ledger
  `UNKNOWN`, no partial record promoted.
- Audit failure pre-launch → no browser start, `AUDIT_GAP`;
  post-seal → separate `AUDIT_GAP` entry, sealed evidence
  untouched.
- Authorization consume ambiguity / start ambiguity → 5H
  semantics verbatim (`EXECUTION_ALREADY_CONSUMED` /
  `OUTCOME_UNKNOWN`).
- Process-cleanup ambiguity (renderer or worker survives kill
  deadline) → `UNKNOWN`, operator-alert accounting entry, and —
  under B5 — namespace teardown as the backstop; in v1 the
  harness has no child processes by construction.

There is no code path from any of the above to CONFIRMED,
VULNERABLE, or any finding-shaped output.

## 13. Live execution gate

`LIVE_BROWSER = False` for v1 (DECIDED, literal constant, not
configurable by environment, constructor, artifact, flag, or
database value — same discipline as 5E/5F).

Why browser-level configuration alone is insufficient
(explicit): route/abort hooks execute in the browser's own
process tree and observe requests the browser chooses to
disclose, after the browser has already resolved DNS
(prefetch, speculative, and renderer-initiated lookups escape
hooks); service workers, WebRTC, OCSP, update, and
captive-portal traffic never traverse page-level hooks;
`data:`/`blob:` execution contexts have no origin to check at
request time; a compromised or buggy renderer can bypass
in-process policy entirely. Enforcement must therefore be a
property of the environment (packets cannot physically leave),
not of the browser's cooperation. That environment is B5.

Future live prerequisites (B5, BLOCKING, not implemented now):
isolated network namespace per execution; forced egress proxy
with an allowlist derived from the 5D-ALLOWed origin set;
literal-IP-only DNS stub (no recursive resolver, no search
domains); egress firewall default-deny with explicit PKI-endpoint
handling; process containment (dedicated UID, no new privileges,
read-only root except scratch); browser sandbox enabled and
verified (never `--no-sandbox`); cgroup CPU/memory/IO caps;
seccomp/landlock profile denying raw sockets, packet sockets,
mount, and ptrace; full process-tree cleanup (session leader +
killpg SIGTERM→SIGKILL with namespace teardown backstop);
binary provenance (pinned browser build hash).

## 14. Legacy compatibility analysis

- `ai/verification/browser_executor.py` (~1400+ lines,
  `BrowserEvidenceExecutor` + `_PlaywrightSession` launching
  real headless Chromium, route-based same-origin abort,
  capability-protected binding transport, E1/E2/E3 channels):
  **dangerous-if-reused-live.** Its same-origin route policy is
  exactly the in-browser telemetry-not-enforcement pattern §6
  rejects as proof; its test suite exercises live local servers
  and optionally real Chromium. Disposition: **HARD-GATE** —
  must never run outside injected fakes/loopback fixtures, must
  never be wired to 5B authority, and its live session
  constructor must eventually be retired or placed behind the
  B5 review. Reusable from it: the P/O vocabulary, the
  capability-transport idea (as telemetry hardening, not as a
  network guarantee), and the E1/E2/E3 predicate shapes for 5I.
- `ai/verification/oracle.py` (S/D derivation, anti-harvest,
  `ORACLE_PATH_PREFIX`, E1/E2/E3 predicates): **REUSE** as the
  frozen oracle math; contains no classification logic to retire.
- `ai/verification/verifier.py`, `xss_pipeline.py`,
  `xss_case_builder.py`, `composite_executor.py`,
  `http_executor.py` (verification dir): **UNTOUCHED**; any path
  that converts browser evidence directly into a finding must be
  identified at 5G-implementation time and hard-gated so 5I is
  the sole classification authority.
- `ai/researcher/xss_orchestrator.py`,
  `xss_researcher.py`, `xss_llm_researcher.py`,
  `ai/schemas/xss*.py`: research-side (hypothesis/payload
  proposal); **UNTOUCHED**; 5G consumes only validated artifact
  bytes, never researcher objects.
- 5B/5C/5D/5E/5F/5H modules: **UNTOUCHED**; reused by reference
  (§3). The legacy `to_findings`-shaped thinking (cf. 5F §20)
  must not be reintroduced for XSS: no `matched`-boolean-to-
  finding adapter may exist in 5G.

## 15. Blocking prerequisites

- **B1 = BLOCKED** — production AddressSource selection/review
  remains pending (inherited; 5G uses injected fakes only).
- **B2 = BLOCKED** — production Mongo
  authorization/ledger/audit/evidence adapters + sweep remain
  pending (inherited).
- **B4 = deferred/blocking for the later production
  template/payload-corpus workflow** — payload corpus
  source-of-truth review outstanding (inherited shape).
- **B5 = BLOCKED (new)** — browser network/containment boundary
  per §13 (netns, forced egress proxy, DNS stub, firewall,
  containment, browser sandbox, cgroups, seccomp/landlock,
  tree cleanup, pinned browser build). The SOLE gate that can
  ever flip `LIVE_BROWSER`; requires separate review.
- **5H browser-ceiling extension = pending** — named dimensions
  for dialog/frame/popup/console/oracle-event counts and DOM
  snapshot bytes (§10); blocking for any live runner.

## 16. Proposed 5G v1 components

`ai/execution/browser_executor.py` (new, offline, deterministic):
`LIVE_BROWSER = False` + `B5_STATUS`; `BrowserExecutionSpec`
(frozen: execution/authorization/program/host/scheme/port/target
string/artifact + P hash/O derivation descriptor/argv-equivalent
launch parameters/context profile descriptor/closed environment/
caps/schema version); `BrowserRunner` protocol
(`launch(spec) -> BrowserRunResult`, spec-only input);
`FakeBrowserRunner` (records invocation; scripted navigation
facts, oracle-channel facts, dialog facts, timeout/killed
states); `LiveBrowserRunner` (always raises
`BROWSER_EXECUTION_BLOCKED` before any process primitive);
`B5IsolatedBrowserRunner` placeholder (always raises);
payload-safety gate reusing artifact validators + 5G deny list
(scheme policy, no file/data/blob authority, no download
primitives, bounded size); P/O identity helpers reusing oracle
math (no new crypto); `execute_browser` 20-step lifecycle
mirroring 5F §10 ordering with `BrowserObservation` evidence.
No Playwright import in the 5G module; no browser binary
reference beyond a server-controlled constant used only in the
pure spec builder.

## 17. Proposed test strategy

Deterministic stdlib `unittest`, offline, mirroring the 5F suite
shape (~100 cases): authorization matrix (expired/consumed/
revoked/forged/wrong execution/class/program/host/artifact/
stale scope); payload matrix (hash drift, oversized, forbidden
scheme, `file:`/`data:`/`javascript:` authority, download
primitive, OOB/callback marker); authority matrix (no target
override from payload or caller); navigation matrix (redirect
chain, loop, cross-origin hop, downgrade, IP hop, port hop);
context matrix (fresh profile proofs: no cookie/storage/extension
inheritance representable in the spec); oracle matrix (P/O hash
separation, wrong-origin oracle signal dropped, anti-harvest
property test on derivation); evidence matrix (observation-only,
no verdict names, scrub-before-hash, hash correctness,
E1/E2/E3 booleans are advisory); crash matrix (start failure,
renderer crash, timeout, popup/download abort, seal failure,
pre/post audit gap, replay); boundary matrix (AST: no
`playwright`/`selenium`/browser/process/transport/DNS imports or
calls, no `evaluate`-with-string primitive, no finding/verdict
names, `LIVE_BROWSER is False` literal, non-configurable gate).
Plus regression: `test_knowledge_store`,
`test_xss_researcher`, `test_xss_llm_researcher`,
`test_openrouter`, evidence/authorization/scope suites, and the
5E/5F suites untouched and green.

## 18. Explicit statement of what is NOT implemented

No live browser runner; no B5 boundary (no netns, proxy,
firewall, DNS stub, containment, sandbox profile, cgroups,
seccomp/landlock, or cleanup logic); no Playwright/Chromium/
Selenium/Firefox integration; no `page.evaluate` automation
primitive; no WebSocket/WebRTC/service-worker support; no
download pipeline; no OOB collector; no finding/verdict/severity
logic; no 5H ceiling redefinition (extension only identified);
no modification to any legacy file; no production adapters (B2);
no corpus review (B4).

## 19. Recommended implementation order

1. 5G v1 closed spec + `FakeBrowserRunner` + blocked live
   runner (mirrors 5F.1/5F.2).
2. Payload-safety gate + P/O identity helpers (reuse oracle
   math; no new crypto).
3. `execute_browser` lifecycle + `BrowserObservation` evidence
   integration (mirror 5F ordering, 5H-core reuse).
4. Offline test suite + AST boundary tests.
5. 5H browser-ceiling extension proposal (separate review).
6. B5 boundary design review (separate phase; live stays
   BLOCKED until it closes).
7. Only then: live-runner implementation under B5, then 5H
   Evidence Store hardening, then 5I verifier, then 5J.

## 20. Exact next phase recommendation

Proceed to **5G implementation (v1 offline harness as specified
in §16)** only after this architecture is reviewed and approved.
Do not reorder phases: after 5G comes **5H Evidence Store**,
then **5I Deterministic Verifier**, then **5J Scheduler/E2E**.
No live browser work may begin before B5 is separately reviewed
and closed.

---

- code modified = NO
- tests added = NO
- browser launched = NO
- JavaScript executed = NO
- network = NO
- DNS = NO
- subprocess = NO
- MongoDB = NO
- Git = NO
- LIVE_BROWSER = False for v1
- CONFIRMED verdict generation = NO
- finding generation = NO
- OOB = DENIED

REPORT:
 /opt/watch/agent-reports/browser-xss-executor-architecture.md
