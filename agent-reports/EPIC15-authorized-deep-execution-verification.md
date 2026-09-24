# EPIC15 — Authorized Deep Execution Verification v1

**Baseline:** `main = 76a9c0a5` (EPIC14 promoted)
**Selected path:** **C** — the capability cannot safely exist in this
environment; the boundary is established honestly and the chain stays
fail-closed. The maximum *safe* capability (a lineage-bound
served-document DOM source→sink verifier) is implemented and real.

## 1. Capability audit (code-verified)

Every claim below was read from the code at `main = 76a9c0a5`; no
capability was inferred from dependencies alone.

**A. Exists and is reusable**

* `ai/execution/browser_executor.py` — the platform's closed-spec
  browser/XSS executor: `LIVE_BROWSER = False` (a literal, with no code
  path that sets it `True`), `B1_STATUS`/`B2_STATUS`/`B4_STATUS`/
  `B5_STATUS` all `BLOCKED`, `BROWSER_EXECUTION_BLOCKED`, a deterministic
  `FakeBrowserRunner` (no I/O), `SERVER_CONTROLLED_BROWSER_ID`, and a
  P/O trust separation in which a submitted payload is never proof of
  execution.
* `ai/limits/ceilings.py::CEILINGS` — frozen ceilings including
  `browser_wall_seconds=15`, `browser_pages=1`, `browser_contexts=1`,
  `redirect_hops=5`, `requests_per_execution=7`,
  `browser_dom_observation_bytes=8 KiB`, `browser_popup_events=0`.
* `ai/execution/b3_boundary.py` — `EgressPolicy` (authorization-bound
  egress allowlist), `check_egress_dial`, `check_request_bounds`,
  `acquire_sandbox`/`release_sandbox`; `ai/execution/netns_sandbox.py`.
* `ai/verification/deterministic/*` (classifier, gate, oracle, …) and
  `ai/verification/oracle.py`.
* EPIC12: `verification/actions.py` already declares
  `TRACE_DOM_SOURCE`/`TRACE_DOM_SINK` (READ_ONLY, `implemented=True`,
  "no browser is launched") and `DELIVER_CONTROLLED_PAYLOAD`/
  `OBSERVE_EXECUTION` (SAFETY_ACTIVE, `implemented=False`, `BLOCKED`);
  `verification/executors.py` implements a DOM trace over a recorded
  document.
* EPIC13 acquisition (transport seam, limits, markers, context, plan,
  capabilities) and EPIC14 (taxonomy/provenance/persistence guard).

**B. Exists but is disabled**

`LIVE_BROWSER`, `LIVE_NUCLEI`, `LIVE_TRAFFIC_ENABLED`,
`HTTP_PROBE_PILOT_ENABLED` — all `False`. `LiveBrowserRunner.launch`
refuses before any primitive. The legacy playwright executor is
non-production.

**C. Exists but is unsafe/unscoped**

`ai/verification/browser_executor.py` (2,053 lines) — playwright-based,
**no authorization or scope gates**, not part of the frozen authority
chain; its only production caller (`watch_xss_verify.py`) was permanently
disabled (Phase 5K P0-1). It must never be reused, and EPIC15 does not
reference it.

**D. Completely absent**

* The `playwright` package is **not installed** in the production
  interpreter (only stale browser *binaries* remain in
  `~/.cache/ms-playwright`).
* The **B5 browser network/containment boundary** — explicitly
  "BLOCKED: browser network/containment boundary remains pending".
* A real Linux network namespace (no root / `CAP_SYS_ADMIN`), so the
  sandbox machinery fails closed with `SANDBOX_UNAVAILABLE`.
* Any execution-evidence lane reachable from the bounded research worker.

**The platform's own rationale is decisive:** a real browser is an
autonomous network agent (its own DNS, redirect chain, subresources,
script-initiated traffic, frames, workers, prefetch, certificate-status
traffic). In-browser hooks are telemetry, never enforcement, so
`SCOPE-EVALUATED == ACTUALLY-DIALED` cannot be established without B5.
A safe live browser capability therefore **cannot exist here** → PATH C.

## 2. What EPIC15 implements

New package `backend/research_agents/verification/deep/` (9 modules):

| Module | Responsibility |
| --- | --- |
| `capability.py` | The capability contract: lanes, states, blockers, switch state read **through** from the platform, ceilings read-through |
| `isolation.py` | Isolation policy (§10), navigation/redirect policy (§11), credential policy (§12) |
| `dom.py` | The lineage-bound served-document DOM source→sink verifier (§5/§6/§13) |
| `execution.py` | Execution attempts and the explicit result-state machine (§16/§18) |
| `exploitability.py` | `PAYLOAD_EXECUTION` ≠ `EXPLOITABILITY_ESTABLISHED` (§9) |
| `budget.py` | Budget reuse of the frozen ceilings — **no new ceiling** (§17) |
| `producer.py` | The trusted deep-observation producer with attestation (§14/§15) |
| `service.py` | Orchestration, authorization at every stage, SOC projection (§16/§21/§27) |
| `__init__.py` | The boundary statement |

Integration (reuse, never duplication): the EPIC13 plan now maps the DOM
stage to the existing read-only `TRACE_DOM_SINK` action; the EPIC13 XSS
capability contract moves `DOM_SINK_IDENTIFIED` from `not_acquirable` to
`evidence` (LIMITED) while `PAYLOAD_EXECUTION` and
`EXPLOITABILITY_ESTABLISHED` stay unavailable with reasons naming
`LIVE_BROWSER` and B5; the chain projection gains
`deep_verification_block()` (§27).

## 3. The DOM verifier: what changed and why it matters

EPIC12's `dom_flow()` was **presence-only**: if the document mentioned any
DOM source pattern *and* any sink pattern anywhere, it produced
`DOM_SINK_IDENTIFIED`. EPIC15 replaces that with a lineage-bound check:

1. the observed parameter must be read from a DOM source into a variable
   (bounded variable-name tracking over inline scripts), and
2. that variable must reach a dangerous sink within a bounded window.

A document with `location.search` in one script and
`document.write('static')` in another is now `SOURCE_ONLY`, not a sink
finding. Source and sink vocabularies are EPIC12's own closed sets,
imported — never re-declared, never widened.

The analysis is bounded by `browser_dom_observation_bytes` and labelled
`served_document_static_analysis` / `epic15-dom-trace-1`. It is **not** a
JavaScript engine and **not** complete taint analysis, and it never
establishes that a sink executed.

## 4. Execution: the honest capability boundary

Every attempt produces exactly one state. Only `EXECUTION_NOT_OBSERVED`
and `DOM_SINK_NOT_OBSERVED` may become negative security evidence, and
only when the instrumented run genuinely reached the relevant point.
Every other state — `BROWSER_UNAVAILABLE`, `BROWSER_START_FAILED`,
`NAVIGATION_BLOCKED`, `REDIRECT_OUT_OF_SCOPE`, `AUTHORIZATION_MISSING`,
`AUTHORIZATION_EXPIRED`, `TIMEOUT`, `BUDGET_EXHAUSTED`,
`INSTRUMENTATION_UNAVAILABLE`, `INCONCLUSIVE` — is a **refusal**, and a
refusal produces a NOT_TESTED observation, never a negative one.

Check order (all fail-closed): authorization → isolation → budget →
navigation/redirect policy → platform lane → injected offline harness.

## 5. Security review (§26)

| Boundary | Position |
| --- | --- |
| SSRF | Navigation and redirect policy deny loopback, RFC1918, link-local, `0.0.0.0/8`, IPv6 loopback/ULA/link-local, cloud metadata (by address **and** by name), any non-http(s) scheme, any port outside 80/443, and any host outside the authorized set |
| Browser sandbox escape | No browser is created here; the live lane is closed by a literal switch plus B1/B2/B4/B5 |
| localhost / private network / metadata | `DESTINATION_BLOCKED` |
| `file://` / arbitrary protocols | `SCHEME_BLOCKED` |
| Cookie / credential leakage | `CREDENTIAL_BLOCKED` for `authorization`, `cookie`, `proxy-authorization`, `set-cookie`, `x-api-key`, `x-auth-token`; isolation forbids stored cookies, profiles, credentials, extensions |
| Host filesystem / downloads | Forbidden by the isolation policy (`host_filesystem=False`, `downloads=False`) |
| Uncontrolled JS / navigation | No JavaScript runs; navigation is bounded and policy-checked; popups pinned at 0 |
| Redirect escape | `REDIRECT_OUT_OF_SCOPE` stops the attempt |
| Unbounded resources | Every bound is read through from the frozen ceilings; the budget is consumed per attempt/navigation/runtime and refuses when exhausted |
| Authorization bypass | Checked at every stage, before any primitive; absence is `BLOCKED` |
| Forged execution evidence | The producer derives the type from the attempt state (a caller cannot submit an `evidence_type`); EPIC14's mismatch rule catches declared-vs-authoritative divergence; a consistent-shape forgery is bounded by the required-evidence rule and the persistence attestation — **stated, not hidden** |
| LLM escalation | The LLM cannot create evidence, sink evidence, execution, or exploitability; advisory rows are never confirmation evidence |

No new security boundary is knowingly broken. No live flag is flipped and
no live capability is introduced.

## 6. Production validation (§21/§22/§23) — READ-ONLY

Run against the promoted runtime store; no writes, no browser, no network.

* Capability: browser lane `NOT_IMPLEMENTED` / closed; all four blockers
  reported; `live_execution_in_production=False`; DOM lane `LIMITED`.
* Deep run with **no authorization** → `DEEP_BLOCKED` /
  `AUTHORIZATION_MISSING`, zero evidence.
* Deep run **authorized but with no browser** →
  `DEEP_CAPABILITY_UNAVAILABLE` / `BROWSER_UNAVAILABLE`, `refused=True`,
  zero evidence, `produces_confirmation_evidence=False`, SOC projection
  `execution: unavailable`.
* DOM trace on served material: lineage → `SOURCE_AND_SINK_LINEAGE`
  (`location_search → innerHTML`); presence-only → `SOURCE_ONLY`,
  `reaches_sink=False`.
* The attacks: `xss_parameter_inventory` + `PAYLOAD_EXECUTION` and
  `xss_parameter_inventory` + `DOM_SINK_IDENTIFIED` both classify
  authoritatively as `PARAMETER_OBSERVED` with a recorded mismatch.
* Network policy: in-scope allowed; loopback, metadata, `file://`, an
  out-of-scope host and a non-standard port all blocked; a redirect to
  localhost is `REDIRECT_OUT_OF_SCOPE`; a cookie header is
  `CREDENTIAL_BLOCKED`.
* **`cand-7c229c48c455`** (20 real `xss_parameter_inventory` rows):
  `BLOCKED`, `confirmed=False`, verification state `BLOCKED` — unchanged,
  and its historical evidence was not touched.

**Real positive validation (§23): not performed, and no fake positive was
created.** No genuinely authorized target exists and no safe browser
capability exists, so the correct result is the capability-blocked
validation above.

## 7. Tests

| Suite | Tests |
| --- | --- |
| `test_epic15_capability_isolation.py` | 90 |
| `test_epic15_dom.py` | 46 |
| `test_epic15_execution.py` | 76 |
| `test_epic15_verdict_matrix.py` | 124 |
| **EPIC15 total** | **336** |
| EPIC11 + EPIC12 + EPIC13 + EPIC14 (regression) | **1,437** |
| Combined | **1,773** |

Coverage: capability, browser isolation, authorization, network policy,
redirects, DOM source/sink, execution states, exploitability, provenance,
evidence, chain/verdict matrix (§19 A–H), persistence, the 20 adversarial
cases (§24), LLM boundary, budget, regression (`cand-7c229c48c455`),
integration and the SOC projection.

**Full-suite regression (worktree discovery):**

    Ran 12901 tests in 170.068s
    FAILED (failures=243, errors=129, skipped=17)

Pre-EPIC15 baseline: 12,563 tests, the same 243 failures / 129 errors.
The 308 unique failing test names are **identical** to the baseline
(`comm` diff empty): **zero new failures, zero EPIC11/12/13/14/15
failures**. The +338 tests are the new EPIC15 modules; the failures are
the pre-existing artifact-dependent suites (report/CLI/artifact tests that
fail on this host regardless of code).

## 8. Honest deviations and limits

* **Path C, not B.** A narrowly-scoped live browser was judged
  *unsafe rather than impractical*: without B5, `SCOPE-EVALUATED ==
  ACTUALLY-DIALED` cannot be established, and a browser that cannot be
  scope-bound would be an SSRF primitive with a JavaScript engine
  attached. The mission's own rule — "If it cannot be safely implemented
  in the current environment, document the exact capability boundary and
  leave the chain fail-closed" — applies.
* **Three EPIC13 tests were updated** (`test_epic13_adversarial.py`,
  `test_epic13_regression_cand_7c229c48c455.py`) because they pinned the
  old statement "DOM analysis is unavailable". The boundary genuinely
  moved: served-document DOM analysis is now available (read-only, no
  browser); execution and exploitability remain unavailable. The
  replacements assert the new truth, including that the DOM trace action
  is read-only and needs no network.
* `PAYLOAD_EXECUTION` remains unreachable in production, so
  `EXPLOITABILITY_ESTABLISHED` is too — fail-closed by construction, not
  by policy alone.
* A consistent-shape forged row is not caught by the mismatch rule (an
  EPIC14 limit, re-stated here in a test rather than papered over).

## 9. Success criterion

> Did attacker-controlled input actually reach a security-relevant
> execution sink under an authorized, isolated verification environment?

**In production: no claim is made, and none can be.** The answer is
`BROWSER_UNAVAILABLE` / `CAPABILITY_UNAVAILABLE` with the exact blocker
named. Where material exists, the layer answers the strictly weaker,
honest question — *does a DOM source carrying the observed parameter
reach a dangerous sink in the served document?* — and records the
instrumentation method and version that produced the answer. A confirmed
XSS alert therefore still requires real authorized execution evidence
that this runtime cannot manufacture.
