# XSS Confirmation State Machine — Implementation Plan (Oracle Integration)

**DESIGN / IMPLEMENTATION PLAN ONLY**

**NO SOURCE CODE WAS MODIFIED**

**Repository:** `/opt/watch`
**Date:** 2026-09-02
**Type:** Security-grade implementation plan for the NEXT phase: integrate
the execution oracle (S/D, E1/E2/E3, anti-harvest) into the XSS confirmation
state machine.

This document is a plan only. It specifies what MUST / MAY / MUST NOT change,
exact predicates, binding rules, trust assignments, a test matrix, and an
ordered implementation sequence. No file was modified, no test was changed,
no behavior was altered, nothing was committed or pushed.

---

## 1. Scope

**IN SCOPE**

- REFLECTED XSS confirmation.
- DOM XSS confirmation.
- The shared browser-classification demotion (the current DOM/mutation
  chain+token CONFIRMED false-positive path must be demoted to POTENTIAL).
- Oracle-attempt planning, execution, binding, and classification.
- run-salt injection and anti-replay re-derivation.
- Anti-harvest invocation in the confirmation flow.
- Findings/audit fields needed to record what proved execution.

**EXPLICITLY OUT OF SCOPE**

- STORED XSS SUBMIT → READ protocol.
- MUTATION XSS redesign (mutation uses the same shared browser branch as DOM
  today; the branch demotion necessarily affects it, but no mutation-specific
  logic, snapshots, or semantics are added).
- `new Function` instrumentation.
- Crawler / parameter-discovery / LLM / knowledge-store redesign.
- Nuclei / CVE pipeline.
- `NOT_VULNERABLE` production (remains never-produced).
- Out-of-band canaries.
- Authenticated contexts, CSRF, multi-field forms, async stored rounds.

---

## 2. Architecture Baseline (verified against source)

- `XSSCaseBuilder` produces cases with `xss_type="unknown"` (context
  `unknown`). The plan builder treats unknown as a reflected pair
  (HTTP + browser) — that pairing is preserved.
- `XSSOrchestrator` never classifies; `XSSVerifier` is the sole classifier.
- `attempt_id` includes payload, origin, attribution, mode, phase.
  `logical_pair_id` excludes mode and phase, includes method. HTTP and
  browser attempts for the same candidate payload share `logical_pair_id`.
- `correlation_token` is page-visible, identity-only, never a secret.
- `_enforce_evidence_binding` checks `evidence.attempt_id == attempt.attempt_id`,
  `evidence.request_url == attempt.endpoint`, `evidence.request_method ==
  attempt.method`. `intended_request_url` / `actual_request_url` exist on
  both executors' evidence but are NOT yet bound by the verifier.
- Browser executor: GET + query only, fresh context, same-origin policy,
  `dialog_events`, `oracle_network_events` (only `/.watch-oracle/<D>`,
  excluded from the generic sink), `eval_invocations` (eval + string
  setTimeout, 240-char bound), capability-protected transport, 5 s window.
- `ai/verification/oracle.py`: `oracle_seed(run_salt, attempt_id, phase)`,
  `oracle_value_from_seed` (W), `OraclePlanner.plan(...)`, `evaluate_e1_dialog`,
  `evaluate_e2_network`, `evaluate_e3_eval`, `PreExecutionInput`,
  `anti_harvest_violations(seed, oracle_value, pre)`. No classification logic.
- `run_salt` exists ONLY in `oracle.py` and tests. Nothing generates it in
  the pipeline; nothing invokes `OraclePlanner` in the pipeline; the verifier
  never calls the oracle predicates; `build_verification_attempt` never sets
  `oracle_seed`/`oracle_value`/`oracle_version`.
- `XSSVerifier(executor)` is constructed in production/test composition with
  a single positional executor; a defaulted new keyword keeps this compatible.

---

## 3. Core Security Question — What Evidence Moves Each Stage

Only the executor-owned oracle channels may establish execution. Data-stage
signals are explicitly demoted.

| Stage | Authority | Evidence required |
|---|---|---|
| 1 REFLECTION (S1) | Verifier re-check of `observed_correlation_token` | HTTP reflection at meaningful location, exact token, no WAF BLOCK/TRANSFORM |
| 2 SOURCE_REACHED (S2) | Advisory (attribution) | Hooked source read of `attempt.parameter` |
| 3 SINK_REACHED (S3) | Advisory (attribution) | Hooked sink with markerset in recorded value |
| 4 JAVASCRIPT_EXECUTION (S4) | **Executor-owned oracle ONLY** | E1 (dialog exact D) OR E2 (path exact `/.watch-oracle/<D>`) OR E3 (eval-family exact P, ≤240) |
| 5 OBSERVABLE_EFFECT (S5) | Executor-owned oracle | E2 fired (attacker-chosen network effect); E1/E3 do NOT grant S5 |
| 6 CONFIRMED | Verifier (sole classifier) | Class rule (below) + binding + freshness + anti-harvest |

**The implementation must NEVER confirm from:** payload reflected, source
reached, sink reached, correlation token in a runtime channel, benign network
request, DOM mutation, console output, storage write, LLM claim, or any
executor advisory boolean. Each of these caps at POTENTIAL (S1/S3), except
where a real E1/E2/E3 oracle event independently establishes S4.

---

## 4. E1 / E2 / E3 Semantics (exact, non-identical strength)

### 4.1 E1 — dialog oracle

```
E1 ≡ ∃ d ∈ evidence.dialog_events:
        d.kind ∈ {alert, confirm, prompt}
        AND d.message == D            (exact full-string)
        AND is_valid_oracle_value(D)
        AND D == W(attempt.oracle_seed) (recomputed by verifier)
        AND attempt-level binding + run freshness hold
        AND anti_harvest(pre-execution material) == []    (D ∉ pre-execution)
```

- Transport: Playwright `page.on('dialog')` — executor-owned, page-unforgeable.
- Establishes: **JAVASCRIPT_EXECUTION only.** Not OBSERVABLE_EFFECT.
- Strength: equal to E2 for execution proof (both are anti-harvest
  computation-only channels). E1 cannot additionally prove attacker-chosen
  network effect.

### 4.2 E2 — network oracle

```
E2 ≡ ∃ n ∈ evidence.oracle_network_events:
        n.is_navigation == False
        AND same_origin(n.url, attempt.endpoint)   (exact origin tuple)
        AND unquote(urlsplit(n.url).path) == "/.watch-oracle/" + D
             (exact, single decode, single segment; query ignored)
        AND is_valid_oracle_value(D) AND D == W(attempt.oracle_seed)
        AND attempt-level binding + run freshness hold
        AND anti_harvest(pre-execution material) == []
```

- Transport: Playwright request/response listeners; page-unforgeable;
  oracle requests already excluded from the generic `network_requests` sink.
- Establishes: **JAVASCRIPT_EXECUTION + OBSERVABLE_EFFECT** (the running code
  issued an attacker-chosen same-origin request). This is the only channel
  that grants S5 in v1.

### 4.3 E3 — eval-family oracle

```
E3 ≡ ∃ k ∈ evidence.eval_invocations:
        k.operator ∈ {"eval", "setTimeout:string"}
        AND k.value == attempt.payload   (exact full payload P)
        AND len(attempt.payload) <= 240  (else E3 DISABLED, never prefix)
        AND attempt-level binding + run freshness hold
        AND anti_harvest(pre-execution material) == []
```

- Transport: capability-protected instrumentation transport (page cannot forge
  the binding call without the per-attempt capability; hostile-page tests
  confirm the capability is unrecoverable). **This is a weaker trust tier than
  E1/E2**: the hook is a page-space monkey-patch that a page could disable
  (FN), and it only covers the eval family (`new Function`, indirect/iframes,
  workers are uncovered — FN, not FP).
- **E3 alone is execution proof for the eval-family sink** (invoking `eval(P)`
  with the full attacker payload IS executing attacker code; no benign page
  evals its query string), but:
  1. it establishes **JAVASCRIPT_EXECUTION only, never OBSERVABLE_EFFECT**;
  2. it is a **supplementary/fallback channel**, most relevant when E1/E2 are
     suppressed (e.g. a sink that evals the payload before the alert/fetch
     action is reached), because the eval-family transport cannot be proven
     persistent across page code (completeness gap);
  3. findings that confirm on E3-only record `oracle_channels=["E3"]` and
     `confirmation_state="JAVASCRIPT_EXECUTION"` — audit distinction from
     E2-derived confirmations.
- `OraclePlan.e3_enabled` is informational; the verifier recomputes the 240
  bound itself (do not trust the plan flag for classification).

### 4.4 Combination semantics (deterministic, no severity inflation)

| Combination | Stage | CONFIRMED granted? | Effect on finding |
|---|---|---|---|
| E1 only | S4 | per class rule | channels `["E1"]`, state `JAVASCRIPT_EXECUTION` |
| E2 only | S4+S5 | per class rule | channels `["E2"]`, state `OBSERVABLE_EFFECT` |
| E3 only | S4 | per class rule (eval-family) | channels `["E3"]`, state `JAVASCRIPT_EXECUTION` |
| E1+E2 | S4+S5 | per class rule | channels `["E1","E2"]`, state `OBSERVABLE_EFFECT` |
| E1+E3 | S4 | per class rule | channels `["E1","E3"]`, state `JAVASCRIPT_EXECUTION` |
| E2+E3 | S4+S5 | per class rule | channels `["E2","E3"]`, state `OBSERVABLE_EFFECT` |
| E1+E2+E3 | S4+S5 | per class rule | channels `["E1","E2","E3"]`, state `OBSERVABLE_EFFECT` |

Multiple channels **never raise severity or status** — status mapping is fixed
(0.95 CONFIRMED). Redundant channels improve **auditability** only
(recorded in `oracle_channels`), keeping classification deterministic.

---

## 5. Correlation Token vs Oracle Value (explicit)

- **Correlation token T** = identity/binding string (page-visible by design;
  binds evidence to an attempt/pair; re-derived and exactly matched).
- **Oracle value D** = execution proof (never on the wire pre-execution;
  produced only by executing W(S)).
- **T appearing in a runtime channel is NEVER execution confirmation.** Under
  the new model, `token in dom/console/network/storage` + bound chain caps at
  SINK_REACHED → POTENTIAL. This is the core demotion that kills the existing
  DOM false-positive path.
- The oracle path does NOT require token-in-runtime for CONFIRMED: D is a
  strictly stronger signal. T remains required for the HTTP S1 binding and the
  demoted POTENTIAL path.

---

## 6. Reflected XSS Confirmation Algorithm

### 6.1 Plan shape (per LLM suggested payload)

For reflected (and `unknown`, which flows as reflected):

```
HTTP attempt      payload = LLM pattern P          phase="http"    mode=http
Browser attempt   payload = LLM pattern P          phase="browser" mode=browser
Oracle attempt    payload = planner payload O      phase="oracle"  mode=browser
```

- HTTP + plain-browser attempts keep the EXACT current construction (identity,
  tokens, evidence) so existing POTENTIAL behavior and tests stay valid.
- The **oracle attempt** is an ADDITIONAL browser attempt, created by a new
  factory `build_oracle_verification_attempt(...)` (Section 11).

### 6.2 Oracle attempt construction (breaks the seed/payload cycle)

`attempt_id` includes the payload; the payload embeds the seed; the seed
derives from an identity — circular if the identity were the oracle attempt's
own `attempt_id`. Resolution (deterministic, non-circular):

1. `candidate_id` = the plain browser attempt's `attempt_id` (or the HTTP
   attempt's `attempt_id`; either is a stable per-candidate identity). Use the
   browser attempt's id for uniformity across reflected and DOM.
2. `plan = OraclePlanner.plan(context_type=case.context.type, case_id=...,
   attempt_id=candidate_id, logical_pair_id=<pair id>, run_salt=<run salt>,
   phase="oracle", delivery_pattern=LLM pattern (attribution only))`.
3. Oracle payload `O = plan.payload`; `seed = plan.seed`; `D = plan.oracle_value`.
4. `oracle_attempt_id = hash(canonical including O)` via the new factory;
   `logical_pair_id = the candidate's logical_pair_id` (passed explicitly);
   `oracle_identity = candidate_id`; `phase = "oracle"`.
5. Record on the attempt: `oracle_seed=seed`, `oracle_value=D`,
   `oracle_version=1`, `oracle_identity=candidate_id`.

`run_salt` is injected into the verifier (default `None` ⇒ **oracle
integration disabled, current behavior preserved except the mandated
demotion**).

### 6.3 Reflected CONFIRMED predicate

```
CONFIRMED_reflected ≡
    S1_meaningful(HTTP attempt of the pair)          # existing _http_path_confirms
    AND S4(oracle attempt of the pair)               # E1|E2|E3
    AND PAIRED: oracle attempt.logical_pair_id == HTTP attempt.logical_pair_id
    AND BINDING: oracle evidence binds (attempt_id/url/method)
                 AND _origin(actual_request_url) == _origin(endpoint)
    AND FRESH: seed re-derivation under run_salt matches
    AND ANTI_HARVEST: violations(oracle attempt pre-execution material) == []
```

- HTTP reflection is evidence of REFLECTION, never execution; the browser
  oracle establishes execution independently. Both halves are required.
- `S1_meaningful` uses the existing `_MEANINGFUL_REFLECTION_LOCATIONS` set and
  exact observed-token equality (unchanged).

### 6.4 Pairing integrity

- Attempts pair by `logical_pair_id` only; list position is never used.
- Evidence from attempt A cannot satisfy attempt B: `evidence.attempt_id ==
  attempt.attempt_id` binding + pair-keyed lookups.
- The oracle attempt's seed binds to `oracle_identity`; the verifier checks
  `oracle_identity == <the pair's plain browser attempt_id>` before accepting
  execution proof (prevents a mismatched/borrowed oracle attempt).

---

## 7. DOM XSS Confirmation Algorithm

```
CONFIRMED_dom ≡ S4(browser oracle attempt)           # E1|E2|E3
    AND BINDING (oracle evidence binds to the oracle attempt)
    AND FRESH (seed re-derivation)
    AND ANTI_HARVEST (== [])
```

- **No HTTP pair required** (DOM has none). No change to that rule.
- **S2/S3 source/sink evidence is ADVISORY (attribution), not mandatory.**
  Justification: D is produced only by executing payload-derived code, so the
  execution oracle is the proof. A legitimate supported DOM execution path may
  not produce a hook-visible chain — the readiness review's §7.3/§7.4 FNs
  (`location.hash` reads unhooked; handler-set sinks unhooked) would otherwise
  turn genuine execution into INCONCLUSIVE. S2/S3, when present, populate
  attribution/context on the finding; their absence never blocks CONFIRMED
  when S4 is a real oracle channel.
- **S2∧S3 (chain+token) without S4 → POTENTIAL** (SINK_REACHED). This is the
  mandated demotion of the current DOM CONFIRMED path
  (`test_dom_browser_only_yields_confirmed` and the chain+token CONFIRMED
  fixtures change to POTENTIAL — justified behavior change).
- E3-only DOM confirmation is accepted (an eval sink executing the full
  payload IS the exploit) and recorded as eval-family execution.

---

## 8. Binding / Replay Model

Checks applied in order before ANY E1/E2/E3 event is accepted for the oracle
attempt (any failure ⇒ execution proof rejected ⇒ INCONCLUSIVE for that
attempt):

1. Evidence identity: `evidence.attempt_id == attempt.attempt_id`; `request_url
   == attempt.endpoint`; `request_method == attempt.method` (existing
   `_enforce_evidence_binding`).
2. Oracle pair validity: `attempt.oracle_seed`, `attempt.oracle_value` set;
   `validate_oracle_pair(seed, value)` (shape, `D == W(S)`, `D != S`).
3. **Run freshness (anti-replay):** re-derive
   `oracle_seed(run_salt, attempt.oracle_identity, attempt.phase) ==
   attempt.oracle_seed`. Failure ⇒ stale/cross-run/cross-attempt D ⇒ reject.
4. **Identity binding:** `attempt.oracle_identity == <pair's candidate
   attempt_id>` (cross-attempt and cross-pair rejection).
5. **Same-origin:** for E2, `_origin(event.url) == _origin(attempt.endpoint)`;
   for all oracle events the browser executor already guarantees the oracle
   run stayed on the endpoint origin; the verifier re-checks
   `_origin(actual_request_url) == _origin(endpoint)` (redirect to an
   unrelated origin ⇒ reject).
6. **Exact-match predicates:** E1 exact message, E2 exact decoded path + non-
   navigation, E3 exact payload + ≤240.
7. **Anti-harvest:** `anti_harvest_violations(seed, D, PreExecutionInput{...})
   == []` (Section 9).
8. **Duplicates/replays:** predicates are existence-based and exact; duplicated
   or replayed events cannot make a wrong value match. Replayed evidence from
   a prior run fails check 3 (different run_salt ⇒ different seed ⇒ different
   D). `evidence.attempt_id` is run-independent but check 3 binds the run.

**Not made cryptographic claims:** W is a deterministic execution oracle, not a
PRF. The guarantees are non-reproduction by copy-class operations + run-salt
separation, exactly as documented. A Watch-aware adversarial page that computes
W(S) itself remains locally indistinguishable (Assumption A4, accepted).

**Redirects:** `intended_request_url` = pre-redirect bound URL; `actual_request_url`
= final. The verifier does NOT require `actual == intended` (allowed redirects).
It requires: (a) origin equality for the oracle run (browser executor already
enforces same-origin navigation); (b) anti-harvest scans BOTH URLs. Reflection
binds to the final HTTP body (existing semantics); `request_url == endpoint`
binding is untouched.

---

## 9. Anti-Harvest Integration

The verifier constructs, per oracle attempt:

```
PreExecutionInput(
    payload=attempt.payload,                       # oracle payload O
    bound_input=O + "~~" + attempt.correlation_token,
    intended_request_url=evidence.intended_request_url or "",
    actual_request_url=evidence.actual_request_url or "",
    request_body="",                              # browser GET: no body
    response_snippet="",                          # browser run: no HTTP body
    referrer_derived="",
    pre_execution_inputs=(),                       # extendable per attempt
)
violations = anti_harvest_violations(seed, D, pre)
```

- `violations != []` ⇒ reject execution proof (fail closed ⇒ INCONCLUSIVE +
  audit note). This enforces **D ∉ payload / bound input / intended / actual
  URL / any pre-execution string**.
- The scanner is structurally PRE-EXECUTION-only (`PreExecutionInput` +
  `TypeError` guard from the boundary fix). The E2 oracle request is passed
  **only** to `evaluate_e2_network`, never to the scanner — it cannot be
  mis-scan as pre-execution material.
- **Anti-harvest does NOT scan `dom_changes`/`console_messages`/
  `storage_writes`/generic `network_requests`** on the oracle run: those are
  POST-EXECUTION channels. In particular the E1 dialog record legitimately
  echoes D into `console_messages` (`dialog:alert:<D>`), so scanning console
  for D would self-contradict E1. The anti-harvest invariant is: D appears
  NOWHERE the page could read BEFORE execution.
- D in generic `network_requests` on the oracle run is audit-only (it can only
  arise from computation, i.e. execution); it is never treated as E2 (E2
  requires the classified `oracle_network_events` channel).

---

## 10. Evidence State Model & Schema Changes

Existing schema is sufficient for evidence production (E1/E2/E3 channels,
intended/actual URLs, oracle fields on the attempt all exist). Three additive
fields are required for binding/freshness and auditable confirmation:

### MUST ADD

1. `VerificationAttempt.oracle_identity: str | None = None`
   - Type: `str`; owner: verifier (trusted planner path); producer: the new
     oracle-attempt factory; trust: trusted (verifier re-derives).
   - Verifier use: run-freshness re-derivation
     (`oracle_seed(run_salt, oracle_identity, phase)`) and candidate-binding
     check. Why existing fields are insufficient: `attempt_id` is the
     executed-payload id (cycle); `oracle_seed/value` identify the pair, not
     the pre-oracle identity the seed was minted against.
2. `XSSFinding.confirmation_state: str | None = None`
   - Type: `str`; owner: verifier; producer: verifier; trust: authoritative
     (verifier-derived).
   - Values: `"REFLECTION"` (HTTP POTENTIAL), `"SINK_REACHED"` (demoted
     POTENTIAL), `"JAVASCRIPT_EXECUTION"`, `"OBSERVABLE_EFFECT"`.
     Why: current `verification_evidence` strings are not mechanically
     consumable; this records the reached stage deterministically.
3. `XSSFinding.oracle_channels: list[str] = []`
   - Type: `list[str]`; owner: verifier; producer: verifier; trust:
     authoritative.
   - Values: subset of `{"E1","E2","E3"}` present at confirmation. Why:
     auditability of which executor-owned channel(s) proved execution.

### MUST NOT ADD (no speculative fields)

- No `run_salt` on the attempt/evidence/finding (kept verifier-side in memory;
  persistence would leak per-run secrecy and break the anti-replay property).
- No `mutation_snapshot`, no round registry, no hash fields for this phase.
- No new executor fields: browser executor already produces all needed
  evidence; `http_executor.py` is unchanged.

---

## 11. Advisory vs Authoritative Evidence (classification)

| Signal | Classification role |
|---|---|
| `executed_script` | **Advisory / audit** — never execution proof |
| `browser_verified` | **Audit-only** — derived from `executed_script` |
| `matched_correlation_token` | **Advisory** — executor self-report |
| `correlation_token_in_runtime` | **Advisory** — token in channel ≠ execution |
| `observed_correlation_token` (browser) | **Prerequisite** (demoted POTENTIAL path) / audit for oracle path |
| `dom_changes` | **Audit-only** — data-stage (≤3) |
| `console_messages` | **Audit-only** — data-stage (≤3) |
| `network_requests` (generic) | **Audit-only** — data-stage; NEVER E2 |
| `storage_writes` | **Audit-only** — data-stage (≤3) |
| `source_to_sink` | **Discovery + prerequisite** (demoted POTENTIAL); verifier-revalidated; never verdict-authoritative for execution |
| `reflection.*` | **S1-authoritative** (for POTENTIAL, via verifier exact-token re-check); never execution |
| `dialog_events` (E1 match) | **Execution-authoritative** (S4) |
| `oracle_network_events` (E2 match) | **Execution+effect-authoritative** (S4+S5) |
| `eval_invocations` (E3 match) | **Execution-authoritative (eval-family)** (S4) |
| `waf_observations` (BLOCK/TRANSFORM) | **Gate** — forces INCONCLUSIVE; INFO is metadata |
| LLM suggestion / `expected_behavior` | **Ignored for verdict** (never an event) |

The executor provides evidence; the verifier is the sole classifier; the LLM
and the page never become the authority for execution.

---

## 12. Implementation Plan (file-by-file)

### MUST CHANGE

1. **`ai/schemas/xss_verification.py`**
   - Responsibility: attempt/evidence/event schemas, deterministic ids.
   - Change: add `VerificationAttempt.oracle_identity: str | None = None`.
   - Functions affected: `VerificationAttempt` model.
   - Data flow: plan builder sets it; verifier reads it for freshness/binding.
   - Invariant: identity is verifier-minted and verifier-re-verified.
   - Tests: schema default/back-compat; tampered identity rejected.
2. **`ai/schemas/xss_finding.py`**
   - Responsibility: finding schema.
   - Change: add `confirmation_state: str | None = None`,
     `oracle_channels: list[str] = []`.
   - Functions affected: `XSSFinding`.
   - Invariant: verifier-derived, never LLM/executor-derived.
   - Tests: defaults back-compat; populated on oracle confirmations.
3. **`ai/verification/verifier.py`** (the core change)
   - Responsibility: sole classifier; plan construction; binding.
   - Change:
     a. `__init__(executor, *, run_salt: str | None = None)` — default None
        ⇒ oracle integration disabled (fail closed).
     b. New factory `build_oracle_verification_attempt(...)` (module or
        static): computes oracle payload via `OraclePlanner` (seeded from
        candidate id), sets attempt identity/pair/oracle fields. Call
        `OraclePlanner` with `context_type=case.context.type`; unsupported
        context ⇒ NO oracle attempt (candidate stays POTENTIAL).
     c. `_build_plan_from_analysis`: for reflected/unknown/dom/mutation, add
        one oracle attempt per suggested payload when `run_salt` is set AND
        planner supports the context.
     d. Pairing maps: keyed by `logical_pair_id`; add an oracle-attempt map
        and candidate map (`oracle_identity` check).
     e. New `_oracle_execution_proof(attempt, evidence, run_salt)` returning
        `(ok, channels, state)` — runs binding checks 1–8 (Section 8) and the
        E1/E2/E3 predicates.
     f. `_classify`/`_classify_browser`: branch on `attempt.oracle_value is
        not None` → `_classify_oracle` (reflected: require paired HTTP
        `_http_path_confirms`; dom/mutation: no pair). Plain browser path:
        **demote `return "CONFIRMED"` → `return "POTENTIAL"`** (SINK_REACHED).
     g. `_build_finding`: populate `confirmation_state`/`oracle_channels`.
   - Data flow:
     `analysis → plan(+oracle attempts) → composite executor → evidence →
     binding → _classify_oracle → CONFIRMED/POTENTIAL/INCONCLUSIVE`.
   - Invariants: never confirm without S4; never accept stale/cross-attempt/
     cross-run oracle evidence; D ∉ pre-execution material.
   - Tests: full matrix (Section 13).
4. **`ai/test_xss_verification.py`**
   - Responsibility: verifier contracts.
   - Change: fixtures gain `run_salt` + oracle evidence constructors; update
     verdict expectations per Section 13; keep identity/determinism tests.
   - Explicitly updated (justified): `test_reflection_plus_correlated_browser_yields_confirmed`,
     `test_dom_browser_only_yields_confirmed`, `test_mutation_browser_only_yields_confirmed`,
     `test_positive_2_reflected_browser_confirmed`,
     `test_positive_3_dom_chain_confirmed`, adversarial DOM chain fixtures —
     chain+token CONFIRMED becomes POTENTIAL; new oracle fixtures confirm.
5. **`ai/test_xss_oracle.py`**
   - Responsibility: oracle predicates/planner/anti-harvest.
   - Change: add planner integration tests: seed binds to candidate identity;
     `build_oracle_verification_attempt` determinism; unsupported context
     yields no oracle attempt. Existing predicate tests stay valid.
   - Invariant: planner remains LLM-independent; D never on wire.

### MAY CHANGE

6. **`ai/verification/xss_pipeline.py`**
   - `build_default_verifier(http_executor, browser_executor, *, run_salt=None)`
     passes `run_salt` through. Back-compatible default.
7. **`watch_xss_verify.py`** (production composition)
   - Generate/own `run_salt` per run and inject it. Out of the AI-layer test
     surface; listed as MAY because the composition helper covers it.
8. **`ai/test_xss_pipeline.py`** — one back-compat test for the new keyword.

### MUST NOT CHANGE

- `ai/verification/oracle.py` (predicates, planner, anti-harvest) — reused
  as-is; the boundary fix is already in place.
- `ai/verification/browser_executor.py` — evidence production complete;
  oracle requests already excluded from the generic sink.
- `ai/verification/http_executor.py`, `ai/verification/composite_executor.py`,
  `ai/verification/xss_case_builder.py` — unchanged (composite routes oracle
  attempts as `BROWSER_EXECUTION` with no code change).
- `ai/researcher/*`, `ai/knowledge/*`, `ai/llm/*`, `ai/schemas/xss.py` —
  unchanged. The LLM must never see S/D/W/oracle payloads.

---

## 13. Test Matrix (before implementation)

### REFLECTED
- reflection only → POTENTIAL (HTTP finding), no CONFIRMED.
- reflection + source only → not confirmed.
- reflection + sink only → not confirmed.
- reflection + token-in-runtime only → not confirmed (POTENTIAL).
- reflection + benign network event → not confirmed.
- reflection + E1 → CONFIRMED (state JAVASCRIPT_EXECUTION).
- reflection + E2 → CONFIRMED (state OBSERVABLE_EFFECT).
- reflection + E3 → CONFIRMED only via eval-family S4 (state
  JAVASCRIPT_EXECUTION); no S5.
- wrong D → reject (INCONCLUSIVE).
- D in pre-execution input → reject.
- stale D (old run_salt) → reject.
- wrong attempt (evidence.attempt_id mismatch) → error/reject.
- wrong logical pair (oracle_identity ≠ candidate) → reject.
- wrong endpoint / wrong parameter → reject (pair identity).
- redirect mismatch (actual origin ≠ endpoint origin) → reject.
- HTTP pair absent → INCONCLUSIVE for oracle attempt (reflected).

### DOM
- source only → not confirmed (no S4).
- sink only → not confirmed.
- source + sink → POTENTIAL.
- source + sink + token → POTENTIAL.
- source + sink + benign network → POTENTIAL.
- source + sink + E1 → CONFIRMED.
- source + sink + E2 → CONFIRMED (S5).
- source + sink + E3 → CONFIRMED (eval-family S4).
- wrong oracle (D mismatch) → reject.
- cross-attempt oracle → reject.
- stale run oracle → reject.
- D pre-harvest (D in pre-execution) → reject.
- benign echo page (query → textContent/console/beacon/storage) → POTENTIAL,
  never CONFIRMED.
- benign telemetry page (path-copy, beacon) → POTENTIAL, never CONFIRMED.
- E2-only DOM with no source/sink chain → CONFIRMED (S3 waived; documented).
- hash/location based DOM execution (no URLSearchParams source) → CONFIRMED
  via E1/E2 with no chain (attribution empty) — the S3-waiver FN fix.

### NEGATIVE / SECURITY
- raw marker copy, seed copy → rejected (E1/E2 exact-match; anti-harvest).
- D in generic network telemetry → NOT E2 (and NOT a violation).
- D in console / storage / DOM → audit-only, NOT E1/E2/E3 (except E1's own
  dialog→console echo, which is expected post-execution noise).
- D in referrer (pre-execution) → anti-harvest violation ⇒ reject.
- malformed oracle event (bad path/shape) → reject.
- duplicate oracle event → no double-increment, still valid/invalid by exact
  match.
- navigation to oracle path → reject (E2 is_navigation guard).
- cross-origin oracle path → reject.
- encoded path (single decode) → pass only if exact after ONE decode; double-
  encoded → reject.
- path suffix / path prefix / second segment → reject.
- eval payload > 240 → E3 disabled (never prefix-match).

### REGRESSION
- All existing identity/determinism/WAF/LLM-neutrality/executor-failure/
  stored tests remain valid EXCEPT the explicitly-justified demotion tests
  listed in Section 12.4. Stored and mutation keep current behavior (mutation
  shares the demoted browser branch; no mutation-specific logic added).

---

## 14. Order of Implementation

1. **Phase 1 — Schema** (`xss_verification.py`, `xss_finding.py`): additive
   fields. No behavior change; run all tests (green).
2. **Phase 2 — Verifier oracle plumbing** (`verifier.py`): `run_salt` kwarg
   (default None), oracle-attempt factory, plan-builder augmentation, pairing
   maps. Still no classification change (run_salt None in existing tests).
3. **Phase 3 — Verifier predicates** (`verifier.py`): `_oracle_execution_proof`
   (binding 1–8, E1/E2/E3, anti-harvest), `_classify_oracle`.
4. **Phase 4 — State machine** (`verifier.py`): branch `_classify` on
   `oracle_value`; **demote** plain-browser CONFIRMED → POTENTIAL; finding
   fields.
5. **Phase 5 — Composition** (`xss_pipeline.py`, `watch_xss_verify.py`):
   `run_salt` injection.
6. **Phase 6 — Tests**: update fixtures (run_salt, oracle evidence), rewrite
   demotion tests, add matrix (Section 13).
7. **Phase 7 — Regression + docs**: full `ai/` suites, `py_compile`, `git
   diff --check`, AGENTS.md-compliant XSS/knowledge regressions.

Dependencies: 1 → 2 → 3 → 4 (schema before verifier; predicates before state
machine). 5 depends on 2. 6 can start in parallel with 2. 7 gates completion.

---

## 15. Stop Conditions

STOP and report (never guess) if any of the following is discovered during
implementation:

- The schema cannot represent the required binding (e.g. `oracle_identity`
  rejected) and no equivalent exists.
- Attempt pairing is ambiguous: more than one candidate per `logical_pair_id`
  for an oracle attempt, or an oracle attempt whose `oracle_identity` maps to
  no same-pair candidate.
- Redirect semantics are undefined for a real oracle run (browser executor
  currently guarantees same-origin navigation; if a supported redirect can
  change origin, binding must be re-specified).
- Oracle evidence cannot be bound to an attempt (evidence.attempt_id/url/method
  mismatch not attributable to tampering).
- The current browser evidence lacks the required identity (it does not today:
  `attempt_id`, `intended/actual_request_url` exist — verify at Phase 2).
- Confirmation semantics conflict with an existing invariant (e.g. the demotion
  would break a documented product contract the task does not authorize).
- `OraclePlanner` produces an unsupported context for a case the task expects
  to confirm — DO NOT silently substitute a generic skeleton in v1 (document
  as candidate-level POTENTIAL; revisit as an open question).

---

## 16. Risks

1. **Demotion is a behavior change** to existing DOM/mutation CONFIRMED
   verdicts; it is the intended security fix but must be explicitly listed in
   the change notes and tests.
2. **E3 transport tier**: capability-authenticated but page-space; do not
   treat E3 as equal to E1/E2 for OBSERVABLE_EFFECT; keep E3 as the
   supplementary eval-family channel.
3. **Context coverage**: `xss_type=unknown`/`context.type=unknown` cases
   cannot host a planner skeleton ⇒ no oracle attempt ⇒ capped at POTENTIAL
   (systemic FN, already flagged by readiness review; not a new risk, must be
   documented).
4. **run_salt lifecycle**: per-run, verifier-side, never persisted. Loss of
   the salt mid-run (restart) invalidates run-binding — acceptable for a
   single-run `verify()`.
5. **Two browser runs per payload** (plain + oracle) doubles browser cost and
   observation time; acceptable for inventory-scale v1; revisit batching.
6. **Planner payload length**: oracle payloads are ~230–260 chars; E3 is often
   disabled — E1/E2 carry confirmation; never weaken E3.
7. **Deterministic IDs for oracle attempts** must not collide with existing
   attempt ids (distinct phase label `"oracle"` and payload ⇒ distinct).

---

## 17. Remaining Open Questions

1. Should an unsupported planner context fall back to the `generic` `<script>`
   skeleton for `xss_type=unknown` cases (execution is still real if it fires),
   or remain candidate-level POTENTIAL? Conservative v1: POTENTIAL; revisit.
2. Should the plain browser attempt remain in the plan (cost/audit) or be
   dropped once the oracle attempt exists? Conservative v1: keep (preserves
   POTENTIAL evidence and demotion tests).
3. Whether `confirmation_state` should also be recorded on POTENTIAL HTTP
   findings (`"REFLECTION"`) or left `None` — plan: set it for audit symmetry.
4. Whether E2's same-origin check should compare against `attempt.endpoint`
   origin or the oracle run's `actual_request_url` origin (they are equal by
   browser policy; plan uses endpoint origin — confirm during Phase 3).
5. Whether to record `oracle_identity` derivation inputs on the attempt for
   full reproducibility, or keep only the identity hash (plan: identity hash
   only, to avoid leaking candidate structure).

---

## 18. Explicit Assumptions

- A1–A6 of the oracle design hold (copy-class non-reproduction of D; W
  bit-parity; executor-owned transport; out-of-model adversarial page
  accepted; run_salt secrecy+freshness; 5 s window).
- The existing executor/verifier split, same-origin policy, LLM isolation, and
  the `logical_pair_id` pairing semantics remain normative.
- `anti_harvest_violations` with `PreExecutionInput` is the sole pre-execution
  scanner; it must never receive `DialogEvent`/`NetworkOracleEvent`.
- Stored XSS stays on its current (single-phase) semantics; mutation stays on
  the shared browser branch with no new mutation logic.
- `NOT_VULNERABLE` remains never-produced.
- No cryptographic unforgeability claim is made for W.

---

## 19. Final Design Decision — READY

The implementation is **READY to plan-complete** subject to: (a) the three
additive schema fields being accepted; (b) the run_salt default-None
back-compat contract; (c) the explicitly-justified demotion of chain+token
CONFIRMED to POTENTIAL. No blocking dependency or contradicting invariant was
found in the existing architecture. Stored-XSS SUBMIT→READ, Mutation redesign,
and `new Function` remain out of scope and must not be pulled in.

**ORACLE INTEGRATION PLAN COMPLETE.** The oracle predicates, planner,
anti-harvest boundary, and browser evidence channels already exist and are
verified; the plan wires them into the verifier as the sole execution-proof
path, demotes all data-stage signals to POTENTIAL, and preserves backward
compatibility for every non-confirmation verdict.
