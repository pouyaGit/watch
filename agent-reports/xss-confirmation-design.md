# XSS Confirmation Design Review — What Exact Evidence Is Sufficient for CONFIRMED?

Read-only design review. Question answered: **what exact evidence is
sufficient to call XSS CONFIRMED?** for Reflected, DOM, Mutation, and Stored
XSS. No code changes, no test changes, no network activity.

---

## 1. The Six-Stage Evidence Chain

CONFIRMED is the terminal state of a chain of *increasingly strong claims*.
Each stage names the exact evidence class that supports it — and nothing else
can substitute:

```
1. REFLECTION              the injected string came back
2. SOURCE_REACHED          attacker-controlled data was READ by the app
3. SINK_REACHED            that data arrived at a dangerous sink API
4. JAVASCRIPT_EXECUTION    attacker-controlled code was parsed AND ran
5. OBSERVABLE_EFFECT       the running attacker code produced an attacker-chosen
                           observable side effect
6. CONFIRMED               the class-specific composition of 1–5
```

**The load-bearing rule of this review:** stages 1–3 are statements about
*data*. Stage 4 is a statement about *code*. Every existing Watch primitive
listed below is a data-stage signal; none of them can logically reach stage 4,
because in every case the same signal can be produced by a page that never
parsed one byte of attacker script:

| Signal | Why it is NOT JavaScript execution (counterexample page) |
|---|---|
| token in `dom_changes` | A search page renders the query parameter as a text node. No script of ours ran; the token is in the DOM. |
| token in `console_messages` | The page (or its error reporter) logs `location.href`, which contains the token. |
| token in `network_requests` | An analytics beacon copies `location.href` into its URL. |
| token in `storage_writes` | The app persists "last search = <query>" via `setItem`. |
| `source_to_sink` chain | Built by substring overlap (`src.value in ev.value`); the echo page above produces a full parameter→innerHTML→mutation chain. |
| `executed_script` boolean | Defined by the executor as "any sink or observable event fired" — the echo page's text-node mutation sets it. |
| `browser_verified` | Derived from `executed_script`; inherits the same weakness. |

A signal is **security-grade execution proof** only if a page that did not
parse attacker code *cannot produce it*. Formally, for a per-attempt secret
marker M embedded inside the attacker payload body: the channel must have
reachability P(page emits signal involving M \| attacker code never parsed) ≈ 0.
This is satisfiable locally (Section 3), and it is what separates stage 4 from
stage 3.

---

## 2. Current DOM Confirmation Logic — Explicit Challenge

Current rule (verifier.py): DOM CONFIRMED requires

- `source_to_sink` well-formed and bound to the attempt (parameter name,
  location, endpoint),
- correlation token present as a substring in one of the four runtime
  channels,
- `observed_correlation_token == correlation_token`.

This is **not sufficient for CONFIRMED**. Concrete failure: a completely
benign search application that does

```
results.textContent = params.get('q')          // source → sink event, token in value
log.info('search', location.search)            // token in console
navigator.sendBeacon('/analytics', location)   // token in network
localStorage.setItem('q', params.get('q'))     // token in storage
```

produces a well-formed chain plus token hits in all four channels. The current
verifier returns CONFIRMED for `xss_type="dom"`. Nothing executed. The DOM
path additionally has **no HTTP pair** as an independent cross-check, so
nothing can catch this. Verdict: the DOM confirmation logic must be demoted to
SINK_REACHED (POTENTIAL) and replaced by the oracle rule in Section 3/6.

---

## 3. Security-Grade Execution Proof (Stage 4) Without an Out-of-Band Canary

Define a per-attempt **execution marker M** (e.g. `xm-<32 hex>`, derived from a
verifier-owned per-run salt and the attempt identity) embedded inside the
payload body by a trusted deterministic planner. Only three channels have
≈0 forgery probability against a non-parsing page:

- **E1 — dialog oracle.** Payload executes `alert(M)` (or confirm/prompt).
  Playwright's dialog handler (already present in `browser_executor.py`, today
  mis-channelled into `console_messages`) reports the exact message. A benign
  page cannot know M; URL echo does not call alert. Exact message equality is
  required, not substring.
- **E2 — path-marker oracle.** Payload executes `fetch('/<M>')` or
  `new Image().src='/<M>'` — a **same-origin path** containing M. URL echo
  reproduces the *query* string, never a newly constructed path, so only
  running code can put M into a path. Observed by the existing page-initiated
  network listeners. Same-origin, so the current network policy permits it.
  (A cross-origin/out-of-band canary is unnecessary AND structurally unobserveable:
  the executor aborts all cross-origin traffic.)
- **E3 — eval-family invocation.** The instrumentation hooks on `eval` /
  string-`setTimeout` record the code argument. Exact equality with the full
  payload proves the call — and the call *is* the execution. Covers only the
  eval family; kept as an additional proof, not the general one.

Everything else (DOM text, console text, storage values, query-position URL,
`document.title`) is stage ≤3 evidence by the counterexamples of Section 1.

---

## 4. Machine-Checkable Stages

Each stage is defined as a predicate over evidence fields (E = the evidence
object of attempt A; T = A.correlation_token; M = A.execution_marker; P =
A.payload). "exact" means full-string equality, no normalization, no
substring.

- **S1 REFLECTION** (HTTP attempt):
  `attempt_status == SUCCEEDED AND ∃i: body[i:i+len(bound)] == bound`
  where `bound == payload ~~ T`; recorded as `reflection.observed_token == T`
  (exact), `response_status ∈ 200..299`, no WAF BLOCK/TRANSFORM observation.
- **S2 SOURCE_REACHED** (browser attempt):
  `∃ source-event s: s.parameter == A.parameter AND s.value ⊇ markerset(A)`
  where `markerset(A) = {T} ∪ ({M} if oracle payload)`. Bound to A's
  parameter name/location via the source hook label. (A source read alone
  proves nothing exploitable — it only licenses stage 3.)
- **S3 SINK_REACHED** (browser attempt):
  `∃ sink-event k: k.op ∈ SINKS AND markerset(A) ∩ exact_value(k) ≠ ∅`
  where `exact_value(k)` is the recorded sink value (or its truncation-flagged
  prefix), and SINKS = {innerHTML, insertAdjacentHTML, document.write, eval,
  setTimeout:string, handler-set sinks (future)}. The current
  substring-overlap chain builder is acceptable for *candidate discovery* but
  MUST NOT be the verdict predicate; verdict requires the value-identity check
  above (token or marker inside the sink's recorded value), not
  `src.value in ev.value` on unrelated values.
- **S4 JAVASCRIPT_EXECUTION** (browser attempt): exactly one of
  - E1: `∃ dialog-event d: d.message == M` (exact);
  - E2: `∃ runtime-request r (page-initiated, non-navigation, same-origin):
        marker_in_path(r.url, M)`;
  - E3: `∃ eval-family sink-event k: k.value == P` (exact full payload).
- **S5 OBSERVABLE_EFFECT**: E2 fired (the running code caused a request the
  attacker chose) OR attacker code wrote M to storage on a *fresh* context, OR
  M persisted across a same-context navigation. E1 alone proves execution, not
  effect. E2 subsumes execution + effect.
- **S6 CONFIRMED**: class rule from Section 5/6 satisfied, all binding and
  anti-replay checks pass (Sections 7–8).

Anti-spoofing notes wired into the predicates:
- token-in-URL echo: `location.href` contains T (and M, since the payload
  carries M into the query). E2 therefore requires M in the **path**, never in
  the query. E1/E3 are inherently unforgeable by echo.
- S2/S3 use markerset(A) — for oracle payloads M dominates T, because M is
  unknown to any page that merely echoes the URL… except that M *is* in the
  URL query (payload contains it). Hence S3 alone still cannot rise above
  stage 3 even with M; only E1–E3 reach stage 4. This asymmetry is deliberate.

---

## 5. Per-Class CONFIRMED Conditions (Machine-Checkable)

### 5.1 Reflected XSS
`CONFIRMED ⇔ S1(context-meaningful) ∧ S4 ∧ PAIRED ∧ BINDING ∧ FRESH`
- S1-meaningful: S1 holds AND `reflection.location ∈ {html_attribute,
  javascript_string, script_block, url}` (all occurrences scanned, not just
  the first).
- S4 on the *browser* attempt of the same `logical_pair_id` (E1 | E2 | E3).
- PAIRED: HTTP and browser attempts share `logical_pair_id`; both within one
  run salt.
- BINDING: evidence attempt_id/request identity checks pass (existing rule,
  extended with actual URL + hashes).
- FRESH: anti-replay rules (Section 8) pass.
- S1-meaningful alone → POTENTIAL. S3 without S4 → POTENTIAL.

### 5.2 DOM XSS
`CONFIRMED ⇔ S2 ∧ S3 ∧ S4 ∧ BINDING ∧ FRESH` (no HTTP pair exists)
- S2: source event bound to the attempt parameter (hook must cover
  URLSearchParams + location.search/hash — hook gap to close).
- S3: value-identity sink event (token or marker in recorded sink value), NOT
  substring-overlap chain alone.
- S4: E1 | E2 | E3. **This is the fix for Section 2's false-positive.**
- S2∧S3 without S4 → POTENTIAL (SINK_REACHED). S2 without S3 → INCONCLUSIVE.

### 5.3 Mutation XSS
`CONFIRMED ⇔ S2 ∧ S3 ∧ S4 ∧ BINDING ∧ FRESH` plus mutation context:
- Required additionally: `mutation_snapshot` recording that the parsed /
  re-serialized form at the injection point differed from the sent payload.
- If S4 fires, CONFIRMED stands even with partial mutation evidence
  (execution is the proof; mutation is attribution).
- Marker stripped by sanitizer → INCONCLUSIVE (with `marker_sanitized` note),
  never NOT_VULNERABLE.

### 5.4 Stored XSS
See protocol (Section 6). Summary predicate:
`CONFIRMED ⇔ SUBMIT_ACCEPTED ∧ ROUND_BOUND ∧ S4(READ pass) ∧ FRESH`
- S1-style reflection on either phase never contributes to CONFIRMED.
- S2∧S3 on the READ pass without S4 → POTENTIAL (the honest ceiling of the
  current architecture).

---

## 6. Stored XSS: Real SUBMIT → READ → EXECUTION Protocol

Two linked attempts in one round, sharing `logical_pair_id` and a fresh secret:

**Round setup (trusted planner).** `round_id = nonce(run_salt)`. Derive
`submit_token`, `read_token`, `execution_marker M` from `round_id`. The READ
attempt's payload = stored payload embedding the oracle action keyed to M.
Critical property: **the READ request URL must not contain M or the round
secrets** — they must reach the page only via the stored server-side content.
That is what makes READ-side signals attributable to persistence rather than
request echo.

**SUBMIT pass** (attempt kind `submit`, HTTP):
1. Build the storage request (method/endpoint/body from the case) carrying the
   payload + `submit_token`.
2. Record: actual request URL, request body hash, response status, response
   body hash, server echo of `submit_token` (S1-strength acceptance evidence).
3. Acceptance = 2xx (or app success signature). Acceptance is a precondition,
   never proof of storage.

**READ pass** (attempt kind `read`, BROWSER, **fresh context**, started only
after SUBMIT acceptance):
1. Navigate the display endpoint (distinct URL or the same endpoint; recorded).
2. Observe runtime channels; require value-identity S3 for the stored payload
   (matched via M, which is unique to this round).
3. Require S4 on the READ pass (E1 | E2 | E3). Because the context is fresh and
   the URL carries no marker, the marker can only have come from the stored
   content being served back and its code running.

**What MUST be bound between the phases (verifier-enforced):**
1. `round_id` present on both attempts and referenced in both evidence objects.
2. Marker identity: M observed on READ == M derived from round_id at SUBMIT
   time.
3. `logical_pair_id` equal; `attempt_id`s distinct.
4. Time ordering: `read.started_at > submit.finished_at` (monotonic,
   future timestamps rejected).
5. Context isolation: read context id ≠ submit context id; fresh context.
6. Transport identity: submit request hash ≠ read request hash; read response
   hash recorded; phase observations carry these hashes.
7. Two distinct real interactions: SUBMIT is transport-verified (request hash
   + response status), READ is transport-verified (navigation + response); one
   executor pass may never emit both phases.
8. Single-use: round_id verifies at most one READ (DB-consumed registry).

**Outcomes:** SUBMIT failed → INCONCLUSIVE. READ without marker → INCONCLUSIVE
(storage unproven). READ with S3, no S4 → POTENTIAL. READ with S4 → CONFIRMED.
READ with S4 + S5 (E2 path-marker request) → CONFIRMED + impact note.

---

## 7. Binding Rules (all classes)

- Evidence attempt_id == attempt.attempt_id (existing).
- Evidence request_method == attempt.method (existing).
- Evidence **actual_request_url** == the URL the executor actually sent
  (post-binding, post-redirect) — new field; checked against a verifier-side
  reconstruction.
- Request/response body hashes recorded; reflection claims must include
  context_before/after snippets.
- All paired attempts derive identifiers under the same `run_salt`.

---

## 8. Anti-Replay Rules

1. `run_salt` (verifier-generated random per run) mixed into correlation
   token, execution marker, round_id, attempt_id canonicals.
2. Evidence whose token/marker does not re-derive under the current run's salt
   → downgraded to ERROR evidence.
3. round_id single-use; consumption registered before the READ pass.
4. Timestamp monotonicity; future timestamps rejected.
5. DB dedup keyed by (case_id, run generation) — re-runs cannot inherit stale
   evidence.

---

# Recommended XSS Confirmation Model

## Final Proposed Rules

### R1. Evidence primitives (new/relabelled)
- `reflection` — all-occurrence scan; exact token; context snippets; actual
  URL + response hash. Proves S1 only.
- `source_events` — parameter-bound reads (URLSearchParams today; extend to
  `location.search/hash`, `document.referrer`, `postMessage`, cookies).
  Proves S2.
- `sink_events` — with recorded exact values and truncation flags. Proves S3
  (value-identity check, not substring chain).
- `dialog_events` — **new first-class channel** (split from console); exact
  message. Proves S4 via E1.
- `oracle_network_events` — page-initiated, non-navigation, same-origin,
  marker-in-path. Proves S4+S5 via E2.
- `eval_invocations` — exact payload argument. Proves S4 via E3.
- `mutation_snapshot` — pre/post serialization diff (mXSS).
- `stored_round` — round_id, phase hashes, timestamps, context ids.
- `run_salt` — verifier-owned, per run.

### R2. Trust boundaries
- LLM: untrusted; suggestions only; never builds oracles.
- Planner: trusted; derives markers/rounds from run_salt; no LLM involvement.
- Executors: untrusted evidence providers; hardened transport retained.
- Server: untrusted; reflection never confirms anything.
- Page: untrusted; console/DOM/storage/URL-echo cap at stage 3.
- Verifier: sole authority; only it may map evidence → stages → CONFIRMED.

### R3. State machine (normative)
```
REFLECTION → SOURCE_REACHED → SINK_REACHED → JAVASCRIPT_EXECUTION
            → OBSERVABLE_EFFECT → CONFIRMED
```
- Terminal failure at any stage → INCONCLUSIVE (audit-only), never
  NOT_VULNERABLE.
- CONFIRMED requires the class predicate of R4–R7; no substitute evidence
  exists.

### R4. Reflected
`CONFIRMED = S1(meaningful location, all occurrences) ∧ S4 ∧ PAIRED ∧
BINDING ∧ FRESH`. S1 alone → POTENTIAL; S3 without S4 → POTENTIAL.

### R5. DOM
`CONFIRMED = S2 ∧ S3 ∧ S4 ∧ BINDING ∧ FRESH`. No HTTP pair. The current
rule (chain + token-in-channel) is **demoted to SINK_REACHED → POTENTIAL**.
Chain substring-overlap is discovery-only, never verdict-competent.

### R6. Mutation
DOM rules plus `mutation_snapshot`; S4 → CONFIRMED with mutation evidence as
attribution; sanitized marker → INCONCLUSIVE with note.

### R7. Stored
Two-attempt round protocol (Section 6):
`CONFIRMED = SUBMIT_ACCEPTED ∧ ROUND_BOUND(8 items) ∧ S4(READ) ∧ FRESH`.
Single-phase evidence → INCONCLUSIVE; READ S3 without S4 → POTENTIAL. The
current single-pass `phase="stored"` navigation is retired — it proves only
reflection.

### R8. Anti-false-positive rules
1. Nothing above POTENTIAL from evidence below S4.
2. Exact-match only for oracle channels; substring hits in console/DOM/
   storage/query never exceed stage 3.
3. E2 requires marker in the request **path**; query-position markers are
   URL echo and are suppressed.
4. E1 requires exact dialog message equality with M.
5. E3 requires the full payload as the code argument.
6. URL-echo suppression: if all runtime hits equal (a substring of) the
   request URL, downgrade to S1.
7. `executed_script` / `browser_verified` retired as verdict inputs; kept as
   runtime-activity metadata.
8. `html_body` reflection remains non-meaningful.
9. WAF BLOCK/TRANSFORM → INCONCLUSIVE; INFO stays metadata.

### R9. Anti-replay rules
As in Section 8: run-salted identifiers, salt re-derivation check on all
evidence, single-use round registry, timestamp monotonicity, generation-aware
DB dedup.

### R10. Required changes (design-level list)
- Schema: `execution_marker`, `round_id`, `run_salt_ref`, `is_oracle` on
  attempts; `dialog_events`, `oracle_network_events`, `eval_invocations`,
  truncation flags on browser observations; `actual_request_url`, body/response
  hashes, `context_id`, `round_id` on evidence; hashed phase observations;
  `confirmation_state` + `proof_summary` on findings; schema `version`.
- Browser executor: split dialog channel; marker-in-path detection; exact
  eval values; extended source hooks; fresh-context stored READ; record actual
  URL + hashes + context ids; truncation flags.
- HTTP executor: multi-occurrence reflection; actual URL + body/response
  hashes; SUBMIT pass for stored.
- Verifier: implement stage predicates; enforce R4–R9; demote current P2-based
  CONFIRMED to POTENTIAL until oracle evidence exists; deterministic
  confidence per stage (SINK_REACHED 0.50, EXECUTION 0.90–0.95,
  OBSERVABLE_EFFECT 0.99).
- Tests: benign-echo matrix (search page echoing query into DOM/console/
  storage/beacon/title) must never exceed POTENTIAL in any class; dialog
  near-miss (substring/wrong marker) must not confirm; query-position marker
  must not confirm; stored round-bound positives and all 8 binding violations;
  replayed run-N evidence in run N+1 → ERROR; legacy P2 CONFIRMED fixtures
  re-asserted as POTENTIAL.

---

**Bottom line:** reflection, source-reached, sink-reached, and every current
token-in-channel signal are data claims. CONFIRMED requires a code claim — a
payload-embedded execution marker observed through a channel whose reachability
requires parsed-and-running attacker JavaScript (dialog-exact, marker-in-path,
or eval-invocation). This is achievable fully locally; no out-of-band canary is
needed. Stored XSS additionally requires a round-bound, transport-verified
SUBMIT → READ sequence in isolated contexts. Design only — nothing implemented.
