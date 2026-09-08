# Stored XSS Design Plan

## Verdict
READY FOR IMPLEMENTATION

## Executive Summary

Stored XSS is the only XSS class whose confirmation requires **two
transport-verified, time-ordered interactions** (SUBMIT then READ) plus
**execution proof bound to the submitted round**. The current production
implementation does not do this: it issues a single browser GET carrying the
payload (`phase="stored"`), records a READ observation when the correlation
token appears in a runtime channel, and confirms on
`paired-HTTP-reflection + SUBMIT/READ token match + token-in-runtime-channel`.
That predicate proves **data reached a channel**, never that **attacker code
executed**, and it cannot attribute execution to Watch's own submission
(pre-existing stored payloads, benign echo, and cross-round confusion all
confirm or would confirm under it).

This plan designs the minimal secure replacement that reuses the already
implemented reflected/DOM execution oracle (S/D, E1/E2/E3, anti-harvest,
run_salt, `oracle_identity`, `logical_pair_id`, executor-owned channels,
`_oracle_execution_proof` ordering) without redesigning it, and adds only the
stored-specific machinery that is genuinely missing: a **round** abstraction,
a real **SUBMIT attempt** (HTTP POST/PUT-capable, persistence-aware), a clean
**READ attempt** (browser, fresh context, oracle-carrying payload submitted but
never present in the READ URL), **round binding + baseline defense**, and a
new `_classify_stored_oracle` predicate. The legacy `_classify_stored`
token-based CONFIRMED path must be removed/demoted.

Conservative v1 scope (justified below): unauthenticated, synchronous,
same-origin, Location-or-case-endpoint READ discovery, one candidate per
round, serialized rounds, no CAPTCHA/async-moderation/multi-step workflows.

No cryptographic unforgeability is claimed for W; the A4 Watch-aware
adversarial-page residual from the oracle design is inherited unchanged.

## Current Stored XSS Behavior

Verified against source (working tree at `f74fd2f` + oracle infrastructure):

**Plan construction** (`ai/verification/verifier.py:_build_plan_from_analysis`,
lines ~448-527):

- `xss_type == "stored"` sets `is_stored=True`.
- An HTTP attempt (`mode=HTTP_REFLECTION`, `phase="http"`) is still built per
  suggested payload (stored is not a DOM flavour, so the HTTP leg exists).
- The browser attempt is built with `phase="stored"` (instead of `"browser"`)
  from the start, so `attempt_id`/`correlation_token` are self-consistent
  against that phase. Same endpoint/method/parameter/location/payload as the
  HTTP attempt; distinct `attempt_id` (phase differs), shared
  `logical_pair_id` (excludes mode/phase, includes method).
- **No oracle attempt is ever built for stored**
  (`if self.run_salt is not None and not is_stored`). Stored candidates are
  structurally excluded from oracle integration.

**Execution** (`verify()` + `CompositeVerificationExecutor`):

- HTTP attempt → `HTTPEvidenceExecutor.execute` (plain GET/POST reflection
  check; SUBMIT semantics do not exist — it is a reflection probe, not a
  persistence operation: no form/JSON/multipart body construction from case
  metadata, no Location-header capture, no object-ID extraction, no
  persistence assertion).
- `phase="stored"` browser attempt → `BrowserEvidenceExecutor.execute`:
  a single GET navigation to the **case endpoint** with the payload bound as a
  query parameter (`state.bound_url`), i.e. a **reflected-style READ**.
  There is no prior SUBMIT interaction, no second request, no round state.

**Stored phase evidence** (`browser_executor.py:1706-1722`):

- If `phase == "stored"` and the attempt's correlation token is found in a
  runtime channel, one `StoredXSSPhaseObservation(phase=READ,
  attempt_id, observed_correlation_token)` is appended. No SUBMIT observation
  is ever produced by the browser executor (comment states SUBMIT is
  "not in scope here" / "orchestrator must drive a SUBMIT pass" — which
  nothing does).
- Consequence: in production, `evidence.stored_phases` contains **at most one
  READ entry**. The SUBMIT entry the verifier demands can only come from
  hand-built test evidence, never from production executors.

**Classification** (`_classify` Rule 2 → `_classify_stored`, lines 684-699,
1047-1139):

- Routes before the oracle branch; returns `(status, None, [])` — stored
  findings carry **no `confirmation_state`/`oracle_channels`**.
- CONFIRMED requires, conjunctively:
  1. paired HTTP attempt+evidence for the same `logical_pair_id` satisfying
     `_http_path_confirms` (meaningful reflection + exact token match) —
     checked on the **paired HTTP** pair, correctly;
  2. a SUBMIT **and** a READ `StoredXSSPhaseObservation`, both with
     `p.attempt_id == attempt.attempt_id` and both with
     `observed_correlation_token == attempt.correlation_token`;
  3. `_runtime_token_observed` — the same correlation token as a substring of
     `dom_changes`/`console_messages`/`network_requests`/`storage_writes`.
- Missing pair → INCONCLUSIVE; single phase → POTENTIAL; token mismatch or no
  runtime token → POTENTIAL; else CONFIRMED.

**Gaps (what this proves, and what it does not):**

1. No SUBMIT transport exists: persistence is never performed or proven.
   The HTTP leg proves reflection at the submission endpoint, not storage.
2. Token equality is the entire "round binding": the correlation token is
   page-visible by design, copyable by any benign echo, beacon, referrer, or
   pre-existing stored content. `token-in-runtime` is a stage-3 data signal
   (demoted everywhere else to SINK_REACHED/POTENTIAL) but is CONFIRMED-grade
   here.
3. No execution proof: E1/E2/E3 are never consulted for stored
   (`phase="stored"` never reaches `_classify_oracle`; `_classify` returns
   early). A page that renders the token as text confirms.
4. No attribution: nothing binds READ content to the SUBMIT (no round_id, no
   S/D, no object ID, no ordering check, no baseline). A pre-existing stored
   payload containing an older token echo, or the reflected payload itself
   echoed in the same GET, satisfies the predicate.
5. `stored_phases` entries are executor self-reports consumed at face value
   beyond the token-equality check; there is no cross-attempt/cross-run
   freshness (no run_salt involvement), no SUBMIT/READ hash or timestamp
   ordering enforcement, no single-use registry.
6. The browser READ is not clean: the payload (and token) travel **in the READ
   URL itself**, so READ-side token observations are request echo, exactly the
   signal the oracle design proves worthless.

In short: the current stored CONFIRMED predicate is the pre-oracle
chain+token false-positive pattern in stored clothing, plus an HTTP reflection
precondition that does not establish persistence. It must not be extended; it
must be replaced.

## Threat Model

Adversary and environment assumptions (extends oracle design §§1,7; stored
additions marked [S]):

- **Page = hostile/untrusted.** May read every attacker-controllable string
  (URL, body, referrer, DOM, reflection, storage, console) and run arbitrary
  *own* code. Cannot produce D without evaluating W(S) (copy-class
  restriction; A4 Watch-aware residual accepted).
- **Server = untrusted.** May reflect, transform, truncate, encode, drop, or
  persist anything. Reflection/acceptance never confirms. Page-controlled IDs
  (object IDs, Location paths, record keys) are **hints for discovery, never
  proof of attribution**.
- **Executor = evidence provider, not authority.** Playwright dialog /
  request / instrumentation transports are executor-owned and page-unforgeable
  (A3); everything else (DOM text, console, generic network, storage) is
  advisory.
- **LLM = untrusted.** Suggests payload patterns and (for stored) workflow
  hints only. Never sees S/D/W/run_salt/oracle payloads; never decides
  SUBMIT-success, READ-location, persistence, or verdict.
- **Planner/verifier = trusted.** Deterministic derivation from
  run_salt + identities. Verifier is the sole classification authority.
- **A5/A6 inherited:** run_salt secret from target and fresh per run;
  5 s observation window (stored READ may need a second, longer window —
  see §20).

Stored-specific threats (must all fail closed):

- **A. Pre-existing stored payload.** DB already contains attacker content.
  Watch submits a benign/new candidate. READ executes the *old* payload.
  Must not CONFIRM the new candidate. *Design answer:* per-round unique S/D;
  only D_new (derived from this round's S_new) confirms; D_old ≠ D_new is
  rejected by exact match + freshness + round binding. Baseline READ (§16)
  provides defense-in-depth detection but is not the primary mechanism.
- **B. Benign storage echo.** App stores and re-renders payload as inert
  text/HTML. Must not CONFIRM. *Answer:* text rendering produces no E1/E2/E3;
  S4 absent → at most POTENTIAL.
- **C. Payload transformation** (HTML/URL/JSON-encode, quote-escape,
  truncate, whitespace-normalize). *Answer:* E1 requires exact D in the dialog
  (D is computed at runtime, emitted verbatim — encoding of the *stored
  payload body* does not alter D once the script runs; if the transform
  breaks the script, no E1/E2/E3 fires → INCONCLUSIVE/POTENTIAL, never
  CONFIRMED. E3 exact-payload equality additionally fails under any
  transformation → E3 simply does not fire; E1/E2 carry confirmation).
  Transformation evidence (truncation flags, reflection location) is advisory
  for triage, never verdict-grade.
- **D. Multiple stored records.** Thread/profile/comment list shows many
  records. *Answer:* round binding by (round_id-derived S/D + object-URL +
  ordering) plus exact-D matching; D from another record (another round or a
  foreign payload) never equals D_current. Record-ID hints (§6) are advisory
  only.
- **E. Concurrent submissions.** Two rounds in flight must not confirm each
  other. *Answer:* v1 serializes rounds (one SUBMIT→READ at a time per
  verifier run); distinct round_ids/S/D per candidate; evidence keyed by
  attempt_id + round binding + freshness.
- **F. Read-after-write ambiguity.** READ lists many records; oracle fires but
  which record caused it? *Answer:* exact-D attribution: only the record
  carrying S_current can compute D_current. Any other record's execution
  yields a different (or no) D and is rejected. Record-level visual
  attribution remains advisory; cryptographic attribution is at round
  granularity, which is sufficient because S is unique per round.
- **G. Existing stored XSS firing during READ.** Unrelated payload executes
  during our READ. *Answer:* same as A — its emitted value ≠ D_current →
  rejected. Baseline READ optionally records its presence for the audit note.
- **H/I. Cross-run / cross-attempt replay.** *Answer:* run freshness
  re-derivation under current run_salt + `oracle_identity`/round binding +
  per-attempt evidence binding, exactly as reflected/DOM.
- **J. Authentication/session state.** *Answer:* v1 UNAUTHENTICATED ONLY
  (§11). Any authenticated stored flow is OUT OF SCOPE and must fail closed
  (INCONCLUSIVE with `auth_required` note), not attempted.

## Security Goals

1. CONFIRMED(stored) ⟺ SUBMIT_ACCEPTED ∧ ROUND_BOUND ∧ S4(READ, own D) ∧
   FRESH, with S5 iff E2. Nothing else confirms.
2. Submission success alone, stored/reflected text alone, chain+token alone,
   correlation token anywhere, generic browser events, or foreign/pre-existing
   execution alone: never CONFIRMED.
3. D never appears in any wire-visible pre-execution material (SUBMIT request,
   READ URL, referrer, logs); S appears only in the SUBMIT body (never in the
   READ URL).
4. SUBMIT and READ are two distinct, transport-verified, time-ordered
   interactions; one executor pass never emits both.
5. Attribution is by exact D equality under round binding, not by token
   presence, payload-string presence, or page-controlled IDs.
6. All failures fail closed to INCONCLUSIVE/POTENTIAL with machine-checkable
   audit notes.

## SUBMIT Model

**Purpose:** perform the persistence operation and record evidence that the
application *accepted* the candidate — explicitly distinguishing "accepted"
from "proven stored" (storage is proven only by READ-side execution of our
own D).

**Attempt representation:** new attempt kind, not a reused reflection probe:

- `mode = HTTP_REFLECTION` (routed to `HTTPEvidenceExecutor`, extended —
  §20), `phase = "stored_submit"` (distinct from `"stored"` legacy and from
  `"http"`/`"browser"`/`"oracle"`; exact string is an implementation detail
  but must be distinct and constant).
- Carries the **oracle payload O** (planner-built, contains S_current, never
  D) as the submission field value — same O that READ will later execute.
  Seeding: `S = oracle_seed(run_salt, submit_attempt.attempt_id,
  "stored_submit")`, i.e. the SUBMIT attempt's own identity breaks the
  seed/payload cycle (unlike reflected, where the oracle attempt seeds from
  the candidate — here SUBMIT *is* the seed owner; see §8).
- Method/body: v1 supports GET-with-query (query param case) and
  POST form-encoded (`application/x-www-form-urlencoded`, single submission
  field = `case.parameter`). JSON bodies, multipart, multi-field forms,
  file uploads: OUT OF SCOPE v1 (INCONCLUSIVE `unsupported_submit_shape`).
  The case builder already yields method/location/parameter; SUBMIT uses them
  verbatim — never downgrades POST→GET.
- Session: unauthenticated only; no cookies persisted across attempts beyond
  what the executor's default session does transiently; CSRF: v1 does not
  fetch/solve tokens — if SUBMIT response indicates CSRF failure, verdict is
  INCONCLUSIVE (`csrf_required`), never retried with harvested tokens.

**Evidence recorded (HTTP executor extension, all untrusted except
transport facts):**

- `request_method`, full SUBMIT URL, request-body hash (sha256 of the exact
  bytes sent), `response_status`, response-body hash, redirect chain
  (hop list with per-hop status + Location), final URL
  (`actual_request_url`), response `Location` header value if present,
  and any extracted **object-hint** (see §5 — recorded as advisory string,
  never trusted).
- Timestamps `started_at`/`finished_at` (monotonic; future rejected).

**SUBMIT_ACCEPTED predicate (precondition, never proof):**

```
SUBMIT_ACCEPTED ≡ attempt_status == SUCCEEDED
  AND response_status in 2xx..3xx (after redirects)   # 4xx/5xx → SUBMIT_FAILED
  AND no WAF BLOCK/TRANSFORM observation
  AND (Location header present OR 2xx with non-error body
       OR response reflects the submission token — any ONE suffices as
       *acceptance*, recorded with which signal fired)
```

- HTTP 200 alone with an error page / "moderation queue" / "login required"
  marker → `persistence_unknown`, still SUBMIT_ACCEPTED (READ decides), but
  the audit records the weak signal. Only transport rejection (4xx/5xx,
  timeout, WAF block) is SUBMIT_FAILED → INCONCLUSIVE, READ never attempted.
- "Accepted" ≠ "stored": the state machine requires READ-side S4 regardless
  of how strong acceptance looks.

**On SUBMIT failure:** INCONCLUSIVE (`submit_failed`), no READ attempted, no
finding (or POTENTIAL only if the SUBMIT response itself meaningfully
reflects — explicitly capped; reflection during SUBMIT is S1 evidence about
the submission endpoint, never stored proof).

## READ Model

**Purpose:** retrieve the stored object through a genuinely separate,
*clean* interaction and observe whether *our* payload executes.

Requirements (all verifier-enforced where checkable, executor-guaranteed
otherwise):

1. **Separate interaction:** READ is a browser attempt
   (`mode=BROWSER_EXECUTION`, `phase="stored_read"`) executed strictly after
   `SUBMIT.finished_at` (timestamp ordering check). The same executor pass
   must never produce both SUBMIT and READ evidence (phase-keyed evidence
   types make this structural).
2. **Clean READ URL:** the READ navigation URL carries **no S, no D, no
   correlation token, no payload substring, no round secret**. The verifier
   re-checks this (anti-harvest over the READ URL for D; substring scan for S
   and the full payload — any hit → reject). The READ URL is the discovered
   object/display URL (§5), not the submission URL with parameters.
3. **No injection into READ URL:** binding is `bound_url = <display URL>` with
   no query augmentation. The existing browser executor's "bind payload into
   query" path must be bypassed for `phase="stored_read"`.
4. **No referrer leakage:** the READ navigation starts from a blank context
   (`about:blank`), so `document.referrer` on the READ page is empty/opaque;
   S never leaks via Referer. (S in the SUBMIT body is not referrer-visible
   anyway since SUBMIT is HTTP-only.)
5. **Fresh browser context:** new `browser.new_context()` per READ (existing
   per-attempt isolation suffices), closed afterwards. Cookies from SUBMIT are
   not carried (v1 unauthenticated; no shared session needed).
6. **Session continuity:** none required in v1 (unauthenticated public
   display). If the READ requires the submitter's session → OUT OF SCOPE →
   INCONCLUSIVE (`auth_required`).

**READ discovery (how Watch finds the display URL):** evaluated options:

| Option | Mechanism | Trust | v1 suitability |
|---|---|---|---|
| D1 Location header | `Location` on SUBMIT 3xx/201 | Hint (server-controlled) | **Preferred when present:** deterministic, standard REST/redirect-after-POST signal; still only a *navigation hint* — attribution comes from D, not the URL |
| D2 Case endpoint itself | `case.endpoint` (e.g. guestbook shows entries inline) | Hint | **Preferred fallback:** zero discovery risk; correct for self-displaying endpoints |
| D3 Response-body link | first same-origin `<a href>` matching object pattern | Hint, fragile | v1: allowed only as second fallback with strict same-origin + path-prefix sanity; recorded |
| D4 API-response ID | JSON `{id: N}` → templated display URL | Hint, app-specific | OUT OF SCOPE v1 (requires per-app adapters) |
| D5 Deterministic record URL | caller-supplied URL template | Config, not generic | OUT OF SCOPE v1 |
| D6 Search/listing crawl | crawl READ candidates | Unbounded, stateful | OUT OF SCOPE (crawl subsystem scope-protected) |

**v1 rule:** D1 if a same-origin Location is present, else D2, else D3 under
the stated constraints; else INCONCLUSIVE (`read_location_unknown`). The
chosen URL is recorded as `read_intended_url`; the final URL after redirects
as `read_actual_url`. Discovery choice never influences the verdict beyond
reachability — only D-equality does.

## Attribution Model

Four identities, deliberately separated:

1. **Transport identity** — `attempt_id` (+ `request_url`/`request_method`
   binding) per attempt. Proves *which interaction* evidence belongs to.
   Trusted (verifier-enforced exact match; mismatch → ERROR).
2. **Storage identity** — (round_id, object-hint, SUBMIT/READ hashes +
   ordering). Proves *a* SUBMIT happened before *a* READ. **Partially
   trusted:** hashes/ordering are transport facts (trusted); the object-hint
   (Location/ID/link) is server-controlled (advisory). Storage identity
   establishes *plausibility of persistence*, never proof of whose content
   executes.
3. **Payload identity** — S (wire-visible seed, unique per round). Proves
   *which candidate bytes* were submitted. Trusted as *uniqueness* (planner
   derivation), untrusted as *location* (anyone can copy S).
4. **Execution identity** — D = W(S) observed through E1/E2/E3. Proves
   *whose code ran*. **The only authoritative attribution.** D is
   unharvestable (copy-class), run-bound, round-bound, and observed only
   through executor-owned channels.

Identifier roles:

- `correlation_token`: transport/session convenience only. Usable for log
  correlation and the weak SUBMIT-acceptance reflection signal. **Never
  verdict-grade.** (Unchanged from the oracle model.)
- `oracle_seed` (S): payload identity + freshness input. Wire-visible by
  necessity (inside SUBMIT body). Copyable — hence never proof.
- `oracle_value` (D): execution identity. Never on wire pre-execution; exact
  match required.
- `attempt_id` (per SUBMIT / per READ): transport identity. Distinct per
  phase (different phase labels → different IDs).
- `logical_pair_id`: **not reused across SUBMIT/READ** as the pairing key
  (it excludes phase but its canonical includes the *payload* — SUBMIT and
  READ carry the same O, but the pairing semantics for stored need the round,
  not the reflected pair). Stored rounds pair by **`round_id`** (new),
  with `logical_pair_id` retained on each attempt for audit continuity only.
- `round_id`: the stored pairing key. `round_id = "sr-" +
  sha256(run_salt ‖ submit_attempt_id)[:32]` (verifier-derivable, single-use,
  never on wire, never persisted beyond the run). Both SUBMIT and READ
  attempts carry it; evidence references it; the verifier registry consumes
  it once.
- Response/request hashes: transport corroboration (detect mismatched
  pairing, truncated bodies). Advisory for verdict, valuable for audit.
- Object ID / Location value: **discovery hint only.** Page-controlled;
  recorded verbatim in evidence; never an input to the CONFIRMED predicate
  except the same-origin sanity check on the READ navigation.

Why page-controlled IDs cannot prove attribution: the server chooses what
Location/ID to return and what content to serve at any URL; a malicious or
buggy server can point Watch at attacker-chosen content regardless of what
was submitted. Only the runtime computation D = W(S_unique) — which no party
except the executing payload can produce — survives this.

## Stored XSS Oracle Model

Reuse of E1/E2/E3 unchanged (predicates, kinds, single-decode, ≤240 rule,
E2=S5). Stored-specific wiring:

- **SUBMIT carries S:** the oracle payload O (with embedded S and the inline
  W transform + E1/E2 actions) is the submitted field value. SUBMIT request,
  body, URL may therefore contain S — expected and harmless (S is not the
  proof). D must not appear in any SUBMIT material (planner self-check +
  verifier anti-harvest over SUBMIT pre-input).
- **READ contains no S:** the READ navigation URL, headers, and pre-navigation
  state contain neither S nor D (verifier re-checks; violation → reject).
  The only route by which S can reach the READ page is **server-side
  persistence** (the stored record), and the only route by which D can exist
  in the READ context is **execution of that record's script**.
- **Execution during READ produces D:** the persisted O renders, its script
  runs `W(S)`, emits `alert(D)` (E1) and/or `GET /.watch-oracle/<D>` (E2);
  E3 fires if the READ page evals the record content and O ≤ 240 chars
  (rare for real ~400-char payloads — same E3-inert reality as reflected;
  E1/E2 carry confirmation).
- **Verifier receives D only through executor-owned channels** on the READ
  evidence (`dialog_events`, `oracle_network_events`, `eval_invocations`).
  Generic READ channels carrying D (console echo of the dialog, DOM text of a
  beacon URL) are audit-only, never E1/E2/E3.

Pre-existing-payload reasoning (`OldPayload → D_old`, `S_new → D_new`):

- The READ page may execute both. `evaluate_e1/e2` are called with
  `value=D_new`; `D_old ≠ D_new` (distinct S ⇒ distinct D with overwhelming
  probability; 128-bit seed space, 64-bit D space) → old execution yields no
  match → rejected. Only exact `D_new` confirms.
- A page that copies S_new from the stored record into a beacon *without*
  executing still cannot emit D_new. A page that copies D_new *after* our
  payload executed it (post-execution echo) does not create a false positive:
  the E1/E2 events already required execution; echoes are not separate proof.
- Anti-harvest for stored scans **both** pre-inputs: SUBMIT pre-input (O,
  SUBMIT URL/body) and READ pre-input (READ URL). D in either → reject.
  Post-execution READ channels are never scanned (E1's own dialog echo into
  console must not self-contradict, same as reflected).

## Attempt Graph

Minimum secure set per candidate payload — **three attempts, two phases,
one round**:

```
Candidate (LLM pattern P, case C)
│
├─ SUBMIT attempt                     mode=HTTP_REFLECTION  phase="stored_submit"
│    payload = O (oracle payload, carries S)     attempt_id=As
│    evidence: HTTP (status/Location/hashes/token-reflection)
│
└─ READ attempt                       mode=BROWSER_EXECUTION phase="stored_read"
     payload = O (same O; NOT bound into URL)    attempt_id=Ar
     round_id shared with SUBMIT; oracle_seed=S; oracle_value=D;
     oracle_identity = As (SUBMIT attempt id — the seed owner)
     evidence: browser (E1/E2/E3 + clean-URL binding + stored_phases READ entry)
```

- The legacy `phase="stored"` single browser attempt is **retired** (no plan
  builder emits it; `_classify` no longer routes on it).
- No separate "READ HTTP" attempt in v1 (a browser READ subsumes observable
  HTTP facts via `actual_request_url`/status; adding a fourth attempt
  doubles cost for no verdict gain — recorded as FUTURE if header-level READ
  forensics are ever needed).
- No plain (non-oracle) browser attempt for stored (unlike reflected's
  plain+oracle pair): the READ *is* the oracle attempt. Token-in-runtime on
  READ is advisory attribution, never a separate POTENTIAL leg worth a second
  navigation. (Cost: 1 HTTP + 1 browser per candidate — cheaper than
  reflected's 1+2.)
- `attempt_id`: distinct per attempt (canonical includes phase → As ≠ Ar).
- `round_id`: shared by exactly the SUBMIT+READ of one candidate in one run.
- `oracle_identity`: = As (SUBMIT id). Freshness re-derivation:
  `oracle_seed(run_salt, oracle_identity, "stored_submit") == S`.
  The READ attempt carries S/D for predicate evaluation but the seed is
  owned by SUBMIT — direction SUBMIT-identity → S → O → READ, no cycle.
- `correlation_token`: distinct per attempt (derived from attempt_id+phase);
  used for log correlation and the weak acceptance signal only.
- Multiple rounds per candidate (retry after INCONCLUSIVE): allowed, each
  with a fresh round_id/S/D (round counter in the derivation). Concurrent
  rounds: forbidden in v1 (serialized).

## Round / Transaction Model

A **round** = `(candidate, round_id, SUBMIT attempt+evidence, READ
attempt+evidence, verdict)`. Properties:

- `round_id = "sr-" + sha256(run_salt ‖ 0x00 ‖ submit_attempt_id ‖ 0x00 ‖
  round_seq)[..32]`, where `round_seq` is 0 for the first round, incremented
  on retry. Deterministic, verifier-recomputable, unique per (run, candidate,
  retry). 256-bit preimage space; not persisted beyond the run; never on the
  wire (it is an index, not a secret — its security comes from S/D, not from
  hiding round_id).
- **Random vs deterministic:** deterministic-from-salt (same rationale as
  attempt_ids: reproducibility + auditability without a randomness source in
  the verifier; freshness comes from run_salt).
- **Run-salted:** yes (replay separation across runs).
- **Persisted:** no (verifier memory + per-finding `round_id` annotation for
  audit only; DB dedup remains keyed by case_id as today).
- **In payload/URLs:** no. round_id never enters the payload (would bloat and
  leak structure), never enters URLs (would pollute the clean-READ
  invariant). The payload carries S only; S is the round's wire
  representative.
- **Single-use registry:** verifier-side `consumed_rounds: set[round_id]`;
  a second READ claiming the same round_id fails closed (duplicate-READ
  rejection). Retries mint a new round_id (new S/D), never reuse.
- **Lifecycle:** plan (mint round_id + S/D/O) → SUBMIT → gate
  (SUBMIT_ACCEPTED?) → READ → classify → consume round_id. SUBMIT failure
  consumes the round without READ.

## Pre-existing Stored XSS Defense

Required combination (no single layer suffices; all are cheap except
baseline which is evaluated separately in §16):

- **A. Unique per-round oracle value (PRIMARY).** S/D fresh per
  (run, candidate, retry). Old content cannot emit D_new. This alone is
  sufficient for *correctness* of CONFIRMED; the layers below are
  defense-in-depth, triage quality, and auditability.
- **B. Storage-record attribution (SUPPORTING).** Object-hint + SUBMIT/READ
  hashes + ordering recorded; READ URL derived from SUBMIT's Location where
  available. Raises the bar for accidental cross-record confusion and gives
  analysts a trail. Never verdict-grade.
- **C. Clean baseline READ (OPTIONAL v1, see §16).** Pre-SUBMIT browser READ
  of the display URL recording which D-values already fire (none should match
  D_new since D_new is minted after — baseline instead records *any* dialog /
  oracle-path activity as `preexisting_activity=true`). Its value is triage
  (explaining INCONCLUSIVE-on-active-page) and detecting hostile pages, not
  attribution (baseline cannot attribute either).
- **D. Post-submit READ (MANDATORY).** The verdict READ. Only READ in v1
  unless baseline is enabled.
- **E. Differential evidence (MANDATORY as audit, not verdict).** The finding
  records pre/post READ summaries (dialog count, oracle-path count) so a
  reviewer can see the delta. Verdict still keys on exact D_new only.
- **F. Dedicated object retrieval (MANDATORY where available).** Prefer the
  Location-derived object URL over the generic listing page: fewer foreign
  records execute during READ, less noise, smaller blast radius.
- **G. Fresh browser context (MANDATORY).** Both baseline (if any) and verdict
  READ run in new contexts; no storage/cookie/state carries attacker values
  into READ.
- **H. Exact oracle matching (MANDATORY).** E1/E2/E3 exact predicates with
  D_new; everything else ignored for verdict.

What is explicitly NOT relied upon: payload-string matching in READ content
(anyone can store the same bytes), token matching (copyable), record-ID
equality (server-controlled), timing heuristics.

## Baseline READ Analysis

**Proposal:** optional `READ-before-SUBMIT` (browser, clean URL = the would-be
display URL, i.e. D2/D3 discovery without SUBMIT context; no payload in URL).

- **Security benefit:** low for *verdict correctness* (per-round D already
  excludes old content), moderate for *triage*: distinguishes "page already
  executes arbitrary stored content" (hostile/noisy target — findings need
  analyst care) from "quiet page, our D is the only signal" (clean proof).
  Also catches the pathological case where the display URL itself reflects
  URL input (stored endpoint that is also reflected — baseline with empty
  query proves the oracle channels are quiet without our content).
- **Performance cost:** +1 browser navigation per stored candidate (~the
  dominant cost; stored candidates are fewer than reflected, but the
  multiplier is 3× vs 2× per candidate with baseline).
- **Race conditions:** TOCTOU — content stored by others between baseline and
  verdict READ changes the page. Fails safe (exact-D still required) but can
  confuse the differential audit. Mitigated by keeping SUBMIT→READ tight and
  serializing rounds.
- **Dynamic content:** rotating ads/comments make baseline diffs noisy;
  differential audit must compare *oracle-channel events for D_new only*,
  never raw DOM diffs.
- **FN risk:** none for verdict (baseline never gates CONFIRMED; a noisy
  baseline must not suppress a valid D_new proof — otherwise an attacker
  could poison the baseline to hide our finding).

**Recommendation:** v1 WITHOUT mandatory baseline. Implement baseline as an
opt-in (`baseline_read: bool = False` planner flag, evidence recorded when
enabled) so noisy-target triage can use it, but the CONFIRMED predicate must
not require it. Revisit mandatory baseline only with production data showing
analyst confusion on shared-board targets. The exact evidence a baseline
establishes when enabled: `baseline_oracle_activity: {dialogs: [...],
oracle_paths: [...]}` + `baseline_at` timestamp — audit only.

## Authentication / Session Model

- **v1: unauthenticated only.** SUBMIT and READ share no session; READ runs in
  a fresh anonymous context. Any case whose SUBMIT response signals auth
  (`401/403`, login redirect, "sign in" marker) or whose READ lands on a
  login page → INCONCLUSIVE (`auth_required`), no retry, no credential use.
- **Must SUBMIT and READ share cookies?** No in v1 (public-board model:
  anonymous post → public display). Authenticated boards (only the poster sees
  the content) are OUT OF SCOPE.
- **Can the browser perform SUBMIT and READ in the same context?** Not in v1:
  SUBMIT is HTTP-only, READ browser-only, contexts never shared. (A future
  authenticated design would need same-context SUBMIT+READ with CSRF handling
  — explicitly deferred.)
- **CSRF tokens:** v1 does not harvest, solve, or replay them. CSRF-protected
  forms fail closed. No credential-handling machinery is introduced; the
  current Watch architecture (env-based LLM keys only, no target credentials)
  is unchanged.
- **Expiry between phases:** irrelevant in v1 (no session). SUBMIT→READ gap
  is seconds within one `verify()` call; no persistence of session across
  cases.

If authenticated Stored XSS is ever required, it needs a separate design
(session jar binding, CSRF-token flow, same-context SUBMIT+READ, logout
detection) — not an extension of this plan.

## Redirect / Origin Model

Reuse the existing browser security model (no new rules except where the
SUBMIT leg differs):

- **SUBMIT leg (HTTP executor):** follow redirects same as today (bounded
  hops, recorded chain). Cross-origin redirect on SUBMIT → allowed to
  complete (the app may POST to an API host), but `SUBMIT_ACCEPTED` requires
  the *final* response to satisfy acceptance; the Location-derived READ hint
  must be **same-origin with the case endpoint's registrable domain**
  (eTLD+1) or INCONCLUSIVE (`cross_origin_read_hint`). HTTPS→HTTP downgrade
  anywhere → INCONCLUSIVE.
- **READ leg (browser executor):** identical to the current oracle READ
  policy: initial navigation same-origin enforced, HTTPS-downgrade rejected,
  redirect chain audited hop-by-hop (same-origin, bounded); verifier
  re-checks `_origin(actual_request_url) == _origin(read_intended_url)` AND
  registrable-domain equality with the case endpoint. Cross-origin final READ
  → reject proof (INCONCLUSIVE).
- `intended_request_url` (pre-redirect READ URL) vs `actual_request_url`
  (final): both recorded; only final-origin equality enforced; both scanned
  by anti-harvest (D must be in neither; S/payload must be in neither for
  READ).
- Exact-origin (scheme+host+port) for the E2 predicate (unchanged);
  registrable-domain (eTLD+1) as the outer bound for READ-hint sanity
  (prevents subdomain-sprawl abuse while allowing app-legitimate
  `www.`↔`app.` display splits — recorded when it triggers).

## Evidence Trust Model

| Evidence | Source | Trust | Verdict role |
|---|---|---|---|
| SUBMIT request bytes/hash, method, URL | HTTP executor (transport fact) | TRUSTED | Binding + audit |
| SUBMIT response status/Location/hashes/chain | HTTP executor (transport fact) | TRUSTED | `SUBMIT_ACCEPTED` gate |
| SUBMIT response body token-reflection | Server-controlled echo | UNTRUSTED | Weak acceptance hint only |
| Object-hint (Location/ID/link) | Server-controlled | UNTRUSTED | Discovery hint only |
| READ navigation URLs (intended/actual), status | Browser executor (transport fact) | TRUSTED | Binding + origin checks |
| E1 dialog_events on READ | Playwright dialog listener | TRUSTED (executor-owned) | S4 authority |
| E2 oracle_network_events on READ | Request listeners, non-nav, same-origin | TRUSTED (executor-owned) | S4+S5 authority |
| E3 eval_invocations on READ | Capability transport | TRUSTED-WEAKER (page-space hook; FN-able, not FP-able) | S4 authority (eval-family) |
| READ dom/console/network-generic/storage | Page-controlled | UNTRUSTED | Advisory attribution only |
| stored_phases SUBMIT/READ entries | Executors (self-report) | PARTIALLY TRUSTED | Structural corroboration; token-equality re-checked by verifier; never sufficient |
| Timestamps | Executors | PARTIALLY TRUSTED | Ordering check; future timestamps rejected |
| Baseline activity (if enabled) | Browser executor | UNTRUSTED-AUDIT | Audit only |
| LLM pattern/idea/context | LLM | UNTRUSTED | Delivery-skeleton attribution only |

Page-controlled content is never verdict-grade. Executor-owned oracle
channels are the only execution authority. The verifier re-derives every
verdict input it can (D, seed, freshness, bindings).

## Stored XSS State Machine

Stages (stored-specific prefix, then shared oracle stages):

```
SUBMIT_ATTEMPTED → SUBMIT_ACCEPTED → STORAGE_ATTRIBUTED → READ_REACHED
  → JAVASCRIPT_EXECUTION → OBSERVABLE_EFFECT → CONFIRMED
```

| Stage | Machine-checkable predicate | Trusted source | Failure → | Authority |
|---|---|---|---|---|
| SUBMIT_ATTEMPTED | SUBMIT attempt executed; evidence bound (attempt_id/url/method) | Executor transport | INCONCLUSIVE (`transport_error`) | Verifier |
| SUBMIT_ACCEPTED | `SUBMIT_ACCEPTED` (§4) | HTTP evidence (status/Location/WAF) | INCONCLUSIVE (`submit_failed`) | Verifier |
| STORAGE_ATTRIBUTED | round_id shared SUBMIT↔READ; `oracle_identity==As`; ordering `read.started > submit.finished`; READ URL clean (no S/D/payload); same-registrable-domain hint | Verifier derivation + transport facts | INCONCLUSIVE (`attribution_failed`) | Verifier |
| READ_REACHED | READ evidence bound; final-origin == intended-origin; status SUCCEEDED | Browser transport | INCONCLUSIVE (`read_failed`) | Verifier |
| JAVASCRIPT_EXECUTION | E1 ∨ E2 ∨ E3 on READ with D_current (exact, after checks 1-6 of proof) | Executor-owned channels | POTENTIAL (see below) | Verifier |
| OBSERVABLE_EFFECT | E2 on READ with D_current | Executor-owned channel | (annotation, not gate) | Verifier |
| CONFIRMED | all above ∧ FRESH (seed re-derives under run_salt) ∧ ANTI_HARVEST clean | Verifier | — | Verifier |

Non-confirming ceilings: READ with stored text/token but no S4 →
POTENTIAL (`STORAGE_ATTRIBUTED`, only when SUBMIT_ACCEPTED + clean READ +
token-or-payload-substring observed in READ content — proves *something*
persisted, not execution). Any earlier failure → INCONCLUSIVE. No path yields
NOT_VULNERABLE.

## Exact CONFIRMED Predicate

```
CONFIRMED_stored ≡
    SUBMIT_ACCEPTED(submit_attempt As, submit_evidence Es)
  ∧ ROUND_BOUND(As, Ar, Es, Er):       # Ar = READ attempt, Er = READ evidence
      Ar.round_id == As.round_id
  ∧   Ar.oracle_identity == As.attempt_id
  ∧   SINGLE_USE(round_id)              # first READ for this round
  ∧   Er.read_started_at > Es.finished_at
  ∧   CLEAN_READ(Ar, Er):               # S,D,payload absent from READ URL
      S ∉ read_intended_url ∧ D ∉ read_intended_url ∧ O ⊄ read_intended_url
  ∧   READ_REACHED(Ar, Er): bound ∧ SUCCEEDED ∧ final-origin == intended-origin
  ∧   S4(Er, D): E1(Er.dialog_events,D) ∨ E2(Er.oracle_network_events,D,read_origin)
              ∨ E3(Er.eval_invocations,O ∧ |O|≤240)
  ∧   FRESH: oracle_seed(run_salt, As.attempt_id, "stored_submit") == S
  ∧   PAIR_VALID: validate_oracle_pair(S,D) ∧ D≠S
  ∧   ANTI_HARVEST: violations(S,D,PreSubmit ∪ PreRead) == []
```

Impossible-to-confirm-from list (each independently insufficient, even
jointly without S4): submission success alone; stored/reflected text alone;
READ-page reflection alone; source/sink chain alone; correlation token alone
(anywhere); generic network event; generic console message; generic DOM
mutation; storage write; pre-existing payload execution (wrong D); stale
evidence (wrong run); foreign-round evidence (wrong round/identity).

## Failure / Verdict Semantics

| Condition | Verdict | State/note |
|---|---|---|
| SUBMIT transport fail/timeout/4xx/5xx/WAF-block | INCONCLUSIVE | `submit_failed` |
| SUBMIT accepted, persistence unknown | proceed to READ | `persistence_unknown` (audit) |
| Object-hint missing & no fallback URL | INCONCLUSIVE | `read_location_unknown` (no READ attempted) |
| READ transport fail/timeout/WAF | INCONCLUSIVE | `read_failed` |
| READ cross-origin final / downgrade | INCONCLUSIVE | `origin_violation` |
| Oracle context unsupported (planner) | POTENTIAL at most | `unsupported_oracle_context` (SUBMIT still attempted? NO — fail before SUBMIT; INCONCLUSIVE with note. Rationale: submitting a non-oracle payload stores unprovable content — avoid polluting the target) |
| Browser unavailable / instrumentation fail | INCONCLUSIVE | `executor_error` |
| Oracle execution missing (no E1/E2/E3 with D) but stored text observed | POTENTIAL | `STORAGE_ATTRIBUTED` |
| Oracle execution missing, nothing stored | INCONCLUSIVE | `no_storage_evidence` |
| Old stored payload executes (D_old only) | POTENTIAL or INCONCLUSIVE per storage signal | `preexisting_execution_only` (never CONFIRMED) |
| Current payload reflected-in-READ-URL (should be impossible by construction) | INCONCLUSIVE | `read_not_clean` (fail closed — indicates executor bug) |
| Multiple oracle values execute incl. D_new | CONFIRMED | channels recorded; foreign values ignored (audit lists them) |
| Duplicate READ evidence / duplicate round | second ignored | `duplicate_round` (fail closed) |
| Concurrent rounds attempted | refused at plan time | v1 serializes; structural |
| Stale evidence (wrong run_salt) | INCONCLUSIVE | `freshness_failed` |
| Session/auth required | INCONCLUSIVE | `auth_required` |
| CSRF failure | INCONCLUSIVE | `csrf_required` |
| Malformed evidence | INCONCLUSIVE | `binding_failed` |

Never escalate on failure. Stored XSS never produces CONFIRMED from
acceptance, reflection, or advisory signals.

## Schema Impact

Minimum additive changes (no field removed, all defaults backward
compatible):

**`ai/schemas/xss_verification.py` (reuse + add):**

- Reuse unchanged: `VerificationAttempt.oracle_seed/oracle_value/
  oracle_version/oracle_identity`, `logical_pair_id`, `correlation_token`,
  `DialogEvent`, `NetworkOracleEvent`, `EvalInvocation`,
  `intended/actual_request_url`, `VerificationEvidence.dialog_events/
  oracle_network_events/eval_invocations`.
- ADD `VerificationAttempt.round_id: str | None = None` — the stored pairing
  key shared by SUBMIT+READ. (Why not reuse `logical_pair_id`: its canonical
  includes payload/attribution but not run_salt/round_seq; round needs
  run-binding + retry separation. Why not `oracle_identity` alone: identity
  names the seed owner; round names the transaction; both are needed.)
- ADD `VerificationAttempt.submit_body_hash / response_hash`-carrying fields?
  NO — hashes live on evidence, not attempts. Instead ADD on
  `VerificationEvidence`: `request_body_hash: str | None`,
  `response_body_hash: str | None`, `redirect_chain: list[str]`
  (capped length), `location_header: str | None`, `object_hint: str | None`
  (advisory verbatim string). All optional, empty defaults.
- ADD `VerificationEvidence.read_intended_url / read_actual_url`? NO —
  redundant: reuse existing `intended_request_url`/`actual_request_url` on
  the READ evidence. Document the mapping instead of duplicating.
- EXTEND `StoredXSSPhaseObservation` with `round_id: str | None = None` and
  optional `observed_oracle_hint: str | None` (never verdict-grade; triage
  only)? Preferred: add `round_id` only; do NOT add oracle-value-carrying
  observation fields (D must travel only through E-channels).
- Do NOT add: `run_salt` anywhere persisted; `mutation_snapshot`-style blobs;
  per-record IDs as first-class trusted fields; credential/session fields.

**`ai/schemas/xss_finding.py` (reuse):**

- Reuse `confirmation_state`/`oracle_channels` (populate for stored:
  `STORAGE_ATTRIBUTED` on POTENTIAL; `JAVASCRIPT_EXECUTION`/`OBSERVABLE_EFFECT`
  + channels on CONFIRMED). ADD `round_id: str | None = None` (audit
  annotation) and optionally `read_url: str | None` (audit). No other
  additions.

**`ai/schemas/xss.py` (no change required):**

- `XSSCase` already carries method/parameter/location/endpoint/context. If
  SUBMIT-shape metadata (form field name vs query) ever diverges from
  parameter_location semantics, a future `submit_hint` could be added —
  explicitly NOT proposed for v1 (deferred to Open Questions).

## Verifier Impact

`_classify_stored` evolves into `_classify_stored_oracle`
(specified, not coded):

- **Required inputs:** submit attempt+evidence, read attempt+evidence
  (resolved by `round_id`, not `logical_pair_id`), run_salt, planner
  (for S/D recomputation reference — verifier re-derives directly via
  `oracle_seed`/`oracle_value_from_seed`).
- **Pairing:** build `round_map: round_id → (submit_attempt, read_attempt,
  submit_evidence, read_evidence)` in `verify()`; duplicate round claims fail
  closed (first wins, rest INCONCLUSIVE + note).
- **Phase validation:** `submit.phase == "stored_submit"`,
  `read.phase == "stored_read"`; legacy `phase == "stored"` → route to
  demoted handler returning at most POTENTIAL (with `deprecated_stored_phase`
  note) during a migration window, then reject.
- **Ordering:** timestamp comparison with clock-skew tolerance (reject future
  timestamps outright; require `read.started > submit.finished`, else
  `attribution_failed`).
- **Oracle validation:** identical 7-step `_oracle_execution_proof` core run
  against (read_attempt-as-carrier, read_evidence), except step 3-4 use
  SUBMIT-owned derivation: `oracle_seed(run_salt, read.oracle_identity,
  "stored_submit") == read.oracle_seed` and
  `read.oracle_identity == submit.attempt_id`. E2 origin compares against the
  READ origin. Anti-harvest input = SUBMIT pre-input ∪ READ pre-input
  (SUBMIT URL/body + READ URL; D in either → reject).
- **Attribution validation:** clean-READ substring checks (S, D, O absent
  from READ URL), registrable-domain hint sanity, single-use consumption.
- **Replay protection:** freshness (run_salt) + round single-use + per-attempt
  evidence binding — same guarantees as reflected, extended across two
  attempts.
- **Exact CONFIRMED predicate:** §"Exact CONFIRMED Predicate" verbatim.
- **Legacy behavior removed/demoted:** the token-equality + runtime-token
  CONFIRMED conjunction is deleted. During migration it may remain as a
  POTENTIAL-only path (`STORAGE_ATTRIBUTED` ceiling) behind the same inputs,
  but it must never return CONFIRMED. The `_http_path_confirms`-on-paired-HTTP
  precondition for stored is deleted (SUBMIT acceptance replaces it; the old
  HTTP reflection leg for stored cases is no longer planned).
- Verifier remains sole classification authority; no executor/LLM input to
  status/state/channels.

## Executor Impact

- **`http_executor.py` (SUBMIT-capable, moderate change):** add SUBMIT request
  builder (form-encoded POST from case.parameter + O; GET-query when
  method==GET; reject other shapes with structured `unsupported_submit_shape`
  ERROR), Location-header capture, body-hash recording, redirect-chain
  recording, acceptance-signal classification (status/Location/WAF). No oracle
  logic in the executor (it transports O opaquely). No credential/CSRF
  machinery.
- **`browser_executor.py` (READ-capable, small change):** for
  `phase == "stored_read"`: skip query-binding of the payload (navigate the
  display URL bare), enforce clean-URL construction, record the standard
  oracle channels unchanged (E1/E2/E3 production already complete), emit the
  READ `StoredXSSPhaseObservation` with `round_id` when any channel fires
  (or when token/payload substring observed — advisory). Retire the legacy
  `phase == "stored"` READ-emission branch (or gate it behind the migration
  flag). No oracle-predicate logic in the executor (unchanged separation).
- **`composite_executor.py` (no logic change):** routing stays mode-based
  (SUBMIT `HTTP_REFLECTION` → http; READ `BROWSER_EXECUTION` → browser).
  Phase-keyed validation (SUBMIT-never-to-browser, READ-never-to-HTTP) is a
  verifier-plan invariant, not a dispatcher rule — no code needed beyond what
  exists. Explicitly: existing executor capabilities are sufficient for the
  oracle channels; only the SUBMIT builder + READ clean-navigation are new.
- **No change to `oracle.py`** (planner/predicates/anti-harvest) is required:
  `OraclePlanner.plan` already supports the needed contexts; stored calls it
  with the SUBMIT identity and `phase="stored_submit"`. If a stored case
  context is unsupported → no SUBMIT (fail before polluting the target).

## Pipeline / Production Impact

- **`XSSVerificationPipeline`:** no structural change (still
  `analyze → verify`). The stored SUBMIT→READ sequencing lives *inside*
  `XSSVerifier.verify()` (sequential `_safe_execute` per attempt, SUBMIT
  before READ, gate on acceptance) — the pipeline must not orchestrate
  phases. One consideration: `verify()` currently executes all planned
  attempts unconditionally; stored needs **gated execution** (skip READ when
  SUBMIT fails / context unsupported). That is a verifier-internal control
  change, not a pipeline change.
- **`watch_xss_verify.py`:** no new credentials, flags, or wiring. The single
  per-run `run_salt` suffices (round_ids derive from it; per-round freshness
  inherits per-run freshness). No additional state. Serialization note: stored
  rounds are sequential *within* a `verify()` call; cases remain sequential
  in `run_job` — no new concurrency. If a future scheduler parallelizes
  cases, rounds must stay case-serial (documented constraint, no code today).
- **Cost:** 1 HTTP + 1 browser per stored candidate (2×, vs reflected 3×);
  +1 browser if baseline opt-in is enabled. No pipeline timeout change
  required beyond the existing per-attempt bounds (consider a longer READ
  window for slow-persisting apps — FUTURE tuning, not v1).

## V1 Scope

**IN SCOPE:**

- Unauthenticated targets only.
- Single submission field (`case.parameter`; form-encoded POST or GET query).
- Synchronous persistence (SUBMIT response → immediately READ; no polling).
- READ discovery D1→D2→D3 (§5) with same-registrable-domain bound.
- Same-origin READ; HTTPS everywhere (downgrade fails closed).
- One candidate per round; serialized rounds; retry = new round.
- Generic (context-planner-supported) payloads only; unsupported context →
  no SUBMIT, INCONCLUSIVE.
- Verifier-gated execution; legacy stored path demoted/removed.

**OUT OF SCOPE (fail closed with named notes):**

- Authenticated sessions, CSRF-token flows, CAPTCHA, MFA.
- JSON/multipart/file-upload/multi-field/multi-step workflows.
- Asynchronous moderation queues / delayed publishing (no polling loop).
- App-specific adapters (per-product comment/profile/ticket APIs).
- Baseline-mandatory operation (opt-in only).
- `new Function` sink coverage (inherits v1.1 gap).
- Active pollution-avoidance beyond "don't SUBMIT when unprovable".

**FUTURE:** authenticated round design; async-persistence polling with
bounded retries; JSON/multipart SUBMIT shapes; API-ID-templated discovery
(D4); READ-HTTP forensics leg; mandatory-baseline evaluation from production
data; E3-on-long-payload revisit (shared with reflected).

## Security Invariants

1. A stored candidate is CONFIRMED only by execution of its own D during its
   own round's READ (exact E1/E2/E3 match under full proof).
2. D never appears in pre-execution wire-visible material (SUBMIT request,
   READ URL, referrer, logs).
3. S appears only in the SUBMIT body (never in any READ URL or second-round
   material except as the new round's own fresh S).
4. SUBMIT and READ are distinct, bound, time-ordered interactions; one pass
   never emits both.
5. READ navigates a clean URL (no S/D/T/payload/round secret); violation fails
   closed.
6. Pre-existing stored content cannot confirm the current round (per-round D).
7. Cross-round evidence cannot confirm the current round (round_id single-use
   + identity binding).
8. Cross-run evidence cannot confirm the current run (run_salt freshness).
9. Correlation token never proves execution or storage.
10. Generic browser events (DOM/console/network-generic/storage) never prove
    execution.
11. Submission acceptance alone never proves XSS (or storage — only READ-side
    S4 proves the chain end to end).
12. Page-controlled values (Location, IDs, links, response bodies) are
    discovery hints only, never proof inputs (except same-origin sanity).
13. Unsupported/ambiguous workflows (auth, CSRF, async, unknown READ location,
    unsupported context) fail closed, and unsupported-context candidates are
    never submitted.
14. Retries mint fresh rounds (fresh S/D/round_id); round_ids are never reused.
15. The verifier is the sole classifier; executors/LLM/pages never influence
    status/state/channels.

## Test Matrix

Conventions: proofs run through `XSSVerifier.verify()` with structured fake
executors unless marked `[real-browser]`; each case asserts
(status, confirmation_state, oracle_channels, audit note).

**POSITIVE (all → CONFIRMED):**

- P1 clean form-POST SUBMIT (201 + Location) → clean READ → E1(D_new) →
  CONFIRMED/JAVASCRIPT_EXECUTION/[E1].
- P2 same via D2 self-endpoint READ → E2(D_new) →
  CONFIRMED/OBSERVABLE_EFFECT/[E2].
- P3 E1+E2 together → CONFIRMED/OBSERVABLE_EFFECT/[E1,E2].
- P4 E3 with short O (hand-built ≤240) → CONFIRMED/JAVASCRIPT_EXECUTION/[E3].
- P5 retry round (round_seq=1, fresh S/D) after first INCONCLUSIVE →
  CONFIRMED on the new round only.

**NEGATIVE (never CONFIRMED):**

- N1 stored text but no execution → POTENTIAL/STORAGE_ATTRIBUTED.
- N2 SUBMIT reflection only (no READ execution) → ≤POTENTIAL.
- N3 old stored payload executes (D_old in E1/E2), ours silent →
  ≤POTENTIAL + `preexisting_execution_only`.
- N4 wrong D (off-by-one hex) → INCONCLUSIVE.
- N5 wrong S (S tampered post-plan) → freshness/pair fail → INCONCLUSIVE.
- N6 wrong round (READ evidence carries round_id_B for round_A) →
  INCONCLUSIVE.
- N7 wrong attempt (evidence.attempt_id mismatch) → ERROR → INCONCLUSIVE.
- N8 wrong run_salt (replay prior run's D) → INCONCLUSIVE.
- N9 wrong candidate (D from candidate A evaluated against candidate B) →
  INCONCLUSIVE.
- N10 D in generic network/console/DOM on READ (no E-channel) →
  ≤POTENTIAL (not E2/E1).
- N11 correlation token everywhere, no D → ≤POTENTIAL.
- N12 duplicate oracle events (same D twice) → CONFIRMED once, no severity
  change (idempotence check).
- N13 multi-record page: our D + foreign D both fire → CONFIRMED on ours,
  foreign ignored (audit lists both).
- N14 READ URL polluted with S (executor bug simulation) → INCONCLUSIVE
  (`read_not_clean`).

**SECURITY:**

- S1 concurrent candidates A,B (interleaved evidence) → each verifies only
  on own round (cross → INCONCLUSIVE).
- S2 cross-run replay (run N evidence into run N+1 verifier) → INCONCLUSIVE.
- S3 cross-round replay (round 0 D into round 1 READ) → INCONCLUSIVE.
- S4 stale READ (pre-SUBMIT timestamp) → INCONCLUSIVE (`attribution_failed`).
- S5 cross-origin READ redirect → INCONCLUSIVE.
- S6 HTTPS downgrade on READ → INCONCLUSIVE.
- S7 object-hint substitution (Location points at attacker page that echoes
  D_new without executing — impossible without W; simulate with wrong-D page)
  → INCONCLUSIVE.
- S8 page-controlled record ID claiming our round → ignored (D decides).
- S9 malicious page copying S_new into beacon path → not E2 (path ≠
  `/.watch-oracle/D_new`) → ≤POTENTIAL.
- S10 S_new/D_new harvested from SUBMIT response reflection and replayed into
  READ URL → clean-READ check fails → INCONCLUSIVE.

**FAILURE:**

- F1 SUBMIT timeout / 5xx / WAF-block → INCONCLUSIVE, READ not attempted
  (assert executor call count: SUBMIT=1, READ=0).
- F2 READ timeout → INCONCLUSIVE.
- F3 unsupported context → INCONCLUSIVE, SUBMIT not attempted (assert 0
  SUBMIT calls — anti-pollution).
- F4 browser unavailable → INCONCLUSIVE.
- F5 malformed evidence (non-model return) → INCONCLUSIVE.
- F6 missing persistence evidence (READ shows nothing) → INCONCLUSIVE or
  POTENTIAL per storage signal (assert never CONFIRMED).
- F7 duplicate round READ → second INCONCLUSIVE.
- F8 `phase="stored"` legacy attempt (migration) → at most POTENTIAL.

## File-by-File Implementation Plan

1. **`ai/schemas/xss_verification.py`** — *add round + SUBMIT forensics
   fields.* Add `VerificationAttempt.round_id`; extend
   `StoredXSSPhaseObservation` with `round_id`; add optional
   `request_body_hash/response_body_hash/redirect_chain/location_header/
   object_hint` to `VerificationEvidence` (all defaulted). Why: binding +
   audit without breaking existing producers. Depends on: nothing. Security:
   advisory fields must be `Optional`/defaulted so absence fails closed.
   Tests: schema defaults/back-compat; tampered round_id rejected (verifier
   level).
2. **`ai/schemas/xss_finding.py`** — *audit annotation.* Add `round_id` and
   `read_url` (both `Optional`, verifier-set). Why: stored auditability.
   Tests: defaults; populated on stored CONFIRMED/POTENTIAL.
3. **`ai/verification/verifier.py`** — *core.* New `build_stored_round()`
   factory (SUBMIT+READ attempt construction + OraclePlanner call with
   `phase="stored_submit"`); plan-builder stored branch emits the pair (no
   legacy single, no HTTP-reflection leg for stored); `verify()` gains
   round_map + gated execution (READ skipped unless SUBMIT_ACCEPTED and
   planner supported) + single-use registry; `_classify` routes
   `stored_submit`→ acceptance gate (never a finding) and
   `stored_read`→`_classify_stored_oracle` (new; §Exact predicate);
   `_classify_stored` demoted to POTENTIAL-only shim then deleted. Why:
   everything verdict-grade lives here. Depends on: 1. Security: ordering
   (binding→freshness→identity→origin→anti-harvest→predicates); no new
   CONFIRMED site except the oracle one. Tests: full §Test Matrix.
4. **`ai/verification/http_executor.py`** — *SUBMIT transport.* Implement
   SUBMIT builder + forensics capture (§4-5). Why: persistence interaction
   does not exist today. Depends on: 1. Security: opaquely transports O;
   never logs bodies; redacts Cookie/Authorization (existing rule). Tests:
   SUBMIT shapes, Location capture, hash correctness, unsupported-shape
   ERROR.
5. **`ai/verification/browser_executor.py`** — *clean READ.* Implement
   `stored_read` navigation (no payload binding, blank-origin start) +
   round-tagged READ observation; retire legacy `stored` branch. Why:
   clean-READ invariant is executor-guaranteed. Depends on: 1. Security:
   context isolation unchanged; oracle channels unchanged. Tests: clean-URL
   assertion, READ observation presence/absence, real-browser integration
   (`[real-browser]` P1 analogue against a local stub server).
6. **`ai/verification/composite_executor.py`** — *no change expected.*
   Verify mode routing covers the new phases (it does: mode-based). Add only
   a regression test pinning SUBMIT→HTTP / READ→browser routing.
7. **`ai/verification/xss_pipeline.py` / `watch_xss_verify.py`** — *no
   functional change.* Document the case-serial constraint; reuse the single
   run_salt. Add an entrypoint regression test (pipeline builds a verifier
   with non-None run_salt; stored case plans a round) — closes the
   production-integration review's MEDIUM-2 gap as a side effect.
8. **Tests** — new `ai/test_xss_stored_round.py` (matrix above) + updates to
   `test_xss_verification.py` (legacy stored CONFIRMED fixtures →
   POTENTIAL/INCONCLUSIVE with justification), `test_browser_executor.py`
   (READ observation), `test_http_executor.py` (SUBMIT forensics),
   `test_xss_pipeline.py` (round planning passthrough).

Explicitly NOT modified: `oracle.py` (predicates/planner/anti-harvest),
`xss_case_builder.py`, `researcher/*`, `knowledge/*`, `llm/*`,
`schemas/xss.py`, `database/*`, `crawl/*`, `ns/*`.

## Migration / Legacy Behavior

- Old stored CONFIRMED findings in the database **remain as historical
  records** but are **not re-validated** by this design: the verifier affects
  new runs only; no DB migration, no reclassification job, no schema migration
  is required (new optional fields default safely on old documents at read
  time via Pydantic defaults; MongoEngine documents ignore unknown fields
  symmetrically — verify at implementation time with a read-back test).
- `_classify_stored` (token-based CONFIRMED) must be **removed**; a one-release
  POTENTIAL-only shim is acceptable for audit continuity but must be
  time-boxed and must never return CONFIRMED. Old `phase="stored"` attempts in
  flight (none persist — plans are per-run, never serialized) need no
  handling.
- `stored_phases` without `round_id` (old evidence shape) is treated as
  legacy → at most POTENTIAL.
- Report to operators: stored CONFIRMED volume is expected to drop (fewer,
  stronger confirmations) and stored POTENTIAL volume to rise — this is the
  intended effect, not a regression.

## Implementation Stop Conditions

STOP (no guessing, report back) if during implementation any of the following
is discovered:

1. The schema cannot represent round binding without breaking existing
   producers, and no additive alternative exists.
2. SUBMIT acceptance cannot be distinguished from transport failure for the
   target class (e.g. all targets return 200-with-error-page and no Location
   or signal) AND no safe READ-location fallback exists — do not invent
   persistence proof.
3. The READ URL cannot be constructed clean (executor must bind payload into
   every navigation by architecture) — the clean-READ invariant is
   non-negotiable.
4. READ execution cannot be bound to the round (evidence lacks attempt
   identity or oracle channels do not survive transport).
5. Authenticated flows are required for the target inventory (auth markers on
   SUBMIT/READ for the in-scope population) — v1 must stop, not add session
   machinery.
6. D appears in pre-execution material by construction (e.g. a SUBMIT shape
   that requires echoing derived values) — anti-harvest cannot be satisfied.
7. Per-round unique S/D cannot be plumbed through SUBMIT→READ without LLM or
   page visibility into D.
8. Executor phase-keyed behavior (SUBMIT builder / clean READ) proves
   infeasible without breaking reflected/DOM paths — do not regress working
   classes for stored.

## Open Questions

1. Should the SUBMIT leg support JSON bodies in v1 (many comment/profile APIs
   are JSON-only)? Recommendation: no — measure target population first; JSON
   is the prime v1.1 extension candidate.
2. Should READ support a bounded persistence-polling loop (submit → poll READ
   N× for async backends)? Recommendation: no in v1 (sync only); polling
   introduces flaky verdicts and stateful verifiers.
3. Should baseline READ become mandatory after production data? Recommendation:
   decide from analyst-feedback data, not a priori (see §16).
4. Should `round_id` enter the DB dedup key (case_id + round generation)?
   Recommendation: no for v1 (case_id dedup already prevents re-verification;
   rounds are intra-run).
5. Should E3's 240-char rule be revisited for stored (stored transforms often
   truncate, making E3 even less viable)? Recommendation: inherit as-is; E3
   stays supplementary.
6. Should the demoted legacy stored path keep emitting POTENTIAL long-term as
   a "storage signal" for triage? Recommendation: yes as POTENTIAL with
   `STORAGE_ATTRIBUTED`/legacy note — cheap, useful, honest.

## Final Recommendation

Implement the v1 design above in the file order of §"File-by-File
Implementation Plan" (schemas → verifier → executors → tests → entrypoint
regression), enforcing the stop conditions and the full §"Test Matrix"
before any production rollout. Expected outcome: stored CONFIRMED becomes as
strong as reflected/DOM CONFIRMED (exact own-D execution proof across a real
SUBMIT→clean-READ round), pre-existing-content and benign-echo false
positives are structurally excluded, and every failure fails closed. Legacy
stored CONFIRMED must be retired, not grandfathered into the new predicate.
