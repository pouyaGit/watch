# Execution-Oracle Design Review — Anti-Harvest XSS Execution Proof

Design-only review. Goal: a security-grade **execution oracle** for the Watch
XSS confirmation model such that (a) a page that has received the attack
request but has NOT executed attacker code cannot reproduce the oracle value,
and (b) actual attacker-controlled JavaScript execution produces evidence
Watch can verify locally with Playwright.

Inputs consulted: `ai/schemas/xss.py`, `ai/schemas/xss_verification.py`,
`ai/schemas/xss_finding.py`, `ai/verification/*` (verifier, http/browser/
composite executors, pipeline, case builder), `ai/researcher/xss_*.py`,
`ai/test_xss_verification.py`, and `/opt/watch/xss-confirmation-design.md` +
`/opt/watch/xss-confirmation-implementation-readiness.md` (located and
consulted; their blocking-gap list — raw-marker harvest, exact-path E2,
stored READ URL/Referer leakage, stored HTTP-pair FP12, DOM S3-hook gaps —
is addressed explicitly in Sections 2–8). The readiness blocker
("marker harvestable from attacker-controllable data") is resolved by the
derived-value design in Section 2-H.

---

## 1. Threat Model

### 1.1 Principal insight

The payload — and therefore anything literally embedded in it — is always
attacker-controllable *data* on the wire. It reaches the page through
`location.search` (reflected cases), request bodies, `document.referrer`, the
DOM, and reflected HTML. Therefore:

> **Any oracle value that appears verbatim in the payload can be harvested by
> any code (or template engine) that copies attacker-controllable strings —
> without executing any attacker JavaScript.**

Harvest vectors are *copy operations*: string interpolation into URLs, query
parsing, telemetry beacons, referrer propagation, DOM echoing, template
rendering. They are not arbitrary computation: a benign page does not run a
hash function over substrings of its own query string and place the result in
an alert or a request path. This asymmetry — copy is free, computation is
intentional code — is the foundation of the design.

Consequence: the marker **on the wire must be a seed, and the oracle value
must be a deterministic function of that seed computed only at runtime by the
payload's own code**. Copying the wire can recover the seed; it cannot recover
the oracle value.

### 1.2 Visibility table

"S" = oracle seed (embedded in payload); "D" = derived oracle value
(`D = W(S)`, Section 2, Design H); "payload" = full bound input including
payload text and S.

| Information | Visible before attacker execution? | Visible after attacker execution? | Can benign page reproduce oracle? | Can verifier trust it? |
|---|---|---|---|---|
| `location.search` / query string | Yes — contains payload text incl. S | Yes | S only, by copy; **never D** (D exists only as output of W) | S reads are untrusted; D never appears here |
| `location.hash` | Yes if payload delivered via fragment | Yes | S only, by copy | Same as above |
| `location.href` | Yes (full URL) | Yes | S only | Untrusted |
| `document.referrer` | Yes — full previous URL incl. payload when navigation came from a link with the payload in it | Yes | S only | Untrusted; cross-page leakage of S is harmless because D is never on the wire |
| DOM (text/HTML of reflected/stored payload) | Yes | Yes | S only | Untrusted |
| Request URLs (this request, subresource URLs, beacons) | Yes for URLs built by copying location/referrer | Yes | S-containing paths only; **D-path impossible without computing W** | D-path = trusted execution evidence |
| Request bodies | Yes if body carries the payload (POST reflection) | Yes | S only | Untrusted |
| Reflected response HTML | Yes — server echoes payload incl. S | Yes | S only | Untrusted |
| Console (page's own logs, pre-execution) | Yes if page logs location | Yes (attacker logs too) | S only | Console channel capped at stage-3 evidence |
| `localStorage` / `sessionStorage` | Pre-existing app data; page may persist payload | Yes | S only | Untrusted |
| Browser APIs (history, PerformanceObserver entries, service-worker caches) | URLs copied from location/referrer | Yes | S only | Untrusted |
| **Derived value D** | **No — exists nowhere on the wire, in the DOM, in storage, or in any string the page can read** | **Yes — computed by `D = W(S)` inside executing payload code** | **No — reproduction requires running W, i.e. running payload-derived code** | **Trusted: exact-match oracle** |

### 1.3 Adversary classes considered

1. **Benign first-party page** receiving the attack request (search/filter
   pages, routers, analytics): copies strings; never computes W. Cannot
   reproduce the oracle. Primary target of this design.
2. **Hostile-but-not-executing page** (attacker-influenced content echoed as
   text, attacker-controlled stored content rendered inertly): same as (1).
3. **Vulnerable page that executes attacker input**: executes the payload,
   computes W(S), fires the oracle. This is a *true positive*.
4. **Adversarial page deliberately targeting Watch** (knows W, extracts S,
   computes and emits D without the payload executing): see Section 7,
   Assumption A4 — outside the benign threat model and indistinguishable from
   execution by any local protocol; residual risk accepted and documented.

---

## 2. Marker Design Comparison

Notation: S = seed present in payload text; M = literal marker; D = derived
value. "Harvestable" = reproducible by copy-only operations available to a
non-executing page.

### A. Raw marker in URL/body (current proposal)
- On the wire: full marker M inside the payload.
- Page can read: M (query/DOM/referrer/reflection).
- Harvestable: **YES** — `alert(extract(location.search))` or
  `fetch('/' + extracted)` reproduce the oracle verbatim.
- Complexity: trivial. Playwright/verifier observability: good.
- FP resistance: **POOR** (analytics path copy, echo pages). FN risk: low.
- Verdict: rejected — this is the readiness blocker.

### B. Marker split into fragments
- On the wire: M = m1‖m2‖…‖mn, fragments separated by payload text.
- Page can read: fragments and — crucially — the *payload text itself*, which
  a reflected/DOM page can read contiguously (the DOM contains the rendered
  payload; `location.search` contains the whole bound input). Recomposition is
  a copy+concat operation.
- Harvestable: **YES** (concatenation is a copy operation).
- Complexity: low. FP resistance: poor. FN risk: moderate (fragments confuse
  weak echo heuristics only).
- Verdict: rejected.

### C. Runtime reconstruction via `String.fromCharCode(...codes)`
- On the wire: a code array; M never literal.
- Page can read: the code array (payload text).
- Harvestable: reconstructing M requires *executing* `String.fromCharCode` on
  the array — i.e. running payload-derived logic. Copy alone cannot.
- BUT: reconstruction is a *one-liner* a page could perform only if it
  executes the payload snippet — which is the true-positive case. However the
  array-to-string relationship is trivially scriptable by an adversarial
  telemetry/router page? No — a benign page does not `fromCharCode` arbitrary
  query integers. FP resistance: good.
- Weakness: the code array is effectively an obfuscated literal; the *value*
  M then appears in alert/path verbatim, so any harvesting of the *executed*
  argument is fine, but a page that extracts the array and passes it to a
  generic decoder is still not benign-realistic. Acceptable but weak vs H.
- Complexity: low. Observability: good. FN risk: low.
- Verdict: acceptable fallback; superseded by H.

### D. Runtime reconstruction via concatenation
- On the wire: `'con' + 'cat' + …` fragments in expression form.
- Page can read: fragments. Harvestable: requires evaluating the expression =
  executing payload code. Equivalent in strength to C but the fragments are
  textual and template engines that re-assemble markup can occasionally
  re-join them (mutation-style reconstruction in the DOM), giving
  stage-3-level artifacts — harmless for stage-4 but noisy.
- FP resistance: good. Complexity: low. FN risk: low-moderate.
- Verdict: acceptable; superseded by H.

### E. Runtime reconstruction via arithmetic/encoding
- On the wire: arithmetic expression over byte values (e.g. base36 chunks,
  XOR chains).
- Strength equivalent to C/D; slightly higher FN risk (numeric edge cases,
  operator precedence mistakes across JS engines are negligible, but payload
  length grows).
- FP resistance: good. Complexity: moderate. Verdict: acceptable; superseded by H.

### F. Hash-derived marker (marker = hash of wire data)
- On the wire: no marker at all; payload instructs code to hash something
  wire-visible (e.g. `sha256(location.search)`).
- Page can read: the hashed input. Harvestable: reproducing the hash requires
  running the hash — but the *input* is arbitrary page data, so the verifier
  cannot independently predict the value without replicating page semantics.
  Worse: an analytics page hashing its own URL produces *a* hash — but not the
  exact one unless input matches exactly; predicate becomes brittle.
- FP resistance: good. FN risk: **high** (encoder availability, secure-context
  requirements of `crypto.subtle`, URL normalization drift between page and
  planner).
- Verdict: rejected as specified; the *fixed-input* variant (hash of the
  embedded seed) is the correct idea → Design H.

### G. Per-attempt capability not present in the request
- On the wire: nothing; the value would have to come from outside (out-of-band
  canary, server-side injection into the response).
- Page can read: only if the server/Watch injects it into the response — at
  which point the *server* is the harvester (server is untrusted) and the
  value is readable pre-execution from response HTML. Self-defeating.
- A true out-of-band canary is structurally unobservable by the current
  same-origin browser policy (cross-origin traffic is aborted) and adds
  external infrastructure trust.
- Verdict: rejected for v1.

### H. Derived oracle value: commit–reveal (RECOMMENDED)
- On the wire: **seed S only** (32 hex chars), embedded in the payload body,
  plus the compact pure-JS transform W. **D = W(S) appears nowhere on the
  wire.**
- Page can read: S and the transform source text. Harvestable: **NO** — D can
  be produced only by *executing* W on S, i.e. by running payload-derived
  code. Copy/echo/telemetry/referrer operations reproduce S-shaped strings,
  never D.
- W is deterministic and mirrored in the verifier (Python), so the verifier
  knows D exactly: `D = hex(fnv1a32(S)) ‖ hex(fnv1a32(hex(fnv1a32(S)) + ':' + S))`
  → 16 hex chars (double-round FNV-1a 32-bit; two independent rounds make
  accidental 16-hex-char collisions by copying impossible and give ~2^-64
  accidental-collision resistance; W is NOT a cryptographic PRF — see
  Section 7 for the honest property statement).
- FP resistance: strong (Section 6). FN risk: low (pure JS, no secure-context
  dependency; bitwise ops are identical across engines via `>>> 0`).
- Complexity: low-moderate (planner emits W inline; Python mirror ~15 lines).
- Observability: E1 dialog message == D; E2 path == '/.watch-oracle/' + D;
  both verified exactly.
- Verdict: **RECOMMENDED**.

---

## 3. E1 Dialog Oracle (safest design)

### 3.1 Generation — trusted deterministic planner, never the LLM

- **Planner inputs** (all trusted): `case_id`, `attempt_id`,
  `logical_pair_id`, `run_salt`, `phase`, payload *skeleton class* (context
  type: html_attribute / script_block / html_body / url), max payload length,
  and the LLM/context payload *pattern id* (for attribution only).
- **Planner outputs** (all derived, deterministic, recorded on the attempt):
  - `oracle_seed S` = HMAC-less derivation: `S = sha256(run_salt ‖ attempt_id
    ‖ phase)[:16]` rendered as 32 hex chars (verifier-owned, run-salted —
    anti-replay by construction);
  - `oracle_value D = W(S)` (Section 2-H) — recorded on the attempt as the
    expected value, never placed in any request;
  - `oracle_payloads`: one payload string per context type, each = exploit
    core (from the LLM suggestion, sanitized to the pattern) + oracle snippet.
- The **LLM never sees S, D, or W** and never generates the oracle. The LLM's
  payload pattern may be used as the *delivery skeleton*; the planner wraps it.
  If the LLM pattern cannot host the snippet (e.g. attribute-size limits), the
  planner falls back to canonical skeleton payloads — this is planner
  behavior, not payload generation by the LLM.

### 3.2 Exact payload structure (reflected, html_body context example)

```
<img src=x onerror="var s='<S>';var h=0x811c9dc5,i;for(i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,0x01000193)>>>0}var h2=0x811c9dc5,t=h.toString(16)+':'+s;for(i=0;i<t.length;i++){h2^=t.charCodeAt(i);h2=Math.imul(h2,0x01000193)>>>0}alert((h).toString(16)+(h2).toString(16))">
```

(Inline form shown compact; the planner emits the same W for `alert(...)`,
`fetch('/.watch-oracle/'+...)`, and script-block forms. `Math.imul` + `>>>0`
guarantee 32-bit semantics on every engine.)

### 3.3 Verifier predicate (E1)

```
E1 ≡ ∃ dialog-event d in attempt evidence:
      d.kind ∈ {alert, confirm, prompt}
  AND d.message == D                      (exact, full-string)
  AND D ≠ S  AND D ∉ payload  AND D ∉ bound_input
  AND D not present in request URL, response body snippet,
      dom_changes, console_messages, storage_writes, or
      any reflected/referrer-derivable string
  AND attempt bound to evidence (existing binding rules)
  AND dialog was auto-handled by the executor (no page-controlled accept path)
```

### 3.4 Anti-harvest checks (verifier-side, all mandatory)

1. `onwire(D) == false`: D appears nowhere in any channel except the oracle
   event itself (substring scan across every recorded string).
2. `copycheck`: D must not be constructible by concatenating substrings of
   the bound input, referrer, or reflected body — enforced by rule 1 (D is
   not a substring of any of them).
3. Seed hygiene: S appears in the payload exactly once; S ≠ D; S not a
   substring of D.
4. Length/shape: D is exactly 16 lowercase hex chars.
5. Dialog message must be *exactly* D — prefix/suffix/padded variants fail.

---

## 4. E2 Network Oracle (stronger than fetch("/{M}"))

The raw `fetch("/{M}")` proposal is insufficient: a benign analytics/router
page can assemble a pathname from `location` data containing M. With the
derived value, the request path carries **D, which is nowhere on the wire**,
so no copy-based pathname assembly can produce it.

### 4.1 Request shape (v1)

- Payload executes `fetch('/.watch-oracle/' + D)` (or `new
  Image().src='/​.watch-oracle/'+D` as fallback where CSP blocks fetch but not
  image loads; planner may emit both).
- Same-origin (relative URL from the target origin) — passes the existing
  network policy; a 404 response is fine, observation of the *request attempt*
  is the signal.

### 4.2 Why not the alternatives

- **Exact pathname with raw marker**: harvestable (Section 2-A). Rejected.
- **Path assembled from fragments**: concat is copy-class once the fragments
  are readable; adds nothing over H. Rejected.
- **Query-independent value**: subsumed — D never appears in any query.
- **Special request method** (e.g. `WATCH`): fetch would fail preflight;
  non-standard methods are observable but method-spoofing by beacon libraries
  (custom method configs) is a real pattern; adds FN risk, no strength gain
  over path-D. Rejected for v1.
- **Special header**: fetch with a custom header triggers CORS preflight even
  same-origin? No — same-origin requests skip CORS, but header adds complexity
  and is not needed; the path is already unharvestable. Rejected for v1.
- **Body value**: POST body with D is observable via listeners only as URL+
  post-data; Playwright post-data availability varies; path is simpler and
  equally unharvestable. Rejected for v1.
- **Another observable property** (title change, storage key): title/storage
  are stage-3 writable by benign pages from copied data. Rejected.

### 4.3 Verifier predicate (E2)

```
E2 ≡ ∃ runtime-request r in attempt evidence:
      page_initiated(r)            (NOT navigation: not is_navigation_request,
                                    resource_type != document, frame-managed)
      AND same_origin(r.url, attempt.endpoint)   (existing policy guarantees;
                                    re-checked)
      AND r.url.path starts with '/.watch-oracle/'
      AND r.url.path == '/.watch-oracle/' + D      (exact; single segment;
                                    no suffix, no traversal, no encoding:
                                    percent-decode once, then exact match)
      AND D == W(S) for the attempt (verifier recomputes)
      AND onwire(D) == false        (Section 3.4 rule 1)
      AND query component of r.url is IGNORED (never contributes to the match)
```

E2 implies execution **and** attacker-chosen network effect (S5-level impact):
the running code issued a request the attacker specified.

---

## 5. E3 Eval Oracle (minimum robust v1)

Existing hooks: `window.eval` and string-`setTimeout` record the code argument
(truncated to 240 chars by the init-script `_val`).

### 5.1 Predicate

```
E3 ≡ ∃ eval-family sink-event k (op ∈ {eval, setTimeout:string}):
      k.value == P                       (exact, full payload string)
      AND len(P) <= 240                  (else hook truncation makes exact
                                          match impossible — planner enforces:
                                          if the oracle payload exceeds 240
                                          chars, E3 is DISABLED for that
                                          attempt, not weakened)
```

### 5.2 Decisions

- **Exact payload equality, no truncation matching**: partial-prefix matching
  would let an unrelated `eval` of a coincidental prefix count. Disabled for
  long payloads instead.
- **Hash of payload**: rejected — the hook records the string; hashing adds a
  second implementation for no gain.
- **Marker reconstruction inside eval**: unnecessary; `eval(P)` executes P,
  which contains the whole oracle anyway — if E3 fires, E1/E2 usually fire
  too. E3's value is covering payloads whose alert/fetch was sandboxed/blocked
  after invocation began.
- **Indirect eval**: `(0,eval)(x)` and `const e=eval; e(x)` route through the
  hooked `window.eval` property → still observed. Covered.
- **`new Function(P)`**: NOT covered by existing hooks. Out of v1 scope (no
  hook exists); adding a `Function` constructor hook is a noted v1.1 item, not
  required for the oracle to be sound — E1/E2 carry confirmation.
- **`setTimeout` (function callback)**: not a code-execution vector; out of
  scope. String form only, as today.
- **Harvest safety**: P is wire-readable, but *invoking* eval-family with P is
  itself execution of attacker code — a page that does it is vulnerable by
  definition (true positive). No benign page evals its query string.

---

## 6. Adversarial Benign-Page Attacks (12 break attempts)

Baseline: target is a **non-vulnerable** first-party page that received the
attack request (payload + S in query/body/referrer/DOM). For each attack:
what the page can observe, whether it can reproduce the oracle, and whether
the verifier accepts.

1. **`alert(location.search)`** — Observable: full bound input (contains S,
   not D). Reproduce D: no (D = W(S) not computed; message ≠ D exactly).
   Verdict: **rejected** (E1 requires exact D).
2. **`alert(extractedMarker)`** — page parses query for a hex-looking token
   and alerts it: it can only extract **S** (32 hex), never D (16 hex, never
   on wire). Verdict: **rejected** (wrong value; shape check 4 also fails:
   32 ≠ 16 hex chars).
3. **`fetch('/' + extractedMarker)`** — path contains S-shaped string, not D.
   Verdict: **rejected** (path ≠ '/.watch-oracle/' + D).
4. **`fetch('/log/' + location.href)`** / `fetch('/log/'+encodeURIComponent(...))`
   — classic telemetry beacon. Path contains the full URL (S inside query
   part, not path-relevant). E2 needs path == '/.watch-oracle/' + D exactly;
   '/log/…' fails prefix and value. Query contains S but query is ignored.
   Verdict: **rejected**.
5. **`navigator.sendBeacon('/beacon', location.href)`** — body/URL echo only;
   no D anywhere. Verdict: **rejected**.
6. **`document.referrer` extraction** — referrer may carry S across pages
   (e.g. app navigates to an error page carrying the original URL). The error
   page can read S. Reproduce D: still requires computing W. Verdict:
   **rejected** (S leakage is harmless by design).
7. **DOM extraction** — page copies its own rendered payload text (containing
   S and the W source) into an alert/beacon. Copy yields S, never D. Verdict:
   **rejected**. (If the page *re-evaluates* the copied script, it executed
   attacker code — true positive.)
8. **Server-reflected marker extraction** — server echoes the payload;
   reflected S everywhere (even in the HTTP response body). Still no D.
   Verdict: **rejected**.
9. **Analytics router** — `fetch('/collect?p=' + location.pathname +
   location.search)` or path-style routing (`history.pushState('/q/'+hash)`).
   All copy-class; S may appear in paths, D never does. Verdict: **rejected**.
10. **Client-side telemetry with encoding** — `fetch('/t/' +
    btoa(location.search))` — path contains base64 of S-containing text;
    decoded ≠ D, prefix ≠ '/.watch-oracle/'. Verdict: **rejected**.
11. **Service-worker-like behavior** — SW caches/mirrors request URLs (S
    visible). SW-mediated fetches still carry copy-derived URLs. D cannot be
    produced without running W. Note: SW traffic is observed by the same
    network listeners; only D-paths count. Verdict: **rejected**.
12. **Application-generated nonce handling** — app generates and reflects its
    own nonces (CSRF tokens, request ids). These are unrelated to S and cannot
    equal D (D is run-salted and unknown to the app; the app never sees D
    because D is computed only inside executing payload code). Verdict:
    **rejected**.

Additional attempted break — **adversarial Watch-aware page** (bonus): a page
that extracts S and implements W itself, then alerts D, without the payload
executing. This **succeeds against E1/E2 locally** (Section 7, Assumption A4).
It is not a benign page (it deliberately implements the verifier's oracle
algorithm); no purely local protocol can distinguish it from execution.
Accepted residual risk; mitigations: rotate W per deployment, treat such
behavior as out-of-model, and keep OOB canary as a documented optional tier.

**BLOCKING check: none of the 12 benign attacks reproduces any oracle. No
t.oracle is trivially spoofable by a benign page.**

---

## 7. Formal Security Property

Let O be an execution oracle emitting observable o (dialog message, request
path) with expected value D = W(S), where S is wire-visible and W is public,
deterministic, and computable only by code execution.

**Property (anti-harvest execution oracle):**

- `Pr[Observable(O) reproduces D | attacker JavaScript NOT executed] ≈ 0`,
  where the adversary is restricted to **copy/derivation-free operations**
  (substring extraction, concatenation, encoding, templating) over
  attacker-controllable data (URL, body, referrer, DOM, reflection, storage,
  console).
- `Pr[Observable(O) reproduces D | attacker JavaScript executed] ≈ 1`
  (payload deterministically computes and emits D; single observation channel;
  no timing dependence).

**Why it holds:** D is not a substring of any attacker-controllable string
(planner enforces onwire(D)=false); every copy-class operation over those
strings yields strings that do not contain D; producing D requires evaluating
W on S, which is payload code execution — i.e. the very event being proven.
The oracle is thus *self-referentially sound*: the only way to fake the proof
is to do the thing being proven.

**Assumptions (explicit, not "cryptographically impossible"):**

- A1: The page cannot obtain D without evaluating W — holds against copy-class
  adversaries; W is public and NOT a cryptographic PRF (double FNV-1a, ~2^-64
  accidental collision resistance; not preimage-resistant against deliberate
  computation).
- A2: The verifier's W implementation is bit-identical to the payload's
  (Math.imul/`>>>0` semantics; covered by cross-implementation tests).
- A3: Transport integrity: dialog events and network listeners are
  executor-owned (capability-protected transport; page cannot inject events);
  Playwright dialog/request events are not forgeable by page JS.
- A4: **Out-of-model adversary**: a page that deliberately extracts S and
  computes W with its own code is indistinguishable from an executing page by
  any local protocol. Accepted; documented; not a benign-page risk.
- A5: `run_salt` secrecy from the target and freshness per run (anti-replay).
- A6: The executor's observation window is long enough for the payload to run
  (bounded, existing 5 s window).

---

## 8. Integration With XSS Classes

### Reflected XSS
- HTTP attempt: plain reflection payload (P0/P1 evidence) — oracle not needed.
- Paired browser attempt: planner replaces (or augments) the LLM payload with
  the oracle payload for the case's context type; navigation URL = endpoint
  with bound input `payload(with S) ~~ correlation_token`. Page reflects and
  executes → W(S) computed → E1 and/or E2 fire → CONFIRMED per the six-stage
  chain.

### DOM XSS
- No HTTP attempt. Browser attempt navigates with the oracle payload as the
  parameter value. Source hook observes the parameter read (S2), sink hook
  observes the value reaching a sink (S3), executing payload computes D → E1/
  E2 (S4). Harvest-resistance is decisive here: the benign-echo pages that
  defeat token-in-channel logic cannot produce D.

### Mutation XSS
- Same as DOM; the oracle snippet is placed so that only the *mutated* form is
  script-bearing where feasible; if mutation strips it, E1/E2 stay silent →
  INCONCLUSIVE with `marker_sanitized` note (never NOT_VULNERABLE).

### Stored XSS — SUBMIT → server storage → clean READ → execution
1. **SUBMIT** (HTTP attempt): stores payload containing S (and the oracle
   code). Response hash + status recorded. The SUBMIT request/URL/body
   contains S but never D.
2. **Clean READ**: a **fresh browser context** navigates the display endpoint.
   The READ URL carries **no oracle material** — no S, no D, no round token
   beyond the existing correlation token needed for phase pairing, and the
   planner must place even that correlation token such that the display page
   does not receive it as parameter-derived input (use a distinct query name
   or cookie-scoped round reference; the stored content is identified by
   round_id server-side, not by URL secrets).
3. **Execution**: stored payload renders, executes, computes D from S → E1/
   E2 fire in a context that never received any oracle material from the
   request — the only path by which D can exist in that context is execution
   of the stored content. This makes the stored READ the strongest oracle
   usage: context isolation + value-not-on-request = proof of persistence AND
   execution.
4. **Referer leakage**: any navigation *from* a page whose URL contains S
   (reflected cases) leaks S to third parties via Referer — harmless (D never
   derivable). For the stored READ, the Referer of the READ navigation is the
   executor's blank/about page (no leakage); ensure the executor does not
   navigate READ from a URL containing S. Sub-resource requests from the
   executing payload (E2) carry D in the path to the *same origin only* —
   same-origin policy prevents D from reaching third parties; even if it
   leaked, D is single-use and run-salted.

---

## 9. Trust Model

- **LLM = untrusted.** Suggestions only. The LLM MUST NEVER decide or even
  see: the execution marker (S/D), the oracle value, the oracle payload
  structure beyond its delivery-skeleton role, execution success, or
  CONFIRMED.
- **Planner = trusted.** Deterministic derivation of S, D, W, oracle payloads,
  round ids from run_salt + attempt identity. No LLM involvement.
- **Executor = evidence provider.** Collects dialog/network/sink/source
  events; transport hardened (capability-protected buffer, same-origin
  policy); never classifies.
- **Page = hostile.** May read every attacker-controllable string and run
  arbitrary *own* code; cannot produce D without running payload-derived code.
- **Server = untrusted.** May reflect anything; reflection never confirms.
- **Verifier = sole classification authority.** Recomputes D, enforces exact
  predicates and anti-harvest checks, owns the state machine.

---

## 10. Final Recommended Design (single, concrete)

- **Marker generation:** `S = sha256(run_salt ‖ attempt_id ‖ phase)[:16]` as
  32 hex chars, planner-generated; `D = W(S)` with double-round FNV-1a 32-bit
  (`h1 = fnv1a32(S)`, `h2 = fnv1a32(hex(h1) + ':' + S)`, `D = hex(h1)+hex(h2)`,
  16 hex chars). W mirrored exactly in Python (Math.imul / >>>0 semantics).
- **Marker representation on wire:** S only, inside the payload body; **D is
  never on the wire anywhere** (never in URL, body, response, DOM until
  computed, storage, or referrer).
- **Oracle payload generation:** planner composes, per context type (html_body,
  html_attribute, script_block, url), a payload = delivery skeleton + inline
  snippet `var s='<S>'; …W…; alert(D); fetch('/.watch-oracle/'+D)` (E1+E2 both
  emitted; either suffices). Bounded length; if > 240 chars, E3 disabled for
  the attempt.
- **E1 predicate:** dialog event, kind ∈ {alert, confirm, prompt}, message
  **== D** (exact), plus anti-harvest checks AH1–AH5 (Section 3.4).
- **E2 predicate:** page-initiated, non-navigation, same-origin request,
  path **== '/.watch-oracle/' + D** (exact, single segment, percent-decoded
  once), query ignored, D == W(S) recomputed by verifier, plus onwire(D)=false.
- **E3 predicate:** eval/string-setTimeout hook value **== P** (exact), only
  when len(P) ≤ 240; disabled otherwise (never weakened).
- **Anti-harvest checks:** AH1 onwire(D)=false across all recorded strings;
  AH2 D∉payload/bound_input and D≠S; AH3 S exactly once in payload; AH4 shape
  (16 lowercase hex); AH5 for stored READ: no oracle material in the READ URL
  (S, D, round secrets) — enforced by planner + verifier re-check.
- **Verifier checks:** recompute D; exact-match predicates; binding rules
  (attempt_id/method/actual URL/hashes); run-salt freshness (anti-replay);
  state-machine mapping (S4 via E1∨E2∨E3; S5 via E2; CONFIRMED per class
  predicates of the confirmation model).
- **Limitations (documented, accepted):** W is not a cryptographic PRF — the
  guarantee is non-reproduction by copy-class operations, not cryptographic
  unforgeability; a Watch-aware adversarial page can synthesize D (A4) and is
  indistinguishable from execution locally; E3 blind to `new Function` (v1.1
  hook); payloads >240 chars lose E3 (E1/E2 unaffected); CSP-blocked execution
  yields no oracle → INCONCLUSIVE (correct, conservative); observation window
  may miss very delayed execution (existing bound).

---

# Final Verdict

READY FOR ORACLE IMPLEMENTATION
