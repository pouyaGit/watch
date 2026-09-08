# XSS Confirmation Model — Implementation-Readiness Review

Read-only review. No source, tests, schemas, or production behavior were
modified. The previous confirmation design
(`xss-confirmation-design.md`) is treated as the current **proposal**,
not as implemented truth. `/opt/watch/agent-report.md` was requested
and is **absent** from the repository; this review is grounded in the
proposal plus the current Watch XSS architecture:

- `ai/schemas/xss.py`, `ai/schemas/xss_verification.py`, `ai/schemas/xss_finding.py`
- `ai/verification/` (verifier, HTTP executor, browser executor, composite, pipeline, case builder)
- `ai/researcher/xss_*.py`, `ai/verification/xss_pipeline.py`
- `ai/test_xss_verification.py`

**Question answered:** can the proposed confirmation model be implemented
on the current HTTP + Playwright architecture without new false
positives, false negatives that are architectural defects, broken
evidence binding, or contradictions?

**Short answer:** no. The six-stage chain and the demotion of
token-in-channel signals to data-stage evidence are the right
direction. Several load-bearing claims in the proposal are false
against the current executors, and three confirmation oracles are
spoofable whenever the execution marker is visible on the wire. Coding
the proposal as written would replace today’s DOM false-positive
CONFIRMED path with a different, still-confirmatory false-positive
path.

---

## 0. Architecture snapshot (what exists today)

These facts constrain every later section.

### 0.1 Identifiers and pairing

- `attempt_id` includes `mode` and `phase`; `logical_pair_id` excludes
  both but includes `method`. HTTP + browser attempts for the same
  payload can pair. GET vs POST never pair.
- `correlation_token` is `ct-` + SHA-256 of `attempt_id|phase`, 32 hex
  chars. It is **not** a secrecy boundary; it is an identity string
  the verifier re-checks.
- Binding today: `evidence.attempt_id == attempt.attempt_id`,
  `evidence.request_url == attempt.endpoint` (exact),
  `evidence.request_method == attempt.method`. Phase is metadata.
- `HTTPEvidenceExecutor` and `BrowserEvidenceExecutor` both set
  `request_url` to `attempt.endpoint`, **not** the URL actually
  issued. The HTTP executor computes a bound URL (or form body) and
  then discards the final post-redirect URL (`_final_url` is unused).

### 0.2 HTTP executor

- Injects `payload + "~~" + correlation_token` into query or
  `application/x-www-form-urlencoded` body.
- Supports GET/HEAD query and non-GET body/form. No JSON body, no
  headers, no cookies as injection surfaces, no multi-field forms.
- Follows redirects with host/eTLD+1, port, and HTTPS-downgrade
  policy. Reflection is classified on the **final** body only.
- Token search is `body.find(token)` — **first occurrence only**.
- Location classifier is a bounded byte heuristic
  (`html_body`, `html_attribute`, `javascript_string`, `script_block`,
  `url`). Header/`Location` reflections are invisible.
- No request-body hash, no response-body hash, no
  `actual_request_url`.
- WAF BLOCK/TRANSFORM is structured; CSP is INFO only.

### 0.3 Browser executor

- **GET + `parameter_location == "query"` only.** POST/body attempts
  return ERROR. Stored SUBMIT cannot be a browser POST.
- Always `new_context()` (fresh, empty cookies/storage).
- Bound input is always placed in the **navigation query string**.
- Same-origin (scheme+host+port of `attempt.endpoint`) allowlist;
  all other traffic aborted. Cross-origin canaries are unobservable
  by construction — the proposal is correct to reject them.
- Instrumentation: `URLSearchParams.get/getAll`, `innerHTML`,
  `insertAdjacentHTML`, `document.write`, `window.eval`, string
  `setTimeout`, `MutationObserver` wrapper, `Storage.setItem`.
- **Not** hooked: `location.search/hash` reads, `document.referrer`,
  `postMessage`, `new Function`, `setInterval(string)`,
  `element.onclick` / `setAttribute`, `javascript:` navigation,
  `document.write` after load in some browsers, Workers.
- Dialogs are captured by Playwright `page.on("dialog")` and dumped
  into `console_messages` as `dialog:{kind}:{msg}` — not a first-class
  channel. Exact message equality is not applied.
- Runtime token match is **substring** across
  `dom_changes`, `console_messages`, `network_requests`,
  `storage_writes`.
- Initial navigation and document navigations are excluded from
  `network_requests`. Page-initiated same-origin requests are
  recorded as full URLs (credentials in query redacted).
- Sink values truncated to 240 characters. Chain builder uses
  substring overlap (`src.value in ev.value`), not value-identity.
- Stored phase: if `phase=="stored"` and the token appears in a
  runtime channel, emit a **READ** observation only. No SUBMIT pass.

### 0.4 Verifier (current CONFIRMED — to be replaced)

- Reflected CONFIRMED: HTTP `_http_path_confirms` (meaningful
  location + exact observed token) **and** browser chain bound to
  attempt **and** token substring in a runtime channel.
- DOM/mutation CONFIRMED: browser-only chain + token in channel.
  **No HTTP pair.** This is the false-positive the proposal
  correctly attacks.
- Stored CONFIRMED: paired HTTP `_http_path_confirms` **plus**
  SUBMIT and READ `stored_phases` on the **same** `attempt_id`
  **plus** runtime token substring. The HTTP executor never emits
  `stored_phases`; the browser executor never emits SUBMIT. The
  stored CONFIRMED path is not producible by production executors.
- `NOT_VULNERABLE` is never produced.
- LLM suggestions never classify.

### 0.5 Production case flow

- `XSSCaseBuilder` always leaves `xss_type="unknown"`.
- Orchestrator / LLM cannot advance a case to CONFIRMED and does
  not set `xss_type`.
- Plan builder treats `unknown` as reflected (HTTP + browser pair).
  DOM/mutation/stored class predicates are unreachable for inventory
  cases unless something else labels `xss_type`.

### 0.6 Proposal vs code (orientation)

The proposal introduces `execution_marker M`, oracles E1–E3, stages
S1–S6, `run_salt`, `round_id`, `actual_request_url`, body/response
hashes, `dialog_events`, `oracle_network_events`, `eval_invocations`,
`mutation_snapshot`, and a two-attempt stored round. **None of these
exist in schemas or executors today.** That absence is expected.
Readiness is about whether those additions can be bound to the
existing HTTP + Playwright evidence plane without lying.

---

## 1. Reflected XSS

Proposed rule:

`CONFIRMED ⇔ S1(meaningful, all occurrences) ∧ S4 ∧ PAIRED ∧ BINDING ∧ FRESH`

### 1.1 Can the chain be implemented on HTTP + Playwright?

**Partially.** The HTTP half of S1 is implementable. The S4 half is
implementable as *observations* (Playwright already sees dialogs,
page-initiated requests, and hooked `eval`). The **composition** as
specified is not safe, and several bindings contradict the current
executor contract.

### 1.2 Request/response binding

| Need | Today | Proposal | Verdict |
|---|---|---|---|
| Attempt identity | `attempt_id` match | keep | OK |
| Method | exact | keep | OK |
| Endpoint vs URL | `request_url == endpoint` | `actual_request_url` equals verifier reconstruction of the **post-binding, post-redirect** URL | **Contradiction** |

If `request_url` is redefined to the issued URL, current binding
breaks (issued query URL ≠ endpoint). If a new `actual_request_url`
is added and the verifier requires it to equal a reconstruction
**after redirects**, same-origin redirects (already allowed by the
HTTP executor) fail binding and become INCONCLUSIVE. Common pattern:
`/search?q=` → `/search/`.

**Required evidence the verifier does not yet have, and the proposal
over-constrains:**

- `intended_request_url` — verifier-reconstructed URL or body after
  payload+token injection, **before** redirects.
- `final_request_url` — what the executor actually landed on.
- Redirect hop list (bounded), already partially collected in the
  browser executor (`nav_redirects`) and unused on HTTP.
- `request_body_sha256`, `response_body_sha256` (or truncated-body
  hash plus `truncated` flag). Today `response_body_truncated` is
  stored raw (up to 512 KiB) with no hash and is not a binding input.

Reflection claims must not be trusted without a hash of the body
that was classified. That addition is implementable.

### 1.3 Payload binding and correlation token

Concatenating `payload~~token` as a single input value is sound for
S1: token presence in the response means **that input** reached the
surface. The verifier’s exact-token check (no normalization) must
stay. Do not let S1 succeed on payload-without-token (the HTTP
executor already records that as WAF INFO only).

The proposal’s S1 predicate uses
`body[i:i+len(bound)] == bound` (full `payload~~token`). Current
code matches **token only**, then separately requires payload bytes
in one of a small set of transit encodings else TRANSFORM. Those
are not the same:

- Token-only match can S1-succeed when the payload is filtered but
  the token is echoed (HTTP executor currently marks TRANSFORM and
  the verifier already forces INCONCLUSIVE). Keep that.
- Full-bound match will **false-negative** HTML-escaped payloads
  (`&lt;script&gt;...ct-...`) where the token is literal but the
  payload is escaped. Escaped reflection is not executable; failing
  S1 is acceptable. Document it.

### 1.4 Execution marker

The proposal embeds M **inside the payload body**, which the
executors place in the query string or form body. Therefore M is a
contiguous substring of the attacker-controlled request. See
§2 and §6: E1 and E2 are then harvestable by page JS that never
parses attacker script. **Reflected CONFIRMED cannot rest on E1/E2
while M is URL/body-visible.**

### 1.5 Reflection locations, redirects, multiple occurrences

- **First-occurrence-only** is a real reflected false negative:
  first hit in inert `html_body`, later hit in `script_block`. The
  proposal’s all-occurrence scan is necessary and implementable
  (scan every `token` index; S1-meaningful if **any** occurrence is
  in the meaningful set). Until that exists, S1-meaningful is
  weaker than the proposal assumes.
- **Redirects:** final-body classification is correct for HTML
  reflection. Token only in `Location` or `Set-Cookie` is invisible
  — acceptable limitation if documented. Binding must not require
  final URL == reconstructed initial URL (§1.2).
- **`html_body` remains non-meaningful (R8.8):** a payload whose
  marker sits inside a newly inserted `<script>` or event-handler
  is usually classified as `script_block` / `html_attribute` by the
  current heuristic, so classic breakout is not automatically
  excluded. Residual FN: marker only in a text node that later
  mutates into executable markup (that is the mutation class, not
  reflected S1).

### 1.6 Browser attempt pairing

`logical_pair_id` already pairs HTTP and browser attempts that share
case, endpoint, method, parameter, location, payload, attribution.
That part of PAIRED is implementable **without** new identity
schemes.

Gaps:

- Browser executor cannot run POST/body. A reflected POST case gets
  HTTP S1 and browser ERROR → never S4. **Architectural FN** for
  body parameters unless READ-style GET display exists (usually it
  does not for reflected POST).
- HTTP and browser correlation tokens **differ** (phase is in
  `attempt_id`). Pairing by `logical_pair_id` is mandatory; pairing
  by token would be wrong. The proposal is consistent with this.
- `run_salt` mixed into `attempt_id` would change today’s
  deterministic IDs. Anti-replay can salt **tokens/markers only**
  and leave `attempt_id` stable. Mixing salt into `attempt_id` is
  optional, not required for soundness.

### 1.7 Same-origin policy

E2 same-origin `fetch('/'+M)` is allowed by the current route
policy. Cross-origin script gadgets / canaries remain blocked —
acceptable. Reflected confirmation must not depend on third-party
origins.

### 1.8 Missing evidence the reflected verifier needs

Minimum new fields (design-level):

1. `execution_marker` **not contiguous in the request URL/body**, or
   an equivalent anti-harvest rule (see §9).
2. First-class `dialog_events` with exact message.
3. Page-initiated request records with **parsed pathname** (not a
   raw URL string) for E2.
4. `eval_invocations` with value + truncation flag.
5. All reflection occurrences (location + context snippets).
6. `intended_request_url`, `final_request_url`, body/response hashes.
7. Browser evidence must not reuse HTTP `request_url==endpoint` as
   proof the bound query was sent; record the actual navigation URL
   separately.

Without (1), reflected S4 is not a code claim. Without (5)–(6), S1
and BINDING are under-specified against the current executors.

**Reflected verdict:** the *shape* (S1 meaningful + independent S4 +
pair) is implementable. The proposed S4 oracles, URL binding, and
first-occurrence S1 are **not** implementation-ready as written.

---

## 2. DOM XSS — oracles E1, E2, E3

Proposed: `CONFIRMED ⇔ S2 ∧ S3 ∧ S4 ∧ BINDING ∧ FRESH` (no HTTP pair).
S2∧S3 without S4 → POTENTIAL. That demotion is correct and necessary.
The question is whether S4 as specified is actually a code claim.

### 2.1 E1 — exact dialog marker

| Question | Answer |
|---|---|
| Can a benign page trigger it without attacker JS executing? | **Yes, if M is in the URL/query.** Page JS can `alert(extract(/xm-[0-9a-f]{32}/))` or `alert` a parsed query field that equals M. URL echo of the **full** query does **not** equal M (good), but **extraction** does. The proposal’s claim “a benign page cannot know M; URL echo does not call alert” is false for DOM/reflected, because M is in `location.search`. |
| Can the page-controlled environment spoof it? | Native `alert`/`confirm`/`prompt` are Playwright-observed, not page-buffered. The page cannot rewrite Python-side evidence. It **can** call `alert(M)` from first-party code. Capability-protected instrumentation is irrelevant to E1; E1 does not go through `__watchTransport`. |
| Can the browser executor observe it reliably? | **Yes.** `page.on("dialog")` already fires. Split out of `console_messages`. Exact equality is implementable. Multiple dialogs: accept and record all, bounded. `beforeunload` is a different dialog type and must not count. |
| Does Playwright expose enough? | Dialog type + message, yes. Not the call stack, not whether the callee was attacker script vs app script. |
| Survive redirects/navigation? | Dialogs after same-origin redirect are observed on the same page if they occur in the observation window. Cross-origin navigation is aborted. Dialog during `goto` before listeners: listeners are installed before `goto` today — OK. |
| Is exact equality sufficient? | Necessary, not sufficient, while M is request-visible. Substring equality would be worse (`dialog:alert:https://host/?q=...M...`). |
| Can the app legitimately generate the same marker? | Yes, by copying it from the URL, from `document.referrer`, or from a reflected HTML text node (innerText scrape). Collision of a 128-bit salted marker by chance is negligible; **harvest** is the issue, not birthday collision. |
| Minimum evidence | `{type, message, timestamp}` with `message == M` exactly; plus proof M was not a contiguous substring of the navigation URL/body/referrer **or** M is computed only by executing payload operators (fromCharCode / split concat). |

**E1 is a good oracle only after the harvest channel is closed.**

### 2.2 E2 — same-origin network request with marker in PATH

| Question | Answer |
|---|---|
| Benign trigger without attacker JS? | **Yes.** The proposal claims URL echo “never” constructs a new path. That is false. Common app code: `sendBeacon('/e/'+encodeURIComponent(location.href))`, `fetch('/log/'+location.search)`, `history`/`router` putting the query into a path. Then `marker_in_path(url, M)` holds because M is a **substring of the path**. |
| Spoofable? | Yes, by path-copy of href/search, and by harvesting M into `fetch('/'+M)`. First-party analytics is enough; no hostile overwrite of the evidence buffer is required. Navigation requests are already excluded — good, but analytics `fetch`/`img`/`sendBeacon` are page-initiated and **would** count. |
| Observable reliably? | Yes, for requests the route policy allows (same origin). Playwright `requestfinished`/`response` already populate `network_requests`. Path parsing is missing; today the verifier only has a URL string substring check (exactly the echo problem). |
| Playwright enough? | URL, method, resource_type, `is_navigation_request()`, frame identity — enough to implement a tight E2. No trustworthy “this fetch was caused by attacker script” bit. |
| Redirects? | A same-origin redirect from `/xm-M` to `/app` still produced a page-initiated request whose **initial** URL path was `/xm-M` if the payload issued that fetch. Record the request URL before redirect. If E2 inspects only the final URL, redirects FN. If it inspects any hop substring, analytics FPs. |
| Exact equality sufficient? | **Substring-in-path is not sufficient.** Minimum: pathname is exactly `/{M}` or `/{M}/`, query empty, not a navigation, same origin, not a substring of the original navigation URL. Residual harvest FP remains if M is in the query and the app does `fetch('/'+extractedM)`. |
| App-generated collision? | Analytics and client routers do this routinely with **substring** E2. Exact-path E2 is rare unless the app harvests `xm-` tokens (e.g. “validate nonce”). |

**E2 as specified (`marker_in_path`) is not implementation-safe.**

### 2.3 E3 — eval-family invocation, exact full payload

| Question | Answer |
|---|---|
| Benign trigger without attacker JS? | If the page `eval`s the **exact** attacker payload string, that **is** DOM XSS (eval sink). Confirming it is correct, not a false positive. Benign `eval('('+json+')')` equals payload P only if P is exactly that JSON — not for oracle/script payloads. |
| Spoofable? | Forging an eval **event** without calling hooked `eval` requires bypassing the capability-bound transport. The current transport is reasonably hardened. Indirect `eval`, `(0,eval)(P)`, and `new Function(P)` are **not** hooked — those are false negatives, not spoofs. |
| Observable reliably? | Only for hooked `window.eval` and string `setTimeout`. Value truncated to 240 chars. |
| Playwright enough? | The hook is page JS, not a Playwright CDP debugger. It can miss engine-internal compilation. Adequate for eval-family **if** completeness is not claimed. |
| Redirects? | N/A; tied to the page that ran eval. |
| Exact equality with full payload? | **Incompatible with the 240-character sink truncation.** Long oracle payloads never satisfy `k.value == P`. Exact equality also fails if the page `eval`s a slice (still XSS). |
| App generating P? | Only by eval-ing attacker input — real XSS. |

**E3 is the strongest of the three oracles for the eval family, but
the predicate `k.value == P` is not implementable as written.** Use
`M` (or a hash of P) inside the recorded argument, with an explicit
`truncated` flag that forces INCONCLUSIVE rather than a wrong
exact-match.

### 2.4 Is S2 + S3 + S4 sufficient for DOM CONFIRMED?

**No, not with S4 = E1|E2|E3 as specified.**

- S2 (`URLSearchParams.get` value contains T or M) is true for almost
  every query-parameter page. Hook coverage is also incomplete
  (`location.hash` DOM XSS would miss S2 — FN, §7).
- S3 (marker in `innerHTML` / `document.write` / eval argument) is
  true for benign rendering (`results.innerHTML = '<b>'+q+'</b>'` with
  escaped q still containing M if M is alphanumeric `xm-…`).
  Alphanumeric markers survive many HTML encodings. S3 is data-stage,
  as the proposal says.
- S4 is supposed to be the discriminator. If E1/E2 fire from URL
  harvest or path-copy, **S2∧S3∧S4 is the same false-positive class
  the proposal exists to kill**, with a fancier oracle name.
- S5 is **not** in the DOM CONFIRMED predicate. That is acceptable
  **if** S4 is a real code claim. It is not acceptable while E1
  counts as S4 and E1 is harvestable.

**Sufficient DOM CONFIRMED (design-level):** S2 bound to the attempt
parameter **and** S3 value-identity on a dangerous sink **and** S4
from an oracle that **cannot be produced by copying request
URL/body/referrer substrings**, plus FRESH/BINDING. S2∧S3∧S4 with
wire-visible M is **not** sufficient.

Current chain+token CONFIRMED must still be demoted to POTENTIAL.
That part of the proposal should survive.

---

## 3. Mutation XSS

### 3.1 Distinctions the proposal blurs

| Concept | What it is | What Watch can see today |
|---|---|---|
| DOM XSS | Source read → dangerous sink → optional execution | Source/sink hooks + mutations of **any** innerHTML write |
| Mutation XSS / mXSS | Browser (re)parse produces **different**, executable markup than the string the app/sanitizer accepted | Not distinguished. MutationObserver fires for ordinary inserts |
| Ordinary DOM mutation | App updates the tree (React render, search results) | `observables` channel; already used in chains |
| HTML parsing without execution | `innerHTML = escapedString`; parser runs; **no** script/event execution | Sink + mutation events **without** E1–E3 |

`mutation_snapshot` (pre/post serialization at the injection point)
can show `sent ≠ serialized`. That is **attribution**: “the parser
changed the string.” It does not prove JavaScript ran. A sanitizer
that rewrites `<div>` to `<DIV>` produces a snapshot diff with no XSS.

### 3.2 Is mutation evidence necessary for CONFIRMED?

**No. It is attribution, not confirmation.**

The proposal contradicts itself:

- §5.3: CONFIRMED requires DOM rules **plus** `mutation_snapshot`.
- Same paragraph: if S4 fires, CONFIRMED stands with **partial**
  mutation evidence; mutation is attribution.
- R6: “DOM rules plus `mutation_snapshot`” then “S4 → CONFIRMED with
  mutation evidence as attribution.”

Implementation cannot encode both “required conjunct” and “optional
attribution.”

**Normative resolution (minimum design change):** Mutation CONFIRMED
uses the **same S4 bar as DOM**. `mutation_snapshot` is optional
evidence that may label `xss_type="mutation"` vs `"dom"`. Missing
snapshot → still CONFIRMED if S4 holds, typed as `dom` or `unknown`.
Sanitized marker (`M` absent after parse) → INCONCLUSIVE, never
NOT_VULNERABLE — keep that.

### 3.3 Implementability of `mutation_snapshot`

Playwright `page.content()` is the **post-parse** document, not a
per-injection-point diff, and not the HTML parser’s intermediate
tree vs sanitizer output. Building a defensible snapshot requires
knowing the injection node. The executor does not have a stable
injection locator today (only bounded sink values). This is a
research-grade instrumentation problem, not a weekend schema field.

**Do not block CONFIRMED on `mutation_snapshot`.** Do not implement
a global `page.content()` hash and call it mXSS evidence.

---

## 4. Stored XSS

Proposed: two linked attempts, `CONFIRMED ⇔ SUBMIT_ACCEPTED ∧
ROUND_BOUND ∧ S4(READ) ∧ FRESH`. READ URL must **not** contain M.

### 4.1 Implementable on current Watch?

**Not as a drop-in.** Several proposal rules invert existing
executor/verifier contracts. A stored round **can** be built from
the existing two executors **if** those contracts are changed in
the ways listed in §9. The current `phase="stored"` single
navigation is correctly described as insufficient.

### 4.2 Mapping of proposed fields onto current ones

| Proposed | Current | Fit |
|---|---|---|
| Distinct SUBMIT vs READ attempts | One HTTP attempt (`phase=http`) + one browser attempt (`phase=stored`) | Partial. Not a round protocol. |
| Shared `logical_pair_id` | Exists | OK if SUBMIT/READ exclude phase from pair id (already excluded). |
| Distinct `attempt_id` | Distinct by mode+phase | OK |
| Same `attempt_id` on SUBMIT and READ phase observations | Verifier **requires** both phases’ `attempt_id ==` the stored **browser** attempt | **Contradiction** with distinct attempt ids |
| `execution_marker` / `round_id` / `run_salt` | Absent | New |
| Fresh browser context | Always `new_context()` | OK for isolation; **fatal** for cookie sessions |
| `request_url` identity | Forced equal to `endpoint` | Hides actual SUBMIT URL and forbids recording a different READ URL |
| Browser READ without query injection | Browser **always** injects bound input into the query | **Direct contradiction** of “READ URL must not contain M” |
| Two real interactions; one pass must not emit both phases | Browser may emit READ only; HTTP emits neither phase | Must not “fix” this by having one execute() synthesize both |
| Single-use round registry in DB | No such registry; AGENTS.md restricts `database/` | **Do not require Mongo.** In-memory per `verify()` is enough for single-process runs |

### 4.3 Time ordering, cookies, bodies, hashes

- `read.started_at > submit.finished_at` is implementable. Future
  timestamps rejected: implementable; clock skew → INCONCLUSIVE
  (acceptable).
- Session/cookie identity: HTTP `requests.Session` may carry cookies
  from SUBMIT; browser context will **not** see them unless the
  design adds an explicit, redacted session-import step. The
  proposal never specifies this. Unauthenticated stored XSS can
  proceed; authenticated stored XSS cannot be confirmed.
- CSRF tokens and multi-field forms: HTTP executor sends **one**
  parameter. Production stored endpoints (comment body + CSRF +
  parent_id) cannot be submitted. Verifier cannot prove SUBMIT
  targeted the intended storage API — only that **some** 2xx
  happened for a one-field POST.
- Async storage (queues, moderation, search index): no wait/retry
  protocol. READ immediately after SUBMIT → systematic FN.
  Acceptable limitation if documented; a hidden assumption if not.
- Actual request URL, request body, response hashes: missing; needed
  for ROUND_BOUND items 6–7. Implementable on the HTTP executor.
  Browser READ should record navigation URL + main document
  response hash **without** putting M in that URL.

### 4.4 Proving the READ payload came from server-side storage

**What the verifier can prove if the protocol is tightened:**

- A SUBMIT interaction with `intended_request_url` / body hash /
  2xx occurred **before** READ.
- A later READ navigation to a URL that does **not** contain M, T,
  or the payload, in a **fresh** context with **no Referer**
  carrying SUBMIT secrets, observed S4 for this round’s M.
- Therefore M appeared in the **document or its runtime** without
  being supplied in the READ request URL. Combined with S4, that is
  strong evidence the **loaded document** caused execution of
  round-secret code.

**What it cannot prove:**

- The bytes were written to durable server-side storage vs cache,
  CDN edge, another microservice, or a SUBMIT response body that
  the client SPA kept in memory (fresh context kills in-memory SPA
  state — good — but a service worker registered on a previous
  same-origin visit in a reused profile would not apply here
  because context is fresh).
- That the stored row is keyed to the intended field (multi-field).
- That the executing user is the victim user (auth).
- That SUBMIT succeeded semantically (2xx with `{"ok":false}`).
- That M did not arrive via `document.referrer` or reflected
  headers if READ is allowed to send Referer.
- HTTP S1 on SUBMIT or READ. The proposal is right to exclude S1
  from stored CONFIRMED (reflection of a stored value in HTML is
  not execution). Current verifier **requires** HTTP
  `_http_path_confirms` for stored CONFIRMED — that is an
  **architectural contradiction** with the proposal and would
  confirm stored XSS that is only reflected on a paired GET of the
  **same** endpoint with the payload in the query (i.e. not stored).

### 4.5 Authentication, CSRF, multi-field, async

Treat as **explicit non-goals** for v1 stored CONFIRMED, or the
class is not implementable on the current executors. The proposal
lists binding hashes but is silent on session import, CSRF, and
read-endpoint identity. `XSSCase` has a single `endpoint`. Stored
rounds need at least:

- `submit_endpoint` / `submit_method` / `submit_location`
- `read_endpoint` (display URL) with **no** automatic query injection

Without a distinct read URL, READ cannot be distinguished from
reflected XSS on the submit endpoint.

**Stored verdict:** the SUBMIT→READ→S4 idea is the right protocol.
It is **not** implementable until READ navigation is specified as
non-injecting, phase observations are rebound to **distinct**
attempt ids, HTTP `_http_path_confirms` is removed from stored
CONFIRMED, referrer is suppressed, and `XSSCase` gains a read
surface. Session/CSRF/async remain documented limitations, not
silent claims of proof.

---

## 5. Evidence trust boundary

| Evidence | Producer | Trust level | What it proves | What it MUST NOT prove |
|---|---|---|---|---|
| LLM suggestion | LLM | Untrusted | A candidate payload/idea | Any stage; any CONFIRMED/POTENTIAL |
| HTTP reflection (`reflection.*`) | HTTP executor | Untrusted observation; verifier re-checks token | S1: bound input echoed in **this** response body at a classified location | Execution; storage; that location is parser-authoritative |
| Response body (truncated) | HTTP executor | Untrusted bytes | Material for independent token search and hashing | Completeness if `truncated`; execution |
| Correlation token T | Planner (deterministic) | Identity, not a secret | Binding of evidence to an attempt when **re-derived/matched exactly** | Execution; that the page could not copy T from the URL |
| Execution marker M | Planner (proposed) | Secret **only if not on the wire** | S4 **only** through E1–E3 under anti-harvest rules | Anything if M is a substring of URL/body/referrer |
| Source event | Browser instrumentation | Untrusted page, authenticated transport | S2: a hooked read of a named parameter returned a value containing the markerset | Sink; execution |
| Sink event | Browser instrumentation | Same | S3: a hooked sink API was invoked with a value containing the markerset | Execution (`innerHTML` of text is not JS) |
| DOM mutation / `dom_changes` | MutationObserver wrapper + sink copies | Same | A tree change occurred; optional overlap with sink value | Execution; mXSS vs ordinary render |
| Console message | Playwright console | Untrusted page | Logging occurred | Execution (apps log `location.href`) |
| Network request URL | Playwright request/response | Untrusted page; executor excludes navigations | A page-initiated request was made | E2 unless pathname exact-match rules pass; never S4 for query-echo URLs |
| Storage write | `Storage.setItem` hook | Untrusted page | App persisted a string | Execution; persistence across contexts |
| Dialog event | Playwright dialog | Untrusted page, trusted observer | Native dialog with a message | S4 unless `message==M` **and** M was not harvestable from the request |
| Eval invocation | `window.eval` / string `setTimeout` hook | Untrusted page, authenticated transport | Eval-family call with recorded argument (possibly truncated) | Completeness of all JS execution; S4 if truncated or not eval-family |
| Actual / intended request URL | Executor | Untrusted report; verifier reconstructs intended | Which URL was meant vs landed | Reflection in a different URL; storage |
| Request hash | Executor | Binding aid | SUBMIT/READ are distinct bodies | Semantic success; CSRF validity |
| Response hash | Executor | Binding aid | Which body was classified | That the body was executed |
| Stored SUBMIT evidence | HTTP executor (proposed) | Untrusted | SUBMIT_ACCEPTED at transport level | That data was stored or will execute |
| Stored READ evidence | Browser executor (proposed) | Untrusted | A later isolated navigation observed something | Storage **unless** READ URL/referrer/body do not carry M and S4 holds |
| `mutation_snapshot` | Browser executor (proposed) | Untrusted, likely incomplete | Parser/serializer differed (attribution) | CONFIRMED; execution |
| `executed_script` / `browser_verified` | Executor/verifier metadata | Advisory | Some sink/observable hook fired | Any stage ≥4 (proposal R8.7 — keep) |
| `source_to_sink` chain | Executor reconstruction | Discovery only | A candidate flow exists | Verdict (proposal is correct) |
| WAF BLOCK/TRANSFORM | HTTP executor | Advisory structured | Payload may not have arrived intact | NOT_VULNERABLE |
| `stored_phases` as used today | Mixed / test-injected | Insufficient | Nothing about a real round | CONFIRMED |

Trust summary the implementation must preserve: **planner is trusted
to mint identifiers; executors are untrusted sensors; the page is
hostile; the verifier is the only classifier.** The proposal’s R2
matches Watch. Several proposed S4 predicates accidentally trust
the page not to copy request substrings.

---

## 6. False-positive attacks (benign pages)

Each scenario assumes the proposal as written (M inside payload;
E2 = marker substring in path; E1 = `dialog.message == M`; DOM
CONFIRMED = S2∧S3∧S4; reflected CONFIRMED = S1-meaningful ∧ S4).
“Must not become CONFIRMED” is the security requirement.

### FP1 — Query reflection into HTML text

- Page: `results.textContent = params.get('q')`.
- Evidence: S2 source get(`q`); possible mutation observable; T and
  M in `dom_changes`; no dialog; network may be empty.
- Stage: S2, maybe S3 if they mis-count `textContent` (currently
  not a sink — stays S2). If `innerHTML` is used instead, S3.
- Must not confirm: no attacker JS.
- Rule: R8.1 / S4 required. **Holds** if S4 is real. Current code
  would CONFIRMED on token-in-dom + chain — proposal correctly
  fixes **this** scenario.

### FP2 — URL logging to console

- Page: `console.log(location.href)`.
- Evidence: T/M substring in `console_messages`.
- Stage: ≤ S1/S2.
- Must not confirm.
- Rule: R8.2 console never exceeds stage 3. **Holds.**

### FP3 — Analytics beacon with query echo

- Page: `navigator.sendBeacon('/collect?u='+location.href)` or
  `fetch('/collect?u='+encodeURIComponent(location.href))`.
- Evidence: T/M in `network_requests` **query**.
- Stage: ≤3 if E2 requires **path**.
- Must not confirm.
- Rule: R8.3 query-position suppressed. **Holds** for this variant.

### FP4 — Analytics beacon / router copying href into the **path**

- Page: `sendBeacon('/e/'+encodeURIComponent(location.href))`.
- Evidence: M appears in the **pathname**.
- Stage: S4-E2 **as specified**.
- Must not confirm: still no attacker JS.
- Rule intended: R8.3. **Does not hold** — R8.3 only mentions
  query-position. **Blocking gap.**

### FP5 — localStorage echo

- Page: `localStorage.setItem('last', params.get('q'))`.
- Evidence: T/M in `storage_writes`; S2.
- Stage: ≤3.
- Must not confirm.
- Rule: R8.2. **Holds.** Proposal S5 allowing “attacker code wrote
  M to storage on a fresh context” must **not** treat this as S5;
  first-party `setItem` of the query is identical. S5 wording is
  unsafe if implemented literally.

### FP6 — DOM text insertion / `innerHTML` without executable content

- Page: `el.innerHTML = '<span>'+escapeHtml(q)+'</span>'` where
  `escapeHtml` leaves `xm-[hex]` intact.
- Evidence: S2, S3 (innerHTML + M), mutation snapshot maybe,
  `executed_script=true` today.
- Stage: SINK_REACHED.
- Must not confirm.
- Rule: S4 required. **Holds** if E1/E2 not spoofed. Current
  verifier would CONFIRMED.

### FP7 — Sanitized HTML (script tags stripped, marker remains)

- Page: DOMPurify then `innerHTML`.
- Evidence: S3 with M; no dialog; maybe mutation_snapshot diff.
- Stage: S3; if snapshot required for mutation class, still no S4.
- Must not confirm.
- Rule: sanitized marker → INCONCLUSIVE; S4 required. **Holds**
  for confirmation. Do not let snapshot diffs promote to CONFIRMED.

### FP8 — CSP blocking script while app still alerts the query

- Page: strict CSP; app `alert('search: '+params.get('q'))` on
  submit. Payload never becomes script.
- Evidence: dialog message is **not** exactly M (prefix/suffix).
- Stage: S2; E1 fails exact equality.
- Must not confirm.
- Rule: E1 exact equality. **Holds** for this variant.

### FP9 — CSP-blocked attacker script + marker harvest dialog

- Page: CSP blocks inline script; app does
  `const m = location.search.match(/xm-[0-9a-f]{32}/); if (m) alert(m[0]);`
  (support/debug overlay).
- Evidence: `dialog.message == M` → S4-E1; S2; maybe S3.
- Stage: proposal DOM CONFIRMED; reflected CONFIRMED if S1-meaningful
  (search `<input value="...M...">` is `html_attribute`).
- Must not confirm: attacker script did not run; CSP forbade it.
- Rule: none in the proposal. **Blocking gap.**

### FP10 — Redirect-based echo

- Server: 302 to `/ok?q=<bound>` same origin; final HTML has token
  in an attribute.
- Evidence: S1-meaningful on **final** body; browser follows
  redirect; URL contains M.
- Must not confirm without S4. With harvest E1/E2, false CONFIRMED.
- Binding risk: if `actual_request_url` must equal pre-redirect
  reconstruction, this becomes ERROR/INCONCLUSIVE instead
  (false negative / broken binding), not a FP.

### FP11 — Application-generated marker collision via harvest

- Page: treats `xm-[32hex]` as a correlation id and
  `fetch('/'+id)` for “telemetry ack”.
- Evidence: exact-path E2 even under a tightened pathname rule.
- Stage: S4-E2.
- Must not confirm.
- Residual risk after tightening. Mitigation: M must **not** appear
  as a contiguous request substring, so harvest has nothing to
  copy. **Blocking** until then.

### FP12 — Stored value reflected but never executed

- SUBMIT stores comment; READ renders `textContent` or escaped
  HTML containing M; no dialog/eval/path fetch from attacker code.
- Evidence: SUBMIT 2xx; READ S2/S3; maybe HTTP S1 on a paired GET.
- Stage: POTENTIAL at most.
- Must not confirm.
- Rule: stored S4 on READ; no S1 contribution. **Holds** if current
  `_http_path_confirms` requirement is **removed**. If kept, a GET
  of the submit endpoint with `q=payload~~token` can supply HTTP
  confirmation **without** storage — **FP / mis-attribution**.

### FP13 — Server-side rendering that contains the marker

- SSR HTML includes M in a JSON island or attribute; hydration
  logs it; no attacker script.
- Evidence: S1; S2 if params read; console/network echo.
- Must not confirm.
- Rule: S4. Same harvest caveats as FP9 if the SSR page’s own JS
  alerts or fetches M.

### FP14 — Referrer leak on stored READ

- SUBMIT URL contains M; READ is a clean display URL but the
  browser sends `Referer: <submit URL>`. Page:
  `alert(document.referrer.match(/xm-[0-9a-f]{32}/)[0])`.
- Evidence: S4-E1 on READ without M in the READ URL.
- Must not confirm (not stored execution of attacker HTML).
- Rule: proposal item “READ URL must not contain M” is **insufficient**.
  Need no-referrer READ and/or non-wire-visible M.

**Count:** fourteen concrete bypasses. At least FP4, FP9, FP11,
FP12 (with current HTTP pair rule), and FP14 defeat the proposed
CONFIRMED predicates. FP1–FP3, FP5–FP8, FP13 are handled **only if**
S4 is not harvestable.

---

## 7. False-negative analysis

Classification: **acceptable limitation** = safe to ship v1 with
INCONCLUSIVE. **Architectural defect** = the model claims to cover
the class but structurally cannot, or the miss is so central that
CONFIRMED becomes theater.

### 7.1 HTML attribute execution (`onerror`, unquoted attr breakout)

- Why missed: if S1 uses first-occurrence and the first hit is
  `html_body`, S1-meaningful fails even when a later occurrence is
  the `onerror` attribute. If oracle payload is
  `<script>alert(M)</script>` in an attribute context, it may not
  execute; planner-unspecified wrapping.
- Class: first-occurrence = **defect** (proposal already wants all
  occurrences). Context-blind oracle wrap = **defect** until the
  planner is specified. Remaining in-attribute encodings = acceptable.

### 7.2 Script-context reflection

- Why missed: S1 classifier can mark `javascript_string` vs
  `script_block` heuristically wrong (quote scan ignores escapes).
  Oracle `alert(M)` inside an already-open string may be data.
- Class: heuristic location = acceptable if S4 still independently
  required. Blind wrapping = defect.

### 7.3 DOM sink execution (`innerHTML` of `<img onerror>`)

- Why missed: S2 incomplete without `location.hash` /
  `location.search` hooks; hash-only DOM XSS never S2. Observation
  window 5s misses delayed sinks. `innerHTML` of `<script>` does
  not execute in modern browsers — correctly no S4.
- Class: missing source hooks = **defect** relative to proposed S2
  (the proposal already lists them as “hook gap”). Delay = acceptable.

### 7.4 Event-handler execution (`setAttribute('onclick', …)`)

- Why missed: not in SINKS; no hook; no S3; if it runs `alert(M)`,
  E1 can still fire. DOM predicate requires S3 — **E1 with no S3
  is INCONCLUSIVE**.
- Class: **defect** in the DOM predicate. S4 with E1/E2 should not
  be discarded solely for missing S3 when S3 hooks cannot see
  handler assignment. Minimum fix: either hook handler-set sinks
  (proposal “future”) **or** allow DOM CONFIRMED = S2 ∧ S4 when
  S4 is anti-harvest E1/E2 (S3 optional if truncated/unhooked).

### 7.5 `javascript:` URL

- Why missed: no click/navigation to `javascript:` URLs; route
  policy aborts non-http(s). S1 may see `url` location (href).
  Browser never executes the scheme.
- Class: **acceptable limitation** for v1 (no UI interaction).
  Document it. Do not claim href-javascript coverage.

### 7.6 SVG (`<svg/onload=…>`, `<use>`, math)

- Why missed: innerHTML may execute `onload` in some browsers
  (E1 possible). mXSS SVG is snapshot/attribution. Exotic namespaces
  may bypass hooks.
- Class: onload+E1 = confirmable if harvest is closed. Exotic SVG
  mXSS = acceptable limitation without snapshot-as-confirmation.

### 7.7 Mutation XSS

- Why missed: CONFIRMED gated on an undefined snapshot; parser
  diffs without S4; or S4 never fires because sanitizer strips M
  but still produces executable markup that does not contain M
  (mXSS that **drops** the marker).
- Class: requiring snapshot = **defect**. Marker-stripped
  executable mXSS = acceptable INCONCLUSIVE (honest).

### 7.8 Stored XSS

- Why missed: no distinct read URL; browser injects query; no
  CSRF/auth; no async wait; verifier demands HTTP meaningful
  reflection; SUBMIT/READ same attempt_id vs distinct.
- Class: **defect** for the stored class as a product feature.
  After protocol fixes, remaining auth/CSRF/async = acceptable.

### 7.9 POST/body parameters

- Why missed: browser executor rejects non-GET and non-query.
  Reflected POST never reaches S4. HTTP S1 alone is POTENTIAL.
- Class: **defect** if Watch inventory `param_records` include
  body (they do). Minimum design: either a Playwright
  `page.request.post` / form-submit path for reflected body, or
  an explicit class limitation that body cases cap at POTENTIAL.

### 7.10 Authenticated flows

- Why missed: empty browser context; HTTP session not imported;
  cookies redacted and not replayed.
- Class: acceptable limitation **only if** CONFIRMED is defined
  as unauthenticated-only. Otherwise stored/reflected authenticated
  XSS is a **silent FN** (defect in scope definition).

### 7.11 CSP variations

- Why missed: `eval`/`Function` blocked → E3 dead. Inline script
  blocked → many E1 payloads dead. `script-src` allowing `'unsafe-inline'`
  still works. CSP is INFO and does not change predicates — correct
  (CSP is not a verdict). Strict CSP + event-handler XSS may still
  alert; harvest FPs also still alert (FP9).
- Class: E3/CSP = acceptable. Using CSP INFO to skip S4 = forbidden.

### 7.12 Additional misses worth recording

- **`new Function` / indirect eval:** E3 incomplete — acceptable if
  E3 is “additional proof,” not the general one (proposal already
  says this).
- **Production `xss_type=unknown`:** all inventory cases take the
  reflected pair path; DOM-only bugs never get the DOM predicate.
  **Defect** in operational labeling, not in S4 math.
- **Oracle planner missing:** LLM payloads do not contain `alert(M)`
  or `fetch('/'+M)`. S4 never fires → systemic FN. **Defect.**

---

## 8. Implementation gap

### BLOCKING GAPS

1. **Wire-visible execution marker.** Embedding M in the payload
   that executors put in query/body makes E1 and E2 harvestable.
   The ≈0 forgery claim is false. CONFIRMED would introduce new FPs
   (FP4, FP9, FP11, FP14).

2. **E2 predicate is substring-in-path.** Application path-copy of
   `location.href` satisfies it. Must be exact pathname `/{M}` with
   empty query **and** anti-harvest (gap 1).

3. **`actual_request_url` vs reconstruction after redirects**
   contradicts the HTTP executor’s allowed same-origin redirects
   and today’s `request_url == endpoint` binding. Split intended vs
   final URL; do not fail binding on allowed redirects.

4. **Stored READ vs query injection.** Proposal forbids M on the
   READ URL; browser executor always injects the bound input.
   Current stored CONFIRMED also requires HTTP
   `_http_path_confirms` and SUBMIT/READ on the **same**
   `attempt_id`. These three facts cannot be implemented together.

5. **No distinct stored read surface.** `XSSCase.endpoint` is one
   URL. Without `read_endpoint` (and no-referrer READ), stored
   cannot be distinguished from reflected.

6. **E3 `k.value == full payload` vs 240-char truncation.** The
   predicate cannot succeed for real oracle payloads.

7. **`mutation_snapshot` as both required and optional.** Ambiguity
   will produce either FNs (blocking CONFIRMED on an unimplementable
   snapshot) or FPs (treating parser diffs as execution).

8. **Trusted oracle planner unspecified.** LLM must not build
   oracles (R2), but attempts are built from `suggested_payloads`
   verbatim. Without a deterministic, context-aware wrap/select
   step, S4 never occurs (systemic FN) or developers will let the
   LLM emit `alert(M)` (trust violation).

9. **S5 storage clause** (“M written to storage on a fresh
   context”) is indistinguishable from FP5. Must not be a
   confirmation oracle.

10. **DOM CONFIRMED requires S3** while handler/`javascript:` /
    unhooked sinks can execute without S3. Combined with harvestable
    S4, the predicate is both too weak and too strong.

### NON-BLOCKING GAPS

- Split `dialog_events` from `console_messages` (Playwright already
  has the signal).
- Record `eval_invocations` separately from generic sink strings.
- All-occurrence HTTP reflection scan (specified; not done).
- Response/request hashes and truncation flags.
- `run_salt` on tokens/markers (not necessarily on `attempt_id`).
- Extended source hooks (`location.search/hash`, `document.referrer`)
  as listed in the proposal.
- Demote current chain+token CONFIRMED to POTENTIAL (verifier
  change; direction is correct).
- In-memory single-use `round_id` for one `verify()` call (no DB).
- Retire `executed_script` / `browser_verified` as verdict inputs
  (already advisory for CONFIRMED except metadata).
- Observation-window / hop-bound tuning.
- WAF INFO vs BLOCK behavior (already correct).

### FUTURE ENHANCEMENTS

- Authenticated context import (cookie/session) with redaction.
- CSRF and multi-field SUBMIT templates.
- Async stored READ retry/backoff.
- Playwright form POST / `page.request` for body reflected XSS.
- `new Function`, string `setInterval`, handler-set, Worker hooks.
- Click/`javascript:` UI interaction.
- Real per-node mXSS snapshots (sanitizer vs parser).
- Generation-aware DB dedup of findings (if productized).
- `NOT_VULNERABLE` two-control schema (explicitly out of scope
  today).
- Out-of-band canaries (correctly rejected; same-origin policy).

Do not implement future enhancements to “make CONFIRMED work.” They
do not close the blocking gaps.

---

## 9. Minimum design changes before coding

Do not redesign the six-stage chain, executor/verifier split, LLM
isolation, or same-origin browser policy. Change only what makes
CONFIRMED a code claim that this architecture can check.

1. **Anti-harvest marker.** M must not appear as a contiguous
   substring of the request URL, request body, or Referer. Mint M
   in the planner; embed only a **computation** of M in the payload
   (e.g. `alert(String.fromCharCode(...))` or concatenation of
   pieces that are not themselves M). Verifier rejects E1/E2 if M
   is a substring of intended URL, final URL, body, or referrer.

2. **Tighten E2.** Page-initiated, non-navigation, same-origin,
   pathname exact `/{M}` or `/{M}/`, query empty, URL not a
   substring-copy of the navigation URL. Record the request URL
   **before** follow-redirect.

3. **Fix E3.** Predicate is: eval-family hook fired, recorded
   argument contains M or equals P, `truncated=false`. If truncated,
   INCONCLUSIVE. Do not require `k.value == P` unconditionally.

4. **Split URL binding.** Keep `request_url` as endpoint echo **or**
   rename carefully; add `intended_request_url` and
   `final_request_url`. Verifier reconstructs intended; allows
   final to differ when the executor’s existing redirect policy
   would allow the hop. Hashes bind classification to the body.

5. **Stored round, aligned with executors.** SUBMIT = HTTP attempt;
   READ = browser attempt; distinct `attempt_id`; shared
   `logical_pair_id` + `round_id`. Phase observations carry their
   **own** attempt ids. Drop HTTP `_http_path_confirms` from stored
   CONFIRMED. READ navigates to `read_endpoint` **without** query
   injection, `Referrer-Policy: no-referrer`. Cap v1 at
   unauthenticated, single-field, synchronous storage. In-memory
   round consumption; no `database/` registry.

6. **Oracle planner.** Trusted, deterministic, non-LLM. Selects or
   wraps payloads **after** optional HTTP S1 context, from a small
   template set keyed by reflection location / sink family. LLM
   patterns remain candidates, not oracles.

7. **Mutation.** `mutation_snapshot` is attribution-only, never a
   CONFIRMED conjunct.

8. **DOM predicate.** Keep demotion of chain+token to POTENTIAL.
   CONFIRMED requires anti-harvest S4. S2 required. S3 required
   **or** explicitly waived when S4 is E1/E2 and the sink family is
   unhooked (document the waiver). Delete S5-via-storage.

9. **Class labeling.** Define v1 behavior for `xss_type=unknown`
   (reflected pairing + S4; DOM CONFIRMED only when S2 source hooks
   fired and no HTTP S1-meaningful pair is required). Do not assume
   inventory cases are pre-typed.

10. **S1 all-occurrence scan** as already proposed; first-hit-only
    must not ship under the new model.

---

# Final Verdict

NOT READY — DESIGN CHANGES REQUIRED
