---
name: web-finding-verification
description: "Use when validating a web vuln candidate before reporting: XSS, SSRF, IDOR, auth bypass, disclosure."
---

# Validating a web/API vulnerability candidate

A candidate is not a finding. Between "the probe returned something interesting"
and "this goes in the report" there is a verification step, and skipping it is how
false positives get published. Every rule below exists because a plausible-looking
signal turned out to mean something else.

**Trigger phrases:** "is this XSS exploitable", "validate this finding",
"is this reportable", "verify the reflection", "confirm the SSRF", "should I
report this", "is this a real vulnerability", "why did the scanner find nothing".

**Scope:** this skill governs VERIFYING a candidate you already have. For the
hunting side - how to find reflections at all, differential baselines, encoding
layers, WAF-gated hosts - load `xss-reflection-verification` alongside it.

## 1. A status code is not evidence

`200` means the request was answered, nothing more. Read the BODY before treating
any response as reachable.

- A 200 carrying `{"errorMessage": "Invalid User Session..."}`, `{"uploaded": false}`,
  or `[]` is a **denial**, not access.
- Any scanner or loop gated on the status code logs a false hit on every iteration.
  Gate on the response body — grep for session / auth / expired / invalid keywords —
  or on the field that must be populated.
- Before concluding "the endpoint is unauthenticated", confirm it returns the data
  you claim. An endpoint that answers 200 with nothing is not a finding.

## 2. A session check that runs before the data layer makes a class untestable

When every object-referencing endpoint returns the same error envelope without a
session, the authorization check executes **before** the data lookup. Swapping `id`,
`fileName`, `partNumber`, `swbNumber`, or any other object reference never reaches a
record.

- The test never executed. Report the surface as **session-gated / not testable
  without credentials**.
- Do NOT record it as "no IDOR found" — that asserts a test you did not perform.
- Do NOT record it as "unauthenticated endpoint" — that asserts access you did not get.
- A sibling endpoint on the same host that *does* answer without a session is a real
  inconsistency worth reporting (Low), but only after confirming it returns no data (§4).

## 3. A hang is not SSRF

An endpoint that hangs, errors, or returns a constant (`"true"`, `"ok"`) when fed a
URL, hostname, or file path is not automatically SSRF, path traversal, or file read.

Run a **differential test** before claiming any of them:

1. Same request, three inputs: (a) a destination reachable from the internet — your
   own listener, (b) an unreachable destination — RFC1918 address with no host, a
   closed port, (c) a malformed value.
2. Compare timing, and confirm with an out-of-band callback (Interactsh, Collaborator,
   or a listener you control).
3. If **every** input behaves identically — same hang, same error, same constant —
   regardless of destination, no network request is being made.

- `http://`, `file://`, and UNC (`\\host\share`) payloads that all behave the same
  prove the parameter is not used to fetch. Say so and stop; do not keep hunting
  payloads for a bug that is not there.
- An unbounded hang on a user-supplied path is still reportable — as **resource
  exhaustion / logic bug (Low–Medium)**, labelled accurately. Never dress it up as SSRF.

## 3a. A CHANGED response is not evidence of a fetch — prove the comparator stable first

§3 covers "nothing changed, so nothing happened". The mirror-image error is
cheaper to make and harder to catch: **something changed, so the input is being
consumed.** It is not. A body difference has at least three causes, and only one
of them involves the server reading your value.

Run these in order. Skipping step 1 is what produces the false positive.

1. **Prove each arm stable across repeats.** Send the identical URL N times and
   require an identical `(status, sha)`. A page that renders a per-request nonce
   hashes differently every time, so "probe differs from control" fires on pure
   jitter — one host returned 298/298/298/298 bytes with four different hashes
   and was reported as parameter-sensitive until the repeat test was added. An
   arm that is not internally stable leaves the host **unjudged**, not clean and
   not vulnerable.
2. **Isolate ONE variable.** If probe is `?goto=<payload>` and control is
   `?<random>=<other value>`, a difference cannot be attributed to the name or to
   the value. Hold the value constant and vary only the name:
   `?goto=<url>` vs `?zqrandom=<url>`. If the unknown name behaves like the real
   one, nothing is reading the name.
3. **Read the BODY, not its length.** Two lengths from one URL can mean two
   different servers. A `?goto=` parameter that turned a 52-byte page into 896
   bytes was serving `<title>Welcome to nginx!</title>` — the load balancer
   routing that query shape to a vhost that was never configured. Nothing was
   fetched, and the byte count had looked like consumption for three phases.
   Stock-page markers that mean "you never reached the application": `Welcome to
   nginx!`, `It works!`, `Apache2 Ubuntu Default Page`, `IIS Windows Server`,
   `Test Page for the`.
4. **Assert what the label implies, across ALL arms.** A verdict name is a
   claim. "Backend switch" requires a baseline that was NOT the default page and
   a probe that IS; `probe_is_default` alone names an event that may never have
   happened on that host. Seven of eight hosts labelled `BACKEND-SWITCH` had
   served the default page on every arm — a different observation (`ALWAYS-
   DEFAULT`) that only appeared once the condition was applied to all arms.

When a later measurement contradicts a verdict you already issued, **withdraw it
in writing** and state what the artifact shows. A retracted verdict with its
reason is evidence that the method was checked; a silently corrected one is not.

## 3b. Triage the SCANNER'S RULE before testing its findings

When the input is a batch from a heuristic template (`-custom` nuclei, any rule
you did not write), the per-finding question "is this a bug" is the wrong first
question — the honest answer for the whole batch may be "this rule cannot detect
one". Answer four things from the findings' own metadata, before spending a
request:

1. **Where did it fire?** A flag on `<host>/` proves the host answers on its root
   path, nothing about a parameter. A rule that fires only at `/` has guessed a
   parameter name and aimed it at the root of every host in the corpus.
2. **Does the host serve an application there?** Read what `/` returns. A stock
   default page means the root is not the app.
3. **Does it answer at all?** Count the dead hosts. In one 28-finding population,
   9 did not answer and 7 served only a default page — over half the batch could
   not have been a finding regardless of the parameter.
4. **How many distinct findings are there?** Deduplicate by host+parameter+path;
   templates that rotate ports or user-agents inflate one condition into many.

Only what survives those four is worth a request. Then report a verdict about the
**rule**, with the population arithmetic: "0 true positives on this scope, and
here is the breakdown that shows why" is a complete result — and a stronger
statement than 28 individual "could not confirm" entries.

When the guessed population is empty, invert it: take the parameter names real
first-party JS actually puts into a request URL. Expect mostly `data-src` /
`target` / `data-api` style *client-side attributes* — lazy-load and modal
targets, not server-side fetch parameters. A census of attribute names is not a
list of sinks.

## 4. Auth inconsistency is not data exposure

When a sibling set of endpoints requires auth but one answers unauthenticated, that is
an **auth inconsistency** — a legitimate Low finding, and nothing more until you prove
otherwise.

- Probe in order: `{ __typename }`, then `__schema`, then `__type(name: "...")`, then
  guessed field names.
- If introspection is disabled and guessed fields return `undefined`, **no data was
  exposed**. Write that sentence in the report instead of implying otherwise.
- Type/table names leaked through validation errors are **schema disclosure**, not data
  exposure. Keep the severity honest rather than upgrading the finding.
- "The endpoint is missing authentication" and "the endpoint leaks data" are different
  claims. Report them separately so the first cannot be read as carrying the second.

## 5. A negative result is a result

A sweep that returns zero is a finding about the surface, not a gap in your work.
Report it plainly, with the volume:

- State requests sent and hits found (`GET ~28,000 · POST ~4,800 · reflected 0`).
  A count with no hits is evidence that the surface was covered.
- Never manufacture a hit, auto-promote a low-confidence candidate, or widen a gate to
  turn an empty result into a non-empty one.
- Never report a positive from a run you did not observe. If a scan produced no output
  file, that is UNVERIFIED — re-run it or report the tool as not having run; do not
  infer its result from the absence of a file.
- A zero-hit result is only a claim about the surface if the run actually
  EXAMINED it — see §10 before quoting it.

## 5a. Tooling pitfalls that silently produce a wrong result

These produce a plausible-looking wrong answer rather than an error, so they
survive review unless you know to look for them.

- **`urllib.parse.urlencode` double-encodes an already-encoded value.** A
  payload that is pre-encoded for the URL layer comes out as `%253C` and never
  decodes, so every probe reads as "the payload did not arrive" and you
  conclude the parameter is inert. Build the query by hand when the value is
  pre-encoded, and assert the final query string contains the encoding you
  intended.
- **Never `%`-format a string that contains a percent-encoded payload.**
  `"...%3C..." % value` raises `ValueError: unsupported format character`.
  Use concatenation, `.format()`, or f-strings.
- **A function-local `import urllib.request` shadows the `urllib` name inside
  that function**, so a later `urllib.parse.unquote` raises
  `UnboundLocalError`. Import submodules at module level.
- **`pkill -f <pattern>` matches the shell running the pkill** when the
  pattern also appears in the kill command line, so it kills its own shell
  (exit 143 / SIGTERM) and the intended target survives. Use a marker that
  does not appear in the kill command, or kill by PID.
- **A script whose own source contains its search pattern will match
  itself.** Grep for a distinctive token, or filter the script's own path out
  of the results.
- **A superseded runner's log is not evidence.** When a scan is replaced,
  keep the replacement's log and delete the old one; two logs with different
  numbers invite quoting the wrong one.

## 6. A WAF block is not a vulnerability

Sustained 403s across every payload variant mean the request never reached the
application.

- Report WAF-protected hosts as **not testable / blocked**, with the technique count
  attempted, rather than as "no vulnerability found".
- Do not record a blocked host as clean — an untested surface and a tested-clean
  surface are different states.

## 7. Scope discipline

- Probe only hosts the program lists as in scope. An out-of-scope host never receives
  traffic, even for a "quick check".
- Stay non-destructive and GET-only unless the operator explicitly authorises
  otherwise. A POST used to detect reflection is fine; a POST that mutates state is not.
- When a safety rule must be broken to make progress, stop and report rather than
  proceeding.

## 8. A client-side reflection is invisible to a body scanner

A parameter the SERVER echoes inertly (escaped, or double-percent-encoded
inside a tracking pixel) can still be exploitable, because the page's own
JavaScript may read `location.search` and write it into an HTML sink. A
body scanner sees only the inert echo and reports "no reflection" on a page
that is genuinely vulnerable.

- **A third-party form toolkit on the page is the thing to read, not the
  response body.** Landing-page platforms (Eloqua, Marketo, Pardot,
  HubSpot) ship a "fill this form from the query string" script that copies
  any parameter into the field of the same name - hidden inputs included -
  applying its OWN decoder, and a form script that writes those values into
  `innerHTML`. Enumerate the page's `<input>`/`<select>` names, then
  enumerate every `innerHTML` write in the form script and classify each
  SOURCE. Fetch the form script from ITS OWN host; it is served from a CDN,
  not the page's host.
- **A source that looks attacker-controlled may be dead.** A variable
  assigned from a personalization API is not a sink if that function is not
  defined on the page. Check `typeof window.<Fn>` before believing the path
  is reachable.
- **The parameter that GATES a branch usually flows into an element too.**
  Test the gate parameter on its own - it is often the shortest vector,
  because it needs no companion parameter.
- **An HTML5 `type="email"` input does not block a payload.** Constraint
  validation runs on form SUBMISSION, not on a programmatic `.val()` write.
- **Conditionally revealed fields are not automatically new sinks.**
  Activating a field can unlock many inputs; enumerate what actually reads
  into an HTML context. Report the activation effect AND the absence of a
  new sink - that is a bounded, useful claim.
- Detail: `references/third-party-form-toolkits.md`.

## 9. Proof of execution must be observed, not inferred

A negative browser result proves nothing until the hook is shown to work.
Three traps make a working payload look dead:

- **An out-of-band beacon over plain HTTP is blocked as mixed content**
  from an HTTPS page, so "no beacon hit" is not evidence of no execution.
  Use an in-page marker read back from the same session
  (`document.title`, a `data-` attribute on `document.body`). For
  same-origin read access, `fetch('/page').then(r=>r.text()).then(t=>document.title='LEN'+t.length)`
  proves the injected code ran with the victim's origin privileges and
  needs no network setup.
- **A page-init hook does not apply to a tab opened afterwards.** Verify
  the hook landed (a flag you set) before trusting its negative.
- **A payload can reach the DOM and still not fire.** `src=""` resolves to
  the page URL, which loads fine, so `onerror` never runs - use a
  non-resolving host. Separating attributes with a SPACE rather than `/`
  matters: `/` yields `src=""` plus a separate `onerror` that never
  triggers. `<svg onload=...>` inserted via `innerHTML` does not fire;
  `<details open ontoggle=...>`, `<video src=x onerror=...>`,
  `<audio src=x onerror=...>` and `<marquee onstart=...>` do.

## 10. A scan that examined nothing is not a clean result

A coverage number and a hit number are different claims, and a filter bug
can zero the first one.

- **Print the number of candidates EXAMINED next to the number of hits.**
  A runner whose filter excludes everything reports "0 hits", which reads
  as "nothing there" instead of "nothing looked at". If the candidate count
  is 0, the run is BROKEN, not clean — fix the filter and re-run before
  quoting it.
- **A zero-hit result becomes a claim about the surface only once you can
  show the surface was examined** (§5). Request count alone is not enough;
  a runner that fetched 0 candidates made 0 requests and learned nothing.
- **Do not let a superseded runner's log stand as evidence.** Keep the
  replacement's log and delete the old one; two logs with different numbers
  invite quoting the wrong one.

## 10a. A blast-radius count needs a verdict distribution

When one shared script serves hundreds of pages, "21 pages are vulnerable" is
unfalsifiable unless the other pages are accounted for. Sweep every page of the
platform and assign each one a verdict:

| verdict | meaning |
|---|---|
| `VULNERABLE` | the shared sink script is loaded and the payload fires |
| `no-fill-script` | the page never loads the query-to-form fill script, so no parameter reaches a form field |
| `no-merge-field` | the fill script is loaded but the page has no merge field, so the value never reaches the sink |
| `no-sink-in-script` | the page loads a matching script, but that script has no HTML sink |

Rules that make the table trustworthy:

- **Derive the verdict from the script, not from the page markup.** A
  page-level grep and a script-level scan produce different candidate sets,
  because the sink lives in an external file the page only references.
  Run both, and treat every disagreement as a page to investigate - not a
  number to average or to report as the "real" count.
- **Separate a broken page from a candidate.** A page that locks the browser
  up even with a benign payload, and whose own assets no longer load, is
  untestable. It is neither vulnerable nor clean, and must not be counted in
  either direction.
- **The scan is a filter; the browser is the verdict.** Confirm the
  survivors in a real browser before publishing a count.
- **Report the distribution table, not just the count.** A reader must be
  able to see that the non-vulnerable pages were examined and why they are
  not vulnerable, otherwise the number is an unfalsifiable claim.
- **Re-run the scan with the corrected criterion before publishing any
  count.** A first pass that used the wrong criterion (server-side
  reflection instead of client-side reachability) can report the same
  surface as clean while missing every real instance. State the corrected
  number in the report, not the first number.

## 11. Report shape

Close with:

- A per-class table: class | tested (count/surface) | result | verified?
- Explicit **VERIFIED: yes/no** per candidate, and for anything not verified the reason
  (session-gated, WAF-blocked, no output, differential disproved).
- The honest verdict. "No reflected XSS in ~33,000 requests" is a complete deliverable.
  A manufactured Medium is not.

See `references/probe-recipes.md` for the concrete commands behind §2–§4.

## 12. Rank the findings by what a reader can act on

When the operator asks "what else did you find that is worth looking at?", the
answer is a RANKED list, not an inventory. Order by:

1. **Reportable as-is** - proven, bounded, with a severity a triager can act on.
2. **Reportable but bounded** - proven, but the impact ceiling must be stated
   explicitly ("blind request forgery to a public host; no internal reach").
3. **Not reportable** - keep these OUT of the ranked list, or the list becomes
   noise and the reportable items get ignored.

For each entry give the class, the severity, and one line on what is and is not
demonstrated. A finding whose evidence supports only a narrow claim must be
listed at that narrow claim's severity, not at the severity the bug class
would allow - a class of bug does not set the severity, the demonstrated impact
does.

Keep the negative results separate from the ranked list. A sweep that found
nothing is a legitimate deliverable with a volume attached, but it is not a
"finding worth checking" and belongs in its own section.
