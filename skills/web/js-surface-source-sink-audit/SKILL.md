---
name: js-surface-source-sink-audit
description: Use when auditing all JS for DOM XSS sources/sinks.
---

# JS Surface Source→Sink Audit

For the request "read every JS file on the target and check all sources and
sinks" — a bulk static audit of a scope's client-side code, as opposed to
testing one page's reflection context.

Companion skills: `hunt-xss` (payloads and reflection contexts),
`hunt-dom` (DOM clobbering / postMessage / CSS exfil techniques),
`xss-reflection-verification` (differential reflection verdicts). Load those
for the technique layer; this skill is the SURVEY layer that decides which
handful of files deserve that depth.

## The order of work

### 1. Inventory the surface, and count FILES not rows

Pull every JS URL for the in-scope hosts from whatever corpus exists, then
**dedupe by FILENAME** before fetching.

A URL count and a file count are different numbers, and conflating them
overstates coverage by an order of magnitude: the same bundle served on 300
hosts is 300 rows and 1 file. Measure both, quote both, and work by
filename — one bundle is one unit of reading.

Expect the corpus to be full of dead entries. A representative fetch
Expect the corpus to be largely NOT application code. Filter, then count:
`cdn-cgi/challenge-platform` (Cloudflare's WAF challenge scripts, one per
protected host), `googletagmanager`, `google-analytics`, `doubleclick`,
`hotjar`, `segment`, `sentry`, `newrelic`, `optimizely`, `qualtrics` and
`fonts.` are infrastructure. On a 60-country scope, **21,515 discovered JS
URLs reduced to 35 distinct artifacts** once challenge scripts were dropped
and per-country mirrors collapsed — so the "all JS" request is a 35-file
read, not a 21,000-file one. Quoting the raw URL count as coverage overstates
the work by three orders of magnitude.

A representative fetch turnout on one large scope: **1,862 of 3,196 attempts failed**
(`404` 927, `403` 614, `html-not-js` 243, `URLError` 65). Report the
failure mix, do not hide it — it is the honest denominator.

Split the worklist into application-looking and vendor-looking files
(`jquery|bootstrap|react|angular|vue|lodash|moment|d3|polyfill|core-js`…)
and cap the vendor share. Vendor code is where library-internal handlers
live, and those are the ones that waste the most time (see step 5).

### 2. Read the bytes, hash them, and keep them on disk

Stream each body to a cache directory keyed by filename, record the md5,
and dedupe by CONTENT afterwards. Write the manifest incrementally so an
interrupted run resumes instead of restarting. Pace per host — one lock per
host, a short sleep between requests to the same host — and keep the global
rate well under any stated ceiling.

Reject `Content-Type: text/html` responses as `html-not-js`: a soft-404 page
saved as `.js` will otherwise be analysed as JavaScript.

### 3. Run the backward-slice analyzer, not a token scan

A source token and a sink token in the same file is NOT a flow. For every
sink call site:

1. take the sink's ARGUMENT and test it for a source → `direct`
2. else take the identifiers in the argument and walk BACKWARD for
   `ident = RHS` whose right-hand side names a source → `assigned`
3. one more hop through another identifier → `chained`
4. an argument that is a literal → count as `literal` and EXCLUDE

Report the four buckets separately and never sum them into one "findings"
number. The `literal` bucket is the co-occurrence noise you removed, and it
is usually the largest — on one pass **1,209 literal-argument sinks against
179 real candidates**.

**Index once; do not re-scan per identifier.** Walking backward by re-running
`re.finditer(r"\bident\s*=\s*(...)", code)` over the whole file for EVERY
identifier in every sink argument is quadratic, and on a multi-MB bundle it
never finishes: two runs on the same scope died at 50 of 1,168 files and then
at 95 flows. Build one assignment map (`ident -> [RHS strings]`) in a single
`finditer` pass and let the backward walk be a dict lookup. Cap per-file size
and sink matches per pattern so the pass COMPLETES, and record oversized
bundles by NAME as `not analysed` rather than silently dropping them.

**A pass that stopped early is a coverage number, never a finding.** If the
run is killed or stalls, the flows it printed so far mean nothing about the
files it never opened — write `50/1,168 files, incomplete` and fix the
performance before reporting any conclusion from it. A scan that reports
"clean" at 4% coverage is worse than no scan, because it looks finished.

**Non-vacuity comes before any count.** Prove the slicer fires on fixtures
it must detect and stays silent on fixtures it must not, or the whole
number is meaningless. See `references/slicer-non-vacuity-and-fixtures.md`
for the two bugs that silently zeroed an entire 1,334-file pass, the
symptom that identifies each, and the fixture set to keep.

If the gate fails, **abort the dependent phases** and say so. A candidate
count from a detector that cannot fire on a known flow is not a measurement.

### 4. Hand-read the survivors, and reconcile the recorded source

The slicer reports the source it found on the backward walk, which is often
NOT the value the sink receives. Open each surviving candidate's sink line
in the real bytes and name the value by hand. Three shapes that recur:

- **a sibling prop was confused for the source** — a
  `dangerouslySetInnerHTML` attributed to `location.href` when
  `location.href` only fed a URL *resolver* for a neighbouring prop
- **a helper's parameter was confused for the source** — an `innerHTML = t`
  helper whose CALL SITES pass a server response field, so the flow is
  server→client, not attacker→client
- **a second-order fetch** — `$.get(el.data('api')).done(r => el.html(r))`,
  where the sink receives the FETCHED BODY and the URL comes off a DOM data
  attribute. Both facts matter: read the attribute's value off the page. A
  static same-host path closes the lead; a query parameter that BUILDS that
  URL makes the response body attacker-choosable HTML into a parsing sink.

Before attributing behaviour to a helper you found by name, print its FULL
definition. A large minified bundle concatenates thousands of functions, and
a match a few hundred bytes away usually belongs to a different component.
Check a library's presence with an exact match IN THAT FILE.

**Identify the library from the code shape before reading it at all.** These
shapes are library internals, and every one of them has been reported as an
app flow by a slicer at least once:

- `<svg>` + `valueOf().toString()` + `firstChild` → an icon library's
  support probe (FontAwesome)
- `"<script><\/script>"` with `removeChild(firstChild)` → React DOM's
  feature test
- `<pre>` concatenation with `"\x3cpre\x3e"` → an editor (CKEditor)
- `highlightedCode` → a syntax highlighter (Prism)
- an `innerHTML` setter whose argument is the function's own parameter, e.g.
  `E.innerHTML = \`<link rel="stylesheet" href="${f}" />\`` inside a
  `preloadCss(f)` helper → the `cookie`/`search` source the slicer attached is
  a MISS, because `f` is a caller argument with no path from `location`
- `t.innerHTML=(e||"").trim()` used as a tag-stripper on a DETACHED element
  (`createElement` then read `textContent`) → a sanitizer, not a sink

When the file is a UI grid/editor/chart bundle, the honest verdict is
"library internals, no application flow" — say it once and move on instead of
chasing each `innerHTML` hit.

### 5. Read the handler census, not just the handler count

For `postMessage`/`onmessage` sinks, grep the count AND read where
`event.data` goes. Two rules:

- **`e.data` is not automatically `postMessage`.** Libraries pass their own
  payload through the same parameter name —
  `keyboard.bind(keys, callback, {href: href})` gives the callback an `e`
  whose `.data` is the binder's own object. Decisive test: does the file
  contain the literal `postMessage`, and any mention of `origin`, at all?
  Zero of both means no attacker drives it.
- **Many handlers with no origin comparison is not automatically a bug.**
  Read each: web-worker pools (`o.push(n.data)` into a worker array), forge
  PRNG handshakes (`n.data.forge.prng`), self-posts
  (`t.source === window && t.data === e`), MessageChannel polyfills. Count
  `addEventListener("message")` and `onmessage=` separately — they are two
  numbers, and a note quoting one while the artifact holds the other is a
  contradiction a verifier will catch.

### 6. Confirm a sanitizer is on the path that matters

A helper shaped
`function f(e){ let t = getSnippet(e) || escapeAll(getRaw(e)); … }` reads as
unescaped if you only look at the primary branch. Name which branch carries
which data before calling it a flow. A raw `snippet` branch fed by a
SEARCH-ENGINE field is not a URL sink; the escaping in the fallback branch
does not cover it, but the data does not reach the sink either — say which.

## Two verdicts you must be willing to write

**UNRESOLVED is a verdict, not a gap.** When a real flow's input cannot be
observed — the element carrying the data attribute is absent from the
archive, the endpoint needs a session — write UNRESOLVED and name exactly
what would close it. Never write "clean" for something you could not
observe, and never leave it looking closed.

**A code flow with no demonstrated attacker influence is NOT reportable.**
"The response body goes into a parsing sink with no encoder between" is a
strong lead and not a finding. State the flow, state the missing
attribution, and stop.

## When a lead is session-gated, find the host that lets you in

Ending with "needs an account" is half an answer. Before naming a site,
**measure the registration surface** of every candidate host — a host whose
signup you never checked wastes the user's time. Probe `/`, `/login`,
`/signin`, `/register`, `/signup`, `/account/register` and classify by what
the form IS:

- **a password field PLUS register/create-account wording** → plausibly
  self-service; worth a human's browser check
- **a password field and NOTHING else** — an `aspnetForm` posting to
  `./Login.aspx` with only `txtUsername` + `txtPassword` — is an
  **existing-account login**, not registration
- **page copy naming a business relationship** (`partner agreement`,
  `partner program`, `vendor`, `contact your administrator`, `business
  email`, `invite`, `request access`, `contact sales`) means the account is
  provisioned by a contract. A portal titled "Vendor Microsite" is the
  giveaway
- **probe the root domain too** — a subdomain can 403 while the root serves
  a working `/account/register`

Then check your OWN client can reach the authenticated surface. A host
answering with a bot challenge (403 "Security Check", Cloudflare
`ctype: 'managed'`) cannot be driven by the agent even after the user
registers there — hand that path to the user's browser or say plainly that
the account is for human-led testing. That sentence is what stops a session
being spent on work the account cannot unlock.

Deliver it as ONE host plus the exact URL, the bug classes that session
unlocks, and the lead a DIFFERENT host's account would NOT reach.

## Reporting discipline for this class

- A note under `evidence/` for everything that is a primitive, informational,
  public-by-design, unconfirmed, or gated — with an explicit "NOT A REPORT"
  line. A report only when the bug is proven.
- Every number in the note must be re-derivable from an artifact on disk.
  **Assert against the artifact's actual value, never a set reconstructed
  from the note's prose** — a check written from memory once demanded a
  parameter on a host whose artifact held it on a different host, and failed
  correctly.
- Write a verifier per note that re-runs the load-bearing claims, and
  re-run the analyzer's fixtures from inside it so the central claim cannot
  rot. Exit non-zero on any failure.
- Disclose capability gaps: fetch failure counts, phases aborted by a failed
  gate, and hosts blocked by a challenge page all belong in the note.

## Support files

- `references/slicer-non-vacuity-and-fixtures.md` — the two slicer bugs that
  zero a pass silently, their symptoms, and the fixture set to keep.
- `references/parameter-surface-inventory.md` — the crawl is not the parameter
  inventory: how to mine `param_records`/x8 output, the two artifact classes
  that inflate it, and the browser-side depth that a static pass cannot reach.
