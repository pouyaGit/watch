---
name: xss-reflection-verification
description: Use when verifying a reflected XSS candidate.
---

# XSS Reflection Verification

Load this alongside `offensive-xss` whenever the task is "find a reflected
XSS" or "is this reflection exploitable". It covers the failure modes that
produce false positives and silent coverage gaps.

## Trigger Phrases

`reflected XSS`, `is this reflection exploitable`, `validate XSS hit`,
`verify the reflection`, `XSS confirmed`, `WAF bypass`, `query string
truncated`, `reflection in Location header`, `DOM sink`, `JSONP callback`

## THE DIFFERENTIAL RULE (non-negotiable)

A window-based "is there a dangerous char near the marker" check is NOT a
verdict — it counts the attribute's own delimiters and produces constant
false positives. Every candidate reflection needs a DIFFERENTIAL test:

1. Fetch the same URL with a benign value -> baseline DOM profile.
2. Fetch it with the breakout payload -> payload DOM profile.
3. REAL only if the payload profile differs:
   - a NEW element appears (svg/iframe/script/img/style)
   - a NEW event-handler attribute appears
   - a raw `<` is inside a PARSED attribute value
   - the payload bytes appear RAW (not percent/entity encoded)

Parse with a real HTML parser (`html.parser` or the browser DOM), never
with a regex over the raw body. A tag the payload did not create (an
`<iframe>` the template always emits, a `link onload` the page ships) is
NOT a finding — only a DELTA against the baseline counts.

Corollary: a detector without a baseline cannot separate "the payload
was reflected" from "the page always contains an iframe". This single
omission invalidated 8,850 stored hits in one real hunt.

### A blocked host is an ENVIRONMENTAL LIMIT, and the re-test must be ready to run

When a WAF starts resetting the TLS handshake mid-run, the phase that
was in flight is **incomplete**, and it stays incomplete until the
host answers again. Record it as incomplete - do not describe the
reflection as either safe or vulnerable.

Three things make the difference between a stalled phase and a
finished one:

1. **Re-check the block at the END of the hunt**, not at the moment
   it happened. The block may lift, and the phase becomes runnable.
2. **Establish the SCOPE of the block.** Test the whole sibling
   family and a control host from the same provider. If
   `gatekeeper.digicert.com` and `my.gatekeeper.digicert.com` both
   reset while `one.oracle.digicert.com` and `www.digicert.com`
   answer normally, it is a per-host edge rate-limit on this source
   IP, not an outage and not a global block. Say which it is.
3. **Write the re-test as a runnable script NOW, while you still
   remember what it has to do** - and make it **abort after a single
   reachability check** when the host is still blocked. A re-test
   script that runs its whole input set against a blocked host
   re-triggers the rate limit that caused the problem.

Do not try to work around the block. `X-Forwarded-For`,
`X-Real-IP` and `CF-Connecting-IP` must not work, and if they did
you would be testing a forgery rather than the product. Try plain
HTTP once in case the WAF filters 443 only, then stop.

### A `raw_context` flag that fires on plain letters is a BROKEN DETECTOR

A checker that looks for `<`, `>`, `"` or `'` within N bytes of the
echoed value will fire on EVERY value, because the value is almost
always echoed into an HTML attribute and the surrounding markup
contains its own quotes:

```
value = "ABCDEFGHIJK"   -> echoed=True  raw_context=True   <- FALSE POSITIVE
```

The markup's own `value="` quotes are what matched. Before believing a
`raw_context` flag:

1. Run it against a BENIGN value made only of letters and digits.
2. If it still fires, the detector is measuring the surrounding
   markup, not an injected character. The test is void.
3. Then print the EXACT bytes around the echo and READ them: which
   element does the value land in (`value="..."` of an input, a text
   node, a `<script>` string, a `data-` attribute), and does the
   dangerous character survive to the wire un-encoded?

Separate the four forms, because they behave differently:

| Form | Where to look | Danger |
|---|---|---|
| wire form | the raw bytes on the socket | what the server actually sent |
| decoded form | after URL-decoding | what the app received |
| entity form | `&lt;` `&quot;` in the body | inert in HTML text, live in some attributes |
| raw character | the dangerous char itself in a parsed context | the only one that is an XSS |

### A field's `maxlength` decides whether a rate limit is the finding

A code-check endpoint with no rate limit looks like a brute-force
primitive and usually is not. Read the `maxlength` and the copy
BEFORE deciding:

- `maxlength=6`, numeric-looking -> a 6-digit PIN, a 1e6 space. An
  unthrottled check is a real takeover primitive.
- `maxlength=45` on a field labelled "enter the code we emailed you"
  -> a long token. A missing rate limit on it is "rate limit on a
  non-critical form" - never-submit.

Measure the code space first; only then decide whether the rate limit
matters.

### A code check has THREE enumeration channels - close all three

1. **Body** - every code shape must return a byte-identical response.
   A shape that gets a different message ("invalid format" vs "not
   found") is a format oracle.
2. **Timing** - measure POST latency per code shape AND the server's
   own baseline (a plain GET of the same page) in the same loop. A
   multi-second server response can hide a 50 ms oracle, so subtract
   the baseline instead of comparing POSTs to each other. If the
   medians span less than the baseline's own jitter, there is no
   timing oracle.
3. **Status code** - a 200 for "not found" and a 400 for "malformed"
   is a shape oracle even when the bodies look alike.

## MEASURE THE SERVER'S REFLECTION LIMITS BEFORE DESIGNING A SWEEP

Two server-side limits silently truncate coverage if ignored. Measure
them first, with one host and one parameter:

- **Query-string truncation**: many servers echo only the first ~500
  bytes of the query string (head kept, tail dropped). Sending 100
  parameters in one request means the tail ones are never reflected, and
  you will wrongly conclude "that parameter does not reflect". Split the
  parameter list into chunks that fit under the limit.
- **Request-target length cap**: a request line above ~2 KB may return
  404/400 instead of the page. A longer marker changes the length, so a
  long marker can flip a 200 into a 404 and look like "no reflection".

Measure both with: one parameter with an increasing-length value, and one
request with an increasing number of parameters.

## A WAF-GATED HOST CAN INVALIDATE AN ENTIRE SCAN

If a host answers every request with a 302 to itself plus a fixed
"Loading" body, the scan is measuring the WAF, not the site:

- A "reflection" in the `Location` header of a self-redirect is just
  the request URI echoed back — not a finding.
- A "reflection" in the WAF's interstitial body is not a finding.
- The same path can behave differently minutes apart as WAF rules
  change, so re-verify old artifacts against CURRENT behaviour.

Detect it: fetch a path that exists and one that does not. If both give
the identical status and body length, the host is WAF-gated and every
reflection found there is suspect. The browser is the tiebreaker: a real
browser sitting on a challenge page (title shows a spinner/emoji, body
length fixed) confirms it.

## CONTEXTS A BODY-ONLY SCANNER MISSES

A reflected XSS does not need to be in the body. Check these explicitly:

- **Response headers** — `Location` is followed by the browser; a raw
  `javascript:` there is a sink. CRLF injection in a reflected header
  splits the response and yields a fully attacker-controlled body.
- **`application/json` without `nosniff`** — the browser may sniff it
  as HTML. Check `X-Content-Type-Options` explicitly.
- **`<script type="application/json">`** — a raw `</script>` in the
  value breaks out of the block.
- **SVG served as `image/svg+xml`** — raw `<` and `>` execute.
- **Comment context** — `-->` ends the comment and the rest is markup.
- **DOM sinks** — `location.replace`, `document.write`, `innerHTML`,
  `eval`, `jQuery .html()`. A `jQuery .html(response)` sink makes the
  RESPONSE of an AJAX endpoint an XSS sink, so test the AJAX endpoint's
  output, not just the page that calls it.
- **Redirect targets** — a `javascript:` URI inside an `href` needs one
  click, which is still a reportable reflected XSS.

## ENCODING IS USUALLY LAYERED — COUNT THE LAYERS

When a value comes back escaped, do not conclude "it is safe". Measure
the layer count: send `&quot;`, `%26quot;`, `%2526quot;`,
`%252526quot;` and read what each becomes. A single double-decode
anywhere in the chain turns a safe-looking `%22` into a live `"`.

Also test the PARAMETER NAME, not just the value: names are often handled
by a different code path, and a name that survives with a raw quote
breaks out of the attribute holding `&<name>=<value>`.

## AN UNAUTHENTICATED ERROR PAGE IS A REAL SURFACE

404/403/500 pages built by the application (not the WAF) often echo the
request path or query string. Test them with the same payloads and the
same differential rule.

Also check whether the error body leaks internal hostnames or private IPs.
A Go service that proxies to an internal upstream and returns the
transport error verbatim discloses the internal host and address — but
that is disclosure, NOT SSRF, because the upstream URL is fixed and only
the query is appended. Say so explicitly in the report.

## WHEN NO XSS EXISTS, GO WHERE THE SERVER ACTUALLY MAKES REQUESTS

A certificate-checker, URL-preview, webhook-test or PDF-render endpoint is
a server-side request primitive, not just a reflection surface. When a
target's front end POSTs a hostname to a back-end and renders the reply
with `jQuery .html(response)`, test the POST body - GET often reflects
nothing at all, and the POST path is where the finding lives.

The productive move is to stand up a controlled server and let the target
connect to YOU:

- `nip.io` / `sslip.io` / `localtest.me` map an IP embedded in the name
  to that IP, so `<your-ip>.nip.io` is a hostname that resolves to you
  without owning DNS.
- The target usually speaks TLS only (if it reports certificate details),
  so serve TLS. Python's `send_response_only()` writes no default
  `Server` header, unlike `send_response()` - use it if you need to
  control that header exactly.
- The certificate CN and SAN are attacker-controlled data too, and they
  are usually reflected next to the Server header. Test them as separate
  vectors with a fresh certificate per payload.
- A self-signed certificate is usually ACCEPTED, because the service only
  reports "not issued by DigiCert" rather than failing. That is itself a
  finding: the endpoint is a universal TLS prober.

Watch for rate limiting: these endpoints answer 429 at roughly one
request per 9 s, and at higher rates the WAF answers 302. Insert a real
gap and treat 429/302 as "not tested", never as a pass.

## A STRING-BASED "PUBLIC ADDRESS" CHECK IS NOT A FILTER

An error like "is not a fully qualified public domain name or public IP
address" reads like it blocks private space. It usually does not:

- IP LITERALS for loopback / link-local / RFC1918 are rejected.
- DNS NAMES THAT RESOLVE TO THOSE ADDRESSES are not - `127.0.0.1.nip.io`
  passes the check and the server proceeds to resolve and connect.

To prove the primitive, connect to a host you control and show the
target's own IP in the response ("DNS resolves X to Y"). To prove the
private reachability, a name resolving to a private address must return a
CERTIFICATE, not just "Unable to connect" - "Unable to connect" is
indistinguishable from a name that never resolved, so do not claim
private reachability on that evidence alone.

## ESCAPING IS A PROPERTY OF THE CONTEXT, NOT OF THE FIELD

When a value comes back entity-encoded, check that the entity is the ONLY
thing present. A payload that yields both `&lt;` and a raw `<` is
different from one that yields only `&lt;`. Enumerate every reflected
`<p>`/`<td>` text node programmatically and look for a raw `<`, `>` or
`"` in ANY of them, and also check whether any value landed in an
ATTRIBUTE context (a different breakout requirement).

If every reflected value is escaped and none is in an attribute, the
finding is the SSRF / the information disclosure - not XSS. Say exactly
that in the report, and report the reflection analysis as its own
section so the reviewer can see the work rather than take the claim on
trust.

## A REFLECTED `Location` HEADER IS NOT AN OPEN REDIRECT

A 302 whose `Location` echoes the request URI is a very common false
positive, especially behind Imperva/Incapsula. Decide it with three
questions, all answerable with a raw socket:

1. **Does the authority ever change?** The Location is built as
   `https://<fixed-host>` + path + `?` + query. Test the payload in the
   PATH and in the QUERY, with `@`, `//`, `\`, `../` and a full
   `https://evil.example.com/` value. If the host part of the Location
   is always the fixed host, it is not an open redirect. A raw `@` or
   `//` inside the *query* is harmless - it is a query value, not an
   authority.
2. **Can the response be split?** Send a raw CRLF in the request target
   (a normal client refuses to send it, so use a socket). If the
   response still has exactly one `HTTP/1.x` block and no injected
   header, there is no header injection.
3. **Is it the WAF or the application?** A fixed 122-byte body plus
   `X-Iinfo`, `visid_incap_*` and `incap_ses_*` cookies, and a 404 path
   that redirects to a health-probe path, means the WAF owns the
   redirect. The application never saw the request.

A raw `<` or `"` inside a Location value is NOT XSS: the browser parses
Location as a URL, not as HTML. It only matters if the authority can
change or the response can be split.

When using a raw socket against an HTTPS host, send SNI
(`server_hostname=`) - without it the WAF answers differently or not at
all, and the test silently measures nothing.

## A REDIRECTED BASELINE IS NOT A BASELINE

When the endpoint 302-redirects, the reflection usually lands on the
REDIRECT TARGET, not the URL you requested. Fetch the target (follow
the `Location`, keeping the query string) for BOTH the baseline and the
payload, or the diff is meaningless.

The classic trap: the crawl compared the payload response against a
hard-coded expectation and reported the page's own `<iframe>`, nine
`onload` handlers and five `onclick` handlers as "NEW-ELEMENT" and
"HANDLER" findings. A fetched baseline showed the template already
contains them. Nine false positives, zero real ones.

## A WAF THAT BLOCKS THE PAYLOAD MAKES THE ENDPOINT UNOBSERVABLE

If benign values return 200 with the full page but every payload shape
returns 406/403, you have NOT proven the endpoint is safe - you have
failed to observe it. Report that as "the endpoint's behaviour under a
payload could not be observed", not as a pass.

To get an observation, vary the payload SHAPE rather than giving up:
different tag, different case, no event handler, entity-encoded,
numeric entity, a lone quote, a lone angle bracket, a plain marker.
In one real test 5 of 20 shapes got through, and all 5 were then
diffed against a real baseline. The lone quote and the plain marker are
the most useful probes: they are enough to see whether the value is
quoted or escaped, without matching an event-handler rule.

Note the reflection context when it does come back - a value in
`form/@action` that arrives as `%22` / `%3e` is attribute-escaped and
cannot break out, no matter what else the page contains.

## PROVE THE BROWSER TEST CAN FAIL BEFORE TRUSTING A CLEAN RESULT

A browser run that reports "no alert" proves nothing unless the alert
hook is shown to work. Install the hook and fire a known-executing
control page FIRST:

```js
window.alert = function(v){ window.__xss = true; window.__xssHits.push(String(v)); return true; };
```

Load a local page that calls `alert('CONTROL_FIRED')` and confirm
`window.__xss === true`. Only then are the negative results meaningful.

Two practical obstacles to expect:
- The browser session's network may not reach the target at all (it
  lands on `chrome-error://chromewebdata/`). A local proxy on
  127.0.0.1 is ALSO unreachable from that sandbox. The workaround that
  works: save the real server response to a local file and load it over
  `file://`. The bytes are the server's own, so the JS context is real.
- `node --check /dev/stdin` silently fails on some builds (it reports a
  fs error, not a syntax error). Write the snippet to a temp file and
  check THAT.

## A JS-STRING REFLECTION IS ONLY A FINDING IF THE STRING BREAKS

When a value lands inside a JavaScript string literal
(`window.location.replace("...q=VALUE...")`), the payload must escape
the string to be exploitable. Check the exact source line:

1. the number of UNESCAPED quotes in the argument must stay even
2. the payload must not appear outside the string literal
3. the line must still parse - `node --check` on a temp file is a real
   parser and settles it

Percent-encoding at the URL layer (`"` -> `%22`, `\` -> `%5C`) makes
the string unbreakable before the value ever reaches the template, and
a JSON-encoded value (`\u0026` for `&`) is safe for the same reason.
Verify the encoding on the rendered line, not on the request.

## A WINDOWED "NO ENCODING FOUND" VERDICT IS NOT "RAW"

A detector that looks at the ~60 bytes around the marker and labels the
hit RAW when it finds neither `%XX` nor `&lt;`/`&gt;`/`&quot;` is
measuring the TEMPLATE, not the payload. A fixed tracking pixel is the
classic case:

```html
<img src="https://.../svrGP?siteid=1&elq_ck=0&q=MARKER" border=0 width=1>
```

The `"` that closes the `src` attribute and the `"` that opens
`border=0` are template characters that sit inside the scanned window,
so a payload that was percent-encoded or dropped still produces a "RAW"
hit. In one real run this produced 80 false positives on 11 different
parameters, all of them the same pixel.

The fix is to compare the window against the SAME window from a
baseline request with a benign value, and to check where the marker
actually sits:

- the marker inside an attribute VALUE is not a breakout - the payload
  has to escape the attribute, which means the attribute's own
  delimiter must be attacker-controlled
- the marker in a TEXT node is not a breakout either - a text node
  needs a raw `<` to open a new tag
- only a raw `<` that the PAYLOAD introduced (i.e. a DOM delta against
  the baseline) counts

Do the decisive test on a sample of the reported hits, not all of them:
a 20-sample differential run with a real HTML parser settles a
80-hit claim in under a minute.

## A REFLECTION THAT IS ONLY INERT ON THE SERVER IS NOT "SAFE"

The most common false negative: the server's own echo is escaped or
double-encoded, so a body-scanner finds nothing, and the hunt concludes
"no reflection". But a page can read `location.search` ITSELF and write it
into the DOM. The server is irrelevant to that path.

When a page loads a third-party form/analytics toolkit, READ the toolkit
before concluding anything. Eloqua landing pages were the concrete case:

- `elqQueryStringToFormField.js` copies ANY query parameter into the
  form field with the same name, then applies its own `decode()`. That
  decoder is lenient: it tests the FIRST hex digit with
  `parseInt(hex,16) < 8`, so `%3C` becomes a literal `<` and `%22` a
  literal `"`.
- `elqForm_*.js` `displayAllFields()` then does
  `document.getElementById("info").innerHTML = '...<b>' + $("[name=firstName]").val() + '</b>...'`

So the chain is URL -> `location.search` -> form field -> `innerHTML`.
The server's echo (in the tracking pixel) is double-encoded and inert,
which is exactly what a body-scanner sees.

**The gate to look for:** the sink branch is often conditional on a
second field being non-empty. Here it was a hidden merge field
(`emailAddressFieldMerge`) that the SAME fill script populates from the
query string. Passing the visible field name directly does not work —
the form's `clearFieldValues()` clears it before the merge field is
copied over it. When the sink does not fire, look for a hidden input
that gates it and check whether the fill script can reach that too.

**How to find the sink in a 50 KB minified form script:** grep for
`innerHTML *=` and look for a concatenation with a field variable, then
trace that variable's assignment. A `var fName = GetElqContentPersonalizationValue('C_FirstName')`
is a DEAD path if that function is not defined on the page — check
`typeof window.GetElqContentPersonalizationValue` before believing the
sink is reachable.

**Character reach must be measured, not assumed.** Send each dangerous
character separately and read the resulting `innerHTML`. `&` was the only
filtered one; `<`, `>`, `"`, `'`, `=`, `/`, space, `:`, `#`, backtick, `$`
and `{` all arrived raw.

## A PAYLOAD THAT REACHES THE DOM BUT DOES NOT FIRE IS STILL A FINDING

A payload can create a real element with a real event handler and still
not execute. Separate "reflected into the DOM" from "executed".

- `src=""` resolves to the page URL, which loads fine, so `onerror`
  NEVER fires. Use a non-resolving host: `src=//no.such.host.invalid/x`.
- Using `/` as the attribute separator instead of a space yields
  `src=""` plus a separate `onerror` attribute — the handler is present
  but inert.
- `=` inside the value is fine IF the value is percent-encoded as `%3d`
  in the URL, because the fill script's `split("=")` truncates a raw `=`.
  `%3d` survives the split and is decoded to `=` afterwards.
- `<svg onload=...>` inserted via `innerHTML` does NOT fire in Chromium:
  SVG markup in the HTML parser does not take the SVG load path.
  `<details open ontoggle=...>`, `<video src=x onerror=...>`,
  `<audio src=x onerror=...>` and `<marquee onstart=...>` DO fire.
- `<script>` inserted via `innerHTML` never executes (HTML spec).

**A same-origin `fetch()` from the injected handler is the strongest
proof of execution** and needs no network setup:
`fetch('/some-page').then(r=>r.text()).then(t=>document.title='LEN'+t.length)`
proves the injected code ran with the victim's origin privileges.

**Beware mixed content when using an out-of-band beacon.** An `http://`
beacon fired from an `https://` page is blocked before it leaves the
browser, so a negative beacon result proves nothing. Prefer an
in-page marker (`document.title`, a `data-` attribute on `document.body`)
and read it back from the same browser session.

**`Page.addScriptToEvaluateOnNewDocument` does not apply to a tab
opened with `new_tab()` afterwards.** The hook silently never lands, so
an alert hook reports "not fired" even for a working payload. Verify the
hook's presence (`typeof window.alert` / a flag you set) before trusting
its negative.

## A RATE-LIMITED ENDPOINT INVALIDATES A WHOLE VERIFICATION RUN

A checker endpoint that answers 429 after a handful of requests will turn
a verification run into a wall of false failures, because a 429 body does
not contain the expected string. Two rules follow:

- **Wait the limit out before each request, not after a failure.** A
  single shared sleep is not enough: the budget is consumed by every
  request in the run, including the ones you did not plan. Poll until a
  probe returns something other than 429, then send the real request.
- **Classify every non-200 as RATE-LIMITED / WAF / APPLICATION**, not as
  a failure. Only a body that actually carries the expected marker counts
  as a pass. A 429 is *untested*, and the report must say so.

A related trap: a check written as `expect_ok ? "marker" in body :
"marker" not in body` passes the NEGATIVE case on a 429 body, because the
429 body does not contain the marker. Such a check reports "the port is
unreachable" when the truth is "the request never ran". Assert on the
status class and the verdict string together, never on a bare negation.

**And separate the layers.** "Blocked" is not one thing. A WAF 403 with
an `X-Iinfo` header and an Imperva interstitial body is a different
defender from an application 200 that returns
`Error: ... is not a fully qualified public domain name`. Record which
layer answered, because the remediation differs: an application check can
be fixed in the application, a WAF rule is a mitigation that may be
reordered later.

**When re-verifying an old finding, re-run it live and diff the
behaviour.** A report written a day earlier can be wrong in a way that
looks like a new bug. In one real case the report claimed a URL-form
parameter was stopped by the WAF with a 403; live testing showed the
APPLICATION strips the scheme and rejects the result itself, and only the
metadata address is stopped by the WAF. The old claim was rewritten.

## WHEN YOU CONTROL THE REMOTE SERVER, THE HARNESS CAN LIE TO YOU

Testing a reflection by controlling the remote server's headers has two
traps that both produce a FALSE POSITIVE, and both look like a real
finding until you read the bytes.

1. **A default header can shadow yours.** Python's `http.server`
   `send_response()` emits `Server: BaseHTTP/0.6 Python/3.x` BEFORE the
   header you set. A client that reads the FIRST `Server` header
   therefore never sees your payload, and the reflected value you
   measure is the framework's, not the attacker's. Use
   `send_response_only()`, which adds no default header, so yours is the
   only one. Always assert that YOUR marker is present in the reflected
   value before drawing any conclusion from that value.

2. **A greedy regex will pick up the page's own markup.** Extracting with
   `re.search(r"Header:(.{0,80})", body, re.S)` runs past the closing
   `</p>` into the following HTML, and the angle brackets it finds belong
   to the page. Extract up to the closing tag: `r"Header:(.*?)</p>"`.

The correct measurement of a reflected value is four independent facts:
the payload does not appear VERBATIM in the body; no dangerous character
survives raw inside the extracted value; the dangerous characters are
present as entities; and a real HTML parser finds no raw dangerous
character in ANY text node and no attribute. Assert all four, and
assert that your own marker is in the value first.

**A payload with no special character is a control, not a test case.**
`Ctrl/1.0` has nothing to encode, so it will appear verbatim and there
will be no entity in the value. Asserting "the payload must not appear
verbatim" on it is a bug in the test, not a finding. Keep one control
case and skip the encoding assertions for it.

## A MISSING HEADER LOOKUP SILENTLY TURNS A PROOF INTO AN ABSENCE

`urllib`'s `HTTPError.headers` is an `email.Message`, and the exact
casing the server used is what `.items()` returns: `www-authenticate`,
not `WWW-Authenticate`. A plain `headers.get("WWW-Authenticate")` then
returns `""` and the check reads as "the server did not send it" -
which is a proof-shaped hole, not a cosmetic issue.

Same trap with redirects: `urllib` FOLLOWS a 302 by default, so the
recorded status is the status of the FINAL page, not the origin. A
host that answers `302 -> <SSO login>` and then `200` looks like a
healthy 200 if you let the client follow it, and the application
behind the gate is never actually reached. Record the origin's status
with a no-redirect opener.

Both mistakes point the same way: an ABSENCE that comes from the
client's own default behaviour, not from the server, is not evidence.
Assert on a field you fetched explicitly, and check that the field is
actually populated before treating it as an answer.

## A CHALLENGE PAGE ECHOES THE REQUEST URI, SO "MARKER IN BODY" IS NEVER A FINDING

A WAF interstitial (Cloudflare, Imperva, Akamai) echoes the request URI
into its OWN JavaScript state, because it has to hand the challenge back
to the browser:

```js
cUPMDTk:"/?q=MARKER%3C&__cf_chl_tk=..."
```

So the marker - and the percent-encoded form of your payload - will
ALWAYS appear in the body. A verifier that treats "the marker is in the
body" as a finding reports every WAF-gated host as a reflection.

The wire form, the decoded form, the entity form, and a raw dangerous
character in a PARSED context are four DIFFERENT facts:

| Fact | Meaning |
|---|---|
| `MARKER + "%3C"` in the body | the wire form - says nothing |
| `MARKER + "<"` in the body | the decoded form - a real raw `<` reached the body |
| `MARKER + "&lt;"` in the body | the entity form - correct output encoding |
| a raw `<` in a parsed TEXT NODE or ATTRIBUTE | a breakout - a finding |

Assert the fourth, not the first. And check whether the body carries the
challenge markers (`cf_chl_tk`, `cf_chl_opt`, `challenge-platform`,
`__cf_chl`, `X-Iinfo` + `visid_incap_*`) before believing any of them.

The same trap applies to a self-redirect: the `Location` header echoes
the request URI, and a WAF interstitial body echoes it in the HTML.

## A SINK IN THE PAGE'S OWN JAVASCRIPT CAN BE INVISIBLE TO EVERY SERVER-SIDE TEST

A value that the server never sees can still be attacker-controlled and
still reach a sink, because the BROWSER has it. The canonical case is a
request HEADER read at render time:

```js
document.write( '<p ...>Your browser: ' + navigator.userAgent + '</strong></p>' );
```

`navigator.userAgent` is the `User-Agent` REQUEST HEADER. The server
does not reflect it - the body is byte-identical for every UA - so a
body scanner reports nothing, and a "no reflection in the response"
conclusion is wrong.

The second source of client-side input the server never sees is the
FRAGMENT: `location.hash` is not sent to the server at all.

So when a page's own JavaScript is worth reading, look for BOTH kinds of
client-side source, not only `location.search`:

- `location.search`, `location.hash`, `location.href`
- `document.referrer`, `document.URL`
- `navigator.userAgent`, `navigator.language`, `navigator.platform`
- `window.name`, `document.cookie`, `localStorage`
- `postMessage` event data

And check the SINK side for the parser-level ones, because those need
different encodings than a text node:
`document.write`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
`jQuery .html()`, `eval`, `setTimeout(string)`.

**The delivery precondition is part of the severity.** A `User-Agent`
sink is real XSS with proven execution, but a victim clicking a link
sends THEIR OWN browser's UA, not the attacker's. To deliver it the
attacker needs a client that lets the user set a custom UA, or an
intermediary that rewrites the header. That is `AC:H` / `UI:R`, and on a
static page with no session it caps the finding at Low. The
`triage-validation` Pre-Severity Gate is where this belongs - do not
assume a proven execution means a proven impact.

- Verify every factual claim in a report by re-fetching it, not from
  memory. A re-verification script that fails loudly is worth writing.
- Distinguish "always disclosed" from "intermittent" — a Go transport
  error alternates between `connection refused` (IP present) and
  `context deadline exceeded` (IP absent). State which.
- If the finding is NOT an XSS, say so in the report body ("this is not
  an XSS because ..."). A bug bounty report that overclaims gets closed
  as informative.
- Do not write a report for a finding you could not verify.
