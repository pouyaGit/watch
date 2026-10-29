# Parameter surface inventory — beyond the crawl

The static JS pass answers "what does the code do with a value". It does not
answer "which parameters exist", and the crawl does not answer it either.
This file is the second channel plus the browser layer that a static pass
cannot reach at all.

## The crawl is not the inventory

Crawl-derived parameters are a LOWER BOUND. The `x8` output stored per endpoint
(`param_records`, or a flat `x8` run) is a separate channel that parses
JavaScript and recovers parameters the crawler never turned into a URL. One
scope held **110,696 (endpoint, param) pairs** in `param_records` against **109
distinct names** from a 10.5M-URL crawl — a different order of magnitude, and
not a superset.

So when a crawl-derived sweep returns zero, mine the x8 channel before writing
"no surface".

## Read the records, not the counts

Two artifact classes inflate any `param_records` total. Identify them before
they drive a sweep:

- **Records whose `example_url` has no query string.** Every `/help/*` page on
  one host carried a `co` record; 27,522 of the 110,696 pairs were this one
  artifact, produced by a parser, not by a discoverer.
- **x8's own probe list.** `p4ssw0rD`, `test`, `debug`, `admin`, `sso`, `show`,
  `waf`, `captcha`, `env`, `encryption`, `disable`, `bot` come from
  `--custom-parameters` defaults — they appear on EVERY scanned host, so a
  parameter that shows up everywhere is evidence about the tool, not the
target. Drop them before ranking by frequency.

What is left is worth testing, and the interesting entries are the ones the
crawl did not have: a keyword parameter present in x8 and absent from the crawl
is a genuine coverage gap. Rank the remainder by frequency, then test the top
names on routes you have already confirmed render.

## The browser layer is not optional for DOM XSS

A static slicer reads what the code COULD do. A browser reads what it DOES.
`location.hash` never reaches the server, so no static-only or HTTP-only pass
can decide a hash sink.

Protocol, in order:

1. **Hook at document-start**, not after load: `Page.addScriptToEvaluateOnNewDocument`.
   An `alert` override installed after load captures nothing and reports
   `None` for a payload that really fired.
2. **Prove the harness fires** on a control page (`<script>alert(888)</script>`
   → `["888"]`) before reading any `[]` as a negative.
3. **Hook the sinks too** — `Element.prototype.innerHTML`, `document.write`,
   `insertAdjacentHTML` — recording values that contain the canary. This
   separates "reached the DOM but did not fire" from "never reached the DOM",
   and catches attribute-only landings.
4. **Confirm the page actually loaded.** A certificate interstitial is one
   script and ~300 bytes; an SSO gate has zero body text. Both run none of the
   app. Check `document.title` and `document.scripts.length` per host and mark
   unloadable hosts `untested`, not `clean`.
5. **Record where the value landed**, not just that it appeared. An `<a href>`
   attribute holding a percent-encoded payload is inert; a live text node is
   not. Walk text nodes and element attributes and report the exact container.

## When the cert blocks the browser, measure it from the shell

`Security.setIgnoreCertificateErrors` does not reliably persist across
navigations, so a re-test that relied on it can come back still-blocked and get
misread as "host is dead". Measure the certificate directly instead:

```bash
openssl s_client -connect HOST:443 -servername HOST </dev/null 2>/dev/null \
  | grep -E "^(Verify return code|subject=|issuer=)"
```

`0` means a victim loads the page silently. `19` (self-signed in chain), `10`
(expired), `20` (unknown issuer) each put a full-page interstitial in front of
the victim — which caps the impact at `C:N/I:N/A:N` even if execution is proven,
and makes "untested" the correct verdict rather than "clean". A host that
resolves in `getaddrinfo` but still fails to navigate is a different fault from
an unresolvable one; say which.

## Stored XSS needs a write surface — measure it first

Before promising an authenticated hunt, count the inputs: `input[type=password]`,
`input[type=text]`, and whether the page copy says signup. A password field
alone is a login form, not registration. A scope where login, registration and
the main search page all return a bot-block page has **no reachable write
surface**, so stored XSS is not "clean" there — it is unassessable, and that is
the sentence the report needs.
