---
name: watch-hunt
description: "Turn Watch recon output into verified, reportable bug-bounty findings. Use whenever working from the Watch pipeline's findings on this server — triaging the Watch DB, reviewing nuclei/takeover/secret candidates, deciding whether a Watch hit is real, or hunting on any output under /opt/watch. Treats every Watch hit as an unverified SUSPICION, routes it to the right hunt-* skill, runs the live verification playbook that kills false positives (reflection, login-page matches, parked pages, public-by-design assets), and marks the DB status. Reads the Watch Finding collection DIRECTLY via its Python model (Hermes has server DB access; do NOT use the port-5000 API — there are no login credentials for it). Use before writing any report from Watch data."
---

# Watch Hunt — candidate → verified finding

Full manual: **`/opt/watch/HUNT_GUIDE.md`** — read it for the complete tool/skill/scope
reference. This SKILL is the operating loop; open the guide for depth.

## Core rule
Watch output is a list of **suspicions, not findings**. Most are false positives.
Never forward a candidate. Disprove the false ones; prove the real ones live; only then report.

## Access — DB directly, never the API
Hermes has server-side DB access and there are **no credentials for the port-5000 API**.
Always read/write findings through the Python model:

```bash
cd /opt/watch && ./.venv/bin/python - <<'PY'
from database.db import Finding
# open candidates for a program, worst first
for f in Finding.objects(program_name="dell", status="open").order_by("-severity","-first_seen"):
    print(f.severity, f.source, f.name, "|", f.target, "|", f.matched, "|", f.extra)
PY
```

`Finding` fields: `program_name, scope, target, source, name, severity, matched, extra, first_seen, last_seen, status`.
`source`: `nuclei | takeover | secret | content` — all LOW trust until verified.

Retire a candidate (never delete — mark status, reversible):
```bash
cd /opt/watch && ./.venv/bin/python - <<'PY'
from database.db import Finding
Finding.objects(target="https://HOST", name="TEMPLATE").update(set__status="false_positive")
PY
```
`status`: `open | triaged | false_positive | fixed`. Disproved → `false_positive`. Confirmed → `triaged`.

## The loop
1. Load `recon-scope-triage` on any fresh dataset; confirm ownership, not brand-name match.
2. Check scope: `cat /opt/watch/programs/<prog>.json` — in `scopes`, not in `ooscopes`.
3. Pull `status="open"` candidates (above), worst severity first.
4. Classify each and load the matching `hunt-*` skill:

   | signal | skill |
   |---|---|
   | `*ssrf*` | hunt-ssrf |
   | `*takeover*` | hunt-subdomain |
   | `*xss*` | hunt-xss / hunt-dom |
   | `*graphql*` | hunt-graphql |
   | `*idor*` | hunt-idor |
   | `*jira*`/`*actuator*`/`*airflow*`/config | hunt-api-misconfig / hunt-source-leak |
   | `secret` source | hunt-source-leak |
   | `*sqli*` | hunt-sqli |
   | redirect/cors/host-header/auth | hunt-open-redirect / hunt-cors / hunt-host-header / hunt-auth-bypass |

   Full list: `ls /root/skills-src/murrtada/skills/`.
5. Run the verification playbook (below). Disprove → `false_positive`. Prove → `triaged`.
6. Load `triage-validation` (7-question gate). Pass → report. Fail → discard.
7. Report with `evidence-hygiene` + `bugcrowd-reporting` + `report-writing`.

## Verification playbooks (kill false positives)
- **Search what already paid on the program BEFORE building a bigger sweep.** Two accepted Indeed XSS
  bugs sat on `www.indeed.com/hire/employer-confirmation?co=&hl=` ($800, 2022) and
  `/career-advice/` — paths already in the corpus that a giant parameter sweep had walked past. A
  disclosed-bug replay is the highest-yield hour on any mature program, and it corrects wrong
  assumptions (an id-looking `co` dismissed as a parsing artifact was the real XSS parameter).
- **A clean request blocked on the same path means payload mutation cannot help.** Send the URL with:
  NO parameters first. If `/career-advice/` alone is 403, the rule is path-based and no encoding trick
  passes — 32 payload variants, origin-IP, client-fingerprint and 20-locale variants all failed so.
- **Double encoding is the whole answer, and only raw bytes show it.** 1,167 of 7,200 payload tests
  "reflected" a marker; every one was `%2522`/`%253C` inside a JSON `continue=` value. Print the raw
  byte slice around the marker before classifying, or encoded and double-encoded look identical.
- **A search box that renders results is not a sink.** Driving docs.digicert.com's search with real
  keyboard events gave 19 results and ZERO DOM insertion of the typed value — results came from a
  prebuilt index. Prove the input reaches a sink via a hook, don't assume echoed output.
- **A browser DOM-XSS negative is void unless the page actually loaded.** 114 of 140 in-scope
  DigiCert hosts showed Chromium's "Privacy error" interstitial — 1 script, 318 bytes — and never
  ran the app. Check `document.title` for "Privacy error" / count `document.scripts` before calling a
  host tested. Same class as the `openssl Verify return code` trap.
- **Install the alert hook at document-start, then PROVE it fires.** Overriding `window.alert` after
  load captures `None`; use `Page.addScriptToEvaluateOnNewDocument` and confirm a control page's
  `<script>alert(888)</script>` lands in the array before trusting any `[]`.
- **Hook the sinks too, not just `alert`.** Wrap `Element.prototype.innerHTML`, `document.write` and
  `insertAdjacentHTML` at document-start and record values containing the canary: that catches
  "reached the DOM but did not fire" and distinguishes it from "never reached the DOM".
- **A reflected URL inside `<script>location.href = '...'</script>` is only a finding if the quote
  survives.** `forms.indeedflex.com/platform/auth` interpolates the whole request URL into a
  single-quoted JS literal — but the quote arrives as `%2527` (double-encoded), so the literal never
  closes. Test the breakout chars individually (`'`, `"`, `\`, `</script>`) and compare the raw bytes.
- **Marketo `forms2.min.js` copies ANY query param into a hidden field**
  (`InputSourceChannel:"url"` → `parse(location.search)[selector]`). That is by design and only
  matters if the hidden value later reaches an HTML sink — check the landing page's own form render
  path before calling it XSS.
- **Cloudflare `managed` challenge pages are the single biggest reflection trap on big scopes.**
  10,134 of 35,337 Indeed targets "reflected" — 2,242 of them were 403 challenge pages echoing the
  URL in `cUPMDTk` (`cType:'managed'`). Bucket by status FIRST and treat non-200 as infrastructure.
- **Dedupe JS by content before a DOM sweep.** 21,515 crawl-discovered JS URLs on a 60-country
  scope collapse to 35 distinct artifacts; most of the list is `cdn-cgi/challenge-platform` plus
  per-country mirrors of the same chunk. Basename+sha256 dedupe turns an impossible pass into a
  15-minute one.
- **A backward slicer must be indexed, not re-scanned.** Resolving each sink-argument identifier by re-scanning the whole file is quadratic: on a 1.9 MB bundle it died at 50/1,168 files, then again at 95 flows. Build one assignment index (`ident -> [RHS...]`) in a single pass and walk that. Cap per-file size and sink matches so the pass COMPLETES — a scan that dies at 4% yields a coverage number, never a finding.
- **A minified bundle turns a slicer into a false-positive machine.** On a 7.8 MB
  `main.js`, every `innerHTML` flow traced to `location.search`/`postMessage` was ag-Grid
  internals (`t.innerHTML=e` where `e` is a cell param) — the identifier `e` was matched to an
  unrelated `e` elsewhere in the bundle. Always open the sink line and name the value by hand
  before reporting a DOM flow. Filter `clientlib|jquery|granite|ag-grid|react|angular|swagger-ui`
  out of the file list and cap bundle size, or the pass never finishes.
- **Reject-list is not a reflects-then-encodes bug — map characters to prove which.**
  `partners.digicert.com` echoed a param into `<form action="./?p=VALUE">`; a per-character
  map showed only plain and paren survive, and `<`/`>`/`"`/`'`/`&`/`=`/space/newline all flip
  the response to `/English/error.aspx`. Report that as blocked, not as safe.
- **Imperva/Cloudflare interstitials masquerade as app output.** A 404 body carrying a
  random-named script (`/Scena-Quing-.../`) is a WAF page; a 403 that appears only when the
  payload is present is the WAF, and the page is untested — not clean.
- **IDOR without accounts = auth posture, not IDOR.** Test only IDs already in the corpus (never a
  sequential sweep) with three fetches: recorded URL, differential control (bogus value in every
  id-ish param), and a nonexistent path on the same host. `401/401/404` means the ID is rejected
  before lookup; `403/403/403` where the control is 401 means a WAF answered, not the app. On this
  corpus every one of 14 query-ID targets, 97 `/api` hosts and 272 admin-path hosts was closed —
  ServiceNow table API 401, Artifactory 401, DigiCert daas 401, `admin.labplatform.dell.com`
  blanket-403. `{"TotalAvailable":0.00}` / `[]` is an anonymous session's empty state, not a leak.
- **CORS: reflection is not the bug, reachable data is.** `Origin: null` echoed with
  `ACAC: true` on 147 hosts looked critical; every path (including a bogus one) returned an
  identical 3,582-byte SPA login shell with a 401. Group results by (host, body_len) — one
  length across all paths = shell, not API. Confirm with 200 + `content-type: json` + body
  starting `{`/`[`. `ACAC: none` makes a credentialed cross-origin read impossible no matter
  how the origin is reflected.
- **Format-assert on config-file sweeps, never keyword-match.** Across 4,456 hosts, none of the
  `/.env`, `/.git/config`, `/.git/HEAD`, `/.svn/entries`, `/server-status`, `/phpinfo.php`
  200s were real. Require structure (`[core]` + `repositoryformatversion`; 40-hex SHA under
  120 bytes; ≥2 `KEY=VALUE` lines plus a secret-shaped key name) and fetch a random control
  path per host to discard catch-all servers.
- **takeover / `microsoft-azure-error`**: a 404 page is NOT a takeover. `dig CNAME`, `dig A`,
  `dig TXT asuid.HOST`. Claimable only if a CNAME points to a dead `*.azurewebsites.net` name
  (NXDOMAIN) with no `asuid` TXT. Bare A to a shared cloud IP, or asuid present = NOT claimable = discard.
  Real PoC = register the resource, serve a unique token on the victim host, then remove it.
- **bulk dnsx resolve is lossy — never trust one pass.** Measured on 2,626 targets: dnsx called
  361 dead, of which **274 resolved fine to individual `dig`** (76% over-report). Re-resolve every
  supposedly-dead target with `dig` against the system resolver + 1.1.1.1 + 8.8.8.8 before calling
  anything dangling, and run the CNAME sweep itself twice (7,927 vs 7,806 hosts on the same input).
- **a dead vendor namespace needs a control from the same namespace.** `*.indeed.tech` had 2,906
  non-resolving targets, but 69 of 87 distinct names in that namespace resolved — so non-resolution
  was the exception, not the rule. Pull real names for the control from crt.sh; an invented name
  proves nothing. Classes where NO name resolves (blackhole) are not evidence at all.
- **WAF blanket-403 masquerades as a hit.** One host returned an identical Cloudflare 403 for
  `/xmlrpc.php`, `/actuator/env`, `/elmah.axd` AND for `/` and a random path. Always request
  `/zq-nonexistent-<rand>` first; if it 403s, the host is blocked (untested, not clean).
- **soft-404 path echo masquerades as a hit.** A Spring host answered
  `{"detail":"No static resource xmlrpc.php.","instance":"/xmlrpc.php"}` — body length differs from
  the control by 2 bytes, so status+length is not a discriminator. Require a service-owned protocol
  marker (WP cookie/`X-Powered-By`, `methodResponse`, `jsonapi`, `FormDigest`, actuator JSON) that
  the control does not carry, **and only accept it on a 2xx** — a 301/404 body that repeats the path,
  and an object store's `<Error><Resource>/xmlrpc.php</Resource></Error>`, both match a naive substring.
  Self-test the fingerprint against the known FP hosts before the sweep, then confirm survivors with a
  real protocol call (`system.listMethods` for XMLRPC, not a GET).
- **`*.google.com` is not your canary** and `og:url`/`canonical` echoing the request is not a
  redirect. Compare the exact hostname and require `location=`/`refresh`/`window.open` semantics.
- **ssrf**: body echoing your payload URL (`computeMetadata`, `iam/security-credentials` once) = reflection FP.
  Real = response-only content never in your request: `AccessKeyId`, `SecretAccessKey`, `ami-id`,
  `instance-id`, or header `Metadata-Flavor: Google`. Blind → `interactsh-client` OOB or it is unconfirmed.
- **airflow/jira/actuator config**: require `Content-Type: application/json`. `text/html` = login/SPA page,
  the "password"/"version" word match is a FP. Airflow real = JSON `total_entries`/`sections`; Jira real = JSON `version`/`baseUrl`/`accountId`.
- **graphql**: re-send introspection; need `__schema`+`queryType` in a JSON body with no `errors`. 405/HTML = discard.
- **xss**: full payload must return unencoded as one block (`"><script>alert(1)</script>`). Entity-encoded or bare `alert(1)` = FP. Confirm with `dalfox`.
- **secret**: `AIza...` google key in client JS = public by design, only matters if unrestricted. Hex blob in `main.js` = build hash = FP.

## Discard on sight
Matcher word that is a substring of the payload (reflection) · 200 + generic word on `text/html` ·
parked/"site not found" with no claimable resource · public-by-design (published images, client keys, open CDNs) ·
static-matcher "IDOR" (needs two-account manual test) · anything that does not reproduce on a second manual request.

## Severity realism
public-by-design → Informational/N/A · non-claimable dangling DNS → P4/P5 · namespace/cert governance → P4 ·
confirmed metadata-SSRF with creds → P1/P2. A precise P4 beats an inflated Medium closed as N/A.
State honestly what is NOT claimed.

## Guardrails
Authorized scope only; never touch `ooscopes`. Read-only by default — no write/push/delete/upload
against a target unless the program allows it. No DoS/mass exploitation. Lightest-possible PoC; remove
anything you created. Pace requests. Mask PII in evidence.

## Authenticated testing — vault origin binding
When testing authenticated surfaces (IDOR, stored XSS, admin panels), credentials are stored via
`hermes vault add` (CLI — there is no UI settings panel; the vault is CLI-only on this host).
The vault fills ONLY on the exact origin the credential was saved for. Two pitfalls:
- **Origin mismatch**: if you navigate to a different origin (even a redirect target like an IdP),
  `browser_vault_fill` refuses with `origin_mismatch`. Save the credential on the origin where the
  login form actually renders, not where you started.
- **Blocked bound origin — verify with a FULL browser UA first.** A 403 from a short/default
  UA (curl's default, browser-use's default) is NOT proof of an IP ban. Akamai/WAF bot-detection
  returns 403 to non-browser User-Agents while the same origin answers 200/302 to a full Chrome
  UA from the SAME IP (confirmed on `www.dell.com`: default UA → 403, full Chrome UA → 302).
  Before declaring an origin blocked, test with:
  `curl -sI -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' -o /dev/null -w '%{http_code}' <origin>`
  Only if the full-UA request also 403s is the origin truly unreachable. The browser-use tool's
  default UA is bot-detected by Akamai — use a full Chrome UA or fall back to curl/requests.
- **No UI**: `hermes vault list` / `hermes vault add` are the only interfaces; do not look for a
  settings panel.
