# Watch hunt — session report

Date: 2026-10-26
Engagement type: **bug bounty** (HackerOne: Dell, Indeed, DigiCert, Wien)
Scope checked against `/opt/watch/programs/*.json` before any request; `ooscopes`
(`partner.digicert.com`, `educate.dell.com`, `console.dell.com`,
`console-test.dell.com`, `salesproductivity.dell.com`) were never touched.

## Result

**No reportable finding this session.** Coverage: 10 non-redirect candidates
disproved with live evidence; 111 redirect parameters tested; 69 reflection
probes; 62,314 subdomains swept for dangling CNAMEs in two passes; 4,456 live
hosts probed for legacy auth surfaces; 4,456 live hosts probed for CORS
reflection across 12 API paths each; 4,456 live hosts probed for exposed VCS/env
files across 6 paths; IDOR auth posture on 14 query-ID targets, 97 `/api` hosts
and 272 admin/user-path hosts (unauthenticated, no enumeration); full XSS hunts
on DigiCert (1.29M URLs / 1,168 JS files) and Indeed (10.48M URLs / 21,515 JS
URLs) with 0 raw reflections.

What the hunt *did* produce is five false-positive traps that would have become
bad reports, each documented with the control that killed it — the lossy bulk
DNS pass (76% over-reported dead), the WAF blanket-403, the soft-404 path echo,
the `*.google.com` canary, and the `og:url` echo.

## Category 1 — GraphQL introspection (8 findings: 5 DigiCert, 3 Indeed)

Re-verified per HUNT_GUIDE §5d with my own introspection query.

| Target | Verdict |
|---|---|
| `vercara/cart/knowledge/mcprod/constellix.digicert.com` GraphQL | Magento 2 storefront GraphQL. Introspection unauthenticated is framework default. `customer`, `customerCart`, `customerOrders` all return `graphql-authorization` errors unauthenticated; only `storeConfig` answers (public `base_url` + `currency`). |
| `compliance.indeed.com/graphql` | Schema is a single `Hello` field. Nothing to expose. |
| `cocos-api.indeed.com/graphql` | Survey/question surface (`getQuestions`, `submitMicroanswerQna`). No PII query reachable unauthenticated. |
| `reportcontent.indeed.com/graphql` | Apollo Federation `_service`/`_entities` + `contentReport` mutation. No cross-tenant read demonstrated. |

Introspection alone is informational; no data-exposure PoC was reachable, so
these are **not** reportable. DB: `false_positive` with the reasoning stored in
`extra.verified`.

## Category 2 — Google API key (1 finding: Indeed)

`AIza…` found in `images.jm.indeed.com/index_files/analytics.js`. The key is
valid — it resolves to a live GCP project (`655407646403`) rather than
"API key not valid". But every API probed is disabled on that project:

- YouTube Data v3 — not used/disabled
- Custom Search — not used/disabled
- Cloud Translation — not used/disabled
- Geocode / StaticMap / Timezone / Places — not activated

No billable capability, no data access. Public-by-design client key →
**not reportable**. DB: `false_positive`.

## Category 3 — Subdomain takeover (2 findings: Dell)

Both Azure "404 Web Site not found" pages. A 404 page is not a takeover — the
question is whether the domain can be claimed.

`selectortool.dell.com`:

```
$ dig +short selectortool.dell.com A
20.105.216.36
$ dig +short selectortool.dell.com CNAME
(empty)
$ dig +short TXT asuid.selectortool.dell.com
"9554513C101455663525D6007F91F342CB44967BBBB8539AB8D902EF4497E38A"
```

`csgincentives.dell.com` (surfaced by the nuclei lane mid-session):

```
$ dig +short csgincentives.dell.com A
52.187.36.104
$ dig +short csgincentives.dell.com CNAME
(empty)
$ dig +short TXT asuid.csgincentives.dell.com
"C31E52A752D7807DFACE932BDF097392A7B8D100944225C5CD9C65AE406CA5C8"
$ curl -s https://csgincentives.dell.com/ | grep -o '<title>.*</title>'
<title>Microsoft Azure Web App - Error 404</title>
```

In both cases: A-record only, no dangling CNAME, and an `asuid` TXT binds the
domain to a live Azure App Service subscription. The app behind the binding may
be gone (hence the Azure 404), but the domain binding is still Dell's, so the
resource cannot be registered by an attacker → **not claimable** (HUNT_GUIDE
§5a). No registration attempt was made. DB: `false_positive`.

## Category 4 — Redirect parameters (111 candidates: 86 Dell, 22 Indeed, 3 DigiCert)

Method: untouched archived URL vs the same URL with every redirect-style
parameter rewritten to `https://google.com`. One GET, no follow. A hit requires
the canary run to land on the **exact host** `google.com` while the baseline does
not.

| verdict | count | meaning |
|---|---|---|
| blocked | 34 | 403/404 from an edge filter on both requests — untested, not clean |
| other | 61 | see below |
| validated-rejected | 7 | parameter consumed, external value refused |
| no-redirect | 5 | no redirect with either value |
| unreachable | 3 | dead host / TLS |
| redirect-changed-host | 1 | DigiCert IdP fell back to its own login page |
| **open-redirect** | **0** | — |

The 61 "other" are endpoints that reflect the value into a **relative**
`Location` (`/user/login/?next=https://google.com`, `/auth?from=…`). Following
the full chain with hostname comparison shows all of them terminate back on the
same site:

```
secure.indeed.com    -> secure.indeed.com    NOT an open redirect
adh.indeed.com       -> id.indeed.tech       NOT an open redirect
feedbackcentral.dell.com -> feedbackcentral.dell.com  NOT (value only in the path)
powercalculator.dell.com -> www.dell.com     NOT (stops at the Dell IdP, 403)
```

Note: these are stored-XSS/HTML-injection hunting surface (the value is echoed
into a redirect URL), not open redirects.

## Category 5 — Reflection / XSS probe on the echo endpoints (69 params)

The 61 "other" + 8 rejected candidates were probed for reflection per
`hunt-xss` (unique random token, token built so it survives escaping
contiguously, one request per context character, plus a no-token control
request to prove the token is not already in the page).

**11 of 69 parameters echo the supplied value.** All 11 echo it into the
`Location` response header, never into an HTML body:

| endpoint | param | behaviour |
|---|---|---|
| `adh.indeed.com/user/login` | `next` | `301 → /user/login/?next=<tok>` |
| `secure.indeed.com/account/login` | `from` | `302 → /auth?from=<tok>` |
| `secure.indeed.com/account/login` | `service` | `302 → /auth?service=<tok>` |
| `feedbackcentral.dell.com/login.html` | `ref` | `302 → /welcome/err/…/?ref=<tok>` |
| `link.indeed.tech/_/login` | `url` | `302 → id.indeed.tech/oauth2/…` |
| `partners.digicert.com/auth/saml2/idp/sso.ashx` | `RelayState` | `302 → error.aspx` |
| + 5 Cloudstore Keycloak / Dell IdP `redirect_uri` | | header only |

A `Location` value is consumed by the browser as a URL, so HTML entities and
angle brackets in it are inert — this is **not** XSS. Encoding was verified
character by character:

```
next=zqaaa111<        -> Location: ...next=zqaaa111%3C
next=zqaaa111"        -> Location: ...next=zqaaa111%22
next=zqaaa111 x       -> Location: ...next=zqaaa111%20x
next=%0d%0aX:y        -> Location: ...next=zqaaa111%250d%250aX%3Ay   (no CRLF)
next=//example.org/x  -> Location: /user/login/?next=%2F%2Fexample.org%2Fx  (stays in the param; not protocol-relative)
```

No response-splitting, no protocol-relative escape, no raw angle bracket
reaching a body. **No XSS.**

The 403s seen while chain-following were payload-triggered, not IP blocking —
verified with a control request per case:

```
?next=/page/browse-metric/x             301
?next=abc123"><svg/onload=alert(1)>     403
?next=zqtest1234<svg>                   301
?next=zqtest1234<svg/onload=alert(1)>   403
?next=javascript:alert(1)               403
```

So the edge rejects the strings `onload=`/`javascript:` and allows bare `<`,
`>`, `"`, `'`. Either way the value lands in a header, so the WAF is not what
is saving them — correct output encoding is.

## Category 6 — Subdomain takeover sweep (62,314 subdomains, two passes)

Full CNAME sweep over every subdomain in the Watch DB, following
`hunt-subdomain`: ~1,000-host chunks, ANSI stripped, parser self-check
(raw==parsed, or abort), **two passes unioned**, then a plain substring class
check over every CNAME target rather than only a provider table.

```
pass1  7,927 hosts with a CNAME   (644s)
pass2  7,806 hosts with a CNAME   (681s)   <- nondeterministic, as the skill warns
union  9,270 hosts with a CNAME
        2,626 distinct CNAME targets
```

The dnsx bulk resolve reported **361** targets as dead. Re-resolving each one
individually with `dig` against the system resolver + 1.1.1.1 + 8.8.8.8:

```
274 / 361 targets that dnsx called dead DO resolve
 87 genuinely non-resolving targets remain  (219 subdomains)
```

So the bulk pass over-reported dead by **76%** — it would have produced 361 bogus
dangling records. This is the same lossy-bulk failure the skill documents, and
the reason no count from a single dnsx pass is trustworthy here.

### The 87 remaining, by class

| class | count | claimable? |
|---|---|---|
| `*.elb.us-east-2.amazonaws.com` (EKS/ALB) | 94 | **no** — name embeds an AWS-assigned hash, vendor-provisioned, not self-service |
| `*.elb.*.amazonaws.com` (other regions) | 47 | **no** — same |
| internal `*.us.dell.com` (osb/dit hosts) | 13 | **no** — internal DNS only |
| `*.websecurity.symauth.net` / `*.ws.symauth.net` | 9 | **no** — Symantec/Entrust contract-provisioned tenant |
| `*.corpit.indeed.net`, `*.ins.dell.com` | 6 | **no** — internal |
| `*.adobecqms.net` | 5 | **no** — Adobe contract-provisioned |

**No self-service provider class appears at all** — zero dangling
`herokudns`, `github.io`, `azurewebsites.net`, `cloudapp.azure.com`, `s3`,
`netlify`, `vercel`, `zendesk`. All 219 affected subdomains fail DNS resolution
entirely (connection refused on both schemes), consistent with dead internal
hosts rather than hijackable third-party slots.

The `cloudapp.azure.com` class — the one with a documented 1-click ATO chain —
was checked specifically: **13 records, 0 dangling.** All 10 that dnsx first
reported dead (`dellcmg01`, `cms-iop`, `prod-irisanalytics`, `mimsy-appgw`, …)
resolve fine to live Azure IPs on individual re-resolution.

**No takeover.**

## Category 7 — Legacy-protocol auth surfaces (4,456 live hosts, complete)

Probed the `hunt-auth-bypass` Legacy-Protocol Matrix on **every** host in the
`Http` collection (4,456, not a subset): WordPress `/wp-login.php`,
`/wp-json/wp/v2/users`, `/xmlrpc.php`, Drupal `/jsonapi/`, Jira
`/rest/api/2/serverInfo`, Spring `/actuator/{health,env}`, SharePoint
`/_api/contextinfo`.

Three false-positive traps fired in sequence and each had to be fixed before the
numbers meant anything:

1. **WAF blanket-403.** `alma.indeed.com` returns an identical Cloudflare 403 for
   `/xmlrpc.php`, `/_api/contextinfo`, `/elmah.axd`, `/trace.axd` *and* for `/`
   and a random nonexistent path. 153 such "hits" were pure WAF noise.
2. **Soft-404 path echo.** `hiringevent.indeed.com` answers
   `{"detail":"No static resource xmlrpc.php.","instance":"/xmlrpc.php"}` — the
   body echoes the requested path, so status+length differ from the control by
   2 bytes and every host looks like it runs XMLRPC. 190 such "hits".
3. **3xx body echo + S3 XML error pages.** `info.wien.at` 301s any path and puts
   the path in the body; `file.vast.dell.com` is an object store that returns
   `<Error><Code>ServerError</Code>…<Resource>/xmlrpc.php</Resource></Error>` for
   a missing key on *any* path. Both matched a body substring.

Final design: a per-host control request to a random path, and a marker only
counts on a **2xx** response (headers/cookies or a JSON schema the control does
not carry). The fingerprint was self-tested against the known false-positive
hosts before the run: `info.wien.at/xmlrpc.php` → `[]`,
`hiringevent.indeed.com/xmlrpc.php` → `[]`,
`api-credentials.dell.com/actuator/health` → `['actuator']`.

**Result: 7 hits, of which 1 survived manual verification.**

```
GET https://api-credentials.dell.com/actuator/health
200 application/vnd.spring-boot.actuator.v3+json
{"status":"UP","groups":["liveness","readiness"]}

GET https://api-credentials.dell.com/actuator
200 {"_links":{"self":…,"health":{"href":…}}}
```

Only `health` and the index are exposed; `/actuator/env`, `/info`, `/metrics`,
`/beans`, `/configprops`, `/loggers`, `/mappings`, `/threaddump`, `/heapdump`
all return `500 No static resource`. No environment, no credentials, no config.
**Informational only — not reportable.**

The 6 XMLRPC hits were all disproved with a real `system.listMethods` POST:

| host | GET | POST | verdict |
|---|---|---|---|
| `billing.indeed.com` | 200 text/html (Next.js app) | 405 Method Not Allowed | not XMLRPC |
| `db.indeed.tech` | 200 text/html (Next.js) | 405 | not XMLRPC |
| `db.qa.indeed.tech` | 200 text/html (Next.js) | 405 | not XMLRPC |
| `file.boss.dell.com` | 200 `application/xml` `<Error>…The specified key does not exist` | same | object store, not XMLRPC |
| `file.testvault.dell.com` | same | same | object store |
| `file.vast.dell.com` | same | same | object store |

### Blocked, not clean

**1,480 of the 4,456 hosts answered every path — including the random control —
with an identical 403/429/503.** Those are WAF-blocked from this IP and are
**untested, not clean** (33%). No WordPress, Drupal, Jira, SharePoint or
credential-bearing actuator instance was reachable unauthenticated on the
remaining hosts. No credential guessing or brute force was attempted anywhere.

The 233 `redirect-param` rows that existed in the Finding collection at session
start were **deleted by the operator on purpose** ("خودم پاک کردم، نویز بودن")
— not by anything I ran, and not a fault in the pipeline. An earlier draft of
this report said they "vanished"; that was wrong and is corrected here.

The 111 candidates used above were rebuilt from `Urls` (86 Dell / 22 Indeed /
3 DigiCert) because the Finding rows were gone:

- `logs/bb4/watch_redirect_candidates.json` (111 candidates)
- `logs/bb4/watch_redirect_confirmed.json` (baseline vs canary per endpoint)
- `logs/bb4/watch_xss_probe.json` / `watch_xss_chain.log` (reflection probe)

## Category 8 — CORS reflection (4,456 hosts × 12 API paths)

Swept every live host with `Origin: https://zq-cors-canary.example` on `/`,
`/api`, `/api/v1/`, `/api/v1/me`, `/api/user`, `/api/session`, `/api/account`,
`/api/graphql`, `/graphql`, `/api/v2/`.

**1,776 origin-reflecting responses on 167 hosts; 1,663 with `ACAC: true`.**
The reflection is **universal** — every Origin is echoed, including the literal
string `null` (147 hosts), which needs no attacker-controlled domain at all:
`cstool-g4.us.dell.com`, `rdoc.us.dell.com`, `digatewaystg.dell.com`,
`3plportal.dell.com`, `aiops.dell.com`, `bugs.indeed.com`, and 141 more.
The negative control (request with **no** `Origin` header) returns no ACAO on
all of them, so this is true reflection, not a static header.

**It is still not reportable, and here is the evidence.** Reflecting an origin
is only a bug if a cross-origin reader gets *data* it could not otherwise have:

- **The bodies are app shells, not API responses.** `cstool-g4`,
  `rdoc.us.dell.com`, `central-di.dell.com` and the other `DI Gateway` hosts
  return the *identical* 3,582-byte HTML login page for every path — including
  a bogus `/totally-bogus-xyz`. `api-credentials.dell.com` returns a 746-byte
  "Developer App Credentials" shell. `trackit.dell.com` returns a 2,135-byte
  React index. `dfsm-api` / `rpe.us.dell.com` return IIS 404 pages.
- **Status codes carry no payload:** 822 of 1,776 responses are 302, 698 are
  401, 172 are 404. Adding a bogus cookie or a bogus `Authorization: Bearer`
  changes nothing (still 401, same length).
- **Only 2 responses returned real JSON** — `sdk.indeed.com/api/` and `/api/v1/`
  (64 KB). Both send `ACAC: none` (so a credentialed cross-origin read is
  impossible) and describe themselves as `"authStatus": "ANONYMOUS"`. Scanning
  the 64 KB payload found no email, no AWS/Google key, no JWT, no private key;
  the only credential-shaped value is `"publicApiKey"`, which by name and by
  context is shipped to every visitor of the public site.

So: a real, universal, credentialed CORS reflection over 147 hosts with **no
reachable data behind it**. If any of those hosts later exposes an
authenticated JSON endpoint, this becomes a live finding — that is the thing to
watch, and `logs/bb4/cors_null_reflect_hosts.txt` lists them.

## Category 9 — Exposed VCS / env / config files (4,456 hosts × 6 paths)

`/.env`, `/.git/config`, `/.git/HEAD`, `/.svn/entries`, `/server-status`,
`/phpinfo.php` on every live host, with a random 14-char control path fetched
per host. **0 validated hits**, 287 hosts unreachable, 4,169 clean.

Every 200 was rejected by a *format* assertion rather than a keyword match, and
by the catch-all guard (200 on the random path with a similar length ⇒ discard
that host): `/.env` needed ≥2 `KEY=VALUE` lines **and** a secret-shaped key
name; `/.git/config` needed `[core]` + `repositoryformatversion`; `/.git/HEAD`
needed a 40-hex SHA or `ref: refs/` in under 120 bytes; `/server-status` needed
the literal Apache banner; `/phpinfo.php` needed `PHP Version` + `php.ini`.

Adjacent surfaces checked and found closed: the Cloudsmith-hosted registries
(`npm.artifacts.indeed.tech`, `docker.artifacts.indeed.tech`,
`npm.cloudsmith.indeed.tech`) answer `{"ok": false, "error": "Repository does
not exist, or is not visible."}` for repository enumeration and
`401 {"errors":[{"code":"UNAUTHORIZED"}]}` on `/v2/_catalog`.

## Category 10 — IDOR / broken access control (unauthenticated posture)

Two accounts do not exist for these programs, so the decidable question per
`hunt-idor` is the **auth posture**: does an ID-shaped endpoint serve record
data to a caller with no session? Only IDs already recorded in the corpus were
used — **no sequential enumeration**.

**10a. Query-parameter IDs — 14 targets, 0 open.** From the 54,515 endpoints
with crawl parameters, 95 carried an ID-shaped name; after removing Keycloak
login URLs (`client_id=oss`), image-CDN links and non-IDs, 14 real targets
remained (DigiCert `daas` `accountId`/`divisionId`/`sensorId`/`surveyDefId`,
Dell `trackit` `userId`, IdP `authorize` endpoints). Each got three fetches —
recorded URL, differential control (`zq999999999999` substituted into every
id-ish value), and a nonexistent path on the same host:

- `daas.digicert.com` ×4 → `401/401/404`, zero-length body on both the recorded
  request and the differential control, so the ID is rejected before lookup.
- `trackit.dell.com/.../redirecturl?userId=` → `403/403/403`; control is 401,
  so a WAF answers before the application sees the ID.
- Dell `www.dell.com/di/v3/fp/{saml,oidc}/*` → `403` on all three fetches.
- `id.indeed.tech` / `myaccess.dell.com` `oauth2/.../authorize` → `200` but
  44,232 / 41,934 bytes of Okta login HTML, no record data; the differential
  control returns 400 with a 2,313-byte error page.

**10b. Path-segment IDs.** The `Endpoints` corpus stores normalized paths, so
literal `/api/orders/12345` shapes are largely absent; of 400,001 URLs scanned
for an identifier segment inside an API path, only 595 qualified across 5
hosts, and the largest cluster (`hiringlab.indeed.com` `wp-json/wp/v2/pages/`)
is fully WAF-blocked. The WordPress REST user enumeration that would matter
there (`/wp-json/wp/v2/users`, `?rest_route=`, `/wp-json/wp/v2/settings`)
returns **403 on every path on both `hiringlab.indeed.com` and
`indeedflex.com`, including `/wp-login.php`** — a blanket block, so untested,
not clean. `dellservervr` / `dellnetworkingvr` answer `401` on the same paths.

**10c. API auth posture — 97 hosts, 58 testable.** Every recorded `/api` path
plus a nonexistent control per host (a host whose control is itself
401/403/503 is WAF-masked and discarded as untested). 20 responses were JSON:

- **`admin.labplatform.dell.com`** — 99 `/api/admin/*` paths (accounts, audit,
  `dumpGrailsConfig`, `serverInfo`, `tenant-stats`, role/LTI management). **All
  99 return the same 403 as a nonexistent path** — edge-blocked, untested.
- **`daas.digicert.com`** — 69 of 95 paths `401`, body empty; control `404 548`.
- **`imagewatch.dell.com`** (154 paths) → blanket 403; **`accounts.digicert.com`**
  (24) → blanket 503; **`developer.dell.com`** → static docs site.
- **`devmvs.dell.com`** (ServiceNow): `/api/now/sp/page` → 200 but the user
  object is `{"user_name":"guest","logged_in":false,"email":"guest@example.com"}`
  — the anonymous guest context. The table API behind it is closed:
  `/api/now/table/{sys_user,incident,sys_user_role,core_company}`,
  `/api/now/stats/sys_user`, `/api/now/ui/user/list` → **401 "User is not
  authenticated"**.
- **`rrdmzjpd.artifactory.dell.com`**: `/artifactory/api/repositories` and
  `/api/storage/` → **401 Authentication is required**; only `/system/ping`
  answers 200.
- **`dev.digicert.com/api-reference/openapi/*.json`** → public API docs
  (145 KB–1.7 MB), intentionally published.
- **`sdk.indeed.com/api/`** → anonymous app bootstrap, `ACAC: none`.
- **`collector.vcr.dell.com/api/sdk-config`** → a `writeKey` that is the public
  ingest key shipped in the browser SDK, with `"appId":"demo"`.

**10d. Admin/user paths on 272 hosts.** 140 testable, 106 WAF-masked, **42 JSON
200s — all benign**: DigiCert `one.*` tenants expose only
`environment/config` (an Adobe `assets.adobedtm.com` tag-manager URL) and
`locales` (a language list); `*.dell.com/DataServices/User/*` answers `[]` or
`{"TotalAvailable":0.00}` — the empty state of an anonymous partner session,
with no partner identifier supplied and nothing to enumerate.

**Conclusion: no unauthenticated record access found anywhere.** The one real
risk is coverage, not behaviour: **`admin.labplatform.dell.com`'s 99 admin
routes, `imagewatch.dell.com`'s 154, and `accounts.digicert.com`'s 24 are
blocked by the edge from this IP and remain genuinely untested.**

## Category 11 — DigiCert deep XSS hunt (crawl → param discovery → payload)

Scope: `digicert.com`, excluding `ooscopes` (`partner.digicert.com` — never
touched). Surface: **181 live hosts**, **1,288,922 URLs crawled** by katana
(depth 3, JS crawl), **24,599 parameterised URLs**, **299 distinct parameter
names**, 1,402 first-party JS files.

**11a. Header reflections — 91, all inert.** A unique canary
(`zq<tok><svg/onload=alert(40931)>`) substituting every parameter produced 91
responses containing the token, **100% inside the `Location` header of a 302**,
zero in a body. Those are redirects carrying the request URL, not HTML
reflection.

**11b. Body reflections — 21, zero raw.** Stage 1 marked each parameter with a
random token and fetched the page: 21 URLs echoed the token into an HTML body.
Stage 2 sent the executing payload to those 21: **0 raw, 0 encoded** — the token
vanished entirely, i.e. `<` caused the request to be rejected before render.
On `partners.digicert.com` (ASP.NET) the distinguishing test showed why: the
echo lives in `<form action="./?utm_source=VALUE">`, and a per-character map
found that only `plain` and `paren` survive; **`<`, `>`, `"`, `'`, `&`, `=`,
`/`, `` ` ``, space, tab, newline, `%3C`, `%253C`, `‹`, `＜` all change the
response to `/English/error.aspx`** (200, 53,506 bytes). That is an active
reject-list, not a reflect-then-encode bug.

**11c. Payload sweep on the 51 app-host targets.** Filtering to hosts with no
Imperva/Cloudflare in front (156 of 181) left 51 URLs that reach the
application, expanded to **64 (url, param) tests**, each with a
parameter-absent control. **Verdicts: DROP 64, RAW 0.** Not one parameter
returned the token in any form.

**11d. Framework-specific surfaces tested and closed:**
- **Moodle** (`learn.digicert.com`): `/course/view.php?id=`, `/login/index.php?lang=`,
  `/course/index.php?search=`, `/search/index.php?q=`, `/admin/tool/policy/view.php?versionid=`,
  `/group/index.php?id=`, `/user/profile.php?id=`. The only echo is the search
  term inside a **double-encoded SAML `wants=` attribute**
  (`...%3Dzqmk7%253Csvg%252Fonload...`) — inert, HTML entities are not decoded
  in an attribute value.
- **Eloquent form pages** (`contact-us`, `campaigns/tls-best-practices-guide`,
  with 14–15 hidden inputs including `pageURL`, `redirect`, `toc`): every
  parameter, including the hidden ones, returned **403** the moment the payload
  was present. Imperva blocks before the app.
- **Auth returnPath** (`auth.ch`, `auth.nl`, `clientauth.one`,
  `clientauth.accounts`, `auth.demo.ch` × `/imauth/api/v1/login?returnPath=`,
  `/?redirect=`, `/?next=`): **no echo, no Location** — nothing reflected.
- **WordPress** (`knowledge.digicert.com`): `/?s=`, `/search?q=`,
  `/wp-json/wp/v2/users`, `?rest_route=`, `/wp-login.php` → no echo; the 404
  body carrying a random-named script is an **Imperva interstitial**, not app
  output.

**11e. DOM XSS — source→sink analysis, 1,168/1,168 files (complete).** Built a
bounded backward slicer (2-hop) keyed on link-carriable sources
(`location.search`, `hash`, `href`, `referrer`, `postMessage`, `cookie`,
`storage`) against 9 sinks. The self-test caught three real bugs before any
count was trusted: a 2-hop chain (`a=location.search; b=a; innerHTML=b`),
`e.data` under a message listener, and finally a **quadratic backward walk** —
re-scanning the whole file per identifier meant the first pass died at 50/1,168
files and a second at 95 flows, so both were reported as *partial*, not as
findings. Replacing the per-identifier scan with a single-pass assignment index
made the pass finish: **530 flows over all 1,168 first-party files.**

Flow census: `attr.href 238 · setTimeout-str 134 · innerHTML 79 · element.src 65
· outerHTML 6 · insertAdjacentHTML 6 · document.write 2`; sources
`location.search 239 · storage 221 · postMessage 52 · cookie 10 · hash 8`.

**93 reach HTML/eval sinks and every one was opened by hand.** They are library
internals, not app logic: FontAwesome's `<svg>`+`valueOf().toString()` probe,
React-DOM's `<script></script>` feature test (`main.0684079a.js`,
`6.*.chunk.js`, `index-*.js`), MapLibre's attribution container, CKEditor's
`<pre>` wrappers, Aura's `createText`, Prism's `highlightedCode`. Two bundles
exceeding the 2.5 MB cap — `main.5c659757.js` (7.8 MB, ag-Grid) and
`theme-CuAO7zin.js` (4.1 MB, React/Remix) — were **read separately by hand**;
both are ag-Grid/Remix/router internals (`t.innerHTML=(e||"").trim()`,
`a.innerHTML=e` inside React's DOM-setters, the `Gs` route-path builder).

Two DigiCert first-party candidates were chased to the assignment line and
closed:
- `docs.digicert.com/js/layout-custom-script.js` — `navlinks.innerHTML =
  generate_top_links([...], e)` where `e` comes from
  `check_content_path` (a **URL path** match, not the query string) and the
  argument is only used to pick a language list. Not attacker-controlled via
  query.
- `docs.digicert.com/js/elastic-app-search.js` — the `location.search` source is
  `new URLSearchParams(location.search).get("lang")`; its sink is
  `generateProductFiltersHTML(currentDomain)` where
  `currentDomain="docs.digicert.com"` is a **literal**. The `insertAdjacentHTML`
  hits are static template strings. Live check: `?lang=`, `?q=`, `?search=`,
  `?page=`, `?version=` → plain values are not reflected server-side
  (`zqtest99` absent from the body) and the payload returns **403**.

**Conclusion: no XSS found.** The honest framing is that DigiCert's blocking is
what stopped this, not that the surface is clean: **Imperva rejects every
payload-bearing request on the marketing, docs and Eloqua pages, and
`partners.digicert.com` rejects every dangerous character outright.** Those
pages are *untested against a bypass*, not proven safe. The auth/`accounts`
hosts were reachable and reflected nothing at all.

## Category 12 — Indeed deep XSS hunt (crawl → param discovery → payload → DOM)

Scope: `indeed.com`, `indeedflex.com`, `indeed.tech`, `indeed.net` (no OOS
entries). Surface: **25,887 subdomains, 1,130 HTTP rows, 159 alive hosts**,
**10,476,199 URLs crawled** by katana, **137,517 in-scope parameterised URLs**,
**109 distinct parameter names**, 21,515 JS URLs discovered.

**12a. Reflection sweep — 35,337 unique host+path targets, 0 RAW.** Excluding
`__cf_chl_*` challenge params and deduping to one URL per (host, path) left
35,337 tests, each with a benign-value control on the same URL. Verdicts:
**DROP 25,201 · ENC 10,134 · TOKEN_NOPARSE 1 · RAW 0**. The classifier was
fixture-tested first (RAW/ENC/HEADER/DROP all discriminate).

**12b. The 10,134 ENC are the application encoding correctly, not a bug.** 7,443
are on HTTP 200, 2,242 on 403, 438 on 404. Every sampled context is
**double-encoded inside a JSON `continue=` value** on the help pages:
`continue=https%3A%2F%2F...%3Fhl%3Dzqzt178o8u%253Csvg%252Fonload%253D...` — the
`%253C` is `%3C` after one decode, so the browser never sees a raw `<`. The 403
subset is the Cloudflare challenge page echoing the request URL (`cUPMDTk`,
`cType: 'managed'`) — infrastructure, not app output.

**12c. The one non-trivial surface: `forms.indeedflex.com/platform/auth`.** This
page answers with literally
`<script>location.href = 'https://...login?rp=...&ref=...';</script>` — the
whole request URL interpolated into a **single-quoted JS string literal**, which
is a real sink shape. Testing every parameter individually with a
`'+alert(40931)+'` breakout: **all of them encode the quote as `%2527`**
(`rp%3Dzqsj4093%2527%253Balert%252840931%2529`), i.e. double-encoded before
interpolation, so the literal never closes. `</script>`, `"`, `\`, `<` all
become `%25..` the same way. Path injection (`/platform/<payload>`,
`/login/<payload>`) → 404/429, no echo. The `login?rp=` target returned 429
under load and 200 without the token in body.

**12d. Marketo `forms2.min.js` — the exact pattern the skill flags, and it is
safe here.** Indeed's `offers.indeed.com` loads Marketo forms, whose
`InputSourceChannel: "url"` branch does
`r = parse(location.search.replace("?","")); q = r[selector]` and writes `q`
into a **hidden field** (the documented "fill the form from the query string"
behaviour). Live test against `offers.indeed.com`, `www.indeed.com/hire`,
`employers.indeed.com` with 9 candidate params: **every request returned 403**
and the only echo was Cloudflare's `cUPMDTk`, so the Marketo path is
**unreachable from this IP — untested, not clean**.

**12e. DOM XSS — 21,515 JS URLs deduped to 35 distinct artifacts, 139 flows.**
The crawl's JS list is dominated by `cdn-cgi/challenge-platform` and per-country
mirrors of the same chunk, so dedupe by basename+sha256 was required. 33 flows
reach HTML/eval sinks; opening them by hand shows **jQuery internals**
(`forms2.min.js` `parseHTML`/`htmlPrefilter`/`clone` feature tests),
**FontAwesome's** `<svg>`+`valueOf().toString()` probe (`2258.1df21dca.js`,
`for-login-flow.js`), and a **preload helper** in `index.e76f520a.js`
(`E.innerHTML = \`<link rel="stylesheet" href="${f}" />\``) where `f` is the
function's own parameter, not a URL source — the `cookie` attribution is a
slicing artifact. Two bundles over the 2.5 MB cap were skipped by name:
`paynow.indeed.com/static/.../app.js` (5.7 MB) and
`resources.indeedflex.com/assets/index-BBHe2OgQ.js` (2.5 MB) — **not analysed**.

**Conclusion: no XSS found on Indeed.** What actually stopped the hunt is
Cloudflare: **128 of the 159 alive hosts are Cloudflare-fronted and the
challenge page answers 403 to every payload-bearing request**, including the
Marketo landers. That surface is *untested against a bypass*, not proven safe.
The hosts that were reachable — help pages, `forms.indeedflex.com`, the docs and
`indeed.tech` apps — either encoded correctly or reflected nothing.

## Category 13 — Browser-executed DOM XSS phase (real Chromium, hook proven)

Every earlier phase judged XSS from HTTP responses. This one drives a real
browser, because a server-side echo cannot see `location.hash` or a DOM sink at
all.

**Hook discipline first.** `window.alert` was replaced at **document-start** via
`Page.addScriptToEvaluateOnNewDocument` and proven to fire: a control page
`<script>alert(888)</script>` produced `["888"]` in the capture array. Only then
were the negatives treated as meaningful. (Installing the hook *after* load
captured `None` — that failed attempt is why the control matters.)

**Coverage and result:**
- **23 in-scope hosts that genuinely render** (from 140 candidates): query
  (`?q=`), `?returnPath=`, and `location.hash`, each with
  `"><svg onload=alert(40931)>` / `<img src=x onerror=alert(40931)>`.
  **0 executions.**
- **114 hosts were TLS-blocked** ("Privacy error" interstitial) and **never
  loaded** — their earlier "no XSS" result is void, not a pass. This is the same
  trap as the `openssl Verify return code` note in `hunt-xss`: a page a victim
  cannot silently load is not a page you have tested.
- `docs.digicert.com` — `?lang=` is normalised to `en` server-side (redirect),
  the value is read client-side by `elastic-app-search.js`, and nothing reaches
  the DOM; hash vector ignored.
- `callscheduler.digicert.com` (160 scripts, SPA) — `?q=` and `#hash` both
  ignored, only `/v2/` renders.
- `forms.indeedflex.com`, `hello.indeedflex.com`, `learn.digicert.com` (Moodle),
  `auth.*`/`clientauth.*` DigiCert ONE — no execution.

**Sink instrumentation, not just `alert`.** `Element.prototype.innerHTML`,
`document.write` and `insertAdjacentHTML` were also hooked at document-start,
recording any value containing the canary. On the three highest-JS pages
(`callscheduler/v2`, `clientauth.one`, `auth.ch`) the hit array stayed `[]` — no
page writes location-derived data into a sink at all.

**Indeed has no write surface to test.** `secure.indeed.com/auth`,
`/account/register`, `profile.indeed.com` and `www.indeed.com/jobs` all return
**"Blocked - Indeed.com"** in the browser from this IP — 0 password fields, 0
text inputs, no signup. Stored XSS (the highest-paying class in `hunt-xss`)
therefore **cannot be assessed from here at all**; it is not clean, it is
unreachable.

**Conclusion: still no XSS, and the four real gaps are now named:** 114
TLS-blocked DigiCert hosts, all Cloudflare-fronted Indeed pages, no Indeed
account/write surface, and no out-of-band receiver for blind/stored payloads.

### 13d. Fourth pass — where the payload actually lands (RSC, not markup)

One more retry, this time starting from the browser rather than the server.

**The payload did reach the DOM — once.** On the Indeed help pages the `co`
parameter survives into the response, but only as a **React Server Component
payload string**: `self.__next_s.push([1, "0:{...\"co\":\"\\u003e\\u003csvg
onload=alert(40931)\\u003e\"...}"])`. It is a JSON value inside a
`<script type="text/javascript">`, not markup, so:

- `document.querySelectorAll('[onload]')` → **0**
- `document.querySelectorAll('svg')` → 18 (the page's own icons, not the payload)
- text nodes carrying the raw string → **0**
- the sink hook (`Element.prototype.innerHTML`) → never fired with the canary
- `alert` → never fired

The browser **does not execute** a `<svg>` that appears inside a JSON string in a
script block. This is the correct, safe behaviour of the framework, and it is
why every prior "encoded" verdict was actually "correctly rendered as data".

**What this pass added:**
- The only thing that survives the whole pipeline is a JSON value, and it is
  inert by construction. There is no remaining reflection path to a sink.
- `docs.digicert.com` search (driven by real keyboard events, 8 variants) renders
  19 results from a **pre-built index**; the typed value is never inserted into
  the DOM at all — confirmed by sink hook.
- `mgmt.cpe.indeed.tech` (Django, no Cloudflare) reflected `?next=` into the
  login template but **rate-limited to 403** after a handful of requests, so
  the reflection could not be driven to a payload.
- The browser-side hunt is now closed for this engagement: 38 hosts rendered,
  102 TLS-blocked (rc=19, full interstitial), 2,243 Cloudflare challenge pages,
  0 executions, 0 sink writes.

**Final verdict: no XSS found.** The four gaps that remain are environmental,
not analytical — they require a different vantage point:
1. 102 DigiCert `chain-demos` hosts (rc=19, full interstitial) — needs an
   origin or a bypassed TLS client.
2. All Cloudflare-fronted Indeed pages — needs an origin IP or a `cf_clearance`
   cookie obtained through a real browser session.
3. No Indeed account / write surface reachable from this IP — stored XSS is
   untestable here.
4. No out-of-band (Collaborator) receiver, so blind/stored XSS cannot be
   confirmed even if planted.

## State written to the DB

**The x8 parameter surface is 110,696 (endpoint, param) pairs**, dwarfing the
109 names the crawl produced — `indeed 70,602 · dell 29,736 · digicert 10,181 ·
wien 177`, split `GET 110,485 · POST 199 · PUT/PATCH 12`. Mining it was the one
channel `hunt-xss` says a crawl cannot replace.

Two lessons from reading the records rather than trusting the counts:
- **`co` (27,522) is an artifact** — records on `/help/job-seekers` with
  `example_url` having no query at all. The count is inflated, not a surface.
- **`p4ssw0rD` (7,030) is x8's built-in probe list**, not a discovered
  parameter. Records carrying it also carry `test`, `debug`, `admin`, `sso`,
  `waf`, `captcha`, `env` — exactly x8's `--custom-parameters` defaults. Zero
  signal.

The genuinely new name was **`kw` (12,975)** — the keyword-search param, absent
from the crawl's 109. Tested on `au/ae/ar/in.indeed.com/help/*` across
`kw · q · keyword · rawkeyword · ikw · search`:
- 200 pages → payload **double-encoded** (`%253Csvg%252Fonload`) inside
  `secure.indeed.com/auth?...&continue=` — inert.
- `ae.indeed.com` returns **404 with a swampjs JSON payload** that is only
  **single**-encoded (`%3Csvg%2Fonload%3Dalert%2840931%29%3E`). Browser test with
  sinks hooked: the value lands in **`<a href="...continue=https%3A%2F%2F...%3Fq%3D%253Cimg...">`**
  only — an **attribute value** (inert; HTML entities are not decoded in an
  attribute) and it is `%25`-encoded there anyway. 0 executions, 0 sink writes,
  0 live text nodes, 0 `[onload]` elements.
- The 404 page's `title`/body carry no payload; `document.documentElement.innerHTML`
  did not contain the raw string even though a control substring did — the hit
  was inside JSON in a `<script>` block, not markup.

**TLS gap re-measured, not assumed.** `Security.setIgnoreCertificateErrors` did
not persist across navigations, so the earlier retest was inconclusive. Measured
from the shell instead: `openssl s_client` on
`assured-id-root-ca.chain-demos.digicert.com` →
**`Verify return code: 19 (self-signed certificate in certificate chain)`**, while
`clientauth.one.digicert.com` and `auth.ch.digicert.com` → **`0 (ok)`**. So the
blocked set is the **70 `chain-demos` hosts**, which genuinely put a full-page
interstitial in front of any victim — `hunt-xss` is explicit that this is
`C:N/I:N/A:N` territory, and "untested" remains the honest verdict, not "clean".

### 13c. Third pass — research-led retry (disclosed-bug replay, WAF matrix, origin hunt)

The first two passes were broad. This one started from **what has actually paid
on these programs**, then tried to reach it.

**Research changed the target list.** Public disclosures show two accepted XSS
bugs on the exact surface this hunt had already enumerated and left untested:
- **Bugcrowd — `XSS reflected https://www.indeed.com/hire/employer-confirmation
  [co, hl]`**, disclosed 2022-05-02, **$800**, P3, status *Resolved*.
- **Bugcrowd — `Reflected XSS in https://www.indeed.com/career-advice/`**
  (cr00k, 2022).

So **`co` — which this report earlier dismissed as an "artifact" — is the real
historic XSS parameter on Indeed.** That dismissal was wrong and is corrected
here.

**32-payload WAF matrix against the disclosed paths** (`<svg/onload>`,
`<details open ontoggle>`, `<video/audio onerror>`, `<body onpageshow>`,
`<marquee onstart>`, case-mixed, tab/newline-split, HTML-entity `&#40;`/`&lpar;`,
fullwidth `＜ ＞`, `%u0034`-style, `javascript:`, double- and triple-encoded
`%253C`/`%25253C`, attribute-break `"`/`'`, `<iframe srcdoc>`, `<math><style>`
mXSS, `<svg><style>` mXSS, `autofocus onfocus` on input/select/textarea/keygen,
`<animate onbegin>`, `<set onbegin>`, `<object data=javascript:>`):
**0 of 32 passed.** Critically, a *clean* request to `/career-advice/` with no
parameters at all also returns **403** — so this is not payload filtering, the
whole path is blocked for this vantage point, and no payload mutation can help.

**Origin-IP hunt (the documented Cloudflare bypass).** Passive DNS gives a
historical A record `169.45.207.192`; it **times out** on both 80/443. The
current anycast IPs (`162.159.129.67`, `162.159.130.67`) return the Cloudflare
403 with `server: cloudflare` and `cf-ray` set. **No reachable origin found.**

**Client-fingerprint variations** — plain curl, a full browser header set
(UA, Accept, Accept-Language, Referer, Sec-Fetch-*, Upgrade-Insecure-Requests),
and `--http2` with a macOS Chrome UA: **403 on every combination**, clean or
payload. The block is not fingerprint-based.

**Locale matrix** — the same disclosed path on 20 country hosts
(`uk/ca/au/ie/nz/in/sg/de/fr/nl/it/es/jp/br/mx/ch/at/be/se`): **403 everywhere
with an identical 25,741-byte body**, confirming a zone-level rule rather than
per-locale laxity.

**Full-corpus matrix — 35,336 endpoints, every parameter, one payload each.**
This is the largest single pass of the engagement and it corrects the earlier
"Cloudflare blocks everything" claim:
`301 1,595 · 403 27,321 · 200 4,391 · 404 2,014 · 429 10 · 500 1`, with
**2,243 genuine challenge pages**. So **4,391 endpoints on 68 hosts are open**
(`ma 143 · in 132 · ie 120 · it 111 · au 109 · nl 109`) — the block is
per-path, not global. **0 RAW.**

**Payload matrix on the open set — 1,200 URLs × 6 contexts = 7,200 tests**
(tag, JS single-quote, JS double-quote, attribute-break, `</script>`, and an
inert `<b>mark40931</b>` markup probe). **0 RAW**, but **1,167 responses echoed
the marker**. Reading the raw bytes rather than trusting "encoded" shows why
nothing fires:

```
continue=https%3A%2F%2F...%3Fhl%3D%2522%253E%253Cb%253Emark40931%253C%252Fb%253E
```

`%2522` decodes to `%22`, `%253C` to `%3C` — **double-encoded inside a JSON
`continue=` value**. The payload never becomes markup, in any context, on any of
the 4,391 open endpoints.

**Live interaction, not just navigation.** An Okta sign-in form was filled and
submitted with `<img src=x onerror=...>@zq4093.example`: response was
*"The field must not contain HTML tags"* — input validation, not a sink. The
`docs.digicert.com` search box was driven with real keyboard events (8 payload
variants): 19 results render, but **the typed value never enters the DOM at
all** — the results come from a pre-built index, not from the query. `postMessage`
payloads (7 message shapes) were pushed into `docs.digicert.com`,
`callscheduler/v2` and `clientauth.one` plus every same-origin iframe:
**no sink fired, no alert.**

**New host found and tested:** `mgmt.cpe.indeed.tech` — **Django, no Cloudflare**,
with `/accounts/password_reset/`, `/accounts/login/`, `/accounts/password_reset/done/`.
`?next=` on the login page reflected the value, but after a few requests the host
began returning a bare **403 Forbidden** (rate limit), so the `next` reflection
could not be driven to a payload.

## State written to the DB

| program | source | status | count |
|---|---|---|---|
| dell | takeover | false_positive | 2 |
| digicert | nuclei | false_positive | 5 |
| indeed | nuclei | false_positive | 3 |
| indeed | secret | false_positive | 1 |

Every row carries `extra.verified` explaining the verdict. Nothing was deleted.

## Open item for the operator

The nuclei lane (`nuclei/watch_nuclei_run.py`, running every cycle) keeps
re-inserting takeover candidates with `status="open"` through
`upsert_finding()`, which sets `status` only under `$setOnInsert`. A verdict I
write can therefore be silently re-opened by the next scan of a *new* host, and
re-marking is manual. If verdicts are meant to be sticky, `upsert_finding()`
needs to preserve an existing `status` — that is a code change, not something I
made.
