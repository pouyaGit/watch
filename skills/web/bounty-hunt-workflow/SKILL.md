---
name: bounty-hunt-workflow
description: Route a bug bounty hunt to the right class skill.
---

# Bug Bounty Hunt Workflow

The loader for a hunt. It answers three questions: which class skill to
open, what must be true before a candidate is a finding, and when to stop
hunting a class and move on.

**Load order:** this skill -> the class skill it names -> (for reporting)
`triage-validation` -> `report-writing`.

## SKILL ROUTING

| What you are hunting | Load this |
|---|---|
| XSS that executes JS | `hunt-xss` |
| Raw HTML, no JS execution | `hunt-html-injection` |
| Client-side only: clobbering, postMessage, SW, CSS exfil | `hunt-dom` |
| IDOR / BOLA | `hunt-idor` |
| Auth bypass, SSO trust | `hunt-auth-bypass` |
| SAML specifically | `hunt-saml` |
| JWT signature / alg-none | `hunt-jwt-crypto` |
| Account takeover chains | `hunt-ato` |
| SSRF | `hunt-ssrf` |
| SQL injection | `hunt-sqli` |
| NoSQL injection | `hunt-nosqli` |
| Command injection / RCE | `hunt-rce` |
| Path traversal / LFI | `hunt-lfi` |
| XXE | `hunt-xxe` |
| Deserialization | `hunt-deserialization` |
| SSTI | `hunt-ssti` |
| CSRF | `hunt-csrf` |
| CORS | `hunt-cors` |
| Open redirect | `hunt-open-redirect` |
| OAuth / OIDC | `hunt-oauth` |
| Business logic | `hunt-business-logic` |
| Race conditions | `hunt-race-condition` |
| File upload | `hunt-file-upload` |
| Cache poisoning / WCD | `hunt-cache-poison` |
| HTTP smuggling | `hunt-http-smuggling` |
| Host header | `hunt-host-header` |
| GraphQL | `hunt-graphql` |
| gRPC | `hunt-grpc` |
| WebSocket | `hunt-websocket` |
| Subdomain takeover | `hunt-subdomain` |
| Cloud misconfig | `hunt-cloud-misconfig` |
| CI/CD pipelines | `hunt-cicd` |
| Kubernetes / Docker | `hunt-k8s` |
| SPA backend API discovery | `hunt-spa-api` |
| Shadow / versioned APIs | `hunt-shadow-api` |
| Source maps / .env / build artifacts | `hunt-source-leak` |
| TLS / DNS misconfig | `hunt-tls-network` |
| LLM / AI features | `hunt-llm-ai` |
| RAG pipelines | `hunt-rag-vector` |
| MFA / 2FA bypass | `hunt-mfa-bypass` |
| Forgot-password flows | `hunt-forgot-password` |
| Brute force / rate limiting | `hunt-brute-force` |
| CAPTCHA | `hunt-captcha-bypass` |
| Session management | `hunt-session` |
| API mass assignment / prototype pollution | `hunt-api-misconfig` |
| Everything else | `hunt-misc` |
| Payloads and bypass tables | `security-arsenal` |
| Scope and asset discovery | `web2-recon` |

## BEFORE ANYTHING ELSE: SCOPE

1. Read the program's in-scope asset list. A host outside it never
   receives traffic, not even for "a quick check".
2. Get-only unless the operator explicitly authorises a specific
   mutating request. A POST used to detect reflection is fine; a POST
   that mutates state is not.
3. If a safety rule must be broken to make progress, stop and report it
   rather than proceeding.
4. `partner.example.com` (singular) can be out of scope while
   `partners.example.com` (plural) is in scope. Read the list, do not
   infer from the shape of the name.

## PHASE 0: FINGERPRINT THE WHOLE SET BEFORE PICKING TARGETS

A list of N fresh URLs is NOT N targets. Fingerprint every one of them
first (one GET each, cheap), and CLASSIFY before you choose. The
typical shape of a fresh set:

| Class | Typical share | Disposition |
|---|---|---|
| SSO / WAF gated | 25-35% | sign-in or "Request Blocked" page - the application is never reached |
| one shared static template | 20-30% | one sink, one class, one verdict - do not re-analyse it N times |
| internal fleet (dev/test tiers) | 15-20% | a uniform 403/empty body; the gate usually holds |
| genuinely distinct applications | 10-20% | **these are your real work** |

So a 90-URL set is often 11 real targets. Choose from the
fingerprint, not from the URL list.

**The fingerprint's gate detection must be BODY-based, not
status-based.** A Cloudflare Access gate answers **HTTP 200** with the
sign-in page for every path on every host it covers, so a status-only
sweep reports the whole fleet as "reachable" and produces a list of
false hits. Detect the gate from the body: the `<title>` carries the
app name ("Sign in ・ Cloudflare Access", "Error ・ Cloudflare
Access"), or the body contains "Request Blocked" / "Security Check".
Then VERIFY the detector against itself: re-check every host it
called "open" for a gate marker, and every host it called "gated" for
its own content. Zero mis-classifications is the bar - a detector
that has not been checked against itself has not been measured.

**Fingerprint for the STACK, not just the status.** The headers say
what is in front of the application, and that decides where the real
surface is:
- `Server: cloudflare` + `X-Amz-Cf-Id` -> CloudFront, and a 404 body
  containing `<BucketName>` means the origin is **S3** - a completely
  different, often richer surface than the hostname suggests
- `X-Iinfo` + `visid_incap` -> Imperva
- `Akamai-GRN` -> Akamai
- `X-Amz-Request-Id` + `NoSuchKey` -> S3 behind CloudFront
- `Server: istio-envoy` -> a service mesh; the app is behind it
- `X-Cache: Error from cloudfront` -> the 403 is CloudFront's own
  behaviour, not the application's

### RE-CHECK EVERY HOST YOU DID NOT RE-CHECK

A sweep that produces "9 hosts answered 200, I verified those 9"
leaves 22 hosts whose result was accepted on the strength of the
sweep's own status code. That is a coverage hole, and in one real
hunt it hid the single host in a 90-host set that was NOT behind a
managed gate.

The re-check is cheap: one GET per path, hash the body, group by hash.

**A body-hash count is NOT a gate test.** The Cloudflare Access login
page embeds a per-request `kid` and `meta` value, so its length
changes with every path (48,283 / 48,291 / ... / 48,379). A
"more than 2 distinct bodies" rule then reports 17 hosts as "routing
differently" when every one of them is gated. **The gate marker in
the body is the test, not the body count.**

**The marker list has to be complete, or you get a false "not
gated".** A short marker list missed the 1,859-byte Access page,
whose text lives inside an iframe's `srcdoc` attribute and reads
*"Unable to connect to application ... check that your API call is
being made from a valid IP address along with the appropriate
headers"*. **Read the body of any host whose response length nobody
else shares - a unique body size is the signal, not noise.**

**Classify every host into exactly one of four classes:**

| Class | Meaning |
|---|---|
| gated | a marker in the body names the gate |
| walled | a WAF challenge page - a CAPTCHA is a decision about THIS client, not a finding about the app |
| unreachable | status 0 on every path - no TLS listener, or the host is down |
| **app** | none of the above - the only class worth spending time on |

A host with status 0 on every path is a fourth class, not a pass. It
means the name resolves to something that does not speak the protocol
- and that turned out to be a bare HTTP-only Apache, which was the
only interesting host in the whole set.

**Check the port, not just the URL.** A name that answers on :80 and
has NO TLS listener at :443 is a different asset from one that
redirects HTTP to HTTPS, and it is frequently an unconfigured virtual
host serving the platform's default page. Test the port directly, and
if :80 answers, walk what it serves.

**When you find a directory listing, walk EVERY listing, and the
parents.** One Apache host in this hunt exposed two live "Index of"
directories. The first was walked and turned up 386 files, all
images. The second, `/icons/small/`, sat in the sibling probe and
would have been missed - and a second listing is a second chance for
a file that is not an icon. Both came back with nothing, but that had
to be measured, not assumed.

Also probe the parents and the classic content locations before
concluding there is nothing behind the listing:
`/icons/../`, `/icons/small/../..`, `/usr/local/apache2/htdocs/`,
`/var/www/html/`, `/srv/`, `/usr/share/httpd/`,
`/usr/local/apache2/conf/`, `/usr/local/apache2/logs/`. A 200 on any
of those changes the finding from "default page" to "real content
exposed".

**A directory listing of only public-domain platform files is a
hygiene finding, not a vulnerability.** The impact test decides it:
if every listed file is stock (Apache's own icons, a default
`index.html`), there is no credential, no data, and no user harm, and
the delivery is the DNS record rather than an exploit. Say that
plainly instead of inflating it.

That header reading is what turned `discovery-service.digicert.com`
from "a 404" into "an S3 bucket behind a CloudFront distribution" in
one pass.

**Rank the deep-dive targets by:**
1. it serves its OWN content (not a gate, not a shared template)
2. it has a plausible API or form surface
3. its name says what it does (`-api`, `discovery`, `portal`,
   `staging`, `mcp`, `gatekeeper`)
4. it is a non-production tier (dev/test/staging) - a bug there is
   cheaper to fix and usually means the same bug in prod

(3) then (4): a named API on a dev tier beats an unnamed production
host every time, because the first has a surface and the second needs
one discovered from scratch.

## PHASE 0.5: THE RECON OUTPUT IS BIGGER THAN THE FRESH SET

A "fresh" URL set is the tip of the tool. The recon output behind it usually holds
orders of magnitude more, and the part a fresh list cannot reach is the **structured
data**: per-endpoint parameter records, full response records with headers, and change
events.

A real recon output for one program set measured:

```
urls                 626,964
endpoints            189,775
endpoints with real param_records   18,338   <- across 307 hosts
http (full responses)                  2,600
change_event                          95,156
live_subdomains                       19,536
```

**Read the `endpoints` collection's parameter records before hunting anything.** The
parameter NAMES are a map of the program's attack surface, and they name the things a
plain URL list never will:

```
preauthurl        506 paths   -> a pre-authentication redirect surface
dest              289 paths   -> a post-login destination
destination, callback, preauthurl, redir, redirectUri, redirection, callURL
sid                             -> a session id
client_id, sso, debug, admin, env, encryption, logout, bot, waf
```

474 of the endpoints carried a redirect-class parameter name. That is a work list built
from the target's own data, not from a wordlist.

**Mine the param records for the NAMES, then rank by what the name implies.** A
parameter called `redirect` is a different hypothesis from one called `sid`, and each
implies a different test. Do not treat "it has parameters" as one class of target.

**THE PARAMETER NAMES ARE A MAP OF THE PROGRAM'S ATTACK SURFACE — and the PATH
SHAPE IS A MAP OF THE STACK.** A parameter set that reads
`client_id, code_challenge, code_challenge_method, redirect_uri, response_type, scope,
state, token` is an OAuth authorization server, and the path that carries it
(`/auth/realms/<realm>/protocol/openid-connect/auth`) names the product outright
(Keycloak). That single read found a **36-host, 34-realm identity provider** that no URL
list names — no subdomain, no path and no title in the recon output says "Keycloak", and
the realm ids (`sr4`, `sr5`, `sr66`) are unguessable.

So before hunting a class, ask what the recon data already says about it. The
parameter names and the path shape together often identify the product, the
configuration surface and the class in one read, and they tell you which SKILL to
open:

| The param names / path shape | The class | The skill |
|---|---|---|
| `client_id, redirect_uri, code_challenge, response_type` | OAuth / OIDC | `hunt-oauth` |
| `code`, `id_token`, `assertion`, `SAMLResponse` | SAML / OIDC | `hunt-saml` |
| `token`, `sid`, `session`, `jwt` | session handling | `hunt-session` |
| `redirect, next, returnUrl, dest, callback, continue` | open redirect | `hunt-open-redirect` |
| `state, nonce, code_challenge_method` | the OAuth specifics | `hunt-oauth` |
| `/auth/realms/<r>/…`, `/oauth/…`, `/.well-known/openid-configuration` | the IdP surface | `hunt-oauth` + `hunt-ato` |

**A product name in the path is a free lead.** `Keycloak`, `Harbor`, `Artifactory`,
`Jenkins`, `GitLab`, `Confluence` in a path or a title means the whole product's API
surface is in scope, and each product has its own known-overexposed endpoints. Hunt
the product, not the URL.

**Rank recon hosts by what their own recorded metadata says**, not by a wordlist. The
`http` collection's stored `title` and `server` header are free triage:

```
"Apache2 Ubuntu Default Page: It works!"   -> a default page; the app is one path down
"Welcome to nginx!"                         -> same
"Harbor"                                    -> a container registry, a content store
"GraphQL" / "OpenAPI" / "Swagger"           -> an API surface
```

In one pass this turned a set of "404s" into three default pages, a Harbor registry and
a Struts application — every one of which was worth a phase, and none of which a URL
list would have surfaced.

**Watch for the wildcard/DNS artifacts in the live-subdomain data.** A `new_live` list is
full of `wildcard.temp.*` and `*.k8s.<domain>` entries: DNS records, not applications.
Filter them before you count them, or the "19,536 live subdomains" figure becomes 19,536
false targets.

## A PARAMETER THAT IS ACCEPTED IS NOT A PARAMETER THAT IS USED

The most common false positive in a parameter hunt is a server that **accepts** a
parameter, **echoes** it, and then **does nothing with it**.

```
GET https://adh.indeed.com/?next=https://offsite-check.example.org/pwned
  -> 302  /user/login?next=%2F%3Fnext%3Dhttps%253A%252F%252Foffsite-check.example.org%252Fpwned
```

That looks like a textbook open redirect. It is not. The off-site URL is carried as a
*string* into the login page and then **dropped before the identity step**. Prove it by
checking, after the redirect chain:

| Where the value might persist | How to check |
|---|---|
| a session cookie | dump every `Set-Cookie` from the chain and search the values |
| the HTML of the next page | search the rendered body |
| the OAuth `state` parameter | decode it - if it is a random token, the value is not in it |
| the post-login callback | fetch the callback without a session and see where it lands |

If the value is in none of them and the callback lands on `/`, then **no request is ever
made to the attacker's host and no code or token is ever delivered there.** The
parameter is accepted, carried, and discarded. Not an open redirect.

The same pattern shows up as a **302 to the application's own error page**:

```
GET https://ext.goqms.dell.com/sso/Index?callURL=https://offsite-check.example.org/pwned
  -> 302  /Error/ExceptionError?adminExceptionId=93311
```

The application raised an exception and rendered an internal exception id. That is an
application error being reported, not a redirect to the supplied URL. Follow the chain
before you call it.

## THE DIFFERENTIAL RULE (non-negotiable)

A window-based "is there a dangerous char near the marker" check is NOT
a verdict. It counts the attribute's own delimiters and produces
constant false positives.

For every candidate:
1. Fetch with a benign value -> baseline DOM profile.
2. Fetch with the breakout payload -> payload DOM profile.
3. REAL only if the profile differs: a NEW element, a NEW event-handler
   attribute, a raw `<` inside a PARSED attribute value, or the payload
   bytes appearing RAW.

Parse with a real HTML parser, never a regex over the raw body. A tag
the payload did not create is not a finding.

Corollary: a detector without a baseline cannot separate "the payload
was reflected" from "the page always contains an iframe". This single
omission invalidated 8,850 stored hits in one real hunt.

## EVERY CORPUS SCAN NEEDS A PATTERN SELF-TEST

A sweep over hundreds of thousands of parameter values is worthless if
its patterns never fire. The cheap guard: before the sweep, require
every pattern to match a POSITIVE fixture and to REJECT a negative
one. A pattern that fails its own fixture is worse than no pattern,
because it reports zero hits with total confidence.

Two defects this caught in one sweep of 490,549 documents:
  - an internal-hostname pattern required `corp` as a TLD, so
    `build.corp.dell.com` never matched - the fixture was wrong AND
    the pattern missed the mid-domain case,
  - an email pattern required a dot-separated label before the program
    name, so `someone@indeed.com` never matched while
    `someone@sub.indeed.com` did.

Also: when a script that produced a result CRASHES, re-derive the
result rather than trusting the earlier run. A malformed regex in a
sibling script is exactly the kind of thing that leaves a
half-populated artifact looking authoritative.

And: count OCCURRENCES and DISTINCT VALUES separately, and say which
one you are quoting. A reader comparing "3 hits" against "37 hits"
needs to know the difference is occurrences versus distinct values,
not that one of the numbers is wrong.

## A CHANGE EVENT WITH A TIMESTAMP FILTER IS NOT A CORPUS

The `change_event` collection is the highest-value table in a recon
store, because two of its event types name SURFACE rather than state:

    new_endpoint     89,016 records    "this path exists now"
    new_parameter      895 records    "this parameter exists now"

A diff against "since the last crawl" reports ZERO of them and looks
like "nothing new" - while the table actually holds 89,016 endpoint
records and 895 parameter records with 590 distinct names. The diff
answered a question nobody asked.

Mine the WHOLE history, then filter. The filter that works is what
the path IS, not how deep it is:

  - drop static assets, framework chunks, and CDN challenge
    artefacts - on one corpus that removed 15,415 of 89,016 records
    and turned noise into 4,143 real application paths,
  - drop template placeholders: a literal `{id}` or `[...slug]` in the
    path is a crawler artefact, not an endpoint,
  - and then group by host, because a shortlist of 4,143 paths is
    useless and a shortlist of 95 HOSTS with their paths is a hunt.

> **Rule: when a corpus table holds "X appeared" events, mine the
> whole table. A timestamp filter measures the crawler's cadence, not
> the corpus.**

And the parameter events are the scarcest and richest part: 895
records with 590 distinct names, where one host owned thirty of them
and they were all an application's internal namespace - which named
the exact parameter that carries the impact class.

## A DIFFERENTIAL IS NOT AN ORACLE WITHOUT A KNOWN-GOOD VALUE

Three answer shapes on an SSO selector looked like an enumeration
oracle:

    "Invalid input detected in idp_id"    a format rejection
    the normal 96 KB page                 the parameter was ignored
    403 with a zero-length body          the lookup found nothing

The difference tracked the input's FORM, not whether the value
exists: digits passed the validator, a uuid did not, and every number
from 0 to 1,000 produced the identical page. With no real identifier
in the corpus and none on the page, there was no known-good value to
compare against - so the honest verdict was "the oracle could not be
established", not "the endpoint leaks which IdPs exist".

> **Rule: an oracle needs a known-good value AND a known-bad value of
> the same shape. A differential you cannot anchor is a format check.
> Say so instead of guessing.**

## CLASSIFY AN OBJECT BY WHAT THE SYSTEM SAYS ABOUT ITSELF

A list of known built-in id prefixes is a guess, and it produced a
false positive: two of nine sys_ids were called "instance-specific"
because a hard-coded prefix list did not contain them. The page's own
metadata said `title: "Not Found"`, `sys_name: "404 message"` and
carried ServiceNow's own "Breakout Game" easter egg - so it was the
standard out-of-box 404 page, and the ids were built-ins.

> **Rule: read the object's self-description before classifying it.
> A title, a sys_name, an "is this the 404 page" flag and an easter
> egg that exists on every instance are stronger evidence than a
> prefix list you wrote down.**

## A SYMMETRIC CHANGE TABLE IS MEASURING THE DETECTOR

A `cdn_changed` table held 3,331 records, which reads like 3,331
infrastructure changes. The transitions were near-perfectly
symmetric:

    Normal -> Akamai        1388        Akamai -> Normal        1329
    Normal -> Cloudfront     296        Cloudfront -> Normal     300

2,717 of the 3,331 are two values swapping back and forth. That is
the detector crossing its own threshold repeatedly, not the
infrastructure moving. What actually changes reachability is a
ONE-WAY transition - a host that left an edge and did not return is
directly reachable - and there were zero of those.

> **Rule: when a change table's transitions come in near-equal
> opposite pairs, count the DIRECTION, not the total. A symmetric
> table measures the detector's threshold, not the target.**

The same pass is worth running for `technology_changed`: diffing each
record's `old_value` against its `new_value` yields what the host
GAINED, and the entries that name a platform - not a JS library or a
security header - are the ones with a classic unauthenticated-read
surface. On one corpus that turned 760 records into eleven hosts, and
the highest-value one (`nepki.au.digicert.com`, Ruby on Rails) had
not appeared in any earlier round.

## A HOST NAMED BY AN IN-SCOPE RESPONSE IS NOT THEREBY IN SCOPE

An OIDC discovery document served by an in-scope host named TEN
endpoints, and all ten pointed at the IdP vendor's own hosting domain
- not the client's domain. Calling any of them sends traffic to a
third party who never scoped you.

Record them and do not call them, and make the decision auditable:

  - print the endpoints SPLIT into in-scope and out-of-scope, and
    store both lists in the artifact,
  - put an assert-in-scope check inside the request function itself,
    so a typo cannot leak a request to the vendor's infrastructure,
  - and state in the output which endpoints you declined to call and
    why.

This is the same rule the earlier scope deviation taught (an
off-scope host probed once for reflection), except now it is applied
BEFORE the request instead of after.

> **Rule: scope is a property of the host you send to, never of the
> document that mentioned it. Split the endpoint list, assert in the
> request path, and write down what you refused to call.**

## A FIELD NAME IS NOT A CREDENTIAL AND A HOST IS NOT A LEAK

Two disclosure markers fired on real responses and both were false
positives of the marker itself:

  - a `creds` pattern matched a `password` attribute inside a page's
    OWN form markup - no value, just the field,
  - an `internal_host` pattern matched `confluence.gtie.dell.com`
    inside a page served BY `ak-confluence.gtie.dell.com` - the
    product's own canonical URL, naming itself.

Both are the same error: matching a NAME where the finding needs a
VALUE or a DIRECTION. The control is cheap and settles it every
time - a credential marker must match a value after an assignment,
and an internal-host marker must match a host that is not the one
serving the page.

> **Rule: a disclosure marker must match data, not a label. If the
> match can be satisfied by the page's own markup or its own hostname,
> it is not a marker.**

And the same all-four-hosts control decides whether an environment
exposure is real: reading the same seven paths on prod, uat, test and
dev returned 7/7 identical on every host, which turned "UAT exposes
an Okta tenant" into "this is how the vendor exposes all four".

## A UNIFORM ANSWER ACROSS A MATRIX IS THE INSTRUMENT, NOT THE TARGET

A 16-value matrix came back with the same empty result for every
value. It reads as a behaviour change ("the parameter stopped being
honoured"). It was a rate limiter. The same three values, two seconds
apart, were fine.

Then, after pacing was added, the SAME empty answer appeared again -
this time because the harness read the redirect target through
`dict(e.headers)`, and on a NoRedirect handler urllib raises
`HTTPError` even for a 302, where that conversion LOSES the header
keys. Reading `e.headers.get("Location")` directly produced the value
every time.

> **Rule: before concluding anything from a uniform result, make the
> instrument produce a KNOWN-GOOD answer once. If you cannot show the
> tool seeing a value it must see, the uniform result is about the
> tool. And when fixing the instrument still gives the uniform
> answer, suspect the instrument a second time.**

## "MY SEARCH FOUND NOTHING" IS NOT "THE THING DOES NOT EXIST"

A search for call sites of a function looked for a variable assigned
from a module id and then searched for one specific property on it.
It found nothing, and the conclusion "no caller exists" was about to
be written.

A second, independent search - a direct count of the property in the
whole file, where the alias turned out to be a name the first pattern
had never captured - also returned zero. The two agreed **for
different reasons**, and that agreement is what made the verdict safe
to state.

> **Rule: a negative finding needs two searches that agree, not one
> search that came back empty. State which two, and why they are
> independent.**

## DEAD CODE IS NOT ATTACK SURFACE

A redirect function with a demonstrably weaker guard was found,
exported, and never imported by any bundle. The gap was real; the
reachability was zero.

A code-quality gap in code that ships but is never called is not a
vulnerability: a caller must be ADDED for it to become reachable, and
adding a caller is a future change, not a present weakness. The
honest verdict is NOT REPORTABLE, and the note says which two facts
decide it - every other export of that module IS consumed, and the
one call site that exists routes through the guarded function.

> **Rule: a guard gap is only a finding if you can name the input
> path that reaches it. Otherwise report the gap as a note and say
> plainly that it is dead code.**

## A REMAINDER TAKEN AGAINST THE WRONG DENOMINATOR INVENTS WORK

A coverage ledger reported `unread_remainder: 22` for a 95-host
shortlist. It was computed as `total - read_in_xq - read_in_xz`, which
is arithmetically true and operationally meaningless: the 22 it named
were **exactly the hosts rounds 1-3 had already read**. The number
looked like pending work and was in fact finished work.

The correct denominator is the set you set out to work through, not
the universe it came from:

    shortlist                     95
    already requested in 1-3      22   <- DONE, not pending
    never requested               73   <- the work set
      read in XQ                  10
      read in XZ                  63
      still unread                 0   <- the real remainder

> **Rule: a remainder must be taken against the SET OF WORK, and the
> work set is defined by what has NOT been done - not by the size of
> the collection you drew it from. Before reporting any remainder,
> assert that the hosts it names have not already been read.**

This is the same failure as counting a host as tested because its name
appeared in a corpus-description artifact: both report a number that is
about bookkeeping rather than about the target. A coverage claim is a
measurement and needs the same treatment as any other measurement.

## A 200 WITH A CONSTANT BODY IS A DISTRIBUTION MECHANISM

Nine paths on one host returned 2,463 bytes each; every asset path on
another returned 346,689 bytes. A depth ranking or a reachability
count would have called both "9 reachable endpoints".

Identical length across every path is a client-side-routed shell, a
catch-all, or an edge default page - not a route. The tell is cheap:
compare the LENGTHS across paths before believing the status.

> **Rule: constant body length across unrelated paths means nothing
> is actually routed. Record the length, not just the status, and
> treat a constant as a shell.**

## 200 ON A MUTATING ROUTE IS NOT SUCCESS

An attachment utility answered **200** to `POST /api/agile/deletefile`,
`replacefile`, `uploadfile`, `oslangupdate` and `relmappingupdate` -
with no session. The body, which is the only place the truth was:

    {"processCompleted": false,
     "errorMessage": "Invalid User Session, please refresh or retry"}

**The authorisation check existed and worked.** But it reported refusal
under a 200, so a client keying on the status code reads a refused
operation as a successful call.

Two rules, and they point in opposite directions - which is why both
are here:

  > **Rule (verdict): when a state-changing route answers 2xx, read the
  > BODY before concluding anything. `200` plus a refusal field is a
  > refusal. Calling it "unauthenticated file deletion" because the
  > status was 200 is a false statement about the target.**

  > **Rule (reportability): an API that reports failure as success has
  > an observability defect, not a security impact. It is NOT
  > reportable, and the honest note says so in the impact terms - C/I/A
  > all none - rather than dressing it up.**

And the cheap way to learn which it is: send an EMPTY body first. A
`415 Unsupported Media Type` on an empty POST means the app wants a
Content-Type you did not send, and the preceding `400` was the absence
of a parseable body rather than a rejection of its content.

## A ROUTE THAT FETCHES NEEDS AN OUT-OF-BAND TEST, NOT AN INFERENCE

A route literally named `remotefilecheck`, documented with a `url`
parameter, answered `true` to six values including a name that cannot
resolve and the EMPTY STRING. The tempting reading - "it fetched all
six" - is unsupported on its face, because a non-resolving name cannot
have been fetched successfully.

The separator is a listener you control plus a control URL:

  - start a local listener, prove it works with a self-test (an
    unrelated bug there would read as "the target did not connect"),
  - point the route at it,
  - and point it at a name that cannot resolve.

Zero connections + a silent control = the route places no request, and
the constant `true` is not a fetch result. **The lead died for a
measured reason rather than by assumption** - which is the difference
between closing a lead and guessing about it.

> **Rule: "does it fetch" is an observable, not a hypothesis. Use a
> loopback listener with a self-test and a non-resolving control.**

## A HIGH PATH COUNT IS NOT A HIGH SURFACE COUNT

Two hosts were ranked first in a 71,145-host worklist by recorded
endpoint count - 1,816 and 958 paths. Both were empty:

  - the 1,816 were ONE investor-relations site's static theme assets,
    every path under a content-hash directory, and every class that
    carries risk (api, auth, admin, user) held ZERO,
  - the 958 fell into no class at all, behind a 403 shell.

> **Rule: rank a worklist by path count PER CLASS, not per host. A
> count per host measures how thoroughly a static tree was crawled.**

Corollary: an application that size ALWAYS has some paths in the api,
auth, admin or user classes. Zero in all four is the tell.

## A GATED GRAPHQL ENDPOINT: PROBE THE ORDER, NOT THE SCHEMA

A GraphQL endpoint answered every unauthenticated request with a key
error. The useful question is not "is introspection on" - it is
**which side of the gate validation happens on**, and one query
answers it:

    no key + a WELL-FORMED query    -> key error  -> gate first
    no key + a BOGUS field          -> key error  -> gate first
    no key + a BOGUS type           -> key error  -> gate first
    no key + a SYNTACTICALLY BROKEN query -> key error  -> gate first
    no key + INTROSPECTION          -> key error  -> gate first

If every one of those gets the same auth error, the query is never
parsed without a key: **the schema is not reachable, and "is
introspection enabled" is UNTESTABLE from outside.** Say that, rather
than reporting "introspection could not be disabled".

If instead a bogus field returns "Cannot query field X on type Y",
validation ran FIRST and the schema is partially enumerable - that IS
escalatable.

> **Rule: five queries - one well-formed, one bogus field, one bogus
> type, one malformed, one introspective - separate "gated before
> validation" from "validated before gating". The order is the
> finding, not the schema.**

### And count the DISTINCT messages

Twelve requests across absent, empty, junk, malformed and alternate
header shapes produced **two** distinct messages. The count itself is
the measurement:

  - eleven `x-api-key` shapes -> one message. No credential oracle.
  - one `Authorization: Bearer` -> a DIFFERENT message, because it is
    a different auth scheme.

That last one discloses which auth headers the endpoint supports. It
carries no impact and should be recorded as measured, not reported as
a finding - but a reader deserves to know the two schemes are
distinguishable rather than reading "one auth error" and assuming
they are not.

## A SHELL NAMES ITS OWN API

A 99 KB application root with no login wall and **zero forms** is not an
application - it is a shell. Every guessed API path returned 404, and
what the root DID name was:

  - two scripts, both on other hosts,
  - one internal link,
  - and `https://apis.indeed.com/graphql` in its configuration.

The tell that the API is elsewhere: unknown paths answer with a
**GraphQL-style error envelope** (`{"errors":[{"message":"No
endpoint GET /graphql."}]}`) rather than an HTML 404. A host that
speaks its API's error format while not being that API is a front end
pointing at another host.

> **Rule: read a shell's own configuration for the API host before
> guessing path shapes. And when a host answers in a framework's error
> envelope, the real endpoint is a sibling host.**

## AN ERROR-PAGE SIGNATURE FIRES ON EVERY VENDOR

A host answered `"Access Denied"` to POST, `"Unsupported Request"` to
PUT and used `&#58;` entity encoding. All three are textbook S3 error
phrasing, so the classifier called it a bucket.

The `Server` header said **`AkamaiNetStorage`**. `&#58;` is HTML-entity
encoding for `:`, which Akamai's error pages use too; "Access Denied"
and "Unsupported Request" appear in several vendors' edge responses.

Rules:
- **Classify an edge by the `Server`/`Via` header, never by error-page
  wording.** Wording is shared across vendors by policy and by copy.
- Any signature set built from strings must be run against a control
  from a DIFFERENT vendor before it is believed. `&#58;` proves nothing.
- `PUT` -> `501 Unsupported Request` + `Server: AkamaiNetStorage` =
  a CDN origin storage endpoint. A route recorded on such a host was
  crawled alongside an app that CALLS the CDN; it is not an object in
  it, and 404-ing identically to the impossible control proves that.
- A **401 with no `WWW-Authenticate`** is an edge refusing, not an app
  asking for a login. The `TS\u2026` `Set-Cookie` is F5 TrafficShield;
  `/health` answering `OK` in 2 bytes is the load balancer's own check.

- **A public container registry whose project is flagged public by the
  registry itself.** `metadata.public: "true"` is the owner saying
  "publish this". A registry that is public on purpose, holding only
  config TEMPLATES and EMPTY credential slots, is a note — not
  "unauthenticated access to a private registry". See
  `hunt-container-registry`.
- **A public API specification for a service that no public host
  serves.** Read the spec, then probe the documented base path on
  every candidate host. A spec for a private service is documentation,
  not an exposed API.
- **A verbose error page with no exploit behind it.** A Struts
  `devMode` stack trace is Low; the same page on a deployment that
  evaluates OGNL is Critical. Test it, do not assume. See
  `hunt-verbose-error-pages`.
- A reflection that only exists in a WAF interstitial, a self-redirect
  `Location` header, or a fixed tracking pixel.
- A `Location` header that echoes the request URI. That is not an open
  redirect unless the AUTHORITY changes or the response can be split.
- An encoded echo. `&lt;script&gt;` is correct output encoding.
- A hang, an error, or a constant response regardless of input. That
  proves no network request is made.
- A 200 carrying an error envelope. A status code is not evidence.
- A body scanner's verdict of "no reflection" when the page's own
  JavaScript reads `location.search` into a DOM sink. That path is
  invisible to a body scanner.

## RATE LIMITS AND WAFS ARE DIFFERENT DEFENDERS

- Classify every non-200 as RATE-LIMITED / WAF / APPLICATION, not as a
  failure. A 429 is *untested*.
- Wait the limit out BEFORE each request, not after a failure. Poll
  until a probe returns something other than 429.
- A WAF 403 with an `X-Iinfo` header and an Imperva body is a
  different defender from an application 200 that returns
  `Error: ... is not a fully qualified public domain name`. Record
  which layer answered.
- A WAF block means the endpoint is NOT TESTABLE, not that it is safe.
  Vary the payload SHAPE to get an observation: different tag,
  different case, no event handler, entity-encoded, a lone quote, a
  lone angle bracket, a plain marker. The lone quote and the plain
  marker are the most useful probes.

## PROOF OF EXECUTION MUST BE OBSERVED

- A negative browser result proves nothing until the alert hook is shown
  to work. Fire a known-executing control page FIRST.
- A payload can reach the DOM and still not fire. `src=""` loads fine so
  `onerror` never runs - use a non-resolving host.
- An `http://` beacon fired from an `https://` page is blocked as mixed
  content, so "no beacon hit" is not evidence of no execution. Use an
  in-page marker read back from the same session.
- A same-origin `fetch()` from the injected handler is the strongest
  proof and needs no network setup.

## BEFORE WRITING A REPORT

Run `triage-validation` (7-Question Gate). One wrong answer = kill
that finding and move on. It does NOT stop the engagement - every other
class is still pending.

Then `report-writing`.

**Run the gate MECHANICALLY, and make the gate's own over-claim scan
context-aware.** A phrase grep for `critical` flags a report that says
*"this is an information-disclosure finding, not a critical one"* — and
that sentence is the author being honest about the boundary, exactly
like a report that says "this is NOT request smuggling". A severity
word inside a NEGATION is not a claim. Flag the word only when it is
NOT preceded by a negator, and flag the severity ROW separately.

**Make the report-directory verifier COUNT-INVARIANT.** A verifier that
asserts "exactly 12 reports" or "exactly 25 findings" breaks the moment
a later campaign files a legitimate report — and then the verifier
fails for the wrong reason and the real signal is lost. Assert the
INVARIANT instead: at least one live finding per report file, the audit
artifact's totals agree with the directory, and the count is at least
the baseline. Reuse the structural parser from `report_audit.py` rather
than re-implementing the report shapes — one source of truth for what
a report looks like.

**A report may only be written after the reportability verdict, never
before.** The file in `reports/` IS the claim. If the impact analysis
later says "not reportable", delete the file and move the evidence to
`evidence/`.

**A negative result is a result.** State the volume: requests sent,
surfaces examined, hits found. A count with no hits is evidence the
surface was covered. But a scan that examined NOTHING (candidate count
= 0) is BROKEN, not clean - fix the filter and re-run before quoting
it.

## WHEN TO STOP HUNTING A CLASS

- 5-minute rule: a target that answers only 401/403/404 everywhere
  shows nothing. Move on.
- One-hour rule: no progress on one target for an hour. Switch context.
- When the class's gate says "kill it", kill it and pick the next class.
  Do not keep hunting a bug that is not there.
- Hunt less-saturated classes when the obvious ones are dry: cache
  poisoning, mobile, business logic, race conditions, OAuth/OIDC
  chains, CI/CD.
