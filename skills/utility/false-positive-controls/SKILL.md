---
name: false-positive-controls
description: "Use when verifying a web candidate before reporting."
---

# False-positive controls

Prove or kill a live web candidate with a **same-run control**, not a canary-only
check. Applies to every candidate produced by a sweep, scanner or recon DB:
redirect params, reflections/XSS, GraphQL/introspection exposure, leaked keys,
subdomain takeover.

Every claim below is a comparison, and the comparison only counts when the
control was captured in the same run as the payload — otherwise anything
unrelated that changed between runs gets blamed on the input. This is what turns
a 2,000-line sweep into a short report of real things, or an honest "nothing
here".

## Control-per-claim table

| claim | control you must fetch in the same run | what the control kills |
|---|---|---|
| open redirect / SSRF via a "go here next" param | the untouched original URL | captive/splash portals that 30x to a fixed host no matter what the param says; an archived value that already redirects |
| the param is honoured at all | original value vs canary value, comparing status **and** `Location` host | params that are parsed and then ignored |
| reflected XSS | same URL with a harmless token, plus a search for that token in the untouched body | markers that occur naturally on the page |
| endpoint still reachable | plain request, no payload | WAF/bot blocks read as "no reflection" / "no redirect" |
| unauthenticated access | a minimal **well-formed** request, not a malformed one | a 4xx raised by a body parser/sanitiser before auth ran |

Capture the control first. A test whose control redirects, blocks, or errors
before the payload is sent has produced nothing.

## Matching rules that decide the verdict

- **Match the exact hostname, never a substring.** If the canary appears in the
  final URL *because your payload sits in that URL's query string*, nothing was
  proven — `urlsplit(final).hostname` must equal the canary host. A `*.canary.tld`
  subdomain is the vendor's own host, not your payload.
- **A value echoed into a response header is inert.** `Location`,
  `Content-Disposition`, `Refresh` are consumed by the browser as URLs or
  instructions; angle brackets there never become markup. Only a body sink can
  become XSS. Percent-encoding in that header (`<`→`%3C`, CRLF→`%250d%250a`, a
  `//host` value staying inside the param) is evidence of *safe* handling, and the
  absence of an off-host `Location` is a clean close, not a weak signal.
- **Follow the whole chain and compare the last hop's host**, not the first
  `Location`. Several hops that each stay same-origin are still not an open
  redirect.
- **Test each payload character separately** — one request per `<`, `"`, `'`, `\`,
  CRLF — so a filter that eats one character does not hide the behaviour of the
  others.

## Blocked is not clean

When requests start returning 403/406/429 mid-test, replay the **harmless version
of the identical URL** before concluding anything:

- payload-triggered (`?p=x` → 200, `?p=<svg onload=…>` → 403, but bare `<` allowed)
  = an edge rule; it tells you nothing about the sink;
- uniform block including the control = your client/IP was blocked and the
  endpoint is **untested**.

Record `blocked` / `unreachable` as their own verdicts, separate from `clean`.
Pooling them into "tested, no issue" overstates coverage; naming them honestly is
what makes the clean rows believable.

## Defaults that are not findings

- **Unauthenticated introspection is the framework default** on Magento 2
  `/graphql`, Apollo Federation (`_service`, `_entities`) and IdP consoles.
  Replay the sensitive queries with no session and read the answer: an
  authorization error with `data: null` means authz holds → informational. Only a
  200 carrying the fields is a finding. For Magento the assert set is
  `{customer{email}}`, `{customerCart{id}}`, `{customerOrders{items{number}}}`;
  `storeConfig` returning `base_url`/currency is public data.
- **A valid credential is not a capability.** An `AIza…` key that resolves to a
  real project (the error names the project instead of "API key not valid") only
  matters if an API is enabled on it. Enumerate a handful (youtube-data,
  customsearch, translate, geocode, staticmap, timezone, places); all answering
  "not activated"/"disabled" means it unlocks nothing → informational.
- **A cloud error page is not a takeover.** Azure: claimable only with a dangling
  CNAME to a dead resource and **no** `asuid` TXT. An `asuid` TXT means the binding
  still belongs to the owner even when the app behind it is gone and Azure serves
  its own "404 Web Site not found". Quote the digest you read in the verdict so
  nobody re-does the lookup.
- **Status code alone is never a bypass.** 200 where the baseline was 403 with a
  byte-identical body is not access.

## Marker discipline for the token itself

Build the marker so it survives escaping **contiguously** — construct the raw
form from the token, never from a random suffix appended separately, or an
escaped reflection splits the token and reads as `absent`. Prove the detector can
fire (a known-local page or a known-reflecting param) before trusting any zero it
returns; a detector that reports `raw=0` while unable to report anything is worse
than none.

## Deliverable shape

One file per stage, in `reports/`, `<topic>-<YYYYMMDD>.md`. Keep the passive
candidate sweep and the live confirmation as **separate** files — they answer
different questions, and merging them lets readers mistake a candidate for a
proven row.

For a parameter sweep the operator wants: one line per finding, the **full URL
including the parameter and its value**, grouped by platform then program, and no
per-line commentary. Keep a short header (scope, method, counts) and one honest
caveat block for blocked/unreachable rows.

## Related

Vendor-specific procedure for the redirect-parameter sweep and Watch DB triage
lives in `hunt-redirect-params`, `watch-hunt`, `triage-validation` and `hunt-xss`
— all user-owned, so patch them only in a foreground session. Scripts implementing
the control-first differentials: `/opt/watch/scripts/bb4_confirm.py`,
`bb4_verify_hits.py`, `bb4_diff.py`, `watch_xss_probe.py`, `watch_redirect_chain.py`.

Writing verdicts back into the Watch `Finding` collection (which field names
MongoEngine accepts, why the row set changes mid-session, how to rebuild a
deleted candidate list from `Urls`): `references/watch-finding-writes.md`.
