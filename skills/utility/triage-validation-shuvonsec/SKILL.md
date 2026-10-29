---

name: triage-validation-shuvonsec
source_name: triage-validation
description: Finding validation before writing any report — 7-Question Gate (all 7 questions), 4 pre-submission gates, always-rejected list, conditionally valid with chain table, CVSS 3.1 quick reference, severity decision guide, report title formula, 60-second pre-submit checklist. Use BEFORE writing any report. One wrong answer = kill the finding and move on. Saves N/A ratio.
---

# TRIAGE & VALIDATION

One wrong answer = STOP. Kill it. Move on.

> "N/A hurts your validity ratio. Informative is neutral. Only submit what passes all 7 questions."

---

## WRITE A REPORT ONLY FOR A BUG YOU ARE SURE OF

**A `.md` report in the reports directory is a CLAIM THAT THIS IS A REAL
BUG.** Do not write one for a finding that is a candidate, a primitive
without impact, a negative result, or an informational note. Writing the
file is the commitment; an uncommitted finding lives in an evidence or
notes directory, not in `reports/`.

The trap is real and it happens like this: a hunt finds a genuine
primitive (a working XSS, a confirmed SSRF), the impact analysis is
still open, and the report gets written while the verdict is still
"probably reportable". Then the impact analysis finishes and says "not
reportable" - and a file that reads like a finding is already sitting
next to the real ones.

**Decide reportability BEFORE writing the file, not after.** Concretely:

1. Run the 7-Question Gate and the Pre-Severity Gate to completion.
2. Run the three Q6 checks below (link-deliverable source, page content,
   reachability).
3. If any of them fails, the finding is a NOTE. Write it to
   `evidence/NOTE-<slug>.md` - outside `reports/` - with "not
   reportable" and "must not be submitted" stated up front.
4. Only when every gate passes does the file belong in `reports/`.

**When a report already exists and the verdict flips to not-reportable,
delete it from `reports/`** and move the evidence to `evidence/`. Do not
leave it with a warning header inside `reports/`: a warning header still
ships a file that looks like a deliverable, and the next reader (or a
triager) skims the title and the severity row.

A verifier for a note asserts the OPPOSITE of a report verifier: that the
note says "not reportable", carries no severity claim, and that
`reports/` contains only real-bug reports. That last check is the one
that catches this mistake.

**A report may only be written AFTER the reportability verdict, never
before.** The file in `reports/` IS the claim. If the impact analysis
later says "not reportable", delete it and move the evidence to
`evidence/`.

**AND THE OTHER DIRECTION MATTERS TOO: a finding that PASSES the gate
MUST get a report file.** The gate is not a filter that silently
discards things — it is a decision procedure, and a "reportable" verdict
with no file in `reports/` is an unfinished job. When the gate says
reportable, write the report in the same pass:

- a title that names the class, the endpoint and the impact
- a severity row, a CVSS 3.1 vector, and a CWE
- the affected asset (host, path, product, version)
- copy-pasteable reproduction steps
- the impact, AND an explicit statement of what the attacker CANNOT do
- remediation
- the evidence files and the verifier that re-measures the claims
- a scope note (methods used, no credential sent, no mutating request)

Then run the report verifier and keep it green. "The bug is real but I
did not write it up" is the worst outcome of all: the work is done, the
proof exists, and nothing is delivered.

**Run the gate MECHANICALLY, and make the gate's own over-claim scan
CONTEXT-AWARE.** A phrase grep for `critical` flags a report that says
*"this is an information-disclosure finding, not a critical one"* — and
that sentence is the author being honest about the boundary, exactly
like a report that says "this is NOT request smuggling". A severity word
inside a NEGATION is not a claim. Flag the word only when it is NOT
preceded by a negator (`not`, `no`, `never`, `isn't`, `rather than`,
`instead of`, `nor`), and flag the severity ROW separately. The same
rule applies to a whole directory: never grep for a kill-phrase and
call a hit a withdrawal.

**Make a report-directory verifier COUNT-INVARIANT.** A verifier that
asserts "exactly 12 reports" or "exactly 25 findings" breaks the moment
a later campaign files a legitimate report — and then the verifier fails
for the wrong reason and the real signal is lost. Assert the INVARIANT
instead: at least one live finding per report file, the audit artifact's
totals agree with the directory, and the count is at least the baseline.
Reuse the structural parser from the directory audit rather than
re-implementing the report shapes in every verifier — one source of
truth for what a report looks like.

### The directory rule needs a STRUCTURAL audit, not a phrase grep

To keep "only real bugs live in reports/", the directory needs a
mechanical check. The first version of one matched kill-marker
PHRASES anywhere in the file, and it produced false flags on the best
reports in the directory:

- a careful findings summary says "this is NOT request smuggling" and
  "no confirmed vulnerability in any of the three classes" precisely
  because it is being honest about the boundaries of what it found
- a phrase in a NEGATION is not a withdrawal

So the audit has to be STRUCTURAL:

1. does the file DECLARE findings - `## F<n>`, or `### <n>.` under a
   `## Findings` section, or the single-finding shape
   (Summary + `**Severity:**` + Reproduction)?
2. is at least one declared finding NOT marked not-reportable?
3. does the file withdraw ITSELF as a whole ("this is not a report",
   "must not be submitted")?

A file passes on all three. Negated phrases in the prose are ignored
on purpose.

**Recognise the real report shapes, or you will flag your best work.**
Three shapes are in use and all of them are reports:
- multi-finding: `## F1 — ...`, `## F2 — ...`
- summary: `## Findings` then `### 1. ...` .. `### 6. ...`
- single-finding: `## 1. Summary` + `**Severity:** Medium` + a
  Reproduction section, with NO `F<n>` label anywhere

The severity line is `**Severity:** Medium` (colon INSIDE the bold),
not `**Severity**: Medium` - match both. And a `###` section under a
single-finding report is a SUB-section of that finding, not a finding
of its own; only count `###` items when the file has a `##` Findings
section.

**Also: a report can be honest about a NEGATIVE and still be a
report.** "The smuggling hypothesis is EXCLUDED on the evidence
available rather than merely untested" is the sentence that makes a
report trustworthy. Never delete a report for containing a negative
result - delete it for containing no finding.

---

## THE 7-QUESTION GATE

Ask IN ORDER. One wrong answer = STOP immediately.

---

### Q1: Can an attacker use this RIGHT NOW, step by step?

Complete this template:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body — copy-paste ready]
3. Result:  I can [read / modify / delete] [exact data shown in response]
4. Impact:  The real-world consequence is [account takeover / PII read / money stolen]
5. Cost:    Time: [X minutes], Capital: [$0 / $X subscription required]
```

**If you CANNOT write step 2 as a real HTTP request → KILL IT.**

**A window-based "is there a dangerous char near the marker" check is NOT a verdict.** It counts the attribute's own delimiters and produces constant false positives. Every candidate needs a DIFFERENTIAL test: fetch the same URL with a benign value, fetch it with the breakout payload, and compare the two DOM profiles. A REAL finding needs a DELTA — a NEW element, a NEW event-handler attribute, a raw `<` inside a PARSED attribute value, or the payload bytes appearing RAW. Parse with a real HTML parser, never with a regex over the raw body. A tag the payload did not create (an `<iframe>` the template always emits) is NOT a finding.

**A server-side echo that is escaped or double-encoded is not a clean result.** It only means the body scanner saw nothing. Before killing an XSS candidate on the basis of an encoded echo, check whether the page's own JavaScript reads `location.search` and writes it into a DOM sink — landing-page platforms (Eloqua, Marketo, Pardot, HubSpot) ship a "fill this form from the query string" script that copies any parameter into a same-named field and a form script that writes it into `innerHTML`. That path is invisible to a body scanner entirely.

---

### Q2: Is the impact on the program's accepted impact list?

Go to the program page. Find "Vulnerability Types" or "Out of Scope."

Common tiers:
- **Critical**: Any-user ATO without interaction, RCE, SQLi with data exfil, admin auth bypass
- **High**: Mass PII exfil, privilege escalation, internal SSRF with data, stored XSS all users
- **Medium**: IDOR on specific user non-critical data, XSS on sensitive page requiring click
- **Low**: Non-sensitive info disclosure, clickjacking with PoC

**If your bug maps to a listed exclusion → KILL IT.**

---

### Q3: Is the root cause in an in-scope asset?

Confirm:
- Vulnerable domain is on the in-scope list (not `*.internal.target.com`)
- It's a production asset (not staging/dev unless explicitly in scope)
- It's not a third-party service the company just uses (not Stripe, Salesforce, Google Auth)

**If out-of-scope → KILL IT.**

---

### Q4: Does it require privileged access that an attacker can't realistically get?

- "Admin can do X" = centralization risk = **KILL IT** (on 99% of programs)
- "Non-admin can do X that only admin should do" = valid
- "Requires physical access / MFA device" = usually invalid
- "Requires compromised victim account to work" = questionable, low severity at best

---

### Q5: Is this already known or accepted behavior?

Search:
1. Program's HackerOne/Bugcrowd disclosed reports: Ctrl+F endpoint name + bug class
2. GitHub issues on target repo: `is:issue label:security ENDPOINT_NAME`
3. Changelog/CHANGELOG.md — does it mention this behavior?
4. API docs / design docs — is it documented as intended?

**If acknowledged/design decision → KILL IT.**

---

### Q6: Can you prove impact beyond "technically possible"?

- XSS → show actual cookie theft or session hijack, not just `alert(1)` or `alert(document.domain)`
- SSRF → hit an internal endpoint that returns data, not just DNS ping
- SQLi → show actual data exfil from a real table, not just error message
- IDOR → show actual other-user's data in response, not just a 200 status code

**If you can only show "technically possible" → DOWNGRADE severity, not kill.**

**A PARAMETER THAT IS ACCEPTED IS NOT A PARAMETER THAT IS USED.** This is the single
most common false positive in a parameter hunt, and it produces a textbook-looking open
redirect that is not one. The server accepts the value, echoes it, and then discards it:

```
GET https://adh.indeed.com/?next=https://offsite-check.example.org/pwned
  -> 302  /user/login?next=%2F%3Fnext%3Dhttps%253A%252F%252Foffsite-check.example.org%252Fpwned
```

That LOOKS like an open redirect. It is not — the off-site URL is dropped before the
identity step. Prove it by checking, after the chain:

| Where the value might persist | How to check |
|---|---|
| a session cookie | dump every `Set-Cookie` from the chain and search the values |
| the HTML of the next page | search the rendered body |
| the OAuth `state` parameter | decode it — if it is a random token, the value is not in it |
| the post-login callback | fetch the callback without a session and see where it lands |

If the value is in none of them and the callback lands on `/`, then **no request is ever
made to the attacker's host and no code or token is ever delivered there.** Not an open
redirect. The same pattern shows up as a 302 to the application's OWN error page
(`/Error/ExceptionError?adminExceptionId=93311`) — an application exception being
reported, not a redirect to the supplied URL. Follow the chain before you call it.

**A CREDENTIAL-SHAPED LINE IS NOT A CREDENTIAL.** A line-level secret scanner reports
`API_KEY=` as a five-character non-empty value, and a config template full of
`MySQLPassword=""`, `MasterSecret=""`, `APIKey=""` then reads as a wall of secrets. A REAL
credential is an assignment whose VALUE is a non-empty secret-shaped string. Classify
every hit into three buckets — populated / empty-slot / not-an-assignment — and report
the populated count alone. The empty bucket is a runtime injection point, and the third
bucket is a `Maintainer` label or a `COPY` build line.

**A PUBLIC REGISTRY IS PUBLIC ON PURPOSE.** If the registry's own project metadata says
`public: "true"`, there is no control that should have applied and did not — that is a
configuration, not a misconfiguration. And a public API SPEC for a service that no
public host serves is documentation of a private system, not an exposed API. Probe the
documented base path on every candidate host before you call either one a finding.

**Q6 is where a proven XSS primitive most often dies, so run these three
checks before you write a word of the report. They are cheap and they
decide the outcome:**

1. **Is the source a LINK-CARRIABLE one?** The source decides the
   deliverability, and most sinks are fed by a source a link CANNOT
   set. `location.search`, `location.hash`, `document.referrer` and
   `location.href` are all link-carriable. A request HEADER is not:
   `navigator.userAgent` is the `User-Agent` header, and a victim
   clicking a link sends THEIR OWN browser's UA, not the attacker's.
   So "reflected XSS via the User-Agent header" is proven execution
   with NO link-deliverable path. It needs a UA-switcher extension or
   an attacker-controlled proxy - both real, both preconditions the
   victim satisfies independently of the link. Test it rather than
   assume: load the page with a `#payload` and with a `?payload` in a
   real browser and look for injected elements. If neither fires, say
   so in the report.

2. **What is ON the page?** The ceiling on an XSS impact is the
   page's value. Measure it: `document.cookie`, `localStorage` keys,
   forms, and what a same-origin `fetch()` can actually read. A
   static demo page with no cookie, no storage, no form and no
   authenticated API has ZERO confidentiality impact - so the honest
   CVSS is `C:N/I:N/A:N`, and a "Low confidentiality impact" claim is
   unsupported. `C:L` requires something to read.

3. **Can the victim even reach the page?** A host behind a broken
   certificate chain shows a full-page interstitial and the script does
   not run until the user clicks through a warning about an untrusted
   root. Measure the chain with `openssl s_client` and read the
   `Verify return code` - do NOT assume "these are demo pages so they
   must be expired". The codes mean different things:
   - `0` = the browser loads it silently - the host is fully reachable
   - `10` = the leaf certificate is expired
   - `19` = the chain ends in a self-signed root that is in no trust store
   - `20` = the issuer is unknown (usually a revoked or demo root)

4. **Is the asset actually linked, and from where?** Reachability
   decides whether a victim ever lands on the page. Check the LIVE
   site, not only the archive. An archive CDX query that returns 0
   proves nothing about the live site: the page may have been created
   after the capture, may sit behind a redirect, or the query's
   `filter=` may apply to a field it does not filter. In one measured
   case an archive query said "0 links to these demo pages" while the
   live knowledge-base page linked 42 of them, 10 of them affected -
   and a draft report had already used the archive answer as a
   discount reason.

**Never assert that a page is orphaned from an archive search.** Fetch
the live page that would plausibly link it, follow the redirects, and
count the real `href`s. And a "negative" reachability result is worth
nothing unless the search covered the place the link would actually
be.

**A finding that is a real defect with zero impact and a non-link
deliverability precondition is an INFORMATIONAL note, not a Low-severity
vulnerability.** Say exactly that in the report rather than inflating it
to Low to look reportable - a triager who checks will find the missing
impact and mark it N/A, which costs more than not submitting.

---

### Q7: Is this a known-invalid bug class?

Check the NEVER SUBMIT list below. If it's on this list without a chain → **KILL IT.**

---

### Q8: Identity check — which session found this, and does it survive?

For any finding made under an authenticated hunt, record the answer to each:

```
1. Session ID:        [12-char BBHUNT_SESSION_ID hash from audit.jsonl]
2. Identity:          [low-priv user A / high-priv user B / API key / etc.]
3. Anonymous repro:   Does the same request work with NO auth header?
4. Cross-identity:    Does it work under session B with the same data scope?
5. Stale-cred repro:  Does a logged-out / expired session still get the data?
```

Why this matters:
- **IDOR / BOLA**: must work with session A reading session B's data — if it
  only works with no auth, that's "missing auth" not IDOR (different bug,
  different severity).
- **Priv-esc**: must work with low-priv session reading high-priv data — if
  both sessions can already see it, no bug.
- **Auth bypass**: must work *without* a valid session — if it stops working
  when you log out, you've found a permissions issue, not a bypass.
- **Always check both directions**: a finding that only reproduces under
  one identity is often a real, scoped permission boundary, not a vuln.

`audit.jsonl` entries are tagged with `session_id`. Re-run the request
under each identity and confirm the bug holds before writing the report.
This is the most common reason "confirmed IDOR" findings come back as N/A.

If you cannot answer the identity questions, treat the finding as unproven.
Blank answers auto-fail on auth-related findings.

---

---

## 4 PRE-SUBMISSION GATES

Run in sequence. ALL 4 must PASS.

### Gate 0: Reality Check (30 seconds)
```
[ ] Bug is REAL — confirmed with actual HTTP requests, not code reading alone
[ ] Bug is IN SCOPE — checked program scope page explicitly
[ ] Reproducible from scratch — can reproduce starting from fresh session
[ ] Evidence ready — screenshot, response body, or video
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] Can answer: "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data" (unless program pays for info disclosure)
[ ] Real victim: another user's data, company's data, financial loss
[ ] Not relying on victim doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title/endpoint
[ ] Searched GitHub issues for target repo
[ ] Read most recent 5 disclosed reports for this program
[ ] Not a "known issue" in their changelog or public docs
[ ] Google: "TARGET_NAME ENDPOINT_NAME bug bounty"
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact (not just 200 status)
[ ] Severity: matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
[ ] NEVER used "could potentially" or "may allow"
```

---

## NEVER SUBMIT LIST

Submitting these destroys your validity ratio.

```
Missing CSP / HSTS / security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR demonstrated)
Banner / version disclosure without working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil proof of concept
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO or OAuth theft chain)
OAuth client_secret in mobile app (known, expected)
SSRF DNS callback only (no internal service access or data)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (search, contact, login with Cloudflare)
Session not invalidated on logout
Concurrent sessions
Internal IP in error message
Mixed content
SSL weak ciphers
Missing HttpOnly / Secure cookie flags alone
Broken external links
Autocomplete on password fields
Pre-account takeover (usually — very specific conditions required)
```

---

## COMMON N/A CLASSES — KILL SIGNALS

These pass basic gut-check but consistently come back N/A. Each row has a **specific signal** that tells you to kill it *before* writing the report.

| Finding | Why it N/As | Kill signal — if you see this, stop |
|---|---|---|
| Reflected XSS | CSP blocks execution; sandbox context; no session access | Dalfox found `alert(1)` but no cookie in response; `Content-Security-Policy` header present |
| SSRF — DNS callback only | No internal data reached; programs require HTTP response with data | Interactsh/Collaborator got DNS ping but no HTTP reply with internal content |
| IDOR — own data only | Attacker == victim; no cross-account access proven | User ID in response matches your own test account |
| SQLi — error message only | WAF filtered or error is cosmetic; no data exfiltrated | Got DB error string but no actual table rows returned |
| CORS wildcard `*` | `*` blocks `withCredentials`; no PII actually exfiltrated | `Access-Control-Allow-Credentials: true` absent; credentialed request returns 403 |
| Rate limit missing — non-sensitive endpoint | Program only pays for rate-limit on auth/payment/OTP surfaces | Endpoint handles search, contact form, or sits behind Cloudflare |
| Nuclei `info` template match | Version detection, not exploitation | Template severity is `info`; no CVE PoC executed against live service |
| MFA rate limit (no lockout) | Impact depends on OTP brute-force succeeding — it usually doesn't | 15 requests returned 200 but no OTP code was accepted |
| Open redirect alone | Redirect is informational without token theft chain | No OAuth `redirect_uri` parameter; no auth code or token in the redirected URL |
| Auth bypass — admin precondition | Requires compromised admin to trigger; attacker can't get there | "Admin can do X on behalf of user" — attacker must already be admin |
| XSS via `alert(document.domain)` | Not proof of session theft | PoC shows domain popup only; no `document.cookie` exfil, no event listener |
| SAML metadata exposed | Disclosure only — aids attack but is not standalone impact | No private key or signing cert extracted; metadata is publicly documented by IdP |
| Verbose error page / devMode stack trace | The same page is Low in one deployment and Critical in the next | The OGNL probe found no evaluation AND the page leaks no path/host/IP/DSN/credential — then it is Low at best |
| Public container registry | Public on purpose is not a vulnerability | The registry's own metadata says `public: "true"`, and every credential slot is empty |
| Parameter accepted and echoed | Acceptance is not use | The value is in no cookie, no HTML, no OAuth `state`, and the callback lands on `/` |
| Credential-shaped line in a config template | A template is not a leak | The value after `=` is empty; a real credential has a populated value |

**Decision rule:** if your finding matches a kill signal → classify as `[INFORMATIONAL]`, do **not** run `/validate`, move on.

---

## CONDITIONALLY VALID — CHAIN REQUIRED

Build the chain first, prove it works end to end, THEN report.

| Standalone Finding | Chain Required | Valid Result |
|---|---|---|
| Open redirect | + OAuth redirect_uri → auth code theft | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils user PII | High |
| CSRF | + sensitive action (transfer funds, change email, delete account) | High |
| Rate limit bypass | + OTP/reset token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data returned | Medium |
| Host header injection | + password reset email uses injected host | High |
| Prompt injection | + reads other user's data (IDOR) | High |
| S3 bucket listing | + JS bundles contain API keys or OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim without their knowledge | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

---

## CVSS 3.1 QUICK REFERENCE

### Common Score Examples

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, any user, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft, stored | 8.8 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 8.6 | High | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Race → double spend | 7.5 | High | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| GraphQL auth bypass | 8.7 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT none algorithm | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

### Metric Quick Guide

| What you have | Metric | Value |
|---|---|---|
| Exploitable over internet | AV | Network (N) |
| No special timing or race | AC | Low (L) |
| Free account needed | PR | Low (L) |
| No login needed | PR | None (N) |
| Admin needed | PR | High (H) |
| No victim action | UI | None (N) |
| Victim must click | UI | Required (R) |
| Reads all data | C | High (H) |
| Reads some data | C | Low (L) |
| Modifies all data | I | High (H) |
| Crashes service | A | High (H) |
| Affects only app | S | Unchanged (U) |
| Affects browser/OS/cloud | S | Changed (C) |

---

## KILL FAST RULES

The goal is to QUICKLY disqualify bad leads so you hunt real bugs:

1. **5-minute rule**: If you can't fill in Q1's template in 5 minutes → move on
2. **Precondition count**: More than 2 preconditions simultaneously required → kill it
3. **Impact test**: "What does attacker walk away with?" — if nothing tangible → kill it
4. **Admin bypass**: "Admin can do X" is NEVER a bug → kill it immediately
5. **Design doc test**: If it's documented behavior → kill it immediately
6. **Rabbit hole signal**: 30+ min on Q6 with no reproducible PoC → kill it

---

## ANTI-PATTERNS THAT LOSE MONEY

```
Writing a report before confirming the bug exists (most common)
Submitting theoretical impact without proof
"The API returns more fields than necessary" (sensitivity matters — is it actually sensitive?)
Chaining A+B into one report when they're separate bugs (two separate payouts)
Reporting B saying "similar to A in my other report" — fresh Gate 0 for every bug
Overclaiming severity — triagers trust you less next time
Under-describing impact — triager doesn't understand why it matters
```
