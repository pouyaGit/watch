---
name: hunt-redirect-params
description: "Find redirect-style parameters on auth-flow endpoints across any bug-bounty target — no login required. Use when hunting open redirect, OAuth/OIDC redirect_uri hijack, or login/signup/logout/password-reset/SSO flows, or when asked to 'find redirect params' / 'find open redirects' / sweep many targets. The pattern: an auth endpoint carrying a 'where to go next' param whose name varies (redirect, redirect_uri, returnUrl, next, dest, goto, continue, callback, RelayState, …) and whose value may be plain, URL-encoded, or base64. Harvests param names + endpoints passively (Watch DB, gau/wayback/katana), mines them against a redirect-name wordlist, sweeps every bounty:true program in projectdiscovery/public-bugbounty-programs, then routes hits to hunt-open-redirect and hunt-oauth."
---

# hunt-redirect-params — redirect params on auth flows (no login)

## The pattern
Auth-adjacent endpoints (login, signup, logout, password reset, forgot-password,
SSO, OAuth) almost always take a "send the browser here next" parameter. The
**name varies** (`redirect`, `redirect_url`, `redirect_uri`, `redirect_to`,
`returnUrl`, `ReturnUrl`, `RETURNURL`, `next`, `dest`, `goto`, `continue`,
`callback`, `url`, `RelayState`, `service`, …). The **value form varies** (plain,
URL-encoded, base64, protocol-relative `//evil`, `\/\/evil`, backslash tricks) —
irrelevant for discovery. Goal of this skill: **get the endpoints and the
redirect parameter name**, with zero authentication.

Param-name universe: `/opt/watch/wordlists/redirect-params.txt` (~200 names,
case variants included). Extend it freely.

## Step 1 — Watch targets: mine + write to findings + confirm
Watch stores every crawled URL's params. Two ways to run:

A) Discover only, print or persist candidates (no requests):
```bash
cd /opt/watch && ./.venv/bin/python scripts/find_redirect_params.py            # print, all programs
cd /opt/watch && ./.venv/bin/python scripts/find_redirect_params.py --program dell --write
#   --write     -> upsert each hit to Finding (source=redirect-param, severity=info)
#   --any-path  -> drop the auth-path filter (noisier)
```
B) Full hunt — discover + write candidates, then CONFIRM live and store confirmed
   open-redirects as medium findings (in-scope hosts only):
```bash
cd /opt/watch && ./.venv/bin/python scripts/watch_redirect_hunt.py              # all programs
cd /opt/watch && ./.venv/bin/python scripts/watch_redirect_hunt.py --program dell
cd /opt/watch && ./.venv/bin/python scripts/watch_redirect_hunt.py --no-confirm # discover only
```
Confirmation uses the nuclei DAST template `nuclei/private_templates/open-redirect-auth.yaml`
(replaces the redirect param with an external canary, matches a `Location:` header
redirecting off-host). Results land in the Finding collection:
`source=redirect-param` (info, candidate) and `source=redirect` (medium, confirmed).

## Step 2 — any target not in Watch (still no login)
Passive URL harvest, then grep auth paths carrying a redirect-name:
```bash
TARGET=example.com
( gau "$TARGET"; echo "$TARGET" | waybackurls; katana -u "https://$TARGET" -d 3 -silent ) \
  | sort -u > /tmp/urls.txt

# keep URLs with a query param, on an auth-flow path, whose param name is a redirect name
grep -iE '\?|&' /tmp/urls.txt \
  | grep -iE '(login|signin|sign-in|logon|auth|oauth|openid|sso|saml|cas|register|signup|logout|signout|password|reset|forgot|recover|verify|confirm|callback|return|continue)' \
  | grep -iEf <(sed 's/^/[?&]/; s/$/=/' /opt/watch/wordlists/redirect-params.txt) \
  | sort -u
```
Then mine parameter NAMES from the URL corpus with `unfurl`:
```bash
unfurl --unique keys < /tmp/urls.txt | grep -iFf /opt/watch/wordlists/redirect-params.txt
```

## Step 3 — active param discovery (when passive is thin)
Use `x8` to brute hidden params on a known auth endpoint, seeded with the wordlist:
```bash
x8 -u "https://$TARGET/login" -w /opt/watch/wordlists/redirect-params.txt
```
`ffuf` alternative: `ffuf -u "https://$TARGET/login?FUZZ=https://evil.example" -w /opt/watch/wordlists/redirect-params.txt -mc all -fr '<matched-on-no-redirect>'`.

## Step 4 — the whole target universe
A filtered 4-platform sweep (bounty:true only, HackerOne/Bugcrowd/YesWeHack/
Intigriti) lives in Watch and is the practical workhorse on this box:
```bash
cd /opt/watch && ./.venv/bin/python scripts/_bb4_extract.py    # seed -> logs/bb4_programs.json
cd /opt/watch && ./.venv/bin/python scripts/bb4_harvest.py --workers 6 --tag full
cd /opt/watch && ./.venv/bin/python scripts/bb4_harvest.py --failed-only --workers 4 --tag retry1
cd /opt/watch && ./.venv/bin/python scripts/bb4_report.py       # -> reports/*.md
```
~1,141 roots take ~90 min at 6 workers. Status is append-only
(`logs/bb4/status.jsonl`, last line per root wins), so a re-run resumes; a root
that yielded 0 URLs is recorded ok=false and is exactly what `--failed-only`
retries.

### Archive-source pitfalls (learned the hard way)
- **Never send `collapse=urlkey` to the Wayback CDX** for big roots: it turns a
  20s answer into a 502/504. `filter=original:.*[?].*` + `limit` alone is fast.
  Use a ladder of `limit` (20000 → 8000 → 3000) on timeout, not a retry.
- A full-regex `filter=original:...(group)` or a `%5B?%5D` character class
  returns **HTTP 500**; only the simple `.*[?].*` form is supported.
- `matchType=prefix` with `url=domain/*` silently yields nothing for archived
  query strings — use `matchType=domain`.
- The CDX endpoint flips to "Internet Archive: Temporarily Offline" for minutes
  at a time; detect `<html` in the body rather than trusting the status code.
- **AlienVault OTX** free tier is 100 req/hour: one page per root max, and back
  off on the first 429 ("Over throttling limit"). A sweep that ignores this
  burns the budget in the first 20 roots.
- urlscan `/api/v1/search/` is free and works; `/api/v1/result/<id>/` is 403
  without a key, so only `page.url` is harvestable.
- arquivo.pt CDX answers `output=json` only, one JSON object per line,
  `filter=url:` + `\?`; thin but cheap for roots the others miss.
- `index.commoncrawl.org` is unreachable from this host (connection refused) —
  don't build a fallback around it.
- Report filter: keep a hit only when the value *looks like a destination*
  (scheme, `/`, `%2F`, `\`, or `host.tld`), and drop the noisy wordlist names
  (`page`, `path`, `file`, `data`, `val`, `image_url`, `feed`). Otherwise the
  output is dominated by `?page=2`.

Older ready-made sweep over every `bounty:true` program (passive, no target
traffic — queries the Wayback CDX archive directly). Writes a timestamped report
and prints its path on stdout so you can deliver it to the user:
```bash
cd /opt/watch && ./.venv/bin/python scripts/redirect_sweep_chaos.py              # all bounty:true roots
cd /opt/watch && ./.venv/bin/python scripts/redirect_sweep_chaos.py --limit 100  # bounded smoke run
cd /opt/watch && ./.venv/bin/python scripts/redirect_sweep_chaos.py --match uber  # one program
cd /opt/watch && ./.venv/bin/python scripts/redirect_sweep_chaos.py --active      # also katana (sends traffic)
# report: logs/redirect-sweep/<timestamp>/report.txt and report.jsonl
```
Scope source is `projectdiscovery/public-bugbounty-programs` → `dist/data.json`
(~1600 bounty roots). The sweep is archive recon; CONFIRM any hit per-program,
respecting that program's scope and rules, before reporting.
**Scope discipline (load `recon-scope-triage`):** the list is only a seed. For each
program, confirm the exact in-scope assets and the program's rules BEFORE testing.
No-login does not mean no-scope — only touch assets a program authorizes.

## Step 5 — verify and value (route onward)
**Always run a baseline-vs-canary differential**, never a canary-only check. A
canary-only match produces false positives in three ways, all seen in practice:
- captive-portal / splash pages that 302 to `http://google.com/` no matter what
the parameter says (using google.com as the canary makes these look confirmed —
check whether the untouched URL also redirects there);
- `*.google.com` Locations, which are legitimate Google hosts, not your payload
  (compare the exact hostname, not a subdomain wildcard);
- the request URL echoed into `<meta og:url>` / `canonical` — that is not a
  redirect. A client-side hit needs `location=`, `location.replace(`,
  `window.open(` or `meta http-equiv=refresh` whose target is the canary.

Method that works: request the untouched archived URL and the canary-rewritten
URL, then classify. Only `baseline != google.com AND canary == google.com` is a
real open redirect. Everything else is one of: param ignored, param validated
and refused (4xx — the whitelist to attack), IdP error-page fallback, edge WAF
blocking both requests, or dead host. `scripts/bb4_confirm.py`,
`bb4_verify_hits.py` and `bb4_diff.py` in `/opt/watch/scripts` implement this.
Also: rewriting *every* wordlist parameter at once breaks endpoints whose other
params (flow, pid, state) are load-bearing — leave non-redirect params alone.

Finding the param is recon, not a bug. Grade by where the param lives:
- **`redirect_uri` on an OAuth/OIDC/SSO endpoint** → highest value. Test whitelist
  bypass (append/replace host, path traversal, `@`, subdomain, open-redirect on an
  allowed host used as a hop). A working bypass steals the `code`/token → account
  takeover. **Load `hunt-oauth`.**
- **`next`/`returnUrl`/`ReturnUrl`/`dest` on login/reset** → classic open redirect.
  Confirm the server actually issues a 30x `Location:` to your external host (or a
  JS/meta redirect). **Load `hunt-open-redirect`** for payload tricks (`//evil`,
  `https:evil`, `\/\/`, `%2f%2f`, base64 values, CRLF).
- Encoding does not change validity — decode base64/URL-encoding, confirm the
  destination is attacker-controlled.

## Confirm before reporting
- Reproduce the redirect to an external, attacker-controlled host (unique marker).
- Pure open redirect is often P4/P5 or OOS on many programs — check program rules;
  the strong report is the OAuth/SSO token-theft chain, or redirect that leaks a
  secret/credential. State impact honestly (load `triage-validation`).

## Guardrails
In-scope assets only; respect each program's rules. No login/credential use needed
or implied. Read-only probing; a single marker request to confirm. Mask any real
token in evidence.
