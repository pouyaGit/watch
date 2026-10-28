# HUNT GUIDE — Watch → Verify → Report

> Operating manual for the Hermes hunting agent on this server.
> Written to be followed **literally**. Prefer the tables and the exact commands.
> When a rule here conflicts with your own guess, the rule wins.

---

## 0. The one rule that matters

**Watch output is a list of SUSPICIONS, not findings. Nothing leaves this box until YOU verified it live.**

A nuclei/secret/takeover hit is a *candidate*. Most candidates are false positives
(reflections, login pages, build hashes, public-by-design assets). Your job is not to
forward candidates — it is to **kill the false ones and prove the real ones**. A
submitted false positive costs reputation and program trust. When unsure, discard.

Golden loop: **Pull candidate → classify → load the matching skill → verify live → decide (prove / discard) → only then report.**

**Second rule — do not only wait for Watch.** Watch emits a narrow slice (nuclei
misconfig/exposure, `secret`, `takeover`, `content`). The highest-paying classes —
IDOR/BOLA, broken access control, business logic, OAuth/`redirect_uri` & account-takeover
chains, authenticated CORS impact, CSRF, race conditions — **Watch can never surface.**
They need you to drive a browser and reason. Spend real time in §11 (proactive hunting),
not just §5 (verifying candidates). See §10 for the logins that unlock the authenticated
surface.

---

## 1. Environment (what is on this box)

| Thing | Location |
|---|---|
| Watch project | `/opt/watch` |
| Python (always use this) | `/opt/watch/.venv/bin/python` |
| Findings DB | MongoDB, via `from database.db import Finding` (connects on import) |
| Programs + scope | `/opt/watch/programs/*.json` (`dell`, `digicert`, `indeed`, `wien`) |
| Dashboard / JSON API | `http://127.0.0.1:5000` (see §3) |
| Nuclei private templates | `/opt/watch/nuclei/private_templates/` |
| Active agent skills | `/root/.hermes/skills/<category>/` |
| Bug-bounty skill library | `/root/skills-src/murrtada/skills/` (the `hunt-*`, `bb-*` skills) |
| Secondary skill library | `/root/skills-src/shuvonsec/skills/` |

Installed CLI tools (use these, do not reinstall): `nuclei`, `httpx`, `subfinder`,
`dnsx`, `katana`, `gau`, `waybackurls`, `gospider`, `ffuf`, `x8`, `dalfox`,
`puredns`, `massdns`, `alterx`, `assetfinder`, `unfurl`, `interactsh-client`,
plus `dig`, `whois`, `openssl`, `curl`, `jq`.

---

## 2. Scope — check BEFORE touching anything

Every target must be in scope for its program. Out-of-scope testing is forbidden.

```bash
cat /opt/watch/programs/dell.json   # -> scopes[] (in) and ooscopes[] (never touch)
```

- A host is in scope only if it matches `scopes` and matches **none** of `ooscopes`.
- At the very start of any engagement load **`recon-scope-triage`** — automated recon
  keyword-matches the brand name, so output is polluted with unrelated same-named orgs.
  Confirm *ownership* before testing (registrar / NS / cert / ASN), not just the string.

---

## 3. Reading Watch output

### 3a. Query the DB (primary)

```bash
cd /opt/watch && ./.venv/bin/python - <<'PY'
from database.db import Finding
# open candidates for one program, newest first
for f in Finding.objects(program_name="dell", status="open").order_by("-first_seen"):
    print(f.severity, f.source, f.name, "|", f.target, "|", f.matched)
PY
```

`Finding` fields: `program_name, scope, target, source, name, severity, matched, extra, first_seen, last_seen, status`.

`source` meanings:

| source | what produced it | default trust |
|---|---|---|
| `nuclei` | a private template matched | LOW — verify the matcher logic |
| `takeover` | nuclei `takeover` tag hit | LOW — fingerprint only, prove claimability |
| `secret` | regex/entropy hit in JS/response | LOW — mostly build hashes & public keys |
| `content` | crawl/diff surfaced a path | INFO — a lead, not a bug |

### 3b. The port-5000 API — do NOT use it

The dashboard/API on `:5000` is auth-gated and there are **no login credentials** for
the agent. Hermes has direct server-side DB access, so always go through the `Finding`
model in §3a. Do not try to hit the API.

### 3c. Retiring a candidate (NO DELETE)

Do not delete rows. Mark status instead — it is reversible and keeps history:

```bash
cd /opt/watch && ./.venv/bin/python - <<'PY'
from database.db import Finding
Finding.objects(target="https://x", name="t").update(set__status="false_positive")
PY
```

`status` values: `open | triaged | false_positive | fixed`. Set `false_positive`
when you disprove it, `triaged` when confirmed and queued for a report.

---

## 4. Skills — how to use them

Skills are folders with a `SKILL.md`. **Read the matching `SKILL.md` before hunting a
class you have not verified today.** They encode payloads, confirmation steps, and the
known gotchas that stop false positives.

### 4a. Always load these (meta-skills)

| When | Skill |
|---|---|
| Start of session / "what next" | `bb-methodology` |
| On any recon/ASM dataset, before testing | `recon-scope-triage` |
| **Before writing ANY report** | `triage-validation` (7-question gate) |
| Preparing PoC / screenshots / HAR | `evidence-hygiene` |
| Filing on Bugcrowd / severity dispute | `bugcrowd-reporting` + `report-writing` |

### 4b. Finding-class → skill routing (full taxonomy)

Pick by the candidate's `name`/`source`/behaviour, load that `hunt-*` skill, follow its
confirm step. All 57 `hunt-*` skills live in `/root/skills-src/murrtada/skills/`.

**Injection**
| Signal | Skill |
|---|---|
| SQL error / boolean / time-based | `hunt-sqli` |
| NoSQL (`$ne`, `$gt`, JSON operators) | `hunt-nosqli` |
| LDAP filter injection | `hunt-ldap` |
| OS command / RCE | `hunt-rce` |
| template expr (`{{7*7}}`, `${}`) | `hunt-ssti` |
| server-side include / HTML injection | `hunt-html-injection` |
| XML / XXE | `hunt-xxe` |
| insecure deserialization (gadget chains) | `hunt-deserialization` |
| LFI / path traversal / file read | `hunt-lfi` |

**Client-side**
| Signal | Skill |
|---|---|
| reflected / stored XSS | `hunt-xss` |
| DOM XSS (sink in JS) | `hunt-dom` |
| CSRF (state-changing, no token) | `hunt-csrf` |
| clickjacking (framable) | `hunt-clickjacking` |
| open redirect | `hunt-open-redirect` |
| redirect param on auth flow (login/reset/SSO) | `hunt-redirect-params` (ready sweep: `scripts/find_redirect_params.py`) |
| CORS misconfig | `hunt-cors` |
| cache poisoning / deception | `hunt-cache-poison` |
| websocket | `hunt-websocket` |

**Access control & logic**
| Signal | Skill |
|---|---|
| IDOR / object reference | `hunt-idor` |
| broken authz / privilege | `hunt-auth-bypass` |
| business-logic / workflow abuse | `hunt-business-logic` |
| race condition / TOCTOU | `hunt-race-condition` |
| exceptional conditions / error states | `hunt-exceptional-conditions` |
| captcha bypass | `hunt-captcha-bypass` |

**Auth / session / identity**
| Signal | Skill |
|---|---|
| session fixation / cookie flaws | `hunt-session` |
| account takeover chain | `hunt-ato` |
| password-reset / forgot flow | `hunt-forgot-password` |
| MFA bypass | `hunt-mfa-bypass` |
| brute force / cred stuffing | `hunt-brute-force` |
| JWT / crypto misuse | `hunt-jwt-crypto` |
| OAuth flows | `hunt-oauth` |
| SAML | `hunt-saml` |
| NTLM info leak | `hunt-ntlm-info` |

**SSRF / network / transport**
| Signal | Skill |
|---|---|
| SSRF (url/redirect params, metadata) | `hunt-ssrf` |
| HTTP request smuggling | `hunt-http-smuggling` |
| host header injection | `hunt-host-header` |
| TLS / network misconfig | `hunt-tls-network` |
| subdomain takeover / dangling DNS | `hunt-subdomain` |

**API surfaces**
| Signal | Skill |
|---|---|
| GraphQL (introspection, batching) | `hunt-graphql` |
| gRPC | `hunt-grpc` |
| API misconfig (actuator, airflow, jira, open admin APIs) | `hunt-api-misconfig` |
| hidden / shadow / undocumented API | `hunt-shadow-api` |
| SPA → backend API mapping | `hunt-spa-api` |
| file upload | `hunt-file-upload` |

**Framework / platform fingerprinted**
| Signal | Skill |
|---|---|
| ASP.NET / viewstate | `hunt-aspnet` |
| Spring Boot / actuator | `hunt-springboot` |
| Laravel | `hunt-laravel` |
| Node.js | `hunt-nodejs` |
| Next.js | `hunt-nextjs` |
| SharePoint | `hunt-sharepoint` |

**Infra / cloud / supply chain**
| Signal | Skill |
|---|---|
| cloud misconfig (buckets, IAM, metadata) | `hunt-cloud-misconfig` |
| Kubernetes / kubelet / API server | `hunt-k8s` |
| CI/CD pipeline exposure | `hunt-cicd` |
| secrets / source / keys leaked (`secret` source, JS) | `hunt-source-leak` |

**AI / LLM**
| Signal | Skill |
|---|---|
| LLM app / prompt injection | `hunt-llm-ai` |
| RAG / vector store | `hunt-rag-vector` |

**Nothing fits** → `hunt-misc`, or `bb-methodology` to re-orient.

---

## 5. Verification playbooks (the part that kills false positives)

These are the exact checks for the classes Watch emits most. Run them before believing any candidate.

### 5a. Subdomain takeover (`takeover`, `microsoft-azure-error`, etc.)
A 404/"site not found" page is **not** a takeover. Prove claimability:
```bash
dig +short HOST CNAME            # dangling CNAME to a dead service name = candidate
dig +short HOST                  # bare A to a shared cloud IP = usually NOT claimable
dig +short TXT asuid.HOST        # Azure: if this exists, domain is bound -> NOT claimable
```
- Azure/App Service: claimable ONLY if a CNAME points to a `*.azurewebsites.net` name
  that no longer resolves (NXDOMAIN) **and** no `asuid` TXT binds it. A-record + asuid = dead end.
- Real PoC = you actually register the resource and serve a unique token on the victim host, then remove it. No registration = no takeover, do not report.

### 5b. SSRF (`ssrf-*`)
- Metadata templates FP when the app **reflects** the payload URL. The body containing
  `computeMetadata` / `iam/security-credentials` once = that is your own payload echoed back.
- Real SSRF = the response contains metadata **response** content that was never in your
  request: `AccessKeyId`, `SecretAccessKey`, `ami-id`, `instance-id`, or header `Metadata-Flavor: Google`.
- Blind SSRF needs `interactsh-client` OOB confirmation. No OOB hit = not confirmed.

### 5c. Config exposure (`airflow-*`, `jira-*`, `*actuator*`)
- Must be the real JSON API: check `Content-Type: application/json`. A `text/html` body
  is a login/SPA page returning 200 for every path — matching on the word "password" is a FP.
- Airflow real: JSON with `total_entries` / `sections`. Jira real: JSON with `version`/`baseUrl`/`accountId`.

### 5d. GraphQL introspection (`graphql-*`)
Re-send the introspection query yourself; confirm `__schema`+`queryType` in a JSON body
with no `errors`. A 405/HTML or "introspection disabled" = discard.

### 5e. Reflected XSS (`*xss*`)
The full payload must come back **unencoded as one block** (`"><script>alert(1)</script>`).
If it is HTML-entity-encoded, or only the substring `alert(1)` appears, it is a FP. Confirm
execution context; use `dalfox` to validate.

### 5f. Secrets (`secret` source)
- `google_api_key` (`AIza...`) in client JS is **public by design** — only valuable if the
  key is unrestricted (no HTTP-referrer / API limits). Check restrictions; usually informational.
- `generic_secret_assignment` matching a hex blob in `main.js` is almost always a build/chunk
  hash, not a secret. Treat as FP unless it is a recognizable live credential.

---

## 6. Known false-positive patterns (discard on sight)

- Any matcher word that is a **substring of the injected payload** (reflection).
- 200 + generic word (`password`, `key`, `version`, `<script>`) on a **`text/html`** page.
- "Site not found"/parked page with no claimable resource.
- Public-by-design assets: published container images, client-side API keys, open CDNs.
- Static-matcher "IDOR" — IDOR cannot be proven by a template; needs two-account manual testing.
- Anything that does not reproduce on a second manual request.

---

## 7. Reporting

Only after `triage-validation` passes all 7 questions.

Structure (one finding per report):
1. **Title** — asset + class + impact in one line.
2. **Scope** — exact host, proof it is in-scope (not in `ooscopes`).
3. **Severity** — Bugcrowd VRT category + realistic P-rating. Do not inflate. State the
   rationale, and state honestly what is NOT claimed.
4. **Steps to reproduce** — copy-paste `curl`/`dig`, real output.
5. **Proof** — unique token / screenshot (redact per `evidence-hygiene`).
6. **Impact** — concrete, no speculation past what you proved.
7. **Remediation**.

Severity realism (this program's history): public-by-design = Informational/N/A;
non-claimable dangling DNS = P4/P5; cert/namespace governance = P4; confirmed
metadata-SSRF with creds = P1/P2. **When the real bug after honest caveats is small, say so — a precise P4 beats an inflated Medium that gets closed N/A.**

---

## 8. Hard guardrails

- Authorized scope only. Never touch `ooscopes` or out-of-program hosts.
- Read-only by default. No write/push/delete/upload against a target (no FTP writes, no
  registry pushes, no form submits) unless the program explicitly allows it.
- No DoS, no brute force beyond what a skill authorizes, no automated mass exploitation.
- Prove with the lightest possible action; remove any resource you had to create for a PoC.
- Pace requests. Respect rate limits.
- Never exfiltrate real user data; mask PII in evidence.

**Authenticated testing (when logged in via §10):**
- Test only with **accounts you control** (the vault test accounts). Never act as, or on the
  data of, a real user.
- IDOR/BOLA: the clean proof is **two of your own accounts** (A can read B's object). With a
  single account you may only probe own-data scoping and auth posture; if a guessed/other
  object reference returns data that is clearly **not yours**, that already proves the bug —
  **stop at that minimal proof, do not page through real records, mask everything.**
- No destructive authenticated actions: no deleting, no placing real orders, no changing
  another user's state. State-changing PoCs use your own account only.
- Back up `storage_state` before any logout/session test — it kills the server session and
  the saved cookies go dead.

---

## 9. Quick start (per session)

1. `bb-methodology` → orient.
2. Load program scope from `/opt/watch/programs/`.
3. **Two parallel tracks — do both, not just the first:**
   - **Verify track (reactive):** pull `status="open"` candidates from the DB (§3a),
     highest severity first → classify → load the `hunt-*` skill (§4b) → run the §5 playbook.
   - **Hunt track (proactive, higher EV):** pick a target → if it has a vault login (§10),
     authenticate → work the §11 priority list (auth-flow logic, then IDOR/authz/business-logic,
     then API surface) with the browser.
4. Disprove → `status="false_positive"`. Confirm → `status="triaged"`.
5. `triage-validation` → if it passes, write the report (§7). Else discard.

---

## 10. Authenticated hunting (vault-backed logins)

Some targets can now be tested **logged in**. Credentials live in the Hermes vault, not in
this repo. The model never sees the password: it is injected server-side.

### 10a. Which targets have a login (keep this current)

| Program | Vault creds | Accounts | Login skill |
|---|---|---|---|
| `dell` | ✅ yes | **1** (single account) | `dell-login-playwright` |
| `digicert` | ⏳ planned | — | (none yet) |
| `wien` | ⏳ planned | — | (none yet) |
| `indeed` | ❌ none | — | — |

When you add accounts, update this table (and note handles, never passwords).

### 10b. How to log in

1. Load the target's login skill (e.g. `dell-login-playwright`) and follow it literally — it
   encodes the Akamai/CAPTCHA/MFA flow that plain `browser_exec` fails.
2. Resolve the password from the vault **without printing it**:
   `VaultStore().resolve_secret(handle).get("password","")`. Never log, echo, or put it in a
   tool argument that gets recorded.
3. Cookies are **fingerprint-bound**: authenticated requests must run from **inside the same
   Playwright context** that logged in. The same cookies in `curl` get an Akamai 403 — do not
   try to port the session out.
4. Each Dell login burns one email-2FA code; the account locks after 6 bad MFA attempts.
   **Never guess codes.** One account = be economical with logins.

### 10c. What ONE account unlocks (Dell today)

A single account is already enough for several real bugs — you do not need two for these:

- **Authenticated CORS impact** — the single biggest payoff right now. The 116
  `cors-credentialed-reflection` findings are only a *shape* until you prove a cross-origin
  read of **authenticated** data. Logged in, replay the endpoint with the evil `Origin` + your
  session and show your own private response is readable cross-origin. One account proves it.
- **Own-data access-control posture** (`bb-authz`, `hunt-auth-bypass`) — map which objects/APIs
  your account can reach; a 200 where a 401/403 is expected is a lead.
- **Business logic** (`hunt-business-logic`) within your own account — pricing, workflow, state.
- **Authenticated GraphQL / API authz** (`hunt-graphql`, `hunt-spa-api`) on your own token.

**Blocked until a second account exists:** clean IDOR/BOLA proof (A reads B). See the §8
authenticated guardrails for the single-account exception and its limits.

---

## 11. Proactive hunting — the bugs Watch can never emit

Watch is a scanner; these classes need a human-style, browser-driven, reasoning pass. Work
them in this order (highest expected value first). For each, load the named `hunt-*` skill.

### 11a. Pre-auth (works with NO login)

1. **OAuth / `redirect_uri` bypass** → `hunt-oauth`. Seed: `scripts/indeed_oauth_bypass.py`
   and the `redirect-param` candidates on auth flows (login/sso/reset).
2. **Password-reset / forgot flow** → `hunt-forgot-password` (host-header poisoning, token leak).
3. **Registration / pre-account-takeover** → `hunt-ato`.
4. **Open redirect, SSRF-via-params, host-header, cache poisoning, smuggling** → their skills.

### 11b. Authenticated (needs §10 login)

5. **IDOR / BOLA** → `hunt-idor` (two accounts for clean proof; see §8/§10c).
6. **Broken access control / privilege escalation** → `hunt-auth-bypass`, `bb-authz`.
7. **Business logic** → `hunt-business-logic`.
8. **Authenticated CORS proof** → `hunt-cors` (turns the 116 findings into real bugs, §10c).
9. **CSRF on state-changing actions, authenticated SSRF, session/JWT** → their skills.

### 11c. Surface mapping (feeds both)

10. **SPA → backend API** (`hunt-spa-api`) and **shadow/undocumented API** (`hunt-shadow-api`)
    from crawled JS → new endpoints → test authz on each.
11. **Framework-specific** on fingerprinted hosts: Spring 401 hosts → `hunt-springboot` +
    the `spring-actuator-heapdump-custom` / `jolokia-jmx-exposure-custom` templates;
    Next.js → `hunt-nextjs`; etc.

### 11d. Seeded leads already on this box

| Lead | Where | Route to |
|---|---|---|
| 116 CORS reflections | `Finding(name="cors-credentialed-reflection-custom")` | §10c authenticated proof + `hunt-cors` |
| redirect-param candidates | `Finding(source="redirect-param")` → `/ui/findings/redirect` | `hunt-oauth` / `hunt-redirect-params` |
| Spring 401 API hosts | CORS-finding hosts returning 401 | `hunt-springboot` + heapdump/jolokia templates |
| GraphQL introspection hits | `Finding(name="graphql-introspection-custom")` | `hunt-graphql` (authz, not just introspection) |

---

## 12. Pre-auth proactive checklist — the [B] work (NO account needed)

This is the anti-laziness list. When the candidate queue is exhausted (all CORS
done/parked), you are NOT blocked — you run this on **fresh** hosts/params.
Minimum bar for a session: **item 1, plus any 3 of items 2–12**, on surface you
have not tested before — and XSS (items 11–12) is a prime pre-auth target, so
work it most sessions. Each item names what proves it real and the skill to load.

WAF note: many hosts (Dell/Akamai) 403 tool UAs. Always set a real browser UA:
```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
```

Build a fresh live-host list for a program (reused by several items):
```bash
cd /opt/watch && ./.venv/bin/python - <<'PY'
from database.db import Urls
hosts = sorted({u.subdomain for u in Urls.objects(program_name="dell").only("subdomain") if u.subdomain})
open("/tmp/live.txt","w").write("\n".join(f"https://{h}" for h in hosts)+"\n")
print(len(hosts), "hosts -> /tmp/live.txt")
PY
```

**1. Spring/Java exposure — heapdump + jolokia + actuator (highest EV, zero-FP)**
```bash
nuclei -l /tmp/live.txt \
  -t nuclei/private_templates/spring-actuator-heapdump.yaml \
  -t nuclei/private_templates/jolokia-jmx-exposure.yaml \
  -t nuclei/private_templates/spring-actuator-exposure.yaml \
  -H "User-Agent: $UA" -rl 40 -nc
```
Matchers self-confirm. Any hit → load `hunt-springboot`, pull the dump/MBeans, report.

**2. Secret / source leak in crawled JS** → `hunt-source-leak`
```bash
./.venv/bin/python - <<'PY'
from database.db import Urls
for u in Urls.objects(program_name="dell").only("url"):
    if u.url.endswith(".js"): print(u.url)
PY
```
Fetch each with the browser UA, grep for live creds / internal hosts / endpoints:
`AKIA[0-9A-Z]{16}`, `AIza[0-9A-Za-z_\-]{35}`, `sk_live_`, `xox[baprs]-`, `ghp_`,
`-----BEGIN`, `s3://`, internal `*.corp`/`*.internal` hosts, `/api/…` paths.
Real only if the key is **live/unrestricted** (a referrer-locked `AIza` key = info).

**3. Shadow / undocumented API from JS** → `hunt-shadow-api` / `hunt-spa-api`
Grep the JS from item 2 for endpoint paths (`/api/`, `/v1/`, `/internal/`, `/admin/`),
`curl -A "$UA"` them unauthenticated. A 200 returning real data (not a login
redirect / SPA shell) = undocumented surface → test authz on it.

**4. OAuth / redirect_uri** → `hunt-oauth` / `hunt-redirect-params`
```bash
python3 scripts/indeed_oauth_bypass.py      # existing bypass harness
./.venv/bin/python - <<'PY'
from database.db import Finding
for f in Finding.objects(source="redirect-param", status="open"):
    print(f.program_name, f.target, (f.extra or {}).get("params"))
PY
```
Prove an actual off-host / cross-account redirect, not just a reflected param.

**5. Open redirect (canary)** → `hunt-open-redirect`
Reuse `scripts/watch_redirect_confirm.py` / `scripts/bb4_confirm.py`: set the param to
`https://google.com`, GET without following; HIT only if `Location` host == `google.com`
while the baseline does not.

**6. SSRF via params (OOB-confirmed)** → `hunt-ssrf`
```bash
interactsh-client -o /tmp/oob.txt &        # prints a canary domain to use as the payload
```
For params named `url,uri,dest,redirect,next,callback,webhook,image,feed,proxy,target`
inject the interactsh URL; a DNS/HTTP hit in `/tmp/oob.txt` = confirmed. No OOB hit =
not confirmed (reflection of your own URL is NOT SSRF — see §5b).

**7. Host-header / password-reset poisoning** → `hunt-host-header` / `hunt-forgot-password`
On login/reset/SSO endpoints: `curl -A "$UA" -H "Host: evil.example"` and
`-H "X-Forwarded-Host: evil.example"`. If an absolute URL / reset link / cache key
reflects `evil.example`, it is a candidate.

**8. Subdomain takeover re-check** → `hunt-subdomain` (full method in §5a)
Dangling CNAME to a dead service + NXDOMAIN + no binding TXT. Prove claimability, never
report a bare 404.

**9. GraphQL authz (beyond introspection)** → `hunt-graphql`
On `graphql-*` hits: re-send introspection to confirm `__schema`, then run a sensitive
query **unauthenticated** — data returned without auth is the bug, not introspection alone.

**10. Misconfig sweep on FRESH hosts (public templates)** → verify each per §5
```bash
nuclei -l /tmp/live.txt -tags exposure,config,cve,default-login,debug,disclosure \
  -severity medium,high,critical -H "User-Agent: $UA" -rl 40 -nc
```
Every hit is a CANDIDATE — run the §5 playbook before believing it.

**11. Reflected XSS** → `hunt-xss` (confirm rules in §5e)
Pull URLs that carry query params, fuzz with `dalfox`:
```bash
./.venv/bin/python - <<'PY'
from database.db import Urls
seen=set()
for u in Urls.objects(program_name="dell").only("url","params"):
    if u.params and u.url not in seen:
        seen.add(u.url); print(u.url)
PY
# -> /tmp/xss_urls.txt, then:
dalfox file /tmp/xss_urls.txt --header "User-Agent: $UA" --rate-limit 40 \
  --skip-bav --waf-evasion --format plain -o /tmp/xss_hits.txt
```
Real only when the FULL payload comes back **unencoded as one block**
(`"><script>alert(1)</script>`) and executes in context. Entity-encoded, or only
the `alert(1)` substring reflected = FP. Let `dalfox` verify, then reproduce by hand.
Also try the auth/error/search params and non-GET reflections dalfox misses.

**12. DOM XSS** → `hunt-dom` (drive it with the `hermes-domxss-verifier` skill)
Crawl for client-side sinks, then confirm execution in a REAL browser — a static
grep is only a lead, DOM XSS counts only when it fires in the DOM.
```bash
katana -u https://HOST -jc -d 3 -silent -H "User-Agent: $UA" -o /tmp/crawl.txt
# fetch the JS and grep for source->sink:
#   sources: location.hash / .search / document.URL / referrer / postMessage / window.name
#   sinks:   innerHTML, outerHTML, document.write, eval, setTimeout, insertAdjacentHTML,
#            .src=, jQuery $(), element.setAttribute, dangerouslySetInnerHTML
```
Trace an attacker-controlled source into a sink with no sanitisation, then PROVE it
by loading the crafted URL in the built-in browser / Playwright and seeing the script
run. Hash-based payloads (`#`) never hit the server — browser-confirm only.

**Record:** new candidates you confirm → `status="triaged"` + evidence in `extra`;
things you disprove → `status="false_positive"` + why. Then `triage-validation` → report.
