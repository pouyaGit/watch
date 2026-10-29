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
| XSS reflection that a CSP seems to block | `hunt-csp-bypass` (§11b) |
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

## Long-Running Scan Discipline

A tool's foreground timeout (default 180s) is a harness limit, not a verdict on the
target. A scan killed mid-flight leaves partial or empty output, and that output is
NOT evidence of "zero hits."

- **Background any scan expected to exceed ~2 minutes** (`background=true` +
  `notify_on_complete=true`), or split the target list into chunks that fit the
  budget. Do not re-run the identical full-list command expecting a different
  outcome — that is the same loop with the same result.
- **A timed-out scan with empty/partial output is an INCOMPLETE SWEEP**, not a
  clean negative. Record it as `incomplete (timeout)` in the session notes and
  re-run in the background; never write "no hits" or "nothing found" from a
  truncated run. (nuclei writes results as it goes, so 0 lines after a timeout
  means it never finished starting on that list, not that nothing matched.)
- **Always run the bare-control request first** before interpreting a 403/empty
  body as "no reflection / no exposure" — a WAF edge can 403 the payload while
  200-ing the canary. A payload-only 403 with no canary control is uninterpretable.
- **Count and report what actually ran**: #hosts probed, #completed, #hits. A
  summary with no Part-1 tool output (or with an incomplete sweep dressed up as a
  negative) is a failed session, not a clean one.

**Lesson from an authorized engagement:** A nuclei spring-actuator sweep over 1460
live hosts was killed at the 180s default with 0 output lines; re-running the
identical command produced the same timeout. The honest record is "incomplete,"
not "no actuator exposure" — and the cors template on the same list did complete
and returned 85 reflection hits, proving the list and the tool both work.

---
"

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
- `Access-Control-Allow-Origin: *` together with `Allow-Credentials: true` — browsers REJECT
  wildcard ACAO when credentials are used, so this combo is NOT exploitable. Dismiss it; a
  credentialed-CORS finding requires ACAO to **reflect a specific attacker origin** + creds
  (the `cors-credentialed-reflection` template already enforces that — a bare `*`+creds is FP).
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

| Program | Accounts (2 each → clean two-account IDOR) | Login / 2FA |
|---|---|---|
| `digicert` | vault_a85ea4c141cc "digicert 1", vault_1c1c68ccad4c "digicert 2" (accounts.digicert.com) | **PRIORITY** — both accounts work; CA = BOLA goldmine. #2 TOTP in vault (`otp_secret`); #1 email/OTP. account/{id} enforces ownership (403) → test cert/order/download/audit endpoints instead |
| `wien` | vault_3f9b507faf27 "wien 1", vault_c68a1e6c03d3 "wien 2" (mein.wien.gv.at) | simple, NO MFA. The PORTAL dashboard is thin (name/address, no portal IDOR) — but wien.gv.at/wien.at is HUGE (~1689 hosts, whole city gov): hunt the many services/apps WIDE, all bug classes, incl. wherever the SSO reaches. Don't write wien off |
| `dell` | vault_2d7b15676045 "dell behnia", vault_509ef42e1e71 "dell totti" (www.dell.com) | `dell-login-playwright`: CAPTCHA + email 2FA, human present |
| `indeed` | ❌ none | — |

Each program has TWO accounts on the SAME app → prefer the gold-standard two-account IDOR
(A owns an object, B reads it). Prompt: `prompts/authenticated-hunt.txt` (start with wien).
When accounts change, update this table (handles only, never passwords).

### 10b. How to log in

1. Load the target's login skill (e.g. `dell-login-playwright`) and follow it literally — it
   encodes the Akamai/CAPTCHA/MFA flow that plain `browser_exec` fails.
2. Resolve the password from the vault **without printing it**:
   `VaultStore().resolve_secret(handle).get("password","")`. Never log, echo, or put it in a
   tool argument that gets recorded. A stored TOTP seed is on the SAME dict under the key
   `otp_secret` (not `totp`): `seed = resolve_secret(handle)["otp_secret"]; pyotp.TOTP(seed).now()`
   → mint the 2FA code yourself (e.g. digicert 2). Never print the seed.
2b. DEPTH on a login PORTAL/SSO: the portal's own dashboard exposes almost nothing (mein.wien.gv.at
   = 4 CMS/account calls, no object refs). Do NOT conclude "no IDOR" there — FOLLOW the SSO into the
   SERVICES it grants (where users create records: petitions, form/Antrag submissions, cert/orders,
   documents, appointments). The IDOR/BOLA surface is in the services, per-service; go deep on 2-3.
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

### Long-Running Scan Discipline

A tool's foreground timeout (default 180s) is a harness limit, not a verdict on the
target. A scan killed mid-flight leaves partial or empty output, and that output is
NOT evidence of "zero hits."

- **Background any scan expected to exceed ~2 minutes** (`background=true` +
  `notify_on_complete=true`), or split the target list into chunks that fit the
  budget. Do not re-run the identical full-list command expecting a different
  outcome — that is the same loop with the same result.
- **A timed-out scan with empty/partial output is an INCOMPLETE SWEEP**, not a
  clean negative. Record it as `incomplete (timeout)` in the session notes and
  re-run in the background; never write "no hits" or "nothing found" from a
  truncated run. (nuclei writes results as it goes, so 0 lines after a timeout
  means it never finished starting on that list, not that nothing matched.)
- **Always run the bare-control request first** before interpreting a 403/empty
  body as "no reflection / no exposure" — a WAF edge can 403 the payload while
  200-ing the canary. A payload-only 403 with no canary control is uninterpretable.
- **Count and report what actually ran**: #hosts probed, #completed, #hits. A
  summary with no Part-1 tool output (or with an incomplete sweep dressed up as a
  negative) is a failed session, not a clean one.

**Lesson from an authorized engagement:** A nuclei spring-actuator sweep over 1460
live hosts was killed at the 180s default with 0 output lines; re-running the
identical command produced the same timeout. The honest record is "incomplete,"
not "no actuator exposure" — and the cors template on the same list did complete
and returned 85 reflection hits, proving the list and the tool both work.

---
"

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

Build a fresh live-host list for a program (reused by several items). DO NOT
re-run httpx on the raw subdomain list — the Watch `http` lane already probes
every target with httpx TWICE A DAY and stores the result (status, title, tech,
headers) in the `Http` collection. Re-probing 1777 mostly-dead hosts wastes
minutes for data that is already in the DB and fresh. READ IT INSTEAD:
```bash
cd /opt/watch && ./.venv/bin/python - <<'PY'
from datetime import datetime, timedelta
from database.db import Http
fresh = datetime.now() - timedelta(days=3)          # http lane runs ~2x/day
rows = [h for h in Http.objects(program_name="dell").only(
            "url","final_url","status_code","title","tech","last_update")
        if h.status_code and (not h.last_update or h.last_update >= fresh)]
with open("/tmp/live.txt","w") as f:
    f.write("\n".join(sorted({(h.final_url or h.url) for h in rows}))+"\n")
print(len(rows), "live hosts from Http (status + fresh) -> /tmp/live.txt")
PY
```
Only re-probe a SINGLE host live (curl/httpx) at the moment you are about to test
it, to confirm it is still up — never a full sweep. Use the stored `tech` to pick
targets (e.g. `tech` contains "Spring"/"Tomcat"/"Java" → the heapdump/jolokia
items), and `Http.last_nuclei_run` / `last_ffuf_run` to SKIP hosts scanned
recently and spend the budget on stale/new ones.

**Surface expansion first — `ffuf` (paths) + `x8` (params).** Run these to GENERATE
fresh surface, then feed it to the bug-class items below. All five tools are
installed and on PATH: `ffuf x8 nuclei katana dalfox` (+ `httpx subfinder gau
interactsh-client`). Do not reinstall them.

- **`ffuf` — content / endpoint discovery** (finds hidden paths, admin panels,
  backups, `.git`/`.env`, old APIs → feeds items 3 and 10):
  ```bash
  ffuf -u https://HOST/FUZZ -w /opt/watch/wordlists/watch_content_medium.txt \
    -H "User-Agent: $UA" -mc 200,204,301,302,401,403 -ac -rate 40 -t 25 -o /tmp/ffuf.json
  ```
  `-ac` auto-calibrates out soft-404s. Point `-w` at a bigger list when a host looks
  interesting. New paths → curl them (item 3) and sweep with nuclei (item 10).

- **`x8` — hidden parameter discovery** (finds params the crawl missed → feeds XSS
  item 11, SSRF item 6, redirect item 5):
  ```bash
  x8 -u "https://HOST/path" -w /opt/watch/wordlists/dell_params.txt -O url -o /tmp/x8.txt
  ```
  But x8 already runs in the watch-param lane — check the DB FIRST before re-running:
  ```bash
  ./.venv/bin/python - <<'PY'
  from database.db import Endpoints
  for e in Endpoints.objects(program_name="dell", x8_checked=True).only("example_url","params_from_x8"):
      if e.params_from_x8: print(e.example_url, e.params_from_x8)
  PY
  ```
  Discovered params are the input to dalfox (item 11) and the SSRF/redirect probes.

**1. Spring/Java exposure — heapdump + jolokia + actuator (highest EV, zero-FP)**
NOTE: the `watch-heavy` lane already runs these templates on every host and writes hits to
`Finding` — read those first (Part 3), don't re-run by default. Run manually ONLY to cover a
Spring host whose `Http.last_nuclei_run` is stale, and then target ONLY the Java/Spring hosts
(from `Http.tech`), not all 1460 — heapdump/jolokia mean nothing on a non-JVM host, a big list
overruns the shell timeout, and a couple of slow hosts can hang nuclei ~0-CPU, so run DETACHED:
```bash
cd /opt/watch && ./.venv/bin/python - <<'PY'
from datetime import datetime, timedelta
from database.db import Http
fresh=datetime.now()-timedelta(days=3); kw=("spring","tomcat","java","jetty","jboss","wildfly","weblogic")
hosts={ (h.final_url or h.url) for h in Http.objects(program_name="dell").only("url","final_url","status_code","tech","last_update")
        if h.status_code and (not h.last_update or h.last_update>=fresh)
        and any(any(k in (t or '').lower() for k in kw) for t in (h.tech or [])) }
open("/tmp/spring.txt","w").write("\n".join(sorted(hosts))+"\n"); print(len(hosts),"Spring hosts")
PY
# nuclei is SLOW to start and WILL overrun a 2-min shell timeout -> run DETACHED, then poll:
nohup nuclei -l /tmp/spring.txt \
  -t nuclei/private_templates/spring-actuator-heapdump.yaml \
  -t nuclei/private_templates/jolokia-jmx-exposure.yaml \
  -t nuclei/private_templates/spring-actuator-exposure.yaml \
  -H "User-Agent: $UA" -rl 60 -c 40 -timeout 6 -retries 0 -duc -ni -nc -stats=false \
  -o /tmp/spring_hits.txt >/tmp/spring.log 2>&1 &
echo "nuclei PID $!"   # later: `kill -0 $! && echo running || cat /tmp/spring_hits.txt`
```
Poll with `wc -l /tmp/spring_hits.txt` in a SEPARATE quick command. Any hit → load
`hunt-springboot`, pull the dump/MBeans, report. **Never re-run an identical scan that
timed out** — it's detached now; check the output file instead.

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
⚠️ interactsh does NOT work from this box — egress to interact.sh is blocked, so
`interactsh-client` hangs with no canary domain. Do NOT run it here (it will loop). Blind
SSRF is therefore NOT confirmable from this box unless you have your OWN reachable OOB
endpoint (a domain/server you control that this box CAN reach). Options: (a) confirm only
NON-blind SSRF — the response contains metadata **content** never in your request
(`AccessKeyId`, `ami-id`, `Metadata-Flavor: Google`, see §5b); (b) collect SSRF candidates
(params `url,uri,dest,redirect,next,callback,webhook,image,feed,proxy,target`) as leads for
later OOB testing from a box that can reach a collaborator. Pick another class instead of
fighting interactsh.

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
dalfox file /tmp/xss_urls.txt --header "User-Agent: $UA" --delay 150 \
  --skip-bav --waf-evasion --format plain -o /tmp/xss_hits.txt
```
(Correct flag is `--delay <ms>`, NOT `--rate-limit`. `--waf-evasion` forces
worker=1 + 3s/request — safe but slow, so use it only on WAF'd hosts and small
URL lists; drop it (keep `--delay`) for speed. Feed param-rich URLs, not bare SPA
hosts — a SPA that 200s every path has nothing for dalfox to reflect.)
Real only when the FULL payload comes back **unencoded as one block**
(`"><script>alert(1)</script>`) and executes in context. Entity-encoded, or only
the `alert(1)` substring reflected = FP. Let `dalfox` verify, then reproduce by hand.
Also try the auth/error/search params and non-GET reflections dalfox misses.

**11b. Reflected + CSP → load `hunt-csp-bypass`. The decision tree (don't give up at the CSP, don't lie about it either).**
A reflected param with a strict CSP is a MAYBE, not an automatic FP. Work it in order:

1. **Confirm injection context FIRST** (a dead end makes CSP moot). Reflect a unique
   marker, then see what survives UNENCODED at the sink:
   - `<` `>` survive in HTML body → you can inject a tag → go to step 2.
   - only inside an attribute (`"` encoded) → try attribute breakout / event handler;
     if `"` and `'` are encoded, usually dead.
   - inside a `<script>` JS string → try string breakout (`';`), template-literal, etc.
   - fully entity-encoded everywhere → **FP, stop.**
2. **Read the response's own CSP** (not a different page's). Classify `script-src`:
   - **absent / `'unsafe-inline'`** → plain reflected XSS, done. Report.
   - **`'strict-dynamic'` present** → host allow-list is IGNORED; you need a trusted
     script-gadget already loaded on the page (hard). Usually park as a lead.
   - **nonce/hash + host allow-list, NO `'unsafe-inline'`, NO `'strict-dynamic'`**
     → the allow-list is live → check it for a bypass primitive in step 3.
3. **Bypass primitives in an active allow-list** (you still need step-1 tag injection):
   - **Wildcard CDNs you can publish to**: `*.cloudfront.net`, `*.s3.amazonaws.com`,
     `*.storage.googleapis.com`, `*.azureedge.net`, `*.web.core.windows.net` → stand up
     your OWN bucket/distribution and load `src=`'d JS from it.
   - **JSONP / callback endpoints on an allow-listed host** (`?callback=`, `?jsonp=`):
     `<script src="https://allowed.host/api?callback=alert(document.domain)">`.
   - **Known gadget libs on allow-listed hosts** (AngularJS <1.8, etc.) → template-injection gadget.
   - none of these → it's genuinely CSP-mitigated → §5e **disprove**, note the CSP.
4. **Observed example (investors.delltechnologies.com):** `action`/`filenum`/`v` reflect,
   CSP `script-src` has a nonce + a host allow-list that INCLUDES `*.cloudfront.net` and
   `qmod.quotemedia.com` — so IF step 1 yields HTML-tag injection, that allow-list is the
   bypass path. Confirm step 1 by hand before claiming anything.

**Making it pay (report framing, see §7).** A confirmed reflected XSS is typically
Bugcrowd VRT **P3** on its own; it climbs to **P2** when you chain it to real impact
on an authenticated/sensitive origin — session/cookie theft, CSRF-token exfil, or an
account-takeover action performed as the victim. So once execution is proven: (a) show
`document.domain` is the in-scope host, (b) demonstrate reading something the victim's
session can see (mask PII per `evidence-hygiene`), (c) state the concrete impact, no
inflation. A precise P3 with a clean PoC pays; a hand-wavy "possible XSS" gets closed.
A CSP bypass that makes a "mitigated" reflection fire is itself worth writing up clearly —
it is the difference between N/A and a paid P3/P2.

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

---

## Long-Running Scan Discipline

A tool's foreground timeout (default 180s) is a harness limit, not a verdict on the
target. A scan killed mid-flight leaves partial or empty output, and that output is
NOT evidence of "zero hits."

- **Background any scan expected to exceed ~2 minutes** (`background=true` +
  `notify_on_complete=true`), or split the target list into chunks that fit the
  budget. Do not re-run the identical full-list command expecting a different
  outcome — that is the same loop with the same result.
- **A timed-out scan with empty/partial output is an INCOMPLETE SWEEP**, not a
  clean negative. Record it as `incomplete (timeout)` in the session notes and
  re-run in the background; never write "no hits" or "nothing found" from a
  truncated run. (nuclei writes results as it goes, so 0 lines after a timeout
  means it never finished starting on that list, not that nothing matched.)
- **Always run the bare-control request first** before interpreting a 403/empty
  body as "no reflection / no exposure" — a WAF edge can 403 the payload while
  200-ing the canary. A payload-only 403 with no canary control is uninterpretable.
- **Count and report what actually ran**: #hosts probed, #completed, #hits. A
  summary with no Part-1 tool output (or with an incomplete sweep dressed up as a
  negative) is a failed session, not a clean one.

**Lesson from an authorized engagement:** A nuclei spring-actuator sweep over 1460
live hosts was killed at the 180s default with 0 output lines; re-running the
identical command produced the same timeout. The honest record is "incomplete,"
not "no actuator exposure" — and the cors template on the same list did complete
and returned 85 reflection hits, proving the list and the tool both work.

---
"

Exact, verified behaviour of the installed tools on THIS box. These were learned
the hard way; follow them so you don't waste a run or misread a result.

**dalfox**
- The rate knob is `--delay <ms>` (delay to the same host). There is NO
  `--rate-limit` flag — it errors out.
- `--waf-evasion` forces worker=1 + 3s/request: safe but very slow. Use it ONLY on
  WAF'd hosts and SMALL lists. For normal runs use `--delay 100 --worker 30`.
- `--skip-bav` skips the non-XSS "basic another vuln" checks; `--only-poc 'r,v'`
  prints only reflected/verified POCs (cuts noise).
- Feed **param-rich URLs** (from `Urls` where `params` is set), not bare hosts. A
  SPA with no reflecting params gives dalfox nothing.
- It is THOROUGH and slow — so slow it can blow even a 10–20 min budget on <10
  URLs. Always wrap it in `timeout` and treat the `[I] Reflected <x> param` lines
  it prints as the real output (LEADS = value echoed back); a kill/exit 124 is NOT
  "no XSS". Don't wait for it to "finish"; harvest the reflected-param leads.
- **CHECK CSP before chasing a reflected param.** dalfox prints the response CSP.
  A `script-src` with a `nonce-...` or a host allow-list and NO `'unsafe-inline'`
  blocks reflected `<script>`/inline-handler XSS — the reflection is real but not
  exploitable unless you find a CSP bypass via a whitelisted host (JSONP/callback,
  open redirect on an allowed origin). Observed live on `investors.delltechnologies.com`
  (`action`/`filenum`/`v` reflect, but strict nonce CSP) — that's a §5e disprove,
  not a finding. Spend XSS effort on hosts with weak/absent CSP.

**ffuf**
- Always use `-ac` (auto-calibrate) — it filters soft-404s.
- **0 hits on a SPA that returns 200 for every path is the CORRECT result, not a
  block.** Many Dell app hosts are SPAs; path fuzzing finds nothing there — that is
  information, not failure. Do not retry endlessly or call it "blocked".
- Raise the wordlist (`/usr/share/seclists/...`) only when a host looks worth it;
  `/opt/watch/wordlists/watch_content_medium.txt` is the quick default.

**x8**
- x8 ALREADY runs in the `watch-param` lane → check `Endpoints.params_from_x8`
  FIRST; only run live on a specific endpoint it hasn't covered.
- Flags: `-u <url>` `-w <wordlist>` `-O url -o <file>`. Run against an endpoint that
  actually takes params; a bare `/` with no params yields nothing.

**Akamai / WAF reality (Dell especially)**
- A real browser UA gets you the HTTP layer (200/302), but a tool's TLS/JA3 can
  still 403 — most on `www.dell.com`. App/sandbox hosts (`*sbx*`, `*-poc*`,
  internal portals) are usually reachable. Prefer those for active testing.
- Cookies from a Playwright login are fingerprint-bound: curl with them → 403.
  Do authenticated requests from inside the same Playwright context (§10b).

**nuclei**
- Slow to start in this env (~15-40s); that's normal, don't kill it early.
- On more than a handful of hosts it WILL overrun a ~2-min shell timeout. **Run it
  DETACHED** (`nohup nuclei ... -o /tmp/out.txt >/tmp/n.log 2>&1 &`) and poll the
  output file (`wc -l /tmp/out.txt`) in separate quick commands. A timed-out run is
  NOT a failure and **must NOT be re-run identically** — that just loops and trips the
  repeated-command guardrail (observed). Shrink the host set (target by `tech`) or wait.
- Private templates already run in the http lane; re-run manually only to target a
  fresh host set. Pass the browser UA with `-H` on WAF'd targets.

**interactsh-client — DISABLED (fast-fail shim) ON THIS BOX**
- Egress to interact.sh / `*.oast.*` is blocked, so the real tool hangs with NO canary.
  It has been replaced by a shim at `/root/go/bin/interactsh-client` that returns INSTANTLY
  with a "disabled" message (real binary saved as `interactsh-client.real`; restore with
  `mv .../interactsh-client.real .../interactsh-client`). So running it no longer hangs —
  but OOB still doesn't work; just read the message and move on, do not retry.
- Consequence: blind SSRF/OOB is not confirmable here (§12 item 6). Confirm only non-blind
  SSRF (metadata content in the response), or collect candidates for later OOB from a box
  that can reach a collaborator you control.

**Liveness — read the `Http` collection, don't re-probe**
- `Urls`/`Endpoints` are historical crawl data full of DEAD hosts (`educationsbx.dell.com`
  no longer resolves) and WAF-403 hosts. But you do NOT need to re-run httpx to find the
  live ones: the Watch `http` lane probes every target with httpx **~2x/day** and stores
  status/title/tech/headers in the **`Http`** collection (`last_update` tells you how
  fresh). Pull live hosts from `Http` (status set + recent `last_update`) — instant, vs
  minutes of re-probing. See the live-host helper in §12.
- Re-probe a SINGLE host live only at the moment you test it (confirm still up); never a
  full httpx sweep — that just duplicates the http lane.
- `Http.tech` already fingerprints the stack (target Spring/Tomcat/Java for heapdump/jolokia),
  and `Http.headers` is stored (you can pre-filter CORS/CSP/actuator candidates from it).
- A `status_code` of `None` in `Urls` means "never re-probed", not dead — but prefer `Http`
  over `Urls` for liveness anyway.

**Target selection (the meta-lesson)**
- Pick param-rich / app hosts, not bare SPA roots. Query `Urls` for in-scope hosts
  with `params`, and prefer reflective pages (search, error, content with
  tab/query params) for reflected XSS.
- On Dell specifically, most param-rich hosts are either Akamai-403 to tools or
  dead; the few that answer (e.g. `investors.delltechnologies.com` 202) are the
  real surface. Don't burn the session on hosts that don't respond.
