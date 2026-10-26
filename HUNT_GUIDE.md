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

---

## 9. Quick start (per session)

1. `bb-methodology` → orient.
2. Load program scope from `/opt/watch/programs/`.
3. Pull `status="open"` candidates from the DB (§3a), highest severity first.
4. For each: classify → load the `hunt-*` skill (§4b) → run the §5 playbook.
5. Disprove → `status="false_positive"`. Confirm → `status="triaged"`.
6. `triage-validation` → if it passes, write the report (§7). Else discard.
