---
name: bb-recon
description: "bb-recon — Discovery Methodology & Tool Commands. Scope: passive + low-noise active recon against in-scope web targets. Load this skill in recon-executor and content-collector tasks. **Every command below must pass the scope guard first** (`python3 bb-ops/lib/scope.py check <target> <host>`)."
---

# bb-recon — Discovery Methodology & Tool Commands

Scope: passive + low-noise active recon against in-scope web targets. Load this skill
in recon-executor and content-collector tasks. **Every command below must pass the
scope guard first** (`python3 bb-ops/lib/scope.py check <target> <host>`).

## 0. Pre-flight
- Read `memory/targets/<target>/target.md`: scope, creds, OAST callback, auth status.
- Record OAST callback for SSRF/interaction detection.

## 1. Subdomain enumeration (passive first, then active)
```
subfinder -d example.com -all -o subs.txt
amass enum -passive -d example.com
assetfinder --subs-only example.com
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u
# resolve + de-dup
cat subs.txt | sort -u | dnsx -silent -a -resp -o resolved.txt
# live hosts + tech
cat resolved.txt | httpx -silent -title -server -status-code -tech-detect -o live.txt
```

## 2. URL / JS / historical collection
```
katana -u https://app.example.com -d 3 -jc -o urls.txt            # crawl + JS analysis
gau --subs example.com | sort -u > historical.txt                  # wayback + commoncrawl + otx
waybackurls example.com | sort -u >> historical.txt
# JS bundle analysis: download all script tags, grep for endpoints
grep -rhoE "https?://[a-zA-Z0-9./_-]+" bundle.js | sort -u
grep -rhoE '"/[a-zA-Z0-9_/-]+"' bundle.js | sort -u               # API path candidates
grep -rniE "secret|token|apikey|api_key|password|client_id" bundle.js
```

## 3. Technology fingerprinting
```
httpx -l live.txt -silent -tech-detect -json -o tech.json
curl -sI https://host | sed -n '1p;/server/i'                     # manual header check
# detect known-framework endpoints
#   Express:   /  -> x-powered-by
#   Spring:    /actuator, /swagger-ui.html, /v3/api-docs
#   Django:    /admin/
#   GraphQL:   /graphql, /query, /gql (POST, content-type application/json)
#   Keycloak:  /auth/realms/{realm}/.well-known/openid-configuration
```

## 4. GitHub / secret recon (in-scope orgs/repos only)
```
gh search repos --owner <org> --limit 100
gh api "orgs/<org>/repos?per_page=100" | jq -r '.[].clone_url' | while read u; do git clone -q "$u" /tmp/recon/$u; done
gitleaks detect --source /tmp/recon --report-format=json --report-path=gitleaks.json
trufflehog git https://github.com/<org>/<repo> --json
grep -rniE "(api[_-]?key|client[_-]?secret|BEGIN (RSA|OPENSSH|EC) PRIVATE|password *= *[^ ]+)" /tmp/recon
```

## 5. Live probe + port discovery (web only)
```
naabu -l live.txt -top-ports 1000 -o ports.txt                    # web-adjacent ports
nuclei -l live.txt -t http/exposures -t http/misconfiguration -severity low,medium,high
```

## 6. Parameter discovery (after endpoints exist)
```
arjun -u https://host/api/endpoint -m GET,POST --stable
x8 -u https://host/api/endpoint --wordlist /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

## 7. LLM-assisted source research (multi-agent prompt)
Adam Kues' approach (Searchlight Cyber, 2026): a long-running prompt designed for aggressive
multi-agent use, scoped to decompiled/downloaded source, can autonomously find full chains.
Reusable pattern for our targets:
```
1. DOWNLOAD source first (SPA bundles, sourcemaps, decompiled jars/classes when available).
2. Scope the prompt tightly: <TARGET + exact component>, "find a pre-auth RCE" style objective.
3. Give the agent the artifact paths and read access; require it to PROVE each step with the
   actual code/endpoint before proposing it.
4. Instruct it to emit a numbered chain (each step independently testable), matching our
   chain-link discipline (verify.dag.yaml / report.dag.yaml gates).
5. Human verifies + reproduces every step non-intrusively. Never submit a model-proposed
   step that wasn't reproduced.
```
- Lesson source: JFrog Artifactory pre-auth RCE (edrabb.fr) found via a Codex run pointed at
  decompiled source using this prompt style — trailing-slash bypass -> refresh token ->
  claim confusion -> Logback RCE.
- Always keep scope guard + program rules (no scanning/DoS) in the prompt too.

## Output discipline
- Every result → `lib/dedup.py upsert <target> asset|endpoint <record>`.
- Raw artifacts → `memory/targets/<target>/evidence/`.
- Emit one `evidence.recorded` event per meaningful batch (1-line summary).
- Never paste full tool dumps into your reply — summarize.

## Safety
- Passive = default. No active fuzzing against hosts without an in-scope confirmation.
- If a subdomain resolves to an IP on a third-party CDN (e.g. S3/Cloudfront without the
  owner's DNS), stop and flag for scope review — don't scan.
