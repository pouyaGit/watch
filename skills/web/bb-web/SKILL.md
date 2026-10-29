---
name: bb-web
description: "bb-web — Client-Side & HTTP-Hygiene Testing Reference. Companion to `bb-ops/playbooks/{xss,xss-dalfox,dom-xss,cors,open-redirect,config-review,csrf,file-upload,http-smuggling,cache-poison,host-header}.yaml`. Load in web-analyzer tasks."
---

# bb-web — Client-Side & HTTP-Hygiene Testing Reference

Companion to `bb-ops/playbooks/{xss,xss-dalfox,dom-xss,cors,open-redirect,config-review,csrf,file-upload,http-smuggling,cache-poison,host-header}.yaml`.
Load in web-analyzer tasks.

## Dalfox v3.2.0 (CLI + MCP)
- Binary: `/usr/bin/dalfox`. CLI: `dalfox scan|server|payload|mcp`. MCP tools available via the
  `dalfox` MCP server: `preflight_dalfox` (dry sizing), `scan_with_dalfox` (async submit),
  `get_results_dalfox` (poll w/ suggested_poll_interval_ms), `list/cancel/delete_scan_dalfox`.
- Workflow: preflight → scan → poll. Findings tags: [V] vulnerable (DOM-verifiable, actionable),
  [A] AST source→sink (confirm in browser), [R] reflected only (candidate, NOT a finding),
  [I] informational. Exit codes 0/1/2 (0=none, 1=findings, 2=error).
- Auth'd targets: `--input-type raw-http request.txt` or `--input-type har capture.har` replay
  Burp/DevTools captures verbatim. Session monitoring auto-on with creds; use
  `--session-check-url <cheap /api/me>`; SESSION_LOST/CONNECTION_FAILED runs prove nothing.
- Stored XSS: `dalfox sxss --url <sink> --data <body> --sxss-url <retrieval>` then fetch retrieval
  URL to confirm render. Blind: `-b <oast>` or `--blind-oob=oast.fun,oast.me`.
- Pacing: `-r/--rate-limit <req/s>`, `--delay <ms>`, `--scan-timeout <s>`, `--max-targets-per-host`.
- Always `--dry-run` first; baseline WAF state before trusting a 'clean' result.
- See `bb-ops/playbooks/xss-dalfox.yaml` for full flag guidance and verification gates.

## XSS (context matters)
```
# HTML context
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(1)>
# attribute context
" onmouseover="alert(1)
# JS string context
';alert(1)//
-alert(1)-
# URL context
javascript:alert(1)
```
- WAF bypass chain: `<svg/onload>` → `<img/src=x onerror=…>` → unicode/HTML entities →
  double-encode → `\x3c` → tag without spaces `<svg/onload=alert(1)//`.
- Stored: place payload in a stored field (name, comment, config value), then check
  rendering elsewhere. Headless browsers often can't confirm — flag `needs_human_verification`.

## DOM XSS
- Map source→sink in bundles: `location.hash/search`, `postMessage`, `document.referrer`,
  `localStorage` → `innerHTML`, `document.write`, `eval`, `setTimeout(str)`, `createContextualFragment`.
- Hash-based (fragment) payloads bypass server filtering entirely.

## CORS
```
curl -s -i -H "Origin: https://evil.com" https://HOST/api/x
```
- Signal: `access-control-allow-origin: https://evil.com` + `access-control-allow-credentials: true`.
- Confirm the API returns sensitive, authenticated data (tokens, PII) to that origin.
- `null` origin reflection is a real (if narrower) vector.

## Open redirect
```
/redirect?url=//evil.com    /redirect?url=https://evil.com@trusted
/redirect?url=\/\/evil.com  /redirect?url=javascript:alert(1)   //evil.com%2f..%2f
```

## Clickjacking
- Missing `X-Frame-Options`/`CSP frame-ancestors` + an authenticated state-changing page.

## Host header / cache
- Absolute-URL redirects reflecting Host; duplicate/whitespace Host headers; cache
  poisoning via `X-Forwarded-Host`/`X-Forwarded-Proto` on cacheable endpoints.

## Output
- Evidence: HTTP pair; for XSS include the sink + verification note. Never self-confirm.
- CORS without ACAC or without sensitive data = low/info; say so in the finding.
