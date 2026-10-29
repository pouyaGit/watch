---
name: bb-report
description: "bb-report — Reporting Discipline. Companion to assessor + reporter roles."
---

# bb-report — Reporting Discipline

Companion to assessor + reporter roles.

## Report anatomy (YesWeHack)
A triager must reproduce in under a minute. Structure:
```
Title: <Type> on <Endpoint> — <Asset>   (e.g. "IDOR on GET /v1/profiles/{id}")
Summary           2-3 non-technical sentences
Severity / CVSS   exact values + asset value (Medium = €500, High = €2,000, ...)
Affected Asset    full URL, mark in-scope
Reproduction      numbered steps, copy-paste curl, paste exact req+res
Impact            the business consequence, not just "data exposed"
Remediation       concrete, actionable
Evidence          file paths + screenshots + OAST logs
```

## Good curl evidence
```bash
# include FULL headers + working creds (redact if the report is shared publicly)
curl -s -X GET "https://HOST/v1/profiles/aaaa-...-uuid" \
  -H "Authorization: Bearer <token>" \
  -H "AC-Property-ID: <uuid>" | jq .
```

## Severity calibration (use assessor, don't inflate)
- Missing security headers, version banners, TLS issues, user enumeration → Info/Low
  (often NON-qualifying — check program scope).
- Blind SSRF without exploitation, subdomain takeover without PoC → often excluded.
- CORS with credentials + sensitive response → Medium/High. Without ACAC → Low.
- Source-map/source-code disclosure of in-scope app → Medium (program-dependent).

## Leak rules (reports of secrets)
- Source in-scope + impact in-scope → eligible.
- Source in-scope + impact out-of-scope → NOT eligible.
- State this explicitly in the report when relevant.

## Rules
- One root cause per report. Reproducible or mark `draft-incomplete`.
- Never submit. Draft to `bb-ops/reports/`, human submits.
