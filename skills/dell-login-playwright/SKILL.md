---
name: dell-login-playwright
description: "Log into Dell.com via Playwright behind Akamai bot defense."
---

# Dell.com Login via Playwright (Akamai-hardened)

Dell.com Akamai blocks: headless browser_exec (403 on UA), `connect_over_cdp` (tab dies between messages), header-spoofed UA (TLS/JA3 fingerprint mismatch).

## Working method

1. **Standalone playwright** (NOT browser_exec): `PYTHONPATH=/root/.local/lib/python3.12/site-packages python3 script.py`. System python has playwright 1.62 + chromium-1234.
2. **Fresh `browser.new_context(user_agent=<full Chrome UA>)`** — UA must be set at context creation, not via extra headers.
3. **CAPTCHA is mandatory**: Dell triggers text-distortion CAPTCHA for datacenter IPs. Flow: dismiss cookie banner (`Tout Refuser`) → screenshot → crop region (~x15-34%, y52-72%) → show crop to user → user reads chars → fill email + captcha + `#btnContinue`.
4. **Password from vault without logging**: `VaultStore().resolve_secret(handle).get("password","")` — never print it.
5. **Email 2FA**: after `#btnSignIn`, page goes to `/di/trustelevation/mfa`. Fill 6 `#otpBoxmfaOtpBoxN` boxes one by one with 300ms gaps, click `#btnVerify`. Single script must cover email→captcha→password→MFA without exiting (poll `/tmp` solution files).
6. **Post-login onboarding**: `addpasskey` page → click link `a:has-text('mot de passe')`; `addmobile` page → click `#btnSkip_AddMobilePage`. Then save `storage_state`.
7. **xvfb for headed if needed**: `xvfb-run -a -s "-screen 0 1366x768x24" env PYTHONPATH=... python3 x.py`. Headless works for login; Akamai may 403 later browsing even with valid cookies (bot manager scores the browser, not the session).
8. **State backup before logout tests**: `cp state.json state.bak` — a logout-flow test kills the server session; cookies in file become dead.

## Limits learned

- Each login burns one email 2FA code; Dell locks account after 6 failed MFA attempts — never guess codes.
- `dell_state.json` cookies + `dci_jwt` work for API fetch from inside playwright (same fingerprint), but curl with same cookies gets Akamai 403 — fingerprint-bound, not portable.
- IDOR needs two accounts; single-session can only prove auth posture (401s) and own-data scoping.
