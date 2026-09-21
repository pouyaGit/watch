# AEC-1 EPIC8 Fix — API Key Propagation through Command Center Navigation

## Status: IMPLEMENTATION COMPLETE

## Problem

`/ui/aec/dashboard?api_key=XXX` rendered correctly, but internal AEC
navigation (quick-actions, case detail links) dropped the query param,
so every tab navigation hit unauthenticated 401s.

## Root cause

The AEC page handlers rendered templates without injecting the
`api_key_qs` context variable that every other Watch UI router
(commands, pages, runs, programs, research) provides. Templates had no
way to append the key to internal links.

## Fix (Option A — server-side, consistent with existing Watch architecture)

1. **`backend/routers/aec.py`** — added `_page_api_key(request)`: reads
   `?api_key=` from the request query string — which the existing
   `APIKeyMiddleware` already validated before the handler runs — and
   injects `api_key_qs` into every AEC page payload context (7 UI
   handlers). Using the request query instead of `backend.deps.API_KEY`
   keeps aec.py's narrow-import guard intact (it bans `backend.*`
   imports).
2. **`web/templates/aec/dashboard.html`** — quick-action links append
   `?api_key={{ api_key_qs }}` when present.
3. **`web/templates/aec/cases.html`** — case-detail cell links append
   the key the same way.

No auth middleware changes; no API-key validation changes; no new
dependencies; keys are never logged and never appended to external
links or static assets.

## Security guarantees (verified)

- Auth middleware untouched: `api.py`, `backend/deps.py`,
  `backend/middleware/*` byte-identical (git diff empty); bad key still
  401.
- api_key is only ever inserted INTO href attributes of internal AEC
  links, bound to the `api_key_qs` variable — never a hardcoded literal.
- External URLs (none in AEC templates) and `/static/*` assets never
  receive the key.
- Navigation without an api_key renders clean links (empty `api_key_qs`).

## Tests

- **15 new tests** in `tests/test_aec_ui_apikey.py`:
  - dashboard URL with api_key → links carry it
  - dashboard quick-actions keep api_key on all 6 destination pages
  - key-free pages render when reached with a key
  - case detail link keeps api_key
  - navigation without api_key stays clean
  - static assets never carry the key; no external-link leakage
  - middleware untouched (no auth imports in router source)
  - page payload builders stay key-free (injection happens in handlers)
- **`tests/test_aec_ui_pages.py`** — secret-literal guard updated: the
  only allowed `api_key=` forms are `api_key={{ api_key_qs }}`
  placeholders; hardcoded values still banned.
- **Full AEC regression: 2149 tests OK** (2134 prior + 15 new).
- Read-only guard: READ-ONLY VERIFIED. Whitespace: clean.

## Files changed

- `backend/routers/aec.py` (+`_page_api_key`, +api_key_qs in 7 handlers)
- `web/templates/aec/dashboard.html` (quick-actions)
- `web/templates/aec/cases.html` (case cell links)
- `tests/test_aec_ui_apikey.py` (new, 15 tests)
- `tests/test_aec_ui_pages.py` (secret-literal guard refinement)

## Limitations

- Header-auth (`X-API-Key`) sessions still get clean links; query-param
  keys propagate. This mirrors the reported bug scope (?api_key=) and
  the existing convention.

## READY FOR PROMOTION: YES