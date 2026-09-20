# Attack Surface UI Integration Fix

## Summary

The Attack Surface Intelligence backend and its Command Center section already
existed, but the section was only reachable by scrolling the Command Center
page — there was no navigation entry anywhere in the UI. This fix exposes the
existing feature through the normal navigation flow without redesigning it.

Clicking **Attack Surface** in the sidebar (a sub-item directly under
**Command Center**) or the **Attack Surface** quick-action on the Command
Center jumps straight to the existing `ATTACK SURFACE INTELLIGENCE` section on
`/ui/command#attack-surface`. The section is rendered from the existing
`/api/command/attack-surface` data; no backend behavior changed.

## Changes

1. **Sidebar navigation entry** (`web/templates/base.html`)
   - Added a sub-link under *Command Center* in the **Overview** group:
     `⌖ Attack Surface` → `/ui/command?api_key=…#attack-surface`.
   - Uses the shared `attack_surface_url` context value with a defensive
     fallback (`command_url ~ '#attack-surface'`) so it can never render an
     empty href.

2. **URL context** (all page routers)
   - Added `"attack_surface_url": build_url("/ui/command") + "#attack-surface"`
     to the common `_ctx()` used by:
     `backend/routers/pages.py`, `runs.py`, `programs.py`,
     `research_pages.py`, `command_center.py`.
   - `build_url` keeps API-key propagation correct: the fragment is appended
     after the query string (`/ui/command?api_key=…#attack-surface`).

3. **Command Center section anchor** (`web/templates/command_center.html`)
   - The existing `ATTACK SURFACE INTELLIGENCE` section label now carries
     `id="attack-surface"` and the `section-anchor` class so the sidebar jump
     lands on it instead of the top of the page.
   - Added an `Attack Surface` quick-action card to the Command Center
     quick-actions row.

4. **Styling** (`web/static/css/custom.css`)
   - `.side-link.side-sub` indents the nav entry under Command Center.
   - `.section-anchor { scroll-margin-top: 72px; }` keeps the anchored section
     label clear of the sticky topbar.

5. **Tests** (`tests/test_attack_surface_api.py`)
   - Added `TestAttackSurfaceNavigation`: verifies the sidebar link exists,
     points at `/ui/command#attack-surface`, and that the target anchor
     `id="attack-surface"` is present; verifies the quick-action card; and
     verifies the sidebar link is present on another page (`/`) so the shared
     context is wired everywhere.

## Files

| File | Change |
|---|---|
| `web/templates/base.html` | sidebar "Attack Surface" sub-link |
| `web/templates/command_center.html` | `id="attack-surface"` anchor + quick-action card |
| `web/static/css/custom.css` | `.side-sub` indent + `.section-anchor` scroll margin |
| `backend/routers/pages.py` | `attack_surface_url` context |
| `backend/routers/runs.py` | `attack_surface_url` context |
| `backend/routers/programs.py` | `attack_surface_url` context |
| `backend/routers/research_pages.py` | `attack_surface_url` context |
| `backend/routers/command_center.py` | `attack_surface_url` context |
| `tests/test_attack_surface_api.py` | navigation/quick-action/anchor tests |

No database, API-schema or attack-surface classifier/scorer behavior changed.

## Verification

- **Route works**: `/ui/command` returns 200 and renders the section; the
  sidebar link resolves to `/ui/command#attack-surface` with the API key
  propagated.
- **Template renders**: `/ui/command` contains the `id="attack-surface"`
  anchor and the `Attack Surface` sidebar/quick-action entries.
- **API data displayed**: the section is the same Attack Surface Intelligence
  payload (`summary` / `discovery` / `candidates` / `priority_queue`) already
  served by `GET /api/command/attack-surface`.
- **Navigation present on every page**: smoke-checked `/`, `/ui/programs`,
  `/ui/tasks`, `/ui/runs`, `/ui/research`, `/ui/domains`, `/ui/endpoints`,
  `/ui/parameters`, `/ui/xss`, `/ui/kb`, `/ui/reports` — all 200 and all render
  the sidebar link.

### Tests

```
python3 -m unittest tests.test_attack_surface_api            # 13 tests, OK
python3 -m unittest tests.test_attack_surface \
  tests.test_attack_surface_classifier tests.test_attack_surface_api \
  tests.test_command_center tests.test_command_center_intelligence \
  tests.test_command_center_operations tests.test_repository_intelligence \
  ai.test_knowledge_store ai.test_xss_researcher \
  ai.test_xss_llm_researcher ai.test_openrouter               # 221 tests, OK
```

`git diff --check` is clean.

## Commit / Push

COMMIT STATUS: committed on `agent/daily-development`
PUSH STATUS: not pushed (push is always manual in this workflow)
READY TO PUSH: YES
