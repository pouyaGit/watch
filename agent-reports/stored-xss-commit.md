# Stored XSS Commit Report

## Commit Hash

`2d6adabf12863eea644b7052dca289ca25f30710` (short: `2d6adab`)

## Commit Message

```
Integrate stored XSS round-trip execution verification
```

## Files Included

10 files in the commit:

| File | Mode | Lines (ins / del) | Role |
| ---- | ---- | ----------------- | ---- |
| `ai/schemas/xss_finding.py` | M | +7 / -0 | +`round_id`, +`read_url` audit fields |
| `ai/schemas/xss_verification.py` | M | +116 / -0 | +`DialogEvent`, +`NetworkOracleEvent`, +`EvalInvocation`; oracle + SUBMIT forensics fields |
| `ai/test_browser_executor.py` | M | +171 / -0 | Stored XSS / Oracle boundary changes only (`evaluate_e2_network` import + `BrowserEvidenceExecutorOracleBoundaryTests`) |
| `ai/test_xss_oracle.py` | M | +893 / -0 | Execution-oracle infrastructure tests |
| `ai/test_xss_stored_round.py` | A | +1795 / -0 | New Stored XSS round-trip test suite (62 tests) |
| `ai/test_xss_verification.py` | M | +478 / -32 | Stored XSS tests rewritten to use the new oracle-round model |
| `ai/verification/browser_executor.py` | M | +175 / -0 | Clean READ navigation, E1/E2/E3 channels, oracle-path detection |
| `ai/verification/http_executor.py` | M | +136 / -0 | SUBMIT shape gate, redirect forensics, SHA-256 body hashing |
| `ai/verification/oracle.py` | A | +620 / -0 | New execution-oracle infrastructure |
| `ai/verification/verifier.py` | M | +1174 / -15 | Stored round construction, W1/W2/W3 hardening, demoted legacy `_classify_stored` |

Totals: **5233 insertions, 332 deletions across 10 files**.

## Confirmation That Unrelated Changes Remained Unstaged

Pre-existing unrelated tracked modifications, preserved unstaged (not
included in the commit):

| File | Status |
| ---- | ------ |
| `AGENTS.md` | ` M` (unstaged) |
| `README-watch-updated.md` | ` D` (unstaged deletion) |
| `ai/test_http_executor.py` | ` M` (unstaged; all three hunks of pre-existing cross-host / cross-port tests) |
| `ai/test_browser_executor.py` | ` M` (unstaged residual — the `FakePage.emit_response` plumbing change; the Stored XSS / Oracle boundary hunks are in the commit) |
| `ai/test_watch_param_discovery.py` | ` M` (unstaged) |
| `ai/test_xss_case_builder.py` | ` M` (unstaged) |
| `crawl/watch_param_discovery.py` | ` M` (unstaged) |
| `database/change_events.py` | ` M` (unstaged) |
| `database/db.py` | ` M` (unstaged) |

Untracked directories, preserved unstaged:

- `agent-reports/`
- `tests/`
- `wordlists/`

No unrelated file was staged. No staged file was modified beyond the
approved Stored XSS / Oracle changes.

## Final Git Status

```
$ git status --short
 M AGENTS.md
 D README-watch-updated.md
 M ai/test_browser_executor.py
 M ai/test_http_executor.py
 M ai/test_watch_param_discovery.py
 M ai/test_xss_case_builder.py
 M crawl/watch_param_discovery.py
 M database/change_events.py
 M database/db.py
?? agent-reports/
?? tests/__init__.py
?? tests/test_change_events.py
?? tests/test_dashboard_logic.py
?? tests/test_page_render.py
?? tests/test_routers_fixes.py
?? tests/test_tz.py
?? wordlists/
```

All entries are unchanged from the staging review final state.

```
$ git show --stat --oneline --decorate HEAD
2d6adab (HEAD -> main) Integrate stored XSS round-trip execution verification
 ai/schemas/xss_finding.py           |    7 +
 ai/schemas/xss_verification.py      |  116 +++
 ai/test_browser_executor.py         |  171 ++++
 ai/test_xss_oracle.py               |  893 +++++++++++++++++
 ai/test_xss_stored_round.py         | 1795 +++++++++++++++++++++++++++++++++++
 ai/test_xss_verification.py         |  478 ++++++----
 ai/verification/browser_executor.py |  175 +++-
 ai/verification/http_executor.py    |  136 ++-
 ai/verification/oracle.py           |  620 ++++++++++++
 ai/verification/verifier.py         | 1174 ++++++++++++++++++++---
 10 files changed, 5233 insertions(+), 332 deletions(-)
```

`HEAD -> main` confirms the commit is on the local `main` branch and
nothing was pushed.

## Commit Status

**Commit was created successfully.**

- Hash: `2d6adabf12863eea644b7052dca289ca25f30710`
- Message: `Integrate stored XSS round-trip execution verification`
- Parent: `f74fd2f Integrate XSS execution oracle confirmation state machine`
- Files: 10 (8 modified, 2 new)
- Not pushed.
- No amend performed.
- No additional files staged.
- No unstaged work modified or reverted.
- `git diff --check` clean (working tree).
- `git diff --cached --check` clean (no remaining staged changes).