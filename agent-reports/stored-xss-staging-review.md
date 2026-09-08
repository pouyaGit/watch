# Stored XSS Staging Review

## Verdict

**READY TO COMMIT**

## Initial Working Tree

```
$ git status --short
 M AGENTS.md
 D README-watch-updated.md
 M ai/schemas/xss_finding.py
 M ai/schemas/xss_verification.py
 M ai/test_browser_executor.py
 M ai/test_http_executor.py
 M ai/test_watch_param_discovery.py
 M ai/test_xss_case_builder.py
 M ai/test_xss_oracle.py
 M ai/test_xss_verification.py
 M ai/verification/browser_executor.py
 M ai/verification/http_executor.py
 M ai/verification/verifier.py
 M crawl/watch_param_discovery.py
 M database/change_events.py
 M database/db.py
?? agent-reports/
?? ai/test_xss_stored_round.py
?? ai/verification/oracle.py
?? tests/__init__.py
?? tests/test_change_events.py
?? tests/test_dashboard_logic.py
?? tests/test_page_render.py
?? tests/test_routers_fixes.py
?? tests/test_tz.py
?? wordlists/
```

Two pre-existing issues were fixed before staging:

1. `ai/test_xss_oracle.py:1081` had a stray blank line at EOF.
2. `ai/verification/oracle.py:621` had multiple blank lines at EOF
   (a new-file whitespace issue).

Both fixed by removing the trailing blank lines only; no logic
modified.

## Files Staged

```
$ git diff --cached --name-status
M	ai/schemas/xss_finding.py
M	ai/schemas/xss_verification.py
M	ai/test_browser_executor.py
M	ai/test_xss_oracle.py
A	ai/test_xss_stored_round.py
M	ai/test_xss_verification.py
M	ai/verification/browser_executor.py
M	ai/verification/http_executor.py
A	ai/verification/oracle.py
M	ai/verification/verifier.py
```

| File | Status | Role |
| ---- | ------ | ---- |
| `ai/schemas/xss_finding.py` | M | +`round_id`, +`read_url` audit-only fields |
| `ai/schemas/xss_verification.py` | M | +`DialogEvent`, +`NetworkOracleEvent`, +`EvalInvocation`; +`oracle_seed`/`oracle_value`/`oracle_version`/`oracle_identity`/`round_id`; SUBMIT forensics fields |
| `ai/test_browser_executor.py` | M (partial) | `+evaluate_e2_network` import + `BrowserEvidenceExecutorOracleBoundaryTests` (Stored XSS / Oracle boundary only) |
| `ai/test_xss_oracle.py` | M | +893 lines of execution-oracle infrastructure tests |
| `ai/test_xss_stored_round.py` | A | New 1795-line Stored XSS round-trip suite (62 tests) |
| `ai/test_xss_verification.py` | M | Stored XSS tests rewritten to use the new oracle-round model |
| `ai/verification/browser_executor.py` | M | Clean READ navigation, E1/E2/E3 channels, oracle-path detection |
| `ai/verification/http_executor.py` | M | SUBMIT shape gate, redirect forensics, SHA-256 body hashing |
| `ai/verification/oracle.py` | A | New 620-line execution-oracle infrastructure |
| `ai/verification/verifier.py` | M | Stored round construction, W1/W2/W3 hardening, demoted legacy `_classify_stored` |

## Files Intentionally Unstaged

These tracked changes are PRE-EXISTING UNRELATED and are left for a
separate commit or future work:

```
$ git diff --name-status
M	AGENTS.md
D	README-watch-updated.md
M	ai/test_browser_executor.py
M	ai/test_http_executor.py
M	ai/test_watch_param_discovery.py
M	ai/test_xss_case_builder.py
M	crawl/watch_param_discovery.py
M	database/change_events.py
M	database/db.py
```

| File | Reason unstaged |
| ---- | --------------- |
| `AGENTS.md` | Doc-only addition of the "Agent Reports" section (pre-existing unrelated) |
| `README-watch-updated.md` (D) | Tracked-file deletion (pre-existing unrelated) |
| `ai/test_browser_executor.py` (residual) | FakePage plumbing change for `emit_response` (`Req()` → `Req(from_main_frame)`); pre-existing test-helper refactor — NOT required by the new oracle tests; both forms are functionally equivalent (the class-level `from_main_frame` attribute remains set inside the inner `Req` class definition) |
| `ai/test_http_executor.py` | Three hunks of cross-host / cross-port redirect tests for pre-existing http_executor behavior at HEAD; not Stored XSS work |
| `ai/test_watch_param_discovery.py` | x8 parser / UA / requeue / registrable-domain tests (pre-existing param discovery work) |
| `ai/test_xss_case_builder.py` | `test_x8_patch_body_record` (pre-existing case-builder work) |
| `crawl/watch_param_discovery.py` | Explicit curl UA flag, GET-only x8 discovery, `example_url` filter, wordlist export comment hardening (pre-existing crawler work) |
| `database/change_events.py` | `_log_persist_failure` structured warning logging (pre-existing dashboard work) |
| `database/db.py` | Mongo host config swap + multiple `record_change` call sites in `upsert_lives` / `upsert_http` (pre-existing dashboard work) |

The untracked directories `agent-reports/`, `tests/`, `wordlists/`
remain untracked. `git ls-files agent-reports` returns empty
(confirmed `agent-reports/` is not part of the repository's tracked
production convention). The repository's `AGENTS.md` describes
agent-reports as a working-folder for agent-generated reports, not a
production-commit location, so they are correctly left untracked.

## Mixed-Hunk Review

### `ai/test_browser_executor.py`

Three hunks in the original working-tree diff:

| Hunk | Range | Decision | Reason |
| ---- | ----- | -------- | ------ |
| 1 | `@@ -28,6 +28,7 @@` (import) | STAGED | Adds `from ai.verification.oracle import evaluate_e2_network`, required by the new oracle tests |
| 2 | `@@ -321,14 +322,17 @@` (`FakePage.emit_response`) | UNSTAGED | Test-helper refactor; `from_main_frame` is class-attribute-set by both old and new code; the new oracle tests do not consume `request.from_main_frame`; both forms work |
| 3 | `@@ -832,6 +836,176 @@` (`BrowserEvidenceExecutorOracleBoundaryTests`) | STAGED | New E2 oracle boundary tests — Stored XSS / Oracle |

Verified after staging:

```
$ git diff --cached -- ai/test_browser_executor.py | grep '^@@'
@@ -28,6 +28,7 @@ from ai.verification import browser_executor as browser_module
@@ -832,6 +833,176 @@ class BrowserEvidenceExecutorRuntimeChannelsTests(unittest.TestCase):

$ git diff -- ai/test_browser_executor.py | grep '^@@'
@@ -322,14 +322,17 @@ class FakePage:
```

Only Hunk 2 remains unstaged.

### `ai/test_http_executor.py`

Three hunks; all PRE-EXISTING UNRELATED:

| Hunk | Range | Decision | Reason |
| ---- | ----- | -------- | ------ |
| 1 | `@@ -623,6 +623,140 @@` | UNSTAGED | 5 new tests for cross-host / cross-port redirect rejection — pre-existing http_executor behavior already at HEAD |
| 2 | `@@ -643,13 +777,15 @@` | UNSTAGED | Tweak of pre-existing `test_cross_host_redirect_rejected` (`evil.example.test` → `evil.example.org`) |
| 3 | `@@ -791,7 +927,7 @@` | UNSTAGED | Same pattern in pre-existing binding test |

The whole file was kept unstaged (no Stored XSS / Oracle hunks).

## Cached Diff Stat

```
$ git diff --cached --stat
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

## Cached Diff Security Review

The staged diff contains:

- All Stored XSS production code changes (`verifier.py`,
  `http_executor.py`, `browser_executor.py`, `oracle.py`, schemas).
- The new oracle test suite (`test_xss_oracle.py`).
- The new Stored XSS round test suite (`test_xss_stored_round.py`).
- The rewritten Stored XSS tests in `test_xss_verification.py`.
- The `evaluate_e2_network` import + `OracleBoundaryTests` class in
  `test_browser_executor.py`.

The staged diff does NOT contain:

- Crawler changes (`crawl/`)
- Database changes (`database/`)
- AGENTS / README / docs changes
- Parameter-discovery changes (`crawl/watch_param_discovery.py`,
  `ai/test_watch_param_discovery.py`)
- Case-builder test additions (`ai/test_xss_case_builder.py`)
- HTTP executor cross-host / cross-port redirect tests
  (`ai/test_http_executor.py`)
- `FakePage` plumbing change in `ai/test_browser_executor.py`
- `agent-reports/` directory (not tracked by the repo)
- `tests/` directory (untracked, pre-existing)
- `wordlists/` directory (untracked, pre-existing)

All Stored XSS dependency chain files are staged:

- `ai/verification/oracle.py` (new) — STAGED.
- `ai/test_xss_stored_round.py` (new) — STAGED.
- `ai/verification/verifier.py` references to the above are STAGED.

No required import is missing from the index.

Security integrity verified against the Stored XSS final review:

- W1 — CSRF detection narrowed to explicit failure semantics.
  Verified at `verifier.py:124-133` and `verifier.py:1571-1575`.
- W2 — Stored READ final origin bound to `read_attempt.endpoint`.
  Verified at `verifier.py:1913-1922`.
- W3 — Stored READ discovery fallback enforces effective port.
  Verified at `verifier.py:1654-1671`.
- `_classify_stored` demoted to hardcoded `"POTENTIAL"`.
- `OraclePlanner`, `run_salt`, anti-harvest, round binding, clean
  READ, and origin checks all preserved.

## Diff Check

```
$ git diff --check
(empty — clean)

$ git diff --cached --check
(empty — clean)
```

Both diff-check passes are clean.

## Test Results

```
$ python3 -m unittest ai.test_xss_stored_round
Ran 62 tests in 7.161s
OK

$ python3 -m unittest ai.test_xss_verification
Ran 125 tests in 0.135s
OK

$ python3 -m unittest ai.test_xss_oracle
Ran 66 tests in 0.290s
OK

$ python3 -m unittest ai.test_http_executor
Ran 58 tests in 0.117s
OK

$ python3 -m unittest ai.test_browser_executor
Ran 57 tests in 18.732s
OK

$ python3 -m unittest ai.test_xss_pipeline
Ran 12 tests in 0.007s
OK
```

Total: **380 tests passed** across all 6 required suites.

## Compile Result

```
$ python3 -m compileall -q ai watch_xss_verify.py
(no output, success)
```

## Final Git Status

```
$ git status --short
 M AGENTS.md
 D README-watch-updated.md
M  ai/schemas/xss_finding.py
M  ai/schemas/xss_verification.py
MM ai/test_browser_executor.py
 M ai/test_http_executor.py
 M ai/test_watch_param_discovery.py
 M ai/test_xss_case_builder.py
M  ai/test_xss_oracle.py
A  ai/test_xss_stored_round.py
M  ai/test_xss_verification.py
M  ai/verification/browser_executor.py
M  ai/verification/http_executor.py
A  ai/verification/oracle.py
M  ai/verification/verifier.py
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

Symbol legend (per `git status --short`):

- ` M` = unstaged modification (working-tree only).
- `M ` = staged modification (index only).
- `MM` = both staged (partial) and unstaged (partial) modifications.
- `A ` = staged addition (new file in index).
- `D ` = staged deletion.
- `??` = untracked.

Stored XSS files staged (`A ` or `M `):

- `M  ai/schemas/xss_finding.py`
- `M  ai/schemas/xss_verification.py`
- `M  ai/test_xss_oracle.py`
- `A  ai/test_xss_stored_round.py`
- `M  ai/test_xss_verification.py`
- `M  ai/verification/browser_executor.py`
- `M  ai/verification/http_executor.py`
- `A  ai/verification/oracle.py`
- `M  ai/verification/verifier.py`
- `MM ai/test_browser_executor.py` (Stored XSS / Oracle boundary
  hunks staged; FakePage plumbing unstaged)

Pre-existing unrelated modifications, all unstaged and preserved:

- ` M AGENTS.md`
- ` D README-watch-updated.md`
- ` M ai/test_watch_param_discovery.py`
- ` M ai/test_xss_case_builder.py`
- ` M crawl/watch_param_discovery.py`
- ` M database/change_events.py`
- ` M database/db.py`
- ` M ai/test_http_executor.py` (entire file)

Untracked (no repository convention to commit):

- `?? agent-reports/`
- `?? tests/`
- `?? wordlists/`

## Final Verdict

**READY TO COMMIT**

The index contains only the Stored XSS implementation and its
required dependency chain. No pre-existing unrelated modifications
have been disturbed. `git diff --check` and `git diff --cached
--check` are both clean. All 380 tests across the six required
suites pass. `compileall` is clean. The single commit is ready
when the user provides the commit authorization.