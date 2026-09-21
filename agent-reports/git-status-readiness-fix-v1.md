# Git Status Readiness Fix v1 (Epic 0.2.1)

## Bug description

`check_auth.py --json` reported `{"verdict": "READY", "method": "ssh"}`,
but `status.sh` rendered the Push capability as blocked (previously:
`push  blocked — run git/check_auth.py for reasons`). The status layer did
not reflect the checker result.

## Root cause

`status.sh` consumed the checker's **human prose** (`READY` / `method: ...`
lines matched with `grep '^READY'`) instead of its **JSON contract**, and
rendered its own invented display strings (`ready via ...`). Any divergence
between prose formatting and the parse — present or future — silently flips
the display to blocked. The status layer was effectively re-interpreting the
verdict instead of rendering it.

## Fix (corrective patch only, in `status.sh`)

- The Push capability section now calls `check_auth.py --json` and decodes
  the document with a real JSON parser. No auth logic duplicated: the checker
  remains the sole owner of the verdict.
- Display follows the contract exactly:
  `push READY` + `method <name>`, or `push BLOCKED` + `reason <CODE> …`.
- Fail-closed parsing: unparsable output, an empty document, a missing
  method on READY, or a missing checker all render `BLOCKED` (reasons
  `CHECKER_OUTPUT_UNPARSEABLE` / `CHECKER_UNAVAILABLE`), never READY.
- Test seam: `GIT_AUTH_CHECKER` overrides the checker path (default: the
  sibling `check_auth.py`), mirroring the existing `PROMOTION_*` override
  pattern. No auth method added, no promotion flow touched, no secrets
  printable (the section renders only verdict/method/reason codes).

## Tests (`tests/test_git_status.py`, written first — 3 failed pre-fix)

1. READY checker output displays READY (+ `method ssh`)
2. BLOCKED checker output displays BLOCKED (+ `reason SSH_UNAVAILABLE`)
3. Garbage checker output fails closed (BLOCKED, never READY)
4. No token/password/secret words in status output (remote URL stays redacted)
5. Existing display contract preserved (sections, redaction, exit 0)

Results: new suite 5/5; `test_git_auth` 9/9, `test_promotion_operator` 15/15,
delivery 82/82, AEC 179/179 — all green. `git diff --check` clean.

## Commit

One commit: `fix(workflow): align git status readiness reporting` — do not
push, do not merge.

**READY TO PUSH.** Waiting for operator.
