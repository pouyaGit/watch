# AEC-1 Task T3 — Report: Deterministic Budget Ledger (S6)

**Status: READY TO PUSH** — one worktree commit, nothing pushed, nothing merged,
production untouched by this task.

**Phase framing:** NOT_CONFIRMED. This task adds an offline accounting module. It
confirms nothing, contacts nothing, authorizes nothing, assigns no severity, and
creates no finding.

---

## 1. Files created / changed

| File | Lines | Change |
|---|---:|---|
| `aec/budget_ledger.py` | ~470 | New: policy, usage, decision, event models + `BudgetLedger` |
| `tests/test_aec_budget_ledger.py` | ~465 | New: written first, 36 tests |
| `tests/test_aec_no_network.py` | +1 line | Added the new suite to `SUITES_UNDER_DENIAL` |
| `agent-reports/AEC-1-T3-report.md` | this file | Task report |

Models live in `budget_ledger.py` rather than extending `aec/models.py`: the
ledger is a self-contained accounting unit with its own closed vocabularies, and
`models.py` stays focused on selection shapes. No existing module was modified.

## 2. RED observed

Before implementation, the new suite failed to import:

- `ModuleNotFoundError: No module named 'aec.budget_ledger'` (1 error, 0 tests ran)

After implementation: first run **35/36**, then 36/36 after correcting one
over-strict test (below).

## 3. GREEN results

- `tests.test_aec_budget_ledger` — **36 pass**
- Full AEC set (`selection`, `redaction`, `budget_ledger`, `readonly_guard`,
  `import_guard`, `constants`, `no_network`) — **179 pass, 0 fail**
- `git diff --check` — clean
- `scripts/check-aec-readonly.sh` — `READ-ONLY VERIFIED`, exit 0
- Delivery `diff_guard.py` over `main...HEAD` after commit — verdict recorded in §6

One test needed correction, not the module: `test_no_verdict_vocabulary_in_the_module`
flagged the module docstring's own disclaimer sentence ("there is no finding,
severity or confirmed vocabulary anywhere here"). Same treatment as T2's import
guard — the sentence names the vocabularies to forbid them, so the test strips
that sentence before asserting.

## 4. Security guarantees (tested, not asserted)

- **Fail-closed, fixed check order:** `INVALID_COST` → `UNKNOWN_CASE` →
  `UNKNOWN_HOST` → `CASE_HOST_MISMATCH` → `TOTAL_BUDGET_EXCEEDED` →
  `CASE_BUDGET_EXCEEDED` → `HOST_BUDGET_EXCEEDED` → `CASE_COUNT_EXCEEDED` →
  `HOST_COUNT_EXCEEDED` → `BUDGET_AVAILABLE`. Every refusal carries exactly one
  code from the closed 10-code vocabulary; `allowed` is true exactly for
  `BUDGET_AVAILABLE` (enforced in `BudgetDecision.__post_init__`).
- **Deterministic:** no clock, no randomness, no dict-ordering dependence
  (snapshots sorted, event ids sequential `evt-000001…`, default stamps are a
  logical clock `t-000001…`). Two ledgers run through the same script produce
  identical decisions, events, usage and audit text (tested).
- **No network / process / filesystem capability:** AST-tested — imports limited
  to `__future__`, `dataclasses`, `typing`, `aec`; no `open`/`write`/`mkdir`,
  no `eval`/`exec`/`__import__`, no clock calls. The suite also runs green
  inside the socket-denial harness (`test_aec_no_network`).
- **Never mutates inputs:** the `known` map is copied at construction
  (caller-side mutation afterwards cannot move the ledger — tested);
  `propose()` is pure; snapshots are detached values. All models are frozen
  dataclasses.
- **Counters never decrease; denials consume nothing:** every `commit()` appends
  exactly one immutable event (`COMMIT` or `DENIED`); only allowances add to
  totals (tested, including a denied request interleaved in the sequence).
- **No verdicts:** no confirmed/vulnerable/exploitable/severity/finding
  vocabulary in code or reason codes (tested).
- **Invalid policy refused at construction** (`ValueError` on non-positive or
  boolean limits); `default_policy()` mirrors the approved `PILOT_BUDGET` /
  `MAX_HOSTS` constants (tested against `aec`).

## 5. Non-goals (explicitly not done)

- No authorization logic — the ledger never grants, and a `BUDGET_AVAILABLE`
  decision is not permission to act.
- No STOP-file or crash-reload-to-disk behaviour — persistence is
  `snapshot()`/`restore()` over plain data only; the caller decides where bytes
  live. No filesystem access exists in this module by design.
- No `models.py` changes; no authority-chain, executor, gate, registry,
  systemd or `.env` contact of any kind.

## 6. Delivery-gate dogfood

- `diff_guard.py` over `main...HEAD`: **PASS**, 4 files, 0 findings.
- `check.sh` full gate: PASS except `PRODUCTION_UNTOUCHED: BLOCK` — expected:
  production moved from `eb46601` to `8d24403` during this session (operator
  merge, not this task). Dirty count unchanged at 27, `.env` mtime unchanged,
  frozen files byte-identical worktree vs production. Read, not "fixed".

## 7. Verification (reproduce)

```sh
cd /opt/watch/.worktrees/watch-agent
/opt/watch/venv/bin/python3 -m unittest tests.test_aec_budget_ledger
/opt/watch/venv/bin/python3 -m unittest tests.test_aec_selection tests.test_aec_redaction tests.test_aec_readonly_guard tests.test_aec_import_guard tests.test_aec_constants tests.test_aec_no_network
git diff --check
bash scripts/check-aec-readonly.sh
```

## 8. Commit

One commit: `feat(aec): add deterministic budget ledger`. Do NOT push. Do NOT
merge. Next task per the plan is **T4 (S7, authorization gate)**; stopping here.
