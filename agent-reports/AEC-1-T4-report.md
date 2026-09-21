# AEC-1 T4 — Authorization Request Compiler (S8)

## Files created

- `aec/case_compiler.py` (275 lines): deterministic compiler — selected
  pilot case → `AuthorizationRequestDraft` + human approval sheet.
- `tests/test_aec_case_compiler.py` (26 tests).
- `agent-reports/AEC-1-T4-report.md` (this file).

## Files modified

- `tests/test_aec_no_network.py`: added `tests.test_aec_case_compiler` to
  `SUITES_UNDER_DENIAL` (new suite now runs under socket denial).

## What the compiler does

`compile_authorization_request(source)` accepts a `CaseRef` or a selected
`SelectionDecision` and returns a frozen `CompileOutcome`: either a frozen
`AuthorizationRequestDraft` (case_id, host, endpoint, parameter, method,
category, closed-vocabulary `purpose_code`, sorted `purpose_detail`,
evidence-gap snapshot, `BudgetReference(policy, requested_cost=1, …)`,
compiler version) or a closed-vocabulary refusal (`INVALID_INPUT`,
`NOT_SELECTED`, `INVALID_CASE_ID`, `MISSING_HOST`, `MISSING_ENDPOINT`,
`MISSING_EVIDENCE_GAP`, `GAP_COMPLETE`, `UNSUPPORTED_METHOD` — GET/HEAD
only). `serialize_request()` yields stable bytes (`sort_keys`); 
`render_approval_sheet()` yields human paperwork headed `STATUS:
DRAFT/REFUSED` and footed `DRAFT ONLY — NOT AN AUTHORIZATION. NO CONTACT
HAS OCCURRED.`

## Security guarantees

- Stdlib + `aec.models` only. No `ai.*` import anywhere in the module
  (the plan's edge table permits the frozen schema; the S1 import guard
  forbids all `ai` imports in `aec/`, and the guard wins — the draft is
  paperwork, not the frozen pydantic type, so it can never be mistaken
  for authority). Method allowlist pinned to the frozen schema's
  `AllowedMethod` by a test that imports the schema (tests may; `aec/`
  may not).
- No sockets, HTTP, DNS, subprocess; no filesystem writes (AST-proven);
  never mutates inputs; frozen outputs; no verdict vocabulary in code or
  sheets (AST-proven); `live_deps.py` / `observation_lane.py` still absent.

## Non-goals

No authorization issuance, no `ai/authorizer` contact, no
`execution_authorization.py` modification, no verification-chain contact,
no live capability, no budget mutation (the reference names the policy;
spending is T3's ledger and T9's gate).

## RED → GREEN

RED: `Ran 26 tests — FAILED (errors=25)` with
`ModuleNotFoundError: No module named 'aec.case_compiler'`.
GREEN after implementation except two test-side corrections (rule right,
test wrong, as in T1): (1) budget-ref accessor — the test subscripted the
frozen `BudgetReference` dataclass instead of using attributes; (2)
complete-gap fixture — the test built `EvidenceGap.build(required, ())`,
which the model deliberately reads as all-missing (absence is never held
evidence); replaced with a directly constructed held gap. Final: 26/26.

## Verification

- New suite: 26/26.
- Full AEC set (selection, redaction, budget, compiler, import/constants/
  readonly/no-network guards): 205/205 green, `git diff --check` clean.
- `check-aec-readonly.sh`: READ-ONLY VERIFIED; frozen files byte-identical
  to production (`execution_authorization.py`, authorizer service,
  verifier, tasks registry).
- Production `/opt/watch` untouched (HEAD `d9435e5`, 27 dirty, `.env`
  mtime unchanged).

## Commit

One commit: `feat(aec): add authorization request compiler`. Do not push,
do not merge.

**READY TO PUSH.** Waiting for operator.
