# Stored XSS Final Review

## Verdict

**READY TO PUSH**

## Commit Reviewed

- **Hash**: `2d6adabf12863eea644b7052dca289ca25f30710`
- **Short**: `2d6adab`
- **Message**: `Integrate stored XSS round-trip execution verification`
- **Parent**: `f74fd2f Integrate XSS execution oracle confirmation state machine`

Files in commit (10): `ai/schemas/xss_finding.py`, `ai/schemas/xss_verification.py`, `ai/verification/oracle.py` (new), `ai/verification/verifier.py`, `ai/verification/http_executor.py`, `ai/verification/browser_executor.py`, `ai/test_xss_oracle.py`, `ai/test_xss_stored_round.py` (new), `ai/test_xss_verification.py`, `ai/test_browser_executor.py`.

## Security Review

No security findings identified.

The following invariants are explicitly enforced in the committed
code and were verified by reading the actual files at HEAD (not just
diffs):

**Stored XSS state-machine integrity**:
- `XSSVerifier.verify()` partitions attempts into regular + stored by
  phase membership in `frozenset({STORED_SUBMIT_PHASE,
  STORED_READ_PHASE})` (`verifier.py:537`).
- Stored rounds execute under gated sequencing: SUBMIT first, READ
  only when SUBMIT is accepted AND a clean same-origin READ URL is
  discovered (`verifier.py:528-700`).
- `_classify()` Rule 2a (`verifier.py:1118-1127`): STORED_SUBMIT
  never confirms — at most POTENTIAL when the SUBMIT response itself
  reflects meaningfully.
- `_classify()` Rule 2b (`verifier.py:1132-1140`): STORED_READ is
  classified by `_classify_stored_oracle` ONLY — no other signal can
  promote it.
- `_classify()` Rule 2c (`verifier.py:1143-1155`): legacy phase
  demoted to at most POTENTIAL (`STORAGE_ATTRIBUTED`) regardless of
  token observations.
- `_classify_stored()` is hardcoded to return `"POTENTIAL"`
  (`verifier.py:1501-1524`).
- `_classify_stored_oracle()` returns CONFIRMED only after the
  full `_stored_oracle_proof` passes (`verifier.py:2053-2083`).

**Oracle binding**:
- All seven required fields are honored: `oracle_identity`,
  `round_id`, `attempt_id`, `correlation_token`, `oracle_seed`,
  `oracle_value`, `run_salt`.
- `oracle_identity` is shared between SUBMIT and READ (`verifier.py:2139-2145`).
- `round_id` is shared (`verifier.py:2134-2138`).
- `oracle_seed`/`oracle_value` are validated via `validate_oracle_pair`
  AND cross-checked identical between SUBMIT and READ
  (`verifier.py:2148-2159`).
- `oracle_seed(run_salt, oracle_identity, STORED_SUBMIT_PHASE) == seed`
  is re-derived locally — stale/cross-run evidence fails here
  (`verifier.py:2162-2176`).

**Anti-harvest**:
- `anti_harvest_violations(seed, value, PreExecutionInput)` accepts
  only `PreExecutionInput` (raises `TypeError` otherwise)
  (`oracle.py:590-597`). Post-execution oracle channels cannot be
  fed to it.
- Applied only to PRE-EXECUTION material: SUBMIT payload/bound-input/URLs
  AND READ URLs. Post-execution oracle channels are NEVER scanned
  (`verifier.py:2213-2236`).
- D is never placed on the wire. Planner enforces
  `seed in payload == 1` and `value not in payload`
  (`oracle.py:373-379`). `request_body_hash` and
  `response_body_hash` are SHA-256 of the wire bytes
  (`http_executor.py:209-214`, `http_executor.py:650-655`).

**Clean READ**:
- Browser executor navigates `stored_read` attempts with bare
  endpoint, no payload/token/oracle material bound
  (`browser_executor.py:928-942`).
- `_clean_read_ok` requires both `intended_request_url` and
  `actual_request_url` to be set, and to contain none of S, D, the
  correlation token, the `round_id`, or the payload
  (`verifier.py:1759-1789`).
- `_read_url_clean_or_none` re-checks at discovery
  (`verifier.py:1701-1716`).

**Origin / effective-port binding**:
- `_stored_oracle_proof` step 5 requires
  `final_origin == endpoint_origin == intended_origin`
  (`verifier.py:2187-2221`).
- `discover_stored_read_url` requires same-origin hint OR same
  registrable domain with matching effective port
  (`verifier.py:1654-1700`).

**SUBMIT/READ temporal ordering**:
- `_stored_round_ordered` requires `read_started > submit_finished`,
  with skew tolerance; unparseable/future timestamps fail closed
  (`verifier.py:1738-1763`).

**SUBMIT acceptance predicate** (`verifier.py:1553-1596`):
- WAF BLOCK / TRANSFORM → reject.
- 401/403/407 (auth) → fail closed.
- 402/405/406/409/410/423/451 → fail closed.
- 200-399 status + explicit-failure markers in body → fail closed.
  Marker list is explicit (no bare "csrf"); a normal
  `csrf_token` field name cannot trigger this.
- HTTP 200 alone is accepted with `success_status` signal — never
  storage proof.

**W1/W2/W3 hardening**:
- **W1**: `_SUBMIT_REJECT_BODY_MARKERS` (`verifier.py:124-138`)
  names explicit failure semantics; no bare `"csrf"`. A bare
  `csrf_token` form field or "CSRF protection" page text does NOT
  match. The match handler routes "csrf"/"token" markers to
  `csrf_required` signal (`verifier.py:1571-1575`).
- **W2**: `_stored_oracle_proof` step 5 binds
  `final_origin == endpoint_origin` (`verifier.py:2221`).
- **W3**: `discover_stored_read_url` registrable-domain fallback
  enforces `candidate_port == case_port`
  (`verifier.py:1665-1671`).

**Reflected/DOM regression assessment**:
- `_classify_oracle` (Reflected path) unchanged.
- `_classify_browser` (DOM/mutation) unchanged.
- HTTP reflection rule (Rule 5, `verifier.py:1186-1197`)
  unchanged — POTENTIAL only.
- `_classify_oracle` remains the only CONFIRMED source for
  Reflected/DOM attempts (`verifier.py:1157-1171`).

**False-CONFIRMED path analysis**:
- Two CONFIRMED-return sites in the file: `_classify_oracle` at
  `verifier.py:1311` (Reflected) and `_classify_stored_oracle` at
  `verifier.py:2060` (Stored).
- `_classify_stored_oracle` requires the full 9-step
  `_stored_oracle_proof`: evidence identity binding (both legs),
  round binding, oracle pair validity + cross-leg consistency, run
  freshness, same-origin READ, ordering, clean READ, anti-harvest
  clean, exact E1/E2/E3 predicates over executor-owned channels.
- No legacy token/phase-based path can confirm: `_classify_stored`
  is hardcoded to `"POTENTIAL"`.
- No new CONFIRMED path is introduced for non-Oracle evidence.
- E1/E2/E3 channels cannot be reused across rounds: each round has
  its own `round_id`, `oracle_seed`/`oracle_value` derived from the
  SUBMIT-candidate identity and `run_salt`. `_stored_oracle_proof`
  step 4 re-derives the seed from the current run's salt and rejects
  stale/cross-run material.

**Imports / circular dependencies**:
- `ai.verification.oracle` imports only stdlib
  (`hashlib`, `struct`, `dataclasses`, `datetime`, `urllib.parse`)
  — no project dependencies, no LLM/network calls.
- `ai.verification.verifier` imports `oracle` (one-way dependency).
- `ai.verification.http_executor` does NOT import `oracle` (no
  dependency from HTTP path).
- `ai.verification.browser_executor` imports only
  `ORACLE_PATH_PREFIX` from `oracle` (constant import).
- `ai.schemas.xss_verification` does NOT import `oracle` (Pydantic
  schemas are pure data).

**Serialization/schema compatibility**:
- All new `VerificationAttempt`/`VerificationEvidence` fields are
  `Optional` or defaulted — existing producers continue to work.
- `XSSFinding.round_id` and `XSSFinding.read_url` default to
  `None` (audit-only metadata; never proof inputs).
- Pydantic schema construction confirmed by direct instantiation.

**Test coverage**:
- `ai.test_xss_stored_round` (62 tests): round shape (5),
  positives (P1-P5), negatives (N1-N20), security (S1-S14),
  failures (F1-F8), auth/CSRF (5), production composition (2),
  localhost real-browser (1).
- `ai.test_xss_verification` (125 tests): rewritten Stored XSS
  tests to use the new oracle-round model, including
  `test_stored_xss_with_complete_round_trip_yields_confirmed`,
  `test_stored_xss_mismatched_phase_tokens_yield_potential`,
  `test_stored_attempt_identity_uses_final_phase`,
  `test_stored_complete_round_trip_yields_confirmed`.
- `ai.test_xss_oracle` (66 tests): W(S) deterministic vectors,
  Python/JS bit-identity, seed generation, validators, planner,
  E1/E2/E3 predicates, anti-harvest, benign-page spoof regression,
  run-salt/replay binding.
- `ai.test_browser_executor` (57 tests): includes
  `BrowserEvidenceExecutorOracleBoundaryTests` (oracle URL stays
  out of generic sink; non-oracle runtime requests preserved).
- `ai.test_http_executor` (58 tests): unchanged.
- `ai.test_xss_pipeline` (12 tests): unchanged.

## Verification

| Check | Status |
| ----- | ------ |
| Stored XSS state-machine integrity | OK |
| Oracle binding (7 fields) | OK |
| Anti-harvest (boundary-typed scanner) | OK |
| Clean READ (executor + verifier re-check) | OK |
| Origin / effective-port binding | OK |
| W1 (CSRF explicit-failure markers only) | OK |
| W2 (READ final origin == endpoint) | OK |
| W3 (port enforcement on registrable fallback) | OK |
| Reflected/DOM regression | NONE |
| Imports / circular dependencies | NONE |
| Schema serialization compatibility | OK |

## Tests

```
$ python3 -m unittest ai.test_xss_stored_round
Ran 62 tests in 6.543s
OK

$ python3 -m unittest ai.test_xss_verification
Ran 125 tests in 0.097s
OK

$ python3 -m unittest ai.test_xss_oracle
Ran 66 tests in 0.146s
OK

$ python3 -m unittest ai.test_http_executor
Ran 58 tests in 0.111s
OK

$ python3 -m unittest ai.test_browser_executor
Ran 57 tests in 18.161s
OK

$ python3 -m unittest ai.test_xss_pipeline
Ran 12 tests in 0.012s
OK

$ python3 -m compileall -q ai watch_xss_verify.py
(no output, success)
```

**Total**: 380 tests passed across 6 required suites. `compileall`
clean. No diff-check performed (this is a review of an already-committed
commit, not a staging review).

## Git State

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

**Confirmation**: no files were modified by this review. The working
tree is identical to its state at the end of the staging review —
all 9 unstaged tracked modifications and 9 untracked items are
pre-existing unrelated work that was preserved by the staging step.

`git status --short` matches the post-commit state from
`agent-reports/stored-xss-commit.md` exactly.