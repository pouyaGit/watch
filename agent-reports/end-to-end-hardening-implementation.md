# Phase 5K Implementation Report — Legacy Severance + Finding Identity Hardening

Status: OFFLINE / LOCAL HARDENING. No network, DNS, browser, JavaScript,
Nuclei, subprocess-for-security-execution, LLM, MongoDB, or live traffic
used. No Git commands run (per Phase 5K absolute rules; `git diff --check`
intentionally skipped — whitespace verified with a read-only script
instead: zero trailing-whitespace lines in all touched files).
B1/B2/B4/B5 remain BLOCKED. No production finding persistence opened.

## 1. Verdict

PASS. All three P0 integration hazards are closed with minimal,
offline, test-gated changes. No security architecture redesign, no new
capabilities, no production execution opened.

- P0-1 (runnable legacy World A live finding pipeline): CLOSED.
- P0-2 (dual finding-minting API): CLOSED.
- P0-3 (duplicate/conflicting SealedFinding identity surface): CLOSED.

## 2. P0-1 remediation (legacy World A severance)

`watch_xss_verify.py` production entrypoint is permanently disabled:

- `main(argv)` now fails closed BEFORE any execution begins: it prints
  a clear disabled message to stderr (directing operators to the
  5B→5J pipeline) and returns exit code 2. It parses no arguments,
  constructs no pipeline, opens no MongoDB, builds no LLM provider,
  and touches no network/browser.
- `if __name__ == "__main__": sys.exit(main())` is retained and now
  exits 2 without executing anything.
- No bypass flag and no `ALLOW_LEGACY`-style environment variable were
  added (verified by test: the string `ALLOW_LEGACY` appears nowhere in
  the file). A runtime flag would leave the bypass alive.
- Importability preserved for offline unit tests only: `run_job` (with
  injected fakes), pure document mappers, and `build_production_pipeline`
  remain importable and are exercised by the existing
  `ai.test_watch_xss_verify` (110-test batch green) and
  `ai.test_xss_stored_round` suites. They are non-authoritative and have
  no production execution entrypoint.
- `LEGACY_PRODUCTION_DISABLED = True` marker plus module-docstring
  banner record the non-runnable status.
- Per the phase brief, legacy executor libraries
  (`ai/verification/http_executor.py`, `browser_executor.py`,
  `composite_executor.py`) were deliberately NOT modified: entrypoint
  severance alone removes the production reach, and the task registry
  contains no entry pointing at them (verified, §9 below).

## 3. P0-2 remediation (dual finding minting removed)

`ai/verification/deterministic/materialization.py::materialize_finding`
is HARD-BLOCKED:

- The function keeps a compatible signature
  `(classification, seam=None)` but ALWAYS raises the deterministic
  `MaterializationSeamDisabledError` — for CONFIRMED, POTENTIAL,
  UNKNOWN, stale, or rebound inputs alike. It can never return a
  finding and never returns `None`-as-control-flow.
- Final authority graph now holds: 5I = `ClassificationResult` only;
  5J (`ai.finding.materialize`, CONFIRMED-only) = finding
  materialization only. 5I classification semantics (gate order,
  rules, severity policy, `FINDING_ELIGIBLE_OUTCOMES` classifier
  ceiling) are untouched — only the conflicting materialization seam
  was retired.
- No production module imports the retired seam (AST-verified across
  `backend/`, `api.py`, and `ai/finding/`; the only importers are the
  5I package init itself and offline tests).
- The frozen 5I `MaterializationTests` block in
  `ai/test_deterministic_verifier.py` was updated to the blocked-seam
  contract (7 tests: CONFIRMED/POTENTIAL/UNKNOWN/stale/rebound all
  raise; error message deterministic across calls; seam can never mint).

## 4. P0-3 remediation (SealedFinding identity hardening)

Option C adopted (rename class AND give a distinct schema version —
smallest safe solution that makes confusion structurally impossible):

- 5J keeps the single authoritative `SealedFinding`
  (`ai/finding/sealed.py`, `FINDING_SCHEMA_VERSION = "sealed-finding/v1"`).
- The old 5I shape is renamed to `DeprecatedSeamFinding` with
  `MATERIALIZATION_SCHEMA_VERSION = "5i-materialized-finding/v1"`
  (a `Literal`-pinned default, so any version skew fails closed).
- The name `SealedFinding` no longer exists on
  `ai.verification.deterministic.materialization` or on the
  `ai.verification.deterministic` package: both expose a PEP 562
  `__getattr__` that raises `AttributeError` with a redirect message,
  so any stale production import fails loudly instead of silently
  binding the wrong shape.
- Cross-validation fails in both directions (regression-proven):
  a real minted 5J finding does not validate as `DeprecatedSeamFinding`
  (version literal + field-set mismatch), and a valid seam payload
  does not validate as 5J `SealedFinding`.
- Identity derivation untouched and deterministic: 5J
  `finding_id_for` + `canonical_finding_bytes` round-trip proven
  byte-identical across repeated materialization (second call is a
  deduplicated no-op).

## 5. Files modified

1. `watch_xss_verify.py` — module banner, `LEGACY_PRODUCTION_DISABLED`
   + `LEGACY_DISABLED_MESSAGE`, `main()` replaced with fail-closed stub,
   `__main__` guard now exits 2 via `main()`. Nothing else touched.
2. `ai/verification/deterministic/materialization.py` — rewritten as a
   retired seam: `DeprecatedSeamFinding` (`5i-materialized-finding/v1`),
   `MaterializationSeamDisabledError`, hard-blocked `materialize_finding`,
   `__getattr__` guard against the old `SealedFinding` name.
3. `ai/verification/deterministic/__init__.py` — exports updated
   (`DeprecatedSeamFinding`, `MaterializationSeamDisabledError`,
   `materialize_finding`; `SealedFinding` removed) + package-level
   `__getattr__` fail-closed guard.
4. `ai/test_deterministic_verifier.py` — `MaterializationTests`
   rewritten to the blocked-seam contract (7 tests); top import extended
   with `MaterializationSeamDisabledError`.

## 6. Files created

1. `ai/test_legacy_severance_5k.py` — 21 focused offline regression
   tests (stdlib `unittest` only): identity (7), retired-seam block (6),
   legacy severance (8).
2. `agent-reports/end-to-end-hardening-implementation.md` — this report.

No other files created. No unrelated files modified. Frozen 5B–5J
semantics (authorization, resolver, scope, executors, evidence,
classification) untouched.

## 7. Legacy entrypoint status

`watch_xss_verify.main` = permanently disabled (returns 2, stderr
message, zero side effects — proven with a bomb-patched
`build_production_pipeline`/`run_job` that is never reached).
`__main__` guard = fails closed. No re-enable flag exists.
`run_job` / builders remain importable for offline unit tests only
(non-authoritative, no scheduler reach: the task registry has no legacy
entry). Legacy executor modules left in place but unreachable from any
production path; legacy Nuclei untouched (no imports added, 5F isolation
intact — `ai.finding` AST-clean per `source_references_banned`).

## 8. Finding authority status

Conceptual authority graph after this phase (as required):

- 5I: classification only (`ClassificationResult`; retired seam raises).
- 5J: finding materialization only (`ai.finding.materialize`,
  CONFIRMED-only, in-memory seam).
- Legacy World A: non-authoritative / non-runnable.
- Legacy Nuclei (`to_findings` / `save_findings` / `NucleiFinding`):
  non-authoritative; no new 5K code references them.
- No other path can mint an authoritative finding: exactly one
  `sealed-finding/v1` (5J); 5J accepts only genuine 5I
  `ClassificationResult` (`XSSFinding` and `NucleiFinding` instances
  are refused with `AUTHORITY_NOT_CLASSIFICATION_RESULT`-family
  outcomes and reach no store).

## 9. Tests

New suite `ai.test_legacy_severance_5k` (21 tests, all passing):

1. only-one-`sealed-finding/v1` (constants, defaults, name removal,
   no 5I source assigns the version) — tests 1–4 of the brief.
2. cross-validation both directions with a really minted 5J finding —
   tests 2–3.
3. old API raises for CONFIRMED/POTENTIAL; POTENTIAL→5J refused and
   reaches no store (`list_ids == ()`); CONFIRMED→only-5J (old raises,
   5J persists) — tests 4–6.
4. entrypoint returns 2 with disabled message; bomb-patch proves no
   pipeline/runner construction; `main` source + `__main__` guard AST
   contain no execution tokens; no `ALLOW_LEGACY` — tests 7–8.
5. registry contains no verify/nuclei/xss/finding task; `backend/` +
   `api.py` never reference `watch_xss_verify` — test 9.
6. `ai.finding` AST-clean (`source_references_banned == ()` for every
   module) plus no reference to `materialize_finding` /
   `DeprecatedSeamFinding` — test 10.
7. `XSSFinding` / `NucleiFinding` refused by 5J `materialize` — tests
   11–12.
8. finding-id determinism + dedup + byte-identity — test 13.

## 10. Regression results

All offline, no live execution of any kind:

- `ai.test_legacy_severance_5k`: 21 tests — OK.
- `ai.test_deterministic_verifier` + `ai.test_finding_pipeline`
  (frozen 5I + 5J): 183 tests — OK.
- `ai.test_knowledge_store` + `ai.test_xss_researcher` +
  `ai.test_xss_llm_researcher` + `ai.test_openrouter` +
  `ai.test_watch_xss_verify`: 110 tests — OK.
- `ai.test_xss_stored_round` + `ai.test_xss_pipeline`: 74 tests — OK.
- Total: 388 tests green, 0 failures.
- `git diff --check` intentionally NOT run (Phase 5K absolute rules
  forbid Git commands); trailing-whitespace scan over all touched
  files: clean.

## 11. Remaining P1/P2/P3

Unchanged from the architecture review; none introduced or closed here:

- P1-1: World A executor modules still execute unconditionally IF
  called — contained by entrypoint severance + empty registry, but the
  code itself was deliberately left in place per minimal-change
  discipline. Future hardening could delete or gate them.
- P1-2: dashboard subprocess trigger + append-a-line registry remain
  a future injection surface (registry verified clean today).
- P1-3: alert-on-DB-write (Telegram recon) pattern untouched.
- P1-4: `XssFindings` schema/Mongo shape untouched (writer disabled
  at the entrypoint; no readers exist).
- P1-5: `ai_data/nuclei/findings/*.json` files untouched.
- P2-1…P2-6, P3-1…P3-3: as documented in
  `agent-reports/end-to-end-security-pipeline-architecture.md`; no 5K
  action taken (out of scope).

## 12. Remaining B1/B2/B4/B5 blockers

B1 = BLOCKED. B2 = BLOCKED. B4 = BLOCKED. B5 = BLOCKED.

None closed, none touched, none ready to close. Production Mongo
adapters, live dial policy, Nuclei corpus truth, and browser
containment reviews are all still required before any activation.

## 13. Live execution status

LIVE_BROWSER = False. LIVE_NUCLEI = False. LIVE_TRAFFIC_ENABLED = False.

No production Mongo. No live network. No live browser. No live Nuclei.
No production finding persistence (5J in-memory seam only). No LLM
calls. No subprocess execution. No Git operations performed.
