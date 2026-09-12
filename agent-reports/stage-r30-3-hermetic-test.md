# R30.3 Hermetic Test Fix

## Status
PASS — the named test is deterministic and data-independent; the mandated
181-test trio is green. Two pre-existing absolute-`53` assertions in another
module remain failing (proven baseline, out of scope — see Test Results).

## Root Cause
`test_money_and_priorities_unchanged` asserted an absolute Money Score
`[53, 53]` computed from machine-local untracked runtime state:
- `ai_data/research/agent/r22-*.r23-1.json` + `.md` reports (git-ignored)
  feed `_report_exists`/`_prior_result_exists` → DUP +15 on this VM;
- lead blockers (incl. `only generic technology match`, +12 FP before the
  FP_CAP clamp) derive from untracked local KB state (`ai_data/knowledge/`).
On this VM that yields money 50 (raw 49.55 → 50); the author's 53-state
required absent R23 artifacts *and* a 3-blocker lead set. R30.3 is exonerated
(diagnostic `stage-r30-3-vm-diagnostic.md`): money formulas, weights, and the
R25/R26/R29 path are untouched, and the asset-projection merge provably
cannot carry `money_score`.

## Fix
Test-only rewrite of `test_money_and_priorities_unchanged` in
`tests/test_asset_cve_matching.py` (single method, +27/−4 lines). No absolute
score is asserted (neither 50 nor 53 is hard-coded); instead the test asserts
invariance around an explicitly executed R30.3 path:
1. Build economics + action money (baseline).
2. `asset_cve_matching.clear_cache()` then `build_matches(cve=CVE)` — forces
   genuine execution of the R30.3 version-association step (not a memoized
   projection); asserts `total > 0` and non-empty `items`.
3. Rebuild economics + action money; assert full-projection equality and
   per-lead money equality (Money unchanged by R30.3 by construction, on any
   machine, for any local data).
4. Range-check each score (int, 0–100).
Seam: the test now isolates at the R30 asset-matching boundary rather than
depending on `ai_data/` contents; determinism holds regardless of local
artifacts.

## Assertions Preserved
- Economics determinism (`before == after` full-projection equality).
- Money invariance across the R30.3 matching run (per-lead equality).
- Money well-formedness (int, 0–100).
- Hunt priorities `["VERIFY_FIRST", "VERIFY_FIRST"]`.
- `HUNT_RULE_VERSION == "r29-1"`.
- R30.3 path genuinely executed (`total > 0`, `items` non-empty) — R30.3
  assertions weakened in no way; the absolute `[53, 53]` expectation (a
  data fingerprint, not a code property) is replaced by a stronger
  machine-independent invariant.

## Test Results
- Mandated trio:
  `python -m unittest tests.test_asset_cve_matching tests.test_observed_inventory tests.test_version_component_association -q`
  → **Ran 181 tests, OK** (previously 1 failure).
- Broader suite (fast, relevant subsets): `ai.test_target_intelligence`
  40 OK; `ai.test_research_cli` 6 OK; `tests.test_opportunity_action_queue`
  non-API classes 65 tests → 2 failures, both `50 != 53` absolute assertions
  (`TestBackend.test_dell_blocked_verify_asset_match:824`,
  `test_no_history_does_not_change_money:883`) — **proven pre-existing via
  `git stash` baseline** (fail identically without this fix; same root
  cause; out of scope, flagged as follow-up).
- `git diff --check` → clean.
- API/UI `TestClient` modules (`test_hunt_queue`, `test_research_leads`,
  `test_research_api`, Api/Ui classes) exhibit ~60 s/test latency on this VM;
  proven pre-existing via stash baseline (`test_filters` 56.7 s without this
  fix). Full runs exceed practical timeouts; unrelated to this change (zero
  production diff).

## Production Code
- Money Score production code unchanged (formulas, weights, caps, rounding).
- R25/R26/R29 unchanged (rule versions and priorities intact).
- R30.1/R30.3 unchanged.
- Full diff: `tests/test_asset_cve_matching.py` only (plus pre-existing,
  unrelated `wordlists/*` pipeline modifications not made here).

## Changes
- Modified: `tests/test_asset_cve_matching.py`
  (`TestAdditiveIntegration.test_money_and_priorities_unchanged` only).
- Created: `agent-reports/stage-r30-3-hermetic-test.md` (this report).
- No other files created, staged, or committed. No push.

## Safety
- no Mongo writes (read-only `find` paths only; tests use existing data)
- no network
- no LLM
- no Nuclei
- no browser
- no target interaction
- no service changes (no restarts; Crawl/X8 untouched; systemd untouched)

## Agent / Model
- Model: opencode/muse-spark-1.3-contributor-free
- Stage: R30.3 Hermetic Test Fix
- Role: Test Reliability
