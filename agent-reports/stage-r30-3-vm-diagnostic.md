# R30.3 VM Diagnostic

## Status
NEEDS_FIX — test-only fix required (make the absolute-score assertion
hermetic to local runtime data). No production-code fix needed: R30.3 is
exonerated, Money Score formulas are intact, and the pipeline is
deterministic (`before == after` passes).

## Test Result
- Command:
  `python -m unittest tests.test_asset_cve_matching tests.test_observed_inventory tests.test_version_component_association -q`
- Result: Ran 181 tests, FAILED (1 failure).
- Failing test:
  `tests.test_asset_cve_matching.TestAdditiveIntegration.test_money_and_priorities_unchanged`
  (`tests/test_asset_cve_matching.py:642`).
- Expected: `[53, 53]` (action `money_score` for the two leads).
- Actual: `[50, 50]`.
- The determinism assertion in the same test (`before == after` economics)
  passes; only the absolute-value assertion fails.

## Root Cause
Exact arithmetic on the VM (reproduced by direct computation, no guessing):

- `compute_value` (unchanged formula): V=59 from P=80, R=20, SEV=75, EX=85
  with weights 0.30/0.35/0.20/0.15.
- Confidence C=51, effort E=52 (both verified identical with and without local
  R23 artifacts — they are not the differentiator).
- Risk K=85 = DUP 45 + FP 40, where:
  - DUP = 20 (public PoC) + 10 (Nuclei candidate) + **10 (`_report_exists`) +
    5 (`_prior_result_exists`)**. The bold +15 fires only because VM-local R23
    agent artifacts exist: `ai_data/research/agent/r22-*.r23-1.json` plus
    `.md` reports (read via `storage.load_result(plan_id, "r23-1")`; returns
    None when absent). That directory is **git-ignored and untracked** — absent
    on a fresh machine.
  - FP = min(12+8+8+8+6, 40) = 40 — all four lead blockers present
    (`only generic technology match`, `affected plugin not observed`,
    `asset component not observed`, `asset version unknown`), derived from
    untracked local KB data (`ai_data/knowledge/`) + research payloads.
- Money: raw = 0.55·59 + 0.15·51 + 0.15·(100−52) + 0.15·(100−85) = 49.55 →
  half_up → 50; the K≥70 cap (≤55) does not bind. **50 confirmed.**
- 53 is a local-data-state fingerprint, not a code property:
  - Removing only the R23-artifact delta (DUP 45→30, K→70) yields **52**
    (computed), still not 53.
  - 53 additionally requires 3 blockers instead of 4 (no generic-technology
    blocker → FP=30, K=60 < 70 so no cap binds → raw 53.3 → 53) — i.e. the
    author's data state at test-writing time (no R23 run artifacts on disk
    plus a 3-blocker lead set).
- Therefore: **cause (2) VM data/environment difference**, with a (3) aspect —
  the test asserts absolute scores computed from mutable, untracked local
  runtime data, so the expectation cannot hold across machines.

## R30.3 Regression Assessment
**R30.3 did NOT cause the difference.** Evidence:
- R30.3 (`f4f90d8`) changed only `backend/asset_cve_matching.py` (observed
  versions now pass through `evaluate_version_association` before the
  untouched R30.1 version evaluator, plus additive `version_association_*`
  context keys), new R30.3 modules, and R30.3 tests. Money-path files were
  last changed in `26bf486` (pre-R30.3).
- The action-queue projection merge cannot carry money: `get_projection()`
  returns exactly 9 `asset_match_*`/`matched_*`/`*_blockers`/`asset_match_reason`
  keys (verified — no `money_score` key), and action money flows
  `opportunity → economic → compute_value`, which never reads asset matching.
- Neither input delta behind 50-vs-53 (R23 artifact presence, lead blocker
  set) is written, read, or influenced by R30.3 code.

## Money Score Integrity
**R25 Money Score code/formula unchanged.** Weights
(`MONEY_W_VALUE=0.55`, `CONFIDENCE=0.15`, `EFFORT_EFF=0.15`, `RISK_AVOID=0.15`),
component constants (`EX_*`, `DUP_*`, `FP_*`, caps), `compute_value`,
`compute_confidence`, `compute_effort`, `compute_risk`, `assess_economic_value`
caps, and `half_up` rounding are all identical to pre-R30.3 (verified via
`git log` and direct source inspection). R25/R26/R29 behavior untouched
(hunt priorities still `VERIFY_FIRST`, rule versions `r29-1`/`r30-1` intact).

## Real Inventory API
- Correct API: `ai.knowledge.observed_inventory.build_observed_inventory(program: str, **kwargs)` —
  `program` is required positional; remaining record categories
  (`http_records`, `url_records`, `endpoint_records`, `subdomain_records`,
  `product_records`, `component_records`, `plugin_records`, `version_records`)
  inject as kwargs (pure function, no I/O).
- Production wrapper: `backend.observed_inventory.get_inventory("<program>")`
  (single program, fail-soft None when unknown) or
  `build_inventory(program="<program>")`. Program selection: any name from
  `list_programs()` (Mongo-derived program list); Mongo reads are find-only
  via `_fetch_documents`. Cache is process-local memory only.
- Real fields feeding version associations: persisted `version_associations`
  records (`version`, `technology_family`, `component`, `source`,
  `evidence_type`) plus flat `versions` lists from inventory and research
  metadata — explicit owners only, never inferred (R30.3 rule).

## Real-Data Test Plan
Exact read-only inspection for ONE real program (no writes, no persistence,
no subprocess/network beyond the Mongo read; run from `/opt/watch`):
`./venv/bin/python3 -c "from backend.observed_inventory import get_inventory; import json; print(json.dumps(get_inventory('dell'), indent=1)[:2000])"`
Expected: deterministic inventory projection for `dell` (or any name in
`list_programs()`), including `version_associations`; exit 0; zero
modifications (verify with `git status --short` afterwards).

## Files Inspected
- `tests/test_asset_cve_matching.py` (failing test + fixtures, esp. lines 1–45, 626–656)
- `ai/knowledge/economics.py` (weights, `compute_value`, `compute_confidence`, `compute_effort`, `compute_risk`, `assess_economic_value`, DUP/FP constants)
- `backend/research_economics.py` (`_project_one`, `_intel_for`, `_payload_for`, `_r23_for`, `_r24_for`, `_report_exists`/`_prior_result_exists` semantics)
- `backend/research_action_queue.py` (`_action_for_opportunity` projection merge — verified money-safe)
- `ai/knowledge/opportunity.py` (money passthrough `economic → opportunity → action`)
- `backend/research_action_queue.py` + `backend/hunt_queue.py` (additive-only asset context)
- `backend/asset_cve_matching.py` + R30.3 diff (`git show HEAD -- backend/asset_cve_matching.py`)
- `ai/knowledge/observed_inventory.py` (`build_observed_inventory`, `collect_program_inventory` — zero write ops verified)
- `backend/observed_inventory.py` (`get_inventory`/`build_inventory` read-only wrappers)
- `git status` / `git diff` / `git log` / `git ls-files ai_data/` (provenance of local-only data)

## Changes
- source changes: NONE
- test changes: NONE
- database changes: NONE
- service changes: NONE
- (Investigation used read-only Python evaluation and `git show`/`grep` only.)

## Safety
- no target interaction
- no network research
- no LLM
- no Nuclei
- no browser
- no finding/alert
- no 5B–5J execution
- (No services restarted, Crawl/X8 untouched, Mongo unmodified.)

## Agent / Model
- Model: opencode/muse-spark-1.3-contributor-free
- Stage: R30.3 VM Diagnostic
- Role: Diagnostic / Integration Verification
