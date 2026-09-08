# Phase P1 Implementation Report — Security Pipeline Hardening

Status: OFFLINE / LOCAL ONLY. No network, DNS, browser, JavaScript,
Nuclei execution, subprocess security execution, LLM, production
MongoDB, or live traffic used at any point. No Git commands were run
(see §11). B1/B2/B4/B5 remain BLOCKED. The frozen 5B→5J authority
chain is preserved unchanged; no architecture redesign, no new
capabilities, no production execution opened.

## 1. VERDICT

PASS. All five P1 targets are closed with minimal, offline,
test-gated changes:

- P1-1 (legacy World A executors): CLOSED — explicit
  non-production markers on all five legacy modules; full
  production-reachability audit proves no runnable path remains.
- P1-2 (task/subprocess surface): CLOSED — import-time registry
  validation plus runtime path-confinement guard; injection and
  shell-execution paths proven blocked.
- P1-3 (finding/alert boundary): CLOSED — only genuine 5J CONFIRMED
  findings reach the authoritative notification seam; legacy objects,
  POTENTIAL, and UNKNOWN proven rejected with zero publications;
  recon Telegram notifications preserved and proven separate.
- P1-4 (legacy XssFindings surface): CLOSED — schema marked
  legacy/non-authoritative; sole writer belongs to the disabled
  entrypoint; no authoritative reader/writer exists.
- P1-5 (legacy Nuclei artifacts): CLOSED — research-only boundary
  made explicit on all four surfaces; real `to_findings` output
  proven unable to enter 5J; no authoritative reader of legacy JSON.

## 2. P1-1 legacy executor status

Reachability audit (static import-surface over the whole repo):

- Production importers of `http_executor` / `browser_executor` /
  `composite_executor` / `verifier` / `xss_pipeline`: exactly one —
  `watch_xss_verify.py` (production entrypoint permanently disabled
  in 5K; re-verified still returning exit 2). No `backend/` module,
  no `api.py`, and no task-registry script (crawl/ns jobs import
  only recon persistence from `database.db`) references them.
- `ai/verification/__init__.py` re-exports and `xss_pipeline`
  internal wiring are reachable only from the disabled entrypoint
  and offline unit tests.

Hardening applied (narrow marker seam, no behavior change, classes
kept importable for offline tests):

- `LEGACY_NON_PRODUCTION = True` constant plus a NON-PRODUCTION
  module banner on all five modules. No environment variable or
  runtime flag exists that could re-enable legacy production
  execution (token scan for `ALLOW_LEGACY` / `LEGACY_ENABLE` /
  `ENABLE_LEGACY` across the legacy surface: absent).
- `xss_pipeline.py` docstring corrected: it no longer presents
  itself as the "production integration layer" without qualification;
  it is now headed as legacy/non-production with the 5K entrypoint
  disablement cited.

## 3. P1-2 task/subprocess status

Findings on the existing surface (unchanged behavior, verified):

- `POST /api/tasks/{task_id}/run` takes only a registry key; unknown
  ids 404 (`trigger_task`) / `ValueError` (`run_task`). Script path,
  interpreter, and arguments come exclusively from the static
  `TASKS_REGISTRY` dict — never from caller input.
- Spawn is `subprocess.Popen([VENV_PYTHON, script_path,
  *default_args], ...)` with no `shell` argument anywhere (AST
  proven: `shell` appears in no `Popen` call keywords).
- Registry today is crawl/DNS recon jobs only; no security executor
  is registrable (verified per entry).

Smallest safe changes (existing non-security behavior unchanged —
all six entries validate identically):

- `backend/tasks_registry.py`: `ALLOWED_SCRIPT_DIRS = ("crawl",
  "ns")`, forbidden shell/control characters, and `_validate_entry`
  / `_validate_registry()` executed at import (fail closed). A bad
  edit — escaping `PROJECT_ROOT`, non-allowlisted directory (e.g.
  `ai/verification`, repo root), non-`.py` file, non-list or
  metacharacter-carrying `default_args`, unsafe task id — raises at
  import before any job can run.
- `backend/task_runner.py`: `_assert_script_confined()` runtime
  guard in `run_task` immediately after the allowlist lookup and
  BEFORE any `isfile` check, `TaskRun` document, log file, or child
  process. Mirrors the import-time rules, so even a runtime-mutated
  registry cannot escape to `/tmp`, repo-root, or `ai/` scripts.
- `TaskSchedule` (Phase-2 model) confirmed write/read by nothing
  outside `backend/models.py`; left untouched. Any future scheduler
  must resolve through the same allowlist (noted for the activation
  review, not built here).

Proven blocked: path-traversal ids, shell-metacharacter ids,
unknown security-sounding ids (`watch_xss_verify`, `verify`,
`nuclei`, `xss`, `finding`, case variants), mutated-registry
absolute escapes, repo-root and `ai/` scripts, relative and
`..`-normalized paths, metacharacter arguments, non-list args,
and any dynamic registry-extension function (no `register` /
`add_task` / `load_registry` / `exec` / `eval` exists).

## 4. P1-3 notification boundary status

No code change required or made: the 5J seam was already
correctly shaped (`RecordingNotificationSink.publish` type-checks
`FindingAlert`; the materializer builds alerts solely from sealed
finding fields on fresh persist only; dedup/reject paths never
publish). Hardening is boundary tests plus confirmation that the
recon pattern is preserved but separate:

- POTENTIAL → refused, zero publications; UNKNOWN (incl.
  `model_copy`-smuggled) → refused, zero publications.
- Legacy `XSSFinding` (even with `payload_reference` attack text),
  legacy `NucleiFinding` (severity `critical`, `matched=True`,
  raw stdout), and raw dicts → refused, zero publications.
- Genuine 5J CONFIRMED → exactly one alert; every notification
  field proven derived from the sealed finding (`finding_id`,
  `program_name`, `severity`, `classification_hash ==
  compute_result_hash(result)`, `alert_id == alert_id_for(...)`).
- Dedup replay → no second publication. `sink.publish` with
  arbitrary caller objects (str, dict, `XSSFinding`) → `TypeError`.
- Recon notifications (`notify_title_change`,
  `notify_status_change`, `notify_new_http` in
  `database/notifications.py`, DB-write-triggered, recon strings
  only) preserved untouched; no 5J module references the recon
  surface (`send_message`/notify names/telegram absent from every
  `ai/finding/*.py`).

## 5. P1-4 XssFindings status

- Schema marked: `XssFindings` carries a LEGACY / NON-AUTHORITATIVE
  class docstring (5J never written/read here, no
  upgrade/downgrade path, no new writers, no finding-grade reads;
  historical data preserved; no Mongo migration introduced).
- Writer audit (repo-wide AST, tests excluded): the name
  `XssFindings` appears in exactly two non-test files —
  `database/db.py` (definition) and `watch_xss_verify.py`
  (`mongo_persist` / `mongo_already_verified`, both belonging to
  the permanently disabled entrypoint and now docstring-marked
  legacy). Zero production readers exist anywhere.
- 5J separation proven: `ai/finding/*.py` contains no
  `XssFindings` / `mongo_persist` name and no
  `mongoengine` / `pymongo` / `database` / `watch_xss_verify`
  import; a genuine CONFIRMED materialization touches only the
  injected memory seams; a legacy `XSSFinding` reaches no store
  (`list_ids == ()`).

## 6. P1-5 legacy Nuclei status

Historical artifacts preserved; authority boundary made explicit
(docstring-only changes, zero behavior change):

- `NucleiRunner` (RESEARCH ONLY), `to_findings`
  (NON-AUTHORITATIVE normalization), `NucleiPipeline` (RESEARCH
  ONLY), `save_findings` (history-only persistence),
  `NucleiFinding` schema (NON-AUTHORITATIVE research record).
- Real `to_findings` output (constructed offline with
  `WatchTargetSelection` + `COMPLETED`/matched run results,
  caller severity `critical`) → refused by 5J, authoritative
  store stays empty. Forged `NucleiFinding` with `critical`
  severity → refused; minted 5J severity proven verbatim from
  the 5I classification, never caller text.
- Legacy JSON: no `.py` reader of `ai_data/nuclei/findings`
  exists outside the sole writer (`nuclei_pipeline.py`) and the
  5J hard-block inventory prose (`legacy_block.py`); test files
  excluded from the scan. Live Nuclei execution untouched and
  never enabled.

## 7. Exact files modified

1. `ai/verification/http_executor.py` — legacy banner docstring +
   `LEGACY_NON_PRODUCTION = True`. No logic touched.
2. `ai/verification/browser_executor.py` — same.
3. `ai/verification/composite_executor.py` — docstring reheaded +
   marker (added to `__all__`). No logic touched.
4. `ai/verification/verifier.py` — legacy banner docstring +
   marker. Oracle predicates and all logic untouched.
5. `ai/verification/xss_pipeline.py` — docstring reheaded (no
   longer unqualified "production") + marker (added to `__all__`).
   No logic touched.
6. `backend/tasks_registry.py` — `ALLOWED_SCRIPT_DIRS`,
   `_FORBIDDEN_CHARS`, `_validate_entry` / `_validate_registry`
   (run at import). Registry entries unchanged.
7. `backend/task_runner.py` — `_assert_script_confined()` guard
   in `run_task` before any side effect; imports extended for
   `ALLOWED_SCRIPT_DIRS` / `PROJECT_ROOT`. Spawn semantics
   unchanged.
8. `database/db.py` — LEGACY / NON-AUTHORITATIVE docstring on
   `XssFindings` only. No field, index, or behavior change; no
   data touched; no migration.
9. `watch_xss_verify.py` — legacy notes on `mongo_persist` /
   `mongo_already_verified` docstrings only. Disabled entrypoint
   untouched.
10. `ai/researcher/nuclei_runner.py` — research-only docstrings on
    `NucleiRunner` / `to_findings`. No logic touched.
11. `ai/researcher/nuclei_pipeline.py` — research-only docstrings
    on `NucleiPipeline` / `save_findings`. No logic touched.
12. `ai/schemas/finding.py` — NON-AUTHORITATIVE docstring on
    `NucleiFinding`. No field change.
13. `ai/schemas/xss_finding.py` — non-authoritative note appended
    to the `XSSFinding` docstring. No field change.

Frozen 5B–5J semantics (authorization, resolver, scope, sealed
executors, evidence, classification, finding materialization)
were not modified in any file.

## 8. Exact files created

1. `ai/test_p1_security_hardening.py` — 30 focused offline tests
   (stdlib `unittest` + `unittest.mock` for call-gating proofs).
2. `agent-reports/p1-security-hardening-implementation.md` — this
   report.

One adjacent fix while testing: a P1 comment in
`backend/tasks_registry.py` mentioned the disabled legacy job by
its literal filename, tripping the frozen 5K assertion that no
`backend/` source references it; the comment was reworded (no
semantic change) and the 5K suite is green again.

## 9. Focused test count/results

`ai.test_p1_security_hardening`: 30 tests — OK.

- P1-1 `LegacyExecutorTests` (4): markers present on all five
  modules; no re-enable flag; no production/registry-script
  imports legacy executors; entrypoint still exit-2.
- P1-2 `TaskRegistryTests` (6): static allowlist intact (6/6
  entries validate); 15 attacker task ids rejected at lookup and
  at `run_task` (before any DB/file/process); 6 mutated-registry
  escapes blocked; 7 bad-entry shapes rejected by validation; no
  `shell=True`; no dynamic extension point; `TaskSchedule`
  unconsumed.
- P1-3 `NotificationBoundaryTests` (7): POTENTIAL/UNKNOWN/legacy
  rejected with zero publications; genuine CONFIRMED publishes
  exactly one fully sealed-derived alert; dedup never re-notifies;
  sink type-gates arbitrary objects; recon notifiers preserved and
  unreferenced by 5J.
- P1-4 `XssFindingsBoundaryTests` (5): schema marker (AST-only,
  see §12); writers limited to definition + disabled job; no
  authoritative usage; 5J writes only memory seams with no
  mongo/legacy imports; legacy finding reaches no store.
- P1-5 `NucleiBoundaryTests` (4): real `to_findings` output
  refused; caller severity never authoritative; all five
  surfaces marked; legacy JSON has no authoritative reader.
- Invariants `AuthorityInvariantTests` (4): exactly one
  `sealed-finding/v1`; no authoritative path imports any of 11
  banned legacy surfaces (AST import scan over `ai/finding`,
  `ai/execution`, `ai/evidence`,
  `ai/verification/deterministic`); finding-id determinism;
  `LIVE_TRAFFIC_ENABLED` / `LIVE_NUCLEI` / `LIVE_BROWSER` False.

## 10. Regression test count/results

All offline; no production app run; no live execution of any kind:

- `ai.test_p1_security_hardening` (new): 30 — OK.
- `ai.test_legacy_severance_5k` (5K): 21 — OK.
- `ai.test_deterministic_verifier` + `ai.test_finding_pipeline`
  (frozen 5I + 5J): 183 — OK.
- `ai.test_knowledge_store` + `ai.test_xss_researcher` +
  `ai.test_xss_llm_researcher` + `ai.test_openrouter` +
  `ai.test_watch_xss_verify`: 110 — OK.
- `ai.test_xss_stored_round` + `ai.test_xss_pipeline` +
  `ai.test_composite_executor`: 88 — OK.
- `ai.test_http_executor` + `ai.test_xss_verification` +
  `ai.test_nuclei_ready` + `ai.test_xss_case_builder`: 230 — OK.
- `ai.test_browser_executor` + `ai.test_xss_oracle`: 123 — OK.
- Total: 785 tests, 0 failures.
- `compileall` over `ai`, `backend`, `database`,
  `watch_xss_verify.py`, `api.py`: clean. Touched files verified
  free of newly introduced trailing whitespace (remaining
  whitespace-only lines in `database/db.py` and
  `ai/researcher/nuclei_pipeline.py` are pre-existing and were
  left untouched per minimal-change discipline).

## 11. Explicit statement — no Git commands

No Git commands were run during this phase — no status, diff,
log, add, commit, push, or any other Git invocation. (Per the
phase absolute rule, `git diff --check` was therefore intentionally
not run; whitespace hygiene was verified with a read-only Python
scan instead.)

## 12. Explicit statement — no live execution

No live execution occurred: no network/DNS traffic, no browser
automation, no Nuclei execution (only pure `to_findings`
normalization over hand-built dataclasses), no subprocess spawned
(`run_task` exercised solely on fail-closed paths that raise
before any `TaskRun` save, log file, or `Popen`), no LLM calls,
no production MongoDB access (the `XssFindings` marker check is
AST-from-source precisely to avoid constructing the module-level
lazy Mongo client; no query or write was issued anywhere), no
live traffic flags touched.

## 13. Remaining P2/P3 findings

Unchanged from the architecture review; none introduced here:

- P2-1: 5H triple omits top-level `record.program_name`
  (documented asymmetry; 5J checks internally).
- P2-2: `model_copy` skips validation (5J revalidates; future
  consumers must too — P1-3 tests re-prove the 5J side).
- P2-3: ~20 version pins with no central registry (process gap).
- P2-4: `XSSVerificationResult.findings` list still consumable
  in-process (contained: only the disabled job reads it).
- P2-5: Telegram/recon helpers remain call-site-unauthenticated
  library functions (finding alerts correctly use the 5J seam).
- P2-6: "INCONCLUSIVE" triple meaning across phases (all paths
  fail closed).
- P3-1: research JSON embeds noisy stdout (housekeeping).
- P3-2: non-registry `__main__` CLI surfaces in crawl/ns/enum
  (out of scope per subsystem rules; registry confinement now
  test-gated so they cannot be pulled under the dashboard).
- P3-3: World A redirect/DNS policy predates 5E discipline
  (moot while hard-blocked).
- New process note (not a code gap): a runtime-memory mutation
  of `TASKS_REGISTRY` with allowlisted-dir-conforming args is
  outside the threat model handled here — an attacker with
  server-memory write already owns the host; file-level change
  control (P1-2 registry review) is the correct layer.

## 14. B1/B2/B4/B5 status

B1 = BLOCKED. B2 = BLOCKED. B4 = BLOCKED. B5 = BLOCKED.

None closed, none touched, none ready to close. No part of this
phase required opening a live capability: nothing was stopped as
BLOCKED mid-task and no architecture weakening was performed to
make any test pass.
