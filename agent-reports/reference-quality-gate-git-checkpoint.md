# Reference Quality Gate — Final Git Checkpoint

Git-only stage. No production code, tests, schemas, telemetry,
artifacts, or reports modified by this stage. No LLM, network, Mongo,
Nuclei, or research pipeline runs. No push.

Final security review result (pre-checkpoint):
`GO WITH OBSERVATION / NO SECURITY BYPASS FOUND / CODE CHANGE REQUIRED: NO`

## 1. HEAD before

```
f58ffe8e4cb58cbcacea5985c31411f4437d9cc3 feat(ai): retain direct GitHub technical evidence
```

Verified with `git log -1 --format='%H %s'` before staging.

## 2. Pre-commit git status

`git status --short` showed the working tree with many known unrelated
modifications and untracked entries (schemas, XSS verification, backend,
database, utils, crawl, nuclei artifacts, agent reports, wordlists,
utils.zip, READMEs, and many untracked `ai/*` modules unrelated to this
feature). Nothing was staged (`git diff --cached --stat` was empty).

## 3. Candidate files considered

| Candidate | Status at pre-commit |
|---|---|
| `ai/researcher/reference_quality.py` | Untracked (the Gate implementation) |
| `ai/researcher/reference_cache.py` | Untracked (hard dependency of the gate) |
| `ai/research_cli.py` | Untracked (single-CVE gate wiring) |
| `ai/test_reference_quality_gate.py` | Untracked |
| `ai/test_reference_quality_decision_boundary.py` | Untracked |
| `ai/test_batch_reference_quality_parity.py` | Untracked |
| `ai/test_single_cve_quality_parity.py` | Untracked |
| `ai/test_reference_cache.py` | Untracked |
| `ai/test_reference_url_canonicalization.py` | Untracked |
| `ai/researcher/cve_batch.py` | Tracked at HEAD (committed in `f58ffe8e`) |
| `ai/researcher/research_context.py` | Tracked at HEAD (committed in `f58ffe8e`) |
| `ai/collectors/reference_ranker.py` | Tracked at HEAD (committed in `f58ffe8e`) |
| `ai/collectors/discovery_fetch.py` | Tracked at HEAD (committed in `f58ffe8e`) |

## 4. Include/exclude decision for every candidate

| Candidate file | Decision | Reason |
|---|---|---|
| `ai/researcher/reference_quality.py` | INCLUDE | The actual Reference Quality Gate implementation (primary feature file). |
| `ai/researcher/reference_cache.py` | INCLUDE | Hard code dependency: `reference_quality.py` imports `canonicalize_reference_url` from it; gate cannot import without it. User-approved. |
| `ai/research_cli.py` | INCLUDE | Single-CVE gate wiring (`gate_reference_contexts` block, lines 193-220); the final security review identified it as the second support file of this checkpoint. |
| `ai/test_reference_quality_gate.py` | INCLUDE | Direct tests of the gate (`gate_reference_contexts`); belongs to this feature. User-approved. |
| `ai/test_reference_quality_decision_boundary.py` | INCLUDE | Proves the gate is FILTER-ONLY and non-authoritative; belongs to this feature. User-approved. |
| `ai/test_batch_reference_quality_parity.py` | INCLUDE | Verifies the batch path exposes the per-CVE `reference_quality` gate outcome; belongs to this feature. User-approved. |
| `ai/test_single_cve_quality_parity.py` | INCLUDE | Verifies the single-CVE path applies the same gate; belongs to this feature. User-approved. |
| `ai/test_reference_cache.py` | EXCLUDE | Tests the separate per-batch reference-cache feature (reference-context-reuse stage), not the quality gate. |
| `ai/test_reference_url_canonicalization.py` | EXCLUDE | Tests the separate URL-canonicalization feature stage, not the quality gate. |
| `ai/researcher/cve_batch.py` | EXCLUDE | Already committed in `f58ffe8e`; zero worktree diff. |
| `ai/researcher/research_context.py` | EXCLUDE | Already committed in `f58ffe8e`; zero worktree diff. |
| `ai/collectors/reference_ranker.py` | EXCLUDE | Already committed in `f58ffe8e`; zero worktree diff. |
| `ai/collectors/discovery_fetch.py` | EXCLUDE | Already committed in `f58ffe8e`; zero worktree diff. |

All other working-tree changes (schemas, telemetry, verification/XSS,
backend, database, utils, crawl, nuclei artifacts, agent reports,
wordlists, utils.zip, READMEs, unrelated new `ai/*` modules and tests)
were EXCLUDED.

## 5. Exact files committed

```
ai/research_cli.py
ai/researcher/reference_cache.py
ai/researcher/reference_quality.py
ai/test_batch_reference_quality_parity.py
ai/test_reference_quality_decision_boundary.py
ai/test_reference_quality_gate.py
ai/test_single_cve_quality_parity.py
```

## 6. Staged diff/stat

```
 ai/research_cli.py                             | 543 ++++++++++++++++++
 ai/researcher/reference_cache.py               | 205 +++++++
 ai/researcher/reference_quality.py             | 170 ++++++
 ai/test_batch_reference_quality_parity.py      | 701 +++++++++++++++++++++++
 ai/test_reference_quality_decision_boundary.py | 639 +++++++++++++++++++++
 ai/test_reference_quality_gate.py              | 755 +++++++++++++++++++++++++
 ai/test_single_cve_quality_parity.py           | 561 ++++++++++++++++++
 7 files changed, 3574 insertions(+)
```

Verified `git diff --cached --name-only` contained ONLY these 7 files
before committing.

## 7. Commit hash

```
01beeebb8c6f325b4dff0e416c12d243457dcc0a
```

## 8. Commit message

```
feat(ai): add reference quality gate
```

Exactly one new commit. No amend, no squash, no empty commit.

## 9. HEAD after

```
01beeebb8c6f325b4dff0e416c12d243457dcc0a feat(ai): add reference quality gate
```

Parent remains the previous checkpoint
`f58ffe8e4cb58cbcacea5985c31411f4437d9cc3` (intact).

## 10. Remaining unrelated changes

All pre-existing unrelated working-tree modifications and untracked
entries remain uncommitted, including:

- Modified: `AGENTS.md`, `README-watch-updated.md` (deleted),
  `ai/config.py`, `ai/correlator/version.py`,
  `ai/researcher/{batch,batch_v3,nuclei_pipeline,researcher,retry_v3}.py`,
  `ai/schemas/{finding,research,xss_finding}.py`,
  `ai/test_{browser_executor,http_executor,watch_param_discovery,xss_case_builder}.py`,
  `ai/verification/*`, `ai_data/nuclei/*`,
  `backend/{task_runner,tasks_registry}.py`, `crawl/watch_param_discovery.py`,
  `database/{change_events,db}.py`, `utils/common.py`, `watch_xss_verify.py`
- Untracked: all `agent-reports/*`, `ai/audit/`, `ai/authorizer/`,
  `ai/evidence/`, `ai/execution/*`, `ai/finding/`, `ai/limits/`,
  `ai/persistence/*`, `ai/resolver/`, `ai/scope/`, many untracked
  `ai/researcher/*` and `ai/schemas/*` modules, untracked test files,
  `wordlists/`, `utils.zip`, `tests/*`, `Watch_README_completed.md*`

## 11. Confirmation: no excluded subsystems included

- `ai/schemas/*` — NOT included
- `ai_data/nuclei/*` — NOT included
- `ai/verification/*` and XSS files — NOT included
- `watch_param_discovery`, backend, database, utils changes — NOT included
- agent reports, wordlists, `utils.zip`, README changes — NOT included
- unrelated new AI modules/tests/artifacts/temp files — NOT included

## 12. Confirmation: no push performed

No `git push` and no `git fetch`/remote operation was executed. The
commit exists only on the local `main` branch.

## Verification summary

- All staged files compiled cleanly (`py_compile`), no test execution
  performed (Git-only stage).
- Post-commit `git show --stat --oneline HEAD` and
  `git show --name-only --format= HEAD` confirm exactly the 7 feature
  files.
- Post-commit `git status --short` confirms unrelated changes remain
  uncommitted; `git diff --cached` is empty.
- Test status carried over from the final security review:
  Focused 174/174 PASS; Full AI regression 2860 tests, 2853 pass,
  7 pre-existing/unrelated failures/errors (left unmodified).

VERDICT: CHECKPOINT CREATED
COMMIT: 01beeebb8c6f325b4dff0e416c12d243457dcc0a
MESSAGE: feat(ai): add reference quality gate
FILES: ai/research_cli.py, ai/researcher/reference_cache.py,
ai/researcher/reference_quality.py, ai/test_batch_reference_quality_parity.py,
ai/test_reference_quality_decision_boundary.py, ai/test_reference_quality_gate.py,
ai/test_single_cve_quality_parity.py
UNRELATED CHANGES: LEFT UNCOMMITTED
PUSH: NOT DONE