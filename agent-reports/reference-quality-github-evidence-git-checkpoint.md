# Reference Quality GitHub Evidence Retention — Git Checkpoint

## 1. Pre-commit status

Branch: `main`
HEAD before this stage: `f58ffe8e4cb58cbcacea5985c31411f4437d9cc3`
(`feat(ai): retain direct GitHub technical evidence`)

`git status --short` (pre-commit, 229 lines total) summary:

- The 5 feature files were CLEAN (no `M`/staged entries):
  - `ai/collectors/reference_ranker.py`
  - `ai/researcher/research_context.py`
  - `ai/collectors/discovery_fetch.py`
  - `ai/researcher/cve_batch.py`
  - `ai/test_reference_ranker_technical_fallback.py`
- 30 tracked files showed unrelated pre-existing modifications (`M`/`D`).
- `ai/researcher/reference_quality.py` was untracked (`??`), NOT modified.
- ~199 further untracked files/dirs (agent-reports, new ai/* modules,
  tests, `wordlists/`, `utils.zip`, etc.) remained.

Full pre-commit `git status --short` was captured to
`/tmp/opencode/pre_status.txt` (229 lines) during the stage.

`git diff --stat` (worktree, pre-commit): 30 files changed,
1749 insertions(+), 862 deletions(-). Captured to
`/tmp/opencode/pre_diffstat.txt` (31 lines).

`git diff --cached --stat` (staged): empty — nothing staged.

`git diff` scoped to the 5 feature files plus `reference_quality.py`:
empty (exit 0) for both unstaged and staged diffs.

`git diff --check`: reports pre-existing trailing-whitespace warnings in
UNRELATED working-tree files only (e.g. `ai/config.py`,
`ai/correlator/version.py`, `ai/researcher/batch.py`, `batch_v3.py`,
`researcher.py`, `retry_v3.py`, `ai/schemas/research.py`). No whitespace
errors in the committed feature files. Left untouched per Git-only scope.

## 2. Files included (committed feature)

HEAD commit `f58ffe8` contains EXACTLY these 5 files
(`git show --name-only --format= HEAD`):

1. `ai/collectors/discovery_fetch.py` (+9)
2. `ai/collectors/reference_ranker.py` (+186)
3. `ai/researcher/cve_batch.py` (+1174)
4. `ai/researcher/research_context.py` (+12)
5. `ai/test_reference_ranker_technical_fallback.py` (+526)

Total: 5 files changed, 1907 insertions(+), 0 deletions (additive).

No new commit was created during this stage because HEAD already is the
clean single-feature checkpoint: the 5 files above have zero worktree
diff and there was nothing feature-scoped left to stage. Running
`git commit` would either fail with "nothing to commit" or — if forced —
incorrectly sweep in unrelated changes. Per "Do NOT include unrelated
changes", the correct Git-only action was to leave HEAD untouched.

## 3. Files excluded as unrelated (remain uncommitted)

### 3a. Tracked modifications — EXCLUDED (30 files, per `git diff --name-only`)

- `AGENTS.md`
- `README-watch-updated.md` (deleted)
- `ai/config.py`
- `ai/correlator/version.py`
- `ai/researcher/batch.py`
- `ai/researcher/batch_v3.py`
- `ai/researcher/nuclei_pipeline.py`
- `ai/researcher/researcher.py`
- `ai/researcher/retry_v3.py`
- `ai/schemas/finding.py`
- `ai/schemas/research.py`
- `ai/schemas/xss_finding.py`
- `ai/test_browser_executor.py`
- `ai/test_http_executor.py`
- `ai/test_watch_param_discovery.py`
- `ai/test_xss_case_builder.py`
- `ai/verification/browser_executor.py`
- `ai/verification/composite_executor.py`
- `ai/verification/http_executor.py`
- `ai/verification/verifier.py`
- `ai/verification/xss_pipeline.py`
- `ai_data/nuclei/findings/CVE-2026-1557.json`
- `ai_data/nuclei/generated/CVE-2026-1557.yaml`
- `backend/task_runner.py`
- `backend/tasks_registry.py`
- `crawl/watch_param_discovery.py`
- `database/change_events.py`
- `database/db.py`
- `utils/common.py`
- `watch_xss_verify.py`

Notably this includes all working-tree `ai/schemas/*` changes — none of
them are part of the feature commit.

### 3b. Untracked — EXCLUDED (remain `??`)

Includes but not limited to:

- `ai/researcher/reference_quality.py` (170 lines on disk, untracked —
  see Section 5)
- `Watch_README_completed.md`, `Watch_README_completed.md:Zone.Identifier`
- `utils.zip`, `wordlists/`, `tests/`
- New `ai/` modules: `ai/audit/`, `ai/authorizer/`, `ai/evidence/`,
  `ai/execution/*`, `ai/finding/`, `ai/knowledge/artifact_store.py`,
  `ai/knowledge/pattern_store.py`, `ai/limits/`, `ai/persistence/*`,
  `ai/research_cli.py`, `ai/researcher/artifact_retrieval.py`,
  `ai/researcher/artifact_validator.py`, `ai/researcher/degraded.py`,
  `ai/researcher/hypothesis_engine.py`,
  `ai/researcher/nuclei_artifact_validator.py`,
  `ai/researcher/pattern_projector.py`,
  `ai/researcher/provider_errors.py`, `ai/researcher/reference_cache.py`,
  `ai/researcher/retry_policy.py`, `ai/researcher/target_intelligence.py`,
  `ai/researcher/target_matcher.py`, `ai/researcher/test_plan_builder.py`,
- New `ai/schemas/*` files (artifact, evidence,
  execution_authorization, hypothesis, research_pattern,
  scope_evaluation, target_*, test_plan)
- New `ai/test_*` files (artifact, b1/b3, batch parity, CVE batch,
  verifier, executors, pattern/store, provider, reference, scope,
  stage1/stage2, target, etc.)
- `ai/verification/deterministic/`, `ai/resolver/`, `ai/scope/`
- ~70 `agent-reports/*` files (this report excluded from the commit as well)

## 4. Commit hash

`f58ffe8e4cb58cbcacea5985c31411f4437d9cc3`

Verified via `git rev-parse HEAD` and
`git log -1 --format='%H %s' HEAD` during this stage.
No new commit was created; HEAD was already the clean checkpoint
(see Section 2 for rationale).

## 5. Commit message

`feat(ai): retain direct GitHub technical evidence`

Verified via `git log -1 --format=%s HEAD`. Matches the suggested message
exactly.

`git show --stat --oneline HEAD`:

```text
f58ffe8 feat(ai): retain direct GitHub technical evidence
 ai/collectors/discovery_fetch.py               |    9 +
 ai/collectors/reference_ranker.py              |  186 ++++
 ai/researcher/cve_batch.py                     | 1174 ++++++++++++++++++++++++
 ai/researcher/research_context.py              |   12 +
 ai/test_reference_ranker_technical_fallback.py |  526 +++++++++++
 5 files changed, 1907 insertions(+)
```

`git show --name-only --format= HEAD`:

```text
ai/collectors/discovery_fetch.py
ai/collectors/reference_ranker.py
ai/researcher/cve_batch.py
ai/researcher/research_context.py
ai/test_reference_ranker_technical_fallback.py
```

## 6. Post-commit status

HEAD is unchanged: `f58ffe8e4cb58cbcacea5985c31411f4437d9cc3`.

- `git status --short -- <5 feature files>`: empty (clean).
- `git show --stat --oneline HEAD` and
  `git show --name-only --format= HEAD`: as quoted in Section 5.
- Full `git status --short` still reports the same 30 unrelated tracked
  modifications plus untracked files (count grows by 1 for this report
  file itself, which is intentionally untracked/uncommitted).
- No production code, tests, schemas, telemetry, or artifacts were
  modified during this stage. No pipeline/LLM/network/Mongo/Nuclei runs.

### reference_quality.py confirmation (required)

- `git ls-files -- ai/researcher/reference_quality.py`: empty (untracked).
- `git show HEAD:ai/researcher/reference_quality.py`: fatal —
  "exists on disk, but not in 'HEAD'".
- Worktree: `-rw-r--r-- ... 170 ai/researcher/reference_quality.py`.
- `git status --short` entry: `?? ai/researcher/reference_quality.py`.
- Conclusion: UNCHANGED / not part of the feature commit. Excluded.

### Schemas/telemetry confirmation (required)

- `git show --name-only --format= HEAD | grep -Ei
  'schema|telemetry|knowledge_store|xss'` → `NO-SCHEMA-TELEMETRY-MATCH`.
- The commit contains zero `ai/schemas/*` and zero telemetry files.
- All working-tree `ai/schemas/*` modifications
  (`finding.py`, `research.py`, `xss_finding.py`) remain uncommitted
  per Section 3a.

## 7. Push confirmation

PUSH: NOT DONE.

- No `git push` was executed in this stage.
- No upstream is configured for `main`
  (`git rev-list HEAD...@{u}` → "no upstream configured"), so no
  ahead/behind push state was altered.
- Remote `origin` (`https://github.com/pouyaGit/watch.git`) was only
  read via `git remote -v` for verification.
