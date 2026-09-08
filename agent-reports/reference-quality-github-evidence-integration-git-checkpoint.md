# Reference Quality Gate → GitHub Evidence Retention Integration — Git Checkpoint

Git-only stage. No production code, tests, schemas, telemetry, or
artifacts modified. No LLM/network/Mongo/Nuclei/research-pipeline runs.
No push.

## 1. Pre-checkpoint status

- `git status --short`: 231 lines total (captured to
  `/tmp/opencode/integ_cp_status.txt`).
- 30 tracked files with unrelated pre-existing modifications
  (`git diff --stat`: 30 files changed, 1749 insertions(+),
  862 deletions(-)).
- `git diff --cached --stat`: empty — nothing staged.
- 201 untracked entries (support files, new modules, tests,
  agent-reports, data dirs).

## 2. HEAD before

`f58ffe8e4cb58cbcacea5985c31411f4437d9cc3`
`feat(ai): retain direct GitHub technical evidence`

Matches the expected previous checkpoint exactly. The integration stage
reported NO CODE CHANGE REQUIRED, so HEAD was expected to be unchanged.

## 3. Feature files verification

The five committed feature files are byte-identical to HEAD:

- `ai/collectors/reference_ranker.py` — clean
- `ai/researcher/research_context.py` — clean
- `ai/collectors/discovery_fetch.py` — clean
- `ai/researcher/cve_batch.py` — clean
- `ai/test_reference_ranker_technical_fallback.py` — clean

Evidence: `git diff -- <5 files>` → empty output (exit 0);
`git diff --cached -- <5 files>` → empty output (exit 0);
`git status --short -- <5 files>` → no output.

HEAD contents re-confirmed (`git show --name-only --format= HEAD`):
exactly the 5 files above — no schemas, no telemetry
(grep for `schema|telemetry` in HEAD file list → NONE).

Support files outside the checkpoint:

- `ai/researcher/reference_quality.py` — status `??` (untracked),
  absent from `git ls-files`, `git show HEAD:<path>` → NOT-IN-HEAD.
- `ai/research_cli.py` — status `??` (untracked), absent from
  `git ls-files`. (Same state as before the integration stage.)

Both remain outside the previous checkpoint. Left untouched.

## 4. Unrelated files excluded

### 4a. Previous committed feature files (in HEAD, not to be recommitted)

The 5 files in Section 3. Already committed in `f58ffe8`; no diff, so
nothing feature-scoped exists to commit.

### 4b. Unrelated pre-existing tracked modifications (30 — EXCLUDED)

`git diff --name-only` (all remain uncommitted):

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

### 4c. Unrelated/pre-existing untracked files (201 — EXCLUDED)

Including `ai/researcher/reference_quality.py`, `ai/research_cli.py`,
new `ai/*` modules (audit, authorizer, evidence, execution, finding,
knowledge, limits, persistence, resolver, scope, schemas, tests),
`tests/`, `wordlists/`, `utils.zip`, `Watch_README_completed.md`, ~70
`agent-reports/*` files (this report included), and
`ai_data/research/*` validation artifacts.

## 5. Whether a new commit was necessary

NO. The integration stage reported NO CODE CHANGE REQUIRED and this
checkpoint verified zero feature-scoped diff (Section 3). Creating a
commit now would either be an empty commit or would sweep in the 30
unrelated tracked modifications — both explicitly forbidden. HEAD was
left unchanged per the stage instructions.

## 6. HEAD after

`f58ffe8e4cb58cbcacea5985c31411f4437d9cc3`
`feat(ai): retain direct GitHub technical evidence`

Identical to HEAD before. Verified via `git log -1 --format='%H %s'`
after all checks.

## 7. Checkpoint identity

No new commit created. The existing checkpoint stands:

- Commit hash: `f58ffe8e4cb58cbcacea5985c31411f4437d9cc3`
- Commit message: `feat(ai): retain direct GitHub technical evidence`
- Contents: exactly the 5 feature files (Section 3), 1907 insertions(+),
  additive only, no schemas/telemetry.
- This is the EXISTING checkpoint from the previous Git stage, not a
  new commit.

## 8. Push confirmation

PUSH: NOT DONE. No `git push` executed. No git writes of any kind
performed (no add, no commit, no stash left behind, no branch changes).
