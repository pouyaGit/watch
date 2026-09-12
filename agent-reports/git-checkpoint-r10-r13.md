# Git Checkpoint — R10–R13

## Commit

- Hash: `5e3fe48`
- Message: `chore: checkpoint research intelligence R10-R13`
- Branch: `main`
- Stats: **76 files changed, 16508 insertions(+), 335 deletions(-)**

## Pre-commit inspection

- `git status --short`: 20 tracked modifications + 1 deletion
  (`Watch_README_completed.md:Zone.Identifier`) + 56 untracked paths.
- `git diff --stat` (tracked): 21 files, +1740/−340.
- `git diff --check` (tracked working tree): clean.
- `git diff --cached --check` (staged): 3 pre-existing whitespace notes in
  newly added files (blank line at EOF in `stage-r10` report and
  `ai/test_body_extraction.py`; one trailing-whitespace line in `stage-r6`
  report). Left untouched — no source modifications allowed in this task.

## Verification (before commit)

- **No secrets**: `.env` is gitignored and untracked; no `.env`/credential
  paths in status. Value scan of the full diff found only (a) the synthetic
  canary `sk-or-v1-secret-key` in `ai/test_openrouter.py` (used in
  `assertNotIn` no-key-leak assertions — R10 work, not a real key) and
  (b) `mongodb://…YourStrongPassword123…` lines in `database/db.py`, which is
  pre-existing in `HEAD` and was deliberately **excluded** (see below).
  Sentinel values (`sk-or-SENTINELKEY9XQ2`) in `ai/test_xss_llm_assistant.py`
  and `sk-or-` banned-substring guards in `tests/test_research_ui.py` are
  synthetic no-leak test fixtures.
- **No DNS/crawl modifications**: `git diff --name-only` and untracked list
  contain nothing under `ns/`, `crawl/`, and no `dnsx`/DNS scripts.
- **R13 report exists**: `agent-reports/stage-r13-reference-body-extraction.md`
  (125 lines).
- **R12/R13 tests per reports**:
  - R13: `Ran 318 tests … OK` (body extraction + reference + ingestion +
    intelligence + knowledge store + XSS researcher/LLM + openrouter).
  - R12: focused suites green (`ai/test_intelligence.py` 32 tests,
    `ai/test_research_ingestion.py` +4; regression 896 + 1269 − overlaps all
    OK) except documented pre-existing, R12-independent failures: one
    `ai.test_watch_param_discovery` x8 command-shape failure (protected crawl
    scope, fails identically without R12 code) and 2 stale-data assertions in
    `tests/test_research_ui.py` (verified failing without R12 code).
- **No push**: only `commit` was run; nothing was pushed.

## Files included (76)

- Tracked modifications (20): `ai/collectors/discovery_fetch.py`,
  `ai/collectors/reference.py`, `ai/knowledge/store.py`,
  `ai/llm/openrouter.py`, `ai/research_cli.py`, `ai/schemas/knowledge.py`,
  `ai/schemas/reference.py`, `ai/schemas/xss.py`, `ai/test_openrouter.py`,
  `ai/test_reference_ranker_technical_fallback.py`, `api.py`,
  `backend/routers/pages.py`, `backend/routers/programs.py`,
  `backend/routers/runs.py`, `requirements.txt`,
  `web/static/css/custom.css`, `web/templates/base.html`,
  `web/templates/dashboard.html`, `web/templates/macros.html`.
- Tracked deletion (1): `Watch_README_completed.md:Zone.Identifier`
  (Windows ADS sidecar junk).
- New source (10): `ai/collectors/body_extraction.py`,
  `ai/knowledge/ingestion.py`, `ai/knowledge/intelligence.py`,
  `ai/reports/__init__.py`, `ai/reports/renderer.py`,
  `ai/researcher/xss_agent.py`, `ai/researcher/xss_llm_assistant.py`,
  `backend/research_data.py`, `backend/routers/research.py`,
  `backend/routers/research_pages.py` + `ai/researcher/xss_seed/` (3 JSON).
- New tests (10): `ai/test_body_extraction.py`, `ai/test_intelligence.py`,
  `ai/test_reports_renderer.py`, `ai/test_research_ingestion.py`,
  `ai/test_research_kb_xss_e2e.py`, `ai/test_xss_agent.py`,
  `ai/test_xss_llm_assistant.py`, `tests/test_research_api.py`,
  `tests/test_research_ui.py`, `tests/test_xss_llm_dashboard.py`.
- New templates (9): `error.html`, `kb.html`, `kb_detail.html`,
  `report_detail.html`, `reports.html`, `research.html`,
  `research_detail.html`, `xss.html`, `xss_detail.html`.
- New reports (26): `stage-r10` + `stage-r11` + `stage-r12` + `stage-r13`,
  `stage-r2`–`stage-r9.5` (11 files), `stage-d1`–`stage-d5` (5 files),
  2× `cve-batch-run-2026-09-09` logs. The R2–R9/D1–D5 reports are the
  uncommitted base the R10–R13 work builds on (file-level inseparable from
  the checkpoint; tracked-category docs, no secrets).

## Files intentionally excluded

- `M database/db.py` — environment-specific Mongo host swap
  (127.0.0.1 → 35.202.201.30) containing example-credential Mongo URIs;
  unrelated to R10–R13, left uncommitted.
- `ai_data/knowledge/` (24 docs + index, ~356K) and `ai_data/reports/`
  (6 md, ~48K) — reproducible runtime-generated data; never tracked in
  history (only `ai_data/nuclei/*` for CVE-2026-1557 is tracked).
  Regenerable via `kb ingest` / report rendering.
- `agent-reports/stage-d5-screenshots/` (12 PNGs, ~2.3M) — binary
  D-stage screenshots, unrelated generated files.
- `.env` — gitignored, never staged.

## Post-commit state

- `git status --short` shows only the excluded items above
  (`M database/db.py` + 3 untracked dirs).
- `git log -1 --oneline`: `5e3fe48 chore: checkpoint research intelligence R10-R13`.
- `git show --stat --oneline HEAD`: 76 files, +16508/−335 (full stat in git).
- This report itself (`agent-reports/git-checkpoint-r10-r13.md`) is written
  after the commit and intentionally left uncommitted.

## Agent / Model

- Model: Muse Spark (muse-spark)
- Stage: Git Checkpoint R10-R13
- Role: Repository Checkpoint
