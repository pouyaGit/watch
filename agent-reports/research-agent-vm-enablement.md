# Research Agent VM Enablement (Google VM, research-only dry-run)

## 1. Objective

Make the Watch AI research agent operational on this Google VM for
research-only, non-authoritative work: CVE collection, reference
research, correlation with Watch targets, candidate Nuclei template
generation/validation, dry-run Nuclei preparation, local persistence,
and agent reports. Explicitly NOT activating live exploitation or live
vulnerability verification.

## 2. Environment

- Host: Google Cloud VM, checkout at `/opt/watch`, branch `main`.
- `origin/main` at `091b277` ("ai: finalize pre-activation validation").
- Python 3.12, project venv at `venv/` (Python 3.12).
- MongoDB reachable at `127.0.0.1:27017`, server version 8.3.8
  (authenticated ping verified; `http` collection holds 4509 assets).
- `nuclei` binary is NOT installed (validation degrades gracefully).
- `pytest` is NOT installed; tests were run with stdlib `unittest`,
  consistent with `AGENTS.md`.

## 3. Repository state observed

- The working tree had the entire `ai/` research track deleted
  (~107 files, ~48k lines) plus `ai_data/` samples, while carrying
  ~32 intentional VPS-migration modifications (`database/db.py` now
  points at local MongoDB, dashboard changes in `app.py`,
  crawl/ns/dns adjustments, etc.).
- All pre-existing `M` modifications were preserved untouched; the
  only deletions reversed were `ai/` and `ai_data/`, which this task
  directly requires. Unrelated deletions (`AGENTS.md`,
  `README-watch-updated.md`, stage 5/6/6A reports,
  `tests/test_ui_redesign.py`, `watch_xss_verify.py`) were left alone.
- Audit findings (read-only, via `git show origin/main:<path>`):
  - A. Invocation: `ai/researcher/batch.py`, `batch_v3.py`,
    `retry_v3.py` (`main()` + `__main__` guard); `NucleiPipeline`
    for template prep. No formal CLI existed.
  - B. No dedicated CLI/entry point existed.
  - C. Required env: `OPENROUTER_API_KEY`, optional
    `OPENROUTER_MODEL` / `OPENROUTER_MAX_TOKENS`, `AVALAI_*`,
    optional `NVD_API_KEY`; Mongo URI was hardcoded to the old VPS.
  - D/E. OpenRouter is primary (`minimax/minimax-m3:free` default);
    AvalAI secondary. Both already implemented; OpenRouter reused.
  - F. Only the LLM provider needs an API key; NVD works
    keyless (rate-limited); Mongo needs credentials.
  - G/H. Research -> `ai_data/research/`; Nuclei ->
    `ai_data/nuclei/{generated,results,findings}/`.
  - I. No scripts/services/timers invoke AI work (`run-pipeline.sh`,
    `setup-core-pipeline.sh`, `setup-weekly-jobs.sh` are recon-only).
  - J. Missing deps: `openai`, `packaging` (both installed into venv).
  - K. Local MongoDB is sufficient (ping OK, 4509 http assets).
  - L. Dry-run safe: `NucleiRunner.dry_run` default; live runs need
    `READY_FOR_SCAN`; `prepare_for_watch` never live-scans.
  - Defects found: `.env` last line concatenated
    `OPENROUTER_MODEL` and `OPENROUTER_MAX_TOKENS` (missing newline);
    batch entry points hardcoded the old VPS Mongo URI + password;
    `origin/main:.gitignore` had a malformed concatenated ignore line.

## 4. Existing architecture used

Reused verbatim, no duplication, no new framework:

- `ai/llm/openrouter.py` (`OpenRouterProvider`) as the LLM client.
- `ai/collectors/{cve,discovery,discovery_fetch,reference,http}`.
- `ai/correlator/{candidates,assessment,index}` + Nuclei
  decision/generator/validator + `watch_targets`/`scope_policy`.
- `ai/researcher/{researcher,research_context,nuclei_pipeline,nuclei_runner}`.
- `ai/knowledge/store.py` (`KnowledgeStore`, hash-canonical).
- `ai/schemas/*` for validation; `ai_data/` layout for outputs.
- Deterministic authority chain (`ai/execution`, `ai/verification`)
  restored byte-identical and NOT modified; live gates untouched.

## 5. Files changed

Restored verbatim from `HEAD` (deletions reversed, zero edits):

- `ai/` (full research track, 107 files) and `ai_data/` samples.

Edited (minimal, isolated):

- `ai/config.py` — added `WATCH_MONGO_URI` (env-only, no secret
  default) + `require_mongo_uri()` fail-closed helper.
- `ai/researcher/batch.py`, `batch_v3.py`, `retry_v3.py` — replaced
  hardcoded VPS Mongo URI with `require_mongo_uri()`.
- `requirements.txt` — appended `openai`, `packaging` (were missing
  despite being imported by the research track).
- `.env.example` — documented AI/Mongo vars with empty placeholders.
- `.gitignore` — ignore locally generated `ai_data/` outputs.

Created (new, isolated):

- `ai/research_cli.py` — research-only CLI (`check` / `research` /
  `batch`), dry-run only, never touches live gates or 5J findings.
- `ai/test_research_cli.py` — offline focused tests.

Fixed outside git (ignored file, no diff impact):

- `.env` — repaired missing newline between `OPENROUTER_MODEL` and
  `OPENROUTER_MAX_TOKENS`; added VM-local `WATCH_MONGO_URI`.

## 6. Why each change was necessary

- Restore `ai/`+`ai_data/`: without them no research agent exists.
- `WATCH_MONGO_URI` + batch edits: old VPS URI is unreachable here
  and embeds a password; env-based config is required for the VM and
  removes secrets from code.
- `ai/research_cli.py`: there was no runnable entry point; the CLI
  reuses batch_v3 logic with `check` (offline), single-CVE, and batch
  modes, all research-only.
- `openai`/`packaging`: hard imports of the research track; nothing
  ran without them.
- `.env` newline fix: the model resolved to a garbage string and the
  token budget var was unset.
- `.env.example`/`.gitignore`: safe-config support without secrets;
  keeps generated outputs out of git status.

## 7. Configuration / environment variables required

Set in `.env` (never commit; never log values):

- `AI_PROVIDER=openrouter`
- `OPENROUTER_API_KEY=<key>` (required for LLM research)
- `OPENROUTER_MODEL=minimax/minimax-m3:free` (default preserved)
- `OPENROUTER_MAX_TOKENS=8192`
- `WATCH_MONGO_URI=mongodb://<user>:<password>@127.0.0.1:27017/watch?authSource=admin`
- `NVD_API_KEY=` (optional; keyless works with stricter rate limits)

## 8. Commands used

- `git checkout HEAD -- ai ai_data` (targeted restore only)
- `venv/bin/pip install openai packaging`
- `venv/bin/python -m ai.research_cli check`
- `venv/bin/python -m unittest ai.test_research_cli -v`
- `venv/bin/python -m unittest ai.test_openrouter ai.test_knowledge_store ai.test_llm`
- `venv/bin/python -m unittest ai.test_ingestion_schema ai.test_knowledge_ingestion ai.test_ingestion_grounding`
- `git diff --check`, `git status --porcelain=v1`
- No heavy pipeline, crawl, DNS brute force, live Nuclei/HTTP, or
  browser execution was run.

## 9. Tests executed and exact results

- `ai.test_research_cli`: 6 tests, OK (fail-closed URI, no-VPS-secret,
  mocked check PASS, missing-key FAIL, dry-run surface).
- `ai.test_openrouter` + `ai.test_knowledge_store` + `ai.test_llm`:
  41 tests, OK.
- `ai.test_ingestion_schema` + `ai.test_knowledge_ingestion` +
  `ai.test_ingestion_grounding`: 117 tests, OK.
- `ai.research_cli check` on the VM: RUNNABLE (key set, model correct,
  Mongo reachable with 4509 http assets, dirs writable, imports OK).
- `ai.test_correlation` / `test_shortlist` / `test_nuclei_ready` /
  `test_candidate_scan`: 0 unittest tests (manual scripts, not run).
- Note: `git diff --check` reports CR-at-EOL warnings because the
  restored `ai/*.py` files use CRLF (pre-existing repo style, also
  present in `HEAD`); new lines match surrounding style. One
  pre-existing warning in `ns/watch_dns_precheck.py` is untouched.

## 10. Safety gates verified

- No `LIVE_* = True` assignment anywhere under `ai/` (source scan).
- `NucleiPipeline.prepare_for_watch` uses `runner.dry_run` only;
  `NucleiRunner.run` refuses unless target is `READY_FOR_SCAN` with a
  program; default status is dry-run/excluded.
- Deterministic chain (`ai/execution`, `ai/verification`) restored
  byte-identical; no live-gate symbol modified.
- CLI writes only to `ai_data/research` and `ai_data/nuclei/*` with
  `authoritative=False`; no 5J materialization, no CONFIRMED claims.
- `require_mongo_uri()` fails closed when unconfigured.
- CLI `check` output contains no secrets (lengths/values never printed).

## 11. Remaining limitations

- `nuclei` binary absent: template semantic validation works, but
  `nuclei -validate` reports "executable not found" (expected,
  non-fatal, dry-run preserved).
- `pytest` absent: regression runs use stdlib `unittest` only.
- `ai.execution.{http_executor,nuclei_executor,browser_executor,b3_boundary,ledger}`
  and `ai.persistence.driver` do not exist in `origin/main`, so the
  B3/pilot/stage-6 gate test modules referencing them cannot import
  (pre-existing upstream condition, unrelated to this task).
- `ai/test_researcher.py` calls a stale `research(title=...)`
  signature (manual script, not a unit test; left untouched).
- Live NVD/LLM paths (`research`/`batch` modes) were NOT exercised
  end-to-end here (would incur network/LLM usage); only `check` and
  mocked/offline suites ran.
- Activation eligibility remains false; live gates remain closed.

## 12. Recommended next step

Run a single cheap `--skip-llm` correlation to prove the offline path
without spending LLM budget or hitting NVD hard:

    venv/bin/python -m ai.research_cli research --cve <CVE-ID> --skip-llm

then, when ready, one full single-CVE `research` run to validate the
OpenRouter call against `ai_data/research/<CVE-ID>.cli.json`. Keep
everything research-only; do not install/enable live execution.
