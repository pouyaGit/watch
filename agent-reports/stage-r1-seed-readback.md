# Stage R1 "Seed + Read Back" — Implementation Report

Date: 2026-09-09 (UTC). Environment: Google VM repo at `/opt/watch`.
Basis: `agent-reports/knowledge-base-reality-check.md`.
No Git commit (per task).

## Implementation summary

Three small, additive changes. No new architecture, no refactored
components, no new network behavior, no HTTP API/UI, no search
semantics beyond the existing `KnowledgeStore.retrieve()` exact-match
filters.

1. **Read-only KB CLI** (`ai/research_cli.py`): new `kb` command group
   with `list`, `show <knowledge_id>`, and `search` (repeatable
   `--technology`, `--xss-type`, `--context`, `--waf`, `--technique`,
   `--source-type`, `--evidence-quality`, `--tag` flags mapping 1:1
   onto `KnowledgeStore.retrieve()` kwargs; `--json` on `list`/`search`
   for full-document output). Wraps only `store.retrieve()` /
   `store.get_by_id()`; corruption/unknown-ID fail with `ERROR` on
   stderr and exit 1. No mutation or ingestion exposed.
2. **Reference archive persistence** (`ai/research_cli.py`):
   new `write_reference_archive(cve_id, reference_contexts,
   discovered_documents)` writes
   `ai_data/research/<CVE>.references.json` (atomic temp+rename,
   sorted keys, `archive_version: "references-1"`) with one record per
   `ReferenceContext` (`source_url`, `source_type`, `title`,
   `exact_record`, `context_chunks`, `content_hash` where the fetched
   material carries one, else `null` — never invented). Called from the
   existing `_research_single_cve` right after the gated
   `reference_contexts` are built, on both the LLM and `--skip-llm`
   paths. The existing research JSON schema is unchanged.
3. **XSS seed corpus** (`ai/knowledge/xss_seed.py`, new): three
   hand-curated, fixture-derived `KnowledgeDocument` payloads ingested
   via the existing `KnowledgeStore.ingest` (no LLM, no network, benign
   pattern labels only, non-routable `example.test` provenance).
   Runnable as `python -m ai.knowledge.xss_seed`; deterministic
   (`source_url` order, content-hash IDs) and idempotent
   (`created=False` on repeats, no duplication).
4. **Backfill** `ai_data/research/CVE-2026-1557.references.json`: the
   cli-1 run never persisted reference bodies and they cannot be rebuilt
   offline, so this file is an explicitly labeled
   (`"completeness": "url-list-backfill"` + `note`) URL-list backfill
   derived strictly from the existing `CVE-2026-1557.cli.json`
   `research.references` (6 URLs; `source_type` per the existing
   `ReferenceCollector.classify_source` rule; unrecoverable fields are
   `null`/`[]`). Full contexts will be captured by
   `write_reference_archive` on the next research run.

## Exact files changed

Modified (tracked):

- `ai/research_cli.py` (+295 lines, additive only):
  `import os`; usage docstring; `REFERENCE_ARCHIVE_VERSION` +
  `write_reference_archive()`; one call site in `_research_single_cve`;
  `KB_SEARCH_FIELDS`, `_kb_search_kwargs`, `_kb_store`,
  `run_kb_list`/`run_kb_show`/`run_kb_search`/`run_kb`, `kb`
  subparsers, `main` dispatch.

Created:

- `ai/knowledge/xss_seed.py` (new seed module + `__main__` entry).
- `ai/test_stage_r1.py` (new focused tests, 11 tests).
- `ai_data/knowledge/` (runtime data: `index.json` + 3
  `documents/<sha256>.json` from running the seed).
- `ai_data/research/CVE-2026-1557.references.json` (backfill, 6
  records; `ai_data/research/` is gitignored per `.gitignore:58`,
  same as the existing `.cli.json`).

Pre-existing workspace state (NOT mine, untouched): modified
`run-heavy-guarded.sh` (0-line diff, was already modified before this
task); untracked `ai/lab/*`, `ai/test_lab_*`, `crawl/output/*`,
`dns-bruteforce/*`, `phase-5k*`/`phase-sync*` agent-reports.

## Exact tests run / results

All offline (`unittest`; no NVD/LLM/reference network, no live runs):

| Suite | Tests | Result |
|---|---|---|
| `ai.test_stage_r1` (new: A–F) | 11 | OK |
| `ai.test_knowledge_store` | 15 | OK |
| `ai.test_xss_researcher` | 12 | OK |
| `ai.test_xss_llm_researcher` | 36 | OK |
| `ai.test_research_cli` | 6 | OK |
| `ai.test_knowledge_ingestion` | 36 | OK |
| `ai.test_openrouter` | 26 | OK |

New-test coverage: (A) `kb list` incl. `--json` + empty-store zero
case; (B) `kb show` full-document keys + unknown-ID exit 1;
(C) `kb search --xss-type reflected` → 2, `--xss-type dom` → 1,
no-filter → 3; (D) archive writer schema/content/hash-passthrough/
`null`-where-absent/no-`.tmp`-leftover + real CVE-2026-1557 archive
schema check; (E) double-seed idempotency (created True→False, same
IDs, exactly 3 docs); (F) `XSSResearcher` on seeded temp store returns
>0 docs with attributed payloads. CLI-level tests chdir into temp dirs
so real `ai_data/` is never touched by tests.

`git diff --check`: clean.

## KB records seeded and their IDs

`python -m ai.knowledge.xss_seed` (run twice; second run: all
`EXISTS`, still 3 records):

| knowledge_id | Title | xss_type / context |
|---|---|---|
| `kb-e9680d762348e261` | Seed: reflected XSS in a quoted HTML attribute (search parameter) | reflected / html_attribute |
| `kb-618f7421f5e69487` | Seed: reflected XSS in a script block (hash parameter) | reflected / script |
| `kb-fd009e0092ecd912` | Seed: DOM XSS via location.hash sink | dom / javascript |

Store files: `ai_data/knowledge/index.json` +
`documents/e9680d… .json`, `documents/618f742… .json`,
`documents/fd009e0… .json` (filenames are the full SHA-256 content
hashes; `knowledge_id` = `kb-` + first 16 hex).

## Reference archive path + record count

- Path: `ai_data/research/CVE-2026-1557.references.json`
- `archive_version: "references-1"`, `record_count: 6`
- Records: 3× wordpress-trac (`source_type: other`), 1× wordfence
  (`other`), 1× nuclei-templates PR #15592 (`github`), 1× crowdsec hub
  PR #1749 (`github`); `title`/`exact_record`/`content_hash` are
  `null`, `context_chunks` are `[]` (backfill-labeled, see above).

## XSSResearcher retrieval proof

Against the seeded production store (`ai_data/knowledge`), case
(reflected / `html_attribute` / `Example Framework` / `Example WAF`):

- `DOCS: 1`, `IDS: ['kb-e9680d762348e261']`
- `PAYLOADS: [('attribute breakout marker', ['src-7ae842e03383fbcd'])]`
- CLI: `kb search --xss-type reflected` → `MATCHES: 2`;
  `kb list` → `KB DOCS: 3`;
  `kb show kb-e9680d762348e261` → full document JSON (aggregate,
  provenance with `src-7ae842e03383fbcd`, `clm-4197f4dcfcd34b35`).

## Production 5-series / live-validation untouched — confirmation

- `git diff --name-only` (tracked): only `ai/research_cli.py`
  (plus pre-existing 0-line `run-heavy-guarded.sh`).
- `ai/live_validation/`, `ai/verification/`, `ai/evidence/`,
  `ai/finding/`: zero modifications (status shows only the
  pre-existing untracked `ai/lab/`).
- No B10/lab files touched; no authorization/scope/materialization
  code touched; no live execution performed.

## Remaining limitations

1. Corpus is 3 seed notes — enough for proof, not for real Reports or
   agent recall; no PortSwigger/CWE/write-up ingestion yet.
2. CVE-2026-1557 archive is a URL-list backfill (no bodies); full
   contexts arrive only on the next research run.
3. Single-CVE coverage still (only CVE-2026-1557 on disk); no CVE
   mirror or cross-CVE research index.
4. Retrieval remains metadata exact-match only (no full-text/semantic
   search, ranking, pagination); XSS retrieval keys still narrow
   (technology/xss_type/context/waf).
5. No report renderer yet (`ai_data/reports/` convention, Markdown/PDF
   export, 5J-labeling helper all still missing).

## Recommended next stage

**Stage R2 — "First real report":** add a read-only report renderer
that consumes the three R1 artifacts (`*.cli.json` +
`*.references.json` + KB `show`/`search` output) and emits a
deterministic Markdown report to `ai_data/reports/<CVE>.md`,
clearly labeling research-track (non-authoritative) vs 5J-sealed
content. No new collection, no agent loop, no search upgrades — it
turns today's inspectable data into the first tangible product output.
