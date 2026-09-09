# Stage D2 — Read-Only Research API — Implementation Report

## Summary

Implemented the Stage D2 read-only Research API. All nine required
endpoints are live, key-gated, and served from a single new router
(`backend/routers/research.py`) backed by one filesystem helper
(`backend/research_data.py`). No frontend changes, no schema changes,
no execution paths added.

## Endpoint table

| Method | Path | Handler | Source |
| --- | --- | --- | --- |
| GET | `/api/research` | `api_research_list` | `ai_data/research/*.cli.json` (compact records) |
| GET | `/api/research/overview` | `api_research_overview` | cheap counts (see Caching) |
| GET | `/api/research/{cve}` | `api_research_detail` | `ai_data/research/<CVE>.cli.json` (full useful structure) |
| GET | `/api/kb` | `api_kb_list` | `KnowledgeStore.retrieve()` (metadata only) |
| GET | `/api/kb/{id}` | `api_kb_detail` | `KnowledgeStore.get_by_id()` (metadata + content + provenance) |
| GET | `/api/xss/candidates` | `api_xss_list` | `ai_data/research/xss/xss-*.json` (compact) |
| GET | `/api/xss/candidates/{id}` | `api_xss_detail` | full candidate JSON + kind/disclaimer |
| GET | `/api/reports` | `api_reports_list` | `ai_data/reports/*.md` (metadata only) |
| GET | `/api/reports/{cve}` | `api_report_detail` | `ai_data/reports/<CVE>.md` (raw Markdown) |

Route order note: `/api/research/overview` is registered before
`/api/research/{cve}` so it is never captured as a CVE id. Same for
`/api/xss/candidates` before `/api/xss/candidates/{id}`.

## Response shapes

- List endpoints return `{total, offset, limit, items}`.
- Research compact record: `cve, title, cvss_score, cvss_vector,
  severity, cwe, products, versions, vulnerability_type, endpoint,
  endpoints, parameters, authentication, public_exploit,
  research_status, llm_status, authoritative, nuclei_decision,
  nuclei_candidate, assets, programs, technologies`.
  Missing values are `null`/`[]`, never invented.
- Research detail adds `summary, root_cause, impact,
  attack_requirements, evidence, detection_ideas, nuclei_reason,
  bug_bounty_relevance, references, artifact`.
- KB list items are metadata only (no `content`/`provenance`):
  `knowledge_id, title, source_url, source_type, summary, tags,
  technologies, xss_types, contexts, confidence, evidence_quality,
  indexed_at, published_at`.
- KB detail adds `content` (plain text) and `provenance` (JSON list).
- XSS compact record: `candidate_id, kind="research_candidate",
  status, xss_type, context, injection_context, confidence, query,
  vulnerability_pattern, technologies, disclaimer`.
- XSS detail returns the full persisted candidate plus
  `kind="research_candidate"`, `is_finding=false`, `disclaimer`,
  `artifact`. Every XSS response carries the research-candidate
  disclaimer; nothing is framed as a production finding.
- Reports list items: `{cve, artifact, size_bytes}` (never bodies).
- Report detail: `{cve, artifact, markdown, size_bytes}` — raw
  Markdown only, no HTML rendering.
- Overview: `{research_cves, kb_documents, xss_candidates,
  xss_by_status, reports, nuclei: {generated, results, findings}}`.

## Authentication behavior

- Every new route declares `dependencies=[Depends(verify_api_key)]`,
  the same dependency used by the existing routers.
- The global `APIKeyMiddleware` in `api.py` also gates all `/api/*`
  paths (401 without a valid `X-API-Key` header or `?api_key=`).
- `verify_api_key` and middleware semantics were NOT modified.
- Verified: all 9 routes return 401 without a key when `API_KEY` is set.

## Filesystem / data sources

- Research: `ai_data/research/<CVE>.cli.json`, CVE id must match
  `^CVE-\d{4}-\d{4,7}$` (shared with the reports renderer).
- KB: `ai_data/knowledge/` via read-only `KnowledgeStore.retrieve()`
  / `get_by_id()`; id must match `^kb-[0-9a-f]{16}$`.
- XSS: `ai_data/research/xss/xss-*.json` only; id must match
  `^xss-[0-9a-f]{16}$`. Legacy Mongo `XssFindings` are never read and
  no `/api/xss/findings` route exists.
- Reports: `ai_data/reports/<CVE>.md`, CVE validated with the same
  `CVE_RE`, path confined under `ai_data/reports` via resolve-and-
  prefix check; traversal rejected.
- Nuclei counts (overview only): file counts under
  `ai_data/nuclei/{generated,results,findings}`; contents never read.
- All filesystem logic lives in `backend/research_data.py`; route
  handlers only map errors to HTTP codes.

## Security controls

- No writes: endpoints never mutate KB, Mongo, or the filesystem.
- No subprocess / network / LLM / Nuclei execution / production
  verifier imports in new code (AST-verified in tests).
- Markdown stays raw Markdown; no HTML rendering, no `|safe`.
- CVE/KB/XSS ids validated against fixed regexes; all constructed
  paths resolved under their fixed base directory.
- Errors are clean JSON: 400 malformed id/filter, 404 missing
  artifact, 401 existing auth behavior. Filesystem paths and secrets
  are never leaked (detail messages use basenames/generic text).
- No API keys, OpenRouter keys, prompts, provider credentials, or
  environment variables are exposed (verified by scan test).

## Pagination behavior

- Query params `limit` (default 50) and `offset` (default 0) on all
  four list endpoints.
- `limit` clamped to `[1, 100]` via `clamp_limit()`; verified that
  `limit=500` returns `limit=100`.
- Ordering is explicit and deterministic: research/reports by CVE
  ascending, KB by `knowledge_id`, XSS by `candidate_id`.
- Filtering: research supports `q` (CVE/title/product substring),
  `cve`, `severity`, `status`; KB supports `q`
  (title/summary/source URL/tags), `cve`, `tag`; XSS supports `status`
  (exact), `type` (exact), `context` (exact); reports support
  `q`/`cve` (CVE substring).

## Caching behavior

- `get_overview()` uses a 10-second in-process TTL cache, consistent
  with `backend/dashboard.py`'s `_CACHE_TTL = 10.0`.
- Overview reads only cheap signals: research/report/XSS file globs,
  KB `index.json` document count (no document reads), Nuclei file
  counts. No report bodies, KB contents, or large context chunks are
  loaded for list/overview paths.

## Test counts (exact)

- New: `tests/test_research_api.py` — **27 tests, all pass**.
  Covers: auth required (9 routes), research list/detail,
  missing/malformed CVE, severity/q/cve filters, KB list (metadata
  only)/detail (content+provenance)/q+cve filters/malformed+missing,
  XSS list/detail/filters (status/type/context)/malformed+missing,
  legacy findings not exposed, reports list/detail/missing/traversal
  rejection, overview counts (+ status sum invariant), pagination caps
  (4 lists), deterministic ordering (4 lists), secret hygiene,
  no-network/subprocess AST check, malformed ids.
- Existing backend/API: `tests.test_routers_fixes` +
  `tests.test_dashboard_logic` + `tests.test_page_render` —
  **39 tests, all pass**.
- Existing AI suites: `ai.test_knowledge_store`,
  `ai.test_research_cli`, `ai.test_research_ingestion`,
  `ai.test_xss_researcher`, `ai.test_xss_agent`,
  `ai.test_reports_renderer`, `ai.test_xss_llm_researcher`,
  `ai.test_openrouter` — **149 tests, all pass**.
- Extra: `ai.test_knowledge_ingestion`, `ai.test_researcher` —
  **36 tests, all pass**.
- No unrelated pre-existing failures were fixed or introduced.

## Changed files

- `backend/research_data.py` — extended (was research-only list/detail):
  fixed `list_research` CVE-filter shadowing bug, added
  endpoint/path extraction, added KB/XSS/reports/overview sections
  with `KB_ID_RE`, `normalize_kb_id`, 10s overview cache.
- `backend/routers/research.py` — NEW: 9 key-gated read-only routes.
- `api.py` — one import line + one `include_router` line (only change).
- `tests/test_research_api.py` — NEW: 27 focused tests.
- `agent-reports/stage-d2-read-only-research-api.md` — this report.

## Sample curl commands

```bash
export BASE=http://localhost:5000 KEY=$API_KEY
curl -s "$BASE/api/research?api_key=$KEY&limit=5" | head -c 500
curl -s "$BASE/api/research/CVE-2026-1557?api_key=$KEY" | head -c 500
curl -s "$BASE/api/research/overview?api_key=$KEY"
curl -s "$BASE/api/kb?api_key=$KEY&q=responsive"
curl -s "$BASE/api/kb/kb-609f38e9c57c0592?api_key=$KEY" | head -c 300
curl -s "$BASE/api/xss/candidates?api_key=$KEY&status=RESEARCH_CANDIDATE"
curl -s "$BASE/api/xss/candidates/xss-60edf609e21c6b41?api_key=$KEY" | head -c 500
curl -s "$BASE/api/reports?api_key=$KEY"
curl -s "$BASE/api/reports/CVE-2026-1557?api_key=$KEY" | head -c 300
# header form also works:
curl -s -H "X-API-Key: $KEY" "$BASE/api/research/overview"
```

## Known limitations

- Research `parameters` extraction only catches `'name' parameter`
  phrasing; some params stated differently are `[]` (not invented).
- `endpoints` extraction is regex-based over persisted text and may
  include file-like tokens (e.g. `/document.xml`); it quotes what the
  artifacts state and infers nothing about live targets.
- KB search is substring match over persisted metadata, not a
  full-text/semantic index (matches KnowledgeStore's metadata-only
  design).
- Only one report (`CVE-2026-1557.md`) is currently persisted, so the
  reports list has a single entry.
- `/api/reports/<traversal>` at the HTTP layer may surface as 404 from
  routing normalization rather than 400; either way no file outside
  `ai_data/reports` is served (unit-verified at the helper layer).

## Untouched-code confirmation

Explicitly untouched per the task constraints:

- No database schema changes (`database/` not modified by this task).
- No research behavior changes (no 5B–5J, live-validation, researcher,
  collector, or correlator code modified).
- No Nuclei execution changes.
- No task runner / task registry changes.
- No authentication semantics changes (`verify_api_key` and middleware
  logic identical; `api.py` gained only import + include lines).
- No frontend changes (no Jinja/HTMX/SPA work).
- No packages installed.
- No Git operations performed (no commit, no push).
