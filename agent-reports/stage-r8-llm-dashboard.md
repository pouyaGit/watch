# Stage R8 — Surface LLM XSS Research in Dashboard & Reports

## Summary

Exposed the persisted R7 LLM XSS research record through the existing
read-only API, XSS detail page, and evaluated the report surface. The
deterministic XSS candidate remains authoritative for status, confidence
and evidence; the LLM output is rendered as clearly-separated research
commentary only. No deterministic agent logic, no R7 generation logic,
no status/confidence semantics, no execution, no provider invocation,
no writes, and no auth changes.

## Files changed

- `backend/research_data.py` — append-only: `XSS_LLM_DIR`
  (`ai_data/research/xss/llm`), `_xss_llm_payload`,
  `has_xss_llm_research`, `get_xss_llm_research`. Exact candidate-id
  validation via existing `normalize_xss_id`, confined path via existing
  `_confined`/`_resolved_under`, missing file → `NotFoundError`,
  malformed JSON / non-dict / candidate-id mismatch →
  `ResearchDataError`, candidate-id match enforced, verbatim payload
  plus `kind=llm_research`, `is_finding=False`, `verified=False`.
- `backend/routers/research.py` — append-only: `GET
  /api/xss/candidates/{candidate_id}/llm-research` behind existing
  `verify_api_key`, deterministic JSON, 404 when no research exists,
  400 on malformed id/artifact, no filesystem path leakage (detail
  strings only), no provider invocation.
- `backend/routers/research_pages.py` — `ui_xss_detail` additionally
  loads the LLM record read-only and fail-safe (`NotFoundError` /
  `ResearchDataError` → neutral absence, never an error page, never a
  provider call); passes `llm` / `llm_error` to the template.
- `web/templates/xss_detail.html` — append-only: "LLM Research" panel
  headed `LLM RESEARCH — NOT VERIFIED`, preceded by an explicit
  `DETERMINISTIC CANDIDATE above is authoritative…` hierarchy note and
  closed with `Research commentary only — not a verified finding`.
  Renders model, explanation, likely attack surface, relevant context,
  supporting reasoning, missing evidence, suggested test idea,
  EVIDENCE/INFERENCE/UNKNOWN cards (kind badge + attribution ids), and
  references used. Absence renders `LLM research not generated.`;
  unreadable artifact renders a safe fallback line. All values use
  default Jinja autoescaping; zero `|safe`; no Markdown/HTML rendering.
- `tests/test_xss_llm_dashboard.py` — NEW: 14 focused tests (see § Tests).

Report renderer (`ai/reports/renderer.py`): UNCHANGED — see § Report
changes. No other files modified.

## API changes

- Added `GET /api/xss/candidates/{candidate_id}/llm-research`
  (`api_xss_llm_research` in `backend/routers/research.py`).
- Auth: existing `verify_api_key` dependency (401 without key verified).
- Read-only: serves only the persisted
  `ai_data/research/xss/llm/<candidate_id>.json`; no provider call, no
  writes, no subprocess/network/Mongo/Nuclei.
- Deterministic: same bytes on repeat reads (tested).
- 404 `llm research not found` when no record exists; 400 on malformed
  id or malformed/mismatched artifact; no path leakage in responses.
- No generic arbitrary-file endpoint: id is regex-validated
  (`^xss-[0-9a-f]{16}$`) and confined under `XSS_LLM_DIR`.

## UI changes

- `/ui/xss/{candidate_id}` gains a visually separated `LLM Research`
  panel (`LLM RESEARCH — NOT VERIFIED` quarantine-style label) placed
  between the deterministic evidence grid and the quarantined
  `UNTESTED RESEARCH IDEA — NEVER EXECUTED` test-idea panel.
- Hierarchy is explicit in-page: `DETERMINISTIC CANDIDATE above is
  authoritative for status, confidence and evidence` →
  `explanatory assistance only` → `never changes candidate status or
  confidence`; closing line repeats `not a verified finding`.
- Existing `RESEARCH CANDIDATE — NOT A PRODUCTION FINDING` and
  `UNTESTED RESEARCH IDEA — NEVER EXECUTED` boundaries untouched and
  still prominent (asserted in tests).
- EVIDENCE / INFERENCE / UNKNOWN items render as individual cards with
  a kind badge and attribution ids; plain escaped text, no links, no
  `|safe`, no Markdown rendering.
- Empty/missing: neutral `LLM research not generated.` — never triggers
  generation or a provider call from the page request. Malformed
  artifact: safe fallback line, candidate still renders.

## Report changes (explicit reason unchanged)

`ai/reports/renderer.py` left UNCHANGED, deliberately:

1. The renderer is CVE-scoped (`build_report_for_cve`,
   `ai_data/reports/<CVE>.md`); R7 LLM research is candidate-scoped
   (`ai_data/research/xss/llm/<candidate_id>.json`) with no CVE linkage
   — there is no deterministic join key, so inclusion would require
   inventing a cross-entity mapping.
2. Reports are byte-identical deterministic renders of persisted CVE
   artifacts; regenerating them to embed probabilistic LLM commentary
   would break that guarantee and risk letting LLM content sit beside
   (and be confused with) the deterministic vulnerability summary,
   violating the "never alter the deterministic summary" rule.
3. The XSS candidate surface (API + detail page) is the correct home
   for per-candidate commentary; CVE reports already carry an explicit
   trust boundary and limitations section.

A dedicated XSS-candidate report was out of scope (would be a redesign).

## Real candidate verification

- Real tree has NO `ai_data/research/xss/llm/` directory (no LLM
  research generated yet): verified `/ui/xss/xss-60edf609e21c6b41`
  renders the neutral `LLM research not generated.` state and `GET
  /api/xss/candidates/xss-60edf609e21c6b41/llm-research` is 404 on real
  data — no fabrication, no auto-generation.
- End-to-end with the real candidate `xss-488f639165085224`
  (INSUFFICIENT_EVIDENCE, 0.35): loaded real KB evidence via
  `KnowledgeStore` (1 doc, `kb-609f38e9c57c0592`), built an
  `XSSLLMResearchAssistantResult` through the real R7 validator,
  persisted to temp, read back through `get_xss_llm_research`:
  status/confidence match the deterministic candidate exactly
  (`True True`), kinds `[EVIDENCE, UNKNOWN]` with correct attribution.
- Deterministic candidate files byte-identical (read-only layer never
  writes to them).

## Security review

- Auth unchanged: new API route uses existing `verify_api_key`;
  UI route uses existing `_UI_AUTH`; 401-without-key tested.
- Read-only: no writes (only `read_text`/`exists`/`glob`), no provider
  invocation from API/UI (AST-verified: no `ai.llm`, `LLMProvider`,
  `OpenRouter` in touched backend files), no subprocess, no socket,
  no execution, no Nuclei execution (only pre-existing read-only
  summaries), no Mongo, no 5B–5J/live-validation contact.
- No arbitrary file reads: id regex + `_confined`/`_resolved_under`
  under `XSS_LLM_DIR`; `../../etc/passwd` and `../secret` variants
  raise `ResearchDataError` (tested at data and HTTP layers).
- Escaping: template uses default autoescaping, zero `|safe`
  (grep-verified); hostile `<script>alert('llm-xss')</script>` in every
  LLM field renders escaped (`&lt;script&gt;`), never raw (tested).
- Secrets absent: no credential material in responses (existing
  no-secret tests still pass); model field is display-only text.
- Legacy `XssFindings` absent: untouched, never imported or surfaced
  (AST + text verified).

## Tests

New `tests/test_xss_llm_dashboard` — **14 tests, all pass**:
data missing (NotFound) / malformed (safe fail) / id-mismatch /
traversal rejection; API 404-missing / deterministic success /
malformed-400 + invalid-id-400 / auth; UI neutral absence /
full panel incl. EVIDENCE/INFERENCE/UNKNOWN + authority banners /
hostile escaping / malformed fail-safe; no-provider/execution imports;
report renderer has no LLM section.

Required + adjacent suites (all `OK`):

| Suite | Tests |
| --- | --- |
| tests.test_xss_llm_dashboard (new) | 14 |
| tests.test_research_api + test_research_ui | 68 (82 with new) |
| tests.test_routers_fixes + test_dashboard_logic + test_page_render + test_ui_redesign | 58 |
| ai.test_xss_llm_assistant | 20 |
| ai.test_xss_agent | 21 |
| ai.test_xss_researcher | 12 |
| ai.test_research_cli | 6 |
| ai.test_reports_renderer | 14 |
| ai.test_knowledge_store | 15 |
| AI total (6 suites) | 88 |

`git diff --check` → clean. No browser/screenshot tooling in this
environment; visual verification via TestClient HTML assertions
(list/detail with and without research, escaped hostile content,
mobile-agnostic server-rendered markup reusing existing classes).

## Remaining limitations

- No `ai_data/research/xss/llm/` records exist in the real tree, so the
  new panel shows the neutral absence state on all real candidates
  until `xss llm-research` is explicitly run (by design — never
  auto-generated from page/API requests).
- `content_hash` ties research to a candidate snapshot; the UI does not
  currently compare it against the live candidate hash (the API exposes
  both values so a client can).
- Report surface intentionally unchanged (see § Report changes).

## Agent / Model

- Model: muse-spark-1.3-contributor (Muse Spark)
- Stage: R8
- Role: Implementation
