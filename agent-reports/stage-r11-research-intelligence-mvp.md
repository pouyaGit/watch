# Stage R11 — Research Intelligence MVP

## Outcome

DONE — 100% execution + validation, **zero code changes**. The existing
research pipeline (CVECollector → ReferenceDiscovery →
ReferenceCollector → quality gate → deterministic research →
persisted CVE research → KB ingestion → XSS agent → reports → read-only
API/dashboard) was run against a real batch of **5 real CVEs** and
produced tangible bug-bounty research artifacts:

- 5/5 CVEs researched successfully (0 failures), persisted under
  `ai_data/research/`
- 18 public references discovered, 9 fetched, 9 context sets built,
  quality gate checked 5 CVEs
- 14 new KnowledgeBase documents added (synthesis + reference-derived);
  ingestion re-run produced **zero duplicates** (idempotency verified)
- 4 new deterministic XSS research candidates persisted with honest
  statuses (1 INSUFFICIENT_EVIDENCE, 3 REJECTED — no forced results)
- 5 deterministic Markdown reports generated
- Read-only API and dashboard verified to expose all new data (8/8
  researched routes return 200 with the new artifacts)

LLM was kept optional exactly as required: the whole R11 pipeline ran
with `--skip-llm` (no provider). There was **no code change**, hence no
provider-abstraction change and no new architecture. One concrete
pipeline observation (batch artifacts vs `kb ingest` inputs) and two
pre-existing data-coupled UI test expectations are documented precisely
in Limitations.

## Starting Point

Audited immediately before the run (state as of this stage's start):

- Pipeline entry points (all existing): `ai/research_cli.py` with
  subcommands `check/research/batch/kb/report/xss/validate-live`;
  batch orchestration in `ai/researcher/cve_batch.py`
  (`run_cve_batch` over explicit `--cves` lists).
- Data layer: `ai_data/research/` already contained 4 researched CVEs
  (CVE-2026-1557, CVE-2026-78203/205/207), 8 batch aggregates,
  3 XSS candidates, a 1-document KB, and `CVE-2026-1557.md` report
  from earlier stages. None of those authoritative artifacts were
  overwritten by R11.
- Environment: LIVE NVD API reachable (by-`cveId` endpoint only in this
  sandbox — keyword search returns 404), public reference sites
  reachable, GitHub API reachable (unauthenticated). MongoDB is NOT
  installed/running on this box (same posture as prior stages), so the
  research-lane Mongo reads were served by the documented in-process
  empty-Mongo sandbox substitute (`mongomock`) via a throwaway driver
  OUTSIDE the repo (`/tmp/r11_sandbox.py`), with a process-only
  `WATCH_MONGO_URI`. Zero Watch assets are registered — identical
  posture to the prior empty-DB sandbox; every research-lane module ran
  UNMODIFIED.
- LLM: `OPENROUTER_API_KEY` is present in the environment, but R11 does
  not require it and did not call any provider (`--skip-llm`).

## CVE Batch

5 real, security-relevant, web/application/plugin CVEs with public
references (selected and verified against the live NVD by `cveId`
lookup — every ID returned exactly one real record):

| CVE | Product/component | CWE | CVSS 3.x | Public references |
| --- | --- | --- | --- | --- |
| CVE-2024-27956 | ValvePress **WordPress Automatic** plugin ≤3.92.0 — unauthenticated arbitrary SQL execution | CWE-89 | 9.9 | Patchstack article + Patchstack DB |
| CVE-2024-42327 | **Zabbix** frontend — SQLi in `CUser` class `addRelatedData`, any non-admin role with API access | CWE-89 | 9.9 | Zabbix support ticket ZBX-25623 |
| CVE-2024-5376 | **Kashipara College Management System** 1.0 — XSS in `view_each_faculty.php` | CWE-79 | 5.3 | github.com/E1CHO/cve_hub PDF + VulDB |
| CVE-2025-3102 | **SureTriggers** WordPress automation plugin — auth bypass → admin account creation (missing empty-value check) | CWE-697 | 8.1 | WordPress plugin trac diff + Wordfence |
| CVE-2025-4893 | **CoinExchange_CryptoExchange_Java** — `uploadLocalImage` path traversal | CWE-22 | 5.3 | github.com/ShenxiuSec/cve-proofs POC + VulDB |

Selection criteria: web/application/plugin focus, publicly available
references/writeups, no authenticated/private source required to
understand, and a mix of XSS-relevant (CVE-2024-5376) and
non-XSS-but-bounty-relevant (SQLi, auth-bypass, path traversal) bugs so
the XSS layer's "no forced results" behavior is exercised honestly.

## Research Results

Two complete runs of the EXISTING batch pipeline
(`research_cli.py batch --cves <5> --skip-llm` →
`ai.researcher.cve_batch.run_cve_batch`), both fully successful
(second run = deterministic rerun, same 5/5):

- batch aggregate: `processed=5 failed=0 completed=5 completed_degraded=0`
- provider outages: 0 (http_402/429/5xx/network all zero)
- provider retries: attempted=0 (LLM skipped; no provider calls)
- Per-CVE canonical artifacts (`research_cli.py research --cve <CVE> --skip-llm`,
  the documented research→ingest pairing) — 5/5 completed:

| CVE | discovered | fetched | contexts | assessment |
| --- | --- | --- | --- | --- |
| CVE-2024-27956 | 5 | 5 | 5 | 0 (no correlated assets) |
| CVE-2024-42327 | 2 | 2 | 2 | 0 |
| CVE-2024-5376 | 4 | 1 | 1 | 0 |
| CVE-2025-3102 | 3 | 0 | 0 | 0 |
| CVE-2025-4893 | 4 | 1 | 1 | 0 |

Persisted artifacts: per-CVE `<CVE>.cli.json` (research payload,
`authoritative=False`, provenance `deterministic=[nvd, reference]`,
`llm=skipped`), `<CVE>.batch.json`, `<CVE>.references.json` reference
archives, batch aggregate JSON, and batch markdown summary (see
Reference Quality / Knowledge Base).

## Reference Quality

- Discovery total: **18** sources across the 5 CVEs (NVD-listed
  references + GitHub repository/issue search, deduplicated and ranked
  by the existing `ReferenceDiscovery`).
- Fetch total: **9** documents fetched successfully by
  `ReferenceCollector` (3 fetch attempts failed — e.g. WordPress trac
  / Wordfence blocked CVE-2025-3102's sources; the pipeline degraded
  gracefully to metadata-only research for that CVE).
- Contexts built: **9**; deterministic quality gate ran on all 5 CVEs
  (`reference_quality: checked=5 rejected=0`). The gate filters
  structurally invalid contexts (not low-value ones); nothing invalid
  was produced this run because contexts are only built from
  successfully-fetched documents.
- Reference archives: 5 files, 9 records total
  (5/2/1/0/1). `content_hash` is **None on every record — never
  invented** (the fetch path in this run did not emit hashes); source
  URLs and provenance are preserved verbatim. No missing reference
  body was fabricated.
- Quality observation (not a defect): GitHub search surfaced 3
  "daily-info-feed" aggregator issues that mention the CVE id in
  passing (BruceFeIix/picker#962, Tyaoo/picker#632,
  crowdsecurity/crowdsec#3562) — structurally valid, analytically weak.
  The existing gate keeps such entries by design (filters invalidity
  only); see Recommendations.

## Knowledge Base

- Ingestion (`research_cli.py kb ingest --cve <CVE>`, deterministic,
  no network, no LLM) added **14 documents**: 5 synthesis documents
  (one per researched CVE) + 9 reference-derived documents. KB total:
  **15** (was 1).
- Idempotency verified: the same 5 ingest commands were run a second
  time — every `knowledge_id` reported `present` (0 re-created),
  document count stayed at 15, and the on-disk documents directory
  stayed at 15 files. No duplicates.
- Synthesis documents carry `tags: [cve:<ID>, research]`, vendor/product
  metadata, and a `local://ai_data/research/<CVE>.cli.json` source-artifact
  URL. Reference documents carry the original public source URL, title,
  source type, and ingested context chunks.

## XSS Intelligence

Four queries derived from the real KB content were run through the
existing deterministic XSS research agent (`xss research`):

| Query (derived from) | candidate_id | status | confidence |
| --- | --- | --- | --- |
| reflected XSS College Management System view_each_faculty php (CVE-2024-5376, a real CWE-79) | xss-66d4b40bc1570361 | INSUFFICIENT_EVIDENCE | 0.35 |
| WordPress Automatic plugin SQL injection parameter (CVE-2024-27956) | xss-2933a49053e5e1a4 | REJECTED | 0.0 |
| Zabbix frontend CUser SQL injection (CVE-2024-42327) | xss-1d270df566e6586d | REJECTED | 0.0 |
| CoinExchange uploadLocalImage path traversal (CVE-2025-4893) | xss-4e04abad731ca671 | REJECTED | 0.0 |

**No results were forced.** The only XSS-positive CVE (2024-5376)
produced INSUFFICIENT_EVIDENCE — the deterministic rule requires an
exact KB `xss_type`+`context` match, and the ingested synthesis
documents carry no `xss_types`/`contexts` metadata (see Limitations).

KB value to XSS research (task 14): the candidate's `source_evidence`
does include the **real** CVE-2024-5376 reference document
(`kb-03b6a1aeb88a4fc3`, the github.com/E1CHO/cve_hub PDF) alongside
the bundled seeds — the KB genuinely grounds the candidate in real
research material. The candidates' `unknowns` are explicit
(`exploitability: unconfirmed by design`, `injection context: no exact
KB context match`, `live reflection: not observed`).

## Reports

- 5 deterministic Markdown reports generated
  (`report --cve <CVE>` → `ai_data/reports/<CVE>.md`), 6 total.
- Read-only render: no network, no LLM, no Nuclei, no Mongo.
- Outputs are honesty-preserving: CVSS score/vector, affected product,
  persisted references with source URLs, KB readback, Watch-relevance
  and Limitations sections render "Unknown" wherever a field is absent
  (e.g. `--skip-llm` → vulnerability title/description/severity Unknown
  rather than hallucinated). Nuclei section explicitly reports
  "Not available" and the trust-boundary disclaimer.
- Report header: "Deterministic read-only render from persisted local
  artifacts. No network, no LLM, no Nuclei execution, no production
  access."

## API

Read-only API (backend/routers/research.py over the filesystem data
layer; no Mongo, no network) exposes all new data — verified in-process
with the existing TestClient + api-key auth:

- `/api/research` → 200, total 9 (5 new CVEs present)
- `/api/research/overview` → kb_documents 15, xss_candidates 7, reports 6
- `/api/kb` → 200, total 15 (all new docs present)
- `/api/xss/candidates` → 200, total 7 (4 new candidates present)
- `/api/reports` → 200, total 6 (5 new reports present)

Note: research list items for the skip-llm CVEs report
`severity=None/status=None` (the deterministic payloads carry no LLM
severity field) — the API returns what exists and omits the rest.

## Dashboard

Dashboard UI (backend/routers/research_pages.py) renders the new data
— verified in-process, all 200:

- `/ui/research` , `/ui/research/CVE-2024-5376`
- `/ui/kb` , `/ui/kb/kb-03b6a1aeb88a4fc3`
- `/ui/xss` , `/ui/xss/xss-66d4b40bc1570361`
- `/ui/reports` , `/ui/reports/CVE-2024-27956`

No dashboard code was changed.

## Real Output Examples

1. **CVE-2024-5376 reference archive record** (real, provenanced):
   `github.com/E1CHO/cve_hub/blob/main/College Management System - xss/College Management System - vuln 10.pdf` — source type `github`, 1 context chunk, `content_hash: null` (not fabricated). This is NVD+CVE hub ground truth for a real CWE-79.
2. **KB reference document** `kb-03b6a1aeb88a4fc3` — title
   `cve_hub/College Management System - xss/...PDF ... E1CHO/cve_hub`,
   tagged `cve:CVE-2024-5376`, feeds the XSS candidate evidence list.
3. **XSS candidate** `xss-66d4b40bc1570361` — `INSUFFICIENT_EVIDENCE`,
   confidence 0.35, `source_evidence` = [kb-0958da2bb9935000 (seed, type exact), kb-59a0bec7d50e6054 (seed), kb-03b6a1aeb88a4fc3 (real 5376 PDF doc)], unknowns explicit.
4. **Research payload provenance** (`CVE-2024-27956.cli.json`):
   `provenance: {deterministic: [nvd, reference], llm: skipped, authoritative: False}`, CVSS 9.9, products `[Automatic, wordpress_automatic_plugin]`.
5. **Report honesty check** (`ai_data/reports/CVE-2024-5376.md`):
   CVSS 5.3 + real reference rendered; vulnerability title/description
   render "Unknown" (skip-llm payload carries no invented fields);
   Watch relevance section states "Unknown — persisted artifacts do not
   confirm the vulnerable product/version on any specific Watch target."

## Metrics

| Metric | Value |
| --- | --- |
| CVEs researched | 5 (batch) + 5 (canonical per-CVE rerun) |
| Successful research | 5/5 completed, 0 failed (both batch runs) |
| References discovered | 18 |
| References fetched | 9 (3 failed fetch attempts, incl. all of CVE-2025-3102) |
| Reference contexts built | 9 |
| Quality gate | checked=5, rejected=0 |
| Reference archive records | 9 across 5 archives (content_hash 0 — never invented) |
| KB documents added | 14 (5 synthesis + 9 reference); total 15 |
| KB idempotency | re-ingest created 0 duplicates |
| XSS candidates generated | 4 new (total 7): 1 INSUFFICIENT_EVIDENCE, 3 REJECTED, 0 RESEARCH_CANDIDATE |
| Reports generated | 5 new (total 6) |
| CVEs with XSS relevance in real data | 1 (CVE-2024-5376, CWE-79) |

## Determinism / Idempotency

- KB ingestion is deterministic and idempotent: two full passes
  produced identical `knowledge_id`s and zero duplicates (15 files
  stable).
- Batch rerun of the same 5 CVEs produced identical statuses and
  artifact structure (timestamps differ by design).
- Per-CVE artifacts are named by stable IDs
  (`<CVE>.cli.json/.references.json/.batch.json`, hashes preserved
  where the source data carries them; `content_hash` is None rather
  than invented).
- No pre-existing authoritative artifacts were overwritten: the 2026
  research/XSS artifacts and the existing KB document/report were
  untouched (verified via snapshot-style listing before/after).
- XSS candidate IDs are deterministic functions of
  (query, signals, evidence) — rerunning the same queries reproduces
  the same IDs.

## Security Boundaries

- No API keys, Mongo credentials/URIs, authorization headers,
  provider account metadata, response bodies, or user identifiers
  appear in any artifact, test, or this report. `.env` was not
  modified. The Mongo substitute used a process-only mock URI with no
  credentials.
- No live target interaction: only public NVD / reference-site /
  GitHub API lookups occurred (the standard research lane). Zero
  Watch assets were contacted or registered.
- No exploitation, no Nuclei execution (batch lane correctly reports
  `nuclei lane skipped: LLM research skipped`), no production
  finding/verdict creation (`authoritative: False` everywhere), no
  alerts/notifications.
- LLM optional and unexercised: `--skip-llm` for the entire run; zero
  provider calls; no provider-abstraction change (requirement 17 — no
  blocker found).

## Tests

- **Focused R11 / research-KB-XSS pipeline tests — 191 passed:**
  `ai.test_cve_batch`, `ai.test_research_kb_xss_e2e`,
  `ai.test_research_cli`, `ai.test_real_research`,
  `ai.test_knowledge_ingestion`, `ai.test_reports_renderer`,
  `ai.test_xss_agent`, `ai.test_batch_reference_quality_parity`,
  `ai.test_single_cve_quality_parity`,
  `ai.test_reference_quality_gate`, `ai.test_reference_cache`.
- **Backend/UI regression — 82 ran, 80 passed, 2 failed. The 2
  failures are PRE-EXISTING data-coupled test expectations in the
  untracked D-series dashboard tests** (`tests/test_research_ui.py`),
  **not R11 regressions**: proven by temporarily moving the R11 data
  aside and running the exact two tests (both pass on the pre-R11 data
  set). They hardcode assumed dataset sizes (`">4<", ">3<", ">1<"`
  with the comment "real persisted counts on the strip (4 CVEs / 3 XSS
  / 1 KB / 1 report)") and assert strict anchor-order equality for a
  title sort — any real data growth trips them. Per the stage's
  explicit constraints ("do not touch unrelated dashboard work", "do
  not modify unrelated pre-existing changes"), they are documented,
  not edited.
- `git diff --check`: clean.
- No code changes were made, so no new unit tests were added (the
  stage mandate: prefer execution + validation over code when the
  existing code is sufficient).

## Diff/Stat

- **Code delta from R11: ZERO lines.** No tracked source file was
  modified, added, or deleted by this stage.
- `git status` at completion: 13 tracked `M` files — all
  PRE-EXISTING uncommitted work from earlier stages (R10 provider
  changes in `ai/llm/openrouter.py`, `ai/test_openrouter.py`; D-series
  dashboard work in `api.py`, `backend/`, `web/`; `ai/research_cli.py`,
  `ai/schemas/xss.py`); 1 pre-existing `D` (a Windows-sidecar file);
  49 untracked (prior-stage test/dashboard files + agent-reports +
  this stage's ai_data artifacts). Nothing unrelated was touched.
- New artifacts from this stage (all under `ai_data/` +
  `agent-reports/`): 5× `<CVE>.cli.json`, 5× `<CVE>.references.json`,
  5× `<CVE>.batch.json`, 2 batch aggregate JSON + 2 batch markdown
  summaries, 4 XSS candidate JSON, 14 KB documents + updated
  `ai_data/knowledge/index.json`, 5 report `.md` files.
- `git diff --check`: OK (no whitespace errors anywhere).

## Code Changes

None. This stage is execution + validation only, exactly the
"if the existing code is sufficient" branch of the stage brief.

## Limitations

1. **`--skip-llm` payloads are thin** by design: reports/API render
   vulnerability title/description/severity as Unknown (no synthesis).
   This is the honest cost of LLM-optional research; the deterministic
   pipeline still yields references, provenance, KB grounding, and
   reports.
2. **CVE-2025-3102 had 0 fetched references** (WordPress trac /
   Wordfence did not serve the fetcher) — research proceeded on CVE
   metadata alone (existing degraded path). Resolution depends on
   third-party sites, out of scope.
3. **Batch ↔ KB input mismatch (documented, untouched):** the `batch`
   path persists `<CVE>.batch.json`, while `kb ingest` consumes
   `<CVE>.cli.json` (+ `.references.json`) from the single-CVE flow.
   R11 therefore used the single-CVE flow for the KB-feeding artifacts
   (the documented R5-era research→ingest pairing) and the batch flow
   for aggregate telemetry. Bridging the two is a new-integration
   decision, not an R11 fix.
4. **KB synthesis documents carry no `xss_types`/`contexts` metadata**,
   so the deterministic XSS rule cannot reach RESEARCH_CANDIDATE from
   the real data (only seeds carry those fields). INSUFFICIENT_EVIDENCE
   is therefore the honest ceiling for the real XSS CVE. A future
   stage could derive XSS-relevant metadata deterministically from NVD
   CWE/description tokens (no LLM needed).
5. **`content_hash` was never fabricated** but was also not populated
   by this run's fetch path — a provenance-strengthening opportunity
   for the reference-fetch pipeline.
6. **Reference noise:** GitHub discovery surfaced "daily-info-feed"
   aggregator issues (valid URLs, weak signal). The existing gate is
   invalidity-only; re-ranking to deprioritize aggregators is a
   deliberate policy change, out of scope.
7. **Two pre-existing data-coupled UI test expectations** now fail with
   the larger real dataset (hardcoded counts + strict anchor-order
   toggle assertion in untracked `tests/test_research_ui.py`). They
   pass on the pre-R11 data set (verified); not touched per scope.
8. **Asset correlation was empty** (zero Watch assets in the sandbox
   Mongo substitute) — assessment counts are 0 and Watch-relevance is
   "Unknown", which is correct but means bounty-relevance scoring was
   not exercised.

## Recommendation

- Keep the flow exactly as-is; the existing CLI + CLI pairing
  (research → kb ingest → xss research → report) is sufficient for a
  real-data research MVP.
- Next-highest-value follow-ups, in order (all future, none required
  here): (1) deterministic XSS/severity metadata derivation for KB
  synthesis docs; (2) content-hash wiring through the single-CVE fetch
  path; (3) a policy decision on aggregator-reference re-ranking;
  (4) deciding whether `batch` and `kb ingest` should be bridged (new
  integration).
- No provider changes are recommended. The deterministic pipeline
  produced usable intelligence without an LLM.

## Agent / Model

- Model: GLM (Z.ai), via the Cline coding agent
- Stage: R11
- Role: Research Intelligence MVP