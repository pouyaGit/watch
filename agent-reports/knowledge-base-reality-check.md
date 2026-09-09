# Knowledge Base Reality Check — Watch (Google VM, 2026-09-09)

Scope: inspection/report only. No features implemented, no refactors, no
production verification/live-validation changes, no live security testing,
no network requests to arbitrary targets. Only offline unit tests were run.
Do NOT Git commit (per task).

## TL;DR

- Three fully-implemented, well-tested **KB store implementations** exist
  (`KnowledgeStore`, `PatternStore`, `ArtifactStore`), but **all three are
  empty on this VM**: `ai_data/knowledge/`, `ai_data/patterns/` and
  `ai_data/artifacts/` do not exist.
- The only persisted research state on disk is **one CVE's research-track
  output**: `ai_data/research/CVE-2026-1557.cli.json` plus its Nuclei
  preparation triple (`generated/`, `results/`, `findings/`).
- The CVE/reference/Nuclei layers are therefore **pipeline + schema rich,
  data poor**: excellent deterministic contracts and tests, but only one
  CVE record, zero persisted reference documents, zero persisted KB
  documents, zero persisted patterns/artifacts, and an empty findings file.
- The XSS research chain (`XSSCase` → `XSSResearcher` →
  `XSSResearchContext` → `XSSLLMResearcher` → `XSSResearchLLMResult`) is
  **code-complete and tested but unfed**: `XSSResearcher` reads exclusively
  from `KnowledgeStore`, which is empty, so every retrieval currently
  returns zero documents.
- There is **no read/search HTTP API, no web UI, and no full-text/semantic
  search** for any KB layer. The only human/CLI surfaces are
  `python -m ai.research_cli` (research execution, not KB search) and direct
  Python use of the store classes.

## 1. Current KB components and exact file paths

### 1a. Core knowledge stores (`ai/knowledge/`)

| Component | Path | Default root |
|---|---|---|
| `KnowledgeStore` (SHA-256 content-addressed JSON docs, `kb-<16hex>` short IDs, `index.json`, atomic writes, fail-closed integrity checks, metadata-only exact-match retrieval) | `ai/knowledge/store.py` | `ai_data/knowledge` (**absent on disk**) |
| `PatternStore` (VulnerabilityPattern/AttackPattern, `semantic_key` + `idempotency_key`, `vp-`/`ap-` aliases, lifecycle ACTIVE→SUPERSEDED→RETIRED) | `ai/knowledge/pattern_store.py` | `ai_data/patterns` (**absent on disk**) |
| `ArtifactStore` (immutable VALID-only artifacts: `nuclei_template`, `xss_payload`, `http_request_spec`; `art-` IDs bound to one TestPlan) | `ai/knowledge/artifact_store.py` | `ai_data/artifacts` (**absent on disk**) |
| Package init | `ai/knowledge/__init__.py` | — |

### 1b. Schemas / models (`ai/schemas/`)

| Schema | Path | Notes |
|---|---|---|
| `KnowledgeDocument`, `KnowledgeProvenance`, `KnowledgeSourceClaims`, `KnowledgeAggregate`, `KnowledgeAttributedValue`, `KnowledgeConfidenceAttribution` | `ai/schemas/knowledge.py` | v1→v2 migration, provenance-first, no global verdict |
| `ResearchResult` (+ `stringify_*` normalizers) | `ai/schemas/research.py` | LLM-output boundary validators |
| `ResearchDocument`, `AffectedVersion` (NVD-side CVE record) | `ai/schemas/source.py` | input to `SecurityResearcher` |
| `ReferenceDocument`, `ReferenceContext` | `ai/schemas/reference.py` | fetched text vs. ranked CVE-specific slice |
| `DiscoveredSource`, `DiscoveryResult` | `ai/schemas/discovery.py` | discovery-only (URL + priority + confidence, no content) |
| `DetectionSpec` | `ai/schemas/detection.py` | parsed template/detection features |
| `NucleiDecision` | `ai/schemas/nuclei.py` | GO/NO-GO + reason + confidence |
| `NucleiFinding` (NON-AUTHORITATIVE, P1) | `ai/schemas/finding.py` | history/research only; barred from 5J |
| `SourceDocument`, `ExtractedClaim`, `ExtractionResult`, `IngestionError` | `ai/schemas/ingestion.py` | LLM extraction → `KnowledgeSourceClaims` projection |
| `XSSCase`, `XSSContext`, `XSSResearchContext`, `XSSAttributedSuggestion`, `XSSSuggestedPayload`, `XSSVerificationIdea`, `XSSContextObservation`, `XSSResearchLLMResult` | `ai/schemas/xss.py` | case ≠ finding; context is deterministic projection |
| `XSSFinding` (NON-AUTHORITATIVE, P1) | `ai/schemas/xss_finding.py` | needs verifier attempt; 5J `SealedFinding` is authoritative |
| `VerificationMode/AttemptStatus/ReflectionLocation/...` + attempt/finding linkage | `ai/schemas/xss_verification.py` (~840 lines) | verifier-owned, never LLM-controlled |

### 1c. Research / ingestion / correlation pipeline

| Component | Path |
|---|---|
| Research CLI (check/research/batch/validate-live) | `ai/research_cli.py` |
| `SecurityResearcher` (NVD + reference contexts + discovered sources → LLM → `ResearchResult`) | `ai/researcher/researcher.py` |
| `KnowledgeIngestionAgent` (prompt → LLM → `ExtractionResult` → grounding/payload-safety gates → quarantine MODEL_INFERENCE → `KnowledgeStore.ingest`) | `ai/ingestion/agent.py` |
| Grounding helpers (`value_grounded`, `claim_values_grounded`, `contains_forbidden`) | `ai/ingestion/grounding.py` (imported; not re-read in full) |
| `XSSResearcher` (deterministic `XSSCase` → `KnowledgeStore.retrieve` → `XSSResearchContext`) | `ai/researcher/xss_researcher.py` |
| `XSSLLMResearcher` (attribution cross-validation; `knowledge` items need `knowledge_ids`+`source_ids`, `model_generated` items must have empty attribution) | `ai/researcher/xss_llm_researcher.py` |
| `XSSOrchestrator` (`analyze` → updated case + context + LLM result + pre-confirmation stage; never CONFIRMED/NOT_VULNERABLE; produces NO `XSSFinding`) | `ai/researcher/xss_orchestrator.py` |
| Batch runner (`run_cve_batch`, per-CVE results + aggregate JSON + markdown report) | `ai/researcher/cve_batch.py` |
| Per-batch in-memory reference cache (`BatchReferenceCache`, success-only, fragment + `utm_*`/`gclid`/`fbclid` key canonicalization) | `ai/researcher/reference_cache.py` |
| Reference quality gate (`gate_reference_contexts`) | `ai/researcher/reference_quality.py` |
| Context builder (`build_research_contexts`: fetched dicts → `ReferenceRanker` → raw context dicts) | `ai/researcher/research_context.py` |
| CVE collector (NVD REST, retry/backoff) | `ai/collectors/cve.py` (~698 lines) |
| Reference discovery / fetch / ranking | `ai/collectors/discovery.py`, `ai/collectors/discovery_fetch.py`, `ai/collectors/reference.py` (`ReferenceCollector`: httpx, HTML→text, SHA-256 `content_hash`, `classify_source`), `ai/collectors/reference_ranker.py` |
| Nuclei chain: template parser, decision engine, generator, semantic validator, pipeline, dry-run runner | `ai/collectors/nuclei_template.py`, `ai/correlator/nuclei_decision.py`, `ai/correlator/nuclei_generator.py`, `ai/correlator/nuclei_validator.py`, `ai/researcher/nuclei_pipeline.py` (~715 lines), `ai/researcher/nuclei_runner.py` |
| Candidates/assessment/target selection/scope | `ai/correlator/candidates.py`, `ai/correlator/assessment.py`, `ai/correlator/watch_targets.py`, `ai/correlator/scope_policy.py` |
| Authoritative evidence (5H) + findings (5J) — NOT KB, but Reports-relevant | `ai/evidence/store.py`, `ai/evidence/blob_store.py`, `ai/evidence/builder.py`, `ai/evidence/handoff.py`, `ai/evidence/index.py`; `ai/finding/materializer.py`, `ai/finding/authority.py`, `ai/finding/eligibility.py`, `ai/finding/sealed.py` |
| Config / persistence reads | `ai/config.py`, `ai/persistence/watch_reads.py` |

### 1d. API / UI surfaces checked — none expose the KB

- `api.py`, `app.py`, `app_local.py`, `backend/` (`dashboard.py`, `routers/pages.py|programs.py|runs.py|system.py|tasks.py`), `web/templates|static`: no routes referencing `KnowledgeStore`, `ResearchResult`, `ReferenceDocument`, `NucleiDecision`, `NucleiFinding`, or `research_cli` (verified by grep).
- The ONLY KB-adjacent executable surfaces are the Python classes themselves and `python -m ai.research_cli` (research execution, dry-run Nuclei prep — not a KB reader).

## 2. Current persisted data locations and formats

| Location | Format | State on this VM |
|---|---|---|
| `ai_data/knowledge/` (`documents/<sha256>.json` + `index.json`) | `KnowledgeDocument` JSON (schema_version 2, `content_hash`, `knowledge_id`, `provenance[]`, `aggregate{}`) | **DOES NOT EXIST** — zero KB documents persisted |
| `ai_data/patterns/` (`records/<idempotency_key>.json` + `index.json`) | Pattern envelope `{pattern, pattern_type, schema_version}` | **DOES NOT EXIST** — zero patterns persisted |
| `ai_data/artifacts/` (`records/<content_hash>.json` + `index.json`) | Artifact envelope `{reference, content_b64, content_hash, schema_version}` | **DOES NOT EXIST** — zero artifacts persisted |
| `ai_data/research/CVE-2026-1557.cli.json` | `research_version: "cli-1"` envelope (see §3) | Present (5.5 KB, generated 2026-09-06T11:47:56Z). The ONLY research record on disk |
| `ai_data/nuclei/generated/CVE-2026-1557.yaml` | Nuclei template YAML (id/info/http raw+matchers) | Present (25 lines) |
| `ai_data/nuclei/results/CVE-2026-1557.json` | Pipeline result JSON (decision + targets + dry-run run_results + embedded non-authoritative findings + `nuclei_validation_output` string) | Present (~198 lines) |
| `ai_data/nuclei/findings/CVE-2026-1557.json` | JSON list of `NucleiFinding` | Present but content is `[]` (empty) |
| Reference document persistence | — | **NONE**: fetched reference bodies live only in memory during a run (`ReferenceCollector` → `fetch_discovered_sources` → `build_research_contexts` → `ReferenceRanker` → per-CVE `ReferenceContext` → LLM prompt). The per-batch `BatchReferenceCache` is dropped after `run_cve_batch`. Only counts survive (see §3/§4) |
| CVE database / mirror | — | **NONE**: `CVECollector` reads live NVD (`services.nvd.nist.gov/rest/json/cves/2.0`); Watch asset side reads live Mongo `watch.http` via `ai/collectors/http.py` + `ai/persistence/watch_reads.py`. No local CVE mirror |

`find ai_data -type f` on this VM returns exactly 4 files (the ones above).
No `index.json` exists anywhere outside `venv/`/`.git/`.

## 3. What information is currently stored for a CVE

Single example: `ai_data/research/CVE-2026-1557.cli.json` + its Nuclei triple.
Per-CVE stored fields:

- **Envelope** (`ai/research_cli.py::_research_single_cve`): `research_version: "cli-1"`, `generated_at`, `mode: "research-only"`, `authoritative: false`, `research_only: true`, `research_status` (`completed` | `completed_degraded`), `llm_status` (`ok` | `unavailable` | `skipped`), `llm_error`, `outage_bucket` + `outage_events` + `retry_attempted`/`retry_succeeded` (provider telemetry), `reference_quality: {checked, rejected}` (counts only), `provenance: {deterministic: ["nvd","reference"], llm, authoritative: false}`, `output_path`.
- **CVE identity block**: `cve.id` (CVE-2026-1557), `vendor: ["stuartbates"]`, `products: ["WP Responsive Images"]`, `cvss_score: 7.5`, `cvss_vector` (full CVSS:3.1 string). No CPE/CWE/affected-version structs persisted here (they exist transiently in `ResearchDocument` from NVD).
- **Correlation metadata**: `programs: ["dell","indeed"]`, `assets: [4 hostnames]`, `technologies: ["WordPress"]`, `assessment_count: 4`, `discovered_source_count: 5`, `fetched_source_count: 5`, `reference_context_count: 5`.
- **`ResearchResult`** (`research` key): `title`, `summary`, `vulnerability_type` ("Path Traversal (CWE-22)"), `severity` ("High (CVSS 7.5)"), `cve_ids`, `affected_products` (plain strings, normalizer-enforced), `affected_versions` (["<=1.0"]), `attack_requirements[]`, `root_cause`, `impact[]`, `public_exploit: true`, `actively_exploited: null`, `bug_bounty_relevance: 2`, `detection_ideas[]`, `nuclei_candidate: true` + `nuclei_reason` (references merged upstream template PR #15592), `references[]` (6 URLs, not fetched bodies), `evidence[]` (11 strings prefixed `CONFIRMED:`/`SECONDARY:`/`NOT OBSERVED:`/`UNKNOWN:`).
- **Nuclei prep** (`ai_data/nuclei/results/CVE-2026-1557.json`): `decision: "GOOD_CANDIDATE"` + `decision_confidence: 0.95`, `generated/semantic_valid/nuclei_valid: true`, `template_path`, `candidate_count/target_count: 4`, per-target `{target, program, technology, product_match: "ecosystem", presence_status, version_status: "UNKNOWN", scope_status: EXCLUDE|DRY_RUN_ONLY, scope_reason}`, per-target `run_results[]` with `status: EXCLUDED|DRY_RUN_ONLY` and unexecuted `nuclei -t ... -u ...` command arrays, embedded `findings[]` (all `matched: false`, evidence = scope-gate message), `nuclei_validation_output` (raw CLI string incl. outdated-templates warning), `findings_path`.
- **NOT stored per CVE**: NVD raw JSON, CPE/CWE lists, affected-version structs, reference bodies/chunks, discovery queries/priorities, ranker scores, LLM prompt/response, DetectionSpec JSON, NucleiDecision JSON as separate record, attempt-level evidence beyond the validation-output string.

## 4. What information is currently stored for references

- **Persisted to disk: effectively nothing beyond URL strings and counts.**
  - `research.references[]`: 6 URL strings inside the CLI JSON (wordpress trac ×3, wordfence, nuclei-templates PR, crowdsec hub PR).
  - `metadata.{discovered,fetched,reference_context}_count`: 5/5/5.
  - `reference_quality: {checked: 1, rejected: 0-or-1}`: counts only, no URLs/contents/CVE IDs.
- **Transient (in-memory only) reference model** — rich but discarded after the run:
  - `DiscoveredSource` (`ai/schemas/discovery.py`): `url`, `source_type`, `title?`, `query?`, `priority`, `confidence`, `tags[]`.
  - `ReferenceDocument` (`ai/schemas/reference.py`): `url` (post-redirect), `source_type` (`github`/`vendor`/`bug_bounty`/`security_research`/`other` via `classify_source`), `title?`, `content` (extracted text, ≤2 MB), `status_code?`, `content_hash` (SHA-256 of raw bytes), `tags[]`. Fetch failures / non-text / empty → `None` (hard miss, never cached).
  - `ReferenceContext` (`ai/schemas/reference.py`): `source_url`, `source_type`, `title?`, `exact_record?`, `context_chunks[]` — the CVE-specific ranked slice actually sent to the LLM.
  - Discovered-document dicts passed to the LLM prompt also carry `priority`, `tags`, and full `content` — but are not written to disk.
- **Cache**: `BatchReferenceCache` shares successful `ReferenceDocument`s between CVEs *within one batch run only*; `state()` exposes `{store, hits}` for tests. No cross-batch or on-disk cache exists.
- Consequence: re-running research re-fetches all references; auditing *what the model saw* is impossible from disk (no prompt/response/content archive).

## 5. What information is currently stored for Nuclei templates/findings

- **Template** (`ai_data/nuclei/generated/CVE-2026-1557.yaml`, 25 lines): `id: CVE-2026-1557`; `info: {name, author: watch-ai, severity: high, description (path-traversal summary + CVSS), tags: [cve,generated,watch-ai]}`; `http: [{raw: ["GET /wp-content/plugins/wp-responsive-images/image_handler.php?src=/wp-config.php ... Host: {{Hostname}}"], matchers: [{type: dsl, dsl: [status_code==200 || status_code==403, contains_all(body,"DB_NAME","DB_PASSWORD")], condition: and}]}]`. Note: generated request uses `src=/wp-config.php` (no traversal prefix) — detection relies on the matcher pair, not on a traversal payload.
- **Result record** (`ai_data/nuclei/results/CVE-2026-1557.json`): see §3. Key point: every target is `EXCLUDED`/`DRY_RUN_ONLY`; **no command was executed** (`error: "scope_status is not READY_FOR_SCAN; command was not executed."` on all four).
- **Findings file** (`ai_data/nuclei/findings/CVE-2026-1557.json`): `[]`. The only finding-like rows live embedded in the results file, all `matched: false`.
- **Schema-level finding model** (`NucleiFinding`, `ai/schemas/finding.py`): `cve_id`, `target`, `program`, `template_id`, `severity` (caller-supplied), `matched` (stdout-derived), `scope_status`, `presence_status`, `version_status`, `matched_at`, `evidence[]`, `raw_output` (unbounded), `error?`. Explicitly NON-AUTHORITATIVE: barred from 5J materialization/persistence/notification by design.
- **Decision model** (`NucleiDecision`, `ai/schemas/nuclei.py`): `cve_id`, `decision`, `confidence`, `reason`, `protocol[]`, `http_detectable`, `version_required`, `exploit_evidence: unknown|confirmed|not_confirmed`, `detection_requirements[]`. No `NucleiDecision` JSON is persisted as its own record — only the flattened `decision`/`decision_confidence` in the results file.
- **Intermediate models never persisted**: `DetectionSpec` (method/path/params/matchers/version/auth/destructive/`reliable_signature`/confidence/evidence/missing_requirements), parsed-template specs, generator/validator outputs beyond booleans.

## 6. Existing read/search/query interfaces

| Interface | Type | Capabilities | Limits |
|---|---|---|---|
| `KnowledgeStore.retrieve(technologies?, xss_types?, contexts?, wafs?, techniques?, source_types?, evidence_quality?, tags?)` (`ai/knowledge/store.py`) | Python API | Deterministic metadata-only exact-match (normalized) filtering; stable `knowledge_id` ordering; `get_by_hash`/`get_by_id` with collision/integrity fail-closed | NO full-text, NO semantic/embedding, NO ranking/scoring, NO pagination, NO CLI wrapper, NO HTTP endpoint |
| `KnowledgeStore.get_by_hash/get_by_id` | Python API | Single-document fetch with hash/ID/filename/aggregate cross-validation | Same as above |
| `PatternStore.get/get_by_idempotency_key/get_by_semantic_key/list(pattern_type?,status?,semantic_key?)/transition` (`ai/knowledge/pattern_store.py`) | Python API | Exact-key + lifecycle-filtered reads, deterministic ordering | NO text search, NO target/scope/severity filtering (by design), NO CLI/HTTP |
| `ArtifactStore.get/get_by_content_hash/exists/list(artifact_type?)` (`ai/knowledge/artifact_store.py`) | Python API | Exact-ID reads, type-filtered list | NO search, NO CLI/HTTP |
| `XSSResearcher.research(case)` (`ai/researcher/xss_researcher.py`) | Python API | `XSSCase` fields → `KnowledgeStore.retrieve` (technology/xss_type/context.type/waf) → `XSSResearchContext` with deduped attributed values + full document blobs | Retrieval key is narrow (4 fields); no keyword/payload-text query |
| `XSSLLMResearcher`, `XSSOrchestrator.analyze` | Python API | Attribution-validated LLM suggestions; audit object (`retrieval_call_count`, `retrieved_knowledge_ids`, knowledge-vs-model flags) | Pre-confirmation only; emits no findings |
| `python -m ai.research_cli check\|research\|batch\|validate-live` (`ai/research_cli.py`) | CLI | Executes research + dry-run Nuclei prep; writes `ai_data/research/*.cli.json` + `ai_data/nuclei/*` | NOT a reader: no `search`/`show`/`list`/`export` subcommand; `research --cve` re-runs the whole pipeline (needs NVD + Mongo + references + LLM unless `--skip-llm`) |
| Backend/UI (`api.py`, `backend/routers/*`, `web/*`) | HTTP/HTML | Programs/runs/tasks dashboards | ZERO KB/research/Nuclei/XSS routes |
| Full-text / semantic search, exports (CSV/PDF), report generator | — | DOES NOT EXIST | — |

## 7. What is reusable for a future Reports layer

All reusable *without* modifying production verification code:

1. **Per-CVE research envelope** (`ai_data/research/*.cli.json` + `ai/schemas/research.py`): already separates CVE identity, correlation metadata, LLM analysis, evidence strings, references, and provider telemetry (`llm_status`, `outage_bucket/events`, `reference_quality`). A report renderer can consume this JSON directly.
2. **Evidence-string convention** (`CONFIRMED:`/`SECONDARY:`/`NOT OBSERVED:`/`UNKNOWN:` prefixes, enforced in the researcher prompt and `stringify_evidence`): gives Reports a ready-made confidence vocabulary.
3. **Nuclei prep triple** (generated YAML + results JSON + findings JSON): decision, scope gating per target, unexecuted commands, and validation output are all machine-readable for a "detection readiness" report section.
4. **Reference URL lists + counts** (`references[]`, `metadata.*_count`, `reference_quality`): enough for a sources-cited section today; full bodies would need §9.1 first.
5. **Batch aggregates** (`ai/researcher/cve_batch.py` outputs aggregate JSON + markdown summary under `ai_data/research/` + `agent-reports/`): the existing multi-CVE roll-up pattern to extend.
6. **Deterministic store primitives** (atomic writes, sorted keys, content hashes, stable IDs): the right foundation for content-addressed report artifacts (dedupe, audit trail).
7. **Authoritative evidence/finding seam** (`ai/evidence/*`, `ai/finding/materializer.py`, `SealedFinding`): Reports must clearly label research-track rows (P1 `NucleiFinding`/`XSSFinding`) as non-authoritative vs. 5J-sealed findings — the boundary code already exists and must be respected, not duplicated.

## 8. What is reusable for a future XSS Agent

1. **Case model** (`XSSCase` + `XSSContext`, `ai/schemas/xss.py`): target/endpoint/method/parameter/location/type/context/framework/tech/WAF/evidence/status/confidence + `retrieved_knowledge_ids` — a solid investigation-hypothesis object distinct from a finding.
2. **Deterministic retrieval** (`XSSResearcher`, `ai/researcher/xss_researcher.py`): side-effect-free, no-network, no-LLM, attribution-preserving projection (`XSSResearchContext` with per-value `source_ids`, stable ordering). The "retrieval before reasoning" boundary the project mandates is already implemented.
3. **Attribution-validated LLM layer** (`XSSLLMResearcher` + `XSSResearchLLMResult`): `knowledge` vs `model_generated` origins enforced by cross-validation; status suggestions restricted to pre-confirmation states. Directly reusable as the agent's reasoning step.
4. **Orchestrator + audit** (`XSSOrchestrator.analyze` → `XSSAnalysisResult` + `XSSAnalysisAudit`): retrieval/LLM call counts, knowledge-vs-model flags, notes — the observability hook a future agent loop needs.
5. **Ingestion pipeline** (`KnowledgeIngestionAgent` + `ai/schemas/ingestion.py` + `ai/ingestion/grounding.py`): grounded, payload-safe, quarantining (MODEL_INFERENCE never trusted) path for growing the XSS knowledge corpus from write-ups/advisories.
6. **Verification + finding models** (`ai/schemas/xss_verification.py`, `ai/schemas/xss_finding.py`, `watch_xss_verify.py`, `ai/test_watch_xss_verify.py`): attempt/finding linkage (`attempt_id`), `confirmation_state`/`oracle_channels` (E1/E2/E3), stored-round audit (`round_id`/`read_url`) — the agent's eventual output contracts already exist.
7. **Artifact/TestPlan machinery** (`ArtifactStore`, `ai/schemas/artifact.py`, `ai/researcher/artifact_validator.py`, `test_plan_builder.py`, `test_plan_readiness.py`): the validated-bytes + TestPlan binding path an XSS payload agent would need before any execution.

## 9. Missing pieces that block useful Reports / XSS Agent functionality

1. **Empty knowledge corpus**: `KnowledgeStore`/`PatternStore`/`ArtifactStore` have zero records on disk. Consequence: `XSSResearcher` always retrieves nothing; any Report "related research" section and any XSS Agent retrieval step are vacuous. (Highest-impact blocker.)
2. **Reference bodies are not persisted**: full fetched text, `exact_record`, and `context_chunks` die with the process. Reports cannot show "what the model saw"; reruns re-fetch; audits can't reconstruct provenance. The `content_hash` exists but no content archive backs it.
3. **Single-CVE coverage**: only CVE-2026-1557 exists on disk. No batch history, no trend/comparison data, no negative examples (NO-GO decisions) to report on.
4. **No KB read/search surface**: no CLI `kb search/show/list`, no HTTP API, no UI; `KnowledgeStore.retrieve` is metadata-exact-match only (no full-text over `content`/`summary`, no semantic search, no ranking, no pagination). Anything beyond "list by tag" requires new code.
5. **No report renderer**: no Markdown/PDF/HTML generator, no report schema, no `ai_data/reports/` convention, no linkage between research JSON → report artifact (hash/ID), no Jean/5J-aware labeling helper.
6. **XSS retrieval keys are narrow**: `XSSResearcher._retrieve` filters only on technology/xss_type/context.type/waf. No keyword, payload-text, framework, or CWE filtering — even once the corpus is seeded, recall will be poor for real cases.
7. **Ingestion is code-complete but unwired to production data flow**: `KnowledgeIngestionAgent` requires an injected `LLMProvider` + caller-supplied `SourceDocument`; nothing in `research_cli` or the batch path calls it, and no seed corpus (PortSwigger, CWE, existing write-ups) has been ingested.
8. **No CVE mirror / research index**: each `research --cve` hits live NVD + live reference URLs + Mongo; there is no local CVE table, no research-record index across CVEs, and no idempotent "already researched" short-circuit a Reports layer could page over.
9. **XSS Agent loop pieces absent**: no case builder wired to crawl/param-discovery output (only `test_xss_case_builder` fixtures), no planner/scheduler, no executor binding for XSS payloads through the authorized 5-series gates, no finding emitter from `XSSAnalysisResult` (orchestrator explicitly emits none).

## 10. Recommended NEXT implementation stage (smallest useful change)

**Stage R1 — "Seed + read back": persist one reference archive per CVE and expose a read-only KB search CLI. Nothing else.**

Concrete, minimal scope:

1. Extend `ai/research_cli.py` with a **read-only** `kb` subcommand group (`search`, `show`, `list`) that wraps the existing `KnowledgeStore.retrieve`/`get_by_id`/`list`-equivalent with JSON/stdout output. No new search semantics (exact-match filters only); no HTTP; no UI.
2. In the single-CVE research path, **persist the already-built reference material** alongside the existing CLI JSON: write `ai_data/research/<CVE>.references.json` containing the `ReferenceContext` list (`source_url`, `source_type`, `title`, `exact_record`, `context_chunks`) plus `content_hash` per source. No schema changes to existing files; no re-fetch logic changes; no ingestion changes.
3. Seed the empty `KnowledgeStore` with **2–5 hand-curated XSS documents** (e.g. PortSwigger XSS cheat-sheet excerpts already covered by `test_knowledge_ingestion` fixtures) via the existing `KnowledgeIngestionAgent` + mocked/unit-tested path — proving `XSSResearcher` returns non-empty `XSSResearchContext` end-to-end.
4. Acceptance: `python -m ai.research_cli kb search --xss-type reflected` returns the seeded docs; `ai_data/research/CVE-2026-1557.references.json` exists; existing suites (`ai.test_knowledge_store`, `ai.test_xss_researcher`, `ai.test_xss_llm_researcher`, `ai.test_openrouter`) still pass; `git diff --check` clean; no production verification/live-validation files touched.

Why this is the right smallest step: it converts the KB from write-only/test-only into something a human can inspect (unblocking every future Report), preserves the full audit trail the project demands (reference bodies on disk), and feeds the XSS Agent's retrieval step with real data — all without new architecture, new network behavior, or touching the controlled-validation boundary. Everything else in §9 (ranking, full-text search, renderer, agent loop) builds on top of R1.

---

## Appendix A — Exact tests inspected / run

All runs offline (`unittest`, no network to arbitrary targets, no live scanning).
`ai/test_research_cli.py` emits a localhost-Mongo `MongoClient` resource warning in one test but still passes.

| Test module | Tests | Result |
|---|---|---|
| `ai.test_knowledge_store` | 15 | OK |
| `ai.test_xss_researcher` | 12 | OK |
| `ai.test_xss_llm_researcher` | 36 | OK |
| `ai.test_openrouter` | 26 | OK (combined required-4 run: 89 tests, OK) |
| `ai.test_knowledge_ingestion` | 36 | OK |
| `ai.test_xss_case_builder` | (in batch below) | OK |
| `ai.test_research_cli` | (in batch below) | OK |
| `ai.test_researcher` | (in batch below) | OK (combined second run: 89 tests, OK) |

Commands run (from `/opt/watch`):

```bash
python3 -m unittest ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter
# Ran 89 tests — OK

python3 -m unittest ai.test_knowledge_ingestion ai.test_xss_case_builder ai.test_research_cli ai.test_researcher
# Ran 89 tests — OK (one MongoClient ResourceWarning from test_research_cli, non-failing)
```

Inspected but not executed (would require NVD/Mongo/LLM network): `ai.test_real_research`, `ai.test_cve_batch`, `ai.test_single_cve_quality_parity`, `ai.test_batch_reference_quality_parity`, live-validation suites.

## Appendix B — Files inspected

Schemas: `ai/schemas/knowledge.py`, `research.py`, `source.py`, `reference.py`, `discovery.py`, `detection.py`, `nuclei.py`, `finding.py`, `ingestion.py`, `xss.py`, `xss_finding.py`, `xss_verification.py` (first 60 lines).
Stores: `ai/knowledge/store.py` (full, 844 lines), `pattern_store.py`, `artifact_store.py`.
Pipeline: `ai/research_cli.py` (full, 614 lines), `ai/researcher/researcher.py`, `xss_researcher.py` (full), `xss_llm_researcher.py` (first 100 lines), `xss_orchestrator.py` (first 60 lines), `research_context.py`, `reference_cache.py`, `nuclei_pipeline.py` (first 80 lines), `ai/ingestion/agent.py` (full, 486 lines).
Collectors/correlator: `ai/collectors/reference.py`, `cve.py` (first 80 lines), `nuclei_template.py` (first 80 lines), `ai/correlator/nuclei_decision.py` (first 60 lines).
Data: `ai_data/research/CVE-2026-1557.cli.json` (full), `ai_data/nuclei/generated/CVE-2026-1557.yaml` (full), `ai_data/nuclei/results/CVE-2026-1557.json` (full), `ai_data/nuclei/findings/CVE-2026-1557.json` (full); directory listings of `ai_data/`, `ai/knowledge/`, `ai/schemas/`, `ai/researcher/`, `ai/collectors/`, `ai/correlator/`, `ai/llm/`, `ai/evidence/`, `ai/finding/`, `ai/ingestion/`, `ai/persistence/`, `backend/`, `backend/routers/`, `web/`, `agent-reports/`; `git status`, `git log --oneline -5`, `git diff --check`; grep sweeps for `KnowledgeStore(`, `ai_data/knowledge|patterns|artifacts`, KB references in `api.py`/`app.py`/`backend/`/`web/`.

## Appendix C — Files modified

**None, except this report.** `git status --short` before writing showed pre-existing workspace changes unrelated to this task (modified `run-heavy-guarded.sh`; untracked `agent-reports/phase-5k-*`, `phase-sync-google-checkpoint.md`, `ai/lab/*`, `crawl/output/*`, `dns-bruteforce/*` lab artifacts). This task created only `agent-reports/knowledge-base-reality-check.md` and did not commit.
