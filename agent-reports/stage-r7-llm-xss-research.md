# Stage R7 — LLM-Assisted XSS Research Intelligence

## Summary

Added an LLM-assisted research layer on top of the deterministic XSS
agent (R3). The deterministic candidate remains the sole authority for
status, confidence, evidence references and research classification.
The LLM is only a research/synthesis assistant that turns a persisted
candidate + its matched KB evidence into a structured, bounded research
explanation persisted separately under
`ai_data/research/xss/llm/<candidate_id>.json`. Reuses the existing
OpenRouter integration and the R1 existing `_parse_llm_json` helper.
No execution, no network beyond the provider, no findings, no alerts,
no scope changes.

## Exact files changed

- `ai/schemas/xss.py` — append-only: `XSSLLMResearchEvidence`,
  `XSSLLMResearchAssistantResult` (the existing `XSSResearchCandidate`
  and `XSSResearchLLMResult` schemas untouched).
- `ai/researcher/xss_llm_assistant.py` — NEW: bounded prompt builder,
  authority/attribution/URL validation, provider call, atomic
  persistence under `ai_data/research/xss/llm/`.
- `ai/research_cli.py` — append-only: `xss llm-research <candidate_id>`
  subparser + `run_xss_llm_research` + dispatch; loads dotenv before
  provider construction (same convention as `run_check`).
- `ai/test_xss_llm_assistant.py` — NEW: 20 focused tests, mock provider.
- This report: `agent-reports/stage-r7-llm-xss-research.md`.

No other files modified. `git diff --check` clean.

## Existing LLM functionality reused

- `ai/llm/base.py` — `LLMProvider` / `LLMResult` interface (injected;
  the assistant holds no provider implementation).
- `ai/llm/openrouter.py` — `OpenRouterProvider` (env-based
  `OPENROUTER_API_KEY` / `OPENROUTER_MODEL` / `OPENROUTER_MAX_TOKENS`),
  constructed only by the CLI; never auto-invoked by `xss research`.
- `ai/researcher/xss_llm_researcher.py::_parse_llm_json` — reused for
  fence-stripping / first-object JSON extraction (no duplication).
- `ai/researcher/xss_agent.py` — `load_candidate` / `persist_candidate`
  conventions and the deterministic `XSSResearchCandidate` schema.
- `ai/knowledge/store.py::get_by_id` — read-only KB evidence loading.

The existing `XSSLLMResearcher` (over `XSSCase`/`XSSResearchContext`)
was NOT duplicated or modified; the new assistant is a distinct,
downstream layer over the deterministic candidate.

## Final LLM trust boundary

```
KnowledgeStore
   ↓ (deterministic)
XSS Agent → candidate + evidence   (authoritative)
   ↓
LLM Research Assistant (this stage)  → structured explanation
   ↓
ai_data/research/xss/llm/<candidate_id>.json
   ↓
read-only dashboard / report
```

The LLM may produce only structured research fields: `explanation`,
`likely_attack_surface`, `relevant_context`, `supporting_reasoning`,
`missing_evidence`, `suggested_test_idea`, `references_used`,
`evidence`. It MUST NOT execute anything, generate/send HTTP requests,
run Nuclei, invoke subprocesses, access Mongo, create findings or
alerts, modify scope, change status/confidence, invent evidence/URLs,
or claim verified exploitation. Every field is model reasoning except
EVIDENCE items and `references_used` (sourced from supplied KB).

## Schema / output structure

```python
class XSSLLMResearchEvidence(BaseModel):
    kind: Literal["EVIDENCE", "INFERENCE", "UNKNOWN"]
    text: str
    knowledge_ids: list[str] = []

class XSSLLMResearchAssistantResult(BaseModel):
    candidate_id: str
    status: str
    confidence: float            # ge=0 le=1
    content_hash: str            # sha256 of the deterministic candidate
    explanation: str
    likely_attack_surface: str | None = None
    relevant_context: str | None = None
    supporting_reasoning: list[str] = []
    missing_evidence: list[str] = []
    suggested_test_idea: str | None = None
    references_used: list[str] = []
    evidence: list[XSSLLMResearchEvidence] = []
    model: str | None = None
    raw_response_id: str | None = None
```

`content_hash` is the deterministic SHA-256 of the deterministic
candidate payload (excluding the `content_hash` field itself), so a
re-read can prove the research was generated against a specific
candidate version. `model` / `raw_response_id` are always overwritten
from the provider result (never from model self-reporting).

## Evidence / inference / unknown rules

- EVIDENCE: a fact directly present in the supplied KB evidence; MUST
  carry `knowledge_ids` ⊆ the supplied KB ids.
- INFERENCE: model interpretation; MUST have empty `knowledge_ids`.
- UNKNOWN: not established from supplied evidence; MUST have empty
  `knowledge_ids`.
- The prompt instructs the phrasing "The supplied evidence indicates X.
  Y is not established by the supplied evidence." The validator rejects
  any EVIDENCE without attribution, any INFERENCE/UNKNOWN carrying
  attribution, any `references_used` outside the supplied KB ids, and
  any http(s) URL not matching a supplied evidence `source_url`.

## Candidate status authority

`build_research_assistant_result` enforces: `candidate_id` match;
`status` exactly equal to the deterministic status (REJECTED cannot
become candidate, INSUFFICIENT_EVIDENCE cannot upgrade, any downgrade
also rejected); `confidence` within 1e-9 of the deterministic value;
`content_hash` match. The deterministic candidate JSON is never
overwritten.

## Persistence behavior

`persist_research` writes atomically (tmp + replace) to
`ai_data/research/xss/llm/<candidate_id>.json` — one record per
candidate, so repeated generation with the same candidate + same model
output converges (byte-identical) with no duplicates and no corruption.
The dashboard XSS glob (`xss-*.json` in the parent dir) does not reach
the `llm/` subdirectory, so LLM research is never surfaced as a
candidate.

## Input minimization

The prompt contains only: the deterministic candidate projection
(id/status/query/type/context/confidence/vulnerability pattern/sinks/
sources/preconditions/unknowns/source_evidence/references), and the
matched KB documents (id/title/source_url/source_type/evidence_quality/
confidence/xss_types/contexts/technologies/summary/bounded content).
Bounds are deterministic: ≤10 evidence docs, ≤1200 content chars/doc,
≤10 source_evidence rows, ≤400/500/300-char field caps, total prompt
capped at 20000 chars. No API keys, Mongo credentials, env values,
filesystem paths beyond the candidate id, or unrelated corpus are sent
(tested).

## CLI behavior

```
venv/bin/python -m ai.research_cli xss llm-research <candidate_id> [--output PATH]
```

1. `load_candidate` (missing/malformed id → `ERROR` + exit 1, no LLM
   call); 2. load referenced KB evidence via `get_by_id`; 3. build
   bounded prompt; 4. construct `OpenRouterProvider` from env (dotenv
   loaded; missing config → `ERROR` + exit 1); 5. call provider;
   6. validate (authority + attribution + URLs + schema); 7. persist
   under `llm/`; 8. print `LLM-RESEARCH: <id> (<status>)` + `SAVED`.
   Never automatic from `xss research`.

## Failure behavior

- Provider failure: caught as `ERROR: <type>: <msg>` on stderr, exit 1,
  nothing persisted.
- Malformed model output: rejected via `_parse_llm_json` /
  `ValidationError` → `XSSLLMResearchError`, nothing persisted; never
  coerced into valid evidence.
- Missing candidate: `XSSAgentError` → `ERROR`, exit 1, no LLM call.
- Missing KB evidence: fail-closed — `XSSLLMResearchError`("no KB
  evidence available… failing closed"), no LLM call, no persisted file.
- No fallback/fabricated evidence anywhere.

## Real-data verification

Isolated copy of the real CVE-2026-1557 artifact → temp store → real
candidate `xss-488f639165085224` (INSUFFICIENT_EVIDENCE, 0.35) → mock
provider research → persisted under `llm/`. Result kept status
`INSUFFICIENT_EVIDENCE` and confidence 0.35; evidence kinds
`[EVIDENCE(1), UNKNOWN(0)]`; prompt length 6060 chars; deterministic
candidate file byte-identical after the run. All 3 real persisted
candidate hashes unchanged (599c14f3…, 343b35f3…, 59334faf…).

## Tests and exact counts

New `ai.test_xss_llm_assistant` — **20 tests, all pass** (mock provider,
no real LLM/network): deterministic authority; REJECTED cannot become
candidate (fail-closed); INSUFFICIENT cannot upgrade; status downgrade
rejected; confidence override rejected; evidence/inference/unknown
separation; unknown knowledge_id in EVIDENCE rejected; arbitrary URL
rejected; references outside supplied set rejected; bounded prompt +
secret redaction (no OPENROUTER_API_KEY / sk-or- / WATCH_MONGO_URI /
api_key in prompt); malformed JSON rejected; provider failure
(no partial output); missing candidate (CLI, no LLM call); missing KB
evidence (no LLM call); persistence idempotency (byte-identical,
single record); deterministic candidate unchanged; schema round-trip;
CLI success path; CLI provider-failure exit 1; real-ai_data snapshot
guard.

Required + adjacent suites (all `OK`):

| Suite | Tests |
| --- | --- |
| ai.test_xss_researcher | 12 |
| ai.test_xss_agent | 21 |
| ai.test_xss_llm_researcher | 36 |
| ai.test_knowledge_store | 15 |
| ai.test_research_ingestion | 19 |
| ai.test_research_cli | 6 |
| ai.test_reports_renderer | 14 |
| ai.test_openrouter | 26 |
| ai.test_xss_llm_assistant (new) | 20 |
| ai.test_research_kb_xss_e2e (R6) | 6 |
| ai.test_knowledge_ingestion | 36 |
| **AI total** | **211** |

Backend/UI regression (schema shared by data helpers): `tests.test_
research_api` + `test_research_ui` + `test_routers_fixes` +
`test_dashboard_logic` + `test_page_render` + `test_ui_redesign` →
**126 tests, all pass**.

`git diff --check` → clean.

## Security review

- No subprocess / no target execution: no subprocess/network/execution
  imports in the assistant (AST-verified); only `hashlib`, `json`,
  `re`, `pathlib`, `typing`, `pydantic`, `ai.llm.base` (interface),
  `ai.schemas.xss`, `ai.researcher.xss_llm_researcher` (parser helper).
- No HTTP generated/executed by the layer: the assistant calls only the
  injected `LLMProvider`; the CLI constructs the existing
  `OpenRouterProvider` (env-config), the allowed provider path.
- No Nuclei, no Mongo, no finding/alert path, no auth change, no scope
  change, no legacy `XssFindings` (AST + grep verified).
- No secret leakage: prompt/redaction tests assert no API keys, Mongo
  URI, or `api_key` material reaches the LLM; provider errors never
  echo keys.
- No arbitrary URL fabrication: any URL token in output must be a
  prefix of a supplied evidence `source_url` or the response is
  rejected.
- No evidence laundering: EVIDENCE/INFERENCE/UNKNOWN attribution rules
  enforced structurally; malformed output rejected, never coerced.
- Deterministic candidate remains authoritative: status/confidence/
  candidate_id/content_hash enforced; the candidate JSON is never
  written by the LLM layer (tested byte-identical).

## Remaining limitations

- The LLM research output is not yet surfaced on the dashboard/report
  (read-only wiring is a downstream UI concern; the file layout is
  ready and isolated from the candidate glob).
- Fail-closed on REJECTED/zero-evidence candidates: they cannot be
  LLM-researched because there is no KB evidence to reason over (by
  design).
- Language generation is inherently probabilistic; the JSON structure
  is validated, but free-text content quality is not measured.
- `content_hash` ties research to a candidate snapshot; regenerating
  after a candidate change yields a new (overwritten) record, not a
  corrupt duplicate.

## Explicit confirmation

No execution capability was added: no subprocess, no target/HTTP
execution, no Nuclei, no automatic LLM calls from `xss research`, no
production finding materialization, no alerting, no auth changes, no
database changes, no packages added, no new architecture, no Git
operations (no commit/push).

## Agent / Model

- Model: deepseek-v4-flash
- Stage: R7
- Role: Implementation